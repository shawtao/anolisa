// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Network operations BPF program
// Traces: bind, listen, connect syscalls
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "procnet.h"
#include "common.h"
#include "cgroup_helper.h"

/* errors_only mode: when true, only syscalls with ret < 0 are emitted;
 * connect aggregation (success / EINPROGRESS) is fully suppressed. */
const volatile bool errors_only_mode = false;

/* Address families from linux/socket.h */
#define AF_INET  2
#define AF_INET6 10

/* Socket option constants */
#define SOL_SOCKET 1
#define SO_ERROR   4

/* ========== temp storage for enter/exit pairing ========== */

struct saved_net_args {
    u32 op;
    u16 port;
    u32 addr;
    u16 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct saved_net_args);
} temp_net_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct connect_agg_key);
    __type(value, struct connect_agg_val);
} connect_agg_map SEC(".maps");

/* ========== temp storage for getsockopt enter/exit pairing ========== */

struct saved_getsockopt_args {
    u64 optval_ptr;   /* user-space pointer to int where SO_ERROR is stored */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct saved_getsockopt_args);
} temp_getsockopt SEC(".maps");

/* ========== sockaddr reading helper ========== */

/* ntohs: network byte order (big-endian) to host (little-endian) */
static __always_inline u16 bpf_ntohs(u16 val)
{
    return (val >> 8) | (val << 8);
}

/*
 * read_sockaddr - Read sockaddr from user-space pointer.
 * Supports AF_INET (full addr+port) and AF_INET6 (port only, addr=0).
 * For other families, records family number with port=0, addr=0.
 * Returns 0 on success (family populated), -1 on read failure.
 */
static __always_inline int read_sockaddr(const void *user_addr,
                                         struct saved_net_args *args)
{
    /* sockaddr_in and sockaddr_in6 both have family(u16) at offset 0
     * and port(u16) at offset 2. Read the common header first. */
    struct {
        u16 family;
        u16 port;
    } sa_head = {};

    if (bpf_probe_read_user(&sa_head, sizeof(sa_head), user_addr) < 0)
        return -1;

    args->family = sa_head.family;

    if (sa_head.family == AF_INET) {
        /* Full IPv4: read addr */
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), user_addr) == 0) {
            args->port = bpf_ntohs(sin.sin_port);
            args->addr = sin.sin_addr.s_addr;
        }
    } else if (sa_head.family == AF_INET6) {
        /* IPv6: port is at same offset; addr is 128-bit, store 0 */
        args->port = bpf_ntohs(sa_head.port);
        args->addr = 0;
    } else {
        /* Other families (AF_UNIX, AF_NETLINK, ...): record family only */
        args->port = 0;
        args->addr = 0;
    }

    return 0;
}

/* ========== helper: emit single net event ========== */

static __always_inline void emit_net_event(u32 op, s32 ret,
                                           struct saved_net_args *args)
{
    /* errors_only gate: drop successful syscalls. */
    if (errors_only_mode && ret >= 0)
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return;

    struct procnet_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return;

    event->source = EVENT_SOURCE_PROCNET;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = cg_id;
    event->op = op;
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->port = args->port;
    event->addr = args->addr;
    event->family = args->family;

    bpf_ringbuf_submit(event, 0);
}

/* ========== bind ========== */

SEC("tp/syscalls/sys_enter_bind")
int trace_bind_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_net_args args = {};
    args.op = PROCNET_BIND;

    const void *user_addr = (const void *)ctx->args[1];
    if (read_sockaddr(user_addr, &args) < 0)
        return 0;

    bpf_map_update_elem(&temp_net_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_bind")
int trace_bind_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_net_args *args = bpf_map_lookup_elem(&temp_net_args, &pid_tgid);
    if (!args)
        return 0;

    emit_net_event(args->op, (s32)ctx->ret, args);

    bpf_map_delete_elem(&temp_net_args, &pid_tgid);
    return 0;
}

/* ========== listen ========== */

SEC("tp/syscalls/sys_enter_listen")
int trace_listen_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_net_args args = {};
    args.op = PROCNET_LISTEN;
    /* listen(fd, backlog) — no sockaddr; port/addr stay zero */

    bpf_map_update_elem(&temp_net_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_listen")
int trace_listen_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_net_args *args = bpf_map_lookup_elem(&temp_net_args, &pid_tgid);
    if (!args)
        return 0;

    emit_net_event(args->op, (s32)ctx->ret, args);

    bpf_map_delete_elem(&temp_net_args, &pid_tgid);
    return 0;
}

/* ========== connect ========== */

SEC("tp/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_net_args args = {};
    args.op = PROCNET_CONNECT_AGG;

    const void *user_addr = (const void *)ctx->args[1];
    if (read_sockaddr(user_addr, &args) < 0)
        return 0;

    bpf_map_update_elem(&temp_net_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct saved_net_args *args = bpf_map_lookup_elem(&temp_net_args, &pid_tgid);
    if (!args)
        return 0;

    s32 ret = (s32)ctx->ret;
    bpf_map_delete_elem(&temp_net_args, &pid_tgid);

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    /* Any error including EINPROGRESS (-115) is emitted as connect_error.
     * EINPROGRESS indicates non-blocking connect in-progress — the caller
     * can distinguish by ret value. This ensures network timeout scenarios
     * (where the actual ETIMEDOUT comes via getsockopt SO_ERROR) still have
     * a visible connect attempt event in the trace. */
    if (ret < 0) {
        struct saved_net_args err_args = *args;
        err_args.op = PROCNET_CONNECT_ERR;
        emit_net_event(PROCNET_CONNECT_ERR, ret, &err_args);
        return 0;
    }

    /* Success — aggregate */
    if (errors_only_mode)
        return 0;

    u64 now = bpf_ktime_get_ns();
    struct connect_agg_key key = {
        .pid = pid,
        .dst_addr = args->addr,
        .dst_port = args->port,
        ._pad = 0,
    };

    struct connect_agg_val *val = bpf_map_lookup_elem(&connect_agg_map, &key);
    if (val) {
        val->count += 1;
        val->last_ts = now;
        val->last_ret = ret;
        val->cgroup_id = cg_id; /* ensure this CPU's slot has correct cgroup */
    } else {
        struct connect_agg_val new_val = {};
        new_val.count = 1;
        new_val.first_ts = now;
        new_val.last_ts = now;
        new_val.cgroup_id = cg_id;
        new_val.last_ret = ret;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&connect_agg_map, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

/* ========== getsockopt (SO_ERROR) ========== */

SEC("tp/syscalls/sys_enter_getsockopt")
int trace_getsockopt_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* getsockopt(fd, level, optname, optval, optlen)
     * args[0]=fd, args[1]=level, args[2]=optname, args[3]=optval, args[4]=optlen */
    int level = (int)ctx->args[1];
    int optname = (int)ctx->args[2];

    /* Only interested in SOL_SOCKET + SO_ERROR */
    if (level != SOL_SOCKET || optname != SO_ERROR)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_getsockopt_args ga = {
        .optval_ptr = (u64)ctx->args[3],
    };
    bpf_map_update_elem(&temp_getsockopt, &pid_tgid, &ga, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_getsockopt")
int trace_getsockopt_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct saved_getsockopt_args *ga = bpf_map_lookup_elem(&temp_getsockopt, &pid_tgid);
    if (!ga)
        return 0;

    u64 optval_ptr = ga->optval_ptr;
    bpf_map_delete_elem(&temp_getsockopt, &pid_tgid);

    /* getsockopt itself failed — nothing useful */
    if ((s32)ctx->ret < 0)
        return 0;

    /* Read the SO_ERROR value from user-space optval pointer */
    int so_error = 0;
    if (bpf_probe_read_user(&so_error, sizeof(so_error), (const void *)optval_ptr) < 0)
        return 0;

    /* so_error == 0 means no pending error — skip */
    if (so_error == 0)
        return 0;

    /* Non-zero SO_ERROR: emit as PROCNET_GETSOCKOPT_ERR.
     * Common values: ETIMEDOUT(110), ECONNREFUSED(111), ENETUNREACH(101) */
    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct procnet_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    event->source = EVENT_SOURCE_PROCNET;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = cg_id;
    event->op = PROCNET_GETSOCKOPT_ERR;
    event->ret = -so_error;  /* negate to match connect error convention (negative errno) */
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->port = 0;
    event->addr = 0;
    event->family = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
