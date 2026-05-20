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

/* AF_INET from linux/socket.h */
#define AF_INET 2

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

/* ========== sockaddr reading helper ========== */

/* ntohs: network byte order (big-endian) to host (little-endian) */
static __always_inline u16 bpf_ntohs(u16 val)
{
    return (val >> 8) | (val << 8);
}

/*
 * read_sockaddr_in - Read IPv4 sockaddr from user-space pointer.
 * Returns 0 on success, populates family/port/addr in args.
 * Returns -1 on failure or non-AF_INET family.
 */
static __always_inline int read_sockaddr_in(const void *user_addr,
                                            struct saved_net_args *args)
{
    /* Read raw sockaddr_in from user space */
    struct sockaddr_in sin = {};
    int ret = bpf_probe_read_user(&sin, sizeof(sin), user_addr);
    if (ret < 0)
        return -1;

    args->family = sin.sin_family;
    if (args->family != AF_INET)
        return -1; /* only track IPv4 for now */

    args->port = bpf_ntohs(sin.sin_port);
    args->addr = sin.sin_addr.s_addr;
    return 0;
}

/* ========== helper: emit single net event ========== */

static __always_inline void emit_net_event(u32 op, s32 ret,
                                           struct saved_net_args *args)
{
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
    if (read_sockaddr_in(user_addr, &args) < 0)
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
    if (read_sockaddr_in(user_addr, &args) < 0)
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

    /* EINPROGRESS (-115) is normal for non-blocking connect */
    if (ret < 0 && ret != -115) {
        /* Connect error — emit single event */
        struct saved_net_args err_args = *args;
        err_args.op = PROCNET_CONNECT_ERR;
        emit_net_event(PROCNET_CONNECT_ERR, ret, &err_args);
        return 0;
    }

    /* Success or EINPROGRESS — aggregate */
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

char LICENSE[] SEC("license") = "GPL";
