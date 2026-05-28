// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Signal and process control BPF program
// Traces: setpgid, setsid, kill, fork (sched_process_fork)
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "procsig.h"
#include "common.h"
#include "cgroup_helper.h"

/* errors_only mode: when true, only syscalls with ret < 0 are emitted;
 * the sched_process_fork aggregation path (no ret) is fully suppressed. */
const volatile bool errors_only_mode = false;

/* ========== temp storage for enter/exit pairing ========== */

struct saved_sig_args {
    u32 op;
    u32 target_pid;
    u32 signal;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct saved_sig_args);
} temp_sig_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct fork_agg_key);
    __type(value, struct fork_agg_val);
} fork_agg_map SEC(".maps");

/* ========== helper: emit single signal event ========== */

static __always_inline void emit_sig_event(u32 op, s32 ret,
                                           u32 target_pid, u32 signal)
{
    /* errors_only gate: drop successful syscalls. */
    if (errors_only_mode && ret >= 0)
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return;

    struct procsig_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return;

    event->source = EVENT_SOURCE_PROCSIG;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = cg_id;
    event->op = op;
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->target_pid = target_pid;
    event->signal = signal;

    bpf_ringbuf_submit(event, 0);
}

/* ========== setpgid ========== */

SEC("tp/syscalls/sys_enter_setpgid")
int trace_setpgid_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_sig_args args = {};
    args.op = PROCSIG_SETPGID;
    args.target_pid = (u32)ctx->args[0]; /* pid argument */

    bpf_map_update_elem(&temp_sig_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_setpgid")
int trace_setpgid_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_sig_args *args = bpf_map_lookup_elem(&temp_sig_args, &pid_tgid);
    if (!args)
        return 0;

    emit_sig_event(args->op, (s32)ctx->ret, args->target_pid, 0);

    bpf_map_delete_elem(&temp_sig_args, &pid_tgid);
    return 0;
}

/* ========== setsid ========== */

SEC("tp/syscalls/sys_enter_setsid")
int trace_setsid_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_sig_args args = {};
    args.op = PROCSIG_SETSID;
    /* setsid takes no arguments */

    bpf_map_update_elem(&temp_sig_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_setsid")
int trace_setsid_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_sig_args *args = bpf_map_lookup_elem(&temp_sig_args, &pid_tgid);
    if (!args)
        return 0;

    emit_sig_event(args->op, (s32)ctx->ret, 0, 0);

    bpf_map_delete_elem(&temp_sig_args, &pid_tgid);
    return 0;
}

/* ========== kill ========== */

SEC("tp/syscalls/sys_enter_kill")
int trace_kill_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_sig_args args = {};
    args.op = PROCSIG_KILL;
    args.target_pid = (u32)ctx->args[0]; /* target pid */
    args.signal = (u32)ctx->args[1];     /* signal number */

    bpf_map_update_elem(&temp_sig_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_kill")
int trace_kill_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_sig_args *args = bpf_map_lookup_elem(&temp_sig_args, &pid_tgid);
    if (!args)
        return 0;

    /* kill always emits single event for full diagnostic context */
    emit_sig_event(args->op, (s32)ctx->ret, args->target_pid, args->signal);

    bpf_map_delete_elem(&temp_sig_args, &pid_tgid);
    return 0;
}

/* ========== fork — aggregated via sched_process_fork tracepoint ========== */

SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    /* fork carries no syscall return value — fully suppress under errors_only.
     * Failed fork paths are captured unconditionally via sys_exit_clone/clone3/vfork below. */
    if (errors_only_mode)
        return 0;

    u32 parent_pid = ctx->parent_pid;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(parent_pid, &cg_id))
        return 0;

    u64 now = bpf_ktime_get_ns();
    struct fork_agg_key key = { .parent_pid = parent_pid };

    struct fork_agg_val *val = bpf_map_lookup_elem(&fork_agg_map, &key);
    if (val) {
        val->count += 1;
        val->last_ts = now;
        val->cgroup_id = cg_id; /* ensure this CPU's slot has correct cgroup */
    } else {
        struct fork_agg_val new_val = {};
        new_val.count = 1;
        new_val.first_ts = now;
        new_val.last_ts = now;
        new_val.cgroup_id = cg_id;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&fork_agg_map, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

/* ========== fork failure — clone/clone3/vfork sys_exit (errors_only only) ==========
 *
 * sched_process_fork only fires AFTER a child task has been created, so it
 * cannot observe failed fork-family syscalls (EAGAIN from pid_max /
 * RLIMIT_NPROC, ENOMEM, EPERM from pids cgroup, etc.). For those diagnostic
 * cases we hook the syscall-exit tracepoints directly and emit a single
 * PROCSIG_FORK_FAIL event when ret < 0. The event reuses the procsig_event
 * layout — `ret` carries the negative errno, `target_pid` and `signal` are 0.
 *
 * These programs are only attached when proc_ext_errors_only is enabled by
 * the user-space loader, so the default (full-event-capture) mode pays zero
 * runtime cost.
 */

static __always_inline int handle_fork_fail(s32 ret)
{
    if (ret >= 0)
        return 0;
    /* emit_sig_event already gates on errors_only_mode + cgroup filter. */
    emit_sig_event(PROCSIG_FORK_FAIL, ret, 0, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int trace_clone_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fork_fail((s32)ctx->ret);
}

SEC("tp/syscalls/sys_exit_clone3")
int trace_clone3_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fork_fail((s32)ctx->ret);
}

SEC("tp/syscalls/sys_exit_vfork")
int trace_vfork_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fork_fail((s32)ctx->ret);
}

/* Legacy fork(2): musl libc on architectures that define __NR_fork (e.g. x86_64)
 * dispatches fork() directly to this syscall rather than clone(SIGCHLD, 0).
 * Without this hook, busybox-musl static binaries inside a cgroup that hits
 * pids.max / RLIMIT_NPROC will silently miss every fork-failure event.
 * arm64 has no __NR_fork; attach is performed with try_attach in user space. */
SEC("tp/syscalls/sys_exit_fork")
int trace_fork_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fork_fail((s32)ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
