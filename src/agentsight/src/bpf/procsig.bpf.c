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

char LICENSE[] SEC("license") = "GPL";
