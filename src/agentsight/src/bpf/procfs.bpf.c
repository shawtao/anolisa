// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Filesystem operations BPF program
// Traces: unlinkat(delete), renameat2(rename), mkdirat(mkdir),
//         ftruncate(truncate), chdir.
// write / pwrite64 / writev: kept in source under #if 0 (off). Set to #if 1 to compile.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "procfs.h"
#include "common.h"
#include "cgroup_helper.h"

/* ========== temp storage for enter/exit pairing ========== */

struct saved_fs_args {
    u32 op;
    char path[MAX_FILENAME_LEN];
    char new_path[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct saved_fs_args);
} temp_fs_args SEC(".maps");

/* PERCPU scratch buffer to avoid 512B BPF stack overflow when allocating
 * struct saved_fs_args (516 bytes) on the stack along with cgroup_helper
 * locals from traced_pid_cgroup_gate_allow(). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct saved_fs_args);
} scratch_fs_args SEC(".maps");

#if 0
/* --- write aggregation (disabled): flip #if above to 1 to re-enable --- */
struct saved_write_args {
    s64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct saved_write_args);
} temp_write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct write_agg_key);
    __type(value, struct write_agg_val);
} write_agg_map SEC(".maps");
#endif

/* ========== helpers ========== */

static __always_inline void emit_fs_event(struct trace_event_raw_sys_exit *ctx,
                                          u32 op, s32 ret,
                                          const char *path, u32 path_len,
                                          const char *new_path, u32 new_path_len)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return;

    struct procfs_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return;

    event->source = EVENT_SOURCE_PROCFS;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = (u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid();
    event->cgroup_id = cg_id;
    event->op = op;
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* copy paths from saved args (already kernel stack) */
    __builtin_memcpy(event->path, path, path_len < MAX_FILENAME_LEN ? path_len : MAX_FILENAME_LEN);
    if (new_path && new_path_len > 0)
        __builtin_memcpy(event->new_path, new_path, new_path_len < MAX_FILENAME_LEN ? new_path_len : MAX_FILENAME_LEN);
    else
        event->new_path[0] = '\0';

    bpf_ringbuf_submit(event, 0);
}

/* ========== unlinkat (delete) ========== */

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_DELETE;

    const char *pathname = (const char *)ctx->args[1];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_unlinkat")
int trace_unlinkat_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  NULL, 0);

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

/* ========== renameat2 (rename) ========== */

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_RENAME;

    const char *oldname = (const char *)ctx->args[1];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), oldname);
    if (len < 0)
        return 0;

    const char *newname = (const char *)ctx->args[3];
    len = bpf_probe_read_user_str(args->new_path, sizeof(args->new_path), newname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int trace_renameat2_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  args->new_path, sizeof(args->new_path));

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

/* ========== mkdirat (mkdir) ========== */

SEC("tp/syscalls/sys_enter_mkdirat")
int trace_mkdirat_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_MKDIR;

    const char *pathname = (const char *)ctx->args[1];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_mkdirat")
int trace_mkdirat_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  NULL, 0);

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

/* ========== ftruncate (truncate) ========== */

SEC("tp/syscalls/sys_enter_ftruncate")
int trace_ftruncate_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_TRUNCATE;
    /* ftruncate operates on fd, no pathname — store empty path */
    args->path[0] = '\0';

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_ftruncate")
int trace_ftruncate_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  NULL, 0);

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

/* ========== chdir ========== */

SEC("tp/syscalls/sys_enter_chdir")
int trace_chdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_CHDIR;

    const char *pathname = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_chdir")
int trace_chdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  NULL, 0);

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

/* ========== openat (open) ========== */

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    u32 zero = 0;
    struct saved_fs_args *args = bpf_map_lookup_elem(&scratch_fs_args, &zero);
    if (!args)
        return 0;
    __builtin_memset(args, 0, sizeof(*args));
    args->op = PROCFS_OPEN;

    /* openat: args[0]=dirfd, args[1]=pathname, args[2]=flags, args[3]=mode */
    const char *pathname = (const char *)ctx->args[1];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    emit_fs_event(ctx, args->op, (s32)ctx->ret,
                  args->path, sizeof(args->path),
                  NULL, 0);

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

#if 0
/* ========== write — high frequency, aggregated (disabled, see #if above) ========== */

/*
 * count lives at args[2] for sys_write, sys_pwrite64, and sys_writev (vlen).
 * Use a constant subscript; ctx->args[idx] with non-constant idx makes the
 * verifier treat the base as a modified ctx pointer → "dereference ... disallowed".
 */
static __always_inline int handle_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    s64 count = (s64)ctx->args[2];

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    struct saved_write_args args = {};
    args.count = count;

    bpf_map_update_elem(&temp_write_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

static __always_inline int handle_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct saved_write_args *args = bpf_map_lookup_elem(&temp_write_args, &pid_tgid);
    if (!args)
        return 0;

    s64 ret = ctx->ret;
    bpf_map_delete_elem(&temp_write_args, &pid_tgid);

    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id))
        return 0;

    if (ret < 0) {
        /* Write error — emit single event via ringbuf */
        struct procfs_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
        if (!event)
            return 0;

        event->source = EVENT_SOURCE_PROCFS;
        event->timestamp_ns = bpf_ktime_get_ns();
        event->pid = pid;
        event->tid = (u32)pid_tgid;
        event->uid = bpf_get_current_uid_gid();
        event->cgroup_id = cg_id;
        event->op = PROCFS_WRITE_ERR;
        event->ret = (s32)ret;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->path[0] = '\0';
        event->new_path[0] = '\0';

        bpf_ringbuf_submit(event, 0);
        return 0;
    }

    /* Write success — aggregate in percpu hash */
    u64 now = bpf_ktime_get_ns();
    struct write_agg_key key = { .pid = pid };

    struct write_agg_val *val = bpf_map_lookup_elem(&write_agg_map, &key);
    if (val) {
        val->count += 1;
        val->total_bytes += (u64)ret;
        val->last_ts = now;
    } else {
        struct write_agg_val new_val = {};
        new_val.count = 1;
        new_val.total_bytes = (u64)ret;
        new_val.first_ts = now;
        new_val.last_ts = now;
        new_val.cgroup_id = cg_id;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&write_agg_map, &key, &new_val, BPF_NOEXIST);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    return handle_write_enter(ctx);
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx);
}

SEC("tp/syscalls/sys_enter_pwrite64")
int trace_pwrite64_enter(struct trace_event_raw_sys_enter *ctx)
{
    return handle_write_enter(ctx);
}

SEC("tp/syscalls/sys_exit_pwrite64")
int trace_pwrite64_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx);
}

SEC("tp/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx)
{
    return handle_write_enter(ctx);
}

SEC("tp/syscalls/sys_exit_writev")
int trace_writev_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_write_exit(ctx);
}
#endif

char LICENSE[] SEC("license") = "GPL";
