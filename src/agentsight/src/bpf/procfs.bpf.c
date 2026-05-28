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

/* errors_only mode: when true, only syscalls with ret < 0 are emitted;
 * the openat success-aggregation path is fully suppressed. */
const volatile bool errors_only_mode = false;

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

/* ========== openat aggregation (per-CPU) ==========
 * Errors bypass aggregation entirely and are emitted via ringbuf with op=PROCFS_OPEN.
 * Successful opens are aggregated by (pid, path) in a per-CPU hash map; user-space
 * periodically drains the map (flush_open_agg) and emits one summary event per
 * unique (pid, path) carrying the accumulated count.
 */
#define OPEN_AGG_MAX_ENTRIES 2048

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, OPEN_AGG_MAX_ENTRIES);
    __type(key, struct open_agg_key);
    __type(value, struct open_agg_val);
} open_agg_map SEC(".maps");

/* PERCPU scratch for open_agg_key (264 bytes) — cannot live on BPF stack
 * together with cgroup_helper locals. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct open_agg_key);
} scratch_open_agg_key SEC(".maps");

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

/* Low-level emit: caller has already passed cgroup gate and decided count. */
static __always_inline void emit_fs_event_full(struct trace_event_raw_sys_exit *ctx,
                                               u32 op, s32 ret,
                                               u64 cg_id, u32 count,
                                               const char *path, u32 path_len,
                                               const char *new_path, u32 new_path_len)
{
    /* errors_only gate: drop successful syscalls. */
    if (errors_only_mode && ret >= 0)
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

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
    event->count = count;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* copy paths from saved args (already kernel stack) */
    __builtin_memcpy(event->path, path, path_len < MAX_FILENAME_LEN ? path_len : MAX_FILENAME_LEN);
    if (new_path && new_path_len > 0)
        __builtin_memcpy(event->new_path, new_path, new_path_len < MAX_FILENAME_LEN ? new_path_len : MAX_FILENAME_LEN);
    else
        event->new_path[0] = '\0';

    bpf_ringbuf_submit(event, 0);
}

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

    emit_fs_event_full(ctx, op, ret, cg_id, 1, path, path_len, new_path, new_path_len);
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

/* ========== openat / open / creat (shared open) ==========
 * openat:  args[1] = pathname
 * open:    args[0] = pathname (legacy, busybox/musl static still emits this)
 * creat:   args[0] = pathname (legacy; equivalent to open(O_CREAT|O_WRONLY|O_TRUNC))
 */

static __always_inline int handle_open_enter(const char *pathname)
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

    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

static __always_inline int handle_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    s32 ret = (s32)ctx->ret;

    struct saved_fs_args *args = bpf_map_lookup_elem(&temp_fs_args, &pid_tgid);
    if (!args)
        return 0;

    /* cgroup gate (already checked at enter, but PID could be reaped/replaced) */
    u64 cg_id;
    if (!traced_pid_cgroup_gate_allow(pid, &cg_id)) {
        bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
        return 0;
    }

    /* Errors bypass aggregation — emit every error event via ringbuf so callers
     * never miss an ENOENT/EACCES/etc. on a hot path. */
    if (ret < 0) {
        emit_fs_event_full(ctx, PROCFS_OPEN, ret, cg_id, 1,
                           args->path, sizeof(args->path),
                           NULL, 0);
        bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
        return 0;
    }

    /* Success path: aggregate per (pid, path) in per-CPU hash map.
     * No ringbuf submission — user-space flush_open_agg() drains the map
     * periodically and emits one PROCFS_OPEN_AGG event per unique key. */
    if (errors_only_mode) {
        bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
        return 0;
    }

    u32 zero = 0;
    struct open_agg_key *agg_key = bpf_map_lookup_elem(&scratch_open_agg_key, &zero);
    if (!agg_key) {
        bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
        return 0;
    }
    __builtin_memset(agg_key, 0, sizeof(*agg_key));
    agg_key->pid = pid;
    __builtin_memcpy(agg_key->path, args->path, MAX_FILENAME_LEN);

    u64 now = bpf_ktime_get_ns();
    struct open_agg_val *val = bpf_map_lookup_elem(&open_agg_map, agg_key);
    if (val) {
        /* per-CPU slot already populated on this CPU — just bump the counter */
        val->count += 1;
        val->last_ts = now;
        val->cgroup_id = cg_id;
    } else {
        struct open_agg_val new_val = {};
        new_val.first_ts = now;
        new_val.last_ts = now;
        new_val.cgroup_id = cg_id;
        new_val.tid = (u32)pid_tgid;
        new_val.uid = bpf_get_current_uid_gid();
        new_val.count = 1;
        bpf_get_current_comm(&new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&open_agg_map, agg_key, &new_val, BPF_NOEXIST);
    }

    bpf_map_delete_elem(&temp_fs_args, &pid_tgid);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* openat: args[0]=dirfd, args[1]=pathname, args[2]=flags, args[3]=mode */
    return handle_open_enter((const char *)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_open_exit(ctx);
}

SEC("tp/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* legacy open: args[0]=pathname, args[1]=flags, args[2]=mode */
    return handle_open_enter((const char *)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_open")
int trace_open_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_open_exit(ctx);
}

SEC("tp/syscalls/sys_enter_creat")
int trace_creat_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* creat(path, mode) ≡ open(path, O_CREAT|O_WRONLY|O_TRUNC, mode); args[0]=pathname */
    return handle_open_enter((const char *)ctx->args[0]);
}

SEC("tp/syscalls/sys_exit_creat")
int trace_creat_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_open_exit(ctx);
}

/* ========== legacy unlink / rmdir / rename / mkdir ==========
 * busybox-static and musl-static binaries frequently invoke these old syscalls
 * directly (rather than the *at variants), so the *at-only tracepoints above
 * miss them. Each enter/exit pair is intentionally a thin wrapper that mirrors
 * the corresponding *at handler — only the args index differs.
 */

static __always_inline int handle_single_path_enter(const char *pathname, u32 op)
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
    args->op = op;

    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), pathname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

static __always_inline int handle_fs_exit_single(struct trace_event_raw_sys_exit *ctx)
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

SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* unlink(pathname); semantically equivalent to unlinkat(AT_FDCWD, p, 0) → reuse PROCFS_DELETE */
    return handle_single_path_enter((const char *)ctx->args[0], PROCFS_DELETE);
}

SEC("tp/syscalls/sys_exit_unlink")
int trace_unlink_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fs_exit_single(ctx);
}

SEC("tp/syscalls/sys_enter_rmdir")
int trace_rmdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* rmdir(pathname); kept distinct from unlink for clearer downstream semantics */
    return handle_single_path_enter((const char *)ctx->args[0], PROCFS_RMDIR);
}

SEC("tp/syscalls/sys_exit_rmdir")
int trace_rmdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fs_exit_single(ctx);
}

SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* mkdir(pathname, mode); args[0]=pathname (legacy, no dirfd) */
    return handle_single_path_enter((const char *)ctx->args[0], PROCFS_MKDIR);
}

SEC("tp/syscalls/sys_exit_mkdir")
int trace_mkdir_exit(struct trace_event_raw_sys_exit *ctx)
{
    return handle_fs_exit_single(ctx);
}

SEC("tp/syscalls/sys_enter_rename")
int trace_rename_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* rename(oldname, newname); args[0]=oldname, args[1]=newname */
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

    const char *oldname = (const char *)ctx->args[0];
    long len = bpf_probe_read_user_str(args->path, sizeof(args->path), oldname);
    if (len < 0)
        return 0;

    const char *newname = (const char *)ctx->args[1];
    len = bpf_probe_read_user_str(args->new_path, sizeof(args->new_path), newname);
    if (len < 0)
        return 0;

    bpf_map_update_elem(&temp_fs_args, &pid_tgid, args, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_rename")
int trace_rename_exit(struct trace_event_raw_sys_exit *ctx)
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
