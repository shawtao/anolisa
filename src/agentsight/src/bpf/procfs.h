// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Filesystem operations probe header
// Monitors delete, rename, mkdir, truncate, chdir, and write syscalls
#ifndef __PROCFS_H
#define __PROCFS_H

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
typedef signed long long    s64;
typedef unsigned long long  u64;

enum procfs_op {
    PROCFS_DELETE    = 1,
    PROCFS_RENAME    = 2,
    PROCFS_MKDIR     = 3,
    PROCFS_TRUNCATE  = 4,
    PROCFS_CHDIR     = 5,
    PROCFS_WRITE_ERR = 6,
    PROCFS_WRITE_AGG = 7,
    PROCFS_OPEN      = 8,   /* open: errors (ret<0) emitted via ringbuf with count=1;
                             * successes (ret==0) aggregated in open_agg_map and emitted
                             * by user-space flush with accumulated count.
                             * Shared by openat / open / creat tracepoints.
                             */
    PROCFS_RMDIR     = 9,   /* legacy rmdir(2): kept distinct from PROCFS_DELETE so that
                             * "remove directory" vs "unlink file" are not conflated.
                             */
    PROCFS_INOTIFY_ADD_WATCH = 10, /* inotify_add_watch(2) failure path; success is dropped
                                    * in BPF (one event per registered watch is too noisy
                                    * and provides no diagnostic value — only ENOSPC
                                    * caused by fs.inotify.max_user_watches saturation
                                    * matters).
                                    */
};

// Single filesystem event - sent via ringbuf
struct procfs_event {
    u32 source;                       // EVENT_SOURCE_PROCFS (7)
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 cgroup_id;
    u32 op;                           // enum procfs_op
    s32 ret;
    u32 count;                        // aggregation count; 1 for non-aggregated events
    char comm[TASK_COMM_LEN];
    char path[MAX_FILENAME_LEN];
    char new_path[MAX_FILENAME_LEN];  // used by rename
};

// openat aggregation key (per-pid, per-path)
struct open_agg_key {
    u32 pid;
    u32 _pad;
    char path[MAX_FILENAME_LEN];
};

// openat aggregation value (sliding window state)
struct open_agg_val {
    u64 first_ts;
    u64 last_ts;
    u64 cgroup_id;
    u32 tid;
    u32 uid;
    u32 count;
    u32 _pad;
    char comm[TASK_COMM_LEN];
};

// Write aggregation key (per-pid)
struct write_agg_key {
    u32 pid;
};

// Write aggregation value (accumulated stats)
struct write_agg_val {
    u64 count;
    u64 total_bytes;
    u64 first_ts;
    u64 last_ts;
    char comm[TASK_COMM_LEN];
    u64 cgroup_id;
};

// Write aggregation event - Rust-side constructs from agg map flush
struct procfs_write_agg_event {
    u32 source;                       // EVENT_SOURCE_PROCFS (7)
    u64 first_ts;
    u64 last_ts;
    u32 pid;
    u64 cgroup_id;
    u32 op;                           // PROCFS_WRITE_AGG
    u64 count;
    u64 total_bytes;
    char comm[TASK_COMM_LEN];
};

#endif /* __PROCFS_H */
