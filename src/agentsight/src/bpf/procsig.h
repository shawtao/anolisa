// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Signal and process control probe header
// Monitors kill, fork, signal_generate (receiver-perspective)
#ifndef __PROCSIG_H
#define __PROCSIG_H

#define TASK_COMM_LEN 16

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
typedef signed long long    s64;
typedef unsigned long long  u64;

enum procsig_op {
    PROCSIG_KILL        = 3,
    PROCSIG_FORK_FAIL   = 4,  // fork-family syscall failure (clone/clone3/vfork ret<0)
    PROCSIG_FORK_AGG    = 5,
    PROCSIG_SIGNAL_RECV = 6,  // signal_generate receiver-perspective event
                              // (raw_tracepoint/signal_generate, covers OOM/SEGV/external kill)
};

// Single signal/process control event - sent via ringbuf
struct procsig_event {
    u32 source;                   // EVENT_SOURCE_PROCSIG (9)
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 cgroup_id;
    u32 op;                       // enum procsig_op
    s32 ret;
    char comm[TASK_COMM_LEN];
    u32 target_pid;
    u32 signal;
};

// Fork aggregation key
struct fork_agg_key {
    u32 parent_pid;
};

// Fork aggregation value
struct fork_agg_val {
    u64 count;
    u64 first_ts;
    u64 last_ts;
    char comm[TASK_COMM_LEN];
    u64 cgroup_id;
};

#endif /* __PROCSIG_H */
