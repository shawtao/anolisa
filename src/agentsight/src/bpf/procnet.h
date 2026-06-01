// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Network operations probe header
// Monitors bind, listen, connect syscalls
#ifndef __PROCNET_H
#define __PROCNET_H

#define TASK_COMM_LEN 16

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
typedef signed long long    s64;
typedef unsigned long long  u64;

enum procnet_op {
    PROCNET_BIND             = 1,
    PROCNET_LISTEN           = 2,
    PROCNET_CONNECT_ERR      = 3,
    PROCNET_CONNECT_AGG      = 4,
    PROCNET_GETSOCKOPT_ERR   = 5,
    PROCNET_SOCKET_ERR       = 6,   /* socket(2) failure, e.g. EMFILE/ENFILE.
                                     * Success path is not emitted (would be too
                                     * noisy and provides no diagnostic value). */
};

// Single network event - sent via ringbuf
struct procnet_event {
    u32 source;                   // EVENT_SOURCE_PROCNET (8)
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u64 cgroup_id;
    u32 op;                       // enum procnet_op
    s32 ret;
    char comm[TASK_COMM_LEN];
    u16 port;
    u32 addr;                     // IPv4 address (network byte order)
    u16 family;                   // AF_INET / AF_INET6
};

// Connect aggregation key
struct connect_agg_key {
    u32 pid;
    u32 dst_addr;
    u16 dst_port;
    u16 _pad;
};

// Connect aggregation value
struct connect_agg_val {
    u64 count;
    u64 first_ts;
    u64 last_ts;
    char comm[TASK_COMM_LEN];
    u64 cgroup_id;
    s32 last_ret;
};

#endif /* __PROCNET_H */
