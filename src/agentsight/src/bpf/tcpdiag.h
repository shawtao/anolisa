// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// TCP stack-level diagnostic probe header
// Captures: retransmit, receive_reset (inet_sock_set_state runs in meta-only mode).
#ifndef __TCPDIAG_H
#define __TCPDIAG_H

#define TASK_COMM_LEN 16

typedef signed char         s8;
typedef unsigned char       u8;
typedef signed short        s16;
typedef unsigned short      u16;
typedef signed int          s32;
typedef unsigned int        u32;
typedef signed long long    s64;
typedef unsigned long long  u64;

/* Operation kinds.
 *
 * Historical note: enum value 2 (STATE_CHANGE) was retired together with the
 * derived close_wait_stuck signal. The inet_sock_set_state tracepoint now
 * runs in meta-only mode and does not emit ringbuf events. The numeric
 * values of the remaining ops are preserved for raw_events backward
 * compatibility. */
enum tcpdiag_op {
    TCPDIAG_OP_RETRANSMIT   = 1,  /* tcp_retransmit_skb */
    TCPDIAG_OP_RESET_RECV   = 3,  /* tcp_receive_reset */
};

/* TCP states (linux/tcp_states.h) */
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

/* Per-socket metadata stored in sock_cgid_map (LRU) */
struct sock_meta {
    u64 cgid;                    /* cgroup inode id (memory cgroup on v1, unified on v2) */
    u32 pid;                     /* owner tgid captured at first traced state change */
    u32 _pad;
    char comm[TASK_COMM_LEN];
};

/* Single TCP-stack event sent via shared ringbuf */
struct tcpdiag_event {
    u32 source;                  /* EVENT_SOURCE_TCPDIAG (10) */
    u32 op;                      /* enum tcpdiag_op */
    u64 timestamp_ns;
    u64 cgroup_id;
    u64 sock_cookie;
    u32 pid;
    u32 _pad0;
    char comm[TASK_COMM_LEN];

    /* Connection 4-tuple (saddr/daddr cover IPv4 in first 4 bytes, IPv6 full 16 bytes) */
    u16 family;                  /* AF_INET / AF_INET6 */
    u16 sport;                   /* host order */
    u16 dport;                   /* host order */
    u16 _pad1;
    u8  saddr[16];
    u8  daddr[16];

    /* Retransmit counters (RETRANSMIT only; CO-RE read from struct tcp_sock) */
    u32 segs_out;
    u32 total_retrans;
};

#endif /* __TCPDIAG_H */
