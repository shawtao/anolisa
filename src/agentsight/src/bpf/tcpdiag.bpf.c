// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// TCP stack-level diagnostic probe.
//
// Tracepoints:
//   sock:inet_sock_set_state  — owns the sock_cookie -> sock_meta map
//                               (writes from syscall context, deletes on
//                               terminal states to bound LRU pressure).
//   tcp:tcp_retransmit_skb    — emits RETRANSMIT (looks up map only).
//   tcp:tcp_receive_reset     — emits RESET_RECV  (looks up map only).
//
// Map design:
//   sock_cgid_map is the single source of truth that ties a kernel socket
//   to the owning container. Writing happens only from syscall context
//   (where bpf_get_current_*() is reliable on both v1 and v2 cgroups);
//   stack hooks merely read from it. LRU eviction + explicit deletion on
//   FIN_WAIT2 / LAST_ACK / TIME_WAIT / CLOSE / CLOSING bound the table to
//   the 65k-entry footprint regardless of churn.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "tcpdiag.h"
#include "common.h"
#include "cgroup_helper.h"

#define AF_INET  2
#define AF_INET6 10

/* sock_cookie -> sock_meta. Sized for ~65k concurrent containerized sockets,
 * which covers application-tier sidecar fan-out comfortably (see design doc).
 * Tunable via rodata for environments with extreme connection counts. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, struct sock_meta);
} sock_cgid_map SEC(".maps");

/* ─── helpers ──────────────────────────────────────────────────────────── */

static __always_inline u64 sk_cookie_of(const void *skaddr)
{
    /* `bpf_get_socket_cookie(sk-ptr)` exists since v5.4 but is gated to
     * cgroup/sock-class program types on several vendor 5.10 backports
     * (e.g. Anolis 8 / RHEL-derived 5.10.x), where calling it from a
     * tracepoint yields `unknown func bpf_get_socket_cookie#46` at load
     * time.
     *
     * We fall back to using the kernel sock address itself. Trade-off:
     *   - We lose the helper's "survives sock free+reuse" guarantee.
     *   - The lifetime we actually need is bounded by inet_sock_set_state
     *     terminal-state deletion + LRU eviction (sock_cgid_map is
     *     LRU_HASH/65536), so the address-collision window is very narrow
     *     for tcp_retransmit_skb / tcp_receive_reset lookups.
     * If the host kernel later exposes the helper to tp programs, switch
     * back to bpf_get_socket_cookie((void *)skaddr) here. */
    return (u64)skaddr;
}

/* ─── inet_sock_set_state: owns sock_cgid_map ──────────────────────────── */

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    /* This program is meta-only: it maintains sock_cgid_map (cookie ->
     * sock_meta) and never emits a ringbuf event. Downstream consumers
     * (handle_tcp_retransmit_skb / handle_tcp_receive_reset) read the
     * map to attach container context to retransmit / RST events.
     *
     * Rationale for dropping STATE_CHANGE / CLOSE_WAIT_STUCK in the SWE
     * evaluation profile:
     *   - SWE workloads are short-lived client processes (pip / cargo /
     *     git / pytest); state-machine traces have near-zero diagnostic
     *     value and dominate raw_events volume.
     *   - CLOSE_WAIT stall detector requires >60s socket lifetime, which
     *     virtually never occurs in evaluation runs.
     *
     * Capture ctx fields up-front into stack locals. 5.10 verifier may
     * lose PTR_TO_CTX after intervening helpers (bpf_get_current_*,
     * bpf_map_update_elem) and reject subsequent ctx-> dereferences with
     * -EACCES.
     */
    u16 protocol = ctx->protocol;
    if (protocol != 6 /* IPPROTO_TCP */)
        return 0;

    const void *skaddr = ctx->skaddr;
    if (!skaddr)
        return 0;

    int newstate = ctx->newstate;

    u64 cookie = sk_cookie_of(skaddr);
    if (!cookie)
        return 0;

    /* Terminal / draining states: free the slot immediately. This is the
     * primary mechanism that keeps map occupancy proportional to "currently
     * active sockets" rather than "ever observed sockets". */
    if (newstate == TCP_FIN_WAIT2 || newstate == TCP_TIME_WAIT ||
        newstate == TCP_CLOSE     || newstate == TCP_LAST_ACK ||
        newstate == TCP_CLOSING) {
        bpf_map_delete_elem(&sock_cgid_map, &cookie);
        return 0;
    }

    /* Non-terminal: only update the map when the current task is part of a
     * traced container (i.e. syscall context owned by the agent). For
     * softirq-driven transitions in the server's accept path, current is
     * unrelated and we skip — the original entry written at SYN_SENT /
     * accept-syscall time is preserved. */
    u64 cgid;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!traced_pid_cgroup_gate_allow(pid, &cgid))
        return 0;

    struct sock_meta meta = {};
    meta.cgid = cgid;
    meta.pid  = pid;
    bpf_get_current_comm(meta.comm, sizeof(meta.comm));
    bpf_map_update_elem(&sock_cgid_map, &cookie, &meta, BPF_ANY);
    return 0;
}

/* Read 4-tuple + family + state from struct sock via CO-RE.
 *
 * tracepoint ctx layout for trace_event_raw_tcp_event_sk_skb /
 * trace_event_raw_tcp_event_sk varies across vendor 5.10 backports
 * (Anolis 8's BTF lacks `family` on tcp_event_sk_skb), making CO-RE
 * relocations on those ctx fields unreliable. struct sock_common
 * fields (skc_*) are stable across all kernels and CO-RE-resolved
 * cleanly, so we source the 4-tuple from sk for the retransmit /
 * receive_reset hooks.
 */
static __always_inline void fill_4tuple_from_sk(struct tcpdiag_event *e,
                                                 const void *skaddr)
{
    struct sock *sk = (struct sock *)skaddr;
    u16 family = 0;
    u16 sport  = 0;       /* host order (skc_num) */
    u16 dport_be = 0;     /* big-endian (skc_dport) */

    BPF_CORE_READ_INTO(&family,   sk, __sk_common.skc_family);
    BPF_CORE_READ_INTO(&sport,    sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);

    e->family = family;
    e->sport  = sport;
    e->dport  = bpf_ntohs(dport_be);

    __builtin_memset(e->saddr, 0, 16);
    __builtin_memset(e->daddr, 0, 16);
    if (family == AF_INET6) {
        BPF_CORE_READ_INTO(e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(e->daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        u32 s4 = 0, d4 = 0;
        BPF_CORE_READ_INTO(&s4, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&d4, sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &s4, 4);
        __builtin_memcpy(e->daddr, &d4, 4);
    }
}

/* ─── tcp_retransmit_skb ───────────────────────────────────────────────── */

SEC("tp/tcp/tcp_retransmit_skb")
int handle_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    /* Only ctx->skaddr is read; the rest comes from struct sock to avoid
     * vendor-BTF divergence on the rest of the tracepoint payload. */
    const void *skaddr = ctx->skaddr;
    if (!skaddr)
        return 0;

    u64 cookie = sk_cookie_of(skaddr);
    if (!cookie)
        return 0;

    struct sock_meta *meta = bpf_map_lookup_elem(&sock_cgid_map, &cookie);
    if (!meta)
        return 0;  /* sock not from a traced container */

    /* Read counters from struct tcp_sock — CO-RE compatible. tcp_sock
     * embeds inet_connection_sock which embeds inet_sock which embeds sock,
     * so a sock pointer is also a tcp_sock pointer for TCP sockets. */
    struct tcp_sock *tp = (struct tcp_sock *)skaddr;
    u32 segs_out = 0, total_retrans = 0;
    BPF_CORE_READ_INTO(&segs_out,      tp, segs_out);
    BPF_CORE_READ_INTO(&total_retrans, tp, total_retrans);

    struct tcpdiag_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->source       = EVENT_SOURCE_TCPDIAG;
    e->op           = TCPDIAG_OP_RETRANSMIT;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = meta->cgid;
    e->sock_cookie  = cookie;
    e->pid          = meta->pid;
    e->_pad0        = 0;
    __builtin_memcpy(e->comm, meta->comm, TASK_COMM_LEN);
    e->segs_out     = segs_out;
    e->total_retrans= total_retrans;
    fill_4tuple_from_sk(e, skaddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ─── tcp_receive_reset ────────────────────────────────────────────────── */
/* tracepoint payload type is trace_event_raw_tcp_event_sk; we only read
 * skaddr from it and pull the 4-tuple from struct sock to remain stable
 * across vendor BTF differences. */
SEC("tp/tcp/tcp_receive_reset")
int handle_tcp_receive_reset(struct trace_event_raw_tcp_event_sk *ctx)
{
    const void *skaddr = ctx->skaddr;
    if (!skaddr)
        return 0;

    u64 cookie = sk_cookie_of(skaddr);
    if (!cookie)
        return 0;

    struct sock_meta *meta = bpf_map_lookup_elem(&sock_cgid_map, &cookie);
    if (!meta)
        return 0;

    struct tcpdiag_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->source       = EVENT_SOURCE_TCPDIAG;
    e->op           = TCPDIAG_OP_RESET_RECV;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id    = meta->cgid;
    e->sock_cookie  = cookie;
    e->pid          = meta->pid;
    e->_pad0        = 0;
    __builtin_memcpy(e->comm, meta->comm, TASK_COMM_LEN);
    e->segs_out     = 0;
    e->total_retrans= 0;
    fill_4tuple_from_sk(e, skaddr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
