// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// UDP DNS BPF program — minimal kernel-side probe
// Only captures raw DNS payload from UDP port 53 queries.
// All complex parsing (QNAME extraction, deduplication) is done in userspace.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "udpdns.h"

// Include common.h with traced_processes map + cgroup_filter map / rodata.
// cgroup_helper.h MUST be included AFTER common.h so traced_pid_cgroup_gate_*
// macros see the shared definitions.
#include "common.h"
#include "cgroup_helper.h"

// DNS header constants
#define DNS_HEADER_LEN 12
#define DNS_QR_MASK    0x80  // QR bit in flags byte 0 (1=response, 0=query)
#define DNS_PORT       53

// Payload buffer bitmask (DNS_PAYLOAD_MAX = 256, power of 2)
#define PAYLOAD_MASK (DNS_PAYLOAD_MAX - 1)  // 0xFF

SEC("fentry/udp_sendmsg")
int BPF_PROG(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    // Fast path: check destination port == 53 (DNS)
    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (dport != bpf_htons(DNS_PORT))
        return 0;

    // Minimum DNS query: 12 (header) + 1 (min QNAME) + 4 (QTYPE+QCLASS) = 17 bytes
    if (size < 17)
        return 0;

    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    /* ── Dual-channel admission ──────────────────────────────────────────
     * Channel A (correlation, NEW): when cgroup filtering is enabled and
     *   the current task's cgroup_id is registered in cgroup_filter, emit
     *   the event WITH cgroup_id so user-space can build a PID/cgroup →
     *   domain LRU for procnet connect error reverse-lookup.
     *
     * Channel B (discovery, LEGACY): when the PID is NOT yet in
     *   traced_processes, emit the event (cgroup_id=0) so AgentScanner
     *   can match domain rules and trigger attach_process().
     *
     * The two channels are independent OR conditions; either one is
     * sufficient to emit. When neither matches, the packet is dropped
     * (e.g. an already-tracked PID outside the configured cgroup set).
     *
     * Backwards compatibility: when filter_cgroup_enabled == false
     *   (default for non-containersight users), channel A is inert and
     *   behaviour is identical to the original "skip already-traced"
     *   discovery path.
     */
    bool emit = false;
    u64 cg_id = 0;
#ifndef NO_CGROUP_FILTER
    if (filter_cgroup_enabled) {
        cg_id = get_cgroup_id_compat();
        if (bpf_map_lookup_elem(&cgroup_filter, &cg_id))
            emit = true;
    }
#endif
    if (!emit) {
        // Legacy discovery: only fire for PIDs not yet tracked.
        if (!bpf_map_lookup_elem(&traced_processes, &pid))
            emit = true;
        else
            cg_id = 0; // already-tracked + not in cgroup filter → drop
    }
    if (!emit)
        return 0;

    // Read the first iovec from msg_iter to get user-space buffer pointer
    const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.iov);
    if (!iov)
        return 0;

    void *iov_base = BPF_CORE_READ(iov, iov_base);
    size_t iov_len = BPF_CORE_READ(iov, iov_len);
    if (!iov_base || iov_len < 17)
        return 0;

    // Reserve ring buffer event
    struct udpdns_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return 0;

    // Clamp read size to payload buffer capacity
    __u32 read_len = iov_len;
    if (read_len > DNS_PAYLOAD_MAX)
        read_len = DNS_PAYLOAD_MAX;

    // Read user-space DNS buffer into event payload
    int ret = bpf_probe_read_user(event->payload, read_len & PAYLOAD_MASK, iov_base);
    if (ret != 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // --- Minimal DNS header validation (cheap, no loops) ---
    // QR bit must be 0 (query, not response)
    if (event->payload[2] & DNS_QR_MASK) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // QDCOUNT must be >= 1
    __u16 qdcount = ((__u16)event->payload[4] << 8) | (__u16)event->payload[5];
    if (qdcount == 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Fill event metadata
    event->source = EVENT_SOURCE_UDPDNS;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = bpf_get_current_uid_gid();
    event->payload_len = read_len;
    event->cgroup_id = cg_id;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
