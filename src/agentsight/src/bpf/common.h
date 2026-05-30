#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef RING_BUFFER_SIZE
#define RING_BUFFER_SIZE (64 * 1024 * 1024)
#endif

#ifndef MAX_TRACED_PROCESSES
#define MAX_TRACED_PROCESSES 1024
#endif


// Event source identifiers - first field of every ringbuffer event
// Allows unified dispatch from a shared ring buffer
typedef enum {
    EVENT_SOURCE_PROC = 1,   // Process events (proctrace)
    EVENT_SOURCE_SSL  = 2,   // SSL/TLS traffic events (sslsniff)
    EVENT_SOURCE_PROCMON = 3, // Process monitor events (procmon)
    EVENT_SOURCE_FILEWATCH = 4, // File watch events (filewatch)
    EVENT_SOURCE_FILEWRITE = 5, // File write events (filewrite)
    EVENT_SOURCE_UDPDNS = 6,   // UDP DNS query events (udpdns)
    EVENT_SOURCE_PROCFS = 7,   // Filesystem operations
    EVENT_SOURCE_PROCNET = 8,  // Network operations
    EVENT_SOURCE_PROCSIG = 9,  // Signal/process control operations
    EVENT_SOURCE_TCPDIAG = 10, // TCP stack-level diagnostic events (tcpdiag)
} event_source_t;

// Common event header - every ringbuffer event MUST start with this
// Allows user-space to read source and dispatch to the right handler
struct common_event_hdr {
    u32 source;  // event_source_t - identifies the event producer
};

// Shared ring buffer - used by all BPF programs to avoid wasting memory
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} rb SEC(".maps");

#ifndef NO_TRACED_PROCESSES_MAP
// Shared traced_processes map - used by all BPF programs for process filtering
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACED_PROCESSES);
    __type(key, u32);
    __type(value, u32);
} traced_processes SEC(".maps");
#endif

/* ========== cgroup filter ==========
 *
 * Optional cgroup-level filter shared across all probes that include common.h.
 * When `filter_cgroup_enabled` is false (default), only `traced_processes`
 * gates events (legacy behavior).
 * When enabled, an event passes if EITHER the PID is in `traced_processes`
 * OR its cgroup id is listed in `cgroup_filter` — cgroup membership observes
 * all processes under registered cgroups without pre-registering each PID.
 * Use `traced_pid_cgroup_gate_allow(traced_map_pid, &cg_id)` in cgroup_helper.h
 * (include common.h first): `traced_map_pid` is the key into `traced_processes`
 * (current tgid or parent tgid on exec enter); `cg_id` is always current task.
 *
 * Probes that act as full-system audit (e.g. procmon) should define
 * NO_CGROUP_FILTER before including common.h to opt out entirely.
 */
#ifndef NO_CGROUP_FILTER
#ifndef MAX_CGROUP_FILTER_ENTRIES
#define MAX_CGROUP_FILTER_ENTRIES 512
#endif

const volatile bool filter_cgroup_enabled = false;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CGROUP_FILTER_ENTRIES);
    __type(key, u64);    /* cgroup inode id from get_cgroup_id_compat() */
    __type(value, u8);   /* 1 = tracked */
} cgroup_filter SEC(".maps");
#endif

#endif
