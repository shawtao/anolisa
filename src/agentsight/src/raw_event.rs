// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Unified raw event structure for the raw_events.db storage channel.

use crate::probes::filewatch::FileWatchEvent;
use crate::probes::filewrite::FileWriteEvent;
use crate::probes::procfs::ProcFsEvent;
use crate::probes::procnet::ProcNetEvent;
use crate::probes::procsig::ProcSigEvent;
use crate::probes::proctrace::ProcEventHeader;
use crate::probes::raw_aggregator::tcp::TcpDerivedEvent;
use crate::probes::tcpdiag::TcpDiagEvent;
use crate::probes::udpdns::UdpDnsEvent;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Unified raw event stored in raw_events.db.
///
/// All probe-specific events are normalized into this structure before
/// being written to the SQLite batch writer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RawEvent {
    /// DB auto-increment ID; None before insertion.
    pub id: Option<i64>,
    /// Unix millisecond timestamp.
    pub timestamp_ms: i64,
    /// Event source: "procfs" | "procnet" | "procsig" | "proctrace" | "filewatch" | "filewrite"
    pub source: String,
    pub pid: u32,
    /// Parent PID enriched by PidTable; 0 when unknown.
    pub ppid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: String,
    pub cgroup_id: u64,
    /// Human-readable operation name.
    pub op: String,
    pub ret: i32,
    /// JSON string containing event-specific fields.
    pub data_json: String,
    /// Aggregation count (1 for non-aggregated events).
    pub count: u64,
}

// ─── Helper ─────────────────────────────────────────────────────────────────

/// Convert a Unix nanosecond timestamp to Unix milliseconds.
fn ns_to_unix_ms(unix_ns: u64) -> i64 {
    (unix_ns / 1_000_000) as i64
}

/// Extract comm string from a ProcEventHeader's comm field.
fn header_comm(header: &ProcEventHeader) -> String {
    let bytes: Vec<u8> = header
        .comm
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ─── Conversion functions ───────────────────────────────────────────────────

impl RawEvent {
    /// Convert a ProcFsEvent into a RawEvent.
    pub fn from_procfs(e: &ProcFsEvent, ppid: u32) -> Self {
        let data_json = if e.new_path.is_empty() {
            serde_json::json!({
                "path": e.path,
                "total_bytes": e.total_bytes,
            })
        } else {
            serde_json::json!({
                "path": e.path,
                "new_path": e.new_path,
                "total_bytes": e.total_bytes,
            })
        };

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "procfs".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: e.op_name().to_owned(),
            ret: e.ret,
            data_json: data_json.to_string(),
            count: if e.count > 0 { e.count } else { 1 },
        }
    }

    /// Convert a ProcNetEvent into a RawEvent.
    pub fn from_procnet(e: &ProcNetEvent, ppid: u32) -> Self {
        let addr_str = Ipv4Addr::from(e.addr.to_be()).to_string();
        let dst_addr_str = Ipv4Addr::from(e.dst_addr.to_be()).to_string();

        let data_json = serde_json::json!({
            "addr": addr_str,
            "port": e.port,
            "dst_addr": dst_addr_str,
            "dst_port": e.dst_port,
            "family": e.family_name(),
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "procnet".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: e.op_name().to_owned(),
            ret: e.ret,
            data_json: data_json.to_string(),
            count: if e.count > 0 { e.count } else { 1 },
        }
    }

    /// Convert a ProcSigEvent into a RawEvent.
    pub fn from_procsig(e: &ProcSigEvent, ppid: u32) -> Self {
        let data_json = serde_json::json!({
            "target_pid": e.target_pid,
            "signal": e.signal,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "procsig".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: e.op_name().to_owned(),
            ret: e.ret,
            data_json: data_json.to_string(),
            count: if e.count > 0 { e.count } else { 1 },
        }
    }

    /// Convert a ProcTrace exec event into a RawEvent.
    ///
    /// Takes the BPF event header plus the parsed filename and args strings.
    pub fn from_proctrace_exec(
        header: &ProcEventHeader,
        filename: &str,
        args: &str,
        ppid: u32,
    ) -> Self {
        let data_json = serde_json::json!({
            "filename": filename,
            "args": args,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(header.timestamp_ns),
            source: "proctrace".to_owned(),
            pid: header.pid,
            ppid,
            tid: header.tid,
            uid: header.uid,
            comm: header_comm(header),
            cgroup_id: header.cgroup_id,
            op: "exec".to_owned(),
            ret: 0,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a ProcTrace exec-failure event into a RawEvent.
    ///
    /// errors-only: `ret` carries the negative errno (e.g. -2 for ENOENT),
    /// matching the `RawEvent` error-code dual-field convention. `data_json`
    /// retains the attempted filename and execveat flags for downstream
    /// `(container, errno, basename)` aggregation in containersight.
    pub fn from_proctrace_exec_fail(
        header: &ProcEventHeader,
        error_code: i32,
        flags: u32,
        filename: &str,
        ppid: u32,
    ) -> Self {
        let data_json = serde_json::json!({
            "filename": filename,
            "flags": flags,
            "errno": -error_code,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(header.timestamp_ns),
            source: "proctrace".to_owned(),
            pid: header.pid,
            ppid,
            tid: header.tid,
            uid: header.uid,
            comm: header_comm(header),
            cgroup_id: header.cgroup_id,
            op: "execve_fail".to_owned(),
            ret: error_code,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a ProcTrace exit event into a RawEvent.
    pub fn from_proctrace_exit(
        header: &ProcEventHeader,
        exit_code: i32,
        ppid: u32,
    ) -> Self {
        let data_json = serde_json::json!({
            "exit_code": exit_code,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(header.timestamp_ns),
            source: "proctrace".to_owned(),
            pid: header.pid,
            ppid,
            tid: header.tid,
            uid: header.uid,
            comm: header_comm(header),
            cgroup_id: header.cgroup_id,
            op: "exit".to_owned(),
            ret: exit_code,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a FileWatchEvent into a RawEvent.
    pub fn from_filewatch(e: &FileWatchEvent, ppid: u32) -> Self {
        let data_json = serde_json::json!({
            "filename": e.filename,
            "flags": e.flags,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "filewatch".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: "open".to_owned(),
            ret: 0,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a FileWriteEvent into a RawEvent.
    pub fn from_filewrite(e: &FileWriteEvent, ppid: u32) -> Self {
        let data_json = serde_json::json!({
            "filename": e.filename,
            "write_size": e.write_size,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "filewrite".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: "write".to_owned(),
            ret: 0,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a UdpDnsEvent into a RawEvent.
    ///
    /// Only intended for the cgroup-filter "correlation" channel (cgroup_id != 0).
    /// Discovery-channel events (cgroup_id == 0) are still consumed by the
    /// AgentScanner in unified.rs and MUST NOT be persisted via this path,
    /// otherwise raw_events.db would be polluted with system-wide DNS noise.
    pub fn from_udpdns(e: &UdpDnsEvent, ppid: u32) -> Self {
        let data_json = serde_json::json!({
            "domain": e.domain,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "udpdns".to_owned(),
            pid: e.pid,
            ppid,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: "dns_query".to_owned(),
            ret: 0,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a base TcpDiagEvent (RETRANSMIT / RESET_RECV) into a RawEvent.
    pub fn from_tcpdiag(e: &TcpDiagEvent, ppid: u32) -> Self {
        let saddr_str = format_addr(e.family, &e.saddr);
        let daddr_str = format_addr(e.family, &e.daddr);

        let data_json = serde_json::json!({
            "sock_cookie": e.sock_cookie,
            "family": e.family_name(),
            "saddr": saddr_str,
            "sport": e.sport,
            "daddr": daddr_str,
            "dport": e.dport,
            "segs_out": e.segs_out,
            "total_retrans": e.total_retrans,
        });

        Self {
            id: None,
            timestamp_ms: ns_to_unix_ms(e.timestamp_ns),
            source: "tcpdiag".to_owned(),
            pid: e.pid,
            ppid,
            tid: 0,
            uid: 0,
            comm: e.comm.clone(),
            cgroup_id: e.cgroup_id,
            op: e.op_name().to_owned(),
            ret: 0,
            data_json: data_json.to_string(),
            count: 1,
        }
    }

    /// Convert a derived TcpDerivedEvent (HighRetrans) into a RawEvent.
    /// `count` carries burst size for HighRetrans.
    pub fn from_tcpdiag_derived(e: &TcpDerivedEvent, ppid: u32) -> Self {
        match e {
            TcpDerivedEvent::HighRetrans {
                cookie, cgroup_id, pid, comm, timestamp_ns,
                family, sport, dport, saddr, daddr,
                retrans_count, window_ms, total_retrans,
            } => {
                let saddr_str = format_addr(*family, saddr);
                let daddr_str = format_addr(*family, daddr);
                let data_json = serde_json::json!({
                    "sock_cookie": cookie,
                    "family": format_family(*family),
                    "saddr": saddr_str,
                    "sport": sport,
                    "daddr": daddr_str,
                    "dport": dport,
                    "retrans_count": retrans_count,
                    "window_ms": window_ms,
                    "total_retrans": total_retrans,
                });
                Self {
                    id: None,
                    timestamp_ms: ns_to_unix_ms(*timestamp_ns),
                    source: "tcpdiag".to_owned(),
                    pid: *pid,
                    ppid,
                    tid: 0,
                    uid: 0,
                    comm: comm.clone(),
                    cgroup_id: *cgroup_id,
                    op: "tcp_high_retrans".to_owned(),
                    ret: 0,
                    data_json: data_json.to_string(),
                    count: *retrans_count as u64,
                }
            }
        }
    }
}

fn format_addr(family: u16, raw: &[u8; 16]) -> String {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;
    match family {
        AF_INET => Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
        AF_INET6 => Ipv6Addr::from(*raw).to_string(),
        _ => String::new(),
    }
}

fn format_family(family: u16) -> &'static str {
    match family {
        2  => "AF_INET(IPv4)",
        10 => "AF_INET6(IPv6)",
        _  => "AF_UNKNOWN",
    }
}
