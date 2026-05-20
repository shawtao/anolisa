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

use std::net::Ipv4Addr;

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
            "family": e.family,
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
}
