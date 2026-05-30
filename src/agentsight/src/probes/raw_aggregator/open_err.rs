// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// User-space OPEN error aggregator for the procfs probe.
//
// The BPF program emits every `openat`-family syscall with `ret < 0` as a
// single ringbuf event by design (see `errors_only_mode` rationale and the
// "errors must always be reported" probe spec). Python interpreters probe
// many non-existent metadata files (`entry_points.txt`, `PKG-INFO`, …) per
// import, which floods downstream consumers with low-value `-ENOENT` rows.
//
// This aggregator runs purely in user space: ringbuf events with
// `op==PROCFS_OPEN && ret<0` are intercepted *before* the unified channel
// send, merged by `(pid, errno, basename)`, and re-emitted as a single
// synthetic `ProcFsEvent` per flush window. The first concrete path that
// hit each key is preserved in `new_path` as a sample for triage.
//
// When the aggregator is not installed, behaviour is identical to before.

use std::{
    collections::HashMap,
    path::Path,
    sync::Mutex,
};

use crate::probes::procfs::ProcFsEvent;

/// Composite key for OPEN error aggregation: `(pid, errno, basename)`.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct OpenErrKey {
    pid: u32,
    errno: i32,
    basename: String,
}

/// Accumulated state for a single `(pid, errno, basename)` window.
#[derive(Debug, Clone)]
struct OpenErrVal {
    count: u64,
    first_ts: u64,
    last_ts: u64,
    cgroup_id: u64,
    tid: u32,
    uid: u32,
    comm: String,
    /// First concrete path observed in this window (kept for triage).
    sample_path: String,
}

/// Sliding-window aggregator for `(pid, errno, basename)` OPEN failures.
///
/// Constructed by `Probes::new_with_cgroup_filter` when procfs is on;
/// shared between the ringbuf callback (writer) and the flush thread
/// (reader/drainer).
pub struct OpenErrAggregator {
    inner: Mutex<HashMap<OpenErrKey, OpenErrVal>>,
}

impl OpenErrAggregator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Try to absorb a freshly parsed `ProcFsEvent`.
    ///
    /// Returns `true` iff the event was an OPEN failure and has been merged
    /// into the aggregator (caller MUST drop it without forwarding).
    /// Returns `false` for any other event — caller forwards it as usual.
    pub fn try_record(&self, e: &ProcFsEvent) -> bool {
        // PROCFS_OPEN == 8; only ret < 0 enters here. Successful opens are
        // never sent via ringbuf (they go through the per-CPU agg map).
        if e.op != 8 || e.ret >= 0 {
            return false;
        }

        // Extract basename; fall back to full path when unavailable
        // (e.g. empty path from probe error).
        let basename = Path::new(&e.path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| e.path.clone());

        let key = OpenErrKey {
            pid: e.pid,
            errno: e.ret,
            basename,
        };

        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            // Mutex poisoning is non-fatal here: drop the event so we never
            // forward an un-aggregated row when aggregation is enabled.
            Err(p) => p.into_inner(),
        };
        let entry = guard.entry(key).or_insert_with(|| OpenErrVal {
            count: 0,
            first_ts: e.timestamp_ns,
            last_ts: e.timestamp_ns,
            cgroup_id: e.cgroup_id,
            tid: e.tid,
            uid: e.uid,
            comm: e.comm.clone(),
            sample_path: e.path.clone(),
        });
        entry.count = entry.count.saturating_add(1);
        if e.timestamp_ns > entry.last_ts {
            entry.last_ts = e.timestamp_ns;
        }
        true
    }

    /// Drain all accumulated entries and emit one synthetic `ProcFsEvent` per key.
    ///
    /// Called by the probes flush thread on the same cadence as
    /// `flush_open_agg`. Safe to call when empty (no-op).
    pub fn flush(&self, tx: &crossbeam_channel::Sender<crate::event::Event>) {
        let drained: Vec<(OpenErrKey, OpenErrVal)> = {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.drain().collect()
        };

        for (key, val) in drained {
            let event = ProcFsEvent {
                pid: key.pid,
                tid: val.tid,
                uid: val.uid,
                timestamp_ns: val.last_ts,
                cgroup_id: val.cgroup_id,
                op: 8, // PROCFS_OPEN (aggregated failure: ret<0, count>=1)
                ret: key.errno,
                comm: val.comm,
                // path carries the basename used as the agg key.
                path: key.basename,
                // new_path carries the first concrete path observed in this
                // window — useful for triage; OPEN events do not otherwise
                // populate this field.
                new_path: val.sample_path,
                count: val.count,
                total_bytes: 0,
                first_ts: val.first_ts,
                last_ts: val.last_ts,
            };
            let _ = tx.send(crate::event::Event::ProcFs(event));
        }
    }
}

impl Default for OpenErrAggregator {
    fn default() -> Self {
        Self::new()
    }
}
