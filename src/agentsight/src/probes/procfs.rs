// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Filesystem operations probe — delete, rename, mkdir, truncate, chdir.
// write / pwrite64 / writev: disabled in procfs.bpf.c (#if 0). User-space
// attach/flush for writes is kept below as comments — uncomment when enabling BPF.

use crate::config;
use anyhow::{Context, Result};
use libbpf_rs::{
    Link, MapHandle,
    skel::{OpenSkel, SkelBuilder},
};
use std::{
    collections::HashMap,
    mem::MaybeUninit,
    os::fd::AsFd,
    path::Path,
    sync::Mutex,
};

// ─── Generated skeleton ───────────────────────────────────────────────────────
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/procfs.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/procfs.rs"));
}
use bpf::*;

// Re-export raw types for size calculation
pub type RawProcFsEvent = bpf::procfs_event;

/// User-space filesystem event
#[derive(Debug, Clone)]
pub struct ProcFsEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub op: u32,
    pub ret: i32,
    pub comm: String,
    pub path: String,
    pub new_path: String,
    // Aggregation fields (zero for single events)
    pub count: u64,
    pub total_bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
}

impl ProcFsEvent {
    /// Human-readable operation name
    pub fn op_name(&self) -> &'static str {
        match self.op {
            1 => "delete",
            2 => "rename",
            3 => "mkdir",
            4 => "truncate",
            5 => "chdir",
            6 => "write_error",
            7 => "write",
            8 => "open",
            9 => "rmdir",
            _ => "unknown",
        }
    }

    /// Parse event from raw ring buffer data
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let event_size = std::mem::size_of::<RawProcFsEvent>();
        if data.len() < event_size {
            return None;
        }

        // SAFETY: BPF guarantees proper alignment and layout
        let raw = unsafe { &*(data.as_ptr() as *const RawProcFsEvent) };

        let comm = raw.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        let path = raw.path
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let path = String::from_utf8_lossy(&path).into_owned();

        let new_path = raw.new_path
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let new_path = String::from_utf8_lossy(&new_path).into_owned();

        Some(ProcFsEvent {
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            timestamp_ns: config::ktime_to_unix_ns(raw.timestamp_ns),
            cgroup_id: raw.cgroup_id,
            op: raw.op,
            ret: raw.ret,
            comm,
            path,
            new_path,
            count: raw.count as u64,
            total_bytes: 0,
            first_ts: 0,
            last_ts: 0,
        })
    }

    /// Construct an aggregated open event from open_agg_map key/value.
    /// One PROCFS_OPEN_AGG event per unique (pid, path) per flush window.
    pub fn from_open_agg(key: &open_agg_key, val: &open_agg_val) -> Self {
        let comm = val.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        let path = key.path
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let path = String::from_utf8_lossy(&path).into_owned();

        ProcFsEvent {
            pid: key.pid,
            tid: val.tid,
            uid: val.uid,
            timestamp_ns: config::ktime_to_unix_ns(val.last_ts),
            cgroup_id: val.cgroup_id,
            op: 8, // PROCFS_OPEN (aggregated success: ret==0, count>=1)
            ret: 0,
            comm,
            path,
            new_path: String::new(),
            count: val.count as u64,
            total_bytes: 0,
            first_ts: config::ktime_to_unix_ns(val.first_ts),
            last_ts: config::ktime_to_unix_ns(val.last_ts),
        }
    }

    /*
    /// Construct an aggregated write event from write_agg_map key/value
    /// (re-enable when procfs.bpf.c write section uses #if 1)
    pub fn from_write_agg(key: &write_agg_key, val: &write_agg_val) -> Self {
        let comm = val.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        ProcFsEvent {
            pid: key.pid,
            tid: 0,
            uid: 0,
            timestamp_ns: config::ktime_to_unix_ns(val.last_ts),
            cgroup_id: val.cgroup_id,
            op: 7, // PROCFS_WRITE_AGG
            ret: 0,
            comm,
            path: String::new(),
            new_path: String::new(),
            count: val.count,
            total_bytes: val.total_bytes,
            first_ts: config::ktime_to_unix_ns(val.first_ts),
            last_ts: config::ktime_to_unix_ns(val.last_ts),
        }
    }
    */
}

// ─── Main struct ──────────────────────────────────────────────────────────────
pub struct ProcFsProbe {
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<ProcfsSkel<'static>>,
    _links: Vec<Link>,
}

impl ProcFsProbe {
    /// Create a new ProcFsProbe that reuses existing traced_processes and ring buffer maps
    pub fn new_with_maps(traced_processes: &MapHandle, rb: &MapHandle) -> Result<Self> {
        Self::new_with_full_maps(traced_processes, rb, None, false, false)
    }

    /// Create a new ProcFsProbe with optional cgroup_filter map sharing.
    pub fn new_with_full_maps(
        traced_processes: &MapHandle,
        rb: &MapHandle,
        cgroup_filter: Option<&MapHandle>,
        cgroup_filter_enabled: bool,
        errors_only: bool,
    ) -> Result<Self> {
        let mut builder = ProcfsSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());

        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let mut open_skel = builder.open().context("failed to open procfs BPF object")?;

        // Mirror the cgroup-filter rodata flag.
        open_skel.rodata_mut().filter_cgroup_enabled = cgroup_filter_enabled;

        // errors_only: only ret < 0 syscalls emitted; openat success aggregation suppressed.
        open_skel.rodata_mut().errors_only_mode = errors_only;

        // Detect cgroup v2 and pass to BPF via rodata.
        open_skel.rodata_mut().cgroup_v2_mode =
            std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        // Reuse external traced_processes map
        open_skel
            .maps_mut()
            .traced_processes()
            .reuse_fd(traced_processes.as_fd())
            .context("failed to reuse external traced_processes map for procfs")?;

        // Reuse external ring buffer
        open_skel
            .maps_mut()
            .rb()
            .reuse_fd(rb.as_fd())
            .context("failed to reuse external rb map for procfs")?;

        // Reuse external cgroup_filter map (if provided)
        if let Some(map) = cgroup_filter {
            open_skel
                .maps_mut()
                .cgroup_filter()
                .reuse_fd(map.as_fd())
                .context("failed to reuse external cgroup_filter map for procfs")?;
        }

        let skel = open_skel.load().context("failed to load procfs BPF object")?;

        // SAFETY: skel borrows open_object which lives in a Box<MaybeUninit>
        let skel =
            unsafe { Box::from_raw(Box::into_raw(Box::new(skel)) as *mut ProcfsSkel<'static>) };

        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
        })
    }

    /// Attach all tracepoints for filesystem monitoring
    pub fn attach(&mut self) -> Result<()> {
        let mut links = Vec::new();

        // unlinkat enter/exit
        links.push(
            self.skel.progs_mut().trace_unlinkat_enter().attach()
                .context("failed to attach trace_unlinkat_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_unlinkat_exit().attach()
                .context("failed to attach trace_unlinkat_exit")?,
        );

        // renameat2 enter/exit
        links.push(
            self.skel.progs_mut().trace_renameat2_enter().attach()
                .context("failed to attach trace_renameat2_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_renameat2_exit().attach()
                .context("failed to attach trace_renameat2_exit")?,
        );

        // mkdirat enter/exit
        links.push(
            self.skel.progs_mut().trace_mkdirat_enter().attach()
                .context("failed to attach trace_mkdirat_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_mkdirat_exit().attach()
                .context("failed to attach trace_mkdirat_exit")?,
        );

        // ftruncate enter/exit
        links.push(
            self.skel.progs_mut().trace_ftruncate_enter().attach()
                .context("failed to attach trace_ftruncate_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_ftruncate_exit().attach()
                .context("failed to attach trace_ftruncate_exit")?,
        );

        // chdir enter/exit
        links.push(
            self.skel.progs_mut().trace_chdir_enter().attach()
                .context("failed to attach trace_chdir_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_chdir_exit().attach()
                .context("failed to attach trace_chdir_exit")?,
        );

        // openat enter/exit
        links.push(
            self.skel.progs_mut().trace_openat_enter().attach()
                .context("failed to attach trace_openat_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_openat_exit().attach()
                .context("failed to attach trace_openat_exit")?,
        );

        // Legacy *non-`*at`* syscalls. busybox-static / musl-static binaries
        // call these directly, so the *at-only attaches above miss them.
        // open / creat share PROCFS_OPEN aggregation with openat.
        //
        // These syscalls do not exist on arm64 (the architecture only ships the
        // *at variants), so attach may fail with -ENOENT there. Treat each
        // failure as non-fatal: warn once and skip — the *at handlers above
        // already cover the standard glibc/aarch64 path.
        let try_attach = |res: anyhow::Result<libbpf_rs::Link>,
                          name: &'static str,
                          links: &mut Vec<Link>| {
            match res {
                Ok(l) => links.push(l),
                Err(e) => log::warn!(
                    "procfs: skipping legacy tracepoint {name} (likely unsupported on this arch): {e}"
                ),
            }
        };
        try_attach(
            self.skel.progs_mut().trace_open_enter().attach().map_err(Into::into),
            "sys_enter_open",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_open_exit().attach().map_err(Into::into),
            "sys_exit_open",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_creat_enter().attach().map_err(Into::into),
            "sys_enter_creat",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_creat_exit().attach().map_err(Into::into),
            "sys_exit_creat",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_unlink_enter().attach().map_err(Into::into),
            "sys_enter_unlink",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_unlink_exit().attach().map_err(Into::into),
            "sys_exit_unlink",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_rmdir_enter().attach().map_err(Into::into),
            "sys_enter_rmdir",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_rmdir_exit().attach().map_err(Into::into),
            "sys_exit_rmdir",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_mkdir_enter().attach().map_err(Into::into),
            "sys_enter_mkdir",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_mkdir_exit().attach().map_err(Into::into),
            "sys_exit_mkdir",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_rename_enter().attach().map_err(Into::into),
            "sys_enter_rename",
            &mut links,
        );
        try_attach(
            self.skel.progs_mut().trace_rename_exit().attach().map_err(Into::into),
            "sys_exit_rename",
            &mut links,
        );

        /*
        // write / pwrite64 / writev enter+exit (enable with procfs.bpf.c #if 1)
        links.push(
            self.skel.progs_mut().trace_write_enter().attach()
                .context("failed to attach trace_write_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_write_exit().attach()
                .context("failed to attach trace_write_exit")?,
        );
        links.push(
            self.skel.progs_mut().trace_pwrite64_enter().attach()
                .context("failed to attach trace_pwrite64_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_pwrite64_exit().attach()
                .context("failed to attach trace_pwrite64_exit")?,
        );
        links.push(
            self.skel.progs_mut().trace_writev_enter().attach()
                .context("failed to attach trace_writev_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_writev_exit().attach()
                .context("failed to attach trace_writev_exit")?,
        );
        */

        self._links = links;
        Ok(())
    }

    /// Return a MapHandle for the open_agg_map, used by the flush coroutine
    pub fn open_agg_map_handle(&self) -> Result<MapHandle> {
        let binding = self.skel.maps();
        let map = binding.open_agg_map();
        MapHandle::try_clone(map).context("failed to create MapHandle from open_agg_map")
    }

    /*
    /// Return a MapHandle for the write_agg_map, used by the flush coroutine
    pub fn write_agg_map_handle(&self) -> Result<MapHandle> {
        let binding = self.skel.maps();
        let map = binding.write_agg_map();
        MapHandle::try_clone(map).context("failed to create MapHandle from write_agg_map")
    }
    */
}

// ─── User-space OPEN error aggregator ────────────────────────────────────────
//
// The BPF program emits every `openat`-family syscall with `ret < 0` as a
// single ringbuf event by design (see `errors_only_mode` rationale and the
// "errors must always be reported" probe spec). Python interpreters probe many
// non-existent metadata files (`entry_points.txt`, `PKG-INFO`, …) per import,
// which floods downstream consumers with low-value `-ENOENT` rows.
//
// This aggregator runs purely in user space: ringbuf events with
// `op==PROCFS_OPEN && ret<0` are intercepted *before* the unified channel send,
// merged by `(pid, errno, basename)`, and re-emitted as a single synthetic
// `ProcFsEvent` per flush window. The first concrete path that hit each key
// is preserved in `new_path` as a sample for triage.
//
// When the aggregator is not installed, behaviour is identical to before.

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
/// Constructed by [`Probes::new_with_cgroup_filter`] when
/// `procfs_open_err_agg` is on; shared between the ringbuf callback (writer)
/// and the flush thread (reader/drainer).
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

/// Drain the per-CPU `open_agg_map`: aggregate per-CPU values for each key,
/// emit a [`crate::event::Event::ProcFs`] event with op=PROCFS_OPEN_AGG, then delete the entry.
///
/// Safe to call when the map is empty (becomes a no-op).
pub fn flush_open_agg(
    map: &MapHandle,
    tx: &crossbeam_channel::Sender<crate::event::Event>,
) {
    let key_size = std::mem::size_of::<open_agg_key>();
    let val_size = std::mem::size_of::<open_agg_val>();
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key_bytes in keys {
        if key_bytes.len() != key_size {
            continue;
        }
        let percpu = match map.lookup_percpu(&key_bytes, libbpf_rs::MapFlags::ANY) {
            Ok(Some(v)) => v,
            _ => {
                let _ = map.delete(&key_bytes);
                continue;
            }
        };

        let mut agg: open_agg_val = unsafe { std::mem::zeroed() };
        let mut count: u32 = 0;
        let mut first_ts: u64 = 0;
        let mut last_ts: u64 = 0;
        let mut got_meta = false;
        for cpu_val_bytes in &percpu {
            if cpu_val_bytes.len() != val_size {
                continue;
            }
            // SAFETY: BPF guarantees layout; size matches val_size.
            let v: &open_agg_val =
                unsafe { &*(cpu_val_bytes.as_ptr() as *const open_agg_val) };
            if v.count == 0 {
                continue;
            }
            count = count.saturating_add(v.count);
            if first_ts == 0 || (v.first_ts != 0 && v.first_ts < first_ts) {
                first_ts = v.first_ts;
            }
            if v.last_ts > last_ts {
                last_ts = v.last_ts;
            }
            if !got_meta {
                agg.comm = v.comm;
                agg.cgroup_id = v.cgroup_id;
                agg.tid = v.tid;
                agg.uid = v.uid;
                got_meta = true;
            }
        }

        if count > 0 {
            agg.count = count;
            agg.first_ts = first_ts;
            agg.last_ts = last_ts;
            // SAFETY: key_bytes.len() == key_size is checked above.
            let key: &open_agg_key =
                unsafe { &*(key_bytes.as_ptr() as *const open_agg_key) };
            let event = ProcFsEvent::from_open_agg(key, &agg);
            let _ = tx.send(crate::event::Event::ProcFs(event));
        }

        let _ = map.delete(&key_bytes);
    }
}
