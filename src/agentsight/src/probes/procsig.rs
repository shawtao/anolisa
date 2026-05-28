// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Signal and process control probe - monitors setpgid, setsid, kill, fork

use crate::config;
use anyhow::{Context, Result};
use libbpf_rs::{
    Link, MapHandle,
    skel::{OpenSkel, SkelBuilder},
};
use std::{
    mem::MaybeUninit,
    os::fd::AsFd,
};

// ─── Generated skeleton ───────────────────────────────────────────────────────
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/procsig.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/procsig.rs"));
}
use bpf::*;

// Re-export raw types for size calculation
pub type RawProcSigEvent = bpf::procsig_event;

/// User-space signal/process control event
#[derive(Debug, Clone)]
pub struct ProcSigEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub op: u32,
    pub ret: i32,
    pub comm: String,
    pub target_pid: u32,
    pub signal: u32,
    // Aggregation fields (zero for single events)
    pub count: u64,
    pub first_ts: u64,
    pub last_ts: u64,
}

impl ProcSigEvent {
    /// Human-readable operation name
    pub fn op_name(&self) -> &'static str {
        match self.op {
            1 => "setpgid",
            2 => "setsid",
            3 => "kill",
            4 => "fork_fail",  // fork-family syscall failure (clone/clone3/vfork ret<0)
            5 => "fork",
            _ => "unknown",
        }
    }

    /// Parse event from raw ring buffer data
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let event_size = std::mem::size_of::<RawProcSigEvent>();
        if data.len() < event_size {
            return None;
        }

        // SAFETY: BPF guarantees proper alignment and layout
        let raw = unsafe { &*(data.as_ptr() as *const RawProcSigEvent) };

        let comm = raw.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        Some(ProcSigEvent {
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            timestamp_ns: config::ktime_to_unix_ns(raw.timestamp_ns),
            cgroup_id: raw.cgroup_id,
            op: raw.op,
            ret: raw.ret,
            comm,
            target_pid: raw.target_pid,
            signal: raw.signal,
            count: 0,
            first_ts: 0,
            last_ts: 0,
        })
    }

    /// Construct an aggregated fork event from fork_agg_map key/value
    pub fn from_fork_agg(key: &fork_agg_key, val: &fork_agg_val) -> Self {
        let comm = val.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        ProcSigEvent {
            pid: key.parent_pid,
            tid: 0,
            uid: 0,
            timestamp_ns: config::ktime_to_unix_ns(val.last_ts),
            cgroup_id: val.cgroup_id,
            op: 5, // PROCSIG_FORK_AGG
            ret: 0,
            comm,
            target_pid: 0,
            signal: 0,
            count: val.count,
            first_ts: config::ktime_to_unix_ns(val.first_ts),
            last_ts: config::ktime_to_unix_ns(val.last_ts),
        }
    }
}

// ─── Main struct ──────────────────────────────────────────────────────────────
pub struct ProcSigProbe {
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<ProcsigSkel<'static>>,
    _links: Vec<Link>,
}

impl ProcSigProbe {
    /// Create a new ProcSigProbe that reuses existing traced_processes and ring buffer maps
    pub fn new_with_maps(traced_processes: &MapHandle, rb: &MapHandle) -> Result<Self> {
        Self::new_with_full_maps(traced_processes, rb, None, false, false)
    }

    /// Create a new ProcSigProbe with optional cgroup_filter map sharing.
    pub fn new_with_full_maps(
        traced_processes: &MapHandle,
        rb: &MapHandle,
        cgroup_filter: Option<&MapHandle>,
        cgroup_filter_enabled: bool,
        errors_only: bool,
    ) -> Result<Self> {
        // `errors_only` only drives rodata-based suppression of success events for
        // setpgid/setsid/kill/fork. Fork-failure capture (clone/clone3/vfork
        // sys_exit) is always attached in attach() below.
        let mut builder = ProcsigSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());

        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let mut open_skel = builder.open().context("failed to open procsig BPF object")?;

        // Mirror the cgroup-filter rodata flag.
        open_skel.rodata_mut().filter_cgroup_enabled = cgroup_filter_enabled;

        // errors_only: only ret < 0 syscalls emitted; fork tracepoint suppressed.
        open_skel.rodata_mut().errors_only_mode = errors_only;

        // Detect cgroup v2 and pass to BPF via rodata.
        open_skel.rodata_mut().cgroup_v2_mode =
            std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        // Reuse external traced_processes map
        open_skel
            .maps_mut()
            .traced_processes()
            .reuse_fd(traced_processes.as_fd())
            .context("failed to reuse external traced_processes map for procsig")?;

        // Reuse external ring buffer
        open_skel
            .maps_mut()
            .rb()
            .reuse_fd(rb.as_fd())
            .context("failed to reuse external rb map for procsig")?;

        // Reuse external cgroup_filter map (if provided)
        if let Some(map) = cgroup_filter {
            open_skel
                .maps_mut()
                .cgroup_filter()
                .reuse_fd(map.as_fd())
                .context("failed to reuse external cgroup_filter map for procsig")?;
        }

        let skel = open_skel.load().context("failed to load procsig BPF object")?;

        // SAFETY: skel borrows open_object which lives in a Box<MaybeUninit>
        let skel =
            unsafe { Box::from_raw(Box::into_raw(Box::new(skel)) as *mut ProcsigSkel<'static>) };

        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
        })
    }

    /// Attach all tracepoints for signal/process control monitoring
    pub fn attach(&mut self) -> Result<()> {
        let mut links = Vec::new();

        // setpgid enter/exit
        links.push(
            self.skel.progs_mut().trace_setpgid_enter().attach()
                .context("failed to attach trace_setpgid_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_setpgid_exit().attach()
                .context("failed to attach trace_setpgid_exit")?,
        );

        // setsid enter/exit
        links.push(
            self.skel.progs_mut().trace_setsid_enter().attach()
                .context("failed to attach trace_setsid_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_setsid_exit().attach()
                .context("failed to attach trace_setsid_exit")?,
        );

        // kill enter/exit
        links.push(
            self.skel.progs_mut().trace_kill_enter().attach()
                .context("failed to attach trace_kill_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_kill_exit().attach()
                .context("failed to attach trace_kill_exit")?,
        );

        // fork (single tracepoint, not enter/exit pair)
        links.push(
            self.skel.progs_mut().trace_fork().attach()
                .context("failed to attach trace_fork")?,
        );

        // fork-failure paths: always attached regardless of errors_only mode.
        // handle_fork_fail() only emits when ret<0, so success forks are filtered
        // at the source; the cost is one branch per clone/clone3/vfork syscall.
        links.push(
            self.skel.progs_mut().trace_clone_exit().attach()
                .context("failed to attach trace_clone_exit")?,
        );
        links.push(
            self.skel.progs_mut().trace_clone3_exit().attach()
                .context("failed to attach trace_clone3_exit")?,
        );
        links.push(
            self.skel.progs_mut().trace_vfork_exit().attach()
                .context("failed to attach trace_vfork_exit")?,
        );

        // Legacy fork(2): musl-static (busybox) on x86_64 dispatches fork()
        // directly to __NR_fork rather than clone. arm64 / riscv64 do not
        // define __NR_fork, so attach must be soft-fail.
        match self.skel.progs_mut().trace_fork_exit().attach() {
            Ok(l) => links.push(l),
            Err(e) => log::warn!(
                "procsig: skipping legacy tracepoint sys_exit_fork (likely unsupported on this arch): {e}"
            ),
        }
        log::info!("procsig: fork-failure capture enabled (clone/clone3/vfork/fork sys_exit; always-on)");

        self._links = links;
        Ok(())
    }

    /// Return a MapHandle for the fork_agg_map, used by the flush coroutine
    pub fn fork_agg_map_handle(&self) -> Result<MapHandle> {
        let binding = self.skel.maps();
        let map = binding.fork_agg_map();
        MapHandle::try_clone(map).context("failed to create MapHandle from fork_agg_map")
    }
}

/// Drain the per-CPU `fork_agg_map`: aggregate per-CPU values for each key,
/// emit a [`crate::event::Event::ProcSig`] event, then delete the entry.
pub fn flush_fork_agg(
    map: &MapHandle,
    tx: &crossbeam_channel::Sender<crate::event::Event>,
) {
    let key_size = std::mem::size_of::<fork_agg_key>();
    let val_size = std::mem::size_of::<fork_agg_val>();
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

        let mut agg: fork_agg_val = unsafe { std::mem::zeroed() };
        let mut count: u64 = 0;
        let mut first_ts: u64 = 0;
        let mut last_ts: u64 = 0;
        let mut got_meta = false;
        for cpu_val_bytes in &percpu {
            if cpu_val_bytes.len() != val_size {
                continue;
            }
            // SAFETY: BPF guarantees layout; size matches val_size.
            let v: &fork_agg_val =
                unsafe { &*(cpu_val_bytes.as_ptr() as *const fork_agg_val) };
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
                got_meta = true;
            }
        }

        if count > 0 {
            agg.count = count;
            agg.first_ts = first_ts;
            agg.last_ts = last_ts;
            // SAFETY: key_bytes.len() == key_size is checked above.
            let key: &fork_agg_key =
                unsafe { &*(key_bytes.as_ptr() as *const fork_agg_key) };
            let event = ProcSigEvent::from_fork_agg(key, &agg);
            let _ = tx.send(crate::event::Event::ProcSig(event));
        }

        let _ = map.delete(&key_bytes);
    }
}
