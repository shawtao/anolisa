// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Network operations probe - monitors bind, listen, connect syscalls

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
    include!(concat!(env!("OUT_DIR"), "/procnet.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/procnet.rs"));
}
use bpf::*;

// Re-export raw types for size calculation
pub type RawProcNetEvent = bpf::procnet_event;

/// User-space network event
#[derive(Debug, Clone)]
pub struct ProcNetEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub cgroup_id: u64,
    pub op: u32,
    pub ret: i32,
    pub comm: String,
    pub port: u16,
    pub addr: u32,
    pub family: u16,
    // Aggregation fields (zero for single events)
    pub count: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub last_ret: i32,
    pub dst_addr: u32,
    pub dst_port: u16,
}

impl ProcNetEvent {
    /// Human-readable operation name
    pub fn op_name(&self) -> &'static str {
        match self.op {
            1 => "bind",
            2 => "listen",
            3 => "connect_error",
            4 => "connect",
            _ => "unknown",
        }
    }

    /// Parse event from raw ring buffer data
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let event_size = std::mem::size_of::<RawProcNetEvent>();
        if data.len() < event_size {
            return None;
        }

        // SAFETY: BPF guarantees proper alignment and layout
        let raw = unsafe { &*(data.as_ptr() as *const RawProcNetEvent) };

        let comm = raw.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        Some(ProcNetEvent {
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            timestamp_ns: config::ktime_to_unix_ns(raw.timestamp_ns),
            cgroup_id: raw.cgroup_id,
            op: raw.op,
            ret: raw.ret,
            comm,
            port: raw.port,
            addr: raw.addr,
            family: raw.family,
            count: 0,
            first_ts: 0,
            last_ts: 0,
            last_ret: 0,
            dst_addr: 0,
            dst_port: 0,
        })
    }

    /// Construct an aggregated connect event from connect_agg_map key/value
    pub fn from_connect_agg(key: &connect_agg_key, val: &connect_agg_val) -> Self {
        let comm = val.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        ProcNetEvent {
            pid: key.pid,
            tid: 0,
            uid: 0,
            timestamp_ns: config::ktime_to_unix_ns(val.last_ts),
            cgroup_id: val.cgroup_id,
            op: 4, // PROCNET_CONNECT_AGG
            ret: 0,
            comm,
            port: 0,
            addr: 0,
            family: 0,
            count: val.count,
            first_ts: config::ktime_to_unix_ns(val.first_ts),
            last_ts: config::ktime_to_unix_ns(val.last_ts),
            last_ret: val.last_ret,
            dst_addr: key.dst_addr,
            dst_port: key.dst_port,
        }
    }
}

// ─── Main struct ──────────────────────────────────────────────────────────────
pub struct ProcNetProbe {
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<ProcnetSkel<'static>>,
    _links: Vec<Link>,
}

impl ProcNetProbe {
    /// Create a new ProcNetProbe that reuses existing traced_processes and ring buffer maps
    pub fn new_with_maps(traced_processes: &MapHandle, rb: &MapHandle) -> Result<Self> {
        Self::new_with_full_maps(traced_processes, rb, None, false)
    }

    /// Create a new ProcNetProbe with optional cgroup_filter map sharing.
    pub fn new_with_full_maps(
        traced_processes: &MapHandle,
        rb: &MapHandle,
        cgroup_filter: Option<&MapHandle>,
        cgroup_filter_enabled: bool,
    ) -> Result<Self> {
        let mut builder = ProcnetSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());

        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let mut open_skel = builder.open().context("failed to open procnet BPF object")?;

        // Mirror the cgroup-filter rodata flag.
        open_skel.rodata_mut().filter_cgroup_enabled = cgroup_filter_enabled;

        // Detect cgroup v2 and pass to BPF via rodata.
        open_skel.rodata_mut().cgroup_v2_mode =
            std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        // Reuse external traced_processes map
        open_skel
            .maps_mut()
            .traced_processes()
            .reuse_fd(traced_processes.as_fd())
            .context("failed to reuse external traced_processes map for procnet")?;

        // Reuse external ring buffer
        open_skel
            .maps_mut()
            .rb()
            .reuse_fd(rb.as_fd())
            .context("failed to reuse external rb map for procnet")?;

        // Reuse external cgroup_filter map (if provided)
        if let Some(map) = cgroup_filter {
            open_skel
                .maps_mut()
                .cgroup_filter()
                .reuse_fd(map.as_fd())
                .context("failed to reuse external cgroup_filter map for procnet")?;
        }

        let skel = open_skel.load().context("failed to load procnet BPF object")?;

        // SAFETY: skel borrows open_object which lives in a Box<MaybeUninit>
        let skel =
            unsafe { Box::from_raw(Box::into_raw(Box::new(skel)) as *mut ProcnetSkel<'static>) };

        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
        })
    }

    /// Attach all tracepoints for network monitoring
    pub fn attach(&mut self) -> Result<()> {
        let mut links = Vec::new();

        // bind enter/exit
        links.push(
            self.skel.progs_mut().trace_bind_enter().attach()
                .context("failed to attach trace_bind_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_bind_exit().attach()
                .context("failed to attach trace_bind_exit")?,
        );

        // listen enter/exit
        links.push(
            self.skel.progs_mut().trace_listen_enter().attach()
                .context("failed to attach trace_listen_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_listen_exit().attach()
                .context("failed to attach trace_listen_exit")?,
        );

        // connect enter/exit
        links.push(
            self.skel.progs_mut().trace_connect_enter().attach()
                .context("failed to attach trace_connect_enter")?,
        );
        links.push(
            self.skel.progs_mut().trace_connect_exit().attach()
                .context("failed to attach trace_connect_exit")?,
        );

        self._links = links;
        Ok(())
    }

    /// Return a MapHandle for the connect_agg_map, used by the flush coroutine
    pub fn connect_agg_map_handle(&self) -> Result<MapHandle> {
        let binding = self.skel.maps();
        let map = binding.connect_agg_map();
        MapHandle::try_clone(map).context("failed to create MapHandle from connect_agg_map")
    }
}

/// Drain the per-CPU `connect_agg_map`: aggregate per-CPU values for each key,
/// emit a [`crate::event::Event::ProcNet`] event, then delete the entry.
pub fn flush_connect_agg(
    map: &MapHandle,
    tx: &crossbeam_channel::Sender<crate::event::Event>,
) {
    let key_size = std::mem::size_of::<connect_agg_key>();
    let val_size = std::mem::size_of::<connect_agg_val>();
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

        let mut agg: connect_agg_val = unsafe { std::mem::zeroed() };
        let mut count: u64 = 0;
        let mut first_ts: u64 = 0;
        let mut last_ts: u64 = 0;
        let mut last_ret: i32 = 0;
        let mut got_meta = false;
        for cpu_val_bytes in &percpu {
            if cpu_val_bytes.len() != val_size {
                continue;
            }
            // SAFETY: BPF guarantees layout; size matches val_size.
            let v: &connect_agg_val =
                unsafe { &*(cpu_val_bytes.as_ptr() as *const connect_agg_val) };
            if v.count == 0 {
                continue;
            }
            count = count.saturating_add(v.count);
            if first_ts == 0 || (v.first_ts != 0 && v.first_ts < first_ts) {
                first_ts = v.first_ts;
            }
            if v.last_ts > last_ts {
                last_ts = v.last_ts;
                last_ret = v.last_ret;
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
            agg.last_ret = last_ret;
            // SAFETY: key_bytes.len() == key_size is checked above.
            let key: &connect_agg_key =
                unsafe { &*(key_bytes.as_ptr() as *const connect_agg_key) };
            let event = ProcNetEvent::from_connect_agg(key, &agg);
            let _ = tx.send(crate::event::Event::ProcNet(event));
        }

        let _ = map.delete(&key_bytes);
    }
}
