// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// TCP stack-level diagnostic probe (kernel side: src/bpf/tcpdiag.bpf.c).
//
// Captures two base events:
//   * RETRANSMIT   — every tcp_retransmit_skb on a tracked socket
//   * RESET_RECV   — every TCP RST received on a tracked socket
//
// inet_sock_set_state runs in meta-only mode (maintains sock_cgid_map for
// retransmit/reset lookup) and does not emit ringbuf events.
//
// User-space side (this file) does:
//   - skel load + tracepoint attach + ringbuf reuse (shared rb owned by
//     proctrace; identical pattern to procnet/udpdns).
//   - raw bytes -> TcpDiagEvent decoding.
//   - `TcpAggregator` integration: pass each base event through the
//     aggregator and surface derived signals (HighRetrans).

use crate::config;
use anyhow::{Context, Result};
use libbpf_rs::{
    Link, MapHandle,
    skel::{OpenSkel, SkelBuilder},
};
use std::{
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::Arc,
};

use super::raw_aggregator::tcp::{
    TcpAggregator, TcpAggregatorConfig, TcpDerivedEvent, TcpDiagOp, TcpEventInput,
};

// ─── Generated skeleton ───────────────────────────────────────────────────────
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/tcpdiag.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/tcpdiag.rs"));
}
use bpf::*;

/// Re-export raw BPF event type for size calculation in the unified poller.
pub type RawTcpDiagEvent = bpf::tcpdiag_event;

/// User-space tcpdiag base event.
#[derive(Debug, Clone)]
pub struct TcpDiagEvent {
    pub op: TcpDiagOp,
    pub timestamp_ns: u64,        // Unix epoch ns (already converted)
    pub cgroup_id: u64,
    pub sock_cookie: u64,
    pub pid: u32,
    pub comm: String,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub segs_out: u32,
    pub total_retrans: u32,
}

impl TcpDiagEvent {
    /// Operation name for logs / DB.
    pub fn op_name(&self) -> &'static str {
        self.op.as_str()
    }

    /// Address-family name.
    pub fn family_name(&self) -> &'static str {
        match self.family {
            2  => "AF_INET(IPv4)",
            10 => "AF_INET6(IPv6)",
            _  => "AF_UNKNOWN",
        }
    }

    /// Decode a raw ringbuf payload into a TcpDiagEvent.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let event_size = std::mem::size_of::<RawTcpDiagEvent>();
        if data.len() < event_size {
            return None;
        }
        // SAFETY: BPF guarantees alignment + layout.
        let raw = unsafe { &*(data.as_ptr() as *const RawTcpDiagEvent) };

        let op = TcpDiagOp::from_raw(raw.op)?;
        let comm_bytes: Vec<u8> = raw
            .comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        let comm = String::from_utf8_lossy(&comm_bytes).into_owned();

        Some(TcpDiagEvent {
            op,
            timestamp_ns: config::ktime_to_unix_ns(raw.timestamp_ns),
            cgroup_id: raw.cgroup_id,
            sock_cookie: raw.sock_cookie,
            pid: raw.pid,
            comm,
            family: raw.family,
            sport: raw.sport,
            dport: raw.dport,
            saddr: raw.saddr,
            daddr: raw.daddr,
            segs_out: raw.segs_out,
            total_retrans: raw.total_retrans,
        })
    }

    /// Build the aggregator input view (no allocation beyond comm clone).
    pub fn to_agg_input(&self) -> TcpEventInput {
        TcpEventInput {
            op: self.op,
            timestamp_ns: self.timestamp_ns,
            cookie: self.sock_cookie,
            cgroup_id: self.cgroup_id,
            pid: self.pid,
            comm: self.comm.clone(),
            family: self.family,
            sport: self.sport,
            dport: self.dport,
            saddr: self.saddr,
            daddr: self.daddr,
            segs_out: self.segs_out,
            total_retrans: self.total_retrans,
        }
    }
}

// ─── Probe ────────────────────────────────────────────────────────────────────

pub struct TcpDiagProbe {
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<TcpdiagSkel<'static>>,
    _links: Vec<Link>,
    aggregator: Arc<TcpAggregator>,
}

impl TcpDiagProbe {
    /// Create a TcpDiagProbe sharing traced_processes / rb / cgroup_filter
    /// with the rest of the unified probe set.
    pub fn new_with_full_maps(
        traced_processes: &MapHandle,
        rb: &MapHandle,
        cgroup_filter: Option<&MapHandle>,
        cgroup_filter_enabled: bool,
        agg_cfg: TcpAggregatorConfig,
    ) -> Result<Self> {
        let mut builder = TcpdiagSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());

        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let mut open_skel = builder
            .open()
            .context("failed to open tcpdiag BPF object")?;

        // rodata flags must be set before load.
        open_skel.rodata_mut().filter_cgroup_enabled = cgroup_filter_enabled;
        open_skel.rodata_mut().cgroup_v2_mode =
            std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        // Reuse external traced_processes map.
        open_skel
            .maps_mut()
            .traced_processes()
            .reuse_fd(traced_processes.as_fd())
            .context("failed to reuse external traced_processes map for tcpdiag")?;

        // Reuse external ring buffer.
        open_skel
            .maps_mut()
            .rb()
            .reuse_fd(rb.as_fd())
            .context("failed to reuse external rb map for tcpdiag")?;

        // Reuse external cgroup_filter map (if provided).
        if let Some(map) = cgroup_filter {
            open_skel
                .maps_mut()
                .cgroup_filter()
                .reuse_fd(map.as_fd())
                .context("failed to reuse external cgroup_filter map for tcpdiag")?;
        }

        let skel = open_skel
            .load()
            .context("failed to load tcpdiag BPF object")?;

        // SAFETY: see procnet.rs — same lifetime extension pattern.
        let skel = unsafe {
            Box::from_raw(Box::into_raw(Box::new(skel)) as *mut TcpdiagSkel<'static>)
        };

        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
            aggregator: Arc::new(TcpAggregator::new(agg_cfg)),
        })
    }

    /// Attach the three tcpdiag tracepoints.
    pub fn attach(&mut self) -> Result<()> {
        let mut links = Vec::new();
        links.push(
            self.skel
                .progs_mut()
                .handle_inet_sock_set_state()
                .attach()
                .context("failed to attach handle_inet_sock_set_state")?,
        );
        links.push(
            self.skel
                .progs_mut()
                .handle_tcp_retransmit_skb()
                .attach()
                .context("failed to attach handle_tcp_retransmit_skb")?,
        );
        links.push(
            self.skel
                .progs_mut()
                .handle_tcp_receive_reset()
                .attach()
                .context("failed to attach handle_tcp_receive_reset")?,
        );
        self._links = links;
        Ok(())
    }

    /// Shared-handle accessor for the unified poller — the ringbuf callback
    /// uses this to pipe base events through the aggregator.
    pub fn aggregator(&self) -> Arc<TcpAggregator> {
        Arc::clone(&self.aggregator)
    }
}

/// Convenience: feed a base event into the aggregator and return the derived
/// event if a HighRetrans threshold was crossed by this event.
pub fn process_event(
    agg: &TcpAggregator,
    ev: &TcpDiagEvent,
) -> Option<TcpDerivedEvent> {
    agg.record(&ev.to_agg_input())
}
