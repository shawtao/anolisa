// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// UDP DNS probe - captures domain names from DNS query packets
// by hooking udp_sendmsg and filtering for destination port 53.
//
// Design: BPF kernel side only does minimal filtering and raw payload capture.
// All DNS QNAME parsing and deduplication is done here in userspace.

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

// --- Generated skeleton ---
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/udpdns.skel.rs"));
    include!(concat!(env!("OUT_DIR"), "/udpdns.rs"));
}
use bpf::*;

// Re-export raw type for size calculation in probes.rs
pub type RawUdpDnsEvent = bpf::udpdns_event;

/// DNS header length in bytes
const DNS_HEADER_LEN: usize = 12;
/// Maximum domain name length (RFC 1035: 253 chars for FQDN)
const MAX_DOMAIN_LEN: usize = 253;
/// Maximum label length per RFC 1035
const MAX_LABEL_LEN: usize = 63;

/// User-space UDP DNS event
#[derive(Debug, Clone)]
pub struct UdpDnsEvent {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    /// cgroup id of producing task. Non-zero when the event was admitted via
    /// the cgroup-filter "correlation" channel (used by containersight to
    /// build a PID/cgroup → domain LRU). Zero when admitted via the legacy
    /// "discovery" channel (PID not in `traced_processes`), which preserves
    /// the original behaviour for non-containersight users.
    pub cgroup_id: u64,
    pub comm: String,
    pub domain: String,
}

/// Parse DNS wire-format QNAME from raw payload into dotted domain string.
///
/// DNS wire format: sequence of (length_byte, label_bytes...) terminated by 0x00.
/// Example: \x03api\x06openai\x03com\x00 → "api.openai.com"
fn parse_dns_qname(payload: &[u8], payload_len: usize) -> Option<String> {
    if payload_len < DNS_HEADER_LEN + 2 {
        return None;
    }

    let data = &payload[..payload_len];
    let mut off = DNS_HEADER_LEN; // QNAME starts after 12-byte DNS header
    let mut domain = String::with_capacity(64);

    loop {
        if off >= data.len() {
            break;
        }

        let label_len = data[off] as usize;

        // Root label (terminator)
        if label_len == 0 {
            break;
        }

        // Pointer (compression) — not expected in queries but bail out safely
        if label_len & 0xC0 != 0 {
            break;
        }

        // RFC 1035: label max 63 bytes
        if label_len > MAX_LABEL_LEN {
            break;
        }

        off += 1;

        // Check we have enough bytes for this label
        if off + label_len > data.len() {
            break;
        }

        // Add dot separator between labels
        if !domain.is_empty() {
            domain.push('.');
        }

        // Append label bytes
        let label_bytes = &data[off..off + label_len];
        // DNS labels should be ASCII; use lossy conversion for safety
        for &b in label_bytes {
            domain.push(b as char);
        }

        off += label_len;

        // Safety: prevent infinite/oversized domains
        if domain.len() > MAX_DOMAIN_LEN {
            break;
        }
    }

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

impl UdpDnsEvent {
    /// Parse event from raw ring buffer data.
    /// Performs DNS QNAME extraction from the raw payload in userspace.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let event_size = std::mem::size_of::<RawUdpDnsEvent>();
        if data.len() < event_size {
            return None;
        }

        // SAFETY: BPF guarantees proper alignment and layout
        let raw = unsafe { &*(data.as_ptr() as *const RawUdpDnsEvent) };

        // Parse comm (null-terminated)
        let comm = raw.comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect::<Vec<u8>>();
        let comm = String::from_utf8_lossy(&comm).into_owned();

        // Parse DNS QNAME from raw payload (userspace parsing — no BPF verifier limits)
        let payload_len = raw.payload_len as usize;
        let payload_len = payload_len.min(raw.payload.len());
        let domain = parse_dns_qname(&raw.payload, payload_len)?;

        Some(UdpDnsEvent {
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            timestamp_ns: config::ktime_to_unix_ns(raw.timestamp_ns),
            cgroup_id: raw.cgroup_id,
            comm,
            domain,
        })
    }
}

// --- Main struct ---
pub struct UdpDns {
    _open_object: Box<MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Box<UdpdnsSkel<'static>>,
    _links: Vec<Link>,
}

impl UdpDns {
    /// Create a new UdpDns that reuses traced_processes + ring buffer only.
    ///
    /// Backwards-compat shim: cgroup_filter sharing is disabled, so only the
    /// legacy "discovery" channel B is active (events fire for PIDs not yet
    /// present in `traced_processes`). All current AgentSight CLI users hit
    /// this path.
    pub fn new_with_maps(traced_processes: &MapHandle, rb: &MapHandle) -> Result<Self> {
        Self::new_with_full_maps(traced_processes, rb, None, false)
    }

    /// Create a new UdpDns with optional cgroup_filter map sharing.
    ///
    /// When `cgroup_filter_enabled == true` AND `cgroup_filter` is provided,
    /// the BPF program admits events via BOTH channels:
    ///   - Channel A (correlation): cgroup_id is in `cgroup_filter` map
    ///   - Channel B (discovery): PID is NOT in `traced_processes` map
    /// Either channel matching is sufficient to emit; cgroup_id in the
    /// emitted event distinguishes the source (non-zero = channel A).
    ///
    /// When disabled, only channel B fires (identical to the original
    /// `new_with_maps` behaviour).
    pub fn new_with_full_maps(
        traced_processes: &MapHandle,
        rb: &MapHandle,
        cgroup_filter: Option<&MapHandle>,
        cgroup_filter_enabled: bool,
    ) -> Result<Self> {
        let mut builder = UdpdnsSkelBuilder::default();
        builder.obj_builder.debug(config::verbose());

        let open_object = Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit());
        let mut open_skel = builder.open().context("failed to open udpdns BPF object")?;

        // Mirror the cgroup-filter rodata flag (drives channel A admission).
        open_skel.rodata_mut().filter_cgroup_enabled = cgroup_filter_enabled;

        // Detect cgroup v2 unified hierarchy at userspace and pass via rodata
        // so get_cgroup_id_compat() picks the right path inside BPF.
        open_skel.rodata_mut().cgroup_v2_mode =
            std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

        // Reuse external traced_processes map
        open_skel
            .maps_mut()
            .traced_processes()
            .reuse_fd(traced_processes.as_fd())
            .context("failed to reuse external traced_processes map for udpdns")?;

        // Reuse external ring buffer
        open_skel
            .maps_mut()
            .rb()
            .reuse_fd(rb.as_fd())
            .context("failed to reuse external rb map for udpdns")?;

        // Reuse external cgroup_filter map (if provided)
        if let Some(map) = cgroup_filter {
            open_skel
                .maps_mut()
                .cgroup_filter()
                .reuse_fd(map.as_fd())
                .context("failed to reuse external cgroup_filter map for udpdns")?;
        }

        let skel = open_skel.load().context("failed to load udpdns BPF object")?;

        // SAFETY: skel borrows open_object which lives in a Box<MaybeUninit>
        let skel =
            unsafe { Box::from_raw(Box::into_raw(Box::new(skel)) as *mut UdpdnsSkel<'static>) };

        Ok(Self {
            _open_object: open_object,
            skel,
            _links: Vec::new(),
        })
    }

    /// Attach fentry hook for udp_sendmsg
    pub fn attach(&mut self) -> Result<()> {
        let mut links = Vec::new();

        let link = self
            .skel
            .progs_mut()
            .trace_udp_sendmsg()
            .attach()
            .context("failed to attach udp_sendmsg fentry")?;
        links.push(link);

        self._links = links;
        Ok(())
    }
}
