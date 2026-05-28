// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Unified probes manager - manages sslsniff and proctrace probes
// with shared traced_processes map and shared ring buffer for coordinated process tracing

use anyhow::{Context, Result};
use libbpf_rs::{MapHandle, RingBufferBuilder};
use std::{
    mem,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    thread,
    time::Duration,
};

use crate::event::Event;
use crate::config::ProbeConfig;

use super::proctrace::{ProcTrace, VariableEvent, ProcEventHeader};
use super::sslsniff::SslSniff;
use super::sslsniff::bpf::probe_SSL_data_t as RawSslEvent;
use super::procmon::{ProcMon, ProcMonEvent};
use super::filewatch::{FileWatch, RawFileWatchEvent};
use super::filewrite::{FileWrite as FileWriteProbe, RawFileWriteEvent};
use super::udpdns::{UdpDns, RawUdpDnsEvent};
use super::procfs::{OpenErrAggregator, ProcFsProbe, ProcFsEvent, RawProcFsEvent};
use super::procnet::{ProcNetProbe, ProcNetEvent, RawProcNetEvent};
use super::procsig::{ProcSigProbe, ProcSigEvent, RawProcSigEvent};

const POLL_TIMEOUT_MS: u64 = 100;

// Event source constants matching common.h event_source_t
const EVENT_SOURCE_PROC: u32 = 1;
const EVENT_SOURCE_SSL: u32 = 2;
const EVENT_SOURCE_PROCMON: u32 = 3;
const EVENT_SOURCE_FILEWATCH: u32 = 4;
const EVENT_SOURCE_FILEWRITE: u32 = 5;
const EVENT_SOURCE_UDPDNS: u32 = 6;
const EVENT_SOURCE_PROCFS: u32 = 7;
const EVENT_SOURCE_PROCNET: u32 = 8;
const EVENT_SOURCE_PROCSIG: u32 = 9;

/// Unified probe manager that coordinates sslsniff and proctrace
/// 
/// This manager ensures both probes share the same traced_processes map
/// and the same ring buffer, allowing coordinated process tracing where:
/// - proctrace captures process creation events
/// - sslsniff captures SSL traffic from those processes
/// Both write to a single shared ring buffer to save memory.
pub struct Probes {
    /// Process trace probe (owns the traced_processes map and ring buffer)
    proctrace: ProcTrace,
    /// SSL sniff probe (reuses proctrace's traced_processes map and ring buffer, optional)
    sslsniff: Option<SslSniff>,
    /// Process monitor probe (reuses ring buffer, optional)
    procmon: Option<ProcMon>,
    /// File watch probe (reuses traced_processes map and ring buffer, optional)
    filewatch: Option<FileWatch>,
    /// File write probe (reuses traced_processes map and ring buffer, optional)
    filewrite: Option<FileWriteProbe>,
    /// UDP DNS probe (reuses ring buffer, captures domains from DNS queries, optional)
    udpdns: Option<UdpDns>,
    /// Filesystem operations probe (optional)
    procfs: Option<ProcFsProbe>,
    /// Network operations probe (optional)
    procnet: Option<ProcNetProbe>,
    /// Signal/process control probe (optional)
    procsig: Option<ProcSigProbe>,
    /// User-space aggregator for OPEN failures (optional, see procfs.rs).
    /// Shared between the ringbuf callback and the flush thread.
    open_err_agg: Option<Arc<OpenErrAggregator>>,
    /// Shared ring buffer handle (cloned from proctrace) for polling
    rb_handle: MapHandle,
    /// Unified event channel - events are converted to Event type inside the poller
    event_tx: crossbeam_channel::Sender<Event>,
    event_rx: crossbeam_channel::Receiver<Event>,
}

impl Probes {
    /// Create a new unified probe manager
    ///
    /// # Arguments
    /// * `target_pids` - Initial PIDs to trace (empty means trace all matching UID)
    /// * `target_uid` - Optional UID filter
    /// * `enable_filewatch` - Enable filewatch probe
    /// * `enable_udpdns` - Enable udpdns probe
    pub fn new(
        target_pids: &[u32],
        target_uid: Option<u32>,
        enable_filewatch: bool,
        enable_udpdns: bool,
    ) -> Result<Self> {
        let probe_config = ProbeConfig {
            filewatch: enable_filewatch,
            ..ProbeConfig::default()
        };
        Self::new_with_cgroup_filter(
            target_pids,
            target_uid,
            &probe_config,
            enable_udpdns,
            false,
            false,
        )
    }

    /// Create a new unified probe manager with explicit cgroup-level filtering toggle.
    ///
    /// When `cgroup_filter_enabled` is true, probes that honor the cgroup map
    /// admit events when **either** the PID is in `traced_processes` **or** the
    /// task's cgroup id is registered in `cgroup_filter` (OR semantics). When
    /// false, only the PID map is used. Procmon stays unfiltered (full-system).
    ///
    /// `enable_udpdns` is the resolved final value (after auto-detection in
    /// the caller; e.g. `unified.rs` consults both `probe_config.udpdns` and
    /// `domain_rules`).
    pub fn new_with_cgroup_filter(
        target_pids: &[u32],
        target_uid: Option<u32>,
        probe_config: &ProbeConfig,
        enable_udpdns: bool,
        cgroup_filter_enabled: bool,
        proc_ext_errors_only: bool,
    ) -> Result<Self> {
        // Create proctrace first - it owns the traced_processes map, the ring
        // buffer, and (when enabled) the cgroup_filter map.
        let proctrace = ProcTrace::new_with_target_and_maps(
            target_pids,
            target_uid,
            None,
            None,
            cgroup_filter_enabled,
        )
        .context("failed to create proctrace")?;

        // Get handles to the shared maps for reuse
        let map_handle = proctrace.traced_processes_handle()
            .context("failed to get traced_processes handle")?;
        let rb_handle = proctrace.rb_handle()
            .context("failed to get rb handle")?;

        // Only fetch a cgroup_filter handle when the feature is on; when off,
        // we let each probe load its own private (unused) cgroup_filter map
        // so we never burn an extra fd in the steady state.
        let cgroup_filter_handle = if cgroup_filter_enabled {
            Some(
                proctrace
                    .cgroup_filter_handle()
                    .context("failed to get cgroup_filter handle")?,
            )
        } else {
            None
        };
        let cgroup_filter_ref = cgroup_filter_handle.as_ref();

        // Create sslsniff - it will reuse both the traced_processes map and ring buffer
        let sslsniff = if probe_config.sslsniff {
            Some(
                SslSniff::new_with_traced_processes(Some(&map_handle), Some(&rb_handle))
                    .context("failed to create sslsniff")?,
            )
        } else {
            log::info!("SslSniff probe disabled by config");
            None
        };

        // Create procmon - it reuses the ring buffer (no cgroup filter: full audit)
        let procmon = if probe_config.procmon {
            Some(
                ProcMon::new_with_rb(&rb_handle)
                    .context("failed to create procmon")?,
            )
        } else {
            log::info!("ProcMon probe disabled by config");
            None
        };

        // Optionally create filewatch - it reuses both the traced_processes map and ring buffer
        let filewatch = if probe_config.filewatch {
            let fw = FileWatch::new_with_full_maps(
                &map_handle,
                &rb_handle,
                cgroup_filter_ref,
                cgroup_filter_enabled,
            )
            .context("failed to create filewatch")?;
            Some(fw)
        } else {
            log::info!("FileWatch probe disabled by config");
            None
        };

        // Optionally create filewrite - it reuses both the traced_processes map and ring buffer
        let filewrite = if probe_config.filewrite {
            Some(
                FileWriteProbe::new_with_full_maps(
                    &map_handle,
                    &rb_handle,
                    cgroup_filter_ref,
                    cgroup_filter_enabled,
                )
                .context("failed to create filewrite")?,
            )
        } else {
            log::info!("FileWrite probe disabled by config");
            None
        };

        // Optionally create udpdns - it reuses traced_processes map and ring buffer
        // Skips already-traced processes to avoid redundant discovery events
        let udpdns = if enable_udpdns {
            let dns = UdpDns::new_with_maps(&map_handle, &rb_handle)
                .context("failed to create udpdns")?;
            Some(dns)
        } else {
            log::info!("UDP DNS probe disabled (no domain_rules configured)");
            None
        };

        // Optionally create procfs - it reuses traced_processes map, ring buffer
        // and (when enabled) the cgroup_filter map.
        let procfs = if probe_config.procfs {
            Some(
                ProcFsProbe::new_with_full_maps(
                    &map_handle,
                    &rb_handle,
                    cgroup_filter_ref,
                    cgroup_filter_enabled,
                    proc_ext_errors_only,
                )
                .context("failed to create procfs probe")?,
            )
        } else {
            log::info!("ProcFs probe disabled by config");
            None
        };

        // Optionally create procnet - it reuses traced_processes map, ring buffer
        // and (when enabled) the cgroup_filter map.
        let procnet = if probe_config.procnet {
            Some(
                ProcNetProbe::new_with_full_maps(
                    &map_handle,
                    &rb_handle,
                    cgroup_filter_ref,
                    cgroup_filter_enabled,
                    proc_ext_errors_only,
                )
                .context("failed to create procnet probe")?,
            )
        } else {
            log::info!("ProcNet probe disabled by config");
            None
        };

        // Optionally create procsig - it reuses traced_processes map, ring buffer
        // and (when enabled) the cgroup_filter map.
        let procsig = if probe_config.procsig {
            Some(
                ProcSigProbe::new_with_full_maps(
                    &map_handle,
                    &rb_handle,
                    cgroup_filter_ref,
                    cgroup_filter_enabled,
                    proc_ext_errors_only,
                )
                .context("failed to create procsig probe")?,
            )
        } else {
            log::info!("ProcSig probe disabled by config");
            None
        };

        let (event_tx, event_rx) = crossbeam_channel::unbounded();

        // Install OPEN-error aggregator whenever procfs is on. Python importlib
        // is the canonical noisy producer (probing many non-existent
        // entry_points.txt/PKG-INFO during imports), so we collapse those by
        // default rather than gating behind a config flag.
        let open_err_agg = if procfs.is_some() {
            Some(Arc::new(OpenErrAggregator::new()))
        } else {
            None
        };
        
        Ok(Self {
            proctrace,
            sslsniff,
            procmon,
            filewatch,
            filewrite,
            udpdns,
            procfs,
            procnet,
            procsig,
            open_err_agg,
            rb_handle,
            event_tx,
            event_rx,
        })
    }

    /// Attach all probes
    pub fn attach(&mut self) -> Result<()> {
        // Attach procmon for process monitoring (if enabled)
        if let Some(ref mut p) = self.procmon {
            p.attach().context("failed to attach procmon")?;
        }
        self.proctrace.attach().context("failed to attach proctrace")?;
        // Attach filewatch for .jsonl file monitoring (if enabled)
        if let Some(ref mut fw) = self.filewatch {
            fw.attach()
                .context("failed to attach filewatch")?;
        }
        // Attach filewrite for JSON write monitoring (if enabled)
        if let Some(ref mut fw) = self.filewrite {
            fw.attach().context("failed to attach filewrite")?;
        }
        // Attach udpdns for DNS query capture (if enabled)
        if let Some(ref mut dns) = self.udpdns {
            dns.attach()
                .context("failed to attach udpdns")?;
        }
        // Attach procfs (filesystem ops) if enabled
        if let Some(ref mut p) = self.procfs {
            p.attach().context("failed to attach procfs")?;
        }
        // Attach procnet (network ops) if enabled
        if let Some(ref mut p) = self.procnet {
            p.attach().context("failed to attach procnet")?;
        }
        // Attach procsig (signal/process control) if enabled
        if let Some(ref mut p) = self.procsig {
            p.attach().context("failed to attach procsig")?;
        }
        // sslsniff uses uprobes attached per-process via attach_process()
        Ok(())
    }

    pub fn attach_process(&mut self, pid: i32) -> Result<()> {
        self.attach_ssl_to_process(pid)?;
        self.add_traced_pid(pid as u32)
    }

    /// Attach SSL probes to a specific process
    pub fn attach_ssl_to_process(&mut self, pid: i32) -> Result<()> {
        if let Some(ref mut s) = self.sslsniff {
            s.attach_process(pid)
                .context("failed to attach sslsniff to process")?;
        }
        Ok(())
    }

    /// Start polling for events from the shared ring buffer
    ///
    /// A single background thread polls the shared ring buffer and dispatches
    /// events as unified Event type to the channel. When any of the proc-ext
    /// probes (procfs/procnet/procsig) are active, an additional flush thread
    /// drains their per-CPU aggregation maps every `flush_interval_ms`.
    pub fn run(&self, flush_interval_ms: u64) -> Result<ProbesPoller> {
        let proc_min_sz = mem::size_of::<ProcEventHeader>();
        let ssl_event_size = mem::size_of::<RawSslEvent>();
        let procmon_event_size = mem::size_of::<ProcMonEvent>();
        let filewatch_event_size = mem::size_of::<RawFileWatchEvent>();
        let filewrite_event_size = mem::size_of::<RawFileWriteEvent>();
        let udpdns_event_size = mem::size_of::<RawUdpDnsEvent>();
        let procfs_event_size = mem::size_of::<RawProcFsEvent>();
        let procnet_event_size = mem::size_of::<RawProcNetEvent>();
        let procsig_event_size = mem::size_of::<RawProcSigEvent>();

        // Capture probe-enabled flags so the poller closure (`move`) can skip
        // events from disabled probes without holding a reference to `self`.
        // In practice disabled probes never attach, so this is defensive only.
        let has_sslsniff = self.sslsniff.is_some();
        let has_procmon = self.procmon.is_some();
        let has_filewatch = self.filewatch.is_some();
        let has_filewrite = self.filewrite.is_some();
        let has_udpdns = self.udpdns.is_some();
        let has_procfs = self.procfs.is_some();
        let has_procnet = self.procnet.is_some();
        let has_procsig = self.procsig.is_some();

        let event_tx = self.event_tx.clone();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_inner = Arc::clone(&stop_flag);

        // Clone the aggregator handle for the ringbuf callback closure; the
        // flush thread uses a second clone below.
        let open_err_agg_cb = self.open_err_agg.as_ref().map(Arc::clone);

        // Build ring buffer from the shared rb handle
        let mut rb_builder = RingBufferBuilder::new();
        rb_builder
            .add(&self.rb_handle, move |data: &[u8]| {
                // Read the first u32 to determine event source (common_event_hdr.source)
                if data.len() < 4 {
                    return 0;
                }
                let source = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                let event = match source {
                    EVENT_SOURCE_PROC => {
                        // Process event - variable size, starts with proc_event_header
                        if data.len() >= proc_min_sz {
                            VariableEvent::from_bytes(data).map(Event::Proc)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_SSL => {
                        if !has_sslsniff { return 0; }
                        // SSL event - convert raw BPF data to user-space SslEvent
                        if data.len() >= ssl_event_size {
                            // SAFETY: BPF guarantees layout and alignment
                            let raw = unsafe { &*(data.as_ptr() as *const RawSslEvent) };
                            let ssl_event = crate::probes::sslsniff::SslEvent::from_bpf(raw);
                            Some(Event::Ssl(ssl_event))
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_PROCMON => {
                        if !has_procmon { return 0; }
                        // Process monitor event
                        if data.len() >= procmon_event_size {
                            super::procmon::Event::from_bytes(data).map(Event::ProcMon)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_FILEWATCH => {
                        if !has_filewatch { return 0; }
                        // File watch event
                        if data.len() >= filewatch_event_size {
                            super::filewatch::FileWatchEvent::from_bytes(data).map(Event::FileWatch)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_FILEWRITE => {
                        if !has_filewrite { return 0; }
                        // File write event (JSON content)
                        if data.len() >= filewrite_event_size {
                            super::filewrite::FileWriteEvent::from_bytes(data).map(Event::FileWrite)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_UDPDNS => {
                        if !has_udpdns { return 0; }
                        // UDP DNS event (domain name from DNS query)
                        if data.len() >= udpdns_event_size {
                            super::udpdns::UdpDnsEvent::from_bytes(data).map(Event::UdpDns)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_PROCFS => {
                        if !has_procfs { return 0; }
                        if data.len() >= procfs_event_size {
                            if let Some(e) = ProcFsEvent::from_bytes(data) {
                                // Intercept OPEN failures into the user-space
                                // aggregator when enabled; otherwise forward
                                // verbatim. try_record returns true only for
                                // op==PROCFS_OPEN && ret<0, which means the
                                // event has been merged and must NOT be sent.
                                if let Some(ref agg) = open_err_agg_cb {
                                    if agg.try_record(&e) {
                                        return 0;
                                    }
                                }
                                let _ = event_tx.send(Event::ProcFs(e));
                            }
                            return 0;
                        }
                        None
                    }
                    EVENT_SOURCE_PROCNET => {
                        if !has_procnet { return 0; }
                        if data.len() >= procnet_event_size {
                            ProcNetEvent::from_bytes(data).map(Event::ProcNet)
                        } else {
                            None
                        }
                    }
                    EVENT_SOURCE_PROCSIG => {
                        if !has_procsig { return 0; }
                        if data.len() >= procsig_event_size {
                            ProcSigEvent::from_bytes(data).map(Event::ProcSig)
                        } else {
                            None
                        }
                    }
                    _ => {
                        // Unknown source - ignore
                        log::warn!("probes: unknown event source {source}");
                        None
                    }
                };
                
                if let Some(e) = event {
                    let _ = event_tx.send(e);
                }
                0
            })
            .context("failed to add shared ring buffer")?;
        let rb = rb_builder.build().context("failed to build ring buffer")?;

        let handle = thread::Builder::new()
            .name("probes-poll".into())
            .spawn(move || {
                let timeout = Duration::from_millis(POLL_TIMEOUT_MS);
                loop {
                    if stop_flag_inner.load(Ordering::Relaxed) {
                        break;
                    }
                    match rb.poll(timeout) {
                        Ok(_) => {}
                        Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
                        Err(e) => {
                            eprintln!("probes poll error: {e:#}");
                            break;
                        }
                    }
                }
            })
            .context("failed to spawn poll thread")?;

        // Spawn flush thread for per-CPU aggregation maps (procnet/procsig/procfs).
        // When re-enabling procfs write (#if 1 in procfs.bpf.c), restore:
        //   let write_agg = self.procfs.as_ref().and_then(|p| p.write_agg_map_handle().ok());
        //   if write_agg.is_some() || connect_agg... in the condition below, and
        //   the flush_write_agg branch inside the loop (see block comment there).
        let connect_agg = self.procnet.as_ref().and_then(|p| p.connect_agg_map_handle().ok());
        let fork_agg = self.procsig.as_ref().and_then(|p| p.fork_agg_map_handle().ok());
        let open_agg = self.procfs.as_ref().and_then(|p| p.open_agg_map_handle().ok());
        let open_err_agg_flush = self.open_err_agg.as_ref().map(Arc::clone);
        let flush_handle = if connect_agg.is_some() || fork_agg.is_some() || open_agg.is_some() || open_err_agg_flush.is_some() {
            let flush_tx = self.event_tx.clone();
            let flush_stop = Arc::clone(&stop_flag);
            let interval = Duration::from_millis(flush_interval_ms.max(1));
            let h = thread::Builder::new()
                .name("probes-flush".into())
                .spawn(move || {
                    while !flush_stop.load(Ordering::Relaxed) {
                        thread::sleep(interval);
                        /*
                        if let Some(ref m) = write_agg {
                            super::procfs::flush_write_agg(m, &flush_tx);
                        }
                        */
                        if let Some(ref m) = connect_agg {
                            super::procnet::flush_connect_agg(m, &flush_tx);
                        }
                        if let Some(ref m) = fork_agg {
                            super::procsig::flush_fork_agg(m, &flush_tx);
                        }
                        if let Some(ref m) = open_agg {
                            super::procfs::flush_open_agg(m, &flush_tx);
                        }
                        if let Some(ref agg) = open_err_agg_flush {
                            agg.flush(&flush_tx);
                        }
                    }
                })
                .context("failed to spawn flush thread")?;
            Some(h)
        } else {
            None
        };

        Ok(ProbesPoller {
            handle: Some(handle),
            flush_handle,
            stop_flag,
        })
    }

    /// Receive the next event from any probe (blocking)
    pub fn recv(&self) -> Option<Event> {
        self.event_rx.recv().ok()
    }

    /// Try to receive an event from any probe (non-blocking)
    pub fn try_recv(&self) -> Option<Event> {
        self.event_rx.try_recv().ok()
    }

    /// Add a PID to the traced_processes map at runtime
    pub fn add_traced_pid(&mut self, pid: u32) -> Result<()> {
        self.proctrace.add_traced_pid(pid)
            .context("failed to add traced pid")
    }

    /// Remove a PID from the traced_processes map at runtime
    pub fn remove_traced_pid(&mut self, pid: u32) -> Result<()> {
        self.proctrace.remove_traced_pid(pid)
            .context("failed to remove traced pid")
    }

    /// Get a handle to the traced_processes map
    pub fn traced_processes_handle(&self) -> Result<MapHandle> {
        self.proctrace.traced_processes_handle()
    }

    /// Add a cgroup inode id to the shared cgroup_filter map at runtime.
    ///
    /// Has no observable effect unless probes were created with
    /// `cgroup_filter_enabled = true`; in that case, only events from
    /// processes whose cgroup id is registered here will be emitted by
    /// proctrace / filewatch / filewrite. sslsniff, udpdns, and procmon are
    /// unaffected.
    pub fn add_traced_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        self.proctrace.add_traced_cgroup(cgroup_id)
            .context("failed to add traced cgroup")
    }

    /// Remove a cgroup inode id from the shared cgroup_filter map at runtime.
    pub fn remove_traced_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        self.proctrace.remove_traced_cgroup(cgroup_id)
            .context("failed to remove traced cgroup")
    }
}

/// Poller handle for the unified ring buffer thread
pub struct ProbesPoller {
    handle: Option<thread::JoinHandle<()>>,
    flush_handle: Option<thread::JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
}

impl ProbesPoller {
    /// Stop the poller thread
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.flush_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ProbesPoller {
    fn drop(&mut self) {
        self.stop();
    }
}
