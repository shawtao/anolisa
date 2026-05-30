// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// User-space aggregator for the tcpdiag probe.
//
// Translates the raw stream of `RETRANSMIT / RESET_RECV` base events into
// derived signals:
//   - `TcpDerivedEvent::HighRetrans` — sliding-window retransmit burst
//                                      (>= threshold within window_ms)
//
// The aggregator is intentionally lock-protected (Mutex over hash maps)
// rather than per-CPU because the input stream comes from the shared ring
// buffer in a single poll thread; contention is negligible.
//
// Historical note: a `CloseWaitStuck` derived signal previously existed,
// fed by a STATE_CHANGE base event emitted on TCP_CLOSE_WAIT entry. Both
// the BPF emit path and this user-space reaper were removed because the
// signal had near-zero value in short-lived client workloads (see commit
// log for the SWE evaluation profile decision). The numeric value of
// STATE_CHANGE in `enum tcpdiag_op` is preserved for raw_events backward
// compatibility.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Minimal projection of a tcpdiag base event needed by the aggregator.
///
/// Keeping this struct decoupled from the BPF skel struct avoids an
/// awkward dependency cycle between `tcpdiag.rs` and this module.
#[derive(Clone, Debug)]
pub struct TcpEventInput {
    pub op: TcpDiagOp,
    pub timestamp_ns: u64,   // unix epoch ns (already converted from ktime)
    pub cookie: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: String,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    /// RETRANSMIT only.
    pub segs_out: u32,
    pub total_retrans: u32,
}

/// Operation kinds matching the BPF `enum tcpdiag_op`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpDiagOp {
    Retransmit,
    ResetRecv,
}

impl TcpDiagOp {
    pub fn from_raw(op: u32) -> Option<Self> {
        match op {
            1 => Some(Self::Retransmit),
            3 => Some(Self::ResetRecv),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retransmit => "tcp_retransmit",
            Self::ResetRecv  => "tcp_reset_recv",
        }
    }
}

/// Derived events emitted by the aggregator.
///
/// Down-stream sinks (raw_events.db / FFI / log) treat these uniformly via
/// `RawEvent::from_tcpdiag_derived`.
#[derive(Clone, Debug)]
pub enum TcpDerivedEvent {
    HighRetrans {
        cookie: u64,
        cgroup_id: u64,
        pid: u32,
        comm: String,
        timestamp_ns: u64,
        family: u16,
        sport: u16,
        dport: u16,
        saddr: [u8; 16],
        daddr: [u8; 16],
        retrans_count: u32,
        window_ms: u64,
        total_retrans: u32,
    },
}

impl TcpDerivedEvent {
    pub fn op_name(&self) -> &'static str {
        match self {
            TcpDerivedEvent::HighRetrans { .. } => "tcp_high_retrans",
        }
    }

    pub fn timestamp_ns(&self) -> u64 {
        match self {
            TcpDerivedEvent::HighRetrans { timestamp_ns, .. } => *timestamp_ns,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TcpAggregatorConfig {
    /// Sliding window length used to count retransmits per socket (ms).
    pub retrans_window_ms: u64,
    /// Number of retransmits within the window required to emit HighRetrans.
    pub retrans_threshold: usize,
    /// Suppress duplicate HighRetrans for the same cookie within this window (ms).
    pub dedup_window_ms: u64,
}

impl Default for TcpAggregatorConfig {
    fn default() -> Self {
        Self {
            retrans_window_ms: 10_000,  // 10s
            retrans_threshold: 5,
            dedup_window_ms:   30_000,  // 30s
        }
    }
}

pub struct TcpAggregator {
    cfg: TcpAggregatorConfig,
    /// cookie -> (timestamp ns) deque of recent retransmits within window.
    retrans: Mutex<HashMap<u64, VecDeque<u64>>>,
    /// cookie -> last emit timestamp ns (HighRetrans dedup).
    retrans_dedup: Mutex<HashMap<u64, u64>>,
}

impl TcpAggregator {
    pub fn new(cfg: TcpAggregatorConfig) -> Self {
        Self {
            cfg,
            retrans: Mutex::new(HashMap::new()),
            retrans_dedup: Mutex::new(HashMap::new()),
        }
    }

    /// Feed a base tcpdiag event. Returns Some(derived) when the event
    /// triggers a derived signal (currently only HighRetrans).
    pub fn record(&self, ev: &TcpEventInput) -> Option<TcpDerivedEvent> {
        match ev.op {
            TcpDiagOp::Retransmit => self.record_retransmit(ev),
            TcpDiagOp::ResetRecv  => None,
        }
    }

    fn record_retransmit(&self, ev: &TcpEventInput) -> Option<TcpDerivedEvent> {
        let window_ns = self.cfg.retrans_window_ms.saturating_mul(1_000_000);
        let threshold = self.cfg.retrans_threshold;
        let now = ev.timestamp_ns;

        // Update sliding window for this cookie.
        let count = {
            let mut map = self.retrans.lock().unwrap();
            let dq = map.entry(ev.cookie).or_default();
            dq.push_back(now);
            // Evict timestamps that fell out of the window.
            while let Some(&front) = dq.front() {
                if now.saturating_sub(front) > window_ns {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            dq.len()
        };

        if count < threshold {
            return None;
        }

        // Dedup: don't re-emit for the same cookie inside dedup_window_ms.
        let dedup_ns = self.cfg.dedup_window_ms.saturating_mul(1_000_000);
        {
            let mut dedup = self.retrans_dedup.lock().unwrap();
            if let Some(&last) = dedup.get(&ev.cookie) {
                if now.saturating_sub(last) < dedup_ns {
                    return None;
                }
            }
            dedup.insert(ev.cookie, now);
        }

        Some(TcpDerivedEvent::HighRetrans {
            cookie: ev.cookie,
            cgroup_id: ev.cgroup_id,
            pid: ev.pid,
            comm: ev.comm.clone(),
            timestamp_ns: now,
            family: ev.family,
            sport: ev.sport,
            dport: ev.dport,
            saddr: ev.saddr,
            daddr: ev.daddr,
            retrans_count: count as u32,
            window_ms: self.cfg.retrans_window_ms,
            total_retrans: ev.total_retrans,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(op: TcpDiagOp, cookie: u64, ts_ns: u64) -> TcpEventInput {
        TcpEventInput {
            op,
            timestamp_ns: ts_ns,
            cookie,
            cgroup_id: 1,
            pid: 100,
            comm: "test".into(),
            family: 2,
            sport: 1234,
            dport: 80,
            saddr: [0; 16],
            daddr: [0; 16],
            segs_out: 0,
            total_retrans: 0,
        }
    }

    #[test]
    fn high_retrans_triggers_at_threshold() {
        let agg = TcpAggregator::new(TcpAggregatorConfig {
            retrans_window_ms: 10_000,
            retrans_threshold: 3,
            ..Default::default()
        });
        assert!(agg.record(&ev(TcpDiagOp::Retransmit, 1, 1_000_000)).is_none());
        assert!(agg.record(&ev(TcpDiagOp::Retransmit, 1, 2_000_000)).is_none());
        let hit = agg.record(&ev(TcpDiagOp::Retransmit, 1, 3_000_000));
        assert!(matches!(hit, Some(TcpDerivedEvent::HighRetrans { retrans_count: 3, .. })));
    }

    #[test]
    fn high_retrans_dedup_suppresses_repeat() {
        let agg = TcpAggregator::new(TcpAggregatorConfig {
            retrans_window_ms: 10_000,
            retrans_threshold: 2,
            dedup_window_ms: 30_000,
            ..Default::default()
        });
        agg.record(&ev(TcpDiagOp::Retransmit, 7, 1_000_000));
        let first = agg.record(&ev(TcpDiagOp::Retransmit, 7, 2_000_000));
        assert!(first.is_some());
        let dup = agg.record(&ev(TcpDiagOp::Retransmit, 7, 3_000_000));
        assert!(dup.is_none(), "dedup should suppress within window");
    }
}
