// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// Probe-local user-space *raw-event* aggregators (event folders).
//
// These types live in the BPF ringbuf consumption path: they accept raw
// probe events one-by-one (`record` / `try_record`), maintain in-memory
// state (sliding windows, pending sets, error counters), and surface
// derived/aggregated signals either synchronously (return value) or
// asynchronously (periodic `flush` / `sweep` from the probes flush
// thread).
//
// Distinct from `crate::aggregator`, which operates on parser results
// (HTTP pairs, HTTP/2 streams, proctrace topology) — that module sits
// downstream of `parser` in the SSL/Proc analysis pipeline. The
// aggregators in *this* module sit upstream of `raw_events.db` and never
// touch the parser pipeline. The `raw_` prefix is intentional: it marks
// the input as untransformed probe ringbuf events.
//
// Current members:
//   - `tcp::TcpAggregator`          — paired with the tcpdiag probe;
//       folds RETRANSMIT base events into HighRetrans derived signals.
//   - `open_err::OpenErrAggregator` — paired with the procfs probe;
//       collapses `(pid, errno, basename)` OPEN failures into a single
//       synthetic `ProcFsEvent` per flush window.

pub mod open_err;
pub mod tcp;

pub use open_err::OpenErrAggregator;
pub use tcp::{
    TcpAggregator, TcpAggregatorConfig, TcpDerivedEvent, TcpDiagOp, TcpEventInput,
};
