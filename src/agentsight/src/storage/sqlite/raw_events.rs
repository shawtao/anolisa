// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2025 AgentSight Project
//
// SQLite storage for unified raw events.
//
// Components:
//   - `RawEventsStore`: read-only query interface for HTTP API handlers.
//   - `RawEventSender`: non-blocking sender handle cloned into event processors.
//   - `spawn_batch_writer`: starts the background batch INSERT thread.
//   - `spawn_ttl_reaper`: starts the background TTL deletion thread.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, types::Value, Connection};

use crate::raw_event::RawEvent;

// ─── DDL & PRAGMA ─────────────────────────────────────────────────────────────

const DDL: &str = "
CREATE TABLE IF NOT EXISTS raw_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms INTEGER NOT NULL,
    source       TEXT    NOT NULL,
    pid          INTEGER NOT NULL,
    ppid         INTEGER NOT NULL DEFAULT 0,
    tid          INTEGER NOT NULL DEFAULT 0,
    uid          INTEGER NOT NULL DEFAULT 0,
    comm         TEXT    NOT NULL DEFAULT '',
    cgroup_id    INTEGER NOT NULL DEFAULT 0,
    op           TEXT    NOT NULL,
    ret          INTEGER NOT NULL DEFAULT 0,
    data_json    TEXT    NOT NULL DEFAULT '{}',
    count        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_raw_ts     ON raw_events(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_raw_source ON raw_events(source);
CREATE INDEX IF NOT EXISTS idx_raw_pid    ON raw_events(pid);
CREATE INDEX IF NOT EXISTS idx_raw_ppid   ON raw_events(ppid);
CREATE INDEX IF NOT EXISTS idx_raw_cgroup ON raw_events(cgroup_id);
CREATE INDEX IF NOT EXISTS idx_raw_cgroup_ts ON raw_events(cgroup_id, timestamp_ms);
";

const PRAGMA: &str = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";

// ─── Row mapping ──────────────────────────────────────────────────────────────

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEvent> {
    let id: i64 = row.get(0)?;
    let timestamp_ms: i64 = row.get(1)?;
    let source: String = row.get(2)?;
    let pid: i64 = row.get(3)?;
    let ppid: i64 = row.get(4)?;
    let tid: i64 = row.get(5)?;
    let uid: i64 = row.get(6)?;
    let comm: String = row.get(7)?;
    let cgroup_id: i64 = row.get(8)?;
    let op: String = row.get(9)?;
    let ret: i32 = row.get(10)?;
    let data_json: String = row.get(11)?;
    let count: i64 = row.get(12)?;

    Ok(RawEvent {
        id: Some(id),
        timestamp_ms,
        source,
        pid: pid as u32,
        ppid: ppid as u32,
        tid: tid as u32,
        uid: uid as u32,
        comm,
        cgroup_id: cgroup_id as u64,
        op,
        ret,
        data_json,
        count: count as u64,
    })
}

const SELECT_COLS: &str =
    "id, timestamp_ms, source, pid, ppid, tid, uid, comm, cgroup_id, op, ret, data_json, count";

// ─── RawEventsStore ───────────────────────────────────────────────────────────

/// Read-only SQLite store for `raw_events`.
///
/// Wraps the connection in `Arc<Mutex<…>>` so it can be cheaply cloned and
/// shared across HTTP handlers without additional synchronisation machinery.
#[derive(Clone)]
pub struct RawEventsStore {
    conn: Arc<Mutex<Connection>>,
}

/// Aggregate statistics over the `raw_events` table.
pub struct RawEventStats {
    pub total: i64,
    pub by_source: HashMap<String, i64>,
    pub oldest_ms: Option<i64>,
    pub newest_ms: Option<i64>,
}

impl RawEventsStore {
    /// Open (or create) the database at `path`, apply WAL pragma, and run DDL.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(PRAGMA)?;
        conn.execute_batch(DDL)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn collect_rows(
        conn: &Connection,
        sql: &str,
        params: &[Value],
    ) -> Vec<RawEvent> {
        let refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("raw_events query prepare failed: {}", e);
                return Vec::new();
            }
        };

        let rows = match stmt.query_map(refs.as_slice(), row_to_event) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("raw_events query_map failed: {}", e);
                return Vec::new();
            }
        };

        let mut out = Vec::new();
        for r in rows {
            match r {
                Ok(e) => out.push(e),
                Err(e) => log::warn!("raw_events row error: {}", e),
            }
        }
        out
    }

    // ── public query API ─────────────────────────────────────────────────────

    /// Incremental pull: returns events with `id > since_id`, ordered by id ASC.
    ///
    /// Optional `source` and `pid` filters are ANDed together.
    pub fn query_since(
        &self,
        since_id: i64,
        limit: u32,
        source: Option<&str>,
        pid: Option<u32>,
    ) -> Vec<RawEvent> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut sql = format!(
            "SELECT {cols} FROM raw_events WHERE id > ?1",
            cols = SELECT_COLS
        );
        let mut values: Vec<Value> = vec![Value::Integer(since_id)];
        let mut idx = 2usize;

        if let Some(s) = source {
            sql.push_str(&format!(" AND source = ?{}", idx));
            values.push(Value::Text(s.to_owned()));
            idx += 1;
        }
        if let Some(p) = pid {
            sql.push_str(&format!(" AND pid = ?{}", idx));
            values.push(Value::Integer(p as i64));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY id ASC LIMIT ?{}", idx));
        values.push(Value::Integer(limit as i64));

        Self::collect_rows(&conn, &sql, &values)
    }

    /// Time-window query: returns events where `timestamp_ms` is in [from_ms, to_ms].
    pub fn query_window(
        &self,
        from_ms: i64,
        to_ms: i64,
        source: Option<&str>,
    ) -> Vec<RawEvent> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut sql = format!(
            "SELECT {cols} FROM raw_events WHERE timestamp_ms BETWEEN ?1 AND ?2",
            cols = SELECT_COLS
        );
        let mut values: Vec<Value> = vec![Value::Integer(from_ms), Value::Integer(to_ms)];

        if let Some(s) = source {
            sql.push_str(" AND source = ?3");
            values.push(Value::Text(s.to_owned()));
        }
        sql.push_str(" ORDER BY timestamp_ms ASC");

        Self::collect_rows(&conn, &sql, &values)
    }

    /// Process-tree query: returns events for `root_pid` and all descendant PIDs,
    /// within the given time window, using a recursive CTE.
    pub fn query_tree(
        &self,
        root_pid: u32,
        from_ms: i64,
        to_ms: i64,
    ) -> Vec<RawEvent> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        // Recursive CTE: accumulates descendant PIDs starting from root_pid.
        let sql = format!(
            "WITH RECURSIVE descendant_pids(pid) AS (
                SELECT ?1
                UNION
                SELECT r.pid
                FROM raw_events r
                INNER JOIN descendant_pids d ON r.ppid = d.pid
                WHERE r.timestamp_ms BETWEEN ?2 AND ?3
            )
            SELECT DISTINCT {cols}
            FROM raw_events
            WHERE pid IN (SELECT pid FROM descendant_pids)
            AND timestamp_ms BETWEEN ?2 AND ?3
            ORDER BY timestamp_ms ASC",
            cols = SELECT_COLS
        );

        let values: Vec<Value> = vec![
            Value::Integer(root_pid as i64),
            Value::Integer(from_ms),
            Value::Integer(to_ms),
        ];

        Self::collect_rows(&conn, &sql, &values)
    }

    /// Container-dimension query: returns events for a given `cgroup_id`
    /// within `[from_ms, to_ms]`, optionally filtered by `source`.
    ///
    /// Results are ordered by `timestamp_ms` ASC and capped at `limit` rows.
    pub fn query_by_cgroup(
        &self,
        cgroup_id: u64,
        from_ms: i64,
        to_ms: i64,
        source: Option<&str>,
        limit: u32,
    ) -> Vec<RawEvent> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut sql = format!(
            "SELECT {cols} FROM raw_events \
             WHERE cgroup_id = ?1 AND timestamp_ms BETWEEN ?2 AND ?3",
            cols = SELECT_COLS
        );
        let mut values: Vec<Value> = vec![
            Value::Integer(cgroup_id as i64),
            Value::Integer(from_ms),
            Value::Integer(to_ms),
        ];
        let mut idx = 4usize;

        if let Some(s) = source {
            sql.push_str(&format!(" AND source = ?{}", idx));
            values.push(Value::Text(s.to_owned()));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY timestamp_ms ASC LIMIT ?{}", idx));
        values.push(Value::Integer(limit as i64));

        Self::collect_rows(&conn, &sql, &values)
    }

    /// Behaviour-summary aggregation: groups by `(source, op)` and SUMs `count`
    /// for events whose `timestamp_ms` falls in `[from_ms, to_ms]` and which
    /// match the given `pid` and/or `cgroup_id`.
    ///
    /// At least one of `pid` / `cgroup_id` must be `Some`; otherwise an empty
    /// map is returned. When both are provided they are combined with `OR` so
    /// that callers can fan-in across two identifying dimensions.
    ///
    /// Returned shape: `outer key = source, inner key = op, value = total count`.
    pub fn query_summary(
        &self,
        pid: Option<u32>,
        cgroup_id: Option<u64>,
        from_ms: i64,
        to_ms: i64,
    ) -> HashMap<String, HashMap<String, i64>> {
        let mut out: HashMap<String, HashMap<String, i64>> = HashMap::new();

        if pid.is_none() && cgroup_id.is_none() {
            return out;
        }

        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return out,
        };

        let mut sql = String::from(
            "SELECT source, op, SUM(count) AS total \
             FROM raw_events \
             WHERE timestamp_ms BETWEEN ?1 AND ?2",
        );
        let mut values: Vec<Value> = vec![Value::Integer(from_ms), Value::Integer(to_ms)];
        let mut idx = 3usize;

        let mut id_clauses: Vec<String> = Vec::new();
        if let Some(p) = pid {
            id_clauses.push(format!("pid = ?{}", idx));
            values.push(Value::Integer(p as i64));
            idx += 1;
        }
        if let Some(c) = cgroup_id {
            id_clauses.push(format!("cgroup_id = ?{}", idx));
            values.push(Value::Integer(c as i64));
            idx += 1;
        }
        let _ = idx; // silence unused warning
        sql.push_str(" AND (");
        sql.push_str(&id_clauses.join(" OR "));
        sql.push_str(") GROUP BY source, op ORDER BY total DESC");

        let refs: Vec<&dyn rusqlite::types::ToSql> =
            values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("raw_events summary prepare failed: {}", e);
                return out;
            }
        };

        let rows = match stmt.query_map(refs.as_slice(), |row| {
            let source: String = row.get(0)?;
            let op: String = row.get(1)?;
            let total: i64 = row.get(2)?;
            Ok((source, op, total))
        }) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("raw_events summary query_map failed: {}", e);
                return out;
            }
        };

        for r in rows {
            match r {
                Ok((source, op, total)) => {
                    out.entry(source).or_default().insert(op, total);
                }
                Err(e) => log::warn!("raw_events summary row error: {}", e),
            }
        }
        out
    }

    /// Aggregate statistics over the entire table.
    pub fn stats(&self) -> RawEventStats {
        let empty = RawEventStats {
            total: 0,
            by_source: HashMap::new(),
            oldest_ms: None,
            newest_ms: None,
        };
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return empty,
        };

        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))
            .unwrap_or(0);

        let oldest_ms: Option<i64> = conn
            .query_row("SELECT MIN(timestamp_ms) FROM raw_events", [], |row| {
                row.get(0)
            })
            .unwrap_or(None);

        let newest_ms: Option<i64> = conn
            .query_row("SELECT MAX(timestamp_ms) FROM raw_events", [], |row| {
                row.get(0)
            })
            .unwrap_or(None);

        let mut by_source: HashMap<String, i64> = HashMap::new();
        if let Ok(mut stmt) =
            conn.prepare("SELECT source, COUNT(*) FROM raw_events GROUP BY source")
        {
            if let Ok(rows) = stmt.query_map([], |row| {
                let src: String = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                Ok((src, cnt))
            }) {
                for r in rows.flatten() {
                    by_source.insert(r.0, r.1);
                }
            }
        }

        RawEventStats {
            total,
            by_source,
            oldest_ms,
            newest_ms,
        }
    }

    /// Total number of rows in the table.
    pub fn total_count(&self) -> i64 {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        conn.query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))
            .unwrap_or(0)
    }
}

// ─── RawEventSender ───────────────────────────────────────────────────────────

/// Non-blocking sender handle for the `BatchWriter`.
///
/// Cheaply cloneable; events are dropped silently when the internal channel is
/// full so that the hot event path is never back-pressured.
#[derive(Clone)]
pub struct RawEventSender {
    tx: crossbeam_channel::Sender<RawEvent>,
}

impl RawEventSender {
    /// Attempt a non-blocking send. If the channel is full the event is discarded.
    pub fn try_send(&self, event: RawEvent) {
        let _ = self.tx.try_send(event);
    }
}

// ─── BatchWriter internals ────────────────────────────────────────────────────

/// Flush `buf` to `conn` inside a single transaction, then clear `buf`.
fn flush(conn: &mut Connection, buf: &mut Vec<RawEvent>) {
    if buf.is_empty() {
        return;
    }

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("BatchWriter: begin transaction failed: {}", e);
            buf.clear();
            return;
        }
    };

    {
        let sql = "INSERT INTO raw_events \
            (timestamp_ms, source, pid, ppid, tid, uid, comm, cgroup_id, op, ret, data_json, count) \
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

        let mut stmt = match tx.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("BatchWriter: prepare insert failed: {}", e);
                buf.clear();
                return;
            }
        };

        for event in buf.iter() {
            if let Err(e) = stmt.execute(params![
                event.timestamp_ms,
                event.source,
                event.pid as i64,
                event.ppid as i64,
                event.tid as i64,
                event.uid as i64,
                event.comm,
                event.cgroup_id as i64,
                event.op,
                event.ret,
                event.data_json,
                event.count as i64,
            ]) {
                log::warn!("BatchWriter: insert failed: {}", e);
            }
        }
    }

    if let Err(e) = tx.commit() {
        log::warn!("BatchWriter: commit failed: {}", e);
    }

    buf.clear();
}

// ─── spawn_batch_writer ───────────────────────────────────────────────────────

/// Start the background batch-INSERT thread and return a `RawEventSender`.
///
/// Parameters
/// ----------
/// * `db_path`           – path to `raw_events.db` (created if absent)
/// * `batch_size`        – maximum events per INSERT transaction (e.g. 512)
/// * `batch_interval_ms` – flush interval in milliseconds (e.g. 200)
/// * `max_buf`           – channel capacity; excess events are silently dropped
pub fn spawn_batch_writer(
    db_path: &Path,
    batch_size: usize,
    batch_interval_ms: u64,
    max_buf: usize,
) -> Result<RawEventSender, rusqlite::Error> {
    // Ensure parent directory exists.
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut conn = Connection::open(db_path)?;
    conn.execute_batch(PRAGMA)?;
    conn.execute_batch(DDL)?;

    let (tx, rx) = crossbeam_channel::bounded::<RawEvent>(max_buf);

    std::thread::Builder::new()
        .name("raw-events-batch-writer".to_owned())
        .spawn(move || {
            let mut buf: Vec<RawEvent> = Vec::with_capacity(batch_size);
            let interval = Duration::from_millis(batch_interval_ms);
            let mut last_flush = std::time::Instant::now();

            loop {
                // Calculate remaining time until the next scheduled flush.
                let elapsed = last_flush.elapsed();
                let timeout = if elapsed >= interval {
                    Duration::ZERO
                } else {
                    interval - elapsed
                };

                match rx.recv_timeout(timeout) {
                    Ok(event) => {
                        buf.push(event);
                        if buf.len() >= batch_size {
                            flush(&mut conn, &mut buf);
                            last_flush = std::time::Instant::now();
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        if !buf.is_empty() {
                            flush(&mut conn, &mut buf);
                        }
                        last_flush = std::time::Instant::now();
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        // All senders dropped; flush remaining events and exit.
                        if !buf.is_empty() {
                            flush(&mut conn, &mut buf);
                        }
                        break;
                    }
                }
            }
        })
        .expect("Failed to spawn batch-writer thread");

    Ok(RawEventSender { tx })
}

// ─── spawn_ttl_reaper ─────────────────────────────────────────────────────────

/// Start the background TTL-reaper thread.
///
/// Every 5 minutes the reaper deletes rows whose `timestamp_ms` is older than
/// `now - ttl_secs * 1_000` milliseconds.
pub fn spawn_ttl_reaper(
    db_path: &Path,
    ttl_secs: u64,
) -> Result<(), rusqlite::Error> {
    let path = db_path.to_path_buf();

    // Open the connection eagerly so we can surface errors to the caller.
    let conn = Connection::open(&path)?;
    conn.execute_batch(PRAGMA)?;

    std::thread::Builder::new()
        .name("raw-events-ttl-reaper".to_owned())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_secs(300)); // 5-minute cycle

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;

            let cutoff_ms = now_ms.saturating_sub(ttl_secs as i64 * 1_000);

            match conn.execute(
                "DELETE FROM raw_events WHERE timestamp_ms < ?1",
                params![cutoff_ms],
            ) {
                Ok(n) if n > 0 => {
                    log::info!("TtlReaper: deleted {} expired raw_events rows", n);
                }
                Ok(_) => {}
                Err(e) => {
                    log::warn!("TtlReaper: DELETE failed: {}", e);
                }
            }
        })
        .expect("Failed to spawn ttl-reaper thread");

    Ok(())
}
