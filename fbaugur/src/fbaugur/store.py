"""Run state in one SQLite file shared by the orchestrator and the MCP tool servers.

FuzzingBrain V2 keeps this state in MongoDB; the records and their status
values follow its SP lifecycle (documentation/06_suspicious_point_lifecycle.md).
Invariant, violation and crash records are added for the Code Augur lane.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS threat_model (harness_scope TEXT PRIMARY KEY, body TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS directions (
    direction_id TEXT PRIMARY KEY, harness_id TEXT, name TEXT, risk_level TEXT, risk_reason TEXT,
    core_functions TEXT, entry_functions TEXT, code_summary TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS pool (
    worker_id TEXT, direction_id TEXT, function_name TEXT, pool TEXT, phase INTEGER,
    status TEXT, sp_count INTEGER DEFAULT 0, error TEXT, updated_at REAL,
    PRIMARY KEY (worker_id, direction_id, function_name));
CREATE TABLE IF NOT EXISTS sps (
    sp_id TEXT PRIMARY KEY, worker_id TEXT, harness_id TEXT, direction_id TEXT, function_name TEXT,
    vuln_type TEXT, description TEXT, score REAL, important_controlflow TEXT,
    status TEXT, is_checked INTEGER DEFAULT 0, is_important INTEGER DEFAULT 0, is_real INTEGER DEFAULT 0,
    verification_notes TEXT, pov_guidance TEXT, reachability_status TEXT, reachability_multiplier REAL,
    reachability_reason TEXT, safety_reason TEXT, safety_location TEXT,
    origin TEXT, origin_ref TEXT, witness_path TEXT, merged_into TEXT, claimed_by TEXT,
    pov_attempts INTEGER DEFAULT 0, created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS povs (
    pov_id TEXT PRIMARY KEY, sp_id TEXT, worker_id TEXT, attempt INTEGER, variant INTEGER,
    blob_path TEXT, crashed INTEGER, crash_type TEXT, summary TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS invariants (
    phi_num INTEGER PRIMARY KEY AUTOINCREMENT, harness_id TEXT, sp_id TEXT, file TEXT, line INTEGER,
    expression TEXT, security_property TEXT, rationale TEXT, status TEXT, distance INTEGER DEFAULT 1,
    repairs INTEGER DEFAULT 0, refinements INTEGER DEFAULT 0, build_version INTEGER,
    reached INTEGER DEFAULT 0, probed_by TEXT,
    last_error TEXT, history TEXT, created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS violations (
    violation_id TEXT PRIMARY KEY, phi_num INTEGER, harness_id TEXT, worker_id TEXT, input_path TEXT,
    status TEXT, verdict TEXT, notes TEXT, created_sp TEXT, created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS crashes (
    crash_id TEXT PRIMARY KEY, worker_id TEXT, source TEXT, sp_id TEXT, input_path TEXT,
    status TEXT, crash_type TEXT, signature TEXT, frames TEXT, details TEXT, report_path TEXT,
    duplicate_of TEXT, created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS builds (
    harness_id TEXT, version INTEGER, status TEXT, binary TEXT, phis TEXT, error TEXT,
    started_at REAL, ended_at REAL, PRIMARY KEY (harness_id, version));
CREATE TABLE IF NOT EXISTS agent_runs (
    run_id TEXT PRIMARY KEY, role TEXT, model TEXT, subject TEXT, status TEXT, turns INTEGER,
    tool_calls INTEGER, input_tokens INTEGER, output_tokens INTEGER, error TEXT,
    started_at REAL, ended_at REAL);
CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, message TEXT);
"""

JSON_FIELDS = {"core_functions", "entry_functions", "important_controlflow", "frames", "details",
               "history", "phis", "body"}


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Store:
    """Thin helper over sqlite3; one instance per process (WAL allows several processes)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path), timeout=60, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=60000")
        self.conn.executescript(SCHEMA)

    # -- generic helpers ---------------------------------------------------
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        out = dict(row)
        for key in JSON_FIELDS & out.keys():
            if out[key]:
                try:
                    out[key] = json.loads(out[key])
                except ValueError:
                    pass
        return out

    def rows(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return [self._row(r) for r in self.conn.execute(sql, args).fetchall()]

    def row(self, sql: str, *args: Any) -> dict[str, Any] | None:
        return self._row(self.conn.execute(sql, args).fetchone())

    def scalar(self, sql: str, *args: Any) -> Any:
        row = self.conn.execute(sql, args).fetchone()
        return None if row is None else row[0]

    def insert(self, table: str, values: dict[str, Any]) -> None:
        values = {k: (json.dumps(v, ensure_ascii=False) if k in JSON_FIELDS and v is not None
                      and not isinstance(v, str) else v) for k, v in values.items()}
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(values.values()))

    def update(self, table: str, key: str, key_value: Any, values: dict[str, Any]) -> None:
        values = {k: (json.dumps(v, ensure_ascii=False) if k in JSON_FIELDS and v is not None
                      and not isinstance(v, str) else v) for k, v in values.items()}
        sets = ", ".join(f"{k}=?" for k in values)
        self.conn.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", (*values.values(), key_value))

    def event(self, kind: str, message: str) -> None:
        self.conn.execute("INSERT INTO events VALUES (?,?,?)", (time.time(), kind, message))

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))

    def get_meta(self, key: str, default: Any = None) -> Any:
        value = self.scalar("SELECT value FROM meta WHERE key=?", key)
        return default if value is None else json.loads(value)

    # -- claims (FBv2 claim-based assignment) ----------------------------------
    def claim_sp(self, *, from_status: str, to_status: str, worker_id: str, agent: str,
                 min_score: float | None = None, important_only: bool = False) -> dict[str, Any] | None:
        clauses = ["status=?", "worker_id=?"]
        args: list[Any] = [from_status, worker_id]
        if min_score is not None:
            clauses.append("score>=?")
            args.append(min_score)
        if important_only:
            clauses.append("is_important=1")
        where = " AND ".join(clauses)
        with self.tx() as conn:
            row = conn.execute(
                f"SELECT sp_id FROM sps WHERE {where} "
                "ORDER BY is_important DESC, score DESC, created_at ASC LIMIT 1", args).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE sps SET status=?, claimed_by=?, updated_at=? WHERE sp_id=?",
                         (to_status, agent, time.time(), row[0]))
        return self.row("SELECT * FROM sps WHERE sp_id=?", row[0])

    def claim(self, table: str, key: str, *, where: str, args: tuple, set_status: str,
              order: str = "created_at ASC") -> dict[str, Any] | None:
        with self.tx() as conn:
            row = conn.execute(f"SELECT {key} FROM {table} WHERE {where} ORDER BY {order} LIMIT 1",
                               args).fetchone()
            if row is None:
                return None
            conn.execute(f"UPDATE {table} SET status=?, updated_at=? WHERE {key}=?",
                         (set_status, time.time(), row[0]))
        # `key` is named explicitly: it may be `rowid`, which `SELECT *` leaves out.
        return self.row(f"SELECT {key}, * FROM {table} WHERE {key}=?", row[0])
