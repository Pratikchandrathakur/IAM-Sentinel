"""
Persistence & audit store for the AI Cyber-Engine.

Every audit an enterprise runs is recorded here with full provenance so they can answer:
"what was scanned, by whom, when, with which rule pack, and what did it find?" — and diff
any two scans of the same target to prove findings were fixed (or regressed).

Design choices for on-prem reliability:
  * SQLite with WAL — zero external DB dependency, safe concurrent reads, single file to
    back up. (A Postgres backend is a clean drop-in later; the API here is storage-agnostic.)
  * Append-only audit_log — records the security-relevant actions themselves.
  * Pure stdlib (sqlite3) — no ML/web deps, fully unit-testable in isolation.

Thread-safety: a fresh connection per operation (check_same_thread not needed), which is
appropriate for the app's request-scoped usage under uvicorn.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Optional

import config
from findings import utc_now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at        TEXT NOT NULL,
    actor             TEXT NOT NULL,
    domain            TEXT NOT NULL,
    target            TEXT NOT NULL,
    artifact_sha256   TEXT NOT NULL,
    engine_version    TEXT NOT NULL,
    ruleset_version   TEXT NOT NULL,
    highest_severity  TEXT NOT NULL,
    finding_count     INTEGER NOT NULL,
    severity_counts   TEXT NOT NULL,
    llm_narrative_ok  INTEGER NOT NULL DEFAULT 1,
    request_id        TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(domain, target, scanned_at);
CREATE INDEX IF NOT EXISTS idx_scans_sha ON scans(artifact_sha256);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    location       TEXT,
    evidence       TEXT,
    confidence     TEXT,
    description    TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    request_id  TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class FindingsStore:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.FINDINGS_DB_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        # WAL improves concurrent reads but isn't supported on some network filesystems
        # (NFS/CIFS/9p). Fall back to the default journal mode rather than failing to start.
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.OperationalError:
            pass
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # --- writes ---------------------------------------------------------------------
    def record_scan(self, scan: dict, actor: str = "anonymous",
                    request_id: str = None, llm_narrative_ok: bool = True) -> int:
        """Persist a ScanResult.to_dict() payload. Returns the new scan id."""
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO scans (scanned_at, actor, domain, target, artifact_sha256,
                       engine_version, ruleset_version, highest_severity, finding_count,
                       severity_counts, llm_narrative_ok, request_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan.get("scanned_at") or utc_now_iso(),
                    actor,
                    scan.get("domain", ""),
                    scan.get("target", ""),
                    scan.get("artifact_sha256", ""),
                    scan.get("engine_version", ""),
                    scan.get("ruleset_version", ""),
                    scan.get("highest_severity", "INFO"),
                    scan.get("finding_count", 0),
                    json.dumps(scan.get("severity_counts", {})),
                    1 if llm_narrative_ok else 0,
                    request_id,
                ),
            )
            scan_id = cur.lastrowid
            for f in scan.get("findings", []):
                conn.execute(
                    """INSERT INTO findings (scan_id, fingerprint, rule_id, severity, title,
                           location, evidence, confidence, description)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        scan_id, f.get("fingerprint", ""), f.get("rule_id", ""),
                        f.get("severity", ""), f.get("title", ""), f.get("location", ""),
                        f.get("evidence", ""), f.get("confidence", ""), f.get("description", ""),
                    ),
                )
            self._audit(conn, actor, "record_scan", request_id,
                        f"domain={scan.get('domain')} target={scan.get('target')} "
                        f"sha={scan.get('artifact_sha256', '')[:12]} findings={scan.get('finding_count', 0)}")
            return scan_id

    def log_action(self, actor: str, action: str, request_id: str = None, detail: str = "") -> None:
        with self._lock, self._connect() as conn:
            self._audit(conn, actor, action, request_id, detail)

    @staticmethod
    def _audit(conn, actor, action, request_id, detail) -> None:
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, request_id, detail) VALUES (?,?,?,?,?)",
            (utc_now_iso(), actor, action, request_id, detail),
        )

    # --- reads ----------------------------------------------------------------------
    def get_scan(self, scan_id: int) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if not row:
                return None
            findings = conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
            ).fetchall()
            d = dict(row)
            d["severity_counts"] = json.loads(d["severity_counts"])
            d["findings"] = [dict(f) for f in findings]
            return d

    def list_scans(self, domain: str = None, target: str = None, limit: int = 50) -> list[dict]:
        q = "SELECT id, scanned_at, actor, domain, target, artifact_sha256, highest_severity, finding_count FROM scans"
        clauses, params = [], []
        if domain:
            clauses.append("domain=?"); params.append(domain)
        if target:
            clauses.append("target=?"); params.append(target)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(q, params).fetchall()]

    def diff_latest(self, domain: str, target: str) -> Optional[dict]:
        """Compare the two most recent scans of a (domain, target).

        Returns fixed / new / persistent findings by fingerprint — the core enterprise
        question "did the remediation actually work?".
        """
        with self._connect() as conn:
            scans = conn.execute(
                "SELECT id FROM scans WHERE domain=? AND target=? ORDER BY id DESC LIMIT 2",
                (domain, target),
            ).fetchall()
            if len(scans) < 2:
                return None
            newer_id, older_id = scans[0]["id"], scans[1]["id"]

            def fp_map(sid):
                rows = conn.execute(
                    "SELECT fingerprint, rule_id, severity, title FROM findings WHERE scan_id=?", (sid,)
                ).fetchall()
                return {r["fingerprint"]: dict(r) for r in rows}

            new_map, old_map = fp_map(newer_id), fp_map(older_id)
            new_fps, old_fps = set(new_map), set(old_map)

            return {
                "older_scan_id": older_id,
                "newer_scan_id": newer_id,
                "fixed": [old_map[fp] for fp in (old_fps - new_fps)],
                "new": [new_map[fp] for fp in (new_fps - old_fps)],
                "persistent": [new_map[fp] for fp in (new_fps & old_fps)],
            }

    def recent_audit(self, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    # --- metering ------------------------------------------------------------------
    # Usage is derived from the scans table (scanned_at is ISO-8601 UTC, so lexicographic
    # comparison against a month-start prefix is correct). No extra bookkeeping table.
    def count_scans_since(self, iso_since: str) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM scans WHERE scanned_at >= ?",
                               (iso_since,)).fetchone()
            return int(row["c"])

    def distinct_actors_since(self, iso_since: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT actor FROM scans WHERE scanned_at >= ? ORDER BY actor",
                (iso_since,)).fetchall()
            return [r["actor"] for r in rows]


_store_singleton: Optional[FindingsStore] = None
_singleton_lock = threading.Lock()


def get_store() -> FindingsStore:
    global _store_singleton
    if _store_singleton is None:
        with _singleton_lock:
            if _store_singleton is None:
                _store_singleton = FindingsStore()
    return _store_singleton
