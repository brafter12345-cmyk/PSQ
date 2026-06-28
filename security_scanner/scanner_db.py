"""Scanner data-access layer (WS1 / SCALE-01) — Postgres in prod, SQLite for
dev/tests, behind one interface.

Replaces app.py's bare ``sqlite3.connect(DB_PATH)`` per call for the **scanner**
tables only (``scans`` + the new ``scan_checkpoints`` + WS2 state columns). The CRM
tables stay on the legacy ``get_db()`` (scanner↔CRM links were dropped, per the
migration-scope decision), so there is no cross-store join.

Backend selection is by ``DATABASE_URL``:
  * set  -> Postgres via a pooled psycopg2 connection (``RealDictCursor`` rows). The
    SQLITE_BUSY / no-pool / no-WAL hazard of the old ``get_db()`` is gone.
  * unset -> SQLite at ``SCANNER_DB_PATH`` / ``DB_PATH`` (default ``scans.db``) —
    identical behaviour to today, so the cutover is a config flip, not a rewrite.

The same ``?``-placeholder SQL runs on both (translated to ``%s`` for psycopg2).
Rows are returned as plain dicts either way.
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

_cfg = {"url": None, "sqlite_path": None, "pool": None, "ready": False}
_lock = threading.Lock()


def configure(database_url: "str | None" = None,
              sqlite_path: "str | None" = None) -> None:
    """(Re)configure the backend. Defaults read the environment. Tests call this
    with an explicit ``sqlite_path`` to use a throwaway DB."""
    with _lock:
        if _cfg["pool"] is not None:
            try:
                _cfg["pool"].closeall()
            except Exception:
                pass
        _cfg["url"] = (database_url if database_url is not None
                       else os.environ.get("DATABASE_URL"))
        _cfg["sqlite_path"] = (sqlite_path or os.environ.get("SCANNER_DB_PATH")
                               or os.environ.get("DB_PATH", "scans.db"))
        _cfg["pool"] = None
        _cfg["ready"] = True


def _ensure() -> None:
    if not _cfg["ready"]:
        configure()
    if _cfg["url"] and _cfg["pool"] is None:
        import psycopg2.pool
        _cfg["pool"] = psycopg2.pool.ThreadedConnectionPool(
            1, int(os.environ.get("DB_POOL_MAX", "10")), dsn=_cfg["url"])


def is_postgres() -> bool:
    _ensure()
    return bool(_cfg["url"])


@contextmanager
def _conn():
    """Yield a (connection, is_pg) pair; commit on success, rollback on error.
    Postgres connections come from the pool and are returned to it."""
    _ensure()
    if _cfg["url"]:
        conn = _cfg["pool"].getconn()
        try:
            yield conn, True
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            _cfg["pool"].putconn(conn)
    else:
        import sqlite3
        conn = sqlite3.connect(_cfg["sqlite_path"])
        conn.row_factory = sqlite3.Row
        try:
            yield conn, False
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _cursor(conn, is_pg):
    if is_pg:
        import psycopg2.extras
        return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn.cursor()


def _sql(query: str, is_pg: bool) -> str:
    # Our scanner SQL uses '?' placeholders and contains no literal '?' or '%'.
    return query.replace("?", "%s") if is_pg else query


def _run(query: str, params: tuple = (), fetch: "str | None" = None) -> Any:
    """Execute ``query`` (with ``?`` placeholders); fetch None | 'one' | 'all'.
    Rows are returned as plain dicts."""
    with _conn() as (conn, is_pg):
        cur = _cursor(conn, is_pg)
        cur.execute(_sql(query, is_pg), params)
        if fetch == "one":
            row = cur.fetchone()
            return dict(row) if row else None
        if fetch == "all":
            return [dict(r) for r in cur.fetchall()]
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- schema ---------------------------------------------------------------
def init_schema() -> None:
    """Create the scanner tables if absent. Idempotent; safe on every boot.
    (Alembic replaces this hand-rolled bootstrap once it's added.)"""
    _run("""
        CREATE TABLE IF NOT EXISTS scans (
            id             TEXT PRIMARY KEY,
            domain         TEXT NOT NULL,
            status         TEXT NOT NULL DEFAULT 'pending',
            results        TEXT,
            risk_score     INTEGER,
            risk_level     TEXT,
            industry       TEXT DEFAULT 'other',
            annual_revenue DOUBLE PRECISION DEFAULT 0,
            country        TEXT DEFAULT '',
            client_id      TEXT DEFAULT '',
            created_at     TEXT NOT NULL,
            completed_at   TEXT,
            started_at     TEXT,
            attempts       INTEGER DEFAULT 0,
            worker_id      TEXT,
            last_heartbeat TEXT
        )
    """)
    _run("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
    _run("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
    _run("""
        CREATE TABLE IF NOT EXISTS scan_checkpoints (
            scan_id      TEXT NOT NULL,
            checker_name TEXT NOT NULL,
            result_json  TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, checker_name)
        )
    """)


# --- scans CRUD (mirrors the old app.py helpers) --------------------------
def save_scan(scan_id: str, domain: str, industry: str = "other",
              annual_revenue: float = 0, country: str = "") -> None:
    _run("INSERT INTO scans (id, domain, status, industry, annual_revenue, country, "
         "created_at) VALUES (?,?,?,?,?,?,?)",
         (scan_id, domain, "pending", industry, annual_revenue, country, _now()))


def update_scan(scan_id: str, results: dict) -> None:
    _run("UPDATE scans SET status=?, results=?, risk_score=?, risk_level=?, "
         "completed_at=? WHERE id=?",
         ("completed", json.dumps(results, default=str),
          results.get("overall_risk_score"), results.get("risk_level"),
          _now(), scan_id))


def mark_failed(scan_id: str, error: str) -> None:
    _run("UPDATE scans SET status='failed', results=?, completed_at=? WHERE id=?",
         (json.dumps({"error": error}), _now(), scan_id))


def fetch_scan(scan_id: str) -> "dict | None":
    return _run("SELECT * FROM scans WHERE id=?", (scan_id,), fetch="one")


def latest_completed_for_domain(domain: str) -> "dict | None":
    return _run("SELECT * FROM scans WHERE domain=? AND status='completed' "
                "ORDER BY created_at DESC LIMIT 1", (domain,), fetch="one")


def scan_history(domain: str, limit: int = 10) -> list:
    return _run("SELECT id, domain, status, risk_score, risk_level, created_at, "
                "completed_at FROM scans WHERE domain=? ORDER BY created_at DESC "
                f"LIMIT {int(limit)}", (domain,), fetch="all")


# --- checkpoints (WS3-ready; used once resumability lands) ----------------
def save_checkpoint(scan_id: str, checker_name: str, result: dict) -> None:
    """Upsert one checker's result. Portable ON CONFLICT (PG + SQLite >= 3.24)."""
    _run("INSERT INTO scan_checkpoints (scan_id, checker_name, result_json, "
         "completed_at) VALUES (?,?,?,?) "
         "ON CONFLICT (scan_id, checker_name) DO UPDATE SET "
         "result_json=EXCLUDED.result_json, completed_at=EXCLUDED.completed_at",
         (scan_id, checker_name, json.dumps(result, default=str), _now()))


def load_checkpoints(scan_id: str) -> dict:
    rows = _run("SELECT checker_name, result_json FROM scan_checkpoints "
                "WHERE scan_id=?", (scan_id,), fetch="all")
    return {r["checker_name"]: json.loads(r["result_json"]) for r in rows}
