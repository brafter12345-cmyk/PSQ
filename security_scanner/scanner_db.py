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


# --- schema / migrations (WS1 / SCALE-01) ---------------------------------
# Ordered, recorded migrations applied once each (a schema_migrations ledger tracks
# applied versions). This is the lightweight equivalent of Alembic — when alembic is
# added, point its env at the same ledger and continue numbering. Each migration is a
# (version, [statements]) pair; statements use '?' placeholders / portable DDL.
MIGRATIONS = [
    ("0001_initial", [
        """CREATE TABLE IF NOT EXISTS scans (
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
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)",
        "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
        """CREATE TABLE IF NOT EXISTS scan_checkpoints (
            scan_id      TEXT NOT NULL,
            checker_name TEXT NOT NULL,
            result_json  TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            PRIMARY KEY (scan_id, checker_name)
        )""",
    ]),
    ("0002_job_queue", [
        """CREATE TABLE IF NOT EXISTS scan_jobs (
            id            TEXT PRIMARY KEY,
            scan_id       TEXT NOT NULL,
            pool          TEXT NOT NULL DEFAULT 'default',
            payload       TEXT NOT NULL,
            status        TEXT NOT NULL DEFAULT 'queued',
            attempts      INTEGER DEFAULT 0,
            worker_id     TEXT,
            created_at    TEXT NOT NULL,
            started_at    TEXT,
            last_heartbeat TEXT,
            error         TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs(status, pool)",
    ]),
    ("0003_usage_ledger", [
        # WS10/SCALE-17: durable spend ledger (the Redis counters are a rebuildable
        # cache of this append-only-ish per-(provider,day) record).
        """CREATE TABLE IF NOT EXISTS usage (
            provider  TEXT NOT NULL,
            day       TEXT NOT NULL,
            calls     INTEGER DEFAULT 0,
            PRIMARY KEY (provider, day)
        )""",
    ]),
]


def migrate() -> list:
    """Apply pending migrations in order; record each in schema_migrations. Returns
    the versions applied this run. Idempotent."""
    _run("""CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)""")
    applied = {r["version"] for r in
               _run("SELECT version FROM schema_migrations", fetch="all")}
    done = []
    for version, statements in MIGRATIONS:
        if version in applied:
            continue
        for stmt in statements:
            _run(stmt)
        _run("INSERT INTO schema_migrations (version, applied_at) VALUES (?,?)",
             (version, _now()))
        done.append(version)
    return done


def init_schema() -> None:
    """Apply migrations (idempotent; safe on every boot)."""
    migrate()


# --- WS10 durable usage ledger (SCALE-17) + DLQ ---------------------------
def record_usage(provider: str, n: int = 1, day: "str | None" = None) -> None:
    """Append-only-ish per-(provider,day) spend mirror. The Redis counters are a
    rebuildable cache of THIS durable record (so a lost Redis loses only the
    rate-limit window, not billing/attribution history)."""
    day = day or datetime.now(timezone.utc).date().isoformat()
    _run("INSERT INTO usage (provider, day, calls) VALUES (?,?,?) "
         "ON CONFLICT (provider, day) DO UPDATE SET calls = usage.calls + ?",
         (provider, day, n, n))


def usage_for(provider: str, day: "str | None" = None) -> int:
    day = day or datetime.now(timezone.utc).date().isoformat()
    row = _run("SELECT calls FROM usage WHERE provider=? AND day=?",
               (provider, day), fetch="one")
    return int(row["calls"]) if row else 0


def list_dead_jobs() -> list:
    """DLQ: jobs that exhausted attempts (the row IS the DLQ record — scan_id,
    attempts, error; the surviving checkpoints are queryable via load_checkpoints)."""
    return _run("SELECT * FROM scan_jobs WHERE status='dead' ORDER BY created_at",
                fetch="all")


# --- WS2 job queue ops ----------------------------------------------------
def enqueue_job(job_id: str, scan_id: str, payload: dict, pool: str = "default") -> None:
    _run("INSERT INTO scan_jobs (id, scan_id, pool, payload, status, created_at) "
         "VALUES (?,?,?,?, 'queued', ?)",
         (job_id, scan_id, pool, json.dumps(payload, default=str), _now()))


def queue_depth(pool: "str | None" = None) -> int:
    if pool:
        row = _run("SELECT COUNT(*) AS n FROM scan_jobs WHERE status='queued' AND pool=?",
                   (pool,), fetch="one")
    else:
        row = _run("SELECT COUNT(*) AS n FROM scan_jobs WHERE status='queued'", fetch="one")
    return int(row["n"]) if row else 0


def claim_job(worker_id: str, pool: str = "default") -> "dict | None":
    """Atomically claim the oldest queued job. Postgres: FOR UPDATE SKIP LOCKED so
    workers never collide; SQLite: serialized single-writer."""
    _ensure()
    skip = " FOR UPDATE SKIP LOCKED" if _cfg["url"] else ""
    sql = (f"UPDATE scan_jobs SET status='running', worker_id=?, "
           f"started_at=?, last_heartbeat=?, attempts=attempts+1 "
           f"WHERE id = (SELECT id FROM scan_jobs WHERE status='queued' AND pool=? "
           f"ORDER BY created_at LIMIT 1{skip}) RETURNING *")
    now = _now()
    row = _run(sql, (worker_id, now, now, pool), fetch="one")
    if row and isinstance(row.get("payload"), str):
        try:
            row["payload"] = json.loads(row["payload"])
        except ValueError:
            pass
    return row


def heartbeat_job(job_id: str) -> None:
    _run("UPDATE scan_jobs SET last_heartbeat=? WHERE id=?", (_now(), job_id))


def complete_job(job_id: str) -> None:
    _run("UPDATE scan_jobs SET status='completed' WHERE id=?", (job_id,))


def fail_job(job_id: str, error: str, requeue: bool = False) -> None:
    status = "queued" if requeue else "failed"
    _run("UPDATE scan_jobs SET status=?, error=? WHERE id=?",
         (status, (error or "")[:500], job_id))


def requeue_stale_jobs(visibility_timeout_s: float, max_attempts: int = 3) -> int:
    """Return running jobs whose heartbeat is older than the visibility timeout to
    'queued' (dead-worker recovery); jobs past max_attempts go to the DLQ ('dead')."""
    cutoff = datetime.now(timezone.utc).timestamp() - visibility_timeout_s
    rows = _run("SELECT id, attempts, last_heartbeat, started_at FROM scan_jobs "
                "WHERE status='running'", fetch="all")
    n = 0
    for r in rows:
        hb = r.get("last_heartbeat") or r.get("started_at")
        try:
            ts = datetime.fromisoformat(hb).timestamp() if hb else 0
        except (TypeError, ValueError):
            ts = 0
        if ts < cutoff:
            if int(r.get("attempts", 0)) >= max_attempts:
                _run("UPDATE scan_jobs SET status='dead' WHERE id=?", (r["id"],))
            else:
                _run("UPDATE scan_jobs SET status='queued', worker_id=NULL WHERE id=?",
                     (r["id"],))
            n += 1
    return n


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


def load_checkpoints(scan_id: str, max_age_seconds: "float | None" = None) -> dict:
    """Return {checker_name: result} for a scan. With ``max_age_seconds``, rows
    older than that (by ``completed_at``) are treated as absent (WS3 freshness
    bound, so a long-resumed scan re-runs stale checkers rather than serving a
    stale vintage — mirrors the WS6 data-type TTL)."""
    rows = _run("SELECT checker_name, result_json, completed_at FROM scan_checkpoints "
                "WHERE scan_id=?", (scan_id,), fetch="all")
    out = {}
    cutoff = None
    if max_age_seconds is not None:
        cutoff = datetime.now(timezone.utc).timestamp() - max_age_seconds
    for r in rows:
        if cutoff is not None:
            try:
                ts = datetime.fromisoformat(r["completed_at"]).timestamp()
                if ts < cutoff:
                    continue  # stale -> treat as absent
            except (TypeError, ValueError):
                pass
        out[r["checker_name"]] = json.loads(r["result_json"])
    return out


# Statuses that mean a checker did NOT successfully complete — never checkpointed,
# so they re-run on resume (matches scoring_analytics _FAILED_/_SKIPPED_STATUSES).
_NOT_DONE_STATUSES = frozenset(
    {"error", "timeout", "no_api_key", "auth_failed", "disabled", "skipped"})


def _is_done(result) -> bool:
    """True if a checker result should be checkpointed: a dict whose status (if any)
    is not a failed/skipped marker. Most successful checkers carry no 'status' key."""
    return isinstance(result, dict) and result.get("status") not in _NOT_DONE_STATUSES


class Checkpointer:
    """WS3 resumability helper used by scanner.scan(). With no scan_id it is a pure
    no-op (compute every checker, persist nothing) — so default scans are unchanged.
    With a scan_id it skip-and-loads a valid checkpoint, else computes and (best-
    effort) persists a non-failed result so a requeue doesn't re-spend credits."""

    def __init__(self, scan_id: "str | None" = None, resume: bool = False,
                 max_age_seconds: "float | None" = None):
        self.scan_id = scan_id
        self.enabled = bool(scan_id)
        self._loaded = (load_checkpoints(scan_id, max_age_seconds)
                        if (scan_id and resume) else {})

    def run(self, name: str, compute_fn):
        if name in self._loaded:
            return self._loaded[name]            # skip-and-load
        result = compute_fn()
        if self.enabled and _is_done(result):
            try:
                save_checkpoint(self.scan_id, name, result)
            except Exception:
                pass  # best-effort: a failed write just re-runs the checker on resume
        return result

    def loaded(self, name: str):
        return self._loaded.get(name)

    def has(self, name: str) -> bool:
        return name in self._loaded
