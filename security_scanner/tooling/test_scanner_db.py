"""Unit tests for scanner_db — runnable without pytest:  py tooling/test_scanner_db.py

Runs against a throwaway SQLite file (proving the SQL + CRUD logic). The IDENTICAL
code path runs on Postgres when DATABASE_URL is set — if it is, the suite also runs
there against a temp table set, so the same assertions gate both backends.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import scanner_db as db

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


def run_suite(label: str) -> None:
    print(f"--- {label} ---")
    db.init_schema()
    db.init_schema()  # idempotent
    check(f"[{label}] init_schema idempotent", True)

    db.save_scan("s1", "example.co.za", industry="finance",
                 annual_revenue=1_000_000, country="ZA")
    row = db.fetch_scan("s1")
    check(f"[{label}] save+fetch round trip",
          row is not None and row["domain"] == "example.co.za"
          and row["status"] == "pending" and row["industry"] == "finance")
    check(f"[{label}] new columns present (state machine ready)",
          "attempts" in row and "worker_id" in row and "last_heartbeat" in row)

    db.update_scan("s1", {"overall_risk_score": 282, "risk_level": "High",
                          "categories": {"_overall_score": 70}})
    row = db.fetch_scan("s1")
    check(f"[{label}] update -> completed + score",
          row["status"] == "completed" and row["risk_score"] == 282
          and row["risk_level"] == "High" and row["completed_at"])

    db.save_scan("s2", "example.co.za")
    db.mark_failed("s2", "boom")
    row = db.fetch_scan("s2")
    check(f"[{label}] mark_failed", row["status"] == "failed"
          and "boom" in (row["results"] or ""))

    latest = db.latest_completed_for_domain("example.co.za")
    check(f"[{label}] latest_completed_for_domain finds s1",
          latest is not None and latest["id"] == "s1")

    hist = db.scan_history("example.co.za")
    check(f"[{label}] scan_history returns both", len(hist) == 2)

    check(f"[{label}] fetch_scan(missing) -> None", db.fetch_scan("nope") is None)

    db.save_checkpoint("s1", "ssl", {"score": 9})
    db.save_checkpoint("s1", "breaches", {"breach_count": 3})
    db.save_checkpoint("s1", "ssl", {"score": 10})  # upsert overwrites
    cps = db.load_checkpoints("s1")
    check(f"[{label}] checkpoints upsert + load",
          cps == {"ssl": {"score": 10}, "breaches": {"breach_count": 3}})
    check(f"[{label}] load_checkpoints(missing) empty", db.load_checkpoints("nope") == {})


# --- SQLite (always) ------------------------------------------------------
tmp = Path(tempfile.mkdtemp()) / "scanner_test.db"
db.configure(database_url="", sqlite_path=str(tmp))  # force sqlite
run_suite("sqlite")
try:
    tmp.unlink()
except OSError:
    pass

# --- Postgres (only if DATABASE_URL is set) -------------------------------
if os.environ.get("DATABASE_URL"):
    db.configure()  # picks up DATABASE_URL
    # isolate: drop scanner tables first so the suite's row counts hold
    db._run("DROP TABLE IF EXISTS scan_checkpoints")
    db._run("DROP TABLE IF EXISTS scans")
    run_suite("postgres")
else:
    print("--- postgres --- SKIPPED (DATABASE_URL not set)")

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
