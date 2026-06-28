"""UAT — backend acceptance tests.

These read like the things a stakeholder would sign off on: "I can submit a scan, a
worker picks it up, the result is persisted with a score, and I can fetch it back and
see it in history." Everything runs through the real durable queue + worker + data
layer. No UI.
"""
from __future__ import annotations

import os
import uuid

import pytest

import scanner_db
from harness import DEFAULT_CHECKERS, drain, make_handler, run_fake_scan


# --- AC1: a single scan flows end to end through the worker tier -------------
def test_single_scan_end_to_end():
    sid = "uat-single"
    scanner_db.enqueue_job(str(uuid.uuid4()), sid, {"scan_id": sid, "domain": "acme.example"})
    assert scanner_db.queue_depth() == 1

    drain(make_handler(), workers=2, timeout=30)

    row = scanner_db.fetch_scan(sid)
    assert row is not None, "scan row should exist"
    assert row["status"] == "completed"
    assert int(row["risk_score"]) > 0
    assert scanner_db.queue_depth() == 0


# --- AC2: a batch of scans all complete exactly once ------------------------
def test_batch_all_complete():
    n = 25
    log = []
    for i in range(n):
        sid = f"uat-batch-{i}"
        scanner_db.enqueue_job(str(uuid.uuid4()), sid, {"scan_id": sid, "domain": f"d{i}.example"})

    drain(make_handler(completion_log=log), workers=4, timeout=60)

    completed = scanner_db._run(
        "SELECT COUNT(*) AS n FROM scans WHERE status='completed'", fetch="one")
    assert int(completed["n"]) == n
    # each scan completed exactly once (no duplicate processing)
    sids = [s for s, _ in log]
    assert len(sids) == len(set(sids)) == n


# --- AC3: results are scored and persisted with the expected shape ----------
def test_results_scored_and_persisted():
    sid = "uat-score"
    results = run_fake_scan(sid, "scored.example", checkers=DEFAULT_CHECKERS)
    expected = sum((i + 1) * 10 for i in range(len(DEFAULT_CHECKERS)))
    assert sum(r["score"] for r in results.values()) == expected

    row = scanner_db.fetch_scan(sid)
    assert row["status"] == "completed"
    assert int(row["risk_score"]) == expected


# --- AC4: usage metering is durably recorded --------------------------------
def test_usage_metering_persisted():
    scanner_db.record_usage("hibp", 1, day="2026-06-28")
    scanner_db.record_usage("hibp", 2, day="2026-06-28")
    scanner_db.record_usage("shodan", 5, day="2026-06-28")
    assert scanner_db.usage_for("hibp", "2026-06-28") == 3
    assert scanner_db.usage_for("shodan", "2026-06-28") == 5
    assert scanner_db.usage_for("nope", "2026-06-28") == 0


# --- AC5: scan history is queryable by domain -------------------------------
def test_history_by_domain():
    for i in range(3):
        run_fake_scan(f"uat-hist-{i}", "history.example")
    hist = scanner_db.scan_history("history.example")
    assert len(hist) == 3
    assert all(h["status"] == "completed" for h in hist)
    latest = scanner_db.latest_completed_for_domain("history.example")
    assert latest is not None and latest["domain"] == "history.example"


# --- AC6 (opt-in): the REAL scanner runs against a benign live target -------
@pytest.mark.skipif(os.environ.get("RUN_LIVE_SCAN") != "1",
                    reason="set RUN_LIVE_SCAN=1 to run the real network scanner")
def test_live_real_scan():
    # Imports the actual scanner engine; hits the network. Off by default.
    from scanner import SecurityScanner
    res = SecurityScanner().scan("example.com", industry="other")
    assert res["domain_scanned"] == "example.com"
    assert "categories" in res and res["categories"]
