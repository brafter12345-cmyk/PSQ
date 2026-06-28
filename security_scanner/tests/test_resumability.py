"""Resumability — a scan that dies partway through resumes without redoing work, and
the queue recovers jobs abandoned by dead workers.

This is the WS3 (checkpoints) + WS2 (visibility-timeout / DLQ) guarantee that makes
the scanner safe to interrupt and horizontally scalable.
"""
from __future__ import annotations

import uuid

import pytest

import scanner_db
from harness import DEFAULT_CHECKERS, Spy, run_fake_scan


# --- crash mid-scan, then resume: earlier checkers are NOT recomputed --------
def test_resume_skips_completed_checkers():
    sid = "resume-1"
    spy = Spy()
    crash_at = 3  # checkers 0,1,2 succeed & checkpoint; 3 crashes

    # First attempt crashes at checker idx 3
    with pytest.raises(RuntimeError):
        run_fake_scan(sid, checkers=DEFAULT_CHECKERS, spy=spy, fail_at=crash_at)

    # checkpoints for the 3 completed checkers exist
    loaded = scanner_db.load_checkpoints(sid)
    assert set(loaded) == set(DEFAULT_CHECKERS[:crash_at])

    # Resume: completed checkers are skip-and-loaded; the crashed + later run now.
    run_fake_scan(sid, checkers=DEFAULT_CHECKERS, spy=spy, resume=True)

    # checkers before the crash: computed once, then skipped on resume (count == 1)
    for name in DEFAULT_CHECKERS[:crash_at]:
        assert spy.count(name) == 1, f"{name} was recomputed on resume (not skipped)"
    # the crashed checker: ran (incremented) then crashed, and re-ran on resume == 2
    assert spy.count(DEFAULT_CHECKERS[crash_at]) == 2
    # checkers after the crash: only ran on resume (count == 1)
    for name in DEFAULT_CHECKERS[crash_at + 1:]:
        assert spy.count(name) == 1, f"{name} should have run once (post-crash only)"

    row = scanner_db.fetch_scan(sid)
    assert row["status"] == "completed"


# --- resume serves the SAME values that were checkpointed -------------------
def test_resume_serves_checkpointed_values():
    sid = "resume-vals"
    first = run_fake_scan(sid, checkers=["a", "b", "c"])
    # wipe the live scan row's result but keep checkpoints; resume should reload them
    second = run_fake_scan(sid, checkers=["a", "b", "c"], resume=True)
    assert first == second


# --- a fully-completed scan resumes to a no-op (everything cached) -----------
def test_resume_full_scan_recomputes_nothing():
    sid = "resume-full"
    spy = Spy()
    run_fake_scan(sid, checkers=DEFAULT_CHECKERS, spy=spy)
    base = spy.total()
    run_fake_scan(sid, checkers=DEFAULT_CHECKERS, spy=spy, resume=True)
    assert spy.total() == base, "a complete scan should recompute nothing on resume"


# --- stale TTL forces recompute even with a checkpoint present ---------------
def test_stale_checkpoint_recomputes():
    sid = "resume-ttl"
    spy = Spy()
    run_fake_scan(sid, checkers=["x", "y"], spy=spy)         # checkpoints written
    # resume with a 0-age freshness bound -> all treated as stale -> recompute
    run_fake_scan(sid, checkers=["x", "y"], spy=spy, resume=True, max_age_seconds=0.0001)
    assert spy.count("x") == 2 and spy.count("y") == 2


# --- dead-worker recovery: a stale 'running' job is requeued -----------------
def test_stale_job_requeued():
    jid = str(uuid.uuid4())
    scanner_db.enqueue_job(jid, "stale-scan", {"scan_id": "stale-scan"})
    scanner_db.claim_job("dead-worker")  # now 'running', attempts=1
    # backdate the heartbeat so it looks abandoned
    scanner_db._run("UPDATE scan_jobs SET last_heartbeat=? WHERE id=?",
                    ("2000-01-01T00:00:00+00:00", jid))
    moved = scanner_db.requeue_stale_jobs(visibility_timeout_s=60, max_attempts=3)
    assert moved == 1
    assert scanner_db.queue_depth() == 1  # back to 'queued', reclaimable


# --- poison job past max attempts goes to the DLQ ('dead') ------------------
def test_poison_job_to_dlq():
    jid = str(uuid.uuid4())
    scanner_db.enqueue_job(jid, "poison", {"scan_id": "poison"})
    scanner_db.claim_job("w1")
    scanner_db._run("UPDATE scan_jobs SET attempts=3, last_heartbeat=? WHERE id=?",
                    ("2000-01-01T00:00:00+00:00", jid))
    scanner_db.requeue_stale_jobs(visibility_timeout_s=60, max_attempts=3)
    dead = scanner_db.list_dead_jobs()
    assert any(d["id"] == jid for d in dead)
    assert scanner_db.queue_depth() == 0  # not reclaimable
