"""Edge cases — the backend's behaviour at and beyond its boundaries.

Covers queue saturation, duplicate/invalid input, checkpoint freshness, cache
negatives, the circuit breaker's full state machine, the retry budget, and the
object-store path-traversal guard.
"""
from __future__ import annotations

import time
import uuid

import pytest

import scanner_db
from harness import make_response, run_fake_scan


# --- queue saturation: in-process queue rejects past maxsize ----------------
def test_inprocess_queue_full_returns_false():
    from job_queue import InProcessJobQueue
    # no workers consuming -> fills up and rejects (the 429 path in app.start_scan)
    q = InProcessJobQueue(handler=lambda p: time.sleep(10), workers=1, maxsize=2)
    accepted = [q.enqueue(f"s{i}", {"scan_id": f"s{i}"}) for i in range(6)]
    assert accepted.count(True) <= 3  # maxsize (+ maybe 1 in-flight)
    assert False in accepted, "an over-capacity enqueue must be rejected"


# --- durable queue depth cap (PostgresJobQueue.enqueue) ---------------------
def test_durable_queue_depth_cap():
    from job_queue import PostgresJobQueue
    q = PostgresJobQueue(max_depth=3)
    results = [q.enqueue(f"d{i}", {"scan_id": f"d{i}"}) for i in range(5)]
    assert results[:3] == [True, True, True]
    assert results[3:] == [False, False]
    assert scanner_db.queue_depth() == 3


# --- duplicate scan_id checkpoints upsert (no duplicate rows) ----------------
def test_duplicate_checkpoint_upserts():
    scanner_db.save_checkpoint("dup", "ssl", {"status": "done", "v": 1})
    scanner_db.save_checkpoint("dup", "ssl", {"status": "done", "v": 2})
    loaded = scanner_db.load_checkpoints("dup")
    assert loaded["ssl"]["v"] == 2  # second write wins, single row


# --- invalid state transitions are rejected ---------------------------------
def test_invalid_state_transitions():
    import scan_state as st
    assert st.can_transition(st.QUEUED, st.RUNNING)
    assert not st.can_transition(st.QUEUED, st.COMPLETED)
    with pytest.raises(st.InvalidTransition):
        st.transition(st.COMPLETED, st.RUNNING)


# --- checkpoint TTL: stale checkpoints are treated as absent -----------------
def test_checkpoint_ttl_expiry():
    scanner_db.save_checkpoint("ttl", "dns", {"status": "done"})
    # fresh: visible
    assert "dns" in scanner_db.load_checkpoints("ttl", max_age_seconds=3600)
    # zero-age window: even a just-written row is "too old" -> absent
    time.sleep(0.02)
    assert scanner_db.load_checkpoints("ttl", max_age_seconds=0.001) == {}


# --- handled-error checker results are NOT checkpointed ----------------------
def test_error_results_not_checkpointed():
    run_fake_scan("errcase", error_at=1)  # checker idx 1 returns status=error
    loaded = scanner_db.load_checkpoints("errcase")
    assert "dns" in loaded          # idx 0 done -> checkpointed
    assert "ssl" not in loaded      # idx 1 error -> not checkpointed


# --- result cache: negative results are cached (not recomputed) -------------
def test_cache_negative_caching():
    from result_cache import InMemoryResultCache
    c = InMemoryResultCache()
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return None  # a "miss" / negative

    c.fetch("hibp", "POST", "https://api/q", {"json": {"q": "x"}}, compute)
    c.fetch("hibp", "POST", "https://api/q", {"json": {"q": "x"}}, compute)
    assert calls["n"] == 1, "negative result must be cached, not recomputed"


# --- result cache: rotated secret param coalesces to one key ----------------
def test_cache_secret_rotation_coalesces():
    from result_cache import InMemoryResultCache
    c = InMemoryResultCache()
    calls = {"n": 0}

    def compute():
        calls["n"] += 1
        return make_response(200, b'{"v":1}')

    c.fetch("hibp", "GET", "https://api/y", {"params": {"d": "x", "key": "AAA"}}, compute)
    c.fetch("hibp", "GET", "https://api/y", {"params": {"d": "x", "key": "BBB"}}, compute)
    assert calls["n"] == 1


# --- circuit breaker: trip -> open -> half-open -> recover -------------------
def test_breaker_state_machine():
    from resilience import CircuitBreaker, CLOSED, OPEN, HALF_OPEN
    clock = [1000.0]
    b = CircuitBreaker(failure_threshold=3, reset_timeout=10.0,
                       now=lambda: clock[0])
    assert b.state == CLOSED and b.allow()
    for _ in range(3):
        b.record_failure()
    assert b.state == OPEN
    assert not b.allow(), "open breaker must reject calls"
    clock[0] += 11.0  # past reset_timeout
    assert b.state == HALF_OPEN
    assert b.allow(), "half-open admits a trial call"
    b.record_success()
    assert b.state == CLOSED


# --- retry budget: exhausted budget stops retries ---------------------------
def test_retry_budget_caps_retries():
    from resilience import RetryPolicy
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        raise ConnectionError("boom")  # retriable

    # budget says "no retries allowed" -> exactly one attempt, then raise
    rp = RetryPolicy(max_attempts=5, sleep=lambda s: None)
    with pytest.raises(ConnectionError):
        rp.run(flaky, can_retry=lambda: False)
    assert attempts["n"] == 1


# --- object store: path-traversal keys are rejected -------------------------
def test_object_store_traversal_guard(tmp_path):
    from object_store import LocalObjectStore
    s = LocalObjectStore(str(tmp_path / "obj"))
    s.put("pdfs/ok.pdf", b"%PDF")
    assert s.get("pdfs/ok.pdf") == b"%PDF"
    with pytest.raises(ValueError):
        s.put("../escape", b"x")
    with pytest.raises(ValueError):
        s.get("a\\b")


# --- empty / weird domains still produce a persisted result -----------------
@pytest.mark.parametrize("domain", ["", "   ", "xn--80ak6aa92e.com", "a.b.c.d.example"])
def test_weird_domains_dont_crash(domain):
    sid = f"weird-{uuid.uuid4().hex[:8]}"
    run_fake_scan(sid, domain or "blank.example")
    row = scanner_db.fetch_scan(sid)
    assert row is not None and row["status"] == "completed"
