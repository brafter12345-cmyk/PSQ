"""Concurrency — the invariants that must hold when many workers/threads race.

* durable queue: a job is claimed by exactly one worker (PG: FOR UPDATE SKIP LOCKED;
  SQLite: serialized single-writer) — no double processing.
* in-process pool: every payload handled exactly once.
* result cache: single-flight — concurrent identical requests compute once.
* rate limiter: concurrent acquire never exceeds the bucket / never deadlocks.
* circuit breaker: thread-safe accounting.
"""
from __future__ import annotations

import threading
import uuid
from collections import Counter

import scanner_db
from harness import drain, make_handler, make_response


# --- durable queue: each job processed exactly once under many workers -------
def test_durable_queue_exactly_once():
    n = 40
    for i in range(n):
        sid = f"conc-{i}"
        scanner_db.enqueue_job(str(uuid.uuid4()), sid, {"scan_id": sid})

    log = []
    drain(make_handler(completion_log=log), workers=8, timeout=60)

    counts = Counter(sid for sid, _ in log)
    assert set(counts.values()) == {1}, f"some job ran >1x: {[k for k,v in counts.items() if v>1]}"
    assert len(counts) == n
    done = scanner_db._run("SELECT COUNT(*) AS n FROM scan_jobs WHERE status='completed'",
                           fetch="one")
    assert int(done["n"]) == n


# --- claim_job mutual exclusion: no two threads claim the same job -----------
def test_claim_job_no_double_claim():
    n = 50
    for i in range(n):
        scanner_db.enqueue_job(str(uuid.uuid4()), f"cl-{i}", {"scan_id": f"cl-{i}"})

    claimed = []
    lock = threading.Lock()
    barrier = threading.Barrier(6)

    def claimer(wid):
        barrier.wait()
        while True:
            try:
                job = scanner_db.claim_job(f"w{wid}")
            except Exception:
                continue  # transient sqlite BUSY -> retry
            if not job:
                # could be empty or contention; confirm truly empty
                if scanner_db.queue_depth() == 0:
                    break
                continue
            with lock:
                claimed.append(job["id"])

    threads = [threading.Thread(target=claimer, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert len(claimed) == len(set(claimed)), "a job was claimed by two workers"
    assert len(set(claimed)) == n, "every job should be claimed exactly once"


# --- result cache single-flight: concurrent identical fetches compute once --
def test_cache_single_flight():
    from result_cache import InMemoryResultCache
    c = InMemoryResultCache()
    calls = {"n": 0}
    cl = threading.Lock()
    start = threading.Barrier(16)

    def compute():
        with cl:
            calls["n"] += 1
        import time
        time.sleep(0.05)  # widen the window for a stampede
        return make_response(200, b'{"v":1}')

    def worker():
        start.wait()
        c.fetch("nvd", "GET", "https://api/z", {"params": {"q": "x"}}, compute)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert calls["n"] == 1, f"single-flight failed: computed {calls['n']}x"


# --- rate limiter: concurrent acquire is safe and bounded -------------------
def test_rate_limiter_concurrent():
    from rate_limiter import RedisRateLimiter
    from redis_support import FakeRedis
    # deterministic clock; no real sleeping
    rl = RedisRateLimiter(FakeRedis(), rate=1000.0, burst=5,
                          now=lambda: 1000.0, sleep=lambda s: None)
    waits = []
    wl = threading.Lock()
    start = threading.Barrier(20)

    def worker():
        start.wait()
        w = rl.acquire("apex.example")
        with wl:
            waits.append(w)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(waits) == 20
    assert all(w >= 0.0 for w in waits)  # no negative / no crash / no deadlock


# --- circuit breaker thread-safety ------------------------------------------
def test_breaker_thread_safe():
    from resilience import CircuitBreaker, OPEN
    b = CircuitBreaker(failure_threshold=100, reset_timeout=999.0)
    start = threading.Barrier(10)

    def worker():
        start.wait()
        for _ in range(50):
            b.allow()
            b.record_failure()

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    # 10*50 = 500 failures, threshold 100 -> definitively open, no torn state
    assert b.state == OPEN
