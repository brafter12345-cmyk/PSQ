"""Performance / benchmarking — throughput, latency percentiles, and the cost of the
core hot paths. Results are written to ``tests/reports/`` (JSON + latest.md) via the
session ``bench`` fixture.

Numbers are characterisation, not pass/fail gates (so they don't go red on a busy CI
box) — the asserts only check sane lower bounds. SQLite is single-writer, so its
throughput reflects serialized writes; point ``TEST_DATABASE_URL`` at Postgres for
real concurrent figures.
"""
from __future__ import annotations

import time
import uuid

import scanner_db
from harness import drain, make_handler, make_response, percentiles


def _workers():
    return 8 if scanner_db.is_postgres() else 4


# --- end-to-end queue throughput + latency percentiles ----------------------
def test_throughput_and_latency(bench):
    n = 200
    enq = {}
    for i in range(n):
        sid = f"perf-{i}"
        scanner_db.enqueue_job(str(uuid.uuid4()), sid, {"scan_id": sid})
        enq[sid] = time.perf_counter()

    log = []
    elapsed = drain(make_handler(completion_log=log), workers=_workers(), timeout=120)

    assert len(log) == n, f"only {len(log)}/{n} jobs completed"
    latencies_ms = [(done - enq[sid]) * 1000.0 for sid, done in log]
    pct = percentiles(latencies_ms)
    throughput = n / elapsed if elapsed > 0 else 0.0

    bench.add("queue_end_to_end",
              jobs=n, workers=_workers(),
              wall_seconds=round(elapsed, 3),
              throughput_jobs_per_sec=round(throughput, 1),
              latency_p50_ms=round(pct["p50"], 2),
              latency_p95_ms=round(pct["p95"], 2),
              latency_p99_ms=round(pct["p99"], 2))

    assert throughput > 1.0  # sane lower bound


# --- checkpoint write/read overhead -----------------------------------------
def test_checkpoint_overhead(bench):
    m = 500
    sid = "perf-ckpt"
    t0 = time.perf_counter()
    for i in range(m):
        scanner_db.save_checkpoint(sid, f"checker_{i}", {"status": "done", "i": i})
    write_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    loaded = scanner_db.load_checkpoints(sid)
    read_s = time.perf_counter() - t1

    assert len(loaded) == m
    bench.add("checkpoint",
              rows=m,
              write_per_row_ms=round(write_s / m * 1000.0, 3),
              load_all_ms=round(read_s * 1000.0, 3),
              writes_per_sec=round(m / write_s, 1) if write_s else None)


# --- result-cache hit overhead ----------------------------------------------
def test_cache_hit_speed(bench):
    from result_cache import InMemoryResultCache
    c = InMemoryResultCache()

    def compute():
        return make_response(200, b'{"v":1,"data":"' + b"x" * 256 + b'"}')

    # prime (miss)
    c.fetch("nvd", "GET", "https://api/z", {"params": {"q": "x"}}, compute)
    k = 5000
    t0 = time.perf_counter()
    for _ in range(k):
        c.fetch("nvd", "GET", "https://api/z", {"params": {"q": "x"}}, compute)
    hit_s = time.perf_counter() - t0

    bench.add("cache_hit",
              iterations=k,
              hit_per_call_us=round(hit_s / k * 1_000_000.0, 2),
              hits_per_sec=round(k / hit_s, 0) if hit_s else None)
    assert hit_s / k < 0.01  # < 10ms/hit, generous


# --- scoring engine throughput ----------------------------------------------
def test_scoring_throughput(bench):
    from scoring_analytics import RiskScorer
    s = RiskScorer()
    sample = {kname: {"score": 50} for kname in s.WEIGHTS}

    k = 300
    t0 = time.perf_counter()
    for _ in range(k):
        s.calculate(dict(sample))
    elapsed = time.perf_counter() - t0

    bench.add("scoring",
              iterations=k,
              per_calc_ms=round(elapsed / k * 1000.0, 3),
              calcs_per_sec=round(k / elapsed, 1) if elapsed else None)
    assert k / elapsed > 5.0
