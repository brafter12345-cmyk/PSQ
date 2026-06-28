# Backend test harness

Exercises the **backend** of the scanner — the scaling machinery, not the Flask/UI:

- durable job queue + worker tier (`enqueue_job` / `claim_job` / `run_worker`)
- the scans + checkpoints data layer (`scanner_db`)
- resumability / checkpoints (WS3)
- circuit breaker + retry budget (WS7)
- result cache single-flight (WS6) and distributed rate limiter (WS5a)
- the scoring engine

There is **no UI involvement** — no Flask test client, no templates, no SSE.

## How it stays fast and deterministic

Real scans hit DNS + ~19 providers over the network. The harness instead drives a
**deterministic, offline fake scan** (`harness.run_fake_scan`) that runs through the
*real* `scanner_db.Checkpointer`, the *real* durable queue, and the *real* worker loop
(`job_queue.run_worker`). So the scaling code paths are genuinely tested; only the
network leaf is stubbed.

A separate **opt-in** UAT runs the actual networked scanner — see `RUN_LIVE_SCAN` below.

## Running

```bash
# full suite (throwaway SQLite, prints perf report)
py tests/run_harness.py

# or plain pytest
py -m pytest tests/ -q

# just one suite
py -m pytest tests/test_concurrency.py -v
py tests/run_harness.py --perf          # benchmarks only
```

### Against real Postgres (real FOR UPDATE SKIP LOCKED concurrency + throughput)

```bash
TEST_DATABASE_URL=postgresql://phishield:phishield_local_dev@localhost:5544/phishield_scanner \
  py tests/run_harness.py
```

We use a dedicated `TEST_DATABASE_URL` (not the app's `DATABASE_URL`) so the suite only
ever wipes a database you explicitly point it at. The container is `phishield-pg`
(`docker start phishield-pg`).

### Include the real networked scanner UAT

```bash
RUN_LIVE_SCAN=1 py tests/run_harness.py -k live
```

## Suites

| File | What it proves |
| --- | --- |
| `test_uat.py` | Acceptance: submit → worker picks up → scored result persisted → fetchable → in history. Batch completes exactly once. Usage metered. |
| `test_edge_cases.py` | Queue saturation (429), depth cap, checkpoint upsert + TTL, error results not checkpointed, cache negatives + secret-rotation coalescing, breaker state machine, retry budget, object-store traversal guard, weird domains. |
| `test_concurrency.py` | Each job processed exactly once under N workers, `claim_job` mutual exclusion (no double-claim), cache single-flight under a stampede, rate-limiter thread-safety, breaker thread-safety. |
| `test_resumability.py` | Crash mid-scan → resume reuses checkpoints (only the failed checker + later ones re-run), full-scan resume is a no-op, stale-TTL forces recompute, dead-worker requeue, poison → DLQ. |
| `test_performance.py` | End-to-end throughput + latency p50/p95/p99, checkpoint write/read cost, cache-hit overhead, scoring throughput. Writes `reports/`. |

## Reports

`test_performance.py` writes to `tests/reports/`:

- `perf_<UTC timestamp>.json` — machine-readable
- `latest.md` — human-readable table (also echoed by `run_harness.py`)

These are gitignored. **SQLite is single-writer**, so its throughput/latency reflect
serialized writes; run against Postgres for representative concurrent figures.

## Notes

- Pyright may flag `import "harness" could not be resolved` and `Response` attribute
  assignments — both are cosmetic (the dir is on `sys.path` at runtime via `conftest`;
  the `Response` pattern matches the existing `tooling/` tests).
- Tables are wiped between tests (`conftest._clean`) for isolation.
