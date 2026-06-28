"""Single REAL scan through the full distributed backend — proof the architecture fires.

Unlike corpus_scan.py (which calls SecurityScanner.scan() directly), this drives the
*actual* production path:

    save_scan -> SCAN_QUEUE.enqueue (durable Postgres queue, WS2)
              -> run_worker claims it (FOR UPDATE SKIP LOCKED, WS2)
              -> app._run_scan_job -> run_scan
                   -> progress bus (Redis, WS8)
                   -> observe_scan (metrics + trace, WS9)
                   -> scanner.scan(scan_id, resume=True) -> per-checker checkpoints (WS3)
                   -> Redis rate-limiter + result cache (WS5a / WS6)
                   -> update_scan -> Postgres persistence (WS1)
                   -> enqueue_pdf -> PDF worker + object store (WS4)

Then it prints the evidence each workstream left behind.

    py tests/backend_smoke.py [domain] [--paid]
"""
from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# --- point every backend at real infra BEFORE importing app ---
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://phishield:phishield_local_dev@localhost:5544/phishield_scanner")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ["QUEUE_BACKEND"] = "postgres"

DOMAIN = next((a for a in sys.argv[1:] if not a.startswith("--")), "standardbank.co.za")
PAID = "--paid" in sys.argv

import scanner_db  # noqa: E402
scanner_db.init_schema()

import app  # noqa: E402  (top-level load_dotenv + builds SCAN_QUEUE on the PG backend)
import observability  # noqa: E402
from job_queue import run_worker  # noqa: E402

# free-only: null the provider keys app loaded from .env so paid checkers self-skip
if not PAID:
    for attr in ("HIBP_API_KEY", "DEHASHED_API_KEY", "DEHASHED_EMAIL",
                 "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY", "SHODAN_API_KEY",
                 "INTELX_API_KEY"):
        if hasattr(app, attr):
            setattr(app, attr, None)

bus = app.get_progress_bus()
print("=" * 72)
print(f"backend   : {'postgres' if scanner_db.is_postgres() else 'sqlite'}")
print(f"queue     : {type(app.SCAN_QUEUE).__name__}")
print(f"progress  : {type(bus).__name__}")
print(f"mode      : {'PAID' if PAID else 'FREE'}")
print(f"target    : {DOMAIN}")
print("=" * 72)

scan_id = "backend-smoke-" + uuid.uuid4().hex[:8]
app.save_scan(scan_id, DOMAIN, industry="other")
accepted = app.SCAN_QUEUE.enqueue(scan_id, {"scan_id": scan_id, "domain": DOMAIN,
                                            "industry": "other"})
print(f"[enqueue] {scan_id}: accepted={accepted}, queue_depth={scanner_db.queue_depth()}")

# --- run ONE real worker (the production loop) to claim + process the job ---
stop = threading.Event()
worker = threading.Thread(target=run_worker,
                          kwargs=dict(handler=app._run_scan_job, poll=0.5, stop=stop),
                          daemon=True)
t0 = time.perf_counter()
worker.start()
print("[worker ] started; waiting for completion ...")

last_n = -1
while time.perf_counter() - t0 < 900:
    row = scanner_db.fetch_scan(scan_id)
    n = len(scanner_db.load_checkpoints(scan_id))
    if n != last_n:
        print(f"   .. checkpoints persisted: {n}", flush=True)
        last_n = n
    if row and row["status"] in ("completed", "failed"):
        break
    time.sleep(3)
stop.set()
worker.join(timeout=5)
elapsed = time.perf_counter() - t0

# --------------------------------------------------------------------------- #
# Evidence dump
# --------------------------------------------------------------------------- #
row = scanner_db.fetch_scan(scan_id)
cps = scanner_db.load_checkpoints(scan_id)
job = scanner_db._run(
    "SELECT id, status, worker_id, attempts FROM scan_jobs WHERE scan_id=?",
    (scan_id,), fetch="one")
try:
    events = bus.recent(scan_id)
except Exception as e:  # noqa: BLE001
    events = [{"type": f"<recent() error: {e}>"}]

print("\n" + "=" * 72)
print("EVIDENCE — each workstream left a trace")
print("=" * 72)
print(f"WS2 queue : job {str(job['id'])[:8]} status={job['status']} "
      f"worker={job['worker_id']} attempts={job['attempts']} | depth now={scanner_db.queue_depth()}")
print(f"WS1 PG    : scan row status={row['status']} score={row['risk_score']} "
      f"level={row['risk_level']} (durable in Postgres)")
print(f"WS3 ckpts : {len(cps)} per-checker checkpoints -> {sorted(cps)}")
ev_types = [e.get("type") for e in events if isinstance(e, dict)]
print(f"WS8 bus   : {len(events)} progress events via Redis; types={ev_types[:12]}")

# WS9 — Prometheus metrics
try:
    from prometheus_client import generate_latest
    txt = generate_latest().decode()
    print("WS9 metrics:")
    for m in ("scans_total", "scan_duration_seconds_count", "provider_calls_total",
              "checker_duration_seconds_count", "circuit_breaker_open_total"):
        hit = [ln for ln in txt.splitlines() if ln.startswith(m)]
        if hit:
            print(f"            {hit[0]}")
except Exception as e:  # noqa: BLE001
    print(f"WS9 metrics: error {e}")

# WS5a / WS6 / WS8 — Redis keyspace touched
try:
    from redis_support import get_redis
    r = get_redis()
    keys = [k.decode() if isinstance(k, bytes) else k for k in r.keys("*")] if r else []
    buckets = [k for k in keys if "bucket" in k or "rl:" in k]
    cache = [k for k in keys if "cache" in k or "rc:" in k or "result" in k]
    prog = [k for k in keys if "progress" in k or scan_id in k]
    print(f"WS5a rate : {len(buckets)} redis token-bucket key(s) {buckets[:3]}")
    print(f"WS6 cache : {len(cache)} redis cache key(s) {cache[:3]}")
    print(f"WS8 redis : {len(prog)} redis progress key(s) {prog[:3]}")
    print(f"            (total redis keys touched: {len(keys)})")
except Exception as e:  # noqa: BLE001
    print(f"Redis     : error {e}")

# WS4 — PDF/object store
try:
    import object_store
    store = object_store.make_object_store()
    pdfs = store.list_prefix(f"pdfs/{scan_id}")
    print(f"WS4 pdf   : object-store blobs for this scan -> {pdfs or '(rendering async/none)'}")
except Exception as e:  # noqa: BLE001
    print(f"WS4 pdf   : {e}")

print("=" * 72)
print(f"completed in {elapsed:.1f}s — status={row['status']}")
sys.exit(0 if row and row["status"] == "completed" else 1)
