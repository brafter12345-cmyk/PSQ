"""Parallel corpus scan via the real worker tier (WS2).

Spawns N separate worker PROCESSES (each its own DNS cache -> safe parallelism),
enqueues a slice of the SA corpus onto the durable Postgres queue, and watches the
workers drain it concurrently. Reports per-domain time, peak concurrency, wall clock,
and the speedup vs running them sequentially.

    py tests/corpus_parallel.py --workers 4 --offset 1 --limit 4
    py tests/corpus_parallel.py --workers 4 --offset 1 --limit 4 --paid

Free-only by default (paid provider keys nulled in each worker). PG + Redis must be up.
"""
from __future__ import annotations

import argparse
import csv
import multiprocessing as mp
import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# distributed backends for every process (children inherit via spawn)
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://phishield:phishield_local_dev@localhost:5544/phishield_scanner")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ["QUEUE_BACKEND"] = "postgres"

CORPUS = ROOT / "tests" / "corpus" / "sa_domains.csv"
PAID_KEYS = ["VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "HIBP_API_KEY",
             "DEHASHED_API_KEY", "SECURITYTRAILS_API_KEY", "INTELX_API_KEY"]


def worker_proc(worker_id: str, stop, paid: bool):
    """A real worker process: drains the PG queue via run_worker."""
    import app  # load_dotenv + PostgresJobQueue (QUEUE_BACKEND=postgres)
    if not paid:
        for k in PAID_KEYS:
            os.environ.pop(k, None)
        for attr in ("HIBP_API_KEY", "DEHASHED_API_KEY", "DEHASHED_EMAIL",
                     "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY", "SHODAN_API_KEY",
                     "INTELX_API_KEY"):
            if hasattr(app, attr):
                setattr(app, attr, None)
    from job_queue import run_worker
    run_worker(app._run_scan_job, worker_id=worker_id, poll=0.5, stop=stop)


def load_slice(offset, limit):
    with CORPUS.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows[offset:offset + limit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--offset", type=int, default=1)   # default: skip standardbank (#0)
    ap.add_argument("--limit", type=int, default=4)
    ap.add_argument("--paid", action="store_true")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    import scanner_db as db
    db.init_schema()

    rows = load_slice(args.offset, args.limit)
    sids = {}
    print(f"[parallel] enqueuing {len(rows)} domain(s) onto the Postgres queue:")
    for r in rows:
        sid = str(uuid.uuid4())
        sids[sid] = r
        db.save_scan(sid, r["domain"], industry="other")
        db.enqueue_job(str(uuid.uuid4()), sid, {"scan_id": sid, "domain": r["domain"],
                                                "industry": "other"})
        print(f"           - {r['domain']:<22} {sid[:8]}")
    print(f"[parallel] queue depth = {db.queue_depth()}")

    # spawn N worker processes
    stop = mp.Event()
    procs = []
    for i in range(args.workers):
        p = mp.Process(target=worker_proc, args=(f"corpusw-{i}", stop, args.paid),
                       daemon=False)
        p.start()
        procs.append(p)
    print(f"[parallel] started {args.workers} worker PROCESSES: "
          f"{[p.pid for p in procs]}")

    t0 = time.perf_counter()
    done = {}
    peak_running = 0
    while len(done) < len(sids) and time.perf_counter() - t0 < args.timeout:
        running = db._run("SELECT COUNT(*) AS n FROM scan_jobs WHERE status='running'",
                          fetch="one")
        peak_running = max(peak_running, int(running["n"]) if running else 0)
        for sid, r in sids.items():
            if sid in done:
                continue
            row = db.fetch_scan(sid)
            if row and row["status"] in ("completed", "failed"):
                dt = time.perf_counter() - t0
                done[sid] = (r["domain"], row["status"], row["risk_score"], dt)
                print(f"[parallel] +{dt:6.1f}s  {r['domain']:<22} {row['status']} "
                      f"score={row['risk_score']}  ({len(done)}/{len(sids)})", flush=True)
        time.sleep(2)
    wall = time.perf_counter() - t0

    stop.set()
    for p in procs:
        p.join(timeout=10)
        if p.is_alive():
            p.terminate()

    # report
    print("\n" + "=" * 64)
    print(f"PARALLEL RUN — {args.workers} worker processes")
    print("=" * 64)
    indiv = sorted((v[3] for v in done.values()))
    seq_estimate = sum(indiv)
    for sid, (dom, st, score, dt) in sorted(done.items(), key=lambda x: x[1][3]):
        print(f"  {dom:<24} {st:<10} score={str(score):<5} done@ {dt:6.1f}s")
    print("-" * 64)
    print(f"  completed       : {len(done)}/{len(sids)}")
    print(f"  peak concurrency: {peak_running} scans running at once")
    print(f"  wall clock      : {wall:.1f}s (parallel)")
    print(f"  sum of finishes : {seq_estimate:.1f}s  (~sequential lower bound)")
    if wall > 0:
        print(f"  speedup         : ~{seq_estimate / wall:.1f}x")
    print("=" * 64)


if __name__ == "__main__":
    mp.freeze_support()
    main()
