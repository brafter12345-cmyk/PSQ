"""Flask-layer hardening gate for pre-deploy verification.

The two existing gates cover the scoring math (verify_supply_chain_
financial_wiring.py) and the scan orchestration (verify_scan_smoke.py),
but neither exercises the Flask app layer — auth, rate limiting, input
validation, queue lifecycle. This gate covers the 2026-06-11 operational
hardening so it cannot silently regress:

  1. SSRF guard      — private/loopback/link-local client_ips rejected,
                       public IPs accepted (app.py /api/scan)
  2. Auth gate       — SCANNER_API_KEY unset -> open (back-compat);
                       set -> 401 without X-Api-Key, 202 with it
  3. Rate limiter    — _RateLimiter fixed window allows N then blocks
  4. Stale pending   — pending scan older than STALE_PENDING_S flips to
                       failed on poll; fresh pending stays 202
  5. Queue timeout   — run_scan fails visibly (DB failed + error event on
                       the progress bus) when no semaphore slot frees within
                       SCAN_QUEUE_TIMEOUT_S, instead of queueing forever
  6. Progress bus +  — WS8 progress bus stores/closes a scan's events, and
     queue admission   the WS2 job queue rejects with 429 when full (these
                       replaced the old in-memory _scan_progress dict + sweep)
  7. Schema version  — scanner stamps RESULTS_SCHEMA_VERSION

Credit-free and network-free: run_scan is monkeypatched to a no-op for
endpoint tests, and the semaphore-timeout test calls run_scan only on a
drained semaphore (it fails before any scanner work starts). Uses a
throwaway SQLite DB via DB_PATH, never scans.db.

Exit code: 0 = all checks pass, 1 = at least one failed (DO NOT DEPLOY).

Usage:
  python tooling/verify_app_hardening.py
"""

import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

# Throwaway DB — must be set BEFORE importing app (init_db runs at import).
_tmpdir = tempfile.mkdtemp(prefix="phishield_hardening_")
os.environ["DB_PATH"] = str(Path(_tmpdir) / "gate_scans.db")
os.environ.pop("SCANNER_API_KEY", None)  # start in open (back-compat) mode

os.chdir(ROOT)
import app as A  # noqa: E402

FAILURES = []


def check(name: str, cond: bool, detail: str = ""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def main():
    client = A.app.test_client()
    # Endpoint tests must not launch real scans. Keep the original for the
    # semaphore-timeout test, which exercises the real pre-scanner path.
    orig_run_scan = A.run_scan
    A.run_scan = lambda *a, **k: None

    # --- 1. SSRF guard on client_ips -----------------------------------
    r = client.post("/api/scan", json={
        "domain": "example.com",
        "client_ips": ["127.0.0.1", "10.0.0.1", "192.168.1.1",
                       "169.254.1.1", "8.8.8.8"],
    })
    body = r.get_json() or {}
    rejected = set(body.get("rejected_client_ips", []))
    check("scan accepts valid domain", r.status_code == 202,
          f"status={r.status_code}")
    check("private/loopback/link-local IPs rejected",
          rejected == {"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1"},
          f"rejected={sorted(rejected)}")
    check("public IP not rejected", "8.8.8.8" not in rejected)

    # --- 2. Auth gate ----------------------------------------------------
    check("auth open when SCANNER_API_KEY unset", r.status_code == 202)
    A.SCANNER_API_KEY = "gate-test-key"
    try:
        r401 = client.post("/api/scan", json={"domain": "example.com"})
        check("401 without X-Api-Key when key set", r401.status_code == 401,
              f"status={r401.status_code}")
        r_ok = client.post("/api/scan", json={"domain": "example.com"},
                           headers={"X-Api-Key": "gate-test-key"})
        check("202 with correct X-Api-Key", r_ok.status_code == 202,
              f"status={r_ok.status_code}")
        r_bad = client.post("/api/scan", json={"domain": "example.com"},
                            headers={"X-Api-Key": "wrong"})
        check("401 with wrong X-Api-Key", r_bad.status_code == 401,
              f"status={r_bad.status_code}")
    finally:
        A.SCANNER_API_KEY = None

    # --- 3. Rate limiter -------------------------------------------------
    rl = A._RateLimiter(max_calls=2, window_s=3600)
    seq = [rl.allow("1.2.3.4"), rl.allow("1.2.3.4"), rl.allow("1.2.3.4")]
    check("rate limiter allows up to max then blocks",
          seq == [True, True, False], f"seq={seq}")
    check("rate limiter isolates per IP", rl.allow("5.6.7.8"))
    rl._hits["1.2.3.4"] = (time.time() - 3601, 2)  # expire the window
    check("rate limiter resets after window", rl.allow("1.2.3.4"))

    # --- 4. Stale-pending expiry -----------------------------------------
    A.save_scan("stale-test-id", "example.com")
    with A.get_db() as conn:
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc)
               - timedelta(seconds=A.STALE_PENDING_S + 60)).isoformat()
        conn.execute("UPDATE scans SET created_at=? WHERE id=?",
                     (old, "stale-test-id"))
        conn.commit()
    r_stale = client.get("/api/scan/stale-test-id")
    body = r_stale.get_json() or {}
    check("stale pending scan flips to failed",
          r_stale.status_code == 500 and body.get("status") == "failed",
          f"status={r_stale.status_code} body={body}")
    row = A.fetch_scan("stale-test-id")
    check("stale scan marked failed in DB", row["status"] == "failed",
          f"db_status={row['status']}")

    A.save_scan("fresh-test-id", "example.com")
    r_fresh = client.get("/api/scan/fresh-test-id")
    check("fresh pending scan still 202", r_fresh.status_code == 202,
          f"status={r_fresh.status_code}")

    # --- 5. Semaphore queue timeout --------------------------------------
    A.save_scan("queue-timeout-id", "example.com")
    held = 0
    while A._semaphore.acquire(blocking=False):
        held += 1
    orig_timeout = A.SCAN_QUEUE_TIMEOUT_S
    A.SCAN_QUEUE_TIMEOUT_S = 1
    try:
        t0 = time.time()
        # Direct (synchronous) call of the REAL run_scan: with the semaphore
        # drained this must fail fast and visibly, never block or touch the
        # network (the timeout fires before any scanner work starts).
        orig_run_scan("queue-timeout-id", "example.com")
        elapsed = time.time() - t0
        row = A.fetch_scan("queue-timeout-id")
        # WS8: progress now flows through the progress bus, not the old
        # in-memory _scan_progress dict — read the error event from there.
        events = A.get_progress_bus().recent("queue-timeout-id")
        emitted_error = any(isinstance(e, dict) and e.get("type") == "error" for e in events)
        check("queued scan fails visibly on slot timeout",
              row["status"] == "failed" and elapsed < 10,
              f"db_status={row['status']} elapsed={elapsed:.1f}s")
        check("queue timeout publishes an error event to the progress bus",
              emitted_error, f"events={events}")
    finally:
        A.SCAN_QUEUE_TIMEOUT_S = orig_timeout
        for _ in range(held):
            A._semaphore.release()
        A.run_scan = lambda *a, **k: None

    # --- 6. Progress bus + job-queue admission ----------------------------
    # WS8/WS2 replaced the old in-memory _scan_progress dict (+ its TTL sweep)
    # with the progress bus and a bounded job queue. Verify the replacement
    # mechanisms that now carry the same guarantees.
    bus = A.get_progress_bus()
    bus.publish("bus-smoke-id", {"type": "running"})
    has_event = any(e.get("type") == "running" for e in bus.recent("bus-smoke-id"))
    bus.close("bus-smoke-id")
    check("progress bus stores then closes a scan's events",
          has_event and bus.recent("bus-smoke-id") == [])

    # Submit-time admission control: when the queue rejects (full), POST
    # /api/scan returns 429 instead of unbounded scan pile-up.
    orig_enqueue = A.SCAN_QUEUE.enqueue
    A.SCAN_QUEUE.enqueue = lambda *a, **k: False
    try:
        r_full = client.post("/api/scan", json={"domain": "example.com"})
        check("scan rejected with 429 when job queue full",
              r_full.status_code == 429, f"status={r_full.status_code}")
    finally:
        A.SCAN_QUEUE.enqueue = orig_enqueue

    # --- 7. Results schema version ----------------------------------------
    from scanner import RESULTS_SCHEMA_VERSION
    check("scanner exports RESULTS_SCHEMA_VERSION",
          isinstance(RESULTS_SCHEMA_VERSION, str) and RESULTS_SCHEMA_VERSION,
          f"value={RESULTS_SCHEMA_VERSION!r}")

    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} check(s) FAILED — DO NOT DEPLOY")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("RESULT: all app-hardening checks PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
