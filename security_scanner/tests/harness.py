"""Shared harness utilities for the backend test suite.

The centrepiece is a *deterministic, offline* scan that drives the REAL backend code
paths — `scanner_db.Checkpointer`, the durable queue (`enqueue_job`/`claim_job`/
`run_worker`), and the scans/checkpoints tables — without any network. That lets the
UAT / concurrency / resumability / performance suites assert behaviour of the actual
scaling machinery rather than mocks.
"""
from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import scanner_db
from job_queue import run_worker

REPORTS = Path(__file__).resolve().parent / "reports"

# A representative checker sequence (names are arbitrary; the pipeline shape is what
# matters for checkpoint/resume behaviour).
DEFAULT_CHECKERS = ["dns", "ssl", "http_headers", "open_ports", "shodan_vulns",
                    "exposed_admin", "dnsbl", "threats"]


# --------------------------------------------------------------------------- #
# Spy — thread-safe per-checker computation counter
# --------------------------------------------------------------------------- #
class Spy:
    """Counts how many times each checker actually *computed*. Resumability tests use
    it to prove a checker was skip-and-loaded from a checkpoint (count stays 0/1)
    rather than recomputed."""

    def __init__(self):
        self._n: dict = {}
        self._lock = threading.Lock()

    def hit(self, name: str) -> None:
        with self._lock:
            self._n[name] = self._n.get(name, 0) + 1

    def count(self, name: str) -> int:
        with self._lock:
            return self._n.get(name, 0)

    def total(self) -> int:
        with self._lock:
            return sum(self._n.values())

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._n)


# --------------------------------------------------------------------------- #
# Deterministic fake scan (runs through the real Checkpointer)
# --------------------------------------------------------------------------- #
def run_fake_scan(scan_id, domain="example.com", *, checkers=None, resume=False,
                  spy=None, fail_at=None, error_at=None, sleep_s=0.0,
                  max_age_seconds=None) -> dict:
    """Mimic `scanner.scan()`'s checkpointed phase loop, offline and deterministically.

    Each checker runs through a real `scanner_db.Checkpointer`, so checkpoints are
    genuinely persisted to / loaded from the configured DB.

    * ``fail_at`` (int idx): raise inside that checker (simulated crash) — nothing is
      checkpointed for it, and the scan aborts (exception propagates).
    * ``error_at`` (int idx): that checker returns an ``{"status": "error"}`` result
      (a *handled* failure) — not checkpointed, so it re-runs on resume.
    """
    checkers = checkers or DEFAULT_CHECKERS
    if not scanner_db.fetch_scan(scan_id):
        scanner_db.save_scan(scan_id, domain)
    ckpt = scanner_db.Checkpointer(scan_id, resume=resume,
                                   max_age_seconds=max_age_seconds)
    results = {}
    for i, name in enumerate(checkers):
        def _compute(name=name, i=i):
            if spy is not None:
                spy.hit(name)
            if sleep_s:
                time.sleep(sleep_s)
            if fail_at is not None and i == fail_at:
                raise RuntimeError(f"injected crash at checker '{name}'")
            if error_at is not None and i == error_at:
                return {"status": "error", "detail": f"handled error at '{name}'"}
            return {"status": "done", "score": (i + 1) * 10}
        results[name] = ckpt.run(name, _compute)
    score = sum(r.get("score", 0) for r in results.values() if isinstance(r, dict))
    scanner_db.update_scan(scan_id, {
        "overall_risk_score": score, "risk_level": "Test", "categories": results})
    return results


def make_handler(*, sleep_s=0.0, fail_scan_ids=None, spy=None, checkers=None,
                 completion_log=None):
    """Build a durable-queue handler ``payload -> None`` that runs a fake scan.

    ``fail_scan_ids`` lets a job raise unconditionally (to drive retry/requeue/DLQ).
    ``completion_log`` (a list) receives ``(scan_id, perf_counter)`` on success.
    """
    fail = set(fail_scan_ids or ())

    def handler(payload):
        sid = payload["scan_id"]
        if sid in fail:
            raise RuntimeError(f"poison job {sid}")
        run_fake_scan(sid, payload.get("domain", "example.com"), checkers=checkers,
                      resume=payload.get("resume", False), spy=spy, sleep_s=sleep_s)
        if completion_log is not None:
            completion_log.append((sid, time.perf_counter()))

    return handler


# --------------------------------------------------------------------------- #
# Multi-worker drainer — drives the real run_worker loop
# --------------------------------------------------------------------------- #
def _running_count() -> int:
    try:
        row = scanner_db._run(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE status='running'", fetch="one")
        return int(row["n"]) if row else 0
    except Exception:
        return 0


def drain(handler, *, workers=4, timeout=60.0, poll=0.01) -> float:
    """Run ``workers`` real `run_worker` threads against the durable queue until it is
    fully drained (no queued or running jobs) or ``timeout`` elapses. Returns elapsed
    seconds. This exercises claim/heartbeat/complete/fail/requeue for real."""
    stop = threading.Event()
    threads = [threading.Thread(
        target=run_worker, kwargs=dict(handler=handler, poll=poll, stop=stop),
        daemon=True, name=f"harness-worker-{i}") for i in range(workers)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    deadline = t0 + timeout
    try:
        while time.perf_counter() < deadline:
            if scanner_db.queue_depth() == 0 and _running_count() == 0:
                break
            time.sleep(poll)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=3.0)
    return time.perf_counter() - t0


# --------------------------------------------------------------------------- #
# A requests.Response factory (for cache tests)
# --------------------------------------------------------------------------- #
def make_response(status=200, body=b'{"ok":1}', url="https://api.example/x") -> "requests.Response":
    r = requests.models.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.url = url
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"X-Test": "1"})
    return r


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
def percentiles(samples, ps=(50, 95, 99)) -> dict:
    """Linear-interpolated percentiles (ms-agnostic; same unit in/out)."""
    if not samples:
        return {f"p{p}": None for p in ps}
    s = sorted(samples)
    out = {}
    for p in ps:
        if len(s) == 1:
            out[f"p{p}"] = s[0]
            continue
        k = (len(s) - 1) * (p / 100.0)
        lo = int(k)
        hi = min(lo + 1, len(s) - 1)
        out[f"p{p}"] = s[lo] + (s[hi] - s[lo]) * (k - lo)
    return out


class Bench:
    """Collects benchmark results across the perf suite and renders a report."""

    def __init__(self, backend="sqlite"):
        self.backend = backend
        self.results: dict = {}

    def add(self, name: str, **fields) -> None:
        self.results[name] = fields

    def save(self):
        if not self.results:
            return None
        REPORTS.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        payload = {
            "generated_at_utc": stamp,
            "backend": self.backend,
            "benchmarks": self.results,
        }
        json_path = REPORTS / f"perf_{stamp}.json"
        md_path = REPORTS / "latest.md"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        md_path.write_text(_render_md(payload), encoding="utf-8")
        payload["_paths"] = {"json": str(json_path), "md": str(md_path)}
        return payload


def _fmt(v):
    if isinstance(v, float):
        return f"{v:,.3f}"
    return str(v)


def _render_md(payload: dict) -> str:
    lines = [
        "# Backend performance report",
        "",
        f"- Generated (UTC): `{payload['generated_at_utc']}`",
        f"- Backend: **{payload['backend']}**",
        "",
        "| Benchmark | Metric | Value |",
        "| --- | --- | --- |",
    ]
    for name, fields in payload["benchmarks"].items():
        first = True
        for k, v in fields.items():
            label = name if first else ""
            lines.append(f"| {label} | {k} | {_fmt(v)} |")
            first = False
    lines.append("")
    lines.append("_Generated by `tests/` harness. SQLite is single-writer; Postgres "
                 "(TEST_DATABASE_URL) reflects real concurrent throughput._")
    return "\n".join(lines)
