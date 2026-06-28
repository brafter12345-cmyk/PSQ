"""Disaster-recovery reconciliation (WS10 / SCALE-18).

The platform spreads state across three stores: Postgres (scans, checkpoints, usage),
object storage (PDFs), and Redis (cache + rate-limit + progress). A naive restore
recovers Postgres to T but the object store to T-Δ (or loses Redis), leaving orphaned
PDFs and mis-attributed spend. The reconciliation rule:

  * **Postgres is the single source of truth.** PDFs and the Redis ledger are
    derivable.
  * After a Postgres PITR, the object store reconciles to ``scans``: drop PDF blobs
    whose scan_id no longer exists; re-render (WS4) completed scans missing their PDF.
  * The Redis usage counters rebuild from the durable Postgres ``usage`` table.

Targets: RPO <= 15 min (Postgres PITR / WAL archiving), RTO <= 1 h.

This module provides the reconciliation sweep; run it after a restore (or on a
schedule). It is read-mostly and safe to dry-run.
"""
from __future__ import annotations

import scanner_db
from object_store import make_object_store


def reconcile_object_store(dry_run: bool = True, reenqueue=None) -> dict:
    """Reconcile object-store PDFs against the scans table.

    Returns a report dict. With ``dry_run=False`` it deletes orphaned PDF blobs and
    (if ``reenqueue`` is given: ``reenqueue(scan_id, tier, results)``) re-renders
    completed scans whose PDF is missing.
    """
    store = make_object_store()
    pdf_keys = [k for k in store.list_prefix("pdfs") if k.endswith(".pdf")]
    # pdfs/<scan_id>/<tier>.pdf
    by_scan = {}
    for k in pdf_keys:
        parts = k.split("/")
        if len(parts) >= 3:
            by_scan.setdefault(parts[1], []).append(k)

    orphaned, missing = [], []
    for scan_id, keys in by_scan.items():
        if scanner_db.fetch_scan(scan_id) is None:
            orphaned.extend(keys)             # scan gone -> blob is orphaned

    # completed scans whose PDF blob is absent -> re-render candidates
    completed = scanner_db._run(
        "SELECT id, results FROM scans WHERE status='completed'", fetch="all")
    import json
    for row in completed:
        if row["id"] not in by_scan:
            missing.append(row["id"])

    if not dry_run:
        for k in orphaned:
            store.delete(k)
        if reenqueue is not None:
            for row in completed:
                if row["id"] in missing and row.get("results"):
                    try:
                        reenqueue(row["id"], "full", json.loads(row["results"]))
                    except Exception:
                        pass

    return {
        "pdf_blobs": len(pdf_keys),
        "scans_with_pdfs": len(by_scan),
        "orphaned_blobs": orphaned,
        "missing_pdf_scans": missing,
        "dry_run": dry_run,
    }


def rebuild_usage_cache(redis=None) -> int:
    """Rebuild the Redis usage counters from the durable Postgres ``usage`` table
    (Redis is a cache of Postgres, never the source of billing truth). Returns rows
    replayed. No-op if Redis is absent."""
    if redis is None:
        from redis_support import get_redis
        redis = get_redis()
    if redis is None:
        return 0
    rows = scanner_db._run("SELECT provider, day, calls FROM usage", fetch="all")
    for r in rows:
        try:
            redis.set(f"usage:{r['provider']}:{r['day']}", int(r["calls"]))
        except Exception:
            pass
    return len(rows)
