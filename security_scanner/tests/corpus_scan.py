"""Real-scan corpus runner.

Runs the ACTUAL `SecurityScanner` against a sample of South African domains
(`tests/corpus/sa_domains.csv`), times each scan, and writes a report to
`tests/reports/`. This makes real network connections (DNS, TLS, HTTP, active TCP
port probes) and — in --paid mode — real provider API calls.

    py tests/corpus_scan.py --limit 1
    py tests/corpus_scan.py --limit 10
    py tests/corpus_scan.py --tier large_corporate --limit 5
    py tests/corpus_scan.py --limit 10 --paid          # enable VT/Shodan/HIBP/etc.

Free-only is the default: the paid provider keys only enter the process via
`load_dotenv()`, which we skip (and we also pop any that leaked in), so those checkers
self-skip with `no_api_key`.

Concurrency note: the in-process scanner shares a module-level DNS cache, so running
multiple scans in ONE process concurrently is unsafe. This runner is sequential. For
true parallel real scans, use the worker tier (Postgres queue + multiple `worker.py`
processes) — each worker is its own process.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CORPUS = HERE / "corpus" / "sa_domains.csv"
REPORTS = HERE / "reports"
PAID_KEYS = ["VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "HIBP_API_KEY",
             "DEHASHED_API_KEY", "SECURITYTRAILS_API_KEY", "INTELX_API_KEY"]


def load_corpus(tier=None, offset=0, limit=None):
    with CORPUS.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if tier:
        rows = [r for r in rows if r["size_tier"] == tier]
    rows = rows[offset:]
    if limit:
        rows = rows[:limit]
    return rows


def _summarize(domain, results, duration, org, sector, tier):
    sc = results.get("_scan_completeness", {}) or {}
    return {
        "domain": domain,
        "organization": org,
        "sector": sector,
        "size_tier": tier,
        "ok": True,
        "duration_s": round(duration, 1),
        "risk_score": results.get("overall_risk_score"),
        "risk_level": results.get("risk_level"),
        "coverage_pct": sc.get("coverage_pct"),
        "confidence": sc.get("confidence_level"),
        "checkers_observed": sc.get("checkers_observed"),
        "ips_found": len(results.get("discovered_ips", []) or []),
        "slowest_checker": sc.get("slowest_checker"),
    }


def run(rows, paid=False, industry="other"):
    if paid:
        try:
            from dotenv import load_dotenv
            load_dotenv()
            print("[corpus] PAID mode: provider keys loaded from .env")
        except Exception:
            print("[corpus] WARN: --paid set but dotenv load failed")
    else:
        for k in PAID_KEYS:
            os.environ.pop(k, None)
        print("[corpus] FREE mode: paid provider keys withheld (checkers self-skip)")

    from scanner import SecurityScanner  # import after env is set

    out = []
    for i, r in enumerate(rows, 1):
        dom = r["domain"]
        print(f"[corpus] ({i}/{len(rows)}) scanning {dom} "
              f"[{r['size_tier']}/{r['sector']}] ...", flush=True)
        t0 = time.perf_counter()
        try:
            # paid keys are popped above; re-pop defensively in free mode in case an
            # import re-loaded .env
            if not paid:
                for k in PAID_KEYS:
                    os.environ.pop(k, None)
            res = SecurityScanner().scan(dom, industry=industry)
            dt = time.perf_counter() - t0
            row = _summarize(dom, res, dt, r["organization"], r["sector"], r["size_tier"])
            print(f"    -> {row['risk_level']} (score {row['risk_score']}), "
                  f"{row['ips_found']} IP(s), coverage {row['coverage_pct']}%, "
                  f"{row['duration_s']}s", flush=True)
        except Exception as e:  # noqa: BLE001
            dt = time.perf_counter() - t0
            row = {"domain": dom, "organization": r["organization"],
                   "sector": r["sector"], "size_tier": r["size_tier"],
                   "ok": False, "duration_s": round(dt, 1), "error": str(e)[:300]}
            print(f"    -> ERROR after {row['duration_s']}s: {row['error']}", flush=True)
        out.append(row)
    return out


def write_report(results, paid):
    REPORTS.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ok = [r for r in results if r.get("ok")]
    durations = [r["duration_s"] for r in ok]
    payload = {
        "generated_at_utc": stamp,
        "mode": "paid" if paid else "free",
        "scanned": len(results),
        "succeeded": len(ok),
        "failed": len(results) - len(ok),
        "avg_duration_s": round(sum(durations) / len(durations), 1) if durations else None,
        "results": results,
    }
    jpath = REPORTS / f"corpus_{stamp}.json"
    jpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\n[corpus] report -> {jpath}")
    # console table
    print("\n  domain                          tier             level        score  cov%  secs")
    print("  " + "-" * 84)
    for r in results:
        if r.get("ok"):
            print(f"  {r['domain']:<31.31} {r['size_tier']:<16.16} "
                  f"{str(r['risk_level']):<12.12} {str(r['risk_score']):>5} "
                  f"{str(r.get('coverage_pct','')):>4}  {r['duration_s']:>5}")
        else:
            print(f"  {r['domain']:<31.31} {r['size_tier']:<16.16} "
                  f"{'ERROR':<12} {'':>5} {'':>4}  {r['duration_s']:>5}")
    print(f"\n  {payload['succeeded']}/{payload['scanned']} succeeded, "
          f"avg {payload['avg_duration_s']}s/scan ({payload['mode']} mode)")
    return jpath


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=1)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--tier", default=None,
                    help="filter: large_corporate|mid_market|sme|public_sector|education|fintech")
    ap.add_argument("--industry", default="other")
    ap.add_argument("--paid", action="store_true", help="enable paid provider APIs")
    args = ap.parse_args()

    rows = load_corpus(tier=args.tier, offset=args.offset, limit=args.limit)
    if not rows:
        print("[corpus] no domains matched the selection")
        return 1
    print(f"[corpus] selected {len(rows)} domain(s)")
    results = run(rows, paid=args.paid, industry=args.industry)
    write_report(results, paid=args.paid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
