"""End-to-end scan smoke test for pre-deploy verification.

Catches the class of bug that broke nexorsa.com on 2026-05-28:
`UnboundLocalError` in `SecurityScanner.scan()` from a redundant local
`from ... import` shadowing a module-level import. Lived in production
~36 hours because the math-only wiring verifier
(`verify_supply_chain_financial_wiring.py`) builds synthetic
`cat_results` dicts and calls the calculators directly — it never
actually invokes `SecurityScanner.scan()` so cannot detect
import / scoping / NameError / AttributeError defects in the scan
orchestration code path.

This script runs a REAL scan against `example.com` (canonical IANA
test domain). It exercises the full `scan()` code path while consuming
ZERO paid-API credits: `SecurityScanner()` is constructed with NO API
keys (see below), so every paid checker — IntelX, DeHashed, VirusTotal,
SecurityTrails, Shodan(full-API), HIBP — returns `no_api_key` and spends
nothing. This matters: the IntelX free tier is only ~50 search credits
per cycle (1/scan), so smoke tests MUST stay credit-free. Network
failures on individual checkers are tolerated; only **scan-startup-class**
errors (Unbound / Name / Import / Attribute) cause the smoke to fail.

CAUTION — manual production verification: a scan against the live
`/api/scan` endpoint DOES use the real keys and WILL burn credits. When
verifying prod manually, pass `skip_intelx:true` (and `skip_dehashed:true`)
in the POST body to avoid draining the limited IntelX/DeHashed credits.

Wall-clock budget: 90-180s depending on network. Run alongside the
math-only verifier as the second step of the pre-deploy gate.

Exit code:
  0 — scan completed (any HTTP / DNS / timeout failures inside
      individual checkers are normal and don't fail the smoke)
  1 — scan-startup-class exception (Unbound / Name / Import /
      Attribute) — DO NOT DEPLOY
  2 — scan failed for some other reason (timeout, fixture error,
      etc.) — investigate before deploying

Usage:
  python tooling/verify_scan_smoke.py
  python tooling/verify_scan_smoke.py --domain example.com
  python tooling/verify_scan_smoke.py --timeout 240
"""

import argparse
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))


# Error classes that indicate a scan-startup / orchestration bug.
# These are the SHIP-STOPPERS. Network / HTTP / DNS / timeout failures
# inside individual checkers are normal and do NOT trigger a fail.
STARTUP_BUG_CLASSES = (
    UnboundLocalError,
    NameError,
    ImportError,
    AttributeError,
    SyntaxError,
    TypeError,        # caught early signature bugs like missing required args
)


def run(domain: str = "example.com",
        timeout: int = 180,
        industry: str = "other",
        annual_revenue_zar: int = 10_000_000) -> int:
    # Stub out env vars the scanner expects so it doesn't crash on
    # missing config — paid-API checkers are skipped anyway.
    for var in ("HIBP_API_KEY", "DEHASHED_EMAIL", "DEHASHED_API_KEY",
                "VIRUSTOTAL_API_KEY", "SECURITYTRAILS_API_KEY",
                "SHODAN_API_KEY", "INTELX_API_KEY"):
        os.environ.setdefault(var, "")

    print(f"=== verify_scan_smoke against {domain} ===")
    print(f"    timeout={timeout}s industry={industry!r} "
           f"revenue=R{annual_revenue_zar:,}")
    print()

    try:
        from scanner import SecurityScanner
    except STARTUP_BUG_CLASSES as e:
        print(f"FAIL — import-time {type(e).__name__}: {e}")
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"ERROR — non-startup import-time {type(e).__name__}: {e}")
        traceback.print_exc()
        return 2

    # Constructed with NO API keys on purpose → every paid checker (IntelX,
    # DeHashed, etc.) returns no_api_key and spends ZERO credits. Do NOT pass
    # real keys here; the IntelX free tier is only ~50 credits/cycle.
    s = SecurityScanner()

    last_progress_ts = [time.perf_counter()]
    completed_checkers = []
    running_checkers = []

    def on_progress(event):
        last_progress_ts[0] = time.perf_counter()
        c = event.get("checker", "?")
        st = event.get("status", "?")
        if st == "running":
            running_checkers.append(c)
        elif st == "done":
            completed_checkers.append(c)

    t0 = time.perf_counter()
    try:
        result = s.scan(
            domain,
            on_progress=on_progress,
            industry=industry,
            annual_revenue=0,
            annual_revenue_zar=annual_revenue_zar,
            country="ZA",
            include_fraudulent_domains=False,
            client_ips=None,
            related_domains=None,
        )
    except STARTUP_BUG_CLASSES as e:
        elapsed = time.perf_counter() - t0
        print(f"FAIL after {elapsed:.1f}s — {type(e).__name__}: {e}")
        print()
        print("This is a scan-startup-class bug. DO NOT DEPLOY.")
        print("Traceback:")
        traceback.print_exc()
        print()
        print(f"Checkers that did start before the crash: "
               f"{running_checkers[-5:] if running_checkers else 'none'}")
        return 1
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"ERROR after {elapsed:.1f}s — non-startup "
               f"{type(e).__name__}: {e}")
        print()
        print("Investigate the traceback before deploying:")
        traceback.print_exc()
        return 2

    elapsed = time.perf_counter() - t0
    print()
    print(f"=== PASS — scan completed in {elapsed:.1f}s ===")
    print(f"    overall_risk_score: {result.get('overall_risk_score', '?')}")
    print(f"    risk_level: {result.get('risk_level', '?')}")
    print(f"    categories built: {len(result.get('categories', {}))}")
    print(f"    checkers reporting done: {len(completed_checkers)}")
    # Quick sanity — Phase 4f always builds a category even when no HR
    # data; absence here suggests scan() returned early via a different
    # path (catastrophic but not startup-class).
    if "third_party_correlation" not in result.get("categories", {}):
        print("    WARN — third_party_correlation missing from categories. "
               "Phase 4f may have been skipped.")
    if "_overall_score" not in result.get("categories", {}):
        print("    WARN — _overall_score not propagated to categories.")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--domain", default="example.com",
                    help="Test domain. Default example.com (canonical IANA "
                         "test domain). Override for SA-specific smoke.")
    p.add_argument("--timeout", type=int, default=180,
                    help="Wall-clock budget in seconds.")
    p.add_argument("--industry", default="other")
    p.add_argument("--revenue-zar", type=int, default=10_000_000)
    args = p.parse_args()
    sys.exit(run(
        domain=args.domain, timeout=args.timeout,
        industry=args.industry, annual_revenue_zar=args.revenue_zar,
    ))
