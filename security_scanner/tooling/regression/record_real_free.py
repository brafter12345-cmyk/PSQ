"""Record REAL free-provider baselines (no API keys, no paid calls) and confirm the
migrated checkers parse live responses deterministically.

Live network. Records each free case through the migrated client (real response),
freezes it, then replays it and asserts determinism — so these baselines are
real-shaped (not synthetic) regression anchors. Lightweight cases only; the
multi-MB catalog feeds (KEV/MSF/ExploitDB/Tranco) are skipped (synthetic-gated +
live-smoke-confirmed). Apex/crt.sh use phishield.com.

    py tooling/regression/record_real_free.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import checker_gate as cg

TARGET = "phishield.com"


def _cases():
    import checkers_threats as ct
    # crt.sh is intentionally excluded: its hand-rolled retry loop + flaky live
    # responses make a real recording nondeterministic (N attempts recorded, 1 on
    # replay). It is synthetic-gated in mig_small_providers and live-confirmed.
    return {
        "real_techstack": lambda: ct.TechStackChecker().check(TARGET),
        "real_osv": lambda: {"v": ct.OSVChecker().query_version("django", "3.2.0", "PyPI")},
        "real_nvd": lambda: ct.ShodanVulnChecker()._fetch_cvss("CVE-2021-44228"),
        "real_epss": lambda: ct.ShodanVulnChecker()._fetch_epss(["CVE-2021-44228"]),
        "real_hudsonrock": lambda: ct.HudsonRockChecker().check(TARGET),
    }


def main() -> int:
    """Record-once then replay-after: a live recording is captured the first time a
    baseline is missing; every later run is a pure offline replay gate."""
    record = "--record" in sys.argv
    failures = 0
    for name, fn in _cases().items():
        cas = cg.DEFAULT_BASELINE_DIR / f"{name}.cassette.json"
        if record or not cas.exists():
            try:
                s = cg.record_baseline(name, fn)      # LIVE
                print(f"[rec ] {name:18s} {s['requests']} real request(s) frozen")
            except Exception as e:  # noqa: BLE001
                print(f"[SKIP] {name:18s} live call failed: {type(e).__name__}: {e}")
                continue
        r = cg.verify(name, fn)                        # offline replay
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("REAL FREE-PROVIDER GATE PASSED (real-shaped baselines)" if not failures
          else f"{failures} case(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
