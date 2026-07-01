"""SCALE-00c golden-output regression harness — scoring / financial layer.

Deterministic and OFFLINE: replays the scoring + financial-impact pipeline
against frozen scan fixtures and asserts the output is stable — byte-for-byte
modulo volatile timestamp/duration fields — against a captured baseline.
`regen_outputs_from_cache._rescore` drives the replay, and as of 2026-07-01 it
invokes the SAME `scoring_pipeline.apply_risk_score` / `apply_insurance_analytics`
the live `scanner.scan()` runs (Phase 5 + Phase 6), so this gate now exercises
the EXACT scoring invocation production uses — no second, drifting copy.
(Before that, `_rescore` hand-rolled the calculator sequence with different
arguments, which is how the RSI-revenue bug scored green here while broken live;
`verify_scoring_pipeline_unified.py` now blocks re-divergence.)

WHAT THIS GATES: refactors to the scoring / financial-impact layer
(`scoring_analytics.py`, `scoring_pipeline.py`, and anything feeding
`insurance.*`). A change that shifts a score, an RSI, a Monte-Carlo percentile,
or the result *shape* fails the check.

WHAT THIS DOES NOT YET GATE: the network checkers and the `scanner.scan()`
orchestration around the scoring call (the frozen fixtures ARE the checker
output — the checkers never re-run here). Replaying those deterministically
needs a record/replay cache, entangled with WS0's single egress seam (you cannot
intercept all traffic until it flows through one client). Until then, scan-
orchestration invariants are held by dedicated guards (e.g.
`verify_scan_timeout_handling.py`) + the live smoke test, not by this replay.
The comparator (`result_diff.py`) is already general enough for the checker gate.

Usage (run from the `security_scanner/` directory):
    py tooling/regression/golden.py --capture            # freeze/refresh baselines
    py tooling/regression/golden.py --check              # CI gate: assert no drift
    py tooling/regression/golden.py --check --fixture phishield
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
TOOLING = HERE.parent
ROOT = TOOLING.parent              # security_scanner/
for _p in (str(HERE), str(TOOLING), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import result_diff as rd                              # noqa: E402  (local package)
from regen_outputs_from_cache import _rescore         # noqa: E402  (offline, no network)

BASELINE_DIR = HERE / "baselines"

# Each fixture is a frozen real scan blob + the scan-context overrides the
# scoring layer needs. Mirrors the canonical invocations in
# regen_outputs_from_cache.py's docstring.
FIXTURES = [
    {
        "name": "phishield_finance_r10m",
        "fixture": "test_fixtures/phishield_R10M_finance_2026-05-15.json",
        "revenue_zar": 10_000_000,
        "industry": "finance",
    },
    {
        "name": "takealot_retail_r135b",
        "fixture": "test_fixtures/takealot_baseline.json",
        "revenue_zar": 13_500_000_000,
        "industry": "retail",
    },
]


def _scoring_view(result: dict) -> dict:
    """The slice of a rescored result that the scoring/financial layer owns."""
    return {
        "overall_risk_score": result.get("overall_risk_score"),
        "risk_level": result.get("risk_level"),
        "recommendations": result.get("recommendations"),
        "insurance": result.get("insurance"),
        "categories_overall_score": (result.get("categories") or {}).get("_overall_score"),
    }


def _compute(fx: dict):
    """Load fixture -> rescore through CURRENT code -> volatile-stripped view (dict)."""
    fixture_path = ROOT / fx["fixture"]
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    rescored = _rescore(copy.deepcopy(data),
                        revenue_zar=fx["revenue_zar"], revenue_usd=0,
                        industry=fx["industry"])
    return rd.strip_volatile(_scoring_view(rescored))


def _selected(name_filter: str | None) -> list:
    if not name_filter:
        return FIXTURES
    sel = [f for f in FIXTURES if name_filter.lower() in f["name"].lower()]
    if not sel:
        print(f"No fixture matches {name_filter!r}. Known: "
              f"{', '.join(f['name'] for f in FIXTURES)}", file=sys.stderr)
        sys.exit(2)
    return sel


def capture(name_filter: str | None) -> int:
    BASELINE_DIR.mkdir(exist_ok=True)
    for fx in _selected(name_filter):
        view = _compute(fx)
        out = BASELINE_DIR / f"{fx['name']}.json"
        out.write_text(json.dumps(view, indent=2, sort_keys=True, default=str),
                       encoding="utf-8")
        score = view.get("overall_risk_score")
        print(f"[capture] {fx['name']:24s} -> {out.relative_to(ROOT)} "
              f"(score={score}, {out.stat().st_size // 1024} KB)")
    print("\nBaselines frozen. Commit them so CI can diff against them.")
    return 0


def check(name_filter: str | None) -> int:
    failures = 0
    for fx in _selected(name_filter):
        baseline_path = BASELINE_DIR / f"{fx['name']}.json"
        if not baseline_path.exists():
            print(f"[FAIL] {fx['name']}: no baseline at "
                  f"{baseline_path.relative_to(ROOT)} — run --capture first")
            failures += 1
            continue

        # Determinism self-check: the offline pipeline must be reproducible, or
        # the whole harness is meaningless. Catch nondeterminism explicitly.
        first, second = _compute(fx), _compute(fx)
        self_diffs = rd.diff(first, second)
        if self_diffs:
            print(f"[FAIL] {fx['name']}: NON-DETERMINISTIC — two back-to-back "
                  f"runs differ in {len(self_diffs)} field(s):")
            print(rd.format_report(self_diffs[:20], "  self-check"))
            failures += 1
            continue

        baseline: dict = json.loads(baseline_path.read_text(encoding="utf-8"))
        diffs = rd.diff(baseline, first)
        if diffs:
            print(f"[FAIL] {fx['name']}: {len(diffs)} difference(s) vs baseline")
            print(rd.format_report(diffs[:40], f"  {fx['name']}"))
            if len(diffs) > 40:
                print(f"  … and {len(diffs) - 40} more")
            failures += 1
        else:
            print(f"[PASS] {fx['name']:24s} score={baseline.get('overall_risk_score')} "
                  f"— equivalent, deterministic")

    print()
    if failures:
        print(f"GOLDEN CHECK FAILED — {failures} fixture(s) drifted. "
              f"If the change is intentional, re-run with --capture.")
        return 1
    print("GOLDEN CHECK PASSED — scoring/financial output is stable.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--capture", action="store_true",
                   help="Freeze/refresh baselines from current code output.")
    g.add_argument("--check", action="store_true",
                   help="Assert current output matches frozen baselines (exit 1 on drift).")
    ap.add_argument("--fixture", default=None,
                    help="Only operate on fixtures whose name contains this substring.")
    args = ap.parse_args()
    return capture(args.fixture) if args.capture else check(args.fixture)


if __name__ == "__main__":
    sys.exit(main())
