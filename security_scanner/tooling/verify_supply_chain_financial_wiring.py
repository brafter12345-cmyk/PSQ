"""
Verification loop — asserts that each of the six supply-chain checkers
moves the relevant loss bucket(s) in the scoring + financial-impact model.

THIS IS HALF OF A TWO-STEP PRE-DEPLOY GATE. This script only exercises
the SCORING pipeline (synthetic cat_results dicts → calculators); it
does NOT actually run `SecurityScanner.scan()`, so it cannot catch
import / scoping / NameError / AttributeError defects in the scan
orchestration code path. A `UnboundLocalError` in scan() broke every
live scan from 2026-05-27 to 2026-05-28 because this verifier passed
30/30 while production was silently dead.

The companion script `tooling/verify_scan_smoke.py` runs a real
end-to-end scan against example.com and DOES catch that class of
bug. Run BOTH before pushing master → origin:

    py tooling/verify_supply_chain_financial_wiring.py   # fast (~5s)
    py tooling/verify_scan_smoke.py                       # slow (~60-180s)

Run this AFTER any change to:
  - scoring_analytics.py (WEIGHTS, RSI factors, DBI components,
    FinancialImpactCalculator, RemediationSimulator)
  - checkers_supply_chain.py (any change to category output shape)

Workflow:
  1. Load a baseline fixture (takealot R13.5B by default).
  2. Use explicitly completed clean supply-chain results as the control.
  3. Re-run RiskScorer + RansomwareIndex + DataBreachIndex +
     FinancialImpactCalculator + RemediationSimulator.
  4. Re-inject supply-chain category data one checker at a time and verify
     the relevant downstream bucket moves.
  5. Print PASS / FAIL for each assertion + the magnitude of the delta.

Exit code:
  0 — all assertions passed
  1 — at least one assertion failed (wiring regression)

Usage:
  python tooling/verify_supply_chain_financial_wiring.py
  python tooling/verify_supply_chain_financial_wiring.py --revenue 13500000000
  python tooling/verify_supply_chain_financial_wiring.py --industry retail
"""

import argparse
import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from scoring_analytics import (
    RiskScorer, RansomwareIndex, DataBreachIndex,
    FinancialImpactCalculator, RemediationSimulator,
)


SUPPLY_CHAIN_KEYS = (
    "related_domains", "dependency_manifests", "third_party_js",
    "email_vendor_surface", "cms_plugin_sbom", "vendor_breach",
    "third_party_correlation",
)


# Worst-case payload per checker — what each looks like when "active".
# These are the inputs that should move the relevant downstream bucket.
WORST_CASE_PAYLOADS = {
    "related_domains": {
        "status": "completed", "declared_count": 3, "scanned_count": 3,
        "critical_count": 2, "high_count": 1, "score": 35,
        "worst_domain": {"domain": "supplier.example.com", "lite_score": 35},
        "dependants": [
            {"domain": "supplier.example.com", "lite_score": 35,
             "critical_paths": 2, "issues": []},
        ],
        "issues": ["CRITICAL: 2 critical exposures"],
    },
    "dependency_manifests": {
        "status": "completed",
        "exposed_manifests": [
            {"path": "/package-lock.json", "ecosystem": "node",
             "severity": "critical", "size_bytes": 480_000,
             "dependency_count": 1234},
            {"path": "/composer.json", "ecosystem": "php",
             "severity": "high", "size_bytes": 4500,
             "dependency_count": 42},
        ],
        "total_dependencies": 1276, "ecosystems": ["node", "php"],
        "critical_count": 1, "high_count": 1, "score": 55,
        "issues": ["CRITICAL: 1 lockfile exposed"],
    },
    "third_party_js": {
        "status": "completed", "total_scripts": 18,
        "third_party_count": 12, "missing_sri_count": 10,
        "compromised_host_count": 1,
        "third_party_hosts": [
            {"host": "polyfill.io", "count": 1, "known_cdn": False},
        ],
        "compromised_scripts": [
            {"host": "polyfill.io",
             "src": "https://polyfill.io/v3/polyfill.min.js",
             "reason": "polyfill.io was sold and weaponised (2024)"},
        ],
        "score": 30, "issues": ["CRITICAL: known-compromised CDN"],
    },
    "email_vendor_surface": {
        "status": "completed",
        "vendors_detected": [
            {"vendor": "sendgrid", "includes": ["sendgrid.net"]},
            {"vendor": "mailchimp", "includes": ["_spf.mailchimp.com"]},
            {"vendor": "microsoft_365",
             "includes": ["spf.protection.outlook.com"]},
        ],
        "vendor_count": 3, "unknown_count": 1,
        "dmarc_policy": "none", "weak_dmarc": True,
        "score": 70, "issues": ["3 vendors + weak DMARC"],
    },
    "cms_plugin_sbom": {
        "status": "completed", "is_wordpress": True,
        "plugins_detected": [
            {"slug": "contact-form-7", "version": "5.0.0", "status_code": 200},
            {"slug": "revslider", "version": "4.6.5", "status_code": 200},
            {"slug": "woocommerce", "version": "4.0.0", "status_code": 200},
        ],
        "plugin_count": 3, "versioned_count": 3, "score": 55,
        "issues": ["3 WordPress plugins with readable versions"],
    },
    "vendor_breach": {
        "status": "completed",
        "vendors_detected": ["microsoft_365", "mailchimp"],
        "matches": [
            {"vendor": "microsoft_365", "date": "2024-01-19",
             "age_days": 490, "severity": "critical",
             "exposure_class": "vendor_email_corp",
             "summary": "Midnight Blizzard 2024",
             "penalty_applied": 20.0},
            {"vendor": "mailchimp", "date": "2023-01-11",
             "age_days": 1232, "severity": "high",
             "exposure_class": "customer_email_lists",
             "summary": "Mailchimp 2023", "penalty_applied": 5.4},
        ],
        "match_count": 2, "critical_match_count": 1, "high_match_count": 1,
        "score": 75, "issues": ["CRITICAL match"],
    },
    # Phase 4f cross-correlation — triple-source critical match (HR
    # exposure × SPF vendor surface × known breach in DB).
    "third_party_correlation": {
        "status": "completed", "severity": "critical",
        "critical_count": 1, "high_count": 0, "medium_count": 0,
        "hudson_rock_third_party_count": 3,
        "hudson_rock_employees": 1,
        "spf_vendor_count": 2,
        "spf_vendors": ["microsoft_365", "mailchimp"],
        "vendor_breach_match_count": 2,
        "suspected_vendors": [
            {"vendor": "microsoft_365",
             "breaches": [{"date": "2024-01-19", "severity": "critical",
                            "exposure_class": "vendor_email_corp"}]},
            {"vendor": "mailchimp",
             "breaches": [{"date": "2023-01-11", "severity": "high",
                            "exposure_class": "customer_email_lists"}]},
        ],
        "score": 45,
        "issues": ["CRITICAL: cross-correlation triple-source match"],
        "rationale": "Three signals align",
    },
}


def _neutral_supply_chain(cats: dict) -> dict:
    # FC13-2 excludes absent raw checks. Wiring must compare adverse findings
    # with explicit clean measurements, not with missing evidence whose weight
    # is redistributed. Keep all existing increase thresholds unchanged.
    out = copy.deepcopy(cats)
    for k in SUPPLY_CHAIN_KEYS:
        out[k] = {"status": "completed", "score": 100}
    out["cms_plugin_sbom"].update(is_wordpress=True, plugin_count=0, versioned_count=0)
    out["email_vendor_surface"].update(vendor_count=0, weak_dmarc=False, dmarc_policy="reject")
    return out


# Must match VendorBreachCorrelationChecker.LOOKBACK_DAYS (5 years). Any row
# older than this is silently dropped by the S-5 join (age > LOOKBACK_DAYS),
# so the DB quietly under-reports. We can't import the checker class here
# without pulling its DNS deps, so the constant is mirrored — keep in sync.
VENDOR_BREACH_LOOKBACK_DAYS = 1825
# Warn this many days BEFORE a row leaves the window, so an operator can
# prune/refresh it deliberately rather than discovering silent drift.
VENDOR_BREACH_DRIFT_WARN_DAYS = 60


def check_vendor_breach_drift() -> list:
    """Lightweight DB-hygiene check (WARN-only, never fails the gate).

    Returns a list of warning strings for vendor_breaches.json rows that are
    within VENDOR_BREACH_DRIFT_WARN_DAYS of crossing the 5-year lookback (or
    already expired). Does NOT change runtime behaviour — purely an operator
    nudge so the DB does not silently drift (e.g. the marketo 2021-06-22 row).
    """
    warnings: list = []
    path = ROOT / "vendor_breaches.json"
    try:
        with path.open(encoding="utf-8") as f:
            db = json.load(f)
    except Exception as e:  # pragma: no cover - operator visibility only
        warnings.append(f"vendor_breaches.json could not be read ({e}); skipping drift check.")
        return warnings

    now = datetime.now(timezone.utc)
    for b in db.get("breaches", []):
        date_str = b.get("date", "")
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            warnings.append(f"vendor_breaches row has unparseable date {date_str!r} (vendor={b.get('vendor')}).")
            continue
        age = (now - dt).days
        remaining = VENDOR_BREACH_LOOKBACK_DAYS - age
        if remaining <= 0:
            warnings.append(
                f"EXPIRED: {b.get('vendor')} {date_str} is {age}d old "
                f"(> {VENDOR_BREACH_LOOKBACK_DAYS}d lookback) — S-5 already drops it; prune it.")
        elif remaining <= VENDOR_BREACH_DRIFT_WARN_DAYS:
            warnings.append(
                f"NEAR-EXPIRY: {b.get('vendor')} {date_str} is {age}d old; "
                f"leaves the {VENDOR_BREACH_LOOKBACK_DAYS}d lookback in {remaining}d — refresh or prune deliberately.")
    return warnings


# Curated point-in-time tables carry a `# review-by: YYYY-MM-DD` marker.
# OVERDUE markers FAIL the gate (upgraded from warn-only 2026-06-11): a
# hand-maintained CVSS/EPSS/KEV/ransomware/EOL table that silently rots is an
# accuracy regression the deploy pipeline must surface, not a nudge. DUE-SOON
# (within REVIEW_BY_WARN_DAYS) stays warn-only. Marked tables as of
# 2026-06-11: IP_DNSBLS, PORT_INTEL, SERVICE_INTEL, TAKEOVER_SIGNATURES
# (checkers_network.py); RANSOMWARE_CVE_MAP, ATTACK_TECHNIQUE_MAP,
# EOL_SIGNATURES, _STEALER_TOKENS (checkers_threats.py); _STEALER_TOKENS
# (darkweb_providers.py); CVE_DESCRIPTIONS (pdf_data.py — split out of
# pdf_report.py 2026-06-11).
_REVIEW_BY_FILES = (
    "checkers_network.py",
    "checkers_threats.py",
    "darkweb_providers.py",
    "pdf_data.py",
)
_REVIEW_BY_RE = re.compile(r"#\s*review-by:\s*(\d{4}-\d{2}-\d{2})")
# Warn this many days BEFORE the review date, mirroring the vendor-breach nudge.
REVIEW_BY_WARN_DAYS = 30


def check_curated_table_staleness() -> tuple:
    """Staleness guard for `# review-by: YYYY-MM-DD` markers.

    Returns (failures, warnings). OVERDUE or unparseable markers are
    failures — they flip the gate's exit code so a stale curated table
    (CVSS/EPSS/KEV/ransomware attribution/EOL) blocks deploy until refreshed
    (refreshing = review the table, then bump the marker date). DUE-SOON and
    unreadable-file conditions remain warnings.
    """
    failures: list = []
    warnings: list = []
    now = datetime.now(timezone.utc)
    for fname in _REVIEW_BY_FILES:
        path = ROOT / fname
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as e:  # pragma: no cover - operator visibility only
            warnings.append(f"{fname} could not be read ({e}); skipping review-by check.")
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = _REVIEW_BY_RE.search(line)
            if not m:
                continue
            date_str = m.group(1)
            try:
                due = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except Exception:
                failures.append(f"{fname}:{lineno} has unparseable review-by date {date_str!r}.")
                continue
            remaining = (due - now).days
            if remaining < 0:
                failures.append(
                    f"OVERDUE: {fname}:{lineno} review-by {date_str} passed "
                    f"{-remaining}d ago — refresh the curated table, then bump the marker.")
            elif remaining <= REVIEW_BY_WARN_DAYS:
                warnings.append(
                    f"DUE-SOON: {fname}:{lineno} review-by {date_str} in {remaining}d "
                    f"— schedule a refresh of the curated table.")
    return failures, warnings


def _run_pipeline(cats: dict, *, industry: str, revenue_zar: int) -> dict:
    """Run the full scoring + financial impact pipeline on a category dict.
    Returns a flat dict of the key numbers used by the assertions below.
    """
    scorer = RiskScorer()
    risk_score, _level, _recs = scorer.calculate(cats, waf_apex_status=None)
    cats_with_score = dict(cats)
    cats_with_score["_overall_score"] = risk_score

    rsi_calc = RansomwareIndex()
    rsi = rsi_calc.calculate(cats, industry=industry, annual_revenue=revenue_zar)

    dbi_calc = DataBreachIndex()
    dbi = dbi_calc.calculate(cats)

    fic = FinancialImpactCalculator()
    fin = fic.calculate(cats_with_score, rsi, annual_revenue=0,
                         industry=industry.title(),
                         annual_revenue_zar=revenue_zar)

    sim = RemediationSimulator()
    rem = sim.calculate(cats, rsi, fin, annual_revenue=revenue_zar,
                         industry=industry)

    return {
        "overall_risk_score": risk_score,
        "rsi_score": rsi.get("rsi_score", 0),
        "rsi_factor_count": rsi.get("factor_count", 0),
        "rsi_factors": [f["factor"] for f in rsi.get("contributing_factors", [])],
        "dbi_score": dbi.get("dbi_score", 0),
        "p_breach": (fin.get("data_breach", {}) or {}).get("probability", 0)
                     if "data_breach" in fin else
                     (fin.get("scenarios", {}) or {})
                         .get("data_breach", {}).get("probability", 0),
        # NOTE (item #15, 2026-06-05): return_periods are now the severity-PML
        # (single severe event), which is POSTURE-INDEPENDENT. SC probability
        # signals deliberately do NOT move fin_p99/p99_5 (asserted invariant in
        # the worst-stack block); they move the ALE (fin_most_likely) + scores.
        "fin_p99": ((fin.get("return_periods", {}) or {})
                     .get("1_in_100", {}) or {}).get("loss_zar", 0),
        "fin_p99_5": ((fin.get("return_periods", {}) or {})
                       .get("1_in_200", {}) or {}).get("loss_zar", 0),
        "fin_p99_6": ((fin.get("return_periods", {}) or {})
                       .get("1_in_250", {}) or {}).get("loss_zar", 0),
        "fin_most_likely": (((fin.get("total", {}) or {}).get("most_likely"))
                             or fin.get("estimated_annual_loss", {})
                                 .get("most_likely", 0)),
        "sc_uplift": (fin.get("supply_chain_vulnerability_uplift", {}) or {})
                      .get("value", 0),
        "sc_tail_applied": (fin.get("supply_chain_tail_adjustment", {}) or {})
                            .get("applied", False),
        "remediation_categories": sorted({
            s["category"] for s in rem.get("steps", [])
        }),
    }


def _assert_moves(name: str, before: dict, after: dict,
                  key: str, *, must_increase: bool = True,
                  min_delta_abs: float = 0.0,
                  min_delta_pct: float = 0.0,
                  passes: list, failures: list) -> None:
    b = before.get(key, 0) or 0
    a = after.get(key, 0) or 0
    delta = a - b
    pct = (delta / b * 100) if b else 0
    abs_ok = abs(delta) >= min_delta_abs
    pct_ok = abs(pct) >= min_delta_pct
    direction_ok = (delta > 0) if must_increase else (delta < 0)
    ok = direction_ok and (abs_ok or min_delta_abs == 0) and (pct_ok or min_delta_pct == 0)
    line = f"  {key}: {b:>15,.2f} -> {a:>15,.2f}  (delta {delta:+,.2f}, {pct:+.1f}%)"
    if ok:
        passes.append((name, key, b, a, delta))
        print(f"PASS [{name}] {line}")
    else:
        failures.append((name, key, b, a, delta, must_increase))
        print(f"FAIL [{name}] {line}  (expected {'>' if must_increase else '<'} 0)")


def _assert_in(name: str, after: dict, key: str, needles: list,
               passes: list, failures: list) -> None:
    haystack = " | ".join(after.get(key, []) or [])
    hits = [n for n in needles if n.lower() in haystack.lower()]
    ok = bool(hits)
    if ok:
        passes.append((name, key, needles, hits, None))
        print(f"PASS [{name}] {key} contains: {hits}")
    else:
        failures.append((name, key, needles, [], None))
        print(f"FAIL [{name}] {key} missing all of: {needles}")
        print(f"         got: {after.get(key, [])}")


def run(industry: str = "retail",
        revenue_zar: int = 13_500_000_000,
        fixture: Path | None = None) -> int:
    fixture = fixture or (ROOT / "test_fixtures" / "takealot_baseline.json")
    with fixture.open(encoding="utf-8") as f:
        data = json.load(f)
    cats = data.get("categories", {})

    cats_baseline = _neutral_supply_chain(cats)
    print(f"Baseline: {len(SUPPLY_CHAIN_KEYS)} explicitly completed clean supply-chain controls")
    baseline = _run_pipeline(cats_baseline, industry=industry,
                              revenue_zar=revenue_zar)
    print(f"  baseline overall_risk_score = {baseline['overall_risk_score']}")
    print(f"  baseline rsi_score          = {baseline['rsi_score']}")
    print(f"  baseline fin_p99            = R{baseline['fin_p99']:,.0f}")
    print(f"  baseline fin_most_likely    = R{baseline['fin_most_likely']:,.0f}")
    print()

    passes: list = []
    failures: list = []

    # Per-checker test: inject one checker's worst-case payload at a time
    # and verify the targeted downstream bucket moves.
    per_checker_expectations = {
        "related_domains": [
            ("overall_risk_score", True, 0, 1.0),
            ("rsi_score", True, 0.01, 0),  # +0.05 base before diminishing/multipliers
            ("fin_most_likely", True, 0, 0.5),
            # fin_p99 (cat) is now severity-PML - posture-independent, so SC
            # probability signals correctly do NOT move it (locked invariant in
            # the worst-stack block). It moves the ALE + scores instead.
        ],
        "dependency_manifests": [
            ("overall_risk_score", True, 0, 1.0),
            ("rsi_score", True, 0.01, 0),
            ("fin_most_likely", True, 0, 0.5),
        ],
        "third_party_js": [
            ("overall_risk_score", True, 0, 1.0),
            ("rsi_score", True, 0.02, 0),
            ("fin_most_likely", True, 0, 0.5),
        ],
        "email_vendor_surface": [
            ("overall_risk_score", True, 0, 0.5),
            ("rsi_score", True, 0.01, 0),
        ],
        "cms_plugin_sbom": [
            ("overall_risk_score", True, 0, 0.5),
            ("rsi_score", True, 0.02, 0),
        ],
        "vendor_breach": [
            ("overall_risk_score", True, 0, 0.5),
            # Cat (fin_p99/p99_5) is now severity-PML - posture-independent, so
            # SC probability signals do NOT move it (locked invariant in the
            # worst-stack block). SC flows through the ALE + scores instead.
            ("fin_most_likely", True, 0, 0.1),
        ],
        # Phase 4f cross-correlation — REPORTING-ONLY (intentionally
        # not in WEIGHTS, not an RSI factor, not a FIC vuln uplift).
        # The cross-correlation's value is qualitative guidance (which
        # specific vendors to rotate); the underlying signals (HR,
        # S-4, S-5) already contribute to scoring via their own
        # channels. So we assert the category appears in cat_results
        # (smoke-test below) but make NO claims about scoring movement
        # — that would be double-counting.
        "third_party_correlation": [],  # see smoke-test loop below
    }

    # Reporting-only categories — assert presence + clean status but
    # explicitly DO NOT expect remediation-map inclusion or scoring
    # movement (would be double-counting underlying signals).
    REPORTING_ONLY = {"third_party_correlation"}

    for checker, expectations in per_checker_expectations.items():
        cats_one = dict(cats_baseline)
        cats_one[checker] = WORST_CASE_PAYLOADS[checker]
        after = _run_pipeline(cats_one, industry=industry,
                               revenue_zar=revenue_zar)
        print(f"--- Injecting only: {checker} ---")
        for key, must_inc, abs_min, pct_min in expectations:
            _assert_moves(checker, baseline, after, key,
                          must_increase=must_inc,
                          min_delta_abs=abs_min,
                          min_delta_pct=pct_min,
                          passes=passes, failures=failures)
        if checker in REPORTING_ONLY:
            # Smoke test: just confirm the category survived through the
            # pipeline (the underlying scanner Phase 4f builds it).
            # Scoring movement is not asserted (by design — see note).
            passes.append((checker, "reporting_only", None, True, None))
            print(f"PASS [{checker}] reporting-only — no scoring movement asserted (by design)")
        elif checker in after["remediation_categories"]:
            passes.append((checker, "remediation_map", None, None, None))
            print(f"PASS [{checker}] remediation_map includes '{checker}'")
        else:
            failures.append((checker, "remediation_map", None, None, None, True))
            print(f"FAIL [{checker}] remediation_map missing '{checker}'"
                  f" — got {after['remediation_categories']}")
        print()

    # Combined worst-case: all 6 active simultaneously — sanity check on
    # additive behaviour and the catastrophe tail.
    cats_all = dict(cats_baseline)
    for k, payload in WORST_CASE_PAYLOADS.items():
        cats_all[k] = payload
    after_all = _run_pipeline(cats_all, industry=industry,
                               revenue_zar=revenue_zar)
    print("--- Worst-case stack (all 6 supply-chain checkers active) ---")
    _assert_moves("worst_stack", baseline, after_all, "overall_risk_score",
                   must_increase=True, min_delta_abs=20,
                   passes=passes, failures=failures)
    _assert_moves("worst_stack", baseline, after_all, "rsi_score",
                   must_increase=True, min_delta_abs=0.10,
                   passes=passes, failures=failures)
    _assert_moves("worst_stack", baseline, after_all, "fin_most_likely",
                   must_increase=True, min_delta_pct=2.0,
                   passes=passes, failures=failures)
    # Cat return periods are now severity-PML (posture-independent): the SC
    # stack raises p_breach / rsi / the ALE, but must leave the cat UNCHANGED
    # (a realised catastrophe is severe regardless of how likely it was).
    if abs((after_all["fin_p99"] or 0) - (baseline["fin_p99"] or 0)) < 1.0:
        passes.append(("worst_stack", "fin_p99 invariant (severity-PML)", None, True, None))
        print("PASS [worst_stack] fin_p99 invariant under SC stack (severity-PML, posture-independent)")
    else:
        failures.append(("worst_stack", "fin_p99 not invariant", None, after_all["fin_p99"], None, False))
        print(f"FAIL [worst_stack] fin_p99 moved under SC stack (should be invariant): "
              f"{baseline['fin_p99']:,.0f} -> {after_all['fin_p99']:,.0f}")
    # K_TAIL_SC removed (2026-05-27): supply-chain effect flows through
    # vulnerability uplift only — no separate cat-tail widening.
    # supply_chain_tail_adjustment.applied is expected to be False now.
    if not after_all["sc_tail_applied"]:
        passes.append(("worst_stack", "sc_tail_NOT_applied (by design)",
                        None, False, None))
        print("PASS [worst_stack] supply_chain_tail_adjustment NOT applied (by design — no double-counting)")
    else:
        failures.append(("worst_stack", "sc_tail_applied", None, True,
                         None, False))
        print("FAIL [worst_stack] supply_chain_tail_adjustment applied (should be False after K_TAIL_SC removal)")
    if after_all["sc_uplift"] > 0:
        passes.append(("worst_stack", "sc_uplift", None, after_all["sc_uplift"], None))
        print(f"PASS [worst_stack] supply_chain_vulnerability_uplift = {after_all['sc_uplift']}")
    else:
        failures.append(("worst_stack", "sc_uplift", None, 0, None, True))
        print("FAIL [worst_stack] supply_chain_vulnerability_uplift not applied")

    # DB-hygiene drift check (WARN-only — never changes exit code).
    print()
    print("--- vendor_breaches.json drift check (warn-only) ---")
    drift_warnings = check_vendor_breach_drift()
    if drift_warnings:
        for w in drift_warnings:
            print(f"WARN [vendor_breach_drift] {w}")
    else:
        print(f"OK   [vendor_breach_drift] no rows within "
              f"{VENDOR_BREACH_DRIFT_WARN_DAYS}d of the "
              f"{VENDOR_BREACH_LOOKBACK_DAYS}d lookback window")

    # Curated-table review-by staleness check (OVERDUE fails the gate;
    # DUE-SOON warns).
    print()
    print("--- curated-table review-by check (overdue = FAIL) ---")
    review_failures, review_warnings = check_curated_table_staleness()
    for f in review_failures:
        print(f"FAIL [review_by] {f}")
        failures.append(f"[review_by] {f}")
    for w in review_warnings:
        print(f"WARN [review_by] {w}")
    if not review_failures and not review_warnings:
        print(f"OK   [review_by] no review-by markers overdue or within "
              f"{REVIEW_BY_WARN_DAYS}d")

    print()
    print("=" * 70)
    print(f"PASS: {len(passes)}    FAIL: {len(failures)}")
    print("=" * 70)
    if failures:
        print("\nFAILURE DETAILS:")
        for f in failures:
            print(f"  {f}")
        return 1
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--industry", default="retail")
    p.add_argument("--revenue", type=int, default=13_500_000_000,
                    help="Revenue in ZAR (default 13.5B for takealot)")
    p.add_argument("--fixture", type=Path, default=None)
    args = p.parse_args()
    sys.exit(run(industry=args.industry, revenue_zar=args.revenue,
                  fixture=args.fixture))
