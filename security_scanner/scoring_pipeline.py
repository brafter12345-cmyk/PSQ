# -*- coding: utf-8 -*-
"""Single source of truth for the scan's scoring + insurance-analytics
invocation.

BOTH the live scanner (`scanner.SecurityScanner.scan`, Phase 5 + Phase 6) and
the offline golden / regen rescore (`tooling/regen_outputs_from_cache._rescore`)
call these two functions. Because they share ONE invocation, the golden
regression exercises the EXACT calculator call sequence production runs — there
is no second, drifting copy for a scoring change to slip through.

Why this module exists (2026-07-01)
-----------------------------------
The live scanner and the golden rescore each had their OWN hand-written copy of
this sequence, called with DIFFERENT arguments:
  - revenue basis: live resolved ZAR via `resolve_effective_revenue_zar`; the
    rescore fed RSI the raw `annual_revenue OR annual_revenue_zar`;
  - WAF status, regulatory_flags, sub_industry, records_override,
    scan_completeness: the live path passed them, the rescore dropped them.
That drift is exactly how the RSI-revenue size-multiplier bug shipped to
production while the golden gate stayed green (the golden rescore fed RSI the
ZAR value; the live scanner fed it the vestigial USD `annual_revenue`, pinning
every form scan to the <R10M "micro" multiplier). Collapsing to one invocation
means a scoring change can no longer pass golden while breaking the live scan.
`tooling/verify_scoring_pipeline_unified.py` blocks re-divergence.

Contract: PURE + OFFLINE. No network, no scanner instance, no module globals.
Every input is an explicit argument the caller sources itself. In particular
`apply_risk_score` takes the WAF apex status as an argument (the live scanner
reads it from the network before scoring; the offline rescore passes the frozen
value from the fixture, or None) so this module never touches the network.
"""
from __future__ import annotations

from scoring_analytics import (
    RiskScorer, RansomwareIndex, DataBreachIndex,
    FinancialImpactCalculator, RemediationSimulator,
)
from peer_benchmarking import resolve_effective_revenue_zar


def apply_risk_score(results: dict, *, waf_apex_status: dict | None = None):
    """Phase 5 — run RiskScorer over ``results["categories"]`` and write the
    overall score / level / recommendations.

    Also writes ``categories["_overall_score"]``: FinancialImpactCalculator.
    _calculate_zar reads it to derive ``vulnerability``; without it the FIC
    defaults to 500 and pins vulnerability at 0.5, decoupling p_breach / the
    Monte-Carlo tails from the actual scan posture.

    Returns ``(risk_score, risk_level, recommendations, scorer)`` so the live
    caller can reuse the same scorer instance for its completeness telemetry
    and compliance summary.
    """
    cat_results = results.setdefault("categories", {})
    scorer = RiskScorer()
    risk_score, risk_level, recommendations = scorer.calculate(
        cat_results, waf_apex_status=waf_apex_status)
    results["overall_risk_score"] = risk_score
    results["risk_level"] = risk_level
    results["recommendations"] = recommendations
    cat_results["_overall_score"] = risk_score
    return risk_score, risk_level, recommendations, scorer


def apply_insurance_analytics(results: dict, *, industry: str,
                              annual_revenue: float, annual_revenue_zar: int,
                              regulatory_flags: dict | None = None,
                              sub_industry: str | None = None,
                              records_override: int | None = None,
                              scan_completeness: dict | None = None) -> dict:
    """Phase 6 — run RSI -> FinancialImpact -> DBI -> Remediation over
    ``results["categories"]`` and write them into ``results["insurance"]``.
    Returns the insurance dict.

    RSI and the RemediationSimulator are scored on the RESOLVED ZAR revenue
    (``_zar``) because the size-multiplier bands are in ZAR and the scan form
    sends revenue only as ``annual_revenue_zar``. The vestigial USD
    ``annual_revenue`` is forwarded to FinancialImpactCalculator only, which
    ignores it whenever ``annual_revenue_zar`` is present (production always
    is). ``apply_risk_score`` MUST have run first — the FIC reads
    ``categories["_overall_score"]``.

    Exceptions propagate: the live scanner wraps this call in try/except to
    record ``insurance["error"]``; the golden rescore lets a failure fail the
    gate. Do NOT swallow errors here.
    """
    cat_results = results.setdefault("categories", {})
    insurance = results.setdefault("insurance", {})

    _zar = resolve_effective_revenue_zar(annual_revenue_zar)

    rsi_calc = RansomwareIndex()
    rsi_result = rsi_calc.calculate(cat_results, industry, _zar)
    insurance["rsi"] = rsi_result

    fin_calc = FinancialImpactCalculator()
    fin_result = fin_calc.calculate(
        cat_results, rsi_result, annual_revenue, industry,
        annual_revenue_zar=_zar,
        regulatory_flags=regulatory_flags,
        sub_industry=sub_industry,
        scan_completeness=scan_completeness,
        records_override=records_override,
    )
    insurance["financial_impact"] = fin_result

    dbi_calc = DataBreachIndex()
    insurance["dbi"] = dbi_calc.calculate(cat_results)

    sim = RemediationSimulator()
    insurance["remediation"] = sim.calculate(
        cat_results, rsi_result, fin_result, _zar, industry)

    return insurance
