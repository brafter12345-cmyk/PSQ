"""Regenerate report outputs from a cached scan JSON, re-running the
scoring + financial-impact pipeline against the CURRENT code.

Loads a cached scan JSON, optionally overrides scan context (revenue,
industry, ZAR vs USD), re-runs RiskScorer + RansomwareIndex +
DataBreachIndex + FinancialImpactCalculator + RemediationSimulator
through the live code path, then renders Broker Summary PDF, Full
Technical PDF, and the offline HTML results page. No network calls.

This is the canonical way to preview broker-facing outputs after any
change to scoring or financial-impact code — pair with
verify_supply_chain_financial_wiring.py to confirm wiring first.

Examples
--------
  # Defaults: most recent phishield_R10M_finance_*.json
  python tooling/regen_outputs_from_cache.py

  # Takealot with the corrected R13.5B revenue
  python tooling/regen_outputs_from_cache.py \\
      --fixture test_fixtures/takealot_baseline.json \\
      --revenue-zar 13500000000 \\
      --industry retail \\
      --tag takealot_r135b
"""
import argparse
import json
import sys
from pathlib import Path

# Script lives at security_scanner/tooling/; runtime modules + data
# (test_fixtures, templates) are at the parent directory.
HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--fixture", type=Path, default=None,
                    help="Path to cached scan JSON. Defaults to most "
                         "recent test_fixtures/phishield_R10M_finance_*.json.")
    p.add_argument("--revenue-zar", type=int, default=0,
                    help="Override annual_revenue_zar (forces ZAR FAIR path).")
    p.add_argument("--revenue-usd", type=float, default=0.0,
                    help="Override annual_revenue (USD path) if no ZAR set.")
    p.add_argument("--industry", default=None,
                    help="Override industry (e.g. retail, financial-services).")
    p.add_argument("--tag", default=None,
                    help="Output filename suffix; defaults to fixture stem.")
    p.add_argument("--no-rescore", action="store_true",
                    help="Skip rescoring (use cached insurance numbers as-is).")
    return p.parse_args()


def _resolve_fixture(arg_path: Path | None) -> Path:
    if arg_path:
        return arg_path if arg_path.is_absolute() else (ROOT / arg_path)
    fixtures = ROOT / "test_fixtures"
    candidates = sorted(fixtures.glob("phishield_R10M_finance_*.json"),
                         reverse=True)
    if not candidates:
        print("No cached phishield_R10M_finance_*.json found and no "
               "--fixture supplied", file=sys.stderr)
        sys.exit(1)
    return candidates[0]


def _rescore(results: dict, *, revenue_zar: int, revenue_usd: float,
             industry: str | None) -> dict:
    """Re-run scoring + financial impact through the live code path.

    Required because cached `insurance.*` numbers are frozen against the
    code at the time of the scan; any wiring change (new RSI factors,
    catastrophe-tail logic, vulnerability uplift) requires re-running.
    """
    from scoring_analytics import (
        RiskScorer, RansomwareIndex, DataBreachIndex,
        FinancialImpactCalculator, RemediationSimulator,
    )
    cats = results.get("categories", {})
    ctx = results.setdefault("scan_context", {})
    if industry:
        ctx["industry"] = industry
    if revenue_zar:
        ctx["annual_revenue_zar"] = revenue_zar
    if revenue_usd:
        ctx["annual_revenue"] = revenue_usd
    industry = ctx.get("industry") or "other"
    rev_zar = int(ctx.get("annual_revenue_zar") or 0)
    rev_usd = float(ctx.get("annual_revenue") or 0)

    scorer = RiskScorer()
    risk_score, risk_level, recs = scorer.calculate(cats, waf_apex_status=None)
    results["overall_risk_score"] = risk_score
    results["risk_level"] = risk_level
    results["recommendations"] = recs
    cats["_overall_score"] = risk_score

    rsi_calc = RansomwareIndex()
    rsi = rsi_calc.calculate(cats, industry=industry,
                              annual_revenue=rev_usd or rev_zar)
    results.setdefault("insurance", {})["rsi"] = rsi

    fic = FinancialImpactCalculator()
    fin = fic.calculate(cats, rsi,
                         annual_revenue=rev_usd,
                         industry=industry.title(),
                         annual_revenue_zar=rev_zar)
    results["insurance"]["financial_impact"] = fin

    dbi_calc = DataBreachIndex()
    results["insurance"]["dbi"] = dbi_calc.calculate(cats)

    sim = RemediationSimulator()
    results["insurance"]["remediation"] = sim.calculate(
        cats, rsi, fin, annual_revenue=rev_zar or rev_usd,
        industry=industry,
    )
    return results


def main() -> int:
    args = _parse_args()
    src = _resolve_fixture(args.fixture)
    tag = args.tag or src.stem
    print(f"Loading cached scan: {src.name} ({src.stat().st_size // 1024} KB)")

    with src.open("r", encoding="utf-8") as f:
        results = json.load(f)

    if not args.no_rescore:
        print("Re-running scoring + financial-impact through current code...")
        results = _rescore(results,
                            revenue_zar=args.revenue_zar,
                            revenue_usd=args.revenue_usd,
                            industry=args.industry)
        rsi = results["insurance"]["rsi"]
        fin = results["insurance"]["financial_impact"]
        print(f"  risk_score = {results['overall_risk_score']} "
               f"({results['risk_level']})")
        print(f"  rsi_score  = {rsi['rsi_score']}  ({rsi['risk_label']})")
        rp = fin.get("return_periods", {})
        eal = fin.get("estimated_annual_loss", {}).get("most_likely")
        if eal:
            print(f"  EAL most_likely = R{eal:,.0f}")
        if rp:
            print(f"  1-in-100 = R{rp['1_in_100']['loss_zar']:,.0f}")
            print(f"  1-in-200 = R{rp['1_in_200']['loss_zar']:,.0f}")
            print(f"  1-in-250 = R{rp['1_in_250']['loss_zar']:,.0f}")
        sc_tail = fin.get("supply_chain_tail_adjustment", {}) or {}
        if sc_tail.get("applied"):
            print(f"  supply-chain tail applied: drivers = "
                   f"{sc_tail.get('drivers')}")
        sc_uplift = fin.get("supply_chain_vulnerability_uplift", {}) or {}
        if sc_uplift.get("value", 0) > 0:
            print(f"  supply-chain vuln uplift = {sc_uplift['value']} "
                   f"({sc_uplift.get('factors')})")

    outdir = ROOT / "test_fixtures" / "regen_outputs"
    outdir.mkdir(exist_ok=True)

    print("\n[1/3] Regenerating full PDF...")
    from pdf_report import generate_pdf
    full_path = outdir / f"{tag}_full.pdf"
    full_path.write_bytes(generate_pdf(results, report_type="full"))
    print(f"  -> {full_path}  ({full_path.stat().st_size // 1024} KB)")

    print("\n[2/3] Regenerating broker summary PDF...")
    summary_path = outdir / f"{tag}_summary.pdf"
    summary_path.write_bytes(generate_pdf(results, report_type="summary"))
    print(f"  -> {summary_path}  ({summary_path.stat().st_size // 1024} KB)")

    print("\n[3/3] Rendering HTML results page...")
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")),
                      autoescape=True)
    template = env.get_template("results.html")
    html_path = outdir / f"{tag}_results.html"
    html_path.write_text(
        template.render(
            results=results, domain=results.get("domain_scanned", ""),
            timestamp=results.get("scan_timestamp", ""),
            scan_id=f"regen-{tag}",
            risk_score=results.get("overall_risk_score", 0),
            risk_level=results.get("risk_level", "Unknown"),
        ),
        encoding="utf-8",
    )
    print(f"  -> {html_path}  ({html_path.stat().st_size // 1024} KB)")

    print(f"\nAll three outputs in: {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
