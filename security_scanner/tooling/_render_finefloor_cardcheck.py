# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX render check (Card-Verification Step 3) for the POPIA/ECTA-scoped fine
floor. Builds the scenario most affected by the fix - a SMALL R5M FS broker flagged
as an accountable institution (sector stack fires) - plus the R200M worked-example
entity, scores them, and renders all PDF tiers + HTML. Confirms the tiers generate
without error and the catastrophe (1-in-250) numbers render sane/readable. Extracts
the catastrophe text from each tier so the numbers can be eyeballed. NOT shipped."""
import sys, json, tempfile, os, re
from pathlib import Path
ROOT = Path(".").resolve(); sys.path.insert(0, str(ROOT))
from scoring_analytics import (RiskScorer, RansomwareIndex, DataBreachIndex,
                               FinancialImpactCalculator)
from checkers_threats import CredentialRiskClassifier
from pdf_report import generate_pdf
from jinja2 import Environment, FileSystemLoader
import fitz

d = json.load(open(ROOT / "test_fixtures" / "takealot_baseline.json", encoding="utf-8"))
base_cats = dict(d.get("categories", d))
OUT = Path(tempfile.gettempdir()) / "finefloor_cardcheck"; OUT.mkdir(exist_ok=True)

SCENARIOS = [
    ("smallFSP_R5M",  5_000_000,   "Insurance Agents, Brokers, And Service",
     {"accountable_institution": True}),
    ("broker_R200M",  200_000_000, "Insurance Agents, Brokers, And Service",
     {"listed_company": True, "b2c": True, "accountable_institution": True}),
]


def money(s):
    return [f"R{int(x):,}" for x in re.findall(r"R\s*([\d,]+)", s)][:0]  # placeholder, unused


for tag, rev, sub, flags in SCENARIOS:
    cats = dict(base_cats)
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
    sc, lv, rc = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry="Financial Services", annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(
        cats, rsi, 0, "Financial Services", annual_revenue_zar=rev,
        regulatory_flags=flags, sub_industry=sub)
    res = {"categories": cats, "overall_risk_score": sc, "risk_level": lv,
           "recommendations": rc, "domain_scanned": f"{tag}.example.co.za",
           "insurance": {"rsi": rsi, "financial_impact": fin,
                         "dbi": DataBreachIndex().calculate(cats)}}
    rp = fin["return_periods"]
    print("=" * 78)
    print(f"{tag}: rev=R{rev/1e6:.0f}M  score={sc} ({lv})")
    print(f"   1-in-100={rp['1_in_100']['loss_zar']:>14,}  "
          f"1-in-250={rp['1_in_250']['loss_zar']:>14,}  "
          f"most_likely={fin['estimated_annual_loss']['most_likely']:>12,}")
    for rt in ("assessment", "full", "summary"):
        try:
            pdf = generate_pdf(res, report_type=rt)
            p = OUT / f"{tag}_{rt}.pdf"; p.write_bytes(pdf)
            doc = fitz.open(p); npages = doc.page_count
            txt = "\n".join(pg.get_text() for pg in doc); doc.close()
            # sanity: no NaN / inf / negative-money / empty
            bad = [w for w in ("nan", "inf", "None", "-R") if w.lower() in txt.lower()]
            cat_hits = txt.count("1-in-250") + txt.lower().count("catastroph")
            print(f"   [{rt:10s}] {len(pdf):>7,}B  {npages:>2} pages  cat-mentions={cat_hits:>2}  "
                  f"{'BAD:'+','.join(bad) if bad else 'clean'}")
        except Exception as e:
            print(f"   [{rt:10s}] RENDER ERROR: {type(e).__name__}: {e}")
    # HTML tier
    try:
        env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
        html = env.get_template("results.html").render(
            results=res, domain=f"{tag}.example.co.za", timestamp="", scan_id="cardcheck",
            risk_score=sc, risk_level=lv)
        (OUT / f"{tag}_results.html").write_text(html, encoding="utf-8")
        print(f"   [html      ] {len(html):>7,}B  rendered")
    except Exception as e:
        print(f"   [html      ] RENDER ERROR: {type(e).__name__}: {e}")
print("=" * 78)
print(f"PDFs/HTML -> {OUT}")
