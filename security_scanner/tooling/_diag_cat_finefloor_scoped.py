# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX diagnostic (read-only): verify the POPIA/ECTA-scoped fine floor.

Fires the SECTOR cat stack by passing regulatory_flags={'accountable_institution':True}
and an FS sub_industry (FSCA R100M + FIC R50M => R150M raw sector). Earlier sweeps this
session passed NO regulatory_flags, so the sector stack never fired and every FS curve
was POPIA-only - the defect this run fixes.

Proves DETERMINISTICALLY (from catastrophe_stack, no MC noise):
  - sector_cat_total = R150M x UN-FLOORED capacity_factor (NOT x 0.80)
  - popia/ecta = ceiling x FLOORED fine_capacity_factor (0.80 at the small end)
  - the OLD buggy sector total (R150M x fine_capacity_factor) for contrast
Plus the 1-in-250 cat as % of revenue (should drop sharply for a small FSP vs the
buggy ~679%), and large-cap (R424M+) unchanged. NOT shipped."""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__)); SEC = os.path.dirname(HERE)
sys.path.insert(0, SEC)
import scoring_analytics as S
from scoring_analytics import RiskScorer, RansomwareIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier

print(f"  levers: TAPER_MIN={S.CAT_RESIDUAL_TAPER_MIN}  HI=R{S.CAT_RESIDUAL_TAPER_HI_ZAR:,.0f}  FINE_FLOOR={S.FINE_CAPACITY_FLOOR}")

d = json.load(open(os.path.join(SEC, "test_fixtures", "takealot_baseline.json"), encoding="utf-8"))
cats = dict(d.get("categories", d))
try:
    cats["credential_risk"] = CredentialRiskClassifier.classify(
        dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {},
        intelx=cats.get("intelx", {}) or {})
except Exception:
    pass

IND = "Financial Services"
SUB = "Insurance Agents, Brokers, And Service"   # FSCA R100M + FIC R50M
FLAGS = {"accountable_institution": True}


def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def M(x):
    x = float(x)
    return f"R{x/1e6:,.1f}M" if abs(x) < 1e9 else f"R{x/1e9:,.2f}bn"


REVS = [5e6, 10e6, 25e6, 50e6, 100e6, 200e6, 424e6, 500e6, 1e9, 3e9]
print("=" * 118)
print(f"INDUSTRY: {IND}  SUB: {SUB}  FLAGS: {FLAGS}   (sector stack = FSCA R100M + FIC R50M = R150M raw)")
print("=" * 118)
hdr = (f"  {'revenue':>9} | {'cap_f':>5} | {'fine_f':>6} | {'sector(NEW=cap)':>15} | "
       f"{'sector OLD(buggy)':>17} | {'POPIA':>7} | {'ECTA':>6} | {'1-in-250 cat':>13} | {'% rev':>7}")
print(hdr)
print("  " + "-" * 114)
for rev in REVS:
    sc, lv, _ = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
    rsi = RansomwareIndex().calculate(cats, industry=IND, annual_revenue=rev)
    fin = FinancialImpactCalculator().calculate(
        cats, rsi, 0, IND, annual_revenue_zar=rev,
        regulatory_flags=FLAGS, sub_industry=SUB)
    cstack = find_key(fin, "catastrophe_stack")
    cap_f = cstack["capacity_factor"]
    fine_f = cstack["fine_capacity_factor"]
    sector_new = cstack["sector_cat_total_zar"]
    sector_raw = sum(b["statutory_max_zar"] for b in cstack["sector_frameworks"])
    sector_old_buggy = int(round(sector_raw * fine_f))   # what the pre-fix code produced
    popia = cstack["popia_statutory_scaled_zar"]
    ecta = cstack["ecta_cat_scaled_zar"]
    cat250 = fin["return_periods"]["1_in_250"]["loss_zar"]
    print(f"  {M(rev):>9} | {cap_f:>5.2f} | {fine_f:>6.2f} | {M(sector_new):>15} | "
          f"{M(sector_old_buggy):>17} | {M(popia):>7} | {M(ecta):>6} | {M(cat250):>13} | {cat250/rev*100:>6.0f}%")
print()
print("  EXPECT: sector(NEW) = R150M x cap_f (scales DOWN); sector OLD(buggy) = R150M x max(cap,0.80)")
print("          (the buggy column floors a R5M FSP's FIC+FSCA to R120M); POPIA floored to ~R8M small-end.")
