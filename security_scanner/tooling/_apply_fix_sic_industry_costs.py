# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): correct the Mining / Construction / Wholesale Trade breach-cost
anchors to the user's CORPORATE RATING ENGINE risk tables (authoritative), replacing
the placeholder nearest-IBM-sibling analogies from the prior commit:
  - Mining        -> Agriculture band   (mult 0.65; was ~Transportation 0.90)
  - Construction  -> Transportation band(mult 0.90; was ~Agriculture 0.65)  [swap]
  - Wholesale Trade -> ~40% LESS risky than Agriculture (0.65 x 0.60 = 0.39; was
    ~Retail 0.80) - wholesale distribution is mostly B2B, not client-facing.
Values map the relative risk position onto the IBM-SA scale (mult x R44.1M baseline,
cost/record = mult x 1881). RSI + BI factors unchanged (already distinct). CRLF-safe.
Run from security_scanner/: py tooling/_apply_fix_sic_industry_costs.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

OLD = (
    '    # SIC divisions added 2026-06-09 (were missing -> fell back to "Other").\n'
    '    # Breach-cost anchored BY ANALOGY to the nearest IBM-SA sibling (PROVISIONAL,\n'
    '    # pending a per-sector IBM/DBIR calibration pass); RSI + BI already distinct.\n'
    '    "Mining":                     {"breach_cost_zar": 39_690_000, "cost_per_record": 1693, "multiplier": 0.90},  # ~Transportation\n'
    '    "Construction":               {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},  # ~Agriculture\n'
    '    "Wholesale Trade":            {"breach_cost_zar": 35_280_000, "cost_per_record": 1505, "multiplier": 0.80},  # ~Retail\n'
)
NEW = (
    '    # SIC divisions added 2026-06-09 (were missing -> fell back to "Other").\n'
    '    # Relative risk positioning from the corporate rating engine risk tables\n'
    '    # (authoritative), mapped onto the IBM-SA breach-cost scale (mult x R44.1M;\n'
    '    # cost/record = mult x 1881). RSI + BI factors already distinct, unchanged.\n'
    '    "Mining":                     {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},  # Agriculture band (corp rating engine)\n'
    '    "Construction":               {"breach_cost_zar": 39_690_000, "cost_per_record": 1693, "multiplier": 0.90},  # Transportation band (corp rating engine)\n'
    '    "Wholesale Trade":            {"breach_cost_zar": 17_200_000, "cost_per_record":  734, "multiplier": 0.39},  # ~40% less risky than Agriculture (B2B distribution, not client-facing)\n'
)
assert s.count(OLD) == 1, ("SIC cost block", s.count(OLD))
s = s.replace(OLD, NEW, 1)

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())

# Self-verify the new values + internal consistency (cost/record = mult x 1881).
import sys
sys.path.insert(0, ROOT)
from scoring_analytics import SA_INDUSTRY_COSTS as C
exp = {"Mining": 0.65, "Construction": 0.90, "Wholesale Trade": 0.39}
for k, mult in exp.items():
    row = C[k]
    assert row["multiplier"] == mult, (k, row["multiplier"], mult)
    assert abs(row["breach_cost_zar"] - round(mult * 44_100_000, -4)) <= 10_000, (k, "breach", row)
    assert row["cost_per_record"] == round(mult * 1881), (k, "cpr", row["cost_per_record"], round(mult*1881))
print("OK scoring_analytics.py: Mining=0.65 Construction=0.90 Wholesale=0.39 "
      "(corporate rating engine anchors); internal consistency verified.")
