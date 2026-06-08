# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-08): update the part5 manual lock to match the POPIA/ECTA-scoped
fine floor (0.80). Two edits (CRLF-safe):
  A. C2 narrative (~line 856): floor 0.60 -> 0.80, scoped to POPIA/ECTA only;
     note the sector mega-ceilings keep scaling by the un-floored capacity factor.
  B. Worked example (~line 1321): POPIA R10M x 0.80 = R8M, ECTA R1M x 0.80 = R0.8M,
     sector lines stay at 0.65 (un-floored); total R129.5M -> R131.2M; R10M variant
     R24M -> R33.4M (verified against the live model).
Run from security_scanner/: py tooling/_apply_part5_finefloor80_manual.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P5 = os.path.join(ROOT, "manual_parts", "part5_tech_compliance_insurance.py")
s = open(P5, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"
n = 0

# ── Edit A: C2 narrative — floor 0.80, POPIA/ECTA-only scope. ──
OLD = (
    "        \"R10 million Section 109 statutory ceiling, scaled by the enterprise \"\n"
    "        \"capacity factor - but that factor is floored (at 0.60) for the fixed-\"\n"
    "        \"cap statutory fines, because a serious breach at even a small qualifying \"\n"
    "        \"entity can attract most of the statutory ceiling, so the fine is not \"\n"
    "        \"discounted away by company size. GDPR exposure (4% of \"\n"
)
NEW = (
    "        \"R10 million Section 109 statutory ceiling, scaled by the enterprise \"\n"
    "        \"capacity factor - but that factor is floored (at 0.80) for the \"\n"
    "        \"POPIA and ECTA fixed-cap ceilings only, because a serious breach at \"\n"
    "        \"even a small qualifying entity can attract most of those broadly-\"\n"
    "        \"applicable statutory ceilings, so the fine is not discounted away by \"\n"
    "        \"company size. The high discretionary sector ceilings (such as FSCA \"\n"
    "        \"R100M and FIC R50M) keep scaling by the un-floored capacity factor, \"\n"
    "        \"so a small qualifying entity is not modelled as facing most of a \"\n"
    "        \"R100M sector ceiling. GDPR exposure (4% of \"\n"
)
assert s.count(OLD) == 1, ("C2 narrative", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── Edit B: worked example — POPIA/ECTA floored to 0.80, sector at 0.65. ──
OLD = (
    "        \"Worked example - R200M listed FS broker (B2C, accountable \"\n"
    "        \"institution), capacity factor 0.65: POPIA R10M x 0.65 = R6.5M; \"\n"
    "        \"ECTA R1M x 0.65 = R0.65M; CPA 10% x R200M = R20M (no factor - \"\n"
    "        \"percentage already scales); FSCA R100M x 0.65 = R65M; FIC R50M \"\n"
    "        \"x 0.65 = R32.5M; JSE R7.5M x 0.65 = R4.875M. Total cat stack: \"\n"
    "        \"approximately R129.5M. The same entity at R10M revenue \"\n"
    "        \"(capacity factor 0.15) would face approximately R24M total.\"\n"
)
NEW = (
    "        \"Worked example - R200M listed FS broker (B2C, accountable \"\n"
    "        \"institution), capacity factor 0.65: POPIA R10M x 0.80 (floored) = \"\n"
    "        \"R8M; ECTA R1M x 0.80 (floored) = R0.8M; CPA 10% x R200M = R20M (no \"\n"
    "        \"factor - percentage already scales); FSCA R100M x 0.65 = R65M; FIC \"\n"
    "        \"R50M x 0.65 = R32.5M; JSE R7.5M x 0.65 = R4.875M. Total cat stack: \"\n"
    "        \"approximately R131.2M. The same entity at R10M revenue (capacity \"\n"
    "        \"factor 0.15, with POPIA/ECTA still floored to 0.80 but the sector \"\n"
    "        \"lines scaling at 0.15) would face approximately R33.4M total.\"\n"
)
assert s.count(OLD) == 1, ("worked example", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(P5, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P5, encoding="utf-8").read())
print(f"OK part5_tech_compliance_insurance.py: {n} edits (floor 0.80 POPIA/ECTA-only + worked example).")
