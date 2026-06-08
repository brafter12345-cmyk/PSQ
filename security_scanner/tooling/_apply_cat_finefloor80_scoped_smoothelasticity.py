# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-08): finish the cat-model fine-floor tweaks held last session.
Four scoped edits to scoring_analytics.py (CRLF-safe):

  1. Scope the fine floor to POPIA(+ECTA) only. The sector cat stack (FSCA R100M /
     FIC R50M / JSE etc.) now uses the UN-FLOORED capacity_factor, because those
     discretionary mega-ceilings must keep scaling DOWN with company size (a R5M
     FSP cannot plausibly attract R40M of FIC). Previously the floor was applied
     to the WHOLE sector stack, ballooning a small FSP's cat to ~679% of revenue.
  2. Raise FINE_CAPACITY_FLOOR 0.60 -> 0.80 (now correctly scoped: POPIA R10M x
     0.80 = R8M for a small qualifying entity = "80% of the statutory fine").
  3. Replace the stepped revenue-elasticity bands with a continuous (kink-free)
     curve tracking the old band centres (removes small non-monotonic %-of-rev blips).
  4. Refresh the two governing comments (module-top lever doc + inline Lever-2 note)
     to record the POPIA/ECTA-only scope.

Run from security_scanner/: py tooling/_apply_cat_finefloor80_scoped_smoothelasticity.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SA = os.path.join(ROOT, "scoring_analytics.py")
s = open(SA, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"
n = 0

# ── Edit 1: fine floor 0.60 -> 0.80, and add the continuous elasticity helper. ──
OLD = "FINE_CAPACITY_FLOOR       = _cat_env_float(\"FINE_CAPACITY_FLOOR\", 0.60, 0.0, 1.0)\n"
NEW = (
    "FINE_CAPACITY_FLOOR       = _cat_env_float(\"FINE_CAPACITY_FLOOR\", 0.80, 0.0, 1.0)\n"
    "\n"
    "\n"
    "def _revenue_elasticity(rev):\n"
    "    \"\"\"Continuous (kink-free) revenue-scaling exponent. Linear in log10(revenue)\n"
    "    through the former stepped bands' transition midpoints - tracks the old\n"
    "    calibration at band centres but removes the step discontinuities, which had\n"
    "    produced small non-monotonic kinks in the cat-as-%-of-revenue curve. Flat\n"
    "    0.60 below R10M, flat 0.35 at/above R2bn.\"\"\"\n"
    "    import math\n"
    "    pts = [(7.0, 0.60), (7.398, 0.55), (7.699, 0.50), (8.0, 0.46),\n"
    "           (8.301, 0.42), (8.699, 0.39), (9.0, 0.365), (9.301, 0.35)]\n"
    "    L = math.log10(max(float(rev), 1.0))\n"
    "    if L <= pts[0][0]:\n"
    "        return pts[0][1]\n"
    "    if L >= pts[-1][0]:\n"
    "        return pts[-1][1]\n"
    "    for (l0, e0), (l1, e1) in zip(pts, pts[1:]):\n"
    "        if l0 <= L <= l1:\n"
    "            return e0 + (e1 - e0) * (L - l0) / (l1 - l0)\n"
    "    return pts[-1][1]\n"
)
assert s.count(OLD) == 1, ("fine floor const", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── Edit 2: module-top lever doc — record POPIA/ECTA-only scope. ──
OLD = (
    "# taper, large-cap). Lever 2: FINE_CAPACITY_FLOOR floors the capacity factor used\n"
    "# for fixed-cap statutory fines (POPIA/ECTA/sector). Env-overridable so the cat\n"
)
NEW = (
    "# taper, large-cap). Lever 2: FINE_CAPACITY_FLOOR floors the capacity factor used\n"
    "# for the broadly-applicable fixed-cap fines (POPIA s109 + ECTA) ONLY; the\n"
    "# discretionary sector mega-ceilings (FSCA/FIC/JSE/etc.) keep scaling by the\n"
    "# un-floored capacity factor, because those sanctions are size-proportionate.\n"
    "# Env-overridable so the cat\n"
)
assert s.count(OLD) == 1, ("module lever doc", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── Edit 3: replace the stepped elasticity bands with the continuous helper. ──
OLD = (
    "        if annual_revenue_zar >= 1_000_000_000:\n"
    "            elasticity = 0.35\n"
    "        elif annual_revenue_zar >= 500_000_000:\n"
    "            elasticity = 0.38\n"
    "        elif annual_revenue_zar >= 200_000_000:\n"
    "            elasticity = 0.40\n"
    "        elif annual_revenue_zar >= 100_000_000:\n"
    "            elasticity = 0.44\n"
    "        elif annual_revenue_zar >= 50_000_000:\n"
    "            elasticity = 0.48\n"
    "        elif annual_revenue_zar >= 25_000_000:\n"
    "            elasticity = 0.52\n"
    "        elif annual_revenue_zar >= 10_000_000:\n"
    "            elasticity = 0.58\n"
    "        else:\n"
    "            elasticity = 0.60\n"
)
NEW = (
    "        # Continuous (kink-free) revenue elasticity - replaces the former stepped\n"
    "        # bands whose discontinuities produced small non-monotonic kinks in the\n"
    "        # cat-as-%-of-revenue curve (smoothed 2026-06-08; tracks old band centres).\n"
    "        elasticity = _revenue_elasticity(annual_revenue_zar)\n"
)
assert s.count(OLD) == 1, ("elasticity bands", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# ── Edit 4: scope fix — sector cat stack uses the UN-FLOORED capacity_factor. ──
# Rewrites the inline Lever-2 comment + the sector_cat_scaled / per-framework
# breakdown so they multiply by capacity_factor (not fine_capacity_factor).
# POPIA (line ~2349) and ECTA (~2353) downstream KEEP fine_capacity_factor.
OLD = (
    "        # Lever 2 (cat refinement, 2026-06-08): a statutory FIXED-CAP fine\n"
    "        # (POPIA s109 R10M, ECTA, sector ceilings) does not scale down with\n"
    "        # company size the way discretionary enforcement does - a serious\n"
    "        # breach at a micro FSP can attract most of the statutory ceiling in a\n"
    "        # 1-in-X catastrophe. Floor the capacity factor used for the fixed-cap\n"
    "        # fines so small QUALIFYING entities carry genuine fine exposure. The\n"
    "        # %-of-turnover frameworks (GDPR / CPA / PCI) are untouched - they\n"
    "        # already scale with revenue. Only the fines that QUALIFY fire (POPIA\n"
    "        # baseline; GDPR / PCI / sector by reg_flags), so this lifts real\n"
    "        # exposure, not phantom fines.\n"
    "        fine_capacity_factor = max(capacity_factor, FINE_CAPACITY_FLOOR)\n"
    "        sector_frameworks = self._sector_cat_stack(\n"
    "            sub_industry, reg_flags.get(\"sub_industry_detail\"), reg_flags)\n"
    "        sector_cat_raw = sum(stat_max for _, stat_max in sector_frameworks)\n"
    "        sector_cat_scaled = int(round(sector_cat_raw * fine_capacity_factor))\n"
    "        # Per-framework scaled breakdown for the audit panel in the PDF.\n"
    "        sector_cat_breakdown = [\n"
    "            {\"framework\": name,\n"
    "             \"statutory_max_zar\": stat_max,\n"
    "             \"cat_scaled_zar\": int(round(stat_max * fine_capacity_factor))}\n"
    "            for name, stat_max in sector_frameworks\n"
    "        ]\n"
)
NEW = (
    "        # Lever 2 (cat refinement, 2026-06-08): a broadly-applicable statutory\n"
    "        # FIXED-CAP fine (POPIA s109 R10M, ECTA R1M) does not scale down with\n"
    "        # company size the way discretionary enforcement does - a serious breach\n"
    "        # at a micro FSP can attract most of that ceiling in a 1-in-X catastrophe.\n"
    "        # Floor the capacity factor used for THESE fines so small QUALIFYING\n"
    "        # entities carry genuine fine exposure (POPIA R10M x 0.80 = R8M).\n"
    "        #\n"
    "        # The floor is DELIBERATELY NOT applied to the discretionary sector\n"
    "        # mega-ceilings (FSCA R100M / FIC R50M / JSE R7.5M / etc.): those\n"
    "        # sanctions are size-proportionate, so a R5M FSP cannot plausibly attract\n"
    "        # R40M of FIC. The sector stack therefore keeps scaling by the UN-FLOORED\n"
    "        # capacity_factor. The %-of-turnover frameworks (GDPR / CPA / PCI) are\n"
    "        # untouched - they already scale with revenue.\n"
    "        fine_capacity_factor = max(capacity_factor, FINE_CAPACITY_FLOOR)\n"
    "        sector_frameworks = self._sector_cat_stack(\n"
    "            sub_industry, reg_flags.get(\"sub_industry_detail\"), reg_flags)\n"
    "        sector_cat_raw = sum(stat_max for _, stat_max in sector_frameworks)\n"
    "        # Un-floored capacity_factor (NOT fine_capacity_factor): sector ceilings\n"
    "        # are size-proportionate and must keep scaling down with revenue.\n"
    "        sector_cat_scaled = int(round(sector_cat_raw * capacity_factor))\n"
    "        # Per-framework scaled breakdown for the audit panel in the PDF.\n"
    "        sector_cat_breakdown = [\n"
    "            {\"framework\": name,\n"
    "             \"statutory_max_zar\": stat_max,\n"
    "             \"cat_scaled_zar\": int(round(stat_max * capacity_factor))}\n"
    "            for name, stat_max in sector_frameworks\n"
    "        ]\n"
)
assert s.count(OLD) == 1, ("sector scope block", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(SA, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(SA, encoding="utf-8").read())
print(f"OK scoring_analytics.py: {n} edits "
      f"(POPIA/ECTA-scoped floor 0.80 + continuous elasticity + sector un-floored).")
