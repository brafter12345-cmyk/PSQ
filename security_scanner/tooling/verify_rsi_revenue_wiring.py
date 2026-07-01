"""Gate: RSI must be scored on the RESOLVED ZAR revenue, not the vestigial
`annual_revenue` field.

The RansomwareIndex size-multiplier bands are in ZAR. The scan form sends revenue
ONLY as `annual_revenue_zar`, so any scan path that feeds RSI the separate
`annual_revenue` argument pins every form scan to the <R10M "micro" multiplier
(1.12) regardless of real revenue — over-loading RSI (and premium) for every
non-micro client. (Found 2026-06-30: live scanner used `annual_revenue` while the
golden rescore used `annual_revenue` OR `annual_revenue_zar`, so golden — a
different code path — never caught it.)

This gate (a) checks the band logic directly and (b) statically asserts the
scanner RSI call site can't regress to the bare `annual_revenue`.

Exit 0 = pass, 1 = fail (DO NOT DEPLOY).  Offline, network-free.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

fails = []

# (a) Band logic — ZAR revenue drives the size multiplier as documented.
from scoring_analytics import RansomwareIndex  # noqa: E402
def _mult(rev):
    return RansomwareIndex().calculate({}, "Retail", rev)["size_multiplier"]
for rev, want in [(2_000_000_000, 0.85), (300_000_000, 0.96), (0, 1.12)]:
    got = _mult(rev)
    if got != want:
        fails.append(f"band: R{rev:,} -> size_mult {got} (expected {want})")

# (b) Static — the RSI call site (now the shared scoring_pipeline, exercised by
#     BOTH the live scan and the golden/regen rescore) must NOT pass the vestigial
#     `annual_revenue`, and must resolve ZAR revenue before scoring RSI. Checking
#     the one shared call site covers both callers (see
#     verify_scoring_pipeline_unified.py, which forbids either from re-inlining it).
src = (ROOT / "scoring_pipeline.py").read_text(encoding="utf-8")
m = re.search(r"rsi_calc\.calculate\(([^)]*)\)", src)
if not m:
    fails.append("scoring_pipeline.py: rsi_calc.calculate(...) call not found")
elif re.search(r"\bannual_revenue\b(?!_zar)", m.group(1)):
    fails.append(f"scoring_pipeline.py: RSI call passes vestigial annual_revenue "
                 f"({m.group(1).strip()}) — must pass the resolved ZAR revenue (_zar)")
if "resolve_effective_revenue_zar(annual_revenue_zar)" not in src:
    fails.append("scoring_pipeline.py: resolve_effective_revenue_zar(annual_revenue_zar) not found")
# It must be resolved BEFORE the RSI call, else _zar is undefined / RSI is stale.
i_resolve = src.find("_zar = resolve_effective_revenue_zar")
i_rsi = src.find("rsi_calc.calculate(")
if i_resolve == -1 or i_rsi == -1 or i_resolve > i_rsi:
    fails.append("scoring_pipeline.py: _zar must be resolved BEFORE the RSI call")

if fails:
    print("RSI REVENUE WIRING GATE FAILED:")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("RSI revenue wiring gate PASS — RSI scored on resolved ZAR revenue "
      "(R2bn->0.85, R300M->0.96, R0->1.12; scoring_pipeline passes _zar)")
