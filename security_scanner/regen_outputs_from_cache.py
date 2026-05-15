"""Regenerate report outputs from cached scan JSON.

Loads the most recent cached scan from test_fixtures/, runs the current
pdf_report.generate_pdf() against it for both full and summary report
types, and renders the HTML results template offline so the user can
review the new layout without needing the live Render server. No
network calls - purely uses the cached data.

Useful when the scanner is under a temporary WAF block at the target
or when iterating on report layout without burning live scan budget.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

# Locate the cached JSON (use today's if present, fall back to yesterday)
fixtures = HERE / "test_fixtures"
candidates = sorted(fixtures.glob("phishield_R10M_finance_*.json"), reverse=True)
if not candidates:
    print("No cached phishield_R10M_finance_*.json found in test_fixtures/")
    sys.exit(1)
src = candidates[0]
print(f"Loading cached scan: {src.name} ({src.stat().st_size // 1024} KB)")

with src.open("r", encoding="utf-8") as f:
    results = json.load(f)

# Output directory next to the cached JSON
outdir = fixtures / "regen_outputs"
outdir.mkdir(exist_ok=True)

# --- Full PDF ---
print("\n[1/3] Regenerating full PDF...")
from pdf_report import generate_pdf
full_bytes = generate_pdf(results, report_type="full")
full_path = outdir / "phishield_full_2026-05-15.pdf"
full_path.write_bytes(full_bytes)
print(f"  -> {full_path}  ({full_path.stat().st_size // 1024} KB)")

# --- Summary PDF ---
print("\n[2/3] Regenerating summary PDF...")
summary_bytes = generate_pdf(results, report_type="summary")
summary_path = outdir / "phishield_summary_2026-05-15.pdf"
summary_path.write_bytes(summary_bytes)
print(f"  -> {summary_path}  ({summary_path.stat().st_size // 1024} KB)")

# --- HTML render via Jinja2 (offline; no Flask required) ---
print("\n[3/3] Rendering HTML results page...")
from jinja2 import Environment, FileSystemLoader
templates = HERE / "templates"
env = Environment(loader=FileSystemLoader(str(templates)),
                  autoescape=True)
template = env.get_template("results.html")
# The template expects `results` + a few helper variables; pass the
# cached scan as `results`. scan_id is synthetic for the offline render.
html_out = template.render(results=results, scan_id="cached-2026-05-15")
html_path = outdir / "phishield_results_2026-05-15.html"
html_path.write_text(html_out, encoding="utf-8")
print(f"  -> {html_path}  ({html_path.stat().st_size // 1024} KB)")

print(f"\nAll three outputs in: {outdir}")
print("\nQuick checks (post-Batch 5/6/7 features should all render):")
sc = results.get("_scan_completeness", {})
print(f"  - per_checker_seconds: {len(sc.get('per_checker_seconds', {}))} entries")
print(f"  - waf_status: {sc.get('waf_status', 'absent in cached JSON - pre-WAF-tracker scan')}")
fin = results.get("insurance", {}).get("financial_impact", {})
le = fin.get("loss_exposure", {}).get("scenarios", {})
print(f"  - loss_exposure scenarios: {list(le.keys())}")
cat = fin.get("regulatory_exposure", {}).get("catastrophe_stack", {})
print(f"  - catastrophe_stack capacity_factor: {cat.get('capacity_factor')}")
print(f"  - catastrophe_stack total: R{cat.get('total_cat_stack_zar', 0):,}")
flags = fin.get("regulatory_exposure", {}).get("flags", {})
print(f"  - flags keys: {list(flags.keys())}")
auto = flags.get("_auto_detected")
print(f"  - _auto_detected present: {auto is not None}")
