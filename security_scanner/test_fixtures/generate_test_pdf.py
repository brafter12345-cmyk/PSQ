"""Generate PDF reports from cached scan data — no live scan needed.

Usage:
    python test_fixtures/generate_test_pdf.py [full|summary|both] [--patch]

Modes:
    full        Generate full technical report only
    summary     Generate broker summary only
    both        Generate both (default)

Options:
    --patch     Inject cached good results for blocked checkers (http_headers,
                waf, tech_stack, privacy_compliance, exposed_admin) into the
                baseline scan data. Use this when testing new scanner features
                that need realistic checker data, not just PDF layout.
                Without --patch, uses raw scan data as-is (may have errored checkers).

Outputs:
    test_fixtures/test_full_report.pdf
    test_fixtures/test_broker_summary.pdf
"""
import json
import sys
import os

# Add parent dir to path so we can import pdf_report
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pdf_report import generate_pdf

fixture_dir = os.path.dirname(__file__)
fixture_path = os.path.join(fixture_dir, "phishield_baseline.json")
cache_path = os.path.join(fixture_dir, "phishield_blocked_cache.json")

with open(fixture_path) as f:
    results = json.load(f)

# Parse args
args = sys.argv[1:]
patch = "--patch" in args
report_type = "both"
for a in args:
    if a in ("full", "summary", "both"):
        report_type = a

# Patch blocked checkers with cached good data
if patch:
    with open(cache_path) as f:
        cache = json.load(f)
    cats = results.get("categories", {})
    patched = []
    for name, good_data in cache.items():
        if name.startswith("_"):
            continue
        current = cats.get(name, {})
        if isinstance(current, dict) and current.get("status") in ("error", "timeout", None):
            cats[name] = good_data
            patched.append(name)
        elif isinstance(current, dict) and current.get("status") == "completed":
            # Also patch if current data is empty/degraded (e.g. exposed_admin with 0 findings)
            if name == "exposed_admin" and not current.get("exposed"):
                cats[name] = good_data
                patched.append(name)
    if patched:
        print(f"Patched {len(patched)} checker(s): {', '.join(patched)}")
    else:
        print("No checkers needed patching (all completed successfully)")

if report_type in ("full", "both"):
    pdf_bytes = generate_pdf(results, report_type="full")
    out = os.path.join(fixture_dir, "test_full_report.pdf")
    with open(out, "wb") as f:
        f.write(pdf_bytes)
    print(f"Full report: {out} ({len(pdf_bytes):,} bytes)")

if report_type in ("summary", "both"):
    pdf_bytes = generate_pdf(results, report_type="summary")
    out = os.path.join(fixture_dir, "test_broker_summary.pdf")
    with open(out, "wb") as f:
        f.write(pdf_bytes)
    print(f"Broker summary: {out} ({len(pdf_bytes):,} bytes)")
