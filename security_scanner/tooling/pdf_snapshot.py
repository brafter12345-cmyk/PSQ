"""PDF output snapshot guard — proves a pdf_report refactor is
behaviour-preserving.

Generates every report tier from the committed test fixtures, normalizes the
volatile PDF metadata (CreationDate / ModDate / trailer ID — everything else
ReportLab emits is deterministic for fixed input), and hashes the result.

  --save    write the baseline hashes to tooling/pdf_snapshot_baseline.json
  --check   regenerate and compare against the saved baseline (exit 1 on drift)

Workflow for a refactor: run --save on the pre-refactor code, refactor, run
--check. A mismatch means rendered output changed — diff before shipping.
NOTE: content changes (new cards, reworded notes) legitimately change hashes;
re-run --save afterwards to re-baseline.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

BASELINE_PATH = HERE / "pdf_snapshot_baseline.json"
FIXTURES = (
    "test_fixtures/phishield_R10M_finance_2026-05-15.json",
    "test_fixtures/takealot_baseline.json",
    # Carries a vendor estate and an ownership-unconfirmed host. The other two
    # fixtures have third_party_hosting = 0 and no estate_total_ips, so the
    # vendor-estate block and the co-tenancy warning rendered NOTHING under this
    # gate: an entire new client-facing section shipped with no snapshot
    # coverage, and estate_ip_count always took its legacy fallback branch.
    "test_fixtures/vendor_estate_baseline.json",
)
TIERS = ("assessment", "summary", "full")

_CREATION_RE = re.compile(rb"/CreationDate \(D:[^)]*\)")
_MOD_RE = re.compile(rb"/ModDate \(D:[^)]*\)")
_ID_RE = re.compile(rb"/ID\s*\[<[0-9a-fA-F]+><[0-9a-fA-F]+>\]")


def _normalized_hash(pdf_bytes: bytes) -> str:
    norm = _CREATION_RE.sub(b"/CreationDate (D:NORM)", pdf_bytes)
    norm = _MOD_RE.sub(b"/ModDate (D:NORM)", norm)
    norm = _ID_RE.sub(b"/ID [<NORM><NORM>]", norm)
    return hashlib.sha256(norm).hexdigest()


def build_hashes() -> dict:
    from pdf_report import generate_pdf
    hashes = {}
    for fixture in FIXTURES:
        results = json.loads((ROOT / fixture).read_text(encoding="utf-8"))
        for tier in TIERS:
            key = f"{Path(fixture).stem}::{tier}"
            pdf = generate_pdf(results, report_type=tier)
            hashes[key] = {"sha256": _normalized_hash(pdf), "bytes": len(pdf)}
            print(f"  {key}: {hashes[key]['sha256'][:16]}… ({len(pdf):,} bytes)")
    return hashes


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--save", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = ap.parse_args()

    print("Generating PDFs from fixtures…")
    hashes = build_hashes()

    if args.save:
        BASELINE_PATH.write_text(json.dumps(hashes, indent=2), encoding="utf-8")
        print(f"Baseline saved: {BASELINE_PATH.name} ({len(hashes)} snapshots)")
        return 0

    if not BASELINE_PATH.exists():
        print("FAIL: no baseline found — run with --save on the reference code first.")
        return 1
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    drift = []
    for key, entry in hashes.items():
        base = baseline.get(key)
        if base is None:
            drift.append(f"{key}: no baseline entry")
        elif base["sha256"] != entry["sha256"]:
            drift.append(f"{key}: hash drift ({base['bytes']:,} -> {entry['bytes']:,} bytes)")
    missing = set(baseline) - set(hashes)
    drift.extend(f"{k}: baseline entry not regenerated" for k in missing)

    if drift:
        print()
        print("FAIL — rendered output drifted from baseline:")
        for d in drift:
            print(f"  {d}")
        return 1
    print(f"PASS — all {len(hashes)} snapshots match the baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
