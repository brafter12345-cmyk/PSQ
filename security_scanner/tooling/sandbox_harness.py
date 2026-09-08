# -*- coding: utf-8 -*-
"""Sandbox harness: measure what a remediation step actually changes.

Replays real completed scans (exported read-only from production) through the
scoring and reporting path and records the signals each remediation step is
meant to move. Run it against master to capture a baseline, then against the
sandbox after a fix, and diff: any change the fix did not intend shows up.

No checker runs and no network call is made. The fixtures are frozen scan
results, so this is deterministic and costs nothing.

    py tooling/sandbox_harness.py --out before.json
    py tooling/sandbox_harness.py --out after.json
    py tooling/sandbox_harness.py --diff before.json after.json
"""
import argparse
import ipaddress
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
sys.path.insert(0, APP)

FIXTURES = os.environ.get("SANDBOX_FIXTURES") or (
    "C:/Users/sarel/AppData/Local/Temp/claude/"
    "C--Users-sarel-Desktop-Sarel-SML-Consulting-PSQ--claude-worktrees-"
    "affectionate-varahamihira-dc4d1a/9966bd2e-be22-4cb7-9555-7ec1d6d5d6f6/"
    "scratchpad/sandbox_fixtures")

# The harness MUST NOT carry its own copy of the edge ranges. It did, and the
# copy was smaller (4 providers, 23 blocks, no IPv6) than the shipped table
# (7 providers, 83 blocks). Measuring a reimplementation measures the
# reimplementation.
from cdn_ranges import edge_provider as _edge_provider   # noqa: E402


def _apex_ips(cats):
    """Exactly what CloudCDNChecker iterates: the apex A records.

    checkers_core.CloudCDNChecker.check resolves dns_cache.resolve(domain, "A")
    into result["ip_addresses"] and scans only that. Anything wider measures an
    algorithm the scanner does not run.
    """
    return list((cats.get("cloud_cdn") or {}).get("ip_addresses") or [])


def _all_resolved_ips(cats):
    """Apex PLUS subdomain addresses.

    Used only for the INDEPENDENT `cdn_true_edge` label, which answers "is this
    target CDN-fronted anywhere", deliberately not the same question the checker
    asks. Keeping the two apart is the point: conflating them made the missed
    count compare one function against itself and always report zero.
    """
    ips = set(_apex_ips(cats))
    for _h, lst in ((cats.get("subdomains") or {}).get("resolved_ips") or {}).items():
        for ip in (lst or []):
            ips.add(ip)
    return ips


def load_fixtures():
    out = []
    for fn in sorted(os.listdir(FIXTURES)):
        if not fn.endswith(".json") or fn.startswith("_"):
            continue
        with open(os.path.join(FIXTURES, fn), encoding="utf-8") as fh:
            out.append(json.load(fh))
    return out


def measure(fx, simulate_cdn=False):
    """Re-score a frozen scan and record every signal the remediation touches.

    ``simulate_cdn`` reconstructs what address-range detection would have found,
    using the addresses the scan actually recorded. The fixtures are frozen
    results, so re-scoring alone can never show a checker-level fix: cloud_cdn
    was written as null at scan time and stays null. Applying the published edge
    ranges to the SAME stored addresses reproduces what the corrected checker
    would emit for that scan, which is what makes the score movement measurable
    without re-scanning anything or spending a credit.
    """
    from scoring_pipeline import apply_risk_score
    results = json.loads(json.dumps(fx["results"]))   # never mutate the fixture
    cats = results.get("categories", {}) or {}

    if simulate_cdn:
        # Reproduce the SHIPPED block: apex addresses only, real edge table,
        # sorted first-match. Simulating over a wider address set reported 7 of
        # 30 detections where production finds 4, and named domains as capped
        # that production never detects.
        cdn = cats.setdefault("cloud_cdn", {})
        if not cdn.get("provider"):
            for ip in sorted(_apex_ips(cats)):
                prov = _edge_provider(ip)
                if prov:
                    cdn.update({"provider": prov, "cdn_detected": True,
                                "hosting_type": "cloud/cdn",
                                "detected_by": "edge_range", "edge_ip": ip})
                    break

    apply_risk_score(results)

    # RiskScorer writes _scan_completeness into the CATEGORIES dict and only
    # scanner.py promotes it, enriching it with live-only fields (coverage_pct,
    # waf_status, per-checker timings). Reading only the fresh copy blinded
    # coverage_pct on 30 of 30 fixtures; reading only the stored copy measured
    # the previous scan. Merge: stored as the base, fresh values winning.
    sc = dict(results.get("_scan_completeness") or {})
    sc.update(cats.get("_scan_completeness") or {})
    cdn = cats.get("cloud_cdn", {}) or {}
    fd = cats.get("fraudulent_domains", {}) or {}
    od = cats.get("origin_discovery", {}) or {}
    ins = results.get("insurance", {}) or {}

    # Deterministic: iterate the addresses in sorted order and keep the FIRST
    # provider seen. Iterating a set and keeping the last match made takealot
    # report Cloudflare or Akamai depending on set ordering, which showed up as
    # a spurious change in every diff and would eventually mask a real one.
    ips = _all_resolved_ips(cats)
    true_edge = None
    for ip in sorted(ips):
        p = _edge_provider(ip)
        if p:
            true_edge = p
            break

    looks = fd.get("fraudulent_domains") or []
    return {
        "domain": fx["domain"],
        "score": results.get("overall_risk_score"),
        "level": results.get("risk_level"),
        "confidence": sc.get("confidence_level"),
        "completeness_pct": sc.get("completeness_pct"),
        "coverage_pct": sc.get("coverage_pct"),
        "estate_confidence": sc.get("estate_confidence"),
        "cdn_provider": cdn.get("provider"),
        "cdn_detected": bool(cdn.get("cdn_detected")),
        "cdn_true_edge": true_edge,          # anywhere on the target
        "cdn_apex_edge": next((_edge_provider(i) for i in sorted(_apex_ips(cats))
                               if _edge_provider(i)), None),
        "origin_verified": len(od.get("verified") or []),
        "origin_candidates": len(od.get("candidates") or []),
        "lookalike_count": len(looks),
        "lookalike_domains": sorted(d.get("domain", "") for d in looks),
        "lookalike_score": fd.get("score"),
        "own_asset_excluded": fd.get("own_assets_excluded"),
        "p_interruption": (ins.get("financial_impact") or {}).get("p_interruption"),
        "rec_count": len(results.get("recommendations") or []),
        "rec_first": (results.get("recommendations") or [""])[0][:110],
    }


def run(out_path, simulate_cdn=False):
    fixtures = load_fixtures()
    rows = [measure(fx, simulate_cdn=simulate_cdn) for fx in fixtures]
    payload = {"fixture_count": len(rows), "rows": {r["domain"]: r for r in rows}}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, default=str, sort_keys=True)
    print("measured %d fixture(s) -> %s" % (len(rows), out_path))

    named = sum(1 for r in rows if r["cdn_provider"])
    # Against the apex label, which is the question the checker asks. Comparing
    # against the wider label made this identical to the simulation input, so it
    # was zero by construction and measured nothing.
    missed = sum(1 for r in rows if not r["cdn_provider"] and r["cdn_apex_edge"])
    print("  CDN named            : %d / %d" % (named, len(rows)))
    print("  CDN present, missed  : %d / %d" % (missed, len(rows)))
    print("  lookalikes reported  : %d / %d"
          % (sum(1 for r in rows if r["lookalike_count"]), len(rows)))
    print("  full confidence      : %d / %d"
          % (sum(1 for r in rows if r["confidence"] == "full"), len(rows)))
    return payload


def diff(a_path, b_path):
    a = json.load(open(a_path, encoding="utf-8"))
    b = json.load(open(b_path, encoding="utf-8"))
    ka, kb = set(a["rows"]), set(b["rows"])
    if ka - kb:
        print("MISSING in after: %s" % sorted(ka - kb))
    if kb - ka:
        print("NEW in after: %s" % sorted(kb - ka))

    changed, unchanged = [], 0
    for dom in sorted(ka & kb):
        ra, rb = a["rows"][dom], b["rows"][dom]
        deltas = {k: (ra.get(k), rb.get(k)) for k in sorted(set(ra) | set(rb))
                  if ra.get(k) != rb.get(k)}
        if deltas:
            changed.append((dom, deltas))
        else:
            unchanged += 1

    print("=" * 74)
    print("fixtures: %d   unchanged: %d   changed: %d"
          % (len(ka & kb), unchanged, len(changed)))
    for dom, deltas in changed:
        print()
        print("  %s" % dom)
        for k, (x, y) in deltas.items():
            sx, sy = str(x), str(y)
            if len(sx) > 60:
                sx = sx[:57] + "..."
            if len(sy) > 60:
                sy = sy[:57] + "..."
            print("    %-20s %s  ->  %s" % (k, sx, sy))
    print("=" * 74)
    scores = [(d, dl["score"]) for d, dl in changed if "score" in dl]
    if scores:
        print("SCORE MOVEMENTS (%d):" % len(scores))
        for d, (x, y) in scores:
            direction = "down (cheaper)" if (y or 0) < (x or 0) else "up (dearer)"
            print("   %-24s %s -> %s   %s" % (d, x, y, direction))
    else:
        print("no score movements")
    return changed


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--simulate-cdn", action="store_true",
                    help="reconstruct address-range CDN detection from the "
                         "addresses each frozen scan recorded")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"))
    args = ap.parse_args()
    if args.diff:
        diff(*args.diff)
    elif args.out:
        run(args.out, simulate_cdn=args.simulate_cdn)
    else:
        ap.error("give --out or --diff")
