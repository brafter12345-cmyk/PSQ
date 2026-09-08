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

# Published edge ranges, used ONLY by the harness to label a fixture as
# CDN-fronted independently of whatever the scanner currently believes.
_CDN = {
    "Cloudflare": ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13",
                   "162.158.0.0/15", "198.41.128.0/17", "173.245.48.0/20",
                   "103.21.244.0/22", "141.101.64.0/18", "108.162.192.0/18",
                   "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22"],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "AWS CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "52.222.128.0/17",
                       "54.192.0.0/16", "99.86.0.0/16"],
    "Akamai": ["23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "2.16.0.0/13"],
}
_NETS = [(p, ipaddress.ip_network(c)) for p, cs in _CDN.items() for c in cs]


def _edge_provider(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    for prov, net in _NETS:
        if a in net:
            return prov
    return None


def _resolved_ips(cats):
    ips = set()
    for _h, lst in ((cats.get("subdomains") or {}).get("resolved_ips") or {}).items():
        for ip in (lst or []):
            ips.add(ip)
    for ip in (cats.get("cloud_cdn") or {}).get("ip_addresses") or []:
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
        cdn = cats.setdefault("cloud_cdn", {})
        if not cdn.get("provider"):
            for ip in sorted(_resolved_ips(cats)):
                prov = _edge_provider(ip)
                if prov:
                    cdn.update({"provider": prov, "cdn_detected": True,
                                "hosting_type": "cloud/cdn",
                                "detected_by": "edge_range", "edge_ip": ip})
                    break

    apply_risk_score(results)

    # RiskScorer.calculate writes _scan_completeness into the CATEGORIES dict;
    # only scanner.py promotes it to the top level during a live scan. An
    # offline re-score therefore leaves the stored, stale copy sitting at the
    # top level, so reading it there measures the previous scan rather than this
    # one. Prefer the freshly computed copy and fall back to the stored one.
    sc = (cats.get("_scan_completeness")
          or results.get("_scan_completeness") or {})
    cdn = cats.get("cloud_cdn", {}) or {}
    fd = cats.get("fraudulent_domains", {}) or {}
    od = cats.get("origin_discovery", {}) or {}
    ins = results.get("insurance", {}) or {}

    # Deterministic: iterate the addresses in sorted order and keep the FIRST
    # provider seen. Iterating a set and keeping the last match made takealot
    # report Cloudflare or Akamai depending on set ordering, which showed up as
    # a spurious change in every diff and would eventually mask a real one.
    ips = _resolved_ips(cats)
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
        "cdn_true_edge": true_edge,
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
    missed = sum(1 for r in rows if not r["cdn_provider"] and r["cdn_true_edge"])
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
