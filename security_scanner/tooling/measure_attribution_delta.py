# -*- coding: utf-8 -*-
"""Measure what the SaaS-attribution change does to every retained scan.

WHY THIS EXISTS AND WHY THE EXISTING HARNESSES CANNOT DO IT. golden.py and
regen_outputs_from_cache._rescore re-score FROZEN CATEGORY AGGREGATES: the
checkers never re-run and _aggregate_ip_results never re-runs, so a change that
moves addresses between the own-attributed and vendor pools is invisible to
them. They would report this change as price-neutral whether it is or not.

So this replays the parts of the pipeline the change actually touches:

    classify_ip -> per-IP pool -> _aggregate_ip_results -> ExternalIPAggregator
                -> apply_risk_score -> apply_insurance_analytics

BEFORE and AFTER are both computed by RUNNING THE CODE, never by reading the
bucket stored in the fixture. The stored ip_classification predates both the
org rule and the post-scan pass, so diffing against it would credit this change
with demotions it did not make. BEFORE is the shipped classifier with the
service-range table disabled; AFTER is the same classifier with it live. That
makes the two sides differ in exactly one thing.

    py tooling/measure_attribution_delta.py
    py tooling/measure_attribution_delta.py --verbose

THE GATE THIS ENFORCES: re-attribution must not be a discount. If any fixture's
risk score IMPROVES or its recommended cover FALLS, the change is a rate cut
wearing an attribution fix's clothes, and the run exits non-zero.
"""
import argparse
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
sys.path.insert(0, APP)

FIXTURES = os.environ.get("SANDBOX_FIXTURES") or os.path.join(APP, "data", "fixtures")

IP_LEVEL_CHECKERS = ("dns_infrastructure", "high_risk_protocols", "dnsbl", "shodan_vulns")


def load_fixtures():
    out = []
    if not os.path.isdir(FIXTURES):
        raise SystemExit("fixture directory not found: %s\n"
                         "set SANDBOX_FIXTURES to the retained-scan export" % FIXTURES)
    for fn in sorted(os.listdir(FIXTURES)):
        if fn.endswith(".json") and not fn.startswith("_"):
            with open(os.path.join(FIXTURES, fn), encoding="utf-8") as fh:
                out.append(json.load(fh))
    return out


def classify_pool(results, rule_on):
    """Split the stored address pool into own / vendor / private by RUNNING the
    classifier, with the service-range table on or off."""
    import ip_classification as ipc
    import saas_ranges

    real = saas_ranges.service_provider
    ipc._service_provider = real if rule_on else (lambda _ip: None)
    try:
        cats = results.get("categories", {}) or {}
        per_ip = cats.get("per_ip") or {}
        # The addresses the scan actually held. per_ip is the scanned pool;
        # ip_classification carries everything discovered, including the hosts
        # a previous run had already demoted.
        addrs = list(dict.fromkeys(
            list(per_ip.keys()) + list((results.get("ip_classification") or {}).keys())))
        own, vendor, private = [], [], []
        for ip in addrs:
            v = per_ip.get(ip) or {}
            dns = v.get("dns_infrastructure") or {}
            shod = v.get("shodan_vulns") or {}
            banner = " ".join(
                str(p.get("detected_version", "")) + " " + str(p.get("banner", ""))
                for p in (dns.get("open_ports") or []))
            bucket, label = ipc.classify_ip(
                ip, reverse_dns=dns.get("reverse_dns"), org=shod.get("org"),
                banner=banner)
            if bucket == ipc.PRIVATE:
                private.append(ip)
            elif bucket == ipc.OWNED:
                own.append(ip)
            else:
                vendor.append((ip, label))
        return own, vendor, private
    finally:
        ipc._service_provider = real


def _aggregate(per_ip, checker_name):
    """Mirror of Scanner._aggregate_ip_results' selection step, richest-first."""
    rows = [per_ip[ip].get(checker_name, {}) for ip in per_ip
            if checker_name in (per_ip.get(ip) or {})]
    if not rows:
        return {"status": "completed", "issues": []}
    best = max(rows, key=lambda r: len(r.get("issues") or []))
    merged = dict(best)
    seen, issues = set(), []
    for r in rows:
        for it in (r.get("issues") or []):
            k = json.dumps(it, sort_keys=True, default=str)
            if k not in seen:
                seen.add(k)
                issues.append(it)
    merged["issues"] = issues
    return merged


def score_side(fixture, rule_on):
    from scoring_pipeline import apply_risk_score, apply_insurance_analytics
    from scoring_analytics import ExternalIPAggregator

    results = copy.deepcopy(fixture["results"])
    cats = results.setdefault("categories", {})
    per_ip_all = cats.get("per_ip") or {}

    own, vendor, private = classify_pool(results, rule_on)
    per_ip = {ip: v for ip, v in per_ip_all.items() if ip in set(own)}

    cats["per_ip"] = per_ip
    for name in IP_LEVEL_CHECKERS:
        if name in cats:
            cats[name] = _aggregate(per_ip, name)
    cats["external_ips"] = ExternalIPAggregator.aggregate(
        own, per_ip, ip_sources=results.get("ip_sources"),
        vendor_ips=[ip for ip, _ in vendor])

    # Call shape copied from regen_outputs_from_cache, which is the one path
    # known to reproduce a stored scan offline. The first version of this file
    # invented a signature, wrapped it in `except Exception: pass`, and
    # silently produced p_interruption=None, cover=None and total_expected=None
    # on 30 of 30 fixtures -- so three of the four regression checks below
    # compared None against None and passed without evaluating anything. The
    # exception is NOT swallowed here for exactly that reason: a broken
    # comparison must fail loudly, not report a clean run.
    ctx = results.setdefault("scan_context", {})
    waf_apex_status = (results.get("_scan_completeness") or {}).get("waf_status")
    apply_risk_score(results, waf_apex_status=waf_apex_status)
    apply_insurance_analytics(
        results,
        industry=ctx.get("industry") or "other",
        annual_revenue=float(ctx.get("annual_revenue") or 0),
        annual_revenue_zar=int(ctx.get("annual_revenue_zar") or 0),
        regulatory_flags=ctx.get("regulatory_flags"),
        sub_industry=ctx.get("sub_industry"),
        records_override=ctx.get("records_held"),
        scan_completeness=results.get("_scan_completeness"),
    )

    sc = dict(results.get("_scan_completeness") or {})
    sc.update(cats.get("_scan_completeness") or {})
    ext = cats.get("external_ips") or {}
    ins = results.get("insurance") or {}
    fin = ins.get("financial_impact") or {}
    # Field names read off the real output, not guessed. The first version of
    # this file invented fin["p_interruption"] / ins["recommended_cover"], which
    # do not exist, so every financial comparison silently compared None to
    # None. The live names are nested under risk_probability, cover_ladder and
    # estimated_annual_loss.
    rp = fin.get("risk_probability") or {}
    ladder = fin.get("cover_ladder") or {}
    eal = fin.get("estimated_annual_loss") or {}
    return {
        "own": len(own), "vendor": len(vendor), "private": len(private),
        "score": results.get("overall_risk_score"),
        "level": results.get("risk_level"),
        "confidence": sc.get("confidence_level"),
        "estate_confidence": sc.get("estate_confidence"),
        "total_unique_ips": ext.get("total_unique_ips"),
        "estate_total_ips": ext.get("estate_total_ips"),
        "unique_asns": ext.get("unique_asns"),
        "asn_coverage": ext.get("asn_coverage"),
        "p_availability": (rp.get("availability_resilience") or {}).get("indicator"),
        "p_breach": (rp.get("data_breach") or {}).get("probability"),
        "p_incident": (rp.get("cyber_incident") or {}).get("probability"),
        "eal_likely": eal.get("most_likely"),
        "cover_severe": (ladder.get("typical_severe") or {}).get("loss_zar"),
        "cover_cat": (ladder.get("catastrophic") or {}).get("loss_zar"),
        "cves": (ext.get("aggregate_vulns") or {}).get("total_cves"),
        "issues": len(ext.get("issues") or []),
        "vendor_labels": sorted({lbl for _ip, lbl in vendor if lbl}),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    fixtures = load_fixtures()
    if not fixtures:
        raise SystemExit("FAIL: zero fixtures loaded. A comparison over nothing "
                         "prints ALL MATCH and proves nothing.")

    rows, regressions, emptied = [], [], []
    # Per-field count of comparisons that ACTUALLY evaluated. A guard that
    # compares None against None reports a clean run over nothing; this
    # codebase has shipped that twice (a source check matching its own
    # comment, and compare_pdfs printing ALL MATCH over zero scenarios).
    import collections as _c
    evaluated = _c.Counter()
    tot_demoted = tot_cve_moved = tot_issue_moved = 0
    for fx in fixtures:
        dom = fx.get("domain") or "?"
        before = score_side(fx, rule_on=False)
        after = score_side(fx, rule_on=True)
        demoted = after["vendor"] - before["vendor"]
        tot_demoted += demoted
        tot_cve_moved += (before["cves"] or 0) - (after["cves"] or 0)
        tot_issue_moved += (before["issues"] or 0) - (after["issues"] or 0)

        # A re-attribution must never make a client look better. Every field
        # compared here is counted in `evaluated` as well, so a comparison that
        # silently degenerates to None-vs-None fails the run instead of passing.
        if (after["score"] or 0) > (before["score"] or 0):
            regressions.append("%s: risk score IMPROVED %s -> %s"
                               % (dom, before["score"], after["score"]))
        for field, label in (("cover_severe", "typical-severe cover"),
                             ("cover_cat", "catastrophic cover"),
                             ("eal_likely", "expected annual loss"),
                             ("p_breach", "p_breach"),
                             ("p_incident", "p_incident"),
                             ("p_availability", "availability indicator")):
            b, a = before[field], after[field]
            if b is None or a is None:
                continue
            evaluated[field] += 1
            if a < b:
                regressions.append("%s: %s FELL %s -> %s" % (dom, label, b, a))
        if demoted and after["own"] == 0 and before["own"] > 0:
            emptied.append(dom)
            if after["estate_confidence"] != "no_own_estate_assessed":
                regressions.append(
                    "%s: own pool emptied but estate_confidence is %r, not "
                    "'no_own_estate_assessed' -- an unmeasured estate is "
                    "rendering as an assessed one"
                    % (dom, after["estate_confidence"]))
            if after["confidence"] == "full":
                regressions.append(
                    "%s: own pool emptied but confidence_level is still 'full'" % dom)
        if demoted and after["estate_total_ips"] != before["estate_total_ips"]:
            regressions.append(
                "%s: estate_total_ips changed %s -> %s; demoting a host must "
                "not shrink the discovered footprint"
                % (dom, before["estate_total_ips"], after["estate_total_ips"]))
        rows.append((dom, before, after, demoted))

    print("=" * 96)
    print("%-24s %11s %11s %9s %8s %-22s" %
          ("domain", "own b->a", "estate b->a", "score", "demoted", "estate_confidence"))
    print("-" * 96)
    for dom, b, a, demoted in rows:
        if not demoted and not args.verbose:
            continue
        print("%-24s %5s->%-5s %5s->%-5s %4s->%-4s %8d %-22s"
              % (dom, b["own"], a["own"], b["estate_total_ips"], a["estate_total_ips"],
                 b["score"], a["score"], demoted, a["estate_confidence"] or ""))
    print("=" * 96)
    print("fixtures=%d  addresses demoted=%d  CVEs moved=%d  issues moved=%d"
          % (len(rows), tot_demoted, tot_cve_moved, tot_issue_moved))
    print("own pool emptied on: %s" % (", ".join(emptied) or "none"))

    FINANCIAL = ("cover_severe", "cover_cat", "eal_likely",
                 "p_breach", "p_incident", "p_availability")
    print("financial comparisons evaluated: %s"
          % {k: evaluated[k] for k in FINANCIAL})
    dead = [k for k in FINANCIAL if not evaluated[k]]
    if dead:
        print("\nFAIL: %d financial field(s) never evaluated on any fixture "
              "(%s). Those checks compared None against None and would have "
              "passed no matter what this change did." % (len(dead), dead))
        return 1

    if tot_demoted == 0:
        print("\nFAIL: the rule demoted nothing on any fixture. Either the table "
              "is not wired in or the corpus does not exercise it; either way "
              "this run measured nothing.")
        return 1

    # THE LOAD-BEARING ASSERTION. The entire case for shipping this without a
    # compensating tail load is that re-attribution moves no findings: the
    # addresses leaving the priced estate carry nothing but open ports 80 and
    # 443 on service endpoints. If a CVE or an issue moves, the table has
    # drifted into customer space and real client exposure is being deleted.
    #
    # This was REPORTED but not ASSERTED in the first version, and a mutation
    # that slipped a client-run Linode host (19 CVEs) into the table printed
    # "CVEs moved=19" and still exited 0. Printing a number the reader is
    # trusted to notice is not a gate.
    if tot_cve_moved or tot_issue_moved:
        print("\nFAIL: re-attribution moved %d CVE(s) and %d issue(s) out of "
              "insureds' estates. This change is only safe because that count "
              "is zero: a finding that moves is a finding deleted from a "
              "client's priced exposure. Check what the table captured."
              % (tot_cve_moved, tot_issue_moved))
        return 1
    if regressions:
        print("\nFAIL: %d regression(s):" % len(regressions))
        for r in regressions:
            print("   " + r)
        return 1
    print("\nOK: %d addresses re-attributed across %d scan(s). No score improved, "
          "no cover or loss figure fell, no estate shrank, across %d evaluated "
          "financial comparisons."
          % (tot_demoted, sum(1 for r in rows if r[3]),
             sum(evaluated[k] for k in FINANCIAL)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
