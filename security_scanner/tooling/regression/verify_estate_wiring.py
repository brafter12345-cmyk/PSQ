# -*- coding: utf-8 -*-
"""Every external_ips aggregation must carry the vendor address list.

THE BUG THIS EXISTS FOR. ExternalIPAggregator.aggregate is called three times in
scanner.py: once after classification, again after OSV enrichment, and a third
time in an unconditional "ensure re-aggregation always runs" block. When the
own/vendor estate split shipped, only the FIRST call was given vendor_ips. The
last one therefore overwrote the result on every single scan, resetting
vendor_ip_count to 0, estate_total_ips to the post-attribution own count, and
asn_coverage to "full".

The effect was the precise harm the split was built to prevent: measured over 30
retained scans, 19 estates shrank and 5 lost a Reconnaissance severity step,
because correcting a client's attribution made their reported footprint smaller.

WHY THE OTHER CHECKS ALL MISSED IT, which is the part worth remembering.
measure_attribution_delta.py calls aggregate ONCE, itself, with vendor_ips, so
it modelled the intended pipeline rather than the real one and reported the
change as working. The unit behaviour was correct in isolation at every point.
Nothing tested the WIRING, and the wiring was the defect.

This is therefore a SOURCE-LEVEL check over the AST, in the same spirit as
verify_rsi_revenue_wiring.py. It reads the parse tree and not the text: an
earlier guard in this codebase matched a keyword inside its own explanatory
comment and reported a false green for two commits.

    py tooling/regression/verify_estate_wiring.py
"""
import ast
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(os.path.dirname(HERE))
SCANNER = os.path.join(SEC, "scanner.py")

REQUIRED_KWARG = "vendor_ips"


def aggregate_calls(tree):
    """Every ExternalIPAggregator.aggregate(...) call node."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "aggregate":
            base = fn.value
            if isinstance(base, ast.Name) and base.id == "ExternalIPAggregator":
                out.append(node)
    return out


def main():
    with io.open(SCANNER, encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    calls = aggregate_calls(tree)

    # Non-vacuity first. A check that finds nothing must fail, not pass: this
    # codebase has shipped a comparison script that printed ALL MATCH over zero
    # scenarios, and the failure mode is indistinguishable from success.
    if not calls:
        print("FAIL: no ExternalIPAggregator.aggregate call found in scanner.py.")
        print("      Either the aggregation moved or this check is looking at "
              "the wrong file. Either way it is proving nothing.")
        return 1

    bad = []
    for node in calls:
        names = [kw.arg for kw in node.keywords]
        if REQUIRED_KWARG not in names:
            bad.append((node.lineno, names))

    for node in calls:
        names = [kw.arg for kw in node.keywords]
        mark = "OK " if REQUIRED_KWARG in names else "MISSING"
        print("  [%s] scanner.py:%-5d kwargs=%s" % (mark, node.lineno, names))

    if bad:
        print()
        print("FAIL: %d of %d ExternalIPAggregator.aggregate call(s) omit %r."
              % (len(bad), len(calls), REQUIRED_KWARG))
        for lineno, names in bad:
            print("      scanner.py:%d  kwargs=%s" % (lineno, names))
        print()
        print("      Any call that omits it OVERWRITES the estate split with a")
        print("      vendor-free result. The last call wins, so one omission")
        print("      anywhere silently undoes the whole thing, and the client's")
        print("      reported external footprint shrinks to the post-attribution")
        print("      own count. Measured when this last happened: 19 of 30")
        print("      estates shrank and 5 lost a Reconnaissance severity step.")
        return 1

    print()
    print("OK: all %d ExternalIPAggregator.aggregate call(s) pass %r."
          % (len(calls), REQUIRED_KWARG))
    return 0


if __name__ == "__main__":
    sys.exit(main())
