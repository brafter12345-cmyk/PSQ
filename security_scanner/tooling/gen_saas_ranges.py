# -*- coding: utf-8 -*-
"""Generate saas_ranges.py from the pinned Microsoft 365 endpoints artefact.

WHY A GENERATOR AND NOT A HAND-TYPED TABLE. The design pass that produced this
rule recalled the Exchange Online Protection prefix as 104.47.128.0/17. The
arithmetic was right (104.47.164.119 really is inside that block) and the fact
was wrong: Microsoft publishes 104.47.0.0/17, the LOWER half, so 104.47.164.119
is not in any published service range and must NOT be demoted. A hand-typed
table would have shipped that error as a client-visible attribution. The table
is therefore derived mechanically from a committed artefact, and a build check
fails if the two ever disagree.

    py tooling/gen_saas_ranges.py --check     # verify the shipped table matches
    py tooling/gen_saas_ranges.py --write     # regenerate after refreshing
    py tooling/gen_saas_ranges.py --refresh   # re-fetch the artefact (network)

REFRESHING IS A DELIBERATE ACT. The artefact is pinned so that a scan is
reproducible and a regression test means something. A provider that silently
changes a JSON feed must not silently change how a client is scored, so
--refresh rewrites the artefact for review and never runs as part of a scan.

review-by: 2027-03-09  (provider address ranges are point-in-time)
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
ARTEFACT = os.path.join(APP, "data", "feeds", "m365_endpoints_worldwide.json")
# The feed payload does not carry its own version, so --refresh records it
# beside the artefact. A bare sha256 tells a reviewer that SOMETHING changed;
# a version tells them WHICH publication they are being asked to accept.
VERSION_FILE = ARTEFACT.replace(".json", ".version")
TARGET = os.path.join(APP, "saas_ranges.py")

FEED_URL = ("https://endpoints.office.com/endpoints/worldwide"
            "?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7")
VERSION_URL = ("https://endpoints.office.com/version/worldwide"
               "?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7")

# ADMISSION TEST. A service area is admitted only if a misconfiguration on a host
# in its address space would be MICROSOFT's to fix and never the client's. All
# four published areas pass: Exchange Online / EOP, SharePoint Online, Teams and
# the Entra / Office common endpoints are managed services, not tenancy the
# client operates. Deliberately absent: every generic compute allocation
# (20.0.0.0/8, 13.64.0.0/11, 40.64.0.0/10), because that is exactly where a
# customer-run Azure VM lives and demoting one deletes the client's real
# exposure. Measured on the 30-scan corpus, Exchange alone and all four areas
# demote the identical 174 addresses, so the extra areas cost nothing today and
# guard a SharePoint or Teams endpoint appearing on a future scan.
ADMITTED_AREAS = ("Exchange", "SharePoint", "Skype", "Common")

# Backstop floors. A prefix wider than these cannot be a service endpoint range,
# and is refused even if the feed lists one: widening a prefix is the cheapest
# way to turn this table into a discount for customer-run hosts.
MIN_V4_PREFIX = 12
MIN_V6_PREFIX = 32

# How long a pinned feed may go unrefreshed before the build blocks. Six
# months: long enough that a refresh is a deliberate, reviewed act, short
# enough that a withdrawn or newly published prefix cannot sit unnoticed
# through a whole underwriting year.
MAX_FEED_AGE_DAYS = 180

AREA_LABELS = {
    "Exchange": "Microsoft 365 (Exchange Online)",
    "SharePoint": "Microsoft 365 (SharePoint Online)",
    "Skype": "Microsoft 365 (Teams)",
    "Common": "Microsoft 365 (common services)",
}

HEADER = '''# -*- coding: utf-8 -*-
"""Provider-published FIRST-PARTY SERVICE address ranges.

GENERATED FILE. Do not edit by hand; run tooling/gen_saas_ranges.py.

WHY THIS EXISTS. ip_classification attributes a host to whoever operates it, and
defaulted to the insured whenever no vendor signal fired. Measured across 30
retained scans, 174 of the 307 addresses classified as the insured's own were
Microsoft 365 service endpoints: Exchange Online front ends behind autodiscover
and mail records, reached because subdomain enumeration resolves them and
nothing downstream could tell them apart from the client's own infrastructure.

Reverse DNS cannot separate them, because those ranges publish no PTR at all.
Shodan's org string cannot either, and in fact made it worse: Exchange Online
and a customer-run Azure VM both answer "Microsoft Corporation", and
ip_classification read that as proof the insured operated the host.

ADDRESS MEMBERSHIP IS THE ONLY SIGNAL IN THIS CHAIN THE INSURED CANNOT AUTHOR.
A customer cannot arrange for their VM to be allocated out of the Exchange
Online service block. It is also the only signal that works on IPv6 and when PTR
and Shodan org are both absent, which is the state of most affected addresses.

ADMISSION TEST, applied by the generator: a range enters only if a
misconfiguration on a host inside it would be MICROSOFT's to fix and never the
client's. Generic compute allocations are excluded by construction, because that
is where customer-run VMs live.

MEASURED EFFECT on the 30-scan corpus: 174 addresses across 19 scans leave the
insured's priced estate, carrying 0 CVEs and 0 issues. Nothing is discounted;
only the attribution changes. Callers must still surface a demoted host as a
supply-chain dependency, or the estate silently shrinks and the client reads as
cleaner than it was measured to be.

review-by: 2027-03-09  (provider address ranges are point-in-time)
"""
import ipaddress

# sha256 of data/feeds/m365_endpoints_worldwide.json this table was built from.
FEED_SHA256 = "%(digest)s"
FEED_VERSION = "%(version)s"
FEED_URL = "%(url)s"

SERVICE_RANGES = {
'''

FOOTER = '''}

# Prefix floors the generator enforced, re-asserted at import so that a hand-edit
# which widens a prefix fails loudly instead of quietly capturing customer hosts.
MIN_V4_PREFIX = %(v4)d
MIN_V6_PREFIX = %(v6)d

_NETS = []
for _label, _cidrs in SERVICE_RANGES.items():
    for _c in _cidrs:
        _n = ipaddress.ip_network(_c)
        _floor = MIN_V6_PREFIX if _n.version == 6 else MIN_V4_PREFIX
        if _n.prefixlen < _floor:
            raise ValueError(
                "saas_ranges: %%s is wider than the /%%d floor" %% (_c, _floor))
        _NETS.append((_n, _label))


def service_provider(ip):
    """Label of the first-party service range holding *ip*, else None.

    Never raises: an unparseable address is simply not a member, which fails
    toward the caller's existing behaviour.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for net, label in _NETS:
        if addr.version == net.version and addr in net:
            return label
    return None


def is_service_ip(ip):
    return service_provider(ip) is not None
'''


def read_version():
    """Recorded feed version, or a marker when the artefact predates this."""
    try:
        with open(VERSION_FILE, encoding="utf-8") as fh:
            return fh.read().strip() or "unrecorded"
    except OSError:
        return "unrecorded"


def load_artefact():
    with open(ARTEFACT, "rb") as fh:
        raw = fh.read()
    return raw, json.loads(raw.decode("utf-8"))


def collect(feed):
    """label -> sorted prefixes, refusing anything wider than the floors."""
    out, refused = {}, []
    for entry in feed:
        area = entry.get("serviceArea")
        if area not in ADMITTED_AREAS:
            continue
        label = AREA_LABELS.get(area, area)
        for cidr in (entry.get("ips") or []):
            try:
                bits = int(cidr.split("/")[1])
            except (IndexError, ValueError):
                continue
            floor = MIN_V6_PREFIX if ":" in cidr else MIN_V4_PREFIX
            if bits < floor:
                refused.append((area, cidr))
                continue
            out.setdefault(label, set()).add(cidr)
    return {a: sorted(v) for a, v in sorted(out.items())}, refused


def render(raw, table, refused):
    digest = hashlib.sha256(raw).hexdigest()
    parts = [HEADER % {"digest": digest, "url": FEED_URL,
                   "version": read_version()}]
    for label, cidrs in table.items():
        parts.append('    "%s": [\n' % label)
        row = []
        for c in cidrs:
            row.append('"%s",' % c)
            if len(" ".join(row)) > 58:
                parts.append("        " + " ".join(row) + "\n")
                row = []
        if row:
            parts.append("        " + " ".join(row) + "\n")
        parts.append("    ],\n")
    body = FOOTER % {"v4": MIN_V4_PREFIX, "v6": MIN_V6_PREFIX}
    if refused:
        body += ("\n# Prefixes REFUSED as wider than the floors: %s\n"
                 % ", ".join("%s (%s)" % (c, a) for a, c in refused))
    parts.append(body)
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()

    if args.refresh:
        import urllib.request
        raw = urllib.request.urlopen(FEED_URL, timeout=40).read()
        ver = urllib.request.urlopen(VERSION_URL, timeout=25).read().decode()
        with open(ARTEFACT, "wb") as fh:
            fh.write(raw)
        try:
            _v = json.loads(ver).get("latest") or ver.strip()
        except Exception:
            _v = ver.strip()
        with open(VERSION_FILE, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(str(_v) + "\n")
        print("refreshed %s (%d bytes, sha256 %s)"
              % (ARTEFACT, len(raw), hashlib.sha256(raw).hexdigest()))
        print("feed version: %s  (recorded in %s)" % (_v, VERSION_FILE))
        print("REVIEW THE DIFF. A refresh changes client-visible attribution;")
        print("it must be its own commit, never swept in with git add -A.")
        print("now run --write, then re-run the harness and the gate")
        return 0

    raw, feed = load_artefact()
    table, refused = collect(feed)
    rendered = render(raw, table, refused)
    n = sum(len(v) for v in table.values())

    if args.write:
        with open(TARGET, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)
        print("wrote %s: %d areas, %d prefixes" % (TARGET, len(table), n))
        if refused:
            print("REFUSED (wider than the floors): %s" % refused)
        return 0

    if not os.path.exists(TARGET):
        print("FAIL: %s does not exist; run --write" % TARGET)
        return 1
    with open(TARGET, encoding="utf-8") as fh:
        current = fh.read()
    if current.replace("\r\n", "\n") != rendered:
        print("FAIL: saas_ranges.py does not match the committed feed artefact.")
        print("      Either the table was hand-edited, or the artefact changed")
        print("      without regenerating. Run --write and review the diff.")
        return 1
    # STALENESS TRIPWIRE. Pinning the table is what makes a scan reproducible,
    # but a pin with no expiry is indistinguishable from an abandoned one. A
    # withdrawn Microsoft prefix keeps demoting hosts forever, and a newly
    # published one keeps being attributed to clients, in both cases silently.
    version = read_version()
    stale = None
    if version != "unrecorded" and len(version) >= 8 and version[:8].isdigit():
        import datetime
        try:
            published = datetime.date(int(version[:4]), int(version[4:6]), int(version[6:8]))
            age = (datetime.date.today() - published).days
            if age > MAX_FEED_AGE_DAYS:
                stale = age
        except ValueError:
            pass
    if stale is not None:
        print("FAIL: the pinned Microsoft feed is %d days old (version %s, "
              "limit %d)." % (stale, version, MAX_FEED_AGE_DAYS))
        print("      Run --refresh, then --write, then re-run the harness and")
        print("      the gate, and commit the artefact change on its own so the")
        print("      attribution movement is visible in review.")
        return 1

    print("OK: saas_ranges.py matches the artefact (%d areas, %d prefixes, "
          "feed version %s, sha256 %s...)"
          % (len(table), n, version, hashlib.sha256(raw).hexdigest()[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
