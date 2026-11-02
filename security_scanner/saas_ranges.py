# -*- coding: utf-8 -*-
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
FEED_SHA256 = "93e78c0533f7aaac9606ee196aff638eb241efc5fb9a0866ee7ff0174c8dbad6"
FEED_VERSION = "2026090800"
FEED_URL = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"

SERVICE_RANGES = {
    "Microsoft 365 (Exchange Online)": [
        "104.47.0.0/17", "13.104.0.0/14", "13.107.128.0/22", "13.107.18.10/31",
        "13.107.6.152/31", "131.253.33.215/32", "132.245.0.0/16", "150.171.32.0/22",
        "204.79.197.215/32", "23.103.160.0/20", "2603:1006::/40", "2603:1016::/36",
        "2603:1026::/36", "2603:1036::/36", "2603:1046::/36", "2603:1056::/36",
        "2620:1ec:4::152/128", "2620:1ec:4::153/128", "2620:1ec:8f0::/46",
        "2620:1ec:900::/46", "2620:1ec:a92::152/128", "2620:1ec:a92::153/128",
        "2620:1ec:c::10/128", "2620:1ec:c::11/128", "2620:1ec:d::10/128",
        "2620:1ec:d::11/128", "2a01:111:f400::/48", "2a01:111:f403::/48",
        "40.104.0.0/15", "40.107.0.0/16", "40.92.0.0/15", "40.96.0.0/13",
        "52.100.0.0/14", "52.238.78.88/32", "52.96.0.0/14",
    ],
    "Microsoft 365 (SharePoint Online)": [
        "104.146.128.0/17", "13.107.136.0/22", "150.171.40.0/22", "2603:1061:1300::/40",
        "2603:1063:6000::/35", "2620:1ec:8f8::/46", "2620:1ec:908::/46",
        "2a01:111:f402::/48", "40.108.128.0/17", "52.104.0.0/14",
    ],
    "Microsoft 365 (Teams)": [
        "2603:1027::/48", "2603:1037::/48", "2603:1047::/48", "2603:1057::/48",
        "2603:1063::/38", "2620:1ec:40::/42", "2620:1ec:6::/48", "52.112.0.0/14",
        "52.122.0.0/15",
    ],
    "Microsoft 365 (common services)": [
        "13.107.140.6/32", "13.107.18.15/32", "13.107.6.171/32", "13.107.6.192/32",
        "13.107.9.192/32", "20.190.128.0/18", "20.20.32.0/19", "20.231.128.0/19",
        "2603:1006:1400::/40", "2603:1006:2000::/48", "2603:1007:200::/48",
        "2603:1016:1400::/48", "2603:1016:2400::/40", "2603:1017::/48",
        "2603:1026:2400::/40", "2603:1026:3000::/48", "2603:1027:1::/48",
        "2603:1036:2400::/40", "2603:1036:3000::/48", "2603:1037:1::/48",
        "2603:1046:1400::/40", "2603:1046:2000::/48", "2603:1047:1::/48",
        "2603:1056:1400::/40", "2603:1056:2000::/48", "2603:1057:2::/48",
        "2603:1063:2000::/38", "2620:1ec:4::192/128", "2620:1ec:8fc::6/128",
        "2620:1ec:a92::171/128", "2620:1ec:a92::192/128", "2620:1ec:c::15/128",
        "2a01:111:f100:2000::a83e:3019/128", "2a01:111:f100:2002::8975:2d79/128",
        "2a01:111:f100:2002::8975:2da8/128", "2a01:111:f100:7000::6fdd:6cd5/128",
        "2a01:111:f100:a004::bfeb:88cf/128", "40.126.0.0/18", "52.108.0.0/14",
        "52.244.37.168/32",
    ],
}

# Prefix floors the generator enforced, re-asserted at import so that a hand-edit
# which widens a prefix fails loudly instead of quietly capturing customer hosts.
MIN_V4_PREFIX = 12
MIN_V6_PREFIX = 32

_NETS = []
for _label, _cidrs in SERVICE_RANGES.items():
    for _c in _cidrs:
        _n = ipaddress.ip_network(_c)
        _floor = MIN_V6_PREFIX if _n.version == 6 else MIN_V4_PREFIX
        if _n.prefixlen < _floor:
            raise ValueError(
                "saas_ranges: %s is wider than the /%d floor" % (_c, _floor))
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
