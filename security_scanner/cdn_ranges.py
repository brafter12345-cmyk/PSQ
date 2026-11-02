# -*- coding: utf-8 -*-
"""Published content-delivery-network edge address ranges.

WHY THIS EXISTS. CloudCDNChecker identified a network only by walking the CNAME
chain against a list of provider suffixes. A domain fronted at its apex cannot
carry a CNAME, so providers answer with address records directly (Cloudflare
calls this CNAME flattening). The chain walk therefore finds nothing, the edge
addresses are treated as the client's own infrastructure, and the client is
scored on a provider's security posture rather than on its own. Measured across
58 production scans: a provider was named 0 times, and 14 scans resolved to an
edge range the checker did not recognise.

TWO CALLERS, OPPOSITE PURPOSES, WHICH IS WHY THIS IS SHARED:

  * CloudCDNChecker asks "is this an edge?" to detect the network.
  * The lookalike checker asks the same question to REFUSE an ownership
    inference. Two domains sharing a Cloudflare edge address share it with
    millions of others, so an address match on an edge range proves nothing
    about common control and must never be read as "this domain is ours".

Ranges are the published, long-lived allocations. They are deliberately a static
table rather than a live fetch: a scan must be reproducible, and a checker that
silently changes behaviour when a provider updates a JSON feed cannot be
regression-tested. Entries are conservative; an unlisted range simply means the
edge is not recognised, which fails toward the pre-existing behaviour.
"""
import ipaddress

# Provider -> CIDR blocks. IPv4 and IPv6 both carried: a domain can resolve to
# either, and the ownership test must refuse an inference on both.
CDN_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18",
        "167.82.0.0/17", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16", "2a04:4e40::/32", "2a04:4e42::/32",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "18.64.0.0/14",
        "52.46.0.0/18", "52.84.0.0/15", "52.124.128.0/17",
        "52.222.128.0/17", "54.182.0.0/16", "54.192.0.0/16",
        "54.230.0.0/16", "54.239.128.0/18", "64.252.64.0/18",
        "65.8.0.0/16", "65.9.0.0/16", "99.84.0.0/16", "99.86.0.0/16",
        "205.251.192.0/19", "216.137.32.0/19",
    ],
    "Akamai": [
        "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "2.16.0.0/13",
        "95.100.0.0/15", "96.16.0.0/15", "104.64.0.0/10", "184.24.0.0/13",
        "184.50.0.0/15", "184.84.0.0/14", "72.246.0.0/15", "88.221.0.0/16",
    ],
    "Azure Front Door": [
        "13.107.42.0/23", "13.107.213.0/24", "13.107.246.0/24",
        "150.171.22.0/24", "150.171.23.0/24", "2620:1ec:bdf::/48",
    ],
    "Imperva": ["199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
                "103.28.248.0/22", "45.64.64.0/22", "185.11.124.0/22"],
    "Sucuri": ["192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22"],
}

# --- Feed-backed providers OVERRIDE the curated table above ------------------
#
# The curated entries were hand-typed and had rotted. Measured 2026-09-10
# against the operators' own published lists: Cloudflare was exact (22 of 22),
# Fastly was missing 6 of 21 prefixes (26% of its v4 space), and AWS CloudFront
# was missing 216 of 243 (66% of its v4 space). Three CloudFront prefixes and
# one Fastly prefix were carried that the operator NO LONGER publishes, which is
# the worse direction: AWS reassigns retired CloudFront space to other services,
# so a stale entry can end up demoting an EC2 instance belonging to someone else.
#
# REPLACE rather than merge, for exactly that reason. A curated entry surviving
# beside a feed is how a withdrawn range keeps demoting hosts forever.
#
# Providers with no machine-readable feed (Akamai, Imperva, Sucuri, Azure Front
# Door) keep their curated entries untouched.
#
# MEASURED EFFECT on the 30 retained scans: ZERO scans newly detect a CDN, so
# this ships price-neutral. The South African SME estate sits on Cloudflare,
# which was already exact, so the gap was latent rather than active. It would
# have become active the moment a client moved to CloudFront or Fastly: an
# unrecognised edge is both scanned as the client's own AND charged the +0.035
# no-CDN availability penalty, wrong in both directions at once.
#
# Imported directly. A silent fallback would turn a broken generated table into
# a silent regression, restoring exactly the rot this replaced.
from cdn_feeds import FEED_RANGES as _FEED_RANGES

_NETS = []
for _prov, _cidrs in CDN_RANGES.items():
    if _prov in _FEED_RANGES:
        continue                      # the operator's own feed is authoritative
    for _c in _cidrs:
        _NETS.append((_prov, ipaddress.ip_network(_c)))
for _prov, _cidrs in _FEED_RANGES.items():
    for _c in _cidrs:
        _NETS.append((_prov, ipaddress.ip_network(_c)))


def edge_provider(ip: str) -> "str | None":
    """Name the CDN whose edge range contains ``ip``, else None.

    Never raises: a malformed or private address simply is not an edge.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    for prov, net in _NETS:
        if addr.version == net.version and addr in net:
            return prov
    return None


def is_edge_ip(ip: str) -> bool:
    """True when the address belongs to a shared CDN edge.

    The ownership test in the lookalike checker uses this as a VETO: an address
    shared by every tenant of a CDN cannot establish that two domains belong to
    the same organisation.
    """
    return edge_provider(ip) is not None


def providers_for(ips) -> list:
    """Distinct providers seen across a set of addresses, order-stable."""
    out = []
    for ip in (ips or []):
        p = edge_provider(ip)
        if p and p not in out:
            out.append(p)
    return out
