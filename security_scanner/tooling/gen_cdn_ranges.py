# -*- coding: utf-8 -*-
"""Generate cdn_feeds.py from the CDN operators that publish address lists.

WHY. cdn_ranges.py was hand-curated, and hand-curated tables rot silently.
Measured 2026-09-10 against the operators' own feeds:

    Cloudflare       22 published,  22 carried,   0 missing  (exact)
    Fastly           21 published,  15 carried,   6 missing  (26% of v4 space)
    AWS CloudFront  243 published,  19 carried, 216 missing  (66% of v4 space)

plus 3 CloudFront and 1 Fastly prefix carried that the operator NO LONGER
publishes, which is the more dangerous direction: AWS reassigns withdrawn
CloudFront space to other services, so a stale entry can demote a host that is
now somebody else's EC2 instance.

The gap is real but currently LATENT. Measured over the 30 retained scans, ZERO
would newly detect a CDN from the missing ranges, because the South African SME
estate sits on Cloudflare, which was already exact. So this ships price-neutral
and guards a case that has not arrived yet. Same shape as the Microsoft 365
attribution defect: correct today by luck, wrong the moment a client moves.

WHICH PROVIDERS ARE GENERATED. Only those publishing a stable, documented,
machine-readable list. Akamai, Imperva, Sucuri and Azure Front Door do not, so
they stay hand-curated in cdn_ranges.CDN_RANGES and are untouched here.

FOR A GENERATED PROVIDER THE FEED IS AUTHORITATIVE and replaces the curated
entries entirely, including dropping withdrawn prefixes. A curated entry that
survives beside a feed is how a withdrawn range keeps demoting hosts forever.

ARTEFACT SIZE. AWS publishes one 2.7 MB document covering every service. Pinning
it whole would put that in git on every refresh, so the artefact stores only the
CLOUDFRONT entries plus syncToken, createDate and the sha256 of the FULL payload
they were filtered from. Provenance: full feed -> recorded hash and syncToken ->
filtered artefact -> generated table.

    py tooling/gen_cdn_ranges.py --check     # shipped table matches artefacts
    py tooling/gen_cdn_ranges.py --write     # regenerate
    py tooling/gen_cdn_ranges.py --refresh   # re-fetch artefacts (network)

review-by: 2027-03-10  (provider address ranges are point-in-time)
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
FEED_DIR = os.path.join(APP, "data", "feeds")
TARGET = os.path.join(APP, "cdn_feeds.py")

# Cloudflare's endpoints return 403 to the default urllib user agent. Worth
# stating: a silent fetch failure would leave a stale table looking healthy,
# which is precisely what this generator exists to prevent.
UA = {"User-Agent": "phishield-scanner/1.0 (CDN range table refresh)"}

SOURCES = {
    "Cloudflare": {"artefact": "cloudflare_ips.json",
                   "urls": ["https://www.cloudflare.com/ips-v4",
                            "https://www.cloudflare.com/ips-v6"]},
    "Fastly": {"artefact": "fastly_public_ips.json",
               "urls": ["https://api.fastly.com/public-ip-list"]},
    "AWS CloudFront": {"artefact": "aws_cloudfront.json",
                       "urls": ["https://ip-ranges.amazonaws.com/ip-ranges.json"]},
}

# A prefix wider than this cannot be an edge allocation and is refused even if
# the operator publishes one. Same reasoning as saas_ranges: widening is the
# cheapest way to turn an attribution table into a blanket discount. Looser than
# the SaaS floors because edge allocations are genuinely large.
MIN_V4_PREFIX = 8
MIN_V6_PREFIX = 24
MAX_FEED_AGE_DAYS = 180


def _get(url):
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=UA), timeout=60).read()


def _write(name, payload):
    path = os.path.join(FEED_DIR, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    print("  wrote %-26s %d prefixes" % (name, len(payload["prefixes"])))


def refresh():
    os.makedirs(FEED_DIR, exist_ok=True)
    stamp = datetime.date.today().isoformat()

    raw4 = _get(SOURCES["Cloudflare"]["urls"][0]).decode()
    raw6 = _get(SOURCES["Cloudflare"]["urls"][1]).decode()
    _write(SOURCES["Cloudflare"]["artefact"], {
        "provider": "Cloudflare", "fetched": stamp,
        "prefixes": sorted({c.strip() for c in (raw4.split() + raw6.split()) if c.strip()}),
        "source_sha256": hashlib.sha256((raw4 + raw6).encode()).hexdigest()})

    raw = _get(SOURCES["Fastly"]["urls"][0])
    fa = json.loads(raw.decode())
    _write(SOURCES["Fastly"]["artefact"], {
        "provider": "Fastly", "fetched": stamp,
        "prefixes": sorted(set(fa.get("addresses", []) + fa.get("ipv6_addresses", []))),
        "source_sha256": hashlib.sha256(raw).hexdigest()})

    raw = _get(SOURCES["AWS CloudFront"]["urls"][0])
    aws = json.loads(raw.decode())
    pref = sorted({p["ip_prefix"] for p in aws.get("prefixes", [])
                   if p.get("service") == "CLOUDFRONT"}
                  | {p["ipv6_prefix"] for p in aws.get("ipv6_prefixes", [])
                     if p.get("service") == "CLOUDFRONT"})
    _write(SOURCES["AWS CloudFront"]["artefact"], {
        "provider": "AWS CloudFront", "fetched": stamp, "prefixes": pref,
        "sync_token": aws.get("syncToken"), "create_date": aws.get("createDate"),
        "source_sha256": hashlib.sha256(raw).hexdigest()})

    print("refreshed %d artefact(s) in %s" % (len(SOURCES), FEED_DIR))
    print("REVIEW THE DIFF. A refresh changes which hosts are attributed to a")
    print("client; it must be its own commit, never swept in with git add -A.")
    return 0


def load_all():
    out = {}
    for provider, cfg in SOURCES.items():
        path = os.path.join(FEED_DIR, cfg["artefact"])
        if not os.path.exists(path):
            raise SystemExit("missing artefact %s; run --refresh" % path)
        with open(path, encoding="utf-8") as fh:
            out[provider] = json.load(fh)
    return out


def render(feeds):
    head = [
        "# -*- coding: utf-8 -*-",
        '"""CDN edge ranges taken from the operators own published feeds.',
        "",
        "GENERATED FILE. Do not edit by hand; run tooling/gen_cdn_ranges.py.",
        "",
        "For every provider here the FEED IS AUTHORITATIVE and replaces the",
        "hand-curated entries in cdn_ranges.CDN_RANGES, including dropping",
        "prefixes the operator has withdrawn. A curated entry surviving beside a",
        "feed is how a withdrawn range keeps demoting hosts forever, and AWS",
        "reassigns retired CloudFront space to other services, so a stale entry",
        "can end up demoting an EC2 instance belonging to somebody else.",
        "",
        "Providers WITHOUT a machine-readable feed (Akamai, Imperva, Sucuri,",
        "Azure Front Door) stay hand-curated in cdn_ranges and are unaffected.",
        '"""',
        "FEED_RANGES = {",
    ]
    body, meta = [], []
    for provider in sorted(feeds):
        data = feeds[provider]
        prefixes = sorted(set(data.get("prefixes") or []))
        body.append('    "%s": [' % provider)
        row = []
        for c in prefixes:
            row.append('"%s",' % c)
            if len(" ".join(row)) > 58:
                body.append("        " + " ".join(row))
                row = []
        if row:
            body.append("        " + " ".join(row))
        body.append("    ],")
        meta.append('    "%s": {"fetched": "%s", "source_sha256": "%s", "count": %d},'
                    % (provider, data.get("fetched", "unrecorded"),
                       (data.get("source_sha256") or "")[:16], len(prefixes)))
    return "\n".join(head + body + ["}", "", "FEED_META = {"] + meta + ["}", ""]) + "\n"


def validate(feeds):
    problems = []
    for provider, data in feeds.items():
        prefixes = data.get("prefixes") or []
        if not prefixes:
            problems.append("%s: artefact carries ZERO prefixes; a feed that "
                            "returned nothing must not silently empty the table"
                            % provider)
        for c in prefixes:
            try:
                n = ipaddress.ip_network(c)
            except ValueError:
                problems.append("%s: unparseable prefix %r" % (provider, c))
                continue
            floor = MIN_V6_PREFIX if n.version == 6 else MIN_V4_PREFIX
            if n.prefixlen < floor:
                problems.append("%s: %s is wider than the /%d floor"
                                % (provider, c, floor))
        fetched = data.get("fetched")
        if fetched and fetched != "unrecorded":
            try:
                age = (datetime.date.today() - datetime.date.fromisoformat(fetched)).days
                if age > MAX_FEED_AGE_DAYS:
                    problems.append("%s: artefact is %d days old (limit %d); run --refresh"
                                    % (provider, age, MAX_FEED_AGE_DAYS))
            except ValueError:
                pass
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()

    if args.refresh:
        return refresh()

    feeds = load_all()
    problems = validate(feeds)
    rendered = render(feeds)
    total = sum(len(set(f.get("prefixes") or [])) for f in feeds.values())

    if args.write:
        with open(TARGET, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)
        print("wrote %s: %d providers, %d prefixes" % (TARGET, len(feeds), total))
        if problems:
            print("PROBLEMS: %s" % problems)
        return 1 if problems else 0

    if problems:
        print("FAIL: %d problem(s) with the pinned CDN artefacts:" % len(problems))
        for p in problems:
            print("   " + p)
        return 1
    if not os.path.exists(TARGET):
        print("FAIL: %s does not exist; run --write" % TARGET)
        return 1
    with open(TARGET, encoding="utf-8") as fh:
        current = fh.read()
    if current.replace("\r\n", "\n") != rendered:
        print("FAIL: cdn_feeds.py does not match the committed artefacts.")
        print("      Either the table was hand-edited, or an artefact changed")
        print("      without regenerating. Run --write and review the diff.")
        return 1
    print("OK: cdn_feeds.py matches the artefacts (%d providers, %d prefixes)"
          % (len(feeds), total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
