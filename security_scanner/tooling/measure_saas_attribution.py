# -*- coding: utf-8 -*-
"""Tight count: `owned` addresses with UNAMBIGUOUS evidence of vendor operation.

Two independent, conservative tests. Loose heuristics (any PTR not containing the
client's name) flagged 268 of 307 and measure nothing; these two are narrow
enough to defend one address at a time.

  A. SERVICE-ONLY PROVENANCE. Every subdomain that resolves to the address is a
     label that exists ONLY to point at a mail/collaboration platform
     (autodiscover, autoconfig, mta-sts, lyncdiscover, enterpriseregistration).
     An organisation does not run its own web or application server behind
     `autodiscover.`; that name is published to hand clients to a provider.

  B. PLATFORM ORG. Shodan's org names an operator of a mail/collaboration
     PLATFORM, on an address whose ports look like that platform rather than a
     general-purpose VM the client might run.
"""
import json, os, glob, collections

FX = os.environ["FX"]
SERVICE_ONLY = ("autodiscover", "autoconfig", "mta-sts", "lyncdiscover", "sip",
                "enterpriseregistration", "enterpriseenrollment", "msoid",
                "_domainkey", "_dmarc", "selector1", "selector2")
PLATFORM_ORG = ("microsoft", "mimecast", "zoho corp", "proofpoint", "barracuda",
                "datapro", "google llc")

a_hits, b_hits, both = [], [], []
scans = affected = owned_total = 0
per_dom = collections.Counter()

for path in sorted(glob.glob(os.path.join(FX, "*.json"))):
    if os.path.basename(path).startswith("_"):
        continue
    d = json.load(open(path, encoding="utf-8"))
    dom = d.get("domain") or os.path.basename(path)
    r = d["results"]; cats = r.get("categories", {}) or {}
    cls = r.get("ip_classification") or {}
    per_ip = cats.get("per_ip") or {}
    resolved = (cats.get("subdomains") or {}).get("resolved_ips") or {}
    ip_to_sub = collections.defaultdict(list)
    for host, ips in resolved.items():
        for ip in (ips or []):
            ip_to_sub[ip].append(host.lower())
    scans += 1
    owned = [ip for ip, b in cls.items() if b == "owned"]
    owned_total += len(owned)
    n = 0
    for ip in owned:
        subs = ip_to_sub.get(ip, [])
        org = ((per_ip.get(ip) or {}).get("shodan_vulns") or {}).get("org") or ""
        ports = ((per_ip.get(ip) or {}).get("shodan_vulns") or {}).get("open_ports") or []
        a = bool(subs) and all(any(k in s.split(".")[0] or s.startswith(k)
                                   for k in SERVICE_ONLY) for s in subs)
        b = any(k in org.lower() for k in PLATFORM_ORG)
        rec = (dom, ip, org.strip(), sorted(ports), sorted(subs)[:3])
        if a and b: both.append(rec)
        elif a:     a_hits.append(rec)
        elif b:     b_hits.append(rec)
        if a or b:
            n += 1
    if n:
        affected += 1
        per_dom[dom] = n

def show(title, rows):
    print("\n%s  (%d)" % (title, len(rows)))
    for dom, ip, org, ports, subs in rows[:200]:
        print("   %-22s %-24s %-24s %-18s %s"
              % (dom, ip, org[:23], str(ports)[:17], ",".join(subs)[:44]))

show("A+B  service-only provenance AND platform org", both)
show("A    service-only provenance, org unknown", a_hits)
show("B    platform org, other provenance", b_hits)
print("\nscans=%d  affected=%d  owned_ips=%d  unambiguous=%d"
      % (scans, affected, owned_total, len(both) + len(a_hits) + len(b_hits)))
print("per-domain:", dict(per_dom.most_common()))
