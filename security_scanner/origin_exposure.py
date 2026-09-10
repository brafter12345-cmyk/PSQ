# -*- coding: utf-8 -*-
"""The apex is published in DNS and bypasses the CDN the client pays for.

WHAT THIS FINDS. CloudCDNChecker resolves the APEX only, so detection answers
"is the apex fronted", not "is this organisation fronted". Where a subdomain
(almost always www) resolves into a provider edge range and the apex does NOT,
the apex is very probably the origin server: published in public DNS, reachable
directly, and outside the edge the client is paying for.

WHY IT MATTERS MORE THAN THE MISSED DETECTION. An attacker who wants the origin
normally has to hunt for it; here it is the first record in the zone. Every
control the edge provides -- DDoS absorption, WAF rules, rate limiting, bot
management -- is bypassed by connecting to the apex directly. Measured across
the 30 retained scans, 4 clients are in this state and two of them have services
listening on the exposed apex:

    aggregato.co.za    156.38.174.226   3306 (MySQL), 110, 143, 80, 53, 22
    rbs.co.za          196.40.97.156    80, 993, 4190, 2222, 110

An internet-facing MySQL on the origin of a CDN-fronted site is exactly the
exposure origin_discovery exists to find, and it was free from records the scan
already held.

WHY THE REMEDIATION TEXT MATTERS AS MUCH AS THE FINDING. Before this, the
recommendation ladder fired its `not cdn_detected` row on these clients and told
them to "Deploy a CDN for DDoS resilience". They already have one. Advice to buy
something they are already paying for is worse than silence: it is wrong, it is
checkable by the client, and it costs the report its credibility at renewal. The
correct action is to move the apex behind the edge and restrict the origin to
the provider's address ranges.

DERIVED, NOT COLLECTED. Everything here comes from fields the scan already
stores, so it replays on frozen scans and can be measured before it ships.
"""

# Ports that a public web origin is expected to answer on. Anything else on a
# directly reachable origin is a service that was never meant to face the
# internet at all, which is what separates a HIGH from a MEDIUM here.
_WEB_PORTS = {80, 443, 8080, 8443}


def _apex_ips(categories):
    return list((categories.get("cloud_cdn") or {}).get("ip_addresses") or [])


def _fronted_subdomains(categories, edge_provider):
    """provider -> the subdomains observed resolving into that provider's edge."""
    out = {}
    resolved = (categories.get("subdomains") or {}).get("resolved_ips") or {}
    for host, ips in resolved.items():
        for ip in (ips or []):
            prov = edge_provider(ip)
            if prov:
                out.setdefault(prov, set()).add(str(host))
    return {k: sorted(v) for k, v in out.items()}


def _apex_open_ports(categories, apex_ips):
    """Observed ports per apex address.

    Delegates to ip_classification.observed_ports rather than re-implementing
    the two-shape walk. This function had its own copy, and a second copy of a
    parser that must tolerate ints AND dicts is a second place for the silent
    `443 in [{"port": 443}]` failure to reappear.
    """
    from ip_classification import observed_ports
    ports = {}
    per_ip = categories.get("per_ip") or {}
    for ip in apex_ips:
        entry = per_ip.get(ip) or {}
        seen = observed_ports((entry.get("shodan_vulns") or {}).get("open_ports"),
                              (entry.get("dns_infrastructure") or {}).get("open_ports"))
        if seen:
            ports[ip] = sorted(seen)
    return ports


def assess(categories, edge_provider=None):
    """Return the origin-exposure finding, or a not-applicable result.

    ``edge_provider`` is injected so the caller controls which range table is
    consulted and so the gate can drive this with a stub.
    """
    if edge_provider is None:                    # pragma: no cover - convenience
        from cdn_ranges import edge_provider as edge_provider

    out = {"exposed": False, "reason": "", "severity": None,
           "apex_ips": [], "edge_provider": None, "fronted_subdomains": [],
           "apex_open_ports": {}, "non_web_ports": []}

    apex = _apex_ips(categories)
    if not apex:
        out["reason"] = "no apex address recorded"
        return out

    # If the apex itself is fronted there is nothing to disclose: the client is
    # behind the edge where it counts.
    apex_edge = [ip for ip in apex if edge_provider(ip)]
    if apex_edge:
        out["reason"] = "apex is itself behind the edge"
        return out

    fronted = _fronted_subdomains(categories, edge_provider)
    if not fronted:
        out["reason"] = "no edge observed anywhere on this estate"
        return out

    provider = sorted(fronted)[0]
    ports = _apex_open_ports(categories, apex)
    non_web = sorted({p for pl in ports.values() for p in pl if p not in _WEB_PORTS})

    out.update({
        "exposed": True,
        "apex_ips": sorted(apex),
        "edge_provider": provider,
        "fronted_subdomains": fronted[provider],
        "apex_open_ports": ports,
        "non_web_ports": non_web,
        # HIGH when the exposed origin answers on something other than web
        # ports: those services were never intended to face the internet, and
        # the edge was the only thing that could have been hiding them.
        "severity": "high" if non_web else "medium",
        "reason": "subdomain fronted by %s, apex resolves elsewhere" % provider,
    })
    return out


def issue_text(finding):
    """One-line issue string for the cloud_cdn category."""
    if not finding.get("exposed"):
        return ""
    prov = finding.get("edge_provider") or "a content delivery network"
    subs = finding.get("fronted_subdomains") or []
    apex = ", ".join(finding.get("apex_ips") or [])
    lead = "HIGH" if finding.get("severity") == "high" else "MEDIUM"
    body = ("%s: the apex (%s) resolves outside %s while %s sits behind it, so "
            "the apex is reachable directly and every control the edge provides "
            "is bypassed"
            % (lead, apex, prov, ", ".join(subs[:3]) or "a subdomain"))
    non_web = finding.get("non_web_ports") or []
    if non_web:
        body += (". Services listening on the exposed origin: %s"
                 % ", ".join(str(p) for p in non_web))
    return body + "."


def remediation_text(finding):
    """The action the client should actually take.

    Deliberately NOT "deploy a CDN", which is what the ladder used to say to
    exactly these clients. They have one; the apex is simply outside it.
    """
    prov = finding.get("edge_provider") or "the content delivery network"
    return ("Move the apex record behind %s and restrict the origin server to "
            "accept traffic only from the provider's published address ranges. "
            "The client already pays for this protection; the apex is currently "
            "outside it, so the edge can be bypassed by connecting to the origin "
            "directly." % prov)
