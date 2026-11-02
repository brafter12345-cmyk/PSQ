# -*- coding: utf-8 -*-
"""How confident is the scanner that a host really belongs to the insured?

WHY THIS IS A CONFIDENCE FIELD AND NOT A FIFTH BUCKET. ip_classification sorts
every address into owned / cdn / saas / private, and only `owned` is scanned and
priced. That collapses two very different states into one: "we proved this is
theirs" (a cert-verified origin, an apex A record) and "nothing said otherwise,
so we defaulted". The module's own docstring forbids reading absence of evidence
as evidence of absence everywhere else; the default-to-owned rule does exactly
that and prints no trace of it.

A bucket cannot carry this. Both callers in scanner.py branch on the bucket: the
pre-scan pass files anything non-private non-owned into third_party_hosting with
a vendor label, and the post-scan pass gates on is_third_party(), so a fifth
verdict would either invent a vendor claim or do nothing at all. A field sits
alongside the bucket, changes no routing, and cannot regress coverage.

THE CASE THAT FORCED IT, measured on the retained scans. boston.ac.za's only
per-IP finding is a Spamhaus listing on 20.126.184.33. That address is generic
Azure space, so the published-service-range rule correctly does not touch it,
and it stays OWNED. But Shodan records two hostnames on it,
mta-certs.sendmarc.com and mta-sts-policy.d.msp.proofpoint.com, belonging to two
unrelated third parties, and the SAME address appears on takealot.com's scan.
The report therefore tells a college to investigate a spam blacklisting on a
shared mail-assurance host that is not theirs and is shared with another
insured in our own corpus. That is the over-attribution failure an external
reviewer flagged, surviving every bucket-level fix.

CO-TENANCY DOWNGRADES CONFIDENCE AND NEVER MOVES A BUCKET, deliberately. The
signal rests partly on names the host's operator publishes, and an insured who
controls their own reverse DNS could forge co-tenants. That is tolerable only
because the rule is conservative in one direction: forging co-tenant names gets
a host FLAGGED FOR REVIEW, never discounted. As a bucket-mover the same forgery
would be a free premium cut, and measured on the corpus it would have deleted
86 or more CVEs from insureds' estates on evidence no frozen scan can
adjudicate host by host.
"""
import ipaddress
import re

def registrable_domain(host):
    # Lazy import avoids estate_discovery -> related_domain_discovery ->
    # ip_attribution import cycles while keeping one canonical reducer.
    from estate_discovery import registrable
    return registrable(host)

# Confidence tiers. Orthogonal to the bucket; affects reporting only.
CONFIRMED = "confirmed"        # positive proof: cert-verified origin, apex record,
                               # or a PTR inside the insured's own zone
VENDOR = "vendor"              # positive vendor signal fired (a range, PTR, banner)
UNCONFIRMED = "unconfirmed"    # defaulted, or contradicted by co-tenancy

# PROVIDER INFRASTRUCTURE ZONES. A name under one of these tells you who the
# PROVIDER is, which is precisely the signal that cannot separate a customer's
# server from a managed one. Counting them as co-tenants is what made a naive
# version of this rule flag 27 addresses carrying 204 CVEs, including
# dedi376.cpt4.host-h.net and dedi918.jnb3.host-h.net -- literally dedicated
# servers -- and ms1.serverflex.co.za with 20 CVEs on ports 21/22/80/110/143/443.
# These exclusions are load-bearing, not decorative.
_INFRA_ZONES = (
    # hyperscaler and VPS reverse zones
    "compute.amazonaws.com", "compute-1.amazonaws.com", "amazonaws.com",
    "googleusercontent.com", "bc.googleusercontent.com",
    "cloudapp.azure.com", "cloudapp.net",
    "linodeusercontent.com", "members.linode.com",
    "your-server.de", "clients.your-server.de", "hetzner.de",
    "digitalocean.com", "vultrusercontent.com", "ovh.net", "ovh.ca",
    # South African and regional hosting / ISP reverse zones
    "host-h.net", "aserv.co.za", "cphost.co.za", "serverflex.co.za",
    "vpslocal.co.za", "xneelo.co.za", "jnb1.host-h.net",
    "telkomsa.net", "vox.co.za", "afrihost.co.za", "imaginet.co.za",
    "mweb.co.za", "rsaweb.co.za", "datapro.co.za", "cybersmart.co.za",
    "internetsolutions.co.za", "is.co.za", "liquidtelecom.net",
)


def _under(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def _is_infra_zone(host):
    return any(_under(host, z) for z in _INFRA_ZONES)


def _is_address_derived(host, ip):
    """True when the hostname is just the address rewritten.

    A PTR like 223.68.190.35.bc.googleusercontent.com or
    ec2-3-92-120-28.compute-1.amazonaws.com names nobody: it is the address with
    separators swapped. Treating those as tenant identities would make every
    cloud host look multi-tenant.
    """
    try:
        octets = str(ipaddress.ip_address(ip)).split(".")
    except ValueError:
        return False
    if len(octets) != 4:
        return False
    digits = re.findall(r"\d+", host or "")
    for run in (octets, list(reversed(octets))):
        for start in range(0, 2):
            window = run[start:start + 3]
            if len(window) == 3 and _contains_run(digits, window):
                return True
    return False


def _contains_run(digits, window):
    n = len(window)
    for i in range(len(digits) - n + 1):
        if digits[i:i + n] == window:
            return True
    return False


def co_tenant_domains(ip, hostnames=None, reverse_dns=None, insured_domain=None):
    """Distinct FOREIGN registrable domains observed on one address.

    Two or more means the address serves organisations other than the insured,
    which is false of a dedicated host by construction. Returns a sorted list;
    fewer than two entries is not a co-tenancy signal.
    """
    insured_apex = registrable_domain(insured_domain or "")
    names = list(hostnames or [])
    if reverse_dns:
        names.append(reverse_dns)

    found = set()
    for raw in names:
        host = (str(raw) or "").strip().rstrip(".").lower()
        if not host or "." not in host:
            continue
        if _is_infra_zone(host):
            continue                      # names the provider, not a tenant
        if _is_address_derived(host, ip):
            continue                      # the address rewritten, not a name
        apex = registrable_domain(host)
        if not apex or apex == insured_apex:
            continue                      # the insured's own name is expected
        found.add(apex)
    return sorted(found)


def attribution_for(ip, bucket, label, *, ip_sources=None, hostnames=None,
                    reverse_dns=None, insured_domain=None, apex_ips=None):
    """(confidence, rule, evidence) for one classified address.

    Never changes the bucket. The caller records this beside the classification
    so a reader can tell a proven attribution from a defaulted one.
    """
    sources = list(ip_sources or [])
    if bucket in ("cdn", "saas"):
        return VENDOR, "vendor_signal", label or ""
    if bucket == "private":
        return CONFIRMED, "rfc1918", "private address space"

    # CONTRADICTION FIRST. Two unrelated organisations answering on one address
    # contradicts "the insured operates this host" no matter what the insured
    # published, so it has to be tested BEFORE the positive proofs rather than
    # after them.
    #
    # Ordering this the other way round was a real defect, caught on the corpus.
    # mcare.co.za's 156.38.230.15 is dedi918.jnb3.host-h.net, a shared cPanel
    # box that also serves crestchoicechickens.com and ffg.co.za, neither of
    # which is mcare. Because that address is also mcare's apex A record, the
    # apex rule fired first and returned "confirmed", silencing the warning on
    # precisely the case it exists for. An SME on shared hosting ALWAYS points
    # its apex at the provider's box: publishing an A record proves the client
    # USES the host, never that it OPERATES it. Same for a PTR the provider set.
    tenants = co_tenant_domains(ip, hostnames=hostnames, reverse_dns=reverse_dns,
                                insured_domain=insured_domain)
    if len(tenants) >= 2:
        return (UNCONFIRMED, "co_tenancy",
                "shared with unrelated organisations: " + ", ".join(tenants))

    # Positive proof the host is the insured's. A cert-verified origin stays
    # strongest; see OUTSTANDING for its own known weakness (a multi-tenant
    # platform serving the client's certificate under SNI also passes).
    if "verified_origin" in sources:
        return CONFIRMED, "cert_verified_origin", "serves the insured's certificate"
    if apex_ips and ip in set(apex_ips):
        return CONFIRMED, "apex_record", "published as an A/AAAA record for the apex"
    rd = (reverse_dns or "").strip().rstrip(".").lower()
    insured_apex = registrable_domain(insured_domain or "")
    if rd and insured_apex and _under(rd, insured_apex):
        return CONFIRMED, "ptr_in_insured_zone", rd

    return UNCONFIRMED, "defaulted", "no vendor signal and no ownership proof"
