# -*- coding: utf-8 -*-
"""Classify a discovered IP by WHO OPERATES THE HOST, so the scanner attributes
exposures to the right party.

WHY THIS EXISTS (checker audit, 2026-06-30 — real takealot.com scan):
    IPs reach the port/protocol/CVE checkers from four sources (apex A-records,
    broker client_ips, subdomain-resolved IPs, origin candidates). Only the
    ORIGIN source was ever classified (cert-match in origin_discovery). The
    subdomain-IP expansion (939cfe4, 2026-03-31) and the apex A-records went in
    RAW. When subdomain discovery widened (8d2663b, 2026-06-02), 41 third-party
    IPs got port-scanned and attributed to takealot as its OWN exposure —
    including a HostRocket shared host (FTP + "exposed Jupyter Notebook") behind
    success-network.takealot.com, plus RFC1918 internal hosts leaked in DNS.

POLICY (broker-confirmed 2026-06-30): attribute on WHO OPERATES THE HOST.
    - INSURED-OPERATED -> OWNED, scanned + attributed as the insured's exposure:
      dedicated IPs, cert-verified origins, and IaaS VMs the insured runs
      (AWS EC2, GCE, Azure VM). An exposed Jenkins/DB/admin on the insured's own
      cloud VM IS their risk — exactly what an external scan must catch.
    - VENDOR-OPERATED -> THIRD-PARTY, surfaced under supply-chain, NOT scanned:
      CDN edges (CloudFront/Akamai/Cloudflare/Fastly), managed SaaS
      (Zendesk/WP Engine/Salesforce), shared hosting (HostRocket), managed load
      balancers (AWS ELB). The provider patches the host; its exposure is the
      provider's risk and a supply-chain dependency for the insured.
    - PRIVATE (RFC1918) -> never scanned; an info-disclosure finding (public DNS
      exposing internal infrastructure).

Signals, strongest first: provider-published first-party SERVICE address ranges
(saas_ranges.py), reverse-DNS suffix (PTR is set by the IP owner), HTTP Server
banner, Shodan org/isp. Default is OWNED — a host is only re-homed to
third-party on a POSITIVE vendor signal, so the insured's own infra (including
no-PTR hosts) is never silently dropped from coverage.

WHAT THE ORG SIGNAL CANNOT DO (2026-09-09). Shodan's org names who holds the
ALLOCATION, and the hyperscalers that dominate it sell the managed service and
the customer VM out of one name. "Microsoft Corporation" is returned by both an
Exchange Online front end and an Azure VM the client runs, so org can never
separate them and must never decide this on its own. It previously did, in the
insured's disfavour, returning the positive claim "cloud IaaS
(insured-operated)". Measured on 30 retained scans, acting on org alone would
have demoted 37 addresses including our own GCE host behind veilguard.phishield.
com and client-run Azure hosts behind portal.nexgro.co.za and ifrs9.bdo.co.za —
deleting real exposure. The provider's own published split of its address space
is the same fact at a resolution that does separate them, which is why step 1b
exists and why steps 4 and 5 now assert nothing.

review-by: 2026-12-30  (provider tables are point-in-time; re-confirm)
"""
import ipaddress

# Imported directly, not behind a try/except. A silent fallback here would turn
# a broken import into a silent regression: every Exchange Online endpoint would
# quietly go back to being attributed to the insured, and the gate's own
# rule-off mutation would become indistinguishable from an accident.
from saas_ranges import service_provider as _service_provider

# Buckets. OWNED is the only scannable / own-attributed bucket.
OWNED = "owned"
PRIVATE = "private"
CDN = "cdn"      # vendor-operated edge / managed LB
SAAS = "saas"    # vendor-operated SaaS / shared hosting
THIRD_PARTY_BUCKETS = (CDN, SAAS)

# --- VENDOR-operated reverse-DNS suffixes -> (bucket, label). Checked first. ---
_CDN_RDNS = {
    "cloudfront.net": "Amazon CloudFront",
    "akamaitechnologies.com": "Akamai", "akamai.net": "Akamai",
    "akamaized.net": "Akamai", "akamaihd.net": "Akamai",
    "edgekey.net": "Akamai", "edgesuite.net": "Akamai",
    "fastly.net": "Fastly",
}
_SAAS_RDNS = {
    "exacttarget.com": "Salesforce Marketing Cloud",
    "zendesk.com": "Zendesk",
    "wpengine.com": "WP Engine",
    "directorysecure.com": "HostRocket (shared host)",
    "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "vercel.app": "Vercel", "netlify.app": "Netlify",
    "myshopify.com": "Shopify", "github.io": "GitHub Pages",
    "squarespace.com": "Squarespace", "wixsite.com": "Wix",
}

# --- INSURED-operated IaaS reverse-DNS markers -> OWNED (scanned). Checked AFTER
# the vendor suffixes so a CloudFront/ELB host on AWS is never mistaken for the
# insured's own EC2 instance. ---
_IAAS_RDNS = (
    "compute.amazonaws.com", "compute-1.amazonaws.com",   # AWS EC2
    "googleusercontent.com",                              # GCE
    "cloudapp.azure.com",                                 # Azure VM
)

# --- HTTP Server banner -> vendor-operated (managed edge / LB). ---
_VENDOR_BANNER = (
    ("cloudflare", (CDN, "Cloudflare")),
    ("cloudfront", (CDN, "Amazon CloudFront")),
    ("akamaighost", (CDN, "Akamai")),
    ("awselb", (CDN, "AWS ELB (managed LB)")),
)

# --- Shodan org/isp substring -> (bucket, label) for VENDOR-operated only. ---
_VENDOR_ORG = (
    ("cloudflare", (CDN, "Cloudflare")),
    ("akamai", (CDN, "Akamai")),
    ("fastly", (CDN, "Fastly")),
    ("zendesk", (SAAS, "Zendesk")),
    ("wpengine", (SAAS, "WP Engine")),
    ("wp engine", (SAAS, "WP Engine")),
    ("salesforce", (SAAS, "Salesforce")),
    ("exacttarget", (SAAS, "Salesforce Marketing Cloud")),
    ("hostrocket", (SAAS, "HostRocket (shared host)")),
    ("shopify", (SAAS, "Shopify")),
)

# --- Shodan org substrings for IaaS providers -> OWNED (insured runs the VM). ---
_IAAS_ORG = ("amazon", "google", "microsoft", "azure", "digitalocean",
             "linode", "hetzner", "ovh", "vultr")


def _suffix_match(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def classify_ip(ip, reverse_dns=None, org=None, banner=None,
                default_cert_names=None, insured_domain=None,
                ptr_confirmed=None):
    """Classify *ip* by who operates the host.

    Returns (bucket, provider_label). bucket is OWNED / PRIVATE / CDN / SAAS.
    Only OWNED is port-scanned and attributed as the insured's own exposure.

    ``ptr_confirmed`` says whether the reverse-DNS name resolves FORWARD back to
    this address. A vendor reverse-DNS suffix may demote a host only when it is
    True. Pass None (the default) when the check was not performed or could not
    complete, and the reverse name will not be used to demote anything.

    WHY. A reverse-DNS record is written by whoever holds the address, and many
    providers let a customer set it. An insured wanting a cheaper premium could
    put `something.wpengine.com` on their own exposed box and have it drop out
    of the priced estate. Forward confirmation closes that: a customer who can
    write the reverse record almost never also controls what `wpengine.com`
    resolves to.

    A MISSING CONFIRMATION MUST NEVER DEMOTE, which is why None and False behave
    alike here. If a DNS timeout demoted a host, the timeout would become a
    discount, and ptr_map in scanner.py already drops addresses silently on
    FuturesTimeoutError. Measured on the 30 retained scans, ZERO addresses were
    demoted by a reverse name alone: every one was also carried by Shodan org, a
    server banner, or a published address range. So this closes a gaming vector
    at no cost to current coverage.
    """
    # 1. private / reserved — never scan, never attribute.
    try:
        obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return (OWNED, "")
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast:
        return (PRIVATE, "internal")

    # 1b. PROVIDER-PUBLISHED FIRST-PARTY SERVICE RANGES (2026-09-09).
    #     Measured across 30 retained scans: 174 of 307 addresses classified as
    #     the insured's own were Microsoft 365 service endpoints, reached because
    #     subdomain enumeration resolves autodiscover / mail / mta-sts names and
    #     nothing below could tell them from the client's own infrastructure.
    #
    #     THIS MUST RUN BEFORE EVERY OTHER SIGNAL, and specifically before the
    #     org rule at step 5. Exchange Online and a customer-run Azure VM both
    #     report org "Microsoft Corporation", so _IAAS_ORG short-circuits to
    #     OWNED and ANY rule placed after it is dead code for exactly the hosts
    #     this fixes. It also needs no argument beyond the address, which is why
    #     it is the only new rule that can fire at the pre-scan call site, where
    #     the caller has resolved nothing but PTR.
    #
    #     Address membership is the only signal in this whole chain that the
    #     party being judged cannot author: a customer cannot arrange for their
    #     VM to be allocated out of the Exchange Online service block. It is also
    #     the only one that works on IPv6 and when PTR and Shodan org are both
    #     absent, which is the state of most affected addresses.
    _service = _service_provider(ip)
    if _service:
        return (SAAS, _service)

    rdns = (reverse_dns or "").strip().rstrip(".").lower()
    orgl = (org or "").strip().lower()
    bannerl = (banner or "").strip().lower()

    # 2. reverse-DNS VENDOR suffixes (CDN, then SaaS / shared hosting).
    #    GATED ON FORWARD CONFIRMATION: the address holder writes this string,
    #    so on its own it is an assertion by the party being judged. Absent or
    #    failed confirmation leaves the host where it was rather than demoting
    #    it, so a DNS timeout can never become a discount.
    if rdns and ptr_confirmed is True:
        for suf, label in _CDN_RDNS.items():
            if _suffix_match(rdns, suf):
                return (CDN, label)
        for suf, label in _SAAS_RDNS.items():
            if _suffix_match(rdns, suf):
                return (SAAS, label)

    # 3. HTTP Server banner — managed edge / LB. Checked BEFORE the IaaS
    #    reverse-DNS rule so a managed AWS ELB (banner 'awselb', but an
    #    ec2-*.compute.amazonaws.com PTR) is not mistaken for an insured EC2 VM.
    for kw, (bucket, label) in _VENDOR_BANNER:
        if kw in bannerl:
            return (bucket, label)

    # 3b. SHARED / MANAGED HOSTING, by the box's DEFAULT certificate.
    #     Must run BEFORE the IaaS rules: providers like Hetzner sell both
    #     customer-operated servers AND managed hosting under the same rDNS and
    #     the same org string, so those rules would otherwise claim it as the
    #     insured's own. Only fires on a POSITIVE reading; unknown falls through.
    if looks_multi_tenant(default_cert_names, insured_domain) is True:
        _sample = sorted(default_cert_names)[0] if default_cert_names else "?"
        return (SAAS, "shared/managed hosting (default cert %s)" % _sample)

    # 4. Address sits in a cloud provider's space by reverse-DNS -> OWNED, i.e.
    #    still scanned, but WITHOUT claiming the insured operates it. The old
    #    label here read "cloud IaaS (insured-operated)", which is a positive
    #    assertion the signal cannot support: a provider-authored PTR suffix says
    #    who the PROVIDER is, never who runs the workload. That false claim is
    #    what a broker read next to a college's name beside an Exchange Online
    #    endpoint. The bucket is deliberately unchanged, so coverage is identical
    #    and nothing moves between scanned and unscanned.
    if rdns:
        for suf in _IAAS_RDNS:
            if _suffix_match(rdns, suf):
                return (OWNED, "cloud IaaS (operator unconfirmed)")

    # 5. Shodan org/isp: VENDOR SaaS/CDN first, then IaaS providers (OWNED).
    for kw, (bucket, label) in _VENDOR_ORG:
        if kw in orgl:
            return (bucket, label)
    # Same de-assertion as step 4, and for a stronger reason: a netblock
    # registrant string is the WEAKEST possible evidence of who operates a host,
    # because the hyperscalers that dominate it sell the managed service and the
    # customer VM out of the same name. Kept as a branch rather than deleted so
    # the org signal stays visible in the ledger; the bucket it yields is now
    # identical to the default two lines below, which is what makes this inert.
    if any(kw in orgl for kw in _IAAS_ORG):
        return (OWNED, "cloud provider netblock (operator unconfirmed)")

    # 5. no vendor signal -> OWNED (conservatively scanned; coverage preserved).
    return (OWNED, "")


def is_scannable(bucket):
    """Only the insured's own infrastructure is actively port-scanned."""
    return bucket == OWNED


def is_third_party(bucket):
    return bucket in THIRD_PARTY_BUCKETS


# --- shared / managed hosting detection -----------------------------------
#
# THE PROBLEM THIS SOLVES (phishield.com, 2026-08-18). 213.133.105.171 serves
# phishield.com and exposes MySQL 3306 + PostgreSQL 5432 to the internet. It was
# attributed to the insured as OWNED, "cloud IaaS (insured-operated)", so the
# report told a broker the client had an internet-facing database and advised
# closing a port the client cannot reach. It is a Hetzner MANAGED SHARED box and
# the client is one tenant on it.
#
# Reverse DNS cannot separate the two: Hetzner sells both customer-operated
# servers and managed hosting, and both live under your-server.de. A provider
# name list cannot either -- it is point-in-time and every provider is different.
#
# THE SIGNAL THAT ACTUALLY SEPARATES THEM is the certificate the box serves when
# you connect with NO SNI. That is the platform's own identity:
#   * a single-tenant server you operate presents YOUR certificate either way;
#   * a multi-tenant platform presents the PROVIDER's default (here
#     CN=*.your-server.de) and only serves your cert once SNI names you.
# Only the platform operator controls the default vhost, so it is hard to spoof,
# it needs no API or subscription, and it generalises to every shared host
# instead of the ones we happened to list.
def _cert_covers(names, domain):
    """Does a certificate name set cover *domain* (wildcards honoured)?"""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return False
    for n in names or ():
        n = (n or "").strip().lower().rstrip(".")
        if not n:
            continue
        if n == d:
            return True
        if n.startswith("*."):
            # RFC 6125: one label only. *.a.com covers x.a.com, not y.x.a.com.
            base = n[2:]
            if d.endswith("." + base) and d.count(".") == base.count(".") + 1:
                return True
    return False


def probe_default_cert(ip, timeout=5.0, port=443):
    """Certificate names the host serves with NO SNI, or None if unavailable.

    Returns a set of lowercase names (CN + subjectAltName DNS entries). None
    means "could not tell" -- the caller must then fall back to the existing
    behaviour rather than guessing, because absence of evidence is not evidence
    of single tenancy.
    """
    import socket, ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False              # we WANT the default vhost's cert
    ctx.verify_mode = _ssl.CERT_NONE        # self-signed defaults are still evidence
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ss:   # deliberately no server_hostname
                der = ss.getpeercert(binary_form=True)
        if not der:
            return None
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            cert = x509.load_der_x509_certificate(der)
            names = set()
            for a in cert.subject:
                if a.oid._name in ("commonName", "common_name"):
                    names.add(str(a.value).lower())
            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                names.update(n.lower() for n in san.get_values_for_type(x509.DNSName))
            except Exception:
                pass
            return names or None
        except ImportError:
            # No cryptography: fall back to the stdlib decoded form, which needs
            # a verifying context. Better to report "unknown" than to guess.
            return None
    except Exception:
        return None


# Names that identify NOBODY. A default vhost certificate often carries the
# box's own hostname, an appliance serial, or a control-panel placeholder. None
# of these is evidence that somebody ELSE is on the host, and treating them as
# such is what produced the demotions listed in the docstring below.
_IDENTITY_FREE_EXACT = {
    "localhost", "localhost.localdomain", "plesk", "cpanel", "webmail",
    "mail", "server", "ubuntu", "debian", "default", "example.com",
}
_IDENTITY_FREE_SUFFIX = (".local", ".lan", ".internal", ".localdomain",
                         ".invalid", ".test", ".home", ".corp")


def _identity_free_cert_name(name):
    """True when a certificate name names nobody in particular."""
    import re as _re
    n = (name or "").strip().lower().rstrip(".").lstrip("*.")
    if not n:
        return True
    if n in _IDENTITY_FREE_EXACT:
        return True
    if any(n.endswith(sfx) for sfx in _IDENTITY_FREE_SUFFIX):
        return True
    if "." not in n:
        # A bare label: a hostname, or an appliance serial such as the
        # FortiGate "fg10e0tb20902714" that demoted a client's VPN endpoint.
        return True
    try:
        ipaddress.ip_address(n)
        return True                      # an address literal, not an identity
    except ValueError:
        pass
    return False


def _registrable(host):
    """Crude registrable domain: last two labels, or three under a known
    multi-part suffix. Deliberately local so this module stays importable
    without the discovery stack."""
    h = (host or "").strip().lower().rstrip(".").lstrip("*.")
    parts = [x for x in h.split(".") if x]
    if len(parts) < 2:
        return h
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac",
                                         "gov", "web", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def looks_multi_tenant(default_cert_names, insured_domain):
    """True only on POSITIVE evidence that the default vhost belongs to someone
    else. False when it belongs to the insured. None when it names nobody.

    THIS WAS AN ABSENCE TEST AND THE ABSENCE TEST WAS WRONG. It read
    ``not _cert_covers(names, insured_domain)`` -- i.e. "the certificate does
    not name the apex, therefore somebody else is on this box". A default vhost
    routinely serves the box's OWN hostname rather than the apex, so the test
    fired on the insured's own infrastructure. Measured on the 30 retained
    scans, 3 of the 36 default-certificate demotions were wrong, and the three
    are the worst possible ones to lose:

        bbgroup.co.za  41.161.81.118   default cert ess.bbgroup.co.za
                                       also serves autohubpol. and remote.
        bbgroup.co.za  102.211.159.114 default cert autohubpta.bbgroup.co.za
        dubetradeport  41.78.234.1     default cert fg10e0tb20902714,
                                       a FortiGate serial; serves vpn.

    All three are the insured's own hosts. All three were deleted from
    per_ip_results and never port-scanned, so their remote-access and VPN
    surfaces were removed from the priced estate entirely. A demotion removes
    findings, which is the discount direction, and remediation step 1 forbids
    the absence of findings from discounting anything.

    THE THREE-WAY VERDICT:
      False -- a name on the certificate shares the insured's registrable
               domain, so this is the client's own box.
      None  -- every name identifies nobody (a bare hostname, an appliance
               serial, a control-panel placeholder, an address literal). Probed
               but unreadable; the caller keeps its existing behaviour.
      True  -- a name identifies a DIFFERENT organisation. Only this demotes.
    """
    if not default_cert_names or not insured_domain:
        return None

    # (a) The insured's own identity on the certificate, by apex or by wildcard.
    if _cert_covers(default_cert_names, insured_domain):
        return False
    insured_apex = _registrable(insured_domain)
    for n in default_cert_names:
        if insured_apex and _registrable(n) == insured_apex:
            return False

    # (b) Nothing on it identifies anyone. Never demote on a non-identity.
    if all(_identity_free_cert_name(n) for n in default_cert_names):
        return None

    # (c) A different organisation's identity. This is the only demoting case.
    return True


def forward_confirms(reverse_name, ip, timeout=3.0):
    """Does *reverse_name* resolve forward to *ip*?

    True only on a positive match. False on a definite non-match. None when the
    lookup could not be completed, so the caller can tell "not this host" from
    "we could not tell" and refuse to demote on the latter.
    """
    name = (reverse_name or "").strip().rstrip(".")
    if not name or not ip:
        return None
    import socket
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None)
    except Exception:
        return None
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass
    addrs = {i[4][0] for i in infos if i and i[4]}
    return str(ip).strip() in addrs
