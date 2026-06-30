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

Signals, strongest first: reverse-DNS suffix (PTR is set by the IP owner), HTTP
Server banner, Shodan org/isp. Default is OWNED — a host is only re-homed to
third-party on a POSITIVE vendor signal, so the insured's own infra (including
no-PTR hosts) is never silently dropped from coverage.

review-by: 2026-12-30  (provider tables are point-in-time; re-confirm)
"""
import ipaddress

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


def classify_ip(ip, reverse_dns=None, org=None, banner=None):
    """Classify *ip* by who operates the host.

    Returns (bucket, provider_label). bucket is OWNED / PRIVATE / CDN / SAAS.
    Only OWNED is port-scanned and attributed as the insured's own exposure.
    """
    # 1. private / reserved — never scan, never attribute.
    try:
        obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return (OWNED, "")
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast:
        return (PRIVATE, "internal")

    rdns = (reverse_dns or "").strip().rstrip(".").lower()
    orgl = (org or "").strip().lower()
    bannerl = (banner or "").strip().lower()

    # 2. reverse-DNS VENDOR suffixes (CDN, then SaaS / shared hosting).
    if rdns:
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

    # 4. INSURED-operated IaaS VMs by reverse-DNS -> OWNED (scanned).
    if rdns:
        for suf in _IAAS_RDNS:
            if _suffix_match(rdns, suf):
                return (OWNED, "cloud IaaS (insured-operated)")

    # 5. Shodan org/isp: VENDOR SaaS/CDN first, then IaaS providers (OWNED).
    for kw, (bucket, label) in _VENDOR_ORG:
        if kw in orgl:
            return (bucket, label)
    if any(kw in orgl for kw in _IAAS_ORG):
        return (OWNED, "cloud IaaS (insured-operated)")

    # 5. no vendor signal -> OWNED (conservatively scanned; coverage preserved).
    return (OWNED, "")


def is_scannable(bucket):
    """Only the insured's own infrastructure is actively port-scanned."""
    return bucket == OWNED


def is_third_party(bucket):
    return bucket in THIRD_PARTY_BUCKETS
