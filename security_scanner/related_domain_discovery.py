"""Related-domain auto-discovery for S-1 v1.1.

Surfaces candidate sibling / supplier / group-related domains during
pre-flight, so the broker can confirm or reject each candidate before
the scan runs. Mirrors the architectural precedent set by
flag_inference.py — auto-detect, hand to broker via pre-flight,
broker confirms via the existing form UX.

v1.1 SCOPE — broker-confirmed cert-SAN discovery only:
    The highest-signal free method per project memory
    project_related_domain_discovery.md. crt.sh exposes a public JSON
    API listing every Certificate Transparency log entry for a search
    term; SAN (subject_alt_names) entries on the same cert imply common
    ownership at the time of issuance.

DEFERRED to v1.2+ (sketched in the project memory):
    - WHOIS registrant match via zaCentral (.co.za) + RDAP (.com)
    - Google Analytics / GTM ID correlation via Shodan corpus search
    - Favicon hash search via Shodan
    - Email-sender domain mining via Dehashed / HIBP
    - CIPC / JSE registry scrape
    - DNS shared-infrastructure clustering (same NS / MX / /24 CIDR)

Output contract:
    discover_related_domains(primary_domain) returns
        list[{
            "domain": str,           # candidate sibling domain (apex)
            "signal": str,           # one of "cert_san_subject_o",
                                     # "cert_san_wildcard", etc.
            "signal_detail": str,    # human-readable evidence
            "confidence": str,       # "high" | "medium" | "low"
            "source_url": str,       # citable URL for FAIS audit
        }]
    Capped at MAX_CANDIDATES to keep the pre-flight UI manageable. The
    broker confirms each candidate; only confirmed candidates flow
    through to the actual LITE-mode scan in S-1 v1.0 wiring.
"""

import re
import socket
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# WS0: route crt.sh through the per-provider seam. CRTSH adds no retry of its own
# (max_attempts=1), so the hand-rolled retry loop below keeps its exact semantics.
# CRTSH.get returns None on a failed request instead of raising.
from providers import CRTSH


CRT_SH_URL = "https://crt.sh/"
# crt.sh's hosted Postgres backend can take 10-25 seconds on a cold
# query, so the budget here is wider than the rest of pre-flight. The
# /api/preflight UX should show a loading state while this runs.
HTTP_TIMEOUT = 35
MAX_CANDIDATES = 20
USER_AGENT = "Mozilla/5.0 (Phishield Scanner) related-domain-discovery/1.1"

# Hostnames that frequently appear as SANs but are clearly NOT
# sibling-owned (shared infrastructure, CDNs, third-party services).
# Suffix match; conservative — the broker still confirms.
SHARED_INFRA_SUFFIXES = (
    # CDN / edge providers
    "cloudfront.net", "amazonaws.com", "cloudflare.com", "cloudflare.net",
    "fastly.net", "akamai.net", "akamaized.net", "akamaihd.net",
    "azureedge.net", "msecnd.net", "azurewebsites.net",
    # SaaS / PaaS that share certs across customers
    "herokuapp.com", "appspot.com", "vercel.app", "netlify.app",
    "github.io", "gitlab.io", "pages.dev", "workers.dev",
    "shopify.com", "myshopify.com", "wixsite.com", "squarespace.com",
    # Mail providers
    "googleusercontent.com", "outlook.com", "office.com", "office365.com",
    # CT-log noise
    "letsencrypt.org", "digicert.com", "sectigo.com", "globalsign.com",
)

# Public-suffix-ish list. crt.sh returns leaf SAN entries (e.g.
# "shop.example.com", "*.example.com"); reduce to the public-suffix
# apex when possible so we don't return 50 subdomain variants.
KNOWN_MULTI_PART_TLDS = (
    "co.za", "ac.za", "gov.za", "org.za", "net.za", "web.za",
    "co.uk", "ac.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "ac.nz",
    "com.br", "com.ar", "com.mx",
    "co.in", "co.jp", "co.kr",
    "com.sg", "com.hk", "com.tw",
)


def _apex(host: str) -> str:
    host = (host or "").lower().strip().lstrip("*.").strip(".")
    if not host or "." not in host:
        return host
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    last_three = ".".join(parts[-3:]) if len(parts) >= 3 else None
    if last_three and last_three.split(".", 1)[1] in KNOWN_MULTI_PART_TLDS:
        return last_three
    return last_two


def _is_shared_infra(host: str) -> bool:
    host = (host or "").lower().strip()
    return any(host == s or host.endswith("." + s)
               for s in SHARED_INFRA_SUFFIXES)


def _crtsh_query(domain: str, retries: int = 2) -> list:
    """Query crt.sh for certificate transparency entries.

    crt.sh's hosted Postgres backend is intermittently slow / empty on
    cold-cache queries. Retry once with a short backoff before giving up
    so a single transient miss doesn't break the pre-flight.

    crt.sh response shape: [{"name_value": "example.com\\nwww.example.com",
                              "issuer_name": "...", ...}, ...]
    `name_value` contains all SAN entries newline-joined.
    """
    if not REQUESTS_AVAILABLE:
        return []
    import time
    for attempt in range(retries + 1):
        try:
            r = CRTSH.get(
                CRT_SH_URL,
                params={"q": domain, "output": "json"},
                headers={"User-Agent": USER_AGENT},
                timeout=HTTP_TIMEOUT,
            )
            if r is not None and r.status_code == 200 and r.text:
                try:
                    data = r.json()
                    if data:
                        return data
                except Exception:
                    pass
        except Exception:
            pass
        if attempt < retries:
            time.sleep(2.0)  # short backoff between retries
    return []


def _extract_san_apexes(crt_rows: list, primary_apex: str) -> dict:
    """Collect distinct apex hosts from SAN entries.

    Returns a dict {apex: {"sample_san": "...", "cert_count": N}}
    so we can both deduplicate AND give the broker the strongest
    individual evidence.
    """
    seen: dict = {}
    for row in crt_rows:
        if not isinstance(row, dict):
            continue
        name_value = row.get("name_value") or ""
        for raw in str(name_value).split("\n"):
            host = raw.strip().lower()
            if not host:
                continue
            apex = _apex(host)
            if not apex or apex == primary_apex:
                continue
            if _is_shared_infra(apex):
                continue
            if apex not in seen:
                seen[apex] = {"sample_san": host, "cert_count": 1}
            else:
                seen[apex]["cert_count"] += 1
                # Prefer the apex-only SAN as the sample (less noisy)
                if host == apex:
                    seen[apex]["sample_san"] = host
    return seen


def _confidence_for(apex: str, meta: dict, primary_apex: str) -> str:
    """Heuristic confidence for the broker to weight their review."""
    cnt = meta.get("cert_count", 0)
    # Shared brand fragment between primary and candidate = stronger
    pri_root = primary_apex.split(".")[0]
    cand_root = apex.split(".")[0]
    shared_root = pri_root and (
        pri_root in cand_root or cand_root in pri_root or
        # Levenshtein-ish: long common prefix
        (len(pri_root) >= 5 and len(cand_root) >= 5 and
         pri_root[:5] == cand_root[:5])
    )
    if cnt >= 5 and shared_root:
        return "high"
    if cnt >= 3 or shared_root:
        return "medium"
    return "low"


def discover_via_cert_san(primary_domain: str) -> list:
    """Cert-SAN method (S-1 v1.1 MVP).

    Returns broker-confirmable candidates with evidence and confidence.
    """
    primary_apex = _apex(primary_domain)
    if not primary_apex:
        return []

    crt_rows = _crtsh_query(primary_apex)
    if not crt_rows:
        return []

    apexes = _extract_san_apexes(crt_rows, primary_apex)
    candidates = []
    for apex, meta in apexes.items():
        confidence = _confidence_for(apex, meta, primary_apex)
        candidates.append({
            "domain": apex,
            "signal": "cert_san",
            "signal_detail": (
                f"Shares SSL/TLS certificate(s) with {primary_apex} — "
                f"{meta['cert_count']} cert(s) in Certificate "
                f"Transparency logs (e.g. SAN: {meta['sample_san']})"
            ),
            "confidence": confidence,
            "source_url": (
                f"https://crt.sh/?q={primary_apex}&output=json"
            ),
        })

    # Sort: high-confidence first, then by cert count desc, then alpha
    order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda c: (
        order.get(c["confidence"], 9),
        -apexes[c["domain"]]["cert_count"],
        c["domain"],
    ))
    return candidates[:MAX_CANDIDATES]


def discover_related_domains(primary_domain: str) -> dict:
    """Top-level discovery — orchestrates all enabled methods.

    Returns:
        {
            "status": "ok" | "no_data" | "error",
            "primary_domain": str,
            "candidates": [...],         # list of candidate dicts (see module docstring)
            "methods_used": ["cert_san"], # ordered list of methods that returned data
            "error": str | None,
        }
    """
    primary_domain = (primary_domain or "").strip().lower()
    primary_domain = primary_domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    if not primary_domain:
        return {
            "status": "error",
            "primary_domain": "",
            "candidates": [],
            "methods_used": [],
            "error": "Empty primary_domain",
        }

    try:
        socket.gethostbyname(primary_domain)
    except Exception:
        return {
            "status": "error",
            "primary_domain": primary_domain,
            "candidates": [],
            "methods_used": [],
            "error": "Primary domain does not resolve",
        }

    methods_used: list = []
    candidates: list = []

    cert_san_results = discover_via_cert_san(primary_domain)
    if cert_san_results:
        methods_used.append("cert_san")
        candidates.extend(cert_san_results)

    # Deduplicate across methods (when v1.2 methods land, the SAME
    # apex may surface from multiple signals — keep the strongest
    # confidence + concatenate signal detail).
    by_apex: dict = {}
    for c in candidates:
        apex = c["domain"]
        if apex not in by_apex:
            by_apex[apex] = c
        else:
            existing = by_apex[apex]
            order = {"high": 0, "medium": 1, "low": 2}
            if order.get(c["confidence"], 9) < order.get(existing["confidence"], 9):
                existing["confidence"] = c["confidence"]
            existing["signal"] = f"{existing['signal']},{c['signal']}"
            existing["signal_detail"] = (
                existing["signal_detail"] + " | " + c["signal_detail"]
            )
    candidates = list(by_apex.values())[:MAX_CANDIDATES]

    return {
        "status": "ok" if candidates else "no_data",
        "primary_domain": primary_domain,
        "candidates": candidates,
        "methods_used": methods_used,
        "error": None,
    }
