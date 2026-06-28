"""Cloudflare-bypass origin-IP discovery (S-? / #5 Part B).

A domain fronted by Cloudflare/Akamai resolves only to CDN edge IPs, so the
real origin server (which may expose RDP, databases, admin panels, etc.) is
invisible to a normal A-record scan. This module finds candidate origin IPs
and AUTO-VERIFIES each before it is allowed into the scan pool, so we never
actively port-scan an IP that may have been reassigned to a third party.

Pipeline
--------
1. DISCOVER  — SecurityTrails historical A-records (the pre-CDN origin is
   usually in the history). Free tier: 2,500 queries/month; gated on the key.
2. VERIFY    — open a single TLS handshake to each candidate on :443 with
   SNI = the target domain and check the presented certificate's CN/SAN
   actually covers the domain. A reassigned third-party IP will NOT serve the
   target's certificate, so this cleanly separates "genuinely this org's
   origin, right now" (safe + accurate to scan) from stale/foreign IPs.
3. CLASSIFY  — verified origins are returned for scanning; unverified
   candidates are surfaced for transparency but never scanned.

The cert-match step is the standard origin-confirmation technique used by
origin-discovery tooling (CloudFail, Censys/Shodan cert pivots).
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# WS0: route SecurityTrails + Shodan through the per-provider seam. Clients add no
# retry (max_attempts=1) and return None on a failed request instead of raising.
from providers import SECURITYTRAILS, SHODAN

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

ST_HISTORY_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/a"
SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
MAX_CANDIDATES = 25          # cap candidate IPs we will verify (both sources merged)
VERIFY_TIMEOUT = 5           # seconds per TLS handshake
VERIFY_WORKERS = 8


def _fetch_historical_a(domain: str, api_key: str) -> list:
    """Return de-duplicated historical A-record IPs for the domain, newest
    first. Best-effort: any API/quota failure yields an empty list."""
    if not REQUESTS_AVAILABLE:
        return []
    try:
        r = SECURITYTRAILS.get(
            ST_HISTORY_URL.format(domain=domain),
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if r is None or r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []

    ips, seen = [], set()
    # records[].values[].ip — most-recent first in SecurityTrails' response.
    for rec in (data.get("records") or []):
        for val in (rec.get("values") or []):
            ip = (val.get("ip") or "").strip()
            if ip and ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips[:MAX_CANDIDATES]


def _shodan_cert_hosts(domain: str, api_key: str):
    """Query Shodan for hosts presenting a certificate for the domain.

    Returns (cert_host_count, search_ips, search_used):
      - cert_host_count: total hosts Shodan indexes with this cert. Uses the
        FREE /host/count endpoint (no query credits) — works on the free 'oss'
        plan, so this hint is always available.
      - search_ips: the actual IPs, from /host/search. That endpoint requires
        a paid plan (Membership+); on the free plan it returns 403 and we fall
        back to count-only. So the moment a paid key is inserted, real origin
        IPs start flowing in automatically — no code change needed.
      - search_used: True if the paid search returned results.
    """
    count, ips, used = None, [], False
    if not REQUESTS_AVAILABLE:
        return count, ips, used
    query = f"ssl.cert.subject.cn:{domain}"
    try:
        rc = SHODAN.get(SHODAN_COUNT_URL,
                        params={"key": api_key, "query": query}, timeout=15)
        if rc is not None and rc.status_code == 200:
            count = rc.json().get("total")
    except Exception:
        pass
    try:
        rs = SHODAN.get(SHODAN_SEARCH_URL,
                        params={"key": api_key, "query": query}, timeout=20)
        if rs is not None and rs.status_code == 200:
            used = True
            for m in (rs.json().get("matches") or []):
                ip = (m.get("ip_str") or "").strip()
                if ip:
                    ips.append(ip)
    except Exception:
        pass
    return count, ips, used


def _cert_names(der: bytes) -> set:
    """Extract lower-cased CN + SAN DNS names from a DER certificate."""
    names = set()
    if not (der and CRYPTO_AVAILABLE):
        return names
    try:
        cert = x509.load_der_x509_certificate(der)
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME and attr.value:
                names.add(str(attr.value).lower())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names.update(n.lower() for n in san.value.get_values_for_type(x509.DNSName))
        except Exception:
            pass
    except Exception:
        pass
    return names


def _name_covers(domain: str, names: set) -> bool:
    """True if any cert name equals the domain or is a wildcard covering it."""
    domain = domain.lower().strip(".")
    for n in names:
        n = n.strip(".")
        if n == domain:
            return True
        if n.startswith("*."):
            base = n[2:]
            if domain == base or domain.endswith("." + base):
                return True
    return False


def _verify_origin(ip: str, domain: str) -> bool:
    """Open one TLS handshake to ip:443 with SNI=domain and confirm the
    presented certificate covers the domain. Chain validation is disabled
    on purpose — we connect by IP and judge identity solely by the cert's
    CN/SAN, which is what proves the IP currently serves THIS domain."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, 443), timeout=VERIFY_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return False
    return _name_covers(domain, _cert_names(der))


def discover_origin_ips(domain: str,
                        securitytrails_api_key: Optional[str] = None,
                        shodan_api_key: Optional[str] = None) -> dict:
    """Discover + verify Cloudflare-bypass origin IPs from two sources.

    Sources:
      - SecurityTrails historical A-records (free-tier key).
      - Shodan certificate match: the FREE /host/count endpoint always yields a
        cert-host COUNT hint; the paid /host/search endpoint contributes actual
        candidate IPs only when a Membership+ key is present (auto-activates on
        key swap — see _shodan_cert_hosts).

    Returns:
      status            — skipped (no keys) / completed / error
      candidates        — all candidate IPs considered (both sources, deduped)
      verified          — IPs that currently serve the domain's certificate
                          (SAFE to scan; the caller adds these to the IP pool)
      unverified        — candidates that did not serve the cert (surfaced
                          only, NEVER scanned)
      shodan_cert_hosts — Shodan's count of hosts presenting this cert (hint;
                          None if no Shodan key). If this exceeds the number of
                          verified origins, there are likely origin IPs we
                          could not retrieve (free plan) — upgrade to fetch them
      shodan_search_used — True if the paid Shodan search contributed IPs
    """
    domain = (domain or "").strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    out = {"status": "skipped", "domain": domain,
           "candidates": [], "verified": [], "unverified": [],
           "shodan_cert_hosts": None, "shodan_search_used": False}
    if not securitytrails_api_key and not shodan_api_key:
        return out

    candidates, seen = [], set()

    def _add(ips):
        for ip in ips or []:
            if ip and ip not in seen:
                seen.add(ip)
                candidates.append(ip)

    if securitytrails_api_key:
        _add(_fetch_historical_a(domain, securitytrails_api_key))
    if shodan_api_key:
        count, shodan_ips, used = _shodan_cert_hosts(domain, shodan_api_key)
        out["shodan_cert_hosts"] = count
        out["shodan_search_used"] = used
        _add(shodan_ips)

    candidates = candidates[:MAX_CANDIDATES]
    out["candidates"] = candidates

    verified, unverified = [], []
    if candidates:
        with ThreadPoolExecutor(max_workers=VERIFY_WORKERS) as ex:
            futs = {ex.submit(_verify_origin, ip, domain): ip for ip in candidates}
            try:
                for fut in as_completed(futs, timeout=VERIFY_TIMEOUT * 3):
                    ip = futs[fut]
                    try:
                        (verified if fut.result() else unverified).append(ip)
                    except Exception:
                        unverified.append(ip)
            except Exception:
                # Batch timeout — treat any unresolved candidate as unverified.
                for fut, ip in futs.items():
                    if ip not in verified and ip not in unverified:
                        unverified.append(ip)

    out["verified"] = verified
    out["unverified"] = unverified
    out["status"] = "completed"
    return out
