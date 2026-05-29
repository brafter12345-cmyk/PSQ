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

try:
    from cryptography import x509
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

ST_HISTORY_URL = "https://api.securitytrails.com/v1/history/{domain}/dns/a"
MAX_CANDIDATES = 15          # cap historical IPs we will verify
VERIFY_TIMEOUT = 5           # seconds per TLS handshake
VERIFY_WORKERS = 8


def _fetch_historical_a(domain: str, api_key: str) -> list:
    """Return de-duplicated historical A-record IPs for the domain, newest
    first. Best-effort: any API/quota failure yields an empty list."""
    if not REQUESTS_AVAILABLE:
        return []
    try:
        r = requests.get(
            ST_HISTORY_URL.format(domain=domain),
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=15,
        )
        if r.status_code != 200:
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
                        securitytrails_api_key: Optional[str] = None) -> dict:
    """Discover + verify Cloudflare-bypass origin IPs.

    Returns:
      status      — skipped (no key) / no_data / completed / error
      candidates  — all historical IPs considered
      verified    — IPs that currently serve the domain's certificate (SAFE
                    to scan; the caller adds these to the IP pool)
      unverified  — candidates that did not serve the cert (surfaced only,
                    NEVER scanned)
    """
    domain = (domain or "").strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    out = {"status": "skipped", "domain": domain,
           "candidates": [], "verified": [], "unverified": []}
    if not securitytrails_api_key:
        return out

    candidates = _fetch_historical_a(domain, securitytrails_api_key)
    out["candidates"] = candidates
    if not candidates:
        out["status"] = "no_data"
        return out

    verified, unverified = [], []
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
            # Timeout on the batch — treat any unresolved candidate as unverified.
            for fut, ip in futs.items():
                if ip not in verified and ip not in unverified:
                    unverified.append(ip)

    out["verified"] = verified
    out["unverified"] = unverified
    out["status"] = "completed"
    return out
