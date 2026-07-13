"""scanner_client.py — thin client for the existing PSQ security_scanner.

The scanner runs ON-PREM in the closed environment (Flask, default port 5001), so it receives the
real inputs (domain, revenue, industry) — those are *not* redacted (redaction only applies to the
external LLM mapping path). Shared by the corporate engine now and the SME engine later.

Flow: trigger_scan() -> POST /api/scan (async, returns scan_id) -> poll get_scan() until completed
-> extract_threat_surface() pulls the TIDE "Threat Surface" findings for the report.

Config: SCANNER_URL (default http://localhost:5001).
"""
import os
import re
import json
import urllib.request

SCANNER_URL = os.environ.get("SCANNER_URL", "http://localhost:5001").rstrip("/")

# Our SIC main groups -> the scanner's VALID_INDUSTRIES whitelist.
SCANNER_INDUSTRY_MAP = {
    "Agriculture, Forestry, And Fishing": "Agriculture",
    "Mining": "Mining",
    "Construction": "Construction",
    "Manufacturing": "Manufacturing",
    "Transportation, Communications, Electric, Gas, And Sanitary Services": "Transportation",
    "Wholesale Trade": "Wholesale Trade",
    "Retail Trade": "Retail",
    "Finance, Insurance, And Real Estate": "Financial Services",
    "Services": "Services",
    "Public Administration": "Public Sector",
}


def industry_for_scanner(main_industry):
    if not main_industry:
        return "Other"
    if main_industry in SCANNER_INDUSTRY_MAP:
        return SCANNER_INDUSTRY_MAP[main_industry]
    low = main_industry.lower()
    for k, v in SCANNER_INDUSTRY_MAP.items():
        if k.lower() in low or low in k.lower():
            return v
    return "Other"


def domain_from_url(url):
    """Reduce a URL / website / email-domain to a bare scannable domain."""
    if not url:
        return ""
    d = re.sub(r"^https?://", "", str(url).strip(), flags=re.I)
    d = d.split("/")[0].split("@")[-1].strip().lower()
    return re.sub(r"^www\.", "", d)


def _post(path, payload):
    req = urllib.request.Request(SCANNER_URL + path, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def _get(path):
    req = urllib.request.Request(SCANNER_URL + path)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"status": "failed"}


def trigger_scan(domain, main_industry=None, sub_industry=None, revenue_zar=None,
                 related_domains=None, country="ZA"):
    """Launch a baseline scan. Returns the scanner's response (incl. scan_id)."""
    domain = domain_from_url(domain)
    if not domain:
        raise ValueError("No scannable domain.")
    payload = {"domain": domain, "industry": industry_for_scanner(main_industry), "country": country}
    if sub_industry:
        payload["sub_industry"] = sub_industry
    if revenue_zar:
        payload["annual_revenue_zar"] = int(revenue_zar)
    if related_domains:
        payload["related_domains"] = [domain_from_url(d) for d in related_domains if d]
    status, data = _post("/api/scan", payload)
    return data


def get_scan(scan_id):
    """Returns (status_str, results_dict). status_str ∈ pending|completed|failed."""
    code, data = _get("/api/scan/" + scan_id)
    if code == 200:
        return "completed", data
    if code == 202:
        return "pending", data
    return "failed", data


def extract_threat_surface(results):
    """Pull the TIDE-style 'Threat Surface' findings from a completed scan result."""
    cats = (results or {}).get("categories", {}) or {}
    dns = cats.get("dns_infrastructure", {}) or {}
    hrp = cats.get("high_risk_protocols", {}) or {}
    deh = cats.get("dehashed", {}) or {}
    breaches = cats.get("breaches", {}) or {}
    hr = cats.get("hudson_rock", {}) or {}
    osv = cats.get("osv_vulns", {}) or {}

    ports = []
    for p in (dns.get("open_ports", []) or []) + (hrp.get("exposed_services", []) or []):
        ports.append({"port": p.get("port"), "service": p.get("service"),
                      "risk": p.get("risk") or p.get("risk_level"),
                      "cves": p.get("notable_cves", [])})
    return {
        "overallScore": results.get("overall_risk_score"),
        "riskLevel": results.get("risk_level"),
        "discoveredIps": results.get("discovered_ips", []),
        "openPorts": ports,
        "rdpExposedIps": dns.get("rdp_exposed_ips", []) or [],
        "credentials": {
            "records": deh.get("total_entries", 0) or 0,
            "hasPasswords": bool(deh.get("has_passwords")),
            "sources": deh.get("breach_sources", []) or [],
            "hibpBreaches": breaches.get("breach_count", 0) or 0,
        },
        "infostealer": {
            "employees": hr.get("compromised_employees", 0) or 0,
            "users": hr.get("compromised_users", 0) or 0,
            "families": hr.get("stealer_families", []) or [],
            "daysAgo": hr.get("days_since_compromise"),
        },
        "cves": {
            "critical": osv.get("critical_count", 0) or 0,
            "high": osv.get("high_count", 0) or 0,
            "total": osv.get("total_vulns", 0) or 0,
        },
    }


def reachable():
    try:
        code, _ = _get("/health")
        return code == 200
    except Exception:
        return False
