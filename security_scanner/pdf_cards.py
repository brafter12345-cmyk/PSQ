"""
PHISHIELD Cyber Risk Assessment — per-category card and section renderers
for the PDF reports. Split out of pdf_report.py (pure move — no behaviour
change).
"""

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, KeepTogether

from pdf_data import CVE_DESCRIPTIONS
from pdf_helpers import (
    C_NAVY, C_BLUE, C_BLUE_LIGHT, C_GREEN, C_GREEN_BG, C_AMBER, C_AMBER_BG,
    C_RED, C_RED_BG, C_CRITICAL, C_CRITICAL_BG, C_GREY_1, C_GREY_2, C_GREY_3,
    C_GREY_4, C_WHITE, C_BLACK, INNER_W,
    build_cat_card, kv_row, make_traffic_circle, not_assessed_card,
    _cat_table, _tl,
)


# ---------------------------------------------------------------------------
# Per-category data extractors
# ---------------------------------------------------------------------------



def cat_ssl(d, S):
    ssl = d.get("ssl", {})
    cert = ssl.get("certificate", {})
    tls  = ssl.get("tls_versions", {})
    cip  = ssl.get("cipher_suite", {})
    grade = ssl.get("grade", "?")
    col = _tl(grade in ("A+", "A", "B"), grade == "C")
    legacy = tls.get("TLS 1.0") or tls.get("TLS 1.1")
    days_left = cert.get("days_until_expiry")
    rows = [
        ("Grade",         grade),
        ("Subject",       cert.get("subject", "—")),
        ("Issuer",        cert.get("issuer", "—")),
        ("Expiry",        cert.get("expiry_date", "—")),
        ("Days left",     days_left if days_left else "—"),
        ("TLS 1.0/1.1",   ("Enabled — RISK" if legacy else "Disabled")),
        ("TLS 1.2/1.3",   ("Supported" if tls.get("TLS 1.2") or tls.get("TLS 1.3") else "Not detected")),
        ("Cipher",        f"{cip.get('name','—')} ({'Weak' if cip.get('is_weak') else 'Strong'})"),
        ("HSTS",          "Present" if ssl.get("hsts") else "Missing"),
        ("OCSP Stapling", "Enabled" if ssl.get("ocsp_stapling") else ("Not enabled" if ssl.get("ocsp_stapling") is False else "Unknown")),
        ("CAA Records",   f"Restrictive ({', '.join(ssl.get('caa_policy',{}).get('issue',[])[:3])})" if ssl.get("caa_policy",{}).get("restrictive") else ("Present but not restrictive" if ssl.get("caa_records") else "None — any CA can issue")),
    ]
    fb = "Certificate and encryption configuration meets current standards." if grade in ("A+", "A", "B") else "Review TLS configuration — weak ciphers or legacy protocols may be in use."
    parts = build_cat_card("SSL / TLS", col, f"Grade: {grade}", rows, ssl.get("issues", []), S, fallback=fb)

    # Narrative
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if grade in ("A+", "A"):
        parts.append(Paragraph(
            "This server has a strong SSL/TLS configuration. Data transmitted between users and the website "
            "is encrypted using modern protocols and ciphers, making interception extremely difficult.",
            S["body"]))
    elif grade == "B":
        parts.append(Paragraph(
            "SSL/TLS configuration is acceptable but has room for improvement. Encryption is in place, "
            "though minor configuration changes could strengthen the overall posture.",
            S["body"]))
    elif grade in ("C", "D"):
        parts.append(Paragraph(
            "The SSL/TLS configuration has notable weaknesses. While basic encryption is present, legacy protocols "
            "or weak cipher suites may allow sophisticated attackers to intercept or downgrade encrypted connections.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "SSL/TLS configuration is poor or could not be fully assessed. Without strong encryption, "
            "data transmitted between users and the server is at risk of interception (man-in-the-middle attacks).",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))

    # Build dynamic recommendations
    recs = []
    if legacy:
        recs.append("Disable TLS 1.0 and TLS 1.1 — these legacy protocols have known vulnerabilities and are no longer considered secure.")
    if cip.get("is_weak"):
        recs.append("Replace weak cipher suites with modern alternatives (AES-256-GCM, ChaCha20-Poly1305).")
    if not ssl.get("hsts"):
        recs.append("Enable HTTP Strict Transport Security (HSTS) to prevent protocol downgrade attacks.")
    if days_left and isinstance(days_left, (int, float)) and days_left < 30:
        recs.append(f"Certificate expires in {int(days_left)} days — renew immediately to prevent service disruption and browser warnings.")
    if not recs:
        recs.append("Maintain current configuration and monitor for newly deprecated protocols or cipher suites.")
    parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    for i, r in enumerate(recs, 1):
        parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_email(d, S):
    em  = d.get("email_security", {})
    spf = em.get("spf", {})
    dm  = em.get("dmarc", {})
    dkim= em.get("dkim", {})
    mx  = em.get("mx", {})
    score = em.get("score", 0)
    col = _tl(score >= 8, score >= 5)
    rows = [
        ("SPF",    ("Present" + (" — DANGEROUS +all" if spf.get("dangerous") else "") if spf.get("present") else "Missing")),
        ("DMARC",  f"Present — policy: {dm.get('policy','—')}" if dm.get("present") else "Missing"),
        ("DKIM",   ("Found: " + ", ".join(dkim.get("selectors_found", []))) if dkim.get("selectors_found") else "Not found"),
        ("MX",     f"{len(mx.get('records', []))} record(s)"),
        ("Score",  f"{score}/10"),
    ]
    fb = "Email authentication is well configured — SPF, DKIM, and DMARC are in place." if score >= 8 else "Email authentication gaps increase susceptibility to phishing and spoofing attacks."
    parts = build_cat_card("Email Authentication (SPF/DKIM/DMARC)", col, f"Score {score}/10", rows, em.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 8:
        parts.append(Paragraph(
            "Email authentication is well configured. SPF, DKIM, and DMARC work together to prevent attackers from "
            "sending emails that appear to come from your domain (email spoofing). This is one of the most effective "
            "defences against business email compromise (BEC) and phishing attacks targeting your staff or clients.",
            S["body"]))
    elif score >= 5:
        parts.append(Paragraph(
            "Email authentication is partially configured. Some protections are in place, but gaps remain that "
            "could allow attackers to spoof emails from your domain. Phishing emails impersonating your organisation "
            "could reach clients, partners, or staff inboxes without being flagged.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Email authentication is weak or misconfigured. Without proper SPF, DKIM, and DMARC records, "
            "anyone can send emails that appear to come from your domain. This makes your organisation a prime "
            "target for business email compromise (BEC) — the most financially damaging category of cybercrime.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    recs = []
    if not spf.get("present"):
        recs.append("Publish an SPF record to specify which mail servers are authorised to send email on behalf of your domain.")
    elif spf.get("dangerous"):
        recs.append("URGENT: Your SPF record uses '+all' which allows ANY server to send as your domain — change to '-all' or '~all'.")
    if not dm.get("present"):
        recs.append("Configure a DMARC record with at minimum p=quarantine to instruct receiving servers to flag spoofed emails.")
    elif dm.get("policy") == "none":
        recs.append("Upgrade DMARC policy from 'none' (monitor only) to 'quarantine' or 'reject' to actively block spoofed emails.")
    if not dkim.get("selectors_found"):
        recs.append("Enable DKIM signing on your mail server to cryptographically verify that emails originate from your domain.")
    if recs:
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_email_hardening(d, S):
    eh   = d.get("email_hardening", {})
    mts  = eh.get("mta_sts", {})
    bimi = eh.get("bimi", {})
    dane = eh.get("dane", {})
    tlsrpt = eh.get("tls_rpt", {})
    score= eh.get("score", 0)
    col  = _tl(score >= 7, score >= 3)
    rows = [
        ("MTA-STS", f"Present — mode: {mts.get('mode','?')}" if mts.get("present") else "Not configured"),
        ("BIMI",    "Present" + (" + VMC" if bimi.get("has_vmc") else "") if bimi.get("present") else "Not configured"),
        ("DANE/TLSA", "Present" if dane.get("present") else "Not configured"),
        ("TLS-RPT", f"Present — reports to: {tlsrpt.get('rua','?')}" if tlsrpt.get("present") else "Not configured"),
        ("Score",   f"{score}/10"),
    ]
    fb = "Advanced email protections are well configured." if score >= 7 else "Advanced email hardening (MTA-STS, DANE, BIMI) is partially or not configured — these controls help prevent email interception."
    parts = build_cat_card("Advanced Email Hardening (MTA-STS/DANE/BIMI)", col, f"Score {score}/10", rows, eh.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 7:
        parts.append(Paragraph(
            "Advanced email hardening controls are in place. MTA-STS enforces encrypted email transport, "
            "DANE/TLSA provides certificate pinning for mail servers, and BIMI displays your verified brand logo "
            "in recipients' inboxes — increasing trust and reducing phishing susceptibility.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Advanced email hardening is not fully configured. These are next-generation email security controls "
            "that go beyond basic SPF/DKIM/DMARC. While not yet widely adopted, they provide meaningful additional "
            "protection against email interception and brand impersonation.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    recs = []
    if not mts.get("present"):
        recs.append("Configure MTA-STS to enforce TLS encryption for inbound email, preventing downgrade attacks.")
    if not dane.get("present"):
        recs.append("Implement DANE/TLSA records if your DNS provider supports DNSSEC — this pins your mail server certificates.")
    if not bimi.get("present"):
        recs.append("Set up BIMI to display your brand logo in email clients — this helps recipients identify legitimate emails from your domain.")
    if not tlsrpt.get("present"):
        recs.append("Configure TLS-RPT (RFC 8460) to receive reports about email TLS delivery failures — helps detect MitM attacks on email transport.")
    if recs:
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_headers(d, S):
    hh    = d.get("http_headers", {})
    # "Could not assess" path: the checker reached only a WAF/CDN block page
    # (non-2xx final response) so there is no genuine header posture to grade.
    # Render an amber "blocked/unreachable" card instead of a misleading "0%
    # coverage / all headers missing".
    if hh.get("status") == "unreachable":
        reason = hh.get("unreachable_reason",
                        "Security headers could not be assessed (site blocked or unreachable).")
        parts = build_cat_card("HTTP Security Headers", C_AMBER,
                               "Could not assess (blocked/unreachable)",
                               [], [reason], S, fallback=reason)
        return parts
    score = hh.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    rows  = [(name, "Present" if data.get("present") else "MISSING")
             for name, data in hh.get("headers", {}).items()]
    # CSP quality detail
    csp_q = hh.get("csp_quality")
    if csp_q:
        rows.append(("", ""))
        rows.append(("CSP Quality Score", f"{csp_q.get('score', 0)}/100"))
        if csp_q.get("dangerous"):
            for d_item in csp_q["dangerous"][:3]:
                rows.append(("  CSP Issue", d_item))
        if csp_q.get("missing_critical"):
            rows.append(("  Missing directives", ", ".join(csp_q["missing_critical"])))
    fb = "All recommended security headers are present." if score >= 80 else f"Only {score}% of recommended security headers are configured — missing headers leave the site vulnerable to clickjacking, XSS, and data injection."
    parts = build_cat_card("HTTP Security Headers", col, f"{score}% coverage", rows, hh.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 80:
        parts.append(Paragraph(
            "Security headers are well configured. These HTTP response headers instruct browsers to enforce "
            "security policies, preventing common web attacks such as clickjacking, cross-site scripting (XSS), "
            "and content injection.",
            S["body"]))
    else:
        missing = [name for name, data in hh.get("headers", {}).items() if not data.get("present")]
        parts.append(Paragraph(
            f"Only {score}% of recommended security headers are present. Missing headers "
            f"({', '.join(missing[:4])}{' and more' if len(missing) > 4 else ''}) leave the website "
            "vulnerable to browser-based attacks. These headers are free to implement and require only "
            "web server configuration changes.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score < 80:
        parts.append(Paragraph("1. Add missing security headers to your web server configuration (Apache, Nginx, or CDN).", S["body"]))
        parts.append(Paragraph("2. Prioritise Content-Security-Policy (CSP) and X-Frame-Options as they prevent the most common attacks.", S["body"]))
        parts.append(Paragraph("3. Test header changes using securityheaders.com before deploying to production.", S["body"]))
    else:
        parts.append(Paragraph("1. Maintain current header configuration and review periodically for new recommended headers.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_waf(d, S):
    waf = d.get("waf", {})
    col = C_GREEN if waf.get("detected") else C_AMBER
    rows = [
        ("WAF detected",  waf.get("waf_name", "None detected") if waf.get("detected") else "Not detected"),
        ("All detected",  ", ".join(waf.get("all_detected", [])) or "—"),
    ]
    fb = "Web application firewall is in place, providing protection against common web attacks." if waf.get("detected") else "No web application firewall detected — the site has no automated protection against SQL injection, XSS, or DDoS attacks."
    parts = build_cat_card("WAF / DDoS Protection", col, "Detected" if waf.get("detected") else "Not detected", rows, waf.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if waf.get("detected"):
        parts.append(Paragraph(
            f"A web application firewall ({waf.get('waf_name', 'WAF')}) was detected protecting this website. "
            "WAFs filter malicious traffic before it reaches the web application, blocking common attacks such as "
            "SQL injection, cross-site scripting, and automated bot activity. This significantly reduces the "
            "attack surface exposed to the internet.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No web application firewall was detected. Without a WAF, the website is directly exposed to automated "
            "attack tools that scan for and exploit web application vulnerabilities. This is one of the most "
            "cost-effective security controls available and is strongly recommended.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    if not waf.get("detected"):
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Deploy a cloud-based WAF such as Cloudflare, AWS WAF, or Akamai — these can be enabled without infrastructure changes.", S["body"]))
        parts.append(Paragraph("2. Enable DDoS protection to prevent volumetric attacks from taking the website offline.", S["body"]))
        parts.append(Paragraph("3. Configure WAF rules to block OWASP Top 10 attack patterns as a minimum baseline.", S["body"]))
        parts.append(Spacer(1, 3 * mm))
    else:
        parts.append(Spacer(1, 1 * mm))
    return parts


def cat_dns(d, S):
    dns  = d.get("dns_infrastructure", {})
    ports= dns.get("open_ports", [])
    high = [p for p in ports if p.get("risk") == "high"]
    col  = _tl(len(high) == 0 and len(ports) <= 2, len(high) == 0)
    port_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports) or "None"
    zt = dns.get("zone_transfer", {})
    recs = dns.get("dns_records", {}) or {}
    aaaa = recs.get("AAAA", []) or []
    txt  = recs.get("TXT", []) or []
    rows = [
        ("Open ports",    port_str),
        ("High-risk ports", ", ".join(f"{p['port']}/{p['service']}" for p in high) or "None"),
        ("Server header", dns.get("server_info", {}).get("Server", "—")),
        ("Reverse DNS",   dns.get("reverse_dns") or "—"),
        # DNSSEC status is surfaced here because a DNSSEC remediation can fire
        # off dns.dnssec_enabled; the underwriter must see the status it is based on.
        ("DNSSEC", "Enabled" if dns.get("dnssec_enabled") else "Disabled"),
        ("AAAA (IPv6) records", ", ".join(aaaa) if aaaa else "None"),
        ("TXT records", str(len(txt)) + " record(s)" if txt else "None"),
        ("Zone transfer (AXFR)", f"VULNERABLE — {zt.get('records_leaked',0)} records leaked via {', '.join(zt.get('vulnerable_ns',[]))}" if zt.get("vulnerable") else ("Protected" if zt.get("tested") else "Not tested")),
    ]
    # Map each port to the actual back-end IP(s) it was found on. On CDN-fronted
    # targets the merged port list otherwise reads as if every port sits on the
    # apex IP, hiding that e.g. FTP lives on a separate origin IP.
    port_ip_map = {}
    for _ip, _data in (dns.get("per_ip") or {}).items():
        for _p in _data.get("dns_infrastructure", {}).get("open_ports", []):
            port_ip_map.setdefault(_p.get("port"), [])
            if _ip not in port_ip_map[_p.get("port")]:
                port_ip_map[_p.get("port")].append(_ip)
    # Per-port exploit intel with group separators and risk-level colours
    risky = [p for p in ports if p.get("risk") in ("high", "medium", "critical")]
    for p in risky:
        rows.append(("———", "———"))  # visual separator
        risk = p.get("risk", "medium")
        risk_label = p.get("risk_level", risk.upper() + " RISK")
        rows.append((f"\u25b6{risk}:{p['port']}/{p['service']}", risk_label))
        owners = port_ip_map.get(p.get("port"), [])
        if owners:
            rows.append(("  Found on IP", ", ".join(owners)))
        if p.get("detected_version"):
            rows.append(("  Detected version", p["detected_version"]))
        if p.get("typical_exploits"):
            rows.append(("  Exploits", p["typical_exploits"]))
        if p.get("vuln_metrics"):
            rows.append(("  Vuln metrics", p["vuln_metrics"]))
        if p.get("notable_cves"):
            for cve_id in p["notable_cves"][:5]:
                desc = CVE_DESCRIPTIONS.get(cve_id, "")
                rows.append((f"  {cve_id}", desc if desc else "See NVD for details"))
        if p.get("insurance_risk"):
            rows.append(("  Insurance risk", p["insurance_risk"]))
        if p.get("osv_vulns"):
            osv_ids = [v.get("id", "") for v in p["osv_vulns"][:5]]
            rows.append(("  OSV.dev CVEs", ", ".join(osv_ids)))
            if len(p["osv_vulns"]) > 5:
                rows.append(("", f"...and {len(p['osv_vulns']) - 5} more"))
    fb = "Minimal attack surface — only essential ports are exposed." if len(high) == 0 and len(ports) <= 2 else (f"{len(high)} high-risk port(s) exposed — each is a potential entry point for attackers." if high else f"{len(ports)} ports open — review whether all exposed services are necessary.")
    parts = build_cat_card("DNS & Open Ports", col, f"{len(ports)} open port(s)", rows, dns.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if len(ports) <= 2 and not high:
        parts.append(Paragraph(
            "Only essential services (typically HTTP/HTTPS) are exposed to the internet. A minimal attack surface "
            "means fewer entry points for attackers to probe, significantly reducing the risk of unauthorised access.",
            S["body"]))
    elif high:
        high_names = ", ".join(f"{p['port']}/{p['service']}" for p in high[:4])
        parts.append(Paragraph(
            f"High-risk ports are exposed to the internet ({high_names}). These services are frequently targeted "
            "by automated attack tools and ransomware operators. Exposed database ports (MySQL, PostgreSQL, MongoDB) "
            "and remote access services (RDP, SSH, FTP) are among the top initial access vectors in cyber incidents.",
            S["body"]))
    else:
        parts.append(Paragraph(
            f"{len(ports)} ports are open on this server. While no high-risk ports were identified, each open port "
            "represents a potential attack vector. Regular review ensures only necessary services remain exposed.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    if high or len(ports) > 5:
        recs = []
        if high:
            recs.append("Close or firewall high-risk ports that do not need public internet access. Use VPN for remote administration.")
        if any(p['port'] == 3306 for p in ports):
            recs.append("MySQL (port 3306) should never be exposed to the internet — restrict to localhost or private network.")
        if any(p['port'] == 21 for p in ports):
            recs.append("Replace FTP (port 21) with SFTP — FTP transmits credentials in cleartext.")
        if len(ports) > 5:
            recs.append("Review all open ports and close any services that are not required for business operations.")
        if not recs:
            recs.append("Conduct regular port audits and close unnecessary services to reduce attack surface.")
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_hrp(d, S):
    hrp  = d.get("high_risk_protocols", {})
    svcs = hrp.get("exposed_services", [])
    col  = C_CRITICAL if svcs else C_GREEN
    rows = []
    for i, s in enumerate(svcs):
        if i > 0:
            rows.append(("———", "———"))  # separator between services
        rows.append((f"\u25b6critical:{s['service']}", f"Port {s['port']} — CRITICAL EXPOSURE"))
        if s.get("known_exploits"):
            rows.append(("  Known exploits", s["known_exploits"]))
        if s.get("vuln_metrics"):
            rows.append(("  Vuln metrics", s["vuln_metrics"]))
        if s.get("notable_cves"):
            for cve_id in s["notable_cves"][:5]:
                desc = CVE_DESCRIPTIONS.get(cve_id, "")
                rows.append((f"  {cve_id}", desc if desc else "See NVD for details"))
        if s.get("insurance_risk"):
            rows.append(("  Insurance risk", s["insurance_risk"]))
        if s.get("underwriting_impact"):
            rows.append(("  Underwriting impact", s["underwriting_impact"]))
    if not rows:
        rows = [("Status", "No critical services exposed")]
    fb = "No high-risk database or remote access services are publicly exposed." if not svcs else f"{len(svcs)} critical service(s) directly accessible from the internet — immediate remediation required."
    parts = build_cat_card("Database & Service Exposure", col,
                          f"{len(svcs)} critical exposure(s)", rows, hrp.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if svcs:
        svc_names = ", ".join(s['service'] for s in svcs[:4])
        parts.append(Paragraph(
            f"Critical services ({svc_names}) are directly accessible from the internet. "
            "These services should never be publicly exposed — they are primary targets for automated attack tools "
            "and ransomware operators. Exposed databases risk complete data exfiltration, while remote access "
            "services are routinely brute-forced to gain initial network access.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Immediately firewall all exposed database and remote access ports from public internet access.", S["body"]))
        parts.append(Paragraph("2. Use a VPN or SSH tunnel for any remote administration requirements.", S["body"]))
        parts.append(Paragraph("3. Audit server firewall rules to ensure only web traffic (ports 80/443) is publicly accessible.", S["body"]))
    else:
        parts.append(Paragraph(
            "No critical database or remote access services are exposed to the public internet. "
            "This is a strong indicator of proper network segmentation and firewall configuration.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_cloud(d, S):
    cdn = d.get("cloud_cdn", {})
    rows = [
        ("Provider",     cdn.get("provider") or "Not detected"),
        ("CDN detected", "Yes" if cdn.get("cdn_detected") else "No"),
        ("Hosting type", cdn.get("hosting_type", "Unknown")),
        ("IP addresses", ", ".join(cdn.get("ip_addresses", [])) or "—"),
    ]
    fb = "Cloud and CDN infrastructure detected — provides caching and basic DDoS mitigation." if cdn.get("cdn_detected") else "No CDN detected — the origin server is directly exposed, increasing latency and DDoS risk."
    parts = build_cat_card("Cloud & CDN Infrastructure", C_BLUE, cdn.get("provider") or "Unknown", rows, cdn.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if cdn.get("cdn_detected"):
        parts.append(Paragraph(
            f"A CDN ({cdn.get('provider', 'content delivery network')}) is in use, which provides performance "
            "benefits (faster page loads) and basic security protections (DDoS mitigation, origin IP masking). "
            "CDNs act as a reverse proxy, meaning attackers interact with the CDN edge servers rather than "
            "your origin infrastructure directly.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No content delivery network (CDN) was detected. The origin server IP address is directly exposed, "
            "which means attackers can target the server directly with DDoS attacks or attempt to exploit "
            "web server vulnerabilities without CDN-layer filtering.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def waf_truncation_note(cresult, S):
    """Inline 'partial coverage' note for a card whose checker EARLY-EXITED
    because the target's WAF / bot-manager hard-blocked path probing (the checker
    set `waf_truncated`). Without it the card's benign 'nothing detected' verdict
    reads as confirmed-clean when the check was actually cut short. Returns []
    when the checker ran to completion, so callers can unconditionally do
    `parts += waf_truncation_note(cresult, S)`."""
    if not (isinstance(cresult, dict) and cresult.get("waf_truncated")):
        return []
    return [
        Paragraph(
            "<i><font color='#92400e'><b>Partial coverage — not fully "
            "assessed.</b></font> The target's WAF / bot-management hard-blocked path "
            "probing, so this check stopped before all paths were tested. Treat a "
            "“nothing found” result here as unverified, not as confirmed "
            "clean.</i>", S["body"]),
        Spacer(1, 2 * mm),
    ]


def cat_vpn(d, S):
    vpn = d.get("vpn_remote", {})
    col = C_CRITICAL if vpn.get("rdp_exposed") else (C_GREEN if vpn.get("vpn_detected") else C_AMBER)
    rows = [
        ("RDP exposed",  "YES — CRITICAL" if vpn.get("rdp_exposed") else "No"),
        ("VPN detected", vpn.get("vpn_name") or ("Detected" if vpn.get("vpn_detected") else "Not detected")),
    ]
    fb = "CRITICAL: RDP is exposed to the internet — this is the #1 ransomware entry vector." if vpn.get("rdp_exposed") else ("VPN gateway detected — verify MFA is enforced on all remote access." if vpn.get("vpn_detected") else "No VPN/remote access gateway detected — remote access method unknown.")
    parts = build_cat_card("VPN & Remote Access", col,
                          "RDP EXPOSED" if vpn.get("rdp_exposed") else (vpn.get("vpn_name") or "None detected"),
                          rows, vpn.get("issues", []), S, fallback=fb)
    parts += waf_truncation_note(vpn, S)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if vpn.get("rdp_exposed"):
        parts.append(Paragraph(
            "Remote Desktop Protocol (RDP) is exposed directly to the internet. RDP is the single most common "
            "entry point for ransomware attacks — automated tools continuously scan the internet for open RDP ports "
            "and attempt brute-force login. Once access is gained, attackers can deploy ransomware across "
            "the entire network within hours.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. IMMEDIATE: Block RDP (port 3389) from public internet access at the firewall.", S["body"]))
        parts.append(Paragraph("2. Require VPN connection before RDP access is permitted.", S["body"]))
        parts.append(Paragraph("3. Enable Network Level Authentication (NLA) and enforce MFA on all RDP sessions.", S["body"]))
        parts.append(Paragraph("4. Review RDP access logs for signs of brute-force attempts or unauthorised logins.", S["body"]))
    elif vpn.get("vpn_detected"):
        parts.append(Paragraph(
            f"A VPN gateway ({vpn.get('vpn_name', 'VPN')}) was detected, which is positive — it indicates remote "
            "access is channelled through an encrypted tunnel rather than being directly exposed. Ensure multi-factor "
            "authentication (MFA) is enforced on the VPN and that the VPN firmware is kept up to date, as VPN "
            "appliance vulnerabilities are frequently exploited by ransomware groups.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No VPN or remote access gateway was detected from external scanning. This could mean remote access "
            "is handled through a cloud-based solution (e.g. Azure AD, Zscaler) that doesn't expose a public gateway, "
            "or that no remote access infrastructure exists. Verify how staff access internal systems remotely.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def origin_discovery_block(d, S, silent_when_absent=False):
    """Cloudflare-bypass origin IPs. Verified origins (TLS cert match) were
    scanned; unverified candidates are surfaced for awareness only.

    silent_when_absent: the block renders on the shared attacker's-view page
    AND in the full report's network section; the shared call passes True so
    a not-assessed notice appears once (in the full report) instead of twice."""
    od = d.get("origin_discovery", {}) or {}
    if od.get("status") != "completed":
        if silent_when_absent:
            return []
        return not_assessed_card(
            "Origin IP Discovery (CDN bypass)",
            "Not assessed on this scan — origin-IP discovery runs for CDN-fronted "
            "targets and requires SecurityTrails / Shodan to be reachable. Whether "
            "the real origin server is exposed behind the CDN was not evaluated; "
            "treat CDN protection as unverified rather than confirmed.", S)
    verified = od.get("verified", []) or []
    unverified = od.get("unverified", []) or []
    cert_hosts = od.get("shodan_cert_hosts")
    gap = (cert_hosts is not None) and (cert_hosts > len(verified))
    if not verified and not unverified and cert_hosts is None:
        if silent_when_absent:
            return []
        return not_assessed_card(
            "Origin IP Discovery (CDN bypass)",
            "Discovery ran but produced no origin candidates: historical DNS and "
            "certificate search surfaced no IPs to verify. No exposed origin was "
            "identified — and none could be conclusively ruled out.", S)
    col = C_CRITICAL if verified else (C_AMBER if (unverified or gap) else C_GREEN)
    rows = []
    if verified:
        rows.append(("Verified origins (scanned)", ", ".join(verified)))
    if unverified:
        rows.append(("Candidate origins (not scanned)", ", ".join(unverified)))
    if cert_hosts is not None:
        rows.append(("Shodan cert-host count", str(cert_hosts)))
    fb = ("Real server IP(s) behind the CDN were confirmed by TLS certificate match and "
          "scanned as part of this assessment." if verified else
          "Historical IP(s) that may sit behind the CDN were found but did not present this "
          "domain's certificate — listed for awareness, not scanned.")
    parts = build_cat_card("Origin IP Discovery (CDN bypass)", col,
                           f"{len(verified)} verified / {len(unverified)} candidate",
                           rows, [], S, fallback=fb)
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "A CDN/WAF (e.g. Cloudflare) normally hides the origin server's real IP. <b>Verified</b> "
        "origins currently serve this domain's TLS certificate — confirmed to be the organisation's "
        "own infrastructure and scanned for exposed services (RDP, databases, admin panels). "
        "<b>Candidate</b> IPs came from historical DNS but did not present the certificate, so they "
        "were not scanned (they may have been reassigned to another party).",
        S["body"]))
    if gap:
        parts.append(Spacer(1, 1 * mm))
        msg = (f"Shodan indexes <b>{cert_hosts}</b> host(s) presenting this domain's certificate — "
               f"more than the {len(verified)} origin(s) confirmed via DNS history. This strongly "
               f"suggests one or more origin servers are directly exposed behind the CDN.")
        if not od.get("shodan_search_used"):
            msg += (" Retrieving and scanning these IPs requires a paid Shodan plan; the current "
                    "key can only return the count.")
        parts.append(Paragraph(msg, S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_breaches(d, S):
    br    = d.get("breaches", {})
    count = br.get("breach_count", 0)
    col   = _tl(count == 0, count <= 3)
    rows  = [
        ("Scope",            "Brand-level breach lookup (free HIBP endpoint)"),
        ("Known breaches",   count),
        ("Most recent",      br.get("most_recent_breach") or "N/A"),
        ("Data types exposed", ", ".join(br.get("data_classes", [])[:5]) or "—"),
    ]
    if br.get("breaches"):
        for b in br["breaches"][:4]:
            rows.append((b.get("name", "—"), f"{b.get('date','?')} — {b.get('pwn_count', 0):,} accounts"))
    fb = ("No brand-level breach record found in the HIBP catalogue for this domain — expected for most B2B domains. "
          "Email-level exposure is assessed separately under Credential Risk Assessment.") if count == 0 \
        else (f"{count} brand-level breach(es) where this domain was the breached service. "
              "Staff credentials in these breaches may be reused against corporate systems.")
    parts = build_cat_card("Brand-Level Breach Record (HIBP)", col,
                          f"{count} breach(es)" if count else "Clean — see Credential Risk",
                          rows, br.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Checks</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "This card uses the free Have I Been Pwned (HIBP) <i>brand-breach</i> endpoint. It answers one narrow question: "
        "has this domain itself ever appeared as a breached service in HIBP\u2019s public catalogue? The canonical examples "
        "are Adobe, LinkedIn, Canva, and similar consumer-facing services where millions of accounts were stolen. A clean "
        "result here is expected for most non-consumer-facing B2B domains and does <b>not</b> mean no credentials have leaked.",
        S["body"]))
    parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph("<b>Where the Rest of the HIBP Picture Lives</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "HIBP plays a second, more important role in the layered credential pipeline: it supplies <b>breach dates</b> and "
        "data-class metadata for every breach source surfaced by Dehashed (whose API does not provide timelines). "
        "Those enriched timelines drive the recency-based uplift in the Credential Risk Assessment card. "
        "If you see dated breach entries in that card, HIBP is doing its job \u2014 even when this card reads 0.",
        S["body"]))
    if count:
        data_types = ", ".join(br.get("data_classes", [])[:4]) or "various data types"
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(f"1. Assume credentials from the {count} identified breach(es) ({data_types}) have been circulated. Force resets for all affected accounts.", S["body"]))
        parts.append(Paragraph("2. Enable multi-factor authentication (MFA) on all accounts to defeat credential stuffing using the leaked passwords.", S["body"]))
        parts.append(Paragraph("3. Implement a password policy that blocks reuse of previously breached passwords (e.g. via HIBP Pwned Passwords).", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dnsbl(d, S):
    bl  = d.get("dnsbl", {})
    all_listed = bl.get("ip_listings", []) + bl.get("domain_listings", [])
    col = C_CRITICAL if all_listed else C_GREEN
    rows = [
        ("IP blacklists",     ", ".join(bl.get("ip_listings", [])) or "Clean"),
        ("Domain blacklists", ", ".join(bl.get("domain_listings", [])) or "Clean"),
        ("Status",            "BLACKLISTED" if all_listed else "Not listed"),
    ]
    fb = "Domain/IP is blacklisted — emails may be blocked and reputation is compromised." if all_listed else "Not listed on any checked blacklists — domain reputation is clean."
    parts = build_cat_card("IP / Domain Reputation (DNSBL)", col,
                          "Blacklisted" if all_listed else "Clean", rows, bl.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if all_listed:
        lists = ", ".join(all_listed[:4])
        parts.append(Paragraph(
            f"This domain or IP is listed on security blacklists ({lists}). Blacklisting typically occurs when "
            "an IP has been associated with spam, malware distribution, or other malicious activity. This can cause "
            "email deliverability issues (emails going to spam/junk folders) and may indicate that the server has "
            "been compromised and is being used for malicious purposes.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Investigate why the IP/domain was blacklisted — check for compromised accounts sending spam.", S["body"]))
        parts.append(Paragraph("2. Submit delisting requests to each blacklist provider after resolving the underlying issue.", S["body"]))
        parts.append(Paragraph("3. Monitor email deliverability and set up alerts for future blacklist appearances.", S["body"]))
    else:
        parts.append(Paragraph(
            "This domain and its IP addresses are not listed on any of the checked DNS-based blacklists. "
            "A clean reputation means emails from this domain are less likely to be flagged as spam, and "
            "the IP has not been associated with known malicious activity.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_admin(d, S):
    adm   = d.get("exposed_admin", {})
    exposed = adm.get("exposed", [])
    col   = C_CRITICAL if adm.get("critical_count", 0) > 0 else (C_RED if adm.get("high_count", 0) > 0 else C_GREEN)
    rows  = [(e["path"], f"HTTP {e['status']} — {e['risk'].upper()}") for e in exposed[:8]] or [("Status", "No sensitive paths exposed")]
    fb = f"{len(exposed)} admin or sensitive path(s) accessible from the internet — restrict access via IP whitelisting or VPN." if exposed else "No sensitive admin panels or configuration paths detected on the public website."
    parts = build_cat_card("Exposed Admin Panels & Sensitive Paths", col,
                          f"{len(exposed)} path(s) found", rows, adm.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if exposed:
        crit_count = adm.get("critical_count", 0)
        parts.append(Paragraph(
            f"{len(exposed)} sensitive path(s) were found accessible from the public internet"
            f"{f', including {crit_count} critical exposure(s)' if crit_count else ''}. "
            "Exposed admin panels, configuration files, and development tools give attackers direct insight into "
            "the application's architecture and may provide authentication bypass or default credential opportunities.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Restrict access to admin panels using IP whitelisting, VPN, or network-level access controls.", S["body"]))
        parts.append(Paragraph("2. Remove or rename default admin paths (/admin, /wp-admin, /phpmyadmin) where possible.", S["body"]))
        parts.append(Paragraph("3. Ensure all admin interfaces require strong authentication with MFA enabled.", S["body"]))
    else:
        parts.append(Paragraph(
            "No sensitive admin panels, configuration files, or development tools were found accessible from "
            "the public internet. This reduces the risk of attackers discovering administrative entry points.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_subdomains(d, S):
    subs  = d.get("subdomains", {})
    risky = subs.get("risky_subdomains", [])
    takeover = subs.get("takeover_vulnerable", [])
    col   = C_CRITICAL if takeover else (C_AMBER if risky else C_GREEN)
    rows  = [
        ("Total subdomains", subs.get("total_count", 0)),
        ("Risky subdomains", len(risky)),
        ("Risky names",      ", ".join(risky[:6]) or "None"),
        ("Takeover vulnerable", f"{len(takeover)} CRITICAL" if takeover else "None detected"),
    ]
    for tv in takeover[:5]:
        rows.append((f"  {tv.get('subdomain','')}", f"CNAME → {tv.get('cname_target','')} ({tv.get('service','')}) — TAKEOVER POSSIBLE"))
    fb = f"{len(risky)} subdomain(s) with risky names (e.g. dev, staging, admin) — verify these are not publicly accessible." if risky else f"{subs.get('total_count',0)} subdomain(s) discovered — none flagged as risky."
    parts = build_cat_card("Subdomain Exposure (CT Logs)", col,
                          f"{subs.get('total_count',0)} found, {len(risky)} risky",
                          rows, subs.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    total = subs.get("total_count", 0)
    # Only claim CT-log sourcing when crt.sh actually returned data; otherwise
    # enumeration was DNS-only and asserting "via Certificate Transparency"
    # would be inaccurate.
    src = "via Certificate Transparency logs" if subs.get("ct_source_ok") else "via DNS enumeration"
    if risky:
        risky_list = ", ".join(risky[:5])
        parts.append(Paragraph(
            f"{total} subdomain(s) were discovered {src}, of which {len(risky)} "
            f"have potentially sensitive names ({risky_list}). Subdomains named 'dev', 'staging', 'test', or 'admin' "
            "often run with weaker security controls and may expose internal tools, unpatched software, or "
            "debug interfaces that attackers can exploit as an alternative entry point.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Restrict access to development and staging subdomains using IP whitelisting or VPN.", S["body"]))
        parts.append(Paragraph("2. Ensure non-production subdomains do not contain real customer data.", S["body"]))
        parts.append(Paragraph("3. Apply the same security standards (HTTPS, authentication, patching) to all subdomains.", S["body"]))
    else:
        parts.append(Paragraph(
            f"{total} subdomain(s) were discovered {src}. None have names that suggest "
            "exposed development, staging, or administrative environments. This is a positive indicator of "
            "controlled subdomain management.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_tech(d, S):
    ts   = d.get("tech_stack", {})
    eols = ts.get("eol_detected", [])
    col  = C_CRITICAL if eols else C_GREEN
    rows = [("CMS", f"{ts.get('cms',{}).get('detected','None')} {ts.get('cms',{}).get('version','') or ''}")] + \
           [(e["software"], e["note"]) for e in eols[:5]] + \
           [("Server software", sw) for sw in ts.get("server_software", [])[:3]]
    js_libs = ts.get("js_libraries", [])
    if js_libs:
        rows.append(("JS Libraries", ", ".join(f"{l['library']} {l['version']}" for l in js_libs)))
    fb = f"{len(eols)} end-of-life component(s) detected — these no longer receive security patches and are vulnerable to known exploits." if eols else "No end-of-life software detected — technology stack appears current."
    parts = build_cat_card("Technology Stack & EOL Software", col,
                          f"{len(eols)} EOL component(s)", rows, ts.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if eols:
        eol_names = ", ".join(e["software"] for e in eols[:3])
        parts.append(Paragraph(
            f"End-of-life software ({eol_names}) was detected. Software that has reached end-of-life no longer "
            "receives security patches from the vendor, meaning any newly discovered vulnerabilities will remain "
            "permanently unpatched. Attackers specifically target EOL software because exploits are reliable "
            "and will never be fixed.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Upgrade all end-of-life software to currently supported versions.", S["body"]))
        parts.append(Paragraph("2. If immediate upgrade is not possible, isolate EOL systems behind a WAF and restrict access.", S["body"]))
        parts.append(Paragraph("3. Establish a software lifecycle management process to track vendor support timelines.", S["body"]))
    else:
        parts.append(Paragraph(
            "No end-of-life software was detected in the externally visible technology stack. All identified "
            "components appear to be within their vendor support lifecycle, meaning security patches are available.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_domain(d, S):
    di  = d.get("domain_intel", {})
    col = C_AMBER if di.get("issues") else C_GREEN
    age = di.get("domain_age_days")
    rows = [
        ("Registrar",      di.get("registrar") or "Unknown"),
        ("Created",        di.get("creation_date") or "Unknown"),
        ("Expires",        di.get("expiry_date") or "Unknown"),
        ("Age",            f"{age} days ({round(age/365,1)} years)" if age else "Unknown"),
        ("WHOIS privacy",  "Protected" if di.get("privacy_protected") else "Public"),
    ]
    fb = "Domain registration details are healthy — established domain with no age-related risk flags." if not di.get("issues") and age and age > 365 else "Review domain registration — new or expiring domains increase phishing and impersonation risk."
    parts = build_cat_card("Domain Intelligence (WHOIS)", col,
                          f"Age: {round(age/365,1)}y" if age else "Unknown",
                          rows, di.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if age and age > 730:
        parts.append(Paragraph(
            f"This domain has been registered for {round(age/365,1)} years, indicating an established web presence. "
            "Older domains generally have higher trust scores with email providers and search engines. "
            "Domain age is used by underwriters as a proxy for business maturity.",
            S["body"]))
    elif age and age < 365:
        parts.append(Paragraph(
            f"This domain is less than one year old ({round(age/365,1)} years). Newly registered domains are "
            "statistically more likely to be associated with fraud or phishing. From an underwriting perspective, "
            "domain age below 1 year is a risk factor worth noting.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Domain registration details provide context about the organisation's online presence maturity. "
            "Registration information, expiry dates, and WHOIS privacy settings all contribute to overall "
            "domain trust assessment.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_security_policy(d, S):
    sp  = d.get("security_policy", {})
    stxt= sp.get("security_txt", {})
    col = C_GREEN if stxt.get("present") else C_AMBER
    rows = [
        ("security.txt",   f"Found at {stxt.get('path','')}" if stxt.get("present") else "Not found"),
        ("PGP key",        "Yes" if stxt.get("has_pgp") else "No"),
        ("robots.txt",     f"Present — {sp.get('robots_txt',{}).get('disallows_count',0)} disallow rules"
                           if sp.get("robots_txt", {}).get("present") else "Not found"),
    ]
    fb = "Vulnerability disclosure policy is published — demonstrates mature security practices." if stxt.get("present") else "No security.txt or vulnerability disclosure policy found — makes responsible reporting of security issues difficult."
    parts = build_cat_card("Security Policy & Vulnerability Disclosure", col,
                          "VDP present" if stxt.get("present") else "No VDP", rows, sp.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if stxt.get("present"):
        parts.append(Paragraph(
            "A security.txt file or vulnerability disclosure policy (VDP) is published. This is an industry "
            "best practice that provides security researchers with a responsible way to report vulnerabilities "
            "they discover. Organisations with a VDP typically learn about and fix security issues faster.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No security.txt file or vulnerability disclosure policy was found. Without a published VDP, security "
            "researchers who discover vulnerabilities have no official channel to report them. This can result in "
            "issues going unreported or being disclosed publicly before the organisation can respond.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Create a security.txt file at /.well-known/security.txt with a contact email for security reports.", S["body"]))
        parts.append(Paragraph("2. Consider establishing a formal Vulnerability Disclosure Policy (VDP) on your website.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_glasswing(d, S):
    gw = d.get("glasswing", {})
    is_partner = gw.get("is_partner", False)
    col = C_GREEN if is_partner else C_GREY_3
    rows = [
        ("Glasswing partner",  "Yes — favourable signal" if is_partner else "Not detected"),
        ("Partner name",       gw.get("partner_name") or "—"),
        ("Match method",       gw.get("match_method") or "—"),
        ("RSI credit applied", f"-{gw.get('score_bonus', 0)/100:.2f}" if is_partner else "None"),
    ]
    fb = gw.get("narrative") or ""
    parts = build_cat_card("AI Readiness — Anthropic Glasswing", col,
                          "Partner" if is_partner else "Not detected",
                          rows, gw.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if is_partner:
        parts.append(Paragraph(
            f"{gw.get('partner_name','This organisation')} is listed as an Anthropic Project Glasswing partner. "
            "Glasswing partners integrate Claude-assisted vulnerability discovery and remediation into their security "
            "programme. This materially shortens the window between a novel vulnerability being disclosed and a patch "
            "being deployed — an increasingly important factor as AI-driven vulnerability research accelerates exploit "
            "development. Treated as a modest favourable signal in the Ransomware Susceptibility Index.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "This domain is not on the public Anthropic Project Glasswing partner list and did not self-declare "
            "a Glasswing partnership on its website. Glasswing partnership is an optional positive signal — "
            "its absence is neutral, not a deficiency. Organisations using equivalent AI-assisted vulnerability "
            "tooling from other vendors receive similar real-world benefits even without formal partnership.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Optional Action</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "If the organisation uses AI-assisted vulnerability scanning or patching (internal or partner-provided), "
            "document the programme for underwriting purposes — it can offset exposure from newly-disclosed CVEs.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_payment(d, S):
    pay = d.get("payment_security", {})
    col = C_CRITICAL if pay.get("self_hosted_payment_form") else (C_AMBER if pay.get("has_payment_page") and not pay.get("payment_page_https") else C_GREEN)
    rows = [
        ("Payment page",         "Detected" if pay.get("has_payment_page") else "Not found"),
        ("Payment provider",     pay.get("payment_provider") or ("Self-hosted — PCI RISK" if pay.get("self_hosted_payment_form") else "Unknown")),
        ("Page HTTPS",           "Yes" if pay.get("payment_page_https") else ("N/A" if not pay.get("has_payment_page") else "NO — CRITICAL")),
        ("Self-hosted card form", "YES — PCI risk" if pay.get("self_hosted_payment_form") else "No"),
    ]
    fb = "CRITICAL: Self-hosted payment form detected — PCI DSS compliance risk. Use a tokenised payment provider." if pay.get("self_hosted_payment_form") else ("Payment processing uses a recognised third-party provider — reduces PCI scope." if pay.get("has_payment_page") else "No payment page detected on this domain.")
    parts = build_cat_card("Payment Security (PCI)", col,
                          pay.get("payment_provider") or ("PCI Risk" if pay.get("self_hosted_payment_form") else "N/A"),
                          rows, pay.get("issues", []), S, fallback=fb)
    parts += waf_truncation_note(pay, S)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if pay.get("self_hosted_payment_form"):
        parts.append(Paragraph(
            "A self-hosted payment form was detected, meaning card data may be processed directly on this server. "
            "This significantly increases PCI DSS compliance scope and liability. If cardholder data is compromised, "
            "the organisation faces regulatory penalties, card brand fines, and reputational damage.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. URGENT: Migrate to a tokenised payment provider (Stripe, PayFast, PayGate) that handles card data externally.", S["body"]))
        parts.append(Paragraph("2. Ensure the payment page is served exclusively over HTTPS with a valid certificate.", S["body"]))
        parts.append(Paragraph("3. If self-hosting is required, engage a PCI QSA (Qualified Security Assessor) for formal compliance assessment.", S["body"]))
    elif pay.get("has_payment_page"):
        parts.append(Paragraph(
            f"Payment processing is handled by {pay.get('payment_provider', 'a third-party provider')}, "
            "which significantly reduces PCI DSS compliance scope. The organisation does not appear to directly "
            "handle or store cardholder data.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No payment processing functionality was detected on this website. If the organisation does not "
            "process online payments, this check is not applicable.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_shodan(d, S):
    sv    = d.get("shodan_vulns", {})
    crit  = sv.get("critical_count", 0)
    high  = sv.get("high_count", 0)
    med   = sv.get("medium_count", 0)
    low   = sv.get("low_count", 0)
    total = crit + high + med + low
    col   = C_CRITICAL if crit > 0 else (C_RED if high > 0 else (C_AMBER if med > 0 else C_GREEN))
    source = "Full API" if sv.get("data_source") == "shodan_full_api" else "InternetDB"
    # Include OSV-enriched CVEs in total if available
    osv_total = d.get("osv_vulns", {}).get("total_vulns", 0)
    display_total = max(total, osv_total) if osv_total > 0 else total
    summary = f"{display_total} CVE(s)" if display_total > 0 else ("No CVEs detected" if total == 0 else "Clean")

    rows = [
        ("IP scanned",   sv.get("ip") or "—"),
        ("Data source",  source),
        ("Total CVEs",   total),
        ("Breakdown",    f"Critical: {crit}  |  High: {high}  |  Medium: {med}  |  Low: {low}"),
        ("Open ports",   ", ".join(str(p) for p in sv.get("open_ports", [])) or "—"),
    ]
    if sv.get("os"):
        rows.append(("OS", sv["os"]))
    if sv.get("org"):
        rows.append(("Organization", sv["org"]))
    if sv.get("isp"):
        rows.append(("ISP", sv["isp"]))
    if sv.get("asn"):
        rows.append(("ASN", sv["asn"]))
    if sv.get("tags"):
        rows.append(("Tags", ", ".join(sv["tags"])))

    # Service banners (full API)
    for svc in sv.get("services", [])[:6]:
        port_label = f"Port {svc.get('port', '?')}/{svc.get('transport', 'tcp')}"
        product = svc.get("product", "")
        version = svc.get("version", "")
        rows.append((port_label, f"{product} {version}".strip() or "—"))

    # Exploit maturity summary
    wpn = sv.get("weaponized_count", 0)
    poc = sv.get("poc_public_count", 0)
    if wpn > 0 or poc > 0:
        rows.append(("Exploit maturity", f"Weaponized: {wpn}  |  PoC Public: {poc}  |  Theoretical: {max(0, total - wpn - poc)}"))

    # Detailed CVE rows
    for cve in sv.get("cves", [])[:8]:
        sev = cve.get("severity", "unknown").upper()
        cvss = cve.get("cvss_score", 0)
        epss = cve.get("epss_score", 0)
        maturity = cve.get("exploit_maturity", "theoretical").upper()
        kev = " | CISA KEV" if cve.get("in_kev") else ""
        desc = cve.get("description", "")
        cve_id = cve.get("cve_id", "")
        epss_str = f" | EPSS {epss*100:.0f}%" if epss else ""

        # CVE header row with colour coding
        rows.append(("———", "———"))
        rows.append((f"\u25b6{sev.lower()}:{cve_id}",
                      f"{sev} | CVSS {cvss}{epss_str}{kev} | {maturity}"))

        # Description on separate row — full text wraps in PDF cell
        if desc:
            rows.append(("  Description", desc))

    fb = f"{display_total} known vulnerabilit{'y' if display_total == 1 else 'ies'} detected — review severity breakdown above for patching priority." if display_total > 0 else "No known CVEs detected for this IP — infrastructure appears patched and current."
    parts = build_cat_card("CVE / Known Vulnerabilities", col, summary, rows, sv.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    wpn = sv.get("weaponized_count", 0)
    if crit > 0 or wpn > 0:
        parts.append(Paragraph(
            f"{'Critical' if crit > 0 else 'Weaponized'} vulnerabilities were detected on this infrastructure. "
            "These are known security flaws in the software running on this server that have publicly available "
            "exploit code. Attackers use automated tools to scan for and exploit these vulnerabilities — often within "
            "hours of public disclosure. Unpatched critical CVEs are the leading cause of data breaches globally.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. URGENT: Patch all critical and weaponized CVEs immediately — these have known exploit code in active use.", S["body"]))
        parts.append(Paragraph("2. Establish a patch management policy with defined SLAs (critical: 48hrs, high: 7 days, medium: 30 days).", S["body"]))
        parts.append(Paragraph("3. Subscribe to vendor security advisories for all deployed software.", S["body"]))
    elif high > 0:
        parts.append(Paragraph(
            f"{high} high-severity CVE(s) were detected. While no critical or weaponized exploits were found, "
            "high-severity vulnerabilities can still be chained together by skilled attackers to achieve "
            "significant impact. Timely patching remains essential.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Schedule patching for all high-severity CVEs within 7 days.", S["body"]))
        parts.append(Paragraph("2. Monitor EPSS scores — if any high CVE's exploitation probability increases, escalate to critical priority.", S["body"]))
    elif display_total > 0:
        parts.append(Paragraph(
            f"{display_total} CVE(s) of medium or low severity were detected. These represent known weaknesses "
            "but are less likely to be exploited in isolation. Address during regular maintenance cycles.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No known CVEs were detected for the software versions running on this infrastructure. "
            "This suggests the server software is up to date with current security patches — a strong positive indicator.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dehashed(d, S):
    dh     = d.get("dehashed", {})
    status = dh.get("status", "completed")
    total  = dh.get("total_entries", 0)
    col    = (C_CRITICAL if total > 50 else C_RED if total > 10 else
              C_AMBER if total > 0 else (C_BLUE if status == "no_api_key" else C_GREEN))
    is_error = status == "error"
    summary = ("No API key" if status == "no_api_key" else
               "API unavailable" if is_error else
               f"{total} records" if total > 0 else "Clean")
    if is_error:
        col = C_BLUE  # Info colour, not red
    status_text = ("API key not configured" if status == "no_api_key" else
                   "API endpoint unavailable — check subscription" if is_error else
                   "Completed")
    cb = dh.get("credential_breakdown", {})
    rows = [
        ("Status",        status_text),
        ("Total records", total),
        ("Unique emails", dh.get("unique_emails", 0)),
        ("Passwords in leaks", "Yes — CRITICAL" if dh.get("has_passwords") else "No"),
    ]
    if cb:
        rows.append(("Plaintext passwords", f"{cb.get('plaintext_count', 0)} — IMMEDIATE RISK" if cb.get('plaintext_count') else "0"))
        rows.append(("Hashed credentials", f"{cb.get('hashed_count', 0)} ({', '.join(f'{k}: {v}' for k, v in cb.get('hash_types', {}).items())})" if cb.get('hashed_count') else "0"))
        rows.append(("Weak hashes (MD5/SHA-1)", f"{cb.get('weak_hash_count', 0)} — easily crackable" if cb.get('weak_hash_count') else "0"))
        rows.append(("Corporate vs Personal", f"{cb.get('corporate_count', 0)} corporate | {cb.get('personal_count', 0)} personal"))
    if dh.get("sample_emails"):
        rows.append(("Affected emails", " | ".join(dh["sample_emails"][:5])))
    if dh.get("breach_sources"):
        rows.append(("Breach sources", " | ".join(dh["breach_sources"][:8])))
    fb = f"{total} credential record(s) found in leak databases — see breach details below." if total > 0 else ("Dehashed API unavailable — credential leak check could not be completed." if is_error else "No leaked credentials found in Dehashed databases for this domain.")
    parts = build_cat_card("Dehashed Credential Leaks", col, summary, rows, dh.get("issues", []), S, fallback=fb)

    # Breach details OUTSIDE the table
    details = dh.get("breach_details", [])
    if details:
        parts.append(Paragraph("<b>Breach Details</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        detail_lines = []
        for i, det in enumerate(details[:10]):
            pw_flag = " [PASSWORD EXPOSED]" if det.get("has_password") else (" [HASH EXPOSED]" if det.get("has_hash") else "")
            user_str = f" (user: {det['username']})" if det.get("username") else ""
            detail_lines.append(f"{det.get('database', 'Unknown')}: {det.get('email', 'N/A')}{user_str}{pw_flag}")
        if len(details) > 10:
            detail_lines.append(f"...and {len(details) - 10} more records")
        for line in detail_lines:
            parts.append(Paragraph(f"\u2022 {line}", S["body"]))
        parts.append(Spacer(1, 2 * mm))

    # Remediation advice OUTSIDE the table
    if total > 0:
        parts.append(Paragraph("<b>Remediation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Force password resets for all identified email addresses across all company systems.", S["body"]))
        parts.append(Paragraph("2. Enable multi-factor authentication on all accounts, especially those with exposed credentials.", S["body"]))
        parts.append(Paragraph("3. Enroll in continuous breach monitoring to detect future exposures.", S["body"]))
        if dh.get("has_passwords"):
            parts.append(Paragraph("4. CRITICAL: Plaintext passwords found — audit all systems for password reuse immediately.", S["body"]))
        parts.append(Spacer(1, 2 * mm))
    parts.append(Spacer(1, 1 * mm))
    return parts


def cat_hudson_rock(d, S):
    hr = d.get("hudson_rock", {})
    employees = hr.get("compromised_employees", 0)
    users = hr.get("compromised_users", 0)
    third = hr.get("third_party_exposures", 0)
    total = employees + users
    col = C_CRITICAL if employees > 0 else (C_RED if users > 0 else (C_AMBER if third > 0 else C_GREEN))
    summary = f"{total} compromised" if total > 0 else ("Third-party exposure" if third > 0 else "Clean")
    rows = [
        ("Compromised employees", f"{employees}" + (" — ACTIVE INFOSTEALER" if employees > 0 else "")),
        ("Compromised users", users),
        ("Third-party exposures", third),
    ]
    fb = "ACTIVE infostealer infection detected — credentials are being exfiltrated in real-time." if employees > 0 else ("Third-party supply chain exposure detected via compromised vendor credentials." if third > 0 else "No infostealer infections detected across employee or user devices.")
    parts = build_cat_card("Infostealer Detection (Hudson Rock)", col, summary, rows, hr.get("issues", []), S, fallback=fb)

    # Narrative interpretation OUTSIDE the table
    if employees > 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "Employee devices are ACTIVELY infected with infostealer malware (Raccoon, RedLine, Vidar). "
            "Credentials are being exfiltrated in real-time and sold on dark web markets. "
            "Immediate incident response required: isolate devices, force password resets, engage forensics.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
    elif third > 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "Third-party supply chain exposure detected. A vendor or partner connected to this domain "
            "has compromised credentials. Review shared access and enforce MFA on all integrations.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
    elif total == 0 and third == 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "No active infostealer infections detected on employee or user devices. "
            "This indicates healthy endpoint security posture.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if employees > 0:
        parts.append(Paragraph(
            "Infostealer malware (such as RedLine, Raccoon, or Vidar) has been detected on devices "
            "belonging to employees of this organisation. This type of malware silently runs in the background "
            "and captures everything — saved passwords from web browsers, banking credentials, email logins, "
            "VPN access details, and even session cookies that allow attackers to bypass MFA. "
            "The stolen data is automatically uploaded to criminal servers and sold within hours. "
            "This is not a historical breach — it indicates CURRENT, ACTIVE compromise.",
            S["body"]))
    elif third > 0:
        parts.append(Paragraph(
            "A third-party vendor or partner connected to this organisation has been found in infostealer databases. "
            "This means a supplier, contractor, or service provider who interacts with your systems has had their "
            "credentials stolen. Attackers frequently use compromised vendor access as a backdoor into larger "
            "organisations (supply chain attacks). Review all shared access and API integrations with external partners.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No infostealer infections were detected. This check scans a database of over 34 million compromised "
            "devices worldwide. A clean result means no employee or user devices associated with this domain "
            "appear in known infostealer databases. This is a positive security indicator.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_intelx(d, S):
    ix = d.get("intelx", {})
    if ix.get("status") == "no_api_key":
        return []
    total = ix.get("total_results", 0)
    darkweb = ix.get("darkweb_count", 0)
    pastes = ix.get("paste_count", 0)
    leaks = ix.get("leak_count", 0)
    col = C_CRITICAL if darkweb > 0 else (C_RED if pastes > 5 else (C_AMBER if total > 0 else C_GREEN))
    summary = f"{total} result(s)" if total > 0 else "Clean"
    rows = [
        ("Total references", total),
        ("Dark web mentions", f"{darkweb}" + (" — ACTIVE TRADING" if darkweb > 0 else "")),
        ("Paste site mentions", pastes),
        ("Leak database entries", leaks),
    ]
    # Add recent findings
    recent = ix.get("recent_results", [])
    if recent:
        rows.append(("", ""))
        rows.append(("RECENT FINDINGS", ""))
        for rec in recent[:8]:
            rows.append((f"  {rec.get('date', '')}", f"{rec.get('name', 'Unknown')} ({rec.get('media', '')})"))
    fb = f"{darkweb} dark web mention(s) found — stolen data may be actively traded on criminal forums." if darkweb > 0 else (f"{total} reference(s) found in leak databases — see interpretation below." if total > 0 else "No references found on dark web forums or leak databases.")
    parts = build_cat_card("Dark Web Monitoring (IntelX)", col, summary, rows, ix.get("issues", []), S, fallback=fb)

    # Plain-English interpretation OUTSIDE the table
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if darkweb > 0:
        parts.append(Paragraph(
            f"We found {darkweb} mention(s) of this domain on dark web criminal forums. "
            "This means stolen data (login credentials, personal information, or internal documents) "
            "associated with your organisation is actively being bought and sold by cybercriminals. "
            "This is a strong indicator of elevated cyber risk and potential for targeted attacks.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Action</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "1. Immediately force password resets for all staff accounts. "
            "2. Enable multi-factor authentication (MFA) on all systems. "
            "3. Engage a forensic investigator to determine the source of the leak. "
            "4. Notify affected individuals as required under POPIA Section 22.",
            S["body"]))
    elif total > 0:
        parts.append(Paragraph(
            f"We found {total} reference(s) to this domain in dark web leak databases. "
            "These entries are typically 'infostealer logs' — records created when malware on someone's "
            "computer silently captures everything they type, including passwords and banking details. "
            "The stolen data is then packaged and uploaded to criminal databases where it can be "
            "purchased by other attackers.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph(
            "In simple terms: someone who has (or had) login access to your systems had their "
            "personal device infected with spyware. The passwords they used for your systems may now "
            "be in criminal hands.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Action</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "1. Force password resets for all staff, especially those using personal devices. "
            "2. Enable MFA — even if passwords are stolen, MFA prevents unauthorised access. "
            "3. Consider endpoint security solutions (antivirus, EDR) for all devices accessing company systems. "
            "4. Educate staff about the risks of downloading unverified software.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No references to this domain were found on dark web forums, paste sites, or leak databases. "
            "This is a positive indicator — there is no evidence of stolen credentials being traded online.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_credential_risk(d, S):
    cr = d.get("credential_risk", {})
    if not cr or not cr.get("risk_level"):
        return []
    level = cr.get("risk_level", "LOW")
    col = C_CRITICAL if level == "CRITICAL" else (C_RED if level == "HIGH" else (C_AMBER if level == "MEDIUM" else C_GREEN))
    rows = [
        ("Overall Risk Level", level),
        ("Risk Score", f"{cr.get('risk_score', 100)}/100"),
        ("Active Compromise", "YES — IMMEDIATE ACTION REQUIRED" if cr.get("active_compromise") else "No"),
    ]
    # Factors
    factors = cr.get("factors", [])
    if factors:
        rows.append(("", ""))
        rows.append(("RISK FACTORS", ""))
        for f in factors:
            rows.append(("", f))
    # Enriched breach timeline — HIBP catalogue cross-referenced against Dehashed sources
    enriched = d.get("dehashed", {}).get("enriched_sources", [])
    if enriched:
        rows.append(("", ""))
        rows.append(("BREACH SOURCE TIMELINE (HIBP-ENRICHED)", ""))
        for src in enriched:
            pw_flag = " [PASSWORDS EXPOSED]" if src.get("passwords_in_breach") else ""
            verified = " [Verified]" if src.get("verified") else ""
            data = ", ".join(src.get("data_exposed", [])[:4]) if src.get("data_exposed") else "Unknown"
            rows.append((f"  {src.get('name', 'Unknown')}", f"Date: {src.get('breach_date', 'Unknown')}{pw_flag}{verified} | Data: {data}"))
    fb = {"CRITICAL": "CRITICAL credential risk — active compromise detected. Immediate incident response required.",
           "HIGH": "HIGH credential risk — recent breaches with password exposure. Force resets and enable MFA.",
           "MEDIUM": "MODERATE credential risk — historical exposure detected. Review password policies and MFA coverage.",
           "LOW": "Low credential risk — no significant exposure. Continue monitoring."}.get(level, "Credential risk assessment complete — see details above.")
    parts = build_cat_card("Credential Risk Assessment", col, level, rows, [], S, fallback=fb)

    # Assessment summary OUTSIDE the table
    summary_text = cr.get("summary", "")
    if summary_text:
        parts.append(Paragraph("<b>Assessment</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(summary_text, S["body"]))
        parts.append(Spacer(1, 2 * mm))

    # What This Means OUTSIDE the table
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if level == "CRITICAL":
        parts.append(Paragraph(
            "One or more employee devices are actively infected with credential-stealing malware. "
            "This is the highest severity finding — attackers have real-time access to stolen passwords "
            "and can log into your systems at any time. Treat this as an active security incident.",
            S["body"]))
    elif level == "HIGH":
        parts.append(Paragraph(
            "Staff credentials (usernames and passwords) have been found in recent data breaches. "
            "While these may have been changed since the breach, attackers routinely use stolen passwords "
            "to attempt access to other systems (credential stuffing). The risk of unauthorised access "
            "is significantly elevated.",
            S["body"]))
    elif level == "MEDIUM":
        parts.append(Paragraph(
            "Historical credential exposure has been detected in older data breaches. "
            "The risk is moderate — passwords may have been changed since the breach, but "
            "organisations with poor password hygiene or no MFA remain vulnerable.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No significant credential exposure detected. This is a positive indicator of "
            "good security practices. Continue monitoring and maintain MFA enforcement.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_virustotal(d, S):
    vt     = d.get("virustotal", {})
    status = vt.get("status", "completed")
    mal    = vt.get("malicious_count", 0)
    sus    = vt.get("suspicious_count", 0)
    col    = (C_CRITICAL if mal > 3 else C_RED if mal > 0 else
              C_AMBER if sus > 0 else (C_BLUE if status == "no_api_key" else C_GREEN))
    summary = ("No API key" if status == "no_api_key" else
               f"{mal} malicious" if mal > 0 else
               f"{sus} suspicious" if sus > 0 else "Clean")
    harmless = vt.get("harmless_count", 0)
    undetected = vt.get("undetected_count", 0)
    total_engines = mal + sus + harmless + undetected
    rep = vt.get("reputation", 0)

    # Build interpretation text
    if status == "no_api_key":
        interp = "VirusTotal API key not configured — unable to check domain reputation."
    elif mal > 3:
        interp = f"CRITICAL: {mal} of {total_engines} security engines flagged this domain as malicious. Indicates active malware hosting, phishing, or compromise. Immediate investigation required."
    elif mal > 0:
        interp = f"WARNING: {mal} engine(s) flagged this domain as malicious. May indicate historical compromise or false positive. Review flagging engines below for context."
    elif sus > 0:
        interp = f"CAUTION: {sus} engine(s) flagged this domain as suspicious. No confirmed malicious activity but warrants monitoring."
    elif harmless > 50:
        interp = f"CLEAN: {harmless} of {total_engines} engines confirmed harmless. Strong positive reputation with no malicious indicators detected."
    else:
        interp = f"No malicious or suspicious detections across {total_engines} security engines. Domain has a clean reputation."

    # Add reputation context
    if rep > 0:
        interp += f" Community reputation score is positive ({rep})."
    elif rep < 0:
        interp += f" Community reputation score is negative ({rep}) — users have flagged concerns."

    rows = [
        ("Malicious detections", f"{mal} of {total_engines} engines"),
        ("Suspicious detections", f"{sus} of {total_engines} engines"),
        ("Harmless",             harmless),
        ("Undetected",           undetected),
        ("Community reputation", rep),
        ("Community votes",      f"Harmless: {vt.get('harmless_votes', 0)}  |  Malicious: {vt.get('malicious_votes', 0)}"),
    ]
    if vt.get("popularity_rank"):
        rows.append(("Popularity rank", f"#{vt['popularity_rank']:,}"))
    if vt.get("categories"):
        rows.append(("Categories", " | ".join(list(vt["categories"].values())[:5])))
    for eng in vt.get("flagging_engines", [])[:5]:
        rows.append((eng.get("engine", ""), f"{eng.get('category', '')} — {eng.get('result', '')}"))
    fb = f"{mal} security engine(s) flagged this domain as malicious — see interpretation below." if mal > 0 else (f"{sus} engine(s) flagged as suspicious — warrants monitoring." if sus > 0 else "Clean reputation across all security engines — no malicious indicators.")
    parts = build_cat_card("VirusTotal Reputation", col, summary, rows, vt.get("issues", []), S, fallback=fb)

    # Interpretation OUTSIDE the table
    parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(interp, S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_securitytrails(d, S):
    st     = d.get("securitytrails", {})
    status = st.get("status", "completed")
    assoc  = st.get("associated_count", 0)
    col    = C_AMBER if assoc > 50 else (C_BLUE if status == "no_api_key" else C_GREEN)
    summary = ("No API key" if status == "no_api_key" else
               f"{assoc} associated" if assoc > 0 else "Info")
    rows = [
        ("Status",             "API key not configured" if status == "no_api_key" else status),
        ("A records",          ", ".join(st.get("a_records", [])) or "—"),
        ("MX records",         ", ".join(st.get("mx_records", [])) or "—"),
        ("NS records",         ", ".join(st.get("ns_records", [])) or "—"),
        ("Associated domains", assoc),
    ]
    if st.get("alexa_rank"):
        rows.append(("Alexa rank", f"#{st['alexa_rank']:,}"))
    if st.get("associated_domains"):
        rows.append(("Top associated", " | ".join(st["associated_domains"][:5])))
    fb = "DNS intelligence collected — provides historical context for domain infrastructure." if status != "no_api_key" else "SecurityTrails API not configured — historical DNS intelligence unavailable."
    parts = build_cat_card("DNS Intelligence (SecurityTrails)", col, summary, rows, st.get("issues", []), S, fallback=fb)

    if status != "no_api_key":
        parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        if assoc > 50:
            parts.append(Paragraph(
                f"{assoc} associated domains share infrastructure with this domain. A high number of associated "
                "domains can indicate shared hosting, which means a compromise of any co-hosted site could "
                "potentially impact this domain. It also expands the attack surface that needs to be monitored.",
                S["body"]))
        else:
            parts.append(Paragraph(
                "DNS intelligence provides historical context about the domain's infrastructure — including "
                "current and historical DNS records, associated domains, and hosting changes. This data helps "
                "assess infrastructure stability and identify potential shared-hosting risks.",
                S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_privacy_compliance(d, S):
    pc    = d.get("privacy_compliance", {})
    pct   = pc.get("compliance_pct", 0)
    found = pc.get("policy_found", False)
    col   = C_GREEN if pct >= 80 else (C_AMBER if pct >= 50 else (C_RED if found else C_CRITICAL))
    summary = f"{pct}%" if found else "Not found"
    rows = [
        ("Policy found", "Yes" if found else "No — compliance risk"),
    ]
    if found:
        rows.append(("Compliance score", f"{pct}%"))
        if pc.get("sections_found"):
            rows.append(("Sections present", " | ".join(pc["sections_found"])))
        if pc.get("sections_missing"):
            rows.append(("Sections missing", " | ".join(pc["sections_missing"])))
    fb = f"Privacy policy found with {pct}% completeness — review missing sections for POPIA compliance." if found and pct < 80 else ("Privacy policy is comprehensive and meets key compliance requirements." if found else "No privacy policy found — required under POPIA for any organisation processing personal information.")
    parts = build_cat_card("Privacy Policy Compliance", col, summary, rows, pc.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if not found:
        parts.append(Paragraph(
            "No privacy policy was found on this website. Under POPIA (Protection of Personal Information Act), "
            "any organisation that processes personal information must have a publicly accessible privacy policy "
            "detailing how data is collected, used, stored, and protected. Absence of a privacy policy is a "
            "compliance gap and a regulatory risk.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Publish a POPIA-compliant privacy policy on the website, accessible from every page.", S["body"]))
        parts.append(Paragraph("2. Include required sections: purpose of processing, data categories, retention periods, data subject rights, and Information Officer details.", S["body"]))
    elif pct < 80:
        missing = pc.get("sections_missing", [])
        missing_str = ", ".join(missing[:3]) if missing else "various sections"
        parts.append(Paragraph(
            f"A privacy policy was found but is only {pct}% complete. Missing sections ({missing_str}) "
            "may leave the organisation exposed to regulatory action under POPIA. A comprehensive privacy policy "
            "is both a legal requirement and a trust signal for clients.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(f"1. Add missing sections to the privacy policy: {missing_str}.", S["body"]))
        parts.append(Paragraph("2. Have the updated policy reviewed by a POPIA compliance specialist.", S["body"]))
    else:
        parts.append(Paragraph(
            "The privacy policy is comprehensive and covers the key sections required for POPIA compliance. "
            "This demonstrates mature data governance practices.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def _finding_colour(text: str) -> str:
    """Return hex colour based on finding severity keywords."""
    tl = text.lower()
    if "critical" in tl:
        return "#dc2626"
    if any(kw in tl for kw in ("high-risk", "missing", "not enforced", "not enabled",
                                "no spf", "no dmarc", "no dkim", "exposed", "no waf")):
        return "#f97316"
    if any(kw in tl for kw in ("medium-risk", "no modern tls", "hsts", "listed")):
        return "#eab308"
    return "#64748b"


def cat_compliance_frameworks(data, S):
    """Render compliance framework mapping section."""
    compliance = data.get("compliance", {})
    if not compliance:
        return []

    story = []

    # External-scan disclaimer
    story.append(Paragraph(
        "<b>Note:</b> This compliance assessment is based on <b>externally observable indicators only</b>. "
        "An external scan can typically assess 60–80% of a framework's controls — those related to encryption, "
        "access controls, network security, and public-facing configurations. Controls requiring internal assessment "
        "(e.g. staff training, incident response procedures, internal access management) cannot be evaluated "
        "externally and are marked as NO_DATA. A full compliance audit would require internal assessment.",
        S["body"]))
    story.append(Spacer(1, 4 * mm))

    for framework, fw_data in compliance.items():
        pct = fw_data.get("overall_pct", 0)
        col = C_GREEN if pct >= 75 else (C_AMBER if pct >= 50 else C_RED)
        rows = []
        for ctrl_name, ctrl in fw_data.get("controls", {}).items():
            status_str = ctrl.get("status", "no_data").upper()
            status_col = {"PASS": "#16a34a", "PARTIAL": "#d97706", "FAIL": "#dc2626", "NO_DATA": "#64748b"}.get(status_str, "#64748b")
            rows.append((ctrl_name, f"<font color='{status_col}'><b>{status_str}</b></font> — {ctrl.get('description', '')}"))
            for finding in ctrl.get("findings", [])[:3]:
                fc = _finding_colour(finding)
                rows.append(("", f"  <font color='{fc}'>↳ {finding[:120]}</font>"))
        # Count assessable vs NO_DATA
        total_ctrl = len(fw_data.get("controls", {}))
        no_data_count = sum(1 for c in fw_data.get("controls", {}).values() if c.get("status") == "no_data")
        assessable = total_ctrl - no_data_count
        fb = (f"{pct}% alignment based on {assessable} of {total_ctrl} externally assessable controls. "
              f"{'Remaining controls require internal assessment.' if no_data_count > 0 else ''}")
        story += build_cat_card(f"{framework}", col, f"{pct}% aligned", rows, [], S, fallback=fb)
    return story


def cat_website(d, S):
    ws    = d.get("website_security", {})
    score = ws.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    ck    = ws.get("cookies", {})
    rows  = [
        ("HTTPS enforced", "Yes" if ws.get("https_enforced") else "No"),
        ("Mixed content",  "Detected" if ws.get("mixed_content") else "None"),
        ("CMS",            f"{ws.get('cms',{}).get('detected','None')} {ws.get('cms',{}).get('version','') or ''}"),
        ("Cookie Secure",  "OK" if ck.get("secure", True) else "Issues"),
        ("Cookie HttpOnly","OK" if ck.get("httponly", True) else "Issues"),
    ]
    fb = "Website security configuration is strong — HTTPS enforced with secure cookie settings." if score >= 80 else f"Website security score of {score}% — review HTTPS enforcement, mixed content, and cookie security settings."
    parts = build_cat_card("Website Security", col, f"{score}%", rows, ws.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 80:
        parts.append(Paragraph(
            "Website security fundamentals are well implemented. HTTPS is enforced, cookies are configured "
            "with Secure and HttpOnly flags, and no mixed content issues were detected. This protects user "
            "sessions from hijacking and ensures data integrity between the browser and server.",
            S["body"]))
    else:
        issues_list = []
        if not ws.get("https_enforced"):
            issues_list.append("HTTPS not enforced")
        if ws.get("mixed_content"):
            issues_list.append("mixed content detected")
        if not ck.get("secure", True):
            issues_list.append("insecure cookie flags")
        parts.append(Paragraph(
            f"Website security score is {score}%"
            f"{' — issues include: ' + ', '.join(issues_list) if issues_list else ''}. "
            "These are foundational web security controls that protect user sessions and data transmission.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        if not ws.get("https_enforced"):
            parts.append(Paragraph("1. Enforce HTTPS across all pages using server-side redirects (HTTP 301 to HTTPS).", S["body"]))
        if ws.get("mixed_content"):
            parts.append(Paragraph("2. Fix mixed content by ensuring all resources (images, scripts, CSS) are loaded over HTTPS.", S["body"]))
        if not ck.get("secure", True) or not ck.get("httponly", True):
            parts.append(Paragraph("3. Set Secure and HttpOnly flags on all session cookies to prevent interception and XSS theft.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_web_ranking(d, S):
    wr = d.get("web_ranking", {})
    rank = wr.get("rank")
    score = wr.get("score", 30)
    col = _tl(score >= 70, score >= 40)
    rows = [
        ("Tranco Rank", f"#{rank:,}" if rank else "Not in top 1M"),
        ("In List", "Yes" if wr.get("in_list") else "No"),
        ("Score", f"{score}/100"),
    ]
    fb = f"Ranked #{rank:,} — established web presence." if rank else "Not ranked in Tranco top 1M — typical for SME websites."
    parts = build_cat_card("Web Ranking (Tranco)", col,
                          f"#{rank:,}" if rank else "Unranked",
                          rows, wr.get("issues", []), S, fallback=fb)
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "Web ranking from the Tranco list (a research-grade domain popularity list) provides context about "
        "website traffic volume. Higher-traffic websites are more attractive targets for attackers but also "
        "tend to have more mature security practices. Unranked sites are common for SMEs and do not indicate "
        "a security concern.",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_info_disclosure(d, S):
    info = d.get("info_disclosure", {})
    score = info.get("score", 100)
    col = _tl(score >= 90, score >= 60)
    exposed = info.get("exposed_paths", [])
    rows = [("Exposed Paths", str(len(exposed)))]
    for p in exposed[:5]:
        rows.append((p.get("path", ""), f"{p.get('risk_level','').upper()} — {p.get('description','')}"))
    if len(exposed) > 5:
        rows.append(("...", f"+{len(exposed)-5} more"))
    fb = f"{len(exposed)} sensitive path(s) exposed — internal files or configuration may be accessible to attackers." if exposed else "No sensitive files or configuration paths are publicly accessible."
    parts = build_cat_card("Information Disclosure", col, f"{score}%",
                          rows, info.get("issues", []), S, fallback=fb)
    parts += waf_truncation_note(info, S)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if exposed:
        parts.append(Paragraph(
            f"{len(exposed)} path(s) were found that may expose sensitive information such as configuration files, "
            "version control data (.git), environment files (.env), or backup files. These files can reveal "
            "database credentials, API keys, internal architecture, and other information that significantly "
            "aids attackers in planning targeted attacks.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Block access to all exposed sensitive paths in your web server configuration.", S["body"]))
        parts.append(Paragraph("2. Remove .git, .env, and backup files from the public web root entirely.", S["body"]))
        parts.append(Paragraph("3. Audit server configuration to prevent directory listing and file enumeration.", S["body"]))
    else:
        parts.append(Paragraph(
            "No sensitive configuration files, version control data, or backup files were found accessible "
            "from the public website. This reduces the risk of information leakage to attackers.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_fraudulent_domains(d, S):
    fd     = d.get("fraudulent_domains", {})
    found  = fd.get("resolved_count", 0)
    col    = C_CRITICAL if found > 3 else (C_RED if found > 0 else C_GREEN)
    rows   = [
        ("Variants checked",  fd.get("total_permutations", 0)),
        ("Lookalikes found",  found),
    ]
    for dom in fd.get("fraudulent_domains", [])[:5]:
        sim = dom.get("similarity")
        sim_str = f" ({int(sim)}% similar)" if sim else ""
        rows.append((dom.get("technique", "lookalike"), f"{dom.get('domain','')}{sim_str}"))
    fb = f"{found} lookalike domain(s) detected — these could be used for phishing attacks against staff or customers." if found > 0 else "No active lookalike domains detected — low brand impersonation risk."
    parts = build_cat_card("Fraudulent Domains (Typosquat)", col, f"{found} found", rows, fd.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if found > 0:
        parts.append(Paragraph(
            f"{found} domain(s) that closely resemble your organisation's domain were found with active DNS records "
            "or SSL certificates. These lookalike domains are commonly used in phishing attacks — attackers register "
            "domains like 'yourdoma1n.com' or 'yourdomain-secure.com' to trick staff or clients into entering "
            "credentials on a fake login page.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Investigate each lookalike domain to determine if it is being used for phishing.", S["body"]))
        parts.append(Paragraph("2. Submit takedown requests to the registrars of confirmed malicious domains.", S["body"]))
        parts.append(Paragraph("3. Register common typo variants of your domain defensively to prevent future abuse.", S["body"]))
        parts.append(Paragraph("4. Alert staff to the existence of these lookalike domains and reinforce phishing awareness.", S["body"]))
    else:
        parts.append(Paragraph(
            "No active lookalike domains were detected. This means no one has registered domains that closely "
            "mimic your brand for phishing purposes. Consider defensively registering common typo variants "
            "to maintain this position.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_related_domains(d, S):
    rd = d.get("related_domains", {})
    if rd.get("status") == "skipped" or rd.get("declared_count", 0) == 0:
        return not_assessed_card(
            "Supply-Chain / Related Domains",
            "Not assessed — no related or supplier domains were declared by the "
            "broker for this scan, so sibling-domain exposure (shared "
            "infrastructure, weakest-link pivots) was not evaluated. Declare "
            "related domains on the scan form to include this surface; "
            "auto-discovery from certificate SANs is on the v1.2 roadmap.", S)
    declared = rd.get("declared_count", 0)
    scanned  = rd.get("scanned_count", 0)
    crit     = rd.get("critical_count", 0)
    high     = rd.get("high_count", 0)
    col      = C_CRITICAL if crit > 0 else (C_RED if high > 0 else C_GREEN)
    rows = [
        ("Declared siblings", declared),
        ("Scanned",           scanned),
        ("Critical findings", crit),
        ("High-risk siblings", high),
    ]
    worst = rd.get("worst_domain") or {}
    if worst:
        rows.append(("Weakest sibling",
                     f"{worst.get('domain','')} (LITE score {worst.get('lite_score',100)}/100)"))
    for dep in (rd.get("dependants") or [])[:5]:
        rows.append((dep.get("domain", ""),
                     f"LITE score {dep.get('lite_score',100)}/100"
                     f"{' — '+str(dep.get('critical_paths'))+' critical path(s)' if dep.get('critical_paths') else ''}"))
    fb = (f"{crit} critical finding(s) across {scanned} declared related domain(s) — review supplier security posture."
          if crit > 0 else
          (f"{high} of {scanned} declared related domain(s) score below 60 — review supplier security posture."
           if high > 0 else
           f"{scanned} declared related domain(s) scanned — no critical findings."))
    parts = build_cat_card("Supply-Chain / Related Domains", col,
                          f"{scanned} scanned, {crit} critical",
                          rows, rd.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if crit > 0 or high > 0:
        parts.append(Paragraph(
            f"{scanned} domain(s) declared by the broker as related entities or suppliers were scanned in LITE "
            "mode (SSL, DNS-port exposure, and information disclosure). Findings on these domains can be imputed "
            "to the insured under aggregator / supplier-liability theory — a breach at any of them may trigger "
            "civil claims even when the insured's own perimeter is clean.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Engage each high-risk sibling to remediate the specific findings (LITE score &lt; 60).", S["body"]))
        parts.append(Paragraph("2. Add a security-posture clause to supplier / inter-company agreements.", S["body"]))
        parts.append(Paragraph("3. Re-scan affected siblings after remediation and confirm score recovery.", S["body"]))
    else:
        parts.append(Paragraph(
            f"All {scanned} declared related domain(s) passed the LITE-mode supplier checks. Continue to "
            "include siblings in the supply-chain scope of future scans so degradations are caught early.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dependency_manifests(d, S):
    dm = d.get("dependency_manifests", {})
    if dm.get("status") not in ("completed",):
        return []
    manifests = dm.get("exposed_manifests", []) or []
    crit = dm.get("critical_count", 0)
    high = dm.get("high_count", 0)
    crit_cves = dm.get("total_critical_cves", 0)
    total_cves = dm.get("total_cves", 0)
    if not manifests:
        col = C_GREEN
    else:
        col = C_CRITICAL if (crit > 0 or crit_cves > 0) else C_RED
    rows = [
        ("Manifests exposed",    len(manifests)),
        ("Lockfiles (critical)", crit),
        ("Manifests (high)",     high),
        ("Ecosystems",           ", ".join(dm.get("ecosystems", [])) or "—"),
        ("Total dependencies",   dm.get("total_dependencies", 0)),
    ]
    if dm.get("osv_lookups_done", 0) > 0:
        rows.append((
            "OSV.dev cross-reference",
            f"{total_cves} CVE(s) ({crit_cves} critical/high) "
            f"across {dm.get('osv_lookups_done', 0)} version queries",
        ))
        for cve in (dm.get("top_critical_cves") or [])[:5]:
            rows.append((
                f"  {cve.get('cve_id', '')}",
                f"{cve.get('package','')} {cve.get('version','')} "
                f"({cve.get('severity','')}, CVSS {cve.get('cvss_score', 0)})",
            ))
    for m in manifests[:5]:
        rows.append((m.get("path", ""),
                     f"{m.get('ecosystem','')} · {m.get('dependency_count',0)} dep(s) · {m.get('severity','')}"))
    if crit_cves > 0:
        fb = (f"{crit_cves} critical/high-severity CVE(s) cross-referenced "
              f"via OSV.dev across {len(manifests)} exposed manifest(s) — "
              "actionable patch targets.")
    elif manifests:
        fb = (f"{len(manifests)} dependency manifest(s) exposed — exact "
              "versions are now public and CVE-chainable.")
    else:
        fb = "No dependency manifests exposed at common web-root paths."
    parts = build_cat_card("Exposed Dependency Manifests", col,
                          f"{len(manifests)} exposed", rows,
                          dm.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if manifests:
        parts.append(Paragraph(
            f"{len(manifests)} dependency manifest file(s) were found publicly accessible at the web root. "
            "Lockfiles (package-lock.json, composer.lock, Gemfile.lock, requirements.txt with pinned "
            "versions) expose the exact version of every dependency — an attacker can feed this directly into "
            "OSV.dev / NVD to compile a list of known-exploitable CVEs without any reconnaissance effort.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Block public access to the exposed manifest paths in your web server config (deny .json / lock files at the root).", S["body"]))
        parts.append(Paragraph("2. Confirm build / deploy pipelines do not ship lockfiles to the public web root.", S["body"]))
        parts.append(Paragraph("3. Audit the disclosed dependency list against known CVEs and patch the high-severity items first.", S["body"]))
    else:
        parts.append(Paragraph(
            "No dependency manifests were found at the common web-root paths (package.json, composer.json, "
            "requirements.txt, etc.). This is the expected configuration and prevents attackers from "
            "harvesting your exact dependency versions for CVE chaining.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_third_party_js(d, S):
    tpjs = d.get("third_party_js", {})
    if tpjs.get("status") not in ("completed",):
        return not_assessed_card(
            "Third-Party JavaScript",
            "Not assessed — the homepage could not be retrieved (commonly a "
            "WAF / bot-manager block on scanner traffic), so third-party script "
            "exposure (Magecart-style injection, missing SRI hashes) was not "
            "evaluated on this scan.", S)
    total       = tpjs.get("total_scripts", 0)
    third       = tpjs.get("third_party_count", 0)
    no_sri      = tpjs.get("missing_sri_count", 0)
    compromised = tpjs.get("compromised_host_count", 0)
    col = C_CRITICAL if compromised > 0 else (C_RED if (third > 0 and no_sri == third) else
          (C_AMBER if no_sri > 0 else C_GREEN))
    rows = [
        ("Scripts on homepage",      total),
        ("Third-party scripts",      third),
        ("Missing SRI hash",         no_sri),
        ("Known-compromised hosts",  compromised),
    ]
    for h in (tpjs.get("third_party_hosts") or [])[:6]:
        label = h.get("host", "")
        if h.get("known_cdn"):
            label += " · CDN"
        rows.append((label, f"{h.get('count', 0)} script(s)"))
    for c in (tpjs.get("compromised_scripts") or [])[:3]:
        rows.append((f"  COMPROMISED: {c.get('host','')}", c.get("reason", "")))
    fb = (f"{compromised} script(s) from known-compromised CDN(s) — replace immediately."
          if compromised > 0 else
          (f"{no_sri} of {third} third-party scripts lack Subresource Integrity — supply-chain tampering risk."
           if no_sri > 0 else
           f"{third} third-party script(s) loaded with SRI integrity hashes — supply-chain controls in place."))
    parts = build_cat_card("Third-Party JavaScript", col,
                          f"{third} third-party, {no_sri} missing SRI",
                          rows, tpjs.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if compromised > 0 or no_sri > 0:
        parts.append(Paragraph(
            "Every external script loaded into your pages runs with the same privileges as your own code — "
            "it can read forms, intercept payment fields, and exfiltrate data. Subresource Integrity (SRI) "
            "hashes pin each script to a known good version, so a hijack of the upstream CDN (Magecart 2018, "
            "polyfill.io 2024) cannot silently replace the script. Missing SRI on third-party scripts is the "
            "single biggest predictor of card-skimming and form-skimming breaches.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        if compromised > 0:
            parts.append(Paragraph("1. Replace scripts from known-compromised CDNs immediately — these are confirmed supply-chain incidents.", S["body"]))
            parts.append(Paragraph("2. Pin all remaining third-party scripts with SRI integrity attributes (sha384 hashes).", S["body"]))
            parts.append(Paragraph("3. Move payment / login pages to a strict Content-Security-Policy that disallows unpinned external scripts.", S["body"]))
        else:
            parts.append(Paragraph("1. Add Subresource Integrity (integrity=\"sha384-...\") attributes to every third-party script tag.", S["body"]))
            parts.append(Paragraph("2. Configure a Content-Security-Policy that disallows scripts without integrity hashes on sensitive pages.", S["body"]))
            parts.append(Paragraph("3. Periodically review the list of third-party origins and remove ones that are no longer needed.", S["body"]))
    else:
        parts.append(Paragraph(
            "All third-party scripts on the homepage carry Subresource Integrity hashes, so a hijack of any "
            "upstream CDN cannot silently swap them out. Maintain this control by adding SRI hashes to every "
            "new third-party script and tracking integrity-mismatch failures in error logging.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_email_vendor_surface(d, S):
    evs = d.get("email_vendor_surface", {})
    if evs.get("status") not in ("completed",):
        return []
    vendors    = evs.get("vendors_detected", []) or []
    count      = evs.get("vendor_count", 0)
    weak_dmarc = evs.get("weak_dmarc", False)
    policy     = evs.get("dmarc_policy") or "missing"
    col = C_RED if (weak_dmarc and count >= 1) else (
          C_AMBER if count >= 6 else (C_AMBER if count >= 3 else C_GREEN))
    rows = [
        ("Email vendors in SPF chain", count),
        ("Unknown includes",           evs.get("unknown_count", 0)),
        ("DMARC policy",               policy),
    ]
    for v in vendors[:8]:
        rows.append((v.get("vendor", ""), ", ".join(v.get("includes", []))))
    fb = (f"{count} email-vendor(s) in SPF chain with weak DMARC (p={policy}) — phishing-via-supplier risk."
          if (weak_dmarc and count >= 1) else
          (f"{count} email-vendor(s) detected in SPF chain — wide fourth-party surface."
           if count >= 6 else
           f"{count} email-vendor(s) detected — DMARC policy: {policy}."))
    parts = build_cat_card("Email-Vendor Surface (SPF)", col,
                          f"{count} vendor(s), DMARC p={policy}",
                          rows, evs.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if weak_dmarc and count >= 1:
        parts.append(Paragraph(
            f"Your SPF record authorises {count} third-party email vendor(s) to send mail on your behalf. "
            f"With DMARC policy set to '{policy}', a credential compromise at any one of these vendors lands "
            "phishing emails in customer inboxes that pass authentication checks. This is the same attack "
            "class that drove the Mailchimp 2023 and Constant Contact 2021 incidents downstream into "
            "customer organisations.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Set DMARC policy to p=quarantine or p=reject to enforce vendor authentication.", S["body"]))
        parts.append(Paragraph("2. Audit each vendor — confirm which still need send authority and remove the rest.", S["body"]))
        parts.append(Paragraph("3. Monitor DMARC aggregate reports for anomalous vendor sending patterns.", S["body"]))
    elif count >= 6:
        parts.append(Paragraph(
            f"Your SPF chain authorises {count} third-party email vendors — every one of them is implicitly "
            "trusted to send mail as your domain. A wide vendor surface multiplies fourth-party breach "
            "exposure: a breach at any single vendor (Mailchimp, Okta, Microsoft 365 etc.) becomes a "
            "phishing path into your customer base.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Audit the vendor list — remove SPF includes for vendors no longer in use.", S["body"]))
        parts.append(Paragraph("2. Confirm DMARC is set to p=quarantine or p=reject and TLS-RPT is enabled.", S["body"]))
        parts.append(Paragraph("3. Use sub-domain delegation (e.g. marketing.yourdomain.com) to compartmentalise vendor authority.", S["body"]))
    else:
        parts.append(Paragraph(
            f"Your SPF chain authorises {count} email vendor(s) with DMARC policy '{policy}' — a focused "
            "vendor surface with proper authentication enforcement. Continue to review the vendor list "
            "during quarterly compliance reviews so unused authorisations are removed.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_cms_plugin_sbom(d, S):
    cms = d.get("cms_plugin_sbom", {})
    if cms.get("status") == "skipped" or not cms.get("is_wordpress"):
        return []
    plugins = cms.get("plugins_detected", []) or []
    versioned = cms.get("versioned_count", 0)
    count = cms.get("plugin_count", 0)
    col = C_RED if versioned >= 3 else (C_AMBER if count >= 5 else C_GREEN)
    rows = [
        ("WordPress detected", "Yes"),
        ("Plugins detected",   count),
        ("Versions readable",  versioned),
    ]
    for p in plugins[:8]:
        ver = p.get("version") or "—"
        rows.append((p.get("slug", ""), f"version {ver}" if ver != "—" else "directory enumerable"))
    fb = (f"{versioned} WordPress plugin version(s) readable — directly CVE-chainable."
          if versioned > 0 else
          (f"{count} popular WordPress plugin(s) detected — wide CMS attack surface."
           if count >= 5 else
           f"{count} popular WordPress plugin(s) detected — limited CMS attack surface."))
    parts = build_cat_card("CMS Plugin Surface (WordPress)", col,
                          f"{count} plugin(s), {versioned} versioned",
                          rows, cms.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if versioned > 0 or count >= 5:
        parts.append(Paragraph(
            f"This site is running WordPress with at least {count} popular plugin(s) detectable by external "
            f"probing, and {versioned} of them publish their version string in readme.txt. Outdated WordPress "
            "plugins are the top external ransomware entry vector for SA SMEs — attackers automate scans for "
            "specific plugin slugs at version-strings with public CVEs (e.g. Revolution Slider 4.x, "
            "WooCommerce &lt; 4.9, Contact Form 7 &lt; 5.3).",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Update every detected plugin to its latest version and enable automatic security updates where supported.", S["body"]))
        parts.append(Paragraph("2. Remove plugins no longer in use — every active plugin is attack surface even when patched.", S["body"]))
        parts.append(Paragraph("3. Block enumeration of /wp-content/plugins/ at the web-server level so version strings stop leaking.", S["body"]))
        parts.append(Paragraph("4. Deploy a WordPress-aware WAF (Wordfence, Patchstack) for virtual patching of plugin CVEs.", S["body"]))
    else:
        parts.append(Paragraph(
            "WordPress is in use but the public plugin surface is limited and version strings are not "
            "readable. Continue to apply plugin security updates promptly and prune unused plugins.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_credential_remediation(d, S, brief=False):
    """Masked staff accounts + services captured from infected devices +
    infection metadata. NO passwords — the complete list with passwords is only
    ever the on-demand encrypted export (User Manual section 6.4). brief=True
    shows a couple of examples (broker summary); brief=False enumerates (full
    report)."""
    n_acc = 3 if brief else 40
    n_svc = 3 if brief else 12
    de = d.get("dehashed", {}) or {}
    hr = d.get("hudson_rock", {}) or {}
    masked = de.get("staff_accounts_masked", []) or []
    staff_total = int(de.get("staff_accounts_total", 0) or 0)
    services = hr.get("compromised_services", []) or []
    svc_total = int(hr.get("compromised_services_total", 0) or 0)
    fam = hr.get("stealer_families", []) or []
    if not masked and not services:
        return []
    rows = []
    if staff_total:
        rows.append(("Staff accounts exposed", str(staff_total)))
    if hr.get("most_recent_compromise"):
        rows.append(("Most recent infection",
                     f"{hr.get('most_recent_compromise')} ({hr.get('days_since_compromise')} day(s) ago)"))
    if fam:
        rows.append(("Stealer families", ", ".join(fam[:6])))
    if svc_total:
        rows.append(("Services with captured logins", str(svc_total)))
    fb = ("Remediation detail for the affected accounts and systems. Identifiers are "
          "partially masked; the complete list (with passwords) is available on request "
          "as an encrypted export, with client consent.")
    title = "Credential Exposure — Examples" if brief else "Credential Remediation Detail"
    parts = build_cat_card(title, C_RED,
                           f"{staff_total} account(s)", rows, [], S, fallback=fb)
    if masked:
        hdr = ("Examples of affected staff accounts (masked):" if brief
               else "Affected staff accounts (masked — force a reset on each):")
        parts.append(Paragraph(f"<b>{hdr}</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        shown = masked[:n_acc]
        more = f" … and {staff_total - len(shown)} more" if staff_total > len(shown) else ""
        parts.append(Paragraph(", ".join(shown) + more, S["body"]))
        parts.append(Spacer(1, 2 * mm))
    if services:
        hdr = ("Examples of services captured from infected devices:" if brief
               else "Services captured from infected devices (rotate / re-issue first):")
        parts.append(Paragraph(f"<b>{hdr}</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for s in services[:n_svc]:
            parts.append(Paragraph(f"• {s.get('url', '')} ({s.get('occurrence', 0)}×)", S["body"]))
        if svc_total > n_svc:
            parts.append(Paragraph(f"… and {svc_total - n_svc} more service(s).", S["body_muted"]))
        parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph(
        "<i>No passwords appear in this report. The complete list including passwords is "
        "delivered only on request, with signed client consent, as an encrypted file.</i>",
        S["body_muted"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_credential_correlation(d, S):
    """Credential-compromise cross-correlation card (reporting-only). Mirrors
    cat_third_party_correlation; verdict + dynamic narrative come straight from
    build_credential_correlation()."""
    cc = d.get("credential_correlation", {})
    if cc.get("status") != "completed":
        return []
    sev = cc.get("severity", "none")
    sig = cc.get("signals", {}) or {}
    col = (C_CRITICAL if sev == "critical" else
           (C_RED if sev == "high" else
            (C_AMBER if sev == "medium" else C_GREEN)))
    rec = int(sig.get("breached_records", 0) or 0)
    pw_n = int(sig.get("password_records", 0) or 0)
    pw = (f" ({pw_n:,} with passwords)" if pw_n
          else (" (some with passwords)" if sig.get("has_passwords") else ""))
    srcs = ", ".join(sig.get("sources", []) or [])
    rows = [
        ("Verdict", sev.upper()),
        ("Breached records", f"{rec:,}{pw}" + (f" — {srcs}" if srcs else "") if rec else "0"),
        ("Active infostealer theft",
         (f"{sig.get('infostealer_employees', 0)} employee + "
          f"{int(sig.get('infostealer_users', 0) or 0):,} user device(s)"
          + ((f" — last infection {sig.get('infostealer_days_ago')}d ago"
              + ("" if sig.get('active_theft_fresh') else " (aged)"))
             if sig.get('infostealer_days_ago') is not None else "")
          if sig.get("active_theft") else "None")),
        ("Active circulation (forum / dump)",
         (f"{sig.get('intelx_leak', 0)} leak / {sig.get('intelx_paste', 0)} paste / "
          f"{sig.get('intelx_darkweb', 0)} dark-web mention(s)"
          + (" — may include re-circulated data" if sig.get('combo_only') else "")
          if sig.get("circulating") else
          ("monitoring pending" if not sig.get("forum_available") else "None"))),
    ]
    fa = sig.get("freshest_age_days")
    if fa is not None:
        rows.append(("Freshest exposure", f"{fa} day(s) ago"))
    bands = cc.get("recency_bands", {}) or {}
    if cc.get("dated_records"):
        rows.append(("Recency timeline", "  ".join(
            f"{b}:{bands.get(b, 0)}" for b in
            ("<30d", "30-90d", "90-180d", "180-360d", "1-2yr", ">2yr"))))
    fb = (cc.get("issues") or [""])[0]
    parts = build_cat_card(
        "Credential Exposure Correlation (DeHashed × Recency × Infostealer × IntelX)",
        col, sev.upper(), rows, cc.get("issues", []), S, fallback=fb)
    if cc.get("rationale"):
        parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(cc["rationale"], S["body"]))
        parts.append(Spacer(1, 3 * mm))
    return parts


def cat_third_party_correlation(d, S):
    tpc = d.get("third_party_correlation", {})
    if tpc.get("status") not in ("completed",):
        return []
    sev = tpc.get("severity", "medium")
    hr_n = tpc.get("hudson_rock_third_party_count", 0)
    spf_n = tpc.get("spf_vendor_count", 0)
    susp = tpc.get("suspected_vendors", []) or []
    col = (C_CRITICAL if sev == "critical" else
           (C_RED if sev == "high" else C_AMBER))
    rows = [
        ("Severity", sev.upper()),
        ("Hudson Rock third-party exposures", hr_n),
        ("S-4 vendors in SPF chain", spf_n),
        ("S-5 breach overlap (suspected rotate-targets)", len(susp)),
    ]
    for s in susp[:5]:
        breaches = s.get("breaches") or []
        dates = ", ".join(b.get("date", "") for b in breaches[:3])
        rows.append((
            f"  {s.get('vendor', '?')}",
            f"{len(breaches)} breach(es) — most recent: {dates or '?'}",
        ))
    # A vendor-breach overlap (susp) drives severity off the WORST underlying
    # breach — so an overlap can be medium/high/critical, not blanket critical.
    if susp:
        fb = (f"{sev.upper()}: {hr_n} HR exposure(s) cross-correlate with "
              f"{len(susp)} breached vendor(s) in your SPF chain "
              f"(worst severity: {sev}).")
    elif spf_n > 0:
        fb = f"HIGH: {hr_n} HR exposure(s) + {spf_n} SPF vendor(s); no S-5 overlap to narrow scope."
    else:
        fb = f"MEDIUM: {hr_n} HR exposure(s) detected; no SPF / breach overlap."
    parts = build_cat_card("Third-Party Cross-Correlation (HR × SPF × Breach)",
                            col, sev.upper(), rows,
                            tpc.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if susp:
        vendor_names = ", ".join(s.get("vendor", "?") for s in susp[:5])
        # Closing urgency tracks the WORST underlying breach severity — a
        # medium-class vendor incident is reviewed, not treated as a live
        # compromise (avoids over-escalating benign overlaps).
        if sev in ("critical", "high"):
            _closing = ("these specific vendors are the most likely source of the "
                        "Hudson Rock harvest and should be treated as already "
                        "compromised until credentials are rotated.")
        else:
            _closing = (f"the underlying vendor breach(es) are {sev}-severity, so "
                        "these vendors should be reviewed and credentials rotated "
                        "as a precaution rather than treated as a confirmed live "
                        "compromise.")
        parts.append(Paragraph(
            "Three independent signals align on vendor-channel credential risk: "
            f"Hudson Rock reports {hr_n} infostealer-harvested credential record(s) "
            "for third-party services accessed from this organisation's machines; "
            f"the SPF chain authorises {spf_n} email vendor(s); and {len(susp)} of "
            f"those vendor(s) ({vendor_names}) have confirmed public breaches in "
            "the curated database. The intersection narrows the rotate-list to "
            f"high-probability targets — {_closing}",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        _urgency = "TODAY: " if sev in ("critical", "high") else ""
        parts.append(Paragraph(
            f"1. {_urgency}rotate all API keys, OAuth tokens, and SSO session "
            f"secrets at: {vendor_names}.", S["body"]))
        parts.append(Paragraph(
            "2. Force MFA re-enrolment for all staff with accounts at the "
            "above vendor(s).", S["body"]))
        parts.append(Paragraph(
            "3. Audit recent login records at these vendor(s) for unusual "
            "geographies / impossible-travel anomalies.", S["body"]))
        parts.append(Paragraph(
            "4. Engage incident response if any vendor shows unrecognised "
            "activity in the past 90 days.", S["body"]))
    elif sev == "high":
        parts.append(Paragraph(
            f"Hudson Rock reports {hr_n} third-party credential exposure(s) "
            f"for this organisation, and {spf_n} email vendor(s) are detected "
            "in the SPF chain. No vendor-breach overlap (S-5) was found, so the "
            "rotate-list cannot be narrowed via cross-correlation — review "
            "credentials at all detected vendors as a precaution.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "1. Review credentials at all detected SPF vendors and rotate where "
            "MFA is not enforced.", S["body"]))
        parts.append(Paragraph(
            "2. Expand the curated vendor_breaches.json database to include "
            "any of the detected vendors that have public breach history not "
            "yet catalogued.", S["body"]))
    else:
        parts.append(Paragraph(
            f"Hudson Rock reports {hr_n} third-party credential exposure(s) "
            "for this organisation. No SPF vendor surface or breach matches to "
            "cross-reference; broker should review the insured's SaaS inventory "
            "manually to identify the most likely affected vendors.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_vendor_breach(d, S):
    vb = d.get("vendor_breach", {})
    if vb.get("status") not in ("completed",):
        return []
    matches = vb.get("matches", []) or []
    crit = vb.get("critical_match_count", 0)
    high = vb.get("high_match_count", 0)
    col = C_CRITICAL if crit > 0 else (C_RED if high > 0 else (C_AMBER if matches else C_GREEN))
    rows = [
        ("Vendors in SPF chain",    len(vb.get("vendors_detected", []) or [])),
        ("Breach matches",          len(matches)),
        ("Critical severity",       crit),
        ("High severity",           high),
    ]
    for m in matches[:6]:
        months = max(1, (m.get("age_days") or 0) // 30)
        rows.append((f"{m.get('vendor','')} ({m.get('severity','')})",
                     f"{m.get('date','')} · ~{months} mo · {m.get('exposure_class','')}"))
    fb = (
        f"{crit} critical-severity breach(es) at vendor(s) in your email send-authority chain — review credential rotation."
        if crit > 0 else
        (f"{high} high-severity breach(es) at vendor(s) in your email send-authority chain."
         if high > 0 else
         ("Vendor surface matched against breach DB — no severe incidents within the lookback window."
          if vb.get("vendors_detected") else
          "No vendor surface detected in SPF chain — no correlation possible."))
    )
    parts = build_cat_card("Vendor Breach Correlation", col,
                          f"{len(matches)} match(es)", rows,
                          vb.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if matches:
        top = matches[0]
        months = max(1, (top.get("age_days") or 0) // 30)
        parts.append(Paragraph(
            f"At least one vendor in your email send-authority chain ({top.get('vendor','')}) suffered a "
            f"confirmed public-record breach approximately {months} month(s) ago "
            f"({top.get('date','')}, {top.get('severity','')}, {top.get('exposure_class','')}). "
            "Customer-key and token rotation after a vendor breach is typically incomplete even years later, "
            "so any credentials, API keys or session tokens shared with this vendor at the time of incident "
            "should be treated as potentially compromised until proven otherwise.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Rotate any API keys, OAuth tokens and service-account credentials issued to the affected vendor since the incident date.", S["body"]))
        parts.append(Paragraph("2. Force re-authentication for staff accounts that used the vendor for SSO or session storage.", S["body"]))
        parts.append(Paragraph("3. Confirm the vendor's post-incident hardening and ensure your contract reflects current security expectations.", S["body"]))
        parts.append(Paragraph("4. Monitor DMARC and audit logs for anomalous activity that pre-dates the rotation date.", S["body"]))
    elif vb.get("vendors_detected"):
        parts.append(Paragraph(
            "Your detected email vendors were correlated against the curated public-record breach database "
            "and no severe incidents fell inside the lookback window. Continue to monitor each vendor's "
            "advisories and re-scan periodically — new disclosures will update this view.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No third-party email vendors were detected in the SPF chain, so there is no fourth-party "
            "vendor-breach exposure to correlate at this time.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_rsi(results, S):
    """RSI (Ransomware Susceptibility Index) card for PDF — insurance analytics."""
    ins = results if "rsi" in results else results.get("insurance", {})
    rsi = ins.get("rsi", {})
    score = rsi.get("rsi_score", 0)
    col = C_CRITICAL if score >= 0.75 else (C_RED if score >= 0.50 else (C_AMBER if score >= 0.25 else C_GREEN))
    rows = [
        ("RSI Score", f"{score:.3f} / 1.000"),
        ("Risk Label", rsi.get("risk_label", "Unknown")),
        ("Base Score", f"{rsi.get('base_score', 0):.3f}"),
        ("Industry", f"{rsi.get('industry', 'other').capitalize()} (×{rsi.get('industry_multiplier', 1.0)})"),
        ("Size Multiplier", f"×{rsi.get('size_multiplier', 1.0)}"),
    ]
    for f in rsi.get("contributing_factors", [])[:8]:
        rows.append((f"  P{f['priority']}: {f['factor']}", f"+{f['impact']:.2f}"))
    fb = f"RSI score of {score:.2f} — {'high ransomware susceptibility, prioritise remediation steps below.' if score >= 0.50 else 'moderate risk, review contributing factors.' if score >= 0.25 else 'low ransomware susceptibility based on current external posture.'}"
    parts = build_cat_card("Ransomware Susceptibility Index (RSI)", col,
                          f"{score:.2f} — {rsi.get('risk_label', '')}",
                          rows, [], S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 0.75:
        parts.append(Paragraph(
            "This organisation has a high ransomware susceptibility score, driven by the contributing factors listed "
            "above. Multiple external risk indicators align with the attack patterns commonly seen in successful "
            "ransomware incidents. Immediate remediation of the highest-priority factors is strongly recommended.",
            S["body"]))
    elif score >= 0.50:
        parts.append(Paragraph(
            "Moderate-to-high ransomware susceptibility. Several external risk factors were identified that, "
            "in combination, create meaningful exposure to ransomware attacks. Addressing the top contributing "
            "factors would materially reduce this risk.",
            S["body"]))
    elif score >= 0.25:
        parts.append(Paragraph(
            "Moderate ransomware susceptibility. Some risk factors are present but the overall external posture "
            "provides reasonable protection. Address contributing factors during planned maintenance cycles.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Low ransomware susceptibility based on externally observable indicators. The organisation's external "
            "security posture does not exhibit the common risk patterns associated with ransomware victims.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dbi(results, S):
    """Data Breach Index card for PDF — insurance analytics."""
    ins = results if "dbi" in results else results.get("insurance", {})
    dbi = ins.get("dbi", {})
    score = dbi.get("dbi_score", 50)
    col = _tl(score >= 80, score >= 40)
    rows = [("DBI Score", f"{score}/{dbi.get('max_score', 100)} — {dbi.get('label', '')}")]
    for key, comp in dbi.get("components", {}).items():
        rows.append((key.replace("_", " ").capitalize(), f"{comp.get('value', '')} ({comp.get('points', 0)}/{comp.get('max', 0)} pts)"))
    fb = f"DBI score {score}/100 — {'strong data breach resilience.' if score >= 80 else 'moderate breach resilience, review component scores.' if score >= 40 else 'weak breach resilience, multiple exposure factors identified.'}"
    parts = build_cat_card("Data Breach Index (DBI)", col,
                          f"{score}/100 — {dbi.get('label', '')}",
                          rows, [], S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "The Data Breach Index (DBI) measures the organisation's resilience to data breach events based on "
        "externally observable factors including credential exposure, encryption strength, data handling practices, "
        "and breach history. A higher score indicates stronger resilience. Component scores above show which "
        "areas contribute most to the overall rating.",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_remediation(results, S):
    """Remediation Roadmap card for PDF — insurance analytics."""
    ins = results if "remediation" in results else results.get("insurance", {})
    rem = ins.get("remediation", {})
    steps = rem.get("steps", [])
    if not steps:
        return []
    col = C_BLUE

    # Rand savings are deliberately NOT shown here: the expected-loss card
    # ("Risk Mitigation Recommendations") is the single Rand-savings
    # authority. Two adjacent cards quoting different savings totals for the
    # same fixes read as a contradiction to brokers (back-test finding #16).
    rows = [
        ("Current RSI", f"{rem.get('current_rsi', 0):.3f}"),
        ("Projected RSI (after fixes)", f"{rem.get('simulated_rsi', 0):.3f}"),
        ("RSI-point reduction", f"{rem.get('rsi_improvement', 0):.3f}"),
        ("", ""),
    ]
    for i, step in enumerate(steps[:10], 1):
        rsi_red = step.get("rsi_reduction", 0)
        rows.append((f"#{i} (P{step['priority']})",
                     f"{step['action']} — RSI &minus;{rsi_red:.2f}"))
    fb = f"{len(steps)} prioritised remediation steps reduce the Ransomware Susceptibility Index from {rem.get('current_rsi', 0):.3f} to {rem.get('simulated_rsi', 0):.3f}."
    parts = build_cat_card("Remediation Roadmap — RSI Prioritisation", col,
                          f"{len(steps)} steps — RSI {rem.get('current_rsi', 0):.2f} → {rem.get('simulated_rsi', 0):.2f}",
                          rows, [], S, fallback=fb)
    parts.append(Paragraph(
        "<i>Methodology: this roadmap orders fixes by their effect on the Ransomware Susceptibility "
        "Index (RSI) — what to fix first. The Rand value of remediation (current vs mitigated annual "
        "loss and per-finding savings) is modelled once, on the \"Risk Mitigation Recommendations "
        "(Expected-Loss)\" card, so a single savings figure carries through the report.</i>",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


# NOTE: the legacy `cat_ransomware_risk` and `cat_data_breach_index` renderers
# were removed (2026-06-02 back-test). They read stale key shapes
# (`ransomware_risk`/`rsi_label`, `data_breach_index`/`dbi_label`/flat fields)
# that the live calculators never produce, and were never wired into the story.
# The live cards are `cat_rsi` (insurance.rsi) and `cat_dbi` (insurance.dbi).


def cat_financial_impact(d, S):
    fin = d.get("financial_impact", {})
    # Accept ZAR results (currency key present) or legacy completed status
    if not fin or (not fin.get("currency") and fin.get("status") != "completed"):
        rows = [
            ("Status", "Financial impact analysis requires annual revenue input"),
            ("", "Re-run this assessment with annual revenue (ZAR) to generate:"),
            ("", "\u2022 Estimated annual cyber loss (min/likely/max scenarios)"),
            ("", "\u2022 Monte Carlo confidence intervals (10,000 simulations)"),
            ("", "\u2022 Insurance coverage recommendations (minimum and recommended)"),
            ("", "\u2022 Per-finding cost reduction estimates"),
        ]
        return build_cat_card("Financial Impact Analysis", C_BLUE, "Revenue required", rows, [], S, fallback="Annual revenue is required to calculate financial impact estimates.")

    is_zar = fin.get("currency") == "ZAR"
    cur    = "R" if is_zar else "$"
    sc     = fin.get("scenarios", {})
    sc4    = fin.get("scenarios_4cat", {})
    col    = C_CRITICAL if fin.get("score", 50) < 30 else (C_RED if fin.get("score", 50) < 50 else
              C_AMBER if fin.get("score", 50) < 70 else C_GREEN)

    if is_zar:
        eal    = fin.get("estimated_annual_loss", {})
        ins    = fin.get("insurance_recommendation", {})
        most_l = eal.get("most_likely", 0)
        mc     = fin.get("monte_carlo", {})
        mc_t   = mc.get("total", {})
        ci90   = mc.get("confidence_interval_90", {})
        ci50   = mc.get("confidence_interval_50", {})
        rows = [
            ("Industry",              fin.get("industry", "Other")),
            ("Annual Revenue",        f"{cur}&nbsp;{fin.get('annual_revenue_zar', 0):,.0f}"),
            ("",                      ""),
            ("Est. Annual Loss (Min)",    f"{cur}&nbsp;{eal.get('minimum', 0):,.0f}"),
            ("Est. Annual Loss (Likely)", f"{cur}&nbsp;{most_l:,.0f}"),
            ("Est. Annual Loss (Max)",    f"{cur}&nbsp;{eal.get('maximum', 0):,.0f}"),
            ("",                      ""),
        ]
        # Monte Carlo section - supporting detail. Headline loss exposure
        # scenarios are presented in the dedicated loss_exposure_scenarios_block
        # immediately after this card (renders as its own Table flowable).
        if mc_t:
            rows.extend([
                ("MONTE CARLO ANALYSIS",  f"{mc.get('iterations', 10000):,} simulations — PERT distribution"),
                ("  90% Confidence Interval", f"{cur}&nbsp;{ci90.get('lower', 0):,.0f} — {cur}&nbsp;{ci90.get('upper', 0):,.0f}"),
                ("  50% Confidence Interval", f"{cur}&nbsp;{ci50.get('lower', 0):,.0f} — {cur}&nbsp;{ci50.get('upper', 0):,.0f}"),
                ("",                      ""),
                ("  Reference percentiles",      ""),
                ("    P5  (low band)",           f"{cur}&nbsp;{mc_t.get('p5', 0):,.0f}"),
                ("    P25 (lower quartile)",     f"{cur}&nbsp;{mc_t.get('p25', 0):,.0f}"),
                ("    P75 (upper quartile)",     f"{cur}&nbsp;{mc_t.get('p75', 0):,.0f}"),
                ("    P95 (severe)",             f"{cur}&nbsp;{mc_t.get('p95', 0):,.0f}"),
                ("",                      ""),
                ("  Mean",                f"{cur}&nbsp;{mc_t.get('mean', 0):,.0f}"),
                ("  Std. Deviation",      f"{cur}&nbsp;{mc_t.get('std_dev', 0):,.0f}"),
                ("",                      ""),
            ])
            # Per-scenario MC breakdown — one compact line per scenario
            # (median + catastrophe tail). The headline aggregate scenarios
            # are in the dedicated Loss Exposure Scenarios table that renders
            # immediately after this card; per-scenario point losses appear
            # in the cost rows below. This avoids triple-disclosing the same
            # figures.
            for sname, slabel in [("data_breach", "Data Breach"), ("ransomware", "Ransomware"), ("business_interruption", "Bus. Interruption")]:
                smc = sc.get(sname, {}).get("monte_carlo", {})
                if smc:
                    rows.append((f"  {slabel} (MC)",
                                 f"P50 {cur}&nbsp;{smc.get('p50', 0):,.0f}"
                                 f"  ·  1-in-250 {cur}&nbsp;{smc.get('p99_6', 0):,.0f}"))
            rows.append(("", ""))

        rows.extend([
            ("Data Breach Loss",      f"{cur}&nbsp;{sc.get('data_breach', {}).get('estimated_loss', 0):,.0f}  (P={sc.get('data_breach', {}).get('probability', 0)})"),
            ("  POPIA regulatory",    f"{cur}&nbsp;{sc.get('data_breach', {}).get('regulatory_fine', 0):,.0f}"),
            ("Detection & Escalation", f"{cur}&nbsp;{sc4.get('detection_escalation', {}).get('estimated_loss', 0):,.0f}") if sc4 else ("", ""),
            ("Ransom Demand",         f"{cur}&nbsp;{sc4.get('ransom_demand', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})") if sc4 else ("Ransomware Loss", f"{cur}&nbsp;{sc.get('ransomware', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})"),
            ("Bus. Interruption",     f"{cur}&nbsp;{sc.get('business_interruption', {}).get('estimated_loss', 0):,.0f}  (indicative outage risk)"),
            ("",                      ""),
            ("Premium Risk Tier",     ins.get("premium_risk_tier", "N/A")),
            ("Cover Sizing",          "See Loss Exposure Scenarios above"),
        ])
    else:
        total  = fin.get("total", {})
        most_l = total.get("most_likely", 0)
        ins    = fin.get("insurance_recommendations", {})
        mc     = fin.get("monte_carlo", {})
        mc_t   = mc.get("total", {})
        ci90   = mc.get("confidence_interval_90", {})
        ci50   = mc.get("confidence_interval_50", {})
        rows = [
            ("Industry",              fin.get("industry", "Other")),
            ("",                      ""),
            ("Est. Annual Loss (Min)",    f"{cur}&nbsp;{total.get('min', 0):,.0f}"),
            ("Est. Annual Loss (Likely)", f"{cur}&nbsp;{most_l:,.0f}"),
            ("Est. Annual Loss (Max)",    f"{cur}&nbsp;{total.get('max', 0):,.0f}"),
            ("",                      ""),
        ]
        if mc_t:
            # Headline loss exposure scenarios are in the dedicated block;
            # this section keeps the supporting MC reference detail only.
            rows.extend([
                ("MONTE CARLO ANALYSIS",  f"{mc.get('iterations', 10000):,} simulations — PERT distribution"),
                ("  90% Confidence Interval", f"{cur}&nbsp;{ci90.get('lower', 0):,.0f} — {cur}&nbsp;{ci90.get('upper', 0):,.0f}"),
                ("  50% Confidence Interval", f"{cur}&nbsp;{ci50.get('lower', 0):,.0f} — {cur}&nbsp;{ci50.get('upper', 0):,.0f}"),
                ("",                      ""),
                ("  Reference percentiles",      ""),
                ("    P5  (low band)",           f"{cur}&nbsp;{mc_t.get('p5', 0):,.0f}"),
                ("    P25 (lower quartile)",     f"{cur}&nbsp;{mc_t.get('p25', 0):,.0f}"),
                ("    P75 (upper quartile)",     f"{cur}&nbsp;{mc_t.get('p75', 0):,.0f}"),
                ("    P95 (severe)",             f"{cur}&nbsp;{mc_t.get('p95', 0):,.0f}"),
                ("",                      ""),
                ("  Mean",                f"{cur}&nbsp;{mc_t.get('mean', 0):,.0f}"),
                ("  Std. Deviation",      f"{cur}&nbsp;{mc_t.get('std_dev', 0):,.0f}"),
                ("",                      ""),
            ])
        rows.extend([
            ("Data Breach",           f"{cur}&nbsp;{sc.get('data_breach', {}).get('most_likely', 0):,.0f}"),
            ("Ransomware",            f"{cur}&nbsp;{sc.get('ransomware', {}).get('most_likely', 0):,.0f}"),
            ("Bus. Interruption",     f"{cur}&nbsp;{sc.get('business_interruption', {}).get('most_likely', 0):,.0f}"),
            ("",                      ""),
            ("Suggested Deductible",  f"{cur}&nbsp;{ins.get('suggested_deductible', 0):,.0f}"),
            ("Cover Sizing",          "See Loss Exposure Scenarios above"),
        ])

    fb = f"Estimated most likely annual loss of {cur}&nbsp;{most_l:,.0f} based on hybrid quantitative risk model with Monte Carlo simulation."
    return build_cat_card("Financial Impact Analysis", col,
                          f"{cur}&nbsp;{most_l:,.0f}", rows, fin.get("issues", []), S, fallback=fb)


def loss_exposure_scenarios_block(d, S):
    """Dedicated Loss Exposure Scenarios table.

    Built from the schema-driven loss_exposure.scenarios dict in the JSON
    output. Presents Most Likely (mode) / Median (P50) / 1-in-100 / 1-in-200 /
    1-in-250 alongside annual exceedance probability. Used in both the
    summary and full report. Replaces the deprecated Insurance Cover
    Recommendation card (FAIS reasonable-advice compliance)."""
    fin = d.get("financial_impact", {})
    if not fin:
        return []
    is_zar = fin.get("currency") == "ZAR"
    cur = "R " if is_zar else "$"
    loss_exp = fin.get("loss_exposure", {})
    scenarios = loss_exp.get("scenarios", {})
    if not scenarios:
        return []

    # Fixed scenario order for consistent presentation
    scenario_order = ["most_likely", "median", "return_1_100", "return_1_200", "return_1_250"]
    # Column widths span full INNER_W to match the other tables in the
    # report (build_cat_card, build_summary_table). Previously the table
    # was 155mm of a 174mm content area — sat noticeably narrower than
    # neighbouring tables. Now totals INNER_W:
    #   Scenario: 65mm — fits "1-in-250 event (P99.6)" at 9pt with margin
    #   Modelled Loss: 55mm — fits "R 999,999,999,999"
    #   Annual Probability: INNER_W - 120mm — fills remaining ~54mm
    col_widths = [65 * mm, 55 * mm, INNER_W - 65 * mm - 55 * mm]

    table_data = [["Scenario", "Modelled Loss", "Annual Probability"]]
    for key in scenario_order:
        sc = scenarios.get(key)
        if not sc:
            continue
        label = sc.get("label", key)
        loss = sc.get("loss_zar", 0)
        prob = sc.get("annual_prob")
        if prob is None:
            # Only the mode row is the actual most-likely peak. The catastrophe
            # rows (return_1_*) are SEVERITY percentiles conditional on a severe
            # event (post-#15 severity-PML), not annual frequencies - an annual
            # probability does not apply, so show a dash rather than repeating
            # "Most likely (peak)" on every catastrophe row.
            prob_text = "Most likely (peak)" if key == "most_likely" else "\u2014"
        else:
            # Percentage with one-decimal precision for <1% per rule #8
            prob_pct = prob * 100
            if prob_pct >= 1:
                prob_text = f"{prob_pct:.0f}%"
            else:
                prob_text = f"{prob_pct:.1f}%"
        table_data.append([label, f"{cur}{loss:,.0f}", prob_text])

    table = Table(table_data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),   "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1),  9),
        # Match the cat-card title-bar styling used throughout the
        # rest of the document — light grey background with dark navy
        # text. The original bright C_BLUE header stood out as an
        # inconsistency (only this table used it; everything else
        # uses the C_GREY_1 / C_NAVY pairing).
        ("BACKGROUND",    (0, 0), (-1, 0),   C_GREY_1),
        ("TEXTCOLOR",     (0, 0), (-1, 0),   C_NAVY),
        ("LINEBELOW",     (0, 0), (-1, 0),   1.0, C_NAVY),
        ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
        ("ALIGN",         (1, 0), (-1, -1),  "RIGHT"),
        ("ALIGN",         (0, 0), (0, -1),   "LEFT"),
        ("LEFTPADDING",   (0, 0), (-1, -1),  8),
        ("RIGHTPADDING",  (0, 0), (-1, -1),  8),
        ("TOPPADDING",    (0, 0), (-1, -1),  5),
        ("BOTTOMPADDING", (0, 0), (-1, -1),  5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [colors.white, C_GREY_1]),
        ("BOX",           (0, 0), (-1, -1),  0.25, C_GREY_2),
        ("INNERGRID",     (0, 1), (-1, -1),  0.25, C_GREY_2),
        # Highlight the catastrophe rows
        ("FONTNAME",      (0, 3), (-1, 5),   "Helvetica-Bold"),
    ]))

    blocks = [
        Spacer(1, 3 * mm),
        Paragraph("<b>Loss Exposure Scenarios</b>", S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(
            "Modelled annual cyber loss across a range of severity scenarios, "
            "derived from a Monte Carlo simulation of incident-type cost components. "
            "Cover sizing should reflect the insured's risk appetite, contractual "
            "exposures, balance sheet capacity, and existing risk transfer arrangements.",
            S["body"]),
        Spacer(1, 2 * mm),
        table,
    ]

    # Coverage-adjusted tail disclosure — closes the loop between the
    # qualitative Partial Coverage Notice and the numeric loading applied
    # to the catastrophe percentiles when a WAF blinded the scan.
    cov = fin.get("coverage_adjustment", {}) or {}
    if cov.get("applied"):
        infl_pct = round((cov.get("tail_inflation_factor", 1.0) - 1.0) * 100)
        affected = cov.get("affected_checkers", []) or []
        names = ", ".join(a.replace("_", " ") for a in affected) if affected \
            else "several path-prober checkers"
        cov_txt = (
            f"<b>Coverage-adjusted tail.</b> The target's WAF / bot-manager "
            f"({cov.get('waf_kind', '').replace('_', ' ')}) prevented this scan "
            f"from verifying {len(affected)} checker(s) ({names}); scan coverage "
            f"was {cov.get('coverage_pct', 100)}%. Because an unverified checker "
            f"can only conceal loss-bearing findings, the catastrophe percentiles "
            f"above (1-in-100 / 1-in-200 / 1-in-250 and the P95 upper bound) have "
            f"been widened by approximately {infl_pct}% to reflect this "
            f"uncertainty. The most-likely and median figures are unchanged. "
            f"Absence of a finding in the affected checkers does not confirm "
            f"absence of the underlying risk — see the Partial Coverage Notice."
        )
        blocks += [Spacer(1, 2 * mm), Paragraph(cov_txt, S["body_muted"])]

    blocks.append(Spacer(1, 3 * mm))
    return blocks


def risk_probability_block(d, S):
    """Cyber-Risk Probability - reporting-only FAIR frequency view (item #17).

    Surfaces fin["risk_probability"]: THREE distinct, separately-graded annual-
    likelihood concepts - (1) total cyber-incident probability (nested ABOVE the
    breach figure), (2) data-breach probability, (3) an INDICATIVE availability
    resilience indicator. New presentation of already-scored signals (no scoring
    weight). Mirrors loss_exposure_scenarios_block styling."""
    fin = d.get("financial_impact", {})
    if not fin:
        return []
    rp = fin.get("risk_probability", {})
    if not rp:
        return []
    db = rp.get("data_breach", {})
    ci = rp.get("cyber_incident", {})
    av = rp.get("availability_resilience", {})

    col_widths = [98 * mm, 30 * mm, INNER_W - 98 * mm - 30 * mm]
    table_data = [
        ["Annual cyber-risk probability", "Likelihood", "Grade"],
        ["Total cyber-incident (breach + ransomware)",
         f"{ci.get('probability_pct', 0):.1f}%", ci.get("grade", "")],
        ["   of which: data breach",
         f"{db.get('probability_pct', 0):.2f}%", db.get("grade", "")],
        ["Availability resilience (indicative)",
         f"{av.get('indicator_pct', 0):.0f}%", "Indicative"],
    ]
    table = Table(table_data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY_1),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_NAVY),
        ("LINEBELOW",     (0, 0), (-1, 0),  1.0, C_NAVY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
        ("ALIGN",         (2, 0), (2, -1),  "CENTER"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_GREY_1]),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("INNERGRID",     (0, 1), (-1, -1), 0.25, C_GREY_2),
        ("FONTNAME",      (0, 1), (-1, 1),  "Helvetica-Bold"),
    ]))

    blocks = [
        Spacer(1, 3 * mm),
        Paragraph("<b>Cyber-Risk Probability</b>", S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(
            "Modelled annual likelihood of a cyber loss event, shown as three "
            "distinct and separately-graded measures. This is a frequency view of "
            "externally-observable signals already scored elsewhere in this report "
            "and carries no additional scoring weight.",
            S["body"]),
        Spacer(1, 2 * mm),
        table,
        Spacer(1, 2 * mm),
        Paragraph(
            "<b>Total cyber-incident probability</b> - the likelihood of ANY "
            "modelled cyber incident in the year, combining the data-breach and "
            "ransomware channels. It nests ABOVE the data-breach figure and is "
            "always greater than or equal to it. Relative posture bands "
            "(&lt;8% Low, 8-18% Typical, 18-28% Elevated, &gt;28% High): the "
            "combined rate sits above per-org material-incident claims "
            "frequency (Coalition 2025 1.2-5.7%/yr), so read it as relative "
            "posture rather than a calibrated annual claim rate.",
            S["body_muted"]),
        Paragraph(
            "<b>Data-breach probability</b> - the likelihood specifically of a "
            "data breach (confidentiality loss / record exfiltration). Graded on "
            "firm public breach-rate bands (Cyentia IRIS SMB &lt;2%/yr, BitSight, "
            "SecurityScorecard): &lt;1% Strong, 1-2% Good, 2-3% Typical, 3-6% "
            "Elevated, 6-12% High, &gt;12% Critical.",
            S["body_muted"]),
        Paragraph(
            "<b>Availability resilience indicator</b> - an INDICATIVE signal of "
            "outage / availability risk (DDoS and system / infrastructure-failure "
            "causes). It describes the risk only; it is not a calibrated "
            "probability and not a statement of policy coverage.",
            S["body_muted"]),
        Spacer(1, 3 * mm),
    ]
    return blocks


def cover_ladder_block(d, S):
    """Cover-Sizing Ladder - severity-PML tiers (P50/P95/P99.6), posture-
    independent (item #17). Surfaces fin["cover_ladder"]: the SEVERITY (LM) axis
    of the FAIR split, the simplified client-facing companion to the Loss
    Exposure Scenarios table. New presentation of already-scored signals."""
    fin = d.get("financial_impact", {})
    if not fin:
        return []
    cl = fin.get("cover_ladder", {})
    if not cl:
        return []
    cur = "R " if fin.get("currency") == "ZAR" else "$"
    ts = cl.get("typical_severe", {})
    bad = cl.get("bad", {})
    cat = cl.get("catastrophic", {})

    col_widths = [65 * mm, 55 * mm, INNER_W - 65 * mm - 55 * mm]
    table_data = [
        ["Cover tier", "Modelled severity", "Reference"],
        ["Typical severe breach", f"{cur}{ts.get('loss_zar', 0):,.0f}", "P50 severity"],
        ["Bad breach",            f"{cur}{bad.get('loss_zar', 0):,.0f}", "P95 severity"],
        ["Catastrophic breach",   f"{cur}{cat.get('loss_zar', 0):,.0f}", "1-in-250 / P99.6"],
    ]
    table = Table(table_data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("BACKGROUND",    (0, 0), (-1, 0),  C_GREY_1),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_NAVY),
        ("LINEBELOW",     (0, 0), (-1, 0),  1.0, C_NAVY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (-1, -1), "RIGHT"),
        ("ALIGN",         (0, 0), (0, -1),  "LEFT"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_GREY_1]),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("INNERGRID",     (0, 1), (-1, -1), 0.25, C_GREY_2),
        ("FONTNAME",      (0, 3), (-1, 3),  "Helvetica-Bold"),
    ]))

    blocks = [
        Spacer(1, 3 * mm),
        Paragraph("<b>Cover-Sizing Ladder</b>", S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(
            "The modelled severity of a single severe cyber event across three "
            "cover tiers - the simplified client-facing companion to the Loss "
            "Exposure Scenarios above. These figures are the magnitude of a "
            "realised event and are independent of how likely it is, so they do "
            "not move with security posture. Cover sizing remains the insured's "
            "decision in consultation with the broker; Phishield does not "
            "recommend a specific cover amount.",
            S["body"]),
        Spacer(1, 2 * mm),
        table,
        Spacer(1, 3 * mm),
    ]
    return blocks


def records_assumption_disclosure(d, S):
    """Cat Modelling Validity Notice (records-based) - surfaces the
    industry-typical record assumption built into the IBM SA breach
    anchor, and the per-industry validity ceiling above which the cat
    modelling no longer captures realistic worst-case loss.

    The data-breach cost component (C1) is the residual after
    subtracting C2 (regulatory fines) + C3 (revenue loss) + C4 (ransom)
    + C5 (IR costs) from the IBM SA total breach anchor. The records
    heuristic is NOT used in the calculation itself; it is presented
    here as transparency about the assumed scale and to direct the
    broker to request bespoke actuarial review when the organisation's
    actual record holdings exceed the IBM regression's calibration
    window. FAIS appropriate-disclosure compliance."""
    fin = d.get("financial_impact", {})
    sc = fin.get("scenarios", {}).get("data_breach", {})
    rad = sc.get("records_assumption_disclosure") or {}
    if not rad:
        return []
    est = int(rad.get("estimated_records", 0))
    ceiling = int(rad.get("model_validity_ceiling", 0))
    divisor = int(rad.get("records_divisor_zar", 0))
    anchor_zar = int(rad.get("model_anchor_zar", 0))
    industry = fin.get("industry") or "Other"

    title = "<b>Cat Modelling Validity Notice (records-based)</b>"
    body = (
        "The data-breach component of the catastrophe modelling anchors "
        "on the IBM SA Cost of a Data Breach 2025 study "
        f"(industry-average total cost: <b>R{anchor_zar:,}</b> for the "
        f"'{industry}' industry). IBM's regression is calibrated against "
        "typical SA breach sizes (~25,000-100,000 records per incident). "
        f"For context, the model implicitly assumes this organisation "
        f"holds approximately <b>{est:,} sensitive records</b>, based on "
        f"the industry heuristic of ~1 record per R{divisor:,} of "
        "revenue. The breach cost component itself is computed as the "
        "residual after subtracting regulatory fines, revenue loss, ransom "
        "payment, and incident-response costs from the IBM anchor - the "
        "records figure is shown for transparency, not used directly in "
        "the calculation."
    )
    ceiling_body = (
        f"<b>The cat modelling is reliable up to approximately "
        f"{ceiling:,} records</b> for this industry. Above this threshold, "
        "the IBM-anchored cat exposure understates realistic worst-case "
        "loss because several cost components scale super-linearly outside "
        "the IBM calibration window: POPIA Section 22 breach-notification "
        "costs (per-subject notice), POPIA Section 99 civil exposure "
        "(uncapped per affected subject), regulator escalation toward "
        "statutory maxima, and forensic / incident-response scope. If the "
        "organisation actually holds more than the threshold above in "
        "sensitive records under POPIA, GDPR, HIPAA, PCI DSS, or other "
        "applicable regulation, the cat figures in this report should "
        "be treated as a <b>FLOOR estimate only</b>."
    )
    action_body = (
        "<i>Common outliers: small fintechs, health-tech aggregators, "
        "marketing platforms, data brokers, and breach-list resellers - "
        "entities with small revenue footprints but record holdings 10-"
        "1000x the industry average. The broker should consult the "
        "insured to verify approximate sensitive-record holdings. If the "
        f"count exceeds {ceiling:,}, contact Phishield for a bespoke "
        "actuarial review of cat exposure - this report's catastrophe "
        "numbers are not reliable at that scale.</i>"
    )
    return [
        Spacer(1, 3 * mm),
        Paragraph(title, S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(body, S["body"]),
        Spacer(1, 2 * mm),
        Paragraph(ceiling_body, S["body"]),
        Spacer(1, 2 * mm),
        Paragraph(action_body, S["body"]),
        Spacer(1, 4 * mm),
    ]


def civil_liability_disclosure(S):
    """Civil liability disclosure block — appears immediately after the
    Financial Impact card on both the summary and the full report.

    Required by FAIS reasonable-advice / appropriate-disclosure obligations:
    the report's regulatory-fine figures exclude POPIA Section 99 civil
    exposure and common-law delict, both of which are uncapped and depend
    on contractual data invisible to an external scan."""
    disclosure_title = "<b>Civil Liability Disclosure</b>"
    disclosure_body = (
        "The financial impact figures presented in this report exclude civil liability "
        "arising from contractual or common-law obligations — specifically POPIA Section 99 "
        "civil action, common-law delict, contractual indemnities, master service agreement "
        "penalties, and third-party claims. These exposures cannot be quantified from an "
        "external security assessment because they depend on contracts, customer terms, "
        "supplier liabilities, and indemnity clauses held by the organisation under "
        "assessment. <b>Civil exposure is uncapped under POPIA Section 99 and South "
        "African common law</b> and can materially exceed the regulatory fine figures "
        "shown. Legal counsel and the organisation's risk officer should review "
        "contractual exposures alongside this report when determining appropriate cover."
    )
    cover_note = (
        "<i>Figures presented are statistical model output. Selection of cover limit is "
        "the responsibility of the insured in consultation with the broker. Phishield "
        "does not recommend a specific cover amount.</i>"
    )
    return [
        Spacer(1, 3 * mm),
        KeepTogether([
            Paragraph(disclosure_title, S["cat_title"]),
            Spacer(1, 2 * mm),
            Paragraph(disclosure_body, S["body"]),
            Spacer(1, 2 * mm),
            Paragraph(cover_note, S["body"]),
        ]),
        Spacer(1, 4 * mm),
    ]


def peer_benchmark_card(results, S):
    """Peer Benchmarking card - percentile-rank + 1.0-10.0 peer rating
    vs same-industry / same-revenue-band peer scans in the benchmark
    pool. Drives the broker conversation 'how does this client compare
    to peers?'.

    Hero metrics (compact strip):
      - Risk Score (0-1000)
      - Peer Rating (1.0-10.0)
      - Critical Findings count
      - Industry / revenue-band context

    Full table: per-metric comparison vs peer P25/P50/P75 distribution.

    Source pool composition is explicitly disclosed so brokers know
    what the comparison draws from (public-domain reference scans vs
    lower-tier upsell cohort vs broker-opt-in pool).
    """
    ins = results.get("insurance", {}) or {}
    pb = ins.get("peer_benchmarking") or {}
    if not pb or pb.get("status") != "ok":
        # Insufficient pool (or no data): omit the section entirely so the
        # client-facing PDF carries no "Insufficient Pool" placeholder.
        # The internal HTML dashboard still surfaces the note.
        return []

    rating = pb.get("peer_rating", 0)
    pct = pb.get("percentile", 0)
    n = pb.get("n_peers", 0)
    interp = pb.get("interpretation", "")
    own_score = pb.get("own_risk_score", 0)
    own_crit = pb.get("own_critical_findings", 0)
    rev_band_disp = pb.get("revenue_band_display", "")
    industry = pb.get("industry") or "Other"
    sub_ind = pb.get("sub_industry") or ""
    spec = pb.get("cell_specificity", "")
    pool = pb.get("pool_composition") or {}
    agg = pb.get("peer_aggregates") or {}

    # Header narrative
    cell_text = (
        f"{industry}"
        f"{' / ' + sub_ind if sub_ind else ''}"
        f"{' / ' + rev_band_disp if rev_band_disp else ''}"
    )
    intro = (
        f"Percentile rank against <b>{n}</b> peer benchmark scans "
        f"matching <b>{cell_text}</b>. Peer rating is derived from the "
        f"percentile rank of the (inverted) risk score - higher rating = "
        f"better security posture relative to peers. Rating: <b>{rating} "
        f"out of 10</b> ({pct}th percentile - {interp})."
    )

    # Hero strip - 4 stat cells
    def _stat_cell(label, value, sub):
        return Table([
            [Paragraph(f"<font size='9' color='#475569'><b>{label}</b></font>", S["body"])],
            [Paragraph(f"<font size='18' color='#0f2744'><b>{value}</b></font>", S["body"])],
            [Paragraph(f"<font size='8' color='#64748b'>{sub}</font>", S["body"])],
        ], colWidths=[40 * mm])

    hero = Table([[
        _stat_cell("Risk Score",         f"{own_score} / 1000", "Lower is worse"),
        _stat_cell("Peer Rating",        f"{rating} / 10",      "Higher is better"),
        _stat_cell("Critical Findings",  f"{own_crit}",          "Cross-checker total"),
        _stat_cell("Percentile",         f"{pct}%",              "vs same-industry peers"),
    ]], colWidths=[40 * mm, 40 * mm, 40 * mm, 40 * mm])
    hero.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_GREY_1),
        ("BOX", (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("LINEAFTER", (0, 0), (-2, -1), 0.5, C_GREY_2),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    # Comparison table - per-metric this-scan vs peer P25/P50/P75
    rs = agg.get("risk_score") or {}
    cf = agg.get("critical_findings") or {}
    rsi_a = agg.get("rsi_score") or {}
    ssl_mode = agg.get("ssl_grade_mode") or "n/a"
    own_rsi = ((ins.get("rsi") or {}).get("rsi_score")) or 0
    own_ssl = ((results.get("categories") or {}).get("ssl") or {}).get("grade") or "?"

    def _fmt(v):
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:.2f}" if v < 10 else f"{int(v)}"
        return str(v)

    comparison_data = [
        ["Metric", "This Scan", "Peer P25", "Peer P50", "Peer P75"],
        ["Risk Score (0-1000, lower=worse)",
            _fmt(own_score), _fmt(rs.get("p25")), _fmt(rs.get("p50")), _fmt(rs.get("p75"))],
        ["Critical Findings (count)",
            _fmt(own_crit), _fmt(cf.get("p25")), _fmt(cf.get("p50")), _fmt(cf.get("p75"))],
        ["RSI Score (0-1.0, higher=worse)",
            _fmt(round(own_rsi, 2)), _fmt(rsi_a.get("p25")), _fmt(rsi_a.get("p50")), _fmt(rsi_a.get("p75"))],
        ["SSL Grade",
            _fmt(own_ssl), "-", _fmt(ssl_mode), "-"],
    ]
    comp_tbl = Table(comparison_data, colWidths=[60 * mm, 25 * mm, 25 * mm, 25 * mm, 25 * mm])
    comp_tbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, C_GREY_2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_GREY_1]),
        ("BOX", (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    # Pool composition disclosure
    pool_breakdown = ", ".join(
        f"{count} {label.replace('_', ' ')}"
        for label, count in sorted(pool.items(), key=lambda kv: -kv[1])
    )
    spec_text = {
        "industry+sub+band": "same industry, sub-industry, and revenue band",
        "industry+sub":      "same industry and sub-industry (revenue band relaxed for sample size)",
        "industry+band":     "same industry and revenue band (sub-industry relaxed)",
        "industry":          "same industry (sub-industry and revenue band relaxed)",
        "global":            "global pool (industry-specific peers below sample threshold)",
    }.get(spec, spec)
    pool_text = (
        f"<i>Pool composition: {pool_breakdown}. Cell match: {spec_text}. "
        f"Pool freshness: {pb.get('pool_freshness_days', 90)}-day window. "
        f"'benchmark pool' = public-domain reference scans; "
        f"'lower tier upsell' = Phishield's existing lower-tier client "
        f"cohort scanned for premier-tier upsell; "
        f"'client optin' = broker-paid scans contributed with explicit "
        f"consent. The lower-tier cohort may not be perfectly "
        f"representative of true industry median; the disclosure makes "
        f"the composition visible so brokers can weight the comparison "
        f"accordingly.</i>"
    )

    return [
        Spacer(1, 4 * mm),
        Paragraph("<b>Peer Benchmarking</b>", S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(intro, S["body"]),
        Spacer(1, 3 * mm),
        hero,
        Spacer(1, 4 * mm),
        comp_tbl,
        Spacer(1, 3 * mm),
        Paragraph(pool_text, S["body"]),
        Spacer(1, 4 * mm),
    ]


def waf_coverage_notice(results, S):
    """Top-level Partial Coverage Notice rendered when the WAFTracker
    flagged the target apex as protected during the scan. Appears
    immediately after the executive summary and again above the
    Insurance Analytics section.

    The notice is FAIS-compliance critical: it explicitly tells the
    broker / client that the report's "no findings" entries in
    affected sections do NOT confirm absence of risk - the scanner
    could not verify them because the target's defensive infrastructure
    intervened. Without this notice the report would mislead."""
    sc = results.get("_scan_completeness", {})
    waf = sc.get("waf_status", {})
    if not waf or not waf.get("blocked"):
        return []
    affected = sc.get("waf_affected_checkers") or []
    coverage = sc.get("coverage_pct", 100)
    kind = waf.get("kind", "waf_blocked")
    kind_label = {
        "waf_challenge": "Challenge page (Cloudflare / Akamai / Imperva / similar)",
        "waf_blocked": "Active blocking (403 / 406 / 451 responses)",
        "waf_rate_limited": "Rate-limit responses (429 / 503)",
        "waf_timeout": "Connection timeouts on probe traffic",
    }.get(kind, "WAF intervention")

    body = (
        "<b>Partial Coverage Notice.</b> The target domain's protective "
        f"infrastructure intervened during this scan. Detected pattern: "
        f"<b>{kind_label}</b> ({waf.get('evidence', '')}). "
        f"Of the assessable checkers, approximately <b>{coverage}%</b> "
        f"returned data; {len(affected)} checker(s) were affected. "
        "Findings in affected sections below carry a per-card disclaimer. "
        "Absence of a finding in those sections does NOT confirm absence "
        "of the underlying risk - it indicates the scanner could not "
        "verify it. Coverage of this scan is therefore <b>partial</b>; "
        "this is a property of the target's defensive posture, not a "
        "scanner limitation. A rescan from a different source IP, or "
        "coordination with the target's security team, may be required "
        "for complete coverage."
    )
    return [
        Spacer(1, 3 * mm),
        Paragraph("<b>WAF / Bot-Manager Intervention Detected</b>", S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(body, S["body"]),
        Spacer(1, 4 * mm),
    ]


def waf_card_disclaimer(checker_name, results, S):
    """Per-card disclaimer block rendered ABOVE a checker card when that
    specific checker is in _scan_completeness.waf_affected_checkers.

    Returns empty list when the checker is not WAF-affected, so callers
    can unconditionally extend their flowables with the return value."""
    sc = results.get("_scan_completeness", {})
    affected = sc.get("waf_affected_checkers") or []
    if checker_name not in affected:
        return []
    waf = sc.get("waf_status", {}) or {}
    body = (
        "<i><b>WAF intervention.</b> The target's protective infrastructure "
        f"intervened during the {checker_name} checker run ({waf.get('evidence', '')}). "
        "Findings in this card may be incomplete; an absence of a finding "
        "here does not confirm absence of the underlying risk. See the "
        "top-level Partial Coverage Notice for details.</i>"
    )
    return [
        Spacer(1, 1.5 * mm),
        Paragraph(body, S["body_muted"]),
        Spacer(1, 1 * mm),
    ]


def flag_audit_panel(d, S):
    """Regulatory flag audit panel - shows broker_input vs auto_detected
    side-by-side for every flag, with evidence. FAIS audit trail.
    `d` is the insurance subtree of the result; flags live under
    financial_impact.regulatory_exposure.flags + flags._auto_detected."""
    fin = d.get("financial_impact", {})
    reg_exp = fin.get("regulatory_exposure", {})
    flags = reg_exp.get("flags", {})
    if not flags:
        return []
    auto = flags.get("_auto_detected", {}) or {}
    # Flag display order + label mapping
    flag_specs = [
        ("listed_company",          "JSE-listed company"),
        ("accountable_institution", "FIC Act accountable institution"),
        ("b2c",                     "Consumer-facing (B2C)"),
        ("sub_industry_detail",     "Healthcare sub-detail"),
        ("insurance_subtype",       "Insurance entity type"),
        ("gdpr",                    "GDPR applicable"),
        ("pci",                     "PCI DSS applicable"),
    ]
    # Map broker-input flag name -> auto-detected dict key
    auto_key_map = {
        "gdpr":                "gdpr_applicable",
        "pci":                 "pci_applicable",
        "sub_industry_detail": "sub_industry_detail",
        "insurance_subtype":   "insurance_subtype",
    }
    # Flags that are purely auto-detected (no broker-input column).
    # Insurance subtype is detected from website content; the broker
    # does not tick it - they tick B2C (which is informed by subtype).
    AUTO_ONLY = {"insurance_subtype"}
    table_data = [["Flag", "Broker Input", "Auto-detected", "Evidence"]]
    for key, label in flag_specs:
        broker_value = flags.get(key)
        if key in AUTO_ONLY:
            broker_disp = "—"
        elif key == "sub_industry_detail":
            broker_disp = str(broker_value) if broker_value else "(not set)"
        else:
            broker_disp = "Yes" if broker_value else "No"
        auto_lookup = auto_key_map.get(key, key)
        auto_entry = auto.get(auto_lookup) or {}
        auto_detected = bool(auto_entry.get("auto_detected"))
        if key == "sub_industry_detail" and auto_detected:
            auto_disp = str(auto_entry.get("sub_industry_detail", "Yes"))
        elif key == "insurance_subtype":
            subtype_val = auto_entry.get("insurance_subtype")
            auto_disp = str(subtype_val).upper() if subtype_val else "n/a"
        else:
            auto_disp = "Yes" if auto_detected else "No"
        evidence = auto_entry.get("evidence", "")[:180] or "—"
        table_data.append([label, broker_disp, auto_disp, evidence])

    # Column widths per rules #6 / #12.
    # Atomic minimums (Helvetica 8pt):
    #   Flag label: "FIC Act accountable institution" = 30 chars ~ 50mm
    #   Broker Input / Auto-detected: "hospital_clinic" = 15 chars ~ 22mm
    #   Evidence: long sentences - wraps; 75mm gives ~3 lines max
    col_widths = [50 * mm, 22 * mm, 22 * mm, 75 * mm]

    # Wrap evidence cells in Paragraphs so long text wraps cleanly
    evidence_style = ParagraphStyle("flag_evidence", fontName="Helvetica",
                                    fontSize=7, leading=9, textColor=colors.HexColor("#475569"))
    wrapped_rows = [table_data[0]]
    for r in table_data[1:]:
        wrapped_rows.append([r[0], r[1], r[2], Paragraph(r[3], evidence_style)])

    table = Table(wrapped_rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),   "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),   8),
        ("FONTSIZE",      (0, 1), (-1, -1),  8),
        ("BACKGROUND",    (0, 0), (-1, 0),   C_GREY_1),
        ("LINEBELOW",     (0, 0), (-1, 0),   0.5, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1),  "MIDDLE"),
        ("ALIGN",         (1, 0), (2, -1),   "CENTER"),
        ("LEFTPADDING",   (0, 0), (-1, -1),  6),
        ("RIGHTPADDING",  (0, 0), (-1, -1),  6),
        ("TOPPADDING",    (0, 0), (-1, -1),  4),
        ("BOTTOMPADDING", (0, 0), (-1, -1),  4),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [colors.white, C_GREY_1]),
        ("BOX",           (0, 0), (-1, -1),  0.5, C_GREY_2),
    ]))
    title = "<b>Regulatory Flag Audit</b>"
    intro = (
        "FAIS audit trail. Each flag shows the broker's input (authoritative - "
        "drives the catastrophe stack calculation) alongside what the external "
        "pre-flight scan detected independently. Discrepancies are not errors; "
        "they reflect broker knowledge of context the scanner cannot observe "
        "(contractual exposures, EU customer relationships, etc.)."
    )
    return [
        Spacer(1, 4 * mm),
        Paragraph(title, S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(intro, S["body"]),
        Spacer(1, 2 * mm),
        table,
        Spacer(1, 4 * mm),
    ]


def scan_duration_profile(results, S):
    """Per-checker wall-time profile section. Populated from
    _scan_completeness.per_checker_seconds. Shown in the full PDF only
    as a Scan Quality / SLA diagnostic."""
    sc = results.get("_scan_completeness", {})
    durations = sc.get("per_checker_seconds", {})
    if not durations:
        return []
    title = "<b>Scan Duration Profile</b>"
    intro = (
        f"Per-checker wall-clock timing for this scan ({sc.get('checkers_observed', 0)} "
        f"checker invocations recorded). Concurrent checkers overlap; the sum is "
        f"not the end-to-end scan wall time. Top entries identify the longest-running "
        f"checkers — useful for SLA diagnostics."
    )
    table_data = [["Checker", "Seconds"]]
    items = sorted(durations.items(), key=lambda kv: kv[1], reverse=True)
    for name, secs in items[:15]:
        table_data.append([name, f"{secs:.2f}"])
    if len(items) > 15:
        table_data.append([f"... {len(items) - 15} more checker(s) under top 15", ""])
    total = sc.get("total_checker_seconds", 0)
    table_data.append(["Sum (concurrent overlap)", f"{total:.1f}"])
    # Column widths: 130mm for checker name (atomic for "shodan_vulns:192.168.0.1"),
    # 30mm for seconds (atomic for "1234.56"). Rule #6 / #12 minimums.
    table = Table(table_data, colWidths=[130 * mm, 30 * mm])
    table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0),   "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1),  8),
        ("BACKGROUND",    (0, 0), (-1, 0),   C_GREY_1),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",     (0, 0), (-1, 0),   0.5, C_GREY_2),
        ("ALIGN",         (1, 0), (1, -1),   "RIGHT"),
        ("LEFTPADDING",   (0, 0), (-1, -1),  6),
        ("RIGHTPADDING",  (0, 0), (-1, -1),  6),
        ("TOPPADDING",    (0, 0), (-1, -1),  3),
        ("BOTTOMPADDING", (0, 0), (-1, -1),  3),
        ("ROWBACKGROUNDS",(0, 1), (-1, -2),  [colors.white, C_GREY_1]),
        ("BACKGROUND",    (0, -1), (-1, -1), C_BLUE_LIGHT),
        ("FONTNAME",      (0, -1), (-1, -1), "Helvetica-Bold"),
    ]))
    return [
        Spacer(1, 4 * mm),
        Paragraph(title, S["cat_title"]),
        Spacer(1, 2 * mm),
        Paragraph(intro, S["body"]),
        Spacer(1, 2 * mm),
        table,
        Spacer(1, 4 * mm),
    ]


def cat_risk_mitigations(d, S):
    fin = d.get("financial_impact", {})
    mit = fin.get("risk_mitigations", {})
    findings = mit.get("findings", [])
    if not findings:
        return []

    is_zar = fin.get("currency") == "ZAR"
    cur = "R" if is_zar else "$"

    total_savings = mit.get("total_potential_savings", 0)
    current = mit.get("current_annual_loss", 0)
    mitigated = mit.get("mitigated_annual_loss", 0)
    reduction_pct = round((total_savings / current * 100) if current > 0 else 0, 1)

    # Re-portrayed (item #17): LEAD with the breach-probability/grade movement
    # + %-reduction in modelled exposure + the posture-INDEPENDENT catastrophe
    # cover (1-in-250). Absolute Rand savings are demoted to secondary detail.
    rs = mit.get("remediation_summary", {})
    rows = []
    if rs:
        rows.extend([
            ("Data-breach likelihood",
             f"{rs.get('breach_probability_before_pct', 0)}% "
             f"({rs.get('breach_grade_before', '')})&nbsp;&rarr;&nbsp;"
             f"{rs.get('breach_probability_after_pct', 0)}% "
             f"({rs.get('breach_grade_after', '')})"),
            ("Reduction in modelled exposure", f"{rs.get('exposure_reduction_pct', 0)}%"),
            ("Catastrophe cover (1-in-250, unchanged)",
             f"{cur}&nbsp;{rs.get('catastrophe_cover_zar', 0):,.0f}"),
            ("", ""),
        ])
    rows.extend([
        ("Current Annual Loss",    f"{cur}&nbsp;{current:,.0f}"),
        ("Mitigated Annual Loss",  f"{cur}&nbsp;{mitigated:,.0f}"),
        ("Total Potential Savings", f"{cur}&nbsp;{total_savings:,.0f} ({reduction_pct}%)"),
        ("", ""),
    ])

    # Count by severity from summary
    summary = mit.get("summary", {})
    for sev in ("critical", "high", "medium"):
        s = summary.get(sev, {})
        if s.get("count", 0) > 0:
            rows.append((f"{sev.title()} Findings", f"{s['count']} — {cur}&nbsp;{s['total_savings_zar']:,.0f} savings"))

    rows.append(("", ""))

    # Individual findings
    for f in findings:
        sev = f.get("severity", "Medium")
        savings = f.get("estimated_annual_savings_zar", 0)
        rows.append((f"[{sev}] {f.get('recommendation', '')}",
                      f"{cur}&nbsp;{savings:,.0f}"))

    rows.append(("", ""))
    rows.append(("Note", "Savings are modelled by reducing the probability of specific incident types (ransomware / breach / DDoS families) and are capped at 85% of current loss. This card is the single Rand-savings view in this report; the \"Remediation Roadmap — RSI Prioritisation\" card orders the same fixes by RSI impact (what to fix first) without re-quoting Rand values. Cost estimates are indicative SA market ranges for prioritisation, not project quotes."))

    fb = f"Implementing all recommendations could reduce annual expected loss by {cur}&nbsp;{total_savings:,.0f} ({reduction_pct}%)."
    return build_cat_card("Risk Mitigation Recommendations (Expected-Loss)", C_GREEN,
                          f"Save {cur}&nbsp;{total_savings:,.0f}", rows, [], S, fallback=fb)


# ---------------------------------------------------------------------------
# Executive summary table
# ---------------------------------------------------------------------------

def _build_legend(S) -> Table:
    """Colour glossary legend for the report."""
    legend_items = [
        (C_GREEN, "Low Risk", "No action required"),
        (C_AMBER, "Medium Risk", "Monitor / improve when feasible"),
        (C_RED, "High Risk", "Remediation recommended"),
        (C_CRITICAL, "Critical Risk", "Immediate action required"),
    ]
    legend_rows = []
    for col, label, desc in legend_items:
        legend_rows.append([
            make_traffic_circle(col, 8),
            Paragraph(f"<b>{label}</b>", S["kv_key"]),
            Paragraph(desc, S["body_muted"]),
        ])
    tbl = Table(legend_rows, colWidths=[14, 28 * mm, INNER_W - 14 - 28 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (0, -1), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 4),
    ]))
    return tbl


# Insurance risk context for executive summary items
_INSURANCE_CONTEXT = {
    "Ransomware Susceptibility": "Determines premium loading; high RSI correlates with ransomware claim frequency",
    "Data Breach Index": "Historical breach exposure; impacts data breach and regulatory fine projections",
    "SSL Grade": "Weak encryption enables man-in-the-middle attacks; increases data breach probability",
    "Email Security Score": "Poor email auth enables phishing/BEC; top initial attack vector for claims",
    "HTTP Security Headers": "Missing headers enable XSS and clickjacking; increases web application breach risk",
    "Known Data Breaches": "Prior breaches significantly increase probability of repeat incidents and claims",
    "Exposed Admin Panels": "Direct entry point for attackers; leads to full system compromise and ransomware",
    "DB/Service Exposure": "Exposed databases enable mass data theft; highest severity finding for underwriting",
    "IP/Domain Blacklisted": "Indicates prior compromise or spam; reputation damage affects business interruption",
    "WAF Protection": "No WAF leaves web applications unprotected against automated attacks and DDoS",
    "RDP Exposed": "Primary ransomware entry vector; single highest risk factor for cyber claims",
    "Est. Annual Loss": "FAIR-modelled expected loss; basis for coverage limits and premium calculation",
    "Fraudulent Domains": "Brand impersonation risk; phishing campaigns targeting clients and employees",
    "Web Ranking (Tranco)": "Site visibility indicator; higher-profile targets attract more automated attacks",
    "Supply-Chain Risk": "Cumulative supplier/CDN/vendor-breach exposure; ~12% of breaches are SC-vectored (IBM CoDB 2024)",
    "Compromised CDN": "Magecart-class card-skimmer risk; confirmed-compromised CDN serving scripts on the homepage",
    "Vendor Breach Match": "Vendor in mail-path had a confirmed public breach in the lookback window; key rotation often incomplete",
    "Exposed Manifests + CVEs": "Public dependency map cross-referenced via OSV.dev; actionable CVE patch targets",
    "Related-Domain Critical": "Critical finding on a broker-declared supplier; civil-liability inflator in financial model",
    "Cross-Correlated Vendor Risk": "Hudson Rock infostealer harvest × S-4 SPF vendor surface × S-5 known breach — three independent signals confirming risk; highest-priority rotate target",
}


def build_summary_table(results: dict, S) -> Table:
    cats = results.get("categories", {})

    # Map traffic light colours to hex for inline font tags
    _COL_HEX = {
        id(C_GREEN): "#16a34a", id(C_AMBER): "#d97706",
        id(C_RED): "#dc2626", id(C_CRITICAL): "#991b1b",
        id(C_BLUE): "#1d4ed8", id(C_GREY_3): "#94a3b8",
    }

    def row(label, value, col):
        circ = make_traffic_circle(col, 9)
        col_hex = _COL_HEX.get(id(col), "#0f172a")
        val_str = str(value)
        ctx = _INSURANCE_CONTEXT.get(label, "")
        val_text = f"<font color='{col_hex}'><b>{val_str}</b></font>  <font size='7' color='#64748b'><i>— {ctx}</i></font>" if ctx else f"<font color='{col_hex}'><b>{val_str}</b></font>"
        return [circ, Paragraph(f"<b>{label}</b>", S["kv_key"]), Paragraph(val_text, S["kv_val"])]

    ssl_grade = cats.get("ssl", {}).get("grade", "?")
    em_score  = cats.get("email_security", {}).get("score", 0)
    hh_score  = cats.get("http_headers", {}).get("score", 0)
    br_count  = cats.get("breaches", {}).get("breach_count", 0)
    adm_c     = cats.get("exposed_admin", {}).get("critical_count", 0)
    adm_h     = cats.get("exposed_admin", {}).get("high_count", 0)
    hrp_c     = cats.get("high_risk_protocols", {}).get("critical_count", 0)
    bl        = cats.get("dnsbl", {}).get("blacklisted", False)
    waf       = cats.get("waf", {}).get("detected", False)
    vpn_rdp   = cats.get("vpn_remote", {}).get("rdp_exposed", False)

    # Insurance analytics
    ins       = results.get("insurance", {})
    rsi_score = ins.get("rsi", {}).get("rsi_score")
    dbi_score = ins.get("dbi", {}).get("dbi_score")

    rows = [
        row("SSL Grade",             ssl_grade,
            _tl(ssl_grade in ("A+", "A", "B"), ssl_grade == "C")),
        row("Email Security Score",  f"{em_score}/10",
            _tl(em_score >= 8, em_score >= 5)),
        row("HTTP Security Headers", f"{hh_score}%",
            _tl(hh_score >= 80, hh_score >= 50)),
        row("Known Data Breaches",   br_count,
            _tl(br_count == 0, br_count <= 3)),
        row("Exposed Admin Panels",  adm_c + adm_h,
            _tl(adm_c + adm_h == 0, adm_c == 0)),
        row("DB/Service Exposure",   f"{hrp_c} critical service(s)",
            C_CRITICAL if hrp_c > 0 else C_GREEN),
        row("IP/Domain Blacklisted", "YES" if bl else "No",
            C_CRITICAL if bl else C_GREEN),
        row("WAF Protection",        "Detected" if waf else "Not detected",
            C_GREEN if waf else C_AMBER),
        row("RDP Exposed",           "YES — CRITICAL" if vpn_rdp else "No",
            C_CRITICAL if vpn_rdp else C_GREEN),
    ]

    # Add insurance rows if available
    if rsi_score is not None:
        rows.insert(0, row("Ransomware Susceptibility", f"{rsi_score:.2f}",
            _tl(rsi_score < 0.3, rsi_score < 0.6)))
    if dbi_score is not None:
        rows.insert(1 if rsi_score is not None else 0,
            row("Data Breach Index", f"{dbi_score}/100",
            _tl(dbi_score >= 70, dbi_score >= 40)))

    # Est. Annual Loss from insurance analytics — Monte Carlo P50 median,
    # the same basis the executive deck headlines. (Was previously the PERT
    # expected/mean ALE, which disagreed with the P50 shown everywhere else.)
    fin_ins = ins.get("financial_impact", {})
    fin_ml  = fin_ins.get("monte_carlo", {}).get("total", {}).get("p50")
    if fin_ml is not None:
        cur_sym   = "R" if fin_ins.get("currency") == "ZAR" else "$"
        fin_score = fin_ins.get("score", 50)
        rows.append(row("Est. Annual Loss", f"{cur_sym} {fin_ml:,.0f}",
                         C_CRITICAL if fin_score < 30 else C_AMBER if fin_score < 70 else C_GREEN))

    fd_count = cats.get("fraudulent_domains", {}).get("resolved_count", 0)
    if fd_count:
        rows.append(row("Fraudulent Domains", f"{fd_count} lookalike(s)",
                         C_CRITICAL if fd_count > 3 else C_RED if fd_count > 0 else C_GREEN))

    wr = cats.get("web_ranking", {})
    wr_rank = wr.get("rank")
    wr_label = f"#{wr_rank:,}" if wr_rank else "Unranked"
    rows.append(row("Web Ranking (Tranco)", wr_label,
                     C_GREEN if wr.get("in_list") else C_AMBER))

    # ── Supply-Chain section ────────────────────────────────────────
    # One aggregated row showing the worst signal across the 6
    # supply-chain categories, then individual rows ONLY for the
    # findings severe enough to warrant the underwriter's eye.
    rd_cat = cats.get("related_domains", {})
    dm_cat = cats.get("dependency_manifests", {})
    tpjs_cat = cats.get("third_party_js", {})
    evs_cat = cats.get("email_vendor_surface", {})
    cms_cat = cats.get("cms_plugin_sbom", {})
    vb_cat = cats.get("vendor_breach", {})

    # Worst-severity rollup across the supply-chain signals. Thresholds
    # MIRROR the per-card severities on the executive-deck supply-chain
    # slide (_assessment_slide_supply_chain) so this row can never read
    # "Clean" while the deck shows MEDIUM/CRITICAL. KEEP IN SYNC with that
    # slide's classification. MEDIUM-tier signals count here (previously
    # they were silently dropped, producing a false "Clean").
    sc_n = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}

    def _sc_bump(level):
        if level in sc_n:
            sc_n[level] += 1

    if dm_cat.get("status") == "completed":
        if dm_cat.get("total_critical_cves", 0) > 0:
            _sc_bump("CRITICAL")
        elif dm_cat.get("exposed_manifests"):
            _sc_bump("HIGH")
    if tpjs_cat.get("status") == "completed":
        comp = tpjs_cat.get("compromised_host_count", 0)
        third = tpjs_cat.get("third_party_count", 0)
        missing_sri = tpjs_cat.get("missing_sri_count", 0)
        if comp > 0:
            _sc_bump("CRITICAL")
        elif third > 0 and missing_sri / max(1, third) > 0.5:
            _sc_bump("HIGH")
    if evs_cat.get("status") == "completed":
        cnt = evs_cat.get("vendor_count", 0)
        if evs_cat.get("weak_dmarc") and cnt >= 1:
            _sc_bump("HIGH")
        elif cnt >= 6:
            _sc_bump("MEDIUM")
    if cms_cat.get("status") == "completed" and cms_cat.get("is_wordpress"):
        if cms_cat.get("versioned_count", 0) >= 1:
            _sc_bump("HIGH")
        elif cms_cat.get("plugin_count", 0) >= 5:
            _sc_bump("MEDIUM")
    if vb_cat.get("status") == "completed":
        if vb_cat.get("critical_match_count", 0) > 0:
            _sc_bump("CRITICAL")
        elif vb_cat.get("high_match_count", 0) > 0:
            _sc_bump("HIGH")
        elif vb_cat.get("matches"):
            _sc_bump("MEDIUM")
    if rd_cat.get("status") == "completed":
        if rd_cat.get("critical_count", 0) > 0:
            _sc_bump("CRITICAL")
        elif rd_cat.get("high_count", 0) > 0:
            _sc_bump("HIGH")

    # Phase-4f cross-correlation is reporting-only (no score) but IS
    # surfaced — a triple-source CRITICAL must not be hidden behind "Clean".
    tpc_cat = cats.get("third_party_correlation", {})
    sc_cross = None
    if tpc_cat.get("status") == "completed":
        if tpc_cat.get("critical_count", 0) > 0:
            susp = tpc_cat.get("suspected_vendors") or []
            names = ", ".join(s.get("vendor", "?") for s in susp[:2])
            sc_cross = ("CRITICAL", f"cross-vendor CRITICAL — rotate at {names}"
                        if names else "cross-vendor CRITICAL")
        elif tpc_cat.get("high_count", 0) > 0:
            sc_cross = ("HIGH", "cross-vendor HIGH")

    sc_any_completed = any(
        c.get("status") == "completed" for c in
        (rd_cat, dm_cat, tpjs_cat, evs_cat, cms_cat, vb_cat)
    )
    if sc_any_completed or sc_cross:
        # Worst severity drives the colour; the cross-correlation can lift it.
        if sc_n["CRITICAL"] > 0 or (sc_cross and sc_cross[0] == "CRITICAL"):
            sc_col = C_CRITICAL
        elif sc_n["HIGH"] > 0 or (sc_cross and sc_cross[0] == "HIGH"):
            sc_col = C_RED
        elif sc_n["MEDIUM"] > 0:
            sc_col = C_AMBER
        else:
            sc_col = C_GREEN
        # Broker-facing wording: lead with the urgent cross-vendor action,
        # then the count of contributing signals by severity.
        bits = []
        if sc_cross:
            bits.append(sc_cross[1])
        counts = []
        if sc_n["CRITICAL"]:
            counts.append(f"{sc_n['CRITICAL']} critical")
        if sc_n["HIGH"]:
            counts.append(f"{sc_n['HIGH']} high")
        if sc_n["MEDIUM"]:
            counts.append(f"{sc_n['MEDIUM']} medium")
        if counts:
            bits.append(", ".join(counts) + " signal(s)")
        sc_label = " · ".join(bits) if bits else "Clean"
        rows.append(row("Supply-Chain Risk", sc_label, sc_col))

    # Spotlight rows — only when the underwriter genuinely benefits.
    if tpjs_cat.get("compromised_host_count", 0) > 0:
        rows.append(row(
            "Compromised CDN",
            f"{tpjs_cat['compromised_host_count']} script(s) — replace immediately",
            C_CRITICAL,
        ))
    if vb_cat.get("critical_match_count", 0) > 0:
        top = (vb_cat.get("matches") or [{}])[0]
        months = max(1, (top.get("age_days") or 0) // 30)
        rows.append(row(
            "Vendor Breach Match",
            f"{top.get('vendor', '?')} ~{months} mo ago ({top.get('severity','')})",
            C_CRITICAL,
        ))
    if dm_cat.get("total_critical_cves", 0) > 0:
        rows.append(row(
            "Exposed Manifests + CVEs",
            f"{dm_cat['total_critical_cves']} critical/high CVE(s) (OSV.dev)",
            C_CRITICAL,
        ))
    if rd_cat.get("critical_count", 0) > 0:
        rows.append(row(
            "Related-Domain Critical",
            f"{rd_cat['critical_count']} critical finding(s) on supplier(s)",
            C_CRITICAL,
        ))

    # Cross-correlation spotlight — strongest single signal in the model
    tpc_cat = cats.get("third_party_correlation", {})
    if tpc_cat.get("status") == "completed":
        if tpc_cat.get("critical_count", 0) > 0:
            susp = tpc_cat.get("suspected_vendors") or []
            vendor_short = ", ".join(s.get("vendor", "?") for s in susp[:2])
            if len(susp) > 2:
                vendor_short += f" +{len(susp) - 2}"
            rows.append(row(
                "Cross-Correlated Vendor Risk",
                f"CRITICAL — rotate at {vendor_short} (HR harvest × SPF × breach)",
                C_CRITICAL,
            ))
        elif tpc_cat.get("high_count", 0) > 0:
            hr_n = tpc_cat.get("hudson_rock_third_party_count", 0)
            spf_n = tpc_cat.get("spf_vendor_count", 0)
            rows.append(row(
                "Cross-Correlated Vendor Risk",
                f"HIGH — {hr_n} HR harvest + {spf_n} SPF vendor(s)",
                C_RED,
            ))

    tbl = Table(rows, colWidths=[18, 45 * mm, INNER_W - 18 - 45 * mm])
    style = [
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (0, -1), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 6),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.25, C_GREY_2),
    ]
    for i in range(0, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_GREY_1))
    for i in range(1, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_WHITE))
    tbl.setStyle(TableStyle(style))
    return tbl


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _build_vulnerability_posture(results: dict, S) -> list:
    """Build Vulnerability Posture summary with severity/age matrix and narrative."""
    parts = []
    cats = results.get("categories", {})

    # Collect all CVEs from per-IP results
    all_cves = []
    per_ip = cats.get("per_ip", {})
    for ip, checkers in per_ip.items():
        shodan = checkers.get("shodan_vulns", {})
        for cve in shodan.get("cves", []):
            all_cves.append(cve)

    # Also check aggregated shodan
    agg_shodan = cats.get("shodan_vulns", {})
    if not all_cves and agg_shodan.get("cves"):
        all_cves = agg_shodan.get("cves", [])

    total = len(all_cves)
    if total == 0:
        # No CVEs — still show the posture block with clean result
        parts.append(Paragraph("<b>Vulnerability Posture</b>", S["cat_title"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph(
            "No known vulnerabilities were detected on the assessed infrastructure. "
            "This is a positive indicator, however it does not guarantee the absence of "
            "vulnerabilities — only that none were identified through passive external scanning.",
            S["body"]))
        return parts

    # Count by severity
    critical = sum(1 for c in all_cves if c.get("severity") == "critical")
    high = sum(1 for c in all_cves if c.get("severity") == "high")
    medium = sum(1 for c in all_cves if c.get("severity") == "medium")
    low = sum(1 for c in all_cves if c.get("severity") == "low")

    # Count by age bucket
    ages = [c.get("age_days") for c in all_cves if c.get("age_days") is not None]
    over_180 = sum(1 for a in ages if a > 180)
    d90_to_180 = sum(1 for a in ages if 90 <= a <= 180)
    under_90 = sum(1 for a in ages if a < 90)
    oldest = max(ages) if ages else 0
    avg_age = round(sum(ages) / len(ages)) if ages else 0

    # Count indicators
    easily_exploitable = sum(1 for c in all_cves if c.get("easily_exploitable"))
    widely_exploited = sum(1 for c in all_cves if c.get("widely_exploited"))
    zero_days = sum(1 for c in all_cves if c.get("zero_day"))
    malware_count = sum(1 for c in all_cves if c.get("ransomware_association"))
    ransomware_names = list(set(
        c.get("ransomware_association", "") for c in all_cves if c.get("ransomware_association")
    ))[:5]

    # Patch management rating
    if oldest > 365:
        pm_rating = "Very Poor"
        pm_color = C_CRITICAL
    elif oldest > 180:
        pm_rating = "Poor"
        pm_color = C_RED
    elif oldest > 90:
        pm_rating = "Fair"
        pm_color = C_AMBER
    else:
        pm_rating = "Good"
        pm_color = C_GREEN

    parts.append(Paragraph("<b>Vulnerability Posture</b>", S["cat_title"]))
    parts.append(Spacer(1, 2 * mm))

    # Severity + Age matrix table (PrimeLogic style)
    header_style = ParagraphStyle("vp_hdr", fontSize=7, fontName="Helvetica-Bold",
                                   textColor=C_WHITE, alignment=TA_CENTER, leading=10)
    # Conditional font size for large numbers to prevent cell overflow
    val_size = 14 if total < 100 else 12
    val_leading = 18 if total < 100 else 16
    val_style = ParagraphStyle("vp_val", fontSize=val_size, fontName="Helvetica-Bold",
                                textColor=C_BLACK, alignment=TA_CENTER, leading=val_leading)
    lbl_style = ParagraphStyle("vp_lbl", fontSize=6, fontName="Helvetica",
                                textColor=C_GREY_3, alignment=TA_CENTER, leading=9)

    matrix_data = [
        # Headers
        [Paragraph("<b>Critical</b>", header_style),
         Paragraph("<b>High</b>", header_style),
         Paragraph("<b>Medium</b>", header_style),
         Paragraph("<b>&gt; 180 days</b>", header_style),
         Paragraph("<b>&lt; 180 days</b>", header_style),
         Paragraph("<b>&lt; 90 days</b>", header_style)],
        # Values
        [Paragraph(f"<b>{critical}</b>", val_style),
         Paragraph(f"<b>{high}</b>", val_style),
         Paragraph(f"<b>{medium + low}</b>", val_style),
         Paragraph(f"<b>{over_180}</b>", val_style),
         Paragraph(f"<b>{d90_to_180}</b>", val_style),
         Paragraph(f"<b>{under_90}</b>", val_style)],
        # Labels
        [Paragraph(f"{critical} instance(s)", lbl_style),
         Paragraph(f"{high} instance(s)", lbl_style),
         Paragraph(f"{medium + low} instance(s)", lbl_style),
         Paragraph(f"{over_180} instance(s)", lbl_style),
         Paragraph(f"{d90_to_180} instance(s)", lbl_style),
         Paragraph(f"{under_90} instance(s)", lbl_style)],
    ]

    col_w = INNER_W / 6
    matrix_tbl = Table(matrix_data, colWidths=[col_w] * 6)
    matrix_tbl.setStyle(TableStyle([
        # Header row styling
        ("BACKGROUND",    (0, 0), (2, 0), C_CRITICAL_BG),
        ("BACKGROUND",    (0, 0), (0, 0), C_CRITICAL),
        ("BACKGROUND",    (1, 0), (1, 0), C_RED),
        ("BACKGROUND",    (2, 0), (2, 0), C_AMBER),
        ("BACKGROUND",    (3, 0), (3, 0), colors.HexColor("#1e40af")),
        ("BACKGROUND",    (4, 0), (4, 0), colors.HexColor("#2563eb")),
        ("BACKGROUND",    (5, 0), (5, 0), colors.HexColor("#3b82f6")),
        # Value row
        ("BACKGROUND",    (0, 1), (-1, 1), C_GREY_1),
        ("BACKGROUND",    (0, 2), (-1, 2), C_WHITE),
        # Grid
        ("BOX",           (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING",    (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("TOPPADDING",    (0, 2), (-1, 2), 2),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 4),
    ]))
    parts.append(matrix_tbl)
    parts.append(Spacer(1, 3 * mm))

    # Threat indicator row (Zero-days, Malware exploited, Exploited in wild, Easily exploitable, Widely exploited)
    kev_count = sum(1 for c in all_cves if c.get("in_kev"))
    # Conditional font size for threat indicator values
    threat_max = max(zero_days, malware_count, kev_count, easily_exploitable, widely_exploited)
    threat_val_size = 14 if threat_max < 100 else 12
    threat_val_leading = 18 if threat_max < 100 else 16
    threat_val_style = ParagraphStyle("vp_threat_val", fontSize=threat_val_size, fontName="Helvetica-Bold",
                                       textColor=C_BLACK, alignment=TA_CENTER, leading=threat_val_leading)
    threat_data = [
        [Paragraph("<b>Zero-days</b>", header_style),
         Paragraph("<b>Malware exploited</b>", header_style),
         Paragraph("<b>Exploited in wild</b>", header_style),
         Paragraph("<b>Easily exploitable</b>", header_style),
         Paragraph("<b>Widely exploited</b>", header_style)],
        [Paragraph(f"<b>{zero_days}</b>", threat_val_style),
         Paragraph(f"<b>{malware_count}</b>", threat_val_style),
         Paragraph(f"<b>{kev_count}</b>", threat_val_style),
         Paragraph(f"<b>{easily_exploitable}</b>", threat_val_style),
         Paragraph(f"<b>{widely_exploited}</b>", threat_val_style)],
        [Paragraph(f"{zero_days} instance(s)", lbl_style),
         Paragraph(f"{malware_count} instance(s)", lbl_style),
         Paragraph(f"{kev_count} instance(s)", lbl_style),
         Paragraph(f"{easily_exploitable} instance(s)", lbl_style),
         Paragraph(f"{widely_exploited} instance(s)", lbl_style)],
    ]
    threat_col_w = INNER_W / 5
    threat_tbl = Table(threat_data, colWidths=[threat_col_w] * 5)
    _threat_grey = colors.HexColor("#475569")
    threat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _threat_grey),
        ("BACKGROUND",    (0, 1), (-1, 1), C_GREY_1),
        ("BACKGROUND",    (0, 2), (-1, 2), C_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING",    (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("TOPPADDING",    (0, 2), (-1, 2), 2),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 4),
    ]))
    parts.append(threat_tbl)
    parts.append(Spacer(1, 2 * mm))

    # Plain-English legend for threat indicators
    legend_style = S["vp_legend"]
    legend_items = [
        "<b>Zero-days:</b> Vulnerabilities with no vendor patch available — no fix exists yet, requiring alternative mitigations.",
        "<b>Malware exploited:</b> Vulnerabilities known to be used by ransomware groups or malware campaigns to attack organisations.",
        "<b>Exploited in wild:</b> Confirmed by CISA (US Cybersecurity Agency) as actively exploited by attackers right now.",
        "<b>Easily exploitable:</b> Can be exploited remotely over the internet with no special tools, passwords, or user interaction required.",
        "<b>Widely exploited:</b> High probability of mass exploitation — automated attack tools are scanning the internet for this vulnerability.",
    ]
    for item in legend_items:
        parts.append(Paragraph(item, legend_style))
    parts.append(Spacer(1, 3 * mm))

    # Narrative paragraph
    narrative = (
        f"This assessment identified <b>{total}</b> known vulnerabilities on the assessed infrastructure"
    )
    if critical > 0:
        narrative += f", of which <b>{critical}</b> are classified as critical severity"
    if high > 0:
        narrative += f" and <b>{high}</b> as high severity"
    narrative += ". "

    if over_180 > 0:
        narrative += (
            f"<b>{over_180}</b> vulnerabilit{'y has' if over_180 == 1 else 'ies have'} "
            f"remained unpatched for over 180 days"
        )
        if oldest > 365:
            narrative += (
                f" — the oldest being <b>{oldest} days</b> old, indicating that software updates "
                f"have not been applied for over {oldest // 365} year(s)"
            )
        narrative += ". "

    if easily_exploitable > 0:
        narrative += (
            f"<b>{easily_exploitable}</b> vulnerabilit{'y is' if easily_exploitable == 1 else 'ies are'} "
            f"easily exploitable — requiring no authentication and accessible directly from the internet. "
        )

    if widely_exploited > 0:
        narrative += (
            f"<b>{widely_exploited}</b> {'is' if widely_exploited == 1 else 'are'} widely exploited "
            f"with a high probability of mass exploitation. "
        )

    if malware_count > 0:
        narrative += (
            f"<b>{malware_count}</b> vulnerabilit{'y is' if malware_count == 1 else 'ies are'} "
            f"associated with known ransomware campaigns ({', '.join(ransomware_names)}). "
        )
    else:
        narrative += "No vulnerabilities were associated with known ransomware campaigns. "

    if zero_days > 0:
        narrative += (
            f"<b>{zero_days}</b> vulnerabilit{'y has' if zero_days == 1 else 'ies have'} "
            f"no vendor patch available. "
        )
    else:
        narrative += "No active zero-day exploits were identified. "

    narrative += (
        f"The overall patch management posture is rated as "
        f"<b><font color='{pm_color}'>{pm_rating}</font></b>"
    )
    if avg_age > 0:
        narrative += f" (average vulnerability age: {avg_age} days)"
    narrative += "."

    parts.append(Paragraph(narrative, S["body"]))
    parts.append(Spacer(1, 2 * mm))

    return parts


_KILL_CHAIN_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _supply_chain_attacker_findings(cats: dict) -> dict:
    """Supply-chain findings mapped to kill-chain phases (Card-Verification Step 7).
    Returns {'access': [...], 'exploit': [...]} - supplier-vectored entry in Initial
    Access, exploitable third-party components in Exploitation. Same fields the
    Supply-Chain Exposure slide uses, so the narrative and the slide never diverge."""
    vb = cats.get("vendor_breach", {}) or {}
    tpc = cats.get("third_party_correlation", {}) or {}
    evs = cats.get("email_vendor_surface", {}) or {}
    tpjs = cats.get("third_party_js", {}) or {}
    dm = cats.get("dependency_manifests", {}) or {}
    cms = cats.get("cms_plugin_sbom", {}) or {}
    access, exploit = [], []
    # Phase 2 - supplier-vectored initial access
    matches = vb.get("matches") or []
    if matches:
        top = matches[0]; mo = max(1, (top.get("age_days") or 0) // 30)
        access.append(f"{len(matches)} breached supplier(s) (e.g. {top.get('vendor','?')} "
                      f"~{mo}mo ago) - supply-chain credential reuse, rotation often incomplete")
    hr_tp = tpc.get("hudson_rock_third_party_count", 0)
    if hr_tp:
        access.append(f"{hr_tp} third-party / vendor credential exposure(s) in infostealer "
                      f"data - supply-chain backdoor")
    if evs.get("weak_dmarc") and evs.get("vendor_count", 0) >= 1:
        access.append(f"{evs.get('vendor_count')} email vendor(s) authorised with weak DMARC "
                      f"(p={evs.get('dmarc_policy') or 'missing'}) - phishing-via-supplier")
    # Phase 3 - exploitable third-party components
    comp = tpjs.get("compromised_host_count", 0); miss = tpjs.get("missing_sri_count", 0)
    if comp:
        exploit.append(f"{comp} compromised third-party script(s) live - Magecart-style "
                       f"client-side code injection")
    elif miss:
        exploit.append(f"{miss} third-party script(s) without integrity (SRI) - supply-chain "
                       f"tampering risk")
    if cms.get("is_wordpress") and cms.get("versioned_count", 0) > 0:
        exploit.append(f"{cms.get('versioned_count')} WordPress plugin(s) with readable versions "
                       f"- known plugin CVEs are a top SA SME exploit vector")
    crit_cves = dm.get("total_critical_cves", 0); man = dm.get("exposed_manifests") or []
    if crit_cves:
        exploit.append(f"{crit_cves} critical CVE(s) from an exposed dependency manifest - "
                       f"zero-recon exploit chaining")
    elif man:
        exploit.append(f"{len(man)} exposed dependency manifest(s) - version map enables CVE chaining")
    return {"access": access, "exploit": exploit}


def _kill_chain_severities(results: dict) -> dict:
    """Single source of truth for the four attacker-kill-chain phase severities.

    Both the full/broker Attacker's View (_build_attackers_view) and the
    executive-deck kill chain (_assessment_kill_chain) call this, so the two
    outputs can never disagree on phase severity again. Logic is the deck's
    (the one that matched the underlying data): Phase 3 keys off CVEs / SSL /
    header score with a real LOW tier; Phase 4 keys off RSI bands + DB exposure.
    """
    cats = results.get("categories", {}) or {}
    ins = results.get("insurance", {}) or {}

    # Phase 1 — Reconnaissance
    ip_count = cats.get("external_ips", {}).get("total_unique_ips", 0)
    emails = cats.get("dehashed", {}).get("unique_emails", 0)
    recon = ("HIGH" if (ip_count > 5 or emails > 3)
             else "MEDIUM" if (ip_count > 1 or emails > 0) else "LOW")

    # Phase 2 — Initial Access
    rdp = cats.get("vpn_remote", {}).get("rdp_exposed", False)
    hrp = cats.get("high_risk_protocols", {}).get("exposed_services", []) or []
    cred_leaks = cats.get("dehashed", {}).get("total_entries", 0)
    infostealers = cats.get("hudson_rock", {}).get("compromised_employees", 0)
    # Supply-chain initial-access escalators (Step 7).
    _vb = cats.get("vendor_breach", {}) or {}
    _tpc = cats.get("third_party_correlation", {}) or {}
    _evs = cats.get("email_vendor_surface", {}) or {}
    sc_acc_crit = _vb.get("critical_match_count", 0) > 0
    sc_acc_high = _vb.get("high_match_count", 0) > 0 or _tpc.get("hudson_rock_third_party_count", 0) > 0
    sc_acc_med = bool(_vb.get("matches")) or (_evs.get("weak_dmarc") and _evs.get("vendor_count", 0) >= 1)
    access = ("CRITICAL" if (rdp or infostealers > 0 or sc_acc_crit)
              else "HIGH" if (len(hrp) > 0 or cred_leaks > 5 or sc_acc_high)
              else "MEDIUM" if (cred_leaks > 0 or sc_acc_med) else "LOW")

    # Phase 3 — Exploitation
    osv = cats.get("osv_vulns", {})
    osv_crit = osv.get("critical_count", 0)
    osv_high = osv.get("high_count", 0)
    ssl_grade = cats.get("ssl", {}).get("grade", "A")
    hh_score = cats.get("http_headers", {}).get("score", 100)
    # Supply-chain exploitation escalators (Step 7).
    _tpjs = cats.get("third_party_js", {}) or {}
    _dm = cats.get("dependency_manifests", {}) or {}
    _cms = cats.get("cms_plugin_sbom", {}) or {}
    sc_exp_crit = _tpjs.get("compromised_host_count", 0) > 0 or _dm.get("total_critical_cves", 0) > 0
    sc_exp_high = (_cms.get("is_wordpress") and _cms.get("versioned_count", 0) > 0) \
        or _tpjs.get("missing_sri_count", 0) > 0 or bool(_dm.get("exposed_manifests"))
    exploit = ("CRITICAL" if (osv_crit > 0 or sc_exp_crit)
               else "HIGH" if (osv_high > 0 or ssl_grade in ("D", "E", "F") or sc_exp_high)
               else "MEDIUM" if hh_score < 50 else "LOW")

    # Phase 4 — Data Access & Impact
    db_ports = {3306, 5432, 27017, 6379, 9200, 1433}
    db_exposed = any(s.get("port") in db_ports for s in hrp)
    rsi = ins.get("rsi", {}).get("rsi_score", 0)
    data = ("CRITICAL" if (db_exposed or rsi >= 0.75)
            else "HIGH" if rsi >= 0.50
            else "MEDIUM" if rsi >= 0.25 else "LOW")

    return {"recon": recon, "access": access, "exploit": exploit, "data": data}


def _build_attackers_view(results: dict, S) -> list:
    """Build an Attacker's View section that maps findings to the cyber kill chain."""
    cats = results.get("categories", {})
    ins = results.get("insurance", {})
    parts = []

    parts.append(Paragraph("<b>Attacker's View — How a Threat Actor Would Approach This Target</b>", S["cat_title"]))
    parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph(
        "<i>This section maps the scan findings to a real-world attack scenario, showing how a cybercriminal "
        "would use the identified weaknesses to compromise this organisation. Each phase represents a step "
        "in a typical attack.</i>", S["body_muted"]))
    parts.append(Spacer(1, 3 * mm))

    # Phase severities come from the shared helper so this view and the
    # executive-deck kill chain stay in lock-step.
    sevs = _kill_chain_severities(results)

    rows = []
    bgs = []

    # Phase 1: Reconnaissance
    sub_count = cats.get("subdomains", {}).get("total_count", 0)
    ip_count = results.get("categories", {}).get("external_ips", {}).get("total_unique_ips", 0)
    tech = cats.get("tech_stack", {})
    dh = cats.get("dehashed", {})
    emails = dh.get("unique_emails", 0)
    recon_risk = sevs["recon"]
    recon_findings = []
    if ip_count: recon_findings.append(f"{ip_count} external IPs discoverable")
    if sub_count: recon_findings.append(f"{sub_count} subdomains enumerable")
    if emails: recon_findings.append(f"{emails} email addresses found in breach databases")
    server_sw = tech.get("server_software") or []
    if server_sw: recon_findings.append(f"Server technology exposed: {', '.join(server_sw[:3])}")

    _PHASE_BG = {"CRITICAL": C_CRITICAL_BG, "HIGH": C_RED_BG, "MEDIUM": C_AMBER_BG, "LOW": C_GREEN_BG}
    _PHASE_FG = {"CRITICAL": "#991b1b", "HIGH": "#dc2626", "MEDIUM": "#92400e", "LOW": "#166534"}

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[recon_risk]}'>Phase 1: RECONNAISSANCE [{recon_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[recon_risk]}'><b>What an attacker learns about the target</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[recon_risk])
    for f in recon_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 2: Initial Access
    rdp = cats.get("vpn_remote", {}).get("rdp_exposed", False)
    hrp = cats.get("high_risk_protocols", {}).get("exposed_services", [])
    cred_leaks = dh.get("total_entries", 0)
    hr = cats.get("hudson_rock", {})
    infostealers = hr.get("compromised_employees", 0)
    access_risk = sevs["access"]
    access_findings = []
    if rdp: access_findings.append("RDP (port 3389) exposed — primary ransomware entry vector, brute-force attack possible")
    for svc in hrp[:3]:
        access_findings.append(f"{svc.get('service', 'Unknown')} on port {svc.get('port', '?')} — direct attack vector")
    if cred_leaks: access_findings.append(f"{cred_leaks} stolen credentials available from breach databases — enables credential stuffing")
    if infostealers: access_findings.append(f"{infostealers} employee device(s) with active infostealer — real-time credential theft")
    dmarc = cats.get("email_security", {}).get("dmarc", {})
    if not dmarc.get("present"): access_findings.append("No DMARC policy — domain can be spoofed for phishing attacks against employees")
    access_findings += _supply_chain_attacker_findings(cats)["access"]  # Step 7

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[access_risk]}'>Phase 2: INITIAL ACCESS [{access_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[access_risk]}'><b>How an attacker would break in</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[access_risk])
    for f in access_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 3: Exploitation
    osv = cats.get("osv_vulns", {})
    osv_crit = osv.get("critical_count", 0)
    osv_high = osv.get("high_count", 0)
    shodan = cats.get("shodan_vulns", {})
    shodan_cves = shodan.get("total_cves", 0)
    ssl_grade = cats.get("ssl", {}).get("grade", "A")
    exploit_risk = sevs["exploit"]
    exploit_findings = []
    if osv_crit: exploit_findings.append(f"{osv_crit} critical CVE(s) with known exploits — remote code execution possible")
    if osv_high: exploit_findings.append(f"{osv_high} high-severity CVE(s) — privilege escalation and data access")
    if ssl_grade in ("D", "E", "F"): exploit_findings.append(f"SSL grade {ssl_grade} — weak encryption enables man-in-the-middle interception")
    headers = cats.get("http_headers", {}).get("score", 100)
    if headers < 40: exploit_findings.append(f"Security headers score {headers}% — vulnerable to XSS, clickjacking, and injection attacks")
    exploit_findings += _supply_chain_attacker_findings(cats)["exploit"]  # Step 7
    if not exploit_findings: exploit_findings.append("No critical exploitation vectors identified from external scan")

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[exploit_risk]}'>Phase 3: EXPLOITATION [{exploit_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[exploit_risk]}'><b>What vulnerabilities an attacker would exploit</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[exploit_risk])
    for f in exploit_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 4: Data Access & Impact (severity from shared kill-chain helper)
    db_exposed = any(s.get("port") in (3306, 5432, 27017, 6379, 9200, 1433) for s in hrp)
    ix = cats.get("intelx", {})
    darkweb = ix.get("total_results", 0)
    fin = ins.get("financial_impact", {})
    fin_p50 = fin.get("monte_carlo", {}).get("total", {}).get("p50", 0)
    data_risk = sevs["data"]

    data_findings = []
    if db_exposed: data_findings.append("Databases directly internet-facing — attacker can extract all business data without further escalation")
    if darkweb > 0: data_findings.append(f"{darkweb} references in dark web databases — stolen data is already circulating in criminal networks")
    rsi = ins.get("rsi", {}).get("rsi_score", 0)
    if rsi > 0.5: data_findings.append(f"Ransomware susceptibility {rsi:.0%} — high probability of ransomware deployment after access is gained")
    if fin_p50:
        cur = "R" if fin.get("currency") == "ZAR" else "$"
        data_findings.append(f"Estimated financial impact: {cur}&nbsp;{fin_p50:,.0f} (Monte Carlo P50 median)")
    if not data_findings: data_findings.append("Limited external data access vectors identified")

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[data_risk]}'>Phase 4: DATA ACCESS & IMPACT [{data_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[data_risk]}'><b>What an attacker would steal or destroy</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[data_risk])
    for f in data_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    tbl = _cat_table(rows, bgs, [40 * mm, INNER_W - 40 * mm], S)
    parts.append(tbl)
    parts.append(Spacer(1, 3 * mm))
    return parts
