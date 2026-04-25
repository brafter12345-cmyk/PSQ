"""
Scoring, analytics, and insurance modules: ExternalIPAggregator, RiskScorer,
RansomwareIndex, FinancialImpactCalculator, DataBreachIndex, RemediationSimulator,
plus COMPLIANCE_MAP and SA_INDUSTRY_COSTS constants.
"""

from scanner_utils import *


# ---------------------------------------------------------------------------
# External IP Aggregator
# ---------------------------------------------------------------------------
# Not a scanner — aggregates discovered IPs + per-IP Shodan results into
# the external_ips structure that the CVE / Known Vulnerabilities panel expects.

class ExternalIPAggregator:
    """
    Builds the external_ips result dict from discovered IPs and per-IP
    Shodan results. Provides IP classification, ASN aggregation, and
    vulnerability summary across all IPs.
    """

    @staticmethod
    def aggregate(discovered_ips: list, per_ip_results: dict, ip_sources: dict = None) -> dict:
        """
        Args:
            discovered_ips: List of IP strings from Phase 1 discovery.
            per_ip_results: Dict of {ip: {checker_name: result}} from Phase 3.

        Returns:
            Dict matching the external_ips template shape.
        """
        result = {
            "status": "completed",
            "total_unique_ips": 0,
            "ipv4_count": 0,
            "ipv6_count": 0,
            "unique_asns": 0,
            "unique_countries": 0,
            "ip_addresses": [],
            "aggregate_vulns": {
                "total_cves": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "kev_count": 0,
                "ips_with_vulns": 0,
                "max_cvss": 0,
                "max_epss": 0,
            },
            "score": 100,
            "issues": [],
        }

        if not discovered_ips:
            return result

        seen_ips = set()
        asns = set()
        countries = set()
        ipv4 = 0
        ipv6 = 0
        ip_entries = []
        agg = result["aggregate_vulns"]

        for i, ip in enumerate(discovered_ips):
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Classify IP version
            if ":" in ip:
                ipv6 += 1
            else:
                ipv4 += 1

            # Get Shodan results for this IP
            ip_data = per_ip_results.get(ip, {})
            shodan = ip_data.get("shodan_vulns", {})
            dns_info = ip_data.get("dns_infrastructure", {})

            # Extract org/ASN/country from Shodan full API or DNS
            org = shodan.get("org", "")
            asn = shodan.get("asn", "")
            country = shodan.get("country", "")
            city = shodan.get("city", "")
            reverse_dns = dns_info.get("reverse_dns", "")
            hostnames = shodan.get("hostnames", [])

            if asn:
                asns.add(asn)
            if country:
                countries.add(country)

            # Build per-IP vulnerability summary
            cves = shodan.get("cves", [])
            cve_count = len(cves)
            critical = sum(1 for c in cves if c.get("severity") == "critical")
            high = sum(1 for c in cves if c.get("severity") == "high")
            medium = sum(1 for c in cves if c.get("severity") == "medium")
            low = sum(1 for c in cves if c.get("severity") == "low")
            kev = sum(1 for c in cves if c.get("in_kev"))
            max_cvss = max((c.get("cvss_score", 0) for c in cves), default=0)
            max_epss = max((c.get("epss_score", 0) for c in cves if c.get("epss_score")), default=0)

            # Risk score per IP — combine CVE score with port/protocol risk
            ip_score = shodan.get("score", 100)

            # Penalise for high-risk open ports (even without CVEs)
            hrp = ip_data.get("high_risk_protocols", {})
            open_ports = shodan.get("open_ports", [])
            high_risk_ports = {21, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
            exposed_high = [p for p in open_ports if p in high_risk_ports]
            exposed_services = hrp.get("exposed_services", [])

            port_penalty = len(exposed_high) * 10  # 10 pts per high-risk port
            svc_penalty = sum(15 if s.get("risk") == "critical" else 8
                              for s in exposed_services)  # extra for critical services
            total_port_penalty = min(60, port_penalty + svc_penalty)

            ip_score = max(0, ip_score - total_port_penalty)

            if ip_score < 20:
                risk_label = "Critical"
            elif ip_score < 50:
                risk_label = "High"
            elif ip_score < 80:
                risk_label = "Medium"
            else:
                risk_label = "Low"

            # Remediation hint
            remediation = ""
            if critical > 0:
                remediation = f"Patch {critical} critical CVE(s) immediately — active exploitation likely"
            elif high > 0:
                remediation = f"Prioritise patching {high} high-severity CVE(s) within 30 days"
            elif cve_count > 0:
                remediation = f"Review and patch {cve_count} known vulnerability(ies)"

            # Determine sources from ip_sources tracking
            ip_src = (ip_sources or {}).get(ip, [])
            sources = ip_src if ip_src else ["A record"]
            if i == 0 and "primary" not in sources:
                sources = sources + ["primary"]

            ip_entry = {
                "ip": ip,
                "is_primary": i == 0,
                "hosting": True,
                "org": org or "Unknown",
                "asn": asn,
                "country": country,
                "city": city,
                "reverse_dns": reverse_dns or (hostnames[0] if hostnames else ""),
                "sources": sources,
                "shodan": {
                    "open_ports": shodan.get("open_ports", []),
                    "cve_count": cve_count,
                    "critical_count": critical,
                    "high_count": high,
                    "medium_count": medium,
                    "low_count": low,
                    "kev_count": kev,
                    "max_cvss": max_cvss,
                    "max_epss": max_epss,
                    "risk_score": ip_score,
                    "risk_label": risk_label,
                    "cves": cves,
                    "remediation": remediation,
                    "data_source": shodan.get("data_source", "internetdb"),
                    "tags": shodan.get("tags", []),
                },
            }
            ip_entries.append(ip_entry)

            # Aggregate totals
            if cve_count > 0:
                agg["ips_with_vulns"] += 1
            agg["total_cves"] += cve_count
            agg["critical_count"] += critical
            agg["high_count"] += high
            agg["medium_count"] += medium
            agg["low_count"] += low
            agg["kev_count"] += kev
            agg["max_cvss"] = max(agg["max_cvss"], max_cvss)
            agg["max_epss"] = max(agg["max_epss"], max_epss)

        result["total_unique_ips"] = len(seen_ips)
        result["ipv4_count"] = ipv4
        result["ipv6_count"] = ipv6
        result["unique_asns"] = len(asns) if asns else 1  # at least 1 if IPs found
        result["unique_countries"] = len(countries) if countries else 1
        result["ip_addresses"] = ip_entries

        # Scoring
        if agg["critical_count"] > 0 or agg["kev_count"] > 0:
            result["score"] = max(0, 20 - agg["critical_count"] * 5)
            result["issues"].append(
                f"CRITICAL: {agg['critical_count']} critical CVE(s) across {agg['ips_with_vulns']} IP(s)"
            )
        elif agg["high_count"] > 0:
            result["score"] = max(20, 50 - agg["high_count"] * 5)
            result["issues"].append(
                f"{agg['high_count']} high-severity CVE(s) detected across external IPs"
            )
        elif agg["total_cves"] > 0:
            result["score"] = max(50, 80 - agg["total_cves"] * 2)
            result["issues"].append(
                f"{agg['total_cves']} CVE(s) detected — review and prioritise patching"
            )

        if agg["kev_count"] > 0:
            result["issues"].append(
                f"CRITICAL: {agg['kev_count']} CVE(s) in CISA Known Exploited Vulnerabilities catalog — "
                "active exploitation confirmed"
            )

        return result


# ---------------------------------------------------------------------------
# Compliance Framework Mapping
# ---------------------------------------------------------------------------
# Maps checker IDs to regulatory/standards control IDs for compliance reporting.

COMPLIANCE_MAP = {
    "POPIA": {
        "S19a \u2014 Encryption in Transit": {
            "description": "Secure data transmission using strong encryption (TLS 1.2+)",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "S19b \u2014 Security Headers": {
            "description": "HTTP security headers to prevent XSS, clickjacking, MIME attacks",
            "checkers": ["http_headers"],
            "weight": 1.0,
        },
        "S19c \u2014 Web Application Security": {
            "description": "Secure web application configuration and WAF protection",
            "checkers": ["website_security", "waf"],
            "weight": 1.0,
        },
        "S19d \u2014 Network Access Control": {
            "description": "Restrict remote access and close high-risk network services",
            "checkers": ["vpn_remote", "high_risk_protocols"],
            "weight": 1.2,
        },
        "S19e \u2014 Email Security": {
            "description": "SPF, DMARC, DKIM to prevent phishing and impersonation",
            "checkers": ["email_security", "email_hardening"],
            "weight": 0.8,
        },
        "S20a \u2014 Privacy Policy": {
            "description": "Published privacy policy covering all required POPIA sections",
            "checkers": ["privacy_compliance"],
            "weight": 1.0,
        },
        "S20b \u2014 Data Minimisation": {
            "description": "Limit data collection and avoid unnecessary information exposure",
            "checkers": ["info_disclosure", "exposed_admin"],
            "weight": 0.8,
        },
        "S21a \u2014 Software Currency": {
            "description": "Keep software and frameworks up to date, no end-of-life components",
            "checkers": ["tech_stack"],
            "weight": 1.0,
        },
        "S22a \u2014 Breach History": {
            "description": "Historical data breach exposure and notification readiness",
            "checkers": ["breaches"],
            "weight": 1.0,
        },
        "S22b \u2014 Credential Exposure": {
            "description": "Leaked credentials in public breach databases",
            "checkers": ["dehashed"],
            "weight": 1.0,
        },
    },
    "PCI DSS v4.0": {
        "Req 2a \u2014 Default Credentials": {
            "description": "Remove default accounts, change vendor defaults before deployment",
            "checkers": ["exposed_admin"],
            "weight": 1.2,
        },
        "Req 2b \u2014 System Hardening": {
            "description": "Harden system configurations and disable unnecessary services",
            "checkers": ["http_headers", "info_disclosure"],
            "weight": 1.0,
        },
        "Req 2c \u2014 Security Policies": {
            "description": "Documented security policies and procedures",
            "checkers": ["security_policy"],
            "weight": 0.8,
        },
        "Req 4a \u2014 TLS Configuration": {
            "description": "Strong TLS encryption for cardholder data transmission",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "Req 4b \u2014 HTTPS Enforcement": {
            "description": "Enforce HTTPS across all endpoints handling sensitive data",
            "checkers": ["website_security"],
            "weight": 1.0,
        },
        "Req 6a \u2014 Patch Management": {
            "description": "Keep systems patched and free of known vulnerabilities",
            "checkers": ["tech_stack", "shodan_vulns"],
            "weight": 1.2,
        },
        "Req 6b \u2014 Secure Coding": {
            "description": "Develop applications securely and protect against common attacks",
            "checkers": ["website_security", "http_headers"],
            "weight": 1.0,
        },
        "Req 8a \u2014 Payment Security": {
            "description": "Secure payment processing and PCI-compliant payment forms",
            "checkers": ["payment_security"],
            "weight": 1.2,
        },
        "Req 11a \u2014 Vulnerability Scanning": {
            "description": "Regular vulnerability scanning of external-facing systems",
            "checkers": ["shodan_vulns"],
            "weight": 1.0,
        },
        "Req 11b \u2014 Threat Monitoring": {
            "description": "Monitor for malicious activity and reputation threats",
            "checkers": ["virustotal", "dnsbl"],
            "weight": 0.8,
        },
    },
    "ISO 27001": {
        "A.8a \u2014 Asset Inventory": {
            "description": "Identify and document all information assets and infrastructure",
            "checkers": ["tech_stack", "external_ips"],
            "weight": 1.0,
        },
        "A.8b \u2014 Attack Surface": {
            "description": "Map and manage the external attack surface including subdomains",
            "checkers": ["subdomains"],
            "weight": 0.8,
        },
        "A.12a \u2014 Network Security": {
            "description": "Secure network services and close unnecessary ports",
            "checkers": ["high_risk_protocols", "dns_infrastructure"],
            "weight": 1.2,
        },
        "A.12b \u2014 Remote Access": {
            "description": "Secure remote access methods, restrict RDP and insecure protocols",
            "checkers": ["vpn_remote"],
            "weight": 1.0,
        },
        "A.12c \u2014 Malware & Reputation": {
            "description": "Monitor for malware, blocklisting, and reputation issues",
            "checkers": ["dnsbl", "virustotal"],
            "weight": 1.0,
        },
        "A.12d \u2014 DDoS Resilience": {
            "description": "Web application firewall and DDoS protection mechanisms",
            "checkers": ["waf", "cloud_cdn"],
            "weight": 0.8,
        },
        "A.14a \u2014 Encryption Standards": {
            "description": "Strong encryption for data in transit and at rest",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "A.14b \u2014 Application Security": {
            "description": "Secure application development and deployment practices",
            "checkers": ["http_headers", "website_security"],
            "weight": 1.0,
        },
        "A.14c \u2014 Payment & Data Handling": {
            "description": "Secure handling of payment data and sensitive information",
            "checkers": ["payment_security", "info_disclosure"],
            "weight": 1.0,
        },
    },
    "NIST CSF 2.0": {
        "GV.1 \u2014 Security Policy": {
            "description": "Documented cybersecurity policies and governance framework",
            "checkers": ["security_policy"],
            "weight": 0.8,
        },
        "GV.2 \u2014 Privacy Governance": {
            "description": "Privacy policy and data protection compliance programme",
            "checkers": ["privacy_compliance"],
            "weight": 0.8,
        },
        "ID.1 \u2014 Asset Discovery": {
            "description": "Identify and inventory organisational IT assets",
            "checkers": ["tech_stack", "external_ips"],
            "weight": 1.0,
        },
        "ID.2 \u2014 Attack Surface Mapping": {
            "description": "Discover subdomains, exposed services, and shadow IT",
            "checkers": ["subdomains", "info_disclosure"],
            "weight": 0.8,
        },
        "PR.1 \u2014 Encryption & TLS": {
            "description": "Protect data in transit with strong encryption",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "PR.2 \u2014 Security Headers & Hardening": {
            "description": "HTTP security headers and web application hardening",
            "checkers": ["http_headers", "website_security"],
            "weight": 1.0,
        },
        "PR.3 \u2014 Perimeter Defence": {
            "description": "WAF, firewall, and network perimeter protection",
            "checkers": ["waf", "high_risk_protocols", "vpn_remote"],
            "weight": 1.2,
        },
        "PR.4 \u2014 Email Authentication": {
            "description": "SPF, DMARC, DKIM to prevent email-based attacks",
            "checkers": ["email_security", "email_hardening"],
            "weight": 0.8,
        },
        "DE.1 \u2014 Vulnerability Detection": {
            "description": "Detect known vulnerabilities across external infrastructure",
            "checkers": ["shodan_vulns"],
            "weight": 1.2,
        },
        "DE.2 \u2014 Threat Intelligence": {
            "description": "Monitor for malicious activity, blocklisting, and fraud",
            "checkers": ["virustotal", "dnsbl", "exposed_admin"],
            "weight": 1.0,
        },
        "RS.1 \u2014 Breach Response": {
            "description": "Historical breach exposure and incident response readiness",
            "checkers": ["breaches", "dehashed"],
            "weight": 1.0,
        },
        "RS.2 \u2014 Security Disclosure": {
            "description": "Published security contact and vulnerability disclosure policy",
            "checkers": ["security_policy"],
            "weight": 0.6,
        },
        "RC.1 \u2014 Infrastructure Resilience": {
            "description": "DNS redundancy, CDN, and infrastructure recovery capability",
            "checkers": ["dns_infrastructure", "cloud_cdn"],
            "weight": 0.8,
        },
        "RC.2 \u2014 Communication Recovery": {
            "description": "Email infrastructure resilience and recovery capability",
            "checkers": ["email_security"],
            "weight": 0.6,
        },
    },
}


# 28. Risk Scoring Engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Weighted 0-1000 risk score.
    All weights must sum to 100 when WAF bonus excluded.
    """
    WEIGHTS = {
        "ssl":                  0.09,
        "email_security":       0.06,
        "email_hardening":      0.02,
        "breaches":             0.07,
        "http_headers":         0.05,
        "website_security":     0.04,
        "exposed_admin":        0.09,
        "high_risk_protocols":  0.08,
        "dnsbl":                0.06,
        "tech_stack":           0.05,
        "payment_security":     0.02,
        "vpn_remote":           0.04,
        "subdomains":           0.02,
        "shodan_vulns":         0.07,
        "dehashed":             0.03,
        "virustotal":           0.05,
        "securitytrails":       0.01,
        "fraudulent_domains":   0.04,
        "privacy_compliance":   0.02,
        "web_ranking":          0.02,
        "info_disclosure":      0.05,
        "external_ips":         0.03,
        "ransomware_risk":      0.06,
        "data_breach_index":    0.03,
        "financial_impact":     0.02,
    }  # Sum — includes all checkers from both branches

    RECOMMENDATIONS = {
        "SSL certificate has EXPIRED": "Renew your SSL certificate immediately — an expired cert causes browser warnings and erodes user trust.",
        "TLS 1.0 supported — deprecated and insecure": "Disable TLS 1.0 on your web server. Set minimum TLS version to 1.2.",
        "TLS 1.1 supported — deprecated": "Disable TLS 1.1. Modern clients support TLS 1.2+.",
        "No SPF record — spoofing risk": "Add an SPF record (e.g. 'v=spf1 include:_spf.google.com -all') to prevent email spoofing.",
        "SPF uses '+all'": "Change SPF to use '-all' (hard fail) or '~all' (soft fail) — '+all' is extremely dangerous.",
        "No DMARC record — phishing risk": "Add a DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com'.",
        "DMARC policy is 'none'": "Upgrade DMARC policy from 'none' to 'quarantine' or 'reject' to enforce email authentication.",
        "No DKIM selectors found": "Configure DKIM signing for outbound email and publish the public key in DNS.",
        "No MTA-STS policy": "Implement MTA-STS to force TLS for inbound email and prevent downgrade attacks.",
        "TLS-RPT not configured": "Configure TLS-RPT (add _smtp._tls TXT record) to receive reports about email TLS delivery failures.",
        "CRITICAL: Zone transfer (AXFR) permitted": "CRITICAL: Disable zone transfers immediately — configure 'allow-transfer { none; };' on all DNS servers.",
        "CRITICAL: Subdomain takeover possible": "CRITICAL: Reclaim or remove dangling DNS records pointing to unclaimed cloud services — attackers can claim these and host phishing content on your domain.",
        "HTTPS not enforced": "Configure your web server to redirect all HTTP traffic to HTTPS (301 redirect).",
        "HSTS header missing": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        "Missing security header: Content-Security-Policy": "Implement a Content Security Policy to mitigate XSS attacks.",
        "Missing security header: X-Frame-Options": "Add 'X-Frame-Options: DENY' to prevent clickjacking.",
        "Missing security header: X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
        "No WAF detected": "Deploy a Web Application Firewall (e.g. Cloudflare, AWS WAF, Imperva) to filter malicious traffic.",
        "RDP (port 3389) is exposed": "Block RDP from public internet immediately. Use VPN or Zero Trust access for remote desktop.",
        "No VPN/remote access gateway detected": "Implement a VPN or Zero Trust Network Access (ZTNA) solution for remote workers.",
        "No security.txt found": "Create a security.txt file at /.well-known/security.txt to establish a vulnerability disclosure policy.",
        "CRITICAL: Sensitive file exposed": "Immediately restrict access to sensitive files. Audit your web server configuration and .htaccess rules.",
        "CRITICAL:": "Immediately investigate and remediate the critically exposed service.",
        "EOL software detected": "Update all end-of-life software immediately — unpatched software is a leading cause of breaches.",
        "Domain/IP listed on": "Investigate blacklist listings — likely indicates past spam, malware distribution, or compromise.",
        "Self-hosted payment card form": "Migrate to a PCI-compliant payment provider (Stripe, PayFast, Peach Payments) to avoid storing card data.",
        "No known breaches found": "",
        "CRITICAL: 1 critical CVE": "Patch critical CVEs on your public-facing servers immediately — attackers actively exploit these.",
        "critical CVE(s) found": "Patch critical CVEs on your public-facing servers immediately — attackers actively exploit these.",
        "high-severity CVE(s) detected": "Review and patch high-severity CVEs — schedule remediation within 30 days.",
        "medium-severity CVE(s) detected": "Review medium-severity CVEs and schedule patching within 90 days.",
        "credential record(s) found in Dehashed": "Notify affected users and enforce mandatory password reset for all leaked accounts.",
        "Plaintext or hashed passwords found": "Enforce immediate password reset and review authentication systems for all affected accounts.",
        "security engine(s) flagged this domain as MALICIOUS": "Investigate VirusTotal malicious flags immediately — your domain may be compromised or serving malware.",
        "security engine(s) flagged this domain as suspicious": "Review VirusTotal suspicious flags — investigate potential domain compromise or abuse.",
        "Domain categorized as": "Review domain categorization flags — being labeled as phishing/malware damages reputation and deliverability.",
        "associated domains on shared infrastructure": "Consider dedicated hosting to reduce shared-infrastructure risk and improve security isolation.",
        "lookalike domains detected": "Register key lookalike domains defensively and set up domain monitoring for brand impersonation.",
        "lookalike domain(s) found": "Review detected lookalike domains for potential typosquatting — consider defensive registration.",
        "No privacy policy found": "Publish a comprehensive privacy policy to comply with POPIA/GDPR — failure to do so risks regulatory fines.",
        "Privacy policy missing critical sections": "Update your privacy policy to include all required sections for POPIA/GDPR compliance.",
    }

    # Statuses that indicate a checker failed and should be excluded from scoring
    _FAILED_STATUSES = {"error", "timeout"}
    # Statuses that indicate a checker was intentionally skipped (no API key,
    # toggle off) — these should NOT count as failures in the completeness warning
    _SKIPPED_STATUSES = {"no_api_key", "auth_failed", "disabled", "skipped"}

    def _is_failed(self, checker_data: dict) -> bool:
        """Return True if this checker errored/timed out and should be excluded."""
        return checker_data.get("status") in self._FAILED_STATUSES

    def calculate(self, results: dict) -> tuple:
        def inv(score_0_100):
            return 100 - score_0_100

        # --- Detect failed vs skipped checkers and exclude from scoring ---
        # Failed (error/timeout): checker ran but broke — unreliable data.
        # Skipped (no_api_key/disabled): intentionally not run — not a failure.
        # Both are excluded from weighting, but only failures trigger the
        # incomplete scan warning.
        failed_checkers = []   # Genuine failures — flag in warning
        skipped_checkers = []  # Intentionally skipped — no warning
        for name in self.WEIGHTS:
            data = results.get(name, {})
            if isinstance(data, dict):
                if self._is_failed(data):
                    failed_checkers.append(name)
                elif data.get("status") in self._SKIPPED_STATUSES:
                    skipped_checkers.append(name)

        # Build effective weights — zero out failed + skipped, redistribute
        excluded = set(failed_checkers + skipped_checkers)
        effective_weights = dict(self.WEIGHTS)
        excluded_weight = sum(effective_weights.get(f, 0) for f in excluded)
        for f in excluded:
            effective_weights[f] = 0
        # Redistribute excluded weight proportionally across remaining checkers
        remaining_weight = sum(v for v in effective_weights.values())
        if remaining_weight > 0 and excluded_weight > 0:
            scale = (remaining_weight + excluded_weight) / remaining_weight
            for k in effective_weights:
                if effective_weights[k] > 0:
                    effective_weights[k] *= scale

        # Per-category risk (0-100 scale, higher = more risky)
        ssl_risk = inv(results.get("ssl", {}).get("score", 50))
        email_risk = inv((results.get("email_security", {}).get("score", 5) / 10) * 100)
        email_hard_risk = inv((results.get("email_hardening", {}).get("score", 0) / 10) * 100)

        breach_count = results.get("breaches", {}).get("breach_count", 0)
        breach_risk = min(100, breach_count * 15)

        header_risk = inv(results.get("http_headers", {}).get("score", 50))
        website_risk = inv(results.get("website_security", {}).get("score", 50))

        # Exposed admin panels
        crit = results.get("exposed_admin", {}).get("critical_count", 0)
        high = results.get("exposed_admin", {}).get("high_count", 0)
        admin_risk = min(100, crit * 50 + high * 20)

        # High-risk protocols (database/service exposure)
        hrisky = results.get("high_risk_protocols", {}).get("critical_count", 0)
        hrisk = min(100, hrisky * 35)

        # DNSBL
        listed = len(results.get("dnsbl", {}).get("ip_listings", [])) + \
                 len(results.get("dnsbl", {}).get("domain_listings", []))
        dnsbl_risk = min(100, listed * 50)

        # Tech stack (EOL)
        tech_risk = inv(results.get("tech_stack", {}).get("score", 100))

        # Payment
        pay = results.get("payment_security", {})
        pay_risk = 0
        if pay.get("self_hosted_payment_form"):
            pay_risk = 80
        elif pay.get("has_payment_page") and not pay.get("payment_page_https"):
            pay_risk = 60

        # VPN/remote
        vpn = results.get("vpn_remote", {})
        vpn_risk = 40 if vpn.get("rdp_exposed") else (20 if not vpn.get("vpn_detected") else 0)

        # Subdomains
        risky_subs = len(results.get("subdomains", {}).get("risky_subdomains", []))
        sub_risk = min(100, risky_subs * 15)

        # Shodan CVE risk (boosted for weaponized/PoC exploits)
        shodan = results.get("shodan_vulns", {})
        shodan_risk = inv(shodan.get("score", 100))
        if shodan.get("weaponized_count", 0) > 0:
            shodan_risk = min(100, shodan_risk * 1.3)
        elif shodan.get("poc_public_count", 0) > 0:
            shodan_risk = min(100, shodan_risk * 1.1)

        # Dehashed credential leak risk
        dehashed = results.get("dehashed", {})
        dehashed_total = dehashed.get("total_entries", 0)
        dehashed_risk = min(100, dehashed_total * 2) if dehashed.get("status") not in ("no_api_key", "auth_failed") else 0

        # VirusTotal risk
        vt = results.get("virustotal", {})
        if vt.get("status") not in ("no_api_key", "auth_failed", "rate_limited"):
            vt_risk = inv(vt.get("score", 100))
        else:
            vt_risk = 0

        # SecurityTrails risk (mostly informational, low weight)
        st = results.get("securitytrails", {})
        if st.get("status") not in ("no_api_key", "auth_failed", "rate_limited"):
            st_risk = inv(st.get("score", 100))
        else:
            st_risk = 0

        # Fraudulent domain risk
        fd = results.get("fraudulent_domains", {})
        fd_risk = inv(fd.get("score", 100))

        # Privacy compliance risk
        pc = results.get("privacy_compliance", {})
        pc_risk = inv(pc.get("score", 100))

        # Web ranking risk (unranked = slightly risky)
        wr = results.get("web_ranking", {})
        wr_risk = inv(wr.get("score", 30))

        # Information disclosure risk
        id_res = results.get("info_disclosure", {})
        id_risk = inv(id_res.get("score", 100))

        # External IPs risk (feature branch checker)
        ext_ip = results.get("external_ips", {})
        ext_ip_risk = inv(ext_ip.get("score", 100)) if ext_ip.get("status") not in ("error", None) else 0

        # Ransomware susceptibility index risk (insurance analytics)
        rsi_res = results.get("ransomware_risk", {})
        rsi_risk = min(100, rsi_res.get("rsi_score", 0) * 100) if rsi_res else 0

        # Data breach index risk (insurance analytics)
        dbi_res = results.get("data_breach_index", {})
        dbi_risk = inv(dbi_res.get("dbi_score", 50)) if dbi_res else 0

        # Financial impact risk (insurance analytics)
        fin_res = results.get("financial_impact", {})
        fin_risk = inv(fin_res.get("score", 50)) if fin_res.get("status") == "completed" else 0

        weighted = (
            ssl_risk         * effective_weights.get("ssl", 0) +
            email_risk       * effective_weights.get("email_security", 0) +
            email_hard_risk  * effective_weights.get("email_hardening", 0) +
            breach_risk      * effective_weights.get("breaches", 0) +
            header_risk      * effective_weights.get("http_headers", 0) +
            website_risk     * effective_weights.get("website_security", 0) +
            admin_risk       * effective_weights.get("exposed_admin", 0) +
            hrisk            * effective_weights.get("high_risk_protocols", 0) +
            dnsbl_risk       * effective_weights.get("dnsbl", 0) +
            tech_risk        * effective_weights.get("tech_stack", 0) +
            pay_risk         * effective_weights.get("payment_security", 0) +
            vpn_risk         * effective_weights.get("vpn_remote", 0) +
            sub_risk         * effective_weights.get("subdomains", 0) +
            shodan_risk      * effective_weights.get("shodan_vulns", 0) +
            dehashed_risk    * effective_weights.get("dehashed", 0) +
            vt_risk          * effective_weights.get("virustotal", 0) +
            st_risk          * effective_weights.get("securitytrails", 0) +
            fd_risk          * effective_weights.get("fraudulent_domains", 0) +
            pc_risk          * effective_weights.get("privacy_compliance", 0) +
            wr_risk          * effective_weights.get("web_ranking", 0) +
            id_risk          * effective_weights.get("info_disclosure", 0) +
            ext_ip_risk      * effective_weights.get("external_ips", 0) +
            rsi_risk         * effective_weights.get("ransomware_risk", 0) +
            dbi_risk         * effective_weights.get("data_breach_index", 0) +
            fin_risk         * effective_weights.get("financial_impact", 0)
        )

        risk_score = round(weighted * 10)

        # WAF bonus — reduce score by up to 50 points
        # Only apply if WAF checker actually ran successfully
        if results.get("waf", {}).get("detected") and "waf" not in failed_checkers:
            risk_score = max(0, risk_score - 50)

        risk_score = min(1000, risk_score)

        risk_level = (
            "Critical" if risk_score >= 600 else
            "High"     if risk_score >= 400 else
            "Medium"   if risk_score >= 200 else
            "Low"
        )

        # Build recommendations from all issues
        all_issues = []
        for cat in results.values():
            if isinstance(cat, dict):
                all_issues.extend(cat.get("issues", []))

        recommendations = []
        seen = set()
        for issue in all_issues:
            for key, rec in self.RECOMMENDATIONS.items():
                if key in issue and key not in seen and rec:
                    recommendations.append(rec)
                    seen.add(key)

        if breach_count > 0 and "breach_rec" not in seen:
            recommendations.append(
                f"Domain found in {breach_count} breach(es). Enforce strong passwords, "
                "implement credential monitoring, and review affected user accounts."
            )

        # Attach scan completeness metadata
        # Only genuine failures count against completeness — skipped (no API key,
        # toggle off) are expected and don't indicate an incomplete scan.
        assessable = len(self.WEIGHTS) - len(skipped_checkers)
        scan_completeness = {
            "total_checkers": len(self.WEIGHTS),
            "assessable_checkers": assessable,
            "failed_checkers": failed_checkers,
            "skipped_checkers": skipped_checkers,
            "failed_count": len(failed_checkers),
            "completeness_pct": round((1 - len(failed_checkers) / assessable) * 100) if assessable > 0 else 100,
            "score_reliable": len(failed_checkers) == 0,
        }
        # Store in results so it can be accessed by PDF/HTML
        results["_scan_completeness"] = scan_completeness

        if failed_checkers:
            recommendations.insert(0,
                f"WARNING: {len(failed_checkers)} checker(s) failed during this scan "
                f"({', '.join(failed_checkers)}). The risk score is based on "
                f"{scan_completeness['completeness_pct']}% of available data. "
                f"A re-scan is recommended for a complete assessment."
            )

        return risk_score, risk_level, recommendations

    def compliance_summary(self, results: dict) -> dict:
        """Map checker results to POPIA/PCI/ISO/NIST compliance controls.

        Hybrid scoring: each sub-control gets a 0-100 score from its checkers,
        then the framework overall_pct is the weighted average of all sub-control
        scores. Controls still display pass/partial/fail badges for quick visual.
        """
        summary = {}
        for framework, controls in COMPLIANCE_MAP.items():
            ctrl_results = {}
            weighted_total = 0.0
            weighted_score = 0.0
            for ctrl_name, ctrl_info in controls.items():
                checker_scores = []
                findings = []
                weight = ctrl_info.get("weight", 1.0)
                for chk_id in ctrl_info["checkers"]:
                    chk = results.get(chk_id, {})
                    if not isinstance(chk, dict):
                        continue
                    score = chk.get("score")
                    if score is not None:
                        checker_scores.append(score)
                    for issue in chk.get("issues", []):
                        findings.append(issue)
                if not checker_scores:
                    status = "no_data"
                    avg = 0
                else:
                    avg = sum(checker_scores) / len(checker_scores)
                    if avg >= 70:
                        status = "pass"
                    elif avg >= 40:
                        status = "partial"
                    else:
                        status = "fail"
                    weighted_total += weight
                    weighted_score += avg * weight
                ctrl_results[ctrl_name] = {
                    "status": status,
                    "score": round(avg, 1),
                    "description": ctrl_info["description"],
                    "checkers": ctrl_info["checkers"],
                    "findings": findings,
                }
            overall = round(weighted_score / weighted_total) if weighted_total > 0 else 0
            summary[framework] = {
                "overall_pct": overall,
                "controls": ctrl_results,
            }
        return summary


# ---------------------------------------------------------------------------
# 29. Ransomware Susceptibility Index (RSI)
# ---------------------------------------------------------------------------
# South African industry breach cost data (IBM 2025, translated to ZAR)
SA_INDUSTRY_COSTS = {
    "Public Sector":              {"breach_cost_zar": 76_730_000, "cost_per_record": 3273, "multiplier": 1.74},
    "Healthcare":                 {"breach_cost_zar": 73_650_000, "cost_per_record": 3141, "multiplier": 1.67},
    "Financial Services":         {"breach_cost_zar": 70_120_000, "cost_per_record": 2992, "multiplier": 1.59},
    "Finance":                    {"breach_cost_zar": 70_120_000, "cost_per_record": 2992, "multiplier": 1.59},
    "Hospitality":                {"breach_cost_zar": 57_330_000, "cost_per_record": 2445, "multiplier": 1.30},
    "Services":                   {"breach_cost_zar": 56_890_000, "cost_per_record": 2426, "multiplier": 1.29},
    "Industrial / Manufacturing": {"breach_cost_zar": 49_390_000, "cost_per_record": 2107, "multiplier": 1.12},
    "Manufacturing":              {"breach_cost_zar": 49_390_000, "cost_per_record": 2107, "multiplier": 1.12},
    "Energy":                     {"breach_cost_zar": 48_070_000, "cost_per_record": 2051, "multiplier": 1.09},
    "Technology":                 {"breach_cost_zar": 47_630_000, "cost_per_record": 2032, "multiplier": 1.08},
    "Tech":                       {"breach_cost_zar": 47_630_000, "cost_per_record": 2032, "multiplier": 1.08},
    "Pharmaceuticals":            {"breach_cost_zar": 45_860_000, "cost_per_record": 1956, "multiplier": 1.04},
    "Entertainment":              {"breach_cost_zar": 44_100_000, "cost_per_record": 1881, "multiplier": 1.00},
    "Media":                      {"breach_cost_zar": 41_900_000, "cost_per_record": 1787, "multiplier": 0.95},
    "Transportation":             {"breach_cost_zar": 39_690_000, "cost_per_record": 1693, "multiplier": 0.90},
    "Education":                  {"breach_cost_zar": 37_490_000, "cost_per_record": 1599, "multiplier": 0.85},
    "Research":                   {"breach_cost_zar": 37_490_000, "cost_per_record": 1599, "multiplier": 0.85},
    "Communications":             {"breach_cost_zar": 37_040_000, "cost_per_record": 1580, "multiplier": 0.84},
    "Consumer":                   {"breach_cost_zar": 37_040_000, "cost_per_record": 1580, "multiplier": 0.84},
    "Retail":                     {"breach_cost_zar": 35_280_000, "cost_per_record": 1505, "multiplier": 0.80},
    "Agriculture":                {"breach_cost_zar": 28_670_000, "cost_per_record": 1223, "multiplier": 0.65},
    "Government":                 {"breach_cost_zar": 76_730_000, "cost_per_record": 3273, "multiplier": 1.74},
    "Legal":                      {"breach_cost_zar": 56_890_000, "cost_per_record": 2426, "multiplier": 1.29},
    "Other":                      {"breach_cost_zar": 44_100_000, "cost_per_record": 1881, "multiplier": 1.00},
}
# ---------------------------------------------------------------------------

class RansomwareIndex:
    """
    Calculates 0.0-1.0 ransomware susceptibility score from scan results.
    Higher = more susceptible. Uses existing checker outputs + user-provided
    industry/revenue context for multipliers.

    Calibration notes (2026-04-08):
    - Base starts at 0.05 (inherent internet exposure risk)
    - Factors are additive with diminishing returns above 0.50 raw score
    - Industry multipliers are modest (1.0-1.15) to avoid inflating mid-range scores
    - Size multiplier: SMEs neutral (1.0), large enterprises slightly lower (0.95)
    - Target distribution: clean domain ~0.10-0.15, moderate issues ~0.30-0.50,
      serious issues ~0.50-0.75, critical (RDP+CVEs+creds) ~0.75-0.90
    - Score of 0.90+ should only occur with RDP exposed + CISA KEV CVEs + active compromise
    """
    # Industry multipliers: modest — higher-targeted industries get small uplift
    # RSI Industry Multiplier — ransomware-specific targeting frequency.
    # Distinct from general breach TEF (Section 12): ransomware targeting
    # differs from breach targeting (e.g., manufacturing is #1 ransomware
    # target but not #1 breach target).
    # BASELINE: Global data (Sophos 2025 sector reports, Check Point Q3 2025).
    # SA-specific adjustment applied to Public Sector only (known SA attacks).
    # All other values require SA calibration — use "Your Value" in Section 3b.
    INDUSTRY_MULTIPLIER = {
        "manufacturing": 1.30, "industrial": 1.30, "industrial / manufacturing": 1.30,
        "healthcare": 1.25,
        "retail": 1.20,
        "financial services": 1.15, "finance": 1.15,
        "hospitality": 1.15,
        "energy": 1.15,
        "public sector": 1.25, "government": 1.25,  # SA-specific: Transnet, DoJ, NHLS attacks
        "education": 1.10, "research": 0.90,
        "legal": 1.10,
        "technology": 1.05, "tech": 1.05,
        "services": 1.05,
        "communications": 1.00, "media": 1.00, "entertainment": 1.00, "pharmaceuticals": 1.00,
        "transportation": 0.95, "consumer": 0.95,
        "mining": 0.90,
        "wholesale trade": 0.85,
        "agriculture": 0.80,
        "construction": 0.80,
        "other": 1.00,
    }

    @staticmethod
    def _diminishing(raw_score: float) -> float:
        """Apply diminishing returns above 0.50 to prevent score inflation.
        Below 0.50: linear (1:1). Above 0.50: each additional 0.10 raw gives
        progressively less. Approaches 1.0 asymptotically.
        Formula: if raw <= 0.5: return raw. Else: 0.5 + 0.5 * (1 - e^(-2*(raw-0.5)))
        """
        if raw_score <= 0.50:
            return raw_score
        import math
        excess = raw_score - 0.50
        return 0.50 + 0.50 * (1 - math.exp(-2.0 * excess))

    def calculate(self, categories: dict, industry: str = "other",
                  annual_revenue: float = 0) -> dict:
        base = 0.05  # Inherent internet exposure risk
        factors = []

        # --- P1: Critical findings (strongest ransomware signals) ---

        # RDP exposed: +0.25 (strongest single signal — #1 ransomware vector)
        if categories.get("vpn_remote", {}).get("rdp_exposed"):
            base += 0.25
            factors.append({"factor": "RDP (port 3389) exposed to internet", "impact": 0.25, "priority": 1})

        # Exposed database/service ports: +0.10 each, cap 0.20
        exposed = categories.get("high_risk_protocols", {}).get("exposed_services", [])
        db_ports = [s for s in exposed if s.get("port") in (27017, 6379, 9200, 5432, 1433, 5984, 3306)]
        db_impact = min(0.20, len(db_ports) * 0.10)
        if db_impact > 0:
            base += db_impact
            factors.append({"factor": f"{len(db_ports)} exposed database port(s)", "impact": round(db_impact, 2), "priority": 1})

        # Credential Risk Assessment (composite from Dehashed + Hudson Rock +
        # IntelX + HIBP enrichment). Uses the multi-layered credential
        # assessment to determine if credentials are static (old/changed)
        # or dynamic (active/traded). Replaces individual Dehashed/breach
        # count factors. Sophos SA 2025: credentials are #1 root cause (34%).
        cred_risk = categories.get("credential_risk", {})
        cred_level = cred_risk.get("risk_level", "LOW")
        if cred_level == "CRITICAL":
            # Active infostealer or real-time credential exfiltration
            base += 0.20
            factors.append({"factor": "CRITICAL credential risk — active compromise detected (infostealer/dark web)", "impact": 0.20, "priority": 1})
        elif cred_level == "HIGH":
            # Recent breaches with passwords, dark web mentions, or high volume leaks
            base += 0.15
            factors.append({"factor": "HIGH credential risk — recent breaches with password exposure or dark web trading", "impact": 0.15, "priority": 1})
        elif cred_level == "MEDIUM":
            # Historical exposure, email-only leaks, older breaches
            base += 0.08
            factors.append({"factor": "MEDIUM credential risk — historical credential exposure detected", "impact": 0.08, "priority": 2})
        # LOW = no contribution to RSI

        # KEV CVEs: +0.08 each, cap 0.20 (confirmed actively exploited)
        cves = categories.get("shodan_vulns", {}).get("cves", [])
        kev_count = sum(1 for c in cves if c.get("in_kev"))
        kev_impact = min(0.20, kev_count * 0.08)
        if kev_impact > 0:
            base += kev_impact
            factors.append({"factor": f"{kev_count} CISA KEV CVE(s) — actively exploited", "impact": round(kev_impact, 2), "priority": 1})

        # --- P2: High-impact findings ---

        # High EPSS CVEs (>0.5): +0.04 each, cap 0.12
        high_epss = sum(1 for c in cves if c.get("epss_score", 0) > 0.5)
        epss_impact = min(0.12, high_epss * 0.04)
        if epss_impact > 0:
            base += epss_impact
            factors.append({"factor": f"{high_epss} high-EPSS CVE(s) (>50% exploit probability)", "impact": round(epss_impact, 2), "priority": 2})

        # Other critical/high CVEs: +0.02 each, cap 0.08
        other_crit = sum(1 for c in cves if c.get("severity") in ("critical", "high") and not c.get("in_kev"))
        other_impact = min(0.08, other_crit * 0.02)
        if other_impact > 0:
            base += other_impact
            factors.append({"factor": f"{other_crit} unpatched critical/high CVE(s)", "impact": round(other_impact, 2), "priority": 2})

        # NOTE: Blacklisted IPs removed from RSI — reputation signal, not a
        # direct ransomware entry vector. Retained in overall posture score / DBI.

        # Information disclosure: +0.02 per critical exposure, cap 0.08
        info = categories.get("info_disclosure", {})
        crit_exposed = sum(1 for p in info.get("exposed_paths", []) if p.get("risk_level") == "critical")
        if crit_exposed > 0:
            info_impact = min(0.08, crit_exposed * 0.02)
            base += info_impact
            factors.append({"factor": f"{crit_exposed} critical file(s) exposed", "impact": round(info_impact, 2), "priority": 2})

        # --- P3: Contributing factors (email vector + hygiene) ---

        # No DMARC: +0.08 / policy none: +0.05
        # Sophos SA 2025: malicious email = 22% of attacks
        dmarc = categories.get("email_security", {}).get("dmarc", {})
        if not dmarc.get("present"):
            base += 0.08
            factors.append({"factor": "No DMARC record — phishing/BEC vector", "impact": 0.08, "priority": 2})
        elif dmarc.get("policy") == "none":
            base += 0.05
            factors.append({"factor": "DMARC policy is 'none' — not enforced", "impact": 0.05, "priority": 3})

        # No WAF: +0.05
        if not categories.get("waf", {}).get("detected"):
            base += 0.05
            factors.append({"factor": "No WAF detected", "impact": 0.05, "priority": 3})

        # Weak SSL: +0.05
        ssl_grade = categories.get("ssl", {}).get("grade", "F")
        if ssl_grade in ("D", "E", "F"):
            base += 0.05
            factors.append({"factor": f"Weak SSL (grade {ssl_grade})", "impact": 0.05, "priority": 3})

        # --- Favourable signals (RSI reduction) ---
        # Anthropic Project Glasswing partners integrate Claude-assisted
        # vulnerability discovery — compresses exposure window to novel CVEs.
        gw = categories.get("glasswing", {}) or {}
        if gw.get("is_partner"):
            glasswing_delta = -0.05  # Modest credit — observable signal only
            base += glasswing_delta
            factors.append({
                "factor": f"Anthropic Glasswing partner ({gw.get('partner_name','')}) — AI-assisted vuln programme",
                "impact": round(glasswing_delta, 2),
                "priority": 3,
            })
        # Floor at 0 — favourable signals cannot drive RSI below the
        # inherent-exposure baseline.
        base = max(0.0, base)

        # --- Apply diminishing returns + multipliers ---
        # Diminishing returns prevents stacking of many moderate findings
        # from pushing the score unrealistically close to 1.0
        raw_score = base
        adjusted = self._diminishing(raw_score)

        ind_key = industry.lower().strip() if industry else "other"
        ind_mult = self.INDUSTRY_MULTIPLIER.get(ind_key, 1.0)

        # Size multiplier: reflects security maturity by company size.
        # Baseline 1.0 at R200M-R300M (~100 employees, Sophos SA 2025 median).
        # Smaller = more vulnerable (58% cite lack of expertise per Sophos),
        # but uplift is modest because the scanner already captures actual
        # posture — the size multiplier only adds what the scanner can't see.
        # Larger = better internal defences not visible externally.
        # Revenue bands aligned with SME Rating Engine.
        if annual_revenue >= 1_000_000_000:
            size_mult = 0.85    # Enterprise — mature security, DFIR retainers, MDR
        elif annual_revenue >= 500_000_000:
            size_mult = 0.90    # Large corporate — CISO, SOC likely
        elif annual_revenue >= 300_000_000:
            size_mult = 0.96    # Corporate — established security programme
        elif annual_revenue >= 200_000_000:
            size_mult = 1.00    # Baseline — ~100 employees, Sophos SA median
        elif annual_revenue >= 150_000_000:
            size_mult = 1.016   # Upper medium — approaching baseline
        elif annual_revenue >= 100_000_000:
            size_mult = 1.032   # Medium — growing security awareness
        elif annual_revenue >= 75_000_000:
            size_mult = 1.048   # Medium — dedicated IT, limited security
        elif annual_revenue >= 50_000_000:
            size_mult = 1.06    # Small/medium — emerging IT function
        elif annual_revenue >= 25_000_000:
            size_mult = 1.08    # Small — some IT awareness, still constrained
        elif annual_revenue >= 10_000_000:
            size_mult = 1.10    # Small — limited budget, shared IT role
        else:
            size_mult = 1.12    # Micro — no dedicated IT, owner-managed

        rsi = min(1.0, round(adjusted * ind_mult * size_mult, 3))

        label = ("Critical" if rsi >= 0.75 else "High" if rsi >= 0.50
                 else "Medium" if rsi >= 0.25 else "Low")

        # Sort factors by priority then impact
        factors.sort(key=lambda f: (f["priority"], -f["impact"]))

        return {
            "rsi_score": rsi,
            "risk_label": label,
            "base_score": round(base, 3),
            "industry": industry,
            "industry_multiplier": ind_mult,
            "annual_revenue": annual_revenue,
            "size_multiplier": size_mult,
            "contributing_factors": factors,
            "factor_count": len(factors),
        }


# ---------------------------------------------------------------------------
# 30. Financial Impact Calculator (FAIR-Based)
# ---------------------------------------------------------------------------

class FinancialImpactCalculator:
    """
    Estimates probable financial loss using Open FAIR-inspired model.
    Three scenarios: Data Breach + Ransomware + Business Interruption.
    Uses Monte Carlo simulation (10,000 iterations) with PERT distributions
    to produce statistically robust confidence intervals.
    Outputs P5/P25/P50/P75/P95 percentiles for insurance underwriting.
    """
    MC_ITERATIONS = 10_000  # Number of Monte Carlo simulations

    @staticmethod
    def _pert_sample(low, mode, high, size=1):
        """Sample from a PERT (modified beta) distribution.
        PERT is preferred over triangular for risk analysis because it
        concentrates more probability around the most likely value."""
        import numpy as np
        if high <= low:
            return np.full(size, mode)
        # PERT lambda=4 (standard); alpha/beta from PERT formula
        lam = 4.0
        mu = (low + lam * mode + high) / (lam + 2)
        # Prevent division by zero
        if high == low:
            return np.full(size, mode)
        a = ((mu - low) * (2 * mode - low - high)) / ((mode - mu) * (high - low)) if (mode - mu) != 0 else 2.0
        a = max(1.01, a)  # ensure valid shape
        b = a * (high - mu) / (mu - low) if (mu - low) != 0 else 2.0
        b = max(1.01, b)
        samples = np.random.beta(a, b, size=size) * (high - low) + low
        return samples

    @staticmethod
    def _mc_percentiles(samples):
        """Extract P5, P25, P50 (median), P75, P95 percentiles."""
        import numpy as np
        p5, p25, p50, p75, p95 = np.percentile(samples, [5, 25, 50, 75, 95])
        return {
            "p5": round(float(p5)),
            "p25": round(float(p25)),
            "p50": round(float(p50)),
            "p75": round(float(p75)),
            "p95": round(float(p95)),
            "mean": round(float(np.mean(samples))),
            "std_dev": round(float(np.std(samples))),
        }

    # RSI-to-deductible lookup table.  Non-linear: gentle at low risk,
    # accelerating at high risk.  Deductible is a % of recommended cover.
    _DEDUCTIBLE_TABLE = [
        # (RSI threshold, deductible %)
        (0.10, 0.005),   # 0.5%
        (0.20, 0.010),   # 1.0%
        (0.30, 0.015),   # 1.5%
        (0.40, 0.025),   # 2.5%
        (0.50, 0.035),   # 3.5%
        (0.60, 0.050),   # 5.0%
        (0.70, 0.070),   # 7.0%
        (0.80, 0.100),   # 10.0%
        (0.90, 0.140),   # 14.0%
        (1.00, 0.200),   # 20.0%
    ]

    @classmethod
    def _rsi_deductible_pct(cls, rsi: float) -> float:
        """Interpolate deductible % from RSI score (0.0-1.0)."""
        rsi_clamped = max(0.10, min(1.0, rsi))
        tbl = cls._DEDUCTIBLE_TABLE
        for i in range(len(tbl) - 1):
            lo_rsi, lo_pct = tbl[i]
            hi_rsi, hi_pct = tbl[i + 1]
            if rsi_clamped <= hi_rsi:
                t = (rsi_clamped - lo_rsi) / (hi_rsi - lo_rsi)
                return lo_pct + t * (hi_pct - lo_pct)
        return tbl[-1][1]

    @classmethod
    def _rsi_deductible(cls, rsi: float, coverage_limit: float) -> float:
        """Calculate suggested deductible (ZAR) from RSI and coverage limit."""
        pct = cls._rsi_deductible_pct(rsi)
        return round(max(10000, coverage_limit) * pct, -3)

    # Industry cost-per-record (IBM/Ponemon averages)
    COST_PER_RECORD = {
        "healthcare": 239, "finance": 219, "tech": 183,
        "education": 173, "manufacturing": 165, "retail": 157,
        "legal": 190, "government": 155, "other": 165,
    }
    # Regulatory fine estimates (typical ranges)
    REGULATORY_FINE = {
        "healthcare": 1_000_000, "finance": 750_000, "legal": 500_000,
        "government": 250_000, "other": 250_000,
    }
    # Average ransom demand as % of revenue (capped)
    RANSOM_PCT = 0.03  # 3% of annual revenue

    # ------------------------------------------------------------------
    # Regulatory exposure: Each jurisdiction computed independently and
    # summed. POPIA capped at R10M, GDPR at 4% uncapped, PCI at R1M
    # scaled by non-compliance, other jurisdictions at R2M each.
    # Replaces the previous multiplier approach — see GAP-008/009.
    # ------------------------------------------------------------------

    def calculate(self, categories: dict, rsi_result: dict,
                  annual_revenue: float, industry: str = "other",
                  annual_revenue_zar: int = 0,
                  regulatory_flags: dict = None,
                  sub_industry: str = None) -> dict:

        # Use ZAR path when ZAR revenue is provided (SA-specific model)
        if annual_revenue_zar > 0:
            return self._calculate_zar(categories, rsi_result, annual_revenue_zar, industry,
                                       regulatory_flags, sub_industry)

        daily_revenue = annual_revenue / 365 if annual_revenue > 0 else 5_000

        # --- Scenario 1: Data Breach ---
        breach_count = categories.get("breaches", {}).get("breach_count", 0)
        tech_score = categories.get("ssl", {}).get("score", 50)
        if breach_count > 3:
            p_breach = 0.35
        elif breach_count > 0:
            p_breach = 0.20
        else:
            p_breach = 0.08
        p_breach = min(0.5, p_breach + (100 - tech_score) / 500)

        cost_per_record = self.COST_PER_RECORD.get(industry, 165)
        est_records = max(1000, int(annual_revenue / 50_000)) if annual_revenue > 0 else 5000
        reg_fine = self.REGULATORY_FINE.get(industry, self.REGULATORY_FINE["other"])

        breach_most_likely = p_breach * (est_records * cost_per_record + reg_fine)
        breach_min = breach_most_likely * 0.3
        breach_max = breach_most_likely * 3.0

        data_breach = {
            "probability": round(p_breach, 3),
            "estimated_records": est_records,
            "cost_per_record": cost_per_record,
            "regulatory_fine": reg_fine,
            "min": round(breach_min),
            "most_likely": round(breach_most_likely),
            "max": round(breach_max),
        }

        # --- Scenario 2: Ransomware ---
        rsi = rsi_result.get("rsi_score", 0.1)
        downtime_days = 22
        ransom_demand = min(5_000_000, annual_revenue * self.RANSOM_PCT) if annual_revenue > 0 else 50_000
        ir_cost = min(500_000, max(50_000, annual_revenue * 0.005)) if annual_revenue > 0 else 75_000

        ransom_most_likely = rsi * (downtime_days * daily_revenue + ransom_demand + ir_cost)
        ransom_min = ransom_most_likely * 0.4
        ransom_max = ransom_most_likely * 2.5

        ransomware = {
            "probability": round(rsi, 3),
            "downtime_days": downtime_days,
            "daily_revenue_loss": round(daily_revenue),
            "ransom_estimate": round(ransom_demand),
            "ir_cost": round(ir_cost),
            "min": round(ransom_min),
            "most_likely": round(ransom_most_likely),
            "max": round(ransom_max),
        }

        # --- Scenario 3: Business Interruption ---
        # P(interruption) from infrastructure signals
        p_interrupt = 0.05
        if not categories.get("waf", {}).get("detected"):
            p_interrupt += 0.05
        if categories.get("ssl", {}).get("grade", "A") in ("D", "E", "F"):
            p_interrupt += 0.03
        exposed_svc = len(categories.get("high_risk_protocols", {}).get("exposed_services", []))
        p_interrupt += min(0.10, exposed_svc * 0.02)
        if categories.get("dnsbl", {}).get("blacklisted"):
            p_interrupt += 0.05
        p_interrupt = min(0.30, p_interrupt)

        bi_downtime = 5  # Average BI days
        impact_factor = 0.6  # Proportion of revenue lost during interruption

        bi_most_likely = p_interrupt * (bi_downtime * daily_revenue * impact_factor)
        bi_min = bi_most_likely * 0.3
        bi_max = bi_most_likely * 4.0

        business_interruption = {
            "probability": round(p_interrupt, 3),
            "downtime_days": bi_downtime,
            "impact_factor": impact_factor,
            "min": round(bi_min),
            "most_likely": round(bi_most_likely),
            "max": round(bi_max),
        }

        # --- Monte Carlo Simulation (USD) ---
        import numpy as np
        np.random.seed(42)
        N = self.MC_ITERATIONS

        mc_p_br = np.clip(self._pert_sample(p_breach * 0.5, p_breach, min(1.0, p_breach * 2.0), N), 0, 1)
        mc_rec = self._pert_sample(est_records * 0.3, est_records, est_records * 3.0, N)
        mc_cpr = self._pert_sample(cost_per_record * 0.6, cost_per_record, cost_per_record * 1.5, N)
        mc_fine = self._pert_sample(reg_fine * 0.5, reg_fine, reg_fine * 2.0, N)
        mc_breach_s = mc_p_br * (mc_rec * mc_cpr + mc_fine)

        mc_rsi = np.clip(self._pert_sample(rsi * 0.5, rsi, min(1.0, rsi * 2.0), N), 0, 1)
        mc_dt = self._pert_sample(7, downtime_days, 45, N)
        mc_rd = self._pert_sample(ransom_demand * 0.3, ransom_demand, ransom_demand * 3.0, N)
        mc_ir = self._pert_sample(ir_cost * 0.5, ir_cost, ir_cost * 2.5, N)
        mc_ransom_s = mc_rsi * (mc_dt * daily_revenue + mc_rd + mc_ir)

        mc_pi = np.clip(self._pert_sample(p_interrupt * 0.3, p_interrupt, min(0.8, p_interrupt * 3.0), N), 0, 1)
        mc_bd = self._pert_sample(1, bi_downtime, 14, N)
        mc_if = np.clip(self._pert_sample(impact_factor * 0.5, impact_factor, min(1.0, impact_factor * 1.5), N), 0, 1)
        mc_bi_s = mc_pi * (mc_bd * daily_revenue * mc_if)

        mc_total_s = mc_breach_s + mc_ransom_s + mc_bi_s
        mc_stats = self._mc_percentiles(mc_total_s)
        mc_breach_stats = self._mc_percentiles(mc_breach_s)
        mc_ransom_stats = self._mc_percentiles(mc_ransom_s)
        mc_bi_stats = self._mc_percentiles(mc_bi_s)

        # Use MC percentiles
        total_min = mc_stats["p5"]
        total_likely = mc_stats["p50"]
        total_max = mc_stats["p95"]

        # Insurance recommendations from MC distribution
        expected_annual = round(mc_stats["p50"], -3)
        coverage_limit = round(mc_stats["p95"] * 1.2, -3)

        # RSI-driven deductible as % of recommended coverage limit
        deductible_pct = self._rsi_deductible_pct(rsi)
        deductible = self._rsi_deductible(rsi, coverage_limit)

        # Add MC stats to scenario dicts
        data_breach["monte_carlo"] = mc_breach_stats
        ransomware["monte_carlo"] = mc_ransom_stats
        business_interruption["monte_carlo"] = mc_bi_stats

        output = {
            "scenarios": {
                "data_breach": data_breach,
                "ransomware": ransomware,
                "business_interruption": business_interruption,
            },
            "monte_carlo": {
                "iterations": N,
                "method": "PERT distribution (lambda=4)",
                "total": mc_stats,
                "confidence_interval_90": {
                    "lower": mc_stats["p5"],
                    "upper": mc_stats["p95"],
                },
                "confidence_interval_50": {
                    "lower": mc_stats["p25"],
                    "upper": mc_stats["p75"],
                },
            },
            "total": {
                "min": round(total_min),
                "most_likely": round(total_likely),
                "max": round(total_max),
            },
            "insurance_recommendations": {
                "suggested_deductible": max(1000, deductible),
                "deductible_pct": round(deductible_pct * 100, 1),
                "expected_annual_loss": max(1000, expected_annual),
                "recommended_coverage": max(10000, coverage_limit),
            },
            "annual_revenue": annual_revenue,
            "industry": industry,
            "currency": "ZAR",
        }
        output["risk_mitigations"] = self._build_mitigations(categories, output)
        return output

    # ------------------------------------------------------------------
    # Threat Event Frequency (TEF) multipliers per industry
    # FAIR: Loss Event Frequency = TEF × Vulnerability
    # TEF reflects how often an industry is targeted by threat actors,
    # independent of the organisation's security posture (Vulnerability).
    # Range: 0.80-1.45 (deliberately modest to avoid probability inflation).
    # Sources: Verizon DBIR 2025, IBM 2025, Sophos SA 2025, SABRIC 2024.
    # Tuneable via FAIR parameters doc Section 12.
    # ------------------------------------------------------------------
    THREAT_EVENT_FREQUENCY = {
        "Financial Services": 1.45, "Finance": 1.45,
        "Healthcare": 1.40,
        "Public Sector": 1.35, "Government": 1.35,
        "Retail": 1.25,
        "Hospitality": 1.20,
        "Manufacturing": 1.15, "Industrial": 1.15, "Industrial / Manufacturing": 1.15,
        "Technology": 1.10, "Tech": 1.10,
        "Energy": 1.10,
        "Education": 1.10, "Research": 0.90,
        "Services": 1.05, "Legal": 1.05,
        "Communications": 1.05,
        "Media": 1.00, "Entertainment": 1.00, "Pharmaceuticals": 1.00,
        "Transportation": 0.95, "Consumer": 0.95,
        "Mining": 0.90,
        "Wholesale Trade": 0.85,
        "Agriculture": 0.80,
        "Construction": 0.80,
        "Other": 1.00,
    }

    # ------------------------------------------------------------------
    # Incident-type split ratios (tuneable via FAIR parameters doc)
    # Each ratio defines what fraction of the parent probability driver
    # (RSI or p_breach) applies to that incident type.
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # BI Factor per sub-industry (from FAIR Model Industry Lookup Tables)
    # Controls proportional allocation of direct operational downtime cost.
    # Range: 0.05 (construction) to 1.75 (depository institutions/banks).
    # Key: matches the sub-industry name from the lookup table.
    # Fallback: industry-level average if sub-industry not specified.
    # ------------------------------------------------------------------
    # Full sub-industry BI factors from FAIR Model Industry Lookup Tables.
    # 86 sub-industries with exact BI factors — NO AVERAGES.
    # Key = sub-industry name. Industry-level keys provided as fallbacks
    # only when sub-industry is not specified.
    INDUSTRY_BI_FACTOR = {
        # ── Sub-industry exact values (86 entries) ──
        "Agricultural Production Crops": 0.1,
        "Agriculture production livestock and animal specialties": 0.05,
        "Agricultural Services": 0.05,
        "Forestry": 0.05,
        "Agriculture, Forestry, And Fishing- Fishing hunting and trapping": 0.05,
        "Metal Mining": 0.15,
        "Coal Mining": 0.15,
        "Oil And Gas Extraction": 0.15,
        "Mining And Quarrying Of Nonmetallic Minerals, Except Fuels": 0.15,
        "Building Construction General Contractors And Operative Builders": 0.05,
        "Heavy Construction Other Than Building Construction Contractors": 0.05,
        "Construction Special Trade Contractors": 0.05,
        "Food And Kindred Products": 0.5,
        "Tobacco Products": 0.5,
        "Textile Mill Products": 0.5,
        "Apparel And Other Finished Products Made From Fabrics And Similar Materials": 0.5,
        "Lumber And Wood Products, Except Furniture": 0.5,
        "Furniture And Fixtures": 0.5,
        "Paper And Allied Products": 0.5,
        "Printing, Publishing, And Allied Industries": 0.5,
        "Chemicals And Allied Products": 0.5,
        "Petroleum Refining And Related Industries": 0.5,
        "Rubber And Miscellaneous Plastics Products": 0.5,
        "Leather And Leather Products": 0.5,
        "Stone, Clay, Glass, And Concrete Products": 0.5,
        "Primary Metal Industries": 0.5,
        "Fabricated Metal Products, Except Machinery And Transportation Equipment": 0.5,
        "Industrial And Commercial Machinery And Computer Equipment": 0.5,
        "Electronic And Other Electrical Equipment And Components, Except Computer Equipment": 0.5,
        "Transportation Equipment": 0.5,
        "Measuring, Analyzing, And Controlling Instruments; Photographic, Medical And Optical Goods; Watches And Clocks": 0.5,
        "Miscellaneous Manufacturing Industries": 0.5,
        "Railroad Transportation": 1.0,
        "Local And Suburban Transit And Interurban Highway Passenger Transportation": 0.75,
        "Motor Freight Transportation And Warehousing": 1.0,
        "Postal Service": 1.0,
        "Water Transportation": 1.0,
        "Transportation By Air": 1.0,
        "Pipelines, Except Natural Gas": 1.0,
        "Transportation Services": 1.0,
        "Communications": 1.0,
        "Electric, Gas, And Sanitary Services": 1.0,
        "Water and Waste Management": 1.0,
        "Wholesale Trade-durable Goods": 1.0,
        "Wholesale Trade-non-durable Goods": 1.0,
        "eCommerce": 1.5,
        "Building Materials, Hardware, Garden Supply, And Mobile Home Dealers": 1.25,
        "General Merchandise Stores": 1.25,
        "Food Stores": 1.25,
        "Automotive Dealers And Gasoline Service Stations": 1.25,
        "Apparel And Accessory Stores": 1.25,
        "Home Furniture, Furnishings, And Equipment Stores": 1.25,
        "Eating And Drinking Places": 1.25,
        "Miscellaneous Retail": 1.25,
        "Depository Institutions": 1.75,
        "Non-depository Credit Institutions": 1.0,
        "Security And Commodity Brokers, Dealers, Exchanges, And Services": 1.0,
        "Insurance Carriers": 0.75,
        "Insurance Agents, Brokers, And Service": 0.5,
        "Real Estate": 0.25,
        "Holding And Other Investment Offices": 0.75,
        "Hotels, Rooming Houses, Camps, And Other Lodging Places": 1.0,
        "Personal Services": 1.0,
        "Business Services": 1.0,
        "Automotive Repair, Services, And Parking": 0.75,
        "Miscellaneous Repair Services": 1.0,
        "Motion Pictures": 1.0,
        "Amusement And Recreation Services": 0.75,
        "Health Services": 1.0,
        "Legal Services": 1.0,
        "Educational Services": 1.0,
        "Social Services": 1.0,
        "Museums, Art Galleries, And Botanical And Zoological Gardens": 1.0,
        "Membership Organizations": 0.5,
        "Engineering, Accounting, Research, Management, And Related Services": 1.0,
        "Private Households": 0.75,
        "Miscellaneous Services": 1.0,
        "Software and Technology": 1.0,
        "Executive, Legislative, And General Government, Except Finance": 1.0,
        "Justice, Public Order, And Safety": 1.0,
        "Public Finance, Taxation, And Monetary Policy": 1.0,
        "Administration Of Human Resource Programs": 1.0,
        "Administration Of Environmental Quality And Housing Programs": 1.0,
        "Administration Of Economic Programs": 1.0,
        "National Security And International Affairs": 1.0,
        "Nonclassifiable Establishments": 1.0,
        # ── Industry-level fallbacks (used when sub-industry not specified) ──
        "Agriculture": 0.06, "Mining": 0.15, "Construction": 0.05,
        "Manufacturing": 0.50, "Industrial / Manufacturing": 0.50,
        "Transportation": 0.98, "Energy": 1.00,
        "Wholesale Trade": 1.00, "Retail": 1.28, "Hospitality": 1.00,
        "Financial Services": 0.86, "Finance": 0.86,
        "Services": 0.93, "Legal": 1.00, "Healthcare": 1.00,
        "Technology": 1.00, "Tech": 1.00, "Education": 1.00,
        "Research": 1.00, "Entertainment": 0.88, "Media": 1.00,
        "Consumer": 1.00, "Pharmaceuticals": 0.50,
        "Public Sector": 1.00, "Government": 1.00,
        "Other": 1.00,
    }

    # Split ratios calibrated from Sophos SA 2025:
    # - 60% of attacks resulted in encryption
    # - 39% of encrypted attacks also had data stolen
    # - True double extortion = 60% × 39% = ~23% (rounded to 0.25)
    # - Encryption only (no exfil) = 60% - 23% = ~37% (rounded to 0.40)
    # - Wiper/destructive = ~5% (unchanged)
    # Breach-family ratios unchanged pending further SA data.
    INCIDENT_SPLIT_RATIOS = {
        "double_extortion":   0.25,  # Sophos SA: 60% encrypt × 39% also exfil = ~23%
        "ransomware_only":    0.40,  # Sophos SA: encryption without exfiltration
        "wiper_destructive":  0.05,  # Destructive attack (wiper, no ransom demand)
        "silent_breach":      0.50,  # Breaches discovered late / no demand
        "data_extortion":     0.20,  # Breaches with extortion demand (no encryption)
        "opportunistic_breach": 0.30,  # Remaining breaches (opportunistic / automated)
    }

    def _calculate_zar(self, categories: dict, rsi_result: dict,
                       annual_revenue_zar: int, industry: str,
                       regulatory_flags: dict = None,
                       sub_industry: str = None) -> dict:
        """SA-specific ZAR calculation using incident-type decomposition.

        Architecture: Rather than three independent scenarios, the model
        defines six incident types that each assemble a subset of five
        shared cost components (C1-C5). Results are then aggregated into
        four reporting categories for the report and frontend.

        Cost Components:
            C1 = Record/breach costs (IBM cost-per-record x estimated records)
            C2 = Regulatory fine (POPIA base + jurisdictional exposure multiplier)
            C3 = Revenue loss from downtime (daily_revenue x days x impact)
            C4 = Ransom payment (tiered by company size)
            C5 = Incident response (DFIR, negotiation, recovery)

        Reallocation: BI factor (per industry) and regulatory exposure
        multiplier work as a conservation-of-cost mechanism. The IBM
        total breach cost is the anchor; BI factor and regulatory
        exposure shift the allocation across pillars without inflating
        or deflating the total.
        """
        import numpy as np

        # Normalise industry key
        industry_key = industry.title()
        industry_data = SA_INDUSTRY_COSTS.get(industry_key, SA_INDUSTRY_COSTS["Other"])
        rsi_score = rsi_result.get("rsi_score", 0.1)
        daily_revenue = annual_revenue_zar / 365

        # ── Probability drivers (from scanner signals) ──
        # FAIR decomposition: Loss Event Frequency = TEF × Vulnerability
        #   - Vulnerability = f(scanner posture score) — how likely a threat
        #     event succeeds given the organisation's defences
        #   - TEF = f(industry targeting frequency) — how often the industry
        #     is targeted by threat actors, independent of defences
        # NOTE: The industry COST multiplier is decoupled from probability
        # (see GAP-008). TEF is a separate, modest factor based on actual
        # breach frequency data (Verizon DBIR, IBM, Sophos, SABRIC).
        overall_score = categories.get("_overall_score", 500)
        vulnerability = (100 - overall_score / 10) / 100  # 0.0 (perfect) to 1.0 (worst)
        tef = self.THREAT_EVENT_FREQUENCY.get(industry_key, self.THREAT_EVENT_FREQUENCY.get("Other", 1.0))
        p_breach = min(1.0, max(0.0, vulnerability * tef * 0.3))

        waf_detected = categories.get("waf", {}).get("detected", False)
        cdn_detected = categories.get("cloud_cdn", {}).get("cdn_detected", False)
        single_asn = categories.get("external_ips", {}).get("unique_asns", 2) <= 1
        p_interruption = min(0.5, 0.05
                             + (0.05 if not waf_detected else 0)
                             + (0.05 if not cdn_detected else 0)
                             + (0.05 if single_asn else 0))

        # ── Total breach magnitude (IBM anchor, scaled by revenue) ──
        # Uses graduated elasticity: flatter for small companies (less aggressive),
        # steeper for large (scales faster). Median at R200M = IBM SA average.
        IBM_BREACH_TOTAL = 49_220_000  # R49.22M ransom-inclusive (IBM R44.1M + Sophos R5.12M avg ransom)
        MEDIAN_REVENUE = 200_000_000   # R200M — SA mid-market reference point
        C4_PROPORTION = 0.1040         # Ransom share from claims data (ransom-inclusive)

        if annual_revenue_zar >= 1_000_000_000:
            elasticity = 0.35
        elif annual_revenue_zar >= 500_000_000:
            elasticity = 0.38
        elif annual_revenue_zar >= 200_000_000:
            elasticity = 0.40
        elif annual_revenue_zar >= 100_000_000:
            elasticity = 0.44
        elif annual_revenue_zar >= 50_000_000:
            elasticity = 0.48
        elif annual_revenue_zar >= 25_000_000:
            elasticity = 0.52
        elif annual_revenue_zar >= 10_000_000:
            elasticity = 0.58
        else:
            elasticity = 0.60

        revenue_ratio = annual_revenue_zar / MEDIAN_REVENUE
        revenue_scale = revenue_ratio ** elasticity  # Revenue scaling factor (reused)

        # Graduated industry multiplier: for high-risk industries (mult > 1.0),
        # the premium graduates from 1.0 at micro company toward the full
        # multiplier at the median (R200M). Small companies don't hold the
        # same density of sensitive data as large ones in the same industry.
        # Low-risk industries (mult <= 1.0) stay constant — the discount
        # reflects data type, not company size.
        raw_multiplier = industry_data["multiplier"]
        if raw_multiplier > 1.0:
            graduation = min(1.0, annual_revenue_zar / MEDIAN_REVENUE)
            effective_multiplier = 1.0 + (raw_multiplier - 1.0) * graduation
        else:
            effective_multiplier = raw_multiplier

        total_breach_magnitude = IBM_BREACH_TOTAL * effective_multiplier * revenue_scale
        # Revenue-scaled total WITHOUT industry multiplier (for C4 ransom calculation)
        total_breach_base = IBM_BREACH_TOTAL * revenue_scale

        # Cost-per-record retained as reference metric (not used in calculation)
        cost_per_record = industry_data["cost_per_record"]
        estimated_records = max(100, annual_revenue_zar // 50_000)  # reference only

        # ── Cost Component C2: Regulatory fines (independent per jurisdiction) ──
        # Each jurisdiction has its own fine calculation, computed independently
        # and summed. This replaces the previous multiplier approach.
        reg_flags = regulatory_flags or {}

        # POPIA: 2% of turnover, capped at R10M (Section 107)
        c2_popia = min(10_000_000, annual_revenue_zar * 0.02)

        # GDPR: 4% of global turnover, uncapped (if EU data processed)
        c2_gdpr = annual_revenue_zar * 0.04 if reg_flags.get("gdpr") else 0

        # PCI DSS: R1M mid-case, scaled by non-compliance.
        # LIMITATION: External scanner can only assess ~30% of PCI requirements
        # (10 control areas out of ~250+ sub-requirements). Internal controls
        # like access management, logging, network segmentation, key management
        # are invisible. The scanner's PCI score is capped by external visibility
        # to avoid overstating compliance. Full PCI assessment requires internal audit.
        if reg_flags.get("pci"):
            EXTERNAL_PCI_VISIBILITY = 0.30  # we can vouch for ~30% of PCI surface
            raw_pci_score = categories.get("_compliance_summary", {}).get(
                "PCI DSS v4.0", {}).get("overall_pct", 50) / 100  # 0.0-1.0
            adjusted_pci_compliance = raw_pci_score * EXTERNAL_PCI_VISIBILITY
            c2_pci = 1_000_000 * (1 - adjusted_pci_compliance)
        else:
            c2_pci = 0

        # Other jurisdictions: R2M estimated per additional regulated jurisdiction
        extra_jurisdictions = reg_flags.get("other_jurisdictions", 0)
        c2_other = extra_jurisdictions * 2_000_000

        c2_regulatory_fine = c2_popia + c2_gdpr + c2_pci + c2_other

        # ── Cost Component C3: Revenue loss from downtime ──
        # Calculated per-incident-type with specific duration and impact
        # (see incident type definitions below)

        # ── Cost Component C4: Ransom payment (proportional, NOT industry-scaled) ──
        # 10.40% of revenue-scaled total WITHOUT industry multiplier.
        # Ransom demands are driven by company size/ability to pay, not industry.
        # A R200M bank and R200M farm face similar ransom demands.
        # Derived from IBM + Sophos SA 2025: R8M × 64% = R5.12M / R49.22M = 10.40%
        c4_ransom = round(total_breach_base * C4_PROPORTION)

        # ── Cost Component C5: Incident response / D&E cost (tiered) ──
        # Aligned with SME revenue bands. Small company IR is typically
        # R250K-R500K (basic DFIR engagement). Scales with infrastructure
        # complexity, not industry. See Gap Analysis D&E floor discussion.
        if annual_revenue_zar >= 1_000_000_000:
            c5_ir = 5_000_000    # Enterprise — full-scale response
        elif annual_revenue_zar >= 500_000_000:
            c5_ir = 4_000_000    # Large corporate — CISO + external team
        elif annual_revenue_zar >= 200_000_000:
            c5_ir = 2_500_000    # Corporate — full DFIR team
        elif annual_revenue_zar >= 100_000_000:
            c5_ir = 1_500_000    # Upper mid-market
        elif annual_revenue_zar >= 75_000_000:
            c5_ir = 1_000_000    # Medium — multi-system response
        elif annual_revenue_zar >= 50_000_000:
            c5_ir = 750_000      # Mid-market — moderate complexity
        elif annual_revenue_zar >= 25_000_000:
            c5_ir = 500_000      # Small/medium — standard engagement
        elif annual_revenue_zar >= 10_000_000:
            c5_ir = 350_000      # Small — limited scope
        else:
            c5_ir = 250_000      # Micro — basic DFIR engagement

        # ── BI Factor (from industry lookup table) ──
        # Controls proportional allocation of direct operational downtime.
        # Ranges from 0.05 (construction) to 1.75 (banks).
        # Prefer exact sub-industry BI factor; fall back to industry-level.
        if sub_industry and sub_industry in self.INDUSTRY_BI_FACTOR:
            bi_factor = self.INDUSTRY_BI_FACTOR[sub_industry]
        else:
            bi_factor = self.INDUSTRY_BI_FACTOR.get(industry_key, 1.0)

        # ── Cost Component C3: Business interruption (SA average 25 days) ──
        # C3 = downtime × daily_revenue × impact_factor × BI_factor
        # impact_factor (0.50) = average revenue impact across recovery period
        #   (not binary — reflects systematic recovery from ~90% loss on day 1
        #   to ~10% loss by end of recovery)
        # BI_factor = industry-specific IT dependency (from Section 1 lookup)
        SA_AVG_DOWNTIME = 25  # SA average recovery days (Sophos SA 2025 + global data)
        IMPACT_FACTOR = 0.50  # Average revenue loss across recovery period
        c3_bi = SA_AVG_DOWNTIME * daily_revenue * IMPACT_FACTOR * bi_factor

        # ── Cost Component C1: Post-breach liability (RESIDUAL) ──
        # C1 = total_breach_magnitude - C2 - C3 - C4 - C5
        # Captures: third-party liability, data restoration, multimedia claims,
        # notification costs, computer crime — everything not covered by C2-C5.
        # Anchored to IBM data via total_breach_magnitude.
        c1_liability = max(0, total_breach_magnitude - c2_regulatory_fine - c3_bi - c4_ransom - c5_ir)

        # ── Split ratios ──
        R = self.INCIDENT_SPLIT_RATIOS

        # ── Incident Type Definitions ──
        # Each incident type assembles a subset of C1-C5 with its own
        # probability driver. C3 uses SA_AVG_DOWNTIME × IMPACT_FACTOR × BI_factor
        # for all incident types (BI impact is industry-driven, not incident-driven).
        # Per-incident downtime variation handled by MC simulation PERT ranges.

        incidents = {}

        # 1. Double extortion ransomware: exfiltration + encryption + demand
        p_dbl = rsi_score * R["double_extortion"]
        cost_dbl = c1_liability + c2_regulatory_fine + c3_bi + c4_ransom + c5_ir
        incidents["double_extortion"] = {
            "label": "Double Extortion Ransomware",
            "probability": round(p_dbl, 4),
            "expected_loss": round(p_dbl * cost_dbl),
            "components": {"C1": round(p_dbl * c1_liability), "C2": round(p_dbl * c2_regulatory_fine),
                           "C3": round(p_dbl * c3_bi), "C4": round(p_dbl * c4_ransom), "C5": round(p_dbl * c5_ir)},
            "downtime_days": SA_AVG_DOWNTIME,
            "has_exfiltration": True, "has_ransom": True, "has_downtime": True,
        }

        # 2. Ransomware (no exfiltration): encryption + demand, no data stolen
        #    No C1 (no data exfiltrated, no third-party liability)
        p_rw = rsi_score * R["ransomware_only"]
        cost_rw = c3_bi + c4_ransom + c5_ir
        incidents["ransomware_only"] = {
            "label": "Ransomware (No Exfiltration)",
            "probability": round(p_rw, 4),
            "expected_loss": round(p_rw * cost_rw),
            "components": {"C3": round(p_rw * c3_bi), "C4": round(p_rw * c4_ransom), "C5": round(p_rw * c5_ir)},
            "downtime_days": SA_AVG_DOWNTIME,
            "has_exfiltration": False, "has_ransom": True, "has_downtime": True,
        }

        # 3. Destructive attack (wiper): no ransom, severe downtime, IR only
        p_wiper = rsi_score * R["wiper_destructive"]
        cost_wiper = c3_bi + c5_ir
        incidents["wiper_destructive"] = {
            "label": "Destructive Attack (Wiper)",
            "probability": round(p_wiper, 4),
            "expected_loss": round(p_wiper * cost_wiper),
            "components": {"C3": round(p_wiper * c3_bi), "C5": round(p_wiper * c5_ir)},
            "downtime_days": SA_AVG_DOWNTIME,
            "has_exfiltration": False, "has_ransom": False, "has_downtime": True,
        }

        # 4. Silent data breach: exfiltration discovered late, no encryption
        #    Full C1+C2, minimal C3 (2 days investigation), reduced C5
        p_silent = p_breach * R["silent_breach"]
        c3_silent = 2 * daily_revenue * IMPACT_FACTOR * bi_factor  # minimal downtime
        c5_silent = c5_ir * 0.60  # lower IR (no encryption recovery)
        cost_silent = c1_liability + c2_regulatory_fine + c3_silent + c5_silent
        incidents["silent_breach"] = {
            "label": "Silent Data Breach",
            "probability": round(p_silent, 4),
            "expected_loss": round(p_silent * cost_silent),
            "components": {"C1": round(p_silent * c1_liability), "C2": round(p_silent * c2_regulatory_fine),
                           "C3": round(p_silent * c3_silent), "C5": round(p_silent * c5_silent)},
            "downtime_days": 2,
            "has_exfiltration": True, "has_ransom": False, "has_downtime": True,
        }

        # 5. Data extortion (no encryption): exfiltration + demand, no lockout
        #    Minimal downtime (3 days), reduced ransom (no operational leverage)
        p_extort = p_breach * R["data_extortion"]
        c3_extort = 3 * daily_revenue * IMPACT_FACTOR * bi_factor
        c4_extort = c4_ransom * 0.40  # lower demand — no operational leverage
        cost_extort = c1_liability + c2_regulatory_fine + c3_extort + c4_extort + c5_ir
        incidents["data_extortion"] = {
            "label": "Data Extortion (No Encryption)",
            "probability": round(p_extort, 4),
            "expected_loss": round(p_extort * cost_extort),
            "components": {"C1": round(p_extort * c1_liability), "C2": round(p_extort * c2_regulatory_fine),
                           "C3": round(p_extort * c3_extort), "C4": round(p_extort * c4_extort), "C5": round(p_extort * c5_ir)},
            "downtime_days": 3,
            "has_exfiltration": True, "has_ransom": True, "has_downtime": True,
        }

        # 6. Opportunistic breach: automated/bot-driven, no targeted demand
        #    Minimal downtime (1 day), reduced C1 (smaller data set), reduced C5
        p_opp = p_breach * R["opportunistic_breach"]
        c3_opp = 1 * daily_revenue * IMPACT_FACTOR * bi_factor
        c1_opp = c1_liability * 0.50  # smaller data set typically exposed
        c5_opp = c5_ir * 0.40  # simpler response
        cost_opp = c1_opp + c2_regulatory_fine + c3_opp + c5_opp
        incidents["opportunistic_breach"] = {
            "label": "Opportunistic Breach",
            "probability": round(p_opp, 4),
            "expected_loss": round(p_opp * cost_opp),
            "components": {"C1": round(p_opp * c1_opp), "C2": round(p_opp * c2_regulatory_fine),
                           "C3": round(p_opp * c3_opp), "C5": round(p_opp * c5_opp)},
            "downtime_days": 1,
            "has_exfiltration": True, "has_ransom": False, "has_downtime": True,
        }

        # 7. DDoS / infrastructure failure: pure availability event
        #    Uses p_interruption, 5-day average, BI factor applies
        c3_ddos = 5 * daily_revenue * IMPACT_FACTOR * bi_factor
        cost_ddos = c3_ddos
        incidents["ddos_infra"] = {
            "label": "DDoS / Infrastructure Failure",
            "probability": round(p_interruption, 4),
            "expected_loss": round(p_interruption * cost_ddos),
            "components": {"C3": round(p_interruption * c3_ddos)},
            "downtime_days": 5,
            "has_exfiltration": False, "has_ransom": False, "has_downtime": True,
        }

        # ── Aggregate into four reporting categories ──
        # Data Breach Exposure        = C1 + C2 across incident types with exfiltration
        # Detection & Escalation      = C5 across all incident types (DFIR, forensics, triage)
        # Ransom Demand               = C4 across incident types with ransom demands
        # Business Interruption       = C3 across ALL incident types
        agg_breach = 0       # C1 + C2 total
        agg_detection = 0    # C5 total (detection & escalation / IR)
        agg_ransom = 0       # C4 total (ransom payment only)
        agg_bi = 0           # C3 total
        total_expected = 0

        for inc in incidents.values():
            comps = inc["components"]
            agg_breach += comps.get("C1", 0) + comps.get("C2", 0)
            agg_detection += comps.get("C5", 0)
            agg_ransom += comps.get("C4", 0)
            agg_bi += comps.get("C3", 0)
            total_expected += inc["expected_loss"]

        # Backward-compatible combined ransomware = C4 + C5
        agg_ransomware = agg_ransom + agg_detection

        most_likely = round(total_expected)

        # ── Monte Carlo Simulation (ZAR) ──
        # Hybrid approach: C2/C3/C5 sampled from their own PERT ranges,
        # C4 proportional to sampled total, C1 as residual.
        # Recovery time uses empirically-sourced SA confidence intervals:
        # P5=3 days, mode=25 days, P95=120 days (Sophos SA 2025 + global data).
        np.random.seed(42)
        N = self.MC_ITERATIONS

        # Probability driver samples
        mc_rsi = np.clip(self._pert_sample(rsi_score * 0.5, rsi_score, min(1.0, rsi_score * 2.0), N), 0, 1)
        mc_p_breach = np.clip(self._pert_sample(p_breach * 0.5, p_breach, min(1.0, p_breach * 2.0), N), 0, 1)
        mc_p_int = np.clip(self._pert_sample(p_interruption * 0.3, p_interruption, min(0.8, p_interruption * 3.0), N), 0, 1)

        # Total breach magnitude samples (IBM anchor with elasticity)
        mc_total_breach = self._pert_sample(
            total_breach_magnitude * 0.5, total_breach_magnitude, total_breach_magnitude * 2.5, N)
        # Base total (without industry multiplier) for C4 ransom
        mc_total_base = self._pert_sample(
            total_breach_base * 0.5, total_breach_base, total_breach_base * 2.5, N)

        # Component samples
        mc_c2 = self._pert_sample(c2_regulatory_fine * 0.5, c2_regulatory_fine, c2_regulatory_fine * 2.0, N)
        mc_c4 = mc_total_base * C4_PROPORTION  # Ransom NOT industry-scaled
        mc_c5 = self._pert_sample(c5_ir * 0.5, c5_ir, c5_ir * 2.5, N)

        # C3: downtime sampled with SA empirical PERT(3, 25, 120) days
        mc_dt = self._pert_sample(3, SA_AVG_DOWNTIME, 120, N)
        mc_c3_full = mc_dt * daily_revenue * IMPACT_FACTOR * bi_factor

        # C1: residual (clamped to >= 0)
        mc_c1 = np.maximum(0, mc_total_breach - mc_c2 - mc_c3_full - mc_c4 - mc_c5)

        # Per-iteration totals for each reporting category (4 categories)
        mc_breach_total = np.zeros(N)
        mc_detection_total = np.zeros(N)
        mc_ransom_demand_total = np.zeros(N)
        mc_bi_total = np.zeros(N)

        # 1. Double extortion ransomware (C1+C2+C3+C4+C5)
        mc_p = mc_rsi * R["double_extortion"]
        mc_breach_total += mc_p * (mc_c1 + mc_c2)
        mc_ransom_demand_total += mc_p * mc_c4
        mc_detection_total += mc_p * mc_c5
        mc_bi_total += mc_p * mc_c3_full

        # 2. Ransomware (no exfiltration) (C3+C4+C5)
        mc_p = mc_rsi * R["ransomware_only"]
        mc_ransom_demand_total += mc_p * mc_c4
        mc_detection_total += mc_p * mc_c5
        mc_bi_total += mc_p * mc_c3_full

        # 3. Wiper / destructive (C3+C5)
        mc_p = mc_rsi * R["wiper_destructive"]
        mc_detection_total += mc_p * mc_c5
        mc_bi_total += mc_p * mc_c3_full

        # 4. Silent data breach (C1+C2+C3_minimal+C5_partial)
        mc_p = mc_p_breach * R["silent_breach"]
        mc_c3_silent = self._pert_sample(1, 2, 5, N) * daily_revenue * IMPACT_FACTOR * bi_factor
        mc_breach_total += mc_p * (mc_c1 + mc_c2)
        mc_detection_total += mc_p * mc_c5 * 0.60
        mc_bi_total += mc_p * mc_c3_silent

        # 5. Data extortion (C1+C2+C3_minimal+C4_reduced+C5)
        mc_p = mc_p_breach * R["data_extortion"]
        mc_c3_extort = self._pert_sample(1, 3, 7, N) * daily_revenue * IMPACT_FACTOR * bi_factor
        mc_breach_total += mc_p * (mc_c1 + mc_c2)
        mc_ransom_demand_total += mc_p * mc_c4 * 0.40
        mc_detection_total += mc_p * mc_c5
        mc_bi_total += mc_p * mc_c3_extort

        # 6. Opportunistic breach (C1_partial+C2+C3_minimal+C5_partial)
        mc_p = mc_p_breach * R["opportunistic_breach"]
        mc_c3_opp = self._pert_sample(0.5, 1, 3, N) * daily_revenue * IMPACT_FACTOR * bi_factor
        mc_breach_total += mc_p * (mc_c1 * 0.50 + mc_c2)
        mc_detection_total += mc_p * mc_c5 * 0.40
        mc_bi_total += mc_p * mc_c3_opp

        # 7. DDoS / infra failure (C3 only, 5-day avg)
        mc_dt_ddos = self._pert_sample(1, 5, 14, N)
        mc_c3_ddos = mc_dt_ddos * daily_revenue * IMPACT_FACTOR * bi_factor
        mc_bi_total += mc_p_int * mc_c3_ddos

        # Total and per-category stats
        mc_total = mc_breach_total + mc_detection_total + mc_ransom_demand_total + mc_bi_total
        mc_stats = self._mc_percentiles(mc_total)
        mc_breach_stats = self._mc_percentiles(mc_breach_total)
        mc_detection_stats = self._mc_percentiles(mc_detection_total)
        mc_ransom_demand_stats = self._mc_percentiles(mc_ransom_demand_total)
        mc_bi_stats = self._mc_percentiles(mc_bi_total)
        # Backward-compatible combined ransomware MC = C4 + C5
        mc_ransom_stats = self._mc_percentiles(mc_ransom_demand_total + mc_detection_total)

        minimum = mc_stats["p5"]
        maximum = mc_stats["p95"]
        # Insurance cover recommendations aligned to product cover bands:
        # SME bands: R1M, R2.5M, R5M, R7.5M, R10M, R15M
        # Above R15M: R5M increments (R20M, R25M, R30M, ...)
        # Recommended = P75, snapped to nearest cover band
        # Minimum = P50, snapped to nearest cover band
        SME_BANDS = [1_000_000, 2_500_000, 5_000_000, 7_500_000, 10_000_000, 15_000_000]

        def snap_to_cover_band(value):
            """Snap a value up to the nearest available cover limit."""
            for band in SME_BANDS:
                if value <= band:
                    return band
            # Above R15M: round up to nearest R5M
            import math
            return int(math.ceil(value / 5_000_000) * 5_000_000)

        recommended_cover = snap_to_cover_band(most_likely)
        minimum_cover = snap_to_cover_band(minimum)  # P5 snapped up

        if rsi_score >= 0.7:
            premium_tier = "Very High"
        elif rsi_score >= 0.5:
            premium_tier = "High"
        elif rsi_score >= 0.25:
            premium_tier = "Medium"
        else:
            premium_tier = "Low"

        loss_pct = most_likely / annual_revenue_zar if annual_revenue_zar > 0 else 0
        # Thresholds recalibrated for hybrid engine (produces higher loss_pct
        # than original model due to IBM-anchored breach magnitude).
        if loss_pct >= 0.30:
            fin_score = 10
        elif loss_pct >= 0.15:
            fin_score = 30
        elif loss_pct >= 0.08:
            fin_score = 50
        elif loss_pct >= 0.04:
            fin_score = 70
        else:
            fin_score = 90

        output = {
            "currency": "ZAR",
            "industry": industry,
            "annual_revenue_zar": annual_revenue_zar,
            "score": fin_score,
            "estimated_annual_loss": {
                "minimum": minimum,
                "most_likely": most_likely,
                "maximum": maximum,
            },
            # ── Backward-compatible 3-scenario views (for PDF/frontend templates) ──
            "scenarios": {
                "data_breach": {
                    "probability": round(p_breach, 3),
                    "estimated_loss": round(agg_breach),
                    "cost_per_record": cost_per_record,
                    "estimated_records": estimated_records,
                    "regulatory_fine": round(c2_regulatory_fine),
                    "monte_carlo": mc_breach_stats,
                    "note": "Aggregated C1+C2 costs across all incident types involving data exfiltration",
                },
                "ransomware": {
                    "rsi_score": rsi_score,
                    "estimated_loss": round(agg_ransomware),
                    "ransom_estimate": c4_ransom,
                    "ir_cost": c5_ir,
                    "monte_carlo": mc_ransom_stats,
                    "note": "Combined C4+C5 for backward compatibility; see scenarios_4cat for split",
                },
                "business_interruption": {
                    "probability": round(p_interruption, 3),
                    "estimated_loss": round(agg_bi),
                    "monte_carlo": mc_bi_stats,
                    "note": "Aggregated C3 (revenue loss from downtime) across ALL incident types",
                },
            },
            # ── 4-category breakdown (IBM-aligned) ──
            "scenarios_4cat": {
                "data_breach": {
                    "label": "Data Breach Exposure",
                    "components": "C1 + C2",
                    "estimated_loss": round(agg_breach),
                    "monte_carlo": mc_breach_stats,
                    "ibm_equivalent": "Post-breach response + Notification",
                    "note": "Record costs + regulatory fines across incident types with data exfiltration",
                },
                "detection_escalation": {
                    "label": "Detection & Escalation",
                    "components": "C5",
                    "estimated_loss": round(agg_detection),
                    "monte_carlo": mc_detection_stats,
                    "ibm_equivalent": "Detection & escalation (~40% of IBM breach cost)",
                    "note": "DFIR, forensics, triage, negotiation across all incident types",
                },
                "ransom_demand": {
                    "label": "Ransom Demand",
                    "components": "C4",
                    "estimated_loss": round(agg_ransom),
                    "monte_carlo": mc_ransom_demand_stats,
                    "ibm_equivalent": "Not included in IBM breach costs (separate)",
                    "note": "Extortion payment across incident types with ransom demands",
                },
                "business_interruption": {
                    "label": "Business Interruption",
                    "components": "C3",
                    "estimated_loss": round(agg_bi),
                    "monte_carlo": mc_bi_stats,
                    "ibm_equivalent": "Lost business (~30% of IBM breach cost)",
                    "note": "Revenue loss from downtime across ALL incident types",
                },
            },
            # ── Incident-type detail (new — full decomposition) ──
            "incident_types": incidents,
            "cost_components": {
                "C1_liability": round(c1_liability),
                "C2_regulatory_fine": round(c2_regulatory_fine),
                "C4_ransom_payment": c4_ransom,
                "C5_incident_response": c5_ir,
            },
            "split_ratios": dict(R),
            "probability_drivers": {
                "vulnerability": round(vulnerability, 4),
                "tef": tef,
                "p_breach": round(p_breach, 4),
                "formula": "p_breach = vulnerability × TEF × 0.3",
            },
            "regulatory_exposure": {
                "flags": reg_flags,
                "c2_popia": round(c2_popia),
                "c2_gdpr": round(c2_gdpr),
                "c2_pci": round(c2_pci),
                "c2_other": round(c2_other),
                "c2_total": round(c2_regulatory_fine),
                "note": "C2 = POPIA (2% capped R10M) + GDPR (4% uncapped) + PCI (R1M × non-compliance) + other jurisdictions (R2M each)",
            },
            "monte_carlo": {
                "iterations": N,
                "method": "PERT distribution (lambda=4), incident-type decomposition",
                "total": mc_stats,
                "confidence_interval_90": {
                    "lower": mc_stats["p5"],
                    "upper": mc_stats["p95"],
                },
                "confidence_interval_50": {
                    "lower": mc_stats["p25"],
                    "upper": mc_stats["p75"],
                },
            },
            "insurance_recommendation": {
                "minimum_cover_zar": minimum_cover,
                "recommended_cover_zar": recommended_cover,
                "premium_risk_tier": premium_tier,
            },
            # Keep total key for template compatibility
            "total": {
                "min": minimum,
                "most_likely": most_likely,
                "max": maximum,
            },
            "insurance_recommendations": {
                "suggested_deductible": max(1000, self._rsi_deductible(rsi_score, recommended_cover)),
                "deductible_pct": round(self._rsi_deductible_pct(rsi_score) * 100, 1),
                "expected_annual_loss": most_likely,
                "recommended_coverage": recommended_cover,
            },
        }
        # Append risk mitigation recommendations
        output["risk_mitigations"] = self._build_mitigations(categories, output)
        return output

    # Mitigation reductions recalibrated to match hybrid engine:
    # - RSI reductions aligned with new RSI contributing factor weights (Section 3a)
    # - p_breach reductions = reductions in vulnerability component of
    #   p_breach = vulnerability × TEF × 0.3 (expressed as vulnerability reduction)
    # - BI reductions = reductions in p_interruption
    # - "scenario" field indicates which incident-type family is affected
    MITIGATIONS = [
        # --- Critical: RSI reductions match new RSI factor weights ---
        {"pattern": r"RDP.*exposed",                          "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.25, "label": "Block RDP from public internet and enforce VPN/Zero Trust access"},
        {"pattern": r"SSL certificate has EXPIRED",           "severity": "Critical", "scenario": "data_breach",            "probability_reduction": 0.10, "label": "Renew SSL certificate immediately"},
        {"pattern": r"listed in CISA KEV",                    "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.08, "label": "Patch CISA Known Exploited Vulnerabilities within 48 hours"},
        {"pattern": r"critical CVE",                          "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.08, "label": "Patch critical CVEs on public-facing servers"},
        {"pattern": r"CRITICAL:.*Sensitive file exposed",     "severity": "Critical", "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Restrict access to exposed sensitive files"},
        # --- High: aligned with rebalanced weights ---
        {"pattern": r"high.severity CVE|high CVE",            "severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.04, "label": "Patch high-severity CVEs within 30 days"},
        {"pattern": r"No WAF detected",                       "severity": "High",     "scenario": "both",                   "rsi_reduction": 0.05, "bi_reduction": 0.05, "label": "Deploy a Web Application Firewall (WAF)"},
        {"pattern": r"No SPF record|No DMARC record",         "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Implement email authentication (SPF/DMARC/DKIM)"},
        {"pattern": r"password.*leaked|Plaintext.*password",   "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Force password resets for all leaked credentials"},
        {"pattern": r"credential record.*found in Dehashed",  "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.06, "label": "Audit and rotate credentials exposed in data leaks"},
        {"pattern": r"admin.*exposed|login.*exposed",          "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.04, "label": "Restrict access to admin and login panels"},
        {"pattern": r"Telnet|FTP.*exposed|high.risk.*protocol","severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.10, "label": "Disable insecure protocols (Telnet, FTP, etc.)"},
        {"pattern": r"SSL.*grade.*(C|D|F|T)",                  "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.05, "label": "Upgrade SSL/TLS configuration to grade A"},
        {"pattern": r"HTTPS not enforced",                     "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.04, "label": "Enforce HTTPS across all endpoints"},
        {"pattern": r"EOL software|end.of.life",               "severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.04, "label": "Update end-of-life software components"},
        {"pattern": r"Self.hosted payment",                    "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.06, "label": "Migrate to PCI-compliant payment provider"},
        {"pattern": r"database port|MySQL|PostgreSQL|MongoDB|Redis|Elasticsearch", "severity": "High", "scenario": "data_breach", "probability_reduction": 0.06, "label": "Restrict database access to private networks/VPN"},
        {"pattern": r"breach_count|known breach",              "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.04, "label": "Enforce password resets and MFA across all accounts"},
        # --- Medium: minor improvements ---
        {"pattern": r"DNSSEC.*not enabled",                    "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Enable DNSSEC for DNS integrity"},
        {"pattern": r"Missing security header|HSTS.*missing|X-Frame|Content-Security-Policy", "severity": "Medium", "scenario": "data_breach", "probability_reduction": 0.02, "label": "Implement security headers (HSTS, CSP, X-Frame-Options)"},
        {"pattern": r"blacklist|blocklist|listed on",          "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Resolve DNS blocklist entries"},
        {"pattern": r"lookalike domain|typosquat|fraudulent",  "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Monitor and take down fraudulent lookalike domains"},
        {"pattern": r"single ASN|unique_asns.*1",              "severity": "Medium",   "scenario": "business_interruption",  "bi_reduction": 0.05, "label": "Add hosting redundancy across multiple providers"},
        {"pattern": r"No VPN.*detected",                       "severity": "Medium",   "scenario": "ransomware",             "rsi_reduction": 0.03, "label": "Implement VPN or Zero Trust Network Access for remote workers"},
        {"pattern": r"No DKIM",                                "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Enable DKIM signing on your mail server"},
        {"pattern": r"No CDN detected",                        "severity": "Medium",   "scenario": "business_interruption",  "bi_reduction": 0.03, "label": "Deploy a CDN for DDoS resilience and availability"},
    ]

    def _build_mitigations(self, categories: dict, fin_output: dict) -> dict:
        """Analyse scan findings and estimate per-finding cost reduction.

        Incident-type aware: mitigations reduce probabilities of specific
        incident types rather than abstract scenarios. Each mitigation
        specifies which probability driver it affects (rsi_reduction for
        ransomware-family incidents, probability_reduction for breach-family
        incidents, bi_reduction for DDoS/infra incidents).

        Savings are calculated by summing the cost reduction across all
        incident types that share the affected probability driver.
        """
        scenarios = fin_output.get("scenarios", {})
        db_scenario = scenarios.get("data_breach", {})
        rw_scenario = scenarios.get("ransomware", {})
        bi_scenario = scenarios.get("business_interruption", {})
        incidents = fin_output.get("incident_types", {})

        # ZAR path uses estimated_loss, USD path uses most_likely
        db_loss = db_scenario.get("estimated_loss", db_scenario.get("most_likely", 0))
        rw_loss = rw_scenario.get("estimated_loss", rw_scenario.get("most_likely", 0))
        bi_loss = bi_scenario.get("estimated_loss", bi_scenario.get("most_likely", 0))
        rsi_score = rw_scenario.get("rsi_score", rw_scenario.get("rsi", 0))
        p_breach = db_scenario.get("probability", 0)

        current_loss = db_loss + rw_loss + bi_loss
        if current_loss <= 0:
            return {"findings": [], "current_annual_loss": 0, "mitigated_annual_loss": 0,
                    "total_potential_savings": 0, "summary": {
                        "critical": {"count": 0, "total_savings_zar": 0},
                        "high": {"count": 0, "total_savings_zar": 0},
                        "medium": {"count": 0, "total_savings_zar": 0}}}

        # Sum expected losses by probability driver family for proportional savings
        rsi_family_loss = sum(inc["expected_loss"] for k, inc in incidents.items()
                              if k in ("double_extortion", "ransomware_only", "wiper_destructive"))
        breach_family_loss = sum(inc["expected_loss"] for k, inc in incidents.items()
                                 if k in ("silent_breach", "data_extortion", "opportunistic_breach"))
        ddos_loss = incidents.get("ddos_infra", {}).get("expected_loss", 0)

        # Collect all issues from every category for pattern matching
        all_issues = []
        for cat_name, cat_data in categories.items():
            if isinstance(cat_data, dict):
                for issue in cat_data.get("issues", []):
                    all_issues.append({"category": cat_name, "text": str(issue)})

        matched_labels = set()
        findings = []

        for mit in self.MITIGATIONS:
            pat = re.compile(mit["pattern"], re.IGNORECASE)
            matched_issue = None
            for issue in all_issues:
                if pat.search(issue["text"]):
                    matched_issue = issue["text"]
                    break
            if not matched_issue:
                continue
            if mit["label"] in matched_labels:
                continue
            matched_labels.add(mit["label"])

            savings = 0

            # RSI reduction: affects ransomware-family incident types
            if "rsi_reduction" in mit:
                if rsi_score > 0:
                    savings += rsi_family_loss * (mit["rsi_reduction"] / rsi_score)

            # Probability reduction: affects breach-family incident types
            if "probability_reduction" in mit:
                if p_breach > 0:
                    savings += breach_family_loss * (mit["probability_reduction"] / p_breach)

            # BI reduction: affects DDoS/infra incident type
            if "bi_reduction" in mit:
                p_int = bi_scenario.get("probability", 0.05)
                if p_int > 0:
                    savings += ddos_loss * (mit["bi_reduction"] / p_int)

            savings = round(min(savings, current_loss))

            findings.append({
                "severity": mit["severity"],
                "finding": matched_issue,
                "recommendation": mit["label"],
                "estimated_annual_savings_zar": savings,
                "scenario_impact": mit["scenario"],
            })

        # Sort: Critical first, then High, then Medium; within tier by savings desc
        severity_order = {"Critical": 0, "High": 1, "Medium": 2}
        findings.sort(key=lambda f: (severity_order.get(f["severity"], 3), -f["estimated_annual_savings_zar"]))

        # Cap total savings at 85% of current loss (can't eliminate all risk)
        total_savings = sum(f["estimated_annual_savings_zar"] for f in findings)
        if total_savings > current_loss * 0.85:
            scale = (current_loss * 0.85) / total_savings if total_savings > 0 else 0
            for f in findings:
                f["estimated_annual_savings_zar"] = round(f["estimated_annual_savings_zar"] * scale)
            total_savings = round(current_loss * 0.85)

        summary = {"critical": {"count": 0, "total_savings_zar": 0},
                    "high": {"count": 0, "total_savings_zar": 0},
                    "medium": {"count": 0, "total_savings_zar": 0}}
        for f in findings:
            key = f["severity"].lower()
            if key in summary:
                summary[key]["count"] += 1
                summary[key]["total_savings_zar"] += f["estimated_annual_savings_zar"]

        return {
            "current_annual_loss": current_loss,
            "mitigated_annual_loss": current_loss - total_savings,
            "total_potential_savings": total_savings,
            "findings": findings,
            "summary": summary,
        }


# ---------------------------------------------------------------------------
# 31. Data Breach Index (DBI)
# ---------------------------------------------------------------------------

class DataBreachIndex:
    """
    Scores historical breach exposure (0-100, higher = better).
    Uses HIBP breach data + Dehashed credential leak data.
    """

    def calculate(self, categories: dict) -> dict:
        score = 0
        components = {}

        breaches = categories.get("breaches", {})
        dehashed = categories.get("dehashed", {})
        breach_count = breaches.get("breach_count", 0)

        # 1. Breach count (0-30 points)
        if breach_count == 0:
            bc_pts = 30
        elif breach_count <= 3:
            bc_pts = 15
        else:
            bc_pts = 0
        score += bc_pts
        components["breach_count"] = {"value": breach_count, "points": bc_pts, "max": 30}

        # 2. Most recent breach recency (0-20 points)
        recency_pts = 20
        most_recent = breaches.get("most_recent_breach")
        if most_recent:
            try:
                breach_date = datetime.fromisoformat(most_recent.replace("Z", "+00:00")) \
                    if "T" in str(most_recent) else datetime.strptime(str(most_recent)[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                days_ago = (datetime.now(timezone.utc) - breach_date).days
                if days_ago < 365:
                    recency_pts = 0
                elif days_ago < 1095:  # 3 years
                    recency_pts = 10
                else:
                    recency_pts = 20
            except Exception:
                recency_pts = 10
        score += recency_pts
        components["recency"] = {"value": str(most_recent or "No breaches"), "points": recency_pts, "max": 20}

        # 3. Data severity (0-15 points)
        data_classes = breaches.get("data_classes", [])
        severe_classes = {"Passwords", "Credit cards", "Bank account numbers",
                          "Social security numbers", "Financial data", "Credit card CVV"}
        has_severe = bool(set(data_classes) & severe_classes)
        sev_pts = 0 if has_severe else (15 if not data_classes else 10)
        score += sev_pts
        components["data_severity"] = {
            "value": "Passwords/financials exposed" if has_severe else ("Emails only" if data_classes else "No data exposed"),
            "points": sev_pts, "max": 15,
        }

        # 4. Credential leak volume from Dehashed (0-20 points)
        total_leaks = dehashed.get("total_entries", 0) if dehashed.get("status") not in ("no_api_key", "auth_failed") else -1
        if total_leaks < 0:
            leak_pts = 10  # Unknown — middle score
        elif total_leaks == 0:
            leak_pts = 20
        elif total_leaks <= 100:
            leak_pts = 10
        else:
            leak_pts = 0
        score += leak_pts
        components["credential_leaks"] = {
            "value": total_leaks if total_leaks >= 0 else "Unknown (no API key)",
            "points": leak_pts, "max": 20,
        }

        # 5. Breach trend (0-15 points)
        # Improving = no breaches in last 2 years; worsening = recent + multiple
        breach_list = breaches.get("breaches", [])
        recent_count = 0
        for b in breach_list:
            try:
                bd = b.get("date", "")[:10]
                if bd and (datetime.now(timezone.utc) - datetime.strptime(bd, "%Y-%m-%d").replace(tzinfo=timezone.utc)).days < 730:
                    recent_count += 1
            except Exception:
                pass
        if recent_count == 0:
            trend_pts = 15
            trend_label = "Improving"
        elif recent_count <= 2:
            trend_pts = 7
            trend_label = "Stable"
        else:
            trend_pts = 0
            trend_label = "Worsening"
        score += trend_pts
        components["trend"] = {"value": trend_label, "points": trend_pts, "max": 15}

        label = ("Excellent" if score >= 80 else "Good" if score >= 60
                 else "Fair" if score >= 40 else "Poor" if score >= 20 else "Critical")

        return {
            "dbi_score": score,
            "label": label,
            "components": components,
            "max_score": 100,
        }


# ---------------------------------------------------------------------------
# 32. Remediation Simulator (Before/After Model)
# ---------------------------------------------------------------------------

class RemediationSimulator:
    """
    Maps scan findings to prioritised remediation steps with projected
    financial impact reduction. The highest-value feature for insurance —
    shows 'fix these N items → $X reduction in probable annual loss'.
    """
    # Remediation catalog: maps issue patterns to actions
    REMEDIATION_MAP = [
        # (checker_key, condition_fn, action, est_cost, rsi_reduction)
        # --- Critical: Immediate action required ---
        ("vpn_remote", lambda c: c.get("rdp_exposed"), "Block RDP (port 3389) from public internet — use VPN/ZTNA instead. RDP is the #1 ransomware entry vector.", "R9,000–R36,000", 0.35),
        ("high_risk_protocols", lambda c: any(s.get("port") in (27017, 6379, 9200, 5432, 1433, 3306) for s in c.get("exposed_services", [])),
         "Firewall exposed database ports (MongoDB, Redis, PostgreSQL, MySQL, etc.) — restrict to VPN/private network only.", "R9,000–R36,000", 0.15),
        ("shodan_vulns", lambda c: c.get("kev_count", 0) > 0,
         "Patch CISA KEV vulnerabilities immediately — these are confirmed actively exploited in the wild. CISA mandates remediation within 14 days.", "R18,000–R90,000", 0.10),
        ("osv_vulns", lambda c: c.get("critical_count", 0) > 0,
         "Patch critical vulnerabilities detected via version analysis (OSV.dev) — update affected software packages to latest stable versions.", "R18,000–R90,000", 0.10),
        # --- High: Address within 30 days ---
        ("shodan_vulns", lambda c: c.get("high_epss_count", 0) > 0,
         "Patch high-EPSS CVEs (>50% exploitation probability within 30 days) — prioritise by EPSS score for maximum risk reduction.", "R18,000–R90,000", 0.05),
        ("ssl", lambda c: c.get("grade", "A") in ("D", "E", "F"),
         "Upgrade SSL/TLS configuration — enable TLS 1.2+, disable weak ciphers. sslyze analysis shows vulnerable protocols or cipher suites.", "R0–R3,600", 0.05),
        ("email_security", lambda c: not c.get("dmarc", {}).get("present"),
         "Implement DMARC with 'quarantine' or 'reject' policy to prevent email spoofing and phishing campaigns.", "R3,600–R9,000", 0.05),
        ("email_security", lambda c: not c.get("spf", {}).get("present"),
         "Configure SPF record to authorise legitimate email senders — reduces phishing and BEC risk.", "R0–R3,600", 0.03),
        ("email_hardening", lambda c: not c.get("mta_sts"),
         "Implement MTA-STS to force TLS for inbound email and prevent downgrade attacks.", "R3,600–R9,000", 0.02),
        ("waf", lambda c: not c.get("detected"),
         "Deploy a Web Application Firewall (Cloudflare, AWS WAF, etc.) — protects against OWASP Top 10 attacks and DDoS.", "R0–R9,000/mo", 0.05),
        ("http_headers", lambda c: c.get("score", 100) < 40,
         "Implement security headers: HSTS, Content-Security-Policy, X-Frame-Options, Permissions-Policy — prevents XSS, clickjacking, and data leakage.", "R0–R3,600", 0.03),
        ("dehashed", lambda c: c.get("total_entries", 0) > 0,
         "Force password resets for all leaked credentials and enable MFA. Breached credentials enable credential stuffing and account takeover attacks.", "R9,000–R36,000", 0.05),
        ("info_disclosure", lambda c: any(p.get("risk_level") == "critical" for p in c.get("exposed_paths", [])),
         "Remove exposed sensitive files (.env, .git, backups, config files) from web root — these leak credentials and infrastructure details.", "R0–R9,000", 0.03),
        ("exposed_admin", lambda c: c.get("critical_count", 0) > 0,
         "Restrict admin panel access — implement IP whitelist, VPN-only access, or move to non-standard paths.", "R3,600–R18,000", 0.02),
        # --- Medium: Address within 90 days ---
        ("tech_stack", lambda c: c.get("eol_count", 0) > 0,
         "Update end-of-life software components — EOL software receives no security patches and is a prime exploitation target.", "R9,000–R36,000", 0.03),
        ("dnsbl", lambda c: c.get("blacklisted"),
         "Investigate and resolve IP/domain blacklisting — indicates prior compromise, spam, or malware distribution.", "R9,000–R36,000", 0.05),
        ("breaches", lambda c: c.get("breach_count", 0) > 0,
         "Implement breach response plan and continuous credential monitoring — prior breaches significantly increase repeat incident probability.", "R18,000–R90,000", 0.02),
        ("privacy_compliance", lambda c: c.get("score", 100) < 60,
         "Update privacy policy to cover all POPIA/GDPR required sections — failure to comply risks regulatory fines up to 2% of annual turnover.", "R9,000–R36,000", 0.01),
        ("fraudulent_domains", lambda c: c.get("lookalike_count", 0) > 0,
         "Register key lookalike domains defensively and set up brand monitoring — lookalike domains enable phishing and brand impersonation.", "R9,000–R36,000", 0.01),
        ("cloud_cdn", lambda c: not c.get("cdn_detected"),
         "Deploy a CDN for DDoS resilience and improved availability — single-origin hosting is vulnerable to volumetric attacks.", "R0–R9,000/mo", 0.02),
        ("security_policy", lambda c: not c.get("security_txt_found"),
         "Create a security.txt file at /.well-known/security.txt — establishes a vulnerability disclosure policy for responsible reporting.", "R0", 0.01),
        ("website_security", lambda c: not c.get("https_enforced"),
         "Configure web server to redirect all HTTP traffic to HTTPS (301 redirect) — prevents credential interception.", "R0–R3,600", 0.02),
        ("dns_infrastructure", lambda c: not c.get("dnssec_enabled"),
         "Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks.", "R3,600–R9,000", 0.01),
    ]

    def calculate(self, categories: dict, rsi_result: dict,
                  fin_result: dict, annual_revenue: float,
                  industry: str = "other") -> dict:
        steps = []
        total_rsi_reduction = 0.0

        for checker_key, condition_fn, action, est_cost, rsi_reduction in self.REMEDIATION_MAP:
            checker_data = categories.get(checker_key, {})
            try:
                if condition_fn(checker_data):
                    # Estimate annual savings proportional to RSI reduction
                    total_likely = fin_result.get("total", {}).get("most_likely", 0)
                    current_rsi = rsi_result.get("rsi_score", 0.1)
                    # Savings = (rsi_reduction / current_rsi) * total_financial_impact
                    if current_rsi > 0:
                        savings = round((rsi_reduction / current_rsi) * total_likely * 0.7)
                    else:
                        savings = 0

                    steps.append({
                        "action": action,
                        "category": checker_key,
                        "priority": 1 if rsi_reduction >= 0.10 else (2 if rsi_reduction >= 0.05 else 3),
                        "estimated_cost": est_cost,
                        "rsi_reduction": rsi_reduction,
                        "annual_savings_estimate": savings,
                    })
                    total_rsi_reduction += rsi_reduction
            except Exception:
                continue

        # Sort by priority then savings
        steps.sort(key=lambda s: (s["priority"], -s["annual_savings_estimate"]))

        # Simulate improved state
        simulated_rsi = max(0.0, rsi_result.get("rsi_score", 0.1) - total_rsi_reduction)
        total_savings = sum(s["annual_savings_estimate"] for s in steps)

        # Recalculate financial impact with simulated RSI
        simulated_fin = {}
        if fin_result.get("total"):
            ratio = simulated_rsi / max(0.01, rsi_result.get("rsi_score", 0.1))
            simulated_fin = {
                "min": round(fin_result["total"]["min"] * ratio),
                "most_likely": round(fin_result["total"]["most_likely"] * ratio),
                "max": round(fin_result["total"]["max"] * ratio),
            }

        return {
            "steps": steps,
            "step_count": len(steps),
            "current_rsi": rsi_result.get("rsi_score", 0),
            "simulated_rsi": round(simulated_rsi, 3),
            "rsi_improvement": round(total_rsi_reduction, 3),
            "current_financial_impact": fin_result.get("total", {}),
            "simulated_financial_impact": simulated_fin,
            "total_potential_savings": total_savings,
        }

