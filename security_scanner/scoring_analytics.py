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
    """
    INDUSTRY_MULTIPLIER = {
        "healthcare": 1.3, "legal": 1.3, "finance": 1.2,
        "government": 1.2, "manufacturing": 1.1, "retail": 1.1,
        "education": 1.1, "tech": 1.0, "other": 1.1,
    }

    def calculate(self, categories: dict, industry: str = "other",
                  annual_revenue: float = 0) -> dict:
        base = 0.10
        factors = []

        # RDP exposed: +0.35 (strongest signal)
        if categories.get("vpn_remote", {}).get("rdp_exposed"):
            base += 0.35
            factors.append({"factor": "RDP (port 3389) exposed to internet", "impact": 0.35, "priority": 1})

        # Exposed database/service ports: +0.15 each, cap 0.30
        exposed = categories.get("high_risk_protocols", {}).get("exposed_services", [])
        db_ports = [s for s in exposed if s.get("port") in (27017, 6379, 9200, 5432, 1433, 5984, 3306)]
        db_impact = min(0.30, len(db_ports) * 0.15)
        if db_impact > 0:
            base += db_impact
            factors.append({"factor": f"{len(db_ports)} exposed database port(s)", "impact": round(db_impact, 2), "priority": 1})

        # KEV CVEs: +0.10 each, cap 0.25
        cves = categories.get("shodan_vulns", {}).get("cves", [])
        kev_count = sum(1 for c in cves if c.get("in_kev"))
        kev_impact = min(0.25, kev_count * 0.10)
        if kev_impact > 0:
            base += kev_impact
            factors.append({"factor": f"{kev_count} CISA KEV CVE(s) — actively exploited", "impact": round(kev_impact, 2), "priority": 1})

        # High EPSS CVEs (>0.5): +0.05 each, cap 0.15
        high_epss = sum(1 for c in cves if c.get("epss_score", 0) > 0.5)
        epss_impact = min(0.15, high_epss * 0.05)
        if epss_impact > 0:
            base += epss_impact
            factors.append({"factor": f"{high_epss} high-EPSS CVE(s) (>50% exploit probability)", "impact": round(epss_impact, 2), "priority": 2})

        # Other critical/high CVEs: +0.03 each, cap 0.10
        other_crit = sum(1 for c in cves if c.get("severity") in ("critical", "high") and not c.get("in_kev"))
        other_impact = min(0.10, other_crit * 0.03)
        if other_impact > 0:
            base += other_impact
            factors.append({"factor": f"{other_crit} unpatched critical/high CVE(s)", "impact": round(other_impact, 2), "priority": 2})

        # Leaked credentials > 100: +0.10
        dehashed = categories.get("dehashed", {})
        if dehashed.get("total_entries", 0) > 100:
            base += 0.10
            factors.append({"factor": f"{dehashed['total_entries']} credential leaks (Dehashed)", "impact": 0.10, "priority": 2})
        elif dehashed.get("total_entries", 0) > 0:
            base += 0.05
            factors.append({"factor": f"{dehashed['total_entries']} credential leaks (Dehashed)", "impact": 0.05, "priority": 3})

        # Breach history: +0.05 if recent breach
        breaches = categories.get("breaches", {})
        if breaches.get("breach_count", 0) > 3:
            base += 0.05
            factors.append({"factor": f"{breaches['breach_count']} historical breaches", "impact": 0.05, "priority": 3})

        # No DMARC: +0.05
        dmarc = categories.get("email_security", {}).get("dmarc", {})
        if not dmarc.get("present"):
            base += 0.05
            factors.append({"factor": "No DMARC record — phishing/BEC vector", "impact": 0.05, "priority": 3})
        elif dmarc.get("policy") == "none":
            base += 0.03
            factors.append({"factor": "DMARC policy is 'none' — not enforced", "impact": 0.03, "priority": 3})

        # No WAF: +0.05
        if not categories.get("waf", {}).get("detected"):
            base += 0.05
            factors.append({"factor": "No WAF detected", "impact": 0.05, "priority": 3})

        # Weak SSL: +0.05
        ssl_grade = categories.get("ssl", {}).get("grade", "F")
        if ssl_grade in ("D", "E", "F"):
            base += 0.05
            factors.append({"factor": f"Weak SSL (grade {ssl_grade})", "impact": 0.05, "priority": 3})

        # Blacklisted IPs: +0.05
        if categories.get("dnsbl", {}).get("blacklisted"):
            base += 0.05
            factors.append({"factor": "IP/domain blacklisted", "impact": 0.05, "priority": 2})

        # Information disclosure: +0.03 per critical exposure
        info = categories.get("info_disclosure", {})
        crit_exposed = sum(1 for p in info.get("exposed_paths", []) if p.get("risk_level") == "critical")
        if crit_exposed > 0:
            info_impact = min(0.10, crit_exposed * 0.03)
            base += info_impact
            factors.append({"factor": f"{crit_exposed} critical file(s) exposed", "impact": round(info_impact, 2), "priority": 2})

        # Apply multipliers
        ind_mult = self.INDUSTRY_MULTIPLIER.get(industry, 1.1)
        if annual_revenue > 0 and annual_revenue < 20_000_000:
            size_mult = 1.2
        elif annual_revenue >= 500_000_000:
            size_mult = 0.9
        else:
            size_mult = 1.0

        rsi = min(1.0, round(base * ind_mult * size_mult, 3))

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

    def calculate(self, categories: dict, rsi_result: dict,
                  annual_revenue: float, industry: str = "other",
                  annual_revenue_zar: int = 0) -> dict:

        # Use ZAR path when ZAR revenue is provided (SA-specific model)
        if annual_revenue_zar > 0:
            return self._calculate_zar(categories, rsi_result, annual_revenue_zar, industry)

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
        deductible = round(mc_stats["p5"] * 0.5, -3)
        expected_annual = round(mc_stats["p50"], -3)
        coverage_limit = round(mc_stats["p95"] * 1.2, -3)

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
                "expected_annual_loss": max(1000, expected_annual),
                "recommended_coverage": max(10000, coverage_limit),
            },
            "annual_revenue": annual_revenue,
            "industry": industry,
            "currency": "ZAR",
        }
        output["risk_mitigations"] = self._build_mitigations(categories, output)
        return output

    def _calculate_zar(self, categories: dict, rsi_result: dict,
                       annual_revenue_zar: int, industry: str) -> dict:
        """SA-specific ZAR calculation using IBM 2025 SA breach cost data and POPIA fines."""
        # Normalise industry key
        industry_key = industry.title()
        industry_data = SA_INDUSTRY_COSTS.get(industry_key, SA_INDUSTRY_COSTS["Other"])
        rsi_score = rsi_result.get("rsi_score", 0.1)
        daily_revenue = annual_revenue_zar / 365

        # --- Scenario 1: Data Breach (ZAR) ---
        overall_score = categories.get("_overall_score", 500)  # fallback
        p_breach = min(1.0, max(0.0, ((100 - overall_score / 10) / 100) * industry_data["multiplier"] * 0.3))
        estimated_records = max(100, annual_revenue_zar // 50_000)
        cost_per_record = industry_data["cost_per_record"]
        regulatory_fine = annual_revenue_zar * 0.02  # POPIA max ~2% of annual turnover
        data_breach_loss = p_breach * (estimated_records * cost_per_record + regulatory_fine)

        # --- Scenario 2: Ransomware (ZAR) ---
        avg_downtime_days = 22
        if annual_revenue_zar < 50_000_000:
            ransom_estimate = 500_000
            ir_cost = 500_000
        elif annual_revenue_zar < 200_000_000:
            ransom_estimate = 2_500_000
            ir_cost = 1_500_000
        elif annual_revenue_zar < 500_000_000:
            ransom_estimate = 10_000_000
            ir_cost = 3_000_000
        else:
            ransom_estimate = 50_000_000
            ir_cost = 5_000_000
        ransomware_loss = rsi_score * (avg_downtime_days * daily_revenue * 0.5 + ransom_estimate + ir_cost)

        # --- Scenario 3: Business Interruption (ZAR) ---
        waf_detected = categories.get("waf", {}).get("detected", False)
        cdn_detected = categories.get("cloud_cdn", {}).get("cdn_detected", False)
        single_asn = categories.get("external_ips", {}).get("unique_asns", 2) <= 1
        p_interruption = min(0.5, 0.05 + (0.05 if not waf_detected else 0) + (0.05 if not cdn_detected else 0) + (0.05 if single_asn else 0))
        impact_factor = min(0.8, 0.3 + (0.15 if not waf_detected else 0) + (0.15 if not cdn_detected else 0) + (0.1 if single_asn else 0))
        bi_loss = p_interruption * (5 * daily_revenue * impact_factor)

        most_likely = round(data_breach_loss + ransomware_loss + bi_loss)

        # --- Monte Carlo Simulation (ZAR) ---
        # Each parameter is sampled from a PERT distribution around its
        # point estimate, using ±30-50% ranges based on parameter uncertainty.
        import numpy as np
        np.random.seed(42)  # Reproducible results for same input
        N = self.MC_ITERATIONS

        # Breach scenario samples
        mc_p_breach = np.clip(self._pert_sample(p_breach * 0.5, p_breach, min(1.0, p_breach * 2.0), N), 0, 1)
        mc_records = self._pert_sample(estimated_records * 0.3, estimated_records, estimated_records * 3.0, N)
        mc_cpr = self._pert_sample(cost_per_record * 0.6, cost_per_record, cost_per_record * 1.5, N)
        mc_reg_fine = self._pert_sample(regulatory_fine * 0.5, regulatory_fine, regulatory_fine * 2.0, N)
        mc_breach = mc_p_breach * (mc_records * mc_cpr + mc_reg_fine)

        # Ransomware scenario samples
        mc_rsi = np.clip(self._pert_sample(rsi_score * 0.5, rsi_score, min(1.0, rsi_score * 2.0), N), 0, 1)
        mc_downtime = self._pert_sample(7, avg_downtime_days, 45, N)  # 7-45 days range
        mc_ransom = self._pert_sample(ransom_estimate * 0.3, ransom_estimate, ransom_estimate * 3.0, N)
        mc_ir = self._pert_sample(ir_cost * 0.5, ir_cost, ir_cost * 2.5, N)
        mc_ransomware = mc_rsi * (mc_downtime * daily_revenue * 0.5 + mc_ransom + mc_ir)

        # BI scenario samples
        mc_p_int = np.clip(self._pert_sample(p_interruption * 0.3, p_interruption, min(0.8, p_interruption * 3.0), N), 0, 1)
        mc_bi_days = self._pert_sample(1, 5, 14, N)  # 1-14 days range
        mc_impact = np.clip(self._pert_sample(impact_factor * 0.5, impact_factor, min(1.0, impact_factor * 1.5), N), 0, 1)
        mc_bi = mc_p_int * (mc_bi_days * daily_revenue * mc_impact)

        # Total loss distribution
        mc_total = mc_breach + mc_ransomware + mc_bi
        mc_stats = self._mc_percentiles(mc_total)

        # Per-scenario percentiles
        mc_breach_stats = self._mc_percentiles(mc_breach)
        mc_ransomware_stats = self._mc_percentiles(mc_ransomware)
        mc_bi_stats = self._mc_percentiles(mc_bi)

        # Use MC percentiles for min/max instead of fixed multipliers
        minimum = mc_stats["p5"]
        maximum = mc_stats["p95"]
        recommended_cover = max(1_000_000, round(maximum * 1.2, -5))
        minimum_cover = max(500_000, round(mc_stats["p50"], -5))

        if rsi_score >= 0.7:
            premium_tier = "Very High"
        elif rsi_score >= 0.5:
            premium_tier = "High"
        elif rsi_score >= 0.25:
            premium_tier = "Medium"
        else:
            premium_tier = "Low"

        loss_pct = most_likely / annual_revenue_zar if annual_revenue_zar > 0 else 0
        if loss_pct >= 0.10:
            fin_score = 10
        elif loss_pct >= 0.05:
            fin_score = 30
        elif loss_pct >= 0.02:
            fin_score = 50
        elif loss_pct >= 0.01:
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
            "scenarios": {
                "data_breach": {
                    "probability": round(p_breach, 3),
                    "estimated_loss": round(data_breach_loss),
                    "cost_per_record": cost_per_record,
                    "estimated_records": estimated_records,
                    "regulatory_fine": round(regulatory_fine),
                    "monte_carlo": mc_breach_stats,
                },
                "ransomware": {
                    "rsi_score": rsi_score,
                    "estimated_loss": round(ransomware_loss),
                    "avg_downtime_days": avg_downtime_days,
                    "ransom_estimate": ransom_estimate,
                    "monte_carlo": mc_ransomware_stats,
                },
                "business_interruption": {
                    "probability": round(p_interruption, 3),
                    "estimated_loss": round(bi_loss),
                    "monte_carlo": mc_bi_stats,
                },
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
                "suggested_deductible": minimum_cover,
                "expected_annual_loss": most_likely,
                "recommended_coverage": recommended_cover,
            },
        }
        # Append risk mitigation recommendations
        output["risk_mitigations"] = self._build_mitigations(categories, output)
        return output

    MITIGATIONS = [
        {"pattern": r"RDP.*exposed",                          "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.35, "label": "Block RDP from public internet and enforce VPN/Zero Trust access"},
        {"pattern": r"SSL certificate has EXPIRED",           "severity": "Critical", "scenario": "data_breach",            "probability_reduction": 0.15, "label": "Renew SSL certificate immediately"},
        {"pattern": r"listed in CISA KEV",                    "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.10, "label": "Patch CISA Known Exploited Vulnerabilities within 48 hours"},
        {"pattern": r"critical CVE",                          "severity": "Critical", "scenario": "ransomware",             "rsi_reduction": 0.10, "label": "Patch critical CVEs on public-facing servers"},
        {"pattern": r"CRITICAL:.*Sensitive file exposed",     "severity": "Critical", "scenario": "data_breach",            "probability_reduction": 0.10, "label": "Restrict access to exposed sensitive files"},
        {"pattern": r"high.severity CVE|high CVE",            "severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.05, "label": "Patch high-severity CVEs within 30 days"},
        {"pattern": r"No WAF detected",                       "severity": "High",     "scenario": "both",                   "rsi_reduction": 0.05, "bi_reduction": 0.05, "label": "Deploy a Web Application Firewall (WAF)"},
        {"pattern": r"No SPF record|No DMARC record",         "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.05, "label": "Implement email authentication (SPF/DMARC/DKIM)"},
        {"pattern": r"password.*leaked|Plaintext.*password",   "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.10, "label": "Force password resets for all leaked credentials"},
        {"pattern": r"credential record.*found in Dehashed",  "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Audit and rotate credentials exposed in data leaks"},
        {"pattern": r"admin.*exposed|login.*exposed",          "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.05, "label": "Restrict access to admin and login panels"},
        {"pattern": r"Telnet|FTP.*exposed|high.risk.*protocol","severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.15, "label": "Disable insecure protocols (Telnet, FTP, etc.)"},
        {"pattern": r"SSL.*grade.*(C|D|F|T)",                  "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Upgrade SSL/TLS configuration to grade A"},
        {"pattern": r"HTTPS not enforced",                     "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.05, "label": "Enforce HTTPS across all endpoints"},
        {"pattern": r"EOL software|end.of.life",               "severity": "High",     "scenario": "ransomware",             "rsi_reduction": 0.05, "label": "Update end-of-life software components"},
        {"pattern": r"Self.hosted payment",                    "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.08, "label": "Migrate to PCI-compliant payment provider"},
        {"pattern": r"DNSSEC.*not enabled",                    "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Enable DNSSEC for DNS integrity"},
        {"pattern": r"Missing security header|HSTS.*missing|X-Frame|Content-Security-Policy", "severity": "Medium", "scenario": "data_breach", "probability_reduction": 0.02, "label": "Implement security headers (HSTS, CSP, X-Frame-Options)"},
        {"pattern": r"blacklist|blocklist|listed on",          "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.03, "label": "Resolve DNS blocklist entries"},
        {"pattern": r"lookalike domain|typosquat|fraudulent",  "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.03, "label": "Monitor and take down fraudulent lookalike domains"},
        {"pattern": r"single ASN|unique_asns.*1",              "severity": "Medium",   "scenario": "business_interruption",  "bi_reduction": 0.05, "label": "Add hosting redundancy across multiple providers"},
        {"pattern": r"No VPN.*detected",                       "severity": "Medium",   "scenario": "ransomware",             "rsi_reduction": 0.03, "label": "Implement VPN or Zero Trust Network Access for remote workers"},
        {"pattern": r"No DKIM",                                "severity": "Medium",   "scenario": "data_breach",            "probability_reduction": 0.02, "label": "Enable DKIM signing on your mail server"},
        {"pattern": r"No CDN detected",                        "severity": "Medium",   "scenario": "business_interruption",  "bi_reduction": 0.03, "label": "Deploy a CDN for DDoS resilience and availability"},
        {"pattern": r"database port|MySQL|PostgreSQL|MongoDB|Redis|Elasticsearch", "severity": "High", "scenario": "data_breach", "probability_reduction": 0.08, "label": "Restrict database access to private networks/VPN"},
        {"pattern": r"breach_count|known breach",              "severity": "High",     "scenario": "data_breach",            "probability_reduction": 0.05, "label": "Enforce password resets and MFA across all accounts"},
    ]

    def _build_mitigations(self, categories: dict, fin_output: dict) -> dict:
        """Analyse scan findings and estimate per-finding cost reduction using FAIR methodology."""
        # Get scenario losses — works for both USD and ZAR paths
        scenarios = fin_output.get("scenarios", {})
        db_scenario = scenarios.get("data_breach", {})
        rw_scenario = scenarios.get("ransomware", {})
        bi_scenario = scenarios.get("business_interruption", {})

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

            if "rsi_reduction" in mit:
                if rsi_score > 0:
                    savings += rw_loss * (mit["rsi_reduction"] / rsi_score)

            if "probability_reduction" in mit:
                if p_breach > 0:
                    savings += db_loss * (mit["probability_reduction"] / p_breach)

            if "bi_reduction" in mit:
                p_int = bi_scenario.get("probability", 0.05)
                if p_int > 0:
                    savings += bi_loss * (mit["bi_reduction"] / p_int)

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

