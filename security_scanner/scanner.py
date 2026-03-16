"""
Cyber Insurance External Security Scanner
Passive, read-only assessment of external-facing infrastructure.
All checks use only publicly available information.
"""

import ssl
import socket
import json
import re
import time
import threading
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 CyberInsuranceScanner/1.0 (passive assessment)"


# ---------------------------------------------------------------------------
# 1. SSL / TLS Assessment
# ---------------------------------------------------------------------------

class SSLChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "certificate": {}, "tls_versions": {},
            "cipher_suite": {}, "hsts": False, "grade": "F", "score": 0, "issues": [],
        }
        try:
            result["certificate"] = self._get_certificate(domain)
            result["tls_versions"] = self._check_tls_versions(domain)
            result["cipher_suite"] = self._get_cipher_suite(domain)
            result["hsts"] = self._check_hsts(domain)
            grade, score, issues = self._calculate_grade(
                result["certificate"], result["tls_versions"],
                result["cipher_suite"], result["hsts"]
            )
            result["grade"] = grade
            result["score"] = score
            result["issues"] = issues
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
            result["issues"] = [f"SSL check error: {e}"]
        return result

    def _get_certificate(self, domain: str) -> dict:
        info = {"valid": False}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    cert = s.getpeercert()
                    not_after = cert.get("notAfter", "")
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    info = {
                        "valid": True,
                        "subject": subject.get("commonName", domain),
                        "issuer": issuer.get("organizationName", "Unknown"),
                        "issuer_cn": issuer.get("commonName", "Unknown"),
                        "expiry_date": not_after,
                        "days_until_expiry": days_left,
                        "is_expired": days_left < 0,
                        "expiring_soon": 0 <= days_left <= 30,
                        "san_count": len(sans),
                    }
        except ssl.SSLCertVerificationError as e:
            info = {"valid": False, "error": str(e)}
        except Exception as e:
            info = {"valid": False, "error": str(e)}
        return info

    def _check_tls_versions(self, domain: str) -> dict:
        versions = {"TLS 1.0": False, "TLS 1.1": False, "TLS 1.2": False, "TLS 1.3": False}
        checks = {
            "TLS 1.2": ("TLSv1_2", True), "TLS 1.3": ("TLSv1_3", True),
            "TLS 1.0": ("TLSv1", False), "TLS 1.1": ("TLSv1_1", False),
        }
        for label, (attr, verify) in checks.items():
            if not hasattr(ssl.TLSVersion, attr):
                continue
            try:
                ver = getattr(ssl.TLSVersion, attr)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = ver; ctx.maximum_version = ver
                ctx.check_hostname = verify
                ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
                with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                    with ctx.wrap_socket(raw, server_hostname=domain):
                        versions[label] = True
            except Exception:
                pass
        return versions

    def _get_cipher_suite(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    c = s.cipher()
                    if c:
                        weak = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
                        return {"name": c[0], "protocol": c[1], "bits": c[2] or 0,
                                "is_weak": any(w in c[0].upper() for w in weak)}
        except Exception as e:
            return {"name": "Unknown", "bits": 0, "is_weak": True, "error": str(e)}
        return {"name": "Unknown", "bits": 0, "is_weak": True}

    def _check_hsts(self, domain: str) -> bool:
        if not REQUESTS_AVAILABLE:
            return False
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return "strict-transport-security" in r.headers
        except Exception:
            return False

    def _calculate_grade(self, cert, tls, cipher, hsts) -> tuple:
        issues, ded = [], 0
        if not cert.get("valid"):
            ded += 40; issues.append("Invalid or unverifiable SSL certificate")
        elif cert.get("is_expired"):
            ded += 40; issues.append("SSL certificate has EXPIRED")
        elif cert.get("expiring_soon"):
            ded += 20; issues.append(f"Certificate expiring in {cert.get('days_until_expiry')} days")
        if tls.get("TLS 1.0"):
            ded += 20; issues.append("TLS 1.0 supported — deprecated and insecure")
        if tls.get("TLS 1.1"):
            ded += 10; issues.append("TLS 1.1 supported — deprecated")
        if not tls.get("TLS 1.2") and not tls.get("TLS 1.3"):
            ded += 30; issues.append("No modern TLS version (1.2/1.3) detected")
        if cipher.get("is_weak"):
            ded += 20; issues.append(f"Weak cipher: {cipher.get('name', 'Unknown')}")
        if not hsts:
            ded += 10; issues.append("HSTS header missing")
        score = max(0, 100 - ded)
        grade = "A+" if score >= 95 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 50 else "F"
        return grade, score, issues


# ---------------------------------------------------------------------------
# 2. Email Security (DNS-based)
# ---------------------------------------------------------------------------

class EmailSecurityChecker:
    DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "dkim", "k1", "smtp"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "spf": {"present": False, "valid": False, "record": None},
            "dmarc": {"present": False, "policy": None, "record": None},
            "dkim": {"selectors_found": []},
            "mx": {"records": []},
            "score": 0, "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; result["error"] = "dnspython not installed"; return result
        try:
            result["spf"] = self._check_spf(domain)
            result["dmarc"] = self._check_dmarc(domain)
            result["dkim"] = self._check_dkim(domain)
            result["mx"] = self._check_mx(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["spf"], result["dmarc"], result["dkim"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_spf(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    valid = "all" in txt
                    return {"present": True, "valid": valid, "record": txt,
                            "dangerous": "+all" in txt}
        except Exception:
            pass
        return {"present": False, "valid": False, "record": None, "dangerous": False}

    def _check_dmarc(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=DMARC1" in txt:
                    match = re.search(r"p=(\w+)", txt)
                    policy = match.group(1) if match else "none"
                    return {"present": True, "policy": policy, "record": txt}
        except Exception:
            pass
        return {"present": False, "policy": None, "record": None}

    def _check_dkim(self, domain: str) -> dict:
        found = []
        for selector in self.DKIM_SELECTORS:
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=5)
                found.append(selector)
            except Exception:
                pass
        return {"selectors_found": found}

    def _check_mx(self, domain: str) -> dict:
        records = []
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=DEFAULT_TIMEOUT)
            records = sorted([{"preference": r.preference, "exchange": str(r.exchange)} for r in answers],
                             key=lambda x: x["preference"])
        except Exception:
            pass
        return {"records": records}

    def _calculate_score(self, spf, dmarc, dkim) -> tuple:
        score, issues = 10, []
        if not spf["present"]:
            score -= 3; issues.append("No SPF record — spoofing risk")
        elif spf.get("dangerous"):
            score -= 3; issues.append("SPF uses '+all' — allows any server to send on your behalf")
        elif not spf["valid"]:
            score -= 1; issues.append("SPF record may be invalid")
        if not dmarc["present"]:
            score -= 4; issues.append("No DMARC record — phishing risk")
        elif dmarc["policy"] == "none":
            score -= 2; issues.append("DMARC policy is 'none' — no enforcement")
        elif dmarc["policy"] == "quarantine":
            score -= 1; issues.append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")
        if not dkim["selectors_found"]:
            score -= 2; issues.append("No DKIM selectors found for common selector names")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 3. Email Hardening (MTA-STS, DANE, BIMI)
# ---------------------------------------------------------------------------

class EmailHardeningChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "mta_sts": {"present": False, "mode": None},
            "bimi": {"present": False, "has_vmc": False},
            "dane": {"present": False},
            "issues": [], "score": 0,
        }
        if not DNS_AVAILABLE or not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            result["mta_sts"] = self._check_mta_sts(domain)
            result["bimi"] = self._check_bimi(domain)
            result["dane"] = self._check_dane(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["mta_sts"], result["bimi"], result["dane"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_mta_sts(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_mta-sts.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=STSv1" in txt:
                    # Also try to fetch the policy file
                    mode = None
                    try:
                        r = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                                         timeout=5, headers={"User-Agent": USER_AGENT})
                        m = re.search(r"mode:\s*(\w+)", r.text)
                        mode = m.group(1) if m else "unknown"
                    except Exception:
                        mode = "unknown"
                    return {"present": True, "mode": mode}
        except Exception:
            pass
        return {"present": False, "mode": None}

    def _check_bimi(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=BIMI1" in txt:
                    has_vmc = "a=https" in txt.lower()
                    return {"present": True, "has_vmc": has_vmc}
        except Exception:
            pass
        return {"present": False, "has_vmc": False}

    def _check_dane(self, domain: str) -> dict:
        # Check TLSA record for primary MX
        try:
            mx_answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            if mx_answers:
                mx_host = str(sorted(mx_answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
                try:
                    dns.resolver.resolve(f"_25._tcp.{mx_host}", "TLSA", lifetime=5)
                    return {"present": True}
                except Exception:
                    pass
        except Exception:
            pass
        return {"present": False}

    def _calculate_score(self, mta_sts, bimi, dane) -> tuple:
        score, issues = 0, []
        if mta_sts["present"]:
            score += 4
            if mta_sts["mode"] == "enforce":
                score += 2
        else:
            issues.append("No MTA-STS policy — inbound email susceptible to TLS downgrade attacks")
        if bimi["present"]:
            score += 2
            if bimi["has_vmc"]:
                score += 1
        if dane["present"]:
            score += 1
        else:
            issues.append("DANE/TLSA not configured for mail servers")
        return min(score, 10), issues


# ---------------------------------------------------------------------------
# 4. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 20),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    def check(self, domain: str) -> dict:
        result = {"status": "completed", "headers": {}, "score": 0, "issues": []}
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            total_weight, earned = 0, 0
            for key, (label, weight) in self.HEADERS.items():
                present = key in headers_lower
                result["headers"][label] = {"present": present, "value": headers_lower.get(key)}
                total_weight += weight
                if present:
                    earned += weight
                else:
                    result["issues"].append(f"Missing security header: {label}")
            result["score"] = round((earned / total_weight) * 100) if total_weight else 0
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 5. WAF Detection
# ---------------------------------------------------------------------------

class WAFChecker:
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status"],
            "cookies": ["__cfduid", "cf_clearance"],
            "body": ["cloudflare"],
        },
        "AWS WAF / CloudFront": {
            "headers": ["x-amz-cf-id", "x-amzn-requestid", "x-cache"],
            "cookies": ["awselb", "awsalb"],
            "body": [],
        },
        "Imperva / Incapsula": {
            "headers": ["x-iinfo", "x-cdn"],
            "cookies": ["visid_incap", "_incap_ses"],
            "body": ["incap_ses", "visid_incap"],
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-check-cacheable"],
            "cookies": ["ak_bmsc", "bm_sz"],
            "body": [],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "cookies": [],
            "body": ["sucuri"],
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-wa-info", "x-frame-options"],
            "cookies": ["ts", "f5avr"],
            "body": [],
        },
        "Barracuda": {
            "headers": [],
            "cookies": ["barra_counter_session"],
            "body": [],
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "detected": False,
            "waf_name": None,
            "all_detected": [],
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            cookies_lower = {k.lower(): v.lower() for k, v in r.cookies.items()}
            body_lower = r.text[:5000].lower()

            detected = []
            for waf_name, sigs in self.WAF_SIGNATURES.items():
                matched = False
                for h in sigs["headers"]:
                    if h in headers_lower:
                        matched = True; break
                if not matched:
                    for c in sigs["cookies"]:
                        if c in cookies_lower:
                            matched = True; break
                if not matched:
                    for b in sigs["body"]:
                        if b in body_lower:
                            matched = True; break
                if matched:
                    detected.append(waf_name)

            if detected:
                result["detected"] = True
                result["waf_name"] = detected[0]
                result["all_detected"] = detected
            else:
                result["issues"].append("No WAF detected — web application firewall recommended")
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 6. Cloud & CDN Provider Detection
# ---------------------------------------------------------------------------

class CloudCDNChecker:
    CLOUD_CNAMES = {
        "Cloudflare": [".cloudflare.com", ".cloudflare.net"],
        "AWS CloudFront": [".cloudfront.net"],
        "AWS": [".amazonaws.com", ".awsglobalaccelerator.com", ".elb.amazonaws.com"],
        "Azure": [".azurewebsites.net", ".trafficmanager.net", ".azure-api.net", ".cloudapp.azure.com"],
        "GCP": [".appspot.com", ".run.app", ".googleapis.com"],
        "Akamai": [".akamaiedge.net", ".akamaihd.net", ".akamaistream.net"],
        "Fastly": [".fastly.net", ".fastlylb.net"],
        "Vercel": [".vercel.app", ".vercel-dns.com"],
        "Netlify": [".netlify.app", ".netlify.com"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "provider": None,
            "cdn_detected": False,
            "ip_addresses": [],
            "hosting_type": "unknown",
            "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            # Resolve IPs
            try:
                ips = [str(r) for r in dns.resolver.resolve(domain, "A", lifetime=DEFAULT_TIMEOUT)]
                result["ip_addresses"] = ips
            except Exception:
                pass

            # Chase CNAME chain
            cname_chain = []
            try:
                target = domain
                for _ in range(5):
                    try:
                        answers = dns.resolver.resolve(target, "CNAME", lifetime=5)
                        cname = str(answers[0].target)
                        cname_chain.append(cname)
                        target = cname
                    except Exception:
                        break
            except Exception:
                pass

            all_cnames = " ".join(cname_chain).lower()

            for provider, patterns in self.CLOUD_CNAMES.items():
                if any(p in all_cnames for p in patterns):
                    result["provider"] = provider
                    result["cdn_detected"] = True
                    result["hosting_type"] = "cloud/cdn"
                    break

            if not result["provider"] and result["ip_addresses"]:
                result["hosting_type"] = "self-hosted or undetected cloud"

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 7. Domain Intelligence (WHOIS)
# ---------------------------------------------------------------------------

class DomainIntelChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "domain_age_days": None,
            "privacy_protected": False,
            "issues": [],
        }
        try:
            import whois
            w = whois.whois(domain)
            creation = w.creation_date
            expiry = w.expiration_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiry, list):
                expiry = expiry[0]

            result["registrar"] = str(w.registrar) if w.registrar else None

            if creation:
                age = (datetime.now() - creation.replace(tzinfo=None)).days
                result["creation_date"] = str(creation.date()) if hasattr(creation, 'date') else str(creation)
                result["domain_age_days"] = age
                if age < 365:
                    result["issues"].append(f"Domain is less than 1 year old ({age} days) — higher fraud risk")
                elif age < 730:
                    result["issues"].append(f"Domain is less than 2 years old ({age} days)")

            if expiry:
                result["expiry_date"] = str(expiry.date()) if hasattr(expiry, 'date') else str(expiry)
                days_to_expiry = (expiry.replace(tzinfo=None) - datetime.now()).days
                if days_to_expiry < 30:
                    result["issues"].append(f"Domain expires in {days_to_expiry} days — renewal risk")

            # Detect privacy protection
            whois_raw = str(w).lower()
            privacy_keywords = ["redacted", "privacy", "withheld", "protected", "proxy"]
            result["privacy_protected"] = any(k in whois_raw for k in privacy_keywords)

        except ImportError:
            result["status"] = "skipped"
            result["error"] = "python-whois not installed"
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 8. Subdomain Discovery (Certificate Transparency)
# ---------------------------------------------------------------------------

class SubdomainChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "subdomains": [],
            "risky_subdomains": [],
            "total_count": 0,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        RISKY_KEYWORDS = ["dev", "staging", "test", "admin", "api", "old", "beta",
                          "backup", "db", "database", "internal", "vpn", "remote",
                          "jenkins", "gitlab", "jira", "grafana", "kibana", "phpmyadmin"]
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=20, headers={"User-Agent": USER_AGENT}
            )
            if r.status_code == 200:
                entries = r.json()
                seen = set()
                subdomains = []
                for entry in entries:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name and name != domain and domain in name and name not in seen:
                            seen.add(name)
                            subdomains.append(name)

                subdomains = subdomains[:100]  # cap at 100
                result["subdomains"] = subdomains
                result["total_count"] = len(subdomains)

                risky = [s for s in subdomains if any(k in s for k in RISKY_KEYWORDS)]
                result["risky_subdomains"] = risky

                if risky:
                    result["issues"].append(
                        f"{len(risky)} risky subdomain(s) found in public CT logs: {', '.join(risky[:5])}"
                    )
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 9. Exposed Admin Panels & Sensitive Paths
# ---------------------------------------------------------------------------

class ExposedAdminChecker:
    PATHS = {
        "critical": [
            "/.env", "/.git/HEAD", "/.git/config", "/wp-config.php",
            "/config.php", "/database.yml", "/.htpasswd", "/backup.sql",
            "/dump.sql", "/db.sql", "/backup.zip", "/backup.tar.gz",
        ],
        "high": [
            "/admin", "/administrator", "/wp-admin", "/wp-login.php",
            "/phpmyadmin", "/cpanel", "/whm", "/webmail",
            "/jenkins", "/grafana", "/kibana", "/portainer",
            "/jira", "/confluence", "/gitlab", "/rancher",
            "/.well-known/", "/api/v1/users", "/api/v2/users",
        ],
        "medium": [
            "/server-status", "/server-info", "/status", "/health",
            "/metrics", "/actuator", "/actuator/health", "/actuator/env",
            "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
            "/robots.txt", "/sitemap.xml", "/phpinfo.php",
        ],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed": [],
            "critical_count": 0,
            "high_count": 0,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        exposed = []

        def probe(path, risk):
            try:
                r = requests.get(
                    f"https://{domain}{path}", timeout=4,
                    allow_redirects=False, headers={"User-Agent": USER_AGENT}
                )
                # 200 = exposed, 401/403 = exists but auth required (still noteworthy for critical)
                if r.status_code == 200 or (risk == "critical" and r.status_code in [401, 403]):
                    return {"path": path, "status": r.status_code, "risk": risk}
            except Exception:
                pass
            return None

        all_paths = [(p, "critical") for p in self.PATHS["critical"]] + \
                    [(p, "high") for p in self.PATHS["high"]] + \
                    [(p, "medium") for p in self.PATHS["medium"]]

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(probe, path, risk): (path, risk) for path, risk in all_paths}
            for f in as_completed(futures, timeout=25):
                try:
                    r = f.result()
                    if r:
                        exposed.append(r)
                except Exception:
                    pass

        result["exposed"] = sorted(exposed, key=lambda x: ["critical", "high", "medium"].index(x["risk"]))
        result["critical_count"] = sum(1 for e in exposed if e["risk"] == "critical")
        result["high_count"] = sum(1 for e in exposed if e["risk"] == "high")

        for e in exposed:
            if e["risk"] == "critical":
                result["issues"].append(f"CRITICAL: Sensitive file exposed — {e['path']} (HTTP {e['status']})")
            elif e["risk"] == "high":
                result["issues"].append(f"Admin panel accessible — {e['path']} (HTTP {e['status']})")

        return result


# ---------------------------------------------------------------------------
# 10. VPN / Remote Access Detection
# ---------------------------------------------------------------------------

class VPNRemoteAccessChecker:
    VPN_SIGNATURES = {
        "Cisco AnyConnect": {
            "paths": ["/+CSCOE+/logon.html", "/+webvpn+/"],
            "body_keywords": ["anyconnect", "cisco ssl vpn"],
        },
        "Fortinet FortiGate SSL VPN": {
            "paths": ["/remote/login", "/remote/logincheck"],
            "body_keywords": ["fortinet", "fortigate", "ssl-vpn"],
        },
        "Pulse Secure / Ivanti": {
            "paths": ["/dana-na/auth/url_default/welcome.cgi"],
            "body_keywords": ["pulse secure", "ivanti"],
        },
        "Palo Alto GlobalProtect": {
            "paths": ["/global-protect/getsoftware.esp", "/ssl-vpn/"],
            "body_keywords": ["globalprotect", "palo alto"],
        },
        "Citrix Gateway": {
            "paths": ["/citrix/xenapp", "/Citrix/XenApp", "/vpn/index.html"],
            "body_keywords": ["citrix gateway", "netscaler"],
        },
        "Microsoft RDS Web": {
            "paths": ["/RDWeb/Pages/en-US/login.aspx", "/RDWeb/"],
            "body_keywords": ["remote desktop", "rdweb"],
        },
        "OpenVPN Access Server": {
            "paths": ["/"],
            "body_keywords": ["openvpn access server", "openvpn-as"],
        },
        "SonicWall SSL VPN": {
            "paths": ["/cgi-bin/sslvpnclient", "/prx/000/http/localhost/cgi-bin/welcome"],
            "body_keywords": ["sonicwall", "netextender"],
        },
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "vpn_detected": False,
            "vpn_name": None,
            "rdp_exposed": False,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        # Check RDP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            rdp_open = s.connect_ex((domain, 3389)) == 0
            s.close()
            result["rdp_exposed"] = rdp_open
            if rdp_open:
                result["issues"].append("RDP (port 3389) is exposed — directly accessible from internet")
        except Exception:
            pass

        # Probe VPN login pages
        for vpn_name, sigs in self.VPN_SIGNATURES.items():
            for path in sigs["paths"]:
                try:
                    r = requests.get(
                        f"https://{domain}{path}", timeout=5,
                        allow_redirects=True, headers={"User-Agent": USER_AGENT}
                    )
                    body = r.text[:3000].lower()
                    if any(kw in body for kw in sigs["body_keywords"]):
                        result["vpn_detected"] = True
                        result["vpn_name"] = vpn_name
                        break
                except Exception:
                    pass
            if result["vpn_detected"]:
                break

        if not result["vpn_detected"]:
            result["issues"].append("No VPN/remote access gateway detected — remote access method unknown")

        return result


# ---------------------------------------------------------------------------
# 11. DNS & Infrastructure
# ---------------------------------------------------------------------------

class DNSInfrastructureChecker:
    HIGH_RISK_PORTS = {21: "FTP", 23: "Telnet", 3306: "MySQL", 3389: "RDP", 5900: "VNC"}
    MEDIUM_RISK_PORTS = {22: "SSH", 25: "SMTP", 110: "POP3", 143: "IMAP"}
    INFO_PORTS = {80: "HTTP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
    ALL_PORTS = {**HIGH_RISK_PORTS, **MEDIUM_RISK_PORTS, **INFO_PORTS}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "dns_records": {}, "reverse_dns": None,
            "open_ports": [], "server_info": {}, "issues": [], "risk_score": 0,
        }
        try:
            if DNS_AVAILABLE:
                result["dns_records"] = self._get_dns_records(domain)
                result["reverse_dns"] = self._get_reverse_dns(domain)
            result["open_ports"] = self._scan_ports(domain)
            result["server_info"] = self._fingerprint_server(domain)
            result["risk_score"], result["issues"] = self._assess_risk(result["open_ports"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _get_dns_records(self, domain: str) -> dict:
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=DEFAULT_TIMEOUT)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    def _get_reverse_dns(self, domain: str) -> Optional[str]:
        try:
            ip = socket.gethostbyname(domain)
            rev = dns.reversename.from_address(ip)
            answer = dns.resolver.resolve(rev, "PTR", lifetime=DEFAULT_TIMEOUT)
            return str(answer[0])
        except Exception:
            return None

    def _scan_ports(self, domain: str) -> list:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return []

        open_ports = []

        def probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    risk = "high" if port in self.HIGH_RISK_PORTS else "medium" if port in self.MEDIUM_RISK_PORTS else "info"
                    return {"port": port, "service": self.ALL_PORTS.get(port, "Unknown"), "risk": risk}
            except Exception:
                pass
            finally:
                try: s.close()
                except: pass
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(probe, p): p for p in self.ALL_PORTS}
            for f in as_completed(futures, timeout=30):
                try:
                    r = f.result()
                    if r:
                        open_ports.append(r)
                except Exception:
                    pass
        return sorted(open_ports, key=lambda x: x["port"])

    def _fingerprint_server(self, domain: str) -> dict:
        if not REQUESTS_AVAILABLE:
            return {}
        info = {}
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                if h in r.headers:
                    info[h] = r.headers[h]
        except Exception:
            pass
        return info

    def _assess_risk(self, open_ports: list) -> tuple:
        issues, score = [], 0
        for p in open_ports:
            if p["risk"] == "high":
                score += 40; issues.append(f"High-risk port open: {p['port']} ({p['service']})")
            elif p["risk"] == "medium":
                score += 15; issues.append(f"Medium-risk port open: {p['port']} ({p['service']})")
        return min(score, 150), issues


# ---------------------------------------------------------------------------
# 12. High-Risk Protocol & Database Exposure
# ---------------------------------------------------------------------------

class HighRiskProtocolChecker:
    CRITICAL_SERVICES = {
        445: "SMB (file sharing)",
        161: "SNMP",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        5432: "PostgreSQL",
        1433: "MSSQL",
        5984: "CouchDB",
        7001: "Oracle WebLogic",
        8888: "Jupyter Notebook",
        11211: "Memcached",
        2375: "Docker API (unencrypted)",
        2376: "Docker API",
        9092: "Kafka",
        4848: "GlassFish Admin",
        8069: "Odoo ERP",
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed_services": [],
            "critical_count": 0,
            "issues": [],
        }
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return result

        exposed = []

        def probe(port, service):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    return {"port": port, "service": service}
            except Exception:
                pass
            finally:
                try: s.close()
                except: pass
            return None

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(probe, port, svc): port for port, svc in self.CRITICAL_SERVICES.items()}
            for f in as_completed(futures, timeout=30):
                try:
                    r = f.result()
                    if r:
                        exposed.append(r)
                except Exception:
                    pass

        result["exposed_services"] = sorted(exposed, key=lambda x: x["port"])
        result["critical_count"] = len(exposed)

        for e in exposed:
            result["issues"].append(
                f"CRITICAL: {e['service']} (port {e['port']}) exposed to internet — "
                f"database/service should never be publicly accessible"
            )

        return result


# ---------------------------------------------------------------------------
# 13. Security Policy (security.txt + VDP)
# ---------------------------------------------------------------------------

class SecurityPolicyChecker:
    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "security_txt": {"present": False, "path": None, "has_contact": False, "has_pgp": False},
            "robots_txt": {"present": False, "disallows_count": 0},
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        # Check security.txt
        for path in ["/.well-known/security.txt", "/security.txt"]:
            try:
                r = requests.get(f"https://{domain}{path}", timeout=5,
                                 headers={"User-Agent": USER_AGENT})
                if r.status_code == 200 and "Contact:" in r.text:
                    result["security_txt"] = {
                        "present": True, "path": path,
                        "has_contact": "Contact:" in r.text,
                        "has_pgp": "Encryption:" in r.text or "-----BEGIN PGP" in r.text,
                    }
                    break
            except Exception:
                pass

        if not result["security_txt"]["present"]:
            result["issues"].append("No security.txt found — no vulnerability disclosure policy (VDP) detected")

        # Check robots.txt
        try:
            r = requests.get(f"https://{domain}/robots.txt", timeout=5,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                disallows = r.text.lower().count("disallow:")
                result["robots_txt"] = {"present": True, "disallows_count": disallows}
        except Exception:
            pass

        return result


# ---------------------------------------------------------------------------
# 14. DNSBL / IP Reputation
# ---------------------------------------------------------------------------

class DNSBLChecker:
    IP_DNSBLS = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net",
    ]
    DOMAIN_DNSBLS = [
        "dbl.spamhaus.org",
        "uribl.com",
    ]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "ip_listings": [],
            "domain_listings": [],
            "blacklisted": False,
            "issues": [],
        }
        if not DNS_AVAILABLE:
            result["status"] = "error"; return result

        try:
            ip = socket.gethostbyname(domain)
            reversed_ip = ".".join(reversed(ip.split(".")))

            # IP-based checks
            for dnsbl in self.IP_DNSBLS:
                try:
                    dns.resolver.resolve(f"{reversed_ip}.{dnsbl}", "A", lifetime=5)
                    result["ip_listings"].append(dnsbl)
                except Exception:
                    pass

            # Domain-based checks
            for dnsbl in self.DOMAIN_DNSBLS:
                try:
                    dns.resolver.resolve(f"{domain}.{dnsbl}", "A", lifetime=5)
                    result["domain_listings"].append(dnsbl)
                except Exception:
                    pass

            all_listings = result["ip_listings"] + result["domain_listings"]
            result["blacklisted"] = len(all_listings) > 0

            if all_listings:
                result["issues"].append(
                    f"Domain/IP listed on {len(all_listings)} blacklist(s): {', '.join(all_listings)}"
                )

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 15. Technology Stack & EOL/CVE Check
# ---------------------------------------------------------------------------

class TechStackChecker:
    EOL_SIGNATURES = {
        "PHP/5": {"risk": "critical", "note": "PHP 5.x — end-of-life Dec 2018, no security patches"},
        "PHP/7.0": {"risk": "critical", "note": "PHP 7.0 — end-of-life Dec 2019"},
        "PHP/7.1": {"risk": "critical", "note": "PHP 7.1 — end-of-life Dec 2019"},
        "PHP/7.2": {"risk": "high", "note": "PHP 7.2 — end-of-life Nov 2020"},
        "PHP/7.3": {"risk": "high", "note": "PHP 7.3 — end-of-life Dec 2021"},
        "PHP/7.4": {"risk": "medium", "note": "PHP 7.4 — end-of-life Nov 2022"},
        "ASP.NET/1": {"risk": "critical", "note": "ASP.NET 1.x — end-of-life"},
        "ASP.NET/2": {"risk": "critical", "note": "ASP.NET 2.0 — end-of-life Jul 2011"},
        "ASP.NET/3": {"risk": "critical", "note": "ASP.NET 3.x — end-of-life"},
        "Apache/2.2": {"risk": "high", "note": "Apache 2.2 — end-of-life Dec 2017"},
        "nginx/1.14": {"risk": "medium", "note": "nginx 1.14 — legacy stable branch"},
        "nginx/1.12": {"risk": "high", "note": "nginx 1.12 — end-of-life"},
        "nginx/1.10": {"risk": "critical", "note": "nginx 1.10 — end-of-life"},
        "OpenSSL/1.0": {"risk": "critical", "note": "OpenSSL 1.0.x — end-of-life Dec 2019"},
        "OpenSSL/1.1.0": {"risk": "high", "note": "OpenSSL 1.1.0 — end-of-life Sep 2019"},
    }

    CMS_SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
        "Drupal": ["/sites/default/", "Drupal.settings", "/modules/system/"],
        "Wix": ["wixsite.com", "wix-code"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        "Squarespace": ["squarespace.com", "data-squarespace"],
        "Magento": ["Mage.Cookies", "/skin/frontend/", "magento"],
        "PrestaShop": ["prestashop", "/themes/default-bootstrap/"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "server_software": [],
            "cms": {"detected": None, "version": None},
            "eol_detected": [],
            "issues": [],
            "score": 100,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            body = r.text[:100000]
            all_headers_str = str(r.headers)

            # Collect disclosed software versions from headers
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                if h in r.headers:
                    result["server_software"].append(f"{h}: {r.headers[h]}")

            # Check for EOL versions
            combined = (all_headers_str + body).lower()
            for sig, info in self.EOL_SIGNATURES.items():
                if sig.lower() in combined:
                    result["eol_detected"].append({**info, "software": sig})
                    result["issues"].append(f"EOL software detected: {info['note']}")
                    if info["risk"] == "critical":
                        result["score"] -= 40
                    elif info["risk"] == "high":
                        result["score"] -= 25
                    elif info["risk"] == "medium":
                        result["score"] -= 10

            # CMS detection
            for cms, sigs in self.CMS_SIGNATURES.items():
                if any(sig in body or sig in all_headers_str for sig in sigs):
                    version = None
                    if cms == "WordPress":
                        m = re.search(r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)", body)
                        if not m:
                            m = re.search(r'content="WordPress ([\d.]+)"', body)
                        version = m.group(1) if m else None
                    result["cms"] = {"detected": cms, "version": version}
                    break

            result["score"] = max(0, result["score"])

        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 16. Breach / Credential Exposure (HIBP)
# ---------------------------------------------------------------------------

class BreachChecker:
    HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"

    def check(self, domain: str, api_key: Optional[str] = None) -> dict:
        result = {
            "status": "completed", "breach_count": 0, "breaches": [],
            "most_recent_breach": None, "data_classes": [], "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            headers = {"User-Agent": USER_AGENT}
            if api_key:
                headers["hibp-api-key"] = api_key
            r = requests.get(self.HIBP_URL, params={"domain": domain},
                             headers=headers, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 200:
                breaches = r.json()
                if breaches:
                    result["breach_count"] = len(breaches)
                    dates, all_classes = [], set()
                    for b in breaches:
                        dates.append(b.get("BreachDate", ""))
                        all_classes.update(b.get("DataClasses", []))
                        result["breaches"].append({
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "pwn_count": b.get("PwnCount"),
                            "data_classes": b.get("DataClasses", []),
                        })
                    dates = [d for d in dates if d]
                    if dates:
                        result["most_recent_breach"] = max(dates)
                    result["data_classes"] = sorted(all_classes)
                    result["issues"].append(f"Domain found in {len(breaches)} known data breach(es)")
            elif r.status_code == 401:
                result["status"] = "requires_api_key"
                result["error"] = "HIBP API key required"
            elif r.status_code == 404:
                pass
            else:
                result["status"] = "error"
                result["error"] = f"HIBP API returned {r.status_code}"
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 17. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 20),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    def check(self, domain: str) -> dict:
        result = {"status": "completed", "headers": {}, "score": 0, "issues": []}
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            total_weight, earned = 0, 0
            for key, (label, weight) in self.HEADERS.items():
                present = key in headers_lower
                result["headers"][label] = {"present": present, "value": headers_lower.get(key)}
                total_weight += weight
                if present:
                    earned += weight
                else:
                    result["issues"].append(f"Missing security header: {label}")
            result["score"] = round((earned / total_weight) * 100) if total_weight else 0
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 18. Website Security Basics
# ---------------------------------------------------------------------------

class WebsiteSecurityChecker:
    CMS_SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
        "Drupal": ["/sites/default/", "Drupal.settings", "/modules/system/"],
        "Wix": ["wixsite.com", "X-Wix-"],
        "Shopify": ["cdn.shopify.com", "Shopify.theme"],
        "Squarespace": ["squarespace.com", "data-squarespace"],
        "Magento": ["Mage.Cookies", "/skin/frontend/"],
    }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "https_enforced": False,
            "cookies": {"secure": True, "httponly": True, "samesite": True, "details": []},
            "mixed_content": False, "cms": {"detected": None, "version": None},
            "issues": [], "score": 0,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; result["error"] = "requests not installed"; return result
        try:
            result["https_enforced"] = self._check_https_redirect(domain)
            result["cookies"] = self._check_cookies(domain)
            result["mixed_content"] = self._check_mixed_content(domain)
            result["cms"] = self._detect_cms(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["https_enforced"], result["cookies"], result["mixed_content"])
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_https_redirect(self, domain: str) -> bool:
        try:
            r = requests.get(f"http://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return r.url.startswith("https://")
        except Exception:
            return False

    def _check_cookies(self, domain: str) -> dict:
        info = {"secure": True, "httponly": True, "samesite": True, "details": []}
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            for cookie in r.cookies:
                detail = {
                    "name": cookie.name, "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or
                                getattr(cookie, "_rest", {}).get("HttpOnly") is not None,
                    "samesite": cookie.get_nonstandard_attr("SameSite"),
                }
                info["details"].append(detail)
                if not detail["secure"]:
                    info["secure"] = False
                if not detail["httponly"]:
                    info["httponly"] = False
                if not detail["samesite"]:
                    info["samesite"] = False
        except Exception:
            pass
        return info

    def _check_mixed_content(self, domain: str) -> bool:
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            return bool(re.search(r'<(?:script|img|link|iframe)[^>]+src=["\']http://', r.text[:50000], re.I))
        except Exception:
            return False

    def _detect_cms(self, domain: str) -> dict:
        try:
            r = requests.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                             allow_redirects=True, headers={"User-Agent": USER_AGENT})
            combined = r.text[:100000] + str(r.headers)
            for cms, sigs in self.CMS_SIGNATURES.items():
                if any(sig in combined for sig in sigs):
                    version = None
                    if cms == "WordPress":
                        m = re.search(r"ver=([\d.]+)", r.text)
                        version = m.group(1) if m else None
                    return {"detected": cms, "version": version}
        except Exception:
            pass
        return {"detected": None, "version": None}

    def _calculate_score(self, https, cookies, mixed) -> tuple:
        score, issues = 100, []
        if not https:
            score -= 40; issues.append("HTTPS not enforced — HTTP does not redirect to HTTPS")
        if not cookies.get("secure", True):
            score -= 20; issues.append("Cookies missing Secure flag")
        if not cookies.get("httponly", True):
            score -= 15; issues.append("Cookies missing HttpOnly flag — XSS risk")
        if mixed:
            score -= 25; issues.append("Mixed content detected")
        return max(0, score), issues


# ---------------------------------------------------------------------------
# 19. Payment Security
# ---------------------------------------------------------------------------

class PaymentSecurityChecker:
    PAYMENT_PROVIDERS = {
        "Stripe": ["js.stripe.com", "stripe.com/v3"],
        "PayPal": ["paypalobjects.com", "paypal.com/sdk"],
        "PayFast": ["payfast.co.za"],
        "PayGate": ["paygate.co.za"],
        "Peach Payments": ["peachpayments.com"],
        "Ozow": ["ozow.com"],
        "Square": ["squareup.com", "squarecdnjs.net"],
        "Braintree": ["braintreepayments.com", "braintree-api.com"],
        "Adyen": ["adyen.com"],
    }
    PAYMENT_PATHS = ["/cart", "/checkout", "/payment", "/pay", "/order",
                     "/shop/cart", "/basket", "/buy", "/purchase"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "has_payment_page": False,
            "payment_provider": None,
            "self_hosted_payment_form": False,
            "payment_page_https": False,
            "issues": [],
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        payment_page_found = None
        for path in self.PAYMENT_PATHS:
            try:
                r = requests.get(f"https://{domain}{path}", timeout=4,
                                 allow_redirects=True, headers={"User-Agent": USER_AGENT})
                if r.status_code == 200:
                    body = r.text[:50000].lower()
                    # Check if this looks like a payment page
                    payment_keywords = ["credit card", "card number", "checkout", "payment",
                                        "billing", "cvv", "expiry", "pay now", "place order"]
                    if any(kw in body for kw in payment_keywords):
                        payment_page_found = (path, r.url, r.text[:50000])
                        break
            except Exception:
                pass

        if payment_page_found:
            path, final_url, body = payment_page_found
            result["has_payment_page"] = True
            result["payment_page_https"] = final_url.startswith("https://")

            # Check for third-party payment providers
            for provider, scripts in self.PAYMENT_PROVIDERS.items():
                if any(s in body.lower() for s in scripts):
                    result["payment_provider"] = provider
                    break

            # Detect self-hosted card form (high risk)
            if not result["payment_provider"]:
                if re.search(r'<input[^>]+(?:card.?number|cardnumber|cc.?num)', body, re.I):
                    result["self_hosted_payment_form"] = True
                    result["issues"].append(
                        "Self-hosted payment card form detected — PCI DSS compliance risk. "
                        "Card data may be processed directly on your servers."
                    )

            if not result["payment_page_https"]:
                result["issues"].append("Payment page not served over HTTPS — critical security risk")

        return result


# ---------------------------------------------------------------------------
# 20. Shodan InternetDB Vulnerability Checker (free, no API key)
# ---------------------------------------------------------------------------

class ShodanVulnChecker:
    """
    Queries Shodan's free InternetDB for CVEs associated with the domain's IP.
    When SHODAN_API_KEY is provided, uses the full Shodan API for richer data
    (service banners, OS detection, ISP/ASN info) and falls back to InternetDB otherwise.
    Enriches top CVEs with CVSS scores from the NVD API (also free, no key).
    """
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
    SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
    NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _cvss_severity(self, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        return "low"

    def _fetch_cvss(self, cve_id: str) -> dict:
        try:
            r = requests.get(self.NVD_URL, params={"cveId": cve_id},
                             headers={"User-Agent": USER_AGENT}, timeout=8)
            if r.status_code != 200:
                return {}
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            desc = next((d["value"] for d in vuln.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            metrics = vuln.get("metrics", {})
            # Try CVSS v3.1, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key)
                if m:
                    base = m[0].get("cvssData", {})
                    score = base.get("baseScore", 0.0)
                    return {
                        "cve_id": cve_id,
                        "description": desc[:200],
                        "cvss_score": score,
                        "severity": self._cvss_severity(score),
                        "vector": base.get("vectorString", ""),
                    }
            return {"cve_id": cve_id, "description": desc[:200], "cvss_score": 0.0, "severity": "unknown", "vector": ""}
        except Exception:
            return {"cve_id": cve_id, "description": "", "cvss_score": 0.0, "severity": "unknown", "vector": ""}

    def _check_full_api(self, ip: str, api_key: str, result: dict) -> bool:
        """Use Shodan full API. Returns True if successful, False to fall back."""
        try:
            r = requests.get(self.SHODAN_HOST_URL.format(ip=ip),
                             params={"key": api_key},
                             headers={"User-Agent": USER_AGENT}, timeout=15)
            if r.status_code in (401, 403):
                return False  # bad key, fall back to InternetDB
            if r.status_code != 200:
                return False

            data = r.json()
            result["data_source"] = "shodan_full_api"
            result["open_ports"] = data.get("ports", [])
            result["tags"] = data.get("tags", [])
            result["os"] = data.get("os")
            result["isp"] = data.get("isp")
            result["org"] = data.get("org")
            result["asn"] = data.get("asn")
            result["hostnames"] = data.get("hostnames", [])

            # Extract service banners from data['data']
            services = []
            for svc in data.get("data", []):
                services.append({
                    "port": svc.get("port"),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "module": svc.get("_shodan", {}).get("module", ""),
                    "banner_snippet": (svc.get("data", "") or "")[:150],
                })
            result["services"] = services

            # CVEs from full API
            raw_cves = data.get("vulns", [])[:20]
            return self._enrich_cves(raw_cves, result)

        except Exception:
            return False

    def _check_internetdb(self, ip: str, result: dict) -> bool:
        """Use free InternetDB. Returns True if successful."""
        r = requests.get(self.INTERNETDB_URL.format(ip=ip),
                         headers={"User-Agent": USER_AGENT}, timeout=10)
        if r.status_code == 404:
            return True
        if r.status_code != 200:
            result["status"] = "error"
            return False

        data = r.json()
        result["data_source"] = "internetdb"
        result["open_ports"] = data.get("ports", [])
        result["cpe_list"]   = data.get("cpes", [])[:10]
        result["tags"]       = data.get("tags", [])

        raw_cves = data.get("vulns", [])[:20]
        return self._enrich_cves(raw_cves, result)

    def _enrich_cves(self, raw_cves: list, result: dict) -> bool:
        """Enrich CVEs with CVSS data and update result."""
        enriched = []
        for cve_id in raw_cves[:10]:
            info = self._fetch_cvss(cve_id)
            if info:
                enriched.append(info)
                sev = info.get("severity", "unknown")
                if sev == "critical":   result["critical_count"] += 1
                elif sev == "high":     result["high_count"] += 1
                elif sev == "medium":   result["medium_count"] += 1
                else:                   result["low_count"] += 1

        for cve_id in raw_cves[10:]:
            result["medium_count"] += 1

        result["cves"] = enriched
        return True

    def check(self, domain: str, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "data_source": "internetdb",
            "ip": None,
            "open_ports": [],
            "cves": [],
            "cpe_list": [],
            "tags": [],
            "services": [],
            "os": None,
            "isp": None,
            "org": None,
            "asn": None,
            "hostnames": [],
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "score": 100,
            "issues": [],
        }
        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip

            # Try full Shodan API first if key available, fall back to InternetDB
            if api_key:
                if not self._check_full_api(ip, api_key, result):
                    self._check_internetdb(ip, result)
            else:
                self._check_internetdb(ip, result)

            # Build issues
            if result["critical_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {result['critical_count']} critical CVE(s) found on this IP — patch immediately"
                )
            if result["high_count"] > 0:
                result["issues"].append(
                    f"{result['high_count']} high-severity CVE(s) detected — review and patch urgently"
                )
            if result["medium_count"] > 0:
                result["issues"].append(
                    f"{result['medium_count']} medium-severity CVE(s) detected — schedule patching"
                )

            # Score: 100 minus penalty per severity
            penalty = (result["critical_count"] * 30 +
                       result["high_count"] * 15 +
                       result["medium_count"] * 5)
            result["score"] = max(0, 100 - min(100, penalty))

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 21. Dehashed Credential Leak Checker (optional API key)
# ---------------------------------------------------------------------------

class DehashedChecker:
    """
    Queries Dehashed for credential leaks associated with the domain.
    Requires DEHASHED_EMAIL + DEHASHED_API_KEY env vars (paid subscription).
    Falls back gracefully with status='no_api_key' when credentials are absent.
    """
    API_URL = "https://api.dehashed.com/search"

    def check(self, domain: str, email: str = None, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "total_entries": 0,
            "unique_emails": 0,
            "has_passwords": False,
            "sample_emails": [],
            "score": 100,
            "issues": [],
        }

        if not email or not api_key:
            result["status"] = "no_api_key"
            return result

        try:
            r = requests.get(
                self.API_URL,
                params={"query": f"domain:{domain}", "size": 100},
                auth=(email, api_key),
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                timeout=15,
            )

            if r.status_code == 401:
                result["status"] = "auth_failed"
                result["issues"].append("Dehashed authentication failed — check API credentials")
                return result

            if r.status_code == 302 or r.status_code == 403:
                result["status"] = "subscription_required"
                return result

            if r.status_code != 200:
                result["status"] = "error"
                result["error"] = f"HTTP {r.status_code}"
                return result

            data = r.json()
            entries = data.get("entries") or []
            total   = data.get("total", len(entries))

            result["total_entries"] = total

            emails_seen = set()
            has_pw = False
            for entry in entries:
                em = entry.get("email", "")
                if em:
                    emails_seen.add(em)
                if entry.get("password") or entry.get("hashed_password"):
                    has_pw = True

            result["unique_emails"] = len(emails_seen)
            result["has_passwords"] = has_pw
            # Show up to 5 sample emails (truncated for display)
            result["sample_emails"] = [
                e[:40] + ("…" if len(e) > 40 else "") for e in list(emails_seen)[:5]
            ]

            if total > 0:
                result["issues"].append(
                    f"{total} credential record(s) found in Dehashed for this domain — "
                    "notify affected users and enforce password reset"
                )
            if has_pw:
                result["issues"].append(
                    "Plaintext or hashed passwords found in leaked records — "
                    "enforce immediate password reset and review authentication systems"
                )

            penalty = min(100, total * 2)
            result["score"] = max(0, 100 - penalty)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 22. VirusTotal Domain Reputation Checker (optional API key)
# ---------------------------------------------------------------------------

class VirusTotalChecker:
    """
    Queries VirusTotal API v3 for domain reputation, malware/phishing flags,
    and security engine detection counts.
    Requires VIRUSTOTAL_API_KEY env var (free tier: 4 req/min, 500/day).
    """
    API_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

    def check(self, domain: str, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "reputation": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "malicious_votes": 0,
            "harmless_votes": 0,
            "categories": {},
            "popularity_rank": None,
            "flagging_engines": [],
            "score": 100,
            "issues": [],
        }

        if not api_key:
            result["status"] = "no_api_key"
            return result

        try:
            r = requests.get(
                self.API_URL.format(domain=domain),
                headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
                timeout=15,
            )

            if r.status_code == 401:
                result["status"] = "auth_failed"
                result["issues"].append("VirusTotal API key invalid")
                return result
            if r.status_code == 429:
                result["status"] = "rate_limited"
                return result
            if r.status_code != 200:
                result["status"] = "error"
                result["error"] = f"HTTP {r.status_code}"
                return result

            data = r.json().get("data", {}).get("attributes", {})

            # Analysis stats
            stats = data.get("last_analysis_stats", {})
            result["malicious_count"]  = stats.get("malicious", 0)
            result["suspicious_count"] = stats.get("suspicious", 0)
            result["harmless_count"]   = stats.get("harmless", 0)
            result["undetected_count"] = stats.get("undetected", 0)

            # Community reputation & votes
            result["reputation"]      = data.get("reputation", 0)
            votes = data.get("total_votes", {})
            result["malicious_votes"] = votes.get("malicious", 0)
            result["harmless_votes"]  = votes.get("harmless", 0)

            # Categories from security vendors
            result["categories"] = data.get("categories", {})

            # Popularity rank
            ranks = data.get("popularity_ranks", {})
            if ranks:
                top_rank = min((v.get("rank", 999999) for v in ranks.values()), default=None)
                result["popularity_rank"] = top_rank

            # Flagging engines (which engines said malicious/suspicious)
            analysis = data.get("last_analysis_results", {})
            for engine, info in analysis.items():
                cat = info.get("category", "")
                if cat in ("malicious", "suspicious"):
                    result["flagging_engines"].append({
                        "engine": engine,
                        "category": cat,
                        "result": info.get("result", ""),
                    })

            # Build issues
            mal = result["malicious_count"]
            sus = result["suspicious_count"]
            if mal > 0:
                result["issues"].append(
                    f"CRITICAL: {mal} security engine(s) flagged this domain as MALICIOUS"
                )
            if sus > 0:
                result["issues"].append(
                    f"{sus} security engine(s) flagged this domain as suspicious"
                )

            # Check categories for phishing/malware
            bad_cats = [v for v in result["categories"].values()
                        if any(w in v.lower() for w in ("malware", "phishing", "spam", "scam"))]
            if bad_cats:
                result["issues"].append(
                    f"Domain categorized as: {', '.join(bad_cats)}"
                )

            # Score: penalize per detection
            penalty = mal * 10 + sus * 5
            result["score"] = max(0, 100 - min(100, penalty))

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 23. SecurityTrails Domain Intelligence Checker (optional API key)
# ---------------------------------------------------------------------------

class SecurityTrailsChecker:
    """
    Queries SecurityTrails API for current DNS records, associated domains,
    and domain metadata.
    Requires SECURITYTRAILS_API_KEY env var (free tier: 2,500 queries/month).
    """
    BASE_URL     = "https://api.securitytrails.com/v1"
    DOMAIN_URL   = BASE_URL + "/domain/{domain}"
    ASSOC_URL    = BASE_URL + "/domain/{domain}/associated"

    def check(self, domain: str, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "associated_domains": [],
            "associated_count": 0,
            "alexa_rank": None,
            "score": 100,
            "issues": [],
        }

        if not api_key:
            result["status"] = "no_api_key"
            return result

        headers = {"APIKEY": api_key, "Accept": "application/json"}

        try:
            # Domain info
            r = requests.get(
                self.DOMAIN_URL.format(domain=domain),
                headers=headers, timeout=15,
            )
            if r.status_code == 401 or r.status_code == 403:
                result["status"] = "auth_failed"
                result["issues"].append("SecurityTrails API key invalid or quota exceeded")
                return result
            if r.status_code == 429:
                result["status"] = "rate_limited"
                return result
            if r.status_code != 200:
                result["status"] = "error"
                result["error"] = f"HTTP {r.status_code}"
                return result

            data = r.json()

            # Extract DNS records
            current = data.get("current_dns", {})
            a_rec = current.get("a", {})
            if a_rec:
                result["a_records"] = [
                    v.get("ip", "") for v in a_rec.get("values", [])
                ]
            mx_rec = current.get("mx", {})
            if mx_rec:
                result["mx_records"] = [
                    v.get("hostname", "") for v in mx_rec.get("values", [])
                ]
            ns_rec = current.get("ns", {})
            if ns_rec:
                result["ns_records"] = [
                    v.get("nameserver", "") for v in ns_rec.get("values", [])
                ]

            result["alexa_rank"] = data.get("alexa_rank")

            # Associated domains
            try:
                r2 = requests.get(
                    self.ASSOC_URL.format(domain=domain),
                    headers=headers, timeout=15,
                )
                if r2.status_code == 200:
                    assoc_data = r2.json()
                    records = assoc_data.get("records", [])
                    result["associated_count"] = assoc_data.get("record_count", len(records))
                    result["associated_domains"] = [
                        rec.get("hostname", "") for rec in records[:10]
                    ]
            except Exception:
                pass  # non-critical, skip

            # Flag if many associated domains (shared hosting risk)
            if result["associated_count"] > 50:
                result["issues"].append(
                    f"{result['associated_count']} associated domains on shared infrastructure — "
                    "shared hosting increases attack surface"
                )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 24. Fraudulent / Lookalike Domain Detection
# ---------------------------------------------------------------------------

class FraudulentDomainChecker:
    """
    Generates typosquat and lookalike domain permutations, then checks
    which ones actually resolve via DNS. Flags resolved domains as potential
    phishing/brand-abuse risks.
    """

    # Common TLD variants to check
    ALT_TLDS = [
        ".com", ".net", ".org", ".co", ".dev", ".online", ".io", ".info",
        ".biz", ".xyz", ".site", ".app", ".tech", ".store", ".shop",
        ".co.za", ".africa",
    ]

    # Homoglyph map (visually similar characters)
    HOMOGLYPHS = {
        "a": ["4", "@"], "b": ["d", "6"], "c": ["k"],
        "e": ["3"], "g": ["q", "9"], "i": ["1", "l", "!"],
        "l": ["1", "i", "|"], "o": ["0"], "s": ["5", "$"],
        "t": ["7"], "u": ["v"], "v": ["u"], "z": ["2"],
    }

    # Adjacent keyboard keys for fat-finger typos
    KEYBOARD_ADJ = {
        "q": "wa", "w": "qeas", "e": "wrds", "r": "etfs", "t": "ryg",
        "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "ol",
        "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
        "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "iolmj",
        "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv",
        "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    }

    def _split_domain(self, domain: str) -> tuple:
        """Split domain into name and TLD (handles multi-part TLDs like .co.za)."""
        parts = domain.split(".")
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            return ".".join(parts[:-2]), "." + ".".join(parts[-2:])
        return ".".join(parts[:-1]), "." + parts[-1]

    def _generate_permutations(self, name: str, original_tld: str) -> list:
        """Generate domain permutations. Returns list of (domain, technique, similarity%)."""
        perms = []
        seen = set()

        def add(d, tech, sim):
            if d not in seen:
                seen.add(d)
                perms.append((d, tech, sim))

        # 1. Character omission (missing letter)
        for i in range(len(name)):
            variant = name[:i] + name[i+1:]
            if len(variant) >= 2:
                sim = round((len(name) - 1) / len(name) * 100)
                add(variant + original_tld, "char-omission", sim)

        # 2. Adjacent character swap
        for i in range(len(name) - 1):
            variant = name[:i] + name[i+1] + name[i] + name[i+2:]
            sim = round((len(name) - 1) / len(name) * 100)
            add(variant + original_tld, "char-swap", sim)

        # 3. Character duplication
        for i in range(len(name)):
            variant = name[:i] + name[i] * 2 + name[i+1:]
            sim = round(len(name) / (len(name) + 1) * 100)
            add(variant + original_tld, "char-duplicate", sim)

        # 4. Homoglyph substitution
        for i, ch in enumerate(name):
            for repl in self.HOMOGLYPHS.get(ch, []):
                variant = name[:i] + repl + name[i+1:]
                add(variant + original_tld, "homoglyph", 90)

        # 5. Adjacent key substitution (fat finger)
        for i, ch in enumerate(name):
            for adj in self.KEYBOARD_ADJ.get(ch, ""):
                variant = name[:i] + adj + name[i+1:]
                sim = round((len(name) - 1) / len(name) * 100)
                add(variant + original_tld, "keyboard-typo", sim)

        # 6. TLD variants
        for tld in self.ALT_TLDS:
            if tld != original_tld:
                add(name + tld, "tld-variant", 85)

        # 7. Dot insertion (e.g., phi.shield.com)
        for i in range(1, len(name)):
            if name[i-1] != "." and name[i] != ".":
                variant = name[:i] + "." + name[i:]
                add(variant + original_tld, "dot-insertion", 80)

        # 8. Hyphen insertion
        for i in range(1, len(name)):
            variant = name[:i] + "-" + name[i:]
            add(variant + original_tld, "hyphen-insertion", 80)

        return perms

    def _resolves(self, domain: str) -> bool:
        """Check if domain resolves to an IP address."""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "total_permutations": 0,
            "resolved_count": 0,
            "fraudulent_domains": [],
            "score": 100,
            "issues": [],
        }

        try:
            name, tld = self._split_domain(domain)
            permutations = self._generate_permutations(name, tld)
            result["total_permutations"] = len(permutations)

            # Check DNS resolution in parallel (cap at 80 to keep it fast)
            to_check = permutations[:80]
            resolved = []

            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {
                    ex.submit(self._resolves, perm[0]): perm
                    for perm in to_check
                }
                for future in as_completed(futures, timeout=30):
                    perm = futures[future]
                    try:
                        if future.result(timeout=5):
                            resolved.append({
                                "domain": perm[0],
                                "technique": perm[1],
                                "similarity": perm[2],
                            })
                    except Exception:
                        pass

            # Sort by similarity descending
            resolved.sort(key=lambda x: x["similarity"], reverse=True)
            result["resolved_count"] = len(resolved)
            result["fraudulent_domains"] = resolved[:20]  # cap display at 20

            if len(resolved) > 5:
                result["issues"].append(
                    f"CRITICAL: {len(resolved)} lookalike domains detected — "
                    "high brand impersonation and phishing risk"
                )
            elif len(resolved) > 2:
                result["issues"].append(
                    f"{len(resolved)} lookalike domains detected — "
                    "monitor for brand abuse and phishing campaigns"
                )
            elif len(resolved) > 0:
                result["issues"].append(
                    f"{len(resolved)} lookalike domain(s) found — "
                    "review for potential typosquatting"
                )

            # Score: penalize per resolved lookalike
            penalty = min(100, len(resolved) * 8)
            result["score"] = max(0, 100 - penalty)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 25. Privacy Policy Compliance Checker
# ---------------------------------------------------------------------------

class PrivacyComplianceChecker:
    """
    Fetches the domain's privacy policy page and checks for required sections
    that map to POPIA / GDPR / general data protection compliance.
    Fully passive — only reads publicly available pages.
    """

    POLICY_PATHS = [
        "/privacy-policy", "/privacy", "/legal/privacy", "/privacypolicy",
        "/privacy_policy", "/legal/privacy-policy", "/terms/privacy",
        "/data-privacy", "/gdpr", "/popia",
    ]

    # Required sections with keywords to look for
    REQUIRED_SECTIONS = {
        "Data Collection": [
            "collect", "data we collect", "information we collect",
            "how do we collect", "what data", "personal information we gather",
        ],
        "Data Usage": [
            "how we use", "use your data", "use of information",
            "purpose of processing", "why we collect",
        ],
        "Data Sharing": [
            "share your", "third part", "disclose", "transfer",
            "sharing of information", "who we share",
        ],
        "Cookie Policy": [
            "cookie", "tracking technolog", "web beacon", "pixel",
        ],
        "User Rights": [
            "your rights", "right to access", "right to erasure", "right to delete",
            "right to rectif", "data subject", "opt out", "opt-out",
        ],
        "Data Retention": [
            "retention", "how long", "retain your", "storage period",
            "delete your data",
        ],
        "Contact Information": [
            "contact us", "data protection officer", "privacy officer",
            "dpo@", "privacy@", "reach us",
        ],
        "Do Not Track": [
            "do not track", "dnt", "do-not-track",
        ],
        "Children's Privacy": [
            "children", "minor", "under 13", "under 16", "child",
        ],
        "Updates to Policy": [
            "update", "changes to this", "modify this", "revised",
            "amend this policy",
        ],
    }

    def _find_policy_url(self, domain: str) -> tuple:
        """Try common paths to find the privacy policy page."""
        for path in self.POLICY_PATHS:
            for scheme in ("https", "http"):
                url = f"{scheme}://{domain}{path}"
                try:
                    r = requests.get(url, headers={"User-Agent": USER_AGENT},
                                     timeout=8, allow_redirects=True)
                    if r.status_code == 200 and len(r.text) > 500:
                        return url, r.text.lower()
                except Exception:
                    continue

        # Fallback: check homepage for privacy policy link
        try:
            r = requests.get(f"https://{domain}", headers={"User-Agent": USER_AGENT},
                             timeout=8, allow_redirects=True)
            if r.status_code == 200:
                text = r.text.lower()
                # Look for privacy policy link in HTML
                import re as _re
                matches = _re.findall(r'href=["\']([^"\']*privac[^"\']*)["\']', text)
                for href in matches[:3]:
                    if href.startswith("/"):
                        href = f"https://{domain}{href}"
                    elif not href.startswith("http"):
                        href = f"https://{domain}/{href}"
                    try:
                        r2 = requests.get(href, headers={"User-Agent": USER_AGENT},
                                          timeout=8, allow_redirects=True)
                        if r2.status_code == 200 and len(r2.text) > 500:
                            return href, r2.text.lower()
                    except Exception:
                        continue
        except Exception:
            pass

        return None, None

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "policy_url": None,
            "policy_found": False,
            "sections_found": [],
            "sections_missing": [],
            "compliance_pct": 0,
            "score": 0,
            "issues": [],
        }

        try:
            url, content = self._find_policy_url(domain)

            if not content:
                result["policy_found"] = False
                result["sections_missing"] = list(self.REQUIRED_SECTIONS.keys())
                result["issues"].append(
                    "No privacy policy found — POPIA/GDPR compliance risk"
                )
                return result

            result["policy_found"] = True
            result["policy_url"] = url

            # Check each required section
            found = []
            missing = []
            for section, keywords in self.REQUIRED_SECTIONS.items():
                if any(kw in content for kw in keywords):
                    found.append(section)
                else:
                    missing.append(section)

            result["sections_found"] = found
            result["sections_missing"] = missing
            total = len(self.REQUIRED_SECTIONS)
            result["compliance_pct"] = round(len(found) / total * 100) if total else 0

            # Issues for missing critical sections
            critical_missing = [s for s in missing if s in (
                "Data Collection", "Data Usage", "User Rights", "Contact Information"
            )]
            if critical_missing:
                result["issues"].append(
                    f"Privacy policy missing critical sections: {', '.join(critical_missing)}"
                )
            if missing and not critical_missing:
                result["issues"].append(
                    f"Privacy policy missing {len(missing)} recommended section(s): "
                    f"{', '.join(missing[:3])}"
                    + (f" (+{len(missing)-3} more)" if len(missing) > 3 else "")
                )

            # Score based on completeness
            result["score"] = result["compliance_pct"]

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 26. Risk Scoring Engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Weighted 0-1000 risk score.
    All weights must sum to 100 when WAF bonus excluded.
    """
    WEIGHTS = {
        "ssl":                  0.09,
        "email_security":       0.05,
        "email_hardening":      0.03,
        "breaches":             0.07,
        "http_headers":         0.05,
        "website_security":     0.04,
        "exposed_admin":        0.09,
        "high_risk_protocols":  0.08,
        "dnsbl":                0.06,
        "tech_stack":           0.05,
        "payment_security":     0.03,
        "vpn_remote":           0.03,
        "subdomains":           0.03,
        "shodan_vulns":         0.07,
        "dehashed":             0.02,
        "virustotal":           0.05,
        "securitytrails":       0.02,
        "fraudulent_domains":   0.05,
        "privacy_compliance":   0.03,
    }

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

    def calculate(self, results: dict) -> tuple:
        def inv(score_0_100):
            return 100 - score_0_100

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

        # Shodan CVE risk
        shodan = results.get("shodan_vulns", {})
        shodan_risk = inv(shodan.get("score", 100))

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

        weighted = (
            ssl_risk         * self.WEIGHTS["ssl"] +
            email_risk       * self.WEIGHTS["email_security"] +
            email_hard_risk  * self.WEIGHTS["email_hardening"] +
            breach_risk      * self.WEIGHTS["breaches"] +
            header_risk      * self.WEIGHTS["http_headers"] +
            website_risk     * self.WEIGHTS["website_security"] +
            admin_risk       * self.WEIGHTS["exposed_admin"] +
            hrisk            * self.WEIGHTS["high_risk_protocols"] +
            dnsbl_risk       * self.WEIGHTS["dnsbl"] +
            tech_risk        * self.WEIGHTS["tech_stack"] +
            pay_risk         * self.WEIGHTS["payment_security"] +
            vpn_risk         * self.WEIGHTS["vpn_remote"] +
            sub_risk         * self.WEIGHTS["subdomains"] +
            shodan_risk      * self.WEIGHTS["shodan_vulns"] +
            dehashed_risk    * self.WEIGHTS["dehashed"] +
            vt_risk          * self.WEIGHTS["virustotal"] +
            st_risk          * self.WEIGHTS["securitytrails"] +
            fd_risk          * self.WEIGHTS["fraudulent_domains"] +
            pc_risk          * self.WEIGHTS["privacy_compliance"]
        )

        risk_score = round(weighted * 10)

        # WAF bonus — reduce score by up to 50 points
        if results.get("waf", {}).get("detected"):
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

        return risk_score, risk_level, recommendations


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

class SecurityScanner:
    def __init__(self, hibp_api_key: Optional[str] = None,
                 dehashed_email: Optional[str] = None,
                 dehashed_api_key: Optional[str] = None,
                 virustotal_api_key: Optional[str] = None,
                 securitytrails_api_key: Optional[str] = None,
                 shodan_api_key: Optional[str] = None):
        self.hibp_api_key          = hibp_api_key
        self.dehashed_email        = dehashed_email
        self.dehashed_api_key      = dehashed_api_key
        self.virustotal_api_key    = virustotal_api_key
        self.securitytrails_api_key = securitytrails_api_key
        self.shodan_api_key        = shodan_api_key

    def scan(self, domain: str) -> dict:
        domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        results = {
            "domain_scanned": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": 0,
            "risk_level": "Unknown",
            "categories": {},
            "recommendations": [],
        }

        checkers = {
            "ssl":                 (SSLChecker().check,               domain),
            "email_security":      (EmailSecurityChecker().check,      domain),
            "email_hardening":     (EmailHardeningChecker().check,     domain),
            "http_headers":        (HTTPHeaderChecker().check,         domain),
            "waf":                 (WAFChecker().check,                domain),
            "cloud_cdn":           (CloudCDNChecker().check,           domain),
            "domain_intel":        (DomainIntelChecker().check,        domain),
            "subdomains":          (SubdomainChecker().check,          domain),
            "exposed_admin":       (ExposedAdminChecker().check,       domain),
            "vpn_remote":          (VPNRemoteAccessChecker().check,    domain),
            "dns_infrastructure":  (DNSInfrastructureChecker().check,  domain),
            "high_risk_protocols": (HighRiskProtocolChecker().check,   domain),
            "security_policy":     (SecurityPolicyChecker().check,     domain),
            "dnsbl":               (DNSBLChecker().check,              domain),
            "tech_stack":          (TechStackChecker().check,          domain),
            "breaches":            (BreachChecker().check,             domain),
            "website_security":    (WebsiteSecurityChecker().check,    domain),
            "payment_security":    (PaymentSecurityChecker().check,    domain),
            "shodan_vulns":        (ShodanVulnChecker().check,         domain),
            "dehashed":            (DehashedChecker().check,           domain),
            "virustotal":          (VirusTotalChecker().check,         domain),
            "securitytrails":      (SecurityTrailsChecker().check,     domain),
            "fraudulent_domains":  (FraudulentDomainChecker().check,   domain),
            "privacy_compliance":  (PrivacyComplianceChecker().check,  domain),
        }

        cat_results = {}
        with ThreadPoolExecutor(max_workers=14) as ex:
            futures = {}
            for name, (fn, arg) in checkers.items():
                if name == "breaches":
                    futures[ex.submit(fn, arg, self.hibp_api_key)] = name
                elif name == "dehashed":
                    futures[ex.submit(fn, arg, self.dehashed_email, self.dehashed_api_key)] = name
                elif name == "virustotal":
                    futures[ex.submit(fn, arg, self.virustotal_api_key)] = name
                elif name == "securitytrails":
                    futures[ex.submit(fn, arg, self.securitytrails_api_key)] = name
                elif name == "shodan_vulns":
                    futures[ex.submit(fn, arg, self.shodan_api_key)] = name
                else:
                    futures[ex.submit(fn, arg)] = name

            for future in as_completed(futures, timeout=180):
                name = futures[future]
                try:
                    cat_results[name] = future.result(timeout=DEFAULT_TIMEOUT * 2)
                except Exception as e:
                    cat_results[name] = {"status": "error", "error": str(e), "issues": []}

        results["categories"] = cat_results
        scorer = RiskScorer()
        risk_score, risk_level, recommendations = scorer.calculate(cat_results)
        results["overall_risk_score"] = risk_score
        results["risk_level"] = risk_level
        results["recommendations"] = recommendations
        return results


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    scanner = SecurityScanner()
    result = scanner.scan(domain)
    print(json.dumps(result, indent=2, default=str))
