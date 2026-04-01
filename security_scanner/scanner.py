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

try:
    from sslyze import Scanner as SSLyzeScanner, ServerScanRequest, ScanCommand
    from sslyze.server_setting import ServerNetworkLocation
    from sslyze.errors import ServerHostnameCouldNotBeResolved
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False

DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 CyberInsuranceScanner/1.0 (passive assessment)"


# ---------------------------------------------------------------------------
# 1. SSL / TLS Assessment
# ---------------------------------------------------------------------------

class SSLChecker:
    # Weak cipher fragments for detection
    WEAK_CIPHERS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "RC2"]

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "certificate": {}, "tls_versions": {},
            "cipher_suite": {}, "hsts": False, "grade": "F", "score": 0, "issues": [],
            "ocsp_stapling": None, "cert_chain_valid": None, "key_size": None,
            "caa_records": [], "data_source": "stdlib",
        }
        try:
            # Try sslyze first for deep analysis
            if SSLYZE_AVAILABLE:
                try:
                    self._check_with_sslyze(domain, result)
                    result["data_source"] = "sslyze"
                except Exception:
                    self._check_with_stdlib(domain, result)
                    result["data_source"] = "stdlib_fallback"
            else:
                self._check_with_stdlib(domain, result)

            # HSTS + CAA always via separate checks
            result["hsts"] = self._check_hsts(domain)
            result["caa_records"] = self._check_caa(domain)

            # Calculate grade from all collected data
            grade, score, issues = self._calculate_grade(
                result["certificate"], result["tls_versions"],
                result["cipher_suite"], result["hsts"],
                result.get("ocsp_stapling"), result.get("cert_chain_valid"),
                result.get("key_size"), result.get("caa_records", []),
            )
            result["grade"] = grade
            result["score"] = score
            result["issues"] = issues
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
            result["issues"] = [f"SSL check error: {e}"]
        return result

    def _check_with_sslyze(self, domain: str, result: dict):
        """Deep SSL/TLS analysis using sslyze library."""
        location = ServerNetworkLocation(hostname=domain, port=443)
        scan_request = ServerScanRequest(server_location=location, scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        })
        scanner = SSLyzeScanner()
        scanner.queue_scans([scan_request])

        for server_result in scanner.get_results():
            # Certificate info
            try:
                cert_result = server_result.scan_result.certificate_info
                if cert_result and cert_result.result:
                    cert_deployments = cert_result.result.certificate_deployments
                    if cert_deployments:
                        dep = cert_deployments[0]
                        leaf = dep.received_certificate_chain[0]
                        now = datetime.now(timezone.utc)
                        days_left = (leaf.not_valid_after_utc - now).days if hasattr(leaf, 'not_valid_after_utc') else (leaf.not_valid_after - now).days

                        # Key size
                        pub_key = leaf.public_key()
                        key_size = getattr(pub_key, 'key_size', None)

                        result["certificate"] = {
                            "valid": dep.leaf_certificate_subject_matches_hostname,
                            "subject": leaf.subject.rfc4514_string() if leaf.subject else domain,
                            "issuer": leaf.issuer.rfc4514_string() if leaf.issuer else "Unknown",
                            "issuer_cn": str(leaf.issuer) if leaf.issuer else "Unknown",
                            "expiry_date": str(leaf.not_valid_after_utc if hasattr(leaf, 'not_valid_after_utc') else leaf.not_valid_after),
                            "days_until_expiry": days_left,
                            "is_expired": days_left < 0,
                            "expiring_soon": 0 <= days_left <= 30,
                            "san_count": len(leaf.extensions) if leaf.extensions else 0,
                            "chain_length": len(dep.received_certificate_chain),
                            "chain_valid": dep.verified_certificate_chain is not None,
                        }
                        result["cert_chain_valid"] = dep.verified_certificate_chain is not None
                        result["key_size"] = key_size
                        result["ocsp_stapling"] = dep.ocsp_response_is_trusted if hasattr(dep, 'ocsp_response_is_trusted') else dep.ocsp_response is not None
            except Exception:
                pass

            # TLS versions — check which have accepted cipher suites
            tls_map = {
                "TLS 1.0": ScanCommand.TLS_1_0_CIPHER_SUITES,
                "TLS 1.1": ScanCommand.TLS_1_1_CIPHER_SUITES,
                "TLS 1.2": ScanCommand.TLS_1_2_CIPHER_SUITES,
                "TLS 1.3": ScanCommand.TLS_1_3_CIPHER_SUITES,
            }
            versions = {}
            all_accepted = []
            for label, cmd in tls_map.items():
                try:
                    cmd_result = getattr(server_result.scan_result, cmd.value, None)
                    if cmd_result and cmd_result.result:
                        accepted = cmd_result.result.accepted_cipher_suites
                        versions[label] = len(accepted) > 0
                        if accepted:
                            all_accepted.extend([(label, cs.cipher_suite.name) for cs in accepted])
                    else:
                        versions[label] = False
                except Exception:
                    versions[label] = False
            result["tls_versions"] = versions

            # Best cipher suite (from highest TLS version)
            if all_accepted:
                # Prefer TLS 1.3 ciphers, then 1.2
                best = all_accepted[-1]  # last = highest version
                cipher_name = best[1]
                weak = any(w in cipher_name.upper() for w in self.WEAK_CIPHERS)
                result["cipher_suite"] = {
                    "name": cipher_name, "protocol": best[0],
                    "bits": 256 if "256" in cipher_name else (128 if "128" in cipher_name else 0),
                    "is_weak": weak,
                    "total_accepted": len(all_accepted),
                    "weak_count": sum(1 for _, c in all_accepted if any(w in c.upper() for w in self.WEAK_CIPHERS)),
                }
            # Check for SSL 2.0/3.0
            for old_cmd, old_label in [(ScanCommand.SSL_2_0_CIPHER_SUITES, "SSL 2.0"),
                                        (ScanCommand.SSL_3_0_CIPHER_SUITES, "SSL 3.0")]:
                try:
                    old_result = getattr(server_result.scan_result, old_cmd.value, None)
                    if old_result and old_result.result and old_result.result.accepted_cipher_suites:
                        result["tls_versions"][old_label] = True
                except Exception:
                    pass

    def _check_with_stdlib(self, domain: str, result: dict):
        """Fallback SSL check using Python stdlib."""
        result["certificate"] = self._get_certificate_stdlib(domain)
        result["tls_versions"] = self._check_tls_versions_stdlib(domain)
        result["cipher_suite"] = self._get_cipher_suite_stdlib(domain)

    def _get_certificate_stdlib(self, domain: str) -> dict:
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

    def _check_tls_versions_stdlib(self, domain: str) -> dict:
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

    def _get_cipher_suite_stdlib(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=DEFAULT_TIMEOUT) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as s:
                    c = s.cipher()
                    if c:
                        return {"name": c[0], "protocol": c[1], "bits": c[2] or 0,
                                "is_weak": any(w in c[0].upper() for w in self.WEAK_CIPHERS)}
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

    def _check_caa(self, domain: str) -> list:
        """Check CAA DNS records — controls which CAs can issue certs."""
        if not DNS_AVAILABLE:
            return []
        try:
            answers = dns.resolver.resolve(domain, "CAA", lifetime=DEFAULT_TIMEOUT)
            return [str(r) for r in answers]
        except Exception:
            return []

    def _calculate_grade(self, cert, tls, cipher, hsts,
                         ocsp_stapling=None, cert_chain_valid=None,
                         key_size=None, caa_records=None) -> tuple:
        issues, ded = [], 0
        # Certificate validity
        if not cert.get("valid"):
            ded += 40; issues.append("Invalid or unverifiable SSL certificate")
        elif cert.get("is_expired"):
            ded += 40; issues.append("SSL certificate has EXPIRED")
        elif cert.get("expiring_soon"):
            ded += 20; issues.append(f"Certificate expiring in {cert.get('days_until_expiry')} days")
        # Certificate chain
        if cert_chain_valid is False:
            ded += 15; issues.append("Certificate chain incomplete or invalid")
        # Key size
        if key_size is not None:
            if key_size < 2048:
                ded += 20; issues.append(f"Weak key size: {key_size}-bit (minimum 2048-bit recommended)")
            elif key_size < 4096:
                pass  # 2048+ is acceptable
        # TLS versions
        if tls.get("SSL 2.0"):
            ded += 30; issues.append("SSL 2.0 supported — critically insecure")
        if tls.get("SSL 3.0"):
            ded += 25; issues.append("SSL 3.0 supported — vulnerable to POODLE attack")
        if tls.get("TLS 1.0"):
            ded += 20; issues.append("TLS 1.0 supported — deprecated and insecure")
        if tls.get("TLS 1.1"):
            ded += 10; issues.append("TLS 1.1 supported — deprecated")
        if not tls.get("TLS 1.2") and not tls.get("TLS 1.3"):
            ded += 30; issues.append("No modern TLS version (1.2/1.3) detected")
        # Cipher suite
        if cipher.get("is_weak"):
            ded += 20; issues.append(f"Weak cipher: {cipher.get('name', 'Unknown')}")
        weak_count = cipher.get("weak_count", 0)
        if weak_count > 0:
            ded += min(10, weak_count * 2)
            issues.append(f"{weak_count} weak cipher suite(s) accepted")
        # HSTS
        if not hsts:
            ded += 10; issues.append("HSTS header missing")
        # OCSP stapling
        if ocsp_stapling is False:
            ded += 5; issues.append("OCSP stapling not enabled — slower certificate revocation checks")
        # CAA records
        if caa_records is not None and len(caa_records) == 0:
            ded += 3; issues.append("No CAA records — any CA can issue certificates for this domain")

        score = max(0, 100 - ded)
        grade = ("A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70
                 else "C" if score >= 55 else "D" if score >= 40 else "F")
        return grade, score, issues


# ---------------------------------------------------------------------------
# 2. Email Security (DNS-based)
# ---------------------------------------------------------------------------

class EmailSecurityChecker:
    DKIM_SELECTORS = [
        # Google / Gmail
        "google", "google2", "gm1", "gm2",
        # Microsoft / Office 365
        "selector1", "selector2",
        # Generic / common
        "default", "mail", "dkim", "k1", "k2", "smtp", "email",
        # Transactional / marketing ESPs
        "sendgrid", "s1", "s2", "smtpapi",
        "mandrill", "mte1", "mte2",
        "mailchimp", "mc",
        "mailgun", "mg",
        "postmark", "pm",
        "amazonses", "ses", "ug7nbmlcpnkfm3bm5tul7oy2kqoyno3s",
        "everlytickey1", "everlytickey2", "everlytic",
        # Security / enterprise
        "mimecast", "protonmail",
        "zendesk", "zendesk1", "zendesk2",
        # CMS / platforms
        "cm", "turbo-smtp", "sparkpost",
    ]

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
                    has_all = "all" in txt
                    has_redirect = "redirect=" in txt
                    valid = has_all or has_redirect
                    # Count DNS lookups in SPF chain (include, a, mx, redirect, exists)
                    dns_lookups = self._count_spf_lookups(txt, depth=0)
                    return {
                        "present": True, "valid": valid, "record": txt,
                        "dangerous": "+all" in txt,
                        "has_redirect": has_redirect,
                        "dns_lookups": dns_lookups,
                        "exceeds_lookup_limit": dns_lookups > 10,
                    }
        except Exception:
            pass
        return {"present": False, "valid": False, "record": None, "dangerous": False,
                "has_redirect": False, "dns_lookups": 0, "exceeds_lookup_limit": False}

    def _count_spf_lookups(self, spf_record: str, depth: int = 0) -> int:
        """Count DNS lookup mechanisms in SPF chain (max 10 per RFC 7208)."""
        if depth > 5:
            return 0
        count = 0
        includes = re.findall(r"include:(\S+)", spf_record)
        count += len(includes)
        count += len(re.findall(r"\ba\b|\ba:", spf_record))
        count += len(re.findall(r"\bmx\b|\bmx:", spf_record))
        count += len(re.findall(r"exists:", spf_record))
        redirect = re.search(r"redirect=(\S+)", spf_record)
        if redirect:
            count += 1
        # Follow includes to count nested lookups
        for inc_domain in includes[:5]:
            try:
                inc_answers = dns.resolver.resolve(inc_domain.rstrip("."), "TXT", lifetime=3)
                for rd in inc_answers:
                    inc_txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rd.strings)
                    if inc_txt.startswith("v=spf1"):
                        count += self._count_spf_lookups(inc_txt, depth + 1)
                        break
            except Exception:
                pass
        # Follow redirect
        if redirect:
            try:
                red_answers = dns.resolver.resolve(redirect.group(1).rstrip("."), "TXT", lifetime=3)
                for rd in red_answers:
                    red_txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rd.strings)
                    if red_txt.startswith("v=spf1"):
                        count += self._count_spf_lookups(red_txt, depth + 1)
                        break
            except Exception:
                pass
        return count

    def _check_dmarc(self, domain: str) -> dict:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=DMARC1" in txt:
                    match = re.search(r"p=(\w+)", txt)
                    policy = match.group(1) if match else "none"
                    # Parse pct= (percentage enforcement, default 100)
                    pct_match = re.search(r"pct=(\d+)", txt)
                    pct = int(pct_match.group(1)) if pct_match else 100
                    # Parse sp= (subdomain policy, defaults to p= value)
                    sp_match = re.search(r"sp=(\w+)", txt)
                    subdomain_policy = sp_match.group(1) if sp_match else policy
                    # Check for rua= (aggregate reporting)
                    has_reporting = "rua=" in txt
                    return {
                        "present": True, "policy": policy, "record": txt,
                        "pct": pct,
                        "partial_enforcement": pct < 100,
                        "subdomain_policy": subdomain_policy,
                        "has_reporting": has_reporting,
                    }
        except Exception:
            pass
        return {"present": False, "policy": None, "record": None,
                "pct": 0, "partial_enforcement": False,
                "subdomain_policy": None, "has_reporting": False}

    def _check_dkim(self, domain: str) -> dict:
        found = []

        def _probe(selector):
            try:
                dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=3)
                return selector
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = pool.map(_probe, self.DKIM_SELECTORS)
            found = [s for s in results if s is not None]
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
        # SPF scoring
        if not spf["present"]:
            score -= 3; issues.append("No SPF record — spoofing risk")
        elif spf.get("dangerous"):
            score -= 3; issues.append("SPF uses '+all' — allows any server to send on your behalf")
        elif not spf["valid"]:
            score -= 1; issues.append("SPF record may be invalid (no 'all' or 'redirect=' mechanism)")
        if spf.get("exceeds_lookup_limit"):
            score -= 1; issues.append(f"SPF exceeds 10 DNS lookup limit ({spf['dns_lookups']} lookups) — may cause validation failures")
        # DMARC scoring
        if not dmarc["present"]:
            score -= 4; issues.append("No DMARC record — phishing risk")
        elif dmarc["policy"] == "none":
            score -= 2; issues.append("DMARC policy is 'none' — not enforced")
        elif dmarc["policy"] == "quarantine":
            score -= 1; issues.append("DMARC policy is 'quarantine' — consider upgrading to 'reject'")
        if dmarc.get("partial_enforcement"):
            score -= 1; issues.append(f"DMARC pct={dmarc['pct']}% — only partial enforcement, should be 100%")
        if dmarc["present"] and dmarc.get("subdomain_policy") == "none" and dmarc["policy"] != "none":
            issues.append("DMARC subdomain policy (sp=none) is weaker than main domain policy")
        if dmarc["present"] and not dmarc.get("has_reporting"):
            issues.append("DMARC has no rua= reporting — no visibility into authentication failures")
        # DKIM scoring
        if not dkim["selectors_found"]:
            score -= 2; issues.append("No DKIM selectors found across 40 common selector names")
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
    # Common prefixes to brute-force resolve as supplement to CT logs
    BRUTE_PREFIXES = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
        "portal", "dns", "relay", "cdn", "api", "dev", "staging", "beta",
        "admin", "old", "backup", "app", "intranet", "db", "database",
        "jenkins", "gitlab", "jira", "grafana", "kibana", "phpmyadmin",
        "cpanel", "webdisk", "autodiscover", "sip", "lyncdiscover",
        "owa", "exchange", "docs", "sharepoint", "crm", "erp",
    ]

    RISKY_KEYWORDS = [
        "dev", "staging", "test", "admin", "api", "old", "beta",
        "backup", "db", "database", "internal", "vpn", "remote",
        "jenkins", "gitlab", "jira", "grafana", "kibana", "phpmyadmin",
        "cpanel", "owa", "exchange", "ftp", "intranet",
    ]

    @staticmethod
    def _resolves(hostname: str) -> list:
        """Try to resolve a hostname, return list of IPs or empty list."""
        try:
            answers = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return list(set(addr[4][0] for addr in answers))
        except Exception:
            return []

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "subdomains": [],
            "risky_subdomains": [],
            "resolved_ips": {},
            "total_count": 0,
            "ct_count": 0,
            "brute_count": 0,
            "issues": [],
            "score": 100,
        }
        if not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result

        seen = set()
        subdomains = []

        # --- Source 1: Certificate Transparency via crt.sh ---
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=20, headers={"User-Agent": USER_AGENT}
            )
            if r.status_code == 200:
                entries = r.json()
                for entry in entries:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower().lstrip("*.")
                        if name and name != domain and domain in name and name not in seen:
                            seen.add(name)
                            subdomains.append(name)
                result["ct_count"] = len(subdomains)
        except Exception:
            pass  # crt.sh can be slow/unreliable — continue with brute-force

        # --- Source 2: DNS brute-force for common prefixes ---
        brute_candidates = [
            f"{prefix}.{domain}" for prefix in self.BRUTE_PREFIXES
            if f"{prefix}.{domain}" not in seen
        ]
        brute_found = 0
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._resolves, host): host for host in brute_candidates}
            for future in as_completed(futures, timeout=15):
                host = futures[future]
                try:
                    ips = future.result(timeout=3)
                    if ips:
                        seen.add(host)
                        subdomains.append(host)
                        brute_found += 1
                except Exception:
                    pass
        result["brute_count"] = brute_found

        # Cap and store
        subdomains = subdomains[:150]
        result["subdomains"] = subdomains
        result["total_count"] = len(subdomains)

        # --- Resolve all subdomains to IPs (for attack surface mapping) ---
        resolved_ips = {}
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._resolves, sub): sub for sub in subdomains[:80]}
            for future in as_completed(futures, timeout=15):
                sub = futures[future]
                try:
                    ips = future.result(timeout=3)
                    if ips:
                        resolved_ips[sub] = ips
                except Exception:
                    pass
        result["resolved_ips"] = resolved_ips

        # Unique IPs across all subdomains
        all_ips = set()
        for ips in resolved_ips.values():
            all_ips.update(ips)
        result["unique_ips_found"] = len(all_ips)

        # --- Identify risky subdomains ---
        risky = [s for s in subdomains if any(k in s for k in self.RISKY_KEYWORDS)]
        result["risky_subdomains"] = risky

        if risky:
            result["issues"].append(
                f"{len(risky)} risky subdomain(s) found: {', '.join(risky[:5])}"
            )
            result["score"] = max(40, 100 - len(risky) * 5)

        if len(subdomains) > 50:
            result["issues"].append(
                f"Large attack surface: {len(subdomains)} subdomains discovered "
                f"across {len(all_ips)} unique IPs"
            )
            result["score"] = min(result["score"], 60)

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

    # Per-port exploit intelligence for insurance underwriting context
    PORT_INTEL = {
        21: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "Anonymous login, credential brute-force, cleartext credential theft (CVE-2015-3306, CVE-2019-12815)",
            "vuln_metrics": "CVSS 9.8 | EPSS 85% | CISA KEV",
            "notable_cves": ["CVE-2015-3306", "CVE-2019-12815", "CVE-2010-4221"],
            "insurance_risk": "Data exfiltration via unencrypted file transfer; ransomware initial access vector",
        },
        22: {
            "risk_level": "HIGH RISK",
            "typical_exploits": "Brute-force attacks, key-based auth bypass (CVE-2024-6387 regreSSHion, CVE-2023-48795 Terrapin)",
            "vuln_metrics": "CVSS 8.1 | EPSS 35%",
            "notable_cves": ["CVE-2024-6387", "CVE-2023-48795", "CVE-2016-20012"],
            "insurance_risk": "Remote command execution if compromised; privilege escalation",
        },
        23: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "Cleartext credential theft, session hijacking, no encryption",
            "vuln_metrics": "CVSS 9.8 | EPSS 90%",
            "notable_cves": ["CVE-2020-10188", "CVE-2011-4862"],
            "insurance_risk": "Full credential interception; trivially exploitable remote access",
        },
        25: {
            "risk_level": "MEDIUM RISK",
            "typical_exploits": "Open relay abuse, email spoofing, spam distribution",
            "vuln_metrics": "CVSS 5.3 | EPSS 10%",
            "notable_cves": ["CVE-2021-3156", "CVE-2020-28018"],
            "insurance_risk": "Email-based attacks; domain reputation damage if abused as open relay",
        },
        110: {
            "risk_level": "HIGH RISK",
            "typical_exploits": "Cleartext credential theft, brute-force, buffer overflow attacks",
            "vuln_metrics": "CVSS 7.5 | EPSS 15%",
            "notable_cves": ["CVE-2011-1720"],
            "insurance_risk": "Email account takeover via credential interception",
        },
        143: {
            "risk_level": "HIGH RISK",
            "typical_exploits": "Cleartext credential interception, brute-force, injection attacks",
            "vuln_metrics": "CVSS 7.5 | EPSS 12%",
            "notable_cves": ["CVE-2021-33515", "CVE-2019-11500"],
            "insurance_risk": "Email account compromise leading to BEC or data theft",
        },
        3306: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "Authentication bypass (CVE-2012-2122), SQL injection, credential brute-force, data dumping",
            "vuln_metrics": "CVSS 9.8 | EPSS 92% | CISA KEV",
            "notable_cves": ["CVE-2012-2122", "CVE-2016-6662", "CVE-2020-14812"],
            "insurance_risk": "Direct database access enables mass data theft; ransomware encryption of data",
        },
        3389: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "BlueKeep (CVE-2019-0708), credential brute-force, NLA bypass, session hijacking",
            "vuln_metrics": "CVSS 9.8 | EPSS 97% | CISA KEV",
            "notable_cves": ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
            "insurance_risk": "Primary ransomware initial access vector; full system compromise",
        },
        5432: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "Credential brute-force, privilege escalation (CVE-2023-5868), SQL injection chaining",
            "vuln_metrics": "CVSS 8.8 | EPSS 40%",
            "notable_cves": ["CVE-2023-5868", "CVE-2019-9193", "CVE-2023-39417"],
            "insurance_risk": "Direct access to structured business data; credential reuse attacks",
        },
        5900: {
            "risk_level": "CRITICAL RISK",
            "typical_exploits": "Authentication bypass, unencrypted session hijacking, brute-force",
            "vuln_metrics": "CVSS 9.8 | EPSS 60%",
            "notable_cves": ["CVE-2006-2369", "CVE-2019-15681"],
            "insurance_risk": "Full desktop control without encryption; trivial lateral movement",
        },
        8080: {
            "risk_level": "MEDIUM RISK",
            "typical_exploits": "Default admin consoles, proxy abuse, application-level attacks",
            "vuln_metrics": "CVSS 5.0 | EPSS 8%",
            "notable_cves": [],
            "insurance_risk": "Exposed management interface; potential application compromise",
        },
    }

    def check(self, domain: str, ip: str = None) -> dict:
        result = {
            "status": "completed", "dns_records": {}, "reverse_dns": None,
            "open_ports": [], "server_info": {}, "issues": [], "risk_score": 0,
        }
        if ip:
            result["ip"] = ip
        try:
            if DNS_AVAILABLE:
                result["dns_records"] = self._get_dns_records(domain)
                result["reverse_dns"] = self._get_reverse_dns(domain, ip=ip)
            result["open_ports"] = self._scan_ports(domain, ip=ip)
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

    def _get_reverse_dns(self, domain: str, ip: str = None) -> Optional[str]:
        try:
            ip = ip or socket.gethostbyname(domain)
            rev = dns.reversename.from_address(ip)
            answer = dns.resolver.resolve(rev, "PTR", lifetime=DEFAULT_TIMEOUT)
            return str(answer[0])
        except Exception:
            return None

    # Banner probes for service version detection
    BANNER_PROBES = {
        21: b"",             # FTP sends banner on connect
        22: b"",             # SSH sends banner on connect
        25: b"EHLO scanner\r\n",
        80: b"HEAD / HTTP/1.0\r\nHost: {domain}\r\n\r\n",
        110: b"",            # POP3 sends banner on connect
        143: b"",            # IMAP sends banner on connect
        3306: b"",           # MySQL sends greeting on connect
        5432: b"",           # PostgreSQL sends error on raw connect (version in error)
        8080: b"HEAD / HTTP/1.0\r\nHost: {domain}\r\n\r\n",
    }

    def _scan_ports(self, domain: str, ip: str = None) -> list:
        try:
            ip = ip or socket.gethostbyname(domain)
        except Exception:
            return []

        open_ports = []

        def probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    risk = "high" if port in self.HIGH_RISK_PORTS else "medium" if port in self.MEDIUM_RISK_PORTS else "info"
                    entry = {"port": port, "service": self.ALL_PORTS.get(port, "Unknown"), "risk": risk}
                    # Banner grabbing for version detection
                    banner = self._grab_banner(s, port, domain)
                    if banner:
                        entry["banner"] = banner[:200]  # cap at 200 chars
                        version = self._extract_version(banner, port)
                        if version:
                            entry["detected_version"] = version
                    return entry
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

    def _grab_banner(self, sock, port: int, domain: str) -> str:
        """Attempt to grab service banner from an open port."""
        try:
            probe = self.BANNER_PROBES.get(port)
            if probe is None:
                return ""
            if probe:
                sock.sendall(probe.replace(b"{domain}", domain.encode()))
            sock.settimeout(2)
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    def _extract_version(self, banner: str, port: int) -> str:
        """Extract software version string from banner text."""
        if not banner:
            return ""
        # SSH: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
        if port == 22 and "SSH-" in banner:
            m = re.search(r"SSH-[\d.]+-(\S+)", banner)
            return m.group(1) if m else ""
        # FTP: "220 ProFTPD 1.3.8b Server"
        if port == 21:
            m = re.search(r"220[- ](.+?)(?:\r|\n|$)", banner)
            return m.group(1).strip() if m else ""
        # SMTP: "220 mail.example.com ESMTP Postfix"
        if port == 25:
            m = re.search(r"220[- ](.+?)(?:\r|\n|$)", banner)
            return m.group(1).strip() if m else ""
        # POP3: "+OK Dovecot ready."
        if port == 110:
            m = re.search(r"\+OK (.+?)(?:\r|\n|$)", banner)
            return m.group(1).strip() if m else ""
        # IMAP: "* OK [CAPABILITY ...] Dovecot ready."
        if port == 143:
            m = re.search(r"\* OK (.+?)(?:\r|\n|$)", banner)
            return m.group(1).strip() if m else ""
        # MySQL: version in greeting packet (after initial bytes)
        if port == 3306:
            m = re.search(r"([\d]+\.[\d]+\.[\d]+[^\x00]*)", banner)
            return m.group(1).strip() if m else ""
        # HTTP Server header
        if port in (80, 8080):
            m = re.search(r"Server:\s*(.+?)(?:\r|\n|$)", banner, re.IGNORECASE)
            return m.group(1).strip() if m else ""
        return ""

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
            # Enrich port data with exploit intelligence
            intel = self.PORT_INTEL.get(p["port"])
            if intel:
                p["risk_level"] = intel["risk_level"]
                p["typical_exploits"] = intel["typical_exploits"]
                p["vuln_metrics"] = intel["vuln_metrics"]
                p["notable_cves"] = intel["notable_cves"]
                p["insurance_risk"] = intel["insurance_risk"]

            if p["risk"] == "high":
                desc = intel["insurance_risk"] if intel else ""
                score += 40
                issues.append(f"High-risk port open: {p['port']} ({p['service']}) — {desc}" if desc
                              else f"High-risk port open: {p['port']} ({p['service']})")
            elif p["risk"] == "medium":
                desc = intel["insurance_risk"] if intel else ""
                score += 15
                issues.append(f"Medium-risk port open: {p['port']} ({p['service']}) — {desc}" if desc
                              else f"Medium-risk port open: {p['port']} ({p['service']})")
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

    SERVICE_INTEL = {
        445: {"known_exploits": "EternalBlue (CVE-2017-0144), relay attacks, ransomware propagation",
              "vuln_metrics": "CVSS 9.8 | EPSS 97% | CISA KEV",
              "notable_cves": ["CVE-2017-0144", "CVE-2020-0796", "CVE-2017-0145"],
              "insurance_risk": "Primary ransomware lateral movement vector; mass encryption of network shares",
              "underwriting_impact": "Exposed SMB is a critical ransomware indicator"},
        161: {"known_exploits": "Community string brute-force, information disclosure, device enumeration",
              "vuln_metrics": "CVSS 7.5 | EPSS 20%",
              "notable_cves": ["CVE-2017-6736", "CVE-2002-0012"],
              "insurance_risk": "Network device enumeration; configuration extraction",
              "underwriting_impact": "SNMP exposure reveals network architecture to attackers"},
        27017: {"known_exploits": "No-auth default config, data exfiltration, ransom-delete attacks",
                "vuln_metrics": "CVSS 9.8 | EPSS 88%",
                "notable_cves": ["CVE-2015-7882", "CVE-2013-1892"],
                "insurance_risk": "Mass data theft from misconfigured NoSQL database; ransom deletion",
                "underwriting_impact": "Exposed MongoDB frequently targeted by automated ransom bots"},
        6379: {"known_exploits": "No-auth RCE via SLAVEOF, config rewrite, Lua sandbox escape",
               "vuln_metrics": "CVSS 9.8 | EPSS 85%",
               "notable_cves": ["CVE-2022-0543", "CVE-2021-32761"],
               "insurance_risk": "Remote code execution leading to full server compromise",
               "underwriting_impact": "Exposed Redis enables trivial RCE on the host system"},
        9200: {"known_exploits": "No-auth data access, Groovy RCE, cluster takeover",
               "vuln_metrics": "CVSS 9.8 | EPSS 75%",
               "notable_cves": ["CVE-2015-1427", "CVE-2014-3120"],
               "insurance_risk": "Full search index exfiltration; remote code execution",
               "underwriting_impact": "Exposed Elasticsearch enables mass data extraction"},
        5432: {"known_exploits": "Credential brute-force, privilege escalation (CVE-2023-5868), SQL injection chaining",
               "vuln_metrics": "CVSS 8.8 | EPSS 40%",
               "notable_cves": ["CVE-2023-5868", "CVE-2019-9193", "CVE-2023-39417"],
               "insurance_risk": "Direct access to structured business data; credential reuse attacks",
               "underwriting_impact": "Exposed PostgreSQL significantly increases data breach claim probability"},
        1433: {"known_exploits": "Credential brute-force, xp_cmdshell RCE, SQL injection",
               "vuln_metrics": "CVSS 9.8 | EPSS 70%",
               "notable_cves": ["CVE-2020-0618", "CVE-2019-1068"],
               "insurance_risk": "Remote code execution via SQL Server; lateral movement",
               "underwriting_impact": "Exposed MSSQL enables direct command execution on the server"},
        5984: {"known_exploits": "No-auth admin access, data replication hijack",
               "vuln_metrics": "CVSS 9.8 | EPSS 50%",
               "notable_cves": ["CVE-2017-12635", "CVE-2017-12636"],
               "insurance_risk": "Database admin takeover; data manipulation and theft",
               "underwriting_impact": "Exposed CouchDB admin panel accessible without credentials"},
        2375: {"known_exploits": "Unauthenticated container escape, host filesystem mount, crypto-mining",
               "vuln_metrics": "CVSS 9.8 | EPSS 90%",
               "notable_cves": ["CVE-2019-5736"],
               "insurance_risk": "Full host compromise via container escape; crypto-mining and ransomware",
               "underwriting_impact": "Exposed Docker API = full host root access"},
    }

    def check(self, domain: str, ip: str = None) -> dict:
        result = {
            "status": "completed",
            "exposed_services": [],
            "critical_count": 0,
            "issues": [],
        }
        if ip:
            result["ip"] = ip
        try:
            ip = ip or socket.gethostbyname(domain)
        except Exception:
            return result

        exposed = []

        def probe(port, service):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                if s.connect_ex((ip, port)) == 0:
                    svc = {"port": port, "service": service}
                    # Enrich with exploit intelligence
                    intel = self.SERVICE_INTEL.get(port)
                    if intel:
                        svc.update(intel)
                    return svc
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
            desc = e.get("insurance_risk", "database/service should never be publicly accessible")
            result["issues"].append(
                f"CRITICAL: {e['service']} (port {e['port']}) exposed to internet — {desc}"
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

    def check(self, domain: str, ip: str = None) -> dict:
        result = {
            "status": "completed",
            "ip_listings": [],
            "domain_listings": [],
            "blacklisted": False,
            "issues": [],
        }
        if ip:
            result["ip"] = ip
        if not DNS_AVAILABLE:
            result["status"] = "error"; return result

        try:
            ip = ip or socket.gethostbyname(domain)
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
        # Node.js EOL
        "Node.js/12": {"risk": "critical", "note": "Node.js 12.x — end-of-life Apr 2022"},
        "Node.js/14": {"risk": "high", "note": "Node.js 14.x — end-of-life Apr 2023"},
        "Node.js/16": {"risk": "medium", "note": "Node.js 16.x — end-of-life Sep 2023"},
        "node/12": {"risk": "critical", "note": "Node.js 12.x — end-of-life Apr 2022"},
        "node/14": {"risk": "high", "note": "Node.js 14.x — end-of-life Apr 2023"},
        "node/16": {"risk": "medium", "note": "Node.js 16.x — end-of-life Sep 2023"},
        # Python 2
        "Python/2": {"risk": "critical", "note": "Python 2.x — end-of-life Jan 2020"},
        # IIS EOL
        "Microsoft-IIS/6": {"risk": "critical", "note": "IIS 6.0 — end-of-life Jul 2015"},
        "Microsoft-IIS/7.0": {"risk": "critical", "note": "IIS 7.0 — end-of-life Jan 2020"},
        "Microsoft-IIS/7.5": {"risk": "high", "note": "IIS 7.5 — end-of-life Jan 2020"},
        # Tomcat EOL
        "Apache-Coyote/1": {"risk": "critical", "note": "Tomcat/Coyote 1.x — end-of-life"},
        "Tomcat/7": {"risk": "critical", "note": "Apache Tomcat 7.x — end-of-life"},
        "Tomcat/8.0": {"risk": "high", "note": "Apache Tomcat 8.0 — end-of-life Jun 2018"},
        "Tomcat/8.5": {"risk": "medium", "note": "Apache Tomcat 8.5 — end-of-life Mar 2024"},
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
            for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
                       "X-Runtime", "X-Drupal-Cache", "X-Varnish", "X-CF-Powered-By"]:
                if h in r.headers:
                    result["server_software"].append(f"{h}: {r.headers[h]}")

            # Flag technology disclosure as info leak
            if "X-Powered-By" in r.headers:
                result["issues"].append(
                    f"X-Powered-By header discloses technology: {r.headers['X-Powered-By']} — information leak"
                )
                result["score"] -= 5

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
                    elif cms == "Joomla":
                        m = re.search(r'<meta\s+name="generator"\s+content="Joomla!\s*([\d.]+)"', body, re.I)
                        if not m:
                            m = re.search(r'content="Joomla!\s*([\d.]+)"', body, re.I)
                        version = m.group(1) if m else None
                    elif cms == "Drupal":
                        m = re.search(r'<meta\s+name="generator"\s+content="Drupal\s*([\d.]+)"', body, re.I)
                        if not m:
                            m = re.search(r'content="Drupal\s*([\d.]+)"', body, re.I)
                        if not m:
                            try:
                                cl = requests.get(f"https://{domain}/CHANGELOG.txt", timeout=5,
                                                  headers={"User-Agent": USER_AGENT})
                                if cl.status_code == 200:
                                    cm = re.search(r'Drupal\s+([\d.]+)', cl.text[:500])
                                    if cm:
                                        version = cm.group(1)
                            except Exception:
                                pass
                        else:
                            version = m.group(1)
                    result["cms"] = {"detected": cms, "version": version}
                    break

            # JavaScript library detection
            js_libs = []
            jquery_m = re.search(r'jquery[.-]?([\d.]+)(?:\.min)?\.js', body, re.I)
            if not jquery_m:
                jquery_m = re.search(r'/\*!\s*jQuery\s+v([\d.]+)', body)
            if not jquery_m:
                jquery_m = re.search(r'jquery\.min\.js\?v(?:er)?=([\d.]+)', body, re.I)
            if jquery_m:
                jq_ver = jquery_m.group(1)
                js_libs.append({"library": "jQuery", "version": jq_ver})
                try:
                    parts = [int(x) for x in jq_ver.split(".")[:3]]
                    if parts[0] < 3 or (parts[0] == 3 and len(parts) > 1 and parts[1] < 5):
                        result["issues"].append(
                            f"jQuery {jq_ver} — versions below 3.5.0 have XSS vulnerabilities (CVE-2020-11022)"
                        )
                        result["score"] -= 15
                except (ValueError, IndexError):
                    pass

            angular_m = re.search(r'angular[.-]?([\d.]+)(?:\.min)?\.js', body, re.I)
            if angular_m:
                js_libs.append({"library": "AngularJS", "version": angular_m.group(1)})
                result["issues"].append(f"AngularJS {angular_m.group(1)} — AngularJS is end-of-life (Dec 2021)")
                result["score"] -= 10

            result["js_libraries"] = js_libs

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
    Enriches top CVEs with CVSS scores from the NVD API (also free, no key),
    CISA KEV (Known Exploited Vulnerabilities) status, EPSS from FIRST.org, and EPSS scores.
    """
    INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
    SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
    NVD_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json"
    EPSS_URL       = "https://api.first.org/data/v1/epss"

    MSF_MODULES_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
    EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    # Module-level caches (24h TTL)
    _kev_cache = None
    _kev_cache_time = 0
    _msf_cache = None
    _msf_cache_time = 0
    _exploitdb_cache = None
    _exploitdb_cache_time = 0

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

    def _load_kev(self) -> set:
        """Load CISA KEV catalog, cached for 24 hours."""
        now = time.time()
        if ShodanVulnChecker._kev_cache is not None and (now - ShodanVulnChecker._kev_cache_time) < 86400:
            return ShodanVulnChecker._kev_cache
        try:
            r = requests.get(self.KEV_URL, timeout=15,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                data = r.json()
                kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                ShodanVulnChecker._kev_cache = kev_set
                ShodanVulnChecker._kev_cache_time = now
                return kev_set
        except Exception:
            pass
        return set()

    def _load_msf_modules(self) -> set:
        """Load Metasploit module CVE list, cached for 24 hours."""
        now = time.time()
        if ShodanVulnChecker._msf_cache is not None and (now - ShodanVulnChecker._msf_cache_time) < 86400:
            return ShodanVulnChecker._msf_cache
        try:
            r = requests.get(self.MSF_MODULES_URL, timeout=25,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                data = r.json()
                cve_set = set()
                cve_pat = re.compile(r'(CVE-\d{4}-\d+)', re.I)
                for mod_info in data.values():
                    for ref in mod_info.get("references", []):
                        m = cve_pat.match(ref)
                        if m:
                            cve_set.add(m.group(1).upper())
                ShodanVulnChecker._msf_cache = cve_set
                ShodanVulnChecker._msf_cache_time = now
                return cve_set
        except Exception:
            pass
        return ShodanVulnChecker._msf_cache or set()

    def _load_exploitdb_cves(self) -> set:
        """Load ExploitDB CVE list from CSV, cached for 24 hours."""
        now = time.time()
        if ShodanVulnChecker._exploitdb_cache is not None and (now - ShodanVulnChecker._exploitdb_cache_time) < 86400:
            return ShodanVulnChecker._exploitdb_cache
        try:
            import csv, io
            r = requests.get(self.EXPLOITDB_CSV_URL, timeout=25,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                cve_set = set()
                cve_pat = re.compile(r'(CVE-\d{4}-\d+)', re.I)
                reader = csv.reader(io.StringIO(r.text))
                header = next(reader, None)
                codes_idx = None
                if header:
                    for i, col in enumerate(header):
                        if 'codes' in col.lower():
                            codes_idx = i
                            break
                if codes_idx is not None:
                    for row in reader:
                        if len(row) > codes_idx:
                            for m in cve_pat.finditer(row[codes_idx]):
                                cve_set.add(m.group(1).upper())
                ShodanVulnChecker._exploitdb_cache = cve_set
                ShodanVulnChecker._exploitdb_cache_time = now
                return cve_set
        except Exception:
            pass
        return ShodanVulnChecker._exploitdb_cache or set()

    def _fetch_epss(self, cve_ids: list) -> dict:
        """Batch-fetch EPSS scores for up to 30 CVEs."""
        if not cve_ids:
            return {}
        try:
            r = requests.get(self.EPSS_URL,
                             params={"cve": ",".join(cve_ids[:30])},
                             headers={"User-Agent": USER_AGENT}, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return {
                    item["cve"]: {
                        "epss_score": float(item.get("epss", 0)),
                        "epss_percentile": float(item.get("percentile", 0)),
                    }
                    for item in data.get("data", [])
                }
        except Exception:
            pass
        return {}

    def _enrich_cves(self, raw_cves: list, result: dict) -> bool:
        """Enrich CVEs with CVSS, KEV, EPSS, and exploit maturity data."""
        # Load enrichment data sources
        kev_set = self._load_kev()
        msf_set = self._load_msf_modules()
        edb_set = self._load_exploitdb_cves()
        epss_data = self._fetch_epss(raw_cves[:10])

        enriched = []
        kev_count = 0
        high_epss_count = 0
        weaponized_count = 0
        poc_count = 0
        for cve_id in raw_cves[:10]:
            info = self._fetch_cvss(cve_id)
            if info:
                # Add KEV status
                info["in_kev"] = cve_id in kev_set
                if info["in_kev"]:
                    kev_count += 1
                # Add EPSS score
                epss = epss_data.get(cve_id, {})
                info["epss_score"] = epss.get("epss_score", 0.0)
                info["epss_percentile"] = epss.get("epss_percentile", 0.0)
                if info["epss_score"] > 0.5:
                    high_epss_count += 1

                # Exploit maturity classification
                in_msf = cve_id.upper() in msf_set
                in_edb = cve_id.upper() in edb_set
                info["in_msf"] = in_msf
                info["in_exploitdb"] = in_edb
                if info["in_kev"] or in_msf:
                    info["exploit_maturity"] = "weaponized"
                    weaponized_count += 1
                elif in_edb or info["epss_score"] > 0.5:
                    info["exploit_maturity"] = "poc_public"
                    poc_count += 1
                else:
                    info["exploit_maturity"] = "theoretical"

                enriched.append(info)
                sev = info.get("severity", "unknown")
                if sev == "critical":   result["critical_count"] += 1
                elif sev == "high":     result["high_count"] += 1
                elif sev == "medium":   result["medium_count"] += 1
                else:                   result["low_count"] += 1

        for cve_id in raw_cves[10:]:
            result["medium_count"] += 1

        result["cves"] = enriched
        result["kev_count"] = kev_count
        result["high_epss_count"] = high_epss_count
        result["weaponized_count"] = weaponized_count
        result["poc_public_count"] = poc_count

        if kev_count > 0:
            result["issues"].append(
                f"{kev_count} CVE(s) in CISA Known Exploited Vulnerabilities catalog — actively exploited in the wild"
            )
        if high_epss_count > 0:
            result["issues"].append(
                f"{high_epss_count} CVE(s) with high EPSS score (>0.5) — high probability of exploitation"
            )
        if weaponized_count > 0:
            result["issues"].append(
                f"{weaponized_count} CVE(s) have weaponized exploits (CISA KEV / Metasploit) — immediate patching required"
            )

        return True

    def check(self, domain: str, api_key: str = None, ip: str = None) -> dict:
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
            ip = ip or socket.gethostbyname(domain)
            result["ip"] = ip

            # Always query InternetDB first for CPE list (feeds OSV.dev pipeline)
            self._check_internetdb(ip, result)
            internetdb_cpes = list(result.get("cpe_list", []))

            # Layer on full Shodan API data if key available (org, ASN, banners)
            if api_key:
                api_ok = self._check_full_api(ip, api_key, result)
                # Preserve InternetDB CPEs — full API doesn't return them
                if api_ok and not result.get("cpe_list"):
                    result["cpe_list"] = internetdb_cpes

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
# 20b. OSV.dev Version-to-CVE Mapper
# ---------------------------------------------------------------------------

class OSVChecker:
    """
    Queries the free OSV.dev API to find known vulnerabilities for detected
    software versions (from Shodan CPE list and banner grabbing).
    No API key required.
    """
    OSV_API_URL = "https://api.osv.dev/v1/query"
    # Map common CPE vendor/product to OSV package queries
    # Primary: Debian package names (most common server OS)
    # Fallback: no-ecosystem query (broader match)
    CPE_TO_OSV = {
        ("apache", "http_server"):       [("Debian:12", "apache2"), (None, "apache")],
        ("nginx", "nginx"):              [("Debian:12", "nginx"), (None, "nginx")],
        ("openssl", "openssl"):          [("Debian:12", "openssl"), (None, "openssl")],
        ("openbsd", "openssh"):          [("Debian:12", "openssh"), (None, "openssh")],
        ("mariadb", "mariadb"):          [(None, "mariadb"), ("Debian:12", "mariadb-10.0")],
        ("mysql", "mysql"):              [(None, "mysql"), ("Debian:12", "mysql-8.0")],
        ("postgresql", "postgresql"):    [("Debian:12", "postgresql-15"), (None, "postgresql")],
        ("php", "php"):                  [("Debian:12", "php8.2"), (None, "php")],
        ("microsoft", "iis"):            [],  # No OSV ecosystem
        ("nodejs", "node.js"):           [("Debian:12", "nodejs"), (None, "node")],
        ("jquery", "jquery"):            [("npm", "jquery")],
        ("angularjs", "angular.js"):     [("npm", "angular")],
    }

    def query_cpe_list(self, cpe_list: list) -> list:
        """Query OSV.dev for each CPE in the list. Returns list of vuln dicts."""
        if not REQUESTS_AVAILABLE or not cpe_list:
            return []
        results = []
        seen_ids = set()
        for cpe in cpe_list[:10]:  # Cap at 10 to avoid rate limits
            try:
                vulns = self._query_single_cpe(cpe)
                for v in vulns:
                    vid = v.get("id", "")
                    if vid and vid not in seen_ids:
                        seen_ids.add(vid)
                        results.append(v)
            except Exception:
                continue
        return results[:50]  # Cap total results

    def query_version(self, package: str, version: str, ecosystem: str = None) -> list:
        """Query OSV.dev for a specific package version."""
        if not REQUESTS_AVAILABLE or not package or not version:
            return []
        try:
            payload = {"version": version, "package": {"name": package}}
            if ecosystem:
                payload["package"]["ecosystem"] = ecosystem
            resp = requests.post(self.OSV_API_URL, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_vulns(data.get("vulns", []))
        except Exception:
            pass
        return []

    def _query_single_cpe(self, cpe: str) -> list:
        """Parse CPE string and query OSV.dev with multiple mapping attempts."""
        # CPE format: cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:version
        parts = cpe.replace("cpe:/a:", "").replace("cpe:2.3:a:", "").split(":")
        if len(parts) < 2:
            return []
        vendor = parts[0].lower()
        product = parts[1].split(":")[0].lower()
        version = parts[2] if len(parts) > 2 else ""
        # Clean version: remove URL-encoded chars and distro suffixes
        version = re.sub(r'%[0-9a-fA-F]{2}', '', version).split("-")[0].split("+")[0]
        # Extract major.minor.patch only
        ver_match = re.match(r'(\d+\.\d+(?:\.\d+)?)', version)
        version = ver_match.group(1) if ver_match else version
        if not version or version == "*":
            return []

        # Try each mapping in order until we get results
        mappings = self.CPE_TO_OSV.get((vendor, product), [])
        for ecosystem, pkg_name in mappings:
            results = self.query_version(pkg_name, version, ecosystem)
            if results:
                # Tag each result with the source package for per-IP matching
                for r in results:
                    r["package"] = product
                    r["vendor"] = vendor
                    r["detected_version"] = version
                return results
        # Fallback: try querying by product name with no ecosystem
        results = self.query_version(product, version)
        for r in results:
            r["package"] = product
            r["vendor"] = vendor
            r["detected_version"] = version
        return results

    def _query_by_cpe_string(self, cpe: str, version: str) -> list:
        """Query OSV.dev using raw CPE approach — search by package name."""
        try:
            # Extract product name for a general query
            parts = cpe.replace("cpe:/a:", "").replace("cpe:2.3:a:", "").split(":")
            if len(parts) >= 2:
                product = parts[1].lower()
                payload = {"version": version, "package": {"name": product, "ecosystem": "OSS-Fuzz"}}
                resp = requests.post(self.OSV_API_URL, json=payload, timeout=10)
                if resp.status_code == 200:
                    return self._parse_vulns(resp.json().get("vulns", []))
        except Exception:
            pass
        return []

    def _parse_vulns(self, vulns: list) -> list:
        """Parse OSV vulnerability entries into simplified dicts."""
        results = []
        for v in vulns[:20]:  # Cap per-package
            severity = "medium"  # default
            cvss_score = None
            cve_id = None
            # Extract CVE alias
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            # Extract CVSS from severity
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        # Numeric score directly
                        cvss_score = float(score_str) if score_str.replace(".", "").isdigit() else None
                    except (ValueError, TypeError):
                        pass
                    # Parse CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")
                    if cvss_score is None and score_str.startswith("CVSS:"):
                        # Use a simple heuristic based on vector components
                        # AV:N = network, AC:L = low complexity, etc.
                        av = "N" if "AV:N" in score_str else ("A" if "AV:A" in score_str else "L")
                        ac = "L" if "AC:L" in score_str else "H"
                        pr = "N" if "PR:N" in score_str else ("L" if "PR:L" in score_str else "H")
                        ui = "N" if "UI:N" in score_str else "R"
                        ci = score_str.count(":H")  # Count High impacts
                        # Approximate score based on attack surface
                        base = 5.0
                        if av == "N": base += 1.5
                        if ac == "L": base += 1.0
                        if pr == "N": base += 1.0
                        elif pr == "L": base += 0.5
                        if ui == "N": base += 0.5
                        base += ci * 0.5
                        cvss_score = min(10.0, round(base, 1))
            # Determine severity from CVSS or database_specific
            db_sev = v.get("database_specific", {}).get("severity")
            if cvss_score:
                severity = ("critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0
                           else "medium" if cvss_score >= 4.0 else "low")
            elif db_sev:
                severity = db_sev.lower()

            # Filter out very old advisories (pre-2015) — likely false positives
            published = v.get("published", "")
            if published and published[:4].isdigit() and int(published[:4]) < 2015:
                continue

            results.append({
                "id": v.get("id", ""),
                "cve": cve_id,
                "summary": (v.get("summary") or v.get("details", ""))[:200],
                "severity": severity,
                "cvss_score": cvss_score,
                "epss": None,  # populated during merge if available
                "published": published,
                "source": "osv.dev",
            })
        return results


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

            # Check DNS resolution in parallel (cap at 60 to keep memory low on free tier)
            to_check = permutations[:60]
            resolved = []

            with ThreadPoolExecutor(max_workers=10) as ex:
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
        "/privacy-statement", "/privacy-notice", "/data-protection",
        "/privacystatement", "/privacynotice",
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
        """Find privacy policy page. Crawls homepage first (1 request),
        then falls back to common paths if no link found."""
        import re as _re

        # --- Strategy 1: Crawl homepage for privacy links (fastest) ---
        try:
            r = requests.get(f"https://{domain}", headers={"User-Agent": USER_AGENT},
                             timeout=10, allow_redirects=True)
            if r.status_code == 200:
                text = r.text.lower()
                # Match links by URL containing privacy keywords
                matches = _re.findall(
                    r'href=["\']([^"\']*(?:privac|popia|data.protect|gdpr)[^"\']*)["\']', text)
                # Also match links where anchor text mentions privacy
                anchor_matches = _re.findall(
                    r'href=["\']([^"\']+)["\'][^>]*>(?:[^<]*(?:privac|popia|data.protect)[^<]*)</a>',
                    text)
                # Filter out non-HTML resources (CSS, JS, images, fonts, etc.)
                skip_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico')
                all_matches = []
                for m in list(dict.fromkeys(matches + anchor_matches)):
                    url_path = m.split("?")[0].lower()
                    if not url_path.endswith(skip_exts):
                        all_matches.append(m)
                for href in all_matches[:5]:
                    if href.startswith("/"):
                        href = f"https://{domain}{href}"
                    elif not href.startswith("http"):
                        href = f"https://{domain}/{href}"
                    try:
                        r2 = requests.get(href, headers={"User-Agent": USER_AGENT},
                                          timeout=10, allow_redirects=True)
                        if r2.status_code == 200 and len(r2.text) > 500:
                            return href, r2.text.lower()
                    except Exception:
                        continue
        except Exception:
            pass

        # --- Strategy 2: Try common paths (fallback) ---
        for path in self.POLICY_PATHS:
            url = f"https://{domain}{path}"
            try:
                r = requests.get(url, headers={"User-Agent": USER_AGENT},
                                 timeout=8, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 500:
                    return url, r.text.lower()
            except Exception:
                continue

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
# 26. Web Ranking (Tranco)
# ---------------------------------------------------------------------------

class WebRankingChecker:
    """
    Checks domain popularity using the Tranco top-1M list.
    More popular = more visible target but also more likely to have security resources.
    """
    TRANCO_URL = "https://tranco-list.eu/download/X5QNN/1000000"

    _cache = None
    _cache_time = 0

    def _load_tranco(self):
        now = time.time()
        if WebRankingChecker._cache and (now - WebRankingChecker._cache_time) < 86400:
            return WebRankingChecker._cache
        try:
            r = requests.get(self.TRANCO_URL, timeout=30)
            if r.status_code == 200:
                ranks = {}
                for line in r.text.strip().split("\n"):
                    parts = line.strip().split(",")
                    if len(parts) == 2:
                        ranks[parts[1].lower()] = int(parts[0])
                WebRankingChecker._cache = ranks
                WebRankingChecker._cache_time = now
                return ranks
        except Exception:
            pass
        return {}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "rank": None, "in_list": False,
            "score": 30, "issues": [],
        }
        try:
            ranks = self._load_tranco()
            if not ranks:
                result["status"] = "error"
                result["error"] = "Could not load Tranco list"
                return result

            rank = ranks.get(domain.lower())
            if rank:
                result["rank"] = rank
                result["in_list"] = True
                if rank <= 1000:
                    result["score"] = 100
                elif rank <= 10000:
                    result["score"] = 90
                elif rank <= 100000:
                    result["score"] = 70
                else:
                    result["score"] = 50
            else:
                result["score"] = 30
                result["issues"].append(
                    "Domain not found in Tranco top-1M list — low visibility but also unranked"
                )
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result


# ---------------------------------------------------------------------------
# 27. Information Disclosure
# ---------------------------------------------------------------------------

class InformationDisclosureChecker:
    """
    Probes for common sensitive files and debug endpoints
    that should not be publicly accessible.
    """
    CRITICAL_PATHS = [
        ("/.env", "Environment variables / secrets"),
        ("/.git/HEAD", "Git repository metadata"),
        ("/.git/config", "Git configuration with potential credentials"),
        ("/wp-config.php.bak", "WordPress config backup"),
        ("/.htpasswd", "Apache password file"),
        ("/backup.sql", "Database backup"),
        ("/dump.sql", "Database dump"),
        ("/db.sql", "Database export"),
    ]
    MEDIUM_PATHS = [
        ("/phpinfo.php", "PHP info page"),
        ("/server-status", "Apache server status"),
        ("/server-info", "Apache server info"),
        ("/elmah.axd", ".NET error log"),
        ("/.DS_Store", "macOS directory metadata"),
        ("/web.config", "IIS/ASP.NET config"),
        ("/debug", "Debug endpoint"),
        ("/actuator", "Spring Boot actuator"),
        ("/actuator/env", "Spring Boot environment"),
        ("/.well-known/openid-configuration", "OpenID config"),
    ]

    def _probe(self, url: str) -> tuple:
        try:
            r = requests.get(url, timeout=6, allow_redirects=False,
                             headers={"User-Agent": USER_AGENT})
            if r.status_code == 200 and len(r.text) > 10:
                # Verify it's not a custom 404 page
                if "not found" not in r.text.lower()[:200] and "404" not in r.text[:50]:
                    return True, r.status_code, len(r.text)
            return False, r.status_code, 0
        except Exception:
            return False, 0, 0

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "exposed_paths": [],
            "score": 100, "issues": [],
        }
        try:
            base = f"https://{domain}"
            exposed = []

            # Check critical paths
            for path, desc in self.CRITICAL_PATHS:
                found, status, size = self._probe(f"{base}{path}")
                if found:
                    exposed.append({
                        "path": path, "description": desc,
                        "risk_level": "critical", "size": size,
                    })
                    result["score"] = max(0, result["score"] - 20)
                    result["issues"].append(
                        f"CRITICAL: Sensitive file exposed: {path} — {desc}"
                    )

            # Check medium paths
            for path, desc in self.MEDIUM_PATHS:
                found, status, size = self._probe(f"{base}{path}")
                if found:
                    exposed.append({
                        "path": path, "description": desc,
                        "risk_level": "medium", "size": size,
                    })
                    result["score"] = max(0, result["score"] - 10)
                    result["issues"].append(
                        f"Information disclosure: {path} accessible — {desc}"
                    )

            # Check directory listing on root
            try:
                r = requests.get(f"{base}/", timeout=6,
                                 headers={"User-Agent": USER_AGENT})
                if "Index of /" in r.text or "<title>Index of" in r.text:
                    exposed.append({
                        "path": "/", "description": "Directory listing enabled",
                        "risk_level": "medium", "size": 0,
                    })
                    result["score"] = max(0, result["score"] - 15)
                    result["issues"].append(
                        "Directory listing is enabled on the web root"
                    )
            except Exception:
                pass

            result["exposed_paths"] = exposed

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result


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
        "S19a — Encryption in Transit": {
            "description": "Secure data transmission using strong encryption (TLS 1.2+)",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "S19b — Security Headers": {
            "description": "HTTP security headers to prevent XSS, clickjacking, MIME attacks",
            "checkers": ["http_headers"],
            "weight": 1.0,
        },
        "S19c — Web Application Security": {
            "description": "Secure web application configuration and WAF protection",
            "checkers": ["website_security", "waf"],
            "weight": 1.0,
        },
        "S19d — Network Access Control": {
            "description": "Restrict remote access and close high-risk network services",
            "checkers": ["vpn_remote", "high_risk_protocols"],
            "weight": 1.2,
        },
        "S19e — Email Security": {
            "description": "SPF, DMARC, DKIM to prevent phishing and impersonation",
            "checkers": ["email_security", "email_hardening"],
            "weight": 0.8,
        },
        "S20a — Privacy Policy": {
            "description": "Published privacy policy covering all required POPIA sections",
            "checkers": ["privacy_compliance"],
            "weight": 1.0,
        },
        "S20b — Data Minimisation": {
            "description": "Limit data collection and avoid unnecessary information exposure",
            "checkers": ["info_disclosure", "exposed_admin"],
            "weight": 0.8,
        },
        "S21a — Software Currency": {
            "description": "Keep software and frameworks up to date, no end-of-life components",
            "checkers": ["tech_stack"],
            "weight": 1.0,
        },
        "S22a — Breach History": {
            "description": "Historical data breach exposure and notification readiness",
            "checkers": ["breaches"],
            "weight": 1.0,
        },
        "S22b — Credential Exposure": {
            "description": "Leaked credentials in public breach databases",
            "checkers": ["dehashed"],
            "weight": 1.0,
        },
    },
    "PCI DSS v4.0": {
        "Req 2a — Default Credentials": {
            "description": "Remove default accounts, change vendor defaults before deployment",
            "checkers": ["exposed_admin"],
            "weight": 1.2,
        },
        "Req 2b — System Hardening": {
            "description": "Harden system configurations and disable unnecessary services",
            "checkers": ["http_headers", "info_disclosure"],
            "weight": 1.0,
        },
        "Req 2c — Security Policies": {
            "description": "Documented security policies and procedures",
            "checkers": ["security_policy"],
            "weight": 0.8,
        },
        "Req 4a — TLS Configuration": {
            "description": "Strong TLS encryption for cardholder data transmission",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "Req 4b — HTTPS Enforcement": {
            "description": "Enforce HTTPS across all endpoints handling sensitive data",
            "checkers": ["website_security"],
            "weight": 1.0,
        },
        "Req 6a — Patch Management": {
            "description": "Keep systems patched and free of known vulnerabilities",
            "checkers": ["tech_stack", "shodan_vulns"],
            "weight": 1.2,
        },
        "Req 6b — Secure Coding": {
            "description": "Develop applications securely and protect against common attacks",
            "checkers": ["website_security", "http_headers"],
            "weight": 1.0,
        },
        "Req 8a — Payment Security": {
            "description": "Secure payment processing and PCI-compliant payment forms",
            "checkers": ["payment_security"],
            "weight": 1.2,
        },
        "Req 11a — Vulnerability Scanning": {
            "description": "Regular vulnerability scanning of external-facing systems",
            "checkers": ["shodan_vulns"],
            "weight": 1.0,
        },
        "Req 11b — Threat Monitoring": {
            "description": "Monitor for malicious activity and reputation threats",
            "checkers": ["virustotal", "dnsbl"],
            "weight": 0.8,
        },
    },
    "ISO 27001": {
        "A.8a — Asset Inventory": {
            "description": "Identify and document all information assets and infrastructure",
            "checkers": ["tech_stack", "external_ips"],
            "weight": 1.0,
        },
        "A.8b — Attack Surface": {
            "description": "Map and manage the external attack surface including subdomains",
            "checkers": ["subdomains"],
            "weight": 0.8,
        },
        "A.12a — Network Security": {
            "description": "Secure network services and close unnecessary ports",
            "checkers": ["high_risk_protocols", "dns_infrastructure"],
            "weight": 1.2,
        },
        "A.12b — Remote Access": {
            "description": "Secure remote access methods, restrict RDP and insecure protocols",
            "checkers": ["vpn_remote"],
            "weight": 1.0,
        },
        "A.12c — Malware & Reputation": {
            "description": "Monitor for malware, blocklisting, and reputation issues",
            "checkers": ["dnsbl", "virustotal"],
            "weight": 1.0,
        },
        "A.12d — DDoS Resilience": {
            "description": "Web application firewall and DDoS protection mechanisms",
            "checkers": ["waf", "cloud_cdn"],
            "weight": 0.8,
        },
        "A.14a — Encryption Standards": {
            "description": "Strong encryption for data in transit and at rest",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "A.14b — Application Security": {
            "description": "Secure application development and deployment practices",
            "checkers": ["http_headers", "website_security"],
            "weight": 1.0,
        },
        "A.14c — Payment & Data Handling": {
            "description": "Secure handling of payment data and sensitive information",
            "checkers": ["payment_security", "info_disclosure"],
            "weight": 1.0,
        },
    },
    "NIST CSF 2.0": {
        "GV.1 — Security Policy": {
            "description": "Documented cybersecurity policies and governance framework",
            "checkers": ["security_policy"],
            "weight": 0.8,
        },
        "GV.2 — Privacy Governance": {
            "description": "Privacy policy and data protection compliance programme",
            "checkers": ["privacy_compliance"],
            "weight": 0.8,
        },
        "ID.1 — Asset Discovery": {
            "description": "Identify and inventory organisational IT assets",
            "checkers": ["tech_stack", "external_ips"],
            "weight": 1.0,
        },
        "ID.2 — Attack Surface Mapping": {
            "description": "Discover subdomains, exposed services, and shadow IT",
            "checkers": ["subdomains", "info_disclosure"],
            "weight": 0.8,
        },
        "PR.1 — Encryption & TLS": {
            "description": "Protect data in transit with strong encryption",
            "checkers": ["ssl"],
            "weight": 1.2,
        },
        "PR.2 — Security Headers & Hardening": {
            "description": "HTTP security headers and web application hardening",
            "checkers": ["http_headers", "website_security"],
            "weight": 1.0,
        },
        "PR.3 — Perimeter Defence": {
            "description": "WAF, firewall, and network perimeter protection",
            "checkers": ["waf", "high_risk_protocols", "vpn_remote"],
            "weight": 1.2,
        },
        "PR.4 — Email Authentication": {
            "description": "SPF, DMARC, DKIM to prevent email-based attacks",
            "checkers": ["email_security", "email_hardening"],
            "weight": 0.8,
        },
        "DE.1 — Vulnerability Detection": {
            "description": "Detect known vulnerabilities across external infrastructure",
            "checkers": ["shodan_vulns"],
            "weight": 1.2,
        },
        "DE.2 — Threat Intelligence": {
            "description": "Monitor for malicious activity, blocklisting, and fraud",
            "checkers": ["virustotal", "dnsbl", "exposed_admin"],
            "weight": 1.0,
        },
        "RS.1 — Breach Response": {
            "description": "Historical breach exposure and incident response readiness",
            "checkers": ["breaches", "dehashed"],
            "weight": 1.0,
        },
        "RS.2 — Security Disclosure": {
            "description": "Published security contact and vulnerability disclosure policy",
            "checkers": ["security_policy"],
            "weight": 0.6,
        },
        "RC.1 — Infrastructure Resilience": {
            "description": "DNS redundancy, CDN, and infrastructure recovery capability",
            "checkers": ["dns_infrastructure", "cloud_cdn"],
            "weight": 0.8,
        },
        "RC.2 — Communication Recovery": {
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
            ssl_risk         * self.WEIGHTS.get("ssl", 0) +
            email_risk       * self.WEIGHTS.get("email_security", 0) +
            email_hard_risk  * self.WEIGHTS.get("email_hardening", 0) +
            breach_risk      * self.WEIGHTS.get("breaches", 0) +
            header_risk      * self.WEIGHTS.get("http_headers", 0) +
            website_risk     * self.WEIGHTS.get("website_security", 0) +
            admin_risk       * self.WEIGHTS.get("exposed_admin", 0) +
            hrisk            * self.WEIGHTS.get("high_risk_protocols", 0) +
            dnsbl_risk       * self.WEIGHTS.get("dnsbl", 0) +
            tech_risk        * self.WEIGHTS.get("tech_stack", 0) +
            pay_risk         * self.WEIGHTS.get("payment_security", 0) +
            vpn_risk         * self.WEIGHTS.get("vpn_remote", 0) +
            sub_risk         * self.WEIGHTS.get("subdomains", 0) +
            shodan_risk      * self.WEIGHTS.get("shodan_vulns", 0) +
            dehashed_risk    * self.WEIGHTS.get("dehashed", 0) +
            vt_risk          * self.WEIGHTS.get("virustotal", 0) +
            st_risk          * self.WEIGHTS.get("securitytrails", 0) +
            fd_risk          * self.WEIGHTS.get("fraudulent_domains", 0) +
            pc_risk          * self.WEIGHTS.get("privacy_compliance", 0) +
            wr_risk          * self.WEIGHTS.get("web_ranking", 0) +
            id_risk          * self.WEIGHTS.get("info_disclosure", 0) +
            ext_ip_risk      * self.WEIGHTS.get("external_ips", 0) +
            rsi_risk         * self.WEIGHTS.get("ransomware_risk", 0) +
            dbi_risk         * self.WEIGHTS.get("data_breach_index", 0) +
            fin_risk         * self.WEIGHTS.get("financial_impact", 0)
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
        ("vpn_remote", lambda c: c.get("rdp_exposed"), "Block RDP (port 3389) from public internet — use VPN/ZTNA instead", "R9,000–R36,000", 0.35),
        ("high_risk_protocols", lambda c: any(s.get("port") in (27017, 6379, 9200, 5432, 1433) for s in c.get("exposed_services", [])),
         "Firewall exposed database ports (MongoDB, Redis, PostgreSQL, etc.)", "R9,000–R36,000", 0.15),
        ("shodan_vulns", lambda c: c.get("kev_count", 0) > 0,
         "Patch CISA KEV vulnerabilities — actively exploited in the wild", "R18,000–R90,000", 0.10),
        ("shodan_vulns", lambda c: c.get("high_epss_count", 0) > 0,
         "Patch high-EPSS CVEs (>50% exploitation probability)", "R18,000–R90,000", 0.05),
        ("email_security", lambda c: not c.get("dmarc", {}).get("present"),
         "Implement DMARC with 'quarantine' or 'reject' policy", "R3,600–R9,000", 0.05),
        ("waf", lambda c: not c.get("detected"),
         "Deploy a Web Application Firewall (Cloudflare, AWS WAF, etc.)", "R0–R9,000/mo", 0.05),
        ("ssl", lambda c: c.get("grade", "A") in ("D", "E", "F"),
         "Upgrade SSL/TLS configuration — enable TLS 1.2+, strong ciphers", "R0–R3,600", 0.05),
        ("info_disclosure", lambda c: any(p.get("risk_level") == "critical" for p in c.get("exposed_paths", [])),
         "Remove exposed sensitive files (.env, .git, backups) from web root", "R0–R9,000", 0.03),
        ("exposed_admin", lambda c: c.get("critical_count", 0) > 0,
         "Restrict admin panel access — IP whitelist or VPN-only", "R3,600–R18,000", 0.02),
        ("dnsbl", lambda c: c.get("blacklisted"),
         "Investigate and resolve IP/domain blacklisting", "R9,000–R36,000", 0.05),
        ("dehashed", lambda c: c.get("total_entries", 0) > 100,
         "Force password reset for leaked credentials and enable MFA", "R9,000–R36,000", 0.05),
        ("breaches", lambda c: c.get("breach_count", 0) > 0,
         "Implement breach response plan and credential monitoring", "R18,000–R90,000", 0.02),
        ("fraudulent_domains", lambda c: c.get("lookalike_count", 0) > 5,
         "Register key lookalike domains defensively and set up monitoring", "R9,000–R36,000", 0.01),
        ("privacy_compliance", lambda c: c.get("score", 100) < 50,
         "Update privacy policy to cover all POPIA/GDPR required sections", "R9,000–R36,000", 0.01),
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


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

class SecurityScanner:
    # Checkers that should be run once per discovered IP
    IP_LEVEL_CHECKERS = ("dns_infrastructure", "high_risk_protocols", "dnsbl", "shodan_vulns")

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

    def discover_ips(self, domain: str) -> list:
        """Resolve all A record IPs for a domain."""
        ips = []
        if DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(domain, "A", lifetime=DEFAULT_TIMEOUT)
                ips = list({str(rdata) for rdata in answers})
            except Exception:
                pass
        if not ips:
            try:
                ips = [socket.gethostbyname(domain)]
            except Exception:
                pass
        return ips

    def _notify(self, on_progress, checker_name, status, result=None):
        if on_progress:
            try:
                event = {"checker": checker_name, "status": status}
                if status == "done" and result:
                    event["score"] = result.get("score") or result.get("grade") or result.get("compliance_pct")
                    if "ips" in result:
                        event["ips"] = result["ips"]
                    if "ip_sources" in result:
                        event["ip_sources"] = result["ip_sources"]
                on_progress(event)
            except Exception:
                pass

    def _aggregate_ip_results(self, per_ip: dict, checker_name: str) -> dict:
        """Merge per-IP results for a checker into a single aggregate (richest data)."""
        all_results = [per_ip[ip].get(checker_name, {}) for ip in per_ip if checker_name in per_ip.get(ip, {})]
        if not all_results:
            return {"status": "completed", "issues": []}
        if len(all_results) == 1:
            agg = dict(all_results[0])
            agg["per_ip"] = per_ip
            return agg
        # Pick the result with the most findings (ports, CVEs, issues, services)
        # Score 0 means "no data" not "high risk", so min(score) picks empty results
        def richness(r):
            return (len(r.get("open_ports", [])) +
                    len(r.get("cves", [])) +
                    len(r.get("exposed_services", [])) +
                    len(r.get("issues", [])) +
                    len(r.get("ip_listings", [])) +
                    len(r.get("domain_listings", [])))
        best = max(all_results, key=richness)
        agg = dict(best)
        # Merge issues from all IPs
        all_issues = []
        for r in all_results:
            for issue in r.get("issues", []):
                if issue not in all_issues:
                    all_issues.append(issue)
        agg["issues"] = all_issues
        # Merge open_ports from all IPs (dedup by port number)
        if checker_name == "dns_infrastructure":
            seen_ports = set()
            merged_ports = []
            for r in all_results:
                for p in r.get("open_ports", []):
                    if p.get("port") not in seen_ports:
                        seen_ports.add(p.get("port"))
                        merged_ports.append(p)
            merged_ports.sort(key=lambda p: p.get("port", 0))
            agg["open_ports"] = merged_ports
        agg["per_ip"] = per_ip
        return agg

    def scan(self, domain: str, on_progress: callable = None,
             industry: str = "other", annual_revenue: float = 0,
             annual_revenue_zar: int = 0,
             country: str = "",
             include_fraudulent_domains: bool = False,
             client_ips: list = None) -> dict:
        domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        results = {
            "domain_scanned": domain,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": 0,
            "risk_level": "Unknown",
            "discovered_ips": [],
            "scan_context": {
                "industry": industry,
                "annual_revenue": annual_revenue,
                "country": country,
            },
            "categories": {},
            "recommendations": [],
            "insurance": {},
        }

        # --- Phase 1: IP Discovery + Client IP Merge ---
        self._notify(on_progress, "ip_discovery", "running")
        discovered_ips = self.discover_ips(domain)

        # Source tracking: record where each IP was found
        ip_sources = {ip: ["dns"] for ip in discovered_ips}

        # Merge client-supplied IPs (dedup against discovered)
        client_ips = client_ips or []
        for ip in client_ips:
            ip_sources.setdefault(ip, []).append("client-supplied")
            if ip not in discovered_ips:
                discovered_ips.append(ip)

        results["discovered_ips"] = discovered_ips
        results["ip_sources"] = ip_sources
        results["client_ips_added"] = len([ip for ip in client_ips if "dns" not in ip_sources.get(ip, [])])
        self._notify(on_progress, "ip_discovery", "done", {
            "ips": discovered_ips,
            "ip_sources": ip_sources,
        })

        # --- Phase 2: Domain-level checkers ---
        # Split into lightweight (concurrent) and heavyweight (sequential) to
        # stay within Render free-tier 512 MB RAM limit.
        domain_checkers = {
            "email_security":      (EmailSecurityChecker().check,      [domain]),
            "email_hardening":     (EmailHardeningChecker().check,     [domain]),
            "http_headers":        (HTTPHeaderChecker().check,         [domain]),
            "waf":                 (WAFChecker().check,                [domain]),
            "cloud_cdn":           (CloudCDNChecker().check,           [domain]),
            "domain_intel":        (DomainIntelChecker().check,        [domain]),
            "exposed_admin":       (ExposedAdminChecker().check,       [domain]),
            "vpn_remote":          (VPNRemoteAccessChecker().check,    [domain]),
            "security_policy":     (SecurityPolicyChecker().check,     [domain]),
            "tech_stack":          (TechStackChecker().check,          [domain]),
            "breaches":            (BreachChecker().check,             [domain, self.hibp_api_key]),
            "website_security":    (WebsiteSecurityChecker().check,    [domain]),
            "payment_security":    (PaymentSecurityChecker().check,    [domain]),
            "dehashed":            (DehashedChecker().check,           [domain, self.dehashed_email, self.dehashed_api_key]),
            "virustotal":          (VirusTotalChecker().check,         [domain, self.virustotal_api_key]),
            "securitytrails":      (SecurityTrailsChecker().check,     [domain, self.securitytrails_api_key]),
            "privacy_compliance":  (PrivacyComplianceChecker().check,  [domain]),
            "web_ranking":         (WebRankingChecker().check,         [domain]),
            "info_disclosure":     (InformationDisclosureChecker().check, [domain]),
        }

        # Heavy checkers run sequentially AFTER the concurrent batch to cap
        # peak memory (sslyze spawns subprocesses, CT logs parse large JSON,
        # subdomains resolve many IPs).
        heavy_checkers = [
            ("ssl",         SSLChecker().check,              [domain]),
            ("subdomains",  SubdomainChecker().check,        [domain]),
        ]
        if include_fraudulent_domains:
            heavy_checkers.append(
                ("fraudulent_domains", FraudulentDomainChecker().check, [domain])
            )

        # --- Phase 3: IP-level checkers (per-IP) ---
        ip_checkers_templates = {
            "dns_infrastructure":  DNSInfrastructureChecker().check,
            "high_risk_protocols": HighRiskProtocolChecker().check,
            "dnsbl":               DNSBLChecker().check,
            "shodan_vulns":        ShodanVulnChecker().check,
        }

        cat_results = {}
        per_ip_results = {}  # {ip: {checker_name: result}}

        # --- Run lightweight domain-level checkers concurrently ---
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}
            for name, (fn, args) in domain_checkers.items():
                self._notify(on_progress, name, "running")
                futures[ex.submit(fn, *args)] = name

            try:
                for future in as_completed(futures, timeout=180):
                    label = futures[future]
                    try:
                        cat_results[label] = future.result(timeout=DEFAULT_TIMEOUT * 2)
                    except Exception as e:
                        cat_results[label] = {"status": "error", "error": str(e), "issues": []}
                    self._notify(on_progress, label, "done", cat_results[label])
            except TimeoutError:
                # Gracefully handle checkers that didn't finish in time
                for fut, name in futures.items():
                    if name not in cat_results:
                        fut.cancel()
                        cat_results[name] = {"status": "timeout", "error": "Checker timed out after 180s", "issues": []}
                        self._notify(on_progress, name, "done", cat_results[name])

        # --- Run heavyweight checkers sequentially (memory-safe) ---
        for name, fn, args in heavy_checkers:
            self._notify(on_progress, name, "running")
            try:
                cat_results[name] = fn(*args)
            except Exception as e:
                cat_results[name] = {"status": "error", "error": str(e), "issues": []}
            self._notify(on_progress, name, "done", cat_results[name])

        # --- Expand IP pool with subdomain-resolved IPs ---
        sub_result = cat_results.get("subdomains", {})
        subdomain_ips = set()
        for ip_list in sub_result.get("resolved_ips", {}).values():
            if isinstance(ip_list, list):
                subdomain_ips.update(ip_list)
            elif isinstance(ip_list, str):
                subdomain_ips.add(ip_list)
        new_ips = [ip for ip in subdomain_ips if ip not in discovered_ips]
        all_ips = discovered_ips + new_ips
        for ip in new_ips:
            ip_sources.setdefault(ip, []).append("subdomain")
        if new_ips:
            results["discovered_ips"] = all_ips
            results["ip_sources"] = ip_sources
            results["subdomain_ips_added"] = len(new_ips)
            self._notify(on_progress, "subdomain_ips", "done", {
                "ips": new_ips,
            })

        # --- Run IP-level checkers on ALL discovered IPs ---
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {}
            for ip in all_ips:
                per_ip_results[ip] = {}
                for checker_name, fn in ip_checkers_templates.items():
                    label = f"{checker_name}:{ip}"
                    self._notify(on_progress, label, "running")
                    if checker_name == "shodan_vulns":
                        futures[ex.submit(fn, domain, self.shodan_api_key, ip)] = label
                    else:
                        futures[ex.submit(fn, domain, ip)] = label

            try:
                for future in as_completed(futures, timeout=180):
                    label = futures[future]
                    try:
                        result = future.result(timeout=DEFAULT_TIMEOUT * 2)
                    except Exception as e:
                        result = {"status": "error", "error": str(e), "issues": []}
                    checker_name, ip = label.split(":", 1)
                    per_ip_results[ip][checker_name] = result
                    self._notify(on_progress, label, "done", result)
            except TimeoutError:
                for fut, lbl in futures.items():
                    checker_name, ip = lbl.split(":", 1)
                    if checker_name not in per_ip_results.get(ip, {}):
                        fut.cancel()
                        per_ip_results.setdefault(ip, {})[checker_name] = {
                            "status": "timeout", "error": "Checker timed out", "issues": []}
                        self._notify(on_progress, lbl, "done", per_ip_results[ip][checker_name])

        # --- Phase 4: Aggregate IP-level results ---
        results["categories"] = cat_results
        results["categories"]["per_ip"] = per_ip_results
        for checker_name in self.IP_LEVEL_CHECKERS:
            results["categories"][checker_name] = self._aggregate_ip_results(
                per_ip_results, checker_name
            )

        # --- Phase 4b: External IP Aggregation (feeds CVE panel) ---
        self._notify(on_progress, "external_ips", "running")
        results["categories"]["external_ips"] = ExternalIPAggregator.aggregate(
            all_ips, per_ip_results, ip_sources=ip_sources
        )
        self._notify(on_progress, "external_ips", "done",
                     results["categories"]["external_ips"])

        # --- Phase 4c: OSV.dev version-to-CVE enrichment ---
        self._notify(on_progress, "osv_enrichment", "running")
        try:
            osv = OSVChecker()
            # Collect CPEs from ALL per-IP Shodan results (not just aggregated)
            all_cpes = set()
            ip_cpe_map = {}  # {ip: [cpe_list]} for per-IP merging
            for ip, checkers in per_ip_results.items():
                shodan_r = checkers.get("shodan_vulns", {})
                ip_cpes = shodan_r.get("cpe_list", [])
                if ip_cpes:
                    all_cpes.update(ip_cpes)
                    ip_cpe_map[ip] = ip_cpes
            # Also check aggregated result as fallback
            agg_shodan = cat_results.get("shodan_vulns", {})
            all_cpes.update(agg_shodan.get("cpe_list", []))

            osv_vulns = osv.query_cpe_list(list(all_cpes)) if all_cpes else []
            if osv_vulns:
                results["categories"]["osv_vulns"] = {
                    "status": "completed",
                    "source": "osv.dev",
                    "total_vulns": len(osv_vulns),
                    "vulns": osv_vulns,
                    "critical_count": sum(1 for v in osv_vulns if v.get("severity") == "critical"),
                    "high_count": sum(1 for v in osv_vulns if v.get("severity") == "high"),
                    "issues": [],
                }
                crit = results["categories"]["osv_vulns"]["critical_count"]
                high = results["categories"]["osv_vulns"]["high_count"]
                if crit > 0:
                    results["categories"]["osv_vulns"]["issues"].append(
                        f"{crit} critical vulnerability(ies) found via version analysis (OSV.dev)")
                if high > 0:
                    results["categories"]["osv_vulns"]["issues"].append(
                        f"{high} high-severity vulnerability(ies) found via version analysis (OSV.dev)")

                # --- Merge OSV CVEs back into per-IP cards ---
                for ip, cpes in ip_cpe_map.items():
                    # Find OSV vulns that match this IP's CPEs
                    ip_osv_cves = []
                    for vuln in osv_vulns:
                        pkg = (vuln.get("package", "") or "").lower()
                        for cpe in cpes:
                            cpe_lower = cpe.lower()
                            # Match by package name in CPE string
                            if pkg and pkg in cpe_lower:
                                ip_osv_cves.append(vuln)
                                break
                    if ip_osv_cves:
                        # Merge into per-IP Shodan result
                        shodan_r = per_ip_results[ip].get("shodan_vulns", {})
                        existing_cve_ids = {c.get("cve_id") for c in shodan_r.get("cves", [])}
                        for ov in ip_osv_cves:
                            # Prefer CVE alias over Debian ID for display
                            cve_id = ov.get("cve") or ov.get("id", "")
                            if cve_id and cve_id not in existing_cve_ids:
                                cvss = ov.get("cvss_score") or 0
                                sev = ov.get("severity", "unknown")
                                # If no CVSS, estimate from severity
                                if not cvss and sev != "unknown":
                                    cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}.get(sev, 0)
                                shodan_r.setdefault("cves", []).append({
                                    "cve_id": cve_id,
                                    "cvss_score": cvss,
                                    "severity": sev,
                                    "epss_score": ov.get("epss") or 0,
                                    "description": ov.get("summary", "")[:200],
                                    "source": "osv.dev",
                                    "package": ov.get("package", ""),
                                    "detected_version": ov.get("detected_version", ""),
                                    "in_kev": False,
                                })
                                existing_cve_ids.add(cve_id)
                        # Update counts
                        all_cves = shodan_r.get("cves", [])
                        shodan_r["total_cves"] = len(all_cves)
                        shodan_r["critical_count"] = sum(1 for c in all_cves if c.get("severity") == "critical")
                        shodan_r["high_count"] = sum(1 for c in all_cves if c.get("severity") == "high")
                        shodan_r["medium_count"] = sum(1 for c in all_cves if c.get("severity") == "medium")
                        shodan_r["low_count"] = sum(1 for c in all_cves if c.get("severity") == "low")
                        max_cvss = max((c.get("cvss_score", 0) for c in all_cves), default=0)
                        max_epss = max((c.get("epss_score", 0) for c in all_cves if c.get("epss_score")), default=0)
                        shodan_r["max_cvss"] = max_cvss
                        shodan_r["max_epss"] = max_epss

                # --- Re-aggregate External IPs with enriched data ---
                results["categories"]["external_ips"] = ExternalIPAggregator.aggregate(
                    all_ips, per_ip_results, ip_sources=ip_sources
                )
        except Exception:
            pass
        self._notify(on_progress, "osv_enrichment", "done")

        # --- Phase 4d: Enrich per-port entries with banner + OSV data ---
        dns_cat = cat_results.get("dns_infrastructure", {})
        osv_vulns_all = results.get("categories", {}).get("osv_vulns", {}).get("vulns", [])
        if dns_cat.get("open_ports") and osv_vulns_all:
            for port_entry in dns_cat["open_ports"]:
                ver = port_entry.get("detected_version", "")
                if not ver:
                    continue
                # Match OSV vulns to this port's detected version by package name
                ver_lower = ver.lower()
                matched = []
                for v in osv_vulns_all:
                    pkg = (v.get("package", "") or "").lower()
                    if pkg and pkg in ver_lower:
                        matched.append(v)
                    elif ver_lower and any(kw in ver_lower for kw in
                        [v.get("ecosystem", "").lower()] if v.get("ecosystem")):
                        matched.append(v)
                if matched:
                    port_entry["osv_vulns"] = matched[:15]

        # --- Phase 5: Score ---
        scorer = RiskScorer()
        risk_score, risk_level, recommendations = scorer.calculate(cat_results)
        results["overall_risk_score"] = risk_score
        results["risk_level"] = risk_level
        results["recommendations"] = recommendations
        results["compliance"] = scorer.compliance_summary(cat_results)

        # --- Phase 6: Insurance Analytics ---
        self._notify(on_progress, "insurance_analytics", "running")
        try:
            # RSI
            rsi_calc = RansomwareIndex()
            rsi_result = rsi_calc.calculate(cat_results, industry, annual_revenue)
            results["insurance"]["rsi"] = rsi_result

            # Financial Impact — default to ZAR (SA product); use 10M estimate if no revenue given
            fin_calc = FinancialImpactCalculator()
            _zar = annual_revenue_zar if annual_revenue_zar > 0 else 10_000_000
            fin_result = fin_calc.calculate(
                cat_results, rsi_result, annual_revenue, industry,
                annual_revenue_zar=_zar
            )
            results["insurance"]["financial_impact"] = fin_result

            # DBI
            dbi_calc = DataBreachIndex()
            results["insurance"]["dbi"] = dbi_calc.calculate(cat_results)

            # Remediation Simulator
            sim = RemediationSimulator()
            results["insurance"]["remediation"] = sim.calculate(
                cat_results, rsi_result, fin_result,
                _zar,
                industry
            )
        except Exception as e:
            results["insurance"]["error"] = str(e)

        self._notify(on_progress, "insurance_analytics", "done")

        return results


if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    scanner = SecurityScanner()
    result = scanner.scan(domain)
    print(json.dumps(result, indent=2, default=str))
