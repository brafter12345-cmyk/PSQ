"""
Core security checkers: SSL, Email, HTTP Headers, WAF, Cloud/CDN, Domain Intel, Exposed Admin.
"""

from scanner_utils import *


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
            result["caa_policy"] = self._parse_caa(result["caa_records"])

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

    def _parse_caa(self, caa_records: list) -> dict:
        """Parse CAA records into structured policy data.
        CAA records look like: '0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:..."'
        """
        result = {"issue": [], "issuewild": [], "iodef": [], "restrictive": False}
        for rec in caa_records:
            parts = str(rec).split(None, 2)  # e.g. ['0', 'issue', '"letsencrypt.org"']
            if len(parts) >= 3:
                tag = parts[1].lower()
                value = parts[2].strip('"').strip()
                if tag == "issue":
                    result["issue"].append(value)
                elif tag == "issuewild":
                    result["issuewild"].append(value)
                elif tag == "iodef":
                    result["iodef"].append(value)
        # Restrictive = at least one 'issue' tag that limits which CAs can issue
        # A value of ";" means "no CA is allowed" (deny). Any non-empty, non-";" value restricts to specific CAs.
        result["restrictive"] = len(result["issue"]) > 0
        return result

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
            ded += 5; issues.append("No CAA records — any CA can issue certificates for this domain")

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
            "tls_rpt": {"present": False, "rua": None},
            "issues": [], "score": 0,
        }
        if not DNS_AVAILABLE or not REQUESTS_AVAILABLE:
            result["status"] = "error"; return result
        try:
            result["mta_sts"] = self._check_mta_sts(domain)
            result["bimi"] = self._check_bimi(domain)
            result["dane"] = self._check_dane(domain)
            result["tls_rpt"] = self._check_tls_rpt(domain)
            result["score"], result["issues"] = self._calculate_score(
                result["mta_sts"], result["bimi"], result["dane"], result["tls_rpt"])
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

    def _check_tls_rpt(self, domain: str) -> dict:
        """Check for TLS-RPT (RFC 8460) — _smtp._tls.{domain} TXT record."""
        try:
            answers = dns.resolver.resolve(f"_smtp._tls.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
                if "v=TLSRPTv1" in txt:
                    # Extract reporting URI (rua=mailto:... or rua=https://...)
                    rua = None
                    m = re.search(r"rua=([^;\s]+)", txt)
                    if m:
                        rua = m.group(1)
                    return {"present": True, "rua": rua}
        except Exception:
            pass
        return {"present": False, "rua": None}

    def _calculate_score(self, mta_sts, bimi, dane, tls_rpt=None) -> tuple:
        if tls_rpt is None:
            tls_rpt = {"present": False}
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
        if tls_rpt["present"]:
            score += 1
        else:
            issues.append("TLS-RPT not configured — no reporting of email TLS delivery failures")
        return min(score, 10), issues


# ---------------------------------------------------------------------------
# 4. HTTP Security Headers
# ---------------------------------------------------------------------------

class HTTPHeaderChecker:
    # CSP presence: 10 pts, CSP quality: 0-10 pts, total CSP weight = 20
    HEADERS = {
        "content-security-policy": ("Content-Security-Policy", 10),
        "x-frame-options": ("X-Frame-Options", 15),
        "x-content-type-options": ("X-Content-Type-Options", 15),
        "strict-transport-security": ("Strict-Transport-Security", 20),
        "referrer-policy": ("Referrer-Policy", 15),
        "permissions-policy": ("Permissions-Policy", 15),
    }

    # Dangerous CSP patterns
    CSP_DANGEROUS = {
        "'unsafe-inline'": "Allows inline scripts — defeats most XSS protections",
        "'unsafe-eval'":   "Allows eval() — enables code injection attacks",
        "*":               "Wildcard source — any domain can load resources",
        "data:":           "data: URIs in script-src — enables XSS via encoded payloads",
    }
    # Critical CSP directives that should be present
    CSP_CRITICAL_DIRECTIVES = ["default-src", "script-src", "frame-ancestors", "object-src", "base-uri"]

    def _analyze_csp(self, csp_value: str) -> dict:
        """Parse and score a Content-Security-Policy header value."""
        result = {
            "score": 0,            # 0-100 quality score
            "directives": {},      # parsed directive → [sources]
            "dangerous": [],       # list of dangerous patterns found
            "missing_critical": [],  # critical directives not present
        }
        if not csp_value:
            return result

        # Parse directives: "default-src 'self'; script-src 'self' cdn.example.com"
        for directive_str in csp_value.split(";"):
            directive_str = directive_str.strip()
            if not directive_str:
                continue
            parts = directive_str.split()
            if parts:
                directive_name = parts[0].lower()
                sources = [s.lower() for s in parts[1:]] if len(parts) > 1 else []
                result["directives"][directive_name] = sources

        # Check for dangerous patterns
        script_src = result["directives"].get("script-src", result["directives"].get("default-src", []))
        style_src = result["directives"].get("style-src", result["directives"].get("default-src", []))
        all_sources = []
        for sources in result["directives"].values():
            all_sources.extend(sources)

        for pattern, description in self.CSP_DANGEROUS.items():
            if pattern == "*":
                # Check wildcard in script-src specifically
                if "*" in script_src:
                    result["dangerous"].append(f"Wildcard (*) in script-src — {description}")
            elif pattern == "data:":
                if "data:" in script_src:
                    result["dangerous"].append(f"data: in script-src — {description}")
            else:
                if pattern in script_src or pattern in style_src:
                    result["dangerous"].append(f"{pattern} detected — {description}")

        # Check for missing critical directives
        for directive in self.CSP_CRITICAL_DIRECTIVES:
            if directive not in result["directives"]:
                result["missing_critical"].append(directive)

        # Calculate quality score (0-100)
        score = 50  # Base score for having CSP at all
        # Deductions for dangerous patterns
        score -= len(result["dangerous"]) * 15
        # Deductions for missing critical directives
        score -= len(result["missing_critical"]) * 8
        # Bonus for restrictive policies
        if "'self'" in script_src and "'unsafe-inline'" not in script_src and "'unsafe-eval'" not in script_src:
            score += 20  # Restrictive script-src
        if "frame-ancestors" in result["directives"]:
            score += 10  # Anti-clickjacking
        if "'none'" in result["directives"].get("object-src", []):
            score += 10  # Blocks Flash/plugins
        if "'none'" in result["directives"].get("base-uri", []):
            score += 10  # Prevents base tag hijacking

        result["score"] = max(0, min(100, score))
        return result

    def check(self, domain: str) -> dict:
        result = {"status": "completed", "headers": {}, "score": 0, "issues": [],
                  "csp_quality": None}
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

            # CSP quality analysis (adds up to 10 bonus points to the total weight)
            csp_val = headers_lower.get("content-security-policy")
            if csp_val:
                csp_quality = self._analyze_csp(csp_val)
                result["csp_quality"] = csp_quality
                # Add CSP quality bonus (0-10 points on top of base CSP presence weight)
                csp_bonus = round(csp_quality["score"] / 10)  # 0-10 pts
                earned += csp_bonus
                total_weight += 10  # CSP quality weight
                # Add issues for dangerous CSP patterns
                for danger in csp_quality["dangerous"]:
                    result["issues"].append(f"CSP quality issue: {danger}")
                if csp_quality["missing_critical"]:
                    result["issues"].append(
                        f"CSP missing critical directives: {', '.join(csp_quality['missing_critical'])}")
            else:
                total_weight += 10  # Still count quality weight even if CSP absent

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
