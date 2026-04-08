"""
Network and infrastructure security checkers: Subdomains, VPN, DNS, Ports, Security Policy, DNSBL.
"""

from scanner_utils import *


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

    # Subdomain takeover signatures: CNAME target patterns → (service, HTTP fingerprint)
    TAKEOVER_SIGNATURES = {
        "github.io":               ("GitHub Pages",  "There isn't a GitHub Pages site here"),
        "s3.amazonaws.com":        ("AWS S3",        "NoSuchBucket"),
        "s3-website":              ("AWS S3",        "NoSuchBucket"),
        "herokuapp.com":           ("Heroku",        "No such app"),
        "herokudns.com":           ("Heroku",        "No such app"),
        "azurewebsites.net":       ("Azure",         "404 Web Site not found"),
        "cloudapp.net":            ("Azure",         None),
        "trafficmanager.net":      ("Azure TM",      None),
        "blob.core.windows.net":   ("Azure Blob",    "BlobNotFound"),
        "ghost.io":                ("Ghost",         "Domain is not configured"),
        "myshopify.com":           ("Shopify",       "Sorry, this shop is currently unavailable"),
        "shopifycloud.com":        ("Shopify",       None),
        "surge.sh":                ("Surge",         "project not found"),
        "bitbucket.io":            ("Bitbucket",     "Repository not found"),
        "wordpress.com":           ("WordPress.com", "Do you want to register"),
        "pantheonsite.io":         ("Pantheon",      "404 error unknown site"),
        "unbouncepages.com":       ("Unbounce",      "The requested URL was not found"),
        "zendesk.com":             ("Zendesk",       "Help Center Closed"),
        "teamwork.com":            ("Teamwork",      None),
        "helpjuice.com":           ("Helpjuice",     "We could not find what you're looking for"),
        "helpscoutdocs.com":       ("HelpScout",     "No settings were found"),
        "cargo.site":              ("Cargo",         None),
        "statuspage.io":           ("Statuspage",    None),
        "fastly.net":              ("Fastly",        "Fastly error: unknown domain"),
        "netlify.app":             ("Netlify",       "Not Found - Request ID"),
        "fly.dev":                 ("Fly.io",        None),
        "vercel.app":              ("Vercel",        None),
        "render.onrender.com":     ("Render",        None),
        "cname.vercel-dns.com":    ("Vercel",        None),
    }

    @staticmethod
    def _resolves(hostname: str) -> list:
        """Try to resolve a hostname, return list of IPs or empty list."""
        try:
            answers = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            return list(set(addr[4][0] for addr in answers))
        except Exception:
            return []

    def _check_cname_takeover(self, subdomain: str) -> Optional[dict]:
        """Check if a subdomain's CNAME points to an unclaimed/dangling service.
        Returns takeover info dict if vulnerable, None otherwise."""
        if not DNS_AVAILABLE:
            return None
        try:
            answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=3)
            cname_target = str(answers[0].target).rstrip(".")
        except Exception:
            return None  # No CNAME record — not vulnerable to CNAME takeover

        # Check CNAME target against known-vulnerable service patterns
        for pattern, (service, fingerprint) in self.TAKEOVER_SIGNATURES.items():
            if pattern in cname_target.lower():
                # CNAME matches a known service — check if the target is dangling
                # A dangling CNAME means the target doesn't resolve (NXDOMAIN) or
                # returns a known "not configured" page
                is_dangling = False
                try:
                    socket.getaddrinfo(cname_target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    # Target resolves — check HTTP fingerprint if available
                    if fingerprint:
                        try:
                            r = requests.get(f"https://{subdomain}", timeout=5,
                                             headers={"User-Agent": USER_AGENT},
                                             allow_redirects=True, verify=False)
                            if fingerprint.lower() in r.text.lower():
                                is_dangling = True
                        except Exception:
                            try:
                                r = requests.get(f"http://{subdomain}", timeout=5,
                                                 headers={"User-Agent": USER_AGENT},
                                                 allow_redirects=True)
                                if fingerprint.lower() in r.text.lower():
                                    is_dangling = True
                            except Exception:
                                pass
                except socket.gaierror:
                    # CNAME target doesn't resolve — dangling!
                    is_dangling = True

                if is_dangling:
                    return {
                        "subdomain": subdomain,
                        "cname_target": cname_target,
                        "service": service,
                        "risk": "critical",
                    }
                else:
                    return None  # CNAME matches pattern but target is live
        return None  # CNAME doesn't match any known-vulnerable patterns

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

        # --- Check for subdomain takeover vulnerabilities ---
        takeover_vulnerable = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(self._check_cname_takeover, sub): sub for sub in subdomains[:60]}
            for future in as_completed(futures, timeout=30):
                try:
                    result_to = future.result(timeout=5)
                    if result_to:
                        takeover_vulnerable.append(result_to)
                except Exception:
                    pass
        result["takeover_vulnerable"] = takeover_vulnerable
        if takeover_vulnerable:
            for tv in takeover_vulnerable:
                result["issues"].append(
                    f"CRITICAL: Subdomain takeover possible — {tv['subdomain']} CNAME points to "
                    f"unclaimed {tv['service']} ({tv['cname_target']})"
                )
            result["score"] = max(0, result["score"] - len(takeover_vulnerable) * 15)

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
            "zone_transfer": {"tested": False, "vulnerable": False, "ns_tested": 0, "records_leaked": 0},
        }
        if ip:
            result["ip"] = ip
        try:
            if DNS_AVAILABLE:
                result["dns_records"] = self._get_dns_records(domain)
                result["reverse_dns"] = self._get_reverse_dns(domain, ip=ip)
                result["zone_transfer"] = self._check_zone_transfer(domain, result["dns_records"])
            result["open_ports"] = self._scan_ports(domain, ip=ip)
            result["server_info"] = self._fingerprint_server(domain)
            result["risk_score"], result["issues"] = self._assess_risk(
                result["open_ports"], result.get("zone_transfer"))
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e)
        return result

    def _check_zone_transfer(self, domain: str, dns_records: dict) -> dict:
        """Attempt AXFR zone transfer against each NS server. Most will refuse (expected).
        A successful transfer is a CRITICAL finding — full DNS zone disclosure."""
        zt = {"tested": False, "vulnerable": False, "ns_tested": 0,
              "records_leaked": 0, "vulnerable_ns": []}
        ns_servers = dns_records.get("NS", [])
        if not ns_servers:
            return zt
        zt["tested"] = True
        try:
            import dns.query
            import dns.zone
        except ImportError:
            return zt
        for ns in ns_servers[:4]:  # Test up to 4 NS servers
            ns = ns.rstrip(".")
            zt["ns_tested"] += 1
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, lifetime=5))
                record_count = len(zone.nodes)
                if record_count > 0:
                    zt["vulnerable"] = True
                    zt["records_leaked"] += record_count
                    zt["vulnerable_ns"].append(ns)
            except Exception:
                pass  # Refused/timeout is expected and safe
        return zt

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

    def _assess_risk(self, open_ports: list, zone_transfer: dict = None) -> tuple:
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
        # Zone transfer vulnerability
        if zone_transfer and zone_transfer.get("vulnerable"):
            score += 50
            ns_list = ", ".join(zone_transfer.get("vulnerable_ns", []))
            issues.append(
                f"CRITICAL: Zone transfer (AXFR) permitted on {ns_list} — "
                f"{zone_transfer.get('records_leaked', 0)} DNS records disclosed. "
                "Attacker can enumerate entire DNS zone including internal hostnames."
            )
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
