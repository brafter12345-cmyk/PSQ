"""
Threat intelligence and vulnerability checkers: TechStack, Breaches, Website Security,
Payment, Shodan, OSV, Dehashed, VirusTotal, SecurityTrails, Hudson Rock, HIBP,
Credential Risk, IntelX, Fraudulent Domains, Privacy, Web Ranking, Info Disclosure.
"""

from scanner_utils import *


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
    KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    KEV_URL_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
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

            # Published date for CVE age calculation
            published = vuln.get("published", "")[:10]  # YYYY-MM-DD

            # Check for patch/advisory references (zero-day indicator)
            references = vuln.get("references", [])
            has_patch = any(
                "Patch" in (ref.get("tags", []) if isinstance(ref.get("tags"), list) else [])
                or "Vendor Advisory" in (ref.get("tags", []) if isinstance(ref.get("tags"), list) else [])
                for ref in references
            )

            # Try CVSS v3.1, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m = metrics.get(key)
                if m:
                    base = m[0].get("cvssData", {})
                    score = base.get("baseScore", 0.0)
                    vector = base.get("vectorString", "")

                    # Parse CVSS vector for exploitability indicators
                    easily_exploitable = (
                        "AV:N" in vector and   # Network accessible
                        "AC:L" in vector and   # Low complexity
                        "PR:N" in vector       # No privileges required
                    )

                    return {
                        "cve_id": cve_id,
                        "description": desc[:200],
                        "cvss_score": score,
                        "severity": self._cvss_severity(score),
                        "vector": vector,
                        "published": published,
                        "has_patch": has_patch,
                        "easily_exploitable": easily_exploitable,
                    }
            return {"cve_id": cve_id, "description": desc[:200], "cvss_score": 0.0, "severity": "unknown",
                    "vector": "", "published": published, "has_patch": has_patch, "easily_exploitable": False}
        except Exception:
            return {"cve_id": cve_id, "description": "", "cvss_score": 0.0, "severity": "unknown",
                    "vector": "", "published": "", "has_patch": False, "easily_exploitable": False}

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
        """Load CISA KEV catalog, cached for 24 hours. Tries CISA direct then GitHub mirror."""
        now = time.time()
        if ShodanVulnChecker._kev_cache is not None and (now - ShodanVulnChecker._kev_cache_time) < 86400:
            return ShodanVulnChecker._kev_cache
        for url in (self.KEV_URL, self.KEV_URL_MIRROR):
            try:
                r = requests.get(url, timeout=15,
                                 headers={"User-Agent": USER_AGENT})
                if r.status_code == 200:
                    data = r.json()
                    kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                    if kev_set:
                        ShodanVulnChecker._kev_cache = kev_set
                        ShodanVulnChecker._kev_cache_time = now
                        return kev_set
            except Exception:
                continue
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

    # Ransomware CVE mapping — known CVEs used by ransomware families
    # Source: community-maintained + CISA advisories
    RANSOMWARE_CVE_MAP = {
        # LockBit
        "CVE-2023-4966": "LockBit (Citrix Bleed)", "CVE-2021-22986": "LockBit",
        "CVE-2023-0669": "LockBit (GoAnywhere)", "CVE-2021-44228": "LockBit (Log4Shell)",
        # Conti / BlackBasta (successor)
        "CVE-2021-34473": "Conti/BlackBasta (ProxyShell)", "CVE-2021-34523": "Conti (ProxyShell)",
        "CVE-2021-31207": "Conti (ProxyShell)", "CVE-2021-26855": "Conti (ProxyLogon)",
        # ALPHV/BlackCat
        "CVE-2023-22515": "ALPHV/BlackCat (Atlassian)", "CVE-2023-22518": "ALPHV/BlackCat",
        # CL0P
        "CVE-2023-34362": "CL0P (MOVEit)", "CVE-2023-0669": "CL0P (GoAnywhere)",
        "CVE-2021-27101": "CL0P (Accellion)",
        # REvil/Sodinokibi
        "CVE-2021-30116": "REvil (Kaseya)", "CVE-2019-2725": "REvil (WebLogic)",
        # Akira
        "CVE-2023-20269": "Akira (Cisco VPN)", "CVE-2020-3259": "Akira (Cisco)",
        # Play
        "CVE-2022-41082": "Play (Exchange)", "CVE-2022-41040": "Play (ProxyNotShell)",
        # General ransomware vectors
        "CVE-2019-0708": "Multiple (BlueKeep — WannaCry, NotPetya)",
        "CVE-2017-0144": "WannaCry/NotPetya (EternalBlue)",
        "CVE-2020-0796": "Multiple (SMBGhost)",
        "CVE-2019-11510": "Multiple (Pulse Secure VPN)",
        "CVE-2019-19781": "Multiple (Citrix ADC)",
        "CVE-2020-5902": "Multiple (F5 BIG-IP)",
        "CVE-2021-27065": "Hafnium/Multiple (Exchange)",
        "CVE-2021-40444": "Multiple (MSHTML)",
        "CVE-2022-26134": "Multiple (Confluence)",
        "CVE-2023-27997": "Multiple (FortiGate)",
        "CVE-2024-1709": "Multiple (ConnectWise ScreenConnect)",
        "CVE-2024-3400": "Multiple (Palo Alto PAN-OS)",
    }

    # MITRE ATT&CK technique mapping for common CVE exploitation patterns
    ATTACK_TECHNIQUE_MAP = {
        # Initial Access techniques
        "CVE-2019-0708": {"technique": "T1210", "name": "Exploitation of Remote Services", "groups": ["APT28", "Lazarus"]},
        "CVE-2017-0144": {"technique": "T1210", "name": "Exploitation of Remote Services", "groups": ["WannaCry", "NotPetya", "Lazarus"]},
        "CVE-2021-44228": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["APT41", "Lazarus", "LockBit"]},
        "CVE-2021-26855": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["Hafnium", "APT27", "Conti"]},
        "CVE-2021-34473": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["Conti", "LockBit", "BlackBasta"]},
        "CVE-2023-34362": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["CL0P"]},
        "CVE-2019-11510": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["APT5", "REvil"]},
        "CVE-2019-19781": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["REvil", "DoppelPaymer"]},
        "CVE-2023-4966": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": ["LockBit", "Medusa"]},
        "CVE-2024-6387": {"technique": "T1190", "name": "Exploit Public-Facing Application", "groups": []},
        "CVE-2023-48795": {"technique": "T1557", "name": "Adversary-in-the-Middle", "groups": []},
        # Privilege escalation
        "CVE-2021-3156": {"technique": "T1068", "name": "Exploitation for Privilege Escalation", "groups": ["Multiple"]},
        # Lateral movement
        "CVE-2020-0796": {"technique": "T1210", "name": "Exploitation of Remote Services", "groups": ["Multiple"]},
    }

    def _enrich_cves(self, raw_cves: list, result: dict) -> bool:
        """Enrich CVEs with CVSS, KEV, EPSS, exploit maturity, exploitability,
        ransomware associations, MITRE ATT&CK mapping, and CVE age data."""
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
        zero_day_count = 0
        easily_exploitable_count = 0
        widely_exploited_count = 0
        malware_exploited_count = 0
        oldest_cve_age = 0
        cve_ages = []

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

                # --- NEW: Easily exploitable (from CVSS vector) ---
                if info.get("easily_exploitable"):
                    easily_exploitable_count += 1

                # --- NEW: Widely exploited (EPSS percentile > 0.9 or score > 0.4) ---
                if info["epss_score"] > 0.4 or info.get("epss_percentile", 0) > 0.9:
                    info["widely_exploited"] = True
                    widely_exploited_count += 1
                else:
                    info["widely_exploited"] = False

                # --- NEW: Zero-day / no patch indicator ---
                if not info.get("has_patch", True):
                    info["zero_day"] = True
                    zero_day_count += 1
                else:
                    info["zero_day"] = False

                # --- NEW: Ransomware association ---
                ransomware = self.RANSOMWARE_CVE_MAP.get(cve_id.upper(), "")
                info["ransomware_association"] = ransomware
                if ransomware:
                    malware_exploited_count += 1

                # --- NEW: MITRE ATT&CK mapping ---
                attack = self.ATTACK_TECHNIQUE_MAP.get(cve_id.upper(), {})
                info["attack_technique"] = attack.get("technique", "")
                info["attack_technique_name"] = attack.get("name", "")
                info["attack_groups"] = attack.get("groups", [])

                # --- NEW: CVE age (days since published) ---
                pub_date = info.get("published", "")
                if pub_date:
                    try:
                        from datetime import datetime
                        pub_dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
                        age_days = (datetime.utcnow() - pub_dt).days
                        info["age_days"] = age_days
                        cve_ages.append(age_days)
                        if age_days > oldest_cve_age:
                            oldest_cve_age = age_days
                    except (ValueError, TypeError):
                        info["age_days"] = None
                else:
                    info["age_days"] = None

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

        # NEW indicators
        result["zero_day_count"] = zero_day_count
        result["easily_exploitable_count"] = easily_exploitable_count
        result["widely_exploited_count"] = widely_exploited_count
        result["malware_exploited_count"] = malware_exploited_count

        # Patch management posture
        result["patch_management"] = {
            "oldest_unpatched_days": oldest_cve_age,
            "average_age_days": round(sum(cve_ages) / len(cve_ages)) if cve_ages else 0,
            "over_180_days": sum(1 for a in cve_ages if a > 180),
            "90_to_180_days": sum(1 for a in cve_ages if 90 <= a <= 180),
            "under_90_days": sum(1 for a in cve_ages if a < 90),
            "total_cves_aged": len(cve_ages),
        }

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
        if zero_day_count > 0:
            result["issues"].append(
                f"{zero_day_count} CVE(s) with no vendor patch available — monitor for updates and apply mitigations"
            )
        if easily_exploitable_count > 0:
            result["issues"].append(
                f"{easily_exploitable_count} CVE(s) are easily exploitable (network accessible, low complexity, no authentication required)"
            )
        if widely_exploited_count > 0:
            result["issues"].append(
                f"{widely_exploited_count} CVE(s) are widely exploited (EPSS > 40%) — mass exploitation campaigns likely"
            )
        if malware_exploited_count > 0:
            ransomware_names = list(set(
                info.get("ransomware_association", "") for info in enriched if info.get("ransomware_association")
            ))[:5]
            result["issues"].append(
                f"{malware_exploited_count} CVE(s) associated with known ransomware/malware: {', '.join(ransomware_names)}"
            )
        # Patch management warning
        pm = result["patch_management"]
        if pm["oldest_unpatched_days"] > 365:
            result["issues"].append(
                f"PATCH MANAGEMENT: Oldest unpatched vulnerability is {pm['oldest_unpatched_days']} days old — "
                f"indicates significant patch management deficiency"
            )
        elif pm["oldest_unpatched_days"] > 180:
            result["issues"].append(
                f"Patch management: {pm['over_180_days']} vulnerability(ies) unpatched for over 180 days"
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
    Requires DEHASHED_API_KEY env var (paid subscription with credits).
    Uses v2 API (POST with JSON body, API key header).
    Falls back gracefully with status='no_api_key' when credentials are absent.
    """
    API_URL_V2 = "https://api.dehashed.com/v2/search"
    API_URL_V1 = "https://api.dehashed.com/search"

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

        if not api_key:
            result["status"] = "no_api_key"
            return result

        # Try v2 API first (POST + API key header)
        try:
            r = requests.post(
                self.API_URL_V2,
                json={"query": f"domain:{domain}", "page": 1, "size": 100},
                headers={
                    "Content-Type": "application/json",
                    "Dehashed-Api-Key": api_key,
                    "User-Agent": USER_AGENT,
                },
                timeout=15,
            )
        except Exception:
            r = None

        # Fall back to v1 if v2 fails completely
        if r is None or r.status_code == 404:
            try:
                r = requests.get(
                    self.API_URL_V1,
                    params={"query": f"domain:{domain}", "size": 100},
                    auth=(email or "", api_key),
                    headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                    timeout=15,
                )
            except Exception as e:
                result["status"] = "error"
                result["error"] = str(e)
                return result

        try:
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
            breach_sources = set()
            breach_details = []
            for entry in entries:
                # v2 API returns email as list, v1 as string
                em = entry.get("email", "")
                if isinstance(em, list):
                    for e in em:
                        if e:
                            emails_seen.add(str(e))
                elif em:
                    emails_seen.add(str(em))

                pw = entry.get("password")
                hpw = entry.get("hashed_password")
                if isinstance(pw, list):
                    pw = pw[0] if pw else None
                if isinstance(hpw, list):
                    hpw = hpw[0] if hpw else None
                if pw or hpw:
                    has_pw = True

                db_name = entry.get("database_name", "Unknown source")
                if db_name:
                    breach_sources.add(db_name)

                # Build detail record for PDF
                email_str = ", ".join(em) if isinstance(em, list) else (em or "N/A")
                username = entry.get("username", "")
                if isinstance(username, list):
                    username = username[0] if username else ""
                breach_details.append({
                    "email": email_str,
                    "username": str(username) if username else "",
                    "database": db_name,
                    "has_password": bool(pw),
                    "has_hash": bool(hpw),
                })

            result["unique_emails"] = len(emails_seen)
            result["has_passwords"] = has_pw
            result["sample_emails"] = [
                e[:40] + ("\u2026" if len(e) > 40 else "") for e in list(emails_seen)[:5]
            ]
            result["breach_sources"] = list(breach_sources)
            result["breach_details"] = breach_details[:20]

            if total > 0:
                src_list = ", ".join(list(breach_sources)[:5])
                result["issues"].append(
                    f"{total} credential record(s) found in Dehashed for this domain "
                    f"(sources: {src_list}) — notify affected users and enforce password reset"
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
# 24. Hudson Rock Infostealer Detection (free, no API key)
# ---------------------------------------------------------------------------

class HudsonRockChecker:
    """
    Checks if a domain has employees/users compromised by infostealer malware
    (Raccoon, RedLine, Vidar, etc.) via Hudson Rock's free OSINT API.
    Active infostealers indicate CURRENT compromise — not historical.
    """
    API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "compromised_employees": 0,
            "compromised_users": 0,
            "third_party_exposures": 0,
            "total_compromised": 0,
            "score": 100,
            "issues": [],
        }
        try:
            r = requests.get(f"{self.API_URL}?domain={domain}",
                             headers={"User-Agent": USER_AGENT}, timeout=15)
            if r.status_code != 200:
                result["status"] = "error"
                return result

            data = r.json()
            employees = data.get("employees", 0) or 0
            users = data.get("users", 0) or 0
            third_parties = data.get("third_parties", 0) or 0
            total = employees + users

            result["compromised_employees"] = employees
            result["compromised_users"] = users
            result["third_party_exposures"] = third_parties
            result["total_compromised"] = total

            if employees > 0:
                result["issues"].append(
                    f"CRITICAL: {employees} employee device(s) infected with infostealer malware — "
                    "credentials are actively being sold on dark web markets. Immediate incident response required."
                )
                result["score"] = max(0, 100 - employees * 30)
            if users > 0:
                result["issues"].append(
                    f"{users} user account(s) compromised via infostealer — "
                    "force password resets and enable MFA for affected accounts."
                )
                result["score"] = max(0, result["score"] - users * 10)
            if third_parties > 0:
                result["issues"].append(
                    f"{third_parties} third-party exposure(s) detected — "
                    "review supply chain partners and shared credential access."
                )
                result["score"] = max(0, result["score"] - third_parties * 5)

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 25. HIBP Breach Metadata (free tier — breach list + date enrichment)
# ---------------------------------------------------------------------------

class HIBPBreachMetadata:
    """
    Uses the free HIBP breach list API to enrich Dehashed results with
    breach dates, data classes exposed, and verification status.
    No API key required for the breach list endpoint.
    """
    BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

    _cache = None
    _cache_time = 0

    def load_breaches(self) -> dict:
        """Load full breach catalog, cached for 24 hours. Returns {name_lower: breach_dict}."""
        now = time.time()
        if HIBPBreachMetadata._cache is not None and (now - HIBPBreachMetadata._cache_time) < 86400:
            return HIBPBreachMetadata._cache
        try:
            r = requests.get(self.BREACHES_URL,
                             headers={"User-Agent": USER_AGENT}, timeout=15)
            if r.status_code == 200:
                breaches = r.json()
                lookup = {}
                for b in breaches:
                    # Index by name (lowercased) and also by common variants
                    name = b.get("Name", "")
                    lookup[name.lower()] = {
                        "name": name,
                        "title": b.get("Title", name),
                        "breach_date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified", False),
                        "is_sensitive": b.get("IsSensitive", False),
                        "description": b.get("Description", "")[:200],
                    }
                HIBPBreachMetadata._cache = lookup
                HIBPBreachMetadata._cache_time = now
                return lookup
        except Exception:
            pass
        return {}

    def enrich_dehashed_results(self, dehashed_result: dict) -> dict:
        """Add breach dates and data classes to Dehashed breach details."""
        breaches_db = self.load_breaches()
        if not breaches_db:
            return dehashed_result

        enriched_sources = []
        for source in dehashed_result.get("breach_sources", []):
            source_lower = source.lower().strip()
            # Try exact match, then partial match
            match = breaches_db.get(source_lower)
            if not match:
                for key, val in breaches_db.items():
                    if source_lower in key or key in source_lower:
                        match = val
                        break
            if match:
                enriched_sources.append({
                    "name": source,
                    "breach_date": match["breach_date"],
                    "records": match["pwn_count"],
                    "data_exposed": match["data_classes"],
                    "verified": match["is_verified"],
                    "passwords_in_breach": "Passwords" in match["data_classes"],
                })
            else:
                enriched_sources.append({
                    "name": source,
                    "breach_date": "Unknown",
                    "records": 0,
                    "data_exposed": [],
                    "verified": False,
                    "passwords_in_breach": False,
                })

        dehashed_result["enriched_sources"] = enriched_sources
        return dehashed_result


# ---------------------------------------------------------------------------
# 26. Credential Risk Classifier
# ---------------------------------------------------------------------------

class CredentialRiskClassifier:
    """
    Combines Dehashed + HIBP + Hudson Rock data to classify credential
    exposure risk as CRITICAL / HIGH / MEDIUM / LOW.
    """

    # Known breach dates for common sources not in HIBP
    KNOWN_BREACH_DATES = {
        "alien txtbase": "2024-12-01",
        "socradar.io": "2024-08-01",
        "collection #1": "2019-01-01",
        "anti public combo list": "2016-12-01",
        "exploit.in": "2017-05-01",
    }

    @staticmethod
    def classify(dehashed: dict, hudson_rock: dict, intelx: dict = None, hibp_enriched: dict = None) -> dict:
        """Return overall credential risk assessment."""
        result = {
            "risk_level": "LOW",
            "risk_score": 100,
            "active_compromise": False,
            "factors": [],
            "summary": "",
        }

        # Factor 1: Active infostealer (Hudson Rock) — CRITICAL
        hr_employees = hudson_rock.get("compromised_employees", 0)
        hr_users = hudson_rock.get("compromised_users", 0)
        if hr_employees > 0:
            result["risk_level"] = "CRITICAL"
            result["active_compromise"] = True
            result["risk_score"] = max(0, result["risk_score"] - 50)
            result["factors"].append(
                f"ACTIVE INFOSTEALER: {hr_employees} employee device(s) currently infected — "
                "credentials are being exfiltrated in real-time"
            )
        if hr_users > 0:
            result["risk_score"] = max(0, result["risk_score"] - 20)
            result["factors"].append(
                f"{hr_users} user account(s) compromised via infostealer malware"
            )

        # Factor 1b: Dark web exposure (IntelX)
        if intelx and isinstance(intelx, dict):
            darkweb = intelx.get("darkweb_count", 0)
            pastes = intelx.get("paste_count", 0)
            total_ix = intelx.get("total_results", 0)
            if darkweb > 0:
                if result["risk_level"] not in ("CRITICAL",):
                    result["risk_level"] = "HIGH"
                result["risk_score"] = max(0, result["risk_score"] - darkweb * 10)
                result["factors"].append(
                    f"DARK WEB: {darkweb} mention(s) found on dark web forums/markets — "
                    "credentials or data may be actively traded"
                )
            if pastes > 3:
                result["risk_score"] = max(0, result["risk_score"] - pastes * 3)
                result["factors"].append(
                    f"{pastes} paste site mention(s) — data shared on public paste sites"
                )
            elif total_ix > 0 and darkweb == 0:
                result["factors"].append(
                    f"{total_ix} reference(s) found in leak databases (IntelX)"
                )

        # Factor 2: Credential exposure (Dehashed)
        total_leaks = dehashed.get("total_entries", 0)
        has_passwords = dehashed.get("has_passwords", False)
        unique_emails = dehashed.get("unique_emails", 0)

        if has_passwords and total_leaks > 0:
            if result["risk_level"] != "CRITICAL":
                result["risk_level"] = "HIGH"
            result["risk_score"] = max(0, result["risk_score"] - 30)
            result["factors"].append(
                f"Plaintext or hashed passwords exposed for {unique_emails} email(s) "
                f"across {total_leaks} breach record(s)"
            )
        elif total_leaks > 0:
            if result["risk_level"] not in ("CRITICAL", "HIGH"):
                result["risk_level"] = "MEDIUM"
            result["risk_score"] = max(0, result["risk_score"] - 15)
            result["factors"].append(
                f"{total_leaks} credential record(s) found across {len(dehashed.get('breach_sources', []))} breach source(s) "
                f"— {unique_emails} unique email(s) exposed"
            )

        # Factor 3: Breach recency (HIBP enrichment)
        enriched = dehashed.get("enriched_sources", [])
        recent_breaches = []
        old_breaches = []
        for src in enriched:
            date_str = src.get("breach_date", "Unknown")
            if date_str and date_str != "Unknown":
                try:
                    year = int(date_str[:4])
                    if year >= 2023:
                        recent_breaches.append(src["name"])
                    else:
                        old_breaches.append(src["name"])
                except (ValueError, IndexError):
                    pass
            pw_in_breach = src.get("passwords_in_breach", False)
            if pw_in_breach:
                result["factors"].append(
                    f"Breach '{src['name']}' (date: {date_str}) included passwords in exposed data"
                )

        if recent_breaches:
            if result["risk_level"] not in ("CRITICAL",):
                result["risk_level"] = "HIGH"
            result["risk_score"] = max(0, result["risk_score"] - 15)
            result["factors"].append(
                f"Recent breaches (2023+): {', '.join(recent_breaches)} — higher likelihood credentials are still active"
            )

        # Build summary
        if result["risk_level"] == "CRITICAL":
            result["summary"] = (
                "CRITICAL credential risk — active infostealer infection detected. "
                "Credentials are being exfiltrated in real-time. Immediate incident response required: "
                "isolate affected devices, force all password resets, enable MFA, engage forensics team."
            )
        elif result["risk_level"] == "HIGH":
            result["summary"] = (
                "HIGH credential risk — recent breaches with password exposure. "
                "Force password resets for all identified accounts, enable MFA, "
                "and implement continuous credential monitoring."
            )
        elif result["risk_level"] == "MEDIUM":
            result["summary"] = (
                "MEDIUM credential risk — historical credential exposure detected. "
                "Review affected accounts, enforce MFA, and monitor for credential stuffing attempts."
            )
        else:
            result["summary"] = (
                "LOW credential risk — no active compromise or significant credential exposure detected."
            )

        return result


# ---------------------------------------------------------------------------
# 27. IntelX Dark Web Monitoring (free tier)
# ---------------------------------------------------------------------------

class IntelXChecker:
    """
    Searches Intelligence X for dark web pastes, leaked documents, and
    breach data associated with a domain. Two-step: initiate search, poll results.
    Free tier: 40 results/search, ~500 credits/day.
    """
    API_URL = "https://free.intelx.io"

    def check(self, domain: str, api_key: str = None) -> dict:
        result = {
            "status": "completed",
            "total_results": 0,
            "paste_count": 0,
            "leak_count": 0,
            "darkweb_count": 0,
            "recent_results": [],
            "score": 100,
            "issues": [],
        }
        if not api_key:
            result["status"] = "no_api_key"
            return result

        try:
            # Step 1: Initiate search
            r = requests.post(f"{self.API_URL}/intelligent/search",
                json={"term": domain, "maxresults": 40, "timeout": 5, "sort": 4, "media": 0},
                headers={"X-Key": api_key}, timeout=15)
            if r.status_code == 401:
                result["status"] = "auth_failed"
                return result
            if r.status_code != 200:
                result["status"] = "error"
                return result

            search_id = r.json().get("id")
            if not search_id:
                return result

            # Step 2: Poll for results (wait up to 8s)
            import time as _time
            _time.sleep(3)
            records = []
            for _ in range(3):
                r2 = requests.get(f"{self.API_URL}/intelligent/search/result",
                    params={"id": search_id},
                    headers={"X-Key": api_key}, timeout=10)
                if r2.status_code != 200:
                    break
                data = r2.json()
                records.extend(data.get("records", []))
                if data.get("status") in (1, 2, 4):  # 1=done, 2=not found, 4=error
                    break
                _time.sleep(2)

            result["total_results"] = len(records)

            # Classify results by type
            for rec in records:
                media = rec.get("media", 0)
                # media types: 1=paste, 2=paste, 5=email, 13=darkweb, 14=document
                if media in (1, 2):
                    result["paste_count"] += 1
                elif media == 13:
                    result["darkweb_count"] += 1
                else:
                    result["leak_count"] += 1

                # Keep recent entries for display
                if len(result["recent_results"]) < 10:
                    result["recent_results"].append({
                        "name": (rec.get("name") or "Unknown")[:80],
                        "type": rec.get("typeh", "Unknown"),
                        "media": rec.get("mediah", "Unknown"),
                        "date": (rec.get("date") or "")[:10],
                    })

            # Scoring
            if result["darkweb_count"] > 0:
                result["score"] = max(0, 100 - result["darkweb_count"] * 15)
                result["issues"].append(
                    f"{result['darkweb_count']} dark web mention(s) found — "
                    "credentials or data may be actively traded on criminal forums."
                )
            if result["paste_count"] > 5:
                result["score"] = max(0, result["score"] - result["paste_count"] * 3)
                result["issues"].append(
                    f"{result['paste_count']} paste site mention(s) — "
                    "data has been shared on public paste sites (Pastebin, etc.)."
                )
            if result["total_results"] > 0 and not result["issues"]:
                result["issues"].append(
                    f"{result['total_results']} reference(s) found in dark web and leak databases."
                )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)

        return result


# ---------------------------------------------------------------------------
# 28. Fraudulent / Lookalike Domain Detection
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
        # Try with and without www prefix
        homepage_url = f"https://{domain}"
        try:
            r = requests.get(homepage_url, headers={"User-Agent": USER_AGENT},
                             timeout=20, allow_redirects=True)
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
                                          timeout=20, allow_redirects=True)
                        if r2.status_code == 200 and len(r2.text) > 500:
                            return href, r2.text.lower()
                    except Exception:
                        continue
        except Exception:
            pass

        # --- Strategy 2: Try common paths on both domain and www variant ---
        domains_to_try = [domain]
        if not domain.startswith("www."):
            domains_to_try.append(f"www.{domain}")
        for d in domains_to_try:
            for path in self.POLICY_PATHS:
                url = f"https://{d}{path}"
                try:
                    r = requests.get(url, headers={"User-Agent": USER_AGENT},
                                     timeout=15, allow_redirects=True)
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
