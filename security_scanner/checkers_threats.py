"""
Threat intelligence and vulnerability checkers: TechStack, Breaches, Website Security,
Payment, Shodan, OSV, Dehashed, VirusTotal, SecurityTrails, Hudson Rock, HIBP,
Credential Risk, IntelX, Fraudulent Domains, Privacy, Web Ranking, Info Disclosure.
"""

from scanner_utils import *

# WS0: route target-apex probes through HTTP, paid/free providers through their
# per-provider clients. All return None on a failed request instead of raising;
# provider clients add no retry (existing per-checker loops keep their semantics).
from http_client import HTTP
from providers import (
    HIBP, NVD, SHODAN, INTERNETDB, KEV, MSF, EXPLOITDB, EPSS, OSV,
    HUDSONROCK, INTELX, TRANCO, DEHASHED, VIRUSTOTAL, SECURITYTRAILS,
)


# ---------------------------------------------------------------------------
# 15. Technology Stack & EOL/CVE Check
# ---------------------------------------------------------------------------

# Shared CMS fingerprints, used by both TechStackChecker and
# WebsiteSecurityChecker. Single table so the signatures can't drift apart
# (they already had: Wix "wix-code" vs "X-Wix-", Magento with/without the
# bare token, PrestaShop in one copy only — this is the union).
CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
    "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
    "Drupal": ["/sites/default/", "Drupal.settings", "/modules/system/"],
    "Wix": ["wixsite.com", "wix-code", "X-Wix-"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Squarespace": ["squarespace.com", "data-squarespace"],
    "Magento": ["Mage.Cookies", "/skin/frontend/", "magento"],
    "PrestaShop": ["prestashop", "/themes/default-bootstrap/"],
}


class TechStackChecker:
    # EOL signature table. Refreshed 2026-06-02 against endoflife.date.
    # Substring-matched against Server/X-Powered-By headers + body, so each key
    # is a header-style "Product/Version" token. Only versions that are genuinely
    # past their security-EOL date as of the refresh date are listed here; newer
    # supported branches are intentionally absent so they are not flagged.
    # review-by: 2026-12-02
    EOL_SIGNATURES = {
        "PHP/5": {"risk": "critical", "note": "PHP 5.x — end-of-life Dec 2018, no security patches"},
        "PHP/7.0": {"risk": "critical", "note": "PHP 7.0 — end-of-life Dec 2018"},
        "PHP/7.1": {"risk": "critical", "note": "PHP 7.1 — end-of-life Dec 2019"},
        "PHP/7.2": {"risk": "critical", "note": "PHP 7.2 — end-of-life Nov 2020"},
        "PHP/7.3": {"risk": "high", "note": "PHP 7.3 — end-of-life Dec 2021"},
        "PHP/7.4": {"risk": "high", "note": "PHP 7.4 — end-of-life Nov 2022"},
        "PHP/8.0": {"risk": "high", "note": "PHP 8.0 — end-of-life Nov 2023"},
        "PHP/8.1": {"risk": "medium", "note": "PHP 8.1 — security support ended Dec 2025"},
        "ASP.NET/1": {"risk": "critical", "note": "ASP.NET 1.x — end-of-life"},
        "ASP.NET/2": {"risk": "critical", "note": "ASP.NET 2.0 — end-of-life Jul 2011"},
        "ASP.NET/3": {"risk": "critical", "note": "ASP.NET 3.x — end-of-life"},
        "Apache/2.2": {"risk": "high", "note": "Apache httpd 2.2 — end-of-life Dec 2017"},
        "nginx/1.10": {"risk": "critical", "note": "nginx 1.10 — end-of-life"},
        "nginx/1.12": {"risk": "high", "note": "nginx 1.12 — end-of-life"},
        "nginx/1.14": {"risk": "high", "note": "nginx 1.14 — end-of-life Apr 2021"},
        "nginx/1.16": {"risk": "high", "note": "nginx 1.16 — end-of-life Apr 2021"},
        "nginx/1.18": {"risk": "medium", "note": "nginx 1.18 — end-of-life May 2021 (legacy stable)"},
        "OpenSSL/1.0": {"risk": "critical", "note": "OpenSSL 1.0.x — end-of-life Dec 2019"},
        "OpenSSL/1.1.0": {"risk": "high", "note": "OpenSSL 1.1.0 — end-of-life Sep 2019"},
        "OpenSSL/1.1.1": {"risk": "high", "note": "OpenSSL 1.1.1 — end-of-life Sep 2023"},
        # Node.js EOL (endoflife.date, even majors only have LTS)
        "Node.js/12": {"risk": "critical", "note": "Node.js 12.x — end-of-life Apr 2022"},
        "Node.js/14": {"risk": "critical", "note": "Node.js 14.x — end-of-life Apr 2023"},
        "Node.js/16": {"risk": "high", "note": "Node.js 16.x — end-of-life Sep 2023"},
        "Node.js/18": {"risk": "medium", "note": "Node.js 18.x — end-of-life Apr 2025"},
        "node/12": {"risk": "critical", "note": "Node.js 12.x — end-of-life Apr 2022"},
        "node/14": {"risk": "critical", "note": "Node.js 14.x — end-of-life Apr 2023"},
        "node/16": {"risk": "high", "note": "Node.js 16.x — end-of-life Sep 2023"},
        "node/18": {"risk": "medium", "note": "Node.js 18.x — end-of-life Apr 2025"},
        # Python 2 / early 3
        "Python/2": {"risk": "critical", "note": "Python 2.x — end-of-life Jan 2020"},
        "Python/3.6": {"risk": "high", "note": "Python 3.6 — end-of-life Dec 2021"},
        "Python/3.7": {"risk": "high", "note": "Python 3.7 — end-of-life Jun 2023"},
        "Python/3.8": {"risk": "medium", "note": "Python 3.8 — end-of-life Oct 2024"},
        # IIS EOL
        "Microsoft-IIS/6": {"risk": "critical", "note": "IIS 6.0 — end-of-life Jul 2015"},
        "Microsoft-IIS/7.0": {"risk": "critical", "note": "IIS 7.0 — end-of-life Jan 2020"},
        "Microsoft-IIS/7.5": {"risk": "high", "note": "IIS 7.5 — end-of-life Jan 2020"},
        "Microsoft-IIS/8.0": {"risk": "high", "note": "IIS 8.0 — end-of-life Oct 2023"},
        "Microsoft-IIS/8.5": {"risk": "medium", "note": "IIS 8.5 — end-of-life Oct 2023"},
        # Tomcat EOL
        "Apache-Coyote/1": {"risk": "critical", "note": "Tomcat/Coyote 1.x — end-of-life"},
        "Tomcat/7": {"risk": "critical", "note": "Apache Tomcat 7.x — end-of-life Mar 2021"},
        "Tomcat/8.0": {"risk": "critical", "note": "Apache Tomcat 8.0 — end-of-life Jun 2018"},
        "Tomcat/8.5": {"risk": "high", "note": "Apache Tomcat 8.5 — end-of-life Mar 2024"},
        "Tomcat/9": {"risk": "medium", "note": "Apache Tomcat 9.x — end-of-life Dec 2025"},
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
            r = HTTP.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                         allow_redirects=True)
            if r is None:
                raise RuntimeError("HTTP egress returned no response")
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

            # Check for EOL versions.
            # Anchor the version on a component boundary so a token like
            # `php/7.1` does NOT match the newer `php/7.10` / `php/7.12` branch
            # (a raw substring match did — falsely flagging a supported release
            # as EOL). The matched token must be followed by a non-digit (end of
            # string, whitespace, a patch dot like `7.1.33`, etc.), never by
            # another digit that would extend it to a different minor version.
            combined = (all_headers_str + body).lower()
            for sig, info in self.EOL_SIGNATURES.items():
                sig_l = sig.lower()
                # \D-or-end lookahead anchors the trailing version component.
                if re.search(re.escape(sig_l) + r"(?!\d)", combined):
                    result["eol_detected"].append({**info, "software": sig})
                    result["issues"].append(f"EOL software detected: {info['note']}")
                    if info["risk"] == "critical":
                        result["score"] -= 40
                    elif info["risk"] == "high":
                        result["score"] -= 25
                    elif info["risk"] == "medium":
                        result["score"] -= 10

            # CMS detection
            for cms, sigs in CMS_SIGNATURES.items():
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
                                cl = HTTP.get(f"https://{domain}/CHANGELOG.txt", timeout=5)
                                if cl is not None and cl.status_code == 200:
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

            result["eol_count"] = len(result["eol_detected"])

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
            r = HIBP.get(self.HIBP_URL, params={"domain": domain},
                         headers=headers, timeout=DEFAULT_TIMEOUT)
            if r is None:
                raise RuntimeError("HIBP egress returned no response")
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
            r = HTTP.get(f"http://{domain}", timeout=DEFAULT_TIMEOUT,
                         allow_redirects=True)
            return r.url.startswith("https://") if r is not None else False
        except Exception:
            return False

    def _check_cookies(self, domain: str) -> dict:
        info = {"secure": True, "httponly": True, "samesite": True, "details": []}
        try:
            r = HTTP.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                         allow_redirects=True)
            for cookie in (r.cookies if r is not None else []):
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
            r = HTTP.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                         allow_redirects=True)
            if r is None:
                return False
            return bool(re.search(r'<(?:script|img|link|iframe)[^>]+src=["\']http://', r.text[:50000], re.I))
        except Exception:
            return False

    def _detect_cms(self, domain: str) -> dict:
        try:
            r = HTTP.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT,
                         allow_redirects=True)
            if r is None:
                return {"detected": None, "version": None}
            combined = r.text[:100000] + str(r.headers)
            for cms, sigs in CMS_SIGNATURES.items():
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
        probed = 0
        for path in self.PAYMENT_PATHS:
            # WAF-aware early-exit: stop enumerating once the apex is hard-blocking.
            if HTTP.stop_probing(domain, probed):
                result["waf_truncated"] = True
                break
            try:
                r = HTTP.get(f"https://{domain}{path}", timeout=4,
                             allow_redirects=True)
                probed += 1
                if r is not None and r.status_code == 200:
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
            r = NVD.get(self.NVD_URL, params={"cveId": cve_id},
                        headers={"User-Agent": USER_AGENT}, timeout=8)
            if r is None or r.status_code != 200:
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
            r = SHODAN.get(self.SHODAN_HOST_URL.format(ip=ip),
                           params={"key": api_key},
                           headers={"User-Agent": USER_AGENT}, timeout=15)
            if r is None:
                return False
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
        r = INTERNETDB.get(self.INTERNETDB_URL.format(ip=ip),
                           headers={"User-Agent": USER_AGENT}, timeout=10)
        if r is None:
            # No local try/except here — preserve the original raise-on-failure.
            raise requests.RequestException("InternetDB egress returned no response")
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
                r = KEV.get(url, timeout=15,
                            headers={"User-Agent": USER_AGENT})
                if r is not None and r.status_code == 200:
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
            r = MSF.get(self.MSF_MODULES_URL, timeout=25,
                        headers={"User-Agent": USER_AGENT})
            if r is not None and r.status_code == 200:
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
            r = EXPLOITDB.get(self.EXPLOITDB_CSV_URL, timeout=25,
                              headers={"User-Agent": USER_AGENT})
            if r is not None and r.status_code == 200:
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
            r = EPSS.get(self.EPSS_URL,
                         params={"cve": ",".join(cve_ids[:30])},
                         headers={"User-Agent": USER_AGENT}, timeout=10)
            if r is not None and r.status_code == 200:
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
    # review-by: 2026-12-02
    # Hand-maintained, point-in-time attribution: new CVEs are weaponised by
    # ransomware affiliates continuously, so this map drifts. Review by the date
    # above (add newly-weaponised CVEs, retire stale family attributions).
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
    # review-by: 2026-12-02
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
            ip = ip or dns_cache.get_ip(domain)
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
            resp = OSV.post(self.OSV_API_URL, json=payload, timeout=10)
            if resp is not None and resp.status_code == 200:
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
                resp = OSV.post(self.OSV_API_URL, json=payload, timeout=10)
                if resp is not None and resp.status_code == 200:
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
            cvss_estimated = False
            cve_id = None
            # Extract CVE alias
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
            # Extract a REAL numeric CVSS only (never fabricate one from the
            # vector string — that synthesises a precise score the source
            # never stated).
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        # Numeric score directly
                        cvss_score = float(score_str) if score_str.replace(".", "").isdigit() else None
                    except (ValueError, TypeError):
                        pass
            # Determine severity. Prefer a real CVSS; otherwise fall back to
            # the source's own database_specific.severity, else "unknown".
            # We do NOT invent a numeric CVSS from the vector — when only a
            # qualitative severity is available the field is flagged
            # `cvss_estimated` so renderers/score can tell it apart from a
            # real measured score.
            db_sev = v.get("database_specific", {}).get("severity")
            if cvss_score:
                severity = ("critical" if cvss_score >= 9.0 else "high" if cvss_score >= 7.0
                           else "medium" if cvss_score >= 4.0 else "low")
            elif db_sev:
                severity = db_sev.lower()
                cvss_estimated = True
            else:
                severity = "unknown"
                cvss_estimated = True

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
                "cvss_estimated": cvss_estimated,  # True when severity is
                                                   # qualitative/unknown, not a
                                                   # measured numeric CVSS
                "epss": None,  # populated during merge if available
                "published": published,
                "source": "osv.dev",
            })
        return results


# ---------------------------------------------------------------------------
# 21. Dehashed Credential Leak Checker (optional API key)
# ---------------------------------------------------------------------------

def _mask_identifier(value: str) -> str:
    """Partial-reveal mask: first two + last char of the local part, e.g.
    'john.doe@takealot.com' -> 'jo***e@takealot.com'. Verifiable by the owner,
    not reconstructable by an outsider. Works for bare usernames too."""
    value = str(value or "").strip()
    if not value:
        return ""
    if "@" in value:
        local, _, dom = value.partition("@")
        masked = (local[:2] + "***" + local[-1]) if len(local) > 2 else ((local[0] if local else "") + "***")
        return masked + "@" + dom
    return (value[:2] + "***" + value[-1]) if len(value) > 2 else (value[0] + "***")


class DehashedChecker:
    """
    Queries Dehashed for credential leaks associated with the domain.
    Requires DEHASHED_API_KEY env var (paid subscription with credits).
    Uses v2 API (POST with JSON body, API key header).
    Falls back gracefully with status='no_api_key' when credentials are absent.
    """
    API_URL_V2 = "https://api.dehashed.com/v2/search"
    API_URL_V1 = "https://api.dehashed.com/search"

    # Hash type detection patterns (order matters — check specific patterns first)
    HASH_PATTERNS = [
        ("bcrypt",  re.compile(r'^\$2[aby]\$\d{2}\$.{53}$')),
        ("argon2",  re.compile(r'^\$argon2(i|d|id)\$')),
        ("scrypt",  re.compile(r'^\$s0\$')),
        ("SHA-512", re.compile(r'^[a-fA-F0-9]{128}$')),
        ("SHA-256", re.compile(r'^[a-fA-F0-9]{64}$')),
        ("SHA-1",   re.compile(r'^[a-fA-F0-9]{40}$')),
        ("MD5",     re.compile(r'^[a-fA-F0-9]{32}$')),
        ("NTLM",    re.compile(r'^[a-fA-F0-9]{32}$')),  # Same as MD5 — context-dependent
    ]
    WEAK_HASH_TYPES = {"MD5", "SHA-1", "NTLM"}
    STRONG_HASH_TYPES = {"bcrypt", "argon2", "scrypt", "SHA-256", "SHA-512"}

    @classmethod
    def _classify_hash(cls, hash_string: str) -> str:
        """Identify hash type from its string representation."""
        if not hash_string or not isinstance(hash_string, str):
            return "unknown"
        h = hash_string.strip()
        if not h or len(h) < 8:
            return "unknown"
        for name, pattern in cls.HASH_PATTERNS:
            if pattern.match(h):
                return name
        return "unknown"

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
        r = DEHASHED.post(
            self.API_URL_V2,
            json={"query": f"domain:{domain}", "page": 1, "size": 100},
            headers={
                "Content-Type": "application/json",
                "Dehashed-Api-Key": api_key,
                "User-Agent": USER_AGENT,
            },
            timeout=15,
        )

        # Fall back to v1 if v2 fails completely
        if r is None or r.status_code == 404:
            r = DEHASHED.get(
                self.API_URL_V1,
                params={"query": f"domain:{domain}", "size": 100},
                auth=(email or "", api_key),
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                timeout=15,
            )
            if r is None:
                result["status"] = "error"
                result["error"] = "Dehashed egress returned no response"
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
            # Credential breakdown tracking
            plaintext_count = 0
            hashed_count = 0
            hash_types = {}
            corporate_count = 0
            personal_count = 0

            for entry in entries:
                # v2 API returns email as list, v1 as string
                em = entry.get("email", "")
                # Email addresses are case-insensitive on the mailbox side; lower-case
                # (and strip) before uniqueness so Rudolph@x and rudolph@x don't count
                # as two distinct mailboxes (also de-dupes the masked staff list).
                if isinstance(em, list):
                    for e in em:
                        if e:
                            emails_seen.add(str(e).strip().lower())
                elif em:
                    emails_seen.add(str(em).strip().lower())

                pw = entry.get("password")
                hpw = entry.get("hashed_password")
                if isinstance(pw, list):
                    pw = pw[0] if pw else None
                if isinstance(hpw, list):
                    hpw = hpw[0] if hpw else None
                if pw or hpw:
                    has_pw = True

                # Credential type classification
                hash_type = "unknown"
                if pw and str(pw).strip():
                    plaintext_count += 1
                elif hpw and str(hpw).strip():
                    hashed_count += 1
                    hash_type = self._classify_hash(str(hpw))
                    hash_types[hash_type] = hash_types.get(hash_type, 0) + 1

                # Corporate vs personal email classification
                email_str_raw = ", ".join(em) if isinstance(em, list) else (em or "")
                if domain.lower() in email_str_raw.lower():
                    corporate_count += 1
                elif email_str_raw:
                    personal_count += 1

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
                    "hash_type": hash_type if hpw else None,
                })

            result["unique_emails"] = len(emails_seen)
            result["has_passwords"] = has_pw
            result["sample_emails"] = [
                e[:40] + ("\u2026" if len(e) > 40 else "") for e in list(emails_seen)[:5]
            ]
            # Masked STAFF accounts (on-domain) for the full-report enumeration.
            # Partial reveal so the org recognises its own accounts but an
            # outsider cannot reconstruct them. NO passwords stored (those are
            # only ever in the on-demand encrypted export).
            corporate_emails = sorted(e for e in emails_seen if domain.lower() in e.lower())
            result["staff_accounts_total"] = len(corporate_emails)
            result["staff_accounts_masked"] = [_mask_identifier(e) for e in corporate_emails[:60]]
            result["breach_sources"] = list(breach_sources)
            result["breach_details"] = breach_details[:20]

            # Credential breakdown summary
            weak_hash_count = sum(v for k, v in hash_types.items() if k in self.WEAK_HASH_TYPES)
            strong_hash_count = sum(v for k, v in hash_types.items() if k in self.STRONG_HASH_TYPES)
            result["credential_breakdown"] = {
                "plaintext_count": plaintext_count,
                "hashed_count": hashed_count,
                "hash_types": hash_types,
                "weak_hash_count": weak_hash_count,
                "strong_hash_count": strong_hash_count,
                "corporate_count": corporate_count,
                "personal_count": personal_count,
            }

            if total > 0:
                src_list = ", ".join(list(breach_sources)[:5])
                result["issues"].append(
                    f"{total} credential record(s) found in Dehashed for this domain "
                    f"(sources: {src_list}) — notify affected users and enforce password reset"
                )
            if plaintext_count > 0:
                result["issues"].append(
                    f"{plaintext_count} plaintext password(s) found — immediate credential stuffing risk"
                )
            if weak_hash_count > 0:
                weak_names = ", ".join(k for k in hash_types if k in self.WEAK_HASH_TYPES)
                result["issues"].append(
                    f"{weak_hash_count} credential(s) use weak hashing ({weak_names}) — easily crackable with modern tools"
                )
            if has_pw and not plaintext_count and not weak_hash_count:
                result["issues"].append(
                    "Hashed passwords found in leaked records — "
                    "enforce password reset and review authentication systems"
                )

            # Enhanced scoring: plaintext more severe than hashes
            penalty = min(100, plaintext_count * 5 + weak_hash_count * 3 +
                          strong_hash_count * 1 + max(0, total - plaintext_count - hashed_count) * 2)
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
            r = VIRUSTOTAL.get(
                self.API_URL.format(domain=domain),
                headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
                timeout=15,
            )
            if r is None:
                raise RuntimeError("VirusTotal egress returned no response")

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
            r = SECURITYTRAILS.get(
                self.DOMAIN_URL.format(domain=domain),
                headers=headers, timeout=15,
            )
            if r is None:
                raise RuntimeError("SecurityTrails egress returned no response")
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
                r2 = SECURITYTRAILS.get(
                    self.ASSOC_URL.format(domain=domain),
                    headers=headers, timeout=15,
                )
                if r2 is not None and r2.status_code == 200:
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
            # Infection-date freshness anchors (the API already returns these;
            # they prove the infostealer data is ACTIVE, not recycled).
            "last_employee_compromised": None,
            "last_user_compromised": None,
            "most_recent_compromise": None,
            "days_since_compromise": None,
            "stealer_families": [],
            # Services whose logins were captured from infected EMPLOYEE
            # devices — the most actionable remediation list (which systems to
            # rotate). Service endpoints, not credentials, so safe to show.
            "compromised_services": [],
            "compromised_services_total": 0,
            "score": 100,
            "issues": [],
        }
        try:
            r = HUDSONROCK.get(f"{self.API_URL}?domain={domain}",
                               headers={"User-Agent": USER_AGENT}, timeout=15)
            if r is None or r.status_code != 200:
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

            # Infection dates — point-in-time malware capture dates, NOT
            # re-compiled breach data, so these are the reliable "is this
            # active?" signal. Take the most recent of the two.
            le = (data.get("last_employee_compromised") or "")[:10] or None
            lu = (data.get("last_user_compromised") or "")[:10] or None
            result["last_employee_compromised"] = le
            result["last_user_compromised"] = lu
            dates = [d for d in (le, lu) if d]
            if dates:
                most_recent = max(dates)
                result["most_recent_compromise"] = most_recent
                try:
                    from datetime import datetime, timezone
                    dt = datetime.strptime(most_recent, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    result["days_since_compromise"] = max(0, (datetime.now(timezone.utc) - dt).days)
                except Exception:
                    pass
            fam = data.get("stealerFamilies")
            if isinstance(fam, dict):
                result["stealer_families"] = [
                    k for k, v in fam.items()
                    if k != "total" and isinstance(v, (int, float)) and v > 0][:8]
            # Captured employee service-logins (which systems to rotate first)
            emp_urls = (data.get("data") or {}).get("employees_urls") or []
            svc = [{"url": str(u.get("url"))[:120], "occurrence": int(u.get("occurrence", 0) or 0)}
                   for u in emp_urls if isinstance(u, dict) and u.get("url")]
            svc.sort(key=lambda x: -x["occurrence"])
            result["compromised_services"] = svc[:15]
            result["compromised_services_total"] = len(emp_urls)

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
            r = HIBP.get(self.BREACHES_URL,
                         headers={"User-Agent": USER_AGENT}, timeout=15)
            if r is not None and r.status_code == 200:
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
                # Fall back to curated dates for known compilation / combo
                # lists that are NOT in HIBP's named-breach catalog (the rough
                # date "guesstimate" before further enrichment). Without this,
                # stuffing lists like ALIEN TXTBASE / Naz.API return "Unknown".
                fallback = CredentialRiskClassifier.KNOWN_BREACH_DATES.get(source_lower)
                enriched_sources.append({
                    "name": source,
                    "breach_date": fallback or "Unknown",
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
        "naz.api": "2024-09-01",
        "apollo": "2018-07-23",
        "socradar.io": "2024-08-01",
        "collection #1": "2019-01-01",
        "collection #2-5": "2019-01-01",
        "anti public combo list": "2016-12-01",
        "exploit.in": "2017-05-01",
        "rockyou2024": "2024-07-01",
        "rockyou2021": "2021-06-01",
    }

    # --- Credential-confidence model (K1-K7) - FIN-9 / 5L calibration -------
    # Per-record weight  w = K1[confidence] x K2[recency] x (K3 if combo),
    # summed to W; W -> class (K4); class -> p(breach) posture slot (K5) +
    # report-only risk_score (K5b). Replaces the confidence-blind
    # `total_entries x 2`. PROPOSED (SANDBOX, FIN-9 2026-06-03); ranges and
    # colleague-gated items in docs/calibration_prep/02_credential_pbreach.md.
    K1_CONFIDENCE = {"high": 1.0, "med": 0.4, "low": 0.1}  # plaintext / hash / email-only
    K2_RECENCY_BANDS = ((90, 1.0), (180, 0.8), (360, 0.6), (730, 0.4))  # (max_age_d, mult)
    K2_FLOOR = 0.25  # >2yr or undated (IBM CoDB 292d dwell -> slow decay, no cliff)
    K3_COMBO_DISCOUNT = 0.3  # combo/aggregator lists (COLLEAGUE-GATED Q-A; band 0.25-0.4)
    K4_THRESHOLDS = ((4.0, "CRITICAL"), (2.0, "HIGH"), (0.8, "MEDIUM"), (0.2, "LOW"))  # else NONE
    K5_PBREACH_CONTRIBUTION = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 35, "LOW": 10, "NONE": 0}
    K5_RISK_SCORE = {"CRITICAL": 0, "HIGH": 25, "MEDIUM": 55, "LOW": 85, "NONE": 100}  # report-only, higher=safer
    L3_HR_STALE_DAYS = 180  # confirmed HR infection older than this decays CRITICAL->HIGH (gated 180-365)
    COMBO_SOURCE_TOKENS = (
        "combo", "collection #", "alien txtbase", "naz.api", "rockyou",
        "exploit.in", "anti public", "apollo", "socradar", "bureau van dijk",
        "telegram", "stealer log", "compilation",
    )

    @staticmethod
    def classify(dehashed: dict, hudson_rock: dict, intelx: dict = None, hibp_enriched: dict = None) -> dict:
        """Confidence-weighted credential-risk classification (K1-K7 model).

        Replaces the old confidence-blind deduction ladder (darkweb x-10 /
        paste x-3, uncapped) with a per-record weighted sum: every DeHashed
        record scores w = K1[confidence] x K2[recency] x (K3 if combo). The
        records sum to W; W maps to a class (K4); the class maps to a
        p(breach) posture contribution (K5) and the report-only risk_score.
        A confirmed Hudson Rock infostealer infection is a hard class FLOOR
        (L3) the weighted sum can never lower. IntelX dark-web mentions are
        report-only (K7=0): aggregated-index / browser-history noise must not
        score as credential theft. See
        docs/calibration_prep/02_credential_pbreach.md.
        """
        from datetime import datetime, timezone
        cls_self = CredentialRiskClassifier
        K1 = cls_self.K1_CONFIDENCE
        today = datetime.now(timezone.utc).date()

        def _is_combo(source):
            s = (source or "").strip().lower()
            return any(tok in s for tok in cls_self.COMBO_SOURCE_TOKENS)

        def _recency_mult(date_str):
            if not date_str or str(date_str).strip().lower() in ("", "unknown", "none"):
                return cls_self.K2_FLOOR
            try:
                d = datetime.strptime(str(date_str)[:10], "%Y-%m-%d").date()
            except (ValueError, TypeError):
                return cls_self.K2_FLOOR
            age = max(0, (today - d).days)
            for max_age, mult in cls_self.K2_RECENCY_BANDS:
                if age <= max_age:
                    return mult
            return cls_self.K2_FLOOR

        # Per-source breach date: prefer HIBP enrichment, fall back to the
        # KNOWN_BREACH_DATES table for sources HIBP does not track.
        src_date = {}
        for src in (dehashed.get("enriched_sources", []) or []):
            nm = (src.get("name") or "").strip().lower()
            if nm:
                src_date[nm] = src.get("breach_date", "Unknown")

        def _date_for(source):
            s = (source or "").strip().lower()
            dt = src_date.get(s)
            if dt and dt not in ("Unknown", ""):
                return dt
            return cls_self.KNOWN_BREACH_DATES.get(s, "Unknown")

        # ---- K1-K3: weight every DeHashed record by what it actually carries.
        records = dehashed.get("breach_details", []) or []
        W = 0.0
        high_records = med_records = 0
        password_sources = set()
        recent_pw_sources = set()
        for r in records:
            has_pw = bool(r.get("has_password"))
            has_hash = bool(r.get("has_hash"))
            if has_pw:
                k1 = K1["high"]; high_records += 1
            elif has_hash:
                k1 = K1["med"]; med_records += 1
            else:
                k1 = K1["low"]
            src = r.get("database", "") or ""
            k2 = _recency_mult(_date_for(src))
            k3 = cls_self.K3_COMBO_DISCOUNT if _is_combo(src) else 1.0
            W += k1 * k2 * k3
            if has_pw or has_hash:
                password_sources.add(src or "unknown")
                if k2 >= 0.6:
                    recent_pw_sources.add(src or "unknown")

        # ---- K4: summed weight -> class.
        cls = "NONE"
        for min_w, name in cls_self.K4_THRESHOLDS:
            if W >= min_w:
                cls = name
                break

        # ---- L3: a confirmed Hudson Rock infection is a hard class FLOOR that
        # can only RAISE the class, never lower it (the weighted sum governs the
        # DeHashed/IntelX corpus and must never down-grade a real infection).
        hr_employees = hudson_rock.get("compromised_employees", 0) or 0
        hr_users = hudson_rock.get("compromised_users", 0) or 0
        hr_days = hudson_rock.get("days_since_compromise")
        active_compromise = bool(hr_employees or hr_users)
        order = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        def _raise_to(current, floor):
            return floor if order.index(floor) > order.index(current) else current

        stale_infection = isinstance(hr_days, (int, float)) and hr_days > cls_self.L3_HR_STALE_DAYS
        if hr_employees > 0:
            cls = _raise_to(cls, "HIGH" if stale_infection else "CRITICAL")
        elif hr_users > 0:
            cls = _raise_to(cls, "HIGH")

        # ---- K5: class -> contributions. risk_level stays display-compatible
        # (CRITICAL/HIGH/MEDIUM/LOW); NONE collapses to LOW for display but
        # contributes 0 to the posture channel.
        pbreach_contribution = cls_self.K5_PBREACH_CONTRIBUTION[cls]
        risk_score = cls_self.K5_RISK_SCORE[cls]
        risk_level = "LOW" if cls == "NONE" else cls

        # ---- Factors (human-readable; IntelX lines are report-only). ----------
        factors = []
        if hr_employees > 0:
            if stale_infection:
                factors.append(f"INFOSTEALER (stale): {hr_employees} employee device(s) infected, last seen ~{int(hr_days)}d ago")
            else:
                factors.append(f"ACTIVE INFOSTEALER: {hr_employees} employee device(s) infected - credentials may be exfiltrating in real time")
        if hr_users > 0:
            factors.append(f"{hr_users} user account(s) compromised via infostealer malware")
        total_records = len(records)
        if high_records or med_records:
            factors.append(
                f"{high_records} plaintext-password and {med_records} hashed-credential record(s) "
                f"of {total_records} exposed (confidence-weighted W={W:.2f}); "
                f"source(s): {', '.join(sorted(password_sources)) or 'n/a'}"
            )
        elif total_records:
            n_src = len({(r.get('database') or '') for r in records})
            factors.append(
                f"{total_records} email-only breach record(s) across {n_src} source(s) - "
                f"no password/hash on record (confidence-weighted W={W:.2f})"
            )
        if recent_pw_sources:
            factors.append("Recent (<=1yr) credential exposure: " + ", ".join(sorted(recent_pw_sources)))
        if intelx and isinstance(intelx, dict):
            dw = intelx.get("darkweb_count", 0) or 0
            pst = intelx.get("paste_count", 0) or 0
            if dw or pst:
                factors.append(
                    f"IntelX: {dw} dark-web and {pst} paste mention(s) - monitoring signal, "
                    "not confirmed credential theft (no score impact)"
                )

        summary_by_level = {
            "CRITICAL": ("CRITICAL credential risk - active infostealer infection or fresh password "
                         "capture. Force resets, enable MFA, isolate infected devices, engage IR."),
            "HIGH": ("HIGH credential risk - confirmed credential exposure (passwords/hashes) or a "
                     "stale infostealer infection. Force resets, enable MFA, monitor for stuffing."),
            "MEDIUM": ("MEDIUM credential risk - some confidence-weighted credential exposure. "
                       "Review affected accounts, enforce MFA, monitor."),
            "LOW": ("LOW credential risk - exposure is historical and/or email-only (no fresh, "
                    "high-confidence passwords; no active infection)."),
        }

        return {
            "risk_level": risk_level,
            "credential_class": cls,
            "risk_score": risk_score,
            "pbreach_contribution": pbreach_contribution,
            "weighted_exposure": round(W, 3),
            "active_compromise": active_compromise,
            "factors": factors,
            "summary": summary_by_level[risk_level],
        }


# ---------------------------------------------------------------------------
# 27. IntelX Dark Web Monitoring (free tier)
# ---------------------------------------------------------------------------

class IntelXChecker:
    """
    Searches Intelligence X for dark web pastes, leaked documents, and
    breach data associated with a domain. Two-step: initiate search, poll results.
    Free tier: 40 results/search; /intelligent/search CreditMax = 50 per DAY,
    reset at midnight UTC (NOT ~500 — verified 2026-05-31 against
    /authenticate/info; IntelX docs: "credits reset at midnight UTC"). Max 3
    concurrent searches.
    """
    API_URL = "https://free.intelx.io"
    # Single source of truth for the requested-and-displayed result cap. The
    # free API does not strictly honour maxresults (it returned 60 for a
    # maxresults:40 request), so we truncate the returned records to this same
    # cap — the displayed total is then bounded by the request and reproducible.
    MAX_RESULTS = 40

    # Infostealer-log filename signatures. IntelX's dominant content is
    # stealer-log dumps whose media type is generic text (not media==13), so
    # they would otherwise all fall into `leak_count` and darkweb_count stays 0
    # even for genuine criminal-forum/market harvest. These tokens identify a
    # record as dark-web-grade infostealer harvest.
    # review-by: 2026-12-02
    _STEALER_TOKENS = (
        "stealer", "redline", "raccoon", "vidar", "lumma", "meta stealer",
        "_default.txt", " default.txt", "/default.txt", "autofill",
        "passwords.txt", "cookies.txt", "credit_cards", "screenshot",
    )

    @classmethod
    def _is_darkweb_grade(cls, rec: dict, media: int) -> bool:
        """True if the record is dark-web-grade (criminal forum/market or
        infostealer-log harvest) rather than a generic leak-DB entry."""
        if media == 13:  # IntelX explicit darkweb media type
            return True
        name = (rec.get("name") or "").lower()
        bucket = (rec.get("bucket") or "").lower()
        # IntelX buckets like "leaks.logs.*" / "darknet.*" carry stealer logs.
        if any(b in bucket for b in ("darknet", "logs", "stealer")):
            return True
        return any(tok in name for tok in cls._STEALER_TOKENS)

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
            r = INTELX.post(f"{self.API_URL}/intelligent/search",
                json={"term": domain, "maxresults": self.MAX_RESULTS, "timeout": 5, "sort": 4, "media": 0},
                headers={"X-Key": api_key}, timeout=15)
            if r is None:
                raise RuntimeError("IntelX egress returned no response")
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
                r2 = INTELX.get(f"{self.API_URL}/intelligent/search/result",
                    params={"id": search_id},
                    headers={"X-Key": api_key}, timeout=10)
                if r2 is None or r2.status_code != 200:
                    break
                data = r2.json()
                records.extend(data.get("records", []))
                if data.get("status") in (1, 2, 4):  # 1=done, 2=not found, 4=error
                    break
                _time.sleep(2)

            # The free API does not strictly honour maxresults, so truncate to
            # the requested cap — the displayed total is then reproducible and
            # bounded by the request rather than reflecting an arbitrary
            # over-return (observed 60 returned for a 40-cap request).
            if len(records) > self.MAX_RESULTS:
                result["result_cap_applied"] = True
            records = records[:self.MAX_RESULTS]
            result["total_results"] = len(records)

            # Classify results by type
            for rec in records:
                media = rec.get("media", 0)
                # media types: 1=paste, 2=paste, 5=email, 13=darkweb, 14=document
                if media in (1, 2):
                    result["paste_count"] += 1
                elif self._is_darkweb_grade(rec, media):
                    # Genuine criminal-forum/market or infostealer-log harvest —
                    # darkweb-grade even when media != 13 (stealer dumps are
                    # served as generic text and would otherwise be miscounted
                    # as leak-DB entries).
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

    # Homoglyph map (visually similar ASCII characters)
    HOMOGLYPHS = {
        "a": ["4", "@"], "b": ["d", "6"], "c": ["k"],
        "e": ["3"], "g": ["q", "9"], "i": ["1", "l", "!"],
        "l": ["1", "i", "|"], "o": ["0"], "s": ["5", "$"],
        "t": ["7"], "u": ["v"], "v": ["u"], "z": ["2"],
    }

    # IDN / Unicode confusables (homoglyph attack — the dominant real-world
    # lookalike vector). Cyrillic / Greek look-alikes that render almost
    # identically to Latin letters. Kept deliberately small and high-confidence
    # so the candidate count does not explode; one substitution per candidate.
    IDN_HOMOGLYPHS = {
        "a": "а",  # Cyrillic a
        "c": "с",  # Cyrillic es
        "e": "е",  # Cyrillic ie
        "i": "і",  # Cyrillic byelorussian-ukrainian i
        "o": "о",  # Cyrillic o
        "p": "р",  # Cyrillic er
        "s": "ѕ",  # Cyrillic dze
        "x": "х",  # Cyrillic ha
        "y": "у",  # Cyrillic u
        "d": "ԁ",  # Cyrillic komi de
        "n": "ո",  # Armenian vo (looks like n)
        "g": "ɡ",  # Latin small script g
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

        # 9. IDN / Unicode confusable substitution (homoglyph attack).
        #    Substitute a single Latin letter with a visually-identical
        #    Cyrillic/Greek/etc. glyph and IDNA-encode to the registrable
        #    punycode (xn--) form so DNS resolution can be checked. Bounded:
        #    one substitution per candidate, capped to keep the count sane.
        idn_added = 0
        for i, ch in enumerate(name):
            repl = self.IDN_HOMOGLYPHS.get(ch)
            if not repl:
                continue
            unicode_variant = name[:i] + repl + name[i+1:] + original_tld
            try:
                puny = unicode_variant.encode("idna").decode("ascii")
            except (UnicodeError, ValueError):
                continue
            # IDNA round-trips a pure-ASCII string unchanged; only keep genuine
            # IDN (xn--) candidates so we don't duplicate the ASCII techniques.
            if "xn--" not in puny:
                continue
            add(puny, "idn-homoglyph", 95)
            idn_added += 1
            if idn_added >= 12:  # hard cap — don't explode the candidate set
                break

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
        then falls back to candidate-path probing through the shared
        HttpClient (rate-limited + WAF-tracked).

        Refactored 2026-05-15 (SCN-025) to route through the global
        HTTP singleton instead of direct requests calls. The rate
        limiter caps per-apex burst rate at 2 req/sec, which means the
        candidate-path probe phase paces itself naturally and stops
        tripping target WAFs. WAF interventions (challenge pages,
        consistent 403/429 patterns, timeouts) are tracked at the
        client level and surfaced in the scan output."""
        import re as _re
        from http_client import HTTP

        # --- Strategy 1: Crawl homepage for privacy links (fastest) ---
        # Try with and without www prefix
        homepage_url = f"https://{domain}"
        r = HTTP.get(homepage_url, timeout=12, allow_redirects=True)
        if r is not None and r.status_code == 200:
            try:
                text = r.text.lower()
            except Exception:
                text = ""
            if text:
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
                # Resolve candidate hrefs to absolute URLs, then probe them
                # via the shared HTTP client (rate-limited).
                candidate_hrefs = []
                for href in all_matches[:5]:
                    if href.startswith("/"):
                        href = f"https://{domain}{href}"
                    elif not href.startswith("http"):
                        href = f"https://{domain}/{href}"
                    candidate_hrefs.append(href)
                if candidate_hrefs:
                    hit = self._probe_urls_concurrent(candidate_hrefs, timeout=10, max_workers=3)
                    if hit:
                        return hit

        # --- Strategy 2: Probe common paths via HTTP client. The shared
        # rate limiter paces this naturally (2 req/sec per apex by default)
        # so we no longer need an aggressive ThreadPoolExecutor here.
        # max_workers reduced 8 -> 3 to leave headroom for parallel
        # checkers; the rate limiter does the real pacing work.
        domains_to_try = [domain]
        if not domain.startswith("www."):
            domains_to_try.append(f"www.{domain}")
        candidate_urls = [
            f"https://{d}{path}"
            for d in domains_to_try
            for path in self.POLICY_PATHS
        ]
        hit = self._probe_urls_concurrent(candidate_urls, timeout=8, max_workers=3)
        if hit:
            return hit

        return None, None

    @staticmethod
    def _probe_urls_concurrent(urls, timeout=8, max_workers=3):
        """Probe a list of candidate URLs via the shared HTTP client.

        Uses HEAD-first via HTTP.discover() to reduce bandwidth and avoid
        body-content WAF rules. Returns the first (url, text_lower) tuple
        for a URL that responds 200 (validated with a follow-up GET for the
        body), or None if no candidate matches. Rate limiting is handled
        centrally by the HttpClient - this method controls only the
        first-match short-circuit semantics."""
        if not urls:
            return None
        from http_client import HTTP
        import threading as _threading
        _probed = {"n": 0}
        _plock = _threading.Lock()

        def _probe(url):
            # WAF-aware early-exit: once we've probed enough candidates and the apex
            # is hard-blocking, skip the rest (they'd all be 403s) — no network, no
            # rate-limit wait.
            with _plock:
                n = _probed["n"]
                _probed["n"] += 1
            if HTTP.stop_probing(url, n):
                return None
            # HEAD-first to check existence cheaply
            r = HTTP.discover(url, timeout=timeout, allow_redirects=True)
            if r is None or r.status_code != 200:
                return None
            # Confirmed-exists; pull the body so we can grade it
            r2 = HTTP.get(url, timeout=timeout, allow_redirects=True)
            if r2 is None or r2.status_code != 200:
                return None
            try:
                body = r2.text.lower()
            except Exception:
                return None
            if len(body) < 500:
                return None
            return (url, body)

        # Global wall ceiling: timeout * (urls / workers) + slack, capped
        # at 35s. Prevents pathological per-probe stalls from dragging
        # the whole probe phase past ~30-35s.
        import math
        wall_ceiling = min(35, max(timeout * 2,
                                    int(math.ceil(len(urls) / max_workers) * timeout) + 5))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(_probe, u): u for u in urls}
            try:
                for fut in as_completed(futures, timeout=wall_ceiling):
                    result = fut.result()
                    if result:
                        # Short-circuit: cancel remaining futures so we
                        # don't keep paying for slow probes once a hit lands.
                        for f in futures:
                            if f is not fut and not f.done():
                                f.cancel()
                        return result
            except (TimeoutError, FuturesTimeoutError):
                pass
        return None

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
            r = TRANCO.get(self.TRANCO_URL, timeout=30)
            if r is not None and r.status_code == 200:
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

class GlasswingPartnerChecker:
    """
    Anthropic Project Glasswing partner lookup. Partners publicly listed on
    Anthropic's Glasswing programme page apply Claude-assisted vulnerability
    discovery and patching — which meaningfully compresses their exposure
    window to novel vulnerabilities.

    Detection is a binary match against a static public list (name or domain).
    Positive match is treated as a favourable risk signal (RSI reduction).

    Matching strategy (in order):
      1. Exact domain match against partner domain list.
      2. Substring match on target domain (e.g. `hackerone.com` matches "hackerone").
      3. Website title/meta lookup for partner brand keywords — cheap HTTP probe.
    """

    # Public partner list — Anthropic Project Glasswing (April 2026 snapshot).
    # Update this list periodically from the Anthropic partner programme page.
    PARTNERS = {
        "hackerone.com":      "HackerOne",
        "carahsoft.com":      "Carahsoft",
        "torq.io":            "Torq",
        "xbow.com":           "XBOW",
        "deeptempo.ai":       "DeepTempo",
        "trustwise.ai":       "Trustwise",
        "dreadnode.io":       "Dreadnode",
        "rootevidence.com":   "Root Evidence",
        "realmsecurity.ai":   "Realm Security",
        "superluminal.ai":    "Superluminal",
        "twinesecurity.com":  "Twine Security",
        "virtueai.com":       "Virtue AI",
    }

    # Keywords used for secondary brand match against HTML <title>/<meta>.
    # Only matched when combined with the word "glasswing" or "anthropic".
    BRAND_KEYWORDS = {name.lower(): canonical for _, canonical in PARTNERS.items()
                      for name in [canonical]}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "is_partner": False,
            "partner_name": None,
            "match_method": None,
            "score_bonus": 0,
            "narrative": "",
            "issues": [],
        }
        d = (domain or "").lower().strip()
        if not d:
            result["status"] = "error"
            return result

        # 1. Exact domain match
        if d in self.PARTNERS:
            result.update(is_partner=True, partner_name=self.PARTNERS[d],
                          match_method="exact_domain", score_bonus=10)

        # 2. Substring match — handles subdomains (e.g. blog.hackerone.com)
        if not result["is_partner"]:
            for partner_domain, name in self.PARTNERS.items():
                # match if target is same apex or a subdomain of the partner
                if d == partner_domain or d.endswith("." + partner_domain):
                    result.update(is_partner=True, partner_name=name,
                                  match_method="domain_suffix", score_bonus=10)
                    break

        # 3. Optional HTML probe for self-declared Glasswing partnership.
        # Only runs when no domain match was made — cheap single GET.
        if not result["is_partner"] and REQUESTS_AVAILABLE:
            try:
                r = HTTP.get(f"https://{domain}", timeout=5,
                             allow_redirects=True)
                html = (r.text or "")[:20000].lower() if r is not None else ""
                if ("project glasswing" in html or
                        ("glasswing" in html and "anthropic" in html)):
                    result.update(is_partner=True,
                                  partner_name="Self-declared Glasswing partner",
                                  match_method="html_declaration", score_bonus=5)
            except Exception:
                pass

        if result["is_partner"]:
            result["narrative"] = (
                f"{result['partner_name']} is listed as an Anthropic Project Glasswing partner. "
                "Glasswing partners integrate Claude-assisted vulnerability discovery and patching "
                "into their security programme, which shortens exposure to novel vulnerabilities and "
                "improves patch cadence. This is a favourable underwriting signal."
            )
        else:
            result["narrative"] = (
                "No Anthropic Project Glasswing partnership detected for this domain. "
                "Glasswing partnership is an optional favourable signal — absence is neutral, "
                "not a deficiency."
            )
        return result


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
        # Route through the shared HttpClient - rate limited per apex,
        # tracked for WAF detection. HEAD first to confirm existence;
        # GET only when HEAD reports 200 (saves bandwidth + reduces WAF
        # signature for "directory enumeration" rules).
        from http_client import HTTP
        head = HTTP.head(url, timeout=8, allow_redirects=False)
        if head is None or head.status_code != 200:
            sc = head.status_code if head is not None else 0
            return False, sc, 0
        r = HTTP.get(url, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200 or len(r.text) < 10:
            sc = r.status_code if r is not None else 0
            return False, sc, 0
        # Verify it's not a custom 404 page
        if "not found" in r.text.lower()[:200] or "404" in r.text[:50]:
            return False, r.status_code, 0
        return True, r.status_code, len(r.text)

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed", "exposed_paths": [],
            "score": 100, "issues": [],
        }
        try:
            base = f"https://{domain}"
            exposed = []

            # Build full probe set (critical + medium). Rate limiter
            # paces the actual request flow; the ThreadPoolExecutor's
            # max_workers is reduced 6 -> 3 so we don't queue too many
            # waiting probes against the shared per-apex bucket.
            probes = (
                [(p, d, "critical", 20) for p, d in self.CRITICAL_PATHS] +
                [(p, d, "medium", 10) for p, d in self.MEDIUM_PATHS]
            )

            # WAF-aware early-exit: skip the medium-risk long tail once the apex is
            # hard-blocking. Critical paths are ALWAYS probed in full.
            import threading as _threading
            _probed = {"n": 0}
            _plock = _threading.Lock()

            def _probe_guarded(url, risk):
                if risk == "medium":
                    with _plock:
                        n = _probed["n"]
                        _probed["n"] += 1
                    if HTTP.stop_probing(domain, n):
                        result["waf_truncated"] = True
                        return (False, 0, 0)
                return self._probe(url)

            with ThreadPoolExecutor(max_workers=3) as ex:
                futures = {
                    ex.submit(_probe_guarded, f"{base}{path}", risk): (path, desc, risk, penalty)
                    for path, desc, risk, penalty in probes
                }
                try:
                    # Wall ceiling widened 30s -> 60s to give the rate
                    # limiter room to pace 18 HEAD+GET probes at 2/sec.
                    for fut in as_completed(futures, timeout=60):
                        path, desc, risk, penalty = futures[fut]
                        try:
                            found, status, size = fut.result(timeout=2)
                        except Exception:
                            continue
                        if not found:
                            continue
                        exposed.append({
                            "path": path, "description": desc,
                            "risk_level": risk, "size": size,
                        })
                        result["score"] = max(0, result["score"] - penalty)
                        if risk == "critical":
                            result["issues"].append(
                                f"CRITICAL: Sensitive file exposed: {path} — {desc}"
                            )
                        else:
                            result["issues"].append(
                                f"Information disclosure: {path} accessible — {desc}"
                            )
                except FuturesTimeoutError:
                    # Treat unfinished probes as negative — scan must not stall.
                    result["issues"].append(
                        "Info disclosure probe batch hit 60s wall-clock — remaining paths skipped"
                    )

            # Directory listing probe (separate — checks root HTML, not path)
            from http_client import HTTP
            r = HTTP.get(f"{base}/", timeout=8)
            if r is not None and (
                "Index of /" in r.text or "<title>Index of" in r.text
            ):
                exposed.append({
                    "path": "/", "description": "Directory listing enabled",
                    "risk_level": "medium", "size": 0,
                })
                result["score"] = max(0, result["score"] - 15)
                result["issues"].append(
                    "Directory listing is enabled on the web root"
                )

            # Keep deterministic order for display (criticals first)
            result["exposed_paths"] = sorted(
                exposed,
                key=lambda e: (0 if e["risk_level"] == "critical" else 1, e["path"])
            )

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        return result
