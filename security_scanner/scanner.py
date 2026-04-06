"""
Cyber Insurance External Security Scanner
Passive, read-only assessment of external-facing infrastructure.
All checks use only publicly available information.
"""

from scanner_utils import *
from checkers_core import *
from checkers_network import *
from checkers_threats import *
from scoring_analytics import *


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
                 shodan_api_key: Optional[str] = None,
                 intelx_api_key: Optional[str] = None):
        self.hibp_api_key          = hibp_api_key
        self.dehashed_email        = dehashed_email
        self.dehashed_api_key      = dehashed_api_key
        self.virustotal_api_key    = virustotal_api_key
        self.securitytrails_api_key = securitytrails_api_key
        self.shodan_api_key        = shodan_api_key
        self.intelx_api_key        = intelx_api_key

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
            "hudson_rock":         (HudsonRockChecker().check,         [domain]),
            "intelx":              (IntelXChecker().check,             [domain, self.intelx_api_key]),
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
            # Always store OSV results for diagnostics
            osv_crit = sum(1 for v in osv_vulns if v.get("severity") == "critical")
            osv_high = sum(1 for v in osv_vulns if v.get("severity") == "high")
            osv_issues = []
            if osv_crit > 0:
                osv_issues.append(f"{osv_crit} critical vulnerability(ies) found via version analysis (OSV.dev)")
            if osv_high > 0:
                osv_issues.append(f"{osv_high} high-severity vulnerability(ies) found via version analysis (OSV.dev)")
            results["categories"]["osv_vulns"] = {
                "status": "completed",
                "source": "osv.dev",
                "total_vulns": len(osv_vulns),
                "vulns": osv_vulns,
                "cpes_queried": list(all_cpes),
                "ips_with_cpes": list(ip_cpe_map.keys()),
                "critical_count": osv_crit,
                "high_count": osv_high,
                "issues": osv_issues,
            }
            if osv_vulns:

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
                                # Calculate CVE age from published date
                                pub = ov.get("published", "")[:10]
                                age_days = None
                                if pub:
                                    try:
                                        from datetime import datetime as _dt
                                        age_days = (_dt.utcnow() - _dt.strptime(pub, "%Y-%m-%d")).days
                                    except (ValueError, TypeError):
                                        pass

                                # Parse CVSS vector for exploitability
                                vector = ov.get("vector", "")
                                easily_exploitable = ("AV:N" in vector and "AC:L" in vector and "PR:N" in vector) if vector else False

                                # Check ransomware association
                                ransomware = ShodanVulnChecker.RANSOMWARE_CVE_MAP.get(cve_id.upper(), "")
                                attack = ShodanVulnChecker.ATTACK_TECHNIQUE_MAP.get(cve_id.upper(), {})

                                epss_val = ov.get("epss") or 0
                                shodan_r.setdefault("cves", []).append({
                                    "cve_id": cve_id,
                                    "cvss_score": cvss,
                                    "severity": sev,
                                    "epss_score": epss_val,
                                    "description": ov.get("summary", "")[:200],
                                    "source": "osv.dev",
                                    "package": ov.get("package", ""),
                                    "detected_version": ov.get("detected_version", ""),
                                    "in_kev": False,
                                    "published": pub,
                                    "age_days": age_days,
                                    "easily_exploitable": easily_exploitable,
                                    "widely_exploited": epss_val > 0.4,
                                    "zero_day": False,
                                    "has_patch": True,
                                    "ransomware_association": ransomware,
                                    "attack_technique": attack.get("technique", ""),
                                    "attack_technique_name": attack.get("name", ""),
                                    "attack_groups": attack.get("groups", []),
                                    "exploit_maturity": "theoretical",
                                })
                                existing_cve_ids.add(cve_id)
                        # Update counts including new indicators
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
                        shodan_r["zero_day_count"] = sum(1 for c in all_cves if c.get("zero_day"))
                        shodan_r["easily_exploitable_count"] = sum(1 for c in all_cves if c.get("easily_exploitable"))
                        shodan_r["widely_exploited_count"] = sum(1 for c in all_cves if c.get("widely_exploited"))
                        shodan_r["malware_exploited_count"] = sum(1 for c in all_cves if c.get("ransomware_association"))
                        # Patch management posture
                        ages = [c.get("age_days") for c in all_cves if c.get("age_days") is not None]
                        shodan_r["patch_management"] = {
                            "oldest_unpatched_days": max(ages) if ages else 0,
                            "average_age_days": round(sum(ages) / len(ages)) if ages else 0,
                            "over_180_days": sum(1 for a in ages if a > 180),
                            "90_to_180_days": sum(1 for a in ages if 90 <= a <= 180),
                            "under_90_days": sum(1 for a in ages if a < 90),
                            "total_cves_aged": len(ages),
                        }

                # --- Batch EPSS + CISA KEV lookup for OSV-enriched CVEs ---
                try:
                    enricher = ShodanVulnChecker()
                    kev_set = enricher._load_kev()
                    all_osv_cve_ids = []
                    for ip, checkers in per_ip_results.items():
                        for c in checkers.get("shodan_vulns", {}).get("cves", []):
                            if c.get("source") == "osv.dev":
                                # Extract CVE ID from advisory ID (e.g., ALPINE-CVE-2023-48795 -> CVE-2023-48795)
                                cid = c.get("cve_id", "")
                                if not cid.startswith("CVE-"):
                                    import re as _re
                                    m = _re.search(r'(CVE-\d{4}-\d+)', cid)
                                    if m:
                                        cid = m.group(1)
                                        c["cve_id"] = cid  # Fix display ID
                                if cid.startswith("CVE-"):
                                    # CISA KEV check
                                    c["in_kev"] = cid in kev_set
                                    if c.get("epss_score", 0) == 0:
                                        all_osv_cve_ids.append((ip, c, cid))

                    if all_osv_cve_ids:
                        unique_cves = list(set(cid for _, _, cid in all_osv_cve_ids))
                        epss_data = enricher._fetch_epss(unique_cves[:30])
                        for ip, cve_entry, cid in all_osv_cve_ids:
                            if cid in epss_data:
                                cve_entry["epss_score"] = epss_data[cid]["epss_score"]
                                # Recalculate flags now that real EPSS is available
                                cve_entry["widely_exploited"] = cve_entry["epss_score"] > 0.4
                                # Upgrade exploit maturity if EPSS is high
                                if cve_entry["epss_score"] > 0.5 and cve_entry.get("exploit_maturity") == "theoretical":
                                    cve_entry["exploit_maturity"] = "poc_public"
                        # Recalculate per-IP aggregate counts with updated flags
                        for ip in per_ip_results:
                            shodan_r = per_ip_results[ip].get("shodan_vulns", {})
                            all_cves = shodan_r.get("cves", [])
                            if all_cves:
                                shodan_r["max_epss"] = max(
                                    (c.get("epss_score", 0) for c in all_cves if c.get("epss_score")), default=0)
                                shodan_r["kev_count"] = sum(1 for c in all_cves if c.get("in_kev"))
                                shodan_r["widely_exploited_count"] = sum(1 for c in all_cves if c.get("widely_exploited"))
                                shodan_r["high_epss_count"] = sum(1 for c in all_cves if c.get("epss_score", 0) > 0.5)
                except Exception:
                    pass

                # --- Re-aggregate after OSV enrichment updated per-IP data ---
                # Shodan counts were set BEFORE OSV added CVEs — re-aggregate now
                for checker_name in self.IP_LEVEL_CHECKERS:
                    results["categories"][checker_name] = self._aggregate_ip_results(
                        per_ip_results, checker_name
                    )
                results["categories"]["external_ips"] = ExternalIPAggregator.aggregate(
                    all_ips, per_ip_results, ip_sources=ip_sources
                )
        except Exception as _osv_err:
            # Log OSV enrichment errors instead of silently swallowing
            results["categories"]["osv_vulns"] = {
                "status": "error", "error": str(_osv_err), "total_vulns": 0,
                "vulns": [], "issues": [f"OSV enrichment failed: {_osv_err}"],
            }
        self._notify(on_progress, "osv_enrichment", "done")

        # --- Ensure re-aggregation always runs (even if OSV failed) ---
        try:
            results["categories"]["external_ips"] = ExternalIPAggregator.aggregate(
                all_ips, per_ip_results, ip_sources=ip_sources
            )
        except Exception:
            pass

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

        # --- Phase 4e: Credential risk enrichment (HIBP + Hudson Rock + Dehashed) ---
        self._notify(on_progress, "credential_risk", "running")
        try:
            # Enrich Dehashed with HIBP breach metadata (dates, data classes)
            hibp = HIBPBreachMetadata()
            dehashed_data = cat_results.get("dehashed", {})
            if dehashed_data.get("total_entries", 0) > 0 or dehashed_data.get("breach_sources"):
                cat_results["dehashed"] = hibp.enrich_dehashed_results(dehashed_data)

            # Build credential risk classification
            hudson_rock_data = cat_results.get("hudson_rock", {})
            intelx_data = cat_results.get("intelx", {})
            classifier = CredentialRiskClassifier()
            cred_risk = classifier.classify(
                dehashed=cat_results.get("dehashed", {}),
                hudson_rock=hudson_rock_data,
                intelx=intelx_data,
            )
            results["categories"]["credential_risk"] = cred_risk
        except Exception:
            pass
        self._notify(on_progress, "credential_risk", "done")

        # --- Phase 5: Score ---
        scorer = RiskScorer()
        risk_score, risk_level, recommendations = scorer.calculate(cat_results)
        results["overall_risk_score"] = risk_score
        results["risk_level"] = risk_level
        results["recommendations"] = recommendations
        # Propagate scan completeness metadata to top level
        if "_scan_completeness" in cat_results:
            results["_scan_completeness"] = cat_results.pop("_scan_completeness")
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
