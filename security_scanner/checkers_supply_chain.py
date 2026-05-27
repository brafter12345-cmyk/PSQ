"""
Supply-chain checkers — assess risk inherited from related/supplier domains.

S-1 RelatedDomainsChecker (v1.0 — broker-declared only)
    Scans broker-declared sibling/supplier domains in LITE mode (SSL +
    DNS infrastructure ports + info_disclosure) and rolls up worst-of-N
    findings into a single supply-chain category for the primary report.

    v1.1 (deferred) — auto-discovery via cert SAN, WHOIS registrant match,
    and analytics-ID correlation; broker confirms via the existing
    pre-flight regulatory-flag UX. See project memory:
    project_related_domain_discovery.md.

    Civil-liability rationale: under aggregator / supplier-liability theory
    (a single Lloyd's Talbot precedent: mrcourier.co.uk), a breach at a
    declared supplier can be imputed back to the insured. This category
    feeds the DBI civil-liability scenario in financial_impact.
"""

from scanner_utils import *
from checkers_core import SSLChecker
from checkers_network import DNSInfrastructureChecker
from checkers_threats import InformationDisclosureChecker


class RelatedDomainsChecker:
    LITE_TIMEOUT_PER_DOMAIN = 45  # seconds
    MAX_DOMAINS = 10              # cap broker-declared list to bound scan time

    def check(self, primary_domain: str, related_domains: list = None) -> dict:
        related = [d.strip().lower() for d in (related_domains or [])
                   if d and isinstance(d, str) and d.strip()]
        related = [d for d in related if d != primary_domain.lower()]
        related = list(dict.fromkeys(related))[:self.MAX_DOMAINS]

        result = {
            "status": "skipped" if not related else "completed",
            "declared_count": len(related),
            "scanned_count": 0,
            "dependants": [],
            "worst_domain": None,
            "critical_count": 0,
            "high_count": 0,
            "score": 100,
            "issues": [],
        }
        if not related:
            return result

        def _scan_one(d: str) -> dict:
            dep = {"domain": d, "ssl_grade": None, "ssl_score": 100,
                   "info_score": 100, "dns_risk": 0,
                   "critical_paths": 0, "lite_score": 100, "issues": []}
            try:
                ssl = SSLChecker().check(d) or {}
                dep["ssl_grade"] = ssl.get("grade")
                dep["ssl_score"] = ssl.get("score", 100)
                dep["issues"] += [f"[ssl] {i}" for i in (ssl.get("issues") or [])[:3]]
            except Exception:
                pass
            try:
                dns = DNSInfrastructureChecker().check(d) or {}
                dep["dns_risk"] = dns.get("risk_score", 0)
                dep["issues"] += [f"[dns] {i}" for i in (dns.get("issues") or [])[:3]]
            except Exception:
                pass
            try:
                info = InformationDisclosureChecker().check(d) or {}
                dep["info_score"] = info.get("score", 100)
                dep["critical_paths"] = sum(
                    1 for p in (info.get("exposed_paths") or [])
                    if p.get("risk_level") == "critical"
                )
                dep["issues"] += [f"[info] {i}" for i in (info.get("issues") or [])[:3]]
            except Exception:
                pass
            dep["lite_score"] = min(
                int(dep["ssl_score"] or 100),
                int(dep["info_score"] or 100),
                max(0, 100 - int(dep["dns_risk"] or 0)),
            )
            return dep

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(_scan_one, d): d for d in related}
            try:
                for fut in as_completed(
                        futures,
                        timeout=self.LITE_TIMEOUT_PER_DOMAIN * len(related)):
                    try:
                        result["dependants"].append(
                            fut.result(timeout=self.LITE_TIMEOUT_PER_DOMAIN))
                    except Exception:
                        pass
            except TimeoutError:
                pass

        result["scanned_count"] = len(result["dependants"])

        if result["dependants"]:
            worst = min(result["dependants"], key=lambda d: d.get("lite_score", 100))
            result["worst_domain"] = {
                "domain": worst["domain"],
                "lite_score": worst.get("lite_score", 100),
            }
            result["critical_count"] = sum(d.get("critical_paths", 0)
                                            for d in result["dependants"])
            result["high_count"] = sum(1 for d in result["dependants"]
                                        if d.get("lite_score", 100) < 60)
            result["score"] = min(d.get("lite_score", 100)
                                   for d in result["dependants"])

            if result["critical_count"] > 0:
                result["issues"].append(
                    f"CRITICAL: {result['critical_count']} critical exposure(s) "
                    f"across {result['scanned_count']} related domain(s) — "
                    "supplier-chain liability risk"
                )
            elif result["high_count"] > 0:
                result["issues"].append(
                    f"{result['high_count']} related domain(s) score below 60 — "
                    "review supplier security posture"
                )

        return result
