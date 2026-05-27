"""
Supply-chain checkers — assess risk inherited from related/supplier
domains, exposed third-party dependency manifests, third-party JavaScript
loaded into the page, the email-vendor surface (SPF include chain), the
CMS-plugin attack surface, and known-breach correlations against the
detected vendor surface.

S-1  RelatedDomainsChecker (v1.0 — broker-declared only)
S-2  ThirdPartyJSChecker — Magecart / polyfill.io / missing-SRI risk
S-3  DependencyManifestChecker — leaked package.json / requirements.txt etc.
S-4  EmailVendorSurfaceChecker — SPF include-chain SaaS sender surface
S-5  VendorBreachChecker — cross-references detected vendor surface against
     curated vendor_breaches.json (Mailchimp, Okta, MS365, HubSpot, etc.)
S-10 CMSPluginSBOMChecker — WordPress plugin enumeration (top SA SME
     ransomware entry vector)

Cross-references to project memory:
    project_scanner_systemic_sweep_2026-05-27.md — original integration map
    project_related_domain_discovery.md — S-1 v1.1 auto-discovery design
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from scanner_utils import *
from checkers_core import SSLChecker
from checkers_network import DNSInfrastructureChecker
from checkers_threats import InformationDisclosureChecker, OSVChecker


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


class DependencyManifestChecker:
    # Manifests grouped by ecosystem. Each tuple is (path, ecosystem,
    # parser-key, severity). The parser-key selects an extraction
    # strategy in _extract_dependencies. The ecosystem is the OSV.dev
    # ecosystem identifier used by OSVChecker.query_version.
    # Severity reflects how much actionable CVE-discovery signal the
    # manifest gives an attacker:
    #
    #   - lockfile (package-lock.json, composer.lock, Gemfile.lock,
    #     requirements.txt, go.sum, Cargo.lock) reveals EXACT pinned
    #     versions → easily chained to OSV CVEs → "critical"
    #   - manifest (package.json, composer.json, Pipfile, Gemfile,
    #     go.mod, Cargo.toml, pom.xml) reveals dependency NAMES and
    #     SemVer ranges → narrower attacker advantage → "high"
    MANIFESTS = [
        ("/package-lock.json",  "node",   "json_lock",      "critical"),
        ("/package.json",       "node",   "json_manifest",  "high"),
        ("/yarn.lock",          "node",   "yarn_lock",      "critical"),
        ("/composer.lock",      "php",    "json_lock",      "critical"),
        ("/composer.json",      "php",    "json_manifest",  "high"),
        ("/requirements.txt",   "python", "requirements",   "critical"),
        ("/Pipfile.lock",       "python", "json_lock",      "critical"),
        ("/Pipfile",            "python", "pipfile",        "high"),
        ("/Gemfile.lock",       "ruby",   "gemfile_lock",   "critical"),
        ("/Gemfile",            "ruby",   "gemfile",        "high"),
        ("/go.mod",             "go",     "go_mod",         "high"),
        ("/go.sum",             "go",     "go_sum",         "critical"),
        ("/Cargo.lock",         "rust",   "toml_lock",      "critical"),
        ("/Cargo.toml",         "rust",   "toml_manifest",  "high"),
        ("/pom.xml",            "java",   "pom",            "high"),
    ]

    # OSV.dev ecosystem identifiers for the .query_version() API.
    ECOSYSTEM_TO_OSV = {
        "node":   "npm",
        "python": "PyPI",
        "php":    "Packagist",
        "ruby":   "RubyGems",
        "go":     "Go",
        "rust":   "crates.io",
        "java":   "Maven",
    }
    # Pinned-version regex: only query OSV.dev when we have an exact
    # version (not a range like ^1.2.0 or ~1.2.0 — those would either
    # mass-flag or mass-miss). For SemVer ranges we skip — the broker
    # gets the manifest-leak finding but no actionable CVE count.
    EXACT_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?([-+][\w.]+)?$")

    MAX_DEPS_RETURNED = 50    # cap per manifest to bound result size
    MAX_OSV_LOOKUPS_PER_SCAN = 30  # cap total OSV calls — 10 req/s rate limit
    OSV_CRIT_HIGH_SEVERITIES = {"CRITICAL", "HIGH"}

    def _probe(self, url: str):
        from http_client import HTTP
        head = HTTP.head(url, timeout=8, allow_redirects=False)
        if head is None or head.status_code != 200:
            return None
        r = HTTP.get(url, timeout=8, allow_redirects=False)
        if r is None or r.status_code != 200 or len(r.text) < 10:
            return None
        text_head = r.text.lower()[:300]
        if "<html" in text_head or "<!doctype" in text_head:
            return None
        if "not found" in text_head[:200] or "404" in text_head[:50]:
            return None
        return r.text[:200_000]

    def _extract_dependencies(self, content: str, parser_key: str) -> list:
        deps = []
        try:
            if parser_key == "json_manifest":
                obj = json.loads(content)
                for section in ("dependencies", "devDependencies",
                                "require", "require-dev"):
                    for name, ver in (obj.get(section) or {}).items():
                        deps.append({"name": name, "version": str(ver),
                                      "section": section})
            elif parser_key == "json_lock":
                obj = json.loads(content)
                pkgs = obj.get("packages") or obj.get("dependencies") or {}
                if isinstance(pkgs, dict):
                    for name, meta in pkgs.items():
                        if not name:
                            continue
                        ver = ""
                        if isinstance(meta, dict):
                            ver = str(meta.get("version", ""))
                        elif isinstance(meta, str):
                            ver = meta
                        deps.append({"name": name.lstrip("/"),
                                      "version": ver})
            elif parser_key == "yarn_lock":
                for m in re.finditer(r'^"?([^@\s"]+)@[^\n"]+"?:\s*\n\s*version\s+"([^"]+)"',
                                      content, re.MULTILINE):
                    deps.append({"name": m.group(1), "version": m.group(2)})
            elif parser_key == "requirements":
                for line in content.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line or line.startswith("-"):
                        continue
                    m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]=?|@)\s*(\S+)", line)
                    if m:
                        deps.append({"name": m.group(1),
                                      "version": m.group(3)})
                    else:
                        deps.append({"name": line, "version": ""})
            elif parser_key == "pipfile":
                cur = None
                for line in content.splitlines():
                    s = line.strip()
                    if s.startswith("[") and s.endswith("]"):
                        cur = s[1:-1]
                        continue
                    if cur in ("packages", "dev-packages") and "=" in s:
                        name, _, rest = s.partition("=")
                        deps.append({"name": name.strip().strip('"'),
                                      "version": rest.strip().strip('"'),
                                      "section": cur})
            elif parser_key == "gemfile_lock":
                in_specs = False
                for line in content.splitlines():
                    if line.strip() == "GEM" or line.strip().startswith("PATH"):
                        in_specs = False
                    if line.strip() == "specs:":
                        in_specs = True
                        continue
                    if in_specs:
                        m = re.match(r"^\s{4}([A-Za-z0-9_\-]+)\s+\(([^)]+)\)", line)
                        if m:
                            deps.append({"name": m.group(1),
                                          "version": m.group(2)})
            elif parser_key == "gemfile":
                for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?",
                                      content):
                    deps.append({"name": m.group(1),
                                  "version": (m.group(2) or "")})
            elif parser_key == "go_mod":
                in_block = False
                for line in content.splitlines():
                    s = line.strip()
                    if s.startswith("require ("):
                        in_block = True
                        continue
                    if in_block and s == ")":
                        in_block = False
                        continue
                    if in_block or s.startswith("require "):
                        s2 = s.removeprefix("require ").strip()
                        parts = s2.split()
                        if len(parts) >= 2:
                            deps.append({"name": parts[0], "version": parts[1]})
            elif parser_key == "go_sum":
                seen = set()
                for line in content.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and (parts[0], parts[1]) not in seen:
                        seen.add((parts[0], parts[1]))
                        deps.append({"name": parts[0],
                                      "version": parts[1].split("/")[0]})
            elif parser_key in ("toml_lock", "toml_manifest"):
                # Minimal TOML parsing — enough to extract [[package]] /
                # [dependencies] entries without a TOML lib dependency.
                if parser_key == "toml_lock":
                    blocks = re.findall(
                        r'\[\[package\]\]\s*\n([^[]+)', content)
                    for block in blocks:
                        name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block)
                        if name_m:
                            deps.append({
                                "name": name_m.group(1),
                                "version": ver_m.group(1) if ver_m else "",
                            })
                else:
                    dep_block = re.search(
                        r'\[dependencies\]\s*\n(.*?)(?:\n\[|\Z)',
                        content, re.DOTALL)
                    if dep_block:
                        for m in re.finditer(
                                r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"',
                                dep_block.group(1), re.MULTILINE):
                            deps.append({"name": m.group(1),
                                          "version": m.group(2)})
            elif parser_key == "pom":
                for m in re.finditer(
                        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*"
                        r"<artifactId>([^<]+)</artifactId>\s*"
                        r"(?:<version>([^<]+)</version>)?",
                        content):
                    deps.append({"name": f"{m.group(1)}:{m.group(2)}",
                                  "version": m.group(3) or ""})
        except Exception:
            return deps[:self.MAX_DEPS_RETURNED]
        return deps[:self.MAX_DEPS_RETURNED]

    def _osv_lookup_dep(self, osv, ecosystem: str, name: str,
                          version: str) -> list:
        """Query OSV.dev for a single (ecosystem, name, version) tuple.
        Returns the list of vuln dicts (already-parsed by OSVChecker)
        or an empty list on miss / error."""
        if not name or not version:
            return []
        if not self.EXACT_VERSION_RE.match(version.strip()):
            return []  # skip SemVer ranges; would mass-flag/miss
        osv_eco = self.ECOSYSTEM_TO_OSV.get(ecosystem)
        if not osv_eco:
            return []
        try:
            return osv.query_version(name, version, osv_eco) or []
        except Exception:
            return []

    def _enrich_with_osv(self, exposed_manifests: list) -> dict:
        """Cross-reference extracted deps against OSV.dev. Caps total
        lookups to bound API rate and scan time. Adds per-manifest
        cve_count + critical_cve_count + cves[] and returns aggregate
        totals across all manifests for the issues / scoring layer."""
        osv = OSVChecker()
        total_cves = 0
        total_critical = 0
        cves_global = []
        lookups_done = 0
        # Spread the budget across manifests in inverse order of size
        # so a lockfile with 1000 deps doesn't starve the smaller ones.
        manifests_sorted = sorted(
            exposed_manifests,
            key=lambda m: m.get("dependency_count", 0),
        )
        per_manifest_budget = max(
            1, self.MAX_OSV_LOOKUPS_PER_SCAN // max(1, len(manifests_sorted))
        )
        for m in manifests_sorted:
            if lookups_done >= self.MAX_OSV_LOOKUPS_PER_SCAN:
                break
            m["cve_count"] = 0
            m["critical_cve_count"] = 0
            m["cves"] = []
            ecosystem = m.get("ecosystem", "")
            budget = min(per_manifest_budget,
                         self.MAX_OSV_LOOKUPS_PER_SCAN - lookups_done)
            for dep in (m.get("dependencies") or [])[:budget]:
                if lookups_done >= self.MAX_OSV_LOOKUPS_PER_SCAN:
                    break
                lookups_done += 1
                vulns = self._osv_lookup_dep(
                    osv, ecosystem, dep.get("name", ""), dep.get("version", "")
                )
                for v in vulns:
                    sev = (v.get("severity") or "").upper()
                    cve_entry = {
                        "package": dep.get("name", ""),
                        "version": dep.get("version", ""),
                        "ecosystem": ecosystem,
                        "cve_id": v.get("cve") or v.get("id", ""),
                        "severity": v.get("severity", ""),
                        "cvss_score": v.get("cvss_score") or 0,
                        "summary": (v.get("summary") or "")[:160],
                    }
                    m["cves"].append(cve_entry)
                    m["cve_count"] += 1
                    if sev in self.OSV_CRIT_HIGH_SEVERITIES:
                        m["critical_cve_count"] += 1
                        cves_global.append(cve_entry)
                    total_cves += 1
                    if sev in self.OSV_CRIT_HIGH_SEVERITIES:
                        total_critical += 1
            # Trim per-manifest stored CVE list to keep result size manageable
            m["cves"] = m["cves"][:10]
        return {
            "lookups_done": lookups_done,
            "lookup_cap": self.MAX_OSV_LOOKUPS_PER_SCAN,
            "total_cves": total_cves,
            "total_critical_cves": total_critical,
            "top_critical_cves": sorted(
                cves_global,
                key=lambda c: -(c.get("cvss_score") or 0),
            )[:5],
        }

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "exposed_manifests": [],
            "total_dependencies": 0,
            "ecosystems": [],
            "critical_count": 0,
            "high_count": 0,
            "osv_lookups_done": 0,
            "total_cves": 0,
            "total_critical_cves": 0,
            "top_critical_cves": [],
            "score": 100,
            "issues": [],
        }
        base = f"https://{domain}"

        def _check_one(entry):
            path, ecosystem, parser_key, severity = entry
            content = self._probe(f"{base}{path}")
            if not content:
                return None
            deps = self._extract_dependencies(content, parser_key)
            return {
                "path": path,
                "ecosystem": ecosystem,
                "severity": severity,
                "size_bytes": len(content),
                "dependency_count": len(deps),
                "dependencies": deps,
            }

        try:
            with ThreadPoolExecutor(max_workers=3) as ex:
                futures = {ex.submit(_check_one, m): m for m in self.MANIFESTS}
                for fut in as_completed(futures, timeout=90):
                    try:
                        out = fut.result(timeout=10)
                    except Exception:
                        continue
                    if out:
                        result["exposed_manifests"].append(out)
        except TimeoutError:
            pass

        if result["exposed_manifests"]:
            result["ecosystems"] = sorted({m["ecosystem"]
                                           for m in result["exposed_manifests"]})
            result["total_dependencies"] = sum(m["dependency_count"]
                                                for m in result["exposed_manifests"])
            result["critical_count"] = sum(1 for m in result["exposed_manifests"]
                                            if m["severity"] == "critical")
            result["high_count"] = sum(1 for m in result["exposed_manifests"]
                                        if m["severity"] == "high")

            # OSV.dev cross-reference (S-3 v1.1) — turn the leaked
            # version map into an ACTIONABLE CVE count. Only exact-
            # pinned versions are looked up; SemVer ranges are skipped.
            osv_agg = self._enrich_with_osv(result["exposed_manifests"])
            result["osv_lookups_done"] = osv_agg["lookups_done"]
            result["total_cves"] = osv_agg["total_cves"]
            result["total_critical_cves"] = osv_agg["total_critical_cves"]
            result["top_critical_cves"] = osv_agg["top_critical_cves"]

            penalty = result["critical_count"] * 30 + result["high_count"] * 15
            # Additional penalty for actionable CVEs surfaced via OSV.
            # Capped so the manifest-leak severity penalty stays
            # dominant — manifest leak is the cause; CVEs are the
            # observable consequence.
            penalty += min(30, result["total_critical_cves"] * 5)
            result["score"] = max(0, 100 - penalty)

            crit_paths = [m["path"] for m in result["exposed_manifests"]
                           if m["severity"] == "critical"]
            if crit_paths:
                result["issues"].append(
                    f"CRITICAL: {len(crit_paths)} dependency lockfile(s) exposed "
                    f"({', '.join(crit_paths)}) — exact pinned versions enable "
                    "OSV-chained CVE discovery"
                )
            high_paths = [m["path"] for m in result["exposed_manifests"]
                           if m["severity"] == "high"]
            if high_paths:
                result["issues"].append(
                    f"{len(high_paths)} dependency manifest(s) exposed "
                    f"({', '.join(high_paths)}) — dependency names + SemVer "
                    "ranges leaked"
                )
            if result["total_critical_cves"] > 0:
                top_pkgs = ", ".join(sorted({
                    c["package"] for c in result["top_critical_cves"][:5]
                }))
                result["issues"].append(
                    f"CRITICAL: {result['total_critical_cves']} critical / "
                    f"high-severity CVE(s) cross-referenced via OSV.dev "
                    f"across the leaked dependency map "
                    f"(top affected: {top_pkgs})"
                )
            elif result["total_cves"] > 0:
                result["issues"].append(
                    f"{result['total_cves']} known CVE(s) cross-referenced "
                    "via OSV.dev across the leaked dependency map "
                    "(medium / low severity)"
                )

        return result


class ThirdPartyJSChecker:
    # Domains with documented supply-chain compromises. Keep tight: only
    # confirmed incidents to avoid noisy "trusted CDN looks scary" findings.
    KNOWN_COMPROMISED_HOSTS = {
        "polyfill.io":         "polyfill.io was sold and weaponised (2024)",
        "cdn.polyfill.io":     "polyfill.io was sold and weaponised (2024)",
        "bootcss.com":         "bootcss.com hosted Magecart skimmer (2018)",
        "bootcdn.net":         "bootcdn.net hosted Magecart skimmer (2018)",
    }

    # Common safe CDN host suffixes — used only to label, not to whitelist.
    KNOWN_CDN_SUFFIXES = (
        "googleapis.com", "gstatic.com", "googletagmanager.com",
        "cloudflare.com", "cloudfront.net", "akamaihd.net", "akamaized.net",
        "fastly.net", "azureedge.net", "msecnd.net",
        "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "jspm.io", "skypack.dev",
        "facebook.net", "twitter.com", "youtube.com",
        "hotjar.com", "intercom.io", "hubspot.com",
    )

    SCRIPT_RE = re.compile(
        r'<script\b([^>]*)>', re.IGNORECASE)
    SRC_RE = re.compile(
        r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    INTEGRITY_RE = re.compile(
        r'integrity\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    CROSSORIGIN_RE = re.compile(
        r'crossorigin\s*=\s*["\']?([^"\'\s>]+)', re.IGNORECASE)

    def _host_of(self, src: str, primary: str) -> str:
        # Resolves protocol-relative + relative URLs to a host for
        # first-party / third-party classification.
        try:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/") or not src.startswith(("http://", "https://")):
                return primary  # first-party
            return (urlparse(src).hostname or "").lower()
        except Exception:
            return ""

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "total_scripts": 0,
            "third_party_count": 0,
            "missing_sri_count": 0,
            "compromised_host_count": 0,
            "third_party_hosts": [],
            "missing_sri_scripts": [],
            "compromised_scripts": [],
            "score": 100,
            "issues": [],
        }
        try:
            from http_client import HTTP
            r = HTTP.get(f"https://{domain}", timeout=12, allow_redirects=True)
        except Exception as e:
            result["status"] = "error"; result["error"] = str(e); return result
        if r is None or r.status_code >= 400:
            result["status"] = "error"
            result["error"] = f"HTTP {r.status_code if r is not None else 'no-response'}"
            return result

        body = r.text[:300_000]
        primary = domain.lower()
        hosts = {}  # host -> {"count": int, "first_src": str}
        for m in self.SCRIPT_RE.finditer(body):
            attrs = m.group(1)
            src_m = self.SRC_RE.search(attrs)
            if not src_m:
                continue
            src = src_m.group(1)
            host = self._host_of(src, primary)
            result["total_scripts"] += 1
            is_third = host and not (host == primary or host.endswith("." + primary))
            if not is_third:
                continue
            result["third_party_count"] += 1
            hosts.setdefault(host, {"count": 0, "first_src": src})
            hosts[host]["count"] += 1

            sri = self.INTEGRITY_RE.search(attrs)
            if not sri:
                result["missing_sri_count"] += 1
                if len(result["missing_sri_scripts"]) < 10:
                    result["missing_sri_scripts"].append({
                        "host": host, "src": src[:160],
                    })

            if host in self.KNOWN_COMPROMISED_HOSTS or any(
                    host == h or host.endswith("." + h)
                    for h in self.KNOWN_COMPROMISED_HOSTS):
                result["compromised_host_count"] += 1
                matched = next(
                    (h for h in self.KNOWN_COMPROMISED_HOSTS
                     if host == h or host.endswith("." + h)),
                    host,
                )
                result["compromised_scripts"].append({
                    "host": host, "src": src[:160],
                    "reason": self.KNOWN_COMPROMISED_HOSTS.get(matched, ""),
                })

        result["third_party_hosts"] = [
            {
                "host": h,
                "count": meta["count"],
                "known_cdn": any(h == k or h.endswith("." + k)
                                  for k in self.KNOWN_CDN_SUFFIXES),
            }
            for h, meta in sorted(hosts.items(), key=lambda kv: -kv[1]["count"])
        ]

        # Scoring: SRI is the practical control. Compromised host = critical.
        penalty = 0
        if result["compromised_host_count"] > 0:
            penalty += 60 * result["compromised_host_count"]
            result["issues"].append(
                f"CRITICAL: {result['compromised_host_count']} script(s) from "
                "known-compromised CDN(s) — replace immediately"
            )
        if result["third_party_count"] > 0:
            sri_pct = (
                (result["third_party_count"] - result["missing_sri_count"])
                / result["third_party_count"]
            )
            if sri_pct < 0.25:
                penalty += 20
                result["issues"].append(
                    f"{result['missing_sri_count']} of "
                    f"{result['third_party_count']} third-party scripts "
                    "lack Subresource Integrity (SRI) hashes — Magecart / "
                    "supply-chain tampering risk"
                )
            elif sri_pct < 0.75:
                penalty += 10
                result["issues"].append(
                    f"{result['missing_sri_count']} third-party scripts "
                    "lack SRI hashes — supply-chain tampering risk"
                )
        # Surface volume itself (lots of unique third-party hosts widens the
        # attack surface even when each script is individually clean)
        if len(hosts) > 15:
            penalty += 5
            result["issues"].append(
                f"{len(hosts)} distinct third-party script origins — "
                "consider consolidating to reduce supply-chain surface"
            )
        result["score"] = max(0, 100 - penalty)
        return result


class EmailVendorSurfaceChecker:
    # SPF include-chain patterns → known email SaaS vendors. Match by
    # suffix; first match wins. Sourced from each vendor's published SPF
    # documentation.
    VENDOR_PATTERNS = [
        ("sendgrid",            ["sendgrid.net", "_spf.sendgrid.net"]),
        ("mailgun",             ["mailgun.org"]),
        ("mailchimp",           ["servers.mcsv.net", "_spf.mailchimp.com"]),
        ("amazon_ses",          ["amazonses.com"]),
        ("microsoft_365",       ["spf.protection.outlook.com",
                                  "spf.messaging.microsoft.com"]),
        ("google_workspace",    ["_spf.google.com", "aspmx.googlemail.com"]),
        ("zoho",                ["zoho.com", "_spf.zoho.eu", "zohomail.com"]),
        ("klaviyo",             ["_spf.klaviyo.com"]),
        ("hubspot",             ["_spf.hubspotemail.net", "mail.hubspot.com"]),
        ("constant_contact",    ["_spf.constantcontact.com"]),
        ("activecampaign",      ["spf.activecampaign.com"]),
        ("mailjet",             ["spf.mailjet.com"]),
        ("postmark",            ["spf.mtasv.net"]),
        ("sparkpost",           ["sparkpostmail.com"]),
        ("sendinblue",          ["spf.sendinblue.com", "spf.brevo.com"]),
        ("zendesk",             ["mail.zendesk.com"]),
        ("freshdesk",           ["email.freshdesk.com"]),
        ("intercom",            ["_spf.intercom.io"]),
        ("salesforce",          ["_spf.salesforce.com",
                                  "_spf.exacttarget.com"]),
        ("oracle_responsys",    ["rsys.net"]),
        ("pardot",              ["_spf.pardot.com"]),
        ("marketo",             ["mktomail.com"]),
        ("netcore",             ["_spf.netcorecloud.net"]),
        ("everlytic",           ["_spf.everlytic.net"]),
    ]

    INCLUDE_RE = re.compile(r"include:(\S+)")

    def _classify(self, include_domain: str) -> str:
        d = include_domain.lower().rstrip(".")
        for vendor, patterns in self.VENDOR_PATTERNS:
            if any(d == p or d.endswith("." + p) for p in patterns):
                return vendor
        return ""

    def _fetch_spf(self, domain: str) -> str:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if txt.startswith("v=spf1"):
                    return txt
        except Exception:
            return ""
        return ""

    def _walk_includes(self, domain: str, depth: int = 0,
                       seen: set = None) -> list:
        if depth > 4:
            return []
        seen = seen if seen is not None else set()
        if domain in seen:
            return []
        seen.add(domain)
        record = self._fetch_spf(domain)
        if not record:
            return []
        includes = self.INCLUDE_RE.findall(record)
        out = []
        for inc in includes[:10]:
            out.append({"include": inc, "depth": depth})
            out.extend(self._walk_includes(inc, depth + 1, seen))
        return out

    def _fetch_dmarc_policy(self, domain: str) -> str:
        try:
            import dns.resolver
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT",
                                            lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if txt.startswith("v=DMARC1"):
                    m = re.search(r"p\s*=\s*(\w+)", txt)
                    if m:
                        return m.group(1).lower()
        except Exception:
            return ""
        return ""

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "spf_includes": [],
            "vendors_detected": [],
            "vendor_count": 0,
            "unknown_count": 0,
            "dmarc_policy": "",
            "weak_dmarc": False,
            "score": 100,
            "issues": [],
        }
        includes = self._walk_includes(domain)
        if not includes:
            result["status"] = "no_data"
            return result
        result["spf_includes"] = includes
        vendor_map = {}
        for entry in includes:
            vendor = self._classify(entry["include"])
            if vendor:
                vendor_map.setdefault(vendor, []).append(entry["include"])
            else:
                result["unknown_count"] += 1
        result["vendors_detected"] = [
            {"vendor": v, "includes": sorted(set(incs))}
            for v, incs in sorted(vendor_map.items())
        ]
        result["vendor_count"] = len(vendor_map)
        result["dmarc_policy"] = self._fetch_dmarc_policy(domain)
        result["weak_dmarc"] = result["dmarc_policy"] in ("", "none")

        # Scoring rationale: the vendor surface itself is informational
        # (broker needs to see who can send mail on your behalf), but a
        # weak DMARC policy combined with a wide vendor surface means a
        # breach at any of N vendors lands phishing in customer inboxes.
        penalty = 0
        if result["vendor_count"] >= 3:
            penalty += 5
        if result["vendor_count"] >= 6:
            penalty += 10
        if result["weak_dmarc"] and result["vendor_count"] >= 1:
            penalty += 20
            result["issues"].append(
                f"{result['vendor_count']} email-vendor(s) in SPF chain with "
                f"DMARC p={result['dmarc_policy'] or 'missing'} — a breach at "
                "any of these vendors enables direct phishing impersonation"
            )
        elif result["vendor_count"] >= 6:
            result["issues"].append(
                f"{result['vendor_count']} email-vendor(s) in SPF chain — wide "
                "fourth-party surface; review whether each still needs send "
                "authority"
            )
        result["score"] = max(0, 100 - penalty)
        return result


class CMSPluginSBOMChecker:
    # Top SA SME ransomware entry vector — outdated WordPress plugins.
    # Probe the top community plugins. List is small and conservative —
    # the goal is "SBOM proxy" (what plugins are in use), not exhaustive
    # enumeration. Each entry: (slug, common_dirname).
    POPULAR_PLUGINS = [
        ("contact-form-7", "contact-form-7"),
        ("elementor", "elementor"),
        ("woocommerce", "woocommerce"),
        ("yoast-seo", "wordpress-seo"),
        ("akismet", "akismet"),
        ("jetpack", "jetpack"),
        ("wpforms-lite", "wpforms-lite"),
        ("classic-editor", "classic-editor"),
        ("really-simple-ssl", "really-simple-ssl"),
        ("updraftplus", "updraftplus"),
        ("all-in-one-seo-pack", "all-in-one-seo-pack"),
        ("wordfence", "wordfence"),
        ("duplicator", "duplicator"),
        ("wp-super-cache", "wp-super-cache"),
        ("litespeed-cache", "litespeed-cache"),
        ("autoptimize", "autoptimize"),
        ("monsterinsights", "google-analytics-for-wordpress"),
        ("loginizer", "loginizer"),
        ("redirection", "redirection"),
        ("better-search-replace", "better-search-replace"),
        ("wp-mail-smtp", "wp-mail-smtp"),
        ("ml-slider", "ml-slider"),
        ("nextgen-gallery", "nextgen-gallery"),
        ("revslider", "revslider"),    # historical CVE-2014-9734 etc.
        ("simply-static", "simply-static"),
    ]

    README_VERSION_RE = re.compile(
        r"^stable tag:\s*([0-9][\w.\-]*)", re.IGNORECASE | re.MULTILINE)

    def _is_wordpress(self, domain: str) -> bool:
        from http_client import HTTP
        # Cheap discriminator: HEAD /wp-content/ — if directory exists and
        # is readable (200/301/403 with WP signature), we're on WP. Pure
        # 404 means almost certainly not WordPress.
        for path in ("/wp-content/", "/wp-login.php", "/wp-includes/"):
            try:
                head = HTTP.head(f"https://{domain}{path}", timeout=6,
                                  allow_redirects=False)
                if head is None:
                    continue
                if head.status_code in (200, 301, 302, 401, 403):
                    return True
            except Exception:
                continue
        return False

    def _probe_plugin(self, base: str, dirname: str) -> dict:
        from http_client import HTTP
        plugin_root = f"{base}/wp-content/plugins/{dirname}/"
        try:
            head = HTTP.head(plugin_root, timeout=6, allow_redirects=False)
        except Exception:
            return None
        if head is None or head.status_code not in (200, 301, 302, 401, 403):
            return None
        version = ""
        try:
            r = HTTP.get(f"{plugin_root}readme.txt", timeout=6,
                          allow_redirects=False)
            if r is not None and r.status_code == 200 and r.text:
                m = self.README_VERSION_RE.search(r.text[:8000])
                if m:
                    version = m.group(1)
        except Exception:
            pass
        return {"slug": dirname, "version": version,
                "status_code": head.status_code}

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "is_wordpress": False,
            "plugins_detected": [],
            "plugin_count": 0,
            "versioned_count": 0,
            "score": 100,
            "issues": [],
        }
        if not self._is_wordpress(domain):
            result["status"] = "skipped"
            return result
        result["is_wordpress"] = True
        base = f"https://{domain}"
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self._probe_plugin, base, dirname): slug
                for slug, dirname in self.POPULAR_PLUGINS
            }
            try:
                for fut in as_completed(futures, timeout=60):
                    try:
                        out = fut.result(timeout=8)
                    except Exception:
                        continue
                    if out:
                        result["plugins_detected"].append(out)
            except TimeoutError:
                pass

        result["plugin_count"] = len(result["plugins_detected"])
        result["versioned_count"] = sum(
            1 for p in result["plugins_detected"] if p["version"])

        # Scoring: every detected plugin is attack surface; readable
        # version strings are a directly-actionable CVE-discovery signal.
        penalty = 0
        if result["plugin_count"] >= 1:
            penalty += min(30, result["plugin_count"] * 3)
        if result["versioned_count"] >= 1:
            penalty += min(20, result["versioned_count"] * 5)
            result["issues"].append(
                f"{result['versioned_count']} WordPress plugin(s) expose "
                "version strings in /wp-content/plugins/<plugin>/readme.txt — "
                "directly actionable for CVE chaining"
            )
        if result["plugin_count"] >= 8:
            result["issues"].append(
                f"{result['plugin_count']} popular WordPress plugins detected — "
                "wide CMS-plugin attack surface (top SA SME ransomware vector)"
            )
        result["score"] = max(0, 100 - penalty)
        return result


class VendorBreachChecker:
    """
    Correlates the email-vendor surface (detected via SPF include chain, the
    same logic as S-4) against a curated public-record breach database
    (`vendor_breaches.json`). For each vendor with known breaches in the
    relevant lookback window, surfaces a finding with breach age, severity,
    and class — strongest broker narrative for "your supplier was breached
    7 months ago, are you reviewing it?".

    Maintenance discipline mirrors `darkweb_providers.py`: editorial review
    before adding new rows, severity_level field, exposure_class field.
    """

    LOOKBACK_DAYS = 1825  # 5 years — vendor incidents stay relevant beyond
                           # 1-2 years because customer-key rotation is
                           # typically incomplete even after disclosure.
    SEVERITY_PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3}

    _CACHED_DB = None
    _CACHED_DB_PATH = None

    @classmethod
    def _load_db(cls) -> dict:
        if cls._CACHED_DB is not None:
            return cls._CACHED_DB
        path = Path(__file__).parent / "vendor_breaches.json"
        try:
            with open(path, encoding="utf-8") as f:
                cls._CACHED_DB = json.load(f)
                cls._CACHED_DB_PATH = str(path)
        except Exception:
            cls._CACHED_DB = {"breaches": []}
        return cls._CACHED_DB

    @staticmethod
    def _days_since(date_str: str) -> int:
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except Exception:
            return 99_999

    def check(self, domain: str) -> dict:
        result = {
            "status": "completed",
            "vendors_detected": [],
            "matches": [],
            "match_count": 0,
            "critical_match_count": 0,
            "high_match_count": 0,
            "score": 100,
            "issues": [],
        }
        db = self._load_db()
        breaches_by_vendor = {}
        for b in db.get("breaches", []):
            breaches_by_vendor.setdefault(b["vendor"], []).append(b)

        # Re-extract the vendor surface (cheaper than a cross-checker
        # dependency and keeps this checker self-contained for testing).
        surface = EmailVendorSurfaceChecker()
        includes = surface._walk_includes(domain)
        if not includes:
            result["status"] = "no_data"
            return result

        seen = set()
        for entry in includes:
            v = surface._classify(entry["include"])
            if v and v not in seen:
                seen.add(v)
                result["vendors_detected"].append(v)

        if not result["vendors_detected"]:
            return result

        penalty = 0
        for v in result["vendors_detected"]:
            for b in breaches_by_vendor.get(v, []):
                age = self._days_since(b.get("date", ""))
                if age > self.LOOKBACK_DAYS:
                    continue
                sev = b.get("severity", "medium")
                # Linear decay: full penalty at age=0, zero at LOOKBACK_DAYS.
                decay = max(0.0, 1.0 - (age / self.LOOKBACK_DAYS))
                pen = self.SEVERITY_PENALTY.get(sev, 5) * decay
                penalty += pen
                match = {
                    "vendor": v,
                    "date": b.get("date"),
                    "age_days": age,
                    "severity": sev,
                    "exposure_class": b.get("exposure_class", ""),
                    "summary": b.get("summary", ""),
                    "penalty_applied": round(pen, 2),
                }
                result["matches"].append(match)
                if sev == "critical":
                    result["critical_match_count"] += 1
                elif sev == "high":
                    result["high_match_count"] += 1

        result["matches"].sort(key=lambda m: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(m["severity"], 4),
            m["age_days"],
        ))
        result["match_count"] = len(result["matches"])
        result["score"] = max(0, round(100 - penalty))

        if result["critical_match_count"] > 0:
            top = result["matches"][0]
            months = max(1, top["age_days"] // 30)
            result["issues"].append(
                f"CRITICAL: {top['vendor']} had a confirmed breach "
                f"~{months} month(s) ago ({top['date']}, "
                f"{top['exposure_class']}) — this vendor is in your email "
                "send-authority chain"
            )
        elif result["high_match_count"] > 0:
            top = result["matches"][0]
            months = max(1, top["age_days"] // 30)
            result["issues"].append(
                f"{top['vendor']} had a breach ~{months} month(s) ago "
                f"({top['date']}, {top['severity']}) — review whether "
                "credentials / tokens have been rotated"
            )
        return result
