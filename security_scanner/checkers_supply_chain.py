"""
Supply-chain checkers — assess risk inherited from related/supplier
domains, exposed third-party dependency manifests, third-party JavaScript
loaded into the page, the email-vendor surface (SPF include chain), the
CMS-plugin attack surface, and known-breach correlations against the
detected vendor surface.

S-1  RelatedDomainsChecker (probes broker-CONFIRMED siblings; discovery runs on every
     scan from certificate records, but discovered domains are listed, not probed)
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

import ipaddress
import json
import re
from concurrent.futures import wait as _wait_futures
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from scanner_utils import *
from checkers_core import SSLChecker
from checkers_network import DNSInfrastructureChecker
from checkers_threats import InformationDisclosureChecker, OSVChecker


class RelatedDomainsChecker:
    # The wall-clock budget. Each confirmed domain runs three sub-checks in
    # turn (SSL, DNS ports, information disclosure), and none of them has a
    # deadline of its own. Worked through the real sub-checkers' timeouts, a
    # domain with one address whose HTTPS does not answer takes about 144 to
    # 146 s with no open port, and about 150 s with one, because the port probe
    # then runs its canary connects (step-5 critique rounds 3 and 4). Each
    # further address adds about 137 s, so such a host can outrun the budget
    # and is then NOT ASSESSED (OUTSTANDING 5aa). Four domains run at a time,
    # so the budget is one allowance per round of four, with a margin over the
    # single-address profile: 180 s for up to four domains, 540 s for ten.
    # check() returns when the budget ends; a domain still being probed then
    # is reported NOT ASSESSED.
    WORKERS = 4
    ROUND_BUDGET = 180            # seconds per round of WORKERS domains
    MAX_DOMAINS = 10              # cap broker-declared list to bound scan time

    @classmethod
    def budget_seconds(cls, n):
        """Wall-clock seconds allowed for assessing *n* confirmed domains."""
        rounds = -(-max(1, int(n or 0)) // cls.WORKERS)
        return cls.ROUND_BUDGET * rounds

    def check(self, primary_domain: str, related_domains: list = None) -> dict:
        related = [d.strip().lower() for d in (related_domains or [])
                   if d and isinstance(d, str) and d.strip()]
        related = [d for d in related if d != primary_domain.lower()]
        related = list(dict.fromkeys(related))[:self.MAX_DOMAINS]

        # "completed", never "skipped", when nothing was confirmed. Measured over
        # the 30 retained scans: a skipped related_domains category redistributes
        # its weight and prices the scan +5 to +16 points higher (mean +8.47),
        # while completed/100 prices at exactly +0. Emitting "skipped" here would
        # therefore make a client with no related domains DEARER than a client
        # with one clean confirmed sibling, which inverts the incentive. The
        # step-1 rule is honoured on the other side by the caller, which reports
        # a discovery outage as "unassessed" rather than as a clean result.
        result = {
            "status": "completed",
            "declared_count": len(related),
            "scanned_count": 0,
            "dependants": [],
            "worst_domain": None,
            "critical_count": 0,
            "high_count": 0,
            "not_assessed": [],
            "score": 100,
            "issues": [],
        }
        if not related:
            return result

        def _measured(res, key):
            # The value a sub-check MEASURED, or None when it did not measure.
            # A measured 0 stays 0: the old `int(x or 100)` read the worst
            # possible result as a clean 100, and a sub-check that raised kept a
            # default of 100, so both priced the sibling as clean.
            if not isinstance(res, dict) or res.get("status", "completed") != "completed":
                return None
            v = res.get(key)
            try:
                return None if v is None else int(v)
            except (TypeError, ValueError):
                return None

        def _open_ports(dns):
            # dns_infrastructure open_ports are dicts; tolerate bare ints too.
            return {p.get("port") if isinstance(p, dict) else p
                    for p in ((dns or {}).get("open_ports") or [])}

        def _tls_reached(ssl):
            # Did any TLS handshake happen? On a connection failure the stdlib
            # path leaves every tls_versions flag False and the certificate as
            # {"valid": False, "error": ...}. A certificate that failed
            # verification still means TLS was reached, and is a finding.
            tv = (ssl or {}).get("tls_versions") or {}
            if any(bool(v) for v in tv.values()):
                return True
            cert = (ssl or {}).get("certificate") or {}
            if cert.get("valid") or cert.get("subject"):
                return True
            err = str(cert.get("error") or "").lower()
            return "certificate verify failed" in err or "certificate_verify_failed" in err

        def _ssl_errors(ssl):
            # Every connection error the SSL check recorded. The certificate and
            # cipher probes are separate connections to 443, so one can hold the
            # answer the other missed (step-5 critique round 6).
            return [str(((ssl or {}).get(k) or {}).get("error")).lower()
                    for k in ("certificate", "cipher_suite")
                    if ((ssl or {}).get(k) or {}).get("error")]

        # 443 accepted a connection and answered without TLS: plain HTTP, an EOF
        # or a reset after the connect.
        _TLS_ANSWERED = ("wrong_version_number", "wrong version number",
                         "record layer failure", "packet length too long",
                         "unknown protocol", "unexpected_eof", "eof occurred",
                         "connection reset", "errno 104", "forcibly closed",
                         "winerror 10054")
        # 443 accepted a connection and never answered the handshake.
        _TLS_HUNG = ("handshake operation timed out", "read operation timed out")
        # The connection itself timed out: nothing accepted it.
        _TCP_TIMEOUT = ("timed out", "timeout", "winerror 10060",
                        "did not properly respond")

        def _has(errs, marks):
            return any(m in e for e in errs for m in marks)

        def _addresses(d):
            # (every IPv4 address, every IPv6 address). All of them, not only
            # the first: the port probe uses the first IPv4 address, but the
            # SSL and HTTP probes resolve the name for themselves, in either
            # address family.
            try:
                v4 = [a for a in (dns_cache.resolve(d, "A") or []) if a]
                if not v4:
                    ip = dns_cache.get_ip(d)
                    v4 = [ip] if ip else []
            except Exception:
                v4 = []
            try:
                v6 = [a for a in (dns_cache.resolve(d, "AAAA") or []) if a]
            except Exception:
                v6 = []
            return v4, v6

        def _public(addr):
            try:
                return ipaddress.ip_address(str(addr)).is_global
            except ValueError:
                return False

        def _scan_one(d: str) -> dict:
            dep = {"domain": d, "ssl_grade": None, "ssl_score": None,
                   "info_score": None, "dns_risk": None,
                   "critical_paths": 0, "lite_score": None,
                   "measured": False, "not_measured": [], "issues": []}
            # A sibling that does not resolve cannot be measured. Every check
            # would fail, and SSLChecker scores a failed connection 0, which
            # priced a broker's typo as the worst possible sibling. The port
            # probe is IPv4 only, so a name with only IPv6 records is not
            # assessed either, and is not described as unresolvable. A name
            # with any private, loopback or link-local address, in either
            # family, is not the insured's public estate: probing it would
            # reach an address inside the scanner's own network and score
            # whatever answers there.
            v4, v6 = _addresses(d)
            why = None
            if not v4:
                why = "resolves to IPv6 only" if v6 else "does not resolve"
            elif not all(_public(a) for a in v4 + v6):
                why = "resolves to a non-public address"
            if why:
                dep["not_measured"] = ["dns", "info", "ssl"]
                dep["issues"].append("[dns] %s; not assessed on this scan" % why)
                return dep
            ssl = dns = info = None
            try:
                ssl = SSLChecker().check(d) or {}
                dep["ssl_grade"] = ssl.get("grade")
                dep["issues"] += [f"[ssl] {i}" for i in (ssl.get("issues") or [])[:3]]
            except Exception:
                ssl = None
            try:
                dns = DNSInfrastructureChecker().check(d) or {}
                dep["dns_risk"] = _measured(dns, "risk_score")
                dep["issues"] += [f"[dns] {i}" for i in (dns.get("issues") or [])[:3]]
            except Exception:
                dns = None
            try:
                info = InformationDisclosureChecker().check(d) or {}
                dep["info_score"] = _measured(info, "score")
                codes = info.get("probe_status_codes")
                if (dep["info_score"] is not None and isinstance(codes, dict)
                        and not [c for c in codes if str(c) != "0"]):
                    # No probe got an HTTP answer (every status 0): the check
                    # still reports completed/100, but it measured nothing.
                    dep["info_score"] = None
                if dep["info_score"] is not None:
                    dep["critical_paths"] = sum(
                        1 for p in (info.get("exposed_paths") or [])
                        if p.get("risk_level") == "critical"
                    )
                dep["issues"] += [f"[info] {i}" for i in (info.get("issues") or [])[:3]]
            except Exception:
                info = None
            ssl_score = _measured(ssl, "score")
            if ssl_score is not None and not _tls_reached(ssl):
                # No TLS handshake completed. 443 answering without TLS (plain
                # HTTP, an EOF, a reset) is a finding whatever the port probe
                # saw. A handshake that 443 accepted and never answered measured
                # nothing whatever it saw: a TCP accept is not an answer. Short
                # of either, the port probe decides: plain HTTP on 80 with
                # nothing on 443, or 443 closing, is a finding; a host with no
                # web port, or whose ports are unknown, measured nothing, and a
                # connection that timed out on a 443 the probe saw open is not
                # an answer (step-5 critique rounds 5 and 6).
                errs = _ssl_errors(ssl)
                if _has(errs, _TLS_ANSWERED):
                    pass
                elif _has(errs, _TLS_HUNG):
                    ssl_score = None
                else:
                    ports = _open_ports(dns) if dep["dns_risk"] is not None else set()
                    if not ports & {80, 443}:
                        ssl_score = None
                    elif 443 in ports and _has(errs, _TCP_TIMEOUT):
                        ssl_score = None
            dep["ssl_score"] = ssl_score
            parts = {
                "ssl": dep["ssl_score"],
                "info": dep["info_score"],
                "dns": None if dep["dns_risk"] is None else max(0, 100 - dep["dns_risk"]),
            }
            got = [v for v in parts.values() if v is not None]
            dep["not_measured"] = sorted(k for k, v in parts.items() if v is None)
            for k in dep["not_measured"]:
                dep["issues"].append(f"[{k}] not assessed on this scan")
            if got:
                # Worst of what was measured. A check that returned nothing is
                # left out rather than counted as clean; one that returned a
                # finding still loads the sibling.
                dep["measured"] = True
                dep["lite_score"] = min(got)
            return dep

        # The budget bounds the wait. A `with ThreadPoolExecutor` block waits on
        # exit for every running probe, so the budget bounded nothing, check()
        # returned only when its slowest domain did, and the caller's own
        # timeout could fire first and discard everything that had finished,
        # findings included (critique round 3). At the budget the pool is shut
        # down without waiting: queued domains are cancelled, running ones are
        # left to finish in the background, and both are reported NOT ASSESSED.
        pool = ThreadPoolExecutor(max_workers=self.WORKERS)
        futures = {pool.submit(_scan_one, d): d for d in related}
        _wait_futures(futures, timeout=self.budget_seconds(len(related)))
        pool.shutdown(wait=False, cancel_futures=True)
        timed_out = []
        for fut, d in futures.items():
            if fut.done() and not fut.cancelled():
                try:
                    result["dependants"].append(fut.result(timeout=0))
                except Exception:
                    pass
            else:
                timed_out.append(d)
        result["timed_out"] = timed_out

        # Only a sibling on which at least one check returned a result counts
        # as scanned. The rest are listed as not assessed; the caller reports
        # the category NOT ASSESSED when nothing at all was measured.
        measured = [d for d in result["dependants"] if d.get("measured")]
        result["scanned_count"] = len(measured)
        _measured_names = {m["domain"] for m in measured}
        result["not_assessed"] = [d for d in related if d not in _measured_names]
        if not measured and timed_out:
            # Nothing was measured, and time ran out on at least one domain
            # (any others did not resolve or were not public). A "timeout" is
            # never checkpointed, so a resumed scan probes again, and the
            # caller reports the confirmed domains NOT ASSESSED.
            result["status"] = "timeout"
            return result

        if measured:
            worst = min(measured, key=lambda d: d["lite_score"])
            result["worst_domain"] = {
                "domain": worst["domain"],
                "lite_score": worst["lite_score"],
            }
            result["critical_count"] = sum(d.get("critical_paths", 0)
                                            for d in measured)
            result["high_count"] = sum(1 for d in measured
                                        if d["lite_score"] < 60)
            result["score"] = min(d["lite_score"] for d in measured)

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
        # Record what each probe met. Returning None for every non-200 is right
        # for avoiding false positives, but it makes a WAF that refuses
        # everything indistinguishable from a site with no exposed manifests —
        # which then scores 100/100 for a dependency surface never examined.
        if head is not None:
            self._codes[head.status_code] = self._codes.get(head.status_code, 0) + 1
        if head is None or head.status_code != 200:
            return None
        r = HTTP.get(url, timeout=8, allow_redirects=False)
        if r is not None and r.status_code != 200:
            self._codes[r.status_code] = self._codes.get(r.status_code, 0) + 1
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
        self._codes = {}     # HTTP status -> count, across every manifest probe

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
        except (TimeoutError, FuturesTimeoutError):
            # FuturesTimeoutError (concurrent.futures) != builtin TimeoutError on
            # Python 3.10 (VM) — keep the partial manifests instead of erroring.
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

        result["probe_status_codes"] = dict(sorted(self._codes.items()))
        # Every manifest path refused and nothing retrieved => we never looked at
        # the dependency surface, so "no exposed manifests, 100/100" is a
        # statement about the WAF. A real origin answers 404 for paths it does
        # not host, so any non-blocking status proves it was talking to us.
        _BLOCKING = {401, 403, 406, 409, 418, 429, 451, 503}
        _n = sum(self._codes.values())
        _answered = sum(k for c, k in self._codes.items() if c not in _BLOCKING)
        # A manifest denied by a server that still serves its home page is not
        # leaked — the control probe separates that from a blanket edge block.
        from http_client import HTTP as _HTTP
        if (_n and not result["exposed_manifests"] and _answered == 0
                and not _HTTP.origin_answering(domain)):
            result["status"] = "unreachable"
            result["http_status"] = max(self._codes, key=self._codes.get)
            result["unreachable_reason"] = (
                f"Exposed dependency manifests could not be assessed — all {_n} "
                f"probes were refused by a WAF/CDN (HTTP "
                f"{', '.join(str(c) for c in sorted(self._codes))}), as was the "
                f"site root. No verdict on a leaked dependency map is implied.")
            result.pop("score", None)

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
        # Mandrill is Mailchimp's (Intuit) transactional-email product and shares
        # the Mailchimp breach exposure — keep it under the "mailchimp" key so it
        # correlates against the mailchimp rows in vendor_breaches.json (S-5).
        ("mailchimp",           ["servers.mcsv.net", "_spf.mailchimp.com",
                                  "spf.mandrillapp.com", "mandrillapp.com",
                                  "mandrill.com"]),
        ("amazon_ses",          ["amazonses.com"]),
        ("microsoft_365",       ["spf.protection.outlook.com",
                                  "spf.messaging.microsoft.com"]),
        ("google_workspace",    ["_spf.google.com", "aspmx.googlemail.com"]),
        # transmail.net / zeptomail are Zoho's transactional-email service (ZeptoMail,
        # formerly TransMail) — same vendor, classify under "zoho".
        ("zoho",                ["zoho.com", "_spf.zoho.eu", "zohomail.com",
                                  "transmail.net", "zeptomail.com",
                                  "zeptomail.eu"]),
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
        # Identity-provider class — Okta isn't an email SaaS in the
        # traditional sense, but its SAML/SSO is in scope for vendor-
        # breach correlation (S-5) because customer SSO compromise is
        # the documented downstream impact (Storm-0558 / 1Password /
        # Cloudflare 2023). Without an entry here, vendor_breaches.json
        # rows for "okta" cannot correlate against ANY detected surface.
        ("okta",                ["okta.com", "oktapreview.com", "okta.net"]),
    ]

    # SPF mechanism and modifier names are case-insensitive (RFC 7208
    # s4.6.1), so "Include:" authorises a vendor and "REDIRECT=" delegates
    # exactly as the lower-case spellings do; reading them as absent certified
    # a surface the walk never followed (step-5 critique round 9). A term
    # starts the record or follows a space, and a mechanism may carry a
    # qualifier.
    INCLUDE_RE = re.compile(r"(?:^|\s)[-+?~]?include:(\S+)", re.I)
    REDIRECT_RE = re.compile(r"(?:^|\s)redirect=(\S+)", re.I)
    SPF_VERSION_RE = re.compile(r"v=spf1(?:\s|$)", re.I)

    def _classify(self, include_domain: str) -> str:
        d = include_domain.lower().rstrip(".")
        for vendor, patterns in self.VENDOR_PATTERNS:
            if any(d == p or d.endswith("." + p) for p in patterns):
                return vendor
        return ""

    def _fetch_spf(self, domain: str) -> str:
        # "" when there is no SPF record, whether the name has no TXT record or
        # does not exist. A lookup that did not answer (a timeout, SERVFAIL, no
        # nameservers) returns "" too, but is recorded in _spf_failed, so an
        # empty vendor surface is not read as a measured one (step-5 critique
        # round 7).
        failed = self.__dict__.setdefault("_spf_failed", set())
        try:
            import dns.resolver
        except Exception:
            failed.add(domain)
            return ""
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=DEFAULT_TIMEOUT)
            for rdata in answers:
                txt = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if self.SPF_VERSION_RE.match(txt):
                    return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ""
        except Exception:
            failed.add(domain)
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
        # A record that delegates with redirect= is not walked: record it, so an
        # empty vendor surface behind it is not read as a measured one (step-5
        # critique round 8).
        if self.REDIRECT_RE.search(record):
            self.__dict__.setdefault("_spf_unfollowed", set()).add(domain)
        out = []
        for inc in includes[:10]:
            out.append({"include": inc, "depth": depth})
            out.extend(self._walk_includes(inc, depth + 1, seen))
        return out

    def _spf_outcome(self, domain: str) -> str:
        """answered, failed or not_followed, for the domain's own SPF lookup."""
        if domain in self.__dict__.get("_spf_failed", set()):
            return "failed"
        if domain in self.__dict__.get("_spf_unfollowed", set()):
            return "not_followed"
        return "answered"

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
        self._spf_failed, self._spf_unfollowed = set(), set()
        includes = self._walk_includes(domain)
        if not includes:
            result["status"] = "no_data"
            # Whether "no includes" was measured. Reporting only: the status,
            # and so the price, is unchanged.
            result["spf_lookup"] = self._spf_outcome(domain)
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
        if not vendor_map and (self._spf_failed or self._spf_unfollowed):
            # Includes were found, but a lookup behind them did not answer, or
            # delegates with redirect=, and no vendor was identified: the vendor
            # surface was not measured. "no_data" prices as a completed result
            # with no vendors does (step-5 critique round 8).
            result["status"] = "no_data"
            result["spf_lookup"] = "failed" if self._spf_failed else "not_followed"
            return result
        # Recorded on a completed result too, so a result stored before this
        # field existed is never read as a measured one; "partial" is a walk
        # that found a vendor while another lookup did not answer or was not
        # followed, so the vendors are a lower bound (step-5 critique round 9).
        result["spf_lookup"] = ("partial" if (self._spf_failed or self._spf_unfollowed)
                                else "answered")
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

    def _is_wordpress(self, domain: str) -> "bool | None":
        from http_client import HTTP
        # Robust discriminator. The previous version accepted ANY
        # 200/301/302/401/403 on /wp-content/ etc., so a CDN/WAF catch-all
        # (which 200s or 403s every path, including random ones) tripped it
        # for non-WordPress sites (e.g. takealot, a Next.js SPA behind
        # Cloudflare). Require a *genuine* WordPress fingerprint and bail if
        # a random control path looks identical (catch-all). Mirrors the
        # 200-only + body-sanity gate in S-3 DependencyManifestChecker._probe.
        base = f"https://{domain}"

        # (a) Catch-all guard — fetch a random nonsense path. If it 200s with
        #     a real body, the host echoes content to everything and no probe
        #     below can be trusted.
        import secrets
        rand_path = f"/{secrets.token_hex(8)}-notreal.txt"
        catch_all_body = ""
        home_usable = False
        login_usable = False
        try:
            ctrl = HTTP.get(base + rand_path, timeout=6, allow_redirects=False)
            if ctrl is not None and ctrl.status_code == 200:
                try:
                    catch_all_body = (ctrl.text or "")[:2000]
                except Exception:
                    catch_all_body = ""
        except Exception:
            catch_all_body = ""

        # (b) Homepage HTML markers — wp-content/wp-includes asset refs or a
        #     WordPress generator meta tag are reliable, body-confirmed.
        try:
            home = HTTP.get(base + "/", timeout=8, allow_redirects=True)
            if home is not None and home.status_code == 200:
                body = home.text or ""
                home_usable = bool(body.strip()) and body[:2000] != catch_all_body
                html = (home.text or "").lower()
                if ('content="wordpress' in html
                        or "/wp-content/" in html
                        or "/wp-includes/" in html):
                    return True
        except Exception:
            pass

        # (c) wp-login.php must return 200 with a genuine WP login body —
        #     not a catch-all 200. Reject if it matches the control body.
        try:
            login = HTTP.get(base + "/wp-login.php", timeout=6,
                             allow_redirects=False)
            if login is not None and login.status_code in (200, 404, 410):
                login_usable = True
            if login is not None and login.status_code == 200:
                body = (login.text or "")
                low = body.lower()
                if (len(body) >= 10
                        and body != catch_all_body
                        and ("user_login" in low or "wp-submit" in low
                             or "wordpress" in low)):
                    return True
        except Exception:
            pass

        # Negative requires usable homepage and login evidence.
        return False if home_usable and login_usable else None

    def _probe_plugin(self, base: str, dirname: str) -> dict:
        from http_client import HTTP
        # A plugin counts as PRESENT only when its readme.txt returns HTTP 200
        # AND the body is a genuine WordPress plugin readme. The old version
        # accepted any 200/301/302/401/403 on the plugin *directory* as
        # evidence — so a CDN/WAF that 403s (or 200s) every path reported all
        # 25 probed plugins as installed. A bare 403 dir is not evidence of a
        # plugin. Mirrors the 200-only + body-sanity gate in S-3
        # DependencyManifestChecker._probe.
        plugin_root = f"{base}/wp-content/plugins/{dirname}/"
        try:
            r = HTTP.get(f"{plugin_root}readme.txt", timeout=6,
                          allow_redirects=False)
        except Exception:
            return None
        if r is None or r.status_code != 200:
            return None
        try:
            text = r.text or ""
        except Exception:
            return None
        if len(text) < 10:
            return None
        head = text.lower()[:300]
        if "<html" in head or "<!doctype" in head:
            return None  # CDN/WAF HTML shell, not a readme
        # Real WordPress plugin readme.txt markers (readme.txt spec). At least
        # one must be present, else this is a catch-all / error body.
        low = text.lower()
        if not ("=== " in text or "stable tag:" in low or "tested up to:" in low):
            return None
        version = ""
        m = self.README_VERSION_RE.search(text[:8000])
        if m:
            version = m.group(1)
        return {"slug": dirname, "version": version,
                "status_code": r.status_code}

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
        wp = self._is_wordpress(domain)
        if wp is False:
            result["status"] = "skipped"
            result["probe_status"] = "confirmed_non_wordpress"
            return result
        if wp is None:
            result.pop("score", None)
            result.update(status="unreachable", is_wordpress=None, probe_status="probe_failed",
                          issues=["CMS fingerprint probes did not return a usable response; WordPress status is not assessed."])
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
            except (TimeoutError, FuturesTimeoutError):
                # FuturesTimeoutError (concurrent.futures) != builtin TimeoutError on
                # Python 3.10 (VM) — keep the partial plugins instead of erroring.
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
        surface._spf_failed, surface._spf_unfollowed = set(), set()
        includes = surface._walk_includes(domain)
        if not includes:
            result["status"] = "no_data"
            # As for the vendor surface: was "no vendors" measured?
            result["spf_lookup"] = surface._spf_outcome(domain)
            return result

        seen = set()
        for entry in includes:
            v = surface._classify(entry["include"])
            if v and v not in seen:
                seen.add(v)
                result["vendors_detected"].append(v)

        if not result["vendors_detected"]:
            if surface._spf_failed or surface._spf_unfollowed:
                # No vendor identified, and a lookup behind the includes did
                # not answer or was not followed: not measured, as for the
                # vendor surface.
                result["status"] = "no_data"
                result["spf_lookup"] = "failed" if surface._spf_failed else "not_followed"
            else:
                result["spf_lookup"] = "answered"
            return result
        # As for the vendor surface: recorded on a completed result too, and
        # "partial" where the walk found a vendor beside a lookup that did not
        # answer or was not followed (step-5 critique round 9).
        result["spf_lookup"] = ("partial" if (surface._spf_failed or surface._spf_unfollowed)
                                else "answered")

        penalty = 0
        for v in result["vendors_detected"]:
            for b in breaches_by_vendor.get(v, []):
                age = self._days_since(b.get("date", ""))
                if age > self.LOOKBACK_DAYS:
                    continue
                sev = b.get("severity", "medium")
                # Linear decay: full penalty at age=0, zero at LOOKBACK_DAYS.
                decay = max(0.0, 1.0 - (age / self.LOOKBACK_DAYS))
                # Clamp an unknown/blank severity to "low" (3) so a malformed
                # or unrecognised row can never out-score an explicit "low".
                # Named severities keep their calibrated penalties unchanged.
                sev_penalty = self.SEVERITY_PENALTY.get(
                    sev, self.SEVERITY_PENALTY["low"])
                pen = sev_penalty * decay
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
