"""
Cyber Insurance External Security Scanner
Passive, read-only assessment of external-facing infrastructure.
All checks use only publicly available information.
"""

from scanner_utils import *
from checkers_core import *
from checkers_network import *
from checkers_threats import *
from checkers_supply_chain import (
    RelatedDomainsChecker, DependencyManifestChecker, ThirdPartyJSChecker,
    EmailVendorSurfaceChecker, CMSPluginSBOMChecker, VendorBreachChecker,
)
from scoring_analytics import *
# Phase 5 + Phase 6 scoring/insurance invocation lives in scoring_pipeline so the
# live scan and the golden/regen rescore share ONE call sequence (no drift — see
# scoring_pipeline.py). RiskScorer/RansomwareIndex/... stay imported above (via *)
# for RiskScorer.WEIGHTS and any direct use elsewhere.
from scoring_pipeline import apply_risk_score, apply_insurance_analytics
from http_client import HTTP, _apex_of
import os
import scanner_db
# as_completed() raises concurrent.futures.TimeoutError, which on Python <3.11 is
# a DISTINCT class from the builtin TimeoutError. Production runs on Python 3.10,
# so the phase-timeout handlers below MUST catch this class — a bare
# `except TimeoutError` silently fails to catch it and crashes the whole scan
# the moment a phase exceeds its 180s budget (e.g. a target with many IPs).
from concurrent.futures import TimeoutError as FuturesTimeoutError
import socket

# WS3: checkpoints older than this are treated as absent on resume (freshness
# bound; per-data-type TTLs refine this in WS6). Default 6h.
CHECKPOINT_TTL_S = int(os.environ.get("CHECKPOINT_TTL_S", "21600"))


# ---------------------------------------------------------------------------
# Main Scanner Orchestrator
# ---------------------------------------------------------------------------

# Stamped into every results dict. Scan results are persisted as JSON blobs
# (scans.results in SQLite) and re-rendered long after the code that wrote
# them has changed — bump this on any breaking change to the results shape
# so renderers can branch on stored version instead of guessing.
RESULTS_SCHEMA_VERSION = "1.0"

_CRED_RECENCY_BANDS = ["<30d", "30-90d", "90-180d", "180-360d", "1-2yr", ">2yr"]

# Known aggregator / combo / credential-stuffing lists — re-packaged historical
# data. A recent OBSERVED/upload date on these is re-circulation, NOT fresh
# compromise, so they must not, on their own, make exposure read as "active".
COMBO_LIST_SOURCES = {
    "alien txtbase", "naz.api", "apollo", "collection #1", "collection #2-5",
    "anti public combo list", "exploit.in", "rockyou2024", "rockyou2021",
    "socradar.io",
}


def _cred_recency_band(age_days):
    if age_days is None:
        return None
    if age_days < 30:   return "<30d"
    if age_days < 90:   return "30-90d"
    if age_days < 180:  return "90-180d"
    if age_days < 360:  return "180-360d"
    if age_days < 730:  return "1-2yr"
    return ">2yr"


def build_credential_correlation(cat_results: dict, today=None) -> dict:
    """Credential-compromise cross-correlation (REPORTING-ONLY, mirrors the
    Phase 4f supply-chain pattern). Joins four independent signals:

      1. Breached credentials present       (DeHashed record corpus)
      2. Recency of the exposure            (dates from IntelX / HIBP / DeHashed)
      3. Active theft                       (Hudson Rock infostealer infections)
      4. Active circulation / trading       (IntelX paste / leak / dark-web mentions)

    The verdict escalates None -> Critical on how many independent signals
    confirm ACTIVE (not merely historical) compromise. Output strings are
    assembled dynamically from the actual findings — never generic. Carries
    NO scoring weight: the underlying signals already score through their own
    channels (credential_risk, hudson_rock, dehashed), so this is purely a
    representational join (same design rule as third_party_correlation)."""
    today = today or datetime.now(timezone.utc)
    de = cat_results.get("dehashed", {}) or {}
    br = cat_results.get("breaches", {}) or {}
    hr = cat_results.get("hudson_rock", {}) or {}
    ix = cat_results.get("intelx", {}) or {}

    out = {
        "status": "completed", "severity": "none",
        "critical_count": 0, "high_count": 0, "medium_count": 0,
        "recency_bands": {b: 0 for b in _CRED_RECENCY_BANDS},
        "dated_records": 0, "signals": {}, "issues": [], "rationale": "",
    }

    # Signal 1 — breached credential corpus
    de_total = int(de.get("total_entries", 0) or 0)
    de_sources = [s for s in (de.get("breach_sources") or []) if s]
    # Password-bearing record COUNT (not just a yes/no) — only a subset of the
    # breached corpus actually ships a credential. Overstating all records as
    # "with passwords" inflates the rotate-now severity (caught in card back-test).
    _cb = de.get("credential_breakdown", {}) or {}
    pw_records = int(_cb.get("plaintext_count", 0) or 0) + int(_cb.get("hashed_count", 0) or 0)
    has_pw = bool(de.get("has_passwords"))
    hibp_count = int(br.get("breach_count", 0) or 0)
    breached = de_total > 0 or hibp_count > 0

    # Signal 2 — recency (parse every dated source we have)
    ages = []

    def _consume(date_str):
        if not date_str:
            return
        s = str(date_str)[:10]
        for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
            try:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
                age = max(0, (today - dt).days)
                ages.append(age)
                out["recency_bands"][_cred_recency_band(age)] += 1
                return
            except Exception:
                continue

    # Primary credential-date source: DeHashed breach sources cross-referenced
    # to HIBP named-breach dates (+ KNOWN_BREACH_DATES fallback for compilation
    # lists) — the rough date guesstimate, enriched onto dehashed.enriched_sources.
    for s in (de.get("enriched_sources") or []):
        bd = s.get("breach_date")
        if bd and bd != "Unknown":
            _consume(bd)
    for rec in (ix.get("recent_results") or []):
        _consume(rec.get("date"))
    for d in (de.get("breach_details") or []):
        _consume(d.get("breach_date") or d.get("date"))
    for b in (br.get("breaches") or []):
        _consume(b.get("breach_date") or b.get("date") or b.get("BreachDate"))
    # Infostealer INFECTION date — the most reliable freshness anchor (a
    # point-in-time malware capture, not re-compiled breach data).
    _consume(hr.get("most_recent_compromise"))
    freshest = min(ages) if ages else None
    out["dated_records"] = len(ages)

    # Are the breached sources purely aggregator / combo lists? If so, a recent
    # OBSERVED date on them is re-circulation of old data, not fresh theft.
    combo_sources = [s for s in de_sources if s.lower().strip() in COMBO_LIST_SOURCES]
    all_combo = bool(de_sources) and len(combo_sources) == len(de_sources)

    # Signal 3 — active theft (infostealer), DATE-ANCHORED
    hr_emp = int(hr.get("compromised_employees", 0) or 0)
    hr_usr = int(hr.get("compromised_users", 0) or 0)
    hr_days = hr.get("days_since_compromise")
    active_theft = (hr.get("status") == "completed") and (hr_emp > 0 or hr_usr > 0)
    # A recent infection date proves the theft is LIVE, not historical/recycled.
    active_theft_fresh = active_theft and (hr_days is not None and hr_days <= 90)

    # Signal 4 — active CIRCULATION (IntelX or replacement). Provider-agnostic:
    # any configured dark-web/forum source populates these counts. Lower
    # confidence than active theft because dumps are frequently re-posted.
    ix_available = ix.get("status") == "completed"
    ix_paste = int(ix.get("paste_count", 0) or 0)
    ix_leak = int(ix.get("leak_count", 0) or 0)
    ix_dw = int(ix.get("darkweb_count", 0) or 0)
    circulating = ix_available and (ix_paste + ix_leak + ix_dw) > 0

    # "Genuine recency": a date-proven fresh infection OR a recent NON-combo
    # breach. Re-posted combo lists do not qualify on their own.
    recent_genuine = active_theft_fresh or (
        freshest is not None and freshest <= 360 and not all_combo)

    out["signals"] = {
        "breached": breached, "breached_records": de_total,
        "has_passwords": has_pw, "password_records": pw_records,
        "sources": de_sources[:6], "combo_only": all_combo,
        "recent": recent_genuine, "freshest_age_days": freshest,
        "active_theft": active_theft, "active_theft_fresh": active_theft_fresh,
        "infostealer_employees": hr_emp, "infostealer_users": hr_usr,
        "infostealer_last_compromised": hr.get("most_recent_compromise"),
        "infostealer_days_ago": hr_days,
        "stealer_families": hr.get("stealer_families", []),
        "circulating": circulating, "forum_available": ix_available,
        "intelx_paste": ix_paste, "intelx_leak": ix_leak, "intelx_darkweb": ix_dw,
    }

    if not breached and not active_theft and not circulating:
        out["rationale"] = ("No breached credentials, infostealer infections, or "
                            "dark-web/forum mentions detected for this domain.")
        return out

    # Verdict — driven by DATE-PROVEN active theft, not re-circulation
    if breached and active_theft_fresh:
        sev = "critical"
    elif active_theft_fresh:
        sev = "high"
    elif breached and (active_theft or recent_genuine):
        sev = "high"
    elif breached and circulating:
        sev = "medium"   # corpus circulating but no fresh-theft proof — may be recycled
    elif active_theft or circulating:
        sev = "medium"
    elif breached and freshest is not None and freshest <= 730:
        sev = "medium"
    elif breached:
        sev = "low"
    else:
        sev = "medium"
    out["severity"] = sev
    out[{"critical": "critical_count", "high": "high_count",
         "medium": "medium_count"}.get(sev, "medium_count")] = 1 if sev != "low" else 0

    # ---- Dynamic, data-driven narrative (no boilerplate) ----
    facts = []
    if de_total:
        src = (" (sources: " + ", ".join(de_sources[:4]) + ")") if de_sources else ""
        if pw_records > 0:
            pw = f", {pw_records:,} with passwords"
        elif has_pw:
            pw = ", some with passwords"
        else:
            pw = ""
        facts.append(f"{de_total:,} leaked credential record(s){pw}{src}")
    if hibp_count:
        facts.append(f"{hibp_count} known breach(es) on record")
    if active_theft:
        bits = []
        if hr_emp: bits.append(f"{hr_emp} employee device(s)")
        if hr_usr: bits.append(f"{hr_usr:,} user account(s)")
        when = f", most recent infection {hr_days} day(s) ago" if hr_days is not None else ""
        fam = hr.get("stealer_families") or []
        famtxt = f" [{', '.join(fam[:4])}]" if fam else ""
        facts.append("ACTIVE infostealer theft on " + " + ".join(bits) + when + famtxt)
    if circulating:
        fb = []
        if ix_leak: fb.append(f"{ix_leak} leak-site")
        if ix_paste: fb.append(f"{ix_paste} paste-site")
        if ix_dw: fb.append(f"{ix_dw} dark-web-market")
        rc = " — may include re-circulated historical data" if all_combo else ""
        facts.append(", ".join(fb) + " mention(s) circulating" + rc)
    elif not ix_available:
        facts.append("forum/dark-web circulation: monitoring pending (no source configured)")
    if all_combo and de_total:
        facts.append("note: breached sources are aggregator/combo lists (re-packaged historical data)")

    headline = {
        "critical": "Credentials compromised AND being actively stolen now",
        "high": "Active or recent credential exposure — rotate now",
        "medium": "Credential exposure circulating but no fresh-theft proof — likely partly remediated",
        "low": "Historical credential exposure only — likely already remediated",
    }[sev]
    out["issues"].append(f"{sev.upper()}: {headline}. " + "; ".join(facts) + ".")

    interp = {
        "critical": ("A known credential corpus PLUS a date-proven live infostealer "
                     "infection — high probability of active account-takeover. Force "
                     "password resets + MFA re-enrolment immediately."),
        "high": ("Credentials are exposed and either freshly stolen or recently breached. "
                 "Prioritise resets and MFA for affected accounts."),
        "medium": ("Exposure is circulating or aging without a fresh-infection signal — "
                   "much of it may already be rotated; confirm resets covered it."),
        "low": ("All datable exposure is old with no active-theft signal — most likely "
                "already remediated via prior password changes."),
    }[sev]
    out["rationale"] = (
        f"Signals — breached: {'Y' if breached else 'N'}; "
        f"actively stolen (dated infostealer): {'Y' if active_theft_fresh else ('aged' if active_theft else 'N')}; "
        f"circulating: {'Y' if circulating else ('N' if ix_available else 'pending')}; "
        f"recency-anchor: {'infostealer infection date' if active_theft_fresh else ('breach dates' if freshest is not None else 'none')}. "
        + interp)
    return out


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
        """Resolve all A record IPs for a domain — uses the shared DNS cache so
        the same lookup is never repeated inside this scan."""
        ips = list(dns_cache.resolve(domain, "A"))
        if not ips:
            try:
                ips = [socket.gethostbyname(domain)]
                dns_cache.seed_records(domain, "A", ips)
            except Exception:
                pass
        return list(dict.fromkeys(ips))  # dedup, preserve order

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
             client_ips: list = None,
             related_domains: list = None,
             scan_id: str = None, resume: bool = False,
             waf_precheck: bool = None) -> dict:
        domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        # Fresh DNS cache for this scan — prevents cross-scan leakage and stale records.
        dns_cache.clear()
        # Reset WAF tracker for this target apex (per-scan baseline; cache
        # is intentionally preserved across scans for future continuous-
        # monitoring use - per SCN-026 cache design).
        scan_apex = _apex_of(f"https://{domain}")
        HTTP.reset_for_scan(scan_apex)
        results = {
            "schema_version": RESULTS_SCHEMA_VERSION,
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

        # Pre-scan WAF / soft-404 probe (opt-in). Off by default so default scans and
        # the offline regression gates are unchanged. Enable with WAF_PRECHECK=1 (or
        # scan(waf_precheck=True)) to establish the blocking / catch-all signal up
        # front, letting the heavy enumeration checkers early-exit (much faster on
        # WAF-protected / soft-404 targets like banks).
        if waf_precheck is None:
            waf_precheck = os.environ.get("WAF_PRECHECK", "").strip().lower() in (
                "1", "true", "on", "yes")
        if waf_precheck:
            try:
                results["scan_context"]["waf_precheck"] = HTTP.precheck(domain)
            except Exception:
                pass

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
            "glasswing":           (GlasswingPartnerChecker().check,   [domain]),
            "dependency_manifests": (DependencyManifestChecker().check, [domain]),
            "third_party_js":      (ThirdPartyJSChecker().check,       [domain]),
            "email_vendor_surface": (EmailVendorSurfaceChecker().check, [domain]),
            "cms_plugin_sbom":     (CMSPluginSBOMChecker().check,      [domain]),
            "vendor_breach":       (VendorBreachChecker().check,       [domain]),
        }

        # Heavy checkers run sequentially AFTER the concurrent batch to cap
        # peak memory (sslyze spawns subprocesses, CT logs parse large JSON,
        # subdomains resolve many IPs). Each is wrapped with a wall-clock
        # timeout guard — sslyze has no internal timeout and can hang on
        # unresponsive servers.
        heavy_checkers = [
            ("ssl",         SSLChecker().check,              [domain], 75),
            # Raised 90→150 (2026-05-27): SubdomainChecker now scans all
            # 150 CT-discovered subdomains for takeover (previously capped
            # at 60 inside an inner 30s loop, leaving ~90 unchecked). Pre-
            # takeover workflow uses ~40s (CT fetch + brute + resolve);
            # 150 takeover probes at 10-15s each / max_workers=10 needs
            # ~110s extra. 150s outer budget gives the takeover loop
            # ~110s to complete, matching the inner 90s as_completed cap.
            ("subdomains",  SubdomainChecker().check,        [domain], 150),
        ]
        if include_fraudulent_domains:
            heavy_checkers.append(
                ("fraudulent_domains", FraudulentDomainChecker().check, [domain], 60)
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
        # Per-checker wall-time, populated as each checker completes.
        # Drives the Scan Duration Profile section in the full PDF.
        checker_durations = {}

        # WS3: resumability. With no scan_id this is a no-op (compute all, persist
        # nothing) — default scans are byte-identical. With a scan_id it skip-and-
        # loads valid checkpoints and persists each non-failed checker result, so a
        # requeue resumes without re-spending paid credits.
        _ckpt = scanner_db.Checkpointer(scan_id, resume, max_age_seconds=CHECKPOINT_TTL_S)

        # --- Run lightweight domain-level checkers concurrently ---
        # Wrap each checker so "running" is emitted at execution start, not
        # at submission. The previous behaviour marked all 21 lightweight
        # checkers as "running" up front; with max_workers=6, 15 checkers
        # appeared "running" while actually queued. UI showed glasswing
        # (or any other late-pickup checker) running for minutes when its
        # actual execution was under 5 seconds.
        def _run_with_timing(name, fn, args, notify):
            notify(on_progress, name, "running")
            t0 = time.perf_counter()
            def _compute():
                try:
                    return fn(*args)
                except Exception as e:
                    return {"status": "error", "error": str(e), "issues": []}
            result = _ckpt.run(name, _compute)   # WS3 skip-and-load / save
            checker_durations[name] = round(time.perf_counter() - t0, 3)
            return result

        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}
            for name, (fn, args) in domain_checkers.items():
                futures[ex.submit(_run_with_timing, name, fn, args, self._notify)] = name

            try:
                for future in as_completed(futures, timeout=180):
                    label = futures[future]
                    try:
                        cat_results[label] = future.result(timeout=DEFAULT_TIMEOUT * 2)
                    except Exception as e:
                        cat_results[label] = {"status": "error", "error": str(e), "issues": []}
                    self._notify(on_progress, label, "done", cat_results[label])
            except FuturesTimeoutError:
                # Gracefully handle checkers that didn't finish in time
                for fut, name in futures.items():
                    if name not in cat_results:
                        fut.cancel()
                        cat_results[name] = {"status": "timeout", "error": "Checker timed out after 180s", "issues": []}
                        checker_durations.setdefault(name, 180.0)
                        self._notify(on_progress, name, "done", cat_results[name])

        # --- Run heavyweight checkers sequentially (memory-safe) ---
        # Each wrapped in run_with_timeout so a single slow checker cannot
        # stall the whole scan — scans previously drifted 10-18 min when
        # sslyze or crt.sh hung on unresponsive targets.
        for name, fn, args, timeout in heavy_checkers:
            self._notify(on_progress, name, "running")
            t0 = time.perf_counter()
            cat_results[name] = _ckpt.run(
                name, lambda fn=fn, args=args, timeout=timeout: run_with_timeout(
                    fn, args=tuple(args), timeout=timeout))
            checker_durations[name] = round(time.perf_counter() - t0, 3)
            self._notify(on_progress, name, "done", cat_results[name])

        # --- Related-domain LITE scan (broker-declared suppliers/siblings) ---
        # Each declared sibling gets SSL + DNS-port + info_disclosure probes,
        # rolled up worst-of-N into a single category. Skipped when no
        # domains are declared. v1.0 broker-declared only — v1.1 will add
        # cert-SAN/WHOIS/analytics-ID auto-discovery (see project memory:
        # project_related_domain_discovery.md).
        if related_domains:
            self._notify(on_progress, "related_domains", "running")
            t0 = time.perf_counter()
            cat_results["related_domains"] = _ckpt.run(
                "related_domains",
                lambda: run_with_timeout(
                    RelatedDomainsChecker().check,
                    args=(domain, related_domains),
                    timeout=min(300, 60 * max(1, len(related_domains))),
                ))
            checker_durations["related_domains"] = round(time.perf_counter() - t0, 3)
            self._notify(on_progress, "related_domains", "done",
                         cat_results["related_domains"])

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

        # --- Expand IP pool with VERIFIED Cloudflare-bypass origin IPs ---
        # A CDN-fronted domain resolves only to edge IPs; the real origin
        # (which may expose RDP / databases / admin) is invisible to plain
        # A-record discovery. discover_origin_ips() pulls candidates from
        # historical DNS and AUTO-VERIFIES each by TLS cert match — only IPs
        # that currently serve THIS domain's certificate are added to the
        # scan pool. Unverified candidates are surfaced for transparency but
        # never scanned (they may have been reassigned to a third party).
        def _compute_origin():
            try:
                from origin_discovery import discover_origin_ips
                return discover_origin_ips(domain, self.securitytrails_api_key,
                                           self.shodan_api_key)
            except Exception as e:
                return {"status": "error", "error": str(e),
                        "candidates": [], "verified": [], "unverified": []}
        # WS3: checkpoint origin_discovery — recomputing it re-spends SecurityTrails
        # + Shodan credits, so a resume must load it, not re-run it.
        origin = _ckpt.run("origin_discovery", _compute_origin)
        cat_results["origin_discovery"] = origin
        verified_new = [ip for ip in origin.get("verified", []) if ip not in all_ips]
        if verified_new:
            all_ips = all_ips + verified_new
            for ip in verified_new:
                ip_sources.setdefault(ip, []).append("verified_origin")
            results["discovered_ips"] = all_ips
            results["ip_sources"] = ip_sources
            results["origin_ips_added"] = len(verified_new)
            self._notify(on_progress, "origin_ips", "done", {"ips": verified_new})

        # --- Classify the IP pool: scan/attribute only the insured's OWN infra -
        # Apex A-records and subdomain-resolved IPs were piped into the port
        # scanners RAW — only origin candidates were ever cert-gated (checker
        # audit, 2026-06-30; see ip_classification.py). A subdomain that merely
        # points at a CDN / cloud / SaaS / shared host means the PROVIDER's
        # infrastructure, not the insured's: its exposed services are the
        # provider's risk and belong under supply-chain, not the insured's own
        # attack surface. RFC1918 hosts leaked in public DNS are an
        # info-disclosure finding and must never be actively scanned. Reverse-DNS
        # is the strongest pre-scan signal (PTR is set by the IP owner); verified
        # origins are already cert-confirmed own infra and always scanned.
        from ip_classification import classify_ip, OWNED, PRIVATE, is_third_party

        def _ptr_lookup(ip):
            try:
                return socket.gethostbyaddr(ip)[0]
            except Exception:
                return None

        ptr_map = {}
        if all_ips:
            with ThreadPoolExecutor(max_workers=16) as _ptr_ex:
                _ptr_futs = {_ptr_ex.submit(_ptr_lookup, ip): ip for ip in all_ips}
                try:
                    for _pf in as_completed(_ptr_futs, timeout=30):
                        ptr_map[_ptr_futs[_pf]] = _pf.result(timeout=5)
                except FuturesTimeoutError:
                    pass

        _ip_to_subs = {}
        for _sub, _sips in (sub_result.get("resolved_ips", {}) or {}).items():
            for _sip in (_sips if isinstance(_sips, list) else [_sips]):
                _ip_to_subs.setdefault(_sip, []).append(_sub)

        scan_ips, third_party_hosting, internal_dns_leak, ip_classification = [], [], [], {}
        for ip in all_ips:
            if "verified_origin" in ip_sources.get(ip, []):
                scan_ips.append(ip)
                ip_classification[ip] = "owned"
                continue
            bucket, label = classify_ip(ip, reverse_dns=ptr_map.get(ip))
            ip_classification[ip] = bucket
            if bucket == PRIVATE:
                internal_dns_leak.append({"ip": ip, "subdomains": _ip_to_subs.get(ip, [])})
            elif bucket == OWNED:
                scan_ips.append(ip)
            else:
                third_party_hosting.append({
                    "ip": ip, "provider": label, "category": bucket,
                    "subdomains": _ip_to_subs.get(ip, []),
                    "reverse_dns": ptr_map.get(ip),
                })
        results["ip_classification"] = ip_classification
        results["third_party_hosting"] = third_party_hosting
        results["internal_dns_leak"] = internal_dns_leak
        self._notify(on_progress, "ip_classification", "done", {
            "owned": len(scan_ips), "third_party": len(third_party_hosting),
            "internal": len(internal_dns_leak),
        })

        # --- Run IP-level checkers on the insured's OWN-infrastructure IPs ---
        # Same instrumentation pattern as the domain-level batch: emit
        # "running" at execution start, not at submission, so per-IP UI
        # status reflects actual execution rather than queue position.
        def _run_ip_with_timing(label, fn, fn_args, notify):
            notify(on_progress, label, "running")
            t0 = time.perf_counter()
            def _compute():
                try:
                    return fn(*fn_args)
                except Exception as e:
                    return {"status": "error", "error": str(e), "issues": []}
            result = _ckpt.run(f"ip::{label}", _compute)   # WS3, keyed per (ip,checker)
            checker_durations[label] = round(time.perf_counter() - t0, 3)
            return result

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {}
            for ip in scan_ips:
                per_ip_results[ip] = {}
                for checker_name, fn in ip_checkers_templates.items():
                    label = f"{checker_name}:{ip}"
                    if checker_name == "shodan_vulns":
                        fn_args = (domain, self.shodan_api_key, ip)
                    else:
                        fn_args = (domain, ip)
                    futures[ex.submit(_run_ip_with_timing, label, fn, fn_args, self._notify)] = label

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
            except FuturesTimeoutError:
                for fut, lbl in futures.items():
                    checker_name, ip = lbl.split(":", 1)
                    if checker_name not in per_ip_results.get(ip, {}):
                        fut.cancel()
                        per_ip_results.setdefault(ip, {})[checker_name] = {
                            "status": "timeout", "error": "Checker timed out", "issues": []}
                        checker_durations.setdefault(lbl, 180.0)
                        self._notify(on_progress, lbl, "done", per_ip_results[ip][checker_name])

        # --- Phase 3b: Post-scan re-classification --------------------------
        # The pre-scan chokepoint only had reverse-DNS. Now the IP checkers have
        # grabbed banners and Shodan org/isp, so re-classify each scanned host
        # and re-home any that prove VENDOR-operated but lacked a diagnostic PTR
        # pre-scan — a no-PTR CDN edge (banner 'cloudflare'), a managed AWS ELB
        # (banner 'awselb' on an ec2-* PTR), or an org-only SaaS host — out of
        # the insured's own-infra into third_party_hosting. Verified origins are
        # never re-homed. This lifts the pre-scan PTR-only result to the full
        # own-vs-vendor split.
        for ip in list(per_ip_results.keys()):
            if "verified_origin" in ip_sources.get(ip, []):
                continue
            checks = per_ip_results[ip]
            dns = checks.get("dns_infrastructure", {}) or {}
            shod = checks.get("shodan_vulns", {}) or {}
            banner = " ".join(
                str(p.get("detected_version", "")) + " " + str(p.get("banner", ""))
                for p in (dns.get("open_ports") or []))
            bucket, label = classify_ip(ip, reverse_dns=dns.get("reverse_dns"),
                                        org=shod.get("org"), banner=banner)
            if is_third_party(bucket):
                ip_classification[ip] = bucket
                third_party_hosting.append({
                    "ip": ip, "provider": label, "category": bucket,
                    "subdomains": _ip_to_subs.get(ip, []),
                    "reverse_dns": dns.get("reverse_dns"),
                })
                del per_ip_results[ip]
        scan_ips = [ip for ip in scan_ips if ip in per_ip_results]
        results["ip_classification"] = ip_classification
        results["third_party_hosting"] = third_party_hosting

        # --- Phase 4: Aggregate IP-level results ---
        results["categories"] = cat_results
        results["categories"]["per_ip"] = per_ip_results
        for checker_name in self.IP_LEVEL_CHECKERS:
            results["categories"][checker_name] = self._aggregate_ip_results(
                per_ip_results, checker_name
            )

        # --- Phase 4a: Reconcile RDP exposure across ALL discovered IPs ---
        # vpn_remote only probes the apex domain, which usually resolves to a
        # Cloudflare/edge IP where 3389 is closed — so RDP on an origin IP was
        # being reported as "No". The per-IP port scan (dns_infrastructure)
        # probes 3389 on every discovered IP; surface any hit in the headline
        # rdp_exposed field instead of hiding it behind the apex probe.
        rdp_ips = []
        for ip, checks in per_ip_results.items():
            ports = (checks.get("dns_infrastructure", {}) or {}).get("open_ports", []) or []
            if any(p.get("port") == 3389 for p in ports):
                rdp_ips.append(ip)
        if rdp_ips:
            vpn = results["categories"].setdefault("vpn_remote", {})
            vpn["rdp_exposed_ips"] = rdp_ips
            if not vpn.get("rdp_exposed"):
                vpn["rdp_exposed"] = True
                vpn.setdefault("issues", []).append(
                    f"RDP (port 3389) exposed on {', '.join(rdp_ips)} — "
                    "directly accessible from internet")

        # --- Phase 4b: External IP Aggregation (feeds CVE panel) ---
        # Own-infra surface = the insured's OWNED IPs only (scan_ips); third-party
        # hosting + internal-DNS leaks are surfaced separately (results.
        # third_party_hosting / internal_dns_leak).
        self._notify(on_progress, "external_ips", "running")
        results["categories"]["external_ips"] = ExternalIPAggregator.aggregate(
            scan_ips, per_ip_results, ip_sources=ip_sources
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
                    scan_ips, per_ip_results, ip_sources=ip_sources
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
                scan_ips, per_ip_results, ip_sources=ip_sources
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

        # --- Phase 4f: Third-party cross-correlation (Hudson Rock × S-4 × S-5) ---
        # Joins three independent signals into a single broker-facing finding:
        #   (A) Hudson Rock reports infostealer-harvested credentials for
        #       third-party services used by the insured's employees
        #       (count only — the free Hudson Rock endpoint doesn't
        #       publish per-vendor breakdown, so we can't do a true
        #       per-vendor join with current data)
        #   (B) S-4 EmailVendorSurfaceChecker detected named SaaS
        #       vendors in the SPF include chain
        #   (C) S-5 VendorBreachChecker matched some of those vendors
        #       against the curated public-breach database
        # Severity ladder:
        #   - CRITICAL: A>0 AND B>0 AND C>0 (HR count + SPF vendor + breach
        #     match) — three independent signals confirming risk. The
        #     vendors in C are the most likely candidates for which the
        #     HR-reported credentials were harvested. Strongest single
        #     actionable signal in the model.
        #   - HIGH: A>0 AND B>0 (no S-5 match) — credentials harvested AND
        #     SPF vendor surface exists, but no known-breach overlap.
        #     Still strong: review credentials at all detected vendors.
        #   - MEDIUM: A>0 only — HR signal alone; covered by base HR card.
        # REPORTING-ONLY: this cross-correlation carries NO scoring weight —
        # it is deliberately excluded from WEIGHTS, RSI, the FIC vuln uplift,
        # and REMEDIATION_MAP, because the underlying signals (Hudson Rock,
        # S-4 email_vendor_surface, S-5 vendor_breach) already score through
        # their own channels; wiring it in would double-count. It is purely a
        # representational join rendered in the broker-facing surfaces.
        # When a vendor-breach overlap is found the card severity tracks the
        # MOST SEVERE underlying breach (medium overlap -> medium card), not a
        # blanket CRITICAL on any overlap.
        self._notify(on_progress, "third_party_correlation", "running")
        try:
            # NOTE: EmailVendorSurfaceChecker is already imported at module
            # scope (top of file). A duplicate local `from ... import` here
            # would make Python treat the name as a local variable for the
            # ENTIRE scan() function, shadowing the module-level import and
            # raising UnboundLocalError at the domain_checkers dict line
            # ~190 — which previously broke EVERY scan in production after
            # commit 0eb1483 / ab68921 / 92a5ae1 until this fix.
            hr = cat_results.get("hudson_rock", {})
            evs = cat_results.get("email_vendor_surface", {})
            vb = cat_results.get("vendor_breach", {})
            corr = {
                "status": "no_data",
                "hudson_rock_third_party_count": int(hr.get("third_party_exposures", 0) or 0),
                "hudson_rock_employees": int(hr.get("compromised_employees", 0) or 0),
                "spf_vendor_count": 0,
                "spf_vendors": [],
                "vendor_breach_match_count": 0,
                "suspected_vendors": [],
                "severity": "none",
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "score": 100,
                "issues": [],
                "rationale": "",
            }
            hr_tp = corr["hudson_rock_third_party_count"]
            # Only meaningful when HR returned data AND at least one
            # third-party exposure was detected.
            if (hr.get("status") == "completed" and hr_tp > 0):
                # Collect S-4 vendor names (already normalised to lowercase
                # keys by EmailVendorSurfaceChecker._classify).
                spf_vendor_keys = []
                for v in (evs.get("vendors_detected") or []):
                    key = (v.get("vendor") or "").lower().strip()
                    if key:
                        spf_vendor_keys.append(key)
                corr["spf_vendors"] = spf_vendor_keys
                corr["spf_vendor_count"] = len(spf_vendor_keys)

                # Cross-reference S-5 matched breaches against the SPF
                # vendor set — vendors in BOTH are the suspected
                # candidates for the HR-reported exposures.
                breach_by_vendor = {}
                for m in (vb.get("matches") or []):
                    vk = (m.get("vendor") or "").lower().strip()
                    if vk:
                        breach_by_vendor.setdefault(vk, []).append({
                            "date": m.get("date", ""),
                            "severity": m.get("severity", ""),
                            "exposure_class": m.get("exposure_class", ""),
                            "summary": (m.get("summary") or "")[:200],
                        })
                suspected = []
                for vk in spf_vendor_keys:
                    if vk in breach_by_vendor:
                        suspected.append({
                            "vendor": vk,
                            "breaches": breach_by_vendor[vk],
                        })
                corr["suspected_vendors"] = suspected
                corr["vendor_breach_match_count"] = len(suspected)

                if suspected:
                    # Severity tracks the MOST SEVERE underlying vendor breach,
                    # not mere presence of an overlap. A single MEDIUM vendor
                    # incident (e.g. zendesk "no customer data exfiltrated")
                    # must not render CRITICAL / "rotate TODAY" — that over-
                    # states a benign-class event (caught in card back-test).
                    _SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                    _worst_rank = -1
                    _worst_sev = "medium"
                    for s in suspected:
                        for b in s.get("breaches", []):
                            bs = (b.get("severity") or "").lower().strip()
                            if _SEV_RANK.get(bs, -1) > _worst_rank:
                                _worst_rank = _SEV_RANK[bs] if bs in _SEV_RANK else _worst_rank
                                if bs in _SEV_RANK:
                                    _worst_sev = bs
                    corr["severity"] = _worst_sev
                    corr["critical_count"] = 1 if _worst_sev == "critical" else 0
                    corr["high_count"] = 1 if _worst_sev == "high" else 0
                    corr["medium_count"] = 1 if _worst_sev == "medium" else 0
                    corr["status"] = "completed"
                    vendor_names = ", ".join(s["vendor"] for s in suspected[:5])
                    _sev_label = _worst_sev.upper()
                    corr["issues"].append(
                        f"{_sev_label}: Hudson Rock reports {hr_tp} third-party "
                        f"credential exposure(s) for this domain. Your SPF "
                        f"chain authorises {len(suspected)} vendor(s) with "
                        f"known public breaches ({vendor_names}, worst "
                        f"severity: {_worst_sev}). Review and rotate "
                        "credentials at these vendors as priority targets."
                    )
                    corr["rationale"] = (
                        f"Three independent signals align: (A) Hudson Rock "
                        f"infostealer harvest count = {hr_tp}; (B) {len(spf_vendor_keys)} "
                        f"vendor(s) in SPF send-authority chain; (C) {len(suspected)} "
                        f"of those vendors have confirmed public breaches in "
                        "the curated vendor_breaches.json. The intersection "
                        "is the most actionable rotate-list."
                    )
                    corr["score"] = max(0, 100 - 35 - hr_tp * 5)
                elif spf_vendor_keys:
                    corr["severity"] = "high"
                    corr["high_count"] = 1
                    corr["status"] = "completed"
                    corr["issues"].append(
                        f"{hr_tp} third-party credential exposure(s) detected "
                        f"(Hudson Rock) AND {len(spf_vendor_keys)} email "
                        "vendor(s) in your SPF chain. No vendor-breach "
                        "overlap found, but review credentials at all "
                        f"detected vendors: {', '.join(spf_vendor_keys[:5])}."
                    )
                    corr["rationale"] = (
                        f"Two signals: HR third-party count {hr_tp}; "
                        f"{len(spf_vendor_keys)} SPF vendors. No S-5 "
                        "breach overlap to narrow the rotate-list."
                    )
                    corr["score"] = max(0, 100 - 20 - hr_tp * 3)
                else:
                    corr["severity"] = "medium"
                    corr["medium_count"] = 1
                    corr["status"] = "completed"
                    corr["issues"].append(
                        f"{hr_tp} third-party credential exposure(s) detected "
                        "(Hudson Rock). No SPF vendor surface or breach "
                        "matches to cross-reference — broker should review "
                        "the insured's SaaS inventory manually."
                    )
                    corr["rationale"] = (
                        f"Single signal: HR third-party count {hr_tp}. "
                        "No S-4 / S-5 overlap to narrow scope."
                    )
                    corr["score"] = max(0, 100 - 10 - hr_tp * 2)
            results["categories"]["third_party_correlation"] = corr
        except Exception as _corr_err:
            results["categories"]["third_party_correlation"] = {
                "status": "error",
                "error": str(_corr_err)[:200],
                "critical_count": 0, "high_count": 0,
                "score": 100, "issues": [],
            }
        self._notify(on_progress, "third_party_correlation", "done")

        # --- Phase 4g: Credential-compromise cross-correlation (reporting-only) ---
        # Joins DeHashed corpus + recency dates + Hudson Rock infostealer +
        # IntelX forum/dump chatter into one escalating verdict. Carries no
        # scoring weight (underlying signals already score through their own
        # channels) — purely how credential exposure is represented to clients.
        self._notify(on_progress, "credential_correlation", "running")
        try:
            results["categories"]["credential_correlation"] = \
                build_credential_correlation(cat_results)
        except Exception as _cc_err:
            results["categories"]["credential_correlation"] = {
                "status": "error", "error": str(_cc_err)[:200],
                "severity": "none", "critical_count": 0, "high_count": 0,
                "issues": [],
            }
        self._notify(on_progress, "credential_correlation", "done")

        # --- Phase 5: Score ---
        # WAF / bot-manager intervention status is read once here, before
        # scoring, so the score can discount the WAF "bonus" when the WAF
        # actively blinded the scan (a blocked scan must not be rewarded for
        # the blindness). The same status object is reused below for the
        # completeness metadata — one sliding-window read, no double count.
        waf_apex_status = HTTP.waf_status(scan_apex)
        # Score via the shared pipeline — the SAME call the golden/regen rescore
        # uses (scoring_pipeline.apply_risk_score). Writes overall_risk_score /
        # risk_level / recommendations and the categories["_overall_score"] the
        # FinancialImpactCalculator reads to derive `vulnerability` (without it the
        # FIC defaults to 500 and pins vulnerability at 0.5). `scorer` is reused
        # below for the completeness telemetry and the compliance summary.
        risk_score, risk_level, recommendations, scorer = apply_risk_score(
            results, waf_apex_status=waf_apex_status)
        # Propagate scan completeness metadata to top level
        if "_scan_completeness" in cat_results:
            results["_scan_completeness"] = cat_results.pop("_scan_completeness")
        else:
            results["_scan_completeness"] = {}
        # Attach per-checker wall-time profile. Drives the Scan Duration
        # Profile section in the full PDF and the SLA diagnostic for slow
        # scans. Sum is wall-clock approximate (concurrent checkers overlap).
        results["_scan_completeness"]["per_checker_seconds"] = dict(
            sorted(checker_durations.items(), key=lambda kv: kv[1], reverse=True)
        )
        results["_scan_completeness"]["checkers_observed"] = len(checker_durations)
        if checker_durations:
            durations = list(checker_durations.values())
            results["_scan_completeness"]["slowest_checker"] = max(
                checker_durations.items(), key=lambda kv: kv[1])
            results["_scan_completeness"]["total_checker_seconds"] = round(sum(durations), 1)

        # WAF / bot-manager intervention status for the target apex.
        # Drives "Partial Coverage Notice" rendering in PDF + HTML when
        # the WAFTracker observed enough blocked / throttled / timeout
        # responses to call the target's defensive posture protected.
        # Checkers that hit HTTP-via-the-client all contribute; the
        # status field surfaces in the report renderers.
        # Reuse the pre-scoring WAF status (already read above).
        results["_scan_completeness"]["waf_status"] = waf_apex_status
        # Checkers that explicitly EARLY-EXITED because the apex hard-blocked
        # their path probing — they set their own `waf_truncated` flag. These are
        # "not fully assessed" even though their benign 'nothing found' line
        # (e.g. "No VPN detected") leaves `issues` non-empty, so the empty-issues
        # heuristic below misses them. Record them for transparency and fold them
        # into the affected set so coverage + the partial-coverage notice are
        # accurate. (Currently set by vpn_remote, payment_security, info_disclosure.)
        truncated = sorted(
            cname for cname, cresult in cat_results.items()
            if isinstance(cresult, dict) and cresult.get("waf_truncated")
        )
        results["_scan_completeness"]["waf_truncated_checkers"] = truncated
        # Compute per-checker WAF flags: a checker is flagged WAF-affected
        # if it reported "no data" outcomes while the apex shows blocked.
        # Used by the PDF / HTML to render per-card disclaimers.
        if waf_apex_status.get("blocked"):
            affected = []
            # The checkers most sensitive to WAF interference are the
            # path-probers and tech fingerprinters. Anything that returns
            # status "completed" with empty/zero findings AND ran during
            # a WAF-blocked scan should carry the disclaimer.
            for cname in ("privacy_compliance", "info_disclosure",
                          "exposed_admin", "payment_security",
                          "security_policy", "vpn_remote", "tech_stack",
                          "website_security", "http_headers", "waf"):
                cresult = cat_results.get(cname)
                if not cresult:
                    continue
                # If the checker reports any findings, it got SOME data
                # through; only flag when it appears to have struck out.
                issues = cresult.get("issues") or []
                if not issues:
                    affected.append(cname)
            # Fold in explicitly-truncated checkers (missed by the empty-issues
            # heuristic when they emit a benign 'nothing found' line).
            affected = sorted(set(affected) | set(truncated))
            results["_scan_completeness"]["waf_affected_checkers"] = affected
            # Coverage estimate: assessable - affected / assessable.
            # Fallback derives from the authoritative WEIGHTS count (the
            # scorer sets total_checkers to len(WEIGHTS) upstream) rather
            # than a hardcoded literal that silently goes stale.
            total = results["_scan_completeness"].get(
                "total_checkers", len(RiskScorer.WEIGHTS))
            cov = max(0, total - len(affected))
            results["_scan_completeness"]["coverage_pct"] = (
                round(cov / total * 100) if total else 100
            )
        else:
            results["_scan_completeness"]["waf_affected_checkers"] = []
            results["_scan_completeness"]["coverage_pct"] = 100
        results["compliance"] = scorer.compliance_summary(cat_results)

        # --- Phase 6: Insurance Analytics ---
        self._notify(on_progress, "insurance_analytics", "running")
        try:
            # All insurance calculators run through the shared pipeline — the SAME
            # call the golden/regen rescore uses (scoring_pipeline.
            # apply_insurance_analytics), so a scoring change cannot pass golden
            # while breaking the live scan. The pipeline resolves the ZAR revenue
            # basis (resolve_effective_revenue_zar) and scores RSI + Remediation on
            # it — the size-multiplier bands are in ZAR and the form sends revenue
            # only as annual_revenue_zar; the vestigial USD annual_revenue is
            # forwarded to the FIC, which ignores it when ZAR is present.
            # regulatory_flags / sub_industry / records_held are set on the scanner
            # instance by app.py before scan().
            apply_insurance_analytics(
                results, industry=industry,
                annual_revenue=annual_revenue,
                annual_revenue_zar=annual_revenue_zar,
                regulatory_flags=getattr(self, '_regulatory_flags', None),
                sub_industry=getattr(self, '_sub_industry', None),
                records_override=getattr(self, '_records_held', None),
                scan_completeness=results.get("_scan_completeness"),
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
