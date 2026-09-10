"""
PHISHIELD Cyber Risk Assessment — PDF Report Generator
Produces a professional, print-ready A4 PDF using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether, CondPageBreak
)
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String
from reportlab.graphics import renderPDF

# Split modules (pure move 2026-06-11): static data tables, shared low-level
# rendering helpers, and per-category card renderers. Names are imported
# explicitly so the public surface of pdf_report is unchanged.
from pdf_data import CVE_DESCRIPTIONS
from pdf_helpers import (
    C_NAVY, C_BLUE, C_BLUE_LIGHT, C_GREEN, C_GREEN_BG, C_AMBER, C_AMBER_BG,
    C_RED, C_RED_BG, C_CRITICAL, C_CRITICAL_BG, C_GREY_1, C_GREY_2, C_GREY_3,
    C_GREY_4, C_WHITE, C_BLACK,
    PAGE_W, PAGE_H, MARGIN, INNER_W,
    risk_color, risk_bg, tl_color, make_traffic_circle, make_risk_gauge,
    build_styles, section_header, section_with_first_card, badge_text,
    kv_row, issues_cell, build_cat_card, not_assessed_card,
    _header_footer, _section_header_banner, _risk_colour_value, _colour_issue,
    score_or_none,
    waf_posture,
    _cat_table, _tl, _load_assessment_brand, _brand,
)
from pdf_cards import (
    cat_ssl, cat_email, cat_email_hardening, cat_headers, cat_waf, cat_dns,
    cat_hrp, cat_cloud, cat_vpn, origin_discovery_block, cat_breaches,
    cat_breach_intel, breach_intel_compact, breach_intel_line,
    cat_dnsbl, cat_admin, cat_subdomains, cat_tech, cat_domain,
    cat_security_policy, cat_glasswing, cat_payment, cat_shodan, cat_dehashed,
    cat_hudson_rock, cat_intelx, cat_credential_risk, cat_virustotal,
    cat_securitytrails, cat_privacy_compliance, cat_compliance_frameworks,
    cat_website, cat_web_ranking, cat_info_disclosure, cat_fraudulent_domains,
    cat_related_domains, cat_dependency_manifests, cat_third_party_js,
    cat_email_vendor_surface, cat_cms_plugin_sbom, cat_credential_remediation,
    cat_credential_correlation, cat_third_party_correlation, cat_vendor_breach,
    cat_rsi, cat_dbi, cat_remediation, cat_financial_impact,
    loss_exposure_scenarios_block, risk_probability_block, cover_ladder_block,
    records_assumption_disclosure, civil_liability_disclosure,
    peer_benchmark_card, waf_coverage_notice, waf_card_disclaimer,
    estate_edge_notice,
    vendor_estate_notice,
    origin_exposure_notice,
    flag_audit_panel, scan_duration_profile, cat_risk_mitigations,
    build_summary_table, _build_legend, _build_vulnerability_posture,
    _build_attackers_view, _supply_chain_attacker_findings,
    _kill_chain_severities, _finding_colour, conclusive_count,
    estate_ip_count,
)


# ===========================================================================
# CYBER SECURITY ASSESSMENT — Executive Summary Deck (compact 2-page layout)
#
# A self-contained alternative output (report_type="assessment") that mirrors
# an external executive-deck template. Bypasses the standard cover / exec
# table / vulnerability posture / attacker's view machinery and produces a
# tight broker/client-facing summary with 8 sections.
# Field paths reused from build_summary_table + _build_attackers_view.
# ===========================================================================

# Fallback used only if assessment_industry_stats.json is missing or malformed.
_ASSESSMENT_STATS_DEFAULT = [
    {"value": "R44.1m",   "label": "average cost of a SA data breach in 2025",       "description": "A business-ending event for most SMEs."},
    {"value": "241 days", "label": "average time to identify and contain a breach",  "description": "Attackers may have access for nearly 8 months."},
    {"value": "Only 35%", "label": "of organisations fully recover from a breach",   "description": "Of those, 76% take more than 100 days."},
    {"value": "60%+",     "label": "of SMBs with severe data loss shut within 6 months", "description": "A single event can be existential."},
    {"value": "86%",      "label": "of breached organisations face operational disruption", "description": "Staff cannot work; obligations go unmet."},
    {"value": "24 days",  "label": "average downtime following a ransomware attack",  "description": "Nearly a month of halted operations."},
]


def _load_assessment_industry_stats() -> list:
    import json as _json
    from pathlib import Path as _Path
    p = _Path(__file__).parent / "assessment_industry_stats.json"
    try:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = _json.load(f)
                stats = data.get("stats", [])
                if isinstance(stats, list) and len(stats) >= 6:
                    return stats[:6]
    except Exception:
        pass
    return _ASSESSMENT_STATS_DEFAULT


# Module-level cache for the current PDF render. Set by _build_assessment_pdf
# so the page-painter callback (which can't take extra args) can read it.
_ASX_CURRENT_BRAND = None


def _asx_image_or_none(image_path, max_width, max_height):
    """Return a ReportLab Image flowable sized to fit (max_width, max_height)
    preserving aspect ratio, or None if the file is missing/unreadable."""
    if not image_path:
        return None
    try:
        from reportlab.platypus import Image as RLImage
        from PIL import Image as PILImage
        with PILImage.open(image_path) as im:
            iw, ih = im.size
        scale = min(max_width / iw, max_height / ih)
        return RLImage(image_path, width=iw * scale, height=ih * scale)
    except Exception:
        return None



# ---------- Data extractors ----------

def _assessment_extract_kpis(results: dict) -> list:
    """6 KPI tiles for the Executive Summary block. Returns list of
    {value, label, description, severity in {ok,warn,bad}}."""
    cats = results.get("categories", {})
    ssl_grade = cats.get("ssl", {}).get("grade", "?")
    em_score  = score_or_none(cats.get("email_security"))
    hh_score  = score_or_none(cats.get("http_headers"))
    adm_total = (cats.get("exposed_admin", {}).get("critical_count", 0)
                 + cats.get("exposed_admin", {}).get("high_count", 0))
    hrp_services = cats.get("high_risk_protocols", {}).get("exposed_services", [])
    db_ports = {3306, 5432, 27017, 6379, 9200, 1433}
    db_count = sum(1 for s in hrp_services if s.get("port") in db_ports)
    rdp_exposed = cats.get("vpn_remote", {}).get("rdp_exposed", False)

    def ssl_sev(g):
        if g in ("A+", "A"): return "ok"
        if g in ("B", "C"):  return "warn"
        return "bad"

    return [
        {"value": ssl_grade,           "label": "SSL / TLS Grade",       "description": "Encryption quality",         "severity": ssl_sev(ssl_grade)},
        # A tile for a checker that did not run shows its state, not a number.
        # Printing "10/10" or "100%" for an absent result is the same false
        # clean the scoring layer stopped banking.
        {"value": f"{em_score}/10" if em_score is not None else "n/a",
         "label": "Email Security",        "description": "Phishing exposure",
         "severity": "unknown" if em_score is None else "ok" if em_score >= 8 else "warn" if em_score >= 5 else "bad"},
        {"value": f"{hh_score}%" if hh_score is not None else "n/a",
         "label": "HTTP Sec. Headers",     "description": "Web app exposure",
         "severity": "unknown" if hh_score is None else "ok" if hh_score >= 80 else "warn" if hh_score >= 50 else "bad"},
        {"value": str(adm_total),     "label": "Exposed Admin Panels", "description": "Direct entry points",        "severity": "bad" if adm_total > 0 else "ok"},
        {"value": str(db_count),      "label": "Critical DB Exposed",  "description": "Database internet-facing",   "severity": "bad" if db_count > 0 else "ok"},
        {"value": "Yes" if rdp_exposed else "No", "label": "RDP Exposed", "description": "Top ransomware vector",    "severity": "bad" if rdp_exposed else "ok"},
    ]


def _assessment_kill_chain(results: dict) -> list:
    """Compact 4-phase kill chain. Each: {name, severity, headline, findings[<=3]}."""
    cats = results.get("categories", {})
    ins  = results.get("insurance", {})
    # Shared with the full/broker Attacker's View so severities never diverge.
    sevs = _kill_chain_severities(results)

    # Phase 1: Reconnaissance
    ip_count  = estate_ip_count(cats, results)
    sub_count = cats.get("subdomains", {}).get("total_count", 0)
    dh = cats.get("dehashed", {})
    emails = dh.get("unique_emails", 0)
    p1_sev = sevs["recon"]
    p1f = []
    if ip_count:  p1f.append(f"{ip_count} external IP addresses discoverable")
    if sub_count: p1f.append(f"{sub_count} subdomains can be enumerated")
    if emails:    p1f.append(f"{emails} staff emails found in breach data")
    # Say WHY a phase is unassessed. "No significant signals" on an estate nobody
    # searched is the false-clean this whole guard exists to stop.
    if p1_sev == "UNKNOWN":
        p1f.append("Breach databases not searched for this scan")
    if not p1f:   p1f = ["No significant reconnaissance signals"]

    # Phase 2: Initial Access
    rdp = cats.get("vpn_remote", {}).get("rdp_exposed", False)
    hrp = cats.get("high_risk_protocols", {}).get("exposed_services", [])
    cred_leaks = dh.get("total_entries", 0)
    hr_cat = cats.get("hudson_rock", {})
    infostealers = hr_cat.get("compromised_employees", 0)
    p2_sev = sevs["access"]
    p2f = []
    if rdp: p2f.append("RDP exposed on port 3389")
    elif hrp:
        svc = hrp[0]
        p2f.append(f"{(svc.get('service') or 'service').capitalize()} open on port {svc.get('port', '?')}")
    if cred_leaks: p2f.append(f"{cred_leaks} stolen credentials available to reuse")
    for _scf in _supply_chain_attacker_findings(cats)["access"]:  # Step 7
        if len(p2f) < 3: p2f.append(_scf)
    if cred_leaks > 0 and len(p2f) < 3: p2f.append("Enables automated credential stuffing")
    if infostealers and len(p2f) < 3:
        _isd = hr_cat.get("days_since_compromise")
        p2f.append(f"{infostealers} infostealer-infected device(s)"
                   + (f", most recent {_isd}d ago" if _isd is not None else ""))
    if p2_sev == "UNKNOWN" and len(p2f) < 3:
        p2f.append("Credential and infostealer exposure not assessed")
    if not p2f: p2f = ["No clear initial-access vectors identified"]

    # Phase 3: Exploitation
    ssl_grade = cats.get("ssl", {}).get("grade") or "F"   # absent SSL is not an A -- fail closed, like every other guard here
    hh_score  = score_or_none(cats.get("http_headers"))
    osv_crit  = cats.get("osv_vulns", {}).get("critical_count", 0)
    osv_high  = cats.get("osv_vulns", {}).get("high_count", 0)
    p3_sev = sevs["exploit"]
    p3f = []
    if ssl_grade in ("D", "E", "F"): p3f.append(f"SSL grade {ssl_grade} enables interception")
    if hh_score is not None and hh_score < 50:
        p3f.append(f"Security headers at {hh_score}% only")
    if osv_crit: p3f.append(f"{osv_crit} critical CVE(s) with known exploits")
    for _scf in _supply_chain_attacker_findings(cats)["exploit"]:  # Step 7
        if len(p3f) < 3: p3f.append(_scf)
    if hh_score is not None and hh_score < 50 and len(p3f) < 3:
        p3f.append("Exposed to XSS & clickjacking")
    if not p3f: p3f = ["No critical exploitation vectors identified"]

    # Phase 4: Data & Impact
    # RSI bands match the scanner's canonical thresholds in scoring_analytics.py:1078:
    #   < 0.25 = Low | 0.25-0.50 = Medium | 0.50-0.75 = High | >= 0.75 = Critical
    # DB exposure forces CRITICAL regardless of RSI.
    db_ports = {3306, 5432, 27017, 6379, 9200, 1433}
    db_exposed = any(s.get("port") in db_ports for s in hrp)
    rsi = ins.get("rsi", {}).get("rsi_score", 0)
    fin = ins.get("financial_impact", {})
    fin_mc_p50 = fin.get("monte_carlo", {}).get("total", {}).get("p50", 0)
    cur_sym = "R" if fin.get("currency") == "ZAR" else "$"
    p4_sev = sevs["data"]
    p4f = []
    if db_exposed: p4f.append("Databases directly internet-facing")
    if rsi:        p4f.append(f"{int(round(rsi*100))}% ransomware susceptibility")
    if fin_mc_p50: p4f.append("Est. impact: " + cur_sym + " " + (
        f"{fin_mc_p50/1_000_000_000:.2f}bn" if fin_mc_p50 >= 1_000_000_000
        else f"{fin_mc_p50/1_000_000:.2f}m") + " (median)")
    if not p4f:    p4f = ["Limited data exfiltration paths visible"]

    return [
        {"name": "RECONNAISSANCE", "severity": p1_sev, "headline": "What an attacker can learn",       "findings": p1f[:3]},
        {"name": "INITIAL ACCESS", "severity": p2_sev, "headline": "How they would break in",          "findings": p2f[:3]},
        {"name": "EXPLOITATION",   "severity": p3_sev, "headline": "What they would exploit",          "findings": p3f[:3]},
        {"name": "DATA & IMPACT",  "severity": p4_sev, "headline": "What they would steal or destroy", "findings": p4f[:3]},
    ]


def _assessment_top_findings(results: dict) -> list:
    """Top 3 highest-severity plain-language findings.
    Each: {level, headline, summary, detail}."""
    cats = results.get("categories", {})
    ins  = results.get("insurance", {})
    weight = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
    cands = []  # tuples of (priority, dict)

    # Prior breach (SCN-041). Ranked just under RDP when recent: for a
    # board-level reader "you were breached three months ago" outranks almost any
    # configuration finding, and it is the one fact HIBP alone never surfaces.
    # Tiered disclosure — the exec deck gets the verdict and the timing, not the
    # incident detail or the sources (those live in the broker/full tiers).
    _bi = cats.get("breach_intel") or {}
    if _bi.get("status") == "completed" and _bi.get("verdict") in ("confirmed", "reported"):
        _m = _bi.get("months_since_most_recent")
        _recent = bool(_bi.get("recent_material_breach"))
        _when = ("on a date the sources do not establish" if _m is None
                 else "within the last month" if _m < 1
                 else f"about {round(_m)} months ago" if _m < 24
                 else f"about {_m / 12:.1f} years ago")
        cands.append((95 if _recent else 60, {
            "level": "CRITICAL" if _recent else "MEDIUM",
            "headline": f"This organisation was breached {_when}",
            "summary": ("Recent breaches materially raise the chance of another one."
                        if _recent else
                        "A prior breach is on record, though not a recent one."),
            "detail": (
                f"Open-source research {_bi.get('verdict')} a prior security incident "
                f"{_when}. "
                + ("Organisations are at their most exposed while still recovering — "
                   "credentials, access routes and the original weakness are often "
                   "still live. Confirm what was remediated and whether the root "
                   "cause is closed. "
                   if _recent else
                   "Older incidents matter less to present-day posture, but confirm "
                   "the root cause was closed. ")
                + "Note this was not found in breach-notification databases; it was "
                  "established from published reporting."),
        }))
    elif _bi and _bi.get("status") != "completed":
        # Never let an outage read as a clean history on a board-level document.
        cands.append((40, {
            "level": "MEDIUM",
            "headline": "Breach history could not be checked",
            "summary": "This is unassessed — it is not a clean bill of health.",
            "detail": ("The breach-history research could not run for this scan, so a "
                       "prior breach can be neither confirmed nor ruled out. Re-run "
                       "the scan before relying on this section."),
        }))

    # RDP exposed — extreme priority
    if cats.get("vpn_remote", {}).get("rdp_exposed"):
        cands.append((100, {
            "level": "CRITICAL",
            "headline": "RDP is exposed to the internet",
            "summary": "Remote Desktop is the #1 entry vector for ransomware.",
            "detail": "Port 3389 (Remote Desktop) is reachable from the internet. A single weak or stolen password could allow an attacker to log in interactively to a workstation or server."
        }))

    # Credential risk.
    #
    # This block thresholded credential_risk.risk_score, which is K5_RISK_SCORE:
    # CRITICAL 0, HIGH 25, MEDIUM 55, LOW 85, NONE 100 -- HIGHER IS SAFER. The
    # tests read `cr_score >= 80 -> CRITICAL`, so the polarity was inverted and
    # the deck reported the SAFEST estates as the worst:
    #
    #     classifier LOW  (85)  -> deck said CRITICAL
    #     classifier NONE (100) -> deck said CRITICAL
    #     classifier CRITICAL (0) -> not flagged by score at all
    #
    # Measured across 20 scans: the deck disagreed with the classifier on 13.
    # morgancarco.com, an unregistered domain with ZERO credential records,
    # reported "Overall credential risk is classified as CRITICAL".
    #
    # It also crashed outright when the estate was not assessed. `.get(key, 0)`
    # returns None when the key EXISTS with a None value, which is exactly what
    # the classifier writes for UNKNOWN -- so every scan run with the credential
    # lookup skipped raised TypeError and the Executive Summary would not
    # download at all, while the other two tiers rendered fine.
    #
    # The classifier already states the verdict. Read it instead of re-deriving
    # one from a number whose direction this block had backwards.
    _cr = (ins.get("credential_risk") or cats.get("credential_risk") or {})
    cr_level = str(_cr.get("risk_level") or "").upper()
    cr_assessed = _cr.get("assessed") is not False and cr_level not in ("", "UNKNOWN")
    _dh = cats.get("dehashed") or {}
    cred_total = _dh.get("total_entries") or 0
    staff_n = _dh.get("staff_accounts_total") or 0
    svc_n = (cats.get("hudson_rock") or {}).get("compromised_services_total") or 0
    hr_emp = (cats.get("hudson_rock") or {}).get("compromised_employees") or 0

    # Only claim a credential finding when the estate was actually assessed and
    # the verdict is material. An unassessed estate is not a clean one, but it
    # is not a FINDING either -- coverage reports it, this deck must not invent
    # a level for it.
    if cr_assessed and cr_level in ("CRITICAL", "HIGH", "MEDIUM"):
        level = cr_level
    elif not cr_assessed and cred_total >= 5:
        # Classifier unavailable but the raw corpus is not empty: fall back to
        # volume alone, which is weaker evidence, so never above HIGH.
        level = "HIGH" if cred_total >= 20 else "MEDIUM"
    else:
        level = None
    if level:
        counts = (f"{cred_total} credential records found"
                  + (f", incl. {staff_n} staff account(s)" if staff_n else "")
                  + (f" and {svc_n} service(s) captured from {hr_emp} infected employee device(s)"
                     if svc_n else ""))
        # Counts also go in the SUMMARY so they show on the exec-deck banner
        # (which renders the primary finding's summary, not its detail).
        extra = ""
        if staff_n or svc_n:
            extra = (f" {staff_n} staff account(s)" if staff_n else "")
            extra += (f" and {svc_n} service(s)" if svc_n else "")
            extra += " exposed."
        cands.append((weight[level], {
            "level": level,
            "headline": f"Overall credential risk is classified as {level}",
            "summary": "Significantly elevated probability of unauthorised access via compromised credentials." + extra,
            "detail": counts + " — staff email addresses and possibly passwords are circulating in breach databases, the fuel for automated password-guessing attacks."
        }))

    # DB / critical service exposure
    hrp = cats.get("high_risk_protocols", {}).get("exposed_services", [])
    db_ports = {3306, 5432, 27017, 6379, 9200, 1433}
    db_count = sum(1 for s in hrp if s.get("port") in db_ports)
    crit_count = cats.get("high_risk_protocols", {}).get("critical_count", 0)
    if db_count > 0:
        cands.append((95, {
            "level": "CRITICAL",
            "headline": f"{db_count} critical service exposed",
            "summary": "A database is reachable directly from the internet.",
            "detail": "A simple connection with a stolen password could grant immediate access to business data without any further hop or exploit."
        }))
    elif crit_count > 0:
        cands.append((90, {
            "level": "CRITICAL",
            "headline": f"{crit_count} high-risk service exposed",
            "summary": "Critical service(s) reachable directly from the internet.",
            "detail": "Direct attack surface that should normally sit behind a VPN or be allow-listed to specific source IPs."
        }))

    # SSL weak
    ssl_grade = cats.get("ssl", {}).get("grade", "?")
    if ssl_grade in ("D", "E", "F"):
        cands.append((65, {
            "level": "HIGH",
            "headline": f"Weak SSL/TLS encryption ({ssl_grade})",
            "summary": "Web traffic can be intercepted or downgraded.",
            "detail": f"SSL grade {ssl_grade} — outdated or weak ciphers allow attackers to intercept connections via man-in-the-middle attacks."
        }))

    # Email weak
    # Unknown != healthy. This defaulted to 10/10, so a missing or skipped
    # email checker silently produced "no email finding" on the exec deck.
    em_score = score_or_none(cats.get("email_security"))
    if em_score is not None and em_score < 5:
        cands.append((60, {
            "level": "HIGH",
            "headline": f"Weak email authentication ({em_score}/10)",
            "summary": "Domain can be spoofed for phishing attacks.",
            "detail": "Without proper SPF/DKIM/DMARC, attackers can impersonate this domain to phish staff, customers, and suppliers."
        }))

    # WAF missing. Only claim ABSENCE when nothing refused us either — a site
    # that returned 403 to every probe plainly has SOMETHING in front of it,
    # and "no protective filter, directly exposed" is then contradicted by the
    # evidence elsewhere in the same report.
    _wp = waf_posture(cats)
    if _wp["state"] == "absent":
        cands.append((55, {
            "level": "MEDIUM",
            "headline": _wp["headline"],
            "summary": "Web traffic is not filtered for malicious patterns.",
            "detail": "The website has no protective filter, leaving it directly exposed to automated attacks and traffic floods."
        }))

    # HTTP headers weak
    # Defaulted to 100/100 -- an absent headers result rendered as perfect.
    hh = score_or_none(cats.get("http_headers"))
    if hh is not None and hh < 40:
        cands.append((50, {
            "level": "MEDIUM",
            "headline": f"Web application headers misconfigured ({hh}%)",
            "summary": "Common web attacks are not blocked at the browser.",
            "detail": f"Security headers at {hh}% — site is exposed to XSS, clickjacking, and content injection that modern headers would block."
        }))

    # Brand-impersonation / lookalike domains
    fd = cats.get("fraudulent_domains", {}).get("resolved_count", 0)
    if fd > 0:
        cands.append((52, {
            "level": "MEDIUM" if fd > 3 else "LOW",
            "headline": f"{fd} lookalike domain(s) registered",
            "summary": "Brand-impersonation infrastructure targeting staff and customers.",
            "detail": f"{fd} domains resembling this brand resolve to live infrastructure — the raw material for phishing and business-email-compromise campaigns against clients and employees."
        }))

    # Backfill so the section always surfaces the THREE highest factors,
    # irrespective of absolute severity — never repeats a single finding when
    # the target is otherwise healthy. These are lower-tier posture signals.
    if len(cands) < 3:
        have = {c[1]["headline"] for c in cands}
        em_b = score_or_none(cats.get("email_security"))
        sub_count = cats.get("subdomains", {}).get("total_count", 0)
        ip_count = estate_ip_count(cats, results)
        # conclusive_count, not a raw .get: an unassessed provider reports 0
        # and would otherwise be indistinguishable from a searched-and-clean
        # estate. Here it only suppresses a finding, but the next reader of
        # this value should not have to work that out.
        breach_emails = conclusive_count(cats, "dehashed", "unique_emails") or 0
        backfill = []
        if ssl_grade == "C":
            backfill.append((38, {
                "level": "LOW",
                "headline": f"SSL/TLS grade {ssl_grade} — encryption could be stronger",
                "summary": "Encryption is acceptable but not best-practice.",
                "detail": f"SSL grade {ssl_grade} indicates older cipher suites or configuration that should be hardened to an A grade."}))
        if em_b is not None and 5 <= em_b < 8:
            backfill.append((36, {
                "level": "LOW",
                "headline": f"Email authentication at {em_b}/10",
                "summary": "Phishing-resistance has room to improve.",
                "detail": "SPF/DKIM/DMARC are partially configured; tightening DMARC to p=reject reduces domain-spoofing risk."}))
        if hh is not None and 40 <= hh < 80:
            backfill.append((34, {
                "level": "LOW",
                "headline": f"Web security headers at {hh}%",
                "summary": "Some browser-side protections are missing.",
                "detail": f"Security headers at {hh}% — adding the missing headers hardens the site against XSS and clickjacking."}))
        if breach_emails > 0:
            backfill.append((30, {
                "level": "LOW",
                "headline": f"{breach_emails} staff email(s) in breach data",
                "summary": "Reconnaissance material for targeted phishing.",
                "detail": f"{breach_emails} staff email addresses appear in historical breach databases — useful to attackers for spear-phishing even without passwords."}))
        if ip_count or sub_count:
            backfill.append((22, {
                "level": "LOW",
                "headline": f"{ip_count} external IP(s), {sub_count} subdomain(s) discoverable",
                "summary": "Internet-facing attack surface is enumerable.",
                "detail": f"{ip_count} IP addresses and {sub_count} subdomains can be enumerated — a larger surface gives attackers more to probe."}))
        for w, d in backfill:
            if d["headline"] not in have:
                cands.append((w, d))

    cands.sort(key=lambda x: -x[0])
    return [c[1] for c in cands[:4]]


# ---------- Slide deck renderers (Kaizen-fidelity 16:9 widescreen) ----------

# PowerPoint widescreen: 960 x 540 pt = 10 x 5.625 in @ 96dpi.
ASX_PAGE_W = 960
ASX_PAGE_H = 540
ASX_MARGIN = 50
ASX_INNER_W = ASX_PAGE_W - 2 * ASX_MARGIN  # 860pt usable width

# Brand palette — modelled on the Kaizen executive deck. Adjust if Phishield
# brand colours diverge.
ASX_NAVY_DEEP  = colors.HexColor("#0a1f3d")   # full navy panels / slide 7 bg
ASX_NAVY       = colors.HexColor("#0f2744")   # standard heading text
ASX_NAVY_2     = colors.HexColor("#11304f")   # card body on navy slides
ASX_BLUE_LINK  = colors.HexColor("#1f5a8a")   # section labels / accent text
ASX_BLUE_BAR   = colors.HexColor("#2f6e9c")   # most-likely scenario bar
ASX_AMBER      = colors.HexColor("#d97706")
ASX_RED        = colors.HexColor("#dc2626")
ASX_CRITICAL   = colors.HexColor("#a32f25")   # slightly redder than C_CRITICAL
ASX_GREEN      = colors.HexColor("#16a34a")
ASX_TILE_BG    = colors.HexColor("#eef2f7")   # light blue-grey card fill
ASX_GREY_BODY  = colors.HexColor("#475569")
ASX_GREY_MUTED = colors.HexColor("#94a3b8")
ASX_WHITE      = colors.white

# Built-in PostScript serif fonts (no registration needed).
ASX_SERIF       = "Times-Roman"
ASX_SERIF_BOLD  = "Times-Bold"
ASX_SERIF_ITAL  = "Times-Italic"
ASX_SANS        = "Helvetica"
ASX_SANS_BOLD   = "Helvetica-Bold"
ASX_SANS_ITAL   = "Helvetica-Oblique"

_ASX_SEV_COLOR = {"CRITICAL": ASX_CRITICAL, "HIGH": ASX_AMBER, "MEDIUM": ASX_AMBER, "LOW": ASX_GREEN}
# UNKNOWN is grey, never green: a kill-chain phase that could not be assessed
# must not wear the colour of one assessed and found clean. Without the key the
# pill lookup at _assessment_kill_chain raises KeyError.
_ASX_SEV_HEX   = {"CRITICAL": "#a32f25", "HIGH": "#d97706", "MEDIUM": "#d97706",
                  "LOW": "#16a34a", "UNKNOWN": "#475569"}
# "unknown" is grey on purpose: a KPI tile for a checker that did not run must
# not borrow any of the three verdict colours.
_KPI_COLOR     = {"ok": ASX_GREEN, "warn": ASX_AMBER, "bad": ASX_RED,
                  "unknown": ASX_GREY_MUTED}


# --- Drawing primitives --------------------------------------------------

def _asx_pill(text, bg_hex, fg_hex="#ffffff", font_size=11, padding_x=18):
    """Rounded pill badge as a Drawing flowable."""
    from reportlab.graphics.shapes import Drawing, Rect, String
    w = max(96, len(text) * font_size * 0.62 + 2 * padding_x)
    h = font_size + 14
    d = Drawing(w, h)
    d.add(Rect(0, 0, w, h, rx=h / 2, ry=h / 2,
                strokeColor=None, fillColor=colors.HexColor(bg_hex)))
    d.add(String(w / 2, (h - font_size) / 2 + 2, text,
                  fontName=ASX_SANS_BOLD, fontSize=font_size,
                  fillColor=colors.HexColor(fg_hex), textAnchor="middle"))
    return d


def _asx_bar(width_pt, color, height=22):
    """Horizontal coloured rounded bar (for scenario bar chart)."""
    from reportlab.graphics.shapes import Drawing, Rect
    d = Drawing(max(8, width_pt), height)
    d.add(Rect(0, 0, max(8, width_pt), height, rx=height / 2, ry=height / 2,
                strokeColor=None, fillColor=color))
    return d


def _asx_circle_number(num, diameter=36):
    """Filled blue circle with a centred white number (Slide 7 step markers)."""
    from reportlab.graphics.shapes import Drawing, Circle, String
    d = Drawing(diameter, diameter)
    d.add(Circle(diameter / 2, diameter / 2, diameter / 2,
                  strokeColor=None, fillColor=ASX_BLUE_LINK))
    d.add(String(diameter / 2, diameter / 2 - 7, str(num),
                  fontName=ASX_SERIF_BOLD, fontSize=18,
                  fillColor=ASX_WHITE, textAnchor="middle"))
    return d


# --- Reusable text styles ------------------------------------------------

def _style_section_label():
    return ParagraphStyle("asx_sect_lbl", fontSize=10, fontName=ASX_SANS_BOLD,
                           textColor=ASX_BLUE_LINK, leading=12, alignment=TA_LEFT,
                           spaceAfter=4)

def _style_slide_title(size=30):
    return ParagraphStyle("asx_sl_title", fontSize=size, fontName=ASX_SERIF_BOLD,
                           textColor=ASX_NAVY, leading=size + 4, alignment=TA_LEFT,
                           spaceAfter=4)

def _style_intro():
    # Darkened from ASX_GREY_MUTED (#94a3b8, fails WCAG AA) to the readable
    # body grey ASX_GREY_BODY (#475569, AAA) - slide subtitles were hard to read.
    return ParagraphStyle("asx_intro", fontSize=11, fontName=ASX_SANS,
                           textColor=ASX_GREY_BODY, leading=15, alignment=TA_LEFT,
                           spaceAfter=10)


# The Next Steps slide is full-bleed navy. Its physical page number is
# content-dependent (an earlier slide can overflow to a 2nd page on data-heavy
# scans), so it is discovered at RENDER time: _AsxNavyAnchor - a zero-size
# marker placed at the END of the slide before Next Steps - records its page;
# the painter then navy-fills the FOLLOWING page. Robust to pagination drift.
from reportlab.platypus import Flowable as _Flowable
_ASX_NAVY_PREV_PAGE = [None]


class _AsxNavyAnchor(_Flowable):
    """Zero-size render-time marker: records the page it lands on so the page
    painter can navy-fill the next page (the Next Steps slide)."""
    width = 0
    height = 0

    def wrap(self, availWidth, availHeight):
        return (0, 0)

    def draw(self):
        _ASX_NAVY_PREV_PAGE[0] = self.canv.getPageNumber()


# --- Per-page background painter (called by SimpleDocTemplate) ----------

def _asx_draw_corner_mark(canvas, brand, x_right, y_baseline, max_w=110, max_h=32, light=False):
    """Draw the company logo if available, otherwise a serif wordmark."""
    logo = brand.get("logo_path") if brand else None
    if logo:
        try:
            from PIL import Image as _PILImage
            with _PILImage.open(logo) as im:
                iw, ih = im.size
            scale = min(max_w / iw, max_h / ih)
            w, h = iw * scale, ih * scale
            canvas.drawImage(logo, x_right - w, y_baseline - h * 0.15,
                             width=w, height=h, mask="auto")
            return
        except Exception:
            pass
    # Fallback wordmark
    canvas.setFont(ASX_SERIF_BOLD, 13 if light else 11)
    canvas.setFillColor(ASX_WHITE if light else ASX_NAVY)
    canvas.drawRightString(x_right, y_baseline,
        (brand.get("company_name", "Phishield") if brand else "Phishield").upper())


def _asx_page_painter(canvas, doc):
    """Slide-aware background + corner brand mark.

    The Next Steps slide is full-bleed navy; everything else is white. The
    navy page is found at render time via _AsxNavyAnchor (records the page of
    the slide before Next Steps); we navy-fill the FOLLOWING page - robust to
    content-driven pagination drift. (Was hardcoded page == 8, which broke
    when an earlier slide overflowed and pushed a light slide onto page 8.)
    Brand mark = logo image if brand_assets/<logo_file> exists, otherwise a
    serif wordmark from brand.company_name."""
    canvas.saveState()
    page = doc.page
    brand = _ASX_CURRENT_BRAND or {}

    navy_page = (_ASX_NAVY_PREV_PAGE[0] + 1) if _ASX_NAVY_PREV_PAGE[0] is not None else None
    if navy_page is not None and page == navy_page:
        canvas.setFillColor(ASX_NAVY_DEEP)
        canvas.rect(0, 0, ASX_PAGE_W, ASX_PAGE_H, stroke=0, fill=1)
        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,
                              ASX_PAGE_H - 40, light=True)
    else:
        _asx_draw_corner_mark(canvas, brand, ASX_PAGE_W - ASX_MARGIN,
                              22, light=False)

    canvas.restoreState()


# === SLIDE 1: Cover ======================================================

def _assessment_slide_cover(domain, timestamp, brand):
    """Cover: title left, optional hero image right (if brand asset exists)."""
    sub_st = ParagraphStyle("c_sub", fontSize=11, fontName=ASX_SANS,
                              textColor=ASX_GREY_BODY, leading=15)
    meta_st = ParagraphStyle("c_meta", fontSize=10, fontName=ASX_SANS_BOLD,
                               textColor=ASX_GREY_BODY, leading=14,
                               spaceAfter=0)
    title_st = ParagraphStyle("c_title", fontSize=60, fontName=ASX_SERIF,
                                textColor=ASX_NAVY, leading=66)

    title_block = [
        Paragraph(f"External Passive Security Evaluation &mdash; {domain}", sub_st),
        Paragraph(f"Executive Summary  |  Assessment date: {timestamp[:10]}", meta_st),
        Spacer(1, 140),
        Paragraph("Cyber Security", title_st),
        Paragraph("Assessment", title_st),
    ]

    hero = _asx_image_or_none(brand.get("cover_hero_path"), max_width=440, max_height=430)
    if hero is None:
        return title_block

    # Two-column layout: text left, hero right
    container = Table([[title_block, hero]],
                       colWidths=[440, ASX_INNER_W - 440])
    container.setStyle(TableStyle([
        ("VALIGN", (0, 0), (0, 0), "TOP"),
        ("VALIGN", (1, 0), (1, 0), "MIDDLE"),
        ("ALIGN",  (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return [container]


# === SLIDE 2: Overall Risk Score + Executive Summary (KPIs) ==============

def _assessment_slide_score_and_kpis(results):
    """Two-panel: dark navy left (~38% wide) with score; white right with 6 KPIs."""
    risk_score = results.get("overall_risk_score", 0)
    risk_level = results.get("risk_level", "Unknown")
    rc = risk_color(risk_level)

    # --- LEFT NAVY PANEL ---
    # Built as a single Table cell with navy fill, full-bleed height of slide.
    label_st = ParagraphStyle("p_lbl", fontSize=11, fontName=ASX_SANS,
                                textColor=ASX_GREY_MUTED, leading=14)
    big_score_st = ParagraphStyle("p_score", fontSize=100, fontName=ASX_SERIF,
                                    textColor=ASX_WHITE, leading=100)
    out_of_st = ParagraphStyle("p_out", fontSize=11, fontName=ASX_SANS,
                                 textColor=ASX_GREY_MUTED, leading=14)
    where_lbl_st = ParagraphStyle("p_where", fontSize=10, fontName=ASX_SANS_BOLD,
                                    textColor=colors.HexColor("#7ba0c4"),
                                    leading=14, spaceAfter=8)
    band_normal_st = ParagraphStyle("p_band_n", fontSize=11, fontName=ASX_SANS,
                                      textColor=ASX_GREY_MUTED, leading=20,
                                      spaceAfter=2)
    band_active_st = ParagraphStyle("p_band_a", fontSize=11, fontName=ASX_SANS_BOLD,
                                      textColor=ASX_AMBER, leading=20,
                                      spaceAfter=2)

    # Severity-pill colour for the risk-level badge
    pill_bg_hex = {"Low": "#16a34a", "Medium": "#d97706",
                    "High": "#dc2626", "Critical": "#a32f25"}.get(risk_level, "#94a3b8")

    # Highlight active band
    def _band(label, rng, active):
        st = band_active_st if active else band_normal_st
        return Paragraph(f"<b>{label}</b>      {rng}", st)

    bands = [
        ("Low Risk", "0 – 199", 0, 199),
        ("Medium Risk", "200 – 399", 200, 399),
        ("High Risk", "400 – 599", 400, 599),
        ("Critical Risk", "600 – 1000", 600, 1000),
    ]
    band_paras = []
    for label, rng, lo, hi in bands:
        active = (lo <= risk_score <= hi)
        band_paras.append(_band(label, rng, active))

    navy_inner = [
        Paragraph("Overall Risk Score", label_st),
        Spacer(1, 10),
        Paragraph(f"{risk_score}", big_score_st),
        Paragraph("out of 1000", out_of_st),
        Spacer(1, 16),
        _asx_pill(f"{risk_level.upper()} RISK", pill_bg_hex, font_size=14, padding_x=22),
        Spacer(1, 28),
        Paragraph(f"WHERE {risk_score} SITS", where_lbl_st),
    ] + band_paras

    # Wrap in a navy Table cell (fixed height = slide minus top/bottom margin)
    navy_panel = Table(
        [[navy_inner]],
        colWidths=[330], rowHeights=[440]
    )
    navy_panel.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ASX_NAVY_DEEP),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 36),
        ("RIGHTPADDING", (0, 0), (-1, -1), 24),
        ("TOPPADDING", (0, 0), (-1, -1), 36),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 36),
    ]))

    # --- RIGHT WHITE PANEL: heading + 6 KPI tiles with coloured left border ---
    kpis = _assessment_extract_kpis(results)
    val_styles = {sev: ParagraphStyle(f"k_v_{sev}", fontSize=48, fontName=ASX_SERIF,
                                       textColor=_KPI_COLOR[sev], leading=52)
                  for sev in _KPI_COLOR}
    lab_st = ParagraphStyle("k_l", fontSize=11, fontName=ASX_SANS_BOLD,
                              textColor=ASX_NAVY, leading=14, spaceBefore=4)
    desc_st = ParagraphStyle("k_d", fontSize=9, fontName=ASX_SANS,
                               textColor=ASX_GREY_MUTED, leading=12)

    def kpi_cell(k):
        return [
            Paragraph(k["value"], val_styles[k["severity"]]),
            Spacer(1, 4),
            Paragraph(k["label"], lab_st),
            Paragraph(k["description"], desc_st),
        ]

    # Build a 2x3 grid. Each cell gets a coloured LEFT line via per-cell style.
    cell_contents = [
        [kpi_cell(kpis[0]), kpi_cell(kpis[1]), kpi_cell(kpis[2])],
        [kpi_cell(kpis[3]), kpi_cell(kpis[4]), kpi_cell(kpis[5])],
    ]

    right_inner_w = ASX_INNER_W + ASX_MARGIN - 330 - 50  # post-navy width
    kpi_grid = Table(cell_contents,
                      colWidths=[right_inner_w / 3] * 3,
                      rowHeights=[160, 160])

    style_cmds = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), ASX_TILE_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        # Outer white gutter between cells
        ("INNERGRID", (0, 0), (-1, -1), 6, ASX_WHITE),
    ]
    # Coloured LEFT bar per cell — paint via LINEBEFORE with thick line
    # Second copy of the KPI severity map; "unknown" must reach both or a tile
    # for a checker that did not run raises KeyError mid-render.
    sev_to_color = {"ok": ASX_GREEN, "warn": ASX_AMBER, "bad": ASX_RED,
                    "unknown": ASX_GREY_MUTED}
    flat = [kpis[0], kpis[1], kpis[2], kpis[3], kpis[4], kpis[5]]
    for idx in range(6):
        col = idx % 3
        row = idx // 3
        bar_col = sev_to_color[flat[idx]["severity"]]
        style_cmds.append(("LINEBEFORE", (col, row), (col, row), 4, bar_col))

    kpi_grid.setStyle(TableStyle(style_cmds))

    right_col = [
        Paragraph("Executive Summary", _style_slide_title(30)),
        Paragraph("The findings that most influence cyber insurance pricing for this organisation.",
                   _style_intro()),
        Spacer(1, 8),
        kpi_grid,
    ]

    # The navy panel needs to bleed to the left edge — use a 2-column container
    # with no padding on the left side.
    # Gap between navy block and right-col text:
    #   - RIGHTPADDING (0,0) = 36 → 36pt of white space after the navy
    #     panel ends, inside the navy cell
    #   - LEFTPADDING (1,0) = 28 → 28pt of additional white space before
    #     the right-col content begins
    # Total gap = 64pt (~22.6mm). The original 36pt felt cramped per
    # user feedback (2026-05-28); 64pt gives the "Executive Summary"
    # heading visible breathing room from the navy block.
    container = Table([[navy_panel, right_col]],
                       colWidths=[330, ASX_PAGE_W - 330 - 50])
    container.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 28),
        ("RIGHTPADDING", (0, 0), (0, 0), 36),
        ("RIGHTPADDING", (1, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return [container]


# === SLIDE 3: Attacker's View (4 phase cards) ===========================

def _assessment_slide_attackers_view(results):
    phases = _assessment_kill_chain(results)

    parts = [
        Paragraph("ATTACKER'S VIEW", _style_section_label()),
        Paragraph("How an Attacker Would Approach This Target", _style_slide_title(30)),
        Paragraph("The same findings, mapped to the four stages of a real-world cyber attack.",
                   _style_intro()),
        Spacer(1, 6),
    ]

    phase_lbl = ParagraphStyle("ph_lbl", fontSize=9, fontName=ASX_SANS_BOLD,
                                 textColor=colors.HexColor("#7ba0c4"), leading=11)
    phase_name = ParagraphStyle("ph_name", fontSize=17, fontName=ASX_SANS_BOLD,
                                  textColor=ASX_WHITE, leading=20)
    headline_st = ParagraphStyle("ph_head", fontSize=11, fontName=ASX_SANS_ITAL,
                                   textColor=ASX_BLUE_LINK, leading=14)
    bullet_st = ParagraphStyle("ph_b", fontSize=10, fontName=ASX_SANS,
                                 textColor=ASX_NAVY, leading=14,
                                 leftIndent=10, firstLineIndent=-10)

    def phase_card(i, ph):
        # Header band cell
        header_cell = [
            Paragraph(f"PHASE {i + 1}", phase_lbl),
            Spacer(1, 4),
            Paragraph(ph["name"], phase_name),
        ]
        # Body cell
        body_cell = [_asx_pill(ph["severity"], _ASX_SEV_HEX[ph["severity"]], font_size=11)]
        body_cell += [Spacer(1, 12), Paragraph(ph["headline"], headline_st), Spacer(1, 8)]
        for f in ph["findings"]:
            body_cell.append(Paragraph(f"&ndash;&nbsp;&nbsp;{f}", bullet_st))
            body_cell.append(Spacer(1, 4))
        # Stack header+body via inner table
        card = Table([[header_cell], [body_cell]],
                      colWidths=[(ASX_INNER_W - 24) / 4],
                      rowHeights=[80, 230])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), ASX_NAVY_DEEP),
            ("BACKGROUND", (0, 1), (0, 1), ASX_WHITE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 18),
            ("RIGHTPADDING", (0, 0), (-1, -1), 18),
            ("TOPPADDING", (0, 0), (0, 0), 18),
            ("BOTTOMPADDING", (0, 0), (0, 0), 14),
            ("TOPPADDING", (0, 1), (0, 1), 18),
            ("BOTTOMPADDING", (0, 1), (0, 1), 18),
            ("BOX", (0, 1), (0, 1), 0.4, colors.HexColor("#cbd5e1")),
        ]))
        return card

    row_cells = [phase_card(i, ph) for i, ph in enumerate(phases)]
    grid = Table([row_cells], colWidths=[(ASX_INNER_W - 24) / 4] * 4)
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    parts.append(grid)
    return parts


# === SLIDE 4: Supply-Chain Exposure =====================================
# Sits between Attacker's View (how) and Financial Impact (cost) because
# supply-chain risk bridges them: it amplifies both the probability of a
# breach (vulnerability uplift in the financial model) and the
# narrative around HOW the insured gets compromised (vendor / CDN /
# declared-supplier paths).

def _assessment_slide_supply_chain(results):
    cats = results.get("categories", {})
    rd = cats.get("related_domains", {})
    dm = cats.get("dependency_manifests", {})
    tpjs = cats.get("third_party_js", {})
    evs = cats.get("email_vendor_surface", {})
    cms = cats.get("cms_plugin_sbom", {})
    vb = cats.get("vendor_breach", {})

    # Per-card severity classification — mirrors how the body PDF
    # cat_* helpers compute traffic-light colours, but condensed.
    # Returns (severity, metric_text) for "skipped" / not-run states;
    # returns None when the checker completed and per-card logic should
    # build the metric from real fields.
    def _classify(payload):
        # A checker that RAN and found nothing (no_data) is CLEAN, not
        # "not run". skipped = not applicable; absent/error = not assessed.
        st = payload.get("status")
        if st == "skipped":
            return "NA", "Not applicable"
        if st == "no_data":
            return "CLEAN", "No exposure found"
        if st == "completed":
            return None
        if st in (None, "error"):
            return "UNKNOWN", "Not assessed (no scan data)"
        return "UNKNOWN", "Not assessed"

    cards = []

    # S-1 Related Domains
    cls = _classify(rd)
    if cls:
        sev, metric = cls
    else:
        crit = rd.get("critical_count", 0)
        scanned = rd.get("scanned_count", 0)
        declared = rd.get("declared_count", 0)
        if declared == 0:
            sev, metric = "NA", "No declared suppliers"
        elif crit > 0:
            sev = "CRITICAL"
            metric = f"{crit} critical of {scanned} declared supplier(s)"
        elif rd.get("high_count", 0) > 0:
            sev = "HIGH"
            metric = f"{rd['high_count']} of {scanned} suppliers below 60/100"
        else:
            sev = "LOW"
            metric = f"{scanned} declared supplier(s) — clean"
    cards.append({
        "label": "S-1 Related Domains",
        "headline": "Civil-liability inflator — supplier-domain compromise",
        "severity": sev,
        "metric": metric,
        "support": "Declared sibling/supplier domains scanned in LITE mode; "
                   "worst-of-N feeds the vulnerability uplift.",
    })

    # S-3 Dependency Manifests
    cls = _classify(dm)
    if cls:
        sev, metric = cls
    else:
        crit_cves = dm.get("total_critical_cves", 0)
        manifests = len(dm.get("exposed_manifests", []) or [])
        if crit_cves > 0:
            sev = "CRITICAL"
            metric = f"{crit_cves} CVE(s) actionable via OSV.dev"
        elif manifests > 0:
            sev = "HIGH"
            metric = f"{manifests} manifest(s) exposed — OSV chain risk"
        else:
            sev = "LOW"
            metric = "No public manifests at web root"
    cards.append({
        "label": "S-3 Dependency Manifests",
        "headline": "Leaked version map enables zero-recon CVE chaining",
        "severity": sev,
        "metric": metric,
        "support": "Probes 15 manifest paths (npm/PyPI/Packagist/RubyGems/Go/"
                   "crates.io/Maven); OSV.dev cross-references exact versions.",
    })

    # S-2 Third-Party JS
    cls = _classify(tpjs)
    if cls:
        sev, metric = cls
    else:
        comp = tpjs.get("compromised_host_count", 0)
        missing = tpjs.get("missing_sri_count", 0)
        third = tpjs.get("third_party_count", 0)
        if comp > 0:
            sev = "CRITICAL"
            metric = f"{comp} compromised CDN script(s) live"
        elif third and missing / max(1, third) > 0.5:
            sev = "HIGH"
            metric = f"{missing}/{third} third-party scripts without SRI"
        else:
            sev = "LOW"
            metric = f"{third} third-party scripts — SRI coverage OK"
    cards.append({
        "label": "S-2 Third-Party JavaScript",
        "headline": "Magecart card-skimmer channel (Polyfill.io 2024)",
        "severity": sev,
        "metric": metric,
        "support": "Parses homepage &lt;script&gt; tags; flags known-"
                   "compromised CDNs and SRI gaps on third-party origins.",
    })

    # S-4 Email-Vendor Surface
    cls = _classify(evs)
    if cls:
        sev, metric = cls
    else:
        count = evs.get("vendor_count", 0)
        weak = evs.get("weak_dmarc", False)
        policy = evs.get("dmarc_policy") or "missing"
        if weak and count >= 1:
            sev = "HIGH"
            metric = f"{count} vendor(s) + DMARC p={policy}"
        elif count >= 6:
            sev = "MEDIUM"
            metric = f"{count} vendor(s) — wide fourth-party surface"
        else:
            sev = "LOW"
            metric = f"{count} vendor(s) — DMARC p={policy}"
    cards.append({
        "label": "S-4 Email-Vendor Surface",
        "headline": "Phishing-via-supplier when DMARC is weak",
        "severity": sev,
        "metric": metric,
        "support": "Walks the SPF include: chain; classifies against 24 known "
                   "email-SaaS patterns; cross-references DMARC policy.",
    })

    # S-10 CMS Plugin SBOM
    cls = _classify(cms)
    if cls:
        sev, metric = cls
    else:
        if not cms.get("is_wordpress"):
            sev, metric = "NA", "Not WordPress"
        else:
            v = cms.get("versioned_count", 0)
            cnt = cms.get("plugin_count", 0)
            if v >= 1:
                sev = "HIGH"
                metric = f"{v} plugin(s) with readable version"
            elif cnt >= 5:
                sev = "MEDIUM"
                metric = f"{cnt} popular plugins enumerable"
            else:
                sev = "LOW"
                metric = f"{cnt} plugin(s) detected"
    cards.append({
        "label": "S-10 CMS Plugin Surface",
        "headline": "Top SA SME ransomware vector (Patchstack 2024)",
        "severity": sev,
        "metric": metric,
        "support": "WordPress-only. Enumerates 25 popular plugin slugs; "
                   "harvests version strings from readme.txt 'Stable tag:'.",
    })

    # S-5 Vendor Breach Correlation
    cls = _classify(vb)
    if cls:
        sev, metric = cls
    else:
        crit = vb.get("critical_match_count", 0)
        high = vb.get("high_match_count", 0)
        if crit > 0:
            sev = "CRITICAL"
            top = (vb.get("matches") or [{}])[0]
            months = max(1, (top.get("age_days") or 0) // 30)
            metric = f"{top.get('vendor', '?')} ~{months} mo ago ({top.get('severity','')})"
        elif high > 0:
            sev = "HIGH"
            metric = f"{high} high-severity vendor match(es)"
        elif vb.get("matches"):
            sev = "MEDIUM"
            metric = f"{len(vb['matches'])} historical vendor match(es)"
        else:
            sev = "LOW"
            metric = "No vendor matches in lookback window"
    cards.append({
        "label": "S-5 Vendor Breach Correlation",
        "headline": "Customer-key rotation often incomplete post-breach",
        "severity": sev,
        "metric": metric,
        "support": "Curated 14-incident database (Mailchimp 2022/23, Okta 22/23, "
                   "MS365 Storm-0558, etc.). 5-year lookback with age decay.",
    })

    # Phase 4f Cross-Correlation (Hudson Rock x S-4 x S-5)
    tpc = cats.get("third_party_correlation", {})
    cls = _classify(tpc)
    if cls:
        sev, metric = cls
    else:
        if tpc.get("critical_count", 0) > 0:
            sev = "CRITICAL"
            susp = tpc.get("suspected_vendors") or []
            vendor_names = ", ".join(s.get("vendor", "?") for s in susp[:3])
            metric = f"Rotate at: {vendor_names}"
        elif tpc.get("high_count", 0) > 0:
            sev = "HIGH"
            metric = (f"{tpc.get('hudson_rock_third_party_count', 0)} HR exposure(s) "
                       f"+ {tpc.get('spf_vendor_count', 0)} SPF vendor(s)")
        elif tpc.get("medium_count", 0) > 0:
            sev = "MEDIUM"
            metric = (f"{tpc.get('hudson_rock_third_party_count', 0)} HR exposure(s) "
                       "(no SPF / breach overlap)")
        else:
            sev = "LOW"
            metric = "No HR third-party exposures"
    cards.append({
        "label": "Phase 4f Cross-Correlation",
        "headline": "Strongest signal: HR observed harvest x SPF x breach DB",
        "severity": sev,
        "metric": metric,
        "support": "Joins Hudson Rock infostealer harvest with S-4 SPF vendor "
                   "surface and S-5 known-breach DB. Triple-source match = "
                   "highest-priority rotate target.",
    })

    # ── Layout: 2 columns × 3 rows ────────────────────────────────────
    label_st = ParagraphStyle("sc_lbl", fontSize=8, fontName=ASX_SANS_BOLD,
                                textColor=colors.HexColor("#7ba0c4"), leading=10)
    name_st = ParagraphStyle("sc_n", fontSize=12, fontName=ASX_SANS_BOLD,
                               textColor=ASX_NAVY, leading=14)
    headline_st = ParagraphStyle("sc_h", fontSize=9, fontName=ASX_SANS_ITAL,
                                   textColor=ASX_BLUE_LINK, leading=11)
    metric_st = ParagraphStyle("sc_m", fontSize=10, fontName=ASX_SANS_BOLD,
                                 textColor=ASX_NAVY, leading=13)
    support_st = ParagraphStyle("sc_s", fontSize=8, fontName=ASX_SANS,
                                  textColor=ASX_GREY_BODY, leading=11)

    # Severity colour map for the pill badge — same hex values used
    # in _assessment_slide_attackers_view.
    _SC_SEV_HEX = {
        "CRITICAL": "#991b1b", "HIGH": "#dc2626",
        "MEDIUM": "#92400e",   "LOW": "#166534",
        "INFO": "#475569",
    }

    # -- Executive roll-up: ONE verdict + only material-finding signals --
    # The signal-by-signal S-1..S-10 detail lives in the full technical
    # report + HTML; an executive deck carries a single verdict and only the
    # signals with a material finding (no "not run"/"not applicable" tiles).
    _SC_PLAIN = {
        "S-1 Related Domains": ("Declared suppliers",
            "A supplier or sister-company domain you rely on is compromised and used to reach you."),
        "S-3 Dependency Manifests": ("Exposed code dependencies",
            "Your software 'parts list' is publicly readable, letting attackers target known flaws with no reconnaissance."),
        "S-2 Third-Party JavaScript": ("Website third-party scripts",
            "A third-party script on your site (analytics, ads, CDN) is hijacked to skim customer or card data."),
        "S-4 Email-Vendor Surface": ("Email service providers",
            "An email vendor in your sending chain is abused to phish your staff and customers in your name."),
        "S-10 CMS Plugin Surface": ("Website plugins",
            "Out-of-date website plugins are a leading ransomware entry point for SA SMEs."),
        "S-5 Vendor Breach Correlation": ("Known vendor breaches",
            "A vendor that holds your data or login keys has a publicly-known breach; key rotation is often left incomplete."),
        "Phase 4f Cross-Correlation": ("Cross-checked vendor exposure",
            "Several independent signals point at the SAME vendor - the highest-priority item to rotate."),
    }
    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
    flagged = [c for c in cards if c["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    clean = [c for c in cards if c["severity"] in ("LOW", "CLEAN")]
    na = [c for c in cards if c["severity"] == "NA"]
    unknown = [c for c in cards if c["severity"] not in
               ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "NA")]
    assessed = flagged + clean
    flagged.sort(key=lambda c: -_SEV_ORDER.get(c["severity"], 0))

    if flagged:
        worst = flagged[0]["severity"]
        verdict_text, vhex = worst + " EXPOSURE", _SC_SEV_HEX.get(worst, "#475569")
        sub = (str(len(flagged)) + " of " + str(len(assessed)) +
               " assessed supply-chain signal(s) flagged for attention.")
    elif assessed:
        verdict_text, vhex = "LOW EXPOSURE", _SC_SEV_HEX["LOW"]
        sub = "All " + str(len(assessed)) + " assessed supply-chain signal(s) are clean."
    else:
        verdict_text, vhex = "NOT ASSESSED", "#475569"
        sub = "No external supply-chain signals could be assessed on this scan."

    vsub_st = ParagraphStyle("sc_vsub", fontSize=11, fontName=ASX_SANS,
                              textColor=ASX_GREY_BODY, leading=15)
    fname_st = ParagraphStyle("sc_fn", fontSize=13, fontName=ASX_SANS_BOLD,
                               textColor=ASX_NAVY, leading=16)
    frisk_st = ParagraphStyle("sc_fr", fontSize=10, fontName=ASX_SANS,
                               textColor=ASX_GREY_BODY, leading=14)
    fdetail_st = ParagraphStyle("sc_fd", fontSize=9.5, fontName=ASX_SANS_BOLD,
                                 textColor=ASX_NAVY, leading=13)
    foot_st = ParagraphStyle("sc_foot", fontSize=8.5, fontName=ASX_SANS,
                              textColor=ASX_GREY_MUTED, leading=12)

    out = [
        Paragraph("SUPPLY-CHAIN EXPOSURE", _style_section_label()),
        Paragraph("Risk Inherited From Vendors, CDNs, and Suppliers",
                   _style_slide_title(28)),
        Spacer(1, 6),
        _asx_pill(verdict_text, vhex, font_size=12),
        Spacer(1, 7),
        Paragraph(sub, vsub_st),
        Spacer(1, 8),
        Paragraph(
            "About one in eight breaches has a supply-chain root cause (IBM "
            "Cost of a Data Breach 2024) and they take roughly 48% longer to "
            "contain. The signals below are what that means for this "
            "organisation.",
            _style_intro()),
        Spacer(1, 12),
    ]

    if flagged:
        frows = []
        for c in flagged:
            pn, pr = _SC_PLAIN.get(c["label"], (c["label"], c.get("headline", "")))
            frows.append([[
                _asx_pill(c["severity"], _SC_SEV_HEX.get(c["severity"], "#475569"),
                           font_size=9),
                Spacer(1, 5),
                Paragraph(pn, fname_st),
                Spacer(1, 3),
                Paragraph(pr, frisk_st),
                Spacer(1, 3),
                Paragraph("What we found: " + str(c["metric"]), fdetail_st),
            ]])
        out.append(Table(frows, colWidths=[ASX_INNER_W], style=TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#fbfbfd")),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 16),
            ("RIGHTPADDING", (0, 0), (-1, -1), 16),
            ("TOPPADDING",   (0, 0), (-1, -1), 13),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
            ("LINEBELOW",    (0, 0), (-1, -2), 0.4, colors.HexColor("#e2e8f0")),
            ("BOX",          (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ])))
    else:
        out.append(Paragraph(
            "No material supply-chain exposure was identified on this scan - "
            "every assessed external signal is within normal bounds. This is a "
            "positive due-diligence result, not an absence of checking.", frisk_st))

    def _plain_names(cardlist):
        return ", ".join(_SC_PLAIN.get(c["label"], (c["label"],))[0]
                          for c in cardlist) or "none"
    foot = "<b>Assessed:</b> " + _plain_names(assessed) + ". "
    if na:
        foot += "<b>Not applicable:</b> " + _plain_names(na) + ". "
    if unknown:
        foot += "<b>Not assessed (no scan data):</b> " + _plain_names(unknown) + ". "
    foot += "Full signal-by-signal detail is in the technical report."
    out += [Spacer(1, 12), Paragraph(foot, foot_st)]
    return out


# === SLIDE 5: Financial Impact (navy card + bar chart) ==================

def _assessment_slide_financial_impact(results):
    ins = results.get("insurance", {})
    fin = ins.get("financial_impact", {})
    cur_sym = "R" if fin.get("currency") == "ZAR" else "$"

    mc = fin.get("monte_carlo", {})
    mc_total = mc.get("total", {})
    mc_p50 = mc_total.get("p50", 0)
    mc_mode = mc_total.get("mode", 0) or fin.get("estimated_annual_loss", {}).get("most_likely", 0)

    def fmt(v):
        if not v or v == 0: return "&mdash;"
        if v >= 1_000_000_000:
            return f"{cur_sym}&nbsp;{v / 1_000_000_000:.2f}bn"
        if v >= 1_000_000:
            return f"{cur_sym}&nbsp;{v / 1_000_000:.2f}m"
        return f"{cur_sym}&nbsp;{v:,.0f}"

    le_scn = (fin.get("loss_exposure", {}) or {}).get("scenarios", {})

    # Build (label, sub, value, bar_color) — ordered, color-graded.
    BAR_COLORS = {
        "most_likely":  ASX_BLUE_BAR,
        "median":       ASX_NAVY_DEEP,
        "return_1_100": ASX_AMBER,
        "return_1_200": ASX_RED,
        "return_1_250": ASX_CRITICAL,
    }
    rows = []
    if isinstance(le_scn, dict) and le_scn:
        for key in ("most_likely", "median", "return_1_100", "return_1_200", "return_1_250"):
            sc = le_scn.get(key)
            if not sc: continue
            # Match Kaizen wording exactly
            label_map = {
                "most_likely": "Most likely outcome",
                "median": "Median (P50)",
                "return_1_100": "Severe event",
                "return_1_200": "Extreme event",
                "return_1_250": "Catastrophic event",
            }
            sub_map = {
                "most_likely": "Most likely (peak)",
                "median": "50% annual probability",
                "return_1_100": "P99 severity",
                "return_1_200": "P99.5 severity",
                "return_1_250": "P99.6 severity (1-in-250)",
            }
            rows.append((label_map[key], sub_map[key], sc.get("loss_zar", 0), BAR_COLORS[key]))
    else:
        if mc_mode: rows.append(("Most likely outcome", "Most likely (peak)", mc_mode, BAR_COLORS["most_likely"]))
        if mc_p50:  rows.append(("Median (P50)", "50% annual probability", mc_p50, BAR_COLORS["median"]))

    # --- LEFT NAVY CARD with median --------------------------------------
    eal_lbl_st = ParagraphStyle("eal_l", fontSize=11, fontName=ASX_SANS_BOLD,
                                  textColor=colors.HexColor("#7ba0c4"), leading=14)
    eal_val_st = ParagraphStyle("eal_v", fontSize=52, fontName=ASX_SERIF,
                                  textColor=ASX_WHITE, leading=58)
    eal_sub_st = ParagraphStyle("eal_s", fontSize=12, fontName=ASX_SANS,
                                  textColor=ASX_GREY_MUTED, leading=16)
    eal_note_st = ParagraphStyle("eal_n", fontSize=10, fontName=ASX_SANS,
                                   textColor=ASX_GREY_MUTED, leading=14)

    navy_inner = [
        Paragraph("ESTIMATED ANNUAL LOSS", eal_lbl_st),
        Spacer(1, 22),
        Paragraph(fmt(mc_p50), eal_val_st),
        Spacer(1, 6),
        Paragraph("Median (P50) modelled outcome", eal_sub_st),
        Spacer(1, 18),
        Paragraph("Modelled with a Monte Carlo simulation calibrated to South African breach and ransomware data for this industry and size.",
                   eal_note_st),
    ]

    navy_card = Table([[navy_inner]],
                       colWidths=[290], rowHeights=[285])
    navy_card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ASX_NAVY_DEEP),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 28),
        ("RIGHTPADDING", (0, 0), (-1, -1), 22),
        ("TOPPADDING", (0, 0), (-1, -1), 28),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [12, 12, 12, 12]),
    ]))

    # --- RIGHT BAR CHART -------------------------------------------------
    scn_lbl_st = ParagraphStyle("sn_l", fontSize=11, fontName=ASX_SANS_BOLD,
                                  textColor=ASX_NAVY, leading=14)
    scn_sub_st = ParagraphStyle("sn_s", fontSize=10, fontName=ASX_SANS,
                                  textColor=ASX_GREY_MUTED, leading=13)
    scn_val_st = ParagraphStyle("sn_v", fontSize=14, fontName=ASX_SANS_BOLD,
                                  textColor=ASX_NAVY, leading=18)

    bar_area_w = ASX_INNER_W - 290 - 30  # right column width minus padding
    max_val = max((v for _, _, v, _ in rows), default=1) or 1

    # NO SCENARIOS = NO TABLE. ReportLab raises "Table must have at least a row
    # and column" on an empty row list, which took down the whole Executive
    # Summary while the broker summary and full report rendered fine.
    #
    # This is reachable in production: scanner.py leaves
    # results["insurance"] = {"error": ...} when apply_insurance_analytics
    # raises, so the scan stores, downloads two tiers, and 500s the third. Same
    # symptom as the credential crash of 2026-08-14, different trigger, found by
    # the review agent that critiqued the fix for the first one.
    #
    # Say so instead. An absent financial model is not a zero exposure, and the
    # deck must not imply one.
    if not rows:
        note = Paragraph(
            "Financial exposure could not be modelled for this scan, so no loss "
            "scenarios are shown. This is not an indication of low exposure — the "
            "modelling inputs were unavailable. Re-run the scan before relying on "
            "this report for a placement decision.",
            ParagraphStyle("fin_na", fontSize=11, fontName=ASX_SANS,
                           textColor=ASX_GREY_BODY, leading=16))
        bar_chart_rows = [[note]]
    else:
        bar_chart_rows = []
        for label, sub, val, bar_color in rows:
            # Label + sub on one line: "Label  ·  sub"
            title_para = Paragraph(
                f"<b><font color='#0f2744'>{label}</font></b>"
                f"  <font color='#94a3b8' size='10'>&middot;  {sub}</font>",
                scn_lbl_st)
            # Bar width proportional to value (min 30pt for visibility)
            bw = max(30, (val / max_val) * (bar_area_w - 130))
            bar = _asx_bar(bw, bar_color, height=20)
            # Bar + value side by side
            bar_row = Table([[bar, Paragraph(fmt(val), ParagraphStyle(
                "v", fontSize=15, fontName=ASX_SANS_BOLD,
                textColor=bar_color, leading=18, alignment=TA_LEFT))]],
                colWidths=[bw + 6, 130])
            bar_row.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING", (1, 0), (1, 0), 10),
            ]))
            bar_chart_rows.append([title_para])
            bar_chart_rows.append([Spacer(1, 3)])
            bar_chart_rows.append([bar_row])
            bar_chart_rows.append([Spacer(1, 5)])

    bar_chart = Table(bar_chart_rows, colWidths=[bar_area_w])
    bar_chart.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    if not rows:
        bar_chart = Paragraph("Financial model not available for this scan.", scn_sub_st)

    body = Table([[navy_card, "", bar_chart]],
                  colWidths=[290, 30, ASX_INNER_W - 290 - 30])
    body.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (1, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    caveat_st = ParagraphStyle("cv", fontSize=9, fontName=ASX_SANS,
                                 textColor=ASX_GREY_MUTED, leading=12,
                                 backColor=ASX_TILE_BG, borderPadding=8)

    # --- FAIR frequency view: compact ANNUAL LIKELIHOOD strip ---
    # New view of already-scored signals (fin['risk_probability'], item #17) -
    # reporting-only. Three tiles: total cyber-incident (nested), data breach,
    # availability (indicative). Grade-coloured % for at-a-glance reading.
    rp = fin.get("risk_probability", {}) or {}
    prob_strip = []
    if rp:
        _db = rp.get("data_breach", {}) or {}
        _ci = rp.get("cyber_incident", {}) or {}
        _av = rp.get("availability_resilience", {}) or {}
        _ghex = {"Strong": "#166534", "Good": "#166534", "Low": "#166534",
                 "Typical": "#92400e", "Elevated": "#b45309",
                 "High": "#dc2626", "Critical": "#991b1b"}
        def _chip(pct, lab, grade, hexc):
            return ("<font name='Helvetica-Bold' size='16' color='" + hexc + "'>" + pct + "</font>"
                    " <font size='10' color='#0f2744'><b>" + lab + "</b></font>"
                    " <font size='9' color='#64748b'>" + grade + "</font>")
        _sep = " &nbsp;&nbsp; <font color='#cbd5e1'>|</font> &nbsp;&nbsp; "
        _line = _sep.join([
            _chip("%.1f%%" % _ci.get('probability_pct', 0), "Total cyber-incident",
                  _ci.get('grade', ''), _ghex.get(_ci.get('grade', ''), "#0f2744")),
            _chip("%.2f%%" % _db.get('probability_pct', 0), "Data breach",
                  _db.get('grade', ''), _ghex.get(_db.get('grade', ''), "#0f2744")),
            _chip("%.0f%%" % _av.get('indicator_pct', 0), "Availability",
                  "indicative", "#475569"),
        ])
        prob_strip = [
            Spacer(1, 10),
            Paragraph("ANNUAL LIKELIHOOD "
                      "<font size=9 color='#94a3b8'>(how often a loss event is "
                      "expected - pairs with the cost above; data breach is nested "
                      "in the total)</font>", _style_section_label()),
            Spacer(1, 5),
            Paragraph(_line, ParagraphStyle("plk", fontSize=11, leading=20)),
        ]

    out = [
        Paragraph("FINANCIAL IMPACT", _style_section_label()),
        Paragraph("What a Breach Could Cost", _style_slide_title(30)),
        Paragraph("Modelled annual cyber loss across a range of severity scenarios, from the most likely outcome to a rare catastrophe.",
                   _style_intro()),
        body,
    ]
    out += prob_strip
    out += [
        Spacer(1, 10),
        Paragraph("Figures are statistical model output. Selecting the appropriate cover limit is a decision for the insured in consultation with the broker.",
                   caveat_st),
    ]
    return out


# === SLIDE 5: Why This Matters (6 stat tiles, no borders) ===============

def _assessment_slide_why_this_matters():
    stats = _load_assessment_industry_stats()

    # Color emphasis on the "existential" stat (index 3, "60%+ SMB shut")
    EMPH_INDEX = 3
    val_navy_st = ParagraphStyle("st_v_n", fontSize=42, fontName=ASX_SERIF,
                                   textColor=ASX_NAVY, leading=48)
    val_red_st  = ParagraphStyle("st_v_r", fontSize=42, fontName=ASX_SERIF,
                                   textColor=ASX_RED, leading=48)
    lab_st = ParagraphStyle("st_l", fontSize=11, fontName=ASX_SANS_BOLD,
                              textColor=ASX_NAVY, leading=14)
    desc_st = ParagraphStyle("st_d", fontSize=10, fontName=ASX_SANS,
                               textColor=ASX_GREY_BODY, leading=13)

    def stat_cell(s, emphasised=False):
        val_st = val_red_st if emphasised else val_navy_st
        return [
            Paragraph(s.get("value", "&mdash;"), val_st),
            Spacer(1, 8),
            Paragraph(s.get("label", ""), lab_st),
            Spacer(1, 3),
            Paragraph(s.get("description", ""), desc_st),
        ]

    grid = Table(
        [[stat_cell(stats[0]), stat_cell(stats[1]), stat_cell(stats[2])],
         [stat_cell(stats[3], emphasised=True), stat_cell(stats[4]), stat_cell(stats[5])]],
        colWidths=[ASX_INNER_W / 3] * 3,
        rowHeights=[170, 170],
    )
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), ASX_TILE_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 22),
        ("RIGHTPADDING", (0, 0), (-1, -1), 22),
        ("TOPPADDING", (0, 0), (-1, -1), 22),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
        # White gutters between cards (no inner grid; cards separated by white space)
        ("INNERGRID", (0, 0), (-1, -1), 10, ASX_WHITE),
    ]))

    return [
        Paragraph("THE REALITY OF A CYBER BREACH", _style_section_label()),
        Paragraph("Why This Matters", _style_slide_title(30)),
        Paragraph("The financial estimate is only part of the story. A breach disrupts an entire business.",
                   _style_intro()),
        Spacer(1, 8),
        grid,
    ]


# === SLIDE 6: Plain-Language Summary (1 banner + 3 supports) ============

def _assessment_slide_plain_language(results):
    findings = _assessment_top_findings(results)

    # Reserve right-column width if a hero asset is present so the banner /
    # supporting findings table do not overflow under the image.
    _hero_path = (_ASX_CURRENT_BRAND or {}).get("findings_hero_path")
    _text_w = ASX_INNER_W - 320 if _hero_path else ASX_INNER_W

    parts = [
        Paragraph("PLAIN-LANGUAGE SUMMARY", _style_section_label()),
        Paragraph("What This Means for the Organisation", _style_slide_title(30)),
        Paragraph("Three findings, explained in plain language.", _style_intro()),
    ]

    if not findings:
        parts.append(Paragraph("No significant external exposure surfaced in this scan. Continue monitoring for new threats.",
                                ParagraphStyle("pl_n", fontSize=11, fontName=ASX_SANS,
                                                textColor=ASX_GREY_BODY, leading=15)))
        return parts

    # ----- Primary banner (top finding) -----
    primary = findings[0]
    banner_head_st = ParagraphStyle("pl_b_h", fontSize=14, fontName=ASX_SANS_BOLD,
                                      textColor=ASX_WHITE, leading=18)
    banner_sub_st = ParagraphStyle("pl_b_s", fontSize=10, fontName=ASX_SANS,
                                     textColor=colors.HexColor("#cbd5e1"), leading=13)

    banner_inner = [
        _asx_pill(primary["level"], _ASX_SEV_HEX[primary["level"]], font_size=11),
    ]
    banner_text = [
        Paragraph(primary["headline"], banner_head_st),
        Spacer(1, 3),
        Paragraph(primary["summary"], banner_sub_st),
    ]
    banner = Table([[banner_inner, banner_text]],
                    colWidths=[140, _text_w - 140])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ASX_NAVY_DEEP),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [8, 8, 8, 8]),
    ]))
    parts.append(banner)
    parts.append(Spacer(1, 14))

    # ----- 3 supporting findings (max 3 — primary + 2 others) -----
    sup_head_st = ParagraphStyle("pl_s_h", fontSize=12, fontName=ASX_SANS_BOLD,
                                   textColor=ASX_NAVY, leading=15)
    sup_body_st = ParagraphStyle("pl_s_b", fontSize=10, fontName=ASX_SANS,
                                   textColor=ASX_GREY_BODY, leading=14)

    # Use findings 1..3 as supports if available; if only 1 finding, use its
    # own headline as a single support entry to keep visual rhythm.
    supports = findings[1:] if len(findings) > 1 else [findings[0]]
    while len(supports) < 3:
        supports.append(None)

    rows = []
    for sup in supports:
        if sup is None:
            rows.append([Spacer(1, 4), Spacer(1, 4)])
            continue
        color = _ASX_SEV_COLOR[sup["level"]]
        rows.append([
            "",  # left coloured rule (drawn via LINEBEFORE)
            [
                Paragraph(sup["headline"], sup_head_st),
                Spacer(1, 3),
                Paragraph(sup["detail"], sup_body_st),
            ],
        ])

    sup_tbl = Table(rows, colWidths=[14, _text_w - 14])
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (1, 0), (1, -1), 14),
    ]
    for i, sup in enumerate(supports):
        if sup is None: continue
        style.append(("LINEBEFORE", (0, i), (0, i), 3, _ASX_SEV_COLOR[sup["level"]]))
    sup_tbl.setStyle(TableStyle(style))
    parts.append(sup_tbl)

    # Optional hero on the right (Kaizen-style office workers photo)
    hero = _asx_image_or_none(
        (_ASX_CURRENT_BRAND or {}).get("findings_hero_path"),
        max_width=300, max_height=430)
    if hero is None:
        return parts

    # Wrap existing parts (text) into the left column, image on the right.
    text_col = parts
    container = Table([[text_col, hero]],
                       colWidths=[ASX_INNER_W - 320, 320])
    container.setStyle(TableStyle([
        ("VALIGN", (0, 0), (0, 0), "TOP"),
        ("VALIGN", (1, 0), (1, 0), "MIDDLE"),
        ("ALIGN",  (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return [container]


# === SLIDE 7: Next Steps (full navy bg, painted by _asx_page_painter) ===

def _assessment_slide_next_steps(brand, results=None):
    # Heading is white on navy background (painted at the page level).
    label_st = ParagraphStyle("ns_lbl", fontSize=10, fontName=ASX_SANS_BOLD,
                                textColor=colors.HexColor("#7ba0c4"), leading=12,
                                spaceAfter=4)
    title_st = ParagraphStyle("ns_t", fontSize=32, fontName=ASX_SERIF,
                                textColor=ASX_WHITE, leading=36, spaceAfter=10)

    head_st = ParagraphStyle("ns_h", fontSize=15, fontName=ASX_SANS_BOLD,
                               textColor=ASX_WHITE, leading=18)
    body_st = ParagraphStyle("ns_b", fontSize=10, fontName=ASX_SANS,
                               textColor=colors.HexColor("#cbd5e1"), leading=14)

    # Promote cross-correlation rotation to step #1 when critical —
    # it's the single highest-value action by far when triple-source
    # match fires (HR harvest × SPF × known breach).
    tpc = (results or {}).get("categories", {}).get(
        "third_party_correlation", {})
    if tpc.get("status") == "completed" and tpc.get("critical_count", 0) > 0:
        susp = tpc.get("suspected_vendors") or []
        vendor_names = ", ".join(s.get("vendor", "?") for s in susp[:3])
        steps = [
            (1, "Rotate cross-matched vendor credentials TODAY",
             f"Three independent signals (Hudson Rock infostealer harvest, "
             f"SPF vendor surface, public-breach database) point at: "
             f"<b>{vendor_names}</b>. Rotate API keys, OAuth tokens, and SSO "
             "session secrets at these vendors and force MFA re-enrolment for "
             "all staff with accounts there. Audit recent login records for "
             "anomalies before assuming compromise stops here."),
            (2, "Cyber Insurance Cover",
             "Structure a tailored policy covering breach response, ransomware, business interruption, regulatory fines, and third-party liability."),
            (3, "Continuous Monitoring",
             "Cyber risk is not static. Ongoing monitoring detects new threats as the attack surface changes."),
        ]
    else:
        steps = [
            (1, "Cyber Insurance Cover",
             "Structure a tailored policy covering breach response, ransomware, business interruption, regulatory fines, and third-party liability."),
            (2, "Vulnerability Remediation",
             "Secure exposed services, patch critical issues, implement MFA, and strengthen posture &mdash; often reducing the premium in the process."),
            (3, "Continuous Monitoring",
             "Cyber risk is not static. Ongoing monitoring detects new threats as the attack surface changes."),
        ]

    def step_cell(n, h, b):
        return [
            _asx_circle_number(n, 40),
            Spacer(1, 14),
            Paragraph(h, head_st),
            Spacer(1, 6),
            Paragraph(b, body_st),
        ]

    grid = Table([[step_cell(*s) for s in steps]],
                  colWidths=[ASX_INNER_W / 3] * 3,
                  rowHeights=[260])
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), ASX_NAVY_2),
        ("LEFTPADDING", (0, 0), (-1, -1), 24),
        ("RIGHTPADDING", (0, 0), (-1, -1), 24),
        ("TOPPADDING", (0, 0), (-1, -1), 22),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
        ("INNERGRID", (0, 0), (-1, -1), 10, ASX_NAVY_DEEP),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [8, 8, 8, 8]),
    ]))

    cta_st = ParagraphStyle("ns_cta", fontSize=12, fontName=ASX_SANS,
                              textColor=ASX_WHITE, leading=16)

    return [
        Paragraph("NEXT STEPS", label_st),
        Paragraph("How We Can Help From Here", title_st),
        Spacer(1, 6),
        grid,
        Spacer(1, 14),
        Paragraph(f"To discuss cover or arrange a remediation assessment, contact your {brand['broker_label']}.",
                   cta_st),
    ]


# === SLIDE 8: Disclosures ===============================================

def _assessment_slide_disclosures(brand):
    head_st = ParagraphStyle("d_h", fontSize=24, fontName=ASX_SERIF,
                               textColor=ASX_NAVY, leading=28, spaceAfter=14)
    sub_head_st = ParagraphStyle("d_sh", fontSize=11, fontName=ASX_SANS_BOLD,
                                   textColor=ASX_NAVY, leading=14, spaceAfter=4)
    body_st = ParagraphStyle("d_b", fontSize=10, fontName=ASX_SANS,
                               textColor=ASX_GREY_BODY, leading=14, spaceAfter=10)

    cn = brand["company_name"]
    le = brand["legal_entity"]
    def rebrand(s):
        # Order matters: replace the full legal entity first so the short
        # name doesn't grab it.
        return s.replace("Phishield UMA (Pty) Ltd", le).replace("Phishield", cn)

    civil = (
        "The financial impact figures presented in this report exclude civil liability "
        "arising from contractual or common-law obligations &mdash; specifically POPIA "
        "Section 99 civil action, common-law delict, contractual indemnities, master "
        "service agreement penalties, and third-party claims. These exposures cannot be "
        "quantified from an external security assessment because they depend on contracts, "
        "customer terms, supplier liabilities, and indemnity clauses held by the "
        "organisation under assessment. Civil exposure is uncapped under POPIA Section 99 "
        "and South African common law and can materially exceed the regulatory fine "
        "figures shown. Legal counsel and the organisation's risk officer should review "
        "contractual exposures alongside this report when determining appropriate cover. "
        "Figures presented are statistical model output. Selection of cover limit is the "
        "responsibility of the insured in consultation with the broker. Phishield does "
        "not recommend a specific cover amount."
    )

    general = (
        "This report has been prepared by Phishield based on information obtained from "
        "third-party sources, publicly available data, client-provided information, "
        "automated assessment tools, and/or external service providers. While reasonable "
        "care has been taken in compiling and presenting the information contained "
        "herein, Phishield makes no representation or warranty, express or implied, as "
        "to the accuracy, completeness, reliability, or suitability of the information, "
        "findings, estimates, projections, or opinions contained in this report. The "
        "contents of this report are provided for general informational and advisory "
        "purposes only and should not be construed as legal, financial, insurance, "
        "cybersecurity, tax, investment, or professional advice. Any reliance placed on "
        "this report or the information contained herein is done entirely at the "
        "recipient's own risk. Phishield, its directors, employees, affiliates, agents, "
        "and representatives shall not be liable for any direct, indirect, incidental, "
        "consequential, or special loss, damage, claim, liability, cost, or expense "
        "arising from or connected to the use of, reliance on, or decisions made based "
        "on this report or any information contained herein. The recipient indemnifies "
        "and holds harmless Phishield, its directors, employees, affiliates, agents, "
        "and representatives against any claims, actions, proceedings, losses, damages, "
        "or liabilities arising from the use of this report, reliance on its contents, "
        "or the implementation or non-implementation of any recommendations or findings "
        "contained herein. This report reflects information and conditions as at the "
        "date of issue only and may not reflect subsequent developments or changes in "
        "circumstances. Phishield accepts no obligation to update or revise this report "
        "after issuance."
    )

    return [
        Paragraph("Disclosures", head_st),
        Paragraph("Civil Liability Disclosure", sub_head_st),
        Paragraph(rebrand(civil), body_st),
        Paragraph("General Disclosure &amp; Indemnity", sub_head_st),
        Paragraph(rebrand(general), body_st),
    ]


# === ASSEMBLER ==========================================================

def _build_assessment_pdf(results: dict) -> bytes:
    """Build the 8-slide Cyber Security Assessment / Executive Summary Deck.

    Brand-driven: company name, FSP entity, broker label, logo and hero
    images all come from brand_assets/brand.json + the image files alongside
    it. To re-brand for a different company, edit brand.json and swap the
    image assets — no code change required."""
    global _ASX_CURRENT_BRAND
    _ASX_CURRENT_BRAND = _load_assessment_brand()
    brand = _ASX_CURRENT_BRAND

    buffer = io.BytesIO()
    domain    = results.get("domain_scanned", "Unknown")
    timestamp = results.get("scan_timestamp", datetime.utcnow().isoformat())

    doc = SimpleDocTemplate(
        buffer, pagesize=(ASX_PAGE_W, ASX_PAGE_H),
        rightMargin=ASX_MARGIN, leftMargin=ASX_MARGIN,
        topMargin=ASX_MARGIN - 10, bottomMargin=ASX_MARGIN - 14,
        title=f"Cyber Security Assessment — {domain}",
        author=brand["company_name"].upper(),
    )

    _ASX_NAVY_PREV_PAGE[0] = None
    story = []
    story += _assessment_slide_cover(domain, timestamp, brand);             story.append(PageBreak())
    story += _assessment_slide_score_and_kpis(results);                     story.append(PageBreak())
    story += _assessment_slide_attackers_view(results);                     story.append(PageBreak())
    story += _assessment_slide_supply_chain(results);                       story.append(PageBreak())
    story += _assessment_slide_financial_impact(results);                   story.append(PageBreak())
    story += _assessment_slide_why_this_matters();                          story.append(PageBreak())
    story += _assessment_slide_plain_language(results);                     story.append(_AsxNavyAnchor()); story.append(PageBreak())
    story += _assessment_slide_next_steps(brand, results);                  story.append(PageBreak())
    story += _assessment_slide_disclosures(brand)

    doc.build(story, onFirstPage=_asx_page_painter, onLaterPages=_asx_page_painter)
    return buffer.getvalue()


def generate_pdf(results: dict, report_type: str = "full") -> bytes:
    # New: Executive Summary Deck / Cyber Security Assessment — self-contained layout.
    if report_type == "assessment":
        return _build_assessment_pdf(results)

    buffer = io.BytesIO()
    domain    = results.get("domain_scanned", "Unknown")
    timestamp = results.get("scan_timestamp", datetime.utcnow().isoformat())
    risk_score= results.get("overall_risk_score", 0)
    risk_level= results.get("risk_level", "Unknown")
    recs      = results.get("recommendations", [])
    cats      = results.get("categories", {})

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=MARGIN, leftMargin=MARGIN,
        topMargin=20 * mm, bottomMargin=16 * mm,
        title=f"Cyber Risk Assessment — {domain}",
        author=_brand()["doc_author"],
    )

    S = build_styles()

    def hf(canvas, doc):
        _header_footer(canvas, doc, domain, timestamp)

    story = []

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("CYBER RISK ASSESSMENT REPORT", S["cover_title"]))
    story.append(Paragraph("External Passive Security Evaluation", S["cover_sub"]))
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Domain assessed:", S["body_muted"]))
    story.append(Paragraph(domain, S["cover_domain"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(f"Assessment date: {timestamp[:10]}    |    Scan time: {timestamp[11:19]} UTC", S["body_muted"]))
    story.append(Spacer(1, 8 * mm))

    # Risk score block
    rc = risk_color(risk_level)
    rb = risk_bg(risk_level)
    score_tbl = Table([
        [Paragraph(f"<b>{risk_score}</b>", ParagraphStyle("rs", fontSize=48, fontName="Helvetica-Bold",
                    textColor=rc, leading=52, alignment=TA_CENTER)),
         Paragraph(f"<b>{risk_level.upper()} RISK</b>",
                   ParagraphStyle("rl", fontSize=20, fontName="Helvetica-Bold",
                                  textColor=rc, leading=24, alignment=TA_LEFT)),
        ],
        [Paragraph("out of 1000", ParagraphStyle("ou", fontSize=9, textColor=C_GREY_3,
                    alignment=TA_CENTER)), ""],
    ], colWidths=[50 * mm, INNER_W - 50 * mm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), rb),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("SPAN",          (1, 0), (1, 1)),
        ("ROUNDEDCORNERS",(0, 0), (-1, -1), [6, 6, 6, 6]),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 5 * mm))

    # Gauge
    story.append(make_risk_gauge(risk_score))
    story.append(Spacer(1, 6 * mm))

    # Colour glossary legend
    story.append(Paragraph("<b>Risk Indicator Legend</b>", S["body_muted"]))
    story.append(Spacer(1, 1 * mm))
    story.append(_build_legend(S))
    story.append(Spacer(1, 3 * mm))

    # Key terms glossary
    glossary_style = ParagraphStyle("glossary", fontSize=7, fontName="Helvetica",
                                     textColor=C_GREY_4, leading=9)
    story.append(Paragraph(
        "<b>Key Terms:</b> CVE = publicly catalogued security vulnerability | "
        "CVSS = severity score (0–10, higher = more dangerous) | "
        "EPSS = probability of exploitation in next 30 days | "
        "CISA KEV = confirmed actively exploited by attackers | "
        "RSI = Ransomware Susceptibility Index | "
        "FAIR = Factor Analysis of Information Risk (financial modelling methodology) | "
        "WAF = Web Application Firewall | MFA = Multi-Factor Authentication | "
        "RDP = Remote Desktop Protocol",
        glossary_style))
    story.append(Spacer(1, 4 * mm))

    # Executive summary table
    story.append(Paragraph("<b>Executive Summary</b>", S["cat_title"]))
    story.append(Spacer(1, 2 * mm))
    story.append(build_summary_table(results, S))

    # ── Vulnerability Posture + Attacker's View (page 2) ────────────────────
    story.append(PageBreak())
    story += _build_vulnerability_posture(results, S)
    story.append(Spacer(1, 4 * mm))
    story += _build_attackers_view(results, S)
    story += origin_discovery_block(results.get("categories", {}), S,
                                    silent_when_absent=True)

    # Breach history, tiered. The broker tier gets the condensed block (verdict,
    # when, what, why) because it is priced on this; the full report carries the
    # complete card further down in Exposure & Reputation.
    if report_type == "summary":
        story += breach_intel_compact(results.get("categories", {}), S)

    # ── Report type branching ───────────────────────────────────────────────
    if report_type == "summary":
        # Financial Impact headline only
        ins_data = results.get("insurance", {})
        fin = ins_data.get("financial_impact", {})
        if fin and (fin.get("currency") or fin.get("status") == "completed"):
            fin_banner = _section_header_banner("FINANCIAL IMPACT SUMMARY", S)

            is_zar = fin.get("currency") == "ZAR"
            cur = "R" if is_zar else "$"

            if is_zar:
                eal = fin.get("estimated_annual_loss", {})
                most_likely = eal.get("most_likely", 0)
                mc = fin.get("monte_carlo", {})
                mc_t = mc.get("total", {})
                mc_p50 = mc_t.get("p50", 0)
                ins_rec = fin.get("insurance_recommendation", {})
            else:
                total = fin.get("total", {})
                most_likely = total.get("most_likely", 0)
                mc = fin.get("monte_carlo", {})
                mc_t = mc.get("total", {})
                mc_p50 = mc_t.get("p50", 0)
                ins_rec = fin.get("insurance_recommendations", {})

            # Summary banner shows the headline mode + median for a quick
            # at-a-glance figure. Full Loss Exposure Scenarios table follows.
            # No "Recommended Cover" string - cover sizing is a broker /
            # client decision (FAIS reasonable-advice compliance).
            mc_mode = mc_t.get("mode", most_likely)
            fin_text = f"Most likely annual loss: <b>{cur}&nbsp;{mc_mode:,.0f}</b>"
            if mc_p50:
                fin_text += f"  |  Median (P50): <b>{cur}&nbsp;{mc_p50:,.0f}</b>"
            # Wrap header + financial text as atomic block
            story.append(KeepTogether([
                Spacer(1, 4 * mm), fin_banner, Spacer(1, 3 * mm),
                Paragraph(fin_text, S["body"]), Spacer(1, 4 * mm)
            ]))
            # Peer Benchmarking card — also on summary so brokers see
            # the comparative posture immediately next to the financial
            # impact figure.
            story += peer_benchmark_card(results, S)

            # Loss Exposure Scenarios dedicated table — also shown on
            # summary so brokers and clients have the catastrophe view
            # before reading further. Schema-driven from loss_exposure.scenarios.
            # Cyber-risk probability cards (FAIR frequency view) + cover-sizing
            # ladder, surfaced alongside the loss exposure scenarios. Item #17.
            story += risk_probability_block(ins_data, S)
            story += loss_exposure_scenarios_block(ins_data, S)
            story += cover_ladder_block(ins_data, S)
            # Data Breach Model Assumption Notice - records-per-revenue
            # heuristic + outlier threshold for the breach component.
            story += records_assumption_disclosure(ins_data, S)
            # Civil liability disclosure - applies to both expected and
            # catastrophe loss views. FAIS-required next to financial impact.
            story += civil_liability_disclosure(S)
            # Regulatory flag audit panel - FAIS audit trail.
            story += flag_audit_panel(ins_data, S)
            # WAF / Bot-Manager Intervention Notice - rendered here on
            # summary so partial-coverage caveat sits next to the loss
            # numbers. Empty list when no intervention detected.
            story += waf_coverage_notice(results, S)
            story += estate_edge_notice(results, S)
            story += vendor_estate_notice(results, S)
            story += origin_exposure_notice(results, S)

        # ── Why This Matters — The Reality of a Cyber Breach ──────────────
        why_banner = _section_header_banner("WHY THIS MATTERS", S)

        # Financial exposure recap
        total_likely = fin.get("total", {}).get("most_likely", 0) if fin else 0
        mc_data = fin.get("monte_carlo", {}).get("total", {}) if fin else {}
        # Catastrophe figures use the severity-PML distribution (single severe
        # event), matching the cover ladder / loss-exposure table / exec-deck
        # bars - NOT the prob-weighted annual total - so every surface agrees on
        # the 1-in-250. The median stays the annual median (correct for the
        # 'estimated annual cyber loss' figure). Falls back to total.* if absent.
        mc_pml = fin.get("monte_carlo", {}).get("severity_pml", {}) if fin else {}
        mc_p50 = mc_data.get("p50", total_likely)
        mc_p99 = mc_pml.get("p99", mc_data.get("p99", 0))
        mc_p99_6 = mc_pml.get("p99_6", mc_data.get("p99_6", 0))
        cur_cta = "R" if (fin and fin.get("currency") == "ZAR") else "$"
        org_location = "a South African" if (fin and fin.get("currency") == "ZAR") else "an"

        # Count critical findings
        cred_risk = cats.get("credential_risk", {}).get("risk_level", "LOW")
        hr_employees = cats.get("hudson_rock", {}).get("compromised_employees", 0)
        ix_total = cats.get("intelx", {}).get("total_results", 0)
        dh_total = conclusive_count(cats, "dehashed", "total_entries") or 0
        hrp_critical = cats.get("high_risk_protocols", {}).get("critical_count", 0)

        # Wrap WHY THIS MATTERS header with first content block
        story.append(KeepTogether([
            Spacer(1, 4 * mm), why_banner, Spacer(1, 3 * mm),
            Paragraph("<b>Estimated Financial Exposure</b>", S["cat_title"]),
            Spacer(1, 2 * mm),
            Paragraph(
                f"Based on this assessment, the organisation faces an estimated annual cyber loss of "
                f"<b>{cur_cta} {mc_p50:,.0f}</b> (median scenario). The severity of a single severe "
                f"event could reach <b>{cur_cta} {mc_p99:,.0f}</b> (P99 severity); a catastrophic event "
                f"(the 1-in-250 severity benchmark) could reach <b>{cur_cta} {mc_p99_6:,.0f}</b>. These severity "
                f"figures are conditional on a severe event occurring and are derived from a Monte Carlo simulation of "
                f"10,000 scenarios modelling data breach, ransomware, and business interruption events "
                f"calibrated to the organisation's industry and risk profile.",
                S["body"]),
            Spacer(1, 4 * mm),
        ]))

        # The human cost of a breach
        story.append(Paragraph(
            "<b>The Reality of a Cyber Breach</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"The financial numbers only tell part of the story. When {org_location} organisation "
            "suffers a data breach, the impact extends far beyond the balance sheet:",
            S["body"]))
        story.append(Spacer(1, 2 * mm))

        # IBM 2025 SA statistics
        stat_style = S["stat"]

        stats = [
            "<b>R44.1 million</b> — the average cost of a data breach in South Africa in 2025 "
            "(IBM Cost of a Data Breach Report). Even with the 17% decline from 2024, this represents "
            "a potentially business-ending event for most SMEs.",

            "<b>241 days</b> — the average time to identify and contain a breach. For nearly 8 months, "
            "attackers may have access to systems, data, and client information before the breach "
            "is even discovered.",

            "<b>Only 35% of organisations fully recover</b> from a data breach. Of those that do recover, "
            "76% need more than 100 days to return to normal operations. During this period, business "
            "operations are disrupted, client trust is eroded, and revenue is lost.",

            "<b>Over 60% of SMBs that experience severe data loss shut down within 6 months</b> "
            "of the incident. Without adequate insurance coverage and a response plan, a single "
            "cyber event can be an existential threat to the business.",

            "<b>86% of breached organisations experience operational disruption</b> — not just data loss, "
            "but inability to process orders, serve clients, or access critical systems. Staff cannot work, "
            "deadlines are missed, and contractual obligations go unmet.",

            "<b>24 days average downtime</b> following a ransomware attack. For nearly a month, "
            "operations may be unable to continue while systems are restored, data is recovered, "
            "and forensic investigations are conducted.",
        ]
        for stat in stats:
            story.append(Paragraph(f"\u2022 {stat}", stat_style))
        story.append(Spacer(1, 4 * mm))

        # Personalised risk context
        story.append(Paragraph(
            "<b>What This Means for the Organisation</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))

        risk_paras = []
        if hr_employees > 0:
            risk_paras.append(
                f"This assessment detected <b>active credential-stealing malware (infostealer)</b> on {hr_employees} employee "
                f"device(s). This is not a historical finding — it means credentials are being stolen "
                f"<b>currently</b> and sold to criminal buyers. Without immediate intervention, a breach "
                f"is not a matter of <i>if</i>, but <i>when</i>."
            )
        if ix_total > 0:
            risk_paras.append(
                f"The assessment found <b>{ix_total} references</b> to the organisation in criminal online marketplaces (dark web). "
                f"This means stolen data associated with the business is circulating in criminal "
                f"networks where it can be purchased by anyone with malicious intent."
            )
        if dh_total > 0:
            risk_paras.append(
                f"<b>{dh_total} credential records</b> linked to the domain were found in breach "
                f"databases. These include email addresses and potentially passwords that attackers "
                f"use for automated password attacks (credential stuffing) — systematically trying stolen passwords across "
                f"multiple systems until they find one that works."
            )
        if hrp_critical > 0:
            risk_paras.append(
                f"<b>{hrp_critical} critical service(s)</b> (databases, remote access) are directly "
                f"exposed to the internet. An attacker does not need sophisticated tools to exploit "
                f"these — a simple connection attempt with stolen credentials could grant immediate "
                f"access to sensitive business data."
            )
        if cred_risk in ("CRITICAL", "HIGH"):
            risk_paras.append(
                f"Overall credential risk is classified as <b>{cred_risk}</b>. "
                f"This means there is a significantly elevated probability of unauthorised access "
                f"to systems using compromised credentials."
            )
        if not risk_paras:
            risk_paras.append(
                "This assessment identified no critical immediate threats, indicating a strong "
                "security foundation. Ongoing cyber insurance provides protection against emerging "
                "threats, zero-day exploits, and the evolving threat landscape \u2014 ensuring business "
                "continuity even when the unexpected occurs."
            )

        for para in risk_paras:
            story.append(Paragraph(f"\u2022 {para}", S["body"]))
            story.append(Spacer(1, 2 * mm))
        story.append(Spacer(1, 4 * mm))

        # Brief, masked credential examples (broker sees masked; full list with
        # passwords is the on-demand encrypted export only).
        story += cat_credential_remediation(results.get("categories", {}), S, brief=True)

        # Call to action - intentionally does NOT recommend a specific
        # cover amount. Cover sizing is a broker / client decision informed
        # by the Loss Exposure Scenarios shown above.
        story.append(Paragraph(
            "<b>Next Steps</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))

        cta_style = S["cta"]

        cta_items = [
            "<b>Cyber Insurance Coverage</b> — The Phishield broker can structure a tailored cyber "
            "insurance policy covering data breach response costs, ransomware negotiation and payment, "
            "business interruption losses, regulatory fines (POPIA Section 109 and applicable sector "
            "frameworks), and third-party liability. Selection of the appropriate cover limit should "
            "be made by the insured with the broker, informed by the Loss Exposure Scenarios shown "
            "above and the organisation's contractual exposure profile.",

            "<b>Vulnerability Remediation</b> — The vulnerabilities identified in this report can be "
            "addressed through professional remediation services. A qualified cybersecurity partner can "
            "secure exposed services, patch critical vulnerabilities, implement MFA, and strengthen "
            "the overall security posture — often reducing the insurance premium in the process.",

            "<b>Continuous Monitoring</b> — Cyber risk is not static. New vulnerabilities are discovered "
            "daily, and the attack surface changes as the business evolves. Ongoing monitoring ensures "
            "emerging threats are detected before they are exploited.",
        ]
        for item in cta_items:
            story.append(Paragraph(f"\u2022 {item}", cta_style))
        story.append(Spacer(1, 4 * mm))

        # Contact block
        story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_BLUE))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            f"<b>{_brand()['contact_text']}</b>",
            S["contact"]
        ))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            _brand()["footer_fsp_text"],
            S["fsp"]
        ))

    else:
        # ── Full report — all sections included ─────────────────────────────

        # ── WAF / Bot-Manager Intervention Notice (top-level) ──────────────
        # Surfaces here so any broker / client reading the full report
        # encounters the partial-coverage notice BEFORE reading individual
        # findings. Returns empty list when no WAF intervention detected.
        story += waf_coverage_notice(results, S)
        story += estate_edge_notice(results, S)
        story += vendor_estate_notice(results, S)
        story += origin_exposure_notice(results, S)

        # ── Insurance Analytics ─────────────────────────────────────────────
        if results.get("insurance"):
            story += section_with_first_card("INSURANCE ANALYTICS", S, cat_rsi(results, S))
            # Peer Benchmarking — surfaces peer rating + percentile rank
            # near the top so brokers see the comparative posture before
            # digging into individual checker findings.
            story += peer_benchmark_card(results, S)
            story += cat_dbi(results, S)
            story += cat_financial_impact(results.get("insurance", {}), S)
            # Loss Exposure Scenarios - dedicated headline table replacing
            # the previous Insurance Cover Recommendation card.
            story += risk_probability_block(results.get("insurance", {}), S)
            story += loss_exposure_scenarios_block(results.get("insurance", {}), S)
            story += cover_ladder_block(results.get("insurance", {}), S)
            # Data Breach Model Assumption Notice - exposes the records-
            # per-revenue heuristic driving the breach component, plus the
            # outlier threshold above which broker recalibration is needed.
            story += records_assumption_disclosure(results.get("insurance", {}), S)
            # Civil liability disclosure - required next to the cat-loss
            # numbers per FAIS reasonable-advice / appropriate-disclosure rules.
            story += civil_liability_disclosure(S)
            # Regulatory flag audit panel - FAIS audit trail showing
            # broker input vs auto-detection per flag.
            story += flag_audit_panel(results.get("insurance", {}), S)
            story += cat_risk_mitigations(results.get("insurance", {}), S)
            story += cat_remediation(results, S)
            # Scan duration profile - diagnostic primitive for SLA / quality.
            story += scan_duration_profile(results, S)

        # ── Discovery ───────────────────────────────────────────────────────
        story += section_with_first_card("DISCOVERY", S, cat_web_ranking(cats, S))

        # ── Core Security ───────────────────────────────────────────────────
        story += section_with_first_card("CORE SECURITY", S, cat_ssl(cats, S))
        story += cat_headers(cats, S)
        story += cat_waf(cats, S)
        story += cat_website(cats, S)
        story += cat_third_party_js(cats, S)

        # ── Information Security ────────────────────────────────────────────
        story += section_with_first_card("INFORMATION SECURITY", S, cat_info_disclosure(cats, S))

        # ── Email Security ──────────────────────────────────────────────────
        story += section_with_first_card("EMAIL SECURITY", S, cat_email(cats, S))
        story += cat_email_hardening(cats, S)
        story += cat_email_vendor_surface(cats, S)

        # ── Network & Infrastructure ────────────────────────────────────────
        story += section_with_first_card("NETWORK & INFRASTRUCTURE", S, cat_dns(cats, S))
        story += cat_hrp(cats, S)
        story += cat_cloud(cats, S)
        story += cat_vpn(cats, S)
        story += origin_discovery_block(cats, S)

        # ── Exposure & Reputation ───────────────────────────────────────────
        # Researched breach history leads the section: a dated, confirmed prior
        # breach is the most consequential item in it, and unlike HIBP it is
        # usually the only place a real corporate incident surfaces at all.
        _bi_card = cat_breach_intel(cats, S)
        if _bi_card:
            story += section_with_first_card("EXPOSURE & REPUTATION", S, _bi_card)
            story += cat_breaches(cats, S)
        else:
            story += section_with_first_card("EXPOSURE & REPUTATION", S, cat_breaches(cats, S))
        story += cat_dnsbl(cats, S)
        story += cat_admin(cats, S)
        story += cat_subdomains(cats, S)
        story += cat_shodan(cats, S)
        story += cat_dehashed(cats, S)
        story += cat_hudson_rock(cats, S)
        story += cat_intelx(cats, S)
        story += cat_credential_risk(cats, S)
        story += cat_credential_correlation(cats, S)
        story += cat_credential_remediation(cats, S)
        story += cat_third_party_correlation(cats, S)
        story += cat_virustotal(cats, S)
        story += cat_fraudulent_domains(cats, S)
        story += cat_related_domains(cats, S)
        story += cat_dependency_manifests(cats, S)
        story += cat_vendor_breach(cats, S)

        # ── Technology & Governance ─────────────────────────────────────────
        story += section_with_first_card("TECHNOLOGY & GOVERNANCE", S, cat_tech(cats, S))
        story += cat_domain(cats, S)
        story += cat_securitytrails(cats, S)
        story += cat_privacy_compliance(cats, S)
        story += cat_security_policy(cats, S)
        story += cat_payment(cats, S)
        story += cat_cms_plugin_sbom(cats, S)
        story += cat_glasswing(cats, S)

        # ── Compliance Framework Mapping ────────────────────────────────────
        if results.get("compliance"):
            story += section_with_first_card("COMPLIANCE FRAMEWORK MAPPING", S, cat_compliance_frameworks(results, S))

        # ── Recommendations ─────────────────────────────────────────────────
        if recs:
            # Wrap header + intro as a single KeepTogether to prevent orphan
            banner = _section_header_banner("REMEDIATION RECOMMENDATIONS", S)
            intro = Paragraph(
                "The following prioritised recommendations are derived from the findings throughout this report. "
                "Each recommendation addresses a specific vulnerability or configuration gap identified during the "
                "scan. Detailed context and per-finding guidance is provided within each section above.",
                S["body"])
            story.append(KeepTogether([Spacer(1, 4 * mm), banner, Spacer(1, 3 * mm), intro, Spacer(1, 3 * mm)]))
            for i, rec in enumerate(recs, 1):
                story.append(Paragraph(
                    f'<font name="Helvetica-Bold" color="{C_BLUE}">{i}.</font>&nbsp;&nbsp;{rec}',
                    S["rec_body"]
                ))
                story.append(Spacer(1, 2 * mm))

    # ── Disclaimer ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        "DISCLAIMER: This report is based solely on passive, external assessment of publicly observable "
        "infrastructure and does not constitute a full security audit. Results reflect point-in-time observations. "
        f"{_brand()['disclaimer_fsp_sentence']} "
        f"{_brand()['company_name']} accepts no liability for decisions made solely on the basis of this automated assessment. "
        "For insurance purposes this report must be reviewed by a qualified underwriter.",
        S["disclaimer"]
    ))

    doc.build(story, onFirstPage=hf, onLaterPages=hf)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Invoice PDF Generator
# ---------------------------------------------------------------------------

def generate_invoice_pdf(invoice: dict, line_items: list, client: dict) -> bytes:
    """Generate a professional invoice PDF in ZAR."""

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=25 * mm, bottomMargin=20 * mm,
    )

    S = {
        "title": ParagraphStyle("inv_title", fontName="Helvetica-Bold", fontSize=22, textColor=C_NAVY),
        "heading": ParagraphStyle("inv_heading", fontName="Helvetica-Bold", fontSize=12, textColor=C_NAVY),
        "normal": ParagraphStyle("inv_normal", fontName="Helvetica", fontSize=10, textColor=C_BLACK, leading=14),
        "small": ParagraphStyle("inv_small", fontName="Helvetica", fontSize=8, textColor=C_GREY_4, leading=11),
        "bold": ParagraphStyle("inv_bold", fontName="Helvetica-Bold", fontSize=10, textColor=C_BLACK),
        "right": ParagraphStyle("inv_right", fontName="Helvetica", fontSize=10, textColor=C_BLACK, alignment=TA_RIGHT),
        "right_bold": ParagraphStyle("inv_right_bold", fontName="Helvetica-Bold", fontSize=10, textColor=C_BLACK, alignment=TA_RIGHT),
        "total": ParagraphStyle("inv_total", fontName="Helvetica-Bold", fontSize=13, textColor=C_NAVY, alignment=TA_RIGHT),
    }

    story = []

    # --- Header ---
    story.append(Paragraph(_brand()["invoice_brand_name"], S["title"]))
    story.append(Paragraph(_brand()["invoice_tagline"], S["small"]))
    story.append(Spacer(1, 6 * mm))
    story.append(HRFlowable(width="100%", thickness=2, color=C_BLUE))
    story.append(Spacer(1, 6 * mm))

    # --- Invoice meta (2-column) ---
    inv_num = invoice.get("invoice_number", "")
    issue_date = invoice.get("issue_date", "")
    due_date = invoice.get("due_date", "")
    status = invoice.get("status", "draft").upper()

    meta_left = [
        Paragraph(f"<b>Invoice:</b> {inv_num}", S["normal"]),
        Paragraph(f"<b>Date:</b> {issue_date}", S["normal"]),
        Paragraph(f"<b>Due:</b> {due_date}", S["normal"]),
        Paragraph(f"<b>Status:</b> {status}", S["normal"]),
    ]
    company = client.get("company_name", "—")
    trading_as = client.get("trading_as", "")
    domain = client.get("domain", "")
    meta_right = [
        Paragraph(f"<b>Bill To:</b>", S["normal"]),
        Paragraph(company, S["bold"]),
    ]
    if trading_as:
        meta_right.append(Paragraph(f"t/a {trading_as}", S["normal"]))
    if domain:
        meta_right.append(Paragraph(domain, S["normal"]))

    # Pad lists to same length
    max_len = max(len(meta_left), len(meta_right))
    while len(meta_left) < max_len:
        meta_left.append(Paragraph("", S["normal"]))
    while len(meta_right) < max_len:
        meta_right.append(Paragraph("", S["normal"]))

    meta_data = [[meta_left[i], meta_right[i]] for i in range(max_len)]
    meta_table = Table(meta_data, colWidths=[INNER_W * 0.5, INNER_W * 0.5])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8 * mm))

    # --- Line items table ---
    header = [
        Paragraph("<b>Description</b>", S["normal"]),
        Paragraph("<b>Qty</b>", S["right_bold"]),
        Paragraph("<b>Unit Price</b>", S["right_bold"]),
        Paragraph("<b>Total</b>", S["right_bold"]),
    ]
    rows = [header]
    for item in line_items:
        rows.append([
            Paragraph(item.get("description", ""), S["normal"]),
            Paragraph(f"{item.get('quantity', 1):.0f}", S["right"]),
            Paragraph(f"R&nbsp;{item.get('unit_price', 0):,.2f}", S["right"]),
            Paragraph(f"R&nbsp;{item.get('line_total', 0):,.2f}", S["right"]),
        ])

    col_widths = [INNER_W * 0.50, INNER_W * 0.12, INNER_W * 0.19, INNER_W * 0.19]
    items_table = Table(rows, colWidths=col_widths, repeatRows=1)
    items_style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, C_GREY_2),
        ("LINEBELOW", (0, -1), (-1, -1), 1, C_NAVY),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    # Alternate row colours
    for i in range(1, len(rows)):
        if i % 2 == 0:
            items_style.append(("BACKGROUND", (0, i), (-1, i), C_GREY_1))
    items_table.setStyle(TableStyle(items_style))
    story.append(items_table)
    story.append(Spacer(1, 6 * mm))

    # --- Totals ---
    subtotal = invoice.get("subtotal", 0)
    vat_rate = invoice.get("vat_rate", 15)
    vat_amount = invoice.get("vat_amount", 0)
    total = invoice.get("total", 0)

    totals_data = [
        ["", Paragraph("Subtotal", S["right"]), Paragraph(f"R&nbsp;{subtotal:,.2f}", S["right_bold"])],
        ["", Paragraph(f"VAT ({vat_rate}%)", S["right"]), Paragraph(f"R&nbsp;{vat_amount:,.2f}", S["right_bold"])],
        ["", Paragraph("<b>TOTAL DUE</b>", S["right_bold"]), Paragraph(f"R&nbsp;{total:,.2f}", S["total"])],
    ]
    totals_table = Table(totals_data, colWidths=[INNER_W * 0.50, INNER_W * 0.25, INNER_W * 0.25])
    totals_table.setStyle(TableStyle([
        ("LINEABOVE", (1, 2), (-1, 2), 1.5, C_NAVY),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
    ]))
    story.append(totals_table)
    story.append(Spacer(1, 10 * mm))

    # --- Bank details ---
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Payment Details", S["heading"]))
    story.append(Spacer(1, 2 * mm))
    bank_info = [
        "<b>Bank:</b> First National Bank (FNB)",
        "<b>Account Name:</b> Phishield (Pty) Ltd",
        "<b>Account Number:</b> Available on request",
        "<b>Branch Code:</b> 250655",
        f"<b>Reference:</b> {inv_num}",
    ]
    for line in bank_info:
        story.append(Paragraph(line, S["normal"]))
    story.append(Spacer(1, 6 * mm))

    # --- Footer disclaimer ---
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GREY_2))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        _brand()["invoice_footer_text"],
        S["small"]
    ))

    doc.build(story)
    return buffer.getvalue()
