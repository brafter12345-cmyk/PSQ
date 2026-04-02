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
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String
from reportlab.graphics import renderPDF

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
C_NAVY      = colors.HexColor("#0f2744")
C_BLUE      = colors.HexColor("#1d4ed8")
C_BLUE_LIGHT= colors.HexColor("#dbeafe")
C_GREEN     = colors.HexColor("#16a34a")
C_GREEN_BG  = colors.HexColor("#dcfce7")
C_AMBER     = colors.HexColor("#d97706")
C_AMBER_BG  = colors.HexColor("#fef3c7")
C_RED       = colors.HexColor("#dc2626")
C_RED_BG    = colors.HexColor("#fee2e2")
C_CRITICAL  = colors.HexColor("#991b1b")
C_CRITICAL_BG = colors.HexColor("#fecaca")
C_GREY_1    = colors.HexColor("#f8fafc")
C_GREY_2    = colors.HexColor("#e2e8f0")
C_GREY_3    = colors.HexColor("#94a3b8")
C_GREY_4    = colors.HexColor("#475569")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#0f172a")

# Brief descriptions for common CVEs referenced in the protocol knowledge base
CVE_DESCRIPTIONS = {
    # FTP
    "CVE-2015-3306": "ProFTPD mod_copy — unauthenticated remote file copy/write",
    "CVE-2019-12815": "ProFTPD mod_copy — arbitrary file copy without auth",
    "CVE-2010-4221": "ProFTPD — remote stack buffer overflow (RCE)",
    # SSH
    "CVE-2024-6387": "regreSSHion — unauthenticated RCE in OpenSSH (critical)",
    "CVE-2023-48795": "Terrapin — SSH prefix truncation attack",
    "CVE-2016-20012": "OpenSSH — username enumeration via timing",
    # Telnet
    "CVE-2020-10188": "Telnetd — remote code execution via buffer overflow",
    "CVE-2011-4862": "FreeBSD telnetd — encryption key ID buffer overflow (RCE)",
    # SMTP
    "CVE-2021-3156": "Sudo heap overflow — local privilege escalation",
    "CVE-2020-28018": "Exim — use-after-free leading to RCE",
    "CVE-2011-1720": "Postfix — memory corruption via SASL",
    # POP3/IMAP
    "CVE-2021-33515": "Dovecot — STARTTLS command injection",
    "CVE-2019-11500": "Dovecot — buffer overflow in mail processing (RCE)",
    # MySQL
    "CVE-2012-2122": "MySQL — authentication bypass via timing attack",
    "CVE-2016-6662": "MySQL — remote root code execution via config file",
    "CVE-2020-14812": "MySQL Server — denial of service via optimizer",
    # RDP
    "CVE-2019-0708": "BlueKeep — unauthenticated RCE in RDP (wormable, critical)",
    "CVE-2019-1181": "DejaBlue — RDP RCE affecting newer Windows versions",
    "CVE-2019-1182": "DejaBlue — RDP RCE variant (wormable)",
    # PostgreSQL
    "CVE-2023-5868": "PostgreSQL — privilege escalation via aggregate functions",
    "CVE-2019-9193": "PostgreSQL — authenticated RCE via COPY FROM PROGRAM",
    "CVE-2023-39417": "PostgreSQL — SQL injection in extension scripts",
    # VNC
    "CVE-2006-2369": "RealVNC — authentication bypass (no password required)",
    "CVE-2019-15681": "TightVNC — heap buffer overflow (RCE)",
    # SMB
    "CVE-2017-0144": "EternalBlue — SMBv1 RCE (WannaCry, NotPetya)",
    "CVE-2020-0796": "SMBGhost — SMBv3 RCE (wormable, critical)",
    "CVE-2017-0145": "EternalRomance — SMBv1 RCE variant",
    # Redis
    "CVE-2022-0543": "Redis — Lua sandbox escape (RCE)",
    "CVE-2021-32761": "Redis — integer overflow in BITFIELD (heap corruption)",
    # Elasticsearch
    "CVE-2015-1427": "Elasticsearch — Groovy scripting RCE (unauthenticated)",
    "CVE-2014-3120": "Elasticsearch — MVEL scripting RCE",
    # MongoDB
    "CVE-2015-7882": "MongoDB — authentication bypass",
    "CVE-2013-1892": "MongoDB — nativeHelper buffer overflow (RCE)",
    # MSSQL
    "CVE-2020-0618": "SQL Server — deserialization RCE",
    "CVE-2019-1068": "SQL Server — remote code execution",
    # CouchDB
    "CVE-2017-12635": "CouchDB — privilege escalation to admin",
    "CVE-2017-12636": "CouchDB — arbitrary command execution",
    # Docker
    "CVE-2019-5736": "runc — container escape to host (critical)",
    # SNMP
    "CVE-2017-6736": "Cisco SNMP — remote code execution",
    "CVE-2002-0012": "SNMP — community string brute-force / info disclosure",
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
INNER_W = PAGE_W - 2 * MARGIN


def risk_color(risk_level: str):
    return {"Low": C_GREEN, "Medium": C_AMBER, "High": C_RED, "Critical": C_CRITICAL}.get(risk_level, C_GREY_3)


def risk_bg(risk_level: str):
    return {"Low": C_GREEN_BG, "Medium": C_AMBER_BG, "High": C_RED_BG, "Critical": C_CRITICAL_BG}.get(risk_level, C_GREY_1)


def tl_color(level: str):
    """Traffic light colour from string key."""
    return {"green": C_GREEN, "amber": C_AMBER, "red": C_RED, "crimson": C_CRITICAL, "blue": C_BLUE}.get(level, C_GREY_3)


# ---------------------------------------------------------------------------
# Custom drawing helpers
# ---------------------------------------------------------------------------

def make_traffic_circle(color, size=10):
    d = Drawing(size, size)
    d.add(Circle(size / 2, size / 2, size / 2 - 0.5,
                 fillColor=color, strokeColor=C_WHITE, strokeWidth=0.5))
    return d


def make_risk_gauge(score: int, width=INNER_W, height=16 * mm) -> Drawing:
    """Horizontal colour-banded gauge with a position marker."""
    d = Drawing(width, height)
    bar_y, bar_h = 5 * mm, 6 * mm
    zones = [
        (0,   200, C_GREEN),
        (200, 400, C_AMBER),
        (400, 600, C_RED),
        (600, 1000, C_CRITICAL),
    ]
    for start, end, col in zones:
        x = (start / 1000) * width
        w = ((end - start) / 1000) * width
        d.add(Rect(x, bar_y, w, bar_h, fillColor=col, strokeColor=None, rx=0))

    # Zone labels
    for label, x_frac in [("Low", 0.1), ("Medium", 0.3), ("High", 0.5), ("Critical", 0.75)]:
        sx = x_frac * width
        d.add(String(sx, bar_y + bar_h / 2 - 2, label,
                     fontSize=6, fillColor=C_WHITE, textAnchor="middle"))

    # Score marker (black triangle / rectangle)
    mx = (score / 1000) * width
    mx = max(2, min(mx, width - 2))
    d.add(Rect(mx - 2, bar_y - 3 * mm, 4, bar_h + 6 * mm,
               fillColor=C_BLACK, strokeColor=None))

    # Score label above marker
    d.add(String(mx, bar_y + bar_h + 3.5 * mm, str(score),
                 fontSize=7, fillColor=C_BLACK, textAnchor="middle"))
    return d


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def build_styles():
    S = {}
    base = dict(fontName="Helvetica", textColor=C_BLACK, leading=14)

    S["cover_title"] = ParagraphStyle("cover_title", fontSize=26, fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=30, spaceAfter=4)
    S["cover_sub"]   = ParagraphStyle("cover_sub",   fontSize=13, textColor=C_GREY_4,
                                       leading=18, spaceAfter=2, **{k: v for k, v in base.items() if k not in ("textColor", "leading")})
    S["cover_domain"]= ParagraphStyle("cover_domain",fontSize=18, fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=22)
    S["section_hdr"] = ParagraphStyle("section_hdr", fontSize=11, fontName="Helvetica-Bold",
                                       textColor=C_WHITE, leading=14, leftIndent=4)
    S["cat_title"]   = ParagraphStyle("cat_title",   fontSize=9,  fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=12)
    S["body"]        = ParagraphStyle("body",         fontSize=8,  leading=11, textColor=C_BLACK)
    S["body_muted"]  = ParagraphStyle("body_muted",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["issue"]       = ParagraphStyle("issue",        fontSize=7.5, leading=10, textColor=C_RED,
                                       leftIndent=8)
    S["rec_num"]     = ParagraphStyle("rec_num",      fontSize=8,  fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=11)
    S["rec_body"]    = ParagraphStyle("rec_body",     fontSize=8,  leading=11, textColor=C_BLACK,
                                       leftIndent=18, firstLineIndent=-18)
    S["footer"]      = ParagraphStyle("footer",       fontSize=6.5, textColor=C_GREY_3,
                                       alignment=TA_CENTER)
    S["disclaimer"]  = ParagraphStyle("disclaimer",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["kv_key"]      = ParagraphStyle("kv_key",       fontSize=7.5, textColor=C_GREY_4, leading=10)
    S["kv_val"]      = ParagraphStyle("kv_val",       fontSize=7.5, textColor=C_BLACK,  leading=10)
    return S


# ---------------------------------------------------------------------------
# Header / footer callback
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc, domain, timestamp):
    canvas.saveState()
    w, h = A4

    # Top bar
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 12 * mm, w, 12 * mm, fill=True, stroke=False)
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(MARGIN, h - 7 * mm, "PHISHIELD Cyber Protect  |  Risk Assessment Report")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - MARGIN, h - 7 * mm, domain)

    # Bottom bar
    canvas.setFillColor(C_GREY_2)
    canvas.rect(0, 0, w, 9 * mm, fill=True, stroke=False)
    canvas.setFillColor(C_GREY_4)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(MARGIN, 3.5 * mm,
                      "PHISHIELD UMA (Pty) Ltd  |  Authorised Financial Services Provider  |  "
                      "FSP 46418")
    canvas.drawRightString(w - MARGIN, 3.5 * mm,
                           f"Page {doc.page}  |  {timestamp[:10]}")
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------

def section_header(title: str, S: dict) -> list:
    tbl = Table([[Paragraph(f"  {title}", S["section_hdr"])]], colWidths=[INNER_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    return [Spacer(1, 4 * mm), tbl, Spacer(1, 2 * mm)]


def badge_text(text: str, bg, fg=C_WHITE) -> Table:
    """Inline coloured badge."""
    t = Table([[Paragraph(f"<b>{text}</b>", ParagraphStyle("b", fontSize=7,
               textColor=fg, leading=9))]], colWidths=[None])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ROUNDEDCORNERS", (0, 0), (-1, -1), [3, 3, 3, 3]),
    ]))
    return t


def _risk_colour_value(val: str) -> str:
    """Wrap risk keywords in value text with appropriate colour tags."""
    v = str(val)
    vl = v.lower()
    # Full-value matches (the entire cell is a risk indicator)
    if vl in ("critical risk", "critical", "yes — critical", "no — critical",
              "critical exposure", "rdp exposed", "exposed"):
        return f"<font color='#991b1b'><b>{v}</b></font>"
    if vl in ("high risk", "high"):
        return f"<font color='#dc2626'><b>{v}</b></font>"
    if vl in ("medium risk", "medium"):
        return f"<font color='#92400e'><b>{v}</b></font>"
    if vl in ("low risk", "low", "low exposure"):
        return f"<font color='#166534'><b>{v}</b></font>"
    # Keyword matches within text
    if "CRITICAL" in v or "EXPOSED" in v:
        v = v.replace("CRITICAL", "<font color='#991b1b'><b>CRITICAL</b></font>")
        v = v.replace("EXPOSED", "<font color='#991b1b'><b>EXPOSED</b></font>")
        return v
    if "CISA KEV" in v:
        v = v.replace("CISA KEV", "<font color='#991b1b'><b>CISA KEV</b></font>")
        return v
    if "HIGH RISK" in v or "HIGH" in v.upper().split("—")[0]:
        v = v.replace("HIGH RISK", "<font color='#dc2626'><b>HIGH RISK</b></font>")
        v = v.replace("HIGH", "<font color='#dc2626'><b>HIGH</b></font>")
        return v
    if "MISSING" in v or "Missing" in v:
        return f"<font color='#dc2626'>{v}</font>"
    if "DANGEROUS" in v:
        return f"<font color='#991b1b'><b>{v}</b></font>"
    if "Weak" in v or "RISK" in v:
        return f"<font color='#d97706'>{v}</font>"
    if "No —" in v or "Not detected" in v or "Not found" in v or "Not configured" in v:
        return f"<font color='#d97706'>{v}</font>"
    # Positive indicators
    if vl in ("present", "yes", "ok", "detected", "strong", "disabled"):
        return f"<font color='#16a34a'>{v}</font>"
    if v.startswith("Present") or v.startswith("Yes") or v.startswith("Supported"):
        return f"<font color='#16a34a'>{v}</font>"
    return v


def kv_row(key, value, S, alt=False):
    bg = C_GREY_1 if alt else C_WHITE
    val_str = str(value) if value is not None else "—"
    coloured_val = _risk_colour_value(val_str)
    row = [Paragraph(key, S["kv_key"]), Paragraph(coloured_val, S["kv_val"])]
    return row, bg


def _colour_issue(text: str) -> str:
    """Apply colour to an issue line based on severity keywords."""
    t = str(text)
    if t.startswith("CRITICAL:") or "CRITICAL" in t.upper()[:20]:
        return f"<font color='#991b1b'><b>{t}</b></font>"
    if "High-risk" in t or "high-risk" in t:
        return f"<font color='#dc2626'>{t}</font>"
    if "Medium-risk" in t or "medium-risk" in t:
        return f"<font color='#92400e'>{t}</font>"
    return t


def issues_cell(issues: list, S) -> Paragraph:
    if not issues:
        return Paragraph("<font color='#16a34a'>No issues detected</font>", S["body"])
    lines = "<br/>".join(f"\u2022 {_colour_issue(i)}" for i in issues[:6])
    if len(issues) > 6:
        lines += f"<br/>\u2022 \u2026and {len(issues) - 6} more"
    return Paragraph(lines, S["issue"])


# ---------------------------------------------------------------------------
# Category card builders
# ---------------------------------------------------------------------------

def _cat_table(rows, bgs, col_widths, S):
    tbl = Table(rows, colWidths=col_widths)
    style = [
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, bg in enumerate(bgs):
        style.append(("BACKGROUND", (0, i), (-1, i), bg))
        # Make separator rows very thin
        if bg == C_GREY_2:
            style.append(("TOPPADDING", (0, i), (-1, i), 0))
            style.append(("BOTTOMPADDING", (0, i), (-1, i), 0))
            style.append(("FONTSIZE", (0, i), (-1, i), 2))
    tbl.setStyle(TableStyle(style))
    return tbl


def build_cat_card(title: str, tl_col, summary: str, data_rows: list, issues: list, S) -> list:
    """
    data_rows: list of (key, value) tuples
    Returns a list of flowables for one category card.
    """
    # Title bar
    title_tbl = Table([
        [make_traffic_circle(tl_col, 10), Paragraph(f"<b>{title}</b>", S["cat_title"]),
         Paragraph(f"<i>{summary}</i>", S["body_muted"])]
    ], colWidths=[18, 80 * mm, INNER_W - 18 - 80 * mm])
    title_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND",    (0, 0), (-1, -1), C_GREY_1),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (0, 0), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 6),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    # Risk-level background colours for group headers
    _RISK_BG = {
        "critical": C_CRITICAL_BG, "high": C_RED_BG,
        "medium": C_AMBER_BG, "low": C_GREEN_BG, "info": C_BLUE_LIGHT,
    }
    _RISK_FG = {
        "critical": "#991b1b", "high": "#dc2626",
        "medium": "#92400e", "low": "#166534", "info": "#1e40af",
    }

    # Data + issues side-by-side
    rows, bgs = [], []
    alt_idx = 0
    for k, v in data_rows:
        if k == "———":
            # Separator row — thin coloured line
            r = [Paragraph("", S["kv_key"]), Paragraph("", S["kv_val"])]
            rows.append(r); bgs.append(C_GREY_2)
        elif str(k).startswith("\u25b6"):
            # Port/service group header — colour-coded by risk level
            # Format: "▶critical:Port 21/FTP" or just "▶ Port 21/FTP"
            key_text = str(k)
            risk_level = "info"
            if ":" in key_text[1:]:
                parts = key_text[1:].split(":", 1)
                risk_level = parts[0].strip().lower()
                key_text = "\u25b6 " + parts[1].strip()
            bg = _RISK_BG.get(risk_level, C_BLUE_LIGHT)
            fg = _RISK_FG.get(risk_level, "#1e40af")
            r = [Paragraph(f"<b><font color='{fg}'>{key_text}</font></b>", S["kv_key"]),
                 Paragraph(f"<b><font color='{fg}'>{v}</font></b>", S["kv_val"])]
            rows.append(r); bgs.append(bg)
            alt_idx = 0
        else:
            r, bg = kv_row(k, v, S, alt=alt_idx % 2 == 0)
            rows.append(r); bgs.append(bg)
            alt_idx += 1

    data_tbl = _cat_table(rows, bgs, [40 * mm, INNER_W - 40 * mm], S) if rows else None

    issues_para = issues_cell(issues, S)
    issues_block = Table([[issues_para]], colWidths=[INNER_W])
    issues_block.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    parts = [title_tbl]
    if data_tbl:
        parts.append(data_tbl)
    parts.append(issues_block)
    parts.append(Spacer(1, 3 * mm))
    return [KeepTogether(parts)]


# ---------------------------------------------------------------------------
# Per-category data extractors
# ---------------------------------------------------------------------------

def _tl(condition_green, condition_amber):
    if condition_green:   return C_GREEN
    if condition_amber:   return C_AMBER
    return C_RED


def cat_ssl(d, S):
    ssl = d.get("ssl", {})
    cert = ssl.get("certificate", {})
    tls  = ssl.get("tls_versions", {})
    cip  = ssl.get("cipher_suite", {})
    grade = ssl.get("grade", "?")
    col = _tl(grade in ("A+", "A", "B"), grade == "C")
    rows = [
        ("Grade",         grade),
        ("Subject",       cert.get("subject", "—")),
        ("Issuer",        cert.get("issuer", "—")),
        ("Expiry",        cert.get("expiry_date", "—")),
        ("Days left",     cert.get("days_until_expiry", "—")),
        ("TLS 1.0/1.1",   ("Enabled — RISK" if tls.get("TLS 1.0") or tls.get("TLS 1.1") else "Disabled")),
        ("TLS 1.2/1.3",   ("Supported" if tls.get("TLS 1.2") or tls.get("TLS 1.3") else "Not detected")),
        ("Cipher",        f"{cip.get('name','—')} ({'Weak' if cip.get('is_weak') else 'Strong'})"),
        ("HSTS",          "Present" if ssl.get("hsts") else "Missing"),
    ]
    return build_cat_card("SSL / TLS", col, f"Grade: {grade}", rows, ssl.get("issues", []), S)


def cat_email(d, S):
    em  = d.get("email_security", {})
    spf = em.get("spf", {})
    dm  = em.get("dmarc", {})
    dkim= em.get("dkim", {})
    mx  = em.get("mx", {})
    score = em.get("score", 0)
    col = _tl(score >= 8, score >= 5)
    rows = [
        ("SPF",    ("Present" + (" — DANGEROUS +all" if spf.get("dangerous") else "") if spf.get("present") else "Missing")),
        ("DMARC",  f"Present — policy: {dm.get('policy','—')}" if dm.get("present") else "Missing"),
        ("DKIM",   ("Found: " + ", ".join(dkim.get("selectors_found", []))) if dkim.get("selectors_found") else "Not found"),
        ("MX",     f"{len(mx.get('records', []))} record(s)"),
        ("Score",  f"{score}/10"),
    ]
    return build_cat_card("Email Authentication (SPF/DKIM/DMARC)", col, f"Score {score}/10", rows, em.get("issues", []), S)


def cat_email_hardening(d, S):
    eh   = d.get("email_hardening", {})
    mts  = eh.get("mta_sts", {})
    bimi = eh.get("bimi", {})
    dane = eh.get("dane", {})
    score= eh.get("score", 0)
    col  = _tl(score >= 7, score >= 3)
    rows = [
        ("MTA-STS", f"Present — mode: {mts.get('mode','?')}" if mts.get("present") else "Not configured"),
        ("BIMI",    "Present" + (" + VMC" if bimi.get("has_vmc") else "") if bimi.get("present") else "Not configured"),
        ("DANE/TLSA", "Present" if dane.get("present") else "Not configured"),
        ("Score",   f"{score}/10"),
    ]
    return build_cat_card("Advanced Email Hardening (MTA-STS/DANE/BIMI)", col, f"Score {score}/10", rows, eh.get("issues", []), S)


def cat_headers(d, S):
    hh    = d.get("http_headers", {})
    score = hh.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    rows  = [(name, "Present" if data.get("present") else "MISSING")
             for name, data in hh.get("headers", {}).items()]
    return build_cat_card("HTTP Security Headers", col, f"{score}% coverage", rows, hh.get("issues", []), S)


def cat_waf(d, S):
    waf = d.get("waf", {})
    col = C_GREEN if waf.get("detected") else C_AMBER
    rows = [
        ("WAF detected",  waf.get("waf_name", "None detected") if waf.get("detected") else "Not detected"),
        ("All detected",  ", ".join(waf.get("all_detected", [])) or "—"),
    ]
    return build_cat_card("WAF / DDoS Protection", col, "Detected" if waf.get("detected") else "Not detected", rows, waf.get("issues", []), S)


def cat_dns(d, S):
    dns  = d.get("dns_infrastructure", {})
    ports= dns.get("open_ports", [])
    high = [p for p in ports if p.get("risk") == "high"]
    col  = _tl(len(high) == 0 and len(ports) <= 2, len(high) == 0)
    port_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports) or "None"
    rows = [
        ("Open ports",    port_str),
        ("High-risk ports", ", ".join(f"{p['port']}/{p['service']}" for p in high) or "None"),
        ("Server header", dns.get("server_info", {}).get("Server", "—")),
        ("Reverse DNS",   dns.get("reverse_dns") or "—"),
    ]
    # Per-port exploit intel with group separators and risk-level colours
    risky = [p for p in ports if p.get("risk") in ("high", "medium", "critical")]
    for p in risky:
        rows.append(("———", "———"))  # visual separator
        risk = p.get("risk", "medium")
        risk_label = p.get("risk_level", risk.upper() + " RISK")
        rows.append((f"\u25b6{risk}:{p['port']}/{p['service']}", risk_label))
        if p.get("detected_version"):
            rows.append(("  Detected version", p["detected_version"]))
        if p.get("typical_exploits"):
            rows.append(("  Exploits", p["typical_exploits"]))
        if p.get("vuln_metrics"):
            rows.append(("  Vuln metrics", p["vuln_metrics"]))
        if p.get("notable_cves"):
            for cve_id in p["notable_cves"][:5]:
                desc = CVE_DESCRIPTIONS.get(cve_id, "")
                rows.append((f"  {cve_id}", desc if desc else "See NVD for details"))
        if p.get("insurance_risk"):
            rows.append(("  Insurance risk", p["insurance_risk"]))
        if p.get("osv_vulns"):
            osv_ids = [v.get("id", "") for v in p["osv_vulns"][:5]]
            rows.append(("  OSV.dev CVEs", ", ".join(osv_ids)))
            if len(p["osv_vulns"]) > 5:
                rows.append(("", f"...and {len(p['osv_vulns']) - 5} more"))
    return build_cat_card("DNS & Open Ports", col, f"{len(ports)} open port(s)", rows, dns.get("issues", []), S)


def cat_hrp(d, S):
    hrp  = d.get("high_risk_protocols", {})
    svcs = hrp.get("exposed_services", [])
    col  = C_CRITICAL if svcs else C_GREEN
    rows = []
    for i, s in enumerate(svcs):
        if i > 0:
            rows.append(("———", "———"))  # separator between services
        rows.append((f"\u25b6critical:{s['service']}", f"Port {s['port']} — CRITICAL EXPOSURE"))
        if s.get("known_exploits"):
            rows.append(("  Known exploits", s["known_exploits"]))
        if s.get("vuln_metrics"):
            rows.append(("  Vuln metrics", s["vuln_metrics"]))
        if s.get("notable_cves"):
            for cve_id in s["notable_cves"][:5]:
                desc = CVE_DESCRIPTIONS.get(cve_id, "")
                rows.append((f"  {cve_id}", desc if desc else "See NVD for details"))
        if s.get("insurance_risk"):
            rows.append(("  Insurance risk", s["insurance_risk"]))
        if s.get("underwriting_impact"):
            rows.append(("  Underwriting impact", s["underwriting_impact"]))
    if not rows:
        rows = [("Status", "No critical services exposed")]
    return build_cat_card("Database & Service Exposure", col,
                          f"{len(svcs)} critical exposure(s)", rows, hrp.get("issues", []), S)


def cat_cloud(d, S):
    cdn = d.get("cloud_cdn", {})
    rows = [
        ("Provider",     cdn.get("provider") or "Not detected"),
        ("CDN detected", "Yes" if cdn.get("cdn_detected") else "No"),
        ("Hosting type", cdn.get("hosting_type", "Unknown")),
        ("IP addresses", ", ".join(cdn.get("ip_addresses", [])) or "—"),
    ]
    return build_cat_card("Cloud & CDN Infrastructure", C_BLUE, cdn.get("provider") or "Unknown", rows, cdn.get("issues", []), S)


def cat_vpn(d, S):
    vpn = d.get("vpn_remote", {})
    col = C_CRITICAL if vpn.get("rdp_exposed") else (C_GREEN if vpn.get("vpn_detected") else C_AMBER)
    rows = [
        ("RDP exposed",  "YES — CRITICAL" if vpn.get("rdp_exposed") else "No"),
        ("VPN detected", vpn.get("vpn_name") or ("Detected" if vpn.get("vpn_detected") else "Not detected")),
    ]
    return build_cat_card("VPN & Remote Access", col,
                          "RDP EXPOSED" if vpn.get("rdp_exposed") else (vpn.get("vpn_name") or "None detected"),
                          rows, vpn.get("issues", []), S)


def cat_breaches(d, S):
    br    = d.get("breaches", {})
    count = br.get("breach_count", 0)
    col   = _tl(count == 0, count <= 3)
    rows  = [
        ("Total breaches",   count),
        ("Most recent",      br.get("most_recent_breach") or "N/A"),
        ("Data types exposed", ", ".join(br.get("data_classes", [])[:5]) or "—"),
    ]
    if br.get("breaches"):
        for b in br["breaches"][:4]:
            rows.append((b.get("name", "—"), f"{b.get('date','?')} — {b.get('pwn_count', 0):,} accounts"))
    return build_cat_card("Credential Exposure (HIBP)", col, f"{count} breach(es)", rows, br.get("issues", []), S)


def cat_dnsbl(d, S):
    bl  = d.get("dnsbl", {})
    all_listed = bl.get("ip_listings", []) + bl.get("domain_listings", [])
    col = C_CRITICAL if all_listed else C_GREEN
    rows = [
        ("IP blacklists",     ", ".join(bl.get("ip_listings", [])) or "Clean"),
        ("Domain blacklists", ", ".join(bl.get("domain_listings", [])) or "Clean"),
        ("Status",            "BLACKLISTED" if all_listed else "Not listed"),
    ]
    return build_cat_card("IP / Domain Reputation (DNSBL)", col,
                          "Blacklisted" if all_listed else "Clean", rows, bl.get("issues", []), S)


def cat_admin(d, S):
    adm   = d.get("exposed_admin", {})
    exposed = adm.get("exposed", [])
    col   = C_CRITICAL if adm.get("critical_count", 0) > 0 else (C_RED if adm.get("high_count", 0) > 0 else C_GREEN)
    rows  = [(e["path"], f"HTTP {e['status']} — {e['risk'].upper()}") for e in exposed[:8]] or [("Status", "No sensitive paths exposed")]
    return build_cat_card("Exposed Admin Panels & Sensitive Paths", col,
                          f"{len(exposed)} path(s) found", rows, adm.get("issues", []), S)


def cat_subdomains(d, S):
    subs  = d.get("subdomains", {})
    risky = subs.get("risky_subdomains", [])
    col   = C_AMBER if risky else C_GREEN
    rows  = [
        ("Total subdomains", subs.get("total_count", 0)),
        ("Risky subdomains", len(risky)),
        ("Risky names",      ", ".join(risky[:6]) or "None"),
    ]
    return build_cat_card("Subdomain Exposure (CT Logs)", col,
                          f"{subs.get('total_count',0)} found, {len(risky)} risky",
                          rows, subs.get("issues", []), S)


def cat_tech(d, S):
    ts   = d.get("tech_stack", {})
    eols = ts.get("eol_detected", [])
    col  = C_CRITICAL if eols else C_GREEN
    rows = [("CMS", f"{ts.get('cms',{}).get('detected','None')} {ts.get('cms',{}).get('version','') or ''}")] + \
           [(e["software"], e["note"]) for e in eols[:5]] + \
           [("Server software", sw) for sw in ts.get("server_software", [])[:3]]
    js_libs = ts.get("js_libraries", [])
    if js_libs:
        rows.append(("JS Libraries", ", ".join(f"{l['library']} {l['version']}" for l in js_libs)))
    return build_cat_card("Technology Stack & EOL Software", col,
                          f"{len(eols)} EOL component(s)", rows, ts.get("issues", []), S)


def cat_domain(d, S):
    di  = d.get("domain_intel", {})
    col = C_AMBER if di.get("issues") else C_GREEN
    age = di.get("domain_age_days")
    rows = [
        ("Registrar",      di.get("registrar") or "Unknown"),
        ("Created",        di.get("creation_date") or "Unknown"),
        ("Expires",        di.get("expiry_date") or "Unknown"),
        ("Age",            f"{age} days ({round(age/365,1)} years)" if age else "Unknown"),
        ("WHOIS privacy",  "Protected" if di.get("privacy_protected") else "Public"),
    ]
    return build_cat_card("Domain Intelligence (WHOIS)", col,
                          f"Age: {round(age/365,1)}y" if age else "Unknown",
                          rows, di.get("issues", []), S)


def cat_security_policy(d, S):
    sp  = d.get("security_policy", {})
    stxt= sp.get("security_txt", {})
    col = C_GREEN if stxt.get("present") else C_AMBER
    rows = [
        ("security.txt",   f"Found at {stxt.get('path','')}" if stxt.get("present") else "Not found"),
        ("PGP key",        "Yes" if stxt.get("has_pgp") else "No"),
        ("robots.txt",     f"Present — {sp.get('robots_txt',{}).get('disallows_count',0)} disallow rules"
                           if sp.get("robots_txt", {}).get("present") else "Not found"),
    ]
    return build_cat_card("Security Policy & Vulnerability Disclosure", col,
                          "VDP present" if stxt.get("present") else "No VDP", rows, sp.get("issues", []), S)


def cat_payment(d, S):
    pay = d.get("payment_security", {})
    col = C_CRITICAL if pay.get("self_hosted_payment_form") else (C_AMBER if pay.get("has_payment_page") and not pay.get("payment_page_https") else C_GREEN)
    rows = [
        ("Payment page",         "Detected" if pay.get("has_payment_page") else "Not found"),
        ("Payment provider",     pay.get("payment_provider") or ("Self-hosted — PCI RISK" if pay.get("self_hosted_payment_form") else "Unknown")),
        ("Page HTTPS",           "Yes" if pay.get("payment_page_https") else ("N/A" if not pay.get("has_payment_page") else "NO — CRITICAL")),
        ("Self-hosted card form", "YES — PCI risk" if pay.get("self_hosted_payment_form") else "No"),
    ]
    return build_cat_card("Payment Security (PCI)", col,
                          pay.get("payment_provider") or ("PCI Risk" if pay.get("self_hosted_payment_form") else "N/A"),
                          rows, pay.get("issues", []), S)


def cat_shodan(d, S):
    sv    = d.get("shodan_vulns", {})
    crit  = sv.get("critical_count", 0)
    high  = sv.get("high_count", 0)
    med   = sv.get("medium_count", 0)
    low   = sv.get("low_count", 0)
    total = crit + high + med + low
    col   = C_CRITICAL if crit > 0 else (C_RED if high > 0 else (C_AMBER if med > 0 else C_GREEN))
    source = "Full API" if sv.get("data_source") == "shodan_full_api" else "InternetDB"
    summary = f"{total} CVE(s)" if total > 0 else "Clean"

    rows = [
        ("IP scanned",   sv.get("ip") or "—"),
        ("Data source",  source),
        ("Total CVEs",   total),
        ("Breakdown",    f"Critical: {crit}  |  High: {high}  |  Medium: {med}  |  Low: {low}"),
        ("Open ports",   ", ".join(str(p) for p in sv.get("open_ports", [])) or "—"),
    ]
    if sv.get("os"):
        rows.append(("OS", sv["os"]))
    if sv.get("org"):
        rows.append(("Organization", sv["org"]))
    if sv.get("isp"):
        rows.append(("ISP", sv["isp"]))
    if sv.get("asn"):
        rows.append(("ASN", sv["asn"]))
    if sv.get("tags"):
        rows.append(("Tags", ", ".join(sv["tags"])))

    # Service banners (full API)
    for svc in sv.get("services", [])[:6]:
        port_label = f"Port {svc.get('port', '?')}/{svc.get('transport', 'tcp')}"
        product = svc.get("product", "")
        version = svc.get("version", "")
        rows.append((port_label, f"{product} {version}".strip() or "—"))

    # Exploit maturity summary
    wpn = sv.get("weaponized_count", 0)
    poc = sv.get("poc_public_count", 0)
    if wpn > 0 or poc > 0:
        rows.append(("Exploit maturity", f"Weaponized: {wpn}  |  PoC Public: {poc}  |  Theoretical: {max(0, total - wpn - poc)}"))

    # Detailed CVE rows
    for cve in sv.get("cves", [])[:8]:
        sev = cve.get("severity", "unknown").upper()
        cvss = cve.get("cvss_score", 0)
        epss = cve.get("epss_score", 0)
        maturity = cve.get("exploit_maturity", "theoretical").upper()
        kev = " | CISA KEV" if cve.get("in_kev") else ""
        desc = cve.get("description", "")
        cve_id = cve.get("cve_id", "")
        epss_str = f" | EPSS {epss*100:.0f}%" if epss else ""

        # CVE header row with colour coding
        rows.append(("———", "———"))
        rows.append((f"\u25b6{sev.lower()}:{cve_id}",
                      f"{sev} | CVSS {cvss}{epss_str}{kev} | {maturity}"))

        # Description on separate row — full text wraps in PDF cell
        if desc:
            rows.append(("  Description", desc))

    return build_cat_card(f"CVE / Known Vulnerabilities (Shodan {source})", col, summary, rows, sv.get("issues", []), S)


def cat_dehashed(d, S):
    dh     = d.get("dehashed", {})
    status = dh.get("status", "completed")
    total  = dh.get("total_entries", 0)
    col    = (C_CRITICAL if total > 50 else C_RED if total > 10 else
              C_AMBER if total > 0 else (C_BLUE if status == "no_api_key" else C_GREEN))
    is_error = status == "error"
    summary = ("No API key" if status == "no_api_key" else
               "API unavailable" if is_error else
               f"{total} records" if total > 0 else "Clean")
    if is_error:
        col = C_BLUE  # Info colour, not red
    status_text = ("API key not configured" if status == "no_api_key" else
                   "API endpoint unavailable — check subscription" if is_error else
                   "Completed")
    rows = [
        ("Status",        status_text),
        ("Total records", total),
        ("Unique emails", dh.get("unique_emails", 0)),
        ("Passwords in leaks", "Yes — CRITICAL" if dh.get("has_passwords") else "No"),
    ]
    if dh.get("sample_emails"):
        rows.append(("Affected emails", " | ".join(dh["sample_emails"][:5])))
    if dh.get("breach_sources"):
        rows.append(("Breach sources", " | ".join(dh["breach_sources"][:8])))
    # Show individual breach records
    details = dh.get("breach_details", [])
    if details:
        rows.append(("", ""))
        rows.append(("BREACH DETAILS", ""))
        for i, d in enumerate(details[:10]):
            pw_flag = " [PASSWORD EXPOSED]" if d.get("has_password") else (" [HASH EXPOSED]" if d.get("has_hash") else "")
            user_str = f" (user: {d['username']})" if d.get("username") else ""
            rows.append((f"  {d.get('database', 'Unknown')}", f"{d.get('email', 'N/A')}{user_str}{pw_flag}"))
        if len(details) > 10:
            rows.append(("", f"...and {len(details) - 10} more records"))
    # Remediation advice
    if total > 0:
        rows.append(("", ""))
        rows.append(("REMEDIATION", ""))
        rows.append(("  1. Password resets", "Force password resets for all identified email addresses across all company systems"))
        rows.append(("  2. MFA enforcement", "Enable multi-factor authentication on all accounts, especially those with exposed credentials"))
        rows.append(("  3. Credential monitoring", "Enroll in continuous breach monitoring to detect future exposures"))
        if dh.get("has_passwords"):
            rows.append(("  4. Password audit", "CRITICAL: Plaintext passwords found — audit all systems for password reuse immediately"))
    return build_cat_card("Dehashed Credential Leaks", col, summary, rows, dh.get("issues", []), S)


def cat_hudson_rock(d, S):
    hr = d.get("hudson_rock", {})
    employees = hr.get("compromised_employees", 0)
    users = hr.get("compromised_users", 0)
    third = hr.get("third_party_exposures", 0)
    total = employees + users
    col = C_CRITICAL if employees > 0 else (C_RED if users > 0 else (C_AMBER if third > 0 else C_GREEN))
    summary = f"{total} compromised" if total > 0 else ("Third-party exposure" if third > 0 else "Clean")
    rows = [
        ("Compromised employees", f"{employees}" + (" — ACTIVE INFOSTEALER" if employees > 0 else "")),
        ("Compromised users", users),
        ("Third-party exposures", third),
    ]
    if employees > 0:
        rows.append(("", ""))
        rows.append(("INTERPRETATION", "Employee devices are ACTIVELY infected with infostealer malware (Raccoon, RedLine, Vidar). "
                      "Credentials are being exfiltrated in real-time and sold on dark web markets. "
                      "Immediate incident response required: isolate devices, force password resets, engage forensics."))
    elif third > 0:
        rows.append(("", ""))
        rows.append(("INTERPRETATION", "Third-party supply chain exposure detected. A vendor or partner connected to this domain "
                      "has compromised credentials. Review shared access and enforce MFA on all integrations."))
    elif total == 0 and third == 0:
        rows.append(("", ""))
        rows.append(("INTERPRETATION", "No active infostealer infections detected on employee or user devices. "
                      "This indicates healthy endpoint security posture."))

    rows.append(("", ""))
    rows.append(("WHAT THIS MEANS", ""))
    if employees > 0:
        rows.append(("", "Infostealer malware (such as RedLine, Raccoon, or Vidar) has been detected on devices "
                      "belonging to employees of this organisation. This type of malware silently runs in the background "
                      "and captures everything — saved passwords from web browsers, banking credentials, email logins, "
                      "VPN access details, and even session cookies that allow attackers to bypass MFA. "
                      "The stolen data is automatically uploaded to criminal servers and sold within hours. "
                      "This is not a historical breach — it indicates CURRENT, ACTIVE compromise."))
    elif third > 0:
        rows.append(("", "A third-party vendor or partner connected to this organisation has been found in infostealer databases. "
                      "This means a supplier, contractor, or service provider who interacts with your systems has had their "
                      "credentials stolen. Attackers frequently use compromised vendor access as a backdoor into larger "
                      "organisations (supply chain attacks). Review all shared access and API integrations with external partners."))
    else:
        rows.append(("", "No infostealer infections were detected. This check scans a database of over 34 million compromised "
                      "devices worldwide. A clean result means no employee or user devices associated with this domain "
                      "appear in known infostealer databases. This is a positive security indicator."))
    return build_cat_card("Infostealer Detection (Hudson Rock)", col, summary, rows, hr.get("issues", []), S)


def cat_intelx(d, S):
    ix = d.get("intelx", {})
    if ix.get("status") == "no_api_key":
        return []
    total = ix.get("total_results", 0)
    darkweb = ix.get("darkweb_count", 0)
    pastes = ix.get("paste_count", 0)
    leaks = ix.get("leak_count", 0)
    col = C_CRITICAL if darkweb > 0 else (C_RED if pastes > 5 else (C_AMBER if total > 0 else C_GREEN))
    summary = f"{total} result(s)" if total > 0 else "Clean"
    rows = [
        ("Total references", total),
        ("Dark web mentions", f"{darkweb}" + (" — ACTIVE TRADING" if darkweb > 0 else "")),
        ("Paste site mentions", pastes),
        ("Leak database entries", leaks),
    ]
    # Add recent findings
    recent = ix.get("recent_results", [])
    if recent:
        rows.append(("", ""))
        rows.append(("RECENT FINDINGS", ""))
        for rec in recent[:8]:
            rows.append((f"  {rec.get('date', '')}", f"{rec.get('name', 'Unknown')} ({rec.get('media', '')})"))
    # Plain-English interpretation
    rows.append(("", ""))
    rows.append(("WHAT THIS MEANS", ""))
    if darkweb > 0:
        rows.append(("", f"We found {darkweb} mention(s) of this domain on dark web criminal forums. "
                      "This means stolen data (login credentials, personal information, or internal documents) "
                      "associated with your organisation is actively being bought and sold by cybercriminals. "
                      "This is a strong indicator of elevated cyber risk and potential for targeted attacks."))
        rows.append(("", ""))
        rows.append(("RECOMMENDED ACTION", "1. Immediately force password resets for all staff accounts. "
                      "2. Enable multi-factor authentication (MFA) on all systems. "
                      "3. Engage a forensic investigator to determine the source of the leak. "
                      "4. Notify affected individuals as required under POPIA Section 22."))
    elif total > 0:
        rows.append(("", f"We found {total} reference(s) to this domain in dark web leak databases. "
                      "These entries are typically 'infostealer logs' — records created when malware on someone's "
                      "computer silently captures everything they type, including passwords and banking details. "
                      "The stolen data is then packaged and uploaded to criminal databases where it can be "
                      "purchased by other attackers."))
        rows.append(("", ""))
        rows.append(("", "In simple terms: someone who has (or had) login access to your systems had their "
                      "personal device infected with spyware. The passwords they used for your systems may now "
                      "be in criminal hands."))
        rows.append(("", ""))
        rows.append(("RECOMMENDED ACTION", "1. Force password resets for all staff, especially those using personal devices. "
                      "2. Enable MFA — even if passwords are stolen, MFA prevents unauthorised access. "
                      "3. Consider endpoint security solutions (antivirus, EDR) for all devices accessing company systems. "
                      "4. Educate staff about the risks of downloading unverified software."))
    else:
        rows.append(("", "No references to this domain were found on dark web forums, paste sites, or leak databases. "
                      "This is a positive indicator — there is no evidence of stolen credentials being traded online."))
    return build_cat_card("Dark Web Monitoring (IntelX)", col, summary, rows, ix.get("issues", []), S)


def cat_credential_risk(d, S):
    cr = d.get("credential_risk", {})
    if not cr or not cr.get("risk_level"):
        return []
    level = cr.get("risk_level", "LOW")
    col = C_CRITICAL if level == "CRITICAL" else (C_RED if level == "HIGH" else (C_AMBER if level == "MEDIUM" else C_GREEN))
    rows = [
        ("Overall Risk Level", level),
        ("Risk Score", f"{cr.get('risk_score', 100)}/100"),
        ("Active Compromise", "YES — IMMEDIATE ACTION REQUIRED" if cr.get("active_compromise") else "No"),
    ]
    # Factors
    factors = cr.get("factors", [])
    if factors:
        rows.append(("", ""))
        rows.append(("RISK FACTORS", ""))
        for f in factors:
            rows.append(("", f))
    # Summary + plain English
    summary_text = cr.get("summary", "")
    if summary_text:
        rows.append(("", ""))
        rows.append(("ASSESSMENT", summary_text))
    rows.append(("", ""))
    rows.append(("WHAT THIS MEANS", ""))
    if level == "CRITICAL":
        rows.append(("", "One or more employee devices are actively infected with credential-stealing malware. "
                      "This is the highest severity finding — attackers have real-time access to stolen passwords "
                      "and can log into your systems at any time. Treat this as an active security incident."))
    elif level == "HIGH":
        rows.append(("", "Staff credentials (usernames and passwords) have been found in recent data breaches. "
                      "While these may have been changed since the breach, attackers routinely use stolen passwords "
                      "to attempt access to other systems (credential stuffing). The risk of unauthorised access "
                      "is significantly elevated."))
    elif level == "MEDIUM":
        rows.append(("", "Historical credential exposure has been detected in older data breaches. "
                      "The risk is moderate — passwords may have been changed since the breach, but "
                      "organisations with poor password hygiene or no MFA remain vulnerable."))
    else:
        rows.append(("", "No significant credential exposure detected. This is a positive indicator of "
                      "good security practices. Continue monitoring and maintain MFA enforcement."))
    # Enriched breach timeline
    enriched = d.get("dehashed", {}).get("enriched_sources", [])
    if enriched:
        rows.append(("", ""))
        rows.append(("BREACH SOURCE TIMELINE", ""))
        for src in enriched:
            pw_flag = " [PASSWORDS EXPOSED]" if src.get("passwords_in_breach") else ""
            verified = " [Verified]" if src.get("verified") else ""
            data = ", ".join(src.get("data_exposed", [])[:4]) if src.get("data_exposed") else "Unknown"
            rows.append((f"  {src.get('name', 'Unknown')}", f"Date: {src.get('breach_date', 'Unknown')}{pw_flag}{verified} | Data: {data}"))
    return build_cat_card("Credential Risk Assessment", col, level, rows, [], S)


def cat_virustotal(d, S):
    vt     = d.get("virustotal", {})
    status = vt.get("status", "completed")
    mal    = vt.get("malicious_count", 0)
    sus    = vt.get("suspicious_count", 0)
    col    = (C_CRITICAL if mal > 3 else C_RED if mal > 0 else
              C_AMBER if sus > 0 else (C_BLUE if status == "no_api_key" else C_GREEN))
    summary = ("No API key" if status == "no_api_key" else
               f"{mal} malicious" if mal > 0 else
               f"{sus} suspicious" if sus > 0 else "Clean")
    harmless = vt.get("harmless_count", 0)
    undetected = vt.get("undetected_count", 0)
    total_engines = mal + sus + harmless + undetected
    rep = vt.get("reputation", 0)

    # Build interpretation text
    if status == "no_api_key":
        interp = "VirusTotal API key not configured — unable to check domain reputation."
    elif mal > 3:
        interp = f"CRITICAL: {mal} of {total_engines} security engines flagged this domain as malicious. Indicates active malware hosting, phishing, or compromise. Immediate investigation required."
    elif mal > 0:
        interp = f"WARNING: {mal} engine(s) flagged this domain as malicious. May indicate historical compromise or false positive. Review flagging engines below for context."
    elif sus > 0:
        interp = f"CAUTION: {sus} engine(s) flagged this domain as suspicious. No confirmed malicious activity but warrants monitoring."
    elif harmless > 50:
        interp = f"CLEAN: {harmless} of {total_engines} engines confirmed harmless. Strong positive reputation with no malicious indicators detected."
    else:
        interp = f"No malicious or suspicious detections across {total_engines} security engines. Domain has a clean reputation."

    # Add reputation context
    if rep > 0:
        interp += f" Community reputation score is positive ({rep})."
    elif rep < 0:
        interp += f" Community reputation score is negative ({rep}) — users have flagged concerns."

    rows = [
        ("INTERPRETATION",       interp),
        ("",                     ""),
        ("Malicious detections", f"{mal} of {total_engines} engines"),
        ("Suspicious detections", f"{sus} of {total_engines} engines"),
        ("Harmless",             harmless),
        ("Undetected",           undetected),
        ("Community reputation", rep),
        ("Community votes",      f"Harmless: {vt.get('harmless_votes', 0)}  |  Malicious: {vt.get('malicious_votes', 0)}"),
    ]
    if vt.get("popularity_rank"):
        rows.append(("Popularity rank", f"#{vt['popularity_rank']:,}"))
    if vt.get("categories"):
        rows.append(("Categories", " | ".join(list(vt["categories"].values())[:5])))
    for eng in vt.get("flagging_engines", [])[:5]:
        rows.append((eng.get("engine", ""), f"{eng.get('category', '')} — {eng.get('result', '')}"))
    return build_cat_card("VirusTotal Reputation", col, summary, rows, vt.get("issues", []), S)


def cat_securitytrails(d, S):
    st     = d.get("securitytrails", {})
    status = st.get("status", "completed")
    assoc  = st.get("associated_count", 0)
    col    = C_AMBER if assoc > 50 else (C_BLUE if status == "no_api_key" else C_GREEN)
    summary = ("No API key" if status == "no_api_key" else
               f"{assoc} associated" if assoc > 0 else "Info")
    rows = [
        ("Status",             "API key not configured" if status == "no_api_key" else status),
        ("A records",          ", ".join(st.get("a_records", [])) or "—"),
        ("MX records",         ", ".join(st.get("mx_records", [])) or "—"),
        ("NS records",         ", ".join(st.get("ns_records", [])) or "—"),
        ("Associated domains", assoc),
    ]
    if st.get("alexa_rank"):
        rows.append(("Alexa rank", f"#{st['alexa_rank']:,}"))
    if st.get("associated_domains"):
        rows.append(("Top associated", " | ".join(st["associated_domains"][:5])))
    return build_cat_card("DNS Intelligence (SecurityTrails)", col, summary, rows, st.get("issues", []), S)


def cat_privacy_compliance(d, S):
    pc    = d.get("privacy_compliance", {})
    pct   = pc.get("compliance_pct", 0)
    found = pc.get("policy_found", False)
    col   = C_GREEN if pct >= 80 else (C_AMBER if pct >= 50 else (C_RED if found else C_CRITICAL))
    summary = f"{pct}%" if found else "Not found"
    rows = [
        ("Policy found", "Yes" if found else "No — compliance risk"),
    ]
    if found:
        rows.append(("Compliance score", f"{pct}%"))
        if pc.get("sections_found"):
            rows.append(("Sections present", " | ".join(pc["sections_found"])))
        if pc.get("sections_missing"):
            rows.append(("Sections missing", " | ".join(pc["sections_missing"])))
    return build_cat_card("Privacy Policy Compliance", col, summary, rows, pc.get("issues", []), S)


def _finding_colour(text: str) -> str:
    """Return hex colour based on finding severity keywords."""
    tl = text.lower()
    if "critical" in tl:
        return "#dc2626"
    if any(kw in tl for kw in ("high-risk", "missing", "not enforced", "not enabled",
                                "no spf", "no dmarc", "no dkim", "exposed", "no waf")):
        return "#f97316"
    if any(kw in tl for kw in ("medium-risk", "no modern tls", "hsts", "listed")):
        return "#eab308"
    return "#64748b"


def cat_compliance_frameworks(data, S):
    """Render compliance framework mapping section."""
    compliance = data.get("compliance", {})
    if not compliance:
        return []

    story = []
    for framework, fw_data in compliance.items():
        pct = fw_data.get("overall_pct", 0)
        col = C_GREEN if pct >= 75 else (C_AMBER if pct >= 50 else C_RED)
        rows = []
        for ctrl_name, ctrl in fw_data.get("controls", {}).items():
            status_str = ctrl.get("status", "no_data").upper()
            status_col = {"PASS": "#16a34a", "PARTIAL": "#d97706", "FAIL": "#dc2626", "NO_DATA": "#64748b"}.get(status_str, "#64748b")
            rows.append((ctrl_name, f"<font color='{status_col}'><b>{status_str}</b></font> — {ctrl.get('description', '')}"))
            for finding in ctrl.get("findings", [])[:3]:
                fc = _finding_colour(finding)
                rows.append(("", f"  <font color='{fc}'>↳ {finding[:120]}</font>"))
        story += build_cat_card(f"{framework}", col, f"{pct}% aligned", rows, [], S)
    return story


def cat_website(d, S):
    ws    = d.get("website_security", {})
    score = ws.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    ck    = ws.get("cookies", {})
    rows  = [
        ("HTTPS enforced", "Yes" if ws.get("https_enforced") else "No"),
        ("Mixed content",  "Detected" if ws.get("mixed_content") else "None"),
        ("CMS",            f"{ws.get('cms',{}).get('detected','None')} {ws.get('cms',{}).get('version','') or ''}"),
        ("Cookie Secure",  "OK" if ck.get("secure", True) else "Issues"),
        ("Cookie HttpOnly","OK" if ck.get("httponly", True) else "Issues"),
    ]
    return build_cat_card("Website Security", col, f"{score}%", rows, ws.get("issues", []), S)


def cat_web_ranking(d, S):
    wr = d.get("web_ranking", {})
    rank = wr.get("rank")
    # Support both scanner data formats (new format uses "ranked", old uses "in_list"/"score")
    if wr.get("ranked") is not None:
        col = C_GREEN if wr.get("ranked") else C_AMBER
        rows = [
            ("Ranked",      "Yes" if wr.get("ranked") else "Not in top 1M"),
            ("Position",    f"#{rank:,}" if rank else "—"),
            ("Popularity",  wr.get("popularity", "Unranked")),
            ("Rank Band",   wr.get("rank_label", "Unranked")),
        ]
        return build_cat_card("Web Ranking (Tranco)", col, wr.get("rank_label", "Unranked"), rows, wr.get("issues", []), S)
    else:
        score = wr.get("score", 30)
        col = _tl(score >= 70, score >= 40)
        rows = [
            ("Tranco Rank", f"#{rank:,}" if rank else "Not in top 1M"),
            ("In List", "Yes" if wr.get("in_list") else "No"),
            ("Score", f"{score}/100"),
        ]
        return build_cat_card("Web Ranking (Tranco)", col,
                              f"#{rank:,}" if rank else "Unranked",
                              rows, wr.get("issues", []), S)


def cat_info_disclosure(d, S):
    info = d.get("info_disclosure", {})
    score = info.get("score", 100)
    col = _tl(score >= 90, score >= 60)
    exposed = info.get("exposed_paths", [])
    rows = [("Exposed Paths", str(len(exposed)))]
    for p in exposed[:5]:
        rows.append((p.get("path", ""), f"{p.get('risk_level','').upper()} — {p.get('description','')}"))
    if len(exposed) > 5:
        rows.append(("...", f"+{len(exposed)-5} more"))
    return build_cat_card("Information Disclosure", col, f"{score}%",
                          rows, info.get("issues", []), S)


def cat_fraudulent_domains(d, S):
    fd     = d.get("fraudulent_domains", {})
    found  = fd.get("fraudulent_domains_found", 0)
    col    = C_CRITICAL if found > 3 else (C_RED if found > 0 else C_GREEN)
    rows   = [
        ("Variants checked",  fd.get("variants_checked", 0)),
        ("Lookalikes found",  found),
    ]
    for dom in fd.get("domains", [])[:5]:
        rows.append((dom.get("type", "lookalike"), f"{dom.get('domain','')} ({dom.get('cert_issuer','')})"))
    return build_cat_card("Fraudulent Domains (Typosquat)", col, f"{found} found", rows, fd.get("issues", []), S)


def cat_rsi(results, S):
    """RSI (Ransomware Susceptibility Index) card for PDF — insurance analytics."""
    ins = results if "rsi" in results else results.get("insurance", {})
    rsi = ins.get("rsi", {})
    score = rsi.get("rsi_score", 0)
    col = C_CRITICAL if score >= 0.75 else (C_RED if score >= 0.50 else (C_AMBER if score >= 0.25 else C_GREEN))
    rows = [
        ("RSI Score", f"{score:.3f} / 1.000"),
        ("Risk Label", rsi.get("risk_label", "Unknown")),
        ("Base Score", f"{rsi.get('base_score', 0):.3f}"),
        ("Industry", f"{rsi.get('industry', 'other').capitalize()} (×{rsi.get('industry_multiplier', 1.0)})"),
        ("Size Multiplier", f"×{rsi.get('size_multiplier', 1.0)}"),
    ]
    for f in rsi.get("contributing_factors", [])[:8]:
        rows.append((f"  P{f['priority']}: {f['factor']}", f"+{f['impact']:.2f}"))
    return build_cat_card("Ransomware Susceptibility Index (RSI)", col,
                          f"{score:.2f} — {rsi.get('risk_label', '')}",
                          rows, [], S)


def cat_dbi(results, S):
    """Data Breach Index card for PDF — insurance analytics."""
    ins = results if "dbi" in results else results.get("insurance", {})
    dbi = ins.get("dbi", {})
    score = dbi.get("dbi_score", 50)
    col = _tl(score >= 80, score >= 40)
    rows = [("DBI Score", f"{score}/{dbi.get('max_score', 100)} — {dbi.get('label', '')}")]
    for key, comp in dbi.get("components", {}).items():
        rows.append((key.replace("_", " ").capitalize(), f"{comp.get('value', '')} ({comp.get('points', 0)}/{comp.get('max', 0)} pts)"))
    return build_cat_card("Data Breach Index (DBI)", col,
                          f"{score}/100 — {dbi.get('label', '')}",
                          rows, [], S)


def cat_remediation(results, S):
    """Remediation Roadmap card for PDF — insurance analytics."""
    ins = results if "remediation" in results else results.get("insurance", {})
    rem = ins.get("remediation", {})
    steps = rem.get("steps", [])
    if not steps:
        return []
    savings = rem.get("total_potential_savings", 0)
    col = C_BLUE
    cur = "R" if ins.get("financial_impact", {}).get("currency") == "ZAR" else "$"

    rows = [
        ("Current RSI", f"{rem.get('current_rsi', 0):.3f}"),
        ("Projected RSI (after fixes)", f"{rem.get('simulated_rsi', 0):.3f}"),
        ("Total Potential Savings", f"{cur} {savings:,.0f}/year"),
        ("", ""),
    ]
    for i, step in enumerate(steps[:10], 1):
        rows.append((f"#{i} (P{step['priority']})", f"{step['action']} — saves {cur} {step['annual_savings_estimate']:,.0f}/yr"))
    return build_cat_card("Remediation Roadmap — Before/After", col,
                          f"{len(steps)} steps — {cur} {savings:,.0f} savings",
                          rows, [], S)


def cat_ransomware_risk(d, S):
    rsi   = d.get("ransomware_risk", {})
    score = rsi.get("rsi_score", 0)
    label = rsi.get("rsi_label", "N/A")
    col   = (C_CRITICAL if score >= 0.8 else C_RED if score >= 0.5 else
             C_AMBER if score >= 0.25 else C_GREEN)
    rows  = [
        ("RSI Score",       f"{score} / 1.0"),
        ("Risk Level",      label),
        ("Industry",        rsi.get("industry", "Other")),
    ]
    if rsi.get("annual_revenue_zar"):
        rows.append(("Annual Revenue", f"R {rsi['annual_revenue_zar']:,.0f}"))
    for f in rsi.get("contributing_factors", [])[:5]:
        rows.append((f["factor"], f"+{f['impact']}"))
    return build_cat_card("Ransomware Susceptibility (RSI)", col, f"{score}", rows, rsi.get("issues", []), S)


def cat_data_breach_index(d, S):
    dbi   = d.get("data_breach_index", {})
    score = dbi.get("dbi_score", 0)
    label = dbi.get("dbi_label", "N/A")
    col   = (C_CRITICAL if score < 25 else C_RED if score < 50 else
             C_AMBER if score < 75 else C_GREEN)
    rows  = [
        ("DBI Score",              f"{score} / 100"),
        ("Risk Level",             label),
        ("Breach Count",           dbi.get("breach_count", 0)),
        ("Most Recent Breach",     dbi.get("most_recent_breach") or "None"),
        ("Sensitive Data Exposed", "Yes" if dbi.get("has_sensitive_data") else "No"),
        ("Credential Leaks",       f"{dbi.get('credential_leaks', 0):,}"),
    ]
    return build_cat_card("Data Breach Index (DBI)", col, f"{score}/100", rows, dbi.get("issues", []), S)


def cat_financial_impact(d, S):
    fin = d.get("financial_impact", {})
    # Accept ZAR results (currency key present) or legacy completed status
    if not fin or (not fin.get("currency") and fin.get("status") != "completed"):
        return build_cat_card("Financial Impact (FAIR Model)", C_BLUE, "N/A",
                              [("Status", "Revenue not provided — skipped")], [], S)

    is_zar = fin.get("currency") == "ZAR"
    cur    = "R" if is_zar else "$"
    sc     = fin.get("scenarios", {})
    col    = C_CRITICAL if fin.get("score", 50) < 30 else (C_RED if fin.get("score", 50) < 50 else
              C_AMBER if fin.get("score", 50) < 70 else C_GREEN)

    if is_zar:
        eal    = fin.get("estimated_annual_loss", {})
        ins    = fin.get("insurance_recommendation", {})
        most_l = eal.get("most_likely", 0)
        mc     = fin.get("monte_carlo", {})
        mc_t   = mc.get("total", {})
        ci90   = mc.get("confidence_interval_90", {})
        ci50   = mc.get("confidence_interval_50", {})
        rows = [
            ("Industry",              fin.get("industry", "Other")),
            ("Annual Revenue",        f"{cur} {fin.get('annual_revenue_zar', 0):,.0f}"),
            ("",                      ""),
            ("Est. Annual Loss (Min)",    f"{cur} {eal.get('minimum', 0):,.0f}"),
            ("Est. Annual Loss (Likely)", f"{cur} {most_l:,.0f}"),
            ("Est. Annual Loss (Max)",    f"{cur} {eal.get('maximum', 0):,.0f}"),
            ("",                      ""),
        ]
        # Monte Carlo section
        if mc_t:
            rows.extend([
                ("MONTE CARLO ANALYSIS",  f"{mc.get('iterations', 10000):,} simulations — PERT distribution"),
                ("  90% Confidence Interval", f"{cur} {ci90.get('lower', 0):,.0f} — {cur} {ci90.get('upper', 0):,.0f}"),
                ("  50% Confidence Interval", f"{cur} {ci50.get('lower', 0):,.0f} — {cur} {ci50.get('upper', 0):,.0f}"),
                ("",                      ""),
                ("  Percentile Breakdown", ""),
                ("    P5  (Best case)",   f"{cur} {mc_t.get('p5', 0):,.0f}"),
                ("    P25 (Optimistic)",  f"{cur} {mc_t.get('p25', 0):,.0f}"),
                ("    P50 (Median)",      f"{cur} {mc_t.get('p50', 0):,.0f}"),
                ("    P75 (Conservative)",f"{cur} {mc_t.get('p75', 0):,.0f}"),
                ("    P95 (Worst case)",  f"{cur} {mc_t.get('p95', 0):,.0f}"),
                ("",                      ""),
                ("  Mean",                f"{cur} {mc_t.get('mean', 0):,.0f}"),
                ("  Std. Deviation",      f"{cur} {mc_t.get('std_dev', 0):,.0f}"),
                ("",                      ""),
            ])
            # Per-scenario MC breakdown
            for sname, slabel in [("data_breach", "Data Breach"), ("ransomware", "Ransomware"), ("business_interruption", "Bus. Interruption")]:
                smc = sc.get(sname, {}).get("monte_carlo", {})
                if smc:
                    rows.append((f"  {slabel} (MC)", ""))
                    rows.append((f"    P5",   f"{cur} {smc.get('p5', 0):,.0f}"))
                    rows.append((f"    P25",  f"{cur} {smc.get('p25', 0):,.0f}"))
                    rows.append((f"    P50",  f"{cur} {smc.get('p50', 0):,.0f}"))
                    rows.append((f"    P75",  f"{cur} {smc.get('p75', 0):,.0f}"))
                    rows.append((f"    P95",  f"{cur} {smc.get('p95', 0):,.0f}"))
                    rows.append(("", ""))
            rows.append(("", ""))

        rows.extend([
            ("Data Breach Loss",      f"{cur} {sc.get('data_breach', {}).get('estimated_loss', 0):,.0f}  (P={sc.get('data_breach', {}).get('probability', 0)})"),
            ("  Records at risk",     f"{sc.get('data_breach', {}).get('estimated_records', 0):,} @ {cur}{sc.get('data_breach', {}).get('cost_per_record', 0):,.0f}/rec"),
            ("  POPIA regulatory",    f"{cur} {sc.get('data_breach', {}).get('regulatory_fine', 0):,.0f}"),
            ("Ransomware Loss",       f"{cur} {sc.get('ransomware', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})"),
            ("  Avg downtime",        f"{sc.get('ransomware', {}).get('avg_downtime_days', 0)} days"),
            ("  Ransom estimate",     f"{cur} {sc.get('ransomware', {}).get('ransom_estimate', 0):,.0f}"),
            ("Bus. Interruption",     f"{cur} {sc.get('business_interruption', {}).get('estimated_loss', 0):,.0f}  (P={sc.get('business_interruption', {}).get('probability', 0)})"),
            ("",                      ""),
            ("Min. Insurance Cover",  f"{cur} {ins.get('minimum_cover_zar', 0):,.0f}"),
            ("Rec. Insurance Cover",  f"{cur} {ins.get('recommended_cover_zar', 0):,.0f}"),
            ("Premium Risk Tier",     ins.get("premium_risk_tier", "N/A")),
        ])
    else:
        total  = fin.get("total", {})
        most_l = total.get("most_likely", 0)
        ins    = fin.get("insurance_recommendations", {})
        mc     = fin.get("monte_carlo", {})
        mc_t   = mc.get("total", {})
        ci90   = mc.get("confidence_interval_90", {})
        ci50   = mc.get("confidence_interval_50", {})
        rows = [
            ("Industry",              fin.get("industry", "Other")),
            ("",                      ""),
            ("Est. Annual Loss (Min)",    f"{cur} {total.get('min', 0):,.0f}"),
            ("Est. Annual Loss (Likely)", f"{cur} {most_l:,.0f}"),
            ("Est. Annual Loss (Max)",    f"{cur} {total.get('max', 0):,.0f}"),
            ("",                      ""),
        ]
        if mc_t:
            rows.extend([
                ("MONTE CARLO ANALYSIS",  f"{mc.get('iterations', 10000):,} simulations — PERT distribution"),
                ("  90% Confidence Interval", f"{cur} {ci90.get('lower', 0):,.0f} — {cur} {ci90.get('upper', 0):,.0f}"),
                ("  50% Confidence Interval", f"{cur} {ci50.get('lower', 0):,.0f} — {cur} {ci50.get('upper', 0):,.0f}"),
                ("",                      ""),
                ("  Percentile Breakdown", ""),
                ("    P5  (Best case)",   f"{cur} {mc_t.get('p5', 0):,.0f}"),
                ("    P25 (Optimistic)",  f"{cur} {mc_t.get('p25', 0):,.0f}"),
                ("    P50 (Median)",      f"{cur} {mc_t.get('p50', 0):,.0f}"),
                ("    P75 (Conservative)",f"{cur} {mc_t.get('p75', 0):,.0f}"),
                ("    P95 (Worst case)",  f"{cur} {mc_t.get('p95', 0):,.0f}"),
                ("",                      ""),
                ("  Mean",                f"{cur} {mc_t.get('mean', 0):,.0f}"),
                ("  Std. Deviation",      f"{cur} {mc_t.get('std_dev', 0):,.0f}"),
                ("",                      ""),
            ])
        rows.extend([
            ("Data Breach",           f"{cur} {sc.get('data_breach', {}).get('most_likely', 0):,.0f}"),
            ("Ransomware",            f"{cur} {sc.get('ransomware', {}).get('most_likely', 0):,.0f}"),
            ("Bus. Interruption",     f"{cur} {sc.get('business_interruption', {}).get('most_likely', 0):,.0f}"),
            ("",                      ""),
            ("Suggested Deductible",  f"{cur} {ins.get('suggested_deductible', 0):,.0f}"),
            ("Recommended Coverage",  f"{cur} {ins.get('recommended_coverage', 0):,.0f}"),
        ])

    return build_cat_card("Financial Impact (FAIR Model)", col,
                          f"{cur} {most_l:,.0f}", rows, fin.get("issues", []), S)


def cat_risk_mitigations(d, S):
    fin = d.get("financial_impact", {})
    mit = fin.get("risk_mitigations", {})
    findings = mit.get("findings", [])
    if not findings:
        return []

    is_zar = fin.get("currency") == "ZAR"
    cur = "R" if is_zar else "$"

    total_savings = mit.get("total_potential_savings", 0)
    current = mit.get("current_annual_loss", 0)
    mitigated = mit.get("mitigated_annual_loss", 0)
    reduction_pct = round((total_savings / current * 100) if current > 0 else 0, 1)

    rows = [
        ("Current Annual Loss",    f"{cur} {current:,.0f}"),
        ("Mitigated Annual Loss",  f"{cur} {mitigated:,.0f}"),
        ("Total Potential Savings", f"{cur} {total_savings:,.0f} ({reduction_pct}%)"),
        ("", ""),
    ]

    # Count by severity from summary
    summary = mit.get("summary", {})
    for sev in ("critical", "high", "medium"):
        s = summary.get(sev, {})
        if s.get("count", 0) > 0:
            rows.append((f"{sev.title()} Findings", f"{s['count']} — {cur} {s['total_savings_zar']:,.0f} savings"))

    rows.append(("", ""))

    # Individual findings
    for f in findings:
        sev = f.get("severity", "Medium")
        savings = f.get("estimated_annual_savings_zar", 0)
        rows.append((f"[{sev}] {f.get('recommendation', '')}",
                      f"{cur} {savings:,.0f}"))

    rows.append(("", ""))
    rows.append(("Note", "Savings are modelled projections based on FAIR methodology"))

    return build_cat_card("Risk Mitigation Recommendations", C_GREEN,
                          f"Save {cur} {total_savings:,.0f}", rows, [], S)


# ---------------------------------------------------------------------------
# Executive summary table
# ---------------------------------------------------------------------------

def _build_legend(S) -> Table:
    """Colour glossary legend for the report."""
    legend_items = [
        (C_GREEN, "Low Risk", "No action required"),
        (C_AMBER, "Medium Risk", "Monitor / improve when feasible"),
        (C_RED, "High Risk", "Remediation recommended"),
        (C_CRITICAL, "Critical Risk", "Immediate action required"),
    ]
    legend_rows = []
    for col, label, desc in legend_items:
        legend_rows.append([
            make_traffic_circle(col, 8),
            Paragraph(f"<b>{label}</b>", S["kv_key"]),
            Paragraph(desc, S["body_muted"]),
        ])
    tbl = Table(legend_rows, colWidths=[14, 28 * mm, INNER_W - 14 - 28 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (0, -1), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 4),
    ]))
    return tbl


# Insurance risk context for executive summary items
_INSURANCE_CONTEXT = {
    "Ransomware Susceptibility": "Determines premium loading; high RSI correlates with ransomware claim frequency",
    "Data Breach Index": "Historical breach exposure; impacts data breach and regulatory fine projections",
    "SSL Grade": "Weak encryption enables man-in-the-middle attacks; increases data breach probability",
    "Email Security Score": "Poor email auth enables phishing/BEC; top initial attack vector for claims",
    "HTTP Security Headers": "Missing headers enable XSS and clickjacking; increases web application breach risk",
    "Known Data Breaches": "Prior breaches significantly increase probability of repeat incidents and claims",
    "Exposed Admin Panels": "Direct entry point for attackers; leads to full system compromise and ransomware",
    "DB/Service Exposure": "Exposed databases enable mass data theft; highest severity finding for underwriting",
    "IP/Domain Blacklisted": "Indicates prior compromise or spam; reputation damage affects business interruption",
    "WAF Protection": "No WAF leaves web applications unprotected against automated attacks and DDoS",
    "RDP Exposed": "Primary ransomware entry vector; single highest risk factor for cyber claims",
    "Est. Annual Loss": "FAIR-modelled expected loss; basis for coverage limits and premium calculation",
    "Fraudulent Domains": "Brand impersonation risk; phishing campaigns targeting clients and employees",
    "Web Ranking (Tranco)": "Site visibility indicator; higher-profile targets attract more automated attacks",
}


def build_summary_table(results: dict, S) -> Table:
    cats = results.get("categories", {})

    # Map traffic light colours to hex for inline font tags
    _COL_HEX = {
        id(C_GREEN): "#16a34a", id(C_AMBER): "#d97706",
        id(C_RED): "#dc2626", id(C_CRITICAL): "#991b1b",
        id(C_BLUE): "#1d4ed8", id(C_GREY_3): "#94a3b8",
    }

    def row(label, value, col):
        circ = make_traffic_circle(col, 9)
        col_hex = _COL_HEX.get(id(col), "#0f172a")
        val_str = str(value)
        ctx = _INSURANCE_CONTEXT.get(label, "")
        val_text = f"<font color='{col_hex}'><b>{val_str}</b></font>  <font size='7' color='#64748b'><i>— {ctx}</i></font>" if ctx else f"<font color='{col_hex}'><b>{val_str}</b></font>"
        return [circ, Paragraph(f"<b>{label}</b>", S["kv_key"]), Paragraph(val_text, S["kv_val"])]

    ssl_grade = cats.get("ssl", {}).get("grade", "?")
    em_score  = cats.get("email_security", {}).get("score", 0)
    hh_score  = cats.get("http_headers", {}).get("score", 0)
    br_count  = cats.get("breaches", {}).get("breach_count", 0)
    adm_c     = cats.get("exposed_admin", {}).get("critical_count", 0)
    adm_h     = cats.get("exposed_admin", {}).get("high_count", 0)
    hrp_c     = cats.get("high_risk_protocols", {}).get("critical_count", 0)
    bl        = cats.get("dnsbl", {}).get("blacklisted", False)
    waf       = cats.get("waf", {}).get("detected", False)
    vpn_rdp   = cats.get("vpn_remote", {}).get("rdp_exposed", False)

    # Insurance analytics
    ins       = results.get("insurance", {})
    rsi_score = ins.get("rsi", {}).get("rsi_score")
    dbi_score = ins.get("dbi", {}).get("dbi_score")

    rows = [
        row("SSL Grade",             ssl_grade,
            _tl(ssl_grade in ("A+", "A", "B"), ssl_grade == "C")),
        row("Email Security Score",  f"{em_score}/10",
            _tl(em_score >= 8, em_score >= 5)),
        row("HTTP Security Headers", f"{hh_score}%",
            _tl(hh_score >= 80, hh_score >= 50)),
        row("Known Data Breaches",   br_count,
            _tl(br_count == 0, br_count <= 3)),
        row("Exposed Admin Panels",  adm_c + adm_h,
            _tl(adm_c + adm_h == 0, adm_c == 0)),
        row("DB/Service Exposure",   f"{hrp_c} critical service(s)",
            C_CRITICAL if hrp_c > 0 else C_GREEN),
        row("IP/Domain Blacklisted", "YES" if bl else "No",
            C_CRITICAL if bl else C_GREEN),
        row("WAF Protection",        "Detected" if waf else "Not detected",
            C_GREEN if waf else C_AMBER),
        row("RDP Exposed",           "YES — CRITICAL" if vpn_rdp else "No",
            C_CRITICAL if vpn_rdp else C_GREEN),
    ]

    # Add insurance rows if available
    if rsi_score is not None:
        rows.insert(0, row("Ransomware Susceptibility", f"{rsi_score:.2f}",
            _tl(rsi_score < 0.3, rsi_score < 0.6)))
    if dbi_score is not None:
        rows.insert(1 if rsi_score is not None else 0,
            row("Data Breach Index", f"{dbi_score}/100",
            _tl(dbi_score >= 70, dbi_score >= 40)))

    # Est. Annual Loss from insurance analytics
    fin_ins = ins.get("financial_impact", {})
    fin_ml  = fin_ins.get("estimated_annual_loss", {}).get("most_likely")
    if fin_ml is not None:
        cur_sym   = "R" if fin_ins.get("currency") == "ZAR" else "$"
        fin_score = fin_ins.get("score", 50)
        rows.append(row("Est. Annual Loss", f"{cur_sym} {fin_ml:,.0f}",
                         C_CRITICAL if fin_score < 30 else C_AMBER if fin_score < 70 else C_GREEN))

    fd_count = cats.get("fraudulent_domains", {}).get("fraudulent_domains_found", 0)
    if fd_count:
        rows.append(row("Fraudulent Domains", f"{fd_count} lookalike(s)",
                         C_CRITICAL if fd_count > 3 else C_RED if fd_count > 0 else C_GREEN))

    wr_label = cats.get("web_ranking", {}).get("rank_label", "Unranked")
    rows.append(row("Web Ranking (Tranco)", wr_label,
                     C_GREEN if cats.get("web_ranking", {}).get("ranked") else C_AMBER))

    tbl = Table(rows, colWidths=[18, 45 * mm, INNER_W - 18 - 45 * mm])
    style = [
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (0, -1), 4),
        ("LEFTPADDING",   (1, 0), (-1, -1), 6),
        ("BOX",           (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.25, C_GREY_2),
    ]
    for i in range(0, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_GREY_1))
    for i in range(1, len(rows), 2):
        style.append(("BACKGROUND", (0, i), (-1, i), C_WHITE))
    tbl.setStyle(TableStyle(style))
    return tbl


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _build_attackers_view(results: dict, S) -> list:
    """Build an Attacker's View section that maps findings to the cyber kill chain."""
    cats = results.get("categories", {})
    ins = results.get("insurance", {})
    parts = []

    parts.append(Paragraph("<b>Attacker's View — How a Threat Actor Would Approach This Target</b>", S["cat_title"]))
    parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph(
        "<i>This section maps the scan findings to a real-world attack scenario, showing how a cybercriminal "
        "would use the identified weaknesses to compromise this organisation. Each phase represents a step "
        "in a typical cyber attack.</i>", S["body_muted"]))
    parts.append(Spacer(1, 3 * mm))

    rows = []
    bgs = []

    # Phase 1: Reconnaissance
    sub_count = cats.get("subdomains", {}).get("total_count", 0)
    ip_count = results.get("categories", {}).get("external_ips", {}).get("total_unique_ips", 0)
    tech = cats.get("tech_stack", {})
    dh = cats.get("dehashed", {})
    emails = dh.get("unique_emails", 0)
    recon_risk = "HIGH" if (ip_count > 5 or emails > 3) else ("MEDIUM" if (ip_count > 1 or emails > 0) else "LOW")
    recon_findings = []
    if ip_count: recon_findings.append(f"{ip_count} external IPs discoverable")
    if sub_count: recon_findings.append(f"{sub_count} subdomains enumerable")
    if emails: recon_findings.append(f"{emails} email addresses found in breach databases")
    if tech.get("server_header"): recon_findings.append(f"Server technology exposed: {tech.get('server_header', '')}")

    _PHASE_BG = {"CRITICAL": C_CRITICAL_BG, "HIGH": C_RED_BG, "MEDIUM": C_AMBER_BG, "LOW": C_GREEN_BG}
    _PHASE_FG = {"CRITICAL": "#991b1b", "HIGH": "#dc2626", "MEDIUM": "#92400e", "LOW": "#166534"}

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[recon_risk]}'>Phase 1: RECONNAISSANCE [{recon_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[recon_risk]}'><b>What an attacker learns about the target</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[recon_risk])
    for f in recon_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 2: Initial Access
    rdp = cats.get("vpn_remote", {}).get("rdp_exposed", False)
    hrp = cats.get("high_risk_protocols", {}).get("exposed_services", [])
    cred_leaks = dh.get("total_entries", 0)
    hr = cats.get("hudson_rock", {})
    infostealers = hr.get("compromised_employees", 0)
    access_risk = "CRITICAL" if (rdp or infostealers > 0) else ("HIGH" if (len(hrp) > 0 or cred_leaks > 5) else ("MEDIUM" if cred_leaks > 0 else "LOW"))
    access_findings = []
    if rdp: access_findings.append("RDP (port 3389) exposed — primary ransomware entry vector, brute-force attack possible")
    for svc in hrp[:3]:
        access_findings.append(f"{svc.get('service', 'Unknown')} on port {svc.get('port', '?')} — direct attack vector")
    if cred_leaks: access_findings.append(f"{cred_leaks} stolen credentials available from breach databases — enables credential stuffing")
    if infostealers: access_findings.append(f"{infostealers} employee device(s) with active infostealer — real-time credential theft")
    dmarc = cats.get("email_security", {}).get("dmarc", {})
    if not dmarc.get("present"): access_findings.append("No DMARC policy — domain can be spoofed for phishing attacks against employees")

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[access_risk]}'>Phase 2: INITIAL ACCESS [{access_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[access_risk]}'><b>How an attacker would break in</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[access_risk])
    for f in access_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 3: Exploitation
    osv = cats.get("osv_vulns", {})
    osv_crit = osv.get("critical_count", 0)
    osv_high = osv.get("high_count", 0)
    shodan = cats.get("shodan_vulns", {})
    shodan_cves = shodan.get("total_cves", 0)
    ssl_grade = cats.get("ssl", {}).get("grade", "A")
    exploit_risk = "CRITICAL" if osv_crit > 0 else ("HIGH" if (osv_high > 0 or ssl_grade in ("D", "E", "F")) else "MEDIUM")
    exploit_findings = []
    if osv_crit: exploit_findings.append(f"{osv_crit} critical CVE(s) with known exploits — remote code execution possible")
    if osv_high: exploit_findings.append(f"{osv_high} high-severity CVE(s) — privilege escalation and data access")
    if ssl_grade in ("D", "E", "F"): exploit_findings.append(f"SSL grade {ssl_grade} — weak encryption enables man-in-the-middle interception")
    headers = cats.get("http_headers", {}).get("score", 100)
    if headers < 40: exploit_findings.append(f"Security headers score {headers}% — vulnerable to XSS, clickjacking, and injection attacks")
    if not exploit_findings: exploit_findings.append("No critical exploitation vectors identified from external scan")

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[exploit_risk]}'>Phase 3: EXPLOITATION [{exploit_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[exploit_risk]}'><b>What vulnerabilities an attacker would exploit</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[exploit_risk])
    for f in exploit_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    # Phase 4: Data Access & Impact
    db_exposed = any(s.get("port") in (3306, 5432, 27017, 6379, 9200, 1433) for s in hrp)
    ix = cats.get("intelx", {})
    darkweb = ix.get("total_results", 0)
    data_risk = "CRITICAL" if db_exposed else ("HIGH" if darkweb > 10 else ("MEDIUM" if darkweb > 0 else "LOW"))
    data_findings = []
    if db_exposed: data_findings.append("Databases directly internet-facing — attacker can extract all business data without further escalation")
    if darkweb > 0: data_findings.append(f"{darkweb} references in dark web databases — stolen data is already circulating in criminal networks")
    rsi = ins.get("rsi", {}).get("rsi_score", 0)
    if rsi > 0.5: data_findings.append(f"Ransomware susceptibility {rsi:.0%} — high probability of ransomware deployment after access is gained")
    fin = ins.get("financial_impact", {}).get("total", {})
    if fin.get("most_likely"):
        cur = "R" if ins.get("financial_impact", {}).get("currency") == "ZAR" else "$"
        data_findings.append(f"Estimated financial impact: {cur} {fin['most_likely']:,.0f} (Monte Carlo P50 median)")
    if not data_findings: data_findings.append("Limited external data access vectors identified")

    rows.append([Paragraph(f"<b><font color='{_PHASE_FG[data_risk]}'>Phase 4: DATA ACCESS & IMPACT [{data_risk}]</font></b>", S["kv_key"]),
                 Paragraph(f"<font color='{_PHASE_FG[data_risk]}'><b>What an attacker would steal or destroy</b></font>", S["kv_val"])])
    bgs.append(_PHASE_BG[data_risk])
    for f in data_findings:
        r, bg = kv_row("", f"• {f}", S, alt=True)
        rows.append(r); bgs.append(bg)

    tbl = _cat_table(rows, bgs, [40 * mm, INNER_W - 40 * mm], S)
    parts.append(tbl)
    parts.append(Spacer(1, 3 * mm))
    return parts


def _build_narrative_summary(results: dict, S) -> list:
    """Build conversational narrative paragraphs for the broker summary report."""
    cats = results.get("categories", {})
    ins = results.get("insurance", {})
    domain = results.get("domain_scanned", "Unknown")
    parts = []

    parts.append(Paragraph("<b>Assessment Narrative</b>", S["cat_title"]))
    parts.append(Spacer(1, 2 * mm))

    # ── 1. Business Context ──────────────────────────────────────────────────
    parts.append(Paragraph("<b>Business Context</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))

    ip_data = cats.get("external_ips", {})
    ip_count = ip_data.get("total_unique_ips", 0)
    sub_count = cats.get("subdomains", {}).get("total_count", 0)
    asn_count = len(ip_data.get("asns", [])) if ip_data.get("asns") else 0
    dns_ports = cats.get("dns_infrastructure", {}).get("open_ports", [])
    svc_count = len(dns_ports)

    fin = ins.get("financial_impact", {})
    industry = fin.get("industry", "")
    revenue = fin.get("annual_revenue_zar", 0) or fin.get("annual_revenue", 0)

    biz_text = (f"This assessment evaluated the external-facing digital infrastructure of <b>{domain}</b>.")
    if industry:
        biz_text += f" The organisation operates in the <b>{industry}</b> sector"
        if revenue:
            cur = "R" if fin.get("currency") == "ZAR" else "$"
            biz_text += f" with reported annual revenue of <b>{cur} {revenue:,.0f}</b>"
        biz_text += "."
    biz_text += (f" The scan discovered <b>{ip_count}</b> external IP address(es)")
    if asn_count:
        biz_text += f" across <b>{asn_count}</b> ASN(s)"
    biz_text += f", <b>{sub_count}</b> subdomain(s), and <b>{svc_count}</b> open service(s)."
    parts.append(Paragraph(biz_text, S["body"]))
    parts.append(Spacer(1, 3 * mm))

    # ── 2. Encryption & Web Security ─────────────────────────────────────────
    parts.append(Paragraph("<b>Encryption &amp; Web Security</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))

    ssl = cats.get("ssl", {})
    ssl_grade = ssl.get("grade", "?")
    ws = cats.get("website_security", {})
    https_enforced = ws.get("https_enforced", False)
    hh_score = cats.get("http_headers", {}).get("score", 0)
    waf = cats.get("waf", {}).get("detected", False)

    if ssl_grade in ("A+", "A"):
        grade_meaning = "confirms strong encryption and a well-configured certificate chain"
    elif ssl_grade == "B":
        grade_meaning = "indicates acceptable encryption with minor configuration improvements possible"
    elif ssl_grade == "C":
        grade_meaning = "indicates moderate encryption weaknesses that should be addressed"
    else:
        grade_meaning = "indicates weak encryption configuration requiring urgent remediation"

    enc_text = (f"The SSL/TLS assessment returned a grade of <b>{ssl_grade}</b>, which {grade_meaning}. ")
    enc_text += f"HTTPS enforcement is <b>{'active' if https_enforced else 'not active'}</b>. "
    enc_text += f"Security headers coverage stands at <b>{hh_score}%</b>. "
    enc_text += f"Web Application Firewall (WAF) protection is <b>{'detected' if waf else 'not detected'}</b>."
    parts.append(Paragraph(enc_text, S["body"]))
    parts.append(Spacer(1, 3 * mm))

    # ── 3. Email Security Posture ────────────────────────────────────────────
    parts.append(Paragraph("<b>Email Security Posture</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))

    em = cats.get("email_security", {})
    spf = em.get("spf", {})
    dkim = em.get("dkim", {})
    dmarc = em.get("dmarc", {})

    spf_status = "present" if spf.get("present") else "missing"
    dkim_status = "present" if dkim.get("selectors_found") else "missing"
    dmarc_status = "present" if dmarc.get("present") else "missing"
    dmarc_policy = dmarc.get("policy", "none") if dmarc.get("present") else "N/A"

    email_text = (f"SPF record is <b>{spf_status}</b>. "
                  f"DKIM is <b>{dkim_status}</b>. "
                  f"DMARC is <b>{dmarc_status}</b>")
    if dmarc.get("present"):
        email_text += f" with policy set to <b>{dmarc_policy}</b>"
    email_text += ". "

    missing_count = sum(1 for s in [spf_status, dkim_status, dmarc_status] if s == "missing")
    if missing_count == 0:
        email_text += "All three email authentication mechanisms are in place, providing strong protection against phishing and business email compromise (BEC)."
    elif missing_count == 1:
        email_text += "One email authentication mechanism is missing, leaving a partial gap that attackers could exploit for phishing or BEC attacks."
    else:
        email_text += f"With <b>{missing_count}</b> authentication mechanisms missing, the domain is significantly vulnerable to email spoofing, phishing, and BEC attacks."
    parts.append(Paragraph(email_text, S["body"]))
    parts.append(Spacer(1, 3 * mm))

    # ── 4. Credential & Dark Web Exposure ────────────────────────────────────
    parts.append(Paragraph("<b>Credential &amp; Dark Web Exposure</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))

    dh = cats.get("dehashed", {})
    hr = cats.get("hudson_rock", {})
    ix = cats.get("intelx", {})
    cr = cats.get("credential_risk", {})

    cred_parts = []
    dh_total = dh.get("total_entries", 0)
    dh_emails = dh.get("unique_emails", 0)
    dh_sources = dh.get("breach_sources", [])
    if dh.get("status") == "no_api_key":
        cred_parts.append("Dehashed credential search was not performed (no API key configured).")
    elif dh_total > 0:
        src_text = ", ".join(dh_sources[:6]) if dh_sources else "various sources"
        cred_parts.append(f"Dehashed identified <b>{dh_emails}</b> email(s) across <b>{dh_total}</b> breach record(s) from sources including {src_text}.")
    else:
        cred_parts.append("Dehashed returned no exposed credentials.")

    hr_emp = hr.get("compromised_employees", 0)
    hr_usr = hr.get("compromised_users", 0)
    if hr_emp > 0:
        cred_parts.append(f"Hudson Rock detected <b>{hr_emp}</b> employee device(s) with <b>active infostealer</b> infections.")
    elif hr_usr > 0:
        cred_parts.append(f"Hudson Rock detected <b>{hr_usr}</b> compromised user credential(s).")
    else:
        cred_parts.append("Hudson Rock reports no active infostealer infections.")

    ix_total = ix.get("total_results", 0)
    ix_darkweb = ix.get("darkweb_count", 0)
    ix_pastes = ix.get("paste_count", 0)
    if ix.get("status") == "no_api_key":
        cred_parts.append("IntelX dark web monitoring was not performed (no API key configured).")
    elif ix_total > 0:
        cred_parts.append(f"IntelX found <b>{ix_darkweb}</b> dark web mention(s) and <b>{ix_pastes}</b> paste reference(s).")
    else:
        cred_parts.append("IntelX returned no dark web mentions.")

    cr_level = cr.get("risk_level", "")
    if cr_level:
        cred_parts.append(f"Overall credential risk level: <b>{cr_level}</b>.")

    parts.append(Paragraph(" ".join(cred_parts), S["body"]))
    parts.append(Spacer(1, 3 * mm))

    # ── 5. Network & Infrastructure ──────────────────────────────────────────
    parts.append(Paragraph("<b>Network &amp; Infrastructure</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))

    port_count = len(dns_ports)
    high_risk_ports = [p for p in dns_ports if p.get("risk") in ("high", "critical")]
    hrp_data = cats.get("high_risk_protocols", {})
    exposed_svcs = hrp_data.get("exposed_services", [])
    bl = cats.get("dnsbl", {})
    is_blacklisted = bl.get("blacklisted", False)
    cdn = cats.get("cloud_cdn", {})
    cdn_detected = cdn.get("cdn_detected") or cdn.get("cloud_detected", False)

    net_text = f"The primary IP has <b>{port_count}</b> open port(s). "
    if high_risk_ports:
        svc_names = [f"{p.get('service', 'unknown')} ({p.get('port', '?')})" for p in high_risk_ports[:5]]
        net_text += f"High-risk exposed services include: <b>{', '.join(svc_names)}</b>. "
    elif exposed_svcs:
        svc_names = [f"{s.get('service', 'unknown')} ({s.get('port', '?')})" for s in exposed_svcs[:5]]
        net_text += f"Exposed services include: <b>{', '.join(svc_names)}</b>. "
    else:
        net_text += "No high-risk services were detected. "
    net_text += f"CDN/WAF protection is <b>{'active' if cdn_detected else 'not detected'}</b>. "
    net_text += f"Blacklist status: <b>{'LISTED — requires immediate attention' if is_blacklisted else 'clean'}</b>."
    parts.append(Paragraph(net_text, S["body"]))
    parts.append(Spacer(1, 3 * mm))

    # ── 6. Compliance Snapshot ───────────────────────────────────────────────
    compliance = results.get("compliance", {})
    if compliance:
        parts.append(Paragraph("<b>Compliance Snapshot</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        comp_lines = []
        for framework, fw_data in compliance.items():
            pct = fw_data.get("overall_pct", 0)
            comp_lines.append(f"<b>{framework}</b>: {pct}% aligned")
        parts.append(Paragraph("  |  ".join(comp_lines), S["body"]))
        parts.append(Spacer(1, 3 * mm))

    return parts


def generate_pdf(results: dict, report_type: str = "full") -> bytes:
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
        author="PHISHIELD / Bryte Insurance",
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
    story.append(Spacer(1, 4 * mm))

    # Executive summary table
    story.append(Paragraph("<b>Executive Summary</b>", S["cat_title"]))
    story.append(Spacer(1, 2 * mm))
    story.append(build_summary_table(results, S))

    # ── Attacker's View ──────────────────────────────────────────────────────
    story.append(PageBreak())
    story += _build_attackers_view(results, S)

    # ── Report type branching ───────────────────────────────────────────────
    if report_type == "summary":
        # Narrative summary paragraphs
        story.append(Spacer(1, 4 * mm))
        story += _build_narrative_summary(results, S)

        # Financial Impact headline only
        ins_data = results.get("insurance", {})
        fin = ins_data.get("financial_impact", {})
        if fin and (fin.get("currency") or fin.get("status") == "completed"):
            story.append(PageBreak())
            story += section_header("FINANCIAL IMPACT SUMMARY", S)
            story.append(Spacer(1, 2 * mm))

            is_zar = fin.get("currency") == "ZAR"
            cur = "R" if is_zar else "$"

            if is_zar:
                eal = fin.get("estimated_annual_loss", {})
                most_likely = eal.get("most_likely", 0)
                mc = fin.get("monte_carlo", {})
                mc_t = mc.get("total", {})
                mc_p50 = mc_t.get("p50", 0)
                ins_rec = fin.get("insurance_recommendation", {})
                rec_cover = ins_rec.get("recommended_cover_zar", 0)
            else:
                total = fin.get("total", {})
                most_likely = total.get("most_likely", 0)
                mc = fin.get("monte_carlo", {})
                mc_t = mc.get("total", {})
                mc_p50 = mc_t.get("p50", 0)
                ins_rec = fin.get("insurance_recommendations", {})
                rec_cover = ins_rec.get("recommended_coverage", 0)

            fin_text = (f"Estimated annual loss (most likely): <b>{cur} {most_likely:,.0f}</b>")
            if mc_p50:
                fin_text += f"  |  Monte Carlo P50 (median): <b>{cur} {mc_p50:,.0f}</b>"
            if rec_cover:
                fin_text += f"  |  Recommended insurance cover: <b>{cur} {rec_cover:,.0f}</b>"
            story.append(Paragraph(fin_text, S["body"]))
            story.append(Spacer(1, 4 * mm))

        # Top 5 remediation items from risk mitigations
        # ── Why This Matters — The Reality of a Cyber Breach ──────────────
        story.append(PageBreak())
        story += section_header("WHY THIS MATTERS", S)
        story.append(Spacer(1, 3 * mm))

        # Financial exposure recap
        total_likely = fin.get("total", {}).get("most_likely", 0) if fin else 0
        mc_data = fin.get("monte_carlo", {}).get("total", {}) if fin else {}
        mc_p50 = mc_data.get("p50", total_likely)
        mc_p95 = mc_data.get("p95", 0)
        cur_cta = "R" if (fin and fin.get("currency") == "ZAR") else "$"

        # Count critical findings
        cred_risk = cats.get("credential_risk", {}).get("risk_level", "LOW")
        hr_employees = cats.get("hudson_rock", {}).get("compromised_employees", 0)
        ix_total = cats.get("intelx", {}).get("total_results", 0)
        dh_total = cats.get("dehashed", {}).get("total_entries", 0)
        hrp_critical = cats.get("high_risk_protocols", {}).get("critical_count", 0)

        story.append(Paragraph(
            f"<b>Your Estimated Financial Exposure</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            f"Based on this assessment, your organisation faces an estimated annual cyber loss of "
            f"<b>{cur_cta} {mc_p50:,.0f}</b> (median scenario). In a worst-case event, losses could reach "
            f"<b>{cur_cta} {mc_p95:,.0f}</b>. These figures are derived from a Monte Carlo simulation of "
            f"10,000 scenarios modelling data breach, ransomware, and business interruption events "
            f"specific to your industry and risk profile.",
            S["body"]))
        story.append(Spacer(1, 4 * mm))

        # The human cost of a breach
        story.append(Paragraph(
            f"<b>The Reality of a Cyber Breach</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            "The financial numbers only tell part of the story. When a South African organisation "
            "suffers a data breach, the impact extends far beyond the balance sheet:",
            S["body"]))
        story.append(Spacer(1, 2 * mm))

        # IBM 2025 SA statistics
        stat_style = ParagraphStyle("stat", fontSize=10, fontName="Helvetica",
                                     textColor=C_BLACK, leading=14, spaceBefore=2, spaceAfter=2,
                                     leftIndent=12, bulletIndent=6)

        stats = [
            "<b>R44.1 million</b> — the average cost of a data breach in South Africa in 2025 "
            "(IBM Cost of a Data Breach Report). Even with the 17% decline from 2024, this represents "
            "a potentially business-ending event for most SMEs.",

            "<b>241 days</b> — the average time to identify and contain a breach. For nearly 8 months, "
            "attackers may have access to your systems, data, and client information before the breach "
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
            "your business may be unable to operate while systems are restored, data is recovered, "
            "and forensic investigations are conducted.",
        ]
        for stat in stats:
            story.append(Paragraph(f"\u2022 {stat}", stat_style))
        story.append(Spacer(1, 4 * mm))

        # Personalised risk context
        story.append(Paragraph(
            f"<b>What This Means for Your Organisation</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))

        risk_paras = []
        if hr_employees > 0:
            risk_paras.append(
                f"This assessment detected <b>active infostealer malware</b> on {hr_employees} employee "
                f"device(s). This is not a historical finding — it means credentials are being stolen "
                f"<b>right now</b> and sold to criminal buyers. Without immediate intervention, a breach "
                f"is not a matter of <i>if</i>, but <i>when</i>."
            )
        if ix_total > 0:
            risk_paras.append(
                f"We found <b>{ix_total} references</b> to your organisation in dark web databases. "
                f"This means stolen data associated with your business is circulating in criminal "
                f"networks where it can be purchased by anyone with malicious intent."
            )
        if dh_total > 0:
            risk_paras.append(
                f"<b>{dh_total} credential records</b> linked to your domain were found in breach "
                f"databases. These include email addresses and potentially passwords that attackers "
                f"use for credential stuffing — systematically trying stolen passwords across "
                f"multiple systems until they find one that works."
            )
        if hrp_critical > 0:
            risk_paras.append(
                f"<b>{hrp_critical} critical service(s)</b> (databases, remote access) are directly "
                f"exposed to the internet. An attacker does not need sophisticated tools to exploit "
                f"these — a simple connection attempt with stolen credentials could grant immediate "
                f"access to your most sensitive business data."
            )
        if cred_risk in ("CRITICAL", "HIGH"):
            risk_paras.append(
                f"Your overall credential risk is classified as <b>{cred_risk}</b>. "
                f"This means there is a significantly elevated probability of unauthorised access "
                f"to your systems using compromised credentials."
            )
        if not risk_paras:
            risk_paras.append(
                "While this assessment did not identify critical immediate threats, the cyber "
                "landscape evolves rapidly. New vulnerabilities are discovered daily, and threat "
                "actors continuously scan for targets. Maintaining adequate cyber insurance ensures "
                "your organisation is protected against unforeseen events."
            )

        for para in risk_paras:
            story.append(Paragraph(para, S["body"]))
            story.append(Spacer(1, 2 * mm))
        story.append(Spacer(1, 4 * mm))

        # Call to action
        story.append(Paragraph(
            f"<b>Protect Your Business — Next Steps</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))

        cta_style = ParagraphStyle("cta", fontSize=10, fontName="Helvetica",
                                    textColor=C_BLACK, leading=14, spaceBefore=2, spaceAfter=4,
                                    leftIndent=12, bulletIndent=6)

        cta_items = [
            "<b>Cyber Insurance Coverage</b> — Speak to your Phishield broker about a tailored cyber "
            "insurance policy that covers data breach response costs, ransomware negotiation and payment, "
            "business interruption losses, regulatory fines (POPIA), and third-party liability. "
            f"Based on this assessment, a minimum cover of <b>{cur_cta} {ins_rec.get('minimum_cover_zar', ins_rec.get('suggested_deductible', 0)):,.0f}</b> "
            f"is recommended, with an optimal cover of <b>{cur_cta} {ins_rec.get('recommended_cover_zar', ins_rec.get('recommended_coverage', 0)):,.0f}</b>."
            if ins_rec else
            "<b>Cyber Insurance Coverage</b> — Speak to your Phishield broker about a tailored cyber "
            "insurance policy that covers data breach response costs, ransomware negotiation, "
            "business interruption losses, regulatory fines (POPIA), and third-party liability.",

            "<b>Vulnerability Remediation</b> — The vulnerabilities identified in this report can be "
            "addressed through professional remediation services. A qualified cybersecurity partner can "
            "help secure exposed services, patch critical vulnerabilities, implement MFA, and strengthen "
            "your overall security posture — often reducing your insurance premium in the process.",

            "<b>Continuous Monitoring</b> — Cyber risk is not static. New vulnerabilities are discovered "
            "daily, and your attack surface changes as your business evolves. Ongoing monitoring ensures "
            "emerging threats are detected before they are exploited.",
        ]
        for item in cta_items:
            story.append(Paragraph(f"\u2022 {item}", cta_style))
        story.append(Spacer(1, 4 * mm))

        # Contact block
        story.append(HRFlowable(width=INNER_W, thickness=0.5, color=C_BLUE))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "<b>To discuss your cyber insurance options or arrange a remediation assessment, "
            "contact your Phishield broker or visit www.phishield.com</b>",
            ParagraphStyle("contact", fontSize=11, fontName="Helvetica-Bold",
                           textColor=C_BLUE, leading=15, alignment=TA_CENTER)
        ))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "PHISHIELD UMA (Pty) Ltd | Authorised Financial Services Provider | FSP 46418",
            ParagraphStyle("fsp", fontSize=8, fontName="Helvetica",
                           textColor=C_GREY_3, leading=11, alignment=TA_CENTER)
        ))

    else:
        # ── Full report — all sections included ─────────────────────────────

        # ── Insurance Analytics ─────────────────────────────────────────────
        if results.get("insurance"):
            story.append(PageBreak())
            story += section_header("INSURANCE ANALYTICS", S)
            story += cat_rsi(results, S)
            story += cat_dbi(results, S)
            story += cat_financial_impact(results.get("insurance", {}), S)
            story += cat_risk_mitigations(results.get("insurance", {}), S)
            story += cat_remediation(results, S)

        story.append(PageBreak())

        # ── Discovery ───────────────────────────────────────────────────────
        story += section_header("DISCOVERY", S)
        story += cat_web_ranking(cats, S)

        # ── Core Security ───────────────────────────────────────────────────
        story += section_header("CORE SECURITY", S)
        story += cat_ssl(cats, S)
        story += cat_headers(cats, S)
        story += cat_waf(cats, S)
        story += cat_website(cats, S)

        # ── Information Security ────────────────────────────────────────────
        story += section_header("INFORMATION SECURITY", S)
        story += cat_info_disclosure(cats, S)

        # ── Email Security ──────────────────────────────────────────────────
        story += section_header("EMAIL SECURITY", S)
        story += cat_email(cats, S)
        story += cat_email_hardening(cats, S)

        # ── Network & Infrastructure ────────────────────────────────────────
        story += section_header("NETWORK & INFRASTRUCTURE", S)
        story += cat_dns(cats, S)
        story += cat_hrp(cats, S)
        story += cat_cloud(cats, S)
        story += cat_vpn(cats, S)

        # ── Exposure & Reputation ───────────────────────────────────────────
        story += section_header("EXPOSURE & REPUTATION", S)
        story += cat_breaches(cats, S)
        story += cat_dnsbl(cats, S)
        story += cat_admin(cats, S)
        story += cat_subdomains(cats, S)
        story += cat_shodan(cats, S)
        story += cat_dehashed(cats, S)
        story += cat_hudson_rock(cats, S)
        story += cat_intelx(cats, S)
        story += cat_credential_risk(cats, S)
        story += cat_virustotal(cats, S)
        story += cat_fraudulent_domains(cats, S)

        # ── Technology & Governance ─────────────────────────────────────────
        story += section_header("TECHNOLOGY & GOVERNANCE", S)
        story += cat_tech(cats, S)
        story += cat_domain(cats, S)
        story += cat_securitytrails(cats, S)
        story += cat_privacy_compliance(cats, S)
        story += cat_security_policy(cats, S)
        story += cat_payment(cats, S)

        # ── Compliance Framework Mapping ────────────────────────────────────
        if results.get("compliance"):
            story += section_header("COMPLIANCE FRAMEWORK MAPPING", S)
            story += cat_compliance_frameworks(results, S)

        # ── Recommendations ─────────────────────────────────────────────────
        if recs:
            story += section_header("REMEDIATION RECOMMENDATIONS", S)
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
        "Phishield UMA (Pty) Ltd is an Authorised Financial Services Provider (FSP 46418). "
        "Phishield accepts no liability for decisions made solely on the basis of this automated assessment. "
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
    story.append(Paragraph("PHISHIELD", S["title"]))
    story.append(Paragraph("Cyber Insurance Brokers — Powered by Bryte Insurance", S["small"]))
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
            Paragraph(f"R {item.get('unit_price', 0):,.2f}", S["right"]),
            Paragraph(f"R {item.get('line_total', 0):,.2f}", S["right"]),
        ])

    col_widths = [INNER_W * 0.50, INNER_W * 0.12, INNER_W * 0.19, INNER_W * 0.19]
    items_table = Table(rows, colWidths=col_widths)
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
        ["", Paragraph("Subtotal", S["right"]), Paragraph(f"R {subtotal:,.2f}", S["right_bold"])],
        ["", Paragraph(f"VAT ({vat_rate}%)", S["right"]), Paragraph(f"R {vat_amount:,.2f}", S["right_bold"])],
        ["", Paragraph("<b>TOTAL DUE</b>", S["right_bold"]), Paragraph(f"R {total:,.2f}", S["total"])],
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
        "Phishield (Pty) Ltd | Authorised Financial Services Provider | "
        "Underwritten by Bryte Insurance Company Limited (FSP 17703)",
        S["small"]
    ))

    doc.build(story)
    return buffer.getvalue()
