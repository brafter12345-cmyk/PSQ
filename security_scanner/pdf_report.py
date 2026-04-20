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
    "CVE-2015-3306": "ProFTPD mod_copy — unauthenticated remote file copy/write — UNDERWRITING: enables data exfiltration via unauthenticated file access",
    "CVE-2019-12815": "ProFTPD mod_copy — arbitrary file copy without auth — UNDERWRITING: enables data theft without credentials",
    "CVE-2010-4221": "ProFTPD — remote stack buffer overflow (RCE) — UNDERWRITING: enables full server takeover via file transfer service",
    # SSH
    "CVE-2024-6387": "regreSSHion — unauthenticated RCE in OpenSSH (critical) — UNDERWRITING: enables full server takeover; primary ransomware deployment vector",
    "CVE-2023-48795": "Terrapin — SSH prefix truncation attack — UNDERWRITING: degrades SSH encryption; facilitates data interception",
    "CVE-2016-20012": "OpenSSH — username enumeration via timing — UNDERWRITING: facilitates targeted brute-force attacks against valid accounts",
    # Telnet
    "CVE-2020-10188": "Telnetd — remote code execution via buffer overflow — UNDERWRITING: unencrypted protocol; enables full system compromise",
    "CVE-2011-4862": "FreeBSD telnetd — encryption key ID buffer overflow (RCE) — UNDERWRITING: legacy protocol RCE; indicates poor patch management",
    # SMTP
    "CVE-2021-3156": "Sudo heap overflow — local privilege escalation — UNDERWRITING: post-compromise privilege escalation to root access",
    "CVE-2020-28018": "Exim — use-after-free leading to RCE — UNDERWRITING: mail server compromise enables email interception and BEC attacks",
    "CVE-2011-1720": "Postfix — memory corruption via SASL — UNDERWRITING: mail server compromise enables data interception",
    # POP3/IMAP
    "CVE-2021-33515": "Dovecot — STARTTLS command injection — UNDERWRITING: enables email credential interception",
    "CVE-2019-11500": "Dovecot — buffer overflow in mail processing (RCE) — UNDERWRITING: mail server RCE enables full email system compromise",
    # MySQL
    "CVE-2012-2122": "MySQL — authentication bypass via timing attack — UNDERWRITING: enables immediate database access without credentials",
    "CVE-2016-6662": "MySQL — remote root code execution via config file — UNDERWRITING: enables full database and OS-level compromise",
    "CVE-2020-14812": "MySQL Server — denial of service via optimizer — UNDERWRITING: enables service disruption; business interruption risk",
    # RDP
    "CVE-2019-0708": "BlueKeep — unauthenticated RCE in RDP (wormable, critical) — UNDERWRITING: wormable; caused WannaCry/NotPetya global outbreaks",
    "CVE-2019-1181": "DejaBlue — RDP RCE affecting newer Windows versions — UNDERWRITING: wormable RDP exploit; lateral movement risk",
    "CVE-2019-1182": "DejaBlue — RDP RCE variant (wormable) — UNDERWRITING: wormable; enables rapid lateral spread across networks",
    # PostgreSQL
    "CVE-2023-5868": "PostgreSQL — privilege escalation via aggregate functions — UNDERWRITING: enables database privilege escalation to admin",
    "CVE-2019-9193": "PostgreSQL — authenticated RCE via COPY FROM PROGRAM — UNDERWRITING: enables OS command execution from database access",
    "CVE-2023-39417": "PostgreSQL — SQL injection in extension scripts — UNDERWRITING: enables database compromise via extension vulnerabilities",
    # VNC
    "CVE-2006-2369": "RealVNC — authentication bypass (no password required) — UNDERWRITING: enables unauthenticated remote desktop control",
    "CVE-2019-15681": "TightVNC — heap buffer overflow (RCE) — UNDERWRITING: enables remote desktop takeover; data exfiltration risk",
    # SMB
    "CVE-2017-0144": "EternalBlue — SMBv1 RCE (WannaCry, NotPetya) — UNDERWRITING: caused $10B+ in global losses via WannaCry/NotPetya",
    "CVE-2020-0796": "SMBGhost — SMBv3 RCE (wormable, critical) — UNDERWRITING: wormable; enables lateral movement across networks",
    "CVE-2017-0145": "EternalRomance — SMBv1 RCE variant — UNDERWRITING: used in NotPetya; enables ransomware lateral spread",
    # Redis
    "CVE-2022-0543": "Redis — Lua sandbox escape (RCE) — UNDERWRITING: enables remote code execution on cache/database servers",
    "CVE-2021-32761": "Redis — integer overflow in BITFIELD (heap corruption) — UNDERWRITING: enables cache server compromise and data manipulation",
    # Elasticsearch
    "CVE-2015-1427": "Elasticsearch — Groovy scripting RCE (unauthenticated) — UNDERWRITING: unauthenticated RCE; full data extraction possible",
    "CVE-2014-3120": "Elasticsearch — MVEL scripting RCE — UNDERWRITING: enables remote code execution on search/analytics infrastructure",
    # MongoDB
    "CVE-2015-7882": "MongoDB — authentication bypass — UNDERWRITING: enables unauthenticated database access; mass data theft risk",
    "CVE-2013-1892": "MongoDB — nativeHelper buffer overflow (RCE) — UNDERWRITING: enables full database server compromise",
    # MSSQL
    "CVE-2020-0618": "SQL Server — deserialization RCE — UNDERWRITING: enables remote code execution on enterprise database servers",
    "CVE-2019-1068": "SQL Server — remote code execution — UNDERWRITING: enables full compromise of enterprise database infrastructure",
    # CouchDB
    "CVE-2017-12635": "CouchDB — privilege escalation to admin — UNDERWRITING: enables unauthorized admin access to document databases",
    "CVE-2017-12636": "CouchDB — arbitrary command execution — UNDERWRITING: enables OS-level compromise via database service",
    # Docker
    "CVE-2019-5736": "runc — container escape to host (critical) — UNDERWRITING: container escape; compromises entire hosting infrastructure",
    # SNMP
    "CVE-2017-6736": "Cisco SNMP — remote code execution — UNDERWRITING: enables network infrastructure takeover",
    "CVE-2002-0012": "SNMP — community string brute-force / info disclosure — UNDERWRITING: enables network topology discovery and device enumeration",
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
    S["cat_title"]   = ParagraphStyle("cat_title",   fontSize=10, fontName="Helvetica-Bold",
                                       textColor=C_NAVY, leading=14)
    S["body"]        = ParagraphStyle("body",         fontSize=8,  leading=11, textColor=C_BLACK)
    S["body_muted"]  = ParagraphStyle("body_muted",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["issue"]       = ParagraphStyle("issue",        fontSize=8, leading=10, textColor=C_RED,
                                       leftIndent=8)
    S["rec_num"]     = ParagraphStyle("rec_num",      fontSize=8,  fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=11)
    S["rec_body"]    = ParagraphStyle("rec_body",     fontSize=8,  leading=11, textColor=C_BLACK,
                                       leftIndent=18, firstLineIndent=-18)
    S["footer"]      = ParagraphStyle("footer",       fontSize=6.5, textColor=C_GREY_3,
                                       alignment=TA_CENTER)
    S["disclaimer"]  = ParagraphStyle("disclaimer",   fontSize=7,  leading=10, textColor=C_GREY_4)
    S["kv_key"]      = ParagraphStyle("kv_key",       fontSize=8, textColor=C_GREY_4, leading=10)
    S["kv_val"]      = ParagraphStyle("kv_val",       fontSize=8, textColor=C_BLACK,  leading=10)
    S["stat"]        = ParagraphStyle("stat",         fontSize=8, fontName="Helvetica",
                                       textColor=C_BLACK, leading=11, spaceBefore=2, spaceAfter=2,
                                       leftIndent=12, bulletIndent=6)
    S["cta"]         = ParagraphStyle("cta",          fontSize=8, fontName="Helvetica",
                                       textColor=C_BLACK, leading=11, spaceBefore=2, spaceAfter=3,
                                       leftIndent=12, bulletIndent=6)
    S["contact"]     = ParagraphStyle("contact",      fontSize=9, fontName="Helvetica-Bold",
                                       textColor=C_BLUE, leading=13, alignment=TA_CENTER)
    S["fsp"]         = ParagraphStyle("fsp",          fontSize=8, fontName="Helvetica",
                                       textColor=C_GREY_3, leading=11, alignment=TA_CENTER)
    S["vp_legend"]   = ParagraphStyle("vp_legend",    fontSize=8, fontName="Helvetica",
                                       textColor=C_GREY_4, leading=10, leftIndent=4)
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

def _section_header_banner(title: str, S: dict) -> Table:
    """Return just the navy banner Table for a section header."""
    tbl = Table([[Paragraph(f"  {title}", S["section_hdr"])]], colWidths=[INNER_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
    ]))
    return tbl


def section_header(title: str, S: dict) -> list:
    tbl = _section_header_banner(title, S)
    tbl.keepWithNext = True
    trailing = Spacer(1, 3 * mm)
    trailing.keepWithNext = True
    return [Spacer(1, 4 * mm), tbl, trailing]


def section_with_first_card(title: str, S: dict, card_flowables: list) -> list:
    """Combine a section header with the first card's KeepTogether to prevent
    orphaned headers. The section banner is placed inside the KeepTogether so
    ReportLab treats header + card as one atomic block.

    card_flowables: the list returned by a cat_* function (first element is
    typically a KeepTogether).
    """
    if not card_flowables:
        return section_header(title, S)

    banner = _section_header_banner(title, S)

    # If the first flowable is a KeepTogether, inject the banner inside it
    if isinstance(card_flowables[0], KeepTogether):
        kt = card_flowables[0]
        # Prepend banner + spacer into the KeepTogether's internal flowables
        inner = [Spacer(1, 4 * mm), banner, Spacer(1, 3 * mm)] + list(kt._content)
        card_flowables[0] = KeepTogether(inner)
    else:
        # Fallback: wrap banner + enough flowables to prevent orphan.
        # Pull items until we hit the first KeepTogether (which is the actual card)
        # or up to 5 items, whichever comes first.
        first_items = [Spacer(1, 4 * mm), banner, Spacer(1, 3 * mm)]
        to_keep = 0
        for j, fl in enumerate(card_flowables):
            to_keep = j + 1
            first_items.append(fl)
            if isinstance(fl, KeepTogether) or to_keep >= 5:
                break
        card_flowables = [KeepTogether(first_items)] + card_flowables[to_keep:]

    return card_flowables


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


def issues_cell(issues: list, S, fallback: str = "") -> Paragraph:
    if not issues:
        msg = fallback or "No issues detected"
        colour = "#6b7280" if fallback else "#16a34a"  # grey for context, green for clean
        return Paragraph(f"<font color='{colour}'>{msg}</font>", S["body"])
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
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
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


def build_cat_card(title: str, tl_col, summary: str, data_rows: list, issues: list, S, fallback: str = "") -> list:
    """
    data_rows: list of (key, value) tuples
    fallback: context-aware message shown when issues list is empty
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

    issues_para = issues_cell(issues, S, fallback=fallback)
    issues_block = Table([[issues_para]], colWidths=[INNER_W])
    issues_block.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("BACKGROUND",    (0, 0), (-1, -1), C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.25, C_GREY_2),
    ]))

    parts = [Spacer(1, 1 * mm), title_tbl]
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
    legacy = tls.get("TLS 1.0") or tls.get("TLS 1.1")
    days_left = cert.get("days_until_expiry")
    rows = [
        ("Grade",         grade),
        ("Subject",       cert.get("subject", "—")),
        ("Issuer",        cert.get("issuer", "—")),
        ("Expiry",        cert.get("expiry_date", "—")),
        ("Days left",     days_left if days_left else "—"),
        ("TLS 1.0/1.1",   ("Enabled — RISK" if legacy else "Disabled")),
        ("TLS 1.2/1.3",   ("Supported" if tls.get("TLS 1.2") or tls.get("TLS 1.3") else "Not detected")),
        ("Cipher",        f"{cip.get('name','—')} ({'Weak' if cip.get('is_weak') else 'Strong'})"),
        ("HSTS",          "Present" if ssl.get("hsts") else "Missing"),
        ("OCSP Stapling", "Enabled" if ssl.get("ocsp_stapling") else ("Not enabled" if ssl.get("ocsp_stapling") is False else "Unknown")),
        ("CAA Records",   f"Restrictive ({', '.join(ssl.get('caa_policy',{}).get('issue',[])[:3])})" if ssl.get("caa_policy",{}).get("restrictive") else ("Present but not restrictive" if ssl.get("caa_records") else "None — any CA can issue")),
    ]
    fb = "Certificate and encryption configuration meets current standards." if grade in ("A+", "A", "B") else "Review TLS configuration — weak ciphers or legacy protocols may be in use."
    parts = build_cat_card("SSL / TLS", col, f"Grade: {grade}", rows, ssl.get("issues", []), S, fallback=fb)

    # Narrative
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if grade in ("A+", "A"):
        parts.append(Paragraph(
            "This server has a strong SSL/TLS configuration. Data transmitted between users and the website "
            "is encrypted using modern protocols and ciphers, making interception extremely difficult.",
            S["body"]))
    elif grade == "B":
        parts.append(Paragraph(
            "SSL/TLS configuration is acceptable but has room for improvement. Encryption is in place, "
            "though minor configuration changes could strengthen the overall posture.",
            S["body"]))
    elif grade in ("C", "D"):
        parts.append(Paragraph(
            "The SSL/TLS configuration has notable weaknesses. While basic encryption is present, legacy protocols "
            "or weak cipher suites may allow sophisticated attackers to intercept or downgrade encrypted connections.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "SSL/TLS configuration is poor or could not be fully assessed. Without strong encryption, "
            "data transmitted between users and the server is at risk of interception (man-in-the-middle attacks).",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))

    # Build dynamic recommendations
    recs = []
    if legacy:
        recs.append("Disable TLS 1.0 and TLS 1.1 — these legacy protocols have known vulnerabilities and are no longer considered secure.")
    if cip.get("is_weak"):
        recs.append("Replace weak cipher suites with modern alternatives (AES-256-GCM, ChaCha20-Poly1305).")
    if not ssl.get("hsts"):
        recs.append("Enable HTTP Strict Transport Security (HSTS) to prevent protocol downgrade attacks.")
    if days_left and isinstance(days_left, (int, float)) and days_left < 30:
        recs.append(f"Certificate expires in {int(days_left)} days — renew immediately to prevent service disruption and browser warnings.")
    if not recs:
        recs.append("Maintain current configuration and monitor for newly deprecated protocols or cipher suites.")
    parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    for i, r in enumerate(recs, 1):
        parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "Email authentication is well configured — SPF, DKIM, and DMARC are in place." if score >= 8 else "Email authentication gaps increase susceptibility to phishing and spoofing attacks."
    parts = build_cat_card("Email Authentication (SPF/DKIM/DMARC)", col, f"Score {score}/10", rows, em.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 8:
        parts.append(Paragraph(
            "Email authentication is well configured. SPF, DKIM, and DMARC work together to prevent attackers from "
            "sending emails that appear to come from your domain (email spoofing). This is one of the most effective "
            "defences against business email compromise (BEC) and phishing attacks targeting your staff or clients.",
            S["body"]))
    elif score >= 5:
        parts.append(Paragraph(
            "Email authentication is partially configured. Some protections are in place, but gaps remain that "
            "could allow attackers to spoof emails from your domain. Phishing emails impersonating your organisation "
            "could reach clients, partners, or staff inboxes without being flagged.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Email authentication is weak or misconfigured. Without proper SPF, DKIM, and DMARC records, "
            "anyone can send emails that appear to come from your domain. This makes your organisation a prime "
            "target for business email compromise (BEC) — the most financially damaging category of cybercrime.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    recs = []
    if not spf.get("present"):
        recs.append("Publish an SPF record to specify which mail servers are authorised to send email on behalf of your domain.")
    elif spf.get("dangerous"):
        recs.append("URGENT: Your SPF record uses '+all' which allows ANY server to send as your domain — change to '-all' or '~all'.")
    if not dm.get("present"):
        recs.append("Configure a DMARC record with at minimum p=quarantine to instruct receiving servers to flag spoofed emails.")
    elif dm.get("policy") == "none":
        recs.append("Upgrade DMARC policy from 'none' (monitor only) to 'quarantine' or 'reject' to actively block spoofed emails.")
    if not dkim.get("selectors_found"):
        recs.append("Enable DKIM signing on your mail server to cryptographically verify that emails originate from your domain.")
    if recs:
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_email_hardening(d, S):
    eh   = d.get("email_hardening", {})
    mts  = eh.get("mta_sts", {})
    bimi = eh.get("bimi", {})
    dane = eh.get("dane", {})
    tlsrpt = eh.get("tls_rpt", {})
    score= eh.get("score", 0)
    col  = _tl(score >= 7, score >= 3)
    rows = [
        ("MTA-STS", f"Present — mode: {mts.get('mode','?')}" if mts.get("present") else "Not configured"),
        ("BIMI",    "Present" + (" + VMC" if bimi.get("has_vmc") else "") if bimi.get("present") else "Not configured"),
        ("DANE/TLSA", "Present" if dane.get("present") else "Not configured"),
        ("TLS-RPT", f"Present — reports to: {tlsrpt.get('rua','?')}" if tlsrpt.get("present") else "Not configured"),
        ("Score",   f"{score}/10"),
    ]
    fb = "Advanced email protections are well configured." if score >= 7 else "Advanced email hardening (MTA-STS, DANE, BIMI) is partially or not configured — these controls help prevent email interception."
    parts = build_cat_card("Advanced Email Hardening (MTA-STS/DANE/BIMI)", col, f"Score {score}/10", rows, eh.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 7:
        parts.append(Paragraph(
            "Advanced email hardening controls are in place. MTA-STS enforces encrypted email transport, "
            "DANE/TLSA provides certificate pinning for mail servers, and BIMI displays your verified brand logo "
            "in recipients' inboxes — increasing trust and reducing phishing susceptibility.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Advanced email hardening is not fully configured. These are next-generation email security controls "
            "that go beyond basic SPF/DKIM/DMARC. While not yet widely adopted, they provide meaningful additional "
            "protection against email interception and brand impersonation.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    recs = []
    if not mts.get("present"):
        recs.append("Configure MTA-STS to enforce TLS encryption for inbound email, preventing downgrade attacks.")
    if not dane.get("present"):
        recs.append("Implement DANE/TLSA records if your DNS provider supports DNSSEC — this pins your mail server certificates.")
    if not bimi.get("present"):
        recs.append("Set up BIMI to display your brand logo in email clients — this helps recipients identify legitimate emails from your domain.")
    if not tlsrpt.get("present"):
        recs.append("Configure TLS-RPT (RFC 8460) to receive reports about email TLS delivery failures — helps detect MitM attacks on email transport.")
    if recs:
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_headers(d, S):
    hh    = d.get("http_headers", {})
    score = hh.get("score", 0)
    col   = _tl(score >= 80, score >= 50)
    rows  = [(name, "Present" if data.get("present") else "MISSING")
             for name, data in hh.get("headers", {}).items()]
    # CSP quality detail
    csp_q = hh.get("csp_quality")
    if csp_q:
        rows.append(("", ""))
        rows.append(("CSP Quality Score", f"{csp_q.get('score', 0)}/100"))
        if csp_q.get("dangerous"):
            for d_item in csp_q["dangerous"][:3]:
                rows.append(("  CSP Issue", d_item))
        if csp_q.get("missing_critical"):
            rows.append(("  Missing directives", ", ".join(csp_q["missing_critical"])))
    fb = "All recommended security headers are present." if score >= 80 else f"Only {score}% of recommended security headers are configured — missing headers leave the site vulnerable to clickjacking, XSS, and data injection."
    parts = build_cat_card("HTTP Security Headers", col, f"{score}% coverage", rows, hh.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 80:
        parts.append(Paragraph(
            "Security headers are well configured. These HTTP response headers instruct browsers to enforce "
            "security policies, preventing common web attacks such as clickjacking, cross-site scripting (XSS), "
            "and content injection.",
            S["body"]))
    else:
        missing = [name for name, data in hh.get("headers", {}).items() if not data.get("present")]
        parts.append(Paragraph(
            f"Only {score}% of recommended security headers are present. Missing headers "
            f"({', '.join(missing[:4])}{' and more' if len(missing) > 4 else ''}) leave the website "
            "vulnerable to browser-based attacks. These headers are free to implement and require only "
            "web server configuration changes.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score < 80:
        parts.append(Paragraph("1. Add missing security headers to your web server configuration (Apache, Nginx, or CDN).", S["body"]))
        parts.append(Paragraph("2. Prioritise Content-Security-Policy (CSP) and X-Frame-Options as they prevent the most common attacks.", S["body"]))
        parts.append(Paragraph("3. Test header changes using securityheaders.com before deploying to production.", S["body"]))
    else:
        parts.append(Paragraph("1. Maintain current header configuration and review periodically for new recommended headers.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_waf(d, S):
    waf = d.get("waf", {})
    col = C_GREEN if waf.get("detected") else C_AMBER
    rows = [
        ("WAF detected",  waf.get("waf_name", "None detected") if waf.get("detected") else "Not detected"),
        ("All detected",  ", ".join(waf.get("all_detected", [])) or "—"),
    ]
    fb = "Web application firewall is in place, providing protection against common web attacks." if waf.get("detected") else "No web application firewall detected — the site has no automated protection against SQL injection, XSS, or DDoS attacks."
    parts = build_cat_card("WAF / DDoS Protection", col, "Detected" if waf.get("detected") else "Not detected", rows, waf.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if waf.get("detected"):
        parts.append(Paragraph(
            f"A web application firewall ({waf.get('waf_name', 'WAF')}) was detected protecting this website. "
            "WAFs filter malicious traffic before it reaches the web application, blocking common attacks such as "
            "SQL injection, cross-site scripting, and automated bot activity. This significantly reduces the "
            "attack surface exposed to the internet.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No web application firewall was detected. Without a WAF, the website is directly exposed to automated "
            "attack tools that scan for and exploit web application vulnerabilities. This is one of the most "
            "cost-effective security controls available and is strongly recommended.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    if not waf.get("detected"):
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Deploy a cloud-based WAF such as Cloudflare, AWS WAF, or Akamai — these can be enabled without infrastructure changes.", S["body"]))
        parts.append(Paragraph("2. Enable DDoS protection to prevent volumetric attacks from taking the website offline.", S["body"]))
        parts.append(Paragraph("3. Configure WAF rules to block OWASP Top 10 attack patterns as a minimum baseline.", S["body"]))
        parts.append(Spacer(1, 3 * mm))
    else:
        parts.append(Spacer(1, 1 * mm))
    return parts


def cat_dns(d, S):
    dns  = d.get("dns_infrastructure", {})
    ports= dns.get("open_ports", [])
    high = [p for p in ports if p.get("risk") == "high"]
    col  = _tl(len(high) == 0 and len(ports) <= 2, len(high) == 0)
    port_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports) or "None"
    zt = dns.get("zone_transfer", {})
    rows = [
        ("Open ports",    port_str),
        ("High-risk ports", ", ".join(f"{p['port']}/{p['service']}" for p in high) or "None"),
        ("Server header", dns.get("server_info", {}).get("Server", "—")),
        ("Reverse DNS",   dns.get("reverse_dns") or "—"),
        ("Zone transfer (AXFR)", f"VULNERABLE — {zt.get('records_leaked',0)} records leaked via {', '.join(zt.get('vulnerable_ns',[]))}" if zt.get("vulnerable") else ("Protected" if zt.get("tested") else "Not tested")),
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
    fb = "Minimal attack surface — only essential ports are exposed." if len(high) == 0 and len(ports) <= 2 else (f"{len(high)} high-risk port(s) exposed — each is a potential entry point for attackers." if high else f"{len(ports)} ports open — review whether all exposed services are necessary.")
    parts = build_cat_card("DNS & Open Ports", col, f"{len(ports)} open port(s)", rows, dns.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if len(ports) <= 2 and not high:
        parts.append(Paragraph(
            "Only essential services (typically HTTP/HTTPS) are exposed to the internet. A minimal attack surface "
            "means fewer entry points for attackers to probe, significantly reducing the risk of unauthorised access.",
            S["body"]))
    elif high:
        high_names = ", ".join(f"{p['port']}/{p['service']}" for p in high[:4])
        parts.append(Paragraph(
            f"High-risk ports are exposed to the internet ({high_names}). These services are frequently targeted "
            "by automated attack tools and ransomware operators. Exposed database ports (MySQL, PostgreSQL, MongoDB) "
            "and remote access services (RDP, SSH, FTP) are among the top initial access vectors in cyber incidents.",
            S["body"]))
    else:
        parts.append(Paragraph(
            f"{len(ports)} ports are open on this server. While no high-risk ports were identified, each open port "
            "represents a potential attack vector. Regular review ensures only necessary services remain exposed.",
            S["body"]))
    parts.append(Spacer(1, 2 * mm))
    if high or len(ports) > 5:
        recs = []
        if high:
            recs.append("Close or firewall high-risk ports that do not need public internet access. Use VPN for remote administration.")
        if any(p['port'] == 3306 for p in ports):
            recs.append("MySQL (port 3306) should never be exposed to the internet — restrict to localhost or private network.")
        if any(p['port'] == 21 for p in ports):
            recs.append("Replace FTP (port 21) with SFTP — FTP transmits credentials in cleartext.")
        if len(ports) > 5:
            recs.append("Review all open ports and close any services that are not required for business operations.")
        if not recs:
            recs.append("Conduct regular port audits and close unnecessary services to reduce attack surface.")
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        for i, r in enumerate(recs, 1):
            parts.append(Paragraph(f"{i}. {r}", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "No high-risk database or remote access services are publicly exposed." if not svcs else f"{len(svcs)} critical service(s) directly accessible from the internet — immediate remediation required."
    parts = build_cat_card("Database & Service Exposure", col,
                          f"{len(svcs)} critical exposure(s)", rows, hrp.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if svcs:
        svc_names = ", ".join(s['service'] for s in svcs[:4])
        parts.append(Paragraph(
            f"Critical services ({svc_names}) are directly accessible from the internet. "
            "These services should never be publicly exposed — they are primary targets for automated attack tools "
            "and ransomware operators. Exposed databases risk complete data exfiltration, while remote access "
            "services are routinely brute-forced to gain initial network access.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Immediately firewall all exposed database and remote access ports from public internet access.", S["body"]))
        parts.append(Paragraph("2. Use a VPN or SSH tunnel for any remote administration requirements.", S["body"]))
        parts.append(Paragraph("3. Audit server firewall rules to ensure only web traffic (ports 80/443) is publicly accessible.", S["body"]))
    else:
        parts.append(Paragraph(
            "No critical database or remote access services are exposed to the public internet. "
            "This is a strong indicator of proper network segmentation and firewall configuration.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_cloud(d, S):
    cdn = d.get("cloud_cdn", {})
    rows = [
        ("Provider",     cdn.get("provider") or "Not detected"),
        ("CDN detected", "Yes" if cdn.get("cdn_detected") else "No"),
        ("Hosting type", cdn.get("hosting_type", "Unknown")),
        ("IP addresses", ", ".join(cdn.get("ip_addresses", [])) or "—"),
    ]
    fb = "Cloud and CDN infrastructure detected — provides caching and basic DDoS mitigation." if cdn.get("cdn_detected") else "No CDN detected — the origin server is directly exposed, increasing latency and DDoS risk."
    parts = build_cat_card("Cloud & CDN Infrastructure", C_BLUE, cdn.get("provider") or "Unknown", rows, cdn.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if cdn.get("cdn_detected"):
        parts.append(Paragraph(
            f"A CDN ({cdn.get('provider', 'content delivery network')}) is in use, which provides performance "
            "benefits (faster page loads) and basic security protections (DDoS mitigation, origin IP masking). "
            "CDNs act as a reverse proxy, meaning attackers interact with the CDN edge servers rather than "
            "your origin infrastructure directly.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No content delivery network (CDN) was detected. The origin server IP address is directly exposed, "
            "which means attackers can target the server directly with DDoS attacks or attempt to exploit "
            "web server vulnerabilities without CDN-layer filtering.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_vpn(d, S):
    vpn = d.get("vpn_remote", {})
    col = C_CRITICAL if vpn.get("rdp_exposed") else (C_GREEN if vpn.get("vpn_detected") else C_AMBER)
    rows = [
        ("RDP exposed",  "YES — CRITICAL" if vpn.get("rdp_exposed") else "No"),
        ("VPN detected", vpn.get("vpn_name") or ("Detected" if vpn.get("vpn_detected") else "Not detected")),
    ]
    fb = "CRITICAL: RDP is exposed to the internet — this is the #1 ransomware entry vector." if vpn.get("rdp_exposed") else ("VPN gateway detected — verify MFA is enforced on all remote access." if vpn.get("vpn_detected") else "No VPN/remote access gateway detected — remote access method unknown.")
    parts = build_cat_card("VPN & Remote Access", col,
                          "RDP EXPOSED" if vpn.get("rdp_exposed") else (vpn.get("vpn_name") or "None detected"),
                          rows, vpn.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if vpn.get("rdp_exposed"):
        parts.append(Paragraph(
            "Remote Desktop Protocol (RDP) is exposed directly to the internet. RDP is the single most common "
            "entry point for ransomware attacks — automated tools continuously scan the internet for open RDP ports "
            "and attempt brute-force login. Once access is gained, attackers can deploy ransomware across "
            "the entire network within hours.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. IMMEDIATE: Block RDP (port 3389) from public internet access at the firewall.", S["body"]))
        parts.append(Paragraph("2. Require VPN connection before RDP access is permitted.", S["body"]))
        parts.append(Paragraph("3. Enable Network Level Authentication (NLA) and enforce MFA on all RDP sessions.", S["body"]))
        parts.append(Paragraph("4. Review RDP access logs for signs of brute-force attempts or unauthorised logins.", S["body"]))
    elif vpn.get("vpn_detected"):
        parts.append(Paragraph(
            f"A VPN gateway ({vpn.get('vpn_name', 'VPN')}) was detected, which is positive — it indicates remote "
            "access is channelled through an encrypted tunnel rather than being directly exposed. Ensure multi-factor "
            "authentication (MFA) is enforced on the VPN and that the VPN firmware is kept up to date, as VPN "
            "appliance vulnerabilities are frequently exploited by ransomware groups.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No VPN or remote access gateway was detected from external scanning. This could mean remote access "
            "is handled through a cloud-based solution (e.g. Azure AD, Zscaler) that doesn't expose a public gateway, "
            "or that no remote access infrastructure exists. Verify how staff access internal systems remotely.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "No breaches found in Have I Been Pwned — no known credential exposure for this domain." if count == 0 else f"{count} breach(es) found — staff credentials may have been exposed. Password resets and MFA enforcement recommended."
    parts = build_cat_card("Credential Exposure (HIBP)", col, f"{count} breach(es)", rows, br.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if count == 0:
        parts.append(Paragraph(
            "No known data breaches were found for email addresses on this domain in the Have I Been Pwned database. "
            "This database tracks over 700 publicly disclosed breaches. A clean result is a positive indicator, "
            "though it does not guarantee zero exposure — some breaches are not publicly disclosed.",
            S["body"]))
    else:
        data_types = ", ".join(br.get("data_classes", [])[:4]) or "various data types"
        parts.append(Paragraph(
            f"This domain appears in {count} known data breach(es), exposing {data_types}. "
            "When staff credentials appear in breaches, attackers use automated tools to test those passwords "
            "against other services (credential stuffing). If employees reuse passwords across work and personal "
            "accounts, a breach on one service can lead to compromise of corporate systems.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Force password resets for all staff email accounts, prioritising those in the most recent breaches.", S["body"]))
        parts.append(Paragraph("2. Enable multi-factor authentication (MFA) on all accounts to prevent credential stuffing.", S["body"]))
        parts.append(Paragraph("3. Implement a password policy that prevents reuse of previously breached passwords.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dnsbl(d, S):
    bl  = d.get("dnsbl", {})
    all_listed = bl.get("ip_listings", []) + bl.get("domain_listings", [])
    col = C_CRITICAL if all_listed else C_GREEN
    rows = [
        ("IP blacklists",     ", ".join(bl.get("ip_listings", [])) or "Clean"),
        ("Domain blacklists", ", ".join(bl.get("domain_listings", [])) or "Clean"),
        ("Status",            "BLACKLISTED" if all_listed else "Not listed"),
    ]
    fb = "Domain/IP is blacklisted — emails may be blocked and reputation is compromised." if all_listed else "Not listed on any checked blacklists — domain reputation is clean."
    parts = build_cat_card("IP / Domain Reputation (DNSBL)", col,
                          "Blacklisted" if all_listed else "Clean", rows, bl.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if all_listed:
        lists = ", ".join(all_listed[:4])
        parts.append(Paragraph(
            f"This domain or IP is listed on security blacklists ({lists}). Blacklisting typically occurs when "
            "an IP has been associated with spam, malware distribution, or other malicious activity. This can cause "
            "email deliverability issues (emails going to spam/junk folders) and may indicate that the server has "
            "been compromised and is being used for malicious purposes.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Investigate why the IP/domain was blacklisted — check for compromised accounts sending spam.", S["body"]))
        parts.append(Paragraph("2. Submit delisting requests to each blacklist provider after resolving the underlying issue.", S["body"]))
        parts.append(Paragraph("3. Monitor email deliverability and set up alerts for future blacklist appearances.", S["body"]))
    else:
        parts.append(Paragraph(
            "This domain and its IP addresses are not listed on any of the checked DNS-based blacklists. "
            "A clean reputation means emails from this domain are less likely to be flagged as spam, and "
            "the IP has not been associated with known malicious activity.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_admin(d, S):
    adm   = d.get("exposed_admin", {})
    exposed = adm.get("exposed", [])
    col   = C_CRITICAL if adm.get("critical_count", 0) > 0 else (C_RED if adm.get("high_count", 0) > 0 else C_GREEN)
    rows  = [(e["path"], f"HTTP {e['status']} — {e['risk'].upper()}") for e in exposed[:8]] or [("Status", "No sensitive paths exposed")]
    fb = f"{len(exposed)} admin or sensitive path(s) accessible from the internet — restrict access via IP whitelisting or VPN." if exposed else "No sensitive admin panels or configuration paths detected on the public website."
    parts = build_cat_card("Exposed Admin Panels & Sensitive Paths", col,
                          f"{len(exposed)} path(s) found", rows, adm.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if exposed:
        crit_count = adm.get("critical_count", 0)
        parts.append(Paragraph(
            f"{len(exposed)} sensitive path(s) were found accessible from the public internet"
            f"{f', including {crit_count} critical exposure(s)' if crit_count else ''}. "
            "Exposed admin panels, configuration files, and development tools give attackers direct insight into "
            "the application's architecture and may provide authentication bypass or default credential opportunities.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Restrict access to admin panels using IP whitelisting, VPN, or network-level access controls.", S["body"]))
        parts.append(Paragraph("2. Remove or rename default admin paths (/admin, /wp-admin, /phpmyadmin) where possible.", S["body"]))
        parts.append(Paragraph("3. Ensure all admin interfaces require strong authentication with MFA enabled.", S["body"]))
    else:
        parts.append(Paragraph(
            "No sensitive admin panels, configuration files, or development tools were found accessible from "
            "the public internet. This reduces the risk of attackers discovering administrative entry points.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_subdomains(d, S):
    subs  = d.get("subdomains", {})
    risky = subs.get("risky_subdomains", [])
    takeover = subs.get("takeover_vulnerable", [])
    col   = C_CRITICAL if takeover else (C_AMBER if risky else C_GREEN)
    rows  = [
        ("Total subdomains", subs.get("total_count", 0)),
        ("Risky subdomains", len(risky)),
        ("Risky names",      ", ".join(risky[:6]) or "None"),
        ("Takeover vulnerable", f"{len(takeover)} CRITICAL" if takeover else "None detected"),
    ]
    for tv in takeover[:5]:
        rows.append((f"  {tv.get('subdomain','')}", f"CNAME → {tv.get('cname_target','')} ({tv.get('service','')}) — TAKEOVER POSSIBLE"))
    fb = f"{len(risky)} subdomain(s) with risky names (e.g. dev, staging, admin) — verify these are not publicly accessible." if risky else f"{subs.get('total_count',0)} subdomain(s) discovered — none flagged as risky."
    parts = build_cat_card("Subdomain Exposure (CT Logs)", col,
                          f"{subs.get('total_count',0)} found, {len(risky)} risky",
                          rows, subs.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    total = subs.get("total_count", 0)
    if risky:
        risky_list = ", ".join(risky[:5])
        parts.append(Paragraph(
            f"{total} subdomain(s) were discovered via Certificate Transparency logs, of which {len(risky)} "
            f"have potentially sensitive names ({risky_list}). Subdomains named 'dev', 'staging', 'test', or 'admin' "
            "often run with weaker security controls and may expose internal tools, unpatched software, or "
            "debug interfaces that attackers can exploit as an alternative entry point.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Restrict access to development and staging subdomains using IP whitelisting or VPN.", S["body"]))
        parts.append(Paragraph("2. Ensure non-production subdomains do not contain real customer data.", S["body"]))
        parts.append(Paragraph("3. Apply the same security standards (HTTPS, authentication, patching) to all subdomains.", S["body"]))
    else:
        parts.append(Paragraph(
            f"{total} subdomain(s) were discovered via Certificate Transparency logs. None have names that suggest "
            "exposed development, staging, or administrative environments. This is a positive indicator of "
            "controlled subdomain management.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{len(eols)} end-of-life component(s) detected — these no longer receive security patches and are vulnerable to known exploits." if eols else "No end-of-life software detected — technology stack appears current."
    parts = build_cat_card("Technology Stack & EOL Software", col,
                          f"{len(eols)} EOL component(s)", rows, ts.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if eols:
        eol_names = ", ".join(e["software"] for e in eols[:3])
        parts.append(Paragraph(
            f"End-of-life software ({eol_names}) was detected. Software that has reached end-of-life no longer "
            "receives security patches from the vendor, meaning any newly discovered vulnerabilities will remain "
            "permanently unpatched. Attackers specifically target EOL software because exploits are reliable "
            "and will never be fixed.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Upgrade all end-of-life software to currently supported versions.", S["body"]))
        parts.append(Paragraph("2. If immediate upgrade is not possible, isolate EOL systems behind a WAF and restrict access.", S["body"]))
        parts.append(Paragraph("3. Establish a software lifecycle management process to track vendor support timelines.", S["body"]))
    else:
        parts.append(Paragraph(
            "No end-of-life software was detected in the externally visible technology stack. All identified "
            "components appear to be within their vendor support lifecycle, meaning security patches are available.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "Domain registration details are healthy — established domain with no age-related risk flags." if not di.get("issues") and age and age > 365 else "Review domain registration — new or expiring domains increase phishing and impersonation risk."
    parts = build_cat_card("Domain Intelligence (WHOIS)", col,
                          f"Age: {round(age/365,1)}y" if age else "Unknown",
                          rows, di.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if age and age > 730:
        parts.append(Paragraph(
            f"This domain has been registered for {round(age/365,1)} years, indicating an established web presence. "
            "Older domains generally have higher trust scores with email providers and search engines. "
            "Domain age is used by underwriters as a proxy for business maturity.",
            S["body"]))
    elif age and age < 365:
        parts.append(Paragraph(
            f"This domain is less than one year old ({round(age/365,1)} years). Newly registered domains are "
            "statistically more likely to be associated with fraud or phishing. From an underwriting perspective, "
            "domain age below 1 year is a risk factor worth noting.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Domain registration details provide context about the organisation's online presence maturity. "
            "Registration information, expiry dates, and WHOIS privacy settings all contribute to overall "
            "domain trust assessment.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "Vulnerability disclosure policy is published — demonstrates mature security practices." if stxt.get("present") else "No security.txt or vulnerability disclosure policy found — makes responsible reporting of security issues difficult."
    parts = build_cat_card("Security Policy & Vulnerability Disclosure", col,
                          "VDP present" if stxt.get("present") else "No VDP", rows, sp.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if stxt.get("present"):
        parts.append(Paragraph(
            "A security.txt file or vulnerability disclosure policy (VDP) is published. This is an industry "
            "best practice that provides security researchers with a responsible way to report vulnerabilities "
            "they discover. Organisations with a VDP typically learn about and fix security issues faster.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No security.txt file or vulnerability disclosure policy was found. Without a published VDP, security "
            "researchers who discover vulnerabilities have no official channel to report them. This can result in "
            "issues going unreported or being disclosed publicly before the organisation can respond.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Create a security.txt file at /.well-known/security.txt with a contact email for security reports.", S["body"]))
        parts.append(Paragraph("2. Consider establishing a formal Vulnerability Disclosure Policy (VDP) on your website.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_payment(d, S):
    pay = d.get("payment_security", {})
    col = C_CRITICAL if pay.get("self_hosted_payment_form") else (C_AMBER if pay.get("has_payment_page") and not pay.get("payment_page_https") else C_GREEN)
    rows = [
        ("Payment page",         "Detected" if pay.get("has_payment_page") else "Not found"),
        ("Payment provider",     pay.get("payment_provider") or ("Self-hosted — PCI RISK" if pay.get("self_hosted_payment_form") else "Unknown")),
        ("Page HTTPS",           "Yes" if pay.get("payment_page_https") else ("N/A" if not pay.get("has_payment_page") else "NO — CRITICAL")),
        ("Self-hosted card form", "YES — PCI risk" if pay.get("self_hosted_payment_form") else "No"),
    ]
    fb = "CRITICAL: Self-hosted payment form detected — PCI DSS compliance risk. Use a tokenised payment provider." if pay.get("self_hosted_payment_form") else ("Payment processing uses a recognised third-party provider — reduces PCI scope." if pay.get("has_payment_page") else "No payment page detected on this domain.")
    parts = build_cat_card("Payment Security (PCI)", col,
                          pay.get("payment_provider") or ("PCI Risk" if pay.get("self_hosted_payment_form") else "N/A"),
                          rows, pay.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if pay.get("self_hosted_payment_form"):
        parts.append(Paragraph(
            "A self-hosted payment form was detected, meaning card data may be processed directly on this server. "
            "This significantly increases PCI DSS compliance scope and liability. If cardholder data is compromised, "
            "the organisation faces regulatory penalties, card brand fines, and reputational damage.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. URGENT: Migrate to a tokenised payment provider (Stripe, PayFast, PayGate) that handles card data externally.", S["body"]))
        parts.append(Paragraph("2. Ensure the payment page is served exclusively over HTTPS with a valid certificate.", S["body"]))
        parts.append(Paragraph("3. If self-hosting is required, engage a PCI QSA (Qualified Security Assessor) for formal compliance assessment.", S["body"]))
    elif pay.get("has_payment_page"):
        parts.append(Paragraph(
            f"Payment processing is handled by {pay.get('payment_provider', 'a third-party provider')}, "
            "which significantly reduces PCI DSS compliance scope. The organisation does not appear to directly "
            "handle or store cardholder data.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No payment processing functionality was detected on this website. If the organisation does not "
            "process online payments, this check is not applicable.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_shodan(d, S):
    sv    = d.get("shodan_vulns", {})
    crit  = sv.get("critical_count", 0)
    high  = sv.get("high_count", 0)
    med   = sv.get("medium_count", 0)
    low   = sv.get("low_count", 0)
    total = crit + high + med + low
    col   = C_CRITICAL if crit > 0 else (C_RED if high > 0 else (C_AMBER if med > 0 else C_GREEN))
    source = "Full API" if sv.get("data_source") == "shodan_full_api" else "InternetDB"
    # Include OSV-enriched CVEs in total if available
    osv_total = d.get("osv_vulns", {}).get("total_vulns", 0)
    display_total = max(total, osv_total) if osv_total > 0 else total
    summary = f"{display_total} CVE(s)" if display_total > 0 else ("No CVEs detected" if total == 0 else "Clean")

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

    fb = f"{display_total} known vulnerabilit{'y' if display_total == 1 else 'ies'} detected — review severity breakdown above for patching priority." if display_total > 0 else "No known CVEs detected for this IP — infrastructure appears patched and current."
    parts = build_cat_card("CVE / Known Vulnerabilities", col, summary, rows, sv.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    wpn = sv.get("weaponized_count", 0)
    if crit > 0 or wpn > 0:
        parts.append(Paragraph(
            f"{'Critical' if crit > 0 else 'Weaponized'} vulnerabilities were detected on this infrastructure. "
            "These are known security flaws in the software running on this server that have publicly available "
            "exploit code. Attackers use automated tools to scan for and exploit these vulnerabilities — often within "
            "hours of public disclosure. Unpatched critical CVEs are the leading cause of data breaches globally.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. URGENT: Patch all critical and weaponized CVEs immediately — these have known exploit code in active use.", S["body"]))
        parts.append(Paragraph("2. Establish a patch management policy with defined SLAs (critical: 48hrs, high: 7 days, medium: 30 days).", S["body"]))
        parts.append(Paragraph("3. Subscribe to vendor security advisories for all deployed software.", S["body"]))
    elif high > 0:
        parts.append(Paragraph(
            f"{high} high-severity CVE(s) were detected. While no critical or weaponized exploits were found, "
            "high-severity vulnerabilities can still be chained together by skilled attackers to achieve "
            "significant impact. Timely patching remains essential.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Schedule patching for all high-severity CVEs within 7 days.", S["body"]))
        parts.append(Paragraph("2. Monitor EPSS scores — if any high CVE's exploitation probability increases, escalate to critical priority.", S["body"]))
    elif display_total > 0:
        parts.append(Paragraph(
            f"{display_total} CVE(s) of medium or low severity were detected. These represent known weaknesses "
            "but are less likely to be exploited in isolation. Address during regular maintenance cycles.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No known CVEs were detected for the software versions running on this infrastructure. "
            "This suggests the server software is up to date with current security patches — a strong positive indicator.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    cb = dh.get("credential_breakdown", {})
    rows = [
        ("Status",        status_text),
        ("Total records", total),
        ("Unique emails", dh.get("unique_emails", 0)),
        ("Passwords in leaks", "Yes — CRITICAL" if dh.get("has_passwords") else "No"),
    ]
    if cb:
        rows.append(("Plaintext passwords", f"{cb.get('plaintext_count', 0)} — IMMEDIATE RISK" if cb.get('plaintext_count') else "0"))
        rows.append(("Hashed credentials", f"{cb.get('hashed_count', 0)} ({', '.join(f'{k}: {v}' for k, v in cb.get('hash_types', {}).items())})" if cb.get('hashed_count') else "0"))
        rows.append(("Weak hashes (MD5/SHA-1)", f"{cb.get('weak_hash_count', 0)} — easily crackable" if cb.get('weak_hash_count') else "0"))
        rows.append(("Corporate vs Personal", f"{cb.get('corporate_count', 0)} corporate | {cb.get('personal_count', 0)} personal"))
    if dh.get("sample_emails"):
        rows.append(("Affected emails", " | ".join(dh["sample_emails"][:5])))
    if dh.get("breach_sources"):
        rows.append(("Breach sources", " | ".join(dh["breach_sources"][:8])))
    fb = f"{total} credential record(s) found in leak databases — see breach details below." if total > 0 else ("Dehashed API unavailable — credential leak check could not be completed." if is_error else "No leaked credentials found in Dehashed databases for this domain.")
    parts = build_cat_card("Dehashed Credential Leaks", col, summary, rows, dh.get("issues", []), S, fallback=fb)

    # Breach details OUTSIDE the table
    details = dh.get("breach_details", [])
    if details:
        parts.append(Paragraph("<b>Breach Details</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        detail_lines = []
        for i, det in enumerate(details[:10]):
            pw_flag = " [PASSWORD EXPOSED]" if det.get("has_password") else (" [HASH EXPOSED]" if det.get("has_hash") else "")
            user_str = f" (user: {det['username']})" if det.get("username") else ""
            detail_lines.append(f"{det.get('database', 'Unknown')}: {det.get('email', 'N/A')}{user_str}{pw_flag}")
        if len(details) > 10:
            detail_lines.append(f"...and {len(details) - 10} more records")
        for line in detail_lines:
            parts.append(Paragraph(f"\u2022 {line}", S["body"]))
        parts.append(Spacer(1, 2 * mm))

    # Remediation advice OUTSIDE the table
    if total > 0:
        parts.append(Paragraph("<b>Remediation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Force password resets for all identified email addresses across all company systems.", S["body"]))
        parts.append(Paragraph("2. Enable multi-factor authentication on all accounts, especially those with exposed credentials.", S["body"]))
        parts.append(Paragraph("3. Enroll in continuous breach monitoring to detect future exposures.", S["body"]))
        if dh.get("has_passwords"):
            parts.append(Paragraph("4. CRITICAL: Plaintext passwords found — audit all systems for password reuse immediately.", S["body"]))
        parts.append(Spacer(1, 2 * mm))
    parts.append(Spacer(1, 1 * mm))
    return parts


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
    fb = "ACTIVE infostealer infection detected — credentials are being exfiltrated in real-time." if employees > 0 else ("Third-party supply chain exposure detected via compromised vendor credentials." if third > 0 else "No infostealer infections detected across employee or user devices.")
    parts = build_cat_card("Infostealer Detection (Hudson Rock)", col, summary, rows, hr.get("issues", []), S, fallback=fb)

    # Narrative interpretation OUTSIDE the table
    if employees > 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "Employee devices are ACTIVELY infected with infostealer malware (Raccoon, RedLine, Vidar). "
            "Credentials are being exfiltrated in real-time and sold on dark web markets. "
            "Immediate incident response required: isolate devices, force password resets, engage forensics.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
    elif third > 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "Third-party supply chain exposure detected. A vendor or partner connected to this domain "
            "has compromised credentials. Review shared access and enforce MFA on all integrations.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
    elif total == 0 and third == 0:
        parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "No active infostealer infections detected on employee or user devices. "
            "This indicates healthy endpoint security posture.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if employees > 0:
        parts.append(Paragraph(
            "Infostealer malware (such as RedLine, Raccoon, or Vidar) has been detected on devices "
            "belonging to employees of this organisation. This type of malware silently runs in the background "
            "and captures everything — saved passwords from web browsers, banking credentials, email logins, "
            "VPN access details, and even session cookies that allow attackers to bypass MFA. "
            "The stolen data is automatically uploaded to criminal servers and sold within hours. "
            "This is not a historical breach — it indicates CURRENT, ACTIVE compromise.",
            S["body"]))
    elif third > 0:
        parts.append(Paragraph(
            "A third-party vendor or partner connected to this organisation has been found in infostealer databases. "
            "This means a supplier, contractor, or service provider who interacts with your systems has had their "
            "credentials stolen. Attackers frequently use compromised vendor access as a backdoor into larger "
            "organisations (supply chain attacks). Review all shared access and API integrations with external partners.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No infostealer infections were detected. This check scans a database of over 34 million compromised "
            "devices worldwide. A clean result means no employee or user devices associated with this domain "
            "appear in known infostealer databases. This is a positive security indicator.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{darkweb} dark web mention(s) found — stolen data may be actively traded on criminal forums." if darkweb > 0 else (f"{total} reference(s) found in leak databases — see interpretation below." if total > 0 else "No references found on dark web forums or leak databases.")
    parts = build_cat_card("Dark Web Monitoring (IntelX)", col, summary, rows, ix.get("issues", []), S, fallback=fb)

    # Plain-English interpretation OUTSIDE the table
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if darkweb > 0:
        parts.append(Paragraph(
            f"We found {darkweb} mention(s) of this domain on dark web criminal forums. "
            "This means stolen data (login credentials, personal information, or internal documents) "
            "associated with your organisation is actively being bought and sold by cybercriminals. "
            "This is a strong indicator of elevated cyber risk and potential for targeted attacks.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Action</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "1. Immediately force password resets for all staff accounts. "
            "2. Enable multi-factor authentication (MFA) on all systems. "
            "3. Engage a forensic investigator to determine the source of the leak. "
            "4. Notify affected individuals as required under POPIA Section 22.",
            S["body"]))
    elif total > 0:
        parts.append(Paragraph(
            f"We found {total} reference(s) to this domain in dark web leak databases. "
            "These entries are typically 'infostealer logs' — records created when malware on someone's "
            "computer silently captures everything they type, including passwords and banking details. "
            "The stolen data is then packaged and uploaded to criminal databases where it can be "
            "purchased by other attackers.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph(
            "In simple terms: someone who has (or had) login access to your systems had their "
            "personal device infected with spyware. The passwords they used for your systems may now "
            "be in criminal hands.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Action</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(
            "1. Force password resets for all staff, especially those using personal devices. "
            "2. Enable MFA — even if passwords are stolen, MFA prevents unauthorised access. "
            "3. Consider endpoint security solutions (antivirus, EDR) for all devices accessing company systems. "
            "4. Educate staff about the risks of downloading unverified software.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No references to this domain were found on dark web forums, paste sites, or leak databases. "
            "This is a positive indicator — there is no evidence of stolen credentials being traded online.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    # Enriched breach timeline (keep in table as data)
    enriched = d.get("dehashed", {}).get("enriched_sources", [])
    if enriched:
        rows.append(("", ""))
        rows.append(("BREACH SOURCE TIMELINE", ""))
        for src in enriched:
            pw_flag = " [PASSWORDS EXPOSED]" if src.get("passwords_in_breach") else ""
            verified = " [Verified]" if src.get("verified") else ""
            data = ", ".join(src.get("data_exposed", [])[:4]) if src.get("data_exposed") else "Unknown"
            rows.append((f"  {src.get('name', 'Unknown')}", f"Date: {src.get('breach_date', 'Unknown')}{pw_flag}{verified} | Data: {data}"))
    fb = {"CRITICAL": "CRITICAL credential risk — active compromise detected. Immediate incident response required.",
           "HIGH": "HIGH credential risk — recent breaches with password exposure. Force resets and enable MFA.",
           "MEDIUM": "MODERATE credential risk — historical exposure detected. Review password policies and MFA coverage.",
           "LOW": "Low credential risk — no significant exposure. Continue monitoring."}.get(level, "Credential risk assessment complete — see details above.")
    parts = build_cat_card("Credential Risk Assessment", col, level, rows, [], S, fallback=fb)

    # Assessment summary OUTSIDE the table
    summary_text = cr.get("summary", "")
    if summary_text:
        parts.append(Paragraph("<b>Assessment</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(summary_text, S["body"]))
        parts.append(Spacer(1, 2 * mm))

    # What This Means OUTSIDE the table
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if level == "CRITICAL":
        parts.append(Paragraph(
            "One or more employee devices are actively infected with credential-stealing malware. "
            "This is the highest severity finding — attackers have real-time access to stolen passwords "
            "and can log into your systems at any time. Treat this as an active security incident.",
            S["body"]))
    elif level == "HIGH":
        parts.append(Paragraph(
            "Staff credentials (usernames and passwords) have been found in recent data breaches. "
            "While these may have been changed since the breach, attackers routinely use stolen passwords "
            "to attempt access to other systems (credential stuffing). The risk of unauthorised access "
            "is significantly elevated.",
            S["body"]))
    elif level == "MEDIUM":
        parts.append(Paragraph(
            "Historical credential exposure has been detected in older data breaches. "
            "The risk is moderate — passwords may have been changed since the breach, but "
            "organisations with poor password hygiene or no MFA remain vulnerable.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "No significant credential exposure detected. This is a positive indicator of "
            "good security practices. Continue monitoring and maintain MFA enforcement.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{mal} security engine(s) flagged this domain as malicious — see interpretation below." if mal > 0 else (f"{sus} engine(s) flagged as suspicious — warrants monitoring." if sus > 0 else "Clean reputation across all security engines — no malicious indicators.")
    parts = build_cat_card("VirusTotal Reputation", col, summary, rows, vt.get("issues", []), S, fallback=fb)

    # Interpretation OUTSIDE the table
    parts.append(Paragraph("<b>Interpretation</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(interp, S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = "DNS intelligence collected — provides historical context for domain infrastructure." if status != "no_api_key" else "SecurityTrails API not configured — historical DNS intelligence unavailable."
    parts = build_cat_card("DNS Intelligence (SecurityTrails)", col, summary, rows, st.get("issues", []), S, fallback=fb)

    if status != "no_api_key":
        parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        if assoc > 50:
            parts.append(Paragraph(
                f"{assoc} associated domains share infrastructure with this domain. A high number of associated "
                "domains can indicate shared hosting, which means a compromise of any co-hosted site could "
                "potentially impact this domain. It also expands the attack surface that needs to be monitored.",
                S["body"]))
        else:
            parts.append(Paragraph(
                "DNS intelligence provides historical context about the domain's infrastructure — including "
                "current and historical DNS records, associated domains, and hosting changes. This data helps "
                "assess infrastructure stability and identify potential shared-hosting risks.",
                S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"Privacy policy found with {pct}% completeness — review missing sections for POPIA compliance." if found and pct < 80 else ("Privacy policy is comprehensive and meets key compliance requirements." if found else "No privacy policy found — required under POPIA for any organisation processing personal information.")
    parts = build_cat_card("Privacy Policy Compliance", col, summary, rows, pc.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if not found:
        parts.append(Paragraph(
            "No privacy policy was found on this website. Under POPIA (Protection of Personal Information Act), "
            "any organisation that processes personal information must have a publicly accessible privacy policy "
            "detailing how data is collected, used, stored, and protected. Absence of a privacy policy is a "
            "compliance gap and a regulatory risk.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Publish a POPIA-compliant privacy policy on the website, accessible from every page.", S["body"]))
        parts.append(Paragraph("2. Include required sections: purpose of processing, data categories, retention periods, data subject rights, and Information Officer details.", S["body"]))
    elif pct < 80:
        missing = pc.get("sections_missing", [])
        missing_str = ", ".join(missing[:3]) if missing else "various sections"
        parts.append(Paragraph(
            f"A privacy policy was found but is only {pct}% complete. Missing sections ({missing_str}) "
            "may leave the organisation exposed to regulatory action under POPIA. A comprehensive privacy policy "
            "is both a legal requirement and a trust signal for clients.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph(f"1. Add missing sections to the privacy policy: {missing_str}.", S["body"]))
        parts.append(Paragraph("2. Have the updated policy reviewed by a POPIA compliance specialist.", S["body"]))
    else:
        parts.append(Paragraph(
            "The privacy policy is comprehensive and covers the key sections required for POPIA compliance. "
            "This demonstrates mature data governance practices.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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

    # External-scan disclaimer
    story.append(Paragraph(
        "<b>Note:</b> This compliance assessment is based on <b>externally observable indicators only</b>. "
        "An external scan can typically assess 60–80% of a framework's controls — those related to encryption, "
        "access controls, network security, and public-facing configurations. Controls requiring internal assessment "
        "(e.g. staff training, incident response procedures, internal access management) cannot be evaluated "
        "externally and are marked as NO_DATA. A full compliance audit would require internal assessment.",
        S["body"]))
    story.append(Spacer(1, 4 * mm))

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
        # Count assessable vs NO_DATA
        total_ctrl = len(fw_data.get("controls", {}))
        no_data_count = sum(1 for c in fw_data.get("controls", {}).values() if c.get("status") == "no_data")
        assessable = total_ctrl - no_data_count
        fb = (f"{pct}% alignment based on {assessable} of {total_ctrl} externally assessable controls. "
              f"{'Remaining controls require internal assessment.' if no_data_count > 0 else ''}")
        story += build_cat_card(f"{framework}", col, f"{pct}% aligned", rows, [], S, fallback=fb)
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
    fb = "Website security configuration is strong — HTTPS enforced with secure cookie settings." if score >= 80 else f"Website security score of {score}% — review HTTPS enforcement, mixed content, and cookie security settings."
    parts = build_cat_card("Website Security", col, f"{score}%", rows, ws.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 80:
        parts.append(Paragraph(
            "Website security fundamentals are well implemented. HTTPS is enforced, cookies are configured "
            "with Secure and HttpOnly flags, and no mixed content issues were detected. This protects user "
            "sessions from hijacking and ensures data integrity between the browser and server.",
            S["body"]))
    else:
        issues_list = []
        if not ws.get("https_enforced"):
            issues_list.append("HTTPS not enforced")
        if ws.get("mixed_content"):
            issues_list.append("mixed content detected")
        if not ck.get("secure", True):
            issues_list.append("insecure cookie flags")
        parts.append(Paragraph(
            f"Website security score is {score}%"
            f"{' — issues include: ' + ', '.join(issues_list) if issues_list else ''}. "
            "These are foundational web security controls that protect user sessions and data transmission.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        if not ws.get("https_enforced"):
            parts.append(Paragraph("1. Enforce HTTPS across all pages using server-side redirects (HTTP 301 to HTTPS).", S["body"]))
        if ws.get("mixed_content"):
            parts.append(Paragraph("2. Fix mixed content by ensuring all resources (images, scripts, CSS) are loaded over HTTPS.", S["body"]))
        if not ck.get("secure", True) or not ck.get("httponly", True):
            parts.append(Paragraph("3. Set Secure and HttpOnly flags on all session cookies to prevent interception and XSS theft.", S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
        fb = f"Ranked #{rank:,} in Tranco top 1M — established web presence." if wr.get("ranked") else "Not in the Tranco top 1M — lower traffic volume, which is typical for SME websites."
        parts = build_cat_card("Web Ranking (Tranco)", col, wr.get("rank_label", "Unranked"), rows, wr.get("issues", []), S, fallback=fb)
    else:
        score = wr.get("score", 30)
        col = _tl(score >= 70, score >= 40)
        rows = [
            ("Tranco Rank", f"#{rank:,}" if rank else "Not in top 1M"),
            ("In List", "Yes" if wr.get("in_list") else "No"),
            ("Score", f"{score}/100"),
        ]
        fb = f"Ranked #{rank:,} — established web presence." if rank else "Not ranked in Tranco top 1M — typical for SME websites."
        parts = build_cat_card("Web Ranking (Tranco)", col,
                              f"#{rank:,}" if rank else "Unranked",
                              rows, wr.get("issues", []), S, fallback=fb)
    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "Web ranking from the Tranco list (a research-grade domain popularity list) provides context about "
        "website traffic volume. Higher-traffic websites are more attractive targets for attackers but also "
        "tend to have more mature security practices. Unranked sites are common for SMEs and do not indicate "
        "a security concern.",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{len(exposed)} sensitive path(s) exposed — internal files or configuration may be accessible to attackers." if exposed else "No sensitive files or configuration paths are publicly accessible."
    parts = build_cat_card("Information Disclosure", col, f"{score}%",
                          rows, info.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if exposed:
        parts.append(Paragraph(
            f"{len(exposed)} path(s) were found that may expose sensitive information such as configuration files, "
            "version control data (.git), environment files (.env), or backup files. These files can reveal "
            "database credentials, API keys, internal architecture, and other information that significantly "
            "aids attackers in planning targeted attacks.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Block access to all exposed sensitive paths in your web server configuration.", S["body"]))
        parts.append(Paragraph("2. Remove .git, .env, and backup files from the public web root entirely.", S["body"]))
        parts.append(Paragraph("3. Audit server configuration to prevent directory listing and file enumeration.", S["body"]))
    else:
        parts.append(Paragraph(
            "No sensitive configuration files, version control data, or backup files were found accessible "
            "from the public website. This reduces the risk of information leakage to attackers.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{found} lookalike domain(s) detected — these could be used for phishing attacks against staff or customers." if found > 0 else "No active lookalike domains detected — low brand impersonation risk."
    parts = build_cat_card("Fraudulent Domains (Typosquat)", col, f"{found} found", rows, fd.get("issues", []), S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if found > 0:
        parts.append(Paragraph(
            f"{found} domain(s) that closely resemble your organisation's domain were found with active DNS records "
            "or SSL certificates. These lookalike domains are commonly used in phishing attacks — attackers register "
            "domains like 'yourdoma1n.com' or 'yourdomain-secure.com' to trick staff or clients into entering "
            "credentials on a fake login page.",
            S["body"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph("<b>Recommended Actions</b>", S["cat_title"]))
        parts.append(Spacer(1, 1 * mm))
        parts.append(Paragraph("1. Investigate each lookalike domain to determine if it is being used for phishing.", S["body"]))
        parts.append(Paragraph("2. Submit takedown requests to the registrars of confirmed malicious domains.", S["body"]))
        parts.append(Paragraph("3. Register common typo variants of your domain defensively to prevent future abuse.", S["body"]))
        parts.append(Paragraph("4. Alert staff to the existence of these lookalike domains and reinforce phishing awareness.", S["body"]))
    else:
        parts.append(Paragraph(
            "No active lookalike domains were detected. This means no one has registered domains that closely "
            "mimic your brand for phishing purposes. Consider defensively registering common typo variants "
            "to maintain this position.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"RSI score of {score:.2f} — {'high ransomware susceptibility, prioritise remediation steps below.' if score >= 0.50 else 'moderate risk, review contributing factors.' if score >= 0.25 else 'low ransomware susceptibility based on current external posture.'}"
    parts = build_cat_card("Ransomware Susceptibility Index (RSI)", col,
                          f"{score:.2f} — {rsi.get('risk_label', '')}",
                          rows, [], S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    if score >= 0.75:
        parts.append(Paragraph(
            "This organisation has a high ransomware susceptibility score, driven by the contributing factors listed "
            "above. Multiple external risk indicators align with the attack patterns commonly seen in successful "
            "ransomware incidents. Immediate remediation of the highest-priority factors is strongly recommended.",
            S["body"]))
    elif score >= 0.50:
        parts.append(Paragraph(
            "Moderate-to-high ransomware susceptibility. Several external risk factors were identified that, "
            "in combination, create meaningful exposure to ransomware attacks. Addressing the top contributing "
            "factors would materially reduce this risk.",
            S["body"]))
    elif score >= 0.25:
        parts.append(Paragraph(
            "Moderate ransomware susceptibility. Some risk factors are present but the overall external posture "
            "provides reasonable protection. Address contributing factors during planned maintenance cycles.",
            S["body"]))
    else:
        parts.append(Paragraph(
            "Low ransomware susceptibility based on externally observable indicators. The organisation's external "
            "security posture does not exhibit the common risk patterns associated with ransomware victims.",
            S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


def cat_dbi(results, S):
    """Data Breach Index card for PDF — insurance analytics."""
    ins = results if "dbi" in results else results.get("insurance", {})
    dbi = ins.get("dbi", {})
    score = dbi.get("dbi_score", 50)
    col = _tl(score >= 80, score >= 40)
    rows = [("DBI Score", f"{score}/{dbi.get('max_score', 100)} — {dbi.get('label', '')}")]
    for key, comp in dbi.get("components", {}).items():
        rows.append((key.replace("_", " ").capitalize(), f"{comp.get('value', '')} ({comp.get('points', 0)}/{comp.get('max', 0)} pts)"))
    fb = f"DBI score {score}/100 — {'strong data breach resilience.' if score >= 80 else 'moderate breach resilience, review component scores.' if score >= 40 else 'weak breach resilience, multiple exposure factors identified.'}"
    parts = build_cat_card("Data Breach Index (DBI)", col,
                          f"{score}/100 — {dbi.get('label', '')}",
                          rows, [], S, fallback=fb)

    parts.append(Paragraph("<b>What This Means</b>", S["cat_title"]))
    parts.append(Spacer(1, 1 * mm))
    parts.append(Paragraph(
        "The Data Breach Index (DBI) measures the organisation's resilience to data breach events based on "
        "externally observable factors including credential exposure, encryption strength, data handling practices, "
        "and breach history. A higher score indicates stronger resilience. Component scores above show which "
        "areas contribute most to the overall rating.",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"{len(steps)} prioritised remediation steps could reduce annual expected loss by {cur} {savings:,.0f}."
    parts = build_cat_card("Remediation Roadmap — Before/After", col,
                          f"{len(steps)} steps — {cur} {savings:,.0f} savings",
                          rows, [], S, fallback=fb)
    parts.append(Paragraph(
        "<i>Note: Estimated costs are indicative ranges based on typical SA market rates and are intended "
        "as a guide for prioritising quick wins and identifying \"bang for buck\" remediation. Actual costs "
        "will vary based on the organisation's size, existing infrastructure, and whether work is performed "
        "in-house or outsourced. These figures should be used as a conversation starter, not a project quote.</i>",
        S["body"]))
    parts.append(Spacer(1, 3 * mm))
    return parts


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
    fb = f"RSI {score}/1.0 — {'high susceptibility to ransomware attacks.' if score >= 0.5 else 'moderate ransomware risk.' if score >= 0.25 else 'low ransomware susceptibility.'}"
    return build_cat_card("Ransomware Susceptibility (RSI)", col, f"{score}", rows, rsi.get("issues", []), S, fallback=fb)


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
    fb = f"DBI {score}/100 — {'strong breach resilience.' if score >= 75 else 'moderate risk exposure.' if score >= 50 else 'elevated breach risk based on current posture.'}"
    return build_cat_card("Data Breach Index (DBI)", col, f"{score}/100", rows, dbi.get("issues", []), S, fallback=fb)


def cat_financial_impact(d, S):
    fin = d.get("financial_impact", {})
    # Accept ZAR results (currency key present) or legacy completed status
    if not fin or (not fin.get("currency") and fin.get("status") != "completed"):
        rows = [
            ("Status", "Financial impact analysis requires annual revenue input"),
            ("", "Re-run this assessment with annual revenue (ZAR) to generate:"),
            ("", "\u2022 Estimated annual cyber loss (min/likely/max scenarios)"),
            ("", "\u2022 Monte Carlo confidence intervals (10,000 simulations)"),
            ("", "\u2022 Insurance coverage recommendations (minimum and recommended)"),
            ("", "\u2022 Per-finding cost reduction estimates"),
        ]
        return build_cat_card("Financial Impact Analysis", C_BLUE, "Revenue required", rows, [], S, fallback="Annual revenue is required to calculate financial impact estimates.")

    is_zar = fin.get("currency") == "ZAR"
    cur    = "R" if is_zar else "$"
    sc     = fin.get("scenarios", {})
    sc4    = fin.get("scenarios_4cat", {})
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
            ("Detection & Escalation", f"{cur} {sc4.get('detection_escalation', {}).get('estimated_loss', 0):,.0f}") if sc4 else ("", ""),
            ("Ransom Demand",         f"{cur} {sc4.get('ransom_demand', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})") if sc4 else ("Ransomware Loss", f"{cur} {sc.get('ransomware', {}).get('estimated_loss', 0):,.0f}  (RSI={sc.get('ransomware', {}).get('rsi_score', 0)})"),
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

    fb = f"Estimated most likely annual loss of {cur} {most_l:,.0f} based on FAIR quantitative risk model with Monte Carlo simulation."
    return build_cat_card("Financial Impact Analysis", col,
                          f"{cur} {most_l:,.0f}", rows, fin.get("issues", []), S, fallback=fb)


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
    rows.append(("Note", "Savings are modelled projections based on FAIR methodology. Cost estimates are indicative SA market ranges for prioritisation, not project quotes."))

    fb = f"Implementing all recommendations could reduce annual expected loss by {cur} {total_savings:,.0f} ({reduction_pct}%)."
    return build_cat_card("Risk Mitigation Recommendations", C_GREEN,
                          f"Save {cur} {total_savings:,.0f}", rows, [], S, fallback=fb)


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

def _build_vulnerability_posture(results: dict, S) -> list:
    """Build Vulnerability Posture summary with severity/age matrix and narrative."""
    parts = []
    cats = results.get("categories", {})

    # Collect all CVEs from per-IP results
    all_cves = []
    per_ip = cats.get("per_ip", {})
    for ip, checkers in per_ip.items():
        shodan = checkers.get("shodan_vulns", {})
        for cve in shodan.get("cves", []):
            all_cves.append(cve)

    # Also check aggregated shodan
    agg_shodan = cats.get("shodan_vulns", {})
    if not all_cves and agg_shodan.get("cves"):
        all_cves = agg_shodan.get("cves", [])

    total = len(all_cves)
    if total == 0:
        # No CVEs — still show the posture block with clean result
        parts.append(Paragraph("<b>Vulnerability Posture</b>", S["cat_title"]))
        parts.append(Spacer(1, 2 * mm))
        parts.append(Paragraph(
            "No known vulnerabilities were detected on the assessed infrastructure. "
            "This is a positive indicator, however it does not guarantee the absence of "
            "vulnerabilities — only that none were identified through passive external scanning.",
            S["body"]))
        return parts

    # Count by severity
    critical = sum(1 for c in all_cves if c.get("severity") == "critical")
    high = sum(1 for c in all_cves if c.get("severity") == "high")
    medium = sum(1 for c in all_cves if c.get("severity") == "medium")
    low = sum(1 for c in all_cves if c.get("severity") == "low")

    # Count by age bucket
    ages = [c.get("age_days") for c in all_cves if c.get("age_days") is not None]
    over_180 = sum(1 for a in ages if a > 180)
    d90_to_180 = sum(1 for a in ages if 90 <= a <= 180)
    under_90 = sum(1 for a in ages if a < 90)
    oldest = max(ages) if ages else 0
    avg_age = round(sum(ages) / len(ages)) if ages else 0

    # Count indicators
    easily_exploitable = sum(1 for c in all_cves if c.get("easily_exploitable"))
    widely_exploited = sum(1 for c in all_cves if c.get("widely_exploited"))
    zero_days = sum(1 for c in all_cves if c.get("zero_day"))
    malware_count = sum(1 for c in all_cves if c.get("ransomware_association"))
    ransomware_names = list(set(
        c.get("ransomware_association", "") for c in all_cves if c.get("ransomware_association")
    ))[:5]

    # Patch management rating
    if oldest > 365:
        pm_rating = "Very Poor"
        pm_color = C_CRITICAL
    elif oldest > 180:
        pm_rating = "Poor"
        pm_color = C_RED
    elif oldest > 90:
        pm_rating = "Fair"
        pm_color = C_AMBER
    else:
        pm_rating = "Good"
        pm_color = C_GREEN

    parts.append(Paragraph("<b>Vulnerability Posture</b>", S["cat_title"]))
    parts.append(Spacer(1, 2 * mm))

    # Severity + Age matrix table (PrimeLogic style)
    header_style = ParagraphStyle("vp_hdr", fontSize=7, fontName="Helvetica-Bold",
                                   textColor=C_WHITE, alignment=TA_CENTER, leading=10)
    # Conditional font size for large numbers to prevent cell overflow
    val_size = 14 if total < 100 else 12
    val_leading = 18 if total < 100 else 16
    val_style = ParagraphStyle("vp_val", fontSize=val_size, fontName="Helvetica-Bold",
                                textColor=C_BLACK, alignment=TA_CENTER, leading=val_leading)
    lbl_style = ParagraphStyle("vp_lbl", fontSize=6, fontName="Helvetica",
                                textColor=C_GREY_3, alignment=TA_CENTER, leading=9)

    matrix_data = [
        # Headers
        [Paragraph("<b>Critical</b>", header_style),
         Paragraph("<b>High</b>", header_style),
         Paragraph("<b>Medium</b>", header_style),
         Paragraph("<b>&gt; 180 days</b>", header_style),
         Paragraph("<b>&lt; 180 days</b>", header_style),
         Paragraph("<b>&lt; 90 days</b>", header_style)],
        # Values
        [Paragraph(f"<b>{critical}</b>", val_style),
         Paragraph(f"<b>{high}</b>", val_style),
         Paragraph(f"<b>{medium + low}</b>", val_style),
         Paragraph(f"<b>{over_180}</b>", val_style),
         Paragraph(f"<b>{d90_to_180}</b>", val_style),
         Paragraph(f"<b>{under_90}</b>", val_style)],
        # Labels
        [Paragraph(f"{critical} instance(s)", lbl_style),
         Paragraph(f"{high} instance(s)", lbl_style),
         Paragraph(f"{medium + low} instance(s)", lbl_style),
         Paragraph(f"{over_180} instance(s)", lbl_style),
         Paragraph(f"{d90_to_180} instance(s)", lbl_style),
         Paragraph(f"{under_90} instance(s)", lbl_style)],
    ]

    col_w = INNER_W / 6
    matrix_tbl = Table(matrix_data, colWidths=[col_w] * 6)
    matrix_tbl.setStyle(TableStyle([
        # Header row styling
        ("BACKGROUND",    (0, 0), (2, 0), C_CRITICAL_BG),
        ("BACKGROUND",    (0, 0), (0, 0), C_CRITICAL),
        ("BACKGROUND",    (1, 0), (1, 0), C_RED),
        ("BACKGROUND",    (2, 0), (2, 0), C_AMBER),
        ("BACKGROUND",    (3, 0), (3, 0), colors.HexColor("#1e40af")),
        ("BACKGROUND",    (4, 0), (4, 0), colors.HexColor("#2563eb")),
        ("BACKGROUND",    (5, 0), (5, 0), colors.HexColor("#3b82f6")),
        # Value row
        ("BACKGROUND",    (0, 1), (-1, 1), C_GREY_1),
        ("BACKGROUND",    (0, 2), (-1, 2), C_WHITE),
        # Grid
        ("BOX",           (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING",    (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("TOPPADDING",    (0, 2), (-1, 2), 2),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 4),
    ]))
    parts.append(matrix_tbl)
    parts.append(Spacer(1, 3 * mm))

    # Threat indicator row (Zero-days, Malware exploited, Exploited in wild, Easily exploitable, Widely exploited)
    kev_count = sum(1 for c in all_cves if c.get("in_kev"))
    # Conditional font size for threat indicator values
    threat_max = max(zero_days, malware_count, kev_count, easily_exploitable, widely_exploited)
    threat_val_size = 14 if threat_max < 100 else 12
    threat_val_leading = 18 if threat_max < 100 else 16
    threat_val_style = ParagraphStyle("vp_threat_val", fontSize=threat_val_size, fontName="Helvetica-Bold",
                                       textColor=C_BLACK, alignment=TA_CENTER, leading=threat_val_leading)
    threat_data = [
        [Paragraph("<b>Zero-days</b>", header_style),
         Paragraph("<b>Malware exploited</b>", header_style),
         Paragraph("<b>Exploited in wild</b>", header_style),
         Paragraph("<b>Easily exploitable</b>", header_style),
         Paragraph("<b>Widely exploited</b>", header_style)],
        [Paragraph(f"<b>{zero_days}</b>", threat_val_style),
         Paragraph(f"<b>{malware_count}</b>", threat_val_style),
         Paragraph(f"<b>{kev_count}</b>", threat_val_style),
         Paragraph(f"<b>{easily_exploitable}</b>", threat_val_style),
         Paragraph(f"<b>{widely_exploited}</b>", threat_val_style)],
        [Paragraph(f"{zero_days} instance(s)", lbl_style),
         Paragraph(f"{malware_count} instance(s)", lbl_style),
         Paragraph(f"{kev_count} instance(s)", lbl_style),
         Paragraph(f"{easily_exploitable} instance(s)", lbl_style),
         Paragraph(f"{widely_exploited} instance(s)", lbl_style)],
    ]
    threat_col_w = INNER_W / 5
    threat_tbl = Table(threat_data, colWidths=[threat_col_w] * 5)
    _threat_grey = colors.HexColor("#475569")
    threat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _threat_grey),
        ("BACKGROUND",    (0, 1), (-1, 1), C_GREY_1),
        ("BACKGROUND",    (0, 2), (-1, 2), C_WHITE),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_GREY_2),
        ("INNERGRID",     (0, 0), (-1, -1), 0.25, C_GREY_2),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0), 4),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING",    (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
        ("TOPPADDING",    (0, 2), (-1, 2), 2),
        ("BOTTOMPADDING", (0, 2), (-1, 2), 4),
    ]))
    parts.append(threat_tbl)
    parts.append(Spacer(1, 2 * mm))

    # Plain-English legend for threat indicators
    legend_style = S["vp_legend"]
    legend_items = [
        "<b>Zero-days:</b> Vulnerabilities with no vendor patch available — no fix exists yet, requiring alternative mitigations.",
        "<b>Malware exploited:</b> Vulnerabilities known to be used by ransomware groups or malware campaigns to attack organisations.",
        "<b>Exploited in wild:</b> Confirmed by CISA (US Cybersecurity Agency) as actively exploited by attackers right now.",
        "<b>Easily exploitable:</b> Can be exploited remotely over the internet with no special tools, passwords, or user interaction required.",
        "<b>Widely exploited:</b> High probability of mass exploitation — automated attack tools are scanning the internet for this vulnerability.",
    ]
    for item in legend_items:
        parts.append(Paragraph(item, legend_style))
    parts.append(Spacer(1, 3 * mm))

    # Narrative paragraph
    narrative = (
        f"This assessment identified <b>{total}</b> known vulnerabilities on the assessed infrastructure"
    )
    if critical > 0:
        narrative += f", of which <b>{critical}</b> are classified as critical severity"
    if high > 0:
        narrative += f" and <b>{high}</b> as high severity"
    narrative += ". "

    if over_180 > 0:
        narrative += (
            f"<b>{over_180}</b> vulnerabilit{'y has' if over_180 == 1 else 'ies have'} "
            f"remained unpatched for over 180 days"
        )
        if oldest > 365:
            narrative += (
                f" — the oldest being <b>{oldest} days</b> old, indicating that software updates "
                f"have not been applied for over {oldest // 365} year(s)"
            )
        narrative += ". "

    if easily_exploitable > 0:
        narrative += (
            f"<b>{easily_exploitable}</b> vulnerabilit{'y is' if easily_exploitable == 1 else 'ies are'} "
            f"easily exploitable — requiring no authentication and accessible directly from the internet. "
        )

    if widely_exploited > 0:
        narrative += (
            f"<b>{widely_exploited}</b> {'is' if widely_exploited == 1 else 'are'} widely exploited "
            f"with a high probability of mass exploitation. "
        )

    if malware_count > 0:
        narrative += (
            f"<b>{malware_count}</b> vulnerabilit{'y is' if malware_count == 1 else 'ies are'} "
            f"associated with known ransomware campaigns ({', '.join(ransomware_names)}). "
        )
    else:
        narrative += "No vulnerabilities were associated with known ransomware campaigns. "

    if zero_days > 0:
        narrative += (
            f"<b>{zero_days}</b> vulnerabilit{'y has' if zero_days == 1 else 'ies have'} "
            f"no vendor patch available. "
        )
    else:
        narrative += "No active zero-day exploits were identified. "

    narrative += (
        f"The overall patch management posture is rated as "
        f"<b><font color='{pm_color}'>{pm_rating}</font></b>"
    )
    if avg_age > 0:
        narrative += f" (average vulnerability age: {avg_age} days)"
    narrative += "."

    parts.append(Paragraph(narrative, S["body"]))
    parts.append(Spacer(1, 2 * mm))

    return parts


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
        "in a typical attack.</i>", S["body_muted"]))
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
    # Severity incorporates financial impact — a high financial impact cannot be LOW
    db_exposed = any(s.get("port") in (3306, 5432, 27017, 6379, 9200, 1433) for s in hrp)
    ix = cats.get("intelx", {})
    darkweb = ix.get("total_results", 0)
    fin = ins.get("financial_impact", {}).get("total", {})
    fin_most_likely = fin.get("most_likely", 0)
    fin_revenue = ins.get("financial_impact", {}).get("annual_revenue_zar", 0)
    fin_loss_pct = fin_most_likely / fin_revenue if fin_revenue > 0 else 0

    # Determine base risk from technical signals
    if db_exposed:
        data_risk = "CRITICAL"
    elif darkweb > 10:
        data_risk = "HIGH"
    elif darkweb > 0:
        data_risk = "MEDIUM"
    else:
        data_risk = "LOW"

    # Elevate based on financial impact severity
    if fin_loss_pct >= 0.30:
        data_risk = max(data_risk, "CRITICAL", key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
    elif fin_loss_pct >= 0.15:
        data_risk = max(data_risk, "HIGH", key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))
    elif fin_loss_pct >= 0.08:
        data_risk = max(data_risk, "MEDIUM", key=lambda x: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x))

    data_findings = []
    if db_exposed: data_findings.append("Databases directly internet-facing — attacker can extract all business data without further escalation")
    if darkweb > 0: data_findings.append(f"{darkweb} references in dark web databases — stolen data is already circulating in criminal networks")
    rsi = ins.get("rsi", {}).get("rsi_score", 0)
    if rsi > 0.5: data_findings.append(f"Ransomware susceptibility {rsi:.0%} — high probability of ransomware deployment after access is gained")
    if fin_most_likely:
        cur = "R" if ins.get("financial_impact", {}).get("currency") == "ZAR" else "$"
        data_findings.append(f"Estimated financial impact: {cur} {fin_most_likely:,.0f} (Monte Carlo P50 median)")
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
            # Wrap header + financial text as atomic block
            story.append(KeepTogether([
                Spacer(1, 4 * mm), fin_banner, Spacer(1, 3 * mm),
                Paragraph(fin_text, S["body"]), Spacer(1, 4 * mm)
            ]))

        # ── Why This Matters — The Reality of a Cyber Breach ──────────────
        why_banner = _section_header_banner("WHY THIS MATTERS", S)

        # Financial exposure recap
        total_likely = fin.get("total", {}).get("most_likely", 0) if fin else 0
        mc_data = fin.get("monte_carlo", {}).get("total", {}) if fin else {}
        mc_p50 = mc_data.get("p50", total_likely)
        mc_p95 = mc_data.get("p95", 0)
        cur_cta = "R" if (fin and fin.get("currency") == "ZAR") else "$"
        org_location = "a South African" if (fin and fin.get("currency") == "ZAR") else "an"

        # Count critical findings
        cred_risk = cats.get("credential_risk", {}).get("risk_level", "LOW")
        hr_employees = cats.get("hudson_rock", {}).get("compromised_employees", 0)
        ix_total = cats.get("intelx", {}).get("total_results", 0)
        dh_total = cats.get("dehashed", {}).get("total_entries", 0)
        hrp_critical = cats.get("high_risk_protocols", {}).get("critical_count", 0)

        # Wrap WHY THIS MATTERS header with first content block
        story.append(KeepTogether([
            Spacer(1, 4 * mm), why_banner, Spacer(1, 3 * mm),
            Paragraph(f"<b>Your Estimated Financial Exposure</b>", S["cat_title"]),
            Spacer(1, 2 * mm),
            Paragraph(
                f"Based on this assessment, your organisation faces an estimated annual cyber loss of "
                f"<b>{cur_cta} {mc_p50:,.0f}</b> (median scenario). In a worst-case event, losses could reach "
                f"<b>{cur_cta} {mc_p95:,.0f}</b>. These figures are derived from a Monte Carlo simulation of "
                f"10,000 scenarios modelling data breach, ransomware, and business interruption events "
                f"specific to your industry and risk profile.",
                S["body"]),
            Spacer(1, 4 * mm),
        ]))

        # The human cost of a breach
        story.append(Paragraph(
            f"<b>The Reality of a Cyber Breach</b>", S["cat_title"]))
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
                f"This assessment detected <b>active credential-stealing malware (infostealer)</b> on {hr_employees} employee "
                f"device(s). This is not a historical finding — it means credentials are being stolen "
                f"<b>right now</b> and sold to criminal buyers. Without immediate intervention, a breach "
                f"is not a matter of <i>if</i>, but <i>when</i>."
            )
        if ix_total > 0:
            risk_paras.append(
                f"We found <b>{ix_total} references</b> to your organisation in criminal online marketplaces (dark web). "
                f"This means stolen data associated with your business is circulating in criminal "
                f"networks where it can be purchased by anyone with malicious intent."
            )
        if dh_total > 0:
            risk_paras.append(
                f"<b>{dh_total} credential records</b> linked to your domain were found in breach "
                f"databases. These include email addresses and potentially passwords that attackers "
                f"use for automated password attacks (credential stuffing) — systematically trying stolen passwords across "
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
                "This assessment identified no critical immediate threats, indicating a strong "
                "security foundation. Ongoing cyber insurance provides protection against emerging "
                "threats, zero-day exploits, and the evolving threat landscape \u2014 ensuring business "
                "continuity even when the unexpected occurs."
            )

        for para in risk_paras:
            story.append(Paragraph(f"\u2022 {para}", S["body"]))
            story.append(Spacer(1, 2 * mm))
        story.append(Spacer(1, 4 * mm))

        # Call to action
        story.append(Paragraph(
            f"<b>Protect Your Business — Next Steps</b>", S["cat_title"]))
        story.append(Spacer(1, 2 * mm))

        cta_style = S["cta"]

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
            S["contact"]
        ))
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            "PHISHIELD UMA (Pty) Ltd | Authorised Financial Services Provider | FSP 46418",
            S["fsp"]
        ))

    else:
        # ── Full report — all sections included ─────────────────────────────

        # ── Insurance Analytics ─────────────────────────────────────────────
        if results.get("insurance"):
            story += section_with_first_card("INSURANCE ANALYTICS", S, cat_rsi(results, S))
            story += cat_dbi(results, S)
            story += cat_financial_impact(results.get("insurance", {}), S)
            story += cat_risk_mitigations(results.get("insurance", {}), S)
            story += cat_remediation(results, S)

        # ── Discovery ───────────────────────────────────────────────────────
        story += section_with_first_card("DISCOVERY", S, cat_web_ranking(cats, S))

        # ── Core Security ───────────────────────────────────────────────────
        story += section_with_first_card("CORE SECURITY", S, cat_ssl(cats, S))
        story += cat_headers(cats, S)
        story += cat_waf(cats, S)
        story += cat_website(cats, S)

        # ── Information Security ────────────────────────────────────────────
        story += section_with_first_card("INFORMATION SECURITY", S, cat_info_disclosure(cats, S))

        # ── Email Security ──────────────────────────────────────────────────
        story += section_with_first_card("EMAIL SECURITY", S, cat_email(cats, S))
        story += cat_email_hardening(cats, S)

        # ── Network & Infrastructure ────────────────────────────────────────
        story += section_with_first_card("NETWORK & INFRASTRUCTURE", S, cat_dns(cats, S))
        story += cat_hrp(cats, S)
        story += cat_cloud(cats, S)
        story += cat_vpn(cats, S)

        # ── Exposure & Reputation ───────────────────────────────────────────
        story += section_with_first_card("EXPOSURE & REPUTATION", S, cat_breaches(cats, S))
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
        story += section_with_first_card("TECHNOLOGY & GOVERNANCE", S, cat_tech(cats, S))
        story += cat_domain(cats, S)
        story += cat_securitytrails(cats, S)
        story += cat_privacy_compliance(cats, S)
        story += cat_security_policy(cats, S)
        story += cat_payment(cats, S)

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
