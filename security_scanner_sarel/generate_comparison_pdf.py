"""
Generate Phishield vs Nucleus Security comparison PDF
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)

W, H = A4

# Colors
NAVY = colors.HexColor("#0f2744")
BLUE = colors.HexColor("#1d4ed8")
BLUE_LIGHT = colors.HexColor("#dbeafe")
GREEN = colors.HexColor("#16a34a")
GREEN_BG = colors.HexColor("#dcfce7")
AMBER = colors.HexColor("#d97706")
RED = colors.HexColor("#dc2626")
GREY1 = colors.HexColor("#f8fafc")
GREY2 = colors.HexColor("#e2e8f0")
GREY4 = colors.HexColor("#475569")
BLACK = colors.HexColor("#0f172a")
WHITE = colors.white

# Styles
sTitle = ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, textColor=NAVY, spaceAfter=4)
sSubtitle = ParagraphStyle("subtitle", fontName="Helvetica", fontSize=11, textColor=GREY4, spaceAfter=16)
sH1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=14, textColor=NAVY, spaceBefore=16, spaceAfter=8)
sH2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, textColor=BLUE, spaceBefore=12, spaceAfter=6)
sBody = ParagraphStyle("body", fontName="Helvetica", fontSize=9, textColor=BLACK, leading=13, spaceAfter=4)
sBold = ParagraphStyle("bold", fontName="Helvetica-Bold", fontSize=9, textColor=BLACK, leading=13, spaceAfter=4)
sBullet = ParagraphStyle("bullet", fontName="Helvetica", fontSize=9, textColor=BLACK, leading=13, leftIndent=14, spaceAfter=2)
sTH = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8.5, textColor=WHITE, leading=11)
sTD = ParagraphStyle("td", fontName="Helvetica", fontSize=8.5, textColor=BLACK, leading=11)
sTDB = ParagraphStyle("tdb", fontName="Helvetica-Bold", fontSize=8.5, textColor=BLACK, leading=11)
sPhase = ParagraphStyle("phase", fontName="Helvetica-Bold", fontSize=9, textColor=GREEN, leading=13, spaceAfter=2)


def make_table(headers, rows, col_widths=None):
    data = [[Paragraph(h, sTH) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), sTD) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ALIGN", (0, 0), (-1, 0), "LEFT"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, GREY2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GREY1]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    t.setStyle(TableStyle(style))
    return t


def build():
    doc = SimpleDocTemplate(
        "Phishield_vs_Nucleus_Comparison.pdf",
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    story = []

    # Title
    story.append(Paragraph("Phishield vs Nucleus Security", sTitle))
    story.append(Paragraph("Comparative Analysis &amp; Strategic Roadmap for Insurance Cyber Risk Platform", sSubtitle))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    story.append(Spacer(1, 10))

    # Section 1: Architecture
    story.append(Paragraph("1. Architecture &amp; Approach", sH1))
    cw = [90, 190, 190]
    story.append(make_table(
        ["Aspect", "Phishield", "Nucleus Security"],
        [
            ["Type", "Standalone scanner \u2014 runs its own checks directly against a domain", "Aggregation platform \u2014 ingests data from 200+ external scanners"],
            ["Target user", "Insurance underwriters evaluating cyber risk", "Enterprise security teams managing vulnerability programs"],
            ["Deployment", "Self-hosted Flask API, single scan per domain", "SaaS platform, enterprise-scale multi-tenant"],
            ["Scanning", "Direct (DNS, HTTP, Shodan, HIBP, crt.sh, NVD, EPSS, KEV)", "Does not scan itself \u2014 orchestrates data from Qualys, Nessus, Tenable, etc."],
        ],
        col_widths=cw,
    ))

    # Section 2: Where Nucleus is Better
    story.append(Paragraph("2. Where Nucleus is Better", sH1))

    nucleus_advantages = [
        ("<b>Scale &amp; data aggregation</b> \u2014 Nucleus ingests from 200+ tools (network, cloud, app, OT) and deduplicates findings across scanners. Phishield runs 20 checks in isolation.",),
        ("<b>Custom risk scoring</b> \u2014 Nucleus lets customers define their own risk scoring algorithm with weighted factors (asset criticality, data sensitivity, internet exposure, compliance scope). Phishield has a fixed scoring model.",),
        ("<b>AI-powered threat intelligence</b> \u2014 Nucleus Insights provides daily-refreshed Nucleus Threat Rating (NTR) per CVE with exploitation signals (Exploited, Public Exploit, Exploited by Malware, OT Impact, exploit-chain context). Phishield uses static EPSS + KEV lookups.",),
        ("<b>Remediation workflow</b> \u2014 Bi-directional integrations with Jira, ServiceNow, SIEMs. Automated ticketing, SLA tracking, remediation status. Phishield has no workflow/ticketing.",),
        ("<b>Organisational risk language</b> \u2014 Aggregated risk scores by team, department, asset group. Board-level reporting. Phishield produces per-domain reports only.",),
        ("<b>Compliance &amp; FedRAMP</b> \u2014 Nucleus is FedRAMP authorised, serves DoD/government. Phishield has no compliance certifications.",),
        ("<b>Historical tracking</b> \u2014 Nucleus tracks vulnerability lifecycle over time, trending, and remediation velocity. Phishield is point-in-time only.",),
    ]
    for item in nucleus_advantages:
        story.append(Paragraph(f"\u2022  {item[0]}", sBullet))

    # Section 3: Where Phishield is Better
    story.append(Paragraph("3. Where Phishield is Better", sH1))

    phishield_advantages = [
        ("<b>Zero-dependency external scanning</b> \u2014 Phishield scans a domain from scratch with no agents, no credentials, no prior tooling. Nucleus requires existing scanner infrastructure to feed it data. For insurance underwriting, this is critical \u2014 you cannot ask a prospect to install Qualys before quoting them.",),
        ("<b>Insurance-specific context</b> \u2014 Every finding maps to insurance risk language and underwriting impact. Port exploit cards show data exfiltration vectors and breach claim likelihood. Nucleus speaks security operations language, not insurance language.",),
        ("<b>Speed to value</b> \u2014 Single API call produces a full domain assessment in ~60 seconds. Nucleus requires onboarding, scanner integrations, agent deployment, and configuration before producing results.",),
        ("<b>External attack surface focus</b> \u2014 Phishield checks 20 categories an attacker sees from outside (SSL, headers, email auth, DNS, open ports, breaches, credential leaks, admin paths, WAF, cloud/CDN, VPN/RDP, tech stack EOL, payment security). Nucleus focuses on internal vulnerability management.",),
        ("<b>Per-IP vulnerability discovery</b> \u2014 Phishield auto-discovers all external IPs (A, AAAA, MX, NS, SPF, subdomains via crt.sh), enriches each with geo/ASN, and scans each through Shodan \u2192 CVE \u2192 CVSS \u2192 EPSS \u2192 KEV. This external attack surface mapping is built-in.",),
        ("<b>Cost</b> \u2014 Phishield uses entirely free APIs (Shodan InternetDB, NVD, FIRST.org EPSS, CISA KEV, crt.sh, ip-api.com). Nucleus is enterprise SaaS with significant licensing costs.",),
        ("<b>PDF/HTML reporting for underwriting</b> \u2014 Purpose-built reports with risk gauges, traffic-light scoring, and insurance-relevant remediation. Nucleus dashboards are designed for security teams, not insurance quote workflows.",),
    ]
    for item in phishield_advantages:
        story.append(Paragraph(f"\u2022  {item[0]}", sBullet))

    story.append(PageBreak())

    # Section 4: Sophos Central Integration Analysis
    story.append(Paragraph("4. Sophos Central Integration Analysis", sH1))
    story.append(Paragraph(
        "If Phishield gains access to Sophos Central threat feeds, it would partially close the gap with Nucleus "
        "and create an even stronger position for the insurance vertical.",
        sBody,
    ))

    story.append(Paragraph("What Sophos Central Would Add", sH2))
    sophos_items = [
        "<b>Internal threat visibility</b> \u2014 malware detections, ransomware attempts, lateral movement, C2 callbacks",
        "<b>Endpoint posture</b> \u2014 patch status, tamper protection, encryption state, policy compliance",
        "<b>Real-time alerting</b> \u2014 active incidents, not just static vulnerabilities",
        "<b>Network-level events</b> \u2014 firewall blocks, IPS triggers, web filtering logs",
    ]
    for item in sophos_items:
        story.append(Paragraph(f"\u2022  {item}", sBullet))

    story.append(Paragraph(
        "This closes the biggest gap vs Nucleus: <b>internal visibility</b>. Currently Phishield only sees what an "
        "attacker sees from outside. Sophos Central reveals what is happening inside the insured's perimeter.",
        sBody,
    ))

    # Comparison table
    story.append(Paragraph("Capability Comparison with Sophos Integration", sH2))
    cw2 = [120, 175, 175]
    story.append(make_table(
        ["Capability", "Nucleus (200+ feeds)", "Phishield + Sophos Central"],
        [
            ["External attack surface", "Via third-party scanners", "Native (already built)"],
            ["Internal vuln data", "Via Qualys/Tenable/Nessus feeds", "Via Sophos endpoint posture"],
            ["Active exploitation signals", "Nucleus Insights AI", "Sophos real-time threat detections"],
            ["Threat feed enrichment", "NTR, EPSS, KEV, exploit chains", "EPSS, KEV, CVSS + Sophos threat intel"],
            ["Continuous monitoring", "Yes", "Yes (with Sophos polling)"],
        ],
        col_widths=cw2,
    ))

    # Remaining gaps
    story.append(Paragraph("Remaining Gaps After Sophos Integration", sH2))
    gaps = [
        "<b>Multi-tool aggregation</b> \u2014 Nucleus aggregates 200+ tools. Sophos alone covers endpoints/firewall but not cloud misconfigs (AWS/Azure/GCP), container vulnerabilities, code scanning (SAST/DAST), or OT/IoT. Additional integrations would be needed over time.",
        "<b>Cross-scanner deduplication</b> \u2014 Nucleus correlates findings across multiple scanners reporting the same CVE. With a single feed, deduplication is simpler but cross-validation is lost.",
        "<b>Custom risk scoring algorithms</b> \u2014 Nucleus lets customers weight factors. Phishield would need to build an insurance-specific equivalent \u2014 but is better positioned because the insurer defines what matters for underwriting.",
    ]
    for item in gaps:
        story.append(Paragraph(f"\u2022  {item}", sBullet))

    # Section 5: Strategic Advantage
    story.append(Paragraph("5. Strategic Advantage for Insurance", sH1))
    story.append(Paragraph(
        "<b>Nucleus serves the insured's security team.</b> It helps them manage their own vulnerabilities. "
        "The insurer has no visibility into it.",
        sBody,
    ))
    story.append(Paragraph(
        "<b>Phishield serves the insurer.</b> If Sophos Central is integrated with the insured's consent, "
        "the insurer gains:",
        sBody,
    ))
    advantages = [
        "<b>Pre-bind assessment</b> \u2014 external scan (current capability)",
        "<b>Continuous portfolio monitoring</b> \u2014 ongoing risk posture of all insureds",
        "<b>Claims correlation</b> \u2014 match threat detections to actual claims data over time",
        "<b>Premium adjustment signals</b> \u2014 risk score changes trigger mid-term reviews",
        "<b>Loss prevention</b> \u2014 alert insureds before incidents become claims",
    ]
    for item in advantages:
        story.append(Paragraph(f"\u2022  {item}", sBullet))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "No vulnerability management platform does this because they are not built for the "
        "insurer-insured relationship. This is Phishield's strategic moat.",
        sBold,
    ))

    # Section 6: Recommended Build-Out Path
    story.append(Paragraph("6. Recommended Build-Out Path", sH1))

    phases = [
        ("Phase 1 (Current)", "External-only scan for underwriting \u2014 completed. 20 scan categories covering SSL, email auth, DNS, open ports, CVE/CVSS/EPSS/KEV, credential exposure, admin paths, tech stack EOL, and more."),
        ("Phase 2", "Add Sophos Central API integration for consenting insureds. Poll /endpoint/v1/endpoints for device posture, /common/v1/alerts for active threats, /endpoint/v1/settings/tamper-protection for security hygiene. Store historical snapshots for trend analysis."),
        ("Phase 3", "Add 2\u20133 more integrations based on insured portfolio (Microsoft 365/Defender, CrowdStrike, SentinelOne) to broaden internal visibility coverage."),
        ("Phase 4", "Build the insurance-specific risk model \u2014 correlate security telemetry with claims data to build actuarial-grade risk scoring that no security vendor can replicate."),
    ]
    for phase_title, phase_desc in phases:
        story.append(Paragraph(phase_title, sPhase))
        story.append(Paragraph(phase_desc, sBullet))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The moat is not in the number of integrations (Nucleus wins that race). The moat is in "
        "<b>combining security telemetry with insurance outcomes</b> \u2014 something only an insurer-facing "
        "platform can do.",
        ParagraphStyle("closing", fontName="Helvetica-Oblique", fontSize=10, textColor=NAVY, leading=14),
    ))

    doc.build(story)
    print("PDF generated: Phishield_vs_Nucleus_Comparison.pdf")


if __name__ == "__main__":
    build()
