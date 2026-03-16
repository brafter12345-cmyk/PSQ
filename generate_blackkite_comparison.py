"""
Generate Phishield vs Black Kite comparison & implementation roadmap PDF
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

# Colours
NAVY      = colors.HexColor("#0f2744")
BLUE      = colors.HexColor("#1d4ed8")
BLUE_LT   = colors.HexColor("#dbeafe")
GREEN     = colors.HexColor("#16a34a")
GREEN_BG  = colors.HexColor("#dcfce7")
AMBER     = colors.HexColor("#d97706")
AMBER_BG  = colors.HexColor("#fef9c3")
RED       = colors.HexColor("#dc2626")
RED_BG    = colors.HexColor("#fee2e2")
GREY1     = colors.HexColor("#f8fafc")
GREY2     = colors.HexColor("#e2e8f0")
GREY3     = colors.HexColor("#94a3b8")
GREY4     = colors.HexColor("#475569")
BLACK     = colors.HexColor("#0f172a")
WHITE     = colors.white

# ── Styles ──────────────────────────────────────────────────────────────
sTitle    = ParagraphStyle("title",    fontName="Helvetica-Bold",   fontSize=22, textColor=NAVY,  spaceAfter=6, leading=26)
sSubtitle = ParagraphStyle("subtitle", fontName="Helvetica",        fontSize=11, textColor=GREY4, spaceAfter=20, leading=14)
sH1       = ParagraphStyle("h1",       fontName="Helvetica-Bold",   fontSize=15, textColor=NAVY,  spaceBefore=22, spaceAfter=10, leading=18)
sH2       = ParagraphStyle("h2",       fontName="Helvetica-Bold",   fontSize=11, textColor=BLUE,  spaceBefore=16, spaceAfter=8,  leading=14)
sH3       = ParagraphStyle("h3",       fontName="Helvetica-Bold",   fontSize=10, textColor=NAVY,  spaceBefore=12, spaceAfter=6,  leading=13)
sBody     = ParagraphStyle("body",     fontName="Helvetica",        fontSize=9.5,textColor=BLACK, leading=14, spaceAfter=6)
sBold     = ParagraphStyle("bold",     fontName="Helvetica-Bold",   fontSize=9.5,textColor=BLACK, leading=14, spaceAfter=6)
sBullet   = ParagraphStyle("bullet",   fontName="Helvetica",        fontSize=9.5,textColor=BLACK, leading=14, leftIndent=16, spaceAfter=4)
sNote     = ParagraphStyle("note",     fontName="Helvetica-Oblique",fontSize=9,  textColor=GREY4, leading=12, spaceAfter=4, leftIndent=16)
sTH       = ParagraphStyle("th",       fontName="Helvetica-Bold",   fontSize=8.5,textColor=WHITE, leading=12)
sTD       = ParagraphStyle("td",       fontName="Helvetica",        fontSize=8.5,textColor=BLACK, leading=12)
sCode     = ParagraphStyle("code",     fontName="Courier",          fontSize=8,  textColor=BLACK, leading=11, spaceAfter=2, leftIndent=20)
sPhase    = ParagraphStyle("phase",    fontName="Helvetica-Bold",   fontSize=10, textColor=GREEN, leading=14, spaceBefore=10, spaceAfter=4)
sClosing  = ParagraphStyle("closing",  fontName="Helvetica-Oblique",fontSize=10, textColor=NAVY,  leading=14, spaceBefore=8)
sCallout  = ParagraphStyle("callout",  fontName="Helvetica-Bold",   fontSize=9.5,textColor=BLUE,  leading=14, spaceAfter=6, leftIndent=16)


def tbl(headers, rows, col_widths=None):
    data = [[Paragraph(h, sTH) for h in headers]]
    for row in rows:
        data.append([Paragraph(str(c), sTD) for c in row])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), WHITE),
        ("FONTSIZE",      (0, 0), (-1, -1), 8.5),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 7),
        ("TOPPADDING",    (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
        ("TOPPADDING",    (0, 1), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
        ("GRID",          (0, 0), (-1, -1), 0.5, GREY2),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, GREY1]),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def callout_box(text, bg=BLUE_LT, border=BLUE):
    """Coloured callout box."""
    t = Table([[Paragraph(text, sCallout)]], colWidths=[W - 40*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), bg),
        ("BOX",         (0, 0), (-1, -1), 1, border),
        ("TOPPADDING",  (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0,0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",(0, 0), (-1, -1), 10),
    ]))
    return t


def build():
    doc = SimpleDocTemplate(
        "Phishield_vs_BlackKite_Analysis.pdf",
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    s = []  # story

    # ── Title ───────────────────────────────────────────────────────────
    s.append(Paragraph("Phishield vs Black Kite", sTitle))
    s.append(Paragraph("DBI, RSI &amp; Financial Impact Analysis  |  Implementation Roadmap for Insurance Cyber Risk Platform", sSubtitle))
    s.append(HRFlowable(width="100%", thickness=1.5, color=NAVY))
    s.append(Spacer(1, 14))

    # ── Section 1: Three Pillars ────────────────────────────────────────
    s.append(Paragraph("1. Black Kite's Three Risk Dimensions", sH1))
    s.append(Paragraph(
        "Black Kite separates cyber risk into three temporal dimensions, each serving a "
        "distinct purpose in risk assessment and insurance underwriting.",
        sBody))
    s.append(Spacer(1, 6))

    s.append(tbl(
        ["Metric", "Time Dimension", "What It Measures"],
        [
            ["DBI (Data Breach Index)", "Past",
             "Historical breach context \u2014 has this company been breached? When, how severe, what data was exposed?"],
            ["Technical Rating (A\u2013F)", "Present",
             "Current security posture across 20 categories, 298 controls (SSL, DNS, patching, email, attack surface, etc.)"],
            ["RSI (Ransomware Susceptibility Index)", "Future",
             "Probability of ransomware attack, using ML + OSINT + threat actor TTP mapping (0.0\u20131.0 scale)"],
        ],
        col_widths=[95, 65, 310],
    ))
    s.append(Spacer(1, 10))

    # DBI
    s.append(Paragraph("Data Breach Index (DBI) \u2014 Backward-Looking", sH2))
    for b in [
        "Aggregates <b>historical breach data</b> \u2014 dates, affected assets, breach type, data classes exposed",
        "Sources: public breach databases, dark web monitoring, leaked credential feeds, regulatory disclosures",
        "Companies with recent/repeated breaches score higher (worse) on DBI",
        "DBI peaked for Oracle Cloud in October 2024, months before their March 2025 breach \u2014 demonstrating predictive signal",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 6))

    # RSI
    s.append(Paragraph("Ransomware Susceptibility Index (RSI) \u2014 Forward-Looking", sH2))
    s.append(Paragraph("Two input categories fed into an ML model producing a 0.0\u20131.0 score:", sBody))
    s.append(Spacer(1, 4))

    s.append(Paragraph("Technical Indicators:", sH3))
    for b in [
        "Exposed remote access ports (RDP, VPN)",
        "Unpatched CVEs \u2014 especially RCE (Zerologon, PrintNightmare, Fortinet)",
        "Stealer logs (credentials from infected machines, sold on dark web / Telegram)",
        "Leaked credentials &amp; botnet activity",
        "Misconfigurations across the attack surface",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 4))
    s.append(Paragraph("Intrinsic Risk Factors:", sH3))
    for b in [
        "Industry classification (healthcare, legal = higher risk)",
        "Geographic location and regulatory environment",
        "Company size / annual revenue (companies under $20M = higher susceptibility)",
        "Exposure history and breach recency",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 6))
    s.append(callout_box(
        "Predictive Power: Companies with RSI 0.8\u20131.0 are 96x more likely to experience "
        "ransomware than those below 0.2. Only 0.82% of monitored companies score above 0.8."
    ))

    s.append(Spacer(1, 10))

    # Financial Impact
    s.append(Paragraph("Financial Impact \u2014 Open FAIR Model", sH2))
    s.append(Paragraph(
        "Black Kite translates technical scores into dollar-denominated probable loss using the Open FAIR "
        "standard (Factor Analysis of Information Risk) \u2014 the only international standard VaR model for cybersecurity.",
        sBody))
    s.append(Spacer(1, 4))

    s.append(callout_box("Risk = Loss Event Frequency (LEF) \u00d7 Loss Magnitude (LM)", bg=GREEN_BG, border=GREEN))
    s.append(Spacer(1, 6))

    s.append(Paragraph("Three scenarios calculated independently then summed:", sBody))
    s.append(Spacer(1, 4))
    s.append(tbl(
        ["Scenario", "LEF Source", "Loss Magnitude Components"],
        [
            ["Data Breach",
             "Technical rating + DBI",
             "Records exposed \u00d7 cost-per-record ($165 avg) + regulatory fines + notification costs"],
            ["Ransomware",
             "RSI score",
             "Downtime (22 days avg) \u00d7 daily revenue + ransom demand + IR costs + reputation damage"],
            ["Business Interruption",
             "Supply chain / geopolitical / environmental",
             "Lost productivity + recovery costs + revenue loss during downtime"],
        ],
        col_widths=[95, 120, 255],
    ))

    s.append(Spacer(1, 8))
    s.append(Paragraph(
        "Output: Minimum / Most Likely / Maximum range (e.g. $9.2K / $222.5K / $2.5M annualised). "
        "This maps directly to insurance policy structuring \u2014 minimum informs deductible, most likely "
        "equals expected loss, maximum guides coverage limits.",
        sBody))

    s.append(PageBreak())

    # ── Section 2: Strategy Report Insights ─────────────────────────────
    s.append(Paragraph("2. Black Kite Strategy Report \u2014 Key Insights", sH1))
    s.append(Paragraph(
        "Black Kite's Strategy Report includes a before/after improvement model showing the financial "
        "impact of remediating specific findings. This is the most compelling feature for insurance.",
        sBody))
    s.append(Spacer(1, 6))

    s.append(Paragraph("Three-Gauge Layout:", sH2))
    s.append(tbl(
        ["Gauge", "Before Improvement", "After Improvement", "Change"],
        [
            ["Cyber Rating", "A", "A+", "+4% increase"],
            ["Probable Financial Impact", "$222.5K most likely", "$176.2K most likely", "$46K decrease"],
            ["Compliance Rating", "66%", "77%", "+16% increase"],
        ],
        col_widths=[110, 120, 120, 120],
    ))

    s.append(Spacer(1, 10))
    s.append(Paragraph("Improvement Steps (Prioritised):", sH2))
    s.append(Paragraph(
        "Step 1 lists the most critical findings. After fixing Step 1, the model recalculates all three "
        "gauges to show the projected improvement. Steps are ordered by impact on financial exposure.",
        sBody))
    s.append(Spacer(1, 4))

    s.append(tbl(
        ["Step 1 Categories", "Findings to Fix"],
        [
            ["Email Security", "1"],
            ["SSL/TLS Strength", "1"],
            ["Fraudulent Domains", "3"],
            ["Information Disclosure", "2"],
            ["Hacktivist Shares", "1"],
        ],
        col_widths=[280, 190],
    ))

    s.append(Spacer(1, 10))
    s.append(Paragraph("Insurance Value of Before/After Model:", sH2))
    for b in [
        "<b>Premium justification</b> \u2014 \"Fix these 8 findings and your probable loss drops $46K/year, justifying a premium reduction\"",
        "<b>Loss prevention</b> \u2014 insurer provides a remediation roadmap tied to measurable financial outcomes",
        "<b>Policy structuring</b> \u2014 min/most likely/max range maps to deductible/expected loss/coverage limit",
        "<b>Renewal incentives</b> \u2014 track improvement between policy periods to reward risk reduction",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 14))

    # ── Section 3: Category Mapping ─────────────────────────────────────
    s.append(Paragraph("3. Phishield Coverage vs Black Kite's 20 Categories", sH1))
    s.append(Paragraph(
        "Phishield currently covers approximately 14 of Black Kite's 20 risk categories. "
        "The 6 missing categories are primarily reputation and brand intelligence.",
        sBody))
    s.append(Spacer(1, 6))

    s.append(tbl(
        ["Black Kite Category", "Phishield Equivalent", "Status"],
        [
            ["SSL/TLS Strength",       "SSL/TLS Checker",                              "Covered"],
            ["DNS Health",             "DNS &amp; Open Ports",                          "Covered"],
            ["Email Security",         "Email Auth + Advanced Email Hardening",         "Covered"],
            ["Application Security",   "HTTP Security Headers + Website Security",      "Partial"],
            ["Patch Management",       "Technology Stack &amp; EOL",                    "Partial"],
            ["Attack Surface",         "CVE / Known Vulnerabilities (per-IP scan)",     "Covered"],
            ["Network Security",       "Database &amp; Service Exposure + HRP",         "Covered"],
            ["IP/Domain Reputation",   "IP / Domain Reputation (DNSBL)",                "Covered"],
            ["Credential Management",  "Credential Exposure (HIBP) + Dehashed",         "Covered"],
            ["CDN Security",           "Cloud &amp; CDN Infrastructure",                "Partial"],
            ["DDoS Resilience",        "WAF / DDoS Protection",                         "Covered"],
            ["Website Security",       "Website Security + Exposed Admin Paths",        "Covered"],
            ["Digital Footprint",      "Subdomain Exposure + External IP Discovery",    "Covered"],
            ["Information Disclosure", "Partially in existing checkers",                "Partial"],
            ["Web Ranking",            "\u2014",                                        "Missing"],
            ["Brand Monitoring",       "\u2014",                                        "Missing"],
            ["Hacktivist Shares",      "\u2014",                                        "Missing"],
            ["Fraudulent Apps",        "\u2014",                                        "Missing"],
            ["Fraudulent Domains",     "\u2014",                                        "Missing"],
            ["Social Media",           "\u2014",                                        "Missing"],
        ],
        col_widths=[115, 220, 135],
    ))

    s.append(PageBreak())

    # ── Section 4: Implementation Plan ──────────────────────────────────
    s.append(Paragraph("4. Implementation Roadmap for Phishield", sH1))
    s.append(Paragraph(
        "Recommended features to implement, ordered by value to insurance underwriting.",
        sBody))
    s.append(Spacer(1, 8))

    # Feature 1: RSI
    s.append(Paragraph("Feature 1: Ransomware Susceptibility Index (RSI)", sH2))
    s.append(Paragraph("<b>Priority: Highest</b> \u2014 ~80% of inputs already exist in Phishield.", sBold))
    s.append(Spacer(1, 4))

    s.append(Paragraph("Inputs already available:", sH3))
    for b in [
        "Open RDP port (VPN &amp; Remote Access checker) \u2014 strongest ransomware signal",
        "Exposed database ports (High-Risk Protocols) \u2014 MySQL, PostgreSQL, MongoDB",
        "Unpatched CVEs with known exploits + CISA KEV matches",
        "EPSS scores &gt; 0.5 \u2014 high exploitation probability",
        "SSL grade, email authentication failures, missing WAF",
        "Leaked credentials (HIBP / Dehashed) \u2014 credential stuffing vector",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 4))
    s.append(Paragraph("Additional inputs needed (user-provided at scan time):", sH3))
    for b in [
        "Industry sector (healthcare, finance, retail, tech, manufacturing, legal, etc.)",
        "Annual revenue or revenue band",
        "Country / primary jurisdiction",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 4))
    s.append(Paragraph("Scoring model (0.0\u20131.0, higher = worse):", sH3))
    for b in [
        "Base 0.1 + RDP exposed (+0.35) + exposed databases (+0.15 each, cap 0.30)",
        "KEV CVEs (+0.10 each, cap 0.25) + high EPSS CVEs (+0.05 each, cap 0.15)",
        "Leaked credentials &gt;100 (+0.10) + no DMARC (+0.05) + no WAF (+0.05) + weak SSL (+0.05)",
        "Industry multiplier: healthcare/legal \u00d71.3, finance \u00d71.2, tech \u00d71.0",
        "Size multiplier: &lt;$20M revenue \u00d71.2, $20M\u2013$500M \u00d71.0, &gt;$500M \u00d70.9",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 10))

    # Feature 2: Financial Impact
    s.append(Paragraph("Feature 2: Financial Impact Estimation (Open FAIR-Inspired)", sH2))
    s.append(Paragraph("<b>Priority: Critical</b> \u2014 the killer feature for insurance. Translates risk into dollars.", sBold))
    s.append(Spacer(1, 4))

    s.append(Paragraph("Formula:", sH3))
    s.append(Paragraph("Total Estimated Loss = Data Breach Loss + Ransomware Loss + Business Interruption Loss", sCode))
    s.append(Spacer(1, 4))

    s.append(tbl(
        ["Scenario", "Probability Source", "Loss Calculation"],
        [
            ["Data Breach",
             "Inverted technical score (0\u20131)",
             "P(breach) \u00d7 (est. records \u00d7 $165/record + regulatory fine)"],
            ["Ransomware",
             "RSI score",
             "RSI \u00d7 (22 days downtime \u00d7 daily revenue + ransom + IR cost)"],
            ["Business Interruption",
             "Infrastructure resilience signals",
             "P(interruption) \u00d7 (downtime \u00d7 daily revenue \u00d7 impact factor)"],
        ],
        col_widths=[95, 130, 245],
    ))

    s.append(Spacer(1, 6))
    s.append(Paragraph("Output: three-value range (minimum / most likely / maximum) plus:", sBody))
    for b in [
        "<b>Insurance recommendation</b> \u2014 minimum cover, recommended cover, premium risk tier",
        "<b>Improvement projection</b> \u2014 \"fix these N findings to reduce probable loss by $X\"",
        "<b>Before/after model</b> \u2014 recalculate financial impact after simulated remediation",
    ]:
        s.append(Paragraph(f"\u2022  {b}", sBullet))

    s.append(Spacer(1, 10))

    # Feature 3: DBI
    s.append(Paragraph("Feature 3: Data Breach Index (DBI)", sH2))
    s.append(Paragraph("<b>Priority: High</b> \u2014 low effort since HIBP/Dehashed data is already collected.", sBold))
    s.append(Spacer(1, 4))

    s.append(Paragraph("Scoring model (0\u2013100, lower = worse):", sH3))
    s.append(tbl(
        ["Factor", "Score Contribution"],
        [
            ["Breach count (HIBP)",           "0 breaches = +30  |  1\u20133 = +15  |  4+ = 0"],
            ["Most recent breach recency",    "&gt;3 years = +20  |  1\u20133 years = +10  |  &lt;1 year = 0"],
            ["Data classes severity",         "Emails only = +15  |  passwords/financials = 0"],
            ["Credential leak volume",        "0 = +20  |  1\u2013100 = +10  |  100+ = 0"],
            ["Breach trend",                  "Improving = +10  |  Worsening = 0"],
        ],
        col_widths=[160, 310],
    ))

    s.append(Spacer(1, 10))

    # Feature 4: Quick Wins
    s.append(Paragraph("Feature 4: Missing Category Coverage (Quick Wins)", sH2))
    s.append(tbl(
        ["Category", "Implementation Approach", "Effort"],
        [
            ["Fraudulent Domains",     "Query crt.sh for typosquat / lookalike domains (crt.sh integration exists)", "Low"],
            ["Web Ranking",            "Query Tranco list (free, updated daily) for domain popularity rank",         "Low"],
            ["Information Disclosure", "Expand checks for .env, .git, debug endpoints, verbose error pages",         "Low"],
            ["Hacktivist Shares",      "Dark web / Telegram API \u2014 or use leaked credentials as proxy",         "High"],
            ["Fraudulent Apps",        "Google Play / App Store search API",                                         "Medium"],
            ["Brand Monitoring",       "Social media mention scanning",                                              "Medium"],
        ],
        col_widths=[110, 270, 90],
    ))

    s.append(PageBreak())

    # ── Section 5: Build Priority ───────────────────────────────────────
    s.append(Paragraph("5. Recommended Build Sequence", sH1))
    s.append(Spacer(1, 6))

    phases = [
        ("Phase 1: RSI (Ransomware Susceptibility Index)",
         "Build RansomwareRiskChecker class. Combine existing scan signals (RDP, exposed DBs, KEV CVEs, "
         "EPSS, credentials, email auth, WAF) with user-provided industry/revenue inputs. "
         "Output 0.0\u20131.0 score with risk label and insurance context."),
        ("Phase 2: Financial Impact Calculator (FAIR-Based)",
         "Build FinancialImpactCalculator. Use RSI + technical score + DBI to derive Loss Event Frequency. "
         "Calculate Loss Magnitude per scenario using industry benchmarks (IBM/Ponemon, Verizon DBIR). "
         "Output min/most likely/max range with insurance coverage recommendations."),
        ("Phase 3: Data Breach Index (DBI)",
         "Build DataBreachIndexChecker. Score historical breach exposure from HIBP + Dehashed data "
         "already collected. Add temporal analysis (recency weighting, trend direction)."),
        ("Phase 4: Before/After Improvement Model",
         "The highest-value feature for insurance. For each finding, calculate the projected impact "
         "on financial exposure if remediated. Produce prioritised improvement steps showing "
         "\"fix these N items \u2192 $X reduction in probable annual loss.\""),
        ("Phase 5: Missing Categories",
         "Add fraudulent domain detection, web ranking (Tranco), and expanded information "
         "disclosure checks to reach 17+ of 20 Black Kite categories."),
    ]
    for title, desc in phases:
        s.append(Paragraph(title, sPhase))
        s.append(Paragraph(desc, sBullet))
        s.append(Spacer(1, 6))

    s.append(Spacer(1, 10))

    # ── Section 6: Strategic Positioning ────────────────────────────────
    s.append(Paragraph("6. Strategic Positioning", sH1))
    s.append(Spacer(1, 6))

    s.append(tbl(
        ["Dimension", "Black Kite", "Phishield (Target State)"],
        [
            ["Primary user",        "CISO / third-party risk teams",              "Insurance underwriters &amp; portfolio managers"],
            ["Scanning approach",   "Passive OSINT, 1,000+ data sources",         "Active external scan + user-provided context"],
            ["Risk quantification", "Open FAIR with 3 scenarios",                 "FAIR-inspired with insurance-specific outputs"],
            ["Unique advantage",    "200+ integrations, MITRE/NIST alignment",    "Zero-dependency scan, insurance language, premium/coverage guidance"],
            ["Before/after model",  "Yes \u2014 strategy report with improvement steps", "To be built \u2014 with dollar-denominated improvement projections"],
            ["Continuous monitoring","Yes \u2014 enterprise platform",             "Phase 2 roadmap (Sophos Central + additional integrations)"],
        ],
        col_widths=[100, 185, 185],
    ))

    s.append(Spacer(1, 14))
    s.append(HRFlowable(width="100%", thickness=1.5, color=NAVY))
    s.append(Spacer(1, 10))
    s.append(Paragraph(
        "Black Kite's moat is scale, integrations, and enterprise maturity. Phishield's moat is "
        "<b>translating cyber risk into insurance decisions</b> \u2014 premium pricing, coverage structuring, "
        "loss prevention, and claims correlation. These are fundamentally different products serving "
        "different buyers, but Phishield can adopt Black Kite's best ideas (RSI, FAIR, before/after model) "
        "and deliver them in an insurance-native context.",
        sClosing))

    doc.build(s)
    print("PDF generated: Phishield_vs_BlackKite_Analysis.pdf")


if __name__ == "__main__":
    build()
