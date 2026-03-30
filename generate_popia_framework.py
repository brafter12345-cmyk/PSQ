"""
POPIA Compliance Framework PDF Generator
Generates a formal compliance framework document for AI adoption in South African UMAs.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, black, white, gray
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    KeepTogether, ListFlowable, ListItem, HRFlowable
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate, Frame
from reportlab.platypus.frames import Frame as PlFrame
from reportlab.pdfgen import canvas

# ── Colour Palette ──────────────────────────────────────────────────────────
NAVY      = HexColor("#1B2A4A")
DARK_BLUE = HexColor("#2C3E6B")
ACCENT    = HexColor("#C8A951")   # Gold accent
LIGHT_BG  = HexColor("#F4F6F9")
MED_GRAY  = HexColor("#6B7280")
DARK_GRAY = HexColor("#374151")
TABLE_HDR = HexColor("#1B2A4A")
TABLE_ALT = HexColor("#EEF1F6")
RED_RISK  = HexColor("#DC2626")
AMBER     = HexColor("#D97706")
GREEN_OK  = HexColor("#059669")
BORDER    = HexColor("#D1D5DB")

WIDTH, HEIGHT = A4
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "POPIA_AI_Compliance_Framework.pdf")


# ── Styles ──────────────────────────────────────────────────────────────────
def build_styles():
    ss = getSampleStyleSheet()

    ss.add(ParagraphStyle(
        "CoverTitle", parent=ss["Title"],
        fontName="Helvetica-Bold", fontSize=28, leading=34,
        textColor=white, alignment=TA_CENTER, spaceAfter=10,
    ))
    ss.add(ParagraphStyle(
        "CoverSub", parent=ss["Normal"],
        fontName="Helvetica", fontSize=14, leading=18,
        textColor=HexColor("#D0D5DD"), alignment=TA_CENTER, spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        "H1", parent=ss["Heading1"],
        fontName="Helvetica-Bold", fontSize=18, leading=24,
        textColor=NAVY, spaceBefore=20, spaceAfter=10,
        borderWidth=0, borderPadding=0,
    ))
    ss.add(ParagraphStyle(
        "H2", parent=ss["Heading2"],
        fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=DARK_BLUE, spaceBefore=14, spaceAfter=6,
    ))
    ss.add(ParagraphStyle(
        "H3", parent=ss["Heading3"],
        fontName="Helvetica-Bold", fontSize=11, leading=14,
        textColor=DARK_BLUE, spaceBefore=10, spaceAfter=4,
    ))
    # Override existing BodyText style
    ss["BodyText"].fontName = "Helvetica"
    ss["BodyText"].fontSize = 10
    ss["BodyText"].leading = 14
    ss["BodyText"].textColor = DARK_GRAY
    ss["BodyText"].alignment = TA_JUSTIFY
    ss["BodyText"].spaceBefore = 2
    ss["BodyText"].spaceAfter = 6
    ss.add(ParagraphStyle(
        "SmallText", parent=ss["Normal"],
        fontName="Helvetica", fontSize=8, leading=10,
        textColor=MED_GRAY,
    ))
    ss.add(ParagraphStyle(
        "TableHeader", parent=ss["Normal"],
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=white, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        "TableCell", parent=ss["Normal"],
        fontName="Helvetica", fontSize=9, leading=12,
        textColor=DARK_GRAY, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        "TableCellBold", parent=ss["Normal"],
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=DARK_GRAY, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        "BulletBody", parent=ss["Normal"],
        fontName="Helvetica", fontSize=10, leading=14,
        textColor=DARK_GRAY, leftIndent=18, bulletIndent=6,
        spaceBefore=2, spaceAfter=2,
    ))
    ss.add(ParagraphStyle(
        "Footer", parent=ss["Normal"],
        fontName="Helvetica", fontSize=7, leading=9,
        textColor=MED_GRAY, alignment=TA_CENTER,
    ))
    ss.add(ParagraphStyle(
        "TOCEntry", parent=ss["Normal"],
        fontName="Helvetica", fontSize=10, leading=16,
        textColor=DARK_BLUE, leftIndent=10,
    ))
    ss.add(ParagraphStyle(
        "RiskHigh", parent=ss["Normal"],
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=RED_RISK, alignment=TA_CENTER,
    ))
    ss.add(ParagraphStyle(
        "RiskMed", parent=ss["Normal"],
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=AMBER, alignment=TA_CENTER,
    ))
    ss.add(ParagraphStyle(
        "RiskLow", parent=ss["Normal"],
        fontName="Helvetica-Bold", fontSize=9, leading=12,
        textColor=GREEN_OK, alignment=TA_CENTER,
    ))
    return ss


# ── Helper functions ────────────────────────────────────────────────────────
def bullet_list(items, ss):
    """Return a list of bullet-pointed paragraphs."""
    return [Paragraph(f"<bullet>&bull;</bullet> {item}", ss["BulletBody"]) for item in items]


def section_hr():
    return HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6, spaceBefore=6)


def make_table(headers, rows, col_widths, ss):
    """Build a styled table."""
    hdr = [Paragraph(h, ss["TableHeader"]) for h in headers]
    data = [hdr]
    for row in rows:
        data.append([Paragraph(str(c), ss["TableCell"]) if not isinstance(c, Paragraph) else c for c in row])

    t = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), TABLE_HDR),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 1), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 5),
    ]
    # Alternate row colours
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), TABLE_ALT))

    t.setStyle(TableStyle(style_cmds))
    return t


# ── Page templates ──────────────────────────────────────────────────────────
class FooterCanvas(canvas.Canvas):
    """Canvas that draws header/footer on every page (except cover)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pages = []

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self.pages)
        for i, page in enumerate(self.pages):
            self.__dict__.update(page)
            if i > 0:  # skip cover
                self._draw_header_footer(i + 1, num_pages)
            super().showPage()
        super().save()

    def _draw_header_footer(self, page_num, total):
        self.saveState()
        # Header line
        self.setStrokeColor(ACCENT)
        self.setLineWidth(1.5)
        self.line(25 * mm, HEIGHT - 18 * mm, WIDTH - 25 * mm, HEIGHT - 18 * mm)
        # Header text
        self.setFont("Helvetica", 7)
        self.setFillColor(MED_GRAY)
        self.drawString(25 * mm, HEIGHT - 16 * mm, "POPIA AI Compliance Framework")
        self.drawRightString(WIDTH - 25 * mm, HEIGHT - 16 * mm, "CONFIDENTIAL")
        # Footer line
        self.setStrokeColor(BORDER)
        self.setLineWidth(0.5)
        self.line(25 * mm, 18 * mm, WIDTH - 25 * mm, 18 * mm)
        # Footer text
        self.setFont("Helvetica", 7)
        self.setFillColor(MED_GRAY)
        self.drawString(25 * mm, 14 * mm, "Prepared by S Lamprecht")
        self.drawCentredString(WIDTH / 2, 14 * mm, f"Page {page_num - 1} of {total - 1}")
        self.drawRightString(WIDTH - 25 * mm, 14 * mm, datetime.now().strftime("%d %B %Y"))
        self.restoreState()


# ── Cover page ──────────────────────────────────────────────────────────────
def build_cover(ss):
    elements = []
    elements.append(Spacer(1, 40 * mm))

    # Navy background box via a table
    cover_data = [
        [Paragraph("", ss["CoverTitle"])],
        [Spacer(1, 10)],
        [Paragraph("POPIA Compliance Framework", ss["CoverTitle"])],
        [Paragraph("for AI Adoption in South African", ss["CoverTitle"])],
        [Paragraph("Underwriting Management Agencies", ss["CoverTitle"])],
        [Spacer(1, 15)],
        [Paragraph("_" * 40, ss["CoverSub"])],
        [Spacer(1, 10)],
        [Paragraph("Incorporating Claude AI (Chat, Cowork &amp; Code)", ss["CoverSub"])],
        [Paragraph("into FSP Process Flows", ss["CoverSub"])],
        [Spacer(1, 20)],
    ]
    cover_table = Table(cover_data, colWidths=[WIDTH - 50 * mm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    elements.append(cover_table)

    elements.append(Spacer(1, 25 * mm))

    # Meta info
    meta_style = ParagraphStyle("meta", fontName="Helvetica", fontSize=11, leading=16, textColor=DARK_GRAY, alignment=TA_CENTER)
    meta_bold = ParagraphStyle("metab", fontName="Helvetica-Bold", fontSize=11, leading=16, textColor=NAVY, alignment=TA_CENTER)

    elements.append(Paragraph("Prepared by", meta_style))
    elements.append(Paragraph("S Lamprecht", meta_bold))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(datetime.now().strftime("%d %B %Y"), meta_style))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("Version 1.0", meta_style))
    elements.append(Spacer(1, 30 * mm))

    # Classification
    class_data = [[Paragraph("CONFIDENTIAL", ParagraphStyle(
        "cls", fontName="Helvetica-Bold", fontSize=10, textColor=RED_RISK, alignment=TA_CENTER
    ))]]
    class_table = Table(class_data, colWidths=[60 * mm])
    class_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, RED_RISK),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(class_table)

    elements.append(PageBreak())
    return elements


# ── Document version / distribution table ───────────────────────────────────
def build_doc_control(ss):
    elements = []
    elements.append(Paragraph("Document Control", ss["H1"]))
    elements.append(section_hr())

    headers = ["Version", "Date", "Author", "Description"]
    rows = [
        ["1.0", datetime.now().strftime("%d %B %Y"), "S Lamprecht", "Initial release"],
    ]
    t = make_table(headers, rows, [20 * mm, 30 * mm, 35 * mm, None], ss)
    elements.append(t)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Distribution", ss["H2"]))
    headers2 = ["Recipient", "Role", "Classification"]
    rows2 = [
        ["Board of Directors", "Governance oversight", "Confidential"],
        ["Compliance Officer / Information Officer", "Regulatory compliance", "Confidential"],
        ["IT / Technology Lead", "Implementation", "Confidential"],
        ["Underwriting Manager", "Operational adoption", "Confidential"],
    ]
    t2 = make_table(headers2, rows2, [45 * mm, 50 * mm, None], ss)
    elements.append(t2)
    elements.append(PageBreak())
    return elements


# ── Table of Contents ───────────────────────────────────────────────────────
def build_toc(ss):
    elements = []
    elements.append(Paragraph("Table of Contents", ss["H1"]))
    elements.append(section_hr())
    elements.append(Spacer(1, 6))

    toc_items = [
        ("1.", "Executive Summary"),
        ("2.", "Regulatory Landscape"),
        ("  2.1", "Protection of Personal Information Act (POPIA)"),
        ("  2.2", "FSCA / Prudential Authority AI Guidance"),
        ("  2.3", "Draft National AI Policy Framework"),
        ("3.", "Anthropic Claude: Data Handling &amp; Contractual Protections"),
        ("  3.1", "Consumer vs Commercial Tiers"),
        ("  3.2", "Data Processing Addendum (DPA)"),
        ("  3.3", "Zero Data Retention (ZDR)"),
        ("4.", "Cross-Border Data Transfer Compliance"),
        ("  4.1", "POPIA Section 72 Analysis"),
        ("  4.2", "Standard Contractual Clauses"),
        ("  4.3", "AWS Bedrock Deployment Option"),
        ("5.", "UMA Process Verticals: AI Use Cases &amp; PII Risk"),
        ("  5.1", "Underwriting"),
        ("  5.2", "Claims Management"),
        ("  5.3", "Policy Administration"),
        ("  5.4", "Compliance &amp; Reporting"),
        ("  5.5", "Client Onboarding (FICA/KYC)"),
        ("  5.6", "Broker / Intermediary Management"),
        ("6.", "PII Gateway Architecture"),
        ("7.", "Compliance Checklist"),
        ("8.", "Risk Register"),
        ("9.", "Implementation Roadmap"),
        ("10.", "Appendix A: Key POPIA Sections Reference"),
        ("11.", "Appendix B: Glossary"),
    ]

    for num, title in toc_items:
        indent = 20 if num.startswith("  ") else 0
        style = ParagraphStyle(
            "toc_item", fontName="Helvetica-Bold" if not num.startswith("  ") else "Helvetica",
            fontSize=10, leading=18, textColor=DARK_BLUE, leftIndent=indent,
        )
        elements.append(Paragraph(f"{num.strip()}  {title}", style))

    elements.append(PageBreak())
    return elements


# ── Section 1: Executive Summary ────────────────────────────────────────────
def build_executive_summary(ss):
    elements = []
    elements.append(Paragraph("1. Executive Summary", ss["H1"]))
    elements.append(section_hr())

    elements.append(Paragraph(
        "This document provides a comprehensive compliance framework for the adoption of Anthropic's Claude AI "
        "(including Claude Chat, Claude for Work, and Claude Code) across the operational verticals of a South African "
        "Underwriting Management Agency (UMA) operating as a Financial Service Provider (FSP) under the Financial "
        "Sector Conduct Authority (FSCA).",
        ss["BodyText"]
    ))
    elements.append(Paragraph(
        "The framework addresses the critical intersection of AI-driven operational efficiency and the legal obligations "
        "imposed by the Protection of Personal Information Act 4 of 2013 (POPIA), with particular focus on:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "The lawful processing of personal information through AI tools (POPIA Sections 9-12)",
        "Cross-border data transfer requirements (POPIA Section 72)",
        "Automated decision-making safeguards (POPIA Section 71)",
        "Operator agreement obligations (POPIA Sections 20-21)",
        "FSCA Treating Customers Fairly (TCF) principles as they apply to AI-assisted decisions",
        "Practical data anonymisation and PII gateway architecture",
    ], ss))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        "The framework recommends a phased approach, beginning with low-PII-risk use cases (such as policy wording "
        "analysis and code development) and progressing to higher-risk operational verticals only after appropriate "
        "safeguards, including a PII anonymisation gateway, are in place.",
        ss["BodyText"]
    ))
    elements.append(Paragraph(
        "<b>Key Finding:</b> Claude AI can be lawfully incorporated into UMA operations provided that (a) commercial-tier "
        "products with appropriate Data Processing Addenda are used, (b) personal information is anonymised or "
        "pseudonymised before transmission, (c) human oversight is maintained for all decisions affecting policyholders, "
        "and (d) the cross-border transfer mechanisms under Section 72 are properly established.",
        ss["BodyText"]
    ))
    elements.append(PageBreak())
    return elements


# ── Section 2: Regulatory Landscape ─────────────────────────────────────────
def build_regulatory_landscape(ss):
    elements = []
    elements.append(Paragraph("2. Regulatory Landscape", ss["H1"]))
    elements.append(section_hr())

    # 2.1 POPIA
    elements.append(Paragraph("2.1 Protection of Personal Information Act (POPIA)", ss["H2"]))
    elements.append(Paragraph(
        "POPIA, effective 1 July 2021, is the primary legislation governing the processing of personal information in "
        "South Africa. It applies to all responsible parties who process personal information of data subjects within "
        "South Africa, regardless of where the processing occurs. Notably, POPIA extends protection to juristic persons "
        "(companies, trusts, and legal entities) in addition to natural persons.",
        ss["BodyText"]
    ))
    elements.append(Paragraph("Key POPIA provisions relevant to AI adoption:", ss["BodyText"]))
    elements.extend(bullet_list([
        "<b>Section 9-12 (Conditions for Lawful Processing):</b> Personal information must be processed lawfully, "
        "with a valid legal basis such as consent, contractual necessity, or legitimate interest.",
        "<b>Section 10 (Minimality):</b> Processing must be adequate, relevant, and not excessive. This is critical "
        "when deciding what data to feed into AI systems.",
        "<b>Section 13 (Purpose Limitation):</b> Personal information must be collected for a specific, explicitly "
        "defined and lawful purpose, and not processed in a manner incompatible with that purpose.",
        "<b>Section 19 (Security Safeguards):</b> Appropriate technical and organisational measures must secure the "
        "integrity and confidentiality of personal information.",
        "<b>Sections 20-21 (Operator Provisions):</b> Where a third party (operator) processes personal information "
        "on behalf of the responsible party, a written contract must be in place ensuring POPIA compliance.",
        "<b>Section 71 (Automated Decision-Making):</b> A data subject may not be subject to a decision with legal "
        "consequences based solely on automated processing intended to profile them. Exceptions exist where the "
        "decision is required by law, for contract performance, or where appropriate measures exist to protect "
        "the data subject's legitimate interests.",
        "<b>Section 72 (Cross-Border Transfers):</b> Personal information may only be transferred outside South "
        "Africa if the recipient is subject to adequate legal protections, bound by binding corporate rules, "
        "contractual safeguards, or where the data subject consents.",
    ], ss))
    elements.append(Spacer(1, 4))

    elements.append(Paragraph(
        "<b>Penalties:</b> Non-compliance may result in administrative fines of up to ZAR 10 million, imprisonment "
        "for up to 10 years, or civil claims for damages.",
        ss["BodyText"]
    ))

    # 2.2 FSCA
    elements.append(Paragraph("2.2 FSCA / Prudential Authority AI Guidance", ss["H2"]))
    elements.append(Paragraph(
        "In November 2025, the FSCA and the Prudential Authority (PA) released a landmark report on AI in "
        "South Africa's financial sector, based on approximately 2,100 survey responses. Key findings relevant to UMAs:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "Insurance sector AI adoption stands at approximately 8%, significantly behind banking (52%) and payments (50%).",
        "Insurers intend to expand AI usage in underwriting and claims management, but high-stakes decision-making "
        "remains cautious due to explainability, data quality, and regulatory compliance concerns.",
        "The FSCA's Treating Customers Fairly (TCF) principles require transparency in AI decision-making processes, "
        "with clear explanations of AI-driven decisions to customers and regulators.",
        "The FSCA 2025-2028 Regulation Plan includes regulatory frameworks for AI governance and cloud technologies.",
        "The FSCA and PA intend to collaborate with the Information Regulator to ensure alignment with POPIA.",
    ], ss))

    # 2.3 Draft AI Policy
    elements.append(Paragraph("2.3 Draft National AI Policy Framework", ss["H2"]))
    elements.append(Paragraph(
        "South Africa's Draft National AI Policy has entered the Cabinet approval process and is expected to be "
        "gazetted for a 60-day public consultation period in March 2026, with finalisation targeted for the "
        "2026/2027 financial year. Key aspects:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "A risk-based approach to AI supervision, adapted to national priorities.",
        "A sector-specific, multi-regulator model (no single AI regulator; governance embedded in existing bodies "
        "such as the Information Regulator and FSCA).",
        "Emphasis on accountability: organisations remain responsible for AI-driven decision outcomes.",
        "Rejection of opaque 'black box' AI deployment in high-impact contexts.",
        "Five pillars: skills capacity, responsible governance, ethical AI, cultural preservation, and human-centred deployment.",
        "An AI Expert Advisory Council is being established to advise on ethical, legal, and technical challenges.",
    ], ss))

    elements.append(Paragraph(
        "<b>Implication for UMAs:</b> While no AI-specific legislation is yet in force, POPIA Section 71 and the "
        "FSCA's TCF principles already impose binding obligations. Early compliance positions the UMA favourably "
        "for the anticipated regulatory framework.",
        ss["BodyText"]
    ))
    elements.append(PageBreak())
    return elements


# ── Section 3: Anthropic Data Handling ──────────────────────────────────────
def build_anthropic_data(ss):
    elements = []
    elements.append(Paragraph("3. Anthropic Claude: Data Handling &amp; Contractual Protections", ss["H1"]))
    elements.append(section_hr())

    # 3.1
    elements.append(Paragraph("3.1 Consumer vs Commercial Tiers", ss["H2"]))
    elements.append(Paragraph(
        "Anthropic maintains a strict separation between consumer and commercial data handling. "
        "This distinction is critical for POPIA compliance:",
        ss["BodyText"]
    ))

    headers = ["Feature", "Consumer (Free/Pro/Max)", "Commercial (API / Claude for Work)"]
    rows = [
        ["Data used for training", "Opt-in (default since Oct 2025)", Paragraph("<b>Never</b>", ss["TableCell"])],
        ["Data retention", "30 days or 5 years (user choice)", Paragraph("<b>7 days default; opt-in 30 days</b>", ss["TableCell"])],
        ["Zero Data Retention", "Not available", Paragraph("<b>Available for qualifying enterprises</b>", ss["TableCell"])],
        ["DPA with SCCs", "Not available", Paragraph("<b>Automatically included</b>", ss["TableCell"])],
        ["Data location", "US-based", "US-based (or regional via Bedrock/Vertex)"],
        ["Employee access to data", "Only with consent or policy enforcement", "Same; additional contractual restrictions"],
        ["HIPAA/BAA support", "No", "Yes (qualifying customers)"],
    ]
    t = make_table(headers, rows, [40 * mm, None, None], ss)
    elements.append(t)
    elements.append(Spacer(1, 8))

    # Critical warning box
    warn_data = [[Paragraph(
        "<b>CRITICAL:</b> Consumer Claude (Free, Pro, Max) must NOT be used for processing client PII or policy "
        "information. Only Commercial-tier products (Claude for Work, API access) provide the contractual "
        "protections required under POPIA Sections 20-21.",
        ParagraphStyle("warn", fontName="Helvetica", fontSize=9, leading=13, textColor=RED_RISK)
    )]]
    warn_t = Table(warn_data, colWidths=[WIDTH - 55 * mm])
    warn_t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.5, RED_RISK),
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FEF2F2")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(warn_t)
    elements.append(Spacer(1, 8))

    # 3.2 DPA
    elements.append(Paragraph("3.2 Data Processing Addendum (DPA)", ss["H2"]))
    elements.append(Paragraph(
        "Anthropic's DPA with Standard Contractual Clauses (SCCs) is automatically incorporated into the Commercial "
        "Terms of Service. The DPA:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "Commits Anthropic to process covered data only in accordance with applicable data protection laws and "
        "on the documented instructions of the customer.",
        "Includes Standard Contractual Clauses (SCCs) that satisfy cross-border transfer requirements.",
        "Includes a UK Addendum for processing subject to UK GDPR.",
        "Governs over the general agreement in the event of conflict regarding data processing.",
        "Serves as the Operator Agreement required under POPIA Sections 20-21.",
    ], ss))
    elements.append(Paragraph(
        "The DPA should be reviewed by the UMA's legal counsel to confirm it provides protection 'substantially "
        "similar' to POPIA as required by Section 72.",
        ss["BodyText"]
    ))

    # 3.3 ZDR
    elements.append(Paragraph("3.3 Zero Data Retention (ZDR)", ss["H2"]))
    elements.append(Paragraph(
        "For enterprise API customers, Anthropic offers a Zero Data Retention agreement under which inputs and "
        "outputs are not stored beyond what is needed to screen for abuse. Under ZDR:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "Conversation inputs and outputs are not persisted after the request completes.",
        "Anthropic retains only User Safety classifier results for Usage Policy enforcement.",
        "ZDR is increasingly adopted by enterprises in finance, healthcare, and regulated industries.",
        "ZDR may require a separate negotiation with Anthropic and is subject to approval.",
    ], ss))
    elements.append(Paragraph(
        "<b>Recommendation:</b> For UMA operations involving any client data (even pseudonymised), ZDR should "
        "be pursued as an additional safeguard. This significantly reduces residual risk under POPIA Section 19.",
        ss["BodyText"]
    ))
    elements.append(PageBreak())
    return elements


# ── Section 4: Cross-Border Transfer ────────────────────────────────────────
def build_cross_border(ss):
    elements = []
    elements.append(Paragraph("4. Cross-Border Data Transfer Compliance", ss["H1"]))
    elements.append(section_hr())

    # 4.1
    elements.append(Paragraph("4.1 POPIA Section 72 Analysis", ss["H2"]))
    elements.append(Paragraph(
        "Anthropic's infrastructure is primarily US-based. Since the United States does not have a general "
        "adequacy determination from South Africa's Information Regulator, the UMA must rely on alternative "
        "transfer mechanisms under Section 72. The available lawful bases are:",
        ss["BodyText"]
    ))

    headers = ["Transfer Basis", "Section 72 Reference", "Applicability", "Recommended"]
    rows = [
        ["Adequate legal protection in recipient country", "S72(1)(a)",
         "US lacks adequacy finding", Paragraph("NO", ss["RiskHigh"])],
        ["Binding corporate rules / contractual safeguards", "S72(1)(b)",
         "Anthropic DPA with SCCs satisfies this", Paragraph("YES", ss["RiskLow"])],
        ["Data subject consent", "S72(1)(c)",
         "Impractical at scale for policy data", Paragraph("FALLBACK", ss["RiskMed"])],
        ["Necessary for contract performance", "S72(1)(d)",
         "Arguable for policy administration", Paragraph("SECONDARY", ss["RiskMed"])],
    ]
    t = make_table(headers, rows, [42 * mm, 28 * mm, None, 24 * mm], ss)
    elements.append(t)
    elements.append(Spacer(1, 8))

    elements.append(Paragraph(
        "<b>Primary mechanism:</b> The Anthropic DPA with Standard Contractual Clauses provides the contractual "
        "safeguards required under Section 72(1)(b). This should be supplemented by the PII Gateway architecture "
        "(Section 6) to minimise the volume of personal information transferred.",
        ss["BodyText"]
    ))

    elements.append(Paragraph(
        "<b>Special personal information (Section 26-33):</b> Where health data (life/health insurance policies), "
        "biometric data, or children's data is involved, prior authorisation from the Information Regulator is "
        "required before cross-border transfer. This is non-negotiable and must be obtained before any such data "
        "is processed through Claude.",
        ss["BodyText"]
    ))

    # 4.2
    elements.append(Paragraph("4.2 Standard Contractual Clauses", ss["H2"]))
    elements.append(Paragraph(
        "Anthropic's DPA includes EU-style Standard Contractual Clauses. While these were designed for GDPR "
        "compliance, they provide a strong contractual framework that can satisfy POPIA Section 72(1)(b). "
        "However, the UMA should note:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "POPIA extends protection to juristic persons, which is not standard in EU SCCs. Legal counsel should "
        "review whether supplementary clauses are needed.",
        "The UMA must conduct a transfer impact assessment documenting the legal regime in the US and any "
        "supplementary measures (encryption, pseudonymisation) that mitigate risks.",
        "The assessment should be documented and retained for presentation to the Information Regulator if requested.",
    ], ss))

    # 4.3
    elements.append(Paragraph("4.3 AWS Bedrock Deployment Option", ss["H2"]))
    elements.append(Paragraph(
        "Claude is available through AWS Bedrock, which provides additional data residency controls:",
        ss["BodyText"]
    ))
    elements.extend(bullet_list([
        "AWS Bedrock allows deployment in specific regions (e.g., EU Frankfurt - eu-west-1) for closer data residency.",
        "Private Service Connect (PSC) can route requests securely without traversing the public internet.",
        "Data governance is managed jointly between Anthropic and AWS under Amazon's infrastructure controls.",
        "AWS provides its own DPA and compliance certifications (SOC 2, ISO 27001) that complement Anthropic's.",
        "While no AWS region currently exists in South Africa, the EU Frankfurt region provides a closer "
        "and potentially more acceptable jurisdiction than the US for regulatory purposes.",
    ], ss))
    elements.append(Paragraph(
        "<b>Recommendation:</b> For maximum data residency control, deploy Claude via AWS Bedrock in the EU "
        "Frankfurt region, combined with the PII Gateway architecture and ZDR agreement.",
        ss["BodyText"]
    ))
    elements.append(PageBreak())
    return elements


# ── Section 5: UMA Process Verticals ────────────────────────────────────────
def build_verticals(ss):
    elements = []
    elements.append(Paragraph("5. UMA Process Verticals: AI Use Cases &amp; PII Risk Assessment", ss["H1"]))
    elements.append(section_hr())

    verticals = [
        {
            "num": "5.1", "title": "Underwriting",
            "risk": "MEDIUM",
            "safe_uses": [
                "Policy wording analysis and comparison",
                "Risk appetite matching against guidelines",
                "Underwriting manual summarisation and Q&A",
                "Comparable risk research and benchmarking",
                "Rate calculation logic validation",
                "Referral reason analysis and trending",
            ],
            "pii_approach": [
                "Feed Claude policy structures, terms, and anonymised risk profiles only",
                "Strip all policyholder names, ID numbers, and contact details before transmission",
                "Use risk category codes rather than individual policy identifiers",
            ],
            "s71_note": "Claude may recommend underwriting decisions, but a qualified underwriter must make the "
                        "final acceptance/decline decision. Document the human review in the underwriting file.",
        },
        {
            "num": "5.2", "title": "Claims Management",
            "risk": "HIGH",
            "safe_uses": [
                "Claims documentation completeness review",
                "Coverage analysis against policy wording",
                "Reserve estimation support and benchmarking",
                "Fraud pattern identification and flagging",
                "Claims correspondence drafting",
                "Subrogation opportunity identification",
            ],
            "pii_approach": [
                "Use claim reference numbers only; anonymise all claimant details",
                "Strip ID numbers, medical information, and banking details",
                "For fraud analysis, use aggregate pattern data rather than individual claim details",
            ],
            "s71_note": "Claims decisions (especially repudiations) that affect the policyholder must have "
                        "documented human oversight. AI-assisted decisions must be reviewable under Section 71.",
        },
        {
            "num": "5.3", "title": "Policy Administration",
            "risk": "MEDIUM",
            "safe_uses": [
                "Policy template generation and endorsement drafting",
                "Renewal analysis and recommendations",
                "Bulk communications drafting (renewal notices, endorsement letters)",
                "Data quality checks and validation rules",
                "System migration mapping assistance",
            ],
            "pii_approach": [
                "Use a middleware PII gateway that strips/pseudonymises data before reaching Claude",
                "Re-insert real data into outputs on the return path",
                "Templates can be generated without any PII by using placeholder tokens",
            ],
            "s71_note": "Policy administration tasks are generally operational and do not trigger Section 71, "
                        "provided no automated decisions are made about policy terms or pricing for individual clients.",
        },
        {
            "num": "5.4", "title": "Compliance &amp; Reporting",
            "risk": "LOW",
            "safe_uses": [
                "FAIS/FSCA regulatory reporting assistance",
                "TCF analysis and monitoring",
                "FICA checklist validation logic",
                "Policy wording compliance checks against regulations",
                "Internal audit report drafting",
                "Regulatory change impact assessment",
            ],
            "pii_approach": [
                "Aggregate and anonymise data for compliance reporting",
                "Claude works with statistical summaries, regulatory texts, and policy wording, not individual records",
                "Compliance frameworks and checklists contain no PII by nature",
            ],
            "s71_note": "Low Section 71 risk. Compliance analysis is advisory and does not directly affect data subjects.",
        },
        {
            "num": "5.5", "title": "Client Onboarding (FICA/KYC)",
            "risk": "HIGH",
            "safe_uses": [
                "Document checklist generation based on client type",
                "FICA requirements guidance and workflow automation",
                "Onboarding process optimisation",
                "Sanction screening logic development",
            ],
            "pii_approach": [
                "Do NOT send raw ID documents, bank statements, or source-of-funds documentation to Claude",
                "Process identity verification locally using dedicated FICA/KYC systems",
                "Claude assists with workflow logic and document requirements only, not with actual document processing",
            ],
            "s71_note": "Onboarding decisions (client acceptance/decline) must not be automated. Any AI-assisted "
                        "risk scoring must have documented human review.",
        },
        {
            "num": "5.6", "title": "Broker / Intermediary Management",
            "risk": "LOW",
            "safe_uses": [
                "Commission calculation logic and reconciliation",
                "Performance reporting and analytics",
                "Broker communication drafting",
                "Training material creation",
                "SLA monitoring and reporting",
            ],
            "pii_approach": [
                "Broker data is less sensitive but still protected under POPIA (juristic persons)",
                "Use broker codes rather than names where possible",
                "Commission data should be aggregated for analysis",
            ],
            "s71_note": "Low Section 71 risk. Broker management decisions typically do not require Section 71 protections.",
        },
    ]

    for v in verticals:
        risk_colour = RED_RISK if v["risk"] == "HIGH" else (AMBER if v["risk"] == "MEDIUM" else GREEN_OK)
        risk_style = "RiskHigh" if v["risk"] == "HIGH" else ("RiskMed" if v["risk"] == "MEDIUM" else "RiskLow")

        elements.append(Paragraph(f'{v["num"]} {v["title"]}', ss["H2"]))

        # Risk badge
        badge = Table(
            [[Paragraph(f'PII Risk: {v["risk"]}', ss[risk_style])]],
            colWidths=[35 * mm],
        )
        badge.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, risk_colour),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]))
        elements.append(badge)
        elements.append(Spacer(1, 4))

        elements.append(Paragraph("<b>Safe AI Use Cases:</b>", ss["BodyText"]))
        elements.extend(bullet_list(v["safe_uses"], ss))
        elements.append(Paragraph("<b>PII Handling Approach:</b>", ss["BodyText"]))
        elements.extend(bullet_list(v["pii_approach"], ss))
        elements.append(Paragraph(f'<b>Section 71 Compliance Note:</b> {v["s71_note"]}', ss["BodyText"]))
        elements.append(Spacer(1, 6))

    elements.append(PageBreak())
    return elements


# ── Section 6: PII Gateway Architecture ─────────────────────────────────────
def build_pii_gateway(ss):
    elements = []
    elements.append(Paragraph("6. PII Gateway Architecture", ss["H1"]))
    elements.append(section_hr())

    elements.append(Paragraph(
        "The PII Gateway is the central technical safeguard enabling POPIA-compliant use of Claude AI. It acts as "
        "a middleware layer between the UMA's internal systems and the Claude API, ensuring that personal information "
        "is anonymised before leaving the organisation's network perimeter.",
        ss["BodyText"]
    ))

    elements.append(Paragraph("6.1 Architecture Overview", ss["H2"]))

    # ASCII-style flow diagram as a table
    flow_data = [
        [Paragraph("<b>UMA Internal Systems</b><br/>(Policy Admin, Claims, Underwriting)", ss["TableCell"])],
        [Paragraph("<font color='#C8A951'>&#x25BC;</font>", ParagraphStyle("arr", fontSize=14, alignment=TA_CENTER, textColor=ACCENT))],
        [Paragraph(
            "<b>PII GATEWAY (On-Premise / Private Cloud)</b><br/>"
            "- Strips/pseudonymises all personal identifiers<br/>"
            "- Maps real IDs to secure tokens (token vault)<br/>"
            "- Logs all requests for audit trail (POPIA S14)<br/>"
            "- Enforces data minimality rules (POPIA S10)<br/>"
            "- Classifies data sensitivity level",
            ss["TableCell"]
        )],
        [Paragraph("<font color='#C8A951'>&#x25BC;</font> <i>Anonymised data only</i>", ParagraphStyle("arr2", fontSize=10, alignment=TA_CENTER, textColor=ACCENT))],
        [Paragraph(
            "<b>CLAUDE API (Commercial Tier)</b><br/>"
            "- DPA + SCCs in place<br/>"
            "- 7-day retention / ZDR<br/>"
            "- No model training on data",
            ss["TableCell"]
        )],
        [Paragraph("<font color='#C8A951'>&#x25BC;</font> <i>AI response</i>", ParagraphStyle("arr3", fontSize=10, alignment=TA_CENTER, textColor=ACCENT))],
        [Paragraph(
            "<b>PII GATEWAY (Return Path)</b><br/>"
            "- Re-inserts real identifiers from token vault<br/>"
            "- Human review checkpoint (Section 71)<br/>"
            "- Logs response for audit",
            ss["TableCell"]
        )],
        [Paragraph("<font color='#C8A951'>&#x25BC;</font>", ParagraphStyle("arr4", fontSize=14, alignment=TA_CENTER, textColor=ACCENT))],
        [Paragraph("<b>Business User / Output System</b>", ss["TableCell"])],
    ]

    flow_table = Table(flow_data, colWidths=[WIDTH - 70 * mm])
    flow_style = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]
    # Colour the key boxes
    for i in [0, 2, 4, 6, 8]:
        bg = NAVY if i in [2, 6] else (DARK_BLUE if i == 4 else LIGHT_BG)
        tc = white if i in [2, 4, 6] else DARK_GRAY
        flow_style.append(("BACKGROUND", (0, i), (0, i), bg))
        flow_style.append(("TEXTCOLOR", (0, i), (0, i), tc))
        if i in [2, 4, 6]:
            flow_style.append(("FONTNAME", (0, i), (0, i), "Helvetica"))
        flow_style.append(("BOX", (0, i), (0, i), 1, BORDER))

    flow_table.setStyle(TableStyle(flow_style))
    elements.append(flow_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("6.2 Anonymisation Techniques", ss["H2"]))
    headers = ["Data Element", "Technique", "Example"]
    rows = [
        ["Names", "Token replacement", "John Smith -> [TOKEN_001]"],
        ["ID Numbers", "Complete removal", "8501015800088 -> [REDACTED]"],
        ["Policy Numbers", "Pseudonymisation", "POL-2024-001 -> REF-A7X9"],
        ["Addresses", "Generalisation", "123 Main St, Sandton -> [AREA: Gauteng Urban]"],
        ["Phone Numbers", "Removal", "+27 82 123 4567 -> [REDACTED]"],
        ["Email Addresses", "Removal", "john@email.com -> [REDACTED]"],
        ["Bank Details", "Never transmitted", "Not sent to Claude under any circumstances"],
        ["Medical Information", "Category only", "Diabetes Type 2 -> [CHRONIC_CONDITION_CAT_3]"],
    ]
    t = make_table(headers, rows, [32 * mm, 32 * mm, None], ss)
    elements.append(t)
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("6.3 Technical Requirements", ss["H2"]))
    elements.extend(bullet_list([
        "<b>Deployment:</b> On-premise or private cloud within South African borders (no cross-border transfer of raw PII)",
        "<b>Token vault:</b> AES-256 encrypted database mapping tokens to real identifiers, with access controls",
        "<b>Audit logging:</b> Every request/response logged with timestamp, user ID, data classification level, and purpose",
        "<b>Data classification engine:</b> Automated detection and classification of PII elements before transmission",
        "<b>Rate limiting:</b> Prevent bulk data extraction through the gateway",
        "<b>Access control:</b> Role-based access with multi-factor authentication",
        "<b>Retention:</b> Gateway logs retained per POPIA requirements; token mappings purged when no longer needed",
    ], ss))

    elements.append(PageBreak())
    return elements


# ── Section 7: Compliance Checklist ─────────────────────────────────────────
def build_checklist(ss):
    elements = []
    elements.append(Paragraph("7. Compliance Checklist", ss["H1"]))
    elements.append(section_hr())

    elements.append(Paragraph(
        "The following checklist must be completed before deploying Claude AI in any UMA operational vertical:",
        ss["BodyText"]
    ))

    checklist = [
        ("Contractual", [
            ("Use Commercial/API tier only (never consumer Claude for business PII)", "Critical"),
            ("Sign/confirm Anthropic DPA with Standard Contractual Clauses", "Critical"),
            ("Negotiate Zero Data Retention (ZDR) agreement", "Recommended"),
            ("Legal review of DPA for POPIA Section 72 adequacy", "Critical"),
            ("Document the lawful basis for processing under Section 11", "Critical"),
        ]),
        ("Organisational", [
            ("Appoint Information Officer registered with Information Regulator", "Critical"),
            ("Conduct POPIA Impact Assessment for AI deployment", "Critical"),
            ("Update Privacy Policy to disclose AI tool usage", "Critical"),
            ("Establish AI Usage Policy for staff (acceptable use, prohibited data)", "Critical"),
            ("Train staff on POPIA-compliant AI usage", "Important"),
            ("Designate AI compliance champion within the organisation", "Recommended"),
        ]),
        ("Technical", [
            ("Build and deploy PII Gateway middleware", "Critical"),
            ("Implement data classification engine", "Critical"),
            ("Establish audit trail logging for all Claude API interactions", "Critical"),
            ("Configure role-based access controls for Claude access", "Important"),
            ("Implement automated PII detection and stripping", "Critical"),
            ("Set up monitoring and alerting for data leakage", "Important"),
        ]),
        ("Regulatory", [
            ("Obtain Information Regulator authorisation for special personal information transfers", "Critical (if applicable)"),
            ("Document cross-border transfer impact assessment", "Critical"),
            ("Align AI usage with FSCA TCF principles", "Important"),
            ("Prepare for FSCA AI governance requirements (2025-2028 plan)", "Recommended"),
            ("Maintain records of processing activities (POPIA Section 14)", "Critical"),
        ]),
        ("Operational", [
            ("Ensure human-in-the-loop for all policyholder-affecting decisions (Section 71)", "Critical"),
            ("Disclose AI assistance to policyholders where decisions are affected", "Important"),
            ("Establish incident response plan for AI-related data breaches", "Important"),
            ("Schedule regular POPIA compliance audits of AI usage", "Recommended"),
            ("Review and update framework annually or when regulations change", "Important"),
        ]),
    ]

    for category, items in checklist:
        elements.append(Paragraph(f"<b>{category} Controls</b>", ss["H3"]))
        headers = ["#", "Requirement", "Priority", "Status"]
        rows = []
        for idx, (req, priority) in enumerate(items, 1):
            p_style = ss["RiskHigh"] if "Critical" in priority else (ss["RiskMed"] if priority == "Important" else ss["RiskLow"])
            rows.append([
                str(idx),
                req,
                Paragraph(priority, p_style),
                Paragraph("<font color='#6B7280'>[ ]</font>", ss["TableCell"]),
            ])
        t = make_table(headers, rows, [8 * mm, None, 30 * mm, 14 * mm], ss)
        elements.append(t)
        elements.append(Spacer(1, 6))

    elements.append(PageBreak())
    return elements


# ── Section 8: Risk Register ────────────────────────────────────────────────
def build_risk_register(ss):
    elements = []
    elements.append(Paragraph("8. Risk Register", ss["H1"]))
    elements.append(section_hr())

    elements.append(Paragraph(
        "The following risk register identifies key risks associated with AI adoption and the corresponding "
        "mitigation strategies:",
        ss["BodyText"]
    ))

    headers = ["ID", "Risk Description", "Likelihood", "Impact", "Rating", "Mitigation"]
    risks = [
        ["R01", "PII transmitted to Claude without anonymisation",
         "Medium", "Critical",
         Paragraph("<b>HIGH</b>", ss["RiskHigh"]),
         "PII Gateway with automated detection; staff training; audit logging"],
        ["R02", "Cross-border transfer without adequate safeguards",
         "Low", "Critical",
         Paragraph("<b>HIGH</b>", ss["RiskHigh"]),
         "DPA with SCCs; legal review; transfer impact assessment"],
        ["R03", "Automated decision-making without human oversight (S71 breach)",
         "Medium", "High",
         Paragraph("<b>HIGH</b>", ss["RiskHigh"]),
         "Mandatory human review checkpoint; decision audit trail; staff training"],
        ["R04", "Staff using consumer Claude for business data",
         "High", "High",
         Paragraph("<b>HIGH</b>", ss["RiskHigh"]),
         "AI Usage Policy; technical controls blocking consumer AI; monitoring"],
        ["R05", "Information Regulator enforcement action",
         "Low", "Critical",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "Proactive compliance; documented framework; registered Information Officer"],
        ["R06", "Data breach at Anthropic exposing client data",
         "Low", "High",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "ZDR agreement; PII Gateway minimisation; incident response plan"],
        ["R07", "AI-generated output contains inaccurate information affecting policyholder",
         "Medium", "Medium",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "Human review of all outputs; validation against source systems; disclaimers"],
        ["R08", "Regulatory change (AI Act) requiring additional compliance",
         "High", "Medium",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "Monitor regulatory developments; annual framework review; flexible architecture"],
        ["R09", "TCF principle breach through biased AI recommendations",
         "Low", "High",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "Regular bias testing; outcome monitoring; diverse training scenarios"],
        ["R10", "Excessive data processing beyond stated purpose (S13 breach)",
         "Medium", "Medium",
         Paragraph("<b>MEDIUM</b>", ss["RiskMed"]),
         "Purpose limitation rules in PII Gateway; data minimality checks; audit"],
    ]

    t = make_table(headers, risks, [10 * mm, None, 18 * mm, 16 * mm, 16 * mm, 45 * mm], ss)
    elements.append(t)
    elements.append(PageBreak())
    return elements


# ── Section 9: Implementation Roadmap ───────────────────────────────────────
def build_roadmap(ss):
    elements = []
    elements.append(Paragraph("9. Implementation Roadmap", ss["H1"]))
    elements.append(section_hr())

    elements.append(Paragraph(
        "A phased approach is recommended, moving from low-risk to higher-risk use cases:",
        ss["BodyText"]
    ))

    phases = [
        {
            "phase": "Phase 1: Foundation (Months 1-2)",
            "colour": GREEN_OK,
            "items": [
                "Appoint Information Officer and register with Information Regulator",
                "Execute Anthropic Commercial Terms and confirm DPA",
                "Negotiate Zero Data Retention agreement",
                "Conduct legal review of DPA against POPIA Section 72 requirements",
                "Draft and approve internal AI Usage Policy",
                "Deploy Claude Code for development team (lowest PII risk)",
                "Begin PII Gateway design and development",
            ],
        },
        {
            "phase": "Phase 2: Low-Risk Verticals (Months 3-4)",
            "colour": ACCENT,
            "items": [
                "Deploy PII Gateway (v1) with basic anonymisation",
                "Roll out Claude for Compliance & Reporting vertical",
                "Roll out Claude for Broker Management vertical",
                "Conduct POPIA Impact Assessment for Phase 2 use cases",
                "Staff training on POPIA-compliant AI usage",
                "Establish audit logging and monitoring",
                "Conduct first compliance audit of AI usage",
            ],
        },
        {
            "phase": "Phase 3: Medium-Risk Verticals (Months 5-7)",
            "colour": AMBER,
            "items": [
                "Enhance PII Gateway with automated data classification",
                "Roll out Claude for Underwriting (anonymised risk profiles only)",
                "Roll out Claude for Policy Administration (via PII Gateway)",
                "Implement human review checkpoints for underwriting recommendations",
                "Update privacy notices to disclose AI assistance",
                "Conduct second compliance audit",
            ],
        },
        {
            "phase": "Phase 4: High-Risk Verticals (Months 8-10)",
            "colour": RED_RISK,
            "items": [
                "Roll out Claude for Claims Management (strict anonymisation via PII Gateway)",
                "Deploy Claude for Client Onboarding workflow support (no raw documents)",
                "If applicable: obtain Information Regulator authorisation for special personal information",
                "Implement comprehensive bias and fairness testing for AI outputs",
                "Full TCF compliance assessment of all AI-assisted processes",
                "Establish ongoing monitoring and annual review cycle",
            ],
        },
        {
            "phase": "Phase 5: Optimisation &amp; Scale (Months 11-12+)",
            "colour": DARK_BLUE,
            "items": [
                "Evaluate AWS Bedrock deployment for enhanced data residency",
                "Optimise PII Gateway performance and accuracy",
                "Expand AI use cases within each vertical based on lessons learned",
                "Prepare for anticipated FSCA AI governance requirements",
                "Prepare for anticipated National AI Policy Framework requirements",
                "Annual comprehensive compliance review",
            ],
        },
    ]

    for p in phases:
        # Phase header
        ph_data = [[Paragraph(f'<b>{p["phase"]}</b>',
                               ParagraphStyle("ph", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=white))]]
        ph_t = Table(ph_data, colWidths=[WIDTH - 55 * mm])
        ph_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), p["colour"]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(ph_t)
        elements.extend(bullet_list(p["items"], ss))
        elements.append(Spacer(1, 8))

    elements.append(PageBreak())
    return elements


# ── Section 10: Appendix A ──────────────────────────────────────────────────
def build_appendix_a(ss):
    elements = []
    elements.append(Paragraph("10. Appendix A: Key POPIA Sections Reference", ss["H1"]))
    elements.append(section_hr())

    headers = ["Section", "Title", "Relevance to AI Adoption"]
    rows = [
        ["S4", "Conditions for lawful processing", "AI processing must comply with all eight conditions"],
        ["S9", "Accountability", "UMA remains accountable for AI processing outcomes"],
        ["S10", "Processing limitation (Minimality)", "Only necessary data may be fed to AI systems"],
        ["S11", "Lawfulness of processing", "Valid legal basis required (consent, contract, legitimate interest)"],
        ["S12", "Consent", "Must be voluntary, specific, and informed if used as legal basis"],
        ["S13", "Purpose specification", "Data collected for specific purpose; AI use must align"],
        ["S14", "Records of processing", "All AI interactions must be logged and auditable"],
        ["S18", "Quality of information", "AI inputs must be accurate and complete"],
        ["S19", "Security safeguards", "Technical measures (encryption, access control, PII Gateway)"],
        ["S20-21", "Operator provisions", "DPA required with Anthropic as data operator"],
        ["S22", "Notification", "Data subjects must be informed of AI processing"],
        ["S26-33", "Special personal information", "Health, biometric, children's data: additional restrictions"],
        ["S71", "Automated decision-making", "No solely automated decisions with legal effect without safeguards"],
        ["S72", "Cross-border transfers", "Adequate protections required for US-based processing"],
        ["S99-106", "Offences and penalties", "Up to ZAR 10 million fine; up to 10 years imprisonment"],
    ]
    t = make_table(headers, rows, [15 * mm, 45 * mm, None], ss)
    elements.append(t)
    elements.append(PageBreak())
    return elements


# ── Section 11: Appendix B ──────────────────────────────────────────────────
def build_appendix_b(ss):
    elements = []
    elements.append(Paragraph("11. Appendix B: Glossary", ss["H1"]))
    elements.append(section_hr())

    terms = [
        ("API", "Application Programming Interface; the programmatic interface for accessing Claude"),
        ("DPA", "Data Processing Addendum; contractual agreement governing data processing"),
        ("FAIS", "Financial Advisory and Intermediary Services Act 37 of 2002"),
        ("FICA", "Financial Intelligence Centre Act 38 of 2001"),
        ("FSP", "Financial Service Provider; licensed under FAIS"),
        ("FSCA", "Financial Sector Conduct Authority"),
        ("KYC", "Know Your Customer; identity verification requirements"),
        ("LLM", "Large Language Model; the AI technology underlying Claude"),
        ("PA", "Prudential Authority; division of the South African Reserve Bank"),
        ("PII", "Personally Identifiable Information"),
        ("POPIA", "Protection of Personal Information Act 4 of 2013"),
        ("SCCs", "Standard Contractual Clauses; cross-border data transfer mechanism"),
        ("TCF", "Treating Customers Fairly; FSCA conduct standard"),
        ("UMA", "Underwriting Management Agency; delegated authority insurer"),
        ("ZDR", "Zero Data Retention; Anthropic agreement for no data storage"),
    ]

    headers = ["Term", "Definition"]
    rows = [[t, d] for t, d in terms]
    t = make_table(headers, rows, [22 * mm, None], ss)
    elements.append(t)

    elements.append(Spacer(1, 20))
    elements.append(section_hr())
    elements.append(Paragraph(
        "<i>This document is intended as a compliance framework and does not constitute legal advice. "
        "The UMA should engage qualified legal counsel specialising in POPIA and financial services regulation "
        "to review and validate the compliance measures prior to implementation.</i>",
        ss["SmallText"]
    ))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        f"<i>Document generated: {datetime.now().strftime('%d %B %Y at %H:%M')}</i>",
        ss["SmallText"]
    ))
    return elements


# ── Main ────────────────────────────────────────────────────────────────────
def build_pdf():
    ss = build_styles()

    doc = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4,
        leftMargin=25 * mm,
        rightMargin=25 * mm,
        topMargin=22 * mm,
        bottomMargin=22 * mm,
        title="POPIA AI Compliance Framework",
        author="S Lamprecht",
        subject="POPIA Compliance Framework for AI Adoption in South African UMAs",
    )

    story = []
    story.extend(build_cover(ss))
    story.extend(build_doc_control(ss))
    story.extend(build_toc(ss))
    story.extend(build_executive_summary(ss))
    story.extend(build_regulatory_landscape(ss))
    story.extend(build_anthropic_data(ss))
    story.extend(build_cross_border(ss))
    story.extend(build_verticals(ss))
    story.extend(build_pii_gateway(ss))
    story.extend(build_checklist(ss))
    story.extend(build_risk_register(ss))
    story.extend(build_roadmap(ss))
    story.extend(build_appendix_a(ss))
    story.extend(build_appendix_b(ss))

    doc.build(story, canvasmaker=FooterCanvas)
    print(f"PDF generated: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_pdf()
