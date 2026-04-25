const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat,
} = require("docx");

// ── Load sensitivity data ──
const data = JSON.parse(fs.readFileSync("sensitivity_results.json", "utf8"));
const ranking = data.ranking;
const baseLosses = data.base_losses;
const profile = data.reference_profile;

// ── Helpers ──
const fmt = (n) => "R " + Math.round(n).toLocaleString("en-ZA");
const pct = (n) => (n >= 0 ? "+" : "") + n.toFixed(2) + "%";
const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

// Page: A4 with 1-inch margins
const PAGE_W = 11906;
const MARGIN = 1440;
const CONTENT_W = PAGE_W - 2 * MARGIN; // 9026

function headerCell(text, width) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: "1B3A5C", type: ShadingType.CLEAR },
    margins: cellMargins,
    verticalAlign: "center",
    children: [new Paragraph({ alignment: AlignmentType.LEFT, children: [
      new TextRun({ text, bold: true, font: "Arial", size: 18, color: "FFFFFF" }),
    ]})],
  });
}

function dataCell(text, width, opts = {}) {
  const shading = opts.fill ? { fill: opts.fill, type: ShadingType.CLEAR } : undefined;
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading,
    margins: cellMargins,
    children: [new Paragraph({ alignment: opts.align || AlignmentType.LEFT, children: [
      new TextRun({ text: String(text), font: "Arial", size: 18, bold: !!opts.bold, color: opts.color || "333333" }),
    ]})],
  });
}

function sensitivityColor(s) {
  if (s === "High") return "FFE0E0";
  if (s === "Medium") return "FFF3D0";
  return "E8F5E9";
}

function sensitivityTextColor(s) {
  if (s === "High") return "B71C1C";
  if (s === "Medium") return "E65100";
  return "2E7D32";
}

// ── Build document sections ──
const children = [];

// Title
children.push(new Paragraph({ spacing: { after: 100 }, children: [
  new TextRun({ text: "Phishield FAIR Model", font: "Arial", size: 36, bold: true, color: "1B3A5C" }),
]}));
children.push(new Paragraph({ spacing: { after: 80 }, children: [
  new TextRun({ text: "Sensitivity Analysis Report", font: "Arial", size: 28, color: "1B3A5C" }),
]}));
children.push(new Paragraph({ spacing: { after: 40 }, children: [
  new TextRun({ text: "Parameter Impact on Total Estimated Annual Loss (ZAR)", font: "Arial", size: 20, color: "666666", italics: true }),
]}));
children.push(new Paragraph({ spacing: { after: 200 }, border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "1B3A5C", space: 1 } }, children: [
  new TextRun({ text: `Version 1.0  |  April 2026  |  SML Consulting`, font: "Arial", size: 18, color: "999999" }),
]}));

// Executive Summary
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "1. Executive Summary", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

children.push(new Paragraph({ spacing: { after: 120 }, children: [
  new TextRun({ text: "This report analyses the sensitivity of each editable parameter in the Phishield FAIR Model to determine which variables have the greatest impact on the total estimated annual cyber loss in ZAR. Each parameter was perturbed by ", font: "Arial", size: 20 }),
  new TextRun({ text: "+/- 25%", font: "Arial", size: 20, bold: true }),
  new TextRun({ text: " from its default value while holding all other parameters constant (one-at-a-time analysis).", font: "Arial", size: 20 }),
]}));

children.push(new Paragraph({ spacing: { after: 120 }, children: [
  new TextRun({ text: "Reference profile: ", font: "Arial", size: 20, bold: true }),
  new TextRun({ text: `R100M annual revenue, "${profile.industry}" industry, moderate security posture (score ${profile.overall_score}/1000), RSI ${profile.rsi_score}, no WAF, no CDN, single ASN.`, font: "Arial", size: 20 }),
]}));

// Base losses summary
const scenarioBreakdown = [
  ["Data Breach", baseLosses.data_breach, (baseLosses.data_breach / baseLosses.total * 100).toFixed(1)],
  ["Ransomware", baseLosses.ransomware, (baseLosses.ransomware / baseLosses.total * 100).toFixed(1)],
  ["Business Interruption", baseLosses.business_interruption, (baseLosses.business_interruption / baseLosses.total * 100).toFixed(1)],
  ["Total", baseLosses.total, "100.0"],
];

children.push(new Paragraph({ spacing: { before: 160, after: 80 }, children: [
  new TextRun({ text: "Baseline Annual Loss Breakdown", font: "Arial", size: 22, bold: true, color: "1B3A5C" }),
]}));

const colWidths1 = [3200, 3000, 2826];
children.push(new Table({
  width: { size: CONTENT_W, type: WidthType.DXA },
  columnWidths: colWidths1,
  rows: [
    new TableRow({ children: [
      headerCell("Scenario", colWidths1[0]),
      headerCell("Estimated Loss (ZAR)", colWidths1[1]),
      headerCell("% of Total", colWidths1[2]),
    ]}),
    ...scenarioBreakdown.map((r, i) => new TableRow({ children: [
      dataCell(r[0], colWidths1[0], { bold: r[0] === "Total", fill: r[0] === "Total" ? "E3EDF7" : (i % 2 === 0 ? "F8F9FA" : "FFFFFF") }),
      dataCell(fmt(r[1]), colWidths1[1], { align: AlignmentType.RIGHT, bold: r[0] === "Total", fill: r[0] === "Total" ? "E3EDF7" : (i % 2 === 0 ? "F8F9FA" : "FFFFFF") }),
      dataCell(r[2] + "%", colWidths1[2], { align: AlignmentType.CENTER, bold: r[0] === "Total", fill: r[0] === "Total" ? "E3EDF7" : (i % 2 === 0 ? "F8F9FA" : "FFFFFF") }),
    ]})),
  ],
}));

children.push(new Paragraph({ spacing: { after: 120 }, children: [
  new TextRun({ text: `At the reference profile, the ransomware scenario dominates at ${(baseLosses.ransomware / baseLosses.total * 100).toFixed(0)}% of total loss, followed by data breach (${(baseLosses.data_breach / baseLosses.total * 100).toFixed(0)}%) and business interruption (${(baseLosses.business_interruption / baseLosses.total * 100).toFixed(0)}%). This means parameters feeding the ransomware scenario naturally have greater leverage.`, font: "Arial", size: 20, color: "555555", italics: true }),
]}));

// Key Findings
children.push(new Paragraph({ spacing: { before: 200, after: 120 }, children: [
  new TextRun({ text: "Key Findings", font: "Arial", size: 22, bold: true, color: "1B3A5C" }),
]}));

const highParams = ranking.filter(r => r.sensitivity === "High");
const medParams = ranking.filter(r => r.sensitivity === "Medium");
const lowParams = ranking.filter(r => r.sensitivity === "Low");

children.push(new Paragraph({ spacing: { after: 60 }, children: [
  new TextRun({ text: `${highParams.length} HIGH-impact parameter(s)`, font: "Arial", size: 20, bold: true, color: "B71C1C" }),
  new TextRun({ text: ` (>= 15% swing): `, font: "Arial", size: 20 }),
  new TextRun({ text: highParams.map(p => p.parameter.replace(/_/g, " ")).join(", "), font: "Arial", size: 20, italics: true }),
]}));
children.push(new Paragraph({ spacing: { after: 60 }, children: [
  new TextRun({ text: `${medParams.length} MEDIUM-impact parameter(s)`, font: "Arial", size: 20, bold: true, color: "E65100" }),
  new TextRun({ text: ` (5-15% swing): `, font: "Arial", size: 20 }),
  new TextRun({ text: medParams.map(p => p.parameter.replace(/_/g, " ")).join(", "), font: "Arial", size: 20, italics: true }),
]}));
children.push(new Paragraph({ spacing: { after: 160 }, children: [
  new TextRun({ text: `${lowParams.length} LOW-impact parameter(s)`, font: "Arial", size: 20, bold: true, color: "2E7D32" }),
  new TextRun({ text: ` (< 5% swing): `, font: "Arial", size: 20 }),
  new TextRun({ text: "cost per record, IR cost, POPIA %, BI parameters, and remaining caps.", font: "Arial", size: 20, italics: true }),
]}));

// Page break
children.push(new Paragraph({ children: [new PageBreak()] }));

// Section 2: Complete Ranking Table
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "2. Complete Parameter Ranking (Tornado View)", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

children.push(new Paragraph({ spacing: { after: 120 }, children: [
  new TextRun({ text: "Parameters ranked by maximum absolute % change in total annual loss when perturbed by +/- 25%. The bar column shows relative magnitude (longest bar = highest impact).", font: "Arial", size: 20 }),
]}));

const colWidths2 = [400, 2800, 1000, 1200, 1200, 2426];
children.push(new Table({
  width: { size: CONTENT_W, type: WidthType.DXA },
  columnWidths: colWidths2,
  rows: [
    new TableRow({ children: [
      headerCell("#", colWidths2[0]),
      headerCell("Parameter", colWidths2[1]),
      headerCell("Scenario", colWidths2[2]),
      headerCell("Impact %", colWidths2[3]),
      headerCell("Rating", colWidths2[4]),
      headerCell("Relative Impact", colWidths2[5]),
    ]}),
    ...ranking.map((r, i) => {
      const maxPct = ranking[0].max_abs_pct;
      const barLen = Math.round((r.max_abs_pct / maxPct) * 20);
      const bar = "\u2588".repeat(barLen) + "\u2591".repeat(20 - barLen);
      const rowFill = i % 2 === 0 ? "F8F9FA" : "FFFFFF";
      return new TableRow({ children: [
        dataCell(r.rank, colWidths2[0], { align: AlignmentType.CENTER, fill: rowFill }),
        dataCell(r.parameter.replace(/_/g, " "), colWidths2[1], { bold: r.sensitivity === "High", fill: rowFill }),
        dataCell(r.scenario, colWidths2[2], { fill: rowFill }),
        dataCell(r.max_abs_pct.toFixed(1) + "%", colWidths2[3], { align: AlignmentType.RIGHT, bold: true, fill: rowFill, color: sensitivityTextColor(r.sensitivity) }),
        dataCell(r.sensitivity, colWidths2[4], { align: AlignmentType.CENTER, fill: sensitivityColor(r.sensitivity), color: sensitivityTextColor(r.sensitivity), bold: true }),
        dataCell(bar, colWidths2[5], { fill: rowFill, color: sensitivityTextColor(r.sensitivity) }),
      ]});
    }),
  ],
}));

// Page break
children.push(new Paragraph({ children: [new PageBreak()] }));

// Section 3: Detailed per-scenario analysis
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "3. Detailed Scenario Analysis", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

// Group detailed results by scenario
const scenarios = [
  { key: "Breach", title: "Scenario 1: Data Breach", baseLoss: baseLosses.data_breach,
    formula: "Loss = p_breach x (estimated_records x cost_per_record + regulatory_fine)",
    formulaDetail: "p_breach = min(1.0, ((100 - overall_score/10) / 100) x industry_multiplier x 0.3)\nestimated_records = max(100, revenue / records_divisor)\nregulatory_fine = revenue x popia_pct" },
  { key: "Ransomware", title: "Scenario 2: Ransomware", baseLoss: baseLosses.ransomware,
    formula: "Loss = rsi_score x (downtime_days x daily_revenue x revenue_loss_pct + ransom_estimate + ir_cost)",
    formulaDetail: "daily_revenue = annual_revenue / 365\nrsi_score = RSI from RansomwareIndex (0.0-1.0)" },
  { key: "BI", title: "Scenario 3: Business Interruption", baseLoss: baseLosses.business_interruption,
    formula: "Loss = p_interruption x (bi_days x daily_revenue x impact_factor)",
    formulaDetail: "p_interruption = min(p_cap, p_base + waf_p + cdn_p + asn_p)\nimpact_factor = min(impact_cap, impact_base + waf_i + cdn_i + asn_i)" },
  { key: "All", title: "Cross-cutting: Annual Revenue", baseLoss: baseLosses.total,
    formula: "Flows into all three scenarios via daily_revenue, estimated_records, and regulatory_fine",
    formulaDetail: "Affects: daily_revenue (Ransomware, BI), estimated_records (Breach), regulatory_fine (Breach)" },
];

for (const scenario of scenarios) {
  const params = ranking.filter(r => r.scenario === scenario.key);
  if (params.length === 0) continue;

  children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 80 }, children: [
    new TextRun({ text: scenario.title, font: "Arial", size: 24, bold: true, color: "1B3A5C" }),
  ]}));

  children.push(new Paragraph({ spacing: { after: 40 }, children: [
    new TextRun({ text: "Base loss: ", font: "Arial", size: 20, bold: true }),
    new TextRun({ text: `${fmt(scenario.baseLoss)} (${(scenario.baseLoss / baseLosses.total * 100).toFixed(1)}% of total)`, font: "Arial", size: 20 }),
  ]}));

  children.push(new Paragraph({ spacing: { after: 40 }, children: [
    new TextRun({ text: "Formula: ", font: "Arial", size: 18, bold: true, color: "555555" }),
    new TextRun({ text: scenario.formula, font: "Consolas", size: 17, color: "555555" }),
  ]}));

  children.push(new Paragraph({ spacing: { after: 100 }, children: [
    new TextRun({ text: "Where: ", font: "Arial", size: 18, bold: true, color: "555555" }),
    new TextRun({ text: scenario.formulaDetail, font: "Consolas", size: 16, color: "777777" }),
  ]}));

  // Per-param detail table
  const colWidths3 = [2200, 1200, 1600, 1200, 1200, 1626];
  children.push(new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: colWidths3,
    rows: [
      new TableRow({ children: [
        headerCell("Parameter", colWidths3[0]),
        headerCell("Default", colWidths3[1]),
        headerCell("Role in Formula", colWidths3[2]),
        headerCell("Impact %", colWidths3[3]),
        headerCell("Rating", colWidths3[4]),
        headerCell("Doc Section", colWidths3[5]),
      ]}),
      ...params.map((r, i) => {
        const defStr = typeof r.default_value === "number" && r.default_value >= 1000
          ? fmt(r.default_value) : String(r.default_value);
        const rowFill = i % 2 === 0 ? "F8F9FA" : "FFFFFF";
        // Derive short formula role
        let role = r.description.split(";")[0].substring(0, 40);
        return new TableRow({ children: [
          dataCell(r.parameter.replace(/_/g, " "), colWidths3[0], { bold: true, fill: rowFill }),
          dataCell(defStr, colWidths3[1], { align: AlignmentType.RIGHT, fill: rowFill }),
          dataCell(role, colWidths3[2], { fill: rowFill }),
          dataCell(r.max_abs_pct.toFixed(1) + "%", colWidths3[3], { align: AlignmentType.RIGHT, bold: true, fill: rowFill, color: sensitivityTextColor(r.sensitivity) }),
          dataCell(r.sensitivity, colWidths3[4], { align: AlignmentType.CENTER, fill: sensitivityColor(r.sensitivity), color: sensitivityTextColor(r.sensitivity), bold: true }),
          dataCell(r.section, colWidths3[5], { fill: rowFill }),
        ]});
      }),
    ],
  }));

  children.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
}

// Page break
children.push(new Paragraph({ children: [new PageBreak()] }));

// Section 4: SA Market Calibration Guidance
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "4. SA Market Calibration Guidance", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

children.push(new Paragraph({ spacing: { after: 100 }, children: [
  new TextRun({ text: "Based on the sensitivity analysis, focus calibration efforts on the highest-impact parameters first. Below are specific recommendations for tuning each parameter to better reflect SA market conditions.", font: "Arial", size: 20 }),
]}));

const guidance = [
  { param: "RSI Score (rsi_score)", impact: "17.1%", rating: "High",
    guidance: "This is the single largest needle-mover. The RSI feeds directly as a probability multiplier into the ransomware scenario. To calibrate for SA: review the RSI contributing factors (Section 3a of the parameters doc) and their weights. SA-specific considerations include higher prevalence of RDP exposure in the SME market, less mature patch management, and frequent load-shedding-driven UPS/network gaps. Consider increasing the base RSI from 0.05 to 0.08 for SA-based companies." },
  { param: "Annual Revenue", impact: "15.2%", rating: "High",
    guidance: "Revenue is the primary scaling factor across all scenarios. It drives estimated records (breach), daily revenue loss (ransomware and BI), and POPIA regulatory fines. This is an input, not a tuneable model parameter, but ensure that revenue is captured accurately in ZAR. The FX rate (R18.02/$) converts IBM USD data correctly. If SA companies tend to understate revenue in submissions, consider a validation step." },
  { param: "Overall Scanner Score", impact: "7.7%", rating: "Medium",
    guidance: "Drives p_breach via the formula. The conversion factor (score/10, then /100, then x multiplier x 0.3) compresses the range significantly. A score of 400 vs 600 produces only a moderate p_breach difference. Consider whether the 0.3 ceiling factor adequately reflects SA breach probability, given that SA has the 5th-highest breach frequency globally per IBM." },
  { param: "Downtime Days / Revenue Loss %", impact: "7.4% each", rating: "Medium",
    guidance: "Both have identical impact because they multiply together. The 22-day average is from global data. SA-specific factors that may increase this: slower incident response availability, fewer local DFIR firms, load-shedding complicating recovery. Consider 25-30 days for SA SMEs. The 50% revenue loss assumption may be conservative for companies without DR plans." },
  { param: "Industry Multiplier", impact: "6.3%", rating: "Medium",
    guidance: "The IBM SA data provides good industry differentiation. The \"Your Value\" column in the parameters doc lets you override. SA-specific adjustments: Public Sector (increase from 1.74 to ~1.82 due to SA government IT underinvestment), Agriculture (increase from 0.65 to ~0.80 given rising agri-tech adoption with poor security)." },
  { param: "Ransom Estimate", impact: "6.1%", rating: "Medium",
    guidance: "Tiered by revenue band. SA ransom demands are typically 30-50% lower than US equivalents in ZAR terms but recovery costs are similar. Consider adjusting the R50M-R200M tier from R2.5M down to R1.5-2M, and adjusting the >R500M tier from R50M down to R25-35M." },
  { param: "Records Divisor", impact: "5.5%", rating: "Medium",
    guidance: "Controls how many records are estimated per company. The default R50,000 divisor means a R100M company has ~2,000 records. SA companies may hold fewer records per rand of revenue than US counterparts (smaller customer bases). Consider increasing the divisor to R75,000-R100,000 for SA." },
  { param: "Cost Per Record", impact: "4.1%", rating: "Low",
    guidance: "IBM SA data already localised. The Your Value column allows per-industry overrides. Current R1,881 average is reasonable. Limited calibration benefit given the low sensitivity." },
  { param: "POPIA Fine %", impact: "2.2%", rating: "Low",
    guidance: "The 2% of turnover is conservative. POPIA allows up to R10M or imprisonment but actual enforcement has been minimal to date. This parameter has limited impact on total loss. No urgent calibration needed." },
  { param: "BI Parameters (all)", impact: "<1.6%", rating: "Low",
    guidance: "Business interruption contributes only 6.2% of total loss at baseline. All BI parameters combined move the needle minimally. However, for companies with high daily revenue and poor infrastructure redundancy, BI may matter more. The current defaults are reasonable for SA." },
];

const colWidths4 = [2200, 800, 800, 5226];
children.push(new Table({
  width: { size: CONTENT_W, type: WidthType.DXA },
  columnWidths: colWidths4,
  rows: [
    new TableRow({ children: [
      headerCell("Parameter", colWidths4[0]),
      headerCell("Impact", colWidths4[1]),
      headerCell("Rating", colWidths4[2]),
      headerCell("SA Market Calibration Notes", colWidths4[3]),
    ]}),
    ...guidance.map((g, i) => {
      const rowFill = i % 2 === 0 ? "F8F9FA" : "FFFFFF";
      return new TableRow({ children: [
        dataCell(g.param, colWidths4[0], { bold: true, fill: rowFill }),
        dataCell(g.impact, colWidths4[1], { align: AlignmentType.CENTER, fill: rowFill, bold: true }),
        dataCell(g.rating, colWidths4[2], { align: AlignmentType.CENTER, fill: sensitivityColor(g.rating), color: sensitivityTextColor(g.rating), bold: true }),
        dataCell(g.guidance, colWidths4[3], { fill: rowFill }),
      ]});
    }),
  ],
}));

// Page break
children.push(new Paragraph({ children: [new PageBreak()] }));

// Section 5: How Parameters Flow into the Rand Value
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "5. Parameter Flow Diagram (Text)", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

children.push(new Paragraph({ spacing: { after: 80 }, children: [
  new TextRun({ text: "The total estimated annual loss in ZAR is the sum of three independent scenario calculations. Below shows how each editable parameter feeds into the final number.", font: "Arial", size: 20 }),
]}));

const flowLines = [
  { text: "TOTAL ANNUAL LOSS (ZAR) = Breach Loss + Ransomware Loss + BI Loss", bold: true, size: 20 },
  { text: "", size: 12 },
  { text: "Scenario 1: DATA BREACH", bold: true, color: "B71C1C", size: 20 },
  { text: "  Breach Loss = p_breach x (estimated_records x cost_per_record + regulatory_fine)", size: 18 },
  { text: "    p_breach = ((100 - overall_score/10) / 100) x industry_multiplier x 0.3    [cap: 1.0]", size: 16, color: "555555" },
  { text: "    estimated_records = revenue / records_divisor                                 [floor: 100]", size: 16, color: "555555" },
  { text: "    regulatory_fine = revenue x popia_pct                                        [default: 2%]", size: 16, color: "555555" },
  { text: "", size: 12 },
  { text: "Scenario 2: RANSOMWARE", bold: true, color: "B71C1C", size: 20 },
  { text: "  Ransomware Loss = rsi_score x (downtime_days x daily_rev x revenue_loss_pct + ransom_est + ir_cost)", size: 18 },
  { text: "    rsi_score = from RansomwareIndex (contributing factors + industry mult + size mult)  [0.0-1.0]", size: 16, color: "555555" },
  { text: "    daily_rev = revenue / 365", size: 16, color: "555555" },
  { text: "    ransom_est & ir_cost = tiered by revenue band", size: 16, color: "555555" },
  { text: "", size: 12 },
  { text: "Scenario 3: BUSINESS INTERRUPTION", bold: true, color: "B71C1C", size: 20 },
  { text: "  BI Loss = p_interruption x (bi_days x daily_rev x impact_factor)", size: 18 },
  { text: "    p_interruption = min(p_cap, p_base + waf_p + cdn_p + asn_p)", size: 16, color: "555555" },
  { text: "    impact_factor = min(impact_cap, impact_base + waf_i + cdn_i + asn_i)", size: 16, color: "555555" },
];

for (const line of flowLines) {
  children.push(new Paragraph({ spacing: { after: 20 }, children: [
    new TextRun({ text: line.text, font: "Consolas", size: line.size || 18, bold: !!line.bold, color: line.color || "333333" }),
  ]}));
}

// Section 6: Methodology note
children.push(new Paragraph({ spacing: { before: 300, after: 120 }, children: [] }));
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 240, after: 120 }, children: [
  new TextRun({ text: "6. Methodology", font: "Arial", size: 28, bold: true, color: "1B3A5C" }),
]}));

children.push(new Paragraph({ spacing: { after: 80 }, children: [
  new TextRun({ text: "One-at-a-time (OAT) sensitivity analysis: each parameter is independently perturbed by +25% and -25% from its default value. All other parameters remain at their defaults. The maximum absolute percentage change in total annual loss is recorded as that parameter's sensitivity score.", font: "Arial", size: 20 }),
]}));
children.push(new Paragraph({ spacing: { after: 80 }, children: [
  new TextRun({ text: "Limitations: ", font: "Arial", size: 20, bold: true }),
  new TextRun({ text: "OAT analysis does not capture interaction effects between parameters. For example, simultaneously changing rsi_score and downtime_days would produce a compound effect not reflected in single-parameter perturbation. The analysis also uses a fixed reference profile; sensitivity rankings may shift for companies with very different revenue or risk profiles.", font: "Arial", size: 20 }),
]}));
children.push(new Paragraph({ spacing: { after: 80 }, children: [
  new TextRun({ text: "Note on Monte Carlo: ", font: "Arial", size: 20, bold: true }),
  new TextRun({ text: "The actual scanner uses 10,000-iteration Monte Carlo simulation with PERT distributions to produce confidence intervals. This sensitivity analysis examines the point-estimate formula to isolate individual parameter effects. The MC simulation amplifies the impact of probability parameters (p_breach, rsi_score, p_interruption) because they are sampled over wide ranges.", font: "Arial", size: 20 }),
]}));

children.push(new Paragraph({ spacing: { before: 200, after: 80 }, children: [
  new TextRun({ text: "Reference: ", font: "Arial", size: 18, color: "999999" }),
  new TextRun({ text: "Phishield_FAIR_Model_Parameters.docx v1.1 | scoring_analytics.py FinancialImpactCalculator._calculate_zar()", font: "Arial", size: 18, color: "999999", italics: true }),
]}));


// ── Assemble document ──
const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 20 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: "1B3A5C" },
        paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: "1B3A5C" },
        paragraph: { spacing: { before: 180, after: 100 }, outlineLevel: 1 } },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: PAGE_W, height: 16838 },
        margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN },
      },
    },
    headers: {
      default: new Header({ children: [new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [new TextRun({ text: "Phishield FAIR Model Sensitivity Analysis", font: "Arial", size: 16, color: "999999", italics: true })],
      })] }),
    },
    footers: {
      default: new Footer({ children: [new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [
          new TextRun({ text: "SML Consulting  |  Confidential  |  Page ", font: "Arial", size: 16, color: "999999" }),
          new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: "999999" }),
        ],
      })] }),
    },
    children,
  }],
});

Packer.toBuffer(doc).then(buffer => {
  const outPath = "Phishield_FAIR_Sensitivity_Analysis.docx";
  fs.writeFileSync(outPath, buffer);
  console.log(`Written: ${outPath} (${(buffer.length / 1024).toFixed(1)} KB)`);
});
