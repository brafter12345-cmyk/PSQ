const docx = require("docx");
const fs = require("fs");
const path = require("path");

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, AlignmentType, HeadingLevel, BorderStyle, ShadingType,
  PageBreak, TableLayoutType, VerticalAlign, convertInchesToTwip
} = docx;

// Load data
const data = JSON.parse(
  fs.readFileSync(path.join(__dirname, "sensitivity_results_v2.json"), "utf8")
);

const NAVY = "1B3A5C";
const WHITE = "FFFFFF";
const LIGHT_GRAY = "F2F4F7";
const MED_GRAY = "E0E4EA";

// Helper: create a text run
function txt(text, opts = {}) {
  return new TextRun({
    text,
    font: "Arial",
    size: opts.size || 20, // 10pt
    bold: opts.bold || false,
    italics: opts.italics || false,
    color: opts.color || "333333",
    ...opts,
  });
}

// Helper: paragraph
function para(runs, opts = {}) {
  if (typeof runs === "string") runs = [txt(runs, opts)];
  if (!Array.isArray(runs)) runs = [runs];
  return new Paragraph({
    children: runs,
    spacing: { after: opts.after !== undefined ? opts.after : 120 },
    alignment: opts.alignment || AlignmentType.LEFT,
    ...opts.paraOpts,
  });
}

// Helper: heading
function heading(text, level = HeadingLevel.HEADING_1) {
  return new Paragraph({
    children: [txt(text, { bold: true, color: NAVY, size: level === HeadingLevel.HEADING_1 ? 28 : level === HeadingLevel.HEADING_2 ? 24 : 20 })],
    heading: level,
    spacing: { before: 240, after: 120 },
  });
}

// Table cell helper
function cell(content, opts = {}) {
  const runs = typeof content === "string" ? [txt(content, {
    bold: opts.bold || false,
    color: opts.fontColor || "333333",
    size: opts.fontSize || 18,
  })] : content;

  return new TableCell({
    children: [new Paragraph({
      children: runs,
      alignment: opts.alignment || AlignmentType.LEFT,
      spacing: { after: 0 },
    })],
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    shading: opts.shading ? {
      type: ShadingType.CLEAR,
      color: "auto",
      fill: opts.shading,
    } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: {
      top: convertInchesToTwip(0.04),
      bottom: convertInchesToTwip(0.04),
      left: convertInchesToTwip(0.08),
      right: convertInchesToTwip(0.08),
    },
  });
}

// Header cell
function hCell(content, opts = {}) {
  return cell(content, {
    bold: true,
    fontColor: WHITE,
    shading: NAVY,
    alignment: opts.alignment || AlignmentType.CENTER,
    width: opts.width,
    fontSize: opts.fontSize || 18,
  });
}

// Create text bar
function makeBar(pct, maxPct) {
  const len = Math.round((pct / maxPct) * 20);
  return "\u2588".repeat(Math.max(1, len)) + "\u2591".repeat(20 - len);
}

// Build ranking table
const ranking = data.ranking;
const maxImpact = ranking[0].avg_max_impact;

function ratingLabel(s) {
  if (s === "High") return "High";
  if (s === "Medium") return "Medium";
  return "Low";
}

// Short param names for table
function shortName(p) {
  return p.replace(/ \(.*?\)/g, "").replace("SA ", "").replace("Graduated ", "");
}

const rankingRows = [
  new TableRow({
    children: [
      hCell("Rank", { width: 8 }),
      hCell("Parameter", { width: 30, alignment: AlignmentType.LEFT }),
      hCell("Avg Impact %", { width: 14 }),
      hCell("Rating", { width: 12 }),
      hCell("Relative Magnitude", { width: 36, alignment: AlignmentType.LEFT }),
    ],
    tableHeader: true,
  }),
  ...ranking.map((r, i) => {
    const isAlt = i % 2 === 1;
    const bg = isAlt ? LIGHT_GRAY : undefined;
    return new TableRow({
      children: [
        cell(String(i + 1), { alignment: AlignmentType.CENTER, shading: bg }),
        cell(shortName(r.param), { shading: bg }),
        cell(r.avg_max_impact.toFixed(1) + "%", { alignment: AlignmentType.CENTER, shading: bg }),
        cell(ratingLabel(r.sensitivity), { alignment: AlignmentType.CENTER, shading: bg }),
        cell(makeBar(r.avg_max_impact, maxImpact), { shading: bg, fontSize: 16 }),
      ],
    });
  }),
];

const rankingTable = new Table({
  rows: rankingRows,
  width: { size: 100, type: WidthType.PERCENTAGE },
  layout: TableLayoutType.FIXED,
  borders: {
    top: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    left: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    right: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    insideVertical: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
  },
});

// Profile detail table for a parameter
function profileTable(param) {
  const profiles = param.profiles;
  const keys = Object.keys(profiles);
  const rows = [
    new TableRow({
      children: [
        hCell("Profile", { width: 20, alignment: AlignmentType.LEFT }),
        hCell("Base (ZAR)", { width: 18 }),
        hCell("+25% (ZAR)", { width: 18 }),
        hCell("-25% (ZAR)", { width: 18 }),
        hCell("Max Impact %", { width: 14 }),
        hCell("Cover Rec.", { width: 12 }),
      ],
      tableHeader: true,
    }),
    ...keys.map((k, i) => {
      const p = profiles[k];
      const bg = i % 2 === 1 ? LIGHT_GRAY : undefined;
      const fmt = (v) => "R " + Math.round(v).toLocaleString("en-ZA");
      return new TableRow({
        children: [
          cell(k, { shading: bg }),
          cell(fmt(p.base), { alignment: AlignmentType.RIGHT, shading: bg }),
          cell(fmt(p.up_total), { alignment: AlignmentType.RIGHT, shading: bg }),
          cell(fmt(p.down_total), { alignment: AlignmentType.RIGHT, shading: bg }),
          cell(p.max_impact.toFixed(1) + "%", { alignment: AlignmentType.CENTER, shading: bg }),
          cell(fmt(p.base_rec_cover), { alignment: AlignmentType.RIGHT, shading: bg }),
        ],
      });
    }),
  ];
  return new Table({
    rows,
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    borders: {
      top: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
      left: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
      right: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
      insideVertical: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" },
    },
  });
}

// Build document sections
const children = [];

// Title
children.push(new Paragraph({
  children: [txt("Phishield Hybrid Financial Impact Model", { bold: true, color: NAVY, size: 36 })],
  alignment: AlignmentType.CENTER,
  spacing: { before: 400, after: 0 },
}));
children.push(new Paragraph({
  children: [txt("Sensitivity Analysis", { bold: true, color: NAVY, size: 32 })],
  alignment: AlignmentType.CENTER,
  spacing: { after: 80 },
}));
children.push(new Paragraph({
  children: [txt("Parameter Impact on Total Estimated Annual Loss (ZAR)", { italics: true, color: "666666", size: 22 })],
  alignment: AlignmentType.CENTER,
  spacing: { after: 200 },
}));
children.push(new Paragraph({
  children: [txt("Version 2.0  |  April 2026  |  SML Consulting", { color: "666666", size: 20 })],
  alignment: AlignmentType.CENTER,
  spacing: { after: 400 },
}));

// Horizontal rule
children.push(new Paragraph({
  children: [],
  border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: NAVY } },
  spacing: { after: 300 },
}));

// Executive Summary
children.push(heading("1. Executive Summary"));
children.push(para("This report presents the results of a One-at-a-Time (OAT) sensitivity analysis on the Phishield Hybrid Financial Impact Model. Each of the 10 key parameters was perturbed by +/-25% from its baseline value across three reference profiles to determine its influence on the Total Estimated Annual Loss."));
children.push(para("The table below ranks all parameters by their average maximum percentage impact:"));
children.push(new Paragraph({ children: [], spacing: { after: 80 } }));
children.push(rankingTable);
children.push(new Paragraph({ children: [], spacing: { after: 200 } }));

// High Impact
children.push(heading("2. High Impact Parameters (>15%)"));

children.push(new Paragraph({
  children: [txt("IBM Breach Anchor (R49.22M)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The IBM breach cost anchor is the single most influential parameter in the model, with a perfectly linear 25% impact across all profiles. This parameter sets the total breach magnitude from which all five cost components (C1-C5) are derived. Because it multiplies the entire cost structure, any change propagates proportionally through every component. This makes it the primary calibration lever: if the IBM Cost of a Data Breach Report updates its South African figure, the entire model shifts accordingly."));
children.push(profileTable(ranking[0]));
children.push(new Paragraph({ children: [], spacing: { after: 160 } }));

children.push(new Paragraph({
  children: [txt("Annual Revenue", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("Annual revenue is the second most influential parameter (18.2% average impact). It affects the model through multiple channels: it scales breach magnitude via the revenue-to-records relationship, drives the C3 business interruption component through daily revenue, influences C2 regulatory fines (POPIA/GDPR), and determines the C5 reputational damage tier. The asymmetric impact (larger effect when revenue decreases vs. increases) reflects the non-linear revenue scaling governed by the elasticity exponent."));
children.push(profileTable(ranking[1]));
children.push(new Paragraph({ children: [], spacing: { after: 200 } }));

// Medium Impact
children.push(heading("3. Medium Impact Parameters (5\u201315%)"));

children.push(new Paragraph({
  children: [txt("Industry Multiplier (Cost Severity)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The industry multiplier scales total breach magnitude for sectors with above-average breach costs (e.g., Financial Services at 1.32x). A notable feature is the graduated application: at R10M revenue, the multiplier is substantially dampened (only 1.74% impact) because the graduation formula blends it toward 1.0 for small companies. At R200M, the full multiplier applies, yielding a 22.5% impact. This makes it the most profile-dependent parameter in the model."));
children.push(profileTable(ranking[2]));
children.push(new Paragraph({ children: [], spacing: { after: 160 } }));

children.push(new Paragraph({
  children: [txt("Scanner Overall Score", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The scanner score drives vulnerability in the breach probability formula. A higher score reduces breach probability, creating an inverse relationship with total loss. At 8.4% average impact, it demonstrates that the security posture assessment has meaningful but bounded influence on the financial output \u2014 consistent with the model design where probability and magnitude are intentionally decoupled."));
children.push(profileTable(ranking[3]));
children.push(new Paragraph({ children: [], spacing: { after: 160 } }));

children.push(new Paragraph({
  children: [txt("TEF (Threat Event Frequency)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("Threat Event Frequency captures industry-specific breach targeting rates and feeds directly into the breach probability calculation. Its 8.2% average impact is comparable to the scanner score, confirming that both probability-side parameters carry similar weight. The asymmetric response (larger impact from increases than decreases) reflects the probability floor constraints in the model."));
children.push(profileTable(ranking[4]));
children.push(new Paragraph({ children: [], spacing: { after: 160 } }));

children.push(new Paragraph({
  children: [txt("Graduated Elasticity", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The elasticity exponent controls how breach magnitude scales with revenue. At 7.2% average impact it falls in the medium range, but this average conceals extreme variation: at R10M it produces a 21.5% impact (the highest of any parameter for that profile), while at R200M it has exactly zero impact because R200M is the anchor point where elasticity has no effect by construction. This makes elasticity the primary calibration tool for small company pricing."));
children.push(profileTable(ranking[5]));
children.push(new Paragraph({ children: [], spacing: { after: 200 } }));

// Low Impact
children.push(heading("4. Low Impact Parameters (<5%)"));

children.push(new Paragraph({
  children: [txt("SA Downtime Days (25)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("Average recovery downtime drives the C3 business interruption component. At 3.9% average impact, it has limited overall influence because C3 is only one of five cost components. However, the impact varies significantly by profile: 7.1% for R200M Agriculture (where daily revenue loss is proportionally larger relative to other components) versus 1.4% for R10M Financial Services."));
children.push(new Paragraph({ children: [], spacing: { after: 120 } }));

children.push(new Paragraph({
  children: [txt("Impact Factor (0.50)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The impact factor represents the average proportion of daily revenue lost during recovery. It multiplies directly with downtime days to determine C3, so it has an identical sensitivity profile to downtime days (3.9%). Together, these two parameters fully determine C3 and could be considered as a single composite parameter."));
children.push(new Paragraph({ children: [], spacing: { after: 120 } }));

children.push(new Paragraph({
  children: [txt("C4 Ransom Proportion (10.40%)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The ransom proportion determines what share of total breach magnitude is allocated to the C4 extortion component. At 3.3% average impact, it is a secondary tuning knob. The value is derived from Sophos State of Ransomware SA 2025 data and can be updated as new survey data becomes available without significantly destabilising the model."));
children.push(new Paragraph({ children: [], spacing: { after: 120 } }));

children.push(new Paragraph({
  children: [txt("POPIA Fine Rate (2%, cap R10M)", { bold: true, color: NAVY, size: 22 })],
  spacing: { before: 160, after: 80 },
}));
children.push(para("The POPIA regulatory fine rate has the lowest sensitivity at 1.0% average impact. The R10M statutory cap limits its influence, particularly for larger companies where the cap is easily reached. This confirms that regulatory fines, while important for compliance, are not a material driver of total estimated loss in the current South African regulatory environment."));
children.push(new Paragraph({ children: [], spacing: { after: 200 } }));

// Key Insight
children.push(heading("5. Key Insight: Revenue-Dependent Parameter Dominance"));
children.push(para("The graduated industry multiplier and elasticity create a notable interaction effect that has important implications for model calibration:", { after: 160 }));

children.push(para([
  txt("At R10M revenue: ", { bold: true }),
  txt("Elasticity is the top differentiator (21.5% impact) while the industry multiplier is nearly inert (1.7%). This occurs because the graduation formula dampens the industry multiplier for small companies, but elasticity\u2019s power-law scaling creates large deviations from the anchor at low revenue levels."),
]));
children.push(para([
  txt("At R200M revenue: ", { bold: true }),
  txt("The relationship inverts completely. The industry multiplier dominates at 22.5% while elasticity has exactly zero impact. R200M is the anchor point for the elasticity calculation, so perturbations cannot produce any change. Meanwhile, the full industry multiplier applies without graduation dampening."),
]));
children.push(new Paragraph({ children: [], spacing: { after: 120 } }));
children.push(para([
  txt("Calibration implication: ", { bold: true, color: NAVY }),
  txt("Small company calibration should focus on tuning the elasticity exponent, while large company calibration should prioritise the industry multiplier. These two parameters effectively partition the calibration space by company size, which is a desirable property for model maintenance."),
], { after: 200 }));

// Methodology
children.push(heading("6. Methodology"));
children.push(para([
  txt("Analysis type: ", { bold: true }),
  txt("One-at-a-Time (OAT) sensitivity analysis. Each parameter is varied independently while all others are held at their baseline values."),
]));
children.push(para([
  txt("Perturbation: ", { bold: true }),
  txt("+/-25% from the baseline value of each parameter."),
]));
children.push(para([
  txt("Reference profiles: ", { bold: true }),
  txt("Three profiles spanning the target market range:"),
]));
children.push(para("     (a)  R10M Financial Services \u2014 small company, high-risk industry", { after: 40 }));
children.push(para("     (b)  R200M Financial Services \u2014 large company, high-risk industry", { after: 40 }));
children.push(para("     (c)  R200M Agriculture \u2014 large company, low-risk industry", { after: 120 }));
children.push(para([
  txt("Metric: ", { bold: true }),
  txt("Average maximum absolute percentage change in Total Estimated Annual Loss across the three profiles. The maximum of |up_pct| and |down_pct| is taken per profile before averaging."),
]));
children.push(para([
  txt("Limitations: ", { bold: true }),
  txt("OAT analysis does not capture interaction effects between parameters varied simultaneously. The Key Insight section discusses one known interaction (elasticity vs. industry multiplier) identified through cross-profile comparison."),
]));

// Footer note
children.push(new Paragraph({
  children: [],
  border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" } },
  spacing: { before: 400, after: 120 },
}));
children.push(para("Prepared by SML Consulting for Phishield. Model version 2.0, April 2026.", { size: 16, color: "999999" }));

// Create document
const doc = new Document({
  styles: {
    default: {
      document: {
        run: { font: "Arial", size: 20 },
      },
    },
  },
  sections: [{
    properties: {
      page: {
        size: { width: 11906, height: 16838 }, // A4
        margin: {
          top: convertInchesToTwip(1),
          right: convertInchesToTwip(0.9),
          bottom: convertInchesToTwip(0.8),
          left: convertInchesToTwip(0.9),
        },
      },
    },
    children,
  }],
});

async function generate() {
  const buffer = await Packer.toBuffer(doc);
  const outPath = path.join(__dirname, "Phishield_Hybrid_Sensitivity_Analysis.docx");
  fs.writeFileSync(outPath, buffer);
  console.log("Written:", outPath);

  // Copy to Local Only
  const copyPath = "C:\\Users\\sarel\\Desktop\\Sarel\\Local Only\\Phishield_Hybrid_Sensitivity_Analysis.docx";
  fs.writeFileSync(copyPath, buffer);
  console.log("Copied:", copyPath);
}

generate().catch(err => { console.error(err); process.exit(1); });
