const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require("docx");

// Colors
const NAVY = "1B3A5C";
const LIGHT_NAVY = "D5E8F0";
const ALT_ROW = "F2F7FA";
const WHITE = "FFFFFF";
const HEADER_BG = NAVY;

// A4 page: 11906 x 16838 DXA, 1440 margins = 9026 content width
const PAGE_W = 11906;
const PAGE_H = 16838;
const MARGIN = 1440;
const CONTENT_W = PAGE_W - 2 * MARGIN; // 9026

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const headerBorder = { style: BorderStyle.SINGLE, size: 1, color: NAVY };
const headerBorders = { top: headerBorder, bottom: headerBorder, left: headerBorder, right: headerBorder };

const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

function headerCell(text, width) {
  return new TableCell({
    borders: headerBorders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: HEADER_BG, type: ShadingType.CLEAR },
    margins: cellMargins,
    verticalAlign: "center",
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, font: "Arial", size: 20, color: WHITE })] })]
  });
}

function dataCell(text, width, shaded) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: shaded ? ALT_ROW : WHITE, type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ spacing: { line: 276 }, children: [new TextRun({ text, font: "Arial", size: 20 })] })]
  });
}

function dataCellBold(text, width, shaded) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: shaded ? ALT_ROW : WHITE, type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ spacing: { line: 276 }, children: [new TextRun({ text, font: "Arial", size: 20, bold: true })] })]
  });
}

// --- Change Log Table ---
const changeLogCols = [1100, 900, 2200, 2200, 1826, 800]; // sum = 9026
const changeLogHeaders = ["Date", "Change ID", "Description", "Rationale", "Impact on Outputs", "Status"];

const changeLogRow1 = [
  "2026-04-13",
  "GAP-001",
  "Restructured from 3 independent scenarios to incident-type decomposition with 7 incident types and 5 shared cost components",
  "Revenue loss (22-day downtime) was misclassified inside the ransomware scenario rather than as a BI cost. This inflated ransomware to 68% of total loss while suppressing BI to 6%. IBM Cost of a Data Breach Report explicitly excludes ransomware costs from breach cost-per-record figures, making the old bundling inconsistent with the data source.",
  "Scenario allocation rebalanced from Breach 25% / Ransomware 68% / BI 6% to approximately Breach 49% / Ransomware 27% / BI 24% at reference profile (R100M revenue, Other industry, moderate posture). Total estimated loss remains similar magnitude.",
  "Implemented"
];

function makeChangeLogTable() {
  const headerRow = new TableRow({
    tableHeader: true,
    children: changeLogHeaders.map((h, i) => headerCell(h, changeLogCols[i]))
  });
  const dataRow = new TableRow({
    children: changeLogRow1.map((val, i) => dataCell(val, changeLogCols[i], false))
  });
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: changeLogCols,
    rows: [headerRow, dataRow]
  });
}

// --- Identified Gaps Table ---
const gapCols = [800, 1800, 900, 1900, 2226, 1400]; // sum = 9026
const gapHeaders = ["Gap ID", "Description", "Severity", "Current Approach", "Proposed Improvement", "Status"];

const gapRows = [
  ["GAP-001", "Revenue loss misallocated to ransomware scenario", "High", "Resolved via incident-type decomposition", "N/A", "Resolved (2026-04-13)"],
  ["GAP-002", "IBM data includes implicit BI costs", "Medium", "Accept IBM cost-per-record as authoritative (includes \u201Clost business\u201D component)", "Monitor whether IBM publishes component-level breakdown in future reports; consider adjusting if data becomes available", "Accepted (by design)"],
  ["GAP-003", "No correlation modelling between incident types", "Medium", "Incident types are summed as independent events", "Implement copula-based correlation for ransomware-family incidents (double extortion and ransomware-only are correlated by RSI)", "Future enhancement"],
  ["GAP-004", "SA-specific breach frequency data lacking", "Medium", "Uses overall score and IBM multiplier as proxy for breach probability", "Source SA-specific breach frequency from SABRIC or Information Regulator annual reports when available", "Future enhancement"],
  ["GAP-005", "Load-shedding impact on recovery not modelled", "Low", "Global average downtime days used (22 for ransomware)", "Add SA-specific recovery delay factor for companies without generator/UPS backup (suggested +3\u20135 days)", "Future enhancement"],
  ["GAP-006", "POPIA enforcement trend not reflected", "Low", "Fixed 2% of turnover", "Adjust based on Information Regulator enforcement track record (currently minimal fines imposed). Could reduce to 0.5\u20131% until enforcement matures.", "Future enhancement"],
  ["GAP-007", "Split ratios not yet empirically calibrated for SA", "Medium", "Global averages (70% double extortion, etc.) from industry reports", "Calibrate against SABRIC/CISA/IBM SA-specific incident-type data when available", "Future enhancement"]
];

function makeGapsTable() {
  const headerRow = new TableRow({
    tableHeader: true,
    children: gapHeaders.map((h, i) => headerCell(h, gapCols[i]))
  });
  const dataRows = gapRows.map((row, ri) =>
    new TableRow({
      children: row.map((val, ci) =>
        ci === 0 ? dataCellBold(val, gapCols[ci], ri % 2 === 1) : dataCell(val, gapCols[ci], ri % 2 === 1)
      )
    })
  );
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: gapCols,
    rows: [headerRow, ...dataRows]
  });
}

// --- Design Decisions Table ---
const decCols = [1000, 2600, 2600, 2826]; // sum = 9026
const decHeaders = ["Decision ID", "Decision", "Alternatives Considered", "Rationale"];

const decRows = [
  ["DEC-001", "Keep IBM cost-per-record data as-is (do not strip implicit BI)", "Reduce IBM data by 20\u201330% to remove \u201Clost business\u201D component", "IBM data is the most authoritative SA-specific source. Stripping a portion would introduce estimation error. The explicit BI modelling captures additional large-scale disruption beyond IBM averages."],
  ["DEC-002", "Hybrid probability model (derive from existing signals, expose split ratios)", "(a) Derive only with fixed ratios, (b) Add entirely new tuneable parameters per incident type", "Hybrid balances simplicity (reuses RSI, p_breach, p_interruption from scanner) with flexibility (split ratios tuneable in parameters doc for SA calibration)."],
  ["DEC-003", "Report still shows 3 categories (Breach/Ransomware/BI) as aggregated views", "Show all 7 incident types in the report", "Familiar structure for underwriters and brokers. Incident-type detail available in the data for advanced users. Avoids information overload."],
  ["DEC-004", "Wiper/destructive IR costs mapped to ransomware reporting category", "Create separate \u201Cdestructive attack\u201D reporting category", "Wipers and destructive attacks are operationally similar to ransomware (same threat actors, similar response). Keeping them in the ransomware category avoids fragmenting the report."]
];

function makeDecisionsTable() {
  const headerRow = new TableRow({
    tableHeader: true,
    children: decHeaders.map((h, i) => headerCell(h, decCols[i]))
  });
  const dataRows = decRows.map((row, ri) =>
    new TableRow({
      children: row.map((val, ci) =>
        ci === 0 ? dataCellBold(val, decCols[ci], ri % 2 === 1) : dataCell(val, decCols[ci], ri % 2 === 1)
      )
    })
  );
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: decCols,
    rows: [headerRow, ...dataRows]
  });
}

// --- Roadmap items ---
const roadmapItems = [
  "Empirical calibration of split ratios using SA incident data (SABRIC, Information Regulator)",
  "Correlation modelling between incident types using copulas",
  "Load-shedding recovery delay factor",
  "POPIA enforcement trend adjustment (dynamic based on regulatory activity)",
  "Industry-specific incident-type distributions (e.g., financial services may have higher data extortion ratio)",
  "Integration with claims data for model validation (when available)"
];

// --- Build Document ---
const doc = new Document({
  styles: {
    default: {
      document: { run: { font: "Arial", size: 24 } }
    },
    paragraphStyles: [
      {
        id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 }
      },
      {
        id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 }
      },
      {
        id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 200, after: 120 }, outlineLevel: 2 }
      }
    ]
  },
  numbering: {
    config: [
      {
        reference: "roadmap-bullets",
        levels: [{
          level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } }
        }]
      }
    ]
  },
  sections: [
    // Title Page
    {
      properties: {
        page: {
          size: { width: PAGE_W, height: PAGE_H },
          margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN }
        }
      },
      children: [
        new Paragraph({ spacing: { before: 4000 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({ text: "Phishield FAIR Model", font: "Arial", size: 52, bold: true, color: NAVY })]
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: NAVY, space: 8 } },
          children: [new TextRun({ text: "Gap Analysis & Change Log", font: "Arial", size: 40, color: NAVY })]
        }),
        new Paragraph({ spacing: { before: 400 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 200 },
          children: [new TextRun({ text: "Living Document for Model Evolution Tracking", font: "Arial", size: 28, italics: true, color: "555555" })]
        }),
        new Paragraph({ spacing: { before: 600 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
          children: [new TextRun({ text: "Version 1.0  |  April 2026  |  SML Consulting", font: "Arial", size: 24, color: "666666" })]
        })
      ]
    },
    // Content
    {
      properties: {
        page: {
          size: { width: PAGE_W, height: PAGE_H },
          margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN }
        }
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: NAVY, space: 4 } },
            spacing: { after: 120 },
            children: [
              new TextRun({ text: "Phishield FAIR Model \u2014 Gap Analysis & Change Log", font: "Arial", size: 18, color: NAVY, italics: true })
            ]
          })]
        })
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            border: { top: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 4 } },
            children: [
              new TextRun({ text: "SML Consulting  |  Version 1.0  |  Page ", font: "Arial", size: 16, color: "999999" }),
              new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: "999999" })
            ]
          })]
        })
      },
      children: [
        // Section 1: Purpose
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: "1. Purpose", font: "Arial" })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "This document tracks structural changes to the Phishield FAIR financial impact model, records design decisions and their rationale, and documents known gaps for future improvement. Each modification receives a dated entry describing what changed, why, what the previous approach was, and the measured impact on outputs.",
            font: "Arial", size: 22
          })]
        }),

        // Section 2: Change Log
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: "2. Change Log", font: "Arial" })]
        }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({
            text: "All structural modifications to the model are recorded below with date, description, rationale, and measured impact.",
            font: "Arial", size: 22, italics: true, color: "555555"
          })]
        }),
        makeChangeLogTable(),

        // Section 3: Identified Gaps
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 400 },
          children: [new TextRun({ text: "3. Identified Gaps", font: "Arial" })]
        }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({
            text: "Known limitations and areas for future improvement are tracked below with severity assessment and proposed remediation.",
            font: "Arial", size: 22, italics: true, color: "555555"
          })]
        }),
        makeGapsTable(),

        // Section 4: Design Decisions
        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun({ text: "4. Design Decisions", font: "Arial" })]
        }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({
            text: "Key architectural and methodological decisions are documented below with alternatives considered and rationale for the chosen approach.",
            font: "Arial", size: 22, italics: true, color: "555555"
          })]
        }),
        makeDecisionsTable(),

        // Section 5: Future Roadmap
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          spacing: { before: 400 },
          children: [new TextRun({ text: "5. Future Roadmap", font: "Arial" })]
        }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({
            text: "Planned improvements in approximate order of priority:",
            font: "Arial", size: 22, italics: true, color: "555555"
          })]
        }),
        ...roadmapItems.map(item =>
          new Paragraph({
            numbering: { reference: "roadmap-bullets", level: 0 },
            spacing: { after: 100, line: 300 },
            children: [new TextRun({ text: item, font: "Arial", size: 22 })]
          })
        )
      ]
    }
  ]
});

const OUTPUT = "C:/Users/sarel/Desktop/Sarel/SML Consulting/PSQ/security_scanner/Phishield_FAIR_Model_Gap_Analysis.docx";

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(OUTPUT, buffer);
  console.log("Document created:", OUTPUT);
  console.log("Size:", (buffer.length / 1024).toFixed(1), "KB");
}).catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
