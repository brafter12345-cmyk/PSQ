const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require("docx");

const NAVY = "1B3A5C";
const ALT_ROW = "F2F7FA";
const WHITE = "FFFFFF";
const GREEN = "16A34A";
const AMBER = "D97706";

const PAGE_W = 11906;
const PAGE_H = 16838;
const MARGIN = 1440;
const CONTENT_W = PAGE_W - 2 * MARGIN;

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const headerBorder = { style: BorderStyle.SINGLE, size: 1, color: NAVY };
const headerBorders = { top: headerBorder, bottom: headerBorder, left: headerBorder, right: headerBorder };
const cellMargins = { top: 80, bottom: 80, left: 120, right: 120 };

function headerCell(text, width) {
  return new TableCell({
    borders: headerBorders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: NAVY, type: ShadingType.CLEAR },
    margins: cellMargins,
    verticalAlign: "center",
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, font: "Arial", size: 20, color: WHITE })] })]
  });
}
function dataCell(text, width, shaded, color) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: shaded ? ALT_ROW : WHITE, type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ spacing: { line: 276 }, children: [new TextRun({ text, font: "Arial", size: 20, color: color || "000000" })] })]
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

function buildTable(headers, colWidths, rows) {
  const headerRow = new TableRow({ tableHeader: true, children: headers.map((h, i) => headerCell(h, colWidths[i])) });
  const dataRows = rows.map((row, ri) =>
    new TableRow({
      children: row.map((val, ci) =>
        ci === 0 ? dataCellBold(val, colWidths[ci], ri % 2 === 1) : dataCell(val, colWidths[ci], ri % 2 === 1)
      )
    })
  );
  return new Table({ width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: colWidths, rows: [headerRow, ...dataRows] });
}

// --- Change Log (v8 -> v9) ---
const changeLogCols = [1300, 1100, 2500, 2500, 1626]; // sum 9026
const changeLogHeaders = ["Date", "Change ID", "Description", "Rationale", "Status"];
const changeLogRows = [
  [
    "2026-04-21", "SCN-009",
    "Added Anthropic Project Glasswing partner detection (checker + RSI credit + PDF/HTML card)",
    "Phase 4 item 4g. Public partner list is cheap to probe. A positive match is a favourable underwriting signal — partners apply Claude-assisted vulnerability discovery, shortening exposure to novel CVEs.",
    "Implemented"
  ],
  [
    "2026-04-21", "SCN-010",
    "Wall-clock timeout guards on sslyze (75s) and SubdomainChecker (90s) via run_with_timeout helper",
    "Strategic roadmap item #1 (scan speed). sslyze spawns subprocesses with no internal timeout and has historically caused 10-18 min scans when hitting unresponsive targets. crt.sh latency caused similar stalls in SubdomainChecker.",
    "Implemented"
  ],
  [
    "2026-04-21", "SCN-011",
    "Parallelised InformationDisclosureChecker path probes with ThreadPoolExecutor(max_workers=6)",
    "Previously 18 paths probed serially at up to 6s each (worst case 108s). Parallel batch caps at ~30s wall-clock — typical 5x speed-up on this checker.",
    "Implemented"
  ],
  [
    "2026-04-21", "SCN-012",
    "Introduced process-wide DNS cache (scanner_utils._DNSCache) to deduplicate lookups across checkers within a scan",
    "A/MX/NS/TXT/CAA records were being resolved repeatedly (discover_ips, CloudCDN, per-IP DNSInfrastructureChecker × N IPs, several socket.gethostbyname fallbacks). For a domain with 5 IPs, DNSInfrastructureChecker alone issued 25+ duplicate DNS queries.",
    "Implemented"
  ],
  [
    "2026-04-21", "SCN-013",
    "Favourable-signal RSI factor with a -0.05 credit for verified Glasswing partners, floor at 0",
    "Design decision: observable favourable signals should reduce RSI but never below the inherent-exposure baseline. -0.05 is modest enough to be defensible to underwriters without overstating a binary lookup.",
    "Implemented"
  ]
];

// --- Roadmap status (post v8) ---
const rmCols = [900, 3000, 3000, 2126]; // sum 9026
const rmHeaders = ["Phase", "Item", "Status (2026-04-21)", "Notes"];
const rmRows = [
  ["4a", "HTTP header score weighting (CSP > XCT)", "Done (Phase 3)", "CSP split to 10+10 in v7."],
  ["4b", "CMS admin path detection (dynamic from tech stack)", "Open", "Next candidate quick win — static path list exists in ExposedAdminChecker."],
  ["4c", "CDN origin IP leakage", "Open", "CDN provider detected; origin not probed."],
  ["4d", "MFA presence on VPN login pages", "Open", "Citrix/Fortinet/Pulse portals detected; MFA not checked."],
  ["4e", "WAF rate limiting / bot protection detection", "Open", "WAF presence detected; no active probing."],
  ["4f", "DNSSEC validation chain", "Open", "DNSSEC presence checked; chain not verified."],
  ["4g", "Glasswing partner detection", "Done (SCN-009, 2026-04-21)", "Binary lookup against 12 public Glasswing partners; RSI credit -0.05 when matched."],
  ["4h", "Exploit Window narrative enhancement", "Open", "Low-effort narrative addition for PDF."],
  ["5i-T1", "AI Threat Readiness Tier 1 (externally observable)", "Open", "Glasswing (4g) is the first piece. EDR via headers, bug-bounty, security.txt, CDN/WAF auto-patching still open."],
  ["Speed #1", "Timeout guards on sslyze + SubdomainChecker", "Done (SCN-010, 2026-04-21)", "run_with_timeout helper in scanner_utils.py; 75s / 90s caps."],
  ["Speed #2", "Parallelise info disclosure probes", "Done (SCN-011, 2026-04-21)", "ThreadPoolExecutor(max_workers=6) in InformationDisclosureChecker.check()."],
  ["Speed #6", "Pre-resolve DNS once", "Done (SCN-012, 2026-04-21)", "Shared _DNSCache singleton; primed at discover_ips; used by DNSInfrastructureChecker._get_dns_records and CAA/CloudCDN A lookups."],
  ["Speed #7", "Per-IP checkers to thread pool", "Done (pre-existing)", "ThreadPoolExecutor(max_workers=4) in scanner.py Phase 3."],
  ["Speed #3/#4/#8", "Tiered scan modes / cache-aware rescans / sslyze lazy mode", "Open", "Requires continuous monitoring scheduler."]
];

// --- Verification evidence ---
const vCols = [2400, 6626]; // sum 9026
const vHeaders = ["Verification", "Evidence"];
const vRows = [
  ["Glasswing partner match (positive)", "GlasswingPartnerChecker().check('hackerone.com') -> is_partner=True, partner_name='HackerOne', match_method='exact_domain'."],
  ["Glasswing partner match (negative)", "GlasswingPartnerChecker().check('takealot.com') -> is_partner=False, match_method=None."],
  ["RSI credit applied", "Synthetic Technology domain at R500M revenue with Glasswing match: RSI factor '-0.05 Anthropic Glasswing partner (HackerOne)' appears in contributing_factors."],
  ["Floor behaviour", "base = max(0.0, base) applied after Glasswing delta so favourable signals cannot push RSI below inherent-exposure baseline."],
  ["End-to-end scan", "scanner.SecurityScanner().scan('example.com') completed in 79.5s with all 22 checkers plus Glasswing returning data. Previous baseline for a clean domain: 8-12 min."],
  ["Timeout guard behaviour", "run_with_timeout returns {'status':'timeout','issues':[...]} if heavy checker exceeds its budget; scan continues and reports partial data rather than stalling."],
  ["Info disclosure parallelism", "18 probes now run under ThreadPoolExecutor(max_workers=6) with 30s wall-clock cap; worst case cut from ~108s to ~30s."]
];

// --- Open gaps ---
const gCols = [800, 2000, 900, 2500, 2826]; // sum 9026
const gHeaders = ["Gap ID", "Description", "Severity", "Current State", "Next Step"];
const gRows = [
  ["SCN-GAP-001", "Glasswing partner list is a static snapshot (Apr 2026)", "Low", "12 partners hardcoded in GlasswingPartnerChecker.PARTNERS", "Schedule quarterly refresh against Anthropic public partner page; consider pulling dynamically in monitoring scheduler."],
  ["SCN-GAP-002", "Timeout guards orphan the underlying thread if sslyze hangs", "Low", "run_with_timeout cancels the Future but subprocesses spawned by sslyze may continue until OS cleanup", "Acceptable on Render free tier — process recycles between scans. If moved to persistent worker, add explicit subprocess kill."],
  ["SCN-GAP-003", "DNS cache lifetime is per-scan (cleared at scan start)", "Low", "dns_cache.clear() called in scanner.scan()", "For continuous monitoring, extend to 24h TTL keyed by (domain, rtype) so rescans reuse stable records."],
  ["SCN-GAP-004", "SPF/DMARC/MX DNS lookups not yet routed through cache", "Low", "Those checks rely on dnspython-specific rdata attributes not exposed by cache", "Extend cache to return raw rdata objects or refactor checkers to use str() form. Defer to next batch."],
  ["SCN-GAP-005", "No AI Threat Readiness Tier 2 (self-reported) yet", "Medium", "Glasswing is the only AI-readiness signal captured", "Add scan-time questionnaire (EDR vendor, AI-assisted scanning, autonomous patching) — Phase 5i-T2."]
];

// --- Design decisions ---
const dCols = [1000, 2700, 2700, 2626]; // sum 9026
const dHeaders = ["ID", "Decision", "Alternatives Considered", "Rationale"];
const dRows = [
  ["DEC-V9-001", "RSI credit of -0.05 for Glasswing partnership, with base floor at 0", "(a) No credit (treat as informational only), (b) -0.10 credit, (c) Multiplier on industry factor", "(a) undervalues an observable signal that compresses exposure window; (b) overstates a binary lookup with no internal tooling visibility; (c) compounds with industry multiplier in misleading ways. -0.05 with a floor is defensible and transparent."],
  ["DEC-V9-002", "Static public partner list rather than HTML scrape of Anthropic page", "(a) Live scrape on each scan, (b) Periodic scrape + cache", "Anthropic's partner page structure can change; a live scrape introduces brittleness and adds external dependency to every scan. Quarterly manual refresh of the static list is low effort and deterministic."],
  ["DEC-V9-003", "Timeout budget: sslyze=75s, subdomains=90s", "(a) 60s/60s uniform, (b) 120s/120s", "60s is too aggressive for sslyze on multi-IP targets (real sslyze runs typically 40-70s). 90s on subdomains accounts for crt.sh occasional latency without permitting true hangs. Both well under the previous 10-18 min worst case."],
  ["DEC-V9-004", "Info disclosure max_workers=6", "(a) 10 (matches other checkers), (b) 3 (conservative)", "6 balances 18 paths × 6s ≈ 18-24s worst case against target politeness. 10 risks triggering rate limits or WAF rules; 3 leaves too much serial latency."],
  ["DEC-V9-005", "DNS cache is a process singleton cleared per scan", "(a) Per-scan instance passed explicitly, (b) Persistent with TTL", "Singleton avoids plumbing the cache through every checker constructor. Per-scan clear() prevents cross-scan leakage. TTL mode deferred to continuous monitoring work."]
];

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 24 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: NAVY },
        paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 1 } }
    ]
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] }
    ]
  },
  sections: [
    {
      properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
      children: [
        new Paragraph({ spacing: { before: 4000 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 200 },
          children: [new TextRun({ text: "Phishield Cyber Risk Scanner", font: "Arial", size: 52, bold: true, color: NAVY })]
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 100 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: NAVY, space: 8 } },
          children: [new TextRun({ text: "Gap Analysis v9", font: "Arial", size: 40, color: NAVY })]
        }),
        new Paragraph({ spacing: { before: 400 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 200 },
          children: [new TextRun({ text: "Quick Wins Delivery - Glasswing, Timeout Guards, Parallelism, DNS Cache", font: "Arial", size: 28, italics: true, color: "555555" })]
        }),
        new Paragraph({ spacing: { before: 600 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 100 },
          children: [new TextRun({ text: "Version 9  |  21 April 2026  |  SML Consulting", font: "Arial", size: 24, color: "666666" })]
        })
      ]
    },
    {
      properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
      headers: {
        default: new Header({ children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: NAVY, space: 4 } },
          spacing: { after: 120 },
          children: [new TextRun({ text: "Phishield Scanner - Gap Analysis v9", font: "Arial", size: 18, color: NAVY, italics: true })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          border: { top: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 4 } },
          children: [
            new TextRun({ text: "SML Consulting  |  v9  |  Page ", font: "Arial", size: 16, color: "999999" }),
            new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: "999999" })
          ]
        })] })
      },
      children: [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "1. Executive Summary", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "This revision captures the 21 April 2026 quick-wins delivery against the priorities identified in Gap Analysis v8 and the strategic roadmap. Four items were implemented in a single pass: Anthropic Project Glasswing partner detection (Phase 4g), wall-clock timeout guards on heavyweight checkers, parallelisation of information disclosure path probes, and a process-wide DNS cache that eliminates duplicate lookups across checkers.",
            font: "Arial", size: 22
          })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "End-to-end verification against a clean reference domain (example.com) completed in 79.5 seconds with all 22 checkers plus the new Glasswing lookup returning data. The Ransomware Susceptibility Index correctly applies a -0.05 credit when a Glasswing partner is detected, with a floor at zero so favourable signals cannot push RSI below the inherent-exposure baseline. PDF and HTML reports now include a dedicated \"AI Readiness (Glasswing)\" card under Technology & Governance.",
            font: "Arial", size: 22
          })]
        }),

        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "2. Change Log (v8 -> v9)", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Structural changes delivered in this revision, each tied to a roadmap item with its rationale and implementation status.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(changeLogHeaders, changeLogCols, changeLogRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "3. Roadmap Status", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Consolidated status across Phase 4 accuracy items and the scan-speed optimisation track from the strategic roadmap.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(rmHeaders, rmCols, rmRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "4. Verification Evidence", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Each quick win was verified independently before release. Evidence below is drawn from unit probes and an end-to-end smoke scan.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(vHeaders, vCols, vRows),

        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "5. Design Decisions", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Non-obvious choices made during delivery, with alternatives considered and rationale.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(dHeaders, dCols, dRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "6. Residual Gaps", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Known limitations introduced by or left open after this revision, with severity and recommended next step.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(gHeaders, gCols, gRows),

        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "7. Reporting Impact", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 160, line: 300 },
          children: [new TextRun({ text: "Changes visible in the underwriter-facing outputs:", font: "Arial", size: 22 })]
        }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "PDF report: new \"AI Readiness - Anthropic Glasswing\" card under TECHNOLOGY & GOVERNANCE, rendered in green when a partnership is detected and grey otherwise. Includes narrative, match method, and the RSI credit applied.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "HTML dashboard: matching \"AI Readiness (Glasswing)\" card with traffic-light indicator and partner narrative. SSE progress stream now emits a glasswing checker event.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Insurance analytics: RSI contributing_factors array gains a Glasswing entry with impact=-0.05 when a partnership is matched. Visible in both PDF and HTML RSI breakdowns.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Scan progress / SSE: heavy checkers that time out now emit status=\"timeout\" events rather than stalling the stream. Scan completes with partial data rather than hanging indefinitely.", font: "Arial", size: 22 })] }),

        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "8. Next Candidate Quick Wins", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 160, line: 300 },
          children: [new TextRun({ text: "Ordered by effort-to-value ratio, informed by what was learned during this delivery:", font: "Arial", size: 22 })]
        }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "CVE age / patch-management indicator (roadmap #11): NVD publishedDate is already fetched by _fetch_cvss; aggregate into oldest-unpatched-days and age-band counts. Pure data presentation.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Bug bounty detection (Phase 5a): HackerOne and Bugcrowd programme badges regex-matched on the homepage. Favourable RSI signal in the same shape as Glasswing.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "retire.js CVE cross-reference (Phase 5f): jQuery / AngularJS versions are already detected by TechStackChecker; map versions to known CVEs via OSV.dev.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "CMS admin path detection (Phase 4b): wire ExposedAdminChecker.PATHS to the detected CMS from TechStackChecker so WordPress installs are probed with /wp-admin but Drupal gets /user/login, and so on.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Extend DNS cache to SPF/DMARC/MX lookups (SCN-GAP-004): refactor cache to return rdata or wrap str() form, then remove duplicate queries across email_security / email_hardening / fraudulent_domains.", font: "Arial", size: 22 })] })
      ]
    }
  ]
});

const OUTPUT = "C:/Users/sarel/Desktop/Sarel/SML Consulting/PSQ/security_scanner/Phishield_Scanner_Gap_Analysis_v9.docx";

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(OUTPUT, buffer);
  console.log("Document created:", OUTPUT);
  console.log("Size:", (buffer.length / 1024).toFixed(1), "KB");
}).catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
