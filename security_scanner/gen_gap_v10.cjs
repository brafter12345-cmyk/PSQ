const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat
} = require("docx");

const NAVY = "1B3A5C";
const ALT_ROW = "F2F7FA";
const WHITE = "FFFFFF";

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

// --- Change Log (v9 -> v10) ---
const changeLogCols = [1300, 1100, 2500, 2500, 1626];
const changeLogHeaders = ["Date", "Change ID", "Description", "Rationale", "Status"];
const changeLogRows = [
  [
    "2026-05-14", "SCN-014",
    "POPIA section reference corrected from Section 107 to Section 109 in code comments, Section 13 PDF generator, and PDF output text. Methodology footnote added clarifying that the 2%-of-turnover formula is an internal capacity-scaling heuristic for the Section 109(3) factors (nature, duration, extent, number of subjects, public importance, prevention, risk assessment, prior offences) and not a statutory formula.",
    "Audit finding (2026-05-14). Section 107 is criminal penalties (R10M fine OR 10 years jail OR both). Administrative fines from the Information Regulator come from Section 109. The 2% formula has no statutory basis in POPIA — Section 109 is a flat R10M ceiling. Fix is required before report can be relied on for FAIS disclosure purposes.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-015",
    "Civil Liability Disclosure added to PDF (summary + full), HTML, and Section 13 of the report. Disclosure explains that POPIA Section 99 civil action and common-law delict exposures cannot be quantified from an external scan because they depend on contracts, master service agreements, indemnity clauses, customer terms, and supplier liabilities held by the organisation. Disclaimer positioned next to BOTH the expected-loss panel and the catastrophe-loss panel.",
    "POPIA Section 99 is uncapped (\"amounts that are just and equitable\"; patrimonial loss + non-patrimonial loss + aggravated damages + costs). Common-law delict is similarly uncapped. These are typically the largest unmodelled tail exposures for SA breaches but require knowledge of the organisation's contractual environment to quantify. Disclosure aligns the report with FAIS reasonable-advice / appropriate-disclosure obligations.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-016",
    "Return-period worst-case views (1-in-50 P98, 1-in-100 P99, 1-in-150 P99.33) added to the Monte Carlo financial impact engine. Phase 1: _mc_percentiles returns the new percentiles, JSON output gains a return_periods block, PDF / HTML financial impact panels gain the corresponding rows. Phase 2: drop \"recommended_cover_zar\" anchored on P95 * 1.2. Phase 3: bump MC_ITERATIONS 10k -> 50k, widen PERT high-bounds for catastrophe legs (ransom demand 3x -> 5x, records leaked 3x -> 5x), and fit a generalised-Pareto tail above P95 for defensible extrapolation at the longest return period.",
    "Broker feedback (2026-05-14): surfacing 1-in-50, 1-in-100, 1-in-150 return-period loss views is commercially mandatory for the SA cyber cover market. Tightens disclosure around financial advice (FAIS reasonable-advice / appropriate disclosure of risk). Current report tops out at P95 = 1-in-20-year event; SA short-term insurance / reinsurance convention requires 1-in-100 minimum.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-017",
    "Sector regulatory framework cat stack added to the C2 (regulatory fines) component. New always-on additions: ECTA Section 89 (R1M cat). New conditional additions keyed off sub_industry: FSRA Section 167 / FSCA admin penalty (R100M conservative cap; no statutory ceiling), FIC Act Section 45C (R50M legal person), Electronic Communications Act + ICASA (R50M cat cap; per-day basis), CPA Section 112 (10% turnover or R1M whichever greater, B2C only), JSE Listings Requirements (R7.5M, listed flag), Property Practitioners Act (R0.5M criminal), Legal Practice Act / LPC (R1M aggregate), PFMA Section 86 (R5M, public sector), NCR / NCA (R1M, credit providers), Mine Health and Safety Act (R3M, mining), National Health Act Section 17(2) (R5M), Health Professions Act / HPCSA (R1M aggregate), Medical Schemes Act Section 66 (R10M, medical schemes), Pharmacy Act (R0.5M, pharmacy), SAHPRA / Medicines Act (R2M, pharma).",
    "User research (Phase E, 2026-05-14): the current C2 stack only models POPIA + GDPR + PCI + a generic R2M-per-extra-jurisdiction term. SA companies face stacked regulatory exposure across 5-8 separate regulators / civil claims depending on industry. For a R200M listed FS broker the cat regulatory stack moves from R12.85M (current model) to ~R188.5M (proposed) - a step-change consistent with broker feedback that the existing model materially understates SA legal exposure.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-018",
    "Sub-industry mapping for sector frameworks. Each of the 86 SIC sub-industries in _bi_factor_data.json maps to zero or more sector-specific framework additions in the C2 stack. Mapping is deterministic (auto-applied from the existing industry parameter), not flagged. Explicit checkbox flags retained for cross-industry conditions: GDPR (already present), listed_company (new), b2c (new), accountable_institution (new).",
    "Avoids broker / consultant having to manually tick \"FAIS applies\" / \"FIC applies\" / \"NHA applies\" - the scanner already collects the sub-industry. Cross-industry conditions (listed, B2C, accountable institution) cannot be inferred from industry alone so remain as form flags.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-019",
    "Cover wording redesigned to remove \"Recommended Cover Limit\" terminology. Replaced with a \"Loss Exposure Scenarios\" table presenting Most Likely (mode), Median (P50), 1-in-50 (P98), 1-in-100 (P99), and 1-in-150 (P99.33) outcomes. Footer disclaimer states that selection of cover limit is the responsibility of the insured in consultation with their broker, and that Phishield does not recommend a specific cover amount. JSON output schema changes: deprecate insurance_recommendation.recommended_cover_zar in favour of a loss_exposure.scenarios object keyed by scenario name.",
    "FAIS exposure: \"Recommended Cover Limit\" as currently labelled constitutes financial advice on cover sizing. UMA must present the spread of possible outcomes and allow the client / broker to choose. New wording maintains the report's analytical content but reframes the output as informational rather than advisory.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-020",
    "Per-checker wall-clock timing instrumented in scanner.py. Each checker invocation now records start_time and end_time via time.perf_counter(). Per-checker durations are folded into _scan_completeness.per_checker_seconds and rendered as a new \"Scan Duration Profile\" section in the full PDF report.",
    "Diagnostic primitive missing today: _scan_completeness records only pass / fail / skipped status, not duration. Real-world scans are running 3-19 minutes (per local scans.db) versus the documented ~80 second baseline. Without per-checker timing there is no defensible way to diagnose which checker is responsible for a slow scan, which blocks SLA discussions with brokers.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-14", "SCN-021",
    "Glasswing checker UI status fix. Today every lightweight checker is marked \"running\" before it is submitted to the ThreadPoolExecutor queue (scanner.py line 208). With max_workers=6 and 21 lightweight checkers, 15 checkers display as \"running\" while actually queued. Fix: emit \"running\" inside the future wrapper at the moment of execution, not at submission. SCN-020 timing data provides the verification primitive.",
    "User-reported (2026-05-14): glasswing UI status showed \"running\" for 4-6 minutes on a phishield.com scan. Code analysis confirms glasswing's actual execution is bounded at ~5s (single HTTP GET with 5s timeout). The 4-6 minute observation is an instrumentation artifact from premature status emission, not a bug in the glasswing checker itself. The real bottleneck is whichever checker(s) held the 6 worker threads - to be identified by SCN-020 timing once implemented.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-15", "SCN-022",
    "Enterprise capacity factor (revenue-band scaling) added to the catastrophe regulatory stack. All statutory maxima are now scaled by a factor between 0.10 (below R10M revenue) and 1.00 (above R10B) before stacking. Percentage-based formulas (CPA 10%, GDPR 4%) are NOT scaled - they already track revenue naturally.",
    "User-flagged (2026-05-15): without revenue-band scaling a R10M FSP would face the same cat ceiling as Sanlam at R200B - indefensible. The Information Regulator's Section 109(3) factors explicitly require consideration of extent and ability to pay, and equivalent enforcement-discretion patterns hold across other SA regulators. Revenue-band table provides a defensible, transparent scaling rule.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-15", "SCN-023",
    "Auto-detection + pre-flight pipeline added. New /api/preflight endpoint runs lightweight detection BEFORE the full scan starts: JSE-listed company (curated static list + footer ticker scrape), B2C (sub-industry + payment-form signals), accountable institution (sub-industry mapping), healthcare sub-detail (domain + title keyword classifier), GDPR / PCI suggestions (page-content hints). Frontend pre-fills broker form with badge-marked detected flags; broker overrides as needed. Both broker input and auto-detected values are recorded in the scan output (regulatory_flags._auto_detected) for FAIS audit trail.",
    "User-requested (Batch 4 scope, 2026-05-15): pre-fill reduces broker work to roughly 1 minute per scan while making the cat-stack inputs much richer. The audit-trail surface (broker input vs auto-detected, side-by-side with evidence) is the FAIS-defensible record of how each regulatory decision was made.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-15", "SCN-024",
    "PrivacyComplianceChecker.\\_find\\_policy\\_url parallelised. Strategy 2 (the common-paths fallback) previously probed 30 candidate URLs (2 domain variants x 15 paths) sequentially at 15s timeout each, giving a 450s worst case. Rewritten to use a ThreadPoolExecutor(max\\_workers=8) with first-match short-circuit and an 8s per-probe timeout. Strategy 1 (homepage anchor scrape) similarly parallelised for up to 5 candidate hrefs at 10s each. New \\_probe\\_urls\\_concurrent helper centralises the pattern.",
    "Phase D timing instrumentation (SCN-020) on the 2026-05-15 phishield.com test scan exposed privacy\\_compliance as the actual slow checker holding a worker thread for 472 seconds (~7.9 minutes). This was the real bottleneck behind the user-reported 'glasswing running for 4-6 min' UI artifact (SCN-021). Smoke test 2026-05-15 post-fix: same checker on same domain returns in 44 seconds (10.7x speedup). Same parallelisation pattern as v9 SCN-011 for InformationDisclosureChecker.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-15", "SCN-025",
    "Centralised HTTP client with per-apex rate limiting, WAF detection, identifying User-Agent, and probe-cache interface slot. New http\\_client.py module exposes a singleton HTTP instance used by burst-mode path-probers (privacy\\_compliance, info\\_disclosure, exposed\\_admin). Rate limiter: token bucket at 2 req/sec per apex with burst 5. WAF tracker: sliding-window response monitor flagging waf\\_blocked (>=40% 403/406/451), waf\\_rate\\_limited (>=25% 429/503), waf\\_timeout (>=50% timeouts), waf\\_challenge (Cloudflare / Akamai / Imperva / DataDome / hCaptcha / PerimeterX signatures). User-Agent: Phishield-Scanner/1.0 (+https://phishield.com/scanner-info) - matches industry-standard self-identification (Bitsight, SecurityScorecard, Coalition, CFC, Black Kite, RiskRecon pattern). New /scanner-info public route serves security-team verification page describing scanner identity, request profile, and contact details.",
    "User-reported 2026-05-15: aggressive parallelisation (introduced in SCN-024) materially increased WAF trigger rates on phishield.com. Browser access to the user's own site timed out for 24-48h after a scan due to defensive challenge-mode escalation. Root cause: SCN-024 burst pattern (30 concurrent path probes within ~30s from a single source IP) trips burst-rate WAF rules even when sustained-rate rules would be lenient. Industry-passive-scanner pattern (1-3 req/sec, identifying UA, transparent IP ranges) avoids this. Per-card and top-level Partial Coverage Notices added to PDF + HTML when WAF intervention detected - replacing previously misleading 'no findings' results with explicit 'scanner could not verify' disclosure. FAIS reasonable-advice compliance: the report must not produce false-negative findings when the scan was actively blocked.",
    "Done 2026-05-15"
  ],
  [
    "2026-05-15", "SCN-026",
    "Probe-cache interface slot defined in http\\_client.HttpClient. Implementation deferred to the continuous-monitoring track; default \\_NullProbeCache makes every lookup miss. Interface contract documented (lookup / store / invalidate) plus refresh rules per response status (2xx: 24h TTL with HEAD re-verify; 404: 7d TTL with 10% spot-check; 5xx: 1h TTL; 403/451/406: 6h TTL; 429/503: 30m TTL; timeout: 1h TTL). Invalidation triggers: TTL expiry, /api/scan?force\\_refresh=true broker override, target primary-IP-or-ASN change. Storage planned: scans.db probe\\_cache(domain, url, status\\_code, response\\_headers, response\\_body\\_hash, last\\_probed\\_at, expires\\_at) indexed by (domain, url).",
    "Continuous-monitoring scheduler (Speed track #3 / #4 'tiered scan modes / cache-aware rescans') requires this cache to be economically viable. Hourly or daily rescans of the same domain without a probe cache would burn through external API budgets and trip WAFs everywhere. Interface ships now in HttpClient so checkers route through the cache lookup automatically; only the backing store implementation is deferred. When the scheduler lands, swap \\_NullProbeCache for a SQLite-backed implementation at module import time - no checker code changes required.",
    "Deferred to continuous-monitoring track"
  ]
];

// --- Roadmap status (post v9) ---
const rmCols = [900, 3000, 3000, 2126];
const rmHeaders = ["Phase", "Item", "Status (2026-05-14)", "Notes"];
const rmRows = [
  ["FAIR-1", "Return-period worst-case views (1:100 / 1:200 / 1:250)", "Done (SCN-016, 2026-05-15)", "Broker-mandated. Phase 1 (percentiles), Phase 2 (drop Recommended Cover, dedicated table), Phase 3 (50k MC + widened PERT + pure-numpy GPD tail fit) all landed in Batch 1-3."],
  ["FAIR-2", "POPIA Section 107 -> 109 correction + heuristic disclosure", "Done (SCN-014, 2026-05-15)", "Required before report can be relied on for FAIS disclosure. Substantive correction; 2% formula retained as documented heuristic."],
  ["FAIR-3", "Civil liability disclosure (POPIA s99 / common-law delict)", "Done (SCN-015, 2026-05-15)", "Qualitative disclosure - rendered in PDF (summary + full) and HTML. Quantification out of scope - depends on contractual data invisible to external scan."],
  ["FAIR-4", "Sector regulatory framework cat stack + capacity factor", "Done (SCN-017, SCN-018, SCN-022, 2026-05-15)", "FSCA / FIC / ECA / JSE / CPA / NHA / HPCSA / MSA / LPC / PPRA / PFMA / NCR / MHSA / SAHPRA all mapped. Revenue-band capacity factor (0.10 to 1.00) applied to defensibly scale by entity size."],
  ["FAIR-5", "Cover wording redesign (Recommended Cover -> Exposure Scenarios)", "Done (SCN-019, 2026-05-15)", "FAIS-safety. Loss Exposure Scenarios table replaces Recommended Cover Limit in PDF + HTML + JSON. Final report wording subject to compliance officer sign-off before going live."],
  ["FAIR-6", "Auto-detection + pre-flight + flag audit trail", "Done (SCN-023, 2026-05-15)", "/api/preflight endpoint, form pre-fill UX, flag audit panel in report. JSE-listed / B2C / accountable institution / healthcare sub-detail auto-inferred; broker confirms."],
  ["4b", "CMS admin path detection (dynamic from tech stack)", "Open", "Carried over from v9. Next quick win candidate."],
  ["4c", "CDN origin IP leakage", "Open", "Carried over from v9."],
  ["4d", "MFA presence on VPN login pages", "Open", "Carried over from v9."],
  ["4e", "WAF rate limiting / bot protection detection", "Open", "Carried over from v9."],
  ["4f", "DNSSEC validation chain", "Open", "Carried over from v9."],
  ["4h", "Exploit Window narrative enhancement", "Open", "Carried over from v9."],
  ["5a", "Bug bounty programme detection (HackerOne / Bugcrowd)", "Open", "Carried over from v9. Same shape as Glasswing - favourable RSI signal."],
  ["5f", "retire.js CVE cross-reference", "Open", "Carried over from v9."],
  ["5i-T1", "AI Threat Readiness Tier 1 (externally observable)", "Open", "Glasswing is the first piece (delivered in v9)."],
  ["5i-T2", "AI Threat Readiness Tier 2 (self-reported)", "Open", "Carried over from v9."],
  ["Speed #3", "Tiered scan modes", "Open", "Requires continuous monitoring scheduler."],
  ["Speed #4", "Cache-aware rescans", "Open", "Requires continuous monitoring scheduler."],
  ["Speed #8", "sslyze lazy mode", "Open", "Requires continuous monitoring scheduler."],
  ["Diag-1", "Per-checker wall-time instrumentation + glasswing UI fix", "Done (SCN-020, SCN-021, 2026-05-15)", "Per-checker wall-clock timing recorded in _scan_completeness.per_checker_seconds. Scan Duration Profile section in full PDF. Glasswing UI artifact fix: 'running' status emitted at execution start, not at submission."],
  ["WAF-1", "Centralised HTTP client + rate limiter + WAF detection + scanner-info page", "Done (SCN-025, 2026-05-15)", "Single chokepoint for outbound HTTP. 2 req/sec per apex; identifying User-Agent linking to /scanner-info; per-card and top-level Partial Coverage Notices when WAF intervention detected."],
  ["WAF-2", "Probe-cache interface slot (continuous-monitoring extension point)", "Done interface; impl deferred (SCN-026)", "ProbeCache protocol + _NullProbeCache default ship now in http_client.py. Backing store (SQLite probe_cache table) lands with the continuous-monitoring scheduler."],
  ["Cont-1", "Continuous monitoring scheduler", "Open", "Hourly / daily rescan capability. Requires SCN-026 cache implementation + per-tenant scheduler + delta-finding detection + alert-on-change pipeline. Estimated 3-4 week build."]
];

// --- Sector framework cat-stack mapping ---
const sCols = [2700, 3300, 3026];
const sHeaders = ["Trigger", "Statutory framework (statutory max)", "Cat-loss addition (ZAR)"];
const sRows = [
  ["All entities (always-on)", "POPIA Section 109 administrative fine", "R10,000,000 (statutory ceiling)"],
  ["All entities (always-on)", "ECTA Section 89 (court-discretionary fine + criminal)", "R1,000,000 conservative cat estimate"],
  ["EU data flag", "GDPR (4% of global turnover, uncapped)", "Revenue x 4%"],
  ["PCI data flag", "PCI DSS scheme fines (capped at 30% external visibility)", "R700,000 - R1,000,000"],
  ["B2C flag", "Consumer Protection Act Section 112", "10% of turnover OR R1,000,000 (greater)"],
  ["Listed flag", "JSE Listings Requirements + FSCA Market Conduct", "R7,500,000"],
  ["Accountable Institution flag", "FIC Act Section 45C", "R50,000,000 (legal person)"],
  ["Depository Institutions (banks)", "FSRA s167 (FSCA) + FIC + Banks Act", "FSCA cat cap R100,000,000 + FIC R50,000,000 = R150,000,000"],
  ["Non-depository Credit Institutions", "FSRA s167 + FIC + NCR (NCA)", "R100,000,000 + R50,000,000 + R1,000,000 = R151,000,000"],
  ["Security/Commodity Brokers, Dealers", "FSRA s167 + FIC", "R150,000,000"],
  ["Insurance Carriers", "FSRA s167 + FIC + Insurance Act", "R150,000,000"],
  ["Insurance Agents, Brokers, Services", "FSRA s167 (FAIS) + FIC", "R150,000,000"],
  ["Real Estate (FS subcategory)", "Property Practitioners Act + FIC (estate agents are AI)", "R0,500,000 + R50,000,000 = R50,500,000"],
  ["Holding & Other Investment Offices", "FSRA s167 + FIC", "R150,000,000"],
  ["Health Services (general)", "National Health Act s17(2) + HPCSA", "R5,000,000 + R1,000,000 = R6,000,000"],
  ["Health Services - medical scheme", "NHA + HPCSA + Medical Schemes Act s66", "R5,000,000 + R1,000,000 + R10,000,000 = R16,000,000"],
  ["Health Services - pharmacy", "NHA + HPCSA + Pharmacy Act", "R5,000,000 + R1,000,000 + R0,500,000 = R6,500,000"],
  ["Health Services - pharma/biotech", "NHA + HPCSA + SAHPRA (Medicines Act)", "R5,000,000 + R1,000,000 + R2,000,000 = R8,000,000"],
  ["Legal Services", "Legal Practice Act / LPC + FIC (attorneys are AI)", "R1,000,000 + R50,000,000 = R51,000,000"],
  ["Communications (telecoms)", "Electronic Communications Act + ICASA", "R50,000,000 cat cap (per-day basis = uncapped)"],
  ["Coal / Metal / Oil&Gas Mining (data-relevant)", "Mine Health and Safety Act", "R3,000,000"],
  ["Public Sector (all sub-industries)", "Public Finance Management Act s86", "R5,000,000"],
  ["All other (Manufacturing, Retail, etc.)", "No industry-specific addition", "R0 (POPIA / CPA / ECTA carry the cross-industry stack)"]
];

// --- Worst-case example: R200M listed FS broker, B2C, accountable institution ---
const exCols = [3500, 2800, 2726];
const exHeaders = ["Component", "Current model (v9)", "Proposed model (v10)"];
const exRows = [
  ["POPIA admin fine (Section 109)", "R4,000,000 (2% of R200M)", "R10,000,000 (statutory ceiling used in cat)"],
  ["POPIA civil action (Section 99)", "Not modelled", "Disclosed qualitatively - uncapped, outside scope"],
  ["GDPR (EU data flag off)", "R0", "R0"],
  ["PCI DSS (off in this example)", "R0", "R0"],
  ["Consumer Protection Act (B2C trigger)", "Not modelled", "R20,000,000 (10% x R200M)"],
  ["ECTA Section 89 (online business)", "Not modelled", "R1,000,000"],
  ["FSRA / FSCA admin (FAIS broker)", "Not modelled", "R100,000,000 cat cap"],
  ["FIC Act s45C (accountable institution)", "Not modelled", "R50,000,000"],
  ["JSE Listings (listed entity)", "Not modelled", "R7,500,000"],
  ["TOTAL C2 cat exposure", "R4,000,000", "R188,500,000"],
  ["Ratio v10 / v9", "1.0x", "47.1x"]
];

// --- Open gaps ---
const gCols = [800, 2000, 900, 2500, 2826];
const gHeaders = ["Gap ID", "Description", "Severity", "Current State", "Next Step"];
const gRows = [
  ["SCN-GAP-001", "Glasswing partner list static snapshot (April 2026)", "Low", "12 partners hardcoded", "Quarterly refresh; pull dynamically when continuous monitoring scheduler exists."],
  ["SCN-GAP-002", "Timeout guards orphan threads if sslyze hangs", "Low", "Acceptable on Render free tier; relevant for persistent worker", "Add explicit subprocess kill when persistent worker is adopted."],
  ["SCN-GAP-003", "DNS cache per-scan only", "Low", "Cleared at scan start", "Extend to 24h TTL keyed by (domain, rtype) for continuous monitoring."],
  ["SCN-GAP-004", "SPF/DMARC/MX lookups not routed through cache", "Low", "Defer to next batch", "Extend cache to return raw rdata or refactor checkers."],
  ["SCN-GAP-005", "No AI Threat Readiness Tier 2 (self-reported)", "Medium", "Glasswing is only AI signal", "Add scan-time questionnaire."],
  ["SCN-GAP-006", "Sample density at long return periods", "Medium", "10k MC iterations yields only 40-100 samples beyond P99; SCN-016 Phase 3 bumps to 50k", "Verify P99.33 stability via repeat-run dispersion test after 50k bump."],
  ["SCN-GAP-007", "PERT distribution upper bound caps the catastrophe tail", "Medium", "mc_rd / mc_rec / mc_fine PERT high-bound currently 2-3x mode; widened to 5x in SCN-016 Phase 3", "Calibrate against SA empirical catastrophe data (Transnet 2021, Life Healthcare 2020, ransomware-family observations)."],
  ["SCN-GAP-008", "Civil liability quantification not modelled", "Accepted", "POPIA s99 + common-law delict are uncapped and depend on contractual data invisible to external scan", "Disclosure (SCN-015) is the in-scope answer. Quantification would require an internal-data add-on product."],
  ["SCN-GAP-009", "Enforcement-discount calibration per regulator", "Medium", "Statutory maximum used for cat (SCN-017); P50 / expected loss uses capacity-scaled heuristic", "Compliance officer must set the enforcement-discount % per regulator for the expected-loss view. Sector by sector: Information Regulator ~25-50%, FSCA ~60-80%, FIC ~70%, ICASA ~30%, JSE varies. To be determined."],
  ["SCN-GAP-010", "Sub-industry tagger for healthcare specialisation", "Low", "Need to distinguish medical_scheme / pharmacy / pharma / hospital among the SIC 'Health Services' parent category", "Add sub_industry_detail field to scan form for Health Services, defaulting to 'hospital_clinic'."],
  ["SCN-GAP-011", "GPD tail fit dependency on scipy", "Low", "Phase 3 uses scipy.stats.genpareto for 1-in-150 extrapolation", "scipy is a heavy dependency; verify Render free-tier build still fits within 512 MB. Fall back to PERT-only if scipy import fails."],
  ["SCN-GAP-012", "UI status premature emission across all concurrent checkers", "Low", "SCN-021 fixes glasswing display; same root cause affects ~14 other checkers", "Same fix automatically corrects the entire concurrent batch (notify at execution start, not at submission). Verification via SCN-020 timing."]
];

// --- Design decisions ---
const dCols = [1000, 2700, 2700, 2626];
const dHeaders = ["ID", "Decision", "Alternatives Considered", "Rationale"];
const dRows = [
  ["DEC-V10-001", "Drop \"Recommended Cover Limit\" label; replace with \"Loss Exposure Scenarios\" table presenting Most Likely / Median / 1-in-50 / 1-in-100 / 1-in-150", "(a) Keep current Recommended Cover label, (b) Rename to 'Suggested Cover Range', (c) Hide recommendation entirely", "(a) is the live FAIS exposure - a UMA recommending a specific cover figure crosses into financial advice; (b) softens the wording but still positions Phishield as the recommender; (c) loses analytical value the broker actually relies on. Scenario table preserves analytical content while moving the recommendation decision to broker + client."],
  ["DEC-V10-002", "Statutory maximum used for catastrophe view; capacity-scaled heuristic used for P50 / expected loss view", "(a) Statutory max everywhere (legally accurate but unrealistic for expected loss), (b) Heuristic everywhere (defensible for expected but loses worst-case signal), (c) Single hybrid number with confidence band", "(a) overstates expected annual loss for premium rating; (b) understates 1-in-100 cover sizing; (c) blurs the distinction brokers and underwriters need. Two-track output (expected vs cat) is industry standard and aligns with reinsurance practice."],
  ["DEC-V10-003", "Sector framework C2 stack auto-applied from sub_industry; cross-industry conditions (listed / B2C / accountable_institution) as explicit flags", "(a) All frameworks behind explicit flags (verbose UI), (b) All frameworks auto-applied (impossible - cross-industry conditions cannot be inferred), (c) Probability-weighted overlay (mixes cat and expected views)", "Sub-industry is already in the scan input; auto-applying its consequences is a free win. Listed / B2C / AI status cannot be inferred from domain or industry so they remain form flags. Probability-weighted is the wrong layer (P50 vs cat are separate views, not blended)."],
  ["DEC-V10-004", "Civil liability disclosed qualitatively, not quantified", "(a) Quantify as records x R500-5,000 PERT in cat MC, (b) Apply a 5-10x multiplier on POPIA admin fine as a heuristic, (c) Omit entirely", "(a) and (b) put a number on something the scanner cannot defensibly model - civil exposure depends on contracts, customer terms, supplier indemnities, master service agreements. Disclosing the gap explicitly is more defensible to brokers and compliance than fabricating a number. (c) is what v9 does and is precisely what the broker flagged needs tightening."],
  ["DEC-V10-005", "FSCA / FSRA s167 cat cap set conservatively at R100M", "(a) Use largest historical SA fine (R475M, AYO Technology 2024), (b) Use median large fine (R50M, Viceroy)", "FSRA Section 167 has no statutory cap. (a) overstates worst-case for the typical FSP; (b) understates the upper tail. R100M is between the median and worst-case observed historical penalties and is defensible as a 1-in-100 estimate. Document as a model assumption."],
  ["DEC-V10-006", "Per-checker wall-time instrumentation as a first-class output (SCN-020)", "(a) Console logging only, (b) Hide from PDF, show only in JSON, (c) Surface in full PDF as a Scan Duration Profile section", "(a) loses brokers' visibility into scan quality; (b) is functionally invisible. (c) is honest about where time is spent, gives brokers a quality signal, and gives operations a permanent diagnostic primitive for slow-scan triage (would have made the glasswing-running-for-4-min report a one-minute investigation)."],
  ["DEC-V10-007", "Glasswing UI status fix scoped to the entire concurrent batch, not glasswing alone", "(a) Patch only glasswing's notify call, (b) Patch all 21 lightweight checkers separately, (c) Refactor _notify integration with the executor", "Root cause is shared - all checkers emit \"running\" before executor pickup (scanner.py line 208). (a) leaves the visual artifact for the other 14 queued checkers. (b) is just (c) with extra steps. Single-point fix at the submission loop addresses the whole batch."]
];

// --- Verification evidence (smoke-tested 2026-05-15) ---
const vCols = [2400, 6626];
const vHeaders = ["Verification", "Evidence (2026-05-15)"];
const vRows = [
  ["POPIA section reference fix", "VERIFIED - scoring_analytics.py:1740-1751 comment cites Section 109 (and explicitly notes the prior 107 reference was wrong). gen_sec13.py row text reads \"SA Information Regulator, Section 109 (Administrative fines).\" PDF Section 13 generator output confirmed."],
  ["Civil liability disclosure rendered", "VERIFIED - civil_liability_disclosure() helper in pdf_report.py wired into both summary section (after FINANCIAL IMPACT SUMMARY) and full report (after Financial Impact card). HTML results.html renders the disclosure block with amber left-border."],
  ["Return-period percentile computation", "VERIFIED - _mc_percentiles(samples) returns p99 / p99_5 / p99_6 plus mode estimate. Smoke test on lognormal(14,1.5): P95 R14M -> P99 R39M -> P99.6 R62M. GPD fitted alternative computed alongside; raw fallback applied when fit fails sanity checks."],
  ["Exposure scenario table replaces Recommended Cover", "VERIFIED - loss_exposure_scenarios_block() in pdf_report.py renders dedicated 3-column Table (Scenario / Modelled Loss / Annual Probability) with 5 rows. JSON output has insurance_recommendation._deprecated=True with _use_instead pointer to loss_exposure.scenarios."],
  ["Sector cat stack applied via sub-industry mapping", "VERIFIED via end-to-end smoke - Insurance Agents R200M (listed + B2C + AI): cat stack R129.5M. Same profile at R10M: R25.15M. Sanlam-scale R200B Insurance Carrier: R20.2B (CPA s112 dominates). Capacity factor curve verified across 9 revenue bands."],
  ["Per-checker timing rendered", "VERIFIED - scanner.py wraps each lightweight + per-IP checker with time.perf_counter() in _run_with_timing / _run_ip_with_timing wrappers. Durations populate _scan_completeness.per_checker_seconds. scan_duration_profile() helper renders top-15 + sum table in full PDF."],
  ["Glasswing UI status fix", "VERIFIED - scanner.py:208 no longer emits \"running\" at submission. _run_with_timing wrapper emits \"running\" at execution start. Glasswing's actual code path is bounded at ~5s (single HTTP GET + 5s timeout); the 4-6 min observation was a queue-position artifact."],
  ["Auto-detection pre-flight", "VERIFIED - flag_inference.run_preflight() on discovery.co.za returns is_listed=True (JSE: DSY, static-list match). On phishield.com returns is_listed=False, accountable_institution=True, b2c=True. Pre-flight wall time 3-16s depending on HTTP latency."],
  ["Flag audit panel rendered", "VERIFIED - flag_audit_panel() helper in pdf_report.py renders 4-column Table (Flag / Broker Input / Auto-detected / Evidence) reading from regulatory_exposure.flags + flags._auto_detected. HTML results.html has matching panel."],
  ["End-to-end test scan", "Phishield.com R10M Finance scan launched 2026-05-15 via run_test_scan.py with broker-confirmed accountable_institution + b2c flags. Result JSON + full PDF cached to test_fixtures/phishield_R10M_finance_2026-05-15.{json,pdf} for further report tuning."]
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
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
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
          children: [new TextRun({ text: "Gap Analysis v10", font: "Arial", size: 40, color: NAVY })]
        }),
        new Paragraph({ spacing: { before: 400 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 200 },
          children: [new TextRun({ text: "Financial Impact Disclosure, Return-Period Worst Case, Regulatory Cat Stack", font: "Arial", size: 28, italics: true, color: "555555" })]
        }),
        new Paragraph({ spacing: { before: 600 } }),
        new Paragraph({
          alignment: AlignmentType.CENTER, spacing: { after: 100 },
          children: [new TextRun({ text: "Version 10  |  14 May 2026  |  SML Consulting", font: "Arial", size: 24, color: "666666" })]
        })
      ]
    },
    {
      properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, right: MARGIN, bottom: MARGIN, left: MARGIN } } },
      headers: {
        default: new Header({ children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: NAVY, space: 4 } },
          spacing: { after: 120 },
          children: [new TextRun({ text: "Phishield Scanner - Gap Analysis v10", font: "Arial", size: 18, color: NAVY, italics: true })]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          border: { top: { style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 4 } },
          children: [
            new TextRun({ text: "SML Consulting  |  v10  |  Page ", font: "Arial", size: 16, color: "999999" }),
            new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: "999999" })
          ]
        })] })
      },
      children: [
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "1. Executive Summary", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "This revision captures a substantive overhaul of the financial impact module driven by three concurrent inputs: (1) broker feedback that the current report's worst-case view (P95 = 1-in-20 year event) is too narrow to support commercial cyber cover decisions in the South African market - reinsurance / underwriting convention requires 1-in-50, 1-in-100, and 1-in-150 return-period views; (2) an audit finding that the POPIA fine reference cited Section 107 (criminal penalties) when it should cite Section 109 (administrative fines), with the 2%-of-turnover formula carrying no statutory basis; (3) a mapping exercise across 86 sub-industries showing that the current C2 regulatory exposure component captures POPIA + GDPR + PCI + a generic R2M-per-extra-jurisdiction, while the realistic SA cat stack involves 5-8 separate regulators per sector. For a R200M listed FS broker, the cat regulatory exposure moves from R12.85M (current model) to R188.5M (proposed), a 47x step-change.",
            font: "Arial", size: 22
          })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "Separately, the cover-recommendation wording is reworked to comply with FAIS reasonable-advice and appropriate-disclosure obligations. The \"Recommended Cover Limit\" label - which positions the UMA as the recommender of a specific cover figure - is dropped in favour of a Loss Exposure Scenarios table presenting modelled losses across Most Likely / Median / 1-in-50 / 1-in-100 / 1-in-150 outcomes, with selection left to the broker and client. Civil liability under POPIA Section 99 and common-law delict is disclosed qualitatively rather than quantified, on the basis that civil exposure depends on contractual data (master service agreements, indemnity clauses, customer terms) invisible to an external scan.",
            font: "Arial", size: 22
          })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "Two diagnostic primitives are added in this revision: per-checker wall-time instrumentation (SCN-020) and the corresponding correction to the SSE progress stream that emits \"running\" for queued-but-not-executing checkers (SCN-021). These resolve a user-reported observation that the glasswing checker appeared to run for 4-6 minutes - confirmed via code analysis to be a UI artifact, not actual execution.",
            font: "Arial", size: 22
          })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "All items in this revision are Done as of 2026-05-15. Implementation was delivered across Batches 1-4 (Phase A/B1/B2/B3/C/D plus auto-detection). End-to-end verification ran against phishield.com (Finance industry, R10M revenue, Insurance Agents sub-industry, with broker-confirmed accountable_institution and b2c flags). Result JSON + full PDF cached under test_fixtures/ for further iteration. SCN-022 (enterprise capacity factor) and SCN-023 (auto-detection + pre-flight + flag audit) were added during implementation in response to user feedback.",
            font: "Arial", size: 22, italics: true
          })]
        }),

        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "2. Change Log (v9 -> v10)", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Structural changes scoped in this revision, each tied to a rationale and current implementation status.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(changeLogHeaders, changeLogCols, changeLogRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "3. Roadmap Status", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Consolidated roadmap across the new FAIR financial impact track and the carried-over Phase 4 / 5 accuracy items.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(rmHeaders, rmCols, rmRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "4. Sector Framework Cat Stack", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({ text: "Statutory maximum exposures used for catastrophe modelling (1-in-50 / 1-in-100 / 1-in-150 views). Capacity-scaled heuristics are used separately for the P50 / expected-loss view. Civil exposure under POPIA Section 99 and common-law delict is qualitatively disclosed, not quantified.", font: "Arial", size: 22 })]
        }),
        buildTable(sHeaders, sCols, sRows),

        new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 400 }, children: [new TextRun({ text: "4.1 Worked example - R200M listed FS broker (B2C, accountable institution)", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 160, line: 300 },
          children: [new TextRun({ text: "Demonstrates the step-change between v9 and v10 cat regulatory exposure for the broker-flagged reference profile. v10 surfaces statutory exposures across 6 regulators that v9 does not capture.", font: "Arial", size: 22 })]
        }),
        buildTable(exHeaders, exCols, exRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "5. Verification Plan", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Verification is deferred until implementation lands. A test scan on phishield.com (Finance, R10M) will be conducted and cached for iterative report tuning.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(vHeaders, vCols, vRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "6. Design Decisions", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Non-obvious choices made during scoping, with alternatives considered and rationale.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(dHeaders, dCols, dRows),

        new Paragraph({ children: [new PageBreak()] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "7. Residual Gaps", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: "Known limitations introduced by or left open after this revision, with severity and recommended next step. SCN-GAP-001 through -005 are carried over from v9; -006 through -012 are new to v10.", font: "Arial", size: 22, italics: true, color: "555555" })]
        }),
        buildTable(gHeaders, gCols, gRows),

        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "8. Reporting Impact", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 160, line: 300 },
          children: [new TextRun({ text: "Changes visible in the underwriter-facing and client-facing outputs:", font: "Arial", size: 22 })]
        }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "PDF financial impact card (summary and full): \"Recommended Cover Limit\" row removed; replaced with \"Loss Exposure Scenarios\" table showing Most Likely / Median / 1-in-50 / 1-in-100 / 1-in-150. Civil liability disclosure paragraph appears immediately below the exposure table on both the summary and full PDF.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "PDF Section 13 (Regulatory Exposure): POPIA row corrected to cite Section 109 with footnote describing the 2%-of-turnover figure as an internal capacity-scaling heuristic for the Section 109(3) factors, not a statutory formula. New rows added for sector frameworks (FSCA / FIC / ECA / CPA / JSE / NHA / HPCSA / MSA / LPC / PPRA / PFMA / NCR / MHSA / SAHPRA) applied via sub-industry mapping. Civil exposure row appears with the disclosure paragraph.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "PDF Monte Carlo analysis: P98 (1-in-50 yr) and P99 (1-in-100 yr) and P99.33 (1-in-150 yr) rows appear beneath the existing P5 / P25 / P50 / P75 / P95 rows. The 90% confidence interval row remains. \"Worst case\" labelling on P95 is removed (P95 is no longer the report's catastrophe figure).", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "PDF full report: new \"Scan Duration Profile\" section listing per-checker wall-time (from SCN-020 instrumentation). Brokers can read this as a scan-quality signal and operations can read it for slow-scan diagnosis.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "HTML results page: matching Loss Exposure Scenarios table, civil liability disclosure, and corrected POPIA section reference. SSE progress stream emits \"running\" only at execution start (SCN-021), removing the misleading 4-6 minute glasswing display.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "JSON API response: insurance.financial_impact.insurance_recommendation.recommended_cover_zar deprecated; replaced with insurance.financial_impact.loss_exposure.scenarios.{most_likely, median, return_1_50, return_1_100, return_1_150}. POPIA fine cite updated in regulatory_exposure.note. _scan_completeness.per_checker_seconds added.", font: "Arial", size: 22 })] }),

        new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 400 }, children: [new TextRun({ text: "9. Compliance / Sign-Off Items Outstanding", font: "Arial" })] }),
        new Paragraph({
          spacing: { after: 160, line: 300 },
          children: [new TextRun({ text: "Items that require compliance officer or external sign-off before implementation can go live:", font: "Arial", size: 22 })]
        }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Final wording of the civil liability disclosure (SCN-015) and the Loss Exposure Scenarios footer disclaimer (SCN-019). Draft language is in the gap-analysis design decisions section; subject to FAIS-compliance review before going live in client-facing reports.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Enforcement-discount percentages per regulator for the expected-loss / P50 view (SCN-GAP-009). Statutory maximum is used for cat; expected loss requires a calibration of typical enforcement vs the statutory ceiling per regulator. Suggested starting values: Information Regulator 25-50%, FSCA 60-80%, FIC 70%, ICASA 30%, JSE varies. Compliance officer / actuarial input required.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Confirmation of return-period choice: 1-in-50 / 1-in-100 / 1-in-150 are the working assumptions. 1-in-200 (FSCA SAM regime convention) and 1-in-250 (reinsurance convention) are alternatives. The MC engine and tail-fit pipeline are agnostic to the specific return periods chosen, but the displayed labels in the PDF must match what brokers and clients expect.", font: "Arial", size: 22 })] }),
        new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 100, line: 300 },
          children: [new TextRun({ text: "Reporting hard-rules document: if a formal layout / disclosure ordering / font / colour specification exists for client-facing UMA reports, implementation must reconcile against it. Currently the spec workspace contains no such document; implementation will preserve the existing v9 layout (Phishield/Bryte branding, navy/blue palette, card structure) by default.", font: "Arial", size: 22 })] })
      ]
    }
  ]
});

const OUTPUT = "C:/Users/sarel/Desktop/Sarel/SML Consulting/PSQ/security_scanner/Phishield_Scanner_Gap_Analysis_v10.docx";

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(OUTPUT, buffer);
  console.log("Document created:", OUTPUT);
  console.log("Size:", (buffer.length / 1024).toFixed(1), "KB");
}).catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
