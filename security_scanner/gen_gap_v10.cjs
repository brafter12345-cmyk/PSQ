const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat, TableLayoutType
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
  return new Table({ width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: colWidths, layout: TableLayoutType.FIXED, rows: [headerRow, ...dataRows] });
}

// --- Change Log (v9 -> v10) ---
const changeLogCols = [1300, 1100, 2500, 2500, 1626];
const changeLogHeaders = ["Date", "Change ID", "Description", "Rationale", "Status"];
const changeLogRows = [
  [
    "2026-05-14", "SCN-014",
    "POPIA section reference corrected from Section 107 to Section 109 in code comments, Section 13 PDF generator, and PDF output text. Methodology footnote added clarifying that the 2%-of-turnover formula is an internal capacity-scaling heuristic for the Section 109(3) factors (nature, duration, extent, number of subjects, public importance, prevention, risk assessment, prior offences) and not a statutory formula.",
    "Audit finding (2026-05-14). Section 107 is criminal penalties (R10M fine OR 10 years jail OR both). Administrative fines from the Information Regulator come from Section 109. The 2% formula has no statutory basis in POPIA; Section 109 is a flat R10M ceiling. Fix is required before report can be relied on for FAIS disclosure purposes.",
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
  ],
  [
    "2026-05-16", "SCN-028",
    "Peer benchmarking subsystem: percentile-rank + 1.0-10.0 peer rating vs same-industry / same-revenue-band reference scans. New peer\\_benchmarking.py module with revenue bands (micro/small/medium/large/major), cell fallback (industry+sub+band -> industry+sub -> industry+band -> industry -> global), and Hero+comparison card rendering in PDF + HTML. New benchmark\\_scans table in scans.db with source tagging (benchmark\\_pool / lower\\_tier\\_upsell / client\\_optin). New benchmark\\_runner.py CLI with curated SA reference seed list (~60 entries covering Finance, Healthcare, Communications, Retail, Manufacturing, Mining, Technology, Transportation, Services, Public Sector). Hero metric replacing compliance %: 'Critical Findings count' - cross-checker aggregate (shodan critical CVEs + KEV, exposed\\_admin critical paths, high\\_risk\\_protocols critical ports, info\\_disclosure critical files, SSL F-grade / expired cert, Dehashed plaintext passwords, Hudson Rock infostealer hits, external\\_ips zero-scored IPs). Pool composition disclosed in the comparison card so brokers see what the benchmark draws from. Rollout plan: Phase 1 (benchmark\\_pool, bi-weekly public reference scans) runs from launch onwards; Phase 2 (lower\\_tier\\_upsell, ~4,000 existing Phishield clients) batches from 1 Jul 2026 over 6-9 months at ~25-30/day; Phase 3 (client\\_optin, broker-paid scans with explicit consent) opens whenever broker-side opt-in plumbing is added. The 4,000-cohort drives premier-tier upsell as primary purpose; benchmark contribution is the secondary effect.",
    "User request 2026-05-16: 'we need some sort of peer benchmarking as part of the output reports - to give the scanned client an indication of how peers of theirs are rating at'. Architectural decisions: (1) derive 1-10 peer rating from existing 0-1000 risk score percentile rank rather than introducing a third independent scale (single source of truth, existing remediation roadmap intact); (2) build own benchmark\\_scans table because no third-party API has SA-granular peer data per SIC sub-industry + revenue band; (3) bi-weekly refresh cadence (matches industry passive-scanner pattern); (4) curated SA reference seed list of ~60 public-domain companies covering top JSE-listed + mid-market; (5) the existing 4,000-client lower-tier cohort tagged source='lower\\_tier\\_upsell' enriches the pool over time (Phishield owns the relationship, no broker intermediation, no consent needed); (6) broker-paid scans contribute only with explicit opt-in (source='client\\_optin', default off); (7) compliance % removed from hero in favour of Critical Findings count - compliance % was misleading because external scans only verify ~10 of ~250 PCI sub-requirements (similar gap for POPIA s19). Quality-control caveats on the 4,000-cohort: selection bias (insurance-aware businesses), sector skew (uneven industry weighting), risk-aware self-selection (lower-tier buyers may already have above-average posture). Pool composition disclosure in every report makes these visible so brokers can weight the comparison.",
    "Done 2026-05-16"
  ],
  [
    "2026-05-16", "SCN-027",
    "Cat Modelling Validity Notice (records-based). Surfaces the industry-typical record-holding assumption built into the IBM SA breach anchor, AND the per-industry validity ceiling above which the IBM-anchored cat exposure no longer represents realistic worst-case loss. Architecture clarification: the breach cost component (C1) is the residual after subtracting C2 + C3 + C4 + C5 from the IBM SA total breach anchor - records-per-revenue is NOT used in the cost calculation. The records heuristic is now positioned as transparency about the assumed scale (industry-aware divisor: finance R5-7.5k, healthcare R9k, telecoms R5k, retail R30k, manufacturing R500k, agriculture R1M, etc.) and to anchor a per-industry validity ceiling: 500,000 records for high-anchor industries (Finance, Healthcare 400K, Public Sector / Tech / Pharma 300K), 250,000 for mid-anchor industries (Insurance, Retail, Services, Education, Communications), 100,000-150,000 for low-anchor industries (Manufacturing, Construction, Transportation, Energy), 50,000 for Agriculture. Above the ceiling, the cat figures are flagged as a 'FLOOR estimate only' and the broker is directed to request bespoke actuarial review.",
    "User clarification 2026-05-16: the previous SCN-027 framing incorrectly described breach cost as (records x cost\\_per\\_record). That is not how the current model works - breach cost is the residual after C2/C3/C4/C5 are subtracted from the IBM anchor. The records heuristic is useful for cat modelling DISCLOSURES (showing the broker what scale the IBM anchor assumes, and flagging when actual holdings exceed the IBM regression's calibration window). Above the per-industry ceiling, several cost components scale super-linearly outside the IBM calibration: POPIA s22 breach-notification (per-subject), POPIA s99 civil exposure (uncapped per subject), Information Regulator s109(3) 'extent and number of subjects' factor pushing fines toward statutory maxima, and forensic / IR scope growing non-linearly. FAIS appropriate-disclosure compliance: the report must transparently say 'these cat numbers are only reliable up to N records for this industry' so the broker knows when bespoke review is required.",
    "Done 2026-05-16"
  ],
  [
    "2026-05-18", "SCN-029",
    "WAF blind-spot coverage adjustment in the financial model. Previously a WAF / bot-manager that blocked the path-prober checkers (exposed\\_admin, info\\_disclosure, tech\\_stack, website\\_security, http\\_headers) caused those checkers to return status 'completed' with empty findings, which the score and FAIR model read as genuinely clean - depressing RSI / DBI / category risk and therefore the modelled loss, while the report simultaneously printed a Partial Coverage Notice the numbers did not honour. Now scan\\_completeness (waf\\_status + coverage\\_pct + waf\\_affected\\_checkers) is threaded scanner.py -> RiskScorer and scanner.py -> FinancialImpactCalculator -> \\_calculate\\_zar. When the WAF actively blinded the scan (waf\\_blocked / waf\\_challenge / waf\\_timeout) the Monte Carlo right tail (P75-P99.6: the 1-in-100 / 1-in-200 / 1-in-250 and P95 catastrophe views) is widened in proportion to the coverage shortfall (K\\_TAIL=1.20); mode, median, analytical most-likely and the suggested deductible / cover figures are restored from the pre-widening distribution. The flat -50 WAF overall-score bonus is halved to -25 on a blinded scan. financial\\_impact.coverage\\_adjustment exposes the numeric basis (waf\\_kind, coverage\\_pct, coverage\\_shortfall, tail\\_inflation\\_factor, affected checkers) and a one-paragraph 'Coverage-adjusted tail' disclosure is rendered in the Loss Exposure Scenarios section of the full + summary PDF and the HTML dashboard. Rate-limiting alone (waf\\_rate\\_limited - still returns data) does not trigger the adjustment. Bundled report-presentation changes: rand values made non-breaking everywhere (atomic-value rule #6), per-scenario card grid made responsive, the redundant per-scenario Monte Carlo sub-block collapsed (triple-disclosure removed), and the orphaned Civil Liability Disclosure heading bonded to its body via KeepTogether.",
    "Identified 2026-05-18: user asked how WAF block detection (SCN-025) feeds the financial model. Code trace showed the WAFTracker signal was presentation-only - it drove the Partial Coverage Notice but was never ingested by RiskScorer or FinancialImpactCalculator. A blocked path-prober returning 'no finding' is statistically downside-only: the hidden finding can only increase loss, never reduce it. The defensible correction is a model-uncertainty loading on the catastrophe tail, NOT a shift of the central estimate (expected loss must not be pulled down, and FAIS cover advice must not change), and to stop double-crediting the WAF (once for the genuine web-layer control, once for the blindness artefact). Verified on the R10M finance fixture: at 63% coverage the 1-in-100 / 1-in-200 / 1-in-250 widened ~28-29% and P95 / CI-upper ~23%, while most-likely / median / mode / recommended cover were byte-identical to the unblinded baseline; the waf\\_rate\\_limited kind correctly produced no adjustment.",
    "Done 2026-05-18"
  ],
  [
    "2026-06-11", "SCN-030",
    "Operational self-protection hardening of the scanner web application. (1) SSRF guard: client-supplied IPs are now restricted to publicly routable addresses (RFC1918, loopback, link-local, CGNAT and multicast rejected and echoed back to the caller), capped at 25 per scan. (2) Bounded scan-slot wait: a queued scan now fails visibly (database row marked failed plus an SSE error event) when no semaphore slot frees within SCAN_QUEUE_TIMEOUT_S (default 15 minutes) instead of queueing forever behind a hung scan. (3) SSE progress queues leaked by abrupt browser disconnects are swept after a 2-hour TTL. (4) Scans stranded in 'pending' by a service restart are expired to failed on the next status poll (45-minute threshold). (5) Every results blob now carries a schema_version field for forward-compatible deserialisation. (6) Opt-in shared-secret API authentication (X-Api-Key, active only when SCANNER_API_KEY is set) plus dependency-free per-IP rate limiting on the scan, preflight, credential-export and balance endpoints. (7) Per-tier PDF caching keyed by scan id, with the report-type parameter whitelisted. New pre-deploy gate tooling/verify_app_hardening.py asserts all of the above through the Flask test client (18 checks).",
    "Operational risk review (2026-06-11): the analytical model was materially stronger than the application shell around it. The scan endpoints had no authentication or rate limiting; internal addresses supplied via client_ips would be port-scanned (a latent SSRF once the scanner moves onto infrastructure with internal routing); a single hung scan could silently queue every later scan; dyno restarts stranded scans in a permanently pending state; and orphaned SSE queues accumulated in memory. All seven fixes are backward-compatible: authentication is off until the environment variable is set on Render and the matching header is added to the frontend.",
    "Done 2026-06-11"
  ],
  [
    "2026-06-11", "SCN-031",
    "Report integrity and maintainability wave. (1) Single rand-savings authority: the RSI remediation roadmap card no longer quotes rand savings (it now shows per-step RSI deltas); the expected-loss mitigation card is the only rand-savings view, removing the broker-visible contradiction of two adjacent cards quoting R2.01M and R2.70M for the same fixes. (2) All report identity strings (header, FSP footer, contact block, disclaimer, invoice branding) now flow through brand_assets/brand.json in every tier; re-branding is a JSON edit. (3) Checks that do not run (origin discovery, broker-declared related domains, third-party JavaScript) now render muted 'Not assessed' cards stating the reason, so an underwriter can distinguish 'assessed, no findings' from 'not checked'. (4) Curated intelligence tables (EOL signatures, port and service intel, ransomware CVE map, ATT&CK map, takeover fingerprints, stealer tokens, CVE narratives) all carry review-by markers, and an overdue marker now fails the wiring gate instead of warning. (5) Duplicated CMS signature tables consolidated to one shared module-level table. (6) pdf_report.py (6,500 lines) split into pdf_data / pdf_helpers / pdf_cards / pdf_report (orchestrator), proven behaviour-identical by a new PDF snapshot guard (tooling/pdf_snapshot.py, 6 fixture-tier hashes byte-identical). (7) Pre-push git hook runs the fast gates on every push and the live smoke test on master pushes; the smoke test gained hard production-shape assertions (schema_version present, overall-score coupling intact, Monte Carlo p50 positive, risk_probability block present). (8) Archive sweep: 75 one-shot tooling scripts, the superseded v1 sensitivity chain, gap-analysis v9 generator and the abandoned _spec_workspace moved to _archive folders; BACKTEST and RETEST findings documents now carry status banners marking fixed items as fixed.",
    "Pre-launch maintainability review (2026-06-11): the dual remediation totals were a direct credibility risk in front of brokers; hardcoded identity strings made re-branding a code change; silently absent cards read as clean passes; hand-maintained intelligence tables had no enforcement against rot (review-by markers existed on only three tables and never failed the gate); and the 6,500-line PDF module concentrated change risk. The snapshot guard plus the pre-push hook make both the refactor and all future deploys verifiable by construction. The stale findings documents had already misled one automated review into reporting fixed bugs as open.",
    "Done 2026-06-11"
  ],
  [
    "2026-06-30", "SCN-032",
    "Production scan-crash fix: Python 3.10 futures-timeout handling. scanner.py guarded its as_completed(timeout=180) phase loops with a bare except TimeoutError (the builtin). On the production VM's Python 3.10 the builtin and concurrent.futures.TimeoutError are distinct classes, so a phase that exceeded 180 seconds (takealot: 68 IPs feeding 272 IP-checker futures) raised the futures timeout, went uncaught, and crashed the whole scan with no output. Fixed to catch the futures class at scanner.py lines 557, 675 and 747. New blocking gate tooling/verify_scan_timeout_handling.py audits every as_completed(timeout=) loop in scanner.py and the four checker modules and fails on a bare except TimeoutError.",
    "The development environment runs Python 3.12, where the two timeout classes are aliased, so the crash never reproduced locally and the golden replay never reaches the timeout path. The bug surfaced only on the 3.10 VM against a large real target. The AST gate closes the blind spot for every current and future as_completed loop.",
    "Done 2026-06-30"
  ],
  [
    "2026-06-30", "SCN-033",
    "IP attribution by host operator. The port, protocol and CVE checkers received candidate IPs from four sources, but only verified-origin candidates were ever classified. Apex A-records and subdomain-resolved IPs went in raw, so as subdomain discovery widened, third-party hosts (CloudFront and Akamai edges, Zendesk and Salesforce SaaS, a HostRocket shared host carrying FTP and a phantom exposed-notebook critical) and RFC1918 internal hosts leaked in public DNS were scanned and attributed as the insured's own exposure. New ip_classification.py classify_ip(ip, reverse_dns, org, banner) returns one of four buckets (owned, private, cdn, saas); reverse-DNS is strongest, and the banner is checked before the IaaS reverse-DNS rule so a managed AWS load balancer is not mistaken for an insured EC2 VM. scanner.py runs two passes: a pre-scan chokepoint (PTR and RFC1918 only) and a post-scan Phase 3b re-classification once banners and Shodan org are available, which re-homes vendor IPs out of per_ip_results. Only owned IPs are scanned and attributed.",
    "Broker-confirmed policy: insured-operated infrastructure (dedicated IPs, verified origins, the insured's own IaaS VMs) is owned and scanned; vendor-operated infrastructure (CDN, managed SaaS, shared hosting, managed load balancers) is supply-chain and not scanned; RFC1918 is an internal DNS leak and never scanned. On the takealot ground-truth scan this moved owned hosts from 68 to 25, removed one phantom critical, and re-homed 39 hosts to supply-chain and 4 to internal-DNS-leak. Locked by 12 IP-attribution scenarios in the adversarial gate.",
    "Done 2026-06-30"
  ],
  [
    "2026-07-01", "SCN-034",
    "CVE-to-software gating plus version-unconfirmed disclosure. notable_cves were templated from the open port and ignored the detected_version banner, so a Pure-FTPd service on port 21 was tagged with ProFTPD CVEs; the intelligence table also carried two wrong-software errors (a Sudo CVE on SMTP and a Postfix CVE on POP3, both removed). Each PORT_INTEL and SERVICE_INTEL entry now carries a cve_software tag; _assess_risk drops the templated CVEs when the banner names a different product and otherwise keeps them, tagging cve_confidence as software_match, port_inferred or potential. The dashboard gates the KEV badge on surviving CVEs, marks port-template CVEs versionConfirmed false, adds a potentialCount, and renders a 'potential, version unconfirmed' disclaimer in the vulnerabilities page and the PDF.",
    "Conservative by design: a possibly-real CVE is never hidden, only flagged as version-unconfirmed, which is the broker's explicit call. This stops a suppressed port from showing a KEV badge with zero CVEs and stops wrong-software CVEs from inflating the vulnerability picture. All CVEs were re-checked against NVD. Guarded by 8 CVE-gating scenarios plus 2 data-error guards in the adversarial gate.",
    "Done 2026-07-01"
  ],
  [
    "2026-07-01", "SCN-035",
    "Golden and live scoring paths unified. The golden regression re-scored frozen fixtures through a hand-rolled duplicate of the Phase 5 and Phase 6 calculator sequence, called with different arguments than the live scanner (RSI on an unresolved revenue; dropped WAF, regulatory, records and scan-completeness inputs), so it gated a different code path than production. New scoring_pipeline.py is the single source of truth exposing apply_risk_score (Phase 5) and apply_insurance_analytics (Phase 6); both scanner.scan() and the golden rescore now call it, so the replay exercises the exact invocation production runs. Live output is byte-identical before and after (a pure refactor). New blocking gate tooling/verify_scoring_pipeline_unified.py fails if either caller re-inlines a calculator constructor or stops calling the shared entry points.",
    "The drift between the two scoring paths is how an earlier revenue-resolution bug scored green in golden while broken live. A single shared entry point removes the class of bug where the test harness and production diverge. A third independent implementation is retained by design in verify_supply_chain_financial_wiring.py as a defense-in-depth check.",
    "Done 2026-07-01"
  ],
  [
    "2026-07-02", "SCN-036",
    "False-positive and non-determinism hardening wave across the checker modules. (1) TechStackChecker matched its end-of-life server-component table against the full response body, so any incidental version mention (a hosting page, a documentation link, a code sample) invented a phantom EOL critical; it now matches the response headers only. (2) VPNRemoteAccessChecker probed 3389 on the apex with a raw socket and set rdp_exposed on connect without the saturated-host gate, so a tarpit apex fabricated a phantom RDP exposure (the single largest RSI signal); it is now gated on is_saturated_host. (3) DehashedChecker attributed staff accounts with a substring match, counting lookalike and adjacent domains as own-staff; it now uses a label-boundary match. (4) The credential-correlation reporting card labels were corrected to state that it is reporting-only and carries no scoring weight (the RSI-driving credential tier is set separately by CredentialRiskClassifier). (5) Three more checker loops (RelatedDomains, DependencyManifest, CMSPluginSBOM) carried the same bare except TimeoutError as the SCN-032 crash and lost partial results on Python 3.10; these were fixed and the timeout gate was extended to all four checker modules.",
    "The frozen takealot fixture is stale and not reliable ground truth for current code, so the sweep ran white-box against the current source and against the credit-free live HTTP checkers. Every core and network checker now carries a comment documenting its prior false-positive fix. Each fix ships with adversarial scenarios proven to fail without the fix and pass with it.",
    "Done 2026-07-02"
  ],
  [
    "2026-07-02", "SCN-037",
    "Dual-source Certificate Transparency for subdomain enumeration. crt.sh is intermittently slow or returns 502; a single failed fetch dropped enumeration to brute-force only (about 16 versus about 90 subdomains), and a re-scan that lost crt.sh looked like the organisation had shed attack surface when it was pure data loss. SubdomainChecker now queries crt.sh and certspotter (a second keyless CT-log API) in parallel and unions the results; certspotter is fast, so wall-time is unchanged. A low_coverage flag is set only when both CT sources fail, with a broker-facing note that a decrease versus a prior scan is data loss, not remediation.",
    "Deterministic subdomain coverage is a precondition for meaningful scan-to-scan deltas and for refreshing the golden fixture. Proven in production: crt.sh returned zero from both the development box and the VM this session while certspotter returned 47, so the union held at 47 versus 16 brute-only. Guarded by 4 subdomain-CT scenarios in the adversarial gate.",
    "Done 2026-07-02"
  ],
  [
    "2026-07-01", "SCN-038",
    "Production moved to a dedicated Google Cloud VM. The broker-facing deployment is now veilguard.phishield.com/scanner on a GCP n2-standard-8 instance (project rugged-sunbeam, zone africa-south1-a), replacing the Render free tier. Deployment is by tarball plus an idempotent deploy script, with the VM contents verified against the repository by sha256. The Render free-tier deployment is retained as a legacy endpoint during the transition and is being retired.",
    "The Render free tier constrained the scanner to a 512 MB build and a non-persistent worker. The dedicated VM removes both limits (ample memory for the scipy tail-fit and a persistent worker for the planned continuous-monitoring scheduler) and gives a stable broker-facing URL.",
    "Done 2026-07-01"
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
  ["4c", "CDN origin IP leakage", "Partial (origin_discovery.py, 2026-05-29)", "SecurityTrails historical-DNS candidates with TLS certificate-match verification are live; verified origins are scanned and candidates surfaced. Free Shodan certificate-host count hint live. Full Shodan certificate-search IP retrieval awaits a paid key (see OUTSTANDING.md section 2 go-live steps)."],
  ["4d", "MFA presence on VPN login pages", "Open", "Carried over from v9."],
  ["4e", "WAF rate limiting / bot protection detection", "Open", "Carried over from v9."],
  ["4f", "DNSSEC validation chain", "Done (Phase 0, 2026-05-27)", "DNSKEY presence query wired in DNSInfrastructureChecker as part of the 9-ghost remedial sweep. Apex DNSKEY = signed zone; DS chain validation deferred (rare in practice, requires walking parent NS). Remediation step in REMEDIATION_MAP now fires only on absent signing."],
  ["SC-1", "Supply-chain: Related Domains (broker-declared)", "Done v1.0 (2026-05-27)", "RelatedDomainsChecker scans declared sibling domains in LITE mode (SSL + DNS ports + info_disclosure). Worst-of-N feeds RSI (+0.03) and financial-impact vulnerability uplift (civil-liability inflator +0.04). v1.1 auto-discovery via cert SAN / WHOIS / analytics-ID deferred."],
  ["SC-2", "Supply-chain: Third-Party JavaScript", "Done (2026-05-27)", "ThirdPartyJSChecker parses homepage script tags, tracks SRI coverage, flags known-compromised CDNs (polyfill.io 2024, bootcss 2018). Magecart channel: contributes RSI +0.05 and vuln uplift +0.06 (largest of the three central-tendency drivers). Anchor: Polyfill.io 2024 = 100,000+ sites compromised."],
  ["SC-3", "Supply-chain: Exposed Dependency Manifests", "Done (2026-05-27)", "DependencyManifestChecker probes 15 manifest paths across Node, PHP, Python, Ruby, Go, Rust, Java. Lockfiles classified critical (exact pinned versions -> OSV chain); manifests classified high (SemVer ranges only). Contributes up to +0.04 RSI raw."],
  ["SC-4", "Supply-chain: Email-Vendor Surface (SPF + DMARC)", "Done (2026-05-27)", "EmailVendorSurfaceChecker walks the SPF include: chain depth-5 and classifies against 24 vendor patterns. Cross-references DMARC policy. CISA BOD 18-01 cohort: DMARC p=reject drops phishing inbox success 69% -> 14%. Contributes up to +0.02 RSI raw when weak DMARC + >=1 vendor."],
  ["SC-5", "Supply-chain: Vendor Breach Correlation", "Done (2026-05-27)", "VendorBreachChecker + curated vendor_breaches.json (11 confirmed incidents across 7 vendors: Mailchimp, Okta, MS365, HubSpot, Salesforce, Intercom, Zendesk). 5-year lookback with linear age-decay; rows age out as they leave the window (Marketo pruned 2026-06). Feeds the FinancialImpactCalculator supply-chain vulnerability uplift (+0.04 on a critical vendor-breach match, within the +0.15 supply-chain cap), which raises p_breach before the Monte Carlo so the modelled distribution and its tail move together; there is no separate catastrophe-tail widening (the earlier K_TAIL_SC was removed as double-counting, see FIN-8). Empirical anchors: MOVEit 2700+ orgs, Storm-0558, Mailchimp 0ktapus cluster."],
  ["SC-10", "Supply-chain: CMS Plugin Surface (WordPress)", "Done (2026-05-27)", "CMSPluginSBOMChecker enumerates 25 popular plugin slugs and harvests versions from readme.txt 'Stable tag:'. WordPress-only (cheap discriminator via /wp-content/). Patchstack 2024: 96% of WP CVEs are in plugins, 11.6% actively exploited. Largest single RSI factor among supply-chain (up to +0.04, scaling with the number of readable plugin versions) reflecting Sophos SA 2024 ransomware vector dominance."],
  ["FIN-7", "Supply-chain wiring into RSI / financial impact / remediation", "Done (2026-05-27)", "All 6 supply-chain checkers wired into RansomwareIndex factors and FinancialImpactCalculator vulnerability uplift (cap +0.15, mid of empirical +15-30pp Ponemon-aligned band). Six new REMEDIATION_MAP rows. Empirically calibrated against IBM CoDB 2024 (supply-chain as initial attack vector = 12% of breaches), Verizon DBIR 2025 (third-party involvement 30%, doubled YoY), Mandiant M-Trends 2025 (supply-chain compromise 3% strict), Patchstack 2024 (96% of WP CVEs in plugins, 11.6% exploited), CISA BOD 18-01 (DMARC p=reject 69% -> 14% phishing inbox), Sophos State of Ransomware SA 2024. SUPPLY_CHAIN_CAP = 0.22 raw RSI (vs RDP single signal +0.25). Verification: tooling/verify_supply_chain_financial_wiring.py (30/30 PASS)."],
  ["FIN-8", "Cat-tail K_TAIL_SC removed (no double-counting)", "Done (2026-05-27 design review)", "Earlier iteration applied a separate K_TAIL_SC widening to the catastrophe percentiles (P75-P99.6) on top of the vulnerability uplift, double-counting the same supply-chain signal. User caught it: 'cat events already capture worst case'. Removed. Supply-chain effect now flows through vulnerability uplift only; the MC distribution shifts up naturally and the tail moves with it. Conditional LGB widening (raise sigma of loss-given-breach when sampled initial vector = supply-chain, anchored to MOVEit per-org Pareto distribution where top 1% absorbed 60-70% of total loss) is the empirically correct next refinement, deferred to FIN-9. WAF blind-spot K_TAIL retained because it represents EPISTEMIC uncertainty (unobserved findings), which cannot flow through p_breach."],
  ["FIN-9", "Conditional LGB widening for supply-chain initial vector", "Retired (2026-06-04 calibration session)", "The Pareto mixture-widening approach was retired at the 2026-06-03/04 calibration session in favour of the records-driven catastrophe redesign (records-driven cat-C1, compound loss-given-event return-period tail, systemic supply-chain disclosure). Specification and decision record: calibration_prep/07_WIRING_SPEC_AND_HANDOFF.md section 7. The original research artefacts (MOVEit Pareto fit alpha=1.35 CI[0.97,2.04]) remain available for reference."],
  ["AUDIT-1", "Three-axis Q&A parameter audit (post supply-chain)", "Done (2026-05-27)", "Spawned 3 parallel Explore agents covering checker modules / scoring model / API+env+manifest. 45 raw findings; cross-verified each before fixing. 5 real bugs fixed: (1) okta in vendor_breaches.json had no VENDOR_PATTERNS entry, dead correlation data; added okta.com/oktapreview.com/okta.net; (2) CHECKER_MANIFEST had insurance_analytics as a fake checker and was missing osv_vulns/external_ips/credential_risk, fixed; (3) SubdomainChecker takeover cap was 60 but CT discovery cap is 150, silently dropped ≥90 candidates from the most critical follow-up check, raised to 150; (4) 5 real checkers had WEIGHTS but no REMEDIATION_MAP row (payment_security, securitytrails, subdomains, virustotal, web_ranking), added 5 rows; (5) WEIGHTS sum = 1.32 not 1.0, doc was misleading, fixed the docstring. 2 false alarms documented; 8 items deferred to v1.2 polish (mostly externalisation / formal-parameter refactors). See memory: project_scanner_audit_findings_2026-05-27.md."],
  ["CRED-CORR-1", "Hudson Rock × S-4 × S-5 cross-correlation (Phase 4f): reporting-only", "Done (2026-05-27)", "Joins three independent risk signals: Hudson Rock infostealer harvest count + S-4 SPF vendor surface + S-5 known-breach DB. When all three align (critical triple-match), the intersection is the highest-priority rotate-target in the scan. DESIGN DECISION: cross-correlation is reporting-only (NOT in WEIGHTS, not an RSI factor, not a FIC vuln uplift, not in REMEDIATION_MAP); the underlying signals it joins (credential_risk via Hudson Rock, S-4 email_vendor_surface, S-5 vendor_breach) ALREADY contribute to scoring through their own channels. Adding a separate weight would double-count the same data without empirical justification (no public evidence that the correlation itself increases breach cost beyond what each individual signal already drives). The correlation's value is QUALITATIVE: tell the broker which specific vendors to rotate at, with confidence backed by three independent sources. Surfaced in ALL six broker-facing outputs (HTML cat-card + recommendations panel, PDF body cat_third_party_correlation, PDF Broker Summary spotlight row, PDF Executive Deck slide 4 (7th card), Executive Deck slide 7 Next Steps promoted to Step 1 on critical, JSON API category). Soft-correlation only (Hudson Rock free endpoint returns counts not per-vendor names); v1.2 to fetch richer per-vendor data from cavalier url-search-by-domain endpoint to tighten attribution. Verification: 31/31 PASS on extended verify_supply_chain_financial_wiring.py (smoke-test asserts category presence; no scoring movement asserted by design)."],
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
  ["Cont-1", "Continuous monitoring scheduler", "Open", "Hourly / daily rescan capability. Requires SCN-026 cache implementation + per-tenant scheduler + delta-finding detection + alert-on-change pipeline. Estimated 3-4 week build."],
  ["AUDIT-2", "Checker ground-truth audit (arc #1 to #7)", "Done (SCN-032 to SCN-038, 2026-07-03)", "White-box sweep of every checker module against current code and the credit-free live HTTP checkers, after a real takealot scan exposed attribution and false-positive gaps the frozen fixture never caught. Covers IP own-vs-vendor attribution (ip_classification.py), CVE-to-software gating, the golden-live scoring unify (scoring_pipeline.py), seven false-positive and non-determinism fixes, and dual-source CT enumeration. Locked by tooling/regression/adversarial_gate.py (40 ground-truth scenarios) plus verify_scan_timeout_handling.py and verify_scoring_pipeline_unified.py in the pre-push gate."],
  ["DEPLOY-1", "Google Cloud VM production deployment", "Done (SCN-038, 2026-07-01)", "Broker-facing deployment is veilguard.phishield.com/scanner on a GCP n2-standard-8 VM (project rugged-sunbeam, zone africa-south1-a). Tarball deploy with sha256 verification of the VM against the repository. The Render free tier is retained as a legacy endpoint during the transition and is being retired."]
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
  ["SCN-GAP-002", "Timeout guards orphan threads if sslyze hangs", "Low", "Now on a persistent GCP VM worker (was the Render free tier), so this is live rather than hypothetical; explicit subprocess teardown still not wired", "Add an explicit subprocess kill on sslyze timeout now that the worker is persistent."],
  ["SCN-GAP-003", "DNS cache per-scan only", "Low", "Cleared at scan start", "Extend to 24h TTL keyed by (domain, rtype) for continuous monitoring."],
  ["SCN-GAP-004", "SPF/DMARC/MX lookups not routed through cache", "Low", "Defer to next batch", "Extend cache to return raw rdata or refactor checkers."],
  ["SCN-GAP-005", "No AI Threat Readiness Tier 2 (self-reported)", "Medium", "Glasswing is only AI signal", "Add scan-time questionnaire."],
  ["SCN-GAP-006", "Sample density at long return periods", "Medium", "10k MC iterations yields only 40-100 samples beyond P99; SCN-016 Phase 3 bumps to 50k", "Verify P99.33 stability via repeat-run dispersion test after 50k bump."],
  ["SCN-GAP-007", "PERT distribution upper bound caps the catastrophe tail", "Medium", "mc_rd / mc_rec / mc_fine PERT high-bound currently 2-3x mode; widened to 5x in SCN-016 Phase 3", "Calibrate against SA empirical catastrophe data (Transnet 2021, Life Healthcare 2020, ransomware-family observations)."],
  ["SCN-GAP-008", "Civil liability quantification not modelled", "Accepted", "POPIA s99 + common-law delict are uncapped and depend on contractual data invisible to external scan", "Disclosure (SCN-015) is the in-scope answer. Quantification would require an internal-data add-on product."],
  ["SCN-GAP-009", "Enforcement-discount calibration per regulator", "Medium", "Statutory maximum used for cat (SCN-017); P50 / expected loss uses capacity-scaled heuristic", "Compliance officer must set the enforcement-discount % per regulator for the expected-loss view. Sector by sector: Information Regulator ~25-50%, FSCA ~60-80%, FIC ~70%, ICASA ~30%, JSE varies. To be determined."],
  ["SCN-GAP-010", "Sub-industry tagger for healthcare specialisation", "Low", "Need to distinguish medical_scheme / pharmacy / pharma / hospital among the SIC 'Health Services' parent category", "Add sub_industry_detail field to scan form for Health Services, defaulting to 'hospital_clinic'."],
  ["SCN-GAP-011", "GPD tail fit dependency on scipy", "Low", "Phase 3 uses scipy.stats.genpareto for 1-in-150 extrapolation", "scipy is a heavy dependency; the GCP n2-standard-8 VM has ample memory, so the 512 MB Render constraint that motivated this gap no longer applies. The PERT-only fallback is retained if the scipy import fails."],
  ["SCN-GAP-012", "UI status premature emission across all concurrent checkers", "Low", "SCN-021 fixes glasswing display; same root cause affects ~14 other checkers", "Same fix automatically corrects the entire concurrent batch (notify at execution start, not at submission). Verification via SCN-020 timing."],
  ["SCN-GAP-013", "Golden fixture (takealot_baseline.json) is stale", "Low", "Carries pre-fix phantom output (exposed_admin 403 criticals, an FTP on 21 on a Cloudflare IP) that current checkers no longer produce; still valid for drift-detection on fixed input but not a realistic current scan", "Re-capture from a fresh real scan (now more deterministic after the dual-source CT change), reviewing the drift before blessing the new baseline."],
  ["SCN-GAP-014", "Certificate Transparency results not cached", "Low", "A transient simultaneous failure of crt.sh and certspotter still drops enumeration to brute-force only; the low_coverage flag surfaces it to the broker", "Add a once-per-domain CT cache with a TTL, backed by the VM Postgres store, to smooth double-failures and aid exact reproducibility."]
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
          children: [new TextRun({ text: "Version 10  |  14 May 2026  |  Revised 3 July 2026  |  SML Consulting", font: "Arial", size: 24, color: "666666" })]
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
            text: "The FAIR financial-impact items in this revision are Done as of 2026-05-15. Implementation was delivered across Batches 1-4 (Phase A/B1/B2/B3/C/D plus auto-detection). End-to-end verification ran against phishield.com (Finance industry, R10M revenue, Insurance Agents sub-industry, with broker-confirmed accountable_institution and b2c flags). Result JSON + full PDF cached under test_fixtures/ for further iteration. SCN-022 (enterprise capacity factor) and SCN-023 (auto-detection + pre-flight + flag audit) were added during implementation in response to user feedback.",
            font: "Arial", size: 22, italics: true
          })]
        }),
        new Paragraph({
          spacing: { after: 200, line: 300 },
          children: [new TextRun({
            text: "Two later waves have since landed and are folded into this revision. An application and maintainability hardening pass (SCN-030, SCN-031; 2026-06-11) added operational self-protection and split the report module behind a snapshot guard. A checker ground-truth audit (SCN-032 through SCN-038; 2026-06-30 to 2026-07-03) then corrected how the scanner attributes IP ownership, gates CVEs against the software actually detected, and unifies the golden and live scoring paths; it also hardened a wave of false-positive and non-determinism classes surfaced by a real production scan. Over the same period the scanner moved from the Render free tier to a dedicated Google Cloud VM at veilguard.phishield.com/scanner, with Render retained as a legacy endpoint during the transition. The audit fixes are locked by tooling/regression/adversarial_gate.py, which reports 40 ground-truth scenarios as of this revision.",
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
          children: [new TextRun({ text: "Known limitations introduced by or left open after this revision, with severity and recommended next step. SCN-GAP-001 through -005 are carried over from v9; -006 through -012 are new to v10; -013 and -014 were added in the 2026-07-03 reconciliation.", font: "Arial", size: 22, italics: true, color: "555555" })]
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
