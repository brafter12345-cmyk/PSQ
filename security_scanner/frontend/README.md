# Phishield CyberRisk Dashboard (frontend)

React + Vite + TypeScript app that renders the **results dashboard** for the
security scanner. It is mounted *inside* the existing Flask app — not a separate
SPA — so every backend route, the PDF pipeline, and the SSE scan-progress stream
are untouched.

## Assessment coverage policy (2026-09-16)

An absent raw checker result is **not assessed**, rather than a clean finding.
The scorer excludes its weight and redistributes it over the remaining signals;
it counts the missing check against completeness. The derived metrics
`ransomware_risk`, `data_breach_index`, and `financial_impact` are exempt from
this missing-probe rule. No weights or measured findings were changed.

The dashboard coverage banner shows score qualification, missing raw checks,
and failed raw checks. Missing checks are not described as WAF blocking.
The PDF summary/full report shows the qualification beside its overall score,
and the assessment deck shows completeness and missing-check count below its KPIs.
Unavailable summary values and KPIs are neutral, not green zeroes.

CMS fingerprinting distinguishes usable non-WordPress evidence from unavailable
probes. A usable homepage and login response without a WordPress fingerprint
produce `skipped` / `confirmed_non_wordpress`. Failed, blocked, or inconclusive
probes produce `unreachable` / `probe_failed`, with unknown WordPress status and
no score. The PDF CMS card and dashboard coverage notice expose this uncertainty.
Historical `skipped` results cannot reveal whether old probes failed; rerunning
the checker is required to establish that fact. Rescoring alone cannot recover it.

The owner approved this pricing policy after offline fixture comparisons:

| Reference fixture | Score before → after | Completeness | Estimated annual loss (ZAR) |
| --- | --- | --- | --- |
| Finance R10m | 282 → 372 | 90% → 67% | 447,252 → 509,411 |
| Retail R13.5bn | 205 → 262 | 100% → 77% | 67,728,866 → 69,120,780 |

Return-period loss totals were unchanged in these comparisons. These are
fixture-specific effects, not a promise of the same price change for other scans.
Stored results retain their old scores until explicitly rescored; this sandbox
change does not rewrite production scan history.

Certificate-discovery notes distinguish zero, one, and two answered sources.
Even two answered sources do not establish a complete asset inventory. Partly
assessed supply chains retain their adverse findings and cannot claim a green
overall exposure verdict. The legend defines the neutral “Not assessed” state.

Build the committed dashboard using the lockfile and
`SCANNER_BASE_PATH=/scanner`; verify byte equality against an isolated rebuild.
Offline verification does not establish that a fresh dependency installation
will succeed without a populated package cache.

### Technical-report measurement qualification

The full technical PDF cards for IntelX, VirusTotal, and fraudulent domains
require completed measurements and usable counts before making clean claims.
Missing, failed, malformed, or incomplete data render as Not assessed. Positive
observations remain visible with their severity and an incomplete-assessment
caveat. Zero VirusTotal engine results and zero checked lookalike variants are
unassessed. The lookalike checker stores at most twenty display records; this
valid cap is preserved. Clean lookalike wording applies only to checked variants.
These follow-up fixes extend FC13-3's five Executive Summary rows.

## How it's wired

- Flask serves `templates/results.html`, a thin shell that injects
  `window.RESULTS` / `window.SCAN_META` / `window.CHECKER_MANIFEST` (the same
  server-side data contract the legacy template used) and loads
  `/static/dashboard/app.{js,css}`.
- `vite build` outputs to `../static/dashboard/`, which Flask serves from its
  default `/static` handler. No new routes, no API contract change.
- The React app reads `window.RESULTS` through the selector layer
  (`src/data/`) — components never touch the raw payload directly.

## Develop

```bash
npm install
npm run dev        # http://localhost:5174  (uses src/dev/sampleResults.json)
npm run typecheck
```

`src/dev/sampleResults.json` is a **dev-only** fixture: a real captured
phishield.com scan enriched with the newer backend blocks
(`_scan_completeness`, `compliance`, `peer_benchmarking`) in their exact
documented shapes, so the coverage banner / compliance matrix / peer empty-state
can be developed without a live scan. It never ships to production.

## Build & deploy

```bash
npm run build      # writes ../static/dashboard/{app.js,app.css,assets/*}
```

**The build output in `../static/dashboard/` is committed to the repo.** The
Render service is pure-Python (no Node toolchain in the deploy), so committing
the bundle keeps the deploy unchanged. After any frontend change: run
`npm run build` and commit the regenerated `static/dashboard/` alongside the
source.

## Structure

```
src/
  data/         selectors, checker-state normalisation, formatters (the data layer)
  types/        RESULTS payload types + CheckerState union
  components/
    primitives/ Panel, Status badges, EmptyState  (shared surface only)
    shell/      AppShell, Sidebar, CommandBar, CategoryTabs, Footer, StatusScreen
    overview/   the executive strip + every analytical panel
    drawer/     EvidenceDrawer (right-side drill-down)
  pages/        OverviewPage, CategoryDetailPage
```
