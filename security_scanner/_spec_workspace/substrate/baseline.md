# Phishield Cyber Risk Scanner — Substrate Baseline

**Purpose.** Authoritative file:line-cited map of what `security_scanner/` does today. This is consumed by every silo in the spec-convergence framework as the "today" reference. Silos A/B/D do NOT re-extract behavioral state — they read this.

**Source.** Composed from two extraction passes:
- Phase 0a — first-pass scanner architecture (app.py orchestration, 27 checkers, scoring, reporting, concurrency).
- Phase 0g — corrections covering CRM (missed in first pass), full scans.db schema, manual_parts, document generators, industry data, sensitivity outputs.

**Convention.** Every claim cites `file:line`. Quote verbatim where practical, especially for hardcoded data tables in `gen_*.cjs`. No speculation about intent — describe what the code does.

---

## 1. Entry points & request flow

### 1.1 Flask API (`app.py`)

- **POST /api/scan** (`app.py:641-737`) — initiates scan
  - Request: `{"domain": "...", "industry": "...", "annual_revenue": N, "annual_revenue_zar": N, "country": "ZA", "include_fraudulent_domains": false, "client_ips": []}`
  - Response: `{"scan_id": "<uuid>"}` immediately; background thread runs scanner via worker queue
  - Auto-creates client/lead row in CRM if no client exists for domain (`app.py:697-719`)
  - Concurrency cap: `MAX_CONCURRENT_SCANS` semaphore (`app.py:51, 62`, default 5)
- **GET /api/scan/<scan_id>** (`app.py:739-755`) — poll for results (returns full JSON when complete)
- **GET /api/scan/<scan_id>/progress** (`app.py:757-795`) — Server-Sent Events stream, emits `{"checker": "...", "status": "running|done", "score": N, "ips": [...]}` per checker
- **GET /api/scan/<scan_id>/pdf** (`app.py:797-821`) — PDF download (`?type=full|summary`)
- **GET /api/history/<domain>** (`app.py:823-835`) — last 10 scans

### 1.2 CLI / direct invocation
```python
scanner = SecurityScanner()
result = scanner.scan(domain)  # returns full results dict
```
(`scanner.py:602-607`)

### 1.3 Persistence
SQLite at `DB_PATH` (`app.py:50`), default `scans.db`. See § 6 for full schema.

---

## 2. The 27 checkers

`scanner.py:104-599` orchestrates three phases. All checkers return `{"status": "completed|error|timeout|no_api_key|auth_failed|disabled|skipped", ...}`.

### 2.1 Phase 1 — IP discovery (foundation, not a checker)
- A-record resolution via process-wide DNS cache (`scanner_utils.py:48-106`); cache cleared per scan (`scanner.py:112`)
- Merge client-supplied IPs (`scanner.py:137-145`)

### 2.2 Phase 2 — Domain-level checkers

**Lightweight concurrent batch** (ThreadPoolExecutor max_workers=6, 180s timeout, `scanner.py:205-225`):

| # | Checker | Class | File:line | Inputs | Output signal |
|---|---------|-------|-----------|--------|---------------|
| 1 | email_security | EmailSecurityChecker | checkers_core.py:318-490 | domain | SPF/DMARC/DKIM/MX, score 0-100 |
| 2 | email_hardening | EmailHardeningChecker | checkers_core.py:511-625 | domain | MTA-STS, BIMI, TLS-RPT |
| 3 | http_headers | HTTPHeaderChecker | checkers_core.py:627-758 | domain | CSP, X-Frame, HSTS etc., score 0-100 |
| 4 | waf | WAFChecker | checkers_core.py:760-847 | domain | WAF/DDoS provider |
| 5 | cloud_cdn | CloudCDNChecker | checkers_core.py:848-912 | domain | CDN provider |
| 6 | domain_intel | DomainIntelChecker | checkers_core.py:914-968 | domain | Domain age, WHOIS, TLD type |
| 7 | exposed_admin | ExposedAdminChecker | checkers_core.py:969-1041 | domain | Known admin paths (wp-admin, admin.php, etc.) |
| 8 | breaches | BreachChecker | checkers_threats.py:177-227 | domain, hibp_api_key | HIBP breach count |
| 9 | website_security | WebsiteSecurityChecker | checkers_threats.py:229-330 | domain | SSL redirect, HTTPS, cookie flags, score 0-100 |
| 10 | payment_security | PaymentSecurityChecker | checkers_threats.py:332-403 | domain | Payment forms, PCI compliance |
| 11 | tech_stack | TechStackChecker | checkers_threats.py:14-176 | domain | Server/CMS versions, EOL software |
| 12 | dehashed | DehashedChecker | checkers_threats.py:1122-1346 | domain, dehashed_email/key | Credential leak records |
| 13 | virustotal | VirusTotalChecker | checkers_threats.py:1347-1464 | domain, vt_key | Engine flagging, score 0-100 |
| 14 | securitytrails | SecurityTrailsChecker | checkers_threats.py:1465-1567 | domain, st_key | DNS records, related domains |
| 15 | hudson_rock | HudsonRockChecker | checkers_threats.py:1568-1865 | domain | Infostealer hits |
| 16 | intelx | IntelXChecker | checkers_threats.py:1866-1971 | domain, intelx_key | Dark-web leak catalog |
| 17 | privacy_compliance | PrivacyComplianceChecker | checkers_threats.py:2151-2333 | domain | POPIA/GDPR section coverage |
| 18 | web_ranking | WebRankingChecker | checkers_threats.py:2335-2401 | domain | Tranco rank int |
| 19 | info_disclosure | InformationDisclosureChecker | checkers_threats.py:2502-2616 | domain | Exposed paths, .git, sensitive files |
| 20 | glasswing | GlasswingPartnerChecker | checkers_threats.py:2403-2501 | domain | Anthropic Glasswing partner match |

**Heavy sequential checkers** (`run_with_timeout`, `scanner.py:184-234`):

| # | Checker | Class | File:line | Timeout | Output |
|---|---------|-------|-----------|---------|--------|
| 21 | ssl | SSLChecker | checkers_core.py:12-316 | 75s | Cert validity, TLS, ciphers, HSTS, CAA, grade A-F |
| 22 | subdomains | SubdomainChecker | checkers_network.py:12-250 | 90s | Subdomains, takeover risk, AXFR |

**Conditional heavy checker** (if `include_fraudulent_domains=True`, `scanner.py:188-191`):

| # | Checker | Class | File:line | Timeout | Output |
|---|---------|-------|-----------|---------|--------|
| 23 | fraudulent_domains | FraudulentDomainChecker | checkers_threats.py:1972-2149 | 60s | Lookalike domains, typosquatting |

### 2.3 Phase 3 — Per-IP checkers (ThreadPoolExecutor max_workers=4, 180s timeout, `scanner.py:256-287`)

| # | Checker | Class | File:line | Output |
|---|---------|-------|-----------|--------|
| 24 | dns_infrastructure | DNSInfrastructureChecker | checkers_network.py:338-641 | Open ports, services, banners, reverse DNS, ASN |
| 25 | high_risk_protocols | HighRiskProtocolChecker | checkers_network.py:643-769 | RDP/SSH/SMB/DB exposure |
| 26 | dnsbl | DNSBLChecker | checkers_network.py:817-874 | Blacklist listings |
| 27 | shodan_vulns | ShodanVulnChecker | checkers_threats.py:405-941 | Per-IP CVEs, EPSS, KEV flags, weaponized, age |

### 2.4 Post-Phase 3 enrichment (`scanner.py:296-549`)

- **ExternalIPAggregator** (`scoring_analytics.py:16-220`) — merges per-IP into `external_ips` summary; per-IP risk labels Critical/High/Medium/Low
- **OSVChecker** (`checkers_threats.py:943-1121`) — version→CVE via OSV.dev; merges into `per_ip[ip].shodan_vulns`; batch EPSS + CISA KEV lookup
- **CredentialRiskClassifier** — ranks dehashed + hudson_rock + intelx into `credential_risk` category

---

## 3. Scoring & analytics (`scoring_analytics.py`)

### 3.1 RiskScorer (`scoring_analytics.py:458-776`)
- **Per-checker weights** (`scoring_analytics.py:463-489`, sum ≈ 1.0): ssl 0.09, exposed_admin 0.09, high_risk_protocols 0.08, breaches 0.07, shodan_vulns 0.07, ransomware_risk 0.06, dnsbl 0.06, email_security 0.06, http_headers 0.05, virustotal 0.05, info_disclosure 0.05, tech_stack 0.05, website_security 0.04, vpn_remote 0.04, fraudulent_domains 0.04, dehashed 0.03, external_ips 0.03, data_breach_index 0.03, email_hardening 0.02, subdomains 0.02, payment_security 0.02, privacy_compliance 0.02, web_ranking 0.02, financial_impact 0.02, securitytrails 0.01
- **Risk scale**: 0–1000. Per-checker risk = `100 - score`. Weighted sum. Failed checkers excluded; weights redistributed (`scoring_analytics.py:549-576`).
- **Risk levels**: Critical 0-250, High 250-500, Medium 500-750, Low 750-1000 (inferred from `scoring_analytics.py:545+`)

### 3.2 Compliance map (`scoring_analytics.py:228-450`)
Frameworks: **POPIA, PCI DSS v4.0, ISO 27001, NIST CSF 2.0**. Each ~10 controls; each control mapped to 1-3 checkers with weight 0.8-1.2. Control verdict: Pass (all ≥80) / Partial / Fail (any ≤20).

### 3.3 RansomwareIndex / RSI (`scoring_analytics.py:856-1189`)
- Inputs: category scores, industry, annual_revenue
- Base 0.05 (inherent exposure baseline)
- ~15 contributing factors: credential risk (high), exposed DB ports, EPSS>50% CVEs, unpatched critical/high CVEs, DMARC=none, no WAF, weak SSL, RDP exposure, breaches+credential leaks, AV listings
- Modifiers: industry mult (FS 1.15, Healthcare 1.12, Other 1.0; `scoring_analytics.py:1378-1385`), size mult (revenue-based 0.85-1.12)
- **Glasswing credit**: -0.05 with floor 0 (`scoring_analytics.py`, added v9 2026-04-21 per `gen_gap_v9.cjs:67-100` SCN-013)
- Output: `{rsi_score: 0.0-1.0, risk_label: Low|Medium|High|Critical, contributing_factors: [...]}`

### 3.4 FinancialImpactCalculator / FAIR-Hybrid (`scoring_analytics.py:1194-2288`)
- **TEF per industry** (`scoring_analytics.py:1378-1385`): FS 1.45, Healthcare 1.40, Manufacturing 1.15, Retail 1.25, Agriculture 0.80, Other 1.0
- **p_breach** = `min(1.0, vulnerability * TEF * 0.3)` where `vulnerability = (100 - overall_score/10) / 100`
- **Decomposition** (post-2026-04-13 restructure per `generate_gap_analysis.cjs:59-100` GAP-001): 7 incident types + 5 shared cost components, aggregated to 3 reporting categories (Breach / Ransomware / BI). Reference profile (R100M Other, moderate posture) splits ≈ Breach 49% / Ransomware 27% / BI 24%.
- **SA breach costs** (`scoring_analytics.py:828-838`): FS R70.1M base, Healthcare R73.65M, etc.
- **Regulatory exposure** (per `gen_sec13.py:43-49`):
  - POPIA always: `min(R10M, rev × 2%)`
  - GDPR if EU data: `rev × 4%` (uncapped)
  - PCI if cards: `R1M × (1 - adj_compliance)`, external visibility cap 30%, fine range R700K-R1M from external alone
  - Other jurisdictions: R2M each
- **Output**: `{score, total: {most_likely, p5, p50, p75, p95}, scenarios_4cat, insurance_recommendation: {minimum_cover_zar, recommended_cover_zar, premium_risk_tier}}`

### 3.5 DataBreachIndex / DBI (`scoring_analytics.py:2292-2397`)
50pts breach history + 30pts credential leaks + 20pts current exposure flags. Higher = better.

### 3.6 RemediationSimulator (`scoring_analytics.py:2401-2518`)
Maps findings → prioritised fixes with estimated annual savings. Sorted by priority (1=critical, 2=high, 3=medium) then savings desc (`scoring_analytics.py:2492`).

---

## 4. Reporting (`pdf_report.py`, 3537 lines)

Entry: `generate_pdf(scan_results, industry, annual_revenue_zar) → bytes` (`pdf_report.py:2973`)

### 4.1 Structure
1. **Cover** (`pdf_report.py:2998-3057`): logo, domain, scan date, risk-score gauge (0-1000, Low 0-200 / Medium 200-400 / High 400-600 / Critical 600-1000), legend, key terms
2. **Executive summary table** (`pdf_report.py:2500-2574`): SSL grade, email score, headers %, breaches, admin panels, DB exposure, blacklist, WAF, RDP, RSI, DBI, est. annual loss, fraudulent domains, web ranking
3. **Vulnerability Posture** (`pdf_report.py:2581-2650+`): severity/age matrix, patch mgmt rating, EPSS, KEV, ransomware association
4. **Attacker's View** (referenced `pdf_report.py:3069`)
5. **Type=summary** (`pdf_report.py:3072-3300`): financial impact banner, "Why This Matters" with IBM 2025 SA stats (R44.1M avg breach, 241 days to identify, 35% recovery, 60% SMB shutdown), POPIA/GDPR/PCI, broker CTA
6. **Type=full**: all of the above + per-category breakdown for all 27 checkers + recommendations

### 4.2 Branding (hard-coded)
- Header: "PHISHIELD Cyber Protect | Risk Assessment Report" (`pdf_report.py:223`)
- Footer: "PHISHIELD UMA (Pty) Ltd | Authorised Financial Services Provider | FSP 46418" (`pdf_report.py:233`)
- Author: "PHISHIELD / Bryte Insurance" (`pdf_report.py:2987`)
- CTAs: "Speak to your Phishield broker" (`pdf_report.py:3245, 3251, 3273`)
- **No white-label config detected**.

### 4.3 Color scheme (`pdf_report.py:23-39`)
Navy #0f2744, Blue #1d4ed8, Green #16a34a, Amber #d97706, Red #dc2626, Critical #991b1b.

---

## 5. HTML output

### 5.1 `templates/results.html`
- Dark theme, Tailwind-like CSS variables (lines 8-12)
- Live SSE progress streaming (lines 29-43); per-IP discovery card (lines 45-48)
- Hero gauge 0-1000 (lines 54-66); executive summary grid (lines 68-73)
- Expandable category cards Jinja2-templated per checker (lines 78-93)
- Traffic-light tl-{green,amber,red,crimson} per finding (lines 85-89)
- Credential Risk Assessment (lines 1509-1548)
- Audience: end-client / broker pull. **No role-based view**.

### 5.2 `templates/index.html`
Form for scan entry: domain, industry dropdown with sub-industry searchable selector (lines 100-133), annual revenue ZAR (lines 136-139), toggles for fraudulent domains / Dehashed / IntelX (lines 142-178), regulatory exposure flags GDPR/PCI (lines 180-206), additional IPs (lines 208-218).

---

## 6. Persistence — full `scans.db` schema

15 tables, all created via inline `CREATE TABLE IF NOT EXISTS` in `app.py:init_db()` (`app.py:127-389`). Migration strategy: inline ALTER TABLE wrapped in try/except (`app.py:145-154, 300-314, 908`). No Alembic, no migrations directory.

| # | Table | Key fields | Indices |
|---|-------|------------|---------|
| 1 | `scans` (`app.py:129-141`) | id (PK), domain, status, results JSON, risk_score, risk_level, industry, annual_revenue, country, created_at, completed_at, **client_id** (added via migration `app.py:149`) | idx_domain |
| 2 | `clients` (`app.py:158-173`) | id (PK), company_name, trading_as, domain, industry, annual_revenue, employee_count, **reseller**, country (default 'ZA'), pipeline_stage, notes, created_at, updated_at, **archived** (migration `app.py:303`) | idx_clients_domain, idx_clients_pipeline |
| 3 | `contacts` (`app.py:178-189`) | id, client_id, name, email, phone, role, is_primary, created_at | idx_contacts_client |
| 4 | `quotes` (`app.py:192-211`) | id, client_id, scan_id, cover_limit, annual_premium, monthly_premium, mdr_selection, mdr_discount, risk_score, risk_level, revenue_band, status (draft|accepted|declined), valid_until, notes, created_at, updated_at, archived | idx_quotes_client |
| 5 | `policies` (`app.py:214-231`) | id, client_id, quote_id, policy_number, cover_limit, annual_premium, inception_date, expiry_date, status (active|renewed), renewal_of, notes, created_at, updated_at, **commission_rate, commission_amount** (migration `app.py:312-314`) | idx_policies_client, idx_policies_expiry |
| 6 | `invoices` (`app.py:234-252`) | id, client_id, policy_id, invoice_number, issue_date, due_date, subtotal, vat_rate (15.0), vat_amount, total, status (draft|sent|paid|overdue), notes, archived | idx_invoices_client, idx_invoices_status |
| 7 | `invoice_line_items` (`app.py:255-265`) | id, invoice_id, description, quantity, unit_price, line_total, sort_order | idx_line_items_invoice |
| 8 | `payments` (`app.py:268-279`) | id, invoice_id, amount, method, reference, payment_date, notes, created_at | idx_payments_invoice |
| 9 | `activities` (`app.py:281-290`) | id, entity_type, entity_id, client_id, action, detail, created_at — audit trail | idx_activities_client |
| 10 | `client_notes` (`app.py:292-298`) | id, client_id, text, created_at | idx_client_notes_client |
| 11 | `records_of_advice` (`app.py:317-333`) | id, client_id, quote_id, policy_id, advisor_name, client_needs, risk_profile, products_recommended, reasons, alternatives_considered, disclosures, client_acknowledged | idx_roa_client |
| 12 | `claims` (`app.py:335-352`) | id, client_id, policy_id, claim_number, claim_date, incident_date, incident_type, description, amount_claimed, amount_paid, status (filed|investigating|approved|denied|resolved), resolution_notes | idx_claims_client, idx_claims_policy |
| 13 | `communications` (`app.py:354-362`) | id, client_id, comm_type (note|email|call|meeting), subject, body, created_at | idx_comms_client |
| 14 | `tasks` (`app.py:364-376`) | id, client_id (nullable), title, description, due_date, priority (high|medium|low), status (pending|completed) | idx_tasks_status, idx_tasks_client |
| 15 | `complaints` (`app.py:378-388`) | id, client_id, subject, description, status (open|resolved), resolution (added via ALTER TABLE `app.py:908`) | idx_complaints_client |

**Persisted vs ephemeral**: All CRM/scan data persisted in SQLite. Scan progress queue `_scan_progress` (`app.py:65, 507`) is in-memory dict, ephemeral.

---

## 7. CRM subsystem — 38 routes (the missed surface)

All routes Jinja2-rendered via `templates/crm/*.html` (17 templates). **No authentication / RBAC layer.**

### 7.1 Pipeline state machine
- Stages (`app.py:455`): `['lead', 'scanned', 'quoted', 'bound', 'renewal']`
- `advance_pipeline(client_id, new_stage)` (`app.py:458-469`): only advances if new index > current index; updates `clients.pipeline_stage`; logs `stage_changed` activity
- Auto-lead creation on `POST /api/scan` (`app.py:697-719`): if no client exists for domain, creates with `pipeline_stage='lead'` and links to scan

### 7.2 Routes (selected; full list in corrections doc)
- **Dashboard** (`/crm/`, `app.py:861`): pipeline counts, MTD/QTD/YTD revenue, renewals within 60 days (`app.py:894-912`), overdue invoices, pending tasks, open claims, commission summary
- **Clients**: list `/crm/clients` (`app.py:963`), detail `/crm/clients/<id>` (`app.py:1029`), edit, archive/unarchive, link-scan (`app.py:1153`), run-scan (`app.py:1171`)
- **Quotes**: new (`app.py:1205`, pre-fills from latest scan's insurance_analytics), create (`app.py:1240`), accept/decline/bind (creates policy with 365-day expiry, 12.5% commission default `app.py:1323-1326`), archive
- **Policies**: renewals list (`app.py:1336`, `?days=30|60|90`, default 60), renew (`app.py:1364-1391`)
- **Invoices**: new/create with line items (15% VAT default `app.py:1443`), view, PDF, record payment (auto-marks paid if total reached), send, archive
- **ROA** (FAIS regulatory artifact): new/create/view; fields advisor_name, client_needs, risk_profile, products_recommended, reasons, alternatives_considered, disclosures, client_acknowledged
- **Claims**: new/create (auto-numbered CLM-*), view, update (status filed→investigating→approved→denied→resolved)
- **Tasks**: new/create/complete/delete; standalone or linked to client; priority + due_date
- **Complaints** (FAIS register): create, resolve
- **Communications**: add note/email/call/meeting log
- **Search**: `/crm/search` (`app.py:1583`)

### 7.3 Renewals logic
- Dashboard query (`app.py:894-912`): cutoff = now + 60 days; policies where `status='active' AND expiry_date <= cutoff AND >= today`
- Renewals list (`app.py:1336-1361`): configurable `?days=30|60|90`
- Renew trigger (`app.py:1364-1391`): inserts new policy with `inception_date = old.expiry_date`, `expiry_date = inception + 365`, `renewal_of = old_id`; marks old `status='renewed'`; advances pipeline to renewal
- **No scheduler**. Manual UI trigger only.

### 7.4 Multi-tenancy
- `reseller` column on clients (`app.py:166`) — **placeholder, never enforced**, never appears in WHERE clauses
- No `tenant_id` / `org_id` columns
- No auth: all routes unguarded `@app.route` (no `@login_required`, no role checks)

---

## 8. Concurrency & cost

### 8.1 Concurrency
- Lightweight domain checkers: ThreadPoolExecutor max_workers=6, 180s timeout (`scanner.py:205-225`)
- Heavy domain checkers (ssl, subdomains, fraudulent_domains): sequential with `run_with_timeout` (75/90/60s individual)
- Per-IP checkers: ThreadPoolExecutor max_workers=4 across all IPs, 180s timeout (`scanner.py:256-287`)
- API: MAX_CONCURRENT_SCANS semaphore default 5 (`app.py:51`)
- Typical e2e: ~80s on Render free tier (`gen_gap_v9.cjs` SCN-010 verification)

### 8.2 External APIs

| API | Checker | Pricing model | Notes |
|---|---|---|---|
| HIBP | breaches | Free | Per-domain |
| Dehashed | dehashed | Paid (credits) | Per query |
| Shodan | shodan_vulns | Free tier 1/month + paid | Per IP |
| VirusTotal | virustotal | Free tier 4/min | Per domain |
| SecurityTrails | securitytrails | Free tier ~100/month | Per query |
| IntelX | intelx | Free tier 10/month | Per query |
| OSV.dev | osv enrichment | Free | Per CPE batch |
| CISA KEV | shodan_vulns enrichment | Free | Batch |
| Tranco | web_ranking | Free, daily list | Cached daily |
| crt.sh | subdomains | Free | Cert log |

### 8.3 Caching
- DNS cache (`scanner_utils.py:48-106`): per-scan, cleared on each scan start (`scanner.py:112`) to prevent cross-scan leakage
- Tranco list: downloaded once daily, cached locally
- CISA KEV list: loaded once per OSV enrichment pass
- **No persistent / cross-scan caching** of any external API result

---

## 9. Configuration

### 9.1 Environment variables (`app.py:43-50`, `scanner.py:22-35`)
`HIBP_API_KEY`, `DEHASHED_EMAIL`, `DEHASHED_API_KEY`, `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, `SHODAN_API_KEY`, `INTELX_API_KEY`, `DB_PATH` (default `scans.db`), `MAX_CONCURRENT_SCANS` (default 5), `SECRET_KEY`.

### 9.2 Per-scan parameters
`include_fraudulent_domains` (`scanner.py:108`), `industry`, `annual_revenue`, `annual_revenue_zar`, `country`.

---

## 10. Test substrate

### 10.1 Fixtures (`test_fixtures/`)
- `takealot_baseline.json` — Retail R5B, Medium risk (235), full scan output
- `phishield_baseline.json` — FS R10M, High risk
- `phishield_blocked_cache.json` — cached for API-key testing
- `generate_test_pdf.py` — utility to render PDF from fixture

### 10.2 QA harness (`run_qa_test.py`, 213 lines)
Loads cached phishield.com from DB; runs FinancialImpact + RSI across 6 test scenarios (industry comparison, size comparison R5M-R1B, regulatory exposure, detailed Monte Carlo, sanity checks clean vs worst, FAIR vs Hybrid, max p_breach). Output: `QA_Test_Results.txt`.

---

## 11. Document generators (verbatim hardcoded data — spec input to Author roles)

### 11.1 `gen_gap_v9.cjs` → `Phishield_Scanner_Gap_Analysis_v9.docx`

**Change log v8→v9 (2026-04-21)** (`gen_gap_v9.cjs:67-100`):
- SCN-009: Anthropic Project Glasswing partner detection (Phase 4g) — checker + RSI credit + PDF/HTML card
- SCN-010: Wall-clock timeout guards on sslyze (75s) and SubdomainChecker (90s)
- SCN-011: Parallelised InformationDisclosureChecker with ThreadPoolExecutor max_workers=6 (~30s wall-clock, 5x speedup)
- SCN-012: Process-wide DNS cache (`scanner_utils._DNSCache`) deduplicates lookups across checkers
- SCN-013: Favourable-signal RSI factor: -0.05 credit for verified Glasswing partners, floor at 0

**Roadmap status** (`gen_gap_v9.cjs:103-120`): 13 rows. **OPEN**: 4b CMS admin path detection (next quick win), 4c CDN origin IP leakage, 4d MFA on VPN login, 4e WAF rate-limit fingerprinting, 4f DNSSEC chain validation, 4h Exploit Window narrative, 5a bug-bounty detection, 5f retire.js CVE cross-ref, 5i-T1 AI Threat Readiness Tier 1, 5i-T2 Tier 2 (self-reported), Speed #3/#4/#8 (tiered scan modes / cache-aware rescans / sslyze lazy mode — all tied to continuous monitoring scheduler).

**Open gaps** (`gen_gap_v9.cjs:135-144`): SCN-GAP-001 partner list static (Low), SCN-GAP-002 timeout orphan threads (Low), SCN-GAP-003 DNS cache per-scan only (Low), SCN-GAP-004 SPF/DMARC/MX not cached (Low), SCN-GAP-005 No AI Tier 2 (Medium).

### 11.2 `generate_gap_analysis.cjs` → `Phishield_FAIR_Model_Gap_Analysis.docx`

**GAP-001 (resolved 2026-04-13)** (`generate_gap_analysis.cjs:59-100`): restructured FAIR from 3 independent scenarios to 7 incident types + 5 shared cost components. Revenue loss was misclassified inside ransomware (inflated to 68%, suppressed BI to 6%). Rebalanced reference profile to Breach 49% / Ransomware 27% / BI 24%.

**Open FAIR gaps** (`generate_gap_analysis.cjs:88-99`):
- GAP-003 Medium: no correlation modelling between incident types — future enhancement copula-based
- GAP-004 Medium: SA-specific breach frequency data lacking — source from SABRIC / Information Regulator
- GAP-005 Low: load-shedding recovery delay not modelled (+3-5 days for no generator/UPS)
- GAP-006 Low: POPIA enforcement trend reflection (currently fixed 2%, could be 0.5-1%)
- GAP-007 Medium: split ratios not empirically calibrated for SA (currently global 70% double-extortion etc.)

### 11.3 `gen_sec13.py` → Section 13 Regulatory Exposure
Hardcoded table (`gen_sec13.py:43-49`) for POPIA / GDPR / PCI / Other jurisdictions formulas. See § 3.4.

### 11.4 `gen_sensitivity_doc.cjs` + `generate_sensitivity_doc.cjs`
Render sensitivity DOCX from `sensitivity_results_v2.json` and `sensitivity_results.json` respectively. SA market calibration guidance includes: increase RSI base 0.05→0.08 for SA RDP prevalence, FX validation R18.02/$, downtime 25-30 days for SA SMEs (load-shedding), reduce ransom estimate tiers 50% vs US, increase Public Sector mult 1.74→1.82, Agriculture 0.65→0.80, increase records_divisor R50K→R75K-100K.

---

## 12. Sensitivity calibration

### 12.1 `sensitivity_results.json` (v1, 2026-04-16)
Reference profile: R100M Other industry, overall_score 550, RSI 0.30, no WAF/CDN, single ASN. Base losses: Breach R777,870 (25.3%) / Ransomware R2,104,110 (68.5%) / BI R191,781 (6.2%) / Total R3,073,760. ±25% OAT perturbation across 25 parameters.

**High sensitivity (≥15%)**: rsi_score 17.1%, annual_revenue 15.2%.
**Medium (5-15%)**: overall_score 7.7%, downtime_days 7.4%, revenue_loss_pct 7.4%, industry_multiplier 6.3%, ransom_estimate 6.1%, records_divisor 5.5%, ir_cost 5.0%, cost_per_record 4.13%.
**Low (<5%)**: bi parameters, popia_pct 2.2%, caps.

### 12.2 `sensitivity_results_v2.json` (2026-04-16)
Three profiles: R10M FS, R200M FS, R200M Agri. Top 3 sensitivities:
1. **IBM Breach Anchor (R49.22M)** — 25% impact (linear) across all profiles. base_rec_cover 5M-35M.
2. **Annual Revenue** — 18.2% avg impact; varies 14-20% by profile.
3. **Industry Multiplier** — profile-dependent: 1.74% at R10M FS (graduation dampens), 22.51% at R200M FS, dominates large-co exposure.

**Key insight** (`sensitivity_analysis_v2.py:239-264`): Interaction effect — at R10M, elasticity exponent dominates (21.5%); at R200M (anchor point), industry multiplier dominates (22.5%) and elasticity is inert. Calibration implication: small-co tune elasticity, large-co tune industry mult.

---

## 13. User Manual (`Phishield_Cyber_Risk_Scanner_User_Manual.docx`)

Built by `generate_manual.py` from 6 `manual_parts/part{1-6}*.py` modules + shared `manual_helpers.py`/`manual_parts/helpers.py` (typography helpers add_h1/h2/body/bullet/tip/warning/note).

| Part | Sections | Coverage |
|---|---|---|
| 1 (38KB) `part1_intro.py` | Cover, ToC, §1-2 | Intro, getting started, 6-phase scan pipeline, 26 scoring categories |
| 2 (34KB) `part2_discovery_core.py` | §4.1-4.2 | Web Ranking (Tranco), SSL/TLS, HTTP Headers, CSP quality, Email Security SPF/DKIM/DMARC, MFA |
| 3 (42KB) `part3_email_network.py` | §4.3-4.5 | Info Disclosure (18 file types probed), DNSBL, DNS, AXFR, VPN/Remote, WAF |
| 4 (55KB) `part4_exposure.py` | §4.6 | Credential exposure (HIBP), Admin panels, Subdomain takeover, CVEs (Shodan), Dehashed, Hudson Rock, IntelX, VirusTotal, fraudulent domains, credential risk assessment |
| 5 (49KB) `part5_tech_compliance_insurance.py` | §4.7-5 | Tech stack (29 EOL signatures), WHOIS, NIST CSF / PCI / ISA 3000 mapping, RSI, DBI, Financial Impact (Hybrid 3-scenario), Remediation roadmap |
| 6 (50KB) `part6_reports_scoring_glossary.py` | §6-11 | PDF reports (full + summary), Scoring methodology, API integrations, Limitations & roadmap, 100+ glossary terms |

Manual is **itself a behavioral spec** — Silo C must reconcile to it or supersede.

---

## 14. Industry data files

### 14.1 `_bi_factor_data.json`
Structure: `bi_map` (flat industry→multiplier 0.05-1.75) + `hierarchy` (7 categories: Agriculture, Mining, Construction, Manufacturing, Transportation, Wholesale Trade, Retail, Financial Services, Services, Public Sector). Sample: Depository Institutions 1.75, eCommerce 1.5, Software/Tech 1.0, Agricultural Production 0.1.

### 14.2 `_sub_ind_js.txt`
Single-line minified JS const mirroring `hierarchy`. Parsed by frontend for industry dropdown population in `templates/index.html`.

---

## 15. Output API contract (canonical)

`GET /api/scan/<id>` response shape (abbreviated; see `test_fixtures/phishield_baseline.json` for full):

```json
{
  "domain_scanned": "example.com",
  "scan_timestamp": "ISO8601",
  "overall_risk_score": 0-1000,
  "risk_level": "Critical|High|Medium|Low",
  "discovered_ips": ["..."],
  "ip_sources": {"ip": ["dns|subdomain"]},
  "scan_context": {"industry": "...", "annual_revenue": N, "country": "ZA"},
  "categories": {
    "<checker_name>": {"status": "completed|error|...", "score": 0-100, "...": "..."},
    "per_ip": {"<ip>": {"<checker>": {...}}},
    "external_ips": {...},
    "osv_vulns": {...},
    "credential_risk": {...},
    "ransomware_risk": {...}
  },
  "recommendations": [{"action": "...", "priority": 1-3, "estimated_cost": "...", "rsi_reduction": N, "annual_savings_estimate": N}],
  "compliance": {"POPIA": {"controls_passed": N, "controls_total": N, "pct": N}, "PCI_DSS_v4": {...}, ...},
  "insurance": {
    "rsi": {"rsi_score": 0.0-1.0, "risk_label": "...", "contributing_factors": [...]},
    "financial_impact": {"score", "total": {"most_likely", "p5", "p50", "p95"}, "scenarios_4cat": {...}, "insurance_recommendation": {...}},
    "dbi": {"dbi_score": N, "label": "..."},
    "remediation": {"findings": [...]}
  }
}
```

---

## 16. Cross-cutting observations (raw — not yet INVARIANTS)

- **Brand**: every output identifies Phishield/Bryte. No white-label.
- **Pull-only scan**: no scheduler, no webhooks, no incremental, no delta detection.
- **CRM persistence is full insurance broker workflow** including FAIS regulatory artifacts (ROA, complaints register).
- **No auth**. Routes unguarded.
- **Single-tenant**: `reseller` column placeholder, never queried.
- **Manual document = behavioral spec** that may diverge from code as code changes faster than docs.
- **DOCX generators encode strategic thinking**: gap-v9, FAIR-gap, sensitivity v2, sec13. These are durable spec input, not regenerable.
- **22 vs 27 vs "26 categories"**: code has 27 distinct checkers; manifest in `app.py:67-113` lists 27; user manual says "26 scoring categories"; project memory says 22. Spec-convergence work must reconcile.
