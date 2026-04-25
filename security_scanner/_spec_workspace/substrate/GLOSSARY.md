# GLOSSARY — shared data dictionary

**Purpose.** Cross-silo data dictionary. Owned by NO silo. Every silo's Author appends term definitions before round 1; consolidator merges. Prevents semantic drift (e.g., "risk_score" meaning different things in Silos A vs. B vs. D).

**Convention.** Term, current usage in code (with `file:line`), aliases, scope (which silo/system component owns the canonical definition).

---

## A. Risk & scoring terms

### overall_risk_score
- **Canonical**: 0-1000 integer; lower = higher risk
- **Code**: `scoring_analytics.py:545+`; surfaced as `overall_risk_score` in `/api/scan` response
- **Aliases**: "risk score", "overall score", "scan score"
- **Anti-pattern**: any silo using "risk_score" to mean a 0-100 number must rename to `risk_score_pct` or `risk_score_normalised`.

### risk_level
- **Canonical**: `Critical` (0-250) | `High` (250-500) | `Medium` (500-750) | `Low` (750-1000)
- **Code**: `scoring_analytics.py:545+`
- **Aliases**: "risk band", "risk tier", "risk category"

### per-checker score
- **Canonical**: 0-100 integer per checker, where 100 = best (no risk), 0 = worst
- **Code**: every checker returns a `score` field
- **Note**: contrast with overall_risk_score (1000-scale, lower = worse). Direction is INVERTED.

### RSI / rsi_score
- **Canonical**: Ransomware Susceptibility Index, 0.0-1.0 float; higher = more susceptible
- **Code**: `scoring_analytics.py:856-1189`
- **Aliases**: "ransomware index", "ransomware risk score" (avoid; conflicts with category name)

### DBI / dbi_score
- **Canonical**: Data Breach Index, 0-100 integer; higher = better posture
- **Code**: `scoring_analytics.py:2292-2397`
- **Note**: direction OPPOSITE to RSI.

### TEF
- **Canonical**: Threat Event Frequency multiplier per industry; FAIR-Hybrid input
- **Code**: `scoring_analytics.py:1378-1385`

### p_breach
- **Canonical**: Annualised probability of breach, [0, 1]; output of FAIR-Hybrid
- **Code**: `scoring_analytics.py:1194-2288`

### EPSS
- **Canonical**: Exploit Prediction Scoring System, 0.0-1.0 float per CVE; vendored from FIRST.org
- **Used by**: shodan_vulns checker enrichment

### KEV
- **Canonical**: CISA Known Exploited Vulnerabilities catalog membership flag, boolean per CVE
- **Used by**: shodan_vulns checker enrichment

### CVSS
- **Canonical**: Common Vulnerability Scoring System, 0.0-10.0 float per CVE; v3.1 score used
- **Used by**: shodan_vulns checker output

### checker score vs. category score
- **Canonical**: identical for most checkers (1:1 mapping). For aggregator categories (`external_ips`, `credential_risk`, `osv_vulns`), category score is computed from underlying checker outputs.
- **Note**: avoid using "category" and "checker" interchangeably — aggregators are categories, not checkers.

---

## B. Scan / output terms

### scan_id
- **Canonical**: UUID v4 string; primary key for `scans` table
- **Code**: `app.py:641-737`

### scan_timestamp
- **Canonical**: ISO 8601 UTC with timezone offset
- **Code**: per fixture inspection

### domain_scanned
- **Canonical**: the apex/sub domain submitted in the scan request, lowercase, no scheme
- **Code**: `scanner.py` input normalisation

### per_ip_results / per_ip
- **Canonical**: dict keyed by IPv4 string; value is per-checker results for that IP
- **Code**: `scanner.py:296-549`

### external_ips
- **Canonical**: aggregated summary across discovered IPs with per-IP risk labels Critical/High/Medium/Low
- **Code**: `scoring_analytics.py:16-220` (ExternalIPAggregator)

### compliance map
- **Canonical**: `{POPIA, PCI_DSS_v4, ISO_27001, NIST_CSF_2}` → control results (Pass / Partial / Fail)
- **Code**: `scoring_analytics.py:228-450`

### insurance section
- **Canonical**: top-level key `insurance` in `/api/scan` response containing `{rsi, financial_impact, dbi, remediation}`
- **Code**: per fixture inspection

### scenarios_4cat
- **Canonical**: legacy term for FAIR Monte Carlo 4-category breakdown (data_breach 75%, detection_escalation 5%, ransom 8%, BI 12%)
- **Note**: this is the OLD breakdown (per `scoring_analytics.py:1194-2288`). The post-2026-04-13 model uses 7 incident types + 5 cost components aggregated to 3 reporting categories (Breach 49%, Ransomware 27%, BI 24%). Disambiguate carefully — Silo C should clarify which is the live behavior.

---

## C. CRM / business terms

### pipeline_stage
- **Canonical**: `lead | scanned | quoted | bound | renewal`; ordered, monotonic
- **Code**: `app.py:455`

### client_id
- **Canonical**: UUID; primary key for `clients` table; foreign key on `scans`, `quotes`, `policies`, etc.
- **Code**: `app.py:158-173`

### policy_number
- **Canonical**: format `PHI-NNNNNN`, auto-generated via `_next_number`
- **Code**: `app.py:1307`

### invoice_number
- **Canonical**: format `INV-NNNNNN`
- **Code**: per `_next_number('INV', 'invoices', 'invoice_number')`

### claim_number
- **Canonical**: format `CLM-NNNNNN`
- **Code**: per `_next_number('CLM', 'claims', 'claim_number')`

### ROA
- **Canonical**: Record of Advice; FAIS regulatory artifact
- **Code**: `app.py:317-333` (table); `app.py:1666-1714` (routes)
- **Note**: required by SA Financial Advisory and Intermediary Services Act (FAIS).

### MDR
- **Canonical**: Multi-Domain Risk; appears in `quotes.mdr_selection` / `mdr_discount`
- **Code**: `app.py:192-211`
- **Note**: not fully documented; Silo C should clarify what this represents in pricing.

### commission
- **Canonical**: 12.5% default rate on bound policy; stored as `commission_rate` and `commission_amount`
- **Code**: `app.py:1323-1326`

### reseller
- **Canonical**: string column on `clients`; placeholder, never enforced
- **Code**: `app.py:166`
- **Anti-pattern**: do not assume `reseller` implies multi-tenancy is implemented — it isn't.

### renewal window
- **Canonical**: 60 days before policy `expiry_date`; configurable on renewals list (`?days=30|60|90`)
- **Code**: `app.py:894-912, 1336-1361`

---

## D. Architecture / output channel terms

### scan
- **Canonical**: a single full execution of `SecurityScanner.scan(domain)` producing one `scans` row
- **Code**: `scanner.py:104-599`
- **Anti-pattern**: do not use "scan" to mean "monitoring run" or "rescan" without qualifying.

### rescan
- **Canonical**: NOT YET A REAL CONCEPT in code. A second `POST /api/scan` for the same domain creates a SECOND `scans` row; nothing links them or computes a diff.
- **Future-state (Silo B)**: a rescan should be incremental — reuse cached unchanged checker outputs, compute deltas vs. prior scan.
- **Anti-pattern**: do not write specs assuming "rescan" exists today.

### delta / delta-event
- **Canonical**: NOT YET A REAL CONCEPT in code. Silo B will define.
- **Tentative scope**: subset of the full scan output that changed since the prior scan, with severity classification.

### action prompt
- **Canonical**: NOT YET A REAL CONCEPT. Silo B/D will define.
- **Tentative scope**: outbound notification (webhook / email) triggered by a critical finding above a threshold, with SLA timer.

### tenant
- **Canonical**: NOT YET A REAL CONCEPT. Silo B will define.
- **Tentative scope**: an organisation that owns a set of clients/scans, isolated from other tenants. The `reseller` column may be retrofitted.

### persona
- **Canonical**: a Silo D term. Refers to the consumer of scan output: broker / continuous-monitoring-recipient / consultant / underwriter / regulator / etc.
- **Anti-pattern**: do not conflate persona with tenant. A tenant has many personas; a persona may exist across tenants.

---

## E. Reserved / DO-NOT-USE-FOR-OTHER-MEANINGS terms

These names are heavily overloaded; specs should disambiguate explicitly when used:

### "score"
Could mean: per-checker score (0-100, higher better), overall risk score (0-1000, lower better), normalised broker UI score (TBD by Silo D), RSI (0-1 float), DBI (0-100 higher better), CVSS (0-10), EPSS (0-1).
**Rule**: never write "score" without a qualifier in any spec.

### "risk"
Could mean: any of overall_risk_score, risk_level, RSI, FAIR p_breach, financial impact, claim probability.
**Rule**: always qualify ("technical risk", "ransomware risk", "claim risk", "regulatory risk").

### "category"
Could mean: scoring category (compliance), checker category (e.g. "ssl"), aggregator category ("external_ips"), industry category, premium category.
**Rule**: prefix with the domain ("checker category", "compliance category", etc.).

### "report"
Could mean: PDF report (full or summary), HTML results page, JSON API response, sensitivity analysis docx, gap analysis docx, FAIR docx, user manual docx.
**Rule**: name the format ("PDF report", "API response", "DOCX deliverable").

### "monitoring"
Could mean: continuous monitoring (currently nonexistent), Render free-tier process monitoring, infrastructure monitoring, dark-web monitoring (IntelX/HudsonRock).
**Rule**: qualify ("continuous client monitoring", "dark-web monitoring", "infrastructure monitoring").

---

## F. Append-here protocol for silo Authors

When introducing a new term in your spec, append a row to this file in the appropriate section BEFORE the spec's first round. Format:

```markdown
### <term>
- **Canonical** (Silo X): <one-line definition>
- **Origin**: <silo or section that owns this>
- **Notes**: <relationships to existing terms, anti-patterns to avoid>
```

Consolidator merges silo-local additions into a single dictionary. Conflicts (same term, different definitions across silos) are surfaced to `consolidation/conflict_scan.md` for adjudication.

---

## G. Open ambiguities flagged for Silo C resolution

- **MDR (Multi-Domain Risk)** in `quotes.mdr_selection` / `mdr_discount` — not documented in code or manual. Silo C should clarify pricing semantics.
- **scenarios_4cat** vs. 3-category aggregation — which is the live FAIR output today? Sensitivity v2 talks about 3 categories; code has `scenarios_4cat`. Silo C should diff-test.
- **"22 vs 27 vs 26 checkers"** — see `KNOWN_ISSUES.md` NUM-001. Silo C produces the canonical count.
- **"26 scoring categories"** vs **27 checker classes** — does the difference equal 1 (the "insurance_analytics" meta-aggregator)? Silo C confirms.
