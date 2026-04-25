# KNOWN_ISSUES — prior diagnoses, with stale-date warnings

**Purpose.** Issues previously identified by the user (in gap-analysis docs, FAIR-gap docs, sensitivity analysis, project memory). Each entry is sourced verbatim where practical so Author roles don't re-discover what's already known. Stale-date warnings flag entries whose status may have changed since recording.

**Convention.** ID, source, status (as recorded), date, and a stale-warning when applicable.

---

## A. Scanner gaps (from `gen_gap_v9.cjs:135-155`, recorded 2026-04-21)

### SCN-GAP-001 (Low) — Glasswing partner list is static snapshot
Source: `gen_gap_v9.cjs:138`
> "12 partners hardcoded in `GlasswingPartnerChecker.PARTNERS`. Schedule quarterly refresh against Anthropic public partner page; consider pulling dynamically in monitoring scheduler."

Status: Open. **Stale check**: today is 2026-04-25; static snapshot is ~4 days old, still fresh. But quarterly cycle implies refresh due ~2026-07-21.

### SCN-GAP-002 (Low) — Timeout guards orphan threads
Source: `gen_gap_v9.cjs:139`
> "`run_with_timeout` cancels the Future but subprocesses spawned by sslyze may continue until OS cleanup. Acceptable on Render free tier — process recycles between scans. If moved to persistent worker, add explicit subprocess kill."

Status: Open / Accepted. **Critical for Silo B**: a continuous-scanner architecture moves to persistent worker, breaking the "process recycles" assumption. This becomes a design constraint.

### SCN-GAP-003 (Low) — DNS cache per-scan only
Source: `gen_gap_v9.cjs:140`
> "Future: extend to 24h TTL for monitoring."

Status: Open. **Critical for Silo B**: continuous monitoring should extend cache TTL.

### SCN-GAP-004 (Low) — SPF/DMARC/MX DNS lookups not cached
Source: `gen_gap_v9.cjs:141`
> "Defer to next batch."

Status: Open. **Easy win for Silo A** speed track.

### SCN-GAP-005 (Medium) — No AI Threat Readiness Tier 2
Source: `gen_gap_v9.cjs:142`
> "Add scan-time questionnaire: EDR vendor, AI-assisted scanning, autonomous patching."

Status: Open. **Relevant for Silo A** (Tier 1 externally-observable signals: bug-bounty, security.txt, EDR via headers; Tier 2 is self-reported).

---

## B. FAIR / Financial Impact gaps (from `generate_gap_analysis.cjs:88-99`, recorded 2026-04-13)

### GAP-001 — Revenue loss misallocated to ransomware (RESOLVED)
Source: `generate_gap_analysis.cjs:91`
> "Resolved via incident-type decomposition (2026-04-13)."

Status: Resolved. Reference profile rebalanced from Breach 25% / Ransomware 68% / BI 6% → Breach 49% / Ransomware 27% / BI 24%. **Stale check**: still current. No further action needed.

### GAP-002 (Medium) — IBM data includes implicit BI costs
Source: `generate_gap_analysis.cjs:92`
> "Accept IBM cost-per-record as authoritative (includes 'lost business' component). Monitor whether IBM publishes component-level breakdown in future reports."

Status: Accepted by design. **Open watch item**: IBM 2026 report (typically published mid-year) may force re-evaluation.

### GAP-003 (Medium) — No correlation modelling between incident types
Source: `generate_gap_analysis.cjs:93`
> "Implement copula-based correlation for ransomware-family incidents (double extortion and ransomware-only are correlated by RSI)."

Status: Future enhancement. **Relevant for Silo A** advanced calibration.

### GAP-004 (Medium) — SA-specific breach frequency data lacking
Source: `generate_gap_analysis.cjs:94`
> "Source SA-specific breach frequency from SABRIC / Information Regulator annual reports."

Status: Future enhancement. **Relevant for Silo A** SA calibration.

### GAP-005 (Low) — Load-shedding recovery delay not modelled
Source: `generate_gap_analysis.cjs:95`
> "Add SA-specific recovery delay (+3-5 days) for companies without generator/UPS backup."

Status: Future enhancement.

### GAP-006 (Low) — POPIA enforcement trend not reflected
Source: `generate_gap_analysis.cjs:96`
> "Currently fixed 2% of turnover. Information Regulator enforcement track record currently minimal; could reduce to 0.5-1%."

Status: Future enhancement. **Relevant for Silo A** SA calibration; opens question of whether to use statutory max or expected enforced fine.

### GAP-007 (Medium) — Split ratios not empirically calibrated for SA
Source: `generate_gap_analysis.cjs:97-99`
> "Currently using global 70% double-extortion etc. Calibrate against SABRIC / CISA / IBM SA-specific incident-type data."

Status: Future enhancement.

---

## C. Sensitivity-analysis findings (from `sensitivity_results_v2.json`, recorded 2026-04-16)

### SENS-001 — IBM Breach Anchor (R49.22M) is highest-leverage parameter
- Linear 25% impact on FAIR output across all 3 profiles tested (R10M FS, R200M FS, R200M Agri)
- Source: `sensitivity_results_v2.json:44-100`
- **Implication for Silo A**: any change to the breach anchor must be defensible; small calibration tweaks have outsized output impact.

### SENS-002 — Profile-dependent dominance
- At R10M, elasticity exponent dominates (21.5%); industry multiplier inert (1.7%)
- At R200M (anchor), industry multiplier dominates (22.5%); elasticity inert
- Source: `sensitivity_analysis_v2.py:239-264`
- **Implication for Silo A**: calibration cannot be one-size-fits-all; small-co calibration tunes elasticity, large-co tunes industry mult.

### SENS-003 — RSI score 17.1% sensitivity (single-profile baseline R100M)
- Highest sensitivity in v1 single-profile run
- Source: `sensitivity_results.json`
- **Recommended SA calibration** (per `gen_sensitivity_doc.cjs` derived guidance): increase base from 0.05 to 0.08 due to SA RDP exposure prevalence.

### SENS-004 — SA market calibration recommendations (per generated sensitivity doc)
- FX rate validation: R18.02/$ for USD→ZAR conversion
- Downtime: 25-30 days for SA SMEs (load-shedding) vs current 22
- Revenue loss %: 50% may be conservative for SA
- Industry multipliers: Public Sector 1.74→1.82, Agriculture 0.65→0.80
- Ransom estimate tiers: reduce R50M-R200M tier (R2.5M→R1.5-2M), >R500M tier (R50M→R25-35M)
- Records divisor: increase R50K→R75K-100K (SA companies hold fewer records per revenue)

---

## D. Architecture / use-case gaps (derived from substrate exploration)

### ARCH-001 — No scheduler / cron / continuous monitoring
- Substrate: no scheduler imports in `app.py` or anywhere; renewals dashboard pulled only when human visits (`app.py:894-912`)
- **Critical for Silo B**: this is the primary use-case (b) feature gap. Continuous monitoring requires entirely new infrastructure.

### ARCH-002 — No webhook / notification surface
- Substrate: zero outbound HTTP callbacks, zero email/SMTP, zero Slack
- **Critical for Silo B and Silo D**: action-prompting on critical findings requires this.

### ARCH-003 — No incremental / delta scanning
- Every scan runs full check set; no `compare_to_previous_scan(domain)`; no caching of unchanged checker outputs
- **Critical for Silo B** scale story: rescanning same domain hourly burns full external API budget.

### ARCH-004 — Hard-coded Phishield/Bryte branding throughout
- `pdf_report.py:223, 233, 2987, 3245, 3251, 3273`; `templates/*` strings
- No `BRANDING_CONFIG`, no per-tenant theme, no logo upload
- **Critical for Silo D** use-case (c) (insurer-agnostic consulting); blocks white-label.

### ARCH-005 — `reseller` column placeholder; no auth; no tenancy
- `app.py:166`; zero WHERE clauses use it; zero `@login_required`
- **Critical for Silo B and D**: any multi-tenant use-case requires authn + authz layer + tenancy column enforcement.

### ARCH-006 — Manual is point-in-time DOCX
- `generate_manual.py` produces single .docx; no auto-regen on code change
- Risk: behavioral spec drifts from code. Silo C must address this.

---

## E. Project-memory items (from `~/.claude/projects/.../memory/`)

### MEM-001 — IntelX trial expires 2026-04-08
- Source: project memory `project_darkweb_monitoring.md`
- **Stale check**: today is 2026-04-25; trial **already expired**. IntelXChecker may now return `no_api_key` or `auth_failed` on every scan.
- **Action item**: Silo A must address dark-web monitoring alternative (HudsonRock + dehashed already cover some surface).

### MEM-002 — Sophos partnership may provide threat feeds
- Source: project memory `project_sophos_partnership.md`
- **Relevance for Silo A**: dynamic CVE re-prioritisation possible via Sophos threat feed. Not currently integrated.

### MEM-003 — Strategic priority order: continuous monitoring, port depth, tech fingerprinting, broker API
- Source: project memory `project_strategic_roadmap.md`
- **Relevance for Silo B (continuous monitoring) and Silo D (broker API)**.

### MEM-004 — Attacker kill chain mapping initiative
- Source: project memory `project_attacker_killchain.md`
- "Design scanner from attacker's perspective, kill chain phase coverage gaps."
- PDF already has "Attacker's View" (`pdf_report.py:3069`) and Kill Chain Narrative (per part6 manual). Coverage may be incomplete.

---

## F. Numerical inconsistencies (substrate-internal contradictions)

### NUM-001 — "22 vs 27 vs 26" checker count
- Project memory says **22 checkers**
- Code has **27 distinct checker classes** (per § 2 of baseline.md)
- App manifest at `app.py:67-113` lists **27 sections** (with one being meta "insurance_analytics")
- User Manual says **"26 scoring categories"**

**Recommendation**: Silo C must reconcile. Likely the truth is 27 checkers + 1 meta-aggregator = 28 total signals; 27 distinct checker classes; "22" is stale memory; "26 scoring categories" excludes the unscored meta-aggregator and one or two non-scored info-only checkers.

### NUM-002 — RSI base 0.05 (code) vs 0.08 (recommended SA calibration)
- Code: 0.05 (`scoring_analytics.py:856-1189`)
- Sensitivity doc recommendation: 0.08 for SA
- Status: recommendation in doc, not yet applied to code

### NUM-003 — POPIA rate 2% (code) vs 0.5-1% (GAP-006)
- Code: fixed 2% (`gen_sec13.py:43-49`)
- Per `generate_gap_analysis.cjs` GAP-006: enforcement track record suggests 0.5-1%
- Status: recognised gap, not yet applied

---

## G. Stale-date warnings on this file

- This file is a **point-in-time snapshot** as of 2026-04-25.
- Anything dated before 2026-03-25 should be re-verified (status changes).
- Anything dated 2026-04-XX is fresh.
- During silo execution (which may span days/weeks), any Author re-checking these items should re-verify status against current code, especially for items marked "Open" or "Future enhancement".

## H. Issues NOT in this file (Author's responsibility to surface)

- Issues a silo's Critic finds in round 1+ that aren't recorded here.
- Issues users have raised verbally without writing to a doc.
- Issues implicit in code complexity / debt that no one has surfaced as a "gap" yet.

These should land in the silo's `rounds/v*_r*` artifacts, not back-fill here. KNOWN_ISSUES.md is for prior-recorded diagnoses only.
