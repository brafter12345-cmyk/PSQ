# INVARIANTS — constraints every silo's spec must satisfy or explicitly violate

**Purpose.** Constraints that hold across the system today. Each silo's Author may violate an invariant only if their spec explicitly calls it out as a deliberate change with rationale. Silent violations = spec is wrong.

**Convention.** Each invariant has an ID (`INV-NN`), a statement, evidence (`file:line`), and a "may-be-violated-by" hint flagging which silo is most likely to need to break it.

---

## I. Scanner correctness invariants

### INV-01 — Per-scan DNS cache isolation
DNS cache is cleared at the start of every scan to prevent cross-scan record leakage.
- Evidence: `scanner.py:112` (`dns_cache.clear()`)
- May be violated by: **Silo B** (continuous monitoring may want to extend cache lifetime to 24h TTL). Per `gen_gap_v9.cjs` SCN-GAP-003 this is already flagged as a candidate change.

### INV-02 — Failed checker excluded from score, weights redistributed
Checkers returning `status` ∈ {error, timeout, no_api_key, auth_failed, disabled} are excluded from the weighted sum and remaining weights are renormalised proportionally.
- Evidence: `scoring_analytics.py:549-576`
- May be violated by: **Silo A** (an accuracy spec may argue some checker failures should penalise score, e.g. consistent timeout on a heavy checker may indicate evasion).

### INV-03 — Risk score scale is 0–1000
Final overall risk score is on a 0–1000 scale. Bands: Critical 0-250 / High 250-500 / Medium 500-750 / Low 750-1000 (lower = worse).
- Evidence: `scoring_analytics.py:545+`
- May be violated by: **Silo D** (use-case specs may need 0-100 normalisation for broker UI or external consumers — must be explicit translation, not redefinition).

### INV-04 — Fresh DNS / subdomain enumeration on every scan
No persistent caching of A-record resolutions or `crt.sh` subdomain queries across scans.
- Evidence: `scanner.py:112`, `checkers_network.py:187`
- May be violated by: **Silo B** (incremental scanning will cache these).

### INV-05 — Per-checker timeout caps
Heavy checkers run under `run_with_timeout`: ssl 75s, subdomains 90s, fraudulent_domains 60s. Per-IP checker pool: 180s wall.
- Evidence: `scanner.py:184-234, 256-287`
- May be violated by: **Silo A** (deeper checker logic may need more headroom) and **Silo B** (continuous mode may use tiered scan modes per `gen_gap_v9.cjs` Speed #3).

### INV-06 — Glasswing RSI credit floor at 0
RSI credit of -0.05 for verified Glasswing partners must not push RSI below 0.
- Evidence: `gen_gap_v9.cjs:67-100` SCN-013, `scoring_analytics.py` (Glasswing factor)
- May be violated by: **Silo A** if it changes RSI methodology entirely.

### INV-07 — `include_fraudulent_domains` is opt-in
Lookalike-domain enumeration runs only when `include_fraudulent_domains=True` in the scan request.
- Evidence: `scanner.py:108, 188-191`
- May be violated by: **Silo B** if continuous-mode scheduling differentiates first-scan vs rescan.

---

## II. Scoring methodology invariants

### INV-08 — Per-checker weights sum ≈ 1.0
Weights in `WEIGHTS` dict sum to approximately 1.0 across the active set.
- Evidence: `scoring_analytics.py:463-489`
- May be violated by: **Silo A** if checker set changes (add/remove); spec must state new weights and sum.

### INV-09 — RSI base 0.05, range [0, 1]
Inherent-exposure baseline 0.05; output bounded [0, 1].
- Evidence: `scoring_analytics.py:856-1189`
- SA calibration recommendation per sensitivity v2: increase base to 0.08 for SA RDP prevalence — this is the leading change candidate.

### INV-10 — TEF per industry (FAIR-Hybrid)
Industry TEF: FS 1.45, Healthcare 1.40, Manufacturing 1.15, Retail 1.25, Agriculture 0.80, Other 1.0.
- Evidence: `scoring_analytics.py:1378-1385`
- May be violated by: **Silo A** if SA-specific calibration replaces global values.

### INV-11 — Compliance frameworks ∈ {POPIA, PCI DSS v4.0, ISO 27001, NIST CSF 2.0}
Exactly four frameworks mapped. Each control has 1-3 checker mappings with weight 0.8-1.2.
- Evidence: `scoring_analytics.py:228-450`
- May be violated by: **Silo D** if insurer-agnostic consulting persona requires additional frameworks (CISA CPGs, NIST 800-53, AICPA SOC 2, etc.).

### INV-12 — Regulatory exposure formulas (sec13)
- POPIA always: `min(R10M, rev × 2%)`
- GDPR if EU data: `rev × 4%` uncapped
- PCI if card data: `R1M × (1 - adj_compliance)`, external visibility cap 30%
- Evidence: `gen_sec13.py:43-49`
- May be violated by: **Silo A** (calibration: POPIA enforcement currently 2% but historical fines suggest 0.5-1%; per `generate_gap_analysis.cjs` GAP-006).

### INV-13 — FAIR Monte Carlo 3-category aggregation
Final report aggregates 7 incident types + 5 cost components into 3 displayed categories (Breach / Ransomware / BI). Reference profile: Breach 49% / Ransomware 27% / BI 24%.
- Evidence: `generate_gap_analysis.cjs:59-100` GAP-001 (resolved 2026-04-13)
- May be violated by: **Silo D** (consulting persona may want 7-type detail surface).

---

## III. Persistence invariants

### INV-14 — All CRM tables single-database
Every CRM entity persists in same SQLite DB as scans (`DB_PATH`).
- Evidence: `app.py:127-389`
- May be violated by: **Silo B** if multi-tenancy retrofit shards by tenant.

### INV-15 — No migration framework
Schema migrations are inline `ALTER TABLE` blocks in `init_db()` wrapped in try/except.
- Evidence: `app.py:145-154, 300-314, 908`
- May be violated by: **Silo B** (any architecture spec adopting Alembic / managed migrations).

### INV-16 — No authentication / RBAC
All routes (`/api/*`, `/crm/*`) unguarded — no `@login_required`, no role checks, no API key auth.
- Evidence: `app.py:641, 861, 963, ...` — every `@app.route` is bare
- May be violated by: **Silo B** (multi-tenancy implies auth) and **Silo D** (broker / consultant personas with different views imply authz).

### INV-17 — `reseller` column unused
`clients.reseller` exists but appears in zero WHERE clauses. Functionally dead today.
- Evidence: `app.py:166` declaration; grep finds no `WHERE reseller` usage
- May be violated by: **Silo B** (this is the natural tenancy hook to revive).

---

## IV. Pipeline invariants

### INV-18 — Pipeline stages are linear, monotonic
`['lead', 'scanned', 'quoted', 'bound', 'renewal']`. `advance_pipeline` only advances forward (higher index); never regresses.
- Evidence: `app.py:455, 458-469`
- May be violated by: **Silo D** (consulting persona may not have a sales pipeline at all).

### INV-19 — Auto-lead creation on scan
Every `POST /api/scan` for a new domain creates a client row at stage='lead' and links the scan.
- Evidence: `app.py:697-719`
- May be violated by: **Silo D** (consulting persona may scan without creating broker leads); **Silo B** (scheduled/incremental rescans should NOT create duplicate leads).

### INV-20 — Renewal triggers manually
No scheduler. Renewals surfaced via `/crm/policies/renewals` dashboard only when human visits.
- Evidence: `app.py:1336-1391`; no cron/scheduler imports found
- May be violated by: **Silo B** (continuous-monitoring scheduler should automate renewal nudges).

---

## V. Branding & output invariants

### INV-21 — Single-tenant Phishield branding hard-coded
Every PDF/HTML output strings "Phishield", "Phishield UMA", "Bryte", "FSP 46418", "Speak to your Phishield broker".
- Evidence: `pdf_report.py:223, 233, 2987, 3245, 3251, 3273`; `templates/results.html`, `templates/index.html`
- May be violated by: **Silo D** (insurer-agnostic persona must be white-labelable). This is the central architectural change for use-case (c).

### INV-22 — PDF only `?type=full|summary`
PDF generation accepts only two report types.
- Evidence: `app.py:797-821`, `pdf_report.py:3072-3300`
- May be violated by: **Silo D** if persona-specific reports (broker / underwriter / consultant / client) require new types.

### INV-23 — No webhook/email/notification surface
Zero outbound HTTP callbacks, zero email triggers, zero Slack/Teams integrations. Pull-only.
- Evidence: grep `app.py` for `requests.post`, `smtplib`, `slack` — none in user-facing flow
- May be violated by: **Silo B** (continuous-monitoring action prompts) and **Silo D** (use-case b is webhook-driven by definition).

### INV-24 — No incremental / delta API
Every scan returns full results. No "changed since" endpoint, no diff payload, no `If-Modified-Since`.
- Evidence: `app.py:739-755`, no delta logic in `scanner.py`
- May be violated by: **Silo B** (delta detection is a primary continuous-monitoring requirement).

---

## VI. External API & cost invariants

### INV-25 — Free-tier-default API stack
Scanner runs without paid API keys; checkers degrade to `status="no_api_key"` rather than failing the scan.
- Evidence: per-checker key checks (e.g., `checkers_threats.py:1122-1346` Dehashed)
- May be violated by: **Silo A** if accuracy improvements depend on paid Coalition / Bitsight / etc. equivalents — must explicitly cost.

### INV-26 — Per-checker external dependency declared
Each checker that needs an external API checks for its key explicitly and returns `no_api_key` if absent. No silent fail.
- Evidence: pattern across `checkers_threats.py` (e.g., Dehashed, VT, ST, Shodan, IntelX)
- May be violated by: **Silo A** if a hard-dependency stance changes the contract.

### INV-27 — Tranco list daily refresh
Web ranking checker uses Tranco list cached locally for 24h.
- Evidence: `checkers_threats.py:2335-2401`
- May be violated by: **Silo B** (continuous mode may want even staler tolerance to save bandwidth).

---

## VII. Test / fixture invariants

### INV-28 — Existing fixtures both SA, both clean
`takealot_baseline.json` (Retail R5B Medium) and `phishield_baseline.json` (FS R10M High) are both SA, both "mostly clean" hygiene.
- Evidence: fixture inspection
- This is a **rubric blind spot**: Silo A's accuracy rubric on these fixtures only tests low-signal cases. Synthesised broken-hygiene fixture is the corrective.

### INV-29 — `run_qa_test.py` validates FAIR + RSI only
QA harness tests RiskScorer, FinancialImpact, RSI; does NOT exercise individual checkers, CRM, or PDF generation.
- Evidence: `run_qa_test.py:1-213`
- May be violated by: **Silo A** if accuracy spec adds checker-level QA cases; **Silo C** if behavioral spec validates more surface.

---

## VIII. Documentation invariants

### INV-30 — Manual is point-in-time DOCX
User Manual is a single `.docx` regenerated by `generate_manual.py` from 6 part files. No versioning beyond filename. No code-to-doc traceability.
- Evidence: `generate_manual.py:13-160`
- May be violated by: **Silo C** (could propose live-rendered HTML docs from code annotations).

### INV-31 — Gap analysis docs encode strategic thinking
`gen_gap_v9.cjs`, `generate_gap_analysis.cjs`, `gen_sec13.py`, `gen_sensitivity_doc.cjs` contain hardcoded change logs / gap rows / design decisions / roadmap status that ARE the strategy record. These must be treated as input to Author roles, not regenerated from scratch.
- Evidence: § 11 of baseline.md
- Hard requirement on every silo's Author.

---

## How to use these invariants

- **Author**: each round, scan your draft for invariant violations. If you violate one, the spec must say "Violates INV-NN because <rationale>".
- **Reviewer**: cross-check Author's draft against this file. Any silent violation is a Reviewer-fail finding.
- **Critic**: an invariant violated without explicit reason is a design-level failure mode (one of your ≥3).
- **Simulator**: when simulating spec output, check whether INV-NN holds for the simulated input.
- **Evaluator**: rubric cases derived from INV-NN are a reliable mechanical check.
