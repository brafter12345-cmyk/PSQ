# Silo D — Use-case / output spec context

## Position in framework
Runs **after Silo A and Silo B converge**. D consumes A's checker manifest contract (for field sourcing) and B's webhook payload schema (for monitoring persona contract).

## Target spec (Author's mandate)
Per-persona output contracts:

### (a) Broker — for selling cyber insurance
- Which fields drive `app.py:1240 create_quote` quote stage
- Which fields drive premium recommendation
- Sales narrative format
- Round-trips into `quote_form.html`

### (b) Continuous monitoring + action prompts
- Delta payload schema (consumed by B's webhook contract)
- Critical-finding identification
- SLA timer per severity: **Critical = 1h, High = 24h, Medium = 7d, Low = no_prompt**
- Webhook payload contract: scan_id, tenant_id, event_type, severity, delta, timestamp, idempotency_key, HMAC signature

### (c) Insurer-agnostic risk consulting
- White-labelable (no Phishield/Bryte/FSP 46418 strings)
- Branding hooks (logo URL, company name, footer disclaimer)
- Must NOT include broker-only fields: `commission`, `premium`, `mdr_selection`, `mdr_discount`, `broker_attribution`
- Persona for any insurer / reinsurer / broker / direct corporate

### (d) Open-ended — 2-3 additional uses
For each: `viability_score` (0-100), `gap_analysis` (≥200 chars with at least one `file:N` citation), `persona_schema`. Candidates the user has hinted at: M&A diligence, vendor risk assessment, regulator submission, board reporting, cyber insurance reinsurance treaty data, internal SOC 2 audit input.

## Hard outputs
1. `silos/D_usecase/spec_final.md` — use-case spec.
2. **JSON Schema (Draft 2020-12) per persona** for: broker, monitoring, consulting, plus the open-ended ones.
3. **Round-trip validation report**: existing fixtures → broker schema → can populate quote_form.html quote stage?
4. **Action-prompt SLA timer table** with normalized seconds.
5. **Field-sourcing report**: every persona-schema field mapped to one of `top:..` / `categories.*` / `computed:..` / `requires_new:silo_[AB]:..`.

## Simulation definition (Simulator's mandate)
1. Feed each fixture (`substrate/sample/*.json`) through proposed contracts.
2. Validate fixture against broker schema → must pass.
3. Validate fixture against monitoring schema → must include `delta` field (test via prior-fixture comparison if needed; if not feasible, the fixture validation is informational).
4. Validate fixture against consulting schema → must NOT contain broker-only fields (negative test).
5. Round-trip: existing JSON → broker schema → check fields match `app.py:1252-1263 create_quote` form payload requirements.
6. Persona isolation: same fixture, three personas → three structurally-distinct top-level key sets.

If a persona schema is incomplete enough that validation can't complete, that's `UNRESOLVED`.

## Evaluator notes
- Standard scoring per `evaluator.md`.
- 30 cases in `silos/D_usecase/eval.json`; all weight=1.
- Mechanical checks: jsonschema, jsonpath, regex, set membership, byte-hash equality.
- Helper constants in eval.json: `BROKER_ONLY_FIELDS`, `BRAND_STRINGS`, `SOURCE_RE`, `SLA_NORMALISER`, `FIXTURE_PRIMARY`.

## Target / convergence threshold
- **Primary**: ≥ 85% weighted score by round 6.
- **Acceptable**: ≥ 75% with negative-test cases (D-010 to D-014) all passing — these are most load-bearing.
- **Hard cap**: 12 rounds.

## Silo-specific anti-patterns
- **Persona blur**: if broker and consulting personas have overlapping fields, the spec must justify each overlap. Default is no leakage.
- **Open-ended fluff**: "could also be used for vendor risk" without `viability_score` + `gap_analysis` + `persona_schema` = rejected.
- **Field-source omission**: every field MUST trace back to scan output or be flagged `requires_new` with cross-ref to A or B. No "TBD" or "see other docs".
- **Branding in consulting persona**: any `phishield`, `bryte`, `fsp 46418` substring in consulting persona output = automatic fail (even in disclaimers).
- **Auto-lead leakage**: consulting persona scans must NOT trigger `app.py:697-719` auto-lead creation. Spec must propose a guard.

## Inputs / dependencies
- Inputs: Silo C's `spec_final.md`, Silo A's `checker_manifest_contract.md`, Silo B's webhook payload schema, substrate/*, fixtures.
- If A or B is mid-flight, D uses today's API contract (from baseline.md § 15) as placeholder and flags dependent lines.

## Open-ended exploration brief
For category (d), the Author proposes 2-3 additional uses. Suggested seed list (Author may propose alternatives with justification):
- **M&A cyber due diligence** — buyer of an SA company wants third-party security posture before acquisition
- **Vendor risk assessment** — corporate procurement scoring a prospective SaaS vendor
- **Regulator submission** — POPIA / Information Regulator request, SARB cyber resilience reporting
- **Reinsurance treaty data** — cedent shares portfolio cyber risk profile with reinsurer
- **Board reporting** — quarterly board pack with trended risk scores
- **Internal SOC 2 audit input** — Type II auditor consumes scanner output as evidence

Each proposed use must include the viability triple per the rubric.
