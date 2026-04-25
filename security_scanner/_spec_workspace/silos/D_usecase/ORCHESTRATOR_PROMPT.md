# Orchestrator prompt — Silo D (Use-case / output spec)

**Paste into a FRESH session AFTER Silos A and B have converged.** D consumes A's checker manifest contract and B's webhook payload schema.

---

# Run Silo D of the Phishield scanner spec-convergence framework

You are the orchestrator for Silo D (Per-persona output contracts: broker / continuous-monitoring / insurer-agnostic-consulting + open-ended uses).

## Pre-flight check

Before round 1, verify these exist:
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md`
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\checker_manifest_contract.md`
- Silo B's webhook payload schema (in `silos/B_architecture/spec_final.md` or extracted alongside)

If A or B is incomplete: use today's API contract (baseline.md § 15) as placeholder, mark dependent spec lines.

## Required reading

1. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\D_usecase\SILO_CONTEXT.md`
2. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md`
3. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\checker_manifest_contract.md`
4. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\B_architecture\spec_final.md`
5. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\baseline.md` (esp. § 4 PDF, § 5 HTML, § 7 CRM, § 15 API contract)
6. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\INVARIANTS.md` (esp. INV-19, INV-21, INV-22, INV-23)
7. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\KNOWN_ISSUES.md`
8. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\GLOSSARY.md`
9. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\D_usecase\eval.json` — rubric (30 cases, jsonschema/jsonpath/regex/byte-hash mechanical)
10. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\roles\{author,reviewer,critic,simulator,evaluator}.md`

Plus inspect `security_scanner/templates/crm/quote_form.html` for round-trip targets.

## Dispatch sequence per round

Standard sequence — Author → Reviewer ‖ Critic ‖ Simulator → Evaluator. Outputs at `silos/D_usecase/rounds/v<epoch>_r<N>/`.

## Round budget & exit conditions

**Hard cap: 12 rounds.** Stop earlier if:

- **Target hit**: Evaluator score ≥ 85% AND all negative-test cases (D-010 to D-014) PASS → stop, declare success.
- **Plateau**: Δ < 2pp × 3 AND Critic 0-new × 2 → stop, declare ceiling.
- **Restart trigger**: as standard.

## Hard outputs

1. `silos/D_usecase/spec_final.md` — use-case spec.
2. **JSON Schema (Draft 2020-12) per persona**: broker, monitoring, consulting, plus 2-3 open-ended.
3. **Round-trip validation report**: existing fixtures → broker schema → can populate `app.py:1240 create_quote`?
4. **SLA timer table** with normalized seconds.
5. **Field-sourcing report**: every persona-schema field traced.

## Open-ended brief (category d)

Author proposes 2-3 additional uses with `viability_score` + `gap_analysis` + `persona_schema`. Suggested seeds in SILO_CONTEXT.md. Author may propose alternatives with justification. Reject open-ended uses missing the viability triple.

## Status reporting & hand-off

When done, all four silos have converged. Run the **consolidation orchestrator** at `_spec_workspace/consolidation/ORCHESTRATOR_PROMPT.md` next, in another fresh session.
