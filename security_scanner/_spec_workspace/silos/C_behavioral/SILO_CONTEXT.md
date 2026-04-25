# Silo C — Behavioral spec context

## Position in framework
**Runs FIRST.** C produces the shared "today" baseline that Silos A / B / D consume. Silos A/B/D do NOT re-extract behavioral state — they read C's converged `spec_final.md`.

## Target spec (Author's mandate)
An authoritative, file:line-cited spec of what `security_scanner/` does today, with **explicit gap markers** vs. target end-state for each of:
- 27 checkers (resolve NUM-001 22-vs-27-vs-26 first)
- Scoring (RiskScorer, RSI, DBI, FAIR-Hybrid)
- Compliance map (POPIA / PCI DSS v4.0 / ISO 27001 / NIST CSF 2.0)
- Reporting (PDF full|summary, HTML results, SSE progress)
- Persistence (15 scans.db tables)
- CRM (38 routes, pipeline, ROA, claims, complaints, renewals)
- Output APIs (`/api/scan`, `/api/scan/<id>`, `/api/scan/<id>/progress`, `/api/scan/<id>/pdf`, `/api/history/<domain>`)
- Document generators (gap-v9, FAIR-gap, sec13, sensitivity v1/v2)
- User Manual reconciliation (manual_parts/part1-6 vs code)

Each section reconciles against current code AND against the User Manual (which may diverge). Each section ends with "Gap to target end-state: <markers>" so downstream silos pick up the right hooks.

## Hard outputs
1. `silos/C_behavioral/spec_final.md` — the authoritative "today" spec.
2. Resolved counts in spec for NUM-001 (canonical checker count).
3. Reconciliation table: User Manual claim vs. code reality, per checker. Format: `| Checker | Manual says | Code does | Drift type |`.
4. Per-checker gap-marker block consumed by Silos A/D.
5. Append to `substrate/GLOSSARY.md`: any new behavioral terms encountered (especially clarify MDR, scenarios_4cat).

## Simulation definition (Simulator's mandate)
**Spec-vs-actual-output oracle.** For each fixture in `substrate/sample/`, the spec must predict the scanner's actual JSON output structure & key values. Simulator's job:
1. Read what the spec predicts (e.g., "for broken_hygiene_synth.json the spec claims overall_risk_score lands in [50, 150]").
2. Open the fixture (this IS the actual scanner output).
3. Diff predicted vs. actual.
4. Report each prediction as MATCH / MISS / UNRESOLVED.

If the spec lacks a prediction for a rubric case's input, that's `UNRESOLVED` and the Evaluator fails the case.

## Evaluator notes
- Standard scoring (PASS / PARTIAL / FAIL / N/A) per `evaluator.md`.
- 35 cases in `silos/C_behavioral/eval.json`; total weight 39.
- Two `weight=2` invariant cases (C-034, C-035) are load-bearing.
- Spec-vs-actual cases (C-031, C-032, C-033) reuse fixtures as ground truth — these are the truth oracles.

## Target / convergence threshold
- **Primary**: ≥ 90% weighted score on eval.json by round 6.
- **Acceptable**: ≥ 85% with explicit declaration of which `weight=1` cases are architecture-bounded vs. rubric-bounded.
- **Hard cap**: 12 rounds; early-exit if Δ < 2pp × 3 AND Critic 0-new × 2.

## Silo-specific anti-patterns
- **Re-discovering**: KNOWN_ISSUES.md is input. Don't re-find SCN-GAP-* / GAP-* / SENS-* / NUM-* etc.
- **Manual-vs-code blur**: when manual says X and code does Y, spec must declare which is authoritative AND propose reconciliation (update manual? change code? document both?).
- **Theoretical fluff**: spec describes what the code does, not what it should do. End-state proposals belong in the gap-markers, not the body.

## Inputs / dependencies
- Inputs only — Silo C is upstream of A/B/D.
- Reads: substrate/* + fixtures.
- Writes nothing that A/B/D can't read directly.

## Hand-off
After convergence, Silo C's `spec_final.md` is the canonical "today" reference. Silos A/B/D's orchestrator prompts include a path to it.
