# Orchestrator prompt — Silo A (Accuracy improvement plan)

**Paste this into a FRESH Claude Code session AFTER Silo C has produced `spec_final.md`.** It is self-contained.

---

# Run Silo A of the Phishield scanner spec-convergence framework

You are the orchestrator for Silo A (Accuracy improvement plan across 27 checkers). Runs after Silo C; in parallel with Silo B. Produces the **checker manifest contract** that Silo B consumes.

## Pre-flight check

Before round 1:
- Verify `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md` exists. If not, **stop** — Silo C must complete first.
- Read it as the authoritative "today" baseline.

## Required reading before round 1

1. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\SILO_CONTEXT.md` — silo target
2. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md` — today's behavior
3. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\baseline.md` (esp. § 2 checkers, § 11 gap docs)
4. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\INVARIANTS.md`
5. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\KNOWN_ISSUES.md` (esp. SCN-GAP-* / SENS-* / MEM-* / GAP-006)
6. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\GLOSSARY.md`
7. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\eval.json` — rubric (34 cases, 4 weight=3 fatal)
8. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\roles\{author,reviewer,critic,simulator,evaluator}.md`

## Fixtures
Same set as Silo C at `_spec_workspace/substrate/sample/*.json`. Critical for accuracy: **broken_hygiene_synth.json** (high-signal fixture) and **phishield_fs.json + takealot_retail.json** (FP guards).

## Phase 4 technical deep-dive (recommended before round 1)

Before round 1 Author dispatch, run a one-shot WebSearch deep-dive: "scanner techniques used by Coalition / CFC / Bitsight / SecurityScorecard / Hunch in 2025-2026." Save to `_spec_workspace/silos/A_accuracy/market_techniques_brief.md`. Author consumes this for market-parity citations. Cost: 5-10 WebSearch calls. Skip if cost-sensitive — Author can WebSearch ad hoc but a cached brief is faster.

## Dispatch sequence per round

Each round at `_spec_workspace/silos/A_accuracy/rounds/v<epoch>_r<N>/`:

1. **Sequential**: Author. Output: `spec_v<N>.md` AND `checker_manifest_contract.md` (the hard output).
2. **Parallel**: Reviewer + Critic + Simulator (single message, 3 Agent calls).
3. **Sequential**: Evaluator after the three above.
4. Read convergence signals; decide.

### Agent dispatch template
```
You are the <ROLE> for Silo A round <N>. Read in order:
- ABSOLUTE_PATH/substrate/roles/<role>.md
- ABSOLUTE_PATH/silos/A_accuracy/SILO_CONTEXT.md
- ABSOLUTE_PATH/silos/C_behavioral/spec_final.md
- (Optional) ABSOLUTE_PATH/silos/A_accuracy/market_techniques_brief.md
- (For round N>1) prior round outputs at ABSOLUTE_PATH/silos/A_accuracy/rounds/v<epoch>_r<N-1>/
- (For non-Author roles in round N) ABSOLUTE_PATH/silos/A_accuracy/rounds/v<epoch>_r<N>/spec_v<N>.md AND checker_manifest_contract.md

Execute role mandate. Write to ABSOLUTE_PATH/silos/A_accuracy/rounds/v<epoch>_r<N>/<Role>.md.
End with convergence-signal block.
```

## Round budget & exit conditions

**Hard cap: 12 rounds.** Stop earlier if:

- **Target hit**: Evaluator score ≥ 80% AND all 4 weight=3 fatal cases (A-014, A-020, A-027, A-037) PASS → stop, declare success.
- **Plateau**: Δ < 2pp × 3 AND Critic 0-new × 2 → stop, declare ceiling. **Critical**: if any weight=3 case is FAIL, classify the silo as architecture-bounded — do NOT declare success. The spec is fundamentally incomplete.
- **Restart trigger**: same as Silo C protocol.

## Hard output

`silos/A_accuracy/spec_final.md` AND `silos/A_accuracy/checker_manifest_contract.md` (the contract for Silo B).

## Coupling note (Silo B may be running in parallel)

If Silo B is mid-flight when A stops, B has been using today's measured numbers (from baseline.md § 8) as placeholder. Notify the user when A's manifest is final so B can replace placeholders in its next round.

## Status reporting & hand-off

Same as Silo C orchestrator.
