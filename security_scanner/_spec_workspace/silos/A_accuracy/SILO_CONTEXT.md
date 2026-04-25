# Silo A — Accuracy improvement plan context

## Position in framework
Runs in **parallel with Silo B** (after Silo C completes). A produces the **checker manifest contract** that B consumes as a hard input.

## Target spec (Author's mandate)
A per-checker accuracy & cost-effectiveness change plan across 27 checkers (canonical count from C). For EACH checker:
- KEEP / MODIFY / ADD / REMOVE flag with rationale
- Target latency band (e.g., p95 < 5s)
- Target $-cost band (free | <$0.01/scan | $0.01-0.10/scan | >$0.10/scan)
- Signal volatility class: **stable | weekly | on-change** (consumed by Silo B's continuous-monitoring scheduler)
- API dependency (free / paid-key-required)
- Market-parity rationale: at least one reference among Coalition / CFC / Bitsight / SecurityScorecard / Hunch — for every MODIFY / ADD checker
- Score band on broken_hygiene_synth (must land in critical zone)
- FP guard on phishield_fs / takealot_retail (must not produce false-critical)

Plus address open roadmap items per `KNOWN_ISSUES.md` SCN-GAP-002 through SCN-GAP-005 and roadmap rows 4b/4c/4d/4e/4f/5a/5f/5i-T1/5i-T2 (each: included with proposed approach, OR explicitly deferred with rationale).

Plus SA calibration items: SENS-003 (RSI base 0.05→0.08), SENS-004 (ransom tiers, downtime, industry mults), GAP-006 (POPIA enforcement rate 2% → 0.5-1%).

Plus disposition for IntelX (per MEM-001, trial expired 2026-04-08): replace, drop, or pay.

## Hard outputs
1. `silos/A_accuracy/spec_final.md` — accuracy change plan with per-checker change table.
2. **`silos/A_accuracy/checker_manifest_contract.md`** — Silo B's hard input. Format:
   ```markdown
   | Checker | Flag | Latency p95 (s) | Cost band | Volatility | API dep | Market parity | Notes |
   ```
3. Updated risk weights if any checker added/removed (must sum ≈ 1.0 — INV-08).
4. Cost projection at 1000 scans/month for the modified checker set.
5. SA calibration delta: which numeric parameters change and to what value.

## Simulation definition (Simulator's mandate)
For each MODIFY / ADD checker the spec describes:
1. Read the spec's proposed checker logic (what it would compute).
2. Walk through the broken_hygiene_synth fixture's input data for that checker.
3. Predict the score the new logic would produce.
4. Compare to the band the spec predicts.
5. Same FP guard on phishield_fs / takealot_retail.

If the spec's logic isn't fully described enough to walk through, that's `UNRESOLVED`. Author owes a tighter description.

## Evaluator notes
- Standard scoring per `evaluator.md`.
- 34 cases in `silos/A_accuracy/eval.json`; total weight 68.
- **4 weight=3 (fatal) cases**: A-014 (cost band declared), A-020 (p95 declared), A-027 (volatility class declared), A-037 (all 27 checkers covered). Failing any of these = spec is fundamentally broken.
- 26 weight=2 cases.
- Pass threshold: 0.80.

## Target / convergence threshold
- **Primary**: ≥ 80% weighted score by round 6.
- **Acceptable**: ≥ 70% with rubric-vs-architecture-bound classification.
- **Hard cap**: 12 rounds.

## Silo-specific anti-patterns
- **"Add 5 new paid checkers" without total $-cost**: every paid addition must include cost projection at 1000 scans/month. Reject specs that don't sum.
- **Market parity hand-waving**: "similar to Bitsight" without naming the specific signal Bitsight emits is not a citation.
- **Ignoring SA calibration**: if you say "no SA calibration changes", you must justify against SENS-003 / SENS-004 / GAP-006.
- **Removing checkers without scoring redistribution**: if you REMOVE a checker, the weight must redistribute (state how) or the cap of 1.0 must be relaxed (state why).

## Inputs / dependencies
- Inputs: Silo C's `spec_final.md` (today baseline), substrate/*, fixtures.
- Output to Silo B: `checker_manifest_contract.md` (consumed for B's per-checker latency/cost calculations).
- If A is mid-flight when B starts, B uses today's measured numbers (from baseline.md § 8) as placeholder and tags every B-spec line that depends on A.
