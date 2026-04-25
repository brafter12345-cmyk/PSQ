# Orchestrator prompt — Silo C (Behavioral spec)

**Paste this entire prompt into a FRESH Claude Code session.** It is self-contained: it references absolute paths to all required files. You do NOT need to brief the new session beyond this.

---

# Run Silo C of the Phishield scanner spec-convergence framework

You are the orchestrator for Silo C (Behavioral spec — what the scanner does TODAY). This silo runs FIRST and produces the shared "today" baseline that downstream silos consume.

## Your job
Dispatch the 5 roles (Author / Reviewer / Critic / Simulator / Evaluator) across up to 12 rounds until convergence. You do NOT write spec content yourself — the Author does. You orchestrate.

## Required reading before round 1

Read these in order:
1. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\SILO_CONTEXT.md` — your silo's target
2. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\baseline.md` — substrate
3. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\INVARIANTS.md`
4. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\KNOWN_ISSUES.md`
5. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\GLOSSARY.md`
6. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\eval.json` — rubric (35 cases)
7. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\roles\{author,reviewer,critic,simulator,evaluator}.md` — role definitions

## Fixtures available
At `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\sample\`:
- `phishield_fs.json` (FS, R10M, High)
- `takealot_retail.json` (Retail, R5B, Medium ~235)
- `broken_hygiene_synth.json` (synth, Critical, RSI 0.92)
- `sun_uni.json` (Education, R5B, Medium 209, 10 IPs)
- `ncr_gov.json` (Public Sector, R150M, High 459, 6 IPs)

## Dispatch sequence per round

Each round at `_spec_workspace/silos/C_behavioral/rounds/v<epoch>_r<N>/` (orchestrator creates dir):

1. **Sequential**: dispatch ONE Author agent. Wait for completion. Author writes `spec_v<N>.md`.
2. **Parallel** (single message, three Agent tool calls): dispatch Reviewer + Critic + Simulator. They are independent given the Author's spec. Each writes their named output file.
3. **Sequential**: dispatch Evaluator after all three above complete. Evaluator writes `Evaluator.md` with score block.
4. Read all 4 outputs' "convergence signal" blocks. Decide next action (continue / stop / restart).

### Agent dispatch template
For each role, dispatch with prompt:
```
You are the <ROLE> for Silo C round <N>. Read in order:
- ABSOLUTE_PATH/substrate/roles/<role>.md  (your role definition)
- ABSOLUTE_PATH/silos/C_behavioral/SILO_CONTEXT.md  (silo specifics)
- (For round N>1) all files at ABSOLUTE_PATH/silos/C_behavioral/rounds/v<epoch>_r<N-1>/
- (For non-Author roles in round N) ABSOLUTE_PATH/silos/C_behavioral/rounds/v<epoch>_r<N>/spec_v<N>.md

Then execute your role's mandate. Write your output to ABSOLUTE_PATH/silos/C_behavioral/rounds/v<epoch>_r<N>/<Role>.md (and Simulator_outputs/* if applicable).

End with the convergence-signal block your role's definition specifies.
```

Use background dispatch (`run_in_background: true`) for parallel triple in step 2; orchestrator sleeps until all three notifications arrive.

## Round budget & exit conditions

**Hard cap: 12 rounds.** Stop earlier if:

- **Target hit**: Evaluator score ≥ 90% on the 35 cases (39 total weight) → stop, declare success.
- **Plateau**: Δ score < 2pp for 3 consecutive rounds AND Critic raised 0 new findings for 2 consecutive rounds → stop, declare ceiling. Classify remaining FAIL cases as rubric-bounded vs. architecture-bounded per Evaluator's ceiling section.
- **Restart trigger**: Critic flags `RESTART_TRIGGER: <subsystem>` indicating a subsystem in code that's missing from substrate → preserve current `rounds/` as `rounds/v<epoch>_epoch/`, dispatch a substrate re-extraction agent for the named subsystem, write `rounds/v<epoch+1>_r1/RESTART_NOTE.md`, restart at round 1 of new epoch on corrected baseline.

## Final emission

When stopping, dispatch a consolidation agent to merge the converged `spec_v<N>.md` (final round) into `silos/C_behavioral/spec_final.md` — the standalone authoritative "today" spec. No "Changes from" sections. Implementer / downstream silos need only this file.

## Status reporting

If asked "status?" reply: `Round <N>, role <X> running, elapsed Xm, rubric score <Y>%`. Don't preview findings.

## Hand-off to downstream silos

When `spec_final.md` exists, this silo is done. Silos A/B/D's orchestrator prompts include the path. C does NOT trigger them — the user kicks them off in fresh sessions.

## Notes

- Maintain TodoWrite tracking each round.
- Don't write spec content yourself. Relay agent summaries.
- Cost-conscious: parallel dispatch in step 2 saves ~3× wallclock per round.
- Restart-trigger sensitivity: CRM was already added to baseline post-first-pass. Future risks per KNOWN_ISSUES.md ARCH-001 to ARCH-006.
