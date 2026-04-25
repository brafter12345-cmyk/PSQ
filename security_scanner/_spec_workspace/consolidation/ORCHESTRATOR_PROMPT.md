# Orchestrator prompt — Consolidation (Phase 5)

**Paste into a FRESH session AFTER all four silos (C, A, B, D) have converged with `spec_final.md` in each silo directory.**

---

# Consolidate the four silo specs into a single end-state spec + sequenced roadmap

You are the consolidation orchestrator. Your job:
1. Pre-merge conflict scan across the four silo specs.
2. Surface conflicts for user adjudication — do NOT silently arbitrate.
3. Synthesize a single `spec_final.md` end-state document.
4. Produce sequenced `ROADMAP.md` from today's code → end-state.
5. Produce `TRAJECTORY.md` summarizing per-silo round metrics, ceilings, rubric-bounded vs. architecture-bounded outcomes.

## Pre-flight check

Verify all four exist:
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md`
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\spec_final.md` AND `checker_manifest_contract.md`
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\B_architecture\spec_final.md`
- `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\D_usecase\spec_final.md`

If any is missing — stop. The named silo must run first.

## Step 1 — Pre-merge conflict scan

Dispatch a conflict-scanner agent. Inputs: all 4 spec_final.md files + substrate/INVARIANTS.md + substrate/GLOSSARY.md.

Conflict categories:
1. **Hard-numeric conflicts**: A says +5 paid checkers @ avg $0.05/scan = +$0.25/scan; B says $/scan ≤ $0.10 SLO. Surface.
2. **Field contradictions**: A removes checker X; D's broker schema references field from X. Surface.
3. **Glossary collisions**: same term used with different meanings in different silos. Surface.
4. **Invariant violations**: silo X declares INV-NN preserved; silo Y violates INV-NN with rationale. Conflict if they overlap on the same surface.
5. **Sequencing conflicts**: silo dependencies that didn't actually hold during the silo runs (e.g., B used placeholder numbers because A wasn't ready; A's final manifest changes the numbers — does B still hold?).

Output: `consolidation/conflict_scan.md`. Each conflict labeled C-NN with: silos involved, statements quoted verbatim, severity (hard | soft), proposed resolution options.

## Step 2 — User adjudication gate

Convert each hard conflict into an entry in `consolidation/decisions_required.md`. Format:

```markdown
## D-NN — <one-line title> — silos <X>↔<Y>

### Silo <X>'s position
> [verbatim quote with citation]
**Rationale**: [from silo X spec]

### Silo <Y>'s position
> [verbatim quote with citation]
**Rationale**: [from silo Y spec]

### Resolution options
1. **Adopt X**: implications [...]
2. **Adopt Y**: implications [...]
3. **Hybrid**: [...]
4. **Defer**: leave as deferred / explicit non-goal

### Recommendation (orchestrator's only opinion, not adjudication)
[one-line preference with reasoning]

USER_DECISION: [pending]
```

**Stop and ask the user** to fill in each `USER_DECISION:` before proceeding. The consolidator does NOT silently pick.

## Step 3 — Synthesize `spec_final.md`

Once user decisions are filled in, dispatch a synthesis agent. Inputs: 4 silo specs + adjudicated conflict resolutions + substrate/baseline.md + substrate/INVARIANTS.md + substrate/GLOSSARY.md.

Output: `consolidation/spec_final.md` — ONE standalone document describing the end-state Phishield scanner. NO "Changes from" sections. NO references to silo names within the prose. Implementer needs only this file plus baseline.md (for "today" reference).

Section structure (suggested):
1. End-state overview (cutting-edge scanner: accuracy + cost + architecture + use-cases)
2. Checker manifest (consumes A's contract, post-adjudication)
3. Scoring & analytics (consumes A's accuracy changes + invariants kept)
4. Architecture (consumes B's spec, post-adjudication)
5. Output personas (consumes D's per-persona schemas)
6. Persistence & migration plan
7. Compliance & regulatory exposure
8. Operations: monitoring, scheduling, action-prompting
9. Glossary (consolidated from substrate/GLOSSARY.md plus silo additions)

## Step 4 — Produce `ROADMAP.md`

Sequenced change list from today's code → end-state. Order by:
1. **Dependency** (must come first): e.g., multi-tenant tables before persona output contracts.
2. **Business value** (prioritize broker / monitoring / consulting per user's stated intent).
3. **Cost / risk**.

Format:
```markdown
| # | Change | Touches | Depends on | Effort | Cost | Use-case impact | Owner silo |
|---|---|---|---|---|---|---|---|
```

Group changes into milestones (Quick wins / Phase 1 foundation / Phase 2 use-cases / Phase 3 advanced).

## Step 5 — Produce `TRAJECTORY.md`

Summarize per silo:
- Round-by-round Evaluator scores
- Ceiling type (target hit / plateau / hard cap)
- Rubric-bounded vs. architecture-bounded FAIL cases
- Restart epochs (if any)
- Critic-flagged restart triggers (if any) and their resolution

This is the "honest report" — surfaces where the framework's ceiling was hit, not just successes.

## Outputs (final)

After all steps:
- `consolidation/conflict_scan.md`
- `consolidation/decisions_required.md` (with user decisions filled in)
- `consolidation/spec_final.md` ← **THE master deliverable**
- `consolidation/ROADMAP.md`
- `consolidation/TRAJECTORY.md`

## Hand-off after consolidation

The user now has:
1. A single end-state spec (`consolidation/spec_final.md`) the implementer can build against.
2. A sequenced roadmap (`ROADMAP.md`).
3. An honest trajectory report (`TRAJECTORY.md`).

Per the original plan, the test harness for implementing this spec is a **separate session** — that's where caching belongs (filesystem cache for embeddings / LLM calls in the implementation, not here).

## Notes

- Don't write spec content yourself. Delegate to agents per step.
- The user must adjudicate in Step 2. Wait for them.
- Be transparent about ceilings in TRAJECTORY.md; don't hide architecture-bounded cases.
- If any silo declared `ARCHITECTURAL_CEILING` during its run, surface that as a top-level finding — those drive future framework iterations.
