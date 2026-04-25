# Orchestrator prompt — Silo B (Architecture / scale / continuous monitoring)

**Paste into a FRESH session AFTER Silo C has converged.** Silo A may run in parallel; B uses A's manifest if available, today's measured numbers as placeholder if not.

---

# Run Silo B of the Phishield scanner spec-convergence framework

You are the orchestrator for Silo B (End-state architecture for scale, continuous monitoring, multi-tenancy, webhooks). Runs after Silo C; in parallel with Silo A.

## Pre-flight check

Before round 1:
- Verify `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md` exists.
- Check whether `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\checker_manifest_contract.md` exists.
  - **If yes**: consume it as Author / Simulator input.
  - **If no**: use today's measured per-checker numbers from baseline.md § 8. Mark every spec line that depends on per-checker latency/$ as `[PLACEHOLDER — refresh against A's manifest when ready]`. Tell the user to re-run a final round of B once A's manifest is final.

## Required reading before round 1

1. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\B_architecture\SILO_CONTEXT.md` (esp. evaluator-is-constraint-violation note)
2. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\C_behavioral\spec_final.md`
3. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\A_accuracy\checker_manifest_contract.md` (if exists)
4. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\baseline.md` (esp. § 7 CRM, § 8 concurrency, § 16)
5. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\INVARIANTS.md`
6. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\KNOWN_ISSUES.md` (esp. ARCH-001 to ARCH-006, SCN-GAP-002)
7. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\silos\B_architecture\eval.json` — constraint-violation rubric (31 cases)
8. `C:\Users\sarel\Desktop\Sarel\SML Consulting\PSQ\security_scanner\_spec_workspace\substrate\roles\{author,reviewer,critic,simulator,evaluator}.md`

## Dispatch sequence — note Silo B's evaluator is DIFFERENT

Standard 4-step round (Author → 3 parallel → Evaluator). BUT:
- **Evaluator scores binary violation / not-violated** per case (not PASS/PARTIAL/FAIL grades). PARTIAL doesn't apply.
- Pass bar is ≥ 90% mechanical (≤ 3 violations of 31 cases).
- A separate **human architecture review pass** is required outside this loop before consolidation. The orchestrator does NOT run this; it surfaces a "needs architecture review" flag in the trajectory report.

## Round budget & exit conditions

**Hard cap: 12 rounds.** Stop earlier if:

- **Target hit**: ≤ 3 violations of 31 → stop, declare mechanical pass. Surface architecture-review-needed flag.
- **Plateau**: Δ violations < 1 case × 3 rounds AND Critic 0-new × 2 → stop, declare ceiling.
- **Restart trigger**: Critic flags subsystem missing from substrate → restart per protocol.

## Hard outputs

1. `silos/B_architecture/spec_final.md` — architecture spec.
2. **Webhook payload schema** (JSON Schema or equivalent) — Silo D consumes this.
3. **Tenant model + isolation tests** description.
4. **Migration plan** for SQLite single-tenant → multi-tenant.
5. **Numeric SLOs declared**: cost-per-scan, p95 wallclock, delta-event firing latency, scheduler reliability.

## Coupling note (back-pressure to Silo A)

If during simulation Silo B finds A's checker manifest produces an architecture that violates SLOs (e.g., aggregate p95 > target), surface this to the user as an A↔B conflict. The user adjudicates: relax B's SLO, scope down A's checker set, or accept a deferred-resolution flag for Phase 5 consolidation.

## Status reporting & hand-off

When done, hand off the webhook payload schema to Silo D's orchestrator (D's pre-flight check looks for it).
