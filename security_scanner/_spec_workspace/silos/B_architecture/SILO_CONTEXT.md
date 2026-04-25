# Silo B — Architecture / scale / continuous-monitoring context

## Position in framework
Runs in **parallel with Silo A** (after Silo C completes). B consumes A's checker manifest contract as a hard input.

## Target spec (Author's mandate)
End-state architecture for `security_scanner/` supporting:
- **Scheduled rescans** (cron / scheduler — currently absent per ARCH-001)
- **Delta detection** (incremental scanning, cache reuse for stable signals — currently absent per ARCH-003)
- **Webhook push** (action prompts on critical findings — currently absent per ARCH-002)
- **Multi-tenant** (white-label per tenant; tenancy enforcement; currently single-tenant per ARCH-004, ARCH-005, INV-21)
- **Authentication / RBAC** (currently nonexistent per INV-16)
- **Cost-per-scan SLO** (must declare numeric target)
- **p95 wallclock latency SLO** (must declare numeric target; consumes A's manifest)
- **Persistent worker model** (current Render free-tier process recycle assumption per SCN-GAP-002 must be replaced)
- **Migration path** (current inline ALTER TABLE per INV-15 must be replaced; explicit plan for legacy CRM data)

## Hard outputs
1. `silos/B_architecture/spec_final.md` — end-state architecture spec.
2. **Webhook payload schema** (JSON schema or equivalent declarative format).
3. **Tenant model** (table changes; tenant_id as repurposed `reseller` or new column; isolation tests).
4. **Migration plan** (today's SQLite single-tenant → end-state multi-tenant; data ownership; backfill).
5. **Scheduler design** (cron syntax, job queue, retry semantics, idempotency keys).
6. **Cost / latency SLOs** (declared numerics; p95 latency, $/scan at 1000/month).

## Simulation definition (Simulator's mandate)
Walk a fixture scan through the proposed pipeline:
1. Take a fixture (e.g., sun_uni.json with 10 IPs).
2. Trace it through the spec's proposed architecture stages.
3. Output: per-stage latency, per-stage $-cost, cache hit/miss per checker, total wallclock, total $-cost.
4. Use Silo A's `checker_manifest_contract.md` for per-checker latency/$. If A hasn't converged, use today's measured numbers (baseline.md § 8) as placeholder and **flag every line that depends**.

If spec doesn't describe a stage clearly enough to trace, that's `UNRESOLVED`.

## Evaluator notes — DIFFERENT FROM OTHER SILOS
**Silo B's evaluator is a constraint-violation checker**, not a quality scorer. Each case in `silos/B_architecture/eval.json` is binary (violation / not violated). PARTIAL doesn't apply.

- 31 cases in eval.json; all weight=1.
- Cases verify the spec **declares** numeric SLO values (correctness of the values is delegated to a separate human architecture-review pass).
- Tenant-isolation cases verify **interface / test declarations** are present.

A pure-rubric score will degrade to vibes for "architecture quality". Therefore:
- Rubric ≥ 90% (i.e., ≤ 3 violations) is the silo's **mechanical-pass bar**.
- A separate human architecture review pass (outside the rubric loop) is required before consolidation.

## Target / convergence threshold
- **Primary**: ≤ 3 unresolved violations (≥ 90% mechanical pass) by round 6.
- **Acceptable**: ≤ 5 violations with each violation documented as a deferred / out-of-scope item.
- **Hard cap**: 12 rounds.
- **Architecture review**: required as a follow-up step before consolidation; not part of the rubric loop.

## Silo-specific anti-patterns
- **Architecture-without-numbers**: "the system will be fast and scalable" is a violation. Numerics are the floor.
- **Multi-tenancy as a column**: declaring `tenant_id` without specifying enforcement (queries, indexes, tests) is incomplete. Cite interface paths.
- **Webhook without idempotency**: at-least-once delivery + idempotency key + N retries is the minimum spec contract. Silent omission = violation.
- **Migration narrative without data**: "we'll migrate the CRM data to the new schema" without specifying how (script, downtime, rollback) is incomplete.
- **Pretending checkers are A's problem**: if A hasn't converged, USE today's numbers and flag every dependent spec line. Don't punt by saying "TBD per A".

## Inputs / dependencies
- Inputs: Silo C's `spec_final.md`, Silo A's `checker_manifest_contract.md` (or today's measured numbers as placeholder), substrate/*, fixtures.
- Output to Silo D: webhook payload schema (D's monitoring persona consumes it).
