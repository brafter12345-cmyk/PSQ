# Roles for Silo B

Same convention — shared role definitions at `../../../substrate/roles/{author,reviewer,critic,simulator,evaluator}.md`. Silo-specific specializations in `../SILO_CONTEXT.md`.

**Important**: Silo B's Evaluator is **constraint-violation, not quality-scoring**. PARTIAL doesn't apply. See `../SILO_CONTEXT.md` § Evaluator notes for details.

A separate human architecture-review pass is required outside the rubric loop before consolidation.

The orchestrator dispatches each role agent with both files in its read-list. See `../ORCHESTRATOR_PROMPT.md`.
