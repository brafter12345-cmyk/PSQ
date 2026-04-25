# Roles for Silo C

To reduce duplication, the 5 role definitions are shared across silos:

- `../../../substrate/roles/author.md`
- `../../../substrate/roles/reviewer.md`
- `../../../substrate/roles/critic.md`
- `../../../substrate/roles/simulator.md`
- `../../../substrate/roles/evaluator.md`

Per-silo specializations (Silo C target, hard outputs, simulator definition redefined as spec-vs-actual oracle) are in `../SILO_CONTEXT.md`.

The orchestrator dispatches each role agent with **both** files in its read-list. See `../ORCHESTRATOR_PROMPT.md` for the dispatch template.

Anti-patterns from the framework script (Author silent-drops, Critic ≥3 or say so, Simulator commit-don't-flag, Evaluator strict-no-upgrade) are embedded verbatim in the role files at `substrate/roles/`.
