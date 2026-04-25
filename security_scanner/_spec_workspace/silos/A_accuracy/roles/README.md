# Roles for Silo A

Same convention as Silo C — shared role definitions at `../../../substrate/roles/{author,reviewer,critic,simulator,evaluator}.md`. Silo-specific specializations (per-checker Author target with KEEP/MODIFY/ADD/REMOVE flags + checker manifest contract hard output + Simulator re-runs proposed checker logic on broken_hygiene_synth) are in `../SILO_CONTEXT.md`.

The orchestrator dispatches each role agent with both files in its read-list. See `../ORCHESTRATOR_PROMPT.md`.

Note Silo A's hard output `checker_manifest_contract.md` is consumed by Silo B as a hard input.
