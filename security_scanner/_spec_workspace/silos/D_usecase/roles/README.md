# Roles for Silo D

Same convention — shared role definitions at `../../../substrate/roles/{author,reviewer,critic,simulator,evaluator}.md`. Silo-specific specializations (per-persona output contracts: broker / monitoring / consulting + open-ended) in `../SILO_CONTEXT.md`.

Silo D's Simulator round-trips fixtures through proposed persona schemas and validates against `app.py:1240 create_quote` consumer fields.

The orchestrator dispatches each role agent with both files in its read-list. See `../ORCHESTRATOR_PROMPT.md`.
