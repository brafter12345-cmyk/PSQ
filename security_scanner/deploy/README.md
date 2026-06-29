# deploy/

Reproducible deployment scripts for the Phishield CyberRisk Scanner on the production VM.

- **[`deploy_vm.sh`](deploy_vm.sh)** — idempotent VM provisioner: dedicated Postgres
  container + Python venv + systemd `phishield-scanner` service. Preserves `.env`,
  `secrets.env`, and the Postgres volume on re-run.
- **[`caddy_patch.py`](caddy_patch.py)** — wires the `/scanner/*` reverse-proxy into the
  existing Caddy site block (idempotent; backs up + expects `caddy validate` before reload).

👉 **Full runbook, topology, operations, and next steps:
[`../docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).**

Live: **https://veilguard.phishield.com/scanner/**
