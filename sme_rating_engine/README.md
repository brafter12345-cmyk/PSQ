# Phishield SME Rating Engine (VM build)

Flask + Postgres 16 + React rebuild of the legacy vanilla SME Rating Engine,
for the Google VM at **`veilguard.phishield.com/smerating/`** (replacing the
Render deployment). The rating math is **extracted verbatim** from the legacy app
and **locked by a parity gate** — same premiums, new stack.

> The legacy app lives in `../SME Rating Engine/` and stays **frozen** until the
> Render service is retired (Render auto-deploys the blueprint on push, so editing
> that dir would redeploy/break the live Render app during the parallel run).

## Layout

```
sme_rating_engine/
  app.py              Flask backend: serves the React build + Postgres quote API
  sme_db.py           Postgres data layer (psycopg2, fresh schema, JSONB, %s params)
  requirements.txt    flask, flask-cors, gunicorn, psycopg2-binary
  frontend/           Vite + React SPA (built with base=/smerating/)
    src/
      rating-data.js    GENERATED from ../../SME Rating Engine/sme-data.js (gen:data)
      rating-engine.js  VERBATIM calculatePremium + helpers + evaluateUnderwriting
      state.js, App.jsx, steps/Step1..5, components/, lib/ (pdf, api, format)
      styles/sme-rating.css   reused verbatim from the legacy app
    tools/
      gen_rating_data.mjs   legacy sme-data.js -> ESM rating-data.js
      parity.mjs            BLOCKING GATE: new engine == legacy engine
      golden_premiums.json  ground-truth snapshot
  deploy/
    deploy_sme_vm.sh    idempotent VM deploy (pg container + venv + systemd)
    caddy_patch_sme.py  Caddy /smerating/* -> :8002 route
  docs/DEPLOYMENT.md    the VM runbook
```

## Develop

```bash
cd frontend
npm install
npm run dev                 # http://localhost:5173 (root base) — engine + UI live
npm run parity             # MUST be green before shipping (data + 49k premium + 5k UW evals)
npm run gen:data           # regenerate rating-data.js if the legacy sme-data.js changes
```

Backend (needs a Postgres reachable via `DATABASE_URL`):

```bash
DATABASE_URL=postgresql://... PDF_DIR=./data/quote_pdfs py app.py   # :8002
```

## Ship

Parity **must** be green, then follow [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md):
push brafter→rjl667, build the frontend with `SME_BASE_PATH=/smerating/`, tarball,
`deploy_sme_vm.sh`, sha256-verify, browser-verify the mount + a full quote round-trip.
