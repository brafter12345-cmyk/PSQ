# Phishield SME Rating Engine — VM Deployment Runbook

**Status: BUILT, not yet deployed.** New Flask + Postgres 16 + React stack that
replaces the legacy Render `sme-rating-engine` service. Mounted under
`https://veilguard.phishield.com/smerating/`, run alongside the scanner on the
shared GCP VM. Adapted from the scanner runbook (`security_scanner/docs/DEPLOYMENT.md`).

---

## TL;DR

| | |
|---|---|
| **Public URL** | **https://veilguard.phishield.com/smerating/** |
| **VM** | `veilguard-prod-jnb` · GCP `rugged-sunbeam-492106-j1` · `africa-south1-a` · `34.35.151.242` · Ubuntu 22.04 |
| **App** | Flask + React, gunicorn under `systemd: sme-rating-engine`, bound `127.0.0.1:8002` |
| **Database** | Dedicated Postgres 16 in Docker `sme-rating-pg`, `127.0.0.1:5545`, db `sme_rating` |
| **Edge** | Caddy reverse-proxies `/smerating/*` → app, terminates TLS |
| **SSH** | `gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a` |

This runs **beside** the scanner (`/scanner/*` → `:8001`, `phishield-scanner-pg` on
`:5544`). Everything here is **separate**: own sub-path, port, container, volume,
and systemd unit — nothing shared, so it can't clash with the scanner or Veilguard.

---

## 1. Architecture — why it needs no prefix awareness

The app is written to own the web root (`/`, `/api`, `/assets`). Caddy's
`handle_path /smerating/*` **strips** `/smerating` before proxying, so Flask sees
root paths unchanged. Two things make that transparent (no `X-Forwarded-Prefix`,
unlike the scanner):

1. **The React bundle is built with `base=/smerating/`** (Vite), so `index.html`
   emits `/smerating/assets/...` — the browser requests those, Caddy strips the
   prefix, Flask serves them from `frontend/dist/assets`. **This base-path build is
   the fix for the asset/colour-scheme break.**
2. **The one API call is base-aware** (`import.meta.env.BASE_URL` + `api/quotes`),
   so it posts to `/smerating/api/quotes` under the mount and `/api/quotes` at root.

```
Internet ──TLS──► Caddy :443 (veilguard.phishield.com)
                    ├── /scanner/*    ──► 127.0.0.1:8001  (scanner, untouched)
                    ├── /smerating/*  ──strip prefix──► 127.0.0.1:8002  (this app)
                    │                                      └── 127.0.0.1:5545  sme-rating-pg
                    └── /*  ──► 127.0.0.1:3000  Veilguard (untouched)
```

---

## 2. Where everything lives (on the VM)

| Thing | Path / name |
|---|---|
| App code | `/opt/sme-rating-engine/app/` (replaced each deploy) |
| PDF store (persistent) | `/opt/sme-rating-engine/data/quote_pdfs/` (**preserved**) |
| Runtime env (secrets) | `/opt/sme-rating-engine/.env` (chmod 600, **not** in git) |
| Generated PG pw + secret | `/opt/sme-rating-engine/secrets.env` (chmod 600, once) |
| Python venv | `/opt/sme-rating-engine/app/.venv/` |
| systemd unit | `/etc/systemd/system/sme-rating-engine.service` |
| gunicorn | `127.0.0.1:8002`, `--workers 2 --threads 4 --timeout 120` |
| Postgres container | `sme-rating-pg` (postgres:16-alpine, `--restart unless-stopped`) |
| Postgres volume | `sme_rating_pgdata` (named Docker volume — **persistent**) |

> Multiple gunicorn workers are safe here: the app holds **no in-memory state**
> (every request is independent and hits Postgres).

---

## 3. Build & deploy

The VM is **tarball-deployed** (`/opt/sme-rating-engine/app` is not a git
checkout). Source of truth = **brafter master by convention** — push before you
build the tarball. `frontend/dist` is git-ignored and **built on the workstation**
(the VM has no Node), then shipped in the tarball.

```bash
# 0. land on local master, push brafter FIRST then RJL (runs pre-push gates)
git push
git push rjl667 master

# 1. build the React frontend WITH the /smerating base (PowerShell — a leading-slash
#    env var under Git Bash mangles the path; use PowerShell or MSYS_NO_PATHCONV=1)
$env:SME_BASE_PATH='/smerating/'; npm --prefix sme_rating_engine/frontend run build
#    verify: dist/index.html references /smerating/assets/...

# 2. package app + built dist (exclude junk + live data), copy up
tar -czf /tmp/sme_deploy.tar.gz \
    --exclude='frontend/node_modules' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='quotes.db' --exclude='quote_pdfs' --exclude='.env' \
    -C sme_rating_engine .
gcloud compute scp /tmp/sme_deploy.tar.gz sme_rating_engine/deploy/deploy_sme_vm.sh \
    veilguard-prod-jnb:/tmp/ --zone=africa-south1-a

# 3. run the idempotent deploy (CRLF-normalise first — tr, not sed)
gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a \
    --command="tr -d '\r' < /tmp/deploy_sme_vm.sh > /tmp/deploy_sme_unix.sh; bash /tmp/deploy_sme_unix.sh"

# 4. verify VM == master by sha256 (tar preserves mtimes)
gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a \
    --command="sha256sum /opt/sme-rating-engine/app/app.py"   # compare to local master
```

The script ([`deploy/deploy_sme_vm.sh`](../deploy/deploy_sme_vm.sh)) unpacks code →
ensures `secrets.env` → ensures the `sme-rating-pg` container → **preserves** `.env`
+ the PDF data dir → venv + `pip install` → `sme_db.init_schema()` → installs/
restarts the systemd unit → health-checks `:8002`.

### Caddy (one-time)

```bash
gcloud compute scp sme_rating_engine/deploy/caddy_patch_sme.py veilguard-prod-jnb:/tmp/ --zone=africa-south1-a
gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a --command="\
  sudo python3 /tmp/caddy_patch_sme.py && \
  sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && \
  sudo systemctl reload caddy"
```

---

## 4. Verification — what "working" looks like

```
GET  /smerating                 → 301 → /smerating/
GET  /smerating/                → 200  (React SPA)
GET  /smerating/assets/*.{js,css} → 200  (NOT 404 — the base-path fix)
GET  /smerating/health          → 200 {"status":"ok","service":"sme-rating-engine"}
POST /smerating/api/quotes      → 201 {id, quoteRef, ...}
GET  /  (Veilguard root)        → unaffected
GET  /scanner/health            → 200 (scanner unaffected)
```

Then browser-verify: open `/smerating/`, confirm **every CSS/JS asset is 200 (not
404)** and the dark theme renders, and run a **full quote round-trip** (Step 1→5,
Save → row appears in Postgres, redeploy → row + PDFs survive).

```bash
sudo docker exec -it sme-rating-pg psql -U sme -d sme_rating \
  -c "SELECT quote_ref, company_name, created_at FROM quotes ORDER BY created_at DESC LIMIT 5;"
```

---

## 5. Day-to-day ops

```bash
systemctl status sme-rating-engine
sudo systemctl restart sme-rating-engine
sudo journalctl -u sme-rating-engine -f
sudo docker exec -it sme-rating-pg psql -U sme -d sme_rating
sudo docker exec sme-rating-pg pg_dump -U sme sme_rating | gzip > ~/sme_rating_$(date +%F).sql.gz
```

> ⚠️ Don't confuse the three Postgres instances: `sme-rating-pg` (5545, SME quotes),
> `phishield-scanner-pg` (5544, scanner scans), Veilguard pgvector (5433). Never
> wipe `sme-rating-pg` — it holds real quotes.

---

## 6. Retiring the Render service (owner dashboard action)

Run the VM in parallel with Render for a few days, then:

1. **Repoint self-references off Render** — the manual generator
   `SME Rating Engine/generate_manual.py` hardcodes `https://sme-rating-engine.onrender.com`
   (lines ~453 + ~1716). Repoint to `https://veilguard.phishield.com/smerating/` and
   regenerate the manual. *(This lives in the legacy dir — do it at retirement, since
   editing that dir triggers a Render redeploy.)*
2. **Remove the `sme-rating-engine` block from repo-root `render.yaml`** (keep
   `life-planner`; `phishield-scanner` is already gone). Gated — do not edit until
   the owner confirms cutover.
3. **Owner, in the Render dashboard:** suspend the `sme-rating-engine` service,
   observe, then delete it.

Render's free-tier disk was ephemeral, so there is no durable quote history to
migrate — the VM starts fresh on Postgres.

---

## 7. Gotchas

- **Frontend build base**: build under PowerShell (`$env:SME_BASE_PATH='/smerating/'`)
  or `MSYS_NO_PATHCONV=1` — a leading-slash env var under Git Bash mangles the path.
  Always verify `dist/index.html` references `/smerating/assets/...`.
- **CRLF**: `tr -d '\r'` the deploy script on the VM (Windows checkout).
- **gcloud via PowerShell** (`& "…\gcloud.cmd" …`), not the Bash tool; the OAuth
  token expires periodically → re-run `gcloud auth login` when scp/ssh fail headless.
- **Don't disturb the scanner / Veilguard**: only add to the Caddyfile inside the
  existing `veilguard.phishield.com {}` block; always `caddy validate` before reload.
