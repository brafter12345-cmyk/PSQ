# Phishield CyberRisk Scanner — VM Deployment Runbook

**Status: LIVE on the Xneelo server at https://apps.phishield.com/scanner/.** Last updated 2026-11-03.

> **Read section 0 first.** Hosting moved from GCP to Xneelo. Sections 1 to 9 describe the
> original GCP VM and the old `deploy/deploy_vm.sh` flow; keep them as history only. The path
> layout, Caddy sub-path design and app internals still apply, but the host, SSH commands and
> deploy script do not. Release record: [RELEASE_2026-11-03.md](RELEASE_2026-11-03.md).

> Handoff note (for Sarel): this is the operational runbook for the production VM
> deployment. Everything below reflects the **actual running state** — it was deployed
> and verified end-to-end (a real `phishield.com` scan completed: score 208 / Medium,
> persisted to Postgres, results page + PDF served). Reproducible scripts live in
> [`security_scanner/deploy/`](../deploy/). See also [`SCALING_IMPLEMENTATION_STATUS.md`](SCALING_IMPLEMENTATION_STATUS.md).

---

## 0. Current production — Xneelo server (verified 2026-11-03)

| | |
|---|---|
| **Public URL** | https://apps.phishield.com/scanner/ (Caddy staff sign-in; `/scanner/health` open) |
| **SSH** | `ssh xneelo` (key-based, sudo). The GCP host and `gcloud` commands below are retired. |
| **App** | `/opt/phishield-scanner/security_scanner`, venv `.venv` (Python 3.12.3), `systemd: phishield-scanner`, gunicorn `127.0.0.1:8001 --workers 1 --threads 16 --timeout 1200` |
| **Database** | Docker `phishield-scanner-pg`, `127.0.0.1:5544`, db `phishield_scanner`. Do not confuse with `127.0.0.1:5433`. |
| **Edge** | Caddy `/etc/caddy/Caddyfile`, `/scanner/*` stripped and proxied to `:8001` with `X-Forwarded-Prefix /scanner` |
| **Shared host** | Also runs corp-rating, sme-rating-engine, veilguard-command-centre, veilguard-whatsapp-session, apps on `:8002` and `:8003`. Never restart them for a scanner release. |
| **Deployed version** | `/opt/phishield-scanner/security_scanner/DEPLOYED_COMMIT` (currently `f7685f7`) |
| **Not on the server** | Node, git checkout, pypdf. The tree is file-deployed, not pulled. |

### 0.1 Release procedure (the one used for f7685f7)

1. Land the release on master and push `origin` first, then `rjl667`, with the pre-push hook on.
   Push from a checkout whose frontend files match the commit byte for byte; a CRLF checkout
   rebuilds a different bundle and fails the bundle gate. Confirm both with
   `git ls-remote <remote> refs/heads/master`.
2. Build the package from the commit, never from a working directory:
   `git archive --format=tar.gz -o scanner_<sha>.tar.gz <sha> security_scanner`. Record its sha256
   and a per-file sha256 manifest. It must contain no `.env`, `*.db`, venvs, caches or captures.
3. Back up on the server before touching live, into
   `/var/backups/phishield-scanner-release-<UTC timestamp>/`: a tgz of `/opt/phishield-scanner`,
   `pg_dump -Fc` of `phishield_scanner` run inside the container, `scans.db`, `pip freeze`, the
   Caddyfile and unit file, plus `SHA256SUMS`. Write the folder path to
   `/var/backups/phishield-scanner-rollback-latest`. Do not display database contents.
4. Stage the package in `/opt/phishield-scanner-staging-<sha>`, compile and run the offline
   transport and safety tests with the live venv, then verify staging still equals the manifest.
5. Copy staging over live with `rsync -a --checksum`, excluding `.env`, `.env.*`, `*.env`, `*.db`,
   `*.sqlite`, `.venv/`, `.venv.py310/`, `__pycache__/` and `scans/`, with no deletes. Re-check
   every manifest hash on live, write `DEPLOYED_COMMIT`, then `systemctl restart phishield-scanner`
   and wait for `curl 127.0.0.1:8001/health` to return 200. Migrations run on start and are idempotent.
6. Verify: bundle hashes, health, public 401 on `/scanner/`, assets and API, fonts, credential
   export status `enabled: false`, other services healthy. Render the dashboard and the three PDF
   tiers from a synthetic fixture in an isolated copy with no env files, a temp SQLite DB and
   network blocked. Never run a paid scan or a real export as a check.

### 0.2 Rollback

```bash
B=$(sudo cat /var/backups/phishield-scanner-rollback-latest)
cd "$B" && sudo sha256sum -c SHA256SUMS
sudo systemctl stop phishield-scanner
sudo mv /opt/phishield-scanner /opt/phishield-scanner.failed-$(date +%Y%m%dT%H%M%S)
sudo tar -xzf "$B/opt-phishield-scanner.tgz" -C /opt      # restores code, venvs, .env, secrets.env
sudo systemctl start phishield-scanner
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/health
```

The f7685f7 schema change is additive (two nullable columns on `credential_export_audit`), so a
code rollback does not need a database restore. Restore the database only for data damage, and
note that it discards scans made since the backup:

```bash
sudo docker exec -i phishield-scanner-pg pg_restore --clean --if-exists -U phishield \
  -d phishield_scanner < "$B/phishield_scanner.pgdump"
```

The backup tgz holds server secrets: keep it root-only and delete old release backups on a schedule.

---

## TL;DR

| | |
|---|---|
| **Public URL** | **https://veilguard.phishield.com/scanner/** |
| **VM** | `veilguard-prod-jnb` · GCP project `rugged-sunbeam-492106-j1` · zone `africa-south1-a` · `n2-standard-8` · **34.35.151.242** · Ubuntu 22.04 |
| **App** | Flask + React, gunicorn under `systemd: phishield-scanner`, bound to `127.0.0.1:8001` |
| **Database** | Dedicated Postgres 16 in Docker `phishield-scanner-pg`, `127.0.0.1:5544`, db `phishield_scanner` |
| **Edge** | Caddy (already on the box) reverse-proxies `/scanner/*` → app, terminates TLS |
| **SSH** | `gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a` |

This is an **interim** deployment on the *one* hostname already pointing at the VM
(`veilguard.phishield.com`), mounted under the **`/scanner`** sub-path so it needs **no
DNS changes**. When a dedicated domain is ready, see [§7 Moving to a root domain](#7-moving-to-a-root-domain).

---

## 1. Why a sub-path, and how it works

The VM is **shared**: it already runs the unrelated **Veilguard** stack (Next.js Command
Centre on `:3000` + ~11 Docker containers + its own pgvector Postgres on `:5433`), all
fronted by **Caddy** on `:80/:443`. Only `veilguard.phishield.com` resolves to this VM
(DNS is at **Hetzner**, `ns*.your-server.de`, *not* Cloud DNS — we can't add records from
gcloud). So the scanner is mounted under `https://veilguard.phishield.com/scanner` rather
than a new subdomain.

The scanner app was originally written assuming it **owns the web root** (`/`, `/api`,
`/static`, `/results`). On the shared host those roots belong to Veilguard, so the app was
made **path-prefix-aware**. Four cooperating pieces (all base-agnostic — they still work at
the root with an empty prefix):

1. **Caddy** (`/etc/caddy/Caddyfile`, inside the `veilguard.phishield.com {}` block):
   ```caddy
   redir /scanner /scanner/ permanent
   handle_path /scanner/* {
       reverse_proxy localhost:8001 {
           header_up X-Forwarded-Prefix /scanner
       }
   }
   ```
   `handle_path` **strips** `/scanner` before proxying (so Flask routes match unchanged),
   and `X-Forwarded-Prefix` tells the app where it's mounted.

2. **Flask** (`app.py`): `ProxyFix(app.wsgi_app, x_prefix=1, ...)` reads `X-Forwarded-Prefix`
   and sets `SCRIPT_NAME=/scanner`, so `request.script_root`, `url_for()`, and redirects
   auto-prefix. The scan-start response `report_url`/`poll_url` are prefixed with
   `request.script_root`.

3. **Templates** (`templates/index.html`, `templates/results.html`): every absolute asset/
   API URL is emitted as `{{ request.script_root }}/...` (e.g. the bundle `<script>`/`<link>`
   and the inline `fetch('/api/...')` calls).

4. **Frontend** (`frontend/`): built with **`SCANNER_BASE_PATH=/scanner`** so Vite's `base`
   becomes `/scanner/static/dashboard/` (this is what fixes the **baked font URLs** in
   `app.css`). `src/base.ts` derives the prefix from `import.meta.env.BASE_URL` and
   `withBase()` wraps all `/api/...` fetches, `EventSource`s, and download hrefs.

```
Internet ──TLS──► Caddy :443 (veilguard.phishield.com)
                    ├── /scanner/*  ──strip prefix + X-Forwarded-Prefix──► 127.0.0.1:8001  (this app, gunicorn)
                    │                                                         └── 127.0.0.1:5544  phishield-scanner-pg (Postgres 16)
                    ├── /ws/client, /api/sub-agents/...  ──► Veilguard backends   (untouched)
                    └── /*  ──► 127.0.0.1:3000  Veilguard Command Centre (Next.js, untouched)
```

---

## 2. Where everything lives (on the VM)

| Thing | Path / name |
|---|---|
| App code | `/opt/phishield-scanner/security_scanner/` |
| Python venv | `/opt/phishield-scanner/security_scanner/.venv/` |
| Runtime env (secrets) | `/opt/phishield-scanner/security_scanner/.env` (chmod 600, **not** in git) |
| Generated PG pw + Flask secret | `/opt/phishield-scanner/secrets.env` (chmod 600, generated once, reused) |
| systemd unit | `/etc/systemd/system/phishield-scanner.service` |
| gunicorn | `127.0.0.1:8001`, `--workers 1 --threads 16 --timeout 1200` |
| Postgres container | `phishield-scanner-pg` (postgres:16-alpine, `--restart unless-stopped`) |
| Postgres volume | `phishield_scanner_pgdata` (named Docker volume — **persistent**) |
| Caddy config | `/etc/caddy/Caddyfile` (scanner block + timestamped `*.bak-scanner-*` backups) |
| `age` binary (credential export) | `/opt/phishield-scanner/security_scanner/bin/age` |

**Single worker on purpose:** without Redis, scan progress (`progress_bus`) and job state
are in-memory, so `--workers 1 --threads 16` keeps them coherent while handling concurrent
connections + SSE. Scans are I/O-bound (port probes), so threads are fine. To scale to
multiple workers, activate Redis first (see §8).

---

## 3. Day-to-day operations

```bash
# SSH in
gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a

# --- app service ---
systemctl status phishield-scanner
sudo systemctl restart phishield-scanner
sudo journalctl -u phishield-scanner -f          # live logs
sudo journalctl -u phishield-scanner -n 100 --no-pager

# --- database ---
sudo docker ps --filter name=phishield-scanner-pg
sudo docker start phishield-scanner-pg           # (it auto-starts on boot)
sudo docker exec -it phishield-scanner-pg psql -U phishield -d phishield_scanner
#   e.g.  SELECT scan_id, domain, status, overall_risk_score, created_at FROM scans ORDER BY created_at DESC LIMIT 10;

# --- edge ---
sudo cat /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy

# --- health checks ---
curl -s https://veilguard.phishield.com/scanner/health          # {"status":"ok",...}
curl -s -o /dev/null -w "%{http_code}\n" https://veilguard.phishield.com/scanner/
```

> ⚠️ **Do NOT delete data in `phishield-scanner-pg` (port 5544).** It holds real user scans.
> This is a *different* database from the Veilguard pgvector on `:5433` — don't confuse them.

---

## 4. Updating / redeploying

Code changes are shipped from a workstation that has the repo + Node. The deploy is a clean
tarball + an **idempotent** script (preserves `.env`, `secrets.env`, and the PG volume).

### Source of truth = brafter (origin) master

The VM is **tarball-deployed** — `/opt/phishield-scanner` is *not* a git checkout and does
*not* pull from GitHub (no `.git`, no remote, no auto-pull). So brafter is the source by
**convention**, enforced by how you deploy:

1. Land changes on local `master`, then push to **brafter FIRST, then RJL** (local `master`'s
   upstream is `origin` = brafter):
   ```bash
   git push                 # → brafter (origin/master)   [runs the pre-push gates + smoke]
   git push rjl667 master   # → RJL (RJL667/PSQ, secondary mirror)
   ```
2. **Build the deploy tarball from local `master`** (== brafter `origin/master`), so what
   ships to the VM is exactly what is on brafter. **Never deploy an unpushed / feature branch.**
3. After deploying, verify VM == brafter by **sha256** (tar preserves the tarball's mtimes, so
   don't trust mtime):
   ```bash
   gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a \
       --command="sha256sum /opt/phishield-scanner/security_scanner/scanner.py"   # compare to local master
   ```

Remotes: `origin` = `github.com/brafter12345-cmyk/PSQ` (brafter) · `rjl667` =
`github.com/RJL667/PSQ`. Rollback: the pre-rjl667 state is preserved as
`backup/master-pre-rjl667-merge-2026-06-30` (`03ce0a2`) on brafter + locally.

```bash
# 1. (only if the frontend changed) rebuild with the /scanner base.
#    IMPORTANT on Git Bash/Windows: set the env var in a shell that does NOT mangle
#    leading-slash paths (PowerShell, or `MSYS_NO_PATHCONV=1`), or Vite bakes a bogus base.
cd security_scanner/frontend
SCANNER_BASE_PATH=/scanner npm run build            # PowerShell: $env:SCANNER_BASE_PATH='/scanner'; npm run build

# 2. package (exclude junk) and copy up
cd ..                                               # security_scanner/
tar -czf /tmp/scanner_deploy.tar.gz --exclude=.git --exclude='*/node_modules' \
    --exclude='*/__pycache__' --exclude='*.pyc' --exclude=scans.db --exclude=.env \
    -C .. security_scanner
gcloud compute scp /tmp/scanner_deploy.tar.gz deploy/deploy_vm.sh \
    veilguard-prod-jnb:/tmp/ --zone=africa-south1-a

# 3. run the idempotent deploy (re-extracts code, pip installs, migrates, restarts).
#    CRLF-normalise first if the script came from a Windows checkout (tr, not sed):
gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a \
    --command="tr -d '\r' < /tmp/deploy_vm.sh > /tmp/deploy_vm_unix.sh; bash /tmp/deploy_vm_unix.sh"
```

The script ([`deploy/deploy_vm.sh`](../deploy/deploy_vm.sh)): unpacks → ensures
`secrets.env` → ensures the PG container → **preserves** an existing `.env` (scaffolds a
placeholder on first run) → venv + `pip install -r requirements.txt` → installs `age` →
applies migrations (`scanner_db.init_schema()`, idempotent) → installs/refreshes the
systemd unit → restarts → health-checks `:8001`.

Caddy was wired once with [`deploy/caddy_patch.py`](../deploy/caddy_patch.py) (idempotent;
backs up + validates). You normally won't re-run it.

---

## 5. Database details & backup

- **DSN** (in `.env` as `DATABASE_URL`): `postgresql://phishield:<pw>@localhost:5544/phishield_scanner`
  (password is in `/opt/phishield-scanner/secrets.env`).
- **Schema**: migrations `0001_initial`, `0002_job_queue`, `0003_usage_ledger` (tables
  `scans`, `scan_checkpoints`, `scan_jobs`, `usage`, `schema_migrations`). Applied
  automatically on every boot — idempotent.
- **Backup** (ad-hoc):
  ```bash
  sudo docker exec phishield-scanner-pg pg_dump -U phishield phishield_scanner \
      | gzip > ~/phishield_scanner_$(date +%F).sql.gz
  ```

---

## 6. Verification — what "working" looks like

All green as of 2026-06-29:

```
GET  /scanner               → 301 → /scanner/
GET  /scanner/              → 200  (scan form; HTML emits /scanner/static/...)
GET  /scanner/static/dashboard/app.{js,css}  → 200
GET  /scanner/static/dashboard/assets/inter-*.woff2  → 200
GET  /scanner/health        → 200 {"status":"ok"}
POST /scanner/api/scan      → 202 {report_url:"/scanner/results/<id>", ...}
GET  /scanner/results/<id>  → 200  (React dashboard; window.RESULTS injected)
GET  /scanner/api/scan/<id>/pdf?type=full → 200 application/pdf
GET  /  (Veilguard root)    → 307  (Next.js — unaffected)
```

End-to-end test scan: `phishield.com` → **completed, score 208 / Medium**, ~2.5 min, row in
Postgres, dashboard + PDF rendered.

---

## 7. Moving to a root domain

When you point a real domain (or subdomain) at the VM later:

1. Add the DNS A record at **Hetzner** → `34.35.151.242` (and AAAA if you want IPv6).
2. Add a **new site block** to `/etc/caddy/Caddyfile` (Caddy auto-issues Let's Encrypt TLS
   on first request once DNS resolves):
   ```caddy
   scan.phishield.com {
       encode gzip zstd
       reverse_proxy localhost:8001
   }
   ```
   (No `X-Forwarded-Prefix` — at the root the app needs no prefix.) `sudo caddy validate ...`
   then `sudo systemctl reload caddy`.
3. **Rebuild the frontend WITHOUT** `SCANNER_BASE_PATH` (so `base` returns to
   `/static/dashboard/`) and redeploy. The templates' `{{ request.script_root }}` and the
   `withBase()` helper both collapse to empty at the root automatically — no source changes.
4. Optionally remove the `/scanner` block from the Veilguard site.

---

## 8. Outstanding / next steps

- **Repoint a dedicated domain** (interim sub-path → §7).
- **Redis** is provisioned in the design but not active here. To scale to multiple gunicorn
  workers, run a Redis container and set `REDIS_URL` in `.env` (activates WS5a/WS6/WS8 and
  lets progress/job state survive across workers), then bump `--workers`.
- **Object store**: PDF pool is local on disk; wire an S3 bucket (`boto3`, config-gated) if
  you want durable/off-box PDFs.
- **Paid provider keys**: `VIRUSTOTAL`/`SECURITYTRAILS`/`SHODAN`/`INTELX`/`DEHASHED` keys are
  live in `.env` (DEHASHED key corrected 2026-07-06, active; IntelX active 50/50); `HIBP`
  absent. All provider keys are optional; the scanner runs without them at reduced coverage.
- **Render retired (2026-07-06)**: the `phishield-scanner` service block was removed from
  `render.yaml`, and the scanner's self-identification (User-Agent + `scanner-info` page) now
  points at the VM (`veilguard.phishield.com/scanner`, static outbound IP `34.35.151.242`).
  Suspend then delete the `phishield-scanner` service in the Render dashboard to finish
  decommission.
- **Monitoring**: app exposes Prometheus metrics at `/scanner/metrics`; not scraped yet.
- **Provider-key readiness — `GET /scanner/health/providers`** (returns **503 when
  degraded**, 200 when healthy). Point an uptime monitor at this. It exists because a
  dead metered key is a *silent* failure mode: scans keep completing and simply report
  breach history as **UNASSESSED** rather than researched, so without a probe the only
  signal is somebody reloading the scan form. `/health` stays a bare liveness check —
  the deploy script gates on it and the app is genuinely up with a dead key, so do not
  make that one fail.

  ```bash
  # any uptime service (UptimeRobot / Better Uptime / Pingdom) → alert on non-200
  https://veilguard.phishield.com/scanner/health/providers
  ```

  Or, with no third party, a cron on the VM:

  ```bash
  */15 * * * * curl -fsS https://veilguard.phishield.com/scanner/health/providers >/dev/null \
    || logger -t scanner-health "PROVIDER KEY DEGRADED — breach history is being reported unassessed"
  ```

  It also reports the **daily budget** for the metered credential providers
  (`providers.dehashed` / `providers.intelx` carry `used` / `cap` / `remaining`).
  **The caps are in HTTP calls, not searches.** Measured on a live scan
  (2026-07-28): one scan costs **1 DeHashed call but 4 IntelX calls** (1
  search-initiate + up to 3 result polls). IntelX's free tier is 50 *searches*
  per day (reset midnight UTC), so the call budget is **200**; setting it to 50
  would throttle at a quarter of the real allowance and wrongly mark dark-web
  sections unassessed while quota remained. DeHashed is a credit pool, so its cap
  is a burn-rate limit rather than the balance.

  The exact instrument for IntelX is its **free** `/authenticate/info` endpoint,
  which reports remaining *searches* authoritatively and would remove the
  call-vs-search estimate entirely. Not yet wired in (see OUTSTANDING); the
  call budget is deliberately loose in the meantime. Both are env-tunable (`INTELX_DAILY_CAP`,
  `DEHASHED_DAILY_CAP`) so a plan change needs no deploy. The counters are read
  from the durable `usage` table, so a restart no longer hands the box a fresh
  allowance it has not got.

  The probe alarms (503) only when a budget is **exhausted**, not when it is
  merely low — a probe that goes red while scans are still fine trains people to
  ignore it. Exhaustion is worth an alarm because every scan until midnight then
  reports that section as UNASSESSED.

  **On a "reserve":** there is deliberately none. Holding back N credits "for a
  real client scan" cannot work while every scan is equal at the queue — the
  reserve would block the client scan exactly as it blocks a demo one. It would
  only be meaningful once scans carry a priority flag, so what exists instead is
  an honest remaining-count you can watch.

  The same probe also reports the **datastore backend** (`providers.datastore`):
  `postgres` healthy, `sqlite_fallback` **degraded**. `scanner_db` falls back to
  SQLite whenever `DATABASE_URL` is unset — right for local dev, silently wrong in
  production. On 2026-07-27 a clobbered `.env` dropped `DATABASE_URL` and the
  service came up serving a stale legacy `scans.db` while the real Postgres
  history sat untouched and invisible, with every health check green. If you are
  deliberately running on SQLite, set `SCANNER_ALLOW_SQLITE=1` and it reports
  `sqlite` without alarming.

### Never let a tarball carry `.env`

`deploy_vm.sh` now excludes `.env` / `.env.*` / `secrets.env` at **extract** time, so
a carelessly built tarball can no longer overwrite server-owned secrets. Build with
the documented `--exclude=.env` anyway — the script warns when a tarball contains
them. This matters because the VM `.env` is **not** a copy of the repo one: it also
holds `GOOGLE_API_KEY`, `DATABASE_URL` and `SECRET_KEY`, none of which are in the
repo. `DATABASE_URL` and `SECRET_KEY` are reconstructible from
`/opt/phishield-scanner/secrets.env` (`PG_PW`, `SECRET_KEY`) with the knob defaults
`phishield` / `phishield_scanner` / port `5544`. `GOOGLE_API_KEY` is **not**
recoverable from the VM at all (it exists nowhere else on the box, and the running
process holds it only in memory) — the owner keeps the authoritative copy on file
and re-supplies it. Confirm a restored key with the fingerprint the readiness probe
reports: `curl -s .../scanner/health/providers` → `providers.web_search_gemini.key_fingerprint`.

  The response names the degraded provider, a non-reversible key fingerprint (so a
  rotation is visible without exposing the key) and the operational impact. It is
  cached for `BREACH_INTEL_HEALTH_TTL_S` (default 300s), so polling costs nothing.
  Prometheus carries the same signal as `provider_key_usable{provider="…"}`.
  Submitting a scan while degraded also returns a `warnings[]` entry in the
  `POST /api/scan` response, so an operator is told at submission time rather than
  discovering it in the finished report.

---

## 9. Gotchas (read before you touch it)

- **Never wipe `phishield-scanner-pg` (5544)** — real user data. It is *not* the Veilguard
  pgvector DB (5433).
- **Frontend build base**: building with a leading-slash env var under Git Bash mangles the
  path (`/scanner` → `/Program Files/Git/scanner`). Build under PowerShell or
  `MSYS_NO_PATHCONV=1`. Always verify `app.css` font URLs start with `/scanner/static/...`.
- **`requirements.txt`** must include `prometheus_client` (hard import in `observability.py`,
  hit during every scan), `psycopg2-binary`, and `pillow` (PDF). These were missing from the
  original core list and are now pinned.
- **Don't disturb the Veilguard stack**: its containers, its Caddy blocks, and `:3000`/`:5433`
  are unrelated and in production. Only add to the Caddyfile inside the existing site block;
  always `caddy validate` before `reload`.
- **Single gunicorn worker** until Redis is active (see §8) — more workers split the
  in-memory progress/job state.
