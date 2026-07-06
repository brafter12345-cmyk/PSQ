#!/usr/bin/env bash
# SME Rating Engine — VM deploy (idempotent).
#
# Provisions a DEDICATED Postgres 16 container + Python venv + systemd service for
# the SME Rating Engine on the shared Ubuntu VM, ALONGSIDE the scanner. Safe to
# re-run: preserves .env, secrets.env, the Postgres volume, and the PDF data dir,
# and never touches the scanner / Veilguard stacks.
#
# LAYOUT (deliberately separate from the scanner — own port/container/volume/unit):
#   /opt/sme-rating-engine/app    <- extracted code (replaced every deploy)
#   /opt/sme-rating-engine/data   <- quote_pdfs/  (PRESERVED across deploys)
#   /opt/sme-rating-engine/.env, secrets.env (PRESERVED, chmod 600)
#   gunicorn 127.0.0.1:8002 ; systemd sme-rating-engine
#   Postgres container sme-rating-pg on 127.0.0.1:5545 (vol sme_rating_pgdata)
#
# SOURCE OF TRUTH = brafter (origin) master, by convention (tarball deploy, not a
# git checkout). Build the tarball FROM local master AFTER pushing brafter+RJL.
#
# Usage (from the repo root, on master, AFTER the two pushes):
#   # 1. build the React frontend with the /smerating base (PowerShell):
#   #      $env:SME_BASE_PATH='/smerating/'; npm --prefix sme_rating_engine/frontend run build
#   # 2. package app + built dist (exclude junk + live data), copy up:
#   tar -czf /tmp/sme_deploy.tar.gz \
#       --exclude='frontend/node_modules' --exclude='__pycache__' --exclude='*.pyc' \
#       --exclude='quotes.db' --exclude='quote_pdfs' --exclude='.env' \
#       -C sme_rating_engine .
#   gcloud compute scp /tmp/sme_deploy.tar.gz sme_rating_engine/deploy/deploy_sme_vm.sh \
#       veilguard-prod-jnb:/tmp/ --zone=africa-south1-a
#   gcloud compute ssh veilguard-prod-jnb --zone=africa-south1-a \
#       --command="tr -d '\r' < /tmp/deploy_sme_vm.sh > /tmp/deploy_sme_unix.sh; bash /tmp/deploy_sme_unix.sh"
#   # verify VM == master by sha256 (tar preserves mtimes):
#   #   sha256sum /opt/sme-rating-engine/app/app.py   (compare to local master)
set -euo pipefail

# --- knobs (override via env) ------------------------------------------------
APP_ROOT=${APP_ROOT:-/opt/sme-rating-engine}
PORT=${PORT:-8002}
PG_PORT=${PG_PORT:-5545}
PG_DB=${PG_DB:-sme_rating}
PG_USER=${PG_USER:-sme}
PG_CONTAINER=${PG_CONTAINER:-sme-rating-pg}
PG_VOLUME=${PG_VOLUME:-sme_rating_pgdata}
TARBALL=${TARBALL:-/tmp/sme_deploy.tar.gz}
# -----------------------------------------------------------------------------
APP_DIR="$APP_ROOT/app"
DATA_DIR="$APP_ROOT/data"

echo "== [1/7] unpack code to $APP_DIR =="
sudo mkdir -p "$APP_DIR" "$DATA_DIR"; sudo chown -R "$USER:$USER" "$APP_ROOT"
# Clean only the code dir (NOT data/.env/secrets), then extract fresh.
find "$APP_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
tar -xzf "$TARBALL" -C "$APP_DIR"
echo "   code at $APP_DIR ; data preserved at $DATA_DIR"

echo "== [2/7] secrets (generate once, reuse after) =="
if [ ! -f "$APP_ROOT/secrets.env" ]; then
  printf 'PG_PW=%s\nSECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" \
    > "$APP_ROOT/secrets.env"
  chmod 600 "$APP_ROOT/secrets.env"
  echo "   generated new secrets.env"
else
  echo "   reusing existing secrets.env"
fi
# shellcheck disable=SC1091
source "$APP_ROOT/secrets.env"

echo "== [3/7] dedicated Postgres container ($PG_CONTAINER on $PG_PORT) =="
if ! sudo docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  sudo docker run -d --name "$PG_CONTAINER" --restart unless-stopped \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_DB="$PG_DB" \
    -v "$PG_VOLUME":/var/lib/postgresql/data -p 127.0.0.1:"$PG_PORT":5432 \
    postgres:16-alpine
  echo "   created $PG_CONTAINER"
else
  sudo docker start "$PG_CONTAINER" >/dev/null 2>&1 || true
  echo "   $PG_CONTAINER already present"
fi
echo "   waiting for postgres..."
for i in $(seq 1 30); do
  sudo docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 \
    && { echo "   postgres ready"; break; }
  sleep 2; [ "$i" = 30 ] && { echo "   ERROR: postgres not ready"; exit 1; }
done

echo "== [4/7] .env (preserve if present; scaffold on first run) =="
if [ ! -f "$APP_ROOT/.env" ]; then
  cat > "$APP_ROOT/.env" <<ENVEOF
PORT=$PORT
DATABASE_URL=postgresql://$PG_USER:$PG_PW@localhost:$PG_PORT/$PG_DB
PDF_DIR=$DATA_DIR/quote_pdfs
SECRET_KEY=$SECRET_KEY
ENVEOF
  chmod 600 "$APP_ROOT/.env"
  echo "   scaffolded $APP_ROOT/.env"
else
  echo "   preserving existing $APP_ROOT/.env"
fi

echo "== [5/7] python venv + deps =="
cd "$APP_DIR"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt

echo "== [6/7] apply DB schema (idempotent) =="
set -a; source "$APP_ROOT/.env"; set +a
./.venv/bin/python -c "import sme_db; sme_db.init_schema()"

echo "== [7/7] systemd service =="
sudo tee /etc/systemd/system/sme-rating-engine.service >/dev/null <<UNITEOF
[Unit]
Description=Phishield SME Rating Engine (Flask/gunicorn)
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_ROOT/.env
ExecStart=$APP_DIR/.venv/bin/gunicorn app:app --bind 127.0.0.1:$PORT --workers 2 --threads 4 --timeout 120
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
sudo systemctl daemon-reload
sudo systemctl enable sme-rating-engine >/dev/null 2>&1 || true
sudo systemctl restart sme-rating-engine
sleep 4
echo "   service: $(systemctl is-active sme-rating-engine)"

echo "== health check =="
sleep 2
curl -fsS "http://127.0.0.1:$PORT/health" -o /dev/null -w "   /health -> HTTP %{http_code}\n" \
  || echo "   /health probe failed — check: sudo journalctl -u sme-rating-engine -n 50"
echo "DONE.  Caddy edge is wired separately (see deploy/caddy_patch_sme.py)."
