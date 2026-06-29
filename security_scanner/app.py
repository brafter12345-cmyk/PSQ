"""
Cyber Insurance Security Scanner — Flask API
Endpoints:
  POST /api/scan           {"domain": "example.co.za", "industry": "finance", "annual_revenue": 5000000}
  GET  /api/scan/<id>      → JSON results or {"status": "pending"}
  GET  /api/scan/<id>/pdf  → download PDF report
  GET  /results/<id>       → HTML visual report
  GET  /api/history/<dom>  → last 10 scans for a domain
"""

import hmac
import io
import os
import json
import queue
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import wraps

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, render_template, abort, send_file, Response, redirect, url_for, flash
from flask_cors import CORS

from scanner import SecurityScanner

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
CORS(app)  # Allow cross-origin calls from Vercel frontend

# When fronted by a reverse proxy that mounts the app under a sub-path (e.g. Caddy
# `handle_path /scanner/*` → X-Forwarded-Prefix: /scanner), honour the forwarded
# prefix/proto/host so url_for, request.script_root and redirects are sub-path aware.
# No-op for a root deploy (no X-Forwarded-* headers ⇒ script_root stays "").
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


@app.template_filter('zar')
def zar_filter(value):
    try:
        return f"R {float(value):,.2f}"
    except (ValueError, TypeError):
        return "R 0.00"


HIBP_API_KEY           = os.environ.get("HIBP_API_KEY")            # Optional
DEHASHED_EMAIL         = os.environ.get("DEHASHED_EMAIL")          # Optional — paid
DEHASHED_API_KEY       = os.environ.get("DEHASHED_API_KEY")        # Optional — paid
VIRUSTOTAL_API_KEY     = os.environ.get("VIRUSTOTAL_API_KEY")      # Optional — free tier
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY")  # Optional — free tier
SHODAN_API_KEY         = os.environ.get("SHODAN_API_KEY")          # Optional — free account
INTELX_API_KEY         = os.environ.get("INTELX_API_KEY")          # Optional — free tier
DB_PATH = os.environ.get("DB_PATH", "scans.db")
# WS1: the scanner's `scans`/`scan_checkpoints` tables live in scanner_db (Postgres
# when DATABASE_URL is set, else this same SQLite file). The CRM tables stay on the
# legacy get_db() below; scanner<->CRM links were dropped, so there is no join.
import scanner_db
from progress_bus import get_progress_bus
from job_queue import make_job_queue
# Default 2 for the Render 512MB / 1-worker tier (env-overridable via
# MAX_CONCURRENT_SCANS; production sets it explicitly). Per-process semaphore.
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_SCANS", "2"))

VALID_INDUSTRIES = [
    "Agriculture", "Mining", "Construction", "Wholesale Trade",
    "Communications", "Consumer", "Education", "Energy",
    "Entertainment", "Financial Services", "Finance", "Healthcare",
    "Hospitality", "Industrial / Manufacturing", "Manufacturing",
    "Legal", "Media", "Pharmaceuticals", "Public Sector", "Research",
    "Retail", "Services", "Technology", "Tech", "Transportation",
    "Government", "Other",
]

_semaphore = threading.Semaphore(MAX_CONCURRENT)
# Longest a queued scan waits for a slot before failing visibly. A hung
# scan would otherwise hold the semaphore forever and every later scan
# would sit at status "pending" with no error surfaced to the caller.
# 15 min ≈ two back-to-back worst-case full scans (~510s each).
SCAN_QUEUE_TIMEOUT_S = int(os.environ.get("SCAN_QUEUE_TIMEOUT_S", "900"))

# WS8: SSE progress now flows through progress_bus (get_progress_bus) — an
# append-only log with replay+tail (in-process default, Redis cross-worker). The old
# in-process queue.Queue dict + TTL sweep were removed.


@contextmanager
def _release_on_exit(sem):
    """Release an already-acquired semaphore on exit. Companion to the
    bounded `_semaphore.acquire(timeout=...)` in run_scan — `with sem:`
    can't be used there because it would re-acquire."""
    try:
        yield
    finally:
        sem.release()


# ---------------------------------------------------------------------------
# Endpoint protection: opt-in shared-secret auth + per-IP rate limiting
# ---------------------------------------------------------------------------

# Auth is opt-in: with SCANNER_API_KEY unset (current deployments) behaviour
# is unchanged. Once the env var is set on Render AND the frontend sends the
# matching X-Api-Key header, expensive / state-changing endpoints reject
# anonymous callers.
SCANNER_API_KEY = os.environ.get("SCANNER_API_KEY")


def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if SCANNER_API_KEY:
            supplied = request.headers.get("X-Api-Key", "")
            if not hmac.compare_digest(supplied, SCANNER_API_KEY):
                return jsonify({"error": "Unauthorized — missing or invalid X-Api-Key"}), 401
        return f(*args, **kwargs)
    return wrapper


class _RateLimiter:
    """Fixed-window per-IP limiter, per gunicorn worker (Render runs 2
    workers, so effective limits are ~2x the configured value — fine for
    abuse damping; the scan semaphore remains the hard concurrency cap).
    In-house on purpose: no new dependency, no shared storage needed."""

    def __init__(self, max_calls: int, window_s: int):
        self.max_calls = max_calls
        self.window_s = window_s
        self._hits = {}  # ip -> (window_start_epoch, count)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            if len(self._hits) > 10000:  # bound memory under address-spraying
                self._hits.clear()
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self.window_s:
                start, count = now, 0
            count += 1
            self._hits[key] = (start, count)
            return count <= self.max_calls


# Scan-class endpoints launch real work (threads, paid-API credits); the
# default 30/h per IP sits above the physical throughput of 2 scan slots
# (~12-24 scans/h), so legitimate sequential use is never throttled.
_scan_limiter = _RateLimiter(int(os.environ.get("SCAN_RATE_LIMIT_PER_HOUR", "30")), 3600)
_light_limiter = _RateLimiter(int(os.environ.get("LIGHT_RATE_LIMIT_PER_HOUR", "120")), 3600)


def rate_limited(limiter):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # First X-Forwarded-For hop is the real client on Render;
            # remote_addr alone would be the platform proxy.
            ip = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or request.remote_addr or "unknown")
            if not limiter.allow(ip):
                return jsonify({"error": "Rate limit exceeded — try again later"}), 429
            return f(*args, **kwargs)
        return wrapper
    return deco

CHECKER_MANIFEST = [
    {"section": "Discovery", "checkers": [
        {"id": "ip_discovery", "label": "IP Discovery"},
        {"id": "web_ranking", "label": "Web Ranking"},
    ]},
    {"section": "Core Security", "checkers": [
        {"id": "ssl", "label": "SSL / TLS Certificate"},
        {"id": "http_headers", "label": "HTTP Security Headers"},
        {"id": "website_security", "label": "Website Security"},
        {"id": "waf", "label": "WAF / DDoS Protection"},
    ]},
    {"section": "Information Security", "checkers": [
        {"id": "info_disclosure", "label": "Information Disclosure"},
    ]},
    {"section": "Email Security", "checkers": [
        {"id": "email_security", "label": "Email Authentication"},
        {"id": "email_hardening", "label": "Email Hardening"},
    ]},
    {"section": "Network & Infrastructure", "checkers": [
        {"id": "dns_infrastructure", "label": "DNS & Open Ports", "per_ip": True},
        {"id": "high_risk_protocols", "label": "High-Risk Protocols", "per_ip": True},
        {"id": "shodan_vulns", "label": "Shodan Vulnerabilities", "per_ip": True},
        {"id": "osv_vulns", "label": "OSV.dev CVE Enrichment"},
        {"id": "dnsbl", "label": "DNSBL / Blacklists", "per_ip": True},
        {"id": "cloud_cdn", "label": "Cloud & CDN"},
        {"id": "vpn_remote", "label": "VPN / Remote Access"},
        {"id": "external_ips", "label": "External IP Aggregation"},
    ]},
    {"section": "Exposure & Reputation", "checkers": [
        {"id": "breaches", "label": "Data Breaches (HIBP)"},
        {"id": "dehashed", "label": "Credential Leaks"},
        {"id": "credential_risk", "label": "Credential Risk Assessment"},
        {"id": "exposed_admin", "label": "Exposed Admin Panels"},
        {"id": "virustotal", "label": "VirusTotal Intelligence"},
        {"id": "subdomains", "label": "Subdomain Recon"},
        {"id": "fraudulent_domains", "label": "Lookalike Domains"},
        {"id": "related_domains", "label": "Supply-Chain / Related Domains"},
        {"id": "dependency_manifests", "label": "Exposed Dependency Manifests"},
        {"id": "third_party_js", "label": "Third-Party JavaScript"},
        {"id": "email_vendor_surface", "label": "Email-Vendor Surface (SPF)"},
        {"id": "cms_plugin_sbom", "label": "CMS Plugin Surface"},
        {"id": "vendor_breach", "label": "Vendor Breach Correlation"},
        {"id": "third_party_correlation", "label": "Cross-Correlation (HR × SPF × Breach)"},
    ]},
    {"section": "Technology & Governance", "checkers": [
        {"id": "tech_stack", "label": "Technology Stack"},
        {"id": "domain_intel", "label": "Domain Intelligence"},
        {"id": "securitytrails", "label": "SecurityTrails DNS"},
        {"id": "security_policy", "label": "Security Policy & VDP"},
        {"id": "payment_security", "label": "Payment Security"},
        {"id": "privacy_compliance", "label": "Privacy Compliance"},
        {"id": "glasswing", "label": "AI Readiness (Glasswing)"},
    ]},
    # Note: insurance_analytics was previously listed here as a "checker"
    # but is actually a post-scan phase (RSI + DBI + FIC + Remediation
    # all run from cat_results); progress is emitted under that phase
    # name in scanner.py but it's not a discrete category in results.
    # Removed 2026-05-27 audit fix.
]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # WS1: the scanner tables (scans, scan_checkpoints) are owned by scanner_db now
    # — Postgres when DATABASE_URL is set, else the same SQLite file. The CRM tables
    # below stay on the legacy get_db().
    scanner_db.init_schema()
    with get_db() as conn:

        # Benchmark scans pool (SCN-028) - feeds peer-rating percentile
        # calculations in peer_benchmarking.py. Three source classes:
        #   'benchmark_pool'    - bi-weekly public-domain scans curated
        #                         by us (no consent needed)
        #   'lower_tier_upsell' - scans of Phishield's existing lower-
        #                         tier clients (~4,000 entities); no
        #                         broker intermediating, Phishield owns
        #                         the client relationship
        #   'client_optin'      - broker-paid scans contributed with
        #                         explicit consent (default opt-out)
        conn.execute("""CREATE TABLE IF NOT EXISTS benchmark_scans (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            industry TEXT,
            sub_industry TEXT,
            annual_revenue_zar INTEGER,
            revenue_band TEXT,
            risk_score INTEGER,
            critical_findings INTEGER,
            rsi_score REAL,
            ssl_grade TEXT,
            scan_timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            scan_results_json TEXT
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bench_industry ON benchmark_scans(industry, sub_industry, revenue_band)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bench_active ON benchmark_scans(is_active)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_bench_source ON benchmark_scans(source)")

        conn.commit()


# WS1: these delegate to scanner_db (Postgres when DATABASE_URL is set, else the
# same SQLite file). Signatures unchanged so every call site is untouched.
def save_scan(scan_id: str, domain: str, industry: str = "other",
              annual_revenue: float = 0, country: str = ""):
    scanner_db.save_scan(scan_id, domain, industry, annual_revenue, country)


def update_scan(scan_id: str, results: dict):
    scanner_db.update_scan(scan_id, results)


def mark_failed(scan_id: str, error: str):
    scanner_db.mark_failed(scan_id, error)


def fetch_scan(scan_id: str):
    return scanner_db.fetch_scan(scan_id)


# Scans hold status "pending" for their whole run (there is no "running"
# state), so the stale threshold must clear worst-case scan duration
# (~510s) PLUS the maximum semaphore queue wait (SCAN_QUEUE_TIMEOUT_S,
# default 900s). 45 min default leaves ~2x headroom. A dyno restart
# orphans in-flight scans; without this check their rows poll "pending"
# forever.
STALE_PENDING_S = int(os.environ.get("STALE_PENDING_SCAN_S", "2700"))


def _scan_is_stale(row: dict) -> bool:
    try:
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created).total_seconds() > STALE_PENDING_S
    except (KeyError, TypeError, ValueError):
        return False


def _now():
    return datetime.now(timezone.utc).isoformat()




# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

def run_scan(scan_id: str, domain: str, industry: str = "other",
             annual_revenue: float = 0, annual_revenue_zar: int = 0, country: str = "",
             include_fraudulent_domains: bool = False, client_ips: list = None,
             skip_dehashed: bool = False, skip_intelx: bool = False,
             regulatory_flags: dict = None, sub_industry: str = None,
             related_domains: list = None):
    # WS8: progress flows through the bus (in-process default, Redis cross-worker
    # when REDIS_URL is set), so a reconnecting/late SSE client replays the backlog.
    bus = get_progress_bus()

    def on_progress(event):
        bus.publish(scan_id, event)

    if not _semaphore.acquire(timeout=SCAN_QUEUE_TIMEOUT_S):
        msg = (f"No scan slot became free within {SCAN_QUEUE_TIMEOUT_S // 60} "
               "minutes (scanner busy or a previous scan hung) — please retry")
        mark_failed(scan_id, msg)
        bus.publish(scan_id, {"type": "error", "message": msg})
        return
    with _release_on_exit(_semaphore):
        try:
            scanner = SecurityScanner(
                hibp_api_key=HIBP_API_KEY,
                dehashed_email=None if skip_dehashed else DEHASHED_EMAIL,
                dehashed_api_key=None if skip_dehashed else DEHASHED_API_KEY,
                virustotal_api_key=VIRUSTOTAL_API_KEY,
                securitytrails_api_key=SECURITYTRAILS_API_KEY,
                shodan_api_key=SHODAN_API_KEY,
                intelx_api_key=None if skip_intelx else INTELX_API_KEY,
            )
            scanner._regulatory_flags = regulatory_flags
            scanner._sub_industry = sub_industry
            import observability
            with observability.observe_scan(scan_id, domain):  # WS9: count + time + trace
                results = scanner.scan(
                    domain, on_progress=on_progress,
                    industry=industry, annual_revenue=annual_revenue,
                    annual_revenue_zar=annual_revenue_zar,
                    country=country,
                    include_fraudulent_domains=include_fraudulent_domains,
                    client_ips=client_ips,
                    related_domains=related_domains,
                    # WS3: persist per-checker checkpoints under this scan_id; resume=True
                    # so a requeue (WS2) skips already-done checkers without re-spending.
                    scan_id=scan_id, resume=True,
                )
            try:
                observability.record_checker_durations(
                    results.get("checker_durations")
                    or results.get("scan_context", {}).get("checker_durations", {}))
            except Exception:
                pass

            # Post-scan: scan_context (peer rating needs sub_industry +
            # annual_revenue_zar) + critical findings count + peer rating
            # vs the benchmark pool (SCN-028).
            try:
                from peer_benchmarking import (
                    count_critical_findings, compute_peer_rating, revenue_band,
                )
                # Ensure scan_context carries the fields peer_benchmarking
                # expects (scanner.scan() does not include sub_industry or
                # annual_revenue_zar by default)
                results.setdefault("scan_context", {})
                results["scan_context"]["sub_industry"] = sub_industry
                results["scan_context"]["annual_revenue_zar"] = annual_revenue_zar
                # Critical findings count - hero metric replacing compliance %
                crit = count_critical_findings(results)
                results.setdefault("insurance", {})["critical_findings"] = crit
                # Peer rating - opens a fresh DB connection so the
                # rating compute can read the benchmark pool
                with get_db() as bench_conn:
                    peer = compute_peer_rating(results, bench_conn)
                results["insurance"]["peer_benchmarking"] = peer
            except Exception as _peer_err:
                # Peer rating is non-fatal - scan must complete even if
                # the benchmark pool is unreachable or thin
                results.setdefault("insurance", {})["peer_benchmarking"] = {
                    "status": "error", "error": str(_peer_err)[:200],
                }

            update_scan(scan_id, results)

            # WS4: render the PDF in the separate PDF worker pool and store it to
            # object storage (replaces the ephemeral scans/<domain>/ disk archive).
            # The download endpoint then serves from the store; reportlab is off the
            # request path for the common case.
            try:
                from pdf_service import enqueue_pdf
                enqueue_pdf(scan_id, "full", results)
            except Exception:
                pass  # PDF generation is best-effort; never fails the scan

            bus.publish(scan_id, {"type": "complete"})
        except Exception as e:
            mark_failed(scan_id, str(e))
            bus.publish(scan_id, {"type": "error", "message": str(e)})


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

import re
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

def valid_domain(domain: str) -> bool:
    domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    return bool(_DOMAIN_RE.match(domain)) and len(domain) <= 253


# WS2: the job queue + in-process worker pool. The job is run_scan(**payload). With
# QUEUE_BACKEND=postgres, enqueue is durable and a separate worker tier (worker.py)
# runs the jobs instead of the in-process pool.
def _run_scan_job(payload: dict):
    run_scan(**payload)


SCAN_QUEUE = make_job_queue(
    _run_scan_job, workers=MAX_CONCURRENT,
    maxsize=int(os.environ.get("SCAN_QUEUE_MAXSIZE", "100")))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scanner-info", methods=["GET"])
def scanner_info():
    """Public scanner-identity page for security teams investigating
    scanner traffic. Mirrors the URL embedded in the scanner's
    User-Agent header so anyone investigating suspicious requests can
    verify out-of-band. Indexable / cacheable / stable - see
    templates/scanner_info.html. Same pattern used by Bitsight,
    SecurityScorecard, etc."""
    return render_template("scanner_info.html")


@app.route("/api/preflight", methods=["POST"])
@require_api_key
@rate_limited(_light_limiter)
def preflight():
    """Run flag auto-detection BEFORE the full scan starts so the broker
    form can pre-fill checkboxes with sensible defaults. Returns the
    auto-detected flags + evidence per flag. Single HTTP fetch to the
    target domain - typical wall time 3-8 seconds. The frontend posts
    domain + sub_industry, then renders the returned flags as
    pre-checked / pre-suggested options the broker can confirm or
    override before submitting the full scan."""
    from flag_inference import run_preflight
    data = request.get_json(silent=True) or {}
    domain = str(data.get("domain", "")).strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    if not domain or not valid_domain(domain):
        return jsonify({"status": "invalid_domain", "error": "Invalid or missing domain"}), 400
    sub_industry = str(data.get("sub_industry", "")).strip() or None
    industry = str(data.get("industry", "")).strip() or None
    try:
        result = run_preflight(domain, sub_industry=sub_industry, industry=industry)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/dehashed/balance", methods=["GET"])
@require_api_key
@rate_limited(_light_limiter)
def dehashed_balance():
    """Check Dehashed API credit balance without using a credit."""
    if not DEHASHED_API_KEY:
        return jsonify({"status": "no_api_key", "balance": None})
    try:
        import requests as req
        r = req.post("https://api.dehashed.com/v2/search",
                     json={"query": "domain:example.com", "page": 1, "size": 1},
                     headers={"Content-Type": "application/json",
                              "Dehashed-Api-Key": DEHASHED_API_KEY},
                     timeout=10)
        if r.status_code == 200:
            data = r.json()
            return jsonify({"status": "active", "balance": data.get("balance")})
        elif r.status_code == 401:
            return jsonify({"status": "inactive", "balance": None,
                            "error": r.json().get("error", "Auth failed")})
        return jsonify({"status": "error", "balance": None})
    except Exception as e:
        return jsonify({"status": "error", "balance": None, "error": str(e)})


@app.route("/api/intelx/balance", methods=["GET"])
@require_api_key
@rate_limited(_light_limiter)
def intelx_balance():
    """Check IntelX API credit balance."""
    if not INTELX_API_KEY:
        return jsonify({"status": "no_api_key", "balance": None})
    try:
        import requests as req
        r = req.get("https://free.intelx.io/authenticate/info",
                     headers={"X-Key": INTELX_API_KEY}, timeout=10)
        if r.status_code == 200:
            data = r.json()
            # Extract search credits from paths
            paths = data.get("paths", {})
            search_info = paths.get("/intelligent/search", {})
            credits_left = search_info.get("Credit", 0)
            credits_max = search_info.get("CreditMax", 0)
            return jsonify({"status": "active", "balance": credits_left,
                            "max_credits": credits_max})
        return jsonify({"status": "error", "balance": None})
    except Exception as e:
        return jsonify({"status": "error", "balance": None, "error": str(e)})


@app.route("/api/credential-export", methods=["POST"])
@require_api_key
@rate_limited(_scan_limiter)
def credential_export():
    """On-demand encrypted credential export (Phase 2 / Manual 6.4). Re-queries
    DeHashed live, builds the full CSV (incl passwords), encrypts it, and streams
    it back as a one-time download. NOTHING is stored. Gated on `consent` (the
    signed consent form is enforced operationally before this is called)."""
    data = request.get_json(force=True, silent=True) or {}
    domain = str(data.get("domain", "")).strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    consent = bool(data.get("consent"))
    age_pub = (data.get("age_public_key") or "").strip() or None
    passphrase = (data.get("passphrase") or "").strip() or None
    if not domain or not consent:
        return jsonify({"status": "error",
                        "error": "domain and explicit consent:true are required"}), 400
    if not DEHASHED_API_KEY:
        return jsonify({"status": "error", "error": "DeHashed not configured"}), 503
    if not (age_pub or passphrase):
        return jsonify({"status": "error",
                        "error": "provide age_public_key (preferred) or passphrase"}), 400
    # Pull recency clustering (breach-date guesstimates) + IntelX leak-reference
    # postings from the domain's latest completed scan, so the export carries the
    # same date clustering as the dashboard WITHOUT spending new credits. Both
    # are optional — a missing/old scan just yields a dateless export.
    source_meta, leak_references = {}, []
    try:
        from scanner import COMBO_LIST_SOURCES
        srow = scanner_db.latest_completed_for_domain(domain)  # WS1: scanner store
        if srow and srow["results"]:
            cats = (json.loads(srow["results"]) or {}).get("categories", {})
            for s in (cats.get("dehashed", {}) or {}).get("enriched_sources", []) or []:
                nm = (s.get("name") or "").lower().strip()
                if nm:
                    source_meta[nm] = {"date": s.get("breach_date", ""),
                                       "combo": nm in COMBO_LIST_SOURCES}
            leak_references = (cats.get("intelx", {}) or {}).get("recent_results", []) or []
    except Exception:
        source_meta, leak_references = {}, []  # enrichment is best-effort
    try:
        from credential_export import generate_encrypted_export
        fname, blob, method, n = generate_encrypted_export(
            domain, DEHASHED_API_KEY, age_recipient=age_pub, passphrase=passphrase,
            source_meta=source_meta, leak_references=leak_references)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)[:200]}), 500
    from flask import Response
    return Response(blob, mimetype="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename={fname}",
        "X-Export-Method": method, "X-Record-Count": str(n),
        "Cache-Control": "no-store"})


@app.route("/api/age-check")
def age_check():
    """Credit-free health probe for the Phase 2 age path: confirms the `age`
    binary resolves and runs on the live deploy. Reuses the same resolver the
    export uses so this proves the real path, not a lookalike."""
    import subprocess
    from credential_export import _age_bin
    age_bin = _age_bin()
    try:
        v = subprocess.run([age_bin, "--version"], capture_output=True, timeout=10)
        return jsonify({"age_available": v.returncode == 0,
                        "version": v.stdout.decode("utf-8", "replace").strip(),
                        "bin": age_bin})
    except Exception as e:
        return jsonify({"age_available": False, "bin": age_bin, "error": str(e)[:160]})


@app.route("/api/scan", methods=["POST"])
@require_api_key
@rate_limited(_scan_limiter)
def start_scan():
    data = request.get_json(silent=True) or {}
    domain = str(data.get("domain", "")).strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]

    if not domain or not valid_domain(domain):
        return jsonify({"error": "Invalid or missing domain"}), 400

    # Parse optional insurance context fields
    industry = str(data.get("industry", "Other")).strip()
    if industry not in VALID_INDUSTRIES:
        industry = "Other"
    try:
        annual_revenue = float(data.get("annual_revenue", 0))
    except (ValueError, TypeError):
        annual_revenue = 0
    try:
        annual_revenue_zar = int(data.get("annual_revenue_zar", 0))
    except (ValueError, TypeError):
        annual_revenue_zar = 0
    country = str(data.get("country", "")).strip()
    sub_industry = str(data.get("sub_industry", "")).strip() or None
    include_fraudulent_domains = bool(data.get("include_fraudulent_domains", False))
    skip_dehashed = bool(data.get("skip_dehashed", False))
    skip_intelx = bool(data.get("skip_intelx", False))

    # Regulatory exposure flags (default: POPIA only).
    # Each flag also carries an audit-trail "auto_detected" dict from the
    # pre-flight endpoint so the report can show both broker confirmation
    # AND auto-detection independently (FAIS audit defensibility).
    regulatory_flags = {}
    if data.get("gdpr_applicable"):
        regulatory_flags["gdpr"] = True
    if data.get("pci_applicable"):
        regulatory_flags["pci"] = True
    # New flags (broker-confirmed via form, optionally pre-filled from pre-flight)
    if data.get("listed_company"):
        regulatory_flags["listed_company"] = True
    if data.get("b2c"):
        regulatory_flags["b2c"] = True
    if data.get("accountable_institution"):
        regulatory_flags["accountable_institution"] = True
    sub_industry_detail = str(data.get("sub_industry_detail", "")).strip() or None
    if sub_industry_detail:
        regulatory_flags["sub_industry_detail"] = sub_industry_detail
    try:
        other_j = int(data.get("other_jurisdictions", 0))
        if other_j > 0:
            regulatory_flags["other_jurisdictions"] = other_j
    except (ValueError, TypeError):
        pass
    # Pre-flight auto-detected results - passed through verbatim from
    # the broker's pre-flight call (or empty if no pre-flight ran).
    # Used for the flag audit panel in the report; does NOT drive any
    # calculation - broker's flags are authoritative.
    auto_detected = data.get("auto_detected_flags") or {}
    if isinstance(auto_detected, dict):
        regulatory_flags["_auto_detected"] = auto_detected

    # Parse client-supplied IPs (optional). Only publicly routable addresses
    # are accepted: an attacker-supplied RFC1918 / loopback / link-local /
    # CGNAT address would otherwise be port-scanned from inside the hosting
    # network (SSRF) the moment the scanner runs on infrastructure with
    # internal routing. Capped at 25 — each IP fans out to 4 per-IP checkers.
    import ipaddress as _ipaddress
    raw_client_ips = data.get("client_ips", [])
    client_ips = []
    rejected_client_ips = []
    if isinstance(raw_client_ips, list):
        for ip_str in raw_client_ips[:25]:
            candidate = str(ip_str).strip()
            try:
                ip_obj = _ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip_obj.is_global:
                client_ips.append(candidate)
            else:
                rejected_client_ips.append(candidate)

    # Broker-declared related/supplier domains (S-1 supply-chain). Each is
    # subject to the same valid_domain check as the primary; v1.1 will add
    # auto-discovery from cert SAN/WHOIS/analytics ID feeding broker confirm.
    raw_related = data.get("related_domains", [])
    related_domains = []
    if isinstance(raw_related, list):
        for rd_str in raw_related:
            rd_clean = str(rd_str).strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
            if rd_clean and valid_domain(rd_clean):
                related_domains.append(rd_clean)

    scan_id = str(uuid.uuid4())
    effective_revenue = annual_revenue_zar if annual_revenue_zar > 0 else annual_revenue
    save_scan(scan_id, domain, industry, effective_revenue, country)


    # WS2: enqueue instead of spawning a thread. Returns 429 when the queue is full
    # (the system's first submit-time admission control). In-process workers run the
    # job by default; with QUEUE_BACKEND=postgres a separate worker tier drains it.
    payload = {
        "scan_id": scan_id, "domain": domain, "industry": industry,
        "annual_revenue": annual_revenue, "annual_revenue_zar": annual_revenue_zar,
        "country": country, "include_fraudulent_domains": include_fraudulent_domains,
        "client_ips": client_ips, "skip_dehashed": skip_dehashed,
        "skip_intelx": skip_intelx, "regulatory_flags": regulatory_flags,
        "sub_industry": sub_industry, "related_domains": related_domains,
    }
    if not SCAN_QUEUE.enqueue(scan_id, payload):
        mark_failed(scan_id, "Scan queue full — please retry shortly")
        return jsonify({
            "error": "Scanner at capacity — queue full, please retry shortly",
            "scan_id": scan_id, "status": "rejected",
        }), 429

    response = {
        "scan_id": scan_id,
        "domain": domain,
        "status": "pending",
        "poll_url": f"{request.script_root}/api/scan/{scan_id}",
        "report_url": f"{request.script_root}/results/{scan_id}",
    }
    if rejected_client_ips:
        response["rejected_client_ips"] = rejected_client_ips
        response["rejected_client_ips_reason"] = (
            "Only publicly routable IP addresses are scanned; private/"
            "loopback/link-local addresses were dropped"
        )
    return jsonify(response), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404

    if row["status"] == "pending":
        if _scan_is_stale(row):
            msg = ("Scan lost — exceeded the maximum pending window (likely "
                   "interrupted by a service restart). Please re-run the scan.")
            mark_failed(scan_id, msg)
            get_progress_bus().close(scan_id)
            return jsonify({"scan_id": scan_id, "status": "failed",
                            "error": msg}), 500
        return jsonify({"scan_id": scan_id, "status": "pending"}), 202

    if row["status"] == "failed":
        error_data = json.loads(row["results"] or "{}")
        return jsonify({"scan_id": scan_id, "status": "failed", "error": error_data.get("error")}), 500

    results = json.loads(row["results"])
    results["scan_id"] = scan_id
    return jsonify(results)


@app.route("/api/scan/<scan_id>/progress")
def scan_progress(scan_id: str):
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404

    # Already finished — send immediate terminal event
    if row["status"] == "completed":
        def done_stream():
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"
        return Response(done_stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    if row["status"] == "failed":
        def fail_stream():
            yield f"data: {json.dumps({'type': 'error'})}\n\n"
        return Response(fail_stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    # WS8: stream from the progress bus — replays the backlog (so a late/reconnecting
    # client catches up) then tails, surviving the web/worker split when on Redis.
    bus = get_progress_bus()

    def event_stream():
        emitted = False
        for event in bus.listen(scan_id, idle_timeout=30):
            emitted = True
            yield f"data: {json.dumps(event, default=str)}\n\n"
            if event.get("type") in ("complete", "error"):
                return
        if not emitted:
            # no events buffered (e.g. worker on another box, pre-Redis) — let the
            # client fall back to polling GET /api/scan rather than hanging.
            yield f"data: {json.dumps({'type': 'idle'})}\n\n"

    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>/pdf", methods=["GET"])
def download_pdf(scan_id: str):
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    if row["status"] == "pending":
        return jsonify({"error": "Scan not yet completed"}), 409
    if row["status"] == "failed":
        return jsonify({"error": "Scan failed — no PDF available"}), 500

    report_type = request.args.get("type", "full")
    if report_type not in ("assessment", "summary", "full"):
        # Whitelist: the value feeds the cache filename, so anything else
        # (path traversal, typos) collapses to the default tier.
        report_type = "full"

    results = json.loads(row["results"])
    results["scan_id"] = scan_id

    # WS4: serve from object storage (rendered by the PDF worker pool on scan
    # completion). On a miss (tier not pre-rendered, or store wiped) render once and
    # store — render-on-first-request, the spec default.
    from pdf_service import get_pdf, render_and_store
    pdf_bytes = get_pdf(scan_id, report_type)
    if pdf_bytes is None:
        pdf_bytes = render_and_store(scan_id, report_type, results)

    date_str = results.get('scan_timestamp', '')[:10]
    if report_type == "assessment":
        # Executive Summary Deck — sold to brokers/clients as "Cyber Security Assessment"
        filename = f"Cyber_Security_Assessment-{row['domain']}-{date_str}.pdf"
    elif report_type == "summary":
        filename = f"cyber-risk-{row['domain']}-{date_str}-summary.pdf"
    else:
        filename = f"cyber-risk-{row['domain']}-{date_str}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/history/<path:domain>", methods=["GET"])
def scan_history(domain: str):
    domain = domain.lower().strip()
    if not valid_domain(domain):
        return jsonify({"error": "Invalid domain"}), 400
    return jsonify(scanner_db.scan_history(domain, limit=10))  # WS1: scanner store


def _json_for_script(obj):
    """json.dumps escaped for safe embedding inside an inline <script> tag.

    json.dumps does NOT neutralise </script> or <!-- , so any scanned field
    containing such a sequence (e.g. a captured banner / error page with an
    inline script) would close the tag early and spill the rest of the JSON
    into the page - a render break AND a stored-XSS vector. Escape </ , <!--
    and the JS line/paragraph separators (invalid bare in JS string literals).
    """
    return (json.dumps(obj, default=str)
            .replace("</", "<\\/")
            .replace("<!--", "<\\!--")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


@app.route("/results/<scan_id>")
def view_results(scan_id: str):
    row = fetch_scan(scan_id)
    if not row:
        abort(404)
    results = None
    if row["status"] == "completed" and row["results"]:
        results = json.loads(row["results"])
    return render_template(
        "results.html",
        scan_id=scan_id,
        domain=row["domain"],
        status=row["status"],
        results=results,
        results_json=_json_for_script(results) if results else "null",
        checker_manifest=CHECKER_MANIFEST,
        manifest_json=_json_for_script(CHECKER_MANIFEST),
    )




@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/metrics")
def metrics():
    # WS9: Prometheus scrape endpoint. Queue depth is sampled at scrape time.
    import observability
    try:
        observability.set_queue_depth(SCAN_QUEUE.depth())
    except Exception:
        pass
    return Response(observability.metrics_text(), mimetype=observability.CONTENT_TYPE)


@app.route("/config")
def config_info():
    # Lightweight config-verification endpoint. Reports the effective
    # MAX_CONCURRENT_SCANS the app booted with (so an env-var change can be
    # confirmed from a URL) and the worker PID. Hit it a few times: a single
    # repeating PID => 1 gunicorn worker; alternating PIDs => 2 workers.
    # No secrets exposed.
    return jsonify({
        "max_concurrent_scans": MAX_CONCURRENT,
        "worker_pid": os.getpid(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
