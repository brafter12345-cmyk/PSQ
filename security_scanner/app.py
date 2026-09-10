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

# Encrypted credential export (Manual §6.4) — releases a client's ACTUAL breached
# passwords. FAIL CLOSED: off unless explicitly enabled, because the control that
# makes it lawful is the client's signed consent, and the authorisation page that
# would capture it is not live yet. The `consent: true` field on the request is an
# operational attestation by the broker, not a technical control — during a demo,
# with testers who have signed nothing, that is not a gate at all.
#
# TODO(demo-exit): re-enable once the consent/authorisation page ships and real
# auth replaces the interim edge Basic auth. Flip with CREDENTIAL_EXPORT_ENABLED=1
# in the VM .env + `sudo systemctl restart phishield-scanner` — config, not code.
CREDENTIAL_EXPORT_ENABLED = os.environ.get(
    "CREDENTIAL_EXPORT_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")

_EXPORT_DISABLED_MSG = (
    "Encrypted credential export is disabled on this deployment. It releases the "
    "client's actual breached passwords, so it stays off until the consent / "
    "authorisation page is live and the signed consent can be recorded against the "
    "request. Everything else in the scan — including which accounts are exposed, "
    "in which breaches, and how recent — is unaffected."
)


def require_credential_export_enabled(f):
    """Fail closed on both export routes (issue AND download).

    The download route is gated too: disabling only the POST would still let a
    token minted before the flip be redeemed afterwards.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not CREDENTIAL_EXPORT_ENABLED:
            return jsonify({"status": "disabled", "error": _EXPORT_DISABLED_MSG}), 503
        return f(*args, **kwargs)
    return wrapper


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
        {"id": "breach_intel", "label": "Breach History (Web Research)"},
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
             skip_dehashed_reason: str = None,
             skip_breach_intel: bool = False,
             regulatory_flags: dict = None, sub_industry: str = None,
             related_domains: list = None, records_held: int = None):
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
                dehashed_skip_reason=skip_dehashed_reason if skip_dehashed else None,
                virustotal_api_key=VIRUSTOTAL_API_KEY,
                securitytrails_api_key=SECURITYTRAILS_API_KEY,
                shodan_api_key=SHODAN_API_KEY,
                intelx_api_key=None if skip_intelx else INTELX_API_KEY,
            )
            scanner._regulatory_flags = regulatory_flags
            scanner._sub_industry = sub_industry
            scanner._records_held = records_held
            import observability
            with observability.observe_scan(scan_id, domain):  # WS9: count + time + trace
                results = scanner.scan(
                    domain, on_progress=on_progress,
                    industry=industry, annual_revenue=annual_revenue,
                    annual_revenue_zar=annual_revenue_zar,
                    country=country,
                    include_fraudulent_domains=include_fraudulent_domains,
                    skip_breach_intel=skip_breach_intel,
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
            # ALL THREE TIERS, not just `full`. Pre-rendering only one meant
            # the other two were never exercised until a human clicked, so a
            # tier that could not build stayed invisible -- which is exactly how
            # the Executive Summary was broken for an unknown period while the
            # other two downloaded fine. Measured cost: assessment 0.05s,
            # summary 0.06s, full 0.30s, on a scan that takes 90-180s.
            try:
                from pdf_service import enqueue_pdf, TIERS
                for _tier in TIERS:
                    enqueue_pdf(scan_id, _tier, results)
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

# Scan-target input handling lives in domain_validation so the regression gate
# can import it without booting Flask. normalize_domain() is what lets a broker
# paste a URL, an email address, or a value copied out of a PDF form and still
# have the scan target come out right.
from domain_validation import normalize_domain, valid_domain, domain_exists


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
    # Expose the API key to the submit page so its fetches can send X-Api-Key.
    # Empty when SCANNER_API_KEY is unset -> no header sent -> auth stays off
    # (current behaviour). This removes the prerequisite that blocked enabling
    # auth: with the key set, the form/preflight/balance calls authenticate
    # instead of 401-ing. (Embedding the key gates casual direct-API access; a
    # per-user key model is the production follow-up.)
    return render_template("index.html", scanner_api_key=SCANNER_API_KEY or "")


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
    # normalize_domain handles what a paste out of a submission form actually
    # contains: invisible characters, a scheme, an email address, a path, a port.
    domain = normalize_domain(data.get("domain", ""))
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
    """Dehashed credit balance, WITHOUT spending a credit to fetch it.

    The docstring used to claim this was free. It was not: DeHashed publishes no
    zero-cost balance endpoint, so this ran a real /v2/search — and the scan form
    calls it on EVERY PAGE LOAD. With several testers refreshing, that quietly
    became the largest consumer of the credit pool, and because it used raw
    `requests` instead of the metered provider seam the spend never appeared in
    the usage ledger (ledger ~17 vs 200+ actually billed).

    Every genuine scan search already returns the balance, so serve that instead.
    A live probe happens only when we have never seen one, and then at most once
    per DEHASHED_BALANCE_TTL_S (default 12h) — so a page-refresh storm costs
    nothing.
    """
    if not DEHASHED_API_KEY:
        return jsonify({"status": "no_api_key", "balance": None})

    import time as _t
    from checkers_threats import (last_dehashed_balance, record_probe_outcome,
                                  last_probe_outcome, probe_in_cooldown)
    _ttl = float(os.environ.get("DEHASHED_BALANCE_TTL_S", "43200"))
    cached = last_dehashed_balance()
    if cached.get("balance") is not None and (_t.time() - cached["at"]) < _ttl:
        return jsonify({"status": "active", "balance": cached["balance"],
                        "cached": True,
                        "as_of_seconds_ago": int(_t.time() - cached["at"])})

    # A FAILED PROBE MUST NOT RE-FIRE ON EVERY PAGE LOAD.
    # The TTL above only ever gates SUCCESS -- a non-200 records no balance, so
    # the cache stays cold and the next request probes again. Unbounded, and it
    # spends the daily cap that gates real scans. Serve the last failure instead.
    if probe_in_cooldown():
        _o = last_probe_outcome()
        return jsonify({"status": _o.get("status", "error"), "balance": None,
                        "http": _o.get("http"), "cached": True,
                        "as_of_seconds_ago": int(_t.time() - float(_o.get("at") or 0))})

    try:
        import requests as req
        # PROBE A DOMAIN THAT EXISTS, RESOLVES AS A NAME, AND MATCHES NOTHING.
        #
        # MEASURED 2026-08-14, live against the API, three independent samples:
        # a search costs exactly ONE credit and the cost does NOT track result
        # volume. takealot.com returning 263,469 records cost 1; this probe
        # returning 0 records costs 1. A rejected request costs nothing
        # (balance 483 -> HTTP 400 -> 482, i.e. the 400 was free).
        #
        # That disproves the theory this comment used to carry -- that
        # `domain:example.com` was expensive because example.com appears in
        # every dump. It was not. The 21 credits attributed to it were ~21
        # separate page-load probes that predated the TTL cache and the ledger.
        #
        # The replacement for example.com was `domain:...invalid` (RFC 2606, so
        # unregistrable). DeHashed REJECTS it: HTTP 400 {"error": "Issue with
        # query format"}. That broke the indicator, and because setCreditState()
        # disables the checkbox on any non-active status, it silently switched
        # OFF the credential check for every scan for ~19 hours.
        #
        # So the requirement is not "cheap", it is: a query DeHashed ACCEPTS,
        # that returns zero rows, under a name no third party can ever register
        # (a random .com could be bought tomorrow and start matching). A
        # subdomain of a domain we own satisfies all three. VERIFY ANY CHANGE TO
        # THIS QUERY AGAINST THE LIVE API BEFORE SHIPPING IT -- the gate mocks
        # requests.post, so it cannot tell an accepted query from a rejected one.
        r = req.post("https://api.dehashed.com/v2/search",
                     json={"query": "domain:balance-probe.phishield.com",
                           "page": 1, "size": 1},
                     headers={"Content-Type": "application/json",
                              "Dehashed-Api-Key": DEHASHED_API_KEY},
                     timeout=10)
        # METER ONLY WHAT WAS ACTUALLY BILLED. This used to increment BEFORE the
        # request and unconditionally, so a rejected 400 -- which DeHashed does
        # not charge for (measured: 483 -> HTTP 400 -> 482) -- still consumed the
        # DEHASHED_DAILY_CAP. That cap is the kill-switch gating REAL scans
        # (provider_client.py allow_call), so a free, failing probe could lock
        # scanning out of a fully funded account.
        if r.status_code == 200:
            try:
                import scanner_db
                scanner_db.record_usage("dehashed")
                from observability import record_provider_call
                record_provider_call("dehashed", "balance_probe")
            except Exception:
                pass
            data = r.json()
            # We just paid for this one — cache it so the next page load, and
            # every refresh for the next TTL, is free.
            bal = data.get("balance")
            if bal is not None:
                from checkers_threats import record_dehashed_balance
                record_dehashed_balance(int(bal), _t.time(), source="balance_probe")
                record_probe_outcome("active", 200)
                return jsonify({"status": "active", "balance": bal, "cached": False})
            # 200 WITHOUT a balance field. Not "active" — the UI requires both
            # (index.html checks status AND balance !== null), so claiming active
            # here produced a state no branch handled.
            record_probe_outcome("error", 200, "200 without a balance field")
            return jsonify({"status": "error", "balance": None, "http": 200,
                            "error": "no balance field in response"})
        elif r.status_code == 401:
            record_probe_outcome("inactive", 401)
            return jsonify({"status": "inactive", "balance": None,
                            "error": r.json().get("error", "Auth failed")})
        # Any other status (403 "Issue with API Key", 400 bad query, 5xx, etc.):
        # the key is present but the credit check did not succeed. Surface the
        # http code so the UI can say "rejected" (403) vs "unavailable".
        record_probe_outcome("error", r.status_code, (r.text or "")[:200])
        return jsonify({"status": "error", "balance": None, "http": r.status_code})
    except Exception as e:
        record_probe_outcome("error", None, str(e))
        return jsonify({"status": "error", "balance": None, "error": str(e)})


@app.route("/api/credential-export/status", methods=["GET"])
def credential_export_status():
    """Whether the encrypted export is available, so the dashboard can present it
    as unavailable rather than letting a broker fill the form and hit a 503."""
    return jsonify({"enabled": CREDENTIAL_EXPORT_ENABLED,
                    "reason": None if CREDENTIAL_EXPORT_ENABLED else _EXPORT_DISABLED_MSG})


@app.route("/api/breach-intel/status", methods=["GET"])
@require_api_key
@rate_limited(_light_limiter)
def breach_intel_status():
    """Health of the web-search (Gemini) key that powers breach-history research.

    Same contract as the Dehashed / IntelX balance probes so the scan form can grey
    the toggle out identically: active | no_api_key | inactive | error. Uses the
    FREE model-listing endpoint, so polling it costs nothing.

    This matters more than a normal credit check: the search engine degrades
    SILENTLY to snippet-only results on a bad key, which would surface as "no
    breaches found" — a false clean bill of health on an underwriting report. The
    key fingerprint is returned (never the key) so a rotation is visible.
    """
    try:
        from websearch import check_key
        st = check_key()
    except Exception as e:
        return jsonify({"status": "error", "error": f"{type(e).__name__}: {e}"})
    st.setdefault("balance", None)  # shape-compatible with the other probes
    hints = {
        "inactive": ("The Google AI Studio key is present but rejected — it was "
                     "likely rotated or revoked. Update GOOGLE_API_KEY in the "
                     "scanner .env; breach-history research is skipped until then."),
        "quota_exhausted": ("The key is valid but its Google AI Studio credits are "
                            "depleted. Top up billing — until then breach history "
                            "is reported as UNASSESSED rather than clean."),
        "no_api_key": ("GOOGLE_API_KEY is not set, so breach-history research is "
                       "skipped and reported as unassessed."),
    }
    if st.get("status") in hints:
        st["hint"] = hints[st["status"]]
    return jsonify(st)


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
        # Carry the http code, as the DeHashed route does. setCreditState() uses
        # it to tell a REJECTED key (403 -> disable the checkbox) from a
        # transient failure (leave the check running). Without it every IntelX
        # hiccup read as "unusable" and silently switched dark-web search off.
        return jsonify({"status": "error", "balance": None, "http": r.status_code})
    except Exception as e:
        return jsonify({"status": "error", "balance": None, "error": str(e)})


@app.route("/api/credential-export", methods=["POST"])
@require_api_key
@require_credential_export_enabled
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
    authorised_by = str(data.get("authorised_by", "")).strip()
    consent_ref = str(data.get("consent_ref", "")).strip()
    age_pub = (data.get("age_public_key") or "").strip() or None
    passphrase = (data.get("passphrase") or "").strip() or None
    if not domain or not consent or not authorised_by:
        return jsonify({"status": "error",
                        "error": "domain, explicit consent:true, and authorised_by "
                                 "(the authorising broker/user, for the FAIS/POPIA "
                                 "audit trail) are required"}), 400
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
        # Step 4: the release is authorised for the scanned domain and its
        # subdomains. Records for mailboxes anywhere else are refused, because
        # the client cannot consent on behalf of another company's employees.
        fname, blob, method, n, excluded_count = generate_encrypted_export(
            domain, DEHASHED_API_KEY, age_recipient=age_pub, passphrase=passphrase,
            source_meta=source_meta, leak_references=leak_references,
            authorised_domains=[domain])
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)[:200]}), 500
    # Deliver via a ONE-TIME, expiring link (Manual 6.4 step 4). The encrypted blob
    # is held briefly in object storage under an unguessable random token — it is
    # already encrypted to the client's key, so the scanner cannot read it — and is
    # deleted on first download or once expired. Write the authorisation audit row.
    import secrets
    from datetime import timedelta
    from object_store import make_object_store
    token = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
    store = make_object_store()
    store.put(f"cred_exports/{token}.bin", blob, "application/octet-stream")
    store.put(f"cred_exports/{token}.meta",
              json.dumps({"filename": fname, "method": method,
                          "record_count": n, "expires_at": expires_at}).encode("utf-8"),
              "application/json")
    try:
        scanner_db.record_credential_export(
            secrets.token_hex(8), domain, authorised_by, consent, consent_ref,
            method, n, token, expires_at, request.remote_addr or "",
            authorised_domains=[domain], excluded_count=excluded_count)
    except Exception:
        pass  # audit is best-effort; never blocks a consented export
    return jsonify({
        "status": "ready",
        "download_url": f"{request.script_root}/api/credential-export/download/{token}",
        "filename": fname, "method": method, "record_count": n,
        # Surfaced so the operator can see the filter ran. A release that
        # refused nothing and one where the filter never ran look identical
        # without this.
        "excluded_out_of_scope": excluded_count,
        "authorised_domains": [domain],
        "expires_at": expires_at, "expires_in_minutes": 15,
    })


@app.route("/api/credential-export/download/<token>", methods=["GET"])
@require_credential_export_enabled
def credential_export_download(token: str):
    """One-time, expiring retrieval of an encrypted credential export (Manual 6.4
    step 4). The token IS the bearer credential (unguessable, single-use); the blob
    is deleted on first download or once expired, so it can never be fetched twice."""
    from object_store import make_object_store
    from flask import Response
    store = make_object_store()
    meta_raw = store.get(f"cred_exports/{token}.meta")
    if not meta_raw:
        return jsonify({"status": "error", "error": "This link is invalid, has "
                        "already been used, or has expired."}), 404
    try:
        meta = json.loads(meta_raw)
        expired = datetime.now(timezone.utc) >= datetime.fromisoformat(meta["expires_at"])
    except Exception:
        meta, expired = {}, True
    # Single-use: delete BOTH objects up front so the link cannot be reused even on
    # a concurrent request.
    store.delete(f"cred_exports/{token}.meta")
    blob = None if expired else store.get(f"cred_exports/{token}.bin")
    store.delete(f"cred_exports/{token}.bin")
    if expired:
        return jsonify({"status": "error", "error": "This download link has expired."}), 410
    if blob is None:
        return jsonify({"status": "error", "error": "This link has already been used."}), 404
    try:
        scanner_db.mark_export_downloaded(token)
    except Exception:
        pass
    return Response(blob, mimetype="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename={meta.get('filename', 'credentials.age')}",
        "X-Export-Method": meta.get("method", ""), "Cache-Control": "no-store"})


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

    # ...and it must actually EXIST. Syntax validation passes a typo of a real
    # domain, and the scan then completes against nothing: every DNS-dependent
    # checker returns empty, empty scores as clean, and the broker receives a
    # risk rating and a financial exposure figure for a domain that was never
    # registered. Refusing here is the only honest answer, and it costs one
    # DNS query. See domain_exists() for why NXDOMAIN specifically.
    if not domain_exists(domain):
        return jsonify({
            "error": f"'{domain}' does not exist (NXDOMAIN). No assessment is "
                     f"possible for a domain that is not registered. Check the "
                     f"spelling, or confirm the correct domain with the client.",
            "code": "domain_not_resolvable",
            "domain": domain,
        }), 400

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
    # Optional broker-supplied total records held (supersedes the revenue/divisor
    # heuristic in the data-breach severity model). None when absent/invalid.
    try:
        records_held = int(data.get("records_held", 0)) or None
        if records_held is not None and records_held <= 0:
            records_held = None
    except (ValueError, TypeError):
        records_held = None
    include_fraudulent_domains = bool(data.get("include_fraudulent_domains", False))
    skip_dehashed = bool(data.get("skip_dehashed", False))
    # Only a whitelisted reason is honoured -- this feeds a scoring class.
    skip_dehashed_reason = (data.get("skip_dehashed_reason")
                            if data.get("skip_dehashed_reason") == "probe_failed" else None)
    skip_intelx = bool(data.get("skip_intelx", False))
    skip_breach_intel = bool(data.get("skip_breach_intel", False))

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
        "skip_dehashed_reason": skip_dehashed_reason,
        "skip_intelx": skip_intelx, "skip_breach_intel": skip_breach_intel,
        "regulatory_flags": regulatory_flags,
        "sub_industry": sub_industry, "related_domains": related_domains,
        "records_held": records_held,
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
    # Tell the submitter NOW if a metered key is down, rather than letting them
    # discover it in the finished report. The scan form checks on page load, but a
    # key that flips mid-book leaves a stale page (or an API caller) submitting
    # scans that will quietly come back with breach history unassessed.
    if not skip_breach_intel:
        try:
            from websearch import check_key_cached
            ks = check_key_cached()
            if ks.get("status") != "active":
                response.setdefault("warnings", []).append({
                    "checker": "breach_intel",
                    "status": ks.get("status"),
                    "message": ("The web-search key is not usable "
                                f"({ks.get('status')}), so this scan will report "
                                "breach history as UNASSESSED rather than "
                                "researched — it will not be a clean result. "
                                "Restore the key and re-run for a researched "
                                "breach history."),
                })
        except Exception:
            pass
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

    # Mask breached-credential identifiers before the results leave the server
    # (Manual 6.4 — dashboard/export show masked accounts; unmasked detail is
    # delivered only via the encrypted credential export).
    from credential_redaction import redact_credentials
    results = redact_credentials(json.loads(row["results"]))
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


def _brief_user() -> str:
    """The authenticated operator, as forwarded by the edge proxy.

    HONEST LIMIT: the app has no authentication of its own (OUTSTANDING 4b). Caddy
    performs Basic auth and forwards the username in `X-Auth-User`; the app cannot
    verify that header, so this is an AUDIT LABEL, not an authorisation decision.
    Nothing is gated on the value. It is adequate only because the user set is a
    handful of internal staff who all already hold identical access, and it stops
    being adequate the moment that is not true.
    """
    u = (request.headers.get("X-Auth-User") or "").strip()
    # Keep it to a plausible username so a spoofed header cannot inject markup or
    # newlines into the audit row or the PDF footer.
    return u[:64] if re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", u or "") else ""


@app.route("/api/scan/<scan_id>/brief/options", methods=["GET"])
def brief_options(scan_id: str):
    """What the brief generator can offer for this scan, for the dashboard panel.

    Credit-free: reports the *estimated* cost of a fingerprint pull from the
    record count already stored on the scan. Nothing is queried."""
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    try:
        results = json.loads(row["results"]) if row["results"] else {}
    except Exception:
        results = {}
    dh = (results.get("categories", {}) or {}).get("dehashed", {}) or {}
    total = dh.get("total_entries")
    from card_severity import NON_CONCLUSIVE_STATUSES
    from meeting_brief import estimate_credits
    conclusive = dh.get("status") not in NON_CONCLUSIVE_STATUSES
    return jsonify({
        "scan_id": scan_id,
        "domain": row["domain"],
        "user": _brief_user(),
        "fingerprints_available": bool(conclusive and total and DEHASHED_API_KEY),
        "fingerprints_unavailable_reason": (
            "" if (conclusive and total and DEHASHED_API_KEY)
            else ("credential source not configured" if not DEHASHED_API_KEY
                  else ("the credential check did not complete on this scan"
                        if not conclusive else "no credential records for this domain"))),
        "estimated_credits": estimate_credits(total) if isinstance(total, int) else None,
        "record_count": total if isinstance(total, int) else None,
    })


@app.route("/api/scan/<scan_id>/brief", methods=["POST"])
@require_api_key
@rate_limited(_scan_limiter)
def generate_brief(scan_id: str):
    """Generate the client meeting brief for a completed scan.

    Password fingerprints are OPT-IN and are the only part of this that spends
    money or touches a third party: the scan stores no password material, so a
    fingerprint requires a fresh paged query at one credit per page. With
    `include_fingerprints` false (the default) this route makes no outbound
    request at all."""
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    if row["status"] != "completed":
        return jsonify({"error": "Brief requires a completed scan"}), 409

    data = request.get_json(force=True, silent=True) or {}
    want_fp = bool(data.get("include_fingerprints"))
    reason = str(data.get("reason", "")).strip()[:200]
    if want_fp and not reason:
        return jsonify({"error": "A reason is required when password fingerprints "
                                 "are included; it is recorded in the audit trail."}), 400
    if want_fp and not DEHASHED_API_KEY:
        return jsonify({"error": "Credential source not configured — fingerprints "
                                 "cannot be produced."}), 503

    results = json.loads(row["results"])
    domain = row["domain"]
    from meeting_brief import build_brief, fetch_fingerprints

    fp_data, credits = None, 0
    if want_fp:
        try:
            fp_data = fetch_fingerprints(domain, DEHASHED_API_KEY)
            credits = fp_data["credits_spent"]
        except Exception as e:
            # Never silently downgrade to a fingerprint-free brief: the operator
            # asked for fingerprints for a reason and would not notice their
            # absence in a PDF that otherwise looks complete.
            return jsonify({"error": "Fingerprint pull failed: %s" % str(e)[:160]}), 502

    user = _brief_user()

    # Write the audit row BEFORE releasing the document. For a fingerprint brief
    # the audit trail is the whole justification for allowing it at all under the
    # current edge-only auth (OUTSTANDING 4b) — if it cannot be recorded, the
    # control is gone and the document must not be released. A fingerprint-free
    # brief carries no credential material, so a failed audit is logged and the
    # brief still goes out.
    try:
        import secrets
        scanner_db.record_meeting_brief(
            secrets.token_hex(8), scan_id, domain, user, want_fp, reason,
            len(fp_data["accounts"]) if fp_data else 0, credits,
            request.remote_addr or "")
    except Exception:
        app.logger.exception("meeting-brief audit row failed")
        if want_fp:
            return jsonify({"error": "The audit trail could not be written, so a "
                                     "brief containing password fingerprints was "
                                     "not produced. Generate without fingerprints, "
                                     "or retry once the datastore is available."}), 503

    pdf_bytes = build_brief(results, domain, fingerprint_data=fp_data,
                            generated_by=user)

    date_str = str(results.get("scan_timestamp", ""))[:10]
    return send_file(
        io.BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True,
        download_name="meeting-brief-%s-%s.pdf" % (domain, date_str))


@app.route("/api/brief-audit", methods=["GET"])
def brief_audit():
    """Recent brief generations, for the audit panel under the generator."""
    try:
        rows = scanner_db.meeting_brief_audit(limit=25)
    except Exception:
        return jsonify({"entries": [], "error": "audit unavailable"}), 200
    return jsonify({"entries": [dict(r) for r in rows]})


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
    # Mask breached-credential identifiers before injection into window.RESULTS
    # (so the dashboard page source never carries raw emails). See Manual 6.4.
    from credential_redaction import redact_credentials
    results = None
    if row["status"] == "completed" and row["results"]:
        results = redact_credentials(json.loads(row["results"]))
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


@app.route("/health/providers")
def health_providers():
    """Readiness of the metered provider keys — returns **503 when degraded**.

    `/health` deliberately stays a bare liveness probe (the deploy script gates on
    it, and the app is genuinely up even with a dead provider key). This is the
    separate readiness probe: point any uptime monitor at it and a key that flips
    mid-book raises an alarm within one poll, instead of going unnoticed until
    somebody happens to reload the scan form.

    Why this matters more than a normal outage: a dead web-search key does NOT
    stop scans. They keep completing and simply report breach history as
    "unassessed" — correct, but easy to miss across a batch. Without this probe
    the failure is silent by construction. The datastore check is here for the
    same reason: an unset DATABASE_URL does not error either, it just serves the
    SQLite fallback as though nothing happened.

    Cached (BREACH_INTEL_HEALTH_TTL_S, default 300s) so a once-a-minute monitor
    costs nothing.
    """
    providers, degraded = {}, []

    try:
        from websearch import check_key_cached
        ks = check_key_cached()
        providers["web_search_gemini"] = {
            "status": ks.get("status"), "key_fingerprint": ks.get("key_fingerprint"),
            "cached": ks.get("cached"),
            **({"error": ks["error"][:160]} if ks.get("error") else {}),
        }
        if ks.get("status") != "active":
            degraded.append("web_search_gemini")
    except Exception as e:
        providers["web_search_gemini"] = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        degraded.append("web_search_gemini")

    # Configured-but-unusable is the alarm condition. A provider that was never
    # configured is a deliberate deployment choice, not a regression, so it is
    # reported without failing the probe.
    for name, key in (("dehashed", DEHASHED_API_KEY), ("intelx", INTELX_API_KEY),
                      ("hibp", HIBP_API_KEY)):
        providers[name] = {"status": "configured" if key else "not_configured"}

    # "Configured" only ever meant "a key is present in .env". It cannot see a
    # key the provider REJECTS. On 2026-08-13 the DeHashed probe returned HTTP
    # 400 for 19 hours -- which disabled credential scanning on every scan --
    # while this route cheerfully reported "configured" and nothing alarmed.
    #
    # Read the STORED outcome of the last real probe. Deliberately a read, never
    # a call: an uptime monitor at 5-minute intervals is 288 polls/day against a
    # 150/day cap, so probing from the health route would turn the monitor itself
    # into an outage.
    if DEHASHED_API_KEY:
        try:
            from checkers_threats import last_probe_outcome
            _po = last_probe_outcome()
            if _po:
                providers["dehashed"] = {
                    "status": "configured" if _po.get("status") == "active" else "rejected",
                    "last_probe": _po.get("status"), "http": _po.get("http"),
                    "probed_seconds_ago": int(time.time() - float(_po.get("at") or 0)),
                }
                if _po.get("status") != "active":
                    degraded.append("dehashed")
                    providers["dehashed"]["error"] = (
                        _po.get("error") or "last balance probe did not succeed")
        except Exception:
            pass

    # Remaining daily budget for the metered credential providers. Exhaustion is
    # no longer a correctness problem — those checkers now report UNASSESSED
    # rather than a false clean — but it IS a quality-of-service one: every scan
    # from here to midnight UTC comes back with that section unassessed, so the
    # operator should hear about it rather than discover it in a client's report.
    # Alarm on EXHAUSTED only, not on merely low: a probe that goes red while
    # scans are still fine trains people to ignore it.
    try:
        import providers as _prov
        budget = _prov.budget_report()
        for name, b in budget.items():
            if providers.get(name, {}).get("status") == "configured":
                providers[name].update(b)
                if b.get("remaining") == 0:
                    providers[name]["status"] = "budget_exhausted"
                    degraded.append(name)
    except Exception as e:
        budget = {"error": f"{type(e).__name__}: {e}"}

    # Datastore backend. scanner_db falls back to SQLite when DATABASE_URL is
    # unset — correct for dev, silently catastrophic in production. On
    # 2026-07-27 a clobbered .env dropped DATABASE_URL and the service came up
    # serving a stale legacy scans.db while the real Postgres history sat
    # untouched and invisible, with every health check green throughout. Same
    # failure shape as a dead web-search key: it does not error, it just quietly
    # answers from the wrong place. So report the live backend, and treat the
    # fallback as an alarm unless it was deliberately asked for.
    try:
        import scanner_db
        backend = scanner_db.configured_backend()   # no pool side effect
        pg = backend == "postgres"
        allow_sqlite = os.environ.get("SCANNER_ALLOW_SQLITE", "").strip().lower() \
            in ("1", "true", "yes")
        # AND CAN WE ACTUALLY REACH IT? The check above answers "what is
        # configured" and never touches the database, which is exactly why it
        # missed the 2026-09-01 outage: both application databases were stopped
        # for a week while this endpoint reported {"backend": "postgres",
        # "status": "postgres"} the entire time, because that is what .env said.
        # The rating engine failed in front of a user for two days. A monitor
        # pointed here would have seen green throughout.
        reachable, reach_err = scanner_db.ping()
        providers["datastore"] = {
            "status": ("postgres" if pg else ("sqlite" if allow_sqlite
                                              else "sqlite_fallback"))
                      if reachable else "unreachable",
            "backend": backend,
            "reachable": reachable,
        }
        if not reachable:
            providers["datastore"]["error"] = reach_err
            degraded.append("datastore")
        elif not pg and not allow_sqlite:
            degraded.append("datastore")
    except Exception as e:
        providers["datastore"] = {"status": "error", "error": f"{type(e).__name__}: {e}"}
        degraded.append("datastore")

    try:
        import observability
        observability.set_provider_key_status(
            "web_search_gemini",
            1 if providers["web_search_gemini"].get("status") == "active" else 0)
        observability.set_provider_key_status(
            "datastore", 0 if "datastore" in degraded else 1)
    except Exception:
        pass

    body = {
        "status": "degraded" if degraded else "ok",
        "degraded": degraded,
        "providers": providers,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if degraded:
        impacts = []
        if "web_search_gemini" in degraded:
            impacts.append(
                "Scans still complete, but breach history is reported as UNASSESSED "
                "rather than researched. Restore the key and re-run any scans taken "
                "while degraded.")
        if "datastore" in degraded:
            impacts.append(
                "DATABASE_URL is unset, so the scanner is reading and writing the "
                "SQLite fallback instead of Postgres: existing scans are invisible "
                "and new ones land in the wrong store. Restore DATABASE_URL (see "
                "deploy/deploy_vm.sh, which reconstructs it from secrets.env) and "
                "restart. If SQLite is intended, set SCANNER_ALLOW_SQLITE=1.")
        if "datastore" in degraded and not (providers.get("datastore") or {}).get("reachable", True):
            impacts.append(
                "The scan datastore is UNREACHABLE. Scans cannot be stored or "
                "retrieved and every history/report request will fail. Existing "
                "data is not lost -- the database is not answering. Check the "
                "database service is running before anything else.")
        spent = [n for n in ("dehashed", "intelx") if n in degraded]
        if spent:
            impacts.append(
                f"Daily budget exhausted for: {', '.join(spent)}. Scans still "
                "complete and correctly report those sections as UNASSESSED "
                "rather than clean, but they carry no credential/dark-web "
                "finding until the quota resets at midnight UTC. Raise the cap "
                "(DEHASHED_DAILY_CAP / INTELX_DAILY_CAP) only if the provider "
                "plan actually allows it.")
        body["impact"] = " ".join(impacts)
    return jsonify(body), (503 if degraded else 200)


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
