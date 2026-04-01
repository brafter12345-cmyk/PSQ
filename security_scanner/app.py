"""
Cyber Insurance Security Scanner — Flask API
Endpoints:
  POST /api/scan           {"domain": "example.co.za", "industry": "finance", "annual_revenue": 5000000}
  GET  /api/scan/<id>      → JSON results or {"status": "pending"}
  GET  /api/scan/<id>/pdf  → download PDF report
  GET  /results/<id>       → HTML visual report
  GET  /api/history/<dom>  → last 10 scans for a domain
"""

import io
import os
import json
import queue
import sqlite3
import threading
import time
import uuid
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
DB_PATH = os.environ.get("DB_PATH", "scans.db")
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))

VALID_INDUSTRIES = [
    "Agriculture", "Communications", "Consumer", "Education", "Energy",
    "Entertainment", "Financial Services", "Finance", "Healthcare",
    "Hospitality", "Industrial / Manufacturing", "Manufacturing",
    "Legal", "Media", "Pharmaceuticals", "Public Sector", "Research",
    "Retail", "Services", "Technology", "Tech", "Transportation",
    "Government", "Other",
]

_semaphore = threading.Semaphore(MAX_CONCURRENT)

# In-memory SSE progress tracking: scan_id -> queue.Queue()
_scan_progress = {}

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
        {"id": "dnsbl", "label": "DNSBL / Blacklists", "per_ip": True},
        {"id": "cloud_cdn", "label": "Cloud & CDN"},
        {"id": "vpn_remote", "label": "VPN / Remote Access"},
    ]},
    {"section": "Exposure & Reputation", "checkers": [
        {"id": "breaches", "label": "Data Breaches (HIBP)"},
        {"id": "dehashed", "label": "Credential Leaks"},
        {"id": "exposed_admin", "label": "Exposed Admin Panels"},
        {"id": "virustotal", "label": "VirusTotal Intelligence"},
        {"id": "subdomains", "label": "Subdomain Recon"},
        {"id": "fraudulent_domains", "label": "Lookalike Domains"},
    ]},
    {"section": "Technology & Governance", "checkers": [
        {"id": "tech_stack", "label": "Technology Stack"},
        {"id": "domain_intel", "label": "Domain Intelligence"},
        {"id": "securitytrails", "label": "SecurityTrails DNS"},
        {"id": "security_policy", "label": "Security Policy & VDP"},
        {"id": "payment_security", "label": "Payment Security"},
        {"id": "privacy_compliance", "label": "Privacy Compliance"},
    ]},
    {"section": "Insurance Analytics", "checkers": [
        {"id": "insurance_analytics", "label": "RSI / Financial Impact / DBI"},
    ]},
]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                domain      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                results     TEXT,
                risk_score  INTEGER,
                risk_level  TEXT,
                industry    TEXT DEFAULT 'other',
                annual_revenue REAL DEFAULT 0,
                country     TEXT DEFAULT '',
                created_at  TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)")
        # Migration: add new columns to existing tables
        for col, coltype, default in [
            ("industry", "TEXT", "'other'"),
            ("annual_revenue", "REAL", "0"),
            ("country", "TEXT", "''"),
            ("client_id", "TEXT", "''"),
        ]:
            try:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {coltype} DEFAULT {default}")
            except sqlite3.OperationalError:
                pass  # Column already exists

        # CRM tables
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                company_name TEXT NOT NULL,
                trading_as TEXT DEFAULT '',
                domain TEXT DEFAULT '',
                industry TEXT DEFAULT 'other',
                annual_revenue REAL DEFAULT 0,
                employee_count INTEGER DEFAULT 0,
                reseller TEXT DEFAULT '',
                country TEXT DEFAULT 'ZA',
                pipeline_stage TEXT DEFAULT 'lead',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_domain ON clients(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_pipeline ON clients(pipeline_stage)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT DEFAULT '',
                phone TEXT DEFAULT '',
                role TEXT DEFAULT '',
                is_primary INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_client ON contacts(client_id)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS quotes (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scan_id TEXT DEFAULT '',
                cover_limit REAL DEFAULT 0,
                annual_premium REAL DEFAULT 0,
                monthly_premium REAL DEFAULT 0,
                mdr_selection TEXT DEFAULT 'no',
                mdr_discount REAL DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT '',
                revenue_band TEXT DEFAULT '',
                status TEXT DEFAULT 'draft',
                valid_until TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quotes_client ON quotes(client_id)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                quote_id TEXT DEFAULT '',
                policy_number TEXT NOT NULL,
                cover_limit REAL DEFAULT 0,
                annual_premium REAL DEFAULT 0,
                inception_date TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                renewal_of TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policies_client ON policies(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policies_expiry ON policies(expiry_date)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS invoices (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                policy_id TEXT DEFAULT '',
                invoice_number TEXT NOT NULL,
                issue_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                subtotal REAL DEFAULT 0,
                vat_rate REAL DEFAULT 15.0,
                vat_amount REAL DEFAULT 0,
                total REAL DEFAULT 0,
                status TEXT DEFAULT 'draft',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS invoice_line_items (
                id TEXT PRIMARY KEY,
                invoice_id TEXT NOT NULL,
                description TEXT NOT NULL,
                quantity REAL DEFAULT 1,
                unit_price REAL DEFAULT 0,
                line_total REAL DEFAULT 0,
                sort_order INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_line_items_invoice ON invoice_line_items(invoice_id)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                invoice_id TEXT NOT NULL,
                amount REAL NOT NULL,
                method TEXT DEFAULT '',
                reference TEXT DEFAULT '',
                payment_date TEXT NOT NULL,
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_payments_invoice ON payments(invoice_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS activities (
            id TEXT PRIMARY KEY,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            client_id TEXT DEFAULT '',
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activities_client ON activities(client_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS client_notes (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_client_notes_client ON client_notes(client_id)")

        # Add archived column to tables that need it
        for tbl in ('clients', 'quotes', 'invoices'):
            try:
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN archived INTEGER DEFAULT 0")
            except Exception:
                pass

        for col, coltype, default in [
            ('commission_rate', 'REAL', '0'),
            ('commission_amount', 'REAL', '0'),
        ]:
            try:
                conn.execute(f"ALTER TABLE policies ADD COLUMN {col} {coltype} DEFAULT {default}")
            except Exception:
                pass

        # --- Phase 2: Insurance-specific tables ---
        conn.execute("""CREATE TABLE IF NOT EXISTS records_of_advice (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            quote_id TEXT DEFAULT '',
            policy_id TEXT DEFAULT '',
            advisor_name TEXT DEFAULT '',
            client_needs TEXT DEFAULT '',
            risk_profile TEXT DEFAULT '',
            products_recommended TEXT DEFAULT '',
            reasons TEXT DEFAULT '',
            alternatives_considered TEXT DEFAULT '',
            disclosures TEXT DEFAULT '',
            client_acknowledged INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_roa_client ON records_of_advice(client_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS claims (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            claim_number TEXT NOT NULL,
            claim_date TEXT NOT NULL,
            incident_date TEXT DEFAULT '',
            incident_type TEXT DEFAULT '',
            description TEXT DEFAULT '',
            amount_claimed REAL DEFAULT 0,
            amount_paid REAL DEFAULT 0,
            status TEXT DEFAULT 'filed',
            resolution_notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_client ON claims(client_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_policy ON claims(policy_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS communications (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            comm_type TEXT NOT NULL,
            subject TEXT DEFAULT '',
            body TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_comms_client ON communications(client_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS tasks (
            id TEXT PRIMARY KEY,
            client_id TEXT DEFAULT '',
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            due_date TEXT DEFAULT '',
            priority TEXT DEFAULT 'medium',
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_client ON tasks(client_id)")

        conn.execute("""CREATE TABLE IF NOT EXISTS complaints (
            id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            resolution TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_complaints_client ON complaints(client_id)")

        conn.commit()


def save_scan(scan_id: str, domain: str, industry: str = "other",
              annual_revenue: float = 0, country: str = ""):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scans (id, domain, status, industry, annual_revenue, country, created_at) VALUES (?,?,?,?,?,?,?)",
            (scan_id, domain, "pending", industry, annual_revenue, country,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()


def update_scan(scan_id: str, results: dict):
    with get_db() as conn:
        conn.execute(
            """UPDATE scans SET status=?, results=?, risk_score=?, risk_level=?, completed_at=?
               WHERE id=?""",
            (
                "completed",
                json.dumps(results, default=str),
                results.get("overall_risk_score"),
                results.get("risk_level"),
                datetime.now(timezone.utc).isoformat(),
                scan_id,
            )
        )
        conn.commit()


def mark_failed(scan_id: str, error: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE scans SET status='failed', results=?, completed_at=? WHERE id=?",
            (json.dumps({"error": error}), datetime.now(timezone.utc).isoformat(), scan_id)
        )
        conn.commit()


def fetch_scan(scan_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def _now():
    return datetime.now(timezone.utc).isoformat()


def _next_number(prefix, table, column):
    """Generate next sequential number like PHI-2026-0001 or INV-2026-0001"""
    year = datetime.now().year
    pattern = f"{prefix}-{year}-%"
    with get_db() as conn:
        row = conn.execute(
            f"SELECT {column} FROM {table} WHERE {column} LIKE ? ORDER BY {column} DESC LIMIT 1",
            (pattern,)
        ).fetchone()
    if row:
        last_seq = int(row[0].split("-")[-1])
        return f"{prefix}-{year}-{last_seq + 1:04d}"
    return f"{prefix}-{year}-0001"


PIPELINE_ORDER = ['lead', 'scanned', 'quoted', 'bound', 'renewal']


def advance_pipeline(client_id, new_stage):
    with get_db() as conn:
        row = conn.execute("SELECT pipeline_stage FROM clients WHERE id=?", (client_id,)).fetchone()
        if row:
            current_stage = row['pipeline_stage']
            current = PIPELINE_ORDER.index(current_stage) if current_stage in PIPELINE_ORDER else -1
            target = PIPELINE_ORDER.index(new_stage) if new_stage in PIPELINE_ORDER else -1
            if target > current:
                conn.execute("UPDATE clients SET pipeline_stage=?, updated_at=? WHERE id=?",
                             (new_stage, _now(), client_id))
                conn.commit()
                log_activity('client', client_id, client_id, 'stage_changed', f'Pipeline: {current_stage} \u2192 {new_stage}')


def log_activity(entity_type, entity_id, client_id, action, detail=''):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO activities (id, entity_type, entity_id, client_id, action, detail, created_at) VALUES (?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), entity_type, entity_id, client_id, action, detail, _now())
            )
            conn.commit()
    except Exception:
        pass


def auto_update_invoice_statuses():
    try:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with get_db() as conn:
            conn.execute(
                "UPDATE invoices SET status='overdue', updated_at=? WHERE status='sent' AND due_date < ?",
                (_now(), today)
            )
            conn.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

def run_scan(scan_id: str, domain: str, industry: str = "other",
             annual_revenue: float = 0, annual_revenue_zar: int = 0, country: str = "",
             include_fraudulent_domains: bool = False, client_ips: list = None):
    progress_q = queue.Queue()
    _scan_progress[scan_id] = progress_q

    def on_progress(event):
        progress_q.put(event)

    with _semaphore:
        try:
            scanner = SecurityScanner(
                hibp_api_key=HIBP_API_KEY,
                dehashed_email=DEHASHED_EMAIL,
                dehashed_api_key=DEHASHED_API_KEY,
                virustotal_api_key=VIRUSTOTAL_API_KEY,
                securitytrails_api_key=SECURITYTRAILS_API_KEY,
                shodan_api_key=SHODAN_API_KEY,
            )
            results = scanner.scan(
                domain, on_progress=on_progress,
                industry=industry, annual_revenue=annual_revenue,
                annual_revenue_zar=annual_revenue_zar,
                country=country,
                include_fraudulent_domains=include_fraudulent_domains,
                client_ips=client_ips,
            )
            update_scan(scan_id, results)
            # Auto-link to client by domain
            try:
                with get_db() as conn:
                    scan_row = conn.execute("SELECT client_id, domain FROM scans WHERE id=?", (scan_id,)).fetchone()
                    if scan_row:
                        cid = scan_row['client_id']
                        if not cid:
                            # Find client by domain match
                            client_row = conn.execute(
                                "SELECT id FROM clients WHERE domain=? LIMIT 1",
                                (scan_row['domain'],)
                            ).fetchone()
                            if client_row:
                                cid = client_row['id']
                                conn.execute("UPDATE scans SET client_id=? WHERE id=?", (cid, scan_id))
                                conn.commit()
                        if cid:
                            advance_pipeline(cid, 'scanned')
            except Exception:
                pass  # Don't fail the scan if CRM linking fails
            progress_q.put({"type": "complete"})
        except Exception as e:
            mark_failed(scan_id, str(e))
            progress_q.put({"type": "error", "message": str(e)})


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

import re
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

def valid_domain(domain: str) -> bool:
    domain = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
    return bool(_DOMAIN_RE.match(domain)) and len(domain) <= 253


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
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
    include_fraudulent_domains = bool(data.get("include_fraudulent_domains", False))

    # Parse client-supplied IPs (optional)
    import ipaddress as _ipaddress
    raw_client_ips = data.get("client_ips", [])
    client_ips = []
    if isinstance(raw_client_ips, list):
        for ip_str in raw_client_ips:
            try:
                _ipaddress.ip_address(str(ip_str).strip())
                client_ips.append(str(ip_str).strip())
            except ValueError:
                continue

    scan_id = str(uuid.uuid4())
    effective_revenue = annual_revenue_zar if annual_revenue_zar > 0 else annual_revenue
    save_scan(scan_id, domain, industry, effective_revenue, country)

    # Auto-create CRM lead if no client exists for this domain
    client_id = None
    try:
        with get_db() as conn:
            existing = conn.execute("SELECT id FROM clients WHERE domain=? LIMIT 1", (domain,)).fetchone()
            if existing:
                client_id = existing['id']
            else:
                client_id = str(uuid.uuid4())
                now = _now()
                conn.execute(
                    """INSERT INTO clients (id, company_name, domain, industry, annual_revenue,
                       country, pipeline_stage, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (client_id, domain, domain, industry, annual_revenue,
                     country or 'ZA', 'lead', now, now)
                )
                conn.commit()
            # Pre-link scan to client
            conn.execute("UPDATE scans SET client_id=? WHERE id=?", (client_id, scan_id))
            conn.commit()
    except Exception:
        pass  # Don't fail the scan if CRM creation fails

    t = threading.Thread(
        target=run_scan,
        args=(scan_id, domain, industry, annual_revenue, annual_revenue_zar, country,
              include_fraudulent_domains, client_ips),
        daemon=True,
    )
    t.start()

    return jsonify({
        "scan_id": scan_id,
        "domain": domain,
        "status": "pending",
        "poll_url": f"/api/scan/{scan_id}",
        "report_url": f"/results/{scan_id}",
    }), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    row = fetch_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404

    if row["status"] == "pending":
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

    progress_q = _scan_progress.get(scan_id)
    if not progress_q:
        def empty_stream():
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"
        return Response(empty_stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    def event_stream():
        while True:
            try:
                event = progress_q.get(timeout=30)
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event.get("type") in ("complete", "error"):
                    break
            except queue.Empty:
                yield ": keepalive\n\n"
        _scan_progress.pop(scan_id, None)

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

    from pdf_report import generate_pdf
    results = json.loads(row["results"])
    results["scan_id"] = scan_id
    pdf_bytes = generate_pdf(results)

    filename = f"cyber-risk-{row['domain']}-{results.get('scan_timestamp','')[:10]}.pdf"
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
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, domain, status, risk_score, risk_level, created_at, completed_at
               FROM scans WHERE domain=? ORDER BY created_at DESC LIMIT 10""",
            (domain,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


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
        results_json=json.dumps(results, default=str) if results else "null",
        checker_manifest=CHECKER_MANIFEST,
        manifest_json=json.dumps(CHECKER_MANIFEST),
    )


# ---------------------------------------------------------------------------
# CRM Routes
# ---------------------------------------------------------------------------

@app.route("/crm/")
def crm_dashboard():
    auto_update_invoice_statuses()
    with get_db() as conn:
        # Pipeline counts
        pipeline_rows = conn.execute(
            "SELECT pipeline_stage, COUNT(*) as cnt FROM clients WHERE (archived=0 OR archived IS NULL) GROUP BY pipeline_stage"
        ).fetchall()
        pipeline = {r['pipeline_stage']: r['cnt'] for r in pipeline_rows}
        for stage in ('lead', 'scanned', 'quoted', 'bound', 'renewal'):
            pipeline.setdefault(stage, 0)
        pipeline['total'] = sum(pipeline.get(s, 0) for s in ('lead', 'scanned', 'quoted', 'bound', 'renewal'))

        # Revenue: paid invoices this month / quarter / year
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1).strftime("%Y-%m-%d")
        quarter_month = ((now.month - 1) // 3) * 3 + 1
        quarter_start = now.replace(month=quarter_month, day=1).strftime("%Y-%m-%d")
        year_start = now.replace(month=1, day=1).strftime("%Y-%m-%d")

        def paid_sum(since):
            row = conn.execute(
                "SELECT COALESCE(SUM(total), 0) as s FROM invoices WHERE status='paid' AND issue_date >= ?",
                (since,)
            ).fetchone()
            return row['s']

        revenue = {
            'month': paid_sum(month_start),
            'quarter': paid_sum(quarter_start),
            'year': paid_sum(year_start),
        }

        # Upcoming renewals: policies expiring in 60 days
        cutoff = (now + timedelta(days=60)).strftime("%Y-%m-%d")
        today_str = now.strftime("%Y-%m-%d")
        renewals_raw = conn.execute(
            """SELECT p.*, c.company_name FROM policies p
               JOIN clients c ON c.id = p.client_id
               WHERE p.status='active' AND p.expiry_date <= ? AND p.expiry_date >= ?
               ORDER BY p.expiry_date""",
            (cutoff, today_str)
        ).fetchall()
        renewals = []
        for r in renewals_raw:
            rd = dict(r)
            try:
                expiry = datetime.fromisoformat(rd['expiry_date'])
                rd['days_left'] = (expiry - now).days
            except Exception:
                rd['days_left'] = 0
            renewals.append(rd)

        # Overdue invoices
        overdue_raw = conn.execute(
            """SELECT i.*, c.company_name FROM invoices i
               JOIN clients c ON c.id = i.client_id
               WHERE i.status IN ('sent', 'overdue') AND i.due_date < ?
               ORDER BY i.due_date""",
            (today_str,)
        ).fetchall()
        overdue = []
        for r in overdue_raw:
            rd = dict(r)
            try:
                due = datetime.fromisoformat(rd['due_date'])
                rd['days_overdue'] = (now - due).days
            except Exception:
                rd['days_overdue'] = 0
            overdue.append(rd)

        # Pending tasks (overdue first)
        today_str = datetime.now().strftime("%Y-%m-%d")
        pending_tasks = [dict(r) for r in conn.execute(
            """SELECT t.*, c.company_name FROM tasks t
               LEFT JOIN clients c ON c.id=t.client_id
               WHERE t.status='pending'
               ORDER BY CASE WHEN t.due_date < ? THEN 0 ELSE 1 END, t.due_date LIMIT 10""",
            (today_str,)).fetchall()]

        # Open claims
        open_claims = [dict(r) for r in conn.execute(
            """SELECT cl.*, c.company_name, p.policy_number FROM claims cl
               JOIN clients c ON c.id=cl.client_id
               LEFT JOIN policies p ON p.id=cl.policy_id
               WHERE cl.status IN ('filed', 'investigating')
               ORDER BY cl.created_at DESC LIMIT 10""").fetchall()]

        # Commission summary
        commission = conn.execute(
            "SELECT COALESCE(SUM(commission_amount), 0) as total FROM policies WHERE status='active'"
        ).fetchone()
        commission_total = commission['total'] if commission else 0

    return render_template("crm/dashboard.html",
                           pipeline=pipeline, revenue=revenue,
                           renewals=renewals,
                           overdue=overdue,
                           pending_tasks=pending_tasks, open_claims=open_claims,
                           commission_total=commission_total)


@app.route("/crm/clients")
def list_clients():
    stage = request.args.get("stage", "")
    with get_db() as conn:
        if stage:
            if stage == 'archived':
                clients = conn.execute(
                    """SELECT cl.*, (SELECT name FROM contacts WHERE client_id=cl.id AND is_primary=1 LIMIT 1) as contact_name,
                       (SELECT MAX(created_at) FROM scans WHERE client_id=cl.id) as last_scan
                       FROM clients cl WHERE cl.archived=1 ORDER BY cl.company_name"""
                ).fetchall()
            else:
                clients = conn.execute(
                    """SELECT cl.*, (SELECT name FROM contacts WHERE client_id=cl.id AND is_primary=1 LIMIT 1) as contact_name,
                       (SELECT MAX(created_at) FROM scans WHERE client_id=cl.id) as last_scan
                       FROM clients cl WHERE cl.pipeline_stage=? AND (cl.archived=0 OR cl.archived IS NULL) ORDER BY cl.company_name""",
                    (stage,)
                ).fetchall()
        else:
            clients = conn.execute(
                """SELECT cl.*, (SELECT name FROM contacts WHERE client_id=cl.id AND is_primary=1 LIMIT 1) as contact_name,
                   (SELECT MAX(created_at) FROM scans WHERE client_id=cl.id) as last_scan
                   FROM clients cl WHERE (cl.archived=0 OR cl.archived IS NULL) ORDER BY cl.company_name"""
            ).fetchall()
    return render_template("crm/client_list.html",
                           clients=[dict(r) for r in clients], active_stage=stage or 'all')


@app.route("/crm/clients/new")
def new_client():
    return render_template("crm/client_form.html", client=None, contact=None)


@app.route("/crm/clients", methods=["POST"])
def create_client():
    f = request.form
    client_id = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    now = _now()

    with get_db() as conn:
        conn.execute(
            """INSERT INTO clients (id, company_name, trading_as, domain, industry,
               annual_revenue, employee_count, reseller, country, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (client_id, f.get('company_name', ''), f.get('trading_as', ''),
             f.get('domain', ''), f.get('industry', 'other'),
             float(f.get('annual_revenue', 0) or 0),
             int(f.get('employee_count', 0) or 0),
             f.get('reseller', ''), f.get('country', 'ZA'),
             f.get('notes', ''), now, now)
        )
        conn.execute(
            """INSERT INTO contacts (id, client_id, name, email, phone, role, is_primary, created_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            (contact_id, client_id, f.get('contact_name', ''),
             f.get('contact_email', ''), f.get('contact_phone', ''),
             f.get('contact_role', ''), now)
        )
        conn.commit()

    company_name = f.get('company_name', '')
    log_activity('client', client_id, client_id, 'created', f'Client {company_name} created')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/clients/<client_id>")
def view_client(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            abort(404)
        client = dict(client)

        contacts = [dict(r) for r in conn.execute(
            "SELECT * FROM contacts WHERE client_id=? ORDER BY is_primary DESC, name", (client_id,)
        ).fetchall()]

        scans = [dict(r) for r in conn.execute(
            "SELECT * FROM scans WHERE client_id=? ORDER BY created_at DESC", (client_id,)
        ).fetchall()]

        quotes = [dict(r) for r in conn.execute(
            "SELECT * FROM quotes q WHERE q.client_id=? AND (q.archived=0 OR q.archived IS NULL) ORDER BY q.created_at DESC", (client_id,)
        ).fetchall()]

        policies = [dict(r) for r in conn.execute(
            "SELECT * FROM policies WHERE client_id=? ORDER BY created_at DESC", (client_id,)
        ).fetchall()]

        invoices_raw = conn.execute(
            "SELECT * FROM invoices inv WHERE inv.client_id=? AND (inv.archived=0 OR inv.archived IS NULL) ORDER BY inv.created_at DESC", (client_id,)
        ).fetchall()
        invoices = []
        for inv in invoices_raw:
            inv_dict = dict(inv)
            payments = [dict(p) for p in conn.execute(
                "SELECT * FROM payments WHERE invoice_id=? ORDER BY payment_date", (inv_dict['id'],)
            ).fetchall()]
            inv_dict['payments'] = payments
            inv_dict['paid_amount'] = sum(p['amount'] for p in payments)
            invoices.append(inv_dict)

        notes = [dict(r) for r in conn.execute(
            "SELECT * FROM client_notes WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]
        activities = [dict(r) for r in conn.execute(
            "SELECT * FROM activities WHERE client_id=? ORDER BY created_at DESC LIMIT 50",
            (client_id,)).fetchall()]
        roas = [dict(r) for r in conn.execute(
            "SELECT * FROM records_of_advice WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]
        claims = [dict(r) for r in conn.execute(
            """SELECT cl.*, p.policy_number FROM claims cl
               LEFT JOIN policies p ON p.id=cl.policy_id
               WHERE cl.client_id=? ORDER BY cl.created_at DESC""",
            (client_id,)).fetchall()]
        comms = [dict(r) for r in conn.execute(
            "SELECT * FROM communications WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]
        client_tasks = [dict(r) for r in conn.execute(
            "SELECT * FROM tasks WHERE client_id=? ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, due_date",
            (client_id,)).fetchall()]
        complaints = [dict(r) for r in conn.execute(
            "SELECT * FROM complaints WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]

    return render_template("crm/client_detail.html",
                           client=client, contacts=contacts, scans=scans,
                           quotes=quotes, policies=policies, invoices=invoices,
                           notes=notes, activities=activities,
                           roas=roas, claims=claims, comms=comms,
                           client_tasks=client_tasks, complaints=complaints)


@app.route("/crm/clients/<client_id>/edit")
def edit_client(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            abort(404)
        contact = conn.execute(
            "SELECT * FROM contacts WHERE client_id=? AND is_primary=1 LIMIT 1", (client_id,)
        ).fetchone()
    return render_template("crm/client_form.html",
                           client=dict(client),
                           contact=dict(contact) if contact else None)


@app.route("/crm/clients/<client_id>", methods=["POST"])
def update_client(client_id):
    f = request.form
    now = _now()

    with get_db() as conn:
        conn.execute(
            """UPDATE clients SET company_name=?, trading_as=?, domain=?, industry=?,
               annual_revenue=?, employee_count=?, reseller=?, country=?, notes=?, updated_at=?
               WHERE id=?""",
            (f.get('company_name', ''), f.get('trading_as', ''),
             f.get('domain', ''), f.get('industry', 'other'),
             float(f.get('annual_revenue', 0) or 0),
             int(f.get('employee_count', 0) or 0),
             f.get('reseller', ''), f.get('country', 'ZA'),
             f.get('notes', ''), now, client_id)
        )
        # Update primary contact
        existing = conn.execute(
            "SELECT id FROM contacts WHERE client_id=? AND is_primary=1 LIMIT 1", (client_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE contacts SET name=?, email=?, phone=?, role=? WHERE id=?",
                (f.get('contact_name', ''), f.get('contact_email', ''),
                 f.get('contact_phone', ''), f.get('contact_role', ''), existing['id'])
            )
        else:
            conn.execute(
                """INSERT INTO contacts (id, client_id, name, email, phone, role, is_primary, created_at)
                   VALUES (?,?,?,?,?,?,1,?)""",
                (str(uuid.uuid4()), client_id, f.get('contact_name', ''),
                 f.get('contact_email', ''), f.get('contact_phone', ''),
                 f.get('contact_role', ''), now)
            )
        conn.commit()

    log_activity('client', client_id, client_id, 'updated', 'Client details updated')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/clients/<client_id>/link-scan", methods=["POST"])
def link_scan(client_id):
    scan_id = request.form.get('scan_id', '')
    with get_db() as conn:
        conn.execute("UPDATE scans SET client_id=? WHERE id=?", (client_id, scan_id))
        # Update client domain from scan if empty
        client = conn.execute("SELECT domain FROM clients WHERE id=?", (client_id,)).fetchone()
        if client and not client['domain']:
            scan = conn.execute("SELECT domain FROM scans WHERE id=?", (scan_id,)).fetchone()
            if scan:
                conn.execute("UPDATE clients SET domain=?, updated_at=? WHERE id=?",
                             (scan['domain'], _now(), client_id))
        conn.commit()
    log_activity('scan', scan_id, client_id, 'linked', 'Scan linked to client')
    advance_pipeline(client_id, 'scanned')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/clients/<client_id>/run-scan", methods=["POST"])
def client_run_scan(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            abort(404)
        client = dict(client)

    domain = client.get('domain', '').strip()
    if not domain or not valid_domain(domain):
        return redirect(url_for('view_client', client_id=client_id))

    industry = client.get('industry', 'other') or 'other'
    annual_revenue = client.get('annual_revenue', 0) or 0

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, domain, industry, annual_revenue, client.get('country', ''))

    # Pre-link scan to client
    with get_db() as conn:
        conn.execute("UPDATE scans SET client_id=? WHERE id=?", (client_id, scan_id))
        conn.commit()

    t = threading.Thread(
        target=run_scan,
        args=(scan_id, domain, industry, annual_revenue,
              int(annual_revenue) if annual_revenue else 0, client.get('country', ''), False),
        daemon=True,
    )
    t.start()

    return redirect(f"/results/{scan_id}")


@app.route("/crm/clients/<client_id>/quotes/new")
def new_quote(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            abort(404)
        client = dict(client)

        # Find latest scan for this client
        scan = conn.execute(
            "SELECT * FROM scans WHERE client_id=? AND status='completed' ORDER BY created_at DESC LIMIT 1",
            (client_id,)
        ).fetchone()
        if not scan and client.get('domain'):
            scan = conn.execute(
                "SELECT * FROM scans WHERE domain=? AND status='completed' ORDER BY created_at DESC LIMIT 1",
                (client['domain'],)
            ).fetchone()

    prefill = {}
    if scan:
        scan = dict(scan)
        prefill['scan_id'] = scan['id']
        prefill['risk_score'] = scan.get('risk_score', 0)
        prefill['risk_level'] = scan.get('risk_level', '')
        if scan.get('results'):
            results = json.loads(scan['results'])
            insurance = results.get('insurance_analytics', {})
            prefill['cover_limit'] = insurance.get('recommended_cover_limit', 0)
            prefill['annual_premium'] = insurance.get('annual_premium', 0)
            prefill['monthly_premium'] = insurance.get('monthly_premium', 0)

    return render_template("crm/quote_form.html", client=client, prefill=prefill)


@app.route("/crm/clients/<client_id>/quotes", methods=["POST"])
def create_quote(client_id):
    f = request.form
    quote_id = str(uuid.uuid4())
    now = _now()

    with get_db() as conn:
        conn.execute(
            """INSERT INTO quotes (id, client_id, scan_id, cover_limit, annual_premium,
               monthly_premium, mdr_selection, mdr_discount, risk_score, risk_level,
               revenue_band, status, valid_until, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (quote_id, client_id, f.get('scan_id', ''),
             float(f.get('cover_limit', 0) or 0),
             float(f.get('annual_premium', 0) or 0),
             float(f.get('monthly_premium', 0) or 0),
             f.get('mdr_selection', 'no'),
             float(f.get('mdr_discount', 0) or 0),
             int(f.get('risk_score', 0) or 0),
             f.get('risk_level', ''),
             f.get('revenue_band', ''),
             'draft', f.get('valid_until', ''),
             f.get('notes', ''), now, now)
        )
        conn.commit()

    cover_limit = float(f.get('cover_limit', 0) or 0)
    log_activity('quote', quote_id, client_id, 'created', f'Quote created: R {cover_limit:,.0f} cover')
    advance_pipeline(client_id, 'quoted')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/quotes/<quote_id>/accept", methods=["POST"])
def accept_quote(quote_id):
    with get_db() as conn:
        quote = conn.execute("SELECT client_id FROM quotes WHERE id=?", (quote_id,)).fetchone()
        if not quote:
            abort(404)
        client_id = quote['client_id']
        conn.execute("UPDATE quotes SET status='accepted', updated_at=? WHERE id=?", (_now(), quote_id))
        conn.commit()
    log_activity('quote', quote_id, client_id, 'accepted', 'Quote accepted')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/quotes/<quote_id>/decline", methods=["POST"])
def decline_quote(quote_id):
    with get_db() as conn:
        quote = conn.execute("SELECT client_id FROM quotes WHERE id=?", (quote_id,)).fetchone()
        if not quote:
            abort(404)
        client_id = quote['client_id']
        conn.execute("UPDATE quotes SET status='declined', updated_at=? WHERE id=?", (_now(), quote_id))
        conn.commit()
    log_activity('quote', quote_id, client_id, 'declined', 'Quote declined')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/quotes/<quote_id>/bind", methods=["POST"])
def bind_quote(quote_id):
    with get_db() as conn:
        quote = conn.execute("SELECT * FROM quotes WHERE id=?", (quote_id,)).fetchone()
        if not quote:
            abort(404)
        quote = dict(quote)

        policy_id = str(uuid.uuid4())
        policy_number = _next_number('PHI', 'policies', 'policy_number')
        now = _now()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        expiry = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d")

        conn.execute(
            """INSERT INTO policies (id, client_id, quote_id, policy_number, cover_limit,
               annual_premium, inception_date, expiry_date, status, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (policy_id, quote['client_id'], quote_id, policy_number,
             quote['cover_limit'], quote['annual_premium'],
             today, expiry, 'active', '', now, now)
        )
        conn.execute("UPDATE quotes SET status='accepted', updated_at=? WHERE id=?", (now, quote_id))

        annual_premium = quote['annual_premium']
        commission_rate = 12.5  # Default 12.5% for cyber insurance
        commission_amount = annual_premium * (commission_rate / 100)
        conn.execute("""UPDATE policies SET commission_rate=?, commission_amount=? WHERE id=?""",
                     (commission_rate, commission_amount, policy_id))

        conn.commit()

    client_id = quote['client_id']
    log_activity('policy', policy_id, client_id, 'created', f'Policy {policy_number} bound')
    advance_pipeline(client_id, 'bound')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/policies/renewals")
def renewals_list():
    days = int(request.args.get('days', 60))
    if days not in (30, 60, 90):
        days = 60
    today = datetime.now(timezone.utc)
    cutoff = (today + timedelta(days=days)).strftime("%Y-%m-%d")
    today_str = today.strftime("%Y-%m-%d")
    with get_db() as conn:
        renewals_raw = conn.execute(
            """SELECT p.*, c.company_name FROM policies p
               JOIN clients c ON c.id = p.client_id
               WHERE p.status='active' AND p.expiry_date <= ? AND p.expiry_date >= ?
               ORDER BY p.expiry_date""",
            (cutoff, today_str)
        ).fetchall()
    renewals = []
    for r in renewals_raw:
        rd = dict(r)
        try:
            expiry = datetime.fromisoformat(rd['expiry_date'])
            rd['days_left'] = (expiry - today).days
        except Exception:
            rd['days_left'] = 0
        renewals.append(rd)
    return render_template("crm/renewals.html", renewals=renewals, active_days=days)


@app.route("/crm/policies/<policy_id>/renew", methods=["POST"])
def renew_policy(policy_id):
    with get_db() as conn:
        old = conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
        if not old:
            abort(404)
        old = dict(old)

        new_id = str(uuid.uuid4())
        new_number = _next_number('PHI', 'policies', 'policy_number')
        now = _now()
        inception = old['expiry_date']
        expiry = (datetime.fromisoformat(inception) + timedelta(days=365)).strftime("%Y-%m-%d")

        conn.execute(
            """INSERT INTO policies (id, client_id, quote_id, policy_number, cover_limit,
               annual_premium, inception_date, expiry_date, status, renewal_of, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (new_id, old['client_id'], old.get('quote_id', ''), new_number,
             old['cover_limit'], old['annual_premium'],
             inception, expiry, 'active', old['id'], '', now, now)
        )
        conn.execute("UPDATE policies SET status='renewed', updated_at=? WHERE id=?", (now, policy_id))
        conn.commit()

    client_id = old['client_id']
    log_activity('policy', new_id, client_id, 'renewed', f'Policy {new_number} renewed')
    advance_pipeline(client_id, 'renewal')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/clients/<client_id>/invoices/new")
def new_invoice(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            abort(404)
        client = dict(client)

        policy = conn.execute(
            "SELECT * FROM policies WHERE client_id=? AND status='active' ORDER BY created_at DESC LIMIT 1",
            (client_id,)
        ).fetchone()

    prefill = {}
    if policy:
        policy = dict(policy)
        prefill['policy_id'] = policy['id']
        prefill['description'] = f"Cyber Insurance Premium - Policy {policy['policy_number']}"
        prefill['amount'] = policy['annual_premium']

    return render_template("crm/invoice_form.html", client=client, prefill=prefill)


@app.route("/crm/clients/<client_id>/invoices", methods=["POST"])
def create_invoice(client_id):
    f = request.form
    invoice_id = str(uuid.uuid4())
    invoice_number = _next_number('INV', 'invoices', 'invoice_number')
    now = _now()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    due_days = int(f.get('due_days', 30) or 30)
    due_date = (datetime.now(timezone.utc) + timedelta(days=due_days)).strftime("%Y-%m-%d")

    descriptions = f.getlist('description[]')
    quantities = f.getlist('quantity[]')
    unit_prices = f.getlist('unit_price[]')

    subtotal = 0.0
    line_items = []
    for i, desc in enumerate(descriptions):
        if not desc.strip():
            continue
        qty = float(quantities[i]) if i < len(quantities) else 1
        price = float(unit_prices[i]) if i < len(unit_prices) else 0
        line_total = qty * price
        subtotal += line_total
        line_items.append((str(uuid.uuid4()), invoice_id, desc, qty, price, line_total, i))

    vat_rate = 15.0
    vat_amount = round(subtotal * vat_rate / 100, 2)
    total = round(subtotal + vat_amount, 2)

    with get_db() as conn:
        conn.execute(
            """INSERT INTO invoices (id, client_id, policy_id, invoice_number, issue_date,
               due_date, subtotal, vat_rate, vat_amount, total, status, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (invoice_id, client_id, f.get('policy_id', ''), invoice_number,
             today, due_date, subtotal, vat_rate, vat_amount, total,
             'draft', f.get('notes', ''), now, now)
        )
        for item in line_items:
            conn.execute(
                """INSERT INTO invoice_line_items (id, invoice_id, description, quantity,
                   unit_price, line_total, sort_order) VALUES (?,?,?,?,?,?,?)""",
                item
            )
        conn.commit()

    inv_number = invoice_number
    log_activity('invoice', invoice_id, client_id, 'created', f'Invoice {inv_number} created: R {total:,.0f}')
    return redirect(url_for('view_invoice', invoice_id=invoice_id))


@app.route("/crm/invoices/<invoice_id>")
def view_invoice(invoice_id):
    with get_db() as conn:
        invoice = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not invoice:
            abort(404)
        invoice = dict(invoice)

        line_items = [dict(r) for r in conn.execute(
            "SELECT * FROM invoice_line_items WHERE invoice_id=? ORDER BY sort_order",
            (invoice_id,)
        ).fetchall()]

        payments = [dict(r) for r in conn.execute(
            "SELECT * FROM payments WHERE invoice_id=? ORDER BY payment_date",
            (invoice_id,)
        ).fetchall()]

        client = conn.execute("SELECT * FROM clients WHERE id=?", (invoice['client_id'],)).fetchone()
        client = dict(client) if client else {}

    invoice['paid_amount'] = sum(p['amount'] for p in payments)

    return render_template("crm/invoice_detail.html",
                           invoice=invoice, line_items=line_items,
                           payments=payments, client=client)


@app.route("/crm/invoices/<invoice_id>/pdf")
def invoice_pdf(invoice_id):
    with get_db() as conn:
        invoice = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not invoice:
            abort(404)
        invoice = dict(invoice)

        line_items = [dict(r) for r in conn.execute(
            "SELECT * FROM invoice_line_items WHERE invoice_id=? ORDER BY sort_order",
            (invoice_id,)
        ).fetchall()]

        client = conn.execute("SELECT * FROM clients WHERE id=?", (invoice['client_id'],)).fetchone()
        client = dict(client) if client else {}

    from pdf_report import generate_invoice_pdf
    pdf_bytes = generate_invoice_pdf(invoice, line_items, client)

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{invoice['invoice_number']}.pdf",
    )


@app.route("/crm/invoices/<invoice_id>/pay", methods=["POST"])
def record_payment(invoice_id):
    f = request.form
    payment_id = str(uuid.uuid4())
    now = _now()

    with get_db() as conn:
        invoice = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not invoice:
            abort(404)
        invoice = dict(invoice)

        conn.execute(
            """INSERT INTO payments (id, invoice_id, amount, method, reference, payment_date, notes, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (payment_id, invoice_id, float(f.get('amount', 0) or 0),
             f.get('method', ''), f.get('reference', ''),
             f.get('payment_date', now[:10]), f.get('notes', ''), now)
        )

        # Check if fully paid
        total_paid = conn.execute(
            "SELECT COALESCE(SUM(amount), 0) as s FROM payments WHERE invoice_id=?",
            (invoice_id,)
        ).fetchone()['s']
        if total_paid >= invoice['total']:
            conn.execute("UPDATE invoices SET status='paid', updated_at=? WHERE id=?", (now, invoice_id))

        conn.commit()

    amount = float(f.get('amount', 0) or 0)
    client_id = invoice['client_id']
    log_activity('payment', payment_id, client_id, 'payment_recorded', f'Payment R {amount:,.0f} recorded')
    return redirect(url_for('view_invoice', invoice_id=invoice_id))


@app.route("/crm/clients/<client_id>/notes", methods=["POST"])
def add_client_note(client_id):
    text = request.form.get('text', '').strip()
    if not text:
        flash("Note cannot be empty", "warning")
        return redirect(url_for('view_client', client_id=client_id))
    note_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute("INSERT INTO client_notes (id, client_id, text, created_at) VALUES (?,?,?,?)",
                     (note_id, client_id, text, _now()))
        conn.commit()
    log_activity('client', client_id, client_id, 'note_added', 'Note added')
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/clients/<client_id>/notes/<note_id>/delete", methods=["POST"])
def delete_client_note(client_id, note_id):
    with get_db() as conn:
        conn.execute("DELETE FROM client_notes WHERE id=? AND client_id=?", (note_id, client_id))
        conn.commit()
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/search")
def crm_search():
    q = request.args.get('q', '').strip()
    if not q:
        return render_template("crm/search_results.html", q='', results={})
    like = f'%{q}%'
    with get_db() as conn:
        clients = [dict(r) for r in conn.execute(
            "SELECT id, company_name, domain, pipeline_stage FROM clients WHERE (company_name LIKE ? OR domain LIKE ?) AND (archived=0 OR archived IS NULL) ORDER BY company_name LIMIT 20",
            (like, like)).fetchall()]
        policies = [dict(r) for r in conn.execute(
            "SELECT p.id, p.policy_number, p.status, c.company_name, p.client_id FROM policies p JOIN clients c ON c.id=p.client_id WHERE p.policy_number LIKE ? LIMIT 20",
            (like,)).fetchall()]
        invoices = [dict(r) for r in conn.execute(
            "SELECT i.id, i.invoice_number, i.status, i.total, c.company_name, i.client_id FROM invoices i JOIN clients c ON c.id=i.client_id WHERE i.invoice_number LIKE ? LIMIT 20",
            (like,)).fetchall()]
    return render_template("crm/search_results.html", q=q,
                           results={'clients': clients, 'policies': policies, 'invoices': invoices})


@app.route("/crm/invoices/<invoice_id>/send", methods=["POST"])
def send_invoice(invoice_id):
    with get_db() as conn:
        inv = conn.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not inv:
            flash("Invoice not found", "danger")
            return redirect(url_for('crm_dashboard'))
        if inv['status'] != 'draft':
            flash("Only draft invoices can be sent", "warning")
            return redirect(url_for('view_invoice', invoice_id=invoice_id))
        conn.execute("UPDATE invoices SET status='sent', updated_at=? WHERE id=?", (_now(), invoice_id))
        conn.commit()
    log_activity('invoice', invoice_id, inv['client_id'], 'sent', f'Invoice {inv["invoice_number"]} marked as sent')
    flash("Invoice marked as sent", "success")
    return redirect(url_for('view_invoice', invoice_id=invoice_id))


@app.route("/crm/clients/<client_id>/archive", methods=["POST"])
def archive_client(client_id):
    with get_db() as conn:
        conn.execute("UPDATE clients SET archived=1, updated_at=? WHERE id=?", (_now(), client_id))
        conn.commit()
    log_activity('client', client_id, client_id, 'archived', 'Client archived')
    flash("Client archived", "success")
    return redirect(url_for('list_clients'))


@app.route("/crm/clients/<client_id>/unarchive", methods=["POST"])
def unarchive_client(client_id):
    with get_db() as conn:
        conn.execute("UPDATE clients SET archived=0, updated_at=? WHERE id=?", (_now(), client_id))
        conn.commit()
    log_activity('client', client_id, client_id, 'unarchived', 'Client unarchived')
    flash("Client restored", "success")
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/quotes/<quote_id>/archive", methods=["POST"])
def archive_quote(quote_id):
    with get_db() as conn:
        q = conn.execute("SELECT client_id FROM quotes WHERE id=?", (quote_id,)).fetchone()
        conn.execute("UPDATE quotes SET archived=1, updated_at=? WHERE id=?", (_now(), quote_id))
        conn.commit()
        client_id = q['client_id'] if q else ''
    log_activity('quote', quote_id, client_id, 'archived', 'Quote archived')
    flash("Quote archived", "success")
    return redirect(url_for('view_client', client_id=client_id))


@app.route("/crm/invoices/<invoice_id>/archive", methods=["POST"])
def archive_invoice(invoice_id):
    with get_db() as conn:
        inv = conn.execute("SELECT client_id FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        conn.execute("UPDATE invoices SET archived=1, updated_at=? WHERE id=?", (_now(), invoice_id))
        conn.commit()
        client_id = inv['client_id'] if inv else ''
    log_activity('invoice', invoice_id, client_id, 'archived', 'Invoice archived')
    flash("Invoice archived", "success")
    return redirect(url_for('view_client', client_id=client_id))


# ── Record of Advice (ROA) ──────────────────────────────────────────

@app.route("/crm/clients/<client_id>/roa/new")
def new_roa(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            flash("Client not found", "danger")
            return redirect(url_for('list_clients'))
        quotes = [dict(r) for r in conn.execute(
            "SELECT id, cover_limit, annual_premium, status, created_at FROM quotes WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]
        policies = [dict(r) for r in conn.execute(
            "SELECT id, policy_number, cover_limit, annual_premium FROM policies WHERE client_id=? ORDER BY created_at DESC",
            (client_id,)).fetchall()]
    return render_template("crm/roa_form.html", client=dict(client), quotes=quotes, policies=policies, roa=None)

@app.route("/crm/clients/<client_id>/roa", methods=["POST"])
def create_roa(client_id):
    f = request.form
    roa_id = str(uuid.uuid4())
    now = _now()
    with get_db() as conn:
        conn.execute("""INSERT INTO records_of_advice
            (id, client_id, quote_id, policy_id, advisor_name, client_needs, risk_profile,
             products_recommended, reasons, alternatives_considered, disclosures, client_acknowledged,
             created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (roa_id, client_id, f.get('quote_id', ''), f.get('policy_id', ''),
             f.get('advisor_name', ''), f.get('client_needs', ''), f.get('risk_profile', ''),
             f.get('products_recommended', ''), f.get('reasons', ''),
             f.get('alternatives_considered', ''), f.get('disclosures', ''),
             1 if f.get('client_acknowledged') else 0, now, now))
        conn.commit()
    log_activity('roa', roa_id, client_id, 'created', 'Record of Advice created')
    flash("Record of Advice saved", "success")
    return redirect(url_for('view_client', client_id=client_id))

@app.route("/crm/roa/<roa_id>")
def view_roa(roa_id):
    with get_db() as conn:
        roa = conn.execute("SELECT * FROM records_of_advice WHERE id=?", (roa_id,)).fetchone()
        if not roa:
            flash("ROA not found", "danger")
            return redirect(url_for('crm_dashboard'))
        roa = dict(roa)
        client = conn.execute("SELECT * FROM clients WHERE id=?", (roa['client_id'],)).fetchone()
    return render_template("crm/roa_detail.html", roa=roa, client=dict(client))


# ── Claims Management ────────────────────────────────────────────────

@app.route("/crm/clients/<client_id>/claims/new")
def new_claim(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not client:
            flash("Client not found", "danger")
            return redirect(url_for('list_clients'))
        policies = [dict(r) for r in conn.execute(
            "SELECT id, policy_number, cover_limit FROM policies WHERE client_id=? AND status='active'",
            (client_id,)).fetchall()]
    return render_template("crm/claim_form.html", client=dict(client), policies=policies, claim=None)

@app.route("/crm/clients/<client_id>/claims", methods=["POST"])
def create_claim(client_id):
    f = request.form
    claim_id = str(uuid.uuid4())
    claim_number = _next_number("CLM", "claims", "claim_number")
    now = _now()
    with get_db() as conn:
        conn.execute("""INSERT INTO claims
            (id, client_id, policy_id, claim_number, claim_date, incident_date, incident_type,
             description, amount_claimed, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (claim_id, client_id, f.get('policy_id', ''), claim_number,
             f.get('claim_date', now[:10]), f.get('incident_date', ''),
             f.get('incident_type', ''), f.get('description', ''),
             float(f.get('amount_claimed', 0) or 0), 'filed', now, now))
        conn.commit()
    log_activity('claim', claim_id, client_id, 'created', f'Claim {claim_number} filed')
    flash(f"Claim {claim_number} filed", "success")
    return redirect(url_for('view_client', client_id=client_id))

@app.route("/crm/claims/<claim_id>")
def view_claim(claim_id):
    with get_db() as conn:
        claim = conn.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
        if not claim:
            flash("Claim not found", "danger")
            return redirect(url_for('crm_dashboard'))
        claim = dict(claim)
        client = conn.execute("SELECT * FROM clients WHERE id=?", (claim['client_id'],)).fetchone()
        policy = conn.execute("SELECT * FROM policies WHERE id=?", (claim['policy_id'],)).fetchone()
    return render_template("crm/claim_detail.html", claim=claim, client=dict(client),
                           policy=dict(policy) if policy else {})

@app.route("/crm/claims/<claim_id>/update", methods=["POST"])
def update_claim(claim_id):
    f = request.form
    now = _now()
    with get_db() as conn:
        claim = conn.execute("SELECT * FROM claims WHERE id=?", (claim_id,)).fetchone()
        if not claim:
            flash("Claim not found", "danger")
            return redirect(url_for('crm_dashboard'))
        new_status = f.get('status', claim['status'])
        conn.execute("""UPDATE claims SET status=?, amount_claimed=?, amount_paid=?,
            resolution_notes=?, updated_at=? WHERE id=?""",
            (new_status, float(f.get('amount_claimed', claim['amount_claimed']) or 0),
             float(f.get('amount_paid', claim['amount_paid']) or 0),
             f.get('resolution_notes', claim['resolution_notes']), now, claim_id))
        conn.commit()
    log_activity('claim', claim_id, claim['client_id'], 'updated', f'Claim updated to {new_status}')
    flash("Claim updated", "success")
    return redirect(url_for('view_claim', claim_id=claim_id))

@app.route("/crm/claims")
def list_claims():
    status_filter = request.args.get('status', 'all')
    with get_db() as conn:
        if status_filter != 'all':
            claims = [dict(r) for r in conn.execute(
                """SELECT cl.*, c.company_name, p.policy_number FROM claims cl
                   JOIN clients c ON c.id=cl.client_id
                   LEFT JOIN policies p ON p.id=cl.policy_id
                   WHERE cl.status=? ORDER BY cl.created_at DESC""",
                (status_filter,)).fetchall()]
        else:
            claims = [dict(r) for r in conn.execute(
                """SELECT cl.*, c.company_name, p.policy_number FROM claims cl
                   JOIN clients c ON c.id=cl.client_id
                   LEFT JOIN policies p ON p.id=cl.policy_id
                   ORDER BY cl.created_at DESC""").fetchall()]
    return render_template("crm/claims_list.html", claims=claims, active_status=status_filter)


# ── Communication Log ────────────────────────────────────────────────

@app.route("/crm/clients/<client_id>/comms", methods=["POST"])
def add_communication(client_id):
    f = request.form
    comm_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute("""INSERT INTO communications (id, client_id, comm_type, subject, body, created_at)
            VALUES (?,?,?,?,?,?)""",
            (comm_id, client_id, f.get('comm_type', 'note'), f.get('subject', ''),
             f.get('body', ''), _now()))
        conn.commit()
    log_activity('communication', comm_id, client_id, 'logged', f'{f.get("comm_type", "note").title()}: {f.get("subject", "")}')
    flash("Communication logged", "success")
    return redirect(url_for('view_client', client_id=client_id))


# ── Tasks ─────────────────────────────────────────────────────────────

@app.route("/crm/tasks")
def list_tasks():
    status_filter = request.args.get('status', 'pending')
    with get_db() as conn:
        if status_filter == 'all':
            tasks = [dict(r) for r in conn.execute(
                """SELECT t.*, c.company_name FROM tasks t
                   LEFT JOIN clients c ON c.id=t.client_id
                   ORDER BY CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, t.due_date""").fetchall()]
        else:
            tasks = [dict(r) for r in conn.execute(
                """SELECT t.*, c.company_name FROM tasks t
                   LEFT JOIN clients c ON c.id=t.client_id
                   WHERE t.status=?
                   ORDER BY CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, t.due_date""",
                (status_filter,)).fetchall()]
    return render_template("crm/tasks_list.html", tasks=tasks, active_status=status_filter)

@app.route("/crm/tasks/new")
def new_task():
    client_id = request.args.get('client_id', '')
    with get_db() as conn:
        clients = [dict(r) for r in conn.execute(
            "SELECT id, company_name FROM clients WHERE (archived=0 OR archived IS NULL) ORDER BY company_name").fetchall()]
    return render_template("crm/task_form.html", clients=clients, prefill_client=client_id, task=None)

@app.route("/crm/tasks", methods=["POST"])
def create_task():
    f = request.form
    task_id = str(uuid.uuid4())
    now = _now()
    client_id = f.get('client_id', '')
    with get_db() as conn:
        conn.execute("""INSERT INTO tasks (id, client_id, title, description, due_date, priority, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (task_id, client_id, f.get('title', ''), f.get('description', ''),
             f.get('due_date', ''), f.get('priority', 'medium'), 'pending', now, now))
        conn.commit()
    if client_id:
        log_activity('task', task_id, client_id, 'created', f'Task: {f.get("title", "")}')
    flash("Task created", "success")
    if client_id:
        return redirect(url_for('view_client', client_id=client_id))
    return redirect(url_for('list_tasks'))

@app.route("/crm/tasks/<task_id>/complete", methods=["POST"])
def complete_task(task_id):
    with get_db() as conn:
        task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if task:
            conn.execute("UPDATE tasks SET status='completed', updated_at=? WHERE id=?", (_now(), task_id))
            conn.commit()
            if task['client_id']:
                log_activity('task', task_id, task['client_id'], 'completed', f'Task completed: {task["title"]}')
    flash("Task completed", "success")
    return redirect(request.referrer or url_for('list_tasks'))

@app.route("/crm/tasks/<task_id>/delete", methods=["POST"])
def delete_task(task_id):
    with get_db() as conn:
        conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        conn.commit()
    flash("Task deleted", "success")
    return redirect(request.referrer or url_for('list_tasks'))


# ── Complaints Register (FAIS requirement) ───────────────────────────

@app.route("/crm/clients/<client_id>/complaints", methods=["POST"])
def create_complaint(client_id):
    f = request.form
    comp_id = str(uuid.uuid4())
    now = _now()
    with get_db() as conn:
        conn.execute("""INSERT INTO complaints (id, client_id, subject, description, status, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?)""",
            (comp_id, client_id, f.get('subject', ''), f.get('description', ''), 'open', now, now))
        conn.commit()
    log_activity('complaint', comp_id, client_id, 'created', f'Complaint: {f.get("subject", "")}')
    flash("Complaint recorded", "success")
    return redirect(url_for('view_client', client_id=client_id))

@app.route("/crm/complaints/<complaint_id>/resolve", methods=["POST"])
def resolve_complaint(complaint_id):
    f = request.form
    with get_db() as conn:
        comp = conn.execute("SELECT * FROM complaints WHERE id=?", (complaint_id,)).fetchone()
        if comp:
            conn.execute("UPDATE complaints SET status='resolved', resolution=?, updated_at=? WHERE id=?",
                         (f.get('resolution', ''), _now(), complaint_id))
            conn.commit()
            log_activity('complaint', complaint_id, comp['client_id'], 'resolved', 'Complaint resolved')
    flash("Complaint resolved", "success")
    return redirect(request.referrer or url_for('crm_dashboard'))


@app.route("/api/lead", methods=["POST"])
def capture_lead():
    data = request.get_json(silent=True) or {}
    client_id = str(uuid.uuid4())
    contact_id = str(uuid.uuid4())
    quote_id = str(uuid.uuid4())
    now = _now()

    with get_db() as conn:
        conn.execute(
            """INSERT INTO clients (id, company_name, trading_as, industry, annual_revenue,
               employee_count, reseller, country, pipeline_stage, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (client_id, data.get('company_name', ''), data.get('trading_as', ''),
             data.get('industry', 'other'), 0,
             int(data.get('employee_count', 0) or 0),
             data.get('reseller', ''), 'ZA', 'lead', now, now)
        )
        conn.execute(
            """INSERT INTO contacts (id, client_id, name, email, phone, role, is_primary, created_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            (contact_id, client_id, data.get('contact_person', ''),
             data.get('email', ''), data.get('contact_number', ''), '', now)
        )
        conn.execute(
            """INSERT INTO quotes (id, client_id, cover_limit, annual_premium, monthly_premium,
               mdr_selection, revenue_band, status, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (quote_id, client_id,
             float(data.get('cover_limit', 0) or 0),
             float(data.get('annual_premium', 0) or 0),
             float(data.get('monthly_premium', 0) or 0),
             data.get('mdr_selection', 'no'),
             data.get('revenue_band', ''),
             'draft', now, now)
        )
        conn.commit()

    return jsonify({"client_id": client_id, "quote_id": quote_id, "status": "lead_captured"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
