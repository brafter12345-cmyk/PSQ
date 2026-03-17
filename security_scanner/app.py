"""
Cyber Insurance Security Scanner — Flask API
Endpoints:
  POST /api/scan           {"domain": "example.co.za"}   → {scan_id, status}
  GET  /api/scan/<id>      → JSON results or {"status": "pending"}
  GET  /api/scan/<id>/pdf  → download PDF report
  GET  /results/<id>       → HTML visual report
  GET  /api/history/<dom>  → last 10 scans for a domain
"""

import io
import os
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, abort, send_file
from flask_cors import CORS

from scanner import SecurityScanner

app = Flask(__name__)
CORS(app)  # Allow cross-origin calls from Vercel frontend

HIBP_API_KEY     = os.environ.get("HIBP_API_KEY")      # Optional
DEHASHED_EMAIL   = os.environ.get("DEHASHED_EMAIL")    # Optional — paid
DEHASHED_API_KEY = os.environ.get("DEHASHED_API_KEY")  # Optional — paid
DB_PATH = os.environ.get("DB_PATH", "scans.db")
MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))

_semaphore = threading.Semaphore(MAX_CONCURRENT)


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
                created_at  TEXT NOT NULL,
                completed_at TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain)")
        conn.commit()


def save_scan(scan_id: str, domain: str):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO scans (id, domain, status, created_at) VALUES (?,?,?,?)",
            (scan_id, domain, "pending", datetime.now(timezone.utc).isoformat())
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


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

def run_scan(scan_id: str, domain: str, industry: str = "Other",
             annual_revenue_zar: int = 0,
             include_fraudulent_domains: bool = False):
    with _semaphore:
        try:
            scanner = SecurityScanner(
                hibp_api_key=HIBP_API_KEY,
                dehashed_email=DEHASHED_EMAIL,
                dehashed_api_key=DEHASHED_API_KEY,
            )
            results = scanner.scan(domain, industry=industry,
                                   annual_revenue_zar=annual_revenue_zar,
                                   include_fraudulent_domains=include_fraudulent_domains)
            update_scan(scan_id, results)
        except Exception as e:
            mark_failed(scan_id, str(e))


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

    industry = str(data.get("industry", "Other")).strip()
    try:
        annual_revenue_zar = int(data.get("annual_revenue_zar", 0))
    except (ValueError, TypeError):
        annual_revenue_zar = 0
    include_fraudulent_domains = bool(data.get("include_fraudulent_domains", False))

    scan_id = str(uuid.uuid4())
    save_scan(scan_id, domain)

    t = threading.Thread(target=run_scan,
                         args=(scan_id, domain, industry, annual_revenue_zar,
                               include_fraudulent_domains),
                         daemon=True)
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
    )


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
