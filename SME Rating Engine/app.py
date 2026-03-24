"""
SME Rating Engine — Flask Backend
Serves static files + API for quote storage in SQLite.

Phishield UMA (Pty) Ltd
"""

import os
import uuid
import json
import sqlite3
import base64
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, send_file, abort
from flask_cors import CORS

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "quotes.db"))
PDF_DIR = BASE_DIR / "quote_pdfs"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "sme-dev-key-change-in-prod")
CORS(app)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quotes (
                id                  TEXT PRIMARY KEY,
                quote_ref           TEXT UNIQUE NOT NULL,
                base_ref            TEXT,
                company_name        TEXT NOT NULL,
                industry_main       TEXT,
                industry_sub        TEXT,
                turnover_prev       REAL,
                turnover_current    REAL,
                actual_turnover     REAL,
                revenue_band        TEXT,
                employee_count      INTEGER,
                quote_type          TEXT,
                market_condition    TEXT,
                prior_claim         INTEGER DEFAULT 0,

                uw_answers          TEXT,
                uw_outcome          TEXT,
                uw_loading_pct      REAL DEFAULT 0,
                uw_conditions       TEXT,
                endorsements        TEXT,

                cover_selections    TEXT,

                posture_discount        REAL DEFAULT 0,
                discretionary_discount  REAL DEFAULT 0,

                competitor_name     TEXT,
                competitor_data     TEXT,

                renewal_cover_limit TEXT,
                renewal_premium     REAL,

                pdf_filename        TEXT,

                status              TEXT DEFAULT 'draft',
                created_by          TEXT DEFAULT '',
                created_at          TEXT NOT NULL,
                updated_at          TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_company    ON quotes(company_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_quote_ref  ON quotes(quote_ref)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON quotes(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status     ON quotes(status)")

        # Add base_ref column if not exists (migration for existing DBs)
        try:
            conn.execute("SELECT base_ref FROM quotes LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE quotes ADD COLUMN base_ref TEXT")
            print("Migrated: added base_ref column to quotes table")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_base_ref   ON quotes(base_ref)")

    print(f"Database ready at {DB_PATH}")


# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.errorhandler(404)
def not_found(e):
    """Serve static files as fallback for unmatched routes."""
    path = request.path.lstrip("/")
    if not path or path.startswith(("api/", "health")):
        return jsonify({"error": "Not found"}), 404
    if path.startswith(("quotes.db", "quote_pdfs/", "app.py", "__pycache__", "requirements.txt")):
        return jsonify({"error": "Not found"}), 404
    filepath = BASE_DIR / path
    if filepath.exists() and filepath.is_file():
        return send_from_directory(str(BASE_DIR), path)
    return jsonify({"error": "Not found"}), 404


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "sme-rating-engine"})


# ---------------------------------------------------------------------------
# API: Save quote
# ---------------------------------------------------------------------------

@app.route("/api/quotes", methods=["POST"])
def save_quote():
    data = request.get_json(force=True)

    quote_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    quote_ref = data.get("quoteRef", "")
    base_ref = data.get("baseRef", quote_ref)  # Shared base ref across multi-cover options
    company = data.get("companyName", "Unknown")

    # Handle PDF if provided (base64-encoded)
    pdf_filename = None
    pdf_b64 = data.get("pdfBase64")
    if pdf_b64:
        # Build folder path: quote_pdfs/YYYY/MM/CompanyName/
        dt = datetime.now()
        safe_company = "".join(c if c.isalnum() or c in " _-" else "_" for c in company).strip()
        pdf_folder = PDF_DIR / str(dt.year) / f"{dt.month:02d}" / safe_company
        pdf_folder.mkdir(parents=True, exist_ok=True)

        cover_label = data.get("coverLabel", "quote")
        fname = f"{quote_ref}_{cover_label}.pdf"
        pdf_path = pdf_folder / fname

        try:
            pdf_bytes = base64.b64decode(pdf_b64)
            pdf_path.write_bytes(pdf_bytes)
            pdf_filename = str(pdf_path.relative_to(BASE_DIR))
        except Exception as e:
            print(f"PDF save error: {e}")

    with get_db() as conn:
        conn.execute("""
            INSERT INTO quotes (
                id, quote_ref, base_ref, company_name, industry_main, industry_sub,
                turnover_prev, turnover_current, actual_turnover, revenue_band,
                employee_count, quote_type, market_condition, prior_claim,
                uw_answers, uw_outcome, uw_loading_pct, uw_conditions, endorsements,
                cover_selections,
                posture_discount, discretionary_discount,
                competitor_name, competitor_data,
                renewal_cover_limit, renewal_premium,
                pdf_filename, status, created_by, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?
            )
        """, (
            quote_id,
            quote_ref,
            base_ref,
            company,
            data.get("industryMain", ""),
            data.get("industrySub", ""),
            data.get("turnoverPrev", 0),
            data.get("turnoverCurrent", 0),
            data.get("actualTurnover", 0),
            data.get("revenueBand", ""),
            data.get("employeeCount", 0),
            data.get("quoteType", "new"),
            data.get("marketCondition", ""),
            1 if data.get("priorClaim") else 0,
            json.dumps(data.get("uwAnswers", {})),
            data.get("uwOutcome", ""),
            data.get("uwLoadingPct", 0),
            json.dumps(data.get("uwConditions", [])),
            data.get("endorsements", ""),
            json.dumps(data.get("coverSelections", [])),
            data.get("postureDiscount", 0),
            data.get("discretionaryDiscount", 0),
            data.get("competitorName", ""),
            json.dumps(data.get("competitorData", [])),
            data.get("renewalCoverLimit", ""),
            data.get("renewalPremium", 0),
            pdf_filename,
            "final",
            data.get("createdBy", ""),
            now,
            now,
        ))

    return jsonify({
        "id": quote_id,
        "quoteRef": quote_ref,
        "pdfPath": pdf_filename,
        "message": "Quote saved successfully",
    }), 201


# ---------------------------------------------------------------------------
# API: Get single quote
# ---------------------------------------------------------------------------

@app.route("/api/quotes/<quote_id>", methods=["GET"])
def get_quote(quote_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM quotes WHERE id = ?", (quote_id,)).fetchone()
    if not row:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# API: List / search quotes
# ---------------------------------------------------------------------------

@app.route("/api/quotes", methods=["GET"])
def list_quotes():
    company = request.args.get("company", "")
    status = request.args.get("status", "")
    from_date = request.args.get("from", "")
    to_date = request.args.get("to", "")
    base_ref = request.args.get("base_ref", "")
    limit = int(request.args.get("limit", 100))

    query = "SELECT id, quote_ref, base_ref, company_name, industry_sub, actual_turnover, revenue_band, cover_selections, status, created_at FROM quotes WHERE 1=1"
    params = []

    if base_ref:
        query += " AND base_ref = ?"
        params.append(base_ref)
    if company:
        query += " AND company_name LIKE ?"
        params.append(f"%{company}%")
    if status:
        query += " AND status = ?"
        params.append(status)
    if from_date:
        query += " AND created_at >= ?"
        params.append(from_date)
    if to_date:
        query += " AND created_at <= ?"
        params.append(to_date)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# API: Update quote
# ---------------------------------------------------------------------------

@app.route("/api/quotes/<quote_id>", methods=["PUT"])
def update_quote(quote_id):
    data = request.get_json(force=True)
    now = datetime.now(timezone.utc).isoformat()

    allowed = {"status", "posture_discount", "discretionary_discount",
               "endorsements", "created_by"}
    updates = {k: v for k, v in data.items() if k in allowed}
    updates["updated_at"] = now

    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [quote_id]

    with get_db() as conn:
        result = conn.execute(f"UPDATE quotes SET {set_clause} WHERE id = ?", values)
        if result.rowcount == 0:
            return jsonify({"error": "Quote not found"}), 404

    return jsonify({"message": "Quote updated", "id": quote_id})


# ---------------------------------------------------------------------------
# API: Archive (soft delete) quote
# ---------------------------------------------------------------------------

@app.route("/api/quotes/<quote_id>", methods=["DELETE"])
def archive_quote(quote_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        result = conn.execute(
            "UPDATE quotes SET status = 'archived', updated_at = ? WHERE id = ?",
            (now, quote_id)
        )
        if result.rowcount == 0:
            return jsonify({"error": "Quote not found"}), 404

    return jsonify({"message": "Quote archived", "id": quote_id})


# ---------------------------------------------------------------------------
# API: Download stored PDF
# ---------------------------------------------------------------------------

@app.route("/api/quotes/<quote_id>/pdf", methods=["GET"])
def download_pdf(quote_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT pdf_filename, company_name, quote_ref FROM quotes WHERE id = ?",
            (quote_id,)
        ).fetchone()

    if not row or not row["pdf_filename"]:
        return jsonify({"error": "PDF not found"}), 404

    pdf_path = BASE_DIR / row["pdf_filename"]
    if not pdf_path.exists():
        return jsonify({"error": "PDF file missing from disk"}), 404

    return send_file(
        str(pdf_path),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=pdf_path.name,
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5002))
    print(f"SME Rating Engine running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
else:
    # Gunicorn: init DB on import
    init_db()
