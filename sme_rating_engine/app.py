"""
SME Rating Engine — Flask backend (VM build).

Serves the built React SPA (frontend/dist) + a Postgres-backed quote-store API.
Mounted under /smerating on the VM via Caddy handle_path (which strips the
prefix), so this app runs at the web root and needs no prefix awareness: the
React bundle is built with base=/smerating/ and the frontend's one API call is
base-aware, so every request that reaches Flask is already root-relative.

Phishield UMA (Pty) Ltd / Bryte Insurance Company Limited.
"""
import os
import uuid
import base64
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from psycopg2.extras import Json

import sme_db

# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "frontend" / "dist"
# PDFs live OUTSIDE the code tree so deploys (which re-extract code) never wipe
# them; the deploy script points PDF_DIR at the preserved data dir.
PDF_DIR = Path(os.environ.get("PDF_DIR", str(BASE_DIR / "quote_pdfs")))

app = Flask(__name__, static_folder=str(DIST_DIR), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "sme-dev-key-change-in-prod")
CORS(app)

# Best-effort schema ensure on boot (deploy also runs it explicitly). Never let a
# transient DB hiccup stop the app from serving the SPA.
try:
    sme_db.init_schema()
except Exception as e:  # noqa: BLE001
    print(f"SME Rating Engine: schema init deferred ({e})")


# ---------------------------------------------------------------------------
# Static SPA
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if not (DIST_DIR / "index.html").exists():
        return jsonify({"error": "frontend not built", "hint": "SME_BASE_PATH=/smerating/ npm run build in frontend/"}), 503
    return send_from_directory(str(DIST_DIR), "index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "sme-rating-engine"})


@app.errorhandler(404)
def spa_fallback(e):
    # API 404s stay JSON; everything else falls back to the SPA shell.
    if request.path.startswith(("/api/", "/health")):
        return jsonify({"error": "Not found"}), 404
    if (DIST_DIR / "index.html").exists():
        return send_from_directory(str(DIST_DIR), "index.html")
    return jsonify({"error": "Not found"}), 404


# ---------------------------------------------------------------------------
# API: quotes
# ---------------------------------------------------------------------------
_COLUMNS = [
    "id", "quote_ref", "base_ref", "company_name", "industry_main", "industry_sub",
    "turnover_prev", "turnover_current", "actual_turnover", "revenue_band",
    "employee_count", "quote_type", "market_condition", "prior_claim",
    "uw_answers", "uw_outcome", "uw_loading_pct", "uw_conditions", "endorsements",
    "cover_selections", "posture_discount", "discretionary_discount",
    "competitor_name", "competitor_data", "renewal_cover_limit", "renewal_premium",
    "pdf_filename", "status", "created_by", "created_at", "updated_at",
]


@app.route("/api/quotes", methods=["POST"])
def save_quote():
    data = request.get_json(force=True)
    quote_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    quote_ref = data.get("quoteRef", "")
    base_ref = data.get("baseRef", quote_ref)
    company = data.get("companyName", "Unknown")

    # Persist the client-generated PDF (base64) to the preserved PDF dir.
    pdf_filename = None
    pdf_b64 = data.get("pdfBase64")
    if pdf_b64:
        dt = datetime.now()
        safe_company = "".join(c if c.isalnum() or c in " _-" else "_" for c in company).strip() or "quote"
        folder = PDF_DIR / str(dt.year) / f"{dt.month:02d}" / safe_company
        folder.mkdir(parents=True, exist_ok=True)
        fname = f"{quote_ref}_{data.get('coverLabel', 'quote')}.pdf"
        path = folder / fname
        try:
            path.write_bytes(base64.b64decode(pdf_b64))
            pdf_filename = str(path.relative_to(PDF_DIR))
        except Exception as e:  # noqa: BLE001
            print(f"PDF save error: {e}")

    row = (
        quote_id, quote_ref, base_ref, company,
        data.get("industryMain", ""), data.get("industrySub", ""),
        data.get("turnoverPrev", 0), data.get("turnoverCurrent", 0), data.get("actualTurnover", 0),
        data.get("revenueBand", ""), data.get("employeeCount", 0),
        data.get("quoteType", "new"), data.get("marketCondition", ""),
        bool(data.get("priorClaim")),
        Json(data.get("uwAnswers", {})), data.get("uwOutcome", ""), data.get("uwLoadingPct", 0),
        Json(data.get("uwConditions", [])), data.get("endorsements", ""),
        Json(data.get("coverSelections", [])),
        data.get("postureDiscount", 0), data.get("discretionaryDiscount", 0),
        data.get("competitorName", ""), Json(data.get("competitorData", [])),
        data.get("renewalCoverLimit", ""), data.get("renewalPremium", 0),
        pdf_filename, "final", data.get("createdBy", ""), now, now,
    )
    placeholders = ", ".join(["%s"] * len(_COLUMNS))
    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO quotes ({', '.join(_COLUMNS)}) VALUES ({placeholders})", row)
        conn.commit()

    return jsonify({"id": quote_id, "quoteRef": quote_ref, "pdfPath": pdf_filename, "message": "Quote saved successfully"}), 201


@app.route("/api/quotes/<quote_id>", methods=["GET"])
def get_quote(quote_id):
    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM quotes WHERE id = %s", (quote_id,))
            row = cur.fetchone()
    if not row:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify(dict(row))


@app.route("/api/quotes", methods=["GET"])
def list_quotes():
    company = request.args.get("company", "")
    status = request.args.get("status", "")
    from_date = request.args.get("from", "")
    to_date = request.args.get("to", "")
    base_ref = request.args.get("base_ref", "")
    limit = int(request.args.get("limit", 100))

    query = ("SELECT id, quote_ref, base_ref, company_name, industry_sub, actual_turnover, "
             "revenue_band, cover_selections, status, created_at FROM quotes WHERE 1=1")
    params = []
    if base_ref:
        query += " AND base_ref = %s"; params.append(base_ref)
    if company:
        query += " AND company_name ILIKE %s"; params.append(f"%{company}%")
    if status:
        query += " AND status = %s"; params.append(status)
    if from_date:
        query += " AND created_at >= %s"; params.append(from_date)
    if to_date:
        query += " AND created_at <= %s"; params.append(to_date)
    query += " ORDER BY created_at DESC LIMIT %s"; params.append(limit)

    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/quotes/<quote_id>", methods=["PUT"])
def update_quote(quote_id):
    data = request.get_json(force=True)
    now = datetime.now(timezone.utc).isoformat()
    allowed = {"status", "posture_discount", "discretionary_discount", "endorsements", "created_by"}
    updates = {k: v for k, v in data.items() if k in allowed}
    updates["updated_at"] = now
    if len(updates) == 1:  # only updated_at
        return jsonify({"error": "No valid fields to update"}), 400
    set_clause = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [quote_id]
    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE quotes SET {set_clause} WHERE id = %s", values)
            affected = cur.rowcount
        conn.commit()
    if affected == 0:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify({"message": "Quote updated", "id": quote_id})


@app.route("/api/quotes/<quote_id>", methods=["DELETE"])
def archive_quote(quote_id):
    now = datetime.now(timezone.utc).isoformat()
    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE quotes SET status = 'archived', updated_at = %s WHERE id = %s", (now, quote_id))
            affected = cur.rowcount
        conn.commit()
    if affected == 0:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify({"message": "Quote archived", "id": quote_id})


@app.route("/api/quotes/<quote_id>/pdf", methods=["GET"])
def download_pdf(quote_id):
    with sme_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pdf_filename FROM quotes WHERE id = %s", (quote_id,))
            row = cur.fetchone()
    if not row or not row["pdf_filename"]:
        return jsonify({"error": "PDF not found"}), 404
    path = PDF_DIR / row["pdf_filename"]
    if not path.exists():
        return jsonify({"error": "PDF file missing from disk"}), 404
    return send_file(str(path), mimetype="application/pdf", as_attachment=True, download_name=path.name)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8002))
    print(f"SME Rating Engine running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
