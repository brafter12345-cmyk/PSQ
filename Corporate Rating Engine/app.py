"""
Corporate Rating Engine — Flask Backend
Serves the static web app + a small API for quote persistence in SQLite.
Sibling of the SME Rating Engine backend.

Phishield UMA (Pty) Ltd
"""

import os
import uuid
import json
import sqlite3
import base64
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

import document_extract

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "corporate_quotes.db"))
PDF_DIR = BASE_DIR / "quote_pdfs"
UPLOAD_DIR = BASE_DIR / "ingest_uploads"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "corp-dev-key-change-in-prod")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap
CORS(app)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quotes (
                id              TEXT PRIMARY KEY,
                quote_ref       TEXT UNIQUE NOT NULL,
                company_name    TEXT,
                website         TEXT,
                sub_industry    TEXT,
                turnover        REAL,
                cover           REAL,
                excess          REAL,
                vat             REAL,
                maturity        TEXT,
                fp_mode         TEXT,
                fp_adjustable   REAL,
                mdr             TEXT,
                benefits        TEXT,
                base_premium    REAL,
                final_premium   REAL,
                inputs          TEXT,
                result          TEXT,
                pdf_filename    TEXT,
                status          TEXT DEFAULT 'final',
                created_by      TEXT DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_company   ON quotes(company_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_quote_ref ON quotes(quote_ref)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_corp_created   ON quotes(created_at)")
    print(f"Corporate DB ready at {DB_PATH}")


# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.errorhandler(404)
def not_found(e):
    path = request.path.lstrip("/")
    if not path or path.startswith(("api/", "health")):
        return jsonify({"error": "Not found"}), 404
    if path.startswith(("corporate_quotes.db", "quote_pdfs/", "ingest_uploads/", "app.py",
                        "document_extract.py", "__pycache__", "requirements.txt", "test-engine", "tools/")):
        return jsonify({"error": "Not found"}), 404
    filepath = BASE_DIR / path
    if filepath.exists() and filepath.is_file():
        return send_from_directory(str(BASE_DIR), path)
    return jsonify({"error": "Not found"}), 404


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "corporate-rating-engine"})


# --------------------------------------------------------------------------
# API: ingest a risk-assessment form -> text (Phase 1: local extraction)
# --------------------------------------------------------------------------
ALLOWED_EXT = {"pdf", "docx", "xlsx", "xlsm", "txt", "md", "csv",
               "png", "jpg", "jpeg", "tif", "tiff", "bmp", "webp"}


@app.route("/api/ingest", methods=["POST"])
def ingest():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded (expected form field 'file')."}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "Empty filename."}), 400
    name = secure_filename(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        return jsonify({"ok": False, "error": f"Unsupported file type: .{ext or '?'}"}), 415

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / (uuid.uuid4().hex + "_" + name)
    f.save(str(dest))
    try:
        result = document_extract.extract(str(dest), name)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Extraction error: {exc}"}), 500

    result["filename"] = name
    result["stored_as"] = dest.name
    result["bytes"] = dest.stat().st_size
    # Trim very large text in the response (full text kept server-side for the mapping phase)
    if result.get("ok") and len(result.get("text", "")) > 200_000:
        result["text"] = result["text"][:200_000] + "\n\n…[truncated for preview]"
    return jsonify(result), (200 if result.get("ok") else 422)


# --------------------------------------------------------------------------
# API: map an ingested form against our questionnaire (Phase 2)
#   redact (PII out) -> Claude (or offline mock) -> rehydrate -> TIDE-style scorecard
# --------------------------------------------------------------------------
@app.route("/api/map", methods=["POST"])
def map_assessment_route():
    import mapping
    data = request.get_json(force=True) or {}
    stored = secure_filename(data.get("stored_as", ""))
    extra_terms = data.get("extra_terms", []) or []
    prefer = data.get("engine", "auto")  # auto | claude | mock

    text = data.get("text", "")
    if stored:
        path = UPLOAD_DIR / stored
        if not path.exists():
            return jsonify({"ok": False, "error": "Uploaded file not found — re-upload the form."}), 404
        ex = document_extract.extract(str(path), stored)
        if not ex.get("ok"):
            return jsonify({"ok": False, "error": ex.get("error", "Extraction failed.")}), 422
        # Do NOT map a document that has un-read (scanned) pages — nothing may slip through.
        if ex.get("needs_ocr"):
            oc = ex.get("ocr_pages", []) or []
            return jsonify({"ok": False, "needs_ocr": True, "ocr_pages": oc, "pages": ex.get("pages"),
                            "error": ("%d of %d page(s) are scanned and not yet read (page %s). "
                                      "Run OCR first (redaction server or local) so the whole form is mapped — "
                                      "not just its text pages." % (len(oc), ex.get("pages"),
                                                                    ", ".join(map(str, oc[:12]))))}), 422
        text = ex.get("text", "") or text
    if not text.strip():
        return jsonify({"ok": False, "error": "No text to map."}), 400

    try:
        result = mapping.map_assessment(text, extra_terms=extra_terms, prefer=prefer)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": f"Mapping error: {exc}"}), 500
    return jsonify(result), (200 if result.get("ok") else 422)


# --------------------------------------------------------------------------
# API: save quote
# --------------------------------------------------------------------------
@app.route("/api/quotes", methods=["POST"])
def save_quote():
    data = request.get_json(force=True)
    quote_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    quote_ref = data.get("quote_ref") or f"CRE-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:4]}"
    company = data.get("company_name", "Unknown")

    # Optional client-rendered PDF (base64) — archived under quote_pdfs/YYYY/MM/Company/
    pdf_filename = None
    pdf_b64 = data.get("pdf_base64")
    if pdf_b64:
        dt = datetime.now()
        safe = "".join(c if c.isalnum() or c in " _-" else "_" for c in company).strip() or "Unknown"
        folder = PDF_DIR / str(dt.year) / f"{dt.month:02d}" / safe
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{quote_ref}.pdf"
        try:
            path.write_bytes(base64.b64decode(pdf_b64))
            pdf_filename = str(path.relative_to(BASE_DIR))
        except Exception as exc:
            print(f"PDF save error: {exc}")

    with get_db() as conn:
        conn.execute("""
            INSERT INTO quotes (
                id, quote_ref, company_name, website, sub_industry, turnover, cover,
                excess, vat, maturity, fp_mode, fp_adjustable, mdr, benefits,
                base_premium, final_premium, inputs, result, pdf_filename,
                status, created_by, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            quote_id, quote_ref, company, data.get("website", ""), data.get("sub_industry", ""),
            data.get("turnover", 0), data.get("cover", 0), data.get("excess", 0), data.get("vat", 0),
            data.get("maturity", ""), data.get("fp_mode", ""), data.get("fp_adjustable", 0),
            data.get("mdr", ""), json.dumps(data.get("benefits", [])),
            data.get("base_premium", 0), data.get("final_premium", 0),
            json.dumps(data.get("inputs", {})), json.dumps(data.get("result", {})),
            pdf_filename, "final", data.get("created_by", ""), now, now,
        ))

    return jsonify({"id": quote_id, "quote_ref": quote_ref, "pdf_path": pdf_filename,
                    "message": "Quote saved"}), 201


@app.route("/api/quotes", methods=["GET"])
def list_quotes():
    company = request.args.get("company", "")
    limit = int(request.args.get("limit", 100))
    query = ("SELECT id, quote_ref, company_name, sub_industry, turnover, cover, "
             "final_premium, status, created_at FROM quotes WHERE 1=1")
    params = []
    if company:
        query += " AND company_name LIKE ?"
        params.append(f"%{company}%")
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/quotes/<quote_id>", methods=["GET"])
def get_quote(quote_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM quotes WHERE id = ?", (quote_id,)).fetchone()
    if not row:
        return jsonify({"error": "Quote not found"}), 404
    return jsonify(dict(row))


@app.route("/api/quotes/<quote_id>", methods=["DELETE"])
def archive_quote(quote_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        res = conn.execute("UPDATE quotes SET status='archived', updated_at=? WHERE id=?", (now, quote_id))
        if res.rowcount == 0:
            return jsonify({"error": "Quote not found"}), 404
    return jsonify({"message": "Quote archived", "id": quote_id})


@app.route("/api/quotes/<quote_id>/pdf", methods=["GET"])
def download_pdf(quote_id):
    with get_db() as conn:
        row = conn.execute("SELECT pdf_filename FROM quotes WHERE id = ?", (quote_id,)).fetchone()
    if not row or not row["pdf_filename"]:
        return jsonify({"error": "PDF not found"}), 404
    pdf_path = BASE_DIR / row["pdf_filename"]
    if not pdf_path.exists():
        return jsonify({"error": "PDF file missing"}), 404
    return send_file(str(pdf_path), mimetype="application/pdf", as_attachment=True, download_name=pdf_path.name)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5003))
    print(f"Corporate Rating Engine running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
else:
    init_db()
