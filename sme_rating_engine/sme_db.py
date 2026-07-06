"""
SME Rating Engine — Postgres data layer.

Dedicated Postgres 16 (VM container `sme-rating-pg`), reached via DATABASE_URL.
Standard SQL + parameterized (%s) queries + RealDictCursor. Fresh schema (no
SQLite migration). JSON columns are JSONB; money is DOUBLE PRECISION (faithful to
the legacy REAL/float behaviour, JSON-serialisable without Decimal surprises).
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL", "")


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set — configure the Postgres DSN in .env")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


DDL = """
CREATE TABLE IF NOT EXISTS quotes (
    id                     TEXT PRIMARY KEY,
    quote_ref              TEXT UNIQUE NOT NULL,
    base_ref               TEXT,
    company_name           TEXT NOT NULL,
    industry_main          TEXT,
    industry_sub           TEXT,
    turnover_prev          DOUBLE PRECISION,
    turnover_current       DOUBLE PRECISION,
    actual_turnover        DOUBLE PRECISION,
    revenue_band           TEXT,
    employee_count         INTEGER,
    quote_type             TEXT,
    market_condition       TEXT,
    prior_claim            BOOLEAN DEFAULT FALSE,
    uw_answers             JSONB,
    uw_outcome             TEXT,
    uw_loading_pct         DOUBLE PRECISION DEFAULT 0,
    uw_conditions          JSONB,
    endorsements           TEXT,
    cover_selections       JSONB,
    posture_discount       DOUBLE PRECISION DEFAULT 0,
    discretionary_discount DOUBLE PRECISION DEFAULT 0,
    competitor_name        TEXT,
    competitor_data        JSONB,
    renewal_cover_limit    TEXT,
    renewal_premium        DOUBLE PRECISION,
    pdf_filename           TEXT,
    status                 TEXT DEFAULT 'final',
    created_by             TEXT DEFAULT '',
    created_at             TEXT NOT NULL,
    updated_at             TEXT
);
CREATE INDEX IF NOT EXISTS idx_quotes_company    ON quotes(company_name);
CREATE INDEX IF NOT EXISTS idx_quotes_quote_ref  ON quotes(quote_ref);
CREATE INDEX IF NOT EXISTS idx_quotes_created_at ON quotes(created_at);
CREATE INDEX IF NOT EXISTS idx_quotes_base_ref   ON quotes(base_ref);
CREATE INDEX IF NOT EXISTS idx_quotes_status     ON quotes(status);
"""


def init_schema():
    """Idempotent — safe to run on every boot/deploy."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(DDL)
        conn.commit()
    print("SME Rating Engine: Postgres schema ready")
