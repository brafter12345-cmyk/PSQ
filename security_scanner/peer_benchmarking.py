"""Peer benchmarking — percentile-rank + 1.0-10.0 rating derivation.

Architecture (per SCN-028 / gap analysis v10):

1. **Data pool** (`benchmark_scans` table in scans.db) holds three classes
   of scan, tagged by `source`:
     - 'benchmark_pool'      — public-domain scans run by us bi-weekly
                               against curated SA reference companies.
                               No consent required (public infrastructure).
     - 'lower_tier_upsell'   — scans of Phishield's existing lower-tier
                               clients (~4,000 entities) run as part of
                               the premier-tier upsell flow. Phishield
                               owns the client relationship; broker
                               consent not required because no broker
                               is intermediating the lower-tier book.
     - 'client_optin'        — scans run by a broker / advisory for
                               their client, contributed to the pool
                               with explicit consent. Default: opt-out.
                               Drives the longer-term benchmark quality.

   The pool composition is surfaced in the report so brokers and
   clients see what the benchmark draws from.

2. **Cells** are keyed by (industry, sub_industry, revenue_band).
   Revenue bands match the capacity-factor table in scoring_analytics:
     micro   < R10M
     small   R10M - R50M
     medium  R50M - R200M
     large   R200M - R1B
     major   >= R1B

3. **Cell fallback** when N < 5 (insufficient sample size for stable
   percentile): widen progressively until a usable cell is found, or
   return 'insufficient_data' if even the global pool is too thin.

4. **Rating** is a percentile rank of (1000 - overall_risk_score) -
   risk score is inverted because lower = worse in the scanner's
   scale but higher = better in the rating - mapped linearly to
   1.0-10.0. Decimals retained for granularity.

5. **Critical findings count** is a cross-checker aggregate of
   severity='critical' issues, used as a secondary hero metric.
   Replaces the previously-considered compliance % which cannot be
   reliably determined from external scans alone (only ~10 of ~250
   PCI sub-requirements are externally observable; POPIA Section 19
   has similar gaps).
"""

import json
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional


# ---------------------------------------------------------------------------
# Revenue bands
# ---------------------------------------------------------------------------

def revenue_band(annual_revenue_zar: float) -> str:
    rev = float(annual_revenue_zar or 0)
    if rev >= 1_000_000_000:
        return "major"
    if rev >= 200_000_000:
        return "large"
    if rev >= 50_000_000:
        return "medium"
    if rev >= 10_000_000:
        return "small"
    return "micro"


REVENUE_BAND_DISPLAY = {
    "micro":  "Micro (< R10M)",
    "small":  "Small (R10M-R50M)",
    "medium": "Medium (R50M-R200M)",
    "large":  "Large (R200M-R1B)",
    "major":  "Major (>= R1B)",
}


# ---------------------------------------------------------------------------
# Critical findings counter (cross-checker aggregator)
# ---------------------------------------------------------------------------

def count_critical_findings(scan_result: dict) -> dict:
    """Aggregate CRITICAL-severity findings across all checkers.

    Sources (in priority order, matching how brokers and underwriters
    interpret severity):
      - shodan_vulns: count of cves with severity='critical' + KEV-listed
      - exposed_admin: critical-classified exposures
      - high_risk_protocols: critical-classified ports (DB ports, RDP, etc.)
      - info_disclosure: critical-classified file exposures
      - ssl: grade F or expired certificate
      - dehashed: plaintext passwords leaked
      - hudson_rock: active infostealer hits
      - external_ips: any IP scored 0 (max-risk per-IP)

    Returns a dict with breakdown by source plus a total. Drives the
    hero-strip 'Critical findings' metric.
    """
    cats = scan_result.get("categories", {}) or {}
    total = 0
    breakdown = {}

    # Shodan CVEs — critical-severity + KEV-listed
    sh = cats.get("shodan_vulns", {}) or {}
    sh_crit = int(sh.get("critical_count") or 0)
    sh_kev = int(sh.get("kev_count") or 0)
    val = sh_crit + max(0, sh_kev - sh_crit)  # KEV-not-already-critical
    if val:
        breakdown["shodan_vulns"] = val
        total += val

    # Exposed admin — critical paths exposed
    ea = cats.get("exposed_admin", {}) or {}
    val = int(ea.get("critical_count") or 0)
    if val:
        breakdown["exposed_admin"] = val
        total += val

    # High-risk protocols — critical-classified ports
    hrp = cats.get("high_risk_protocols", {}) or {}
    val = int(hrp.get("critical_count") or 0)
    if val:
        breakdown["high_risk_protocols"] = val
        total += val

    # Info disclosure — count exposed paths classified 'critical'
    info = cats.get("info_disclosure", {}) or {}
    exposed = info.get("exposed_paths") or []
    val = sum(1 for e in exposed if (e.get("risk_level") or "").lower() == "critical")
    if val:
        breakdown["info_disclosure"] = val
        total += val

    # SSL — F grade or expired cert is one critical finding
    ssl_r = cats.get("ssl", {}) or {}
    grade = (ssl_r.get("grade") or "").upper()
    if grade in ("F", "T") or "expired" in str(ssl_r.get("issues") or []).lower():
        breakdown["ssl"] = 1
        total += 1

    # Dehashed — plaintext passwords each count as a critical
    de = cats.get("dehashed", {}) or {}
    cb = de.get("credential_breakdown") or {}
    val = int(cb.get("plaintext_count") or 0)
    if val:
        breakdown["dehashed_plaintext"] = val
        total += val

    # Hudson Rock — active infostealer hits
    hr = cats.get("hudson_rock", {}) or {}
    val = int(hr.get("compromised_employees") or 0)
    if val:
        breakdown["hudson_rock"] = val
        total += val

    # External IPs — any IP scored 0 (max risk)
    ext = cats.get("external_ips", {}) or {}
    per_ip = ext.get("per_ip") or []
    val = sum(1 for ip in per_ip if int(ip.get("score") or 100) == 0)
    if val:
        breakdown["external_ips_max_risk"] = val
        total += val

    return {
        "total": total,
        "breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
# Peer aggregates lookup (with cell fallback)
# ---------------------------------------------------------------------------

# Minimum sample size for a cell to produce a stable percentile rank
MIN_CELL_N = 5

# Freshness window — benchmark scans older than this are excluded from
# the pool. Matches the bi-weekly refresh cadence (allow 3x for jitter).
FRESHNESS_DAYS = 90


def _db_query_cell(conn: sqlite3.Connection, industry: Optional[str],
                   sub_industry: Optional[str], revenue_band_key: Optional[str]) -> list:
    """Return list of (risk_score, critical_findings, rsi_score, ssl_grade,
    source) for active benchmark scans matching the cell. Wildcard cells
    pass None for that dimension."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=FRESHNESS_DAYS)).isoformat()
    where = ["is_active = 1", "scan_timestamp >= ?"]
    params = [cutoff]
    if industry is not None:
        where.append("LOWER(industry) = LOWER(?)")
        params.append(industry)
    if sub_industry is not None:
        where.append("LOWER(sub_industry) = LOWER(?)")
        params.append(sub_industry)
    if revenue_band_key is not None:
        where.append("revenue_band = ?")
        params.append(revenue_band_key)
    sql = ("SELECT risk_score, critical_findings, rsi_score, ssl_grade, source "
           "FROM benchmark_scans WHERE " + " AND ".join(where))
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(zip(["risk_score", "critical_findings", "rsi_score",
                          "ssl_grade", "source"], r)) for r in rows]
    except sqlite3.OperationalError:
        # Table may not exist yet on first deploy
        return []


def get_peer_cell(conn: sqlite3.Connection, industry: Optional[str],
                  sub_industry: Optional[str], revenue_band_key: str) -> dict:
    """Find the most-specific cell with N >= MIN_CELL_N, walking up the
    fallback ladder.

    Order:
      1. (industry, sub_industry, revenue_band)   -> most specific
      2. (industry, sub_industry, *)
      3. (industry, *, revenue_band)
      4. (industry, *, *)
      5. (*, *, *)                                 -> global pool
    """
    fallback_chain = [
        (industry, sub_industry, revenue_band_key, "industry+sub+band"),
        (industry, sub_industry, None,            "industry+sub"),
        (industry, None,         revenue_band_key, "industry+band"),
        (industry, None,         None,            "industry"),
        (None,     None,         None,            "global"),
    ]
    for ind, sub, band, label in fallback_chain:
        rows = _db_query_cell(conn, ind, sub, band)
        if len(rows) >= MIN_CELL_N:
            return {
                "cell_industry":     ind,
                "cell_sub_industry": sub,
                "cell_revenue_band": band,
                "cell_specificity":  label,
                "rows":              rows,
                "n":                 len(rows),
            }
    # Nothing matched - return the global pool for at least source-mix
    # disclosure even if N < threshold
    rows = _db_query_cell(conn, None, None, None)
    return {
        "cell_industry":     None,
        "cell_sub_industry": None,
        "cell_revenue_band": None,
        "cell_specificity":  "insufficient",
        "rows":              rows,
        "n":                 len(rows),
    }


def _percentile_of(value: float, distribution: list) -> float:
    """Percentile rank of `value` in `distribution`. 0..100. Average of
    'strictly below' and 'at or below' to handle ties cleanly."""
    if not distribution:
        return 50.0
    n = len(distribution)
    below = sum(1 for v in distribution if v < value)
    at_or_below = sum(1 for v in distribution if v <= value)
    return ((below + at_or_below) / 2.0) / n * 100.0


def compute_peer_rating(scan_result: dict, conn: sqlite3.Connection) -> dict:
    """End-to-end peer rating compute. Returns the dict that the
    scanner attaches to results['insurance']['peer_benchmarking']."""
    industry = (scan_result.get("scan_context") or {}).get("industry")
    sub_industry = (scan_result.get("scan_context") or {}).get("sub_industry")
    annual_rev = (scan_result.get("scan_context") or {}).get("annual_revenue") or 0
    annual_rev_zar = (scan_result.get("scan_context") or {}).get("annual_revenue_zar") or annual_rev
    own_risk_score = int(scan_result.get("overall_risk_score") or 500)
    own_critical = count_critical_findings(scan_result).get("total", 0)
    band = revenue_band(annual_rev_zar)

    cell = get_peer_cell(conn, industry, sub_industry, band)

    if cell["cell_specificity"] == "insufficient" or cell["n"] < MIN_CELL_N:
        return {
            "status": "insufficient_data",
            "n_peers": cell["n"],
            "min_cell_n": MIN_CELL_N,
            "own_risk_score": own_risk_score,
            "own_critical_findings": own_critical,
            "revenue_band": band,
            "revenue_band_display": REVENUE_BAND_DISPLAY.get(band, band),
            "industry": industry,
            "sub_industry": sub_industry,
            "evidence": (
                f"Fewer than {MIN_CELL_N} peer benchmark scans available "
                f"for {industry or '?'} / {sub_industry or '?'} / "
                f"{REVENUE_BAND_DISPLAY.get(band, band)}. Peer rating "
                f"will become available once the benchmark pool grows."
            ),
        }

    rows = cell["rows"]
    scores = [int(r["risk_score"] or 500) for r in rows]
    inverse_scores = [1000 - s for s in scores]
    own_inverse = 1000 - own_risk_score

    percentile = _percentile_of(own_inverse, inverse_scores)
    rating = round(1.0 + 9.0 * (percentile / 100.0), 1)

    # Aggregate the comparison metrics
    sorted_scores = sorted(scores)
    crit_values = [int(r["critical_findings"] or 0) for r in rows]
    rsi_values = [float(r["rsi_score"] or 0.5) for r in rows]

    def _q(values, q):
        if not values:
            return None
        s = sorted(values)
        idx = max(0, min(len(s) - 1, int(round((q / 100.0) * (len(s) - 1)))))
        return s[idx]

    # SSL grade mode (most common grade)
    from collections import Counter
    ssl_grades = [str(r["ssl_grade"] or "").upper() for r in rows if r.get("ssl_grade")]
    ssl_mode = Counter(ssl_grades).most_common(1)[0][0] if ssl_grades else None

    # Pool composition for transparency
    sources = Counter(r["source"] or "unknown" for r in rows)

    return {
        "status": "ok",
        "peer_rating": rating,                       # 1.0 - 10.0, higher = better
        "percentile": round(percentile, 1),          # 0 - 100
        "interpretation": _interpret_rating(rating, percentile),
        "n_peers": len(rows),
        "cell_specificity": cell["cell_specificity"],
        "cell_industry": cell["cell_industry"],
        "cell_sub_industry": cell["cell_sub_industry"],
        "cell_revenue_band": cell["cell_revenue_band"],
        "revenue_band": band,
        "revenue_band_display": REVENUE_BAND_DISPLAY.get(band, band),
        "industry": industry,
        "sub_industry": sub_industry,
        "own_risk_score": own_risk_score,
        "own_critical_findings": own_critical,
        "peer_aggregates": {
            "risk_score":          {"p25": _q(scores, 25), "p50": _q(scores, 50), "p75": _q(scores, 75)},
            "critical_findings":   {"p25": _q(crit_values, 25), "p50": _q(crit_values, 50), "p75": _q(crit_values, 75)},
            "rsi_score":           {"p25": _q(rsi_values, 25), "p50": _q(rsi_values, 50), "p75": _q(rsi_values, 75)},
            "ssl_grade_mode":      ssl_mode,
        },
        "pool_composition": dict(sources),
        "pool_freshness_days": FRESHNESS_DAYS,
    }


def _interpret_rating(rating: float, percentile: float) -> str:
    """Human-readable interpretation of the peer rating. Drives the
    badge text on the hero strip."""
    if percentile >= 75:
        return "Top quartile for peer group"
    if percentile >= 50:
        return "Above peer median"
    if percentile >= 25:
        return "Below peer median"
    return "Bottom quartile for peer group"


# ---------------------------------------------------------------------------
# Benchmark write-through (records the just-completed scan into the pool
# if its source classification permits)
# ---------------------------------------------------------------------------

def record_to_benchmark_pool(scan_result: dict, conn: sqlite3.Connection,
                              source: str) -> Optional[str]:
    """Persist a scan into the benchmark_scans pool. Caller decides the
    source classification:
      - 'benchmark_pool' for our own bi-weekly reference scans
      - 'lower_tier_upsell' for the existing 4,000-client cohort
      - 'client_optin' when a broker has explicitly opted in

    Returns the inserted row id, or None if the scan is missing required
    fields for benchmarking.
    """
    import uuid
    industry = (scan_result.get("scan_context") or {}).get("industry")
    sub_industry = (scan_result.get("scan_context") or {}).get("sub_industry")
    annual_rev_zar = ((scan_result.get("scan_context") or {}).get("annual_revenue_zar")
                      or (scan_result.get("scan_context") or {}).get("annual_revenue") or 0)
    risk_score = scan_result.get("overall_risk_score")
    domain = scan_result.get("domain_scanned")
    if risk_score is None or not domain:
        return None
    crit = count_critical_findings(scan_result).get("total", 0)
    rsi = ((scan_result.get("insurance") or {}).get("rsi") or {}).get("rsi_score")
    ssl_grade = ((scan_result.get("categories") or {}).get("ssl") or {}).get("grade")
    band = revenue_band(annual_rev_zar)

    row_id = str(uuid.uuid4())
    try:
        conn.execute(
            """INSERT INTO benchmark_scans
               (id, domain, industry, sub_industry, annual_revenue_zar,
                revenue_band, risk_score, critical_findings, rsi_score,
                ssl_grade, scan_timestamp, source, is_active, scan_results_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
            (row_id, domain, industry, sub_industry, int(annual_rev_zar),
             band, int(risk_score), int(crit),
             float(rsi) if rsi is not None else None,
             ssl_grade, datetime.now(timezone.utc).isoformat(),
             source, json.dumps(scan_result, default=str)[:200000])
        )
        conn.commit()
        return row_id
    except Exception:
        return None
