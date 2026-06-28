"""Tests for WS7-tail + WS10 (completeness floor, usage mirror, DLQ, secrets, DR).
py tooling/test_ws10.py (offline; sqlite + local object store)
"""
from __future__ import annotations

import json
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import scanner_db as db
import object_store as os_mod
from object_store import LocalObjectStore
import secrets_provider as sp
import dr

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


tmp = Path(tempfile.mkdtemp())
db.configure(database_url="", sqlite_path=str(tmp / "ws10.db"))
db.init_schema()
os_mod.reset_for_tests(LocalObjectStore(str(tmp / "obj")))

# --- WS7 completeness floor ----------------------------------------------
from scoring_analytics import RiskScorer
s = RiskScorer()
full = {k: {"score": 50} for k in s.WEIGHTS}
s.calculate(full)
check("completeness: full coverage -> full", full["_scan_completeness"]["confidence_level"] == "full")
deg = dict(full)
for k in ("ssl", "exposed_admin", "shodan_vulns", "high_risk_protocols", "dnsbl"):
    deg[k] = {"status": "error"}
s.calculate(deg)
sc = deg["_scan_completeness"]
check("completeness: heavy loss -> low_confidence + qualified",
      sc["confidence_level"] == "low_confidence" and sc["score_qualified"]
      and sc["disclaimer"])

# --- WS10 durable usage mirror -------------------------------------------
db.record_usage("hibp", 1, day="2026-06-28")
db.record_usage("hibp", 2, day="2026-06-28")
check("usage mirror accumulates", db.usage_for("hibp", "2026-06-28") == 3)

# --- WS7 DLQ -------------------------------------------------------------
jid = str(uuid.uuid4())
db.enqueue_job(jid, "scanX", {"scan_id": "scanX"})
db.claim_job("w1")
db._run("UPDATE scan_jobs SET attempts=3, last_heartbeat=? WHERE id=?",
        ("2000-01-01T00:00:00+00:00", jid))
db.requeue_stale_jobs(visibility_timeout_s=60, max_attempts=3)
dead = db.list_dead_jobs()
check("poison job routed to DLQ ('dead')", any(d["id"] == jid for d in dead))

# --- WS10 secrets provider -----------------------------------------------
import os
os.environ["TEST_SECRET_X"] = "shh"
check("get_secret reads env by default", sp.get_secret("TEST_SECRET_X") == "shh")
check("get_secret default for missing", sp.get_secret("NOPE", "fallback") == "fallback")
class FakeSecrets:
    def get(self, n): return "vaulted" if n == "K" else None
sp.reset_for_tests(FakeSecrets())
check("get_secret uses configured provider", sp.get_secret("K") == "vaulted")
sp.reset_for_tests(None)

# --- WS10 DR reconciliation ----------------------------------------------
store = os_mod.make_object_store()
db.save_scan("s1", "x.io"); db.update_scan("s1", {"overall_risk_score": 1, "risk_level": "Low"})
db.save_scan("s2", "y.io"); db.update_scan("s2", {"overall_risk_score": 2, "risk_level": "Low"})
store.put("pdfs/s1/full.pdf", b"%PDF")        # s1 has a pdf
store.put("pdfs/ghost/full.pdf", b"%PDF")     # ghost: no such scan -> orphan
# s2 completed but no pdf -> missing
rep = dr.reconcile_object_store(dry_run=True)
check("DR sweep finds orphaned blob (ghost)",
      any("ghost" in k for k in rep["orphaned_blobs"]))
check("DR sweep finds missing-pdf completed scan (s2)", "s2" in rep["missing_pdf_scans"])

import shutil
shutil.rmtree(tmp, ignore_errors=True)
os_mod.reset_for_tests(None)
print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
