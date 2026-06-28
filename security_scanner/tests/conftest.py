"""Backend test-harness fixtures.

This harness exercises the *backend* (scanner data layer, durable job queue + worker
tier, checkpoints/resumability, rate-limiter, cache, circuit-breaker, scoring) — there
is no Flask/UI involvement.

Backend selection
-----------------
By default everything runs against a throwaway **SQLite** file in a temp dir — always
available, hermetic, and safe to wipe between tests. To run the *same* suite against a
real **Postgres** (exercising FOR UPDATE SKIP LOCKED for real), export::

    TEST_DATABASE_URL=postgresql://phishield:phishield_local_dev@localhost:5544/phishield_scanner

We deliberately use a dedicated ``TEST_DATABASE_URL`` (not the app's ``DATABASE_URL``) so
the suite never truncates a database you didn't explicitly point it at.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make the backend importable (security_scanner/ is the parent of tests/).
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scanner_db  # noqa: E402

from harness import Bench  # noqa: E402

TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "").strip()

# Tables the harness writes; wiped before each test for isolation.
_WIPE = ("scan_checkpoints", "scan_jobs", "usage", "scans")


@pytest.fixture(scope="session", autouse=True)
def backend(tmp_path_factory):
    """Configure scanner_db once for the whole session and report the backend."""
    if TEST_DB_URL:
        scanner_db.configure(database_url=TEST_DB_URL)
    else:
        dbfile = tmp_path_factory.mktemp("scanner_db") / "harness.db"
        # Empty string forces SQLite even if the app's DATABASE_URL is in the env.
        scanner_db.configure(database_url="", sqlite_path=str(dbfile))
    scanner_db.init_schema()
    name = "postgres" if scanner_db.is_postgres() else "sqlite"
    print(f"\n[harness] backend = {name}")
    return name


@pytest.fixture(autouse=True)
def _clean(backend):
    """Truncate harness tables before every test so suites never bleed into each other."""
    for t in _WIPE:
        try:
            scanner_db._run(f"DELETE FROM {t}")
        except Exception:
            pass  # table may not exist on a given backend; ignore
    yield


@pytest.fixture(scope="session")
def bench(backend):
    """Session-wide benchmark collector; writes reports/ on teardown."""
    b = Bench(backend=backend)
    yield b
    payload = b.save()
    if payload:
        print(f"\n[harness] perf report -> {payload['_paths']['md']}")
