"""One-command backend harness runner.

    py tests/run_harness.py            # full suite, SQLite, prints perf report
    py tests/run_harness.py -k concur  # pass extra args straight to pytest
    py tests/run_harness.py --perf     # only the performance/benchmark suite

Run against Postgres instead of the throwaway SQLite:

    TEST_DATABASE_URL=postgresql://phishield:phishield_local_dev@localhost:5544/phishield_scanner \
        py tests/run_harness.py

Include the real (network) scanner UAT:  RUN_LIVE_SCAN=1 py tests/run_harness.py -k live
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    import pytest

    args = sys.argv[1:]
    if "--perf" in args:
        args = [a for a in args if a != "--perf"] + ["test_performance.py"]

    pytest_args = ["-v", "--no-header", "-p", "no:cacheprovider", str(HERE), *args]
    print(f"[run_harness] pytest {' '.join(pytest_args)}\n")
    code = pytest.main(pytest_args)

    report = HERE / "reports" / "latest.md"
    if report.exists():
        print("\n" + "=" * 70)
        print(report.read_text(encoding="utf-8"))
        print("=" * 70)
        print(f"[run_harness] full report: {report}")
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
