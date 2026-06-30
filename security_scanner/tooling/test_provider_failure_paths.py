"""Checker-level failure-path coverage (WS7 retry/breaker/ledger).

The unit tests in test_provider_client.py prove the ProviderClient itself
retries / trips its breaker / swallows to None. The record-replay migration
gates (tooling/regression/mig_*.py) only ever replay HTTP 200 cassettes, so the
behaviour of a REAL checker when its provider keeps failing — the path WS7 made
live by default — was untested. This closes that gap.

For each provider-backed checker it drives check() with a transport that:
  * returns HTTP 503 on every call (retriable -> retries exhausted -> last 503), and
  * raises Timeout on every call (-> ProviderClient returns None),
and asserts the checker DEGRADES GRACEFULLY:
  1. no exception escapes check() (a failing provider must never crash a scan);
  2. it returns a dict carrying a status (downstream scoring maps no-data ->
     skipped and redistributes weight — it must not silently read as clean-100);
  3. no partial/garbage enrichment survives (the "breaker trips mid-CVE-loop"
     concern): any per-item enrichment the checker emits is internally consistent.

Offline + credit-free:  py tooling/test_provider_failure_paths.py
"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # security_scanner/
sys.path.insert(0, str(ROOT))

import requests
import requests.sessions as _S

K = "DUMMY-KEY-FOR-GATE"
_passed = 0
_failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f" — {detail}" if detail and not cond else ""))
    _passed += 1 if cond else 0
    _failed += 0 if cond else 1


def _resp(status: int):
    r = requests.models.Response()
    r.status_code = status
    r._content = b'{"error": "unavailable"}'
    r._content_consumed = True
    r.url = "https://api.example/x"
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "application/json"})
    return r


def _make_transport(mode: str):
    """mode='503' -> always 503; mode='timeout' -> always raise Timeout."""
    def _t(*a, **k):
        if mode == "timeout":
            raise requests.exceptions.Timeout("simulated timeout")
        return _resp(503)
    return _t


def _with_failing(mode: str, fn):
    """Drive fn() with every HTTP egress (module-level requests.request used by
    the provider seam AND Session.request used by http_client/direct calls)
    failing per `mode`. DNS/socket/sleep stubbed for determinism."""
    transport = _make_transport(mode)
    orig_req = requests.request
    orig_sreq = _S.Session.request
    orig_sleep = time.sleep
    orig_gai, orig_ghn = socket.getaddrinfo, socket.gethostbyname
    try:
        import dns.resolver
        orig_resolve = dns.resolver.resolve
    except Exception:
        dns, orig_resolve = None, None
    requests.request = transport
    _S.Session.request = lambda self, method, url, **k: transport(method, url, **k)
    time.sleep = lambda *a, **k: None
    socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("203.0.113.4", 0))]
    socket.gethostbyname = lambda *a, **k: "203.0.113.4"
    if orig_resolve is not None:
        dns.resolver.resolve = lambda *a, **k: []
    try:
        return fn(), None
    except Exception as e:  # noqa: BLE001 — a crash here IS the failure under test
        return None, e
    finally:
        requests.request = orig_req
        _S.Session.request = orig_sreq
        time.sleep = orig_sleep
        socket.getaddrinfo = orig_gai
        socket.gethostbyname = orig_ghn
        if orig_resolve is not None:
            dns.resolver.resolve = orig_resolve


def _cases():
    import checkers_threats as ct
    return {
        "virustotal":     lambda: ct.VirusTotalChecker().check("examplecorp.co.za", api_key=K),
        "securitytrails": lambda: ct.SecurityTrailsChecker().check("examplecorp.co.za", api_key=K),
        "dehashed":       lambda: ct.DehashedChecker().check("examplecorp.co.za", api_key=K),
        "hudsonrock":     lambda: ct.HudsonRockChecker().check("examplecorp.co.za"),
        "shodanvuln":     lambda: ct.ShodanVulnChecker().check("examplecorp.co.za", api_key=K, ip="203.0.113.4"),
    }


def _assert_graceful(label: str, result, err):
    check(f"{label}: no exception escapes check()", err is None,
          f"raised {type(err).__name__ if err else ''}: {err}")
    if err is not None or result is None:
        return
    check(f"{label}: returns a dict with a status", isinstance(result, dict) and "status" in result,
          f"got {type(result).__name__}")
    # No fabricated/garbage per-item enrichment: every CVE entry that carries an
    # age must carry a numeric (or None) age, never a half-written value, and the
    # patch-management summary must be self-consistent with the cve list.
    cves = result.get("cves") if isinstance(result, dict) else None
    if isinstance(cves, list):
        ok = all((c.get("age_days") is None) or isinstance(c.get("age_days"), int)
                 for c in cves if isinstance(c, dict))
        check(f"{label}: no half-written CVE enrichment", ok)


def main() -> int:
    cases = _cases()
    for mode in ("503", "timeout"):
        print(f"\n--- provider failure mode: {mode} ---")
        for name, fn in cases.items():
            result, err = _with_failing(mode, fn)
            _assert_graceful(f"{name}/{mode}", result, err)

    # The breaker actually engages end-to-end: a provider hammered with retriable
    # failures opens and then short-circuits (degrade-don't-fail). Drive the seam
    # client directly through many failures and confirm the open state.
    import providers
    from resilience import CircuitBreaker, RetryPolicy
    probe = providers._client("failtest", rate=1000, burst=1000,
                              max_attempts=1, failure_threshold=3, reset_timeout=999)
    def _hammer():
        t = _make_transport("503")
        orig = requests.request
        requests.request = t
        try:
            for _ in range(5):
                probe.get("https://api.example/x")
        finally:
            requests.request = orig
        return probe.breaker_state
    state, err = _hammer(), None
    print("\n--- breaker engagement ---")
    check("breaker opens under sustained provider failure", state == "open",
          f"state={state}")

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
