"""Offline provider-transport failure-path regression checks.

These checks exercise ``ProviderClient`` through the real retry and circuit
breaker seams.  The only transport is an in-memory ``Session.request`` stub;
the paid-egress guard is installed around it before the first client call.
This module is intentionally standalone so the adversarial gate can wire it
once its current run is complete.
"""
from __future__ import annotations

import sys
from unittest import mock

import requests

from provider_client import ProviderClient
from resilience import CircuitBreaker, RetryPolicy
from usage_ledger import InMemoryUsageLedger


PAID_HOSTS = (
    "dehashed.com", "intelx.io", "api.shodan.io", "virustotal.com",
    "securitytrails.com", "hudsonrock.com", "haveibeenpwned.com",
    "snusbase.com", "leakcheck.io", "whiteintel.io",
)

# The adversarial gate supplies its already-installed guard when wired in.  A
# standalone invocation uses the equivalent local guard below.
_GATE_GUARD = None
_GATE_BLOCKED = None


def _response(status: int):
    response = requests.Response()
    response.status_code = status
    response.url = "https://synthetic.invalid/provider"
    response._content = b"{}"
    return response


def _run_scenario(outcomes, *, retry, breaker=None, ledger=None):
    calls = []
    blocked_egress = []
    queue = list(outcomes)

    # Patch the exact funnel used by requests.request before constructing or
    # invoking a client.  Any accidental paid-provider URL remains visible.
    def fake_session_request(_session, method, url, *args, **kwargs):
        calls.append((method, url, kwargs))
        outcome = queue.pop(0) if queue else _response(599)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    original = requests.sessions.Session.request

    def paid_guard(self, method, url, *args, **kwargs):
        lowered = str(url).lower()
        if any(host in lowered for host in PAID_HOSTS):
            blocked_egress.append(f"{method} {url}")
            raise AssertionError(f"paid-provider egress attempted: {method} {url}")
        return fake_session_request(self, method, url, *args, **kwargs)

    if _GATE_GUARD is None:
        requests.sessions.Session.request = paid_guard
    else:
        # Install the gate's guard around the synthetic transport.  This keeps
        # its shared blocked-egress ledger authoritative for the integrated run.
        requests.sessions.Session.request = fake_session_request
        _GATE_GUARD()
    try:
        client = ProviderClient(
            "synthetic-paid", rate=100000.0, burst=100,
            retry=retry, breaker=breaker, ledger=ledger,
            default_timeout=0.1,
        )
        result = client.get("https://synthetic.invalid/provider")
    finally:
        requests.sessions.Session.request = original
    assert not blocked_egress, blocked_egress
    return result, calls, client


def run_checks(*, install_paid_guard=None, blocked_egress=None) -> None:
    global _GATE_GUARD, _GATE_BLOCKED
    _GATE_GUARD = install_paid_guard
    _GATE_BLOCKED = blocked_egress
    # 429/503 are retriable and must be bounded by max_attempts; success on the
    # third attempt proves the real response classifier and retry loop ran.
    ledger = InMemoryUsageLedger(default_daily_cap=10, retry_cap_per_window=5)
    result, calls, _ = _run_scenario(
        [_response(429), _response(503), _response(200)],
        retry=RetryPolicy(max_attempts=3, base_delay=0, jitter=False,
                          sleep=lambda _: None), ledger=ledger,
    )
    assert result is not None and result.status_code == 200
    assert len(calls) == 3
    assert ledger.spend_today("synthetic-paid") == 3

    # A timeout is retriable, but a paid-provider ledger with no retry budget
    # must make exactly one attempt and return the provider's failure response.
    ledger = InMemoryUsageLedger(default_daily_cap=10, retry_cap_per_window=0)
    result, calls, _ = _run_scenario(
        [_response(429), _response(200)],
        retry=RetryPolicy(max_attempts=3, base_delay=0, jitter=False,
                          sleep=lambda _: None), ledger=ledger,
    )
    assert result is not None and result.status_code == 429
    assert len(calls) == 1
    assert ledger.spend_today("synthetic-paid") == 1

    ledger = InMemoryUsageLedger(default_daily_cap=10, retry_cap_per_window=5)
    result, calls, _ = _run_scenario(
        [requests.Timeout("synthetic timeout"), _response(200)],
        retry=RetryPolicy(max_attempts=2, base_delay=0, jitter=False,
                          sleep=lambda _: None), ledger=ledger,
    )
    assert result is not None and result.status_code == 200
    assert len(calls) == 2

    # Two final 503s trip the breaker.  The third request must be rejected
    # before Session.request, and therefore must not consume ledger spend.
    ledger = InMemoryUsageLedger(default_daily_cap=10, retry_cap_per_window=0)
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=10,
                             now=lambda: clock[0], name="synthetic")
    clock = [0.0]
    retry = RetryPolicy(max_attempts=1, base_delay=0, jitter=False,
                        sleep=lambda _: None)
    result, calls, client = _run_scenario(
        [_response(503)],
        retry=retry, breaker=breaker, ledger=ledger,
    )
    assert result is not None and result.status_code == 503
    assert len(calls) == 1
    result, calls, _ = _run_scenario(
        [_response(503)],
        retry=retry, breaker=breaker, ledger=ledger,
    )
    assert result is not None and result.status_code == 503
    assert len(calls) == 1
    result, calls, _ = _run_scenario(
        [_response(200)], retry=retry, breaker=breaker, ledger=ledger,
    )
    assert result is None and calls == []
    assert ledger.spend_today("synthetic-paid") == 2

    # Advance the injected clock: half-open recovery admits one call and a
    # successful response closes the breaker.
    clock[0] = 10.0
    result, calls, _ = _run_scenario(
        [_response(200)], retry=retry, breaker=breaker, ledger=ledger,
    )
    assert result is not None and result.status_code == 200
    assert len(calls) == 1 and client.breaker_state == "closed"
    assert not calls[0][2].get("verify", False)
    if _GATE_BLOCKED is not None:
        assert not _GATE_BLOCKED, _GATE_BLOCKED


if __name__ == "__main__":
    run_checks()
    print("PASS provider transport failures: retry bounds, timeout, circuit open/recovery, paid guard")
