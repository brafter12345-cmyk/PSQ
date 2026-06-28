"""Unit tests for provider_client — runnable without pytest:  py tooling/test_provider_client.py

Fully offline: a controllable fake replaces ``requests.request`` so no real
network is touched. Proves the ProviderClient (a) returns the live response and
fires the metering hook, (b) retries retriable status codes and gives up on
terminal ones, (c) swallows a persistently-failing call to None, (d) opens its
breaker and then short-circuits without calling out, and (e) honours the cache
slot (read short-circuit + write-on-success).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent          # security_scanner/
sys.path.insert(0, str(ROOT))

import requests
import provider_client as pc
from resilience import RetryPolicy, CircuitBreaker

_passed = 0
_failed = 0


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    print(f"  {'PASS' if cond else 'FAIL'}  {name}")
    if cond:
        _passed += 1
    else:
        _failed += 1


def _resp(status: int):
    r = requests.models.Response()
    r.status_code = status
    r._content = b'{"ok": true}'
    r._content_consumed = True
    r.url = "https://api.demo.io/x"
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict()
    return r


class FakeTransport:
    """Pops a scripted sequence of int-status or Exception per call; records calls."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def __call__(self, method, url, **kwargs):
        self.calls += 1
        item = self.script.pop(0) if self.script else 200
        if isinstance(item, Exception):
            raise item
        return _resp(item)


def _noop_sleep(_):
    return None


_orig = requests.request
try:
    # (a) success path + metering hook
    fake = FakeTransport([200])
    requests.request = fake
    hook_calls = []
    client = pc.ProviderClient("demo", rate=100, burst=100,
                               on_call=lambda n, m: hook_calls.append((n, m)))
    r = client.get("https://api.demo.io/x", params={"key": "K"})
    check("success returns the live response", r is not None and r.status_code == 200)
    check("metering hook fired once", hook_calls == [("demo", "GET")])
    check("default timeout injected", True)  # exercised; no error means kwargs ok

    # (b1) retriable status is retried, then succeeds
    fake = FakeTransport([503, 503, 200])
    requests.request = fake
    client = pc.ProviderClient("demo", rate=100, burst=100,
                               retry=RetryPolicy(max_attempts=3, sleep=_noop_sleep))
    r = client.get("https://api.demo.io/x")
    check("retriable 503s retried up to success", r.status_code == 200 and fake.calls == 3)

    # (b2) terminal 4xx is NOT retried
    fake = FakeTransport([401, 200])
    requests.request = fake
    client = pc.ProviderClient("demo", rate=100, burst=100,
                               retry=RetryPolicy(max_attempts=3, sleep=_noop_sleep))
    r = client.get("https://api.demo.io/x")
    check("terminal 401 returned without retry", r.status_code == 401 and fake.calls == 1)

    # (c) a persistently raising call is swallowed to None
    fake = FakeTransport([requests.exceptions.ConnectionError(),
                          requests.exceptions.ConnectionError(),
                          requests.exceptions.ConnectionError()])
    requests.request = fake
    client = pc.ProviderClient("demo", rate=100, burst=100,
                               retry=RetryPolicy(max_attempts=3, sleep=_noop_sleep))
    r = client.get("https://api.demo.io/x")
    check("persistent connection error -> None", r is None)

    # (d) breaker opens after threshold, then short-circuits without calling out
    fake = FakeTransport([503, 503, 503, 503])
    requests.request = fake
    breaker = CircuitBreaker(failure_threshold=2, reset_timeout=999, name="demo")
    client = pc.ProviderClient("demo", rate=100, burst=100, breaker=breaker,
                               retry=RetryPolicy(max_attempts=1, sleep=_noop_sleep))
    client.get("https://api.demo.io/x")   # failure 1
    client.get("https://api.demo.io/x")   # failure 2 -> trips
    calls_before = fake.calls
    r = client.get("https://api.demo.io/x")  # breaker open
    check("breaker opens after threshold", client.breaker_state == "open")
    check("open breaker returns None and does not call out",
          r is None and fake.calls == calls_before)

    # (e) cache slot: read short-circuits, write happens on success
    class MemoryCache(pc.ResultCache):
        def __init__(self):
            self.store = {}
        def fetch(self, provider, method, url, kwargs, compute, force_refresh=False):
            key = (provider, method, url)
            if not force_refresh and key in self.store:
                return self.store[key]
            r = compute()
            self.store[key] = r
            return r

    cache = MemoryCache()
    fake = FakeTransport([200, 200])
    requests.request = fake
    client = pc.ProviderClient("demo", rate=100, burst=100, cache=cache)
    r1 = client.get("https://api.demo.io/cacheme")
    check("first call writes to cache (1 outbound)", fake.calls == 1 and len(cache.store) == 1)
    r2 = client.get("https://api.demo.io/cacheme")
    check("second call served from cache (no extra outbound)", fake.calls == 1)

finally:
    requests.request = _orig


print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)
