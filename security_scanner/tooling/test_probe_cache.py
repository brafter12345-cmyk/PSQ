"""Unit tests for the WS6a HTTP ProbeCache. py tooling/test_probe_cache.py (offline)"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import requests
import requests.sessions as _S
import http_client as hc

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


def resp(status=200, body=b"hello"):
    r = requests.models.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.url = "https://x.io/p"
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"Server": "nginx"})
    return r


# --- TTL table ------------------------------------------------------------
check("2xx ttl 24h", hc._probe_ttl(200) == 86400)
check("404 ttl 7d", hc._probe_ttl(404) == 604800)
check("403 ttl 6h", hc._probe_ttl(403) == 21600)
check("429 ttl 30m", hc._probe_ttl(429) == 1800)
check("500 ttl 1h", hc._probe_ttl(500) == 3600)

# --- InMemoryProbeCache store/lookup/invalidate ---------------------------
c = hc.InMemoryProbeCache()
check("lookup miss -> None", c.lookup("https://x.io/p", "GET") is None)
c.store("https://x.io/p", "GET", resp(200, b"body-data"))
hit = c.lookup("https://x.io/p", "GET")
check("store+lookup returns full response (body intact)",
      hit is not None and hit.status_code == 200 and hit.content == b"body-data")
c.invalidate(url="https://x.io/p")
check("invalidate(url) removes", c.lookup("https://x.io/p", "GET") is None)


# --- HTTP._request cache-hit + force_refresh ------------------------------
calls = {"n": 0}
def fake(session_self, method, url, **kwargs):
    calls["n"] += 1
    return resp(200, b"net")

_orig = _S.Session.request
_orig_pc = hc.HTTP.probe_cache
try:
    _S.Session.request = fake
    hc.HTTP.probe_cache = hc.InMemoryProbeCache()
    r1 = hc.HTTP.get("https://x.io/p")
    r2 = hc.HTTP.get("https://x.io/p")
    check("2nd identical GET served from probe cache (1 outbound)",
          calls["n"] == 1 and r1.status_code == 200 and r2.status_code == 200)
    hc.HTTP.get("https://x.io/p", force_refresh=True)
    check("force_refresh bypasses cache (new outbound)", calls["n"] == 2)
finally:
    _S.Session.request = _orig
    hc.HTTP.probe_cache = _orig_pc

# default factory is the no-op unless Redis / opt-in (keeps gates unaffected)
check("default probe cache is no-op", type(hc.make_probe_cache()).__name__ == "_NullProbeCache")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
