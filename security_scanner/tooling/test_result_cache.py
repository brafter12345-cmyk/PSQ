"""Unit tests for result_cache (WS6b) + ProviderClient integration.
py tooling/test_result_cache.py   (offline; InMemory + FakeRedis)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import requests
import result_cache as rc
from redis_support import FakeRedis
import provider_client as pc

_p = _f = 0
def check(n, c):
    global _p, _f
    print(f"  {'PASS' if c else 'FAIL'}  {n}")
    _p += 1 if c else 0
    _f += 0 if c else 1


def resp(status=200, body=b'{"ok":1}'):
    r = requests.models.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.url = "https://api.x/y"
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"X-T": "1"})
    return r


def counting(seq):
    """compute() returning the next scripted response, counting calls."""
    box = {"n": 0, "seq": list(seq)}
    def compute():
        box["n"] += 1
        return box["seq"].pop(0) if box["seq"] else resp()
    return compute, box


# --- response round-trip --------------------------------------------------
blob = rc._dump(resp(200, b'{"v":42}'))
r2 = rc._load(blob)
check("dump/load round-trips status+body", r2.status_code == 200 and r2.json()["v"] == 42)
check("dump/load None (negative)", rc._load(rc._dump(None)) is None)


def suite(make_cache, label):
    print(f"--- {label} ---")
    # miss computes, hit serves
    c = make_cache()
    comp, box = counting([resp(200, b'{"hit":1}')])
    a = c.fetch("hibp", "GET", "https://api.x/y", {"params": {"d": "x"}}, comp)
    b = c.fetch("hibp", "GET", "https://api.x/y", {"params": {"d": "x"}}, comp)
    check(f"[{label}] miss computes once, hit serves cached",
          box["n"] == 1 and a.json()["hit"] == 1 and b.json()["hit"] == 1)

    # rotated secret param => same key (coalesced)
    comp2, box2 = counting([resp()])
    c.fetch("hibp", "GET", "https://api.x/y", {"params": {"d": "x", "key": "AAA"}}, comp2)
    c.fetch("hibp", "GET", "https://api.x/y", {"params": {"d": "x", "key": "BBB"}}, comp2)
    # note: different key value but same logical key -> but different from first key (has 'key' param)
    check(f"[{label}] rotated secret coalesces", box2["n"] == 1)

    # force_refresh bypasses read but still computes + caches
    comp3, box3 = counting([resp(200, b'{"n":1}'), resp(200, b'{"n":2}')])
    c.fetch("nvd", "GET", "https://api.x/z", {}, comp3)
    fr = c.fetch("nvd", "GET", "https://api.x/z", {}, comp3, force_refresh=True)
    check(f"[{label}] force_refresh recomputes", box3["n"] == 2 and fr.json()["n"] == 2)
    after = c.fetch("nvd", "GET", "https://api.x/z", {}, comp3)
    check(f"[{label}] force_refresh wrote fresh value", box3["n"] == 2 and after.json()["n"] == 2)

    # negative caching: compute returns None -> cached, not recomputed
    comp4, box4 = counting([None])
    c.fetch("dehashed", "POST", "https://api.x/q", {"json": {"q": "d"}}, comp4)
    c.fetch("dehashed", "POST", "https://api.x/q", {"json": {"q": "d"}}, comp4)
    check(f"[{label}] negative result cached (coalesced)", box4["n"] == 1)


suite(lambda: rc.InMemoryResultCache(), "in-memory")
suite(lambda: rc.RedisResultCache(FakeRedis()), "redis(fake)")


# --- TTL expiry (in-memory, injected clock) -------------------------------
clk = [1000.0]
c = rc.InMemoryResultCache(now=lambda: clk[0])
comp, box = counting([resp(200, b'{"a":1}'), resp(200, b'{"a":2}')])
c.fetch("epss", "GET", "https://api.x/e", {}, comp)            # ttl ~ 43200
clk[0] += 100000                                                # past TTL
c.fetch("epss", "GET", "https://api.x/e", {}, comp)
check("TTL expiry forces recompute", box["n"] == 2)


# --- ProviderClient integration (cache coalesces real calls) --------------
_orig = requests.request
try:
    calls = {"n": 0}
    def fake(method, url, **kwargs):
        calls["n"] += 1
        return resp(200, b'{"p":1}')
    requests.request = fake
    client = pc.ProviderClient("hibp", rate=100, burst=100,
                               cache=rc.InMemoryResultCache())
    r1 = client.get("https://api.x/y", params={"domain": "d"})
    r2 = client.get("https://api.x/y", params={"domain": "d"})
    check("ProviderClient cache: 2 identical calls -> 1 outbound",
          calls["n"] == 1 and r1.json()["p"] == 1 and r2.json()["p"] == 1)
    r3 = client.get("https://api.x/y", params={"domain": "d"}, force_refresh=True)
    check("ProviderClient force_refresh -> new outbound", calls["n"] == 2)
finally:
    requests.request = _orig

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
