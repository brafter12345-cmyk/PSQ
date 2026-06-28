"""Paid-API result cache + single-flight (WS6b / SCALE-08a) — the primary cost lever.

Caches paid-provider responses keyed by ``(provider, canonical params)`` with
per-data-type TTLs (breach corpus -> days; infostealer feeds -> hours), so the same
domain scanned twice (continuous monitoring) pays once. Includes:
  * **single-flight** — concurrent identical calls coalesce onto ONE provider call
    via a Redis lease (fencing token, TTL >= worst-case call, holder-side renewal
    implied by the long lease); waiters poll the result key with a bounded timeout
    and fall through to fetch themselves only if the holder crashed.
  * **negative caching** — "no result" is cached too (shorter TTL), so a clean
    domain is also coalesced and not re-paid on every rescan.
  * **force_refresh** — bypasses the cache *read* but still takes the lease and
    writes, so a refresh burst can't stampede the provider.

Backends: ``InMemoryResultCache`` (single-process default) and ``RedisResultCache``
(shared). Both expose ``fetch(provider, method, url, kwargs, compute, force_refresh)``
returning a ``requests.Response`` (reconstructed from the cached snapshot) or
whatever ``compute`` returns on a miss. ProviderClient calls ``fetch`` when a cache
is configured.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from datetime import timedelta
from typing import Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from requests.models import Response

_SECRET = frozenset({"key", "apikey", "api_key", "token", "auth", "access_token",
                     "x-key", "secret", "password", "pass"})

# Per-provider freshness. Breach corpora change slowly (days); infostealer / dark-web
# feeds are fresher (hours); vuln catalogs daily. Tune against real cadence.
DATA_TYPE_TTLS = {
    "hibp": 86400, "dehashed": 43200, "snusbase": 21600, "leakcheck": 21600,
    "whiteintel": 21600, "intelx": 21600, "shodan": 43200, "securitytrails": 86400,
    "virustotal": 21600, "crtsh": 86400, "osv": 86400, "nvd": 86400, "kev": 86400,
    "msf": 86400, "exploitdb": 86400, "epss": 43200, "tranco": 86400,
    "internetdb": 43200, "hudsonrock": 21600,
}
DEFAULT_TTL = 21600
NEGATIVE_TTL = 3600          # "no result" cached shorter
LEASE_MS = 60000            # >= worst-case provider call (Shodan 20s, DeHashed 30s)
WAITER_TIMEOUT_S = 35.0


def _canon_key(provider: str, method: str, url: str, kwargs: dict) -> str:
    parsed = urlsplit(url or "")
    q = parse_qsl(parsed.query, keep_blank_values=True)
    params = (kwargs or {}).get("params")
    if isinstance(params, dict):
        q += list(params.items())
    elif isinstance(params, (list, tuple)):
        q += [tuple(p) for p in params]
    norm = sorted((str(k), "<r>" if str(k).lower() in _SECRET else str(v)) for k, v in q)
    host = (parsed.hostname or "").lower()
    base = urlunsplit((parsed.scheme.lower(), host, parsed.path, urlencode(norm), ""))
    body = (kwargs or {}).get("json")
    sig = ""
    if body is not None:
        sig = hashlib.sha256(json.dumps(body, sort_keys=True, default=str)
                             .encode()).hexdigest()[:16]
    return f"{provider}|{(method or 'GET').upper()}|{base}|{sig}"


def _dump(resp) -> str:
    if resp is None:
        return json.dumps({"none": True})
    try:
        content = resp.content or b""
    except Exception:
        content = b""
    return json.dumps({
        "status_code": int(getattr(resp, "status_code", 0) or 0),
        "headers": dict(getattr(resp, "headers", {}) or {}),
        "url": getattr(resp, "url", None),
        "encoding": getattr(resp, "encoding", None),
        "b64": base64.b64encode(content).decode("ascii"),
    })


def _load(blob: str):
    d = json.loads(blob)
    if d.get("none"):
        return None
    from requests.structures import CaseInsensitiveDict
    r = Response()
    r.status_code = d.get("status_code", 0)
    r._content = base64.b64decode(d.get("b64", "") or "")
    r._content_consumed = True
    r.url = d.get("url")
    r.encoding = d.get("encoding")
    r.headers = CaseInsensitiveDict(d.get("headers") or {})
    r.elapsed = timedelta(0)
    return r


def _ttl_for(provider: str, cacheable: bool) -> int:
    return DATA_TYPE_TTLS.get(provider, DEFAULT_TTL) if cacheable else NEGATIVE_TTL


def _cacheable(resp) -> bool:
    """Only cache successful, non-retriable responses (and 404s as negatives)."""
    if resp is None:
        return True  # negative cache
    sc = getattr(resp, "status_code", 0)
    return sc == 200 or sc == 404


class ResultCache:
    def fetch(self, provider, method, url, kwargs, compute, force_refresh=False):
        raise NotImplementedError


class InMemoryResultCache(ResultCache):
    def __init__(self, now: Callable[[], float] = time.time):
        self._d: dict = {}
        self._now = now
        self._locks: dict = {}
        self._guard = threading.Lock()

    def _lock_for(self, key):
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    def fetch(self, provider, method, url, kwargs, compute, force_refresh=False):
        key = _canon_key(provider, method, url, kwargs)
        if not force_refresh:
            ent = self._d.get(key)
            if ent and ent[0] > self._now():
                return _load(ent[1])
        with self._lock_for(key):  # single-flight (in-process)
            if not force_refresh:
                ent = self._d.get(key)
                if ent and ent[0] > self._now():
                    return _load(ent[1])
            resp = compute()
            if _cacheable(resp):
                self._d[key] = (self._now() + _ttl_for(provider, resp is not None),
                                _dump(resp))
            return resp


class RedisResultCache(ResultCache):
    def __init__(self, redis, now: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 token: Callable[[], str] = lambda: hashlib.sha1(
                     str(time.time_ns()).encode()).hexdigest()):
        self.r = redis
        self._now = now
        self._sleep = sleep
        self._token = token

    def fetch(self, provider, method, url, kwargs, compute, force_refresh=False):
        key = f"rc:{_canon_key(provider, method, url, kwargs)}"
        lock = f"{key}:lock"
        if not force_refresh:
            blob = self.r.get(key)
            if blob is not None:
                return _load(blob)
        deadline = self._now() + WAITER_TIMEOUT_S
        while True:
            tok = self._token()
            if self.r.set(lock, tok, nx=True, px=LEASE_MS):
                try:                                   # we are the holder
                    resp = compute()
                    if _cacheable(resp):
                        self.r.set(key, _dump(resp),
                                   ex=_ttl_for(provider, resp is not None))
                        self.r.publish(f"{key}:ready", "1")
                    return resp
                finally:
                    if self.r.get(lock) == tok:        # fencing: only release our lease
                        self.r.delete(lock)
            # not the holder: wait for the result, bounded
            blob = self.r.get(key)
            if blob is not None:
                return _load(blob)
            if self._now() >= deadline:
                return compute()                       # holder crashed -> fetch self
            self._sleep(0.05)


def make_result_cache():
    """Redis cache (with single-flight) when REDIS_URL is set. Single-box default is
    **no cache** — so behaviour (and the regression gates) are unchanged until the
    distributed store exists; opt into the in-process cache with RESULT_CACHE_INPROC=1
    (e.g. continuous-monitoring on one box). RESULT_CACHE=0 disables entirely."""
    import os
    if os.environ.get("RESULT_CACHE", "1") == "0":
        return None
    from redis_support import get_redis
    r = get_redis()
    if r is not None:
        return RedisResultCache(r)
    if os.environ.get("RESULT_CACHE_INPROC") == "1":
        return InMemoryResultCache()
    return None
