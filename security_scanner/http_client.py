"""HTTP client with per-apex rate limiting, WAF detection, and probe-cache slot.

Single chokepoint for all outbound HTTP traffic from the scanner. Centralises:

1. **Polite request pacing** — token-bucket rate limit per apex domain so
   the scanner never bursts more than N requests/sec at any one target,
   irrespective of how many checkers run concurrently. This was the root
   cause of the WAF-triggering behaviour identified on the 2026-05-15
   phishield.com test scan after parallelising the privacy-policy probes.

2. **WAF / bot-manager intervention detection** — sliding-window analysis
   of response codes per apex. When the rate of 4xx/5xx/timeouts crosses
   threshold, or a known challenge-page pattern is detected in the body,
   the apex is flagged as "WAF protected" and downstream consumers (PDF /
   HTML report renderers) can show explicit "partial coverage" disclaimers
   rather than producing misleading "no findings" results.

3. **Identifying User-Agent** — every request announces the scanner with
   a link to /scanner-info so security teams investigating suspicious
   traffic can verify legitimacy out-of-band. Same pattern used by
   Bitsight, SecurityScorecard, Coalition, CFC, Black Kite, RiskRecon.

4. **Probe-cache slot** — the ProbeCache protocol is defined and wired
   into the request path; default implementation is a no-op. SQLite or
   Redis-backed cache implementation is deferred to the continuous-
   monitoring track (gap analysis SCN-026). When continuous scanning
   lands, swap the cache instance at module level — no checker touches
   are needed.

Usage:
    from http_client import HTTP

    # Rate-limited GET (apex-keyed; scan target gets its own bucket,
    # api.shodan.io etc. each get their own bucket too)
    r = HTTP.get(url, timeout=10)

    # HEAD-first probe with GET fallback on 405 - used for path discovery
    r = HTTP.discover(candidate_url, timeout=8)

    # WAF status for an apex (used by report renderers)
    waf = HTTP.waf_status("phishield.com")
"""

import re
import json as _json
import time
import threading
from collections import defaultdict, deque, Counter
from typing import Optional

try:
    import requests
except ImportError:
    requests = None


# ---------------------------------------------------------------------------
# Apex extraction
# ---------------------------------------------------------------------------

# eTLDs with two labels (country-code SLDs). The scanner's primary market
# is SA so .za is the priority; common Commonwealth variants included.
_TWO_LABEL_ETLDS = {"za", "uk", "au", "nz", "jp"}
_TWO_LABEL_SECOND = {"co", "org", "ac", "gov", "net", "edu", "mil", "ne"}


def _apex_of(url: str) -> str:
    """Extract a sensible rate-limit / WAF-tracking key from a URL.

    Returns the registrable apex domain (e.g. example.com, example.co.za).
    IP addresses are returned as-is so each external IP gets its own bucket.
    Returns empty string on parse failure rather than raising.
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return ""
    if not host:
        return ""
    # IPv4 or IPv6 - use as-is
    if all(c.isdigit() or c == "." for c in host) or ":" in host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Detect country-code SLDs like .co.za, .org.za, .ac.za, .gov.za,
    # .co.uk, etc. Keep the last 3 labels in that case.
    if (len(parts) >= 3
            and parts[-1] in _TWO_LABEL_ETLDS
            and parts[-2] in _TWO_LABEL_SECOND):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# DomainRateLimiter - token bucket per apex
# ---------------------------------------------------------------------------

class DomainRateLimiter:
    """Per-apex token-bucket rate limiter.

    Steady-state rate of `rate` requests/sec with burst capacity `burst`.
    Threads share a single instance; the per-bucket lock is short (just
    the bookkeeping math). The `time.sleep` for over-budget waits happens
    OUTSIDE the lock, so other threads against other apexes can keep
    acquiring while one thread is paced.

    Default 2 req/sec, burst 5 - matches industry-passive-scanner pacing
    (Bitsight / SecurityScorecard / Coalition operate in 1-3 req/sec range).
    """

    def __init__(self, rate: float = 2.0, burst: int = 5):
        self.rate = float(rate)
        self.burst = int(burst)
        self._buckets = {}  # apex -> [tokens, last_refill_monotonic]
        self._lock = threading.Lock()

    def acquire(self, apex: str) -> float:
        """Block until a token is available for `apex`. Returns the wait
        time actually slept (0 if immediate). Apex extraction is the
        caller's responsibility."""
        if not apex:
            return 0.0
        with self._lock:
            bucket = self._buckets.get(apex)
            if bucket is None:
                bucket = [float(self.burst), time.monotonic()]
                self._buckets[apex] = bucket
            now = time.monotonic()
            elapsed = max(0.0, now - bucket[1])
            bucket[0] = min(float(self.burst), bucket[0] + elapsed * self.rate)
            bucket[1] = now
            if bucket[0] >= 1.0:
                bucket[0] -= 1.0
                return 0.0
            # Insufficient tokens — schedule the wait and release lock
            deficit = 1.0 - bucket[0]
            wait = deficit / self.rate
            bucket[0] = 0.0
            bucket[1] = now + wait
        # Sleep outside the lock
        time.sleep(wait)
        return wait

    def stats(self, apex: str) -> dict:
        with self._lock:
            bucket = self._buckets.get(apex)
            if not bucket:
                return {"apex": apex, "tokens": self.burst, "active": False}
            return {"apex": apex, "tokens": round(bucket[0], 2), "active": True}


# ---------------------------------------------------------------------------
# WAFTracker - sliding-window response monitor
# ---------------------------------------------------------------------------

class WAFTracker:
    """Per-apex sliding window of recent response signals. Flags a domain
    as WAF-protected when any of the detection rules cross threshold.

    Detection rules (in priority order):
      1. **waf_challenge** - any explicit challenge page (Cloudflare,
         Akamai, Imperva, DataDome, etc.) detected in response body
      2. **waf_blocked** - >= 40% of recent responses are 403 / 406 / 451
      3. **waf_rate_limited** - >= 25% of recent responses are 429 / 503
      4. **waf_timeout** - >= 50% of recent probes timed out / failed

    Window defaults to 20 most recent observations per apex.
    """

    def __init__(self, window: int = 20):
        self.window = int(window)
        self._history = defaultdict(lambda: deque(maxlen=self.window))
        self._lock = threading.Lock()

    def record(self, apex: str, status_code: int) -> None:
        if not apex:
            return
        with self._lock:
            self._history[apex].append(("status", int(status_code)))

    def record_timeout(self, apex: str) -> None:
        if not apex:
            return
        with self._lock:
            self._history[apex].append(("timeout", None))

    def record_challenge(self, apex: str, vendor: str) -> None:
        """Record a positive WAF challenge-page detection.

        vendor is one of: cloudflare / akamai / imperva / datadome /
        captcha / unknown."""
        if not apex:
            return
        with self._lock:
            self._history[apex].append(("challenge", str(vendor)))

    def status(self, apex: str) -> dict:
        """Return a status dict for the apex.

        Shape:
          {
            "blocked": bool,
            "kind": "none" | "waf_challenge" | "waf_blocked" |
                    "waf_rate_limited" | "waf_timeout",
            "evidence": str,
            "codes": {200: 5, 403: 8, ...},
            "samples": N,
          }
        """
        with self._lock:
            hist = list(self._history.get(apex, []))
        result = {
            "blocked": False, "kind": "none", "evidence": "",
            "codes": {}, "samples": len(hist),
        }
        if not hist:
            return result
        codes = Counter(h[1] for h in hist if h[0] == "status")
        timeouts = sum(1 for h in hist if h[0] == "timeout")
        challenges = [h[1] for h in hist if h[0] == "challenge"]
        n = len(hist)
        result["codes"] = dict(codes)
        if challenges:
            result.update(blocked=True, kind="waf_challenge",
                          evidence=f"Challenge page detected ({challenges[0]})")
            return result
        blocked_count = sum(codes.get(c, 0) for c in (403, 406, 451))
        rate_limited = sum(codes.get(c, 0) for c in (429, 503))
        if blocked_count / n >= 0.40:
            result.update(blocked=True, kind="waf_blocked",
                          evidence=f"{blocked_count} of {n} probes returned 403/406/451")
            return result
        if rate_limited / n >= 0.25:
            result.update(blocked=True, kind="waf_rate_limited",
                          evidence=f"{rate_limited} of {n} probes rate-limited (429/503)")
            return result
        if timeouts / n >= 0.50:
            result.update(blocked=True, kind="waf_timeout",
                          evidence=f"{timeouts} of {n} probes timed out / failed")
            return result
        return result

    def reset(self, apex: Optional[str] = None) -> None:
        with self._lock:
            if apex:
                self._history.pop(apex, None)
            else:
                self._history.clear()


# ---------------------------------------------------------------------------
# ProbeCache - interface only; SCN-026 deferred to continuous monitoring
# ---------------------------------------------------------------------------

class ProbeCache:
    """Probe-result cache interface.

    Implementations decide what 'fresh' means and where to persist.
    Default is _NullProbeCache - every lookup misses. Real backing
    store (SQLite per-domain table or Redis) is deferred to the
    continuous-monitoring track per gap analysis SCN-026.

    Cache refresh rules per status (to be honoured by implementation):
      - 2xx        : TTL 24h; re-verify HEAD on rescan (cheap)
      - 404        : TTL 7d; spot-check 10% of cached 404s per scan
      - 5xx        : TTL 1h; re-probe immediately
      - 403/451/406: TTL 6h; back off (likely WAF intervention)
      - 429/503    : TTL 30m; honour Retry-After if present
      - timeout    : TTL 1h; re-probe with caution

    Invalidation triggers:
      - TTL expiry
      - Explicit invalidation via /api/scan?force_refresh=true
      - Target's primary IP or ASN changes (infrastructure migration)
    """

    def lookup(self, url: str, method: str = "GET"):
        raise NotImplementedError

    def store(self, url: str, method: str, response) -> None:
        raise NotImplementedError

    def invalidate(self, url: Optional[str] = None,
                   apex: Optional[str] = None) -> None:
        raise NotImplementedError


class _NullProbeCache(ProbeCache):
    """No-op cache for one-off scans. Every lookup misses; every store
    is discarded. Drop in a real implementation for continuous monitoring."""

    def lookup(self, url, method="GET"):
        return None

    def store(self, url, method, response):
        pass

    def invalidate(self, url=None, apex=None):
        pass


# WS6a (SCN-026): TTL per status class, from the ProbeCache docstring.
def _probe_ttl(status_code: int) -> int:
    if 200 <= status_code < 300:
        return 86400          # 2xx: 24h
    if status_code == 404:
        return 604800         # 404: 7d
    if status_code in (403, 451, 406):
        return 21600          # WAF-ish: 6h
    if status_code in (429, 503):
        return 1800           # rate-limited: 30m
    if 500 <= status_code < 600:
        return 3600           # other 5xx: 1h
    return 3600


def _probe_dump(response) -> str:
    import base64 as _b64
    try:
        content = response.content or b""
    except Exception:
        content = b""
    return _json.dumps({
        "status_code": int(getattr(response, "status_code", 0) or 0),
        "headers": dict(getattr(response, "headers", {}) or {}),
        "url": getattr(response, "url", None),
        "encoding": getattr(response, "encoding", None),
        "b64": _b64.b64encode(content).decode("ascii"),
    })


def _probe_load(blob: str):
    import base64 as _b64
    d = _json.loads(blob)
    r = requests.models.Response()
    r.status_code = d.get("status_code", 0)
    r._content = _b64.b64decode(d.get("b64", "") or "")
    r._content_consumed = True
    r.url = d.get("url")
    r.encoding = d.get("encoding")
    r.headers = requests.structures.CaseInsensitiveDict(d.get("headers") or {})
    return r


class InMemoryProbeCache(ProbeCache):
    """Single-process probe cache (full response + status-based TTL)."""

    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def lookup(self, url, method="GET"):
        with self._lock:
            ent = self._d.get((method, url))
            if ent and ent[0] > time.time():
                return _probe_load(ent[1])
            return None

    def store(self, url, method, response):
        if response is None:
            return
        with self._lock:
            self._d[(method, url)] = (time.time() + _probe_ttl(response.status_code),
                                      _probe_dump(response))

    def invalidate(self, url=None, apex=None):
        with self._lock:
            if url is not None:
                for m in ("GET", "HEAD", "POST"):
                    self._d.pop((m, url), None)
            elif apex is not None:
                for k in [k for k in self._d if _apex_of(k[1]) == apex]:
                    self._d.pop(k, None)
            else:
                self._d.clear()


class RedisProbeCache(ProbeCache):
    """Shared probe cache in Redis (full response + status-based TTL)."""

    def __init__(self, redis):
        self.r = redis

    def _key(self, method, url):
        return f"pc:{method}:{url}"

    def lookup(self, url, method="GET"):
        blob = self.r.get(self._key(method, url))
        return _probe_load(blob) if blob is not None else None

    def store(self, url, method, response):
        if response is None:
            return
        self.r.set(self._key(method, url), _probe_dump(response),
                   ex=_probe_ttl(response.status_code))

    def invalidate(self, url=None, apex=None):
        if url is not None:
            self.r.delete(self._key("GET", url), self._key("HEAD", url),
                          self._key("POST", url))


def make_probe_cache():
    """Redis probe cache when REDIS_URL set; in-process when PROBE_CACHE_INPROC=1;
    else the no-op (single-box default unchanged — gates unaffected)."""
    import os
    if os.environ.get("PROBE_CACHE", "1") == "0":
        return _NullProbeCache()
    try:
        from redis_support import get_redis
        r = get_redis()
        if r is not None:
            return RedisProbeCache(r)
    except Exception:
        pass
    if os.environ.get("PROBE_CACHE_INPROC") == "1":
        return InMemoryProbeCache()
    return _NullProbeCache()


# ---------------------------------------------------------------------------
# HttpClient
# ---------------------------------------------------------------------------

class HttpClient:
    """Wraps requests with rate-limiting, WAF detection, and probe caching.

    All scanner HTTP traffic should route through a single shared instance
    (`HTTP` module singleton below). Direct `requests.get` calls bypass
    these controls — refactor them to `HTTP.get` / `HTTP.head` /
    `HTTP.discover` whenever found.
    """

    # Self-identification URL for security teams, served live on the VM. The
    # brand-canonical https://phishield.com/scanner-info does not serve the page
    # yet (it 301s to www then 404s), so point at the VM's own /scanner-info.
    # (Was the now-retired Render free-tier URL.) Switch to the brand URL once a
    # static copy / reverse-proxy is set up on the HTML site.
    USER_AGENT = "Phishield-Scanner/1.0 (+https://veilguard.phishield.com/scanner/scanner-info)"

    # Challenge HTML patterns. Conservative: only match strong signals so
    # legitimate sites that mention "captcha" in unrelated context don't
    # trip a false WAF flag.
    _CHALLENGE_PATTERNS = (
        (re.compile(
            r"cf-chl-bypass|cf-browser-verification|cf_chl_opt|"
            r"cloudflare.*ray.id|__cf_chl_", re.IGNORECASE), "cloudflare"),
        (re.compile(r"ak_bmsc|akamai.*bot.manager|bm_sv", re.IGNORECASE), "akamai"),
        (re.compile(r"incapsula|incap_ses|visid_incap", re.IGNORECASE), "imperva"),
        (re.compile(r"datadome.*challenge|datadome\.co", re.IGNORECASE), "datadome"),
        (re.compile(r"hcaptcha|recaptcha.*challenge|<title>[^<]*captcha", re.IGNORECASE), "captcha"),
        (re.compile(r"perimeterx|_px_session|_pxhd", re.IGNORECASE), "perimeterx"),
    )

    def __init__(self, rate_limiter: Optional[DomainRateLimiter] = None,
                 waf_tracker: Optional[WAFTracker] = None,
                 probe_cache: Optional[ProbeCache] = None):
        self.rate_limiter = rate_limiter or DomainRateLimiter()
        self.waf_tracker = waf_tracker or WAFTracker()
        self.probe_cache = probe_cache or _NullProbeCache()
        # Per-apex "catch-all / soft-404" flag, set by precheck(): when True every
        # path returns success-like, so path enumeration is pointless.
        self._catchall: dict = {}
        self._catchall_lock = threading.Lock()

    # ---- Public methods --------------------------------------------------

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def head(self, url, **kwargs):
        return self._request("HEAD", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def discover(self, url, **kwargs):
        """HEAD first; on 405 (Method Not Allowed), fall back to GET.

        Used for path-existence checks where we don't actually need the
        body — significantly reduces bandwidth and is much less likely
        to trip directory-enumeration WAF rules than serial GETs."""
        r = self.head(url, **kwargs)
        if r is not None and r.status_code == 405:
            return self.get(url, **kwargs)
        return r

    def waf_status(self, apex: str) -> dict:
        """Surface WAF status for an apex to the report renderers."""
        return self.waf_tracker.status(apex)

    def hard_blocked(self, apex_or_url: str, min_samples: int = 8) -> bool:
        """True when an apex shows SUSTAINED WAF blocking. Conservative: requires at
        least `min_samples` observations so a single stray 403 can't trip it. Accepts
        a bare apex/domain or a full URL."""
        url = apex_or_url if "://" in apex_or_url else f"https://{apex_or_url}"
        st = self.waf_tracker.status(_apex_of(url))
        return bool(st.get("blocked")) and int(st.get("samples", 0)) >= min_samples

    def stop_probing(self, apex_or_url: str, probed: int, *, min_probes: int = 10,
                     min_samples: int = 8) -> bool:
        """WAF-aware early-exit gate for path-enumeration checkers.

        Returns True once a checker has probed at least `min_probes` of its OWN paths
        AND the target either (a) is in sustained WAF blocking, or (b) was flagged as
        catch-all / soft-404 by precheck() (every path returns success -> nothing to
        find). The per-checker `probed` count keeps it fair regardless of checker
        order. Never fires on a healthy target, so non-WAF scans are unchanged."""
        url = apex_or_url if "://" in apex_or_url else f"https://{apex_or_url}"
        apex = _apex_of(url)
        # Catch-all / soft-404 (from precheck): enumeration can't find anything, so
        # bail after only a few confirming probes — no need for the full min_probes.
        with self._catchall_lock:
            if self._catchall.get(apex):
                return probed >= min(min_probes, 4)
        if probed < min_probes:
            return False
        st = self.waf_tracker.status(apex)
        return bool(st.get("blocked")) and int(st.get("samples", 0)) >= min_samples

    def precheck(self, domain: str, *, bogus: int = 2) -> dict:
        """Pre-scan WAF / soft-404 probe (opt-in; see WAF_PRECHECK / scan(waf_precheck)).

        Fires a few requests up front so the heavy enumeration checkers can early-exit
        instead of grinding full path lists:
          * `bogus` random paths -> a real site 404s these; if they come back 200/3xx
            the host is a catch-all (soft-404) and path enumeration can't find anything
          * a couple of known WAF-trigger paths -> surface 403/406/451 EARLY so the
            sustained-blocking signal is established before the big checkers run.
        Populates the WAF tracker + the catch-all flag; returns a summary."""
        import random
        apex = _apex_of(f"https://{domain}")
        statuses, non_404 = [], 0
        for i in range(max(0, bogus)):
            rp = f"/zz-{random.randint(10**7, 10**8)}-{i}-doesnotexist"
            r = self.get(f"https://{domain}{rp}", timeout=6, allow_redirects=False)
            if r is not None:
                statuses.append(r.status_code)
                if r.status_code in (200, 301, 302, 307, 308):
                    non_404 += 1
        for rp in ("/.git/config", "/.env", "/admin"):
            r = self.get(f"https://{domain}{rp}", timeout=6, allow_redirects=False)
            if r is not None:
                statuses.append(r.status_code)
        catch_all = bogus > 0 and non_404 >= bogus   # every bogus path looked "alive"
        with self._catchall_lock:
            self._catchall[apex] = catch_all
        return {"apex": apex, "statuses": statuses, "catch_all": catch_all,
                "waf": self.waf_status(apex)}

    def reset_for_scan(self, apex: Optional[str] = None) -> None:
        """Clear WAF history for a target apex at scan start. Cache is
        intentionally NOT reset - cache is designed to persist across
        scans (when a real backend is plugged in)."""
        self.waf_tracker.reset(apex)

    # ---- Internal --------------------------------------------------------

    def _request(self, method, url, force_refresh=False, **kwargs):
        if requests is None:
            return None
        apex = _apex_of(url)

        # WS6a cache lookup. _NullProbeCache always returns None (single-box
        # default). force_refresh bypasses the read but still re-stores below.
        if not force_refresh:
            cached = self.probe_cache.lookup(url, method)
            if cached is not None:
                return cached

        # Apply rate limit (no-op if apex is empty)
        if apex:
            self.rate_limiter.acquire(apex)

        # Identifying User-Agent (caller can override by passing headers)
        headers = kwargs.setdefault("headers", {})
        headers.setdefault("User-Agent", self.USER_AGENT)
        # Default timeout - shorter than the previous per-checker defaults
        # to avoid one slow request stalling the rate-limit pacing.
        kwargs.setdefault("timeout", 10)

        try:
            r = requests.request(method, url, **kwargs)
        except requests.Timeout:
            if apex:
                self.waf_tracker.record_timeout(apex)
            return None
        except (requests.ConnectionError, requests.RequestException):
            if apex:
                self.waf_tracker.record_timeout(apex)
            return None
        except Exception:
            if apex:
                self.waf_tracker.record_timeout(apex)
            return None

        # Record the status code
        if apex:
            self.waf_tracker.record(apex, r.status_code)
            # Check body for known WAF challenge signatures - only for
            # GET responses (HEAD doesn't return a body). Cap inspection
            # at 5KB to keep the regex cost bounded.
            if method == "GET" and 200 <= r.status_code < 500:
                try:
                    body_sample = (r.text or "")[:5000]
                except Exception:
                    body_sample = ""
                for pat, vendor in self._CHALLENGE_PATTERNS:
                    if pat.search(body_sample):
                        self.waf_tracker.record_challenge(apex, vendor)
                        break

        # Store full response in cache (no-op for _NullProbeCache).
        try:
            self.probe_cache.store(url, method, r)
        except Exception:
            pass

        return r


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

HTTP = HttpClient()

# WS5a: if REDIS_URL is set, share the per-apex politeness bucket across workers
# (the in-process bucket can't, so the limit is ~2x today under --workers 2). Falls
# back silently to the in-process bucket when Redis is absent.
try:
    from rate_limiter import maybe_redis_limiter
    _redis_apex = maybe_redis_limiter(rate=2.0, burst=5, namespace="apex")
    if _redis_apex is not None:
        HTTP.rate_limiter = _redis_apex
except Exception:
    pass

# WS6a: activate the probe cache (Redis when REDIS_URL set, else no-op default).
try:
    HTTP.probe_cache = make_probe_cache()
except Exception:
    pass
