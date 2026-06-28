"""Per-provider HTTP client wrapper (WS0b / SCALE-00, shape (b)).

The scaling design calls for routing every paid/quota'd provider (Shodan, HIBP,
DeHashed, IntelX, VirusTotal, SecurityTrails, OSV, crt.sh, …) through a thin
per-provider client that owns the cross-cutting controls those calls need but the
raw ``requests.*`` sites lack:

  * a **per-provider token bucket** — provider quota pacing, independent of the
    per-*apex* politeness limiter in ``http_client.HTTP`` (which exists for the
    scan *target*, not for API endpoints). Ready to become the WS5a distributed
    bucket later by swapping the limiter.
  * **retry + circuit breaker** — mounted from the already-built, fully-tested
    ``resilience`` toolkit (``guarded_call``). A dead provider trips its breaker
    and the call returns ``None`` so the checker is marked ``skipped`` (scoring
    redistributes weight) instead of dragging the whole scan.
  * a **result-cache slot** — the WS6b primary cost lever. Disabled by default
    (no cache); plug a ``ResultCache`` in once the store exists. The slot is here
    so call sites are migrated *once*, not twice.
  * a **metering hook** — a no-op by default; the WS5b/SCALE-17 usage ledger plugs
    in here to count spend per provider without touching call sites again.

Layering note: this wraps ``requests`` **directly**, not ``http_client.HTTP``.
``HTTP`` swallows errors and returns ``None``, which would blind the retry policy
(it must see the real status code / exception to classify retriable vs terminal).
Routing through ``requests`` keeps the egress visible to the regression cassette
(which patches ``requests.sessions.Session.request``) while letting resilience do
its job.

**Imported by no checker yet.** This is the seam the WS0 call-site migration will
move the direct ``requests.*`` calls onto, one site at a time, each gated by the
checker-level golden gate (``tooling/regression/checker_gate.py``). Until then it
changes no runtime behaviour.
"""
from __future__ import annotations

from typing import Callable, Optional, TYPE_CHECKING, cast

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard dep of the scanner
    requests = None

if TYPE_CHECKING:
    from requests import Response

from http_client import DomainRateLimiter
from resilience import (
    CircuitBreaker, CircuitOpenError, RetryPolicy, classify_response, guarded_call,
)


class ResultCache:
    """WS6b result-cache protocol. ``get`` returns a cached response-like object
    or ``None`` (miss); ``put`` stores one. Implementations own TTLs, the global
    ``(provider, params)`` key, and the single-flight lease (see SCALE-08a). The
    default client uses no cache; this is the slot, not an implementation."""

    def get(self, provider: str, method: str, url: str, kwargs: dict):
        raise NotImplementedError

    def put(self, provider: str, method: str, url: str, kwargs: dict, response) -> None:
        raise NotImplementedError


class ProviderClient:
    """One configured egress path for a single provider.

    Example (migration target)::

        SHODAN = ProviderClient("shodan", rate=1.0, burst=2)
        r = SHODAN.get(SHODAN_HOST_URL.format(ip=ip), params={"key": KEY})
        if r is None:        # breaker open or call failed after retries
            return {"status": "skipped"}
        if r.status_code == 200:
            ...

    The return contract matches the raw ``requests`` sites it replaces: a
    ``requests.Response`` on success (including terminal 4xx — the caller still
    inspects ``status_code``), or ``None`` when the breaker is open or every retry
    raised. Terminal/retriable classification and backoff are handled internally.
    """

    def __init__(self, name: str, *, rate: float = 2.0, burst: int = 5,
                 retry: Optional[RetryPolicy] = None,
                 breaker: Optional[CircuitBreaker] = None,
                 cache: Optional[ResultCache] = None,
                 default_timeout: float = 15.0,
                 on_call: Optional[Callable[[str, str], None]] = None):
        self.name = name
        self._limiter = DomainRateLimiter(rate=rate, burst=burst)
        self._retry = retry or RetryPolicy()
        self._breaker = breaker or CircuitBreaker(name=name)
        self._cache = cache
        self._default_timeout = default_timeout
        # Metering hook: called (provider, method) per real outbound call. The
        # WS5b/SCALE-17 ledger plugs in here; default counts nothing.
        self._on_call = on_call

    # ---- public verbs ----------------------------------------------------
    def get(self, url, **kwargs) -> "Response | None":
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs) -> "Response | None":
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs) -> "Response | None":
        return self.request("HEAD", url, **kwargs)

    # ---- core ------------------------------------------------------------
    def request(self, method, url, **kwargs) -> "Response | None":
        if requests is None:
            return None

        # 1. WS6b cache read (global (provider, params) key; disabled by default).
        if self._cache is not None:
            hit = self._cache.get(self.name, method, url, kwargs)
            if hit is not None:
                return cast("Response", hit)

        # 2. per-provider quota pacing (single bucket keyed by provider name).
        self._limiter.acquire(self.name)

        kwargs.setdefault("timeout", self._default_timeout)

        def _do():
            if self._on_call is not None:
                self._on_call(self.name, method)
            return requests.request(method, url, **kwargs)

        # 3. retry + breaker. guarded_call returns the last response (so a
        #    terminal 4xx flows back for the caller to inspect) and re-raises only
        #    if every attempt raised; a tripped breaker raises CircuitOpenError.
        try:
            resp = guarded_call(_do, breaker=self._breaker, retry=self._retry,
                                classify_result=classify_response)
        except CircuitOpenError:
            return None
        except Exception:
            # Every retry raised (e.g. persistent connection error). Match the
            # raw-site contract: surface as None, let the checker mark skipped.
            return None

        # 4. WS6b cache write (only successful, non-retriable responses).
        if self._cache is not None and resp is not None \
                and classify_response(resp) != "retriable":
            try:
                self._cache.put(self.name, method, url, kwargs, resp)
            except Exception:
                pass

        return cast("Optional[Response]", resp)

    # ---- introspection for ops/tests -------------------------------------
    @property
    def breaker_state(self) -> str:
        return self._breaker.state
