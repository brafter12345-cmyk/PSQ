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
    from usage_ledger import UsageLedger

from rate_limiter import make_rate_limiter
from resilience import (
    CircuitBreaker, CircuitOpenError, RetryPolicy, classify_response, guarded_call,
)


class ResultCache:
    """WS6b result-cache protocol (see result_cache.py). ``fetch`` is get-or-compute
    with single-flight: it returns a cached response, or runs ``compute`` (the real
    provider call) on a miss while coalescing concurrent identical calls onto one.
    ``force_refresh`` bypasses the read but still takes the lease + writes."""

    def fetch(self, provider, method, url, kwargs, compute, force_refresh=False):
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
                 on_call: Optional[Callable[[str, str], None]] = None,
                 ledger: "Optional[UsageLedger]" = None):
        self.name = name
        # WS5a: per-provider bucket — Redis-shared across workers when REDIS_URL is
        # set, else the in-process token bucket.
        self._limiter = make_rate_limiter(rate, burst, namespace=f"prov:{name}")
        self._retry = retry or RetryPolicy()
        self._breaker = breaker or CircuitBreaker(name=name)
        self._cache = cache
        self._default_timeout = default_timeout
        # Metering hook: called (provider, method) per real outbound call. The
        # WS5b/SCALE-17 ledger plugs in here; default counts nothing.
        self._on_call = on_call
        # WS7/WS5b usage ledger: kill-switch (allow_call), spend metering
        # (record_call), and retry budget (allow_retry). None = unenforced.
        self._ledger = ledger

    # ---- public verbs ----------------------------------------------------
    def get(self, url, **kwargs) -> "Response | None":
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs) -> "Response | None":
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs) -> "Response | None":
        return self.request("HEAD", url, **kwargs)

    # ---- core ------------------------------------------------------------
    def request(self, method, url, force_refresh: bool = False, **kwargs) -> "Response | None":
        if requests is None:
            return None
        kwargs.setdefault("timeout", self._default_timeout)

        # The actual provider call: kill-switch -> pace -> meter -> retry/breaker.
        # Runs only on a genuine cache miss (and once, via single-flight).
        def _provider_call():
            if self._ledger is not None and not self._ledger.allow_call(self.name):
                return None  # WS5b kill-switch: daily budget spent
            self._limiter.acquire(self.name)

            def _do():
                if self._ledger is not None:
                    self._ledger.record_call(self.name)  # meter every attempt
                if self._on_call is not None:
                    self._on_call(self.name, method)
                return requests.request(method, url, **kwargs)

            can_retry = ((lambda: self._ledger.allow_retry(self.name))
                         if self._ledger is not None else None)
            try:
                return guarded_call(_do, breaker=self._breaker, retry=self._retry,
                                    classify_result=classify_response, can_retry=can_retry)
            except CircuitOpenError:
                return None
            except Exception:
                return None  # every retry raised -> None, checker marks skipped

        # WS6b: route through the result cache (get-or-compute + single-flight) when
        # one is configured; otherwise call the provider directly.
        if self._cache is not None:
            return cast("Optional[Response]", self._cache.fetch(
                self.name, method, url, kwargs, _provider_call, force_refresh))
        return cast("Optional[Response]", _provider_call())

    # ---- introspection for ops/tests -------------------------------------
    @property
    def breaker_state(self) -> str:
        return self._breaker.state
