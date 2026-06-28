"""Central registry of per-provider egress clients (WS0).

One `ProviderClient` per external provider, so every paid/quota'd call routes
through a single controllable seam instead of a bare `requests.*`. Checkers import
the client they need (`from providers import SHODAN`) and call `SHODAN.get(...)`.

WS0 stance — *transparent routing, behaviour-preserving*:
  * **No added retry** (`max_attempts=1`) — checkers that already own a retry loop
    (crt.sh, OSV polling, IntelX polling) keep their exact semantics; checkers with
    none don't suddenly gain extra outbound calls. WS7 turns retry on later by
    raising `max_attempts` here — one edit, no checker touched.
  * **Breaker effectively disabled** (`failure_threshold` enormous) — no mid-scan
    trip changes results today; WS7 lowers it to enable the degrade-don't-fail path.
  * **Gentle per-provider bucket** — pacing only (adds delay, never changes a
    result or which calls are made), the machinery WS5a tightens into real quota
    enforcement and swaps for the distributed (Redis) bucket.
  * **Cache + metering slots empty** — WS6b result cache and WS5b usage ledger plug
    in here later without touching a single call site.

`ProviderClient.request` returns a `requests.Response` (incl. terminal 4xx/5xx,
which the caller still inspects) or `None` when the single attempt raised
(connection error / timeout) — i.e. exactly the cases the old `try/except` around
`requests.*` handled. Migrated call sites map `None` to their existing failure path.
"""
from __future__ import annotations

from provider_client import ProviderClient
from resilience import CircuitBreaker, RetryPolicy

_NO_TRIP = 10 ** 9  # WS0: breaker present but won't trip; WS7 lowers this.


def _ws0(name: str, *, rate: float = 5.0, burst: int = 10,
         default_timeout: float = 15.0) -> ProviderClient:
    """A behaviour-preserving WS0 client: route + pace only, no retry, no trip."""
    return ProviderClient(
        name, rate=rate, burst=burst, default_timeout=default_timeout,
        retry=RetryPolicy(max_attempts=1),
        breaker=CircuitBreaker(failure_threshold=_NO_TRIP, name=name),
    )


# --- paid / quota'd providers --------------------------------------------
SHODAN = _ws0("shodan")                 # api.shodan.io (host + cert search/count)
HIBP = _ws0("hibp")                     # haveibeenpwned.com (breach + metadata)
DEHASHED = _ws0("dehashed", default_timeout=30.0)
INTELX = _ws0("intelx")                 # free.intelx.io (search initiate + poll)
SECURITYTRAILS = _ws0("securitytrails")
SNUSBASE = _ws0("snusbase")
LEAKCHECK = _ws0("leakcheck")
WHITEINTEL = _ws0("whiteintel")

# --- free / unauthenticated providers ------------------------------------
CRTSH = _ws0("crtsh", default_timeout=30.0)   # crt.sh (CT logs)
OSV = _ws0("osv")                       # api.osv.dev
NVD = _ws0("nvd")                       # services.nvd.nist.gov
EPSS = _ws0("epss")                     # api.first.org/data/v1/epss
EXPLOITDB = _ws0("exploitdb")           # gitlab.com/.../exploitdb CSV
MSF = _ws0("msf")                       # raw.githubusercontent metasploit modules
TRANCO = _ws0("tranco", default_timeout=30.0)
INTERNETDB = _ws0("internetdb")         # internetdb.shodan.io (free, != paid Shodan)
HUDSONROCK = _ws0("hudsonrock")         # cavalier.hudsonrock.com (free domain API)
