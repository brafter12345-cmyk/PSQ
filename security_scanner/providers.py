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
from usage_ledger import InMemoryUsageLedger
from result_cache import make_result_cache

# WS6b: one shared result cache (Redis single-flight when REDIS_URL is set; None
# single-box by default — see make_result_cache).
_CACHE = make_result_cache()

# WS7 is now ON: clients retry transient failures, trip a breaker on sustained
# failure (-> checker marked skipped, scoring redistributes), and are bounded by a
# shared usage ledger so an outage can't retry-storm into rate limits / paid cost.
#
# The ledger is in-process (single-box scanner). The distributed version swaps in
# with the same interface: Redis counters (provider+day / provider+window) mirrored
# to a Postgres `usage` table (SCALE-17/18). Daily caps below are conservative
# placeholders — tune against real quotas. Free providers are uncapped.
_LEDGER = InMemoryUsageLedger(
    default_daily_cap=None,
    daily_caps={
        "shodan": 1000, "hibp": 1000, "dehashed": 1000, "intelx": 1000,
        "securitytrails": 2000, "virustotal": 500, "snusbase": 2000,
        "leakcheck": 2000, "whiteintel": 500,
    },
    retry_cap_per_window=50,
    retry_window_seconds=300,
)


def _client(name: str, *, rate: float = 5.0, burst: int = 10,
            default_timeout: float = 15.0, max_attempts: int = 3,
            failure_threshold: int = 5, reset_timeout: float = 60.0) -> ProviderClient:
    """A WS7 client: route + pace + retry (exp backoff/jitter) + per-provider
    breaker + ledger-enforced budget. Success path is unchanged from WS0 (no
    retry/trip on a healthy 2xx), so the migration gates stay green."""
    return ProviderClient(
        name, rate=rate, burst=burst, default_timeout=default_timeout,
        retry=RetryPolicy(max_attempts=max_attempts),
        breaker=CircuitBreaker(failure_threshold=failure_threshold,
                               reset_timeout=reset_timeout, name=name),
        ledger=_LEDGER,
        cache=_CACHE,
    )


# Backwards-compatible alias (WS0 call sites built clients via _ws0).
_ws0 = _client


# --- paid / quota'd providers --------------------------------------------
SHODAN = _ws0("shodan")                 # api.shodan.io (host + cert search/count)
HIBP = _ws0("hibp")                     # haveibeenpwned.com (breach + metadata)
DEHASHED = _ws0("dehashed", default_timeout=30.0)
INTELX = _ws0("intelx")                 # free.intelx.io (search initiate + poll)
SECURITYTRAILS = _ws0("securitytrails")
VIRUSTOTAL = _ws0("virustotal")
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
KEV = _ws0("kev")                       # CISA Known Exploited Vulns catalog + mirror
