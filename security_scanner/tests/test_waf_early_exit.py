"""WAF-aware early-exit gate logic (HTTP.hard_blocked / HTTP.stop_probing).

Proves the conservative behaviour that makes it safe to bolt onto every path-probing
checker: it never fires on a healthy target, requires a minimum sample of real probes,
and only trips on sustained blocking.
"""
from __future__ import annotations

from http_client import HttpClient


def _block(client, apex, n, code=403):
    for _ in range(n):
        client.waf_tracker.record(apex, code)


def test_not_blocked_without_samples():
    c = HttpClient()
    assert c.hard_blocked("clean.example") is False


def test_healthy_target_never_trips():
    c = HttpClient()
    _block(c, "healthy.example", 30, code=200)        # all 200s
    assert c.hard_blocked("healthy.example") is False
    # even far past min_probes, a healthy target never early-exits
    assert c.stop_probing("healthy.example", probed=500) is False


def test_sustained_blocking_trips_after_min_samples():
    c = HttpClient()
    _block(c, "waf.example", 4, code=403)              # only 4 samples
    assert c.hard_blocked("waf.example", min_samples=8) is False
    _block(c, "waf.example", 4, code=403)              # now 8 samples, all 403
    assert c.hard_blocked("waf.example", min_samples=8) is True


def test_stop_probing_respects_min_probes():
    c = HttpClient()
    _block(c, "waf.example", 12, code=403)             # apex is hard-blocking
    # below the per-checker min_probes -> keep probing our own paths
    assert c.stop_probing("waf.example", probed=5, min_probes=10) is False
    # past min_probes AND blocked -> bail
    assert c.stop_probing("waf.example", probed=10, min_probes=10) is True


def test_partial_blocking_below_threshold():
    c = HttpClient()
    # 3 of 10 are 403 (30%) -> below the 40% block threshold -> not blocked
    _block(c, "mild.example", 3, code=403)
    _block(c, "mild.example", 7, code=200)
    assert c.hard_blocked("mild.example") is False
    assert c.stop_probing("mild.example", probed=50) is False


def test_accepts_url_or_apex():
    c = HttpClient()
    _block(c, "waf.example", 10, code=451)
    assert c.hard_blocked("https://waf.example/admin") is True
    assert c.hard_blocked("waf.example") is True


# --- catch-all / soft-404 + precheck ----------------------------------------
def test_catchall_flag_trips_stop_probing():
    import http_client
    c = HttpClient()
    c._catchall[http_client._apex_of("https://catchall.example")] = True
    # below min_probes -> still probe our own paths first
    assert c.stop_probing("catchall.example", probed=3) is False
    # past min_probes + catch-all -> bail (no WAF 403 needed)
    assert c.stop_probing("catchall.example", probed=10) is True


def test_precheck_detects_catchall(monkeypatch):
    import http_client
    from harness import make_response
    # every path (incl. random bogus ones) returns 200 -> catch-all / soft-404
    monkeypatch.setattr(http_client.requests, "request",
                        lambda method, url, **kw: make_response(200))
    c = HttpClient()
    summary = c.precheck("catchall.example", bogus=2)
    assert summary["catch_all"] is True
    assert c.stop_probing("catchall.example", probed=10) is True


def test_precheck_no_catchall_on_real_404(monkeypatch):
    import http_client
    from harness import make_response
    # bogus paths 404 (real not-found handling), trigger paths 403
    monkeypatch.setattr(
        http_client.requests, "request",
        lambda method, url, **kw: make_response(404 if "/zz-" in url else 403))
    c = HttpClient()
    summary = c.precheck("clean.example", bogus=2)
    assert summary["catch_all"] is False
    # only ~5 samples gathered -> below min_samples, so no early-exit yet
    assert c.stop_probing("clean.example", probed=20) is False
