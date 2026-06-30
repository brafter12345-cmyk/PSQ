"""WS0 checker-level gate for checkers_threats.py — drives each provider checker's
check() entry point offline (dummy keys for paid providers), closing the gap left
by mig_checkers_threats.py (which gates the free feeds at unit level).

Covers: BreachChecker (HIBP + apex helpers), PaymentSecurityChecker, VirusTotal,
SecurityTrails, Dehashed, HudsonRock, IntelX, WebRanking (Tranco), Glasswing,
ShodanVuln (Shodan full + enrichment). DNS/socket/time.sleep stubbed and class-level
caches reset per case for determinism.

    git stash push -- security_scanner/checkers_threats.py
    py tooling/regression/mig_threats_full.py --record
    git stash pop
    py tooling/regression/mig_threats_full.py
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import requests
import checker_gate as cg

K = "DUMMY-KEY-FOR-GATE"

_ROUTES = [
    ("haveibeenpwned", b'[{"Name":"Acme","Title":"Acme","BreachDate":"2021-03-01",'
                       b'"DataClasses":["Email addresses","Passwords"],"PwnCount":1000}]'),
    ("/associated", b'{"records":[],"record_count":0}'),
    ("securitytrails", b'{"current_dns":{"a":{"values":[{"ip":"203.0.113.4"}]},'
                       b'"mx":{"values":[]},"ns":{"values":[]}},"alexa_rank":12345}'),
    ("virustotal", b'{"data":{"attributes":{"last_analysis_stats":{"malicious":0,'
                   b'"suspicious":0,"harmless":80,"undetected":5},"reputation":0,'
                   b'"total_votes":{"malicious":0,"harmless":1},"categories":{}}}}'),
    ("dehashed", b'{"entries":[{"email":"a@examplecorp.co.za","password":"x"}],"total":1,"balance":99}'),
    ("hudsonrock", b'{"stealers":[],"employees":[],"totalStealers":0,"data":[]}'),
    ("/intelligent/search/result", b'{"records":[],"status":1}'),
    ("/intelligent/search", b'{"id":"abc-123"}'),
    ("internetdb.shodan.io", b'{"ports":[80],"cpes":[],"vulns":[],"tags":[]}'),
    ("shodan.io/shodan/host", b'{"ports":[80,443],"vulns":["CVE-2021-44228"],"data":[],'
                              b'"tags":[],"hostnames":[]}'),
    ("tranco", b"1,examplecorp.co.za\n2,other.co.za\n"),
    ("osv.dev", b'{"vulns":[]}'),
    ("nvd.nist.gov", b'{"vulnerabilities":[{"cve":{"id":"CVE-2021-44228",'
                     b'"descriptions":[{"lang":"en","value":"x"}],"metrics":{"cvssMetricV31":'
                     b'[{"cvssData":{"baseScore":10.0,"vectorString":"AV:N/AC:L/PR:N"}}]},'
                     b'"published":"2021-12-10T00:00Z","references":[]}}]}'),
    ("cisa.gov", b'{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}'),
    ("metasploit", b'{"m":{"references":["CVE-2021-44228"]}}'),
    ("exploit", b"id,file,codes\n1,x,CVE-2021-44228\n"),
    ("first.org", b'{"data":[{"cve":"CVE-2021-44228","epss":"0.9","percentile":"0.9"}]}'),
]


def _fake(session_self, method, url, **kwargs):
    body = (b"<html><head><title>Example Corp</title></head><body>hi</body></html>")
    for needle, b in _ROUTES:
        if needle in url:
            body = b
            break
    r = requests.models.Response()
    r.status_code = 200
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict(
        {"Content-Type": "application/json", "Server": "nginx"})
    return r


def _reset_caches():
    import checkers_threats as ct
    for cls_name in ("ShodanVulnChecker", "WebRankingChecker", "HIBPBreachMetadata"):
        cls = getattr(ct, cls_name, None)
        if cls is None:
            continue
        for attr in list(vars(cls)):
            if attr.endswith("_cache"):
                setattr(cls, attr, None)
            if attr.endswith("_cache_time") or attr == "_cache_time":
                setattr(cls, attr, 0)


def _cases():
    import checkers_threats as ct
    return {
        "full_breach": lambda: ct.BreachChecker().check("examplecorp.co.za"),
        "full_payment": lambda: ct.PaymentSecurityChecker().check("examplecorp.co.za"),
        "full_virustotal": lambda: ct.VirusTotalChecker().check("examplecorp.co.za", api_key=K),
        "full_securitytrails": lambda: ct.SecurityTrailsChecker().check("examplecorp.co.za", api_key=K),
        "full_dehashed": lambda: ct.DehashedChecker().check("examplecorp.co.za", api_key=K),
        "full_hudsonrock": lambda: ct.HudsonRockChecker().check("examplecorp.co.za"),
        "full_intelx": lambda: ct.IntelXChecker().check("examplecorp.co.za", api_key=K),
        "full_webranking": lambda: ct.WebRankingChecker().check("examplecorp.co.za"),
        "full_glasswing": lambda: ct.GlasswingPartnerChecker().check("examplecorp.co.za"),
        "full_shodanvuln": lambda: ct.ShodanVulnChecker().check("examplecorp.co.za", api_key=K, ip="203.0.113.4"),
    }


# Frozen "now" for the gate so CVE-age derived fields (age_days,
# patch_management.*_age_days, and the "X days old" issue string) are
# deterministic across runs. Without this, ShodanVulnChecker computes
# `datetime.utcnow() - published` (checkers_threats.py ~L844), which ticks +1/day
# and produces a spurious gate failure the day after the baseline was frozen.
# Both --record and verify run under this clock, so the age stays constant.
_FROZEN_NOW = (2026, 6, 30)


def _with_stubs(fn):
    import requests.sessions as S
    try:
        import dns.resolver
        orig_resolve = dns.resolver.resolve
    except Exception:
        dns, orig_resolve = None, None
    import datetime as _dtmod
    orig_dt = _dtmod.datetime

    class _FrozenDateTime(orig_dt):
        @classmethod
        def utcnow(cls):
            return cls(*_FROZEN_NOW)

        @classmethod
        def now(cls, tz=None):
            return cls(*_FROZEN_NOW, tzinfo=tz) if tz else cls(*_FROZEN_NOW)

    orig_req, orig_sleep = S.Session.request, time.sleep
    orig_gai, orig_ghn = socket.getaddrinfo, socket.gethostbyname
    S.Session.request = _fake
    time.sleep = lambda *a, **k: None
    socket.getaddrinfo = lambda *a, **k: [(2, 1, 6, "", ("203.0.113.4", 0))]
    socket.gethostbyname = lambda *a, **k: "203.0.113.4"
    _dtmod.datetime = _FrozenDateTime
    if orig_resolve is not None:
        dns.resolver.resolve = lambda *a, **k: []
    _reset_caches()
    try:
        return fn()
    finally:
        S.Session.request = orig_req
        time.sleep = orig_sleep
        socket.getaddrinfo = orig_gai
        socket.gethostbyname = orig_ghn
        _dtmod.datetime = orig_dt
        if orig_resolve is not None:
            dns.resolver.resolve = orig_resolve


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            try:
                s = _with_stubs(lambda fn=fn: cg.record_baseline(name, fn))
                print(f"[record] {name:22s} {s['requests']} request(s) frozen")
            except Exception as e:  # noqa: BLE001
                print(f"[SKIP]   {name:22s} could not drive offline: {type(e).__name__}: {e}")
        print("\nBaselines frozen. Restore migrated file, then re-run without --record.")
        return 0
    failures = 0
    for name, fn in cases.items():
        cas_path = cg.DEFAULT_BASELINE_DIR / f"{name}.cassette.json"
        if not cas_path.exists():
            print(f"[skip] {name}: no baseline (was not offline-driveable at record)")
            continue
        r = _with_stubs(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("CHECKER-LEVEL GATE PASSED — checkers_threats provider checkers preserved." if not failures
          else f"CHECKER-LEVEL GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
