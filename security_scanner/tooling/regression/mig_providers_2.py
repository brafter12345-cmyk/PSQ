"""WS0 migration gate for origin_discovery (SecurityTrails + Shodan) and
darkweb_providers (IntelX, Snusbase, LeakCheck, WhiteIntel).

Offline. Fake transport returns realistic per-provider JSON; all are paid, so dummy
keys are injected to reach the HTTP path. `time.sleep` is stubbed so IntelX's poll
loop doesn't stall. Workflow:

    # with ORIGINAL (pre-migration) files:
    py tooling/regression/mig_providers_2.py --record
    # restore migrated files, then:
    py tooling/regression/mig_providers_2.py
"""
from __future__ import annotations

import argparse
import dataclasses
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

_BODIES = [
    ("api.securitytrails.com", b'{"records":[{"values":[{"ip":"203.0.113.4"}]},'
                               b'{"values":[{"ip":"203.0.113.5"}]}]}'),
    ("/shodan/host/count", b'{"total":42}'),
    ("/shodan/host/search", b'{"matches":[{"ip_str":"198.51.100.9"}]}'),
    ("/intelligent/search/result", b'{"records":[{"name":"leak.txt","bucket":"leaks",'
                                   b'"media":0,"date":"2026-01-01","typeh":"Document"}],"status":1}'),
    ("/intelligent/search", b'{"id":"abc-123"}'),
    ("api.snusbase.com", b'{"results":{"STEALER_LOGS":[{"email":"a@examplecorp.co.za",'
                         b'"lastip_date":"2026-01-01"}]}}'),
    ("leakcheck.io", b'{"result":[{"email":"a@examplecorp.co.za","origin":"darknet",'
                     b'"source":{"name":"BreachX","date":"2026-01-01"}}]}'),
    ("api.whiteintel.io", b'{"data":[{"employee":"a@examplecorp.co.za","password":"p",'
                          b'"source_url":"http://x","infection_date":"2026-01-01"}]}'),
]


def _fake(session_self, method, url, **kwargs):
    body = b"{}"
    for needle, b in _BODIES:          # order matters: result before search
        if needle in url:
            body = b
            break
    r = requests.models.Response()
    r.status_code = 200
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.url = url
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "application/json"})
    return r


def _cases():
    import origin_discovery as od
    import darkweb_providers as dw
    K = "DUMMY-KEY-FOR-GATE"
    return {
        "origin_securitytrails": lambda: {"ips": od._fetch_historical_a("examplecorp.co.za", K)},
        "origin_shodan": lambda: dict(zip(("count", "ips", "used"),
                                          od._shodan_cert_hosts("examplecorp.co.za", K))),
        "dw_intelx": lambda: dataclasses.asdict(dw.IntelXProvider(api_key=K).query("examplecorp.co.za")),
        "dw_snusbase": lambda: dataclasses.asdict(dw.SnusbaseProvider(api_key=K).query("examplecorp.co.za")),
        "dw_leakcheck": lambda: dataclasses.asdict(dw.LeakCheckProvider(api_key=K).query("examplecorp.co.za")),
        "dw_whiteintel": lambda: dataclasses.asdict(dw.WhiteIntelProvider(api_key=K).query("examplecorp.co.za")),
    }


def _with_stubs(fn):
    import requests.sessions as S
    orig_req, orig_sleep = S.Session.request, time.sleep
    S.Session.request = _fake
    time.sleep = lambda *a, **k: None
    try:
        return fn()
    finally:
        S.Session.request = orig_req
        time.sleep = orig_sleep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            s = _with_stubs(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:24s} {s['requests']} request(s) frozen")
        print("\nBaselines frozen. Restore migrated files, then re-run without --record.")
        return 0
    failures = 0
    for name, fn in cases.items():
        r = _with_stubs(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("MIGRATION GATE PASSED — origin_discovery + darkweb_providers preserved." if not failures
          else f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
