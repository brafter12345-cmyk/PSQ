"""WS0 migration gate for related_domain_discovery (crt.sh) + credential_export (DeHashed).

Offline. Fake transport returns realistic crt.sh JSON and a synthetic DeHashed page;
DeHashed is a paid provider, so a dummy key is injected to reach the HTTP path.

    # with the ORIGINAL (pre-migration) files checked out:
    py tooling/regression/mig_small_providers.py --record
    # restore the migrated files, then:
    py tooling/regression/mig_small_providers.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent.parent
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import requests
import checker_gate as cg

_CRT_JSON = (b'[{"name_value":"examplecorp.co.za\\nwww.examplecorp.co.za",'
             b'"issuer_name":"C=US, O=Let\'s Encrypt, CN=R3"},'
             b'{"name_value":"shop.examplecorp.co.za","issuer_name":"C=US"}]')
_DEHASHED_JSON = b'{"entries":[{"email":"a@examplecorp.co.za","database_name":"x"}]}'


def _resp(body: bytes, ctype: str = "application/json", status: int = 200):
    r = requests.models.Response()
    r.status_code = status
    r._content = body
    r._content_consumed = True
    r.encoding = "utf-8"
    r.headers = requests.structures.CaseInsensitiveDict({"Content-Type": ctype})
    return r


def _fake(session_self, method, url, **kwargs):
    if "dehashed" in url:
        r = _resp(_DEHASHED_JSON)
    elif "crt.sh" in url:
        r = _resp(_CRT_JSON)
    else:
        r = _resp(b"{}")
    r.url = url
    return r


def _cases():
    import related_domain_discovery as rdd
    import credential_export as ce
    return {
        "rdd_crtsh_query": lambda: {"rows": rdd._crtsh_query("examplecorp.co.za")},
        "ce_dehashed_full": lambda: {
            "entries": ce._fetch_dehashed_full("examplecorp.co.za",
                                               "DUMMY-KEY-FOR-GATE", max_pages=2)},
    }


def _with_fake(fn):
    import requests.sessions as S
    orig = S.Session.request
    S.Session.request = _fake
    try:
        return fn()
    finally:
        S.Session.request = orig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", action="store_true")
    args = ap.parse_args()
    cases = _cases()
    if args.record:
        for name, fn in cases.items():
            s = _with_fake(lambda fn=fn: cg.record_baseline(name, fn))
            print(f"[record] {name:20s} {s['requests']} request(s) frozen")
        print("\nBaselines frozen. Restore migrated files, then re-run without --record.")
        return 0
    failures = 0
    for name, fn in cases.items():
        r = _with_fake(lambda fn=fn: cg.verify(name, fn))
        print(r)
        failures += 0 if r.ok else 1
    print()
    print("MIGRATION GATE PASSED — small-provider behaviour preserved." if not failures
          else f"MIGRATION GATE FAILED — {failures} case(s) drifted.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
