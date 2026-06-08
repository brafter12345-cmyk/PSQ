# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SHIP (2026-06-09): lower the in-code MAX_CONCURRENT_SCANS default 5 -> 2 (the
handoff "minor open code" tidy). Production already sets MAX_CONCURRENT_SCANS=2 on
Render (512MB tier, 1 worker), so live behaviour is unchanged - this just aligns the
fallback default with the deployed intent so an absent/cleared env var degrades to
the safe value rather than over-subscribing the 512MB instance. CRLF-safe.
Run from security_scanner/: py tooling/_apply_max_concurrent_default_2.py
"""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, "app.py")
s = open(APP, encoding="utf-8").read()
assert "\r" not in s, "expected universal-newline read to strip CR"

OLD = 'MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))\n'
NEW = ('# Default 2 for the Render 512MB / 1-worker tier (env-overridable via\n'
       '# MAX_CONCURRENT_SCANS; production sets it explicitly). Per-process semaphore.\n'
       'MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_SCANS", "2"))\n')
assert s.count(OLD) == 1, ("MAX_CONCURRENT default", s.count(OLD))
s = s.replace(OLD, NEW, 1)

ast.parse(s)
with open(APP, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(APP, encoding="utf-8").read())
print("OK app.py: MAX_CONCURRENT_SCANS in-code default 5 -> 2.")
