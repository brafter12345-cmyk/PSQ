# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""LOCAL change (2026-06-10): format the Annual Revenue (ZAR) scan-form input with
en-ZA thousands spacing (e.g. 14 300 000), matching the SME Rating Engine's
focus=raw / blur=grouped behaviour (same `toLocaleString('en-ZA')` call, so it
renders identically). type=number -> type=text + inputmode=numeric; the submit
handler reads digits-only so the backend still receives a clean integer.
CRLF-safe. NOT pushed by this script (a scan is running on prod)."""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(ROOT, "templates", "index.html")
s = open(IDX, encoding="utf-8").read()
assert "\r" not in s, "expected text-mode normalised (no raw CR)"
n = 0

# 1. The input element: number spinner -> formatted text.
OLD = '          <input type="number" id="revenue" name="annual_revenue_zar" placeholder="e.g. 50000000" min="0" step="1" />\n'
NEW = '          <input type="text" inputmode="numeric" id="revenue" name="annual_revenue_zar" placeholder="e.g. 50 000 000" autocomplete="off" />\n'
assert s.count(OLD) == 1, ("input element", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Submit read: strip non-digits (the en-ZA group space) before parseInt.
OLD = "  const revenue = parseInt(document.getElementById('revenue').value, 10);\n"
NEW = "  const revenue = parseInt(document.getElementById('revenue').value.replace(/[^\\d]/g, ''), 10);\n"
assert s.count(OLD) == 1, ("submit read", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Wire focus/blur/paste thousands formatting (mirrors the SME engine).
ANCHOR = "form.addEventListener('submit', async (e) => {\n"
BLOCK = (
    "// Annual Revenue: en-ZA thousands spacing (like the SME Rating Engine).\n"
    "// Raw digits on focus for easy editing, space-grouped on blur; the submit\n"
    "// handler reads digits-only so the formatted display never reaches the API.\n"
    "(function () {\n"
    "  const rev = document.getElementById('revenue');\n"
    "  if (!rev) return;\n"
    "  const digits = (v) => (v || '').replace(/[^\\d]/g, '');\n"
    "  const grouped = (v) => { const d = digits(v); return d ? Number(d).toLocaleString('en-ZA') : ''; };\n"
    "  rev.addEventListener('focus', () => { rev.value = digits(rev.value); });\n"
    "  rev.addEventListener('blur', () => { rev.value = grouped(rev.value); });\n"
    "  rev.addEventListener('paste', () => { setTimeout(() => { rev.value = grouped(rev.value); }, 0); });\n"
    "  rev.value = grouped(rev.value);  // format any pre-filled value on load\n"
    "})();\n"
    "\n"
)
assert s.count(ANCHOR) == 1, ("submit anchor", s.count(ANCHOR))
s = s.replace(ANCHOR, BLOCK + ANCHOR, 1); n += 1

with open(IDX, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
# re-read & sanity-check the round-trip
chk = open(IDX, encoding="utf-8").read()
assert 'inputmode="numeric" id="revenue"' in chk
assert "toLocaleString('en-ZA')" in chk
assert "replace(/[^\\d]/g, '')" in chk
print(f"OK templates/index.html: {n} edits (revenue en-ZA thousands-spacing).")
