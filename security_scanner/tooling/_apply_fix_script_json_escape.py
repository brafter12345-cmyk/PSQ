# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX FIX (2026-06-08): results.html embeds json.dumps(results) raw inside
<script>var RESULTS = {{ results_json|safe }}</script>. json.dumps does NOT escape
</script> or <!-- , so any scanned field containing such a sequence (e.g. a captured
HTTP banner / Cloudflare error page with an inline <script>) closes the tag early and
spills the rest of the JSON into the visible page (observed on mamamoney.co.za). Also
a stored-XSS vector. Fix: escape </ , <!-- and the JS line/para separators in the
JSON before embedding, for BOTH results_json and manifest_json. CRLF-safe. NOT shipped
by this script."""
import ast, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AP = os.path.join(ROOT, "app.py")
s = open(AP, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Insert the helper just before the /results route.
OLD = (
    "@app.route(\"/results/<scan_id>\")\n"
    "def view_results(scan_id: str):\n"
)
NEW = (
    "def _json_for_script(obj):\n"
    "    \"\"\"json.dumps escaped for safe embedding inside an inline <script> tag.\n"
    "\n"
    "    json.dumps does NOT neutralise </script> or <!-- , so any scanned field\n"
    "    containing such a sequence (e.g. a captured banner / error page with an\n"
    "    inline script) would close the tag early and spill the rest of the JSON\n"
    "    into the page - a render break AND a stored-XSS vector. Escape </ , <!--\n"
    "    and the JS line/paragraph separators (invalid bare in JS string literals).\n"
    "    \"\"\"\n"
    "    return (json.dumps(obj, default=str)\n"
    "            .replace(\"</\", \"<\\\\/\")\n"
    "            .replace(\"<!--\", \"<\\\\!--\")\n"
    "            .replace(\"\\u2028\", \"\\\\u2028\")\n"
    "            .replace(\"\\u2029\", \"\\\\u2029\"))\n"
    "\n"
    "\n"
    "@app.route(\"/results/<scan_id>\")\n"
    "def view_results(scan_id: str):\n"
)
assert s.count(OLD) == 1, ("route anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Route results_json + manifest_json through the escaper.
for tag, old, new in [
    ("results_json",
     "results_json=json.dumps(results, default=str) if results else \"null\",",
     "results_json=_json_for_script(results) if results else \"null\","),
    ("manifest_json",
     "manifest_json=json.dumps(CHECKER_MANIFEST),",
     "manifest_json=_json_for_script(CHECKER_MANIFEST),"),
]:
    assert s.count(old) == 1, (tag, s.count(old))
    s = s.replace(old, new, 1); n += 1

ast.parse(s)
with open(AP, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(AP, encoding="utf-8").read())
print(f"OK app.py: {n} edits (helper + results_json + manifest_json escaped for <script>).")
