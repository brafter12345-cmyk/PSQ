# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX verify (2026-06-08): reproduce the </script> breakout and confirm the fix.
Injects a banner containing </script><h1>PWNED</h1> into the results, renders
results.html the OLD way (json.dumps raw) and the NEW way (_json_for_script), and
checks whether the payload breaks out of the RESULTS <script> into the page body.
NOT shipped."""
import sys, json, re
from pathlib import Path
ROOT = Path(".").resolve(); sys.path.insert(0, str(ROOT))
from scoring_analytics import RiskScorer, RansomwareIndex, DataBreachIndex, FinancialImpactCalculator
from checkers_threats import CredentialRiskClassifier
from app import _json_for_script
from jinja2 import Environment, FileSystemLoader

PAYLOAD = "HTTP/1.1 530\r\n<html><script>window.PWNED=1</script><h1>PWNED-BODY</h1></html>"
d = json.load(open(ROOT / "test_fixtures" / "takealot_baseline.json", encoding="utf-8"))
cats = dict(d.get("categories", d))
# Inject the breakout payload into an external-IP banner (mamamoney-style).
ei = cats.setdefault("external_ips", {}); ips = ei.setdefault("ip_addresses", [])
if not ips:
    ips.append({"ip": "1.2.3.4", "services": []})
ips[0].setdefault("services", []).append({"port": 443, "banner_snippet": PAYLOAD})
cats["credential_risk"] = CredentialRiskClassifier.classify(
    dehashed=cats.get("dehashed", {}) or {}, hudson_rock=cats.get("hudson_rock", {}) or {}, intelx=cats.get("intelx", {}) or {})
sc, lv, rc = RiskScorer().calculate(cats, waf_apex_status=None); cats["_overall_score"] = sc
rsi = RansomwareIndex().calculate(cats, industry="eCommerce", annual_revenue=20_000_000_000)
fin = FinancialImpactCalculator().calculate(cats, rsi, annual_revenue=0, industry="eCommerce",
        annual_revenue_zar=20_000_000_000, sub_industry="eCommerce")
results = {"categories": cats, "overall_risk_score": sc, "risk_level": lv, "recommendations": rc,
           "domain_scanned": "mamamoney-sim", "scan_timestamp": "2026-06-08T00:00:00",
           "insurance": {"rsi": rsi, "financial_impact": fin, "dbi": DataBreachIndex().calculate(cats)}}

env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
tpl = env.get_template("results.html")

def render(results_json_str):
    return tpl.render(results=results, results_json=results_json_str,
                      manifest_json="{}", domain="mamamoney-sim", timestamp="",
                      scan_id="x", risk_score=sc, risk_level=lv)

def body_after_results_script(html):
    # Everything after the FIRST </script> that follows 'var RESULTS =' is page body.
    i = html.find("var RESULTS =")
    j = html.find("</script>", i)
    return html[j + len("</script>"):] if i >= 0 and j >= 0 else ""

old = render(json.dumps(results, default=str))             # buggy path
new = render(_json_for_script(results))                    # fixed path

print("=" * 70)
print("OLD (json.dumps raw):")
print("  PWNED-BODY leaks into page body :", "PWNED-BODY" in body_after_results_script(old))
print("NEW (_json_for_script):")
print("  PWNED-BODY leaks into page body :", "PWNED-BODY" in body_after_results_script(new))
print("  RESULTS script still parseable  :", "var RESULTS = {" in new and "<\\/script>" in new)
print("  cyber-band card still renders   :", "Relative posture bands" in new)
print("=" * 70)
ok = ("PWNED-BODY" in body_after_results_script(old)) and \
     ("PWNED-BODY" not in body_after_results_script(new)) and \
     ("Relative posture bands" in new)
print("RESULT:", "PASS - bug reproduced on OLD, contained on NEW" if ok else "*** CHECK ***")
