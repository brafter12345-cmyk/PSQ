# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""SANDBOX (2026-06-08) Step-7 application: wire the six supply-chain checkers into the
Attacker's View kill chain (they were priced in the model but absent from the narrative).
Phase 2 Initial Access <- vendor breach (S-5), HR third-party exposures, weak email-vendor
DMARC (S-4). Phase 3 Exploitation <- compromised/no-SRI third-party JS (S-2), vulnerable
CMS plugins (S-10), dependency-manifest CVEs (S-3). Wired into BOTH findings builders
(_assessment_kill_chain exec deck + _build_attackers_view full/broker) and the shared
_kill_chain_severities. CRLF-safe. NOT shipped by this script."""
import ast, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = os.path.join(ROOT, "pdf_report.py")
s = open(P, encoding="utf-8").read()
assert "\r" not in s
n = 0

# 1. Helper before _kill_chain_severities.
OLD = "def _kill_chain_severities(results: dict) -> dict:\n"
NEW = (
    "def _supply_chain_attacker_findings(cats: dict) -> dict:\n"
    "    \"\"\"Supply-chain findings mapped to kill-chain phases (Card-Verification Step 7).\n"
    "    Returns {'access': [...], 'exploit': [...]} - supplier-vectored entry in Initial\n"
    "    Access, exploitable third-party components in Exploitation. Same fields the\n"
    "    Supply-Chain Exposure slide uses, so the narrative and the slide never diverge.\"\"\"\n"
    "    vb = cats.get(\"vendor_breach\", {}) or {}\n"
    "    tpc = cats.get(\"third_party_correlation\", {}) or {}\n"
    "    evs = cats.get(\"email_vendor_surface\", {}) or {}\n"
    "    tpjs = cats.get(\"third_party_js\", {}) or {}\n"
    "    dm = cats.get(\"dependency_manifests\", {}) or {}\n"
    "    cms = cats.get(\"cms_plugin_sbom\", {}) or {}\n"
    "    access, exploit = [], []\n"
    "    # Phase 2 - supplier-vectored initial access\n"
    "    matches = vb.get(\"matches\") or []\n"
    "    if matches:\n"
    "        top = matches[0]; mo = max(1, (top.get(\"age_days\") or 0) // 30)\n"
    "        access.append(f\"{len(matches)} breached supplier(s) (e.g. {top.get('vendor','?')} \"\n"
    "                      f\"~{mo}mo ago) - supply-chain credential reuse, rotation often incomplete\")\n"
    "    hr_tp = tpc.get(\"hudson_rock_third_party_count\", 0)\n"
    "    if hr_tp:\n"
    "        access.append(f\"{hr_tp} third-party / vendor credential exposure(s) in infostealer \"\n"
    "                      f\"data - supply-chain backdoor\")\n"
    "    if evs.get(\"weak_dmarc\") and evs.get(\"vendor_count\", 0) >= 1:\n"
    "        access.append(f\"{evs.get('vendor_count')} email vendor(s) authorised with weak DMARC \"\n"
    "                      f\"(p={evs.get('dmarc_policy') or 'missing'}) - phishing-via-supplier\")\n"
    "    # Phase 3 - exploitable third-party components\n"
    "    comp = tpjs.get(\"compromised_host_count\", 0); miss = tpjs.get(\"missing_sri_count\", 0)\n"
    "    if comp:\n"
    "        exploit.append(f\"{comp} compromised third-party script(s) live - Magecart-style \"\n"
    "                       f\"client-side code injection\")\n"
    "    elif miss:\n"
    "        exploit.append(f\"{miss} third-party script(s) without integrity (SRI) - supply-chain \"\n"
    "                       f\"tampering risk\")\n"
    "    if cms.get(\"is_wordpress\") and cms.get(\"versioned_count\", 0) > 0:\n"
    "        exploit.append(f\"{cms.get('versioned_count')} WordPress plugin(s) with readable versions \"\n"
    "                       f\"- known plugin CVEs are a top SA SME exploit vector\")\n"
    "    crit_cves = dm.get(\"total_critical_cves\", 0); man = dm.get(\"exposed_manifests\") or []\n"
    "    if crit_cves:\n"
    "        exploit.append(f\"{crit_cves} critical CVE(s) from an exposed dependency manifest - \"\n"
    "                       f\"zero-recon exploit chaining\")\n"
    "    elif man:\n"
    "        exploit.append(f\"{len(man)} exposed dependency manifest(s) - version map enables CVE chaining\")\n"
    "    return {\"access\": access, \"exploit\": exploit}\n"
    "\n"
    "\n"
    "def _kill_chain_severities(results: dict) -> dict:\n"
)
assert s.count(OLD) == 1, ("helper anchor", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 2. Severity: Phase 2 access escalator.
OLD = (
    "    access = (\"CRITICAL\" if (rdp or infostealers > 0)\n"
    "              else \"HIGH\" if (len(hrp) > 0 or cred_leaks > 5)\n"
    "              else \"MEDIUM\" if cred_leaks > 0 else \"LOW\")\n"
)
NEW = (
    "    # Supply-chain initial-access escalators (Step 7).\n"
    "    _vb = cats.get(\"vendor_breach\", {}) or {}\n"
    "    _tpc = cats.get(\"third_party_correlation\", {}) or {}\n"
    "    _evs = cats.get(\"email_vendor_surface\", {}) or {}\n"
    "    sc_acc_crit = _vb.get(\"critical_match_count\", 0) > 0\n"
    "    sc_acc_high = _vb.get(\"high_match_count\", 0) > 0 or _tpc.get(\"hudson_rock_third_party_count\", 0) > 0\n"
    "    sc_acc_med = bool(_vb.get(\"matches\")) or (_evs.get(\"weak_dmarc\") and _evs.get(\"vendor_count\", 0) >= 1)\n"
    "    access = (\"CRITICAL\" if (rdp or infostealers > 0 or sc_acc_crit)\n"
    "              else \"HIGH\" if (len(hrp) > 0 or cred_leaks > 5 or sc_acc_high)\n"
    "              else \"MEDIUM\" if (cred_leaks > 0 or sc_acc_med) else \"LOW\")\n"
)
assert s.count(OLD) == 1, ("access severity", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 3. Severity: Phase 3 exploit escalator.
OLD = (
    "    exploit = (\"CRITICAL\" if osv_crit > 0\n"
    "               else \"HIGH\" if (osv_high > 0 or ssl_grade in (\"D\", \"E\", \"F\"))\n"
    "               else \"MEDIUM\" if hh_score < 50 else \"LOW\")\n"
)
NEW = (
    "    # Supply-chain exploitation escalators (Step 7).\n"
    "    _tpjs = cats.get(\"third_party_js\", {}) or {}\n"
    "    _dm = cats.get(\"dependency_manifests\", {}) or {}\n"
    "    _cms = cats.get(\"cms_plugin_sbom\", {}) or {}\n"
    "    sc_exp_crit = _tpjs.get(\"compromised_host_count\", 0) > 0 or _dm.get(\"total_critical_cves\", 0) > 0\n"
    "    sc_exp_high = (_cms.get(\"is_wordpress\") and _cms.get(\"versioned_count\", 0) > 0) \\\n"
    "        or _tpjs.get(\"missing_sri_count\", 0) > 0 or bool(_dm.get(\"exposed_manifests\"))\n"
    "    exploit = (\"CRITICAL\" if (osv_crit > 0 or sc_exp_crit)\n"
    "               else \"HIGH\" if (osv_high > 0 or ssl_grade in (\"D\", \"E\", \"F\") or sc_exp_high)\n"
    "               else \"MEDIUM\" if hh_score < 50 else \"LOW\")\n"
)
assert s.count(OLD) == 1, ("exploit severity", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 4. Exec deck (_assessment_kill_chain) Phase 2.
OLD = (
    "    if cred_leaks: p2f.append(f\"{cred_leaks} stolen credentials available to reuse\")\n"
    "    if cred_leaks > 0 and len(p2f) < 3: p2f.append(\"Enables automated credential stuffing\")\n"
)
NEW = (
    "    if cred_leaks: p2f.append(f\"{cred_leaks} stolen credentials available to reuse\")\n"
    "    for _scf in _supply_chain_attacker_findings(cats)[\"access\"]:  # Step 7\n"
    "        if len(p2f) < 3: p2f.append(_scf)\n"
    "    if cred_leaks > 0 and len(p2f) < 3: p2f.append(\"Enables automated credential stuffing\")\n"
)
assert s.count(OLD) == 1, ("exec p2 supply-chain", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 5. Exec deck Phase 3.
OLD = (
    "    if osv_crit: p3f.append(f\"{osv_crit} critical CVE(s) with known exploits\")\n"
    "    if hh_score < 50 and len(p3f) < 3: p3f.append(\"Exposed to XSS & clickjacking\")\n"
)
NEW = (
    "    if osv_crit: p3f.append(f\"{osv_crit} critical CVE(s) with known exploits\")\n"
    "    for _scf in _supply_chain_attacker_findings(cats)[\"exploit\"]:  # Step 7\n"
    "        if len(p3f) < 3: p3f.append(_scf)\n"
    "    if hh_score < 50 and len(p3f) < 3: p3f.append(\"Exposed to XSS & clickjacking\")\n"
)
assert s.count(OLD) == 1, ("exec p3 supply-chain", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 6. Full/broker (_build_attackers_view) Phase 2.
OLD = "    if not dmarc.get(\"present\"): access_findings.append(\"No DMARC policy — domain can be spoofed for phishing attacks against employees\")\n"
NEW = (
    "    if not dmarc.get(\"present\"): access_findings.append(\"No DMARC policy — domain can be spoofed for phishing attacks against employees\")\n"
    "    access_findings += _supply_chain_attacker_findings(cats)[\"access\"]  # Step 7\n"
)
assert s.count(OLD) == 1, ("broker p2 supply-chain", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

# 7. Full/broker Phase 3.
OLD = "    if not exploit_findings: exploit_findings.append(\"No critical exploitation vectors identified from external scan\")\n"
NEW = (
    "    exploit_findings += _supply_chain_attacker_findings(cats)[\"exploit\"]  # Step 7\n"
    "    if not exploit_findings: exploit_findings.append(\"No critical exploitation vectors identified from external scan\")\n"
)
assert s.count(OLD) == 1, ("broker p3 supply-chain", s.count(OLD))
s = s.replace(OLD, NEW, 1); n += 1

ast.parse(s)
with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
ast.parse(open(P, encoding="utf-8").read())
print(f"OK pdf_report.py: {n} edits (supply-chain wired into kill chain: helper + 2 severity + 4 findings).")
