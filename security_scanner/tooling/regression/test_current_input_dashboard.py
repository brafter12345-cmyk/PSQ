"""Offline regressions for related-domain input and dashboard risk factors.

This module is intentionally standalone: the adversarial gate can call
``run()`` once its owner wires the hook. It never imports the scanner runtime,
opens a socket, reads an environment file, or builds the static bundle.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from domain_validation import clean_related_domains


SEC = Path(__file__).resolve().parents[2]
PAGE = SEC / "templates" / "index.html"
SELECTORS = SEC / "frontend" / "src" / "data" / "selectors.ts"
PARTS = SEC / "frontend" / "src" / "components" / "detail" / "parts.tsx"
VENDOR_PANEL = SEC / "frontend" / "src" / "data" / "emailVendorPanel.ts"
TS = SEC / "frontend" / "node_modules" / "typescript"


def _node(script: str) -> object:
    env = dict(os.environ)
    env.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1",
               PYTHON_DOTENV_DISABLED="1")
    p = subprocess.run(["node", "-e", script], cwd=SEC.parent,
                       text=True, capture_output=True, env=env, check=True)
    return json.loads(p.stdout.strip().splitlines()[-1])


def _browser_clean(values: list[str]) -> list[list[str]]:
    page = PAGE.read_text(encoding="utf-8")
    normal_start = page.index("function normalizeDomainOnce")
    normal_end = page.index("const domainEl", normal_start)
    collect_start = page.index("function collectRelatedDomains")
    collect_end = page.index("// CSV upload", collect_start)
    source = page[normal_start:normal_end] + page[collect_start:collect_end]
    encoded = json.dumps(values)
    script = f"""
const source = {json.dumps(source)};
const values = {encoded};
const got = values.map(value => {{
  const document = {{querySelectorAll: () => [], getElementById: id =>
    id === 'related-domains' ? {{value}} : null}};
  return new Function('document', source + 'return collectRelatedDomains()')(document);
}});
console.log(JSON.stringify(got));
"""
    return _node(script)


def _selector_rows() -> dict[str, dict]:
    script = f"""
const fs = require('fs'), path = require('path');
const ts = require({json.dumps(str(TS))});
require.extensions['.ts'] = (mod, file) => {{
  const src = fs.readFileSync(file, 'utf8');
  const out = ts.transpileModule(src, {{compilerOptions: {{module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX}}}}).outputText;
  mod._compile(out, file);
}};
const m = require({json.dumps(str(SELECTORS))});
const c = (status, severity) => {{ const x = {{status, _severity: severity}}; return x; }};
const fixtures = {{
  no_score_critical: {{categories: {{dns_infrastructure:c('completed','critical'),
    high_risk_protocols:c('completed','positive'), shodan_vulns:c('completed','positive')}}}},
  all_unknown: {{categories: {{dns_infrastructure:c('completed','unknown'),
    high_risk_protocols:c('completed','unknown'), shodan_vulns:c('completed','unknown')}}}},
  mixed_error_stale_stamp: {{categories: {{dns_infrastructure:c('completed','critical'),
    high_risk_protocols:c('completed','positive'), shodan_vulns:c('error','critical')}}}},
}};
const out = {{}};
for (const [k, r] of Object.entries(fixtures)) out[k] = m.getRiskFactors(r).find(x => x.key === 'network');
console.log(JSON.stringify(out));
"""
    return _node(script)


def _vendor_rows() -> dict[str, dict]:
    script = f"""
const fs = require('fs'), ts = require({json.dumps(str(TS))});
require.extensions['.ts'] = (mod, file) => mod._compile(ts.transpileModule(
  fs.readFileSync(file, 'utf8'), {{compilerOptions: {{module: ts.ModuleKind.CommonJS}}}}).outputText, file);
const {{vendorPanel}} = require({json.dumps(str(VENDOR_PANEL))});
const output = {{}};
for (const state of ['not_run', 'answered', 'no_record', 'failed', 'unknown']) {{
  output[state] = vendorPanel({{status:'completed', spf_lookup:'answered',
    vendors_detected:['vendor'], weak_dmarc:true, dmarc_policy:'reject', dmarc_lookup:state}});
}}
console.log(JSON.stringify(output));
"""
    return _node(script)


def _coverage_render() -> list[dict]:
    script = f"""
const fs = require('fs'), ts = require({json.dumps(str(TS))});
const register = (mod, file) => {{
  const src = fs.readFileSync(file, 'utf8');
  mod._compile(ts.transpileModule(src, {{compilerOptions: {{module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX}}}}).outputText, file);
}};
require.extensions['.ts'] = register; require.extensions['.tsx'] = register;
require.extensions['.css'] = mod => {{ mod.exports = {{}}; }};
const React = require({json.dumps(str(SEC / "frontend" / "node_modules" / "react"))});
const render = require({json.dumps(str(SEC / "frontend" / "node_modules" / "react-dom" / "server"))}).renderToStaticMarkup;
const {{networkCoverageNotes}} = require({json.dumps(str(SELECTORS))});
const {{PartialCoverageNote}} = require({json.dumps(str(PARTS))});
const r = {{categories: {{
  dns_infrastructure: {{partial_coverage:true, incomplete_probes:{{brute_force:25, resolution:30}}}},
  high_risk_protocols: {{partial_coverage:true, unassessed_ips:[{{ip:'8.8.8.8'}}]}},
  shodan_vulns: {{partial_coverage:true, incomplete_probes:[{{probe:'lookup'}}]}},
  external_ips: {{partial_coverage:true, unassessed_ips:[{{ip:'1.1.1.1'}}]}}
}}}};
const notes = networkCoverageNotes(r).map(x => ({{label:x.label,
  html:render(React.createElement(PartialCoverageNote, x))}}));
for (const [label, incomplete_probes] of [['numeric', 25], ['unknown', {{resolution:{{}}}}]]) {{
  notes.push({{label, html:render(React.createElement(PartialCoverageNote,
    {{label, category:{{partial_coverage:true, incomplete_probes}}}}))}});
}}
console.log(JSON.stringify(notes));
"""
    return _node(script)


def run() -> None:
    assert clean_related_domains(["jane@one.test bob@two.test"]) == ["one.test", "two.test"]
    assert clean_related_domains(["Jane <jane@one.test> Bob <bob@two.test>"]) == ["one.test", "two.test"]
    assert clean_related_domains(["acme.co.za,"]) == ["acme.co.za"]
    assert clean_related_domains(["supplier.co.za jane@brokerfirm.co.za"]) == ["supplier.co.za"]
    assert clean_related_domains(["foo.ſom1 <user@broker.co.za>"]) == []
    assert clean_related_domains(["foo.com- <user@broker.co.za>"]) == []
    assert clean_related_domains(["foo.écom <user@broker.co.za>"]) == []
    assert clean_related_domains(["v2.1 <jane@supplier.co.za>"]) == ["supplier.co.za"]
    assert clean_related_domains(["Acme Group Holdings, 01.03.2026, ops@acme.co.za"]) == ["acme.co.za"]

    browser = _browser_clean([
        "jane@one.test bob@two.test", "Jane <jane@one.test> Bob <bob@two.test>",
        "acme.co.za,", "supplier.co.za jane@brokerfirm.co.za",
        "foo.ſom1 <user@broker.co.za>", "foo.com- <user@broker.co.za>",
        "foo.écom <user@broker.co.za>", "v2.1 <jane@supplier.co.za>",
    ])
    assert browser == [["one.test", "two.test"], ["one.test", "two.test"],
                       ["acme.co.za"], ["supplier.co.za"], [], [], [],
                       ["supplier.co.za"]]

    inputs = ["foo.公司 <user@broker.co.za>", "foo.ελ <user@broker.co.za>",
              "foo.𐐀𐐁 <user@broker.co.za>", "foo.𐐀 <user@broker.co.za>",
              "Accounts #2 <accounts2@acme.co.za>", "v2.1 <jane@supplier.co.za>",
              "01.03.2026 <jane@supplier.co.za>", "foo.٣m <jane@supplier.co.za>"]
    assert _browser_clean(inputs) == [clean_related_domains([value]) for value in inputs]
    assert _browser_clean(inputs) == [[], [], [], ["broker.co.za"],
                                      ["acme.co.za"], ["supplier.co.za"],
                                      ["supplier.co.za"], ["supplier.co.za"]]

    coverage = _coverage_render()
    assert [x['label'] for x in coverage] == ['DNS and ports', 'High-risk protocols', 'Shodan / InternetDB', 'numeric', 'unknown']
    assert 'DNS and ports: partial coverage' in coverage[0]['html']
    assert '2 probe groups did not complete.' in coverage[0]['html']
    assert '8.8.8.8' in coverage[1]['html']
    assert 'Shodan / InternetDB: partial coverage' in coverage[2]['html']
    assert '1 probe did not complete' in coverage[2]['html']
    assert '25 probes did not complete.' in coverage[3]['html']
    assert 'Some probes did not complete.' in coverage[4]['html']

    vendors = _vendor_rows()
    for state in ('not_run', 'answered', 'no_record', 'unknown'):
        assert [row['label'] for row in vendors[state]['rows']] == [
            'Vendors detected', 'SPF includes', 'Weak DMARC']
    assert any(row['label'] == 'DMARC policy' for row in vendors['failed']['rows'])
    failed_rows = {row['label']: row for row in vendors['failed']['rows']}
    assert failed_rows['DMARC policy']['value'] == 'Not verified'
    assert failed_rows['Weak DMARC']['value'] == 'Not verified'
    assert vendors['failed']['badge']['state'] == 'completed'
    assert vendors['answered']['badge']['state'] == 'failed'

    rows = _selector_rows()
    assert rows["no_score_critical"]["severity"] == "critical"
    assert rows["no_score_critical"]["assessed"] == 3
    assert rows["all_unknown"]["severity"] == "unknown"
    assert rows["all_unknown"]["assessed"] == 0
    assert rows["mixed_error_stale_stamp"]["assessed"] == 2
    assert rows["mixed_error_stale_stamp"]["total"] == 3
    assert rows["mixed_error_stale_stamp"]["severity"] == "critical"
    print("CURRENT_INPUT_DASHBOARD_REGRESSION PASS")


if __name__ == "__main__":
    run()
