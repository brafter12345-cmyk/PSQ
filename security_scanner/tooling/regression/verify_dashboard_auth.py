"""Offline dashboard authentication transport behavior; no app import or DB."""
import ast
import html
from pathlib import Path
import re
import subprocess
import sys

from flask import Flask, abort, render_template

SEC = Path(__file__).resolve().parents[2]


def run_checks():
    tree = ast.parse((SEC / 'app.py').read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'view_results')
    node.decorator_list = []
    ns = {'fetch_scan': lambda _: {'status': 'pending', 'results': None, 'domain': 'example.invalid'},
          'abort': abort, 'render_template': render_template, 'SCANNER_API_KEY': 'synthetic"<&key',
          'CHECKER_MANIFEST': [], '_json_for_script': lambda obj: '[]'}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SEC / 'app.py'), 'exec'), ns)
    app = Flask(__name__, template_folder=str(SEC / 'templates'))
    with app.test_request_context('/results/example', environ_overrides={'SCRIPT_NAME': '/scanner'}):
        rendered = ns['view_results']('example')
    match = re.search(r'<meta name="scanner-api-key" content="([^"]*)">', rendered)
    assert match and html.unescape(match.group(1)) == ns['SCANNER_API_KEY']
    assert '&lt;' in match.group(1) and '&amp;' in match.group(1)
    assert '/scanner/static/dashboard/app.js' in rendered
    ns['SCANNER_API_KEY'] = ''
    with app.test_request_context('/results/example'):
        assert '<meta name="scanner-api-key" content="">' in ns['view_results']('example')
    run = subprocess.run(['node', str(Path(__file__).with_name('auth_transport.cjs'))],
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, 'node auth transport regression failed: ' + run.stdout + run.stderr
    print('AUTH TRANSPORT GREEN')


if __name__ == '__main__':
    sys.path.insert(0, str(SEC))
    run_checks()
