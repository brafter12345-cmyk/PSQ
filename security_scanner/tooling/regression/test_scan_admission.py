"""Scanner admission rejects unsafe targets before checkers and persists failure."""
import ast
import contextlib
from pathlib import Path
import socket
import sys
import types
from unittest.mock import Mock, patch
import scanner
from target_safety import UnsafeTarget


def _answer(ip):
    return (socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))


def run_checks():
    with patch('target_safety.socket.getaddrinfo',return_value=[_answer('8.8.8.8')]), patch.object(scanner.dns_cache,'clear',side_effect=RuntimeError('admitted')):
        try: scanner.SecurityScanner().scan('example.test')
        except RuntimeError as exc: assert str(exc)=='admitted'
        else: raise AssertionError('public target did not reach post-admission path')
    source=(Path(scanner.__file__).parent/'app.py').read_text(encoding='utf-8')
    tree=ast.parse(source)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_scan')
    bus=types.SimpleNamespace(publish=Mock()); failed=Mock(); updated=Mock()
    namespace={'SecurityScanner':scanner.SecurityScanner,'get_progress_bus':lambda:bus,
               '_semaphore':types.SimpleNamespace(acquire=lambda **kw:True),
               '_release_on_exit':lambda sem:contextlib.nullcontext(),
               'SCAN_QUEUE_TIMEOUT_S':1,'mark_failed':failed,'update_scan':updated}
    namespace.update({k:None for k in ('HIBP_API_KEY','DEHASHED_EMAIL','DEHASHED_API_KEY',
                                       'VIRUSTOTAL_API_KEY','SECURITYTRAILS_API_KEY','SHODAN_API_KEY','INTELX_API_KEY')})
    exec(compile(ast.Module(body=[node],type_ignores=[]),'app.py','exec'),namespace)
    for answers in ([_answer('127.0.0.1')],[_answer('8.8.8.8'),_answer('10.0.0.1')]):
        bus=types.SimpleNamespace(publish=Mock()); failed=Mock(); updated=Mock()
        namespace.update(get_progress_bus=lambda:bus,mark_failed=failed,update_scan=updated)
        obs=types.SimpleNamespace(observe_scan=lambda *a:contextlib.nullcontext())
        with patch.dict(sys.modules,{'observability':obs}), patch('target_safety.socket.getaddrinfo',return_value=answers), patch.object(scanner.HTTP,'precheck') as precheck, patch.object(scanner.dns_cache,'clear') as clear:
            namespace['run_scan']('synthetic','example.test')
        failed.assert_called_once(); updated.assert_not_called(); precheck.assert_not_called(); clear.assert_not_called()
        assert 'non-public' in failed.call_args.args[1]
        assert bus.publish.call_args.args[1]['type']=='error'
    bus=types.SimpleNamespace(publish=Mock()); failed=Mock(); updated=Mock()
    namespace.update(get_progress_bus=lambda:bus,mark_failed=failed,update_scan=updated)
    obs=types.SimpleNamespace(observe_scan=lambda *a:contextlib.nullcontext())
    with patch.dict(sys.modules,{'observability':obs}), patch('target_safety.socket.getaddrinfo',side_effect=socket.gaierror('synthetic DNS failure')), patch.object(scanner.HTTP,'precheck') as precheck:
        namespace['run_scan']('synthetic','example.test')
    failed.assert_called_once(); updated.assert_not_called(); precheck.assert_not_called()
    assert 'synthetic DNS failure' in failed.call_args.args[1]
    print('SCAN ADMISSION GREEN: public admitted; unsafe/mixed and DNS failure persist failed before probes')
