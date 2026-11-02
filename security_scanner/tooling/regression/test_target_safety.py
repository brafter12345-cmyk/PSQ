"""Offline transport tests: actual Requests adapter and connection boundary."""
import io
import socket
import unittest
from unittest.mock import patch

import requests
import target_safety as safety


def answer(ip, port=80):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    addr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, 6, '', addr)


class FakeSocket:
    def __init__(self, responses, calls):
        self.responses, self.calls = responses, calls
    def settimeout(self, value): pass
    def setsockopt(self, *args): pass
    def bind(self, address): pass
    def connect(self, address): self.calls.append(address)
    def sendall(self, data): pass
    def makefile(self, *args, **kwargs): return io.BytesIO(self.responses.pop(0))
    def close(self): pass
    def shutdown(self, *args): pass


class TargetSafetyTests(unittest.TestCase):
    def test_rejects_unsafe_and_mixed_before_socket(self):
        for ips in [('127.0.0.1',), ('10.0.0.1',), ('169.254.0.1',),
                    ('100.64.0.1',), ('::1',), ('8.8.8.8', '10.0.0.1')]:
            with self.subTest(ips=ips), patch.object(socket, 'getaddrinfo', return_value=[answer(ip) for ip in ips]), patch.object(socket, 'socket') as factory:
                with self.assertRaises(safety.UnsafeTarget):
                    safety.connect_public('example.com', 80)
                factory.assert_not_called()

    def test_connect_pins_resolved_sockaddr(self):
        calls = []
        with patch.object(socket, 'getaddrinfo', return_value=[answer('8.8.8.8')]) as lookup, patch.object(socket, 'socket', side_effect=lambda *a: FakeSocket([], calls)):
            safety.connect_public('example.com', 80, timeout=3)
        self.assertEqual(calls, [('8.8.8.8', 80)])
        self.assertEqual(lookup.call_count, 1)

    def test_redirect_to_private_is_blocked_at_next_connection(self):
        calls = []
        responses = [b'HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n']
        def lookup(host, port, **kwargs):
            return [answer('8.8.8.8' if host == 'example.com' else '127.0.0.1', port)]
        with patch.object(socket, 'getaddrinfo', side_effect=lookup), patch.object(socket, 'socket', side_effect=lambda *a: FakeSocket(responses, calls)):
            with self.assertRaises((safety.UnsafeTarget, requests.exceptions.ConnectionError)):
                safety.safe_request('GET', 'http://example.com/', timeout=2)
        self.assertEqual(calls, [('8.8.8.8', 80)])

    def test_rebinding_between_connections_is_blocked(self):
        calls = []
        responses = [b'HTTP/1.1 302 Found\r\nLocation: http://example.com/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n']
        with patch.object(socket, 'getaddrinfo', side_effect=[[answer('8.8.8.8')], [answer('127.0.0.1')]]), patch.object(socket, 'socket', side_effect=lambda *a: FakeSocket(responses, calls)):
            with self.assertRaises((safety.UnsafeTarget, requests.exceptions.ConnectionError)):
                safety.safe_request('GET', 'http://example.com/', timeout=2)
        self.assertEqual(calls, [('8.8.8.8', 80)])

    def test_environment_proxy_cannot_bypass_guard(self):
        with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:9999', 'ALL_PROXY': 'http://127.0.0.1:9999'}), patch.object(socket, 'getaddrinfo', return_value=[answer('127.0.0.1')]), patch.object(socket, 'socket') as factory:
            with self.assertRaises((safety.UnsafeTarget, requests.exceptions.ConnectionError)):
                safety.safe_request('GET', 'http://example.com/', timeout=2)
            factory.assert_not_called()
        with self.assertRaises(safety.UnsafeTarget):
            safety.safe_request('GET', 'http://example.com/', proxies={'http': 'http://proxy:8080'})

    def test_ssl_refusal_is_an_error_not_a_negative_finding(self):
        import checkers_core as core
        for source in ('certificate', 'versions', 'cipher', 'sslyze'):
            with self.subTest(source=source), patch.object(core, 'SSLYZE_AVAILABLE', source == 'sslyze'), patch.object(core.SSLChecker, '_check_hsts') as hsts, patch.object(core.SSLChecker, '_check_caa'):
                checker = core.SSLChecker()
                with patch.object(core, 'connect_public', side_effect=safety.UnsafeTarget('unsafe')), patch.object(core, 'resolve_public', side_effect=safety.UnsafeTarget('unsafe')):
                    with patch.object(checker, '_get_certificate_stdlib', side_effect=(safety.UnsafeTarget('unsafe') if source == 'certificate' else None), return_value={}), patch.object(checker, '_check_tls_versions_stdlib', side_effect=(safety.UnsafeTarget('unsafe') if source == 'versions' else None), return_value={}), patch.object(checker, '_get_cipher_suite_stdlib', side_effect=(safety.UnsafeTarget('unsafe') if source == 'cipher' else None), return_value={}):
                        result = checker.check('example.com')
                self.assertEqual(result['status'], 'error')
                self.assertEqual(len(result['issues']), 1)
                self.assertIn('unsafe', result['issues'][0])
                hsts.assert_not_called()
        # Exercise the actual stdlib helpers, including their exception handlers.
        checker = core.SSLChecker()
        with patch.object(core, 'SSLYZE_AVAILABLE', False), patch.object(core, 'connect_public', side_effect=safety.UnsafeTarget('unsafe')):
            result = checker.check('example.com')
            self.assertEqual(result['status'], 'error')
            self.assertEqual(len(result['issues']), 1)
            self.assertIn('unsafe', result['issues'][0])
        with patch.object(core, 'connect_public', side_effect=safety.UnsafeTarget('unsafe')):
            for fn in (checker._get_certificate_stdlib, checker._check_tls_versions_stdlib, checker._get_cipher_suite_stdlib):
                with self.assertRaises(safety.UnsafeTarget):
                    fn('example.com')

    def test_https_preserves_hostname_and_pins_address(self):
        import urllib3.connection as connection
        calls, sni = [], []
        responses = [b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK']
        def wrap(*args, **kwargs):
            sni.append(kwargs.get('server_hostname'))
            return connection._WrappedAndVerifiedSocket(kwargs['sock'], True)
        with patch.object(socket, 'getaddrinfo', return_value=[answer('8.8.8.8', 443)]), patch.object(socket, 'socket', side_effect=lambda *a: FakeSocket(responses, calls)), patch.object(connection, '_ssl_wrap_socket_and_match_hostname', side_effect=wrap):
            response = safety.safe_request('GET', 'https://example.com/', timeout=2)
        self.assertEqual(response.text, 'OK')
        self.assertEqual(calls, [('8.8.8.8', 443)])
        self.assertEqual(sni, ['example.com'])


def run_checks():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TargetSafetyTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise AssertionError('target safety regression failed')


if __name__ == '__main__':
    unittest.main()
