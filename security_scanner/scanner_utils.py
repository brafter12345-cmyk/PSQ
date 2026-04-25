"""
Shared imports, feature flags, and constants for the security scanner modules.
"""

import ssl
import socket
import json
import re
import time
import threading
from datetime import datetime, timezone
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from sslyze import Scanner as SSLyzeScanner, ServerScanRequest, ScanCommand
    from sslyze.server_setting import ServerNetworkLocation
    from sslyze.errors import ServerHostnameCouldNotBeResolved
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False

DEFAULT_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 CyberInsuranceScanner/1.0 (passive assessment)"


# ---------------------------------------------------------------------------
# Shared DNS cache — single resolution pass per (domain, record-type) per scan.
# Prevents duplicate lookups across checkers (A records alone were being
# resolved 5+ times per scan: discover_ips, cloud_cdn, socket.gethostbyname
# fallbacks in DNS/DNSBL/HRP/Shodan per-IP callers, etc.).
# ---------------------------------------------------------------------------

class _DNSCache:
    """Process-wide DNS cache shared by all checkers during a scan."""
    def __init__(self):
        self._records = {}
        self._ips = {}
        self._lock = threading.Lock()

    def clear(self):
        with self._lock:
            self._records.clear()
            self._ips.clear()

    def resolve(self, domain: str, rtype: str, lifetime: float = DEFAULT_TIMEOUT):
        """Cached dns.resolver.resolve() — returns list of string answers.
        Empty list means 'tried and got nothing' (still cached to avoid re-try)."""
        key = (domain.lower(), rtype.upper())
        with self._lock:
            if key in self._records:
                return self._records[key]
        answers = []
        if DNS_AVAILABLE:
            try:
                rr = dns.resolver.resolve(domain, rtype, lifetime=lifetime)
                answers = [str(r) for r in rr]
            except Exception:
                answers = []
        with self._lock:
            self._records[key] = answers
        return answers

    def seed_records(self, domain: str, rtype: str, values: list):
        """Seed cache with pre-resolved records (e.g. from scanner.discover_ips)."""
        key = (domain.lower(), rtype.upper())
        with self._lock:
            self._records[key] = list(values or [])

    def get_ip(self, domain: str) -> Optional[str]:
        """Return first A record for domain (or socket.gethostbyname fallback).
        Used to replace repeated socket.gethostbyname(domain) calls in per-domain checkers."""
        key = domain.lower()
        with self._lock:
            if key in self._ips:
                return self._ips[key]
        ip = None
        a_records = self.resolve(domain, "A")
        if a_records:
            ip = a_records[0]
        if not ip:
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = None
        with self._lock:
            self._ips[key] = ip
        return ip


# Module-level singleton — any checker imports it via `from scanner_utils import *`
dns_cache = _DNSCache()


def run_with_timeout(func, args=(), kwargs=None, timeout: float = 60.0,
                      on_timeout_result=None):
    """Execute `func(*args, **kwargs)` in a worker thread with a hard wall-clock
    timeout. If the task doesn't finish in time, returns `on_timeout_result`
    (or an error dict). The thread is allowed to orphan — acceptable for
    network probes because the scan still returns on time.

    Use for slow, timeout-unsafe checkers such as sslyze (which spawns
    subprocesses) and SubdomainChecker (which depends on crt.sh latency).
    """
    kwargs = kwargs or {}
    default_timeout_result = {
        "status": "timeout",
        "error": f"Checker timed out after {int(timeout)}s",
        "issues": [f"Checker did not complete within {int(timeout)}s — partial or unavailable result"],
    }
    with ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except FuturesTimeoutError:
            future.cancel()
            return on_timeout_result if on_timeout_result is not None else default_timeout_result
        except Exception as e:
            return {"status": "error", "error": str(e),
                    "issues": [f"Checker failed: {e}"]}
