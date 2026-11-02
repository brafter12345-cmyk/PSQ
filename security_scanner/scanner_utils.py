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

# Bound the number of still-running timeout workers process-wide. A running
# thread cannot be killed by Future.cancel(); retain its slot until it exits.
_TIMEOUT_WORKER_SLOTS = threading.BoundedSemaphore(32)
_PARTIAL_PROBE_SLOTS = threading.BoundedSemaphore(512)


def bounded_probe_results(func, jobs, *, max_workers, timeout):
    """Collect finished probe values until deadline; late jobs own slots until done.

    Jobs are (key, argument tuple). Returns (completed key/value pairs,
    incomplete count). Running work cannot be killed and may finish later.
    """
    pool = ThreadPoolExecutor(max_workers=max_workers)
    futures = {}
    incomplete = 0
    try:
        for key, args in jobs:
            if not _PARTIAL_PROBE_SLOTS.acquire(blocking=False):
                incomplete += 1
                continue
            try:
                future = pool.submit(func, *args)
            except BaseException:
                _PARTIAL_PROBE_SLOTS.release()
                raise
            future.add_done_callback(lambda _f: _PARTIAL_PROBE_SLOTS.release())
            futures[future] = key
        completed = []
        skipped = incomplete
        try:
            for future in as_completed(futures, timeout=timeout):
                try:
                    completed.append((futures[future], future.result()))
                except Exception:
                    incomplete += 1
        except FuturesTimeoutError:
            # Count values not consumed by the iterator, including jobs that
            # completed concurrently with the deadline.
            incomplete = skipped + len(futures) - len(completed)
        return completed, incomplete
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


class PartialProbeList(list):
    """List-compatible port data carrying an incomplete-probe count."""
    def __init__(self, values=(), incomplete=0):
        super().__init__(values)
        self.incomplete = incomplete


def run_with_timeout(func, args=(), kwargs=None, timeout: float = 60.0,
                      on_timeout_result=None):
    """Return at the deadline without pretending a running thread was stopped.

    A late worker can continue its own side effects and delay interpreter exit.
    At most 32 such workers may be outstanding in this process; a slot stays
    owned until the worker actually finishes. Callers must not treat a timeout
    as proof that the underlying operation was cancelled.
    """
    kwargs = kwargs or {}
    default_timeout_result = {
        "status": "timeout",
        "error": f"Checker timed out after {int(timeout)}s",
        "issues": [f"Checker did not complete within {int(timeout)}s — partial or unavailable result"],
    }
    if not _TIMEOUT_WORKER_SLOTS.acquire(blocking=False):
        return {"status": "timeout", "error": "Checker worker capacity exhausted",
                "issues": ["Checker was not started because timed-out workers are still running"]}
    try:
        ex = ThreadPoolExecutor(max_workers=1)
    except BaseException:
        _TIMEOUT_WORKER_SLOTS.release()
        raise
    try:
        future = ex.submit(func, *args, **kwargs)
    except BaseException:
        _TIMEOUT_WORKER_SLOTS.release()
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    future.add_done_callback(lambda _future: _TIMEOUT_WORKER_SLOTS.release())
    try:
        return future.result(timeout=timeout)
    except FuturesTimeoutError:
        future.cancel()
        return on_timeout_result if on_timeout_result is not None else default_timeout_result
    except Exception as e:
        return {"status": "error", "error": str(e),
                "issues": [f"Checker failed: {e}"]}
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
