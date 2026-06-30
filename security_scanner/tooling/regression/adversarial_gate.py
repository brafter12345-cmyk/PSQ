# -*- coding: utf-8 -*-
"""Adversarial ground-truth gate for the network/port checkers (BLOCKING).

The golden-replay and cassette harnesses prove *stability* (output == baseline)
and HTTP-replay fidelity. Neither tests *plausibility* against adversarial
inputs, and neither covers the raw-socket port scan. This gate does: it drives
the real checker code with socket-level mocks for known adversarial cases and
asserts the CORRECT classification — the thing a human analyst would assert on
sight, encoded once so it runs on every change with no human in the loop.

Each scenario is a labelled ground truth:
  - tarpit            : SYN-ACKs every port, no banners  -> ALL findings dropped
  - real_mail_host    : 21/110/143 w/ banners, TLS ports -> kept, banner-confirmed
  - cdn_edge          : 80/443, cloudflare 403 on 80     -> kept
  - real_exposed_db   : MongoDB 27017 genuinely open      -> REPORTED (no over-drop)

Run: py tooling/regression/adversarial_gate.py   (exit 1 on any mismatch)
This file is wired into the pre-push hook so the tarpit false-positive — and any
regression of the saturated-host gate — can never ship again.
"""
import os, sys, socket
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SEC)

import checkers_network as cn


class _FakeSocket:
    """Per-probe fake. `open` is a set of open ports or the string "ALL"."""
    def __init__(self, scenario):
        self._sc = scenario
        self._port = None

    def settimeout(self, _):
        pass

    def connect_ex(self, addr):
        self._port = addr[1]
        openset = self._sc["open"]
        is_open = (openset == "ALL") or (self._port in openset)
        return 0 if is_open else 111  # 111 = ECONNREFUSED (closed)

    def sendall(self, _):
        pass

    def recv(self, _):
        return self._sc["banners"].get(self._port, b"")

    def close(self):
        pass


def _run(scenario):
    """Run both network checkers against a mocked host; return (scan, hrp)."""
    cn._saturated_host_cache.clear()
    factory = lambda *a, **k: _FakeSocket(scenario)
    with mock.patch.object(cn.socket, "socket", factory):
        scan = cn.DNSInfrastructureChecker()._scan_ports("target.example", scenario["ip"])
        hrp = cn.HighRiskProtocolChecker().check("target.example", scenario["ip"])
    return scan, hrp


# ---- ground-truth scenarios -------------------------------------------------
SCENARIOS = {
    "tarpit": {
        "ip": "10.9.9.1", "open": "ALL", "banners": {},
        "expect_scan_ports": set(),          # everything discarded
        "expect_hrp_ports": set(),
    },
    "real_mail_host": {
        "ip": "10.9.9.2", "open": {21, 110, 143, 443, 993, 995},
        "banners": {21: b"220 Pure-FTPd", 110: b"+OK Dovecot ready",
                    143: b"* OK Dovecot ready"},
        "expect_scan_ports": {21, 110, 143, 443, 993, 995},
        "expect_hrp_ports": set(),            # no CRITICAL_SERVICES port open
        "expect_confirmed": {21: True, 443: False},
    },
    "cdn_edge": {
        "ip": "10.9.9.3", "open": {80, 443},
        "banners": {80: b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare"},
        "expect_scan_ports": {80, 443},
        "expect_hrp_ports": set(),
    },
    "real_exposed_db": {                      # TRUE positive — must NOT be dropped
        "ip": "10.9.9.4", "open": {443, 27017},
        "banners": {},
        "expect_scan_ports": {443},           # 27017 not in port-scan ALL_PORTS
        "expect_hrp_ports": {27017},          # but IS a CRITICAL_SERVICE -> reported
    },
}


def main():
    failures = []
    for name, sc in SCENARIOS.items():
        scan, hrp = _run(sc)
        scan_ports = {e["port"] for e in scan}
        hrp_ports = {e["port"] for e in hrp.get("exposed_services", [])}
        ok = True
        if scan_ports != sc["expect_scan_ports"]:
            failures.append(f"{name}: scan ports {sorted(scan_ports)} != expected {sorted(sc['expect_scan_ports'])}")
            ok = False
        if hrp_ports != sc["expect_hrp_ports"]:
            failures.append(f"{name}: high-risk ports {sorted(hrp_ports)} != expected {sorted(sc['expect_hrp_ports'])}")
            ok = False
        for port, want in sc.get("expect_confirmed", {}).items():
            got = next((e.get("confirmed") for e in scan if e["port"] == port), None)
            if got != want:
                failures.append(f"{name}: port {port} confirmed={got} != expected {want}")
                ok = False
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<18} scan={sorted(scan_ports)} high-risk={sorted(hrp_ports)}")

    print("=" * 70)
    if failures:
        print(f"ADVERSARIAL GATE FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print(f"ADVERSARIAL GATE PASS — {len(SCENARIOS)} ground-truth scenarios")


if __name__ == "__main__":
    main()
