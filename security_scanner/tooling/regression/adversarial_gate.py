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
import io
import os, sys, socket
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, SEC)
sys.path.insert(0, os.path.join(SEC, "tooling"))   # breach_web_discovery (SCN-040)

import checkers_network as cn
import checkers_threats as ct
import ip_classification as ipc
import scanner as sc


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

    def getpeername(self):
        return (self._sc.get("ip", "8.8.8.8"), 3389)


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
        "ip": "8.8.8.8", "open": "ALL", "banners": {},
        "expect_scan_ports": set(),          # everything discarded
        "expect_hrp_ports": set(),
    },
    "real_mail_host": {
        "ip": "8.8.8.9", "open": {21, 110, 143, 443, 993, 995},
        "banners": {21: b"220 Pure-FTPd", 110: b"+OK Dovecot ready",
                    143: b"* OK Dovecot ready"},
        "expect_scan_ports": {21, 110, 143, 443, 993, 995},
        "expect_hrp_ports": set(),            # no CRITICAL_SERVICES port open
        "expect_confirmed": {21: True, 443: False},
    },
    "cdn_edge": {
        "ip": "8.8.8.10", "open": {80, 443},
        "banners": {80: b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare"},
        "expect_scan_ports": {80, 443},
        "expect_hrp_ports": set(),
    },
    "real_exposed_db": {                      # TRUE positive — must NOT be dropped
        "ip": "8.8.8.11", "open": {443, 27017},
        "banners": {},
        "expect_scan_ports": {443},           # 27017 not in port-scan ALL_PORTS
        "expect_hrp_ports": {27017},          # but IS a CRITICAL_SERVICE -> reported
    },
}


# ---- IP-attribution ground truth (real takealot.com hosts, 2026-06-30) -------
# (label, ip, reverse_dns, org, banner) -> expected ip_classification bucket.
# Encodes the own-vs-vendor judgment that keeps third-party infrastructure (a
# HostRocket shared host's FTP / "exposed Jupyter", CDN edges, managed LBs) out
# of the insured's OWN attack surface, while still scanning the insured's own
# IaaS VMs (an exposed Jenkins/Elasticsearch on their EC2/GCE is THEIR risk).
# Without this gate the subdomain-IP path attributes 41 third-party hosts to the
# target as its own exposure (the bug this audit found).
# 7th element is ptr_confirmed: whether the reverse name resolves FORWARD back
# to this address. A vendor reverse suffix may demote ONLY when it does, because
# the reverse record is written by whoever holds the address and is therefore an
# assertion by the party being judged. Most rows below do not need it: they are
# decided by Shodan org, a server banner or a published address range. Measured
# on the 30 retained scans, ZERO addresses demoted on a reverse name alone, so
# this closes the gaming vector at no cost to coverage.
CLASSIFY_SCENARIOS = [
    # --- vendor-operated -> third-party (NOT scanned/attributed as own) ---
    ("hostrocket_sharedhost", "66.147.238.15", "dirapp84.directorysecure.com",
     "HostRocket Web Services", "220 Pure-FTPd", ipc.SAAS, True),
    ("cloudfront_edge", "143.204.4.4", "server-143-204-4-4.jnb51.r.cloudfront.net",
     None, "CloudFront", ipc.CDN, True),
    ("akamai_edge", "23.196.227.231", "a23-196-227-231.deploy.static.akamaitechnologies.com",
     None, "AkamaiGHost", ipc.CDN, True),
    ("cloudflare_no_ptr", "104.16.71.64", None, None,
     "HTTP/1.1 403 Forbidden\r\nServer: cloudflare", ipc.CDN, None),
    # The ONLY original row whose verdict rests on the reverse name alone, so
    # it is the one that proves the gate is exercising the confirmation.
    ("salesforce_exacttarget", "13.111.150.233", "ja233.mta.exacttarget.com",
     None, None, ipc.SAAS, True),
    # THE GAMING CASE. Identical inputs, confirmation absent: the host must
    # STAY in the priced estate. An insured who can write their own reverse
    # record must not be able to drop their exposed box out of scoring.
    ("forged_ptr_unconfirmed", "13.111.150.233", "ja233.mta.exacttarget.com",
     None, None, ipc.OWNED, None),
    # And a reverse name that definitely does NOT forward-confirm.
    # NOT a TEST-NET address: 203.0.113.0/24 is reserved and ipaddress marks it
    # private, so the row would have proved nothing about the reverse-name rule.
    ("forged_ptr_refuted", "102.219.50.41", "something.wpengine.com",
     None, None, ipc.OWNED, False),
    ("zendesk_org_only", "216.198.54.99", None, "Zendesk, Inc.", "", ipc.SAAS, None),
    ("aws_elb_managed", "108.132.68.82", "ec2-108-132-68-82.eu-west-1.compute.amazonaws.com",
     None, "awselb/2.0", ipc.CDN, True),   # ec2-style PTR but managed LB banner -> NOT owned
    # --- insured-operated -> OWNED (scanned + attributed as the insured's) ---
    ("aws_ec2_vm", "3.92.120.28", "ec2-3-92-120-28.compute-1.amazonaws.com",
     "Amazon Data Services", "", ipc.OWNED, True),
    ("gce_vm", "104.199.105.60", "60.105.199.104.bc.googleusercontent.com",
     None, "", ipc.OWNED, True),
    ("insured_dc_no_signal", "102.219.50.40", None, None, "", ipc.OWNED, None),
    # --- private (internal host leaked in public DNS) -> never scanned ---
    ("rfc1918_fortiauth", "10.0.1.250", None, None, None, ipc.PRIVATE, None),
    ("rfc1918_elasticsearch", "10.28.32.100", None, None, None, ipc.PRIVATE, None),
]


def _check_classification(failures):
    for label, ip, rdns, org, banner, expected, ptr_ok in CLASSIFY_SCENARIOS:
        got, _provider = ipc.classify_ip(ip, reverse_dns=rdns, org=org,
                                         banner=banner, ptr_confirmed=ptr_ok)
        ok = (got == expected)
        if not ok:
            failures.append(f"classify[{label}]: {ip} -> {got!r} != expected {expected!r}")
        print(f"  [{'PASS' if ok else 'FAIL'}] classify:{label:<24} -> {got}")

    # NON-VACUITY. At least one row's verdict must CHANGE when the forward
    # confirmation is withheld, or the whole dimension is decorative and a
    # regression that dropped the check would pass unnoticed.
    swung = [label for label, ip, rdns, org, banner, expected, ptr_ok
             in CLASSIFY_SCENARIOS
             if ptr_ok is True
             and ipc.classify_ip(ip, reverse_dns=rdns, org=org, banner=banner,
                                 ptr_confirmed=None)[0] != expected]
    if not swung:
        failures.append(
            "classify: no scenario depends on ptr_confirmed, so the "
            "forward-confirmation guard is untested. Add a row whose verdict "
            "rests on the reverse name alone.")
    print("  [%s] classify:ptr_confirmation_is_load_bearing (%d row(s) swing)"
          % ("PASS" if swung else "FAIL", len(swung)))


# ---- CVE<->software matching ground truth (checker audit, 2026-07-01) ---------
# (label, port, detected_version, cves_kept?, confidence), driven through the REAL
# DNSInfrastructureChecker._assess_risk. Port-template CVEs must DROP when the
# banner names a different product (Pure-FTPd must not carry ProFTPD CVEs; a
# Postfix host must not carry Exim CVEs), and be KEPT + flagged version-unconfirmed
# when the software matches or can't be fingerprinted. Also guards the two data
# errors this audit removed (Sudo CVE-2021-3156 on :25, Postfix CVE-2011-1720 on :110).
CVE_GATE_SCENARIOS = [
    ("ftp_pure_ftpd_drops_proftpd", 21,  "Pure-FTPd 1.0.47",     False, "software_mismatch"),
    ("ftp_proftpd_keeps",           21,  "ProFTPD 1.3.5 Server", True,  "software_match"),
    ("ftp_no_banner_keeps",         21,  "",                     True,  "port_inferred"),
    ("ssh_openssh_keeps",           22,  "OpenSSH_8.9p1 Ubuntu", True,  "software_match"),
    ("ssh_dropbear_drops",          22,  "Dropbear sshd",        False, "software_mismatch"),
    ("smtp_postfix_drops_exim",     25,  "mail ESMTP Postfix",   False, "software_mismatch"),
    ("smtp_exim_keeps",             25,  "mail ESMTP Exim 4.94", True,  "software_match"),
    ("pop3_dovecot_keeps",          110, "Dovecot ready.",       True,  "software_match"),
]


def _check_cve_gating(failures):
    for label, port, ver, kept, conf in CVE_GATE_SCENARIOS:
        p = {"port": port, "service": "x", "risk": "high"}
        if ver:
            p["detected_version"] = ver
        cn.DNSInfrastructureChecker()._assess_risk([p])
        has_cves = bool(p.get("notable_cves"))
        ok = (has_cves == kept) and (p.get("cve_confidence") == conf)
        if not ok:
            failures.append(f"cve_gate[{label}]: kept={has_cves}!={kept} "
                            f"conf={p.get('cve_confidence')!r}!={conf!r}")
        print(f"  [{'PASS' if ok else 'FAIL'}] cve_gate:{label:<28} kept={has_cves} conf={p.get('cve_confidence')}")
    # Data-error guards — the wrong-software/wrong-protocol CVEs must stay removed.
    PI = cn.DNSInfrastructureChecker.PORT_INTEL
    for label, port, bad in (("sudo_off_smtp_25", 25, "CVE-2021-3156"),
                             ("postfix_off_pop3_110", 110, "CVE-2011-1720")):
        gone = bad not in PI[port]["notable_cves"]
        if not gone:
            failures.append(f"cve_gate[{label}]: {bad} still in PORT_INTEL[{port}]")
        print(f"  [{'PASS' if gone else 'FAIL'}] cve_gate:{label:<28} {bad} removed")


# ---- TechStack EOL: header-authoritative, no body-substring FP (2026-07-01) ----
# EOL server-component version tokens (PHP/nginx/Apache/IIS/Tomcat/Node/Python/
# OpenSSL) must be matched against the response HEADERS only. The page BODY was
# previously included, so any incidental mention of an old version — a hosting
# page listing supported PHP versions, a `docs.python.org/2.7` link, an embedded
# code sample — invented a phantom EOL finding (up to a -40 CRITICAL) for software
# the target never runs. Drives the REAL TechStackChecker.check() with a mocked
# HTTP response.
class _FakeResp:
    def __init__(self, headers, body, status=200):
        self.headers = headers
        self.text = body
        self.status_code = status


TECHSTACK_EOL_SCENARIOS = [
    # label, response headers, response body, expected eol `software` set
    ("eol_in_server_header", {"Server": "nginx/1.14"}, "<html>clean</html>", {"nginx/1.14"}),
    ("eol_in_xpoweredby", {"X-Powered-By": "PHP/7.2"}, "<html>clean</html>", {"PHP/7.2"}),
    ("eol_only_in_body_ignored", {"Server": "cloudflare"},
     "<html>We support php/7.2, php/7.4 and php/8.1 - see docs.python.org/2.7</html>", set()),
    ("supported_version_not_flagged", {"Server": "nginx/1.27"}, "<html>clean</html>", set()),
]


def _check_techstack_eol(failures):
    for label, headers, body, expect in TECHSTACK_EOL_SCENARIOS:
        resp = _FakeResp(headers, body)
        with mock.patch.object(ct.HTTP, "get", lambda *a, **k: resp):
            r = ct.TechStackChecker().check("target.example")
        got = {e["software"] for e in r.get("eol_detected", [])}
        ok = (got == expect)
        if not ok:
            failures.append(f"techstack_eol[{label}]: {sorted(got)} != expected {sorted(expect)}")
        print(f"  [{'PASS' if ok else 'FAIL'}] techstack_eol:{label:<28} eol={sorted(got)}")


# ---- VPN apex RDP probe: tarpit-gated (2026-07-02) ----
# VPNRemoteAccessChecker probes 3389 on the apex with a raw socket. A saturated
# host (tarpit / IPS / LB that SYN-ACKs every port) makes that connect() succeed
# and would fabricate "RDP exposed" -- the single largest RSI signal (+0.20) plus
# a 40-pt vpn_risk hit. The probe must gate on is_saturated_host like the port
# scanner does. Drives the REAL VPNRemoteAccessChecker.check() with a mocked
# socket (fake connect_ex) + resolver + HTTP so no packet leaves the box.
VPN_RDP_SCENARIOS = [
    # label, open ports (or "ALL"), expected rdp_exposed
    ("tarpit_apex_suppressed", "ALL", False),  # 3389 + canaries answer -> tarpit -> suppressed
    ("real_rdp_flagged", {3389}, True),         # 3389 open, canaries closed -> real exposure kept
    ("no_rdp", {443}, False),                    # 3389 closed -> not exposed
]


def _check_vpn_rdp_tarpit(failures):
    for label, openset, expect in VPN_RDP_SCENARIOS:
        cn._saturated_host_cache.clear()
        scenario = {"open": openset, "banners": {}, "ip": "8.8.8.8"}
        sock_factory = lambda *a, **k: _FakeSocket(scenario)
        def fake_connect(_host, _port, **_kwargs):
            if openset == "ALL" or 3389 in openset:
                return sock_factory()
            raise ConnectionRefusedError("synthetic closed port")
        with mock.patch.object(cn.socket, "socket", sock_factory), \
             mock.patch.object(cn, "connect_public", fake_connect), \
             mock.patch.object(cn.HTTP, "get", lambda *a, **k: None), \
             mock.patch.object(cn.HTTP, "stop_probing", lambda *a, **k: False):
            r = cn.VPNRemoteAccessChecker().check("target.example")
        got = bool(r.get("rdp_exposed"))
        ok = (got == expect)
        if not ok:
            failures.append(f"vpn_rdp[{label}]: rdp_exposed={got} != expected {expect}")
        print(f"  [{'PASS' if ok else 'FAIL'}] vpn_rdp:{label:<28} rdp_exposed={got}")


# ---- Dehashed corporate/staff attribution: boundary-match not substring (2026-07-02) ----
# DehashedChecker classifies corporate-vs-personal and builds the masked staff list
# by mailbox domain. The old `domain in email` substring counted lookalike / adjacent
# domains (evil-takealot.com, takealot.company.co.za -- both CONTAIN "takealot.com")
# as the insured's OWN staff, inflating the staff-account attribution shown to the
# broker (reporting-only; the score uses Dehashed's server-side `total`). Drives the
# REAL check() with a mocked Dehashed v2 API response.
class _FakeDehashedResp:
    def __init__(self, entries):
        self.status_code = 200
        self._entries = entries

    def json(self):
        return {"entries": self._entries, "total": len(self._entries)}


DEHASHED_ATTR_ENTRIES = [
    {"email": ["ceo@takealot.com"]},            # on-domain       -> staff
    {"email": ["it@mail.takealot.com"]},         # subdomain       -> staff
    {"email": ["victim@evil-takealot.com"]},     # lookalike       -> NOT staff
    {"email": ["user@takealot.company.co.za"]},  # adjacent domain -> NOT staff
    {"email": ["someone@gmail.com"]},            # personal        -> NOT staff
]


def _check_dehashed_attribution(failures):
    resp = _FakeDehashedResp(DEHASHED_ATTR_ENTRIES)
    with mock.patch.object(ct.DEHASHED, "post", lambda *a, **k: resp):
        r = ct.DehashedChecker().check("takealot.com", api_key="gate-test-key")
    staff = int(r.get("staff_accounts_total", -1))
    corp = int((r.get("credential_breakdown") or {}).get("corporate_count", -1))
    ok = (staff == 2 and corp == 2)
    if not ok:
        failures.append(f"dehashed_attr: staff={staff} corporate={corp} != 2/2 "
                        "(lookalike/adjacent domains must not count as own-staff)")
    print(f"  [{'PASS' if ok else 'FAIL'}] dehashed_attr: staff={staff} corporate={corp} (expect 2/2)")


# ---- credential_correlation REPORTING card: staff vs customer-only tier (2026-07-02) ----
# LABEL NOTE: this tests build_credential_correlation, the REPORTING-ONLY cross-
# correlation join (no scoring weight). It does NOT test the RSI. The RSI-driving
# credential tier (CredentialRiskClassifier.classify) separately + already floors
# customer-only (hr_users) to HIGH and staff (hr_employees) to CRITICAL. This gate
# just locks the reporting card to the SAME staff-vs-customer distinction: staff-fresh
# CRITICAL (breached) / HIGH (alone); customer-ONLY-fresh capped one tier lower, HIGH
# (breached) / MEDIUM (alone). Pure function -- synthetic cat_results, no mocks.
def _cc_fixture(emp, usr, days, de_total):
    return {
        "hudson_rock": {"status": "completed", "compromised_employees": emp,
                        "compromised_users": usr, "days_since_compromise": days},
        "dehashed": {"total_entries": de_total},
    }


CRED_CALIB_SCENARIOS = [
    # label, employees, users, days_since, dehashed_total, expected severity
    ("staff_fresh_breached", 2, 0, 10, 100, "critical"),
    ("staff_fresh_alone", 2, 0, 10, 0, "high"),
    ("customer_only_fresh_breached", 0, 5000, 10, 100, "high"),   # was CRITICAL pre-calib
    ("customer_only_fresh_alone", 0, 5000, 10, 0, "medium"),      # was HIGH pre-calib
]


def _check_cred_calibration(failures):
    for label, emp, usr, days, det, expect in CRED_CALIB_SCENARIOS:
        out = sc.build_credential_correlation(_cc_fixture(emp, usr, days, det))
        got = out.get("severity")
        ok = (got == expect)
        if not ok:
            failures.append(f"cred_calib[{label}]: severity={got} != expected {expect}")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_calib:{label:<30} severity={got}")


# ---- Subdomain CT union: crt.sh + certspotter fallback + low-coverage flag (#7, 2026-07-02) ----
# crt.sh is flaky; a single failure used to drop enumeration to brute-only (~16 vs
# ~90 subdomains -- the #7 non-determinism that made scan-to-scan deltas meaningless).
# Now crt.sh + certspotter are queried in parallel and UNIONed; `low_coverage` flags
# the scan ONLY when BOTH CT sources fail. Drives the REAL SubdomainChecker.check()
# with the two CT helpers + the DNS-dependent methods mocked (no packet leaves the box).
SUBDOMAIN_CT_SCENARIOS = [
    # label, crtsh names, certspotter names, (ct_count, ct_source_ok, low_coverage, sources)
    ("both_ct_sources", {"a.x.com", "b.x.com"}, {"b.x.com", "c.x.com"}, 3, True, False, ["certspotter", "crtsh"]),
    ("crtsh_flaked", set(), {"b.x.com", "c.x.com"}, 2, True, False, ["certspotter"]),
    ("certspotter_flaked", {"a.x.com"}, set(), 1, True, False, ["crtsh"]),
    ("both_ct_failed", set(), set(), 0, False, True, []),
]


def _check_subdomain_ct(failures):
    for label, crt, cs, exp_ct, exp_ok, exp_low, exp_src in SUBDOMAIN_CT_SCENARIOS:
        with mock.patch.object(cn.SubdomainChecker, "_ct_crtsh", staticmethod(lambda d, _r=frozenset(crt): set(_r))), \
             mock.patch.object(cn.SubdomainChecker, "_ct_certspotter", staticmethod(lambda d, _r=frozenset(cs): set(_r))), \
             mock.patch.object(cn.SubdomainChecker, "_wildcard_ips", lambda self, d: set()), \
             mock.patch.object(cn.SubdomainChecker, "_resolves", lambda self, h: None), \
             mock.patch.object(cn.SubdomainChecker, "_check_cname_takeover", lambda self, s: None):
            r = cn.SubdomainChecker().check("x.com")
        got = (r.get("ct_count"), r.get("ct_source_ok"), r.get("low_coverage"),
               sorted(r.get("ct_sources") or []))
        want = (exp_ct, exp_ok, exp_low, sorted(exp_src))
        ok = got == want
        if not ok:
            failures.append(f"subdomain_ct[{label}]: {got} != {want}")
        print(f"  [{'PASS' if ok else 'FAIL'}] subdomain_ct:{label:<22} "
              f"ct={got[0]} ok={got[1]} low={got[2]} src={got[3]}")


# ---- Breach-intel: company matching + fail-safe + recency ladder (SCN-040/041) ----
# Three distinct failure modes, all observed live on the 2026-07-27 mip.co.za scan
# or designed against it:
#
#  (a) COMPANY MATCHING. title_is_about() used a substring test, so the 3-letter
#      token "mip" matched nine unrelated ransomware victims (bMIProjects.de,
#      ekonoMIPoolen.se, MIPa.com.br, luMIPlan.com, MIPS Technologies, MIPe.com,
#      euroMIP.fr). That mattered because a leak-site listing FLOORS the verdict at
#      "confirmed" -- a short company token could have asserted a breach at a
#      company that was never breached. Same class as the Dehashed attribution bug.
#  (b) FAIL-SAFE SCORING. The search engine degrades SILENTLY to snippets when its
#      key is missing/rotated/unfunded. An unresearched scan must therefore never
#      score as clean: researched_breach_risk() must return None for every
#      non-conclusive state so the HIBP value is kept rather than a falsely low one.
#  (c) RECENCY LADDER. Owner calibration: recency drives impact, not count, and the
#      first year is cut into quarters because the post-breach recovery window is
#      itself the elevated-risk period.
BREACH_FP_VICTIMS = [           # live ransomware.live rows for keyword "mip"
    "bmiprojects.de", "ekonomipoolen.se/Sweden/32/GB", "Ekonomipoolen",
    "mipa.com.br", "lumiplan.com", "MIPS Technologies", "mipe.com", "euromip.fr",
]
BREACH_TRUE_MATCHES = [
    ("MIP Holdings", "Mip"), ("mip.co.za", "Mip"), ("BELFOR", "BELFOR"),
    ("Takealot Fulfilment Solutions employee blunder leads to leak", "Takealot"),
    ("Dis-Chem data breach affects 3.68 million customers", "Dis-Chem"),
]
BREACH_TRUE_NEGATIVES = [
    ("Naspers reports jump in ecommerce profit", "Takealot"),
    ("Chemical spill at DisChemicals plant", "Dis-Chem"),
]
# (months_since, verdict) -> expected category risk, expected RSI impact
BREACH_LADDER = [
    (1,    "confirmed", 90.0, 0.16),   # inside the recovery window
    (4,    "confirmed", 90.0, 0.14),
    (7,    "confirmed", 90.0, 0.12),
    (11,   "confirmed", 90.0, 0.10),
    (18,   "confirmed", 70.0, 0.06),
    (30,   "confirmed", 45.0, 0.03),
    (48,   "confirmed", 25.0, 0.00),   # RSI factor has decayed out
    (80,   "confirmed", 10.0, 0.00),
    (1,    "reported",  63.0, 0.112),  # single-source -> x0.70 on both channels
    (None, "confirmed", 50.0, 0.04),   # confirmed but undated
]
BREACH_FAILSAFE = [             # every one must contribute NOTHING
    ("no_api_key", "unknown"), ("error", "unknown"),
    ("completed", "none"), ("completed", "possible"),
]
# Mid-scan key failure: the key is probed BEFORE the research, so it can die
# during it (revoked, rotated, or -- as happened in production -- the AI Studio
# credits running out between probe and synthesis). The engine then degrades to
# headline-matching, whose "most recent" date is the earliest ARTICLE date, not
# the incident date: for Dis-Chem that is a 2025 follow-up piece about a 2022
# breach, which would score a three-year-old incident as if it were last quarter.
# A degraded result must therefore never reach the recency lever.
BREACH_DEGRADED = [
    ("researched confirmed",     {"researched": True},  True),
    ("degraded confirmed",       {"researched": False}, False),
    ("legacy (flag absent)",     {},                    True),
]
# (d) KEY-PROBE STATUS MAPPING. Everything above depends on check_key() correctly
# calling a dead key dead — it is the trigger for the 503 readiness alarm, the
# submission-time warning and the UNASSESSED verdict. Google rejects a bad key
# with a code that depends on the key FORMAT, which the 2026-07-27 alarm drill
# exposed: our production key is the new "AQ.…" style, whose rejection is 401,
# and 401 was NOT in the rejected set — so a genuinely revoked production key
# fell through to the generic "error" branch, which reported no fingerprint and
# no remediation hint. The alarm still fired, but the on-call operator would have
# been told "error" instead of "key rejected — rotated or revoked", and could not
# see WHICH key was failing. Mapping is asserted here per HTTP code, offline.
#   (label, listing_code, generation_code, expected_status, expect_fingerprint)
KEY_PROBE_SCENARIOS = [
    ("revoked AQ.-style",    401, None, "inactive",         True),
    ("revoked AIza-style",   400, None, "inactive",         True),
    ("wrong key type",       403, None, "inactive",         True),
    ("valid but unfunded",   200,  429, "quota_exhausted",  True),
    ("healthy",              200,  200, "active",           True),
    ("transient upstream",   503, None, "error",            True),
]


# (e) DATASTORE FALLBACK. scanner_db silently falls back to SQLite when
# DATABASE_URL is unset. That is right for dev and catastrophic in production:
# on 2026-07-27 a clobbered .env dropped DATABASE_URL and the scanner came up
# serving a stale legacy scans.db while the real Postgres history sat untouched,
# with /health AND /health/providers both green the whole time. Nothing errored,
# so nothing alarmed -- the same shape as a dead web-search key reporting a
# clean breach history. The readiness probe must therefore treat an unasked-for
# SQLite fallback as degraded (503), while still allowing a deliberate dev
# SQLite run via SCANNER_ALLOW_SQLITE.
#   (label, DATABASE_URL set?, SCANNER_ALLOW_SQLITE, expect_degraded, expect_status)
DATASTORE_SCENARIOS = [
    ("postgres configured",     True,  "",  False, "postgres"),
    ("silent sqlite fallback",  False, "",  True,  "sqlite_fallback"),
    ("sqlite asked for (dev)",  False, "1", False, "sqlite"),
    ("postgres + dev flag",     True,  "1", False, "postgres"),
]


def _check_datastore_readiness(failures):
    import importlib
    app_mod = importlib.import_module("app")
    for label, has_url, allow, want_degraded, want_status in DATASTORE_SCENARIOS:
        env = {"SCANNER_ALLOW_SQLITE": allow}
        if has_url:
            env["DATABASE_URL"] = "postgresql://u:p@localhost:5544/db"
        with mock.patch.dict(os.environ, env, clear=False):
            if not has_url:
                os.environ.pop("DATABASE_URL", None)
            # Re-point scanner_db at the patched env, and keep the probe offline.
            import scanner_db
            scanner_db.configure(database_url=os.environ.get("DATABASE_URL"),
                                 sqlite_path=":memory:")
            # The reachability probe (2026-09-08) is stubbed REACHABLE here on
            # purpose: these scenarios assert the CONFIGURED-BACKEND logic, and the
            # DSN above points at a database that does not exist in the gate, so an
            # unstubbed probe would fail them for a reason they are not testing.
            # Reachability gets its own scenarios below.
            with mock.patch("websearch.check_key_cached",
                            return_value={"status": "active",
                                          "key_fingerprint": "test", "cached": True}), \
                 mock.patch.object(scanner_db, "ping", return_value=(True, "")), \
                 app_mod.app.test_client() as client:
                resp = client.get("/health/providers")
                body = resp.get_json() or {}
        ds = (body.get("providers") or {}).get("datastore", {})
        got_status = ds.get("status")
        got_degraded = "datastore" in (body.get("degraded") or [])
        code_ok = resp.status_code == (503 if want_degraded else 200)
        ok = (got_status == want_status) and (got_degraded == want_degraded) and code_ok
        if not ok:
            failures.append(
                f"datastore[{label}]: status={got_status!r} (want {want_status!r}), "
                f"degraded={got_degraded} (want {want_degraded}), "
                f"http={resp.status_code} — an unasked-for SQLite fallback must "
                "raise the readiness alarm, otherwise the scanner can serve a stale "
                "database while every health check reports green")
        print(f"  [{'PASS' if ok else 'FAIL'}] datastore:{label:<22} "
              f"{got_status} degraded={got_degraded} http={resp.status_code}")
    # REACHABILITY -- the half the configured-backend check cannot see.
    # 2026-09-01 09:35:21: both application databases stopped and nothing
    # noticed for a week, because this endpoint reported
    # {"backend": "postgres", "status": "postgres"} throughout -- that is what
    # .env said. The scanner 500'd on every history request and the rating
    # engine failed 11 quote saves in front of a user over two days. A
    # readiness endpoint that stays green through an outage is worse than none,
    # because it is the thing a monitor trusts.
    import scanner_db as _sdb
    for label, ping_result, want_deg, want_status in (
            ("reachable", (True, ""), False, "sqlite"),
            ("UNREACHABLE", (False, "OperationalError: connection refused"),
             True, "unreachable"),
    ):
        with mock.patch.dict(os.environ, {"SCANNER_ALLOW_SQLITE": "1"}, clear=False):
            os.environ.pop("DATABASE_URL", None)
            _sdb.configure(database_url=None, sqlite_path=":memory:")
            with mock.patch("websearch.check_key_cached",
                            return_value={"status": "active",
                                          "key_fingerprint": "t", "cached": True}), \
                 mock.patch.object(_sdb, "ping", return_value=ping_result), \
                 app_mod.app.test_client() as client:
                resp = client.get("/health/providers")
                body = resp.get_json() or {}
        ds = (body.get("providers") or {}).get("datastore", {})
        got_deg = "datastore" in (body.get("degraded") or [])
        impact_ok = "UNREACHABLE" in (body.get("impact") or "")
        ok = (ds.get("status") == want_status and got_deg == want_deg
              and resp.status_code == (503 if want_deg else 200))
        if want_deg:
            ok = ok and impact_ok
        if not ok:
            failures.append(
                f"datastore_reach[{label}]: status={ds.get('status')!r} "
                f"(want {want_status!r}), degraded={got_deg} (want {want_deg}), "
                f"http={resp.status_code}, operator-impact="
                f"{'present' if impact_ok else 'MISSING'} - a readiness endpoint "
                "that stays green while the database is gone is worse than none, "
                "and flipping a flag without telling the operator what it means "
                "leaves them guessing at data loss")
        print(f"  [{'PASS' if ok else 'FAIL'}] datastore_reach:{label:<13} "
              f"{ds.get('status')} degraded={got_deg} http={resp.status_code}")
    # leave the module pointed somewhere harmless for any later check
    import scanner_db
    scanner_db.configure(database_url=None, sqlite_path=":memory:")


# (g) CREDENTIAL PROVIDERS MUST FAIL CLOSED. A dead or unfunded DeHashed/IntelX
# produced a report that read CLEAN rather than unassessed - the same silent
# degradation the breach-history checker was deliberately built to avoid, never
# applied to these two. Four distinct leaks, all observed in code:
#   * IntelX returns a 200 with NO search id once the daily free allowance is
#     gone; the checker returned status="completed", total_results=0, which is
#     byte-identical to a genuinely clean domain.
#   * A failed result-poll (402/429/5xx) broke out of the loop with records=[]
#     and status still "completed".
#   * The Data Breach Index defaulted total_entries to 0 for any status except
#     no_api_key/auth_failed, taking the FULL-MARKS 20/20 clean branch - so a
#     BROKEN provider scored better than an ABSENT one (10/20 "Unknown").
#   * CredentialRiskClassifier never read the status at all: no records meant
#     class NONE / risk LOW plus the affirmative "exposure is historical and/or
#     email-only" summary. That is the RSI-driving channel.
# Every non-conclusive status must reach the scorer as "we did not look".
NON_CONCLUSIVE = ["error", "timeout", "quota_exhausted", "subscription_required",
                  "no_api_key", "auth_failed"]


def _check_credential_failclosed(failures):
    import importlib
    ct_mod = importlib.import_module("checkers_threats")
    sa = importlib.import_module("scoring_analytics")

    # (1) the classifier must refuse to classify an unsearched estate
    for st in NON_CONCLUSIVE:
        res = ct_mod.CredentialRiskClassifier.classify(
            {"status": st, "breach_details": [], "total_entries": 0}, {}, {})
        lvl, assessed = res.get("risk_level"), res.get("assessed", True)
        ok = (lvl == "UNKNOWN") and (assessed is False) \
            and "NOT ASSESSED" in (res.get("summary") or "")
        if not ok:
            failures.append(
                f"cred_failclosed[classify/{st}]: risk_level={lvl!r} assessed={assessed} "
                "— an unsearched credential estate must report UNKNOWN/unassessed, "
                "never LOW with a reassuring summary; this channel drives the RSI")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:classify/{st:<22} "
              f"{lvl} assessed={assessed}")

    # (2) a healthy-but-genuinely-clean lookup must STILL score clean (no over-correction)
    clean = ct_mod.CredentialRiskClassifier.classify(
        {"status": "completed", "breach_details": [], "total_entries": 0}, {}, {})
    ok = clean.get("risk_level") == "LOW" and clean.get("assessed", True) is not False
    if not ok:
        failures.append(f"cred_failclosed[classify/genuinely-clean]: {clean.get('risk_level')!r} "
                        "— a real empty result must still read LOW, or we have swapped "
                        "one wrong answer for another")
    print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:classify/genuine-clean   "
          f"{clean.get('risk_level')}")

    # (3) the Data Breach Index must not award the clean sweep to a failed lookup
    def _dbi(status):
        cats = {"breaches": {"status": "completed", "breach_count": 0, "issues": []},
                "dehashed": {"status": status, "total_entries": 0}}
        comp = sa.DataBreachIndex().calculate(cats)["components"]["credential_leaks"]
        return comp["points"]
    conclusive_pts = _dbi("completed")
    for st in NON_CONCLUSIVE:
        pts = _dbi(st)
        ok = (pts is not None) and (pts < conclusive_pts)
        if not ok:
            failures.append(
                f"cred_failclosed[dbi/{st}]: {pts} pts vs {conclusive_pts} for a real "
                "clean lookup — a provider that never answered must not earn the "
                "full-marks clean branch")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:dbi/{st:<24} "
              f"{pts} pts (real clean = {conclusive_pts})")

    # (4) the headline scorer must exclude them rather than treat them as valid
    for st in ("quota_exhausted", "subscription_required"):
        ok = st in sa.RiskScorer._FAILED_STATUSES
        if not ok:
            failures.append(f"cred_failclosed[failed_statuses/{st}]: not in _FAILED_STATUSES "
                            "— it would score as a valid, clean category")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:failed_status/{st:<16} {ok}")

    # (5) the PAGE must say so too. Correct scoring is invisible to a broker
    # reading the PDF: an empty dark-web section still reads as good news unless
    # the card states it was never searched.
    pc = importlib.import_module("pdf_cards")
    from pdf_helpers import build_styles
    S = build_styles()

    def _txt(parts):
        return " ".join(getattr(p, "text", "") or "" for p in parts)

    render_cases = [
        ("dehashed/quota", pc.cat_dehashed,
         {"dehashed": {"status": "quota_exhausted", "total_entries": 0, "issues": []}}, True),
        ("dehashed/subscription", pc.cat_dehashed,
         {"dehashed": {"status": "subscription_required", "total_entries": 0, "issues": []}}, True),
        ("dehashed/genuine-clean", pc.cat_dehashed,
         {"dehashed": {"status": "completed", "total_entries": 0, "unique_emails": 0, "issues": []}}, False),
        ("intelx/quota", pc.cat_intelx,
         {"intelx": {"status": "quota_exhausted", "total_results": 0, "issues": []}}, True),
        ("intelx/poll-error", pc.cat_intelx,
         {"intelx": {"status": "error", "total_results": 0, "issues": []}}, True),
        ("intelx/genuine-clean", pc.cat_intelx,
         {"intelx": {"status": "completed", "total_results": 0, "darkweb_count": 0,
                     "paste_count": 0, "leak_count": 0, "issues": []}}, False),
        ("credrisk/unassessed", pc.cat_credential_risk,
         {"credential_risk": {"risk_level": "UNKNOWN", "assessed": False,
                              "status": "quota_exhausted"}}, True),
        ("credrisk/real-low", pc.cat_credential_risk,
         {"credential_risk": {"risk_level": "LOW", "risk_score": 100, "factors": []}}, False),
    ]
    for label, fn, data, want_caveat in render_cases:
        txt = _txt(fn(data, S))
        has = "Not assessed" in txt
        ok = has == want_caveat
        if not ok:
            failures.append(
                f"cred_failclosed[render/{label}]: caveat_present={has}, expected "
                f"{want_caveat} — a card built from a lookup that never ran must say "
                "'Not assessed'; correct scoring alone is invisible to the reader")
        print(f"  [{'PASS' if ok else 'FAIL'}] cred_failclosed:render/{label:<22} "
              f"caveat={has}")


# (f) CREDENTIAL-EXPORT KILL SWITCH. The export releases a client's ACTUAL
# breached passwords. What makes that lawful is the client's signed consent, and
# the request's `consent: true` field is only a broker attestation -- during the
# 2026-07-28 demo, with testers who have signed nothing, it is not a control at
# all. So the export must FAIL CLOSED unless explicitly enabled, and the DOWNLOAD
# route must be gated too: gating only the POST would still let a token minted
# before the flip be redeemed after it. Asserted here so a future refactor cannot
# quietly reopen it.
#   (label, env value, expect_blocked)
# ---------------------------------------------------------------------------
# PAID-PROVIDER EGRESS GUARD.
#
# THIS GATE MUST BE OFFLINE. It runs on every push -- twice per check-in, once
# per remote -- and on a developer machine `import app` loads .env, which puts
# the LIVE production keys into the process. Any scenario that reaches a metered
# provider therefore spends real money, silently, on every push.
#
# That is not hypothetical: _check_export_switch did exactly this from the day
# the export scenarios were added, at 5 DeHashed credits a run, and nobody saw
# it because a local run meters to SQLite while we read the ledger from the VM's
# Postgres. It cost roughly 500 credits before it was found.
#
# So: block the hosts, collect what was attempted, and FAIL the gate. Blocking
# alone is not enough -- provider_client.guarded_call swallows the exception and
# returns None, so a blocked call still looks like a passing scenario. The
# collected list is asserted at the end of main() for that reason.
_PAID_PROVIDER_HOSTS = (
    "dehashed.com", "intelx.io", "api.shodan.io", "virustotal.com",
    "securitytrails.com", "hudsonrock.com", "haveibeenpwned.com",
    "snusbase.com", "leakcheck.io", "whiteintel.io",
)
_BLOCKED_EGRESS: list = []


def _install_paid_egress_guard():
    """Patch the ONE funnel every requests verb passes through.

    Session.request, not requests.post -- a scenario that mocks requests.post
    leaves requests.get, requests.request and any Session call wide open, which
    is precisely how the export path stayed invisible to the balance-metering
    scenario sitting a few hundred lines away.
    """
    import requests.sessions
    _orig = requests.sessions.Session.request

    def guarded(self, method, url, *args, **kwargs):
        u = str(url).lower()
        if any(h in u for h in _PAID_PROVIDER_HOSTS):
            _BLOCKED_EGRESS.append(f"{method} {url}")
            raise RuntimeError(f"paid-provider egress blocked in gate: {method} {url}")
        return _orig(self, method, url, *args, **kwargs)

    requests.sessions.Session.request = guarded


EXPORT_SWITCH_SCENARIOS = [
    ("unset (default)",  None,    True),
    ("explicit off",     "0",     True),
    ("garbage value",    "maybe", True),   # anything but a true-ish value = closed
    ("enabled",          "1",     False),
]


def _check_shared_hosting_attribution(failures):
    """A shared-hosting box must not be attributed as the insured's OWN infra.

    2026-08-18, phishield.com. 213.133.105.171 serves the site and exposes MySQL
    3306 + PostgreSQL 5432. classify_ip returned ('owned', 'cloud IaaS
    (insured-operated)'), so the report told a broker the client had an
    internet-facing database and advised closing a port on a box the client does
    not operate -- it is a Hetzner MANAGED SHARED host and the client is one
    tenant. This is the SAME defect ip_classification was created to fix: its
    docstring cites a HostRocket shared host wrongly attributed to takealot.

    Reverse DNS and org cannot separate the cases (Hetzner sells both), so the
    signal is the certificate served with NO SNI -- the platform's own identity.
    Offline here: the cert names are supplied, no network call.
    """
    import importlib
    ipc = importlib.import_module("ip_classification")

    HETZNER_SHARED = {"*.your-server.de", "your-server.de"}
    cases = [
        # label, kwargs, expect_third_party
        ("shared host, provider default cert",
         dict(reverse_dns="dedi5586.your-server.de", org="Hetzner Online AG",
              default_cert_names=HETZNER_SHARED, insured_domain="phishield.com"), True),
        # the insured's OWN server must stay scannable -- over-correcting here
        # would silently drop real exposures off the insured's attack surface.
        ("own server, cert names the insured",
         dict(reverse_dns="static.1.2.3.4.clients.your-server.de",
              org="Hetzner Online AG",
              default_cert_names={"acme.co.za", "www.acme.co.za"},
              insured_domain="acme.co.za"), False),
        ("own server, wildcard covering the insured",
         dict(default_cert_names={"*.acme.co.za"},
              insured_domain="app.acme.co.za"), False),
        # unknown must NOT invent a verdict: no 443, probe blocked, no crypto lib
        ("cert unreadable -> unchanged behaviour",
         dict(reverse_dns="dedi5586.your-server.de", org="Hetzner Online AG",
              default_cert_names=None, insured_domain="phishield.com"), False),
    ]
    for label, kw, want_tp in cases:
        bucket, prov = ipc.classify_ip("213.133.105.171", **kw)
        got_tp = ipc.is_third_party(bucket)
        ok = (got_tp == want_tp)
        if not ok:
            failures.append(
                f"shared_hosting[{label}]: classify_ip -> ({bucket!r}, {prov!r}), "
                f"third_party={got_tp} but expected {want_tp}. Attributing a "
                "vendor-operated shared host to the insured produces a finding "
                "they cannot remediate; attributing their OWN server to a vendor "
                "silently drops a real exposure from the attack surface.")
        print(f"  [{'PASS' if ok else 'FAIL'}] shared_hosting:{label[:38]:<38} "
              f"{bucket}/{prov[:28]}")

    # RFC 6125: a wildcard covers ONE label only.
    ok_w = (ipc._cert_covers({"*.a.com"}, "x.a.com") is True
            and ipc._cert_covers({"*.a.com"}, "y.x.a.com") is False)
    if not ok_w:
        failures.append("shared_hosting[wildcard_depth]: *.a.com must cover "
                        "x.a.com but NOT y.x.a.com (RFC 6125 single-label)")
    print(f"  [{'PASS' if ok_w else 'FAIL'}] shared_hosting:wildcard_single_label")

def _check_checker_wiring(failures):
    """Every `SomeChecker().method` scanner.py references must actually exist.

    2026-08-18: a helper block was inserted using a METHOD as its anchor, so it
    landed inside ShodanVulnChecker's body and de-indented every method after it
    out of the class. ShodanVulnChecker lost .check entirely and scan() died at
    startup with AttributeError. NINE OFFLINE GATES PASSED over that build --
    none of them constructs the scanner -- and only the pre-push live smoke test
    caught it, which runs on master pushes alone. A feature branch would have
    shipped it.

    The registry is built inline inside scan(), so no offline gate can reach it
    by calling. Check it STATICALLY instead: walk scanner.py's AST for every
    `X().attr`, import X, assert the attribute is there. Milliseconds, no
    network, and it fails on exactly the defect that got through.
    """
    import ast, importlib
    src = open(os.path.join(SEC, "scanner.py"), encoding="utf-8").read()
    tree = ast.parse(src)

    wanted = set()          # (ClassName, attr)
    for node in ast.walk(tree):
        # matches `ShodanVulnChecker().check` -> Attribute(value=Call(func=Name))
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id.endswith(("Checker", "Classifier", "Metadata",
                                                 "Index", "Scorer", "Calculator"))):
            wanted.add((node.value.func.id, node.attr))

    if not wanted:
        failures.append("checker_wiring: parsed scanner.py and found NO "
                        "`SomeChecker().method` references — the gate has gone "
                        "blind, which is worse than it failing")
        print("  [FAIL] checker_wiring:parsed                 0 references")
        return

    # Resolve each class from the modules scanner.py imports from.
    mods = {}
    for m in ("checkers_core", "checkers_network", "checkers_threats",
              "checkers_supply_chain", "scoring_analytics", "scanner"):
        try:
            mods[m] = importlib.import_module(m)
        except Exception:
            pass

    missing, checked = [], 0
    for cls_name, attr in sorted(wanted):
        cls = None
        for m in mods.values():
            cls = getattr(m, cls_name, None)
            if cls is not None:
                break
        if cls is None:
            continue            # not one of ours / conditionally imported
        checked += 1
        if not hasattr(cls, attr):
            missing.append(f"{cls_name}.{attr}")

    ok = not missing
    if not ok:
        failures.append(
            "checker_wiring: scanner.py calls " + ", ".join(missing) +
            " but the attribute does not exist on the class. scan() will raise "
            "AttributeError at startup and EVERY scan fails. This is the class of "
            "break that nine offline gates missed on 2026-08-18.")
    print(f"  [{'PASS' if ok else 'FAIL'}] checker_wiring:attrs_exist          "
          f"{checked} checked, {len(missing)} missing")


# Recommendation ordering uses a synthetic scanner address, not an
# external IP-echo service. This fixture is unrelated to live egress.
@mock.patch("egress.egress_ip", new=lambda: "192.0.2.10")
def _check_recommendation_priority(failures):
    """The report calls this list "prioritised". It must actually be.

    2026-08-18, owner-reported on a live client report: the REMEDIATION
    RECOMMENDATIONS block ranked "Implement MTA-STS" above a credential breach,
    printed the identical "Patch critical CVEs" line twice (items 15 and 18), and
    described the credential exposure so generically -- no count, no severity, no
    MFA -- that the owner read the list as saying nothing about it at all, while
    the credential card in the same report was CRITICAL.

    Three separate causes, all reproduced before fixing:
      * no ordering: emitted in results-dict order, not severity order;
      * dedupe keyed on the MAPPING KEY, and two keys carry the same sentence;
      * a static recommendation string that cannot state scale.
    """
    import importlib
    SA = importlib.import_module("scoring_analytics")

    cats = {
        "email_hardening": {"status": "completed", "score": 50,
                            "issues": ["No MTA-STS policy found"]},
        "http_headers":    {"status": "completed", "score": 50,
                            "issues": ["Missing Content-Security-Policy header"]},
        "dehashed":        {"status": "completed", "score": 0, "total_entries": 2245,
                            "issues": ["2245 credential record(s) found in Dehashed for this domain"]},
        "credential_risk": {"status": "completed", "risk_level": "CRITICAL", "assessed": True},
        "shodan_vulns":    {"status": "completed", "score": 0,
                            "issues": ["CRITICAL: 1 critical CVE", "3 critical CVE(s) found"]},
    }
    _s, _l, recs = SA.RiskScorer().calculate(dict(cats), {})

    checks = []
    checks.append(("no_duplicate_lines", len(recs) == len(set(recs)),
                   "the same recommendation sentence is printed more than once; "
                   "dedupe on the TEXT, not the mapping key"))

    cred_i = next((i for i, r in enumerate(recs) if "leaked credential record" in r), None)
    mta_i = next((i for i, r in enumerate(recs) if "MTA-STS" in r), None)
    checks.append(("credential_outranks_hygiene",
                   cred_i is not None and mta_i is not None and cred_i < mta_i,
                   f"credential breach at position {cred_i}, MTA-STS at {mta_i} — a "
                   "CRITICAL credential exposure must outrank email hygiene in a list "
                   "the report calls prioritised"))

    cred = recs[cred_i] if cred_i is not None else ""
    checks.append(("credential_states_scale", "2,245" in cred,
                   "the credential recommendation does not say HOW MANY records; a "
                   "generic line reads as boilerplate and gets skipped"))
    checks.append(("credential_states_severity", cred.startswith("CRITICAL"),
                   "the credential recommendation does not carry the severity the "
                   "credential card shows, so the action list and the narrative disagree"))
    checks.append(("credential_names_mfa", "multi-factor" in cred,
                   "password reset without MFA leaves the account takeover path open"))

    # and a deliberate skip must NOT manufacture a credential action
    cats2 = dict(cats)
    cats2["dehashed"] = {"status": "no_api_key", "total_entries": 0, "issues": []}
    cats2["credential_risk"] = {"status": "no_api_key", "assessed": False,
                                "risk_level": "UNKNOWN"}
    _s2, _l2, recs2 = SA.RiskScorer().calculate(dict(cats2), {})
    checks.append(("unassessed_claims_no_count",
                   not any("leaked credential record" in r for r in recs2),
                   "an UNASSESSED credential check produced a numeric credential "
                   "recommendation — asserting a count nobody measured"))

    # An ACTIVE exposure must outrank a COMPLIANCE gap even when card_severity
    # rates both categories critical in aggregate. Real 2026-08-20 scan: a
    # missing privacy policy and an internet-exposed Jupyter Notebook were both
    # category-critical, and results-dict order put the compliance gap above the
    # remote-code-execution path.
    cats3 = {
        "privacy_compliance":  {"status": "completed", "score": 0,
                                "issues": ["No privacy policy found — POPIA/GDPR compliance risk"]},
        "high_risk_protocols": {"status": "completed", "score": 0, "critical_count": 1,
                                "issues": ["CRITICAL: Jupyter Notebook (port 8888) exposed to internet"]},
    }
    _s3, _l3, recs3 = SA.RiskScorer().calculate(dict(cats3), {})
    exp_i = next((i for i, r in enumerate(recs3) if "critically exposed service" in r), None)
    pol_i = next((i for i, r in enumerate(recs3) if "privacy policy" in r), None)
    checks.append(("active_exposure_over_compliance",
                   exp_i is not None and pol_i is not None and exp_i < pol_i,
                   f"critically exposed service at {exp_i}, privacy policy at {pol_i} — a "
                   "finding that names itself CRITICAL is a specific active exposure and "
                   "must outrank a category-level compliance gap"))

    # Credential exposure has NO card_severity rule; its band must come from the
    # credential_risk verdict, not fall through to the unknown default.
    cats4 = {
        "email_hardening": {"status": "completed", "score": 50,
                            "issues": ["No MTA-STS policy found"]},
        "dehashed":        {"status": "completed", "score": 0, "total_entries": 8,
                            "issues": ["8 credential record(s) found in Dehashed for this domain"]},
        "credential_risk": {"status": "completed", "risk_level": "HIGH", "assessed": True},
    }
    _s4, _l4, recs4 = SA.RiskScorer().calculate(dict(cats4), {})
    c4 = next((i for i, r in enumerate(recs4) if "leaked credential record" in r), None)
    m4 = next((i for i, r in enumerate(recs4) if "MTA-STS" in r), None)
    checks.append(("credential_band_from_verdict",
                   c4 is not None and m4 is not None and c4 < m4,
                   "a HIGH credential verdict sorted below email hygiene — dehashed has no "
                   "card_severity rule, so its band must be taken from credential_risk"))

    # Do not tell a broker to re-scan when a re-scan cannot help. bbgroup.co.za
    # 2026-08-20: the target's edge filters the scanner's egress IP on 80 AND
    # 443, so the two failed checkers were unrecoverable, yet the report advised
    # a re-scan. Measured, not assumed: 0/5 from the scanner, 10/10 HTTP 200
    # from an ordinary connection.
    fail_cats = {"website_security": {"status": "unreachable"},
                 "third_party_js": {"status": "error", "error": "HTTP no-response"}}
    _sb, _lb, recs_b = SA.RiskScorer().calculate(
        dict(fail_cats), {"blocked": True, "kind": "waf_timeout",
                          "evidence": "12 of 20 probes timed out / failed"})
    _st, _lt, recs_t = SA.RiskScorer().calculate(dict(fail_cats), {})
    blocked_msg = recs_b[0] if recs_b else ""
    transient_msg = recs_t[0] if recs_t else ""
    checks.append(("blocked_does_not_advise_rescan",
                   "re-scan is recommended" not in blocked_msg
                   and "same result" in blocked_msg,
                   "the scan was refused by the target's edge but the report still "
                   "advises a re-scan, which cannot succeed from the same source"))
    # NAME THE ADDRESS TO ALLOW-LIST, but only when it is relevant and only when
    # it is actually known. A hardcoded literal goes stale the first time the VM
    # moves and a client then allow-lists an address we no longer use, which is
    # worse than silence because it looks like it worked.
    import egress as _EG
    _orig_egress = _EG.egress_ip
    try:
        _EG.egress_ip = lambda *a, **k: "34.35.151.242"
        _known = SA.RiskScorer().calculate(
            dict(fail_cats), {"blocked": True, "evidence": "12 of 20 probes timed out"})[2][0]
        _EG.egress_ip = lambda *a, **k: None
        _unknown = SA.RiskScorer().calculate(
            dict(fail_cats), {"blocked": True, "evidence": "12 of 20 probes timed out"})[2][0]
    finally:
        _EG.egress_ip = _orig_egress

    checks.append(("blocked_names_the_source", "34.35.151.242" in _known,
                   "the client is told to allow-list the assessment source but the "
                   "address is not stated, so the instruction cannot be acted on"))
    checks.append(("unknown_source_omits_cleanly",
                   "originates from" not in _unknown and "()" not in _unknown
                   and "allow-listing the assessment source" in _unknown,
                   "with no detectable egress address the report must omit it "
                   "entirely -- never an empty bracket and never a guess"))
    checks.append(("unblocked_does_not_leak_source",
                   "originates from" not in transient_msg,
                   "the scanner's own source address appears on a report where "
                   "nothing was blocked; it is only useful in the blocked case"))

    checks.append(("transient_still_advises_rescan",
                   "re-scan is recommended" in transient_msg,
                   "a genuinely transient failure must still advise a re-scan; the "
                   "blocked-path wording must not swallow the ordinary case"))

    for label, ok, why in checks:
        if not ok:
            failures.append(f"rec_priority[{label}]: {why}")
        print(f"  [{'PASS' if ok else 'FAIL'}] rec_priority:{label:<32}")


def _check_meeting_brief(failures):
    """The client meeting brief must not spend, and must not print a password.

    Two independent ways this could go wrong, both of which have precedent here:
      * the fingerprint-free path quietly acquiring an outbound call, which is
        exactly how the credential export burned ~500 credits from inside a
        guard test (see _check_export_switch);
      * the fingerprint renderer widening to something replayable. A fingerprint
        that leaks more than the first character stops being a recognition aid
        and becomes a credential.
    The paid path is never exercised: fetch_fingerprints is stubbed, and the
    module-level Session.request guard fails the run if anything escapes anyway.
    """
    import importlib
    mb = importlib.import_module("meeting_brief")

    # 1. the renderer reveals first character + length, and nothing else.
    for pw in ("Kruger2024", "P@ssw0rd!", "a"):
        fp = mb.fingerprint(pw)
        shown = mb.render_fingerprint(fp)
        leaked = (set(fp.keys()) != {"first", "length"}
                  or (len(pw) > 1 and (pw in shown or pw[1:] in shown)))
        if leaked:
            failures.append(
                f"meeting_brief[fingerprint]: render_fingerprint({pw!r}) -> "
                f"{shown!r} exposes more than the first character; a fingerprint "
                "must not be replayable")
        print(f"  [{'FAIL' if leaked else 'PASS'}] meeting_brief:fingerprint "
              f"{len(pw)}ch -> {shown}")

    # 2. credits are counted in PAGES, not records (the source bills per search).
    for n, want in ((100, 1), (101, 2), (230, 3), (10 ** 6, mb.MAX_PAGES)):
        got = mb.estimate_credits(n)
        if got != want:
            failures.append(f"meeting_brief[credits]: estimate_credits({n}) = "
                            f"{got}, expected {want} (one credit per page of "
                            f"{mb.PAGE_SIZE}, capped at {mb.MAX_PAGES})")
    print(f"  [{'PASS' if all(mb.estimate_credits(n) == w for n, w in ((100, 1), (101, 2), (230, 3))) else 'FAIL'}]"
          f" meeting_brief:credit_estimate    pages-not-records")

    # 3. the fingerprint-free brief makes NO outbound call and prints no password.
    results = {
        "domain_scanned": "examplecorp.co.za", "scan_timestamp": "2026-01-01T00:00:00",
        "recommendations": ["CRITICAL: rotate the exposed role accounts"],
        "_scan_completeness": {"failed_checkers": [], "waf_affected_checkers": [],
                               "completeness_pct": 100, "coverage_pct": 100},
        "categories": {"dehashed": {"status": "completed", "total_entries": 7,
                                    "breach_details": [
                                        {"email": "a@examplecorp.co.za",
                                         "database": "synthetic",
                                         "has_password": True, "has_hash": False}]}},
    }
    before = len(_BLOCKED_EGRESS)
    pdf = mb.build_brief(results, "examplecorp.co.za")
    spent = len(_BLOCKED_EGRESS) - before
    ok = pdf[:4] == b"%PDF" and spent == 0
    if not ok:
        failures.append(
            f"meeting_brief[free_path]: {spent} outbound call(s) during a "
            "fingerprint-free brief — this path must spend nothing")
    print(f"  [{'PASS' if ok else 'FAIL'}] meeting_brief:free_path          "
          f"outbound={spent} pdf={len(pdf)}B")

    # 4. the route refuses fingerprints without a recorded reason.
    #
    # fetch_scan is stubbed rather than seeded: _check_datastore_readiness runs
    # before this and deliberately leaves the store unreachable, so a real lookup
    # would 500 and the assertion would be measuring the datastore instead of the
    # reason gate. Stubbing pins the route to the one behaviour under test.
    app_mod = importlib.import_module("app")
    import json as _json
    row = {"id": "gate-synthetic", "domain": "examplecorp.co.za",
           "status": "completed", "results": _json.dumps(results)}
    with mock.patch.object(app_mod, "fetch_scan", return_value=row), \
         mock.patch.object(mb, "fetch_fingerprints",
                           side_effect=AssertionError("must not be reached")), \
         app_mod.app.test_client() as c:
        no_reason = c.post("/api/scan/gate-synthetic/brief",
                           json={"include_fingerprints": True})
        blank = c.post("/api/scan/gate-synthetic/brief",
                       json={"include_fingerprints": True, "reason": "   "})
        free = c.post("/api/scan/gate-synthetic/brief",
                      json={"include_fingerprints": False})
    ok = (no_reason.status_code == 400 and blank.status_code == 400
          and free.status_code == 200 and free.data[:4] == b"%PDF")
    if not ok:
        failures.append(
            f"meeting_brief[reason_gate]: no_reason={no_reason.status_code} "
            f"blank={blank.status_code} free={free.status_code} — a fingerprint "
            "request without a recorded reason must be refused (400), and the "
            "fingerprint-free brief must still render")
    print(f"  [{'PASS' if ok else 'FAIL'}] meeting_brief:reason_gate        "
          f"no_reason={no_reason.status_code} blank={blank.status_code} "
          f"free={free.status_code}")

    # 5. no audit row, no fingerprints. The audit trail is the only thing standing
    # behind a credential-bearing document while the app has no auth of its own
    # (OUTSTANDING 4b); if it cannot be written the document must not be released.
    # The datastore is genuinely unreachable at this point in the run, so this
    # asserts the real failure mode rather than a simulated one.
    with mock.patch.object(app_mod, "fetch_scan", return_value=row), \
         mock.patch.object(mb, "fetch_fingerprints", return_value={
             "accounts": [], "records": 0, "credits_spent": 1,
             "by_domain": {}, "complete": True}), \
         mock.patch.object(app_mod.scanner_db, "record_meeting_brief",
                           side_effect=RuntimeError("datastore down")), \
         app_mod.app.test_client() as c:
        fp_req = c.post("/api/scan/gate-synthetic/brief",
                        json={"include_fingerprints": True, "reason": "gate"})
        free_req = c.post("/api/scan/gate-synthetic/brief",
                          json={"include_fingerprints": False})
    ok = (fp_req.status_code == 503 and fp_req.data[:4] != b"%PDF"
          and free_req.status_code == 200)
    if not ok:
        failures.append(
            f"meeting_brief[audit_required]: fingerprints={fp_req.status_code} "
            f"free={free_req.status_code} — with the audit write failing, a "
            "fingerprint brief must be refused (503) while a fingerprint-free "
            "brief still renders")
    print(f"  [{'PASS' if ok else 'FAIL'}] meeting_brief:audit_required     "
          f"fingerprints={fp_req.status_code} free={free_req.status_code}")


def _check_export_switch(failures):
    # Two halves, deliberately: reloading app to re-read the env would re-run
    # init_db() against whatever DB the env points at, so instead patch the flag
    # the decorator reads at call time (route behaviour), and check the env
    # parsing separately against the same values (config behaviour).
    #
    # THE "enabled" SCENARIO REACHES A REAL, PAGINATED, BILLED DeHashed FETCH.
    # 2026-08-14: this was the single largest DeHashed credit consumer in the
    # project. With export enabled the POST is NOT blocked, so the route runs
    # credential_export.generate_encrypted_export -> _fetch_dehashed_full, which
    # pages max_pages=5 x size=100 against `domain:example.com` -- 1,220,357
    # records, so no page is ever short and the loop always runs all five.
    # FIVE credits per gate run, TEN per check-in (the pre-push hook fires once
    # per remote), plus every manual run during development. Measured: balance
    # 476 -> 466 across exactly two runs.
    #
    # It never appeared in the usage ledger because a local run writes to SQLite,
    # not the VM's Postgres, so the durable ledger we report from never saw one.
    #
    # Stub the fetch, not the flag: the point of these scenarios is the ROUTE's
    # open/closed behaviour (503 on POST and on download, plus the status
    # endpoint), all of which is preserved. Only the network call goes away.
    import importlib
    app_mod = importlib.import_module("app")
    ce_mod = importlib.import_module("credential_export")
    for label, val, want_blocked in EXPORT_SWITCH_SCENARIOS:
        parsed = str(val or "").strip().lower() in ("1", "true", "yes", "on")
        with mock.patch.object(app_mod, "CREDENTIAL_EXPORT_ENABLED", parsed), \
             mock.patch.object(ce_mod, "_fetch_dehashed_full", return_value=[
                 {"email": "probe@examplecorp.co.za", "password": "x",
                  "database_name": "synthetic"}]), \
             app_mod.app.test_client() as c:
            post = c.post("/api/credential-export", json={
                "domain": "example.com", "consent": True, "authorised_by": "T",
                "age_public_key": "age1" + "q" * 50})
            dl = c.get("/api/credential-export/download/tok")
            st = (c.get("/api/credential-export/status").get_json() or {})
        blocked = (post.status_code == 503 and dl.status_code == 503)
        env_ok = (parsed != want_blocked)      # env string -> the flag we expect
        ok = (blocked == want_blocked) and (st.get("enabled") == (not want_blocked)) and env_ok
        if not ok:
            failures.append(
                f"export_switch[{label}]: env={val!r} parsed={parsed} "
                f"POST={post.status_code} DL={dl.status_code} "
                f"status.enabled={st.get('enabled')} — expected "
                f"{'BLOCKED (503 on both)' if want_blocked else 'open'}; the export "
                "releases real breached passwords and must fail closed, including "
                "the download route")
        print(f"  [{'PASS' if ok else 'FAIL'}] export_switch:{label:<18} "
              f"env={str(val):<6} POST={post.status_code} DL={dl.status_code} "
              f"enabled={st.get('enabled')}")


# (h) PROVIDER BUDGET GUARD. The guard existed but was decorative: caps were
# placeholders 20x above the real quota (1000/day vs IntelX's free 50/day) so it
# could never fire first, and the counters were in-process, so every deploy
# handed the box a fresh allowance it did not have. The durable `usage` table
# recorded every call and had no reader. Two subtleties are asserted here because
# both were got wrong on the first attempt:
#   * a FRESH ledger (i.e. after a restart) must inherit the day's durable spend;
#   * a STALE durable read must not hand out allowance already spent — anchoring
#     to max(durable, in-process) silently overruns the cap by up to one cache
#     TTL's worth of calls, which is why the delta is measured from the
#     in-process counter at fetch time instead.
def _check_provider_budget(failures):
    import importlib
    P = importlib.import_module("providers")

    def L(cap):
        return P.DurableUsageLedger(default_daily_cap=None, daily_caps={"intelx": cap},
                                    retry_cap_per_window=50, retry_window_seconds=300)

    checks = []

    # real quota, not a placeholder
    # The cap is in HTTP CALLS, not searches: a live scan on 2026-07-28 showed one
    # IntelX search costs 4 calls (1 initiate + 3 polls). Asserting 50 here — the
    # search quota — is what shipped a cap that would throttle at a quarter of the
    # real allowance. Assert the CALL budget covers 50 searches instead.
    ix_cap = P._LEDGER.caps().get("intelx")
    checks.append(("real_quota_unit", ix_cap is not None and ix_cap >= 50 * 4,
                   f"intelx cap={ix_cap} calls — one search costs up to 4 calls, so a "
                   "50-search/day free tier needs a 200-call budget; a lower value "
                   "throttles while quota remains and wrongly marks dark-web unassessed"))

    # the cap binds
    l = L(3)
    with mock.patch.object(l, "_durable_spend", return_value=0):
        seq = []
        for _ in range(5):
            a = l.allow_call("intelx")
            seq.append(a)
            if a:
                l.record_call("intelx")
    checks.append(("cap_binds", seq == [True, True, True, False, False],
                   f"cap=3 produced {seq} — the cap must stop the 4th call"))

    # survives a restart
    f = L(50)
    with mock.patch.object(f, "_durable_spend", return_value=48):
        rem0 = f.remaining("intelx")
        f.record_call("intelx"); f.record_call("intelx")
        after = f.allow_call("intelx")
    checks.append(("survives_restart", rem0 == 2 and after is False,
                   f"a fresh ledger saw remaining={rem0} then allow={after} — it must "
                   "inherit the durable count, not restart the day's allowance at zero"))

    # stale cache must not overrun
    s = L(50)
    with mock.patch.object(s, "_durable_spend", return_value=49):
        s.spend_today("intelx")        # prime the cache
        s.record_call("intelx")        # the 50th call
        overran = s.allow_call("intelx")
    checks.append(("stale_cache", overran is False,
                   "a call made after the durable snapshot was not counted — the cap "
                   "overruns by up to one cache TTL"))

    # metering must never block a scan
    b = L(50)
    with mock.patch("scanner_db.usage_for", side_effect=RuntimeError("db down")):
        okfail = b.allow_call("intelx")
    checks.append(("fails_open_on_db_error", okfail is True,
                   "a metering failure blocked a provider call — accounting must never "
                   "take the scanner down"))

    for label, ok, why in checks:
        if not ok:
            failures.append(f"provider_budget[{label}]: {why}")
        print(f"  [{'PASS' if ok else 'FAIL'}] provider_budget:{label:<24} {ok}")


# (i) LOOKALIKE POSTURE. "4 lookalikes resolve" is not actionable; what decides
# danger is whether a domain can SEND MAIL as the client. Ground truth from the
# real phishield.com self-scan (2026-08-06):
#   phisheild.com  Namecheap PrivateEmail + 5 forwarders, Cloudflare  -> HIGH
#   hishield.com   GoDaddy secureserver MX, 411-byte parking page     -> HIGH
#   phshield.com   NULL MX ("0 .") + SPF -all, Afternic for-sale      -> NOT high
#   pishield.com   no MX, 114-byte parking page                       -> LOW
# The null-MX case is the trap: a first pass treated any non-empty MX answer as
# mail-capable and labelled phshield.com a phishing risk, when RFC 7505 "0 ."
# declares the exact opposite. Asserted offline so no scan or DNS is needed.
MX_SCENARIOS = [
    ("null mx",        ["0 ."],                        0, True),
    ("real mx",        ["10 mx1.privateemail.com."],   1, False),
    ("mixed",          ["0 .", "10 mx1.example.com."], 1, False),
    ("absent",         [],                             0, False),
]
# (label, entry, expected risk)
VERDICT_SCENARIOS = [
    ("mail, no site (phisheild profile)",
     {"mail_capable": True, "serves_content": False, "similarity": 89}, "high"),
    ("mail + live site",
     {"mail_capable": True, "serves_content": True, "similarity": 89}, "high"),
    ("null mx, parked for sale (phshield profile)",
     {"mail_capable": False, "null_mx": True, "listed_for_sale": True,
      "serves_content": False, "similarity": 89}, "medium"),
    ("no mail, parked (pishield profile)",
     {"mail_capable": False, "null_mx": False, "serves_content": False,
      "similarity": 89}, "low"),
]


def _check_edge_measured_labelling(failures):
    """When the web assessment measured a CDN edge, the report must say so.

    boston.ac.za, 2026-08-14: 97 out of 1000, Low risk, 100 per cent
    completeness, no failed checkers, measured against Cloudflare. The client's
    own estate WAS discovered and port-scanned; every web-layer verdict
    described the provider, and nothing in the report said which was which.

    Also asserts the free origin-candidate path, because the fix that made it
    possible is worth nothing if the candidates never reach the verifier.
    """
    import importlib
    pc = importlib.import_module("pdf_cards")
    ph = importlib.import_module("pdf_helpers")
    od = importlib.import_module("origin_discovery")
    S = ph.build_styles()

    CASES = [
        ("edge_measured", {"edge_measured_checkers": ["ssl", "http_headers"],
                           "edge_provider": "Cloudflare"}, True),
        ("origin_verified", {}, False),
        ("no_cdn", {}, False),
    ]
    for label, sc, expect in CASES:
        out = pc.estate_edge_notice({"_scan_completeness": sc}, S)
        got = len(out) > 0
        ok = got == expect
        if not ok:
            failures.append(
                "edge_labelling[%s]: notice rendered=%s, expected %s. A web "
                "assessment that measured the provider's edge must say so, and "
                "must stay silent otherwise." % (label, got, expect))
        print("  [%s] edge_label:%-18s rendered=%s"
              % ("PASS" if ok else "FAIL", label, got))

    # The notice must name the affected checkers and refuse the clean reading.
    txt = pc.estate_edge_notice(
        {"_scan_completeness": {"edge_measured_checkers": ["ssl"],
                                "edge_provider": "Cloudflare"}}, S)[1].text
    needed = ["Cloudflare", "ssl", "not evidence about the client",
              "must not be read as a clean result"]
    missing = [n for n in needed if n not in txt]
    if missing:
        failures.append("edge_labelling[wording]: the notice omits %s" % missing)
    print("  [%s] edge_label:wording           omits=%s"
          % ("FAIL" if missing else "PASS", missing or "nothing"))

    # Free origin candidates: local addresses must be offered to the verifier,
    # edge addresses must not, and no key may be required to try.
    LOCAL = ["196.41.30.122", "104.26.3.40", "20.126.184.33", "2606:4700::1"]
    with mock.patch.object(od, "_verify_origin", lambda ip, d: False):
        res = od.discover_origin_ips("example.test", None, None,
                                     extra_candidates=LOCAL)
    cands = res.get("candidates") or []
    edge_leaked = "104.26.3.40" in cands
    v6_leaked = any(":" in c for c in cands)
    ok = (res.get("status") == "completed" and "196.41.30.122" in cands
          and not edge_leaked and not v6_leaked)
    if not ok:
        failures.append(
            "edge_labelling[local_candidates]: status=%s candidates=%s. Locally "
            "resolved non-edge addresses must be offered to origin verification "
            "with no API key, and edge addresses must never be, since the edge "
            "is what the discovery is trying to bypass."
            % (res.get("status"), cands))
    print("  [%s] edge_label:local_candidates  candidates=%s edge_leaked=%s"
          % ("PASS" if ok else "FAIL", cands, edge_leaked))


# ---- SaaS service-range attribution (OUTSTANDING 5q, 2026-09-09) ------------
#
# THE DEFECT. ip_classification defaulted an address to the insured whenever no
# vendor signal fired, and the Shodan-org rule made it worse by returning the
# positive claim "cloud IaaS (insured-operated)". Measured on 30 retained scans,
# 174 of 307 addresses attributed to the insured were Microsoft 365 service
# endpoints: Exchange Online front ends behind autodiscover / mail / mta-sts
# names. A finding on any of them would have been priced as the client's.
#
# THE BOUNDARY IS THE WHOLE DESIGN, so this gate asserts the KEEP side at least
# as hard as the DEMOTE side. The cheapest way to "fix" a red build here is to
# widen a prefix, and a widened prefix silently deletes customer-run cloud hosts
# from the priced estate. MUTATION M2 exists to make that impossible to land.
SAAS_DEMOTE = [
    # (label, ip, reverse_dns, org) -> must classify SAAS.
    ("exo_v4_no_ptr",        "52.98.22.8",   None, "Microsoft Corporation"),
    ("exo_v4_40_104",        "40.104.15.56", None, "Microsoft Corporation"),
    ("exo_v4_52_98_20",      "52.98.20.136", None, "Microsoft Corporation"),
    # The IPv6 rows are the important ones: no PTR, no Shodan record, no banner.
    # Address membership is the ONLY signal that exists for these hosts, which is
    # why a PTR-suffix or org-string rule could never have reached them.
    ("exo_v6_c1c",           "2603:1006:2:c1c::8",  None, None),
    ("exo_v6_102a",          "2603:1006:2:102a::8", None, None),
    ("exo_v6_1029",          "2603:1006:2:1029::8", None, None),
]

SAAS_KEEP = [
    # (label, ip, reverse_dns, org) -> must stay OWNED and stay scanned.
    # Generic Azure customer space. Microsoft org, no PTR, and NOT in any
    # published service range. This is boston's mta-sts host: genuinely not the
    # college's, but no offline non-gameable signal reaches it, so it stays
    # OWNED rather than being demoted on a widened prefix. Pinned here so a
    # later widening cannot quietly capture it.
    ("azure_generic_mta_sts", "20.126.184.33",  None, "Microsoft Corporation"),
    # Client-run Azure hosts, measured in the corpus behind portal.nexgro.co.za
    # and ifrs9.bdo.co.za. Same org string as every row above.
    ("azure_customer_vm",     "20.164.162.95",  None, "Microsoft Corporation"),
    ("azure_customer_vm2",    "20.87.11.76",    None, "Microsoft Corporation"),
    # Our own GCE box behind veilguard.phishield.com. If an org-based rule ever
    # ships, this row is the one that catches it.
    ("gce_own_infra",         "34.35.151.242",  None, "Google LLC"),
    ("gce_customer_vm",       "35.190.68.223",
     "223.68.190.35.bc.googleusercontent.com", "Google LLC"),
    # A client-run Linode PBX behind sip.cyberres.co.za carrying 19 CVEs. This
    # is the address that killed the subdomain-provenance rule: "every name on
    # this host is a service label" demoted it along with the real endpoints.
    ("linode_customer_pbx",   "213.219.38.226", None, "Linode, LLC"),
    # DataPro's shared IronPort. The honest residual: genuinely vendor-operated,
    # not reachable by any offline non-gameable signal, so it stays OWNED. A row
    # that flips this to SAAS is a FAILURE, not an improvement -- it would mean
    # the table grew to cover space DataPro never published.
    ("datapro_ironport",      "196.41.30.122",
     "ironport.datapro.co.za", "DataPro Infrastructure"),
    # Exchange Online Protection by function, but in 104.47.128.0/17, the UPPER
    # half, which Microsoft does NOT publish (the feed lists 104.47.0.0/17). The
    # design pass asserted this address was covered; it is not. Pinned as a KEEP
    # so that nobody "completes" the table by hand to make boston look tidy.
    ("eop_unpublished_half",  "104.47.164.119", None, "Microsoft Corporation"),
]

# Addresses that must NEVER appear inside the shipped table, asserted against
# the ranges directly rather than through classify_ip. This turns the build
# check from pressure-to-widen into pressure-to-narrow.
SAAS_NON_CONTAINMENT = [
    "34.35.151.242", "20.164.162.95", "20.87.11.76", "35.190.68.223",
    "20.126.184.33", "3.92.120.28", "104.199.105.60", "102.219.50.40",
    "213.219.38.226", "169.255.29.162", "102.218.213.68", "156.38.174.226",
    "104.47.164.119", "196.41.30.122",
]


def _check_saas_service_ranges(failures):
    import ipaddress
    import importlib
    import subprocess

    ipc = importlib.import_module("ip_classification")
    sr = importlib.import_module("saas_ranges")

    demoted = 0
    for label, ip, rdns, org in SAAS_DEMOTE:
        bucket, prov = ipc.classify_ip(ip, reverse_dns=rdns, org=org)
        ok = (bucket == ipc.SAAS)
        demoted += int(ok)
        if not ok:
            failures.append(
                "saas_range[%s]: %s -> %r (%s), expected SAAS" % (label, ip, bucket, prov))
        print("  [%s] saas_demote:%-22s -> %s" % ("PASS" if ok else "FAIL", label, bucket))

    for label, ip, rdns, org in SAAS_KEEP:
        bucket, prov = ipc.classify_ip(ip, reverse_dns=rdns, org=org)
        ok = (bucket == ipc.OWNED)
        if not ok:
            failures.append(
                "saas_keep[%s]: %s -> %r (%s), expected OWNED. A KEEP row that "
                "flips to a vendor bucket means the table captured customer "
                "space -- that deletes real client exposure." % (label, ip, bucket, prov))
        print("  [%s] saas_keep:%-24s -> %s" % ("PASS" if ok else "FAIL", label, bucket))

    # Non-containment, asserted against the table itself.
    for ip in SAAS_NON_CONTAINMENT:
        hit = sr.service_provider(ip)
        if hit:
            failures.append("saas_non_containment: %s is inside the shipped "
                            "table (%s); it must not be" % (ip, hit))
    print("  [%s] saas:non_containment (%d addresses)"
          % ("PASS" if not any("non_containment" in f for f in failures) else "FAIL",
             len(SAAS_NON_CONTAINMENT)))

    # Prefix floors. A range wider than these cannot be a service endpoint block.
    wide = []
    for label, cidrs in sr.SERVICE_RANGES.items():
        for c in cidrs:
            n = ipaddress.ip_network(c)
            floor = sr.MIN_V6_PREFIX if n.version == 6 else sr.MIN_V4_PREFIX
            if n.prefixlen < floor:
                wide.append(c)
    if wide:
        failures.append("saas_prefix_floor: %s wider than the floors" % wide)
    print("  [%s] saas:prefix_floors (%d prefixes)"
          % ("PASS" if not wide else "FAIL",
             sum(len(v) for v in sr.SERVICE_RANGES.values())))

    # The table must equal what the committed feed artefact yields. Catches a
    # hand-edited CIDR, which is exactly how the wrong 104.47.128.0/17 would
    # have entered.
    try:
        r = subprocess.run([sys.executable, "tooling/gen_saas_ranges.py", "--check"],
                           cwd=SEC, capture_output=True, text=True, timeout=90)
        ok = (r.returncode == 0)
        if not ok:
            failures.append("saas_artefact_parity: %s" % (r.stdout or r.stderr).strip()[:300])
        print("  [%s] saas:artefact_parity" % ("PASS" if ok else "FAIL"))
    except Exception as e:
        failures.append("saas_artefact_parity: could not run generator (%s)" % e)
        print("  [FAIL] saas:artefact_parity")

    # ---- MUTATION M1: rule off. Every DEMOTE row must revert to OWNED. -------
    # A DEMOTE row that still passes with the table disabled is being decided by
    # a pre-existing path, not by this fix, and proves the row tests nothing.
    _real = sr.service_provider
    try:
        ipc._service_provider = lambda _ip: None
        survivors = [label for label, ip, rdns, org in SAAS_DEMOTE
                     if ipc.classify_ip(ip, reverse_dns=rdns, org=org)[0] == ipc.SAAS]
    finally:
        ipc._service_provider = _real
    if survivors:
        failures.append(
            "MUTATION M1: %d DEMOTE row(s) still classify SAAS with the range "
            "table disabled (%s). Those rows are not exercising this fix."
            % (len(survivors), survivors))
    print("  [%s] saas:MUTATION_M1 rule-off reverts %d/%d rows"
          % ("PASS" if not survivors else "FAIL",
             len(SAAS_DEMOTE) - len(survivors), len(SAAS_DEMOTE)))
    if demoted == 0:
        failures.append("MUTATION M1 is vacuous: zero DEMOTE rows passed in the "
                        "first place, so reverting them proves nothing.")

    # ---- MUTATION M2: table widened. Must be REFUSED BY THE MODULE ITSELF. --
    # 40.104.0.0/15 is a real Exchange Online prefix. 40.64.0.0/10 is the coarse
    # Azure allocation that provably contains it and also contains customer VMs.
    # That is the edit a red build tempts an implementer into.
    #
    # THIS EXECUTES A MUTATED COPY OF THE REAL saas_ranges.py SOURCE and requires
    # the import to raise. An earlier version of this check re-implemented the
    # prefix-floor loop here and asserted on the gate's OWN arithmetic. It passed
    # for a while after the module's `raise ValueError` guard had been lost
    # entirely, because the gate was only ever testing that MIN_V4_PREFIX existed
    # and that 10 < 12. gen_saas_ranges --check could not catch it either: it
    # proves the table matches the generator, and the generator had lost the same
    # three lines, so the two agreed with each other about the wrong thing.
    src_path = os.path.join(SEC, "saas_ranges.py")
    with io.open(src_path, encoding="utf-8") as _fh:
        _src = _fh.read()
    if '"40.104.0.0/15"' not in _src:
        failures.append("MUTATION M2 is vacuous: 40.104.0.0/15 is no longer in "
                        "saas_ranges.py, so the widening it guards cannot be "
                        "tested. Point it at a prefix that is present.")
    mutated = _src.replace('"40.104.0.0/15"', '"40.64.0.0/10"')
    refused = None
    try:
        exec(compile(mutated, "<saas_ranges widened>", "exec"), {"__name__": "_m2"})
    except ValueError as e:
        refused = str(e)
    except Exception as e:
        refused = "%s: %s" % (type(e).__name__, e)
    if not refused:
        failures.append(
            "MUTATION M2: saas_ranges.py imported cleanly with 40.104.0.0/15 "
            "widened to the /10 Azure allocation. The module's own prefix-floor "
            "guard is missing or ineffective, so that edit would land and pull "
            "customer-run Azure VMs into the vendor bucket, deleting their "
            "findings from insureds' estates.")
    print("  [%s] saas:MUTATION_M2 module refuses a widened table (%s)"
          % ("PASS" if refused else "FAIL", (refused or "NOT REFUSED")[:64]))

    # M2b: prove M2 is not passing for an unrelated reason. The UNmutated source
    # must import cleanly; if it also raises, M2's signal means nothing.
    try:
        exec(compile(_src, "<saas_ranges pristine>", "exec"), {"__name__": "_m2b"})
        clean_ok = True
    except Exception as e:
        clean_ok = False
        failures.append("MUTATION M2b: the UNmutated saas_ranges.py does not "
                        "import cleanly (%s), so M2 proves nothing." % e)
    print("  [%s] saas:MUTATION_M2b pristine table imports cleanly"
          % ("PASS" if clean_ok else "FAIL"))



# ---- Estate floor: an unmeasured estate must not read as a clean one --------
#
# WHY THIS IS A GATE AND NOT A HARNESS ROW. The SaaS attribution work added a
# no_own_estate_assessed state for the case where every address discovered for a
# client turns out to be operated by a provider, so the checkers ran against
# nobody's infrastructure but a vendor's. NO FIXTURE IN THE 30-SCAN CORPUS
# REACHES IT: measured, the worst case leaves one own-attributed host, not zero.
# An untested branch on a scoring path is a defect by itself, so the condition
# is driven directly here instead of being left to a corpus that cannot reach
# it. If a later change makes the corpus reach it, this still holds.
#
# The third row is the one that stops the branch over-firing: an estate that was
# empty from the start is NOT this failure, and must not be relabelled.
NO_OWN_ESTATE_SCENARIOS = [
    # (label, own_ips, vendor_ips, expected_estate_confidence, capped?)
    ("normal_mixed_estate",   9, 6, "assessed",               False),
    ("all_hosts_are_vendor",  0, 6, "no_own_estate_assessed", True),
    ("nothing_discovered",    0, 0, "assessed",               False),
    ("no_vendor_hosts",       3, 0, "assessed",               False),
]


def _check_no_own_estate(failures):
    from scoring_analytics import RiskScorer

    # DRIVEN THROUGH THE REAL AGGREGATOR, not a hand-built dict. The first
    # version of this check constructed external_ips by hand and passed while
    # the branch was UNREACHABLE in production: ExternalIPAggregator.aggregate
    # returned early on an empty own pool, 150 lines before it wrote
    # vendor_ip_count, so the field the ladder reads was never set in exactly
    # the case the ladder exists for. Testing a consumer with synthetic input
    # proves the consumer works and says nothing about whether the producer
    # ever supplies it.
    from scoring_analytics import ExternalIPAggregator

    for label, own, vendor, expected, capped in NO_OWN_ESTATE_SCENARIOS:
        own_ips = ["10.20.30.%d" % (i + 1) for i in range(own)]
        vendor_addrs = ["52.98.20.%d" % (i + 1) for i in range(vendor)]
        ext = ExternalIPAggregator.aggregate(
            own_ips, {ip: {} for ip in own_ips}, vendor_ips=vendor_addrs)
        if ext.get("vendor_ip_count") != vendor:
            failures.append(
                "no_own_estate[%s]: the aggregator returned vendor_ip_count=%r "
                "for %d vendor address(es). The ladder below reads that field, "
                "so a missing value makes the whole branch unreachable."
                % (label, ext.get("vendor_ip_count"), vendor))
        cats = {"external_ips": ext}
        RiskScorer().calculate(cats)
        sc = cats.get("_scan_completeness") or {}
        got = sc.get("estate_confidence")
        conf = sc.get("confidence_level")
        note = sc.get("estate_note") or ""
        ok = (got == expected)
        if not ok:
            failures.append("no_own_estate[%s]: estate_confidence %r != %r"
                            % (label, got, expected))
        if capped and conf == "full":
            failures.append(
                "no_own_estate[%s]: every discovered address belongs to a "
                "provider, yet confidence_level is still 'full'. An estate "
                "nobody measured must never read as fully assessed." % label)
            ok = False
        if capped and not note:
            failures.append("no_own_estate[%s]: no estate_note explaining why "
                            "the score is qualified" % label)
            ok = False
        if not capped and note:
            failures.append("no_own_estate[%s]: estate_note set on a scan that "
                            "did assess own hosts (%r)" % (label, note[:60]))
            ok = False
        print("  [%s] no_own_estate:%-22s -> %s / %s"
              % ("PASS" if ok else "FAIL", label, got, conf))

    # MUTATION: make the condition fire on an estate that was empty to begin
    # with. That would relabel every domain with no discovered addresses as an
    # unmeasured estate, which is a different and wrong claim.
    cats = {"external_ips": ExternalIPAggregator.aggregate([], {}, vendor_ips=[])}
    RiskScorer().calculate(cats)
    over = (cats.get("_scan_completeness") or {}).get("estate_confidence")
    if over == "no_own_estate_assessed":
        failures.append("no_own_estate MUTATION: the branch fires when NOTHING "
                        "was discovered. The condition must require that "
                        "addresses were found and all went to a vendor.")
    print("  [%s] no_own_estate:MUTATION over-fire guard"
          % ("PASS" if over != "no_own_estate_assessed" else "FAIL"))


# ---- Attribution confidence + co-tenancy (OUTSTANDING 5q, 2026-09-09) -------
#
# THE CASE THIS EXISTS FOR. boston.ac.za's ONLY per-IP finding is a Spamhaus
# listing on 20.126.184.33. That address is generic Azure space, so the
# published-service-range rule correctly does not touch it and it stays OWNED
# and scanned. But Shodan records mta-certs.sendmarc.com and
# mta-sts-policy.d.msp.proofpoint.com on it -- two unrelated third parties --
# and the SAME address appears on takealot.com's scan. Without this rule the
# report tells a college to investigate a spam blacklisting on a shared
# mail-assurance host that is not theirs.
#
# CO-TENANCY MUST NEVER MOVE A BUCKET. The signal rests partly on names the
# host's operator publishes, and an insured with custom reverse DNS could forge
# co-tenants. That is only tolerable because the rule is conservative in one
# direction: forging gets a host FLAGGED, never discounted. The KEEP rows below
# are what hold that line.
ATTRIBUTION_SCENARIOS = [
    # (label, ip, hostnames, reverse_dns, insured, expected_rule)
    ("shared_mta_sts_host", "20.126.184.33",
     ["mta-certs.sendmarc.com", "mta-sts-policy.d.msp.proofpoint.com"],
     None, "boston.ac.za", "co_tenancy"),
    # Dedicated servers whose PTR merely names the HOSTING PROVIDER. A naive
    # version of this rule flagged 27 such addresses carrying 204 CVEs.
    ("dedicated_host_h_net", "197.221.12.39", [],
     "dedi376.cpt4.host-h.net", "excellentmeat.co.za", "defaulted"),
    ("dedicated_jnb3", "156.38.230.15", [],
     "dedi918.jnb3.host-h.net", "mcare.co.za", "defaulted"),
    ("serverflex_shared_ptr", "156.38.174.226", ["ms1.serverflex.co.za"],
     "ms1.serverflex.co.za", "aggregato.co.za", "defaulted"),
    # THE ROW THAT MAKES MUTATION M3 MEAN SOMETHING. Real corpus data:
    # 102.222.124.23 is ibis.aserv.co.za and also answers for redalert.co.za.
    # aserv.co.za is a hosting provider's own zone, so with the infra-zone
    # filter ON there is ONE foreign tenant and the row stays "defaulted"; with
    # it OFF there are two and the row flips to co_tenancy. Without a row shaped
    # like this, M3 turns the filters off and nothing changes, which is how it
    # reported itself toothless the first time it ran.
    ("aserv_provider_zone", "102.222.124.23",
     ["www.redalert.co.za", "ibis.aserv.co.za", "mail.redalert.co.za"],
     "ibis.aserv.co.za", "cyberres.co.za", "defaulted"),
    # Same shape for an address-derived name: the Linode PTR is the address
    # rewritten, so with the derived-name filter OFF it counts as a tenant.
    ("linode_address_derived_pair", "213.219.38.226",
     ["213-219-38-226.ip.linodeusercontent.com", "sip.example-vendor.com"],
     "213-219-38-226.ip.linodeusercontent.com", "cyberres.co.za", "defaulted"),
    ("datapro_ironport", "196.41.30.122", [],
     "ironport.datapro.co.za", "boston.ac.za", "defaulted"),
    # Address-derived names are the address rewritten, not tenant identities.
    ("ec2_address_derived", "3.92.120.28", [],
     "ec2-3-92-120-28.compute-1.amazonaws.com", "example.com", "defaulted"),
    ("gce_address_derived", "35.190.68.223", [],
     "223.68.190.35.bc.googleusercontent.com", "bbgroup.co.za", "defaulted"),
    # The insured's own names must never count as foreign tenants.
    ("own_names_only", "1.2.3.4", ["mail.x.co.za", "www.x.co.za"],
     "mail.x.co.za", "x.co.za", "ptr_in_insured_zone"),
    # A single foreign name is not co-tenancy; two or more is.
    ("one_foreign_name", "5.6.7.8", ["something.vendor.com"], None,
     "x.co.za", "defaulted"),
]


def _check_attribution_confidence(failures):
    import importlib
    ia = importlib.import_module("ip_attribution")

    # Fresh-process import-order guard: estate_discovery imports related-domain
    # helpers, so the canonical reducer must remain lazy and provider-zone
    # rejection must survive either import order.
    import subprocess as _sp, sys as _sys
    _probe = ("import sys;sys.path.insert(0,%r);%s;import ip_attribution as ia;"
              "print(ia.attribution_for('156.38.174.226','owned','',"
              "hostnames=['ms1.serverflex.co.za'],"
              "reverse_dns='ms1.serverflex.co.za',insured_domain='aggregato.co.za')[1])")
    for _order in ("import ip_attribution;import estate_discovery",
                   "import estate_discovery;import ip_attribution"):
        _p = _sp.run([_sys.executable, "-c", _probe %
                      (os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), _order)],
                     capture_output=True, text=True, timeout=20)
        if not (_p.returncode == 0 and "defaulted" in _p.stdout):
            failures.append("registry import order/provider-zone guard failed: %s" % _order)

    # Registry consistency: confidence and estate discovery must use one
    # reducer. Keep these boundary cases narrow; this is not a PSL expansion.
    from estate_discovery import registrable
    registry_cases = (("stjohns.school.za", "stjohns.school.za"),
                      ("www.acme.co.za", "acme.co.za"),
                      ("example.com", "example.com"),
                      ("school.za", ""))
    for host, expected_apex in registry_cases:
        got = ia.registrable_domain(host)
        ok = (got == expected_apex and got == registrable(host))
        if not ok:
            failures.append("registry[%s]: %r != %r" %
                            (host, got, expected_apex))
        print("  [%s] attribution:registry:%-18s -> %s" %
              ("PASS" if ok else "FAIL", host, got))

    for label, ip, hostnames, rdns, insured, expected in ATTRIBUTION_SCENARIOS:
        conf, rule, ev = ia.attribution_for(
            ip, "owned", "", hostnames=hostnames, reverse_dns=rdns,
            insured_domain=insured)
        ok = (rule == expected)
        if not ok:
            failures.append("attribution[%s]: %s -> rule %r != %r (%s)"
                            % (label, ip, rule, expected, ev[:80]))
        print("  [%s] attribution:%-22s -> %s / %s"
              % ("PASS" if ok else "FAIL", label, conf, rule))

    # Positive-proof tiers must not collapse into the default.
    proofs = [
        ("verified_origin", dict(ip_sources=["verified_origin"]), "cert_verified_origin"),
        ("apex_record", dict(apex_ips=["9.9.9.9"]), "apex_record"),
    ]
    for label, kw, expected in proofs:
        _c, rule, _e = ia.attribution_for("9.9.9.9", "owned", "",
                                          insured_domain="x.co.za", **kw)
        ok = (rule == expected)
        if not ok:
            failures.append("attribution[%s]: rule %r != %r" % (label, rule, expected))
        print("  [%s] attribution:%-22s -> %s" % ("PASS" if ok else "FAIL", label, rule))

    # ORDERING: co-tenancy must beat the positive proofs. Real corpus case --
    # mcare.co.za's 156.38.230.15 is a shared cPanel box (dedi918.jnb3.host-h.net)
    # that also serves crestchoicechickens.com and ffg.co.za, AND it is mcare's
    # own apex A record. Checking the apex rule first returned "confirmed" and
    # silenced the warning on exactly the case it exists for. An SME on shared
    # hosting always points its apex at the provider's box, so publishing an A
    # record proves the client USES the host, never that it OPERATES it.
    _c, rule, _e = ia.attribution_for(
        "156.38.230.15", "owned", "",
        hostnames=["crestchoicechickens.com", "ffg.co.za", "dedi918.jnb3.host-h.net"],
        reverse_dns="dedi918.jnb3.host-h.net", insured_domain="mcare.co.za",
        apex_ips=["156.38.230.15"])
    ok = (rule == "co_tenancy")
    if not ok:
        failures.append(
            "attribution[apex_does_not_beat_cotenancy]: rule %r != 'co_tenancy'. "
            "A shared host that is also the insured's apex A record is being "
            "reported as confirmed ownership." % rule)
    print("  [%s] attribution:%-22s -> %s"
          % ("PASS" if ok else "FAIL", "apex_loses_to_cotenancy", rule))

    # A vendor bucket must report vendor confidence, never "confirmed".
    conf, rule, _e = ia.attribution_for("52.98.22.8", "saas",
                                        "Microsoft 365 (Exchange Online)")
    ok = (conf == ia.VENDOR)
    if not ok:
        failures.append("attribution[vendor_bucket]: confidence %r != vendor" % conf)
    print("  [%s] attribution:%-22s -> %s" % ("PASS" if ok else "FAIL",
                                              "vendor_bucket", conf))

    # ---- MUTATION M3: exclusions off. MUST make the gate fail. --------------
    # Disabling the provider-infrastructure-zone and address-derived filters is
    # the "simplification" that looks harmless and is not: measured on the
    # corpus it flags 27 addresses carrying 204 CVEs, including two literally
    # DEDICATED servers. This proves the exclusions are load-bearing.
    real_infra, real_derived = ia._is_infra_zone, ia._is_address_derived
    try:
        ia._is_infra_zone = lambda _h: False
        ia._is_address_derived = lambda _h, _ip: False
        swept = [label for label, ip, hn, rdns, insured, expected
                 in ATTRIBUTION_SCENARIOS
                 if expected == "defaulted"
                 and ia.attribution_for(ip, "owned", "", hostnames=hn,
                                        reverse_dns=rdns,
                                        insured_domain=insured)[1] == "co_tenancy"]
    finally:
        ia._is_infra_zone, ia._is_address_derived = real_infra, real_derived
    # With both filters off, a provider PTR plus any other name reads as
    # co-tenancy. At least one KEEP row must flip, or the filters are inert.
    if not swept:
        failures.append(
            "MUTATION M3 is toothless: turning off the infra-zone and "
            "address-derived filters changed no KEEP row, so those filters are "
            "not actually what protects the 204 CVEs on dedicated servers. "
            "Either the scenarios do not exercise them or the rule has moved.")
    print("  [%s] attribution:MUTATION_M3 exclusions load-bearing (%d row(s) flip)"
          % ("PASS" if swept else "FAIL", len(swept)))


# ---- The gate must not be able to lose a check silently --------------------
#
# MUTATION F, from the step-3 critique: a _check_* function can be unwired from
# the runner while the gate still prints its PASS banner. Deleting one call
# removes a guard and nothing says so, which is the same false-green shape as a
# source check matching its own comment or a comparison running over zero
# scenarios. Both have shipped here before.
#
# This closes the CLASS rather than one instance. It parses this file's own AST,
# collects every _check_* function defined at module level and every _check_*
# called anywhere, and fails on any that is defined but never invoked. AST and
# not text: a name appearing inside a comment or a docstring must not count as
# wiring, which is precisely how the earlier false green happened.
def _check_gate_self_wiring(failures):
    import ast

    src_path = os.path.abspath(__file__)
    with io.open(src_path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())

    defined, called = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("_check_"):
            defined.add(node.name)
        elif isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name and name.startswith("_check_"):
                called.add(name)

    # This function is invoked by the runner like any other, so it appears in
    # both sets; nothing special-cased.
    orphans = sorted(defined - called - {"_check_gate_self_wiring"})

    if not defined:
        failures.append("gate_self_wiring: found ZERO _check_* definitions. The "
                        "parse is looking at the wrong file and proves nothing.")
    if orphans:
        failures.append(
            "gate_self_wiring: %d check(s) are DEFINED BUT NEVER CALLED (%s). "
            "An unwired check leaves the PASS banner intact while the guard it "
            "provides is gone." % (len(orphans), ", ".join(orphans)))
    print("  [%s] gate:self_wiring %d defined, %d wired, %d orphaned"
          % ("PASS" if (defined and not orphans) else "FAIL",
             len(defined), len(defined) - len(orphans), len(orphans)))


# ---- Feed-backed CDN edge table (step 3, 2026-09-10) -----------------------
#
# cdn_ranges was hand-curated and had rotted: against the operators' own feeds
# it was missing 216 of AWS CloudFront's 243 prefixes (66% of its v4 space) and
# 6 of Fastly's 21, while carrying 3 CloudFront and 1 Fastly prefix the operator
# no longer publishes. AWS reassigns retired CloudFront space to other services,
# so a stale entry can demote an EC2 instance belonging to somebody else.
#
# The same boundary discipline as the SaaS table applies: the KEEP side matters
# at least as much as the DETECT side, because a CDN table that captures a
# customer host removes that host's findings from the priced estate.
CDN_DETECT = [
    ("cloudflare_v4",     "104.26.2.40",            "Cloudflare"),
    ("cloudflare_v6",     "2606:4700:20::681a:328", "Cloudflare"),
    # Both of these are in the 216 prefixes the curated table was missing, so
    # each row fails if the feed table is ever dropped back to the old list.
    ("cloudfront_added",  "205.251.249.5",          "AWS CloudFront"),
    ("cloudfront_added2", "23.228.249.5",           "AWS CloudFront"),
    ("fastly",            "151.101.1.1",            "Fastly"),
    # A provider with NO feed, still hand-curated. Proves the override replaced
    # only the feed-backed providers and left the rest intact.
    ("akamai_curated",    "23.32.0.1",              "Akamai"),
]

# Real client-run hosts from the retained corpus. None may be inside the CDN
# table, in either direction.
CDN_NON_CONTAINMENT = [
    "34.35.151.242", "20.164.162.95", "20.87.11.76", "35.190.68.223",
    "213.219.38.226", "3.92.120.28", "104.199.105.60", "102.219.50.40",
    "169.255.29.162", "102.218.213.68", "156.38.174.226", "196.41.30.122",
    "20.126.184.33",
]


def _check_cdn_feed_table(failures):
    import importlib
    import subprocess
    cr = importlib.import_module("cdn_ranges")

    for label, ip, expected in CDN_DETECT:
        got = cr.edge_provider(ip)
        ok = (got == expected)
        if not ok:
            failures.append("cdn_feed[%s]: %s -> %r, expected %r"
                            % (label, ip, got, expected))
        print("  [%s] cdn_feed:%-20s -> %s" % ("PASS" if ok else "FAIL", label, got))

    captured = [(ip, cr.edge_provider(ip)) for ip in CDN_NON_CONTAINMENT
                if cr.edge_provider(ip)]
    if captured:
        failures.append(
            "cdn_feed_non_containment: %s are inside the CDN table. A CDN table "
            "that captures a customer host deletes that host's findings from the "
            "insured's priced estate." % captured)
    print("  [%s] cdn_feed:non_containment (%d addresses)"
          % ("PASS" if not captured else "FAIL", len(CDN_NON_CONTAINMENT)))

    # The feed-backed providers must genuinely come from cdn_feeds, not from a
    # curated entry that quietly survived the override.
    try:
        feeds = importlib.import_module("cdn_feeds")
        overridden = [p for p in feeds.FEED_RANGES if p in cr.CDN_RANGES]
        live = {p for p, _n in cr._NETS}
        missing = [p for p in feeds.FEED_RANGES if p not in live]
        if missing:
            failures.append("cdn_feed: provider(s) %s are in cdn_feeds but "
                            "contribute no active ranges" % missing)
        for prov in overridden:
            curated = set(cr.CDN_RANGES[prov])
            active = {str(n) for p, n in cr._NETS if p == prov}
            leaked = sorted(curated - set(feeds.FEED_RANGES[prov]) & active)
            leaked = sorted(c for c in curated
                            if c not in feeds.FEED_RANGES[prov] and c in active)
            if leaked:
                failures.append(
                    "cdn_feed: curated prefix(es) %s for %s survived alongside "
                    "the feed. A withdrawn range that survives keeps demoting "
                    "hosts forever." % (leaked, prov))
        print("  [%s] cdn_feed:feed_is_authoritative (%d overridden)"
              % ("PASS" if not any("survived alongside" in f for f in failures)
                 else "FAIL", len(overridden)))
    except Exception as e:
        failures.append("cdn_feed: could not verify authority (%s)" % e)
        print("  [FAIL] cdn_feed:feed_is_authoritative")

    try:
        r = subprocess.run([sys.executable, "tooling/gen_cdn_ranges.py", "--check"],
                           cwd=SEC, capture_output=True, text=True, timeout=90)
        ok = (r.returncode == 0)
        if not ok:
            failures.append("cdn_feed_artefact_parity: %s"
                            % (r.stdout or r.stderr).strip()[:300])
        print("  [%s] cdn_feed:artefact_parity" % ("PASS" if ok else "FAIL"))
    except Exception as e:
        failures.append("cdn_feed_artefact_parity: could not run generator (%s)" % e)
        print("  [FAIL] cdn_feed:artefact_parity")


# ---- Origin exposed behind a fronted subdomain (OUTSTANDING 5o, 2026-09-10) --
#
# CloudCDNChecker resolves the APEX only, so where www sits behind a provider
# and the apex does not, the apex is very probably the origin: published in DNS,
# reachable directly, outside the edge the client pays for. Measured on the 30
# retained scans, 4 clients are in this state and two have services listening on
# the exposed origin (aggregato.co.za 3306/110/143/80/53/22, rbs.co.za
# 80/993/4190/2222/110).
#
# THE REMEDIATION EXCLUSIVITY IS THE POINT OF THIS GATE. Before the fix the
# ladder fired its generic "Deploy a CDN" row on exactly these clients, telling
# them to buy protection they already pay for. That is checkable by the client
# and costs the report its credibility at renewal, so the two rows must never
# both fire.
#
# REPORTING ONLY, asserted here. The exposed apex is already a scanned OWNED
# host whose CVEs and ports are counted; scoring the finding again would price
# one exposure twice.
ORIGIN_EXPOSURE_SCENARIOS = [
    # (label, apex_ips, subdomain->ips, apex_ports, expect_exposed, expect_sev)
    ("apex_outside_edge_nonweb", ["156.38.174.226"],
     {"www.x.co.za": ["104.26.2.40"]}, {"156.38.174.226": [3306, 22, 80]},
     True, "high"),
    ("apex_outside_edge_webonly", ["203.0.113.10"],
     {"www.x.co.za": ["104.26.2.40"]}, {"203.0.113.10": [80, 443]},
     True, "medium"),
    # The apex is itself fronted: nothing is disclosed, the client is behind the
    # edge where it counts.
    ("apex_is_fronted", ["104.26.2.40"],
     {"www.x.co.za": ["104.26.2.40"]}, {}, False, None),
    # No edge anywhere. This is the genuinely un-fronted client who SHOULD get
    # the generic "deploy a CDN" advice.
    ("no_edge_anywhere", ["203.0.113.10"],
     {"www.x.co.za": ["203.0.113.11"]}, {}, False, None),
    ("no_apex_recorded", [], {"www.x.co.za": ["104.26.2.40"]}, {}, False, None),
]


def _check_origin_exposure(failures):
    import importlib
    oe = importlib.import_module("origin_exposure")
    cr = importlib.import_module("cdn_ranges")
    sa = importlib.import_module("scoring_analytics")

    for label, apex, subs, ports, want, want_sev in ORIGIN_EXPOSURE_SCENARIOS:
        cats = {
            "cloud_cdn": {"ip_addresses": apex},
            "subdomains": {"resolved_ips": subs},
            "per_ip": {ip: {"shodan_vulns": {"open_ports": pl}}
                       for ip, pl in ports.items()},
        }
        got = oe.assess(cats, cr.edge_provider)
        ok = (bool(got.get("exposed")) == want
              and (got.get("severity") == want_sev))
        if not ok:
            failures.append(
                "origin_exposure[%s]: exposed=%r sev=%r, expected %r/%r (%s)"
                % (label, got.get("exposed"), got.get("severity"), want,
                   want_sev, got.get("reason")))
        print("  [%s] origin_exposure:%-26s -> exposed=%s sev=%s"
              % ("PASS" if ok else "FAIL", label, got.get("exposed"),
                 got.get("severity")))

    # THE TWO REMEDIATION ROWS MUST BE MUTUALLY EXCLUSIVE.
    rows = [(cond, action) for k, cond, action, _c, _d
            in sa.RemediationSimulator.REMEDIATION_MAP if k == "cloud_cdn"]
    for label, exposed, detected, want_move, want_deploy in [
            ("exposed_origin",  True,  False, True,  False),
            ("no_cdn_at_all",   False, False, False, True),
            ("fully_fronted",   False, True,  False, False)]:
        cat = {"cdn_detected": detected, "origin_exposure": {"exposed": exposed}}
        fired = [a for cond, a in rows if cond(cat)]
        move = any("Move the apex" in a for a in fired)
        deploy = any("Deploy a CDN" in a for a in fired)
        ok = (move == want_move and deploy == want_deploy)
        if not ok:
            failures.append(
                "origin_exposure_remediation[%s]: move=%r deploy=%r, expected "
                "%r/%r. Telling a client to deploy a CDN they already pay for "
                "is wrong, checkable by them, and costs the report its "
                "credibility." % (label, move, deploy, want_move, want_deploy))
        print("  [%s] origin_exposure_rem:%-22s move=%s deploy=%s"
              % ("PASS" if ok else "FAIL", label, move, deploy))

    # MUTATION: drop the exclusivity guard from the generic row. Both rows then
    # fire on an exposed-origin client, which is the defect this replaced.
    naive = [a for cond, a in rows if cond({"cdn_detected": False})]
    if len([a for a in naive if "Deploy a CDN" in a]) == 0:
        failures.append("origin_exposure MUTATION is vacuous: the generic row "
                        "no longer fires for an unfronted client at all, so the "
                        "exclusivity it guards cannot be tested.")
    print("  [%s] origin_exposure:MUTATION generic row still reachable"
          % ("PASS" if any("Deploy a CDN" in a for a in naive) else "FAIL"))


# ---- single_asn: PRODUCTION rule `unique_asns <= 1` (owner decision 2026-11-03)
#
# Owner decision, 3 November 2026: preserve production scoring. The OUTSTANDING
# 5s charge-on-evidence rule, (unique_asns == 1) or (unique_asns == 0 and
# vendor_ip_count > 0), is DEFERRED as its own rate decision and is not shipped.
# This guard asserts production behaviour: any count <= 1, INCLUDING 0, carries
# the +0.025 availability charge, with or without vendor hosts.
#
# Why the deferred rule exists is recorded beside single_asn in
# FinancialImpactCalculator: 0 means NOT COLLECTED, so <= 1 prices a count that
# was never measured (five of the 13 charged fixtures on the 30 retained scans).
#
# NEITHER GOLDEN FIXTURE EXERCISES THIS. phishield carries unique_asns=1 and
# takealot 2, so golden --check passes either way and proves nothing about this
# rule. That is exactly why the condition is driven directly here.
# (label, unique_asns, vendor_ip_count, should_charge)
SINGLE_ASN_SCENARIOS = [
    ("never_collected", 0, 0, True),
    ("zero_after_demotion", 0, 6, True),
    ("measured_single_asn", 1, 0, True),
    ("measured_single_w_vendor", 1, 6, True),
    ("measured_multi_homed", 2, 0, False),
    ("measured_multi_w_vendor", 2, 6, False),
    ("measured_many", 7, 0, False),
]


def _check_single_asn_measured(failures):
    import importlib
    sa = importlib.import_module("scoring_analytics")

    for label, ua, vendor_n, want in SINGLE_ASN_SCENARIOS:
        cats = {"external_ips": {"unique_asns": ua, "total_unique_ips": 3,
                                 "vendor_ip_count": vendor_n,
                                 "score": 100, "status": "completed", "issues": []},
                "waf": {"detected": True},
                "cloud_cdn": {"cdn_detected": True}}
        fi = sa.FinancialImpactCalculator()
        try:
            out = fi._calculate_zar(cats, {}, 10_000_000, "other", None, None,
                                    None, None)
        except Exception as e:
            # Signature drift must fail loudly rather than silently skip: a
            # guard that cannot drive the code it guards is not a guard.
            failures.append("single_asn[%s]: could not drive "
                            "_calculate_zar (%s); the guard is inert" % (label, e))
            print("  [FAIL] single_asn:%-24s (could not drive)" % label)
            continue
        rp = (out or {}).get("risk_probability") or {}
        ind = (rp.get("availability_resilience") or {}).get("indicator")
        # base 0.03, +0.025 when the term fires, nothing else set here.
        charged = ind is not None and round(ind, 4) >= 0.055
        ok = (charged == want)
        if not ok:
            failures.append(
                "single_asn[%s]: unique_asns=%d vendor=%d charged=%r, expected "
                "%r (availability indicator %s). Production charges every "
                "unique_asns <= 1, including a count of 0; changing that is a "
                "deferred rate decision (owner, 3 November 2026), not a fix."
                % (label, ua, vendor_n, charged, want, ind))
        print("  [%s] single_asn:%-26s asns=%d vendor=%d charged=%s"
              % ("PASS" if ok else "FAIL", label, ua, vendor_n, charged))

    # MUTATION: the scorer must carry production's `<= 1`. A bare `== 1`, or
    # the deferred charge-on-evidence rule, un-charges a never-collected count
    # and moves production pricing without an owner decision.
    import inspect
    src = inspect.getsource(sa.FinancialImpactCalculator._calculate_zar)
    uses_prod = '.get("unique_asns", 2) <= 1' in src
    if not uses_prod:
        failures.append(
            "single_asn MUTATION: the scorer no longer carries production's "
            "`unique_asns <= 1` rule. The measured-ASN change is deferred by "
            "owner decision (3 November 2026) and must not ship as a side effect.")
    print("  [%s] single_asn:MUTATION scorer tests <= 1 (production)"
          % ("PASS" if uses_prod else "FAIL"))


# ---- SA second-level domain coverage (OUTSTANDING 5n, 2026-09-10) ----------
#
# ALT_TLDS carried the generic TLDs and .co.za but none of the other South
# African second-level domains, so scanning boston.ac.za generated boston.co.za
# as a candidate while scanning boston.co.za NEVER generated boston.ac.za. The
# same organisation got a different answer depending on which apex was
# submitted, and a typosquat under an unlisted second-level domain was never
# probed at all.
#
# SYMMETRY IS THE PROPERTY WORTH GATING, not the presence of a string in a list.
# A list membership test would pass while the generator silently stopped using
# it, so these rows drive the real _generate_permutations.
#
# Measured before shipping: 148 new candidates across the 30 retained scans, of
# which THREE resolve. End to end that is boston.ac.za 97 -> 100 of 1000 and
# takealot UNCHANGED, its lookalike penalty already capped.
SA_SLDS = (".co.za", ".ac.za", ".org.za", ".net.za", ".gov.za", ".web.za")


def _check_sa_second_level_domains(failures):
    import importlib
    ct = importlib.import_module("checkers_threats")
    c = ct.FraudulentDomainChecker()

    # 1. Every SA second-level domain must SPLIT correctly, or the brand label
    #    is wrong and every permutation built from it is wrong too. ".web.za"
    #    was the one missing from _split_domain when this shipped.
    for sld in SA_SLDS:
        got_name, got_tld = c._split_domain("acme" + sld)
        ok = (got_name == "acme" and got_tld == sld)
        if not ok:
            failures.append(
                "sa_slds split[%s]: acme%s -> (%r, %r), expected ('acme', %r). "
                "A bad split makes the brand label wrong and every permutation "
                "built from it meaningless." % (sld, sld, got_name, got_tld, sld))
        print("  [%s] sa_slds:split%-12s -> (%s, %s)"
              % ("PASS" if ok else "FAIL", sld, got_name, got_tld))

    # 2. SYMMETRY. From any SA apex, every OTHER SA second-level domain must be
    #    generated, and the target's own must not be (a self-match is not a
    #    lookalike).
    for target in ("boston.ac.za", "aggregato.co.za", "dept.gov.za"):
        name, tld = c._split_domain(target)
        variants = {(x[0] if isinstance(x, (list, tuple)) else x)
                    for x in c._generate_permutations(name, tld)}
        want = {name + s for s in SA_SLDS if s != tld}
        missing = sorted(want - variants)
        selfmatch = target in variants
        ok = not missing and not selfmatch
        if missing:
            failures.append(
                "sa_slds symmetry[%s]: did NOT generate %s. Scanning one apex "
                "must find lookalikes under the others, or the same client gets "
                "a different answer depending which apex was submitted."
                % (target, missing))
        if selfmatch:
            failures.append("sa_slds symmetry[%s]: generated ITSELF as a "
                            "lookalike candidate" % target)
        print("  [%s] sa_slds:symmetry:%-18s %d/%d generated, self-match=%s"
              % ("PASS" if ok else "FAIL", target,
                 len(want) - len(missing), len(want), selfmatch))

    # 3. NON-VACUITY / MUTATION. Removing the SA entries from ALT_TLDS must
    #    break symmetry, or these rows are testing nothing.
    real = ct.FraudulentDomainChecker.ALT_TLDS
    try:
        ct.FraudulentDomainChecker.ALT_TLDS = [
            t for t in real if t not in (".ac.za", ".org.za", ".net.za",
                                         ".gov.za", ".web.za")]
        c2 = ct.FraudulentDomainChecker()
        name, tld = c2._split_domain("boston.ac.za")
        variants = {(x[0] if isinstance(x, (list, tuple)) else x)
                    for x in c2._generate_permutations(name, tld)}
        still = {"boston" + s for s in SA_SLDS if s != tld} - variants
    finally:
        ct.FraudulentDomainChecker.ALT_TLDS = real
    if not still:
        failures.append(
            "sa_slds MUTATION is vacuous: removing the SA second-level domains "
            "from ALT_TLDS changed nothing, so the symmetry rows above are not "
            "actually exercising the table.")
    print("  [%s] sa_slds:MUTATION removing them breaks symmetry (%d lost)"
          % ("PASS" if still else "FAIL", len(still)))


# ---- Credential export must carry only the client's mailboxes (step 4) ------
#
# THE DEFECT. _fetch_dehashed_full issues a bare `domain:{domain}` query and
# every returned record went straight into the CSV. DeHashed's domain: operator
# matches ADJACENT AND LOOKALIKE mailboxes, so the export could hand a client
# credentials belonging to staff at other organisations. It is the same
# substring-versus-boundary defect _email_at_domain fixed on the scan path,
# never applied to the export.
#
# NO SIGNED CONSENT CAN CURE IT: a client cannot consent on behalf of another
# company's employees, so until the filter exists the authorisation form
# describes a process the software does not perform.
#
# THIS CHECK NEVER TOUCHES DEHASHED. Every row is synthetic. A guard test in
# this repo once ran a real paginated credential export and burned roughly 500
# credits, because cost tracks SEARCHES, not results. The no-network assertion
# below is not decoration.
EXPORT_SCOPE_SCENARIOS = [
    # (label, email, authorised, in_scope)
    ("own_mailbox",            "staff@takealot.com",           ["takealot.com"], True),
    ("own_subdomain",          "ceo@mail.takealot.com",        ["takealot.com"], True),
    ("uppercase",              "A@TAKEALOT.COM",               ["takealot.com"], True),
    ("trailing_dot",           "a@takealot.com.",              ["takealot.com"], True),
    # The three the bare domain: query would have swept in.
    ("hyphen_lookalike",       "v@evil-takealot.com",          ["takealot.com"], False),
    ("adjacent_suffix",        "v@takealot.company.co.za",     ["takealot.com"], False),
    ("suffix_impersonation",   "v@takealot.com.evil.ru",       ["takealot.com"], False),
    # FAIL CLOSED: unattributable records are refused, not included.
    ("no_at_sign",             "nomailbox",                    ["takealot.com"], False),
    ("empty",                  "",                             ["takealot.com"], False),
    ("none",                   None,                           ["takealot.com"], False),
    ("no_authorised_domains",  "staff@takealot.com",           [],               False),
    ("multi_domain_release",   "s@second-brand.co.za",
     ["takealot.com", "second-brand.co.za"], True),
]


def _check_export_mailbox_scope(failures):
    import importlib
    ce = importlib.import_module("credential_export")

    for label, email, authorised, want in EXPORT_SCOPE_SCENARIOS:
        got = bool(ce.mailbox_in_scope(email, authorised))
        ok = (got == want)
        if not ok:
            failures.append(
                "export_scope[%s]: in_scope=%r, expected %r. A mailbox outside "
                "the authorised domains belongs to another organisation's staff, "
                "and no client consent can authorise its release."
                % (label, got, want))
        print("  [%s] export_scope:%-24s -> %s" % ("PASS" if ok else "FAIL", label, got))

    # End to end through the real CSV builder, synthetic rows only.
    entries = [{"email": "staff@takealot.com", "password": "x", "database_name": "S"},
               {"email": "v@evil-takealot.com", "password": "x", "database_name": "S"},
               {"username": "no-mailbox", "password": "x", "database_name": "S"}]
    kept, excluded = ce.filter_entries_to_authorised(entries, ["takealot.com"])
    csv = ce.build_credential_csv(
        entries, authorised_domains=["takealot.com"],
        leak_references=[{"name": "stealer-dump-2026", "date": "2026-01-02"}]).decode()
    # Report WHICH condition failed. Counts being right while the rows still
    # reach the file is a different defect from the counts being wrong, and a
    # message that conflates them costs a debugging cycle.
    problems = []
    if len(kept) != 1 or excluded != 2:
        problems.append("filter counts kept=%d excluded=%d, expected 1/2"
                        % (len(kept), excluded))
    leaked = [n for n in ("evil-takealot", "no-mailbox") if n in csv]
    if leaked:
        problems.append("out-of-scope rows REACHED THE FILE: %s -- the counts "
                        "may be right while the CSV is still built from the "
                        "unfiltered list" % leaked)
    if "staff@takealot.com" not in csv:
        problems.append("the client's OWN mailbox is missing from the file; the "
                        "filter is refusing records it should release")
    ok = not problems
    if not ok:
        failures.append("export_scope[csv]: " + "; ".join(problems))
    print("  [%s] export_scope:%-24s kept=%d excluded=%d"
          % ("PASS" if ok else "FAIL", "csv_end_to_end", len(kept), excluded))

    # A leak_reference is an IntelX posting naming the DOMAIN, with no mailbox,
    # so there is no person to mis-attribute and it must survive the filter.
    ok = "stealer-dump-2026" in csv
    if not ok:
        failures.append("export_scope[leak_reference]: a domain-level IntelX "
                        "posting was dropped by a MAILBOX filter; it carries no "
                        "mailbox and cannot be mis-attributed to anyone.")
    print("  [%s] export_scope:%-24s" % ("PASS" if ok else "FAIL", "leak_reference_kept"))

    # The count handed to the operator and the audit row must describe the FILE,
    # not the raw query. Reporting the pre-filter number would tell an operator
    # the export contains records it deliberately withheld.
    import inspect
    src = inspect.getsource(ce.generate_encrypted_export)
    ok = "len(kept)" in src and "len(entries)" not in src.split("csv_bytes")[-1]
    if not ok:
        failures.append("export_scope[record_count]: generate_encrypted_export "
                        "does not report len(kept); the operator would be told "
                        "the file holds records it refused to write.")
    print("  [%s] export_scope:%-24s" % ("PASS" if ok else "FAIL", "count_is_post_filter"))

    # MUTATION: authorise nothing and assert everything is refused. If a record
    # survives an empty authorisation set the filter is not fail-closed.
    kept2, _ = ce.filter_entries_to_authorised(entries, [])
    if kept2:
        failures.append("export_scope MUTATION: %d record(s) survived an EMPTY "
                        "authorised-domain set. The filter must fail closed."
                        % len(kept2))
    print("  [%s] export_scope:MUTATION empty authorisation refuses all"
          % ("PASS" if not kept2 else "FAIL"))


# ---- The default-certificate test must be POSITIVE, not an absence test -----
#
# looks_multi_tenant read `not _cert_covers(names, insured_domain)`: "the
# certificate does not name the apex, therefore somebody else is on this box".
# A default vhost routinely serves the box's OWN hostname rather than the apex,
# so it fired on the insured's own infrastructure.
#
# MEASURED on the 30 retained scans: 3 of the 36 default-certificate demotions
# were wrong, and they are the worst ones to lose:
#
#   bbgroup.co.za  41.161.81.118    cert ess.bbgroup.co.za
#                                   also serves autohubpol. and remote.
#   bbgroup.co.za  102.211.159.114  cert autohubpta.bbgroup.co.za
#   dubetradeport  41.78.234.1      cert fg10e0tb20902714 (FortiGate serial),
#                                   serves vpn.dubetradeport.co.za
#
# All three are the insured's own hosts, all three were deleted from
# per_ip_results and NEVER PORT-SCANNED. Their remote-access and VPN surfaces
# left the priced estate entirely. A demotion removes findings, which is the
# discount direction, and step 1 forbids absence from discounting anything.
#
# Re-running all 36 through the corrected rule: 33 stand, 3 reverse, every
# reversal in the LOAD direction, no genuine shared-hosting demotion lost.
DEFAULT_CERT_SCENARIOS = [
    # (label, cert names, insured, expected verdict)
    ("own_apex",              {"bbgroup.co.za"},          "bbgroup.co.za",       False),
    # The exact shape of the shipped bug.
    ("own_subdomain",         {"ess.bbgroup.co.za"},      "bbgroup.co.za",       False),
    ("own_subdomain_2",       {"autohubpta.bbgroup.co.za"}, "bbgroup.co.za",     False),
    ("own_wildcard",          {"*.bbgroup.co.za"},        "bbgroup.co.za",       False),
    # Genuine third parties: these must keep demoting.
    ("shared_host_wildcard",  {"*.jnb3.host-h.net"},      "dinamika.co.za",      True),
    ("another_tenant",        {"*.artztudio.ca"},         "gcrratings.com",      True),
    ("hetzner_managed",       {"*.your-server.de"},       "phishield.com",       True),
    # Identity-free names identify nobody and must NEVER demote.
    ("appliance_serial",      {"fg10e0tb20902714"},       "dubetradeport.co.za", None),
    ("bare_hostname",         {"server"},                 "x.co.za",             None),
    ("localhost",             {"localhost"},              "x.co.za",             None),
    ("address_literal",       {"196.41.30.122"},          "x.co.za",             None),
    ("dot_local",             {"box.local"},              "x.co.za",             None),
    # The insured's own name anywhere on the certificate wins.
    ("mixed_own_and_other",   {"ess.bbgroup.co.za", "*.host-h.net"}, "bbgroup.co.za", False),
    ("mixed_serial_and_other", {"fg123", "*.host-h.net"}, "x.co.za",             True),
    ("no_certificate",        None,                       "x.co.za",             None),
]


def _check_default_cert_verdict(failures):
    import importlib
    ipc = importlib.import_module("ip_classification")

    for label, names, insured, expected in DEFAULT_CERT_SCENARIOS:
        got = ipc.looks_multi_tenant(names, insured)
        ok = (got is expected)
        if not ok:
            failures.append(
                "default_cert[%s]: %r vs %s -> %r, expected %r. True demotes a "
                "host out of the priced estate, so a wrong True deletes the "
                "client's own findings and a wrong False keeps somebody else's."
                % (label, names, insured, got, expected))
        print("  [%s] default_cert:%-24s -> %s" % ("PASS" if ok else "FAIL", label, got))

    # MUTATION: restore the absence test. The own-infrastructure rows must flip
    # to True, i.e. back to demoting the client's own boxes.
    real = ipc.looks_multi_tenant
    try:
        ipc.looks_multi_tenant = lambda names, dom: (
            None if not names or not dom else not ipc._cert_covers(names, dom))
        flipped = [label for label, names, insured, expected
                   in DEFAULT_CERT_SCENARIOS
                   if expected is False
                   and ipc.looks_multi_tenant(names, insured) is True]
    finally:
        ipc.looks_multi_tenant = real
    if not flipped:
        failures.append(
            "default_cert MUTATION is vacuous: restoring the absence test "
            "changed no own-infrastructure row, so these rows are not actually "
            "exercising the positive test.")
    print("  [%s] default_cert:MUTATION absence test re-demotes own infra (%d rows)"
          % ("PASS" if flipped else "FAIL", len(flipped)))


# ---- The default-cert probe gate must read BOTH port shapes ----------------
#
# The gate was `443 in (shod.get("open_ports") or [])` -- Shodan's list alone.
# That list is empty whenever Shodan holds no record, and it can simply
# disagree with our own scan: aggregato.co.za's 156.38.174.226 has a FULL
# Shodan record whose port list lacks the 443 our own port scan observed.
#
# Measured on the retained corpus: 77 hosts probed, our own scan sees 443 on
# 82, union 95. Eighteen hosts across 14 of 30 scans were never probed despite
# an observed 443, and eight of those carry the textbook shared-cPanel port set
# (21/22/80/110/143/443/993/995/3306) -- the gate failed hardest on exactly the
# population the probe exists to identify.
#
# THE TWO SHAPES ARE THE TRAP. shodan_vulns["open_ports"] is a list of INTS;
# dns_infrastructure["open_ports"] is a list of DICTS. Both naive unions fail,
# and one fails SILENTLY:
#     set(dns) | set(shodan)  -> TypeError: unhashable type: 'dict'
#     443 in [{"port": 443}]  -> False, forever, no error
# A regression written the second way passes green over zero real evaluations.
TLS_GATE_SCENARIOS = [
    # (label, shodan list, dns list, expect probe)
    ("shodan_ints_443",       [80, 443],  None,                    True),
    ("dns_dicts_443",         [],         [{"port": 443}],         True),
    # The 18-host case: Shodan saw the host but not the port.
    ("shodan_has_no_443",     [80],       [{"port": 443}],         True),
    ("no_shodan_record",      [],         [{"port": 443}],         True),
    ("digit_strings",         [],         [{"port": "443"}],       True),
    ("neither_has_tls",       [80, 25],   [{"port": 22}],          False),
    ("both_empty",            [],         [],                      False),
    ("both_none",             None,       None,                    False),
    # bool is an int subclass; True must not read as port 1.
    ("bool_refused",          [True],     [{"port": False}],       False),
    ("junk_ignored",          ["abc"],    [{"noport": 1}, None],   False),
]


def _check_tls_port_gate(failures):
    import importlib
    ipc = importlib.import_module("ip_classification")

    for label, shod, dns, want in TLS_GATE_SCENARIOS:
        got = bool(ipc.tls_observed(shod, dns))
        ok = (got == want)
        if not ok:
            failures.append(
                "tls_gate[%s]: shodan=%r dns=%r -> probe=%r, expected %r"
                % (label, shod, dns, got, want))
        print("  [%s] tls_gate:%-22s -> probe=%s" % ("PASS" if ok else "FAIL", label, got))

    # The extractor must survive every shape without raising.
    try:
        ipc.observed_ports([1], [{"port": 2}], ["3"], [None, "x", {}, [4]], None)
        raised = None
    except Exception as e:
        raised = e
    if raised is not None:
        failures.append("tls_gate[extractor]: observed_ports raised %r on mixed "
                        "input; it must never raise" % raised)
    print("  [%s] tls_gate:%-22s" % ("PASS" if raised is None else "FAIL",
                                     "extractor_never_raises"))

    # MUTATION 1, the LOUD failure: the naive set union.
    try:
        set([{"port": 443}]) | set([443])
        loud = False
    except TypeError:
        loud = True
    if not loud:
        failures.append("tls_gate MUTATION: set(dns) | set(shodan) no longer "
                        "raises, so the dict shape has changed and this guard "
                        "is describing a trap that no longer exists.")
    print("  [%s] tls_gate:MUTATION naive union still raises" % ("PASS" if loud else "FAIL"))

    # MUTATION 2, the SILENT failure, which is the dangerous one. A membership
    # test straight against the dict list must still be False -- that is what
    # makes the shape-tolerant extractor necessary rather than decorative.
    silent = (443 not in [{"port": 443}])
    if not silent:
        failures.append("tls_gate MUTATION: `443 in [{'port': 443}]` is now "
                        "True, so the silent-failure shape this guard exists "
                        "for has changed.")
    print("  [%s] tls_gate:MUTATION `443 in [dict]` still silently False"
          % ("PASS" if silent else "FAIL"))

    # The shipped gate must not read Shodan alone. Source-level, on the AST, so
    # a keyword inside a comment cannot satisfy it.
    import ast
    with io.open(os.path.join(SEC, "scanner.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "id", None) == "tls_observed"]
    if not calls:
        failures.append("tls_gate[wiring]: scanner.py never calls tls_observed; "
                        "the probe gate has reverted to a single source.")
    print("  [%s] tls_gate:wired_in_scanner (%d call site(s))"
          % ("PASS" if calls else "FAIL", len(calls)))


# ---- Step 5: related domains, discovery on EVERY scan, assessment on confirmed -
#
# Discovery ran only in the form's pre-flight, so an API scan looked for related
# domains not at all. It now runs inside every scan from the certificate names
# SubdomainChecker already fetches, and the whole category is built by
# estate_discovery.build_related_domains_category, which scan() calls once.
#
# THIS GATE DRIVES THE REAL CODE. Its first version called discover() on
# hand-fed names and priced dicts it built itself, so deleting the feature, or
# turning a CT outage into "completed", passed it (step-5 critique round 1), and
# round 2 found sixteen more regressions it missed. Every check below runs what
# a scan runs: the builder, the CT fetchers through faked HTTP clients,
# RelatedDomainsChecker with its three sub-checks faked, the form pre-flight,
# the PDF card, the executive deck and the summary tier, scan()'s wiring by AST
# including its arguments, and the dashboard's TypeScript state logic under node.
#
# THE STATUS CONTRACT IS A PRICE DECISION. Measured over the 30 retained scans:
# a related_domains category that is absent, completed/100 or unassessed prices
# at exactly +0; skipped, error or timeout prices at +5 to +16 (mean +8.47). So
# this category may only ever be "completed" or "unassessed", a discovery outage
# must never read as "none found", and a partial assessment is never clean.
DISCOVERY_SCENARIOS = [
    # (label, scanned domain, foreign names, sources_ok, attested,
    #  want listed {domain: attested}, want rejected {domain: reason fragment})
    # A wildcard name counts as its organisation, on the form and in the report.
    ("shared_cert_tenant_listed_unconfirmed", "acme.co.za",
     ["shop.clientb.co.za", "*.clientc.co.za"], ["certspotter"], [],
     {"clientb.co.za": False, "clientc.co.za": False}, {}),
    ("attested_flagged", "acme.co.za",
     ["www.acme-group.co.za"], ["crtsh"], ["acme-group.co.za"],
     {"acme-group.co.za": True}, {}),
    ("registry_zone_never_a_sibling", "acme.co.za",
     ["school.za"], ["crtsh"], [], {}, {"school.za": "registry zone"}),
    ("scanned_domain_excluded", "acme.co.za",
     ["www.acme.co.za"], ["crtsh"], [], {}, {"acme.co.za": "scanned domain"}),
    ("scanned_organisation_named_as_such", "www.acme.co.za",
     ["acme.co.za", "mail.acme.co.za"], ["crtsh"], [], {},
     {"acme.co.za": "scanned organisation"}),
    ("cdn_excluded", "acme.co.za",
     ["d1.cloudfront.net"], ["crtsh"], [], {}, {"cloudfront.net": "CDN"}),
    ("provider_zone_excluded", "acme.co.za",
     ["cpanel.host-h.net"], ["crtsh"], [], {}, {"host-h.net": "provider"}),
    ("certificate_authority_named_as_such", "acme.co.za",
     ["r3.letsencrypt.org"], ["crtsh"], [], {},
     {"letsencrypt.org": "certificate authority"}),
    # The keep side. A bare endswith() would reject all three as CA or CDN.
    ("substring_of_ca_is_kept", "acme.co.za",
     ["www.myssl.com", "www.notdigicert.com"], ["crtsh"], [],
     {"myssl.com": False, "notdigicert.com": False}, {}),
    ("substring_of_cdn_is_kept", "acme.co.za",
     ["www.mycloudfront.net"], ["crtsh"], [], {"mycloudfront.net": False}, {}),
    ("ip_address_never_a_sibling", "acme.co.za",
     ["196.22.1.5"], ["crtsh"], [], {}, {"196.22.1.5": "IP address"}),
    ("african_second_level_registry", "acme.co.za",
     ["www.acme.com.na", "shop.other.co.ke"], ["crtsh"], [],
     {"acme.com.na": False, "other.co.ke": False}, {}),
    # Each half of the registry rule on its own: the generic-label heuristic
    # (co.ao is in no list) and the named list (govt.nz has no generic label).
    ("generic_label_heuristic_only", "acme.co.za",
     ["shop.acme.co.ao", "www.other.co.ao"], ["crtsh"], [],
     {"acme.co.ao": False, "other.co.ao": False}, {}),
    ("named_registry_list_only", "acme.co.za",
     ["www.acme.govt.nz", "www.other.govt.nz"], ["crtsh"], [],
     {"acme.govt.nz": False, "other.govt.nz": False}, {}),
    ("private_registry_za_com", "acme.co.za",
     ["www.acme.za.com", "other.za.com"], ["crtsh"], [],
     {"acme.za.com": False, "other.za.com": False}, {}),
    ("round2_registry_sc_ke", "acme.co.za",
     ["stmarys.sc.ke", "kenyahigh.sc.ke"], ["crtsh"], [],
     {"stmarys.sc.ke": False, "kenyahigh.sc.ke": False}, {}),
    ("za_always_three_labels", "acme.co.za",
     ["www.foo.nis.za"], ["crtsh"], [], {"foo.nis.za": False}, {}),
    ("provider_zone_deeper_than_the_apex", "acme.co.za",
     ["vm1.southafricanorth.cloudapp.azure.com"], ["crtsh"], [], {},
     {"azure.com": "provider"}),
    ("platform_zone", "acme.co.za",
     ["sni12345.cloudflaressl.com"], ["crtsh"], [], {},
     {"cloudflaressl.com": "shared platform"}),
    ("provider_zone_of_the_insureds_own_brand_is_kept", "afrihost.com",
     ["www.afrihost.co.za"], ["crtsh"], [], {"afrihost.co.za": False}, {}),
    ("provider_zone_of_another_brand_is_rejected", "acme.co.za",
     ["www.afrihost.co.za"], ["crtsh"], [], {}, {"afrihost.co.za": "provider"}),
    ("platform_zone_needs_an_exact_brand", "webstar.co.za",
     ["x.web.app"], ["crtsh"], [], {}, {"web.app": "shared platform"}),
    # Name likeness is not ownership: hetzner.co.za is xneelo's (formerly
    # Hetzner South Africa), not Hetzner Online's. A provider or platform zone
    # is listed only through its own group's alias list (round 5).
    ("like_named_platform_zone_is_rejected", "hetzner.com",
     ["www.hetzner.co.za"], ["crtsh"], [], {}, {"hetzner.co.za": "shared platform"}),
    ("platform_zone_of_the_insureds_group_is_kept", "xneelo.co.za",
     ["www.hetzner.co.za"], ["crtsh"], [], {"hetzner.co.za": False}, {}),
    # Round 4: the brand exception is exact, or a listed alias, and never
    # unlocks a zone deeper than its registrable domain.
    ("provider_group_alias_is_kept", "voxtelecom.co.za",
     ["www.vox.co.za"], ["crtsh"], [], {"vox.co.za": False}, {}),
    ("brand_containment_is_not_a_brand", "laservision.co.za",
     ["cp12.aserv.co.za"], ["crtsh"], [], {}, {"aserv.co.za": "provider"}),
    ("provider_zone_below_its_apex_never_branded", "azurecapital.co.za",
     ["acp.southafricanorth.cloudapp.azure.com"], ["crtsh"], [], {},
     {"azure.com": "provider"}),
    ("short_generic_brand_never_unlocks_a_platform", "web.co.za",
     ["x.web.app"], ["crtsh"], [], {}, {"web.app": "shared platform"}),
    ("two_letter_provider_never_branded", "discovery.co.za",
     ["mail.is.co.za"], ["crtsh"], [], {}, {"is.co.za": "provider"}),
    # compute.amazonaws.com's first label is the insured's brand, but the
    # candidate would be amazonaws.com, the provider's own apex.
    ("deep_provider_zone_never_branded", "compute.co.za",
     ["ec2-1-2-3-4.compute.amazonaws.com"], ["crtsh"], [], {},
     {"amazonaws.com": "provider"}),
    ("telkom_group_zone_is_kept", "telkom.co.za",
     ["webmail.telkomsa.net"], ["crtsh"], [], {"telkomsa.net": False}, {}),
    ("internet_solutions_alias_is_kept", "internetsolutions.co.za",
     ["mail.is.co.za"], ["crtsh"], [], {"is.co.za": False}, {}),
    # An insured whose name merely equals, or begins with, a group's is not
    # that group: aliases are keyed on the group's own domains (round 6).
    ("like_named_brand_is_not_the_group", "vox.com",
     ["www.vox.co.za"], ["crtsh"], [], {}, {"vox.co.za": "provider"}),
    ("first_label_coincidence_is_rejected", "liquid.co.za",
     ["x.liquidtelecom.net"], ["crtsh"], [], {}, {"liquidtelecom.net": "provider"}),
    ("alias_prefix_is_not_the_group", "voxel.co.za",
     ["www.vox.co.za"], ["crtsh"], [], {}, {"vox.co.za": "provider"}),
    ("like_named_provider_zone_is_rejected", "datapro.net",
     ["cpanel.datapro.co.za"], ["crtsh"], [], {}, {"datapro.co.za": "provider"}),
]

# SubdomainChecker results the builder receives, one per real situation.
RD_SUB_OK = {"status": "completed", "ct_sources": ["crtsh"],
             "ct_sources_answered": ["certspotter", "crtsh"],
             "ct_foreign_names": ["shop.clientb.co.za", "www.acme-group.co.za"],
             "ct_foreign_orgs_dropped": 0}
RD_SUB_EMPTY = {"status": "completed", "ct_sources": ["crtsh"],
                "ct_sources_answered": ["crtsh"], "ct_foreign_names": [],
                "ct_foreign_orgs_dropped": 0}
RD_SUB_ANSWERED_EMPTY = {"status": "completed", "ct_sources": [],
                         "ct_sources_answered": ["crtsh"], "ct_foreign_names": [],
                         "ct_foreign_orgs_dropped": 0}
RD_SUB_OUTAGE = {"status": "completed", "ct_sources": [], "ct_sources_answered": [],
                 "ct_foreign_names": [], "ct_foreign_orgs_dropped": 0}
RD_SUB_ONLY_CONFIRMED = {"status": "completed", "ct_sources": ["crtsh"],
                         "ct_sources_answered": ["certspotter", "crtsh"],
                         "ct_foreign_names": ["www.acme-group.co.za"],
                         "ct_foreign_orgs_dropped": 0}
RD_SUB_TIMEOUT = {"status": "timeout", "error": "Checker timed out after 150s"}
RD_SUB_PRECHANGE = {"status": "completed", "ct_sources": ["certspotter", "crtsh"]}
RD_SUB_ANSWERED_NO_SUBDOMAINS = {"status": "completed", "ct_sources": [],
                                 "ct_sources_answered": ["certspotter"],
                                 "ct_foreign_names": ["acme-group.co.za"],
                                 "ct_foreign_orgs_dropped": 0}


# More than twenty confirmed domains co-listed on the insured's certificates:
# confirmed candidates must not crowd every unconfirmed one out of the list.
RD_SUB_MANY_ATTESTED = {"status": "completed", "ct_sources": ["crtsh"],
                        "ct_sources_answered": ["crtsh"],
                        "ct_foreign_names": (["www.sib%02d.co.za" % i for i in range(22)]
                                             + ["www.clienta.co.za", "www.clientb.co.za",
                                                "www.clientc.co.za"]),
                        "ct_foreign_orgs_dropped": 0}
# Only confirmed domains listed, but organisations the producer left out still
# exist: the "and N more" line must survive the empty unconfirmed list.
RD_SUB_ATTESTED_PLUS_DROPPED = {"status": "completed", "ct_sources": ["crtsh"],
                                "ct_sources_answered": ["crtsh"],
                                "ct_foreign_names": ["www.acme-group.co.za"],
                                "ct_foreign_orgs_dropped": 7}
# Fifteen organisations on the certificates, none confirmed: the card lists
# twelve and says "and 3 more".
RD_SUB_FIFTEEN = {"status": "completed", "ct_sources": ["crtsh"],
                  "ct_sources_answered": ["crtsh"],
                  "ct_foreign_names": ["www.org%02d.co.za" % i for i in range(15)],
                  "ct_foreign_orgs_dropped": 0}
# Five confirmed domains and eighteen unconfirmed tenants: the list holds the
# eighteen and two confirmed, so "and N more" is 6 (18 - 12), never 9, which
# counted the three confirmed domains past the list as awaiting confirmation.
RD_SUB_FIVE_PLUS_EIGHTEEN = {"status": "completed", "ct_sources": ["crtsh"],
                             "ct_sources_answered": ["crtsh"],
                             "ct_foreign_names": (["www.sib%d.co.za" % i for i in range(5)]
                                                  + ["www.tenant%02d.co.za" % i
                                                     for i in range(18)]),
                             "ct_foreign_orgs_dropped": 0}


def _rd_probe(kind, calls):
    """A stand-in for RelatedDomainsChecker that records what it was asked."""
    def run(domains):
        calls.append(list(domains))
        if kind == "raise":
            raise RuntimeError("probe blew up")
        if kind in ("timeout", "error", "skipped"):
            return {"status": kind}
        deps = []
        for i, d in enumerate(domains):
            measured = not (kind == "none_measured" or (
                kind in ("partial", "partial_finding", "partial_high") and i > 0))
            score = {"finding": 40, "high": 45, "partial_finding": 40,
                     "partial_high": 45}.get(kind, 100)
            gap = (kind == "partial_checks"
                   or (kind == "partial_checks_last" and i == len(domains) - 1))
            dep = {"domain": d, "measured": measured,
                   "lite_score": score if measured else None,
                   "critical_paths": (1 if measured and kind in ("finding", "partial_finding")
                                      else 0),
                   "not_measured": ["ssl"] if gap else []}
            if kind == "legacy_shape":
                # What the pre-change checker wrote: no measured marker at all.
                del dep["measured"]
                del dep["not_measured"]
            deps.append(dep)
        m = [x for x in deps if x.get("measured", kind == "legacy_shape")]
        return {"status": "completed", "declared_count": len(domains),
                "scanned_count": len(m), "dependants": deps,
                "worst_domain": ({"domain": m[0]["domain"], "lite_score": m[0]["lite_score"]}
                                 if m else None),
                "critical_count": sum(x["critical_paths"] for x in m),
                "high_count": sum(1 for x in m if x["lite_score"] < 60),
                "score": min((x["lite_score"] for x in m), default=100), "issues": []}
    return run


NONE_FOUND_TEXT = "no related domains were found"

# (label, confirmed list, subdomains result, probe kind, expectations)
RD_BUILDER = [
    ("api_ct_answered", None, RD_SUB_OK, None,
     dict(status="completed", state="awaiting_confirmation", probed=None, colour="blue",
          listed={"clientb.co.za", "acme-group.co.za"},
          says=["awaiting confirmation", "clientb.co.za"],
          never=["none found", NONE_FOUND_TEXT])),
    ("api_ct_answered_none_found", None, RD_SUB_EMPTY, None,
     dict(status="completed", state="none_found", probed=None, listed=set(),
          says=[NONE_FOUND_TEXT, "does not show"])),
    ("api_ct_answered_empty_names", None, RD_SUB_ANSWERED_EMPTY, None,
     dict(status="completed", state="none_found", probed=None,
          never=["did not return a result"])),
    ("api_ct_outage", None, RD_SUB_OUTAGE, None,
     dict(status="unassessed", state="degraded", probed=None, listed=set(),
          says=["not assessed", "not a finding that none exist",
                "certificate-record lookup did not return a result"],
          never=["none found", NONE_FOUND_TEXT])),
    ("api_subdomains_timed_out", None, RD_SUB_TIMEOUT, None,
     dict(status="unassessed", state="degraded", probed=None,
          says=["not assessed", "the subdomain check"],
          never=["none found", NONE_FOUND_TEXT, "certificate-record lookup"])),
    ("resumed_prechange_checkpoint", None, RD_SUB_PRECHANGE, None,
     dict(status="unassessed", state="degraded", probed=None,
          says=["not assessed", "resumed from a checkpoint"],
          never=["none found", NONE_FOUND_TEXT, "certificate-record lookup"])),
    ("source_answered_without_subdomains", None, RD_SUB_ANSWERED_NO_SUBDOMAINS, None,
     dict(status="completed", state="awaiting_confirmation",
          listed={"acme-group.co.za"},
          never=["did not return a result", NONE_FOUND_TEXT])),
    ("primary_only_confirmed_in_outage", ["ACME.co.za "], RD_SUB_OUTAGE, "clean",
     dict(status="unassessed", state="degraded", probed=None,
          rejected={"acme.co.za"}, says=["assessed by the main scan"],
          never=["none found", NONE_FOUND_TEXT])),
    ("confirmed_own_subdomain", ["shop.acme.co.za"], RD_SUB_OK, "clean",
     dict(status="completed", state="awaiting_confirmation", probed=None,
          rejected={"shop.acme.co.za"},
          says=["shop.acme.co.za", "a subdomain of the scanned domain",
                "not assessed separately on this scan", "submitted for assessment 1"])),
    ("subdomain_scan_confirms_parent", ["acme.co.za", "portal.acme.co.za"],
     RD_SUB_OK, "clean",
     dict(domain="www.acme.co.za", status="completed", state="confirmed",
          probed=[["acme.co.za", "portal.acme.co.za"]], rejected=set())),
    ("registry_zone_never_probed", ["school.za", "acme-group.co.za"], RD_SUB_OK, "clean",
     dict(status="completed", state="confirmed", probed=[["acme-group.co.za"]],
          rejected={"school.za"}, listed={"clientb.co.za"},
          says=["school.za", "submitted for assessment 2"])),
    ("confirmed_clean", ["acme-group.co.za"], RD_SUB_OK, "clean",
     dict(status="completed", state="confirmed", listed={"clientb.co.za"}, full=True,
          colour="green", says=["passed the lite-mode checks"],
          never=[NONE_FOUND_TEXT, "confirmed by broker"],
          block_excludes="acme-group.co.za")),
    ("confirmed_finding", ["acme-group.co.za"], RD_SUB_OK, "finding",
     dict(status="completed", state="confirmed", loads=True, colour="critical",
          never=["passed the lite-mode checks"])),
    ("confirmed_high_only", ["acme-group.co.za"], RD_SUB_OK, "high",
     dict(status="completed", state="confirmed", loads=True, colour="red",
          never=["passed the lite-mode checks"])),
    ("probe_timed_out", ["acme-group.co.za"], RD_SUB_OK, "timeout",
     dict(status="unassessed", state="confirmed_unassessed", reason="timeout",
          says=["not assessed", "within the time allowed"],
          never=["were assessed", "confirmed by broker", NONE_FOUND_TEXT])),
    ("probe_errored", ["acme-group.co.za"], RD_SUB_OK, "error",
     dict(status="unassessed", state="confirmed_unassessed", reason="error",
          says=["because the assessment failed"],
          never=["time allowed", "were assessed"])),
    ("probe_raised", ["acme-group.co.za"], RD_SUB_OK, "raise",
     dict(status="unassessed", state="confirmed_unassessed", reason="error")),
    ("probe_returned_skipped", ["acme-group.co.za"], RD_SUB_OK, "skipped",
     dict(status="unassessed", state="confirmed_unassessed")),
    ("probe_measured_nothing", ["acme-group.co.za"], RD_SUB_OK, "none_measured",
     dict(status="unassessed", state="confirmed_unassessed", reason="not_measured",
          never=["were assessed"])),
    ("resumed_prechange_probe_result", ["acme-group.co.za"], RD_SUB_OK, "legacy_shape",
     dict(status="unassessed", state="confirmed_unassessed", reason="not_measured")),
    ("probe_measured_some", ["acme-group.co.za", "acme-holdings.co.za"], RD_SUB_OK, "partial",
     dict(status="completed", state="confirmed", not_assessed=["acme-holdings.co.za"],
          full=False, colour="amber",
          says=["could not be assessed on this scan", "assessment is incomplete"],
          never=["passed the lite-mode checks"])),
    ("partial_checks", ["acme-group.co.za"], RD_SUB_OK, "partial_checks",
     dict(status="completed", state="confirmed", full=False,
          colour="amber",
          says=["ssl not assessed", "some checks returned no result",
                "assessment is incomplete"],
          never=["passed the lite-mode checks"])),
    ("over_the_cap", ["sib%02d.co.za" % i for i in range(12)], RD_SUB_OK, "clean",
     dict(status="completed", state="confirmed",
          probed=[["sib%02d.co.za" % i for i in range(10)]],
          over_cap=["sib10.co.za", "sib11.co.za"], full=False,
          colour="amber",
          says=["at most 10", "submitted for assessment 12", "assessment is incomplete"],
          never=["passed the lite-mode checks"])),
    ("confirmed_while_discovery_down", ["acme-group.co.za"], RD_SUB_OUTAGE, "clean",
     dict(status="completed", state="confirmed", says=["discovery could not run"])),
    ("partial_while_discovery_down", ["acme-group.co.za"], RD_SUB_OUTAGE, "partial_checks",
     dict(status="completed", state="confirmed", full=False,
          says=["discovery could not run", "ssl not assessed"])),
    ("finding_while_discovery_down", ["acme-group.co.za"], RD_SUB_OUTAGE, "finding",
     dict(status="completed", state="confirmed", loads=True,
          says=["discovery could not run"])),
    ("timeout_while_discovery_down", ["acme-group.co.za"], RD_SUB_OUTAGE, "timeout",
     dict(status="unassessed", state="confirmed_unassessed", reason="timeout",
          says=["discovery could not run", "within the time allowed"])),
    # The only certificate name besides the insured's own is the confirmed
    # domain: nothing is listed, and the dashboard lead says nothing of listed
    # candidates (critique round 6, GS6-6).
    ("confirmed_only_attested_candidate", ["acme-group.co.za"], RD_SUB_ONLY_CONFIRMED,
     "clean", dict(status="completed", state="confirmed", full=True,
                   block_excludes="acme-group.co.za")),
    ("twenty_confirmed_domains_on_certificates",
     ["sib%02d.co.za" % i for i in range(22)], RD_SUB_MANY_ATTESTED, "clean",
     dict(status="completed", state="confirmed",
          listed={"clienta.co.za", "clientb.co.za", "clientc.co.za"},
          over_cap=["sib%02d.co.za" % i for i in range(10, 22)], full=False,
          says=["clienta.co.za"], never=["and 5 more"])),
    ("dropped_organisations_still_counted", ["acme-group.co.za"],
     RD_SUB_ATTESTED_PLUS_DROPPED, "clean",
     dict(status="completed", state="confirmed", says=["and 7 more"])),
    # Round 4. A partial assessment that found something shows the finding,
    # on the card, the deck and the summary tier.
    ("partial_with_critical", ["acme-group.co.za", "acme-holdings.co.za"], RD_SUB_OK,
     "partial_finding",
     dict(status="completed", state="confirmed", full=False, loads=True, colour="critical",
          not_assessed=["acme-holdings.co.za"], never=["passed the lite-mode checks"])),
    ("partial_with_high", ["acme-group.co.za", "acme-holdings.co.za"], RD_SUB_OK,
     "partial_high",
     dict(status="completed", state="confirmed", full=False, loads=True, colour="red",
          never=["passed the lite-mode checks"])),
    # The card lists five dependants; the sixth's missing check is in the note.
    ("partial_checks_beyond_five_rows", ["sib%d.co.za" % i for i in range(6)], RD_SUB_OK,
     "partial_checks_last",
     dict(status="completed", state="confirmed", full=False, colour="amber",
          says=["some checks returned no result", "sib5.co.za: ssl",
                "assessment is incomplete"])),
    ("fifteen_candidates_none_confirmed", None, RD_SUB_FIFTEEN, None,
     dict(status="completed", state="awaiting_confirmation", says=["and 3 more"])),
    ("five_confirmed_among_eighteen_tenants", ["sib%d.co.za" % i for i in range(5)],
     RD_SUB_FIVE_PLUS_EIGHTEEN, "clean",
     dict(status="completed", state="confirmed", full=True, says=["and 6 more"],
          never=["and 9 more"])),
    # A confirmed host attests its own registrable domain, which is therefore
    # not listed as awaiting confirmation.
    ("confirmed_host_attests_its_domain", ["www.acme-group.co.za"], RD_SUB_OK, "clean",
     dict(status="completed", state="confirmed", probed=[["www.acme-group.co.za"]],
          listed={"clientb.co.za"}, block_excludes="acme-group.co.za")),
    # Round 5. A clean confirmed estate with no candidate left awaiting
    # confirmation: the only kind whose summary row may read "Clean".
    ("confirmed_clean_no_candidates", ["acme-group.co.za"], RD_SUB_EMPTY, "clean",
     dict(status="completed", state="confirmed", full=True, colour="green",
          says=["passed the lite-mode checks"])),
    # A partial assessment beside a rejected entry: the deck counts confirmed
    # related domains only.
    ("partial_with_rejected_entry", ["school.za", "acme-group.co.za"], RD_SUB_OK,
     "partial_checks",
     dict(status="completed", state="confirmed", full=False, colour="amber",
          says=["submitted for assessment 2"])),
    # A probe that assessed nothing, beside confirmed domains over the cap and
    # a rejected entry: the card still names both.
    ("unassessed_with_overcap_and_rejected",
     ["school.za"] + ["sib%02d.co.za" % i for i in range(12)], RD_SUB_OK, "timeout",
     dict(status="unassessed", state="confirmed_unassessed", reason="timeout",
          says=["at most 10", "school.za"])),
]

# Categories stored BEFORE step 5, as they sit in the database today.
RD_LEGACY = [
    ("legacy_stored_timeout",
     {"status": "timeout", "error": "Checker timed out after 60s",
      "issues": ["Checker did not complete within 60s"]}, "not_run"),
    ("legacy_stored_skipped",
     {"status": "skipped", "declared_count": 0, "scanned_count": 0, "score": 100,
      "issues": []}, "not_run"),
    ("legacy_stored_error", {"status": "error", "error": "boom"}, "not_run"),
    ("legacy_completed_nothing_scanned",
     {"status": "completed", "declared_count": 2, "scanned_count": 0, "score": 100,
      "issues": []}, "not_run"),
    ("legacy_confirmed_completed",
     {"status": "completed", "declared_count": 1, "scanned_count": 1, "score": 88,
      "dependants": [{"domain": "sib.co.za", "lite_score": 88, "critical_paths": 0}],
      "worst_domain": {"domain": "sib.co.za", "lite_score": 88},
      "critical_count": 0, "high_count": 0, "issues": []}, "confirmed"),
]


def _rd_flow_text(x):
    """Visible text of reportlab flowables: cards, tables, nested groups."""
    out = []

    def walk(y):
        if y is None:
            return
        if isinstance(y, (list, tuple)):
            for z in y:
                walk(z)
            return
        if isinstance(y, str):
            out.append(y)
            return
        if isinstance(y, (int, float)):
            out.append(str(y))
            return
        t = getattr(y, "text", None)
        if isinstance(t, str):
            out.append(t)
        for row in (getattr(y, "_cellvalues", None) or []):
            for c in row:
                walk(c)
        for attr in ("_content", "_flowables"):
            walk(getattr(y, attr, None))

    walk(x)
    return " ".join(out)


def _summary_sc_row(table):
    """The Supply-Chain Risk row of the summary table, as text ('' if absent)."""
    for row in (getattr(table, "_cellvalues", None) or []):
        t = _rd_flow_text(list(row))
        if "Supply-Chain Risk" in t:
            return t
    return ""


def _pdf_visible_text(pdf):
    """The text a reader sees in a generated PDF (content streams, decoded)."""
    import re, zlib, base64
    chunks = []
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        blob = m.group(1).strip()
        for dec in (lambda b: zlib.decompress(base64.a85decode(b, adobe=True)),
                    zlib.decompress):
            try:
                chunks.append(dec(blob).decode("latin-1"))
                break
            except Exception:
                pass
    doc = " ".join(chunks)
    out, i, n = [], 0, len(doc)
    while i < n:
        if doc[i] == "(":
            j, buf = i + 1, []
            while j < n:
                ch = doc[j]
                if ch == "\\" and j + 1 < n:
                    buf.append(doc[j + 1])
                    j += 2
                    continue
                if ch == ")":
                    break
                buf.append(ch)
                j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return re.sub(r"\s+", " ", " ".join(out))


def _deck_group(text, name="Related domains"):
    """Which footer group of the executive deck lists *name*, or None. A signal
    that gathered data but was not (fully) assessed has a sentence of its own,
    returned as 'own: not assessed' or 'own: not fully assessed'."""
    import re
    m = re.search(re.escape(name) + r": (not fully assessed|not assessed) \(", text)
    if m:
        return "own: " + m.group(1)
    for m in re.finditer(r"(Not assessed \(no scan data\)|Not applicable|"
                         r"Partly assessed|Fully assessed|Assessed):\s*([^.]*)", text):
        if name in m.group(2):
            # "Fully assessed" is the same group under a heading the slide uses
            # when something else on it was only partly read.
            return "Assessed" if m.group(1) == "Fully assessed" else m.group(1)
    return None


def _colour_spy(pc, sink):
    """Wrap pdf_cards.build_cat_card to record the related-domains card's colour."""
    real = pc.build_cat_card
    names = {id(pc.C_GREEN): "green", id(pc.C_AMBER): "amber", id(pc.C_RED): "red",
             id(pc.C_CRITICAL): "critical", id(pc.C_BLUE): "blue"}

    def spy(title, col, *a, **k):
        if title == pc._RD_TITLE:
            sink.append(names.get(id(col), "other"))
        return real(title, col, *a, **k)
    return spy


class _FakeCT:
    """A CT HTTP client returning one canned response. No packet leaves the box."""

    def __init__(self, status, payload):
        self.status, self.payload = status, payload

    def get(self, url, **kw):
        import json as _j
        resp = mock.MagicMock()
        resp.status_code = self.status
        resp.text = _j.dumps(self.payload)
        resp.json = lambda: self.payload
        return resp


class _FakeWeb:
    """An HTTP client for InformationDisclosureChecker. By default every path
    answers 404. ``head(path)`` may return another code, or None for no answer;
    ``root`` is the site root's code (None: no answer); ``apex`` is what
    apex_answered reports; a path in ``raise_on`` raises. Every HEAD is
    recorded, so the gate can see which paths were asked for."""

    def __init__(self, head=None, root=404, apex=True, raise_on=()):
        self.heads = []
        self._head = head or (lambda path: 404)
        self._root, self._apex, self._raise_on = root, apex, set(raise_on)

    def _resp(self, code):
        r = mock.MagicMock()
        r.status_code = code
        r.text = "nothing here"
        r.headers = {}
        return r

    @staticmethod
    def _path(url):
        rest = url.split("://", 1)[-1]
        return "/" + rest.split("/", 1)[1] if "/" in rest else "/"

    def head(self, url, **kw):
        self.heads.append(url)
        path = self._path(url)
        if path in self._raise_on:
            raise RuntimeError("probe blew up")
        code = self._head(path)
        return None if code is None else self._resp(code)

    def get(self, url, **kw):
        if self._path(url) == "/":
            return None if self._root is None else self._resp(self._root)
        return self._resp(404)

    def stop_probing(self, *a, **k):
        return False

    def apex_answered(self, *a, **k):
        return self._apex


def _fake_checker(result, delay=0.0, calls=None):
    class _Fake:
        def check(self, d, *a, **k):
            if calls is not None:
                calls.append(d)
            if delay:
                import time as _t
                _t.sleep(delay)
            if isinstance(result, Exception):
                raise result
            return dict(result)
    return _Fake


def _fake_dns(v4, v6=(), per=None):
    """dns_cache.resolve and get_ip answering from fixed lists, or per domain
    from ``per`` ({domain: (v4, v6)}). No packet leaves."""
    def pick(d):
        return (per or {}).get(d, (v4, v6))

    def resolve(d, rtype, *a, **k):
        a4, a6 = pick(d)
        return list(a4 if rtype.upper() == "A" else a6 if rtype.upper() == "AAAA" else [])

    def get_ip(d):
        a4, _ = pick(d)
        return a4[0] if a4 else None
    return resolve, get_ip


def _check_review17_reporting(failures):
    """Deferred reporting findings, asserted against the real renderer paths."""
    import re
    import pdf_cards as pc
    import pdf_report as pr
    import estate_discovery as ed
    S = pr.build_styles()
    bad = []
    def check(ok, detail):
        if not ok:
            bad.append(detail)
    def text(obj):
        if isinstance(obj, (list, tuple)):
            return " ".join(text(x) for x in obj)
        return str(getattr(obj, "text", "")) + " " + text(getattr(obj, "_cellvalues", []))
    labels = ("Known Data Breaches", "Exposed Admin Panels", "DB/Service Exposure",
              "IP/Domain Blacklisted", "RDP Exposed")
    keys = ("breaches", "exposed_admin", "high_risk_protocols", "dnsbl", "vpn_remote")
    for status in (None, "error", "timeout", "no_api_key", "unknown", "completed"):
        for adverse in (False, True):
            cats = {key: {"status": status} for key in keys} if status else {}
            if adverse:
                cats = {key: {"status": status} for key in keys}
                cats["breaches"]["breach_count"] = 2
                cats["exposed_admin"]["critical_count"] = 2
                cats["high_risk_protocols"].update(critical_count=2, exposed_services=[{"port": 3306}, {"port": 5432}])
                cats["dnsbl"]["blacklisted"] = True
                cats["vpn_remote"]["rdp_exposed"] = True
            rows = {re.sub(r"</?b>", "", getattr(r[1], "text", "")): getattr(r[2], "text", "")
                    for r in pc.build_summary_table({"categories": cats}, S)._cellvalues}
            expected = (("2", "2", "2 critical service(s)", "YES", "YES") if adverse else
                        ("0", "0", "0 critical service(s)", "No", "No") if status == "completed" else
                        ("Not assessed",) * 5)
            for label, value in zip(labels, expected):
                raw = rows[label]
                visible = re.sub(r"<[^>]+>", "", raw).split("—", 1)[0].strip()
                check(visible == value, "FC13-3 %s/%s %s value %r != %r" % (status, adverse, label, visible, value))
                check(("#16a34a" in raw) == (not adverse and status == "completed"),
                      "FC13-3 %s/%s %s colour" % (status, adverse, label))
            kpis = {k["label"]: k for k in pr._assessment_extract_kpis({"categories": cats})}
            for label, value in zip(("Exposed Admin Panels", "Critical DB Exposed", "RDP Exposed"),
                                    ("2", "2", "Yes") if adverse else ("0", "0", "No") if status == "completed" else ("n/a",) * 3):
                check(kpis[label]["value"] == value, "FC13-3 KPI %s/%s %s value" % (status, adverse, label))
                check(kpis[label]["severity"] == ("bad" if adverse else "ok" if status == "completed" else "unknown"),
                      "FC13-3 KPI %s/%s %s severity" % (status, adverse, label))
    for sources, count in (([], 0), (["crtsh"], 1), (["certspotter"], 1), (["crtsh", "certspotter"], 2),
                           (["crtsh", "crtsh", "future-source", {}], 1)):
        for confirmed in (False, True):
            rd = {"status": "completed", "declared_count": int(confirmed), "scanned_count": int(confirmed),
                  "dependants": [{"domain": "partner.example", "measured": True, "not_measured": []}] if confirmed else [],
                  "discovery": {"ran": bool(sources), "sources_ok": sources, "candidate_count": 0}}
            expected = "Certificate discovery: %d of 2 sources answered; %s." % (
                count, "discovery coverage is partial" if count < 2 else "this does not prove a complete estate")
            check(ed.related_domains_certificate_coverage(rd) == expected, "C3 helper source count")
            for surface, rendered in (
                    ("card", pc.cat_related_domains({"related_domains": rd}, S)),
                    ("summary", pc.build_summary_table({"categories": {"related_domains": rd}}, S)),
                    ("deck", pr._assessment_slide_supply_chain({"categories": {"related_domains": rd}}))):
                check(expected in text(rendered), "C3 %s/%s/%s missing source coverage" % (count, confirmed, surface))
    check(ed.related_domains_certificate_coverage({}) is None, "C3 legacy fabricated coverage")
    check(ed.related_domains_certificate_coverage({"discovery": {}}) == "Certificate-source coverage was not recorded for this scan.",
          "C3 unrecorded coverage fabricated")

    # Coverage metadata is reporting-only: it must surface without changing
    # legacy checker score/status fields or implying a clean aggregate.
    partial = {"partial_coverage": True,
               "unassessed_ips": [{"ip": "203.0.113.9", "status": "timeout"}]}
    check("not assessed" in pc._per_ip_coverage_text(partial).lower(),
          "per-IP partial coverage note missing")
    summary = text(pc.build_summary_table({"categories": {
        "dns_infrastructure": dict(partial),
        "high_risk_protocols": {"status": "completed"},
        "shodan_vulns": {"status": "completed"},
    }}, S))
    check("Partial" in summary and "assessment incomplete" in summary,
          "summary omits per-IP partial coverage")

    from checkers_supply_chain import EmailVendorSurfaceChecker as _EVS
    _old_walk, _old_dmarc = _EVS._walk_includes, _EVS._fetch_dmarc_policy
    try:
        _EVS._walk_includes = lambda self, domain: [{"include": "sendgrid.net", "depth": 0}]
        _EVS._fetch_dmarc_policy = lambda self, domain: (setattr(self, "_dmarc_lookup", "failed") or "")
        _failed = _EVS().check("synthetic.test")
        _EVS._fetch_dmarc_policy = lambda self, domain: (setattr(self, "_dmarc_lookup", "no_record") or "")
        _no_record = _EVS().check("synthetic.test")
    finally:
        _EVS._walk_includes, _EVS._fetch_dmarc_policy = _old_walk, _old_dmarc
    check(_failed.get("dmarc_lookup") == "failed" and _no_record.get("dmarc_lookup") == "no_record",
          "DMARC lookup outcome metadata missing")
    check(_failed.get("score") == _no_record.get("score") and
          _failed.get("weak_dmarc") == _no_record.get("weak_dmarc"),
          "DMARC metadata changed legacy score/weak_dmarc")
    _failed_render = text(pc.cat_email_vendor_surface(
        {"email_vendor_surface": dict(_failed, status="completed")}, S)).lower()
    check("not verified" in _failed_render and "weak dmarc" not in _failed_render
          and "weak-policy finding is therefore unconfirmed" in _failed_render
          and "enables direct phishing impersonation" not in _failed_render,
          "failed DMARC actual checker-to-PDF flow still presents a confirmed weak policy")
    check("enables direct phishing impersonation" not in " ".join(_failed.get("issues") or []),
          "failed DMARC checker issue still claims confirmed impersonation risk")
    _medium_vb = {"status": "completed", "vendors_detected": ["sendgrid"],
                  "matches": [{"vendor": "sendgrid", "severity": "medium",
                               "date": "2025-01-01", "age_days": 100,
                               "exposure_class": "credentials"}],
                  "match_count": 1, "critical_match_count": 0,
                  "high_match_count": 0, "score": 100, "issues": [],
                  "vendor_breach_scope": "curated public-record database; not exhaustive",
                  "spf_lookup": "answered"}
    _medium_render = text(pc.cat_vendor_breach({"vendor_breach": _medium_vb}, S)).lower()
    check("confirmed public-record breach" in _medium_render
          and "no matching records" not in _medium_render,
          "medium/low vendor match incorrectly rendered as no matches")
    if bad:
        failures.append("review17[reporting]: " + "; ".join(bad))
    print("  [%s] review17 reporting: 12 status/finding cases and 10 provider/state cases" % ("FAIL" if bad else "PASS"))


def _check_review18_missing(failures):
    try:
        import copy
        from scoring_analytics import RiskScorer
        derived = {'ransomware_risk', 'data_breach_index', 'financial_impact'}
        base = {name: {'status': 'completed', 'score': 100} for name in RiskScorer.WEIGHTS}
        problems = []
        for name in RiskScorer.WEIGHTS:
            absent = copy.deepcopy(base)
            del absent[name]
            absent_score = RiskScorer().calculate(absent)
            sc = absent['_scan_completeness']
            if name in derived:
                if name in sc['failed_checkers'] or name in sc.get('missing_checkers', []):
                    problems.append(name + ': derived metric treated as raw probe')
                continue
            # PRODUCTION SCORING (owner decision, 3 November 2026): an absent
            # raw checker scores exactly like an empty, un-excluded category,
            # i.e. through the per-category defaults. Excluding it and
            # redistributing its weight is a deferred rate decision.
            empty = copy.deepcopy(base)
            empty[name] = {}
            empty_score = RiskScorer().calculate(empty)
            if absent_score[0] != empty_score[0]:
                problems.append('%s: missing checker re-weighted (absent %s, production default %s)'
                                % (name, absent_score[0], empty_score[0]))
            if name in sc['failed_checkers']:
                problems.append(name + ': missing checker joined failed_checkers (score/warning path)')
            # Reporting is kept: listed, qualified and explained.
            if name not in sc.get('missing_checkers', []):
                problems.append(name + ': missing metadata absent')
            if not sc.get('score_qualified') or sc.get('confidence_level') == 'full':
                problems.append(name + ': missing check counted complete')
            if 'not measured clean' not in sc['disclaimer']:
                problems.append(name + ': explanation absent')
        print('raw_cases=28 derived_controls=3 failures=' + str(len(problems)))
        for failure in problems:
            print(failure)
        assert not problems, problems
    except Exception as exc:
        failures.append("review18[missing]: " + str(exc))


def _check_review18_cms(failures):
    try:
        import http_client
        import checkers_supply_chain as cs
        import pdf_cards as pc
        from pdf_helpers import build_styles
        class Resp:
            def __init__(self,status,text=''): self.status_code=status; self.text=text
        class FakeHTTP:
            def __init__(self,mode): self.mode=mode
            def get(self,url,**kwargs):
                m=self.mode
                if m=='failed': return None
                if m=='exception': raise OSError('offline probe failure')
                if m in ('403','429','500'): return Resp(int(m),'blocked')
                if m=='control_only': return Resp(404,'not found') if 'notreal' in url else None
                if m=='home_only_failure': return Resp(404,'not found') if 'wp-login' in url else None
                if m=='login_only_failure': return Resp(200,'ordinary homepage') if url.endswith('/') else None
                if m in ('nonwp404','nonwp410'):
                    return Resp(200,'<html>ordinary</html>') if url.endswith('/') else Resp(404 if m=='nonwp404' else 410,'not found')
                if m=='catchall': return Resp(200,'same shell')
                if m=='wp_home': return Resp(200,'<link href="/wp-content/plugins/x.css">') if url.endswith('/') else Resp(404,'not found')
                if m=='wp_login':
                    if 'notreal' in url: return Resp(404,'not found')
                    return Resp(404,'not found') if url.endswith('/') else Resp(200,'<form><input name="user_login"></form>')
                raise AssertionError(m)
        def check_mode(mode):
            old_http=http_client.HTTP; old_probe=cs.CMSPluginSBOMChecker._probe_plugin
            http_client.HTTP=FakeHTTP(mode); cs.CMSPluginSBOMChecker._probe_plugin=lambda self,base,dirname: None
            try: return cs.CMSPluginSBOMChecker().check('example.test')
            finally: http_client.HTTP=old_http; cs.CMSPluginSBOMChecker._probe_plugin=old_probe
        unknown=['failed','exception','403','429','500','control_only','home_only_failure','login_only_failure','catchall']
        rows={m:check_mode(m) for m in unknown+['nonwp404','nonwp410','wp_home','wp_login']}
        for m in unknown:
            r=rows[m]; assert r['status']=='unreachable' and 'score' not in r and r.get('is_wordpress') is None and r.get('probe_status')=='probe_failed',(m,r)
        for m in ['nonwp404','nonwp410']:
            r=rows[m]; assert r['status']=='skipped' and r.get('probe_status')=='confirmed_non_wordpress',(m,r)
        for m in ['wp_home','wp_login']:
            r=rows[m]; assert r['status']=='completed' and r.get('is_wordpress') is True,(m,r)
        S=build_styles()
        def txt(parts):
            out=[]
            def walk(p):
                t=getattr(p,'text',None) or (p.getPlainText() if hasattr(p,'getPlainText') else '')
                if t: out.append(t)
                for row in getattr(p,'_cellvalues',[]) or []:
                    for cell in row:
                        if isinstance(cell,(list,tuple)): walk(cell)
                        else: walk(cell)
                for child in getattr(p,'_flowables',[]) or []: walk(child)
                for child in getattr(p,'_content',[]) or []: walk(child)
            for p in parts: walk(p)
            return ' '.join(out)
        up=pc.cat_cms_plugin_sbom({'cms_plugin_sbom':rows['failed']},S); np=pc.cat_cms_plugin_sbom({'cms_plugin_sbom':rows['nonwp404']},S)
        u=txt(up); n=txt(np)
        assert 'Not assessed' in u and 'fingerprint probes were unavailable' in u
        assert 'Not applicable' in n and 'Not detected on answered probes' in n
    except Exception as exc:
        failures.append("review18[cms]: " + str(exc))


def _check_discovery_parity(failures):
    import importlib, ast, json, copy, shutil, subprocess, tempfile
    import re as _re
    ed = importlib.import_module("estate_discovery")
    pc = importlib.import_module("pdf_cards")
    pr = importlib.import_module("pdf_report")
    csc = importlib.import_module("checkers_supply_chain")
    rdd = importlib.import_module("related_domain_discovery")
    import http_client as _hc
    from scoring_pipeline import apply_risk_score
    S = pr.build_styles()
    _check_review17_reporting(failures)
    _check_review18_missing(failures)
    _check_review18_cms(failures)
    coverage_case = {"overall_risk_score": 372, "risk_level": "Medium", "categories": {},
                     "_scan_completeness": {"score_qualified": True, "completeness_pct": 67,
                         "missing_checkers": ["related_domains"], "failed_checkers": ["related_domains", "cms_plugin_sbom"],
                         "disclaimer": "Unavailable checks are not measured clean."}}
    coverage_text = _rd_flow_text(pc.assessment_coverage_notice(coverage_case, S))
    deck_coverage = _rd_flow_text(pr._assessment_slide_score_and_kpis(coverage_case))
    if not all(text in coverage_text for text in ("Assessment coverage incomplete", "not measured clean", "cms plugin sbom")):
        failures.append("review18[coverage]: PDF qualification missing")
    if not all(text in deck_coverage for text in ("Score qualified", "67%", "1 raw check(s) missing")):
        failures.append("review18[coverage]: deck qualification missing")
    if pc.assessment_coverage_notice({"_scan_completeness": {"score_qualified": False}}, S):
        failures.append("review18[coverage]: completed control falsely qualified")

    def report(ok, label, detail=""):
        print("  [%s] discovery:%-46s %s" % ("PASS" if ok else "FAIL", label, detail))

    # 1. The reducer, the reject side and the keep side.
    for label, primary, names, srcs, att, want, want_rej in DISCOVERY_SCENARIOS:
        out = ed.discover(primary, names, srcs, attested=att)
        got = {c["domain"]: c["attested"] for c in out["discovered"]}
        rej = {r["domain"]: r["reason"] for r in out["rejected"]}
        conf_ok = all(c["confidence"] == "unconfirmed" for c in out["discovered"])
        rej_ok = all(k in rej and frag in rej[k] for k, frag in want_rej.items())
        ok = (got == want) and rej_ok and conf_ok
        if not ok:
            failures.append("discovery[%s]: listed=%r rejected=%r" % (label, got, rej))
        report(ok, label)

    # Every alias entry lists its zone for each of the group's own domains
    # (critique round 5, G5-13).
    bad = []
    for zone, owners in ed._BRAND_ALIASES.items():
        for owner in owners:
            listed_ = {c["domain"] for c in ed.discover(owner, ["www." + zone],
                                                        ["crtsh"])["discovered"]}
            if zone not in listed_:
                bad.append("%s for %s" % (zone, owner))
    if bad:
        failures.append("discovery[aliases]: not listed: " + "; ".join(bad))
    report(not bad, "every_group_alias_lists_its_zone", "%d zones" % len(ed._BRAND_ALIASES))

    # 2. "ran" means a source answered, and names can only come from one that did.
    no_source = ed.discover("acme.co.za", [], [])["discovery"]["ran"]
    names_only = ed.discover("acme.co.za", ["www.sib.co.za"], [])["discovery"]["ran"]
    ok = no_source is False and names_only is True
    if not ok:
        failures.append("discovery[ran]: no source -> %r, names without a source -> %r"
                        % (no_source, names_only))
    report(ok, "ran_means_a_source_answered")

    # A sister company with five names among 21 single-name tenants is listed
    # first: organisations rank by the names seen, not only by a producer
    # sample. The two tenants past the list are counted as unconfirmed.
    names = (["h%d.zz-sister.co.za" % i for i in range(5)]
             + ["www.tenant%02d.co.za" % i for i in range(21)])
    out = ed.discover("acme.co.za", names, ["crtsh"])
    listed = [c["domain"] for c in out["discovered"]]
    unl = out["discovery"]["not_listed_unconfirmed_count"]
    ok = listed[:1] == ["zz-sister.co.za"] and len(listed) == 20 and unl == 2
    if not ok:
        failures.append("discovery[ranking]: first=%r listed=%d unconfirmed_not_listed=%r"
                        % (listed[:1], len(listed), unl))
    report(ok, "ranks_by_names_seen_and_counts_the_rest")

    with io.open(os.path.join(SEC, "test_fixtures", "takealot_baseline.json"),
                 encoding="utf-8") as fh:
        fx = json.load(fh)
    base = fx.get("results") if "results" in fx else fx

    def with_rd(rd):
        r = copy.deepcopy(base)
        if rd is None:
            r["categories"].pop("related_domains", None)
        else:
            r["categories"]["related_domains"] = copy.deepcopy(rd)
        return r

    def price(rd):
        r = with_rd(rd)
        apply_risk_score(r)
        return r.get("overall_risk_score") or 0

    # FC13-2: absence now excludes a raw checker from weighting. Discovery's
    # no-adverse-finding contract compares with an explicit neutral result;
    # the missing-category policy is tested separately for every raw checker.
    neutral = price({"status": "completed", "score": 100})

    # 3. The builder scan() calls: every state, priced, and rendered.
    built = {}
    for label, related, sub, kind, want in RD_BUILDER:
        calls = []
        rd = ed.build_related_domains_category(
            want.get("domain", "acme.co.za"), related, copy.deepcopy(sub),
            _rd_probe(kind or "clean", calls))
        built[label] = rd
        state = ed.related_domains_state(rd)
        bad = []
        if rd.get("status") != want["status"]:
            bad.append("status=%r" % rd.get("status"))
        if state != want["state"]:
            bad.append("state=%r" % state)
        if "probed" in want and calls != (want["probed"] or []):
            bad.append("probed=%r" % calls)
        if "listed" in want:
            got = {c["domain"] for c in rd.get("discovered", []) if not c.get("attested")}
            if got != want["listed"]:
                bad.append("listed=%r" % sorted(got))
        for key, field in (("reason", "unassessed_reason"),
                           ("over_cap", "confirmed_over_cap"),
                           ("not_assessed", "confirmed_not_assessed")):
            if key in want and rd.get(field) != want[key]:
                bad.append("%s=%r" % (field, rd.get(field)))
        if "rejected" in want:
            got = {x["domain"] for x in rd.get("confirmed_rejected", [])}
            if got != want["rejected"]:
                bad.append("confirmed_rejected=%r" % sorted(got))
        if "full" in want and ed.related_domains_fully_assessed(rd) != want["full"]:
            bad.append("fully_assessed=%r" % ed.related_domains_fully_assessed(rd))
        p = price(rd)
        if want.get("loads"):
            if not p > neutral:
                bad.append("a confirmed finding priced %s, not above neutral %s" % (p, neutral))
        elif p != neutral:
            bad.append("priced %s against neutral %s" % (p, neutral))
        seen_col = []
        with mock.patch.object(pc, "build_cat_card", _colour_spy(pc, seen_col)):
            text = _rd_flow_text(pc.cat_related_domains({"related_domains": rd}, S)).lower()
        if "colour" in want and (seen_col or [None])[-1] != want["colour"]:
            bad.append("card colour %r, want %r" % ((seen_col or [None])[-1], want["colour"]))
        for ph in want.get("says", []):
            if ph.lower() not in text:
                bad.append("card lacks %r" % ph)
        for ph in want.get("never", []):
            if ph.lower() in text:
                bad.append("card says %r" % ph)
        if "block_excludes" in want:
            block = _rd_flow_text(pc._rd_discovered_block(rd, S))
            if want["block_excludes"] in block:
                bad.append("a confirmed domain is listed as awaiting confirmation")
        if bad:
            failures.append("discovery[builder:%s]: %s" % (label, "; ".join(bad)))
        report(not bad, "builder:" + label, "%s / %s / %s" % (rd.get("status"), state, p))

    # Parity: the form (a confirmed domain) and the API (none) see one estate.
    form = {c["domain"] for c in built["confirmed_clean"]["discovered"]}
    api = {c["domain"] for c in built["api_ct_answered"]["discovered"]}
    ok = form == api and bool(api)
    if not ok:
        failures.append("discovery[parity]: form %r vs API %r" % (sorted(form), sorted(api)))
    report(ok, "form_and_api_discover_the_same")

    # 4. Scans stored before step 5 never re-render as "none found".
    for label, rd, want_state in RD_LEGACY:
        state = ed.related_domains_state(rd)
        text = _rd_flow_text(pc.cat_related_domains({"related_domains": rd}, S)).lower()
        bad = []
        if state != want_state:
            bad.append("state=%r" % state)
        if want_state == "not_run":
            if "not assessed" not in text:
                bad.append("card does not say Not assessed")
            if "none found" in text or NONE_FOUND_TEXT in text:
                bad.append("card says none found")
        elif "before related-domain discovery was added" not in text:
            bad.append("card does not say the scan predates discovery")
        if (rd.get("status") in ("timeout", "error")
                and "confirmed for this scan were not assessed" not in text):
            bad.append("a stored timeout or error does not say its confirmed domains "
                       "went unassessed")
        if want_state == "confirmed" and text.count(pc._RD_LEGACY_CONFIRMED.lower()) != 1:
            bad.append("a stored confirmed result does not state its caveat exactly once")
        if bad:
            failures.append("discovery[legacy:%s]: %s" % (label, "; ".join(bad)))
        report(not bad, "legacy:" + label, state)

    # Beside a finding, and beside issues (where the card's fallback is hidden),
    # the stored-result caveat is still stated, and only once (critique round 5,
    # T5-4).
    legacy_base = next(rd for l, rd, st in RD_LEGACY if st == "confirmed")
    legacy_shapes = [
        ("clean", legacy_base),
        ("with_issues", dict(legacy_base, issues=["[dns] sib.co.za: port 3389 open"])),
        ("with_high", dict(legacy_base, score=40, high_count=1,
                           dependants=[{"domain": "sib.co.za", "lite_score": 40,
                                        "critical_paths": 0}],
                           worst_domain={"domain": "sib.co.za", "lite_score": 40},
                           issues=["[ssl] sib.co.za: no valid TLS"])),
        ("with_critical", dict(legacy_base, critical_count=1,
                               dependants=[{"domain": "sib.co.za", "lite_score": 88,
                                            "critical_paths": 1}],
                               issues=["[info] sib.co.za: /.env exposed"])),
    ]
    bad = []
    for l, rd in legacy_shapes:
        card_ = _rd_flow_text(pc.cat_related_domains({"related_domains": rd}, S))
        n = card_.count(pc._RD_LEGACY_CONFIRMED)
        m = card_.lower().count("not a complete assessment")
        if n != 1 or m != 1:
            bad.append("%s states it %d time(s), 'not a complete assessment' %d time(s)"
                       % (l, n, m))
    if bad:
        failures.append("discovery[legacy_caveat]: " + "; ".join(bad))
    report(not bad, "stored_result_caveat_once", "%d shapes" % len(legacy_shapes))

    # 5. The executive deck, rendered: every discovery state, every legacy
    # shape, and the confirmed states, where a finding must show as a finding.
    NA = "Not assessed (no scan data)"
    OWN, OWN_PART = "own: not assessed", "own: not fully assessed"
    deck_cases = [
        # (label, category, footer group, text the deck must carry, text it must not)
        ("degraded", built["api_ct_outage"], OWN,
         "not assessed (the certificate lookup returned no result)", None),
        ("degraded_subdomains", built["api_subdomains_timed_out"], OWN,
         "not assessed (the subdomain check did not complete)", None),
        ("awaiting_confirmation", built["api_ct_answered"], OWN,
         "2 found on certificate records", None),
        ("confirmed_unassessed", built["probe_timed_out"], OWN,
         "1 confirmed related domain(s) could not be assessed within the time "
         "allowed; 1 further related domain(s) found, awaiting broker confirmation",
         None),
        ("none_found", built["api_ct_answered_none_found"], OWN,
         "none found on certificate records", None),
        # A clean confirmed estate: candidates still awaiting confirmation are
        # stated beside it, and only where there are some.
        ("confirmed_clean", built["confirmed_clean"], "Assessed",
         "1 further related domain(s) found on certificate records, awaiting "
         "broker confirmation and not assessed", None),
        ("confirmed_clean_no_candidates", built["confirmed_clean_no_candidates"],
         "Assessed", None, "further related domain"),
        ("partial_checks", built["partial_checks"], OWN_PART,
         "1 of 1 confirmed related domain(s) assessed, some checks not assessed on 1; "
         "1 further related domain(s) found, awaiting broker confirmation", None),
        ("partial_with_rejected_entry", built["partial_with_rejected_entry"], OWN_PART,
         "1 of 1 confirmed related domain(s) assessed", "1 of 2"),
        ("over_the_cap", built["over_the_cap"], OWN_PART,
         "10 of 12 confirmed related domain(s) assessed", None),
        ("confirmed_finding", built["confirmed_finding"], None,
         "1 critical of 1 assessed related domain(s)", None),
        ("confirmed_high_only", built["confirmed_high_only"], None,
         "1 of 1 related domain(s) below 60/100", None),
        # A partial assessment's finding outranks its incompleteness.
        ("partial_with_critical", built["partial_with_critical"], None,
         "1 critical of 1 assessed related domain(s)", None),
        ("partial_with_high", built["partial_with_high"], None,
         "1 of 1 related domain(s) below 60/100", None),
        # Beside a finding, what the card leaves unsaid gets a sentence of its own.
        ("confirmed_finding_footnote", built["confirmed_finding"], None,
         "Related domains: 1 further related domain(s) found on certificate records, "
         "awaiting broker confirmation and not assessed", None),
        ("partial_with_critical_footnote", built["partial_with_critical"], None,
         "not fully assessed (1 of 2 confirmed related domain(s) assessed)", None),
        ("confirmed_while_discovery_down", built["confirmed_while_discovery_down"],
         "Assessed", "related-domain discovery could not run on this scan", None),
        ("partial_while_discovery_down", built["partial_while_discovery_down"], OWN_PART,
         "1 of 1 confirmed related domain(s) assessed, some checks not assessed on 1; "
         "related-domain discovery could not run", None),
        # Nothing assessed is never "a positive due-diligence result".
        ("nothing_assessed_is_not_clean", built["api_ct_answered_none_found"], OWN,
         "No supply-chain signal could be assessed on this scan",
         "positive due-diligence result"),
        # Beside a finding every gap is still stated (critique round 6: GS6-5,
        # CD6-2): a HIGH card's partial assessment, discovery that could not
        # run beside a finding and beside a timeout, a stored result with a
        # finding.
        ("partial_with_high_footnote", built["partial_with_high"], None,
         "not fully assessed (1 of 2 confirmed related domain(s) assessed)", None),
        ("finding_while_discovery_down", built["finding_while_discovery_down"], None,
         "related-domain discovery could not run on this scan", None),
        ("timeout_while_discovery_down", built["timeout_while_discovery_down"], OWN,
         "could not be assessed within the time allowed; related-domain discovery "
         "could not run", None),
        ("legacy_with_high", dict(legacy_shapes)["with_high"], None,
         "not fully assessed (stored by an earlier version of the check", None),
        ("legacy_with_critical", dict(legacy_shapes)["with_critical"], None,
         "not fully assessed (stored by an earlier version of the check", None),
        # Timed out beside domains over the cap: the deck counts those too
        # (critique round 6, ST6-5).
        ("unassessed_with_overcap", built["unassessed_with_overcap_and_rejected"], OWN,
         "2 further confirmed related domain(s) not assessed, because a scan assesses "
         "at most 10", None),
        # Partly assessed and nothing else: never "none could be assessed"
        # (critique round 6, ST6-4).
        ("partly_assessed_wording", built["over_the_cap"], OWN_PART,
         "No supply-chain signal was fully assessed on this scan",
         "could be assessed on this scan"),
    ] + [("legacy:" + l, rd, NA if st == "not_run" else OWN_PART,
          None if st == "not_run" else "stored by an earlier version of the check", None)
         for l, rd, st in RD_LEGACY]
    for label, rd, want_group, want_text, never_text in deck_cases:
        text = _pdf_visible_text(pr.generate_pdf(with_rd(rd), report_type="assessment"))
        group = _deck_group(text)
        ok = ((want_group is None or group == want_group)
              and (want_text is None or want_text in text)
              and (never_text is None or never_text not in text))
        if not ok:
            failures.append("discovery[deck:%s]: related domains filed under %r%s%s"
                            % (label, group,
                               "" if want_text is None or want_text in text
                               else ", and the deck lacks %r" % want_text,
                               "" if never_text is None or never_text not in text
                               else ", and the deck says %r" % never_text))
        report(ok, "deck:" + label, "%s %s" % (group, want_text or ""))

    # The vendor cross-correlation's "no_data" is clean only when Hudson Rock
    # completed; when Hudson Rock did not, nothing was measured (critique round
    # 6, FC6-1). The dict is the one scan() writes.
    tpc_no_data = {"status": "no_data", "hudson_rock_third_party_count": 0,
                   "hudson_rock_employees": 0, "spf_vendor_count": 0, "spf_vendors": [],
                   "vendor_breach_match_count": 0, "suspected_vendors": [],
                   "severity": "none", "critical_count": 0, "high_count": 0,
                   "score": 100, "issues": []}
    bad = []
    # Every way Hudson Rock can fail to complete, a status the gate has never
    # seen, and no Hudson Rock at all (critique round 7, GS7-2).
    for hr_status, clean_ in (("error", False), ("timeout", False), ("no_api_key", False),
                              ("rate_limited", False), ("skipped", False),
                              ("never-seen-status", False), (None, False), ("missing", False),
                              ("completed", True)):
        r_ = with_rd(built["api_ct_outage"])
        if hr_status == "missing":
            r_["categories"].pop("hudson_rock", None)
        elif hr_status is None:
            r_["categories"]["hudson_rock"] = {"third_party_exposures": 0}
        else:
            r_["categories"]["hudson_rock"] = {"status": hr_status, "third_party_exposures": 0}
        r_["categories"]["third_party_correlation"] = dict(tpc_no_data)
        text = _pdf_visible_text(pr.generate_pdf(r_, report_type="assessment"))
        positive_claim = "positive due-diligence result" in text
        measured_footer = "Assessed: Cross-checked vendor exposure" in text
        # The nine Hudson Rock cases never produce the strongest positive
        # paragraph; assert that absence independently from the footer.
        if positive_claim:
            bad.append("Hudson Rock %s -> the deck emitted an unearned "
                       "positive due-diligence result" % hr_status)
        if measured_footer != clean_:
            bad.append("Hudson Rock %s -> measured vendor footer=%r, expected=%r"
                       % (hr_status, measured_footer, clean_))
    if bad:
        failures.append("discovery[deck:vendor_join]: " + "; ".join(bad))
    report(not bad, "deck_vendor_join_clean_only_when_measured")

    # The slide's pill and sub-line, not only its paragraph (critique round 7,
    # GS7-3), and its footer list beside a partly assessed signal (ST7-4).
    # Every pill the deck draws, so the verdict's colour is read as well as its
    # words (critique round 8, GS8-6). The slide's palette is local to it, so
    # it is read from the source.
    pills = []
    sev_hex_ = {}
    for n_ in ast.walk(ast.parse(io.open(pr.__file__, encoding="utf-8").read())):
        if isinstance(n_, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_SC_SEV_HEX"
                                              for t in n_.targets):
            sev_hex_ = {k: str(v).lower() for k, v in ast.literal_eval(n_.value).items()}

    def slide_of(rd, extra=None):
        r_ = with_rd(rd)
        for k, v in (extra or {}).items():
            r_["categories"][k] = v
        real_pill = pr._asx_pill

        def _pill(text, bg_hex, *a, **k):
            pills.append((str(text), str(bg_hex).lower()))
            return real_pill(text, bg_hex, *a, **k)
        del pills[:]
        with mock.patch.object(pr, "_asx_pill", _pill):
            text_ = _pdf_visible_text(pr.generate_pdf(r_, report_type="assessment"))
        i_ = text_.find("SUPPLY-CHAIN EXPOSURE")
        return text_[i_:text_.find("Full signal-by-signal detail", i_)] if i_ >= 0 else ""

    def verdict_pill():
        """The last slide's verdict pill, and whether its fill is the one its
        words call for: neutral grey for NOT ASSESSED and NOT FULLY ASSESSED,
        never a severity colour; a severity's own colour otherwise."""
        vp = [p for p in pills if p[0].endswith(" EXPOSURE")
              or p[0] in ("NOT ASSESSED", "NOT FULLY ASSESSED")]
        if len(vp) != 1:
            return vp, False
        words, fill = vp[0]
        verdict_fills = {sev_hex_.get(k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        if words.startswith("NOT "):
            return vp, fill == "#475569" and fill not in verdict_fills
        return vp, bool(sev_hex_) and fill == sev_hex_.get(words.split()[0])
    # The neutral measurement state must be explained alongside risk colours.
    _legend17 = pc._build_legend(S)
    _legend17_labels = [getattr(r[1], "text", "") for r in _legend17._cellvalues]
    if "<b>Not assessed</b>" not in _legend17_labels:
        failures.append("discovery[legend]: the unmeasured state has no legend entry")
    verdicts = [
        ("nothing_assessed", built["api_ct_answered_none_found"], None,
         ["NOT ASSESSED", "No external supply-chain signals could be assessed on this scan."],
         ["LOW EXPOSURE", "NOT FULLY ASSESSED", "All 0"]),
        ("partly_assessed", built["over_the_cap"], None,
         ["NOT FULLY ASSESSED",
          "No external supply-chain signal was fully assessed on this scan.",
          "Fully assessed: none."],
         ["LOW EXPOSURE", "All 0", "Assessed: none."]),
        ("finding", built["confirmed_finding"], None, ["CRITICAL EXPOSURE"], ["LOW EXPOSURE"]),
        ("vendor_join_measured", built["api_ct_outage"],
         {"hudson_rock": {"status": "completed", "third_party_exposures": 0},
          "third_party_correlation": dict(tpc_no_data)},
         ["NOT FULLY ASSESSED", "All 1 assessed supply-chain signal(s) are clean."],
         ["LOW EXPOSURE", "NOT ASSESSED"]),
        ("vendor_join_unmeasured", built["api_ct_outage"],
         {"hudson_rock": {"status": "timeout"}, "third_party_correlation": dict(tpc_no_data)},
         ["NOT ASSESSED"], ["LOW EXPOSURE", "positive due-diligence result"]),
    ]
    bad = []
    if {k.lower(): v for k, v in sev_hex_.items()} != {
            "critical": "#991b1b", "high": "#dc2626", "medium": "#92400e",
            "low": "#166534", "info": "#475569"}:
        bad.append("the slide's palette is %r" % (sev_hex_,))
    for label, rd, extra, must, never in verdicts:
        slide = slide_of(rd, extra)
        miss = [m for m in must if m not in slide]
        hit = [n for n in never if n in slide]
        if not slide or miss or hit:
            bad.append("%s: missing %r, has %r" % (label, miss, hit))
        vp, fill_ok = verdict_pill()
        if not fill_ok:
            bad.append("%s: verdict pill %r" % (label, vp))
    if bad:
        failures.append("discovery[deck:verdict]: " + "; ".join(bad))
    report(not bad, "deck_verdict_follows_what_was_assessed", "%d cases" % len(verdicts))

    # S-4 and S-5 say whether "no vendors" was measured: an SPF lookup that did
    # not answer is not clean on the deck (critique round 7, CL7-1).
    import dns.resolver as _dnsr
    import dns.exception as _dnse
    import checkers_supply_chain as _csc_spf
    bad = []
    # A MEDIUM vendor join is Hudson Rock alone, or an overlap whose worst
    # matched breach is medium: the slide says which (critique round 9, CD9-6).
    join_hr = {"status": "completed", "compromised_employees": 0, "compromised_users": 0,
               "third_party_exposures": 3, "issues": []}
    join_base = {"status": "completed", "severity": "medium", "medium_count": 1,
                 "critical_count": 0, "high_count": 0, "score": 90, "issues": [],
                 "hudson_rock_third_party_count": 3, "spf_vendor_count": 1,
                 "vendor_breach_match_count": 1}
    slide_ov = slide_of(built["api_ct_outage"], {
        "hudson_rock": join_hr,
        "third_party_correlation": dict(join_base, suspected_vendors=[
            {"vendor": "intercom", "breaches": [{"severity": "medium", "date": "2023-08-31"}]}])})
    slide_hr = slide_of(built["api_ct_outage"], {
        "hudson_rock": join_hr,
        "third_party_correlation": dict(join_base, suspected_vendors=[])})
    if "overlap at intercom" not in slide_ov or "no SPF / breach overlap" in slide_ov:
        bad.append("a MEDIUM join with an overlap does not name the vendor")
    if "no SPF / breach overlap" not in slide_hr:
        bad.append("a MEDIUM join without an overlap does not say so")
    for how, exc, want_ in (("timeout", _dnse.Timeout(), "failed"),
                            ("servfail", _dnsr.NoNameservers(), "failed"),
                            ("nxdomain", _dnsr.NXDOMAIN(), "answered"),
                            ("noanswer", _dnsr.NoAnswer(), "answered")):
        def _raise(*a, _e=exc, **k):
            raise _e
        with mock.patch.object(_dnsr, "resolve", _raise):
            evs_ = _csc_spf.EmailVendorSurfaceChecker().check("acme.co.za")
            vb_ = _csc_spf.VendorBreachChecker().check("acme.co.za")
        got_ = (evs_.get("status"), evs_.get("spf_lookup"), vb_.get("status"),
                vb_.get("spf_lookup"))
        if got_ != ("no_data", want_, "no_data", want_):
            bad.append("%s -> %r" % (how, got_))
    for how in ("failed", "answered"):
        slide = slide_of(built["api_ct_outage"], {
            "email_vendor_surface": {"status": "no_data", "spf_lookup": how, "score": 100,
                                     "issues": [], "vendors_detected": [], "vendor_count": 0},
            "vendor_breach": {"status": "no_data", "spf_lookup": how, "score": 100,
                              "issues": [], "matches": [], "match_count": 0}})
        # A measured SPF pair is credited as measured, not as a clean estate.
        credited = all(_deck_group(slide, name) == "Assessed" for name in
                       ("Email service providers", "Known vendor breaches"))
        if credited != (how == "answered"):
            bad.append("SPF lookup %s -> the deck %s" % (
                how, "calls S-4/S-5 clean" if credited else "does not credit a measured result"))
    # A lookup behind an include, and a record that delegates with redirect=,
    # where no vendor was identified, are not measured either; a walk that
    # answered and found a vendor completes (critique round 8, FC8-1, FC8-3).
    class _Txt:
        def __init__(self, t):
            self.strings = [t.encode()]

    def _zone(rec):
        def res(name, rdtype="A", *a, **k):
            v = rec.get(str(name).rstrip("."))
            if v is None:
                raise _dnsr.NXDOMAIN()
            if isinstance(v, Exception):
                raise v
            return [_Txt(v)]
        return res
    evs_real, vb_real = {}, {}
    top_ = "v=spf1 include:_spf.acme.co.za -all"
    MS_, PM_ = "spf.protection.outlook.com", "spf.mtasv.net"
    # want: S-4 status and outcome, S-5 status and outcome, a vendor identified.
    for how, rec, want_ in (
            ("nested_timeout", {"acme.co.za": top_, "_spf.acme.co.za": _dnse.Timeout()},
             ("no_data", "failed", "no_data", "failed", False)),
            ("nested_servfail", {"acme.co.za": top_, "_spf.acme.co.za": _dnsr.NoNameservers()},
             ("no_data", "failed", "no_data", "failed", False)),
            ("redirect_only", {"acme.co.za": "v=spf1 redirect=_spf.acme.co.za"},
             ("no_data", "not_followed", "no_data", "not_followed", False)),
            ("include_and_redirect",
             {"acme.co.za": "v=spf1 include:_spf.x.co.za redirect=_spf.acme.co.za",
              "_spf.x.co.za": "v=spf1 -all"},
             ("no_data", "not_followed", "no_data", "not_followed", False)),
            ("no_includes", {"acme.co.za": "v=spf1 ip4:196.22.1.5 -all"},
             ("no_data", "answered", "no_data", "answered", False)),
            ("includes_no_vendor",
             {"acme.co.za": "v=spf1 include:_spf.x.co.za -all",
              "_spf.x.co.za": "v=spf1 ip4:196.22.1.5 -all"},
             ("completed", "answered", "completed", "answered", False)),
            ("nested_answered",
             {"acme.co.za": top_, "_spf.acme.co.za": "v=spf1 include:%s -all" % MS_,
              MS_: "v=spf1 -all"},
             ("completed", "answered", "completed", "answered", True)),
            # SPF mechanism and modifier names are case-insensitive (RFC 7208
            # s4.6.1): a capitalised spelling delegates, and authorises, exactly
            # as the lower-case one does (critique round 9, FC9-2, IR9-2, GS9-1,
            # ST9-3).
            ("upper_redirect",
             {"acme.co.za": "v=spf1 Redirect=_spf.acme.co.za",
              "_spf.acme.co.za": "v=spf1 include:%s -all" % MS_, MS_: "v=spf1 -all"},
             ("no_data", "not_followed", "no_data", "not_followed", False)),
            ("nested_upper_redirect",
             {"acme.co.za": "v=spf1 include:_spf.x.co.za -all",
              "_spf.x.co.za": "v=spf1 REDIRECT=_spf.y.co.za"},
             ("no_data", "not_followed", "no_data", "not_followed", False)),
            ("caps_include",
             {"acme.co.za": "v=spf1 Include:%s -all" % MS_, MS_: "v=spf1 -all"},
             ("completed", "answered", "completed", "answered", True)),
            ("caps_version",
             {"acme.co.za": "V=SPF1 include:%s -all" % MS_, MS_: "v=spf1 -all"},
             ("completed", "answered", "completed", "answered", True)),
            # A vendor found beside a lookup that did not answer, or a record
            # the walk does not follow: the vendors are a lower bound, and a
            # finding they carry still loads (critique round 9, GS9-2).
            ("vendor_plus_timeout",
             {"acme.co.za": "v=spf1 include:%s include:_spf.acme.co.za -all" % MS_,
              MS_: "v=spf1 -all", "_spf.acme.co.za": _dnse.Timeout()},
             ("completed", "partial", "completed", "partial", True)),
            ("vendor_plus_redirect",
             {"acme.co.za": "v=spf1 include:%s redirect=_spf.acme.co.za" % MS_,
              MS_: "v=spf1 -all"},
             ("completed", "partial", "completed", "partial", True)),
            ("quiet_vendor_plus_timeout",
             {"acme.co.za": "v=spf1 include:%s include:_spf.acme.co.za -all" % PM_,
              PM_: "v=spf1 -all", "_spf.acme.co.za": _dnse.Timeout(),
              "_dmarc.acme.co.za": "v=DMARC1; p=reject"},
             ("completed", "partial", "completed", "partial", True))):
        with mock.patch.object(_dnsr, "resolve", _zone(rec)):
            evs_ = _csc_spf.EmailVendorSurfaceChecker().check("acme.co.za")
            vb_ = _csc_spf.VendorBreachChecker().check("acme.co.za")
        got_ = (evs_.get("status"), evs_.get("spf_lookup"), vb_.get("status"),
                vb_.get("spf_lookup"), bool(evs_.get("vendor_count")))
        evs_real[how], vb_real[how] = evs_, vb_
        if got_ != want_:
            bad.append("%s -> %r" % (how, got_))
    # The deck, rendered from what the real checkers returned for every zone:
    # each signal's own outcome decides its place, S-5's as well as S-4's
    # (critique round 9, GS9-4). A partial walk is never clean; a finding it
    # carries still loads, with the lower bound stated.
    for how in evs_real:
        e_, v_ = evs_real[how], vb_real[how]
        slide = slide_of(built["api_ct_outage"], {"email_vendor_surface": e_,
                                                  "vendor_breach": v_})
        credited = []
        for name_, pay_, flagged_ in (
                ("Email service providers", e_,
                 bool((e_.get("weak_dmarc") and e_.get("vendor_count", 0) >= 1)
                      or e_.get("vendor_count", 0) >= 6)),
                ("Known vendor breaches", v_, bool(v_.get("matches")))):
            outcome_ = pay_.get("spf_lookup")
            if outcome_ in ("failed", "not_followed"):
                want_grp = "own: not assessed"
            elif outcome_ == "partial" and not flagged_:
                want_grp = "own: not fully assessed"
            elif outcome_ == "partial":
                # The finding it carries still loads and still sets the verdict,
                # but the signal is named as partly assessed, never as assessed
                # (step-5 critique round 11, R11-SC-3).
                want_grp = "Partly assessed"
            else:
                want_grp = "Assessed"
            if outcome_ == "partial" and not flagged_:
                # The reason, not just the heading it opens with: the
                # parenthetical could state the opposite and pass (GS11-5).
                import re as _re_g
                m_r = _re_g.search(_re_g.escape(name_)
                                   + r": not fully assessed \(([^)]*)\)", slide)
                reason_ = m_r.group(1).lower() if m_r else ""
                if ("lower bound" not in reason_
                        or "complete sending surface" in reason_):
                    bad.append("%s/%s: the reason reads %r"
                               % (how, name_, reason_[:140]))
            grp_ = _deck_group(slide, name_)
            if grp_ != want_grp:
                bad.append("%s/%s: %s filed under %r, want %r"
                           % (how, outcome_, name_, grp_, want_grp))
            credited.append(want_grp == "Assessed")
            if outcome_ == "partial" and flagged_ and "lower bound" not in slide:
                bad.append("%s: %s does not state the lower bound" % (how, name_))
            if (outcome_ == "partial" and flagged_
                    and "carry a finding on an SPF chain that was only partly "
                        "read" not in slide):
                bad.append("%s: the verdict sub-line omits the partly read "
                           "finding for %s" % (how, name_))
        if not any(credited) and "positive due-diligence result" in slide:
            bad.append("%s: the deck credits an unmeasured slide" % how)
    # Each deck block reads its own category's field, in mixed outcomes
    # (critique round 8, GS8-2), for a result stored before the field existed
    # (CD8-3) and for a record that redirects (FC8-3); a signal the deck
    # cannot credit says why, in a sentence of its own.
    def _evs(how, status="no_data"):
        d = {"status": status, "score": 100, "issues": [], "vendors_detected": [],
             "vendor_count": 0}
        if how is not None:
            d["spf_lookup"] = how
        return d

    def _vb(how, status="no_data"):
        d = {"status": status, "score": 100, "issues": [], "matches": [], "match_count": 0}
        if how is not None:
            d["spf_lookup"] = how
        return d
    measured_ = {"status": "completed", "spf_lookup": "answered",
                 "score": 100, "issues": [], "vendor_count": 1,
                 "unknown_count": 0, "dmarc_policy": "reject", "weak_dmarc": False,
                 "spf_includes": [{"include": "spf.protection.outlook.com", "depth": 0}],
                 "vendors_detected": [{"vendor": "microsoft_365",
                                       "includes": ["spf.protection.outlook.com"]}]}
    why_ = {"failed": "an SPF lookup did not answer",
            "not_followed": "a record in the SPF chain redirects to another record",
            None: "stored by an earlier version of the check"}
    for label, e_, v_, e_in, v_in in (
            ("s4_answered_s5_failed", _evs("answered"), _vb("failed"), True, False),
            ("s4_failed_s5_answered", _evs("failed"), _vb("answered"), False, True),
            ("s4_measured_s5_failed", measured_, _vb("failed"), True, False),
            ("s4_not_followed_s5_answered", _evs("not_followed"), _vb("answered"),
             False, True),
            ("both_stored_before_the_field", _evs(None), _vb(None), False, False)):
        slide = slide_of(built["api_ct_outage"], {"email_vendor_surface": e_,
                                                  "vendor_breach": v_})
        for name_, inn, pay in (("Email service providers", e_in, e_),
                                ("Known vendor breaches", v_in, v_)):
            grp_ = _deck_group(slide, name_)
            if inn and grp_ != "Assessed":
                bad.append("%s: %s filed under %r" % (label, name_, grp_))
            if not inn and ("%s: not assessed (%s" % (name_, why_[pay.get("spf_lookup")])
                            not in slide):
                bad.append("%s: %s filed under %r, without its reason" % (label, name_, grp_))
        if not (e_in or v_in) and ("LOW EXPOSURE" in slide
                                   or "positive due-diligence result" in slide):
            bad.append("%s: the deck credits S-4/S-5" % label)
    # Every S-4/S-5 "no_data" prices exactly as a completed result with no
    # vendors, whatever the lookup recorded: the mapping reports, it never
    # prices (critique round 8).
    def _price_sc(e_, v_):
        r_ = with_rd(None)
        r_["categories"]["email_vendor_surface"] = copy.deepcopy(e_)
        r_["categories"]["vendor_breach"] = copy.deepcopy(v_)
        apply_risk_score(r_)
        return r_.get("overall_risk_score") or 0
    p_done = _price_sc(_evs(None, "completed"), _vb(None, "completed"))
    p_nd = {str(h_): _price_sc(_evs(h_), _vb(h_))
            for h_ in ("answered", "failed", "not_followed", None)}
    if set(p_nd.values()) != {p_done}:
        bad.append("no_data prices %r against %r for a completed result" % (p_nd, p_done))
    # A vendor found beside a lookup that did not answer is a finding, and a
    # finding prices (critique round 9, GS9-2).
    p_vendor = _price_sc(evs_real["vendor_plus_timeout"], vb_real["vendor_plus_timeout"])
    if not p_vendor > p_done:
        bad.append("a vendor found beside a failed lookup prices %r, not above %r"
                   % (p_vendor, p_done))
    # The shape the earlier check stored whenever a lookup behind an include did
    # not answer, or a record redirected: completed, no vendor, no record of the
    # lookup. It cannot be told from a measured result, so no surface may read
    # it as clean (critique round 9, ST9-2, FC9-3).
    stored_evs = {"status": "completed", "score": 100, "issues": [], "vendor_count": 0,
                  "unknown_count": 1, "dmarc_policy": "reject", "weak_dmarc": False,
                  "vendors_detected": [],
                  "spf_includes": [{"include": "_spf.acme.co.za", "depth": 0}]}
    stored_vb = {"status": "completed", "score": 100, "issues": [], "vendors_detected": [],
                 "matches": [], "match_count": 0, "critical_match_count": 0,
                 "high_match_count": 0}
    measured_evs = dict(stored_evs, spf_lookup="answered")
    measured_vb = dict(stored_vb, spf_lookup="answered")
    slide = slide_of(built["api_ct_outage"], {"email_vendor_surface": stored_evs,
                                              "vendor_breach": stored_vb})
    for name_ in ("Email service providers", "Known vendor breaches"):
        if _deck_group(slide, name_) != "own: not assessed":
            bad.append("stored completed: %s filed under %r"
                       % (name_, _deck_group(slide, name_)))
    if ("did not record whether every SPF lookup answered" not in slide
            or "positive due-diligence result" in slide):
        bad.append("stored completed: the deck does not say why, or credits it")
    # Some signals assessed and others not: the credit is proportionate, and the
    # unqualified "not an absence of checking" belongs only to a slide with
    # nothing left unassessed (critique round 13, FC13-5).
    slide_mixed = slide_of(built["api_ct_outage"],
                           {"email_vendor_surface": measured_evs,
                            "vendor_breach": {"status": "error", "error": "boom",
                                              "issues": []}})
    if ("could not be assessed on this scan" not in slide_mixed
            or "not an absence of checking" in slide_mixed):
        bad.append("the deck credits a scan with signals unassessed: %r"
                   % (slide_mixed[:220],))
    # ...and the other side of that pair, which nothing produced. Every
    # reference to "positive due-diligence result" in this function is a must-NOT
    # pin, and no fixture here ever rendered the sentence, because the baseline
    # carries none of the supply-chain categories and an absent one classifies as
    # UNKNOWN - so the proportionate paragraph was always the one taken and
    # rewording the claim changed nothing any assertion could see (round 15, D3).
    # A never-list cannot catch a rewording: the claim must be PRODUCED.
    _deck_clean_signal = {"status": "completed", "score": 100, "issues": [],
                          "high_count": 0, "critical_count": 0}
    _deck_all_measured = {
        "email_vendor_surface": dict(measured_evs),
        "vendor_breach": dict(measured_vb),
        "third_party_js": dict(_deck_clean_signal),
        "dependency_manifests": dict(_deck_clean_signal, exposed_manifests=[]),
        # Completed and not WordPress is "Not applicable" - a measured answer,
        # which is what lets `unknown` empty at all.
        "cms_plugin_sbom": dict(_deck_clean_signal, is_wordpress=False),
        "third_party_correlation": dict(
            _deck_clean_signal, medium_count=0, suspected_vendors=[],
            hudson_rock_third_party_count=0, spf_vendor_count=0,
            severity="none"),
        "hudson_rock": {"status": "completed", "third_party_exposures": 0,
                        "score": 100, "issues": []},
    }
    slide_pos = slide_of(built["confirmed_clean_no_candidates"],
                         _deck_all_measured)
    _vp17, _fill17 = verdict_pill()
    if not _fill17 or not _vp17 or _vp17[0][0] != "LOW EXPOSURE":
        bad.append("a fully measured clean estate lacks its correctly coloured LOW verdict")
    if ("positive due-diligence result" not in slide_pos
            or "could not be assessed on this scan" in slide_pos):
        bad.append("a fully measured supply-chain surface does not read as a "
                   "positive result: %r" % (slide_pos[:260],))
    # And one signal short of that flips it back, so the pair cannot both be
    # satisfied by a constant.
    slide_one_short = slide_of(
        built["confirmed_clean_no_candidates"],
        dict(_deck_all_measured,
             third_party_js={"status": "error", "error": "boom", "issues": []}))
    if ("positive due-diligence result" in slide_one_short
            or "could not be assessed on this scan" not in slide_one_short):
        bad.append("one unassessed signal still reads as a positive result: %r"
                   % (slide_one_short[:260],))

    # A partly assessed estate must not be NAMED among the signals this scan
    # assessed, exactly as a partly read SPF chain is not (round 11, R11-SC-3).
    # _deck_group could not see this: it returns the card's own sentence first,
    # so it reported "own: not fully assessed" and never noticed the same name
    # ALSO listed under "Assessed:", directly above that very footnote
    # (round 15, C2).
    def _deck_named_in(text_, group_, name_="Related domains"):
        for m_ in _re.finditer(
                r"(Not assessed \(no scan data\)|Not applicable|Partly assessed|"
                r"Fully assessed|Assessed):\s*([^.]*)", text_):
            if m_.group(1) == group_ and name_ in m_.group(2):
                return True
        return False

    for _lbl_c2 in ("partial_with_critical", "partial_with_high"):
        _slide_c2 = slide_of(built[_lbl_c2])
        if "on an SPF chain" in _slide_c2:
            bad.append("%s: a partial related-domain finding is falsely "
                       "described as an SPF-chain finding" % _lbl_c2)
        if "in an assessment that was incomplete" not in _slide_c2:
            bad.append("%s: the partial finding lacks its assessment "
                       "coverage qualification" % _lbl_c2)
        if _deck_named_in(_slide_c2, "Assessed"):
            bad.append("%s: a partly assessed estate is named among the signals "
                       "this scan assessed, above its own not-fully-assessed "
                       "footnote: %r" % (_lbl_c2, _slide_c2[:260]))
    _mixed_partial16 = slide_of(built["partial_with_high"], {
        "email_vendor_surface": evs_real["vendor_plus_timeout"],
        "vendor_breach": vb_real["vendor_plus_timeout"],
    })
    if ("in an assessment that was incomplete" not in _mixed_partial16
            or "signal(s) carry a finding on an SPF chain" in _mixed_partial16):
        bad.append("mixed partial domain and SPF findings are described "
                   "as though they all came from an SPF chain")
    if (pc.cat_email_vendor_surface({"email_vendor_surface": stored_evs}, S)
            or pc.cat_vendor_breach({"vendor_breach": stored_vb}, S)):
        bad.append("stored completed: the technical report draws a card")
    if not (pc.cat_email_vendor_surface({"email_vendor_surface": measured_evs}, S)
            and pc.cat_vendor_breach({"vendor_breach": measured_vb}, S)):
        bad.append("a measured result draws no card")
    # A partly read chain, and the stored result that is the same walk without
    # the record: a card, but never the clean colour, and it says why (critique
    # round 10, FC10-1, ST10-1).
    stored_vendor_evs = {k: v for k, v in evs_real["nested_answered"].items()
                         if k != "spf_lookup"}
    stored_vendor_vb = {k: v for k, v in vb_real["nested_answered"].items()
                        if k != "spf_lookup"}

    def _card_of(builder, key, payload):
        seen = {}
        real_card = pc.build_cat_card

        def spy(title, col, *a, **k):
            seen["col"] = col
            return real_card(title, col, *a, **k)
        with mock.patch.object(pc, "build_cat_card", spy):
            flow = builder({key: payload}, S)
        return seen.get("col"), _rd_flow_text(flow)
    for label_, builder_, key_, payload_ in (
            ("partial_s4", pc.cat_email_vendor_surface, "email_vendor_surface",
             evs_real["quiet_vendor_plus_timeout"]),
            ("partial_s5", pc.cat_vendor_breach, "vendor_breach",
             vb_real["quiet_vendor_plus_timeout"]),
            ("stored_with_vendor_s4", pc.cat_email_vendor_surface, "email_vendor_surface",
             stored_vendor_evs),
            ("stored_with_vendor_s5", pc.cat_vendor_breach, "vendor_breach",
             stored_vendor_vb)):
        col_, text_ = _card_of(builder_, key_, payload_)
        low_ = text_.lower()
        # Literals, not the module's own strings. Reading _SPF_PARTIAL_ROW back
        # out of pdf_cards asserts only that the card says whatever the module
        # says, so the row could be reworded to claim the chain was fully read
        # and stay green (critique round 11, GS11-3, GS11-4).
        want_ = ["partly read", "lower bound", "never read",
                 "not a complete assessment of the sending surface", "re-scan"]
        # The fallback line renders only where the card carries no issues.
        if not payload_.get("issues"):
            want_.append("part of the spf chain was not read")
        never_ = ["fully read", "every sending vendor was identified",
                  "complete sending surface", "no re-scan is needed",
                  "authorise no further senders"]
        missing_ = [w for w in want_ if w not in low_]
        said_ = [w for w in never_ if w in low_]
        if col_ is None or col_ is pc.C_GREEN or missing_ or said_:
            bad.append("the %s card is %r, omits %r and says %r"
                       % (label_, col_, missing_, said_))
    # An outcome the rule does not know draws no card either: the allow-list is
    # pinned on the cards, not only on the deck, the row and the dashboard
    # (critique round 11, GS11-1).
    # A never-list only forbids the spellings it happens to know. The row the
    # broker reads is pinned outright (critique round 12, GS12-6).
    if pc._SPF_PARTIAL_ROW != ("SPF chain", "Partly read - the vendors are a lower bound"):
        bad.append("the partly-read row reads %r" % (pc._SPF_PARTIAL_ROW,))
    unknown_evs_ = dict(measured_evs, spf_lookup="truncated")
    unknown_vb_ = dict(measured_vb, spf_lookup="truncated")
    if (pc.cat_email_vendor_surface({"email_vendor_surface": unknown_evs_}, S)
            or pc.cat_vendor_breach({"vendor_breach": unknown_vb_}, S)):
        bad.append("an outcome the rule does not know draws a technical card")

    def _sc_row(e_, v_, neighbour=None, others_measured=False):
        # The row's gap rule is total over SIGNALS now, so a case that asserts
        # Clean must supply every signal the row summarises. The errored default
        # stays, because three of these cases exist to prove that an unmeasured
        # S-4/S-5 renders NO row, which depends on nothing else having completed
        # (round 15, B1).
        _clean_ = {"status": "completed", "score": 100, "issues": [],
                   "high_count": 0, "critical_count": 0}
        r_ = with_rd(built["confirmed_clean_no_candidates"]
                     if others_measured else None)
        for k_ in ("dependency_manifests", "third_party_js", "cms_plugin_sbom",
                   "third_party_correlation", "hudson_rock"):
            r_["categories"][k_] = (dict(_clean_) if others_measured
                                    else {"status": "error"})
        if neighbour is not None:
            r_["categories"]["dependency_manifests"] = neighbour
        r_["categories"]["email_vendor_surface"] = copy.deepcopy(e_)
        r_["categories"]["vendor_breach"] = copy.deepcopy(v_)
        return _summary_sc_row(pc.build_summary_table(r_, S))
    # The row's own text, not merely the absence of "Clean": an unmeasured or
    # partly read signal renders no row of its own, a measured one reads Clean,
    # and a finding renders the row even where nothing counted as completed
    # (critique round 10, GS10-3).
    for label_, e_, v_, want_, om_ in (
            ("stored_completed", stored_evs, stored_vb, "", False),
            ("measured", measured_evs, measured_vb, "Clean", True),
            ("partial", evs_real["quiet_vendor_plus_timeout"],
             vb_real["quiet_vendor_plus_timeout"], "", False),
            ("stored_with_vendor", stored_vendor_evs, stored_vendor_vb,
             "signal(s)", False),
            ("partial_finding", evs_real["vendor_plus_timeout"],
             vb_real["vendor_plus_timeout"], "signal(s)", False)):
        row_ = _sc_row(e_, v_, others_measured=om_)
        ok_ = (row_.strip() == "") if want_ == "" else (want_ in row_)
        if not ok_:
            bad.append("summary row for %s reads %r, want %r" % (label_, row_[:140], want_))
    # A measured neighbour beside an S-4/S-5 nobody read: without one,
    # sc_any_completed is false and the row's green branch - the branch the
    # unmeasured guard protects - is never reached, which is why removing that
    # guard went uncaught (critique round 12, SC-ROW-CLEAN-OVER-UNMEASURED).
    _clean_neighbour = {"status": "completed", "score": 100, "issues": [],
                        "high_count": 0, "critical_count": 0, "exposed_manifests": []}
    # The colour as well as the words: dropping the notes flips the label to
    # "Clean", but removing the guard leaves the text alone and only turns the
    # row green, and the row carries its own colour.
    for label_, e_, v_, want_ in (
            ("unmeasured_beside_measured", stored_evs, stored_vb, "not assessed"),
            ("partly_beside_measured", evs_real["quiet_vendor_plus_timeout"],
             vb_real["quiet_vendor_plus_timeout"], "partly read"),
            # Two independent SPF walks differ routinely: one answers while the
            # other times out. With the signals in the SAME state, half the
            # guard could be deleted green (critique round 13, GS13-1).
            ("s4_measured_s5_unmeasured", measured_evs, stored_vb,
             "the vendor-breach correlation was not assessed"),
            ("s4_unmeasured_s5_measured", stored_evs, measured_vb,
             "the email-vendor surface was not assessed"),
            # The shapes a checker actually fails in, which had no case at all
            # although the guard exists for them (FC13-1).
            ("errored_beside_measured",
             {"status": "error", "error": "boom", "issues": []},
             {"status": "error", "error": "boom", "issues": []}, "not assessed"),
            ("timed_out_beside_measured",
             {"status": "timeout", "error": "Checker timed out after 180s", "issues": []},
             {"status": "timeout", "error": "Checker timed out after 180s", "issues": []},
             "not assessed")):
        # Every OTHER signal measured, so the gap names exactly the S-4/S-5
        # under test. Left errored, the row named three signals at once and
        # these cases stopped isolating the pair they exist for (round 15, B1).
        row_n = _sc_row(e_, v_, _clean_neighbour, others_measured=True)
        low_n = row_n.lower()
        if "clean" in low_n or "#16a34a" in low_n or want_ not in low_n:
            bad.append("the summary row for %s reads %r" % (label_, row_n[:220]))
    # An outcome this rule does not know is not a measurement (FC10-3), and a
    # six-vendor surface is a finding on every surface (GS10-4).
    future_evs = dict(measured_evs, spf_lookup="truncated")
    future_vb = dict(measured_vb, spf_lookup="truncated")
    slide_future = slide_of(built["api_ct_outage"], {"email_vendor_surface": future_evs,
                                                     "vendor_breach": future_vb})
    for name_ in ("Email service providers", "Known vendor breaches"):
        if _deck_group(slide_future, name_) != "own: not assessed":
            bad.append("an outcome the rule does not know is credited: %s filed under %r"
                       % (name_, _deck_group(slide_future, name_)))
    _wide = ("mailchimp", "sendgrid", "mailgun", "postmark", "zendesk", "intercom")
    wide_evs = {"status": "completed", "spf_lookup": "answered", "score": 95, "issues": [],
                "vendor_count": 6, "unknown_count": 0, "dmarc_policy": "reject",
                "weak_dmarc": False,
                "vendors_detected": [{"vendor": v, "includes": [v + ".example"]}
                                     for v in _wide],
                "spf_includes": [{"include": v + ".example", "depth": 0} for v in _wide]}
    if "wide fourth-party surface" not in slide_of(
            built["api_ct_outage"], {"email_vendor_surface": wide_evs,
                                     "vendor_breach": measured_vb}):
        bad.append("a six-vendor surface is not a finding on the deck")
    if bad:
        failures.append("discovery[spf_lookup]: " + "; ".join(bad))
    report(not bad, "spf_lookup_that_did_not_answer_is_not_clean")

    # The summary tier. The summary report has no related-domains card, so the
    # supply-chain row may never read a plain "Clean" beside confirmed domains
    # that were not fully assessed, or beside candidates awaiting confirmation,
    # whether or not another supply-chain category completed (the fixture has
    # none; a completed, finding-free dependency check is the neighbour).
    neighbour = {"status": "completed", "exposed_manifests": [], "total_critical_cves": 0}

    def sc_row(rd, with_neighbour=False, measured_spf=False):
        r = with_rd(rd)
        # The baseline fixture carries NO email_vendor_surface and NO
        # vendor_breach, so every case here runs with an absent vendor surface
        # unless it asks otherwise. A case that asserts "Clean" in green must
        # ask, because an absent vendor surface is not assessed and the row now
        # says so (step-5 critique round 13, FC13-1). A case that asserts the
        # related-domain wording alone must NOT ask, or "No finding on assessed
        # signals" becomes true and stops being the false claim its `never`
        # list forbids.
        if measured_spf:
            r["categories"]["email_vendor_surface"] = dict(measured_evs)
            r["categories"]["vendor_breach"] = dict(measured_vb)
            # ...and the other three, for the same reason: the gap rule is total
            # over signals now, so leaving them absent holds every case off green
            # regardless of what it asserts, and the mutations against that
            # branch go inert (round 15, B1). with_neighbour still overrides the
            # dependency manifest below.
            for _k in ("dependency_manifests", "third_party_js", "cms_plugin_sbom"):
                r["categories"][_k] = {"status": "completed", "score": 100,
                                       "issues": [], "high_count": 0,
                                       "critical_count": 0}
        if with_neighbour:
            r["categories"]["dependency_manifests"] = dict(neighbour)
        return _summary_sc_row(pc.build_summary_table(r, S))

    legacy_confirmed = next(rd for l, rd, st in RD_LEGACY if st == "confirmed")
    legacy_timeout = next(rd for l, rd, st in RD_LEGACY if rd.get("status") == "timeout")
    legacy_error = next(rd for l, rd, st in RD_LEGACY if rd.get("status") == "error")
    legacy_nothing = next(rd for l, rd, st in RD_LEGACY
                          if l == "legacy_completed_nothing_scanned")
    BLUE, GREEN, AMBER = "#1d4ed8", "#16a34a", "#d97706"
    NOFIND = "No finding on assessed signals"
    summary_cases = [
        # (label, category, with neighbour, must contain, must not contain)
        ("awaiting_alone", built["api_ct_answered"], False,
         [NOFIND, "2 related domain(s) found, awaiting confirmation", BLUE],
         ["Clean", GREEN]),
        # Discovery ran and found nothing: stated, never "Clean" (critique
        # round 6, ST6-6).
        ("none_found_alone", built["api_ct_answered_none_found"], False,
         [NOFIND, "no related domains found on certificate records", BLUE],
         ["Clean", GREEN]),
        ("none_found_with_neighbour", built["api_ct_answered_none_found"], True,
         ["no related domains found on certificate records", BLUE], ["Clean", GREEN]),
        ("finding_while_discovery_down", built["finding_while_discovery_down"], False,
         ["critical", "related-domain discovery could not run"], ["Clean"]),
        ("timeout_while_discovery_down", built["timeout_while_discovery_down"], False,
         ["confirmed related domains not assessed", "related-domain discovery could not run",
          AMBER], ["Clean"]),
        ("degraded_alone", built["api_ct_outage"], False,
         ["related-domain discovery could not run", BLUE], ["Clean", GREEN]),
        ("degraded_with_neighbour", built["api_ct_outage"], True,
         ["related-domain discovery could not run", BLUE], ["Clean", GREEN]),
        ("confirmed_while_discovery_down", built["confirmed_while_discovery_down"], False,
         ["related-domain discovery could not run", BLUE], ["Clean", GREEN]),
        ("partial_while_discovery_down", built["partial_while_discovery_down"], False,
         ["not fully assessed", "related-domain discovery could not run", AMBER], ["Clean"]),
        ("clean_with_a_candidate_alone", built["confirmed_clean"], False,
         ["1 related domain(s) found, awaiting confirmation", BLUE], ["Clean", GREEN]),
        # The only kind whose row may read "Clean" - and only where the vendor
        # surface was actually measured (FC13-1).
        ("clean_no_candidates_alone", built["confirmed_clean_no_candidates"], False,
         ["Clean", GREEN], ["not fully", "awaiting"], True),
        ("critical_alone", built["confirmed_finding"], False, ["critical"], ["Clean"]),
        ("high_alone", built["confirmed_high_only"], False, ["high"], ["Clean"]),
        ("partial_alone", built["partial_checks"], False,
         ["not fully assessed", AMBER], ["Clean"]),
        ("partial_critical_alone", built["partial_with_critical"], False,
         ["critical", "not fully assessed"], ["Clean"]),
        ("partial_high_alone", built["partial_with_high"], False, ["high"], ["Clean"]),
        ("partial_with_neighbour", built["partial_checks"], True,
         ["not fully assessed", AMBER], ["Clean"]),
        ("over_cap_with_neighbour", built["over_the_cap"], True, ["not fully assessed"], ["Clean"]),
        ("timed_out_with_neighbour", built["probe_timed_out"], True,
         ["confirmed related domains not assessed",
          "1 related domain(s) found, awaiting confirmation"], ["Clean"]),
        ("awaiting_with_neighbour", built["api_ct_answered"], True,
         ["awaiting confirmation", BLUE], ["Clean", GREEN]),
        ("clean_with_a_candidate_with_neighbour", built["confirmed_clean"], True,
         ["awaiting confirmation", BLUE], ["Clean", GREEN]),
        ("legacy_with_neighbour", legacy_confirmed, True, ["not fully assessed"], ["Clean"]),
        ("legacy_timeout_with_neighbour", legacy_timeout, True,
         ["confirmed related domains not assessed", AMBER], ["Clean"]),
        ("legacy_error_with_neighbour", legacy_error, True,
         ["confirmed related domains not assessed", AMBER], ["Clean"]),
        ("legacy_nothing_scanned_with_neighbour", legacy_nothing, True,
         ["confirmed related domains not assessed", AMBER], ["Clean"]),
        ("clean_no_candidates_with_neighbour", built["confirmed_clean_no_candidates"], True,
         ["Clean", GREEN], ["not fully", "awaiting"], True),
        # Nothing measured at all: the row must still RENDER, because discovery
        # having failed or found nothing is itself the thing to report, and it
        # must NOT claim a finding-free reading of signals nobody read. With a
        # measured surface in every case the row rendered regardless of its own
        # condition, and the no-finding branch was unreachable (round 15, D1,
        # D2, and the two mutations p120 silently made inert).
        ("degraded_alone_unmeasured", built["api_ct_outage"], False,
         ["related-domain discovery could not run", "not assessed", BLUE],
         ["Clean", GREEN, NOFIND], False),
        ("none_found_alone_unmeasured", built["api_ct_answered_none_found"], False,
         ["no related domains found on certificate records", "not assessed", BLUE],
         ["Clean", GREEN, NOFIND], False),
    ]
    bad = []
    for _case in summary_cases:
        label, rd, nb, must, never = _case[:5]
        # Measured by DEFAULT: left absent, the vendor-surface gap blocks the
        # row's green branch and every mutation against that branch is inert
        # (found by round 14's own mutation run).
        row_text = sc_row(rd, nb, measured_spf=(_case[5] if len(_case) > 5 else True))
        miss = [m for m in must if m not in row_text]
        hit = [n for n in never if n in row_text]
        if miss or hit:
            bad.append("%s reads %r (missing %r, has %r)" % (label, row_text[:120], miss, hit))
    if bad:
        failures.append("discovery[summary]: " + "; ".join(bad))
    report(not bad, "summary_row_follows_the_findings", "%d cases" % len(summary_cases))

    # EVERY signal the row summarises, one at a time. The predicate was total
    # over the SHAPES a checker fails in but ran over a list of two signals, so
    # the other four reached the green branch untested and a completed neighbour
    # carried the row to "Clean" over them (round 15, B1 and C1, found
    # independently by two critics; the same defect as
    # SC-ROW-CLEAN-OVER-UNMEASURED and FC13-1 for the third time).
    def _row_with(overrides, drop_rd=False):
        r_ = with_rd(None if drop_rd else built["confirmed_clean_no_candidates"])
        _ok = {"status": "completed", "score": 100, "issues": [],
               "high_count": 0, "critical_count": 0}
        for k_ in ("third_party_js", "dependency_manifests", "cms_plugin_sbom"):
            r_["categories"][k_] = dict(_ok)
        r_["categories"]["email_vendor_surface"] = dict(measured_evs)
        r_["categories"]["vendor_breach"] = dict(measured_vb)
        for k_, v_ in overrides.items():
            if v_ is None:
                r_["categories"].pop(k_, None)
            else:
                r_["categories"][k_] = dict(v_)
        return _summary_sc_row(pc.build_summary_table(r_, S))

    bad = []
    # The control. Without it every case below could pass because the row is
    # never green for some unrelated reason - which is how two assertions went
    # inert in round 14.
    _all_measured = _row_with({})
    if "Clean" not in _all_measured or GREEN not in _all_measured:
        bad.append("the all-measured control is not green: %r" % _all_measured[:200])
    _ERR = {"status": "error", "error": "boom", "issues": []}
    _TMO = {"status": "timeout", "error": "Checker timed out after 180s", "issues": []}
    for name_, key_, shape_ in (
            ("third-party JavaScript", "third_party_js", _ERR),
            ("third-party JavaScript", "third_party_js", _TMO),
            ("third-party JavaScript", "third_party_js", None),
            ("code dependencies", "dependency_manifests", _ERR),
            ("code dependencies", "dependency_manifests", _TMO),
            ("code dependencies", "dependency_manifests", None),
            ("website plugins", "cms_plugin_sbom", _ERR),
            ("website plugins", "cms_plugin_sbom", _TMO),
            ("website plugins", "cms_plugin_sbom", None)):
        row_ = _row_with({key_: shape_})
        if GREEN in row_ or "Clean" in row_ or name_ not in row_:
            bad.append("%s %s: %r" % (key_, "absent" if shape_ is None
                                      else shape_["status"], row_[:200]))
    # The related-domains category missing entirely: a result stored before
    # step 5, when the checker ran only if domains were confirmed. Nothing was
    # looked for, so the row may not read Clean over it.
    row_rdm = _row_with({}, drop_rd=True)
    if (GREEN in row_rdm or "Clean" in row_rdm
            or "related domains were not assessed" not in row_rdm):
        bad.append("a missing related-domains category: %r" % row_rdm[:200])
    # "skipped" counts as MEASURED: the plugin checker saying this site is not
    # WordPress. It writes the same status when every probe timed out or was
    # refused and the two cannot be told apart, which is recorded as B2 for the
    # owner. Pinned so the choice stays deliberate and visible.
    row_skip = _row_with({"cms_plugin_sbom": {"status": "skipped", "issues": []}})
    if "Clean" not in row_skip or GREEN not in row_skip:
        bad.append("a skipped plugin scan is read as unmeasured: %r" % row_skip[:200])
    if bad:
        failures.append("discovery[summary:signals]: " + "; ".join(bad))
    report(not bad, "summary_row_names_every_unmeasured_signal", "11 shapes")

    # A MEDIUM vendor join beside a clean estate: never "Clean" on the summary
    # row, as it is MEDIUM on the deck and the card (critique round 7, ST7-2).
    # Built through _row_with, so EVERY signal the row summarises is measured
    # and the green branch is REACHABLE. This block has gone inert twice for the
    # same reason - once when the vendor surface gained an unmeasured test
    # (round 14) and again when the other three signals did (round 15) - because
    # it built its own result and inherited neither fix. Using the helper means
    # the next signal to gain a test cannot make it inert a third time.
    row_m = _row_with({"third_party_correlation": {
        "status": "completed", "severity": "medium", "critical_count": 0,
        "high_count": 0, "medium_count": 1, "hudson_rock_third_party_count": 3,
        "spf_vendor_count": 0, "suspected_vendors": [], "score": 84,
        "issues": []}})
    ok = "cross-vendor MEDIUM" in row_m and "Clean" not in row_m and GREEN not in row_m
    if not ok:
        failures.append("discovery[summary:vendor_join_medium]: %r" % row_m[:160])
    report(ok, "summary_row_states_a_medium_vendor_join")

    # Names from a stored result or a certificate record are printed, never
    # parsed: markup in them neither stops the PDF nor renders as markup
    # (critique round 5, PR5-2).
    # One name per printing path, so an unescaped path cannot hide behind another.
    esc = copy.deepcopy(built["confirmed_clean"])
    esc["dependants"][0]["domain"] = "<b>sib.co.za"
    esc["dependants"].append({"domain": "<s>un.co.za", "measured": False, "lite_score": None,
                              "critical_paths": 0, "not_measured": []})
    esc["worst_domain"] = {"domain": "<em>w.co.za", "lite_score": 100}
    esc["confirmed_not_assessed"] = ["<u>na.co.za"]
    for c in esc.get("discovered") or []:
        if not c.get("attested"):
            c["domain"], c["evidence"] = "<i>cand.co.za", "a & b <x>"
            break
    bad = []
    try:
        text = _rd_flow_text(pc.cat_related_domains({"related_domains": esc}, S))
        for want in ("&lt;b&gt;sib.co.za", "&lt;s&gt;un.co.za", "&lt;u&gt;na.co.za",
                     "&lt;i&gt;cand.co.za", "a &amp; b &lt;x&gt;"):
            if want not in text:
                bad.append("%r not escaped" % want)
        for raw in ("<b>sib", "<s>un", "<em>w", "<u>na", "<i>cand", "<x>"):
            if raw in text:
                bad.append("%r printed as markup" % raw)
        pr.generate_pdf(with_rd(esc), report_type="full")
    except Exception as exc:
        bad.append("the card raised %r" % exc)
    if bad:
        failures.append("discovery[escaping]: " + "; ".join(bad))
    report(not bad, "names_are_printed_not_parsed")

    # 6. The producer: the real CT fetchers, fed canned HTTP answers.
    crt_payload = [{"name_value": "acme.co.za\nwww.acme.co.za\nmyacme.co.za\n"
                                  "acme.co.za.evil.net\nshop.clientb.co.za"}]
    cs_payload = [{"dns_names": ["acme.co.za", "acme-group.co.za", "notacme.co.za",
                                 "acme.co.za.evil.net"]}]

    def run_sub(crt_client, cs_client):
        with mock.patch.object(cn, "CRTSH", crt_client), \
             mock.patch.object(cn, "CERTSPOTTER", cs_client), \
             mock.patch.object(cn.SubdomainChecker, "_wildcard_ips", lambda self, d: set()), \
             mock.patch.object(cn.SubdomainChecker, "_resolves", lambda self, h: None), \
             mock.patch.object(cn.SubdomainChecker, "_check_cname_takeover", lambda self, s: None), \
             mock.patch.object(cn.SubdomainChecker, "CRTSH_EMPTY_RETRY_DELAY", 0):
            return cn.SubdomainChecker().check("acme.co.za")

    def build(sub):
        return ed.build_related_domains_category("acme.co.za", None, sub,
                                                 _rd_probe("clean", []))

    # A 200 whose body is not a list of entries is not an answer on either
    # source, and must not read as "none found" (critique round 5, PR5-4).
    bad = []
    class _FakeCTText:
        """A CT client whose body is raw text: an HTML error page or a truncated
        body fails to parse, as a real one does (critique round 6, GS6-2)."""

        def __init__(self, status, text):
            self.status, self.text = status, text

        def get(self, url, **kw):
            import json as _j
            resp = mock.MagicMock()
            resp.status_code = self.status
            resp.text = self.text
            resp.json = lambda: _j.loads(self.text)
            return resp

    shapes = [(_FakeCT(200, a), _FakeCT(200, b)) for a, b in (
        (None, None), ({}, {}), ({"error": "rate limited"}, {"x": 1}), (["x"], ["y"]),
        ([{"name_value": None}], [{"dns_names": None}]),
        ([{"name_value": 5}], [{"dns_names": [5]}]),
        # Entries without their names field (critique round 7, CL7-2).
        ([{}], [{}]), ([{"id": 1}], [{"id": "1", "tbs_sha256": "ab"}]),
        ([{"error": "rate limited"}], [{"error": "rate limited"}]))]
    shapes += [(_FakeCTText(200, t), _FakeCTText(200, t))
               for t in ("<html><body>502 Bad Gateway</body></html>", '[{"name_value": "x')]
    for crt_client, cs_client in shapes:
        sub_ = run_sub(crt_client, cs_client)
        rd_ = build(sub_)
        ran_ = (rd_.get("discovery") or {}).get("ran")
        if (sub_.get("ct_sources_answered") or ran_ or sub_.get("low_coverage") is not True
                or ed.related_domains_state(rd_) != "degraded"):
            bad.append("%r / %r -> answered=%r ran=%r low_coverage=%r state=%r" % (
                getattr(crt_client, "payload", getattr(crt_client, "text", "")),
                getattr(cs_client, "payload", getattr(cs_client, "text", "")),
                sub_.get("ct_sources_answered"), ran_, sub_.get("low_coverage"),
                ed.related_domains_state(rd_)))
    if bad:
        failures.append("discovery[ct_reply_shapes]: " + "; ".join(bad))
    report(not bad, "ct_non_list_reply_is_not_an_answer")

    # crt.sh answers empty, then with names: the scan retries an empty answer as
    # the pre-flight does, so both list the same domains (critique round 7,
    # IR7-3).
    class _SeqCT:
        """A CT client giving each canned body in turn (None is a 502)."""

        def __init__(self, bodies):
            self.bodies, self.calls = list(bodies), 0

        def get(self, url, **kw):
            import json as _j
            body = self.bodies[min(self.calls, len(self.bodies) - 1)]
            self.calls += 1
            resp = mock.MagicMock()
            resp.status_code = 200 if body is not None else 502
            resp.text = _j.dumps(body) if body is not None else "bad gateway"
            resp.json = lambda: _j.loads(resp.text)
            return resp

    import related_domain_discovery as _rdd_seq
    rows_ = [{"name_value": "www.acme-group.co.za\nshop.clientb.co.za"}]
    crt_seq = _SeqCT([[], rows_])
    sub_ = run_sub(crt_seq, _SeqCT([None]))
    scan_listed = {c["domain"] for c in build(sub_).get("discovered", [])}
    with mock.patch.object(_rdd_seq, "CRTSH", _SeqCT([[], rows_])), \
         mock.patch.object(_rdd_seq.socket, "gethostbyname", lambda h: "196.22.1.5"), \
         mock.patch("time.sleep", lambda s: None):
        form_listed = {c["domain"] for c in
                       (_rdd_seq.discover_related_domains("acme.co.za").get("candidates") or [])}
    ok = (crt_seq.calls == 2
          and scan_listed == form_listed == {"acme-group.co.za", "clientb.co.za"})
    if not ok:
        failures.append("discovery[ct_empty_then_names]: crt.sh calls=%d scan %r form %r"
                        % (crt_seq.calls, sorted(scan_listed), sorted(form_listed)))
    report(ok, "empty_crtsh_answer_is_retried_on_both_sides")
    # When the retry itself fails, the empty answer stands: crt.sh answered, so
    # this is "none found", not an outage.
    sub_ = run_sub(_SeqCT([[], None]), _SeqCT([None]))
    rd_ = build(sub_)
    ok = (sub_.get("ct_sources_answered") == ["crtsh"]
          and ed.related_domains_state(rd_) == "none_found")
    if not ok:
        failures.append("discovery[ct_empty_then_outage]: answered=%r state=%r"
                        % (sub_.get("ct_sources_answered"), ed.related_domains_state(rd_)))
    report(ok, "empty_crtsh_answer_stands_when_the_retry_fails")

    bad = []
    sub = run_sub(_FakeCT(200, crt_payload), _FakeCT(200, cs_payload))
    rd = build(sub)
    listed = {c["domain"] for c in rd.get("discovered", [])}
    if sub.get("subdomains") != ["www.acme.co.za"]:
        bad.append("subdomains=%r (a name merely containing the domain is not its "
                   "subdomain, on either source)" % sub.get("subdomains"))
    if (sub.get("ct_sources") != ["crtsh"]
            or sub.get("ct_sources_answered") != ["certspotter", "crtsh"]):
        bad.append("ct_sources=%r answered=%r" % (sub.get("ct_sources"),
                                                  sub.get("ct_sources_answered")))
    want_listed = {"myacme.co.za", "evil.net", "clientb.co.za", "acme-group.co.za",
                   "notacme.co.za"}
    if listed != want_listed or rd.get("status") != "completed":
        bad.append("listed=%r status=%r" % (sorted(listed), rd.get("status")))
    down = run_sub(_FakeCT(502, None), _FakeCT(502, None))
    if (down.get("ct_sources_answered") != [] or down.get("low_coverage") is not True
            or build(down).get("status") != "unassessed"):
        bad.append("both sources down -> answered=%r low=%r status=%r"
                   % (down.get("ct_sources_answered"), down.get("low_coverage"),
                      build(down).get("status")))
    empty = run_sub(_FakeCT(200, []), _FakeCT(502, None))
    if (empty.get("ct_sources_answered") != ["crtsh"] or empty.get("low_coverage")
            or ed.related_domains_state(build(empty)) != "none_found"):
        bad.append("crt.sh answered [] -> answered=%r low=%r state=%r"
                   % (empty.get("ct_sources_answered"), empty.get("low_coverage"),
                      ed.related_domains_state(build(empty))))
    apex_only = run_sub(_FakeCT(200, [{"name_value": "acme.co.za"}]),
                        _FakeCT(200, [{"dns_names": ["acme.co.za"]}]))
    if apex_only.get("low_coverage") or "unreachable" in " ".join(apex_only.get("issues") or []):
        bad.append("both sources answered with no subdomains, yet low_coverage=%r"
                   % apex_only.get("low_coverage"))
    if bad:
        failures.append("discovery[producer]: " + "; ".join(bad))
    report(not bad, "producer_ct_fetch_to_listed_candidates")

    # The cap, through check() and the builder: one organisation with 40 names
    # and 350 single-name tenants. Organisations past 300 are counted, and the
    # sister company ranks first by its TRUE name count, not the capped sample.
    big = "\n".join(["h%02d.zz-acme-group.co.za" % i for i in range(40)]
                    + ["www.tenant%03d.co.za" % i for i in range(350)])
    sub_cap = run_sub(_FakeCT(200, [{"name_value": "www.acme.co.za\n" + big}]),
                      _FakeCT(502, None))
    rd_cap = build(sub_cap)
    disc = rd_cap["discovery"]
    top = (rd_cap.get("discovered") or [{}])[0]
    ok = (sub_cap.get("ct_foreign_orgs_dropped") == 51 and disc["candidate_count"] == 351
          and disc["not_examined_count"] == 51 and top.get("domain") == "zz-acme-group.co.za"
          and top.get("name_count") == 40)
    if not ok:
        failures.append("discovery[cap]: dropped=%r candidates=%r not_examined=%r top=%r/%r"
                        % (sub_cap.get("ct_foreign_orgs_dropped"), disc["candidate_count"],
                           disc["not_examined_count"], top.get("domain"), top.get("name_count")))
    report(ok, "cap_through_check_counts_and_ranks")
    row_cap = _summary_sc_row(pc.build_summary_table(with_rd(rd_cap), S))
    ok = "351 related domain(s) found, awaiting confirmation" in row_cap
    if not ok:
        failures.append("discovery[cap_summary]: 351 candidates read %r" % row_cap[:120])
    report(ok, "summary_row_counts_every_candidate")

    # 7. The form pre-flight uses the report's reducer and rejection rules.
    bad = []
    rows_ = [{"name_value": "d1.cloudfront.net\nsni1.cloudflaressl.com\ncpanel.host-h.net\n"
                            "stjohns.school.za\nshop.clientb.co.za\n196.22.1.5\n"
                            "www.acme.co.za\nnotacme.co.za"}]
    offered = set(rdd._extract_san_apexes(rows_, "acme.co.za"))
    if offered != {"clientb.co.za", "stjohns.school.za", "notacme.co.za"}:
        bad.append("form offers %r" % sorted(offered))
    for label, primary, names, srcs, att, want, want_rej in DISCOVERY_SCENARIOS:
        form_set = set(rdd._extract_san_apexes([{"name_value": "\n".join(names)}],
                                               ed.registrable(primary) or primary))
        report_set = {c["domain"] for c in ed.discover(primary, names, srcs)["discovered"]}
        if form_set != report_set:
            bad.append("%s: form %r, report %r" % (label, sorted(form_set), sorted(report_set)))
    with mock.patch.object(rdd, "_crtsh_query", lambda d, retries=2: [
            {"name_value": "stjohns.school.za\nwww.stjohns.school.za\notherschool.school.za"}]):
        cands = {c["domain"] for c in rdd.discover_via_cert_san("stjohns.school.za")}
    if cands != {"otherschool.school.za"}:
        bad.append("pre-flight for stjohns.school.za offers %r" % sorted(cands))
    if bad:
        failures.append("discovery[preflight]: " + "; ".join(bad))
    report(not bad, "form_preflight_matches_the_report")

    # The form's pre-flight states a crt.sh outage as unavailable, never as
    # "none found", and its confidence label does not treat containment as a
    # shared brand (critique round 4, T4-9 and PR4-3).
    bad = []

    class _CrtResp:
        def __init__(self, code, body):
            self.status_code, self.text = code, body

        def json(self):
            return json.loads(self.text)

    class _Crt:
        def __init__(self, code, body):
            self.code, self.body = code, body

        def get(self, *a, **k):
            return _CrtResp(self.code, self.body)
    with mock.patch.object(rdd, "CRTSH", _Crt(502, "bad gateway")):
        down = rdd._crtsh_query("acme.co.za", retries=0)
    with mock.patch.object(rdd, "CRTSH", _Crt(200, "[]")):
        empty = rdd._crtsh_query("acme.co.za", retries=0)
    if down is not None or empty != []:
        bad.append("crt.sh down -> %r, answered empty -> %r" % (down, empty))
    for body in ("{}", "null", "<html>502</html>", '[{"name_value": "x', '["x"]',
                 '[{"name_value": null}]', '[{"name_value": 5}]', '[{"id": 1}]', '[{}]',
                 '[{"error": "rate limited"}]'):
        with mock.patch.object(rdd, "CRTSH", _Crt(200, body)):
            if rdd._crtsh_query("acme.co.za", retries=0) is not None:
                bad.append("crt.sh 200 %r read as an answer" % body[:20])
    with mock.patch.object(rdd.socket, "gethostbyname", lambda h: "196.22.1.5"):
        with mock.patch.object(rdd, "_crtsh_query", lambda d, retries=2: None):
            out_down = rdd.discover_related_domains("acme.co.za")
        with mock.patch.object(rdd, "_crtsh_query", lambda d, retries=2: []):
            out_empty = rdd.discover_related_domains("acme.co.za")
    if out_down.get("status") != "error" or out_empty.get("status") != "no_data":
        bad.append("pre-flight: outage -> %r, empty -> %r"
                   % (out_down.get("status"), out_empty.get("status")))
    conf = {a: rdd._confidence_for(a, {"cert_count": 5}, p) for a, p in (
        ("me.co.za", "acme.co.za"), ("vision.co.za", "laservision.co.za"),
        ("azure.co.za", "azurecapital.co.za"), ("acme-group.co.za", "acme.co.za"),
        ("jones-attorneys.co.za", "smith-attorneys.co.za"),
        ("xyz-holdings.co.za", "abc-holdings.co.za"), ("my-bank.co.za", "my-acme.co.za"),
        ("1234-ltd.co.za", "1234.co.za"), ("group-one.co.za", "group-two.co.za"))}
    one_cert = rdd._extract_san_apexes(
        [{"name_value": "www.clientx.co.za\nmail.clientx.co.za\ncpanel.clientx.co.za\n"
                        "clientx.co.za\nwebmail.clientx.co.za"}], "acme.co.za")
    if one_cert.get("clientx.co.za", {}).get("cert_count") != 1:
        bad.append("one certificate counted as %r" % one_cert.get("clientx.co.za"))
    if conf["acme-group.co.za"] != "high" or any(
            v == "high" for k, v in conf.items() if k != "acme-group.co.za"):
        bad.append("confidence labels %r" % conf)
    with io.open(os.path.join(SEC, "templates", "index.html"), encoding="utf-8") as fh:
        page_ = fh.read().replace("\r\n", "\n")

    def _node_file(src):
        """Run a script under node from a UTF-8 file: the page's code carries
        characters a Windows command line may not. None when node is absent."""
        import tempfile as _tf_node
        node_ = shutil.which("node")
        if not node_:
            return None
        fd_, p_ = _tf_node.mkstemp(suffix=".js")
        os.close(fd_)
        with io.open(p_, "w", encoding="utf-8") as fh_:
            fh_.write(src)
        try:
            return subprocess.run([node_, p_], capture_output=True, text=True,
                                  encoding="utf-8", timeout=60)
        finally:
            os.remove(p_)
    if ("normal for well-isolated" in page_
            or "show that the client has no other domains" not in page_):
        bad.append("the form's empty-result text is not the report's caveat")
    # One cleaner, everywhere the form reads the domain box: the pre-flight and
    # the submit handler had a cruder one, so a value sent with Enter reached
    # the server cut at the first "/" (critique round 9, IR9-5).
    if _re.search(r"\.trim\(\)\s*\.toLowerCase\(\)", page_):
        bad.append("the form still carries a cleaner of its own")
    if page_.count("normalizeDomainInput(document.getElementById('domain').value)") != 2:
        bad.append("the pre-flight and the submit handler do not both use the server's cleaner")
    # The preview searches crt.sh alone, and says the report can list more
    # (critique round 8, ST8-4).
    if ("No related domains were found in the crt.sh certificate search" not in page_
            or "so its report can list domains this preview did not" not in page_):
        bad.append("the form's empty result does not name its one source")
    # The form never pre-ticks a candidate, renders an outage as unavailable,
    # and its banner says so (critique round 5, G5-01, G5-08, T5-5).
    m_rc = _re.search(r"function renderRelatedCandidates\(rc\) \{.*?\n\}\n", page_, _re.S)
    rc_body = m_rc.group(0) if m_rc else ""
    if not rc_body:
        bad.append("renderRelatedCandidates not found")
    else:
        # Any way of ticking a box anywhere in the page's scripts, other than
        # the page's own business flags; un-ticking is always allowed. A box
        # ticked outside the renderer, in runPreflight say, would reach the
        # scan as broker-confirmed (critique rounds 6 and 8, GS6-3, GS8-5).
        scripts_ = "\n".join(_re.findall(r"<script[^>]*>(.*?)</script>", page_, _re.S))
        tick = _re.compile(r"\.checked\s*(?:\|\||&&|\?\?|\*\*|<<|>>>?|[-+*/%&|^])?=(?!=)"
                           r"|\[\s*['\"]checked['\"]\s*\]\s*(?:\|\||&&|\?\?)?=(?!=)"
                           r"|defaultChecked|setAttribute\(\s*['\"]checked"
                           r"|toggleAttribute\(\s*['\"]checked|Reflect\.set\([^)]*checked"
                           r"|\.click\(\s*\)|dispatchEvent\(\s*new\s+\w*Event\(\s*['\"]"
                           r"(?:click|change)|['\"]?\bchecked['\"]?\s*:"
                           r"|<input[^>]*\bchecked\b")
        flag_ = _re.compile(r"document\.getElementById\('(?:listed|ai|b2c|gdpr|pci)-check'\)"
                            r"\.checked = true;")
        ticks = []
        for l in scripts_.splitlines():
            s_ = l.strip()
            if not tick.search(s_) or flag_.fullmatch(s_):
                continue
            if not tick.search(_re.sub(r"\.checked\s*=\s*false\b", "", s_)):
                continue
            ticks.append(s_[:60])
        if "function renderRelatedCandidates" not in scripts_:
            ticks.append("the page's scripts were not found")
        if ticks:
            bad.append("the form ticks candidates: %r" % ticks[:2])
        # And run it: render two candidates into a stub DOM, then collect. No
        # box is ticked, and only what the broker typed is sent (critique round
        # 7, GS7-5).
        m_col = _re.search(r"function collectRelatedDomains\(\) \{.*?\n\}\n", page_, _re.S)
        m_pre = _re.search(r"async function runPreflight\(\) \{.*?\n\}\n", page_, _re.S)
        m_k1 = _re.search(r"function normalizeDomainOnce\(raw\) \{.*?\n\}\n", page_, _re.S)
        m_k2 = _re.search(r"function normalizeDomainInput\(raw\) \{.*?\n\}\n", page_, _re.S)
        # The pre-flight itself, in a stub DOM: it ticks no box anywhere (a
        # candidate ticked outside the renderer would be sent as
        # broker-confirmed), it asks about the domain the server would scan, and
        # the box keeps every entry the API keeps (critique rounds 7 and 9,
        # GS7-5, GS9-6, IR9-4, IR9-5).
        import domain_validation as _dv_form
        tokens_ = ["<https://supplier.co.za/>", '"https://supplier2.co.za"',
                   "mailto://accounts@supplier3.co.za", "https://http://supplier4.co.za",
                   "//supplier5.co.za", "ftp://supplier6.co.za", "<info@supplier7.co.za>",
                   "Supplier8.CO.ZA.", "https://supplier9.co.za/contact?to=<jane@gmail.com>"]
        # More than ten, so a cap written into the browser shows here (critique
        # round 10, GS10-1).
        tokens_ += ["supplier1%d.co.za" % i for i in range(5)]
        # A contact address beside a host on one line. The API cleans the entry
        # whole and keeps the host, so the form must not also send the
        # contact's domain into the client's scope (round 10, IR10-3).
        tokens_.append("acme.co.za <info@brokerfirm.co.za>")
        # URL userinfo is not a contact address: both doors keep the URL's host
        # AND the plain host beside it (critique round 12, IH12-5).
        tokens_.append("https://ops@group-holdings.com/portal "
                       "supplier-userinfo.co.za")
        # A scheme must not hide a contact, and a wildcard entry is cleaned
        # rather than dropped: each was asserted on the API door only, so a
        # form-only change survived (round 13, IH13-1, IH13-2, R13-IN-2).
        # A domain no other token supplies, so DROPPING the rule each of these
        # tests is observable and not merely the leak direction (round 15, D4;
        # the defect p121 fixed for the wildcard token, and IH13-4 before that).
        tokens_.append("supplier-mailto.co.za mailto://jane@brokerfirm.co.za")
        tokens_.append("supplier-protorel.co.za //accounts@brokerfirm.co.za")
        # A domain that appears on no other token, so dropping the wildcard
        # line is observable: acme.co.za is supplied by another entry and
        # would mask it (round 13, IH13-4, reproduced in round 14).
        tokens_.append("*.wildcard-sib.co.za")
        # The form's fallback must clean the WHOLE entry, as the server's
        # _keep(s) does. Cleaning each token separately never reaches the
        # display-name rule, so an unreadable host beside a contact collected
        # the BROKER's own domain, which the server then accepted when it
        # re-cleaned the list (round 15, A1).
        tokens_.append("a1-unreadable.co.za1 <accounts@a1-leak.co.za>")
        # Python's \s also matches U+001C to U+001F and U+0085, so the server
        # split this entry and the form did not, and the form sent the
        # contact's domain where the server kept the host (round 15, A3).
        tokens_.append("a3-probe.co.za\u0085accounts@a3-leak.co.za")
        # Every layer that was pasted, stripped in one go on BOTH doors: one
        # layer per pass left the form rejecting what the server keeps
        # (round 15, A2).
        tokens_.append("*..a2-deep-sib.co.za")
        js_d = (r"""
const made = [];
function el(tag) {
  const e = { tagName: tag, style: {}, dataset: {}, attrs: {}, children: [], value: '',
    classList: { add() {}, remove() {} },
    appendChild(c) { this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = v; } };
  made.push(e);
  return e;
}
const byId = { 'related-candidates-list': el('div'), 'related-candidates-checkboxes': el('div'),
  'related-domains-badge': el('span'),
  'related-domains': { value: """ + json.dumps("\n".join(tokens_)) + r""" },
  'domain': { value: 'Accounts/Finance <accounts@acme.co.za>' },
  'sub-industry': { value: '' } };
globalThis.document = {
  getElementById: (id) => byId[id] || (byId[id] = el('stub')),
  createElement: (t) => el(t),
  querySelectorAll: (sel) => made.filter((e) => e.tagName === 'input'
    && (!sel.includes(':checked') || e.checked || e.defaultChecked || 'checked' in e.attrs)),
};
let preflightInFlight = false;
let preflightResult = null;
function setRelatedCandidatesLoading() {}
function setBadge() {}
function apiHeaders(h) { return h || {}; }
const asked = [];
globalThis.fetch = async (url, opt) => {
  asked.push(JSON.parse((opt || {}).body || '{}'));
  return { ok: true, json: async () => ({ status: 'ok', flags: {}, related_candidates: {
    status: 'ok', candidates: [{ domain: 'a.co.za', confidence: 'high', signal_detail: 'x' },
                               { domain: 'b.co.za', confidence: 'medium', signal_detail: 'y' }] } }) };
};
""" + (m_k1.group(0) if m_k1 else "") + (m_k2.group(0) if m_k2 else "")
                + rc_body + (m_col.group(0) if m_col else "")
                + (m_pre.group(0) if m_pre else "") + r"""
(async () => {
  await runPreflight();
  const boxes = made.filter((e) => e.tagName === 'input');
  const ticked = boxes.filter((e) => e.checked || e.defaultChecked || 'checked' in e.attrs);
  const collected0 = collectRelatedDomains();
  byId['related-domains'].value = 'supplier.co.za jane@brokerfirm.co.za';
  const contact0 = collectRelatedDomains();
  byId['related-domains'].value = 'Acme Group Holdings <info@acmegroup.co.za>';
  const named0 = collectRelatedDomains();
  byId['related-domains'].value = 'acme-group.co.za acmeholdings.co.za';
  const twohosts0 = collectRelatedDomains();
  byId['related-domains'].value = 'Acme Group Holdings, 01.03.2026, ops@acme.co.za';
  const dated0 = collectRelatedDomains();
  byId['related-domains'].value = ('a'.repeat(60) + '.').repeat(5) + 'co.za';
  const toolong0 = collectRelatedDomains();
  console.log(JSON.stringify({ boxes: boxes.length, ticked: ticked.length,
    collected: collected0, contact: contact0, named: named0,
    twohosts: twohosts0, dated: dated0, toolong: toolong0,
    asked: asked.map((a) => a.domain) }));
})();
""")
        r_d = _node_file(js_d) if (m_col and m_pre and m_k1 and m_k2) else None
        try:
            dom = json.loads(r_d.stdout.strip().splitlines()[-1])
        except Exception:
            dom = {}
        # A contact on the line is a contact whether or not it wears brackets,
        # and a line whose host is a company name must still send the domain it
        # names: qualifying a host by truthiness dropped the whole line
        # (critique round 11, IR11-3, IR11-1).
        if sorted(dom.get("contact") or []) != ["supplier.co.za"]:
            bad.append("the box sends a bare contact address: %r"
                       % (dom.get("contact"),))
        if sorted(dom.get("named") or []) != ["acmegroup.co.za"]:
            bad.append("the box drops a line whose host is a company name: %r"
                       % (dom.get("named"),))
        # Every host on the line, not just the first (critique round 12,
        # GS12-4), and a token that merely contains a dot is not a host, or it
        # captures the branch and drops the broker's domain (IH12-1).
        if sorted(dom.get("twohosts") or []) != ["acme-group.co.za", "acmeholdings.co.za"]:
            bad.append("the box keeps only some hosts on a line: %r"
                       % (dom.get("twohosts"),))
        if sorted(dom.get("dated") or []) != ["acme.co.za"]:
            bad.append("a dotted non-domain token captured the host branch: %r"
                       % (dom.get("dated"),))
        # Parity cannot see this one: an over-long value is dropped by the API
        # on BOTH sides of that comparison, so what the form SENDS is asserted
        # outright (round 13, IH13-5). Sixty-character labels, because a single
        # long label is rejected on label length and the cap would never be
        # what did the work.
        if (dom.get("toolong") or []) != []:
            bad.append("the box sends a value the API discards for length: %r"
                       % (dom.get("toolong"),))
        want_col = sorted(_dv_form.clean_related_domains(tokens_))
        got_col = sorted(_dv_form.clean_related_domains(dom.get("collected") or []))
        if (dom.get("boxes") != 2 or dom.get("ticked") != 0 or got_col != want_col
                or dom.get("asked") != ["acme.co.za"]):
            bad.append("the form as rendered: %r (the API keeps %r) %s"
                       % (dom, want_col,
                          (r_d.stderr.strip()[-200:] if r_d else "no node, or no code")))
    if ("} else if (status === 'no_data') {" not in rc_body
            or "Auto-discovery temporarily unavailable" not in rc_body.rsplit("} else {", 1)[-1]):
        bad.append("an outage is not rendered as unavailable")
    # The banner itself, run under node for each pre-flight outcome: an outage
    # says so, and an answer does not (critique round 6, GS6-3).
    m_b = _re.search(r"(const candFragment = .*?\+ \(rdDown \? ' Related-domain "
                     r"auto-discovery was unavailable\.' : ''\);)", page_, _re.S)
    node_b = shutil.which("node")
    if not (m_b and node_b):
        bad.append("the pre-flight banner code, or node, was not found")
    else:
        # With and without flags detected, and with candidates found
        # (critique round 7, GS7-5).
        js = ("const out = {};\n"
              "const cases = {error: {status: 'error'}, skipped: {status: 'skipped'},"
              " missing: undefined, ok: {status: 'ok', candidates: [{}, {}, {}]},"
              " no_data: {status: 'no_data'}};\n"
              "for (const [k, rc] of Object.entries(cases)) for (const dc of [0, 2]) {\n"
              "  const d = {related_candidates: rc}; const domain = 'acme.co.za';\n"
              "  const detectedCount = dc; const banner = {};\n"
              "  const candCount = (rc && rc.candidates) ? rc.candidates.length : 0;\n"
              + m_b.group(1) + "\n  out[k + ':' + dc] = banner.textContent;\n}\n"
              "console.log(JSON.stringify(out));\n")
        r_b = subprocess.run([node_b, "-e", js], capture_output=True, text=True, timeout=60)
        try:
            said = json.loads(r_b.stdout.strip().splitlines()[-1])
        except Exception:
            said = {}
        wrong = [k for k in ("%s:%d" % (s_, dc_) for s_ in ("error", "skipped", "missing",
                                                             "ok", "no_data")
                             for dc_ in (0, 2))
                 if k not in said
                 or ("unavailable" in said[k]) != (k.split(":")[0] in ("error", "skipped",
                                                                      "missing"))]
        if wrong:
            bad.append("the banner is wrong for %r: %r"
                       % (wrong, {k: said.get(k) for k in wrong} or r_b.stderr[-120:]))
    # The form's cleaner shows the target the server scans: the same steps in
    # the same order to the same fixed point (critique round 7, IR7-1, IR7-5).
    import domain_validation as _dv_js
    m_n1 = _re.search(r"function normalizeDomainOnce\(raw\) \{.*?\n\}\n", page_, _re.S)
    m_n2 = _re.search(r"function normalizeDomainInput\(raw\) \{.*?\n\}\n", page_, _re.S)
    raws = ['"acme.co.za".', "'acme.co.za'.", "<acme.co.za>.", ">acme.co.za<",
            "https://www.acme.co.za/contact?email=jane@gmail.com",
            "acme.co.za/?utm_source=x&to=info@mimecast.com",
            "https://www.acme.co.za/#/team/jane@acme-group.com", "info@acme.co.za",
            "mailto:info@acme.co.za?subject=x", "user:pw@host.co.za:8443/x",
            "ACME.CO.ZA.", "  acme.co.za  ", "acme.co.za:443", "acme.co.za​",
            "﻿acme.co.za", "x" + '".' * 50]
    # Display-name addresses, chained schemes and Python's whitespace set,
    # which both sides clean to the address's domain (critique round 8, IR8-3
    # and IR8-4).
    addr_raws = ["Accounts/Finance <accounts@acme.co.za>",
                 '"Sales / Marketing" <sales@acme.co.za>', "HR/Payroll <payroll@acme.co.za>",
                 "Accounts #2 <accounts2@acme.co.za>",
                 '"Claims (Ref #4471)" <claims@acme.co.za>', "Jane Doe <jane@acme.co.za>",
                 "mailto://jane@acme.co.za", "mailto:https://acme.co.za",
                 "https://http://acme.co.za", "http://https://acme.co.za/x",
                 "//https://acme.co.za", "\x1cacme.co.za\x85", "\x1f acme.co.za \x1c",
                 "\x1dacme.co.za", "\x1eacme.co.za", "ftp://acme.co.za"]
    # A URL that carries an address in its path, query or fragment: the host is
    # the target, as round 7 settled (critique round 9, IR9-3, FC9-4).
    url_raws = ["https://acme.co.za/contact?to=<jane@gmail.com>",
                "acme.co.za/#<ops@gmail.com>",
                "www.acme.co.za/contact <info@brokerfirm.co.za>",
                "https://www.acme.co.za/ (broker: Jane <jane@brokerfirm.co.za>)",
                "acme.co.za <info@brokerfirm.co.za>",
                "https://acme.co.za\\@attacker.com"]
    # A host ends where host characters end: a trailing dot or comma must not
    # hand the scan to the contact (critique round 11, IR11-2). Both still clean
    # to acme.co.za, so they belong in the list above.
    url_raws += ["acme.co.za. <info@brokerfirm.co.za>",
                 "acme.co.za, attn Jane <jane@brokerfirm.co.za>"]
    # These clean to a host of their own, so the fixed pair url_raws asserts is
    # not about them. They are still compared door to door below, and each has
    # its expected host stated outright (GS11-2, IR11-1).
    host_raws = ["acme-group.co.za <info@brokerfirm.co.za>",
                 "first-national.co.za, attn Jane <jane@brokerfirm.co.za>",
                 "acme.co.za1 <accounts@brokerfirm.co.za>",
                 "foo.ſom1 <user@broker.co.za>",
                 "foo.Kom1 <user@broker.co.za>",
                 "foſ.com1 <user@broker.co.za>",
                 "foo.comſ <user@broker.co.za>",
                 "foİ.com1 <user@broker.co.za>",
                 "foo.comİ <user@broker.co.za>",
                 "foı.com1 <user@broker.co.za>",
                 "foo.comı <user@broker.co.za>",
                 "acme.africa <info@brokerfirm.co.za>",
                 "acme.insurance <accounts@brokerfirm.co.za>",
                 "acme.capetown <ops@brokerfirm.co.za>",
                 "Acme Group Holdings <info@acmegroup.co.za>",
                 # A dotted first token that is NOT a host: the near-miss guard
                 # must not eat it (round 15, E1).
                 "01.03.2026 <jane@supplier.co.za>",
                 "196.22.1.5 <jane@supplier.co.za>",
                 "v2.1 <jane@supplier.co.za>",
                 "A.B. Electrical <accounts@abelectrical.co.za>"]
    # Parity between the two doors would survive a rule narrowed identically on
    # both sides, so the host each value must clean to is stated (critique round
    # 11, GS11-2, IR11-1, IR11-2).
    import domain_validation as _dv_host
    for raw_, want_host_ in (
            ("acme.africa <info@brokerfirm.co.za>", "acme.africa"),
            ("acme.insurance <accounts@brokerfirm.co.za>", "acme.insurance"),
            ("acme.capetown <ops@brokerfirm.co.za>", "acme.capetown"),
            ("acme.co.za. <info@brokerfirm.co.za>", "acme.co.za"),
            ("acme.co.za, attn Jane <jane@brokerfirm.co.za>", "acme.co.za"),
            ("Acme Group Holdings <info@acmegroup.co.za>", "acmegroup.co.za"),
            # A hyphen is a host character: narrowing the label class on both
            # doors kept parity and handed the scan to the contact (GS12-2).
            ("acme-group.co.za <info@brokerfirm.co.za>", "acme-group.co.za"),
            ("first-national.co.za, attn Jane <jane@brokerfirm.co.za>",
             "first-national.co.za"),
            # A label after the host must not be dropped by backtracking to a
            # shorter one: this falls through to the address (IH12-2).
            # Host-shaped but unreadable fails closed rather than becoming
            # the contact's domain, and the contact differs from every expected
            # host so no case here can pass by accident (round 13, IH13-3,
            # IH13-4).
            ("acme.co.za1 <accounts@brokerfirm.co.za>", ""),
            # Unicode letters accepted by Python re.I must be host-shaped in
            # the browser too; malformed near-misses fail closed, never to the
            # contact domain. These entries kill an ASCII-only JS guard.
            ("foo.ſom1 <user@broker.co.za>", ""),
            ("foo.Kom1 <user@broker.co.za>", ""),
            ("foſ.com1 <user@broker.co.za>", ""),
            ("foo.comſ <user@broker.co.za>", "foo.comſ"),
            ("foİ.com1 <user@broker.co.za>", ""),
            ("foo.comİ <user@broker.co.za>", "foo.comi̇"),
            ("foı.com1 <user@broker.co.za>", ""),
            ("foo.comı <user@broker.co.za>", "foo.comı"),
            # ...and the near-miss guard is the HOST rule minus its two
            # lookaheads, so it catches only a host it refused to read. Written
            # as its own looser pattern it matched every dotted first token and
            # dropped the broker's confirmed domain with nothing said on any
            # surface, undoing IH12-1 through a green gate (round 15, E1).
            ("01.03.2026 <jane@supplier.co.za>", "supplier.co.za"),
            ("196.22.1.5 <jane@supplier.co.za>", "supplier.co.za"),
            ("v2.1 <jane@supplier.co.za>", "supplier.co.za"),
            ("R1.5m <accounts@supplier.co.za>", "supplier.co.za"),
            ("s.a <jane@supplier.co.za>", "supplier.co.za"),
            ("No.1 Logistics <ops@no1log.co.za>", "no1log.co.za"),
            ("A.B. Electrical <accounts@abelectrical.co.za>",
             "abelectrical.co.za")):
        got_host_ = _dv_host.normalize_domain(raw_)
        if got_host_ != want_host_:
            bad.append("the cleaner reads %r as %r, want %r"
                       % (raw_, got_host_, want_host_))
    raws = raws + addr_raws + url_raws + host_raws
    r_n = (_node_file(m_n1.group(0) + m_n2.group(0)
                      + "console.log(JSON.stringify(%s.map(normalizeDomainInput)));\n"
                      % json.dumps(raws)) if (m_n1 and m_n2) else None)
    try:
        js_out = json.loads(r_n.stdout.strip().splitlines()[-1])
    except Exception:
        js_out = None
    py_out = [_dv_js.normalize_domain(x) for x in raws]
    off_ = [x for x in addr_raws if _dv_js.normalize_domain(x) != "acme.co.za"]
    off_ += [x for x in url_raws
             if _dv_js.normalize_domain(x) not in ("acme.co.za", "www.acme.co.za")]
    if off_:
        bad.append("not cleaned to the host, or the address's domain: %r" % off_[:3])
    if js_out != py_out:
        bad.append("the form's cleaner differs from the server's: %r" % (
            [(x, j_, p_) for x, j_, p_ in zip(raws, js_out or [], py_out) if j_ != p_][:3]
            or (r_n.stderr[-160:] if r_n else "no node, or no cleaner")))
    # The API keeps the value it validated (critique round 5, PR5-1).
    import domain_validation as _dv
    got_rd = _dv.clean_related_domains(["Sib.co.za.", "*.group.co.za", "info@sib2.co.za",
                                        "<b>@sib3.co.za", "https://sib4.co.za:8443/x?y=1",
                                        "sib5.co.za\u200b", "not a domain", "196.22.1.5",
                                        "Sib.co.za", '"sib6.co.za".', "'sib7.co.za'.",
                                        'https://"sib8.co.za"', "*.*.sib9.co.za",
                                        "https://sib10.co.za/contact?email=jane@gmail.com",
                                        "https://sib11.co.za/#/team/x@other.co.za",
                                        "*." * 3000 + "sib12.co.za"])
    # More than ten are kept: the scan, not the API, applies the cap and lists
    # the rest (critique round 7, GS7-1); an address in a URL's query or
    # fragment is not the host (IR7-1).
    if got_rd != ["sib.co.za", "group.co.za", "sib2.co.za", "sib3.co.za", "sib4.co.za",
                  "sib5.co.za", "sib6.co.za", "sib7.co.za", "sib8.co.za", "sib9.co.za",
                  "sib10.co.za", "sib11.co.za", "sib12.co.za"]:
        bad.append("the API keeps %r" % got_rd)
    # A contact beside a host, on ONE entry, through the API door: the rule the
    # form applies must apply here too, or the same pasted text scopes in the
    # broker's own domain depending on which door it arrives through (critique
    # round 12, GS12-3). Every entry here is one string, as a client posts it.
    for entry_, want_rd_ in (
            ("supplier.co.za jane@brokerfirm.co.za", ["supplier.co.za"]),
            ("acme.co.za <info@brokerfirm.co.za>", ["acme.co.za"]),
            ("acme-group.co.za acmeholdings.co.za",
             ["acme-group.co.za", "acmeholdings.co.za"]),
            # A dotted non-domain token is not a host, and a display-name entry
            # still falls through to whole-entry cleaning (IH12-1).
            ("Acme Group Holdings, 01.03.2026, ops@acme.co.za", ["acme.co.za"]),
            ("Accounts/Finance <accounts@acme.co.za>", ["acme.co.za"]),
            # URL userinfo is not a contact; a scheme does not hide one; and a
            # wildcard entry is cleaned rather than dropped (round 13, IH13-2,
            # R13-IN-2, IH13-1). Stated per door, because parity alone is lost
            # when both doors change together (GS13-4).
            ("https://ops@group-holdings.com/portal supplier.co.za",
             ["group-holdings.com", "supplier.co.za"]),
            ("supplier.co.za mailto://jane@brokerfirm.co.za", ["supplier.co.za"]),
            ("supplier.co.za //accounts@brokerfirm.co.za", ["supplier.co.za"]),
            ("*.acme.co.za", ["acme.co.za"])):
        got_e_ = _dv.clean_related_domains([entry_])
        if got_e_ != want_rd_:
            bad.append("the API reads %r as %r, want %r"
                       % (entry_, got_e_, want_rd_))
    for raw_, want_ in (("https://www.acme.co.za/contact?email=jane@gmail.com", "www.acme.co.za"),
                        ("acme.co.za/?utm_source=x&to=info@mimecast.com", "acme.co.za"),
                        ("mailto:info@acme.co.za?subject=x", "acme.co.za"),
                        ("user:pw@host.co.za:8443/x", "host.co.za"),
                        ('"supplier.co.za".', "supplier.co.za")):
        if _dv.normalize_domain(raw_) != want_:
            bad.append("normalize_domain(%r) = %r" % (raw_, _dv.normalize_domain(raw_)))
    # Normalising stays linear on a hostile value (critique round 7, IR7-2).
    import time as _time_n
    t_n = _time_n.time()
    _dv.normalize_domain("x" + '".' * 64000)
    _dv.clean_related_domains(["*." * 32768 + "acme.co.za"] * 3)
    if _time_n.time() - t_n > 2.0:
        bad.append("normalising long pasted values took %.1f s" % (_time_n.time() - t_n))
    # The value kept is its own normalisation (critique round 6, IR6-1).
    unstable = [v for v in got_rd if _dv.normalize_domain(v) != v]
    if unstable:
        bad.append("kept values that normalise further: %r" % unstable)
    # The scan route enqueues the domain and related domains it normalised and
    # validated, each assigned once (critique round 6, GS6-3 and IR6-3).
    import ast as _ast
    with io.open(os.path.join(SEC, "app.py"), encoding="utf-8") as fh:
        app_tree = _ast.parse(fh.read())
    fn_ = next((n for n in _ast.walk(app_tree)
                if isinstance(n, _ast.FunctionDef) and n.name == "start_scan"), None)
    if fn_ is None:
        bad.append("app.py has no start_scan")
    else:
        binds = {}
        for n in _ast.walk(fn_):
            if isinstance(n, _ast.Assign):
                for t in n.targets:
                    if isinstance(t, _ast.Name):
                        binds.setdefault(t.id, []).append(n.value)
        def _of_data(call, key):
            # The argument is data.get("<key>", ...) itself: nothing trimmed or
            # sliced on the way in (critique round 7, GS7-1).
            a = call.args[0] if call.args else None
            return (isinstance(a, _ast.Call) and isinstance(a.func, _ast.Attribute)
                    and a.func.attr == "get" and isinstance(a.func.value, _ast.Name)
                    and a.func.value.id == "data" and bool(a.args)
                    and isinstance(a.args[0], _ast.Constant) and a.args[0].value == key)
        for name, func in (("domain", "normalize_domain"),
                           ("related_domains", "clean_related_domains")):
            vals = binds.get(name, [])
            if not (len(vals) == 1 and isinstance(vals[0], _ast.Call)
                    and getattr(vals[0].func, "id", None) == func
                    and _of_data(vals[0], name)):
                bad.append("start_scan: %s is not assigned once from %s(data.get(%r, ...))"
                           % (name, func, name))
        payloads = [n for n in _ast.walk(fn_) if isinstance(n, _ast.Dict)
                    and any(isinstance(k, _ast.Constant) and k.value == "related_domains"
                            for k in n.keys)]
        if not payloads or not all(
                isinstance(v, _ast.Name) and v.id == k.value
                for d_ in payloads for k, v in zip(d_.keys, d_.values)
                if isinstance(k, _ast.Constant) and k.value in ("domain", "related_domains")):
            bad.append("start_scan does not enqueue the normalised domain and related domains")
    if bad:
        failures.append("discovery[preflight_outage]: " + "; ".join(bad))
    report(not bad, "form_preflight_states_an_outage")

    # The related domains the route validated reach scan()'s builder as they
    # are: nothing in start_scan, _run_scan_job, run_scan or scan() rebinds,
    # slices, deletes from or otherwise changes the list, and run_scan passes
    # it on verbatim. A cap anywhere in that chain would drop confirmed domains
    # unreported and read the estate fully assessed (critique round 8, GS8-1).
    mut_ = {"append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse",
            "__delitem__", "__setitem__", "__iadd__"}

    def _roots(t):
        if isinstance(t, (_ast.Tuple, _ast.List)):
            for e in t.elts:
                yield from _roots(e)
        elif isinstance(t, _ast.Starred):
            yield from _roots(t.value)
        else:
            while isinstance(t, (_ast.Subscript, _ast.Attribute)):
                t = t.value
            yield t

    def _changes(fn, nm):
        out = []
        for n in _ast.walk(fn):
            tg = []
            if isinstance(n, (_ast.Assign, _ast.Delete)):
                tg = n.targets
            elif isinstance(n, (_ast.AugAssign, _ast.AnnAssign, _ast.NamedExpr,
                                _ast.For, _ast.AsyncFor, _ast.comprehension)):
                tg = [n.target]
            elif isinstance(n, (_ast.With, _ast.AsyncWith)):
                tg = [i.optional_vars for i in n.items if i.optional_vars is not None]
            if any(isinstance(r, _ast.Name) and r.id == nm for t in tg for r in _roots(t)):
                out.append(n)
            if (isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
                    and n.func.attr in mut_ and isinstance(n.func.value, _ast.Name)
                    and n.func.value.id == nm):
                out.append(n)
        return out
    bad = []
    fns_ = {n.name: n for n in _ast.walk(app_tree) if isinstance(n, _ast.FunctionDef)
            and n.name in ("start_scan", "_run_scan_job", "run_scan")}
    with io.open(os.path.join(SEC, "scanner.py"), encoding="utf-8") as fh:
        sc_tree_ = _ast.parse(fh.read())
    scan_fns_ = [n for n in _ast.walk(sc_tree_) if isinstance(n, _ast.FunctionDef)
                 and n.name == "scan"
                 and "related_domains" in [a.arg for a in n.args.args + n.args.kwonlyargs]]
    bad += ["app.py has no %s" % f_ for f_ in ("start_scan", "_run_scan_job", "run_scan")
            if f_ not in fns_]
    if len(scan_fns_) != 1:
        bad.append("scanner.py has %d scan() taking related_domains" % len(scan_fns_))
    if not bad:
        ch_ = _changes(fns_["start_scan"], "related_domains")
        if len(ch_) != 1 or not isinstance(ch_[0], _ast.Assign):
            bad.append("start_scan changes related_domains %d time(s)" % len(ch_))
        job_ = fns_["_run_scan_job"]
        body_ = [s for s in job_.body
                 if not (isinstance(s, _ast.Expr) and isinstance(s.value, _ast.Constant))]
        call_ = body_[0].value if (len(body_) == 1 and isinstance(body_[0], _ast.Expr)) else None
        if not (isinstance(call_, _ast.Call) and getattr(call_.func, "id", "") == "run_scan"
                and not call_.args and len(call_.keywords) == 1
                and call_.keywords[0].arg is None and job_.args.args
                and getattr(call_.keywords[0].value, "id", "") == job_.args.args[0].arg):
            bad.append("_run_scan_job does more than run_scan(**payload)")
        if _changes(fns_["run_scan"], "related_domains"):
            bad.append("run_scan changes related_domains")
        passes_ = [k.value for n in _ast.walk(fns_["run_scan"])
                   if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
                   and n.func.attr == "scan"
                   for k in n.keywords if k.arg == "related_domains"]
        if not (len(passes_) == 1 and isinstance(passes_[0], _ast.Name)
                and passes_[0].id == "related_domains"):
            bad.append("run_scan does not pass related_domains=related_domains to scan()")
        if _changes(scan_fns_[0], "related_domains"):
            bad.append("scan() changes related_domains")
    # The list is used only where it is passed on: start_scan cleans it once and
    # puts it in the payload, run_scan hands it to scan(), and scan() hands it
    # to the builder. An alias (confirmed = related_domains; del confirmed[10:])
    # trims the same list without touching a name the walk follows (critique
    # round 9, GS9-3).
    if not bad:
        for fn_, nm_, want_uses_, how_ in (
                (fns_["start_scan"], "start_scan", 2, "cleaned once and put in the payload"),
                (fns_["run_scan"], "run_scan", 1, "handed to scan()"),
                (scan_fns_[0], "scan()", 1, "handed to the builder")):
            uses_ = [n for n in _ast.walk(fn_)
                     if isinstance(n, _ast.Name) and n.id == "related_domains"]
            if len(uses_) != want_uses_:
                bad.append("%s names related_domains %d times, not %d (%s)"
                           % (nm_, len(uses_), want_uses_, how_))
        # The payload dict itself: built once, passed on, never written into.
        pay_uses = [n for n in _ast.walk(fns_["start_scan"])
                    if isinstance(n, _ast.Name) and n.id == "payload"]
        pay_writes = [n for n in _ast.walk(fns_["start_scan"])
                      if isinstance(n, (_ast.Assign, _ast.AugAssign, _ast.Delete))
                      and any(isinstance(t, _ast.Subscript)
                              and getattr(t.value, "id", "") in ("payload", "data")
                              for t in (n.targets if isinstance(n, (_ast.Assign, _ast.Delete))
                                        else [n.target]))]
        if len(pay_uses) != 2 or pay_writes:
            bad.append("start_scan builds the payload %d time(s) and writes into the "
                       "payload or the request %d time(s)" % (len(pay_uses) - 1, len(pay_writes)))
    # And by behaviour: 12 confirmed domains posted to the route must reach the
    # scanner as 12. A cap written to the payload, to the request body or
    # through an alias changes no name the AST walk follows (critique round 9,
    # GS9-3).
    twelve_ = ["sib%02d.co.za" % i for i in range(12)]
    seen_ = {}

    class _StubScanner:
        def __init__(self, *a, **k):
            pass

        def scan(self, domain, **kw):
            seen_["scanner"] = list(kw.get("related_domains") or [])
            raise RuntimeError("the arguments are recorded; the scan itself is not run")

    app_mod = importlib.import_module("app")
    import contextlib as _ctx
    import types as _types
    # run_scan imports observability, which needs prometheus_client: a stub
    # stands in, so this measures the chain rather than the environment.
    _obs = _types.ModuleType("observability")
    _obs.observe_scan = lambda *a, **k: _ctx.nullcontext()
    _obs.record_checker_durations = lambda *a, **k: None

    def _enqueue(scan_id, payload):
        seen_["payload"] = list(payload.get("related_domains") or [])
        app_mod._run_scan_job(payload)
        return True

    def _failed(scan_id, msg=None, *a, **k):
        seen_.setdefault("failed", msg)
    try:
        with mock.patch.object(app_mod, "domain_exists", lambda *a, **k: True), \
             mock.patch.object(app_mod, "SecurityScanner", _StubScanner), \
             mock.patch.object(app_mod, "save_scan", lambda *a, **k: None), \
             mock.patch.object(app_mod, "mark_failed", _failed), \
             mock.patch.dict(sys.modules, {"observability": _obs}), \
             mock.patch.object(app_mod.SCAN_QUEUE, "enqueue", _enqueue), \
             app_mod.app.test_client() as client_:
            resp_ = client_.post("/api/scan", json={"domain": "acme.co.za",
                                                    "related_domains": twelve_})
        seen_["http"] = resp_.status_code
    except Exception as exc_:
        seen_["error"] = repr(exc_)[:160]
    if seen_.get("payload") != twelve_ or seen_.get("scanner") != twelve_:
        bad.append("the route enqueued %r and the scanner received %r of 12 confirmed "
                   "domains (%r)" % (len(seen_.get("payload") or []),
                                     len(seen_.get("scanner") or []),
                                     seen_.get("error") or seen_.get("failed")
                                     or seen_.get("http")))
    if bad:
        failures.append("discovery[related_domains_chain]: " + "; ".join(bad))
    report(not bad, "related_domains_reach_the_builder_as_validated")

    # 8. The checker: measured only where the sibling answered, at a public
    # address; a measured 0 is 0; every branch of the TLS-reached test; and it
    # returns at its budget with what finished, through scan()'s own runner.
    import threading
    import time as _time
    import scanner_db as _sdb
    dns_ok = {"status": "completed", "risk_score": 0, "issues": [],
              "open_ports": [{"port": 443}]}
    dns_no_ports = {"status": "completed", "risk_score": 0, "issues": [], "open_ports": []}
    info_ok = {"status": "completed", "score": 100, "exposed_paths": [], "issues": [],
               "probe_status_codes": {404: 18}}
    ssl_zero = {"status": "completed", "score": 0, "grade": "F",
                "tls_versions": {"TLS 1.2": True}}
    off = {"TLS 1.0": False, "TLS 1.1": False, "TLS 1.2": False, "TLS 1.3": False}
    ssl_fail = {"status": "completed", "score": 0, "grade": "F", "tls_versions": dict(off),
                "certificate": {"valid": False, "error": "[Errno 111] Connection refused"}}
    ssl_good = {"status": "completed", "score": 95, "grade": "A",
                "tls_versions": {"TLS 1.2": True, "TLS 1.3": True},
                "certificate": {"valid": True, "subject": "CN=sib.co.za"}}
    no_answer = {"status": "completed", "score": 100, "exposed_paths": [], "issues": [],
                 "probe_status_codes": {0: 18}}
    no_codes = {"status": "completed", "score": 100, "exposed_paths": [], "issues": [],
                "probe_status_codes": {}}
    # What SSLChecker returns when TLS WAS reached (critique round 3 read these
    # off the real checker): the stdlib path against a self-signed host, the
    # stdlib path with a certificate read and no protocol answer, the sslyze
    # path, and protocols answered with a certificate error. Each is paired
    # with a DNS check that failed, and with one that lists no web port, so the
    # score can only be kept because TLS was reached.
    tls_shapes = [
        ("stdlib_self_signed", 0, {"status": "completed", "score": 0, "grade": "F",
                                   "tls_versions": dict(off),
                                   "certificate": {"valid": False, "error":
                                                   "[SSL: CERTIFICATE_VERIFY_FAILED] certificate "
                                                   "verify failed: self-signed certificate"}}),
        ("stdlib_certificate_only", 20, {"status": "completed", "score": 20, "grade": "F",
                                         "tls_versions": dict(off),
                                         "certificate": {"valid": True,
                                                         "subject": "CN=sib.co.za"}}),
        ("sslyze_tls10", 50, {"status": "completed", "score": 50, "grade": "C",
                              "tls_versions": {"TLS 1.0": True, "TLS 1.2": True},
                              "certificate": {"valid": True, "subject": "CN=sib.co.za"}}),
        ("versions_with_certificate_error", 30, {"status": "completed", "score": 30,
                                                 "grade": "D",
                                                 "tls_versions": {"TLS 1.0": True},
                                                 "certificate": {"valid": False,
                                                                 "error": "hostname mismatch"}}),
    ]
    pub = ["196.22.1.5"]
    checker_cases = [
        ("ssl_zero", ssl_zero, dns_ok, info_ok, pub, []),
        ("ssl_error", {"status": "error", "score": 0}, dns_ok, info_ok, pub, []),
        ("nothing", RuntimeError("down"), RuntimeError("down"), RuntimeError("down"), pub, []),
        ("no_dns", ssl_zero, dns_ok, info_ok, [], []),
        ("no_web", ssl_fail, {"status": "completed", "risk_score": 0,
                              "open_ports": [{"port": 25}]}, no_answer, pub, []),
        ("plain_http", ssl_fail, {"status": "completed", "risk_score": 0,
                                  "open_ports": [{"port": 80}]}, no_answer, pub, []),
        ("info_error", ssl_zero, dns_ok,
         {"status": "error", "exposed_paths": [{"path": "/.env", "risk_level": "critical"}]},
         pub, []),
        ("info_no_probe_finished", ssl_good, dns_ok, no_codes, pub, []),
        ("loopback", ssl_zero, dns_ok, info_ok, ["127.0.0.1"], []),
        ("rfc1918", ssl_zero, dns_ok, info_ok, ["10.1.2.3"], []),
        ("link_local", ssl_zero, dns_ok, info_ok, ["169.254.169.254"], []),
        ("one_private_among_public", ssl_zero, dns_ok, info_ok, ["196.22.1.5", "10.0.0.1"], []),
        ("ipv6_only", ssl_zero, dns_ok, info_ok, [], ["2001:db8::10"]),
        ("cgnat", ssl_zero, dns_ok, info_ok, ["100.64.1.1"], []),
        ("public_a_loopback_aaaa", ssl_zero, dns_ok, info_ok, pub, ["::1"]),
        ("public_a_private_aaaa", ssl_zero, dns_ok, info_ok, pub, ["fd00::5"]),
        ("dual_stack_public", ssl_zero, dns_ok, info_ok, pub, ["2001:4860:4860::8888"]),
        # 443 accepts TCP but never answers the handshake: nothing measured.
        # An EOF or a plain-HTTP reply on 443 is an answer, and a finding.
        ("hung_tls_on_443", dict(ssl_fail, certificate={
            "valid": False, "error": "_ssl.c:993: The handshake operation timed out"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         no_answer, pub, []),
        ("tls_eof_on_443", dict(ssl_fail, certificate={
            "valid": False, "error": "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in "
                                     "violation of protocol (_ssl.c:1006)"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        ("http_on_443", dict(ssl_fail, certificate={
            "valid": False, "error": "[SSL: WRONG_VERSION_NUMBER] wrong version number "
                                     "(_ssl.c:1006)"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        # Every branch of the TLS rule (critique round 6: GS6-1, CD6-1, FC6-3,
        # FC6-4). A handshake that 443 accepted and never answered is not
        # assessed whatever the port probe listed; 443 answering without TLS is
        # a finding whatever it listed; a connect that timed out is a finding
        # only beside plain HTTP on 80.
        ("hung_tls_probe_missed_443", dict(ssl_fail, certificate={
            "valid": False, "error": "_ssl.c:993: The handshake operation timed out"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 80}]},
         info_ok, pub, []),
        ("connect_timeout_443_filtered_80_open", dict(ssl_fail, certificate={
            "valid": False, "error": "timed out"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 80}]},
         info_ok, pub, []),
        ("connect_timeout_on_open_443", dict(ssl_fail, certificate={
            "valid": False, "error": "timed out"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        ("reset_on_443", dict(ssl_fail, certificate={
            "valid": False, "error": "[Errno 104] Connection reset by peer"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        ("forcibly_closed_on_443", dict(ssl_fail, certificate={
            "valid": False, "error": "[WinError 10054] An existing connection was forcibly "
                                     "closed by the remote host"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        ("hang_then_plain_http", dict(ssl_fail, certificate={
            "valid": False, "error": "_ssl.c:993: The handshake operation timed out"},
            cipher_suite={"name": "Unknown", "bits": 0, "is_weak": True,
                          "error": "[SSL: WRONG_VERSION_NUMBER] wrong version number"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": [{"port": 443}]},
         info_ok, pub, []),
        ("http_on_443_port_check_failed", dict(ssl_fail, certificate={
            "valid": False, "error": "[SSL: WRONG_VERSION_NUMBER] wrong version number"}),
         {"status": "error", "error": "port scan timed out"}, info_ok, pub, []),
        ("http_on_443_no_ports_listed", dict(ssl_fail, certificate={
            "valid": False, "error": "[SSL: WRONG_VERSION_NUMBER] wrong version number"}),
         {"status": "completed", "risk_score": 0, "issues": [], "open_ports": []},
         info_ok, pub, []),
        ("reset_on_443_port_check_failed", dict(ssl_fail, certificate={
            "valid": False, "error": "[Errno 104] Connection reset by peer"}),
         {"status": "error", "error": "port scan timed out"}, info_ok, pub, []),
    ] + [("tls:%s:dns_down" % n, s, RuntimeError("dns down"), info_ok, pub, [])
         for n, _, s in tls_shapes] \
      + [("tls:%s:no_ports" % n, s, dns_no_ports, info_ok, pub, [])
         for n, _, s in tls_shapes]
    # One case per error the SSL check records, written as the real checker
    # writes it, beside the port probe that decides it (critique round 7: GS7-4,
    # CL7-3). An answer without TLS is a finding whatever the probe saw; a hang
    # is never priced; a connect timeout, a refusal or an alert is left to the
    # probe.
    dns_443 = {"status": "completed", "risk_score": 0, "issues": [],
               "open_ports": [{"port": 443}]}
    dns_80 = {"status": "completed", "risk_score": 0, "issues": [],
              "open_ports": [{"port": 80}]}
    dns_80_443 = {"status": "completed", "risk_score": 0, "issues": [],
                  "open_ports": [{"port": 80}, {"port": 443}]}
    dns_failed = {"status": "error", "error": "port scan timed out"}
    answered_errs = [
        "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1006)",
        "[SSL: RECORD_LAYER_FAILURE] record layer failure (_ssl.c:1000)",
        "[SSL: PACKET_LENGTH_TOO_LONG] packet length too long (_ssl.c:1000)",
        "[SSL: UNKNOWN_PROTOCOL] unknown protocol (_ssl.c:1000)",
        "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol "
        "(_ssl.c:1006)",
        "EOF occurred in violation of protocol (_ssl.c:2427)",
        "[Errno 104] Connection reset by peer",
        "[WinError 10054] An existing connection was forcibly closed by the remote host",
    ]
    hung_errs = ["_ssl.c:993: The handshake operation timed out",
                 "_ssl.c:980: The read operation timed out"]
    tcp_errs = ["timed out", "[Errno 110] Connection timed out",
                "[WinError 10060] A connection attempt failed because the connected party "
                "did not properly respond after a period of time, or established connection "
                "failed because connected host has failed to respond"]
    alert = "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1010)"

    def tls_fail(cert_err, cipher_err=None):
        s_ = dict(ssl_fail, certificate={"valid": False, "error": cert_err})
        if cipher_err:
            s_["cipher_suite"] = {"name": "Unknown", "bits": 0, "is_weak": True,
                                  "error": cipher_err}
        return s_
    tls_table = []   # (label, SSL result, DNS result, a finding?)
    for i, e in enumerate(answered_errs):
        tls_table += [("answered%d:port_check_failed" % i, tls_fail(e), dns_failed, True),
                      ("answered%d:beside_a_hang" % i, tls_fail(hung_errs[0], e), dns_443, True)]
    for i, e in enumerate(hung_errs):
        tls_table += [("hung%d:80_listed" % i, tls_fail(e), dns_80, False),
                      ("hung%d:80_443_listed" % i, tls_fail(e), dns_80_443, False)]
    for i, e in enumerate(tcp_errs):
        tls_table += [("tcp%d:443_listed" % i, tls_fail(e), dns_443, False),
                      ("tcp%d:80_443_listed" % i, tls_fail(e), dns_80_443, False),
                      ("tcp%d:80_listed" % i, tls_fail(e), dns_80, True)]
    tls_table += [
        ("refused:443_listed", tls_fail("[Errno 111] Connection refused"), dns_443, True),
        ("refused:80_443_listed", tls_fail("[Errno 111] Connection refused"), dns_80_443,
         True),
        ("refused:port_check_failed", tls_fail("[Errno 111] Connection refused"), dns_failed,
         False),
        ("alert:443_listed", tls_fail(alert), dns_443, True),
        ("alert:port_check_failed", tls_fail(alert), dns_failed, False),
    ]
    checker_cases += [("tls_table:" + l, s_, d_, info_ok, pub, [])
                      for l, s_, d_, _f in tls_table]
    got = {}
    for label, s_res, d_res, i_res, v4, v6 in checker_cases:
        calls = []
        res_fn, ip_fn = _fake_dns(v4, v6)
        with mock.patch.object(csc, "SSLChecker", _fake_checker(s_res, calls=calls)), \
             mock.patch.object(csc, "DNSInfrastructureChecker", _fake_checker(d_res, calls=calls)), \
             mock.patch.object(csc, "InformationDisclosureChecker",
                               _fake_checker(i_res, calls=calls)), \
             mock.patch.object(csc.dns_cache, "resolve", res_fn), \
             mock.patch.object(csc.dns_cache, "get_ip", ip_fn):
            r = csc.RelatedDomainsChecker().check("acme.co.za", ["sib.co.za"])
            c = ed.build_related_domains_category(
                "acme.co.za", ["sib.co.za"], RD_SUB_OK,
                lambda ds: csc.RelatedDomainsChecker().check("acme.co.za", ds))
        got[label] = (r, c, ((r.get("dependants") or [{}])[0]), len(calls))
    bad = []
    r, c, dep, _n = got["ssl_zero"]
    if not (r["scanned_count"] == 1 and r["score"] == 0 and r["high_count"] == 1):
        bad.append("SSL 0 -> scanned=%s score=%s high=%s"
                   % (r["scanned_count"], r["score"], r["high_count"]))
    clean_price = price(built["confirmed_clean"])
    if not price(c) > clean_price:
        bad.append("a sibling with SSL 0 prices %s, not above a clean sibling %s"
                   % (price(c), clean_price))
    r, c, dep, _n = got["ssl_error"]
    if not (r["scanned_count"] == 1 and r["score"] == 100 and dep.get("not_measured") == ["ssl"]):
        bad.append("SSL error -> score=%s not_measured=%r" % (r["score"], dep.get("not_measured")))
    for label in ("nothing", "no_dns"):
        r, c, dep, _n = got[label]
        if not (r["scanned_count"] == 0 and r.get("not_assessed") == ["sib.co.za"]
                and c.get("status") == "unassessed"
                and c.get("unassessed_reason") == "not_measured"):
            bad.append("%s -> scanned=%s category=%s/%s" % (
                label, r["scanned_count"], c.get("status"), c.get("unassessed_reason")))
    if "[dns] does not resolve; not assessed on this scan" not in got["no_dns"][2].get("issues", []):
        bad.append("an unresolvable sibling is not described as such: %r"
                   % got["no_dns"][2].get("issues"))
    r, c, dep, _n = got["no_web"]
    if not (r["scanned_count"] == 1 and r["score"] == 100
            and dep.get("not_measured") == ["info", "ssl"]
            and not ed.related_domains_fully_assessed(c)):
        bad.append("no web service -> score=%s not_measured=%r"
                   % (r["score"], dep.get("not_measured")))
    r, c, dep, _n = got["plain_http"]
    if not (r["score"] == 0 and dep.get("ssl_score") == 0):
        bad.append("plain-HTTP web host lost its no-TLS finding: score=%s" % r["score"])
    r, c, dep, _n = got["info_error"]
    if r["critical_count"] != 0:
        bad.append("an errored info check still counted %s critical path(s)"
                   % r["critical_count"])
    r, c, dep, _n = got["info_no_probe_finished"]
    if not (r["scanned_count"] == 1 and dep.get("not_measured") == ["info"]
            and not ed.related_domains_fully_assessed(c)):
        bad.append("an info check on which no probe finished counted as measured: "
                   "not_measured=%r full=%r" % (dep.get("not_measured"),
                                               ed.related_domains_fully_assessed(c)))
    for label in ("loopback", "rfc1918", "link_local", "one_private_among_public",
                  "cgnat", "public_a_loopback_aaaa", "public_a_private_aaaa"):
        r, c, dep, n_calls = got[label]
        if not (r["scanned_count"] == 0 and n_calls == 0 and c.get("status") == "unassessed"
                and any("non-public address" in i for i in dep.get("issues", []))):
            bad.append("%s -> scanned=%s sub-checks called=%d status=%s issues=%r"
                       % (label, r["scanned_count"], n_calls, c.get("status"),
                          dep.get("issues")))
    r, c, dep, n_calls = got["ipv6_only"]
    issues = " ".join(dep.get("issues", []))
    if not (r["scanned_count"] == 0 and n_calls == 0 and "resolves to IPv6 only" in issues
            and "does not resolve" not in issues):
        bad.append("IPv6-only sibling -> scanned=%s calls=%d issues=%r"
                   % (r["scanned_count"], n_calls, dep.get("issues")))
    r, c, dep, _n = got["hung_tls_on_443"]
    if not (dep.get("ssl_score") is None and "ssl" in dep.get("not_measured", [])
            and price(c) == neutral):
        bad.append("a TLS handshake that timed out on an open 443 was scored: ssl_score=%r "
                   "not_measured=%r price=%s/%s" % (dep.get("ssl_score"),
                                                  dep.get("not_measured"), price(c), neutral))
    for label in ("tls_eof_on_443", "http_on_443", "connect_timeout_443_filtered_80_open",
                  "reset_on_443", "forcibly_closed_on_443", "hang_then_plain_http",
                  "http_on_443_port_check_failed", "http_on_443_no_ports_listed",
                  "reset_on_443_port_check_failed"):
        r, c, dep, _n = got[label]
        if not (dep.get("ssl_score") == 0 and price(c) > neutral):
            bad.append("%s lost its no-TLS finding: ssl_score=%r price=%s/%s"
                       % (label, dep.get("ssl_score"), price(c), neutral))
    for label in ("hung_tls_probe_missed_443", "connect_timeout_on_open_443"):
        r, c, dep, _n = got[label]
        if not (dep.get("ssl_score") is None and "ssl" in dep.get("not_measured", [])
                and price(c) == neutral):
            bad.append("%s was scored: ssl_score=%r price=%s/%s"
                       % (label, dep.get("ssl_score"), price(c), neutral))
    for l, _s, _d, finding in tls_table:
        r, c, dep, _n = got["tls_table:" + l]
        ok_ = ((dep.get("ssl_score") == 0 and price(c) > neutral) if finding else
               (dep.get("ssl_score") is None and "ssl" in dep.get("not_measured", [])))
        if not ok_:
            bad.append("%s: ssl_score=%r price=%s/%s, %s expected"
                       % (l, dep.get("ssl_score"), price(c), neutral,
                          "a finding" if finding else "not assessed"))
    r, c, dep, n_calls = got["dual_stack_public"]
    if not (r["scanned_count"] == 1 and n_calls == 6 and r["score"] == 0):
        bad.append("a public dual-stack sibling -> scanned=%s calls=%d score=%s"
                   % (r["scanned_count"], n_calls, r["score"]))
    for n, want_score, _s in tls_shapes:
        for how, want_nm in (("dns_down", ["dns"]), ("no_ports", [])):
            r, c, dep, _n = got["tls:%s:%s" % (n, how)]
            if not (dep.get("ssl_score") == want_score and r["high_count"] == 1
                    and dep.get("not_measured") == want_nm and price(c) > neutral):
                bad.append("TLS reached (%s, DNS %s) lost its finding: ssl_score=%r high=%s "
                           "not_measured=%r price=%s/%s"
                           % (n, how, dep.get("ssl_score"), r["high_count"],
                              dep.get("not_measured"), price(c), neutral))
    if bad:
        failures.append("discovery[checker]: " + "; ".join(bad))
    report(not bad, "checker_measures_only_what_answered", "%d cases" % len(checker_cases))

    # The runner scan() uses, with the real run_with_timeout. The checker must
    # return at its own budget with what finished, and the outer timeout must
    # never fire first: before round 4 the checker's `with` block waited for its
    # slowest domain and the outer timeout discarded every finished one,
    # findings included. A slow check is held on an event released only after
    # the builder has returned, so a checker that waited for it could not
    # return at all: that, not a wall-clock bound, is what the gate detects
    # (critique round 4, G4-12). The held check is the last of the three, and
    # the fakes stay in place until every held thread has finished.
    crit_info = {"status": "completed", "score": 80, "issues": [],
                 "exposed_paths": [{"path": "/.env", "risk_level": "critical"}],
                 "probe_status_codes": {200: 1, 404: 17}}

    class _Held:
        """InformationDisclosureChecker whose slow domains wait for a release."""

        def __init__(self, slow=(), delay=0.0):
            self.slow, self.delay = set(slow), delay
            self.release, self.lock = threading.Event(), threading.Lock()
            self.started, self.running, self.peak, self.done = [], 0, 0, 0

        def factory(self):
            held = self

            class _Info:
                def check(self, d, *a, **k):
                    with held.lock:
                        held.started.append(d)
                        held.running += 1
                        held.peak = max(held.peak, held.running)
                    try:
                        if d in held.slow or "*" in held.slow:
                            held.release.wait(10)
                        elif held.delay:
                            _time.sleep(held.delay)
                        return dict(crit_info if d == "fast.co.za" else info_ok)
                    finally:
                        with held.lock:
                            held.running -= 1
                            held.done += 1
            return _Info

        def settle(self, n):
            """Release every held check and wait until *n* checks have finished."""
            self.release.set()
            t_end = _time.monotonic() + 10
            while _time.monotonic() < t_end:
                with self.lock:
                    if self.done >= n:
                        return True
                _time.sleep(0.02)
            return False

    class _Ck:
        """Scan()'s checkpointer, recording whether it would save the result."""

        def __init__(self):
            self.name = self.saved = None

        def run(self, name, fn):
            res = fn()
            self.name, self.saved = name, _sdb._is_done(res)
            return res

    def run_builder(confirmed, ck):
        """The builder through scan()'s runner, in a thread with a hang guard."""
        box = {}

        def go():
            box["rd"] = ed.build_related_domains_category(
                "acme.co.za", confirmed, RD_SUB_OK,
                lambda ds: sc._run_related_probe(ck, "acme.co.za", ds))
        t = threading.Thread(target=go, daemon=True)
        t.start()
        t.join(5)
        return box.get("rd") or {}, not t.is_alive()

    bad = []
    RDC = csc.RelatedDomainsChecker
    res_fn, ip_fn = _fake_dns(pub)
    # (1) One domain answers at once with a critical finding; one is held.
    held = _Held(slow=["slow.co.za"])
    with mock.patch.object(RDC, "ROUND_BUDGET", 0.3), \
         mock.patch.object(csc, "SSLChecker", _fake_checker(ssl_good)), \
         mock.patch.object(csc, "DNSInfrastructureChecker", _fake_checker(dns_ok)), \
         mock.patch.object(csc, "InformationDisclosureChecker", held.factory()), \
         mock.patch.object(csc.dns_cache, "resolve", res_fn), \
         mock.patch.object(csc.dns_cache, "get_ip", ip_fn):
        ck = _Ck()
        rd_run, returned = run_builder(["fast.co.za", "slow.co.za"], ck)
        settled = held.settle(2)
    if not (returned and settled and rd_run.get("status") == "completed"
            and rd_run.get("critical_count") == 1
            and rd_run.get("confirmed_not_assessed") == ["slow.co.za"]
            and rd_run.get("timed_out") == ["slow.co.za"]
            and ck.name == "related_domains" and ck.saved is True
            and price(rd_run) > neutral):
        bad.append("one slow domain: returned=%s status=%r critical=%r not_assessed=%r "
                   "timed_out=%r checkpointed=%r"
                   % (returned, rd_run.get("status"), rd_run.get("critical_count"),
                      rd_run.get("confirmed_not_assessed"), rd_run.get("timed_out"),
                      ck.saved))
    # (2) Nothing measured and time ran out: only a held domain, and a held
    # domain beside one that does not resolve. Both are a timeout, which is
    # never checkpointed, so a resumed scan probes again.
    for label, confirmed, per in (
            ("only_a_slow_domain", ["slow.co.za"], None),
            ("slow_beside_unresolvable", ["gone.co.za", "slow.co.za"],
             {"gone.co.za": ([], [])})):
        held = _Held(slow=["slow.co.za"])
        r_fn, i_fn = _fake_dns(pub, per=per)
        with mock.patch.object(RDC, "ROUND_BUDGET", 0.3), \
             mock.patch.object(csc, "SSLChecker", _fake_checker(ssl_good)), \
             mock.patch.object(csc, "DNSInfrastructureChecker", _fake_checker(dns_ok)), \
             mock.patch.object(csc, "InformationDisclosureChecker", held.factory()), \
             mock.patch.object(csc.dns_cache, "resolve", r_fn), \
             mock.patch.object(csc.dns_cache, "get_ip", i_fn):
            ck2 = _Ck()
            rd_to, returned = run_builder(confirmed, ck2)
            settled = held.settle(1)
        if not (returned and settled and rd_to.get("status") == "unassessed"
                and rd_to.get("unassessed_reason") == "timeout" and ck2.saved is False):
            bad.append("%s: returned=%s status=%r reason=%r checkpointed=%r"
                       % (label, returned, rd_to.get("status"),
                          rd_to.get("unassessed_reason"), ck2.saved))
    # (3) More domains than workers: eight domains of 0.4 s each run as two
    # rounds of four inside the two-round budget (1.2 s). A checker that waits
    # for one round only, or runs fewer than four at a time, leaves some
    # unassessed.
    held = _Held(delay=0.4)
    eight = ["s%d.co.za" % i for i in range(8)]
    with mock.patch.object(RDC, "ROUND_BUDGET", 0.6), \
         mock.patch.object(csc, "SSLChecker", _fake_checker(ssl_good)), \
         mock.patch.object(csc, "DNSInfrastructureChecker", _fake_checker(dns_ok)), \
         mock.patch.object(csc, "InformationDisclosureChecker", held.factory()), \
         mock.patch.object(csc.dns_cache, "resolve", res_fn), \
         mock.patch.object(csc.dns_cache, "get_ip", ip_fn):
        r8 = csc.RelatedDomainsChecker().check("acme.co.za", eight)
        held.settle(8)
    if not (r8.get("scanned_count") == 8 and not r8.get("timed_out")
            and held.peak == RDC.WORKERS == 4):
        bad.append("eight domains: scanned=%r timed_out=%r peak concurrency=%r"
                   % (r8.get("scanned_count"), r8.get("timed_out"), held.peak))
    # (4) Queued domains are cancelled at the budget and never probed after
    # it: nine held domains, four running and five queued when it ends.
    held = _Held(slow=["*"])
    nine = ["q%d.co.za" % i for i in range(9)]
    with mock.patch.object(RDC, "ROUND_BUDGET", 0.1), \
         mock.patch.object(csc, "SSLChecker", _fake_checker(ssl_good)), \
         mock.patch.object(csc, "DNSInfrastructureChecker", _fake_checker(dns_ok)), \
         mock.patch.object(csc, "InformationDisclosureChecker", held.factory()), \
         mock.patch.object(csc.dns_cache, "resolve", res_fn), \
         mock.patch.object(csc.dns_cache, "get_ip", ip_fn):
        r9 = csc.RelatedDomainsChecker().check("acme.co.za", nine)
        started_at_return = list(held.started)
        held.settle(len(started_at_return))
        _time.sleep(0.3)
        started_after = list(held.started)
        held.settle(len(started_after))
    if not (r9.get("status") == "timeout"
            and sorted(r9.get("timed_out") or []) == sorted(nine)
            and len(started_at_return) == 4 and started_after == started_at_return):
        bad.append("nine held domains: status=%r timed_out=%d started by the budget=%d, "
                   "started after it=%r"
                   % (r9.get("status"), len(r9.get("timed_out") or []),
                      len(started_at_return),
                      sorted(set(started_after) - set(started_at_return))))
    # The outer budget, as scan() passes it, for one to ten confirmed domains.
    seen = []

    def spy(fn, args=(), kwargs=None, timeout=60.0, on_timeout_result=None):
        seen.append((type(getattr(fn, "__self__", None)), args, timeout, on_timeout_result))
        return {"status": "completed", "dependants": [], "scanned_count": 0}
    with mock.patch.object(sc, "run_with_timeout", spy):
        for n in range(1, 11):
            sc._run_related_probe(_Ck(), "acme.co.za", ["s%02d.co.za" % i for i in range(n)])
    for n, (cls, args_, timeout, oto) in zip(range(1, 11), seen):
        if not (cls is RDC and args_ == ("acme.co.za", ["s%02d.co.za" % i for i in range(n)])
                and timeout >= RDC.budget_seconds(n) + 30 and oto == {"status": "timeout"}):
            bad.append("n=%d: runner called %r with %r, outer timeout %r against a checker "
                       "budget of %r, on_timeout=%r" % (n, cls, args_, timeout,
                                                        RDC.budget_seconds(n), oto))
    if len(seen) != 10:
        bad.append("the runner called run_with_timeout %d times for 10 runs" % len(seen))
    # The budget covers the slowest realistic domain with a margin: one whose
    # HTTPS does not answer takes about 144 to 150 s, the upper figure when an
    # open port makes the port probe run its canary connects (rounds 3 and 4).
    if not (RDC.ROUND_BUDGET >= 160 and RDC.budget_seconds(4) == RDC.ROUND_BUDGET
            and RDC.budget_seconds(10) == 3 * RDC.ROUND_BUDGET):
        bad.append("budget: ROUND_BUDGET=%r budget(4)=%r budget(10)=%r"
                   % (RDC.ROUND_BUDGET, RDC.budget_seconds(4), RDC.budget_seconds(10)))
    if bad:
        failures.append("discovery[runner]: " + "; ".join(bad))
    report(not bad, "runner_returns_at_the_budget_with_what_finished")

    # 9. InformationDisclosureChecker requests all 18 of its paths (5y). A late
    # local import once made HTTP unbound in the probe threads, so the 10
    # medium-risk paths were never requested while the check reported completed.
    web = _FakeWeb()
    with mock.patch.object(_hc, "HTTP", web), mock.patch.object(ct, "HTTP", web):
        res = ct.InformationDisclosureChecker().check("acme.co.za")
    asked = {u.split("acme.co.za", 1)[1] for u in web.heads}
    want_paths = {p for p, _ in (ct.InformationDisclosureChecker.CRITICAL_PATHS
                                 + ct.InformationDisclosureChecker.MEDIUM_PATHS)}
    ok = asked == want_paths and res.get("status") == "completed" and not res.get("probe_errors")
    if not ok:
        failures.append("discovery[info_paths]: %d of %d paths requested (missing %r), "
                        "status=%r probe_errors=%r"
                        % (len(asked & want_paths), len(want_paths),
                           sorted(want_paths - asked)[:4], res.get("status"),
                           res.get("probe_errors")))
    report(ok, "info_disclosure_requests_every_path", "%d/%d" % (len(asked), len(want_paths)))

    # A probe with no HTTP answer never decides the refusal test (critique
    # round 3, C3-1): on a host that refused every answered probe, an
    # unanswered one used to turn "unreachable" into a clean 100. A probe that
    # raises is counted.
    CRIT = {p for p, _ in ct.InformationDisclosureChecker.CRITICAL_PATHS}
    MED = [p for p, _ in ct.InformationDisclosureChecker.MEDIUM_PATHS]
    info_cases = [
        # (label, head(path), root, apex_answered, raise_on, want)
        ("walled_off_medium_unanswered", lambda p: 403 if p in CRIT else None, None, False, (),
         dict(status="unreachable", silent=10)),
        ("one_unanswered_probe", lambda p: None if p == MED[0] else 403, 403, False, (),
         dict(status="unreachable", silent=1)),
        ("denied_with_unanswered_medium", lambda p: 403 if p in CRIT else None, 200, False, (),
         dict(status="completed", denied=8)),
        ("probe_that_raises_is_counted", None, 404, True, ("/.env",),
         dict(status="completed", errors=1)),
    ]
    bad = []
    for label, head, root, apex, raise_on, want in info_cases:
        web = _FakeWeb(head=head, root=root, apex=apex, raise_on=raise_on)
        with mock.patch.object(_hc, "HTTP", web), mock.patch.object(ct, "HTTP", web):
            res = ct.InformationDisclosureChecker().check("acme.co.za")
        why = res.get("unreachable_reason") or ""
        if (res.get("status") != want["status"]
                or ("denied" in want and res.get("sensitive_paths_denied") != want["denied"])
                or ("errors" in want and res.get("probe_errors") != want["errors"])
                or ("silent" in want and "%d got no answer" % want["silent"] not in why)
                or (want["status"] == "unreachable" and res.get("http_status") == 0)):
            bad.append("%s -> status=%r denied=%r errors=%r http_status=%r reason=%r"
                       % (label, res.get("status"), res.get("sensitive_paths_denied"),
                          res.get("probe_errors"), res.get("http_status"), why[:90]))
    if bad:
        failures.append("discovery[info_refusal]: " + "; ".join(bad))
    report(not bad, "unanswered_probe_never_decides_a_refusal", "%d cases" % len(info_cases))

    # The scan form sends every confirmed domain. The server caps the list and
    # reports the overflow as not assessed; a browser-side trim dropped it unseen.
    with io.open(os.path.join(SEC, "templates", "index.html"), encoding="utf-8") as fh:
        page = fh.read().replace("\r\n", "\n")
    m = _re.search(r"function collectRelatedDomains\(\) \{.*?\n\}\n", page, _re.S)
    body = m.group(0) if m else ""
    ok = bool(body) and not _re.search(r"\.(slice|splice)\(|\.length\s*=", body)
    if not ok:
        failures.append("discovery[form]: collectRelatedDomains %s"
                        % ("not found" if not body else "trims the confirmed list"))
    report(ok, "form_sends_every_confirmed_domain")

    # 10. Wiring. scan() builds the category once, through the builder, with
    # the right arguments, assigns it once, and probes confirmed domains only
    # through the module-level runner, which gives the checker the runner's own
    # list. AST, so a comment cannot satisfy it. The runner's budget is checked
    # by running it (section 8).
    with io.open(os.path.join(SEC, "scanner.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    scan_fn = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "scan")
    runner = next((n for n in tree.body
                   if isinstance(n, ast.FunctionDef) and n.name == "_run_related_probe"), None)
    builder_calls = gated = 0
    call_ok = False
    builder_targets, writes = set(), []
    for node in ast.walk(scan_fn):
        if isinstance(node, ast.If) and "related_domains" in ast.dump(node.test):
            for inner in ast.walk(node):
                if (isinstance(inner, ast.Call)
                        and getattr(inner.func, "id", "") == "build_related_domains_category"):
                    gated += 1
        if (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "build_related_domains_category"):
            builder_calls += 1
            a = node.args
            sub_ok = len(a) > 2 and any(
                isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute)
                and x.func.attr == "get" and getattr(x.func.value, "id", "") == "cat_results"
                and x.args and getattr(x.args[0], "value", None) == "subdomains"
                for x in ast.walk(a[2]))
            probe = a[3] if len(a) == 4 else None
            probe_ok = False
            if isinstance(probe, ast.Lambda) and len(probe.args.args) == 1:
                p = probe.args.args[0].arg
                b = probe.body
                probe_ok = (isinstance(b, ast.Call)
                            and getattr(b.func, "id", "") == "_run_related_probe"
                            and len(b.args) == 3 and not b.keywords
                            and getattr(b.args[0], "id", "") == "_ckpt"
                            and getattr(b.args[1], "id", "") == "domain"
                            and getattr(b.args[2], "id", "") == p)
            call_ok = (len(a) == 4 and getattr(a[0], "id", "") == "domain"
                       and getattr(a[1], "id", "") == "related_domains" and sub_ok
                       and probe_ok)
        if isinstance(node, ast.Assign):
            if (isinstance(node.value, ast.Call)
                    and getattr(node.value.func, "id", "") == "build_related_domains_category"):
                builder_targets |= {t.id for t in node.targets if isinstance(t, ast.Name)}
            for t in node.targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                        and t.value.id == "cat_results"
                        and isinstance(t.slice, ast.Constant)
                        and t.slice.value == "related_domains"):
                    writes.append(node.value)
    write_ok = (len(writes) == 1 and isinstance(writes[0], ast.Name)
                and writes[0].id in builder_targets)
    # Every assignment to the builder's variable is the builder call: a
    # fallback such as `except: _rd = {"status": "error"}` would pass as built
    # once from the builder, and "error" prices +5 to +16.
    target_assigns = [
        n for n in ast.walk(scan_fn)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        and any(isinstance(t, ast.Name) and t.id in builder_targets
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
    write_ok = write_ok and len(target_assigns) == 1
    in_scan = sum(1 for n in ast.walk(scan_fn)
                  if isinstance(n, ast.Name) and n.id == "RelatedDomainsChecker")
    runner_ok = False
    if runner is not None and len(runner.args.args) == 3:
        dparam, lparam = runner.args.args[1].arg, runner.args.args[2].arg
        for n in ast.walk(runner):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "run_with_timeout":
                first = n.args[0] if n.args else None
                first_ok = (isinstance(first, ast.Attribute) and first.attr == "check"
                            and isinstance(first.value, ast.Call)
                            and getattr(first.value.func, "id", "") == "RelatedDomainsChecker")
                kw = {k.arg: k.value for k in n.keywords}
                targs = kw.get("args")
                args_ok = (isinstance(targs, ast.Tuple) and len(targs.elts) == 2
                           and getattr(targs.elts[0], "id", "") == dparam
                           and getattr(targs.elts[1], "id", "") == lparam)
                oto = kw.get("on_timeout_result")
                oto_ok = isinstance(oto, ast.Dict) and {
                    getattr(k, "value", None): getattr(v, "value", None)
                    for k, v in zip(oto.keys, oto.values)}.get("status") == "timeout"
                runner_ok = first_ok and args_ok and oto_ok
    ckpt_ok = {"timeout", "error"} <= set(_sdb._NOT_DONE_STATUSES)
    ok = (builder_calls == 1 and gated == 0 and call_ok and write_ok and runner_ok
          and in_scan == 0 and ckpt_ok)
    if not ok:
        failures.append(
            "discovery[wiring]: builder calls=%d gated=%d arguments=%s single-assignment=%s "
            "runner=%s RelatedDomainsChecker named in scan()=%d timeout-not-checkpointed=%s"
            % (builder_calls, gated, call_ok, write_ok, runner_ok, in_scan, ckpt_ok))
    report(ok, "scan_builds_once_with_the_right_arguments")

    # 11. The dashboard, run by node on every case the gate built, against the
    # Python and the PDF card: the state, whether fully assessed, the notes word
    # for word, the lead sentence (the card's own opening sentence, where the
    # two share one), the badge against the card's colour, the rows, and the
    # candidates and "and N more" count. frontend/src/data/relatedDomains.ts is
    # self-contained so node can run it as it ships.
    # The page renders every field of the model and shows related domains
    # nowhere else, and the committed bundle carries this module's wording, so
    # a stale build cannot ship (critique round 4, G4-04).
    mod_path = os.path.join(SEC, "frontend", "src", "data", "relatedDomains.ts")
    with io.open(os.path.join(SEC, "frontend", "src", "pages", "detail", "ExposurePage.tsx"),
                 encoding="utf-8") as fh:
        page_tsx = fh.read()
    with io.open(mod_path, encoding="utf-8") as fh:
        mod_src = fh.read()
    with io.open(os.path.join(SEC, "static", "dashboard", "app.js"), encoding="utf-8") as fh:
        bundle = fh.read()
    bad = [f for f in ("m.intro", "m.lead", "m.sources", "m.badge", "m.rows", "m.notes",
                       "m.pending", "m.extra") if f not in page_tsx]
    page_tsx_n = page_tsx.replace("\r\n", "\n")
    for snippet in ("\n      <div style={{ fontSize: 12.5, marginBottom: 10 }}>{m.lead}</div>\n",
                    "\n      {m.notes.map((n) => (\n",
                    "\n      {(m.pending.length > 0 || m.extra > 0) && (\n"):
        if snippet not in page_tsx_n:
            bad.append("not rendered unconditionally: %r" % snippet.strip()[:40])
    # The panel itself is mounted unconditionally (critique round 7, GS7-5).
    lines_ = page_tsx_n.split("\n")
    at_ = [i for i, l in enumerate(lines_) if l.strip() == "<RelatedDomainsPanel r={r} />"]
    before_ = [l.strip() for l in lines_[:at_[0]] if l.strip()][-1] if at_ else ""
    if len(at_) != 1 or before_.endswith(("&&", "&& (", "?", "? (", "(", "{")):
        bad.append("the related-domains panel is not mounted unconditionally")
    # A generic panel for a completed checker reads its own severity and
    # finding counts, never "Passed" beside a finding (critique round 7,
    # ST7-2); the Additional Intelligence Sources panels use it.
    if "<CheckerHeader category={c} refine />" not in page_tsx_n:
        bad.append("MoreCheckers does not refine its badges")
    # Pinning panelShowsCounts in isolation left the caller free: replacing the
    # one decision line puts the counts back over a chain nobody read, and the
    # gate stayed green (critique round 12, GS12-1).
    with io.open(os.path.join(SEC, "frontend", "src", "components", "detail",
                              "parts.tsx"), encoding="utf-8") as fh:
        parts_src = fh.read().replace("\r\n", "\n")
    # Forced with no reason given, the note must fail closed rather than explain
    # a not-assessed checker as "(passed)" (critique round 12, SC-NOTE-PASSED).
    if "force ? 'the checker recorded no measurement'" not in parts_src:
        bad.append("the forced not-assessed note takes its reason from the status")
    for need_ in ("notAssessed: !panelShowsCounts(c)",
                  "<NotAssessedNote category={c} force",
                  "body.kind === 'note'", "body.lowerBound"):
        if need_ not in page_tsx_n:
            bad.append("MoreCheckers does not consume the measurement gate: %r" % need_)
    cs_path = os.path.join(SEC, "frontend", "src", "data", "checkerState.ts")
    node_cs = shutil.which("node")
    if not node_cs:
        bad.append("node is not on PATH, so checkerState.ts cannot be run")
    else:
        td_cs = tempfile.mkdtemp(prefix="cs_")
        try:
            shutil.copyfile(cs_path, os.path.join(td_cs, "checkerState.mts"))
            with io.open(os.path.join(td_cs, "cs_check.mts"), "w", encoding="utf-8") as fh:
                # Each field the rule reads, then real checker shapes: a
                # generic panel never shows "Passed", and a result marked
                # assessed: false is not assessed (critique round 8, FC8-2,
                # ST8-2, GS8-3).
                fh.write("import { refineCompletedState as f, STATE_META as M }"
                         " from './checkerState.mts'\n"
                         "console.log(JSON.stringify([\n"
                         "  f({status: 'completed', severity: 'medium', medium_count: 1}),\n"
                         "  f({status: 'completed', severity: 'high'}),\n"
                         "  f({status: 'completed', critical_count: 2}),\n"
                         "  f({status: 'completed', critical_match_count: 1}),\n"
                         "  f({status: 'completed', high_match_count: 1}),\n"
                         "  f({status: 'completed', severity: 'none'}),\n"
                         "  f({status: 'completed', severity: 'critical'}),\n"
                         "  f({status: 'completed', severity: 'medium'}),\n"
                         "  f({status: 'no_data', severity: 'medium', medium_count: 1}),\n"
                         "  f({status: 'error', critical_count: 3}),\n"
                         "  f(undefined),\n"
                         "  f({status: 'completed', high_count: 1, critical_count: 0}),\n"
                         "  f({status: 'completed', medium_count: 2}),\n"
                         "  f({status: 'completed', severity: 'none', assessed: false}),\n"
                         "  f({status: 'completed', match_count: 1, critical_match_count: 0,"
                         " high_match_count: 0}),\n"
                         "  f({status: 'completed', is_wordpress: true, plugin_count: 1,"
                         " versioned_count: 1}),\n"
                         "  f({status: 'completed', compromised_employees: 3}),\n"
                         "  f({status: 'completed', risk_level: 'CRITICAL'}),\n"
                         "  f({status: 'completed'}),\n"
                         "  M.completed]))\n")
            r_cs = subprocess.run([node_cs, "--no-warnings",
                                   os.path.join(td_cs, "cs_check.mts")],
                                  capture_output=True, text=True, timeout=60)
            try:
                cs_out = json.loads(r_cs.stdout.strip().splitlines()[-1])
            except Exception:
                cs_out = r_cs.stderr[-160:]
            if cs_out != ["warning", "failed", "critical", "critical", "failed", "completed",
                          "critical", "warning",
                          "no_data", "error", "not_assessed",
                          "failed", "warning", "not_assessed", "completed", "completed",
                          "completed", "completed", "completed",
                          {"label": "Completed", "severity": "unknown", "conclusive": True}]:
                bad.append("refineCompletedState gives %r" % (cs_out,))
        finally:
            shutil.rmtree(td_cs, ignore_errors=True)
    # CheckerHeader routes refine to that rule, and the Email-Vendor panel
    # prints its rows only for a completed result, saying when the SPF lookup
    # did not answer or was not followed (critique round 8, GS8-3, FC8-4).
    with io.open(os.path.join(SEC, "frontend", "src", "components", "detail", "parts.tsx"),
                 encoding="utf-8") as fh:
        parts_src_ = fh.read().replace("\r\n", "\n")
    if ("  const b = headerBadge(category, refine)\n" not in parts_src_
            or "  return <StatusBadge state={b.state} label={b.label} />\n" not in parts_src_):
        bad.append("CheckerHeader does not render the badge headerBadge gives")
    with io.open(os.path.join(SEC, "frontend", "src", "components", "primitives",
                              "Status.tsx"), encoding="utf-8") as fh:
        status_src_ = fh.read().replace("\r\n", "\n")
    if "  completed: CircleDot,\n" not in status_src_:
        bad.append("the Completed badge does not carry an icon of its own")
    # The Email-Vendor panel renders from data/emailVendorPanel.ts, which runs
    # under node on the real S-4 checker's output for every SPF outcome the
    # zone cases produced, and on a stored result without the field (critique
    # round 8, FC8-4; the round-9 spot check found the checker's vendor and
    # include objects joined into "[object Object]").
    with io.open(os.path.join(SEC, "frontend", "src", "pages", "detail", "EmailPage.tsx"),
                 encoding="utf-8") as fh:
        email_src_ = fh.read().replace("\r\n", "\n")
    if ("  const vp = vendorPanel(vendor as Record<string, unknown> | undefined)\n"
            not in email_src_
            or "{vp.kind === 'rows' ? <KV rows={vp.rows} /> : <EmptyState compact title={vp.title} />}"
            not in email_src_
            or "'Weak DMARC'" in email_src_ or "vendor.spf_includes" in email_src_):
        bad.append("the Email-Vendor panel does not render from emailVendorPanel.ts")
    vp_cases = dict(evs_real)
    vp_cases["stored_no_data"] = {k: v for k, v in evs_real["no_includes"].items()
                                  if k != "spf_lookup"}
    vp_cases["stored_completed"] = stored_evs
    vp_cases["timeout"] = {"status": "timeout", "error": "Checker timed out after 180s",
                           "issues": []}
    vp_cases["stored_with_vendor"] = stored_vendor_evs
    vp_cases["unknown_outcome"] = future_evs
    vp_cases["wide_surface"] = wide_evs
    vp_cases["error"] = {"status": "error", "error": "no answer", "issues": []}
    # Driven with the badge decision as a parameter, so this asserts the panel
    # body and not the badge (round 13, GS13-2).
    body_cases = {
        "not_assessed": {"v": vb_real["nested_timeout"],
                         "opts": {"notAssessed": True, "isSpf": True}},
        "partial_quiet": {"v": evs_real["quiet_vendor_plus_timeout"],
                          "opts": {"notAssessed": False, "isSpf": True}},
        "partial_with_finding": {"v": vb_real["vendor_plus_timeout"],
                                 "opts": {"notAssessed": False, "isSpf": True}},
        "measured": {"v": evs_real["nested_answered"],
                     "opts": {"notAssessed": False, "isSpf": True}},
        "partial_not_spf": {"v": evs_real["quiet_vendor_plus_timeout"],
                            "opts": {"notAssessed": False, "isSpf": False}},
    }
    vp_out = None
    if node_cs:
        td_vp = tempfile.mkdtemp(prefix="vp_")
        try:
            shutil.copyfile(os.path.join(SEC, "frontend", "src", "data", "emailVendorPanel.ts"),
                            os.path.join(td_vp, "emailVendorPanel.mts"))
            with io.open(os.path.join(td_vp, "vp_check.mts"), "w", encoding="utf-8") as fh:
                fh.write("import { vendorPanel, panelBody }"
                         " from './emailVendorPanel.mts'\n"
                         "const cases = " + json.dumps(vp_cases) + "\n"
                         "const out = {}\n"
                         "for (const [k, v] of Object.entries(cases)) out[k] = vendorPanel(v)\n"
                         "out.absent = vendorPanel(undefined)\n"
                         "const body = " + json.dumps(body_cases) + "\n"
                         "out.__body = {}\n"
                         "for (const [k, c] of Object.entries(body))"
                         " out.__body[k] = panelBody(c.v, c.opts)\n"
                         "console.log(JSON.stringify(out))\n")
            r_vp = subprocess.run([node_cs, "--no-warnings", os.path.join(td_vp, "vp_check.mts")],
                                  capture_output=True, text=True, timeout=60)
            try:
                vp_out = json.loads(r_vp.stdout.strip().splitlines()[-1])
            except Exception:
                vp_out = r_vp.stderr[-200:]
        finally:
            shutil.rmtree(td_vp, ignore_errors=True)
    if not isinstance(vp_out, dict):
        bad.append("the Email-Vendor panel did not run under node: %r" % (vp_out,))
        vp_out = {}

    def _want_panel(p):
        """What the panel must say, from the renderer's own rule."""
        why = pc.spf_surface_unmeasured(p)
        if why:
            return {"kind": "empty", "title": "Not assessed: " + why,
                    "badge": {"state": "not_assessed", "label": "Not assessed"}}
        if p.get("status") == "completed":
            vendors = [x.get("vendor") for x in (p.get("vendors_detected") or [])]
            vendors = [v for v in vendors if v]
            incs = [x.get("include") for x in (p.get("spf_includes") or [])]
            weak, partial = bool(p.get("weak_dmarc")), pc.spf_surface_partial(p)
            rows = [{"label": "Vendors detected",
                     "value": ", ".join(vendors) or "None identified"},
                    {"label": "SPF includes", "value": ", ".join(i for i in incs if i) or "—"},
                    {"label": "Weak DMARC", "value": "Yes" if weak else "No",
                     "severity": "medium" if weak else "positive"}]
            if partial:
                rows.append({"label": "SPF chain", "severity": "medium",
                             "value": "Partly read: a lookup did not answer, or a record "
                                      "redirects, so the vendors above are a lower bound"})
            if weak and vendors:
                badge = {"state": "failed"}
            elif len(vendors) >= 6:
                badge = {"state": "warning"}
            elif partial:
                badge = {"state": "warning", "label": "Partly assessed"}
            else:
                badge = {"state": "completed"}
            return {"kind": "rows", "rows": rows, "badge": badge}
        if p.get("status") == "no_data":
            return {"kind": "rows", "badge": {"state": "completed"},
                    "rows": [{"label": "Vendors detected",
                              "value": "None: no SPF includes are published"}]}
        return {"kind": "empty", "title": "No vendor-surface data"}
    for k_, p_ in sorted(vp_cases.items()):
        if vp_out.get(k_) != _want_panel(p_):
            bad.append("the Email-Vendor panel for %s gives %r, want %r"
                       % (k_, vp_out.get(k_), _want_panel(p_)))
    if vp_out.get("absent") != {"kind": "empty", "title": "No vendor-surface data"}:
        bad.append("the Email-Vendor panel with no result gives %r" % (vp_out.get("absent"),))
    if "[object" in json.dumps(vp_out):
        bad.append("the Email-Vendor panel prints an object")
    # The panel's body decision, run under node: a note where nothing was
    # measured, counts otherwise, and the lower-bound row exactly where the
    # chain was partly read - including beside a finding, which is where the
    # badge-label test used to lose it (round 13, GS13-2, GS13-3).
    body_want = {
        "not_assessed": {"kind": "note", "lowerBound": False},
        "partial_quiet": {"kind": "counts", "lowerBound": True},
        "partial_with_finding": {"kind": "counts", "lowerBound": True},
        "measured": {"kind": "counts", "lowerBound": False},
        "partial_not_spf": {"kind": "counts", "lowerBound": False},
    }
    body_got = (vp_out.get("__body") or {})
    for k_, w_ in sorted(body_want.items()):
        if body_got.get(k_) != w_:
            bad.append("the panel body for %s gives %r, want %r"
                       % (k_, body_got.get(k_), w_))
    # Pinned, not derived from the same threshold the module uses (GS10-4).
    if (vp_out.get("wide_surface") or {}).get("badge") != {"state": "warning"}:
        bad.append("a six-vendor surface is not a finding on the dashboard: %r"
                   % ((vp_out.get("wide_surface") or {}).get("badge"),))
    # The header badge, on the same real results and on the generic panels'
    # shapes: a measurement reads Completed, an unmeasured or partly read
    # surface never does, and nothing reads "Passed" (critique round 9, GS9-5).
    hb_cases = {
        "vb_failed": vb_real["nested_timeout"],
        "vb_not_followed": vb_real["redirect_only"],
        "vb_answered": vb_real["no_includes"],
        "vb_partial_quiet": vb_real["quiet_vendor_plus_timeout"],
        "vb_partial_matches": vb_real["vendor_plus_timeout"],
        "vb_stored_with_vendor": dict(stored_vendor_vb, matches=[],
                                     critical_match_count=0, high_match_count=0,
                                     issues=[]),
        "vb_unknown_outcome": future_vb,
        "vb_matches": vb_real["nested_answered"],
        "vb_stored": stored_vb,
        # An errored provider leaves its counts at the zeros it initialised
        # them to, and hb_cases carried no failing status at all until now
        # (critique round 12, R12-1, R12-4).
        "intelx_error": {"status": "error", "error": "poll timed out", "issues": [],
                         "total_results": 0, "paste_count": 0, "leak_count": 0,
                         "darkweb_count": 0},
        "hudson_error": {"status": "error", "error": "no answer", "issues": [],
                         "compromised_employees": 0, "compromised_users": 0,
                         "third_party_exposures": 0},
        "dependency_manifests": {"status": "completed", "high_count": 1, "critical_count": 0},
        "credential_correlation": {"status": "completed", "severity": "none", "assessed": False},
        "cms_plugin_sbom": {"status": "completed", "is_wordpress": True, "plugin_count": 1,
                            "versioned_count": 1},
    }
    hb_out = None
    if node_cs:
        td_hb = tempfile.mkdtemp(prefix="hb_")
        try:
            shutil.copyfile(cs_path, os.path.join(td_hb, "checkerState.mts"))
            with io.open(os.path.join(td_hb, "hb_check.mts"), "w", encoding="utf-8") as fh:
                fh.write("import { headerBadge as h, STATE_META as M,"
                         " panelShowsCounts as psc } from './checkerState.mts'\n"
                         "const cases = " + json.dumps(hb_cases) + "\n"
                         "const out = {}\n"
                         "for (const [k, v] of Object.entries(cases)) {\n"
                         "  const b = h(v, true)\n"
                         "  out[k] = { state: b.state, label: b.label ?? null,"
                         " shown: M[b.state].label }\n"
                         "}\n"
                         "const n = h(undefined, true)\n"
                         "out.absent = { state: n.state, label: n.label ?? null,"
                         " shown: M[n.state].label }\n"
                         "out.__counts = Object.fromEntries(Object.entries(cases)"
                         ".map(([k, v]) => [k, psc(v)]))\n"
                         "console.log(JSON.stringify(out))\n")
            r_hb = subprocess.run([node_cs, "--no-warnings", os.path.join(td_hb, "hb_check.mts")],
                                  capture_output=True, text=True, timeout=60)
            try:
                hb_out = json.loads(r_hb.stdout.strip().splitlines()[-1])
            except Exception:
                hb_out = r_hb.stderr[-200:]
        finally:
            shutil.rmtree(td_hb, ignore_errors=True)
    if not isinstance(hb_out, dict):
        bad.append("the header badge did not run under node: %r" % (hb_out,))
        hb_out = {}
    _vbm = vb_real["nested_answered"]
    want_hb = {
        "vb_failed": {"state": "not_assessed", "label": "Not assessed", "shown": "Not assessed"},
        "vb_not_followed": {"state": "not_assessed", "label": "Not assessed",
                            "shown": "Not assessed"},
        "vb_answered": {"state": "completed", "label": None, "shown": "Completed"},
        "vb_partial_quiet": {"state": "warning", "label": "Partly assessed", "shown": "Warning"},
        # A partly read chain that still carries a finding shows the finding.
        "vb_partial_matches": {
            "state": "critical" if vb_real["vendor_plus_timeout"].get("critical_match_count")
            else "failed", "label": None,
            "shown": "Critical" if vb_real["vendor_plus_timeout"].get("critical_match_count")
            else "Failed"},
        "vb_stored_with_vendor": {"state": "warning", "label": "Partly assessed",
                                  "shown": "Warning"},
        # An outcome the rule does not know is not a measurement, on the badge
        # as on the panel and the deck (round 11's mutation survivor).
        "vb_unknown_outcome": {"state": "not_assessed", "label": "Not assessed",
                               "shown": "Not assessed"},
        "vb_matches": {"state": "critical" if _vbm.get("critical_match_count") else "failed",
                       "label": None,
                       "shown": "Critical" if _vbm.get("critical_match_count") else "Failed"},
        "vb_stored": {"state": "not_assessed", "label": "Not assessed", "shown": "Not assessed"},
        "dependency_manifests": {"state": "failed", "label": None, "shown": "Failed"},
        "credential_correlation": {"state": "not_assessed", "label": None,
                                   "shown": "Not assessed"},
        "cms_plugin_sbom": {"state": "completed", "label": None, "shown": "Completed"},
        "absent": {"state": "not_assessed", "label": "Not in scan", "shown": "Not assessed"},
    }
    for k_, w_ in sorted(want_hb.items()):
        if hb_out.get(k_) != w_:
            bad.append("the header badge for %s gives %r, want %r" % (k_, hb_out.get(k_), w_))
    # A generic panel prints counts only where something was measured: "match
    # count = 0" over a chain nobody read reads as a clean vendor estate
    # (critique round 11, R11-SC-2).
    psc_want = {
        "vb_failed": False, "vb_not_followed": False, "vb_stored": False,
        "vb_unknown_outcome": False, "credential_correlation": False,
        "vb_partial_quiet": True, "vb_partial_matches": True,
        "vb_stored_with_vendor": True, "vb_answered": True, "vb_matches": True,
        "dependency_manifests": True, "cms_plugin_sbom": True,
    }
    psc_want["intelx_error"] = False
    psc_want["hudson_error"] = False
    psc_got = hb_out.get("__counts") or {}
    for k_, w_ in sorted(psc_want.items()):
        if psc_got.get(k_) != w_:
            bad.append("the panel's measurement gate for %s gives %r, want %r"
                       % (k_, psc_got.get(k_), w_))
    if ("<RelatedDomainsPanel r={r} />" not in page_tsx
            or "getRelatedDomainsPanel(r)" not in page_tsx):
        bad.append("the panel is not rendered from getRelatedDomainsPanel")
    more_ids = _re.search(r"<MoreCheckers r=\{r\} ids=\{\[([^\]]*)\]\}", page_tsx)
    if more_ids is None or "related_domains" in more_ids.group(1):
        bad.append("related_domains also shows as a generic checker card")
    # Every single-quoted string of 12 or more characters in the module's code,
    # tokenised left to right with the comments and the other string forms, so
    # a short literal's closing quote never opens another (round 6).
    code = "\n".join(l for l in mod_src.splitlines()
                     if not l.lstrip().startswith("import"))
    wording = [w for w in _re.findall(
        r"//[^\n]*|/\*.*?\*/|'((?:[^'\\\n]|\\.)*)'|\"(?:[^\"\\\n]|\\.)*\"|`(?:[^`\\]|\\.)*`",
        code, _re.S) if len(w) >= 12 and "\\" not in w]
    stale = [w[:40] for w in wording if w not in bundle]
    if len(wording) < 20 or stale:
        bad.append("the bundle lacks %d of %d sentences: %r" % (len(stale), len(wording),
                                                                stale[:2]))
    # The committed bundle is what a rebuild of the source produces, byte for
    # byte, so no sentence and no line of logic can be stale (critique round 6,
    # GS6-4 and CD6-3). The build is deterministic; the base path is the one the
    # deployed bundle needs.
    import tempfile as _tempfile
    fe_dir = os.path.join(SEC, "frontend")
    vite_js = os.path.join(fe_dir, "node_modules", "vite", "bin", "vite.js")
    node_v = shutil.which("node")
    if not (node_v and os.path.isfile(vite_js)):
        bad.append("cannot rebuild the dashboard to compare with the committed bundle "
                   "(node or frontend/node_modules missing)")
    else:
        out_dir = _tempfile.mkdtemp(prefix="rd_bundle_")
        try:
            r_v = subprocess.run([node_v, vite_js, "build", "--outDir", out_dir,
                                  "--emptyOutDir", "--logLevel", "error"],
                                 cwd=fe_dir, capture_output=True, text=True, timeout=300,
                                 env=dict(os.environ, SCANNER_BASE_PATH="/scanner"))
            if r_v.returncode != 0:
                bad.append("the dashboard rebuild failed: %s"
                           % (r_v.stderr or r_v.stdout)[-200:])
            else:
                for name in ("app.js", "app.css"):
                    with open(os.path.join(out_dir, name), "rb") as fh:
                        fresh = fh.read()
                    with open(os.path.join(SEC, "static", "dashboard", name), "rb") as fh:
                        if fh.read() != fresh:
                            bad.append("static/dashboard/%s is stale: rebuild it with "
                                       "SCANNER_BASE_PATH=/scanner" % name)
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)
    if bad:
        failures.append("discovery[dashboard_page]: " + "; ".join(bad))
    report(not bad, "dashboard_page_and_bundle", "%d sentences" % len(wording))

    node = shutil.which("node")
    if not node:
        failures.append("discovery[ts]: node is not on PATH, so the dashboard's "
                        "related-domains logic cannot be checked against Python")
        report(False, "dashboard_matches_the_pdf_card", "node missing")
    else:
        mod = os.path.join(SEC, "frontend", "src", "data", "relatedDomains.ts")
        cases = (list(built.values()) + [r for _, r, _ in RD_LEGACY]
                 + [v[1] for v in got.values()] + [rd_run, rd_to]
                 + [None, {}, {"status": "completed", "discovery": None},
                    {"status": "completed", "declared_count": None,
                     "discovery": {"ran": True, "candidate_count": 2}},
                    {"status": "unassessed", "declared_count": 0,
                     "discovery": {"ran": True, "candidate_count": 3}},
                    {"status": "completed", "declared_count": 0,
                     "discovery": {"ran": True}}])
        badge_of = {"critical": ("critical", "Critical"), "red": ("failed", "Below 60"),
                    "green": ("passed", "Passed"), "amber": ("warning", "Partly assessed")}

        def python_view(rd):
            rd_ = rd or {}
            state = ed.related_domains_state(rd)
            sink, reasons, fallbacks = [], [], []
            colour = _colour_spy(pc, sink)
            real_nac = pc.not_assessed_card

            def bcc(title, col, *a, **k):
                if title == pc._RD_TITLE:
                    fallbacks.append(k.get("fallback"))
                return colour(title, col, *a, **k)

            def nac(title, reason, S_):
                reasons.append(reason)
                return real_nac(title, reason, S_)
            with mock.patch.object(pc, "build_cat_card", bcc), \
                 mock.patch.object(pc, "not_assessed_card", nac):
                text = _rd_flow_text(pc.cat_related_domains({"related_domains": rd_}, S))
            flat = " ".join(text.split())
            # The card's own opening text: the Not assessed reason without the
            # shared "how related domains are handled" paragraph, or the
            # fallback sentence of the "none found" card.
            own_lead = None
            if state in ("not_run", "degraded", "confirmed_unassessed") and reasons:
                own_lead = reasons[-1]
                if own_lead.endswith(" " + pc._RD_HOW):
                    own_lead = own_lead[: -len(" " + pc._RD_HOW)]
            elif state == "none_found" and fallbacks:
                own_lead = fallbacks[-1]
            more = _re.search(r"and (\d+) more\.", text)
            notes = ([] if state == "not_run" else
                     pc._rd_notes(rd_, state in ("confirmed", "confirmed_unassessed")))
            if state == "confirmed_unassessed":
                badge = ["not_assessed", "Not assessed"]
            elif state == "confirmed":
                badge = list(badge_of.get((sink or ["?"])[-1], ("?", "?")))
                if badge[0] == "warning" and "discovery" not in rd_:
                    badge[1] = "Not verified"
            else:
                badge = None
            lead = None
            if state == "confirmed" and "discovery" in rd_:
                full = ed.related_domains_fully_assessed(rd)
                lead = ("The domains confirmed by the broker were assessed." if full else
                        "The domains confirmed by the broker were only partly assessed; "
                        "the notes below say what was not.")
                if _re.search(r"&nbsp;&nbsp;<b>[^<]+</b>:|and \d+ more\.", text):
                    # Only where the card lists candidates.
                    lead += (" Domains found on certificate records but not confirmed "
                             "are listed for confirmation and have not been assessed.")
            return {
                "state": state,
                "full": ed.related_domains_fully_assessed(rd),
                "notes": notes,
                # The notes, candidates and count as the card RENDERED them.
                "notes_rendered": all(" ".join(n.split()) in flat for n in notes),
                "badge": badge,
                "pending": _re.findall(r"&nbsp;&nbsp;<b>([^<]+)</b>:", text),
                "extra": int(more.group(1)) if more else 0,
                "lead": lead,
                "own_lead": own_lead,
                "legacy": "discovery" not in rd_,
                "submitted": str(rd_.get("submitted_count") or rd_.get("declared_count", 0)),
                "sources": (list((rd_.get("discovery") or {}).get("sources_ok") or [])
                            if state in ("none_found", "awaiting_confirmation") else None),
                "text": flat,
            }

        py = [python_view(rd) for rd in cases]
        harness = ("import { readFileSync } from 'node:fs'\n"
                   "import * as R from './relatedDomains.mts'\n"
                   "const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'))\n"
                   "const out = cases.map((rd) => {\n"
                   "  const m = R.relatedDomainsPanel(rd)\n"
                   "  return { state: R.relatedDomainsState(rd), full: R.relatedDomainsFullyAssessed(rd),\n"
                   "    lead: m.lead, notes: m.notes, badge: m.badge ? [m.badge.state, m.badge.label] : null,\n"
                   "    rows: m.rows.map((x) => [x.label, x.value]), pending: m.pending.map((c) => c.domain),\n"
                   "    extra: m.extra, sources: m.sources }\n"
                   "})\n"
                   "console.log(JSON.stringify(out))\n")
        detail, ok = "", False
        with tempfile.TemporaryDirectory() as td:
            cp = os.path.join(td, "cases.json")
            with io.open(cp, "w", encoding="utf-8") as fh:
                json.dump(cases, fh)
            shutil.copyfile(mod, os.path.join(td, "relatedDomains.mts"))
            mts = os.path.join(td, "rd_check.mts")
            with io.open(mts, "w", encoding="utf-8") as fh:
                fh.write(harness)
            try:
                run = subprocess.run([node, "--no-warnings", mts, cp], capture_output=True,
                                     text=True, timeout=60)
                line = (run.stdout.strip().splitlines() or [""])[-1]
                ts = json.loads(line) if line.startswith("[") else None
                if run.returncode != 0 or ts is None:
                    detail = "node failed: %s" % (run.stderr.strip()[-300:] or line)
                else:
                    diffs = []
                    for i, (p, t) in enumerate(zip(py, ts)):
                        for key in ("state", "full", "notes", "badge", "pending", "extra",
                                    "sources"):
                            if p[key] != t[key]:
                                diffs.append((i, key, p[key], t[key]))
                        if not p["notes_rendered"]:
                            diffs.append((i, "notes_rendered", p["notes"][:1], None))
                        # Rows: every label and value as the card prints them.
                        if p["state"] == "confirmed":
                            for label, value in t["rows"]:
                                if ("%s %s" % (label, value)).lower() not in p["text"].lower():
                                    diffs.append((i, "row", label, value))
                            if len(t["rows"]) != 4:
                                diffs.append((i, "rows", 4, len(t["rows"])))
                        elif p["state"] == "confirmed_unassessed":
                            if t["rows"] != [["submitted for assessment", p["submitted"]]]:
                                diffs.append((i, "rows", p["submitted"], t["rows"]))
                        elif t["rows"]:
                            diffs.append((i, "rows", [], t["rows"]))
                        # The lead: the card's own opening where the two share
                        # one, the card's candidate sentence for candidates
                        # awaiting confirmation, and the assessed or partly
                        # assessed wording, or the stored-result sentence,
                        # for confirmed domains.
                        lead = " ".join(t["lead"].split())
                        if p["state"] in ("not_run", "degraded", "none_found",
                                          "confirmed_unassessed"):
                            ok_lead = lead == " ".join((p["own_lead"] or "").split())
                        elif p["state"] == "awaiting_confirmation":
                            # Every sentence is the card's (its "NOT" is
                            # capitalised), and none of its key phrases is lost.
                            sents = [x for x in _re.split(r"(?<=\.)\s+", lead) if x]
                            need = ["none has been confirmed, so none has been assessed or scored"]
                            if p["pending"] or p["extra"]:
                                need += ["have not been assessed and do not affect the score",
                                         "not evidence that the wider estate is clean"]
                            ok_lead = (all(x.lower() in p["text"].lower() for x in sents)
                                       and all(n in lead.lower() for n in need))
                        elif p["legacy"]:
                            # The card's own sentence, from What This Means.
                            ok_lead = lead == pc._RD_LEGACY_CONFIRMED
                        else:
                            ok_lead = lead == p["lead"]
                        if not ok_lead:
                            diffs.append((i, "lead", p["lead"] or p["text"][:80], t["lead"][:80]))
                    ok = len(ts) == len(py) and not diffs
                    detail = "%d cases, %d disagree %s" % (len(ts), len(diffs), diffs[:3])
            except Exception as exc:
                detail = "node run raised %r" % exc
        if not ok:
            failures.append("discovery[ts]: dashboard vs Python and the PDF card: " + detail)
        report(ok, "dashboard_matches_the_pdf_card", detail[:60])

    # 12. Exclusion must still differ from an explicit neutral result on this
    # fixture. A mutation that skips an answered discovery category must be
    # caught, even though FC13-2 now also excludes genuinely absent raw checks.
    skipped = price({"status": "skipped", "score": 100, "declared_count": 0,
                     "scanned_count": 0, "critical_count": 0, "high_count": 0,
                     "dependants": [], "issues": []})
    ok = skipped > neutral
    if not ok:
        failures.append("discovery MUTATION is vacuous: status 'skipped' now prices "
                        "the same as neutral (%s vs %s)" % (skipped, neutral))
    report(ok, "MUTATION skipped still prices above neutral", "(%s > %s)" % (skipped, neutral))

    st = csc.RelatedDomainsChecker().check("acme.co.za", []).get("status")
    ok = st == "completed"
    if not ok:
        failures.append("discovery[checker]: empty confirmed list -> status %r, "
                        "must be 'completed'" % st)
    report(ok, "checker_empty_list_status", "-> %s" % st)


def _check_cdn_edge_detection(failures):
    """A content delivery network edge must be recognised from its ADDRESS, and
    an edge-only assessment must never claim full confidence.

    Detection walked the CNAME chain only. A domain fronted at its apex cannot
    carry a CNAME, so providers answer with address records directly and the
    walk finds nothing. Measured over 58 production scans: a provider was named
    0 times, and 14 scans resolved into a published edge range. boston.ac.za
    returned 97/1000 Low at 100 per cent completeness with no failed checkers,
    having assessed Cloudflare.

    THE TWO HALVES ARE ONE CHANGE. Detection alone is a DISCOUNT: the
    availability term adds 0.035 when no network is detected, so every scan has
    been carrying that penalty. Measured on the boston.ac.za fixture, detection
    alone moves P(interruption) 0.065 -> 0.030 and drops R20,376 from the
    modelled loss on that incident, while the scanner still cannot see the
    origin. The scenarios below therefore assert BOTH, and a change that ships
    detection without the confidence cap fails here.
    """
    import importlib
    cr = importlib.import_module("cdn_ranges")
    cc = importlib.import_module("checkers_core")

    EDGE = [("Cloudflare", "104.26.3.40"), ("Cloudflare", "172.67.71.95"),
            ("Akamai", "23.45.67.89"), ("Fastly", "151.101.1.1"),
            ("AWS CloudFront", "13.32.1.1")]
    for want, ip in EDGE:
        got = cr.edge_provider(ip)
        ok = got == want
        if not ok:
            failures.append("cdn_edge[range]: %s should resolve to %s, got %s"
                            % (ip, want, got))
        print("  [%s] cdn_edge:range %-16s -> %s" % ("PASS" if ok else "FAIL", ip, got))

    for ip in ("196.41.30.122", "8.8.8.8", "10.0.0.1", "not-an-ip"):
        got = cr.edge_provider(ip)
        ok = got is None
        if not ok:
            failures.append("cdn_edge[range]: %s must NOT be an edge, got %s" % (ip, got))
        print("  [%s] cdn_edge:not_edge %-14s -> %s" % ("PASS" if ok else "FAIL", ip, got))

    # Detection fires on an apex that answers with address records only.
    with mock.patch.object(cc, "DNS_AVAILABLE", True), \
         mock.patch.object(cc.dns_cache, "resolve",
                           lambda d, t: ["104.26.3.40"] if t == "A" else []), \
         mock.patch.object(cc.dns.resolver, "resolve",
                           side_effect=Exception("no CNAME at an apex")):
        res = cc.CloudCDNChecker().check("edge-fronted.test")
    ok = res.get("provider") == "Cloudflare" and res.get("detected_by") == "edge_range"
    if not ok:
        failures.append("cdn_edge[apex]: an apex answering with edge address records "
                        "must be detected; got provider=%s detected_by=%s"
                        % (res.get("provider"), res.get("detected_by")))
    print("  [%s] cdn_edge:apex_no_cname        provider=%s by=%s"
          % ("PASS" if ok else "FAIL", res.get("provider"), res.get("detected_by")))

    # Confidence cap. Same checker set, same completeness; the ONLY difference
    # is whether an origin was verified behind the detected edge.
    from scoring_analytics import RiskScorer
    def _conf(cdn_detected, verified, missing_ssl=False):
        cats = {
            "ssl": {"status": "completed", "grade": "A", "score": 95},
            "http_headers": {"status": "completed", "score": 90},
            "exposed_admin": {"status": "completed", "panels": []},
            "shodan_vulns": {"status": "completed", "critical_count": 0,
                             "high_count": 0, "medium_count": 0},
            "cloud_cdn": {"status": "completed", "cdn_detected": cdn_detected,
                          "provider": "Cloudflare" if cdn_detected else None},
            "origin_discovery": {"status": "completed",
                                 "verified": ["1.2.3.4"] if verified else []},
        }
        # Isolate the estate-confidence cap from missing-check qualification.
        # FC13-2 requires explicit completion rather than an absent-data default.
        for name in RiskScorer.WEIGHTS:
            if name not in RiskScorer.DERIVED_CATEGORIES:
                cats.setdefault(name, {"status": "completed"})
        if missing_ssl:
            cats.pop("ssl")
        RiskScorer().calculate(cats)
        sc = cats.get("_scan_completeness") or {}
        return sc.get("confidence_level"), sc.get("estate_confidence")

    CASES = [
        ("no_cdn",              False, False, "full",    "assessed"),
        ("cdn_origin_verified", True,  True,  "full",    "assessed"),
        ("cdn_edge_only",       True,  False, "partial", "origin_not_reached"),
    ]
    for label, det, ver, want_conf, want_estate in CASES:
        conf, estate = _conf(det, ver)
        ok = conf == want_conf and estate == want_estate
        if not ok:
            failures.append(
                "cdn_edge[confidence:%s]: got confidence=%s estate=%s, expected "
                "%s/%s. An edge-only assessment must not claim full confidence: "
                "every checker ran, but none of them measured the client."
                % (label, conf, estate, want_conf, want_estate))
        print("  [%s] cdn_edge:confidence %-20s %s / %s"
              % ("PASS" if ok else "FAIL", label, conf, estate))
    if _conf(True, False, missing_ssl=True) != ("low_confidence", "origin_not_reached"):
        failures.append("cdn_edge[missing]: edge qualification must not erase missing-check low confidence")


def _check_lookalike_ownership(failures):
    """A domain the insured controls must never be reported as hostile, and a
    hostile domain must never be able to exclude ITSELF.

    boston.ac.za, 2026-08-14: boston.co.za, the client's own website, was listed
    among the client's lookalike threats. The only exclusion was an exact string
    match against the scanned name.

    These scenarios are adversarial by construction. Two earlier attempts at
    this fix were broken open by review: the first trusted an unvalidated
    certificate and the candidate's own A record, either of which let a hostile
    domain delete itself from the report AND lower the client's risk score; the
    second was guarded only by a text search that `ssl._create_unverified_context()`
    walked straight past. The probe is therefore tested by BEHAVIOUR here, against
    a real self-signed TLS server on loopback.
    """
    import importlib
    ct = importlib.import_module("checkers_threats")
    chk = ct.FraudulentDomainChecker()
    INSURED = "boston.ac.za"

    # (label, candidate, insured-cert names, candidate-cert names, expect, why)
    SCEN = [
        ("own_estate_cert", "boston.co.za", set(),
         {"boston.ac.za", "boston.co.za", "bostonbc.co.za"}, True,
         "candidate's CA cert also covers the insured, brand-coherent"),
        ("insured_side_cert", "boston.ac.za", {"boston.ac.za", "boston.co.za"},
         set(), True,
         "the INSURED's own cert names the candidate: unforgeable direction"),
        ("unrelated_cert", "boston.org", set(), {"boston.org"}, False,
         "valid cert, but it does not cover the insured"),
        ("no_usable_cert", "b0ston.ac.za", set(), set(), False,
         "no chain-validated certificate: no ownership claim"),
        ("shared_multitenant_cert", "attacker.co.za", set(),
         {"boston.ac.za"} | {"tenant%d.host.com" % i for i in range(40)}, False,
         "names the insured but on a wide shared pool: not estate evidence"),
        ("wildcard_not_apex", "tenant.provider.co.za", set(),
         {"*.provider.co.za"}, False,
         "a wildcard covers one label, never the apex (RFC 6125)"),
    ]
    for label, cand, ins_names, cand_names, expect_owned, why in SCEN:
        insured = "provider.co.za" if label == "wildcard_not_apex" else INSURED
        with mock.patch.object(ct.FraudulentDomainChecker, "_validated_cert_names",
                               staticmethod(lambda d, timeout=4.0, _c=cand_names: set(_c))):
            why_txt, _names = chk._ownership_verdict({"domain": cand}, insured,
                                                     ins_names)
        got = why_txt is not None
        ok = got == expect_owned
        if not ok:
            failures.append(
                "lookalike_ownership[%s]: %s was %s, expected %s (%s)"
                % (label, cand, "excluded as owned" if got else "reported hostile",
                   "excluded" if expect_owned else "reported", why))
        print("  [%s] lookalike_own:%-24s owned=%-5s %s"
              % ("PASS" if ok else "FAIL", label, got, why[:40]))

    # BEHAVIOURAL PROBE TEST. The scenarios above stub the probe, so they cannot
    # see the probe itself accepting an attacker's certificate. A text guard was
    # tried and defeated by ssl._create_unverified_context(). This stands up a
    # real TLS listener on loopback presenting a self-signed certificate that
    # names the insured, and asserts the probe reads NOTHING from it.
    probe_ok, detail = _selfsigned_probe_rejected(ct, INSURED)
    if not probe_ok:
        failures.append(
            "lookalike_ownership[cert_probe]: _validated_cert_names accepted a "
            "SELF-SIGNED certificate naming the insured (%s). An attacker could "
            "serve one on a lookalike and have it excluded from the report while "
            "improving the client's score." % detail)
    print("  [%s] lookalike_own:cert_probe_behavioural  %s"
          % ("PASS" if probe_ok else "FAIL", detail))

    # END TO END, including the numbers that move the price. An earlier gate
    # asserted the wording only, and a mutation that re-counted owned assets
    # into resolved_count and the penalty passed it untouched.
    OWN, HOSTILE = "own.example.co.za", "h0stile.example.co.za"

    def _fake_resolve(self, d):
        return d in (OWN, HOSTILE)

    def _fake_perms(self, name, tld):
        return [(OWN, "tld-variant", 90), (HOSTILE, "typo", 88)]

    def _fake_enrich(self, entry):
        entry.update({"mail_capable": True, "serves_content": True,
                      "mx_hosts": ["mx.test"], "risk": "high",
                      "recommendation": "test"})
        return entry

    def _fake_cert(d, timeout=4.0):
        return {"example.co.za", OWN} if d == OWN else set()

    with mock.patch.object(ct.FraudulentDomainChecker, "_resolves", _fake_resolve), \
         mock.patch.object(ct.FraudulentDomainChecker, "_generate_permutations", _fake_perms), \
         mock.patch.object(ct.FraudulentDomainChecker, "_enrich", _fake_enrich), \
         mock.patch.object(ct.FraudulentDomainChecker, "_validated_cert_names",
                           staticmethod(_fake_cert)):
        res = ct.FraudulentDomainChecker().check("example.co.za")

    excluded_line = [i for i in (res.get("issues") or []) if "own assets" in i]
    blob = " ".join(res.get("issues") or []) + " " + \
           " ".join(res.get("mail_capable_domains") or []) + " " + \
           " ".join(d.get("domain", "") for d in res.get("fraudulent_domains") or [])
    leaked = OWN in blob.replace(" ".join(excluded_line), "")
    checks = {
        "status": res.get("status") == "completed",
        "excluded_1": res.get("own_assets_excluded") == 1,
        "no_leak": not leaked,
        "hostile_kept": HOSTILE in blob,
        # The commercial half: the client must not be counted or charged for a
        # domain it owns.
        "resolved_count_1": res.get("resolved_count") == 1,
        "score_92": res.get("score") == 92,
    }
    e2e_ok = all(checks.values())
    if not e2e_ok:
        failures.append(
            "lookalike_ownership[end_to_end]: %s. An owned asset must not appear "
            "in any derived list, must not be counted in resolved_count, and must "
            "not be charged in the score."
            % ", ".join("%s=%s" % (k, v) for k, v in checks.items() if not v))
    print("  [%s] lookalike_own:end_to_end             count=%s score=%s leaked=%s"
          % ("PASS" if e2e_ok else "FAIL", res.get("resolved_count"),
             res.get("score"), leaked))

    src = open(ct.__file__, encoding="utf-8").read()
    leaked_line = "CRITICAL: {len(resolved)} lookalike domains detected" in src
    if leaked_line:
        failures.append("lookalike_ownership[severity]: the unconditional "
                        "count-driven CRITICAL line is still emitted")
    print("  [%s] lookalike_own:count_severity_removed present=%s"
          % ("FAIL" if leaked_line else "PASS", leaked_line))


def _selfsigned_probe_rejected(ct, insured):
    """Serve a self-signed cert naming ``insured`` on loopback; probe must reject.

    Returns (ok, detail). Offline: nothing leaves the machine.
    """
    import datetime as _dt
    import socket as _sock
    import ssl as _ssl
    import tempfile
    import threading
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception as e:
        return False, "cryptography unavailable, cannot run the probe test (%s)" % e

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, insured)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(insured), x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))

    tmp = tempfile.mkdtemp()
    cpath, kpath = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    with open(cpath, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kpath, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))

    srv = _sock.socket(); srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cpath, kpath)

    def serve():
        try:
            c, _ = srv.accept()
            try:
                ctx.wrap_socket(c, server_side=True).close()
            except Exception:
                pass
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True); t.start()
    try:
        # Probe by name, but reach the loopback listener: patch the connector.
        real_conn = ct.socket.create_connection

        def fake_conn(host, target_port, timeout=None, *a, **kw):
            return real_conn(("127.0.0.1", port), timeout=timeout)

        with mock.patch.object(ct, "connect_public", fake_conn):
            names = ct.FraudulentDomainChecker._validated_cert_names(insured)
    except Exception as e:
        names = set()
        return True, "probe raised rather than trusting (%s)" % type(e).__name__
    finally:
        try:
            srv.close()
        except Exception:
            pass
        t.join(timeout=2)

    if names:
        return False, "read %d name(s) from a self-signed cert: %s" % (
            len(names), sorted(names)[:3])
    return True, "self-signed cert naming the insured yielded no names"


def _check_lookalike_posture(failures):
    import importlib
    F = importlib.import_module("checkers_threats").FraudulentDomainChecker

    # THE DOMAIN IS NEVER A LOOKALIKE OF ITSELF. Found live on
    # excellentmeat.co.za (2026-08-06): char-swap transposing two ADJACENT
    # IDENTICAL letters is a no-op — "exce(ll)ent" swaps to "excellent" — so the
    # generator emitted the scanned domain, it "resolved" (it is their real
    # domain), probed as mail-capable (their real mail server) and was published
    # as a HIGH-risk impersonator with advice to report it to its own registrar.
    # Every domain with a doubled letter was affected; phishield.com has none,
    # which is exactly why testing missed it. Domains below all contain doubles.
    c = F()
    for dom in ("excellentmeat.co.za", "coffee.com", "williams.co.za",
                "mattress.com", "aabb.com", "phishield.com"):
        name, tld = c._split_domain(dom)
        perms = c._generate_permutations(name, tld)
        hits = [p[0] for p in perms if p[0].lower().strip(".") == dom.lower().strip(".")]
        ok = not hits and len(perms) > 10      # and the generator still produces work
        if not ok:
            failures.append(
                f"lookalike_self[{dom}]: generated itself {len(hits)} time(s) "
                f"(perms={len(perms)}) — the scanned domain must never be reported as "
                "impersonating itself; it resolves, probes as mail-capable, and gets "
                "published as HIGH risk with a recommendation to report the client to "
                "their own registrar")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_self:{dom:<22} "
              f"perms={len(perms)} self={len(hits)}")

    # COVERAGE: a cap must never delete a whole ATTACK CLASS. The old
    # `permutations[:60]` truncated a list built technique-by-technique, so on
    # phishield.com it probed 0 of 16 tld-variants, 0 of 8 dot-insertions, 0 of 8
    # hyphen-insertions and 0 of 6 IDN homoglyphs — and missed three live
    # lookalikes (phishield.io, phi-shield.com, phish.ield.com). It also
    # reported "115 permutations tested" while testing 60.
    import collections as _collections
    _probed = []

    def _fake_resolves(self, d):
        _probed.append(d)
        return False

    with mock.patch.object(F, "_resolves", _fake_resolves):
        _out = F().check("phishield.com")
    _c = F()
    _n, _t = _c._split_domain("phishield.com")
    _perms = _c._generate_permutations(_n, _t)
    _tech = {p[0]: p[1] for p in _perms}
    _cov = _collections.Counter(_tech.get(d, "?") for d in _probed)
    _all = _collections.Counter(p[1] for p in _perms)
    _missing = sorted(t for t in _all if _cov.get(t, 0) == 0)
    ok_cov = not _missing
    if not ok_cov:
        failures.append(
            f"lookalike_coverage: technique(s) never probed at all: {_missing} — a "
            "probe cap must sample across techniques, not amputate whole attack "
            "classes (tld-variant carries .co.za / .co / .io)")
    print(f"  [{'PASS' if ok_cov else 'FAIL'}] lookalike_coverage:all_techniques "
          f"probed={len(_probed)}/{len(_perms)} unprobed_classes={len(_missing)}")

    ok_honest = _out.get("total_permutations") == len(_probed)
    if not ok_honest:
        failures.append(
            f"lookalike_coverage[reporting]: reports total_permutations="
            f"{_out.get('total_permutations')} but probed {len(_probed)} — the panel "
            "must state what was actually tested, not what was generated")
    print(f"  [{'PASS' if ok_honest else 'FAIL'}] lookalike_coverage:honest_count  "
          f"reported={_out.get('total_permutations')} probed={len(_probed)}")

    for label, raw, want_usable, want_null in MX_SCENARIOS:
        usable, null = F._usable_mx(raw)
        ok = (len(usable) == want_usable) and (null == want_null)
        if not ok:
            failures.append(
                f"lookalike_mx[{label}]: usable={len(usable)} null={null}, expected "
                f"{want_usable}/{want_null} — RFC 7505 '0 .' means the domain accepts "
                "NO mail; counting it as an MX host labels a harmless parked domain "
                "a phishing risk")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_mx:{label:<12} "
              f"usable={len(usable)} null_mx={null}")

    # A SIMILAR NAME IS NOT IMPERSONATION. phishield.io resolves, is
    # mail-capable, and is a completely unrelated company: "PHIShield —
    # HIPAA-Safe X12 De-Identification" (PHI = Protected Health Information).
    # The first cut told the reader to report it to its registrar. A live,
    # branded site must therefore be framed verify-first, and the page's own
    # title quoted so a human settles it in one second.
    live = {"mail_capable": True, "serves_content": True, "similarity": 85,
            "page_title": "PHIShield - HIPAA-Safe X12 De-Identification"}
    _risk, rec = F._verdict(dict(live))
    quotes_title = "PHIShield" in rec
    verify_first = rec.lower().find("verify") < rec.lower().find("report")         if "report" in rec.lower() else True
    ok_live = quotes_title and verify_first
    if not ok_live:
        failures.append(
            f"lookalike_identity: recommendation for a live branded lookalike does "
            f"not quote its title ({quotes_title}) or leads with 'report' rather "
            f"than 'verify' ({verify_first}) — that tells a client to file an abuse "
            "complaint against what may be a legitimate unrelated business")
    print(f"  [{'PASS' if ok_live else 'FAIL'}] lookalike_identity:verify_first   "
          f"quotes_title={quotes_title} verify_before_report={verify_first}")

    for label, entry, want in VERDICT_SCENARIOS:
        risk, rec = F._verdict(dict(entry))
        ok = (risk == want) and bool(rec)
        if not ok:
            failures.append(
                f"lookalike_verdict[{label}]: risk={risk!r} expected {want!r} "
                f"(recommendation present={bool(rec)}) — a mail-capable near-typo must "
                "outrank a parked one, or the panel ranks by resemblance instead of "
                "by what the domain can actually do")
        print(f"  [{'PASS' if ok else 'FAIL'}] lookalike_verdict:{label[:30]:<32} {risk}")


# (j) TABLE HEADERS MUST NOT BE ORPHANED. Reported from a real broker report:
# the Regulatory Flag Audit header row sat alone at the foot of page 5 with its
# body on page 6. ReportLab will happily split a table after row 0 unless
# repeatRows is set; with it, a split that would leave only the repeat-rows is
# refused outright, so the table moves whole to the next page AND the header
# repeats on continuation pages. No table in the report set repeatRows.
#
# This asserts the LIBRARY behaviour we depend on (filler=39 reproduces the
# split exactly on A4 with these margins) plus the fact that every header table
# in the report actually sets it — the second half is what stops a new table
# being added without it.
def _check_table_headers(failures):
    import io, re
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from pypdf import PdfReader

    SS = getSampleStyleSheet()
    ROWS = [["Flag", "BrokerInput", "AutoDetected", "Evidence"]] + \
           [[f"rowmarker{i}", "No", "No", "evidence"] for i in range(1, 8)]

    def orphans(repeat):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
        story = [Paragraph(f"Filler {i} " * 8, SS["BodyText"]) for i in range(39)]
        t = Table(ROWS, colWidths=[45 * mm, 25 * mm, 28 * mm, 50 * mm],
                  **({"repeatRows": 1} if repeat else {}))
        t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
        story.append(t)
        doc.build(story)
        buf.seek(0)
        pages = [p.extract_text() or "" for p in PdfReader(buf).pages]
        h = next((i for i, p in enumerate(pages) if "AutoDetected" in p), None)
        r = next((i for i, p in enumerate(pages) if "rowmarker1" in p), None)
        return h is not None and r is not None and h != r

    without, with_ = orphans(False), orphans(True)
    ok = without and not with_
    if not ok:
        failures.append(
            f"table_header[reportlab_behaviour]: orphan without repeatRows={without}, "
            f"with={with_} — the fix depends on ReportLab refusing a split that "
            "leaves only the header; if this stops reproducing, the guard below is "
            "no longer sufficient")
    print(f"  [{'PASS' if ok else 'FAIL'}] table_header:repeatRows_prevents_orphan  "
          f"without={without} with={with_}")

    # Every table styled with a bold row-0 header must set repeatRows.
    for fn in ("pdf_cards.py", "pdf_report.py"):
        src = open(os.path.join(SEC, fn), encoding="utf-8").read()
        headers = len(re.findall(
            r'"FONTNAME"\s*,\s*\(0,\s*0\)\s*,\s*\(-1,\s*0\)\s*,\s*"Helvetica-Bold"', src))
        repeats = len(re.findall(r"repeatRows\s*=\s*1", src))
        ok2 = repeats >= headers
        if not ok2:
            failures.append(
                f"table_header[{fn}]: {headers} table(s) have a bold row-0 header but "
                f"only {repeats} set repeatRows=1 — a header table without it can be "
                "split after row 0, stranding the header at a page foot")
        print(f"  [{'PASS' if ok2 else 'FAIL'}] table_header:{fn:<16} "
              f"headers={headers} repeatRows={repeats}")


# (k) A BLOCKED CHECKER MUST NOT SCORE AS A CLEAN ONE. On the 2026-08-06
# phishield.com scan a WAF answered 403 to 20 of 20 probes, and six checkers
# were recorded as affected — yet info_disclosure and tech_stack both reported
# status="completed" with a PERFECT 100/100. A block page carries none of the
# signals they read (no Server / X-Powered-By, no EOL version string, no
# retrievable path), so "nothing found" was indistinguishable from a tidy site.
#
# The subtle half is the scoring side. Dropping a blocked checker's score is NOT
# enough: the per-category fallbacks are not neutral — tech_stack and
# info_disclosure both default to score=100, i.e. a perfect result — so a
# score-less blocked checker banks the exact clean sweep being removed. Only
# http_headers defaults to a neutral 50, which is why the earlier fix there
# appeared sufficient. "unreachable" therefore has to be an EXCLUDING status.
class _Resp:
    def __init__(self, code, text="", headers=None):
        self.status_code = code
        self.text = text
        self.headers = headers or {}


def _check_blocked_not_clean(failures):
    import copy, importlib
    ct_mod = importlib.import_module("checkers_threats")
    sa = importlib.import_module("scoring_analytics")

    # --- tech_stack -------------------------------------------------------
    for label, resp, want_status, want_scored in (
        ("waf 403 block page", _Resp(403, "<html>Forbidden</html>"), "unreachable", False),
        ("healthy clean 200",  _Resp(200, "<html>hi</html>"),        "completed",   True),
        ("healthy leaky 200",  _Resp(200, "<html>x</html>",
                                     {"X-Powered-By": "PHP/5.6"}),   "completed",   True),
    ):
        with mock.patch.object(ct_mod, "HTTP") as H:
            H.get.return_value = resp
            out = ct_mod.TechStackChecker().check("example.com")
        got, scored = out.get("status"), ("score" in out)
        ok = (got == want_status) and (scored == want_scored)
        if not ok:
            failures.append(
                f"blocked_clean[tech_stack/{label}]: status={got!r} scored={scored}, "
                f"expected {want_status!r}/{want_scored} — a block page has no Server "
                "header and no EOL string, so parsing it yields a perfect score for a "
                "stack that was never seen")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:tech_stack/{label:<20} "
              f"{got} scored={scored}")

    # --- info_disclosure --------------------------------------------------
    def run_id(code):
        with mock.patch("http_client.HTTP") as H, mock.patch.object(ct_mod, "HTTP") as H2:
            H.head.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 50)
            H2.get.return_value = _Resp(code, "x" * 50)
            H2.stop_probing.return_value = False
            return ct_mod.InformationDisclosureChecker().check("example.com")

    for label, code, want_status, want_scored in (
        ("every probe 403 (WAF)",   403, "unreachable", False),
        ("every probe 404 (clean)", 404, "completed",   True),
    ):
        out = run_id(code)
        got, scored = out.get("status"), ("score" in out)
        ok = (got == want_status) and (scored == want_scored)
        if not ok:
            failures.append(
                f"blocked_clean[info_disclosure/{label}]: status={got!r} "
                f"scored={scored}, expected {want_status!r}/{want_scored} — refusing "
                "every probe is not the same as finding nothing exposed")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:info_disc/{label:<22} "
              f"{got} scored={scored}")

    # --- exposed_admin / vpn_remote / payment_security --------------------
    # Same shape: each returns "nothing found" when a WAF refuses every probe.
    # exposed_admin is the worst on screen (it renders a green "Passed"), and
    # vpn_remote is the worst in words (it prints "No VPN/remote access gateway
    # detected", an assertion of absence from a probe that never landed).
    cc = importlib.import_module("checkers_core")
    cn_mod = importlib.import_module("checkers_network")

    # Faithful control-probe answer for the uniform-code mocks below: a site that
    # returns `code` to everything returns it to the site root as well.
    _root_answers = lambda code: code not in {401, 403, 406, 409, 418, 429, 451, 503}

    def _admin(code):
        with mock.patch("http_client.HTTP") as H:
            H.discover.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 500)
            H.stop_probing.return_value = False
            # This mock refuses EVERY url, so the site root is refused too.
            # Leaving origin_answering as a bare MagicMock would return a truthy
            # sentinel and quietly convert this blind case into a clean one.
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return cc.ExposedAdminChecker().check("example.com")

    def _simple(mod, cls, code):
        # HTTP-response scenarios do not probe a real RDP port.
        with mock.patch.object(mod, "HTTP") as H, \
             mock.patch.object(cn_mod, "connect_public", side_effect=ConnectionRefusedError("synthetic closed port")):
            H.get.return_value = _Resp(code, "nope")
            H.stop_probing.return_value = False
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return getattr(mod, cls)().check("example.com")

    trio = [
        ("exposed_admin",    lambda c: _admin(c)),
        ("vpn_remote",       lambda c: _simple(cn_mod, "VPNRemoteAccessChecker", c)),
        ("payment_security", lambda c: _simple(ct_mod, "PaymentSecurityChecker", c)),
    ]
    for name, run in trio:
        blocked, clean = run(403), run(404)
        ok = (blocked.get("status") == "unreachable"
              and clean.get("status") == "completed")
        if not ok:
            failures.append(
                f"blocked_clean[{name}]: blocked={blocked.get('status')!r} "
                f"clean={clean.get('status')!r} — a blanket WAF deny must read as "
                "unreachable, while an origin answering 404 must still read as a "
                "genuine clean result")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:{name:<18} "
              f"blocked={blocked.get('status')} clean={clean.get('status')}")

    # vpn_remote must stop ASSERTING absence when it was blocked
    v_blocked = _simple(cn_mod, "VPNRemoteAccessChecker", 403)
    asserts = any("No VPN" in str(i) for i in v_blocked.get("issues", []))
    if asserts:
        failures.append(
            "blocked_clean[vpn_remote/absence]: still prints 'No VPN/remote access "
            "gateway detected' after every probe was refused — that reads to a broker "
            "as 'they have no VPN', which a blanket 403 does not support")
    print(f"  [{'PASS' if not asserts else 'FAIL'}] blocked_clean:vpn_absence_claim     "
          f"asserts={asserts}")

    # a REAL exposure must survive the guard (no suppression of true positives)
    with mock.patch("http_client.HTTP") as H:
        H.discover.side_effect = lambda url, **kw: _Resp(200) if "/admin" in url else _Resp(403)
        H.get.return_value = _Resp(200, "admin login panel " * 40)
        H.stop_probing.return_value = False
        real = cc.ExposedAdminChecker().check("example.com")
    kept = real.get("status") == "completed" and (real.get("high_count") or 0) > 0
    if not kept:
        failures.append(
            f"blocked_clean[exposed_admin/true_positive]: status={real.get('status')!r} "
            f"high_count={real.get('high_count')} — a genuine exposure found amid "
            "blocking must still be reported, or the guard hides real findings")
    print(f"  [{'PASS' if kept else 'FAIL'}] blocked_clean:true_positive_kept    "
          f"high_count={real.get('high_count')}")

    # --- round 2: website_security + dependency_manifest -------------------
    # Found by the smoke harness once it patched provider clients, not just
    # HTTP. WebsiteSecurityChecker is the sharpest of the two: EVERY default in
    # its result is optimistic (cookies secure/httponly/samesite all True,
    # mixed_content False), so a block page yields "no cookie problems, no mixed
    # content, no CMS exposure" and a top score for a site never inspected.
    cs_m = importlib.import_module("checkers_supply_chain")

    def _ws(code):
        with mock.patch.object(ct_mod, "HTTP") as H:
            H.get.return_value = _Resp(code, "<html>x</html>")
            H.stop_probing.return_value = False
            return ct_mod.WebsiteSecurityChecker().check("example.com")

    def _dm(code):
        with mock.patch("http_client.HTTP") as H:
            H.head.return_value = _Resp(code)
            H.get.return_value = _Resp(code, "x" * 50)
            H.stop_probing.return_value = False
            H.origin_answering.side_effect = lambda d, **k: _root_answers(code)
            return cs_m.DependencyManifestChecker().check("example.com")

    for label, fn in (("website_security", _ws), ("dependency_manifest", _dm)):
        blocked, clean = fn(403), fn(404 if label == "dependency_manifest" else 200)
        ok = (blocked.get("status") == "unreachable"
              and "score" not in blocked
              and clean.get("status") == "completed")
        if not ok:
            failures.append(
                f"blocked_clean[{label}]: blocked={blocked.get('status')!r} "
                f"scored={'score' in blocked} clean={clean.get('status')!r} — a "
                "checker whose defaults are all optimistic must not score a block "
                "page as a well-configured site")
        print(f"  [{'PASS' if ok else 'FAIL'}] blocked_clean:{label:<20} "
              f"blocked={blocked.get('status')} clean={clean.get('status')}")

    # --- round 3: DENIED IS NOT BLIND --------------------------------------
    # The overcorrection. Rounds 1-2 taught four path-enumeration checkers to
    # report "unreachable" when every probe came back 403. But every path they
    # request is one a hardened server SHOULD refuse (/.env, /admin,
    # /remote/login, /package.json), so "all 403" is ALSO the signature of
    # correct configuration — and the two were indistinguishable.
    #
    # Live case, excellentmeat.co.za 2026-08-06: apex 19/19 = 200, exposed_admin
    # collected 15 honest 404s, and all 8 sensitive-file probes returned 403.
    # The site was answering us the whole time. We reported info_disclosure as
    # "unreachable — refused by a WAF/CDN", which then fed refusal_blinded_checkers
    # and made the WAF card announce "active blocking observed" on a site with no
    # WAF at all. Good hardening was rendered as a coverage gap AND a phantom WAF.
    #
    # The control is the site root: a page nobody has reason to deny. This must
    # cut BOTH ways, so each checker is run three times — the middle row is the
    # regression this round fixes, and the last row is the round-1/2 behaviour
    # that must survive it.
    def _urlaware(pc, rc):
        """Fake HTTP where the site ROOT answers differently from probed paths."""
        is_root = lambda u: u.rstrip("/").count("/") == 2
        H = mock.MagicMock()
        H.head.side_effect     = lambda url, **k: _Resp(rc if is_root(url) else pc)
        H.discover.side_effect = lambda url, **k: _Resp(rc if is_root(url) else pc)
        H.get.side_effect      = lambda url, **k: (_Resp(rc, "<html>Home</html>")
                                                   if is_root(url) else _Resp(pc, "x" * 80))
        H.stop_probing.return_value = False
        H.hard_blocked.return_value = False
        H.REFUSAL_CODES = frozenset({401, 403, 406, 409, 418, 429, 451, 503})
        H.origin_answering.side_effect = lambda d, **k: rc not in H.REFUSAL_CODES
        return H

    denied_trio = [
        ("info_disclosure", ct_mod, "InformationDisclosureChecker"),
        ("exposed_admin",   cc,     "ExposedAdminChecker"),
        ("vpn_remote",      cn_mod, "VPNRemoteAccessChecker"),
        ("dep_manifest",    cs_m,   "DependencyManifestChecker"),
    ]
    for name, mod, cls in denied_trio:
        got = {}
        for row, pc, rc in (("ordinary", 404, 200),
                            ("denied",   403, 200),
                            ("walled",   403, 403)):
            H = _urlaware(pc, rc)
            with mock.patch("http_client.HTTP", H), mock.patch.object(mod, "HTTP", H, create=True), \
                 mock.patch.object(cn_mod, "connect_public", side_effect=ConnectionRefusedError("synthetic closed port")):
                got[row] = getattr(mod, cls)().check("example.com").get("status")
        ok = (got["ordinary"] == "completed"      # plain clean site
              and got["denied"] == "completed"    # hardened: refusals ANSWER the question
              and got["walled"] == "unreachable")  # blind: still fails closed
        if not ok:
            failures.append(
                f"denied_not_blind[{name}]: ordinary={got['ordinary']!r} "
                f"denied={got['denied']!r} walled={got['walled']!r} — a server that "
                "refuses sensitive paths while serving its home page has ANSWERED "
                "this checker's question (nothing is publicly reachable) and must "
                "score as clean; only a root that is refused too means we were blind")
        print(f"  [{'PASS' if ok else 'FAIL'}] denied_not_blind:{name:<16} "
              f"ordinary={got['ordinary']} denied={got['denied']} walled={got['walled']}")

    # --- round 4: a failed probe is not a refusal; 503 is not a control -----
    # Two defects in round 3, both found on live traffic (excellentmeat.co.za
    # scan f0313b6a, 4th scan of that domain in one day):
    #
    #  (a) the control probe TIMED OUT under our own scan load, and returning
    #      None for that meant "walled off" -- re-creating the exact false
    #      blindness the control was added to remove, on a scan where the same
    #      host answered 13x200, 25x404 and a 301.
    #  (b) the apex went blocked=True kind=waf_rate_limited on 7x503, so the
    #      WAF card announced "protective filtering present". 503 is what a
    #      server returns when its worker pool is exhausted, frequently because
    #      of us. 429 is a policy refusing us; 503 is a symptom we caused.
    hc = importlib.import_module("http_client")

    def _apex(code, n_bad, n_ok=13, total_dom="x.co"):
        t = hc.WAFTracker()
        for _ in range(n_bad):
            t.record(total_dom, code)
        for _ in range(n_ok):
            t.record(total_dom, 200)
        return t

    for label, code, want_kind, want_control in (
        ("429 policy throttle", 429, "waf_rate_limited",  True),
        ("503 capacity",        503, "origin_overloaded", False),
    ):
        st = _apex(code, 7).status("x.co")
        kind = st.get("kind")
        deliberate = bool(st.get("blocked")) and kind != "origin_overloaded"
        ok = (kind == want_kind) and (deliberate == want_control)
        if not ok:
            failures.append(
                f"rate_limit_kind[{label}]: kind={kind!r} counts_as_control={deliberate}, "
                f"expected {want_kind!r}/{want_control} — 503 is capacity exhaustion, "
                "not evidence of a security control, and must not put 'protective "
                "filtering present' on the WAF card")
        print(f"  [{'PASS' if ok else 'FAIL'}] rate_limit_kind:{label:<21} "
              f"kind={kind} control={deliberate}")

    # A control probe that got NO RESPONSE must consult the rest of the scan.
    for label, apex_code, want in (
        ("apex answered 200s", 200, True),
        ("apex all refused",   403, None),
    ):
        t = hc.WAFTracker()
        for _ in range(20):
            t.record("y.co", apex_code)
        c = hc.HttpClient(waf_tracker=t)
        with mock.patch.object(c, "get", return_value=None):
            got = c.origin_answering("y.co")
        ok = got is want
        if not ok:
            failures.append(
                f"control_fallback[{label}]: origin_answering={got!r} expected {want!r} "
                "— a timed-out control probe is not a refusal; when the apex tracker "
                "already shows the origin answering, the clean result is still earned")
        print(f"  [{'PASS' if ok else 'FAIL'}] control_fallback:{label:<19} {got}")

    # ...and the phantom WAF that the false blindness produced. With no checker
    # left blinded and an apex that never blocked, nothing may claim blocking.
    _wafc = {"detected": False, "waf_name": None}
    _cats = {"waf": _wafc,
             "info_disclosure": {"status": "completed",
                                 "probe_status_codes": {"403": 8}},
             "exposed_admin": {"status": "completed",
                               "probe_status_codes": {"200": 1, "403": 8, "404": 15}}}
    _blinded = sorted(
        n for n, c in _cats.items()
        if isinstance(c, dict) and c.get("status") == "unreachable")
    phantom = bool(_blinded)
    if phantom:
        failures.append(
            "denied_not_blind[waf_card]: a scan whose checkers all completed still "
            f"reports blinded checkers {_blinded} — the WAF card would announce "
            "'active blocking observed' on a site with no WAF")
    print(f"  [{'PASS' if not phantom else 'FAIL'}] denied_not_blind:waf_card_quiet  "
          f"blinded={_blinded}")

    # --- the WAF row must not claim ABSENCE while blocking is observed ------
    # The report said "No WAF detected" in red, charged RSI +0.04 and BI +0.015,
    # and advised buying a WAF — on the same page as "20 of 20 probes returned
    # 403, active blocking pattern". We cannot claim a WAF either (a 403 wall may
    # be a bot-manager, a CDN rule or plain auth), so the correct position is
    # neutral: no penalty, and no detected-WAF credit.
    for label, wafcat, want_penalty in (
        ("no waf, no blocking",      {"detected": False}, True),
        ("blocking observed",        {"detected": False, "blocking_observed": True}, False),
        ("vendor detected",          {"detected": True, "waf_name": "Cloudflare"}, False),
    ):
        cats = {"waf": wafcat,
                "breaches": {"status": "completed", "breach_count": 0, "issues": []},
                "credential_risk": {"risk_level": "LOW"}}
        rsi = sa.RansomwareIndex().calculate(cats, industry="technology")
        charged = any("No WAF detected" in f.get("factor", "")
                      for f in rsi.get("contributing_factors", []))
        ok = charged == want_penalty
        if not ok:
            failures.append(
                f"waf_row[{label}]: RSI 'No WAF detected' charged={charged}, expected "
                f"{want_penalty} — penalising absence while the scan reports being "
                "blocked contradicts the evidence on the same page")
        print(f"  [{'PASS' if ok else 'FAIL'}] waf_row:{label:<24} penalty={charged}")

    # --- ...and every RENDERER must agree with the scorer -------------------
    # The scorer learned the neutral position above; no renderer did. The PDF's
    # plain-language summary, the WAF category card, the RSI recommendation list
    # and the dashboard panel all read `detected` alone, so phishield.com --
    # apex 20/20 = 403, every checker refused on every probe -- still printed
    # "No web application firewall: the website has no protective filter,
    # leaving it directly exposed to automated attacks and traffic floods."
    # That is the worst sentence we can put in front of a client: confidently
    # wrong, with the contradicting evidence on the same page.
    import json
    ph = importlib.import_module("pdf_helpers")
    pr = importlib.import_module("pdf_report")

    for label, wafcat, want_state in (
        ("vendor detected",     {"detected": True, "waf_name": "Cloudflare"}, "protected"),
        ("blocking observed",   {"detected": False, "blocking_observed": True}, "unconfirmed"),
        ("nothing at all",      {"detected": False}, "absent"),
    ):
        got = ph.waf_posture({"waf": wafcat})["state"]
        ok = got == want_state
        if not ok:
            failures.append(
                f"waf_render[posture/{label}]: state={got!r} expected {want_state!r} — "
                "'detected' means a VENDOR was fingerprinted, not that protection "
                "exists; absence may only be claimed when nothing refused us either")
        print(f"  [{'PASS' if ok else 'FAIL'}] waf_render:posture/{label:<18} {got}")

    # The plain-language summary is the exact card in the screenshot.
    # _assessment_top_findings feeds the "What This Means for the Organisation"
    # slide -- the exact card that shipped the wrong sentence.
    for label, wafcat, want_claim in (
        ("blocking observed", {"detected": False, "blocking_observed": True}, False),
        ("nothing at all",    {"detected": False}, True),
    ):
        cats = {"waf": wafcat}
        out = pr._assessment_top_findings({"categories": cats})
        txt = json.dumps(out, default=str)
        claims = "No web application firewall" in txt
        ok = claims == want_claim
        if not ok:
            failures.append(
                f"waf_render[plain_language/{label}]: claims-no-WAF={claims}, expected "
                f"{want_claim} — a site that refused every probe must not be told it "
                "has 'no protective filter, leaving it directly exposed'")
        print(f"  [{'PASS' if ok else 'FAIL'}] waf_render:plain/{label:<20} "
              f"claims_absent={claims}")

    # ...and we must not advise buying a control the site may already run.
    for label, wafcat, want_rec in (
        ("blocking observed", {"detected": False, "blocking_observed": True}, False),
        ("nothing at all",    {"detected": False}, True),
    ):
        cats = {"waf": wafcat,
                "breaches": {"status": "completed", "breach_count": 0, "issues": []},
                "credential_risk": {"risk_level": "LOW"}}
        rsi = sa.RansomwareIndex().calculate(cats, industry="technology")
        fin = {"total": {"min": 0, "most_likely": 0, "max": 0}}
        sim = sa.RemediationSimulator().calculate(cats, rsi, fin, 10_000_000,
                                                  industry="technology")
        recs = json.dumps(sim.get("steps", []), default=str)
        advised = "Web Application Firewall" in recs
        ok = advised == want_rec
        if not ok:
            failures.append(
                f"waf_render[recommendation/{label}]: advises-deploy-WAF={advised}, "
                f"expected {want_rec} — recommending a WAF to a site that blocked "
                "every probe is advice the same report contradicts")
        print(f"  [{'PASS' if ok else 'FAIL'}] waf_render:rec/{label:<22} advised={advised}")

    # --- scoring: unreachable must EXCLUDE, not fall back to a 100 default --
    ok_excl = "unreachable" in sa.RiskScorer._FAILED_STATUSES
    if not ok_excl:
        failures.append(
            "blocked_clean[scoring]: 'unreachable' is not in _FAILED_STATUSES — "
            "tech_stack and info_disclosure default to score=100, so a blocked "
            "checker without an explicit score is scored as PERFECT")
    print(f"  [{'PASS' if ok_excl else 'FAIL'}] blocked_clean:unreachable_excludes    {ok_excl}")

    base = {
        "ssl": {"status": "completed", "score": 90},
        "email_security": {"status": "completed", "score": 8},
        "breaches": {"status": "completed", "breach_count": 0, "issues": []},
        "tech_stack": {"status": "completed", "score": 100, "eol_count": 0},
        "info_disclosure": {"status": "completed", "score": 100, "exposed_paths": []},
    }

    def score(c):
        out = sa.RiskScorer().calculate(c)
        return out[0] if isinstance(out, tuple) else out

    blocked = copy.deepcopy(base)
    for k in ("tech_stack", "info_disclosure"):
        blocked[k] = {"status": "unreachable", "unreachable_reason": "WAF refused all probes"}
    clean_score, blocked_score = score(copy.deepcopy(base)), score(blocked)
    ok_diff = clean_score != blocked_score
    if not ok_diff:
        failures.append(
            f"blocked_clean[composite]: blocked scan scored {blocked_score}, identical "
            f"to a genuinely clean {clean_score} — a scan that saw nothing must not "
            "score the same as one that looked and found nothing")
    print(f"  [{'PASS' if ok_diff else 'FAIL'}] blocked_clean:composite_differs      "
          f"clean={clean_score} blocked={blocked_score}")


# (l) THE DASHBOARD MUST NOT LINK OUT OF ITS OWN BASE PATH. The scanner is
# mounted under /scanner on a shared host whose ROOT is the unrelated Command
# Centre, so a bare absolute href leaves the product entirely. "Re-run
# Assessment" carried href="/" and sent users to the Command Centre — in a file
# that already imported withBase and used it correctly one line above. A static
# check because the failure only shows on the sub-path deployment, never in a
# root-mounted dev build.
import re as _re


# app captures the configured key at import; an environment-only fixture
# added later cannot configure the already imported endpoint.
@mock.patch("app.DEHASHED_API_KEY", "gate-synthetic-key")
def _check_balance_not_metered(failures):
    """The credit indicator must not BE the biggest credit consumer.

    DeHashed publishes no free balance endpoint, so /api/dehashed/balance ran a
    real /v2/search — and the scan form calls it on every page load. With several
    testers refreshing it quietly outspent the scans themselves, and because it
    used raw requests instead of the provider seam the spend never reached the
    usage ledger (ledger ~17 vs 200+ actually billed over the same period).
    """
    import importlib, time
    os.environ["DEHASHED_API_KEY"] = os.environ.get("DEHASHED_API_KEY") or "x"
    os.environ.setdefault("SCANNER_ALLOW_SQLITE", "1")
    A = importlib.import_module("app")
    ct_m = importlib.import_module("checkers_threats")

    calls = {"n": 0}

    class _Bal:
        status_code = 200
        def json(self):
            return {"balance": 231, "entries": [], "total": 0}

    def _post(*a, **kw):
        calls["n"] += 1
        return _Bal()

    # REDIRECT THE DURABLE FILES TO A TEMP DIR FIRST.
    # This check calls the REAL record_dehashed_balance with synthetic values
    # (309, 228, 231), which wrote them into scans/_dehashed_balance.json AND
    # appended them to _dehashed_balance_history.jsonl -- the append-only ledger
    # built specifically to answer "which call spent what". Every gate run was
    # injecting fake balances with fake deltas into the one forensic record we
    # rely on, and the history file is never cleaned. The sibling check below
    # already redirects properly; this one did not.
    import tempfile as _tf3
    _tmpd = _tf3.mkdtemp(prefix="gate_bal_")
    _orig_bf, _orig_hf = ct_m._BALANCE_FILE, ct_m._BALANCE_HISTORY_FILE
    _orig_pf = getattr(ct_m, "_PROBE_FILE", None)
    ct_m._BALANCE_FILE = os.path.join(_tmpd, "b.json")
    ct_m._BALANCE_HISTORY_FILE = os.path.join(_tmpd, "h.jsonl")
    if _orig_pf is not None:
        ct_m._PROBE_FILE = os.path.join(_tmpd, "p.json")

    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    with mock.patch("requests.post", side_effect=_post), A.app.test_client() as c:
        for _ in range(10):
            c.get("/api/dehashed/balance")
    ok = calls["n"] <= 1
    if not ok:
        failures.append(
            f"balance_metering[page_loads]: 10 loads of the scan form performed "
            f"{calls['n']} live DeHashed searches — the credit indicator must serve a "
            "cached balance, not buy one per page view")
    print(f"  [{'PASS' if ok else 'FAIL'}] balance_metering:10_page_loads      "
          f"paid_searches={calls['n']}")

    # THE CACHE MUST SURVIVE A RESTART. An in-memory-only cache is not a cache
    # on a service that restarts with every deploy: 10 service starts on
    # 2026-08-06 alone, each wiping it, so the next page load bought a credit.
    import time as _t2
    ct_m.record_dehashed_balance(309, _t2.time())
    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})   # the restart
    recovered = ct_m.last_dehashed_balance().get("balance")
    ok_persist = recovered == 309
    if not ok_persist:
        failures.append(
            f"balance_metering[persistence]: after a simulated restart the balance "
            f"read back as {recovered!r}, not 309 — an in-memory cache is wiped by "
            "every deploy, so each one silently costs a credit")
    print(f"  [{'PASS' if ok_persist else 'FAIL'}] balance_metering:survives_restart  "
          f"recovered={recovered}")
    try:
        os.remove(ct_m._BALANCE_FILE)
    except OSError:
        pass

    # a balance captured from a real scan must be served for free
    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    ct_m.record_dehashed_balance(228, time.time())
    before = calls["n"]
    with mock.patch("requests.post", side_effect=_post), A.app.test_client() as c:
        got = (c.get("/api/dehashed/balance").get_json() or {}).get("balance")
    ok2 = (calls["n"] == before) and got == 228
    if not ok2:
        failures.append(
            f"balance_metering[from_scan]: balance={got} extra_calls="
            f"{calls['n'] - before} — a balance already returned by a real scan "
            "search must be reused, not re-purchased")
    print(f"  [{'PASS' if ok2 else 'FAIL'}] balance_metering:reuse_scan_balance "
          f"balance={got} extra_paid={calls['n'] - before}")

    # A REJECTED PROBE MUST NOT RE-FIRE ON EVERY PAGE LOAD.
    # This is the mechanism that actually burned credits and NOTHING gated it.
    # The scenarios above all mock a 200 CARRYING a balance, so they only ever
    # exercise the happy path -- under a 400 the assertion above ("<=1 call per
    # 10 loads") would have passed at 10 out of 10, because a non-200 records no
    # balance, the TTL cache never warms, and the next load probes again.
    # Unbounded, and each one spends the daily cap that gates real scans.
    class _Rej:
        status_code = 400
        text = '{"error": "Issue with query format"}'
        def json(self):
            return {"error": "Issue with query format"}

    rej = {"n": 0}

    def _post_rej(*a, **kw):
        rej["n"] += 1
        return _Rej()

    # Clear BOTH durable files, not just the in-process dict: last_dehashed_
    # balance() falls back to the file, so the previous scenario's cached 228
    # would satisfy the TTL and no probe would fire at all.
    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    for _f in (getattr(ct_m, "_PROBE_FILE", None), ct_m._BALANCE_FILE):
        try:
            os.remove(_f)
        except (OSError, TypeError):
            pass
    with mock.patch("requests.post", side_effect=_post_rej), A.app.test_client() as c:
        statuses = [c.get("/api/dehashed/balance").get_json() for _ in range(10)]
    ok_rej = rej["n"] <= 1
    if not ok_rej:
        failures.append(
            f"balance_metering[rejected_probe]: 10 page loads after a rejected probe "
            f"performed {rej['n']} live calls — a FAILING probe must be cooled down, "
            "not retried per page view. A non-200 records no balance, so the success "
            "TTL cannot bound it; this is what drained the account on 2026-08-13.")
    # and it must still report the failure honestly, not fall back to 'active'
    ok_honest = all((s or {}).get("status") != "active" for s in statuses)
    if not ok_honest:
        failures.append(
            "balance_metering[rejected_probe_honesty]: a rejected probe reported "
            "status=active — the indicator must never claim a working key it "
            "could not confirm")
    print(f"  [{'PASS' if ok_rej and ok_honest else 'FAIL'}] balance_metering:rejected_probe_cooldown "
          f"live_calls={rej['n']}/10 honest={ok_honest}")

    # 200 WITHOUT a balance field must not be reported as active: index.html
    # requires status=='active' AND balance!==null, so that combination was a
    # state no branch handled. Reachable, and previously untested.
    class _NoBal:
        status_code = 200
        def json(self):
            return {"entries": [], "total": 0}      # no 'balance' key

    ct_m._DEHASHED_BALANCE.update({"balance": None, "at": 0.0})
    for _f in (ct_m._PROBE_FILE, ct_m._BALANCE_FILE):
        try:
            os.remove(_f)
        except OSError:
            pass
    with mock.patch("requests.post", side_effect=lambda *a, **k: _NoBal()), \
            A.app.test_client() as c:
        nb = c.get("/api/dehashed/balance").get_json() or {}
    ok_nb = not (nb.get("status") == "active" and nb.get("balance") is None)
    if not ok_nb:
        failures.append(
            "balance_metering[200_without_balance]: returned status=active with "
            "balance=None — the UI treats that as a failure, so the endpoint must "
            "not claim active without a number")
    print(f"  [{'PASS' if ok_nb else 'FAIL'}] balance_metering:200_without_balance "
          f"status={nb.get('status')} balance={nb.get('balance')}")

    # restore the real durable paths
    ct_m._BALANCE_FILE, ct_m._BALANCE_HISTORY_FILE = _orig_bf, _orig_hf
    if _orig_pf is not None:
        ct_m._PROBE_FILE = _orig_pf


def _check_hibp_and_waf_evidence(failures):
    """Two more of the same defect, found by an empirical WAF smoke test.

    1. BreachChecker with no HIBP key returned status="completed",
       breach_count=0 — rendering "Known Breaches (HIBP): 0 - Passed" from a
       lookup that never ran. HIBP_API_KEY is unset on the live deployment, so
       EVERY scan carried that false clean, and the DBI banked 30/30 for it.
    2. waf.blocking_observed was keyed off the APEX tracker only. A site that
       serves 200 at the root but 403s every sensitive path never trips it —
       excellentmeat.co.za did exactly that (apex {200:18, 503:2} => blocked
       False) while info_disclosure was refused 8/8. The WAF row therefore kept
       claiming "No WAF detected" on a page that also said "refused by a
       WAF/CDN". Per-checker probe codes are the stronger evidence.
    """
    import importlib
    ct_m = importlib.import_module("checkers_threats")
    sa_m = importlib.import_module("scoring_analytics")

    out = ct_m.BreachChecker().check("example.com")          # no key
    ok = out.get("status") == "no_api_key"
    if not ok:
        failures.append(
            f"hibp[no_key]: status={out.get('status')!r} breach_count="
            f"{out.get('breach_count')} — with no API key the lookup cannot have "
            "run, so 'completed / 0 breaches' is a green pass on breach history "
            "nobody checked")
    print(f"  [{'PASS' if ok else 'FAIL'}] hibp:no_key_is_not_clean        {out.get('status')}")

    def _dbi(status):
        cats = {"breaches": {"status": status, "breach_count": 0, "issues": []},
                "dehashed": {"status": "completed", "total_entries": 0}}
        r = sa_m.DataBreachIndex().calculate(cats)
        return r["components"]["breach_count"]["points"]

    def _dbi_bi(status, bi):
        cats = {"breaches": {"status": status, "breach_count": 0, "issues": []},
                "dehashed": {"status": "completed", "total_entries": 0}}
        if bi:
            cats["breach_intel"] = bi
        r = sa_m.DataBreachIndex().calculate(cats)
        return r["components"]["breach_count"]["points"]

    full, unknown = _dbi("completed"), _dbi("no_api_key")
    ok2 = unknown < full
    if not ok2:
        failures.append(
            f"hibp[dbi]: an unassessed breach lookup scored {unknown}/30, the same "
            f"as a real clean {full}/30 — the index must not award full marks for a "
            "check that never happened")
    print(f"  [{'PASS' if ok2 else 'FAIL'}] hibp:dbi_no_full_marks          "
          f"unknown={unknown} real_clean={full}")

    # RESEARCH IS THE AUTHORITY, NOT HIBP. HIBP finds almost nothing for SA
    # domains and has no key on this deployment; the researched breach-history
    # checker is the real source. So a missing HIBP key must NOT by itself make
    # the picture unknown when the research reached a verdict — including a
    # verdict of NONE, which is a genuine, earned clean.
    researched_clean = _dbi_bi("no_api_key",
                               {"status": "completed", "verdict": "none"})
    researched_hit = _dbi_bi("no_api_key",
                             {"status": "completed", "verdict": "confirmed",
                              "incident_count": 1, "most_recent_breach": "2026-06-26"})
    ok3 = researched_clean == full and researched_hit < full
    if not ok3:
        failures.append(
            f"hibp[research_authority]: researched-clean scored {researched_clean}/30 "
            f"(expected {full}) and researched-breach {researched_hit}/30 — a missing "
            "HIBP key must not downgrade a verdict the web research actually reached")
    print(f"  [{'PASS' if ok3 else 'FAIL'}] hibp:research_is_authority      "
          f"researched_clean={researched_clean} researched_hit={researched_hit}")

def _check_dehashed_credit_guards(failures):
    """The balance probe must be CHEAP, and a repeat scan must be FREE.

    2026-08-14 CORRECTION, measured live against the API. A search costs exactly
    ONE credit and cost does NOT track result volume: takealot.com (263,469
    records) and a zero-row probe both cost 1. A rejected request costs nothing
    (483 -> HTTP 400 -> 482).

    So the earlier reading recorded here -- that `domain:example.com` cost ~21
    because it matches a huge corpus -- was WRONG. Those 21 credits were ~21
    separate page-load probes from before the TTL cache and the ledger existed.

    This gate's own remediation text then told the next reader to probe under the
    RFC 2606 `.invalid` TLD. DeHashed REJECTS that with HTTP 400 "Issue with
    query format", which killed the balance indicator, which (via
    setCreditState) unticked and disabled the DeHashed checkbox, which silently
    switched the credential check OFF for every scan for ~19 hours. The gate
    caused the outage it was written to prevent.

    The real requirement is a query DeHashed ACCEPTS that returns zero rows,
    under a name no third party can register. This gate CANNOT verify the first
    of those -- _check_balance_not_metered mocks requests.post, so a rejected
    query looks identical to an accepted one. Changing the probe query requires
    a live check against the API.
    """
    import re as _re2
    app_src = open(os.path.join(SEC, "app.py"), encoding="utf-8").read()

    # 1. The probe query must not name a domain with a large breach corpus.
    # The probe is the only "domain:" literal in app.py; the scan checker's own
    # query is built from the target and lives in checkers_threats.
    m = _re2.search(r'"query":\s*"domain:([^"]+)"', app_src)
    probe_domain = m.group(1) if m else None
    BANNED = {"example.com", "example.org", "example.net", "test.com",
              "gmail.com", "yahoo.com", "hotmail.com"}
    # RESERVED TLDs ARE NOT SAFE HERE. .invalid/.test/.example/.localhost are
    # unregistrable, which is why they look ideal and why this gate used to
    # recommend one -- but DeHashed rejects them outright (HTTP 400 "Issue with
    # query format"), and a rejected probe reads to the UI as "credits
    # unavailable", which disables the credential check on every subsequent
    # scan. Unregistrable is worth nothing if the provider will not parse it.
    RESERVED_TLDS = (".invalid", ".test", ".example", ".localhost")
    _d = (probe_domain or "").lower()
    reserved = _d.endswith(RESERVED_TLDS)
    ok = bool(probe_domain) and _d not in BANNED and not reserved
    if reserved:
        failures.append(
            f"dehashed_credits[probe_target]: balance probe queries {probe_domain!r} — "
            "DeHashed REJECTS reserved TLDs with HTTP 400, and a rejected probe "
            "disables the credential check on every scan (live outage 2026-08-13). "
            "Use a subdomain of a domain we own, and verify it returns HTTP 200 "
            "against the real API before shipping")
    elif not ok:
        failures.append(
            f"dehashed_credits[probe_target]: balance probe queries {probe_domain!r} — "
            "a domain that appears in breach corpora returns rows we neither need nor "
            "want to page through. Probe a name we control that matches nothing, e.g. "
            "a subdomain of our own domain, verified HTTP 200 against the real API")
    print(f"  [{'PASS' if ok else 'FAIL'}] dehashed_credits:probe_target      {probe_domain}")

    # 2. The probe must stay TTL-cached, or a refresh storm bills per page load.
    ttl_guarded = "DEHASHED_BALANCE_TTL_S" in app_src and "cached" in app_src
    if not ttl_guarded:
        failures.append(
            "dehashed_credits[probe_ttl]: the balance probe lost its TTL cache — "
            "every page load would spend a credit, which is the original leak")
    print(f"  [{'PASS' if ttl_guarded else 'FAIL'}] dehashed_credits:probe_ttl_cached  {ttl_guarded}")

    # 3. Cache conclusive results only; never pin an outage in place.
    import tempfile as _tf, time as _time, importlib as _il2, json as _js2
    ct2 = _il2.import_module("checkers_threats")
    _tmp = _tf.mkdtemp()
    _orig_dir, _orig_hist = ct2._DH_CACHE_DIR, ct2._BALANCE_HISTORY_FILE
    ct2._DH_CACHE_DIR = os.path.join(_tmp, "c")
    ct2._BALANCE_HISTORY_FILE = os.path.join(_tmp, "h.jsonl")
    try:
        for label, res, want in (
            ("completed",             {"status": "completed"},             True),
            ("quota_exhausted",       {"status": "quota_exhausted"},       False),
            ("error",                 {"status": "error"},                 False),
            ("no_api_key",            {"status": "no_api_key"},            False),
            ("subscription_required", {"status": "subscription_required"}, False),
        ):
            d = "gate-%s.example" % label
            ct2.dehashed_cache_put(d, res)
            got = ct2.dehashed_cache_get(d) is not None
            okc = got == want
            if not okc:
                failures.append(
                    f"dehashed_credits[cache/{label}]: cached={got} expected {want} — "
                    "caching a non-conclusive lookup pins a provider outage in place "
                    "for the whole TTL and hides it behind a stale hit")
            print(f"  [{'PASS' if okc else 'FAIL'}] dehashed_credits:cache/{label:<20} {got}")

        # 4. The balance history must record a DELTA, which is what attributes
        #    spend to a call. Only the latest value used to be kept, which is
        #    why the 2026-08-13 question took a day to answer.
        ct2.record_dehashed_balance(98, _time.time(), source="scan:a.com")
        ct2.record_dehashed_balance(77, _time.time(), source="balance_probe")
        rows = [_js2.loads(l) for l in open(ct2._BALANCE_HISTORY_FILE, encoding="utf-8")]
        okh = (len(rows) == 2 and rows[1]["delta"] == -21
               and rows[1]["source"] == "balance_probe")
        if not okh:
            failures.append(
                f"dehashed_credits[history]: {rows} — the append-only log must record "
                "delta and source per observation, or credit spend cannot be attributed "
                "to the call that caused it")
        print(f"  [{'PASS' if okh else 'FAIL'}] dehashed_credits:history_delta     "
              f"{rows[-1]['delta'] if rows else None} / {rows[-1]['source'] if rows else None}")
    finally:
        ct2._DH_CACHE_DIR, ct2._BALANCE_HISTORY_FILE = _orig_dir, _orig_hist
        import shutil as _sh; _sh.rmtree(_tmp, ignore_errors=True)


def _check_score_scale_agreement(failures):
    """The dashboard must know which category scores are 0..10, not 0..100.

    EmailSecurityChecker._calculate_score starts at 10 and deducts;
    EmailHardeningChecker returns min(score, 10). Both write to the same
    `score` field as every other category, which is 0..100. RiskScorer knows
    and rescales explicitly (`inv((score / 10) * 100)`), so the overall score
    and the PDF are right. getRiskFactors did not, and averaged the two scales
    together -- a 9-out-of-10 email posture counted as 9-out-of-100.

    Measured on takealot.com (score 144, 100% coverage):
        Credential Security  avg(dehashed 0, email_security 9)  = 4  Critical
                        vs   avg(0, 90)                         = 45 High
        System Hardening     avg(ssl 95, email_hardening 5)     = 50 High
                        vs   avg(95, 50)                        = 72 Moderate

    This asserts the two sides AGREE. A third 0..10 checker added later must be
    declared in the frontend set, or this fails -- which is the whole point,
    because the failure mode is silent and understates a client's posture.
    """
    import re as _re3, importlib as _il3
    sel = open(os.path.join(SEC, "frontend", "src", "data", "selectors.ts"),
               encoding="utf-8").read()
    m = _re3.search(r"TEN_POINT_CATEGORIES\s*=\s*new Set\(\[([^\]]*)\]", sel)
    declared = set(_re3.findall(r"'([^']+)'", m.group(1))) if m else set()

    # Ground truth from the checkers themselves: score them with PERFECT input
    # and see what the maximum actually is.
    cc3 = _il3.import_module("checkers_core")
    actual = set()
    try:
        good_spf = {"present": True, "valid": True, "all_qualifier": "-all",
                    "dangerous": False, "dns_lookups": 3, "exceeds_lookup_limit": False,
                    "has_redirect": False, "record": "v=spf1 -all"}
        good_dmarc = {"present": True, "policy": "reject", "pct": 100,
                      "partial_enforcement": False, "subdomain_policy": "reject",
                      "has_reporting": True, "record": "v=DMARC1; p=reject"}
        good_dkim = {"selectors_found": ["default"]}
        sc, _ = cc3.EmailSecurityChecker()._calculate_score(good_spf, good_dmarc, good_dkim)
        if sc <= 10:
            actual.add("email_security")
    except Exception as e:
        print(f"  [WARN] could not score EmailSecurityChecker: {e}")
    try:
        sc, _ = cc3.EmailHardeningChecker()._calculate_score(
            {"present": True, "mode": "enforce"}, {"present": True, "has_vmc": True},
            {"present": True}, {"present": True, "rua": "x"})
        if sc <= 10:
            actual.add("email_hardening")
    except Exception as e:
        print(f"  [WARN] could not score EmailHardeningChecker: {e}")

    ok = declared == actual and bool(actual)
    if not ok:
        failures.append(
            f"score_scale[agreement]: frontend declares {sorted(declared)} as 0..10 but the "
            f"checkers actually max at 10 for {sorted(actual)} — the roll-up will average a "
            "0..10 score against 0..100 ones and silently understate that dimension for "
            "every client")
    print(f"  [{'PASS' if ok else 'FAIL'}] score_scale:frontend_matches_checkers  "
          f"declared={sorted(declared)} actual={sorted(actual)}")

    # --- the dashboard must not invent a verdict the PDF already states -----
    # The PDF is the scrutinised artefact and this panel has no counterpart in
    # it, so where the PDF states a verdict the dashboard must show THAT one.
    # Credential Security used to average dehashed + breaches + email_security;
    # `dehashed.score` has no validated consumer anywhere (RiskScorer reads
    # credential_risk.pbreach_contribution, the PDF card reads credential_risk),
    # and email authentication posture is not credential exposure at all.
    #
    # Measured across the 14 most recent scans: agreement with the PDF card went
    # 8/14 -> 14/14. The one that mattered most was phishield.com on 2026-08-06,
    # where credentials were never assessed (dehashed: no_api_key) and the panel
    # rendered a green "Low / 100%".
    reads_cr = "credentialVerdict" in sel and "credential_risk" in sel
    if not reads_cr:
        failures.append(
            "score_scale[cred_source]: Credential Security no longer reads "
            "credential_risk — the dashboard is computing a parallel verdict to the "
            "one the PDF card states, which is how the two came to disagree")
    print(f"  [{'PASS' if reads_cr else 'FAIL'}] score_scale:cred_reads_pdf_field   {reads_cr}")

    # ...and it must fail closed exactly as the PDF card does.
    fails_closed = "'UNKNOWN'" in sel and "assessed === false" in sel
    if not fails_closed:
        failures.append(
            "score_scale[cred_failclosed]: the credential verdict does not gate on "
            "UNKNOWN / assessed:false, so an unassessed credential estate can render "
            "as a verdict — the PDF card refuses to")
    print(f"  [{'PASS' if fails_closed else 'FAIL'}] score_scale:cred_fails_closed     {fails_closed}")

    # --- two axes: a good score must be able to coexist with a blocker ------
    # Measured over 142 dimension verdicts across all 36 scans:
    #   worst-member-only   79.6% High/Critical, 8.5% Low
    #   weighted average    85.2% Low/Medium, 2 Critical in 142
    # One cries wolf, the other never alarms; they disagree on 109 of 142.
    # rbs.co.za's Data Protection scores 75 -- a well-run area -- while carrying
    # a CRITICAL finding. A single number cannot say both, so the row carries
    # the posture score AND the blocker independently.
    has_blockers = "blockers" in sel and "'high' || v === 'critical'" in sel
    weighted = "SEVERITY_POINTS" in sel and "SEVERITY_POINTS[v], 0) / real.length" in sel
    if not (has_blockers and weighted):
        failures.append(
            f"two_axis[present]: blockers={has_blockers} weighted_score={weighted} — the "
            "dimension must carry a posture score AND a named blocker list. Collapsing "
            "them loses the state that matters: a well-run area with one confirmed "
            "exposure reads as neither wholly good nor wholly bad")
    print(f"  [{'PASS' if has_blockers and weighted else 'FAIL'}] two_axis:score_and_blockers      "
          f"blockers={has_blockers} weighted={weighted}")

    # The axes must be INDEPENDENT: the score must not be derived from the band,
    # or a blocker would drag the score down and the two would collapse into one.
    independent = "SEVERITY_BAR" not in sel
    if not independent:
        failures.append(
            "two_axis[independent]: the bar still renders a band position rather than the "
            "weighted score — a blocker would then drive both axes and a well-run area "
            "with one bad finding could not be told from a badly-run one")
    print(f"  [{'PASS' if independent else 'FAIL'}] two_axis:axes_independent       {independent}")

    # Replicate the arithmetic: 3 clean + 1 critical must give a HIGH score and
    # a CRITICAL label simultaneously. That is the whole point.
    PTS = {"positive": 100, "medium": 60, "high": 30, "critical": 0}
    members = ["positive", "positive", "positive", "critical"]
    score = round(sum(PTS[m] for m in members) / len(members))
    label = max(members, key=["positive", "medium", "high", "critical"].index)
    ok_both = score >= 70 and label == "critical"
    if not ok_both:
        failures.append(
            f"two_axis[coexist]: 3 clean + 1 critical gives score={score} label={label!r}; "
            "a high score must be able to coexist with a critical label")
    print(f"  [{'PASS' if ok_both else 'FAIL'}] two_axis:good_score_with_blocker score={score} label={label}")

    # ...and the roll-up must actually apply it.
    applies = "toPercent" in sel and "TEN_POINT_CATEGORIES.has" in sel
    if not applies:
        failures.append(
            "score_scale[applied]: TEN_POINT_CATEGORIES is declared but getRiskFactors "
            "does not rescale with it")
    print(f"  [{'PASS' if applies else 'FAIL'}] score_scale:rollup_applies_it        {applies}")

    # The coverage denominator must reach the row, or a 1-of-4 dimension still
    # renders as a full verdict -- and green on thin coverage is never questioned.
    rf = open(os.path.join(SEC, "frontend", "src", "components", "overview",
                           "RiskFactors.tsx"), encoding="utf-8").read()
    shows = "assessed" in rf and "f.total" in rf
    if not shows:
        failures.append(
            "score_scale[coverage_shown]: the Risk Factors row does not show how many "
            "categories produced a verdict, so a dimension resting on one checker reads "
            "as a verdict on all of them")
    print(f"  [{'PASS' if shows else 'FAIL'}] score_scale:coverage_denominator     {shows}")


def _check_card_severity_equivalence(failures):
    """card_severity must render the SAME verdict the PDF card renders.

    The dashboard's Risk Factors panel has no counterpart in the PDF, and it
    used to average whatever `score` fields happened to exist. Several
    categories have no `score` at all, and each PDF card computes its own
    traffic light from that category's NATIVE fields -- open ports, exposed
    services, a grade letter, a compliance percentage.

    takealot.com: the panel showed a GREEN "Network Exposure - Low" drawn from
    shodan_vulns alone, while the PDF's DNS card was RED for a confirmed open
    FTP port (vsFTPd 3.0.5). The finding existed, was rendered in the PDF, and
    was invisible in the dashboard.

    The severity is now computed once in card_severity.py, stamped onto each
    category during scan assembly, and read by the dashboard. This asserts the
    module still agrees with what pdf_cards ACTUALLY does, by rendering each
    real card and intercepting the colour it chose. If someone edits a card's
    traffic light without editing card_severity, this fails.
    """
    import importlib as _il4
    ph4 = _il4.import_module("pdf_helpers")
    pc4 = _il4.import_module("pdf_cards")
    cs4 = _il4.import_module("card_severity")

    COL2SEV = {str(ph4.C_GREEN): "positive", str(ph4.C_AMBER): "medium",
               str(ph4.C_RED): "high", str(ph4.C_CRITICAL): "critical",
               str(ph4.C_GREY_4): "unknown"}
    CASES = {
        ("dns_infrastructure", "cat_dns"): [
            {"status": "completed", "open_ports": []},
            {"status": "completed", "open_ports": [{"port": 80, "service": "H", "risk": "low"},
                                                   {"port": 443, "service": "S", "risk": "low"},
                                                   {"port": 8080, "service": "P", "risk": "low"}]},
            {"status": "completed", "open_ports": [{"port": 21, "service": "FTP", "risk": "high"}]},
        ],
        ("shodan_vulns", "cat_shodan"): [
            {"status": "completed", "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0},
            {"status": "completed", "critical_count": 0, "high_count": 0, "medium_count": 2, "low_count": 0},
            {"status": "completed", "critical_count": 0, "high_count": 1, "medium_count": 0, "low_count": 0},
            {"status": "completed", "critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0},
        ],
        ("website_security", "cat_website"): [{"status": "completed", "score": v} for v in (100, 60, 20)],
        # fraudulent_domains was absent from this dict, so the one category the
        # 2026-09-08 remediation touched had no equivalence coverage at all and
        # the PDF card graded it by a count rule while card_severity graded it
        # by capability. Measured divergences before the fix: 4 parked
        # lookalikes rendered critical in the PDF and medium on the dashboard;
        # 1 mail-capable domain with no website rendered high and critical.
        ("fraudulent_domains", "cat_fraudulent_domains"): [
            {"status": "completed", "total_permutations": 10, "resolved_count": 0, "fraudulent_domains": []},
            {"status": "completed", "resolved_count": 4,
             "fraudulent_domains": [{"domain": "a%d.test" % i, "similarity": 80,
                                     "mail_capable": False,
                                     "serves_content": False} for i in range(4)]},
            {"status": "completed", "resolved_count": 1,
             "fraudulent_domains": [{"domain": "m.test", "similarity": 90,
                                     "mail_capable": True,
                                     "serves_content": False}]},
            {"status": "completed", "resolved_count": 1,
             "fraudulent_domains": [{"domain": "s.test", "similarity": 90,
                                     "mail_capable": True,
                                     "serves_content": True}]},
            # Resolved but never enriched: capability unmeasured, not absent.
            {"status": "completed", "resolved_count": 2,
             "fraudulent_domains": [{"domain": "u1.test", "similarity": 70},
                                    {"domain": "u2.test", "similarity": 70}]},
        ],
        ("http_headers", "cat_headers"):     [{"status": "completed", "score": v} for v in (100, 60, 20)],
        ("waf", "cat_waf"): [
            {"status": "completed", "detected": True, "waf_name": "Cloudflare"},
            {"status": "completed", "detected": False, "blocking_observed": True},
            {"status": "completed", "detected": False},
        ],
        ("privacy_compliance", "cat_privacy_compliance"): [
            {"status": "completed", "compliance_pct": 90, "policy_found": True},
            {"status": "completed", "compliance_pct": 60, "policy_found": True},
            {"status": "completed", "compliance_pct": 10, "policy_found": True},
            {"status": "completed", "compliance_pct": 0, "policy_found": False},
        ],
        ("payment_security", "cat_payment"): [
            {"status": "completed"},
            {"status": "completed", "has_payment_page": True, "payment_page_https": False},
            {"status": "completed", "self_hosted_payment_form": True},
        ],
        ("exposed_admin", "cat_admin"): [
            {"status": "completed", "critical_count": 0, "high_count": 0, "exposed": []},
            {"status": "completed", "critical_count": 0, "high_count": 2, "exposed": []},
            {"status": "completed", "critical_count": 1, "high_count": 0, "exposed": []},
        ],
        ("info_disclosure", "cat_info_disclosure"): [
            {"status": "completed", "score": v, "exposed_paths": []} for v in (100, 70, 10)],
        ("ssl", "cat_ssl"): [{"status": "completed", "grade": g} for g in ("A+", "C", "F")],
        ("email_hardening", "cat_email_hardening"): [{"status": "completed", "score": v} for v in (10, 5, 1)],
        ("security_policy", "cat_security_policy"): [
            {"status": "completed", "security_txt": {"present": True}},
            {"status": "completed", "security_txt": {"present": False}},
        ],
        ("vpn_remote", "cat_vpn"): [
            {"status": "completed", "vpn_detected": True},
            {"status": "completed", "vpn_detected": False},
            {"status": "completed", "rdp_exposed": True},
        ],
    }

    S = ph4.build_styles()
    checked = mismatched = 0
    for (cat_id, fn_name), cases in CASES.items():
        card = getattr(pc4, fn_name, None)
        if card is None:
            failures.append(f"card_severity[{cat_id}]: pdf_cards.{fn_name} not found")
            continue
        for data in cases:
            seen = {}
            orig = pc4.build_cat_card

            def spy(title, col, status, rows, issues, S_, **kw):
                seen["col"] = col
                return orig(title, col, status, rows, issues, S_, **kw)

            pc4.build_cat_card = spy
            try:
                card({cat_id: data}, S)
            except Exception:
                pc4.build_cat_card = orig
                continue
            pc4.build_cat_card = orig
            pdf_sev = COL2SEV.get(str(seen.get("col")))
            mine = cs4.category_severity(cat_id, data)
            checked += 1
            if pdf_sev != mine:
                mismatched += 1
                failures.append(
                    f"card_severity[{cat_id}]: PDF card renders {pdf_sev!r} but "
                    f"card_severity says {mine!r} for {data} — the dashboard would show "
                    "a different verdict from the PDF for the same scan")
    ok = mismatched == 0 and checked > 30
    print(f"  [{'PASS' if ok else 'FAIL'}] card_severity:matches_pdf_cards    "
          f"{checked} branches, {mismatched} mismatched")

    # ...and a dimension takes its WORST member, never an average.
    w = cs4.worst_severity(["positive", "positive", "high", "positive"])
    ok_w = w == "high"
    if not ok_w:
        failures.append(
            f"card_severity[worst]: worst_severity returned {w!r} for a group containing "
            "a high finding — a dimension must be as weak as its weakest member, or a "
            "confirmed exposure is averaged away by clean siblings")
    print(f"  [{'PASS' if ok_w else 'FAIL'}] card_severity:dimension_is_worst  {w}")


def _check_exec_deck_credentials(failures):
    """The Executive Summary must render, and must not invert the verdict.

    TWO live defects, found 2026-08-14 when the Executive Summary would not
    download while the broker summary and full report both did.

    1. CRASH. `_assessment_top_findings` read
       `credential_risk.get("risk_score", 0)`. The default applies only when the
       KEY IS ABSENT -- the classifier writes the key with value None for an
       unassessed estate, so `None >= 50` raised TypeError. Every scan run with
       the credential lookup skipped produced a broken exec deck and two working
       ones, which is why it looked tier-specific rather than data-specific.

    2. INVERSION. It then thresholded that score, but K5_RISK_SCORE is
       CRITICAL 0 / HIGH 25 / MEDIUM 55 / LOW 85 / NONE 100 -- HIGHER IS SAFER.
       The tests read `>= 80 -> CRITICAL`, so the SAFEST estates were reported
       as the worst and genuinely critical ones were not flagged by score at all:

           classifier LOW (85)      -> deck said CRITICAL
           classifier NONE (100)    -> deck said CRITICAL
           classifier CRITICAL (0)  -> not flagged

       Measured across 20 stored scans, the deck disagreed with the classifier
       on 13. morgancarco.com -- an unregistered domain with ZERO credential
       records -- reported "Overall credential risk is classified as CRITICAL".

    The deck now reads `risk_level`, which the classifier already states.
    """
    import importlib as _il5
    pr5 = _il5.import_module("pdf_report")

    def deck_level(cred_risk, dehashed=None):
        res = {"categories": {"credential_risk": cred_risk,
                              "dehashed": dehashed or {"total_entries": 0}}}
        found = pr5._assessment_top_findings(res)
        f = next((x for x in found
                  if "credential risk" in str(x.get("headline", "")).lower()), None)
        return f["level"] if f else None

    # The classifier's verdict must survive to the deck unchanged.
    for level, score in (("CRITICAL", 0), ("HIGH", 25), ("MEDIUM", 55)):
        got = deck_level({"risk_level": level, "risk_score": score, "assessed": True})
        ok = got == level
        if not ok:
            failures.append(
                f"exec_deck[{level}]: deck reported {got!r} for a classifier verdict of "
                f"{level!r} (score {score}, where HIGHER IS SAFER) — thresholding that "
                "score inverts the verdict and reports the safest estates as the worst")
        print(f"  [{'PASS' if ok else 'FAIL'}] exec_deck:level/{level:<9}          {got}")

    # A safe estate must NOT be reported as a finding at all.
    for level, score in (("LOW", 85), ("NONE", 100)):
        got = deck_level({"risk_level": level, "risk_score": score, "assessed": True})
        ok = got is None
        if not ok:
            failures.append(
                f"exec_deck[{level}]: a {level} credential estate (score {score}) was "
                f"reported as a {got!r} finding — this is the inversion that put "
                "'credential risk CRITICAL' on clean reports")
        print(f"  [{'PASS' if ok else 'FAIL'}] exec_deck:safe_not_flagged/{level:<5} {got}")

    # An UNASSESSED estate must not crash, and must not invent a level.
    for label, cr in (("risk_score None", {"risk_level": "UNKNOWN", "risk_score": None,
                                           "assessed": False}),
                      ("missing entirely", {})):
        try:
            got = deck_level(cr)
            crashed = False
        except Exception as e:
            got, crashed = "%s: %s" % (type(e).__name__, e), True
        ok = (not crashed) and got is None
        if not ok:
            failures.append(
                f"exec_deck[unassessed/{label}]: {got!r} — an unassessed credential estate "
                "must not raise and must not be given a level; the Executive Summary "
                "would not download at all while the other two tiers rendered")
        print(f"  [{'PASS' if ok else 'FAIL'}] exec_deck:unassessed/{label:<16} {got}")


def _check_report_degradation(failures):
    """Every tier must RENDER on a degraded scan, and the tiers must AGREE.

    Two controls the 2026-08-14 incident showed were missing, both proposed by
    the review agent that critiqued the first fix.

    (a) RENDERS AT ALL. pdf_snapshot renders 3 tiers x 2 fixtures, both fully
        populated, and compares HASHES. It cannot catch a tier that raises on a
        shape the fixtures do not contain. Two separate live crashes hid there:
        `credential_risk.risk_score = None` (an unassessed estate) and
        `insurance = {"error": ...}` (analytics raised, which scanner.py leaves
        behind). Both took down ONLY the Executive Summary, so it read as a tier
        bug rather than a data bug.

        This sweeps every category x {absent, blocked, score None} x 3 tiers and
        asserts each renders. When first run it found roughly forty crash sites,
        nearly all of them a `.get("score", <perfect>)` default flowing into a
        comparison.

    (b) THE TIERS MUST AGREE. Before the fix, phishield_R10M_finance rendered
        "credential risk CRITICAL" on the assessment tier and LOW on the full
        tier -- same scan, same gate run, both hashed and blessed. A hash cannot
        see a contradiction between two artefacts; only an assertion can.
    """
    import copy as _cp, json as _js3, importlib as _il6, re as _re6, traceback as _tb6
    pr6 = _il6.import_module("pdf_report")

    fx = os.path.join(SEC, "test_fixtures", "phishield_R10M_finance_2026-05-15.json")
    base = _js3.loads(open(fx, encoding="utf-8").read())

    # --- (a) degradation sweep ------------------------------------------
    cats = sorted(base.get("categories", {}))
    SHAPES = (
        ("absent",    lambda c, k: c.pop(k, None)),
        ("blocked",   lambda c, k: c.update({k: {"status": "unreachable"}})),
        ("scoreNone", lambda c, k: c.update({k: {"status": "completed", "score": None}})),
    )
    # per_ip is a field carried alongside the categories, not a checker; the
    # blocked shape is not one it can take, so exclude rather than special-case.
    cats = [c for c in cats if c != "per_ip"]

    crashes, runs = [], 0
    for cid in cats:
        for lbl, mut in SHAPES:
            d = _cp.deepcopy(base); mut(d["categories"], cid)
            for tier in ("assessment", "summary", "full"):
                runs += 1
                try:
                    pr6.generate_pdf(d, report_type=tier)
                except Exception:
                    fr = _re6.findall(r"(pdf_\w+\.py)\", line (\d+), in (\w+)",
                                      _tb6.format_exc())
                    crashes.append("%s/%s/%s at %s" % (
                        cid, lbl, tier, ("%s:%s %s" % fr[-1]) if fr else "?"))

    # Scan-level degradation the categories sweep cannot express.
    for lbl, mut in (("insurance={'error'}", lambda d: d.update(insurance={"error": "x"})),
                     ("insurance absent",    lambda d: d.pop("insurance", None)),
                     ("no categories",       lambda d: d["categories"].clear())):
        d = _cp.deepcopy(base); mut(d)
        for tier in ("assessment", "summary", "full"):
            runs += 1
            try:
                pr6.generate_pdf(d, report_type=tier)
            except Exception:
                fr = _re6.findall(r"(pdf_\w+\.py)\", line (\d+), in (\w+)",
                                  _tb6.format_exc())
                crashes.append("%s/%s at %s" % (
                    lbl, tier, ("%s:%s %s" % fr[-1]) if fr else "?"))

    ok_a = not crashes
    if not ok_a:
        failures.append(
            "report_degradation[renders]: %d of %d renders raised. A tier that will "
            "not build is invisible until a client clicks download, and only ONE tier "
            "breaks, so it reads as a tier bug. First few: %s"
            % (len(crashes), runs, "; ".join(crashes[:4])))
    print(f"  [{'PASS' if ok_a else 'FAIL'}] report_degradation:all_tiers_render "
          f"{runs} renders, {len(crashes)} crashed")

    # --- (b) cross-tier agreement ---------------------------------------
    cr = (base.get("categories", {}) or {}).get("credential_risk") or {}
    level = str(cr.get("risk_level") or "").upper()
    deck = pr6._assessment_top_findings(base)
    cred = next((f for f in deck
                 if "credential risk" in str(f.get("headline", "")).lower()), None)
    deck_level = cred["level"] if cred else None
    # The deck may legitimately stay silent on a LOW/NONE estate; what it may
    # NOT do is contradict the classifier.
    ok_b = deck_level is None or deck_level == level
    if not ok_b:
        failures.append(
            f"report_degradation[cross_tier]: the assessment deck says {deck_level!r} "
            f"while credential_risk.risk_level is {level!r} for the same scan. Two "
            "artefacts describing one estate differently is what the hash-only "
            "baseline blessed for months")
    print(f"  [{'PASS' if ok_b else 'FAIL'}] report_degradation:tiers_agree      "
          f"deck={deck_level} classifier={level}")


def _check_scan_target_input(failures):
    """Two ways the scan target goes wrong before a single checker runs.

    1. A domain pasted out of a submission form, a PDF or a mail client arrives
       as a full URL, an email address, or text carrying a zero-width character
       that is INVISIBLE in the input box. The old syntax-only check rejected it
       with "Invalid or missing domain" while the broker could see the domain
       was correct.

    2. A typo of a real domain passes syntax validation and scans to completion
       against nothing. morgancarco.com (for morgancargo.com), 2026-08-07:
       a fully scored report, 266 "Medium", 77% coverage, 0 discovered IPs, and
       headline findings "No SPF record - spoofing risk" / "No DMARC record -
       phishing risk". Both are vacuously true of a domain that does not exist
       and both read as real findings; the real morgancargo.com publishes SPF
       with -all and a DMARC policy.

    DNS is mocked so the gate stays offline and deterministic.
    """
    import importlib as _il
    from unittest import mock
    dv = _il.import_module("domain_validation")

    for label, raw, want in (
        ("plain",              "morgancargo.com",                     "morgancargo.com"),
        ("full URL + path",    "https://www.morgancargo.com/contact",  "www.morgancargo.com"),
        ("email from a form",  "info@morgancargo.com",                 "morgancargo.com"),
        ("mailto link",        "mailto:info@morgancargo.com",          "morgancargo.com"),
        ("zero-width space",   "morgancargo.com​",                "morgancargo.com"),
        ("BOM",                "﻿morgancargo.com",                "morgancargo.com"),
        ("port",               "morgancargo.com:443",                  "morgancargo.com"),
        ("query + fragment",   "https://morgancargo.com?utm=x#f",      "morgancargo.com"),
        ("root dot",           "morgancargo.com.",                     "morgancargo.com"),
    ):
        got = dv.normalize_domain(raw)
        ok = got == want and dv.valid_domain(raw)
        if not ok:
            failures.append(
                f"scan_target[normalise/{label}]: {raw!r} -> {got!r}, expected {want!r} "
                "(valid=%s) — a broker pasting this out of a submission form must not "
                "be told the domain is invalid" % dv.valid_domain(raw))
        print(f"  [{'PASS' if ok else 'FAIL'}] scan_target:normalise/{label:<18} {got}")

    # www. is a real hostname and must NOT be silently rewritten to the apex:
    # deciding apex-vs-www is a product choice, not input cleaning.
    keeps_www = dv.normalize_domain("https://www.morgancargo.com") == "www.morgancargo.com"
    if not keeps_www:
        failures.append(
            "scan_target[normalise/www]: 'www.' was stripped — that silently changes "
            "which host is scanned")
    print(f"  [{'PASS' if keeps_www else 'FAIL'}] scan_target:normalise/keeps_www      {keeps_www}")

    # --- existence: NXDOMAIN must be refused, everything else allowed --------
    import dns.resolver as _dnsr
    import dns.exception as _dnse

    def _resolver(behaviour):
        class _R:
            lifetime = 5
            timeout = 5
            def resolve(self, name, rdtype):
                if behaviour == "nxdomain":
                    raise _dnsr.NXDOMAIN()
                if behaviour == "noanswer":
                    raise _dnsr.NoAnswer()
                if behaviour == "timeout":
                    raise _dnse.Timeout()
                if behaviour == "ns_only":
                    if rdtype == "NS":
                        return ["ns1.example."]
                    raise _dnsr.NoAnswer()
                return ["1.2.3.4"]
        return _R

    for label, behaviour, want in (
        ("NXDOMAIN (typo)",        "nxdomain", False),
        ("resolves normally",      "ok",       True),
        ("registered, NS only",    "ns_only",  True),
        ("resolver timeout",       "timeout",  True),
        ("no answer any type",     "noanswer", True),
    ):
        with mock.patch.object(_dnsr, "Resolver", _resolver(behaviour)):
            got = dv.domain_exists("example.com")
        ok = got is want
        if not ok:
            failures.append(
                f"scan_target[exists/{label}]: domain_exists={got!r} expected {want!r} — "
                "only NXDOMAIN proves the name is unregistered; a parked domain with NS "
                "records is a legitimate target and resolver trouble must fail OPEN "
                "rather than block a real scan")
        print(f"  [{'PASS' if ok else 'FAIL'}] scan_target:exists/{label:<20} {got}")


def _check_base_path_links(failures):
    src_dir = os.path.join(SEC, "frontend", "src")
    # (?!/) excludes protocol-relative "//cdn.example.com" while still matching
    # the exact root href="/" — the actual bug. An earlier [^/"'] class here
    # rejected the closing quote and therefore missed href="/" entirely, so the
    # check passed while the defect was present. Verified by reintroducing it.
    pattern = _re.compile(
        r"""href=["']/(?!/)|href=\{["']/(?!/)"""
        r"""|location\.(?:href|assign|replace)\s*=\s*["']/(?!/)"""
        r"""|window\.open\(["']/(?!/)""")
    offenders = []
    for root, _dirs, files in os.walk(src_dir):
        for fn in files:
            if not fn.endswith((".ts", ".tsx")):
                continue
            fp = os.path.join(root, fn)
            for i, line in enumerate(open(fp, encoding="utf-8"), 1):
                if "withBase" in line or line.lstrip().startswith(("//", "*")):
                    continue
                if pattern.search(line):
                    offenders.append(f"{os.path.relpath(fp, src_dir)}:{i}")
    ok = not offenders
    if not ok:
        failures.append(
            "base_path[absolute_links]: " + ", ".join(offenders[:5]) +
            " — an absolute href/navigation without withBase() escapes the /scanner "
            "mount and lands on the Command Centre at the site root")
    print(f"  [{'PASS' if ok else 'FAIL'}] base_path:no_bare_absolute_links   "
          f"offenders={len(offenders)}")

    # ...and the SHIPPED bundle, which the source check cannot see.
    #
    # BASE is baked in at BUILD time from import.meta.env.BASE_URL, so the
    # prefix is only correct when the build is run as
    # `SCANNER_BASE_PATH=/scanner npm run build`. A plain `npm run build` emits
    # a bundle where BASE is "" and every withBase('/api/...') call resolves to
    # /api/... instead of /scanner/api/... — off the Caddy `handle_path
    # /scanner/*` mount entirely.
    #
    # That failure is close to silent. The dashboard still renders (Flask serves
    # results.html, not this index.html), the elapsed timer still ticks, and
    # ScanProgress's polling fallback treats any non-200/non-500 as "keep
    # polling" — so a finished scan sits on screen at 0/39 forever. Shipped
    # 2026-08-06; the running scan had already completed server-side.
    #
    # The committed artefact is what deploys, so assert on the artefact.
    idx = os.path.join(SEC, "static", "dashboard", "index.html")
    if os.path.exists(idx):
        html = open(idx, encoding="utf-8").read()
        refs = _re.findall(r'(?:src|href)="([^"]*static/dashboard[^"]*)"', html)
        bad = [r for r in refs if not r.startswith("/scanner/")]
        ok_b = bool(refs) and not bad
        if not ok_b:
            failures.append(
                f"base_path[built_bundle]: index.html asset refs {bad or refs} are not "
                "under /scanner/ — this bundle was built without SCANNER_BASE_PATH, so "
                "every API call from the dashboard will miss the Caddy mount and the "
                "scan progress screen will hang at 0 checks on a completed scan. "
                "Rebuild with SCANNER_BASE_PATH=/scanner npm run build")
        print(f"  [{'PASS' if ok_b else 'FAIL'}] base_path:built_bundle_prefixed   "
              f"refs={refs}")


class _FakeKeyResp:                 # distinct from the techstack _FakeResp above
    def __init__(self, code):
        self.status_code = code
        self.text = '{"error":{"message":"synthetic"}}'

    def json(self):
        return {"error": {"message": "synthetic"}}


def _check_key_probe(failures):
    import importlib
    ws = importlib.import_module("websearch")
    for label, listing, gen, want, want_fp in KEY_PROBE_SCENARIOS:
        with mock.patch.dict(os.environ, {"GOOGLE_API_KEY": "AQ.synthetic-probe-key"}), \
             mock.patch("httpx.get", return_value=_FakeKeyResp(listing)), \
             mock.patch("httpx.post", return_value=_FakeKeyResp(gen or 200)):
            r = ws.check_key(timeout_s=1.0)
        got, fp = r.get("status"), bool(r.get("key_fingerprint"))
        ok = (got == want) and (fp == want_fp)
        if not ok:
            failures.append(
                f"key_probe[{label}]: HTTP {listing}/{gen} -> status={got!r} "
                f"(want {want!r}), fingerprint_present={fp} (want {want_fp}) — a "
                "rejected key must be reported as 'inactive' WITH its fingerprint, "
                "otherwise the operator gets no remediation hint and cannot tell "
                "which key is failing")
        print(f"  [{'PASS' if ok else 'FAIL'}] key_probe:{label:<21} "
              f"{listing}/{gen or '-'} -> {got} fp={fp}")


def _check_breach_intel(failures):
    import importlib
    bwd = importlib.import_module("breach_web_discovery")
    import scoring_analytics as _sa

    # (a) company matching: word boundary, not substring
    toks = bwd.company_tokens("Mip")
    fp = [v for v in BREACH_FP_VICTIMS if bwd.title_is_about(v, toks)]
    ok = not fp
    if not ok:
        failures.append(f"breach_match: '{'mip'}' still matches unrelated victims {fp} "
                        "(substring match reintroduced; a leak-site hit floors the verdict "
                        "at confirmed, so this asserts breaches at the wrong company)")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:false_positives   rejected "
          f"{len(BREACH_FP_VICTIMS) - len(fp)}/{len(BREACH_FP_VICTIMS)}")

    miss = [t for t, c in BREACH_TRUE_MATCHES if not bwd.title_is_about(t, bwd.company_tokens(c))]
    ok = not miss
    if not ok:
        failures.append(f"breach_match: genuine matches lost {miss}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:true_positives    matched "
          f"{len(BREACH_TRUE_MATCHES) - len(miss)}/{len(BREACH_TRUE_MATCHES)}")

    bad = [t for t, c in BREACH_TRUE_NEGATIVES if bwd.title_is_about(t, bwd.company_tokens(c))]
    ok = not bad
    if not ok:
        failures.append(f"breach_match: unrelated headlines matched {bad}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_match:true_negatives    rejected "
          f"{len(BREACH_TRUE_NEGATIVES) - len(bad)}/{len(BREACH_TRUE_NEGATIVES)}")

    # (b) fail-safe: an unresearched or clean result must score nothing
    for status, verdict in BREACH_FAILSAFE:
        got = _sa.researched_breach_risk({"status": status, "verdict": verdict})
        ok = got is None
        if not ok:
            failures.append(f"breach_failsafe: status={status}/{verdict} returned {got}, "
                            "must be None — an unresearched scan must never score as clean")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_failsafe:{status + '/' + verdict:<22} -> {got}")

    # (b1) undated researched incident must NOT borrow a scraped article date.
    # Live on the 2026-07-28 mip.co.za scan: the researched incident came back
    # undated, the code fell back to the news-RSS dates, and a 2020 article aged a
    # breach disclosed the previous month to "75.2 months" — which also fell
    # outside every recency band and silently dropped the RSI factor.
    from datetime import datetime as _dt, timezone as _tz
    _old = _dt(2020, 4, 21, tzinfo=_tz.utc)
    _undated_incident = [{"title": "x", "incident_date": "", "disclosure_date": ""}]
    got_dates = bwd._incident_dates(_undated_incident)
    ok = got_dates == []
    if not ok:
        failures.append(f"breach_undated: undated incident produced dates {got_dates}")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_undated:incident_dates    -> {got_dates or 'undated (correct)'}")
    # and the undated path must score as "date unestablished", not as an old breach
    r_undated = _sa.researched_breach_risk(
        {"status": "completed", "verdict": "confirmed", "researched": True,
         "months_since_most_recent": None})
    ok = bool(r_undated) and abs(r_undated[0] - 50.0) < 0.01
    if not ok:
        failures.append(f"breach_undated: undated confirmed scored {r_undated}, want 50.0")
    print(f"  [{'PASS' if ok else 'FAIL'}] breach_undated:risk_band         -> {r_undated}")

    # (b2) mid-scan key failure: a degraded verdict must not drive the score
    for label, extra, should_score in BREACH_DEGRADED:
        bi = {"status": "completed", "verdict": "confirmed",
              "months_since_most_recent": 1, **extra}
        got = _sa.researched_breach_risk(bi)
        ok = (got is not None) == should_score
        if not ok:
            failures.append(f"breach_degraded: {label} scored={got is not None}, "
                            f"expected {should_score} — a headline-only verdict dates "
                            "from the earliest ARTICLE, not the incident")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_degraded:{label:<22} scores={got is not None}")

    # (c) recency ladder, both channels
    for months, verdict, want_risk, want_rsi in BREACH_LADDER:
        bi = {"status": "completed", "verdict": verdict, "incident_count": 1,
              "months_since_most_recent": months}
        got = _sa.researched_breach_risk(bi)
        got_risk = round(got[0], 1) if got else None
        rsi = _sa.RansomwareIndex().calculate(
            {"breaches": {"status": "completed", "breach_count": 0, "issues": []},
             "credential_risk": {"risk_level": "LOW"}, "breach_intel": bi},
            industry="technology")
        f = [x for x in rsi.get("contributing_factors", []) if "repeat-victimisation" in x["factor"]]
        got_rsi = round(f[0]["impact"], 3) if f else 0.0
        ok = (got_risk == round(want_risk, 1)) and (got_rsi == round(want_rsi, 3))
        if not ok:
            failures.append(f"breach_ladder: {months}mo/{verdict} risk={got_risk} "
                            f"(want {want_risk}) rsi={got_rsi} (want {want_rsi})")
        print(f"  [{'PASS' if ok else 'FAIL'}] breach_ladder:{str(months) + 'mo/' + verdict:<18} "
              f"risk={got_risk} rsi_impact={got_rsi}")



def _check_technical_card_measurement(failures):
    """Rendered cards must distinguish absent measurement from clean evidence."""
    import io
    import math
    import re
    import fitz
    import pdf_cards as pc
    from pdf_helpers import build_styles
    from card_severity import NON_CONCLUSIVE_STATUSES
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate

    def render(fn, data):
        buf = io.BytesIO()
        SimpleDocTemplate(buf, pagesize=A4, leftMargin=24, rightMargin=24,
                          topMargin=24, bottomMargin=24).build(fn(data, build_styles()))
        doc = fitz.open(stream=buf.getvalue(), filetype="pdf")
        try:
            return "\n".join(page.get_text() for page in doc)
        finally:
            doc.close()

    def flat(value):
        return re.sub(r"\s+", " ", value).strip().lower()

    def neutral(label, text, evidence=None):
        low = text.lower().replace("not clean", "")
        ok = "not assessed" in low and not re.search(
            r"\bclean\b|no active lookalike|no references found|"
            r"no malicious or suspicious detections|no issues detected", low)
        if evidence is not None:
            ok = ok and flat(evidence) in flat(text)
        if not ok:
            failures.append("technical_card[%s]: incomplete result was not neutral "
                            "or lost observed evidence: %s" % (label, flat(text)[:240]))
        return ok

    def positive(label, text, *evidence):
        ok = all(flat(item) in flat(text) for item in evidence)
        if not ok:
            failures.append("technical_card[%s]: completed finding lost evidence %r: %s" %
                            (label, evidence, flat(text)[:240]))
        return ok

    # Missing/null and every non-conclusive status must be neutral. Positive
    # counters remain visible, with the qualifier that the check is incomplete.
    for label, fn, key, observed, clean, finding in (
        ("intelx", pc.cat_intelx, "intelx",
         {"status": "error", "total_results": 2, "darkweb_count": 1,
          "paste_count": 1, "leak_count": 0},
         {"status": "completed", "total_results": 0, "darkweb_count": 0,
          "paste_count": 0, "leak_count": 0},
         {"status": "completed", "total_results": 1, "darkweb_count": 1,
          "paste_count": 0, "leak_count": 0}),
        ("virustotal", pc.cat_virustotal, "virustotal",
         {"status": "timeout", "malicious_count": 2, "suspicious_count": 0,
          "harmless_count": 8, "undetected_count": 0},
         {"status": "completed", "malicious_count": 0, "suspicious_count": 0,
          "harmless_count": 1, "undetected_count": 0},
         {"status": "completed", "malicious_count": 2, "suspicious_count": 0,
          "harmless_count": 8, "undetected_count": 0}),
    ):
        neutral(label + ":missing", render(fn, {}))
        neutral(label + ":null", render(fn, {key: None}))
        for status in NON_CONCLUSIVE_STATUSES:
            sample = dict(observed)
            sample["status"] = status
            neutral(label + ":" + status, render(fn, {key: sample}),
                    "Total references 2" if label == "intelx" else "Malicious detections 2")
        clean_text = render(fn, {key: clean})
        if label == "intelx":
            positive(label + ":clean", clean_text, "Total references 0", "Clean")
        else:
            positive(label + ":clean", clean_text, "Harmless", "1")
        finding_text = render(fn, {key: finding})
        positive(label + ":finding", finding_text,
                 "Total references 1" if label == "intelx" else "Malicious detections 2")

    # IntelX requires all four counters.  VT requires four valid finite counts.
    for field, bad in (("total_results", None), ("darkweb_count", "1"),
                       ("paste_count", True), ("leak_count", -1),
                       ("total_results", float("nan"))):
        sample = {"status": "completed", "total_results": 1,
                  "darkweb_count": 0, "paste_count": 0, "leak_count": 0}
        sample[field] = bad
        neutral("intelx:malformed:" + field, render(pc.cat_intelx, {"intelx": sample}))
    for field, bad in (("malicious_count", None), ("suspicious_count", "1"),
                       ("harmless_count", True), ("undetected_count", -1),
                       ("malicious_count", float("nan"))):
        sample = {"status": "completed", "malicious_count": 0,
                  "suspicious_count": 0, "harmless_count": 1, "undetected_count": 0}
        sample[field] = bad
        neutral("virustotal:malformed:" + field, render(pc.cat_virustotal, {"virustotal": sample}))
    neutral("virustotal:zero-engines", render(pc.cat_virustotal, {
        "virustotal": {"status": "completed", "malicious_count": 0,
                        "suspicious_count": 0, "harmless_count": 0,
                        "undetected_count": 0}}))

    # Fraudulent-domain measurement requires a positive permutation count and
    # a count/list match; retain a listed domain when the measurement is bad.
    fd_clean = {"status": "completed", "total_permutations": 1,
                "resolved_count": 0, "fraudulent_domains": []}
    positive_fd = {"status": "completed", "total_permutations": 1,
                   "resolved_count": 1, "fraudulent_domains": [{
                       "domain": "example-secure.test", "risk": "high",
                       "similarity": 94, "mail_capable": True,
                       "serves_content": False}]}
    neutral("fraudulent_domains:missing", render(pc.cat_fraudulent_domains, {}))
    neutral("fraudulent_domains:null", render(pc.cat_fraudulent_domains,
                                               {"fraudulent_domains": None}))
    positive("fraudulent_domains:clean", render(pc.cat_fraudulent_domains,
             {"fraudulent_domains": fd_clean}), "Lookalikes found 0")
    positive("fraudulent_domains:finding", render(pc.cat_fraudulent_domains,
             {"fraudulent_domains": positive_fd}), "Lookalikes found 1", "example-secure.test")
    mismatch = dict(positive_fd)
    mismatch["resolved_count"] = 2
    neutral("fraudulent_domains:mismatch", render(pc.cat_fraudulent_domains,
                                                   {"fraudulent_domains": mismatch}),
            "example-secure.test")
    neutral("fraudulent_domains:zero-variants", render(pc.cat_fraudulent_domains, {
        "fraudulent_domains": {"status": "completed", "total_permutations": 0,
                                "resolved_count": 0, "fraudulent_domains": []}}))

    for field, bad in (("total_permutations", None), ("resolved_count", "1"),
                       ("total_permutations", True), ("resolved_count", -1),
                       ("resolved_count", float("nan"))):
        sample = dict(fd_clean)
        sample[field] = bad
        neutral("fraudulent_domains:malformed:" + field,
                render(pc.cat_fraudulent_domains, {"fraudulent_domains": sample}))
    capped = dict(fd_clean, resolved_count=21, total_permutations=30,
                  fraudulent_domains=[dict(domain="capped%d.test" % i,
                                           mail_capable=False, serves_content=False)
                                      for i in range(20)])
    capped_text = render(pc.cat_fraudulent_domains, {"fraudulent_domains": capped})
    positive("fraudulent_domains:valid_display_cap", capped_text, "21 found", "capped0.test")
    if "Not assessed" in capped_text:
        failures.append("technical_card[display_cap]: valid completed result marked incomplete")
    print("  [%s] technical_card:measurement_and_rendering" %
          ("FAIL" if any(item.startswith("technical_card[") for item in failures) else "PASS"))

def _check_origin_candidate_boundary(failures):
    """No internal targets or over-broad certificate names enter the origin pool."""
    import origin_discovery as od
    from unittest.mock import patch
    bad = ["10.0.0.1", "127.0.0.1", "169.254.1.2", "192.168.1.1",
           "172.16.0.1", "100.64.0.1", "0.0.0.0", "192.0.2.1",
           "224.0.0.1", "240.0.0.1", "::1", "2001:4860:4860::8888",
           "internal.example.test", "not-an-ip"]
    public = "93.184.216.34"
    start = len(failures)
    for source in ("local", "history", "shodan"):
        attempted = []
        with patch.object(od, "_fetch_historical_a", return_value=bad + [public]), \
             patch.object(od, "_shodan_cert_hosts", return_value=(15, bad + [public], True)), \
             patch.object(od, "_verify_origin", side_effect=lambda ip, domain: attempted.append(ip) or True):
            args = {"extra_candidates": bad + [public]} if source == "local" else (
                {"securitytrails_api_key": "synthetic"} if source == "history" else
                {"shodan_api_key": "synthetic"})
            result = od.discover_origin_ips("example.test", **args)
        if attempted != [public] or result["verified"] != [public] or result["candidates"] != [public]:
            failures.append("origin_boundary[%s]: non-public or non-literal candidate reached verification" % source)
    for ip in bad:
        with patch.object(od.ssl, "create_default_context") as context, \
             patch.object(od.socket, "create_connection") as connect:
            result = od._verify_origin(ip, "example.test")
        if result or context.called or connect.called:
            failures.append("origin_boundary[direct/%s]: verifier did not reject before socket/TLS setup" % ip)
    cases = [
        ("example.test", {"*.example.test"}, False),
        ("a.example.test", {"*.example.test"}, True),
        ("a.b.example.test", {"*.example.test"}, False),
        ("badexample.test", {"*.example.test"}, False),
        ("example.test", {"example.test"}, True),
        ("EXAMPLE.TEST.", {"EXAMPLE.TEST."}, True),
        ("a.example.test", {"other.test"}, False),
        ("a.example.test", {"*example.test"}, False),
    ]
    for domain, names, expected in cases:
        if od._name_covers(domain, names) is not expected:
            failures.append("origin_boundary[certificate/%s/%s]: incorrect hostname coverage" % (domain, names))
    print("  [%s] origin_boundary:25 synthetic cases" % ("PASS" if len(failures) == start else "FAIL"))


def main():
    failures = []
    _install_paid_egress_guard()   # must be first: the gate is offline by contract
    try:
        from test_bounded_probe_lifecycle import run_checks as _bounded_probe_checks
        from test_partial_probe_groups import run_checks as _partial_probe_checks
        _bounded_probe_checks()
        _partial_probe_checks()
        from test_target_safety import run_checks as _target_safety_checks
        from test_current_input_dashboard import run as _current_input_checks
        _target_safety_checks()
        from test_scan_admission import run_checks as _scan_admission_checks
        _scan_admission_checks()
        _current_input_checks()
    except Exception as exc:
        failures.append(f"bounded_probe: {exc}")
        print(f"  [FAIL] bounded_probe: {exc}")
    _check_breach_intel(failures)
    _check_key_probe(failures)
    _check_datastore_readiness(failures)
    _check_meeting_brief(failures)
    _check_export_switch(failures)
    _check_shared_hosting_attribution(failures)
    _check_checker_wiring(failures)
    _check_recommendation_priority(failures)
    _check_credential_failclosed(failures)
    _check_provider_budget(failures)
    try:
        from test_provider_transport_failures import run_checks as _provider_transport_checks
        _provider_transport_checks(install_paid_guard=_install_paid_egress_guard,
                                   blocked_egress=_BLOCKED_EGRESS)
        print("  [PASS] provider_transport:retry_timeout_circuit")
    except Exception as exc:
        failures.append(f"provider_transport: {exc}")
        print(f"  [FAIL] provider_transport: {exc}")
    _check_edge_measured_labelling(failures)
    _check_cdn_edge_detection(failures)
    _check_saas_service_ranges(failures)
    _check_no_own_estate(failures)
    _check_attribution_confidence(failures)
    _check_cdn_feed_table(failures)
    _check_origin_exposure(failures)
    _check_origin_candidate_boundary(failures)
    _check_single_asn_measured(failures)
    _check_sa_second_level_domains(failures)
    _check_export_mailbox_scope(failures)
    _check_default_cert_verdict(failures)
    _check_tls_port_gate(failures)
    _check_discovery_parity(failures)
    _check_gate_self_wiring(failures)
    _check_lookalike_ownership(failures)
    _check_lookalike_posture(failures)
    _check_table_headers(failures)
    _check_blocked_not_clean(failures)
    _check_base_path_links(failures)
    try:
        from verify_dashboard_auth import run_checks as _dashboard_auth_checks
        _dashboard_auth_checks()
    except Exception as exc:
        failures.append(f"dashboard_auth: {exc}")
        print(f"  [FAIL] dashboard_auth: {exc}")
    _check_scan_target_input(failures)
    _check_dehashed_credit_guards(failures)
    _check_score_scale_agreement(failures)
    _check_card_severity_equivalence(failures)
    _check_technical_card_measurement(failures)
    _check_exec_deck_credentials(failures)
    _check_report_degradation(failures)
    _check_balance_not_metered(failures)
    _check_hibp_and_waf_evidence(failures)
    _check_classification(failures)
    _check_cve_gating(failures)
    _check_techstack_eol(failures)
    _check_vpn_rdp_tarpit(failures)
    _check_dehashed_attribution(failures)
    _check_cred_calibration(failures)
    _check_subdomain_ct(failures)
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

    # Every scenario has run. Anything that tried to reach a metered provider
    # was blocked above, but blocking is invisible to the scenario itself
    # (guarded_call swallows the error and returns None), so assert it here.
    if _BLOCKED_EGRESS:
        uniq = sorted(set(_BLOCKED_EGRESS))
        failures.append(
            f"paid_egress: the gate attempted {len(_BLOCKED_EGRESS)} live call(s) to "
            f"metered providers ({', '.join(uniq[:4])}"
            f"{' ...' if len(uniq) > 4 else ''}). The gate runs on every push with the "
            "live keys loaded from .env, so this spends real credits every time — "
            "and a local run meters to SQLite, so it never shows up in the VM ledger. "
            "Stub the provider call in the scenario that reaches it.")
    print(f"  [{'PASS' if not _BLOCKED_EGRESS else 'FAIL'}] paid_egress:no_live_provider_calls  "
          f"attempted={len(_BLOCKED_EGRESS)}")

    print("=" * 70)
    if failures:
        print(f"ADVERSARIAL GATE FAILED ({len(failures)}):")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print(f"ADVERSARIAL GATE PASS — {len(SCENARIOS)} socket + {len(CLASSIFY_SCENARIOS)} "
          f"ip-attribution + {len(CVE_GATE_SCENARIOS)} cve-gating + "
          f"{len(TECHSTACK_EOL_SCENARIOS)} techstack-eol + {len(VPN_RDP_SCENARIOS)} "
          f"vpn-rdp + 1 dehashed-attr + {len(CRED_CALIB_SCENARIOS)} cred-calib + "
          f"{len(SUBDOMAIN_CT_SCENARIOS)} subdomain-ct + "
          f"{5 + len(BREACH_FAILSAFE) + len(BREACH_DEGRADED) + len(BREACH_LADDER)} breach-intel + "
          f"{len(KEY_PROBE_SCENARIOS)} key-probe + "
          f"{len(DATASTORE_SCENARIOS)} datastore-readiness + "
          f"{len(EXPORT_SWITCH_SCENARIOS)} export-switch + "
          f"{len(NON_CONCLUSIVE) * 2 + 11} credential-failclosed + "
          f"5 provider-budget + "
          f"{len(MX_SCENARIOS) + len(VERDICT_SCENARIOS) + 9} lookalike-posture + "
          f"3 table-header + "
          f"15 blocked-not-clean + 1 base-path + 2 balance-metering "
          "ground-truth scenarios")


if __name__ == "__main__":
    main()
