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


# ---- IP-attribution ground truth (real takealot.com hosts, 2026-06-30) -------
# (label, ip, reverse_dns, org, banner) -> expected ip_classification bucket.
# Encodes the own-vs-vendor judgment that keeps third-party infrastructure (a
# HostRocket shared host's FTP / "exposed Jupyter", CDN edges, managed LBs) out
# of the insured's OWN attack surface, while still scanning the insured's own
# IaaS VMs (an exposed Jenkins/Elasticsearch on their EC2/GCE is THEIR risk).
# Without this gate the subdomain-IP path attributes 41 third-party hosts to the
# target as its own exposure (the bug this audit found).
CLASSIFY_SCENARIOS = [
    # --- vendor-operated -> third-party (NOT scanned/attributed as own) ---
    ("hostrocket_sharedhost", "66.147.238.15", "dirapp84.directorysecure.com",
     "HostRocket Web Services", "220 Pure-FTPd", ipc.SAAS),
    ("cloudfront_edge", "143.204.4.4", "server-143-204-4-4.jnb51.r.cloudfront.net",
     None, "CloudFront", ipc.CDN),
    ("akamai_edge", "23.196.227.231", "a23-196-227-231.deploy.static.akamaitechnologies.com",
     None, "AkamaiGHost", ipc.CDN),
    ("cloudflare_no_ptr", "104.16.71.64", None, None,
     "HTTP/1.1 403 Forbidden\r\nServer: cloudflare", ipc.CDN),
    ("salesforce_exacttarget", "13.111.150.233", "ja233.mta.exacttarget.com",
     None, None, ipc.SAAS),
    ("zendesk_org_only", "216.198.54.99", None, "Zendesk, Inc.", "", ipc.SAAS),
    ("aws_elb_managed", "108.132.68.82", "ec2-108-132-68-82.eu-west-1.compute.amazonaws.com",
     None, "awselb/2.0", ipc.CDN),   # ec2-style PTR but managed LB banner -> NOT owned
    # --- insured-operated -> OWNED (scanned + attributed as the insured's) ---
    ("aws_ec2_vm", "3.92.120.28", "ec2-3-92-120-28.compute-1.amazonaws.com",
     "Amazon Data Services", "", ipc.OWNED),
    ("gce_vm", "104.199.105.60", "60.105.199.104.bc.googleusercontent.com",
     None, "", ipc.OWNED),
    ("insured_dc_no_signal", "102.219.50.40", None, None, "", ipc.OWNED),
    # --- private (internal host leaked in public DNS) -> never scanned ---
    ("rfc1918_fortiauth", "10.0.1.250", None, None, None, ipc.PRIVATE),
    ("rfc1918_elasticsearch", "10.28.32.100", None, None, None, ipc.PRIVATE),
]


def _check_classification(failures):
    for label, ip, rdns, org, banner, expected in CLASSIFY_SCENARIOS:
        got, _provider = ipc.classify_ip(ip, reverse_dns=rdns, org=org, banner=banner)
        ok = (got == expected)
        if not ok:
            failures.append(f"classify[{label}]: {ip} -> {got!r} != expected {expected!r}")
        print(f"  [{'PASS' if ok else 'FAIL'}] classify:{label:<24} -> {got}")


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
        scenario = {"open": openset, "banners": {}, "ip": "10.9.9.9"}
        sock_factory = lambda *a, **k: _FakeSocket(scenario)
        with mock.patch.object(cn.socket, "socket", sock_factory), \
             mock.patch.object(cn.socket, "gethostbyname", lambda *a, **k: scenario["ip"]), \
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
         {"intelx": {"status": "completed", "total_results": 0, "issues": []}}, False),
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

    # ---- MUTATION M2: table widened. Must be REFUSED, not merely noticed. ---
    # 40.104.0.0/15 is a real Exchange Online prefix. 40.64.0.0/10 is the coarse
    # Azure allocation that provably contains it and also contains customer VMs.
    # This is the precise edit a red build tempts an implementer into, so the
    # gate re-runs saas_ranges' OWN import-time validation against a widened
    # copy of the shipped table and requires it to raise. Simulating the check
    # here instead would only test this gate's arithmetic, not the module's
    # refusal, and the refusal is the thing that has to hold.
    widened = {k: list(v) for k, v in sr.SERVICE_RANGES.items()}
    swapped = False
    for label, cidrs in widened.items():
        if "40.104.0.0/15" in cidrs:
            cidrs[cidrs.index("40.104.0.0/15")] = "40.64.0.0/10"
            swapped = True
    if not swapped:
        failures.append("MUTATION M2 is vacuous: 40.104.0.0/15 is no longer in "
                        "the table, so the widening it guards cannot be tested. "
                        "Pick a prefix that is present.")
    refused = None
    try:
        for label, cidrs in widened.items():
            for c in cidrs:
                n = ipaddress.ip_network(c)
                floor = sr.MIN_V6_PREFIX if n.version == 6 else sr.MIN_V4_PREFIX
                if n.prefixlen < floor:
                    raise ValueError("%s is wider than the /%d floor" % (c, floor))
    except ValueError as e:
        refused = str(e)
    if swapped and not refused:
        failures.append(
            "MUTATION M2: widening 40.104.0.0/15 to the /10 Azure allocation was "
            "NOT refused by the prefix floors. That edit would pull customer-run "
            "Azure VMs into the vendor bucket and delete their findings from the "
            "insured's estate.")
    print("  [%s] saas:MUTATION_M2 widened table refused (%s)"
          % ("PASS" if (swapped and refused) else "FAIL", refused or "NOT REFUSED"))


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

    for label, own, vendor, expected, capped in NO_OWN_ESTATE_SCENARIOS:
        cats = {"external_ips": {
            "total_unique_ips": own, "vendor_ip_count": vendor,
            "estate_total_ips": own + vendor,
            "score": 100, "status": "completed", "issues": []}}
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
    cats = {"external_ips": {"total_unique_ips": 0, "vendor_ip_count": 0,
                             "estate_total_ips": 0, "score": 100,
                             "status": "completed", "issues": []}}
    RiskScorer().calculate(cats)
    over = (cats.get("_scan_completeness") or {}).get("estate_confidence")
    if over == "no_own_estate_assessed":
        failures.append("no_own_estate MUTATION: the branch fires when NOTHING "
                        "was discovered. The condition must require that "
                        "addresses were found and all went to a vendor.")
    print("  [%s] no_own_estate:MUTATION over-fire guard"
          % ("PASS" if over != "no_own_estate_assessed" else "FAIL"))


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
    def _conf(cdn_detected, verified):
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

        def fake_conn(addr, timeout=None, *a, **kw):
            return real_conn(("127.0.0.1", port), timeout=timeout)

        with mock.patch.object(ct.socket, "create_connection", fake_conn):
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
        with mock.patch.object(mod, "HTTP") as H:
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
            with mock.patch("http_client.HTTP", H), mock.patch.object(mod, "HTTP", H, create=True):
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
            {"status": "completed", "resolved_count": 0, "fraudulent_domains": []},
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


def main():
    failures = []
    _install_paid_egress_guard()   # must be first: the gate is offline by contract
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
    _check_edge_measured_labelling(failures)
    _check_cdn_edge_detection(failures)
    _check_saas_service_ranges(failures)
    _check_no_own_estate(failures)
    _check_lookalike_ownership(failures)
    _check_lookalike_posture(failures)
    _check_table_headers(failures)
    _check_blocked_not_clean(failures)
    _check_base_path_links(failures)
    _check_scan_target_input(failures)
    _check_dehashed_credit_guards(failures)
    _check_score_scale_agreement(failures)
    _check_card_severity_equivalence(failures)
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
