# Wave 7 Triage — leftover `fragile` / `arbitrary` heuristics

**Source:** the code-wide heuristics audit (`docs/heuristics_audit/00..06`, 2026-06-03).
**Method:** collected EVERY remaining `fragile` and `arbitrary` heuristic across the 6
modules, EXCLUDED the items already shipped in Waves 6a/6b, and assigned each a
**blast-radius tier** + **fix pattern** + **effort**. Calibration-gated heuristics are NOT
in this list (their *magnitudes* go to FIN-9) — see the count at the bottom.

**Blast-radius tiers**
- **A — feeds a score or a flag** (changes the underwriting number) → highest priority
- **B — reporting-only card** (cosmetic / narrative) → medium
- **C — calibration-overlap** (magnitude → FIN-9, but a logic-only correctness fix lands here) → low
- **D — data/feature work** (not heuristic hardening — coverage/feature build) → separate track

**Fix patterns:** boundary-match · `_probe` 200-gate · drift-marker ·
switch-to-live-feed (KEV/EPSS/endoflife.date) · document-rationale · feature-build.

**Already shipped (Waves 6a/6b) — EXCLUDED from every row below:**
B2C/PCI auto-detect over-broad; OSV synthetic-CVSS fabrication + OSV default-`medium` +
OSV pre-2015 drop (`checkers_threats._parse_vulns` now carries `cvss_estimated` /
`unknown` fallback — verified in code); SSL cipher bit-strength (`SHA256` suffix);
S-5 unknown-severity default; `total_checkers` fallback 27; and the loose-substring
family — SPF `all` mechanism, WAF **body** markers, WHOIS field-scoping,
`RISKY_KEYWORDS` label-boundary, the 7 VPN vendors 200-gate, EOL `7.1`≠`7.10`
boundary; dead SORBS list removed + `PORT_INTEL`/`RANSOMWARE_CVE_MAP` staleness markers.

---

## Triage table (sorted by tier — A first)

| Item | Module:loc | Tier | Feeds | Fix pattern | Effort |
|---|---|---|---|---|---|
| `active_theft_fresh` 90d cutoff (live-theft verdict) | scanner.py:133 | A | credential card critical/high **flag** → financial exposure | document-rationale (logic) / magnitude→FIN-9 | S |
| `recent_genuine` 360d cutoff (genuinely-recent breach) | scanner.py:146-147 | A | severity ladder **flag** | document-rationale (logic) / magnitude→FIN-9 | S |
| Severity ladder None→Critical (8-branch boundaries) | scanner.py:169-187 | A | headline "rotate now" **verdict** flag | document-rationale (branch order) / magnitude→FIN-9 | M |
| `COMBO_LIST_SOURCES` set (stale + exact-string match) | scanner.py:28-32,124-146 | A | `recent_genuine`/`all_combo` gate → credential **verdict** | drift-marker + boundary-match (substring/prefix) | M |
| OSV CVSS-from-severity `{crit:9.5,high:7.5,…}` (no `cvss_estimated` flag) | scanner.py:716 | A | `max_cvss` + CVE entry feeding `shodan_vulns` (0.07) | document-rationale (mark `cvss_estimated`, mirror L1121 fix) | S |
| `JSE_LISTED_DOMAINS` static map (snapshot 2026-05-15) | flag_inference.py:46-124 | A | listed-company **flag** → D&O/disclosure posture | drift-marker (review-date assertion) | S |
| `JSE_TICKER_RE` footer scrape (`JSE:` + 2-5 caps) | flag_inference.py:128,164 | A | medium-confidence listed **flag** | boundary-match (cross-check real ticker set) | S |
| B2C supporting overrides (`payment_form_detected`/`ecommerce_tech_detected` flip) | flag_inference.py:259-266,528-530 | A | B2C **flag** → CPA s112 cat stack | boundary-match (≥2 signals) / document-rationale | M |
| Insurance subtype regexes (`\bUMA\b`/`\bMGA\b` in 5k-char body) | flag_inference.py:304-367 | A | insurance-entity **flag** (B2B hard-negate) | boundary-match (weight domain/title over body) | S |
| Healthcare default `hospital_clinic` w/ `auto_detected=True` (no signal) | flag_inference.py:374-412 | A | healthcare sub-detail **flag** | document-rationale (`auto_detected=False` on default) | S |
| `PAYMENT_FORM_HINTS`/`ECOMMERCE_PLATFORM_HINTS` PCI form-hint side | flag_inference.py:431-446,465-480 | A | PCI **flag** suggestion | boundary-match (demote loose path/word hits) | M |
| OCSP fallback `ocsp_response is not None` (untrusted staple = stapled) | checkers_core.py:120 | A | SSL score −5 (`ssl_risk` 0.09) | document-rationale (prefer `_is_trusted`) | S |
| SSL key-size `<2048` gate trips EC keys (256/384 → false "weak key") | checkers_core.py:330-333 | A | SSL score −20 (`ssl_risk` 0.09) | document-rationale (skip gate for EC keys) | S |
| `WEAK_CIPHERS` stdlib path: exception → `is_weak:True, bits:0` | checkers_core.py:271-275 | A | SSL score (`ssl_risk` 0.09) | `_probe`-style (distinguish "could not assess" from "weak") | S |
| `resolved_ips` cap `[:80]` → `unique_ips_found` under-counts | checkers_network.py:235 | A | `unique_ips_found` count (subdomain card / surface) | document-rationale (record sampled-at-80) | S |
| GPD/MITIGATIONS regex e.g. `r"SSL.*grade.*(C\|D\|F\|T)"` mis-match | scoring_analytics.py:3063-3093 (MITIGATIONS) | A | remediation rsi/probability/bi deltas (sim output) | boundary-match (tighten patterns) | M |
| `web_ranking` default score 30 → risk 70 on absent | scoring_analytics.py:703 / L30 audit | A | `web_ranking` risk (penalty-on-absent) | document-rationale (redistribute, not bake-in) | S |
| `_consume` date parse (only `%Y-%m-%d`/`%Y/%m/%d`; drops ISO-T/`DD/MM/YYYY`) | scanner.py:89-101 | A | `dated_records` → recency completeness of credential card | document-rationale (add `fromisoformat`) | S |
| Privacy `REQUIRED_SECTIONS` keyword substrings (`child`/`update`/`contact us`) | checkers_threats.py:2362-2400 | A | `compliance_pct` → `privacy_compliance` (0.02) | boundary-match (≥2 hits per section) | M |
| `_split_domain` multi-TLD set misses `.gov.za`/`.web.za` | checkers_threats.py:2178 | B | typosquat apex (`fraudulent_domains` 0.04) — SA edge | document-rationale | S |
| IDN/permutation cap `[:60]` truncates before DNS check | checkers_threats.py:2261,2290 | B | resolved-count recall ceiling (`fraudulent_domains`) | document-rationale (order high-similarity first) | S |
| `CMS_SIGNATURES` substrings (`shopify.com`/`squarespace.com` in any asset) | checkers_threats.py:69-78; checkers_core WebSec 250-258 | B | CMS attribution (reporting-only) | boundary-match (generator-meta / first-party) | S |
| EPSS thresholds `>0.4`/`>0.5` uncited (issues text) | checkers_threats.py:755,777; scanner.py:749,814 | C | issues text + maturity label (magnitude→FIN-9) | switch-to-live-feed / document-rationale | S |
| CVE caps `[:20]/[:10]/[:30]` + tail forced to `medium_count` | checkers_threats.py:546,568,653,730,825 | B | `medium_count` display (severity fabrication on tail) | document-rationale (relabel tail `unknown`) | M |
| Patch-mgmt age bands 365/180/90 uncited | checkers_threats.py:844-888; scanner.py:779 | B | patch-posture narrative buckets | document-rationale (cite CISA BOD 22-01) | S |
| `KNOWN_BREACH_DATES` combo-list fallback dates (stale) | checkers_threats.py:1817-1828 | B | recency band display | drift-marker (review-date) | S |
| `_STEALER_TOKENS` (`autofill`/`screenshot`/`default.txt`) FP surface | checkers_threats.py:1996-2013; darkweb_providers 106-122 | B | darkweb reclassification (reporting-grade) | boundary-match (token AND leak/log bucket) | S |
| `darkweb_providers` Snusbase/LeakCheck table-name substrings (unverified live) | darkweb_providers.py:201-253 | B | provider table→class map (reporting) | document-rationale (verify vs real vocab) | S |
| `PaymentSecurity` self-hosted-form regex, no HEAD/WAF gate | checkers_threats.py:380-417 | B | PCI self-hosted-form finding (reporting) | `_probe` 200-gate | M |
| `EOL_SIGNATURES` no automated drift test (refresh-dated only) | checkers_threats.py:20-67 | C | EOL hit → `tech_stack` 0.05 (magnitude→FIN-9) | drift-marker (clone Wave-5 vendor-DB test) | S |
| `SERVICE_INTEL` point-in-time CVSS/EPSS/KEV strings | checkers_network.py:756-842 | B | service narrative (not score) | drift-marker / switch-to-live-feed (EPSS) | M |
| `TAKEOVER_SIGNATURES` no `last_verified` + drift test | checkers_network.py:32-62 | B | takeover fingerprint (display + local score) | drift-marker | S |
| robots.txt `disallows_count` counts on any 200 body | checkers_network.py:937-939 | B | `disallows_count` (informational) | `_probe` 200-gate (content-type) | S |
| OpenVPN `/` root-path probe (marketing-copy match) | checkers_network.py:353-355 | B | VPN-detection narrative (post-200-gate) | `_probe` 200-gate (login-form context) | S |
| `DKIM_SELECTORS` 38-name list (a miss ≠ "no DKIM"; over-claims) | checkers_core.py:373-393,566 | B | DKIM issue text (probe-miss as absence) | document-rationale (never assert "no DKIM") | S |
| SSL `best = all_accepted[-1]` (list-position "highest version") | checkers_core.py:155 | B | "best cipher" display | document-rationale (pick by TLS label) | S |
| DANE TLSA probes primary-MX only | checkers_core.py:629-642 | B | DANE-absent narrative | document-rationale / feature (probe all MX) | S |
| WHOIS creation/expiry positional `[0]` (may not be authoritative) | checkers_core.py:1036-1039 | B | domain-age display | boundary-match (`min(creation)`/`max(expiry)`) | S |
| Exposed-admin body-sanity slices (`404`/`not found` naked substring) | checkers_core.py:1138-1143 | B | could reject a real file starting "404" (false-neg, safe) | boundary-match (standalone tokens) | S |
| Cred-risk recency band `year ≥ 2023 = recent` (silently ages) | checkers_threats.py:1925 | C | recent/old split feeding cred ladder (magnitude→FIN-9) | document-rationale (rolling window) | S |
| Cred-risk `pastes > 3` vs IntelX `paste_count > 5` inconsistency | checkers_threats.py:1871 vs 2102 | C | paste factor gate (magnitude→FIN-9) | document-rationale (reconcile thresholds) | S |
| `SecurityTrails` "associated > 50" cut; ST `score` inert at 100 | checkers_threats.py:1595 | B | shared-hosting issue text (ST weight inert) | document-rationale | S |
| `Glasswing PARTNERS` static 12 + `"glasswing"+"anthropic"` body probe | checkers_threats.py:2682-2743 | C | favourable −0.05 RSI credit (magnitude→FIN-9) | drift-marker + boundary-match | S |
| `WebRanking` Tranco bands + popularity-as-protective semantics | checkers_threats.py:2641-2652 | C | `web_ranking` score (semantics + magnitude→FIN-9) | document-rationale (clarify direction) | S |
| `loss_pct → fin_score` step function + 0.02-weight circularity | scoring_analytics.py:2786-2798 | C | `fin_risk` back into posture (magnitude→FIN-9) | document-rationale | S |
| DBI `severe-class` set + `credential_leaks`/`breach_count` cutoffs | scoring_analytics.py:3234-3289 | B | DataBreachIndex points (display index, not p_breach) | drift-marker (HIBP `data_classes`) | S |
| `record_density_divisor` / `records_validity_ceiling` (unsourced) | scoring_analytics.py:2180-2257 | B | est-records **disclosure only** (not in cost calc) | document-rationale | S |
| `SHARED_INFRA_SUFFIXES` (S-1 discovery + related_domain) stale | checkers_supply_chain discovery:62-75; related_domain_discovery.py:62-75 | C/D | sibling candidate suggestions (broker/auto-verify gated) | drift-marker | S |
| `KNOWN_MULTI_PART_TLDS` hand-rolled PSL subset | related_domain_discovery.py:80-102; discovery:80-88; http_client.py:62-94 | C/D | apex reduction / rate-limit key (mild) | feature-build (`publicsuffix2`) | M |
| `_confidence_for` cnt 5/3 + 5-char-prefix shared-root | related_domain_discovery.py:178-194; discovery:178-194 | C | broker-weighting confidence (no score) | document-rationale | S |
| WAFTracker thresholds (blocked≥40%, window=20) | http_client.py:173,232-243 | C | partial-coverage **disclaimer** (not score) | document-rationale | S |
| WAF-affected = `completed` + empty `issues` (conflates clean/blocked) | scanner.py:1144-1162 | B | partial-coverage disclaimer (gated, not score) | `_probe`-style (prefer `status:timeout/no_data`) | S |
| `S-2 KNOWN_COMPROMISED_HOSTS` tight allow-deny (new-incident lag) | checkers_supply_chain.py:526-531 | D | Magecart +60 penalty + uplift (coverage) | feature-build (threat-feed refresh) | M |
| `S-10 POPULAR_PLUGINS` 25-slug list (coverage) | checkers_supply_chain.py:849-875 | D | plugin SBOM coverage (readme-gated) | feature-build (refresh from wordpress.org) | S |
| `vendor_breaches.json` SA-exposure coverage gaps | `vendor_breaches.json` + S-4:681-724 | D | S-5 breach correlation (coverage) | feature-build (add SA vendors) | M |
| S-4 `VENDOR_PATTERNS` ↔ breaches.json asymmetry (18/25 no breach row) | checkers_supply_chain.py:681-724 | D | S-4/S-5 correlation completeness | feature-build (add Mimecast/Proofpoint/Pinpoint) | M |
| S-1 uplift dormant absent broker list (cert-SAN auto-promote) | checkers_supply_chain.py:38-55; flag_inference.py:539-554 | D | Civil-liability +0.04 (dormant — feature) | feature-build (TLS-cert-match auto-promote) | L |
| S-1 `high_count` `<60` cutoff (cosmetic) | checkers_supply_chain.py:116-117 | B | issue string + remediation row (not uplift) | document-rationale | S |

---

## Recommended Wave 7 scope (Tier-A only)

Wave 7 should fix the **19 Tier-A items** — the heuristics that still move a score or a
flag. They cluster into three buckets, all free (correctness/robustness, no calibration):
**(1) the credential-verdict path** — the 90d/360d cutoffs, the 8-branch severity ladder,
and the stale exact-string `COMBO_LIST_SOURCES` gate together set the headline "rotate
now" verdict, so document/boundary-harden the *logic* (cutoff magnitudes still go to
FIN-9) and add a drift-marker; **(2) the `flag_inference` flag surface** — the
`JSE_LISTED_DOMAINS`/footer-ticker listed flags, the B2C/PCI supporting overrides, the
`\bUMA\b` body-acronym insurance match, and the no-signal `hospital_clinic` default,
which all flip a flag that changes regulatory/D&O exposure (require ≥2 signals, cross-check
ticker sets, mark unconfirmed defaults `auto_detected=False`); **(3) the SSL/score-input
correctness trio** — OCSP untrusted-staple, the EC-key `<2048` false-"weak", and the
stdlib-error "weak" default, plus the `web_ranking` penalty-on-absent, the MITIGATIONS
regex mis-match, the `[:80]` IP-count undercount, the ISO-date drop, and the
privacy-section loose keywords. The unflagged-but-live **OSV CVSS-from-severity at
scanner.py:716** rides along — mirror the `cvss_estimated` flag already added to its
`_parse_vulns` sibling. Everything is boundary-match / `_probe`-gate / drift-marker /
document-rationale; no magnitude is touched.

## Counts per tier

| Tier | Meaning | Count |
|---|---|---|
| **A** | feeds a score or a flag | **19** |
| **B** | reporting-only card | **22** |
| **C** | calibration-overlap (logic-only fix here, magnitude→FIN-9) | **11** |
| **D** | data/feature work (separate track) | **6** (+2 dual-tagged C/D) |
| **Total fragile/arbitrary triaged** | | **58** |

**Calibration-gated (NOT triaged here — magnitudes → FIN-9):** ~74 across all modules
(the dominant bucket lives in `scoring_analytics.py`, ~36 of its 56 heuristics). These are
flagged with anchors in the audit and are **not** intuited; Wave 7 touches only the
logic-only correctness sub-fixes that overlap them (the Tier-C rows).

*Note: a handful of audit rows carry a primary `fragile`/`arbitrary` class plus a secondary
flag; each is counted once under its dominant tier. Two PSL-subset rows (`SHARED_INFRA_SUFFIXES`,
`KNOWN_MULTI_PART_TLDS`) span discovery + http_client and are dual-tagged C/D.*
