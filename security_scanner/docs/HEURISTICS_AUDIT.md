# Phishield Scanner — Code-Wide Heuristics Audit

# Code-Wide Heuristics Audit — Executive Summary

**Date:** 2026-06-03
**Method:** the new Card Verification Protocol **Step 6** applied code-wide — 6 module-owner agents enumerated every heuristic (hardcoded threshold, magic constant, multiplier, cap, fingerprint/substring, fallback default, status rule, curated table), screened each against the five back-test failure modes, and classified it. White-box, read-only, no credits, against fixed-code data (`test_fixtures/phishield_live.json`).
**Scope:** ~232 heuristics across `checkers_core`, `checkers_network`, `checkers_threats`, `checkers_supply_chain`, `scoring_analytics`, `scanner.py` + supporting.

## Tally

| Class | ~Count | Meaning |
|---|---|---|
| **justified** | ~93 | has an empirical/documented basis — leave |
| **fragile** | ~67 | works on the sample, brittle elsewhere — harden (free) |
| **arbitrary** | ~22 | no rationale — document or remove |
| **calibration-gated** | ~74 | scoring magic-number — value belongs to FIN-9, NOT intuited |

All Waves 1-5 fixes re-screened **clean** across every module.

## New correctness bugs (not in the original back-test)

| # | Bug | Module | Severity | Failure mode |
|---|---|---|---|---|
| 1 | **B2C/PCI auto-detect over-broad** — `PAYMENT_FORM_HINTS` matches generic `/cart`, "add to cart", Product JSON-LD, so a B2B site can auto-tick **B2C** → adds CPA s112 (10% turnover / R1M) to the cat stack, inflating regulatory + financial exposure | `flag_inference.py:431` | **HIGH** | generic-response-as-signal |
| 2 | **OSV synthetic-CVSS fabrication** — invents a numeric CVSS from a vector when the source has none → feeds CVE/RSI | `checkers_threats.py:1104` | medium | fabrication on absent input |
| 3 | **SSL cipher bit-strength mislabel** — `256 if "256" in name` matches the `SHA256` suffix → `AES_128_..._SHA256` renders as 256-bit | `checkers_core.py:160` | low (rendered) | wrong parse |
| 4 | **S-5 unknown-severity default 5 > low's 3** — a mild inversion (unknown treated worse than low) | `checkers_supply_chain.py` | low | inversion |
| 5 | **`total_checkers` stale fallback 27** vs the authoritative 31 (`len(WEIGHTS)`) | `scanner.py` | low | stale constant |

## Dominant theme — the "loose-substring" family (fragile)

The single biggest pattern: a **substring match against a whole string** treated as a positive signal — the same class as the WAF/F5 and DNSBL bugs, but spread across more checkers. All free word-boundary / probe-gate fixes:
- SPF `"all" in txt` (incidental match); WAF **body** markers (`"cloudflare"` in page text → phantom WAF bonus); WHOIS privacy keywords vs the whole blob.
- `RISKY_KEYWORDS` via `any(k in fqdn)` (flags `api.`, db-brands, even the apex) → inflates `risky_subdomains` → `sub_risk × 15`.
- VPN signatures: only RDS got the `require_200` gate in Wave 2 — the **other 7 vendors still match a token in any response** (soft-404 / marketing); apply the S-3 `_probe` gate uniformly. Plus `vpn_risk` "no VPN page = +20" risks inverting against ZTNA orgs.
- EOL substring mis-matches `7.1` vs `7.10`.

## Stale curated tables — extend the Wave-4/5 drift-test pattern

Several hardcoded tables silently go stale and have no drift test: `dnsbl.sorbs.net` (SORBS **ceased mid-2024** — likely dead), `PORT_INTEL`/`SERVICE_INTEL` (point-in-time CVSS/EPSS/KEV), `TAKEOVER_SIGNATURES`, `RANSOMWARE_CVE_MAP`, `KNOWN_BREACH_DATES`, `COMBO_LIST_SOURCES` (a new combo dump reads as fresh compromise), `JSE_LISTED_DOMAINS`, `SECTOR_FRAMEWORKS` statutory maxima, `SA_INDUSTRY_COSTS`. Clone the Wave-5 `vendor_breaches` drift-warn for each + add dated-review markers.

## Calibration-gated (~74) — consolidated for FIN-9

The large bucket is, correctly, **calibration not correctness** — flagged with anchors, never intuited. The highest-leverage constants (extends OUTSTANDING §6b):
1. `0.3` in `p_breach = vulnerability × TEF × 0.3` (scoring_analytics.py:2107) — scales every breach probability; unvalidated since Wave 1 made the coupling live.
2. `vulnerability = (100 − _overall_score/10)/100` (L2038) — the posture→probability curve, first time on a real score.
3. `dehashed_total × 2` (L677) — the confidence-blind credential input (the 5L problem).
Plus the CredentialRiskClassifier ladder (−50/−20/−30/−15/−10/−3, uncapped `darkweb×10`/`paste×3`, **HR recency computed-but-never-applied** — OUTSTANDING §6), the supply-chain penalty constants + `+0.15` cap + `1825d` lookback, RSI factor sizes, `K_TAIL=1.20`, `COST_PER_RECORD`/`REGULATORY_FINE`, HIBP step thresholds, EPSS 0.4/0.5, recency cutoffs 90d/360d.

## Recommendation

**A "Wave 6" (all free, correctness + robustness — no calibration):**
1. The 5 new correctness bugs — lead with **#1 (B2C auto-detect)**: it mis-prices regulatory exposure on B2B sites, so it directly affects the financial output FIN-9 will calibrate. Harden to ≥2 signals or broker-confirm.
2. The loose-substring family — apply word-boundary matching + the S-3 `_probe` gate uniformly (esp. the 7 remaining VPN vendors).
3. The stale-table drift tests — clone the Wave-5 pattern.

**Calibration (~74 constants) → FIN-9 / 5L**, per OUTSTANDING §6/§6b — the audit hands the session a complete, anchored parameter inventory.

**Rating note:** these are mostly *robustness* improvements on already-fixed-and-verified output (the scanner sits at ~8.5/10 post-Wave-5). The one item that moves the needle is #1 (B2C auto-detect), because it can mis-classify regulatory exposure. Wave 6 + the FIN-9 calibration are the path to a defensible 9.

*Per-module detail follows.*


---

# checkers_core.py — Heuristics Audit

**Module:** `security_scanner/checkers_core.py` (SSL/TLS, Email Security DNS,
Email Hardening, HTTP Security Headers, WAF, Cloud/CDN, Domain Intel/WHOIS,
Exposed Admin).
**Protocol:** Step 6 (white-box heuristics sweep) of `docs/card_verification_protocol.md`.
**Reference fixed-code data:** `test_fixtures/phishield_live.json` (live phishield.com scan).
**Scope note:** Waves 1-5 already hardened SSL (sslyze-6.x cert API), WAF (F5
markers), DKIM (`v=DKIM1` / `p=` gate), Exposed-Admin (200-only + body sanity),
and HTTP-headers (non-2xx guard). Those are **confirmed clean against the
fixture** (re-checked below) and this audit focuses on the REMAINING heuristics.

Class legend: `justified` (defensible, basis stated) / `fragile` (works on the
sample, brittle elsewhere — hardening proposed) / `arbitrary` (no rationale —
document or remove) / `calibration-gated` (scoring magic-number whose VALUE
belongs to the calibration session — FLAGGED, not intuited).

Scoring context (downstream consumers in `scoring_analytics.py`):
`ssl_risk = inv(ssl.score, default 50)`; `email_risk = inv(score/10*100, default 5)`;
`email_hard_risk = inv(score/10*100, default 0)`; `header_risk = inv(http_headers.score, default 50)`;
`admin_risk = min(100, crit*50 + high*20)`; WAF presence yields a category bonus.
So every SSL/email/header `ded`/`score` constant is a **scoring** magic-number.

---

## SSLChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `WEAK_CIPHERS = [RC4,DES,3DES,MD5,NULL,EXPORT,ANON,RC2]` | L14 | Substring list flags weak cipher fragments | Loose-substring screen: each token is specific enough (no false hits on modern AEAD names like AES_GCM/CHACHA20); `DES`⊄`AES`/`3DES`-safe. Curated-table: stable (these never become "strong"). | justified | Keep. Empirically sound TLS-weak set; no drift risk. |
| `bits = 256 if "256" in name else (128 if "128" in name else 0)` | L160 | Infers cipher strength from name substring | **Fragile / data-quality bug:** fixture shows `name=TLS_AES_128_CCM_SHA256` → matched on the `SHA256` and reported **bits=256** for an AES-**128** cipher. Substring is checked against the WHOLE name incl. the hash. Not scored today, but rendered. | fragile | Parse bits from the cipher token only (regex `AES_(\d+)` / `_(128\|256)_`), not the hash suffix; or read sslyze's `key_size`. Free, deterministic. |
| `best = all_accepted[-1]` ("last = highest version") | L155 | Picks "best" cipher as last accepted suite | Order assumption: relies on tls_map iteration order (1.0→1.3) + extend order; brittle if a version block is empty/reordered. Cosmetic only (display), not scored. | fragile | Select explicitly by highest negotiated TLS label present, not list position. Low priority (display-only). |
| Cert `valid = chain_valid AND hostname_match AND days_left>=0` | L102 | Composite validity gate | Inversion/fabrication screen: clean — on sslyze parse error it re-`raise`s (L127) so `certificate={}` does NOT silently brand cert invalid (the Wave-1 fix). Confirmed: fixture `valid:True`. | justified | Keep (Wave-1 hardened). |
| `expiring_soon = 0 <= days_left <= 30` | L112,233 | 30-day expiry window | Threshold: 30d is the CA/Browser-forum renewal-alert norm; matches ACME auto-renew lead time. | justified | Keep; cite 30d = industry renewal-alert standard. |
| `_hostname_matches` wildcard: `host.count(".")==name.count(".")` | L199 | RFC6125 single-label wildcard match | Loose-match screen: correctly rejects bare apex vs `*.` and multi-label; label-count guard is the RFC-6125 rule. | justified | Keep. Correct RFC-6125 behaviour. |
| OCSP fallback `dep.ocsp_response is not None` | L120 | Treats any OCSP response as "stapled" | Fabrication-ish: when `ocsp_response_is_trusted` is None it falls back to presence-only (untrusted staple counts as stapled). Low impact (−5 only). | fragile | Prefer the `_is_trusted` boolean; treat unknown as `None` (no deduction) rather than "present". |
| **Grade deductions** `40/40/20/15/20/30/25/20/10/30/20/10/5/5` | L320-360 | Per-issue point deductions → 0-100 score | Calibration screen: these are the SSL **score** magic-numbers; `ssl.score` feeds `ssl_risk` at weight 0.09. No single value is wrong, but the relative sizing (e.g. missing-CAA −5 vs TLS1.0 −20 vs invalid-cert −40) is unanchored. | calibration-gated | FLAG for FIN-9. Do not retune here; anchor relative weights to an external SSL grading rubric (e.g. SSL Labs / Mozilla TLS) in the calibration pass. |
| Grade bands `A+>=95, A>=85, B>=70, C>=55, D>=40, F` | L363 | Maps score→letter grade | Calibration: band cutoffs are arbitrary-but-conventional; cosmetic (grade not scored, score is). | calibration-gated | FLAG with the deductions; align bands to whichever rubric the deductions are calibrated against. |
| Key-size gate `<2048 → −20; <4096 → pass` | L330-333 | Penalises sub-2048 RSA only | Threshold: 2048 = NIST SP800-57 / CA-Browser minimum; the dead `<4096 elif: pass` is a no-op. Note: ECDSA key_size (256/384) would trip `<2048` → false "weak key". Fixture is RSA-2048 (clean). | fragile | Add curve awareness: skip/relabel the 2048 gate for EC keys (key_size 256/384 are strong). Free check on key type. |
| `WEAK_CIPHERS` re-applied to stdlib path bits=`c[2] or 0` | L271-275 | stdlib fallback cipher strength | Fabrication screen: on exception returns `is_weak:True, bits:0` — a hard-fail default that biases toward "weak". Defensible (fail-closed) but can over-penalise on a transient stdlib error. | fragile | Distinguish "could not assess" from "weak" so a connect error doesn't read as a weak-cipher finding (mirror the headers `unreachable` pattern). |

## EmailSecurityChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `DKIM_SELECTORS` (38 names) | L373-393 | Brute-probes common DKIM selectors | Curated-table + boolean-as-count: list will drift as ESPs add selectors; **a miss ≠ "no DKIM"** (selectors are unbounded). Wave fix on `_probe` (L519 `v=dkim1`/`p=` gate) correctly stops wildcard-TXT false positives — confirmed (fixture found only `k2`). | fragile | Keep the probe gate (clean). For the list: document it as best-effort, never assert "no DKIM"; the score text (below) already over-claims. Add selectors opportunistically. |
| Issue text "across 40 common selector names" | L566 | Hardcoded "40" | **Boolean/count mismatch (cosmetic):** list has **38** entries, message says 40 — silently stale. | arbitrary | Replace literal with `len(self.DKIM_SELECTORS)`; remove the magic "40". |
| SPF `valid = has_all OR has_redirect` | L425 | Validity = presence of `all`/`redirect` | Loose-substring: `has_all = "all" in txt` matches the substring "all" ANYWHERE (e.g. a domain literally containing "all", or `mx:mail.smallco.com`), not the `-all`/`~all`/`+all` mechanism. Over-counts valid. | fragile | Match the qualifier mechanism `[-~?+]all\b` at a word boundary, not bare `"all" in txt`. Free regex. |
| SPF `dangerous = "+all" in txt` | L430 | Flags permissive `+all` | Substring: `+all` is specific; correct. | justified | Keep. |
| SPF `exceeds_lookup_limit = dns_lookups > 10` | L433 | RFC 7208 10-lookup cap | Threshold: 10 is the literal RFC 7208 §4.6.4 limit. The counter (`_count_spf_lookups`) regex-counts `a`/`mx`/`include`/`exists`/`redirect` with `depth>5` recursion guard and `includes[:5]` truncation — under-counts deep chains but won't fabricate. Fixture: 11 lookups flagged, plausible. | justified | Keep threshold (RFC). Note counter may under-report (truncation) — acceptable, fail-low not fail-high. |
| SPF lookup counter `depth>5` / `includes[:5]` caps | L442,454 | Recursion + breadth caps | Arbitrary caps: 5/5 are unstated. They bound runtime; risk is under-count on pathological SPF, not a false finding. | arbitrary | Document the 5/5 as DoS/runtime guards; note they can under-report lookup count on very deep chains. |
| DMARC `policy = p=(\w+)` else `"none"` | L483-484 | Extract policy, default none | Fabrication screen: defaults to `"none"` only when `p=` absent in a present DMARC1 record (malformed) — that IS effectively no enforcement, so the default is conservative-correct. | justified | Keep. |
| DMARC `pct` default `100` (present) / `0` (absent) | L487,503 | Percentage enforcement | Justified: RFC default for pct is 100; absent-record uses 0 (won't trigger partial-enforcement penalty falsely). | justified | Keep (RFC default). |
| `subdomain_policy` defaults to `policy` | L490 | sp= inherits p= | Justified: RFC 7489 — sp defaults to p when omitted. | justified | Keep (RFC). |
| **Email score** start `10`; SPF −3/−3/−1/−1; DMARC −4/−2/−1/−1; DKIM −2 | L541-566 | Builds 0-10 email score | Calibration: these feed `email_risk` (default 5). Relative sizing (DMARC-absent −4 vs DKIM-absent −2 vs SPF-absent −3) is plausible-but-unanchored; DKIM −2 is harsh given selector-probe is best-effort (a real DKIM with an uncommon selector → false −2). | calibration-gated | FLAG for FIN-9. Especially reconsider the DKIM −2: probe-miss is not proof-of-absence. Anchor to DBIR/M3AAWG email-auth posture data. |

## EmailHardeningChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| MTA-STS mode via `re.search(r"mode:\s*(\w+)")` on policy file; fallback `"unknown"` | L608-611 | Reads enforce/testing mode | Fabrication screen: clean — on fetch failure sets `"unknown"`, and scoring only awards the +2 bonus when `mode=="enforce"`, so unknown ≠ enforce. | justified | Keep. |
| BIMI `has_vmc = "a=https" in txt.lower()` | L623 | VMC presence via `a=` tag | Loose-substring: `a=https` is the BIMI VMC evidence tag; specific enough. | justified | Keep. |
| DANE: TLSA on `_25._tcp.{primary MX}` only | L629-642 | Probes only lowest-pref MX | Coverage gap (not a false signal): checks only the primary MX; a domain with DANE on secondary MXs but not primary reads as "absent". Conservative (won't fabricate present). | fragile | Probe all MX hosts (or document "primary-MX only"). Free DNS. Low priority. |
| **Hardening score** MTA-STS +4(+2), BIMI +2(+1), DANE +1, TLS-RPT +1, `min(score,10)` | L665-683 | Builds 0-10 hardening score | Calibration: feeds `email_hard_risk` (default 0 → absent reads as MAX risk via `inv`). The +4 MTA-STS vs +2 BIMI vs +1 DANE sizing is unanchored; BIMI (a brand/deliverability feature) scoring nearly as high as DANE (a security control) is questionable. | calibration-gated | FLAG for FIN-9. Reconsider BIMI weight vs DANE/MTA-STS on a security basis. Note default-0 means a failed/`status:error` hardening check penalises as if fully absent. |

## HTTPHeaderChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| Non-2xx guard → `status:"unreachable"`, drop score/headers | L796-811 | Skips header scoring on WAF/CDN 403/503/429 | Inversion screen: **clean** — this IS the Wave-5 fix; fixture confirms phishield 403 → `unreachable`, no penalty. Downstream falls back to neutral 50. | justified | Keep (Wave-5 hardened). Reference pattern for the SSL stdlib-error case above. |
| Header weights CSP 10, XFO 15, XCTO 15, HSTS 20, Referrer 15, Permissions 15 | L692-699 | Per-header earned/total weighting | Calibration: weights set the header sub-score that becomes `header_risk`. Permissions-Policy weighted equal to XCTO/Referrer (15) despite far lower real-world security value; HSTS 20 is defensible (transport security). Unanchored relative sizing. | calibration-gated | FLAG for FIN-9. Anchor to a header-importance rubric (e.g. Mozilla Observatory weights). Don't retune here. |
| CSP quality base `50`; dangerous −15 each; missing-critical −8 each; bonuses +20/+10/+10/+10 | L758-771 | 0-100 CSP quality sub-score | Calibration: nested magic-numbers feeding a `round(score/10)` 0-10 bonus. Internally plausible (Observatory-like) but unanchored. | calibration-gated | FLAG for FIN-9. Cite/borrow Mozilla Observatory CSP scoring rather than bespoke constants. |
| `CSP_DANGEROUS` + `CSP_CRITICAL_DIRECTIVES` lists | L702-709 | Pattern/directive curation | Curated-table: these are stable CSP semantics (unsafe-inline/eval/*/data:); directive set is the standard critical set. Wildcard checked in `script-src` specifically (good — avoids generic `*` false hit). | justified | Keep. Stable CSP spec, low drift. |
| `csp_bonus = round(quality/10)` added to `earned` | L829 | Folds CSP quality into score | Logic: adds up to +10 earned AND +10 to total_weight (L831) whether or not CSP present (L839) — symmetric, no inflation. | justified | Keep. |

## WAFChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `WAF_SIGNATURES` header/cookie/body/server markers | L852-895 | Fingerprint table for 7 WAFs | Curated-table + Wave-2 fix: F5 `x-frame-options`/`ts` removed (ubiquitous-header inversion) — confirmed clean. Remaining markers are vendor-specific. Table will drift (new WAFs/renamed headers) but won't fabricate. | justified | Keep (Wave-2 hardened). Document as best-effort; absence ≠ "no WAF" (already only a recommendation, not a hard score). |
| Body match on `r.text[:5000].lower()` substrings (`cloudflare`,`sucuri`,`incap_ses`…) | L912,929 | Body-substring WAF detection | Loose-substring screen: `"cloudflare"`/`"sucuri"` in body could match incidental page text (e.g. a blog mentioning Cloudflare) → false WAF-positive → phantom WAF bonus in scoring. Header/cookie matches are safe; body is the weak channel. | fragile | Tighten body markers to error-page/challenge fingerprints (e.g. `Attention Required! \| Cloudflare`, `Access Denied - Sucuri`), not bare vendor names. Free string change. |
| Cookie prefix-match `name==c or name.startswith(c)` | L926 | Matches dynamic-suffix vendor cookies | Wave-fix: enables `BIGipServer<pool>`/`TS01<hex>`; prefixes are specific. | justified | Keep. |
| `waf_name = detected[0]` (first match wins) | L941 | Reports single WAF when multiple match | Minor: arbitrary tie-break by dict order; `all_detected` preserved so no data loss. | justified | Keep (full list retained). |

## CloudCDNChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `CLOUD_CNAMES` suffix table (9 providers) | L955-965 | CNAME-suffix → provider | Curated-table: leading-dot suffixes (`.cloudfront.net`) are anchored enough to avoid false hits; drift risk is missing a NEW provider (false-negative, safe), not false-positive. | justified | Keep; document as non-exhaustive. |
| CNAME chase `range(5)` | L989 | Caps CNAME-chain follow at 5 | Arbitrary cap: 5 is unstated but bounds a pathological chain; under-follow only → false-negative, safe. | arbitrary | Document 5 as a loop-DoS guard. |
| `hosting_type = "self-hosted or undetected cloud"` when no CNAME match but IPs exist | L1009 | Fallback label | Fabrication screen: honest fallback ("undetected"), not invented certainty. Not scored. | justified | Keep. |

## DomainIntelChecker (WHOIS)

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| Age bands `<365d` and `<730d` → fraud-risk issues | L1047-1050 | Young-domain flag | Threshold: 1yr/2yr are common newly-registered-domain (NRD) heuristics; reasonable for fraud/typosquat context. Not a hard score (issue text only). | justified | Keep; cite NRD-age convention. |
| Expiry `<30d → renewal risk` | L1055 | Imminent-expiry flag | Threshold: 30d is a sensible renewal-alert window. | justified | Keep. |
| `privacy_keywords = [redacted,privacy,withheld,protected,proxy]` on `str(w).lower()` | L1060-1061 | Detects WHOIS privacy | **Loose-substring screen:** matching against the WHOLE stringified WHOIS object is broad — `"protected"`/`"proxy"` can appear in unrelated fields (registrar names, status URLs, nameservers like `*.proxy.*`), risking false "privacy_protected". `privacy_protected` is informational (not scored) but can mislead attribution. | fragile | Match only registrant/admin contact fields, not the whole blob; or require ≥2 keyword hits. Free. |
| `creation/expiry` list→`[0]` (first element) | L1036-1039 | Picks first date when WHOIS returns a list | Fabrication-ish: some registries return multiple dates; `[0]` may not be authoritative. Low impact. | fragile | Prefer `min(creation)`/`max(expiry)` over positional `[0]`. Low priority. |

## ExposedAdminChecker

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| 200-only + body-sanity gate (`<10` len, `<html`/`<!doctype`, `not found`/`404`) | L1126-1145 | Confirms real exposure | Inversion screen: **clean** — Wave-1 fix; 401/403/3xx/404 no longer count, HTML shells rejected. Fixture: `exposed:[]`, counts 0. | justified | Keep (Wave-1 hardened). Reference pattern. |
| `PATHS` critical/high/medium wordlists (38 paths) | L1076-1095 | Sensitive-path enumeration list | Curated-table: stable, well-known sensitive paths; risk-tier assignment (`.env`=critical, `/admin`=high) is conventional and sound. | justified | Keep; conventional sensitive-path set. |
| Body sanity `len(text) < 10` and `head = text[:300]` / `[:200]` / `[:50]` slices | L1138-1143 | Rejects trivial/error bodies | Arbitrary slice constants (10/300/200/50): pragmatic body-shape checks; risk is a marginal real exposure with a tiny body being missed (false-negative, safe). `404` in first 50 chars could rarely reject a legit file whose body starts with "404". | fragile | Document the slice thresholds; consider matching `404`/`not found` as standalone tokens rather than naked substrings to avoid rejecting a real file literally containing "404…". Low priority. |
| `max_workers=3`, `as_completed timeout=90`, `HTTP.discover timeout=6` | L1156,1159,1117 | Concurrency/wall/probe budgets | Arbitrary-but-justified: documented (SCN-025) as rate-limiter-paced (2 req/s); 90s wall sized to ~38 probes. Operational, not a scoring signal. | justified | Keep (documented rationale present). |

---

## Summary

total=33 justified=18 fragile=10 arbitrary=3 calibration-gated=5

(Counts assign each row its single primary class; the 5 calibration-gated rows
are the SSL grade-deduction set, SSL grade bands, email score set, email-hardening
score set, and the HTTP-header weights + CSP quality constants — all flagged for
FIN-9, none retuned here.)

### Top 3 concerns

1. **NEW DATA-QUALITY BUG — SSL cipher `bits` substring (L160).** `256 if "256"
   in name` matches the `SHA256` hash suffix, so the fixture's `AES_128_CCM_SHA256`
   is reported as **256-bit** (it is AES-128). Not scored today, but it is
   rendered and would mislead an underwriter. Free fix: parse the AES key length
   from the cipher token, not the whole name (or use sslyze's key size).

2. **Loose-substring family (fragile, not yet caught by Waves 1-5).** Three
   ubiquitous-substring reads survive: SPF `"all" in txt` (L423) flags validity on
   any incidental "all"; WAF **body** markers (`"cloudflare"`/`"sucuri"` in page
   text, L929) can fabricate a WAF-positive → phantom WAF scoring bonus; and WHOIS
   privacy keywords matched against the whole WHOIS blob (L1060). All three are
   the same back-test failure mode (generic/incidental string read as a signal)
   and all have free word-boundary / error-page-fingerprint fixes.

3. **Calibration-gated scoring constants (flag only).** Every SSL `ded` value,
   the email 0-10 deltas, the email-hardening +4/+2/+1 bonuses, and the HTTP-header
   weights / CSP-quality base+bonuses are unanchored magic-numbers that flow into
   the category risks (`ssl_risk`/`email_risk`/`header_risk`). Two value-judgements
   to raise with the calibrator: the email **DKIM −2** penalises a probe-miss as
   proof-of-absence (selectors are unbounded — a real DKIM on an uncommon selector
   is mis-scored), and **BIMI weighted near DANE/MTA-STS** scores a brand feature
   like a security control. FLAG for FIN-9; do not intuit new values.

### Confirmed-clean Wave 1-5 fixes (re-screened)
SSL sslyze-6.x cert API + re-`raise` (no fake "Invalid"); DKIM `v=DKIM1`/`p=`
gate (kills wildcard-TXT false positive); Exposed-Admin 200-only + body sanity
(no 403 inversion); HTTP-headers non-2xx `unreachable` guard (no WAF-403 penalty);
WAF F5 marker pruning (no XFO/`ts` ubiquitous-header inversion). All verified
against `phishield_live.json`.


---

# checkers_network.py — Heuristics Audit

White-box Step-6 heuristics sweep of `checkers_network.py` (6 classes:
`SubdomainChecker`, `VPNRemoteAccessChecker`, `DNSInfrastructureChecker`,
`HighRiskProtocolChecker`, `SecurityPolicyChecker`, `DNSBLChecker`).
RESEARCH ONLY — no code changed. Failure-mode screen per
`docs/card_verification_protocol.md` Step 6.

**Scope note.** Shodan/InternetDB and origin-discovery checkers do NOT live in
this module (they are in `checkers_threats.py` / `origin_discovery.py`) — out of
scope here. Waves 1-5 fixes confirmed present and clean in this file:
DNSBL return-code validation (`_is_genuine_listing`), RDS/VPN `require_200` +
genuine-marker tokens, subdomain wildcard guard + crt.sh `%25` primary with
`ct_source_ok`. The remaining audit targets the *unhardened* heuristics:
per-port score deltas, the high-risk port taxonomy, the brute wordlist, caps,
timeouts, and the curated CVE/EOL-flavoured intel tables.

**Calibration boundary.** Per-checker `score`/`risk_score`/`*N` deltas that feed
`scoring_analytics.RiskScorer` are calibration-gated and flagged for FIN-9 — I do
NOT propose numeric replacements for them. Where a heuristic is a *correctness
gate* (substring match, status-code rule, fallback, curated list) I propose a
free robust fix (bucket 1/2).

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `BRUTE_PREFIXES` (48 prefixes) | Subdomain L14-22 | DNS-brute candidate list supplementing crt.sh | No fabrication (each is a real resolve); generic/error N/A (positive resolve required). Coverage curated, not exhaustive | justified | Document: supplemental only (crt.sh is primary); reasonable infra-name list. Optional: note last-reviewed date so it doesn't silently rot |
| `RISKY_KEYWORDS` (25 substrings, `any(k in s)`) | Subdomain L24-29, L296 | Flags subdomains whose name contains a risky token | **Loose substring** — `k in s` over full FQDN matches the apex too (`api.takealot.com` flagged by `api`; `olddomain.com` → `old`; a brand literally containing `db`/`test`). False positives on benign hosts. Substring not label-boundary | fragile | Bucket-2: match on dotted **labels** (`set(host.split("."))`), not raw substring; and exclude the apex/`www`. Stops phantom "risky subdomain" counts feeding `sub_risk` |
| `TAKEOVER_SIGNATURES` (28 services, CNAME→fingerprint) | Subdomain L32-62 | CNAME-target pattern → dangling-service body fingerprint | Curated table can go **stale** (services rename/retire fingerprint pages); ~12 entries have `fingerprint=None` → dangling decided on NXDOMAIN only (sound). Pattern is `in cname_target` substring (acceptable for vendor domains) | fragile | Bucket-2: add a `last_verified` date + a periodic fingerprint-drift test (mirror the vendor-DB drift test from Wave 5). None-fingerprint entries are conservative — keep |
| Takeover via HTTP GET body `fingerprint in r.text` (`verify=False`) | Subdomain L106-124 | Confirms dangling by matching vendor 404 string in body | Generic-response risk is LOW (requires specific vendor string), but `verify=False` + `allow_redirects=True` could match a redirected catch-all page that echoes the string. Sound enough | justified | Document: relies on vendor-specific strings, not a generic 200/403; matches S-3 `_probe` spirit |
| Takeover `score -= 15` per vuln (`max(0, …)`) | Subdomain L293 | Subtracts 15 from local 0-100 score per takeover | **Calibration magic-number** feeding the card score | calibration-gated | FLAG for FIN-9 — do not intuit. (Note: this local `score` is largely informational; `subdomains` weight in scorer is driven by `risky_subdomains` count, not this score) |
| Risky-subdomain `score = max(40, 100 - n*5)` | Subdomain L303 | Per-risky-sub score delta with 40 floor | Calibration magic-numbers (5, 40 floor) | calibration-gated | FLAG for FIN-9 |
| Large-surface threshold `len > 50` → `score = min(score, 60)` | Subdomain L305-310 | "Large attack surface" if >50 subdomains | Threshold 50 + cap 60 are arbitrary; benign for big orgs (takealot easily >50) → could over-penalise large legit estates | calibration-gated | FLAG for FIN-9 (threshold + cap). Document that absolute count, not normalised, may bias against large orgs |
| Cap `subdomains[:150]` | Subdomain L227 | Caps stored subdomain list at 150 | No fabrication; bounds memory/time. Could truncate very large estates (>150) silently | justified | Document rationale (perf bound; aligns with takeover cap). Optional: record `truncated=True` when hit |
| `resolved_ips` cap `[:80]` | Subdomain L235 | Resolves only first 80 subs to IPs | `unique_ips_found` then under-counts on big estates (boolean-ish undercount, not fabrication) | fragile | Bucket-2: note in output that IP-resolution is sampled at 80 so `unique_ips_found` isn't read as a complete count |
| Takeover probe cap `[:150]` + `as_completed(timeout=90)`, `max_workers=10`, per-future `result(timeout=5)` | Subdomain L277-279 | Coverage budget for takeover probing | Well-documented (L253-275 audit note). Timeout-driven partial coverage means some subs unchecked → **under-detection, not fabrication** (safe-direction) | justified | Document already strong. Keep; note that misses are false-negatives (acceptable for non-intrusive posture) |
| `_wildcard_ips`: 2 random labels, `secrets.token_hex(8)` | Subdomain L73-83 | Wildcard-DNS guard (Wave-3 fix) | Correctly prevents fabrication of phantom brute hits. 2 samples is low but adequate (random 16-hex collision ~nil) | justified | Clean (Wave 3). Document: 2-sample is sufficient given entropy |
| `ThreadPoolExecutor(max_workers=20)` (brute + resolve) | Subdomain L210,234; DNS L624; HRP L878 | Concurrency for socket probes | Not a signal; perf only. 20 parallel TCP connects is mildly aggressive but bounded | justified | Document: respects non-intrusive posture (passive TCP connect, no payload flood) |
| `VPN_SIGNATURES` paths + `body_keywords` (8 vendors) | VPN L320-361 | Probes known VPN login paths, matches body tokens | RDS entry hardened (`require_200` + genuine markers, Wave 2). Others match on **specific vendor tokens** (`anyconnect`,`fortigate`) — low generic-response risk, but no `require_200` on the other 7 → a soft-404/redirect page echoing e.g. "citrix" could false-positive | fragile | Bucket-2: extend `require_200` (or S-3 `_probe` 200+body-sanity) to all 8 signatures, not just RDS. Vendor tokens are specific enough that risk is modest, but apply the gate uniformly |
| OpenVPN signature path `"/"` + tokens `openvpn access server` | VPN L353-355 | Detects OpenVPN-AS on root path | Root-path probe + generic token; `openvpn access server` is specific so low risk, but probing `/` means any homepage mentioning the product matches | fragile | Bucket-2: same `require_200` + ensure token appears in a login-form context, not marketing copy |
| RDP check: `connect_ex((domain,3389)) == 0`, `settimeout(3)` | VPN L375-382 | Flags RDP exposed if 3389 open | `connect_ex==0` is a true open-port signal (sound). Connects to `domain` (apex A) not per-resolved IP — single-IP attribution; behind CDN this is the edge IP not origin (false-negative, safe). Timeout 3s arbitrary but fine | justified | Document: open-port is genuine; note apex-only attribution (origin RDP behind CDN won't show — safe-direction miss) |
| `vpn_risk = 40 if rdp else (20 if not vpn_detected else 0)` | scoring L660 | Maps VPN result to risk; **"no VPN detected" → +20** | **Possible inversion/over-penalty**: absence of a *detected* gateway is treated as a 20-pt risk, but many orgs use ZTNA/cloud VPN (no on-prem login page) — penalises modern, well-defended orgs. Boolean (`vpn_detected`) drives score, which is correct, but the "unknown = risk" mapping is questionable | calibration-gated | FLAG for FIN-9 (the 40/20/0). Also flag the *semantics*: "no on-prem VPN page" ≠ "insecure remote access" — consider neutral, not +20 |
| `HIGH_RISK_PORTS` {21,23,3306,3389,5900}; `MEDIUM` {22,25,110,143}; `INFO` {80,443,993,995,8080,8443} | DNS L420-422 | Port → risk-tier taxonomy | Taxonomy curated. 5432(Postgres) & 1433(MSSQL) absent here but covered in HRP `CRITICAL_SERVICES` (no double-count: different checker). 22(SSH) as medium is defensible. No fabrication | justified | Document: tiering matches insurer convention (cleartext/DB/remote-admin = high). Cross-ref HRP so 5432/1433 aren't expected here |
| Port score deltas: high `+40`, medium `+15`, zone-transfer `+50`, `min(score,150)` | DNS L711,716,721,728 | Per-open-port risk accumulation | Calibration magic-numbers (40/15/50/150 cap) | calibration-gated | FLAG for FIN-9 |
| `PORT_INTEL` curated table (CVEs, CVSS, EPSS, KEV per port) | DNS L426-504 | Enriches port findings with exploit/CVSS/EPSS/KEV strings | **Stale-table risk**: hardcoded CVSS/EPSS/"CISA KEV" labels and CVE lists go out of date; EPSS especially is time-varying. Used as narrative enrichment, not score input (score is from tier, not these) → display-only staleness, not a scoring defect | fragile | Bucket-2: add a generated-on date + caveat that CVSS/EPSS are point-in-time; or source EPSS live. Not load-bearing for score, so low urgency |
| `BANNER_PROBES` (9 ports, raw bytes) + `_extract_version` regexes | DNS L582-592, L649-681 | Grabs service banner, regex-extracts version | Banner is real evidence (sound). Regexes are best-effort; a missed parse → empty version (no fabrication). `HEAD /` probe is non-intrusive | justified | Document: passive banner read, fail-open to empty (no fabricated version). Clean |
| Banner cap `[:200]`, `recv(1024)`, `settimeout(2)` | DNS L612,643-644 | Bounds banner capture | Pure bounds; no signal | justified | Document |
| Zone transfer: `ns_servers[:4]`, `lifetime=5`, `record_count>0`→vulnerable | DNS L552-563 | AXFR against ≤4 NS; any records = critical | `from_xfr` succeeding with `nodes>0` is genuine disclosure (sound, not generic-response). `[:4]` may skip later NS (under-test, safe) | justified | Document: refused/timeout correctly swallowed; success is true-positive. Note `[:4]` cap is a coverage choice (false-neg safe) |
| `_check_dnssec`: `bool(resolve(domain,"DNSKEY"))` | DNS L529-536 | DNSKEY presence ⇒ DNSSEC enabled | Presence of DNSKEY is a real signal; absence → False (no fabrication). Doesn't validate DS chain (documented) | justified | Clean. Document: apex DNSKEY only, not full chain-of-trust (stated in code) |
| Port-scan `settimeout(3)`, `as_completed(timeout=30)` | DNS L605,626; HRP L863,880 | TCP-connect timeouts | Bounds; non-signal. 3s connect is standard | justified | Document |
| `CRITICAL_SERVICES` (16 DB/admin ports) | HRP L736-754 | DB/service exposure port set | Curated; each is a genuine high-risk service. `connect_ex==0` = real open port (sound, no generic-response) | justified | Document: passive connect, port-open is ground truth. Reasonable DB/admin coverage |
| `SERVICE_INTEL` curated CVE/EPSS/KEV table (16 entries) | HRP L756-842 | Narrative enrichment per critical service | **Stale-table risk** same as `PORT_INTEL` (hardcoded CVSS/EPSS/KEV strings). Display-only; `critical_count` (not these) drives `hrisk` score | fragile | Bucket-2: date-stamp + point-in-time caveat for CVSS/EPSS; not score-load-bearing |
| `critical_count` → `hrisk = min(100, n*35)` | scoring L639-640 | Each exposed DB/service ⇒ +35 risk | **Count is genuine** (real open ports). 35 multiplier + 100 cap are calibration | calibration-gated | FLAG for FIN-9 (the 35) |
| `dnsbl_risk = min(100, listed*50)` | scoring L645 | Each blacklist listing ⇒ +50 | Count uses validated `_is_genuine_listing` (Wave-1 clean) → no false-positive inflation. 50 multiplier is calibration | calibration-gated | FLAG for FIN-9 (the 50). Listing count itself is sound |
| `_is_genuine_listing` return-code ranges (127.0.0.2-255; 127.0.1.2-99; reject 127.255.255.x & 127.0.0.1) | DNSBL L963-1005 | Validates DNSBL reply codes per spec | **Wave-1 fix — directly addresses the generic/error-response failure mode.** Correctly rejects open-resolver/refused codes. Per-list nuance folded into generic ranges (slight over-generalisation across 5 lists but conservative) | justified | Clean. Optional doc: SORBS/UCEPROTECT/Barracuda use 127.0.0.x so the generic range is correct for them; Spamhaus zen multi-code handled |
| `IP_DNSBLS` (5 lists) / `DOMAIN_DNSBLS` (2 lists) + `lifetime=5` | DNSBL L951-961 | Curated DNSBL providers | Curated; lists can deprecate (UCEPROTECT/SORBS reliability varies; SORBS shut down 2024 — **potential stale entry**) | fragile | Bucket-2: verify `dnsbl.sorbs.net` still resolves (SORBS ceased operation mid-2024); drop dead lists so a NXDOMAIN'd provider can't skew availability. Quick free check |
| security.txt: `status==200 and "Contact:" in r.text` | SecPolicy L920-925 | Detects VDP via security.txt | Requires 200 **and** literal `Contact:` — robust (S-3-style); a soft-404/SPA won't false-positive. `has_pgp` substring on `Encryption:`/PGP header is fine | justified | Clean. Good pattern — 200+content-sanity. Document as reference-correct |
| robots.txt `disallows_count = text.count("disallow:")` | SecPolicy L937-939 | Counts Disallow lines | Counts on any 200 body without sanity-check — a soft-404 HTML page containing the word would mis-count; but `disallows_count` is **informational only** (not scored) | fragile | Bucket-2: gate on `content-type: text/plain` or a `User-agent:` line present before counting, to avoid counting an HTML catch-all. Low urgency (unscored) |
| `vpn_detected` body slice `r.text[:3000].lower()` | VPN L399 | Limits body scanned for tokens | Bound; could miss tokens past 3000 chars (under-detection, safe) | justified | Document |

## Summary
total=33 justified=15 fragile=11 arbitrary=0 calibration-gated=7; top 3 concerns.

**Top 3 concerns**

1. **`RISKY_KEYWORDS` loose-substring match (fragile, free fix).** `any(k in s)`
   over the full FQDN flags benign hosts — `api.`, `db`-containing brands, the
   apex/`www` itself — inflating `risky_subdomains`, which *directly* drives
   `sub_risk` (`*15`) in the scorer. This is the back-test's "loose substring"
   failure mode and the only fragile item that feeds a real score. **Fix:**
   label-boundary match (`set(host.split("."))`) + exclude apex/www.

2. **VPN signatures lack a uniform `require_200`/body-sanity gate (fragile).**
   Only the RDS signature was hardened in Wave 2; the other 7 vendors still
   match a vendor token in any response (incl. soft-404/redirect/marketing
   copy). **Fix:** apply the S-3 `_probe` 200-only + body-sanity pattern to all
   8 signatures. Related: the `vpn_risk` "no VPN page detected = +20" mapping
   risks **inverting** against ZTNA/cloud-VPN orgs — flag the *semantics* to
   FIN-9, not just the number.

3. **Stale curated tables (fragile).** `PORT_INTEL`/`SERVICE_INTEL` hardcode
   point-in-time CVSS/EPSS/"CISA KEV" strings (display-only, low urgency), and
   `dnsbl.sorbs.net` may be a **dead list** (SORBS ceased operation mid-2024) —
   verify and drop. `TAKEOVER_SIGNATURES` should carry a `last_verified` date +
   drift test (mirror Wave-5 vendor-DB drift test). None are score-load-bearing
   except via listing-count, which is itself validated.

**Calibration-gated (FIN-9, not intuited):** takeover `-15`/sub `100-n*5`+40
floor / large-surface `>50`→`60` (Subdomain local score); port `+40/+15`,
zone-xfer `+50`, `min(,150)` (DNS); `hrisk n*35`; `dnsbl listed*50`; `vpn_risk
40/20/0`. The underlying **counts** behind every flagged delta are sound
(real open ports, validated listings) — only the multipliers/thresholds need
calibration.


---

# checkers_threats.py — Heuristics Audit

Module: `checkers_threats.py` (+ `darkweb_providers.py`). White-box Step-6 sweep
of the Card Verification Protocol (`docs/card_verification_protocol.md`). RESEARCH
ONLY — no code changed.

**Scoring-flow context (grounds the classification):**
- Every checker's `score` (0-100) is inverted (`inv = 100 - score`) and folded into
  **RSI** through `WEIGHTS` in `scoring_analytics.py` (e.g. `dehashed` 0.03,
  `fraudulent_domains` 0.04, `shodan_vulns` 0.07, `tech_stack` 0.05, `virustotal`
  0.05). So a checker's internal penalty deltas are RSI magic-numbers ⇒ **calibration-gated**.
- `CredentialRiskClassifier.classify()` `risk_level` feeds **p(breach)** directly
  (`scoring_analytics.py` ~L1029: CRITICAL +0.20, HIGH +0.15, MEDIUM +0.08 to base
  probability). Its internal `risk_score` deltas (-50/-20/-30/-15/-10/-3) are the
  5L/FIN-9 credential→p(breach) refactor target ⇒ **calibration-gated, DO NOT intuit**.
- `HudsonRockChecker.score`, `IntelXChecker.score`, `DehashedChecker.score` are
  scored. `BreachChecker`, `HIBPBreachMetadata`, `SecurityTrailsChecker`,
  `GlasswingPartnerChecker` narrative are largely reporting-only / informational.

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| **EOL_SIGNATURES** table (~45 rows, "refreshed 2026-06-02") | TechStack L20-67 | Substring-match header/body for EOL product/version → critical/high/medium | **Stale-table risk** (the exact failure mode the protocol calls out: EOL dates silently age). Refresh-dated, which is good, but no automated drift test. Also substring `"php/7.1".lower() in combined` will match `"php/7.10"` and `"php/7.12"` substrings (false EOL on a *newer* branch) | fragile | Add a drift test asserting refresh-date < N months (mirror Wave-5 vendor-DB drift test). Anchor version tokens with a boundary so `7.1` ≠ `7.10`. |
| EOL penalty deltas **-40/-25/-10** (critical/high/medium) | TechStack L117-121 | Score deduction per EOL hit | Feeds RSI via `tech_stack` 0.05. No empirical basis cited | calibration-gated | Flag for FIN-9 with KEV/DBIR EOL-exploit anchors; don't intuit. |
| X-Powered-By disclosure **-5** | TechStack L108 | Info-leak penalty | Reporting-grade signal scored as risk; small | calibration-gated | Flag for FIN-9 (minor). |
| jQuery `<3.5.0` **-15**, AngularJS EOL **-10** | TechStack L172,180 | JS-lib version penalty | CVE-2020-11022 is real; the *delta size* is unanchored | calibration-gated | Cite CVE; flag delta for FIN-9. |
| jQuery version regex `parts[0]<3 or (==3 and parts[1]<5)` | TechStack L168 | "below 3.5.0" test | Justified (correct semver gate) | justified | Documented. |
| **CMS_SIGNATURES** substrings (WordPress `/wp-content/` etc.) | TechStack L69-78, WebSec L250-258 | Detect CMS from body/header substrings | Loose-substring risk: `squarespace.com`/`shopify.com` appear in any embedded asset/CDN link → false CMS attribution. Reporting-only (not scored) so low blast radius | fragile | Constrain to generator-meta or first-party host; document as reporting-only. |
| **HIBP** `breach_count = len(breaches)` + `most_recent = max(dates)` | Breach L216-229 | Count + recency from HIBP domain breaches | Clean — real list length, real max-date. No boolean-as-count | justified | Documented. |
| **CVSS severity cut-offs** 9.0/7.0/4.0 | Shodan `_cvss_severity` L451 | Map CVSS base → critical/high/medium/low | Justified — standard FIRST CVSS v3 bands | justified | Documented (industry standard). |
| `easily_exploitable` = AV:N & AC:L & PR:N | Shodan L489 | CVSS-vector exploitability gate | Justified — robust vector parse, not a magic number | justified | Documented. |
| EPSS thresholds **>0.5** (high), **>0.4 / pct>0.9** (widely exploited) | Shodan L755,777 | EPSS-based flags | 0.5/0.4 are conventional EPSS triage cut-offs but uncited here; not directly scored (drive issues text + RSI via `score`) | fragile | Cite FIRST EPSS guidance (≈0.1 default actionable; 0.5 is conservative); document rationale. |
| CVE caps: **`[:20]` raw, `[:10]` enriched, `[:30]` EPSS batch** | Shodan L546,568,653,730,744 | Limit CVE enrichment volume | **Silent under-count + inconsistency:** raw list capped 20, only first 10 enriched, remainder dumped to `medium_count` (L825-826) regardless of true severity → can both over- and under-state. The `>10` tail being forced to "medium" is an arbitrary fabrication of severity | fragile | Document the cap; at minimum don't relabel un-enriched CVEs as "medium" — count them as `unknown`. |
| Severity penalty **crit×30 + high×15 + med×5**, `min(100,·)` | Shodan `check` L947-950 | Score from CVE counts | Feeds RSI via `shodan_vulns` 0.07 | calibration-gated | Flag for FIN-9. |
| **RANSOMWARE_CVE_MAP** (~35 rows), **ATTACK_TECHNIQUE_MAP** (~15) | Shodan L670-721 | Tag CVE→ransomware family / ATT&CK | Stale-curated-table: hand-maintained, no source date, will drift as new CVEs are weaponised. Reporting/narrative (drives issues text, not a separate weight) | fragile | Add a "last reviewed" date + periodic-refresh note; document as illustrative not exhaustive. |
| Patch-mgmt age bands **365 / 180 / 90** days | Shodan L844-846,883-888 | Bucket CVE age; warn >365/>180 | Recency-band cut-offs are reasonable patch-SLA conventions but uncited | fragile | Cite a patch-SLA reference (e.g. CISA BOD 22-01 KEV due dates); document. |
| KEV/MSF/ExploitDB caches **86400s TTL** | Shodan L574,594,618 | 24h cache of feeds | Justified — feeds change daily | justified | Documented. |
| `exploit_maturity`: KEV/MSF→weaponized; EDB/EPSS>0.5→poc | Shodan L763-770 | Maturity classification | Justified gate (real feed membership), not magic | justified | Documented. |
| **OSV CVSS-vector approximation** base=5.0 +1.5/+1.0/+0.5… | OSV `_parse_vulns` L1104-1111 | *Invents* a CVSS score from vector when none given | **Fabrication on absent input** — synthesises a numeric severity the source never stated; arbitrary additive weights with no CVSS-spec basis | arbitrary | Remove the synthetic score; fall back to `database_specific.severity` or mark `unknown`. Do not fabricate CVSS. |
| OSV pre-2015 advisory drop | OSV L1122 | Skip advisories published <2015 | Arbitrary recency cut — silently hides genuinely-old-but-live vulns | arbitrary | Document rationale or gate on "fixed/affected version match" instead of publish-year. |
| OSV default severity `"medium"` | OSV L1077 | Fallback when no CVSS/db-sev | Fabrication-lite: unknown rendered as "medium" → inflates RSI tail | fragile | Default to `unknown`, not `medium`. |
| **HASH_PATTERNS** regexes (bcrypt/argon2/SHA-*/MD5/NTLM); MD5≡NTLM both 32-hex | Dehashed L1167-1176 | Identify hash type from string | Justified regexes; the **NTLM==MD5 collision is acknowledged in-code** and can mis-bucket NTLM as MD5 (both `WEAK`, so net-harmless to the weak/strong split) | justified | Documented (collision noted; harmless because both weak). |
| Dehashed penalty **plaintext×5 + weak×3 + strong×1 + other×2**, `min(100,·)` | Dehashed L1376-1377 | Score from credential breakdown | Feeds RSI via `dehashed` 0.03. Wave-3 fixed the case-double-count; the *delta sizes* remain unanchored | calibration-gated | Flag for FIN-9 (plaintext vs hashed severity ratio). |
| `staff_accounts_masked[:60]`, `sample_emails[:5]`, `breach_details[:20]` | Dehashed L1328-1339 | Display caps | Justified display bounds; counts (`staff_accounts_total`) computed on full set, not the cap | justified | Documented. |
| **VirusTotal** penalty `mal×10 + sus×5`, `min(100,·)` | VirusTotal L1495 | Score from engine detections | Feeds RSI via `virustotal` 0.05. Real counts (not boolean), but delta unanchored | calibration-gated | Flag for FIN-9. |
| VT bad-category substrings (`malware/phishing/spam/scam`) | VirusTotal L1488 | Issue text from categories | Reporting-only substring match; low risk | justified | Documented. |
| **SecurityTrails** "associated > 50" shared-hosting flag | SecurityTrails L1595 | Issue text when >50 associated domains | Arbitrary threshold, reporting-only (not in WEIGHTS at 0.01 it barely scores via `score`=100 always here — note: ST `score` never decremented, stays 100) | arbitrary | Document the 50 cut-off or derive from distribution; note ST score is inert. |
| **HudsonRock** penalties **emp×30, user×10, 3p×5** | HudsonRock L1695-1707 | Score from infostealer counts | Real counts (not boolean). Feeds credential_risk + RSI. Active-compromise = strongest p(breach) driver | calibration-gated | Flag for FIN-9 (the 30/10/5 ladder). |
| HR `data.get("employees",0) or 0` etc. | HudsonRock L1650-1652 | Null-safe count extraction | Clean — `or 0` only guards null, doesn't fabricate (no `or 1`) | justified | Documented. |
| HR `days_since_compromise` (no recency *gate*) | HudsonRock L1671-1674 | Computes age but does **not** down-weight stale infections | **Gap (OUTSTANDING §6 date-gate-HR ticket):** a 3-year-old infostealer hit scores identically to a fresh one; protocol step-2 recency not enforced in scoring | calibration-gated | Flag for FIN-9 + §6 ticket: apply a recency decay/gate to HR contribution. Don't intuit the curve. |
| **KNOWN_BREACH_DATES** (10 combo-list dates) | CredRiskClassifier L1817-1828 | Fallback dates for non-HIBP combo lists | Stale-curated-table; small + slow-moving, used only for display/recency band | fragile | Add review-date comment; document as best-effort. |
| Cred-risk **risk_score deltas -50/-20/-30/-15/-10/-3** | CredRiskClassifier L1847-1940 | Per-factor credential risk_score deductions | **Core 5L/FIN-9 target.** Also `darkweb×10` and `pastes×3` are **uncapped per-mention** (40-record IntelX cap ⇒ up to -400, floored at 0 — saturates instantly) | calibration-gated | **DO NOT intuit.** Flag whole ladder for FIN-9; note darkweb/paste per-mention multipliers need a cap or log-scale. |
| Recency band **year ≥ 2023 = "recent"** | CredRiskClassifier L1925 | Split breaches recent vs old | Hardcoded calendar year — silently ages (2023 becomes "3 years stale" by 2026); should be relative (now − N days) | fragile | Replace fixed year with rolling window (e.g. <24 months); document. |
| `pastes > 3` gate | CredRiskClassifier L1871 | Threshold for paste factor | Arbitrary, inconsistent with IntelXChecker's `paste_count > 5` (L2102) | arbitrary | Reconcile the two paste thresholds; document one rationale. |
| **IntelX MAX_RESULTS = 40** + over-return truncation | IntelX L1989,2066-2068 | Cap + truncate (free API over-returns) | Justified — Wave-3 fix, reproducible bound, documented in-code | justified | Documented (clean). |
| **_STEALER_TOKENS** + bucket `darknet/logs/stealer` darkweb-grade gate | IntelX L1996-2013; mirrored darkweb_providers L106-122 | Reclassify generic-text stealer dumps as darkweb | Loose-substring risk: tokens like `"autofill"`, `"screenshot"`, `" default.txt"` could match benign filenames; but conservative and reporting-grade. Bucket gate is sound | fragile | Document false-positive surface; consider requiring token **and** a leak/log bucket. |
| IntelX media map `1,2=paste; 13=darkweb; 5=email` | IntelX L2073-2075 | Media-type classification | Justified — IntelX documented codes | justified | Documented. |
| IntelX penalty **darkweb×15, paste×3** (`paste_count>5`) | IntelX L2096-2103; darkweb_providers L396-405 | Score from counts | Feeds RSI; unanchored deltas, but bounded by 40-cap (max -600 → floor 0) | calibration-gated | Flag for FIN-9; note bound. |
| IntelX poll: `sleep(3)` + 3×`sleep(2)`, statuses `(1,2,4)` | IntelX L2048-2060 | Two-step search poll | Justified — matches IntelX async protocol | justified | Documented. |
| **FraudulentDomain HOMOGLYPHS / IDN_HOMOGLYPHS / KEYBOARD_ADJ** maps | FraudDomain L2139-2173 | Generate typosquat permutations | Justified (Wave-5 IDN fix confirmed clean); high-confidence, one-sub-per-candidate | justified | Documented. |
| IDN cap **12**, permutation check cap **60**, display cap **20** | FraudDomain L2261,2290,2313 | Bound candidate explosion / memory | Justified low-footprint bounds; but `[:60]` truncates *before* DNS check, so resolved-count is capped by generation order not by reality (a real lookalike past index 60 is missed) | fragile | Document the 60-cap as a known recall ceiling; consider ordering high-similarity techniques first. |
| `_split_domain` multi-TLD set `(co,com,org,net,ac,gov)` | FraudDomain L2178 | Handle `.co.za` etc. | Justified for SA market; could miss `.gov.za`/`.web.za` edge TLDs | justified | Documented (SA-appropriate). |
| Similarity %s **90/95/85/80** per technique | FraudDomain L2196-2259 | Display-only similarity score | Cosmetic, not scored | justified | Documented (display heuristic). |
| FraudDomain penalty `resolved×8`, `min(100,·)`; issue bands `>5/>2/>0` | FraudDomain L2315-2333 | Score + issue tiers from resolved count | Feeds RSI via `fraudulent_domains` 0.04. Unanchored delta + bands | calibration-gated | Flag for FIN-9. |
| **Glasswing PARTNERS** static list (12) + `score_bonus 10/10/5` | Glasswing L2682-2743 | Favourable-signal bonus (RSI reduction) | Stale-curated-table (April-2026 snapshot). HTML `"glasswing"+"anthropic"` probe is a loose-substring positive-signal-from-page-content — but bonus is small & favourable | fragile | Add refresh-date enforcement; document the substring probe's FP surface. score_bonus → FIN-9. |
| **WebRanking Tranco** bands `≤1000→100, ≤10k→90, ≤100k→70, else 50`; not-listed→30 | WebRanking L2641-2652 | Popularity→score | Inverted-meaning concern: high popularity = *higher* score (treated as protective) yet popular = bigger target; semantics debatable. Bands arbitrary | calibration-gated | Clarify whether ranking should raise or lower risk; flag bands for FIN-9. |
| **InfoDisclosure** `_probe`: HEAD→GET, **200-only + len≥10 + not "404"/"not found"** | InfoDisc L2791-2808 | Sensitive-file probe | **Reference-grade gate** (the S-3 `_probe` pattern the protocol endorses) — guards against WAF/CDN 200 catch-alls and custom-404 false positives | justified | Documented (model pattern). |
| InfoDisc penalties **critical×20, medium×10, dir-listing −15** | InfoDisc L2824-2873 | Score from exposed paths | Feeds RSI via `info_disclosure` 0.05 | calibration-gated | Flag for FIN-9. |
| **PrivacyCompliance** `_probe`: HEAD→GET 200 + body≥500 | Privacy L2488-2503 | Policy-page discovery | Justified robust gate (body-sanity, avoids WAF 200) | justified | Documented. |
| Privacy REQUIRED_SECTIONS keyword lists (10 sections) | Privacy L2362-2400 | Section-presence via keyword substring | Loose-substring: `"child"`/`"update"`/`"contact us"` are extremely common, will false-positive "section present" on almost any page → over-states compliance % | fragile | Tighten keywords or require ≥2 distinct hits per section; document. |
| Privacy `compliance_pct → score` (= score) | Privacy L2565,2583 | Score = % sections found | Compliance % drives `privacy_compliance` 0.02 weight; the keyword fragility above propagates here | fragile (gate) / calibration-gated (weight) | Harden keywords (above); weight delta → FIN-9. |
| **PaymentSecurity** self-hosted-form regex `card.?number…` on 200 page | Payment L380-417 | Detect self-hosted card form (PCI risk) | Generic-response risk partly mitigated (checks payment keywords first), but probes 9 paths with `timeout=4` and no HEAD/WAF gate; a 200 catch-all + keyword could false-positive | fragile | Route through the `_probe`/HTTP-client pattern used elsewhere; document. |
| `darkweb_providers` Snusbase/LeakCheck table-name substrings (`STEALER/LOG/MALWARE`, `darknet/combolist`) | darkweb_providers L201-253 | Map provider table → darkweb/leak/paste | Loose-substring on provider-controlled names; reasonable but provider-dependent and unverified live (no key in fixture) | fragile | Verify against each provider's real table/origin vocabulary before enabling in prod; document. |

## Summary
total≈42 heuristics catalogued.
**justified=15, fragile=15, arbitrary=4, calibration-gated=13** (several rows carry a
fragile *gate* + a calibration-gated *weight* — counted under their dominant class;
the 4 explicit `arbitrary` are the OSV synthetic-CVSS, OSV pre-2015 drop, ST ">50"
shared-hosting cut, and CredRisk `pastes>3` inconsistency).

**Top 3 concerns**
1. **OSV synthetic CVSS fabrication** (`_parse_vulns` L1104-1111) — invents a numeric
   severity from a vector when the source gives none, with arbitrary additive weights.
   This is the exact "fabrication on absent input" failure mode and it propagates into
   `shodan_vulns`/CVE risk. **Bucket-2 free fix:** fall back to `database_specific.severity`
   or `unknown`; never synthesise a CVSS score.
2. **Stale-curated-table drift** across EOL_SIGNATURES, RANSOMWARE_CVE_MAP,
   KNOWN_BREACH_DATES, Glasswing PARTNERS — all hand-maintained, only EOL is
   refresh-dated, none has an automated drift test. **Bucket-1 free fix:** add a
   refresh-date assertion test (clone the Wave-5 vendor-DB drift test) + boundary-anchor
   the EOL substring so `7.1`≠`7.10`.
3. **Calibration-gated credential/p(breach) ladder** — CredentialRiskClassifier
   `-50/-20/-30/-15/-10/-3` plus **uncapped** `darkweb×10`/`paste×3` per-mention, the
   HR `30/10/5` ladder, and the **un-gated HR recency** (days_since_compromise computed
   but never applied). These drive p(breach) (CRITICAL +0.20) and are the precise
   5L/FIN-9 scope. **FLAGGED for FIN-9 — do not intuit;** the only free pre-FIN-9 note
   is that the darkweb/paste per-mention multipliers need a cap or log-scale, and the
   "year ≥ 2023" recency band should become a rolling window.


---

# checkers_supply_chain.py — Heuristics Audit

Module: `checkers_supply_chain.py` (S-1 RelatedDomains, S-2 ThirdPartyJS, S-3
DependencyManifest, S-4 EmailVendorSurface, S-5 VendorBreach, S-10 CMSPluginSBOM)
+ `related_domain_discovery.py` (S-1 v1.1 pre-flight). Scoring contribution
(`supply_chain_vulnerability_uplift`) lives in `scoring_analytics.py` ~L2066-2104.

Method: every heuristic enumerated, screened against the Step-6 failure modes
(fabrication-on-absent-input / generic-or-error-response-as-signal /
boolean-as-count / inversion / stale-curated-table), then classified
**justified / fragile / arbitrary / calibration-gated**. Bucket-1/2 = free
correctness or hardening; **bucket-3 (scoring magic-numbers) flagged for FIN-9 —
not intuited here.** Waves 1-5 fixes (S-4 Mandrill/Zoho, S-10 WP-fingerprint +
plugin body-sanity, vendor-row prune + drift warn) confirmed present and clean;
this audit focuses on the REMAINING heuristics.

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| `ROUND_BUDGET=180` s per round of `WORKERS=4`, `MAX_DOMAINS=10` | S-1 `RelatedDomainsChecker` class constants, `budget_seconds` | Bound LITE-mode related-domain scan time/concurrency | Operational caps, no signal interpretation; a domain still being checked when the budget ends is NOT ASSESSED | justified | Keep; document as scan-budget bounds. |
| A failed TLS check is read from the SSL error text: an answer without TLS (wrong version number, EOF, reset) is a finding; a handshake 443 accepted and never answered is NOT ASSESSED; otherwise the port probe decides | S-1 `RelatedDomainsChecker.check` `_ssl_errors`, `_TLS_ANSWERED`, `_TLS_HUNG`, `_TCP_TIMEOUT` | Tell a host that answered without TLS from one that never answered | Matches OpenSSL and Python error strings, which vary by version and platform; an unrecognised error falls back to the port-probe rule, and a hang is never priced (step 5, 2026-09-11) | fragile | Keep; replace with a structured failure reason if SSLChecker records one. |
| `lite_score` = min of the measured parts of ssl, info and 100-dns_risk | S-1 `_scan_one` | Worst-axis rollup of a related domain's posture | Min of the parts that measured (worst signal wins). Since step 5 (2026-09-11) a sub-check that failed or measured nothing is left out and shown as not assessed, never defaulted to 100 | justified | Keep. |
| `high_count` = lite_score `< 60` | S-1 L116-117 | Counts related domains scoring below 60 as "high" | Threshold only triggers the issue string + RSI remediation row; not the uplift. 60 is an arbitrary cutoff | arbitrary | Document basis (60 = "below passing") or align to the global grade band; low stakes (cosmetic). |
| S-1 probes run only on broker-confirmed or API-declared `related_domains`; discovery runs inside every scan (step 5, 2026-09-11) | `estate_discovery.build_related_domains_category` | Candidates from the certificate names the scan already fetches are listed for confirmation on every scan, never probed or scored | Superseded by step 5: discovery is no longer pre-flight-only, and an empty confirmed list returns status "completed" ("skipped" would price +5 to +16). The civil-liability uplift still needs a confirmed domain with a finding | fragile | Auto-confirmation stays deferred (docs/OUTSTANDING.md 5w). |
| crt.sh `SHARED_INFRA_SUFFIXES` (CDN/SaaS/CA exclusion list) | discovery L62-75 | Drops shared-infra apexes from SAN candidates | Stale-table risk (new CDNs/PaaS appear); conservative — broker still confirms, so misses are recoverable | fragile | Keep; add a periodic-review note. Not signal-critical (suggestions only). |
| Pre-flight apex reducer | related_domain_discovery `_extract_san_apexes` -> `estate_discovery.registrable` and `_rejection` | Reduces SAN hosts to the registrable domain with the report's own rules | Shared with the scan's discovery since step 5 (2026-09-11); not a Public Suffix List (docs/OUTSTANDING.md 5ad) | fragile | Keep in parity with the report; a PSL snapshot is the proper fix. |
| `_confidence_for`: certificates>=5 and a shared brand -> high; >=3 or a shared brand -> medium | related_domain_discovery `_confidence_for`, `_brand_part` | Confidence label for broker review | Labels only, never scored or pre-ticked. A shared brand is the same first part of the name, at least four letters and not a generic business word; certificates are counted, not names (step 5, 2026-09-11) | justified | Keep (reporting-only confidence hint). |
| S-3 `MANIFESTS` severity: lockfile=critical, manifest=high | S-3 L150-166 | Exact-pin lockfiles → critical; range manifests → high | Rationale documented (exact versions enable OSV chaining). Curated path list could miss new ecosystems (low stakes) | justified | Keep; rationale already inline. |
| S-3 `_probe`: HEAD+GET **200-only** + `len≥10` + reject `<html`/`<!doctype` + reject "not found"/"404" | S-3 L188-201 | Body-sanity gate so a WAF/CDN 200 catch-all isn't read as a leaked manifest | **Reference pattern** for generic-response-as-signal. Correctly rejects 403/redirect/HTML-shell. Robust gate, not a magic number | justified | Keep — this is the template Step-6 endorses. |
| `EXACT_VERSION_RE` (skip SemVer ranges) | S-3 L182, L338 | Only query OSV for pinned versions | Avoids mass-flag/mass-miss on ranges. Sound; ranges still yield the leak finding, just no CVE count | justified | Keep; rationale inline. |
| `MAX_DEPS_RETURNED=50`, `MAX_OSV_LOOKUPS_PER_SCAN=30`, per-manifest budget | S-3 L184-185, L364-366 | Cap OSV calls (10 req/s limit) + spread budget smallest-first | Operational/rate caps. Budget spread prevents a 1000-dep lockfile starving small ones — good design | justified | Keep. |
| S-3 penalty `crit*30 + high*15`; `+min(30, total_critical_cves*5)` CVE add-on; `score=max(0,100-penalty)` | S-3 L479-485 | Per-checker score delta into the 0.04-weighted `dependency_manifests` channel | **Scoring magic-numbers** (30/15/5 and the 30-cap). Drive a WEIGHTS-scored card. Not yet calibration-anchored | calibration-gated | **FLAG FIN-9.** Do not intuit. CVE-cap-keeps-leak-dominant rationale is sound directionally; the constants are the open question. |
| S-2 `KNOWN_COMPROMISED_HOSTS` (polyfill.io, bootcss/bootcdn) | S-2 L526-531 | Tight allow-deny of confirmed Magecart/skimmer CDNs | Stale-table: deliberately tight ("only confirmed incidents"). Risk is under-coverage of NEW incidents, not false-positives | fragile | Keep tight; add review cadence. Each hit = +60 penalty + Magecart uplift, so completeness matters — periodic refresh from threat feeds. |
| S-2 `KNOWN_CDN_SUFFIXES` (label only) | S-2 L534-542 | Tags a third-party host as "known CDN" for display | Comment says "label, not whitelist" — confirmed not used to suppress findings. No inversion | justified | Keep. |
| S-2 `_host_of`: relative/`/`-prefixed ⇒ first-party | S-2 L553-563 | Classifies script origin | Protocol-relative `//` handled; relative ⇒ primary. Sound | justified | Keep. |
| S-2 SRI penalty: `sri_pct<0.25`→+20; `<0.75`→+10; `>15 hosts`→+5; compromised→`60×n` | S-2 L639-672 | Per-checker score delta | **Scoring magic-numbers** (20/10/5/60, 0.25/0.75/15 thresholds). SRI-coverage logic is correct (protective signal lowers penalty — no inversion), but magnitudes uncalibrated | calibration-gated | **FLAG FIN-9** for the constants. Logic/direction justified; magnitudes not. |
| S-4 `VENDOR_PATTERNS` (25 vendor→SPF-suffix rows) | S-4 L681-724 | Maps SPF includes to email-SaaS vendors; first-match-wins suffix match | **Coverage gap (stale-table class):** S-4 detects 25 vendors but only **7 have rows in vendor_breaches.json** (hubspot, intercom, mailchimp, microsoft_365, okta, salesforce, zendesk + none for the other 18; the marketo row was pruned 2026-06-11, see section 2). Conversely, every breaches.json vendor key IS covered by a pattern (no orphan rows). Notable SA-market senders absent from patterns: **Everlytic is present (good)**; missing: Mailchimp-owned **Mandrill correctly folded** (Wave 1 ✓), Zoho ZeptoMail folded (Wave 1 ✓). Gaps: no **Twilio/SendGrid-subsidiary nuance**, no **Amazon Pinpoint**, no **Mimecast/Proofpoint** secure-gateways (common SA corp), no **Sage/Xero** finance senders | fragile | Pattern→breach coverage is the live risk. (1) Add SA-relevant senders (Mimecast, Proofpoint, Amazon Pinpoint) — free. (2) Document that 20/28 patterns have no S-5 breach correlation by design (detection ≠ breach history). (3) Suffix match is sound (Wave-1 hardened). |
| S-4 `_walk_includes` depth≤4, `includes[:10]` per node | S-4 L750-766 | Bounds SPF recursion (DNS 10-lookup limit) | Mirrors RFC 7208 lookup cap; cycle-guarded via `seen` | justified | Keep. |
| S-4/S-5 SPF lookup outcome: NXDOMAIN or NoAnswer is an answer (no SPF record); any other resolver error, for the domain's own record or one behind an include, is a lookup that did not answer (`spf_lookup: "failed"`), and a record in the chain that delegates with `redirect=` is not followed (`"not_followed"`); terms are read without regard to case | S-4 `_fetch_spf`, `_walk_includes`, `_spf_outcome`, `check`; S-5 `check` | Tell "no email vendors" from "the lookup did not answer" | Reporting only: with no vendor identified the status is "no_data", which prices as a completed result with no vendors did; a completed result records `"answered"`, or `"partial"` where a vendor was found beside a lookup that did not answer, so a result stored before the field existed is not read as measured, and no surface reads an unmeasured or partly read chain as clean (step 5, 2026-09-12) | justified | Keep; whether an unmeasured vendor surface should price as an error is a scoring decision, left open (5af). |
| S-4 `weak_dmarc = policy in ("", "none")` | S-4 L816 | Flags missing/none DMARC | Correct: `p=none`/absent = no enforcement. Not inverted. Boolean used as boolean (not as count) | justified | Keep. |
| S-4 penalty: vendor≥3→+5; ≥6→+10; weak_dmarc & ≥1→+20 | S-4 L822-840 | Per-checker score delta | **Scoring magic-numbers** (5/10/20, thresholds 3/6). Direction sound (wide surface + weak DMARC = phishing risk); magnitudes uncalibrated | calibration-gated | **FLAG FIN-9.** |
| S-10 `_is_wordpress` catch-all guard: random `token_hex(8)` path 200-check + homepage `/wp-content/`-`/wp-includes/`-generator markers + `wp-login.php` 200 ≠ control-body w/ `user_login`/`wp-submit`/`wordpress` | S-10 L880-936 | Robust WP discriminator; bails if host echoes content to nonsense paths | **Wave-2 fix confirmed clean.** Directly defeats the CDN/WAF catch-all-200/403 false-positive (the takealot-Next.js case). Body-confirmed, control-differenced. Exemplary | justified | Keep — second reference pattern alongside S-3 `_probe`. |
| S-10 `_probe_plugin`: readme.txt **200-only** + `len≥10` + reject HTML shell + require `=== `/`stable tag:`/`tested up to:` marker | S-10 L938-974 | Plugin counts PRESENT only on a genuine readme body | **Wave-2 fix confirmed clean.** Defeats "WAF 403s/200s every path ⇒ all 25 plugins installed" bug. readme.txt-spec markers are the right sanity check | justified | Keep. |
| S-10 `POPULAR_PLUGINS` (25 slugs) | S-10 L849-875 | "SBOM proxy" probe list | Deliberately small/conservative (not exhaustive). Stale-table risk low — only affects coverage, gated by readme sanity | fragile | Keep; refresh occasionally from wordpress.org popularity. |
| S-10 `README_VERSION_RE` (`^stable tag:`) | S-10 L877-878 | Extracts plugin version | Per readme.txt spec; multiline/IGNORECASE. Sound | justified | Keep. |
| S-10 penalty: plugin≥1→`min(30, n*3)`; versioned≥1→`min(20, n*5)`; ≥8 plugins→issue | S-10 L1013-1028 | Per-checker score delta | **Scoring magic-numbers** (3/5 per-plugin, 30/20 caps). Uncalibrated | calibration-gated | **FLAG FIN-9.** |
| S-5 `LOOKBACK_DAYS=1825` (5yr) | S-5 L1045 | Window past which vendor breaches drop out | **Stale-table control — sound design.** Rationale inline (incomplete key rotation keeps incidents relevant). Paired with the Wave-5 **drift warn** (`VENDOR_BREACH_DRIFT_WARN_DAYS=60`) that nudges before rows expire silently. 5yr itself is a judgement call, not empirically pinned | calibration-gated | **FLAG FIN-9** for the 1825 value (window length affects which breaches score). Drift-warn mechanism is justified and confirmed present. |
| S-5 linear decay `1 - age/LOOKBACK`; `pen = SEVERITY_PENALTY[sev] × decay` | S-5 L1116-1117 | Full penalty at age 0, zero at 5yr | Linear decay is a reasonable shape; defensible. The shape choice (linear vs exponential) is a modelling assumption | calibration-gated (shape) | Note shape assumption; FIN-9 may revisit linear vs half-life decay. |
| S-5 `SEVERITY_PENALTY` {critical:25, high:15, medium:8, low:3}; default 5 | S-5 L1048, L1117 | Severity→penalty map feeding score + the S-5 uplift trigger | **Scoring magic-numbers.** Uncalibrated. (Also: unknown-severity default `5` > `low:3` — a row with a typo'd severity scores *higher* than an explicit `low`; minor inversion risk) | calibration-gated | **FLAG FIN-9** for the map. Free fix: clamp unknown-severity default to `low`(3) or skip, so a malformed row can't out-score an explicit low. |
| S-5 `_days_since` ⇒ `99_999` on parse failure | S-5 L1066-1072 | Bad/missing date ⇒ effectively "ancient" ⇒ dropped by lookback | **Fail-safe, not fabrication:** a malformed date is excluded, not invented as recent. Correct direction | justified | Keep. |
| S-5 vendor_breaches.json (11 rows, 7 vendors, oldest okta 2022-01-20) | `vendor_breaches.json` | Curated breach DB | **Stale-table — primary risk class for S-5.** All 11 rows currently within the 1825d window (6 high, 3 medium, 2 critical); okta 2022-01-20 is the nearest-expiry (drift-warn target). No rows past lookback. `_meta.version` "2026-05-27" — manually maintained | fragile | Keep + maintain. Drift-warn covers silent expiry. Add: cap-table coverage for high-SA-exposure vendors (no Everlytic/Netcore/SA-ISP breach rows even though patterns exist). |
| `supply_chain_vulnerability_uplift` per-checker deltas: Magecart(S-2)+0.06; Civil-liability(S-1)+0.04; Vendor-breach crit(S-5)+0.04 / high+0.02 | `scoring_analytics.py` L2066-2091 | Observed supply-chain risk → p_breach uplift (pre-MC) | **Scoring magic-numbers.** Triggers are gated on `status=="completed"` + real counts (no fabrication-on-absent; S-1 dormant absent broker list, see above). Direction sound (observed→uplift, no double-count w/ cat-tail per L2700-2736). Magnitudes (0.06/0.04/0.02) are the open question | calibration-gated | **FLAG FIN-9.** Architecture (reporting-only cross-corr stays out, no K_TAIL_SC) confirmed respected — do not re-add. |
| `sc_vuln_uplift = min(0.15, …)` cap | `scoring_analytics.py` L2099-2103 | Caps total SC uplift at +0.15 (mid of empirical +15-30pp band) | **Scoring magic-number.** Comment cites Ponemon/DBIR +15-30pp triangulation as basis — has a stated anchor, but mid-band placement and the cap value are calibration choices. No inversion/fabrication | calibration-gated | **FLAG FIN-9** to confirm 0.15 vs the +15-30pp band (arguably could sit higher when crit S-5 + Magecart stack). Basis is documented — good — but the value is gated. |

## Summary

total=31 justified=14 fragile=8 arbitrary=1 calibration-gated=8

**Top 3 concerns:**

1. **S-4 VENDOR_PATTERNS ↔ vendor_breaches.json coverage asymmetry (fragile, free fix).**
   S-4 detects 25 email vendors but only 7 have breach rows; 18 detected
   vendors can never correlate in S-5. No orphan breach rows (clean reverse),
   and Wave-1 Mandrill/Zoho folding is confirmed. Add SA-market senders
   (Mimecast, Proofpoint, Amazon Pinpoint) to patterns and document the
   detection≠breach-history asymmetry. Bucket-1.

2. **S-1 uplift is dormant in unattended scans (fragile, architecture-aware).**
   `RelatedDomainsChecker.check` only runs on a broker-supplied list;
   cert-SAN auto-discovery stays in pre-flight and never feeds the scan, so
   the +0.04 Civil-liability factor effectively never fires autonomously. Per
   the autonomous-verification memo, TLS-cert-match auto-promotion of
   high-confidence candidates would let S-1 contribute without a human —
   respects observed→uplift + no-double-count.

3. **Eight calibration-gated scoring magic-numbers — FLAG FIN-9, do not intuit.**
   The per-checker penalty constants (S-2 60/20/10, S-3 30/15/5, S-4 5/10/20,
   S-10 3/5 caps), the S-5 SEVERITY_PENALTY map, the +0.06/0.04/0.02 uplift
   deltas, the **+0.15 cap**, and the **1825-day lookback**. Direction/logic of
   every one is sound (observed→uplift, no inversion, no double-count); only the
   magnitudes are open. **Two free correctness sub-fixes** ride along: clamp the
   S-5 unknown-severity default (5) so a malformed row can't out-score an
   explicit `low` (3), and document the S-1 `<60` "high" cutoff. Confirmed clean
   from Waves 1-5: S-3 `_probe`, S-10 WP-fingerprint catch-all guard + plugin
   readme body-sanity, S-4 Mandrill/Zoho folding, vendor-row prune + drift warn.


---

# scoring_analytics.py — Heuristics Audit

**Scope:** `scoring_analytics.py` — `RiskScorer` (WEIGHTS, per-checker risk maps, WAF bonus,
risk-level bands), `RansomwareIndex` (RSI factors, caps, diminishing returns, industry/size
multipliers), `FinancialImpactCalculator` (`_calculate_zar` p_breach / TEF / vulnerability,
cost components, regulatory stack, MC/PERT/GPD, return-period mapping, coverage K_TAIL),
`DataBreachIndex`, `RemediationSimulator` (REMEDIATION_MAP + Wave-4 caps), `MITIGATIONS`.
**Method:** Step-6 Card Verification Protocol (white-box). Each heuristic screened for the five
back-test failure modes (fabrication-on-absent, generic/error-as-signal, boolean-as-count,
inversion, stale table) and classified `justified` / `fragile` / `arbitrary` / `calibration-gated`.
**Calibration discipline:** per the protocol + FIN-9 rule, calibration-gated constants are FLAGGED
with the anchor that should set them — **no new values proposed here**. Concrete fixes are proposed
ONLY for genuine correctness bugs (fabrication/inversion/boolean-as-count/wiring).
Cross-references OUTSTANDING.md §6 + §6b and `credential_confidence_pbreach_design.md` (5L).

---

## A. RiskScorer — overall posture score (0-1000)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `WEIGHTS` dict (31 entries, ssl 0.09 … financial_impact 0.02; nominal sum ~1.32) | L481-524 | Relative category weight in weighted posture sum | Documented (docstring) — derived rows over-1.0 by design; redistribution rescales failed/skipped. Not empirically fitted, expert-set | calibration-gated | Weights are the posture-model's free parameters; anchor relative ordering to DBIR root-cause shares (credentials/exploits) + Sophos SA. Don't intuit individual deltas |
| `breach_risk = min(100, breach_count*15)` | L628 | HIBP breach count → 0-100 risk | Count-based (not boolean) — OK. 15/breach is arbitrary slope | calibration-gated | Slope vs DBIR repeat-breach base rate |
| `admin_risk = min(100, crit*50 + high*20)` | L636 | Exposed-admin count → risk | Count-based. Depends on exposed_admin 403-inversion fix (Wave 1) upstream — values here fine | calibration-gated | Slope arbitrary; flag |
| `hrisk = min(100, crit_count*35)` | L640 | High-risk protocol criticals → risk | Count-based OK | arbitrary | Document 35/port rationale or flag |
| `dnsbl_risk = min(100, listed*50)` | L643-645 | DNSBL listings → risk | Counts list **entries** (len of ip+domain listings), not a boolean — OK post Wave-1 DNSBL fix. 50/listing harsh (2 listings=100) | fragile | Depends on DNSBL checker correctly excluding open-resolver `127.x` replies; if upstream fixed, slope still steep — flag |
| `dehashed_risk = min(100, total_entries*2)` guarded by status not in (no_api_key, auth_failed) | L676-677 | Credential count → risk (weight 0.03) | Count-based, status-guarded (no fabrication on absent key). **But confidence-blind**: 13 stale email-only == 13 fresh passwords (the 5L problem) | calibration-gated | **Top-3 leverage.** Replace with confidence-weighted credential class per `credential_confidence_pbreach_design.md` K1-K7 (DBIR/Mandiant/Sophos SA). FIN-9 |
| `shodan_risk *= 1.3` (weaponized) / `*1.1` (PoC), cap 100 | L669-672 | Boost CVE risk for weaponized/PoC exploits | Count-gated (>0). Multipliers arbitrary | arbitrary | Document or anchor to EPSS/KEV exploit-maturity |
| `vpn_risk = 40 if rdp_exposed else (20 if not vpn_detected else 0)` | L660 | RDP/VPN posture → risk | Boolean-driven flags (legitimately boolean) — OK | fragile | "no VPN detected = 20" risks penalising orgs whose VPN isn't externally visible; flag basis |
| Score defaults via `inv(...score, DEFAULT)` (ssl 50, email 5/10, http 50, tech 100, vt 100, st 100, fd 100, pc 100, wr 30, id 100, ext_ip 100) | L623-744 | Fallback risk when checker absent | **Fabrication-on-absent screen:** most default to 100-score→0-risk (safe, no false penalty) OR are status-guarded to 0. `web_ranking` default 30→70 risk if absent is a mild penalty-on-absent | fragile | wr default 30 invents risk when ranking unknown; prefer redistribute (status-skip) over a baked-in penalty |
| WAF bonus −50 (full) / −25 (blinding WAF) | L797-802 | Web-control credit, halved when WAF blinded the scan | Anti-inversion design (correctly discounts blinded credit) — good. Magnitudes arbitrary | calibration-gated | −50/−25 vs measured WAF efficacy; flag |
| Risk-level bands 600/400/200 (Critical/High/Medium/Low) | L806-811 | 0-1000 → label | Arbitrary cutpoints; cosmetic | calibrationarbitrary | Document; align with premium tiers |
| Redistribution `scale = (remaining+excluded)/remaining` | L611-620 | Reallocate failed/skipped weight | Correct conservation logic — no failure mode | justified | Sound |
| `completeness_pct = 1 - failed/assessable` | L843 | Scan-completeness % | Correct (skipped excluded from denominator) | justified | Sound |
| COMPLIANCE_MAP control weights (0.6-1.2); pass/partial/fail at 70/40 | L236-460, L889-893 | Framework % via weighted sub-control avg | 70/40 cutoffs arbitrary but cosmetic; weights expert-set | arbitrary | Document; not a scoring input to p_breach |

## B. RansomwareIndex (RSI, 0.0-1.0)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `base = 0.05` inherent | L1003 | Floor exposure | Documented (internet-exposure baseline) | calibration-gated | Modest; flag |
| RDP +0.25 | L1009-1011 | #1 ransomware vector | Boolean flag (legit). Sized as dominant single signal (documented) | calibration-gated | Anchor vs Mandiant/Sophos RDP initial-access share |
| DB ports +0.10 each, cap 0.20 | L1014-1019 | Exposed DB ports | Count-based, port-allowlisted — OK | calibration-gated | Slope/cap vs anchor |
| Credential class +0.20/+0.15/+0.08/0 (CRIT/HIGH/MED/LOW) | L1026-1039 | `credential_risk.risk_level` → RSI | **Confidence-aware (the precedent 5L wants to match)** — uses level not raw count; LOW=0 (no fabrication). Sophos SA 34% cited | calibration-gated | Already the good pattern; values still FIN-9. Anchor: Sophos SA creds #1 (34%) |
| KEV +0.08 each cap 0.20; high-EPSS(>0.5) +0.04 cap 0.12; other crit/high +0.02 cap 0.08 | L1042-1064 | CVE severity → RSI | Count-based, KEV/EPSS-gated — OK | calibration-gated | Slopes/caps vs EPSS exploit-probability |
| info_disclosure +0.02/crit cap 0.08 | L1069-1075 | Critical exposed files | Count-based, risk_level=="critical" gated — OK | calibration-gated | Flag |
| No DMARC +0.08 / policy none +0.05 | L1081-1087 | Email vector | Boolean — OK. Sophos SA 22% cited | calibration-gated | Anchor to DMARC efficacy (CISA BOD 18-01) |
| No WAF +0.05; weak SSL (D/E/F) +0.05 | L1090-1098 | Hygiene | Boolean — OK | calibration-gated | Flag |
| SUPPLY_CHAIN_CAP 0.22 + S-10/S-3/S-2/S-4/S-1 sub-factors (0.02-0.05) | L1131-1231 | SC vectors, proportionally scaled under cap | Status=="completed"-gated (no fabrication); cap+rescale documented vs RDP 0.25; DBIR 30% / Patchstack / Mandiant cited | calibration-gated | Well-reasoned; values FIN-9. Anchor: DBIR third-party 30% |
| Glasswing −0.05 (favourable), floor base≥0 | L1236-1247 | AI-vuln-programme credit | Observable-signal-gated, floored — OK | arbitrary | −0.05 undocumented magnitude; flag |
| `_diminishing`: linear ≤0.5, `0.5+0.5(1-e^-2x)` above | L988-999 | Anti-stacking compression | Math sound; −2.0 rate arbitrary | calibration-gated | Curve shape vs target distribution; flag |
| INDUSTRY_MULTIPLIER 0.80-1.30 | L967-986 | Ransomware-targeting uplift | Sophos/CheckPoint baseline; SA adj public-sector only; rest "require SA calibration" (self-documented) | calibration-gated | SA ransomware-targeting data |
| Size multiplier 0.85-1.12 by revenue band | L1265-1286 | Maturity-by-size | Bands aligned to Sophos SA median R200M (documented) | calibration-gated | Flag bands |
| RSI label bands 0.75/0.50/0.25 | L1290 | Label | Arbitrary cutpoints | arbitrary | Document |

## C. FinancialImpactCalculator — ZAR path (`_calculate_zar`, the live underwriting path)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `vulnerability = (100 - _overall_score/10)/100` | L2037-2038 | Posture score → 0-1 vulnerability | **Now live (Wave-1 wired `_overall_score`; was pinned at 0.5).** Linear map never validated against working coupling | calibration-gated | **TOP-1 leverage** (§6b). Curve shape vs DBIR/IBM base rates. FIN-9 |
| `p_breach = vulnerability × TEF × 0.3` | L2107 | FAIR LEF | **The `0.3` is the single highest-leverage constant** — scales every breach-family probability. Never validated post-coupling | calibration-gated | **TOP-2 leverage** (§6b). Anchor absolute p_breach for a worst-posture org vs DBIR/IBM industry base rate. FIN-9 |
| TEF table 0.80-1.45 | L1840-1859 | Industry targeting frequency | DBIR/IBM/Sophos/SABRIC cited; range deliberately modest (documented) | calibration-gated | Per-industry SA targeting; flag |
| SC vulnerability uplift: Magecart +0.06, S-1 +0.04, S-5 crit +0.04/high +0.02, cap +0.15 | L2066-2104 | Direct p_breach uplift for SC paths | Status-gated (no fabrication); DBIR 30%/IBM CoDB/Mandiant cited; cap documented; no double-count w/ cat-tail (design note) | calibration-gated | Values FIN-9; anchor DBIR/IBM CoDB |
| IBM_BREACH_TOTAL R49.22M; MEDIAN_REVENUE R200M; C4_PROPORTION 0.1040 | L2120-2122 | Severity anchor + ransom share | IBM SA + Sophos SA derivation shown (R8M×64%) | calibration-gated | Refresh each IBM/Sophos annual; flag drift |
| Elasticity 0.35-0.60 by revenue band | L2124-2139 | Revenue→severity scaling exponent | Graduated, documented intent; exponents arbitrary | calibration-gated | Anchor to IBM revenue-regression |
| Graduated industry multiplier (only if >1.0) | L2150-2155 | Small-co data-density discount | Reasoned (documented) | calibration-gated | Flag |
| `record_density_divisor` (R5k-R1M/record by industry) | L2180-2210 | est. records (reference/disclosure only, **not in cost calc** — documented) | Not a cost input; disclosure transparency | fragile | SA-market observation, not sourced; flag but low-leverage |
| `records_validity_ceiling` (50k-500k) | L2225-2257 | Floor-estimate disclosure trigger | Disclosure only; documented vs IBM regression window | arbitrary | Document basis; non-scoring |
| C2 POPIA `min(10M, rev×0.02)` | L2272-2273 | POPIA fine (expected) | 2% explicitly flagged "internal heuristic, NOT statutory"; R10M ceiling correct | calibration-gated | Enforcement-discount % (OUTSTANDING §6) |
| C2 GDPR rev×0.04 (flag-gated); PCI R1M×(1−adj); EXTERNAL_PCI_VISIBILITY 0.30; other R2M/jurisdiction | L2275-2295 | Per-jurisdiction fines | Flag-gated (no fabrication). 0.30 visibility documented; R2M arbitrary | calibration-gated | PCI visibility + R2M vs SA precedent |
| Cat stack (ECTA R1M, CPA max(R1M,10%rev), capacity_factor 0.10-1.00, SECTOR_FRAMEWORKS statutory maxima, FSCA R100M assumption) | L1356-1484, L2301-2348 | Statutory-max cat stack, capacity-scaled | Statutory maxima sourced (gap-analysis v10); FSCA R100M flagged as model assumption; **STALE-TABLE risk** (statutory maxima change by amendment) | calibration-gated | Re-verify statutory maxima annually (stale-table). Capacity bands flag |
| C5 IR tier R250k-R5M by revenue | L2365-2382 | DFIR cost | Reasoned bands; arbitrary magnitudes | calibration-gated | SA DFIR market data |
| INDUSTRY_BI_FACTOR 0.05-1.75 (86 sub-industries) | L1877-1977 | Downtime cost allocation (conservation, not inflation — documented) | Sourced from FAIR lookup tables; exact, no averages | justified | Cited lookup-table source |
| SA_AVG_DOWNTIME 25d; IMPACT_FACTOR 0.50 | L2399-2401 | C3 downtime | Sophos SA cited; 0.50 documented as recovery-curve avg | calibration-gated | Anchor 25d/0.50 to Sophos SA |
| INCIDENT_SPLIT_RATIOS (0.05-0.50) | L1986-1993 | Incident-type decomposition | Sophos SA 2025 derivation shown (60%×39%≈0.25) | calibration-gated | Refresh vs Sophos SA annual |
| Per-incident downtime/cost modifiers (silent ×0.60 C5, extort C4×0.40, opp C1×0.50/C5×0.40, C3 2d/3d/1d/5d) | L2459-2519 | Incident cost shaping | Reasoned; magnitudes arbitrary | calibration-gated | Flag |
| `loss_pct` → fin_score steps 0.30/0.15/0.08/0.04 → 10/30/50/70/90 | L2786-2798 | Loss% → 0-100 financial score | Step function arbitrary; **note:** this `score` feeds `fin_risk` back into posture (weight 0.02) — mild circularity, low weight | fragile | Document steps; circularity acceptable at 0.02 |
| `p_interruption` 0.05 base + 0.05 each (WAF/CDN/single-ASN), cap 0.5 | L2109-2115 | BI/DDoS probability | Boolean signals — OK | calibration-gated | Flag |
| SA_INDUSTRY_COSTS (breach_cost_zar, cost_per_record, multiplier) | L916-941 | IBM-2025-ZAR per-industry anchors | "IBM 2025 translated to ZAR" — sourced | calibration-gated | Refresh annually (stale-table); flag |

## D. Monte Carlo / PERT / GPD / return periods

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| MC_ITERATIONS 50_000 | L1326 | Sim count for stable P99.6 (~200 tail) | Documented (wall-time/Render-memory tradeoff) | justified | Sound |
| `np.random.seed(42)` | L1750, L2550 | Determinism | Reproducible output — intentional | justified | Note: identical seed both paths; fine |
| PERT λ=4 | L1337 | Standard PERT shape | Standard | justified | Standard |
| PERT spreads: total_breach 0.5×/5.0× (was 2.5×, widened B3); mc_c2 upper=cat_stack; downtime PERT(3,25,120); component 0.5×/2.5× | L2564-2583 | MC bounds | Widening documented (Transnet/Life/Experian precedent) | calibration-gated | Tail recalibration vs SA cat data (OUTSTANDING §6) |
| GPD MOM (shape=0.5(1−m²/v), scale=0.5m(1+m²/v)); sanity guards (n<50→raw, fitted<raw→raw, >10×raw→raw) | L1486-1551 | Tail extrapolation for return periods | Pure-numpy MOM (no scipy, Render constraint, documented); guards prevent overshoot | justified | MLE upgrade deferred (OUTSTANDING §6); guards sound |
| K_TAIL 1.20 (WAF blind-spot tail widening), shortfall cap 0.60 | L2670-2671 | Widen P75+ when WAF blinded scan | EPISTEMIC-uncertainty design (correctly NOT via p_breach; restores P5-P50 + mode); documented | calibration-gated | SCN-029: calibrate vs blinded-vs-rescan deltas. **Do NOT re-add K_TAIL_SC** (double-count, design note L2700) |
| Return-period mapping P99/P99.5/P99.6 → 1-in-100/200/250 | L2997-3005, L3009-3017 | Percentile → return period | Mathematically correct (1/(1−q)); prefers GPD-fitted | justified | Correct |
| SME_BANDS snap (R1M…R15M, then R5M increments) | L2763-2772 | Cover-band snapping (deprecated/internal) | Cosmetic; cover no longer recommended (FAIS) | justified | Deprecated path |
| `_DEDUCTIBLE_TABLE` (RSI 0.10-1.00 → 0.5%-20%), clamp ≥0.10 | L1600-1631 | RSI → deductible % | Non-linear interp; magnitudes arbitrary | calibration-gated | Actuarial deductible curve |

## E. DataBreachIndex (DBI, 0-100, higher=better)

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| breach_count 0→30 / ≤3→15 / else 0 | L3234-3242 | Count points | Count-based — OK | arbitrary | Document cutoffs |
| recency <365d→0 / <1095d→10 / else 20; except→10 | L3244-3261 | Recency points | Date-parsed (real recency, not boolean); except-fallback 10 reasonable | justified | Date-anchored, sound |
| data_severity: severe-class set → 0 / emails-only→10 / none→15 | L3263-3273 | Sensitivity points | Curated severe-class set; **stale-table risk** (HIBP class names) | fragile | Verify against current HIBP `data_classes` vocabulary periodically |
| credential_leaks: unknown→10 / 0→20 / ≤100→10 / else 0; status-guarded `-1` | L3275-3289 | Dehashed volume points | Status-guarded (no fabrication on absent key) — good | arbitrary | Cutoff 100 arbitrary; document |
| trend: recent(<730d) 0→15 / ≤2→7 / else 0 | L3291-3312 | Trend points | Date-parsed — OK | justified | Date-anchored |
| DBI label bands 80/60/40/20 | L3314-3315 | Label | Cosmetic | arbitrary | Document |

## F. RemediationSimulator + MITIGATIONS

| Heuristic (value) | Location | What it does | Failure-mode / anchored? | Class | Recommendation / anchor |
|---|---|---|---|---|---|
| `RSI_RESIDUAL_FLOOR = 0.05` | L3341 | RSI floor (no posture risk-free) | Set heuristically (Wave 4); mirrors RSI base 0.05 | calibration-gated | §6b: ~81% modelled loss-cut now a calibration Q. FIN-9 |
| `MAX_RSI_REDUCTION_FRACTION = 0.15` | L3342 | Residual ≥15% of current RSI | Wave-4 heuristic; mirrors 85% loss cap | calibration-gated | §6b. FIN-9 |
| REMEDIATION_MAP rsi_reduction values (0.01-0.35) | L3344-3429 | Per-fix RSI delta | Mirror RSI factor weights (RDP 0.35 etc); condition_fns status/count-gated (no fabrication); ghost-audit closed (5 added 2026-05-27) | calibration-gated | Must track RSI factor sizes; flag |
| savings `= (rsi_reduction/current_rsi) × total_likely × 0.7` | L3446 | Per-step savings | 0.7 realisation factor arbitrary | arbitrary | Document 0.7 |
| 85% total-savings cap | L3190-3196 (`_build_mitigations`), L3477 floor | Can't eliminate all risk | Internally consistent w/ RSI floor — good | justified | Sound |
| MITIGATIONS reductions (rsi/probability/bi 0.02-0.25) | L3063-3093 | Incident-family deltas | Regex-pattern-matched on issues (substring risk: e.g. `r"SSL.*grade.*(C\|D\|F\|T)"` could mis-match) | fragile | Patterns brittle; align values w/ REMEDIATION_MAP; flag |

## G. Peer benchmarking interplay (module: `peer_benchmarking.py`)

Out-of-file but in-scope as interplay: peer module **consumes** `rsi_score` / `risk_score`
outputs of this module and resolves the revenue band "the SAME way the FinancialImpactCalculator"
capacity-factor table does (peer_benchmarking.py L25, L300). Note `rsi_score or 0.5` fallbacks
(peer L338/L420) — a fabrication-on-absent screen point, but it lives in the peer module, not here.
Cohort-bias correction is calibration-gated (OUTSTANDING §6, `lower_tier_upsell`). No correctness
bug in this module's side of the interface.

---

## Summary

**total = 56**  •  **justified = 13**  •  **fragile = 11**  •  **arbitrary = 12**  •  **calibration-gated = 36**
*(counts exceed 56 because several rows carry a primary class plus a secondary stale-table/fragility flag; primary-class tally: justified 13 / fragile 11 / arbitrary 12 / calibration-gated 36 ≈ the dominant bucket).*

### The 3 highest-leverage calibration constants (all FIN-9, do NOT intuit)
1. **`0.3` in `p_breach = vulnerability × TEF × 0.3`** (L2107) — scales every breach-family
   probability; never validated since Wave-1 made the `_overall_score` coupling live. Anchor:
   DBIR / IBM CoDB absolute breach base rates.
2. **`vulnerability = (100 − _overall_score/10)/100`** (L2038) — the posture→probability curve,
   first time coupled to a real score. Anchor: DBIR/IBM base-rate calibration of the curve shape.
3. **`dehashed_risk = min(100, total_entries × 2)`** (L677) — confidence-blind credential input;
   the 5L pre-read's whole purpose. Replace with the confidence-weighted credential class
   (`credential_confidence_pbreach_design.md` K1-K7). Anchor: Sophos SA (creds #1, 34%) + DBIR/Mandiant.

### Genuine correctness bugs found in THIS module
**None new.** All five back-test failure modes were screened:
- **Fabrication-on-absent:** every API-keyed checker (dehashed, virustotal, securitytrails, GDPR/PCI
  flags) is status- or flag-guarded before contributing — no invented values. The only mild
  penalty-on-absent is `web_ranking` default score 30 → risk 70 (L703) — *fragile, not a bug*
  (prefer redistribution over a baked-in penalty).
- **Boolean-as-count:** the count-based maps (breach_count, dehashed total_entries, dnsbl listings,
  KEV/EPSS counts) all consume real integers, not booleans. DNSBL counts list **length** (L643-645),
  correctly avoiding the "13 with passwords" class of bug.
- **Inversion:** none — the WAF bonus (L797) and WAF blind-spot K_TAIL (L2663) are explicitly
  designed *against* inversion (blinded scans are discounted / tail-widened, not rewarded).
- **Stale-table:** flagged (not bugs today) on `SECTOR_FRAMEWORKS` statutory maxima (L1374),
  `SA_INDUSTRY_COSTS` / `IBM_BREACH_TOTAL` (annual IBM/Sophos refresh), and DBI's severe-class set
  / HIBP `data_classes` vocabulary (L3265) — add a periodic-refresh check.

The module's correctness was materially improved by the 2026-06-03 Wave 1-5 fixes (especially wiring
`_overall_score` into `vulnerability`, which had been pinned at 0.5). The residual work is almost
entirely **calibration**, correctly deferred to FIN-9 + the 5L credential-confidence session — not
correctness. The dominant audit finding is that **36 of 56 heuristics are calibration-gated**, which
is expected for the calibration-heaviest module and consistent with OUTSTANDING §6/§6b.


---

# scanner.py + supporting — Heuristics Audit

White-box Step-6 heuristics sweep of the orchestrator (`scanner.py`) plus
`origin_discovery.py`, `flag_inference.py`, `related_domain_discovery.py`,
`http_client.py`. Research only — no code changed. Screened against the
Step-6 failure modes: fabrication-on-absent-input, generic/error response
read as signal, boolean-as-count, inversion, stale curated table.

Classes: **justified** (cite basis) / **fragile** (works on sample, harden) /
**arbitrary** (no rationale — document or remove) / **calibration-gated**
(scoring magic-number — FLAG for FIN-9, do NOT intuit).

Confirmed-clean from Waves 1–5 (re-verified, listed for completeness):
`pw_records` (line 81) is a true plaintext+hashed COUNT from
`DehashedChecker.credential_breakdown` — boolean-as-count resolved; the
narrative falls back to "some with passwords" only when `has_pw` and count==0.
Cross-correlation severity (lines 1001–1014) tracks the **worst** underlying
vendor-breach severity, not blanket CRITICAL. `_overall_score` is written
back to `cat_results` (line 1114) so Financial Impact reads real posture.

| Heuristic (value) | Location | What it does | Failure-mode screen | Class | Recommendation |
|---|---|---|---|---|---|
| Credential recency bands `<30/90/180/360/730d` | scanner.py:23,35–43 | Buckets dated leak/infection records into 6 age bands for the export + card | No fabrication (None→None); pure presentation, carries no score weight | **justified** | Keep. Band edges are display buckets, not score inputs — document as cosmetic. |
| `COMBO_LIST_SOURCES` set (10 named aggregator lists) | scanner.py:28–32 | Marks DeHashed sources as re-circulated combo dumps so a recent OBSERVED date can't read as fresh theft | **Stale curated table** — hardcoded list silently goes out of date as new combo dumps appear (alien txtbase, naz.api already dated); a NEW unlisted combo list scores as genuine recency | **fragile** | Harden: this is the right design but needs a drift test (like `vendor_breaches.json`) + a dated review marker. Add `socradar`-class entries on review. Matching is exact-lowercase-strip — a source named "Collection #1 (2019)" misses. Consider substring/prefix match. |
| `all_combo` gate (combo-only ⇒ recency discounted) | scanner.py:124–125,146 | If EVERY source is a combo list, `recent_genuine` requires fresh infostealer instead | Correct anti-inversion (protects against recycled-data false "active"); depends on the stale table above | **justified** | Keep; inherits the COMBO_LIST drift risk only. |
| `active_theft_fresh` cutoff `hr_days <= 90` | scanner.py:133 | Infostealer infection ≤90d ⇒ "live theft"; drives critical/high verdict | 90d is a verdict-severity threshold (changes critical vs high → financial exposure). Not fabrication, but a magic cutoff with no cited basis | **calibration-gated** | FLAG for FIN-9. Do NOT intuit. Anchor to infostealer log-resale half-life (Hudson Rock / Flare median credential-validity window). |
| `recent_genuine` cutoff `freshest <= 360` | scanner.py:146–147 | Non-combo breach within 1yr counts as genuinely recent | Same class as above — 360d magic edge feeds the severity ladder | **calibration-gated** | FLAG for FIN-9 with the 90d cutoff; calibrate both together against breach-recency loss curves. |
| Severity ladder None→Critical (8 branches) | scanner.py:169–187 | Maps signal combo (breached × active_theft_fresh × circulating × freshest) to severity + count | No boolean-as-count (counts derive from `sev`); logic is internally consistent but the *boundaries* are intuited | **calibration-gated** | FLAG. Reporting-only card so financial leakage is indirect, but it's the headline "rotate now" verdict — calibrate the branch order/cutoffs at FIN-9, don't tweak ad hoc. |
| `de_sources[:6]` / `[:4]` / `fam[:4]` / `[:5]` narrative caps | scanner.py:153,192,207,1016,1044 | Truncate lists in human-readable strings | Cosmetic display caps; no score, no fabrication | **justified** | Keep — document as presentation truncation. |
| `IP_LEVEL_CHECKERS` tuple (4 checkers) | scanner.py:252 | Which checkers run once per discovered IP (dns_infra, high_risk_protocols, dnsbl, shodan_vulns) | Architectural selection, not a signal heuristic; no failure-mode applies | **justified** | Keep. Curated set matches per-IP semantics. |
| `_aggregate_ip_results` richness = `max(findings)` | scanner.py:295–334 | Picks the per-IP result with most ports+CVEs+issues as the aggregate | Comment explicitly guards the inversion (score 0 = "no data" not safe, so min(score) is wrong) — correct. Merges issues/ports across IPs | **justified** | Keep; the anti-inversion reasoning is documented in-code. |
| Concurrency `max_workers=6` (domain) / `4` (IP) | scanner.py:474,585 | Thread-pool sizes, tuned for Render 512MB | Resource tuning, not a signal; no failure mode | **justified** | Keep — cite Render free-tier RAM cap. |
| `as_completed(timeout=180)` + `DEFAULT_TIMEOUT*2` per-future | scanner.py:480,483,598 | Wall-clock guards; timeout ⇒ `{"status":"timeout"}` | Timeout produces explicit `status:timeout`, NOT a false "no findings" — correctly avoids generic-as-signal | **justified** | Keep. The status surfaces in completeness metadata. |
| Heavy-checker budgets: ssl=75, subdomains=150, fraud=60 | scanner.py:428–441 | Per-checker wall-clock caps | Documented rationale in-code (150 derived from 150 CT subdomains × probe time); not a signal heuristic | **justified** | Keep — rationale already inline. |
| RDP reconcile: `port==3389` on any IP ⇒ `rdp_exposed=True` | scanner.py:631–643 | Surfaces RDP found on origin IPs the apex probe missed | True port-scan hit (not a 403/200 catch-all). Open-port ⇒ exposed is correct; no inversion | **justified** | Keep; fixes a real false-negative. Optionally confirm 3389 served RDP banner (vs reassigned). |
| OSV CVSS-from-severity map `{crit:9.5,high:7.5,med:5.0,low:2.5}` | scanner.py:716 | Fabricates a CVSS when OSV gives none | **Fabrication on absent input** — invents a numeric CVSS where source has none; feeds CVE counts/financial. Mild (bounded, only when severity present) | **fragile** | Harden: mark these CVEs `cvss_estimated=True` so renderers/score can distinguish a real 7.5 from an inferred one. Edges themselves are conventional severity-band midpoints — defensible but should be flagged-as-estimate. |
| `widely_exploited = epss > 0.4`; `high_epss = epss > 0.5` | scanner.py:749,814,827 | EPSS thresholds for "widely exploited" flag | EPSS 0.4/0.5 are score-driving cutoffs feeding CVE exploitability counts → financial | **calibration-gated** | FLAG for FIN-9 — these mirror cutoffs likely used in `checkers_threats`; calibrate centrally, not per-site. |
| `exploit_maturity` upgrade theoretical→poc_public at epss>0.5 | scanner.py:816–817 | Promotes maturity label on high EPSS | Same EPSS-cutoff family | **calibration-gated** | FLAG with the EPSS thresholds above. |
| `patch_management` age buckets 90/180d | scanner.py:779–782 | Buckets CVE age into <90 / 90–180 / >180 | Presentation buckets over a real `age_days`; no fabrication (None excluded) | **justified** | Keep — display buckets. |
| Coverage `total_checkers` fallback **27** | scanner.py:1164 | Denominator for `coverage_pct` when scorer didn't set `total_checkers` | **Stale magic number** — scorer authoritatively sets this to `len(WEIGHTS)` = **31**; the 27 fallback is wrong and would silently under-count coverage if the key were ever missing | **arbitrary** | Replace literal 27 with `len(RiskScorer.WEIGHTS)` or drop the fallback (key is always set upstream). Document or remove. |
| WAF-affected = checker `completed` with empty `issues` | scanner.py:1144–1162 | Flags checkers as WAF-blinded if no issues during a blocked scan | Risk of **inversion**: a genuinely clean checker (no findings = good) gets a "partial coverage" disclaimer only when apex is WAF-blocked — gated correctly by `waf_apex_status.blocked`, so a well-defended clean site isn't penalised in score (disclaimer only) | **fragile** | Acceptable (disclaimer, not score) but "empty issues ⇒ blinded" conflates "clean" with "blocked". Harden: prefer per-checker `status:timeout`/`no_data` over `not issues`. |
| `_consume` date parse: 2 formats, `[:10]` slice | scanner.py:89–101 | Parses dates from 4 heterogeneous sources | Silent skip on unparseable date (no fabrication); but only `%Y-%m-%d`/`%Y/%m/%d` — ISO-T timestamps & `DD/MM/YYYY` silently dropped ⇒ undercounts `dated_records`, weakening recency | **fragile** | Harden: accept ISO-8601 (`fromisoformat`) + log drop count. Affects recency completeness, not correctness. |
| **flag_inference** `JSE_LISTED_DOMAINS` (≈70 rows, snapshot 2026-05-15) | flag_inference.py:46–124 | Static domain→ticker map for listed-company flag | **Stale curated table** — explicitly snapshot-dated; de-listings/new-listings drift silently. Listed status changes D&O/disclosure posture | **fragile** | Harden: add a review-date assertion + drift test. Footer-ticker scrape (below) is the live fallback, mitigating staleness for missed entries. |
| `JSE_TICKER_RE` footer scrape `JSE\s*:\s*([A-Z]{2,5})` | flag_inference.py:128,164 | Medium-confidence listed detection from homepage footer | Loose 2–5 cap letter match after "JSE:" — could match unrelated "JSE: HELP" text; low false-positive risk (rare token) | **fragile** | Harden: require the captured ticker to be a real JSE ticker (cross-check a ticker set) before auto-flagging. |
| `B2C_SUB_INDUSTRY_LABELS` (16 SIC labels) | flag_inference.py:193–212 | Auto-ticks B2C ⇒ adds CPA s112 (10% turnover) to cat stack | Conservative-by-design (excludes ambiguous FS brokers/lenders — documented). **B2C mis-flag materially inflates B2B exposure** — the highest-stakes flag in this module | **justified** | Keep the conservative list. BUT verify the supporting-signal overrides (next row) can't re-introduce false B2C on a B2B site. |
| B2C supporting overrides: `payment_form_detected` / `ecommerce_tech_detected` | flag_inference.py:259–266,528–530 | A payment form or e-comm platform flips ambiguous sub-industry to B2C | **Generic-signal risk**: `PAYMENT_FORM_HINTS` matches `/cart`, `add to cart`, `"@type":"Product"` — a B2B wholesale portal or any site with a cart string auto-flags B2C, adding CPA s112 fines to a B2B insured | **fragile** | HARDEN (high priority — changes regulatory/financial exposure). The hint regex is broad; `add to cart`/JSON-LD `Product` appear on B2B catalogs. Require ≥2 independent signals, or gate s112 on broker confirmation rather than auto-add. Note: UMA/reinsurer override (line 242–252) correctly hard-negates first — good. |
| `ACCOUNTABLE_INSTITUTION_LABELS` (8 SIC labels) | flag_inference.py:216–225 | FIC Act AI status from sub-industry | Maps SIC→FIC Schedule 1; "Real Estate"/"Legal Services" are AIs per Act — cited basis. Sub-industry, not free-text, so low false-positive | **justified** | Keep — FIC Schedule 1 is the legal basis; add a comment cite. |
| Insurance subtype regexes UMA/reinsurer/broker/carrier + priority order | flag_inference.py:304–367 | Classifies insurance entity; UMA/reinsurer ⇒ hard B2B | Priority order documented (UMA before catch-all carrier). `\bUMA\b`/`\bMGA\b` could match unrelated acronyms in body text (5000-char haystack) | **fragile** | Harden: weight domain/title matches over body-text acronym hits; `\bUMA\b` in unrelated prose would mis-classify a carrier as UMA (negating B2C wrongly — but that's the safe direction for exposure). |
| Healthcare sub-detail keyword classifier + default `hospital_clinic` | flag_inference.py:374–412 | scheme/pharmacy/pharma/hospital from keywords; defaults hospital_clinic | **Fabrication-on-absent-input (soft)**: with NO signal it still auto-detects `hospital_clinic` with `auto_detected=True` and evidence "Default … no specific subtype signal" — a guess presented as a detection | **fragile** | Harden: set `auto_detected=False` for the no-signal default so the broker sees it as an unconfirmed default, not a positive detection. |
| `GDPR_KEYWORDS` / `EU_LANGUAGE_HINTS` | flag_inference.py:419–426,449–462 | Suggests GDPR applicability | EU-language hreflang ⇒ GDPR is weak (a SA site offering `fr`/`de` ≠ EU establishment); but it's a *suggestion* the broker confirms, `auto_detected` flagged as hint | **fragile** | Acceptable as broker-confirmed hint; ensure renderer labels it "suggestion" not "detected". hreflang alone over-suggests. |
| `PAYMENT_FORM_HINTS` / `ECOMMERCE_PLATFORM_HINTS` (PCI) | flag_inference.py:431–446,465–480 | Suggests PCI applicability | Same broad-regex concern as the B2C override; platform fingerprints (shopify/woocommerce) are strong, but the form-hint side (`/checkout`, `cvv`) over-matches | **fragile** | Platform fingerprints justified; raw card-field/URL hints fragile — prefer platform/structured-data signals for the auto-tick, demote loose path/word hits to "suggestion". |
| **origin_discovery** cert-match verify (CN/SAN covers domain) | origin_discovery.py:135–163 | Only IPs whose live TLS cert covers the domain enter the scan pool | Strongest possible attribution gate — chain validation off by design, identity judged by cert CN/SAN (documented). Anti-fabrication: unverified candidates surfaced but NEVER scanned | **justified** | Keep — textbook origin-confirmation; this is the reference pattern. |
| `MAX_CANDIDATES=25`, `VERIFY_TIMEOUT=5`, `VERIFY_WORKERS=8` | origin_discovery.py:44–46 | Caps + timeouts for candidate verification | Resource bounds; no signal interpretation | **justified** | Keep. |
| Shodan free `/host/count` hint vs paid `/host/search` | origin_discovery.py:77–112,185–189 | count-only on free plan; IPs on paid | 403 on free plan handled as "fall back to count" — NOT read as a finding (no generic-as-signal). Auto-activates on key swap | **justified** | Keep — graceful degradation, no false signal. |
| **related_domain_discovery** `SHARED_INFRA_SUFFIXES` (≈35 suffixes) | related_domain_discovery.py:62–75 | Excludes CDN/SaaS/CT-noise SANs from sibling candidates | **Stale curated table** (mild) — new CDN/SaaS suffix not listed ⇒ false sibling candidate. But broker confirms every candidate, so failure is contained | **fragile** | Low priority (broker-gated). Periodic refresh; document review cadence. |
| Pre-flight apex reducer | related_domain_discovery `_extract_san_apexes` -> `estate_discovery.registrable` and `_rejection` | Reduces SAN hosts to the registrable domain with the report's own rules | Shared with the scan's discovery since step 5 (2026-09-11); not a Public Suffix List (docs/OUTSTANDING.md 5ad) | fragile | Keep in parity with the report; a PSL snapshot is the proper fix. |
| `_confidence_for`: certificates>=5 and a shared brand -> high; >=3 or a shared brand -> medium | related_domain_discovery `_confidence_for`, `_brand_part` | Confidence label for broker review | Labels only, never scored or pre-ticked. A shared brand is the same first part of the name, at least four letters and not a generic business word; certificates are counted, not names (step 5, 2026-09-11) | justified | Keep (reporting-only confidence hint). |
| **http_client** `_apex_of` two-label eTLD sets | http_client.py:62–94 | Rate-limit / WAF key per registrable apex | Hand-rolled PSL subset (za/uk/au/nz/jp × co/org/ac/gov…); a non-listed ccSLD buckets wrong ⇒ mild rate-limit mis-keying, not a signal | **fragile** | Harden with PSL where available; SA-priority set is adequate now. Document. |
| RateLimiter `rate=2.0/s, burst=5` | http_client.py:114 | Polite pacing per apex | Cited basis (Bitsight/SSC/Coalition 1–3 req/s passive range) — documented | **justified** | Keep — industry-anchored. |
| WAFTracker thresholds: blocked≥40%, rate-limited≥25%, timeout≥50%, window=20 | http_client.py:173,232–243 | Calls an apex WAF-protected from response-mix | Drives the partial-coverage disclaimer (NOT score). Thresholds intuited; window=20 small — a 9/20 403 mix (45%) flips "blocked". Risk of **inversion** is contained: it gates a disclaimer, and a WAF *is* protective | **calibration-gated** (disclaimer-only) | FLAG lightly for FIN-9 review of the % cutoffs, OR document as deliberately conservative. Not financial — lower priority than the credential cutoffs. |
| WAF challenge regexes (6 vendors) | http_client.py:332–341 | Detects challenge pages by body fingerprint | "Conservative — strong signals only" (documented); `cloudflare.*ray.id` etc. are specific, low false-positive | **justified** | Keep — matches the S-3 "200-only + body-sanity" robust-gate spirit. |
| `discover()` HEAD→GET-on-405 | http_client.py:361–370 | Path-existence probe with method fallback | Correct (405 = method issue, retry GET); not a signal misread | **justified** | Keep. |
| Default request `timeout=10`; challenge-scan body cap `5KB`, codes `200–500` | http_client.py:404,427–429 | Request timeout + bounded regex cost | Resource bounds; challenge scan only on 2xx–4xx GET (HEAD has no body) — correct | **justified** | Keep. |

## Summary
total=37 justified=18 fragile=12 arbitrary=2 calibration-gated=5; top 3 concerns.

1. **B2C / PCI auto-detect over-broad regex (flag_inference.py:431–446, 259–266)** — highest-stakes finding. `PAYMENT_FORM_HINTS` matches generic cart/checkout strings and JSON-LD `"@type":"Product"`, so a B2B site with a cart string can auto-tick **B2C**, adding CPA s112 (10% turnover / R1M) to the catastrophe stack — a generic-response-as-signal that directly inflates regulatory + financial exposure for B2B insureds. Harden: require ≥2 independent signals or broker-confirm s112; prefer platform/structured-data fingerprints over loose path/word hits. (The UMA/reinsurer hard-negate at line 242 is correct and protective.)

2. **Stale curated tables (3): `COMBO_LIST_SOURCES`, `JSE_LISTED_DOMAINS` (snapshot 2026-05-15), `SHARED_INFRA_SUFFIXES`** — all silently drift. COMBO_LIST is the most consequential: a new, unlisted combo dump would read as genuinely-recent compromise and escalate the credential verdict. Add drift tests + dated-review markers (mirror the `vendor_breaches.json` pattern) and broaden COMBO matching beyond exact-string.

3. **Calibration-gated credential/EPSS cutoffs (90d fresh-infection, 360d recent-breach, the 8-branch severity ladder, EPSS 0.4/0.5)** — these set the headline "rotate now" verdict and CVE exploitability counts. DO NOT intuit: flag all for FIN-9 and calibrate together against infostealer credential-validity half-life and breach-recency loss curves. Plus two hygiene items: stale `total_checkers` fallback **27** (scorer sets it to 31 = `len(WEIGHTS)`) and OSV CVSS-from-severity fabrication (mark `cvss_estimated`).
