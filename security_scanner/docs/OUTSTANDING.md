# Outstanding Items — Phishield Scanner

**Last updated**: 2026-07-02
**Owner**: SML Consulting (engineering) + Phishield UMA (ops)
**Authoritative source** for items pending across the scanner project.
Consolidates open items from gap analysis SCN-* entries, memory files,
and session-level decisions. Update this file whenever a new
outstanding item lands.

**File pair:**
- `OUTSTANDING.md` (this file) is the live working version — edit here.
- `OUTSTANDING.docx` is a polished read-only snapshot for easy reading.
  Regenerate after each edit with `py -3 tooling/generate_outstanding_docx.py`
  (from the `security_scanner/` directory). The script applies Phishield
  branding and formats tables for printable / shareable output.

---

## 1. Hosting / infrastructure

| Item | Status | Owner | Target date |
|---|---|---|---|
| **Cloudflare / Hetzner proxy for `phishield.com/scanner-info`** | Pending hosting-company action | Hosting team | Tuesday 2026-05-19 (WordPress → HTML cutover). Handoff doc at `docs/scanner_info_proxy_setup.md`. Options: static copy (simplest), nginx reverse-proxy (cleanest), Cloudflare layer (long-term). |
| **User-Agent flip back to canonical `phishield.com/scanner-info`** | Blocked by proxy above | Engineering | After hosting team confirms `phishield.com/scanner-info` returns 200. Single-line change in `http_client.py` USER_AGENT constant. |
| **GCP migration of scanner backend** | **Largely DONE (2026-06).** Scanner runs live on the Google VM `veilguard-prod-jnb` (GCP project `rugged-sunbeam-492106-j1`, `africa-south1-a`, `n2-standard-8`) at `veilguard.phishield.com/scanner`, with a **dedicated Postgres 16** container (not the ephemeral Render SQLite). gunicorn under systemd, Caddy edge. Runbook: `docs/DEPLOYMENT.md`. | Phishield ops + engineering | **Remaining:** (a) **Vertex AI / LLM-augmented analysis** (the "protected environment + LLM" goal, not yet started). Render decommission is DONE in code (2026-07-06): the `phishield-scanner` block was removed from `render.yaml` and the scanner's self-identification (User-Agent + scanner-info page) repointed to the VM; only the Render-dashboard suspend/delete remains. The **persistent Postgres removes the ephemeral-`scans.db` risk to the encrypted-export enrichment (5k)** on the VM path. |
| **Eventual move to Hetzner self-hosted** | Future-future | TBD | After GCP/Vertex experience accumulated. |
| **Enable API auth (`SCANNER_API_KEY`)** | Code shipped 2026-06-11, env var NOT yet set (auth is opt-in / off) | Engineering + frontend | Set `SCANNER_API_KEY` on Render AND add the matching `X-Api-Key` header to the Vercel frontend's calls to `/api/scan`, `/api/preflight`, `/api/credential-export`, balance endpoints. Order matters: frontend first or simultaneously, else scans 401. Rate limiting (per-IP, env-tunable) is already live and needs nothing. |
| **`vendor_breaches.json` — Adobe/Marketo watch item** | 2021 `marketo` row PRUNED 2026-06-11 (aged out of the 5-yr lookback; decayed contribution was ~0.5%). | Engineering | WATCH: alleged Adobe breach early-April 2026 (UNC6783, ~13M support tickets via compromised BPO; Marketo Engage plausibly in scope). Confirmed-only DB discipline — add a fresh row with the 2026 date if/when Adobe confirms. Details in `vendor_breaches.json` `_pruned`. |

## 2. External API budget (Phase 2 unblockers)

| API | Current tier | Required tier for 4,000-cohort | Estimated monthly cost | Action by |
|---|---|---|---|---|
| Shodan | Free `oss` (0 query credits — confirmed via `/api-info` 2026-05-29) | **Freelancer ($69/mo, 10,000 query credits)** unlocks search + origin cert-search. One-time **Membership (~$49, 100 credits/mo)** is a low-volume stopgap. | ~$69/mo (≈R1,300) if per-IP vuln data stays on free InternetDB and only origin cert-search spends credits (~1 credit/scan). Higher only if per-IP `/shodan/host/{ip}` lookups are also moved to the paid API. | Before 1 July 2026 — **also gates origin IP discovery (see §5, item 4c), which is a scanner-breaking RDP false-negative on CDN-fronted targets** |
| SecurityTrails | Free (100/month; history endpoint works on current key — confirmed 2026-05-29, NOT paid-gated) | Paid tier for sustained usage | Similar order of magnitude | Before 1 July 2026 |
| VirusTotal | Free (4/min, 500/day) | No upgrade needed | — | n/a |
| IntelX | **CRITICAL.** Returning data in the 2026-05-29 live test (300 results: 260 leak + 40 paste mentions, with per-record dates) — the "expired 2026-04-08" note is stale, the configured key currently works. It is now **load-bearing**: the 4th signal (active forum/dump circulation + recency dates) in the **Credential Exposure Correlation**. | Confirm a sustainable IntelX subscription OR equivalent (Snusbase / LeakCheck Pro / SpyCloud) — must persist, not lapse | TBD | **CRITICAL — before shipping live.** Credential correlation degrades gracefully without it ("monitoring pending") but loses the active-circulation signal + its main recency source. |
| HIBP, Hudson Rock, OSV.dev | Free unlimited | No upgrade needed | — | n/a |

### Shodan origin cert-search — how to make it live

Origin IP discovery (`origin_discovery.py`) is **already wired and deployed**.
It works in two stages and the paid stage **auto-activates the moment a paid
key is in place — no code change or redeploy of logic is needed**:

1. **Free stage (live now):** `/shodan/host/count` returns how many internet
   hosts present the target's TLS certificate. Surfaced in the report as the
   "Origin IP Discovery" card. When that count exceeds the origins we confirm
   via DNS history, the report flags a likely **undiscovered exposed origin**.
2. **Paid stage (pending key):** `/shodan/host/search` returns the actual
   origin IPs. On the free `oss` plan it returns HTTP 403 and we fall back to
   count-only. On a paid plan it returns the IPs, which are then TLS-cert
   verified and scanned like any other origin.

**Go-live steps:**
1. Buy a Shodan plan — **Freelancer ($69/mo)** recommended (10,000 query
   credits/mo); or one-time **Membership (~$49)** for low volume. Buy it on
   the Shodan account **whose API key is already set in Render** (so credits
   attach to that key), or buy on a new account and update the key in step 2.
2. Set / confirm `SHODAN_API_KEY` in the Render environment for the scanner
   service (Render → service → Environment). No code change required.
3. (Optional) verify with `GET https://api.shodan.io/api-info?key=...` —
   `query_credits` should be > 0 and `plan` should read `dev`/`member`/etc.,
   not `oss`.
4. Next scan of a CDN-fronted domain will retrieve + verify + scan the real
   origin IPs automatically; the "Origin IP Discovery" card switches from a
   count-only hint to listing the verified origins.

Budget note: keep per-IP vulnerability data on the **free InternetDB** path
(current default) so Shodan credits are spent only on the ~1-credit-per-scan
cert-search. Moving `/shodan/host/{ip}` per-IP lookups onto the paid API is
the larger credit consumer (~1 credit per discovered IP per scan) and is a
separate decision.

### IntelX (free tier) — current state + Wednesday testing

Confirmed 2026-05-29: the configured IntelX key **works** (the "trial expired"
note was stale). **Verified 2026-05-31 via `/authenticate/info` + IntelX docs:**
the free tier's `/intelligent/search` cap is **`CreditMax = 50` per DAY, reset
at midnight UTC** (NOT ~500 — that was a wrong code comment), 1 credit/scan,
**max 3 concurrent searches**.

Planning implication: the cohort runs at **~25-30 scans/day** (§3), which fits
*under* 50/day with modest headroom — so the free daily tier is **borderline-
viable for the steady cohort rate**, NOT "10× too small" as first thought.
BUT: zero burst headroom, the 3-concurrent cap throttles throughput, and any
broker ad-hoc scans eat into the same 50. So a **paid replacement
(Snusbase / LeakCheck Pro / SpyCloud) is still recommended** for safety +
throughput + always-on use, but it is no longer an emergency blocker. Avoid
burning credits on test scans (`skip_intelx:true`; the smoke test is already
credit-free).

- **DONE (2026-06-01):** `INTELX_API_KEY` (and `SHODAN_API_KEY`) are set on
  Render — prod now carries the IntelX/forum signal. The *paid-tier upgrade
  decision* (Shodan Freelancer, IntelX replacement) remains open above.
- **DONE (2026-07-01):** `INTELX_API_KEY` is now also set on the **Google VM**
  `.env` (service restarted, balance active). The key is account-scoped, so the
  VM and Render **share the same 50-credit/day pool** (they do not each get 50).
- **Still seek a sustainable replacement** (Snusbase / LeakCheck Pro /
  SpyCloud) for the cohort-scale + always-on case; the free tier can remain a
  fallback for ad-hoc use. The credential-correlation circulation slot is
  provider-agnostic, so swapping is a checker change, not a correlation rewrite.

## 3. Peer benchmarking rollout (SCN-028)

| Phase | Status | Start date | Source tag |
|---|---|---|---|
| Phase 1 — public reference seed pool | **Live** (bi-weekly via `tooling/benchmark_runner.py`) | 2026-05-16 onwards | `benchmark_pool` |
| Phase 2 — lower-tier-upsell cohort (~4,000 clients) | Pending launch (1-July window now open; gated on the prerequisites below) | 1 July 2026 → ~Feb 2027 (6-9 months at ~25-30/day) | `lower_tier_upsell` |
| Phase 3 — broker opt-in via scan form checkbox | Future | When opt-in plumbing is added; no fixed date | `client_optin` |

**Phase 2 prerequisites** (must complete before 1 July):
- [ ] Export 4,000-client list to CSV (`domain, industry, sub_industry, annual_revenue_zar` columns)
- [ ] API tier upgrades (see section 2)
- [ ] Daily cron / Render scheduled job invoking `py -3 tooling/benchmark_runner.py --source lower_tier_upsell --input-csv ... --limit 25`
- [ ] Phase 2 upsell workflow definition (how to deliver PDFs to brokers / clients)

## 4. Deferred-to-continuous-monitoring track (SCN-026)

| Item | Status |
|---|---|
| Probe-cache SQLite-backed implementation | Interface defined in `http_client.ProbeCache`; default `_NullProbeCache` no-op. Real implementation lands with continuous-monitoring scheduler. |
| Continuous-monitoring scheduler | Open. Estimated 3-4 week build. Requires probe cache + per-tenant scheduling + delta-finding detection + alert-on-change pipeline. |

## 5. Open accuracy items (gap analysis roadmap)

Carried over from v9 / v10 gap analyses. Not blocking but worth flagging:

**Checker accuracy audit (2026-06-30 → 2026-07-02) — COMPLETE.** A ground-truth
sweep of every checker module (white-box plus credit-free live runs, since the
frozen golden fixture is stale). Seven fixes shipped, deployed, and sha256-verified
on the VM, each locked by an `adversarial_gate.py` ground-truth scenario (the gate
now runs 40 across socket / IP-attribution / CVE-gating / checker-FP cases):

- **Py3.10 scan-crash fixed** (the scan phase loops now catch the
  `concurrent.futures` timeout, not the builtin; live scans had crashed on
  high-IP targets) plus a blocking AST guard, now extended to all four checker
  modules.
- **IP attribution by who-operates-the-host** (`ip_classification.py`): own vs
  vendor vs internal (RFC1918). Directly mitigates the "reassigned / vendor IP
  scored as the insured's own exposure" risk flagged in 4c / 4c-ii below.
- **CVE-to-software evidence-gating** (port-template CVEs dropped when the banner
  names a different product) and two wrong-software CVE data errors removed.
- **Live and golden scoring unified** into `scoring_pipeline` (one calculator
  invocation shared by the live scan and the golden replay) plus a guard against
  re-divergence; this drift is how the RSI-revenue size-multiplier bug had hidden.
- **False-positive hardening:** TechStack end-of-life detection matched against
  response headers only (not incidental version mentions in the page body); the
  VPN apex RDP probe now tarpit-gated (`is_saturated_host`) so a SYN-ACK-everything
  host cannot fabricate an RDP exposure; Dehashed staff attribution boundary-matches
  the mailbox domain (no lookalike-domain leaked account counted as own-staff).
- **hudson_rock staff-vs-customer distinction made consistent** on the reporting
  credential-correlation card (customer-only infections cap below staff there).
  The RSI-driving credential tier (`CredentialRiskClassifier`) already floored
  customer-only to HIGH and staff to CRITICAL, so the RSI itself was unchanged;
  this was a reporting-consistency correction, not a scoring change.
- **Subdomain enumeration made reliable (#7):** crt.sh and certspotter queried in
  parallel and unioned, with a `low_coverage` flag when both fail, so a flaky
  crt.sh no longer collapses enumeration to brute-force-only.

**Deferred follow-ups from the audit:** (a) cache Certificate-Transparency results
per-domain (TTL) for even tighter reproducibility; (b) refresh the stale golden
fixture (`test_fixtures/takealot_baseline.json`) from a fresh scan, then re-run
`tooling/regression/golden.py --capture` after reviewing the drift.

| Phase | Item | Status |
|---|---|---|
| 4b | CMS admin path detection (dynamic from tech stack) | Open |
| 4c | CDN origin IP leakage / origin discovery | **Partial — implemented (`origin_discovery.py`, 2026-05-29):** SecurityTrails historical-DNS candidates + TLS cert-match verification live; verified origins scanned, candidates surfaced. Free Shodan cert-host count hint live. **Full Shodan cert-search IP retrieval pending paid key (see §2 go-live).** Also: RDP exposure now reconciled across all discovered IPs, not just the apex (was a false-negative on CDN-fronted targets). |
| 4d | MFA presence on VPN login pages | Open |
| 4c-ii | **Infrastructure-infection / C2-beaconing signal** (reinsurer "Infrastructure Infections — Malicious Connection Attempt" card). Distinct from credential/infostealer: it flags *org servers/hosts* observed connecting to malicious infra. We partially cover via DNSBL (reputation/blacklist), but lack infection-type + days-observed granularity. Would need a threat-intel feed (Spamhaus CSS/XBL, GreyNoise, abuse.ch Feodo). **Attribution caveat:** the reinsurer's example IP `152.111.191.48` reverse-resolves to `download.kalahari.com` (Kalahari merged into Takealot 2014) — a legacy/related-brand IP not in takealot.com's scope, so it would only surface via related-domain (S-1) discovery + cert-verification. The reassigned/legacy-IP attribution risk is now mitigated by the own-vs-vendor classification (`ip_classification.py`, 2026-06-30), which keeps vendor/legacy hosts out of the insured's own attack surface; the C2-beaconing signal itself still needs a threat-intel feed. | Open (signal not built; attribution risk mitigated) |
| 4e | WAF rate limiting / bot protection detection | Open |
| 4f | DNSSEC validation chain | Open |
| 4h | Exploit Window narrative enhancement | Open |
| 5a | Bug bounty programme detection (HackerOne / Bugcrowd) | Open |
| 5f | retire.js CVE cross-reference | Open |
| 5i-T1 | AI Threat Readiness Tier 1 (externally observable) | Glasswing done; rest open |
| 5i-T2 | AI Threat Readiness Tier 2 (self-reported) | Open |
| 5k | **Fresh-dump content-fetch (credit-gated tier)** | **Partial — done 2026-06-02:** the encrypted export now includes IntelX stealer-log postings as date-ordered `leak_reference` rows with a `match_type`→`confidence` label (`credential_export.py`; Manual §6.4). **Still open:** the **content-fetch tier** — on explicit client request, pull the named dump BODY (IntelX selector/view, costs credits) to confirm whether a real credential was exposed vs just a `History/` visit. The free listing classifies by path but cannot read the contents. |
| 5L | **Confidence-gate the p(breach) / RSI input (scoring decision — NOT done)** | Open, **calibration-gated** (scoring-change rule). The export/dashboard now expose a `match_type`→`confidence` model, but the *score* does not yet use it: a recent LOW-confidence reference (aggregated index, browser-History visit) can still pull credential signals the same as a HIGH-confidence password capture. Decision to make: gate any p(breach)/RSI uplift on HIGH-confidence (or content-fetch-confirmed) evidence, so low-confidence freshness alone does not inflate the probability. Builds on the §6 "Credential-risk scoring calibration" ticket. **Cat model is unaffected — this is purely the p(breach) input.** Until decided, the disclaimer + content-fetch prompt (5k) is the interim control. **Design pre-read for the 2026-06-03 FIN-9 calibration session: `docs/credential_confidence_pbreach_design.md`** (current wiring, the model, the K1-K7 calibration knobs, and the empirical anchors that set them). |

## 6. Architectural follow-ups (low priority)

| Item | Status |
|---|---|
| Enforcement-discount % calibration per regulator | Statutory maxima used everywhere in cat stack. Expected-loss view uses heuristic. Compliance officer should set per-regulator discount %. |
| Civil exposure quantification (POPIA s99 / common-law delict) | Currently qualitative disclosure only. Quantification requires internal-contract data. |
| Tail recalibration with empirical SA cat data | 5× PERT upper bound on `mc_total_breach` is conservative. Calibrate against SABRIC + CISA + IBM SA-specific incident-type data when available. |
| WAF coverage-loading constant calibration (SCN-029) | `K_TAIL=1.20` in `_calculate_zar` sets how aggressively the catastrophe tail widens per unit of lost scan coverage. Heuristic — calibrate against rescan deltas (blinded scan vs allow-listed rescan of the same target) once continuous monitoring provides paired observations. Only the ZAR path is loaded; the dead USD path is not. |
| Bias correction on `lower_tier_upsell` benchmark cohort | Cohort may not be SA median; pool composition disclosed in report. Future: source-class weighting in percentile calculation. |
| GPD tail fit MLE upgrade (currently method-of-moments + pure numpy) | scipy.stats.genpareto provides MLE fit but adds dependency. Defer until scipy is acceptable on Render. |
| **Credential-risk scoring calibration** | **Structural tweaks DONE via the K1-K7 confidence-weighted rewrite of `CredentialRiskClassifier.classify` (FIN-9, 2026-06-03; checkers_threats.py).** Both landed: (1) IntelX paste/dark-web mentions are now **report-only (K7=0, "no score impact")**, not an uncapped per-mention deduction; (2) the Hudson Rock class FLOOR is **date-gated** (`L3_HR_STALE_DAYS=180`: a stale employee infection floors to HIGH, not CRITICAL), and a customer-only (`hr_users`, no employees) infection floors to HIGH while staff floors to CRITICAL. The K1-K7 *magnitudes/ranges* remain colleague-gated (see §6b and `docs/calibration_prep/02_credential_pbreach.md`). |

## 6b. FIN-9 calibration inputs — financial-loss impact of the 2026-06-03 accuracy waves

> **STATUS (2026-06-11):** the 2026-06-03/04 session RETIRED the FIN-9 Pareto
> widening; the #14 records-driven cat redesign was wired instead (see
> `calibration_prep/07_WIRING_SPEC_AND_HANDOFF.md` §7 and the FIN-9 memory
> memo). The dead-USD `COST_PER_RECORD` / `REGULATORY_FINE` tables listed
> below have since been **deleted** from `scoring_analytics.py`. Still
> genuinely open from this table: the `p_breach` base/curve sign-off, risk-band
> re-fit (200/400/600), TEF multipliers, K_TAIL, HIBP step thresholds,
> remediation caps — all colleague-gated.
>
> **UPDATE (2026-07-02):** the checker accuracy audit (§5) is complete — a further
> round of false-positive hardening (TechStack EOL, VPN RDP tarpit-gate, Dehashed
> attribution, evidence-gated CVEs) plus the live/golden scoring unification. These
> did **not** move the frozen golden fixture scores (they fixed FPs that were not
> firing on those fixtures), so the calibration baseline is stable; but the
> pre-session reference-loss-curve regeneration should run on the LATEST code.

**Why this matters for the FIN-9 session.** Wave 1 wired `cat_results["_overall_score"]`
into the FinancialImpactCalculator for the FIRST time in production — `vulnerability`
now couples to the real posture score (was permanently pinned at 0.5). Combined with
the de-inflation from the other waves (SSL no longer auto-"Invalid" −40, DNSBL no longer
auto-"blacklisted", Exposed-Admin 403-inversion gone, phantom F5-WAF and fabricated
CVE ASN/geo removed, HTTP-headers no longer false-penalised off a 403 block page), the
financial-loss **inputs changed materially**. Worked example: a fixed-code production
scan of phishield.com now scores **169 (Low)** vs **381 (Medium)** pre-fix, so its
`p_breach`, expected loss and every Monte-Carlo return-period tail shift accordingly.

**Consequence:** the FIN-9 Pareto widening (and the 5L credential-confidence work) must
anchor to the **corrected post-fix loss baseline**, not the old inflated one. The
downstream financial constants below were never empirically validated against *working*
coupling (the coupling was broken until Wave 1), so they now genuinely need calibration.

**Parameters to calibrate (anchor to DBIR / Mandiant M-Trends / IBM CoDB / Sophos SA + colleague judgement):**

| Parameter | Where | Why it now needs calibration |
|---|---|---|
| `vulnerability` ← `_overall_score` mapping, and the `0.3` in `p_breach = vulnerability × TEF × 0.3` | `scoring_analytics.py` (~L2099) | coupling is live for the first time; neither the curve nor the `0.3` was ever validated against real scores |
| credential → p(breach) contribution (replaces `dehashed_total × 2`, ~L669) | 5L / pre-read **K1–K7** | the confidence-weighted credential class (`docs/credential_confidence_pbreach_design.md`) |
| Pareto **alpha** + LGB **mixture weight** (FIN-9 core) | `_calculate_zar` | re-anchor to the corrected loss baseline + the MOVEit per-org curve |
| Remediation cap: `MAX_RSI_REDUCTION_FRACTION=0.15`, `RSI_RESIDUAL_FLOOR=0.05` | `scoring_analytics.py` (Wave 4) | set heuristically in Wave 4; the ~81% modelled loss-cut is now a calibration question, not a bug |
| TEF industry-targeting multipliers | `scoring_analytics.py` | how often each industry is targeted |
| HIBP scenario `p_breach` step thresholds (0.35 / 0.20 / 0.08) | `scoring_analytics.py:1664` | heuristic step function |
| `COST_PER_RECORD`, `REGULATORY_FINE` tables | `scoring_analytics.py` | per-industry SA values |
| `K_TAIL = 1.20` (catastrophe tail widening) | `_calculate_zar` | heuristic |
| Risk-level bands `200 / 400 / 600` (Low/Med/High/Crit on the 0-1000 score) | `scoring_analytics.py:806` | fixed even split, set against the OLD inflated distribution; de-inflation lowered scores (phishield 381->169) so they may now mis-bucket — re-fit to the corrected distribution + align to the calibrated p(breach) tiers |

**Pre-session action:** regenerate the reference loss curves on the FIXED code (a clean
post-fix scan of takealot + 1–2 references) so the calibration anchors to the corrected
baseline. `verify_supply_chain_financial_wiring.py` confirms wiring but INJECTS scores —
use a real fixed-code scan for the magnitudes. (A fixed-code phishield scan is already in
`test_fixtures/phishield_live.json`.)

## 7. Documentation / artifacts

| Item | Status |
|---|---|
| User Manual docx regeneration | `py -3 generate_manual.py` — now a **thin orchestrator** that assembles `manual_parts/part1-6` (each `build(doc)`); writes `Phishield_Cyber_Risk_Scanner_User_Manual.docx`. **Edit content in `manual_parts/`** (not the orchestrator). Helpers live in `manual_parts/helpers.py` (aliased by top-level `manual_helpers.py`); part1 uses `set_helpers()` injection, parts 2-6 import directly. The pre-2026-05-18 monolith is retired but preserved in git history (commit before the cutover) if ever needed. |
| Gap Analysis v10 regeneration | Regenerated via `node gen_gap_v10.cjs` **from the `security_scanner/` directory** (the script + its content live at `security_scanner/gen_gap_v10.cjs`, not a `generators/` subfolder). Outputs `security_scanner/Phishield_Scanner_Gap_Analysis_v10.docx`. This is hand-authored content in the `.cjs` (there is no markdown source); edit the `.cjs` then re-run. |
| FAIR Model Gap Analysis (legacy) | `security_scanner/generate_gap_analysis.cjs` produces `Phishield_FAIR_Model_Gap_Analysis.docx`. Pre-v10 artifact; check if still needed before next regeneration |
| Sensitivity analysis docs | `tooling/sensitivity/sensitivity_analysis*.py` + JSONs + `generators/gen_sensitivity_doc.cjs`. Pre-v10 calibration analysis; verify relevance before next regeneration |
| Legacy gap analysis v6/v7/v8 docx | Archived at `docs/archive/`. Kept for historical reference; not regenerated |

## 8. Document quality rules (cross-project)

Hard rules for all client-facing PDF / docx outputs live in
`C:\Users\sarel\.claude\projects\C--Users-sarel-Desktop-Sarel-Local-Only\memory\feedback_document_quality.md`.
Audit every output against the rules (now 16, numbered 0-15) before regeneration.
Pre-build audit gate is rule #0; rule #13 bans em-dashes; rule #14 requires font
embedding in every generated PDF.

---

## How to use this file

- Adding an outstanding item: append a row to the relevant section, note status / owner / target date
- Closing an item: remove the row (don't strike through — keep the file tight)
- Major architectural decisions: add a new section if a single line doesn't capture it
- Periodic review: scan this file before any big planning session or commit
