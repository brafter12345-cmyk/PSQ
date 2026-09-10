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

## 0. DEMO WINDOW — must be reversed when the demo ends (opened 2026-07-28)

A small group of external testers was given access to the live VM scanner. Three
temporary controls were put in place for that window. **All three are reversals,
not features** — work through this table before the scanner is treated as
production, and again the moment demo feedback is concluded.

| Item | Status | How to reverse | Notes |
|---|---|---|---|
| **Interim edge Basic auth on `/scanner`** | LIVE (Caddy, 2026-07-28) | The `basic_auth` block in `/etc/caddy/Caddyfile` is split into two labelled groups. **When the demo ends, delete only the lines under `# --- DEMO TESTERS ---`** and run `sudo systemctl reload caddy`; the internal-staff group stays. Remove the whole `@needs_auth` + `basic_auth` block to reopen access entirely. | Internal staff (keep): `sarel`, `zamani`, `inze`. Demo testers (remove at demo end): `demo1`–`demo4`. bcrypt hashes; one login each so access can be revoked individually and the access log attributes activity. `/health` and `/health/providers` are deliberately EXEMPT so the uptime monitor and the deploy's public-reachability check keep working; `/metrics` IS gated. **This is a shared-secret gate, not user auth** — no per-user identity inside the app, no session expiry, no audit trail beyond Caddy's access log. It does NOT satisfy the production auth requirement below. |
| **Encrypted credential export DISABLED** | Fails closed by default (2026-07-28) | Set `CREDENTIAL_EXPORT_ENABLED=1` in the VM `.env` and `sudo systemctl restart phishield-scanner`. Config only — no code change, no redeploy. | The export releases a client's **actual breached passwords**. What makes that lawful is the client's signed consent, and the `consent: true` field on the request is only a broker attestation — with demo testers who have signed nothing, it is not a control at all. Both the POST **and** the one-time download route are gated (gating only the POST would let a token minted before the flip still be redeemed). The dashboard shows the control as unavailable rather than letting a tester complete a consent attestation and then hit a 503. Everything else in the scan — which accounts are exposed, in which breaches, how recent — is unaffected. **Re-enable only once the consent/authorisation page ships.** |
| **Demo-facing manual in circulation** | Written 2026-07-28 | Withdraw the demo manual; the full manual stays internal. | `Phishield_Scanner_Demo_Guide.docx` deliberately omits scoring weights, calibration anchors, checker internals, data sources and thresholds. Do not circulate the full `Phishield_Cyber_Risk_Scanner_User_Manual.docx` to demo testers. |

**Also open (2026-07-28):** wire IntelX's **free** `/authenticate/info` endpoint
into the budget guard. The guard currently counts HTTP calls and estimates the
search quota from them (1 search = up to 4 calls); that endpoint reports remaining
*searches* authoritatively, at no credit cost, and would remove the estimate.

**Related, still open:** the production auth model (see *Enable API auth* in §1
and the full gap in **§4b**) is unchanged by the demo gate — edge Basic auth is a
stopgap in front of an app that still has no authentication of its own. **Do not
execute the reversals in this table until §4b is built**: removing the edge gate
with nothing behind it leaves the scanner open, and the app can now emit client
credential material (password fingerprints, and the credential export once
re-enabled).

### Deferred, flagged for review (not defects — decisions not yet taken)

| Item | Owner | Why it is parked |
|---|---|---|
| **Uptime monitor on `/scanner/health/providers`** | Owner (ops) | The readiness probe returns 503 when a provider key dies, the datastore falls back to SQLite, or a metered budget is exhausted — all silent failures otherwise. Nothing is watching it yet. A 2026-07-27 drill confirmed the 503 fires correctly; only the monitor is missing. |
| **Should lookalike mail-capability carry SEVERITY?** | Owner (calibration) | Lookalike posture probing (MX / SPF / parking / content) ships as **reporting-only**: the category score is still a flat penalty per resolved domain, so a mail-capable near-typo and a parked null-MX domain score identically. Weighting by capability means either replacing that channel or justifying a second one, plus the manual paragraph that locks it — a calibration decision under the no-double-count rule, not a code tweak. Options: weight the existing penalty by risk band, add a probability uplift, or keep reporting-only permanently. |

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
| Shodan | **Paid `basic`, 10,000 query credits — re-confirmed via `/api-info` 2026-09-08. The "free oss" line below is STALE.** | **Freelancer ($69/mo, 10,000 query credits)** unlocks search + origin cert-search. One-time **Membership (~$49, 100 credits/mo)** is a low-volume stopgap. | ~$69/mo (≈R1,300) if per-IP vuln data stays on free InternetDB and only origin cert-search spends credits (~1 credit/scan). Higher only if per-IP `/shodan/host/{ip}` lookups are also moved to the paid API. | Before 1 July 2026 — **also gates origin IP discovery (see §5, item 4c), which is a scanner-breaking RDP false-negative on CDN-fronted targets** |
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

### 3c. Targets can block the scanner by source IP, silently costing coverage (GAP, 2026-08-20)

**Observed, not theorised.** bbgroup.co.za refuses the scanner's egress IP
outright: TCP filtered on port 80 AND 443 from the VM (34.35.151.242, Google
Cloud africa-south1), 0 of 5 probes connecting, while the same host answered 10
of 10 with HTTP 200 from an ordinary connection at 1.6-3.0s. Not a user-agent
problem, a browser UA fails identically. Two checkers were lost permanently and
the scan completed at 93% coverage.

**What already works.** The blocking IS detected (`waf_status.blocked`,
`kind: waf_timeout`), the affected checkers fail closed rather than scoring
clean, the weight is redistributed, and since `9d6d0bd` the report states the
refusal is not transient instead of advising a re-scan that cannot succeed.
Nine stored scans carried that wrong advice.

**What is missing.**

1. **Nobody is counting it.** There is no measure of how many scans lose checkers
   to source blocking, which checkers are lost most often, or whether it is
   trending. Coverage loss is currently visible only one scan at a time, and a
   systematic degradation would look like a series of unremarkable individual
   scans. A count over the stored corpus is cheap and would size the problem
   before any mitigation is designed.
2. **One egress IP, no fallback.** Every scan leaves from a single VM address. A
   target that blocks it blocks the whole product for that client, permanently,
   and the block may not be aimed at us -- cloud and datacentre ranges are
   commonly filtered wholesale.
3. **No allow-list workflow.** The corrected report now tells the client to
   allow-list the assessment source, but nothing tells them WHAT to allow-list.
   The egress address is not published anywhere a broker can hand to a client.
   That is a one-line fix and should probably happen regardless of the rest.
4. **Coverage is not part of the quoting decision.** A 93%-coverage scan and a
   100%-coverage scan are quoted identically. The redistribution assumes the
   unmeasured checkers resemble the measured ones, which is an assumption, not a
   measurement, and its direction of error is unknown: a client whose website
   security is genuinely poor scores better for having blocked us. That is a
   perverse incentive worth naming even if the answer is to accept it.

**Interaction with the 2026-08-20 quoting decision.** Quotes must come off a
fresh scan. Nothing yet says a fresh scan must also be a sufficiently COMPLETE
one. Whether a coverage floor should gate quoting, and where it should sit, is an
owner decision that has not been taken.

**Not urgent.** One observed instance, correctly handled and honestly reported.
It is here so it is sized before it is a pattern.

### 3b. Historical scans no longer reproduce their own score (OBSERVED, 2026-08-20)

**Found by a safety guard, not by looking for it.** The recommendation backfill
re-ran the scorer over every completed scan's STORED categories, making no
provider call, and refused to write any scan whose score moved. Twelve of
fifty-two moved.

| | |
|---|---|
| Scans re-scoring identically | 40 |
| Scans re-scoring differently | **12** |
| Typical movement | 14 to 28 points down; one moved +65 |

**Two causes confirmed, both legitimate:**

- `38da8562` phishield.com (218 -> 200): `http_headers` now grades as FAILED
  where it did not, because `unreachable` was added to `_FAILED_STATUSES` in the
  blocked-is-not-clean work. Excluded weight 0.045 -> 0.083, so the redistribution
  differs.
- `007f19d1` mip.co.za (117 -> 182): identical failed/skipped sets and identical
  excluded weight, so the movement is in the scoring maths itself, not exclusion.

Neither is a defect. Both are scoring improvements made after those scans ran.

**Why it is recorded here.** A stored scan is an underwriting artefact. A client
quoted off a 2026-07 score cannot have that number silently restated months
later, so the backfill deliberately left those twelve alone and only corrected
the ordering of the action list on the other forty. But it means **a re-quote off
an old scan is not comparable to a re-quote off a fresh one**, and nothing in the
product says so.

**OWNER DECISION, 2026-08-20: quotes must NOT be produced off earlier scans.**
A quote is derived from a fresh scan or it is not produced. That settles question
2 below and makes question 1 the enabling work rather than a nice-to-have: the
policy cannot be enforced, or even audited after the fact, unless a stored scan
records the model it was scored under.

**Remaining, to schedule:**

1. **Stamp the scoring model version onto every scan** so a stale score is
   visibly stale rather than silently stale. Cheap now, impossible to reconstruct
   later, and it is the mechanism the decision above depends on. Without it
   "is this scan current?" is answerable only by re-scoring and comparing, which
   is exactly the accident that surfaced this.
2. **Decide where the policy is enforced.** Recording it in a document does not
   stop anyone. Candidates: the scan record carries a freshness/model field the
   rating path refuses to quote against, or the report itself states the scan
   date and model prominently enough that quoting off a stale one is obvious.
3. All twelve divergent scans are phishield/takealot test scans or have a newer
   scan for the same domain, so there is no known live exposure today. That is
   luck, not design, and it is the reason this is schedulable rather than urgent.

Ties into 4a: a stable finding identity across re-scans is the same prerequisite.

### 4a. Risk-register workflow: analyst/client adjudication of findings (GAP, 2026-08-18)

**Owner-raised, explicitly NOT for now.** Recorded here so the continuous-monitoring
build does not get designed without it, because it changes the data model rather
than the UI, and retrofitting it later is far more expensive than allowing for it.

**The gap.** Today a finding has exactly one state: whatever the scanner decided.
There is no way to record what happened when a human looked at it. After a client
session the broker knows things the scan cannot: that an exposed service is a
decommissioned host awaiting teardown, that a "critical" database is a vendor's
shared platform (see 2026-08-18, `707418b`), that a lookalike domain is the
client's own marketing site. None of that survives anywhere. The next scan
re-raises the same finding at the same severity, and the client sees an
unchanged report after telling us it was wrong.

**What is wanted.** Selectable fields on each identified risk so a finding can be
adjudicated:

- a **status** drop-down (open / accepted / mitigated / false positive / vendor-owned / decommissioned)
- an **override severity** with the scanner's original severity retained alongside it, never overwritten
- a **mandatory comment** whenever the override differs from the scan verdict, so the escalation or de-escalation carries its own justification
- **attribution and timestamp** on every change, since this becomes the audit trail for why a quoted risk differed from a scanned one

**Reference UI.** The owner cites Darkivore's scan interface as the shape to aim
for (risk items managed in place, adjudicated rather than merely listed). Not
independently reviewed by me and NOT verified against their product; treat as a
directional pointer from the owner, not a specification, and confirm before
designing to it.

**Why it is a continuous-monitoring item and not a dashboard item.** Adjudication
only pays off across repeat scans. Its whole value is that scan N+1 remembers what
a human decided about scan N, which means the override must attach to a STABLE
FINDING IDENTITY that survives re-scanning, not to a row in one scan's results.
That identity does not exist yet and is a prerequisite for the delta-finding
detection already listed in section 4. Design them together.

**Underwriting caution, to settle before build.** An override that de-escalates a
finding changes the risk score a quote is derived from. That needs an explicit
decision: does an adjudicated score feed the premium, or does the scanner's own
score remain the rated one with the override shown alongside as broker context?
Silently letting a client talk a score down would be a serious defect in an
underwriting tool. Recommend the scanner's score stays authoritative for rating
and the adjudicated view is presented separately, but this is the owner's call.

**Ties into 5m (UI screening test).** 5m is about the dashboard faithfully
REPORTING what the scan found. This item adds a second, human-authored layer on
top. Doing 5m first is the right order: there is no point building adjudication
over a display that does not yet provably agree with the scoring path.

### 4b. No application-level user accounts — identity, permissions and audit (GAP, 2026-09-08)

**Owner-approved to defer:** real user accounts are fine "in due course"; all
currently authorised users get the new functionality in the meantime. Recorded
here so it is not lost, and because it now gates more than it used to.

**The gap.** The scanner has no authentication of its own. The only gate is the
Caddy edge Basic auth described in section 0 — a shared-secret prompt in front of
an app that cannot tell one caller from another. Consequently there is **no user
identity inside the application, no roles or permissions, no session expiry, and
no audit trail beyond Caddy's access log**. Revoking access means editing a
Caddyfile and reloading Caddy.

**Why it matters more now than it did in July.** When the gate went up, everything
behind it was read-only reporting. It no longer is. The meeting-brief generator
(2026-09-08) can emit **password fingerprints** for a client's exposed accounts,
and the encrypted credential export (section 0) releases actual passwords once it
is re-enabled. Both are actions a production system would restrict to named users
and log per use. Today the app cannot name the user taking them.

**What is in place as an interim, and its honest limit.** Caddy forwards the
authenticated username, and the brief generator records it against each
generation together with whether fingerprints were requested and the stated
reason. That produces a usable audit trail for the current small, known, internal
group (`sarel`, `zamani`, `inze`). **It is not an authorisation control:** the app
trusts a header it cannot verify, every user has identical rights, and anyone who
reaches the app other than through Caddy is unauthenticated and unlogged. It is
adequate because the user set is three people who all already have full access,
and it stops being adequate the moment that is not true.

**What production needs.**

- real accounts with per-user credentials and session expiry, replacing the shared-secret edge gate
- **roles**, so that viewing a report and releasing client credential material are separable rights rather than the same right
- a **server-side audit log** of credential-affecting actions (brief with fingerprints, credential export, consent attestation) that does not depend on a forwarded header
- **individual revocation** that does not require a Caddyfile edit

**Sequencing.** This is the same work as *Enable API auth (`SCANNER_API_KEY`)* in
section 1 and the reversal of the edge Basic auth in section 0; do not build them
as three separate things. The trigger is the end of the demo window: taking the
demo gate off without app auth behind it would leave the scanner open, so
**section 0's reversal must not be executed until this is built.** Re-enabling the
encrypted credential export has the same dependency, for a stronger reason — that
control releases plaintext passwords.

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
| 4c | CDN origin IP leakage / origin discovery | **Partial — implemented (`origin_discovery.py`, 2026-05-29):** SecurityTrails historical-DNS candidates + TLS cert-match verification live; verified origins scanned, candidates surfaced. Free Shodan cert-host count hint live. **RESOLVED, and it has been live longer than this document said.** Measured 2026-09-08: `/api-info` reports plan `basic` with 10,000 query credits, `/shodan/host/search` returns HTTP 200 (not the 403 the code comment predicts for the free tier), and `shodan_search_used` is true on **28 of 30** retained scans. The paid certificate search has been contributing origin candidates all along. Where it returns nothing (boston.ac.za, www.zinia.co.za: `cert_hosts` 0) Shodan simply has no host indexed presenting that certificate, which is what a correctly locked-down origin that only accepts connections from its CDN looks like. That is not a licensing gap and no purchase closes it. Also: RDP exposure now reconciled across all discovered IPs, not just the apex (was a false-negative on CDN-fronted targets). |
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

### 5m. UI screening test — validate every dashboard display against the PDF/scoring path (NEW, 2026-08-06)

**The gap.** The React dashboard is a SECOND rendering path over the same scan
results, and it has never been validated against the first. The PDF/scoring path
is well gated: `pdf_snapshot.py` (byte-level render baseline), `golden.py`
(scoring regression), `adversarial_gate.py` (now 100+ ground-truth scenarios),
plus the financial-wiring verifiers. The dashboard has almost none of that —
`tsc --noEmit`, a base-path link check, and the recently added built-bundle
prefix check. Nothing asserts that what the dashboard SAYS about a scan matches
what the PDF says about the same scan.

**Why this is now a named gap.** Three separate defects in ~36 hours, all of the
same shape — a rule taught to one layer and not the others:

1. **WAF `blocking_observed` (fixed `583dcca`).** Added to the scorer in
   `ba6b380`; NO renderer learned it. The PDF plain-language summary, the PDF
   category card, the RemediationSimulator recommendation list and the dashboard
   panel all still read `waf.detected` alone, so a site that refused 20 of 20
   probes was told it had "no protective filter, leaving it directly exposed".
2. **Risk Factors roll-up (`selectors.ts` `getRiskFactors`, OPEN).** Each
   dimension averages the `score` field of its categories, but several checkers
   (`exposed_admin`, `payment_security`, `vpn_remote`, `dns_infrastructure`,
   `high_risk_protocols`, `cloud_cdn`, `security_policy`, `waf`) never emit a
   per-category `score` at all — their contribution is computed downstream in
   `scoring_analytics`. The roll-up silently averages whatever subset happens to
   carry the field, while the label still claims the full dimension. Observed on
   excellentmeat.co.za `f0313b6a`: **Data Protection ran on 1 of 4 categories**
   (privacy_compliance=0, i.e. "no compliant privacy policy page found") and
   rendered "Critical +100"; **Network Exposure ran on 1 of 4** (shodan_vulns=100)
   and rendered **green "Low"**. A green verdict resting on one signal is the
   dangerous direction — nobody challenges green.
3. **Base-path build (fixed `5cdbaa9`).** The bundle shipped without
   `SCANNER_BASE_PATH`, so every dashboard API call missed the Caddy mount. The
   page still rendered and the timer still ticked, so a completed scan sat at
   "0 / 39 Scanning" indefinitely.

**Deferred deliberately, not overlooked.** The dashboard sits behind the demo
edge auth (§0) and the PDF is the client deliverable, so the exposure is
currently internal. That is what makes this schedulable rather than urgent.

**What the screening test should do** — for every display element in the
dashboard, trace what drives it and assert it agrees with the PDF/scoring path
for the same scan:

- Enumerate each panel/field and record its data source (category, derived
  selector, or computed-in-frontend), so "computed in the frontend" is a visible
  category rather than an accident. `getRiskFactors` and `getAttackPath` are
  known frontend-side derivations; there may be others.
- For a fixture scan, diff every dashboard-rendered verdict against the
  corresponding PDF statement. Any divergence is either a bug or a documented
  deliberate difference — currently there is no record of which.
- Assert coverage honesty per dimension: show the denominator ("1 of 4
  assessed"), and do not render green where the underlying coverage is thin.
- Add whatever survives as gate scenarios, so the dashboard gets the same
  "does not silently degrade" guarantee the PDF has.

**ENUMERATION DONE, 2026-08-20 — `tooling/ui_enumerate.py`.** Static inventory of
every exported selector: what it reads, and whether it forms its own verdict.

| | |
|---|---|
| Selectors | 22 |
| **Deriving their own verdict** | **17** |
| Using `isConclusive` | **2** (`getRiskFactors`, `getAttackPath` — both fixed earlier this month) |
| Deriving from raw category reads with NO guard | **6** |

The six: `getRiskSnapshot`, `getKeyFindings`, `getCriticalAlerts`,
`getOpenServices`, `getVulnerabilitySummary`, `getVulnerabilityList`.

**DIVERGENCE MEASURED, not inferred.** The selectors were compiled to CommonJS
and executed against a results object where every category carries
`status: "error"` — the shape a real scan produces when a WAF refuses us or a
provider is unavailable. The same object was passed to the PDF's
`_kill_chain_severities`. **Every phase disagrees:**

| Phase | PDF | Dashboard |
|---|---|---|
| Reconnaissance | `UNKNOWN` | `medium`, itemised as "0 external IPs", "0 subdomains" |
| Initial Access | `UNKNOWN` | `low` |
| Exploitation | `HIGH` | `low`, "No critical exploitation vector confirmed by current external scan" |
| Data & Impact | `LOW` | `medium` |

The dashboard states counts as facts ("0 external IPs") that came from an errored
checker, and asserts "no critical exploitation vector confirmed" where the PDF
rates the same evidence HIGH. A broker reading the console and a client reading
the report are looking at different assessments of one scan.

**Also measured:**

- `getVulnerabilitySummary` returns `{available: true, total: 0, critical: 0}`
  when both `osv_vulns` and `shodan_vulns` errored. `available: true` on an
  unassessed pair is the false clean in its purest form.
- `getCriticalFindings` returns `{total: 0}` on a fully blind scan.
- `getRiskSnapshot` and `getRiskFactors` handle it correctly — proof the pattern
  is achievable and that the other selectors simply never learned it.

**Next, in order:** guard the six; then re-run the comparison and assert
phase-by-phase agreement; then land that assertion as a gate so the dashboard
gets the same "does not silently degrade" guarantee the PDF has.

**Also open from the same review:** the `+xx` impact figure reads as an additive
contribution to a score but is only `100 - dimension_score` (a display-only
inversion; the five values summed to 326 on a scan whose overall risk score was
251). Relabel. And "Data Protection" is currently driven by privacy-policy
presence, which the name does not convey.

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

### 5n. Lookalike permutation coverage is thin for South African second-level domains (OBSERVED, 2026-09-08)

**QUEUED: owner-flagged 2026-09-08 for after the six remediation steps.** Not a 
blocker for any of them. First action is measurement rather than a code change: 
run the expanded second-level-domain list across the retained scans and report how 
many new candidates appear and how far category and overall scores move, so the 
calibration decision is taken on numbers rather than on expectation.

Found while verifying the client-ownership fix. `FraudulentDomainChecker.ALT_TLDS`
carries the generic top-level domains and `.co.za`, but not the other South
African second-level domains: `.ac.za`, `.org.za`, `.net.za`, `.gov.za`,
`.web.za`. Scanning `boston.ac.za` therefore generates `boston.co.za` as a
candidate, while scanning `boston.co.za` never generates `boston.ac.za`.

Consequences, in both directions:

- A genuine typosquat registered under an unlisted South African second-level
  domain is never probed and never reported.
- The client-ownership exclusion cannot fire on a domain that was never
  generated, so the same client scanned from a different apex gets a different
  answer.

NOT fixed with the ownership work, deliberately: adding second-level domains
generates more candidates for every South African client, which moves the
category score and therefore the risk score. That is a scoring change and needs
its own justification, a golden re-baseline, and a decision on whether the extra
candidates are counted in the penalty at the same weight. Raise it with the
calibration owner rather than folding it into a correctness fix.

### 5o. A CDN-fronted www with a non-CDN apex probably exposes the origin (OBSERVED, 2026-09-08)

Found while correcting the measurement for remediation step 3. CloudCDNChecker
resolves the apex only, so detection answers "is the apex fronted", not "is this
organisation fronted". Across the 30 retained scans:

- 4 apexes resolve into a published edge range and are now detected.
- A further 4 (aggregato.co.za, dubetradeport.co.za, excellentmeat.co.za,
  rbs.co.za) have edge addresses on a SUBDOMAIN, typically www, while the apex
  resolves elsewhere: aggregato's apex is Xneelo (156.38.174.226) with www on
  Cloudflare; rbs.co.za's apex is Hetzner/Xneelo; dubetradeport's apex is a
  Google Cloud load balancer.

The interesting half is not the missed detection. Where www sits behind a CDN
and the apex does not, **the apex is very likely the origin server**, published
in DNS, reachable directly, and unprotected by the edge the client is paying
for. That is the exact exposure origin_discovery exists to find, available for
free from records the scan already holds, and the scanner currently says nothing
about it.

TWO SEPARATE PIECES OF WORK, neither folded into step 3:

1. **Detection breadth.** Whether cloud_cdn should consider subdomain addresses.
   This changes which scans are detected and therefore moves the availability
   credit and the estate-confidence cap. Scoring change: needs calibration
   sign-off, a golden re-baseline, and a decision on whether a fronted www with
   an unfronted apex counts as "protected" at all.

2. **Origin disclosure as a finding.** Emitting "the apex appears to be the
   origin behind the edge on www" is new signal, not a re-weighting, and is
   arguably the more valuable of the two. Also needs its own severity decision.

Raise both with the calibration owner. Step 3 deliberately ships apex-only
detection, matching what the checker has always asked, so that the confidence
cap can be introduced without simultaneously changing which targets are
detected.

### 5p. Should edge-measured web checks be graded non-conclusive? (CALIBRATION DECISION, 2026-09-08)

Remediation step 3b labels the web-layer checks that measured a CDN edge rather
than the client: ssl, http_headers, website_security, exposed_admin,
third_party_js and waf carry `measured_at: "cdn_edge"`, and the report renders a
notice naming them. That is REPORTING-ONLY. The categories still score normally,
so a clean TLS grade on Cloudflare still contributes a clean TLS grade to the
client's score.

The arguable position is that they should be graded NON-CONCLUSIVE, the same as
a checker that could not run. The scanner's own rule is that absence of evidence
is not evidence of absence, and a checker that measured somebody else's server
has produced no evidence about the client.

NOT DONE, deliberately. Grading them non-conclusive excludes their weight, which
redistributes across the remaining categories and moves the score in a direction
that depends on the rest of the scan. Three of the four must-have checkers are in
this set, so on a CDN-fronted target it would also trip the must-have-missing
branch and drop confidence to low_confidence, which is a materially different
statement from the "partial" that step 3 now sets. That is a calibration change
requiring sign-off, a golden re-baseline, and a decision on what a scan that can
see almost nothing about the web layer should be allowed to say at all.

Interim control: the underwriting rule issued as step 1 already prevents the
commercial harm, because absence of findings may not discount or clear a risk.
The labelling makes the situation visible to whoever reads the report.

Related: 5o (a fronted www with an unfronted apex probably exposes the origin).

### 5q. SaaS mail infrastructure is attributed to the insured as OWNED (OBSERVED, 2026-09-08)

Found while checking whether the reviewer's over-attribution finding was already
closed. It is not. On boston.ac.za the scan classified every one of these as
`owned`:

| Address | What it actually is |
|---|---|
| 104.47.164.119, 52.98.22.8, 52.98.20.136, 40.104.15.56 | Microsoft Exchange Online |
| 2603:1006:2:c1c::8 and three siblings | Microsoft |
| 20.126.184.33 | Azure |
| 196.41.30.122 | `ironport.datapro.co.za`, a shared mail-security appliance |

None is operated by the client. They enter the pool from MX and autodiscover
records, which for an SME on Microsoft 365 are by definition somebody else's
servers.

TWO CAUSES, both mechanical:

1. `_SAAS_RDNS` matches on a reverse-DNS suffix, and the Microsoft ranges
   publish **no PTR at all** (verified: 52.98.22.8, 104.47.164.119, 40.104.15.56
   and 20.126.184.33 all return no PTR). With no reverse name there is nothing
   for the suffix table to match, so the address falls through to `owned`.
2. `196.41.30.122` DOES have a PTR, `ironport.datapro.co.za`, but Datapro is a
   regional South African mail-security provider and is not in the table. Same
   fall-through.

WHY IT MATTERS. The CDN half of this problem is handled: Cloudflare addresses
are classified `cdn`, removed from `per_ip_results` and excluded from scoring.
Shared web hosting is handled too (707418b). SaaS mail is not, so any finding on
a Microsoft or Datapro host would be reported as the client's own exposure and
priced accordingly. On boston.ac.za nothing surfaced, so no harm materialised,
but the attribution is wrong and the harm is one exposed service away. This is
precisely the over-attribution failure mode the external review described.

FIX DIRECTION. Reverse DNS cannot carry this alone. The classifier already
receives Shodan's `org` field, which names Microsoft on these hosts, and
published Microsoft 365 / Azure address ranges are available in the same way the
CDN edge ranges now are. Adding a regional mail-provider suffix list closes the
Datapro case. Treat as remediation step 3c, before step 4.

#### 5q measurement across all 30 retained scans (2026-09-09)

boston.ac.za is not special. Counting only addresses the scan classified `owned`
that carry unambiguous evidence of vendor operation, using two narrow tests
(`tooling/measure_saas_attribution.py`; a looser first pass flagged 268 of 307
and measured nothing, so it was discarded):

  A. SERVICE-ONLY PROVENANCE - every subdomain resolving to the address is a
     label that exists only to hand a client to a mail/collaboration platform
     (`autodiscover`, `autoconfig`, `mta-sts`, `lyncdiscover`,
     `enterpriseregistration`). Nobody runs their own application server behind
     `autodiscover.`.
  B. PLATFORM ORG - Shodan's org names an operator of a mail platform.

| bucket | count | reading |
|---|---|---|
| A and B agree | 80 | unambiguous, both signals |
| A only (org unknown, mostly IPv6 with no Shodan record) | 76 | unambiguous |
| B only | 37 | **NOT safe to act on** |
| total `owned` addresses across 30 scans | 307 | |

20 of 30 scans are affected. 156 addresses are safely demotable on provenance.

THE 37 ORG-ONLY CASES ARE THE TRAP, and they are why org must never decide this
alone. That bucket contains genuine customer-operated infrastructure:
`34.35.151.242` behind `veilguard.phishield.com` is our OWN GCE VM;
`20.164.162.95` behind `portal.nexgro.co.za` and `staging.nexgro.co.za`,
`20.87.11.76` behind `ifrs9.bdo.co.za`, `35.190.68.223` behind
`qr.bbgroup.co.za` are all client-run cloud hosts. Demoting on org would delete
those from the scan and understate the client's real exposure, which is the
opposite error and just as expensive.

It also contains real vendor hosts that provenance alone misses: DataPro's
`196.41.30.122` (port 25 only), four Mimecast relays on `41.74.x` (25/587),
`104.47.164.119` behind `amazon.boston.ac.za`, and five `52.96.x` Microsoft hosts
on mydata.co.za with no subdomain recorded at all.

THE DISCRIMINATOR THAT FALLS OUT OF THIS. The org list has to be split, because
the two halves behave differently:
  * PURE MAIL-SECURITY VENDORS (Mimecast, Proofpoint, Barracuda, DataPro) do not
    sell customer-run VMs. Their org string IS decisive on its own.
  * HYPERSCALERS (Microsoft, Google, Amazon) sell both the managed service and
    the VM the client runs. Their org string is never decisive and must be paired
    with provenance or a published service address range.
This is the same shape as the CDN fix: identity published by the operator, not
by the party being judged.

### 5r. A demoted host disappears from the report entirely (OBSERVED, 2026-09-09)

Found while designing the 5q fix, and it constrains that fix. Three outputs of
the attribution step are written and never read anywhere:

| field | written | read by |
|---|---|---|
| `results["third_party_hosting"]` | `scanner.py` | **nothing** |
| `results["internal_dns_leak"]` | `scanner.py` | **nothing** |
| `results["ip_classification"]` | `scanner.py` | `adversarial_gate.py` only (a test); the two hits in `scoring_analytics.py` are comments |

Verified by grepping the whole tree for each name across `.py`, `.ts` and `.tsx`.
No PDF card, no dashboard component and no scoring path consumes any of them.

The comment at `scanner.py:886-888` asserts the opposite: "third-party hosting +
internal-DNS leaks are surfaced separately (results.third_party_hosting /
internal_dns_leak)". They are not surfaced anywhere. That comment is false and
should be corrected in the same change.

CONSEQUENCE. When a host leaves the OWNED bucket it is deleted from
`per_ip_results`, excluded from `scan_ips`, and therefore dropped from
`external_ips.total_unique_ips`, which is the number the report prints as the
client's external footprint. Nothing else records that it existed. The estate
silently shrinks and the client reads as cleaner. This already happens today for
every Cloudflare edge address.

WHY THIS BLOCKS 5q. The 5q fix demotes up to 156 addresses across 20 of 30 scans.
Shipping it against this reporting gap would trade over-attribution for
under-statement, which is the OTHER half of the same reviewer's criticism, and
would move scores in the client's favour for a reason no reader could see. The
demotion rule and a supply-chain reporting surface have to land together:
a demoted host must still be visible, named, attributed to its operator, and
counted toward estate coverage, just not priced as the insured's own exposure.

### 5s. unique_asns == 0 means "not collected" but is priced as single-homed

Found while measuring 5q, and deliberately NOT fixed there, because it is a rate
movement and does not belong inside an attribution change.

`ExternalIPAggregator` sets `result["unique_asns"] = len(asns)` and its own
comment beside that line is explicit: do not fabricate a count, `0` means
not-collected, and the renderers show "n/a" rather than a number. The scorer does
not honour that. `scoring_analytics.py` reads

    single_asn = categories["external_ips"].get("unique_asns", 2) <= 1

so `0` satisfies `<= 1` and adds **+0.025 to p_interruption** against a 0.03
base, a third of the whole availability probability, for a control that was never
measured. It is the absence-of-evidence error the module elsewhere refuses.

MEASURED on the 30 retained scans: 13 fixtures currently fire the term, and 5 of
them have `unique_asns == 0` -- dinamika.co.za, elleyarns.com, morgancarco.com
and pureburn.co.za have no discovered addresses at all, and fundagroup.co.za
carries `asn_geo_unavailable: true`, meaning the free Shodan InternetDB path
returned no ASN. All five are charged for single-homing on no evidence.

THE FIX IS ONE CHARACTER OF INTENT: fire only on `unique_asns == 1`, i.e. we
measured, and it is one. Restricting it that way takes the charged set from 13 to
11 on today's corpus.

WHY IT IS FLAGGED RATHER THAN DONE. It is a discount for five clients, and the
house rule is that a signal enters pricing through exactly one channel with its
own calibration. Bundling a rate cut into an attribution correction would make
the attribution change impossible to defend as price-neutral, which it currently
is (0 CVEs and 0 issues moved, no score improved, no cover fell). Needs owner
sign-off as its own change.

NOTE the direction of the 5q change on this same term. Removing vendor addresses
from the own pool makes `unique_asns` more faithful to the client's own hosting,
so the charged set RISES from 13 to 19. That is an increase, not a cut, and it
requires no new coefficient: it is the existing rule reading a corrected pool.

### 5q status after step 3c, and the residuals that remain open

CLOSED. Microsoft 365 service endpoints are no longer attributed to the insured:
176 addresses across 19 of 30 retained scans, carrying 0 CVEs and 0 issues, with
no score improved, no cover or loss figure fallen and no estate shrunk. The
demoted hosts are now rendered rather than silently deleted, and confidence is
recorded beside every classification.

RESIDUALS, stated rather than engineered around.

**196.41.30.122 and its class.** DataPro's shared IronPort mail appliance stays
OWNED. Nothing offline, non-gameable and already stored reaches it: DataPro
publishes no service ranges, its PTR names only the provider, and it carries a
single hostname so the co-tenancy threshold is not met. Every name-based rule
that would reach it also sweeps up 27 real client boxes carrying 204 CVEs. The
only mechanism that could settle it is a STARTTLS default-certificate probe on
port 25, which is live-only, cannot be replayed on frozen scans, and adds a
handshake per mail host. Recommend accepting the residual and revisiting with
measured incidence; it is a coverage-versus-cost call for the owner.

**The co-tenancy threshold of two.** Requiring two or more distinct foreign
registrable domains is deliberately conservative and it costs real detections.
`102.222.124.23` is `ibis.aserv.co.za` and also serves redalert.co.za; cyberres
appears nowhere on it, so it is plainly a shared box, but aserv.co.za is the
provider's own zone and is excluded, leaving one foreign tenant and no flag.
Lowering the threshold to one would flag it and would also flag every client
whose single-tenant server happens to carry one stale foreign name. Not changed
without calibration.

**104.47.164.119.** Exchange Online Protection by function, but in
104.47.128.0/17, the upper half, which Microsoft does not publish (the feed
lists 104.47.0.0/17). It is pinned as a KEEP row in the gate specifically so
nobody "completes" the table by hand to make boston.ac.za look tidy. If
Microsoft later publishes the upper half, `--refresh` picks it up and the KEEP
row must then be retired deliberately, with the change visible in review.

**The remediation text still reads as the client's to fix.** A finding on a
co-tenancy-flagged host is now labelled in the vendor-estate block, but the
recommendation ladder and the remediation queue still phrase it as the client's
action. boston.ac.za's "Investigate blacklist listings" is the live example: the
listing is on 20.126.184.33, shared with Sendmarc and Proofpoint. The finding
must keep its score (removing it would be a demotion by another name and would
break the zero-findings-moved invariant), but the wording should say ownership
is unconfirmed. Queued as its own change because it touches recommendation
generation.

**IPv6 is discovered but never port-scanned.** `checkers_network._scan_ports`
opens `socket.socket(socket.AF_INET, ...)` while resolution uses `AF_UNSPEC`, so
every IPv6 address enters the pool, returns zero open ports and renders as an
OWNED host with no findings, clean by construction. Step 3c removes many of them
(they were Exchange Online endpoints, correctly demoted), which makes the
remainder a larger share of what is left. Pre-existing; deserves its own ticket.

**verified_origin bypasses classification entirely.** Both call sites `continue`
before `classify_ip`, and `_verify_origin` accepts any certificate covering the
domain with chain validation off, so a multi-tenant platform serving the client's
custom-domain certificate passes. A cert match proves the host SERVES the domain,
not that the client OPERATES it, which is the distinction this module exists to
draw. Narrow in practice, but it is the one path reaching the priced surface with
no classification at all.

### 5t. Steps 2 and 3 of classify_ip rest on signals the insured can author

Raised by the adversarial critique of step 3c and confirmed. Walking classify_ip
in order: step 1 (private/reserved) is arithmetic; step 1b (published service
ranges) is genuinely un-authorable by the party being judged, which is the whole
reason it was chosen. Steps 2 and 3 are not.

* Step 2 matches a reverse-DNS SUFFIX. Where a provider delegates the reverse
  zone, or lets a customer set custom rDNS, the address holder writes that
  string. A PTR of `something.wpengine.com` on the insured's own exposed box
  demotes it to SAAS and removes its findings from the priced estate.
* Step 3 matches an HTTP `Server` banner. That header is whatever the origin
  chooses to send. Returning `Server: cloudflare` demotes the host to CDN.

Both predate this change and neither is newly introduced, but the step 3c work
made the consequence sharper by giving demotion real teeth: a demoted host now
leaves per_ip entirely and its findings leave the client's estate.

THE FIX IS FORWARD CONFIRMATION, NOT A LONGER TABLE. Resolve the PTR name and
require the address to come back. A customer who can write the reverse record
usually cannot also make `wpengine.com` resolve to their box. The banner rule
should require corroboration from an independent signal (org, or an address
range) rather than standing alone.

NOT DONE HERE because it is a behaviour change with its own measurement: a
missing forward confirmation must never demote, or a DNS timeout becomes a
discount, and `ptr_map` at `scanner.py` already drops addresses silently on
`FuturesTimeoutError`. Needs its own change with a regression proving that an
unresolvable PTR leaves the bucket alone.

### 5u. measure_attribution_delta does not replay the post-scan default-cert rule

`classify_pool` passes reverse_dns, org and banner. It does not pass
`default_cert_names` or `insured_domain`, so the no-SNI shared-hosting rule
(`looks_multi_tenant`) never fires in the harness, and the harness cannot see
any host whose only vendor signal is the provider's default certificate.

The effect is bounded and in the safe direction: the harness UNDER-counts
demotions, so its "0 CVEs moved" is measured over a pool at least as large as
production's, never smaller. It is recorded rather than fixed because the probe
is live-only. Per-IP certificate names are not persisted anywhere
(`scanner.py` probes them into a local and discards them; `checkers_core` stores
only the apex certificate's subject and issuer), so no frozen scan can replay
it. Persisting per-IP SAN sets would make the existing shared-hosting verdict
replayable and is worth doing on its own.

### 5v. Dashboard estate change is SOURCE-ONLY: not typechecked, not rebuilt

`frontend/src/data/selectors.ts` gained `estateIpCount` and `vendorIpCount`, and
`DiscoveryPage.tsx` / `NetworkPage.tsx` now use them, so the dashboard agrees
with the PDF about how big a client's estate is. Before this, both panels read
`external_ips.total_unique_ips` under the labels "Discovered IPs" and "External
IPs", which after the attribution work is the POST-attribution pool: boston.ac.za
would have read 3 on the dashboard and 15 in the PDF, and the label is the
giveaway, because those hosts *were* discovered.

**RESOLVED 2026-09-10.** `npm install` (there is no lockfile, so `npm ci`
is not available), `npm run typecheck` clean, and `SCANNER_BASE_PATH=/scanner
npm run build` run. Verified afterwards rather than assumed: the built
`index.html` references `/scanner/static/dashboard/`, which is the base path
whose absence makes a finished scan hang at "0/39 Scanning" forever; and the
string "Vendor-operated" is present in the emitted `app.js`, so the change is
genuinely in the bundle rather than only in the source. `static/dashboard/` is
committed; `node_modules` is gitignored and stays out.
