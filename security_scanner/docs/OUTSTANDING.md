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

**RESOLVED 2026-09-10, owner-approved after measurement.** See the measured impact below. Not a 
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

**BUILD TRAP, WINDOWS.** `SCANNER_BASE_PATH=/scanner` under Git Bash is rewritten
by MSYS path translation into `/Program Files/Git/scanner`, and the base path is
baked into `index.html` silently. The first build here shipped
`src="/Program Files/Git/scanner/static/dashboard/app.js"`, which breaks the
dashboard outright. Build with `MSYS_NO_PATHCONV=1` prefixed, or from PowerShell.

Verify by extracting the `src`/`href` values and asserting each STARTS WITH
`/scanner/static/dashboard/`. A substring grep for `/scanner/static/dashboard/`
matches happily inside the mangled path and reports success on a broken build,
which is how the bad artefact was committed here in the first place.

#### 5n MEASURED (2026-09-10) — the numbers the decision was waiting for

Owner asked for measurement before any code change. Run over the 30 retained
scans, adding `.ac.za`, `.org.za`, `.net.za`, `.gov.za` and `.web.za` to
`ALT_TLDS`:

| | |
|---|---|
| new candidate domains generated | **148** (about 5 per client, 22 of 30 targets are `.za`) |
| of those, actually RESOLVE | **3** |
| clients whose lookalike count rises | **3 of 30**, by exactly 1 each |

    boston.ac.za    boston.net.za    -> 102.223.199.248
    takealot.com    takealot.org.za  -> 156.38.135.146
    example.com     example.org.za   -> 41.203.18.177   (test fixture)

So the scoring impact is far smaller than the candidate count suggests: two real
clients gain one resolving lookalike each. Cost is about 5 extra DNS lookups per
South African client, which is negligible against the existing permutation set.

Each of the three would still pass through the ownership verification added in
remediation step 2, so a defensively-registered domain the client owns is
excluded rather than counted against them. `takealot.org.za` is a plausible
defensive registration; `boston.net.za` is the one worth a human look.

CORRECTION TO A FIRST ATTEMPT AT THIS MEASUREMENT. My first probe extracted the
brand label as `domain.split(".")[0]`, which for the target `www.zinia.co.za`
yields `www` and generated `www.ac.za`, `www.gov.za`, `www.net.za` — three of
which resolve, because they are ordinary hosts under the South African
second-level domains. That produced a headline of 8 resolving candidates and an
apparent checker bug. There is no such bug: `FraudulentDomainChecker._split_domain`
correctly returns `("www.zinia", ".co.za")`. The reimplementation was wrong, not
the checker. Measure with the shipped function, not a paraphrase of it.

STILL A CALIBRATION DECISION. Three new resolving candidates move
`resolved_count` and therefore the category and overall scores on two live
clients, so it needs a golden re-baseline and a decision on whether the extra
candidates carry the same penalty weight as the existing ones.

#### 5n SHIPPED (2026-09-10)

`.ac.za`, `.org.za`, `.net.za`, `.gov.za` and `.web.za` added to `ALT_TLDS`.
Scanning either apex now finds lookalikes under the others, so the same
organisation no longer gets a different answer depending which apex was
submitted.

MEASURED IMPACT, end to end: **boston.ac.za 97 -> 100 of 1000**, takealot
**unchanged**. takealot already carries 20 resolving lookalikes and the penalty
`min(100, resolved * 8)` is already capped at 100, so extra candidates cost it
nothing. Movement is upward, i.e. toward more risk, which is the safe side of
the step-1 underwriting rule.

A GOLDEN RE-BASELINE WAS NOT NEEDED, and my earlier claim that it was is
withdrawn. golden.py replays the SCORING layer over frozen checker output; its
own docstring says "the frozen fixtures ARE the checker output -- the checkers
never re-run here". `ALT_TLDS` is a checker constant, so golden is structurally
blind to it. Verified empirically as well as by reading: adding the five TLDs
left `golden --check` passing unchanged. Golden gates `scoring_analytics` /
`scoring_pipeline`; a checker-table change needs live measurement instead, which
is what was done.

ALSO FIXED, found while doing this: `_split_domain` recognised
`co/com/org/net/ac/gov` but NOT `web`, so `x.web.za` split as `("x.web", ".za")`
and a client submitted at a `.web.za` address had its brand label taken as
`<name>.web`, making every permutation built from it meaningless.

THE FLAT PENALTY IS UNCHANGED AND STILL A CALIBRATION QUESTION. Every resolving
candidate costs a flat 8 of 100 category points regardless of how convincing it
is: `boston.net.za` and a homoglyph like `bo5ton.ac.za` score identically, and
everything past about 13 resolving lookalikes is free because of the cap. That
is pre-existing and 5n only adds three items to it, but it is worth revisiting
when lookalike scoring is next calibrated.

### Remediation step 4 SHIPPED (2026-09-10) — export restricted to the client's mailboxes

`_fetch_dehashed_full` issued a bare `domain:{domain}` query and every returned
record went straight into the CSV. DeHashed's `domain:` operator matches ADJACENT
AND LOOKALIKE mailboxes, so the export could hand a client credentials belonging
to staff at other organisations. It is the same substring-versus-boundary defect
`_email_at_domain` fixed on the scan path, never applied to the export.

`mailbox_in_scope` / `filter_entries_to_authorised` now gate the row builder on a
boundary match, defaulting to the scanned domain and its subdomains. FAIL CLOSED:
a record with no email, an unparseable one, or any record when no domains are
authorised, is REFUSED. `leak_reference` rows survive, because an IntelX posting
names the domain and carries no mailbox, so there is no person to mis-attribute.

The count reported to the operator and written to the audit row is now the
POST-filter count. Reporting the raw query total would tell an operator the file
holds records it deliberately withheld.

Migration 0006 adds `authorised_domains` and `excluded_count` to
`credential_export_audit`: the authorisation is domain-scoped, so without them
the row cannot evidence that the release stayed inside what the client consented
to, and a release that refused nothing looks identical to one where the filter
never ran. Verified on a fresh database and on an upgraded pre-0006 one, with
the existing row intact.

WHAT THIS UNBLOCKS. The authorisation form now describes a process the software
performs. The export remains disabled behind `CREDENTIAL_EXPORT_ENABLED`; that is
a separate decision (§0 demo window) and this change does not flip it.

NO DEHASHED CALL WAS MADE building or testing this. Every row is synthetic. A
guard test in this repo once ran a real paginated export and burned roughly 500
credits, because cost tracks SEARCHES, not results.

### Remediation step 5 SHIPPED IN PART (2026-09-10) — discovery parity

Owner decision 2026-09-10: ship discovery parity now, scope the full spec for
later.

SHIPPED. Related-domain discovery runs inside every scan, whether submitted
through the web form or the API. Before this only the form's pre-flight looked
for related domains, so an API scan was silently narrower, and none of the 30
retained scans carried a related_domains result at all. Candidates come from the
certificate names SubdomainChecker already fetches from crt.sh and CertSpotter
and used to discard, so parity holds by construction at zero added network cost.
The union is also far more available than the old crt.sh-only discovery: crt.sh
returned names under the scanned domain on 7 of the 30 retained scans, CertSpotter
on 27. (The stored field recorded a source only when it returned such names, not
whether it answered at all; that is recorded separately from this change on, as
ct_sources_answered.)

Discovered domains are LISTED FOR CONFIRMATION AND NEVER PROBED OR PRICED. Only
domains a broker confirms on the form, or an API request declares, are scanned
(LITE mode) and scored, exactly as before. The form no longer pre-ticks
"high confidence" candidates: a machine guess must not become a confirmation by
default.

STATUS CONTRACT. The category is only ever "completed" or "unassessed". Measured
over the corpus, absent, completed/100 and unassessed all price at +0, while
skipped, error and timeout all price at +5 to +16 (mean +8.47). The checker's
old "skipped" on an empty list would therefore have made a client with no
related domains DEARER than one with a clean confirmed sibling. A discovery
outage is "unassessed" (renders Not Assessed), never "no_data", which the
supply-chain slide renders as CLEAN.

Reporting states discovery parity on every surface: the full PDF card (four
states), the assessment-tier supply-chain slide, the executive-deck label, the
client meeting brief, the dashboard Exposure page, the scan form, manual section
4.6.12, and the manual changelog. The false sentence "auto-discovery from
certificate SANs is on the v1.2 roadmap" is gone.

ALSO FIXED ALONG THE WAY. The pre-flight reducer returned `school.za` for
`stjohns.school.za` and could offer a registry zone as a "sibling". The new
reducer treats every `.za` name as sitting under a registry zone, and the form's
pre-flight now uses the same reducer and rejection rules as the report.

BACK-TEST FINDING #17 (S-1 inert, broker-declared only) is closed in part by
this change: discovery now runs on every scan, while assessing discovered
domains stays deferred under 5w. The back-test and re-test findings documents
are dated records of what was true when they were written, and are left as
written.

### 5w. The FULL step 5 spec — scoped for later, with its prerequisites

The plan's step 5 also said "give a confirmed sibling the same checker suite as
the apex". That is deferred, on measurement, and cannot ship until each
prerequisite below is met IN ORDER.

1. **Record which names a certificate carries, not only how many.** SSLChecker
   stores `san_count` and discards the SAN names, so no offline measurement can
   say how many organisations a real South African SME certificate spans.
   Capture the name list (capped, and under a key no report renders, because a
   shared certificate's SAN list is other companies' domains, a POPIA
   consideration), then re-freeze a fixture corpus.
2. **Replace the ownership rubber stamp.** `checkers_threats._cert_scope_trusted`
   opens `if len(names) <= 4: return True`. Of the 26 certificates the 30
   retained scans measured, 20 carry four names or fewer (11 of those 20 are
   Let's Encrypt), so the guard would wave through two thirds of the book. That
   population is the insured's own served certificate, a proxy for the
   candidate-side certificates the guard actually evaluates. A shared-hosting
   certificate covering a web agency's clients is the case to worry about, but
   the corpus contains none (its largest certificate carries 7 names), so that
   is an illustration, not a measurement. `_ownership_verdict`'s insured-side
   branch has no scope test at all. Design the replacement on the data from (1),
   never before it.
3. **Recalibrate the sibling roll-up before widening the suite.**
   `RelatedDomainsChecker` collapses a sibling with
   `min(ssl_score, info_score, 100 - dns_risk)` over the checks that returned a
   result, then takes min over siblings. (Until 2026-09-11 it used
   `int(x or 100)`, which read a measured 0, the worst possible result, as a
   clean 100, and counted a check that raised as 100 too; fixed in critique
   round 1 below.) A replay over the corpus with a plain min() over eight free
   apex checkers drives the median sibling to 0, with 27 of 30 at exactly zero:
   a flat +40 to +55 on every insured with any sibling. A signal that fires on
   everyone prices no one. Replace min() with a calibrated roll-up, with its
   own re-baseline.
4. **Never run metered checkers on siblings. Permanent, not deferred.** DeHashed,
   IntelX, VirusTotal, SecurityTrails, HIBP and Shodan per sibling would cut
   daily throughput roughly by the sibling count, and a rate-limited provider
   either drops out of the weights and is redistributed (DeHashed, IntelX and
   HIBP) or, for VirusTotal and SecurityTrails today, keeps its full weight at
   zero risk and scores as a clean result (5z). Either way a credit overrun
   becomes a silent scoring bug. This is the shape of the leak that once burned
   about 500 credits: cost tracks searches, not results.
5. **Never actively probe an unconfirmed sibling. Permanent.** The LITE probe
   runs a TCP-connect scan and 18 sensitive-path probes including `/.env` and
   `/.git/config`. Firing those at a domain the insured has not been shown to
   own is unauthorised scanning of a third party, which is unlawful-access
   exposure under the Cybercrimes Act 19 of 2020 sitting with the UMA. (The
   Act's Schedule is understood to repeal ECTA ss85 to 88 and s90 and to amend
   s89; counsel to confirm the provision that applies, and whether the
   catastrophe model's "ECTA Section 89" fine, c2_ecta_cat in
   scoring_analytics.py, still rests on offences in force.)

RELATED, RECORDED SEPARATELY:

- **The standing 0.04 free credit.** An absent related_domains category is in
  neither the failed nor the skipped status set, so it keeps full weight at zero
  risk, and every historical scan banked a clean-sibling credit for a checker
  that never ran. Fixing it by weight redistribution is exactly what creates the
  +8.47 inversion above, so it must not be fixed that way. If the owner wants the
  epistemic gap priced, the channel is coverage uncertainty, which widens the
  tail and leaves the median anchored.
- **Pre-flight discovery on the form is still crt.sh-only** (three attempts at a
  35-second timeout), so the form's preview can come back empty when the scan's
  CT union later finds candidates. It now uses the report's reducer and
  rejection rules, so it no longer offers a recognised registry zone (5ad), and
  its empty result says it searched crt.sh alone and that the report can list
  more. It also searches crt.sh in its own way (critique round 8, IR8-2, GS8-4):
  a different search string, a 35-second timeout against the scan's 20, and up
  to three attempts where the scan retries an empty answer once. So even on
  crt.sh alone the two can differ, in either direction: two empty answers and
  then names give the form candidates and the report none. The report is
  authoritative. Fix: one crt.sh fetcher shared by the pre-flight and the scan
  (search string, timeout, retries and the handling of an empty answer), with
  the gate asserting the request each side sends.
- **8443.** Extending the TLS probe gate to 8443 adds exactly one host on the
  corpus (gcrratings.com 105.27.161.218) and needs `port=` threaded into
  `probe_default_cert`. Measure separately.
- **MAX_DOMAINS truncation. FIXED 2026-09-11.** A broker who confirmed more
  than the ten domains a scan assesses used to have the rest silently dropped.
  They are now recorded (confirmed_over_cap) and shown as not assessed on every
  surface.

### 5x. Timeout gate: one false positive cleared, five loops it never inspects, and a false clean behind them (2026-09-11)

Found while verifying step 5. `tooling/verify_scan_timeout_handling.py` failed on
every commit from 0ba06e9 (sandbox step 2, 2026-09-08) to c6b4fda, 34 commits;
it passed at ce75eea. The pre-push hook runs it and would have blocked a push,
but nothing was pushed in that window, and the sandbox's manual suite runs did
not include it.

CLEARED. The failure was a false positive. The lookalike ownership loop in
`checkers_threats.py` was guarded by an inner `except Exception`, but it sat
inside a cleanup-only try/finally, and the gate requires every try that contains
the loop to catch the futures TimeoutError. The gate was left as it is: that
strictness is what catches an inner `except TimeoutError` hidden behind an outer
broad handler, which is the Python 3.10 bug it exists for. The code was
restructured instead, into separate submit and collect blocks, and proven
behaviour-identical to HEAD in four modes (stall, raise, owned, submission
failure). The inspected-loop count falls from 15 to 14 because one try no longer
contains the loop.

OPEN, NOT FIXED. A propagation model over all 18 `as_completed(timeout=)` calls
in scanner.py and the four checker modules found five in `checkers_network.py`
that sit in no try at all, so the gate never inspects them:

- `SubdomainChecker.check`, brute-force resolution, 15 s budget
- `SubdomainChecker.check`, subdomain-to-IP resolution, 15 s
- `SubdomainChecker.check`, CNAME takeover check, 90 s
- `DNSInfrastructureChecker._scan_ports`, the port probe, 30 s
- `HighRiskProtocolChecker.check`, the critical-services probe, 30 s

(At c6b4fda these are checkers_network.py lines 269, 310, 353, 870 and 1170;
the working tree moves them.) All five predate the remediation. What happens
when one of those budgets expires depends on the checker, and ONE CASE IS A
FALSE CLEAN TODAY:

- SubdomainChecker (the three loops above). The timeout leaves `check()` and
  `run_with_timeout` catches it, so the whole category is recorded as "timeout",
  which is not clean. Its message names the outer budget rather than the 15 or
  90 s one that expired, and everything the checker had collected is lost.
- DNSInfrastructureChecker (`_scan_ports`). `check()` catches the exception and
  marks that IP's result "error". HighRiskProtocolChecker (`check`) has no such
  handler, so the
  timeout leaves `check()` for that IP.
- In a scan with more than one IP, `SecurityScanner._aggregate_ip_results`
  (scanner.py) builds the category from the RICHEST per-IP result and adopts
  its status; ties go to the first IP, because a failed result carries no
  issues. A failed IP is silently absent whenever a healthy IP has findings
  (always for dns_infrastructure, since open 80/443 count): the category reads
  "completed", a FALSE CLEAN for that IP, with no NOT ASSESSED marker. On a tie
  the outcome depends on IP order and can instead read "error" or "timeout",
  discarding the healthy IP's measurement (critique round 2 drove the real
  function). How a single-IP scan records it depends on the per-IP runner and
  was not re-verified here.
- Each loop also sits in a `with ThreadPoolExecutor` block, whose exit waits for
  every outstanding probe, so the budget does not bound the wait either.

The aggregation is the urgent part, because it turns a measurement failure into
a clean result that prices. Fix `_aggregate_ip_results` to carry a per-IP failure
through (the failed IP is NOT ASSESSED, and the category says so), with its own
measurement over the corpus. For the loops, catch the timeout, return the partial
result explicitly marked incomplete, never as completed and clean, shut the pool
down without waiting, and extend the gate to flag any `as_completed(timeout=)`
call with no enclosing try.

### Step 5 critique round 1 (2026-09-11)

A five-dimension adversarial critique (fail-closed and pricing, reporting
surfaces, the reducer, the gates, and the claims), with each medium-or-worse
finding then attacked by a separate skeptic, confirmed ten findings and refuted
none. What was done:

- ONE STATE MODEL. `estate_discovery.related_domains_state` defines six states;
  the PDF card, the deck, the summary tier and, by a line-for-line port, the
  dashboard all use it. Before, the dashboard said confirmed domains "were
  assessed" when their probe had timed out, while the PDF said Not assessed.
- THE STATUS DECISION IS ONE TESTED FUNCTION. `build_related_domains_category`
  replaced the inline scanner block; scan() calls it once and the gate drives
  it. It closes: a primary-only confirmed list during a CT outage reading
  "Assessed, none found"; a resumed scan's pre-change checkpoint reading as
  discovery having run; a probe that measured nothing reading as completed and
  clean; a timed-out probe being checkpointed as NOT ASSESSED and never retried;
  confirmed domains over the cap of ten vanishing; a registry zone or the
  client's own domain being probed as a "sibling".
- A MEASURED 0 IS 0. The confirmed-sibling roll-up read the worst possible
  result as a clean 100, and a check that raised as 100 too. Now a check that
  returns nothing is left out, and a sibling with no result is NOT ASSESSED. The
  critique measured the effect on a confirmed sibling with no usable TLS at +40
  to +55 on the 0-1000 scale across the 30 retained scans: the rule working, as
  a finding loads.
- STORED PRE-CHANGE SCANS never re-render as "none found". A stored "timeout",
  "error" or "skipped" reads Not assessed, as it did before step 5.
- SUMMARY TIER. Discovery alone no longer makes the supply-chain row read
  "Clean"; related domains count only when confirmed domains were probed.
- DECK. Candidates awaiting confirmation are Not assessed, not "Not applicable".
- PRODUCER. A certificate name is the client's subdomain only on a label
  boundary (`notacme.co.za` is not under `acme.co.za`); before, such names were
  resolved and takeover-probed as the client's own. A source that answered with
  no subdomains is no longer reported as an outage. Foreign names are capped per
  organisation with the overflow counted, not truncated alphabetically.
- REDUCER. IP addresses and every `.za` registry zone are rejected; the common
  Southern and East African second-level registries and a named list elsewhere
  are recognised (not every registry: 5ad); provider zones deeper than a
  registrable domain are caught. The form's pre-flight uses the same reducer, so
  it no longer offers `school.za`.
- WORDING. The meeting brief no longer says confirming a related domain assesses
  its credential exposure (it runs only the LITE probe). Every claim the claims
  critic disproved was corrected (5w, 5x, and the counts above).
- GATE. `_check_discovery_parity` now drives the real builder, the real CT
  fetchers through faked HTTP clients, the real checker, and the real renderers
  (card, deck, summary tier). Round 2 still found plausible regressions it
  missed; see round 2.

The dashboard selector's state logic is TypeScript. From round 2 the gate runs it
under node against the Python functions on every case, and fails if node is
missing.

### 5y. InformationDisclosureChecker: one defect fixed, one recorded (2026-09-11)

FIXED in step 5. From 57e43b6 (2026-06-28) a local `from http_client import
HTTP` late in `check()` made HTTP a local variable, unbound while the probe pool
ran, so every one of the 10 medium-risk path probes (/phpinfo.php,
/server-status, /actuator/env, /web.config and so on) raised NameError and was
silently dropped. Only the 8 critical paths were ever requested: all 24 of the
retained scans that record probe codes counted exactly 8 responses. The late
import is gone, and a probe that raises is now counted (probe_errors, stored
with the result; nothing reads it yet). The critique measured one dropped
medium path at +5 to +7 risk points (mean 5.63), three at +15 to +21. How often
a medium path is exposed on real clients is unknown, because the probes never
ran.

Running the medium paths was not load-only on its own, although the round-2
record said so (critique round 3, C3-1). A probe with no HTTP answer (status 0)
counted as probed but not as refused, so on a host that refused every answered
probe, one unanswered medium probe turned "unreachable" (fail-closed) into a
clean completed/100. Applied to each of the 30 retained exports that move is
worth -6 to -20 (mean -10.43), with four changing band; no retained scan is
known to have been in that state. Round 4 counts only answered probes in the
refusal test. On the same answers, that rule only ever adds "unreachable"
results compared with HEAD's: it also closes the older form of the hole, where
an unanswered CRITICAL probe did the same (HEAD read {403: 7, 0: 1}, with the
root refused, as completed/100). It can also add the "paths denied, correct
configuration" note (sensitive_paths_denied, which nothing scores) where some
probes got no answer and the root answered. Replayed on the stored probe
codes of the 30 retained scans, the rule changes no stored verdict: five store
an unanswered probe, four with no answer at all (the open part below) and
wwib, whose root answered. What the medium probes can still do, by
design, is supply a real answer: a medium path answered 404 on a host that
refused every critical path and the root counts as the origin talking to us,
and the result is a completed, earned clean, as the control rule intends for
any real 404. How often that happens is unknown.

OPEN, owner decision. When no probe gets any HTTP answer (every status code 0),
the checker still reports completed with score 100: with no answered probe
there is nothing to refuse. On 4 of the 30 retained scans (cyberres,
dubetradeport, morgancarco, quarphix) the primary did exactly that while
http_headers, tech_stack and waf errored and website_security read
unreachable. Reporting it fail-closed ("unreachable", which is in the failed
set) prices those scans 9 to 13 points higher. That is a primary-scan pricing
change, and today it breaches the rule that an absence of findings may never
discount. Confirmed siblings are guarded: a sibling's info check that got no
HTTP answer is not assessed, and one refused on every answered probe is not
assessed unless its site root answered (a denial with the root answering is
measured clean, as for the primary).

### 5z. VirusTotal and SecurityTrails "rate_limited" keeps full weight at zero risk (2026-09-11)

OPEN, owner decision. On HTTP 429 both checkers set status "rate_limited",
which is in neither _FAILED_STATUSES nor _SKIPPED_STATUSES, so the category
keeps its full weight (VirusTotal 0.05, SecurityTrails 0.01) at zero risk: a
verified-clean result nobody measured. The report card already says NOT
ASSESSED, so price and report disagree. SecurityTrails is stored rate_limited on
18 of the 30 retained scans (18 of the 20 dated 2026-08-14 to 2026-08-27,
every one from 2026-08-14 10:40 UTC on; 11 of the 18 still carry confidence
"full"); pricing them fail-closed adds +1 to +4
(mean 2.22, no band change). The VirusTotal path is latent (completed on all 30)
and worth +6 to +20. Fix by adding "rate_limited" to _FAILED_STATUSES, or by
mapping 429 to quota_exhausted as DeHashed and IntelX do, with its own
re-baseline.

### 5aa. run_with_timeout never orphans its worker (2026-09-11)

Its `with ThreadPoolExecutor` exit calls shutdown(wait=True), so after a timeout
it still waits for the checker to finish, then discards the finished result.
The docstring says the thread is "allowed to orphan"; it is not. This affects
every heavy checker, and the same `with` pattern inside a checker makes its own
as_completed budget bound nothing (5x).

For related_domains this is handled in step 5, in round 4, after critique round
3 showed the round-3 claim ("a finished sibling measurement is no longer thrown
away") false. RelatedDomainsChecker now shuts its pool down without waiting when
its budget ends (180 s per round of four confirmed domains, raised from 150 s
in round 5), keeps every domain
that finished, reports the rest NOT ASSESSED, and returns; the outer
run_with_timeout budget sits 60 s above it, so it fires only if the checker
hangs outside its pool. The round is sized for a single-address host: each
further address of a domain whose HTTPS does not answer adds about 137 s, so
such a domain can run past it (critique round 5). A domain whose own checks
run past the budget is still
not assessed, because its three sub-checks have no deadlines of their own;
giving each one a deadline belongs to the general fix. The general fix (keep
the late result, or truly orphan the worker, for every heavy checker) is open.

### 5ab. ip_attribution still uses the old reducer (2026-09-11)

`ip_attribution` reduces names with `related_domain_discovery._apex`, which
returns school.za for stjohns.school.za. For an insured under a .za zone or a
ccTLD registry that the old list does not know, another organisation's host can
read CONFIRMED as the insured's, and co-tenancy is hidden. Reporting only: the
confidence tier never moves a bucket. Fix by moving `registrable` to a leaf
module both can import; a direct import would cycle with estate_discovery.

### 5ac. Adversarial gate hygiene (2026-09-11)

Pre-existing, outside the discovery section, which is offline and
order-independent. A full run attempts six live TCP connects to example.com:3389
(_check_blocked_not_clean patches HTTP but not socket), and egress-IP lookups
to api.ipify.org and checkip.amazonaws.com when no egress cache exists; the
paid-egress guard is a host denylist and cannot see them. balance_metering
passes or fails depending on which check imports app first (app.py reads
DEHASHED_API_KEY at import). Fix: a default-deny socket block for the whole
gate, SCANNER_EGRESS_IP set for the recommendation check, and the key set on
the imported module.

### 5ad. Registry zones outside the recognised list (2026-09-11)

registrable() knows every .za zone, a named list of second-level registries, and
the co/com/net/org/ac/edu/gov/go/or/ne/mil/nom/sch labels under two-letter
ccTLDs. Any other registry zone, including three-label suffixes such as
nsw.gov.au, reduces to the zone itself. It can then be listed as a candidate
that merges unrelated registrants, and probed if a broker confirms it.
Discovered candidates are never priced. How often this occurs cannot be measured
from the retained corpus, because no scan before step 5 stored co-listed
certificate names. The proper fix is a vendored Public Suffix List snapshot.

### Step 5 critique round 2 (2026-09-11)

A second five-dimension critique attacked the round-1 fixes; ten findings went
to a skeptic, none was refuted, and most were downgraded. Nothing challenged the
one-state-model design. What was done in step 5:

- A confirmed sibling counts as measured only where it answered. A sibling that
  does not resolve, an information-disclosure check with no HTTP answer, and a
  TLS check on a host with no web service are NOT ASSESSED, not the worst
  possible score. A pre-change checkpoint's probe result counts nothing as
  measured.
- A sibling that finishes after the checker's budget, while the pool shutdown
  waits for it anyway, is collected instead of discarded, and the outer budget
  sits above the checker's own. (Critique round 3 showed that was not enough:
  the outer budget could still fire first. See round 3 below and 5aa.)
- Scanning a subdomain no longer rejects its parent or sibling hosts as "the
  scanned domain or one of its subdomains"; only the scanned host and hosts
  under it are rejected.
- A partly assessed confirmed domain is marked as such on every surface: the
  card rows and colour, a note shared word for word with the dashboard, the deck
  (NOT ASSESSED, not LOW), the summary row (not "Clean" from related domains
  alone; round 3 below covers the aggregate row), and a dashboard badge
  derived from the counts, so a critical finding no longer shows "Passed".
- The scan form no longer trims the confirmed list to ten in the browser, so
  confirmed domains beyond ten are listed as not assessed on the form path too.
- Discovery lists unconfirmed candidates first, ranks organisations by their
  true name count, and never hides the "and N more" line. A provider zone of the
  insured's own brand is a candidate, not "a hosting provider's own zone". More
  registry zones are recognised. Subdomain enumeration no longer calls a source
  that answered with no names "unreachable".
- The deck files "none found" as NOT ASSESSED, not "Not applicable".
- InformationDisclosureChecker's medium-path probes run again (5y).
- The gate now checks scan()'s arguments by AST; the deck and summary content in
  the confirmed states; the pre-flight reducer against the report's; the cap
  through check(); every legacy shape through the deck; and runs the dashboard's
  TypeScript state logic under node against Python.

Recorded, not fixed, as owner decisions on primary-scan pricing or as separate
work: 5y (info check with no HTTP answer), 5z (rate_limited VirusTotal and
SecurityTrails), 5aa (run_with_timeout), 5ab (ip_attribution reducer), 5ac (gate
hygiene), 5ad (registry zones).

### 5ae. No check that a scanned name resolves to a public address (2026-09-11)

OPEN. The primary domain is accepted on syntax and existence (NXDOMAIN) only,
and several checkers then connect to the NAME before any address is
classified: ExposedAdminChecker and InformationDisclosureChecker request
sensitive paths, SSLChecker connects to port 443, VPNRemoteAccessChecker to
3389 and to gateway paths. A primary name that resolves to a loopback,
private or link-local address is therefore probed from inside the scanner's
network; http_client has no address check. Step 5 closes this for confirmed
related domains only: a sibling with any non-public address, IPv4 or IPv6, is
not probed and is not assessed (critique rounds 3 and 4). Fix: one address check
shared by the primary and the siblings, with the connection pinned to the
vetted address to limit DNS rebinding; the sibling check resolves the name
separately from the probes, so a rebinding name can still pass it.

### Step 5 critique round 3 (2026-09-11)

A third critique (fail-closed, reporting, the reducer, the gates and the
claims; twelve agents) confirmed seven findings, all downgraded by its
skeptics, and raised twenty-six unverified lower-severity ones. Round 4 acted
on all of them:

- THE BUDGET BOUNDS THE WAIT (FC3-1). The round-3 fix raised the outer budget
  but left the checker's `with` block waiting for its slowest domain, so the
  outer timeout could still fire first and discard every finished domain,
  findings included. The checker now stops at its budget, one allowance per
  round of four domains (150 s, raised to 180 s in round 5: a single-address
  domain whose HTTPS does not answer takes about 144 to 150 s), keeps what
  finished, and
  reports the rest NOT
  ASSESSED; when nothing finished because time ran out the result is a
  "timeout", which a resumed scan re-probes. The runner moved to module level
  and the gate runs it with a domain slower than the budget. See 5aa.
- A NO-ANSWER PROBE NEVER DECIDES A REFUSAL (C3-1). See 5y.
- TLS REACHED (G3-01). Gate cases where the DNS check fails or lists no web
  port, paired with the real SSLChecker shapes (stdlib self-signed, stdlib
  certificate-only, sslyze, TLS versions with a certificate error), so each
  branch of the TLS-reached test is guarded.
- SUMMARY ROW (R3-TRUTH-1, C3-2). The aggregate supply-chain row no longer
  reads a plain "Clean" beside confirmed domains that were not fully
  assessed, or beside candidates awaiting confirmation: it says so, amber
  for an incomplete assessment. It still does not show other supply-chain
  categories' gaps (a third_party_js error, a vendor_breach no_data), as
  before step 5.
- NON-PUBLIC AND IPv6-ONLY SIBLINGS (FC3-2, FC3-4). A confirmed domain that
  resolves to a private, loopback or link-local address (from round 5, in its
  AAAA records too) is not probed and is
  not assessed; one with IPv6 records only is not assessed and is no longer
  described as unresolvable. The primary-domain side is 5ae.
- REPORTING. "And N more" counts unconfirmed candidates only; the
  discovery-could-not-run wording names its cause (certificate lookup,
  subdomain check, or a pre-discovery checkpoint); the deck gives related
  domains that gathered data a footer sentence of their own instead of "no
  scan data" (for a discovery that could not run and an unassessed probe,
  from round 5); "Submitted for assessment" counts every confirmed entry
  the scan received; a
  result stored before step 5 is never shown as a clean pass; the dashboard
  badge is red for a domain below 60 and amber for a partial assessment, as
  the card is. The manual's presentation and scoring paragraphs say the same.
- REDUCER. The provider and platform brand exception became exact (or a
  listed alias, voxtelecom for vox.co.za; since round 5, a listed alias only)
  and never applies to a zone deeper than
  its registrable domain, so laservision.co.za no longer lists aserv.co.za
  and azurecapital.co.za no longer lists azure.com.
- A confirmed subdomain of the scanned host stays unassessed, but the reason
  no longer says the main scan covers it: the main scan does not check that
  host's certificate or web paths either. Assessing the insured's own
  subdomains belongs to the full spec (5w).
- GATE. The dashboard panel's logic moved to
  frontend/src/data/relatedDomains.ts, which the gate runs under node on every
  case and compares with the PDF card: the state, the notes word for word,
  the lead sentence, the badge against the card's colour, the rows and the
  "and N more" count. Also added: partial assessments with a finding (deck
  and summary), card colours, the partial note beyond five rows, more than
  twelve candidates, the form's untrimmed list, the brand rules, the empty
  info code map, probe_errors, and the refusal test with unanswered probes.

### Step 5 critique round 4 (2026-09-11)

A fourth critique (eleven agents) confirmed five findings, every one
downgraded to low by its skeptic, refuted one, and raised thirty-two
unverified ones (four rated medium by their finder, all of them gate
coverage). No medium or worse finding survived verification. Round 5 acted on
them:

- BUDGET MARGIN (FC4-1). A single-address domain whose HTTPS does not answer
  takes about 150 s once an open port makes the port probe run its canary
  connects,
  against a 150 s round, so its measured port finding was lost. The round
  budget is now 180 s (540 s for ten domains).
- AAAA RECORDS (FC4-2, C4-1). Every IPv6 address of a confirmed domain must be
  public too: a public A record beside a loopback or private AAAA record is no
  longer probed.
- TIMEOUT RULE (FC4-3, G4-02). When nothing was measured and any domain ran
  out of time, the result is a timeout, re-probed on resume, not a
  checkpointed "none of the checks returned a result".
- CANDIDATES BESIDE CONFIRMED DOMAINS (T4-1, T4-6). The summary row and the
  deck say when candidates await confirmation beside assessed confirmed
  domains, not only when nothing is confirmed, and candidates are never shown
  in the colour of Clean.
- DECK (T4-3, C4-4, T4-5, PR4-4). A discovery that could not run and a probe
  that could not assess its domains get a footer sentence with the cause; only
  a scan that predates discovery stays under "no scan data". The partial
  metric counts confirmed related domains only, not rejected entries.
- STORED RESULTS (T4-4, T4-8). A confirmed result stored before step 5 is
  worded as unverifiable ("Not verified" on the dashboard), and a stored
  timeout or error says its confirmed domains went unassessed, on the card,
  the dashboard and the summary row.
- DISCOVERY CARD (T4-7). Its broker row counts what was submitted.
- REDUCER (PR4-1, PR4-2, PR4-3). A provider or platform zone is a candidate
  only through an explicit per-group alias list (Afrihost, MWEB, Vox, Telkom,
  Liquid, xneelo, Internet Solutions); name likeness alone never lists one.
  The form's confidence label no longer treats containment as a shared brand.
- FORM (T4-9). A certificate-lookup outage reads as unavailable, not as a
  reassuring "none found", and an empty result carries the report's caveat.
- API (PR4-5). A trailing dot or a wildcard prefix on a submitted related
  domain is cleaned rather than dropped. RECORDED, NOT FIXED: entries that are
  still not valid domain names are dropped at the API before the scan, and no
  surface reports them.
- CLAIMS (C4-2, C4-3, C4-5, C4-6, C4-7, C4-8). 5y, the refusal-test comment,
  the heuristics-audit rows and the pointers to the dashboard module
  corrected.
- GATE (G4-01 to G4-12, PR4-6). The runner test is deterministic (a slow
  domain is held until the checker has returned) and adds more domains than
  workers, queued domains that must be cancelled, and a mixed timeout. The
  dashboard comparison checks every lead, badge label and row label: against
  the rendered card where the card prints the same text, and against the
  gate's own wording for the confirmed-state leads and the Not verified label;
  the notes and candidates are checked as rendered. The dashboard
  page and the committed bundle are checked. Also added: CGNAT and AAAA
  addresses, submitted counts with rejected entries, the legacy deck metric,
  the alias rules, a wildcard name, the form's outage handling and
  confidence label, and a single assignment of the builder's result in
  scan().

### Step 5 critique round 5 (2026-09-11)

A fifth critique (nine agents) confirmed four findings, every one downgraded
to low by its skeptic, and raised thirty-three unverified ones, nearly all low;
for the second round running no medium or worse finding survived
verification. Round 6 acted on them:

- A TLS HANDSHAKE THAT TIMES OUT IS NOT A FINDING (FC5-1). A confirmed domain
  whose port 443 accepted a connection but never answered the handshake was
  priced as the worst TLS result (+40 to +55): a TCP accept is not an answer.
  It is now not assessed; an EOF, a reset or a plain-HTTP reply on 443 is still
  a finding, because the host answered.
- API INPUT (PR5-1, PR5-2). The API validated a normalised related domain but
  stored the raw string, so a pasted name with an invisible character, a port
  or an email prefix reached the report as malformed and unassessed, and
  markup in it could stop the full PDF from building. The normalised value is
  now stored (domain_validation.clean_related_domains), and submitted text is
  escaped wherever the PDF card prints it.
- DISCOVERY THAT COULD NOT RUN BESIDE CONFIRMED DOMAINS (T5-1). The deck and
  the summary row now say so; before, only the card and the dashboard did.
- A PARTIAL ASSESSMENT WITH A FINDING (C5-3). The deck states the partial
  assessment in a sentence of its own beside the finding.
- WORDING (T5-3, T5-4, T5-5, T5-7). The dashboard mentions listed candidates
  only where some are listed; a stored pre-step-5 result states its caveat
  once per surface; the form's pre-flight banner says when related-domain
  auto-discovery was unavailable; the deck's "positive due-diligence result"
  sentence (older than step 5) now appears only when a signal reported a
  result. (Corrected after round 8: a signal that reports a result it did not
  measure, such as S-3 on a host that never answers, still counts, 5af.)
- REDUCER (PR5-5, C5-2). Group aliases are keyed on the group's own
  registrable domains, so an insured whose name merely equals a group's
  (vox.com, liquid.co.za) lists nothing.
- FORM CONFIDENCE LABEL (T5-2, PR5-3). A shared brand is the same first part
  of the name, at least four letters and not a generic business word, and
  certificates are counted rather than names.
- CERTIFICATE-TRANSPARENCY REPLIES (PR5-4). A reply is an answer only when it
  is a list of entries, on the scan and in the form alike.
- CLAIMS (C5-1, C5-4, T5-6, PR5-6, C5-5). The budget figures are stated for a
  single-address host; the dashboard comparison is described as it is; the
  heuristics-audit rows for the form's confidence label and apex reducer are
  rewritten.
- GATE (G5-01 to G5-14). The form never pre-ticks a candidate, renders an
  outage as unavailable and says so in its banner; the summary tier has
  none-found, stored-error and stored-nothing-scanned cases; candidates are
  checked in every state that lists them, on the summary row and the deck; the
  crt.sh reply shapes, the stale-bundle check over every dashboard string, the
  page's unconditional renders, the API cleaning, every alias entry, alias
  prefixes and look-alikes, and the confidence label's floor and generic words
  are all guarded.

### Step 5 critique round 6 (2026-09-11)

A sixth critique (fifteen agents: five reviewers and ten skeptics) upheld
seven findings, one of them high, refuted three, and left fourteen
unverified; round 7 acted on or recorded every one:

- THE VENDOR CROSS-CHECK READ CLEAN WITH NOTHING MEASURED (FC6-1, high). The
  deck classified the Phase 4f join's "no_data" as clean. scan() writes
  "no_data" when Hudson Rock found no third-party exposure and also when
  Hudson Rock did not complete, so a scan on which every supply-chain signal
  failed still read LOW EXPOSURE and "a positive due-diligence result": the
  round-6 wording for a scan with nothing assessed (T5-7) never appeared on
  real output. The deck now counts the join as clean only when Hudson Rock
  completed. The join is unchanged; the technical report and the summary
  table read it only when it completed, and the dashboard shows "no_data"
  as No data.
- TLS (CD6-1 upheld; FC6-3, FC6-4). The round-6 exemption was keyed on the
  port probe's list, so a handshake that timed out on a 443 the probe had
  missed was still priced as the worst TLS result, against the manual, and a
  plain-HTTP reply on 443 was dropped when the port probe failed or listed
  nothing. The rule now reads every recorded connection error: 443
  answering without TLS is a finding, and a handshake 443 accepted and never
  answered is not assessed, whatever the port probe saw; otherwise the port
  probe decides as before.
- INPUT (IR6-1, IR6-3, and IR6-4 in part). normalize_domain stops only at a
  fixed point,
  so '"supplier.co.za".' is kept as supplier.co.za rather than as a
  malformed name that is never probed; the scan route normalises the primary
  domain as the pre-flight does, so the insured's own domain in the related
  list is recognised; de-duplication uses a set.
- DECK AND SUMMARY WORDING (CD6-2, ST6-3, ST6-4, ST6-5, ST6-6). A stored
  pre-step-5 result with a finding has a deck footnote; a slide on which
  nothing was assessed in full, but a signal was in part, says so; the footer
  for confirmed domains that timed out counts those over the cap too; the
  summary row says when discovery found none, never "Clean"; the stored
  result's card says "not a complete assessment" once.
- CERTIFICATE-TRANSPARENCY REPLIES (CD6-4). One test on the scan and the form:
  a list of entries, each with its names as text.
- GATE (GS6-1 to GS6-6, CD6-3). Every branch of the TLS rule; replies that do
  not parse, and badly typed ones, on both sides; the banner run under node
  for every pre-flight outcome; any way of ticking a candidate box; the scan
  route checked by AST; the vendor join with Hudson Rock failed and
  completed; deck and summary cases beside findings, timeouts, discovery
  down and the cap; an estate whose only certificate name is the confirmed
  domain. The round-5 record's "stale-bundle check over every dashboard
  string" read only single-quoted strings and missed a change of logic (the
  round-5 bundle passed it); the check is now a rebuild of the dashboard
  compared byte for byte with the committed bundle. The mutation harness
  rebuilds the bundle for every dashboard mutation, so the parity checks,
  not the stale-bundle check, must catch those.
- REFUTED: FC6-2 (a filtered 443 beside plain HTTP on 80 is a finding by
  design), ST6-1 (a rejected entry never makes an estate partial, PR4-4) and
  ST6-2 (a clean confirmed estate beside discovery that could not run reads
  LOW, with a footnote, by design).
- RECORDED, NOT FIXED: related domains that fail validation are still dropped
  at the API unreported (IR6-2; listing them would change the card and the
  dashboard only, since a rejected entry never makes the estate partial);
  /api/scan sets no request-size limit (the rest of IR6-4).

### Step 5 critique round 7 (2026-09-11)

A seventh critique (fifteen agents) upheld seven findings, one of them high,
refuted three, and left fourteen unverified; round 8 acted on them:

- S-4 AND S-5 READ CLEAN WHEN THE SPF LOOKUP FAILED (CL7-1, high). The
  email-vendor surface and the vendor-breach correlation write "no_data" both
  for a domain whose SPF record has no includes and for a lookup that timed
  out or failed, and the deck read both as clean, so round 6's claim that a
  slide with nothing assessed says so was still false through these two
  signals (and, round 8 found, through S-3 on a host that never answers,
  5af). Both checks now record whether the lookup answered (spf_lookup:
  answered or failed); the status, and so the price, is unchanged, and the
  deck credits "no_data" only when the lookup answered. (Round 8 found that
  this covered the domain's own lookup only, not one behind an include or a
  record that redirects, and that a stored result still read clean; round 9
  closed all three.) Whether a failed lookup should price as an error is a
  scoring decision, left open (5af).
- A MEDIUM VENDOR CROSS-CHECK READ CLEAN (ST7-2). The summary row now states
  it, in amber, and the dashboard's generic panels refine a completed
  checker's badge from its own severity and finding counts. (That still
  showed "Passed" beside findings held in fields the rule does not read;
  after round 8 a generic panel never shows "Passed".)
- INPUT (IR7-1, IR7-2, IR7-5). normalize_domain cut an address before the
  path, so a URL with an address in its query scanned the address's domain
  (a round-7 regression on the scan route); the path now goes first. The
  fixed point stops after eight passes, so a hostile value costs linear
  time (a 128 KB value had taken 10.6 s). The form's cleaner runs the same
  steps in the same order to the same fixed point.
- CERTIFICATE-TRANSPARENCY REPLIES (CL7-2, IR7-3). An entry must carry its
  names field, and the scan retries an empty crt.sh answer once. (Round 8
  found that this does not make the form and the report list the same
  domains: the pre-flight searches crt.sh alone, and in its own way, 5w.)
- WORDING (ST7-3, ST7-4, ST7-5, CL7-4, CL7-5, CL7-6). The manual states the
  TLS rule as the code runs it; the deck footer reads "Fully assessed:
  none." beside a partly assessed signal; the stored-result caveat no longer
  says every confirmed domain was assessed; the round-6 record's IR6-4 and
  partly-assessed sentences are corrected; the manual names the dashboard
  page that shows the vendor cross-check.
- GATE (GS7-1 to GS7-6, CL7-3). More than ten related domains through the API
  and the route's arguments by AST; every Hudson Rock status; the slide's
  pill and sub-line; one case per SSL error the checker records, beside every
  port probe that decides it; the form rendered in a stub DOM, and its
  cleaner and banner run under node; the panel mounted unconditionally;
  S-4/S-5 with the SPF lookup failed; an empty crt.sh answer followed by
  names; the generic panels' badge.
- REFUTED OR BY DESIGN: FC7-1 (a TLS alert with the ports unknown is left to
  the port probe), FC7-2 (a Windows socket error never reaches a report),
  ST7-1 and FC7-3 (a measured clean vendor join is an assessed signal).

### 5af. Supply-chain results that claim more than was measured (2026-09-11)

OPEN, recorded by critique round 8. Each predates step 5 or sits beside it, and
each is a checker's fidelity rather than discovery parity:

- **S-3 on a host that never answers (CD8-1).** DependencyManifestChecker
  records a probe's status only when HEAD returns a response, and its
  unreachable test needs at least one recorded status, so a web host that
  refuses or times out on every probe reports "completed" with score 100. The
  deck counts it as an assessed clean signal, so a slide with nothing measured
  can read LOW EXPOSURE and "a positive due-diligence result"; the technical
  card calls it the expected configuration, the summary row reads a plain
  "Clean", or "No finding on assessed signals" beside a related-domain note,
  and it prices as clean. S-2 on the same host returns
  an error. Fix: count a probe with no response, as
  InformationDisclosureChecker does since critique round 3, and report
  "unreachable" when no probe got an HTTP answer. That changes the price of
  every scan of such a host, so it needs a scoring decision and a re-baseline.
- **An SPF walk that found a vendor while another lookup failed. FIXED
  2026-09-12 (round 10).** S-4 and S-5 report from the vendors found when a
  lookup behind another include did not answer, or a record in the chain
  redirects. The walk now records spf_lookup "partial" on that completed
  result: the deck reads it as not fully assessed where the signal would
  otherwise be clean and states the lower bound beside a finding it carries,
  the summary row does not count it as a completed signal, and the dashboard
  says the chain was only partly read. A finding it carries still loads.
- **More than one v=spf1 record, and a chain wider than the walk (FC9-1, IR9-1,
  refuted in round 9 as out of scope).** _fetch_spf returns the first record it
  finds, and the walk reads ten includes per record to a depth of four. Two
  published records are an RFC 7208 permerror and a common misconfiguration,
  and the resolver's order then decides which is read, so S-4 and S-5 can read
  different records within one scan; a vendor past the tenth include is never
  seen. Both predate step 5: the critique's verifiers reproduced the same
  output, price and wording on the pre-step-5 tree, and no document claims
  otherwise. Fix: read every v=spf1 record, record more than one as a chain the
  walk cannot measure, and record a truncated walk as partial.
- **The vendor cross-check over unmeasured legs (FC8-5, ST8-3).** scanner.scan
  joins Hudson Rock with S-4's vendors and S-5's matches without reading
  whether either leg was measured. With a failed SPF lookup the join states
  "no SPF / breach overlap", and with only S-5's lookup failed it drops a
  CRITICAL join to HIGH, on the deck, the card, the summary row and the
  dashboard. Reporting only: the join does not price. Fix: carry spf_lookup
  into the join, say which leg was not assessed, and mark the severity as a
  lower bound.
- **Pricing an unmeasured vendor surface.** S-4/S-5 "no_data" prices as a
  completed result with no vendors (+0), whether the lookup answered, failed
  or was not followed. That is fail-closed (an absence never discounts), but
  whether an unmeasured vendor surface should price as an error is a scoring
  decision, left open.
- **The dashboard's own panels.** A page with its own panel for a checker (the
  Email Security page's authentication and hardening panels, for example) shows
  the "Passed" run marker for any completed checker, beside findings its rows
  state. The generic Additional Intelligence Sources panels no longer do (round
  9), and nor does the Email-Vendor panel, whose badge follows what the panel
  says (round 10). Fix: derive each page's header from its own verdict, as
  those two do.

### Step 5 critique round 8 (2026-09-11)

An eighth critique (fifteen agents) upheld nine findings, five of them high,
refuted one, and left seventeen unverified; round 9 acted on or recorded every
one:

- THE SPF FIX COVERED THE DOMAIN'S OWN LOOKUP ONLY (FC8-1, ST8-1, CD8-2, high;
  FC8-3). A lookup behind an include that timed out or failed was recorded and
  never read, and a record that delegates with redirect= (a hosted-SPF
  service's usual form, as on a retained fixture) was never followed yet
  certified "answered", so S-4 and S-5 read clean on the deck, the summary row
  and the cards while the vendors behind them were never looked up. Where no
  vendor is identified, both now write "no_data" with spf_lookup "failed" or
  "not_followed", which prices exactly as the completed result with no
  vendors did, and the deck reads either as not assessed. A walk that found a
  vendor is reported from the vendors found, as a lower bound (round 10 made
  the deck, the summary row and the dashboard say so).
- A STORED RESULT READ CLEAN (CD8-3). The deck credits "no_data" only when the
  lookup is recorded as answered, so a result stored before the field existed
  is not assessed, as a stored related-domains result is never clean. Each
  S-4/S-5 signal the deck cannot credit gives its reason in a sentence of its
  own rather than "no scan data".
- THE GENERIC PANELS STILL SAID "PASSED" (FC8-2, ST8-2, CD8-4, GS8-3). Round 7's
  rule reads severity and a few counts, which several of the generic panels'
  checkers do not carry (Hudson Rock, IntelX, information disclosure, CMS
  plugins, vendor breaches, credential risk), and a credential correlation
  marked assessed: false showed "Passed". A generic panel now shows the
  finding level its result states and otherwise a neutral "Completed", never
  "Passed"; assessed: false is Not assessed.
- THE EMAIL-VENDOR PANEL (FC8-4). It printed "None identified" and a green
  "Weak DMARC: No" for a lookup that failed. It now prints its rows only for a
  completed result, and otherwise says why it has none. A browser check in
  round 9 found that it also printed "[object Object]" for the vendors and
  SPF includes of every completed result (older than step 5: the checker
  stores both as objects). Its content now comes from one module,
  data/emailVendorPanel.ts, which the gate runs on the real checker's output.
- CLAIMS (CD8-1, CD8-5, CD8-6, ST8-4, ST8-5, IR8-2). The claim that a slide
  with nothing assessed says so is narrowed, in the manual, the changelog and
  the round-5 and round-7 records, to a slide on which no signal reported a
  result, because S-3 reports a result on a host that never answers (5af).
  The round-7 claim that the form and the report list the same domains is
  withdrawn (5w), and the form's empty result says it searched crt.sh alone.
  The changelog states the TLS rule's timed-out-connection exception. The
  stored-result caveat names both defects of the old check (no result, or the
  worst possible score, counted as a pass) on the card, the dashboard and the
  deck, and in the manual.
- INPUT (IR8-3, IR8-4). A round-8 regression: cutting the path before the
  address broke an address pasted with a display name containing "/" or "#"
  ("Accounts/Finance <accounts@...>"), on the scan route and in the form. The
  address inside the angle brackets is taken first, a chain of schemes
  (mailto://, https://http://) is removed in one step on both sides, and the
  form strips the server's whitespace set.
- GATE (GS8-1, GS8-2, GS8-3, GS8-5, GS8-6). The related domains reach the
  builder as validated, by AST over start_scan, _run_scan_job, run_scan and
  scan() (no rebinding, slicing, deletion or mutation, and a verbatim
  pass-through); mixed S-4/S-5 outcomes, a stored result, a nested failure, a
  redirect, and the price of every "no_data" outcome; the verdict pill's
  colour; real checker shapes for the generic badge, and CheckerHeader's
  routing; the Email-Vendor panel, run on the real checker's output; any way
  of ticking a box anywhere in the form's scripts; display-name and
  chained-scheme inputs.
- RECORDED (5af, 5w): S-3 on an unreachable host, an SPF walk that found a
  vendor beside a failed lookup, the vendor join over unmeasured legs (FC8-5,
  ST8-3), the pricing of an unmeasured vendor surface, the dashboard's own
  panels, and the pre-flight's crt.sh search (IR8-2, GS8-4).
- REFUTED OR BY DESIGN: IR8-1, and FC8-6 with it (an empty crt.sh answer is an
  answer: "degraded" means that no certificate source answered, and the
  pre-flight draws the same line).

### Step 5 critique round 9 (2026-09-12)

A ninth critique (fifteen agents) upheld six findings, three of them high,
refuted four, and left seventeen unverified; round 10 acted on or recorded
every one:

- THE REDIRECT GUARD WAS CASE-SENSITIVE (FC9-2, IR9-2, GS9-1, high; ST9-3).
  SPF mechanism and modifier names are case-insensitive (RFC 7208 s4.6.1), so
  "Redirect=" delegates exactly as "redirect=" does while round 9's guard read
  it as absent: the deck credited a vendor surface the walk never followed, and
  the dashboard stated that no includes are published. "Include:" and "V=SPF1"
  read the same way. The three patterns are now case-insensitive and match
  whole terms.
- A STORED COMPLETED RESULT WITH NO VENDOR READ CLEAN (ST9-2, FC9-3, high).
  Round 9 read a stored "no_data" as unverifiable, but the earlier check wrote
  "completed" with no vendors whenever a lookup behind an include failed or a
  record redirected, and that shape carries no record of the lookup either.
  Both checks now record the outcome on a completed result too ("answered", or
  "partial"), so a stored completed result that identified no vendor is read as
  not assessed on the deck, the cards, the summary row and the dashboard.
- A PARTIAL WALK READ CLEAN (CD9-1, ST9-4, medium; 5af's open bullet). Where
  the walk found a vendor beside a lookup that did not answer, or a record it
  does not follow, the vendors are a lower bound. The deck now reads that
  signal as not fully assessed where it would otherwise be clean, and states
  the lower bound beside a finding it did carry; the summary row does not count
  it as a completed signal; the dashboard says the chain was partly read.
- INPUT (IR9-3, FC9-4, IR9-4, IR9-5). Round 9's display-name step took a
  bracketed address anywhere, so a URL with an address in its query scanned the
  address's domain: it now applies only where the value is a display name and
  one address, which keeps round 7's rule that a URL's query is not the host.
  The related-domains box and the Enter-key submit path use the server's
  cleaner, so an entry the API would keep is no longer dropped unseen, and a
  value sent without a blur is the target the box shows.
- WORDING (ST9-6, CD9-3, CD9-4, CD9-5, CD9-6). The redirect reason names a
  record in the chain rather than the client's own record; the changelog states
  the TLS rule as the code runs it; the dashboard gives the stored-result
  reason; 5af's summary-row wording is corrected; 4.6.19's severity ladder is
  stated as the join computes it, and a MEDIUM join names the vendors that
  overlap.
- GATE (GS9-1 to GS9-6). Mixed-case records and a redirect behind an include; a
  vendor found beside a failed lookup, with its price; the deck rendered from
  the real checkers' output for every zone, so S-5's own outcomes are covered
  too; the verdict palette pinned to literal colours; the related-domains chain
  through the route into the builder by behaviour as well as by AST; the header
  badge and the Email-Vendor panel run under node on real checker output; the
  pre-flight run under a stub DOM, so a candidate ticked anywhere in it is
  caught, and the domain it asks about is the one the server would scan; the
  related-domains box compared with the API entry by entry; U+001D, U+001E and
  ftp:// in the cleaner parity list.
- REFUTED: FC9-1 and IR9-1 (two v=spf1 records, or an upper-case record, read
  the same before step 5: the first-record read predates it, now recorded in
  5af), ST9-1 (the summary row and the technical report have never stated a
  not-assessed signal's gap, the convention recorded in the round-3 record) and
  CD9-2 (the row's "Clean" comes from the signals that were assessed).

### Step 5 critique round 10 (2026-09-12)

A tenth critique (fifteen agents) upheld eight findings, five of them high,
refuted two, and left eleven unverified; round 11 acted on or recorded every
one:

- THE TECHNICAL REPORT DREW A CLEAN CARD FOR A PARTLY READ CHAIN (FC10-1,
  ST10-1, high; CD10-3). The deck, the summary row and the dashboard all read a
  partly read SPF chain as a lower bound, but neither card renderer consulted
  the rule, so the broker's most detailed surface drew a full green card whose
  wording asserted a clean vendor surface - byte-identical to the fully answered
  control. Both cards now consult it: never the clean colour, a row and a
  closing note saying part of the chain was never read, and the lower bound
  named in the summary line. The Vendor Breach card carries that note too, found
  while checking this round's own work: its matches are drawn from the vendors
  the chain named, so an include that was never read may be a breached vendor
  the card does not list.
- A STORED RESULT THAT NAMED A VENDOR READ CLEAN (FC10-2, ST10-2, CD10-1,
  high). Round 10 read a stored completed result as unverifiable only where it
  identified no vendor. The earlier check wrote the same shape - completed, a
  vendor, no record of the lookup - for a walk whose nested lookup did not
  answer, so a stored scan of that walk read as fully measured while the same
  DNS reality scanned today reads as a lower bound. A completed result with no
  recorded outcome that named a vendor is now a lower bound on every surface,
  and the audit's claim is true as written.
- AN OUTCOME THE RULE DOES NOT KNOW (FC10-3, medium). The completed branch
  credited any value that was not absent, while the no_data branch refused an
  unknown one - and 5af's own next fix will write exactly such a value. The
  completed branch is now an allow-list: "answered" and "partial" are credited,
  every other value renders not assessed, on the cards, the deck, the summary
  row and the dashboard.
- INPUT (IR10-1, IR10-3, IR10-4, IR10-5). Where a host precedes a bracketed
  address the host is the target on both surfaces, so "acme.co.za
  <info@brokerfirm.co.za>" scans the client and not the broker's firm. A
  backslash ends the authority, as every browser reads it. The form carries one
  cleaner: the collector's checkbox branch and the paste handler both call it.
  And a bracketed contact address beside a host in the related-domains box is a
  contact, not a related domain: the box split the line before cleaning and sent
  the contact's own domain into the client's supply-chain scope, where the API,
  cleaning the entry whole, keeps only the host. It could not discount a rate,
  but it put an uninvolved third party's exposure in the client's file.
- GATE (GS10-1 to GS10-5). The stub DOM types more than ten domains, so a
  browser-side cap bites; the header badge covers a partly read result that
  carries a finding and a stored result that named a vendor without one; the
  summary row's own text is asserted, including the case that renders only
  because a finding bumped it; a six-vendor surface is pinned as a finding on
  the deck and on the dashboard rather than derived from the threshold the code
  uses; the cards are asserted for the partial and stored-with-vendor shapes;
  the cleaner check matches the pattern rather than one spelling of it; and the
  related-domains token list carries a contact line. The zone case GS10-5 asked
  for (every lookup answered, no vendor identified) is present as
  includes_no_vendor.
- DOCUMENTS (CD10-2, CD10-4, CD10-5, ST10-3). 4.6.15 no longer says the summary
  table states a partly read chain: it says the table does not count it as a
  clean signal, which is what the row does. The vendor-pattern count is the 25
  the code carries, in the manual and on the deck's S-4 card, with Zoho and Okta
  named. The audit's S-5 row is re-derived from vendor_breaches.json as it
  stands: 11 rows, 7 vendors, six high, three medium and two critical, okta
  2022-01-20 as the nearest expiry, and 18 of the 25 detected vendors with no
  breach row.
- REFUTED: IR10-1 (round 10's host-like guard does decide three of the shapes at
  issue, and the gate already fails when it is removed; the residual path-free
  shape predates step 5, and is fixed in this round regardless) and IR10-2 (the
  form self-heals - the blur listener the reviewer's harness omitted re-runs the
  pre-flight and detaches the ticked boxes; the surviving variant renders
  identically on the committed pre-image, so it is not a step-5 defect).
