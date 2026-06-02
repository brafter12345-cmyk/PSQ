# Phishield Scanner — Parameter Calibration Prep (round-0)

# Parameter Calibration — Round-0 Prep & Session Handoff

**Date:** 2026-06-03
**Status:** **SANDBOX PREP — proposals only, nothing shipped.** Produced by 5 research-grounded calibration teams (each ran dev → expert → critic → orchestrator, with live SA + international breach-data research and validation-by-recompute against the fixed-code baseline `test_fixtures/phishield_live.json`). Final values are set in the dedicated calibration session with the colleague and must pass the 2-step gate before anything lands.
**Read with:** the FIN-9 pre-read (`credential_confidence_pbreach_design.md`), OUTSTANDING §6b, and the FIN-9 Pareto memory.

---

## 0. TWO correctness findings to fix BEFORE calibrating (not calibration — bugs)

The recompute surfaced two structural problems. Calibrating *around* them would waste the session.

### 0.1 ✅ The vulnerability curve was POLARITY-INVERTED — POLARITY FIXED 2026-06-03 (commit `1cc204d`); curve SHAPE still to calibrate
`scoring_analytics.py:2038` — `vulnerability = (100 − overall_score/10)/100`, commented *"0.0 (perfect) to 1.0 (worst)"*. The comment proves the formula expects a **posture/security score (higher = better)**. But **Wave 1 wired in `risk_score` (0–1000, higher = WORSE)**. Net effect: a **well-postured org gets a HIGH p_breach**.
- phishield **169 (Low risk)** → `vulnerability = 0.831` → **p_breach ≈ 0.36**. A low-risk org should be ~0.02–0.07.
- a hypothetical **900 (terrible)** → `vulnerability = 0.10` → low p_breach. Backwards.
- Pre-Wave-1 it was a harmless flat 0.5 (the 500 default sat at the midpoint); Wave 1 coupled it to the wrong-polarity input.
- **Fix (correctness, not calibration):** correct the polarity — e.g. `vulnerability = overall_score/1000` (linear, higher risk → higher vuln). **The SHAPE (linear vs the proposed convex `(score/1000)^k`, k≈1.8) is the calibration decision** — do that with the colleague. **After the fix, re-check the wiring verifier's hardcoded expected deltas** (they may have been set against the inverted curve).

### 0.2 🟠 The named cost/fine params are the DEAD USD path
`COST_PER_RECORD`, `REGULATORY_FINE`, and `est_records = revenue/50000` are **never reached** — the live ZAR path (`SA_INDUSTRY_COSTS` + the `_zar` logic, which floors ≥ R10M) is what runs. **Calibrate the live ZAR equivalents, not the dead USD constants** (and consider deleting the dead path so the next audit doesn't re-flag it). The live `SA_INDUSTRY_COSTS` table is already correct IBM-2025-ZAR.

---

## 1. Proposed values by group (current → proposed-range, confidence, open question)

| Group | Param | Current | Proposed (range) | Confidence | Key open question (colleague) |
|---|---|---|---|---|---|
| **p(breach) core** | vulnerability curve | inverted (see 0.1) | fix polarity; then convex `(score/1000)^k`, k **1.5–2.0** | dir=high, shape=med | which base rate — annual **loss-event (~1–3% SME)** or material-incident? (moves the constant 3–5×) |
| | the `0.3` | 0.3 | **retain 0.20–0.35** if convex curve; drop to ~0.06–0.10 only if linear | med | tied to the base-rate choice above |
| **credential → p(breach)** | K1 conf mults (hi/med/lo) | n/a | **1.0 / 0.4 / 0.1** | high | — |
| | K2 recency decay (<30d…>2yr) | n/a | 1.0/1.0/0.8/0.6/0.4/0.25 | med | — |
| | K3 combo discount | n/a | ×0.3 | med | **flat 0.3 wrong for fresh+combo** (ALIEN TXTBASE 2024-12 but combo) — make recency-aware? |
| | K4/K5 class + contribution | n/a | cutoffs 4/2/0.8/0.2; 100/70/35/10/0 ×0.03 | med | — |
| | `dehashed×2` | raw count | **replace** with the confidence class | high | — |
| | ladder caps (darkweb/paste) | uncapped | darkweb −40 (gated), paste −30 | high | — |
| **RSI factors** | RDP | +0.25 | **0.18–0.22** | high (dir) | confirm baseline RSI; **fix the credential count input first** (feeds HIGH +0.15) |
| | CRITICAL credential | +0.20 | **0.20–0.24 (≥ RDP)** | high (dir) | SA Sophos: creds 34% #1 > vuln 28% > email 22% |
| | DB-port / no-WAF / weak-SSL (surfaces) | 0.10 / 0.05 / 0.05 | trim 0.06–0.08 / 0.03–0.05 / 0.02–0.03 | med | RDP/DB are exposure *surfaces*, not root causes |
| **SA cost/fine/TEF** | ZAR per-record | (live table) | ~R1,880 Other / R2,992 FS | high | already correct (IBM-2025); annual refresh only |
| | regulatory fine (expected/P50) | flat 2%×turnover | **P(fine)×E[fine] ≈ R100k–250k**; hold R10M ceiling for cat view | med-high | **P(POPIA fine \| private-SME breach)** — empirically <5%, unpublished — compliance-officer call |
| | TEF (SA) | Gov 1.35, Comms 1.05 | Gov **1.40–1.50**, Comms **1.20–1.30** (SA inverts global) | med-high | — |
| **tail / Pareto (FIN-9)** | Pareto alpha | n/a | **1.5–2.0** (EVT 1.77 anchor) | needs-colleague | Q-A per-org LGB alpha vs MOVEit |
| | LGB mixture weight | n/a | **0.25–0.35** | needs-colleague | Q-E confirm Pareto-mixture on SC-slice |
| | SC-vectored fraction f_sc | n/a | **0.12** (IBM CoDB) | med-high | Q-C 12% strict vs 20% |
| | K_TAIL | 1.20 | **hold** (epistemic/WAF — keep separate from FIN-9) | n/a | — |

**Recompute sanity (with proposed values, on phishield):** p_breach 0.36 → ~0.018 (after polarity + convex); credential class → LOW (was HIGH; the "12 darkweb mentions" were low-confidence Slow-dom/History noise — de-escalation is correct); RSI rebalance net-neutral on the headline but fixes the RDP-alone > critical-credential-alone inversion; tail lifts 1-in-250 +18–50% with the median <2% (no double-count, ordering preserved).

## 2. The iterative loop — for the dedicated calibration session (NOT this session)

1. **Item 0.1 (polarity) is already fixed** (`1cc204d`, linear placeholder; verifier passed unchanged) — **calibrate its SHAPE** (linear vs convex k≈1.8) here. **Fix item 0.2 (dead USD path)** still to do.
2. **Decide the p(breach) base rate** (the single highest-leverage choice — §1 row 1).
3. Set, in order: vulnerability curve shape → the `0.3` → credential class (K1–K7) → RSI rebalance → SA fine expected-value → TEF → **tail/Pareto with the colleague** (their domain).
4. **Overall-outcome panel:** map the *combined* calibration to real-world SA loss benchmarks (IBM SA R44.1M, Coveware ransom distributions, the return-period ladder) and the peer pool; iterate until the headline ZAR + 1-in-100/200/250 land defensibly.
5. **Gate:** `verify_supply_chain_financial_wiring.py` (re-baselined) + `verify_scan_smoke.py`; present per-checker p_breach deltas; colleague sign-off; THEN ship (both remotes).

## 3. Honesty / limits
SA-specific actuarial breach data is genuinely sparse — cost-per-record and the statutory ceiling are well-anchored; the **p(breach) base rate, the combo-recency interaction, P(POPIA fine), and the entire tail shape are the genuinely-unresolved inputs** that need the colleague's international breach-cost judgement. Ranges are given, not false precision. Per-group detail + sources are in `01_p_breach_core.md` … `05_tail_pareto.md`.


---

# Calibration Prep 01 — p(breach) core

**Parameter group:** the posture→probability curve (`vulnerability`) and the `0.3`
multiplier in `p_breach = vulnerability × TEF × 0.3`.
**Status:** SANDBOX PREP — *proposed* values for the 2026-06-03 calibration session.
**NOT applied to production.** No edits made to `scoring_analytics.py`.
**Author:** calibration team (dev / domain-expert / critic / orchestrator roles).

---

## TL;DR

There are **two** issues, not one:

1. **CORRECTNESS (headline, not calibration):** the current curve is **inverted**.
   `vulnerability = (100 − _overall_score/10)/100` assumes the score rises as posture
   *improves*. But `_overall_score` is **0–1000 where HIGHER = WORSE** (`scoring_analytics.py`
   L807: `Critical if risk_score >= 600 … Low` below 200). So a **good** org (phishield,
   169 = Low) is assigned `vulnerability = 0.831` and a **terrible** org (900) is assigned
   `0.10`. The curve is **backwards**. This must be fixed before any calibration of the
   constant is meaningful — and it is a *bug*, so it is arguably not gated by the
   "scoring-change = calibration-gated" rule, but is in-scope here because it lives on the
   exact line we were asked to calibrate.

2. **CALIBRATION (the actual ask):** even once corrected, the *shape* (linear vs convex)
   and the `0.3` constant set the absolute p(breach). Anchored to BitSight / Cyentia /
   SecurityScorecard loss-event base rates, a **convex curve `(score/1000)^k` with k≈1.8
   and the existing `0.3` retained** reproduces sane absolute values (good org ≈ 1.8 %/yr,
   weak org ≈ 26 %/yr).

---

## Parameter table

| Param | Current | Proposed (range) | Confidence | Empirical anchor (sources) | Recompute result | Open question for colleague |
|---|---|---|---|---|---|---|
| `vulnerability` curve | `(100 − score/10)/100` — **inverted**: good org→0.831, worst org→0.10 | **Correct the direction + make convex:** `vulnerability = (score/1000)**k`, **k = 1.8** (range **1.5–2.0**) | **Direction fix: data-supported (high).** Convexity & k: **reasoned-extrapolation (medium)** | Score direction confirmed in code (L807). Convex shape matches **SecurityScorecard** relative ladder A=1.0 / B=2.9× / C=5.4× / D=9.2× / **F=13.8×** (steeply convex). **BitSight/Marsh** absolute: rating ≥700→**<1%**, <500→**~3%** annual. | phishield 169(Low): **0.831 → 0.041** vuln. Monotonic ↑ with worse posture, bounded [0,1] (verified k∈{1.5,1.8,2.0}). | Is convex `(s/1000)^1.8` the right shape, or do you prefer a logistic/piecewise mapping pinned to the four risk bands (Low/Med/High/Crit)? |
| `0.3` multiplier | `0.3` | **Retain 0.3** (range **0.20–0.35**) — **conditional on adopting the convex curve.** If a *linear* curve is chosen instead, drop to **~0.06–0.10**. | **Conditional (medium).** Data sets the *output* range; the constant is the free scalar to hit it | IBM CoDB **SA $2.37M** (loss model anchor); **Cyentia IRIS**: SMB loss-event **<2%/yr**, F1000 ~25%/yr; SA survey "any attack" 40–50% (*attempt*, not loss — do **not** anchor here). | With convex k=1.8 & 0.3: good=**1.8%**, Medium=**5.0%**, High=**10.3%**, Critical=**20%**, worst=**36%** (TEF=1.45). Brackets the 1–3% strong/weak band + leaves a defensible tail. | Anchor p(breach) to the **loss-event** base rate (1–3% SME, my assumption) or to a broader "material incident" rate? This single choice moves the constant ~3–5×. |

---

## Recompute detail (throwaway python, no production edit)

Score scale **0–1000, higher = worse** (bands: <200 Low, 200–399 Med, 400–599 High, ≥600 Critical).
TEF = 1.45 (Financial Services, phishield's industry).

**Current formula (inverted) vs proposed convex `(s/1000)^1.8 × TEF × 0.3`:**

| Posture | score | CURRENT p_breach | PROPOSED p_breach | Empirical target (annual loss-event) |
|---|---|---|---|---|
| excellent | 50 | 0.391 | **0.002** | ≪1% |
| **phishield (Low/good)** | **169** | **0.361** | **0.018** | <1–2% (BitSight strong / Cyentia SMB) |
| Medium | 300 | 0.304 | **0.050** | ~3–5% |
| High | 450 | 0.239 | **0.103** | ~5–10% |
| Critical | 650 | 0.152 | **0.200** | ~15–25% |
| worst | 900 | 0.043 | **0.360** | tail / weak-posture upper bound |

**Note the inversion in the CURRENT column:** p_breach *falls* as posture worsens
(0.391 at score 50 → 0.043 at score 900). The proposed column is correctly **monotonic
increasing** and bounded [0,1] (asserted over s = 0…1000 for k = 1.5/1.8/2.0).

Worked single-line check for phishield (169, Financial Services):
- Current: `vuln=(100−16.9)/100=0.831 → 0.831×1.45×0.3 = 0.3615` (matches the live fixture
  `probability_drivers.p_breach = 0.3615` — confirms the formula as wired).
- Proposed: `vuln=(169/1000)^1.8=0.041 → 0.041×1.45×0.3 = 0.018`.

---

## Rationale & honesty labelling

- **The base-rate distinction is the crux.** SA SME "experienced a cyber attack" surveys
  read **40–50%/yr** (Mastercard, UK Gov Cyber Security Breaches Survey, MySecurityMarketplace).
  But those count *attempts/attacks*. The scanner's `p_breach` feeds a **loss** model
  (IBM-anchored ZAR), so it must anchor to the **material breach / loss-event** rate, which
  Cyentia IRIS puts at **<2%/yr for SMBs** (and ~25% for Fortune-1000). BitSight/Marsh give
  the posture-conditioned version: **<1% strong, ~3% weak**. The proposed curve targets
  this lower, loss-relevant band. *(data-supported)*

- **Why convex, not linear.** SecurityScorecard's empirically-fit ladder (A→F = 1.0→13.8×)
  is strongly convex: risk barely moves across the top grades then accelerates at the bottom.
  A convex `(s/1000)^k` reproduces "a Low org is genuinely safe; risk bites hard only as you
  slide toward Critical." Linear over-penalises mid-posture orgs. *(reasoned-extrapolation —
  the 13.8× spread is data; mapping it onto our 0–1000 scale via a single exponent is a
  modelling choice.)*

- **Why keep 0.3.** With the convex curve, 0.3 already lands the outputs on the empirical
  band, so changing both the curve *and* the constant would be over-fitting two knobs to one
  target. If the room prefers a **linear** curve instead, the constant must fall to ~0.06–0.10
  to avoid a 36% p_breach for a merely-average org. *(conditional)*

- **Ranges, not false precision.** k = **1.5–2.0** and C = **0.20–0.35** are the defensible
  bands; k=1.8 / C=0.3 is the central recommendation. The absolute SME loss-event rate
  (~1–3%) is itself a thin, triangulated number — **needs-colleague** confirmation of which
  base rate (loss-event vs material-incident) we are underwriting to.

- **Interaction note (out of our group but flagged):** the `sc_vuln_uplift` (≤+0.15) and the
  per-industry **TEF** (≤1.45) both multiply/add *after* the curve. Under the current inverted
  curve they were stacking on an already-near-1.0 vulnerability and getting clipped; under the
  corrected convex curve they will have real headroom and behave very differently. The TEF team
  and SC-uplift owners should re-check their magnitudes **against the corrected curve**, not the
  current one.

---

## Sources

- **Cyentia Institute — Information Risk Insights Study (IRIS):** F1000 ~1-in-4/yr loss event;
  SMB loss-event rate **<2%/yr**. https://www.cyentia.com/iris/
- **BitSight / Marsh McLennan correlation study:** rating ≥700 → breach probability **<1%**;
  rating <500 → **~3%**.
  https://www.bitsight.com/blog/these-14-cybersecurity-analytics-can-help-you-make-better-cyber-insurance-decisions
- **SecurityScorecard Scoring 3.0 — Breach Likelihood ladder:** A=1.0, B=2.9×, C=5.4×, D=9.2×,
  **F=13.8×** (relative).
  https://support.securityscorecard.com/hc/en-us/articles/22601556325147-A-Closer-Look-at-Scoring-3-0-Vocabulary-and-Breach-Likelihood
- **IBM Cost of a Data Breach 2025 — South Africa:** average breach **$2.37M** (down from $2.78M).
  https://www.ibm.com/reports/data-breach  ·  https://mea.newsroom.ibm.com/codb-me-findings-2025
- **Sophos State of Ransomware in South Africa 2025:** 60% encryption rate (vs 50% global);
  median ransom demand R17M; recovery ~R23M.
  https://assets.sophos.com/X24WTUEQ/at/tsspfmkhgxkbm4w6r7h/sophos-state-of-ransomware-in-south-africa-2025.pdf
- **South Africa Information Regulator (POPIA):** FY2024/25 **2,374** security-compromise
  notifications (~198/mo); 2025 running at ~284/mo (+40%). (denominator unknown — frequency
  context only, not a per-org rate)
  https://www.itweb.co.za/article/inforeg-exposes-popia-violators-as-data-breaches-mount/kLgB17ezby5M59N4
- **SA / global SME "attacked" surveys (attempt-rate, NOT loss-rate — context only):** ~40–50%/yr.
  Mastercard (46%), UK Gov Cyber Security Breaches Survey 2025 (50% small / 70% medium identify
  breaches/attacks). https://www.mastercard.com/us/en/news-and-trends/stories/2025/small-business-cybersecurity-study.html

---

## Pre-session checklist for the colleague

1. **Confirm the inversion fix** (good org should get LOW vulnerability) — this is a bug, get
   explicit sign-off to correct the direction.
2. **Pick the base rate we underwrite to:** loss-event (~1–3% SME) vs material-incident
   (higher). Sets whether C stays 0.3 (convex) or drops.
3. **Pick the curve family:** convex `(s/1000)^k` (k≈1.8) vs band-pinned piecewise vs logistic.
4. Re-validate TEF and `sc_vuln_uplift` magnitudes **against the corrected curve** (they were
   tuned against the broken one).


---

# Calibration prep — credential signals → p(breach) / RSI (param group 02)

**For:** FIN-9 / 5L calibration session, 2026-06-03 (with colleague — international breach-cost experience)
**Status:** SANDBOX — research-grounded **PROPOSED** values + ranges, NOT final. **No production code edited.** Proposals only.
**Relates to:** `docs/credential_confidence_pbreach_design.md` (the K1–K7 plan), `OUTSTANDING.md` §5 (5L), §6 ("Credential-risk scoring calibration" ticket), §6b (FIN-9 inputs).
**Recompute basis:** `test_fixtures/phishield_live.json` (fixed-code baseline; 13 DeHashed records, 2 plaintext pw, 6 enriched sources, 40 IntelX results / 12 "darkweb").

---

## 0. The problem this group fixes (one paragraph)

Three credential paths into the score are **confidence-blind**:
1. **p(breach)** gets `dehashed_risk = min(100, total_entries × 2)` (weight `0.03`, `scoring_analytics.py` L677/L769) → `_overall_score` → `vulnerability` → `p_breach = vulnerability × TEF × 0.3` (L2107). 13 stale email-only appearances move p(breach) **exactly as hard as** 13 fresh passwords.
2. **RSI** gets `credential_risk.risk_level` → `+0.20/+0.15/+0.08` (L1028–1039) — graduated, but the *level* itself is set by a confidence-blind ladder.
3. The `CredentialRiskClassifier` ladder (`checkers_threats.py` L1839+) deducts **darkweb ×−10/mention and paste ×−3 UNCAPPED** — 12 darkweb mentions = −120, flooring the 0–100 score to 0, and can out-deduct Hudson Rock's flat −50 even when HR is the stronger signal.

**The phishield fixture is the textbook failure case:** its HIGH level + floored-to-0 score is driven by "12 darkweb mentions" that, on inspection of `intelx.recent_results`, are **entirely `Slow-dom-*.txt` aggregated-domain indexes and `History/` browser-visit records — NOT one `Passwords.txt`/`Autofill` capture.** Hudson Rock shows **0 infected employees**. So the signal escalating phishield is low-confidence and mostly old, yet it scores like an active compromise.

---

## 1. Empirical anchors (what the numbers are pinned to)

| Anchor | Figure | Pins |
|---|---|---|
| **Verizon DBIR 2025** | Stolen creds = **22%** of breaches (**#1** initial-access vector); **30%** managed / **46%** unmanaged infostealer-log devices carry corporate creds; 88% of basic web-app attacks use stolen creds | K1 (capture is real & common), K5 base rate |
| **Mandiant M-Trends 2025** | Stolen creds = **#2** vector at **16%** (up from 10%); **exploits #1 at 33%** | Ceiling discipline — creds must NOT out-rotate p(breach) past exploit/RDP/KEV channels |
| **IBM CoDB 2024** | Compromised creds = **16%** of breaches; **292-day** dwell (longest of any vector); **$4.81M** (costliest) | K2 recency decay (long dwell ⇒ slow decay, not a cliff), severity context |
| **Sophos SA 2025** | Compromised creds = **#1 root cause, 34%** (already cited in RSI code) | **Local** anchor — sets the CRITICAL top class |
| **SpyCloud "New Age of Combolists" / 2025–26 Identity Exposure** | Old breach compilations **1–2% still valid**; fresh infostealer ULP **30–60% valid** (samples 60/46/38%), curated combos **up to 98%**; reuse **42% corporate / 65% consumer**; **⅓** of ransomware orgs had an infostealer infection in the **preceding 16 weeks (~112d)** | **K1 high:low ratio (~15–50×)**, **K2 decay shape**, **K3 combo discount** |

**Cross-check (anti-double-count):** the resulting *absolute* p(breach) for a CRITICAL-credential org must sit sensibly vs the industry base rate already in TEF — not double whole-industry frequency off one signal. Because this channel is **weight 0.03 on a 0–100 slot**, even a max contribution (100) moves the posture score only ~3 points, so the cap risk is modest — but RSI (+0.20) is the louder lever and is where over-rotation would bite.

---

## 2. Proposed values

> Multiplier model (per credential record / leak mention):
> **`w = K1[confidence] × K2[recency_band] × (K3 if combo-source)`**, summed to `W`; `W` → class via **K4**; class → contributions via **K5** (p(breach) 0–100 slot) and the existing RSI ladder. Low-confidence records contribute per **K7**.

| # | Param | Current | **Proposed (range)** | Conf. | Anchor | Recompute (phishield) | Open question |
|---|---|---|---|---|---|---|---|
| **K1** | Confidence multipliers high / med / low | none (blind) | **1.0 / 0.4 / 0.1** (low 0.05–0.15; med 0.3–0.5) | **data-supported** | SpyCloud: fresh-valid 30–60% vs old-valid 1–2% ⇒ high:low ≈ 15–50×; 0.1 low sits mid-band | high=ALIEN TXTBASE pw records; all 11 others low | Is low=0.1 already too generous given 1–2% validity? Could go 0.05 |
| **K2** | Recency decay per band (<30d…>2yr) | none | **<30d 1.0 / 30–90d 1.0 / 90–180d 0.8 / 180–360d 0.6 / 1–2yr 0.4 / >2yr 0.25** (>2yr floor 0.2–0.3) | **reasoned** (anchored) | IBM 292-d dwell ⇒ no fast cliff; SpyCloud 16-wk infostealer→ransomware ⇒ full weight to ~90d | phishield sources mostly >2yr (Apollo'18, Canva'19, Nitro'20) → heavy decay | Plateau to 90d or start decay at 30d? Colleague call |
| **K3** | Combo-list discount (×) | none | **×0.3** (0.25–0.4) | **reasoned** | SpyCloud: combos *can* be fresh (up to 98%) BUT only with infostealer provenance; default-discount the re-circulated case | ALIEN TXTBASE, Apollo, SocRadar all combo → pw records 0.12 each | ALIEN TXTBASE is dated 2024-12 (recent) **and** combo — does fresh+combo deserve less discount? **(biggest tension below)** |
| **K4** | Class thresholds on `W` (CRIT/HIGH/MED/LOW) | n/a | **CRIT ≥4 / HIGH ≥2 / MED ≥0.8 / LOW ≥0.2 / else NONE** | **reasoned** | Tuned so 5 fresh password captures→CRIT; 13 old email-only combos→NONE; Sophos SA 34% = top class = "active compromise" | **phishield W=0.59 → LOW** (was HIGH) | A *single* fresh password capture lands MEDIUM (W=1.0) — should it be HIGH? |
| **K5** | Class → p(breach) contribution (0–100 slot, ×0.03) | `dehashed_total×2`, cap 100 | **CRIT 100 / HIGH 70 / MED 35 / LOW 10 / NONE 0** | **reasoned** | Same 0–100 scale as the slot it replaces; graduated like RSI | **phishield 10** (was 26) → posture delta 0.30 pt (was 0.78) | Keep on 0.03 slot, or promote to a small direct vulnerability uplift like the SC channel? |
| **K6** | Contribution cap | 100 (implicit) | **100** (keep) | data-supported | One channel at weight 0.03 can't dominate; cap already non-binding | n/a | Only revisit if K5 is promoted off the 0.03 slot |
| **K7** | Low-confidence-fresh floor into p(breach) | n/a | **0** (no monitoring floor in the *score*; surface in *report* only) | **reasoned** | A fresh `History/` visit ≠ raised breach probability; export disclaimer already says "monitoring, not theft" | phishield IntelX mentions (all low-conf) → **0** contribution ✓ | Tiny ε (e.g. LOW floor 5) on *content-fetch-confirmed* fresh dumps only? |
| **L1** | Ladder cap — darkweb deduction | ×−10/mention, **uncapped** | **cap −40** (≈4 mentions) **+ confidence-gate** (only `media==13`/stealer-token paths count) | **reasoned** | §6 ticket; mention-count ≠ credential count; aggregated-index spam shouldn't floor the score | 12 mentions: −120→ capped −40, and most are low-conf so largely excluded | Cap level −30 vs −40? |
| **L2** | Ladder cap — paste deduction | ×−3/paste (>3), **uncapped** | **cap −30** | **reasoned** | §6 ticket symmetry | phishield paste=0, no effect | — |
| **L3** | HR CRITICAL date-gate (preserve as hard floor) | `hr_employees>0` ⇒ CRITICAL always | **HR ≥1 infected employee ⇒ CRITICAL floor**, but **stale infection (days_since > 180–365) ⇒ HIGH** via `days_since_compromise` | **reasoned** | §6 ticket; correlation already date-anchors (`active_theft_fresh` ≤90d). HR is a *confirmed* infection ⇒ must stay a class floor regardless of `W` | phishield HR=0 → no trigger (so de-escalation is safe here) | Stale-cliff at 180d or 365d? |

### Hard floors that survive the weighted sum (no-double-count safe)
- **A confirmed live infostealer infection (Hudson Rock employee, recent) hard-sets CRITICAL** regardless of `W`. The weighted sum governs the *DeHashed/IntelX* corpus; it must never *down*-grade a real infection. (phishield HR=0, so this floor is dormant and the de-escalation to LOW is correct.)
- **`credential_correlation` stays reporting-only** — what is promoted is the *class*, not the correlation card (design §6).
- **Replace, don't stack** `dehashed_total×2`. HIBP `breach_count` scenario path (L1664) is **out of scope for this group** → Q3.

---

## 3. Recompute result (phishield_live.json, today=2026-06-02)

Per-record weighting (faithful to fixture `breach_details` + `enriched_sources`):

| Channel | Detail | Current | **Proposed** |
|---|---|---|---|
| DeHashed weighted sum | 2× ALIEN TXTBASE high+combo+1–2yr (0.12 ea) + 11× low old (Apollo/Canva/Nitro/SocRadar/BvD) | — | **W=0.59** |
| IntelX mentions | 10 sampled: all `Slow-dom`/`History`/unspecified = **low confidence** → 0 under K7=0 | drives HIGH + score→0 | **W=0.0** |
| **Credential class** | | **HIGH** | **LOW** |
| **p(breach) contribution** (0–100, ×0.03) | | **26** (`13×2`) | **10** → posture delta 0.78pt → **0.30pt** |
| **RSI factor** | | **+0.15** (HIGH) | **+0.0** (LOW) |

**De-escalation is the correct call here:** every password-bearing record is in a combo source dated ≥2019 (`ALIEN TXTBASE` is 2024-12 but combo), Hudson Rock shows **zero** active infections, and the "darkweb" volume is aggregated-index/browser-history noise. Current scoring treats this as active-compromise HIGH; the proposed model reads it as historical LOW.

### Counterfactual checks (model behaves)
- **Remove the 2 plaintext passwords** (pure old email-only): W=0.37 → still **LOW**. ✓ (volume of old email-only doesn't manufacture risk)
- **Archetype A — 5 fresh (<30d) `Passwords.txt`, non-combo:** W=5.0 → **CRITICAL**. ✓
- **Archetype C — 3 hashed, 90–180d, non-combo:** W=0.96 → **MEDIUM**. ✓
- **Archetype E — 13 old email-only combo:** W=0.10 → **NONE**. ✓
- **Archetype F — 1 fresh email-only aggregated index:** W=0.10 → **NONE**. ✓ **(confirms a low-confidence/old — and even low-confidence/fresh — exposure does NOT spike p(breach), the core 5L requirement)**

---

## 4. Biggest open questions (for the colleague)

- **Q-A (the tension): fresh + combo.** ALIEN TXTBASE is dated 2024-12 (recent) **and** a combo source, and it is where phishield's only real passwords sit. K3=0.3 currently discounts it to 0.12/record. SpyCloud says curated combos can be 98% valid — so a *recent* combo with infostealer provenance may deserve **less** discount than a re-circulated 2019 dump. **Proposal to debate:** make K3 recency-aware (full discount only when the combo's own date is >1yr; near-1.0 when <90d). This is the single knob most likely to be wrong as a flat 0.3.
- **Q-B: single fresh password capture = MEDIUM or HIGH?** Under K4, one fresh `Passwords.txt` (W=1.0) → MEDIUM. One confirmed fresh corporate credential is arguably HIGH. Lower the HIGH threshold to ~1.0, or add "≥1 high-confidence fresh record ⇒ min HIGH" floor?
- **Q-C (Q3 from design): HIBP `breach_count` scenario p(breach) (L1664)** — fold into this class or leave separate? (Out of scope for *this* recompute; flagged.)
- **Q-D: K5 placement** — keep on the 0.03-weighted posture slot (small absolute p_breach effect), or promote to a direct vulnerability uplift like the supply-chain channel (`sc_vuln_uplift`)? Affects whether the magnitude is meaningful at all.

## 5. Honesty / confidence labels
- **data-supported:** K1 ratio band, K6 (multiplier vs validity %; cap non-binding).
- **reasoned (anchored, needs sign-off):** K2 shape, K3 level, K4 thresholds, K5 mapping, K7, L1–L3. Tuned against archetypes + anchors, not intuited, but the exact cutpoints are judgment.
- **needs-colleague:** Q-A (fresh+combo), Q-B (single-capture class), Q-D (slot vs uplift).
- Ranges are given, not false precision. No production constant changed.

## 6. Verification gate (after numbers are set — NOT done here)
1. `py tooling/verify_supply_chain_financial_wiring.py` (expect 31/31).
2. `py tooling/verify_scan_smoke.py` (exit 0 — scan-path/scoring change).
3. Present per-checker p(breach) deltas (phishield + a high-confidence reference) + AskUserQuestion vs §1 anchors; iterate K1–K7 until calibrated.
4. Only then commit + push (both remotes) → Render.


---

# RSI Factor Weights — Calibration Prep (PROPOSED, not final)

**Parameter group:** Ransomware Susceptibility Index (RSI) additive factor weights + base + band mapping.
**Code:** `scoring_analytics.py` class `RansomwareIndex.calculate()` (L1001-1306).
**Status:** SANDBOX PREP for the 2026-06-03 calibration session. **No production code edited.** All values below are research-grounded *proposals* for discussion, with confidence tags and recompute evidence.
**Date:** 2026-06-02.

---

## TL;DR (read this first)

The current model's **single largest factor is `RDP exposed +0.25`**, justified in-code as "the #1 ransomware vector." The 2026 evidence — **and especially the SA-specific cut** — does not support RDP being the single biggest *root cause*. It supports a **credentials ≈ vuln-exploit > email** ordering, with **RDP/remote-access being an *exposure surface* through which the credential and vuln channels are realised** (CISA: RDP compromise is *achieved via* brute-force, stolen creds, or VPN-software exploits — it is not an independent root cause).

**Headline proposal:** rebalance so the **dominant root cause (credentials) is at least as heavy as RDP**, trim RDP from +0.25 to a still-strong **+0.18–0.22** (it remains a confirmed observable, which earns a premium over a probabilistic signal), and lift the top credential tier so CRITICAL credentials ≥ RDP. Recompute shows bands stay sane: Phishield stays **Medium (~0.45–0.49)**, worst-case primary stacks stay **Critical (~0.84)**.

---

## Empirical anchors — initial-access vectors, SA-prioritised

| Source (year) | Vector shares relevant to RSI | Note |
|---|---|---|
| **Sophos State of Ransomware in *South Africa* 2025** (primary SA anchor) | **Compromised credentials 34% (#1)** · **Exploited vulnerabilities 28% (#2)** · **Malicious email 22% (#3)** | 150+ SA orgs. Also: 58% cite "lack of expertise", 53% "unknown defence weakness" as operational root cause → supports a non-zero base + size multiplier. |
| **Mandiant M-Trends 2025 — *ransomware-specific* intrusions** | **Brute-force #1** (incl. RDP login attempts, VPN default creds, password spraying) · **stolen credentials 21% & exploits 21% (tied #2)** · prior compromise 15% · third-party 10% | "Brute-force #1" = the RDP/remote-access *surface*; its payload is credential abuse. Creds + exploits co-dominant. |
| **Mandiant M-Trends 2025 — all intrusions** | Exploits 33% (#1) · stolen credentials 16% (#2) | Generic, not ransomware-only. |
| **Verizon DBIR 2025** | Stolen credentials = #1 initial-access (22%) · vuln-exploitation **+34% YoY** (edge/VPN devices) · **54% of ransomware victims had prior infostealer credential exposure** | Strong support for heavy credential weight + the credential↔infostealer link the scanner already models. |
| **Coveware Q4 2024** | Phishing #1; remote-access compromise rising fast at #2 (VPN vulns + stolen creds + brute force); software-vuln & insider declining | No public per-vector %; remote-access "often initiated through phishing" → overlap, not independence. |
| **CISA #StopRansomware** | RDP/exposed remote services = top-tier initial access, but achieved *via* brute-force / compromised creds / VPN-software exploit | Confirms RDP is a **surface that overlaps** the credential + vuln channels — central to the no-double-count argument. |
| **Patchstack State of WordPress 2024** | 96% of WP CVEs in plugins; **11.6% actively exploited / expected**; 33% unpatched at disclosure | Validates the existing S-10 CMS factor sizing (small, version-readability-gated). |

**Synthesised relative ordering (named vectors, SA-weighted):** Credentials **40%** ≳ Vuln-exploit **33%** > Email **26%**. RDP/remote-access and DB-port exposure are *surfaces* feeding the credential + vuln channels, so they earn an **observability premium** but must not be summed as if independent of them (double-count risk).

---

## Proposed factor table

| Factor | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute / effect | Open question |
|---|---|---|---|---|---|---|
| **RDP (3389) exposed** | +0.25 | **+0.18–0.22** | Reasoned | M-Trends (brute-force #1 but = surface); CISA (RDP via creds/brute/vuln, not independent root cause) | Worst-case stack 0.84→0.84 (diminishing absorbs the trim). Removes the "RDP-alone (0.345) > CRITICAL-cred-alone (0.287)" inversion. | Keep a premium for being a *confirmed observable* vs probabilistic credential risk — how big? 0.20 is the proposed midpoint. |
| **Credential CRITICAL** | +0.20 | **+0.20–0.24** | Data-supported | SA 34% #1; DBIR creds #1; M-Trends creds 21% (tied) | CRITICAL-cred-alone 0.287→up to ~0.32; ensures #1 root cause ≥ RDP surface. | Depends on credential team confirming CRITICAL = genuinely active (infostealer/real-time). |
| **Credential HIGH** | +0.15 | **+0.15–0.18** | Data-supported | As above; HIGH = recent breach w/ passwords or dark-web trade | Phishield 0.451→**0.489** at 0.18 (still Medium). | **Input-integrity flag (see §Double-count):** HIGH is fed by the credential card's count-vs-boolean bug — fix the *input* before lifting the *weight*. |
| **Credential MEDIUM** | +0.08 | **+0.06–0.08** | Reasoned | MEDIUM = historical/email-only → weakest cred tier | negligible | Should email-only historical exposure contribute to a *ransomware* index at all, or only to DBI? |
| **Exposed DB port (each)** | +0.10, cap 0.20 | **+0.06–0.08 each, cap 0.16** | Reasoned | DB-port = exposure surface, not a named ransomware root cause; overlaps RDP/remote-access narrative | Phishield: trimming 0.10→0.08 offsets the credential lift to net ~0.451. | Is an exposed managed DB (e.g. takealot RDS) materially a *ransomware* vector or a *data-breach* one? Lean: weight more in DBI. |
| **CISA KEV CVE (each)** | +0.08, cap 0.20 | **+0.08–0.10 each, cap 0.20–0.24** | Data-supported | Vuln-exploit = 28% SA / 21% M-Trends ransomware / +34% DBIR YoY; KEV = confirmed exploited | Lifts the vuln channel toward parity with credentials (empirically co-dominant). | Combined vuln cap (KEV+EPSS+other = 0.40) already ≈ credentials; is per-CVE or the cap the right lever? |
| **High-EPSS CVE (>0.5, each)** | +0.04, cap 0.12 | **+0.04, cap 0.12** (hold) | Reasoned | EPSS = probabilistic, below KEV | unchanged | — |
| **Other crit/high CVE (each)** | +0.02, cap 0.08 | **+0.02, cap 0.08** (hold) | Reasoned | Unconfirmed exploitability | unchanged | — |
| **No DMARC** | +0.08 | **+0.07–0.09** (hold ~0.08) | Data-supported | Email 22% SA (#3); CISA BOD 18-01: p=reject cuts inbox-success 69%→14% | unchanged | — |
| **DMARC policy = none** | +0.05 | **+0.05** (hold) | Reasoned | Partial enforcement | unchanged | — |
| **No WAF** | +0.05 | **+0.03–0.05** | Reasoned / weak | WAF absence is a hygiene proxy, not a named ransomware vector | Phishield: trim to 0.04 helps net the credential lift. | **Back-test Theme-1 caveat:** WAF *detection* itself has false-positive bugs (F5 off `x-frame-options`) — the *input* may be unreliable; don't over-weight. |
| **Weak SSL (D/E/F)** | +0.05 | **+0.02–0.03** | Reasoned / weak | Weak TLS is rarely the ransomware entry vector; mostly hygiene/MITM | minor | Candidate to drop from RSI entirely and keep only in posture/DBI. SSL grade also has a known sslyze-6.x scoring bug (back-test). |
| **Base value** | 0.05 | **0.05** (hold) | Reasoned | "Inherent internet exposure"; SA 58% lack-of-expertise supports a non-zero floor | — | — |
| **Diminishing knee** | 0.50 | **0.50** (hold) | Reasoned | Prevents stacking inflation; bands behave well in recompute | — | Revisit only if rebalanced caps change the typical raw-score distribution. |
| **Band map** | C≥0.75 / H≥0.50 / M≥0.25 / L | **hold** | Data-supported | Recompute: Phishield Medium, worst-case Critical — both correct | — | — |
| Supply-chain stack (S-1/2/3/4/10) | cap 0.22 | **hold cap 0.22** | Reasoned | Verizon 30% third-party; Patchstack 11.6% exploited; cap < single RDP by design | unchanged | Owned by supply-chain team; the **cat-tail "no double-count" rule** (observed→probability uplift) already governs this — leave to that group. |

---

## Recompute evidence (throwaway python, production pipeline replicated, no edit)

Reproduced the live pipeline exactly (`_diminishing` + industry×size multipliers).

**Phishield (fixture `phishield_live.json`):** active factors = HIGH credential (+0.15) + 1 exposed DB port PostgreSQL/5432 (+0.10) + No WAF (+0.05); base 0.05 → raw **0.35** → ×1.15 (finance) ×1.12 (revenue=0) = **RSI 0.451 (Medium)**. My harness reproduces 0.451 to the digit.

> ⚠️ **Fixture artifact:** `annual_revenue = 0` triggers the **micro-business multiplier 1.12**. At a realistic R500M the same findings give **RSI 0.362**. The brief's "0.728-ish" current value was **not reproducible** from this fixture — likely stale or from a different target. Confirm the intended baseline with the team.

| Scenario | Current | Proposed | Band |
|---|---|---|---|
| Phishield, rev=0 (as-shipped) | 0.451 | 0.489 (cred HIGH→0.18) / 0.451 (Prop B: also DBport→0.08, WAF→0.04) | Medium → Medium |
| Phishield, realistic R500M | 0.362 | ~0.40 | Medium → Medium |
| Worst-case primary stack (RDP + CRITICAL cred + 2 KEV + no-DMARC + no-WAF + weak-SSL), finance R200M | raw 0.84 → **0.859 Critical** | RDP 0.20 + cred 0.22 → raw 0.81 → **0.841 Critical** | Critical → Critical (preserved) |
| Single-signal: RDP-alone | 0.345 | ~0.29 (at RDP 0.20) | — |
| Single-signal: CRITICAL-cred-alone | 0.287 | ~0.32 (at cred 0.22) | **fixes the inversion** |

**Takeaway:** the rebalance toward the empirically-dominant credential channel is **net-neutral on the headline RSI** when paired with modest trims to the surface/hygiene factors (RDP, DB-port, WAF, SSL), while **correcting the single-signal ordering** to match SA/global evidence and **preserving the Critical band** for true primary-access stacks.

---

## Double-count & input-integrity checks (CRITIC)

1. **RDP vs credentials vs DB-ports — surface vs root-cause.** RDP-exposed, DB-port-exposed, *and* credential-risk can all fire for the same compromise path (CISA: RDP is breached *via* stolen creds/brute-force). Summing them at full weight over-counts the remote-access narrative. **Mitigation in proposal:** trim the *surface* factors (RDP, DB-port), keep the *root-cause* factor (credentials) heavy. The brute-force overlap is the reason credentials should not be *below* RDP.
2. **Credential card input bug (cross-team — flag to credential group).** Back-test Theme 3: the Credential Risk Assessment that sets `risk_level=HIGH` (→ +0.15 here) reportedly renders "passwords for 4 emails across 13 records" when only **2 records / 1 mailbox** actually carry a password. **The RSI weight is only as good as the tier classification feeding it — fix the input before tuning the weight.** Do not lift HIGH→0.18 until the credential team confirms the tier is correctly assigned.
3. **WAF / SSL inputs are themselves buggy (back-test Theme 1).** No-WAF (+0.05) and weak-SSL (+0.05) are fed by checkers with known false-positives (F5 fingerprint off `x-frame-options`; sslyze-6.x grade bug). Proposed trims partly hedge this, but the *correctness* fix lives in those checkers, not in RSI.
4. **Phase-4f / third_party_correlation already correctly excluded** (reporting-only, code comment L1100-1108) — no action; do not add it as a factor.
5. **Supply-chain stack governed by the cat-tail rule** — observed risk → probability uplift (pre-MC), not K_TAIL. Leave to the supply-chain team; the 0.22 cap < single-RDP design intent is sound.

---

## Honesty / confidence summary

- **Data-supported:** credential-channel should be ≥ RDP (SA 34% #1, DBIR #1, M-Trends tied-#2); vuln-exploit deserves parity with credentials (28% SA, +34% DBIR); email ~0.08 (22% SA). Band map validated by recompute.
- **Reasoned (defensible, not directly measured):** the *exact* RDP trim (0.25→0.18–0.22), DB-port and WAF/SSL trims, the observability premium for confirmed surfaces. These are judgement calls on how to split a probabilistic root-cause weight from an observed-surface weight.
- **Needs-colleague (2026-06-03):** (a) the intended Phishield baseline RSI (0.451 reproduces; 0.728 does not); (b) confirmation that the credential-tier input bug is fixed before lifting the HIGH weight; (c) whether exposed managed DBs belong in RSI or DBI; (d) the precise RDP-vs-credentials premium given underwriting appetite. Ranges given throughout where the SA-specific data is thin (Coveware/M-Trends give no clean SA per-vector split — only the Sophos SA cut does).

**Sources:** Sophos State of Ransomware in South Africa 2025; Mandiant M-Trends 2025; Verizon DBIR 2025; Coveware Q4 2024; CISA #StopRansomware; Patchstack State of WordPress 2024.


---

# Calibration Prep 04 — SA Cost / Fine Tables + TEF (Threat-Event Frequency)

**Status:** SANDBOX PREP for the calibration session. Values below are **research-grounded
PROPOSALS, NOT final**. No production code was edited. This is the most SA-specific parameter
group — anchored to IBM SA Cost of a Data Breach, the POPIA s109 fine structure + actual
Information Regulator enforcement to date, SABRIC, and Check Point SA sector telemetry.

Owner roles for the session: **DEV** proposes → **EXPERT** validates vs SA breach data →
**CRITIC** challenges (statutory-max vs expected-enforced; est_records for an SME) →
**ORCHESTRATOR** reconciles.

---

## 0. CRITICAL FRAMING — the params literally named in the brief are DEAD in production

The brief names `COST_PER_RECORD`, `REGULATORY_FINE`, and `est_records = max(1000, revenue/50000)`.
These are the **legacy USD path** (`scoring_analytics.py:1634-1684`). **They never execute in
production.**

- `FinancialImpactCalculator.calculate()` (L1661-1665) routes to `_calculate_zar()` whenever
  `annual_revenue_zar > 0`.
- `scanner.py:1195` passes `annual_revenue_zar = resolve_effective_revenue_zar(...)`, which
  **defaults a no-revenue scan to R10,000,000** (`peer_benchmarking.py:90`,
  `DEFAULT_REVENUE_ZAR_WHEN_ABSENT`). So `_zar` is **always ≥ R10M ⇒ ZAR path always fires**.
- The legacy `else` branch (USD `COST_PER_RECORD`/`REGULATORY_FINE`/`est_records`) is unreachable.

**Recompute proof** (throwaway, no edit): the legacy path, if forced (`annual_revenue_zar=0`),
returns `cost_per_record=219`, `est_records=1000`, `regulatory_fine=R750,000` for finance — a
mixed-currency artefact (219 was a *USD* figure now sitting in a ZAR product; the R750k fine has
no POPIA statutory basis). **It is a latent landmine, not a live input.**

**The LIVE equivalents to calibrate are:**

| Brief param (dead) | LIVE production equivalent | Location |
|---|---|---|
| `COST_PER_RECORD` (USD) | `SA_INDUSTRY_COSTS[*]["cost_per_record"]` (ZAR) | L916-941 |
| `REGULATORY_FINE` (flat ZAR) | C2 POPIA stack: expected `min(R10M, rev×0.02)` + cat `R10M×capacity_factor` | L2272-2348 |
| `est_records = rev/50000` | `record_density_divisor` per-industry + `estimated_records` | L2180-2210 |
| (TEF — correctly named) | `THREAT_EVENT_FREQUENCY` | L1840-1859 |

**DECISION FOR SESSION (recommended):** delete or hard-disable the legacy USD path so it can never
silently re-activate, and calibrate only the live ZAR equivalents. (Echoes the `OUTSTANDING.md`
§ "stale-table" flag and heuristics-audit row 79.)

---

## 1. SA research anchors (sources at bottom)

**IBM Cost of a Data Breach — South Africa**
- **2025:** avg total **R44.1M** (−17% YoY); avg **23,445 records**/breach ⇒ implied
  **~R1,880/record** (R44.1M ÷ 23,445). Top sectors: **Financial Services R70.2M**,
  Hospitality R57.5M, Services R56.8M.
- **2024:** avg total R53.1M; FS **R75.31M**, Industrial R67.26M, Hospitality R61.76M; breach
  sizes 2,100–113,000 records.
- Attack vectors (2025 SA, cost): phishing R50.4M (13%), compromised credentials R48M (13%),
  DoS R38.8M (13%), third-party/supply-chain R29.6M (17% — most *common*).

→ The code's `SA_INDUSTRY_COSTS` is the **IBM 2025 SA** table (FS R70.12M ≈ reported R70.2M;
"Other" R44.1M = the national avg). `cost_per_record` values are back-derived as
`breach_cost_zar / 23,445` (e.g. FS 70.12M/23,445 = R2,991 ≈ table's 2,992). **Internally
consistent and correctly sourced.** Only risk = annual staleness.

**POPIA s109 administrative fine — statutory vs ACTUAL enforcement**
- **Statutory max: R10,000,000** (s109; or up to 10 yrs imprisonment, or both).
- **Actual enforcement to date — only TWO administrative fines, both R5M, both vs government
  departments, both for *failure to comply with an enforcement notice* (not the breach itself):**
  1. **Dept of Justice & Constitutional Development — R5M**, July 2023 (1,200 files, ransomware;
     expired AV/SIEM/IDS licences). DoJ challenged it.
  2. **Dept of Basic Education — R5M**, infringement notice 23 Dec 2024.
- Other actions stopped at **enforcement notices** (no fine yet): TransUnion (SA's biggest breach),
  WhatsApp/Meta (settled Nov 2025), IEC, Lancet Labs, Blouberg Municipality.

→ **Expected-enforced fine ≈ R5M (the only data points), well below the R10M ceiling, and so far
0 fines against private-sector commercial entities.** Statutory max R10M is correct for the
**catastrophe view**; it is **too high for the expected-loss (P50) view**.

**SA sector attack frequency (for TEF)**
- **Check Point SA 2025:** **Government/Military #1 at 3,480 attacks/org/week**;
  **Communications #2 at 1,062/wk**; then financial services and consumer goods. SA overall avg
  1,884/wk (+69% YoY — the steepest global rise). Africa = most-attacked region (3,286/wk).
- **SABRIC 2024:** digital-banking fraud +86% YoY, **R1.888bn** gross losses (97,975 incidents),
  banking apps 65.3% of incidents — but **predominantly social-engineering, not technical breach**
  of the institution (relevant: SABRIC volume overstates *institutional* TEF for FS).

→ **SA-specific divergence from the global default:** global DBIR/IBM rank **FS #1**; SA Check
Point telemetry ranks **Government/Public Sector #1 by attack volume, Communications #2**. The
current TEF table (FS 1.45, Public Sector/Gov 1.35, Communications 1.05) under-weights the two
sectors SA attackers hit hardest. This is the headline TEF calibration question.

---

## 2. Proposal table

| Param | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute | Open question |
|---|---|---|---|---|---|---|
| **Currency of cost-per-record** | ZAR (live `SA_INDUSTRY_COSTS`); USD orphan in dead `COST_PER_RECORD` | Confirm **ZAR**; **delete legacy USD table** | **Data-supported** (high) | scanner.py:1195 always sends `_zar≥R10M` ⇒ ZAR path only; legacy returns USD 219 / R750k | Forcing legacy: cpr=219, est=1000, fine=750k (mixed-currency artefact, never reached) | Delete vs hard-assert the dead branch? |
| **`cost_per_record` "Other"** | R1,881 | **R1,880 (R1,700–R2,050)** | **Data-supported** (high) | IBM SA 2025: R44.1M ÷ 23,445 rec = R1,880 | "Other" breach_cost R44.1M = national avg ✓ | Refresh annually (IBM 2026) |
| **`cost_per_record` Financial Services** | R2,992 | **R2,992 (R2,800–R3,200)** | **Data-supported** (high) | IBM SA 2025 FS R70.2M ÷ 23,445 | FS R10M scan: cpr ref 2992, used only as disclosure metric | FS is most *expensive* (IBM) but in SA most *attacked* = Gov (see TEF) |
| **`cost_per_record` Public Sector** | R3,273 | **R3,200–R3,400** (hold) | **Reasoned** (med) | IBM 2025 Public Sector highest-cost; multiplier 1.74 | breach_cost R76.73M | IBM SA doesn't publish every sector yearly — some rows are 2024-scaled |
| **`SA_INDUSTRY_COSTS` whole table** | IBM-2025-ZAR | **Hold; add a dated `# IBM 2025` refresh stamp** | **Data-supported** (high) | FS/Hospitality/Services match IBM 2025 reported | n/a | Which sectors are 2025-actual vs 2024-carried? Mark each |
| **REGULATORY_FINE — expected (P50) POPIA** | `min(R10M, rev×0.02)` ⇒ R200k @ R10M | **Anchor to ACTUAL enforcement: expected ≈ R0–R5M, enforcement-discounted.** Replace flat 2% with a **probability-weighted expected fine** (see §3) | **Reasoned** (med) | Only 2 fines ever, both R5M, both govt, 0 private; s109 max R10M | @R10M: current expected C2=R200k. Proposed expected ≈ R150k–R400k (P(fine)·E[fine\|fine]) | What is P(POPIA fine \| breach) for a *private* SA SME? Likely <5% to date — **needs colleague / compliance officer** |
| **REGULATORY_FINE — catastrophe (tail) POPIA** | `R10M × capacity_factor` (0.15 @ R10M ⇒ R1.5M) | **Hold R10M statutory ceiling** for cat view; keep capacity scaling | **Data-supported** (high) | s109 hard ceiling = R10M | @R10M cat: popia_statutory_scaled R1.5M ✓ | Capacity_factor band magnitudes (0.10–1.00) — separate calibration |
| **`est_records` heuristic (dead)** | `max(1000, rev/50000)` | **Delete** (replaced live by `record_density_divisor`) | **Data-supported** (high) | dead path only | rev/50000 @R10M = 1,000 (floored) | n/a — dead |
| **`record_density_divisor` finance** | R7,500/record | **R5,000–R10,000** (hold 7,500) | **Reasoned** (med) | code note "1 cust record per R5–10k"; not externally sourced | @R10M FS ⇒ 10M/7,500 = **1,333 records** (vs IBM SA avg 23,445!) | An R10M SME modelled at 1,333 records is **plausible for a tiny firm** but far below IBM's 23,445 enterprise avg — is the SME floor right? |
| **`estimated_records` (live, reference only)** | `max(100, zar//divisor)` — disclosure metric, NOT in cost calc | Hold; **document it is non-scoring** | **Data-supported** (high) | heuristics-audit row 67: "not a cost input" | C1 liability uses IBM total×multiplier×revenue-scale, NOT records×cpr | Should we surface "vs IBM SA avg 23,445" in the disclosure? |
| **TEF Financial Services** | 1.45 | **1.30–1.45** (hold ~1.40) | **Reasoned** (med) | IBM FS #1 cost; SABRIC R1.9bn — but SABRIC is social-eng, not institutional breach | p_breach @ vuln 0.619 = 0.619×1.45×0.3 = **0.269** | SABRIC volume overstates institutional TEF — discount it |
| **TEF Public Sector / Government** | 1.35 | **↑ 1.40–1.50** | **Data-supported** (med-high) | **Check Point SA: Gov #1 @ 3,480/wk** — most-attacked SA sector | Gov @ vuln 0.619: 0.619×1.50×0.3 = **0.279** | Raising Gov above FS is SA-specific (inverts the global DBIR order) — confirm with EXPERT |
| **TEF Communications** | 1.05 | **↑ 1.20–1.30** | **Data-supported** (med) | **Check Point SA: Comms #2 @ 1,062/wk**; telco cybercrime R5.3bn 2025 | n/a | Comms currently mid-pack; SA telemetry says #2 |
| **TEF Retail / Consumer** | 1.25 / 0.95 | **Consumer ↑ to ~1.10** | **Reasoned** (med) | Check Point SA: "consumer goods & services" in SA top-3 | n/a | Reconcile Retail vs Consumer (split keys) |
| **TEF Healthcare** | 1.40 | **1.20–1.35** (consider ↓) | **Reasoned** (low-med) | Global IBM #2 cost, but **not** in SA Check Point top sectors; Lancet/NHLS attacks exist | n/a | SA healthcare attack *frequency* thinner than global — needs SA data |
| **TEF range / `0.3` interaction** | 0.80–1.45 (modest) | Hold range; **note TEF × the `0.3` LEF constant jointly set absolute p_breach** | **Reasoned** (med) | FAIR LEF = vuln×TEF×0.3 | TEF is a *relative* multiplier; absolute level is the `0.3` (FIN-9 / doc 01) | Don't double-calibrate: fix `0.3` first (separate group), then TEF as relative tilt |

---

## 3. The statutory-max vs expected-enforced question (CRITIC's central challenge)

**Current model is already two-tier and largely correct:**
- **Expected (P50) C2** = `min(R10M, rev×0.02)` — code *explicitly flags* this 2% as "an internal
  capacity-scaling heuristic, NOT a statutory formula" (L2267-2271). Good honesty.
- **Catastrophe C2** = `R10M × capacity_factor` stacked with ECTA/CPA/sector maxima — the hard
  statutory ceiling, capacity-scaled. Correct for the tail.

**The gap:** the expected-view 2%-of-turnover is **not anchored to actual enforcement**. Reality:
- POPIA has produced **2 fines in its enforcement history, both R5M, both public-sector, zero
  private-commercial.** P(administrative fine | private SME breach) is empirically **very low**
  (arguably <5% to date — the Regulator's pattern is enforcement-notice-first, fine only on
  *non-compliance* with the notice).
- A statutory- or turnover-anchored expected fine therefore **overstates** the P50 regulatory
  cost for a private SME, and **understates the conditional severity** (when a fine lands it has
  been the full R5M, half the ceiling).

**DEV proposal (for EXPERT/colleague validation):** replace the flat 2% expected with an explicit
**expected-value decomposition**:

```
E[POPIA fine] = P(fine | breach) × E[fine | fine]
   where, anchored to enforcement to date:
     P(fine | breach)  ≈ 0.02–0.05  (private SME; higher for public sector / repeat offender)
     E[fine | fine]    ≈ R5M        (both actual fines; ~50% of the R10M ceiling)
   ⇒ E[POPIA fine] ≈ R100k–R250k   (vs current R200k @ R10M — coincidentally similar!)
```

**Reconciliation note (ORCHESTRATOR):** the *current* R200k expected output is, by luck,
inside the proposed R100k–R250k band — so the **headline expected loss barely moves**; the value of
the change is **defensibility** (anchored to real enforcement, not an unsourced 2%) and **correct
behaviour at the revenue extremes** (2%-of-turnover sends a R200M firm to the R10M cap on the
expected line, which over-prices; an enforcement-probability model would not). **P(fine|breach) is
the single biggest unknown and is a compliance-officer / colleague call, not a dev intuition.**

---

## 4. Recompute summary (throwaway python, no production edit)

Fixture assumption: **Financial Services, R10M** (the no-revenue default), `_overall_score=381`
(phishield real posture, post Wave-1 `_overall_score` wiring).

| Metric | Current production output |
|---|---|
| vulnerability | 0.619 (= (100 − 381/10)/100) |
| TEF (FS) | 1.45 |
| **p_breach** | **0.269** (0.619 × 1.45 × 0.3) |
| C1 liability | R7.17M |
| C2 regulatory (expected POPIA) | **R200k** (2% × R10M) |
| C2 catastrophe (statutory) | R1.5M (R10M × 0.15 capacity) |
| C4 ransom | R0.90M |
| C5 IR | R0.35M |
| **total most_likely** | **R3.88M** |
| est_records (live, finance R7,500 divisor) | **1,333** (cf. IBM SA avg 23,445) |

Sanity vs published SA: IBM SA 2025 FS avg breach = R70.2M (enterprise). The model returns R3.88M
for a **R10M micro-SME** — i.e. ~5.5% of the enterprise figure, scaled down by revenue elasticity.
**Directionally sane** (an SME is not an enterprise) but note the est_records (1,333) sits far below
IBM's 23,445 enterprise average — expected for a tiny firm, but the EXPERT should confirm the SME
record-density floor is realistic, since C1 (the largest component, R7.17M) is driven by the
IBM-total × multiplier × revenue-scale path, **not** by records × cost_per_record (cost_per_record
is a disclosure-only reference here — see heuristics-audit row 67).

---

## 5. Honesty ledger

| Claim | Confidence | Basis |
|---|---|---|
| Legacy USD `COST_PER_RECORD`/`REGULATORY_FINE`/`est_records` are dead in production | **Data-supported (high)** | code trace scanner.py:1195 + resolve_effective_revenue_zar default R10M + recompute |
| `SA_INDUSTRY_COSTS` = correct IBM-2025-SA-ZAR | **Data-supported (high)** | FS/Hospitality/Services match IBM 2025 reported; "Other"=R44.1M national avg |
| Per-record ~R1,880 ("Other") | **Data-supported (high)** | IBM 2025 R44.1M ÷ 23,445 records |
| POPIA expected fine should be enforcement-anchored, not 2%-turnover | **Reasoned (med)** | only 2 fines ever (both R5M, both govt); P(fine\|breach) low |
| **P(POPIA fine \| private SME breach) ≈ 0.02–0.05** | **NEEDS COLLEAGUE / compliance officer (low)** | inferred from enforcement scarcity; not a published rate |
| Statutory R10M correct for catastrophe tier | **Data-supported (high)** | s109 hard ceiling |
| TEF should raise **Gov/Public-Sector and Communications** above current | **Data-supported (med-high)** | Check Point SA 2025 sector ranking (Gov #1, Comms #2) |
| Exact TEF magnitudes | **Reasoned / needs-colleague (med)** | attack-volume ≠ loss-event-frequency; TEF is relative, absolute level set by the `0.3` LEF constant (separate group) |
| `record_density_divisor` values (R5k–R1M/record) | **Reasoned (low-med)** | code-internal SA-market observation, not externally sourced |

---

## 6. Biggest open question (carry into the session)

**What is P(POPIA administrative fine | breach) for a private-sector SA SME, and what conditional
severity should the expected-loss view use?** The entire POPIA enforcement record is **two R5M
fines, both against government departments, zero against private commercial entities**, with the
Regulator consistently issuing enforcement-notices-first. This makes the *expected* (P50)
regulatory line almost entirely a **compliance-officer judgement call**, not a dev/data decision.
The statutory R10M ceiling (catastrophe tier) and the IBM-anchored cost-per-record (ZAR, high
confidence) are settled; the regulatory **expectation** is the one genuinely unresolved,
colleague-gated input.

Secondary: should TEF invert the global order to put **Public Sector ≥ Financial Services** for the
SA market (Check Point telemetry says yes by volume; loss-severity says FS) — and should this be
done in TEF (frequency) or left to the cost multiplier (severity)?

---

## Sources

- IBM Cost of a Data Breach 2025 — South Africa: avg R44.1M, 23,445 records, FS R70.2M / Hospitality R57.5M / Services R56.8M; vectors phishing R50.4M, credentials R48M, third-party R29.6M (DoS R38.8M). (htxt.co.za 2025-07; techcentral.co.za/267820; iafrica.com)
- IBM Cost of a Data Breach 2024 — South Africa: avg R53.1M; FS R75.31M, Industrial R67.26M, Hospitality R61.76M; 2,100–113,000 records. (itweb.co.za/6GxRKqYQag9qb3Wj; intelligentcio.com/africa 2024-08)
- POPIA s109 administrative fine (max R10M / 10 yrs). (popia.co.za/section-109-administrative-fines)
- Information Regulator R5M fine — Dept of Justice, July 2023 (first-ever; ransomware, 1,200 files, expired AV/SIEM/IDS). (lexology.com; itweb.co.za inforeg-justice; inforegulator.org.za media statements)
- Information Regulator R5M infringement notice — Dept of Basic Education, 23 Dec 2024. (itweb.co.za education-dept-r5m)
- Enforcement notices (no fine): TransUnion, WhatsApp/Meta (settled 13 Nov 2025), IEC, Lancet Labs, Blouberg Municipality. (itweb.co.za inforeg-transunion; timeslive.co.za 2024-09-11; misa.org WhatsApp settlement)
- Check Point SA 2025 sector telemetry: Government/Military 3,480/wk (#1), Communications 1,062/wk (#2); SA avg 1,884/wk (+69% YoY); Africa 3,286/wk (most-attacked region). (intelligentcio.com/africa 2025-06-02; businessday.co.za 2025-12-17)
- SABRIC Annual Crime Statistics 2024: digital-banking fraud +86%, R1.888bn gross losses, 97,975 incidents, apps 65.3% (predominantly social-engineering). (sabric.co.za CRIME-STATISTICS-REPORT-2024; techafricanews.com 2025-08-29)
- Telco cybercrime SA R5.3bn 2025. (businessday.co.za 2026-01-12)


---

# Calibration pre-read — Catastrophe tail / Pareto (FIN-9 core)

**For:** FIN-9 calibration session, 2026-06-03 (with colleague — international breach-cost / heavy-tail experience).
**Status:** SANDBOX PREP. **Research-grounded PROPOSED values, NOT final. No production code edited.**
**This is the colleague's core domain.** Everything tail-shape-related below is a *defensible starting point + the precise open questions* — **not** a pre-empted decision. The Pareto alpha and the mixture weight are explicitly flagged **needs-colleague-validation**.
**Relates to:** OUTSTANDING §6b + §"Tail recalibration"/"WAF coverage-loading constant"; the cat-tail no-double-count rule (`project_scanner_supplychain_cat_tail_design_2026-05-27`); the FIN-9 memory flag.

---

## 0. Scope of this parameter group

Three sub-groups inside `FinancialImpactCalculator._calculate_zar` (and helpers):

1. **`K_TAIL = 1.20`** — WAF-blind-spot coverage-loss tail-widening constant (epistemic uncertainty; *not* supply-chain).
2. **FIN-9 core** — a **conditional Pareto-mixture loss-given-breach (LGB) widening** applied **only to the ~12% supply-chain-vectored MC trials** (the IBM CoDB SC-root-cause slice). Parameters: **Pareto `alpha`** + **mixture weight `mix_w`** + the SC-vectored **fraction `f_sc`**.
3. **PERT bounds + return-period mapping** — the `0.5× / mode / 5.0×` PERT envelope on `mc_total_breach`, and the P99/P99.5/P99.6 → 1-in-100/200/250 percentile map (incl. the GPD Peaks-Over-Threshold refinement above P95).

**Critical design discipline (do NOT relitigate — confirmed 2026-05-27):** supply-chain risk already enters `p_breach` via the `supply_chain_vulnerability_uplift` (cap +0.15 on `vulnerability`). The whole MC distribution shifts right from that, so the tail *already* moves. **FIN-9 widens LGB (severity) on the SC slice, NOT `p`. Do NOT re-introduce a blanket `K_TAIL_SC` post-MC multiplier — that double-counts.** The verifier asserts `supply_chain_tail_adjustment.applied == False` as a PASS condition.

**Baseline caveat (read first):** calibrate against the **post-Wave-1 fixed-code** loss baseline, not the old inflated one. Wave 1 wired `_overall_score` → `vulnerability` for the first time (was pinned 0.5). The recompute below uses the R10M-finance fixture (vuln=0.5, pre-Wave-1) **only to demonstrate tail SHAPE deltas** — the shape comparison is invariant to the absolute `p_breach`, but **regenerate the magnitude anchors on a fixed-code scan before fixing final numbers** (OUTSTANDING §6b).

---

## 1. Parameter table

| Param | Current | Proposed (range) | Confidence | Anchor (sources) | Recompute (P99 / P99.5 / P99.6 delta) | Open question for colleague |
|---|---|---|---|---|---|---|
| **FIN-9 Pareto `alpha`** (LGB tail shape on SC slice) | none (not implemented) | **1.5 – 2.0** central; 1.2 aggressive (MOVEit-like) … 2.5 conservative | **needs-colleague** (their core domain) | German max-loss EVT study **α = 1.77** [Geneva Papers]; Eling-Ibragimov-Ning tail-dynamics (heavy-tail confirmed, α<2) [ScienceDirect/SSRN]; Advisen aggregate Hill/ECF estimates 0.05–0.32 (= "infinite mean", flagged extreme model-risk) [PMC10024527]; smaller α ⇒ heavier tail (α<2 infinite variance, α<1 infinite mean) | At **f_sc=12%, mix_w=30%**: α=2.0 → **+8% / +14% / +18%**; α=1.5 → **+15% / +36% / +50%**; α=1.2 → +38% / +108% / +141%; α=2.5 → +4% / +6% / +7% | **Q-A:** Given the *whole-portfolio* Advisen tail index sits <1 (infinite-mean, but huge parameter uncertainty) yet a *stable body-tail* fit lands ~1.77, what α do you use for **per-org LGB** on a **conditional SC slice**? Is 1.5–2.0 the right working band, or do you anchor harder to MOVEit (≈1.2)? |
| **FIN-9 mixture weight `mix_w`** (fraction of SC trials that draw the heavy Pareto component) | none | **0.25 – 0.35** central | **needs-colleague** | MOVEit per-org curve: top **1%** of ~2,700 orgs absorbed **~60–70%** of total cost [Emsisoft; ORX]; Coveware Q4-2024 ransom **mean/median ≈ 5.0** ($553,959 / $110,890), 63% of demands ≥ $1M, one $75M outlier [Coveware] | mix_w is the lever that sets how much tail mass the heavy component carries; at α=1.5 moving mix_w 20%→40% roughly doubles the P99.6 uplift | **Q-B:** A literal MOVEit fit (top-1%→60–70%) implies a *very* small mix_w on a *very* heavy α. Do we reproduce that shape, or deliberately temper it for an SA SME book (smaller absolute exposures, FSP/UMA context)? |
| **FIN-9 SC-vectored fraction `f_sc`** | n/a (12% cited in comments, not wired to a tail) | **0.12** (IBM CoDB SC root-cause); sensitivity to 0.20 (DBIR-bounded upper) | medium-high (well-anchored) | IBM CoDB 2024 SC = initial vector in **12%** [IBM]; DBIR 2025 third-party *involvement* 30% (broader, not pure root cause); Mandiant ~3% strict trojanised-vendor — **defensible root-cause band 12–20%** | f_sc=20% (α=1.5) → +32% / +87% / +111% vs the 12% case +15% / +36% / +50% | **Q-C:** Use the strict IBM root-cause 12%, or a wider 12–20% to bracket DBIR "involvement"? (12% is the cleaner causal number; 20% risks bleeding into signals already counted via the vuln uplift.) |
| **`K_TAIL = 1.20`** (WAF blind-spot, coverage-loss) | **1.20** | **hold 1.20** pending paired rescan data | low-medium (heuristic; **separate from FIN-9**) | No empirical anchor yet — designed to be calibrated against blinded-vs-allow-listed **rescan deltas** once continuous monitoring exists (SCN-029) | n/a — independent of FIN-9; documented here for completeness. At 10% coverage shortfall → +12% on 1-in-250; at 40% → +48% | **Q-D:** Any external benchmark for "expected hidden-finding severity given a blinded external scan"? Otherwise hold 1.20 and revisit with paired data. Keep it strictly epistemic (NOT merged with FIN-9). |
| **PERT upper bound** on `mc_total_breach` / `mc_total_base` | **5.0×** mode (lower 0.5×) | **hold 5.0×** if FIN-9 lands; revisit only if NOT | medium | Widened 2.5×→5.0× (Phase B3) for SA cat precedent (Transnet, Life Healthcare, Experian). IBM mega-breach: 1–10M records ≈ $42M (~9× avg); ≥50M ≈ $375M | The current 5.0× envelope alone yields **mean/median ≈ 1.12, P99.6/P50 ≈ 3.1** — *too light* vs empirical cyber tails (Coveware mean/median ≈ 5) | **Q-E:** Is the FIN-9 Pareto mixture the right way to add tail weight (preferred — targeted to SC slice), vs simply widening this PERT bound further (blunt — inflates *all* trials, incl. non-SC)? |
| **Return-period map** P99/P99.5/P99.6 → 1-in-100/200/250 + GPD POT fit above P95 | as-is (MoM GPD, pure-numpy) | **hold**; FIN-9 feeds the *input* dist, map is downstream | medium-high | Standard actuarial RP convention; GPD POT is textbook tail extrapolation (MoM, no scipy on Render) | FIN-9 widens the underlying samples; the existing P95-threshold GPD then refits naturally on the heavier tail | **Q-F:** With a genuine Pareto component in the body of the SC slice, does the P95 POT threshold still sit in the right place, or lift the threshold (e.g. P97/P98) for the SC-conditional refit? MoM→MLE GPD upgrade still deferred (scipy). |

---

## 2. What the recompute shows (throwaway numpy — no production edit)

Faithful reconstruction of the R10M-finance fixture's MC (PERT λ=4, 7-scenario incident decomposition, real cost components C1=R7.29M / C2=R0.2M / C4=R0.90M / C5=R0.35M, `p_breach`=0.2175), then a **conditional Pareto-mixture LGB** multiplier applied to the C1+C2 *breach severity* of the SC-vectored slice only.

**Baseline (current model shape):** P50 R2.98M · P95 R6.59M · P99 R8.43M · P99.5 R9.11M · P99.6 R9.31M · mean R3.33M.
→ **mean/median = 1.12**, **P99.6/P50 = 3.1**. This is **lighter-tailed than empirical cyber loss** (Coveware ransom mean/median ≈ 5.0; the literature repeatedly finds lognormal/PERT *under-predicts* the cyber tail). That gap is the gap FIN-9 closes.

| Scenario (f_sc, α, mix_w) | P99 Δ | P99.5 Δ | P99.6 Δ | mean Δ | P50 Δ | ordering |
|---|---|---|---|---|---|---|
| central (12%, 2.0, 30%) | +8.2% | +14.4% | **+18.2%** | +2.7% | +0.8% | OK |
| heavier (12%, 1.5, 30%) | +14.7% | +35.6% | **+49.8%** | +5.8% | +1.0% | OK |
| aggressive / MOVEit-like (12%, 1.2, 40%) | +37.7% | +108.1% | **+140.9%** | +19.2% | +1.8% | OK |
| conservative (12%, 2.5, 20%) | +3.7% | +5.7% | **+6.7%** | +1.1% | +0.4% | OK |
| upper SC frac (20%, 1.5, 30%) | +31.7% | +87.0% | **+111.1%** | +11.7% | +1.7% | OK |

**Findings:**
- **Median essentially unmoved** (P50 +0.4% … +1.8%) across the entire parameter space → the widening is **tail-only**, confirming no double-count with the `p_breach` channel. Expected-loss view barely shifts (mean +1% … +6% in the plausible band).
- **Ordering P99 ≤ P99.5 ≤ P99.6 preserved in every run.**
- The **central band (α 1.5–2.0, mix_w ~30%, f_sc 12%)** lifts the 1-in-250 by **~18–50%** and the mean/median ratio from 1.12 toward **1.14–1.17** — a *modest* move toward the empirical 1.2–1.3 region, still far short of an unconstrained Coveware ≈5. Reads as defensible, not punitive.
- **α=1.2 is a true upper bound** (1-in-250 +141%, mean/median 1.31) — only justified if the colleague judges the SC tail should literally approach the MOVEit per-org curve.

*Heavy-tail behaviour check (expert validation point):* the recompute reproduces the qualitative MOVEit shape (a thin slice of trials carrying disproportionate loss). The colleague should confirm whether the **top-1%-absorbs-60–70%** property holds at the chosen (α, mix_w) — the literal MOVEit fit needs a heavier α + smaller mix_w than the central band; the central band is a *tempered* version chosen for an SA SME book. **This temper is a proposal, not a decision — Q-B.**

---

## 3. Honesty / confidence statement

- **Pareto `alpha` + mixture `mix_w`: needs-colleague.** These set the catastrophe capital view; they are the colleague's domain. The ranges above are a *defensible starting point* from public literature, **not** a recommendation to adopt a specific value.
- **`f_sc`=12%: medium-high confidence** (clean IBM root-cause anchor); the 12–20% sensitivity is the honest uncertainty band.
- **`K_TAIL`=1.20: hold** — heuristic, no anchor yet, but **independent of FIN-9** (epistemic, not severity). Do not fold the two together.
- **PERT 5.0× / return-period map: hold** — the FIN-9 mixture is the *preferred* mechanism to add SC tail weight (targeted) over further blunt PERT widening (untargeted).
- All deltas are **shape** results valid regardless of the absolute `p_breach`; **magnitudes must be re-anchored on a fixed-code scan** (OUTSTANDING §6b) before any number is fixed.

## 4. The precise asks for the colleague (decision checklist)

1. **Q-A — α:** per-org LGB Pareto shape for a conditional SC slice — working band **1.5–2.0**, or anchor to MOVEit (~1.2)? (Reconcile: whole-portfolio Advisen α<1 infinite-mean *vs* stable body-tail α≈1.77.)
2. **Q-B — mix_w + MOVEit fidelity:** reproduce the literal top-1%→60–70% shape, or the tempered SA-SME version (central band)?
3. **Q-C — f_sc:** strict IBM root-cause **12%**, or widen toward DBIR-involvement 20%?
4. **Q-D — K_TAIL:** any external benchmark for blinded-scan hidden-severity, or hold 1.20 until paired-rescan data?
5. **Q-E — mechanism:** confirm Pareto-mixture-on-SC-slice (targeted) is preferred over a wider blanket PERT bound (untargeted).
6. **Q-F — RP map / GPD threshold:** keep the P95 POT threshold for the SC-conditional refit, or lift it; MoM→MLE GPD upgrade timing.
7. **Cross-check (do together):** confirm the resulting 1-in-100/200/250 ZAR figures for a CRITICAL-SC org sit sensibly vs SA cat precedent (Transnet/Life Healthcare/Experian) and the colleague's international per-org loss curves — and that the **mean/expected-loss is essentially unchanged** (capital view only).

## 5. No-double-count guardrails (hard rules — carry into implementation)

- FIN-9 widens **LGB severity on the SC slice**, never `p`. SC already raises `p_breach` via the vulnerability uplift.
- **No `K_TAIL_SC`.** Verifier must still PASS `supply_chain_tail_adjustment.applied == False`.
- `K_TAIL` (WAF) stays strictly epistemic and separate.
- Run the 2-step gate after any wiring (`verify_supply_chain_financial_wiring.py` 31/31 + `verify_scan_smoke.py` exit 0) and present per-percentile deltas + sanity-check before shipping.

## Sources

- German max-loss EVT study (selected Pareto **α = 1.77**) — Geneva Papers on Risk and Insurance: https://link.springer.com/article/10.1057/s41288-023-00293-x
- Eling, Ibragimov, Ning — *The Changing Landscape of Cyber Risk: loss severity & tail dynamics* (heavy-tail confirmed, α<2): https://www.sciencedirect.com/science/article/pii/S0167668725001428 · SSRN: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5158032
- Cyber loss model risk / Advisen tail-index estimates (Hill/ECF 0.05–0.32, infinite-mean caveat) — PMC10024527: https://pmc.ncbi.nlm.nih.gov/articles/PMC10024527/
- *Nature of losses from cyber-related events* (Advisen, sector tails) — Oxford Journal of Cybersecurity: https://academic.oup.com/cybersecurity/article/9/1/tyac016/7000422
- MOVEit per-org / top-victim statistics — Emsisoft: https://www.emsisoft.com/en/blog/44123/unpacking-the-moveit-breach-statistics-and-analysis/ · ORX deep dive: https://orx.org/resource/moveit-transfer-data-breaches-orx-news-deep-dive
- Coveware Q4-2024 ransom distribution (mean/median ≈ 5.0; 63% ≥ $1M; $75M outlier): https://www.coveware.com/blog/2025/1/31/q4-report · https://www.coveware.com/ransomware-quarterly-reports
- IBM Cost of a Data Breach 2024 (mega-breach $42M / $375M tiers; SC 12% root cause): https://www.ibm.com/think/insights/whats-new-2024-cost-of-a-data-breach-report
- Spliced/mixture cyber-loss severity modelling (lognormal under-predicts tail; Pareto for large claims) — SCIRP: https://www.scirp.org/journal/paperinformation?paperid=126218
