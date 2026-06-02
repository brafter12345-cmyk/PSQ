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
