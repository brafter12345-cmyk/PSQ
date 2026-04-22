# SME Rating Engine — Project Summary

## Overview
Internal underwriter tool for Phishield UMA (Pty) Ltd that automates SME cyber insurance premium calculations. Replaces the manual spreadsheet-based rating process.

- **Product:** Cyber Protect Business Policy (Risk Rated)
- **Administrator:** Phishield UMA (Pty) Ltd
- **Insurer:** Bryte Insurance Company Limited
- **Target:** SME clients with turnover up to R200M

## Architecture
Single-page HTML portal (no frameworks), 5-step wizard:

| File | Purpose |
|------|---------|
| `index.html` | 5-step wizard UI |
| `sme-data.js` | Premium tables, formulas, modifiers, IToo benchmarks, industry list |
| `sme-rating.js` | Calculation engine + UI logic |
| `sme-rating.css` | Dark theme styling (matching quote estimator) |

## 5-Step Wizard Flow

1. **Client & Industry** — Company details, turnover inputs, industry selection, underwriting questions (Q1-Q9), quote type, prior claim flag
2. **Coverage Recommendations** — Auto-recommended cover limits based on turnover, FP selection, Micro SME detection
3. **Competitor Quotes & Benchmarking** — Multi-cover-limit comparison inputs, IToo benchmark (ex-FP)
4. **Adjustments & Live Comparison** — Posture/discretionary discounts, real-time bar comparison vs benchmarks
5. **Quote Summary & Export** — Full audit trail, dual Phishield figures (with FP / ex-FP), print/PDF, clipboard copy

## Key Business Rules

- **Micro SME:** T/O < R50M + cover <= R5M (general); T/O < R10M for S&T and Finance
- **Industry Modifiers:** S&T (1.10-1.67) and Finance (1.00-1.40) applied to base only, not FP
- **Bracket Shifting:** Lower premium brackets for competitive pricing on certain T/O + cover combos
- **Turnover Calc:** Midpoint of previous year and current estimate
- **Underwriting Questions (April 2026 revised):** Q1 is compound (4 baseline sub-parts); Q1.1 (AV/EDR) or Q1.2 (Firewall) No → Decline; Q1.3 (Email security) or Q1.4 (Web filter) No → Condition of Cover (caution). Loading pool is Q2.1, Q2.2, Q3, Q4, Q5 (five independent questions). Q6/Q7 are FP>R250k-dependent Conditions of Cover; Q8 is prior cyber cover with optional Insurer/Inception-Date follow-up (auto-Yes on Renewal)
- **Underwriting Loading:** Grace of two, then 5/10/15% for 3/4/5 "No" answers on Q2.1-Q5
- **Discount Cap:** Combined posture + discretionary max ~35%
- **Blockers:** Healthcare/Public Admin, T/O > R200M, Q1=No, Prior Claim ticked, Renewal-with-Q9=No contradiction -> "Refer for Underwriting"
- **Market Condition:** Read-only indicator (currently "Softening 2026"), hardcoded in sme-data.js
- **Renewals:** Benchmark is previous year's premium; three required inputs (cover, premium, FP sub-limit); Q9 auto-set to Yes; market condition drives upgrade/alternative/downgrade options; **Premium-drop Protection rule** triggers when new premium at same cover/FP is <80% of existing, auto-adjusting recommendations to retain >=90%, with Corporate escalation when max SME cover still falls short. Ladder-gap fill: when the target cover is >1 step above existing, intermediate covers are surfaced as Alternative cards with a "XX% retention" badge (replacing the above-target card)

## PDF Output Structure
```
Quotes/Year/Month/CompanyName/CompanyName_CoverLimit.pdf
```

## Data Update Points (in sme-data.js)
- `MARKET_CONDITION` — Update annually (softening/stable/hardening)
- `ITOO_BENCHMARKS` — Update with new competitor pricing
- `INDUSTRY_MODIFIERS` — Adjust if risk profiles change
- `PREMIUM_FORMULAS` — Update rate coefficients if product spec changes
- `FP_COSTS` — Update if FP pricing changes

## Quote Reference Format
`CPB-YYYYMMDD-NNNN`

---
*Last updated: 2026-04-22 — Renewal logic overhaul (v1.3) + Rule I ladder-gap fill (v1.3.1) + live FP Step 2 card updates (v1.3.2) + UW question set aligned to V1 2026 proposal (v1.4)*
