# Corporate Rating Engine — Spreadsheet Analysis (validated)

**Source:** `Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx` (not git-tracked; local working file).
**Status:** Engine fully reverse-engineered and **reproduced in Python — every step matches the workbook's cached values to the rand** (Final Premium R457,460.93 for the embedded example). See `tools/reproduce_engine.py` (spreadsheet-parity check) and `test-engine.js` (JS-engine oracle).
**Purpose of this doc:** durable spec for porting the engine to a web app (mirroring the SME Rating Engine architecture).

---

## 1. Workbook structure (5 sheets)

| # | Sheet | Role |
|---|-------|------|
| 0 | **Summary & Input Flieds** | Data-entry form + headline outputs. Turnover, cover, sub-industry, excess, 9-benefit table, VAT, MDR, FP. |
| 1 | **Premium Calculation** | The engine (rows 1–62). Full premium chain. |
| 2 | **Cybersecurity Questionaire** | ~150 questions → weighted posture score at `H282` + ~35 underwriting condition flags (col I). |
| 3 | **Look Up Tables** | All reference data (base-premium constants, sub-industry factors, breach costs, benefit contributions, maturity bands, FP tables, MDR, excess list, questionnaire answer-option lists). |
| 4 | **Cover Amount** | Multi-cover projection grid (R5M…R150M × turnover) — curve-fit/validation artifact, **not needed verbatim** for the app. |

**External link:** one cell only — `'[1]Standard Premium Tables'!T5 = 0.6173` = the **SME/Corporate Ratio** (from the SME product-spec workbook on OneDrive), used only for the SME-equivalent comparison line. Treat as a single constant/parameter.

**Corporate threshold:** turnover input is validated `> R249,999,999` (note in sheet: "min 250 mil for now, must be 500 mil"). Sits above the SME engine's R200M ceiling.

---

## 2. The premium chain (Premium Calculation sheet)

All values below are for the embedded example (turnover R7.2bn, cover R50M, sub-industry "Manufacturing – Fabricated Metal Products", override "Moderate", excess R2M, adjustable FP R2M, No MDR).

| Cell | Step | Formula (plain English) | Value |
|------|------|--------------------------|-------|
| C6 | **Base premium (rate)** | `BaseConst(cover) × (turnover/cover)^(−0.03035·ln(turnover)+1.462732)` | 800,025 |
| C8 | Industry risk modifier | lookup sub-industry → factor `S` | −29.24% |
| C9 | BI contribution modifier | lookup sub-industry → factor `U` | +13.84% |
| C11 | Cyber posture | `= Questionnaire!H282` (0–1) | 0.99998 |
| C12 | Maturity modifier (computed) | posture banded: ≥.9→0.75, .8–.9→0.85, .7–.8→1.0, .6–.7→1.15, else 1.25 | 0.75 |
| C13 | Maturity override | override label → multiplier (Very Strong .75 … Very Weak 1.25; **N/A → use computed**) | 1.00 |
| C15 | **Adjusted premium** | `C6·(1+C8)·(1+C9)·[override=N/A ? C12 : C13] / 1.155 · (1+VAT)` | 641,693 |
| C16 | + ransomware | `C15 + C15/100 + D25` (D25 = cyber-extortion contribution) | 648,110 |
| D19–D27 | Benefits weighting | per benefit: included? → contribution (`AG` table; BI uses industry `U`). Sub-limit ratio credit = `D·√ratio` | — |
| D28 | Σ benefit contributions | sum of included benefits | 84.17% |
| C29/C30 | Benefits-adjusted premium | `C16 × Σcontributions` | 545,498 |
| C31 | Yearly market adj | `C30 × (1 + D31)`, D31 = −0.20 | 436,399 |
| C38 | Excess credit | if excess ≤ 50%·cover: `excess/E[breachcost]` (or `(excess/cover)^1.1`); else self-insurance warning | 7.06% |
| C45 | Expected industry breach cost | `BreachCostZAR(sub-industry) × (SA/global factor 0.5697)` | 28,332,757 |
| C48 | Post-excess premium | `C31 × (1 − C38)` | 405,593 |
| C34/C35 | Funds Protect | standard (10% cover band) **or** adjustable (sub-limit → cost) | 24,420 |
| C50 | Risk-mgmt fee | 6% (gross-up `/(1−0.06)`) | — |
| C51 | Depository-institution modifier | only if sub-industry = Depository Institutions; banded by turnover | 1.0 |
| C53 | **Base premium (final pre-discount)** | `((C48 + FP)/(1−0.06)) × depository?` → Summary "Base Premium" | 457,461 |
| C56 | Sophos MDR discount | MDR tier → % off | 0 |
| C57 | **FINAL PREMIUM** | `C53 − C56` → Summary "Final Premium" | **457,461** |

**Summary derivations (row 36–38):** ex-fee `/1.06`, with-loading `×1.088`, ex-FP/SME-equiv `×0.8/1.15`, monthly `/12`, commission `×6%`, SME-ratio `× 0.6173`, etc.

---

## 3. Questionnaire posture (Cybersecurity Questionaire sheet)

Weighted, normalized scoring tree. `H282 = Σ section scores ≈ 1.0` when all-favourable.
**Section → subsection → question**, each question `IF(answer="Yes", weight, 0)` or `XLOOKUP(multi-choice answer → score) × weight`.

| Section | Weight | Section | Weight |
|---------|-------:|---------|-------:|
| 1 Data Security & Info Governance | 0.10 | 9 Remote Access & Workforce | 0.02 |
| 2 Security Controls & Ops Safeguards | 0.02 | 10 Third-Party Vendors & Cloud | 0.02 |
| 3 Secure Config & Change Control | 0.02 | 11 Asset Inventory & Lifecycle | 0.10 |
| 4 Facility & Physical Security | 0.02 | 12 Vulnerability Management | 0.10 |
| 5 Business Continuity & Incident Mgmt | 0.02 | 13 Security Operations (SOC/SIEM/MDR) | 0.15 |
| 6 Identity, Access & Privileged Accounts | 0.10 | 14 Claims History | *(informational, not scored)* |
| 7 **Network, Perimeter & Email** | **0.29** | 15 Payment Fraud Controls | 0.02 |
| 8 Employee Awareness & Training | 0.02 | | |

**Underwriting checks (column I):** ~35 key controls each set a 0/1 flag (`I282 = ΣI = 35` when all met). When a flag is 0 the control surfaces as a **condition of cover** in the "Underwriting Requirements" list (Summary `B40` = `FILTER(questions where I=0)`). Flagged controls include: ≥weekly + immutable backups, vuln remediation, POS encryption/segmentation, offsite backups, annual IR-plan test, password policy, **MFA (privileged + payments)**, **EDR**, **email & web filtering**, security-awareness training + phishing sims, VPN+MFA, **MDR**, and payment-fraud vetting/beneficiary-verification/account-verification.

**Two posture modes (both native to the sheet):**
- **Override = "N/A"** → use the computed questionnaire posture (`C12`).
- **Override = a maturity band** (Very Strong…Very Weak) → bypass the questionnaire, use the band's multiplier directly (`C13`). *(The embedded example uses "Moderate", so the questionnaire is bypassed.)*

---

## 4. Key lookup tables (to extract into the data layer)

- **Base premium constants** (cover → constant): R5M 1179.07 · R7.5M 1930.59 · R10M 2447.78 · R15M 3696.02 · R25M 6896.46 · R50M 17093 · R75M 32385.5 · R100M 51945.5 · R150M **TBC**. *(Main engine lookup covers R5M–R100M only.)*
- **Sub-industry factor table** (`N3:N88`, 86 rows): full SIC "Industry – Sub-industry" label → breach cost (USD/ZAR), industry factor `S`, BI factor `U`. Same SIC taxonomy as the security scanner.
- **Benefit contributions** (`AD4:AG12`, 9 benefits): ransom-inclusive normalized breach-cost contribution per benefit.
- **Maturity bands** (`AP3:AT8`): label, multiplier, ≥/< thresholds, description.
- **Funds Protect**: standard table (`A69:K70`, 10%-of-cover, from workbook) + adjustable table (**client-provided 2026-06-09**, 250k→3,144 … 5M→71,160, supersedes workbook `A74:J75`; injected in `tools/gen_corporate_data.py`).
- **Excess/deductible list** (`A15:A65`), **Sophos MDR options** (`A89:B93`), **depository turnover bands** (`A79:C86`), **VAT options** (`E2:E12`), **BI-impact list** (`J7:J46`).
- **Questionnaire answer-option lists** (`AP10:AY40` + `BA11:BA103`): Yes/No, frequency scales, percentage bands, SOC tiers, MDR tiers, compliance frameworks, etc., with their score rows.

---

## 5. Notes / quirks (carry into the build)
- `C16` adds `C15/100 + D25` (a few thousand rand + a tiny fraction) — faithfully reproduced; looks like an author rounding/■ artifact but is part of the official figure.
- Cover Amount sheet uses exponent −0.030**65** vs the engine's −0.030**35** (minor inconsistency in the projection sheet only).
- R150M base constant is "TBC"; R150M = R100M in the projection grid (placeholder).
- Named ranges `IndustryList`/`SubIndustryList` are `#REF!`-broken (dropdowns now point directly at Look Up Tables columns).
- `/1.155` then `×(1+VAT 0.15)` in C15 ≈ net ×0.9957 — reproduced exactly.
