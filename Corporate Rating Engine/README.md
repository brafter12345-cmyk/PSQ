# Phishield Corporate Rating Engine (web app)

Internal underwriting tool that automates the **Corporate** cyber rating spreadsheet
(`Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx`) for clients with
turnover **above R250M** (above the SME engine's ceiling). Sibling of the SME Rating Engine.

## Status
- ✅ Premium engine ported and **validated to the rand** against the spreadsheet
  (`node test-engine.js` → Final Premium R457,460.93 for the embedded example).
- ✅ 4-step wizard: Client & Cover → Cyber Maturity (override) → Benefits & Funds Protect → Quote.
- ✅ Flask + SQLite quote persistence.
- ✅ **v1.1:** Specialized-Underwriting framing, free excess input, free per-benefit %, Funds Protect
  from R250k (interpolated) + <10%-cover warning, MDR discount display, discretionary discount,
  and a cover-comparison table. See `IDEAS_AND_SME_NUANCES.md` for what's proposed next + open questions.
- ⏳ **v2:** full 150-question security questionnaire (auto-computes the maturity score and the
  conditions-of-cover list, replacing the manual maturity band); renewal flow + competitor benchmarking.

## Architecture (vanilla JS, no framework)
| File | Purpose |
|------|---------|
| `index.html` | 4-step wizard shell |
| `corporate-data.js` | **auto-generated** data layer (all Look Up Tables) — see `tools/gen_corporate_data.py` |
| `corporate-engine.js` | pure premium engine (Node + browser); faithful port of "Premium Calculation" |
| `corporate-rating.js` | UI controller (state, wizard, live recompute, export, save) |
| `corporate-rating.css` | dark-glass theme (shared tokens with SME) |
| `app.py` | Flask: serves the app + `/api/quotes` CRUD, SQLite (`corporate_quotes.db`) |
| `test-engine.js` | headless oracle test (`node test-engine.js`) |
| `ENGINE_ANALYSIS.md` | full reverse-engineering spec of the spreadsheet |

## Run
```bash
pip install -r requirements.txt
python app.py            # http://localhost:5003
# or just open index.html for the calculator (save needs the backend)
```

## Updating rates
The spreadsheet is the source of truth. When it changes:
```bash
py tools/reproduce_engine.py     # 1. confirm the formula structure still matches (spreadsheet parity)
py tools/gen_corporate_data.py   # 2. regenerate corporate-data.js from the new Look Up Tables
node test-engine.js              # 3. re-validate the JS engine against the oracle
```

Quote reference format: `CRE-YYYYMMDD-NNNN`.
