# Corporate Rating Engine — Session Handoff (2026-06-09)

Single entry point for a fresh session. **All work is uncommitted** in git worktree
`sharp-chatelet-7b84b6` (branch `claude/sharp-chatelet-7b84b6`), under
`PSQ/Corporate Rating Engine/`. Related deep docs: `ENGINE_ANALYSIS.md` (spreadsheet spec),
`IDEAS_AND_SME_NUANCES.md` (feature backlog), `INGESTION_PLAN.md` (ingestion/mapping/scan detail),
`README.md`. Project memory: `…/memory/project_corporate_rating_engine.md`.

---

## What this is
A web app that automates the **Corporate** cyber rating spreadsheet
(`Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx` — local, **untracked**;
turnover **> R250M**), plus a **risk-assessment ingestion** pipeline that maps any third-party
assessment form against our questionnaire and (soon) attaches an external **scan**. Sibling of the
SME Rating Engine; the two should share the ingestion/scan layer.

## Run / verify
```bash
cd "PSQ/Corporate Rating Engine"
python app.py                 # http://localhost:5003  (launch.json config: "corporate-engine")
node test-engine.js           # engine oracle — expect Final Premium R457,460.93
py tools/reproduce_engine.py  # spreadsheet parity — R457,460.93
```
Rating engine: `localhost:5003/` · Ingestion: `localhost:5003/assessment.html`.
Scanner (separate app): `PSQ/security_scanner`, Flask **:5001**.

## Files
- **Rating engine:** `index.html`, `corporate-data.js` (auto-gen — do not hand-edit),
  `corporate-engine.js` (validated math), `corporate-rating.js` (UI), `corporate-rating.css`,
  `jspdf.min.js`, `app.py` (Flask + SQLite `corporate_quotes.db`), `test-engine.js`,
  `tools/gen_corporate_data.py`, `tools/reproduce_engine.py`.
- **Ingestion / mapping / scan:** `assessment.html` + `assessment.js`, `document_extract.py`
  (local convert + `find_scan_seeds`), `redaction.py` (mini on-prem PII redact/rehydrate),
  `mapping.py` (schema + mock + Claude engine), `scanner_client.py` (security_scanner client).
- **Backend endpoints:** `/health`, `/api/quotes` (CRUD + pdf), `/api/ingest`, `/api/map`.

## Config / env vars
| Var | Default | Purpose |
|-----|---------|---------|
| `REDACTION_URL` | *(unset → local mini unit)* | **Real redaction server (NOW READY — wire this first).** Fails closed if set + unreachable. |
| `ANTHROPIC_API_KEY` | *(unset → mock mapper)* | Claude mapping auto-activates when set. |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Mapping model (confirmed valid ID). |
| `SCANNER_URL` | `http://localhost:5001` | The PSQ security_scanner. |
| `PORT` / `DB_PATH` | `5003` / `corporate_quotes.db` | Flask. |

## Status — DONE & verified
- **Engine** reverse-engineered from the spreadsheet and **validated to the rand** (R457,460.93);
  full chain, questionnaire posture model, lookups in `ENGINE_ANALYSIS.md`.
- **v1 → v1.3 UI**: 4-step wizard; "Specialized Underwriting"; free per-benefit %; **MDR +
  discretionary discounts**; **Premium-without-RM-Fee** (= final ÷ 1.06); **quote types**
  New Business / Renewal / Competing Quote (benchmark comparison); **PDF** (jsPDF, branded, archived
  on Save); **up to 3 quote options** (per-option cover/FP, Save writes `REF-Opt1/2/3`).
  **FP = workbook's real R500k-upwards table** (an earlier client image was a wrong reference).
- **Ingestion Phase 1**: `/api/ingest` local convert (native PDF/Word/Excel/text) + drag-drop UI +
  scan-seed detection (domains/IPs on the form).
- **Mapping Phase 2 framework**: `redaction.py` (redact→rehydrate, swaps to `REDACTION_URL`),
  `mapping.py` (13-family/~32-control schema, ~10 minimum-requirements; **mock** engine for keyless
  local testing + **Claude** engine auto-used when key set), `/api/map`, TIDE-style **scorecard UI**
  (score /5, family ratings, favourable/deficient/missing, min-req gate). Verified on the keyless path.
- **Scanner client**: `scanner_client.py` — industry map, `trigger_scan`/`get_scan` (async poll),
  `extract_threat_surface`. Logic verified vs a sample scan result.

## Key decisions (don't re-litigate)
- **Closed environment + their own redaction server** (now ready). **Two lanes:** real inputs →
  internal scanner (on-prem, port 5001); **redacted** text → external Claude. Redaction interface =
  **service-call** (`POST text → {redacted, map}`) so we can rehydrate.
- **Claude API ≠ Max subscription** (separate product; Console key, pay-as-you-go ≈ R4/form on Sonnet).
  Org under the **insurer**, **consulting company's card** for billing (card ≠ org is fine). ZDR
  **optional** because redaction removes PII before egress.
- **Output = both**: attach gap report to quote **and** auto-fill Step 2 posture.
- Sample report to emulate = **`TIDE scan result.pdf`** ("True View": scorecard + Threat Surface).

## NEXT (priority order for the fresh session)
1. **Wire the now-ready redaction server**: set `REDACTION_URL`, confirm the `POST text → {redacted, map}`
   contract matches `redaction.py`, test redact→map→rehydrate through it; verify fail-closed.
2. **Turn on Claude**: set `ANTHROPIC_API_KEY`; run a live `/api/map` on a **sample** form first, then
   real (R&D). Sanity-check `mapping.claude_map` output shape; tune the system prompt if needed.
3. **Expand the schema** in `mapping.py` from the representative 13-family set to the **full ~150-question**
   questionnaire (structure in `ENGINE_ANALYSIS.md`).
4. **Gap-report PDF** in the True-View layout (posture scorecard **+** Threat Surface), attachable to the quote.
5. **Auto-fill Step 2** posture from the mapping; **gate** on the minimum-requirements result.
6. **Wire the scanner**: rating-app trigger+poll endpoints → "Queue external scan" (seeded by the form's
   detected domain) → render Threat Surface via `scanner_client.extract_threat_surface`; run a live baseline
   scan (`example.com`) to prove the loop.
7. **Scanned/image forms** (client has both native PDFs *and* scanned-and-emailed PDFs).
   **DONE + verified:** the toolset **auto-detects per page** whether it's a text read or needs OCR
   (`document_extract._extract_pdf` → `native`, `needs_ocr`, `text_pages`, `ocr_pages`); handles **hybrids**
   (text cover + scanned body); and **`/api/map` refuses** any doc with un-OCR'd pages (no partial mapping —
   nothing slips through). The UI chip shows "OCR required — X/Y page(s) scanned".
   **Remaining = the OCR *execution*.**
   **Preferred path (owner's intent): the redaction server handles BOTH** — for a scan, hand it the file; it
   OCRs + redacts and returns clean text → Claude. This keeps *all* sensitive processing (incl. the raw image)
   in the redaction component. **Owner flagged this is unverified — confirm it in the live test first.**
   **Fallback** (if the server turns out text-only, or OCRs poorly): add app-side OCR —
   `rapidocr-onnxruntime` (offline, no Tesseract binary), render pages via PyMuPDF → OCR → text → redaction →
   Claude. Either way OCR stays in the closed env; **never** send raw page images to Claude vision.
   `document_extract.py` flags scans as `needs_ocr=True`; for the server-handles-it path, add a mode that POSTs
   the *file* (not pre-extracted text) to the redaction server for `needs_ocr` docs.
8. Replicate the ingestion/scan layer for the **SME engine**; then **commit/deploy** when the owner says so.

## Guardrails
- The **spreadsheet is the source of truth** for rates; regenerate data via `tools/gen_corporate_data.py`
  and re-check `node test-engine.js` after any change. **Never fabricate financial figures.**
- **Verify before asserting** (run it, cite the check). Nothing is committed/pushed/deployed yet — the owner
  triggers that.
