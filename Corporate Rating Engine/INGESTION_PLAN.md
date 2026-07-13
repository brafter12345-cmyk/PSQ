# Risk-Assessment Ingestion — research + plan

Goal: ingest **any** third-party cyber risk-assessment form, convert it to text, **map it against our
questionnaire** (15-section posture model + ~35 minimum-requirement "conditions of cover"), surface what's
missing to rate & quote, and produce a **mapping report** to attach to the quote.

---

## 1. Conversion approach — research conclusion

**Recommendation: an LLM-first hybrid pipeline using Claude, with local pre-extraction.**

Why (vs. classic OCR / cloud Document AI):
- The forms are **variable-layout** ("any other risk assessment form"). Evaluations consistently show
  **LLMs beat fixed-template OCR on variable / poor-quality documents**; OCR only wins on standardized,
  unchanging templates. ([TableFlow](https://tableflow.com/blog/ocr-vs-llms), [Vellum](https://www.vellum.ai/blog/document-data-extraction-llms-vs-ocrs))
- The **end goal is semantic mapping** of arbitrary fields to *our* specific questions — that needs an LLM
  regardless, so doing extraction + mapping in one Claude pass is the simplest robust design.
- **Claude has native PDF/vision support** — it reads PDFs (incl. scanned) and images directly, up to ~100
  pages for visual analysis, ~1.5–3k tokens/page, no separate OCR engine needed. ([Claude PDF docs](https://platform.claude.com/docs/en/build-with-claude/pdf-support), [Vision docs](https://platform.claude.com/docs/en/build-with-claude/vision))
- **Volume is low** (one form per quote) so token cost is trivial (a 10-page form ≈ a few cents); the usual
  "LLMs are pricey at scale" caveat ([Mindee](https://www.mindee.com/blog/llm-vs-ocr-api-cost-comparison)) doesn't bite here.
- Phishield already runs on Claude, so one more API integration is natural.

**The pipeline:**
1. **Upload** → backend receives the file.
2. **Pre-extract locally** (cheap, on-prem, POPIA-friendly): native-text PDF → PyMuPDF; Word → python-docx;
   Excel → openpyxl; text/csv → direct. *(All available in this environment.)*
3. **Scanned / image** forms (little embedded text, detected by a chars-per-page heuristic) → render pages
   and send to **Claude vision**.
4. **Map via Claude**: feed the extracted text (or page images) + our questionnaire schema → Claude returns
   structured JSON: per-question mapped answer + confidence + the evidence snippet, plus a **minimum-requirements
   gap list**.
5. **Report**: render a mapping/gap report (to your template) to attach to the quote; the posture score can
   feed the engine's maturity modifier (replacing the manual band).

**Alternatives considered:** cloud Document AI (AWS Textract / Azure Document Intelligence / Google Document AI)
is excellent on fixed forms/tables but is cloud, per-doc priced, and still needs a separate mapping layer —
overkill here. Pure local **Tesseract / PaddleOCR / Surya** is free/offline but weaker on tables/handwriting/
variable layouts and does no mapping; useful only as an offline extraction fallback for scans.

## 2. Hosting & POPIA — closed environment + redaction server

The engine is hosted in a **closed environment** (isolated/controlled host, not the public internet), with a
**redaction server on the egress path**. The data flow is:

> upload → **local extraction (on-prem)** → **redaction server (strips PII)** → Claude (maps de-identified text) → result stays on-prem

This **removes the POPIA exposure at source**: no personal information leaves the closed environment — only
**de-identified security-control content** (backups, MFA, EDR, email/web filtering, MDR…) reaches the LLM.
That content is exactly what the mapping needs, so redacting names / SA ID numbers / account numbers / contact
details **loses nothing** for mapping a form to our security questionnaire.

- The app is **fully portable** (Flask + SQLite + static files) — it runs in a closed / air-gapped-style host;
  the *only* outbound egress is the **redacted** Claude call (Phase 2, optional).
- With redaction in place, Anthropic's commercial terms (no training on your data; 30-day retention) are more
  than sufficient; a **ZDR** agreement is optional belt-and-suspenders, and the fully-offline fallback is no
  longer needed for compliance.
- Integration: the mapping pipeline will call the redaction server via a configurable **`REDACTION_URL`** hook
  (POST text → redacted text) before any external call; if unset it fails closed (no egress).

---

## 3. What's built (Phase 1 — this session)

- `document_extract.py` — local converter: native PDF (PyMuPDF), Word (python-docx, incl. tables),
  Excel (openpyxl), text/csv; detects scanned PDFs/images and flags them for the vision step.
- `app.py` → **`POST /api/ingest`** — accepts a file (≤25 MB), extracts text, returns
  `{ok, format, pages, native, chars, needs_ocr, text, notes}`. Uploads stored under `ingest_uploads/`
  (git-ignored, not web-served).
- `assessment.html` + `assessment.js` — a **drag-&-drop upload page** (linked from the rating engine via a
  header nav) showing the extracted text + metadata chips + a (disabled) "Map to our questionnaire →" button.
- Verified end-to-end: 46-page native PDF (65,948 chars), Word tables, csv/md, and unsupported-type rejection.

**Phase 2 framework (also built this session — runs locally, no key needed):**
- `redaction.py` — **mini on-prem redaction unit**: `redact()` strips PII (emails, phones, SA ID/VAT, IPs,
  URLs + explicit known entities) to `«TOKEN»`s; `rehydrate()` restores them into the LLM output. Swaps to the
  real redaction server via **`REDACTION_URL`** (same `POST text → {redacted, map}` contract; **fails closed**
  if a remote URL is set but unreachable). Round-trip verified.
- `mapping.py` — requirement **schema** (13 families / ~32 controls, ~10 flagged as minimum requirements),
  a keyless **mock** mapper (offline keyword scan, for plumbing tests) and a **Claude** engine
  (`claude_map`, auto-used when `ANTHROPIC_API_KEY` is set), then `assemble()` → TIDE-style scorecard:
  overall score (1–5), favourable %, completeness, per-family ratings, favourable/deficient/missing controls,
  and the **minimum-requirements gate** (`ready` to rate & quote + the unmet list).
- `POST /api/map` (`{stored_as}` → redact → map → rehydrate → scorecard) + the **scorecard UI** on the
  assessment page (overall badge, family table, favourable/deficient/missing columns, min-req gate).
- Verified end-to-end in the browser on the keyless local path: upload → redact → mock-map → scorecard
  (3/5 Moderate, 13 families, min-req gate). **The mock can't read negation** ("no MDR" → reads as present)
  — it only tests the plumbing; real accuracy comes from the Claude engine once the key is set.

---

## 4. Phase 2 — mapping (next)

1. **Encode our requirement schema** from the questionnaire (already reverse-engineered in `ENGINE_ANALYSIS.md`):
   the 15 sections, each question, weight, and the ~35 column-I **minimum-requirement** controls (MFA, EDR,
   backups, email/web filtering, payment-fraud vetting, MDR…).
2. **Redact** the extracted text via the redaction server (`REDACTION_URL`) — PII out, security content in —
   before anything leaves the closed environment (fails closed if unset).
3. **Claude mapping call** (`anthropic` SDK — *not yet installed*; needs an **API key**): input = the *redacted*
   text / page images + the schema; output = per-question {answer, confidence, evidence} + gap list +
   computed posture (0–1).
4. **Gap / minimum-requirements report** (to your template) → **attach to the quote**, **and** push the computed
   posture into **Step 2** (auto-filling the maturity band). *(Both — confirmed 2026-06-09.)*

## 5. Status of open items

1. **Claude API key** — *standalone product, not the Max subscription* (subscription ≠ API). Self-service,
   ~5 min at console.anthropic.com (pay-as-you-go, no minimum). ≈ **R4/form** on Sonnet. Framework auto-uses it
   once `ANTHROPIC_API_KEY` is set; until then the keyless mock runs. **Pending the key.**
2. **Redaction server** — confirmed **yours, being finalised, not yet integrateable**. Chosen interface:
   **service-call** (`POST text → {redacted, map}`) — cleaner than a proxy because we rehydrate. The **mini
   on-prem unit is built** as the test stand-in; point `REDACTION_URL` at the real server to swap over.
3. **Sample report** — received (`TIDE scan result.pdf`, "True View"). Scorecard UI mirrors it; the
   attach-to-quote **PDF** of this report is the next build.
4. **Output** — attach report **+** auto-fill Step 2 posture: *confirmed (both)* — **next to wire**.

## 6. External scan — the form already carries the scan seeds
Quotes (corporate now, SME later) will include an **external scan** alongside the posture map — exactly like
the TIDE report's page-3 "Threat Surface" (open RDP/ports, data dumps, infra infections, website-tech CVEs).
Built this session: **`find_scan_seeds()`** pulls candidate scan targets (company **domains, websites, IPs**)
from the ingested form and surfaces them in the assessment UI. They're used **locally** to seed the scan, so
they can still be **redacted before the mapping LLM** call (no conflict). One ingestion → feeds *both* the
posture map and the scan. This should be a **shared module across the corporate + SME engines.**

## 7. Still to build (next)
- **External-scan integration** — call the existing PSQ **security scanner** with the confirmed domain → fold
  its findings into the report as a "Threat Surface" section (TIDE page 3). *(Need the scanner's interface —
  see §8.)*
- **Gap-report PDF** in the True-View layout (posture scorecard **+** external-scan section), attachable to the quote.
- **Auto-fill Step 2** — push the mapped posture into the maturity band; gate on the minimum requirements.
- **Claude engine** live test (once key) + **scanned/image** forms via **local OCR or the redaction server's
  OCR** (so text redaction still applies — *not* Claude vision, which would send un-redacted page images).
- Optional **device-lock** for the local test box.

## 8. Scanner integration — mapped + client built
The scanner is the PSQ `security_scanner` (Flask, **port 5001**, **no auth**, **async**):
- `POST /api/scan` `{domain, industry (must be in the scanner whitelist), annual_revenue_zar, sub_industry,
  country, related_domains}` → `{scan_id, poll_url}` (HTTP 202). Background thread; `MAX_CONCURRENT_SCANS`.
- Poll `GET /api/scan/{id}` → 202 pending / 200 full results (`overall_risk_score`, `risk_level`, `categories.*`).
  Typical 30–180s. Also `GET /api/scan/{id}/progress` (SSE) and `/api/scan/{id}/pdf`.
- **Threat-surface findings:** `dns_infrastructure.open_ports` + `rdp_exposed_ips`, `high_risk_protocols.exposed_services`,
  `dehashed` (credential dumps), `breaches` (HIBP), `hudson_rock` (infostealer infections), `osv_vulns`/`shodan_vulns`
  (CVEs). **Baseline scan needs no external API keys** (DeHashed/IntelX/Shodan only enrich if present).
- **Architecture:** the scanner runs **on-prem** → it gets the *real* inputs (domain/revenue/industry); redaction
  applies only to the external LLM. Two lanes: **real inputs → internal scanner**, **redacted text → external Claude**.

**Built this session:** `scanner_client.py` — `industry_for_scanner()` (our SIC main-group → scanner whitelist),
`domain_from_url()`, `trigger_scan()`, `get_scan()` (poll), `extract_threat_surface()` (→ the TIDE page-3 structure:
open ports/RDP, credential dumps, infostealer, CVEs). Logic verified against a sample scan result. Configurable via
**`SCANNER_URL`** (default `http://localhost:5001`).

**Next:** rating-app trigger+poll endpoints → a "Queue external scan" action (seeded by the form's detected
domain) → render a **Threat Surface** section into the report; live test once the scanner is running.
