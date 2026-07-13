# Corporate Rating Engine — SME nuances to port + new ideas

Written 2026-06-09 in response to "research more nuances we implement from the SME rating engine, and come up with a few ideas on what to add additionally." Prioritised; nothing here is built yet unless noted under §0.

---

## 0. Already added (v1.1 + v1.2)

**v1.1**
- Header → **"Specialized Underwriting"**; turnover hard-floor relaxed to a soft band (SME cross-over cases coming).
- Industry shows the **full "Main – Sub" label** after selection.
- Benefits gained a **free % column** (0–100%) alongside the preset dropdown; sub-limit Rand auto-adjusts; engine prices any ratio via the `×√ratio` contribution.
- **Funds Protect** is a free input + dropdown, priced from the **workbook's actual FP table (from R500k up**: 500k→6,054.55 … 10M→196,198), interpolated between anchors, with a **<10%-of-cover warning**. *(An earlier image table was reverted — it was a different/SME reference; the corporate engine's real FP runs from R500k.)*
- **Sophos MDR** shows the discount % and Rand amount; **discretionary discount/loading** field, recorded on the quote.
- **Cover Comparison** table in the quote (same inputs across every cover limit, with "Use" to switch).

**v1.2 (this batch)**
- **Excess** reverted to the clean **select** (the datalist double-counting is gone); FP datalist also de-duplicated.
- **Quote types** — **New Business / Renewal / Competing Quote** selector on Step 1, with distinct branches:
  - *Renewal* → existing cover/premium/FP inputs + market-condition badge → "vs Existing Policy" comparison bars + retention %, with a >20%-drop caution.
  - *Competing Quote* → competitor name/premium/limit + "competitor incl FP?" toggle → "vs Competitor" comparison bars (like-for-like with/ex-FP) + cheaper/within/above verdict.
- **Premium without RM Fee** — prominent box on the quote (annual `÷1.06` + monthly), matching the SME final step and the workbook's "Excl. RM" (D36). Also in the PDF.
- **PDF output** (jsPDF) — branded A4 quote: header, client details, full premium build-up, final-premium box (incl. the premium-without-RM line), benchmark line, insuring clauses. "Download PDF" button; **Save Quote** also archives the PDF server-side under `quote_pdfs/YYYY/MM/Company/REF.pdf`.

**v1.3 (this batch)**
- **Funds Protect reverted to the workbook's real R500k-upwards table** (so the validated example is back to **R457,461**). The earlier client image was a different reference and has been dropped.
- **Up to 3 quote options** (SME-style "optional quotes") — a Quote-Options bar on Step 4; click a card to view it, vary **cover** and **Funds Protect** per option, "+ Add" (capped at 3), remove. **Download PDF** emits one PDF per option; **Save** writes one record per option (`REF-Opt1/2/3`, shared base ref). Other inputs (industry, maturity, benefits, MDR, excess, discretionary, quote type) are shared across options.

---

## A. SME nuances worth porting (in priority order)

1. **Competitor benchmarking + live comparison bars** — SME has `ITOO_BENCHMARKS` (competitor pricing, FP-excluded) and renders the Phishield figure against competitors as bars in real time. *Corporate has no benchmark dataset yet* — we'd need corporate-band competitor numbers (or a reinsurer/treaty reference). Slots into the Quote step beside the existing SME-equivalent line. **Needs data.**

2. **Renewal flow** — SME treats the prior-year premium as the benchmark and has *premium-drop protection* (if the new premium at the same cover is <80% of expiring, it nudges cover up to retain ≥90%, surfacing intermediate covers as alternatives) plus market-condition-driven up/downgrade suggestions. High value for a corporate book with annual renewals. Add a "New / Renewal" toggle on Step 1 with three renewal inputs (expiring cover, premium, FP).

3. **Market-condition indicator** — SME exposes `MARKET_CONDITION` (softening / stable / hardening, currently "Softening 2026") as a read-only badge that also drives renewal options. Cheap to add as a header chip; one constant in `corporate-data.js`.

4. **Underwriting outcomes & conditions of cover** — SME's `evaluateUW()` produces standard / caution / loading / decline / refer with a conditions list and endorsements. For Corporate this is the natural home for the **questionnaire's column-I flags** (→ conditions of cover) and **Section 14 claims history** (→ refer). Pairs with v2.

5. **Client-rendered PDF (jsPDF)** — SME builds a structured quote PDF client-side and archives it under `quote_pdfs/YYYY/MM/Company/`. We already left the backend hook (`pdf_base64`); add a jsPDF template so "Print/PDF" produces a branded schedule, not just the browser print.

6. **Quote history / search view** — the backend already exposes `GET /api/quotes`; add a lightweight "recent quotes" panel (search by company) like SME, so underwriters can reopen/duplicate.

7. **Endorsements / special-conditions free-text** — SME captures endorsements that print on the schedule. Add a textarea on the Quote step, persisted and shown in output.

8. **Combined-discount cap** — SME caps posture + discretionary at ~35%. Add a soft cap/warning on the discretionary field (and later posture) so a quote can't be over-discounted without an explicit override.

---

## B. New corporate-specific ideas

1. **Full security questionnaire (v2, already planned)** — the 150-question weighted tree that auto-computes the 0–1 posture (→ maturity modifier, replacing the manual band) and emits the ~35 conditions of cover. The single biggest value-add; everything in §A.4 hangs off it.

2. **Premium-as-%-of-cover sanity band** — the spreadsheet has a "TEST against cover amount" note: the premium should sit ~1–8% of cover (higher turnover → nearer 8%). Surface a green/amber flag on the Quote showing where this quote lands, to catch mis-keyed inputs.

3. **Cover-adequacy check** — we already compute the *expected industry breach cost* (R28.3M in the example). Show cover vs expected breach cost as a ratio ("cover = 1.8× expected breach cost") so the underwriter can judge adequacy.

4. **Excess optimiser** — same idea as the cover comparison but sweeping the deductible, so the broker can show the premium/excess trade-off curve.

5. **R150M cover tier** — currently `TBC` in the workbook (engine covers R5M–R100M). Add once its base constant is set.

6. **SME cross-over handler** — for the sub-R250M "specialised" cases you mentioned: a mode that pulls the SME premium (or the SME/Corporate-ratio line we already show, ×0.6173) and blends/compares, so the hand-off from the SME engine is explicit. *You said you'll guide this — flagged for when you do.*

7. **Rate-table version stamp** — record the source-workbook date on every saved quote (and show it), so a quote is reproducible even after the rates change. Cheap traceability.

8. **Depository/financial visibility** — when the depository-institution modifier applies (×2.5→1.0 by turnover band) surface it explicitly on Step 1, since it materially moves the premium (×1.65 in testing).

---

## C. Open questions / decisions for you

1. **Funds Protect R250k pricing — RESOLVED 2026-06-09.** You supplied the official annual FP
   contribution table (150k→2,100 · 200k→2,616 · 250k→3,144 · 500k→4,800 · 1M→9,108 · 1.5M→15,756 ·
   2M→26,640 · 2.5M→31,680 · 3M→42,420 · 4M→56,760 · 5M→71,160). This is now the **adjustable** FP
   schedule (broker-selectable from R250k; off-table amounts interpolate between these anchors).
   It supersedes the workbook's FP figures, so the validated example shifts: R2M FP R24,420 → **R26,640**,
   final R457,461 → **R459,823**.
   - **Still open:** the **standard** (auto, 10%-of-cover) FP still uses the *workbook* table
     (500k→6,054.55 … 10M→132,840), because it needs values up to R10M for the largest covers, which
     the new table (max R5M) doesn't cover. So right now the same R500k FP costs R4,800 (adjustable)
     vs R6,054.55 (standard 10%-of-cover). **Do you want standard 10%-of-cover FP to adopt the new
     figures too?** If so I need the R7.5M and R10M contributions (for 75M / 100M covers' 10%).

2. **<10%-FP warning wording** — I used a generic message; if the SME engine has specific wording you want matched verbatim, paste it and I'll align.

3. **Discretionary cap** — should corporate cap discretionary discount (SME ≈35%)? At what %? Hard block or soft warning?

4. **Comparison scope** — the cover comparison currently sweeps the 8 cover tiers. Do you want it to also (a) compare competitor/benchmark figures (needs data), and/or (b) be a full SME-style multi-option quote (per-option FP/discount, one PDF each)?
