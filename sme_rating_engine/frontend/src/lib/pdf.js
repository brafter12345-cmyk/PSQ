import { jsPDF } from 'jspdf';
import { formatR, calculatePremium, getItooBenchmark } from '../rating-engine.js';
import {
  INDUSTRIES, REVENUE_BANDS, COVER_LIMITS, MARKET_CONDITION_LABEL, getAvailableFPOptions,
} from '../rating-data.js';
import { parseCurrency } from './format.js';

// Client quote PDF — layout ported VERBATIM from the legacy vanilla
// `generatePDF` (sme-rating.js). Coordinates, colours, fonts, boxes, and text
// are byte-for-byte the same; only the data source is adapted (the legacy global
// `state` -> this app's state + engine-derived values). `option` is one quote
// option ({ coverIndex, fpIndex, postureDiscount, discretionaryDiscount } — the
// legacy optionOverride path, one cover per PDF). Returns { doc, filename }.
export function buildQuotePdf({ state, derived, quoteRef, option }) {
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageW = 210;
  const margin = 18;
  const contentW = pageW - margin * 2;
  let y = 15;
  const lineH = 5;

  // Adapted data handles (legacy read these off the global `state`).
  const actualTurnover = derived.actualTurnover;
  const revenueBandIndex = derived.revenueBandIndex;
  const uw = derived.uw;

  function checkPage(needed) {
    if (y + (needed || 10) > 280) { doc.addPage(); y = 15; }
  }
  function addText(text, size, style, color, x) {
    checkPage(size * 0.5);
    doc.setFontSize(size || 9);
    doc.setFont('helvetica', style || 'normal');
    doc.setTextColor(...(color || [51, 51, 51]));
    const lines = doc.splitTextToSize(String(text), contentW - (x ? x - margin : 0));
    doc.text(lines, x || margin, y);
    y += lines.length * lineH + 1;
  }
  function addSpacer(h) { y += h || 3; }
  function addRule() {
    doc.setDrawColor(200, 210, 220);
    doc.line(margin, y, pageW - margin, y);
    y += 4;
  }
  function addSection(title) {
    addSpacer(2);
    doc.setFillColor(0, 40, 80);
    doc.rect(margin, y - 1, contentW, 7, 'F');
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(255, 255, 255);
    doc.text(title, margin + 3, y + 4);
    y += 10;
  }
  function addField(label, value, labelW) {
    checkPage(8);
    const lw = labelW || 42;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(120, 120, 120);
    doc.text(label, margin + 2, y);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 30, 30);
    doc.text(String(value), margin + lw, y);
    y += lineH + 1;
  }

  // Benchmark for a cover (renewal -> existing policy; else IToo industry).
  function getBenchmark(coverIndex) {
    if (state.quoteType === 'renewal' && parseCurrency(state.renewalPremium) > 0) {
      return { premium: parseCurrency(state.renewalPremium), label: 'Existing Policy', deductible: 0 };
    }
    const itoo = getItooBenchmark(actualTurnover, coverIndex);
    if (itoo) return { premium: itoo.premium, label: 'Industry Benchmark', deductible: itoo.deductible };
    return null;
  }

  // ── Header Bar ──
  doc.setFillColor(0, 25, 50);
  doc.rect(0, 0, pageW, 20, 'F');
  doc.setFillColor(0, 180, 216);
  doc.rect(0, 20, pageW, 0.8, 'F');
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 180, 216);
  doc.text('Phishield', margin, 12);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(160, 175, 190);
  doc.text('SME Rating Engine — Quote Output', margin + 40, 12);
  doc.text(new Date().toLocaleDateString('en-ZA', { year: 'numeric', month: 'long', day: 'numeric' }), pageW - margin, 12, { align: 'right' });
  y = 26;

  // ── Quote Reference ──
  const pdfQuoteRef = quoteRef;
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('Quote Ref: ' + pdfQuoteRef, margin, y);
  y += 8;
  addRule();

  // ── Client Details ──
  addSection('CLIENT DETAILS');
  addField('Company:', state.companyName);
  if (state.industryIndex >= 0) {
    addField('Industry:', INDUSTRIES[state.industryIndex].main + ' — ' + INDUSTRIES[state.industryIndex].sub);
  }
  addField('Actual Turnover:', formatR(actualTurnover));
  addField('Revenue Bracket:', revenueBandIndex >= 0 ? REVENUE_BANDS[revenueBandIndex].label : '--');
  if (state.websiteAddress) addField('Website:', state.websiteAddress);
  const qtLabels = { new: 'New Business', renewal: 'Renewal', competing: 'Competing Quote' };
  addField('Quote Type:', qtLabels[state.quoteType] || '--');
  if (state.quoteType === 'renewal') {
    addField('Market Condition:', MARKET_CONDITION_LABEL);
  }
  if (state.competitorName) {
    addField('Competitor:', state.competitorName);
  }
  addSpacer(2);

  // ── Underwriting ──
  addSection('UNDERWRITING');
  const outcomeLabels = { standard: 'Standard Rates', caution: 'Proceed with Caution', loading: Math.round(uw.loadingPct * 100) + '% Loading', decline: 'Declined', refer: 'Refer to Senior UW' };
  addField('Outcome:', outcomeLabels[uw.outcome] || '--');
  addField('Loading:', uw.loadingPct > 0 ? Math.round(uw.loadingPct * 100) + '%' : 'None');
  if (state.uwEndpointVendor) addField('Endpoint Security:', state.uwEndpointVendor);
  if (state.uwAnswers && state.uwAnswers['q8'] === true && (state.uwPriorInsurer || state.uwPriorInceptionDate)) {
    if (state.uwPriorInsurer)        addField('Prior Insurer:', state.uwPriorInsurer);
    if (state.uwPriorInceptionDate)  addField('Prior Inception:', state.uwPriorInceptionDate);
  }
  const pdfAllConds = [].concat(uw.q1Conditions || [], uw.fpConditions || []);
  if (pdfAllConds.length > 0) {
    addField('Conditions of Cover:', '');
    pdfAllConds.forEach((c, idx) => {
      checkPage(20);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(180, 130, 0);
      const bulletText = (idx + 1) + '. ' + c;
      const wrappedLines = doc.splitTextToSize(bulletText, contentW - 10);
      doc.text(wrappedLines, margin + 4, y);
      y += wrappedLines.length * (lineH - 0.5) + 3;
    });
  } else {
    addField('Conditions of Cover:', 'None');
  }
  if (state.priorClaim) {
    addSpacer(2);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(200, 50, 50);
    doc.text('! Prior claim flagged — additional underwriting required', margin + 2, y);
    y += lineH + 2;
  }
  // Renewal caveats — the premium-drop-protection ladder is not yet ported to the
  // React app, so these flags are absent (false) and the caveats stay inert; the
  // existing-FP line still prints.
  if (state.quoteType === 'renewal') {
    const renewalFPLimit = parseCurrency(state.renewalFPLimit);
    if (renewalFPLimit > 0) {
      addField('Existing FP Sub-limit:', formatR(renewalFPLimit));
    }
    if (uw.loadingPct > 0) {
      addSpacer(1);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'italic');
      doc.setTextColor(90, 90, 90);
      const pct = Math.round(uw.loadingPct * 100);
      const msg = 'Comparison caveat: new premium includes ' + pct + '% UW loading (Q2.1–Q5). Prior posture not on record — year-on-year comparison not strictly like-for-like.';
      const wrapped = doc.splitTextToSize(msg, contentW - 6);
      doc.text(wrapped, margin + 2, y);
      y += wrapped.length * (lineH - 0.5) + 3;
    }
  }
  addSpacer(2);

  // ── Endorsements ──
  if (state.endorsements) {
    addSection('ENDORSEMENTS / NOTES');
    const endorseLines = doc.splitTextToSize(state.endorsements, contentW - 6);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(80, 80, 80);
    endorseLines.forEach(line => {
      checkPage(6);
      doc.text(line, margin + 3, y);
      y += lineH;
    });
    addSpacer(3);
  }

  // ── Per Cover Limit Breakdown (one option per PDF — legacy optionOverride path) ──
  const pdfCovers = option ? [option] : [];

  pdfCovers.forEach((opt) => {
    const ci = opt.coverIndex;
    const calc = calculatePremium(ci, derived.engineBase, {
      fpIndex: opt.fpIndex,
      postureDiscount: opt.postureDiscount || 0,
      discretionaryDiscount: opt.discretionaryDiscount || 0,
    });
    if (!calc) return;

    checkPage(60);
    // Legacy optionOverride path uses the option label: "R5M / FP R250k".
    const availFPsec = getAvailableFPOptions(COVER_LIMITS[ci].key);
    const fpLblSec = (opt.fpIndex >= 0 && opt.fpIndex < availFPsec.length) ? availFPsec[opt.fpIndex].label : 'Base FP';
    const sectionLabel = COVER_LIMITS[ci].label + ' / FP ' + fpLblSec;
    addSection('COVER LIMIT: ' + sectionLabel + (calc.isMicro ? '  (Micro SME)' : ''));

    // Audit trail as table
    const colX = [margin + 2, margin + 14, margin + contentW - 25];
    const rowH = 8;
    doc.setFillColor(235, 240, 248);
    doc.rect(margin, y, contentW, rowH, 'F');
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(80, 80, 80);
    const headerTextY = y + rowH * 0.6;
    doc.text('STEP', colX[0], headerTextY);
    doc.text('DESCRIPTION', colX[1], headerTextY);
    doc.text('VALUE', colX[2] + 20, headerTextY, { align: 'right' });
    y += rowH + 1;

    calc.breakdown.forEach((b, idx) => {
      checkPage(rowH + 2);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentW, rowH, 'F');
      }
      const textY = y + rowH * 0.55;
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(0, 100, 160);
      doc.text(String(b.step), colX[0], textY);
      doc.setTextColor(50, 50, 50);
      doc.text(b.desc, colX[1], textY);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 30, 30);
      doc.text(formatR(b.value), colX[2] + 20, textY, { align: 'right' });
      y += rowH;
    });
    addSpacer(4);

    // Final premiums box
    checkPage(22);
    doc.setFillColor(235, 245, 255);
    doc.rect(margin, y, contentW, 16, 'F');
    doc.setDrawColor(0, 150, 200);
    doc.rect(margin, y, contentW, 16, 'S');
    const thirdW = contentW / 3;
    const boxY = y + 5;
    doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 100, 100);
    doc.text('ANNUAL (WITH FP)', margin + thirdW * 0.5, boxY, { align: 'center' });
    doc.setFontSize(12); doc.setFont('helvetica', 'bold'); doc.setTextColor(0, 100, 170);
    doc.text(formatR(calc.annual), margin + thirdW * 0.5, boxY + 7, { align: 'center' });
    doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 100, 100);
    doc.text('ANNUAL (EXCL FP)', margin + thirdW * 1.5, boxY, { align: 'center' });
    doc.setFontSize(12); doc.setFont('helvetica', 'bold'); doc.setTextColor(50, 50, 50);
    doc.text(formatR(calc.annualExFP), margin + thirdW * 1.5, boxY + 7, { align: 'center' });
    doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 100, 100);
    doc.text('MONTHLY', margin + thirdW * 2.5, boxY, { align: 'center' });
    doc.setFontSize(12); doc.setFont('helvetica', 'bold'); doc.setTextColor(0, 100, 170);
    doc.text(formatR(calc.monthly), margin + thirdW * 2.5, boxY + 7, { align: 'center' });
    y += 20;

    // Total Premium without RM Fee (internal back-office figure — admin platform adds 6%)
    var rmAnnual = calc.annual / 1.06;
    var rmMonthly = Math.ceil(rmAnnual / 12);
    var rmBoxH = 17;
    checkPage(rmBoxH + 9);
    doc.setFillColor(245, 250, 255);
    doc.rect(margin, y, contentW, rmBoxH, 'F');
    doc.setDrawColor(0, 150, 200);
    doc.rect(margin, y, contentW, rmBoxH, 'S');
    var rmCx = margin + contentW / 2;
    doc.setFontSize(10.2); doc.setFont('helvetica', 'bold'); doc.setTextColor(60, 60, 60);
    doc.text('Total Premium without RM Fee', rmCx, y + 6.5, { align: 'center' });
    doc.setFontSize(13); doc.setTextColor(0, 100, 170);
    doc.text(formatR(rmAnnual) + ' /yr        ' + formatR(rmMonthly) + ' /mo', rmCx, y + 13.5, { align: 'center' });
    y += rmBoxH + 3;
    doc.setFontSize(6.5); doc.setFont('helvetica', 'italic'); doc.setTextColor(120, 120, 120);
    doc.text('Capture this figure on the administration platform, which adds a 6% fee to the input premium.', margin + 3, y);
    y += 6;

    // Comparison row
    const pdfBenchmark = getBenchmark(ci);
    const compRowData = state.competitorRows.find((r) => r.coverIndex === ci);
    const compPrem = compRowData ? parseCurrency(compRowData.competitorPremium) : 0;
    const compRow = compPrem > 0 ? { competitorPremium: compPrem } : null;
    if (pdfBenchmark || (compRow && compRow.competitorPremium > 0)) {
      checkPage(10);
      doc.setFontSize(7); doc.setFont('helvetica', 'normal'); doc.setTextColor(100, 100, 100);
      let compText = '';
      if (pdfBenchmark) compText += pdfBenchmark.label + ': ' + formatR(pdfBenchmark.premium);
      if (compRow && compRow.competitorPremium > 0) compText += '    |    Competitor: ' + formatR(compRow.competitorPremium);
      if (pdfBenchmark) {
        const pdfCompareAmt = state.competitorHasFP ? calc.annual : calc.annualExFP;
        const d = pdfCompareAmt - pdfBenchmark.premium;
        const pct = Math.round(d / pdfBenchmark.premium * 100);
        compText += '    |    Delta (' + (state.competitorHasFP ? 'with FP' : 'ex-FP') + '): ' + (d <= 0 ? '' : '+') + formatR(Math.abs(d)) + ' (' + (d <= 0 ? '' : '+') + pct + '%)';
      }
      doc.text(compText, margin + 2, y);
      y += 6;
    }

    addSpacer(4);
    addRule();
  });

  // ── Footer ──
  addSpacer(6);
  doc.setFontSize(7);
  doc.setFont('helvetica', 'italic');
  doc.setTextColor(150, 150, 150);
  doc.text('Internal use only. Premiums are indicative and subject to final underwriting approval.', margin, y);
  y += 4;
  doc.text('Phishield SME Rating Engine © 2026. Not for distribution.', margin, y);

  // Filename (legacy optionOverride: companySlug_Cover_FPxxx.pdf)
  const companySlug = (state.companyName || 'quote').replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_');
  let coverLabels = 'quote';
  if (option) {
    const cl = COVER_LIMITS[option.coverIndex].label.replace(/[\s,]/g, '');
    const afp = getAvailableFPOptions(COVER_LIMITS[option.coverIndex].key);
    const fpL = (option.fpIndex >= 0 && option.fpIndex < afp.length) ? afp[option.fpIndex].label.replace(/[\s,]/g, '') : 'BaseFP';
    coverLabels = cl + '_FP' + fpL;
  }
  const filename = companySlug + '_' + coverLabels + '.pdf';
  return { doc, filename };
}

// data:...;base64,XXXX -> XXXX  (for backend storage, like the legacy pdfBase64).
export function pdfBase64(doc) {
  const uri = doc.output('datauristring');
  return uri.substring(uri.indexOf(',') + 1);
}
