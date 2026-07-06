import { jsPDF } from 'jspdf';
import { formatR } from '../rating-engine.js';
import { COVER_LIMITS, getAvailableFPOptions } from '../rating-data.js';

// Build a client quote PDF for the selected cover. Returns { doc, filename }.
// Clean, self-contained layout (the legacy jsPDF coordinate layout can be
// ported verbatim later if the exact branding is required — this carries the
// same content: client, cover, premiums, audit trail, UW outcome, conditions).
export function buildQuotePdf({ state, derived, quoteRef }) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = 48;
  let y = 0;

  const calc = derived.selectedCalc;
  const cover = COVER_LIMITS[state.selectedCoverIndex];
  const fpIdx = state.fpSelections[state.selectedCoverIndex] ?? 0;
  const fpOpt = getAvailableFPOptions(cover.key)[fpIdx];

  const line = (txt, { size = 10, style = 'normal', color = [40, 40, 40], x = M, gap = 16 } = {}) => {
    if (y > H - M) { doc.addPage(); y = M; }
    doc.setFont('helvetica', style);
    doc.setFontSize(size);
    doc.setTextColor(color[0], color[1], color[2]);
    doc.text(String(txt), x, y);
    y += gap;
  };
  const rule = () => { doc.setDrawColor(210); doc.line(M, y, W - M, y); y += 14; };
  const kv = (k, v) => {
    doc.setFont('helvetica', 'normal'); doc.setFontSize(10); doc.setTextColor(110);
    doc.text(k, M, y);
    doc.setFont('helvetica', 'bold'); doc.setTextColor(30);
    doc.text(String(v), M + 190, y);
    y += 16;
  };

  // Header band
  doc.setFillColor(11, 18, 32);
  doc.rect(0, 0, W, 78, 'F');
  doc.setTextColor(255); doc.setFont('helvetica', 'bold'); doc.setFontSize(20);
  doc.text('Phishield', M, 42);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(10); doc.setTextColor(0, 180, 216);
  doc.text('Cyber Protect Business Policy — Quote', M, 60);
  doc.setTextColor(200); doc.setFontSize(9);
  doc.text(quoteRef || '', W - M, 42, { align: 'right' });
  y = 108;

  line('Quote Summary', { size: 14, style: 'bold', color: [11, 18, 32], gap: 22 });
  kv('Company', state.companyName || '—');
  kv('Quote Type', state.quoteType);
  kv('Actual Turnover', formatR(derived.actualTurnover));
  kv('Revenue Band', derived.revenueBandIndex >= 0 ? derived.bandLabel : '—');
  kv('Cover Limit', cover ? cover.label : '—');
  kv('Funds Protect', fpOpt ? `${fpOpt.label} (${formatR(fpOpt.cost)}/yr)` : '—');
  y += 6; rule();

  if (calc) {
    line('Premium', { size: 12, style: 'bold', color: [11, 18, 32], gap: 20 });
    kv('Annual (incl. Funds Protect)', formatR(calc.annual));
    kv('Annual (excl. Funds Protect)', formatR(calc.annualExFP));
    kv('Monthly', formatR(calc.monthly));
    if (calc.isMicro) kv('Rating', 'Micro SME rates applied');
    y += 6; rule();

    line('Audit Trail', { size: 12, style: 'bold', color: [11, 18, 32], gap: 20 });
    calc.breakdown.forEach((b) => {
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(90);
      doc.text(`${b.step}.`, M, y);
      doc.text(String(b.desc), M + 18, y);
      doc.setFont('helvetica', 'bold'); doc.setTextColor(30);
      doc.text(formatR(b.value), W - M, y, { align: 'right' });
      y += 15;
      if (y > H - M) { doc.addPage(); y = M; }
    });
    y += 6; rule();
  }

  // Underwriting
  line('Underwriting', { size: 12, style: 'bold', color: [11, 18, 32], gap: 20 });
  kv('Outcome', (derived.uw.outcome || '—').toUpperCase());
  if (derived.uw.loadingPct > 0) kv('Loading', `${Math.round(derived.uw.loadingPct * 100)}%`);
  const conds = derived.uw.allConditions || [];
  if (conds.length) {
    y += 4;
    line('Conditions of Cover:', { size: 10, style: 'bold', color: [30, 30, 30], gap: 16 });
    conds.forEach((c) => {
      const wrapped = doc.splitTextToSize('• ' + c, W - 2 * M);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(70);
      wrapped.forEach((w) => { if (y > H - M) { doc.addPage(); y = M; } doc.text(w, M, y); y += 13; });
    });
  }
  if (state.endorsements && state.endorsements.trim()) {
    y += 6; rule();
    line('Endorsements / Notes', { size: 12, style: 'bold', color: [11, 18, 32], gap: 18 });
    doc.splitTextToSize(state.endorsements.trim(), W - 2 * M).forEach((w) => {
      if (y > H - M) { doc.addPage(); y = M; }
      doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(70);
      doc.text(w, M, y); y += 13;
    });
  }

  // Footer
  doc.setFontSize(8); doc.setTextColor(150);
  doc.text('Internal use only. Premiums are indicative and subject to final underwriting approval. Administrator: Phishield UMA (Pty) Ltd. Insurer: Bryte Insurance Company Limited.', M, H - 28, { maxWidth: W - 2 * M });

  const safeCompany = (state.companyName || 'quote').replace(/[^\w -]/g, '_');
  const filename = `${quoteRef || 'quote'}_${cover ? cover.label : ''}_${safeCompany}.pdf`.replace(/\s+/g, '_');
  return { doc, filename };
}

// data:...;base64,XXXX -> XXXX  (for backend storage, like the legacy pdfBase64).
export function pdfBase64(doc) {
  const uri = doc.output('datauristring');
  return uri.substring(uri.indexOf(',') + 1);
}
