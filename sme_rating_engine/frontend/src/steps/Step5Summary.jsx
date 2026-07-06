import { useMemo, useState } from 'react';
import { INDUSTRIES, COVER_LIMITS, getAvailableFPOptions } from '../rating-data.js';
import { formatR, getItooBenchmark } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import { optionLabel } from '../lib/options.js';
import { buildQuotePdf, pdfBase64 } from '../lib/pdf.js';
import { saveQuote } from '../lib/api.js';

function genQuoteRef() {
  const d = new Date();
  const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const seq = String(Math.floor(1000 + (d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds()) % 9000)).padStart(4, '0');
  return `CPB-${ymd}-${seq}`;
}

// A quote option -> the shape lib/pdf.js expects (fraction discounts).
function pdfOption(o) {
  return {
    coverIndex: o.coverIndex, fpIndex: o.fpIndex,
    postureDiscount: (parseFloat(o.posturePct) || 0) / 100,
    discretionaryDiscount: (parseFloat(o.discretionaryPct) || 0) / 100,
  };
}

// Per-option quote ref (legacy getOptionQuoteRef): baseRef-{Cover}-FP{fp}.
function optionRef(baseRef, o) {
  const cl = COVER_LIMITS[o.coverIndex].label.replace(/[\s,]/g, '');
  const afp = getAvailableFPOptions(COVER_LIMITS[o.coverIndex].key);
  const fpL = (o.fpIndex >= 0 && o.fpIndex < afp.length) ? afp[o.fpIndex].label.replace(/[\s,]/g, '') : 'BaseFP';
  return `${baseRef}-${cl}-FP${fpL}`;
}

export default function Step5Summary({ state, patch, derived, goToStep }) {
  const quoteRef = useMemo(() => state.quoteRef || genQuoteRef(), [state.quoteRef]);
  const [saveStatus, setSaveStatus] = useState(null);
  const options = state.quoteOptions;
  const industry = state.industryIndex >= 0 ? INDUSTRIES[state.industryIndex] : null;
  const conditions = derived.uw.allConditions || [];

  function downloadPdf(o) {
    const { doc, filename } = buildQuotePdf({ state, derived, quoteRef: optionRef(quoteRef, o), option: pdfOption(o) });
    doc.save(filename);
  }
  function downloadAll() {
    options.forEach((o, i) => setTimeout(() => downloadPdf(o), i * 400));
  }

  function buildPayload() {
    const first = options[0];
    let pdfB64 = null;
    if (first) {
      const { doc } = buildQuotePdf({ state, derived, quoteRef: optionRef(quoteRef, first), option: pdfOption(first) });
      pdfB64 = pdfBase64(doc);
    }
    return {
      quoteRef, baseRef: quoteRef, companyName: state.companyName,
      industryMain: industry ? industry.main : '', industrySub: industry ? industry.sub : '',
      turnoverPrev: derived.prev, turnoverCurrent: derived.current, actualTurnover: derived.actualTurnover,
      revenueBand: derived.bandLabel, employeeCount: parseInt(state.employeeCount, 10) || 0,
      quoteType: state.quoteType, marketCondition: 'Softening market for 2026',
      priorClaim: state.priorClaim, uwAnswers: state.uwAnswers, uwOutcome: derived.uw.outcome,
      uwLoadingPct: derived.uw.loadingPct, uwConditions: conditions, endorsements: state.endorsements,
      coverSelections: options.map((o) => {
        const calc = derived.optionCalcs[o.id] || {};
        const fp = getAvailableFPOptions(COVER_LIMITS[o.coverIndex].key)[o.fpIndex];
        return { coverIndex: o.coverIndex, coverLabel: COVER_LIMITS[o.coverIndex].label, fpLabel: fp ? fp.label : '', ...calc };
      }),
      postureDiscount: options[0] ? (parseFloat(options[0].posturePct) || 0) / 100 : 0,
      discretionaryDiscount: options[0] ? (parseFloat(options[0].discretionaryPct) || 0) / 100 : 0,
      competitorName: state.competitorName, competitorData: state.competitorRows,
      renewalCoverLimit: state.renewalCoverIndex >= 0 ? COVER_LIMITS[state.renewalCoverIndex].label : '',
      renewalPremium: derived.renewalPremiumNum, coverLabel: first ? COVER_LIMITS[first.coverIndex].label : 'quote',
      createdBy: state.createdBy || '', pdfBase64: pdfB64,
    };
  }
  async function saveNow() {
    setSaveStatus('saving');
    try { await saveQuote(buildPayload()); if (!state.quoteRef) patch({ quoteRef }); setSaveStatus('saved'); }
    catch { setSaveStatus('error'); }
  }
  function copyClipboard() {
    const lines = [`Phishield SME Cyber Quote — ${quoteRef}`, `Company: ${state.companyName}`,
      `Industry: ${industry ? industry.sub : '—'}`, `Turnover: ${formatR(derived.actualTurnover)} (${derived.bandLabel})`, `UW: ${derived.uw.outcome}`, ''];
    options.forEach((o) => {
      const c = derived.optionCalcs[o.id]; if (!c) return;
      lines.push(`${optionLabel(o.coverIndex, o.fpIndex)}: R${c.annual.toLocaleString('en-ZA')}/yr · R${c.monthly.toLocaleString('en-ZA')}/mo`);
    });
    navigator.clipboard?.writeText(lines.join('\n'));
  }

  return (
    <section className="step-panel active" id="step-5">
      <div className="glass-card">
        <div className="step-header"><h2>Quote Summary</h2><p>Review the full quote breakdown before exporting.</p></div>
        <div className="quote-ref">{quoteRef}</div>

        <div className="summary-section">
          <h3>Client Details</h3>
          <div className="summary-grid">
            <SItem label="Company" value={state.companyName || '—'} />
            <SItem label="Industry" value={industry ? industry.sub : '—'} />
            <SItem label="Turnover" value={formatR(derived.actualTurnover)} />
            <SItem label="Revenue Bracket" value={derived.bandLabel || '—'} />
            <SItem label="Website" value={state.websiteAddress || '—'} />
            <SItem label="Quote Type" value={state.quoteType} />
          </div>
        </div>

        <div className="summary-section">
          <h3>Underwriting</h3>
          <div className="summary-grid">
            <SItem label="UW Outcome" value={(derived.uw.outcome || '—').toUpperCase()} />
            <SItem label="Loadings" value={derived.uw.loadingPct > 0 ? `${Math.round(derived.uw.loadingPct * 100)}%` : 'None'} />
            <SItem label="Conditions of Cover" value={conditions.length ? `${conditions.length} noted` : 'None'} />
          </div>
        </div>

        {state.priorClaim && (
          <div className="prior-claim-note" style={{ display: 'flex' }}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            <span>Prior claim flagged. Additional underwriting review applied.</span>
          </div>
        )}
        {conditions.length > 0 && (
          <div className="summary-section"><h3>Conditions of Cover</h3>
            <ul className="summary-endorsements">{conditions.map((c, i) => <li key={i}>{c}</li>)}</ul></div>
        )}
        {state.endorsements.trim() && (
          <div className="summary-section"><h3>Endorsements / Notes</h3><div className="summary-endorsements">{state.endorsements}</div></div>
        )}

        {/* Per-option breakdown cards */}
        <div className="quote-breakdowns">
          {options.length === 0 && <p className="field-hint">No cover selected — go back to Step 2.</p>}
          {options.map((o) => {
            const calc = derived.optionCalcs[o.id];
            if (!calc) return null;
            const fp = getAvailableFPOptions(COVER_LIMITS[o.coverIndex].key)[o.fpIndex];
            const bench = getItooBenchmark(derived.actualTurnover, o.coverIndex);
            return (
              <div className="quote-breakdown-card" key={o.id}>
                <h4>Cover Limit: {COVER_LIMITS[o.coverIndex].label}{fp ? ` · FP ${fp.label}` : ''}{calc.isMicro ? ' · Micro SME' : ''}</h4>
                <table className="audit-trail">
                  <thead><tr><th>Step</th><th>Description</th><th>Value</th></tr></thead>
                  <tbody>{calc.breakdown.map((b, i) => (
                    <tr key={i}><td>{b.step}</td><td>{b.desc}</td><td>{formatR(b.value)}</td></tr>
                  ))}</tbody>
                </table>
                <div className="breakdown-finals">
                  <div className="breakdown-final-item"><span>With FP</span><strong>{formatR(calc.annual)}</strong></div>
                  <div className="breakdown-final-item"><span>Excl FP</span><strong>{formatR(calc.annualExFP)}</strong></div>
                  <div className="breakdown-final-item"><span>Monthly</span><strong>{formatR(calc.monthly)}</strong></div>
                </div>
                {bench && (
                  <div className="breakdown-comparison">
                    <span>Industry: {formatR(bench.premium)}</span>
                    <span>Delta: {calc.annual - bench.premium <= 0 ? '' : '+'}{formatR(calc.annual - bench.premium)}</span>
                  </div>
                )}
                {parseCurrency(o.manualOverride) > 0 && (
                  <div className="breakdown-comparison"><span>Manual override: {formatR(parseCurrency(o.manualOverride))}</span></div>
                )}
                {options.length >= 2 && (
                  <div className="btn-row" style={{ marginTop: 8 }}>
                    <button type="button" className="btn btn-ghost" onClick={() => downloadPdf(o)}>Download this PDF</button>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="btn-row"><button type="button" className="btn btn-ghost" onClick={() => goToStep(4)}>Back</button></div>

        <div className="btn-row">
          <button type="button" className="btn btn-primary btn-print" onClick={() => window.print()}>Print Quote</button>
          <button type="button" className="btn btn-ghost btn-clipboard" onClick={copyClipboard}>Copy to Clipboard</button>
          {options.length <= 1 && (
            <button type="button" className="btn btn-primary btn-download-pdf" disabled={!options[0]} onClick={() => downloadPdf(options[0])}>Download PDF</button>
          )}
          {options.length >= 2 && (
            <button type="button" className="btn btn-download-all" onClick={downloadAll}>Download All PDFs</button>
          )}
          <button type="button" className="btn btn-primary" disabled={!options[0] || saveStatus === 'saving'} onClick={saveNow}>
            {saveStatus === 'saved' ? 'SAVED ✓' : saveStatus === 'saving' ? 'Saving…' : saveStatus === 'error' ? 'Save failed — retry' : 'Save Quote'}
          </button>
        </div>

        <p className="footer-note-internal">Internal use only. Premiums are indicative and subject to final underwriting approval.</p>
      </div>
    </section>
  );
}

function SItem({ label, value }) {
  return (
    <div className="summary-item">
      <div className="summary-label">{label}</div>
      <div className="summary-value">{value}</div>
    </div>
  );
}
