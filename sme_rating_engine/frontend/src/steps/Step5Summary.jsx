import { useMemo, useState } from 'react';
import { INDUSTRIES, COVER_LIMITS, getAvailableFPOptions } from '../rating-data.js';
import { formatR } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import { buildQuotePdf, pdfBase64 } from '../lib/pdf.js';
import { saveQuote } from '../lib/api.js';

function genQuoteRef() {
  const d = new Date();
  const ymd = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  const seq = String(Math.floor(1000 + (d.getHours() * 3600 + d.getMinutes() * 60 + d.getSeconds()) % 9000)).padStart(4, '0');
  return `CPB-${ymd}-${seq}`;
}

export default function Step5Summary({ state, patch, derived, goToStep }) {
  const quoteRef = useMemo(() => state.quoteRef || genQuoteRef(), [state.quoteRef]);
  const [saveStatus, setSaveStatus] = useState(null); // null | 'saving' | 'saved' | 'error'
  const calc = derived.selectedCalc;
  const cover = state.selectedCoverIndex >= 0 ? COVER_LIMITS[state.selectedCoverIndex] : null;
  const industry = state.industryIndex >= 0 ? INDUSTRIES[state.industryIndex] : null;
  const fpIdx = cover ? (state.fpSelections[state.selectedCoverIndex] ?? 0) : 0;
  const fpOpt = cover ? getAvailableFPOptions(cover.key)[fpIdx] : null;
  const conditions = derived.uw.allConditions || [];

  function buildPayload(withPdf) {
    let pdfB64 = null;
    if (withPdf) {
      const { doc } = buildQuotePdf({ state, derived, quoteRef });
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
      coverSelections: cover && calc ? [{ coverIndex: state.selectedCoverIndex, coverLabel: cover.label, fpLabel: fpOpt ? fpOpt.label : '', ...calc }] : [],
      postureDiscount: derived.postureFrac, discretionaryDiscount: derived.discFrac,
      competitorName: state.competitorName, competitorData: parseCurrency(state.competitorPremium) > 0 ? [{ premium: parseCurrency(state.competitorPremium), hasFP: state.competitorHasFP }] : [],
      renewalCoverLimit: state.renewalCoverIndex >= 0 ? COVER_LIMITS[state.renewalCoverIndex].label : '',
      renewalPremium: parseCurrency(state.renewalPremium), coverLabel: cover ? cover.label : 'quote',
      createdBy: state.createdBy || '', pdfBase64: pdfB64,
    };
  }

  function downloadPdf() {
    const { doc, filename } = buildQuotePdf({ state, derived, quoteRef });
    doc.save(filename);
  }

  async function saveNow() {
    setSaveStatus('saving');
    try {
      await saveQuote(buildPayload(true));
      if (!state.quoteRef) patch({ quoteRef });
      setSaveStatus('saved');
    } catch (e) {
      setSaveStatus('error');
    }
  }

  function copyClipboard() {
    const lines = [
      `Phishield SME Cyber Quote — ${quoteRef}`,
      `Company: ${state.companyName}`,
      `Industry: ${industry ? industry.sub : '—'}`,
      `Turnover: ${formatR(derived.actualTurnover)} (${derived.bandLabel})`,
      cover ? `Cover: ${cover.label}` : '',
      fpOpt ? `Funds Protect: ${fpOpt.label}` : '',
      calc ? `Annual (incl FP): ${formatR(calc.annual)}` : '',
      calc ? `Annual (ex FP): ${formatR(calc.annualExFP)}` : '',
      calc ? `Monthly: ${formatR(calc.monthly)}` : '',
      `UW: ${derived.uw.outcome}`,
    ].filter(Boolean);
    navigator.clipboard?.writeText(lines.join('\n'));
  }

  return (
    <section className="step-panel active" id="step-5">
      <div className="glass-card">
        <div className="step-header">
          <h2>Quote Summary</h2>
          <p>Review the full quote breakdown before exporting.</p>
        </div>

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
          <div className="summary-section">
            <h3>Conditions of Cover</h3>
            <ul className="summary-endorsements">{conditions.map((c, i) => <li key={i}>{c}</li>)}</ul>
          </div>
        )}

        {state.endorsements.trim() && (
          <div className="summary-section">
            <h3>Endorsements / Notes</h3>
            <div className="summary-endorsements">{state.endorsements}</div>
          </div>
        )}

        {/* Breakdown */}
        <div className="quote-breakdowns">
          {calc && cover ? (
            <div className="quote-breakdown-card">
              <h4>Cover Limit: {cover.label}{fpOpt ? ` · FP ${fpOpt.label}` : ''}</h4>
              <table className="audit-trail">
                <thead><tr><th>Step</th><th>Description</th><th>Value</th></tr></thead>
                <tbody>
                  {calc.breakdown.map((b, i) => (
                    <tr key={i}><td>{b.step}</td><td>{b.desc}</td><td>{formatR(b.value)}</td></tr>
                  ))}
                </tbody>
              </table>
              <div className="breakdown-finals">
                <div className="breakdown-final-item"><span>With FP</span><strong>{formatR(calc.annual)}</strong></div>
                <div className="breakdown-final-item"><span>Excl FP</span><strong>{formatR(calc.annualExFP)}</strong></div>
                <div className="breakdown-final-item"><span>Monthly</span><strong>{formatR(calc.monthly)}</strong></div>
              </div>
              {derived.selectedItoo && (
                <div className="breakdown-comparison">
                  <span>Industry: {formatR(derived.selectedItoo.premium)}</span>
                  <span>Delta: {calc.annual - derived.selectedItoo.premium <= 0 ? '' : '+'}{formatR(calc.annual - derived.selectedItoo.premium)}</span>
                </div>
              )}
              {parseCurrency(state.manualOverride) > 0 && (
                <div className="breakdown-comparison"><span>Manual override: {formatR(parseCurrency(state.manualOverride))}</span></div>
              )}
            </div>
          ) : <p className="field-hint">No cover selected — go back to Step 2.</p>}
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" onClick={() => goToStep(4)}>Back</button>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-primary btn-print" onClick={() => window.print()}>Print Quote</button>
          <button type="button" className="btn btn-ghost btn-clipboard" onClick={copyClipboard}>Copy to Clipboard</button>
          <button type="button" className="btn btn-primary btn-download-pdf" disabled={!calc} onClick={downloadPdf}>Download PDF</button>
          <button type="button" className="btn btn-primary" disabled={!calc || saveStatus === 'saving'} onClick={saveNow}>
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
