import { COVER_LIMITS } from '../rating-data.js';
import { formatR } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import Toggle from '../components/Toggle.jsx';

export default function Step3Compare({ state, patch, derived, goToStep }) {
  const calc = derived.selectedCalc;
  const itoo = derived.selectedItoo;
  const cover = state.selectedCoverIndex >= 0 ? COVER_LIMITS[state.selectedCoverIndex] : null;

  const benchWithFp = itoo ? itoo.premium : null;
  const delta = calc && benchWithFp != null ? calc.annual - benchWithFp : null;

  return (
    <section className="step-panel active" id="step-3">
      <div className="glass-card">
        <div className="step-header">
          <h2>Competitor Quotes &amp; Benchmarking</h2>
          <p>Compare Phishield pricing against competitor quotes and industry benchmarks.</p>
        </div>

        <div className="step3-section">
          <label className="field-label section-label">Competitor Comparison</label>
          <div className="form-grid" style={{ marginBottom: 16 }}>
            <div className="form-group">
              <label className="field-label" htmlFor="competitor-name">Competitor / Provider Name</label>
              <input className="form-input" id="competitor-name" type="text" placeholder="e.g. Guardrisk / Chubb"
                value={state.competitorName} onChange={(e) => patch({ competitorName: e.target.value })} />
            </div>
            <div className="form-group">
              <label className="field-label">Does the competitor quote include a FP equivalent?</label>
              <Toggle
                value={state.competitorHasFP ? 'yes' : 'no'}
                onChange={(v) => patch({ competitorHasFP: v === 'yes' })}
                options={[{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }]}
              />
            </div>
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label className="field-label" htmlFor="competitor-premium">Competitor Premium for {cover ? cover.label : 'selected cover'} (R)</label>
              <input className="form-input" id="competitor-premium" type="text" inputMode="numeric" placeholder="e.g. 22,000"
                value={state.competitorPremium} onChange={(e) => patch({ competitorPremium: e.target.value })} />
            </div>
          </div>
        </div>

        <div className="step3-section" style={{ marginTop: 28 }}>
          <label className="field-label section-label">Industry Benchmark Comparison</label>
        </div>
        <div className="comparison-table">
          <table>
            <thead>
              <tr>
                <th>Cover Limit</th>
                <th>Phishield (with FP)</th>
                <th>Phishield (ex-FP)</th>
                <th>Industry Benchmark</th>
                <th>Delta</th>
              </tr>
            </thead>
            <tbody>
              {calc && cover ? (
                <tr>
                  <td>{cover.label}</td>
                  <td>{formatR(calc.annual)}</td>
                  <td>{formatR(calc.annualExFP)}</td>
                  <td>{benchWithFp != null ? formatR(benchWithFp) : '—'}</td>
                  <td style={{ color: delta != null ? (delta <= 0 ? 'var(--success, #22c55e)' : 'var(--danger, #ef4444)') : undefined }}>
                    {delta != null ? (delta <= 0 ? '' : '+') + formatR(delta) : '—'}
                  </td>
                </tr>
              ) : (
                <tr><td colSpan={5}>Select a cover in Step 2.</td></tr>
              )}
              {parseCurrency(state.competitorPremium) > 0 && cover && (
                <tr>
                  <td>{state.competitorName || 'Competitor'}</td>
                  <td colSpan={2}>{formatR(parseCurrency(state.competitorPremium))}{state.competitorHasFP ? ' (incl. FP equiv.)' : ' (ex-FP)'}</td>
                  <td>—</td>
                  <td>{calc ? (calc.annual - parseCurrency(state.competitorPremium) <= 0 ? '' : '+') + formatR(calc.annual - parseCurrency(state.competitorPremium)) : '—'}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" onClick={() => goToStep(2)}>Back</button>
          <button type="button" className="btn btn-primary" onClick={() => goToStep(4)}>
            Continue to Adjust
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}
