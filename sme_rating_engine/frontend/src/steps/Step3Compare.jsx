import { COVER_LIMITS } from '../rating-data.js';
import { formatR, getItooBenchmark } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import Toggle from '../components/Toggle.jsx';
import CurrencyInput from '../components/CurrencyInput.jsx';

export default function Step3Compare({ state, patch, derived, goToStep }) {
  const options = state.quoteOptions;
  const distinctCovers = [...new Set(options.map((o) => o.coverIndex))];

  const compFor = (ci) => {
    const row = state.competitorRows.find((r) => r.coverIndex === ci);
    return row ? row.competitorPremium : '';
  };
  const setComp = (ci, val) => {
    const rows = state.competitorRows.filter((r) => r.coverIndex !== ci);
    if (val !== '') rows.push({ coverIndex: ci, competitorPremium: val });
    patch({ competitorRows: rows });
  };

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
              <Toggle value={state.competitorHasFP ? 'yes' : 'no'} onChange={(v) => patch({ competitorHasFP: v === 'yes' })}
                options={[{ value: 'no', label: 'No' }, { value: 'yes', label: 'Yes' }]} />
            </div>
          </div>
          {distinctCovers.map((ci) => (
            <div className="form-group" key={ci} style={{ marginBottom: 12 }}>
              <label className="field-label" htmlFor={'comp-' + ci}>Competitor Premium for {COVER_LIMITS[ci].label} (R)</label>
              <CurrencyInput className="form-input" id={'comp-' + ci} type="text" inputMode="numeric" placeholder="e.g. 22,000"
                value={compFor(ci)} onChange={(v) => setComp(ci, v)} />
            </div>
          ))}
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
              {options.map((o) => {
                const calc = derived.optionCalcs[o.id];
                if (!calc) return null;
                const bench = getItooBenchmark(derived.actualTurnover, o.coverIndex);
                const benchPrem = bench ? bench.premium : null;
                const cmp = state.competitorHasFP ? calc.annual : calc.annualExFP;
                const delta = benchPrem != null ? cmp - benchPrem : null;
                return (
                  <tr key={o.id}>
                    <td>{COVER_LIMITS[o.coverIndex].label}</td>
                    <td>{formatR(calc.annual)}</td>
                    <td>{formatR(calc.annualExFP)}</td>
                    <td>{benchPrem != null ? formatR(benchPrem) : '—'}</td>
                    <td>{delta != null ? (delta <= 0 ? '' : '+') + formatR(delta) : '—'}</td>
                  </tr>
                );
              })}
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
