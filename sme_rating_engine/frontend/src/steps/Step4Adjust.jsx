import { COVER_LIMITS } from '../rating-data.js';
import { calculatePremium, formatR, getItooBenchmark } from '../rating-engine.js';
import { optionLabel, coverInstanceCount } from '../lib/options.js';
import CurrencyInput from '../components/CurrencyInput.jsx';

export default function Step4Adjust({ state, patch, dispatch, derived, goToStep }) {
  const options = state.quoteOptions;
  const activeOpt = options.find((o) => o.id === state.activeOptionTab) || options[0];

  const setDiscount = (field, val) => {
    if (state.applyDiscountsToAll) {
      dispatch({ type: 'setOptions', options: options.map((o) => ({ ...o, [field]: val })) });
    } else if (activeOpt) {
      dispatch({ type: 'patchOption', id: activeOpt.id, patch: { [field]: val } });
    }
  };

  const pFrac = (o) => (parseFloat(o.posturePct) || 0) / 100;
  const dFrac = (o) => (parseFloat(o.discretionaryPct) || 0) / 100;

  // Active option rand impacts (base vs each discount).
  let postureRand = 0, discRand = 0, combinedPct = 0;
  if (activeOpt && derived.revenueBandIndex >= 0) {
    const base = calculatePremium(activeOpt.coverIndex, derived.engineBase, { fpIndex: activeOpt.fpIndex });
    const pOnly = calculatePremium(activeOpt.coverIndex, derived.engineBase, { fpIndex: activeOpt.fpIndex, postureDiscount: pFrac(activeOpt) });
    const dOnly = calculatePremium(activeOpt.coverIndex, derived.engineBase, { fpIndex: activeOpt.fpIndex, discretionaryDiscount: dFrac(activeOpt) });
    if (base && pOnly) postureRand = base.annual - pOnly.annual;
    if (base && dOnly) discRand = base.annual - dOnly.annual;
    combinedPct = Math.round((pFrac(activeOpt) + dFrac(activeOpt)) * 100);
  }
  const overCap = combinedPct > 35;

  return (
    <section className="step-panel active" id="step-4">
      <div className="glass-card">
        <div className="step-header">
          <h2>Adjustments &amp; Comparison</h2>
          <p>Apply discounts or overrides and compare against benchmarks.</p>
        </div>

        {options.length >= 2 && (
          <>
            <label className="apply-all-toggle">
              <input type="checkbox" checked={state.applyDiscountsToAll} onChange={(e) => patch({ applyDiscountsToAll: e.target.checked })} />
              <span>Apply discounts to all quote options</span>
            </label>
            <div className="option-tabs" aria-label="Adjustment tabs">
              {options.map((o, idx) => {
                const inst = coverInstanceCount(options, o.coverIndex) > 1
                  ? ' (' + (options.filter((x, i) => x.coverIndex === o.coverIndex && i <= idx).length) + ')' : '';
                return (
                  <button key={o.id} type="button" className={'option-tab' + (o.id === state.activeOptionTab ? ' active' : '')}
                    onClick={() => patch({ activeOptionTab: o.id })}>{COVER_LIMITS[o.coverIndex].label}{inst}</button>
                );
              })}
            </div>
          </>
        )}

        {activeOpt && (
          <div className="discount-section">
            <div className="discount-group">
              <label className="field-label" htmlFor="posture-discount">Posture Adjustment (%){options.length >= 2 && !state.applyDiscountsToAll ? ` — ${COVER_LIMITS[activeOpt.coverIndex].label}` : ''}</label>
              <div className="discount-input-row">
                <input className="form-input" id="posture-discount" type="text" inputMode="numeric" placeholder="e.g. 15 or -10"
                  value={activeOpt.posturePct} onChange={(e) => setDiscount('posturePct', e.target.value)} />
                <span className="discount-computed">{postureRand >= 0 ? '-' : '+'}{formatR(Math.abs(postureRand))}</span>
              </div>
            </div>
            <div className="discount-group">
              <label className="field-label" htmlFor="discretionary-discount">Discretionary Adjustment (%)</label>
              <div className="discount-input-row">
                <input className="form-input" id="discretionary-discount" type="text" inputMode="numeric" placeholder="e.g. 5 or -10"
                  value={activeOpt.discretionaryPct} onChange={(e) => setDiscount('discretionaryPct', e.target.value)} />
                <span className="discount-computed">{discRand >= 0 ? '-' : '+'}{formatR(Math.abs(discRand))}</span>
              </div>
            </div>
            {overCap && (
              <div className="discount-warning" style={{ display: 'flex' }} aria-live="polite">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                <span>Combined discount exceeds 35%. Senior underwriter approval required.</span>
              </div>
            )}
          </div>
        )}

        {activeOpt && (
          <div className="form-group">
            <label className="field-label" htmlFor="manual-override">Manual Premium Override (R) <span className="field-hint-inline">Optional — {COVER_LIMITS[activeOpt.coverIndex].label}</span></label>
            <CurrencyInput className="form-input" id="manual-override" type="text" inputMode="numeric" placeholder="Leave blank to use calculated premium"
              value={activeOpt.manualOverride} onChange={(v) => dispatch({ type: 'patchOption', id: activeOpt.id, patch: { manualOverride: v } })} />
          </div>
        )}

        <div className="form-group" style={{ marginTop: 24 }}>
          <label className="field-label">Endorsements / Underwriter Notes</label>
          <textarea className="form-input endorsements-textarea" rows={4} placeholder="Enter any endorsements, special conditions, or notes to be included on the quote output..."
            value={state.endorsements} onChange={(e) => patch({ endorsements: e.target.value })} />
        </div>

        <div className="comparison-panel">
          <div className="comparison-panel-header"><label className="field-label">Compare Against Industry Benchmark</label></div>
          <div className="comparison-bars">
            {options.map((o) => {
              const calc = derived.optionCalcs[o.id];
              if (!calc) return null;
              const bench = getItooBenchmark(derived.actualTurnover, o.coverIndex);
              const b = bench ? bench.premium : 0;
              const max = Math.max(calc.annual, b, 1);
              return (
                <div className="comparison-bar" key={o.id}>
                  <div className="comparison-bar-label">{optionLabel(o.coverIndex, o.fpIndex)} — Phishield {formatR(calc.annual)}{b ? ` vs Industry ${formatR(b)}` : ''}</div>
                  <div className="comparison-bar-track">
                    {b > 0 && <div className="bar-target-line" style={{ left: `${(b / max) * 100}%` }} />}
                    <div className="bar-fill" style={{ width: `${(calc.annual / max) * 100}%` }} />
                  </div>
                  <div className="bar-delta">{b > 0 ? `${calc.annual - b <= 0 ? '' : '+'}${formatR(calc.annual - b)} vs industry` : 'No benchmark for this band'}</div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" onClick={() => goToStep(3)}>Back</button>
          <button type="button" className="btn btn-primary" onClick={() => goToStep(5)}>
            Continue to Summary
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}
