import { COVER_LIMITS } from '../rating-data.js';
import { calculatePremium, formatR } from '../rating-engine.js';

export default function Step4Adjust({ state, patch, derived, goToStep }) {
  const selected = state.selectedCoverIndex;
  const calc = derived.selectedCalc;
  const es = derived.engineState;

  const withDiscounts = (p, d) => (selected >= 0 && derived.revenueBandIndex >= 0
    ? calculatePremium(selected, { ...es, postureDiscount: p, discretionaryDiscount: d }, {}) : null);

  const base = withDiscounts(0, 0);
  const postureOnly = withDiscounts(derived.postureFrac, 0);
  const discOnly = withDiscounts(0, derived.discFrac);
  const postureRand = base && postureOnly ? base.annual - postureOnly.annual : 0;
  const discRand = base && discOnly ? base.annual - discOnly.annual : 0;

  const overCap = derived.combinedDiscountPct > 35;
  const itoo = derived.selectedItoo;

  // Comparison bar widths (Phishield vs benchmark), normalised to the larger.
  const ph = calc ? calc.annual : 0;
  const bench = itoo ? itoo.premium : 0;
  const max = Math.max(ph, bench, 1);

  return (
    <section className="step-panel active" id="step-4">
      <div className="glass-card">
        <div className="step-header">
          <h2>Adjustments &amp; Comparison</h2>
          <p>Apply discounts or overrides and compare against benchmarks.</p>
        </div>

        <div className="discount-section">
          <div className="discount-group">
            <label className="field-label" htmlFor="posture-discount">Posture Adjustment (%)</label>
            <div className="discount-input-row">
              <input className="form-input" id="posture-discount" type="text" inputMode="numeric" placeholder="e.g. 15 or -10"
                value={state.postureDiscount} onChange={(e) => patch({ postureDiscount: e.target.value })} />
              <span className="discount-computed">{postureRand >= 0 ? '-' : '+'}{formatR(Math.abs(postureRand))}</span>
            </div>
          </div>
          <div className="discount-group">
            <label className="field-label" htmlFor="discretionary-discount">Discretionary Adjustment (%)</label>
            <div className="discount-input-row">
              <input className="form-input" id="discretionary-discount" type="text" inputMode="numeric" placeholder="e.g. 5 or -10"
                value={state.discretionaryDiscount} onChange={(e) => patch({ discretionaryDiscount: e.target.value })} />
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

        <div className="form-group">
          <label className="field-label" htmlFor="manual-override">Manual Premium Override (R) <span className="field-hint-inline">Optional</span></label>
          <input className="form-input" id="manual-override" type="text" inputMode="numeric" placeholder="Leave blank to use calculated premium"
            value={state.manualOverride} onChange={(e) => patch({ manualOverride: e.target.value })} />
        </div>

        <div className="form-group" style={{ marginTop: 24 }}>
          <label className="field-label">Endorsements / Underwriter Notes</label>
          <textarea className="form-input endorsements-textarea" rows={4} placeholder="Enter any endorsements, special conditions, or notes to be included on the quote output..."
            value={state.endorsements} onChange={(e) => patch({ endorsements: e.target.value })} />
        </div>

        {calc && (
          <div className="comparison-panel">
            <div className="comparison-panel-header">
              <label className="field-label">Compare Against Industry Benchmark</label>
            </div>
            <div className="comparison-bars">
              <div className="comparison-bar">
                <div className="comparison-bar-label">{COVER_LIMITS[selected].label} — Phishield {formatR(ph)}{bench ? ` vs Industry ${formatR(bench)}` : ''}</div>
                <div className="comparison-bar-track">
                  {bench > 0 && <div className="bar-target-line" style={{ left: `${(bench / max) * 100}%` }} />}
                  <div className="bar-fill" style={{ width: `${(ph / max) * 100}%` }} />
                </div>
                <div className="bar-delta">{bench > 0 ? `${ph - bench <= 0 ? '' : '+'}${formatR(ph - bench)} vs industry` : 'No benchmark for this band'}</div>
              </div>
            </div>
          </div>
        )}

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
