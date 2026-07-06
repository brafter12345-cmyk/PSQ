import { COVER_LIMITS, BASE_FP_BY_COVER, getAvailableFPOptions } from '../rating-data.js';
import { calculatePremium, formatR } from '../rating-engine.js';

export default function Step2Coverage({ state, patch, dispatch, derived, goToStep }) {
  const industryIndex = state.industryIndex;
  // Premium preview for a cover card: base FP, no discounts (menu price).
  const preview = (ci) => calculatePremium(
    ci,
    { revenueBandIndex: derived.revenueBandIndex, industryIndex, actualTurnover: derived.actualTurnover, uwLoadingPct: derived.uw.loadingPct, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 },
    {},
  );

  const selectCover = (ci) => {
    const key = COVER_LIMITS[ci].key;
    patch({
      selectedCoverIndex: ci,
      fpSelections: { ...state.fpSelections, [ci]: 0 },
      fpOver250k: BASE_FP_BY_COVER[key] > 250000,
    });
  };

  const selected = state.selectedCoverIndex;
  const coverKey = selected >= 0 ? COVER_LIMITS[selected].key : null;
  const fpOptions = coverKey ? getAvailableFPOptions(coverKey) : [];
  const fpIdx = selected >= 0 ? (state.fpSelections[selected] ?? 0) : 0;

  const selectFp = (idx) => {
    const fp = fpOptions[idx];
    dispatch({ type: 'setFp', coverIndex: selected, fpIndex: idx });
    patch({ fpOver250k: fp.limit > 250000 });
  };

  const calc = derived.selectedCalc;

  return (
    <section className="step-panel active" id="step-2">
      <div className="glass-card">
        <div className="step-header">
          <h2>Coverage Recommendations &amp; Selection</h2>
          <p>Review recommended cover options or select a custom limit.</p>
        </div>

        {calc && calc.isMicro && (
          <div className="micro-badge" style={{ display: 'flex' }}>
            <div className="micro-badge-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div className="micro-badge-text">
              <strong>Micro SME Rates Applied</strong>
              <span>Turnover and cover limit qualify for Micro SME pricing.</span>
            </div>
          </div>
        )}

        {/* Recommended */}
        <div className="coverage-section">
          <label className="field-label">Recommended Cover Options</label>
          <div className="card-selector cover-recommendations">
            {derived.recommendedCovers.length === 0 && <p className="field-hint">Complete Step 1 to see recommendations.</p>}
            {derived.recommendedCovers.map((ci) => {
              const c = preview(ci);
              return (
                <button key={ci} type="button" className={'sel-card' + (selected === ci ? ' active' : '')} onClick={() => selectCover(ci)}>
                  <span className="sc-value">{COVER_LIMITS[ci].label}</span>
                  {c && <span className="sc-sub">{formatR(c.annual)}/yr</span>}
                </button>
              );
            })}
          </div>
        </div>

        {/* Custom */}
        <div className="manual-selection-toggle">
          <button type="button" className="btn btn-ghost" onClick={() => patch({ showCustomCover: !state.showCustomCover })}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
            Select Custom Cover Limit
          </button>
        </div>

        {state.showCustomCover && (
          <div className="custom-selection" style={{ display: 'block' }}>
            <div className="coverage-section">
              <label className="field-label">Cover Limit</label>
              <div className="card-selector">
                {COVER_LIMITS.map((c, ci) => (
                  <button key={ci} type="button" className={'sel-card' + (selected === ci ? ' active' : '')} onClick={() => selectCover(ci)}>
                    <span className="cover-badge" />
                    <span className="sc-value">{c.label}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* FP selector */}
        {selected >= 0 && (
          <div className="coverage-section">
            <label className="field-label">Funds Protect Cover</label>
            <div className="card-selector" id="fp-selector">
              {fpOptions.map((fp, idx) => (
                <button key={idx} type="button" className={'sel-card fp-card' + (fpIdx === idx ? ' active' : '')} onClick={() => selectFp(idx)}>
                  <span className="sc-value">{fp.label}</span>
                  <span className="sc-sub">{formatR(fp.cost)}/yr</span>
                </button>
              ))}
            </div>
            <p className="field-hint">Base FP included. Upgrade options shown above.</p>
          </div>
        )}

        {/* Pricing */}
        {calc && (
          <div className="pricing-display">
            <div className="pd-header">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="pd-icon"><circle cx="12" cy="12" r="10" /><path d="M12 6v12M8 10h8M8 14h8" /></svg>
              <span>Estimated Premium</span>
            </div>
            <div className="pd-amounts">
              <div className="pd-amount-item">
                <div className="pd-label">Annual</div>
                <div className="pd-value"><span className="pd-currency">R</span><span className="pd-number">{calc.annual.toLocaleString('en-ZA')}</span></div>
                <div className="pd-sub">/year</div>
              </div>
              <div className="pd-divider" />
              <div className="pd-amount-item">
                <div className="pd-label">Monthly</div>
                <div className="pd-value"><span className="pd-currency">R</span><span className="pd-number">{calc.monthly.toLocaleString('en-ZA')}</span></div>
                <div className="pd-sub">/month</div>
              </div>
            </div>
          </div>
        )}

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" onClick={() => goToStep(1)}>Back</button>
          <button type="button" className="btn btn-primary" disabled={selected < 0} onClick={() => goToStep(3)}>
            Continue to Compare
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}
