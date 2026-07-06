import { useEffect } from 'react';
import { COVER_LIMITS, BASE_FP_BY_COVER, getAvailableFPOptions } from '../rating-data.js';
import { calculatePremium, formatR, getCardStyling, fpIndexForLimit } from '../rating-engine.js';
import { makeOption, optionLabel, isCoverInOptions, coverInstanceCount } from '../lib/options.js';

const AUTO_ROLES = ['recommended', 'current', 'recommended-target'];

export default function Step2Coverage({ state, patch, dispatch, derived, goToStep }) {
  const { engineBase, reco, optionCalcs } = derived;
  const options = state.quoteOptions;
  const isRenewalWithData = state.quoteType === 'renewal' && state.renewalCoverIndex >= 0 && derived.renewalPremiumNum > 0 && derived.renewalFPNum > 0;

  const setOptions = (opts) => {
    dispatch({ type: 'setOptions', options: opts });
    if (!opts.find((o) => o.id === state.activeOptionTab)) {
      patch({ activeOptionTab: opts.length ? opts[0].id : null });
    }
  };

  // Auto-select recommended/current/target covers on entry (empty) — legacy behaviour.
  useEffect(() => {
    if (derived.revenueBandIndex < 0 || options.length > 0) return;
    const picks = reco.cardSpecs.filter((s) => AUTO_ROLES.includes(s.role));
    if (!picks.length) return;
    const opts = picks.map((s) => {
      const fpIdx = isRenewalWithData ? fpIndexForLimit(COVER_LIMITS[s.coverIndex].key, derived.renewalFPNum) : 0;
      return makeOption(s.coverIndex, fpIdx);
    });
    dispatch({ type: 'setOptions', options: opts });
    patch({ activeOptionTab: opts.length ? opts[0].id : null });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [derived.revenueBandIndex, state.quoteType, state.renewalCoverIndex, derived.renewalPremiumNum, derived.renewalFPNum]);

  // FP index to display on a recommendation card.
  const cardFp = (ci) => {
    const forCover = options.filter((o) => o.coverIndex === ci);
    if (forCover.length) {
      const active = forCover.find((o) => o.id === state.activeOptionTab);
      return (active || forCover[0]).fpIndex;
    }
    if (isRenewalWithData) return fpIndexForLimit(COVER_LIMITS[ci].key, derived.renewalFPNum);
    return undefined;
  };

  const toggleCover = (ci) => {
    if (isCoverInOptions(options, ci)) {
      setOptions(options.filter((o) => o.coverIndex !== ci));
    } else {
      if (options.length >= 4) return;
      const fp = cardFp(ci);
      const opt = makeOption(ci, fp !== undefined ? fp : 0);
      setOptions([...options, opt]);
      patch({ activeOptionTab: opt.id, showCustomCover: false });
    }
  };

  const duplicateCover = (ci) => {
    if (options.length >= 4) return;
    const fp = cardFp(ci);
    const opt = makeOption(ci, fp !== undefined ? fp : 0);
    setOptions([...options, opt]);
    patch({ activeOptionTab: opt.id });
  };

  const selectCustom = (ci) => {
    if (isCoverInOptions(options, ci)) return;
    if (options.length >= 4) return;
    const key = COVER_LIMITS[ci].key;
    const opt = makeOption(ci, 0);
    setOptions([...options, opt]);
    patch({ activeOptionTab: opt.id, fpOver250k: BASE_FP_BY_COVER[key] > 250000 });
  };

  const activeOpt = options.find((o) => o.id === state.activeOptionTab) || options[0];
  const activeFpOptions = activeOpt ? getAvailableFPOptions(COVER_LIMITS[activeOpt.coverIndex].key) : [];
  const selectFp = (idx) => {
    if (!activeOpt) return;
    const fp = activeFpOptions[idx];
    dispatch({ type: 'patchOption', id: activeOpt.id, patch: { fpIndex: idx } });
    patch({ fpOver250k: fp.limit > 250000 });
  };

  const anyMicro = options.some((o) => optionCalcs[o.id] && optionCalcs[o.id].isMicro);

  return (
    <section className="step-panel active" id="step-2">
      <div className="glass-card">
        <div className="step-header">
          <h2>Coverage Recommendations &amp; Selection</h2>
          <p>Review recommended cover options or select custom limits. Add up to 4 to compare.</p>
        </div>

        {anyMicro && (
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

        {isRenewalWithData && <RenewalBanner reco={reco} state={state} derived={derived} />}

        {/* Recommendation cards */}
        <div className="coverage-section">
          <label className="field-label">{isRenewalWithData ? 'Renewal Recommendations' : 'Recommended Cover Options'}</label>
          <div className="cover-recommendations" aria-label="Recommended cover options">
            {reco.cardSpecs.length === 0 && <p className="field-hint">Complete Step 1 to see recommendations.</p>}
            {reco.cardSpecs.map((spec) => {
              const ci = spec.coverIndex;
              const fpIdx = cardFp(ci);
              const calc = calculatePremium(ci, engineBase, fpIdx !== undefined ? { fpIndex: fpIdx } : {});
              if (!calc) return null;
              const isAlsoRecommended = reco.recommended.includes(ci);
              const { badgeText, badgeClass, cardClass } = getCardStyling(spec.role, isAlsoRecommended);
              const selected = isCoverInOptions(options, ci);
              const uwPct = Math.round(derived.uw.loadingPct * 100);
              const retention = spec.role === 'alternative-intermediate' && derived.renewalPremiumNum > 0
                ? Math.round((calc.annual / derived.renewalPremiumNum) * 100) : null;
              return (
                <div
                  key={spec.role + '-' + ci}
                  className={'cover-rec-card ' + cardClass + (selected ? ' selected active' : '')}
                  onClick={() => toggleCover(ci)}
                >
                  <div className="check-overlay">&#10003;</div>
                  <div className="rec-card-header">
                    <span className="rec-card-cover">{COVER_LIMITS[ci].label}</span>
                    {badgeText && <span className={'rec-badge ' + badgeClass}>{badgeText}</span>}
                    {retention != null && <span className="retention-badge">{retention}% retention</span>}
                    {calc.isMicro && <span className="micro-label">Micro SME</span>}
                    {uwPct > 0 && <span className="uw-load-badge">UW +{uwPct}%</span>}
                  </div>
                  <div className="rec-card-body">
                    <div className="rec-price-annual">{formatR(calc.annual)}<span>/yr</span></div>
                    <div className="rec-price-monthly">{formatR(calc.monthly)}/mo</div>
                    <div className="rec-fp-note">FP incl: {formatR(calc.fpCost)}</div>
                  </div>
                  <button type="button" className="duplicate-btn" title="Add another option with this cover limit"
                    onClick={(e) => { e.stopPropagation(); duplicateCover(ci); }}>+</button>
                </div>
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
                  <button key={ci} type="button" className={'sel-card' + (isCoverInOptions(options, ci) ? ' active' : '')} onClick={() => selectCustom(ci)}>
                    <span className="cover-badge" />
                    <span className="sc-value">{c.label}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* FP selector — option tabs when 2+ */}
        {options.length >= 2 && (
          <div className="option-tabs" aria-label="FP selection tabs">
            {options.map((o, idx) => {
              const inst = coverInstanceCount(options, o.coverIndex) > 1
                ? ' (' + (options.filter((x, i) => x.coverIndex === o.coverIndex && i <= idx).length) + ')' : '';
              return (
                <button key={o.id} type="button" className={'option-tab' + (o.id === state.activeOptionTab ? ' active' : '')}
                  onClick={() => patch({ activeOptionTab: o.id })}>
                  {COVER_LIMITS[o.coverIndex].label}{inst}
                  <span className="option-tab-remove" title="Remove" onClick={(e) => { e.stopPropagation(); setOptions(options.filter((x) => x.id !== o.id)); }}> ×</span>
                </button>
              );
            })}
          </div>
        )}

        {activeOpt && (
          <div className="coverage-section">
            <label className="field-label">Funds Protect Cover{options.length >= 2 ? ` — ${optionLabel(activeOpt.coverIndex, activeOpt.fpIndex)}` : ''}</label>
            <div className="card-selector" id="fp-selector">
              {activeFpOptions.map((fp, idx) => (
                <button key={idx} type="button" className={'sel-card fp-card' + (activeOpt.fpIndex === idx ? ' active' : '')} onClick={() => selectFp(idx)}>
                  <span className="sc-value">{fp.label}</span>
                  <span className="sc-sub">{formatR(fp.cost)}/yr</span>
                </button>
              ))}
            </div>
            <p className="field-hint">Base FP included. Upgrade options shown above.</p>
          </div>
        )}

        {/* Pricing */}
        {options.length === 1 && optionCalcs[options[0].id] && (
          <SinglePricing calc={optionCalcs[options[0].id]} />
        )}
        {options.length >= 2 && (
          <div className="pricing-display">
            <div className="pd-header">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="pd-icon"><circle cx="12" cy="12" r="10" /><path d="M12 6v12M8 10h8M8 14h8" /></svg>
              <span>Estimated Premiums ({options.length} options)</span>
            </div>
            <table className="multi-pricing-table">
              <thead><tr><th>Option</th><th>Annual</th><th>Monthly</th></tr></thead>
              <tbody>
                {options.map((o) => {
                  const calc = optionCalcs[o.id];
                  if (!calc) return null;
                  return <tr key={o.id}><td>{optionLabel(o.coverIndex, o.fpIndex)}</td><td>{formatR(calc.annual)}</td><td>{formatR(calc.monthly)}</td></tr>;
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="btn-row">
          <button type="button" className="btn btn-ghost" onClick={() => goToStep(1)}>Back</button>
          <button type="button" className="btn btn-primary" disabled={options.length === 0} onClick={() => goToStep(3)}>
            Continue to Compare
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}

function SinglePricing({ calc }) {
  return (
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
  );
}

function RenewalBanner({ reco, state, derived }) {
  const r = reco.renewal;
  const parts = [];
  const cover = (i) => COVER_LIMITS[i] ? COVER_LIMITS[i].label : '--';
  let severity = '';
  if (r.dropTriggered) {
    severity = 'severity-critical';
    const dropPct = Math.round(r.dropPct * 100);
    if (r.corporateEscalation) {
      parts.push(<h4 key="h">⚠ Premium loss risk — Corporate referral suggested</h4>);
      parts.push(<p key="p1">At the existing cover ({cover(state.renewalCoverIndex)}) and FP sub-limit ({formatR(derived.renewalFPNum)}), the new premium is <strong>{dropPct}% lower</strong> than the existing policy ({formatR(derived.renewalPremiumNum)}).</p>);
      parts.push(<p key="p2">The highest available SME cover still produces a premium below 90% of existing. <strong>Consider converting to a Corporate product</strong> — refer to the underwriter.</p>);
    } else {
      parts.push(<h4 key="h">⚠ Premium loss risk on renewal</h4>);
      parts.push(<p key="p1">At the existing cover ({cover(state.renewalCoverIndex)}) and FP sub-limit ({formatR(derived.renewalFPNum)}), the new premium is <strong>{dropPct}% lower</strong> than the existing policy ({formatR(derived.renewalPremiumNum)}).</p>);
      parts.push(<p key="p2">Recommended cover adjusted to <strong>{cover(r.recommendedCoverIndex)}</strong> to retain at least 90% of existing premium. The existing cover is shown as reference only.</p>);
    }
  } else if (r.bandChanged) {
    severity = 'severity-info';
    parts.push(<h4 key="h">Revenue band shift since last renewal</h4>);
    parts.push(<p key="p1">The existing cover ({cover(state.renewalCoverIndex)}) is not within the current recommended set. It is shown as <em>Current Cover</em>; verify it remains adequate.</p>);
  }
  if (derived.uw.loadingPct > 0) {
    const pct = Math.round(derived.uw.loadingPct * 100);
    if (parts.length) parts.push(<hr key="hr" className="ins-divider" />);
    if (!severity) severity = 'severity-info';
    parts.push(<p key="uw" style={{ margin: 0 }}><strong>Note on comparison:</strong> the new premium includes a <strong>{pct}% underwriting loading</strong> (Q2.1–Q5). The prior term's posture is not on record, so the year-on-year comparison is not strictly like-for-like.</p>);
  }
  if (!parts.length) return null;
  return <div className={'renewal-insights-banner ' + severity} style={{ display: 'block' }} aria-live="polite">{parts}</div>;
}
