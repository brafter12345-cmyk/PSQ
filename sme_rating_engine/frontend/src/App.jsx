import { useMemo, useReducer } from 'react';
import { initialState, reducer } from './state.js';
import { INDUSTRIES, COVER_AVAILABILITY, REVENUE_BANDS } from './rating-data.js';
import {
  calcActualTurnover, findRevenueBand, evaluateUnderwriting, calculatePremium,
  getItooBenchmark, getRecommendedCovers,
} from './rating-engine.js';
import { parseCurrency } from './lib/format.js';
import Step1Client from './steps/Step1Client.jsx';
import Step2Coverage from './steps/Step2Coverage.jsx';
import Step3Compare from './steps/Step3Compare.jsx';
import Step4Adjust from './steps/Step4Adjust.jsx';
import Step5Summary from './steps/Step5Summary.jsx';

const STEPS = [
  { n: 1, label: 'Client' },
  { n: 2, label: 'Coverage' },
  { n: 3, label: 'Compare' },
  { n: 4, label: 'Adjust' },
  { n: 5, label: 'Summary' },
];

function computeDerived(state) {
  const prev = parseCurrency(state.turnoverPrev);
  const current = parseCurrency(state.turnoverCurrent);
  const actualTurnover = calcActualTurnover(prev, current);
  const over200 = actualTurnover > 200_000_000;
  const revenueBandIndex = over200 ? -1 : actualTurnover > 0 ? findRevenueBand(actualTurnover) : -1;
  const bandLabel = revenueBandIndex >= 0 ? REVENUE_BANDS[revenueBandIndex].label : '';
  const industry = state.industryIndex >= 0 ? INDUSTRIES[state.industryIndex] : null;
  const uw = evaluateUnderwriting(state.uwAnswers, {
    quoteType: state.quoteType, priorClaim: state.priorClaim, fpOver250k: state.fpOver250k,
  });

  let blocked = false;
  let blockReason = '';
  if (industry && industry.referForUW) { blocked = true; blockReason = `${industry.main} requires referral for underwriting.`; }
  else if (over200) { blocked = true; blockReason = 'Turnover exceeds R200M. Refer for Underwriting.'; }
  else if (uw.outcome === 'decline') { blocked = true; blockReason = 'Underwriting declined: minimum security requirements not met.'; }
  else if (uw.outcome === 'refer') { blocked = true; blockReason = 'This risk does not meet standard acceptance criteria. Please refer to a senior underwriter.'; }

  const hasCompany = state.companyName.trim().length > 0;
  const q1GateAnswered = state.uwAnswers['q1-1'] !== undefined && state.uwAnswers['q1-2'] !== undefined;
  let renewalOk = true;
  if (state.quoteType === 'renewal') {
    renewalOk = state.renewalCoverIndex >= 0 && parseCurrency(state.renewalPremium) > 0 && parseCurrency(state.renewalFPLimit) > 0;
  }
  const canNext1 = !blocked && hasCompany && state.industryIndex >= 0 && actualTurnover > 0 && q1GateAnswered && renewalOk;

  // Discounts entered as percent strings ("15", "-10") -> fractions for the engine.
  const postureFrac = (parseFloat(state.postureDiscount) || 0) / 100;
  const discFrac = (parseFloat(state.discretionaryDiscount) || 0) / 100;
  const combinedDiscountPct = Math.round((postureFrac + discFrac) * 100);

  const engineState = {
    revenueBandIndex, industryIndex: state.industryIndex, actualTurnover,
    uwLoadingPct: uw.loadingPct, fpSelections: state.fpSelections,
    postureDiscount: postureFrac, discretionaryDiscount: discFrac,
  };
  const selectedCalc = state.selectedCoverIndex >= 0 && revenueBandIndex >= 0
    ? calculatePremium(state.selectedCoverIndex, engineState, {}) : null;
  const selectedItoo = getItooBenchmark(actualTurnover, state.selectedCoverIndex);
  const recommendedCovers = getRecommendedCovers(revenueBandIndex);

  // Ticker: selected-cover monthly once chosen, else first recommended cover.
  let ticker = null;
  if (selectedCalc) ticker = selectedCalc.monthly;
  else if (revenueBandIndex >= 0 && industry && !blocked && q1GateAnswered) {
    const avail = COVER_AVAILABILITY[revenueBandIndex] || [];
    let ci = avail.findIndex((a) => a === 'recommended');
    if (ci < 0) ci = 2;
    const calc = calculatePremium(ci, { ...engineState, postureDiscount: 0, discretionaryDiscount: 0 }, {});
    if (calc) ticker = calc.monthly;
  }

  return {
    prev, current, actualTurnover, over200, revenueBandIndex, bandLabel, industry, uw,
    blocked, blockReason, canNext1, ticker, engineState, selectedCalc, selectedItoo,
    recommendedCovers, postureFrac, discFrac, combinedDiscountPct,
  };
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const patch = (p) => dispatch({ type: 'patch', patch: p });
  const derived = useMemo(() => computeDerived(state), [state]);

  const goToStep = (n) => {
    if (n < 1 || n > 5) return;
    if (n > state.currentStep && derived.blocked) return;
    patch({ currentStep: n });
  };

  const progressPct = ((state.currentStep - 1) / (STEPS.length - 1)) * 100;
  const stepProps = { state, patch, dispatch, derived, goToStep };

  return (
    <>
      <header className="site-header">
        <div className="header-inner">
          <div className="logo-area">
            <div className="shield-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <h1><span className="brand-accent">Phishield</span></h1>
              <p className="header-tagline">SME Rating Engine (Internal)</p>
            </div>
          </div>
        </div>
      </header>

      <div className="main-container">
        <div className="progress-wrapper">
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${progressPct}%` }} />
          </div>
          <div className="progress-steps">
            {STEPS.map((s) => (
              <button
                key={s.n}
                type="button"
                className={'progress-step' + (state.currentStep === s.n ? ' active' : '') + (state.currentStep > s.n ? ' complete' : '')}
                onClick={() => goToStep(s.n)}
              >
                <span className="ps-dot"><span className="ps-num">{s.n}</span></span>
                <span className="ps-label">{s.label}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="quote-ticker" id="quoteTicker">
          <div className="ticker-label">Estimated Monthly</div>
          <div className="ticker-amount">{derived.ticker != null ? 'R' + derived.ticker.toLocaleString('en-ZA') : '--'}</div>
        </div>

        {state.currentStep === 1 && <Step1Client {...stepProps} onNext={() => goToStep(2)} />}
        {state.currentStep === 2 && <Step2Coverage {...stepProps} />}
        {state.currentStep === 3 && <Step3Compare {...stepProps} />}
        {state.currentStep === 4 && <Step4Adjust {...stepProps} />}
        {state.currentStep === 5 && <Step5Summary {...stepProps} />}

        <p className="footer-note">Phishield SME Rating Engine &copy; 2026. Internal tool — not for distribution.</p>
      </div>
    </>
  );
}
