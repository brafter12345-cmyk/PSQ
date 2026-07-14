import { useEffect, useState } from 'react';
import { REVENUE_BANDS } from '../rating-data.js';
import { formatR } from '../rating-engine.js';
import { parseCurrency } from '../lib/format.js';
import IndustrySelect from '../components/IndustrySelect.jsx';
import Toggle, { YesNo } from '../components/Toggle.jsx';
import CurrencyInput from '../components/CurrencyInput.jsx';

const RENEWAL_COVERS = [
  { i: 0, label: 'R1,000,000', v: 1000000 },
  { i: 1, label: 'R2,500,000', v: 2500000 },
  { i: 2, label: 'R5,000,000', v: 5000000 },
  { i: 3, label: 'R7,500,000', v: 7500000 },
  { i: 4, label: 'R10,000,000', v: 10000000 },
  { i: 5, label: 'R15,000,000', v: 15000000 },
];
const FP_SUBLIMITS = [150000, 200000, 250000, 500000, 1000000, 1500000, 2000000, 3000000, 4000000, 5000000];

export default function Step1Client({ state, patch, dispatch, derived, onNext }) {
  const setAns = (key, value) => dispatch({ type: 'setUwAnswer', key, value });
  const a = state.uwAnswers;
  const { uw } = derived;

  const [overlayDismissed, setOverlayDismissed] = useState(false);
  useEffect(() => { setOverlayDismissed(false); }, [derived.blockReason]);

  const q1GateAnswered = a['q1-1'] !== undefined && a['q1-2'] !== undefined;
  const showOutcome = q1GateAnswered;

  return (
    <section className="step-panel active" id="step-1">
      <div className="glass-card">
        <div className="step-header">
          <h2>Client &amp; Industry</h2>
          <p>Capture the client's details, industry classification and underwriting questions.</p>
        </div>

        {/* Company Name */}
        <div className="form-group">
          <label className="field-label" htmlFor="company-name">Company Name</label>
          <input
            className="form-input" id="company-name" type="text" placeholder="e.g. Acme Trading (Pty) Ltd"
            value={state.companyName} onChange={(e) => patch({ companyName: e.target.value })}
          />
        </div>

        {/* Industry */}
        <div className="form-group">
          <label className="field-label">Industry</label>
          <IndustrySelect value={state.industryIndex} onSelect={(idx) => patch({ industryIndex: idx })} />
        </div>

        {/* Turnover */}
        <div className="form-grid">
          <div className="form-group">
            <label className="field-label" htmlFor="turnover-prev">Previous Financial Year Turnover (R)</label>
            <CurrencyInput className="form-input" id="turnover-prev" type="text" inputMode="numeric" placeholder="e.g. 12,000,000"
              value={state.turnoverPrev} onChange={(v) => patch({ turnoverPrev: v })} />
          </div>
          <div className="form-group">
            <label className="field-label" htmlFor="turnover-current">Current Year Estimated Revenue (R)</label>
            <CurrencyInput className="form-input" id="turnover-current" type="text" inputMode="numeric" placeholder="e.g. 15,000,000"
              value={state.turnoverCurrent} onChange={(v) => patch({ turnoverCurrent: v })} />
          </div>
        </div>

        {derived.actualTurnover > 0 && (
          <div className="turnover-info" style={{ display: 'flex' }} aria-live="polite">
            <div className="turnover-info-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></svg>
            </div>
            <div className="turnover-info-text">
              <div className="turnover-actual">Actual Turnover: <strong>{formatR(derived.actualTurnover)}</strong></div>
              <div className="turnover-bracket">Matched Bracket: <strong>{derived.over200 ? 'Over R200M — Refer for Underwriting' : REVENUE_BANDS[derived.revenueBandIndex].label}</strong></div>
            </div>
          </div>
        )}

        {/* Employees + Website */}
        <div className="form-grid">
          <div className="form-group">
            <label className="field-label" htmlFor="employee-count">Number of Employees</label>
            <input className="form-input" id="employee-count" type="number" min="1" placeholder="e.g. 25"
              value={state.employeeCount} onChange={(e) => patch({ employeeCount: e.target.value })} />
          </div>
          <div className="form-group">
            <label className="field-label" htmlFor="website-address">Website Address</label>
            <input className="form-input" id="website-address" type="text" placeholder="e.g. www.company.co.za"
              value={state.websiteAddress} onChange={(e) => patch({ websiteAddress: e.target.value })} />
          </div>
        </div>

        {/* Underwriting Questions */}
        <div className="uw-questions">
          <h3 className="uw-header">Underwriting Assessment</h3>

          {/* Q1 compound */}
          <div className="uw-question">
            <div className="uw-question-text">1. Does your business have a comprehensive, paid-for internet security software subscription installed and up to date on all computer systems and access devices? This must include at a minimum:</div>
            {[
              ['q1-1', '1.1 Antivirus/anti-malware with real-time endpoint detection and response (EDR)'],
              ['q1-2', '1.2 A network firewall configured to filter incoming and outgoing traffic'],
              ['q1-3', '1.3 An email security solution that filters for phishing, malware and malicious attachments'],
              ['q1-4', '1.4 A web-filtering solution that blocks access to known malicious or suspicious websites'],
            ].map(([key, text]) => (
              <div className="uw-sub-question" key={key}>
                <div className="uw-question-text">{text}</div>
                <YesNo answer={a[key]} onAnswer={(v) => setAns(key, v)} ariaPrefix={key} />
              </div>
            ))}
            <div className="uw-text-followup">
              <label className="field-label" htmlFor="uw-q1-vendor">If Yes to the above, provide the name of endpoint security vendor and product name (optional):</label>
              <input className="form-input" id="uw-q1-vendor" type="text" placeholder="e.g. SentinelOne Singularity, Sophos Intercept X"
                value={state.uwEndpointVendor} onChange={(e) => patch({ uwEndpointVendor: e.target.value })} />
            </div>
          </div>

          {/* Q2 compound */}
          <div className="uw-question">
            <div className="uw-question-text">2. Data Back-Up</div>
            {[
              ['q2-1', '2.1 Do you back up your data on a weekly basis?'],
              ['q2-2', '2.2 Do you perform recovery testing at least once per year?'],
            ].map(([key, text]) => (
              <div className="uw-sub-question" key={key}>
                <div className="uw-question-text">{text}</div>
                <YesNo answer={a[key]} onAnswer={(v) => setAns(key, v)} ariaPrefix={key} />
              </div>
            ))}
          </div>

          {/* Q3-Q5 */}
          {[
            ['q3', '3. Is your data stored separately from your main computer e.g. via the cloud or on an offline hard disk?'],
            ['q4', '4. Do you regularly update and patch your computers so that they always have the latest security patches installed?'],
            ['q5', '5. Are your employees regularly advised about the secure use of their workplace computer, especially regarding the dangers of using the internet/email?'],
          ].map(([key, text]) => (
            <div className="uw-question" key={key}>
              <div className="uw-question-text">{text}</div>
              <YesNo answer={a[key]} onAnswer={(v) => setAns(key, v)} ariaPrefix={key} />
            </div>
          ))}

          {/* FP checkbox */}
          <div className="uw-fp-checkbox">
            <label>
              <input type="checkbox" checked={state.fpOver250k} onChange={(e) => patch({ fpOver250k: e.target.checked })} />
              <span>For Funds Protect cover limits above R250 000, complete questions 6 and 7:</span>
            </label>
          </div>

          {state.fpOver250k && (
            <>
              <div className="uw-question uw-fp-dependent">
                <div className="uw-question-text">6. Do you have documented procedures in place for the following:</div>
                {[
                  ['q6-1', '6.1 Vetting of new vendors/customers/payees?'],
                  ['q6-2', '6.2 To verify new beneficiaries loaded onto your business’s banking profiles for funds transfers?'],
                  ['q6-3', '6.3 To verify requests to amend existing beneficiary payment details?'],
                ].map(([key, text]) => (
                  <div className="uw-sub-question" key={key}>
                    <div className="uw-question-text">{text}</div>
                    <YesNo answer={a[key]} onAnswer={(v) => setAns(key, v)} ariaPrefix={key} />
                  </div>
                ))}
              </div>
              <div className="uw-question uw-fp-dependent">
                <div className="uw-question-text">7. Does your business utilise account verification services offered by your bank or third-party provider?</div>
                <YesNo answer={a['q7']} onAnswer={(v) => setAns('q7', v)} ariaPrefix="q7" />
              </div>
            </>
          )}

          {/* Q8 */}
          <div className="uw-question">
            <div className="uw-question-text">8. Have you been covered for cyber liability risks in the last 12 months prior to the inception date of this policy?</div>
            <YesNo answer={a['q8']} onAnswer={(v) => setAns('q8', v)} ariaPrefix="q8" />
            {a['q8'] === true && (
              <div className="uw-text-followup" style={{ display: 'block' }}>
                <div className="uw-followup-row">
                  <div className="form-group">
                    <label className="field-label" htmlFor="uw-q8-insurer">Insurer (optional)</label>
                    <input className="form-input" id="uw-q8-insurer" type="text" placeholder="e.g. Bryte / Guardrisk / CFC"
                      value={state.uwPriorInsurer} onChange={(e) => patch({ uwPriorInsurer: e.target.value })} />
                  </div>
                  <div className="form-group">
                    <label className="field-label" htmlFor="uw-q8-inception">Inception Date (optional)</label>
                    <input className="form-input" id="uw-q8-inception" type="date"
                      value={state.uwPriorInceptionDate} onChange={(e) => patch({ uwPriorInceptionDate: e.target.value })} />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Condition of Cover banner (FP conditions) */}
          {uw.fpConditions.length > 0 && (
            <div className="condition-of-cover-banner" style={{ display: 'block' }} aria-live="polite">
              <strong>Condition of Cover</strong>
              <p>The following will become conditions of cover and will be noted in the quote audit and printed output:</p>
              <ul>{uw.fpConditions.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </div>
          )}

          {/* UW Outcome */}
          {showOutcome && <UwOutcome uw={uw} />}
        </div>

        {/* Prior Claim */}
        <div className="prior-claim-section">
          <label className="prior-claim-label">
            <input type="checkbox" checked={state.priorClaim} onChange={(e) => patch({ priorClaim: e.target.checked })} />
            <span>Prior claim in previous term</span>
          </label>
          {state.priorClaim && (
            <div className="prior-claim-warning" style={{ display: 'flex' }} aria-live="polite">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
              <span>Additional underwriting required. Refer to senior underwriter.</span>
            </div>
          )}
        </div>

        {/* Quote Type */}
        <div className="form-group">
          <label className="field-label">Quote Type</label>
          <Toggle
            value={state.quoteType}
            onChange={(v) => patch({ quoteType: v })}
            options={[
              { value: 'new', label: 'New Business' },
              { value: 'renewal', label: 'Renewal' },
              { value: 'competing', label: 'Competing Quote' },
            ]}
          />
        </div>

        {state.quoteType === 'renewal' && (
          <div className="renewal-section" style={{ display: 'block' }}>
            <div className="form-group">
              <label className="field-label" htmlFor="renewal-cover-limit">Current Cover Limit</label>
              <select className="form-select" id="renewal-cover-limit" value={state.renewalCoverIndex}
                onChange={(e) => patch({ renewalCoverIndex: parseInt(e.target.value, 10) })}>
                <option value={-1} disabled>Select current cover limit</option>
                {RENEWAL_COVERS.map((c) => <option key={c.i} value={c.i}>{c.label}</option>)}
              </select>
            </div>
            <div className="form-group">
              <label className="field-label" htmlFor="renewal-premium">Current Annual Premium (R)</label>
              <CurrencyInput className="form-input" id="renewal-premium" type="text" inputMode="numeric" placeholder="e.g. 18,500"
                value={state.renewalPremium} onChange={(v) => patch({ renewalPremium: v })} />
            </div>
            <div className="form-group">
              <label className="field-label" htmlFor="renewal-fp-sublimit">Current Funds Protect Sub-limit</label>
              <select className="form-select" id="renewal-fp-sublimit" value={state.renewalFPLimit}
                onChange={(e) => patch({ renewalFPLimit: e.target.value })}>
                <option value="" disabled>Select current FP sub-limit</option>
                {FP_SUBLIMITS.map((v) => <option key={v} value={v}>R{v.toLocaleString('en-ZA')}</option>)}
              </select>
            </div>
            <div className="market-badge">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M23 6l-9.5 9.5-5-5L1 18" /><polyline points="17 6 23 6 23 12" /></svg>
              <span>Softening market for 2026</span>
            </div>
          </div>
        )}

        {state.quoteType === 'competing' && (
          <div className="competing-section" style={{ display: 'block' }}>
            <div className="info-banner">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 18, height: 18, flexShrink: 0 }}><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></svg>
              <span>Competitor quote details will be captured in the Compare step.</span>
            </div>
          </div>
        )}

        {/* Blocker overlay */}
        {derived.blocked && !overlayDismissed && (
          <div className="blocker-overlay" style={{ display: 'flex' }}>
            <div className="blocker-content">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" /></svg>
              <h3>Refer for Underwriting</h3>
              <p>{derived.blockReason}</p>
              <button type="button" className="btn btn-ghost" onClick={() => setOverlayDismissed(true)}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow flip"><polyline points="9 18 15 12 9 6" /></svg>
                Amend Answers
              </button>
            </div>
          </div>
        )}

        {/* Nav */}
        <div className="btn-row">
          <div />
          <button type="button" className="btn btn-primary" disabled={!derived.canNext1} onClick={onNext}>
            Continue to Coverage
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="btn-arrow"><polyline points="9 18 15 12 9 6" /></svg>
          </button>
        </div>
      </div>
    </section>
  );
}

function UwOutcome({ uw }) {
  if (uw.outcome === 'decline') {
    return <div className="uw-outcome visible decline"><span className="uw-outcome-badge decline">Declined</span><span>Does not meet minimum requirements.</span></div>;
  }
  if (uw.outcome === 'refer') {
    return <div className="uw-outcome visible refer"><span className="uw-outcome-badge refer">Refer</span><span>Prior incidents reported. Refer to senior underwriter.</span></div>;
  }
  if (uw.outcome === 'standard') {
    return <div className="uw-outcome visible standard"><span className="uw-outcome-badge standard">Standard Rates</span><span>All underwriting criteria met.</span></div>;
  }
  if (uw.outcome === 'caution') {
    const parts = [];
    const q1c = uw.q1Conditions.length;
    if (q1c > 0) parts.push(`${q1c} Q1 condition${q1c !== 1 ? 's' : ''} of cover noted`);
    if (uw.noCount > 0) parts.push(`${uw.noCount} Q2–Q5 concern${uw.noCount !== 1 ? 's' : ''} noted`);
    const detail = parts.length > 0 ? parts.join(', ') + '. No loading applied.' : 'No loading applied.';
    return <div className="uw-outcome visible caution"><span className="uw-outcome-badge caution">Proceed with Caution</span><span>{detail}</span></div>;
  }
  if (uw.outcome === 'loading') {
    const pct = Math.round(uw.loadingPct * 100);
    return <div className="uw-outcome visible loading"><span className="uw-outcome-badge loading">{pct}% Loading</span><span>{uw.noCount} concerns noted. {pct}% loading applied to base premium.</span></div>;
  }
  return null;
}
