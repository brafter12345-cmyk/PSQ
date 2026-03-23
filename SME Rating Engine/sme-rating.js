/**
 * SME Rating Engine — Calculation Engine & UI Logic
 * Phishield UMA (Pty) Ltd / Bryte Insurance Company Limited
 *
 * Last updated: 2026-03-23
 */

/* ===== DOM Helpers ===== */
const $ = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

function formatR(n) {
  return 'R ' + Math.round(n).toLocaleString('en-ZA');
}

/* ===== Number Animation ===== */
function animateNumber(el, target, prefix = '', suffix = '') {
  const current = parseInt((el.textContent || '0').replace(/[^\d]/g, ''), 10) || 0;
  if (current === Math.round(target)) return;

  el.classList.add('changing');
  setTimeout(() => {
    el.textContent = prefix + Math.round(target).toLocaleString('en-ZA') + suffix;
    el.classList.remove('changing');
  }, 150);
}

/* ===== State ===== */
const state = {
  currentStep: 1,
  // Step 1
  companyName: '',
  industryIndex: -1,
  turnoverPrev: 0,
  turnoverCurrent: 0,
  actualTurnover: 0,
  revenueBandIndex: -1,
  employeeCount: 0,
  uwAnswers: {},
  uwOutcome: null,
  uwLoadingPct: 0,
  uwNoCount: 0,
  fpOver250k: false,
  priorClaim: false,
  quoteType: 'new',
  // Renewal
  renewalCoverIndex: -1,
  renewalPremium: 0,
  // Competing
  competitorName: '',
  competitorCoverIndex: -1,
  competitorPremium: 0,
  // Step 2
  selectedCovers: [],
  isMicroSME: false,
  fpSelections: {},
  recommendedCovers: [],
  isCustomSelection: false,
  // Step 3
  numRequestedCovers: 1,
  hasExistingQuotes: false,
  competitorRows: [],
  // Step 4
  postureDiscount: 0,
  discretionaryDiscount: 0,
  manualOverride: null,
  compareTarget: 'itoo',
  // Computed
  calculations: {},
  quoteRef: '',
  isBlocked: false,
  blockReason: '',
};

/* ===== Currency Input Helpers ===== */
function parseCurrency(str) {
  if (!str) return 0;
  return parseFloat(String(str).replace(/[R,\s]/g, '')) || 0;
}

function formatCurrencyInput(el) {
  const val = parseCurrency(el.value);
  if (val > 0) {
    el.value = 'R' + val.toLocaleString('en-ZA');
  }
}

function stripCurrencyInput(el) {
  const val = parseCurrency(el.value);
  if (val > 0) {
    el.value = val;
  } else {
    el.value = '';
  }
}

/* ===== Turnover Calculation ===== */
function calcActualTurnover(prev, current) {
  if (prev > 0 && current > 0) return (prev + current) / 2;
  if (prev > 0) return prev;
  if (current > 0) return current;
  return 0;
}

function findRevenueBand(turnover) {
  for (let i = REVENUE_BANDS.length - 1; i >= 0; i--) {
    if (turnover >= REVENUE_BANDS[i].min) return i;
  }
  return 0;
}

function updateTurnoverInfo() {
  const prev = parseCurrency($('turnover-prev').value);
  const current = parseCurrency($('turnover-current').value);
  state.turnoverPrev = prev;
  state.turnoverCurrent = current;
  state.actualTurnover = calcActualTurnover(prev, current);

  const infoPanel = $('turnover-info');

  if (state.actualTurnover > 0) {
    // Check R200M blocker
    if (state.actualTurnover > 200_000_000) {
      state.revenueBandIndex = -1;
      $('turnover-actual-value').textContent = formatR(state.actualTurnover);
      $('turnover-bracket-value').textContent = 'Over R200M — Refer for Underwriting';
      infoPanel.style.display = 'flex';
      setBlocker(true, 'Turnover exceeds R200M. Refer for Underwriting.');
      return;
    }

    state.revenueBandIndex = findRevenueBand(state.actualTurnover);
    $('turnover-actual-value').textContent = formatR(state.actualTurnover);
    $('turnover-bracket-value').textContent = REVENUE_BANDS[state.revenueBandIndex].label;
    infoPanel.style.display = 'flex';

    // Clear turnover blocker if industry is not blocked
    if (state.isBlocked && state.blockReason.includes('R200M')) {
      setBlocker(false, '');
    }
  } else {
    infoPanel.style.display = 'none';
    state.revenueBandIndex = -1;
  }

  checkNextBtn1();
}

/* ===== Micro SME Detection ===== */
function checkMicroSME(industryIndex, bandIndex, coverIndex) {
  if (industryIndex < 0 || bandIndex < 0 || coverIndex < 0) return false;

  const industry = INDUSTRIES[industryIndex];
  const isSmallCover = coverIndex <= 2; // R1M, R2.5M, R5M
  const isSoftTech = industry.sub === 'Software and Technology';
  const isFinance = industry.main === 'Finance, Insurance, And Real Estate';

  if (isSoftTech || isFinance) {
    return bandIndex === 0 && isSmallCover; // Only R0-R10M
  }
  // General: turnover < R50M AND cover <= R5M
  return bandIndex <= 2 && isSmallCover;
}

/* ===== Industry Modifier Lookup ===== */
function getIndustryModifier(industryIndex, bandIndex) {
  if (industryIndex < 0 || bandIndex < 0) return 1.0;
  const industry = INDUSTRIES[industryIndex];

  if (industry.sub === 'Software and Technology') {
    const mods = INDUSTRY_MODIFIERS['Software and Technology'];
    return (bandIndex < mods.length) ? mods[bandIndex] : mods[mods.length - 1];
  }
  if (industry.main === 'Finance, Insurance, And Real Estate') {
    const mods = INDUSTRY_MODIFIERS['Finance'];
    return (bandIndex < mods.length) ? mods[bandIndex] : mods[mods.length - 1];
  }
  return 1.0;
}

/* ===== Bracket Shifting ===== */
// NOTE: Bracket shifting has been removed. The premium tables have been updated
// with correct amounts per band, so the actual band is used directly.
function getEffectiveBandIndex(bandIndex, coverIndex) {
  return bandIndex;
}

/* ===== Premium Calculation Pipeline ===== */
function calculatePremium(coverIndex, overrideState) {
  const s = overrideState || state;
  const bandIndex = s.revenueBandIndex;
  if (bandIndex < 0 || coverIndex < 0 || coverIndex >= COVER_LIMITS.length) {
    return null;
  }

  const coverKey = COVER_LIMITS[coverIndex].key;
  const breakdown = [];
  let basePremium = 0;
  let isMicro = false;

  // 1. Check Micro SME
  if (checkMicroSME(s.industryIndex, bandIndex, coverIndex)) {
    isMicro = true;
    const micro = MICRO_PREMIUMS[coverKey];
    if (!micro) return null;
    basePremium = micro.basePremium;
    breakdown.push({ step: 1, desc: 'Micro SME base premium', value: basePremium });

    const fpCost = micro.baseFPCost;
    const modifier = getIndustryModifier(s.industryIndex, bandIndex);
    let adjustedBase = basePremium * modifier;
    breakdown.push({ step: 2, desc: `Industry modifier (${modifier.toFixed(2)}x)`, value: adjustedBase });

    // UW loading
    const uwLoad = s.uwLoadingPct || 0;
    if (uwLoad > 0) {
      adjustedBase *= (1 + uwLoad);
      breakdown.push({ step: 3, desc: `UW loading (+${Math.round(uwLoad * 100)}%)`, value: adjustedBase });
    }

    // FP cost — use selected FP or base
    let selectedFPCost = fpCost;
    if (s.fpSelections && s.fpSelections[coverIndex] !== undefined) {
      const fpIdx = s.fpSelections[coverIndex];
      const availFP = getAvailableFPOptions(coverKey);
      if (fpIdx >= 0 && fpIdx < availFP.length) {
        selectedFPCost = availFP[fpIdx].cost;
      }
    }
    breakdown.push({ step: 4, desc: 'Funds Protect cost', value: selectedFPCost });

    let totalPremium = adjustedBase + selectedFPCost;
    const annualExFP = adjustedBase;
    breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

    // Apply discounts
    const postureD = s.postureDiscount || 0;
    const discretionaryD = s.discretionaryDiscount || 0;
    if (postureD > 0 || discretionaryD > 0) {
      totalPremium = totalPremium * (1 - postureD) * (1 - discretionaryD);
      breakdown.push({ step: 6, desc: `Discounts (posture ${Math.round(postureD * 100)}%, discretionary ${Math.round(discretionaryD * 100)}%)`, value: totalPremium });
    }

    const monthly = Math.ceil(totalPremium / 12);

    return {
      annual: Math.round(totalPremium),
      monthly,
      annualExFP: Math.round(annualExFP),
      basePremium: Math.round(basePremium),
      fpCost: selectedFPCost,
      modifier,
      uwLoading: uwLoad,
      postureDisc: postureD,
      discretionaryDisc: discretionaryD,
      isMicro: true,
      breakdown,
    };
  }

  // 2. Standard calculation — determine effective band
  const effectiveBand = getEffectiveBandIndex(bandIndex, coverIndex);

  // SME_PREMIUMS includes FP — subtract base FP to get base-only premium
  const baseFPCostForCover = getBaseFPCost(coverKey);

  if (effectiveBand === 0) {
    // Band 0: flat rate from table, minus FP to get base-only
    basePremium = SME_PREMIUMS[0][coverIndex] - baseFPCostForCover;
    breakdown.push({ step: 1, desc: 'Band 0 base premium (ex-FP)', value: basePremium });
  } else {
    // Bands 1-6: formula
    const formula = PREMIUM_FORMULAS[coverKey];
    if (formula) {
      const fi = effectiveBand - 1;
      if (fi >= 0 && fi < formula.rateCoeffs.length) {
        basePremium = formula.rateCoeffs[fi] * s.actualTurnover + formula.adjustments[fi];
        breakdown.push({ step: 1, desc: `Formula: (${formula.rateCoeffs[fi]} x ${formatR(s.actualTurnover)}) + ${formatR(formula.adjustments[fi])}`, value: basePremium });
      } else {
        basePremium = SME_PREMIUMS[Math.min(effectiveBand, SME_PREMIUMS.length - 1)][coverIndex];
        breakdown.push({ step: 1, desc: 'Table lookup (fallback)', value: basePremium });
      }
    } else {
      basePremium = SME_PREMIUMS[Math.min(effectiveBand, SME_PREMIUMS.length - 1)][coverIndex];
      breakdown.push({ step: 1, desc: 'Table lookup', value: basePremium });
    }
  }

  // 3. Industry modifier
  const modifier = getIndustryModifier(s.industryIndex, bandIndex);
  let adjustedBase = basePremium * modifier;
  breakdown.push({ step: 2, desc: `Industry modifier (${modifier.toFixed(2)}x)`, value: adjustedBase });

  // 4. UW loading
  const uwLoad = s.uwLoadingPct || 0;
  if (uwLoad > 0) {
    adjustedBase *= (1 + uwLoad);
    breakdown.push({ step: 3, desc: `UW loading (+${Math.round(uwLoad * 100)}%)`, value: adjustedBase });
  }

  // 5. FP cost
  let selectedFPCost = getBaseFPCost(coverKey);
  if (s.fpSelections && s.fpSelections[coverIndex] !== undefined) {
    const fpIdx = s.fpSelections[coverIndex];
    const availFP = getAvailableFPOptions(coverKey);
    if (fpIdx >= 0 && fpIdx < availFP.length) {
      selectedFPCost = availFP[fpIdx].cost;
    }
  }
  breakdown.push({ step: 4, desc: 'Funds Protect cost', value: selectedFPCost });

  let totalPremium = adjustedBase + selectedFPCost;
  const annualExFP = adjustedBase;
  breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

  // 6. Discounts
  const postureD = s.postureDiscount || 0;
  const discretionaryD = s.discretionaryDiscount || 0;
  if (postureD > 0 || discretionaryD > 0) {
    totalPremium = totalPremium * (1 - postureD) * (1 - discretionaryD);
    breakdown.push({ step: 6, desc: `Discounts (posture ${Math.round(postureD * 100)}%, discretionary ${Math.round(discretionaryD * 100)}%)`, value: totalPremium });
  }

  const monthly = Math.ceil(totalPremium / 12);

  return {
    annual: Math.round(totalPremium),
    monthly,
    annualExFP: Math.round(annualExFP),
    basePremium: Math.round(basePremium),
    fpCost: selectedFPCost,
    modifier,
    uwLoading: uwLoad,
    postureDisc: postureD,
    discretionaryDisc: discretionaryD,
    isMicro: false,
    breakdown,
  };
}

/* ===== Industry Benchmark Lookup ===== */
function getItooBenchmark(actualTurnover, coverIndex) {
  const entry = ITOO_BENCHMARKS.find(b => actualTurnover >= b.min && actualTurnover <= b.max);
  if (!entry || coverIndex < 0 || coverIndex >= entry.premiums.length) return null;
  return { premium: entry.premiums[coverIndex], deductible: entry.deductible };
}

/* ===== Update Pricing Display ===== */
function updatePricing() {
  if (state.selectedCovers.length === 0 && state.revenueBandIndex < 0) return;

  // Calculate for all selected covers
  state.calculations = {};
  const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
  covers.forEach(ci => {
    const calc = calculatePremium(ci, state);
    if (calc) state.calculations[ci] = calc;
  });

  // Update pricing display with primary selected cover
  const primaryCoverIdx = covers[0];
  const calc = state.calculations[primaryCoverIdx];

  const pdAnnualNum = $('pdAnnualNum');
  const pdMonthlyNum = $('pdMonthlyNum');

  if (calc) {
    animateNumber(pdAnnualNum, calc.annual);
    animateNumber(pdMonthlyNum, calc.monthly);

    // Ticker
    const ticker = $('quoteTicker');
    const tickerAmount = $('tickerAmount');
    if (state.currentStep >= 2) {
      ticker.classList.add('visible');
      tickerAmount.textContent = formatR(calc.monthly) + '/mo';
    }
  } else {
    pdAnnualNum.textContent = '--';
    pdMonthlyNum.textContent = '--';
  }
}

/* ===== Blocker Logic ===== */
function setBlocker(blocked, reason) {
  state.isBlocked = blocked;
  state.blockReason = reason;

  const overlay = $('blocker-overlay');
  const nextBtn = $('nextBtn1');

  if (blocked) {
    overlay.style.display = 'flex';
    const contentP = overlay.querySelector('.blocker-content p');
    if (contentP) contentP.textContent = reason;
    nextBtn.disabled = true;
  } else {
    overlay.style.display = 'none';
    checkNextBtn1();
  }
}

/* ===== Underwriting Assessment ===== */
function evaluateUW() {
  const a = state.uwAnswers;

  // Q1 = No -> Decline
  if (a['q1'] === false) {
    state.uwOutcome = 'decline';
    state.uwLoadingPct = 0;
    state.uwNoCount = 0;
    renderUWOutcome();
    return;
  }

  // Q2 compound: Yes only if BOTH Q2.1 AND Q2.2 are Yes
  const q2 = (a['q2-1'] === true && a['q2-2'] === true);

  // Count Q2-Q6 "No" answers
  let noCount = 0;
  if (a['q2-1'] !== undefined && a['q2-2'] !== undefined && !q2) noCount++;
  if (a['q3'] === false) noCount++;
  if (a['q4'] === false) noCount++;
  if (a['q5'] === false) noCount++;
  if (a['q6'] === false) noCount++;

  state.uwNoCount = noCount;

  // All Q1-Q6 answered No (except Q1 which we already checked)?
  // Actually: Q1=No already handled above. 5 No means Q2-Q6 all No.
  if (noCount >= 5) {
    state.uwOutcome = 'decline';
    state.uwLoadingPct = 0;
    renderUWOutcome();
    return;
  }

  // Loading from table
  const loadingEntry = UNDERWRITING_LOADINGS[Math.min(noCount, 5)];
  state.uwLoadingPct = loadingEntry.loading;

  if (noCount === 0) {
    state.uwOutcome = 'standard';
  } else if (noCount === 1) {
    state.uwOutcome = 'caution';
  } else {
    state.uwOutcome = 'loading';
  }

  // Q9 = No means prior incidents/claims exist -> add referral note
  if (a['q9'] === false) {
    state.uwOutcome = 'refer';
  }

  renderUWOutcome();
  checkNextBtn1();
}

function renderUWOutcome() {
  const el = $('uw-outcome');
  if (!el) return;

  el.className = 'uw-outcome';

  if (state.uwOutcome === 'decline') {
    el.innerHTML = '<span class="uw-outcome-badge decline">Declined</span><span>Does not meet minimum requirements.</span>';
    el.classList.add('visible', 'decline');
    setBlocker(true, 'Underwriting declined: minimum security requirements not met.');
    return;
  }

  if (state.uwOutcome === 'refer') {
    el.innerHTML = '<span class="uw-outcome-badge refer">Refer</span><span>Prior incidents reported. Refer to senior underwriter.</span>';
    el.classList.add('visible', 'refer');
  } else if (state.uwOutcome === 'standard') {
    el.innerHTML = '<span class="uw-outcome-badge standard">Standard Rates</span><span>All underwriting criteria met.</span>';
    el.classList.add('visible', 'standard');
  } else if (state.uwOutcome === 'caution') {
    el.innerHTML = '<span class="uw-outcome-badge caution">Proceed with Caution</span><span>1 concern noted. No loading applied.</span>';
    el.classList.add('visible', 'caution');
  } else if (state.uwOutcome === 'loading') {
    const pct = Math.round(state.uwLoadingPct * 100);
    el.innerHTML = `<span class="uw-outcome-badge loading">${pct}% Loading</span><span>${state.uwNoCount} concerns noted. ${pct}% loading applied to base premium.</span>`;
    el.classList.add('visible', 'loading');
  }

  // Clear decline blocker if outcome is not decline
  if (state.uwOutcome !== 'decline' && state.isBlocked && state.blockReason.includes('Underwriting declined')) {
    setBlocker(false, '');
  }

  // Check FP-dependent conditions of cover (Q7/Q8 answered No)
  let fpConditions = [];
  if (state.fpOver250k) {
    if (state.uwAnswers['q7-1'] === false) fpConditions.push('Q7.1: Vetting of new vendors/customers/payees');
    if (state.uwAnswers['q7-2'] === false) fpConditions.push('Q7.2: Verify new beneficiaries on banking profiles');
    if (state.uwAnswers['q7-3'] === false) fpConditions.push('Q7.3: Verify requests to amend beneficiary details');
    if (state.uwAnswers['q8'] === false) fpConditions.push('Q8: Account verification services');
  }
  state.uwFPConditions = fpConditions;

  // Show/hide condition of cover banner
  const cocBanner = $('condition-of-cover-banner');
  if (cocBanner) {
    if (fpConditions.length > 0) {
      cocBanner.innerHTML = '<strong>Condition of Cover</strong>' +
        '<p>The following will become conditions of cover and will be noted in the quote audit and printed output:</p>' +
        '<ul>' + fpConditions.map(c => '<li>' + c + '</li>').join('') + '</ul>';
      cocBanner.style.display = 'block';
    } else {
      cocBanner.style.display = 'none';
    }
  }
}

/* ===== Check Next Button 1 Enablement ===== */
function checkNextBtn1() {
  const btn = $('nextBtn1');
  if (state.isBlocked) {
    btn.disabled = true;
    return;
  }

  const hasCompany = state.companyName.trim().length > 0;
  const hasIndustry = state.industryIndex >= 0;
  const hasTurnover = state.actualTurnover > 0;
  const q1Answered = state.uwAnswers['q1'] !== undefined;

  btn.disabled = !(hasCompany && hasIndustry && hasTurnover && q1Answered);
}

/* ===== Populate Industry Dropdown ===== */
function populateIndustryDropdown() {
  const select = $('industry-select');
  // Clear existing optgroups
  const optgroups = select.querySelectorAll('optgroup');
  optgroups.forEach(og => og.innerHTML = '');

  // Build map of main -> optgroup label
  const ogMap = {};
  optgroups.forEach(og => {
    const label = og.getAttribute('label');
    ogMap[label] = og;
  });

  // Map main categories to optgroup labels
  const mainToLabel = {
    'Agriculture, Forestry, And Fishing': 'Agriculture',
    'Mining': 'Mining',
    'Construction': 'Construction',
    'Manufacturing': 'Manufacturing',
    'Transportation, Communications, Electric, Gas And Sanitary Services': 'Transportation',
    'Wholesale Trade': 'Wholesale Trade',
    'Retail Trade': 'Retail Trade',
    'Finance, Insurance, And Real Estate': 'Finance/Insurance/Real Estate',
    'Services': 'Services',
    'Healthcare': 'Healthcare',
    'Public Administration': 'Public Administration',
  };

  INDUSTRIES.forEach((ind, idx) => {
    const label = mainToLabel[ind.main];
    const og = ogMap[label];
    if (og) {
      const opt = document.createElement('option');
      opt.value = idx;
      opt.textContent = ind.sub;
      opt.dataset.main = ind.main;
      opt.dataset.refer = ind.referForUW ? 'true' : 'false';
      og.appendChild(opt);
    }
  });
}

/* ===== Step Navigation ===== */
function goToStep(n) {
  if (n < 1 || n > 5) return;
  if (n === state.currentStep) return;

  // Cannot skip ahead past current+1
  if (n > state.currentStep + 1) return;

  // Hide all steps
  $$('.step-panel').forEach(p => p.classList.remove('active'));

  // Show target
  const target = $('step-' + n);
  if (target) target.classList.add('active');

  state.currentStep = n;

  // Progress bar fill: 5 steps -> 0%, 25%, 50%, 75%, 100%
  const fillPct = ((n - 1) / 4) * 100;
  $('progressFill').style.width = fillPct + '%';

  for (let i = 1; i <= 5; i++) {
    const stepEl = $('pStep' + i);
    stepEl.classList.remove('active', 'completed');
    if (i < n) stepEl.classList.add('completed');
    else if (i === n) stepEl.classList.add('active');
  }

  // Ticker visibility
  const ticker = $('quoteTicker');
  if (n >= 2 && n <= 4 && Object.keys(state.calculations).length > 0) {
    ticker.classList.add('visible');
  } else {
    ticker.classList.remove('visible');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ===== Get Recommended Covers ===== */
function getRecommendedCovers(bandIndex) {
  if (bandIndex < 0 || bandIndex >= COVER_AVAILABILITY.length) return [];
  const row = COVER_AVAILABILITY[bandIndex];
  const recommended = [];
  row.forEach((status, idx) => {
    if (status === 'recommended') recommended.push(idx);
  });
  return recommended;
}

/* ===== Render Cover Recommendation Cards ===== */
function renderRecommendations() {
  const container = $('cover-recommendations');
  container.innerHTML = '';

  if (state.revenueBandIndex < 0) return;

  const recommended = getRecommendedCovers(state.revenueBandIndex);
  state.recommendedCovers = recommended;

  // For renewals in softening market, also show 2 higher covers
  let upgradeCovers = [];
  if (state.quoteType === 'renewal' && MARKET_CONDITION === 'softening') {
    const maxRec = Math.max(...recommended, -1);
    for (let i = maxRec + 1; i < COVER_LIMITS.length && upgradeCovers.length < 2; i++) {
      const avail = COVER_AVAILABILITY[state.revenueBandIndex][i];
      if (avail) upgradeCovers.push(i);
    }
  }

  const allToShow = [...recommended, ...upgradeCovers];

  allToShow.forEach(ci => {
    const calc = calculatePremium(ci, state);
    if (!calc) return;

    const isRec = recommended.includes(ci);
    const isUpgrade = upgradeCovers.includes(ci);

    const card = document.createElement('div');
    card.className = 'cover-rec-card' + (isRec ? ' recommended' : '') + (isUpgrade ? ' upgrade' : '');
    card.dataset.coverIndex = ci;

    const badgeText = isRec ? 'Recommended' : (isUpgrade ? 'Upgrade Option' : '');
    const microLabel = calc.isMicro ? '<span class="micro-label">Micro SME</span>' : '';

    card.innerHTML = `
      <div class="rec-card-header">
        <span class="rec-card-cover">${COVER_LIMITS[ci].label}</span>
        ${badgeText ? `<span class="rec-badge ${isRec ? 'rec' : 'upgrade'}">${badgeText}</span>` : ''}
        ${microLabel}
      </div>
      <div class="rec-card-body">
        <div class="rec-price-annual">${formatR(calc.annual)}<span>/yr</span></div>
        <div class="rec-price-monthly">${formatR(calc.monthly)}/mo</div>
        <div class="rec-fp-note">FP incl: ${formatR(calc.fpCost)}</div>
      </div>
    `;

    card.addEventListener('click', () => {
      container.querySelectorAll('.cover-rec-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      state.selectedCovers = [ci];
      state.isCustomSelection = false;

      // Update micro badge
      state.isMicroSME = calc.isMicro;
      $('micro-badge').style.display = calc.isMicro ? 'flex' : 'none';

      renderFPSelector(ci);
      updatePricing();
    });

    container.appendChild(card);
  });

  // Auto-select first recommended
  if (recommended.length > 0 && state.selectedCovers.length === 0) {
    const firstCard = container.querySelector('.cover-rec-card');
    if (firstCard) firstCard.click();
  }
}

/* ===== Render Custom Cover Selector Badges ===== */
function renderCoverBadges() {
  if (state.revenueBandIndex < 0) return;

  const cards = $$('#cover-selector .sel-card');
  cards.forEach((card, idx) => {
    const avail = COVER_AVAILABILITY[state.revenueBandIndex] ? COVER_AVAILABILITY[state.revenueBandIndex][idx] : null;
    const badge = card.querySelector('.cover-badge');

    card.classList.remove('unavailable', 'active');
    badge.textContent = '';
    badge.className = 'cover-badge';

    if (!avail) {
      card.classList.add('unavailable');
      badge.textContent = 'N/A';
      badge.classList.add('na');
    } else if (avail === 'recommended') {
      badge.textContent = 'Recommended';
      badge.classList.add('rec');
    } else if (avail === 'optional') {
      badge.textContent = 'Optional';
      badge.classList.add('opt');
    } else if (avail === 'request-only') {
      badge.textContent = 'Request Only';
      badge.classList.add('req');
    }
  });
}

/* ===== Render FP Selector ===== */
function renderFPSelector(coverIndex) {
  const container = $('fp-selector');
  container.innerHTML = '';

  if (coverIndex < 0) return;

  const coverKey = COVER_LIMITS[coverIndex].key;
  const options = getAvailableFPOptions(coverKey);

  options.forEach((fp, idx) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'sel-card fp-card';
    card.dataset.fpIndex = idx;
    card.innerHTML = `
      <span class="sc-value">${fp.label}</span>
      <span class="sc-sub">${formatR(fp.cost)}/yr</span>
    `;

    // Mark base FP as default selected
    if (idx === 0) card.classList.add('active');

    card.addEventListener('click', () => {
      container.querySelectorAll('.fp-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      state.fpSelections[coverIndex] = idx;

      // Check if FP > R250k
      const wasOver250k = state.fpOver250k;
      state.fpOver250k = fp.limit > 250_000;
      if (state.fpOver250k !== wasOver250k) {
        toggleFPQuestions(state.fpOver250k);
      }

      updatePricing();
    });

    container.appendChild(card);
  });

  // Default: base FP
  state.fpSelections[coverIndex] = 0;

  // Check auto-activate FP > R250k (base FP >= R500k for R7.5M+)
  const baseFP = BASE_FP_BY_COVER[coverKey];
  if (baseFP > 250_000) {
    state.fpOver250k = true;
    $('fp-over-250k').checked = true;
    toggleFPQuestions(true);
  }
}

/* ===== Toggle FP-dependent Questions ===== */
function toggleFPQuestions(show) {
  $('uw-q7').style.display = show ? 'block' : 'none';
  $('uw-q8').style.display = show ? 'block' : 'none';

  if (!show) {
    // Clear FP-dependent answers
    delete state.uwAnswers['q7-1'];
    delete state.uwAnswers['q7-2'];
    delete state.uwAnswers['q7-3'];
    delete state.uwAnswers['q8'];

    // Clear toggle button states
    $$('#uw-q7 .toggle-btn, #uw-q8 .toggle-btn').forEach(b => b.classList.remove('active'));
  }
}

/* ===== Competitor Row Management (Step 3) ===== */
function updateCompetitorRows() {
  const container = $('competitor-rows');
  const existingRows = container.querySelectorAll('.competitor-row');
  const count = state.numRequestedCovers;

  // Add/remove rows
  if (existingRows.length < count) {
    for (let i = existingRows.length; i < count; i++) {
      const template = existingRows[0];
      const clone = template.cloneNode(true);
      clone.dataset.rowIndex = i;

      // Reset inputs
      clone.querySelectorAll('select').forEach(s => s.selectedIndex = 0);
      clone.querySelectorAll('input').forEach(inp => inp.value = '');
      clone.querySelector('.competitor-status').innerHTML = '';

      // Add event listeners
      setupCompetitorRowEvents(clone, i);
      container.appendChild(clone);
    }
  } else {
    for (let i = existingRows.length - 1; i >= count; i--) {
      existingRows[i].remove();
    }
  }

  // Toggle competitor inputs based on existing quotes flag
  container.querySelectorAll('.competitor-limit-input, .competitor-premium-input').forEach(inp => {
    inp.style.display = state.hasExistingQuotes ? 'block' : 'none';
    inp.closest('.form-group').style.display = state.hasExistingQuotes ? 'block' : 'none';
  });

  updateComparisonTable();
}

function setupCompetitorRowEvents(row, index) {
  const select = row.querySelector('.competitor-cover-select');
  const limitInput = row.querySelector('.competitor-limit-input');
  const premiumInput = row.querySelector('.competitor-premium-input');

  select.addEventListener('change', () => {
    updateCompetitorRowStatus(row, index);
    updateComparisonTable();
  });

  if (limitInput) {
    limitInput.addEventListener('blur', () => {
      formatCurrencyInput(limitInput);
      updateCompetitorRowStatus(row, index);
      updateComparisonTable();
    });
    limitInput.addEventListener('focus', () => stripCurrencyInput(limitInput));
  }

  if (premiumInput) {
    premiumInput.addEventListener('blur', () => {
      formatCurrencyInput(premiumInput);
      updateCompetitorRowStatus(row, index);
      updateComparisonTable();
    });
    premiumInput.addEventListener('focus', () => stripCurrencyInput(premiumInput));
  }
}

function updateCompetitorRowStatus(row, index) {
  const select = row.querySelector('.competitor-cover-select');
  const statusEl = row.querySelector('.competitor-status');
  const selectedValue = parseInt(select.value, 10);

  if (!selectedValue) {
    statusEl.innerHTML = '';
    return;
  }

  // Find matching cover index
  const coverIdx = COVER_LIMITS.findIndex(cl => cl.value === selectedValue);

  if (coverIdx >= 0 && state.revenueBandIndex >= 0) {
    const avail = COVER_AVAILABILITY[state.revenueBandIndex][coverIdx];
    if (avail) {
      statusEl.innerHTML = '<span class="status-matched">Matched</span>';

      // Store competitor row data
      if (!state.competitorRows[index]) state.competitorRows[index] = {};
      state.competitorRows[index].requestedCoverIndex = coverIdx;
      state.competitorRows[index].competitorLimit = parseCurrency(row.querySelector('.competitor-limit-input').value);
      state.competitorRows[index].competitorPremium = parseCurrency(row.querySelector('.competitor-premium-input').value);
    } else {
      // Find 2 closest available covers
      const closest = [];
      for (let i = coverIdx - 1; i >= 0 && closest.length < 1; i--) {
        if (COVER_AVAILABILITY[state.revenueBandIndex][i]) closest.unshift(i);
      }
      for (let i = coverIdx + 1; i < COVER_LIMITS.length && closest.length < 2; i++) {
        if (COVER_AVAILABILITY[state.revenueBandIndex][i]) closest.push(i);
      }

      const suggestions = closest.map(ci => COVER_LIMITS[ci].label).join(', ');
      statusEl.innerHTML = `<span class="status-na">Not Available</span> <span class="status-suggest">Suggested: ${suggestions}</span>`;
    }
  }
}

/* ===== Comparison Table (Step 3) ===== */
function updateComparisonTable() {
  const tbody = $('comparison-tbody');
  tbody.innerHTML = '';

  const rows = $('competitor-rows').querySelectorAll('.competitor-row');
  rows.forEach((row, idx) => {
    const select = row.querySelector('.competitor-cover-select');
    const selectedValue = parseInt(select.value, 10);
    if (!selectedValue) return;

    const coverIdx = COVER_LIMITS.findIndex(cl => cl.value === selectedValue);
    if (coverIdx < 0) return;

    const calc = calculatePremium(coverIdx, state);
    if (!calc) return;

    const itoo = getItooBenchmark(state.actualTurnover, coverIdx);
    const compPremium = parseCurrency(row.querySelector('.competitor-premium-input').value);

    const tr = document.createElement('tr');
    const itooStr = itoo ? formatR(itoo.premium) : '--';
    const delta = itoo ? calc.annualExFP - itoo.premium : null;
    const deltaStr = delta !== null ? `${delta >= 0 ? '+' : ''}${formatR(Math.abs(delta))} (${delta >= 0 ? '+' : '-'}${Math.abs(Math.round(delta / itoo.premium * 100))}%)` : '--';
    const deltaClass = delta !== null ? (delta <= 0 ? 'delta-green' : (delta / itoo.premium <= 0.05 ? 'delta-amber' : 'delta-red')) : '';

    tr.innerHTML = `
      <td>${COVER_LIMITS[coverIdx].label}</td>
      <td>${formatR(calc.annual)}</td>
      <td>${formatR(calc.annualExFP)}</td>
      <td>${itooStr}</td>
      <td class="${deltaClass}">${deltaStr}</td>
    `;
    tbody.appendChild(tr);
  });
}

/* ===== Step 4: Live Comparison Bars ===== */
function updateComparisonBars() {
  const container = $('comparison-bars');
  container.innerHTML = '';

  // Gather all cover limits being quoted
  const coverIndices = [];
  const rows = $('competitor-rows').querySelectorAll('.competitor-row');
  rows.forEach(row => {
    const val = parseInt(row.querySelector('.competitor-cover-select').value, 10);
    if (val) {
      const idx = COVER_LIMITS.findIndex(cl => cl.value === val);
      if (idx >= 0 && !coverIndices.includes(idx)) coverIndices.push(idx);
    }
  });

  // Fallback to selected covers
  if (coverIndices.length === 0) {
    state.selectedCovers.forEach(ci => {
      if (!coverIndices.includes(ci)) coverIndices.push(ci);
    });
  }

  coverIndices.forEach(ci => {
    let calc = calculatePremium(ci, state);
    if (!calc) return;

    // Apply manual override if set
    let phishieldPremium = calc.annualExFP;
    if (state.manualOverride && state.manualOverride > 0) {
      phishieldPremium = state.manualOverride;
    }

    let targetPremium = 0;
    let targetLabel = '';

    if (state.compareTarget === 'itoo') {
      const itoo = getItooBenchmark(state.actualTurnover, ci);
      if (itoo) {
        targetPremium = itoo.premium;
        targetLabel = 'Industry';
      }
    } else {
      // Find competitor premium for this cover
      const compRow = state.competitorRows.find(r => r && r.requestedCoverIndex === ci);
      if (compRow && compRow.competitorPremium > 0) {
        targetPremium = compRow.competitorPremium;
        targetLabel = 'Competitor';
      }
    }

    if (targetPremium <= 0) return;

    const maxVal = Math.max(phishieldPremium, targetPremium);
    const phishieldPct = (phishieldPremium / maxVal) * 100;
    const targetPct = (targetPremium / maxVal) * 100;
    const delta = phishieldPremium - targetPremium;
    const deltaPct = Math.round((delta / targetPremium) * 100);

    let barColor = 'var(--green)';
    if (delta > 0) {
      barColor = Math.abs(deltaPct) <= 5 ? 'var(--amber, #f59e0b)' : 'var(--red, #ef4444)';
    }

    const statusText = delta <= 0
      ? 'Competitive — Phishield is lower'
      : (Math.abs(deltaPct) <= 5 ? 'Close — within 5% of benchmark' : 'Over benchmark');
    const statusClass = delta <= 0 ? 'delta-green' : (Math.abs(deltaPct) <= 5 ? 'delta-amber' : 'delta-red');

    const barDiv = document.createElement('div');
    barDiv.className = 'comparison-bar';
    barDiv.innerHTML = `
      <div class="comparison-bar-header">
        <span class="comparison-bar-label">${COVER_LIMITS[ci].label} Cover</span>
        <span class="bar-status ${statusClass}">${statusText}</span>
      </div>
      <div class="comparison-bar-values">
        <span class="bar-value-phishield">Phishield (ex-FP): <strong>${formatR(phishieldPremium)}</strong></span>
        <span class="bar-value-target">${targetLabel}: <strong>${formatR(targetPremium)}</strong></span>
      </div>
      <div class="comparison-bar-track">
        <div class="bar-target-line" style="left: ${targetPct}%;" title="${targetLabel}: ${formatR(targetPremium)}"></div>
        <div class="bar-fill" style="width: ${phishieldPct}%; background: ${barColor};" title="Phishield (ex-FP): ${formatR(phishieldPremium)}"></div>
      </div>
      <div class="bar-delta ${statusClass}">
        Difference: ${delta <= 0 ? '' : '+'}${formatR(Math.abs(delta))} (${delta <= 0 ? '' : '+'}${deltaPct}%) &nbsp;|&nbsp; FP benefit included: ${formatR(calc.fpCost)}
      </div>
    `;
    container.appendChild(barDiv);
  });
}

/* ===== Step 4: Discount Logic ===== */
function updateDiscounts() {
  const posture = parseFloat($('posture-discount').value) || 0;
  const discretionary = parseFloat($('discretionary-discount').value) || 0;

  state.postureDiscount = Math.min(posture, 100) / 100;
  state.discretionaryDiscount = Math.min(discretionary, 100) / 100;

  // Combined discount check
  const combined = 1 - (1 - state.postureDiscount) * (1 - state.discretionaryDiscount);
  const warning = $('discount-warning');
  if (combined > 0.35) {
    warning.style.display = 'flex';
  } else {
    warning.style.display = 'none';
  }

  // Update computed values
  const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
  if (covers.length > 0) {
    const calc = calculatePremium(covers[0], state);
    if (calc) {
      const baseBeforeDisc = calc.annual / ((1 - state.postureDiscount) * (1 - state.discretionaryDiscount)) || calc.annual;
      const postureAmt = baseBeforeDisc * state.postureDiscount;
      const discAmt = (baseBeforeDisc - postureAmt) * state.discretionaryDiscount;
      $('posture-discount-value').textContent = formatR(postureAmt);
      $('discretionary-discount-value').textContent = formatR(discAmt);
    }
  }

  // Manual override
  const overrideVal = parseCurrency($('manual-override').value);
  state.manualOverride = overrideVal > 0 ? overrideVal : null;

  updatePricing();
  updateComparisonBars();
}

/* ===== Step 5: Quote Summary ===== */
function generateQuoteRef() {
  const now = new Date();
  const dateStr = now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0');
  const seq = String(Math.floor(Math.random() * 10000)).padStart(4, '0');
  state.quoteRef = `CPB-${dateStr}-${seq}`;
  $('quote-ref-date').textContent = dateStr;
  $('quote-ref-seq').textContent = seq;
}

function populateSummary() {
  generateQuoteRef();

  // Client summary
  $('sum-company').textContent = state.companyName || '--';
  $('sum-industry').textContent = state.industryIndex >= 0
    ? `${INDUSTRIES[state.industryIndex].main} — ${INDUSTRIES[state.industryIndex].sub}`
    : '--';
  $('sum-turnover').textContent = state.actualTurnover > 0 ? formatR(state.actualTurnover) : '--';
  $('sum-bracket').textContent = state.revenueBandIndex >= 0 ? REVENUE_BANDS[state.revenueBandIndex].label : '--';

  const quoteTypeLabels = { new: 'New Business', renewal: 'Renewal', competing: 'Competing Quote' };
  $('sum-quote-type').textContent = quoteTypeLabels[state.quoteType] || '--';

  // Market badge
  $('summary-market-badge').style.display = state.quoteType === 'renewal' ? 'flex' : 'none';

  // UW summary
  const outcomeLabels = {
    standard: 'Standard Rates',
    caution: 'Proceed with Caution',
    loading: `${Math.round(state.uwLoadingPct * 100)}% Loading`,
    decline: 'Declined',
    refer: 'Refer to Senior UW',
  };
  $('sum-uw-outcome').textContent = outcomeLabels[state.uwOutcome] || '--';
  $('sum-uw-loadings').textContent = state.uwLoadingPct > 0 ? `${Math.round(state.uwLoadingPct * 100)}%` : 'None';
  $('sum-uw-conditions').textContent = (state.uwFPConditions && state.uwFPConditions.length > 0)
    ? state.uwFPConditions.join('; ')
    : 'None';

  // Prior claim
  $('sum-prior-claim').style.display = state.priorClaim ? 'flex' : 'none';

  // Per cover limit breakdowns
  renderQuoteBreakdowns();
}

function renderQuoteBreakdowns() {
  const container = $('quote-breakdowns');
  container.innerHTML = '';

  const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;

  // Also include competitor row covers
  const allCovers = [...covers];
  state.competitorRows.forEach(row => {
    if (row && row.requestedCoverIndex >= 0 && !allCovers.includes(row.requestedCoverIndex)) {
      allCovers.push(row.requestedCoverIndex);
    }
  });

  allCovers.forEach(ci => {
    const calc = calculatePremium(ci, state);
    if (!calc) return;

    const itoo = getItooBenchmark(state.actualTurnover, ci);
    const compRow = state.competitorRows.find(r => r && r.requestedCoverIndex === ci);

    const card = document.createElement('div');
    card.className = 'quote-breakdown-card';

    // Audit trail rows
    let trailRows = '';
    calc.breakdown.forEach(b => {
      trailRows += `<tr><td>${b.step}</td><td>${b.desc}</td><td>${formatR(b.value)}</td></tr>`;
    });

    // Comparison row
    const itooStr = itoo ? formatR(itoo.premium) : '--';
    const compStr = (compRow && compRow.competitorPremium > 0) ? formatR(compRow.competitorPremium) : '--';

    let deltaStr = '--';
    if (itoo) {
      const d = calc.annualExFP - itoo.premium;
      deltaStr = `${d <= 0 ? '' : '+'}${formatR(Math.abs(d))} (${d <= 0 ? '' : '+'}${Math.round(d / itoo.premium * 100)}%)`;
    }

    card.innerHTML = `
      <div class="breakdown-header">
        <h4>Cover Limit: ${COVER_LIMITS[ci].label}</h4>
        ${calc.isMicro ? '<span class="micro-label">Micro SME</span>' : ''}
      </div>
      <table class="audit-trail">
        <thead><tr><th>Step</th><th>Description</th><th class="text-right">Value</th></tr></thead>
        <tbody>${trailRows}</tbody>
      </table>
      <div class="breakdown-finals">
        <div class="breakdown-final-item">
          <span class="bf-label">Annual (with FP)</span>
          <strong class="bf-value accent">${formatR(calc.annual)}</strong>
        </div>
        <div class="breakdown-final-item">
          <span class="bf-label">Annual (excl FP)</span>
          <strong class="bf-value">${formatR(calc.annualExFP)}</strong>
        </div>
        <div class="breakdown-final-item">
          <span class="bf-label">Monthly</span>
          <strong class="bf-value accent">${formatR(calc.monthly)}</strong>
        </div>
      </div>
      <div class="breakdown-comparison">
        <div class="bc-item"><span class="bc-label">Industry Benchmark</span><strong>${itooStr}</strong></div>
        <div class="bc-item"><span class="bc-label">Competitor</span><strong>${compStr}</strong></div>
        <div class="bc-item"><span class="bc-label">Delta vs Industry</span><strong class="${itoo && calc.annualExFP <= itoo.premium ? 'text-success' : 'text-danger'}">${deltaStr}</strong></div>
      </div>
    `;

    container.appendChild(card);
  });
}

/* ===== Clipboard Export ===== */
function buildClipboardText() {
  const lines = [];
  lines.push('PHISHIELD SME RATING ENGINE — QUOTE SUMMARY');
  lines.push('='.repeat(50));
  lines.push(`Quote Ref: ${state.quoteRef}`);
  lines.push(`Date: ${new Date().toLocaleDateString('en-ZA')}`);
  lines.push('');
  lines.push('CLIENT DETAILS');
  lines.push('-'.repeat(30));
  lines.push(`Company: ${state.companyName}`);
  if (state.industryIndex >= 0) {
    lines.push(`Industry: ${INDUSTRIES[state.industryIndex].main} — ${INDUSTRIES[state.industryIndex].sub}`);
  }
  lines.push(`Actual Turnover: ${formatR(state.actualTurnover)}`);
  lines.push(`Revenue Bracket: ${state.revenueBandIndex >= 0 ? REVENUE_BANDS[state.revenueBandIndex].label : '--'}`);
  lines.push(`Quote Type: ${state.quoteType}`);
  lines.push('');
  lines.push('UNDERWRITING');
  lines.push('-'.repeat(30));
  lines.push(`Outcome: ${state.uwOutcome || '--'}`);
  lines.push(`Loading: ${state.uwLoadingPct > 0 ? Math.round(state.uwLoadingPct * 100) + '%' : 'None'}`);
  if (state.priorClaim) lines.push('** Prior claim flagged **');
  lines.push('');
  lines.push('PREMIUMS');
  lines.push('-'.repeat(30));

  const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
  covers.forEach(ci => {
    const calc = state.calculations[ci] || calculatePremium(ci, state);
    if (!calc) return;
    lines.push(`${COVER_LIMITS[ci].label}: ${formatR(calc.annual)}/yr (${formatR(calc.monthly)}/mo) | Ex-FP: ${formatR(calc.annualExFP)}`);
  });

  lines.push('');
  lines.push('Internal use only. Subject to final underwriting approval.');
  return lines.join('\n');
}


/* ===== INITIALIZATION ===== */
document.addEventListener('DOMContentLoaded', () => {

  // Populate industry dropdown
  populateIndustryDropdown();

  // ─── Step 1 Event Listeners ─────────────────────────────────

  // Company name
  $('company-name').addEventListener('input', () => {
    state.companyName = $('company-name').value.trim();
    checkNextBtn1();
  });

  // Industry select
  $('industry-select').addEventListener('change', () => {
    const select = $('industry-select');
    const idx = parseInt(select.value, 10);
    state.industryIndex = idx;

    const industry = INDUSTRIES[idx];

    // Check referForUW
    if (industry.referForUW) {
      setBlocker(true, `${industry.main} requires referral for underwriting.`);
      return;
    }

    // Clear any industry-based blocker
    if (state.isBlocked && !state.blockReason.includes('R200M') && !state.blockReason.includes('Underwriting declined')) {
      setBlocker(false, '');
    }

    checkNextBtn1();
  });

  // Turnover inputs
  ['turnover-prev', 'turnover-current'].forEach(id => {
    const el = $(id);
    el.addEventListener('blur', () => {
      formatCurrencyInput(el);
      updateTurnoverInfo();
    });
    el.addEventListener('focus', () => stripCurrencyInput(el));
    el.addEventListener('paste', () => {
      setTimeout(() => updateTurnoverInfo(), 50);
    });
  });

  // Employee count
  $('employee-count').addEventListener('input', () => {
    state.employeeCount = parseInt($('employee-count').value, 10) || 0;
  });

  // UW toggle buttons
  $$('.uw-question .toggle-btn, .uw-sub-question .toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const parent = btn.closest('.uw-sub-question') || btn.closest('.uw-question');
      const key = parent.dataset.uw;
      const value = btn.dataset.value === 'yes';

      // Toggle active state
      parent.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      state.uwAnswers[key] = value;
      evaluateUW();
      checkNextBtn1();
    });
  });

  // FP checkbox
  $('fp-over-250k').addEventListener('change', () => {
    state.fpOver250k = $('fp-over-250k').checked;
    toggleFPQuestions(state.fpOver250k);
    evaluateUW();
  });

  // Prior claim
  $('prior-claim-check').addEventListener('change', () => {
    state.priorClaim = $('prior-claim-check').checked;
    $('prior-claim-warning').style.display = state.priorClaim ? 'flex' : 'none';
  });

  // Quote type toggle
  $('quote-type-toggle').querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('quote-type-toggle').querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.quoteType = btn.dataset.value;

      $('renewal-section').style.display = state.quoteType === 'renewal' ? 'block' : 'none';
      $('competing-section').style.display = state.quoteType === 'competing' ? 'block' : 'none';
    });
  });

  // Renewal inputs
  $('renewal-cover-limit').addEventListener('change', () => {
    const val = parseInt($('renewal-cover-limit').value, 10);
    state.renewalCoverIndex = COVER_LIMITS.findIndex(cl => cl.value === val);
  });

  $('renewal-premium').addEventListener('blur', () => {
    formatCurrencyInput($('renewal-premium'));
    state.renewalPremium = parseCurrency($('renewal-premium').value);
  });
  $('renewal-premium').addEventListener('focus', () => stripCurrencyInput($('renewal-premium')));

  // Competing inputs
  $('competitor-name').addEventListener('input', () => {
    state.competitorName = $('competitor-name').value.trim();
  });

  $('competitor-cover-limit').addEventListener('change', () => {
    const val = parseInt($('competitor-cover-limit').value, 10);
    state.competitorCoverIndex = COVER_LIMITS.findIndex(cl => cl.value === val);
  });

  $('competitor-premium').addEventListener('blur', () => {
    formatCurrencyInput($('competitor-premium'));
    state.competitorPremium = parseCurrency($('competitor-premium').value);
  });
  $('competitor-premium').addEventListener('focus', () => stripCurrencyInput($('competitor-premium')));

  // ─── Step 1 Next Button ─────────────────────────────────────

  $('nextBtn1').addEventListener('click', () => {
    if ($('nextBtn1').disabled) return;

    // Render step 2 content
    renderRecommendations();
    renderCoverBadges();
    updatePricing();
    goToStep(2);
  });

  // ─── Step 2 Event Listeners ─────────────────────────────────

  // Custom cover toggle
  $('custom-cover-toggle').addEventListener('click', () => {
    const section = $('custom-selection');
    const isHidden = section.style.display === 'none';
    section.style.display = isHidden ? 'block' : 'none';
    state.isCustomSelection = isHidden;
  });

  // Custom cover selector cards
  $$('#cover-selector .sel-card').forEach(card => {
    card.addEventListener('click', () => {
      if (card.classList.contains('unavailable')) return;

      const ci = parseInt(card.dataset.coverIndex, 10);

      // Toggle selection
      $$('#cover-selector .sel-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      state.selectedCovers = [ci];

      // Check micro
      state.isMicroSME = checkMicroSME(state.industryIndex, state.revenueBandIndex, ci);
      $('micro-badge').style.display = state.isMicroSME ? 'flex' : 'none';

      // Deselect recommendation cards
      $$('.cover-rec-card').forEach(c => c.classList.remove('active'));

      renderFPSelector(ci);
      updatePricing();
    });
  });

  $('nextBtn2').addEventListener('click', () => {
    if (state.selectedCovers.length === 0 && state.recommendedCovers.length === 0) {
      // Need at least one cover selected
      return;
    }
    updateCompetitorRows();
    goToStep(3);
  });

  $('backBtn2').addEventListener('click', () => goToStep(1));

  // ─── Step 3 Event Listeners ─────────────────────────────────

  $('num-cover-limits').addEventListener('change', () => {
    state.numRequestedCovers = parseInt($('num-cover-limits').value, 10) || 1;
    updateCompetitorRows();
  });

  // Existing quotes toggle
  $('existing-quote-toggle').querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('existing-quote-toggle').querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.hasExistingQuotes = btn.dataset.value === 'yes';
      updateCompetitorRows();
    });
  });

  // Setup initial competitor row events
  const firstRow = $('competitor-rows').querySelector('.competitor-row');
  if (firstRow) setupCompetitorRowEvents(firstRow, 0);

  $('nextBtn3').addEventListener('click', () => {
    updateDiscounts();
    updateComparisonBars();
    goToStep(4);
  });

  $('backBtn3').addEventListener('click', () => goToStep(2));

  // ─── Step 4 Event Listeners ─────────────────────────────────

  $('posture-discount').addEventListener('input', updateDiscounts);
  $('discretionary-discount').addEventListener('input', updateDiscounts);
  $('manual-override').addEventListener('blur', () => {
    formatCurrencyInput($('manual-override'));
    updateDiscounts();
  });
  $('manual-override').addEventListener('focus', () => stripCurrencyInput($('manual-override')));

  // Compare toggle
  $('compare-toggle').querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('compare-toggle').querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.compareTarget = btn.dataset.value;
      updateComparisonBars();
    });
  });

  $('nextBtn4').addEventListener('click', () => {
    populateSummary();
    goToStep(5);
  });

  $('backBtn4').addEventListener('click', () => goToStep(3));

  // ─── Step 5 Event Listeners ─────────────────────────────────

  $('btn-print').addEventListener('click', () => window.print());

  $('btn-clipboard').addEventListener('click', () => {
    const text = buildClipboardText();
    navigator.clipboard.writeText(text).then(() => {
      const btn = $('btn-clipboard');
      const origHTML = btn.innerHTML;
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!';
      setTimeout(() => { btn.innerHTML = origHTML; }, 2000);
    });
  });

  // ─── Progress Step Clicks (backward navigation only) ─────────

  $$('.progress-step').forEach(step => {
    step.addEventListener('click', () => {
      const targetStep = parseInt(step.dataset.step, 10);
      if (targetStep < state.currentStep) {
        goToStep(targetStep);
      }
    });
  });

  // ─── Initialize ──────────────────────────────────────────────
  checkNextBtn1();
});
