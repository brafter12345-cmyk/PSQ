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
  websiteAddress: '',
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
  // Step 2 — Multi-cover quote options
  quoteOptions: [],           // [{id, coverIndex, fpIndex, label, postureDiscount, discretionaryDiscount, manualOverride, competitorRows}]
  activeOptionTab: null,      // Currently active option tab ID
  selectedCovers: [],         // Backward compat: derived from quoteOptions
  isMicroSME: false,
  fpSelections: {},           // Backward compat: derived from quoteOptions
  recommendedCovers: [],
  isCustomSelection: false,
  // Step 3
  numRequestedCovers: 1,
  hasExistingQuotes: false,
  competitorHasFP: false,
  competitorRows: [],
  // Step 4
  postureDiscount: 0,
  discretionaryDiscount: 0,
  manualOverride: null,
  endorsements: '',
  compareTarget: 'itoo',
  applyDiscountsToAll: true,
  // Computed
  calculations: {},           // Keyed by option ID (not cover index)
  quoteRef: '',
  baseRef: '',                // Shared base ref: CPB-YYYYMMDD-NNNN
  isBlocked: false,
  blockReason: '',
};

/* ===== Multi-Cover Helper: Generate Option ID ===== */
let _optionCounter = 0;
function generateOptionId() {
  return 'opt-' + (++_optionCounter);
}

/* ===== Multi-Cover: Build option label ===== */
function buildOptionLabel(coverIndex, fpIndex) {
  const coverLabel = COVER_LIMITS[coverIndex].label;
  const coverKey = COVER_LIMITS[coverIndex].key;
  const availFP = getAvailableFPOptions(coverKey);
  const fpLabel = (fpIndex >= 0 && fpIndex < availFP.length) ? availFP[fpIndex].label : 'Base FP';
  return coverLabel + ' / FP ' + fpLabel;
}

/* ===== Multi-Cover: Sync selectedCovers & fpSelections from quoteOptions ===== */
function syncFromQuoteOptions() {
  state.selectedCovers = state.quoteOptions.map(opt => opt.coverIndex);
  state.fpSelections = {};
  state.quoteOptions.forEach(opt => {
    // Use the last fpIndex for each coverIndex (backward compat)
    state.fpSelections[opt.coverIndex] = opt.fpIndex;
  });
}

/* ===== Multi-Cover: Add option ===== */
function addQuoteOption(coverIndex, fpIndex) {
  if (state.quoteOptions.length >= 4) return null;
  fpIndex = fpIndex || 0;
  const opt = {
    id: generateOptionId(),
    coverIndex: coverIndex,
    fpIndex: fpIndex,
    label: buildOptionLabel(coverIndex, fpIndex),
    postureDiscount: 0,
    discretionaryDiscount: 0,
    manualOverride: null,
    competitorRows: [],
  };
  state.quoteOptions.push(opt);
  syncFromQuoteOptions();
  return opt;
}

/* ===== Multi-Cover: Remove option ===== */
function removeQuoteOption(optionId) {
  state.quoteOptions = state.quoteOptions.filter(o => o.id !== optionId);
  syncFromQuoteOptions();
}

/* ===== Multi-Cover: Find option by ID ===== */
function getOption(optionId) {
  return state.quoteOptions.find(o => o.id === optionId);
}

/* ===== Multi-Cover: Is cover already in options? ===== */
function isCoverInOptions(coverIndex) {
  return state.quoteOptions.some(o => o.coverIndex === coverIndex);
}

/* ===== Multi-Cover: Count of options with same cover ===== */
function coverInstanceCount(coverIndex) {
  return state.quoteOptions.filter(o => o.coverIndex === coverIndex).length;
}

/* ===== Multi-Cover: Check if multi mode ===== */
function isMultiMode() {
  return state.quoteOptions.length >= 2;
}

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
function calculatePremium(coverIndex, overrideState, optionOverrides) {
  const s = overrideState || state;
  // optionOverrides: { fpIndex, postureDiscount, discretionaryDiscount } for per-option calc
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
    const microFpIdx = (optionOverrides && optionOverrides.fpIndex !== undefined) ? optionOverrides.fpIndex
      : (s.fpSelections && s.fpSelections[coverIndex] !== undefined) ? s.fpSelections[coverIndex] : undefined;
    if (microFpIdx !== undefined) {
      const availFP = getAvailableFPOptions(coverKey);
      if (microFpIdx >= 0 && microFpIdx < availFP.length) {
        selectedFPCost = availFP[microFpIdx].cost;
      }
    }
    breakdown.push({ step: 4, desc: 'Funds Protect cost', value: selectedFPCost });

    let totalPremium = adjustedBase + selectedFPCost;
    const annualExFP = adjustedBase;
    breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

    // Apply discounts
    const postureD = (optionOverrides && optionOverrides.postureDiscount !== undefined) ? optionOverrides.postureDiscount : (s.postureDiscount || 0);
    const discretionaryD = (optionOverrides && optionOverrides.discretionaryDiscount !== undefined) ? optionOverrides.discretionaryDiscount : (s.discretionaryDiscount || 0);
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
  const stdFpIdx = (optionOverrides && optionOverrides.fpIndex !== undefined) ? optionOverrides.fpIndex
    : (s.fpSelections && s.fpSelections[coverIndex] !== undefined) ? s.fpSelections[coverIndex] : undefined;
  if (stdFpIdx !== undefined) {
    const availFP = getAvailableFPOptions(coverKey);
    if (stdFpIdx >= 0 && stdFpIdx < availFP.length) {
      selectedFPCost = availFP[stdFpIdx].cost;
    }
  }
  breakdown.push({ step: 4, desc: 'Funds Protect cost', value: selectedFPCost });

  let totalPremium = adjustedBase + selectedFPCost;
  const annualExFP = adjustedBase;
  breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

  // 6. Discounts
  const postureD = (optionOverrides && optionOverrides.postureDiscount !== undefined) ? optionOverrides.postureDiscount : (s.postureDiscount || 0);
  const discretionaryD = (optionOverrides && optionOverrides.discretionaryDiscount !== undefined) ? optionOverrides.discretionaryDiscount : (s.discretionaryDiscount || 0);
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

  // Calculate for all quote options (multi-mode) or selected covers (legacy/single)
  state.calculations = {};

  if (state.quoteOptions.length > 0) {
    // Multi-cover mode: calculate per option
    state.quoteOptions.forEach(opt => {
      const calc = calculatePremium(opt.coverIndex, state, {
        fpIndex: opt.fpIndex,
        postureDiscount: opt.postureDiscount || 0,
        discretionaryDiscount: opt.discretionaryDiscount || 0,
      });
      if (calc) state.calculations[opt.id] = calc;
    });
  } else {
    // Legacy single-cover mode
    const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
    covers.forEach(ci => {
      const calc = calculatePremium(ci, state);
      if (calc) state.calculations[ci] = calc;
    });
  }

  const pdAnnualNum = $('pdAnnualNum');
  const pdMonthlyNum = $('pdMonthlyNum');
  const singleAmounts = $('pd-single-amounts');
  const multiContainer = $('multi-pricing-container');

  if (isMultiMode()) {
    // Multi-option: show table, hide single amounts
    singleAmounts.style.display = 'none';
    multiContainer.style.display = 'block';

    const tbody = $('multi-pricing-tbody');
    tbody.innerHTML = '';
    state.quoteOptions.forEach(opt => {
      const calc = state.calculations[opt.id];
      if (!calc) return;
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${opt.label}</td><td>${formatR(calc.annual)}</td><td>${formatR(calc.monthly)}</td>`;
      tbody.appendChild(tr);
    });

    // Ticker: show first option's monthly + count
    const firstOpt = state.quoteOptions[0];
    const firstCalc = state.calculations[firstOpt.id];
    const ticker = $('quoteTicker');
    const tickerAmount = $('tickerAmount');
    if (firstCalc && state.currentStep >= 2) {
      ticker.classList.add('visible');
      tickerAmount.innerHTML = formatR(firstCalc.monthly) + '/mo <span class="ticker-options-count">' + state.quoteOptions.length + ' options</span>';
    }
  } else {
    // Single-option mode
    singleAmounts.style.display = 'flex';
    multiContainer.style.display = 'none';

    let primaryCalc = null;
    if (state.quoteOptions.length === 1) {
      primaryCalc = state.calculations[state.quoteOptions[0].id];
    } else {
      const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
      primaryCalc = state.calculations[covers[0]];
    }

    if (primaryCalc) {
      animateNumber(pdAnnualNum, primaryCalc.annual);
      animateNumber(pdMonthlyNum, primaryCalc.monthly);

      const ticker = $('quoteTicker');
      const tickerAmount = $('tickerAmount');
      if (state.currentStep >= 2) {
        ticker.classList.add('visible');
        tickerAmount.textContent = formatR(primaryCalc.monthly) + '/mo';
      }
    } else {
      pdAnnualNum.textContent = '--';
      pdMonthlyNum.textContent = '--';
    }
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
    if (state.uwAnswers['q7-1'] === false) fpConditions.push('The Insured must have or implement documented procedures for the vetting of all new vendors, customers, and payees before processing any payments or financial transactions.');
    if (state.uwAnswers['q7-2'] === false) fpConditions.push('The Insured must have or implement documented procedures to verify all new beneficiaries loaded onto the business\'s banking profiles before authorising any funds transfers.');
    if (state.uwAnswers['q7-3'] === false) fpConditions.push('The Insured must have or implement documented procedures to verify and validate any requests to amend existing beneficiary payment details before processing changes.');
    if (state.uwAnswers['q8'] === false) fpConditions.push('The Insured must utilise account verification services offered by their bank or a third-party provider to confirm the legitimacy of beneficiary accounts before processing payments.');
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

/* ===== Searchable Industry Dropdown ===== */

const mainToLabel = {
  'Agriculture, Forestry, And Fishing': 'Agriculture',
  'Mining': 'Mining',
  'Construction': 'Construction',
  'Manufacturing': 'Manufacturing',
  'Transportation, Communications, Electric, Gas And Sanitary Services': 'Transportation',
  'Wholesale Trade': 'Wholesale Trade',
  'Retail Trade': 'Retail Trade',
  'Finance, Insurance, And Real Estate': 'Finance / Insurance / Real Estate',
  'Services': 'Services',
  'Healthcare': 'Healthcare',
  'Public Administration': 'Public Administration',
};

function populateIndustryDropdown() {
  const dropdown = $('industry-dropdown');
  const searchInput = $('industry-search');
  dropdown.innerHTML = '';

  // Group industries by main category
  const groups = {};
  INDUSTRIES.forEach((ind, idx) => {
    const label = mainToLabel[ind.main] || ind.main;
    if (!groups[label]) groups[label] = [];
    groups[label].push({ idx, sub: ind.sub, main: ind.main, refer: ind.referForUW });
  });

  // Render all groups and options
  Object.keys(groups).forEach(groupLabel => {
    const groupDiv = document.createElement('div');
    groupDiv.className = 'dropdown-group-label';
    groupDiv.textContent = groupLabel;
    groupDiv.dataset.group = groupLabel.toLowerCase();
    dropdown.appendChild(groupDiv);

    groups[groupLabel].forEach(item => {
      const optDiv = document.createElement('div');
      optDiv.className = 'dropdown-option';
      optDiv.textContent = item.sub;
      optDiv.dataset.idx = item.idx;
      optDiv.dataset.sub = item.sub.toLowerCase();
      optDiv.dataset.main = item.main.toLowerCase();
      optDiv.dataset.group = groupLabel.toLowerCase();
      optDiv.dataset.refer = item.refer ? 'true' : 'false';
      optDiv.addEventListener('click', () => selectIndustry(item.idx));
      dropdown.appendChild(optDiv);
    });
  });

  // Open dropdown on input focus/click
  searchInput.addEventListener('focus', () => {
    dropdown.classList.add('open');
    filterIndustryDropdown(searchInput.value);
  });

  searchInput.addEventListener('click', () => {
    dropdown.classList.add('open');
  });

  // Filter on typing
  searchInput.addEventListener('input', () => {
    dropdown.classList.add('open');
    filterIndustryDropdown(searchInput.value);
  });

  // Keyboard navigation
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      dropdown.classList.remove('open');
      searchInput.blur();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      moveHighlight(1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      moveHighlight(-1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const highlighted = dropdown.querySelector('.dropdown-option.highlighted');
      if (highlighted) {
        selectIndustry(parseInt(highlighted.dataset.idx));
      }
    }
  });

  // Close on click outside
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#industry-wrapper')) {
      dropdown.classList.remove('open');
    }
  });
}

function filterIndustryDropdown(query) {
  const dropdown = $('industry-dropdown');
  const q = query.toLowerCase().trim();
  let anyVisible = false;

  dropdown.querySelectorAll('.dropdown-group-label').forEach(g => g.style.display = 'none');
  dropdown.querySelectorAll('.dropdown-option').forEach(opt => {
    const matchesSub = opt.dataset.sub.includes(q);
    const matchesMain = opt.dataset.main.includes(q);
    const matchesGroup = opt.dataset.group.includes(q);
    const visible = !q || matchesSub || matchesMain || matchesGroup;
    opt.style.display = visible ? '' : 'none';
    if (visible) {
      anyVisible = true;
      // Show the group label too
      const groupLabel = opt.dataset.group;
      const groupEl = dropdown.querySelector(`.dropdown-group-label[data-group="${groupLabel}"]`);
      if (groupEl) groupEl.style.display = '';
    }
  });

  // Show "no results" message
  let noResults = dropdown.querySelector('.dropdown-no-results');
  if (!anyVisible) {
    if (!noResults) {
      noResults = document.createElement('div');
      noResults.className = 'dropdown-no-results';
      dropdown.appendChild(noResults);
    }
    noResults.textContent = `No industries matching "${query}"`;
    noResults.style.display = '';
  } else if (noResults) {
    noResults.style.display = 'none';
  }
}

function moveHighlight(direction) {
  const dropdown = $('industry-dropdown');
  const visible = Array.from(dropdown.querySelectorAll('.dropdown-option')).filter(o => o.style.display !== 'none');
  if (visible.length === 0) return;

  const current = dropdown.querySelector('.dropdown-option.highlighted');
  let idx = current ? visible.indexOf(current) : -1;
  if (current) current.classList.remove('highlighted');

  idx += direction;
  if (idx < 0) idx = visible.length - 1;
  if (idx >= visible.length) idx = 0;

  visible[idx].classList.add('highlighted');
  visible[idx].scrollIntoView({ block: 'nearest' });
}

function selectIndustry(industryIdx) {
  const dropdown = $('industry-dropdown');
  const searchInput = $('industry-search');
  const industry = INDUSTRIES[industryIdx];

  // Update hidden input and state
  $('industry-select').value = industryIdx;
  state.industryIndex = industryIdx;

  // Update search input display
  searchInput.value = industry.sub;

  // Mark selected
  dropdown.querySelectorAll('.dropdown-option').forEach(o => o.classList.remove('selected'));
  const selected = dropdown.querySelector(`.dropdown-option[data-idx="${industryIdx}"]`);
  if (selected) selected.classList.add('selected');

  // Close dropdown
  dropdown.classList.remove('open');

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
      <div class="check-overlay">&#10003;</div>
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
      <button type="button" class="duplicate-btn" title="Add another option with this cover limit">+</button>
    `;

    // Multi-toggle: click to add/remove from quoteOptions
    card.addEventListener('click', (e) => {
      // Ignore if clicking the duplicate button
      if (e.target.closest('.duplicate-btn')) return;

      if (isCoverInOptions(ci)) {
        // Remove all instances of this cover
        state.quoteOptions = state.quoteOptions.filter(o => o.coverIndex !== ci);
        syncFromQuoteOptions();
        card.classList.remove('selected', 'active');
      } else {
        // Add this cover as a new option (max 4)
        if (state.quoteOptions.length >= 4) return;
        addQuoteOption(ci, 0);
        card.classList.add('selected', 'active');
      }

      state.isCustomSelection = false;

      // Update micro badge
      state.isMicroSME = calc.isMicro;
      $('micro-badge').style.display = calc.isMicro ? 'flex' : 'none';

      // Deselect custom cards
      $$('#cover-selector .sel-card').forEach(c => c.classList.remove('active'));

      renderFPSelectorMulti();
      updatePricing();
    });

    // Duplicate button: add another instance of same cover
    const dupBtn = card.querySelector('.duplicate-btn');
    dupBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (state.quoteOptions.length >= 4) return;
      addQuoteOption(ci, 0);
      renderFPSelectorMulti();
      updatePricing();
    });

    container.appendChild(card);
  });

  // Auto-select ALL recommended options if no options yet
  if (recommended.length > 0 && state.quoteOptions.length === 0) {
    const allCards = container.querySelectorAll('.cover-rec-card.recommended');
    allCards.forEach(card => {
      const ci = parseInt(card.dataset.coverIndex, 10);
      addQuoteOption(ci, 0);
      card.classList.add('selected', 'active');
    });

    // Check micro for first option
    if (state.quoteOptions.length > 0) {
      const firstCalc = calculatePremium(state.quoteOptions[0].coverIndex, state);
      if (firstCalc) {
        state.isMicroSME = firstCalc.isMicro;
        $('micro-badge').style.display = firstCalc.isMicro ? 'flex' : 'none';
      }
    }
    renderFPSelectorMulti();
    updatePricing();
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

    // Mark active if cover is in quoteOptions
    if (isCoverInOptions(idx)) {
      card.classList.add('active');
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

/* ===== Render FP Selector Multi-Option ===== */
function renderFPSelectorMulti() {
  const tabsContainer = $('fp-option-tabs');
  const fpContainer = $('fp-selector');

  if (state.quoteOptions.length === 0) {
    tabsContainer.classList.add('hidden');
    fpContainer.innerHTML = '';
    return;
  }

  if (state.quoteOptions.length === 1) {
    // Single option — no tabs, just render FP for the single option
    tabsContainer.classList.add('hidden');
    const opt = state.quoteOptions[0];
    renderFPSelectorForOption(opt);
    return;
  }

  // Multi-option: show tabs
  tabsContainer.classList.remove('hidden');
  tabsContainer.innerHTML = '';

  state.quoteOptions.forEach((opt, idx) => {
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.className = 'option-tab' + (idx === 0 ? ' active' : '');
    tab.dataset.optionId = opt.id;
    // Label: cover label + instance number if duplicated
    const instanceNum = coverInstanceCount(opt.coverIndex) > 1
      ? ' (' + (state.quoteOptions.filter((o, i) => o.coverIndex === opt.coverIndex && i <= idx).length) + ')'
      : '';
    tab.textContent = COVER_LIMITS[opt.coverIndex].label + instanceNum;

    tab.addEventListener('click', () => {
      tabsContainer.querySelectorAll('.option-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeOptionTab = opt.id;
      renderFPSelectorForOption(opt);
    });

    tabsContainer.appendChild(tab);
  });

  // Show first option's FP
  state.activeOptionTab = state.quoteOptions[0].id;
  renderFPSelectorForOption(state.quoteOptions[0]);
}

/* ===== Render FP Selector for a specific option ===== */
function renderFPSelectorForOption(opt) {
  const container = $('fp-selector');
  container.innerHTML = '';

  const coverKey = COVER_LIMITS[opt.coverIndex].key;
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

    if (idx === opt.fpIndex) card.classList.add('active');

    card.addEventListener('click', () => {
      container.querySelectorAll('.fp-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      opt.fpIndex = idx;
      opt.label = buildOptionLabel(opt.coverIndex, idx);

      // Also update backward compat
      state.fpSelections[opt.coverIndex] = idx;

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

  // Check auto-activate FP > R250k
  const baseFP = BASE_FP_BY_COVER[coverKey];
  if (baseFP > 250_000) {
    state.fpOver250k = true;
    const checkbox = $('fp-over-250k');
    if (checkbox) checkbox.checked = true;
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

  // In multi-mode, sync count from quoteOptions
  const count = isMultiMode() ? state.quoteOptions.length : state.numRequestedCovers;

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

  // In multi-mode, auto-map each row to its corresponding quote option
  if (isMultiMode()) {
    const rows = container.querySelectorAll('.competitor-row');
    rows.forEach((row, idx) => {
      if (idx < state.quoteOptions.length) {
        const opt = state.quoteOptions[idx];
        const coverValue = COVER_LIMITS[opt.coverIndex].value;
        const select = row.querySelector('.competitor-cover-select');

        // Auto-set dropdown to the quote option's cover limit
        if (select) {
          select.value = coverValue.toString();
          select.dispatchEvent(new Event('change'));
        }

        // Update the row label with sequential number and cover info
        const labelEl = row.querySelector('.competitor-row-header');
        if (labelEl) {
          labelEl.textContent = 'QUOTE OPTION ' + (idx + 1) + ': ' + opt.label;
        } else {
          // Create label if it doesn't exist
          const label = document.createElement('div');
          label.className = 'competitor-row-header';
          label.textContent = 'QUOTE OPTION ' + (idx + 1) + ': ' + opt.label;
          row.insertBefore(label, row.firstChild);
        }
      }
    });
  } else {
    // Single mode: update labels with sequential numbers
    const rows = container.querySelectorAll('.competitor-row');
    rows.forEach((row, idx) => {
      const labelEl = row.querySelector('.competitor-row-header');
      if (labelEl) {
        labelEl.textContent = 'QUOTE OPTION ' + (idx + 1);
      }
    });
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

  // Determine which Phishield figure to compare: ex-FP (default) or with FP (if competitor includes FP)
  const useFullPremium = state.competitorHasFP;
  const compLabel = useFullPremium ? 'Phishield (with FP)' : 'Phishield (ex-FP)';

  // Update the comparison column header
  const thead = tbody.closest('table')?.querySelector('thead');
  if (thead) {
    const headers = thead.querySelectorAll('th');
    if (headers.length >= 3) headers[2].textContent = compLabel;
  }

  // If we have quoteOptions, show a row per option in the comparison table
  if (state.quoteOptions.length > 0) {
    state.quoteOptions.forEach(opt => {
      const ci = opt.coverIndex;
      const calc = calculatePremium(ci, state, { fpIndex: opt.fpIndex, postureDiscount: opt.postureDiscount || 0, discretionaryDiscount: opt.discretionaryDiscount || 0 });
      if (!calc) return;

      const phishieldCompare = useFullPremium ? calc.annual : calc.annualExFP;
      const itoo = getItooBenchmark(state.actualTurnover, ci);
      const tr = document.createElement('tr');
      const itooStr = itoo ? formatR(itoo.premium) : '--';
      const delta = itoo ? phishieldCompare - itoo.premium : null;
      const deltaStr = delta !== null ? `${delta >= 0 ? '+' : ''}${formatR(Math.abs(delta))} (${delta >= 0 ? '+' : '-'}${Math.abs(Math.round(delta / itoo.premium * 100))}%)` : '--';
      const deltaClass = delta !== null ? (delta <= 0 ? 'delta-green' : (delta / itoo.premium <= 0.05 ? 'delta-amber' : 'delta-red')) : '';

      tr.innerHTML = `
        <td>${opt.label}</td>
        <td>${formatR(calc.annual)}</td>
        <td>${formatR(phishieldCompare)}</td>
        <td>${itooStr}</td>
        <td class="${deltaClass}">${deltaStr}</td>
      `;
      tbody.appendChild(tr);
    });
    return;
  }

  // Legacy: competitor rows
  const rows = $('competitor-rows').querySelectorAll('.competitor-row');
  rows.forEach((row, idx) => {
    const select = row.querySelector('.competitor-cover-select');
    const selectedValue = parseInt(select.value, 10);
    if (!selectedValue) return;

    const coverIdx = COVER_LIMITS.findIndex(cl => cl.value === selectedValue);
    if (coverIdx < 0) return;

    const calc = calculatePremium(coverIdx, state);
    if (!calc) return;

    const phishieldCompare = useFullPremium ? calc.annual : calc.annualExFP;
    const itoo = getItooBenchmark(state.actualTurnover, coverIdx);
    const compPremium = parseCurrency(row.querySelector('.competitor-premium-input').value);

    const tr = document.createElement('tr');
    const itooStr = itoo ? formatR(itoo.premium) : '--';
    const delta = itoo ? phishieldCompare - itoo.premium : null;
    const deltaStr = delta !== null ? `${delta >= 0 ? '+' : ''}${formatR(Math.abs(delta))} (${delta >= 0 ? '+' : '-'}${Math.abs(Math.round(delta / itoo.premium * 100))}%)` : '--';
    const deltaClass = delta !== null ? (delta <= 0 ? 'delta-green' : (delta / itoo.premium <= 0.05 ? 'delta-amber' : 'delta-red')) : '';

    tr.innerHTML = `
      <td>${COVER_LIMITS[coverIdx].label}</td>
      <td>${formatR(calc.annual)}</td>
      <td>${formatR(phishieldCompare)}</td>
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

  // Build list of items to compare
  const compareItems = []; // [{label, coverIndex, calc, fpCost, manualOverride}]

  if (state.quoteOptions.length > 0) {
    state.quoteOptions.forEach(opt => {
      const calc = calculatePremium(opt.coverIndex, state, {
        fpIndex: opt.fpIndex,
        postureDiscount: opt.postureDiscount || 0,
        discretionaryDiscount: opt.discretionaryDiscount || 0,
      });
      if (calc) {
        compareItems.push({
          label: opt.label,
          coverIndex: opt.coverIndex,
          calc: calc,
          fpCost: calc.fpCost,
          manualOverride: opt.manualOverride,
        });
      }
    });
  } else {
    // Legacy: gather from competitor rows and selected covers
    const coverIndices = [];
    const rows = $('competitor-rows').querySelectorAll('.competitor-row');
    rows.forEach(row => {
      const val = parseInt(row.querySelector('.competitor-cover-select').value, 10);
      if (val) {
        const idx = COVER_LIMITS.findIndex(cl => cl.value === val);
        if (idx >= 0 && !coverIndices.includes(idx)) coverIndices.push(idx);
      }
    });
    if (coverIndices.length === 0) {
      state.selectedCovers.forEach(ci => {
        if (!coverIndices.includes(ci)) coverIndices.push(ci);
      });
    }
    coverIndices.forEach(ci => {
      const calc = calculatePremium(ci, state);
      if (calc) {
        compareItems.push({
          label: COVER_LIMITS[ci].label,
          coverIndex: ci,
          calc: calc,
          fpCost: calc.fpCost,
          manualOverride: state.manualOverride,
        });
      }
    });
  }

  compareItems.forEach(item => {
    let phishieldPremium = state.competitorHasFP ? item.calc.annual : item.calc.annualExFP;
    if (item.manualOverride && item.manualOverride > 0) {
      phishieldPremium = item.manualOverride;
    }

    let targetPremium = 0;
    let targetLabel = '';

    if (state.compareTarget === 'itoo') {
      const itoo = getItooBenchmark(state.actualTurnover, item.coverIndex);
      if (itoo) {
        targetPremium = itoo.premium;
        targetLabel = 'Industry';
      }
    } else {
      const compRow = state.competitorRows.find(r => r && r.requestedCoverIndex === item.coverIndex);
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

    let barColor = 'var(--success, #2ec4b6)';
    if (delta > 0) {
      barColor = Math.abs(deltaPct) <= 5 ? 'var(--warning, #ffb703)' : 'var(--danger, #e63946)';
    }

    const statusText = delta <= 0
      ? 'Competitive — Phishield is lower'
      : (Math.abs(deltaPct) <= 5 ? 'Close — within 5% of benchmark' : 'Over benchmark');
    const statusClass = delta <= 0 ? 'delta-green' : (Math.abs(deltaPct) <= 5 ? 'delta-amber' : 'delta-red');

    const barDiv = document.createElement('div');
    barDiv.className = 'comparison-bar';
    barDiv.innerHTML = `
      <div class="comparison-bar-header">
        <span class="comparison-bar-label">${item.label} Cover</span>
        <span class="bar-status ${statusClass}">${statusText}</span>
      </div>
      <div class="comparison-bar-values">
        <span class="bar-value-phishield">Phishield (ex-FP): <strong>${formatR(phishieldPremium)}</strong></span>
        <span class="bar-value-target">${targetLabel}: <strong>${formatR(targetPremium)}</strong></span>
      </div>
      <div class="comparison-bar-track">
        <div class="bar-target-line" style="left: ${targetPct}%;" title="${targetLabel}: ${formatR(targetPremium)}"></div>
        <div class="bar-fill" style="width: ${phishieldPct}%; background: ${barColor};" title="Phishield ${state.competitorHasFP ? '(with FP)' : '(ex-FP)'}: ${formatR(phishieldPremium)}"></div>
      </div>
      <div class="bar-delta ${statusClass}">
        Difference: ${delta <= 0 ? '' : '+'}${formatR(Math.abs(delta))} (${delta <= 0 ? '' : '+'}${deltaPct}%) &nbsp;|&nbsp; FP benefit included: ${formatR(item.fpCost)}
      </div>
    `;
    container.appendChild(barDiv);
  });
}

/* ===== Step 4: UW Conditions Panel ===== */
function renderUWConditionsPanel() {
  const panel = $('uw-conditions-panel');
  const content = $('uw-conditions-content');
  if (!panel || !content) return;

  let html = '';
  let hasConditions = false;

  // 1. UW Outcome & Loading
  if (state.uwOutcome && state.uwOutcome !== 'standard') {
    hasConditions = true;
    const outcomeLabel = state.uwOutcome === 'caution' ? 'Proceed with Caution'
      : state.uwOutcome === 'loading' ? `${Math.round(state.uwLoadingPct * 100)}% Loading Applied`
      : state.uwOutcome === 'refer' ? 'Referral Required'
      : state.uwOutcome;
    html += `<div class="uw-cond-section">
      <div class="uw-cond-label">Underwriting Outcome</div>
      <div class="uw-cond-value">${outcomeLabel} (${state.uwNoCount || 0} concern${state.uwNoCount !== 1 ? 's' : ''} noted)</div>
    </div>`;
  }

  // 2. FP Conditions of Cover (Q7/Q8 No answers)
  // Check FP limit from selected covers / quote options
  let effectiveFPOver250k = state.fpOver250k;
  if (state.quoteOptions.length > 0) {
    // Check all options for any FP > 250k
    state.quoteOptions.forEach(opt => {
      const coverKey = COVER_LIMITS[opt.coverIndex].key;
      const baseFP = BASE_FP_BY_COVER[coverKey];
      if (baseFP > 250_000) effectiveFPOver250k = true;
      if (opt.fpIndex !== undefined) {
        const availFP = getAvailableFPOptions(coverKey);
        if (opt.fpIndex >= 0 && opt.fpIndex < availFP.length && availFP[opt.fpIndex].limit > 250_000) {
          effectiveFPOver250k = true;
        }
      }
    });
  } else if (state.selectedCovers.length > 0) {
    const ci = state.selectedCovers[0];
    const coverKey = COVER_LIMITS[ci].key;
    const baseFP = BASE_FP_BY_COVER[coverKey];
    if (baseFP > 250_000) effectiveFPOver250k = true;
    // Also check selected FP tier
    if (state.fpSelections && state.fpSelections[ci] !== undefined) {
      const fpIdx = state.fpSelections[ci];
      const availFP = getAvailableFPOptions(coverKey);
      if (fpIdx >= 0 && fpIdx < availFP.length && availFP[fpIdx].limit > 250_000) {
        effectiveFPOver250k = true;
      }
    }
  }

  // Auto-sync FP checkbox and Q7/Q8 visibility if needed
  if (effectiveFPOver250k && !state.fpOver250k) {
    state.fpOver250k = true;
    const checkbox = $('fp-over-250k');
    if (checkbox) checkbox.checked = true;
    toggleFPQuestions(true);
    evaluateUW(); // Re-evaluate with Q7/Q8 now active
  }

  if (effectiveFPOver250k && state.uwFPConditions && state.uwFPConditions.length > 0) {
    hasConditions = true;
    html += `<div class="uw-cond-section">
      <div class="uw-cond-label">Conditions of Cover (FP &gt; R250,000)</div>
      <div class="uw-cond-value">The following requirements are conditions of cover:</div>
      <ul>${state.uwFPConditions.map(c => '<li>' + c + '</li>').join('')}</ul>
    </div>`;
  } else if (effectiveFPOver250k) {
    // FP > R250k but Q7/Q8 not yet answered
    const q7Answered = state.uwAnswers['q7-1'] !== undefined;
    const q8Answered = state.uwAnswers['q8'] !== undefined;
    if (!q7Answered || !q8Answered) {
      hasConditions = true;
      html += `<div class="uw-cond-section">
        <div class="uw-cond-label">FP Cover &gt; R250,000</div>
        <div class="uw-cond-value" style="color: var(--warning);">Q7 and Q8 require answers — FP cover exceeds R250,000 threshold. Please complete underwriting questions on Step 1.</div>
      </div>`;
    }
  }

  // 3. Prior claim
  if (state.priorClaim) {
    hasConditions = true;
    html += `<div class="uw-cond-section">
      <div class="uw-cond-label">Prior Claim</div>
      <div class="uw-cond-value">Additional underwriting required based on prior claims history.</div>
    </div>`;
  }

  if (hasConditions) {
    content.innerHTML = html;
    panel.style.display = 'block';
  } else {
    panel.style.display = 'none';
  }
}

/* ===== Step 4: Discount Logic ===== */
function updateDiscounts() {
  const posture = parseFloat($('posture-discount').value) || 0;
  const discretionary = parseFloat($('discretionary-discount').value) || 0;

  state.postureDiscount = Math.min(posture, 100) / 100;
  state.discretionaryDiscount = Math.min(discretionary, 100) / 100;

  // Apply to quoteOptions
  if (state.quoteOptions.length > 0) {
    if (state.applyDiscountsToAll) {
      // Apply same discounts to all options
      state.quoteOptions.forEach(opt => {
        opt.postureDiscount = state.postureDiscount;
        opt.discretionaryDiscount = state.discretionaryDiscount;
      });
    } else {
      // Apply to active tab's option only
      const activeOpt = getOption(state.activeOptionTab);
      if (activeOpt) {
        activeOpt.postureDiscount = state.postureDiscount;
        activeOpt.discretionaryDiscount = state.discretionaryDiscount;
      }
    }
  }

  // Combined discount check
  const combined = 1 - (1 - state.postureDiscount) * (1 - state.discretionaryDiscount);
  const warning = $('discount-warning');
  if (combined > 0.35) {
    warning.style.display = 'flex';
  } else {
    warning.style.display = 'none';
  }

  // Update computed values
  if (state.quoteOptions.length > 0) {
    const opt = state.quoteOptions[0];
    const calc = calculatePremium(opt.coverIndex, state, {
      fpIndex: opt.fpIndex,
      postureDiscount: opt.postureDiscount || 0,
      discretionaryDiscount: opt.discretionaryDiscount || 0,
    });
    if (calc) {
      const pd = opt.postureDiscount || 0;
      const dd = opt.discretionaryDiscount || 0;
      const baseBeforeDisc = calc.annual / ((1 - pd) * (1 - dd)) || calc.annual;
      const postureAmt = baseBeforeDisc * pd;
      const discAmt = (baseBeforeDisc - postureAmt) * dd;
      $('posture-discount-value').textContent = formatR(postureAmt);
      $('discretionary-discount-value').textContent = formatR(discAmt);
    }
  } else {
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
  }

  // Manual override
  const overrideVal = parseCurrency($('manual-override').value);
  state.manualOverride = overrideVal > 0 ? overrideVal : null;
  if (state.quoteOptions.length > 0 && state.applyDiscountsToAll) {
    state.quoteOptions.forEach(opt => { opt.manualOverride = state.manualOverride; });
  } else if (state.quoteOptions.length > 0) {
    const activeOpt = getOption(state.activeOptionTab);
    if (activeOpt) activeOpt.manualOverride = state.manualOverride;
  }

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
  state.baseRef = `CPB-${dateStr}-${seq}`;

  if (state.quoteOptions.length <= 1) {
    // Single option — use base ref as quote ref
    if (state.quoteOptions.length === 1) {
      const opt = state.quoteOptions[0];
      const coverLabel = COVER_LIMITS[opt.coverIndex].label.replace(/[\s,.]/g, '');
      const coverKey = COVER_LIMITS[opt.coverIndex].key;
      const availFP = getAvailableFPOptions(coverKey);
      const fpLabel = (opt.fpIndex >= 0 && opt.fpIndex < availFP.length) ? availFP[opt.fpIndex].label.replace(/[\s,.]/g, '') : 'BaseFP';
      state.quoteRef = `${state.baseRef}-${coverLabel}-FP${fpLabel}`;
    } else {
      state.quoteRef = state.baseRef;
    }
  } else {
    // Multi-option: base ref shown, per-option refs generated in PDF
    state.quoteRef = state.baseRef;
  }

  $('quote-ref-date').textContent = dateStr;
  $('quote-ref-seq').textContent = seq;
}

/* ===== Generate per-option quote ref ===== */
function getOptionQuoteRef(opt) {
  const coverLabel = COVER_LIMITS[opt.coverIndex].label.replace(/[\s,.]/g, '');
  const coverKey = COVER_LIMITS[opt.coverIndex].key;
  const availFP = getAvailableFPOptions(coverKey);
  const fpLabel = (opt.fpIndex >= 0 && opt.fpIndex < availFP.length) ? availFP[opt.fpIndex].label.replace(/[\s,.]/g, '') : 'BaseFP';
  return `${state.baseRef}-${coverLabel}-FP${fpLabel}`;
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

  if ($('sum-website')) $('sum-website').textContent = state.websiteAddress || '--';

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

  // Build comprehensive conditions list
  let allConditions = [];
  // FP conditions of cover
  if (state.uwFPConditions && state.uwFPConditions.length > 0) {
    allConditions = allConditions.concat(state.uwFPConditions);
  }
  // Check if FP > R250k but Q7/Q8 unanswered (auto-detected from cover selection)
  if (state.selectedCovers.length > 0) {
    const ci = state.selectedCovers[0];
    const coverKey = COVER_LIMITS[ci].key;
    const baseFP = BASE_FP_BY_COVER[coverKey];
    let fpExceeds = baseFP > 250_000;
    if (state.fpSelections && state.fpSelections[ci] !== undefined) {
      const fpIdx = state.fpSelections[ci];
      const availFP = getAvailableFPOptions(coverKey);
      if (fpIdx >= 0 && fpIdx < availFP.length && availFP[fpIdx].limit > 250_000) fpExceeds = true;
    }
    if (fpExceeds && (!state.uwFPConditions || state.uwFPConditions.length === 0)) {
      // FP exceeds but no conditions captured — Q7/Q8 all Yes or unanswered
      if (state.uwAnswers['q7-1'] === undefined && state.uwAnswers['q8'] === undefined) {
        allConditions.push('FP > R250k: Q7 and Q8 pending completion');
      }
    }
  }
  // Prior claim
  if (state.priorClaim) {
    allConditions.push('Prior claim: additional underwriting required');
  }

  const condEl = $('sum-uw-conditions');
  if (allConditions.length > 0) {
    condEl.innerHTML = '<ol class="sum-conditions-list">' +
      allConditions.map(c => '<li>' + c + '</li>').join('') +
      '</ol>';
  } else {
    condEl.textContent = 'None';
  }

  // Prior claim
  $('sum-prior-claim').style.display = state.priorClaim ? 'flex' : 'none';

  // Endorsements
  state.endorsements = ($('endorsements') ? $('endorsements').value : '').trim();
  const endSection = $('sum-endorsements-section');
  const endContent = $('sum-endorsements');
  if (endSection && endContent) {
    if (state.endorsements) {
      endContent.textContent = state.endorsements;
      endSection.style.display = 'block';
    } else {
      endSection.style.display = 'none';
    }
  }

  // Per cover limit breakdowns
  renderQuoteBreakdowns();

  // Show/hide multi vs single PDF buttons
  const singlePdfBtn = $('btn-download-pdf');
  const multiPdfBtn = $('btn-download-all-pdfs');
  if (isMultiMode()) {
    singlePdfBtn.style.display = 'none';
    multiPdfBtn.style.display = 'inline-flex';
  } else {
    singlePdfBtn.style.display = 'inline-flex';
    multiPdfBtn.style.display = 'none';
  }
}

function renderQuoteBreakdowns() {
  const container = $('quote-breakdowns');
  container.innerHTML = '';

  if (state.quoteOptions.length > 0) {
    // Multi-option: one breakdown card per option
    state.quoteOptions.forEach(opt => {
      const ci = opt.coverIndex;
      const calc = calculatePremium(ci, state, {
        fpIndex: opt.fpIndex,
        postureDiscount: opt.postureDiscount || 0,
        discretionaryDiscount: opt.discretionaryDiscount || 0,
      });
      if (!calc) return;

      const itoo = getItooBenchmark(state.actualTurnover, ci);
      const compRow = state.competitorRows.find(r => r && r.requestedCoverIndex === ci);
      const optRef = getOptionQuoteRef(opt);

      renderBreakdownCard(container, ci, calc, itoo, compRow, opt.label, optRef);
    });
  } else {
    // Legacy single-cover mode
    const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
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
      renderBreakdownCard(container, ci, calc, itoo, compRow, COVER_LIMITS[ci].label, null);
    });
  }
}

function renderBreakdownCard(container, ci, calc, itoo, compRow, label, optRef) {
  const card = document.createElement('div');
  card.className = 'quote-breakdown-card';

  let trailRows = '';
  calc.breakdown.forEach(b => {
    trailRows += `<tr><td>${b.step}</td><td>${b.desc}</td><td>${formatR(b.value)}</td></tr>`;
  });

  const itooStr = itoo ? formatR(itoo.premium) : '--';
  const compStr = (compRow && compRow.competitorPremium > 0) ? formatR(compRow.competitorPremium) : '--';

  let deltaStr = '--';
  if (itoo) {
    const d = calc.annualExFP - itoo.premium;
    deltaStr = `${d <= 0 ? '' : '+'}${formatR(Math.abs(d))} (${d <= 0 ? '' : '+'}${Math.round(d / itoo.premium * 100)}%)`;
  }

  const refHtml = optRef ? `<div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:8px;">Ref: ${optRef}</div>` : '';

  card.innerHTML = `
    ${refHtml}
    <div class="breakdown-header">
      <h4>${label}</h4>
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

  if (state.quoteOptions.length > 0) {
    state.quoteOptions.forEach(opt => {
      const calc = state.calculations[opt.id] || calculatePremium(opt.coverIndex, state, { fpIndex: opt.fpIndex, postureDiscount: opt.postureDiscount || 0, discretionaryDiscount: opt.discretionaryDiscount || 0 });
      if (!calc) return;
      const optRef = getOptionQuoteRef(opt);
      lines.push(`${opt.label} [${optRef}]: ${formatR(calc.annual)}/yr (${formatR(calc.monthly)}/mo) | Ex-FP: ${formatR(calc.annualExFP)}`);
    });
  } else {
    const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
    covers.forEach(ci => {
      const calc = state.calculations[ci] || calculatePremium(ci, state);
      if (!calc) return;
      lines.push(`${COVER_LIMITS[ci].label}: ${formatR(calc.annual)}/yr (${formatR(calc.monthly)}/mo) | Ex-FP: ${formatR(calc.annualExFP)}`);
    });
  }

  if (state.endorsements) {
    lines.push('');
    lines.push('ENDORSEMENTS / NOTES');
    lines.push('-'.repeat(30));
    lines.push(state.endorsements);
  }

  lines.push('');
  lines.push('Internal use only. Subject to final underwriting approval.');
  return lines.join('\n');
}


/* ===== Generate All PDFs (Multi-Option) ===== */
function generateAllPDFs() {
  if (state.quoteOptions.length === 0) {
    generatePDF();
    return;
  }

  state.quoteOptions.forEach(opt => {
    generatePDF(opt);
  });
}

/* ===== PDF Generation ===== */
function generatePDF(optionOverride) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF('p', 'mm', 'a4');
  const pageW = 210;
  const margin = 18;
  const contentW = pageW - margin * 2;
  let y = 15;
  const lineH = 5; // standard line height

  function checkPage(needed) {
    if (y + (needed || 10) > 280) { doc.addPage(); y = 15; }
  }

  function addText(text, size, style, color, x) {
    checkPage(size * 0.5);
    doc.setFontSize(size || 9);
    doc.setFont('helvetica', style || 'normal');
    doc.setTextColor(...(color || [51, 51, 51]));
    const lines = doc.splitTextToSize(String(text), contentW - (x ? x - margin : 0));
    doc.text(lines, x || margin, y);
    y += lines.length * lineH + 1;
  }

  function addSpacer(h) { y += h || 3; }

  function addRule() {
    doc.setDrawColor(200, 210, 220);
    doc.line(margin, y, pageW - margin, y);
    y += 4;
  }

  function addSection(title) {
    addSpacer(2);
    doc.setFillColor(0, 40, 80);
    doc.rect(margin, y - 1, contentW, 7, 'F');
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(255, 255, 255);
    doc.text(title, margin + 3, y + 4);
    y += 10;
  }

  function addField(label, value, labelW) {
    checkPage(8);
    const lw = labelW || 42;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(120, 120, 120);
    doc.text(label, margin + 2, y);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 30, 30);
    doc.text(String(value), margin + lw, y);
    y += lineH + 1;
  }

  // ── Header Bar ──
  doc.setFillColor(0, 25, 50);
  doc.rect(0, 0, pageW, 20, 'F');
  doc.setFillColor(0, 180, 216);
  doc.rect(0, 20, pageW, 0.8, 'F');
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 180, 216);
  doc.text('Phishield', margin, 12);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(160, 175, 190);
  doc.text('SME Rating Engine \u2014 Quote Output', margin + 40, 12);
  doc.text(new Date().toLocaleDateString('en-ZA', { year: 'numeric', month: 'long', day: 'numeric' }), pageW - margin, 12, { align: 'right' });
  y = 26;

  // ── Quote Reference ──
  const pdfQuoteRef = optionOverride ? getOptionQuoteRef(optionOverride) : state.quoteRef;
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(0, 0, 0);
  doc.text('Quote Ref: ' + pdfQuoteRef, margin, y);
  y += 8;
  addRule();

  // ── Client Details ──
  addSection('CLIENT DETAILS');
  addField('Company:', state.companyName);
  if (state.industryIndex >= 0) {
    addField('Industry:', INDUSTRIES[state.industryIndex].main + ' \u2014 ' + INDUSTRIES[state.industryIndex].sub);
  }
  addField('Actual Turnover:', formatR(state.actualTurnover));
  addField('Revenue Bracket:', state.revenueBandIndex >= 0 ? REVENUE_BANDS[state.revenueBandIndex].label : '--');
  if (state.websiteAddress) addField('Website:', state.websiteAddress);
  const qtLabels = { new: 'New Business', renewal: 'Renewal', competing: 'Competing Quote' };
  addField('Quote Type:', qtLabels[state.quoteType] || '--');
  if (state.quoteType === 'renewal') {
    addField('Market Condition:', MARKET_CONDITION_LABEL);
  }
  if (state.competitorName) {
    addField('Competitor:', state.competitorName);
  }
  addSpacer(2);

  // ── Underwriting ──
  addSection('UNDERWRITING');
  const outcomeLabels = { standard: 'Standard Rates', caution: 'Proceed with Caution', loading: Math.round(state.uwLoadingPct * 100) + '% Loading', decline: 'Declined', refer: 'Refer to Senior UW' };
  addField('Outcome:', outcomeLabels[state.uwOutcome] || '--');
  addField('Loading:', state.uwLoadingPct > 0 ? Math.round(state.uwLoadingPct * 100) + '%' : 'None');
  if (state.uwFPConditions && state.uwFPConditions.length > 0) {
    addField('Conditions of Cover:', '');
    state.uwFPConditions.forEach((c, idx) => {
      checkPage(20);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(180, 130, 0);
      const bulletText = (idx + 1) + '. ' + c;
      const wrappedLines = doc.splitTextToSize(bulletText, contentW - 10);
      doc.text(wrappedLines, margin + 4, y);
      y += wrappedLines.length * (lineH - 0.5) + 3;
    });
  } else {
    addField('Conditions of Cover:', 'None');
  }
  if (state.priorClaim) {
    addSpacer(2);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(200, 50, 50);
    doc.text('\u26A0 Prior claim flagged \u2014 additional underwriting required', margin + 2, y);
    y += lineH + 2;
  }
  addSpacer(2);

  // ── Endorsements ──
  if (state.endorsements) {
    addSection('ENDORSEMENTS / NOTES');
    const endorseLines = doc.splitTextToSize(state.endorsements, contentW - 6);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(80, 80, 80);
    endorseLines.forEach(line => {
      checkPage(6);
      doc.text(line, margin + 3, y);
      y += lineH;
    });
    addSpacer(3);
  }

  // ── Per Cover Limit Breakdowns ──
  let pdfCovers = [];
  if (optionOverride) {
    // Single option PDF: only this option's cover
    pdfCovers = [{ coverIndex: optionOverride.coverIndex, opt: optionOverride }];
  } else if (state.quoteOptions.length > 0) {
    pdfCovers = state.quoteOptions.map(o => ({ coverIndex: o.coverIndex, opt: o }));
  } else {
    const covers = state.selectedCovers.length > 0 ? state.selectedCovers : state.recommendedCovers;
    const allCovers = [...covers];
    state.competitorRows.forEach(row => {
      if (row && row.requestedCoverIndex >= 0 && !allCovers.includes(row.requestedCoverIndex)) {
        allCovers.push(row.requestedCoverIndex);
      }
    });
    pdfCovers = allCovers.map(ci => ({ coverIndex: ci, opt: null }));
  }

  pdfCovers.forEach(({ coverIndex: ci, opt }) => {
    const calc = opt ? calculatePremium(ci, state, {
      fpIndex: opt.fpIndex,
      postureDiscount: opt.postureDiscount || 0,
      discretionaryDiscount: opt.discretionaryDiscount || 0,
    }) : calculatePremium(ci, state);
    if (!calc) return;

    checkPage(60);
    const sectionLabel = opt ? opt.label : COVER_LIMITS[ci].label;
    addSection('COVER LIMIT: ' + sectionLabel + (calc.isMicro ? '  (Micro SME)' : ''));

    // Audit trail as table
    const colX = [margin + 2, margin + 14, margin + contentW - 25];
    // Table header
    const rowH = 8;
    doc.setFillColor(235, 240, 248);
    doc.rect(margin, y, contentW, rowH, 'F');
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(80, 80, 80);
    const headerTextY = y + rowH * 0.6;
    doc.text('STEP', colX[0], headerTextY);
    doc.text('DESCRIPTION', colX[1], headerTextY);
    doc.text('VALUE', colX[2] + 20, headerTextY, { align: 'right' });
    y += rowH + 1;

    // Table rows
    calc.breakdown.forEach((b, idx) => {
      checkPage(rowH + 2);
      if (idx % 2 === 0) {
        doc.setFillColor(248, 250, 252);
        doc.rect(margin, y, contentW, rowH, 'F');
      }
      const textY = y + rowH * 0.55;
      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(0, 100, 160);
      doc.text(String(b.step), colX[0], textY);
      doc.setTextColor(50, 50, 50);
      doc.text(b.desc, colX[1], textY);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(30, 30, 30);
      doc.text(formatR(b.value), colX[2] + 20, textY, { align: 'right' });
      y += rowH;
    });
    addSpacer(4);

    // Final premiums box
    checkPage(22);
    doc.setFillColor(235, 245, 255);
    doc.rect(margin, y, contentW, 16, 'F');
    doc.setDrawColor(0, 150, 200);
    doc.rect(margin, y, contentW, 16, 'S');

    const thirdW = contentW / 3;
    const boxY = y + 5;

    // Annual (with FP)
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    doc.text('ANNUAL (WITH FP)', margin + thirdW * 0.5, boxY, { align: 'center' });
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 100, 170);
    doc.text(formatR(calc.annual), margin + thirdW * 0.5, boxY + 7, { align: 'center' });

    // Annual (excl FP)
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    doc.text('ANNUAL (EXCL FP)', margin + thirdW * 1.5, boxY, { align: 'center' });
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(50, 50, 50);
    doc.text(formatR(calc.annualExFP), margin + thirdW * 1.5, boxY + 7, { align: 'center' });

    // Monthly
    doc.setFontSize(7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 100, 100);
    doc.text('MONTHLY', margin + thirdW * 2.5, boxY, { align: 'center' });
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 100, 170);
    doc.text(formatR(calc.monthly), margin + thirdW * 2.5, boxY + 7, { align: 'center' });

    y += 20;

    // Comparison row
    const itoo = getItooBenchmark(state.actualTurnover, ci);
    const compRow = state.competitorRows.find(r => r && r.requestedCoverIndex === ci);
    if (itoo || (compRow && compRow.competitorPremium > 0)) {
      checkPage(10);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 100, 100);
      let compText = '';
      if (itoo) compText += 'Industry Benchmark: ' + formatR(itoo.premium);
      if (compRow && compRow.competitorPremium > 0) compText += '    |    Competitor: ' + formatR(compRow.competitorPremium);
      if (itoo) {
        const d = calc.annualExFP - itoo.premium;
        const pct = Math.round(d / itoo.premium * 100);
        compText += '    |    Delta: ' + (d <= 0 ? '' : '+') + formatR(Math.abs(d)) + ' (' + (d <= 0 ? '' : '+') + pct + '%)';
      }
      doc.text(compText, margin + 2, y);
      y += 6;
    }

    addSpacer(4);
    addRule();
  });

  // ── Footer ──
  addSpacer(6);
  doc.setFontSize(7);
  doc.setFont('helvetica', 'italic');
  doc.setTextColor(150, 150, 150);
  doc.text('Internal use only. Premiums are indicative and subject to final underwriting approval.', margin, y);
  y += 4;
  doc.text('Phishield SME Rating Engine \u00A9 2026. Not for distribution.', margin, y);

  // Save locally
  const companySlug = state.companyName.replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_');
  let coverLabels;
  if (optionOverride) {
    const cl = COVER_LIMITS[optionOverride.coverIndex].label.replace(/[\s,.]/g, '');
    const ck = COVER_LIMITS[optionOverride.coverIndex].key;
    const afp = getAvailableFPOptions(ck);
    const fpL = (optionOverride.fpIndex >= 0 && optionOverride.fpIndex < afp.length) ? afp[optionOverride.fpIndex].label.replace(/[\s,.]/g, '') : 'BaseFP';
    coverLabels = cl + '_FP' + fpL;
  } else {
    coverLabels = pdfCovers.map(({ coverIndex: ci2 }) => COVER_LIMITS[ci2].label.replace(/\./g, '')).join('_');
  }
  const filename = companySlug + '_' + coverLabels + '.pdf';
  doc.save(filename);

  // Also save to backend (if available)
  try {
    const pdfBase64 = doc.output('datauristring').split(',')[1];
    saveQuoteToBackend(coverLabels, pdfBase64, optionOverride ? pdfQuoteRef : null);
  } catch (e) {
    console.log('Backend save skipped:', e.message);
  }
}

/* ===== BACKEND SAVE ===== */

async function saveQuoteToBackend(coverLabel, pdfBase64, optionQuoteRef) {
  const industry = state.industryIndex >= 0 ? INDUSTRIES[state.industryIndex] : {};

  const payload = {
    quoteRef: optionQuoteRef || state.quoteRef,
    baseRef: state.baseRef,
    companyName: state.companyName,
    industryMain: industry.main || '',
    industrySub: industry.sub || '',
    turnoverPrev: state.turnoverPrev,
    turnoverCurrent: state.turnoverCurrent,
    actualTurnover: state.actualTurnover,
    revenueBand: state.revenueBandIndex >= 0 ? REVENUE_BANDS[state.revenueBandIndex].label : '',
    employeeCount: state.employeeCount,
    websiteAddress: state.websiteAddress,
    quoteType: state.quoteType,
    marketCondition: MARKET_CONDITION,
    priorClaim: state.priorClaim,
    uwAnswers: state.uwAnswers,
    uwOutcome: state.uwOutcome,
    uwLoadingPct: state.uwLoadingPct,
    uwConditions: state.fpConditions || [],
    endorsements: state.endorsements || '',
    coverSelections: Object.keys(state.calculations).map(ci => ({
      coverIndex: parseInt(ci),
      coverLabel: COVER_LIMITS[parseInt(ci)].label,
      ...state.calculations[ci],
    })),
    postureDiscount: state.postureDiscount,
    discretionaryDiscount: state.discretionaryDiscount,
    competitorName: state.competitorName || '',
    competitorData: state.competitorRows || [],
    renewalCoverLimit: state.renewalCoverIndex >= 0 ? COVER_LIMITS[state.renewalCoverIndex].label : '',
    renewalPremium: state.renewalPremium || 0,
    coverLabel: coverLabel,
    pdfBase64: pdfBase64 || null,
  };

  try {
    const res = await fetch('/api/quotes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      const result = await res.json();
      console.log('Quote saved to backend:', result.quoteRef, result.id);

      // Show save confirmation
      const btn = $('btn-download-pdf');
      if (btn) {
        const orig = btn.innerHTML;
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn-icon"><path d="M20 6L9 17l-5-5"/></svg> SAVED';
        setTimeout(() => { btn.innerHTML = orig; }, 2000);
      }
    } else {
      console.warn('Backend save failed:', res.status);
    }
  } catch (e) {
    // Backend not available (local file:// or offline) — silently skip
    console.log('Backend not available, quote saved locally only.');
  }
}

/* ===== Step 4: Render Option Tabs ===== */
function renderStep4Tabs() {
  const tabsContainer = $('step4-option-tabs');
  if (state.quoteOptions.length < 2) {
    tabsContainer.classList.add('hidden');
    return;
  }

  tabsContainer.classList.remove('hidden');
  tabsContainer.innerHTML = '';

  state.quoteOptions.forEach((opt, idx) => {
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.className = 'option-tab' + (idx === 0 ? ' active' : '');
    tab.dataset.optionId = opt.id;

    const instanceNum = coverInstanceCount(opt.coverIndex) > 1
      ? ' (' + (state.quoteOptions.filter((o, i) => o.coverIndex === opt.coverIndex && i <= idx).length) + ')'
      : '';
    tab.textContent = COVER_LIMITS[opt.coverIndex].label + instanceNum;

    tab.addEventListener('click', () => {
      tabsContainer.querySelectorAll('.option-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeOptionTab = opt.id;

      // Load this option's discounts into the fields
      $('posture-discount').value = opt.postureDiscount ? Math.round(opt.postureDiscount * 100) : '';
      $('discretionary-discount').value = opt.discretionaryDiscount ? Math.round(opt.discretionaryDiscount * 100) : '';
      $('manual-override').value = opt.manualOverride ? opt.manualOverride : '';

      updateDiscounts();
      updateComparisonBars();
    });

    tabsContainer.appendChild(tab);
  });

  state.activeOptionTab = state.quoteOptions[0].id;
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

  // Industry select — handled by selectIndustry() in searchable dropdown

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

  // Website address
  $('website-address').addEventListener('input', () => {
    state.websiteAddress = $('website-address').value.trim();
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

  // Competing inputs (competitor name now in Step 3)
  if ($('competitor-name-step3')) {
    $('competitor-name-step3').addEventListener('input', () => {
      state.competitorName = $('competitor-name-step3').value.trim();
    });
  }

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

  // Custom cover selector cards — multi-toggle
  $$('#cover-selector .sel-card').forEach(card => {
    card.addEventListener('click', () => {
      if (card.classList.contains('unavailable')) return;

      const ci = parseInt(card.dataset.coverIndex, 10);

      if (isCoverInOptions(ci)) {
        // Remove this cover from options
        state.quoteOptions = state.quoteOptions.filter(o => o.coverIndex !== ci);
        syncFromQuoteOptions();
        card.classList.remove('active');
      } else {
        if (state.quoteOptions.length >= 4) return;
        addQuoteOption(ci, 0);
        card.classList.add('active');
      }

      // Check micro
      state.isMicroSME = checkMicroSME(state.industryIndex, state.revenueBandIndex, ci);
      $('micro-badge').style.display = state.isMicroSME ? 'flex' : 'none';

      // Sync recommendation card highlighting
      $$('.cover-rec-card').forEach(c => {
        const rci = parseInt(c.dataset.coverIndex, 10);
        if (isCoverInOptions(rci)) {
          c.classList.add('selected', 'active');
        } else {
          c.classList.remove('selected', 'active');
        }
      });

      renderFPSelectorMulti();
      updatePricing();
    });
  });

  $('nextBtn2').addEventListener('click', () => {
    if (state.quoteOptions.length === 0 && state.selectedCovers.length === 0 && state.recommendedCovers.length === 0) {
      // Need at least one cover selected
      return;
    }

    // For multi-mode, auto-set the number of competitor rows to match options
    if (isMultiMode()) {
      $('num-cover-limits').value = state.quoteOptions.length;
      state.numRequestedCovers = state.quoteOptions.length;
      // Hide the manual count selector in multi-mode (auto-synced)
      $('num-cover-limits').closest('.form-group').style.display = 'none';

      // Show quote options summary bar (not tabs — all options compared together)
      const s3Tabs = $('step3-option-tabs');
      s3Tabs.classList.remove('hidden');
      s3Tabs.innerHTML = '<span class="options-summary-label">Quoting:</span> ' +
        state.quoteOptions.map(opt => '<span class="options-summary-item">' + opt.label + '</span>').join('');
      s3Tabs.className = 'options-summary-bar';
    } else {
      $('step3-option-tabs').classList.add('hidden');
    }

    updateCompetitorRows();
    updateComparisonTable();
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

  // Competitor FP toggle
  $('competitor-fp-toggle').querySelectorAll('.toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('competitor-fp-toggle').querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.competitorHasFP = btn.dataset.value === 'yes';
      updateComparisonTable();
    });
  });

  // Setup initial competitor row events
  const firstRow = $('competitor-rows').querySelector('.competitor-row');
  if (firstRow) setupCompetitorRowEvents(firstRow, 0);

  $('nextBtn3').addEventListener('click', () => {
    // Show/hide apply-all toggle and option tabs based on multi-mode
    if (isMultiMode()) {
      $('apply-all-toggle').style.display = 'flex';
      renderStep4Tabs();
    } else {
      $('apply-all-toggle').style.display = 'none';
      $('step4-option-tabs').classList.add('hidden');
    }
    renderUWConditionsPanel();
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

  // Apply-all checkbox
  $('apply-all-check').addEventListener('change', () => {
    state.applyDiscountsToAll = $('apply-all-check').checked;
    if (state.applyDiscountsToAll) {
      // Sync current values to all options
      updateDiscounts();
    }
  });

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

  $('btn-download-pdf').addEventListener('click', () => {
    if (state.quoteOptions.length === 1) {
      generatePDF(state.quoteOptions[0]);
    } else {
      generatePDF();
    }
  });

  $('btn-download-all-pdfs').addEventListener('click', () => {
    generateAllPDFs();
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
