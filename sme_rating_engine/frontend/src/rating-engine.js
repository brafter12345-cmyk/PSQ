/**
 * rating-engine.js — the SME premium + underwriting math, extracted VERBATIM
 * from the legacy vanilla app `SME Rating Engine/sme-rating.js`.
 *
 * Every function here is a byte-for-byte copy of the legacy function body, with
 * exactly ONE deliberate adaptation, documented inline:
 *   - calculatePremium: `const s = overrideState || state` -> `const s = overrideState`.
 *     The legacy function fell back to a module-global `state`; this module has
 *     none — the React app (and the parity harness) ALWAYS pass an explicit
 *     state object, so the removed fallback is never exercised and outputs are
 *     identical.
 *
 * `evaluateUnderwriting` is the ONE re-expressed function: it replicates the
 * PURE pricing/outcome logic of the legacy `evaluateUW` (+ the FP condition-of-
 * cover sentences from `renderUWOutcome`), with the DOM side-effects removed.
 *
 * ALL of this is locked by `tools/parity.mjs`, which drives the *legacy*
 * functions in a sandbox and deep-equals their output against these across a
 * large input grid. Do not "tidy" the math here — if parity fails, the port is
 * wrong, not the legacy code.
 */
import {
  REVENUE_BANDS,
  COVER_LIMITS,
  COVER_AVAILABILITY,
  SME_PREMIUMS,
  PREMIUM_FORMULAS,
  MICRO_PREMIUMS,
  INDUSTRIES,
  INDUSTRY_MODIFIERS,
  ITOO_BENCHMARKS,
  UNDERWRITING_LOADINGS,
  MARKET_CONDITION,
  getAvailableFPOptions,
  getBaseFPCost,
} from './rating-data.js';

/* ===== Formatting ===== */
export function formatR(n) {
  return 'R ' + Math.round(n).toLocaleString('en-ZA');
}

/* ===== Turnover Calculation ===== */
export function calcActualTurnover(prev, current) {
  if (prev > 0 && current > 0) return (prev + current) / 2;
  if (prev > 0) return prev;
  if (current > 0) return current;
  return 0;
}

export function findRevenueBand(turnover) {
  for (let i = REVENUE_BANDS.length - 1; i >= 0; i--) {
    if (turnover >= REVENUE_BANDS[i].min) return i;
  }
  return 0;
}

/* ===== Micro SME Detection ===== */
export function checkMicroSME(industryIndex, bandIndex, coverIndex) {
  if (industryIndex < 0 || bandIndex < 0 || coverIndex < 0) return false;

  const industry = INDUSTRIES[industryIndex];
  const isSmallCover = coverIndex <= 2; // R1M, R2.5M, R5M
  const isSoftTech = industry.sub === 'Software and Technology';
  const isFinance = industry.main === 'Finance, Insurance, And Real Estate';

  // All industries (including S&T and Finance): turnover < R50M AND cover <= R5M
  return bandIndex <= 2 && isSmallCover;
}

/* ===== Industry Modifier Lookup ===== */
export function getIndustryModifier(industryIndex, bandIndex) {
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
export function getEffectiveBandIndex(bandIndex, coverIndex) {
  return bandIndex;
}

/* ===== Premium Calculation Pipeline ===== */
export function calculatePremium(coverIndex, overrideState, optionOverrides) {
  const s = overrideState; // legacy: `overrideState || state` — caller always passes state explicitly
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
    let annualExFP = adjustedBase;
    breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

    // Apply discounts (to both total and ex-FP)
    const postureD = (optionOverrides && optionOverrides.postureDiscount !== undefined) ? optionOverrides.postureDiscount : (s.postureDiscount || 0);
    const discretionaryD = (optionOverrides && optionOverrides.discretionaryDiscount !== undefined) ? optionOverrides.discretionaryDiscount : (s.discretionaryDiscount || 0);
    if (postureD !== 0 || discretionaryD !== 0) {
      const discountMultiplier = (1 - postureD) * (1 - discretionaryD);
      totalPremium = totalPremium * discountMultiplier;
      annualExFP = annualExFP * discountMultiplier;
      const postureLabel = postureD >= 0 ? `discount ${Math.round(postureD * 100)}%` : `loading ${Math.abs(Math.round(postureD * 100))}%`;
      const discLabel = discretionaryD >= 0 ? `discount ${Math.round(discretionaryD * 100)}%` : `loading ${Math.abs(Math.round(discretionaryD * 100))}%`;
      breakdown.push({ step: 6, desc: `Adjustments (posture ${postureLabel}, discretionary ${discLabel})`, value: totalPremium });
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
  let annualExFP = adjustedBase;
  breakdown.push({ step: 5, desc: 'Total before discounts', value: totalPremium });

  // 6. Discounts (applied to both total and ex-FP)
  const postureD = (optionOverrides && optionOverrides.postureDiscount !== undefined) ? optionOverrides.postureDiscount : (s.postureDiscount || 0);
  const discretionaryD = (optionOverrides && optionOverrides.discretionaryDiscount !== undefined) ? optionOverrides.discretionaryDiscount : (s.discretionaryDiscount || 0);
  if (postureD !== 0 || discretionaryD !== 0) {
    const discountMultiplier = (1 - postureD) * (1 - discretionaryD);
    totalPremium = totalPremium * discountMultiplier;
    annualExFP = annualExFP * discountMultiplier;
    const postureLabel = postureD >= 0 ? `discount ${Math.round(postureD * 100)}%` : `loading ${Math.abs(Math.round(postureD * 100))}%`;
    const discLabel = discretionaryD >= 0 ? `discount ${Math.round(discretionaryD * 100)}%` : `loading ${Math.abs(Math.round(discretionaryD * 100))}%`;
    breakdown.push({ step: 6, desc: `Adjustments (posture ${postureLabel}, discretionary ${discLabel})`, value: totalPremium });
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
export function getItooBenchmark(actualTurnover, coverIndex) {
  const entry = ITOO_BENCHMARKS.find(b => actualTurnover >= b.min && actualTurnover <= b.max);
  if (!entry || coverIndex < 0 || coverIndex >= entry.premiums.length) return null;
  return { premium: entry.premiums[coverIndex], deductible: entry.deductible };
}

/* ===== Recommended Covers (verbatim) ===== */
export function getRecommendedCovers(bandIndex) {
  if (bandIndex < 0 || bandIndex >= COVER_AVAILABILITY.length) return [];
  const row = COVER_AVAILABILITY[bandIndex];
  const recommended = [];
  row.forEach((status, idx) => {
    if (status === 'recommended') recommended.push(idx);
  });
  return recommended;
}

/* ===== FP index for a rand limit (verbatim) ===== */
export function fpIndexForLimit(coverKey, limitRand) {
  const availFP = getAvailableFPOptions(coverKey);
  if (!availFP || availFP.length === 0) return 0;
  const idx = availFP.findIndex(fp => fp.limit === limitRand);
  if (idx >= 0) return idx;
  // Find the lowest available FP >= limitRand (so we don't drop FP below existing)
  const upIdx = availFP.findIndex(fp => fp.limit >= limitRand);
  return upIdx >= 0 ? upIdx : 0;
}

/* ===== Renewal-ladder helpers (verbatim; `state` supplies revenueBandIndex + calc inputs) ===== */
export function findTargetCoverForRetention(state, startIdx, targetPremium, fpLimitRand) {
  if (state.revenueBandIndex < 0) return -1;
  const row = COVER_AVAILABILITY[state.revenueBandIndex];
  if (!row) return -1;
  for (let i = startIdx; i < COVER_LIMITS.length; i++) {
    if (!row[i]) continue;
    const key = COVER_LIMITS[i].key;
    const fpIdx = fpIndexForLimit(key, fpLimitRand);
    const calc = calculatePremium(i, state, { fpIndex: fpIdx });
    if (calc && calc.annual >= targetPremium) return i;
  }
  return -1;
}

export function findHighestAvailableCover(state) {
  if (state.revenueBandIndex < 0) return -1;
  const row = COVER_AVAILABILITY[state.revenueBandIndex];
  if (!row) return -1;
  for (let i = COVER_LIMITS.length - 1; i >= 0; i--) {
    if (row[i]) return i;
  }
  return -1;
}

export function findNextAvailableCoverAbove(state, startIdx) {
  if (state.revenueBandIndex < 0) return -1;
  const row = COVER_AVAILABILITY[state.revenueBandIndex];
  if (!row) return -1;
  for (let i = startIdx + 1; i < COVER_LIMITS.length; i++) {
    if (row[i]) return i;
  }
  return -1;
}

export function findNextAvailableCoverBelow(state, startIdx) {
  if (state.revenueBandIndex < 0) return -1;
  const row = COVER_AVAILABILITY[state.revenueBandIndex];
  if (!row) return -1;
  for (let i = startIdx - 1; i >= 0; i--) {
    if (row[i]) return i;
  }
  return -1;
}

/* ===== Cover recommendation + renewal-ladder card specs (pure) =====
 * Mirrors the flag/cardSpec computation of the legacy renderRecommendations
 * (DOM removed). `state` needs: revenueBandIndex, industryIndex, actualTurnover,
 * uwLoadingPct, quoteType, renewalCoverIndex, renewalPremium (number),
 * renewalFPLimit (number), fpSelections, postureDiscount, discretionaryDiscount.
 * Returns { cardSpecs:[{coverIndex, role}], recommended:[idx], renewal:{...} }.
 */
export function buildCoverRecommendations(state) {
  const bandIndex = state.revenueBandIndex;
  const renewal = { dropTriggered: false, dropPct: 0, corporateEscalation: false, recommendedCoverIndex: -1, bandChanged: false };
  if (bandIndex < 0) return { cardSpecs: [], recommended: [], renewal };

  const recommended = getRecommendedCovers(bandIndex);
  const cardSpecs = [];
  const isRenewalWithData = (
    state.quoteType === 'renewal'
    && state.renewalCoverIndex >= 0
    && state.renewalPremium > 0
    && state.renewalFPLimit > 0
  );

  if (isRenewalWithData) {
    renewal.bandChanged = !recommended.includes(state.renewalCoverIndex);
    const existingKey = COVER_LIMITS[state.renewalCoverIndex].key;
    const existingFpIdx = fpIndexForLimit(existingKey, state.renewalFPLimit);
    const atSameCoverCalc = calculatePremium(state.renewalCoverIndex, state, { fpIndex: existingFpIdx });
    const triggerThreshold = 0.80;
    const retentionTarget = 0.90;

    if (atSameCoverCalc && atSameCoverCalc.annual < triggerThreshold * state.renewalPremium) {
      renewal.dropTriggered = true;
      renewal.dropPct = 1 - (atSameCoverCalc.annual / state.renewalPremium);
      const targetPremium = retentionTarget * state.renewalPremium;
      let target = findTargetCoverForRetention(state, state.renewalCoverIndex, targetPremium, state.renewalFPLimit);
      if (target < 0) {
        renewal.corporateEscalation = true;
        target = findHighestAvailableCover(state);
      }
      renewal.recommendedCoverIndex = target;
      cardSpecs.push({ coverIndex: state.renewalCoverIndex, role: 'reference' });
      if (target >= 0 && target !== state.renewalCoverIndex) {
        const intermediateCovers = [];
        const row = COVER_AVAILABILITY[bandIndex] || [];
        for (let i = state.renewalCoverIndex + 1; i < target; i++) {
          if (row[i]) intermediateCovers.push(i);
        }
        if (intermediateCovers.length > 0) {
          intermediateCovers.forEach(ci => cardSpecs.push({ coverIndex: ci, role: 'alternative-intermediate' }));
          cardSpecs.push({ coverIndex: target, role: 'recommended-target' });
        } else {
          cardSpecs.push({ coverIndex: target, role: 'recommended-target' });
          const alt = findNextAvailableCoverAbove(state, target);
          if (alt >= 0) cardSpecs.push({ coverIndex: alt, role: 'alternative-higher' });
        }
      } else if (target === state.renewalCoverIndex) {
        cardSpecs[0].role = 'current';
      }
    } else {
      cardSpecs.push({ coverIndex: state.renewalCoverIndex, role: 'current' });
      if (MARKET_CONDITION === 'softening') {
        let added = 0;
        for (let i = state.renewalCoverIndex + 1; i < COVER_LIMITS.length && added < 2; i++) {
          const avail = COVER_AVAILABILITY[bandIndex] ? COVER_AVAILABILITY[bandIndex][i] : null;
          if (avail) { cardSpecs.push({ coverIndex: i, role: 'upgrade' }); added++; }
        }
      } else if (MARKET_CONDITION === 'stable') {
        const lower = findNextAvailableCoverBelow(state, state.renewalCoverIndex);
        if (lower >= 0) cardSpecs.unshift({ coverIndex: lower, role: 'alternative-lower' });
        const higher = findNextAvailableCoverAbove(state, state.renewalCoverIndex);
        if (higher >= 0) cardSpecs.push({ coverIndex: higher, role: 'alternative-higher' });
      } else if (MARKET_CONDITION === 'hardening') {
        const lower = findNextAvailableCoverBelow(state, state.renewalCoverIndex);
        if (lower >= 0) cardSpecs.unshift({ coverIndex: lower, role: 'downgrade' });
      }
    }
  } else {
    recommended.forEach(ci => cardSpecs.push({ coverIndex: ci, role: 'recommended' }));
  }

  return { cardSpecs, recommended, renewal };
}

/* ===== Card styling for a recommendation role (verbatim) ===== */
export function getCardStyling(role, isAlsoRecommended) {
  switch (role) {
    case 'recommended':        return { badgeText: 'Recommended',          badgeClass: 'rec',         cardClass: 'recommended role-recommended' };
    case 'current':            return { badgeText: isAlsoRecommended ? 'Current Cover • Recommended' : 'Current Cover', badgeClass: 'current', cardClass: 'recommended role-current' };
    case 'reference':          return { badgeText: 'Reference — Not Recommended', badgeClass: 'reference', cardClass: 'role-reference' };
    case 'recommended-target': return { badgeText: 'Recommended',          badgeClass: 'rec',         cardClass: 'recommended role-target' };
    case 'upgrade':            return { badgeText: 'Upgrade Option',       badgeClass: 'upgrade',     cardClass: 'upgrade role-upgrade' };
    case 'downgrade':          return { badgeText: 'Downgrade Option',     badgeClass: 'downgrade',   cardClass: 'role-downgrade' };
    case 'alternative':
    case 'alternative-lower':
    case 'alternative-higher':
    case 'alternative-intermediate':
                               return { badgeText: 'Alternative',          badgeClass: 'alternative', cardClass: 'role-alternative' };
    default:                   return { badgeText: '',                     badgeClass: '',            cardClass: '' };
  }
}

/* ===== Underwriting Assessment (pure) =====
 * Replicates the PRICING/outcome logic of legacy `evaluateUW` (sme-rating.js),
 * plus the FP condition-of-cover sentences that the legacy `renderUWOutcome`
 * derives, with all DOM side-effects removed. Returns everything a caller needs
 * to price + display:
 *   { outcome, loadingPct, noCount, q1Conditions, fpConditions, allConditions }
 * outcome ∈ 'decline' | 'refer' | 'standard' | 'caution' | 'loading'.
 *
 * Control flow matches the legacy exactly:
 *   - Q1.1 or Q1.2 = No -> decline (loading 0, no conditions).
 *   - Q1.3 / Q1.4 = No -> Q1 conditions of cover (do NOT decline).
 *   - Loading pool = Q2.1, Q2.2, Q3, Q4, Q5 (five independent No's); grace of
 *     two, then 5/10/15% at 3/4/5 No's (UNDERWRITING_LOADINGS).
 *   - Prior claim, or Renewal + Q8 = No -> refer (loadingPct kept as computed).
 *   - FP conditions (Q6.1-6.3, Q7) only when fpOver250k.
 */
export function evaluateUnderwriting(answers, ctx = {}) {
  const a = answers || {};
  const quoteType = ctx.quoteType || 'new';
  const priorClaim = !!ctx.priorClaim;
  const fpOver250k = !!ctx.fpOver250k;

  // Q1 decline gate — Q1.1 (AV/EDR) and Q1.2 (firewall) are non-negotiable.
  if (a['q1-1'] === false || a['q1-2'] === false) {
    return { outcome: 'decline', loadingPct: 0, noCount: 0, q1Conditions: [], fpConditions: [], allConditions: [] };
  }

  // Q1.3 / Q1.4 No -> conditions of cover (only meaningful past the gate).
  const q1Conditions = [];
  if (a['q1-3'] === false) {
    q1Conditions.push('An email security solution that filters for phishing, malware and malicious attachments must be implemented as a condition of cover.');
  }
  if (a['q1-4'] === false) {
    q1Conditions.push('A web-filtering solution that blocks access to known malicious or suspicious websites must be implemented as a condition of cover.');
  }

  // Loading pool: Q2.1, Q2.2, Q3, Q4, Q5 (five independent questions).
  let noCount = 0;
  if (a['q2-1'] === false) noCount++;
  if (a['q2-2'] === false) noCount++;
  if (a['q3']   === false) noCount++;
  if (a['q4']   === false) noCount++;
  if (a['q5']   === false) noCount++;

  const loadingPct = UNDERWRITING_LOADINGS[Math.min(noCount, 5)].loading;

  // Outcome label: 0 Nos = standard (or caution if Q1 conditions), 1-2 = caution, 3+ = loading.
  let outcome;
  if (noCount === 0) {
    outcome = q1Conditions.length > 0 ? 'caution' : 'standard';
  } else if (noCount <= 2) {
    outcome = 'caution';
  } else {
    outcome = 'loading';
  }

  // FP-dependent conditions of cover (Q6.1-6.3, Q7) — only when FP > R250k.
  const fpConditions = [];
  if (fpOver250k) {
    if (a['q6-1'] === false) fpConditions.push('The Insured must have or implement documented procedures for the vetting of all new vendors, customers, and payees before processing any payments or financial transactions.');
    if (a['q6-2'] === false) fpConditions.push('The Insured must have or implement documented procedures to verify all new beneficiaries loaded onto the business\'s banking profiles before authorising any funds transfers.');
    if (a['q6-3'] === false) fpConditions.push('The Insured must have or implement documented procedures to verify and validate any requests to amend existing beneficiary payment details before processing changes.');
    if (a['q7']   === false) fpConditions.push('The Insured must utilise account verification services offered by their bank or a third-party provider to confirm the legitimacy of beneficiary accounts before processing payments.');
  }

  // Prior claim / renewal-Q8 contradiction -> refer (overrides label; loading kept).
  const renewalQ8Contradiction = (quoteType === 'renewal' && a['q8'] === false);
  if (priorClaim || renewalQ8Contradiction) {
    outcome = 'refer';
  }

  const allConditions = [].concat(q1Conditions, fpConditions);
  return { outcome, loadingPct, noCount, q1Conditions, fpConditions, allConditions };
}
