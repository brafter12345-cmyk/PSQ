/* corporate-engine.js — pure premium-calculation engine for the Corporate Rating Engine.
 *
 * Faithful port of the "Premium Calculation" sheet from
 * 'Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx'.
 * Validated step-by-step against the workbook's cached values (Final Premium R457,460.93).
 *
 * Runs in both the browser (global CorpEngine) and Node (module.exports) so the
 * math can be unit-tested headlessly.
 */
(function (global) {
  "use strict";
  const D = (typeof global.CORP_DATA !== "undefined" && global.CORP_DATA) ||
            (typeof require !== "undefined" ? require("./corporate-data.js") : null);
  if (!D) throw new Error("CORP_DATA not loaded");
  const K = D.CONSTANTS;

  // Exact-match lookup (mirrors XLOOKUP(...,,0) with match-mode 0)
  function xlookup(key, keys, vals, dflt) {
    for (let i = 0; i < keys.length; i++) {
      if (keys[i] === key) return vals[i];
    }
    return dflt === undefined ? null : dflt;
  }

  // --- table accessors ---
  function industryByLabel(label) {
    return D.INDUSTRIES.find((r) => r.sub === label) || null;
  }
  function basePremiumConstant(cover) {
    const row = D.BASE_PREMIUM.find((b) => b.cover === cover && b.constant != null);
    return row ? row.constant : null;
  }
  function benefitContribution(name) {
    const b = D.BENEFITS.find((x) => x.name === name);
    return b ? b.contribution : 0;
  }
  function maturityByLabel(label) {
    return D.MATURITY_BANDS.find((m) => m.label === label) || null;
  }

  // Adjustable Funds Protect cost for ANY amount, by piecewise-linear interpolation
  // across the spreadsheet's FP table anchors (which include the (0,0) point).
  // Exact table amounts return the exact cost; in-between amounts are interpolated.
  function fpAdjustableCost(amount) {
    const A = D.FP_ADJUSTABLE.amounts, C = D.FP_ADJUSTABLE.costs;
    const idx = A.indexOf(amount);
    if (idx !== -1) return { cost: C[idx], interpolated: false };
    if (amount <= A[0]) return { cost: C[0], interpolated: amount !== A[0] };
    for (let i = 0; i < A.length - 1; i++) {
      if (amount >= A[i] && amount <= A[i + 1]) {
        const t = (amount - A[i]) / (A[i + 1] - A[i]);
        return { cost: C[i] + t * (C[i + 1] - C[i]), interpolated: true };
      }
    }
    const n = A.length - 1;
    const slope = (C[n] - C[n - 1]) / (A[n] - A[n - 1]);
    return { cost: C[n] + slope * (amount - A[n]), interpolated: true };
  }

  // C12: computed maturity multiplier from a 0..1 posture score, banded by AS/AT thresholds.
  function computedMaturityMultiplier(posture) {
    const m = D.MATURITY_BANDS;
    if (posture >= m[0].gte) return m[0].multiplier;
    for (const i of [1, 2, 3]) {
      if (m[i].gte != null && m[i].lt != null && posture >= m[i].gte && posture < m[i].lt) return m[i].multiplier;
    }
    return m[4].multiplier;
  }

  /**
   * Compute a full corporate premium. See README / ENGINE_ANALYSIS.md for the input shape.
   * Returns { ok, warning?, finalPremium, basePremium, monthly, ..., steps:[{label,value,kind,note}] }
   * step kinds: "zar" (currency) | "pct" (percentage) | "mult" (bare multiplier).
   */
  function computePremium(inp) {
    const steps = [];
    const push = (label, value, kind, note) => steps.push({ label, value, kind: kind || "zar", note: note || "" });

    const vat = inp.vat != null ? inp.vat : K.DEFAULT_VAT;
    const ind = industryByLabel(inp.subIndustry);
    if (!ind) return { ok: false, error: "Unknown sub-industry: " + inp.subIndustry };

    // C6 — Base premium (rate)
    const baseConst = basePremiumConstant(inp.cover);
    if (baseConst == null) return { ok: false, error: "No base-premium constant for cover " + inp.cover };
    const exponent = K.EXPONENT_A * Math.log(inp.turnover) + K.EXPONENT_B;
    const C6 = baseConst * Math.pow(inp.turnover / inp.cover, exponent);
    push("Base premium (rate)", C6, "zar", "constant × (turnover/cover)^power");

    // C8 industry risk modifier, C9 BI contribution modifier
    const C8 = ind.industryFac;
    const C9 = ind.biFac;
    push("Industry risk modifier", C8, "pct");
    push("Business-interruption modifier", C9, "pct");

    // C12/C13 — maturity multiplier (override band, or computed from posture when override = N/A)
    const override = inp.maturityOverride || "N/A";
    const computedMat = inp.posture != null ? computedMaturityMultiplier(inp.posture) : null;
    const overrideBand = maturityByLabel(override);
    const overrideMult = overrideBand ? overrideBand.multiplier : 1;
    const maturityMult = override === "N/A" ? (computedMat != null ? computedMat : 1) : overrideMult;
    push("Cyber-maturity multiplier", maturityMult, "mult", override === "N/A" ? "from questionnaire posture" : override);

    // C15 — Adjusted premium
    const C15 = (C6 * (1 + C8) * (1 + C9) * maturityMult) / K.C15_DIVISOR * (1 + vat);
    push("Adjusted premium", C15, "zar", "industry × BI × maturity, VAT-normalised");

    // C16 — ransomware-inclusive
    const cyberExtBenefit = (inp.benefits || []).find((b) => b.name === "Cyber Extortion Costs");
    const cyberExtD = cyberExtBenefit && cyberExtBenefit.included ? benefitContribution("Cyber Extortion Costs") : 0;
    const C16 = C15 / K.RANSOM_DIV + cyberExtD + C15;
    push("Adjusted premium (ransomware incl.)", C16, "zar");

    // Benefits D19..D27 -> D28 (baseline), H28 (sub-limit adjusted)
    let Dsum = 0, Hsum = 0;
    const benefitRows = [];
    for (const b of inp.benefits || []) {
      let d = 0;
      if (b.included) {
        d = b.name === "Business Interruption Loss" ? ind.biFac : benefitContribution(b.name);
      }
      const ratio = b.sublimitRatio != null ? b.sublimitRatio : 1;
      const h = b.included && ratio ? d * Math.sqrt(ratio) : 0;
      Dsum += d;
      Hsum += h;
      benefitRows.push({ name: b.name, included: !!b.included, contribution: d, ratio, adjusted: h, subLimit: ratio * inp.cover });
    }
    push("Σ benefit contributions", Hsum, "pct");

    // C30 (sub-limit adjusted), C31 yearly market adjustment
    const C30 = C16 * Hsum;
    const C31 = C30 * (1 + K.YEARLY_MARKET_ADJ);
    push("Yearly market-adjusted premium", C31, "zar", pctStr(K.YEARLY_MARKET_ADJ) + " market factor");

    // Excess / deductible credit
    const C42 = K.SA_BREACH_FACTOR;
    const C45 = ind.breachZAR * C42; // expected average industry breach cost
    let C38, warning = null;
    if (inp.excess <= K.EXCESS_HALF_COVER * inp.cover) {
      C38 = C45 < inp.cover ? inp.excess / C45 : Math.pow(inp.excess / inp.cover, K.EXCESS_POWER);
    } else {
      warning = "Selected cover may result in partial self-insurance. Please review your cover amount.";
      C38 = 0;
    }
    push("Excess / self-insurance credit", C38, "pct", warning || "");
    const C48 = C31 * (1 - C38);
    push("Premium after excess credit", C48, "zar");

    // Funds Protect: adjustable (>0) else standard (10% of cover)
    let fp = 0, fpKind = "None", fpInterpolated = false, fpBelowMin = false;
    if (inp.fpAdjustableAmount && inp.fpAdjustableAmount > 0) {
      const fr = fpAdjustableCost(inp.fpAdjustableAmount);
      fp = fr.cost; fpInterpolated = fr.interpolated;
      fpBelowMin = inp.fpAdjustableAmount < 0.10 * inp.cover;
      fpKind = "Adjustable FP @ " + zar(inp.fpAdjustableAmount) + (fr.interpolated ? " (interpolated)" : "");
    } else {
      fp = xlookup(inp.cover * 0.1, D.FP_STANDARD.amounts, D.FP_STANDARD.costs, 0) || 0;
      fpKind = "Standard FP (10% of cover)";
    }
    push("Funds Protect contribution", fp, "zar", fpKind);

    // Depository-institution modifier (only for Depository Institutions sub-industry)
    let depository = 0;
    if (inp.subIndustry === D.DEPOSITORY_SUB) {
      for (const band of D.DEPOSITORY_BANDS) {
        const lo = band.gte, hi = band.lt;
        if (hi == null ? inp.turnover >= lo : inp.turnover >= lo && inp.turnover < hi) {
          depository = band.modifier;
          break;
        }
      }
    }

    // C53 — base premium (pre-discount), C56/C57 — MDR discount & final
    const C53 = ((C48 + fp) / (1 - K.RISK_MGMT_FEE)) * (depository > 0 ? depository : 1);
    push("Base premium", C53, "zar", depository > 0 ? "incl. depository ×" + depository : "incl. 6% risk-mgmt fee");
    const mdrDiscount = xlookup(inp.mdr || "No MDR", D.MDR_OPTIONS.map((m) => m.label), D.MDR_OPTIONS.map((m) => m.discount), 0) || 0;
    const C56 = C53 * mdrDiscount;
    const premiumPreDisc = C53 - C56; // C57 — final before any discretionary adjustment
    if (mdrDiscount > 0) push("Sophos MDR discount", -C56, "zar", pctStr(mdrDiscount) + " — " + inp.mdr);

    // Discretionary adjustment (positive = discount, negative = loading), applied to the final premium.
    const discretionary = inp.discretionary || 0;
    const discretionaryAmount = premiumPreDisc * discretionary;
    const finalPremium = premiumPreDisc - discretionaryAmount;
    if (discretionary !== 0) {
      push("Premium before discretionary", premiumPreDisc, "zar");
      const verb = discretionary >= 0 ? "discount" : "loading";
      push("Discretionary " + verb, -discretionaryAmount, "zar", pctStr(Math.abs(discretionary)) + " (manual)");
    }
    push("Final premium", finalPremium, "zar");

    // Summary-row derivations (on the final, post-discretionary premium)
    const monthly = finalPremium / 12;
    // "Premium without RM Fee" — the figure captured on the admin platform, which then adds
    // a 6% RM fee to reach the final premium. Matches the workbook's "Excl. RM" line (D36 = C36/1.06).
    const premiumExRM = finalPremium / 1.06;
    const monthlyExRM = Math.ceil(premiumExRM / 12);
    const exFP = finalPremium - fp;
    const smeEquivalent = (finalPremium * 0.8) / (1 + vat); // F36 ex-FP / ex-VAT SME-equivalent
    const smeRatio = finalPremium * K.SME_CORP_RATIO; // I36

    return {
      ok: true, warning,
      finalPremium, premiumPreDiscretionary: premiumPreDisc, basePremium: C53, fundsProtect: fp,
      monthly, premiumExRM, monthlyExRM, exFP, smeEquivalent, smeRatio,
      mdrDiscount, mdrAmount: C56, discretionary, discretionaryAmount,
      fpInterpolated, fpBelowMin, depositoryModifier: depository, expectedBreachCost: C45,
      industry: ind, maturityMultiplier: maturityMult, benefitRows, vat, steps,
    };
  }

  // Compute the premium for the given inputs across every cover option (for the comparison view).
  function computeAcrossCovers(inp) {
    return D.COVER_OPTIONS.map((c) => {
      const r = computePremium(Object.assign({}, inp, { cover: c }));
      return r.ok
        ? { cover: c, finalPremium: r.finalPremium, monthly: r.monthly, fundsProtect: r.fundsProtect, warning: r.warning, fpBelowMin: r.fpBelowMin }
        : { cover: c, error: r.error };
    });
  }

  function pctStr(x) { return (x * 100).toFixed(2) + "%"; }
  function zar(n) { return "R" + Math.round(n).toLocaleString("en-ZA"); }

  const ENGINE = { xlookup, computePremium, computeAcrossCovers, fpAdjustableCost, computedMaturityMultiplier, industryByLabel, basePremiumConstant, zar };
  if (typeof module !== "undefined" && module.exports) module.exports = ENGINE;
  global.CorpEngine = ENGINE;
})(typeof window !== "undefined" ? window : globalThis);
