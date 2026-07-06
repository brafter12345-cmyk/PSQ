/**
 * parity.mjs — BLOCKING GATE. Proves the extracted ESM rating modules
 * (src/rating-data.js, src/rating-engine.js) are behaviourally identical to the
 * legacy vanilla app (SME Rating Engine/sme-data.js + sme-rating.js).
 *
 * Method (mirrors the scanner's golden-replay discipline):
 *   1. Load the LEGACY files in a node:vm sandbox with a stubbed DOM, so the
 *      real legacy functions run untouched and serve as ground truth.
 *   2. Deep-equal every exported data constant + FP helper output.
 *   3. Deep-equal calculatePremium() across a full input grid (both the
 *      optionOverrides path and the state-field path).
 *   4. Deep-equal evaluateUnderwriting() against the legacy evaluateUW()'s
 *      effect on state, across a full underwriting-answer grid.
 *   5. Write a human-readable golden snapshot (tools/golden_premiums.json).
 * Exits non-zero on ANY mismatch.
 *
 *   node tools/parity.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';
import { isDeepStrictEqual } from 'node:util';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..', '..');
const LEGACY_DIR = resolve(REPO_ROOT, 'SME Rating Engine');

// ---------------------------------------------------------------------------
// 1. Load legacy files in a stubbed-DOM sandbox
// ---------------------------------------------------------------------------
function makeFakeEl() {
  const el = {
    style: {}, dataset: {},
    classList: { add() {}, remove() {}, contains() { return false; }, toggle() {} },
    value: '', textContent: '', innerHTML: '', className: '', disabled: false,
    appendChild(c) { return c; }, removeChild(c) { return c; },
    insertBefore(c) { return c; }, remove() {},
    setAttribute() {}, removeAttribute() {}, getAttribute() { return null; },
    addEventListener() {}, removeEventListener() {},
    querySelector() { return makeFakeEl(); }, querySelectorAll() { return []; },
    closest() { return null; }, focus() {}, blur() {}, click() {},
    cloneNode() { return makeFakeEl(); },
  };
  return el;
}
const fakeDoc = {
  getElementById() { return makeFakeEl(); },
  querySelector() { return makeFakeEl(); },
  querySelectorAll() { return []; },
  createElement() { return makeFakeEl(); },
  addEventListener() {}, removeEventListener() {},
  body: makeFakeEl(),
};
const sandbox = {
  document: fakeDoc,
  window: {},
  navigator: { userAgent: 'parity' },
  console,
  setTimeout: () => 0,
  clearTimeout: () => {},
  Math, JSON, Intl, Date, Object, Array, Number, String, Boolean,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const dataSrc = readFileSync(resolve(LEGACY_DIR, 'sme-data.js'), 'utf8');
const ratingSrc = readFileSync(resolve(LEGACY_DIR, 'sme-rating.js'), 'utf8');
const shim = `
globalThis.__ENGINE__ = { state, calculatePremium, evaluateUW,
  calcActualTurnover, findRevenueBand, checkMicroSME, getIndustryModifier,
  getEffectiveBandIndex, getItooBenchmark, getRecommendedCovers, fpIndexForLimit,
  findTargetCoverForRetention, findHighestAvailableCover, findNextAvailableCoverAbove,
  findNextAvailableCoverBelow, renderRecommendations };
globalThis.__DATA__ = { MARKET_CONDITION, MARKET_CONDITION_YEAR, MARKET_CONDITION_LABEL,
  REVENUE_BANDS, COVER_LIMITS, SME_PREMIUMS, PREMIUM_FORMULAS, MICRO_PREMIUMS,
  BASE_FP_BY_COVER, FP_COSTS, INDUSTRY_MODIFIERS, FINANCE_SUB_INDUSTRIES,
  ITOO_BENCHMARKS, INDUSTRIES, COVER_AVAILABILITY, UNDERWRITING_QUESTIONS,
  UNDERWRITING_LOADINGS, BROKER_COMMISSION, ADMIN_FEE_RATE };
globalThis.__FPFN__ = { getAvailableFPOptions, getBaseFPCost };
`;
vm.runInContext(dataSrc + '\n' + ratingSrc + '\n' + shim, sandbox, { filename: 'legacy.js' });
const L = sandbox.__ENGINE__;
const LD = sandbox.__DATA__;
const LFP = sandbox.__FPFN__;

// ---------------------------------------------------------------------------
// 2. Import the new ESM modules
// ---------------------------------------------------------------------------
const N = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-engine.js')).href);
const ND = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-data.js')).href);

let failures = 0;
const fail = (msg, extra) => { failures++; console.error('  ✗ ' + msg); if (extra !== undefined) console.error('    ' + extra); };
// Legacy values live in the vm realm (different Object/Array prototypes than the
// imported ESM values). isDeepStrictEqual compares [[Prototype]] with ===, so it
// would reject cross-realm-but-identical values. Normalise both sides through
// JSON first — our data is pure numbers/strings/bools/null/arrays/objects, so
// this is lossless and realm-agnostic.
const norm = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));
const eq = (a, b) => isDeepStrictEqual(norm(a), norm(b));

// ---------------------------------------------------------------------------
// 3. Data parity
// ---------------------------------------------------------------------------
console.log('[1] data-constant parity');
let dataChecked = 0;
for (const key of Object.keys(LD)) {
  dataChecked++;
  if (!eq(LD[key], ND[key])) fail(`data mismatch: ${key}`, `legacy=${JSON.stringify(LD[key]).slice(0, 120)} new=${JSON.stringify(ND[key]).slice(0, 120)}`);
}
console.log(`    ${dataChecked} constants compared`);

console.log('[2] FP-helper parity');
const coverKeys = LD.COVER_LIMITS.map((c) => c.key);
for (const ck of coverKeys) {
  if (!eq(LFP.getAvailableFPOptions(ck), ND.getAvailableFPOptions(ck))) fail(`getAvailableFPOptions("${ck}")`);
  if (!eq(LFP.getBaseFPCost(ck), ND.getBaseFPCost(ck))) fail(`getBaseFPCost("${ck}")`);
}
console.log(`    ${coverKeys.length} cover keys compared`);

console.log('[2b] recommendation / benchmark / fp-index parity');
let helperChecked = 0;
for (let b = -1; b <= 7; b++) { if (!eq(L.getRecommendedCovers(b), N.getRecommendedCovers(b))) fail(`getRecommendedCovers(${b})`); helperChecked++; }
for (const ck of coverKeys) {
  for (const lim of [0, 100000, 150000, 250000, 300000, 1000000, 5000000, 9999999]) {
    if (!eq(L.fpIndexForLimit(ck, lim), N.fpIndexForLimit(ck, lim))) fail(`fpIndexForLimit("${ck}", ${lim})`);
    helperChecked++;
  }
}
for (const to of [0, 5e6, 12e6, 40e6, 90e6, 130e6, 180e6, 240e6, 300e6]) {
  for (let ci = -1; ci <= 6; ci++) { if (!eq(L.getItooBenchmark(to, ci), N.getItooBenchmark(to, ci))) fail(`getItooBenchmark(${to}, ${ci})`); helperChecked++; }
}
console.log(`    ${helperChecked} helper evaluations compared`);

// ---------------------------------------------------------------------------
// 4. calculatePremium parity — full grid
// ---------------------------------------------------------------------------
console.log('[3] calculatePremium parity (full grid)');
const INDUSTRIES = LD.INDUSTRIES;
const plainIdx = INDUSTRIES.findIndex((x) => x.main !== 'Finance, Insurance, And Real Estate' && x.sub !== 'Software and Technology' && !x.referForUW);
const softIdx = INDUSTRIES.findIndex((x) => x.sub === 'Software and Technology');
const finIdx = INDUSTRIES.findIndex((x) => x.main === 'Finance, Insurance, And Real Estate');
const industryIdxs = [-1, plainIdx, softIdx, finIdx];
const bandIdxs = [-1, 0, 1, 2, 3, 4, 5, 6];
const coverIdxs = [-1, 0, 1, 2, 3, 4, 5, 6];
const loadings = [0, 0.05, 0.10, 0.15];
const postures = [0, 0.15, -0.10];
const discretionaries = [0, 0.20];

const bandTurnover = (b) => {
  if (b < 0) return 0;
  const band = LD.REVENUE_BANDS[b];
  return Math.round((band.min + band.max) / 2);
};
// FP indices to probe per cover (undefined = base, plus valid samples + out-of-range guard)
const fpProbes = (coverIdx) => {
  if (coverIdx < 0 || coverIdx >= LD.COVER_LIMITS.length) return [undefined];
  const n = LFP.getAvailableFPOptions(LD.COVER_LIMITS[coverIdx].key).length;
  const set = new Set([undefined, 0, Math.floor(n / 2), n - 1, 99]);
  return [...set];
};

let premChecked = 0;
let firstMismatch = null;
outer:
for (const ind of industryIdxs) {
  for (const band of bandIdxs) {
    for (const cover of coverIdxs) {
      for (const fpIndex of fpProbes(cover)) {
        for (const load of loadings) {
          for (const posture of postures) {
            for (const disc of discretionaries) {
              // Mode A: optionOverrides carries fp + discounts
              const stateA = {
                revenueBandIndex: band, industryIndex: ind, actualTurnover: bandTurnover(band),
                uwLoadingPct: load, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0,
              };
              const ovA = { fpIndex, postureDiscount: posture, discretionaryDiscount: disc };
              const la = L.calculatePremium(cover, stateA, ovA);
              const na = N.calculatePremium(cover, stateA, ovA);
              premChecked++;
              if (!eq(la, na)) { firstMismatch = firstMismatch || { mode: 'A', ind, band, cover, fpIndex, load, posture, disc, la, na }; fail(`calculatePremium mode A (ind=${ind} band=${band} cover=${cover} fp=${fpIndex} load=${load} p=${posture} d=${disc})`); if (failures > 8) break outer; }

              // Mode B: state fields carry fp + discounts, no optionOverrides
              const stateB = {
                revenueBandIndex: band, industryIndex: ind, actualTurnover: bandTurnover(band),
                uwLoadingPct: load,
                fpSelections: fpIndex === undefined ? {} : { [cover]: fpIndex },
                postureDiscount: posture, discretionaryDiscount: disc,
              };
              const lb = L.calculatePremium(cover, stateB, undefined);
              const nb = N.calculatePremium(cover, stateB, undefined);
              premChecked++;
              if (!eq(lb, nb)) { firstMismatch = firstMismatch || { mode: 'B', ind, band, cover, fpIndex, load, posture, disc, lb, nb }; fail(`calculatePremium mode B (ind=${ind} band=${band} cover=${cover} fp=${fpIndex} load=${load} p=${posture} d=${disc})`); if (failures > 8) break outer; }
            }
          }
        }
      }
    }
  }
}
console.log(`    ${premChecked} premium evaluations compared`);
if (firstMismatch) console.error('    first mismatch: ' + JSON.stringify(firstMismatch).slice(0, 400));

// ---------------------------------------------------------------------------
// 5. evaluateUnderwriting parity — full answer grid
// ---------------------------------------------------------------------------
console.log('[4] evaluateUnderwriting parity');
const S = L.state;
const TRI = [true, false, undefined];
const BI = [true, false];
function legacyUW(answers, ctx) {
  // reset the fields evaluateUW / renderUWOutcome read-or-write, so decline's
  // early return (which skips FP-condition recompute) yields [] not stale data
  S.uwAnswers = answers;
  S.quoteType = ctx.quoteType;
  S.priorClaim = !!ctx.priorClaim;
  S.fpOver250k = !!ctx.fpOver250k;
  S.uwOutcome = null; S.uwLoadingPct = 0; S.uwNoCount = 0;
  S.uwQ1ConditionsOfCover = []; S.uwFPConditions = []; S.uwAllConditions = [];
  S.isBlocked = false; S.blockReason = '';
  L.evaluateUW();
  return {
    outcome: S.uwOutcome, loadingPct: S.uwLoadingPct, noCount: S.uwNoCount,
    q1Conditions: S.uwQ1ConditionsOfCover, fpConditions: S.uwFPConditions,
    allConditions: S.uwAllConditions,
  };
}
let uwChecked = 0;
let uwFirst = null;
// (a) targeted: sweep the pricing pool + gates
for (const q11 of BI) for (const q12 of BI) for (const q13 of TRI) for (const q14 of TRI)
for (const q21 of BI) for (const q22 of BI) for (const q3 of BI) for (const q4 of BI) for (const q5 of BI) {
  const answers = { 'q1-1': q11, 'q1-2': q12, 'q1-3': q13, 'q1-4': q14, 'q2-1': q21, 'q2-2': q22, q3, q4, q5 };
  for (const ctx of [{ quoteType: 'new', priorClaim: false, fpOver250k: false }, { quoteType: 'renewal', priorClaim: false, fpOver250k: false }]) {
    const lo = legacyUW(answers, ctx); const no = N.evaluateUnderwriting(answers, ctx);
    uwChecked++;
    if (!eq(lo, no)) { uwFirst = uwFirst || { answers, ctx, lo, no }; fail('evaluateUnderwriting (pricing pool)'); if (failures > 12) break; }
  }
}
// (b) FP conditions + prior claim + renewal-Q8 + Q8 follow-up (Q1 gate passing)
for (const q61 of TRI) for (const q62 of TRI) for (const q63 of TRI) for (const q7 of TRI) for (const q8 of TRI)
for (const priorClaim of BI) for (const fpOver250k of BI) for (const quoteType of ['new', 'renewal', 'competing']) {
  const answers = { 'q1-1': true, 'q1-2': true, 'q1-3': true, 'q1-4': true, 'q2-1': true, 'q2-2': true, q3: true, q4: true, q5: true, 'q6-1': q61, 'q6-2': q62, 'q6-3': q63, q7, q8 };
  const ctx = { quoteType, priorClaim, fpOver250k };
  const lo = legacyUW(answers, ctx); const no = N.evaluateUnderwriting(answers, ctx);
  uwChecked++;
  if (!eq(lo, no)) { uwFirst = uwFirst || { answers, ctx, lo, no }; fail('evaluateUnderwriting (FP/claim/renewal)'); if (failures > 12) break; }
}
console.log(`    ${uwChecked} underwriting evaluations compared`);
if (uwFirst) console.error('    first UW mismatch: ' + JSON.stringify(uwFirst).slice(0, 500));

// ---------------------------------------------------------------------------
// 5b. Renewal-ladder helpers + cover-recommendation flags parity
// ---------------------------------------------------------------------------
console.log('[5] recommendation + renewal-ladder parity');
let recoChecked = 0;
let recoFirst = null;
// (a) directional helpers across all bands + start indices
for (let band = -1; band <= 7; band++) {
  S.revenueBandIndex = band;
  const st = { revenueBandIndex: band };
  if (!eq(L.findHighestAvailableCover(), N.findHighestAvailableCover(st))) { recoFirst = recoFirst || { fn: 'findHighest', band }; fail(`findHighestAvailableCover(band=${band})`); }
  recoChecked++;
  for (let s = -1; s <= 6; s++) {
    if (!eq(L.findNextAvailableCoverAbove(s), N.findNextAvailableCoverAbove(st, s))) { recoFirst = recoFirst || { fn: 'above', band, s }; fail(`findNextAvailableCoverAbove(band=${band},s=${s})`); }
    if (!eq(L.findNextAvailableCoverBelow(s), N.findNextAvailableCoverBelow(st, s))) { recoFirst = recoFirst || { fn: 'below', band, s }; fail(`findNextAvailableCoverBelow(band=${band},s=${s})`); }
    recoChecked += 2;
  }
}
// (b) findTargetCoverForRetention across scenarios (needs full calc inputs)
for (const band of [0, 1, 3, 6]) {
  for (const ind of [plainIdx, softIdx, finIdx]) {
    const full = { revenueBandIndex: band, industryIndex: ind, actualTurnover: bandTurnover(band), uwLoadingPct: 0, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 };
    Object.assign(S, full);
    for (const start of [0, 2, 4]) {
      for (const tp of [5000, 20000, 60000, 200000]) {
        for (const fp of [150000, 250000, 1000000]) {
          if (!eq(L.findTargetCoverForRetention(start, tp, fp), N.findTargetCoverForRetention(full, start, tp, fp))) { recoFirst = recoFirst || { fn: 'target', band, ind, start, tp, fp }; fail(`findTargetCoverForRetention(band=${band},start=${start},tp=${tp},fp=${fp})`); }
          recoChecked++;
        }
      }
    }
  }
}
// (c) buildCoverRecommendations renewal flags vs legacy renderRecommendations state flags
function legacyReco(sc) {
  Object.assign(S, {
    revenueBandIndex: sc.band, industryIndex: sc.ind, actualTurnover: bandTurnover(sc.band), uwLoadingPct: sc.load || 0,
    quoteType: sc.quoteType, renewalCoverIndex: sc.renewalCoverIndex ?? -1, renewalPremium: sc.renewalPremium || 0, renewalFPLimit: sc.renewalFPLimit || 0,
    fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0,
    quoteOptions: [], selectedCovers: [], recommendedCovers: [], activeOptionTab: null,
    renewalPremiumDropTriggered: false, renewalPremiumDropPct: 0, renewalCorporateEscalation: false, renewalRecommendedCoverIndex: -1, renewalBandChanged: false,
  });
  L.renderRecommendations();
  return {
    dropTriggered: S.renewalPremiumDropTriggered, dropPct: S.renewalPremiumDropPct,
    corporateEscalation: S.renewalCorporateEscalation, recommendedCoverIndex: S.renewalRecommendedCoverIndex, bandChanged: S.renewalBandChanged,
  };
}
const recoScenarios = [
  { band: 1, ind: plainIdx, quoteType: 'new' },
  { band: 4, ind: softIdx, quoteType: 'competing' },
  // renewals: low existing premium (not triggered -> softening upgrades)
  { band: 1, ind: plainIdx, quoteType: 'renewal', renewalCoverIndex: 2, renewalPremium: 8000, renewalFPLimit: 250000 },
  { band: 2, ind: finIdx, quoteType: 'renewal', renewalCoverIndex: 1, renewalPremium: 9000, renewalFPLimit: 200000 },
  // renewals: high existing premium (drop triggered / retention target)
  { band: 1, ind: plainIdx, quoteType: 'renewal', renewalCoverIndex: 2, renewalPremium: 40000, renewalFPLimit: 250000 },
  { band: 3, ind: softIdx, quoteType: 'renewal', renewalCoverIndex: 2, renewalPremium: 60000, renewalFPLimit: 500000 },
  // renewals: very high existing (corporate escalation)
  { band: 1, ind: plainIdx, quoteType: 'renewal', renewalCoverIndex: 2, renewalPremium: 250000, renewalFPLimit: 250000 },
  { band: 6, ind: finIdx, quoteType: 'renewal', renewalCoverIndex: 5, renewalPremium: 500000, renewalFPLimit: 1500000 },
  // renewals: band-changed (existing cover not in recommended set)
  { band: 6, ind: plainIdx, quoteType: 'renewal', renewalCoverIndex: 0, renewalPremium: 30000, renewalFPLimit: 150000 },
  { band: 0, ind: plainIdx, quoteType: 'renewal', renewalCoverIndex: 5, renewalPremium: 40000, renewalFPLimit: 1500000 },
  // renewals with UW loading
  { band: 3, ind: softIdx, quoteType: 'renewal', renewalCoverIndex: 3, renewalPremium: 45000, renewalFPLimit: 500000, load: 0.15 },
];
for (const sc of recoScenarios) {
  const lo = legacyReco(sc);
  const myState = { revenueBandIndex: sc.band, industryIndex: sc.ind, actualTurnover: bandTurnover(sc.band), uwLoadingPct: sc.load || 0, quoteType: sc.quoteType, renewalCoverIndex: sc.renewalCoverIndex ?? -1, renewalPremium: sc.renewalPremium || 0, renewalFPLimit: sc.renewalFPLimit || 0, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 };
  const no = N.buildCoverRecommendations(myState).renewal;
  recoChecked++;
  if (!eq(lo, no)) { recoFirst = recoFirst || { sc, lo, no }; fail('buildCoverRecommendations.renewal'); }
}
console.log(`    ${recoChecked} recommendation/renewal evaluations compared`);
if (recoFirst) console.error('    first reco mismatch: ' + JSON.stringify(recoFirst).slice(0, 500));

// ---------------------------------------------------------------------------
// 6. Golden snapshot (curated, human-readable) — outputs are ground truth (legacy)
// ---------------------------------------------------------------------------
const golden = { generatedBy: 'tools/parity.mjs', note: 'Ground-truth outputs from the LEGACY engine; parity proves the new ESM engine matches.', premiums: [], underwriting: [] };
const goldScenarios = [
  { label: 'micro R1M plain band0', ind: plainIdx, band: 0, cover: 0, ov: {} },
  { label: 'micro R5M soft-tech band2', ind: softIdx, band: 2, cover: 2, ov: {} },
  { label: 'std R10M finance band4', ind: finIdx, band: 4, cover: 4, ov: {} },
  { label: 'std R15M plain band6 +15% load', ind: plainIdx, band: 6, cover: 5, ov: {}, load: 0.15 },
  { label: 'std R2.5M soft band1 FP tier2 -10% posture', ind: softIdx, band: 1, cover: 1, ov: { fpIndex: 2, postureDiscount: -0.10 } },
  { label: 'std R7.5M plain band3 15% posture 20% disc', ind: plainIdx, band: 3, cover: 3, ov: { postureDiscount: 0.15, discretionaryDiscount: 0.20 } },
];
for (const g of goldScenarios) {
  const st = { revenueBandIndex: g.band, industryIndex: g.ind, actualTurnover: bandTurnover(g.band), uwLoadingPct: g.load || 0, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 };
  golden.premiums.push({ label: g.label, output: L.calculatePremium(g.cover, st, g.ov) });
}
const goldUW = [
  { label: 'all yes', answers: { 'q1-1': true, 'q1-2': true, 'q1-3': true, 'q1-4': true, 'q2-1': true, 'q2-2': true, q3: true, q4: true, q5: true }, ctx: { quoteType: 'new' } },
  { label: 'decline (q1-1 no)', answers: { 'q1-1': false }, ctx: { quoteType: 'new' } },
  { label: '3 nos -> 5% loading', answers: { 'q1-1': true, 'q1-2': true, 'q2-1': false, q3: false, q4: false }, ctx: { quoteType: 'new' } },
  { label: 'refer prior claim', answers: { 'q1-1': true, 'q1-2': true }, ctx: { quoteType: 'new', priorClaim: true } },
  { label: 'fp conditions', answers: { 'q1-1': true, 'q1-2': true, 'q6-1': false, q7: false }, ctx: { quoteType: 'new', fpOver250k: true } },
];
for (const g of goldUW) golden.underwriting.push({ label: g.label, output: legacyUW(g.answers, { quoteType: 'new', priorClaim: false, fpOver250k: false, ...g.ctx }) });
writeFileSync(resolve(__dirname, 'golden_premiums.json'), JSON.stringify(golden, null, 2), 'utf8');

// ---------------------------------------------------------------------------
console.log('');
if (failures === 0) {
  console.log(`PARITY OK — data(${dataChecked}) + premium(${premChecked}) + underwriting(${uwChecked}) all identical. Golden snapshot written.`);
  process.exit(0);
} else {
  console.error(`PARITY FAILED — ${failures} mismatch(es). The port is wrong; do not ship.`);
  process.exit(1);
}
