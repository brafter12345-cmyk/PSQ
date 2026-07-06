/**
 * pdf_parity.mjs — QA: generate the LEGACY generatePDF output and the ported
 * buildQuotePdf output for identical scenarios, write both to PDFs, so a text
 * extractor (compare_pdfs.py) can diff them. Proves the verbatim PDF port matches
 * the legacy (Render) PDF.
 *
 *   node tools/pdf_parity.mjs <outDir>
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import vm from 'node:vm';
import { jsPDF } from 'jspdf';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..', '..');
const LEGACY_DIR = resolve(REPO_ROOT, 'SME Rating Engine');
const OUT = process.argv[2] || __dirname;

// --- new (ported) engine + pdf ---------------------------------------------
const E = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-engine.js')).href);
const D = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'rating-data.js')).href);
const P = await import(pathToFileURL(resolve(__dirname, '..', 'src', 'lib', 'pdf.js')).href);

// --- legacy sandbox (generatePDF) ------------------------------------------
let CAPTURED = null;
function WrappedJsPDF(orientation, unit, format) {
  const doc = new jsPDF(orientation, unit, format);
  doc.save = function () { CAPTURED = doc; return doc; }; // capture instead of download
  return doc;
}
function fakeEl() {
  return { style: {}, classList: { add() {}, remove() {} }, innerHTML: '', value: '', textContent: '',
    appendChild(c) { return c; }, querySelectorAll() { return []; }, addEventListener() {} };
}
const sandbox = {
  window: {}, document: { getElementById: () => fakeEl(), querySelector: () => fakeEl(), querySelectorAll: () => [], addEventListener() {}, createElement: () => fakeEl(), body: fakeEl() },
  navigator: { userAgent: 'pdfqa' }, console,
  setTimeout: (fn) => { if (typeof fn === 'function') { /* skip */ } return 0; }, clearTimeout: () => {},
  fetch: () => Promise.resolve({ ok: false, status: 0, json: async () => ({}) }),
  Math, JSON, Intl, Date, Object, Array, Number, String, Boolean,
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.window.jspdf = { jsPDF: WrappedJsPDF };
vm.createContext(sandbox);
const dataSrc = readFileSync(resolve(LEGACY_DIR, 'sme-data.js'), 'utf8');
const ratingSrc = readFileSync(resolve(LEGACY_DIR, 'sme-rating.js'), 'utf8');
vm.runInContext(dataSrc + '\n' + ratingSrc + '\nglobalThis.__state=state; globalThis.__generatePDF=generatePDF;', sandbox, { filename: 'legacy.js' });
const LSTATE = sandbox.__state;
const LGEN = sandbox.__generatePDF;

// --- scenarios --------------------------------------------------------------
const INDUSTRIES = D.INDUSTRIES;
const idxOf = (pred) => INDUSTRIES.findIndex(pred);
const plainIdx = idxOf((x) => x.sub === 'eCommerce');
const softIdx = idxOf((x) => x.sub === 'Software and Technology');
const finIdx = idxOf((x) => x.main === 'Finance, Insurance, And Real Estate');

const scenarios = [
  {
    name: 'plain_newbiz_r5m_micro',
    company: 'Acme Trading (Pty) Ltd', industryIndex: plainIdx, prev: 12000000, current: 15000000,
    coverIndex: 2, fpIndex: 0, quoteType: 'new', website: 'www.acme.co.za',
    answers: { 'q1-1': true, 'q1-2': true, 'q1-3': true, 'q1-4': true, 'q2-1': true, 'q2-2': true, q3: true, q4: true, q5: true },
    posture: 0, discretionary: 0, endorsements: '', competitorName: '', competitorPremium: 0, competitorHasFP: false, priorClaim: false, endpointVendor: '',
  },
  {
    name: 'softtech_r10m_conditions_loading_prior',
    company: 'DevWorks SA (Pty) Ltd', industryIndex: softIdx, prev: 80000000, current: 95000000,
    coverIndex: 4, fpIndex: 2, quoteType: 'new', website: '',
    answers: { 'q1-1': true, 'q1-2': true, 'q1-3': false, 'q1-4': true, 'q2-1': false, 'q2-2': false, q3: false, q4: true, q5: true },
    posture: 0.15, discretionary: 0, endorsements: 'Subject to MFA rollout within 60 days. Prior loss noted.', competitorName: '', competitorPremium: 0, competitorHasFP: false, priorClaim: true, endpointVendor: 'SentinelOne Singularity',
  },
  {
    name: 'finance_r15m_competitor',
    company: 'Capital Brokers Ltd', industryIndex: finIdx, prev: 170000000, current: 185000000,
    coverIndex: 5, fpIndex: 0, quoteType: 'new', website: 'capitalbrokers.co.za',
    answers: { 'q1-1': true, 'q1-2': true, 'q1-3': true, 'q1-4': true, 'q2-1': true, 'q2-2': true, q3: true, q4: true, q5: true },
    posture: 0, discretionary: 0.1, endorsements: '', competitorName: 'Guardrisk', competitorPremium: 62000, competitorHasFP: true, priorClaim: false, endpointVendor: '',
  },
];

function fpOver250(coverIndex, fpIndex) {
  const key = D.COVER_LIMITS[coverIndex].key;
  const opt = D.getAvailableFPOptions(key)[fpIndex];
  return !!opt && opt.limit > 250000;
}

for (const s of scenarios) {
  const actualTurnover = E.calcActualTurnover(s.prev, s.current);
  const revenueBandIndex = E.findRevenueBand(actualTurnover);
  const fpOver = fpOver250(s.coverIndex, s.fpIndex);
  const uw = E.evaluateUnderwriting(s.answers, { quoteType: s.quoteType, priorClaim: s.priorClaim, fpOver250k: fpOver });
  const fpSel = { [s.coverIndex]: s.fpIndex };
  const fpLabelFull = D.getAvailableFPOptions(D.COVER_LIMITS[s.coverIndex].key)[s.fpIndex].label;
  const optLabelFull = D.COVER_LIMITS[s.coverIndex].label + ' / FP ' + fpLabelFull;
  const fpLabel = fpLabelFull.replace(/[\s,]/g, '');
  const coverLabel = D.COVER_LIMITS[s.coverIndex].label.replace(/[\s,]/g, '');
  const baseRef = `CPB-QA-${s.name}`;
  const optRef = `${baseRef}-${coverLabel}-FP${fpLabel}`;
  const option = { coverIndex: s.coverIndex, fpIndex: s.fpIndex, postureDiscount: s.posture, discretionaryDiscount: s.discretionary };

  // NEW pdf (per-option path)
  const myState = {
    companyName: s.company, industryIndex: s.industryIndex, quoteType: s.quoteType, websiteAddress: s.website,
    competitorName: s.competitorName, competitorHasFP: s.competitorHasFP,
    competitorRows: s.competitorPremium > 0 ? [{ coverIndex: s.coverIndex, competitorPremium: String(s.competitorPremium) }] : [],
    uwAnswers: s.answers, uwEndpointVendor: s.endpointVendor, uwPriorInsurer: '', uwPriorInceptionDate: '',
    priorClaim: s.priorClaim, endorsements: s.endorsements, renewalPremium: '', renewalFPLimit: '',
  };
  const myDerived = {
    actualTurnover, revenueBandIndex, uw,
    engineBase: { revenueBandIndex, industryIndex: s.industryIndex, actualTurnover, uwLoadingPct: uw.loadingPct, fpSelections: {}, postureDiscount: 0, discretionaryDiscount: 0 },
  };
  const { doc: newDoc } = P.buildQuotePdf({ state: myState, derived: myDerived, quoteRef: optRef, option });
  writeFileSync(resolve(OUT, `new_${s.name}.pdf`), Buffer.from(newDoc.output('arraybuffer')));

  // LEGACY pdf
  Object.keys(LSTATE).forEach((k) => { /* keep object identity */ });
  Object.assign(LSTATE, {
    companyName: s.company, industryIndex: s.industryIndex, turnoverPrev: s.prev, turnoverCurrent: s.current,
    actualTurnover, revenueBandIndex, websiteAddress: s.website, quoteType: s.quoteType, competitorName: s.competitorName,
    uwAnswers: s.answers, uwOutcome: uw.outcome, uwLoadingPct: uw.loadingPct, uwNoCount: uw.noCount,
    uwQ1ConditionsOfCover: uw.q1Conditions, uwFPConditions: uw.fpConditions, uwAllConditions: uw.allConditions,
    uwEndpointVendor: s.endpointVendor, uwPriorInsurer: '', uwPriorInceptionDate: '', fpOver250k: fpOver,
    priorClaim: s.priorClaim, endorsements: s.endorsements,
    renewalFPLimit: 0, renewalPremium: 0, renewalCoverIndex: -1, renewalPremiumDropTriggered: false, renewalBandChanged: false, renewalCorporateEscalation: false, renewalRecommendedCoverIndex: -1, renewalPremiumDropPct: 0,
    quoteOptions: [], activeOptionTab: null, selectedCovers: [s.coverIndex], recommendedCovers: [s.coverIndex],
    competitorRows: s.competitorPremium > 0 ? [{ requestedCoverIndex: s.coverIndex, competitorPremium: s.competitorPremium }] : [],
    competitorHasFP: s.competitorHasFP, calculations: {}, quoteRef: baseRef, baseRef,
    fpSelections: fpSel, postureDiscount: s.posture, discretionaryDiscount: s.discretionary,
  });
  CAPTURED = null;
  LGEN({ coverIndex: s.coverIndex, fpIndex: s.fpIndex, postureDiscount: s.posture, discretionaryDiscount: s.discretionary, label: optLabelFull });
  if (!CAPTURED) { console.error(`FAIL: legacy generatePDF did not produce a doc for ${s.name}`); process.exit(2); }
  writeFileSync(resolve(OUT, `legacy_${s.name}.pdf`), Buffer.from(CAPTURED.output('arraybuffer')));
  console.log(`wrote new_${s.name}.pdf + legacy_${s.name}.pdf`);
}
console.log('DONE. scenarios: ' + scenarios.map((s) => s.name).join(', '));
