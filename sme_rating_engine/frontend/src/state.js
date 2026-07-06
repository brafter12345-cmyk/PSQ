// Central wizard state — mirrors the fields of the legacy vanilla `state`
// object. Derived values (actualTurnover, revenueBandIndex, UW outcome, blocker,
// premiums) are computed from these via the parity-locked engine, not stored raw.
export const initialState = {
  currentStep: 1,

  // Step 1 — client & industry
  companyName: '',
  industryIndex: -1,
  turnoverPrev: '',
  turnoverCurrent: '',
  employeeCount: '',
  websiteAddress: '',
  uwAnswers: {},        // { 'q1-1': true|false, ... }
  uwEndpointVendor: '',
  uwPriorInsurer: '',
  uwPriorInceptionDate: '',
  fpOver250k: false,
  priorClaim: false,
  quoteType: 'new',     // 'new' | 'renewal' | 'competing'

  // Renewal inputs
  renewalCoverIndex: -1,
  renewalPremium: '',
  renewalFPLimit: '',

  // Step 2 — coverage (single primary cover; multi-cover comparison is a follow-up)
  selectedCoverIndex: -1,
  fpSelections: {},     // { coverIndex: fpIndex } (index into getAvailableFPOptions)
  showCustomCover: false,

  // Step 3 — competitor comparison
  competitorName: '',
  competitorHasFP: false,
  competitorPremium: '',   // competitor premium for the selected cover

  // Step 4 — adjustments (percent strings, e.g. "15" or "-10")
  postureDiscount: '',
  discretionaryDiscount: '',
  manualOverride: '',
  endorsements: '',
  compareTarget: 'itoo',

  // Step 5 — export
  quoteRef: '',
  createdBy: '',
};

export function reducer(state, action) {
  switch (action.type) {
    case 'patch':
      return { ...state, ...action.patch };
    case 'setUwAnswer':
      return { ...state, uwAnswers: { ...state.uwAnswers, [action.key]: action.value } };
    case 'setFp':
      return { ...state, fpSelections: { ...state.fpSelections, [action.coverIndex]: action.fpIndex } };
    case 'reset':
      return { ...initialState };
    default:
      return state;
  }
}
