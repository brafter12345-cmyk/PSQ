// Central wizard state — mirrors the fields of the legacy vanilla `state`
// object. Derived values (turnover, band, UW outcome, blocker, premiums,
// recommendations) are computed through the parity-locked engine, not stored.
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

  // Step 2 — coverage (multi-cover quote options)
  quoteOptions: [],     // [{ id, coverIndex, fpIndex, postureDiscount, discretionaryDiscount, manualOverride }]
  activeOptionTab: null,
  showCustomCover: false,

  // Step 3 — competitor comparison
  competitorName: '',
  competitorHasFP: false,
  competitorRows: [],   // [{ coverIndex, competitorPremium }] per requested cover

  // Step 4 — adjustments
  applyDiscountsToAll: false,
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
    case 'setOptions':
      return { ...state, quoteOptions: action.options };
    case 'patchOption': {
      const quoteOptions = state.quoteOptions.map((o) =>
        o.id === action.id ? { ...o, ...action.patch } : o);
      return { ...state, quoteOptions };
    }
    case 'reset':
      return { ...initialState };
    default:
      return state;
  }
}
