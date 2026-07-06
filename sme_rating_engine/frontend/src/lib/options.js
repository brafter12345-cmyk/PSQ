import { COVER_LIMITS, getAvailableFPOptions } from '../rating-data.js';

// Multi-cover quote options — mirrors the legacy quoteOptions model.
let _optionCounter = 0;
export function generateOptionId() {
  return 'opt-' + (++_optionCounter);
}

export function makeOption(coverIndex, fpIndex = 0) {
  return {
    id: generateOptionId(),
    coverIndex,
    fpIndex: fpIndex || 0,
    posturePct: '',        // percent string, e.g. "15" or "-10"
    discretionaryPct: '',  // percent string
    manualOverride: '',
  };
}

export function optionLabel(coverIndex, fpIndex) {
  const cover = COVER_LIMITS[coverIndex].label;
  const availFP = getAvailableFPOptions(COVER_LIMITS[coverIndex].key);
  const fp = (fpIndex >= 0 && fpIndex < availFP.length) ? availFP[fpIndex].label : 'Base FP';
  return `${cover} / FP ${fp}`;
}

export function coverInstanceCount(options, coverIndex) {
  return options.filter((o) => o.coverIndex === coverIndex).length;
}

export function isCoverInOptions(options, coverIndex) {
  return options.some((o) => o.coverIndex === coverIndex);
}
