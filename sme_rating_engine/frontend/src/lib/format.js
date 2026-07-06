// Currency parse/format — faithful to the legacy vanilla helpers.
export function parseCurrency(str) {
  if (!str) return 0;
  return parseFloat(String(str).replace(/[R,\s]/g, '')) || 0;
}

// Grouped thousands for display inside numeric inputs (en-ZA uses spaces).
export function formatThousands(n) {
  const v = typeof n === 'number' ? n : parseCurrency(n);
  if (!v) return '';
  return Math.round(v).toLocaleString('en-ZA');
}
