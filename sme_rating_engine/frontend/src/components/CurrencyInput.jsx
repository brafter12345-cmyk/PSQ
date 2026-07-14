import { useState } from 'react';
import { parseCurrency } from '../lib/format.js';

// Currency text input — mirrors the legacy formatCurrencyInput/stripCurrencyInput:
// shows the grouped value ("R29 308 000", en-ZA spaces) when blurred, and raw
// digits when focused for easy editing. Calls onChange(rawDigitString) so callers
// keep storing a plain numeric string in state. Percent fields (discounts) do NOT
// use this — only rand amounts.
export default function CurrencyInput({ value, onChange, prefix = 'R', ...rest }) {
  const [focused, setFocused] = useState(false);
  const num = parseCurrency(value);
  const display = focused ? (value ?? '') : num > 0 ? prefix + num.toLocaleString('en-ZA') : '';
  return (
    <input
      {...rest}
      value={display}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onChange={(e) => onChange(e.target.value.replace(/[^\d]/g, ''))}
    />
  );
}
