// A toggle-button group, reproducing the legacy `.toggle-group > .toggle-btn`
// markup + `.active` state so the existing CSS applies unchanged.
export default function Toggle({ value, onChange, options, ariaPrefix }) {
  return (
    <div className="toggle-group">
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          className={'toggle-btn' + (value === o.value ? ' active' : '')}
          aria-label={`${ariaPrefix || ''} ${o.label}`.trim()}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// Yes/No convenience: maps the tri-state boolean answer <-> 'yes'/'no'.
export function YesNo({ answer, onAnswer, ariaPrefix }) {
  const value = answer === true ? 'yes' : answer === false ? 'no' : undefined;
  return (
    <Toggle
      value={value}
      ariaPrefix={ariaPrefix}
      onChange={(v) => onAnswer(v === 'yes')}
      options={[
        { value: 'yes', label: 'Y' },
        { value: 'no', label: 'N' },
      ]}
    />
  );
}
