import { useEffect, useMemo, useRef, useState } from 'react';
import { INDUSTRIES } from '../rating-data.js';

// Group-header labels, verbatim from the legacy `mainToLabel`.
const mainToLabel = {
  'Agriculture, Forestry, And Fishing': 'Agriculture',
  'Mining': 'Mining',
  'Construction': 'Construction',
  'Manufacturing': 'Manufacturing',
  'Transportation, Communications, Electric, Gas And Sanitary Services': 'Transportation',
  'Wholesale Trade': 'Wholesale Trade',
  'Retail Trade': 'Retail Trade',
  'Finance, Insurance, And Real Estate': 'Finance / Insurance / Real Estate',
  'Services': 'Services',
  'Healthcare': 'Healthcare',
  'Public Administration': 'Public Administration',
};

// Searchable industry dropdown — reproduces the legacy markup/classes
// (.searchable-select / .searchable-dropdown.open / .dropdown-group-label /
// .dropdown-option.highlighted/.selected) so the existing CSS applies.
export default function IndustrySelect({ value, onSelect }) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(-1);
  const wrapRef = useRef(null);

  // Keep the input text in sync when an industry is chosen externally.
  useEffect(() => {
    if (value >= 0 && INDUSTRIES[value]) setQuery(INDUSTRIES[value].sub);
  }, [value]);

  // Flattened, grouped, filtered option list.
  const groups = useMemo(() => {
    const q = query.toLowerCase().trim();
    const bySelected = value >= 0 && INDUSTRIES[value] && INDUSTRIES[value].sub === query;
    const out = [];
    const seen = {};
    INDUSTRIES.forEach((ind, idx) => {
      const label = mainToLabel[ind.main] || ind.main;
      const matches = !q || bySelected
        || ind.sub.toLowerCase().includes(q)
        || ind.main.toLowerCase().includes(q)
        || label.toLowerCase().includes(q);
      if (!matches) return;
      if (!seen[label]) { seen[label] = []; out.push({ label, items: seen[label] }); }
      seen[label].push({ idx, sub: ind.sub, refer: ind.referForUW });
    });
    return out;
  }, [query, value]);

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  useEffect(() => {
    function onDocClick(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('click', onDocClick);
    return () => document.removeEventListener('click', onDocClick);
  }, []);

  function choose(idx) {
    onSelect(idx);
    setQuery(INDUSTRIES[idx].sub);
    setOpen(false);
    setHighlight(-1);
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') { setOpen(false); e.currentTarget.blur(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setOpen(true); setHighlight((h) => Math.min(h + 1, flat.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHighlight((h) => Math.max(h - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); if (flat[highlight]) choose(flat[highlight].idx); }
  }

  return (
    <div className="searchable-select" id="industry-wrapper" ref={wrapRef}>
      <input
        type="text"
        className="form-input"
        id="industry-search"
        placeholder="Search or select industry..."
        autoComplete="off"
        aria-label="Search industry"
        value={query}
        onFocus={() => setOpen(true)}
        onClick={() => setOpen(true)}
        onChange={(e) => { setQuery(e.target.value); setOpen(true); setHighlight(-1); }}
        onKeyDown={onKeyDown}
      />
      <div className="searchable-select-arrow">&#9662;</div>
      <div className={'searchable-dropdown' + (open ? ' open' : '')} id="industry-dropdown">
        {groups.length === 0 && (
          <div className="dropdown-no-results">{`No industries matching "${query}"`}</div>
        )}
        {groups.map((g) => (
          <div key={g.label}>
            <div className="dropdown-group-label">{g.label}</div>
            {g.items.map((it) => {
              const hi = flat[highlight] && flat[highlight].idx === it.idx;
              return (
                <div
                  key={it.idx}
                  className={'dropdown-option' + (hi ? ' highlighted' : '') + (value === it.idx ? ' selected' : '')}
                  onMouseEnter={() => setHighlight(flat.findIndex((f) => f.idx === it.idx))}
                  onClick={() => choose(it.idx)}
                >
                  {it.sub}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}
