// ---------------------------------------------------------------------------
// Base access to the server-injected RESULTS payload + shared formatters.
// Every component reads data through selectors (see selectors.ts), never by
// reaching into window.RESULTS directly.
// ---------------------------------------------------------------------------
import type { Results } from '../types/results'

export function getResults(): Results | null {
  return window.RESULTS ?? null
}

export interface ScanMeta {
  status: 'completed' | 'pending' | 'failed'
  domain: string
  scanId: string
  error?: string
}

export function getScanMeta(): ScanMeta {
  const m = window.SCAN_META
  return {
    status: (m?.status as ScanMeta['status']) ?? 'pending',
    domain: m?.domain ?? window.RESULTS?.domain_scanned ?? '',
    scanId: m?.scanId ?? '',
    error: m?.error,
  }
}

// --- numeric / currency / date formatting (tabular numerals in CSS) ---------

const ZAR = new Intl.NumberFormat('en-ZA', { maximumFractionDigits: 0 })

/** Rand value, compacted for large magnitudes (R 2.1bn, R 1.2M, R 493k). */
export function fmtZar(value: number | null | undefined, opts: { compact?: boolean } = {}): string {
  if (value == null || Number.isNaN(value)) return '—'
  const compact = opts.compact ?? true
  const abs = Math.abs(value)
  // Keep ONE significant decimal across the whole M / bn range so related
  // figures reconcile on screen: an expected R82.1M less a R29.6M saving reads
  // as R52.5M (29.6 + 52.5 = 82.1). Rounding each to whole millions instead
  // (the old ">= R10M → 0dp") showed R82M / R30M / R53M, i.e. 30 + 53 = 83 != 82.
  // Trailing ".0" is trimmed so round values stay clean (R87M, not R87.0M).
  const trim1 = (n: number) => n.toFixed(1).replace(/\.0$/, '')
  if (compact && abs >= 1_000_000_000) return `R ${trim1(value / 1_000_000_000)}bn`
  if (compact && abs >= 1_000_000) return `R ${trim1(value / 1_000_000)}M`
  if (compact && abs >= 10_000) return `R ${Math.round(value / 1000)}k`
  return `R ${ZAR.format(Math.round(value))}`
}

export function fmtNum(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return '—'
  return value.toLocaleString('en-ZA', { minimumFractionDigits: digits, maximumFractionDigits: digits })
}

export function fmtPct(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return '—'
  return `${value.toFixed(digits)}%`
}

/** 0..1 ratio → percentage string. */
export function fmtRatioPct(value: number | null | undefined, digits = 0): string {
  if (value == null || Number.isNaN(value)) return '—'
  return `${(value * 100).toFixed(digits)}%`
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleDateString('en-ZA', { day: '2-digit', month: 'short', year: 'numeric' })
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('en-ZA', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

/** "3 days ago" / "in 2 months" style relative label. */
export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const diff = d.getTime() - Date.now()
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 31_536_000_000], ['month', 2_592_000_000], ['day', 86_400_000],
    ['hour', 3_600_000], ['minute', 60_000],
  ]
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === 'minute') return rtf.format(Math.round(diff / ms), unit)
  }
  return 'just now'
}

// --- risk banding -----------------------------------------------------------

export type RiskBandKey = 'low' | 'medium' | 'high' | 'critical'

export interface RiskBand {
  key: RiskBandKey
  label: string
  /** css colour variable name, e.g. 'var(--warning)' */
  color: string
}

const BANDS: Record<RiskBandKey, RiskBand> = {
  low: { key: 'low', label: 'Low Risk', color: 'var(--positive)' },
  medium: { key: 'medium', label: 'Medium Risk', color: 'var(--warning)' },
  high: { key: 'high', label: 'High Risk', color: 'var(--high)' },
  critical: { key: 'critical', label: 'Critical Risk', color: 'var(--critical)' },
}

/**
 * Map an overall risk score (0..max, default 1000) to a band. Thresholds match
 * the scanner's own Low/Medium/High/Critical labelling: <250 Low, <500 Medium,
 * <750 High, else Critical. Prefer the backend `risk_level` when present
 * (riskBandFromLabel) and only fall back to this for colour banding.
 */
export function riskBandFromScore(score: number, max = 1000): RiskBand {
  const pct = (score / max) * 1000
  if (pct < 250) return BANDS.low
  if (pct < 500) return BANDS.medium
  if (pct < 750) return BANDS.high
  return BANDS.critical
}

export function riskBandFromLabel(label: string | null | undefined): RiskBand {
  const l = (label ?? '').toLowerCase()
  if (l.startsWith('crit')) return BANDS.critical
  if (l.startsWith('high')) return BANDS.high
  if (l.startsWith('med')) return BANDS.medium
  if (l.startsWith('low')) return BANDS.low
  return BANDS.medium
}
