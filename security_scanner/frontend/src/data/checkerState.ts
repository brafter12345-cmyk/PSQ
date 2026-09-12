// ---------------------------------------------------------------------------
// Checker-state normalisation — the correctness backbone of the redesign.
//
// Rules enforced (spec §7, §22, §28, §33):
//   * A checker that did not complete (blocked / error / no_data / no API key /
//     subscription_required / rate_limited / skipped) NEVER renders green and
//     NEVER renders as a "pass".
//   * "passed" is only ever derived by a checker that actually completed with
//     genuinely passing semantics — decided per-metric in selectors, not from
//     score===100 or an empty issues list alone.
// ---------------------------------------------------------------------------
import type { CategoryBase, CheckerState, Severity } from '../types/results'

export interface StateMeta {
  /** human label for the state */
  label: string
  /** severity drives colour + icon */
  severity: Severity
  /** true when the checker produced a real verdict (pass/fail/etc.) */
  conclusive: boolean
}

export const STATE_META: Record<CheckerState, StateMeta> = {
  passed: { label: 'Passed', severity: 'positive', conclusive: true },
  // Ran to the end, with no verdict the panel can read: never a pass.
  completed: { label: 'Completed', severity: 'unknown', conclusive: true },
  warning: { label: 'Warning', severity: 'medium', conclusive: true },
  failed: { label: 'Failed', severity: 'high', conclusive: true },
  critical: { label: 'Critical', severity: 'critical', conclusive: true },
  blocked: { label: 'Blocked', severity: 'medium', conclusive: false },
  error: { label: 'Checker error', severity: 'unknown', conclusive: false },
  not_assessed: { label: 'Not assessed', severity: 'unknown', conclusive: false },
  no_data: { label: 'No data', severity: 'unknown', conclusive: false },
  not_applicable: { label: 'Not applicable', severity: 'unknown', conclusive: false },
  subscription_required: { label: 'Subscription required', severity: 'unknown', conclusive: false },
  rate_limited: { label: 'Rate limited', severity: 'unknown', conclusive: false },
  skipped: { label: 'Skipped', severity: 'unknown', conclusive: false },
}

// Raw scanner `status` strings → canonical CheckerState. Anything that means
// "the checker ran and produced findings" maps to 'passed' as a NEUTRAL run
// marker; callers then refine to warning/failed/critical from the actual
// findings. Anything inconclusive keeps its own non-green state.
const RAW_STATE_MAP: Record<string, CheckerState> = {
  completed: 'passed',
  complete: 'passed',
  ok: 'passed',
  success: 'passed',
  done: 'passed',
  passed: 'passed',
  pass: 'passed',

  warning: 'warning',
  warn: 'warning',

  failed: 'failed',
  fail: 'failed',
  failure: 'failed',

  critical: 'critical',

  blocked: 'blocked',
  waf_blocked: 'blocked',
  forbidden: 'blocked',

  error: 'error',
  exception: 'error',
  timeout: 'error',
  timed_out: 'error',

  no_api_key: 'not_assessed',
  no_key: 'not_assessed',
  missing_api_key: 'not_assessed',
  unreachable: 'not_assessed',
  not_assessed: 'not_assessed',
  unknown: 'not_assessed',

  no_data: 'no_data',
  empty: 'no_data',
  none: 'no_data',

  not_applicable: 'not_applicable',
  na: 'not_applicable',
  'n/a': 'not_applicable',

  subscription_required: 'subscription_required',
  requires_subscription: 'subscription_required',
  paid: 'subscription_required',

  rate_limited: 'rate_limited',
  ratelimited: 'rate_limited',
  throttled: 'rate_limited',
  // The provider refused on usage grounds: credits spent or allowance hit. Same
  // class as rate_limited (non-conclusive, never green). Unmapped statuses
  // already fall back to not_assessed, so this is about giving the operator a
  // precise label rather than about safety.
  quota_exhausted: 'rate_limited',
  quota_exceeded: 'rate_limited',
  credits_exhausted: 'rate_limited',

  skipped: 'skipped',
  skip: 'skipped',
  disabled: 'skipped',
}

export function normalizeState(raw: string | null | undefined): CheckerState {
  if (!raw) return 'not_assessed'
  return RAW_STATE_MAP[String(raw).toLowerCase().trim()] ?? 'not_assessed'
}

/** Did a checker actually run to a verdict? false for blocked/error/no-data/etc. */
export function isConclusive(category: CategoryBase | undefined): boolean {
  return STATE_META[normalizeState(category?.status)].conclusive
}

/** The state of a generic panel for a checker with no selector of its own.
 *  A completed checker's own severity, or its finding counts, give its finding
 *  level; otherwise the panel says only that it completed, never "Passed",
 *  because its findings may sit in fields a generic panel does not read (step-5
 *  critique rounds 7 and 8). A result marked assessed: false was not assessed,
 *  and anything that did not complete keeps its own state. */
export function refineCompletedState(category: CategoryBase | undefined): CheckerState {
  const state = normalizeState(category?.status)
  if (state !== 'passed' || !category) return state
  const c = category as unknown as Record<string, unknown>
  if (c.assessed === false) return 'not_assessed'
  const sev = String(c.severity ?? '').toLowerCase()
  const n = (...keys: string[]) => keys.reduce((t, k) => t + (Number(c[k] ?? 0) || 0), 0)
  if (sev === 'critical' || n('critical_count', 'critical_match_count') > 0) return 'critical'
  if (sev === 'high' || n('high_count', 'high_match_count') > 0) return 'failed'
  if (sev === 'medium' || n('medium_count') > 0) return 'warning'
  return 'completed'
}

/** The badge a checker's panel header shows: its state, and the reason where
 *  the checker did not complete. One function, so the regression gate runs the
 *  real thing under node on real checker output rather than reading a line of
 *  the page (step-5 critique rounds 7 to 9).
 *
 *  The email-vendor surface (S-4) and the vendor-breach correlation (S-5) carry
 *  their own rule: the surface is a measurement only where the SPF lookup is
 *  recorded as answered, a result stored before that field existed cannot show
 *  it, and a walk that found a vendor beside a lookup that did not answer read
 *  only part of the chain. */
export function headerBadge(category: CategoryBase | undefined,
                            refine = false): { state: CheckerState; label?: string } {
  if (!category) return { state: 'not_assessed', label: 'Not in scan' }
  const c = category as unknown as Record<string, unknown>
  if ('vendors_detected' in c) {
    const how = c.spf_lookup
    const none = !((c.vendors_detected as unknown[]) ?? []).length && !c.vendor_count
    if (c.status === 'no_data') {
      return how === 'answered'
        ? { state: 'completed' }
        : { state: 'not_assessed', label: 'Not assessed' }
    }
    if (c.status === 'completed' && how === undefined && none) {
      return { state: 'not_assessed', label: 'Not assessed' }
    }
    if (c.status === 'completed' && how !== undefined && how !== 'answered'
        && how !== 'partial') {
      // An outcome this rule does not know is not a measurement.
      return { state: 'not_assessed', label: 'Not assessed' }
    }
    // A result stored before the outcome was recorded that still named a vendor
    // is the shape a partly read chain writes (step-5 critique round 10).
    if (c.status === 'completed' && (how === 'partial' || how === undefined)) {
      const refined = refineCompletedState(category)
      return refined === 'completed'
        ? { state: 'warning', label: 'Partly assessed' }
        : { state: refined }
    }
  }
  const state = refine ? refineCompletedState(category) : normalizeState(category.status)
  const label = isConclusive(category) ? undefined : inconclusiveLabel(category.status as string)
  return { state, label }
}

/** Friendlier label for inconclusive states, with the no-API-key nuance. */
/** May a generic panel print this checker's counts?
 *
 *  A result the badge calls not assessed has no counts to print: "match count =
 *  0" over an SPF chain nobody read is the absence of findings dressed as a
 *  finding of absence, and the broker skimming the panel reads a clean vendor
 *  estate off three zeros (step-5 critique round 11, R11-SC-2). */
export function panelShowsCounts(category: CategoryBase | undefined): boolean {
  return headerBadge(category, true).state !== 'not_assessed'
}

export function inconclusiveLabel(raw: string | null | undefined): string {
  const r = String(raw ?? '').toLowerCase().trim()
  if (r === 'no_api_key' || r === 'no_key' || r === 'missing_api_key') return 'No API key'
  if (r === 'unreachable') return 'Unreachable'
  if (r === 'quota_exhausted' || r === 'quota_exceeded' || r === 'credits_exhausted') {
    return 'Search quota exhausted'
  }
  return STATE_META[normalizeState(raw)].label
}

// --- severity → presentation (colour var + short code) ----------------------

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--info)',
  positive: 'var(--positive)',
  unknown: 'var(--unknown)',
}

export const SEVERITY_SOFT: Record<Severity, string> = {
  critical: 'var(--critical-soft)',
  high: 'var(--high-soft)',
  medium: 'var(--warning-soft)',
  low: 'var(--info-soft)',
  info: 'var(--info-soft)',
  positive: 'var(--positive-soft)',
  unknown: 'var(--unknown-soft)',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  positive: 'Positive',
  unknown: 'Unknown',
}

/** Normalise an arbitrary severity-ish string from the payload. */
export function normalizeSeverity(raw: string | null | undefined): Severity {
  const r = String(raw ?? '').toLowerCase().trim()
  if (r === 'critical' || r === 'crit') return 'critical'
  if (r === 'high') return 'high'
  if (r === 'medium' || r === 'med' || r === 'moderate' || r === 'warning') return 'medium'
  if (r === 'low') return 'low'
  if (r === 'info' || r === 'informational') return 'info'
  if (r === 'positive' || r === 'good' || r === 'pass') return 'positive'
  return 'unknown'
}

export function severityRank(sev: Severity): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1, positive: 0, unknown: 1 }[sev]
}
