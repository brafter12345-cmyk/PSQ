import type { ReactNode } from 'react'
import type { CategoryBase, Severity } from '../../types/results'
import { StatusBadge } from '../primitives/Status'
import { headerBadge, isConclusive, inconclusiveLabel, SEVERITY_COLOR } from '../../data/checkerState'
import styles from './parts.module.css'

/** Page heading with optional one-line subtitle. */
export function PageTitle({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className={styles.pageTitle}>
      <h2>{title}</h2>
      {subtitle && <p>{subtitle}</p>}
    </div>
  )
}

/** Loud "we did not look" note for an inconclusive checker.
 *
 *  A status badge alone is not enough where the panel also prints counts: a
 *  failed credential lookup yields 0 records, and "0 leaked records" reads as a
 *  clean estate to anyone skimming. Render this INSTEAD of the numbers, so the
 *  absence of findings can never be mistaken for a finding of absence. */
export function NotAssessedNote({ category, what, why: reason, force = false }:
  { category: CategoryBase | undefined; what: string; why?: string; force?: boolean }) {
  // force: a checker can be conclusive by status and still be no measurement -
  // a completed SPF walk stored before the outcome was recorded - and the panel
  // must not print its counts either (step-5 critique round 11, R11-SC-2).
  // reason: where the status is not the reason, the caller supplies it.
  if (!category || (!force && isConclusive(category))) return null
  // Forced, with no reason given, the status is not the reason: a completed
  // checker marked assessed: false would explain itself as "(passed)" under a
  // heading that says Not assessed (step-5 critique round 12, SC-NOTE-PASSED).
  const why = (reason
    || (force ? 'the checker recorded no measurement' : inconclusiveLabel(category.status as string))
  ).toLowerCase()
  return (
    <div style={{ fontSize: 11.5, lineHeight: 1.55, color: 'var(--text-secondary)',
      background: 'var(--panel-bg-elevated)', border: '1px solid var(--border-emphasis)',
      borderRadius: 8, padding: '9px 11px' }}>
      <b style={{ color: 'var(--text-primary)' }}>Not assessed.</b>{' '}
      {what} could not be searched for this scan ({why}), so exposure can be neither
      confirmed nor ruled out. This is <b>not</b> evidence of a clean record.
    </div>
  )
}

/** Status header for a checker that NEVER presents a stale score as a pass when
 *  the checker did not actually complete (spec §18/§33). */
export function CheckerHeader({ category, refine = false }: { category: CategoryBase | undefined; refine?: boolean }) {
  // refine: a generic panel reads a completed checker's own severity and
  // finding counts, never a bare "Passed" beside a finding (step-5 critique
  // round 7). The state and its reason come from one function the gate runs.
  const b = headerBadge(category, refine)
  return <StatusBadge state={b.state} label={b.label} />
}

/** Explain mixed-IP checker results next to the affected network surface. */
export function PartialCoverageNote({ category, label }: { category: CategoryBase | undefined; label: string }) {
  if (!category?.partial_coverage) return null
  const unassessed = Array.isArray(category.unassessed_ips) ? category.unassessed_ips : []
  const probes = category.incomplete_probes
  const validCount = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
  const counts = probes && !Array.isArray(probes) && typeof probes === 'object'
    ? Object.values(probes) : null
  const groups = counts && counts.length > 0 && counts.every(validCount)
    ? counts.filter((count) => count > 0).length : 0
  const probeCount = Array.isArray(probes) ? probes.length
    : validCount(probes) ? probes : 0
  const ips = unassessed
    .map((entry) => entry?.ip)
    .filter((ip): ip is string => typeof ip === 'string' && ip.length > 0)
  const scope = ips.length
    ? `Unassessed IPs: ${ips.join(', ')}`
    : groups
      ? `${groups} probe group${groups === 1 ? '' : 's'} did not complete.`
      : probeCount
        ? `${probeCount} probe${probeCount === 1 ? '' : 's'} did not complete.`
        : 'Some probes did not complete.'
  return (
    <div style={{ fontSize: 11.5, lineHeight: 1.5, color: 'var(--text-secondary)',
      background: 'var(--panel-bg-elevated)', border: '1px solid var(--border-emphasis)',
      borderRadius: 8, padding: '9px 11px', marginBottom: 12 }}>
      <b style={{ color: 'var(--text-primary)' }}>{label}: partial coverage.</b>{' '}
      An unavailable IP or probe cannot be treated as clean. {scope}
    </div>
  )
}

/** Render a checker's numeric score ONLY when the checker is conclusive. */
export function ScoreLine({ category, max = 100 }: { category: CategoryBase | undefined; max?: number }) {
  if (!category || typeof category.score !== 'number') return null
  if (!isConclusive(category)) {
    return <div className={styles.scoreMuted}>Score not applicable — checker did not complete</div>
  }
  const s = category.score
  const color = s >= 80 ? 'var(--positive)' : s >= 50 ? 'var(--warning)' : 'var(--high)'
  return (
    <div className={styles.scoreLine}>
      <span className={styles.scoreVal} style={{ color }}>{s}</span>
      <span className={styles.scoreMax}>/ {max}</span>
    </div>
  )
}

export interface KVRow { label: string; value: ReactNode; severity?: Severity }
export function KV({ rows }: { rows: KVRow[] }) {
  return (
    <dl className={styles.kv}>
      {rows.map((r, i) => (
        <div key={i}>
          <dt>{r.label}</dt>
          <dd style={r.severity ? { color: SEVERITY_COLOR[r.severity] } : undefined}>{r.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

/** A pass/warn/fail check line (SPF present, HSTS, etc.). */
export function CheckLine({ label, state, value }: { label: string; state: 'pass' | 'warn' | 'fail' | 'neutral'; value?: ReactNode }) {
  const color = state === 'pass' ? 'var(--positive)' : state === 'warn' ? 'var(--warning)' : state === 'fail' ? 'var(--high)' : 'var(--unknown)'
  return (
    <div className={styles.checkLine}>
      <span className={styles.checkDot} style={{ background: color }} aria-hidden />
      <span className={styles.checkLabel}>{label}</span>
      <span className={styles.checkVal} style={{ color }}>{value}</span>
    </div>
  )
}

export function IssueList({ issues }: { issues?: Array<string | { message?: string }> }) {
  if (!issues || issues.length === 0) return null
  return (
    <ul className={styles.issues}>
      {issues.map((it, i) => <li key={i}>{typeof it === 'string' ? it : it.message ?? JSON.stringify(it)}</li>)}
    </ul>
  )
}

export function StatGrid({ stats }: { stats: Array<{ label: string; value: ReactNode; severity?: Severity }> }) {
  return (
    <div className={styles.statGrid}>
      {stats.map((s, i) => (
        <div className={styles.stat} key={i}>
          <span className={styles.statVal} style={s.severity ? { color: SEVERITY_COLOR[s.severity] } : undefined}>{s.value}</span>
          <span className={styles.statLabel}>{s.label}</span>
        </div>
      ))}
    </div>
  )
}

/** Two/three-column responsive grid for detail panels. */
export function DetailGrid({ children, cols = 2 }: { children: ReactNode; cols?: 2 | 3 }) {
  return <div className={cols === 3 ? styles.grid3 : styles.grid2}>{children}</div>
}
