import type { ReactNode } from 'react'
import {
  CheckCircle2, AlertTriangle, XCircle, ShieldAlert, CircleHelp,
  MinusCircle, Clock, Lock, CircleDot,
} from 'lucide-react'
import type { CheckerState, Severity } from '../../types/results'
import {
  SEVERITY_COLOR, SEVERITY_SOFT, SEVERITY_LABEL, STATE_META,
} from '../../data/checkerState'
import styles from './Status.module.css'

const SEV_ICON: Record<Severity, typeof CheckCircle2> = {
  critical: ShieldAlert,
  high: AlertTriangle,
  medium: AlertTriangle,
  low: CircleDot,
  info: CircleDot,
  positive: CheckCircle2,
  unknown: CircleHelp,
}

const STATE_ICON: Partial<Record<CheckerState, typeof CheckCircle2>> = {
  passed: CheckCircle2,
  completed: CircleDot,
  warning: AlertTriangle,
  failed: XCircle,
  critical: ShieldAlert,
  blocked: Lock,
  error: XCircle,
  not_assessed: CircleHelp,
  no_data: MinusCircle,
  not_applicable: MinusCircle,
  subscription_required: Lock,
  rate_limited: Clock,
  skipped: MinusCircle,
}

/** Small coloured dot — pair with text, never the only signal. */
export function SeverityDot({ severity, size = 8 }: { severity: Severity; size?: number }) {
  return (
    <span
      className={styles.dot}
      style={{ background: SEVERITY_COLOR[severity], width: size, height: size }}
      aria-hidden
    />
  )
}

/** Pill carrying severity colour + icon + label. */
export function SeverityBadge({ severity, label }: { severity: Severity; label?: string }) {
  const Icon = SEV_ICON[severity]
  return (
    <span
      className={styles.badge}
      style={{ color: SEVERITY_COLOR[severity], background: SEVERITY_SOFT[severity] }}
    >
      <Icon size={12} strokeWidth={2.25} aria-hidden />
      {label ?? SEVERITY_LABEL[severity]}
    </span>
  )
}

/** Pill carrying a normalised checker state (passed/blocked/not_assessed/…). */
export function StatusBadge({ state, label }: { state: CheckerState; label?: string }) {
  const meta = STATE_META[state]
  const Icon = STATE_ICON[state] ?? CircleHelp
  return (
    <span
      className={styles.badge}
      style={{ color: SEVERITY_COLOR[meta.severity], background: SEVERITY_SOFT[meta.severity] }}
    >
      <Icon size={12} strokeWidth={2.25} aria-hidden />
      {label ?? meta.label}
    </span>
  )
}

/** Generic neutral pill. */
export function Pill({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'accent' }) {
  return <span className={tone === 'accent' ? styles.pillAccent : styles.pill}>{children}</span>
}
