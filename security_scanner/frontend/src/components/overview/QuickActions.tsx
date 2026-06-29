import { useNavigate } from 'react-router-dom'
import {
  Download, Share2, ListChecks, CalendarClock, GitCompareArrows, Table2, RefreshCw, ChevronRight,
} from 'lucide-react'
import Panel from '../primitives/Panel'
import { getScanMeta } from '../../data/results'
import styles from './QuickActions.module.css'
import { withBase } from '../../base'

interface Action {
  label: string
  value: string
  icon: typeof Download
  href?: string
  to?: string
  onClick?: () => void
  disabled?: boolean
  tip?: string
}

export default function QuickActions() {
  const { scanId } = getScanMeta()
  const navigate = useNavigate()

  const share = async () => {
    try { await navigator.clipboard.writeText(window.location.href) } catch { /* noop */ }
  }

  const actions: Action[] = [
    { label: 'Download Full Report', value: 'PDF', icon: Download, href: withBase(`/api/scan/${scanId}/pdf?type=full`) },
    { label: 'Share Executive Summary', value: 'Secure link', icon: Share2, onClick: share },
    { label: 'Create Remediation Plan', value: 'Start now', icon: ListChecks, to: '/remediation' },
    { label: 'Schedule Continuous Scan', value: 'Daily', icon: CalendarClock, disabled: true, tip: 'Continuous scanning is not enabled for this account.' },
    { label: 'Compare With Previous Scan', value: 'View changes', icon: GitCompareArrows, disabled: true, tip: 'Requires at least one previous scan of this domain.' },
    { label: 'Export Underwriting Data', value: 'CSV / JSON', icon: Table2, href: withBase(`/api/scan/${scanId}`) },
    { label: 'Re-run Assessment', value: 'New scan', icon: RefreshCw, href: withBase('/') },
  ]

  return (
    <Panel title="Quick Actions" fill flush>
      <ul className={styles.list}>
        {actions.map((a) => {
          const Icon = a.icon
          const inner = (
            <>
              <span className={styles.icon}><Icon size={15} /></span>
              <span className={styles.label}>{a.label}</span>
              <span className={styles.value}>{a.value}</span>
              {!a.disabled && <ChevronRight size={14} className={styles.chev} />}
            </>
          )
          if (a.disabled) {
            return <li key={a.label}><span className={`${styles.row} ${styles.disabled}`} title={a.tip} aria-disabled>{inner}</span></li>
          }
          if (a.href) {
            return <li key={a.label}><a className={styles.row} href={a.href} target={a.href.startsWith('/api') ? '_blank' : undefined} rel="noreferrer">{inner}</a></li>
          }
          return <li key={a.label}><button className={styles.row} type="button" onClick={a.onClick ?? (() => a.to && navigate(a.to))}>{inner}</button></li>
        })}
      </ul>
    </Panel>
  )
}
