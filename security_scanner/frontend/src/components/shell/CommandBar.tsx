import { useState, useRef, useEffect } from 'react'
import {
  ChevronDown, Download, Share2, RefreshCw, CheckCircle2, FileText,
  Presentation, FileCode2, Braces, GitCompareArrows,
} from 'lucide-react'
import { getScanMeta, getResults, fmtDateTime } from '../../data/results'
import { getCoverageSummary } from '../../data/selectors'
import styles from './CommandBar.module.css'
import { withBase } from '../../base'

const EXPORTS: Array<{ label: string; type: string; icon: typeof FileText; raw?: boolean }> = [
  { label: 'Broker Summary', type: 'summary', icon: FileText },
  { label: 'Executive Summary Deck', type: 'assessment', icon: Presentation },
  { label: 'Full Technical Report', type: 'full', icon: FileCode2 },
  { label: 'Export Raw Data', type: 'raw', icon: Braces, raw: true },
]

export default function CommandBar() {
  const meta = getScanMeta()
  const r = getResults()
  const cov = getCoverageSummary(r)
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  const share = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch { /* clipboard unavailable */ }
  }

  const covPct = cov.coveragePct
  return (
    <header className={styles.bar}>
      <div className={styles.left}>
        <h1 className={styles.pageTitle}>CyberRisk Assessment</h1>
        <span className={styles.domain}>{meta.domain}</span>
        <span className={styles.statusGroup}>
          {meta.status === 'completed' && (
            <span className={styles.completed}><CheckCircle2 size={13} /> Completed</span>
          )}
          <span className={styles.scanned}>Scanned {fmtDateTime(r?.scan_timestamp)}</span>
        </span>
      </div>

      <div className={styles.right}>
        {covPct != null && (
          <div className={styles.coverage} title="Assessable scan coverage">
            <span className={styles.covLabel}>Coverage</span>
            <span className={styles.covValue}>{covPct}%</span>
            <span className={styles.covTrack}>
              <span className={styles.covFill} style={{ width: `${covPct}%`,
                background: covPct >= 95 ? 'var(--positive)' : 'var(--warning)' }} />
            </span>
          </div>
        )}

        <button className={styles.compare} type="button" title="Comparison requires a previous scan">
          <GitCompareArrows size={14} /> vs Previous scan <ChevronDown size={13} />
        </button>

        <div className={styles.exportWrap} ref={menuRef}>
          <button className={styles.btn} type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="menu">
            <Download size={14} /> Export Report <ChevronDown size={13} />
          </button>
          {open && (
            <div className={styles.menu} role="menu">
              {EXPORTS.map((e) => {
                const Icon = e.icon
                const href = withBase(e.raw ? `/api/scan/${meta.scanId}` : `/api/scan/${meta.scanId}/pdf?type=${e.type}`)
                return (
                  <a key={e.type} className={styles.menuItem} href={href} target="_blank" rel="noreferrer" role="menuitem" onClick={() => setOpen(false)}>
                    <Icon size={14} /> {e.label}
                  </a>
                )
              })}
            </div>
          )}
        </div>

        <button className={styles.btn} type="button" onClick={share}>
          <Share2 size={14} /> {copied ? 'Link copied' : 'Share'}
        </button>

        <a className={styles.primary} href="/" title="Start a new assessment for this domain">
          <RefreshCw size={14} /> Re-run Assessment
        </a>
      </div>
    </header>
  )
}
