import { useEffect, useRef, useState } from 'react'
import { ShieldHalf, Server, Globe, CheckCircle2, Loader2, AlertTriangle } from 'lucide-react'
import styles from './ScanProgress.module.css'
import { withBase } from '../../base'

type Status = 'pending' | 'running' | 'done'
interface CheckerDef { id: string; label: string; per_ip?: boolean }
interface SectionDef { section: string; checkers: CheckerDef[] }

// Manifest sections → display phases (spec §29), plus trailing post-scan phases.
const TRAILING_PHASES = ['Insurance Analytics', 'Report Generation']

export default function ScanProgress({ scanId, domain }: { scanId: string; domain: string }) {
  const manifest: SectionDef[] = (window.CHECKER_MANIFEST as SectionDef[]) ?? []
  const [states, setStates] = useState<Record<string, { status: Status; score?: number }>>({})
  const [current, setCurrent] = useState<string>('')
  const [ips, setIps] = useState<string[]>([])
  const [subIps, setSubIps] = useState<string[]>([])
  const [elapsed, setElapsed] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const startRef = useRef<number | null>(null)

  const total = manifest.reduce((n, s) => n + s.checkers.length, 0)
  const done = Object.values(states).filter((s) => s.status === 'done').length
  const pct = total ? Math.round((done / total) * 100) : 0

  // section index of the active checker → current phase
  const sectionOf = (id: string) => manifest.find((s) => s.checkers.some((c) => c.id === id.split(':')[0]))?.section
  const currentPhase = current ? sectionOf(current) ?? 'Discovery' : 'Discovery'

  useEffect(() => {
    // elapsed timer (Date.now is fine in the browser)
    const t = setInterval(() => {
      if (startRef.current == null) startRef.current = Date.now()
      setElapsed(Math.floor((Date.now() - startRef.current) / 1000))
    }, 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    let es: EventSource | null = null
    let poll: ReturnType<typeof setInterval> | null = null
    const reloadToResults = () => window.location.reload()

    const startPolling = () => {
      if (poll) return
      poll = setInterval(async () => {
        try {
          const res = await fetch(withBase(`/api/scan/${scanId}`))
          if (res.status === 200) { const d = await res.json(); if (d.status !== 'pending') reloadToResults() }
          else if (res.status === 500) { const d = await res.json(); setError(d.error || 'Scan failed') }
        } catch { /* keep polling */ }
      }, 4000)
    }

    try {
      es = new EventSource(withBase(`/api/scan/${scanId}/progress`))
      es.onmessage = (e) => {
        const data = JSON.parse(e.data)
        if (data.type === 'complete') { es?.close(); setTimeout(reloadToResults, 900); return }
        if (data.type === 'error') { es?.close(); setError(data.message || 'Scan failed'); return }
        if (data.type === 'idle') { es?.close(); startPolling(); return }
        const checker: string = data.checker
        const status: Status = data.status
        if (!checker) return
        if (status === 'running') setCurrent(checker)
        if (checker === 'ip_discovery' && status === 'done' && data.ips?.length) setIps(data.ips)
        if (checker === 'subdomain_ips' && status === 'done' && data.ips?.length) setSubIps(data.ips)
        setStates((prev) => ({ ...prev, [checker.split(':')[0]]: { status, score: data.score } }))
      }
      es.onerror = () => { es?.close(); startPolling() }
    } catch { startPolling() }

    return () => { es?.close(); if (poll) clearInterval(poll) }
  }, [scanId])

  const eta = done > 0 && elapsed > 0 ? Math.max(0, Math.round((elapsed / done) * (total - done))) : null
  const fmtT = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
  const phases = [...manifest.map((s) => s.section), ...TRAILING_PHASES]
  const activePhaseIdx = phases.indexOf(currentPhase)

  if (error) {
    return (
      <div className={styles.wrap}>
        <div className={styles.card}>
          <span className={`${styles.logo} ${styles.logoErr}`}><AlertTriangle size={24} /></span>
          <h1>Assessment failed</h1>
          <p className={styles.sub}>{error}</p>
          <a className={styles.retry} href="/">Start a new assessment</a>
        </div>
      </div>
    )
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.panel}>
        <header className={styles.head}>
          <span className={styles.logo}><ShieldHalf size={22} /></span>
          <div className={styles.headText}>
            <span className={styles.brand}>PHISHIELD CyberRisk Assessment</span>
            <span className={styles.dom}><Globe size={12} /> {domain}</span>
          </div>
          <span className={styles.live}><span className={styles.liveDot} /> Scanning</span>
        </header>

        <div className={styles.hero}>
          <Ring pct={pct} />
          <div className={styles.heroInfo}>
            <div className={styles.heroCount}>{done} <span>/ {total} checks</span></div>
            <div className={styles.heroPhase}>
              <Loader2 size={13} className={styles.spin} />
              {currentPhase}{current ? ` · ${current.split(':')[0].replace(/_/g, ' ')}` : ''}
            </div>
            <div className={styles.heroMeta}>
              <span>Elapsed {fmtT(elapsed)}</span>
              {eta != null && <span>· ~{fmtT(eta)} remaining</span>}
            </div>
          </div>
        </div>

        <div className={styles.phases}>
          {phases.map((p, i) => (
            <span key={p} className={`${styles.phase} ${i < activePhaseIdx ? styles.phaseDone : i === activePhaseIdx ? styles.phaseActive : ''}`}>{p}</span>
          ))}
        </div>

        {(ips.length > 0 || subIps.length > 0) && (
          <div className={styles.assets}>
            <span className={styles.assetsLabel}><Server size={13} /> Discovered assets</span>
            <div className={styles.chips}>
              {ips.map((ip) => <span key={ip} className={styles.chip}>{ip}</span>)}
              {subIps.map((ip) => <span key={`s${ip}`} className={`${styles.chip} ${styles.chipSub}`}>{ip}</span>)}
            </div>
          </div>
        )}

        <div className={styles.sections}>
          {manifest.map((s) => (
            <div className={styles.section} key={s.section}>
              <div className={styles.sectionTitle}>{s.section}</div>
              <ul className={styles.checklist}>
                {s.checkers.map((c) => {
                  const st = states[c.id]?.status ?? 'pending'
                  return (
                    <li key={c.id} className={styles.item}>
                      <span className={styles.icon}>
                        {st === 'done' ? <CheckCircle2 size={14} className={styles.ok} />
                          : st === 'running' ? <Loader2 size={13} className={styles.spin} />
                          : <span className={styles.dot} />}
                      </span>
                      <span className={`${styles.label} ${st === 'pending' ? styles.labelPending : ''}`}>{c.label}</span>
                      {states[c.id]?.score != null && <span className={styles.score}>{states[c.id]?.score}</span>}
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Ring({ pct }: { pct: number }) {
  const r = 34, c = 2 * Math.PI * r
  return (
    <svg width={84} height={84} viewBox="0 0 84 84" className={styles.ring}>
      <circle cx={42} cy={42} r={r} fill="none" stroke="var(--border)" strokeWidth={7} />
      <circle cx={42} cy={42} r={r} fill="none" stroke="var(--accent-bright)" strokeWidth={7}
        strokeLinecap="round" strokeDasharray={`${(c * pct) / 100} ${c}`} transform="rotate(-90 42 42)"
        style={{ transition: 'stroke-dasharray .5s ease' }} />
      <text x="42" y="47" textAnchor="middle" className={styles.ringText}>{pct}%</text>
    </svg>
  )
}
