import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { createPortal } from 'react-dom'
import { getResults, fmtDateTime, fmtDate } from '../../data/results'
import { cat, CATEGORY_LABELS, getCoverageSummary } from '../../data/selectors'
import type { VulnRecord } from '../../data/selectors'
import { normalizeState, isConclusive, inconclusiveLabel } from '../../data/checkerState'
import { StatusBadge, SeverityBadge } from '../primitives/Status'
import styles from './EvidenceDrawer.module.css'

export type DrawerTarget =
  | { kind: 'category' | 'coverage'; id: string }
  | { kind: 'cve'; cve: VulnRecord }
type Tab = 'overview' | 'evidence' | 'technical'

const MATURITY_LABEL: Record<string, string> = {
  weaponized: 'Weaponized — public exploit code in active use',
  poc_public: 'PoC public — proof-of-concept exploit available',
  theoretical: 'Theoretical — no known public exploit',
}

// Plain-language business meaning per checker (spec §26 "business meaning").
const MEANING: Record<string, string> = {
  high_risk_protocols: 'Internet-facing database, file-transfer or admin protocols give attackers a direct path to business data and are a leading driver of breach and ransomware claims.',
  ssl: 'TLS configuration determines whether traffic to the site is encrypted and trusted. Weak grades expose users to interception and erode trust signals.',
  http_headers: 'Security headers harden the browser against common web attacks. When the probe is blocked, the posture is simply unknown — not safe.',
  waf: 'A web application firewall filters malicious traffic. Its presence reduces exploitability; its absence increases it.',
  breaches: 'Historical breaches indicate prior compromise and credential exposure that raise the likelihood of account-takeover attacks.',
  dehashed: 'Leaked credentials in dark-web dumps enable credential-stuffing and targeted phishing against the organisation.',
  exposed_admin: 'Reachable admin or sensitive paths are high-value targets for unauthorised access and lateral movement.',
  website_security: 'HTTPS enforcement and cookie protections prevent downgrade and session-theft attacks.',
  email_security: 'SPF, DKIM and DMARC prevent attackers from spoofing the domain in phishing and business-email-compromise campaigns.',
}

function meaningFor(id: string): string | null {
  return MEANING[id] ?? null
}

function KVBlock({ rows }: { rows: Array<[string, unknown]> }) {
  if (!rows.length) return null
  return (
    <dl className={styles.kv}>
      {rows.map(([k, v]) => (
        <div key={k}><dt>{k.replace(/_/g, ' ')}</dt><dd>{String(v)}</dd></div>
      ))}
    </dl>
  )
}

function CoverageBody({ tab }: { tab: Tab }) {
  const cov = getCoverageSummary(getResults())
  if (tab === 'technical') {
    return <pre className={styles.raw}>{JSON.stringify(cov.probeCodes, null, 2)}</pre>
  }
  return (
    <div className={styles.section}>
      {tab === 'overview' && (
        <p className={styles.lead}>Protective infrastructure intervened during the scan. The absence of
          findings on the affected checks does not confirm an absence of risk — those checks could not be verified.</p>
      )}
      <KVBlock rows={[['Coverage', cov.coveragePct != null ? `${cov.coveragePct}%` : '—'], ['Intervention', cov.kind], ['Probes', cov.probeSummary], ['Affected checks', cov.affectedCount]]} />
      <div className={styles.subhead}>Affected checks (not assessed)</div>
      <ul className={styles.bullets}>{cov.affectedCheckers.map((c) => <li key={c}>{CATEGORY_LABELS[c] ?? c}</li>)}</ul>
    </div>
  )
}

function CategoryBody({ id, tab }: { id: string; tab: Tab }) {
  const c = cat(getResults(), id)
  if (!c) return <div className={styles.section}><p className={styles.lead}>No data for this checker in this scan.</p></div>
  const issues = (c.issues ?? []) as Array<string | { message?: string }>
  const scalars = Object.entries(c).filter(([k, v]) => !['issues', 'per_ip', 'status'].includes(k) && (typeof v !== 'object' || v === null))
  const nested = Object.entries(c).filter(([k, v]) => typeof v === 'object' && v !== null && k !== 'per_ip')
  const exposed = id === 'high_risk_protocols' ? (c.exposed_services as Array<Record<string, unknown>> | undefined) ?? [] : []

  if (tab === 'technical') {
    return <pre className={styles.raw}>{JSON.stringify(c, null, 2)}</pre>
  }
  if (tab === 'evidence') {
    return (
      <div className={styles.section}>
        {issues.length > 0 ? (
          <>
            <div className={styles.subhead}>Issues &amp; findings</div>
            <ul className={styles.bullets}>{issues.map((it, i) => <li key={i}>{typeof it === 'string' ? it : it.message ?? JSON.stringify(it)}</li>)}</ul>
          </>
        ) : <p className={styles.lead}>No discrete findings recorded.</p>}
        {exposed.map((s, i) => (
          <div key={i} className={styles.exposed}>
            <div className={styles.exposedHead}>{String(s.service)} · port {String(s.port)}</div>
            {!!s.notable_cves && <div className={styles.cves}>{(s.notable_cves as string[]).map((cve) => <span key={cve} className={styles.cve}>{cve}</span>)}</div>}
            {!!s.vuln_metrics && <div className={styles.meta}>{String(s.vuln_metrics)}</div>}
            {!!s.underwriting_impact && <div className={styles.uw}><b>Underwriting:</b> {String(s.underwriting_impact)}</div>}
          </div>
        ))}
      </div>
    )
  }
  // overview
  const meaning = meaningFor(id)
  return (
    <div className={styles.section}>
      {meaning && <p className={styles.lead}>{meaning}</p>}
      {!isConclusive(c) && (
        <div className={styles.warnBox}>This checker did not complete ({inconclusiveLabel(c.status as string)}). Any score shown is not a verdict.</div>
      )}
      <KVBlock rows={scalars} />
      {nested.length > 0 && <div className={styles.hint}>Switch to the Technical tab for full structured evidence.</div>}
    </div>
  )
}

function CveBody({ v, tab }: { v: VulnRecord; tab: Tab }) {
  if (tab === 'technical') {
    return <pre className={styles.raw}>{JSON.stringify(v, null, 2)}</pre>
  }
  const pct = (n: number | null | undefined) => (typeof n === 'number' ? `${(n * 100).toFixed(1)}%` : '—')
  const rows: Array<[string, unknown]> = [
    ['Severity', v.severity === 'unknown' ? 'Unknown' : v.severity],
    ['CVSS base score', v.cvss != null ? v.cvss.toFixed(1) : 'unscored'],
    ['CVSS vector', v.vector || '—'],
    ['EPSS (exploit probability)', v.epss != null ? `${pct(v.epss)}${v.epssPercentile != null ? ` · ${pct(v.epssPercentile)} pctl` : ''}` : '—'],
    ['Exploit maturity', v.exploitMaturity ? (MATURITY_LABEL[v.exploitMaturity] ?? v.exploitMaturity) : '—'],
    ['CISA KEV', v.kev ? 'Yes — known exploited' : 'No'],
    ['Ransomware association', v.ransomware || 'None recorded'],
    ['MITRE ATT&CK', v.mitreTechnique ? `${v.mitreTechnique}${v.mitreTechniqueName ? ` · ${v.mitreTechniqueName}` : ''}` : '—'],
    ['Threat groups', v.mitreGroups && v.mitreGroups.length ? v.mitreGroups.join(', ') : '—'],
    ['Patch available', v.hasPatch == null ? '—' : v.hasPatch ? 'Yes' : 'No (unpatched)'],
    ['Patch age', v.ageDays != null ? `${v.ageDays} days since disclosure` : '—'],
    ['Published', v.published ? fmtDate(v.published) : '—'],
    ['Package', v.pkg ? `${v.pkg}${v.version ? ` @ ${v.version}` : ''}` : '—'],
    ['Source', v.source],
  ]
  const flags: string[] = []
  if (v.zeroDay) flags.push('Zero-day / no patch')
  if (v.easilyExploitable) flags.push('Easily exploitable (network · low complexity · no privileges)')
  if (v.widelyExploited) flags.push('Widely exploited in the wild')
  if (v.kev) flags.push('On the CISA Known Exploited Vulnerabilities catalog')
  return (
    <div className={styles.section}>
      {v.description && <p className={styles.lead}>{v.description}</p>}
      {flags.length > 0 && <div className={styles.warnBox}>{flags.join('  ·  ')}</div>}
      <KVBlock rows={rows} />
      {tab === 'overview' && (
        <div className={styles.hint}>Switch to the Technical tab for the full structured record. Severity, EPSS,
          KEV and exploit-maturity are correlated from NVD, FIRST EPSS, CISA KEV and exploit databases — theoretical
          exposure from external fingerprints, not a confirmed live exploit.</div>
      )}
    </div>
  )
}

export default function EvidenceDrawer({ target, onClose }: { target: DrawerTarget | null; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>('overview')
  useEffect(() => { setTab('overview') }, [target])
  useEffect(() => {
    if (!target) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [target, onClose])

  if (!target) return null
  const r = getResults()
  const cveRec = target.kind === 'cve' ? target.cve : null
  const isCoverage = target.kind === 'coverage'
  const c = target.kind === 'category' ? cat(r, target.id) : undefined
  const title = target.kind === 'cve' ? (target.cve.cve ?? target.cve.id)
    : target.kind === 'coverage' ? 'WAF / Bot-Manager Intervention'
    : (CATEGORY_LABELS[target.id] ?? target.id.replace(/_/g, ' '))
  const state = isCoverage ? 'blocked' : normalizeState(c?.status)
  const stateLabel = isCoverage ? 'Blocked' : (c && !isConclusive(c) ? inconclusiveLabel(c.status as string) : undefined)
  const tabs: Tab[] = cveRec ? ['overview', 'technical'] : ['overview', 'evidence', 'technical']

  return createPortal(
    <div className={styles.overlay} onMouseDown={onClose}>
      <aside className={styles.drawer} onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-label={title} aria-modal>
        <header className={styles.head}>
          <div className={styles.headMain}>
            <h2 className={styles.title}>{title}</h2>
            {cveRec
              ? (cveRec.severity === 'unknown'
                  ? <StatusBadge state="not_assessed" label="Unknown severity" />
                  : <SeverityBadge severity={cveRec.severity} />)
              : <StatusBadge state={state} label={stateLabel} />}
          </div>
          <button className={styles.close} onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>
        <div className={styles.tabs} role="tablist">
          {tabs.map((t) => (
            <button key={t} role="tab" aria-selected={tab === t}
              className={`${styles.tab} ${tab === t ? styles.tabActive : ''}`} onClick={() => setTab(t)}>
              {t[0].toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
        <div className={styles.scroll}>
          {cveRec ? <CveBody v={cveRec} tab={tab} />
            : isCoverage ? <CoverageBody tab={tab} />
            : <CategoryBody id={(target as { id: string }).id} tab={tab} />}
        </div>
        <footer className={styles.foot}>
          <span>{cveRec ? 'Source: NVD · FIRST EPSS · CISA KEV · exploit DBs' : 'Data source: external passive scan'}</span>
          <span>{fmtDateTime(r?.scan_timestamp)}</span>
        </footer>
      </aside>
    </div>,
    document.body,
  )
}
