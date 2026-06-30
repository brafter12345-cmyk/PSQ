import { useState } from 'react'
import Panel from '../../components/primitives/Panel'
import { SeverityBadge } from '../../components/primitives/Status'
import EvidenceTable, { type Column } from '../../components/detail/EvidenceTable'
import EvidenceDrawer, { type DrawerTarget } from '../../components/drawer/EvidenceDrawer'
import { PageTitle, StatGrid } from '../../components/detail/parts'
import { fmtDate } from '../../data/results'
import { getResults } from '../../data/results'
import { getVulnerabilityList, getVulnerabilitySummary, type VulnRecord } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

const FILTERS: Array<{ key: string; label: string; test: (v: VulnRecord) => boolean }> = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'kev', label: 'KEV', test: (v) => v.kev },
  { key: 'scored', label: 'Scored', test: (v) => v.cvss != null },
  { key: 'unknown', label: 'Unknown severity', test: (v) => v.severity === 'unknown' },
]

export default function VulnerabilitiesPage({ r = getResults()! }: { r?: Results }) {
  const all = getVulnerabilityList(r)
  const sum = getVulnerabilitySummary(r)
  const [filter, setFilter] = useState('all')
  const [drawer, setDrawer] = useState<DrawerTarget | null>(null)
  const rows = all.filter(FILTERS.find((f) => f.key === filter)!.test)

  const unknownSev = all.filter((v) => v.severity === 'unknown').length
  const noScore = all.filter((v) => v.cvss == null).length

  const columns: Array<Column<VulnRecord>> = [
    { key: 'id', header: 'CVE / ID', render: (v) => <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontSize: 11 }}>{v.cve ?? v.id}</span> },
    { key: 'pkg', header: 'Package', render: (v) => v.pkg ? <span>{v.pkg}{v.version ? ` @ ${v.version}` : ''}</span> : <span className={styles.dash}>—</span> },
    { key: 'sev', header: 'Severity', render: (v) => v.severity === 'unknown'
      ? <span style={{ fontSize: 11, color: 'var(--unknown)', fontWeight: 600 }}>Unknown</span>
      : <SeverityBadge severity={v.severity} /> },
    { key: 'cvss', header: 'CVSS', align: 'right', render: (v) => v.cvss != null
      ? <span style={{ fontWeight: 700, color: cvssColor(v.cvss) }}>{v.cvss.toFixed(1)}</span>
      : <span className={styles.dash} title="Score unavailable">unscored</span> },
    { key: 'epss', header: 'EPSS', align: 'right', render: (v) => v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : <span className={styles.dash}>—</span> },
    { key: 'kev', header: 'KEV', align: 'center', render: (v) => v.kev ? <span className={styles.kev}>KEV</span> : <span className={styles.dash}>—</span> },
    { key: 'pub', header: 'Published', align: 'right', render: (v) => v.published ? fmtDate(v.published) : <span className={styles.dash}>—</span> },
    { key: 'src', header: 'Source', render: (v) => <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v.source}</span> },
    { key: 'status', header: 'Status', render: (v) => <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{v.severity === 'unknown' || v.cvss == null ? 'Needs validation' : 'Open'}</span> },
    { key: 'detail', header: '', align: 'right', render: () => <span style={{ fontSize: 11, color: 'var(--accent-bright)', fontWeight: 600 }}>Detail ›</span> },
  ]

  return (
    <div className={styles.page}>
      <PageTitle title="Vulnerabilities" subtitle="CVEs correlated from external service fingerprints (OSV.dev + InternetDB). Theoretical exposure pending validation — not confirmed live exploits." />

      <Panel title="Vulnerability Summary">
        <StatGrid stats={[
          { label: 'Total known', value: sum.total },
          { label: 'Critical', value: sum.critical, severity: sum.critical > 0 ? 'critical' : 'positive' },
          { label: 'High', value: sum.high, severity: sum.high > 0 ? 'high' : 'positive' },
          { label: 'KEV', value: sum.kevCount, severity: sum.kevCount > 0 ? 'critical' : 'positive' },
          { label: 'High EPSS', value: sum.highEpssCount, severity: sum.highEpssCount > 0 ? 'high' : 'positive' },
          { label: 'Unknown severity', value: unknownSev, severity: 'unknown' },
          { label: 'Score unavailable', value: noScore, severity: 'unknown' },
          { label: 'Max CVSS', value: sum.maxCvss != null ? sum.maxCvss.toFixed(1) : '—' },
        ]} />
      </Panel>

      <Panel
        title="Known Vulnerabilities"
        action={
          <div style={{ display: 'flex', gap: 2 }}>
            {FILTERS.map((f) => (
              <button key={f.key} onClick={() => setFilter(f.key)}
                style={{ padding: '3px 9px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                  color: filter === f.key ? 'var(--accent-bright)' : 'var(--text-muted)',
                  background: filter === f.key ? 'var(--accent-soft)' : 'transparent' }}>
                {f.label}
              </button>
            ))}
          </div>
        }
        flush
      >
        <EvidenceTable columns={columns} rows={rows} getKey={(v, i) => `${v.id}-${i}`}
          empty="No vulnerability records for this scan."
          onRowClick={(v) => setDrawer({ kind: 'cve', cve: v })} />
      </Panel>

      <EvidenceDrawer target={drawer} onClose={() => setDrawer(null)} />
    </div>
  )
}

function cvssColor(v: number): string {
  if (v >= 9) return 'var(--critical)'
  if (v >= 7) return 'var(--high)'
  if (v >= 4) return 'var(--warning)'
  return 'var(--info)'
}
