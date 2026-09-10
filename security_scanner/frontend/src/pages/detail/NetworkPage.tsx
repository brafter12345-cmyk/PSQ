import Panel from '../../components/primitives/Panel'
import { SeverityBadge, SeverityDot } from '../../components/primitives/Status'
import EvidenceTable, { type Column } from '../../components/detail/EvidenceTable'
import { PageTitle, KV, StatGrid, IssueList } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import { cat, estateIpCount, getOpenServices, getVulnerabilitySummary, vendorIpCount, type OpenService } from '../../data/selectors'
import { SEVERITY_COLOR } from '../../data/checkerState'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

function cvssColor(v: number | null): string {
  if (v == null) return 'var(--unknown)'
  if (v >= 9) return 'var(--critical)'
  if (v >= 7) return 'var(--high)'
  if (v >= 4) return 'var(--warning)'
  return 'var(--info)'
}

export default function NetworkPage({ r = getResults()! }: { r?: Results }) {
  const services = getOpenServices(r)
  const dns = cat(r, 'dns_infrastructure')
  const ext = cat(r, 'external_ips')
  const ips = r.discovered_ips ?? []
  const dnssec = dns?.dnssec_enabled
  const zone = dns?.zone_transfer as { vulnerable?: boolean } | undefined

  const columns: Array<Column<OpenService>> = [
    { key: 'port', header: 'Port', render: (s) => <strong style={{ color: 'var(--text-primary)' }}>{s.port}</strong> },
    { key: 'service', header: 'Service', render: (s) => (
      <div className={styles.svc}><span className={styles.svcName}>{s.service}</span>{s.version && <span className={styles.svcVer}>{s.version}</span>}</div>
    ) },
    { key: 'risk', header: 'Risk', render: (s) => <SeverityBadge severity={s.severity} /> },
    { key: 'cvss', header: 'CVSS', align: 'right', render: (s) => s.cvss != null ? <span className={styles.cvss} style={{ color: cvssColor(s.cvss) }}>{s.cvss.toFixed(1)}</span> : <span className={styles.dash}>—</span> },
    { key: 'epss', header: 'EPSS', align: 'right', render: (s) => s.epss != null ? `${s.epss}%` : <span className={styles.dash}>—</span> },
    { key: 'kev', header: 'KEV', align: 'center', render: (s) => s.kev ? <span className={styles.kev}>KEV</span> : <span className={styles.dash}>—</span> },
    { key: 'cves', header: 'Known CVEs', render: (s) => s.cves.length ? <div className={styles.cves}>{s.cves.map((c) => <span key={c} className={styles.cve}>{c}</span>)}</div> : <span className={styles.dash}>—</span> },
    { key: 'impact', header: 'Insurance impact', render: (s) => <div className={styles.impact}>{s.insuranceImpact ?? '—'}</div> },
  ]

  const aggregate = ext?.aggregate_vulns as Record<string, number> | undefined
  // Unified vuln summary — folds in open-service CVEs so "Aggregate CVEs" and
  // "KEV exposed" agree with the Open Services table below (and the Vuln page),
  // instead of reading only the external_ips aggregate (which omits open ports).
  const vsum = getVulnerabilitySummary(r)

  return (
    <div className={styles.page}>
      <PageTitle title="Network & Infrastructure" subtitle="External attack surface — discovered assets, exposed services and DNS posture." />

      <Panel title="Asset & Exposure Summary">
        <StatGrid stats={[
          { label: 'External IPs', value: estateIpCount(r) || ips.length || '—' },
          ...(vendorIpCount(r) > 0
            ? [{ label: 'Vendor-operated', value: vendorIpCount(r) }]
            : []),
          { label: 'Open services', value: services.length },
          { label: 'High-risk services', value: services.filter((s) => s.severity === 'critical' || s.severity === 'high').length, severity: 'high' },
          { label: 'Aggregate CVEs', value: vsum.total || (aggregate?.total_cves ?? '—') },
          { label: 'KEV exposed', value: vsum.kevCount, severity: vsum.kevCount > 0 ? 'critical' : 'positive' },
          { label: 'DNSSEC', value: dnssec ? 'On' : 'Off', severity: dnssec ? 'positive' : 'medium' },
        ]} />
      </Panel>

      <Panel title="Open Services" action={<span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{services.length} ports</span>} flush>
        <EvidenceTable columns={columns} rows={services} getKey={(s) => String(s.port)}
          empty="No open services detected on the external surface." />
        <div style={{ padding: '0 12px 12px' }}>
          <p className={styles.note}>CVSS/EPSS/KEV reflect the typical exposure of each detected service and its notable CVEs; they are not a confirmed live exploit. Internet-facing database and file-transfer services are the highest underwriting concern.</p>
        </div>
      </Panel>

      <div className={styles.page} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px,1fr))' }}>
        <Panel title="DNS & Hosting">
          <KV rows={[
            { label: 'Reverse DNS', value: (dns?.reverse_dns as string) ?? '—' },
            { label: 'Server', value: (dns?.server_info as { Server?: string })?.Server ?? '—' },
            { label: 'DNSSEC', value: dnssec ? 'Enabled' : 'Not enabled', severity: dnssec ? 'positive' : 'medium' },
            { label: 'Zone transfer (AXFR)', value: zone?.vulnerable ? 'Vulnerable' : 'Not vulnerable', severity: zone?.vulnerable ? 'critical' : 'positive' },
            { label: 'DNS risk score', value: (dns?.risk_score as number) ?? '—' },
          ]} />
          <IssueList issues={dns?.issues as string[]} />
        </Panel>

        <Panel title="Discovered IP Addresses" action={<SeverityDot severity="info" />}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {ips.length ? ips.map((ip) => (
              <span key={ip} style={{ fontSize: 11.5, fontFamily: 'var(--font-mono)', padding: '3px 9px', borderRadius: 6, background: 'var(--panel-bg-elevated)', border: '1px solid var(--border)', color: 'var(--text-secondary)' }}>{ip}</span>
            )) : <span className={styles.dash}>No IPs discovered.</span>}
          </div>
          <IssueList issues={ext?.issues as string[]} />
        </Panel>
      </div>
    </div>
  )
}
