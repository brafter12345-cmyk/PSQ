import Panel from '../../components/primitives/Panel'
import { PageTitle, CheckerHeader, CheckLine, KV, IssueList, DetailGrid } from '../../components/detail/parts'
import EmptyState from '../../components/primitives/EmptyState'
import { StatusBadge } from '../../components/primitives/Status'
import { getResults } from '../../data/results'
import { cat, getEmailSecuritySummary } from '../../data/selectors'
import { vendorPanel } from '../../data/emailVendorPanel'
import type { CheckerState, Results } from '../../types/results'
import styles from './detail.module.css'

export default function EmailPage({ r = getResults()! }: { r?: Results }) {
  const e = getEmailSecuritySummary(r)
  const auth = cat(r, 'email_security')
  const hard = cat(r, 'email_hardening')
  const vendor = cat(r, 'email_vendor_surface')
  const vp = vendorPanel(vendor as Record<string, unknown> | undefined)

  return (
    <div className={styles.page}>
      <PageTitle title="Email Security" subtitle="Authentication (SPF / DKIM / DMARC), advanced transport hardening and the email-vendor surface." />

      <DetailGrid cols={2}>
        <Panel title="Email Authentication"
          action={<><CheckerHeader category={auth} />{e.authScore != null && <span style={{ marginLeft: 8, fontSize: 12, fontWeight: 700 }}>{e.authScore}/10</span>}</>}>
          <CheckLine label="SPF record" state={e.spf.present ? (e.spf.valid ? 'pass' : 'warn') : 'fail'} value={e.spf.present ? (e.spf.valid ? 'Valid' : 'Present, issues') : 'Missing'} />
          {e.spf.present && (
            <CheckLine label="SPF DNS lookups" state={e.spf.exceedsLimit ? 'fail' : 'pass'} value={`${e.spf.lookups ?? '—'}${e.spf.exceedsLimit ? ' (exceeds 10)' : ''}`} />
          )}
          <CheckLine label="DMARC policy" state={dmarcState(e.dmarc.policy)} value={e.dmarc.present ? (e.dmarc.policy ?? 'none') : 'Missing'} />
          <CheckLine label="DMARC reporting" state={e.dmarc.reporting ? 'pass' : 'warn'} value={e.dmarc.reporting ? 'Configured' : 'None'} />
          <CheckLine label="DKIM selectors" state={e.dkim.selectors > 0 ? 'pass' : 'warn'} value={String(e.dkim.selectors)} />
          <CheckLine label="MX records" state={e.mx.records.length > 0 ? 'pass' : 'neutral'} value={String(e.mx.records.length)} />
          <IssueList issues={auth?.issues as string[]} />
        </Panel>

        <Panel title="Advanced Email Hardening"
          action={<><CheckerHeader category={hard} />{e.hardeningScore != null && <span style={{ marginLeft: 8, fontSize: 12, fontWeight: 700 }}>{e.hardeningScore}/10</span>}</>}>
          <CheckLine label="MTA-STS" state={e.hardening.mtaSts ? 'pass' : 'warn'} value={e.hardening.mtaSts ? 'Enabled' : 'Not configured'} />
          <CheckLine label="TLS-RPT" state={e.hardening.tlsRpt ? 'pass' : 'warn'} value={e.hardening.tlsRpt ? 'Enabled' : 'Not configured'} />
          <CheckLine label="DANE / TLSA" state={e.hardening.dane ? 'pass' : 'neutral'} value={e.hardening.dane ? 'Present' : 'Not present'} />
          <CheckLine label="BIMI" state={e.hardening.bimi ? 'pass' : 'neutral'} value={e.hardening.bimi ? 'Published' : 'Not published'} />
          <IssueList issues={hard?.issues as string[]} />
        </Panel>
      </DetailGrid>

      <Panel title="Email-Vendor Surface"
        action={vp.badge
          ? <StatusBadge state={vp.badge.state as CheckerState} label={vp.badge.label} />
          : <CheckerHeader category={vendor} />}>
        {vp.kind === 'rows' ? <KV rows={vp.rows} /> : <EmptyState compact title={vp.title} />}
        <IssueList issues={vendor?.issues as string[]} />
      </Panel>
    </div>
  )
}

function dmarcState(policy?: string): 'pass' | 'warn' | 'fail' {
  const p = (policy ?? '').toLowerCase()
  if (p === 'reject' || p === 'quarantine') return 'pass'
  if (p === 'none') return 'warn'
  return 'fail'
}
