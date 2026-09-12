import Panel from '../../components/primitives/Panel'
import { getRelatedDomainsPanel } from '../../data/selectors'
import { StatusBadge } from '../../components/primitives/Status'
import { PageTitle, CheckerHeader, KV, IssueList, DetailGrid, NotAssessedNote } from '../../components/detail/parts'
import { getResults } from '../../data/results'
import { cat, CATEGORY_LABELS } from '../../data/selectors'
import { isConclusive, headerBadge, panelShowsCounts } from '../../data/checkerState'
import { vendorSurfaceUnmeasured } from '../../data/emailVendorPanel'
import CredentialExportPortal from '../../components/overview/CredentialExportPortal'
import MeetingBriefPanel from '../../components/overview/MeetingBriefPanel'
import BreachIntelPanel from '../../components/detail/BreachIntelPanel'
import type { Results, CategoryBase } from '../../types/results'
import type { KVRow } from '../../components/detail/parts'
import styles from './detail.module.css'

/** A registered domain that impersonates the client's. `technique` is how the
 *  string was derived (char-swap, char-omission, homoglyph…), `similarity` how
 *  close it is — both matter when deciding which ones to act on first. */
export interface Lookalike {
  domain: string
  technique?: string
  similarity?: number
  risk?: 'high' | 'medium' | 'low'
  recommendation?: string
  mail_capable?: boolean | null
  null_mx?: boolean
  spf?: string
  mx_hosts?: string[]
  nameservers?: string[]
  listed_for_sale?: boolean
  serves_content?: boolean
  http_status?: number
  page_title?: string
}

const LA_RISK: Record<string, { color: string; bg: string; label: string }> = {
  high: { color: 'var(--high)', bg: 'var(--high-soft)', label: 'High' },
  medium: { color: 'var(--warning)', bg: 'var(--warning-soft)', label: 'Medium' },
  low: { color: 'var(--text-muted)', bg: 'var(--panel-bg-elevated)', label: 'Low' },
  // Scans taken before posture probing existed, and any domain beyond the
  // per-scan probe cap, carry no verdict. Defaulting those to "Low" would
  // assert a conclusion we never reached — the same absence-of-evidence error
  // this release removes everywhere else.
  unprobed: { color: 'var(--unknown)', bg: 'var(--panel-bg-elevated)', label: 'Not probed' },
}

/** Lookalikes ordered by what they can actually DO, not just how similar they
 *  look. A near-typo with working MX and no site can phish your people today;
 *  a parked domain with a null MX cannot email anyone. Sorting high-risk first
 *  is what makes the panel actionable rather than a list of 20 strings. */
function LookalikeList({ domains }: { domains?: Lookalike[] }) {
  if (!domains || domains.length === 0) return null
  // Probed verdicts first (high → medium → low), then anything unprobed. An
  // unprobed domain is not "safest", it is unknown, so it sits at the end
  // rather than being ranked among conclusions.
  const rank = (d: Lookalike) =>
    d.risk === 'high' ? 0 : d.risk === 'medium' ? 1 : d.risk === 'low' ? 2 : 3
  const sorted = [...domains].sort((a, b) => rank(a) - rank(b) || (b.similarity ?? 0) - (a.similarity ?? 0))
  return (
    <ul style={{ listStyle: 'none', margin: '10px 0 0', padding: 0,
      display: 'flex', flexDirection: 'column', gap: 9 }}>
      {sorted.map((d) => {
        const rs = LA_RISK[d.risk ?? 'unprobed'] ?? LA_RISK.unprobed
        const caps: string[] = []
        if (d.mail_capable) caps.push('sends mail')
        else if (d.null_mx) caps.push('no mail (null MX)')
        if (d.serves_content) caps.push('live site')
        if (d.listed_for_sale) caps.push('for sale')
        if (d.spf) caps.push(`SPF ${d.spf}`)
        return (
          <li key={d.domain} style={{ borderLeft: `2px solid ${rs.color}`, paddingLeft: 9 }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 7, flexWrap: 'wrap' }}>
              <span style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{d.domain}</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: rs.color, background: rs.bg,
                borderRadius: 999, padding: '1px 7px' }}>{rs.label}</span>
              {d.technique && (
                <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{d.technique}</span>
              )}
              {typeof d.similarity === 'number' && (
                <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{d.similarity}%</span>
              )}
            </div>
            {caps.length > 0 && (
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>
                {caps.join(' · ')}
              </div>
            )}
            {/* The site's own title, verbatim. A live lookalike is as often an
                unrelated business with a similar name as an impersonator, and
                one line of its own words settles which — far faster than any
                heuristic we could apply. */}
            {d.page_title && (
              <div style={{ fontSize: 10.5, marginTop: 2, color: 'var(--text-secondary)' }}>
                page says: <i>&ldquo;{d.page_title}&rdquo;</i>
              </div>
            )}
            {d.recommendation ? (
              <div style={{ fontSize: 11, lineHeight: 1.5, color: 'var(--text-secondary)', marginTop: 3 }}>
                {d.recommendation}
              </div>
            ) : (
              <div style={{ fontSize: 11, lineHeight: 1.5, color: 'var(--text-muted)', marginTop: 3 }}>
                Mail and hosting posture not probed for this domain — re-run the scan
                to see whether it can send email as your brand. Not a clean result.
              </div>
            )}
          </li>
        )
      })}
    </ul>
  )
}

export default function ExposurePage({ r = getResults()! }: { r?: Results }) {
  const get = (id: string) => cat(r, id)
  const breaches = get('breaches')
  const dehashed = get('dehashed')
  const vt = get('virustotal')
  const admin = get('exposed_admin')
  const subs = get('subdomains')
  const fraud = get('fraudulent_domains')

  const adminReachable = ((admin?.exposed as Array<{ status: number }> | undefined) ?? []).filter((e) => e.status === 200)

  return (
    <div className={styles.page}>
      <PageTitle title="Exposure & Reputation" subtitle="Breach history, credential exposure, reputation intelligence and exposed assets. States distinguish clean results from unavailable data sources." />

      {/* Researched breach history leads the page: a dated, confirmed prior breach
          is the single most consequential thing on it, and (unlike HIBP) it is
          usually the only place a real incident shows up at all. */}
      <BreachIntelPanel bi={get('breach_intel')} />

      <DetailGrid cols={3}>
        <Panel title="Known Breaches (HIBP)" action={<CheckerHeader category={breaches} />}>
          <KV rows={[
            { label: 'Breach count', value: String((breaches?.breach_count as number) ?? 0), severity: (breaches?.breach_count as number) > 0 ? 'high' : 'positive' },
            { label: 'Most recent', value: (breaches?.most_recent_breach as string) ?? 'None' },
            { label: 'Data classes', value: ((breaches?.data_classes as string[]) ?? []).length || 'None' },
          ]} />
          <IssueList issues={breaches?.issues as string[]} />
        </Panel>

        <Panel title="Credential Leaks" action={<CheckerHeader category={dehashed} />}>
          {isConclusive(dehashed) ? (
            <>
              <KV rows={[
                { label: 'Leaked records', value: String((dehashed?.total_entries as number) ?? '—') },
                { label: 'Unique emails', value: String((dehashed?.unique_emails as number) ?? '—') },
                { label: 'Passwords present', value: (dehashed?.has_passwords as boolean) ? 'Yes' : 'No' },
              ]} />
              <IssueList issues={dehashed?.issues as string[]} />
              {((dehashed?.total_entries as number) ?? 0) > 0 && <CredentialExportPortal />}
              <MeetingBriefPanel />
            </>
          ) : (
            // Suppress the counts entirely: a failed lookup returns 0 records, and
            // "0 leaked records" is indistinguishable from a clean estate.
            <NotAssessedNote category={dehashed} what="The breached-credential database" />
          )}
        </Panel>

        <Panel title="VirusTotal Reputation" action={<CheckerHeader category={vt} />}>
          <KV rows={[
            { label: 'Malicious', value: String((vt?.malicious_count as number) ?? 0), severity: (vt?.malicious_count as number) > 0 ? 'high' : 'positive' },
            { label: 'Suspicious', value: String((vt?.suspicious_count as number) ?? 0) },
            { label: 'Harmless', value: String((vt?.harmless_count as number) ?? 0) },
            { label: 'Reputation', value: String((vt?.reputation as number) ?? '—') },
          ]} />
          <IssueList issues={vt?.issues as string[]} />
        </Panel>

        <Panel title="Exposed Admin Panels" action={<CheckerHeader category={admin} />}>
          <KV rows={[
            { label: 'Reachable (HTTP 200)', value: String(adminReachable.length), severity: adminReachable.length > 0 ? 'critical' : 'positive' },
            { label: 'Critical paths', value: String((admin?.critical_count as number) ?? 0) },
            { label: 'High-risk paths', value: String((admin?.high_count as number) ?? 0) },
          ]} />
          <IssueList issues={admin?.issues as string[]} />
        </Panel>

        <Panel title="Subdomains" action={<CheckerHeader category={subs} />}>
          <KV rows={[
            { label: 'Discovered', value: String((subs?.total_count as number) ?? ((subs?.subdomains as unknown[]) ?? []).length) },
            { label: 'Risky', value: String(((subs?.risky_subdomains as unknown[]) ?? []).length), severity: ((subs?.risky_subdomains as unknown[]) ?? []).length > 0 ? 'high' : undefined },
          ]} />
          <IssueList issues={subs?.issues as string[]} />
        </Panel>

        <Panel title="Lookalike Domains" action={<CheckerHeader category={fraud} />}>
          <KV rows={[
            { label: 'Permutations tested', value: String((fraud?.total_permutations as number) ?? '—') },
            { label: 'Resolved (live)', value: String((fraud?.resolved_count as number) ?? 0), severity: (fraud?.resolved_count as number) > 0 ? 'medium' : 'positive' },
          ]} />
          {/* Name the domains. A count alone is not actionable: brand-abuse
              follow-up (registrar complaint, defensive registration, monitoring)
              starts from the actual strings, and every other panel that finds
              specific assets lists them. */}
          <LookalikeList domains={fraud?.fraudulent_domains as Lookalike[] | undefined} />
          <IssueList issues={fraud?.issues as string[]} />
        </Panel>
      </DetailGrid>

      <RelatedDomainsPanel r={r} />

      <MoreCheckers r={r} ids={['credential_risk', 'credential_correlation', 'vendor_breach', 'hudson_rock', 'intelx', 'info_disclosure']} />
    </div>
  )
}

/** Compact auto-rendered panels for the long tail — shows state correctly
 *  (no-API-key / subscription / no-data are neutral, not green). */
export function MoreCheckers({ r, ids }: { r: Results; ids: string[] }) {
  const present = ids.map((id) => [id, cat(r, id)] as const).filter(([, c]) => !!c)
  if (!present.length) return null
  return (
    <Panel title="Additional Intelligence Sources">
      <DetailGrid cols={3}>
        {present.map(([id, c]) => {
          const fields = Object.entries(c as CategoryBase)
            .filter(([k, v]) => !['status', 'issues', 'per_ip', 'score'].includes(k) && (typeof v !== 'object' || v === null))
            .slice(0, 4)
          const rows: KVRow[] = fields.map(([k, v]) => ({ label: k.replace(/_/g, ' '), value: String(v) }))
          // Counts are only printed where something was measured. A chain that
          // was never read yields "match count = 0", which reads as a clean
          // vendor estate (step-5 critique round 11, R11-SC-2).
          const badge = headerBadge(c, true)
          // One function, which the regression gate runs under node on real
          // checker output (step-5 critique round 11, R11-SC-2).
          const unmeasured = !panelShowsCounts(c)
          const partly = badge.label === 'Partly assessed'
          // Only the two SPF-bearing checkers carry an SPF reason to give.
          const spfWhy = (id === 'vendor_breach' || id === 'email_vendor_surface')
            ? vendorSurfaceUnmeasured(c as unknown as Record<string, unknown>)
            : ''
          return (
            <div key={id} style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{CATEGORY_LABELS[id] ?? id.replace(/_/g, ' ')}</span>
                <CheckerHeader category={c} refine />
              </div>
              {unmeasured ? (
                <NotAssessedNote category={c} force
                  what={CATEGORY_LABELS[id] ?? id.replace(/_/g, ' ')}
                  why={spfWhy || (badge.label ?? undefined)} />
              ) : (
                <>
                  {rows.length > 0 && <KV rows={rows} />}
                  {partly && <KV rows={[{ label: 'SPF chain',
                    value: 'Partly read - the figures above are a lower bound' }]} />}
                </>
              )}
            </div>
          )
        })}
      </DetailGrid>
    </Panel>
  )
}

/** Related domains, in the same six states as the PDF card, deck and summary
 *  tier. Every word and number comes from data/relatedDomains.ts, which the
 *  regression gate runs against the PDF card under node. */
function RelatedDomainsPanel({ r }: { r: Results }) {
  const m = getRelatedDomainsPanel(r)
  return (
    <Panel title="Related Domains">
      {m.intro && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{m.intro}</div>
      )}
      <div style={{ fontSize: 12.5, marginBottom: 10 }}>{m.lead}</div>
      {m.sources && (
        <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>
          Certificate sources that answered: {m.sources.length ? m.sources.join(', ') : 'n/a'}
        </div>
      )}
      {m.badge && (
        <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 12, marginBottom: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>Broker-confirmed domains</span>
            <StatusBadge state={m.badge.state} label={m.badge.label} />
          </div>
          {m.rows.length > 0 && <KV rows={m.rows} />}
        </div>
      )}
      {m.notes.map((n) => (
        <div key={n} style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>{n}</div>
      ))}
      {(m.pending.length > 0 || m.extra > 0) && (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 7 }}>
          {m.pending.map((c) => (
            <li key={c.domain} style={{ borderLeft: '2px solid var(--border)', paddingLeft: 9 }}>
              <span style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12, fontWeight: 600 }}>{c.domain}</span>
              <span style={{ fontSize: 10, fontWeight: 700, marginLeft: 7, color: 'var(--text-muted)' }}>UNCONFIRMED</span>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{c.evidence}</div>
            </li>
          ))}
          {m.extra > 0 && (
            <li style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>and {m.extra} more.</li>
          )}
        </ul>
      )}
    </Panel>
  )
}
