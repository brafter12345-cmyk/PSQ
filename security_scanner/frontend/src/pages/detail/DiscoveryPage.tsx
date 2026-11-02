import Panel from '../../components/primitives/Panel'
import { PageTitle, CheckerHeader, KV, IssueList, DetailGrid } from '../../components/detail/parts'
import { MoreCheckers } from './ExposurePage'
import { getResults } from '../../data/results'
import { cat, estateIpCount, vendorIpCount } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './detail.module.css'

export default function DiscoveryPage({ r = getResults()! }: { r?: Results }) {
  const ext = cat(r, 'external_ips')
  const ranking = cat(r, 'web_ranking')
  const info = cat(r, 'info_disclosure')
  const subs = cat(r, 'subdomains')
  const ips = r.discovered_ips ?? []

  return (
    <div className={styles.page}>
      <PageTitle title="Discovery & Information Security" subtitle="Asset discovery, web ranking and information-disclosure surface that seed the rest of the assessment." />

      <DetailGrid cols={3}>
        <Panel title="IP & Asset Discovery" action={<CheckerHeader category={ext} />}>
          <KV rows={[
            { label: 'Discovered IPs', value: String(estateIpCount(r) || ips.length || 0) },
            ...(vendorIpCount(r) > 0
              ? [{ label: 'Vendor-operated', value: `${vendorIpCount(r)} (not scored)` }]
              : []),
            { label: 'IPv4 / IPv6', value: `${(ext?.ipv4_count as number) ?? 0} / ${(ext?.ipv6_count as number) ?? 0}` },
            { label: 'Subdomains', value: String((subs?.total_count as number) ?? ((subs?.subdomains as unknown[]) ?? []).length) },
          ]} />
          <IssueList issues={ext?.issues as string[]} />
        </Panel>

        <Panel title="Web Ranking" action={<CheckerHeader category={ranking} />}>
          <KV rows={[
            { label: 'Rank', value: (ranking?.rank as number) != null ? String(ranking?.rank) : 'Unranked' },
            { label: 'In ranking list', value: (ranking?.in_list as boolean) ? 'Yes' : 'No' },
          ]} />
          <IssueList issues={ranking?.issues as string[]} />
        </Panel>

        <Panel title="Information Disclosure" action={<CheckerHeader category={info} />}>
          <KV rows={[
            { label: 'Exposed paths', value: String(((info?.exposed_paths as unknown[]) ?? []).length), severity: ((info?.exposed_paths as unknown[]) ?? []).length > 0 ? 'high' : 'positive' },
          ]} />
          <IssueList issues={info?.issues as string[]} />
        </Panel>
      </DetailGrid>

      <MoreCheckers r={r} ids={['origin_discovery', 'securitytrails', 'web_ranking']} />
    </div>
  )
}
