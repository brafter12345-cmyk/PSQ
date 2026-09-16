/**
 * Related domains on the dashboard: the six states of
 * estate_discovery.related_domains_state (Python), which the PDF card, the
 * executive deck and the summary tier use, and the panel's wording.
 *
 * Self-contained on purpose (no runtime imports): the regression gate runs
 * this file under node on every case it builds and compares it with the
 * Python and the rendered PDF card: the state, whether the estate was fully
 * assessed, the notes (word for word), the lead sentence, the badge and its
 * label (against the card's colour), the rows and their labels, the listed
 * candidates and the "and N more" count. Change both together, or the gate
 * fails.
 *
 * Discovery runs on every scan (remediation step 5), form or API alike, from
 * public certificate records. What it finds is LISTED for confirmation and is
 * not assessed or scored; only broker-confirmed domains are. Anything the scan
 * did not measure is Not Assessed, never "none found", and a partly assessed
 * estate is never called clean.
 */
import type { CheckerState } from '../types/results'

export interface DiscoveredDomain {
  domain: string
  evidence: string
  attested: boolean
}

export type RelatedDomainsState =
  | 'not_run'
  | 'degraded'
  | 'none_found'
  | 'awaiting_confirmation'
  | 'confirmed'
  | 'confirmed_unassessed'

export interface RelatedDomainsDiscovery {
  state: RelatedDomainsState
  status: string
  hasDiscovery: boolean
  discoveryRan: boolean
  notRunReason: string
  fullyAssessed: boolean
  unassessedReason: string
  sourcesOk: string[]
  sourceCoverageNote: string | null
  discovered: DiscoveredDomain[]
  candidateCount: number
  notListedUnconfirmedCount: number
  declaredCount: number
  submittedCount: number
  scannedCount: number
  criticalCount: number
  highCount: number
  notAssessed: string[]
  overCap: string[]
  partial: Array<{ domain: string; notMeasured: string[] }>
  rejected: Array<{ domain: string; reason: string }>
}

export interface RelatedDomainsPanelModel {
  intro: string | null
  lead: string
  sources: string[] | null
  badge: { state: CheckerState; label: string } | null
  rows: Array<{ label: string; value: string }>
  notes: string[]
  pending: DiscoveredDomain[]
  extra: number
}

const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map((x) => String(x)) : [])

/** A value from a fixed wording table, never an inherited object property. */
function pick(table: Record<string, string>, key: string, fallback: string): string {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : fallback
}

export function relatedDomainsState(rd: Record<string, unknown> | null): RelatedDomainsState {
  if (!rd || Object.keys(rd).length === 0) return 'not_run'
  const declared = Number(rd.declared_count ?? 0)
  if (!('discovery' in rd)) {
    // Stored before step 5. Only a completed probe that measured at least one
    // confirmed sibling was an assessment; skipped, timeout and error were not.
    return rd.status === 'completed' && declared > 0 && Number(rd.scanned_count ?? 0) > 0
      ? 'confirmed'
      : 'not_run'
  }
  const disc = (rd.discovery ?? {}) as Record<string, unknown>
  if (declared > 0) return rd.status === 'completed' ? 'confirmed' : 'confirmed_unassessed'
  if (rd.status !== 'completed' || !disc.ran) return 'degraded'
  return Number(disc.candidate_count ?? 0) > 0 ? 'awaiting_confirmation' : 'none_found'
}

export function relatedDomainsFullyAssessed(rd: Record<string, unknown> | null): boolean {
  if (!rd || relatedDomainsState(rd) !== 'confirmed') return false
  // Stored before step 5 by a check that counted a sub-check returning nothing
  // as a pass: never a complete assessment (a finding in it still loads).
  if (!('discovery' in rd)) return false
  const na = rd.status === 'completed' && Array.isArray(rd.confirmed_not_assessed) ? rd.confirmed_not_assessed.length : 0
  const oc = Array.isArray(rd.confirmed_over_cap) ? rd.confirmed_over_cap.length : 0
  const deps = Array.isArray(rd.dependants) ? (rd.dependants as Array<Record<string, unknown>>) : []
  const partial = deps.filter(
    (d) => d !== null && typeof d === 'object' && d.measured === true && Array.isArray(d.not_measured) && d.not_measured.length > 0,
  ).length
  return na === 0 && oc === 0 && partial === 0
}

export function relatedDomainsCertificateCoverage(rd: Record<string, unknown> | null): string | null {
  if (!rd || !('discovery' in rd)) return null
  const disc = rd.discovery as Record<string, unknown> | null
  if (!disc || !Array.isArray(disc.sources_ok)) return 'Certificate-source coverage was not recorded for this scan.'
  const answered = new Set(disc.sources_ok.filter((x) => x === 'crtsh' || x === 'certspotter'))
  const count = answered.size
  const qualifier = count < 2 ? 'discovery coverage is partial' : 'this does not prove a complete estate'
  return `Certificate discovery: ${count} of 2 sources answered; ${qualifier}.`
}

export function relatedDomainsDiscovery(rd: Record<string, unknown> | null): RelatedDomainsDiscovery {
  const hasDiscovery = !!rd && 'discovery' in rd
  const disc = ((rd?.discovery ?? {}) as Record<string, unknown>)
  const list = ((rd?.discovered ?? []) as Array<Record<string, unknown>>).map((c) => ({
    domain: String(c.domain ?? ''),
    evidence: String(c.evidence ?? ''),
    attested: Boolean(c.attested),
  }))
  const rejected = (Array.isArray(rd?.confirmed_rejected)
    ? (rd?.confirmed_rejected as Array<Record<string, unknown>>)
    : []
  ).map((x) => ({ domain: String(x.domain ?? ''), reason: String(x.reason ?? '') }))
  const deps = Array.isArray(rd?.dependants) ? (rd?.dependants as Array<Record<string, unknown>>) : []
  const partial = deps
    .filter((d) => d !== null && typeof d === 'object' && d.measured === true && Array.isArray(d.not_measured) && d.not_measured.length > 0)
    .map((d) => ({ domain: String(d.domain ?? ''), notMeasured: strList(d.not_measured) }))
  const declaredCount = Number(rd?.declared_count ?? 0)
  // Unconfirmed candidates the list could not show. A result without that
  // count falls back to the total, which can only over-count.
  const unlisted = disc.not_listed_unconfirmed_count ?? disc.not_listed_count ?? 0
  return {
    state: relatedDomainsState(rd),
    status: String(rd?.status ?? ''),
    hasDiscovery,
    discoveryRan: Boolean(disc.ran),
    notRunReason: String(disc.not_run_reason ?? ''),
    fullyAssessed: relatedDomainsFullyAssessed(rd),
    unassessedReason: String(rd?.unassessed_reason ?? ''),
    sourcesOk: strList(disc.sources_ok),
    sourceCoverageNote: relatedDomainsCertificateCoverage(rd),
    discovered: list,
    candidateCount: Number(disc.candidate_count ?? 0),
    notListedUnconfirmedCount: Number(unlisted),
    declaredCount,
    submittedCount: Number(rd?.submitted_count ?? 0) || declaredCount,
    scannedCount: Number(rd?.scanned_count ?? 0),
    criticalCount: Number(rd?.critical_count ?? 0),
    highCount: Number(rd?.high_count ?? 0),
    notAssessed: rd?.status === 'completed' ? strList(rd?.confirmed_not_assessed) : [],
    overCap: strList(rd?.confirmed_over_cap),
    partial,
    rejected,
  }
}

// The PDF card's sentences (pdf_cards.py), word for word.
const RD_INTRO = 'Every scan looks for related domains automatically, whether submitted through the form or the API. Only domains a broker confirms are scanned and scored.'
const RD_NOT_RUN = 'Not assessed. This scan was run before related-domain discovery was added, so the scan did not look for related domains. Re-scan to include them.'
// A result stored before step 5 with status timeout or error: the category then
// existed only if domains were confirmed, so they went unassessed.
const RD_LEGACY_UNASSESSED = ' The related domains confirmed for this scan were not assessed.'
const RD_LEGACY_CONFIRMED = 'This result was stored by an earlier version of the check, which counted a check that returned no result, or the worst possible score, as a pass, so it is not a complete assessment of the confirmed domains. Re-scan to assess them.'
const RD_NONE_FOUND = 'No related domains were found on public certificate records. This does not show that the client has no other domains: only a domain that appears on a certificate alongside the scanned domain can be found this way.'
const RD_AWAITING = 'These domains appear on public certificate records alongside the scanned domain. They have not been assessed and do not affect the score. An unconfirmed domain is not evidence that the wider estate is clean.'
const RD_DEGRADED: Record<string, string> = {
  ct_unanswered: 'Not assessed. The certificate-record lookup did not return a result on this scan, so the scan could not look for related domains. This is not a finding that none exist.',
  subdomains_failed: 'Not assessed. The subdomain check, which fetches the certificate records, did not complete on this scan, so the scan could not look for related domains. This is not a finding that none exist.',
  prechange_checkpoint: 'Not assessed. This scan resumed from a checkpoint saved before related-domain discovery was added, so the scan did not look for related domains. This is not a finding that none exist.',
}
const RD_DEGRADED_GENERIC = 'Not assessed. Related-domain discovery could not run on this scan. This is not a finding that none exist.'
const RD_WHY: Record<string, string> = {
  timeout: 'within the time allowed',
  error: 'because the assessment failed',
  not_measured: 'because none of the checks returned a result',
}

/** The sentences the PDF card adds about what was NOT assessed (pdf_cards._rd_notes). */
export function relatedDomainsNotes(d: RelatedDomainsDiscovery, includeDiscovery: boolean): string[] {
  const out: string[] = d.sourceCoverageNote ? [d.sourceCoverageNote] : []
  if (includeDiscovery) {
    if (!d.hasDiscovery) out.push('This scan was run before related-domain discovery was added, so other related domains were not looked for.')
    else if (!d.discoveryRan) out.push('Related-domain discovery could not run on this scan, so other related domains were not looked for. That is not a finding that none exist.')
  }
  if (d.notAssessed.length) out.push(`${d.notAssessed.length} of ${d.declaredCount} confirmed related domain(s) could not be assessed on this scan and are not assessed, not clean: ${d.notAssessed.slice(0, 10).join(', ')}.`)
  if (d.partial.length) out.push(`On ${d.partial.length} confirmed related domain(s), some checks returned no result (${d.partial.slice(0, 10).map((p) => `${p.domain}: ${p.notMeasured.join(', ')}`).join('; ')}); those checks are not assessed, not clean.`)
  if (d.overCap.length) out.push(`${d.overCap.length} further confirmed related domain(s) were not assessed, because a scan assesses at most 10: ${d.overCap.slice(0, 10).join(', ')}.`)
  if (d.rejected.length) out.push(`Not assessed as related domains: ${d.rejected.slice(0, 10).map((x) => `${x.domain} (${x.reason})`).join('; ')}.`)
  return out
}

/** The panel's lead sentence. For every state but awaiting_confirmation and
 *  confirmed it is the PDF card's own opening sentence. */
export function relatedDomainsLead(d: RelatedDomainsDiscovery): string {
  switch (d.state) {
    case 'not_run':
      if (d.declaredCount > 0) return `${RD_NOT_RUN} ${d.declaredCount} confirmed related domain(s) were not assessed on this scan.`
      return d.status === 'timeout' || d.status === 'error' ? RD_NOT_RUN + RD_LEGACY_UNASSESSED : RD_NOT_RUN
    case 'degraded':
      return pick(RD_DEGRADED, d.notRunReason, RD_DEGRADED_GENERIC)
    case 'none_found':
      return RD_NONE_FOUND
    case 'awaiting_confirmation': {
      // The card's own sentence, then, where it lists candidates, the
      // sentence it prints above the list.
      const found = `${d.candidateCount} related domain(s) found on certificate records. None has been confirmed, so none has been assessed or scored.`
      const listed = d.discovered.some((c) => !c.attested) || d.notListedUnconfirmedCount > 0
      return listed ? `${found} ${RD_AWAITING}` : found
    }
    case 'confirmed_unassessed':
      return `Not assessed. ${d.declaredCount} confirmed related domain(s) could not be assessed ${pick(RD_WHY, d.unassessedReason, 'on this scan')}. They are not assessed, not clean.`
    default: {
      if (!d.hasDiscovery) return RD_LEGACY_CONFIRMED
      const first = d.fullyAssessed
        ? 'The domains confirmed by the broker were assessed.'
        : 'The domains confirmed by the broker were only partly assessed; the notes below say what was not.'
      // Only where the panel lists candidates, as for the awaiting lead.
      const listed = d.discovered.some((c) => !c.attested) || d.notListedUnconfirmedCount > 0
      const second = listed
        ? ' Domains found on certificate records but not confirmed are listed for confirmation and have not been assessed.'
        : ''
      return first + second
    }
  }
}

/** The badge follows the PDF card's colour: critical, red for a domain below
 *  60, green only for a full clean assessment, amber otherwise. A critical
 *  finding is never Passed, and a partial assessment is never Passed. */
export function relatedDomainsBadge(d: RelatedDomainsDiscovery): { state: CheckerState; label: string } | null {
  if (d.state === 'confirmed_unassessed') return { state: 'not_assessed', label: 'Not assessed' }
  if (d.state !== 'confirmed') return null
  if (d.criticalCount > 0) return { state: 'critical', label: 'Critical' }
  if (d.highCount > 0) return { state: 'failed', label: 'Below 60' }
  if (d.fullyAssessed) return { state: 'passed', label: 'Passed' }
  // A result stored before step 5 cannot show which checks returned nothing.
  if (!d.hasDiscovery) return { state: 'warning', label: 'Not verified' }
  return { state: 'warning', label: 'Partly assessed' }
}

/** The PDF card's rows. The counts beyond "submitted" appear only when
 *  something was measured: beside a Not assessed status, "critical 0 / high 0"
 *  would read as clean. */
export function relatedDomainsRows(d: RelatedDomainsDiscovery): Array<{ label: string; value: string }> {
  if (d.state === 'confirmed') {
    return [
      { label: 'submitted for assessment', value: String(d.submittedCount) },
      { label: 'assessed', value: String(d.scannedCount) },
      { label: 'critical findings', value: String(d.criticalCount) },
      { label: 'high-risk siblings', value: String(d.highCount) },
    ]
  }
  if (d.state === 'confirmed_unassessed') return [{ label: 'submitted for assessment', value: String(d.submittedCount) }]
  return []
}

/** Candidates awaiting confirmation: the first twelve, and how many more.
 *  Listed only where discovery ran. Broker-confirmed ones are shown as
 *  assessed (or not), never as unconfirmed. */
export function relatedDomainsPending(d: RelatedDomainsDiscovery): { pending: DiscoveredDomain[]; extra: number } {
  const lists = d.state === 'awaiting_confirmation' || d.state === 'confirmed' || d.state === 'confirmed_unassessed'
  if (!lists) return { pending: [], extra: 0 }
  const all = d.discovered.filter((c) => !c.attested)
  return { pending: all.slice(0, 12), extra: d.notListedUnconfirmedCount + Math.max(0, all.length - 12) }
}

/** Everything the related-domains panel shows, for one related_domains category. */
export function relatedDomainsPanel(rd: Record<string, unknown> | null): RelatedDomainsPanelModel {
  const d = relatedDomainsDiscovery(rd)
  const confirmedState = d.state === 'confirmed' || d.state === 'confirmed_unassessed'
  const { pending, extra } = relatedDomainsPending(d)
  return {
    intro: d.hasDiscovery ? RD_INTRO : null,
    lead: relatedDomainsLead(d),
    sources: d.state === 'none_found' || d.state === 'awaiting_confirmation' ? d.sourcesOk : null,
    badge: relatedDomainsBadge(d),
    rows: relatedDomainsRows(d),
    notes: d.state === 'not_run' ? [] : relatedDomainsNotes(d, confirmedState),
    pending,
    extra,
  }
}
