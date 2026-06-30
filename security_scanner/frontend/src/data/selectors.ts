// ---------------------------------------------------------------------------
// Selectors — the single mapping layer between the raw RESULTS payload and the
// UI (spec §28). Components never read window.RESULTS or deep paths directly;
// they consume these typed, view-ready models. Every selector tolerates missing
// branches and reports availability instead of inventing data (spec §10/§33).
// ---------------------------------------------------------------------------
import type {
  Results, CategoryBase, Severity, ContributingFactor, RemediationStep,
} from '../types/results'
import {
  riskBandFromLabel, riskBandFromScore, type RiskBand,
} from './results'
import {
  normalizeSeverity, severityRank, isConclusive,
} from './checkerState'
import type { CheckerState } from '../types/results'

export function cat(r: Results | null, id: string): CategoryBase | undefined {
  return r?.categories?.[id]
}

// === Overall assessment (§6 panel 1) ========================================

export interface OverallAssessment {
  domain: string
  score: number
  max: number
  level: string
  band: RiskBand
  timestamp: string
  criticalFindings: number | null
}

export function getOverallAssessment(r: Results | null): OverallAssessment | null {
  if (!r) return null
  const score = r.overall_risk_score ?? 0
  const band = r.risk_level ? riskBandFromLabel(r.risk_level) : riskBandFromScore(score)
  const cf = r.insurance?.critical_findings
  const criticalFindings = typeof cf === 'number'
    ? cf
    : (cf && typeof cf === 'object' && typeof cf.total === 'number' ? cf.total : null)
  return {
    domain: r.domain_scanned,
    score,
    max: 1000,
    level: r.risk_level || band.label.replace(' Risk', ''),
    band,
    timestamp: r.scan_timestamp,
    criticalFindings,
  }
}

// === Coverage / WAF intervention (§5, §7) ===================================

export interface CoverageSummary {
  available: boolean
  coveragePct: number | null
  blocked: boolean
  kind: string
  evidence: string
  affectedCheckers: string[]
  affectedCount: number
  probeCodes: Record<string, number>
  probeSummary: string
}

export function getCoverageSummary(r: Results | null): CoverageSummary {
  const sc = r?._scan_completeness
  const waf = sc?.waf_status
  const affected = sc?.waf_affected_checkers ?? []
  const codes = waf?.codes ?? {}
  const blockedProbes = ['403', '406', '451'].reduce((n, c) => n + (codes[c] ?? 0), 0)
  const totalProbes = Object.values(codes).reduce((n, v) => n + v, 0)
  return {
    available: !!sc,
    coveragePct: sc?.coverage_pct ?? null,
    blocked: !!waf?.blocked,
    kind: waf?.kind ?? 'none',
    evidence: waf?.evidence ?? '',
    affectedCheckers: affected,
    affectedCount: affected.length,
    probeCodes: codes,
    probeSummary: totalProbes
      ? `${blockedProbes} of ${totalProbes} probes returned 403 / 406 / 451`
      : (waf?.evidence ?? ''),
  }
}

// === Ransomware Susceptibility (§6 panel 2) =================================

export interface RsiSummary {
  available: boolean
  score: number | null
  max: number
  label: string
  severity: Severity
  baseScore: number | null
  factors: ContributingFactor[]
}

export function getRsiSummary(r: Results | null): RsiSummary {
  const rsi = r?.insurance?.rsi
  const score = typeof rsi?.rsi_score === 'number' ? rsi.rsi_score : null
  return {
    available: score != null,
    score,
    max: 1,
    label: rsi?.risk_label ?? 'Unknown',
    severity: normalizeSeverity(rsi?.risk_label),
    baseScore: typeof rsi?.base_score === 'number' ? rsi.base_score : null,
    factors: (rsi?.contributing_factors ?? []).slice().sort((a, b) => b.impact - a.impact),
  }
}

// === Data Breach Resilience (§6 panel 3) ====================================

export interface DbiComponentRow {
  key: string
  label: string
  value: string
  points: number
  max: number
}
export interface DbiSummary {
  available: boolean
  score: number | null
  max: number
  label: string
  severity: Severity
  breachCount: number | null
  credentialLeaks: string | number | null
  trend: string | null
  components: DbiComponentRow[]
}

const DBI_LABELS: Record<string, string> = {
  breach_count: 'Breach count',
  recency: 'Recency',
  data_severity: 'Data severity',
  credential_leaks: 'Credential leaks',
  trend: 'Trend',
}

export function getDbiSummary(r: Results | null): DbiSummary {
  const dbi = r?.insurance?.dbi
  const comps = dbi?.components ?? {}
  const rows: DbiComponentRow[] = Object.entries(comps).map(([key, c]) => ({
    key,
    label: DBI_LABELS[key] ?? key.replace(/_/g, ' '),
    value: String(c.value),
    points: c.points,
    max: c.max,
  }))
  const dbiScore = typeof dbi?.dbi_score === 'number' ? dbi.dbi_score : null
  const sev: Severity = dbiScore == null ? 'unknown'
    : dbiScore >= 85 ? 'positive' : dbiScore >= 60 ? 'medium' : 'high'
  return {
    available: dbiScore != null,
    score: dbiScore,
    max: dbi?.max_score ?? 100,
    label: dbi?.label ?? 'Unknown',
    severity: sev,
    breachCount: typeof comps.breach_count?.value === 'number' ? comps.breach_count.value as number : null,
    credentialLeaks: comps.credential_leaks?.value ?? null,
    trend: comps.trend?.value != null ? String(comps.trend.value) : null,
    components: rows,
  }
}

// === Financial exposure (§6 panel 4, §15) ===================================

export interface ScenarioRow { key: string; label: string; loss: number }
export interface CompositionRow { key: string; label: string; loss: number; share: number }
export interface FinancialSummary {
  available: boolean
  currency: string
  expectedAnnualLoss: number | null
  loss: { min: number | null; likely: number | null; max: number | null }
  premiumTier: string | null
  recommendedCover: number | null
  scenarios: ScenarioRow[]
  composition: CompositionRow[]
}

const SCENARIO_LABELS: Record<string, string> = {
  data_breach: 'Data breach',
  ransomware: 'Ransomware',
  business_interruption: 'Business interruption',
  regulatory: 'POPIA regulatory',
  detection: 'Detection & escalation',
}

export function getFinancialSummary(r: Results | null): FinancialSummary {
  const fi = r?.insurance?.financial_impact
  const total = fi?.total ?? {}
  const eal = fi?.estimated_annual_loss
  const likely = total.most_likely ?? eal?.most_likely ?? null
  const scenarios: ScenarioRow[] = Object.entries(fi?.scenarios ?? {})
    .map(([key, v]) => ({
      key,
      label: SCENARIO_LABELS[key] ?? key.replace(/_/g, ' '),
      loss: (v as Record<string, number>).estimated_loss ?? 0,
    }))
    .sort((a, b) => b.loss - a.loss)
  const compTotal = scenarios.reduce((n, s) => n + s.loss, 0) || 1
  const composition: CompositionRow[] = scenarios.map((s) => ({
    ...s, share: s.loss / compTotal,
  }))
  return {
    available: likely != null,
    currency: fi?.currency ?? 'ZAR',
    expectedAnnualLoss: likely,
    loss: {
      min: total.min ?? eal?.minimum ?? null,
      likely,
      max: total.max ?? eal?.maximum ?? null,
    },
    premiumTier: fi?.insurance_recommendation?.premium_risk_tier ?? null,
    recommendedCover: fi?.insurance_recommendation?.recommended_cover_zar
      ?? fi?.insurance_recommendations?.recommended_coverage ?? null,
    scenarios,
    composition,
  }
}

// === Risk Snapshot (§9) — bespoke per-row state logic =======================

export interface SnapshotRow {
  id: string
  label: string
  value: string
  severity: Severity
  state: CheckerState
  /** category id to open in the evidence drawer */
  drill: string
}

function sslGradeSeverity(grade: string | undefined): Severity {
  const g = (grade ?? '').toUpperCase()
  if (g === 'A+' || g === 'A' || g === 'A-') return 'positive'
  if (g === 'B') return 'low'
  if (g === 'C') return 'medium'
  if (g === 'D' || g === 'E') return 'high'
  if (g === 'F' || g === 'T') return 'critical'
  return 'unknown'
}

export function getRiskSnapshot(r: Results | null): SnapshotRow[] {
  if (!r) return []
  const rows: SnapshotRow[] = []
  const affected = new Set(r._scan_completeness?.waf_affected_checkers ?? [])

  // SSL grade
  const ssl = cat(r, 'ssl')
  const grade = ssl?.grade as string | undefined
  rows.push({
    id: 'ssl', label: 'SSL Grade',
    value: grade ?? 'Not assessed',
    severity: grade ? sslGradeSeverity(grade) : 'unknown',
    state: grade ? 'warning' : 'not_assessed', drill: 'ssl',
  })

  // Email security (0..10)
  const email = cat(r, 'email_security')
  const escore = typeof email?.score === 'number' ? email.score : null
  rows.push({
    id: 'email_security', label: 'Email Security',
    value: escore != null ? `${escore} / 10` : 'Not assessed',
    severity: escore == null ? 'unknown' : escore >= 8 ? 'positive' : escore >= 5 ? 'medium' : 'high',
    state: escore == null ? 'not_assessed' : 'passed', drill: 'email_security',
  })

  // Known breaches
  const br = cat(r, 'breaches')
  const bc = typeof br?.breach_count === 'number' ? br.breach_count : null
  rows.push({
    id: 'breaches', label: 'Known breaches',
    value: bc == null ? 'No data' : String(bc),
    severity: bc == null ? 'unknown' : bc === 0 ? 'positive' : bc <= 2 ? 'high' : 'critical',
    state: bc == null ? 'no_data' : 'passed', drill: 'breaches',
  })

  // Exposed admin panels — only status 200 are confirmed reachable
  const ea = cat(r, 'exposed_admin')
  const exposedList = (ea?.exposed as Array<{ status: number; risk: string }> | undefined) ?? []
  const reachable = exposedList.filter((e) => e.status === 200)
  rows.push({
    id: 'exposed_admin', label: 'Exposed admin panels',
    value: String(reachable.length),
    severity: reachable.length === 0 ? 'positive'
      : reachable.some((e) => normalizeSeverity(e.risk) === 'critical') ? 'critical' : 'high',
    state: ea ? 'passed' : 'not_assessed', drill: 'exposed_admin',
  })

  // DB / service exposures (high-risk protocols)
  const hrp = cat(r, 'high_risk_protocols')
  const exposedSvc = (hrp?.exposed_services as Array<unknown> | undefined) ?? []
  rows.push({
    id: 'high_risk_protocols', label: 'DB / Service exposures',
    value: String(exposedSvc.length),
    severity: exposedSvc.length === 0 ? 'positive' : 'critical',
    state: hrp ? 'passed' : 'not_assessed', drill: 'high_risk_protocols',
  })

  // WAF
  const waf = cat(r, 'waf')
  const detected = waf?.detected === true
  rows.push({
    id: 'waf', label: 'WAF',
    value: detected ? `Detected${waf?.waf_name ? ` (${waf.waf_name})` : ''}` : 'Not detected',
    severity: detected ? 'positive' : 'high',
    state: waf ? 'passed' : 'not_assessed', drill: 'waf',
  })

  // RDP
  const vpn = cat(r, 'vpn_remote')
  const rdp = vpn?.rdp_exposed === true
  rows.push({
    id: 'rdp', label: 'RDP',
    value: rdp ? 'Exposed' : 'Not exposed',
    severity: rdp ? 'critical' : 'positive',
    state: vpn ? 'passed' : 'not_assessed', drill: 'vpn_remote',
  })

  // HTTP security headers — "Not assessed" when WAF blinded it (spec correction #3)
  const hh = cat(r, 'http_headers')
  const blinded = affected.has('http_headers')
  const hscore = typeof hh?.score === 'number' ? hh.score : null
  rows.push({
    id: 'http_headers', label: 'HTTP security headers',
    value: blinded || hscore == null ? 'Not assessed' : `${hscore} / 100`,
    severity: blinded || hscore == null ? 'unknown' : hscore >= 80 ? 'positive' : hscore >= 50 ? 'medium' : 'high',
    state: blinded || hscore == null ? 'not_assessed' : 'passed', drill: 'http_headers',
  })

  return rows
}

// === Key Findings (§10) =====================================================

export interface Finding {
  id: string
  rank: number
  title: string
  evidence: string
  severity: Severity
  count: number
  countLabel: string
  drill: string
  isCoverage?: boolean
}

export function getKeyFindings(r: Results | null): Finding[] {
  if (!r) return []
  const out: Array<Omit<Finding, 'rank'>> = []

  // 1. Internet-facing database service — always top when present
  const hrp = cat(r, 'high_risk_protocols')
  const svc = (hrp?.exposed_services as Array<{ port: number; service: string }> | undefined) ?? []
  if (svc.length) {
    const names = svc.map((s) => `${s.service} ${s.port}`).join(', ')
    out.push({
      id: 'db_exposure', title: 'Internet-facing database service',
      evidence: `${names} exposed to the public internet`, severity: 'critical',
      count: svc.length, countLabel: `${svc.length} affected ${svc.length === 1 ? 'asset' : 'assets'}`,
      drill: 'high_risk_protocols',
    })
  }

  // 2. WAF / Bot-Manager intervention (coverage warning)
  const cov = getCoverageSummary(r)
  if (cov.blocked) {
    out.push({
      id: 'waf_intervention', title: 'WAF / Bot-Manager intervention detected',
      evidence: cov.probeSummary, severity: 'medium',
      count: cov.affectedCount, countLabel: `${cov.affectedCount} affected checks`,
      drill: 'coverage', isCoverage: true,
    })
  }

  // 3. HTTPS not enforced
  const ws = cat(r, 'website_security')
  if (ws && ws.https_enforced === false) {
    out.push({
      id: 'https', title: 'HTTPS not enforced',
      evidence: 'HTTP does not redirect to HTTPS', severity: 'high',
      count: 1, countLabel: '1 affected asset', drill: 'website_security',
    })
  }

  // 4. Missing HSTS
  const ssl = cat(r, 'ssl')
  if (ssl && ssl.hsts === false) {
    out.push({
      id: 'hsts', title: 'Missing HSTS',
      evidence: 'Strict-Transport-Security not configured', severity: 'medium',
      count: 1, countLabel: '1 affected asset', drill: 'ssl',
    })
  }

  // 5. Exposed admin panel reachable
  const ea = cat(r, 'exposed_admin')
  const reachable = ((ea?.exposed as Array<{ path: string; status: number; risk: string }> | undefined) ?? [])
    .filter((e) => e.status === 200)
  if (reachable.length) {
    out.push({
      id: 'admin', title: 'Reachable admin / sensitive path',
      evidence: reachable.map((e) => e.path).join(', '),
      severity: reachable.some((e) => normalizeSeverity(e.risk) === 'critical') ? 'critical' : 'high',
      count: reachable.length, countLabel: `${reachable.length} path${reachable.length === 1 ? '' : 's'}`,
      drill: 'exposed_admin',
    })
  }

  // 6. Positive: no known breaches
  const br = cat(r, 'breaches')
  if (br && br.breach_count === 0) {
    out.push({
      id: 'no_breach', title: 'No known breaches',
      evidence: 'No historical breach exposure detected', severity: 'positive',
      count: 0, countLabel: 'Clean', drill: 'breaches',
    })
  }

  // sort: severity desc, but coverage warning sits just under criticals,
  // positives always last. DB exposure forced rank 1 already by being critical.
  const order = (s: Severity) => severityRank(s)
  out.sort((a, b) => {
    if (a.severity === 'positive' && b.severity !== 'positive') return 1
    if (b.severity === 'positive' && a.severity !== 'positive') return -1
    return order(b.severity) - order(a.severity)
  })
  return out.map((f, i) => ({ ...f, rank: i + 1 }))
}

// === Risk Factors (§11) — deterministic mapping from category scores ========
// The backend does not emit per-dimension factor scores, so each dimension is
// a documented deterministic roll-up of existing category `score` fields
// (0..100, higher = safer). We surface the security score AND the inverted risk
// contribution, never a fabricated number. Dimensions with no scorable category
// report status only (spec §11).

export interface RiskFactorRow {
  key: string
  label: string
  /** 0..100 security score (higher = safer); null when no category scored */
  score: number | null
  severity: Severity
  riskLabel: string
  topContributor: string
  /** 0..100 share of remaining risk this dimension represents */
  impact: number | null
}

const FACTOR_MAP: Array<{ key: string; label: string; categories: string[] }> = [
  { key: 'network', label: 'Network Exposure', categories: ['dns_infrastructure', 'high_risk_protocols', 'shodan_vulns', 'cloud_cdn'] },
  { key: 'appsec', label: 'Application Security', categories: ['website_security', 'http_headers', 'waf'] },
  { key: 'data', label: 'Data Protection', categories: ['privacy_compliance', 'payment_security', 'exposed_admin', 'info_disclosure'] },
  { key: 'cred', label: 'Credential Security', categories: ['dehashed', 'breaches', 'email_security'] },
  { key: 'hardening', label: 'System Hardening', categories: ['ssl', 'email_hardening', 'security_policy', 'vpn_remote'] },
]

export function getRiskFactors(r: Results | null): RiskFactorRow[] {
  if (!r) return []
  return FACTOR_MAP.map(({ key, label, categories }) => {
    const scored: Array<{ id: string; score: number }> = []
    for (const id of categories) {
      const c = cat(r, id)
      if (c && typeof c.score === 'number' && isConclusive(c)) scored.push({ id, score: c.score })
    }
    if (!scored.length) {
      return { key, label, score: null, severity: 'unknown', riskLabel: 'Not assessed', topContributor: '—', impact: null }
    }
    const avg = Math.round(scored.reduce((n, s) => n + s.score, 0) / scored.length)
    const worst = scored.slice().sort((a, b) => a.score - b.score)[0]
    const sev: Severity = avg >= 75 ? 'positive' : avg >= 55 ? 'medium' : avg >= 35 ? 'high' : 'critical'
    const riskLabel = avg >= 75 ? 'Low' : avg >= 55 ? 'Moderate' : avg >= 35 ? 'High' : 'Critical'
    return {
      key, label, score: avg, severity: sev, riskLabel,
      topContributor: CATEGORY_LABELS[worst.id] ?? worst.id,
      impact: 100 - avg,
    }
  })
}

// === Attacker's Path (§12) ==================================================

export interface AttackStage {
  key: string
  index: number
  title: string
  items: string[]
  risk: Severity
  /** when the stage is inferred from unverified checks, flag it (spec §12.3) */
  unverified?: boolean
  drill?: string
}

export function getAttackPath(r: Results | null): AttackStage[] {
  if (!r) return []
  const ips = r.discovered_ips ?? []
  const subs = (cat(r, 'subdomains')?.subdomains as unknown[] | undefined)?.length
    ?? (cat(r, 'subdomains')?.total_count as number | undefined) ?? 0
  const server = (cat(r, 'tech_stack')?.server_software as string[] | undefined)?.[0]
    ?? (cat(r, 'dns_infrastructure')?.server_info as Record<string, string> | undefined)?.Server
  const svc = (cat(r, 'high_risk_protocols')?.exposed_services as Array<{ service: string; port: number }> | undefined) ?? []
  const cred = cat(r, 'dehashed')
  const credExposed = (cred?.total_entries as number | undefined) ?? 0
  const cves = (cat(r, 'shodan_vulns')?.cves as unknown[] | undefined)?.length ?? 0
  const fin = getFinancialSummary(r)

  const recon: string[] = [
    `${ips.length} external IP${ips.length === 1 ? '' : 's'}`,
    `${subs} subdomain${subs === 1 ? '' : 's'}`,
  ]
  if (server) recon.push(`${server} exposed`)

  const access: string[] = []
  if (svc.length) access.push(`Internet-facing ${svc.map((s) => s.service).join(', ')} service`)
  if (credExposed > 0) access.push('Third-party credential exposure')
  if (!access.length) access.push('No confirmed initial-access vector from external scan')

  const exploit: string[] = cves > 0
    ? [`${cves} known CVE${cves === 1 ? '' : 's'} on exposed services`]
    : ['No critical exploitation vector confirmed by current external scan']

  const impact: string[] = []
  if (svc.length) impact.push('Internet-facing database could expose business data')
  if (fin.expectedAnnualLoss != null) impact.push('Estimated financial impact modelled')

  return [
    { key: 'recon', index: 1, title: 'Reconnaissance', items: recon, risk: ips.length || subs ? 'high' : 'medium', drill: 'dns_infrastructure' },
    { key: 'access', index: 2, title: 'Initial Access', items: access, risk: svc.length ? 'high' : 'low', drill: 'high_risk_protocols' },
    { key: 'exploit', index: 3, title: 'Exploitation', items: exploit, risk: cves > 0 ? 'high' : 'low', unverified: cves === 0, drill: 'shodan_vulns' },
    { key: 'impact', index: 4, title: 'Data Access & Impact', items: impact.length ? impact : ['Limited modelled impact'], risk: svc.length ? 'critical' : 'medium', drill: 'high_risk_protocols' },
  ]
}

// === Critical Alerts (§13) ==================================================

export type AlertState = 'new' | 'open' | 'acknowledged' | 'resolved' | 'suppressed'
export interface Alert {
  id: string
  title: string
  severity: Severity
  detail: string
  timestamp: string
  state: AlertState
  drill: string
}

export function getCriticalAlerts(r: Results | null): Alert[] {
  if (!r) return []
  const ts = r.scan_timestamp
  const alerts: Alert[] = []

  const svc = (cat(r, 'high_risk_protocols')?.exposed_services as Array<{ service: string; port: number }> | undefined) ?? []
  if (svc.length) {
    alerts.push({
      id: 'db_port', title: 'Exposed Database Port Detected', severity: 'critical',
      detail: `${svc.map((s) => `${s.service} ${s.port}`).join(', ')} reachable — direct data access risk`,
      timestamp: ts, state: 'new', drill: 'high_risk_protocols',
    })
  }
  const cov = getCoverageSummary(r)
  if (cov.blocked) {
    alerts.push({
      id: 'waf', title: 'WAF / Bot-Manager Intervention Detected', severity: 'high',
      detail: `${cov.probeSummary} — active blocking pattern`,
      timestamp: ts, state: 'open', drill: 'coverage',
    })
  }
  // Grouped service-exposure alert from open ports (don't flood — one rollup)
  const ports = (cat(r, 'dns_infrastructure')?.open_ports as Array<{ port: number; service: string; risk: string }> | undefined) ?? []
  const risky = ports.filter((p) => ['high', 'medium', 'critical'].includes((p.risk ?? '').toLowerCase()))
  if (risky.length) {
    alerts.push({
      id: 'services', title: 'Sensitive Network Services Exposed', severity: risky.some((p) => p.risk === 'high') ? 'high' : 'medium',
      detail: risky.slice(0, 6).map((p) => `${p.service} ${p.port}`).join(' · '),
      timestamp: ts, state: 'open', drill: 'dns_infrastructure',
    })
  }
  return alerts.sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
}

// === Remediation Priority Queue (§16) =======================================
// Re-orders the engine's steps + free-text recommendations into the spec's
// priority order. A failed checker is surfaced as a scan-quality action, never
// an ordinary vulnerability (spec §16).

export interface RemediationAction {
  rank: number
  title: string
  severity: Severity
  rsiReduction: number | null
  estSaving: number | null
  effort: string
  status: string
  kind: 'remediation' | 'scan_quality'
  source: string
}

// keyword -> priority rank (lower = sooner). Critical DB exposure first.
const PRIORITY_RULES: Array<{ rank: number; sev: Severity; test: RegExp; effort: string }> = [
  { rank: 1, sev: 'critical', test: /database|postgres|mysql|mongo|redis|5432|3306|exposed.*(port|service)|firewall.*(port|database)/i, effort: 'Medium' },
  { rank: 2, sev: 'high', test: /ftp|exposed (ftp|service)|patch.*(service|protocol)/i, effort: 'Medium' },
  { rank: 3, sev: 'high', test: /\bwaf\b|web application firewall/i, effort: 'Medium' },
  { rank: 4, sev: 'high', test: /https|redirect.*http|http.*redirect|tls (enforce|redirect)/i, effort: 'Low' },
  { rank: 5, sev: 'medium', test: /hsts|strict-transport/i, effort: 'Low' },
  { rank: 6, sev: 'medium', test: /mta-?sts/i, effort: 'Low' },
  { rank: 7, sev: 'medium', test: /tls-?rpt/i, effort: 'Low' },
  { rank: 8, sev: 'medium', test: /vpn|ztna|zero.?trust|remote access/i, effort: 'High' },
  { rank: 9, sev: 'medium', test: /privacy policy|popia|privacy/i, effort: 'Low' },
  { rank: 10, sev: 'low', test: /security\.txt|vdp|disclosure policy/i, effort: 'Low' },
  { rank: 11, sev: 'medium', test: /dmarc|dkim|spf/i, effort: 'Low' },
]

export function getRemediationActions(r: Results | null): {
  actions: RemediationAction[]
  projection: { currentRsi: number | null; simulatedRsi: number | null; totalSavings: number | null }
} {
  if (!r) return { actions: [], projection: { currentRsi: null, simulatedRsi: null, totalSavings: null } }
  const steps: RemediationStep[] = r.insurance?.remediation?.steps ?? []
  const recs: string[] = r.recommendations ?? []

  type Raw = { title: string; rsiReduction: number | null; estSaving: number | null; source: string }
  const raws: Raw[] = []
  const seen = new Set<string>()
  const keyOf = (t: string) => t.toLowerCase().replace(/[^a-z]/g, '').slice(0, 28)

  for (const s of steps) {
    const k = keyOf(s.action)
    if (seen.has(k)) continue
    seen.add(k)
    raws.push({ title: s.action, rsiReduction: s.rsi_reduction ?? null, estSaving: s.annual_savings_estimate ?? null, source: 'engine' })
  }
  for (const rec of recs) {
    const k = keyOf(rec)
    if (seen.has(k)) continue
    seen.add(k)
    raws.push({ title: rec, rsiReduction: null, estSaving: null, source: 'recommendation' })
  }

  const classify = (title: string) => {
    // scan-quality: failed/blocked checker rescans
    if (/failed|re-?scan|rescan|re-?run|third[_-]?party.?js|checker (failed|error)/i.test(title)) {
      return { rank: 90, sev: 'medium' as Severity, effort: 'Low', kind: 'scan_quality' as const }
    }
    for (const rule of PRIORITY_RULES) {
      if (rule.test.test(title)) return { rank: rule.rank, sev: rule.sev, effort: rule.effort, kind: 'remediation' as const }
    }
    return { rank: 50, sev: 'medium' as Severity, effort: 'Medium', kind: 'remediation' as const }
  }

  const actions = raws
    .map((raw) => ({ raw, c: classify(raw.title) }))
    .sort((a, b) => a.c.rank - b.c.rank || (b.raw.estSaving ?? 0) - (a.raw.estSaving ?? 0))
    .map(({ raw, c }, i): RemediationAction => ({
      rank: i + 1,
      title: raw.title,
      severity: c.sev,
      rsiReduction: raw.rsiReduction,
      estSaving: raw.estSaving,
      effort: c.effort,
      status: 'Open',
      kind: c.kind,
      source: raw.source,
    }))

  const rem = r.insurance?.remediation
  return {
    actions,
    projection: {
      currentRsi: rem?.current_rsi ?? null,
      simulatedRsi: rem?.simulated_rsi ?? null,
      totalSavings: rem?.total_potential_savings ?? null,
    },
  }
}

// === Compliance (§24) =======================================================

export interface ComplianceRow {
  name: string
  alignmentPct: number | null
  passed: number
  partial: number
  failed: number
  notAssessed: number
  total: number
  evidenceCoverage: number
  topGap: string | null
}

export function getComplianceSummary(r: Results | null): ComplianceRow[] {
  const comp = r?.compliance
  if (!comp) return []
  return Object.entries(comp).map(([name, fw]) => {
    const controls = Object.entries(fw.controls ?? {})
    let passed = 0, partial = 0, failed = 0, notAssessed = 0
    let topGap: { name: string; score: number } | null = null
    for (const [cname, c] of controls) {
      const st = c.status
      if (st === 'pass') passed++
      else if (st === 'partial') partial++
      else if (st === 'fail') failed++
      else notAssessed++
      if (st === 'fail' || st === 'partial') {
        const sc = c.score ?? 0
        if (!topGap || sc < topGap.score) topGap = { name: cname, score: sc }
      }
    }
    const total = controls.length
    const assessed = total - notAssessed
    return {
      name,
      alignmentPct: typeof fw.overall_pct === 'number' ? fw.overall_pct : null,
      passed, partial, failed, notAssessed, total,
      evidenceCoverage: total ? Math.round((assessed / total) * 100) : 0,
      topGap: topGap?.name ?? null,
    }
  })
}

// === Peer benchmarking (§25) ================================================

export interface PeerSummary {
  available: boolean
  insufficient: boolean
  nPeers: number | null
  minN: number
  industry: string
  subIndustry: string
  revenueBand: string
  rating: number | null
  percentile: number | null
}

export function getPeerSummary(r: Results | null): PeerSummary {
  const p = r?.insurance?.peer_benchmarking as Record<string, unknown> | undefined
  const status = p?.status as string | undefined
  return {
    available: !!p,
    insufficient: status === 'insufficient_data' || !p,
    nPeers: typeof p?.n_peers === 'number' ? p.n_peers : null,
    minN: typeof p?.min_cell_n === 'number' ? (p.min_cell_n as number) : 5,
    industry: (p?.industry as string) || 'Other',
    subIndustry: (p?.sub_industry as string) || 'Unknown',
    revenueBand: (p?.revenue_band_display as string) || 'Unknown',
    rating: typeof p?.peer_rating === 'number' ? (p.peer_rating as number) : null,
    percentile: typeof p?.percentile === 'number' ? (p.percentile as number) : null,
  }
}

// === Network open services (§20) ============================================

export interface OpenService {
  port: number
  service: string
  version: string | null
  severity: Severity
  cvss: number | null
  epss: number | null
  kev: boolean
  cves: string[]
  insuranceImpact: string | null
  exploits: string | null
  banner: string | null
}

/** Parse "CVSS 9.8 | EPSS 85% | CISA KEV" → structured metrics. */
function parseVulnMetrics(s: string | undefined): { cvss: number | null; epss: number | null; kev: boolean } {
  if (!s) return { cvss: null, epss: null, kev: false }
  const cvss = s.match(/CVSS\s+([\d.]+)/i)
  const epss = s.match(/EPSS\s+([\d.]+)\s*%/i)
  return {
    cvss: cvss ? parseFloat(cvss[1]) : null,
    epss: epss ? parseFloat(epss[1]) : null,
    kev: /KEV/i.test(s),
  }
}

export function getOpenServices(r: Results | null): OpenService[] {
  const dns = cat(r, 'dns_infrastructure')
  const ports = (dns?.open_ports as Array<Record<string, unknown>> | undefined) ?? []
  const exposedSet = new Set(
    ((cat(r, 'high_risk_protocols')?.exposed_services as Array<{ port: number }> | undefined) ?? []).map((s) => s.port),
  )
  return ports.map((p) => {
    const m = parseVulnMetrics(p.vuln_metrics as string | undefined)
    const riskLevel = String(p.risk_level ?? p.risk ?? '').toLowerCase()
    let severity = normalizeSeverity(p.risk as string)
    if (riskLevel.includes('critical') || exposedSet.has(p.port as number)) severity = 'critical'
    else if (riskLevel.includes('high')) severity = 'high'
    return {
      port: p.port as number,
      service: String(p.service ?? '—'),
      version: (p.detected_version as string) ?? null,
      severity,
      cvss: m.cvss,
      epss: m.epss,
      kev: m.kev,
      cves: (p.notable_cves as string[]) ?? [],
      insuranceImpact: (p.insurance_risk as string) ?? null,
      exploits: (p.typical_exploits as string) ?? null,
      banner: (p.banner as string) ?? null,
    }
  }).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.cvss ?? 0) - (a.cvss ?? 0))
}

// === Vulnerability summary (§21) ============================================

export interface VulnSummary {
  available: boolean
  total: number
  critical: number
  high: number
  medium: number
  kevCount: number
  highEpssCount: number
  zeroDay: number
  maxCvss: number | null
  maxEpss: number | null
  ipsWithVulns: number | null
}

export function getVulnerabilitySummary(r: Results | null): VulnSummary {
  const ext = cat(r, 'external_ips')?.aggregate_vulns as Record<string, number> | undefined
  const shodan = cat(r, 'shodan_vulns')
  const osv = cat(r, 'osv_vulns')
  const total = (ext?.total_cves ?? 0) || ((osv?.total_vulns as number) ?? 0) || ((shodan?.cves as unknown[] | undefined)?.length ?? 0)
  return {
    available: !!(ext || shodan || osv),
    total,
    critical: ext?.critical_count ?? (osv?.critical_count as number) ?? (shodan?.critical_count as number) ?? 0,
    high: ext?.high_count ?? (osv?.high_count as number) ?? (shodan?.high_count as number) ?? 0,
    medium: ext?.medium_count ?? (shodan?.medium_count as number) ?? 0,
    kevCount: ext?.kev_count ?? (shodan?.kev_count as number) ?? 0,
    highEpssCount: (shodan?.high_epss_count as number) ?? 0,
    zeroDay: (shodan?.zero_day_count as number) ?? 0,
    maxCvss: ext?.max_cvss ?? null,
    maxEpss: ext?.max_epss ?? null,
    ipsWithVulns: ext?.ips_with_vulns ?? null,
  }
}

// === Vulnerability records (§21) ============================================
// Preserves "unknown severity" and "score unavailable" explicitly — never
// collapses a CVSS 0 / null into a low-risk green.

export interface VulnRecord {
  id: string
  cve: string | null
  pkg: string | null
  version: string | null
  severity: Severity
  cvss: number | null
  epss: number | null
  kev: boolean
  published: string | null
  source: string
}

export function getVulnerabilityList(r: Results | null): VulnRecord[] {
  const out: VulnRecord[] = []
  const seen = new Set<string>()
  const push = (rec: VulnRecord) => {
    const k = (rec.cve || rec.id).toUpperCase()
    if (seen.has(k)) return
    seen.add(k)
    out.push(rec)
  }
  const cvssOrNull = (v: unknown): number | null => {
    const n = typeof v === 'number' ? v : NaN
    return n > 0 ? n : null
  }

  for (const v of (cat(r, 'osv_vulns')?.vulns as Array<Record<string, unknown>> | undefined) ?? []) {
    push({
      id: String(v.id ?? v.cve ?? '—'),
      cve: (v.cve as string) ?? (typeof v.id === 'string' && /CVE-\d{4}-\d+/.test(v.id) ? v.id.match(/CVE-\d{4}-\d+/)![0] : null),
      pkg: (v.package as string) ?? null,
      version: v.detected_version != null ? String(v.detected_version) : null,
      severity: normalizeSeverity(v.severity as string),
      cvss: cvssOrNull(v.cvss_score),
      epss: typeof v.epss === 'number' ? v.epss : null,
      kev: !!v.kev,
      published: (v.published as string) ?? null,
      source: (v.source as string) ?? 'osv.dev',
    })
  }
  for (const v of (cat(r, 'shodan_vulns')?.cves as Array<Record<string, unknown>> | undefined) ?? []) {
    push({
      id: String(v.cve_id ?? '—'),
      cve: (v.cve_id as string) ?? null,
      pkg: null,
      version: null,
      severity: normalizeSeverity(v.severity as string),
      cvss: cvssOrNull(v.cvss_score),
      epss: typeof v.epss_score === 'number' ? v.epss_score : null,
      kev: !!v.kev || !!v.in_kev,
      published: (v.published as string) ?? null,
      source: 'internetdb',
    })
  }
  // critical/high first, then by cvss desc, unknown sorts to the middle (not last)
  return out.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.cvss ?? 0) - (a.cvss ?? 0))
}

// === Email security (§19) ===================================================

export interface EmailSummary {
  available: boolean
  authScore: number | null
  hardeningScore: number | null
  spf: { present: boolean; valid: boolean; record?: string; lookups?: number; exceedsLimit?: boolean }
  dmarc: { present: boolean; policy?: string; reporting?: boolean }
  dkim: { selectors: number }
  mx: { records: string[] }
  hardening: { mtaSts: boolean; bimi: boolean; dane: boolean; tlsRpt: boolean }
  vendors: string[]
}

export function getEmailSecuritySummary(r: Results | null): EmailSummary {
  const e = cat(r, 'email_security')
  const h = cat(r, 'email_hardening')
  const v = cat(r, 'email_vendor_surface')
  const spf = (e?.spf as Record<string, unknown>) ?? {}
  const dmarc = (e?.dmarc as Record<string, unknown>) ?? {}
  return {
    available: !!e,
    authScore: typeof e?.score === 'number' ? e.score : null,
    hardeningScore: typeof h?.score === 'number' ? h.score : null,
    spf: {
      present: !!spf.present, valid: !!spf.valid, record: spf.record as string,
      lookups: spf.dns_lookups as number, exceedsLimit: !!spf.exceeds_lookup_limit,
    },
    dmarc: { present: !!dmarc.present, policy: dmarc.policy as string, reporting: !!dmarc.has_reporting },
    dkim: { selectors: ((e?.dkim as { selectors_found?: unknown[] })?.selectors_found ?? []).length },
    mx: { records: ((e?.mx as { records?: string[] })?.records ?? []) },
    hardening: {
      mtaSts: !!(h?.mta_sts as { present?: boolean })?.present,
      bimi: !!(h?.bimi as { present?: boolean })?.present,
      dane: !!(h?.dane as { present?: boolean })?.present,
      tlsRpt: !!(h?.tls_rpt as { present?: boolean })?.present,
    },
    vendors: (v?.vendors_detected as string[]) ?? [],
  }
}

// === Shared category labels =================================================

export const CATEGORY_LABELS: Record<string, string> = {
  ssl: 'SSL / TLS', http_headers: 'HTTP Security Headers', waf: 'WAF / DDoS',
  website_security: 'Website Security', third_party_js: 'Third-Party JavaScript',
  email_security: 'Email Authentication', email_hardening: 'Email Hardening',
  email_vendor_surface: 'Email-Vendor Surface', dns_infrastructure: 'DNS & Open Ports',
  high_risk_protocols: 'High-Risk Protocols', shodan_vulns: 'Shodan / InternetDB',
  cloud_cdn: 'Cloud & CDN', vpn_remote: 'VPN / Remote Access', dnsbl: 'DNS Blocklists',
  breaches: 'Data Breaches', dehashed: 'Credential Leaks', credential_risk: 'Credential Risk',
  exposed_admin: 'Exposed Admin Panels', virustotal: 'VirusTotal', subdomains: 'Subdomains',
  fraudulent_domains: 'Lookalike Domains', related_domains: 'Related Domains',
  dependency_manifests: 'Dependency Manifests', cms_plugin_sbom: 'CMS Plugin Surface',
  vendor_breach: 'Vendor Breach', info_disclosure: 'Information Disclosure',
  tech_stack: 'Technology Stack', domain_intel: 'Domain Intelligence',
  securitytrails: 'SecurityTrails DNS', security_policy: 'Security Policy & VDP',
  payment_security: 'Payment Security', privacy_compliance: 'Privacy Compliance',
  glasswing: 'AI Readiness', web_ranking: 'Web Ranking',
}
