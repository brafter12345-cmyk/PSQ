// ---------------------------------------------------------------------------
// Types for the live RESULTS payload (server-injected, identical shape whether
// backed by Postgres or the legacy SQLite store). Modelled from real scans.
// Long-tail / evolving checker fields use index signatures so the UI degrades
// gracefully rather than the build breaking when the scanner adds a field.
// ---------------------------------------------------------------------------

/** Normalised checker lifecycle state — never infer "pass" from score===100. */
export type CheckerState =
  | 'passed'
  | 'warning'
  | 'failed'
  | 'critical'
  | 'blocked'
  | 'error'
  | 'not_assessed'
  | 'no_data'
  | 'not_applicable'
  | 'subscription_required'
  | 'rate_limited'
  | 'skipped'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'positive' | 'unknown'

export interface Issue {
  message?: string
  severity?: string
  [k: string]: unknown
}

/** Base shape shared by every entry in `categories`. */
export interface CategoryBase {
  status?: string
  score?: number
  issues?: Array<string | Issue>
  [k: string]: unknown
}

export interface OpenPort {
  port: number
  service: string
  risk?: string
}

export interface ExposedService {
  port: number
  service: string
}

export interface ExposedAdminEntry {
  path: string
  status: number
  risk: string
}

export interface ContributingFactor {
  factor: string
  impact: number
  priority?: number
}

export interface RsiBranch {
  rsi_score?: number
  risk_label?: string
  base_score?: number
  industry?: string
  industry_multiplier?: number
  annual_revenue?: number
  size_multiplier?: number
  contributing_factors?: ContributingFactor[]
  factor_count?: number
}

export interface MoneyTriple {
  min?: number
  most_likely?: number
  max?: number
  minimum?: number
  maximum?: number
}

export interface FinancialImpact {
  currency?: string
  industry?: string
  annual_revenue_zar?: number
  score?: number
  estimated_annual_loss?: { minimum?: number; most_likely?: number; maximum?: number }
  scenarios?: Record<string, Record<string, number>>
  // 4-category loss decomposition (Data Breach / Detection & Escalation /
  // Ransom Demand / Business Interruption). Each carries a display label and
  // estimated_loss; current scans emit this alongside the legacy `scenarios`.
  scenarios_4cat?: Record<string, { label?: string; estimated_loss?: number; note?: string; components?: string; [k: string]: unknown }>
  // Monte Carlo aggregate distribution + confidence intervals.
  monte_carlo?: {
    iterations?: number
    method?: string
    total?: Record<string, number>
    confidence_interval_90?: { lower?: number; upper?: number }
    confidence_interval_50?: { lower?: number; upper?: number }
    [k: string]: unknown
  }
  insurance_recommendation?: {
    minimum_cover_zar?: number
    recommended_cover_zar?: number
    premium_risk_tier?: string
  }
  total?: MoneyTriple
  insurance_recommendations?: {
    suggested_deductible?: number
    expected_annual_loss?: number
    recommended_coverage?: number
  }
  // Some scans carry a full Monte Carlo distribution / percentiles block.
  distribution?: Record<string, unknown>
  percentiles?: Record<string, number>
  simulations?: number
  [k: string]: unknown
}

export interface DbiComponent {
  value: number | string
  points: number
  max: number
}

export interface DbiBranch {
  dbi_score?: number
  label?: string
  components?: Record<string, DbiComponent>
  max_score?: number
}

export interface RemediationStep {
  action: string
  category?: string
  priority?: number
  estimated_cost?: string
  rsi_reduction?: number
  annual_savings_estimate?: number
  [k: string]: unknown
}

export interface RemediationBranch {
  steps?: RemediationStep[]
  step_count?: number
  current_rsi?: number
  simulated_rsi?: number
  rsi_improvement?: number
  current_financial_impact?: MoneyTriple
  simulated_financial_impact?: MoneyTriple
  total_potential_savings?: number
}

export interface Insurance {
  rsi?: RsiBranch
  financial_impact?: FinancialImpact
  dbi?: DbiBranch
  remediation?: RemediationBranch
  // older scans store an int; current scanner stores { total, breakdown }
  critical_findings?: number | { total?: number; breakdown?: Record<string, number> }
  peer_benchmarking?: Record<string, unknown>
  compliance?: Record<string, unknown>
  [k: string]: unknown
}

export interface ScanContext {
  industry?: string
  annual_revenue?: number
  country?: string
  sub_industry?: string
  annual_revenue_zar?: number
  [k: string]: unknown
}

export interface WafStatus {
  blocked?: boolean
  kind?: 'none' | 'waf_challenge' | 'waf_blocked' | 'waf_rate_limited' | 'waf_timeout'
  evidence?: string
  codes?: Record<string, number>
  samples?: number
}

export interface ScanCompleteness {
  total_checkers?: number
  coverage_pct?: number
  waf_status?: WafStatus
  waf_affected_checkers?: string[]
  slowest_checker?: [string, number]
  total_checker_seconds?: number
}

export interface ComplianceControl {
  status?: 'pass' | 'partial' | 'fail' | 'no_data'
  score?: number
  description?: string
  checkers?: string[]
  findings?: string[]
}

export interface ComplianceFramework {
  overall_pct?: number
  controls?: Record<string, ComplianceControl>
}

export interface Results {
  domain_scanned: string
  scan_timestamp: string
  overall_risk_score: number
  risk_level: string
  discovered_ips?: string[]
  scan_context?: ScanContext
  categories: Record<string, CategoryBase>
  recommendations?: string[]
  insurance?: Insurance
  compliance?: Record<string, ComplianceFramework>
  _scan_completeness?: ScanCompleteness
  scan_id?: string
  [k: string]: unknown
}
