import { Info, TrendingUp, ShieldCheck, Coins } from 'lucide-react'
import Panel from '../primitives/Panel'
import EmptyState from '../primitives/EmptyState'
import { SeverityDot } from '../primitives/Status'
import OverallRiskGauge from './OverallRiskGauge'
import { fmtZar } from '../../data/results'
import {
  getOverallAssessment, getRsiSummary, getDbiSummary, getFinancialSummary,
} from '../../data/selectors'
import type { Results } from '../../types/results'
import { SEVERITY_COLOR } from '../../data/checkerState'
import styles from './ExecutiveStrip.module.css'

function Tip({ text }: { text: string }) {
  return <span className={styles.tip} tabIndex={0} role="note" aria-label={text}><Info size={12} /><span className={styles.tipBody}>{text}</span></span>
}

export default function ExecutiveStrip({ r }: { r: Results }) {
  const oa = getOverallAssessment(r)!
  const rsi = getRsiSummary(r)
  const dbi = getDbiSummary(r)
  const fin = getFinancialSummary(r)

  const rsiPct = rsi.score != null ? Math.min(1, rsi.score) : 0
  const basePct = rsi.baseScore != null ? Math.min(1, rsi.baseScore) : 0

  return (
    <div className={styles.grid}>
      {/* Panel 1 — Overall Risk Score */}
      <Panel title="Overall Risk Score" fill>
        <div className={styles.gaugeBox}>
          <OverallRiskGauge score={oa.score} max={oa.max} color={oa.band.color} level={`${oa.band.label}`} />
          {oa.criticalFindings != null && oa.criticalFindings > 0 && (
            <div className={styles.critNote}>
              <SeverityDot severity="critical" />
              {oa.criticalFindings} critical finding{oa.criticalFindings === 1 ? '' : 's'}
            </div>
          )}
        </div>
      </Panel>

      {/* Panel 2 — Ransomware Susceptibility */}
      <Panel title="Ransomware Susceptibility" action={<Tip text="RSI — modelled likelihood of a successful ransomware event from externally observable exposure, 0 (low) to 1 (high)." />} fill>
        {rsi.available ? (
          <div className={styles.metricBody}>
            <div className={styles.bigRow}>
              <span className={styles.big} style={{ color: SEVERITY_COLOR[rsi.severity] }}>{rsi.score!.toFixed(3)}</span>
              <span className={styles.outOf}>/ 1.000</span>
              <span className={styles.tag} style={{ color: SEVERITY_COLOR[rsi.severity], background: `${SEVERITY_COLOR[rsi.severity]}1f` }}>{rsi.label}</span>
            </div>
            <div className={styles.compTrack} aria-hidden>
              <span className={styles.compBase} style={{ width: `${basePct * 100}%` }} />
              <span className={styles.compAdd} style={{ width: `${Math.max(0, (rsiPct - basePct)) * 100}%`, background: SEVERITY_COLOR[rsi.severity] }} />
            </div>
            <div className={styles.subline}>
              <span>Base score <strong>{rsi.baseScore?.toFixed(3) ?? '—'}</strong></span>
              {rsi.factors[0] && <span className={styles.factorHint}>+{rsi.factors[0].impact.toFixed(2)} {rsi.factors[0].factor}</span>}
            </div>
          </div>
        ) : <EmptyState compact title="RSI unavailable">Ransomware index not produced for this scan.</EmptyState>}
      </Panel>

      {/* Panel 3 — Data Breach Resilience */}
      <Panel title="Data Breach Resilience" icon={<ShieldCheck size={14} />} fill>
        {dbi.available ? (
          <div className={styles.metricBody}>
            <div className={styles.bigRow}>
              <span className={styles.big} style={{ color: SEVERITY_COLOR[dbi.severity] }}>{dbi.score}</span>
              <span className={styles.outOf}>/ {dbi.max}</span>
              <span className={styles.tag} style={{ color: SEVERITY_COLOR[dbi.severity], background: `${SEVERITY_COLOR[dbi.severity]}1f` }}>{dbi.label}</span>
            </div>
            <div className={styles.dbiBars} aria-hidden>
              {dbi.components.map((c) => (
                <span key={c.key} className={styles.dbiSeg} title={`${c.label}: ${c.points}/${c.max}`}>
                  <span style={{ height: `${(c.points / Math.max(1, c.max)) * 100}%`,
                    background: c.points >= c.max ? 'var(--positive)' : c.points > 0 ? 'var(--warning)' : 'var(--border-emphasis)' }} />
                </span>
              ))}
            </div>
            <div className={styles.subline}>
              <span>Breaches <strong>{dbi.breachCount ?? '—'}</strong></span>
              <span>Cred. leaks <strong>{dbi.credentialLeaks ?? '—'}</strong></span>
              {dbi.trend && <span className={styles.trend}><TrendingUp size={12} /> {dbi.trend}</span>}
            </div>
          </div>
        ) : <EmptyState compact title="Breach index unavailable" />}
      </Panel>

      {/* Panel 4 — Financial Exposure */}
      <Panel title="Financial Exposure" icon={<Coins size={14} />} fill>
        {fin.available ? (
          <div className={styles.finGrid}>
            <div className={styles.finPrimary}>
              <span className={styles.finLabel}>Expected annual loss</span>
              <span className={styles.finBig}>{fmtZar(fin.expectedAnnualLoss)}</span>
              <span className={styles.finRange}>{fmtZar(fin.loss.min)} – {fmtZar(fin.loss.max)} range</span>
            </div>
            <dl className={styles.finStats}>
              <div><dt>Premium tier</dt><dd>{fin.premiumTier ?? '—'}</dd></div>
              <div><dt>Catastrophe (1-in-250)</dt><dd>{fmtZar(fin.catastropheExposure)}</dd></div>
              <div><dt>Loss scenarios</dt><dd>{fin.scenarios.length ? `${fin.scenarios.length} modelled` : '—'}</dd></div>
              <div><dt>Top scenario</dt><dd>{fin.scenarios[0] ? `${fin.scenarios[0].label} · ${fmtZar(fin.scenarios[0].loss)}` : '—'}</dd></div>
            </dl>
          </div>
        ) : <EmptyState compact title="Financial model unavailable">No financial exposure values were produced for this scan.</EmptyState>}
      </Panel>
    </div>
  )
}
