import Panel from '../primitives/Panel'
import EmptyState from '../primitives/EmptyState'
import { fmtZar, fmtPct } from '../../data/results'
import { getFinancialSummary } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './FinancialExposure.module.css'

const COMP_COLORS = ['var(--critical)', 'var(--high)', 'var(--warning)', 'var(--info)', 'var(--accent)']

export default function FinancialExposure({ r }: { r: Results }) {
  const fin = getFinancialSummary(r)
  const rem = r.insurance?.remediation
  const current = fin.expectedAnnualLoss
  const mitigated = rem?.simulated_financial_impact?.most_likely ?? null
  const saving = rem?.total_potential_savings
    ?? (current != null && mitigated != null ? current - mitigated : null)
  const reduction = current && mitigated != null ? ((current - mitigated) / current) * 100 : null

  if (!fin.available) {
    return (
      <Panel title="Financial Exposure" icon={undefined}>
        <EmptyState title="Financial model unavailable">No financial exposure values were produced for this scan.</EmptyState>
      </Panel>
    )
  }

  const max = Math.max(fin.loss.max ?? 0, current ?? 0, 1)
  const pct = (v: number | null) => `${Math.max(2, Math.min(100, ((v ?? 0) / max) * 100))}%`

  return (
    <Panel title="Financial Exposure" action={<span className={styles.cur}>{fin.currency}</span>}>
      <div className={styles.grid}>
        {/* Left — summary column */}
        <div className={styles.summary}>
          <div className={styles.sBlock}>
            <span className={styles.sLabel}>Expected annual loss</span>
            <span className={styles.sBig}>{fmtZar(current)}</span>
          </div>
          <div className={styles.sBlock}>
            <span className={styles.sLabel}>Mitigated annual loss</span>
            <span className={styles.sMid} style={{ color: 'var(--positive)' }}>{fmtZar(mitigated)}</span>
          </div>
          <dl className={styles.sStats}>
            <div><dt>Potential saving</dt><dd style={{ color: 'var(--positive)' }}>{fmtZar(saving)}</dd></div>
            <div><dt>Reduction</dt><dd>{reduction != null ? fmtPct(reduction) : '—'}</dd></div>
            <div><dt>Premium tier</dt><dd>{fin.premiumTier ?? '—'}</dd></div>
            <div><dt>Catastrophe (1-in-250)</dt><dd>{fmtZar(fin.catastropheExposure)}</dd></div>
          </dl>
        </div>

        {/* Middle — modelled loss range (honest; no fabricated distribution) */}
        <div className={styles.dist}>
          <div className={styles.distHead}>Modelled annual-loss range</div>
          <div className={styles.rangeChart}>
            <div className={styles.rangeBar}>
              <span className={styles.rangeFill} style={{ left: pct(fin.loss.min), right: `calc(100% - ${pct(fin.loss.max)})` }} />
              <span className={styles.rangeMarker} style={{ left: pct(current) }} title="Expected (most likely)" />
            </div>
            <div className={styles.rangeLabels}>
              <span><b>{fmtZar(fin.loss.min)}</b><i>Low</i></span>
              <span className={styles.rangeMid}><b>{fmtZar(current)}</b><i>Expected</i></span>
              <span className={styles.rangeRight}><b>{fmtZar(fin.loss.max)}</b><i>High</i></span>
            </div>
          </div>
          <p className={styles.disclaimer}>
            Range is derived from the assessment's loss model on externally observable exposure and
            South African industry breach-cost data. Indicative only — not a guarantee of loss.
          </p>
        </div>

        {/* Right — scenario ladder + composition */}
        <div className={styles.right}>
          <div className={styles.distHead}>Loss scenarios</div>
          {fin.scenarios.length ? (
            <>
              <ul className={styles.ladder}>
                {fin.scenarios.map((s) => (
                  <li key={s.key}><span className={styles.ladderLabel}>{s.label}</span><span className={styles.ladderVal}>{fmtZar(s.loss)}</span></li>
                ))}
              </ul>
              <div className={styles.compBar}>
                {fin.composition.map((c, i) => (
                  <span key={c.key} style={{ width: `${c.share * 100}%`, background: COMP_COLORS[i % COMP_COLORS.length] }} title={`${c.label} ${Math.round(c.share * 100)}%`} />
                ))}
              </div>
              <div className={styles.compLegend}>
                {fin.composition.map((c, i) => (
                  <span key={c.key}><i style={{ background: COMP_COLORS[i % COMP_COLORS.length] }} />{c.label}</span>
                ))}
              </div>
            </>
          ) : <EmptyState compact title="No scenario breakdown available" />}
        </div>
      </div>
    </Panel>
  )
}
