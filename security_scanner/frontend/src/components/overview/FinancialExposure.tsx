import Panel from '../primitives/Panel'
import EmptyState from '../primitives/EmptyState'
import { fmtZar, fmtPct, fmtNum } from '../../data/results'
import { getFinancialSummary } from '../../data/selectors'
import type { MonteCarloSummary } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './FinancialExposure.module.css'

const COMP_COLORS = ['var(--critical)', 'var(--high)', 'var(--warning)', 'var(--info)', 'var(--accent)']

/**
 * Monte Carlo probability-interval visual: the coloured band shows where the
 * modelled annual loss is likely to fall. Inner (darker) band = central 50% of
 * outcomes, outer band = central 90%; the full track spans P5 → the 1-in-250
 * tail (P99.6). The median marker sits on the most-likely outcome.
 */
function McDistribution({ mc }: { mc: MonteCarloSummary }) {
  const lo = mc.p5 ?? 0
  const hi = mc.p99_6 ?? mc.p95 ?? lo + 1
  const span = Math.max(hi - lo, 1)
  const at = (v: number | null) => `${Math.max(0, Math.min(100, (((v ?? lo) - lo) / span) * 100))}%`
  const band = (a: number | null, b: number | null) => ({ left: at(a), right: `calc(100% - ${at(b)})` })
  return (
    <div className={styles.mc}>
      <div className={styles.mcTrack}>
        {mc.ci90 && (
          <span className={styles.mcBand90} style={band(mc.ci90.lower, mc.ci90.upper)}
            title={`90% of modelled outcomes: ${fmtZar(mc.ci90.lower)} – ${fmtZar(mc.ci90.upper)}`} />
        )}
        {mc.ci50 && (
          <span className={styles.mcBand50} style={band(mc.ci50.lower, mc.ci50.upper)}
            title={`50% of modelled outcomes: ${fmtZar(mc.ci50.lower)} – ${fmtZar(mc.ci50.upper)}`} />
        )}
        {mc.mean != null && <span className={styles.mcMean} style={{ left: at(mc.mean) }} title={`Mean ${fmtZar(mc.mean)}`} />}
        <span className={styles.mcMedian} style={{ left: at(mc.p50) }} title={`Median (most likely) ${fmtZar(mc.p50)}`} />
      </div>
      <div className={styles.mcScale}>
        <span><b>{fmtZar(mc.p5)}</b><i>P5 · low</i></span>
        <span className={styles.mcScaleMid}><b>{fmtZar(mc.p50)}</b><i>Median</i></span>
        <span className={styles.mcScaleMid}><b>{fmtZar(mc.p95)}</b><i>P95 · severe</i></span>
        <span className={styles.mcScaleEnd}><b>{fmtZar(mc.p99_6)}</b><i>1-in-250</i></span>
      </div>
      <div className={styles.mcLegend}>
        <span><i className={styles.lg50} />Central 50%</span>
        <span><i className={styles.lg90} />Central 90%</span>
        <span><i className={styles.lgMed} />Median{mc.iterations ? ` · ${fmtNum(mc.iterations)} simulations` : ''}</span>
      </div>
    </div>
  )
}

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

        {/* Middle — Monte Carlo modelled-loss distribution (probability interval).
            Falls back to a simple min/likely/max range on older scans that
            carry no Monte Carlo block. */}
        <div className={styles.dist}>
          <div className={styles.distHead}>Modelled annual-loss range</div>
          {fin.monteCarlo.available ? (
            <McDistribution mc={fin.monteCarlo} />
          ) : (
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
          )}
          <p className={styles.disclaimer}>
            Distribution is derived from the assessment's Monte Carlo loss model on externally observable
            exposure and South African industry breach-cost data. Indicative only — not a guarantee of loss.
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
