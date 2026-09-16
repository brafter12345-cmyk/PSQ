import { useState } from 'react'
import { ShieldAlert, ChevronDown, X } from 'lucide-react'
import { getCoverageSummary, CATEGORY_LABELS } from '../../data/selectors'
import type { Results } from '../../types/results'
import styles from './CoverageBanner.module.css'

export default function CoverageBanner({ r, onReview }: { r: Results; onReview?: (cat: string) => void }) {
  const cov = getCoverageSummary(r)
  const [expanded, setExpanded] = useState(false)
  const [dismissed, setDismissed] = useState(false)

  const hasMissing = cov.missingCheckers.length > 0
  const hasFailed = cov.failedCheckers.length > 0
  const scoreUnqualified = cov.scoreQualified === true ||
    (cov.confidenceLevel != null && cov.confidenceLevel.toLowerCase() !== 'full')
  if ((!cov.blocked && !hasMissing && !hasFailed && !scoreUnqualified) || dismissed) return null
  const qualification = (scoreUnqualified || cov.disclaimer)
    ? `Score qualification: ${cov.disclaimer ?? cov.confidenceLevel ?? 'incomplete'}`
    : null
  const facts = [
    cov.completenessPct != null ? `${cov.completenessPct}% assessment completeness` : null,
    cov.blocked && cov.coveragePct != null ? `${cov.coveragePct}% external visibility` : null,
    cov.blocked ? `${cov.affectedCount} affected checker${cov.affectedCount === 1 ? '' : 's'}` : null,
    cov.blocked ? 'Active blocking detected' : null,
    hasMissing ? `${cov.missingCheckers.length} raw checker${cov.missingCheckers.length === 1 ? '' : 's'} missing` : null,
    hasFailed ? `${cov.failedCheckers.length} raw checker${cov.failedCheckers.length === 1 ? '' : 's'} failed` : null,
    cov.blocked ? cov.probeSummary : null,
    qualification,
  ].filter(Boolean) as string[]

  return (
    <div className={styles.banner}>
      <div className={styles.head}>
        <span className={styles.icon}><ShieldAlert size={16} /></span>
        <div className={styles.headText}>
          <div className={styles.title}>{cov.blocked
            ? 'Partial External Visibility — WAF / Bot-Manager Intervention Detected'
            : 'Assessment coverage incomplete'}</div>
          <div className={styles.facts}>
            {facts.map((f, i) => <span key={i} className={styles.fact}>{f}</span>)}
          </div>
        </div>
        <div className={styles.actions}>
          <button className={styles.review} type="button" onClick={() => setExpanded((e) => !e)} aria-expanded={expanded}>
            Review affected checks <ChevronDown size={13} className={expanded ? styles.chevUp : ''} />
          </button>
          <button className={styles.dismiss} type="button" onClick={() => setDismissed(true)} aria-label="Dismiss coverage notice">
            <X size={15} />
          </button>
        </div>
      </div>

      {expanded && (
        <div className={styles.detail}>
          <p>
            {cov.blocked
              ? <>Protective infrastructure on this target actively intervened during the scan.
                The <strong>absence of findings does not confirm the absence of risk</strong> — the
                scanner could not verify the affected checks. A scan from a different source IP, or
                coordination with the target's security team, may be required to complete coverage.</>
              : <>The assessment has limited coverage. Review the score qualification before relying on the result.
                Missing and failed checkers are not assessed, not clean.</>}
          </p>
          {cov.blocked && cov.affectedCheckers.length > 0 && (
            <div className={styles.affected}>
              <span className={styles.affectedLabel}>Affected checks (not assessed):</span>
              <div className={styles.chips}>
                {cov.affectedCheckers.map((c) => (
                  <button key={c} type="button" className={styles.chip} onClick={() => onReview?.(c)}>
                    {CATEGORY_LABELS[c] ?? c.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>
            </div>
          )}
          {hasMissing && <div className={styles.affected}>
            <span className={styles.affectedLabel}>Missing raw checks (not assessed):</span>
            <div className={styles.chips}>{cov.missingCheckers.map((c) => <button key={c} type="button" className={styles.chip} onClick={() => onReview?.(c)}>{CATEGORY_LABELS[c] ?? c.replace(/_/g, ' ')}</button>)}</div>
          </div>}
          {hasFailed && <div className={styles.affected}>
            <span className={styles.affectedLabel}>Failed raw checks (not assessed):</span>
            <div className={styles.chips}>{cov.failedCheckers.map((c) => <button key={c} type="button" className={styles.chip} onClick={() => onReview?.(c)}>{CATEGORY_LABELS[c] ?? c.replace(/_/g, ' ')}</button>)}</div>
          </div>}
        </div>
      )}
    </div>
  )
}
