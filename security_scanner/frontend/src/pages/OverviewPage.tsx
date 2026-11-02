import { useState, useCallback } from 'react'
import CategoryTabs from '../components/shell/CategoryTabs'
import Footer from '../components/shell/Footer'
import ExecutiveStrip from '../components/overview/ExecutiveStrip'
import CoverageBanner from '../components/overview/CoverageBanner'
import RiskSnapshot from '../components/overview/RiskSnapshot'
import KeyFindings from '../components/overview/KeyFindings'
import RiskFactors from '../components/overview/RiskFactors'
import AttackPath from '../components/overview/AttackPath'
import Alerts from '../components/overview/Alerts'
import QuickActions from '../components/overview/QuickActions'
import FinancialExposure from '../components/overview/FinancialExposure'
import RemediationQueue from '../components/overview/RemediationQueue'
import ComplianceMatrix from '../components/overview/ComplianceMatrix'
import PeerBenchmark from '../components/overview/PeerBenchmark'
import EvidenceDrawer, { type DrawerTarget } from '../components/drawer/EvidenceDrawer'
import { PartialCoverageNote } from '../components/detail/parts'
import { getResults } from '../data/results'
import { networkCoverageNotes } from '../data/selectors'
import styles from './OverviewPage.module.css'

export default function OverviewPage() {
  const r = getResults()!
  const [drawer, setDrawer] = useState<DrawerTarget | null>(null)
  const openCat = useCallback((id: string) => {
    setDrawer(id === 'coverage' ? { kind: 'coverage', id } : { kind: 'category', id })
  }, [])

  return (
    <>
      <CategoryTabs />
      <ExecutiveStrip r={r} onOpenCritical={() => setDrawer({ kind: 'critical' })} />
      <CoverageBanner r={r} onReview={openCat} />
      {networkCoverageNotes(r).map(({ label, category }) =>
        <PartialCoverageNote key={label} label={label} category={category} />)}

      <div className={styles.mainGrid}>
        <div className={styles.col}>
          <RiskSnapshot r={r} onDrill={openCat} />
          <KeyFindings r={r} onDrill={openCat} />
        </div>
        <div className={styles.col}>
          <RiskFactors r={r} />
          <AttackPath r={r} onDrill={openCat} />
        </div>
        <div className={styles.col}>
          <Alerts r={r} onDrill={openCat} />
          <QuickActions />
        </div>
      </div>

      <div className={styles.financialRow}>
        <FinancialExposure r={r} />
        <RemediationQueue r={r} />
      </div>

      <div className={styles.complianceRow}>
        <ComplianceMatrix r={r} />
        <PeerBenchmark r={r} />
      </div>

      <Footer />
      <EvidenceDrawer target={drawer} onClose={() => setDrawer(null)} onNavigate={setDrawer} />
    </>
  )
}
