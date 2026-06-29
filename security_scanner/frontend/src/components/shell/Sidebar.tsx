import { NavLink } from 'react-router-dom'
import { ShieldHalf, ChevronDown } from 'lucide-react'
import { NAV, type NavItem } from './nav'
import { getScanMeta } from '../../data/results'
import styles from './Sidebar.module.css'
import { withBase } from '../../base'

function pdfUrl(scanId: string, type: string): string {
  const t = type === 'raw' ? '' : `?type=${type}`
  return withBase(type === 'raw' ? `/api/scan/${scanId}` : `/api/scan/${scanId}/pdf${t}`)
}

function ItemLink({ item, scanId }: { item: NavItem; scanId: string }) {
  const Icon = item.icon
  if (item.report) {
    return (
      <a className={styles.item} href={pdfUrl(scanId, item.report)} target="_blank" rel="noreferrer">
        <span className={styles.rail} aria-hidden />
        <Icon size={16} strokeWidth={1.9} />
        <span className={styles.label}>{item.label}</span>
      </a>
    )
  }
  if (item.disabled) {
    return (
      <span className={`${styles.item} ${styles.disabled}`} title="Coming soon" aria-disabled>
        <span className={styles.rail} aria-hidden />
        <Icon size={16} strokeWidth={1.9} />
        <span className={styles.label}>{item.label}</span>
      </span>
    )
  }
  return (
    <NavLink
      to={item.to ?? '/'}
      end={item.to === '/'}
      className={({ isActive }) => `${styles.item} ${isActive ? styles.active : ''}`}
    >
      <span className={styles.rail} aria-hidden />
      <Icon size={16} strokeWidth={1.9} />
      <span className={styles.label}>{item.label}</span>
    </NavLink>
  )
}

export default function Sidebar() {
  const { scanId } = getScanMeta()
  return (
    <aside className={styles.sidebar}>
      <div className={styles.brand}>
        <span className={styles.logo}><ShieldHalf size={20} strokeWidth={2} /></span>
        <div className={styles.brandText}>
          <span className={styles.brandName}>PHISHIELD</span>
          <span className={styles.brandSub}>CYBER PROTECT</span>
        </div>
      </div>

      <nav className={styles.nav} aria-label="Primary">
        {NAV.map((group) => (
          <div className={styles.group} key={group.label}>
            <div className={styles.groupLabel}>{group.label}</div>
            {group.items.map((item) => (
              <ItemLink key={item.label} item={item} scanId={scanId} />
            ))}
          </div>
        ))}
      </nav>

      <button className={styles.account} type="button">
        <span className={styles.avatar}>AU</span>
        <span className={styles.accountText}>
          <span className={styles.accountName}>Admin User</span>
          <span className={styles.accountRole}>Team Owner</span>
        </span>
        <ChevronDown size={15} className={styles.accountChevron} />
      </button>
    </aside>
  )
}
