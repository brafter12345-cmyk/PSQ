import type { ReactNode } from 'react'
import styles from './EvidenceTable.module.css'

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  align?: 'left' | 'right' | 'center'
  width?: string
}

export default function EvidenceTable<T>({
  columns, rows, getKey, empty, onRowClick,
}: {
  columns: Array<Column<T>>
  rows: T[]
  getKey: (row: T, i: number) => string
  empty?: ReactNode
  /** When set, rows become clickable (cursor + hover) and invoke this on click. */
  onRowClick?: (row: T) => void
}) {
  if (rows.length === 0) {
    return <div className={styles.empty}>{empty ?? 'No records.'}</div>
  }
  return (
    <div className={styles.scroll}>
      <table className={styles.table}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={{ textAlign: c.align ?? 'left', width: c.width }}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={getKey(row, i)}
              className={onRowClick ? styles.clickable : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              role={onRowClick ? 'button' : undefined}
              onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(row) } } : undefined}>
              {columns.map((c) => (
                <td key={c.key} style={{ textAlign: c.align ?? 'left' }}>{c.render(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
