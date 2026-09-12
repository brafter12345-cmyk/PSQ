/**
 * The Email-Vendor panel's content and badge, from the S-4
 * (email_vendor_surface) result. Self-contained (no runtime imports) so the
 * regression gate runs it under node on the real checker's output (step-5
 * critique rounds 8 to 10).
 *
 * Rows only for a measured result: a lookup that did not answer, a record the
 * walk does not follow, and a result stored before the lookup was recorded are
 * not assessed; a walk that found a vendor beside one of those read part of the
 * chain, so its vendors are a lower bound and the badge never reads as a pass.
 * The checker stores its vendors as {vendor, includes} and its includes as
 * {include, depth}; a plain string is kept as it is.
 */
export interface VendorPanelRow {
  label: string
  value: string
  severity?: 'medium' | 'positive'
}

export interface VendorPanelBadge {
  state: string
  label?: string
}

export type VendorPanel =
  | { kind: 'rows'; rows: VendorPanelRow[]; badge?: VendorPanelBadge }
  | { kind: 'empty'; title: string; badge?: VendorPanelBadge }

function names(list: unknown, key: string): string[] {
  if (!Array.isArray(list)) return []
  return list
    .map((x) => (typeof x === 'string' ? x : String((x as Record<string, unknown> | null)?.[key] ?? '')))
    .filter(Boolean)
}

/** Why the result is not a measurement of the vendor surface, or '' where it is. */
export function vendorSurfaceUnmeasured(v: Record<string, unknown> | undefined): string {
  if (!v) return ''
  const how = v.spf_lookup
  if (v.status === 'no_data') {
    if (how === 'answered') return ''
    if (how === 'failed') return 'an SPF lookup did not answer'
    if (how === 'not_followed') {
      return 'a record in the SPF chain redirects to another record, which the check does not follow'
    }
    if (how === undefined) {
      return 'stored by an earlier version of the check, which did not record whether the SPF lookup answered'
    }
    return 'the SPF lookup is not recorded as answered'
  }
  if (v.status === 'completed') {
    // "partial" is a measurement as far as it went; vendorSurfacePartial marks
    // the rest. A result stored before the outcome was recorded is a lower
    // bound where it named a vendor, and unverifiable where it named none.
    if (how === 'answered' || how === 'partial') return ''
    if (how === undefined) {
      return vendorSurfacePartial(v)
        ? ''
        : 'stored by an earlier version of the check, which did not record whether every SPF lookup answered'
    }
    return 'the SPF lookup is not recorded as answered'
  }
  return ''
}

/** Only part of the SPF chain was read: the walk recorded it, or the result was
 *  stored before the outcome was recorded and still named a vendor, which is
 *  the shape the earlier check wrote for exactly that walk. */
export function vendorSurfacePartial(v: Record<string, unknown> | undefined): boolean {
  if (!v) return false
  if (v.spf_lookup === 'partial') return true
  return v.status === 'completed' && v.spf_lookup === undefined
    && (names(v.vendors_detected, 'vendor').length > 0 || !!v.vendor_count)
}

/** What a generic panel renders for one checker: the note, or the counts.
 *
 *  `notAssessed` is the caller's badge decision (checkerState.panelShowsCounts)
 *  and `isSpf` says whether this checker carries an SPF chain at all. Both are
 *  parameters so this module keeps no imports and the regression gate can run
 *  it under node exactly as it ships (step-5 critique round 13, GS13-2,
 *  GS13-3). */
export function panelBody(
  v: Record<string, unknown> | undefined,
  opts: { notAssessed: boolean; isSpf: boolean },
): { kind: 'note' | 'counts'; lowerBound: boolean } {
  if (opts.notAssessed) return { kind: 'note', lowerBound: false }
  return { kind: 'counts', lowerBound: !!opts.isSpf && vendorSurfacePartial(v) }
}

export function vendorPanel(v: Record<string, unknown> | undefined): VendorPanel {
  const why = vendorSurfaceUnmeasured(v)
  if (why) {
    return { kind: 'empty', title: 'Not assessed: ' + why,
      badge: { state: 'not_assessed', label: 'Not assessed' } }
  }
  if (v && v.status === 'completed') {
    const vendors = names(v.vendors_detected, 'vendor')
    const includes = names(v.spf_includes, 'include')
    const partial = vendorSurfacePartial(v)
    const weak = !!v.weak_dmarc
    const rows: VendorPanelRow[] = [
      { label: 'Vendors detected', value: vendors.length ? vendors.join(', ') : 'None identified' },
      { label: 'SPF includes', value: includes.join(', ') || '—' },
      { label: 'Weak DMARC', value: weak ? 'Yes' : 'No', severity: weak ? 'medium' : 'positive' },
    ]
    if (partial) {
      rows.push({ label: 'SPF chain', severity: 'medium',
        value: 'Partly read: a lookup did not answer, or a record redirects, so the vendors above are a lower bound' })
    }
    const finding: VendorPanelBadge | null = weak && vendors.length > 0
      ? { state: 'failed' }
      : vendors.length >= 6 ? { state: 'warning' } : null
    const badge = finding
      ?? (partial ? { state: 'warning', label: 'Partly assessed' } : { state: 'completed' })
    return { kind: 'rows', rows, badge }
  }
  if (v && v.status === 'no_data') {
    return { kind: 'rows', badge: { state: 'completed' },
      rows: [{ label: 'Vendors detected', value: 'None: no SPF includes are published' }] }
  }
  return { kind: 'empty', title: 'No vendor-surface data' }
}
