import { useEffect, useState } from 'react'
import { FileText, X, AlertTriangle, Check } from 'lucide-react'
import { getResults } from '../../data/results'
import { apiFetch } from '../../base'

// Client meeting brief: a short, client-facing companion to the full report.
//
// Password FINGERPRINTS (first character + length) are opt-in and are the only
// part of this that spends money or touches a third party — the scan stores no
// password material at all, so a fingerprint needs a fresh paged query at one
// credit per page. The estimated cost is shown BEFORE the operator commits, and a
// reason is mandatory, because the resulting PDF carries credential indicators for
// the client's own accounts and someone has to own that decision.
//
// The audit trail below is only as good as the username the edge proxy forwards;
// the app has no authentication of its own (OUTSTANDING §4b).

interface Options {
  domain: string
  user: string
  fingerprints_available: boolean
  fingerprints_unavailable_reason: string
  estimated_credits: number | null
  record_count: number | null
}

interface AuditRow {
  id: string
  domain: string
  generated_by: string
  fingerprints: number
  reason: string
  credits_spent: number
  created_at: string
}

const I = {
  fontSize: 12.5, padding: '8px 10px', borderRadius: 8,
  background: 'var(--panel-bg-elevated)', border: '1px solid var(--border-emphasis)',
  color: 'var(--text-primary)', width: '100%', fontFamily: 'inherit',
} as const

export default function MeetingBriefPanel() {
  const scanId = getResults()?.scan_id ?? ''
  const [open, setOpen] = useState(false)
  const [opts, setOpts] = useState<Options | null>(null)
  const [withFp, setWithFp] = useState(false)       // OFF unless explicitly turned on
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)
  const [audit, setAudit] = useState<AuditRow[]>([])

  useEffect(() => {
    if (!scanId) return
    let live = true
    apiFetch(`/api/scan/${scanId}/brief/options`)
      .then((r) => r.json())
      .then((d) => { if (live && !d.error) setOpts(d as Options) })
      .catch(() => { /* panel simply stays hidden */ })
    return () => { live = false }
  }, [scanId])

  const loadAudit = () => {
    apiFetch('/api/brief-audit')
      .then((r) => r.json())
      .then((d) => setAudit((d.entries || []) as AuditRow[]))
      .catch(() => setAudit([]))
  }

  useEffect(() => { if (open) loadAudit() }, [open])

  const close = () => {
    setOpen(false); setWithFp(false); setReason('')
    setError(null); setBusy(false); setDone(false)
  }

  const generate = async () => {
    if (withFp && !reason.trim()) { setError('Enter a reason first'); return }
    setBusy(true); setError(null)
    try {
      const res = await apiFetch(`/api/scan/${scanId}/brief`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ include_fingerprints: withFp, reason: reason.trim() }),
      })
      if (!res.ok) {
        const d = await res.json().catch(() => ({}))
        setError(res.status === 401 || res.status === 403 ? `Request denied (HTTP ${res.status})` : (d.error || `Request failed (HTTP ${res.status})`))
      } else {
        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `meeting-brief-${opts?.domain ?? 'scan'}.pdf`
        document.body.appendChild(a); a.click(); a.remove()
        setTimeout(() => URL.revokeObjectURL(url), 4000)
        setDone(true)
        loadAudit()
      }
    } catch (e) {
      setError(String(e))
    }
    setBusy(false)
  }

  if (!scanId || !opts) return null

  return (
    <>
      <button onClick={() => setOpen(true)}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 7, marginTop: 10,
          padding: '7px 12px', borderRadius: 8, fontSize: 12, fontWeight: 600,
          color: 'var(--text-primary)', background: 'var(--panel-bg-elevated)',
          border: '1px solid var(--border-emphasis)' }}>
        <FileText size={13} /> Generate meeting brief
      </button>

      {open && (
        <div onClick={close} style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,14,0.66)',
          display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: 'min(600px, 96vw)',
            maxHeight: '90vh', overflowY: 'auto', background: 'var(--panel-bg)',
            border: '1px solid var(--border-emphasis)', borderRadius: 14, padding: 20 }}>

            <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 2 }}>
              <FileText size={18} style={{ color: 'var(--accent-bright)' }} />
              <span style={{ fontSize: 15, fontWeight: 700 }}>Meeting brief</span>
              <button onClick={close} style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}><X size={16} /></button>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 14px' }}>
              A short client-facing note built from this scan. Not the full report.
            </p>

            <Row checked disabled label="Prioritised findings and remediation sequence"
              hint="Always included." />
            <Row checked disabled label="Affected accounts, grouped by credential state"
              hint="Addresses and record counts. No password material." />

            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start',
              padding: '10px 0', borderTop: '1px solid var(--border-emphasis)' }}>
              <input type="checkbox" id="mb-fp" checked={withFp}
                disabled={!opts.fingerprints_available}
                onChange={(e) => { setWithFp(e.target.checked); setError(null) }}
                style={{ marginTop: 3 }} />
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <label htmlFor="mb-fp" style={{ fontSize: 13, cursor: 'pointer' }}>
                    Include password fingerprints
                  </label>
                  <span style={{ fontSize: 10.5, padding: '2px 8px', borderRadius: 6,
                    background: 'var(--warning-soft, var(--panel-bg-elevated))',
                    color: 'var(--warning)', fontWeight: 600 }}>Sensitive</span>
                </div>
                <p style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.55, margin: '3px 0 0' }}>
                  First character and length only, for example{' '}
                  <code style={{ fontFamily: 'var(--font-mono)' }}>K… (9 chars)</code>. Lets an
                  account owner recognise a password without it being reusable. Off unless you turn it on.
                </p>
                {opts.fingerprints_available ? (
                  <p style={{ fontSize: 11.5, color: 'var(--text-secondary)', margin: '5px 0 0' }}>
                    The scan stores no password material, so this runs a fresh query:{' '}
                    <b>about {opts.estimated_credits} credit{opts.estimated_credits === 1 ? '' : 's'}</b>
                    {opts.record_count ? ` for ${opts.record_count.toLocaleString()} records` : ''}.
                  </p>
                ) : (
                  <p style={{ fontSize: 11.5, color: 'var(--text-muted)', margin: '5px 0 0' }}>
                    Unavailable — {opts.fingerprints_unavailable_reason}.
                  </p>
                )}

                {withFp && (
                  <>
                    <div style={{ marginTop: 10, padding: '10px 12px', borderLeft: '3px solid var(--warning)',
                      background: 'var(--panel-bg-elevated)' }}>
                      <div style={{ display: 'flex', gap: 7, alignItems: 'center', marginBottom: 4 }}>
                        <AlertTriangle size={13} style={{ color: 'var(--warning)' }} />
                        <span style={{ fontSize: 12.5, color: 'var(--warning)', fontWeight: 600 }}>
                          This brief will contain client credential indicators
                        </span>
                      </div>
                      <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
                        Hand it over in person or send it encrypted.
                        {opts.user ? ` Your username (${opts.user}) is recorded against the generated file.`
                          : ' The generating user is recorded against the file.'}
                      </p>
                    </div>
                    <div style={{ marginTop: 10 }}>
                      <label style={{ fontSize: 12, color: 'var(--text-secondary)' }} htmlFor="mb-reason">
                        Reason (recorded)
                      </label>
                      <input id="mb-reason" style={{ ...I, marginTop: 4 }}
                        placeholder="Client IT session, 8 Sept" value={reason}
                        onChange={(e) => { setReason(e.target.value); setError(null) }} />
                    </div>
                  </>
                )}
              </div>
            </div>

            {error && (
              <div style={{ fontSize: 12, color: 'var(--critical)', background: 'var(--critical-soft)',
                padding: '7px 10px', borderRadius: 8, marginBottom: 10 }}>{error}</div>
            )}

            <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingTop: 12,
              borderTop: '1px solid var(--border-emphasis)' }}>
              <button onClick={generate} disabled={busy}
                style={{ padding: '9px 14px', borderRadius: 8, fontSize: 13, fontWeight: 700,
                  color: '#fff', background: busy ? 'var(--panel-hover)' : 'var(--accent)',
                  opacity: busy ? 0.6 : 1, cursor: busy ? 'not-allowed' : 'pointer' }}>
                {busy ? 'Generating…' : 'Generate brief'}
              </button>
              <span style={{ fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 5,
                color: done ? (withFp ? 'var(--warning)' : 'var(--positive)')
                  : (withFp ? 'var(--warning)' : 'var(--text-secondary)') }}>
                {done && <Check size={13} />}
                {done
                  ? (withFp ? 'Generated with fingerprints — logged' : 'Generated — no credential material')
                  : (withFp ? 'Fingerprints included — handle as confidential' : 'Fingerprints excluded')}
              </span>
            </div>

            {audit.length > 0 && (
              <div style={{ marginTop: 16, padding: '12px 14px', borderRadius: 10,
                background: 'var(--panel-bg-elevated)' }}>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 8 }}>
                  Audit trail written on every generation
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.9,
                  color: 'var(--text-secondary)' }}>
                  {audit.slice(0, 6).map((r) => (
                    <div key={r.id}>
                      {String(r.created_at).slice(0, 16).replace('T', ' ')}{'  '}
                      <span style={{ color: 'var(--text-primary)' }}>{r.generated_by || 'unknown'}</span>{'  '}
                      {r.domain}{'  '}fingerprints=
                      <span style={{ color: r.fingerprints ? 'var(--critical)' : 'inherit' }}>
                        {r.fingerprints ? 'yes' : 'no'}
                      </span>
                      {r.fingerprints && r.reason ? `  "${r.reason}"` : ''}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}

function Row({ checked, disabled, label, hint }:
  { checked: boolean; disabled: boolean; label: string; hint: string }) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', padding: '10px 0' }}>
      <input type="checkbox" checked={checked} disabled={disabled} readOnly style={{ marginTop: 3 }} />
      <div>
        <div style={{ fontSize: 13 }}>{label}</div>
        <p style={{ fontSize: 11.5, color: 'var(--text-muted)', margin: '2px 0 0' }}>{hint}</p>
      </div>
    </div>
  )
}
