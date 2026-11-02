import { useEffect, useState } from 'react'
import { KeyRound, ShieldCheck, X, Copy, Check, Lock } from 'lucide-react'
import { getResults } from '../../data/results'
import { apiFetch } from '../../base'

// Manual 6.4 authorisation portal: the ONLY route to the unmasked credential list
// (incl. actual passwords). Captures the signed-consent authorisation + the client's
// age public key, calls /api/credential-export, and surfaces the one-time, expiring
// download link the broker forwards to the client. The scanner encrypts to the
// client's key and cannot read the file; nothing unmasked is ever rendered here.

interface ExportResult {
  download_url: string
  filename: string
  method: string
  record_count: number
  expires_at: string
  expires_in_minutes: number
}

const I = { fontSize: 12.5, padding: '8px 10px', borderRadius: 8, background: 'var(--panel-bg-elevated)',
  border: '1px solid var(--border-emphasis)', color: 'var(--text-primary)', width: '100%', fontFamily: 'inherit' } as const

export default function CredentialExportPortal() {
  const domain = getResults()?.domain_scanned ?? ''
  const [open, setOpen] = useState(false)
  const [consent, setConsent] = useState(false)
  const [authorisedBy, setAuthorisedBy] = useState('')
  const [consentRef, setConsentRef] = useState('')
  const [useAge, setUseAge] = useState(true)
  const [ageKey, setAgeKey] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ExportResult | null>(null)
  const [copied, setCopied] = useState(false)
  // Server decides. The API fails closed on its own, but asking up front lets us
  // present the control as unavailable instead of letting a broker complete a
  // consent attestation and only then hit a 503.
  const [enabled, setEnabled] = useState<boolean | null>(null)
  const [disabledReason, setDisabledReason] = useState('')

  useEffect(() => {
    let live = true
    apiFetch('/api/credential-export/status')
      .then((r) => r.json())
      .then((d) => { if (live) { setEnabled(!!d.enabled); setDisabledReason(d.reason || '') } })
      .catch(() => { if (live) setEnabled(false) })   // unreachable -> assume off
    return () => { live = false }
  }, [])

  const close = () => {
    setOpen(false); setResult(null); setError(null); setBusy(false); setCopied(false)
    setConsent(false); setAuthorisedBy(''); setConsentRef(''); setAgeKey(''); setPassphrase('')
  }

  const canSubmit = consent && authorisedBy.trim().length > 1 &&
    (useAge ? ageKey.trim().startsWith('age1') : passphrase.length >= 8)

  const submit = async () => {
    setBusy(true); setError(null)
    try {
      const body: Record<string, unknown> = {
        domain, consent, authorised_by: authorisedBy.trim(), consent_ref: consentRef.trim(),
      }
      if (useAge) body.age_public_key = ageKey.trim()
      else body.passphrase = passphrase
      const res = await apiFetch('/api/credential-export', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok || data.status === 'error') {
        setError(res.status === 401 || res.status === 403 ? `Request denied (HTTP ${res.status})` : (data.error || `Request failed (HTTP ${res.status})`))
      } else {
        setResult(data as ExportResult)
      }
    } catch (e) {
      setError(String(e))
    }
    setBusy(false)
  }

  const fullLink = result ? `${location.origin}${result.download_url}` : ''
  const copy = () => { navigator.clipboard?.writeText(fullLink).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1800) }) }

  if (enabled === null) return null            // don't flash a control we may disable

  if (!enabled) {
    return (
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 10, padding: '9px 11px',
        borderRadius: 8, fontSize: 11.5, lineHeight: 1.5, color: 'var(--text-secondary)',
        background: 'var(--panel-bg-elevated)', border: '1px solid var(--border-emphasis)' }}>
        <Lock size={13} style={{ marginTop: 2, flexShrink: 0, color: 'var(--text-muted)' }} />
        <span>
          <b style={{ color: 'var(--text-primary)' }}>Credential export unavailable.</b>{' '}
          {disabledReason || 'Releasing the client’s actual breached passwords requires the '
            + 'signed-consent authorisation flow, which is not live on this deployment.'}
        </span>
      </div>
    )
  }

  return (
    <>
      <button onClick={() => setOpen(true)}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 7, marginTop: 10, padding: '7px 12px',
          borderRadius: 8, fontSize: 12, fontWeight: 600, color: 'var(--accent-bright)',
          background: 'var(--accent-soft)', border: '1px solid var(--border-emphasis)' }}>
        <KeyRound size={13} /> Request encrypted export (incl. passwords)
      </button>

      {open && (
        <div onClick={close} style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,14,0.66)',
          display: 'grid', placeItems: 'center', zIndex: 1000, padding: 20 }}>
          <div onClick={(e) => e.stopPropagation()} style={{ width: 'min(560px, 96vw)', maxHeight: '90vh',
            overflowY: 'auto', background: 'var(--panel-bg)', border: '1px solid var(--border-emphasis)',
            borderRadius: 14, padding: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 4 }}>
              <ShieldCheck size={18} style={{ color: 'var(--accent-bright)' }} />
              <span style={{ fontSize: 15, fontWeight: 700 }}>Encrypted Credential Export</span>
              <button onClick={close} style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}><X size={16} /></button>
            </div>

            {!result ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, margin: '2px 0 4px' }}>
                  Generates the complete credential list <b>including actual passwords</b> for <b>{domain}</b>,
                  encrypted to the client's own key so the scanner cannot read it, delivered as a
                  one-time expiring link. Requires the client's signed consent (Manual §6.4).
                </p>

                <label style={{ display: 'flex', gap: 9, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--text-primary)' }}>
                  <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} style={{ marginTop: 2 }} />
                  <span>I confirm the client's <b>signed consent</b> has been obtained. This is the authorisation gate and FAIS / POPIA audit trail.</span>
                </label>

                <input style={I} placeholder="Authorised by — your name (recorded for audit)" value={authorisedBy} onChange={(e) => setAuthorisedBy(e.target.value)} />
                <input style={I} placeholder="Consent reference (optional — e.g. signed form ID)" value={consentRef} onChange={(e) => setConsentRef(e.target.value)} />

                <div style={{ display: 'flex', gap: 4, fontSize: 11, marginTop: 2 }}>
                  {(['age', 'pass'] as const).map((m) => (
                    <button key={m} onClick={() => setUseAge(m === 'age')}
                      style={{ padding: '5px 10px', borderRadius: 7, fontWeight: 600,
                        color: (useAge === (m === 'age')) ? 'var(--accent-bright)' : 'var(--text-muted)',
                        background: (useAge === (m === 'age')) ? 'var(--accent-soft)' : 'transparent' }}>
                      {m === 'age' ? 'age public key (recommended)' : 'passphrase (AES fallback)'}
                    </button>
                  ))}
                </div>

                {useAge ? (
                  <textarea style={{ ...I, minHeight: 60, fontFamily: 'var(--font-mono)', fontSize: 11.5 }}
                    placeholder="Client's age public key — starts with 'age1...' (safe to share openly)"
                    value={ageKey} onChange={(e) => setAgeKey(e.target.value)} />
                ) : (
                  <input style={I} type="password" placeholder="Passphrase (min 8 chars — send to client via a SEPARATE channel)"
                    value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
                )}

                {error && <div style={{ fontSize: 12, color: 'var(--critical)', background: 'var(--critical-soft)', padding: '7px 10px', borderRadius: 8 }}>{error}</div>}

                <button disabled={!canSubmit || busy} onClick={submit}
                  style={{ marginTop: 4, padding: '9px 12px', borderRadius: 8, fontSize: 13, fontWeight: 700,
                    color: '#fff', background: canSubmit && !busy ? 'var(--accent)' : 'var(--panel-hover)',
                    opacity: canSubmit && !busy ? 1 : 0.6, cursor: canSubmit && !busy ? 'pointer' : 'not-allowed' }}>
                  {busy ? 'Generating encrypted export…' : 'Generate encrypted export'}
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
                <div style={{ fontSize: 12.5, color: 'var(--positive)', fontWeight: 600 }}>
                  ✓ {result.record_count} record(s) encrypted ({result.method}). Nothing was stored on the scanner.
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
                  <b>One-time link</b> — works once and expires in {result.expires_in_minutes} minutes. Share it with the client:
                </p>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input readOnly value={fullLink} style={{ ...I, fontFamily: 'var(--font-mono)', fontSize: 11 }} onFocus={(e) => e.currentTarget.select()} />
                  <button onClick={copy} style={{ padding: '0 11px', borderRadius: 8, background: 'var(--accent-soft)', color: 'var(--accent-bright)', border: '1px solid var(--border-emphasis)' }}>
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
                {result.method === 'age' ? (
                  <p style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.5, margin: 0 }}>
                    Client decrypts with: <code style={{ fontFamily: 'var(--font-mono)' }}>age -d -i key.txt -o credentials.csv {result.filename}</code>
                  </p>
                ) : (
                  <p style={{ fontSize: 11.5, color: 'var(--warning)', lineHeight: 1.5, margin: 0 }}>
                    Send the passphrase to the client on a <b>separate</b> channel (never with the link).
                  </p>
                )}
                <button onClick={close} style={{ marginTop: 4, padding: '8px 12px', borderRadius: 8, fontSize: 12.5, fontWeight: 600, color: 'var(--text-secondary)', background: 'var(--panel-bg-elevated)', border: '1px solid var(--border-emphasis)' }}>Done</button>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}
