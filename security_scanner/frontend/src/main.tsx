import React from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/inter'
import './theme/tokens.css'
import App from './App'
import type { Results } from './types/results'

async function bootstrap() {
  // DEV ONLY: the standalone Vite dev server has no Flask injection, so load a
  // captured scan. Guarded by import.meta.env.DEV — Vite replaces this with
  // `false` in production so the dynamic import (and the fixture JSON) are
  // dead-code-eliminated from the shipped bundle. In production window.RESULTS
  // is always set by results.html before app.js runs.
  if (import.meta.env.DEV && !window.RESULTS) {
    // Optional local dev fixture — gitignored, never committed. Drop a real
    // RESULTS payload at src/dev/sampleResults.json to develop standalone.
    // import.meta.glob resolves to {} when the file is absent, so the build
    // never depends on it.
    const fixtures = import.meta.glob('./dev/sampleResults.json', { import: 'default' })
    const load = fixtures['./dev/sampleResults.json']
    if (load) {
      const sample = (await load()) as Results
      window.RESULTS = sample
      window.SCAN_META = { status: 'completed', domain: sample.domain_scanned, scanId: 'dev-local' }
      window.CHECKER_MANIFEST = []
    }
    // dev-only: ?progress previews the scan-in-progress experience with a
    // representative manifest (SSE will fall back to harmless polling).
    if (new URLSearchParams(location.search).has('progress')) {
      window.RESULTS = null
      window.SCAN_META = { status: 'pending', domain: 'phishield.com', scanId: 'dev-progress' }
      window.CHECKER_MANIFEST = [
        { section: 'Discovery', checkers: [{ id: 'ip_discovery', label: 'IP Discovery' }, { id: 'web_ranking', label: 'Web Ranking' }] },
        { section: 'Core Security', checkers: [{ id: 'ssl', label: 'SSL / TLS' }, { id: 'http_headers', label: 'HTTP Headers' }, { id: 'waf', label: 'WAF / DDoS' }] },
        { section: 'Email Security', checkers: [{ id: 'email_security', label: 'Email Auth' }, { id: 'email_hardening', label: 'Email Hardening' }] },
        { section: 'Network & Infrastructure', checkers: [{ id: 'dns_infrastructure', label: 'DNS & Ports' }, { id: 'high_risk_protocols', label: 'High-Risk Protocols' }] },
        { section: 'Exposure & Reputation', checkers: [{ id: 'breaches', label: 'Data Breaches' }, { id: 'virustotal', label: 'VirusTotal' }] },
      ]
    }
  }

  const el = document.getElementById('root')
  if (el) {
    createRoot(el).render(
      <React.StrictMode>
        <App />
      </React.StrictMode>,
    )
  }
}

void bootstrap()
