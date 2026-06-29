// Runtime base-path prefix, so the dashboard can be served under a sub-path
// (e.g. https://veilguard.phishield.com/scanner) without a domain at the root.
//
// Derived from Vite's build-time base (import.meta.env.BASE_URL):
//   root build  → base "/static/dashboard/"          → BASE = ""        (URLs stay /api/...)
//   /scanner build → base "/scanner/static/dashboard/" → BASE = "/scanner" (URLs become /scanner/api/...)
//
// The Flask templates mirror this via {{ request.script_root }}, so server- and
// client-emitted URLs always agree. To move to a root domain later, just rebuild
// without SCANNER_BASE_PATH set.
export const BASE: string = import.meta.env.BASE_URL.replace(/\/static\/dashboard\/?$/, '')

/** Prefix an absolute app path (e.g. "/api/scan/123") with the deploy base. */
export const withBase = (path: string): string => BASE + path
