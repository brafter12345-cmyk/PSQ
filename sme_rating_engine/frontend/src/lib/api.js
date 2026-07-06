// Base-aware API calls — mirrors the scanner's withBase(). import.meta.env.BASE_URL
// is '/' for local/root and '/smerating/' for the VM build, so the same code
// hits /api/quotes at root and /smerating/api/quotes under the sub-path mount.
const API_BASE = String(import.meta.env.BASE_URL || '/').replace(/\/?$/, '/');

export async function saveQuote(payload) {
  const res = await fetch(API_BASE + 'api/quotes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('save failed: ' + res.status);
  return res.json();
}
