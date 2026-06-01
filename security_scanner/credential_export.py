"""On-demand encrypted credential export (Phase 2).

Generated ONLY on request, with client consent. Re-queries DeHashed live, builds
a CSV (including the actual passwords), encrypts it, and returns the bytes.
NOTHING is stored — no plaintext passwords ever land on disk or in scans.db.
See User Manual section 6.4.

Encryption:
  - Preferred: age public-key (recipient's key; only their private key decrypts).
    Requires the `age` binary on PATH. Decrypt: `age -d -i key.txt -o out.csv file`.
  - Fallback: AES-256-CBC in OpenSSL "Salted__" / PBKDF2(sha256, 10000) format.
    Decrypt: `openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:PASSPHRASE -in file -out out.csv`.
"""
import csv
import io
import os
import subprocess
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None

DEHASHED_V2 = "https://api.dehashed.com/v2/search"

# Per-row disclaimer surfaced at the top of every export. The whole point of the
# match_type / confidence columns is that NOT every hit is a stolen credential:
# a browser-History reference means the site was merely visited, an aggregated
# domain-index dump lists thousands of domains, whereas a Passwords/Autofill
# capture is an actual credential. Only HIGH-confidence rows should be weighed
# as evidence of compromise; LOW-confidence rows are monitoring signals and need
# a content-fetch of the specific dump to confirm before they justify treating
# breach probability as raised. See User Manual §6.4.
_DISCLAIMER = (
    "CONFIDENCE GUIDE — high = credential/secret actually captured "
    "(password/autofill/credit-card store); medium = session data (cookies) or "
    "hashed password; low = site merely referenced (browser history) or listed "
    "in an aggregated multi-domain dump. LOW-confidence rows are monitoring "
    "signals, NOT confirmed theft — request a content-fetch of the named dump to "
    "confirm before acting on them as a breach."
)


def _recency_band(age_days):
    """Mirror of scanner._cred_recency_band — kept local so this module stays
    importable without the heavy scanner package."""
    if age_days is None:
        return ""
    if age_days < 30:   return "<30d"
    if age_days < 90:   return "30-90d"
    if age_days < 180:  return "90-180d"
    if age_days < 360:  return "180-360d"
    if age_days < 730:  return "1-2yr"
    return ">2yr"


def _age_days(date_str, today):
    if not date_str or str(date_str) == "Unknown":
        return None
    s = str(date_str)[:10]
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return max(0, (today - dt).days)
        except ValueError:
            continue
    return None


def _credential_confidence(entry):
    """A DeHashed record's evidentiary weight: an actual password is high, a
    hash is medium, an email-only breach appearance is low."""
    if _g(entry, "password"):
        return "plaintext_password", "high"
    if _g(entry, "hashed_password"):
        return "hashed_password", "medium"
    return "email_only", "low"


def _leak_match_type(name):
    """Classify an IntelX stealer-log path by what was actually exposed. The
    folder inside the .rar is the tell: Passwords/Autofill/CreditCards = a real
    secret captured (HIGH); Cookies = a session token (MEDIUM); History = the
    site was only visited (LOW); a domain-sorted aggregate index = lowest
    specificity (LOW)."""
    n = (name or "").lower()
    if "password" in n or "/login" in n:
        return "password_store", "high"
    if "autofill" in n:
        return "autofill", "high"
    if "credit" in n or "/cc" in n or "card" in n:
        return "credit_cards", "high"
    if "cookie" in n:
        return "cookies", "medium"
    if "history" in n:
        return "browser_history", "low"
    if "slow-dom" in n or "domain" in n or "/all" in n:
        return "aggregated_domain_index", "low"
    return "unspecified", "low"


def _fetch_dehashed_full(domain, api_key, max_pages=5, size=100):
    """Re-query DeHashed for full records (incl passwords). On-demand only."""
    entries = []
    if not (requests and api_key and domain):
        return entries
    for page in range(1, max_pages + 1):
        try:
            r = requests.post(
                DEHASHED_V2,
                json={"query": f"domain:{domain}", "page": page, "size": size},
                headers={"Content-Type": "application/json",
                         "Dehashed-Api-Key": api_key,
                         "User-Agent": "PhishieldScanner/1.0"},
                timeout=30)
            if r.status_code != 200:
                break
            batch = (r.json().get("entries") or r.json().get("results") or [])
            if not batch:
                break
            entries.extend(batch)
            if len(batch) < size:
                break
        except Exception:
            break
    return entries


def _g(entry, key):
    v = entry.get(key)
    if isinstance(v, list):
        return v[0] if v else ""
    return v if v is not None else ""


_COLUMNS = ["record_type", "source", "date", "recency_band", "match_type",
            "confidence", "email", "username", "password", "hashed_password",
            "note"]


def build_credential_csv(entries, source_meta=None, leak_references=None,
                         today=None):
    """Unified, date-clustered export INCLUDING passwords (export-only).

    Two record types in one file, sorted newest-first so the most recent
    circulation leads:
      - ``credential``     — a DeHashed leak record (may carry a password).
      - ``leak_reference`` — an IntelX stealer-log posting referencing the
                             domain (no credential in-hand; match_type says how
                             specific the hit is).
    ``source_meta`` maps a lower-cased source name to
    ``{"date": "YYYY-MM-DD", "combo": bool}`` (from the scan's enriched
    sources), so each credential inherits its source's breach-date guesstimate
    and recency band. Encryption is applied to whatever this returns — enriching
    the rows never touches the crypto."""
    today = today or datetime.now(timezone.utc)
    source_meta = source_meta or {}
    rows = []

    for e in entries:
        src = _g(e, "database_name") or _g(e, "database")
        meta = source_meta.get((src or "").lower().strip(), {})
        date = meta.get("date", "")
        band = _recency_band(_age_days(date, today))
        mtype, conf = _credential_confidence(e)
        note = ("aggregator/combo source — re-circulated historical data, "
                "not necessarily a fresh compromise") if meta.get("combo") else ""
        rows.append({
            "record_type": "credential", "source": src, "date": date,
            "recency_band": band, "match_type": mtype, "confidence": conf,
            "email": _g(e, "email"), "username": _g(e, "username"),
            "password": _g(e, "password"),
            "hashed_password": _g(e, "hashed_password"), "note": note,
        })

    for ref in (leak_references or []):
        name = ref.get("name") or ref.get("bucket") or ""
        date = str(ref.get("date") or "")[:10]
        band = _recency_band(_age_days(date, today))
        mtype, conf = _leak_match_type(name)
        rows.append({
            "record_type": "leak_reference", "source": "IntelX", "date": date,
            "recency_band": band, "match_type": mtype, "confidence": conf,
            "email": "", "username": "", "password": "", "hashed_password": "",
            "note": name,
        })

    rows.sort(key=lambda r: (r["date"] or "0000-00-00"), reverse=True)

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_COLUMNS)
    w.writerow(["_disclaimer", "", "", "", "", "", "", "", "", "", _DISCLAIMER])
    for r in rows:
        w.writerow([r[c] for c in _COLUMNS])
    return buf.getvalue().encode("utf-8")


def _age_bin():
    """Resolve the `age` binary: AGE_BIN env override, then a bundled copy next to
    this module (security_scanner/bin/age, dropped in by the Render build), then
    plain `age` on PATH."""
    env = os.environ.get("AGE_BIN")
    if env:
        return env
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", "age")
    return local if os.path.exists(local) else "age"


def encrypt_age(data, recipient_pubkey):
    """Encrypt to an age recipient public key via the `age` CLI."""
    p = subprocess.run([_age_bin(), "-r", recipient_pubkey],
                       input=data, capture_output=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError("age failed: " + p.stderr.decode("utf-8", "replace")[:200])
    return p.stdout


def encrypt_aes_openssl(data, passphrase):
    """AES-256-CBC, OpenSSL 'Salted__' + PBKDF2(sha256, 10000) format."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    salt = os.urandom(8)
    keyiv = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt,
                       iterations=10000).derive(passphrase.encode("utf-8"))
    key, iv = keyiv[:32], keyiv[32:48]
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return b"Salted__" + salt + enc.update(padded) + enc.finalize()


def generate_encrypted_export(domain, dehashed_api_key, age_recipient=None,
                              passphrase=None, source_meta=None,
                              leak_references=None):
    """Returns (filename, ciphertext_bytes, method, record_count). Nothing stored.

    ``source_meta`` / ``leak_references`` come from the domain's latest scan
    (breach-date guesstimates + IntelX dump postings) so the export carries the
    same recency clustering as the dashboard. Both optional — without them the
    export still produces credentials, just without dates/leak references."""
    entries = _fetch_dehashed_full(domain, dehashed_api_key)
    csv_bytes = build_credential_csv(entries, source_meta=source_meta,
                                     leak_references=leak_references)
    safe = "".join(c for c in (domain or "export") if c.isalnum() or c in ".-")
    if age_recipient:
        return (f"{safe}-credentials.csv.age",
                encrypt_age(csv_bytes, age_recipient), "age", len(entries))
    if passphrase:
        return (f"{safe}-credentials.csv.enc",
                encrypt_aes_openssl(csv_bytes, passphrase), "aes-256-cbc", len(entries))
    raise ValueError("Provide an age_recipient public key or a passphrase")
