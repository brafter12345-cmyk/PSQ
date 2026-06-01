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

try:
    import requests
except ImportError:
    requests = None

DEHASHED_V2 = "https://api.dehashed.com/v2/search"


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


def build_credential_csv(entries):
    """CSV with full detail INCLUDING passwords (export-only)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["email", "username", "password", "hashed_password", "database"])
    for e in entries:
        w.writerow([_g(e, "email"), _g(e, "username"), _g(e, "password"),
                    _g(e, "hashed_password"), _g(e, "database_name")])
    return buf.getvalue().encode("utf-8")


def encrypt_age(data, recipient_pubkey):
    """Encrypt to an age recipient public key via the `age` CLI."""
    p = subprocess.run(["age", "-r", recipient_pubkey],
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
                              passphrase=None):
    """Returns (filename, ciphertext_bytes, method, record_count). Nothing stored."""
    entries = _fetch_dehashed_full(domain, dehashed_api_key)
    csv_bytes = build_credential_csv(entries)
    safe = "".join(c for c in (domain or "export") if c.isalnum() or c in ".-")
    if age_recipient:
        return (f"{safe}-credentials.csv.age",
                encrypt_age(csv_bytes, age_recipient), "age", len(entries))
    if passphrase:
        return (f"{safe}-credentials.csv.enc",
                encrypt_aes_openssl(csv_bytes, passphrase), "aes-256-cbc", len(entries))
    raise ValueError("Provide an age_recipient public key or a passphrase")
