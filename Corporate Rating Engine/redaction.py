"""redaction.py — mini on-prem PII redaction unit.

A local stand-in for the closed-environment redaction server, so Phase 2 (mapping) is
testable now. Strips PII to opaque tokens before anything is sent to the LLM, and rehydrates
the tokens back into the LLM's output so the report reads naturally.

Swap-over: set the REDACTION_URL env var to the real redaction server and apply_redaction()
routes there instead (same contract: POST {text, extra_terms} -> {redacted, map}). If a remote
URL is configured but unreachable, it raises — i.e. it FAILS CLOSED, never sending raw text out.

Security content (controls, percentages, CVEs, counts) is deliberately preserved; only clear,
high-confidence PII is removed, plus any explicit known entities passed in (company name, contacts).
"""
import os
import re
import json
import urllib.request

# Conservative, SA-aware PII patterns. Order matters (emails/URLs before bare numbers).
_PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    ("URL",   re.compile(r"\bhttps?://[^\s)>\]]+", re.I)),
    ("SAID",  re.compile(r"\b\d{13}\b")),                       # SA ID number (13 digits)
    ("VAT",   re.compile(r"\b4\d{9}\b")),                       # SA VAT number (10 digits, starts 4)
    ("PHONE", re.compile(r"(?<!\d)(?:\+?27|0)(?:[\s-]?\d){9}(?!\d)")),
    ("IP",    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")),
]


def redact(text, extra_terms=None):
    """Local redaction. Returns (redacted_text, token_map {token: original})."""
    token_map = {}
    counters = {}

    def tok(kind, value):
        for t, v in token_map.items():            # reuse a token for a repeated value
            if v == value:
                return t
        counters[kind] = counters.get(kind, 0) + 1
        t = "«%s_%d»" % (kind, counters[kind])   # «KIND_n» — unlikely to occur naturally
        token_map[t] = value
        return t

    out = text or ""
    # structured PII first, so an entity sitting inside an email/URL doesn't break that match
    for kind, pat in _PATTERNS:
        out = pat.sub(lambda m, kind=kind: tok(kind, m.group(0)), out)
    # then explicit known entities (company name, website, contacts) — longest match first.
    # Store the *matched* text so rehydration restores exact casing.
    for term in sorted({str(t) for t in (extra_terms or []) if t and len(str(t).strip()) >= 3}, key=len, reverse=True):
        out = re.sub(re.escape(term), lambda m: tok("ENTITY", m.group(0)), out, flags=re.I)
    return out, token_map


def rehydrate(text, token_map):
    """Restore original values from a token map into LLM output."""
    out = text or ""
    for t, v in (token_map or {}).items():
        out = out.replace(t, v)
    return out


def mode():
    return "remote" if os.environ.get("REDACTION_URL") else "local"


def _redact_via_server(text, extra_terms=None):
    url = os.environ["REDACTION_URL"]
    body = json.dumps({"text": text, "extra_terms": extra_terms or []}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:   # raises -> fails closed
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("redacted", ""), data.get("map", {})


def apply_redaction(text, extra_terms=None):
    """Route to the real redaction server if REDACTION_URL is set (fail closed), else the local unit."""
    if os.environ.get("REDACTION_URL"):
        return _redact_via_server(text, extra_terms)
    return redact(text, extra_terms)


if __name__ == "__main__":
    sample = ("Contact Jane Doe (jane@takealot.co.za, 082 555 1234, ID 8001015009087). "
              "Server 152.111.191.48. We run weekly immutable backups and CrowdStrike EDR.")
    red, m = redact(sample, extra_terms=["Takealot"])
    print("REDACTED:\n", red)
    print("\nMAP:", m)
    print("\nREHYDRATED matches original:", rehydrate(red, m) == sample)
