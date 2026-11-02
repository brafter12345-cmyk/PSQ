"""Scan-target input handling: normalise, validate syntax, prove existence.

Three separate questions, deliberately kept apart:

  normalize_domain()  what did the user actually mean?
  valid_domain()      is that a syntactically legal domain?
  domain_exists()     is it registered at all?

They were previously one syntax regex in app.py, and both other questions went
unasked. That produced two real failures:

  * A broker pasting a target out of a submission form got "Invalid or missing
    domain" for a domain that looked perfectly correct on screen, because the
    paste carried a zero-width character, a full URL, or an email address.
  * morgancarco.com (a typo of morgancargo.com) passed the syntax check and
    scanned to completion against nothing: 266 "Medium", 77% coverage, zero
    discovered IPs, and headline findings of "No SPF record" and "No DMARC
    record" that are vacuously true of a domain which does not exist.

Kept free of Flask so the regression gate can import it directly.
"""
import re

__all__ = ["normalize_domain", "valid_domain", "domain_exists",
           "clean_related_domains"]

# A domain anyone typed or pasted settles in two or three passes; an input
# still changing after this many is not one, and gets no more work.
_MAX_PASSES = 8

# A display-name address, "Name <user@host>": the whole value is a name and one
# bracketed address. A URL that merely carries an address in its query or
# fragment is not one, or the host would lose to a third party's domain (step-5
# critique rounds 7 and 9).
_DISPLAY_ADDR_RE = re.compile(r"^(?P<pre>[^<>]*)<(?P<addr>[^<>@\s]*@[^<>\s]*)>\s*$")
# The host ends where host characters end. An allow-list of the four
# separators that may follow missed a trailing dot or comma, and the value then
# fell through to the contact's address (step-5 critique round 11, IR11-2).
# The second lookahead refuses a SHORTER match: without it "acme.co.za1"
# backtracks to "acme.co" and retargets the scan at another registrable domain
# (step-5 critique round 12, IH12-2).
_HOSTLIKE_RE = re.compile(
    r"\s*[\"']?(?:[a-z0-9-]+\.)+[a-z]{2,}(?![a-z0-9-])(?!\.[a-z0-9-])", re.I)
# Is this token a contact ADDRESS rather than a host or a URL? The scheme is
# read, not removed: after removal every @-bearing shape looks the same, and a
# portal URL carrying a username was dropped as if it were an address (step-5
# critique rounds 12 and 13, IH12-5, IH13-2, R13-IN-2).
def _is_contact_token(tok: str) -> bool:
    t = str(tok).strip().lower()
    if t.startswith("mailto:"):
        return True
    if t.startswith(("http://", "https://", "ftp://")):
        return False
    if t.startswith("//"):
        # Protocol-relative: a path makes it a URL, none makes it the address a
        # mail client autolinked.
        return "@" in t[2:] and "/" not in t[2:]
    return "@" in t.split("/")[0]


# Host-SHAPED, whether or not the rule above will read it: used to tell "there
# is no host here" from "there is a host here I refused to read" (round 13,
# IH13-3). DERIVED from the host rule - it is that rule minus the two lookaheads
# that stop it reading a shorter host - so the two cannot drift apart. Written
# as its own looser pattern it matched every dotted first token, so a date, an
# amount, an IP, a version or initials before the brackets read as an unreadable
# host and the broker's confirmed domain was dropped with nothing said on any
# surface, undoing round 12's IH12-1 (round 15).
_HOSTISH_RE = re.compile(r"\s*[\"']?(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)


def _looks_like_host_token(value: str) -> bool:
    """Conservative guard for dotted, alphabetic tokens that failed syntax."""
    raw = str(value).strip(" \t\"'")
    token = raw.split()[0] if raw else ""
    if "." not in token:
        return False
    tail = token.rsplit(".", 1)[-1]
    # Numeric-leading tails are dates, versions, or amounts commonly used in
    # display names ("v2.1", "R1.5m", "No.1"), not unreadable hostnames.
    if len(tail) < 2 or tail[0].isdecimal():
        return False
    return any(ch.isalpha() for ch in tail) and (
        any(ord(ch) > 127 for ch in tail)
        or tail[-1].isdecimal()
        or tail.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", tail, re.I)
    )

# A scheme, or a chain of them (mailto://jane@..., https://http://...).
_SCHEME_RE = re.compile(r"^(?:(?:https?|ftp)://|//|mailto:)+")

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

# Characters that survive a copy out of a PDF, a Word table or a web form and
# are invisible in the input box. U+200B/C/D and U+FEFF are the usual culprits;
# str.strip() does not remove them, so the regex rejects a domain the broker can
# see is correct. U+00A0 IS stripped by str.strip() but is listed for clarity.
_INVISIBLE = dict.fromkeys(map(ord,
    "​‌‍⁠﻿­‎‏‪‫‬"
    "‭‮⁦⁧⁨⁩"), None)


def _normalize_once(raw: str) -> str:
    """One pass of normalize_domain."""
    if not raw:
        return ""
    s = str(raw).translate(_INVISIBLE).strip()
    # A display-name address ("Accounts/Finance <accounts@acme.co.za>"): the
    # address inside the angle brackets, before anything else. Only where the
    # value is a display name and one address: in a URL the host wins, so an
    # address in a query or fragment is not the target (rounds 8 and 9).
    m = _DISPLAY_ADDR_RE.match(s)
    if m and not _SCHEME_RE.match(m.group("pre").strip().lower()):
        host = _HOSTLIKE_RE.match(m.group("pre"))
        # "acme.co.za <info@brokerfirm.co.za>": a host before the brackets is
        # the target, and the contact address is not; without a host the value
        # is a display name and its address is (rounds 8 to 10).
        if host:
            s = host.group(0)
        elif (_HOSTISH_RE.match(m.group("pre"))
              or _looks_like_host_token(m.group("pre"))):
            # Host-shaped but unreadable: an unreadable target must not become
            # the contact's domain (step-5 critique round 13, IH13-3).
            return ""
        else:
            s = m.group("addr")
    s = s.strip("\"'<>").strip()
    if not s:
        return ""
    s = s.lower()
    # Scheme, including the ones a broker might paste out of a mail client, and
    # a chain of them, removed in one step (step-5 critique round 8).
    s = _SCHEME_RE.sub("", s)
    # Path, query and fragment first: an address in a URL's query or fragment
    # (?email=jane@gmail.com) is not the host (step-5 critique round 7). A
    # backslash ends the authority, as every browser reads it (round 10).
    s = s.replace("\\", "/")
    for sep in ("/", "?", "#"):
        s = s.split(sep, 1)[0]
    # An email address is an extremely common paste from a submission form;
    # the domain is the part the scan wants. Also covers URL userinfo.
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # Port.
    if ":" in s:
        s = s.split(":", 1)[0]
    # A fully-qualified name may carry the root dot.
    return s.strip().rstrip(".")


def normalize_domain(raw: str) -> str:
    """Best-effort extraction of the domain the user meant.

    Handles, in order: invisible characters and surrounding whitespace, a
    display-name address (the part inside the angle brackets), surrounding
    quotes, a scheme or a chain of them, a path/query/fragment, userinfo or a
    pasted email address, a port, and a trailing root dot. Returns "" when
    nothing usable is left.

    Repeated until nothing changes, because one pass can leave work for the
    next: in '"supplier.co.za".' the full stop shields the closing quote. The
    result is its own normalisation, so a value that is validated is the value
    kept (step-5 critique round 6). An input still changing after _MAX_PASSES
    passes is not a domain anyone typed and returns "", so the cost stays linear
    (step-5 critique round 7).

    Deliberately does NOT strip a leading "www.": that is a real hostname and
    the caller may genuinely mean it. Deciding apex-vs-www is a product choice,
    not an input-cleaning one.
    """
    s = _normalize_once(raw)
    for _ in range(_MAX_PASSES):
        t = _normalize_once(s)
        if t == s:
            return s
        s = t
    return ""


def valid_domain(domain: str) -> bool:
    """Syntax only. Says nothing about whether the domain exists."""
    d = normalize_domain(domain)
    return bool(_DOMAIN_RE.match(d)) and len(d) <= 253


def clean_related_domains(raw_related) -> list:
    """The broker-confirmed related domains a scan request carries, cleaned.

    Each entry is normalised the way the primary domain is (invisible
    characters, quotes, a scheme, a pasted email address, a path, a port and
    a trailing dot removed), a wildcard prefix is dropped, and the value that
    passes valid_domain is the value kept. Keeping the raw string instead let
    a name the check had accepted reach the report as malformed and
    unassessed, and let markup reach the PDF (step-5 critique round 5).
    Anything still not a valid domain name is dropped.
    """
    out, seen = [], set()
    if not isinstance(raw_related, list):
        return out

    def _clean(value):
        d = normalize_domain(str(value))
        # A wildcard prefix, in as many layers as were pasted, stripped in one
        # go and normalised again, a bounded number of times.
        for _ in range(4):
            if not d.startswith("*."):
                break
            d = normalize_domain(d.lstrip("*."))
        return d

    def _keep(value):
        d = _clean(value)
        if d and valid_domain(d) and d not in seen:
            seen.add(d)
            out.append(d)

    for raw in raw_related:
        s = str(raw)
        # A contact address beside a host, on one entry, is a contact - the rule
        # the scan form applies, now applied here too, so the same text cannot
        # scope in the broker's own domain through this door (step-5 critique
        # round 12, GS12-3). Deliberately narrow: only where the entry carries
        # more than one token, one of them an address, and another a name this
        # function would itself accept. Every single-token entry is untouched.
        toks = [t for t in re.split(r"[\s,;]+", s) if t]
        if len(toks) > 1:
            hosts = [t for t in toks if not _is_contact_token(t)]
            if any(valid_domain(_clean(t)) for t in hosts):
                for t in hosts:
                    _keep(t)
                continue
            # A line may contain several contacts and no host.  Normalising the
            # whole line keeps only the last address (the final @ wins), which
            # silently drops the other confirmed contact domains.  Keep every
            # contact token in input order; display names are ignored.
            contacts = [t for t in toks if _is_contact_token(t)]
            invalid_host = any(
                not _is_contact_token(t) and _looks_like_host_token(t)
                for t in toks
            )
            if contacts and not invalid_host:
                for t in contacts:
                    _keep(t)
                continue
        # Comma/semicolon-separated input commonly arrives as one list entry
        # with a trailing separator (e.g. "supplier.co.za,").  The separator
        # is already removed by the server tokenizer; validate that token
        # rather than the raw entry so the API door matches the form door.
        if len(toks) == 1 and toks[0] != s.strip():
            _keep(toks[0])
            continue
        _keep(s)
    return out


def domain_exists(domain: str, *, timeout: float = 5.0) -> bool:
    """Is this domain REGISTERED? (NXDOMAIN => no.)

    Deliberately narrow: this asks ONLY whether the name exists in DNS, not
    whether it serves anything. A registered domain with NS records but no A or
    MX is a thin but legitimate target -- parked brand-protection domains are a
    real part of an attack surface -- so it must still scan. Only NXDOMAIN,
    meaning the name is not registered at all, is rejected.

    Fails OPEN on resolver trouble. Refusing real work because our own DNS
    hiccupped is worse than the occasional scan of a dead name.
    """
    d = normalize_domain(domain)
    if not d:
        return False
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        # Without dnspython the stdlib cannot tell NXDOMAIN from "no A record",
        # so only a clean resolution proves existence and everything else is
        # let through rather than guessed at.
        import socket
        try:
            socket.gethostbyname(d)
        except Exception:
            pass
        return True

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    # NS first: it is the record that proves delegation, and it is present for
    # registered domains publishing neither A nor MX.
    for rdtype in ("NS", "A", "MX", "SOA"):
        try:
            resolver.resolve(d, rdtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False            # authoritative: the name does not exist
        except dns.resolver.NoAnswer:
            continue                # exists, just not this record type
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return True             # resolver trouble: fail open
        except Exception:
            return True
    return True
