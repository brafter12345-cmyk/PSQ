# -*- coding: utf-8 -*-
"""Client meeting brief: a short, client-facing companion to the full report.

WHY THIS EXISTS. The full report is written for the broker and the underwriter.
When we sit with a client's IT team they need something different: what to do
first, which of their accounts are affected, and how we know. This builds that
from a completed scan.

PASSWORD FINGERPRINTS. Optionally the brief carries a FINGERPRINT of each leaked
password - the first character and the length, e.g. ``K... (9 chars)`` - and
nothing more. The question an IT team actually needs answered is "is this one
still in rotation", and an account owner can answer that from a fingerprint.
Printing the password itself turns a briefing note into a credential dump: a
document that, if mislaid, hands whoever finds it working credentials they did
not previously have. The fingerprint answers the question and cannot be replayed.

Fingerprints are OFF by default and cost money. The scan deliberately persists no
password material at all (``checkers_threats`` stores only has_password /
has_hash booleans), so a fingerprint can only come from a fresh paged query
against the credential source, at one credit per page of 100 records. With
fingerprints off this module makes NO outbound request of any kind and spends
nothing.
"""
import math

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from pdf_helpers import C_NAVY, build_styles

PAGE_SIZE = 100
MAX_PAGES = 10          # hard ceiling: 10 credits per brief, whatever the client
C_RED = colors.HexColor("#a32f25")
C_AMBER = colors.HexColor("#b45309")
C_GREY = colors.HexColor("#475569")
C_LIGHT = colors.HexColor("#f1f5f9")
C_LINE = colors.HexColor("#cbd5e1")


# --------------------------------------------------------------------------
# fingerprints


# --------------------------------------------------------------------------


def fingerprint(password: str) -> "dict | None":
    """First character and length. Enough to recognise, useless to replay.

    Deliberately returns no other derivative of the password - not a hash, not a
    character-class summary, not the last character. Each of those narrows a
    guess; none of them help the account owner answer "is this mine".
    """
    if not password:
        return None
    p = str(password)
    return {"first": p[0], "length": len(p)}


def render_fingerprint(fp: dict) -> str:
    """Display form. The ONLY function that turns a fingerprint into text."""
    return "%s\u2026 (%d chars)" % (fp["first"], fp["length"])


def estimate_credits(total_entries: int) -> int:
    """Credits a fingerprint pull would cost: one per page of 100, capped.

    The source bills per accepted search, not per record returned, so this is
    pages-not-records. Shown to the operator BEFORE they commit to generating.
    """
    if not total_entries or total_entries < 1:
        return 1
    return max(1, min(MAX_PAGES, math.ceil(total_entries / PAGE_SIZE)))


def _first(v):
    """The credential source returns some fields as a list, some as a scalar."""
    if isinstance(v, list):
        return v[0] if v else ""
    return v or ""


def fetch_fingerprints(domain: str, api_key: str, max_pages: int = MAX_PAGES) -> dict:
    """Page the complete record set for a domain and reduce it to fingerprints.

    PAID. One credit per page. Called only when the operator ticked the option.
    The plaintext passwords exist only inside this function's loop and are never
    returned, logged or stored - only the fingerprint derived from them escapes.
    """
    import requests

    entries, pages = [], 0
    for page in range(1, max_pages + 1):
        r = requests.post("https://api.dehashed.com/v2/search",
                          json={"query": "domain:%s" % domain,
                                "page": page, "size": PAGE_SIZE},
                          headers={"Content-Type": "application/json",
                                   "Dehashed-Api-Key": api_key},
                          timeout=30)
        pages += 1
        if r.status_code != 200:
            break
        body = r.json()
        batch = body.get("entries") or []
        if not batch:
            break
        entries.extend(batch)
        if len(batch) < PAGE_SIZE:
            break

    accounts = {}
    for e in entries:
        em = str(_first(e.get("email"))).strip().lower()
        if not em:
            continue
        a = accounts.setdefault(em, {
            "email": em, "domain": em.rsplit("@", 1)[-1], "records": 0,
            "sources": set(), "fingerprints": [], "hashed": 0,
        })
        a["records"] += 1
        src = e.get("database_name") or "Unknown source"
        a["sources"].add(src)
        pw = _first(e.get("password"))
        if pw:
            fp = fingerprint(pw)
            if fp and fp not in a["fingerprints"]:
                a["fingerprints"].append(fp)
        if _first(e.get("hashed_password")):
            a["hashed"] += 1
        del pw  # the password leaves scope here and is never referenced again

    rows = []
    for a in accounts.values():
        rows.append({"email": a["email"], "domain": a["domain"],
                     "records": a["records"], "sources": sorted(a["sources"]),
                     "fingerprints": a["fingerprints"],
                     "distinct_passwords": len(a["fingerprints"]),
                     "hashed": a["hashed"]})
    rows.sort(key=lambda x: (-x["distinct_passwords"], -x["hashed"], x["email"]))
    by_domain = {}
    for x in rows:
        by_domain[x["domain"]] = by_domain.get(x["domain"], 0) + 1
    return {"accounts": rows, "records": len(entries), "credits_spent": pages,
            "by_domain": by_domain, "complete": pages < max_pages}


# --------------------------------------------------------------------------
# accounts from the stored scan (free path)


# --------------------------------------------------------------------------


def accounts_from_scan(cats: dict) -> list:
    """Account rows derived from what the scan already stored. Spends nothing.

    ``breach_details`` is capped at 20 records by the checker and carries only
    has_password / has_hash booleans, so this path can say WHICH accounts are
    affected and in what state, but never how many distinct passwords leaked.
    """
    dh = cats.get("dehashed", {}) or {}
    seen = {}
    for r in dh.get("breach_details", []) or []:
        em = str(r.get("email") or "").strip().lower()
        if not em or em == "n/a":
            continue
        a = seen.setdefault(em, {"email": em, "domain": em.rsplit("@", 1)[-1],
                                 "records": 0, "sources": set(),
                                 "plaintext": 0, "hashed": 0})
        a["records"] += 1
        if r.get("database"):
            a["sources"].add(r["database"])
        if r.get("has_password"):
            a["plaintext"] += 1
        if r.get("has_hash"):
            a["hashed"] += 1
    rows = [{**a, "sources": sorted(a["sources"])} for a in seen.values()]
    rows.sort(key=lambda x: (-x["plaintext"], -x["hashed"], x["email"]))
    return rows


# --------------------------------------------------------------------------
# PDF


# --------------------------------------------------------------------------


def _styles():
    S = build_styles()
    S["mb_h1"] = ParagraphStyle("mb_h1", parent=S["body"], fontSize=17,
                                textColor=C_NAVY, leading=20, spaceAfter=3,
                                fontName="Helvetica-Bold")
    S["mb_h2"] = ParagraphStyle("mb_h2", parent=S["body"], fontSize=12,
                                textColor=C_NAVY, leading=15, spaceBefore=11,
                                spaceAfter=4, fontName="Helvetica-Bold")
    S["mb_body"] = ParagraphStyle("mb_body", parent=S["body"], fontSize=9.3,
                                  leading=13.4, spaceAfter=5)
    S["mb_small"] = ParagraphStyle("mb_small", parent=S["mb_body"], fontSize=8.1,
                                   textColor=C_GREY, leading=11)
    S["mb_tiny"] = ParagraphStyle("mb_tiny", parent=S["mb_body"], fontSize=7.6,
                                  leading=9.6)
    S["mb_bull"] = ParagraphStyle("mb_bull", parent=S["mb_body"], leftIndent=9,
                                  bulletIndent=2, spaceAfter=3)
    return S


def _table(header_bg, rows, widths):
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, C_LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build_brief(results: dict, domain: str, fingerprint_data: "dict | None" = None,
                generated_by: str = "") -> bytes:
    """Render the meeting brief. ``fingerprint_data`` is the return of
    ``fetch_fingerprints``; when None the brief is built entirely from the stored
    scan and contains no password-derived material of any kind."""
    import io as _io

    S = _styles()
    story = []

    def P(t, st="mb_body"):
        story.append(Paragraph(t, S[st]))

    def B(t):
        story.append(Paragraph(t, S["mb_bull"], bulletText=u"•"))

    def SP(h=3):
        story.append(Spacer(1, h * mm))

    cats = results.get("categories", {}) or {}
    dh = cats.get("dehashed", {}) or {}
    sc = results.get("_scan_completeness", {}) or {}
    with_fp = bool(fingerprint_data)

    P("%s: cyber exposure briefing" % domain, "mb_h1")
    P("Prepared for the meeting with %s. Companion to the full technical report, "
      "not a replacement for it.%s" % (
          domain,
          "  CONFIDENTIAL: contains password fingerprints for the client's own "
          "accounts." if with_fp else ""), "mb_small")
    SP(4)

    # 1 -------------------------------------------------------------------
    P("1. What this assessment is, and what it is not", "mb_h2")
    P("This is a <b>passive external assessment</b>. Everything in it was obtained "
      "from outside the network, using publicly reachable infrastructure and "
      "commercial breach-intelligence databases. Nothing was logged into, no "
      "password was tried, no system was accessed. It is the view an attacker gets "
      "for free, before making any attempt.")
    P("Two consequences worth stating up front. It cannot see inside the perimeter, "
      "so it says nothing about endpoint controls, internal patching or backups. "
      "And an absence of findings is not proof of safety: where a check was blocked "
      "or a source was unavailable, the report says <b>not assessed</b> rather than "
      "reporting a clean result.")

    # 2 -------------------------------------------------------------------
    recs = [r for r in (results.get("recommendations") or []) if str(r).strip()]
    if recs:
        P("2. What to do, in order", "mb_h2")
        P("Taken from the full report's prioritised recommendations, highest "
          "severity first.", "mb_small")
        rows = [[Paragraph("<b>#</b>", S["mb_small"]),
                 Paragraph("<b>Action</b>", S["mb_small"])]]
        for i, r in enumerate(recs[:12], 1):
            rows.append([Paragraph("<b>%d</b>" % i, S["mb_tiny"]),
                         Paragraph(str(r), S["mb_tiny"])])
        story.append(_table(C_NAVY, rows, [10 * mm, 158 * mm]))
        if len(recs) > 12:
            SP(1)
            P("A further %d recommendation(s) appear in the full report."
              % (len(recs) - 12), "mb_small")

    # 3 -------------------------------------------------------------------
    P("3. Affected accounts", "mb_h2")
    if with_fp:
        acc = fingerprint_data["accounts"]
        withpw = [a for a in acc if a["distinct_passwords"] > 0]
        repeat = [a for a in withpw if a["distinct_passwords"] >= 2]
        hashonly = [a for a in acc if a["distinct_passwords"] == 0 and a["hashed"]]
        nocred = [a for a in acc if a["distinct_passwords"] == 0 and not a["hashed"]]
        P("A complete pull of the source data returns <b>%d records across %d unique "
          "addresses on %d domains</b>. The records are not all the same kind of "
          "thing and do not warrant the same response."
          % (fingerprint_data["records"], len(acc),
             len(fingerprint_data["by_domain"])))
        if repeat:
            P("<b>%d account(s) hold more than one distinct leaked password.</b> That "
              "pattern matters more than the volume: several different passwords for "
              "one account means the password was changed and then captured again, "
              "so rotation on its own has not stopped it. That points at "
              "credential-stealing malware on a device that keeps signing in, rather "
              "than a single historic breach." % len(repeat))
        if withpw:
            SP(2)
            P("<b>Readable password present. Act on these first.</b>")
            rows = [[Paragraph("<b>Account</b>", S["mb_small"]),
                     Paragraph("<b>Records</b>", S["mb_small"]),
                     Paragraph("<b>Distinct<br/>passwords</b>", S["mb_small"]),
                     Paragraph("<b>Password fingerprints "
                               "(first character and length)</b>", S["mb_small"])]]
            for a in withpw:
                fps = ", ".join(render_fingerprint(f) for f in a["fingerprints"][:8])
                if len(a["fingerprints"]) > 8:
                    fps += ", and %d more" % (len(a["fingerprints"]) - 8)
                rows.append([Paragraph(a["email"], S["mb_tiny"]),
                             Paragraph(str(a["records"]), S["mb_tiny"]),
                             Paragraph("<b>%d</b>" % a["distinct_passwords"],
                                       S["mb_tiny"]),
                             Paragraph(fps, S["mb_tiny"])])
            story.append(_table(C_RED, rows, [50 * mm, 15 * mm, 18 * mm, 85 * mm]))
            SP(2)
            P("<b>How to use the fingerprints.</b> Each entry is the first character "
              "and the length of a password found in the leaked data. The account "
              "owner can compare that against what they currently use and confirm "
              "whether any of these is still in rotation. The passwords themselves "
              "are deliberately not reproduced: they add nothing to the decision, "
              "which is to rotate, and a document containing them becomes a "
              "liability the moment it leaves the room. They can be supplied "
              "separately, encrypted, on a formal request.")
        if hashonly:
            SP(2)
            P("<b>Hashed credential only.</b> The password is not directly readable, "
              "so rotate at the next convenient cycle rather than today.")
            rows = [[Paragraph("<b>Account</b>", S["mb_small"]),
                     Paragraph("<b>Records</b>", S["mb_small"]),
                     Paragraph("<b>Where it appeared</b>", S["mb_small"])]]
            for a in hashonly:
                rows.append([Paragraph(a["email"], S["mb_tiny"]),
                             Paragraph(str(a["records"]), S["mb_tiny"]),
                             Paragraph(", ".join(a["sources"])[:90], S["mb_tiny"])])
            story.append(_table(C_AMBER, rows, [55 * mm, 18 * mm, 95 * mm]))
        if nocred:
            SP(2)
            P("<b>Listed, but no credential involved.</b> %d address(es) appear only "
              "in directory-type sources, which are commercial business-information "
              "databases rather than breaches. No password, hash or credential of "
              "any kind is attached to them. Presenting these as compromised "
              "accounts would overstate the position and would not survive scrutiny "
              "from a competent IT team." % len(nocred))
            P(", ".join(a["email"] for a in nocred), "mb_tiny")
        by = fingerprint_data["by_domain"]
        if len(by) > 1:
            SP(2)
            P("<b>The exposure spans more than the scanned domain.</b> Affected "
              "addresses appear across %d domains: %s. Only %s was scanned, so "
              "accounts on the other domains are currently classified as personal "
              "rather than corporate, which understates them. That is a limitation "
              "of scanning one domain, not a judgement about those accounts. "
              "Credential exposure on those domains is assessed only by scanning "
              "each one as a domain in its own right. Confirming them as related "
              "domains on the scan form adds a lighter check of their "
              "certificates, DNS and exposed files, not a credential assessment."
              % (len(by), ", ".join("%s (%d)" % (k, v) for k, v in
                                    sorted(by.items(), key=lambda t: -t[1])), domain))
    else:
        rows_a = accounts_from_scan(cats)
        total = dh.get("total_entries")
        staff_total = dh.get("staff_accounts_total")
        if rows_a:
            P("The scan recorded <b>%s credential record(s)</b> for this domain%s. "
              "The detail below is drawn from the sample retained with the scan."
              % ("{:,}".format(total) if isinstance(total, int) else "a number of",
                 ", covering %d staff account(s)" % staff_total
                 if isinstance(staff_total, int) and staff_total else ""))
            rows = [[Paragraph("<b>Account</b>", S["mb_small"]),
                     Paragraph("<b>Credential state</b>", S["mb_small"]),
                     Paragraph("<b>Where it appeared</b>", S["mb_small"])]]
            for a in rows_a:
                state = ("<b>Readable password</b>" if a["plaintext"]
                         else ("Hashed password" if a["hashed"]
                               else "Listed, no credential"))
                rows.append([Paragraph(a["email"], S["mb_tiny"]),
                             Paragraph(state, S["mb_tiny"]),
                             Paragraph(", ".join(a["sources"])[:90], S["mb_tiny"])])
            story.append(_table(C_RED, rows, [58 * mm, 34 * mm, 76 * mm]))
            SP(2)
        else:
            P("No credential records were recorded against this domain in this scan.")
        P("<b>Password fingerprints were not included in this brief.</b> The scan "
          "stores no password material at all, by design, so a fingerprint requires "
          "a fresh query against the credential source. Ask for the brief to be "
          "regenerated with fingerprints if the client's team needs to establish "
          "whether a leaked password is still in rotation.", "mb_small")

    # 4 -------------------------------------------------------------------
    failed = sc.get("failed_checkers") or []
    waf_affected = sc.get("waf_affected_checkers") or []
    n = 4
    if failed or waf_affected:
        P("4. What could not be assessed", "mb_h2")
        n = 5
        if waf_affected:
            waf = sc.get("waf_status", {}) or {}
            P("The web edge intervened during the assessment%s, so %d check(s) could "
              "not be verified: %s. <b>This is protective infrastructure doing its "
              "job</b> against traffic it does not recognise, not a "
              "misconfiguration. It does mean those areas are unverified rather "
              "than clean. Allow-listing the assessment source for a short window "
              "would close the gap; the full report names the source address."
              % (" (%s)" % waf.get("evidence") if waf.get("evidence") else "",
                 len(waf_affected),
                 ", ".join(a.replace("_", " ") for a in waf_affected)))
        other = [f for f in failed if f not in waf_affected]
        if other:
            P("A further %d check(s) failed to complete: %s. Their weight was "
              "excluded from the score rather than counted as a pass, so the score "
              "reflects only what could actually be established."
              % (len(other), ", ".join(o.replace("_", " ") for o in other)))

    # 5 -------------------------------------------------------------------
    P("%d. How the findings were reached" % n, "mb_h2")
    B("<b>Credentials.</b> The domain is queried against commercial breach and "
      "infostealer databases. Records are grouped by account and classified by "
      "whether a readable password, a hash, or no credential at all was present.")
    B("<b>Exposed services.</b> Publicly resolvable addresses are port-scanned from "
      "outside and each answering service is fingerprinted from its own banner, so "
      "a finding rests on the service identifying itself rather than on an open "
      "port being assumed to mean something.")
    B("<b>Vulnerabilities.</b> Known issues are matched against detected software "
      "versions. Where a version cannot be confirmed the finding is labelled "
      "unconfirmed rather than asserted, so the count is not inflated with issues "
      "that may not apply to the software actually running.")
    B("<b>Scoring.</b> Each area contributes a weighted share of the total. A check "
      "that could not run is excluded and its weight redistributed, so a blocked "
      "check never counts as a pass.")

    # 6 -------------------------------------------------------------------
    comp = sc.get("completeness_pct")
    cov = sc.get("coverage_pct")
    if isinstance(comp, (int, float)) and isinstance(cov, (int, float)) and comp != cov:
        P("%d. Two numbers that look alike and are not" % (n + 1), "mb_h2")
        P("<b>Scan completeness, %d percent</b>, is how many checks ran to "
          "completion. <b>External visibility, %d percent</b>, is how much of the "
          "estate the edge allowed the assessment to see. A scan can run every "
          "check and still see relatively little." % (round(comp), round(cov)))

    SP(3)
    P("Limits. This briefing summarises the full technical report and does not "
      "replace it. Findings are point-in-time and external only, and do not "
      "constitute a full security audit.%s%s"
      % ("  Credential detail is drawn from a complete pull of the source database "
         "on the date of this note; new records can appear at any time."
         if with_fp else "",
         "  Generated by %s." % generated_by if generated_by else ""), "mb_small")

    buf = _io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                      topMargin=14 * mm, bottomMargin=14 * mm,
                      title="%s cyber exposure briefing" % domain,
                      author="Phishield UMA").build(story)
    return buf.getvalue()
