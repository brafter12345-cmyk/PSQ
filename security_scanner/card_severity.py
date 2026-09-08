"""Per-category severity, mirroring exactly what each PDF card renders.

WHY THIS EXISTS. The PDF is the scrutinised artefact. Every category card in
pdf_cards.py computes its own traffic light from that category's NATIVE fields
-- open ports, exposed services, a grade letter, a compliance percentage -- not
from a generic `score`. Several categories have no `score` at all.

The dashboard's Risk Factors panel had no access to any of that, so it averaged
whatever `score` fields happened to exist and rendered a verdict from them. On
takealot.com that produced a green "Network Exposure - Low" drawn from
shodan_vulns alone, while the PDF's own DNS card was RED for a confirmed open
FTP port (vsFTPd 3.0.5) that the panel could not see.

Replicating these rules in TypeScript would have re-created the exact fault this
module removes: two implementations of one verdict, free to drift. Instead the
severity is computed once, here, stored on each category during scan assembly,
and read by the dashboard. `adversarial_gate` asserts these rules still match
the colours pdf_cards actually uses.

DIRECTION. Severity is about the finding, not a score: 'positive' is good.
Mapping to the PDF's colour constants:

    positive -> C_GREEN      medium -> C_AMBER
    high     -> C_RED        critical -> C_CRITICAL
    unknown  -> not assessed (the PDF renders _not_assessed_block)
"""

__all__ = ["category_severity", "SEVERITY_ORDER", "NON_CONCLUSIVE_STATUSES",
           "worst_severity"]

SEVERITY_ORDER = ["positive", "medium", "high", "critical"]

# A checker that did not produce a verdict has no severity. Mirrors the PDF,
# which renders _not_assessed_block rather than colouring the card.
NON_CONCLUSIVE_STATUSES = {
    "error", "timeout", "no_api_key", "subscription_required", "rate_limited",
    "skipped", "unreachable", "no_data", "not_applicable", "quota_exhausted",
    "disabled", "auth_failed",
    # The credential toggle was switched off FOR the operator by a failing
    # balance probe, not BY the operator. Distinct from no_api_key (a deliberate
    # deployment choice) so the scan can grade a forged skip as a failure rather
    # than certifying full confidence on an estate nobody searched.
    "probe_failed",
}


def _tl(green: bool, amber: bool) -> str:
    """pdf_helpers._tl, in severity terms."""
    if green:
        return "positive"
    if amber:
        return "medium"
    return "high"


def _num(d: dict, key: str, default=0):
    v = d.get(key, default)
    return v if isinstance(v, (int, float)) else default


def category_severity(cat_id: str, data: dict):
    """Severity for one category, or None when the category has no card verdict.

    None is returned for categories the PDF presents WITHOUT a traffic light
    (cloud_cdn is informational: "no CDN" is not a security failure). Those must
    not be folded into a dimension, or the dimension inherits a verdict the PDF
    never made.
    """
    if not isinstance(data, dict):
        return None
    if data.get("status") in NON_CONCLUSIVE_STATUSES:
        return "unknown"

    # --- Network -------------------------------------------------------
    if cat_id == "dns_infrastructure":
        # cat_dns: green only when there are no high-risk ports AND the surface
        # is small; amber when no high-risk ports; red otherwise.
        ports = data.get("open_ports", []) or []
        high = [p for p in ports if isinstance(p, dict) and p.get("risk") == "high"]
        return _tl(len(high) == 0 and len(ports) <= 2, len(high) == 0)

    if cat_id == "high_risk_protocols":
        # cat_hrp: any exposed service at all is critical.
        return "critical" if (data.get("exposed_services") or []) else "positive"

    if cat_id == "shodan_vulns":
        crit, high, med = (_num(data, "critical_count"), _num(data, "high_count"),
                           _num(data, "medium_count"))
        if crit > 0:
            return "critical"
        if high > 0:
            return "high"
        return "medium" if med > 0 else "positive"

    if cat_id == "cloud_cdn":
        return None          # informational card, no traffic light in the PDF

    if cat_id == "fraudulent_domains":
        # Severity from CAPABILITY, not from how many permutations happened to
        # resolve. Until 2026-09-08 this category had no branch here at all, so
        # category_severity returned None and the recommendation bander dropped
        # every lookalike finding into the unknown bucket. That was masked by an
        # unconditional "CRITICAL: N lookalike domains detected" issue line,
        # which the bander matched on the word CRITICAL. Removing that line for
        # being a bare-count trigger removed the only severity channel with it,
        # so the channel is restored here on the signal that actually matters.
        #
        # A lookalike that can send mail as the brand and publishes no website
        # is the classic credential-phishing setup. One that also serves a site
        # is as often an unrelated business with a similar name, so it is graded
        # lower and the card tells the reader to verify before acting.
        mail_no_site = [d for d in (data.get("fraudulent_domains") or [])
                        if isinstance(d, dict) and d.get("mail_capable")
                        and not d.get("serves_content")]
        mail_capable = data.get("mail_capable_domains") or []
        if mail_no_site:
            return "critical"
        if mail_capable:
            return "high"
        return "medium" if (data.get("fraudulent_domains") or []) else "positive"

    # --- Application ---------------------------------------------------
    if cat_id == "website_security":
        return _tl(_num(data, "score", 100) >= 80, _num(data, "score", 100) >= 50)

    if cat_id == "http_headers":
        return _tl(_num(data, "score", 100) >= 80, _num(data, "score", 100) >= 50)

    if cat_id == "waf":
        # Three states, per the 2026-08-06 fix: a vendor was fingerprinted, or
        # something refused us but could not be named, or neither. "Unconfirmed"
        # is deliberately neutral -- it may not claim protection OR its absence.
        if data.get("detected"):
            return "positive"
        if data.get("blocking_observed"):
            return "unknown"
        return "medium"

    # --- Data protection -----------------------------------------------
    if cat_id == "privacy_compliance":
        pct = _num(data, "compliance_pct")
        found = bool(data.get("policy_found"))
        if pct >= 80:
            return "positive"
        if pct >= 50:
            return "medium"
        return "high" if found else "critical"

    if cat_id == "payment_security":
        if data.get("self_hosted_payment_form"):
            return "critical"
        if data.get("has_payment_page") and not data.get("payment_page_https"):
            return "medium"
        return "positive"

    if cat_id == "exposed_admin":
        if _num(data, "critical_count") > 0:
            return "critical"
        return "high" if _num(data, "high_count") > 0 else "positive"

    if cat_id == "info_disclosure":
        return _tl(_num(data, "score", 100) >= 90, _num(data, "score", 100) >= 60)

    # --- Hardening ------------------------------------------------------
    if cat_id == "ssl":
        grade = data.get("grade", "")
        return _tl(grade in ("A+", "A", "B"), grade == "C")

    if cat_id == "email_hardening":
        # 0..10 scale, NOT 0..100. cat_email_hardening: _tl(score >= 7, score >= 3)
        return _tl(_num(data, "score") >= 7, _num(data, "score") >= 3)

    if cat_id == "security_policy":
        stxt = data.get("security_txt") or {}
        present = stxt.get("present") if isinstance(stxt, dict) else data.get("present")
        return "positive" if present else "medium"

    if cat_id == "vpn_remote":
        if data.get("rdp_exposed"):
            return "critical"
        return "positive" if data.get("vpn_detected") else "medium"

    return None


def worst_severity(severities):
    """The dimension verdict: as weak as its weakest member.

    Averaging is wrong for a risk summary -- a confirmed open FTP port does not
    become acceptable because three sibling checks were clean. 'unknown' does
    not outrank a real finding, but it is reported separately so a dimension
    resting on unassessed checks cannot pass for a clean one.
    """
    real = [s for s in severities if s in SEVERITY_ORDER]
    if not real:
        return "unknown"
    return max(real, key=SEVERITY_ORDER.index)
