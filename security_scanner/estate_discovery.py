# -*- coding: utf-8 -*-
"""Related domains: discover them on every scan, list them for confirmation,
and build the related_domains category. Never scan or price a domain nobody
confirmed.

WHY THIS EXISTS (remediation step 5, 2026-09-10). Related-domain discovery ran
only in the pre-flight endpoint, which only the web FORM calls. A scan submitted
through the API therefore looked for related domains not at all, and was
silently narrower than the same scan submitted through the form. Across the 30
retained scans, no scan had a related_domains result of any kind.

PARITY BY CONSTRUCTION. The candidates come from names the scan ALREADY
fetches: SubdomainChecker queries crt.sh and CertSpotter on every scan and used
to discard every name outside the scanned domain. Those names are the
related-domain candidates, so every scan, by every entry path, derives the same
list from the same fetch at no added network cost. (The stored ct_sources field
lists a source only when it returned names under the scanned domain: crt.sh did
on 7 of the 30 retained scans and CertSpotter on 27. Whether a source answered
at all is recorded separately, as ct_sources_answered.)

DISCOVER AND REPORT, NEVER CONFIRM. Certificate co-listing is a discovery signal
only: one certificate can list several unrelated organisations, so appearing on
a certificate with the insured proves nothing about who owns a name. Every
candidate here is "unconfirmed". Only a broker's confirmation on the form, or an
explicit related_domains list in an API request, moves a domain into the
assessed and priced estate, exactly as before.

WHY NOT AUTO-CONFIRM (deferred, docs/OUTSTANDING.md 5w). The only automatic
ownership guard available opens `if len(names) <= 4: return True`. Of the 26
certificates the 30 retained scans measured, 20 carry four names or fewer, so
the guard would wave through two thirds of the book. That population is the
insured's own served certificate, a proxy for the candidate-side certificates
the guard actually evaluates. It cannot be calibrated either, because a scan
stores how many names a certificate carries and not which.

ONE STATE MODEL. related_domains_state() and related_domains_fully_assessed()
define what the category says. The full PDF card, the executive deck and the
summary tier call them, and the dashboard module
(frontend/src/data/relatedDomains.ts: relatedDomainsState,
relatedDomainsFullyAssessed) is a line-for-line port that the regression gate
runs under node against these functions, so no two surfaces can disagree about
whether anything was assessed.
"""
import ipaddress
import re

from related_domain_discovery import SHARED_INFRA_SUFFIXES

try:                                   # zones that name a hosting PROVIDER
    from ip_attribution import _INFRA_ZONES as _PROVIDER_ZONES
except Exception:                      # pragma: no cover
    _PROVIDER_ZONES = ()

# How many candidates to list. The overflow is COUNTED, never silently dropped:
# not_listed_count carries it, together with any organisations the producer had
# to leave out of its stored name list (ct_foreign_orgs_dropped).
MAX_LISTED = 20

# How many confirmed domains one scan assesses (RelatedDomainsChecker.MAX_DOMAINS).
# Confirmed domains beyond it are listed as NOT assessed, never dropped.
MAX_CONFIRMED = 10

# Certificate-transparency noise that is never an organisation's domain.
_NOISE_SUFFIXES = (
    "letsencrypt.org", "digicert.com", "sectigo.com", "globalsign.com",
    "comodoca.com", "godaddy.com", "entrust.net", "amazontrust.com",
    "pki.goog", "certum.pl", "ssl.com", "zerossl.com",
)

# Platform zones whose customers share certificates or hostnames, missing from
# both SHARED_INFRA_SUFFIXES and the provider list. Each one was offered as a
# "related domain" before it was added here.
_PLATFORM_SUFFIXES = (
    "cloudflaressl.com", "azurefd.net", "trafficmanager.net", "cloudapp.net",
    "b-cdn.net", "wpengine.com", "wpenginepowered.com", "onmicrosoft.com",
    "sharepoint.com", "blogspot.com", "wordpress.com", "firebaseapp.com",
    "web.app", "hetzner.co.za",
)

# Second-level registries: a name directly under one of these IS the
# organisation's registrable domain, so the apex is three labels, not two. This
# is a named list, not the Public Suffix List (OUTSTANDING 5ad): a registry
# missing from it and from the heuristic below still reduces to the zone itself.
_MULTI_PART = (
    "co.uk", "ac.uk", "gov.uk", "org.uk", "ltd.uk", "plc.uk", "me.uk",
    "net.uk", "sch.uk", "nhs.uk", "police.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "ac.nz", "net.nz", "org.nz", "govt.nz", "school.nz", "kiwi.nz",
    "gen.nz",
    "com.br", "net.br", "org.br", "gov.br", "com.ar", "com.mx", "gob.mx",
    "co.in", "net.in", "org.in", "nic.in", "res.in", "gen.in", "firm.in",
    "co.jp", "ne.jp", "or.jp", "co.kr",
    "com.sg", "com.hk", "com.tw", "com.cn", "com.tr", "co.il", "org.il",
    "com.ph", "com.my", "co.id", "co.th", "com.vn", "com.pk", "com.eg",
    "gouv.fr", "gv.at",
    # CentralNic-style private second-level zones under .com.
    "za.com", "co.com", "uk.com",
    # Southern and East Africa, where a South African group's regional
    # entities most plausibly register.
    "com.na", "org.na", "info.na", "pro.na", "co.bw", "org.bw",
    "co.ke", "or.ke", "ac.ke", "go.ke", "sc.ke", "info.ke", "me.ke", "mobi.ke",
    "com.ng", "org.ng", "i.ng", "mobi.ng", "name.ng",
    "co.zw", "org.zw", "co.mz", "org.mz", "adv.mz",
    "co.tz", "or.tz", "sc.tz", "info.tz", "co.ug", "or.ug", "sc.ug",
    "com.gh", "org.gh", "co.zm", "org.zm", "biz.zm", "info.zm",
    "co.ls", "org.ls", "biz.ls", "info.ls", "sc.ls",
    "co.sz", "org.sz", "co.mw", "org.mw", "int.mw", "biz.mw",
    "com.mu", "org.mu",
)

# Generic second-level labels. Under a two-letter country-code TLD a name like
# acme.co.xx or acme.com.xx is registered at the third label, exactly as
# acme.co.za is. No hand list can enumerate every registry, and a missing one
# used to turn the registry zone itself into a "related domain" and merge
# unrelated organisations under it.
_GENERIC_SLD = frozenset((
    "co", "com", "net", "org", "ac", "edu", "gov", "go", "or", "ne", "mil",
    "nom", "sch",
))

_LABEL = re.compile(r"^[a-z0-9-]{1,63}$")
_REGISTRY_REASON = "not a registrable domain (registry zone, IP address or malformed)"


def _clean(host):
    h = (host or "").strip().lower()
    h = h.removeprefix("https://").removeprefix("http://").split("/")[0]
    h = h.rstrip(".")
    while h.startswith("*."):
        h = h[2:]
    return h.lstrip(".")


def registrable(host):
    """The registrable domain for *host*, or "" when it has none.

    "" for a registry zone (school.za, co.ke), an IP address or a malformed
    name, so none of those can ever be offered or accepted as a sibling.
    """
    h = _clean(host)
    if not h or "." not in h:
        return ""
    try:
        ipaddress.ip_address(h)
        return ""
    except ValueError:
        pass
    parts = h.split(".")
    if not all(_LABEL.match(p) for p in parts) or parts[-1].isdigit():
        return ""
    if parts[-1] == "za":
        # .za takes no direct second-level registrations: every name sits under
        # a registry zone (co.za, org.za, school.za, nis.za ...), so the
        # organisation is always the third label from the right.
        return ".".join(parts[-3:]) if len(parts) >= 3 else ""
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_PART or (len(parts[-1]) == 2 and parts[-2] in _GENERIC_SLD):
        return ".".join(parts[-3:]) if len(parts) >= 3 else ""
    return last_two


def _under(host, suffix):
    return host == suffix or host.endswith("." + suffix)


# Hosting and ISP groups whose own zone can sit on a certificate beside one of
# the group's other domains, keyed by the zone and listing the group's own
# registrable domains. A provider or platform zone is a candidate only for an
# insured whose registrable domain is listed against it; any other is
# rejected, however its name compares. Name likeness is not ownership:
# hetzner.co.za is xneelo's (formerly Hetzner South Africa), not Hetzner
# Online's (hetzner.com), vox.com is not Vox Telecom, and laservision.co.za
# merely contains "aserv" (step-5 critique rounds 3 to 5).
_BRAND_ALIASES = {
    "afrihost.co.za": ("afrihost.com",),
    "vox.co.za": ("voxtelecom.co.za",),
    "telkomsa.net": ("telkom.co.za",),
    "liquidtelecom.net": ("liquid.tech", "liquidtelecom.com"),
    "host-h.net": ("xneelo.co.za",),
    "hetzner.co.za": ("xneelo.co.za",),
    "is.co.za": ("internetsolutions.co.za",),
    "internetsolutions.co.za": ("is.co.za",),
}


def _same_brand(zone, primary_apex):
    """Is the provider or platform *zone* one of the insured's group's own?

    Only through _BRAND_ALIASES, on the insured's whole registrable domain
    (afrihost.com and afrihost.co.za, voxtelecom.co.za and vox.co.za). A zone
    deeper than its registrable domain, such as cloudapp.azure.com, never
    matches, because the candidate listed would be the provider's own apex.
    """
    if not zone or registrable(zone) != zone:
        return False
    return bool(primary_apex) and primary_apex in _BRAND_ALIASES.get(zone, ())


def _rejection(apex, primary_apex, raw="", scanned_host=""):
    """Why *apex* is not a related-domain candidate, or None if it is one.

    Tested against the full host as well as the reduced apex, because a
    provider zone can sit deeper than a registrable domain:
    vm1.cloudapp.azure.com reduces to azure.com, which no list names.
    """
    if not apex:
        return _REGISTRY_REASON
    host = raw or apex
    if apex == primary_apex:
        # Scanning www.acme.co.za, the certificate's acme.co.za is not "the
        # scanned domain": it is the same organisation's own domain. The
        # reason is stored with the result; the report prints reasons only for
        # rejected CONFIRMED domains.
        if (not scanned_host or host == scanned_host
                or host.endswith("." + scanned_host)):
            return "the scanned domain itself"
        return "the scanned organisation's own domain"

    def hits(suffixes):
        return [s for s in suffixes if _under(host, s) or _under(apex, s)]

    # Most specific reason first: SHARED_INFRA_SUFFIXES also lists some
    # certificate authorities.
    if hits(_NOISE_SUFFIXES):
        return "certificate authority, not an organisation"
    provider = hits(_PROVIDER_ZONES)
    if provider and not any(_same_brand(z, primary_apex) for z in provider):
        return "hosting provider's own zone"
    if hits(SHARED_INFRA_SUFFIXES):
        return "shared platform or CDN infrastructure"
    platform = hits(_PLATFORM_SUFFIXES)
    if platform and not any(_same_brand(z, primary_apex) for z in platform):
        return "shared platform or CDN infrastructure"
    return None


def discover(primary_domain, foreign_names, ct_sources_ok, attested=None,
             orgs_dropped=0, org_counts=None):
    """Build the discovery block for the related_domains category.

    ``foreign_names``  names seen on certificates alongside the primary domain.
    ``ct_sources_ok``  which certificate-transparency sources answered.
    ``attested``       domains the broker confirmed, or the API declared.
    ``orgs_dropped``   organisations the producer left out of its stored list.
    ``org_counts``     true name counts for organisations the producer sampled.

    Discovery "ran" when a source answered; foreign names can only have come
    from a source that answered, so they count too. Organisations the producer
    left out are counted as candidates: nothing examined them, so they can
    never be reported as "none found".
    """
    scanned_host = _clean(primary_domain)
    primary_apex = registrable(primary_domain) or scanned_host
    attested_set = {registrable(a) for a in (attested or []) if a}
    attested_set.discard("")
    counts = {}
    for k, v in (org_counts or {}).items():
        try:
            counts[k] = int(v)
        except (TypeError, ValueError):
            pass

    seen, candidates, rejected = {}, [], {}
    for raw in sorted({_clean(n) for n in (foreign_names or []) if n}):
        if not raw:
            continue
        apex = registrable(raw)
        why = _rejection(apex, primary_apex, raw, scanned_host)
        if why:
            rejected.setdefault(apex or raw, why)
            continue
        entry = seen.get(apex)
        if entry is None:
            entry = {"domain": apex, "sample_name": raw, "name_count": 0,
                     "source": "certificate_transparency",
                     "confidence": "unconfirmed",
                     "attested": apex in attested_set}
            seen[apex] = entry
            candidates.append(entry)
        entry["name_count"] += 1
    for c in candidates:
        # The producer keeps a few sample names per organisation; the true
        # count is the ownership signal, so rank by it.
        c["name_count"] = max(c["name_count"], counts.get(c["domain"], 0))

    # Unconfirmed candidates first: confirmed ones need no listing, and sorting
    # them first let twenty confirmed domains crowd every unconfirmed one out.
    candidates.sort(key=lambda c: (c["attested"], -c["name_count"], c["domain"]))
    listed = candidates[:MAX_LISTED]
    for c in listed:
        c["evidence"] = ("appears on a certificate alongside %s (e.g. %s)"
                         % (primary_domain, c["sample_name"]))
    dropped = max(0, int(orgs_dropped or 0))
    # Unconfirmed candidates the list could not show, plus organisations the
    # producer left out: what "and N more" counts under "awaiting
    # confirmation". Confirmed domains past the list are not awaiting
    # confirmation; the report shows them as assessed or not assessed.
    unlisted_unconfirmed = (sum(1 for c in candidates if not c["attested"])
                            - sum(1 for c in listed if not c["attested"])
                            + dropped)

    return {
        "discovery": {
            "ran": bool(ct_sources_ok) or bool(foreign_names),
            "sources_ok": sorted(ct_sources_ok or []),
            "candidate_count": len(candidates) + dropped,
            "listed_count": len(listed),
            "not_listed_count": max(0, len(candidates) - len(listed)) + dropped,
            "not_listed_unconfirmed_count": unlisted_unconfirmed,
            "not_examined_count": dropped,
            "attested_count": len(attested_set),
            "rejected_count": len(rejected),
        },
        "discovered": listed,
        "rejected": [{"domain": d, "reason": r}
                     for d, r in sorted(rejected.items())][:MAX_LISTED],
    }


_TIMEOUT_ISSUE = ("Confirmed related domains could not be assessed within the "
                  "time allowed; they are NOT assessed, not clean.")
_ERROR_ISSUE = ("Confirmed related domains could not be assessed on this scan "
                "because the assessment failed; they are NOT assessed, not clean.")
_NOT_MEASURED_ISSUE = ("None of the checks on the confirmed related domains "
                       "returned a result; they are NOT assessed, not clean.")
_SCANNED_HOST_REASON = "the scanned domain itself, assessed by the main scan"
_OWN_SUBDOMAIN_REASON = ("a subdomain of the scanned domain: the insured's own "
                         "host, not a related organisation, and not assessed "
                         "separately on this scan")


def build_related_domains_category(domain, related_domains, subdomains_result,
                                   run_probe):
    """The related_domains category for one scan (remediation step 5).

    scanner.scan() calls this exactly once and assigns what it returns, and the
    regression gate drives this same function, so the status mapping the gate
    tests is the one a scan runs. ``run_probe(domains)`` returns
    RelatedDomainsChecker's result for exactly those domains, or a dict whose
    status is "timeout" or "error".

    STATUS CONTRACT, measured over the 30 retained scans: a related_domains
    category that is absent, completed with score 100, or unassessed prices at
    exactly +0, while skipped, error and timeout price at +5 to +16. So the
    category is only ever "completed" or "unassessed", and anything the scan
    did not measure is "unassessed", never a clean "completed".
    """
    sub = subdomains_result if isinstance(subdomains_result, dict) else {}
    host = _clean(domain)

    # A subdomains result without ct_foreign_names was not produced by this
    # code: a checkpoint written before the change, or a checker that timed out
    # or failed. Discovery did not run on it, whatever else it carries.
    if "ct_foreign_names" in sub and sub.get("status", "completed") == "completed":
        foreign = sub.get("ct_foreign_names") or []
        answered = sub.get("ct_sources_answered")
        if answered is None:
            answered = sub.get("ct_sources") or []
        dropped = sub.get("ct_foreign_orgs_dropped") or 0
        org_counts = sub.get("ct_foreign_org_counts") or {}
    else:
        foreign, answered, dropped, org_counts = [], [], 0, {}
    # Why discovery did not run, when it did not, so every surface can say so.
    if not sub or sub.get("status", "completed") != "completed":
        not_run_reason = "subdomains_failed"
    elif "ct_foreign_names" not in sub:
        not_run_reason = "prechange_checkpoint"
    else:
        not_run_reason = "ct_unanswered"

    # The confirmed list, cleaned the way the report shows it. The scanned host
    # is assessed by the main scan. A host under it is the insured's own, not a
    # related organisation; the main scan does not check its certificate or
    # its web paths either, and the report says it is not assessed separately
    # (OUTSTANDING 5w). Anything that is not a registrable domain is never
    # probed, because a registry zone such as school.za would otherwise be
    # port-scanned and scored as the client's sibling. The parent or sibling
    # hosts of a scanned SUBDOMAIN are none of these, and are probed like any
    # confirmed domain.
    confirmed, confirmed_rejected, seen = [], [], set()
    for raw in related_domains or []:
        if not isinstance(raw, str):
            continue
        d = _clean(raw)
        if not d or d in seen:
            continue
        seen.add(d)
        if not registrable(d):
            confirmed_rejected.append({"domain": d, "reason": _REGISTRY_REASON})
        elif d == host:
            confirmed_rejected.append({"domain": d, "reason": _SCANNED_HOST_REASON})
        elif d.endswith("." + host):
            confirmed_rejected.append({"domain": d, "reason": _OWN_SUBDOMAIN_REASON})
        else:
            confirmed.append(d)
    probe_list, over_cap = confirmed[:MAX_CONFIRMED], confirmed[MAX_CONFIRMED:]

    estate = discover(domain, foreign, answered, attested=confirmed,
                      orgs_dropped=dropped, org_counts=org_counts)
    ran = estate["discovery"]["ran"]
    if not ran:
        estate["discovery"]["not_run_reason"] = not_run_reason

    rd = {"status": "completed", "score": 100, "declared_count": 0,
          "scanned_count": 0, "dependants": [], "worst_domain": None,
          "critical_count": 0, "high_count": 0, "issues": []}
    not_assessed = []
    if not probe_list:
        if not ran:
            rd.update(status="unassessed", unassessed_reason="discovery_not_run")
    else:
        try:
            got = run_probe(list(probe_list))
        except Exception as exc:
            got = {"status": "error", "error": str(exc)[:120]}
        got = dict(got) if isinstance(got, dict) else {"status": "error"}
        if got.get("status") == "completed":
            rd.update(got)
            # Only an explicit measured=True counts. A result without that
            # marker was written by the pre-change checker (a checkpoint loaded
            # on resume), whose `int(x or 100)` had already read a measured 0 as
            # a clean 100: it measured nothing this code can trust.
            measured = {dep.get("domain") for dep in (rd.get("dependants") or [])
                        if isinstance(dep, dict) and dep.get("measured") is True}
            not_assessed = [d for d in probe_list if d not in measured]
            if not measured or not int(rd.get("scanned_count") or 0):
                # Nothing measured: NOT ASSESSED, never a clean "completed".
                rd.update(status="unassessed", unassessed_reason="not_measured",
                          score=100, critical_count=0, high_count=0,
                          worst_domain=None, issues=[_NOT_MEASURED_ISSUE])
                not_assessed = list(probe_list)
            else:
                rd["status"] = "completed"
        else:
            reason = "timeout" if got.get("status") == "timeout" else "error"
            rd.update(status="unassessed", unassessed_reason=reason,
                      issues=[_TIMEOUT_ISSUE if reason == "timeout" else _ERROR_ISSUE])
            not_assessed = list(probe_list)
        rd["declared_count"] = len(probe_list)

    rd["confirmed_not_assessed"] = not_assessed
    rd["confirmed_over_cap"] = over_cap
    rd["confirmed_rejected"] = confirmed_rejected
    # Everything the broker or the API submitted: probed, over the cap, or
    # rejected. The report shows it beside the number assessed.
    rd["submitted_count"] = len(confirmed) + len(confirmed_rejected)
    rd.update(estate)
    return rd


def related_domains_state(rd):
    """What the related_domains category says, as one of six states.

    not_run                no discovery on this scan (stored before step 5)
    degraded               discovery could not run and nothing was confirmed
    none_found             discovery ran, found nothing, nothing confirmed
    awaiting_confirmation  discovery found candidates, nothing confirmed
    confirmed              confirmed domains were assessed (possibly partly:
                           see related_domains_fully_assessed)
    confirmed_unassessed   confirmed domains could not be assessed

    The dashboard's relatedDomainsState (frontend/src/data/relatedDomains.ts)
    is a line-for-line port, run against this function by the regression gate.
    """
    if not rd:
        return "not_run"
    if "discovery" not in rd:
        # Stored before step 5. Only a completed probe that measured at least
        # one confirmed sibling was an assessment; every other stored status,
        # including "skipped", "timeout" and "error", was not.
        if (rd.get("status") == "completed" and (rd.get("declared_count") or 0)
                and (rd.get("scanned_count") or 0)):
            return "confirmed"
        return "not_run"
    disc = rd.get("discovery") or {}
    if rd.get("declared_count") or 0:
        return "confirmed" if rd.get("status") == "completed" else "confirmed_unassessed"
    if rd.get("status") != "completed" or not disc.get("ran"):
        return "degraded"
    return ("awaiting_confirmation" if int(disc.get("candidate_count") or 0)
            else "none_found")


def related_domains_gaps(rd):
    """What a confirmed-domain assessment did NOT cover.

    Returns (not_assessed, over_cap, partial): confirmed domains the probe did
    not measure, confirmed domains beyond the cap, and (domain, [checks])
    pairs for domains on which some checks returned no result.
    """
    rd = rd or {}
    na = (list(rd.get("confirmed_not_assessed") or [])
          if rd.get("status") == "completed" else [])
    oc = list(rd.get("confirmed_over_cap") or [])
    partial = [(d.get("domain"), list(d.get("not_measured") or []))
               for d in (rd.get("dependants") or [])
               if isinstance(d, dict) and d.get("measured") is True
               and d.get("not_measured")]
    return na, oc, partial


def related_domains_certificate_coverage(rd):
    """Describe source response coverage without claiming estate completeness."""
    if "discovery" not in (rd or {}):
        return None
    disc = rd.get("discovery")
    if not isinstance(disc, dict) or not isinstance(disc.get("sources_ok"), list):
        return "Certificate-source coverage was not recorded for this scan."
    answered = {x for x in disc["sources_ok"] if isinstance(x, str)} & {"crtsh", "certspotter"}
    count = len(answered)
    qualifier = ("discovery coverage is partial" if count < 2 else
                 "this does not prove a complete estate")
    return "Certificate discovery: %d of 2 sources answered; %s." % (count, qualifier)


def related_domains_fully_assessed(rd):
    """True only when every confirmed domain was assessed by every check.

    A partly assessed estate is not clean: the deck files it NOT ASSESSED
    rather than LOW, the summary row says it is not fully assessed, and no
    surface says it "passed". A result stored before step 5 is never fully
    assessed: the check then counted a sub-check that returned nothing as a
    pass (a finding in it still loads). The dashboard's
    relatedDomainsFullyAssessed is a line-for-line port.
    """
    if "discovery" not in (rd or {}):
        return False
    na, oc, partial = related_domains_gaps(rd)
    return related_domains_state(rd) == "confirmed" and not (na or oc or partial)
