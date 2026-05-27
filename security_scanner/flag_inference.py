"""Regulatory flag auto-detection utilities.

Resolves listed_company / b2c / accountable_institution / healthcare
sub-detail / GDPR / PCI flags from external scan signals so the broker
form pre-fills with sensible defaults the broker can confirm or override.

Each detector returns a dict with:
    {
        "auto_detected": bool,
        "evidence": str,    # short human-readable explanation
        ... additional fields per detector
    }

This module is invoked by:
    1. The /api/preflight endpoint (fast: domain + sub-industry only)
    2. The /api/scan flow (passes through broker-confirmed values; the
       auto-detected values come from the broker's earlier pre-flight call)

The scan result records BOTH the broker's input AND the auto-detected
value for every flag, with evidence, so the report can show the audit
trail (FAIS reasonable-advice defensibility).
"""

import re
import socket
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

USER_AGENT = "Mozilla/5.0 (Phishield Scanner) flag-inference/1.0"
HTTP_TIMEOUT = 8  # pre-flight is interactive, keep snappy


# ----------------------------------------------------------------------
# Listed company detection (JSE)
# ----------------------------------------------------------------------

# Curated JSE Top-40 + most-recognisable listed entities (snapshot 2026-05-15).
# Periodic refresh expected against JSE's published listed-companies list -
# treat as a static list, similar to GlasswingPartnerChecker.PARTNERS.
# Maps lowercase domain (or suffix) -> (ticker, full company name).
JSE_LISTED_DOMAINS = {
    # Top-40 / heavyweight
    "naspers.com":               ("NPN", "Naspers"),
    "prosus.com":                ("PRX", "Prosus N.V."),
    "richemont.com":             ("CFR", "Compagnie Financiere Richemont"),
    "bhp.com":                   ("BHG", "BHP Group"),
    "angloamerican.com":         ("AGL", "Anglo American"),
    "amplats.co.za":             ("AMS", "Anglo American Platinum"),
    "anglogoldashanti.com":      ("ANG", "AngloGold Ashanti"),
    "sasol.com":                 ("SOL", "Sasol"),
    "goldfields.com":            ("GFI", "Gold Fields"),
    "implats.co.za":             ("IMP", "Impala Platinum"),
    "sibanyestillwater.com":     ("SSW", "Sibanye Stillwater"),
    "northam.co.za":             ("NPH", "Northam Platinum"),
    "exxaroresources.com":       ("EXX", "Exxaro Resources"),
    "kumbairon.com":             ("KIO", "Kumba Iron Ore"),
    # Financial services
    "standardbank.com":          ("SBK", "Standard Bank Group"),
    "standardbank.co.za":        ("SBK", "Standard Bank Group"),
    "firstrand.co.za":           ("FSR", "FirstRand"),
    "rmbholdings.co.za":         ("RMH", "RMB Holdings"),
    "nedbank.co.za":             ("NED", "Nedbank Group"),
    "absa.africa":               ("ABG", "Absa Group"),
    "absa.co.za":                ("ABG", "Absa Group"),
    "capitecbank.co.za":         ("CPI", "Capitec Bank Holdings"),
    "investec.com":              ("INL", "Investec"),
    "investec.co.za":            ("INL", "Investec"),
    "sanlam.co.za":              ("SLM", "Sanlam"),
    "oldmutual.com":             ("OMU", "Old Mutual"),
    "oldmutual.co.za":           ("OMU", "Old Mutual"),
    "discovery.co.za":           ("DSY", "Discovery"),
    "momentum.co.za":            ("MTM", "Momentum Metropolitan Holdings"),
    "metropolitan.co.za":        ("MTM", "Momentum Metropolitan Holdings"),
    "libertyholdings.co.za":     ("LBH", "Liberty Holdings"),
    "psg.co.za":                 ("PSG", "PSG Group"),
    "santam.co.za":              ("SNT", "Santam"),
    "remgro.com":                ("REM", "Remgro"),
    # Telecoms / tech / media
    "mtn.com":                   ("MTN", "MTN Group"),
    "mtn.co.za":                 ("MTN", "MTN Group"),
    "vodacom.co.za":             ("VOD", "Vodacom Group"),
    "vodacom.com":               ("VOD", "Vodacom Group"),
    "telkom.co.za":              ("TKG", "Telkom"),
    "multichoice.com":           ("MCG", "MultiChoice Group"),
    "multichoice.co.za":         ("MCG", "MultiChoice Group"),
    # Retail / consumer
    "shoprite.co.za":            ("SHP", "Shoprite Holdings"),
    "shopriteholdings.com":      ("SHP", "Shoprite Holdings"),
    "woolworths.co.za":          ("WHL", "Woolworths Holdings"),
    "picknpay.co.za":            ("PIK", "Pick n Pay Stores"),
    "spar.co.za":                ("SPP", "The SPAR Group"),
    "mrprice.com":               ("MRP", "Mr Price Group"),
    "truworths.co.za":           ("TRU", "Truworths International"),
    "tigerbrands.com":           ("TBS", "Tiger Brands"),
    "abi.co.za":                 ("ABI", "Amalgamated Beverage Industries"),
    "distell.co.za":             ("DGH", "Distell Group"),
    "clicks.co.za":              ("CLS", "Clicks Group"),
    # Industrial / construction / chemicals
    "aveng.co.za":               ("AEG", "Aveng"),
    "barloworld.com":            ("BAW", "Barloworld"),
    "bidvest.com":               ("BVT", "The Bidvest Group"),
    "imperial.co.za":            ("IPL", "Imperial Logistics"),
    "afrimat.co.za":             ("AFT", "Afrimat"),
    "pioneerfoods.co.za":        ("PFG", "Pioneer Foods"),
    # Pharma / healthcare
    "aspen.co.za":               ("APN", "Aspen Pharmacare Holdings"),
    "aspenpharma.com":           ("APN", "Aspen Pharmacare Holdings"),
    "dischem.co.za":             ("DCP", "Dis-Chem Pharmacies"),
    "lifehealthcare.co.za":      ("LHC", "Life Healthcare Group"),
    "mediclinic.com":            ("MEI", "Mediclinic International"),
    "netcare.co.za":             ("NTC", "Netcare"),
    # Property
    "growthpoint.co.za":         ("GRT", "Growthpoint Properties"),
    "redefine.co.za":            ("RDF", "Redefine Properties"),
    "resilient.co.za":           ("RES", "Resilient REIT"),
    # Insurance
    "outsurance.co.za":          ("OUT", "OUTsurance Group"),
    "rmihholdings.com":          ("RMI", "RMI Holdings"),
}

# Footer ticker pattern: matches "JSE: ABG" or "JSE: ABG,WHL" or "JSE:ABG".
# Captures the first 3-5 letter ticker after JSE label.
JSE_TICKER_RE = re.compile(r"JSE\s*:\s*([A-Z]{2,5})\b")


def infer_listed_company(domain: str, html_content: Optional[str] = None) -> dict:
    """Detect JSE listing via static-list match (highest confidence) or
    footer ticker scrape (medium confidence). Returns a dict with
    auto_detected, jse_ticker, evidence."""
    result = {"auto_detected": False, "jse_ticker": None, "match_method": None,
              "evidence": "No JSE listing signals detected"}
    d = (domain or "").lower().strip()
    if not d:
        return result

    # Static-list direct lookup (exact or apex suffix match)
    if d in JSE_LISTED_DOMAINS:
        ticker, name = JSE_LISTED_DOMAINS[d]
        result.update(auto_detected=True, jse_ticker=ticker, match_method="static_list",
                      evidence=f"Domain matches JSE-listed entity ({name}, JSE: {ticker})")
        return result
    # Apex / subdomain suffix match
    for listed_domain, (ticker, name) in JSE_LISTED_DOMAINS.items():
        if d == listed_domain or d.endswith("." + listed_domain):
            result.update(auto_detected=True, jse_ticker=ticker, match_method="static_list_suffix",
                          evidence=f"Subdomain of JSE-listed entity ({name}, JSE: {ticker})")
            return result

    # Footer ticker scrape - cheap HTTP probe if html not already provided
    if html_content is None and REQUESTS_AVAILABLE:
        try:
            r = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT,
                             headers={"User-Agent": USER_AGENT}, allow_redirects=True)
            html_content = (r.text or "")[:40000]  # cap to footer-reachable size
        except Exception:
            html_content = None

    if html_content:
        m = JSE_TICKER_RE.search(html_content)
        if m:
            ticker = m.group(1)
            result.update(auto_detected=True, jse_ticker=ticker,
                          match_method="footer_ticker",
                          evidence=f"Homepage footer references 'JSE: {ticker}'")
            return result

    return result


# ----------------------------------------------------------------------
# Sub-industry rule-based inference (B2C, AI, healthcare detail)
# ----------------------------------------------------------------------

# B2C sub-industries (SIC labels from _bi_factor_data.json hierarchy).
# Strict conservative default: only sub-industries that are UNAMBIGUOUSLY
# consumer-facing get auto-ticked. Sub-industries that serve a mix of
# consumers and businesses (FS brokers, commercial lenders, etc.) are
# deliberately excluded - the broker must tick those manually if the
# specific client serves consumers. Mis-classifying as B2C adds CPA
# Section 112 (10% turnover or R1M) to the cat stack, which materially
# inflates exposure for B2B entities.
#
# Specifically excluded (history: 2026-05-15):
#   "Insurance Agents, Brokers, And Service" - insurance brokers can be
#       B2B (Phishield case), B2C, or mixed; SIC code does not say which
#   "Non-depository Credit Institutions" - commercial lenders are B2B;
#       consumer credit / microlenders are B2C; SIC code does not say which
B2C_SUB_INDUSTRY_LABELS = {
    # All Retail sub-industries - unambiguously consumer-facing
    "Building Materials, Hardware, Garden Supply, And Mobile Home Dealers",
    "General Merchandise Stores",
    "Food Stores",
    "Automotive Dealers And Gasoline Service Stations",
    "Apparel And Accessory Stores",
    "Home Furniture, Furnishings, And Equipment Stores",
    "Eating And Drinking Places",
    "Miscellaneous Retail",
    # Consumer-facing Services - unambiguous
    "Hotels, Rooming Houses, Camps, And Other Lodging Places",
    "Personal Services",
    "Amusement And Recreation Services",
    "Health Services",
    "Educational Services",
    "Social Services",
    "Motion Pictures",
    "Private Households",
}

# Accountable institutions per FIC Act Schedule 1. Most map directly from
# FS sub-industries; legal services and real estate are also AIs.
ACCOUNTABLE_INSTITUTION_LABELS = {
    "Depository Institutions",
    "Non-depository Credit Institutions",
    "Security And Commodity Brokers, Dealers, Exchanges, And Services",
    "Insurance Carriers",
    "Insurance Agents, Brokers, And Service",
    "Real Estate",  # estate agents are AIs
    "Holding And Other Investment Offices",
    "Legal Services",  # attorneys are AIs
}


def infer_b2c(sub_industry: Optional[str], payment_form_detected: bool = False,
              ecommerce_tech_detected: bool = False,
              insurance_subtype: Optional[str] = None) -> dict:
    """Infer B2C status from sub-industry + supporting signals.

    Honours a regulatory-structure override via `insurance_subtype`:
    UMAs (Underwriting Management Agents) and Reinsurers are B2B by
    SA insurance regulation and cannot transact directly with consumers,
    so when the insurance-subtype classifier detects either of those
    the function returns B2C=False with explicit regulatory evidence,
    regardless of other signals."""
    result = {"auto_detected": False, "evidence": "Sub-industry not flagged as B2C"}

    # Strongest negative: SA insurance regulatory structure
    if insurance_subtype == "uma":
        result.update(auto_detected=False,
                      evidence="Underwriting Management Agent - cannot sell "
                              "directly to consumers under SA insurance "
                              "regulatory structure (B2B only)")
        return result
    if insurance_subtype == "reinsurer":
        result.update(auto_detected=False,
                      evidence="Reinsurer - sells only to other insurers "
                              "(B2B only)")
        return result

    if sub_industry and sub_industry.strip() in B2C_SUB_INDUSTRY_LABELS:
        result.update(auto_detected=True,
                      evidence=f"Sub-industry '{sub_industry}' is consumer-facing")
        return result
    # Supporting signals can flip even ambiguous sub-industries to B2C
    if payment_form_detected:
        result.update(auto_detected=True,
                      evidence="Payment form detected on site (consumer checkout)")
        return result
    if ecommerce_tech_detected:
        result.update(auto_detected=True,
                      evidence="E-commerce platform detected (Shopify / WooCommerce / etc.)")
        return result
    return result


def infer_accountable_institution(sub_industry: Optional[str]) -> dict:
    """Infer FIC Act accountable-institution status from sub-industry."""
    result = {"auto_detected": False,
              "evidence": "Sub-industry not flagged as FIC accountable institution"}
    if sub_industry and sub_industry.strip() in ACCOUNTABLE_INSTITUTION_LABELS:
        result.update(auto_detected=True,
                      evidence=f"Sub-industry '{sub_industry}' is a FIC Act accountable institution")
    return result


# ----------------------------------------------------------------------
# Insurance sub-type keyword classifier
# ----------------------------------------------------------------------
# The SIC bucket "Insurance Agents, Brokers, And Service" lumps together
# several distinct entity types that SA FAIS / Insurance Act regulation
# treats very differently:
#
#   - UMA (Underwriting Management Agent) - by SA regulatory structure
#     CANNOT sell directly to consumers; underwrites on behalf of an
#     insurer and reaches the market only through brokers. B2B only.
#
#   - Reinsurer - sells only to other insurers. B2B by definition.
#
#   - Insurance broker - sells to consumers and / or businesses.
#     Mixed; broker confirms B2C status.
#
#   - Insurance carrier (direct insurer) - sells to consumers and / or
#     businesses, sometimes via own sales channels. Often B2C.
#
# The classifier inspects domain + page title + page-body keywords to
# decide which subtype the scanned entity is, then uses that result to
# refine the B2C auto-detect (UMA / Reinsurer -> negate B2C with
# evidence; Broker / Carrier -> leave B2C unset).

_INSURANCE_UMA_RE = re.compile(
    r"\b(underwriting[\s-]+manag(?:er|ing|ement)|underwriting[\s-]+agen|"
    r"\bUMA\b|managing[\s-]+general[\s-]+agen|\bMGA\b)",
    re.IGNORECASE)
_INSURANCE_REINSURER_RE = re.compile(
    r"\b(reinsur|re-insur)", re.IGNORECASE)
_INSURANCE_BROKER_RE = re.compile(
    r"\b(insurance[\s-]+broker|insurance[\s-]+brokerage|"
    r"insurance[\s-]+intermediary|insurance[\s-]+advice)",
    re.IGNORECASE)
_INSURANCE_CARRIER_RE = re.compile(
    r"\b(insurance[\s-]+company|insurance[\s-]+carrier|"
    r"life[\s-]+insurance|short-term[\s-]+insur|long-term[\s-]+insur)",
    re.IGNORECASE)


def infer_insurance_subtype(sub_industry: Optional[str], domain: Optional[str],
                             page_title: Optional[str] = None,
                             page_text_sample: Optional[str] = None) -> dict:
    """Classify FS-insurance entities into UMA / reinsurer / broker /
    carrier from website content. Only runs when the SIC sub-industry
    suggests an insurance-related entity. Returns subtype + evidence."""
    result = {"auto_detected": False, "insurance_subtype": None,
              "evidence": "Not an insurance-related sub-industry"}
    if not sub_industry:
        return result
    sub_lower = sub_industry.strip().lower()
    # Only relevant for FS sub-industries that include insurance entities
    if "insurance" not in sub_lower:
        return result

    haystack = " ".join(filter(None, [
        (domain or "").lower(),
        (page_title or "").lower(),
        (page_text_sample or "").lower()[:5000],
    ]))

    # Priority order: UMA -> Reinsurer -> Broker -> Carrier.
    # Higher-specificity entity types match first; the catch-all
    # 'carrier' regex would otherwise swallow UMAs that mention
    # "insurance company" anywhere on the page.
    if _INSURANCE_UMA_RE.search(haystack):
        result.update(auto_detected=True, insurance_subtype="uma",
                      evidence="Underwriting Management Agent (UMA) - "
                              "sells only through brokers per SA insurance "
                              "regulatory structure")
        return result
    if _INSURANCE_REINSURER_RE.search(haystack):
        result.update(auto_detected=True, insurance_subtype="reinsurer",
                      evidence="Reinsurer - sells only to other insurers")
        return result
    if _INSURANCE_BROKER_RE.search(haystack):
        result.update(auto_detected=True, insurance_subtype="broker",
                      evidence="Insurance broker / intermediary - "
                              "B2C status depends on client mix; "
                              "broker manually confirms")
        return result
    if _INSURANCE_CARRIER_RE.search(haystack):
        result.update(auto_detected=True, insurance_subtype="carrier",
                      evidence="Insurance carrier - "
                              "B2C status depends on distribution model; "
                              "broker manually confirms")
        return result
    return result


# ----------------------------------------------------------------------
# Healthcare sub-detail keyword classifier
# ----------------------------------------------------------------------

HEALTHCARE_PHARMA_KEYWORDS = re.compile(
    r"\b(pharma|pharmaceutical|biotech|biotechnology|clinical[- ]trial|medicines?|drug)",
    re.IGNORECASE)
HEALTHCARE_PHARMACY_KEYWORDS = re.compile(
    r"\b(pharmacy|chemist|dispensary|prescription)\b", re.IGNORECASE)
HEALTHCARE_SCHEME_KEYWORDS = re.compile(
    r"\b(medical[- ]scheme|medical[- ]aid|medical[- ]plan|gap[- ]cover)\b", re.IGNORECASE)


def infer_healthcare_subdetail(sub_industry: Optional[str], domain: Optional[str],
                                page_title: Optional[str] = None,
                                page_text_sample: Optional[str] = None) -> dict:
    """For Health Services sub-industry, classify the entity as one of
    medical_scheme / pharmacy / pharma / hospital_clinic via domain
    keywords + page metadata heuristics."""
    result = {"auto_detected": False, "sub_industry_detail": None,
              "evidence": "Not a Health Services sub-industry"}
    if not sub_industry or sub_industry.strip().lower() != "health services":
        return result
    # Default for Health Services: hospital_clinic. Heuristics flip
    # to more specific categories when keyword signals are present.
    haystack = " ".join(filter(None, [
        (domain or "").lower(),
        (page_title or "").lower(),
        (page_text_sample or "").lower()[:2000],
    ]))
    if HEALTHCARE_SCHEME_KEYWORDS.search(haystack):
        result.update(auto_detected=True, sub_industry_detail="medical_scheme",
                      evidence="Medical scheme keywords detected (scheme/aid/gap-cover)")
    elif HEALTHCARE_PHARMA_KEYWORDS.search(haystack):
        result.update(auto_detected=True, sub_industry_detail="pharma",
                      evidence="Pharma / biotech keywords detected")
    elif HEALTHCARE_PHARMACY_KEYWORDS.search(haystack):
        result.update(auto_detected=True, sub_industry_detail="pharmacy",
                      evidence="Pharmacy / chemist keywords detected")
    else:
        result.update(auto_detected=True, sub_industry_detail="hospital_clinic",
                      evidence="Default for Health Services with no specific subtype signal")
    return result


# ----------------------------------------------------------------------
# GDPR / PCI signal hints
# ----------------------------------------------------------------------

GDPR_KEYWORDS = re.compile(
    r"(gdpr|general data protection regulation|eu data protection|"
    r"data protection officer|cookie consent for eu|dpo@|eu representative)",
    re.IGNORECASE)
# Common EU language hints in language selectors / hreflang tags
EU_LANGUAGE_HINTS = re.compile(
    r'(?:lang=["\']|hreflang=["\'])(de|fr|it|es|nl|pt|pl|sv|fi|da|el|cs|hu|ro|bg)(?:[-_]|["\'])',
    re.IGNORECASE)
PAYMENT_FORM_HINTS = re.compile(
    r"(stripe|paypal|payfast|peach[- ]?payment|yoco|adyen|braintree|"
    r"checkout\.com|2checkout|sagepay|opayo|woocommerce|shopify)",
    re.IGNORECASE)


def infer_gdpr_suggestion(domain: Optional[str], html_content: Optional[str] = None) -> dict:
    """Infer likely GDPR applicability from EU-language site signals or
    explicit GDPR text. Suggestion only - broker confirms via flag."""
    result = {"auto_detected": False, "evidence": "No EU / GDPR signals detected"}
    if not html_content:
        return result
    if GDPR_KEYWORDS.search(html_content):
        result.update(auto_detected=True,
                      evidence="GDPR text or EU data protection references found on site")
        return result
    if EU_LANGUAGE_HINTS.search(html_content):
        result.update(auto_detected=True,
                      evidence="EU language selectors / hreflang tags suggest EU customer base")
    return result


def infer_pci_suggestion(domain: Optional[str], html_content: Optional[str] = None) -> dict:
    """Suggest PCI applicability if payment form / e-commerce platform
    signals are detected. Suggestion only - broker confirms via flag."""
    result = {"auto_detected": False, "evidence": "No payment-form signals detected"}
    if not html_content:
        return result
    m = PAYMENT_FORM_HINTS.search(html_content)
    if m:
        result.update(auto_detected=True,
                      evidence=f"Payment / e-commerce signal detected ({m.group(1)})")
    return result


# ----------------------------------------------------------------------
# Pre-flight runner
# ----------------------------------------------------------------------

def run_preflight(domain: str, sub_industry: Optional[str] = None,
                  industry: Optional[str] = None) -> dict:
    """Run all auto-detectors for the broker form. Single HTTP fetch
    shared across detectors. Returns a dict keyed by flag name."""
    domain = (domain or "").strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]

    html_content = None
    page_title = None

    # Resolve the apex - skip pre-flight if DNS doesn't resolve
    try:
        socket.gethostbyname(domain)
    except Exception:
        return {
            "domain": domain,
            "status": "dns_failed",
            "evidence": "Domain does not resolve - pre-flight aborted",
        }

    if REQUESTS_AVAILABLE:
        try:
            r = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT,
                             headers={"User-Agent": USER_AGENT}, allow_redirects=True)
            html_content = (r.text or "")[:60000]
            # Pull <title>
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", html_content,
                                    re.IGNORECASE)
            if title_match:
                page_title = title_match.group(1).strip()
        except Exception:
            html_content = None

    listed = infer_listed_company(domain, html_content)
    # Insurance-subtype classifier runs BEFORE B2C so the result can
    # feed in as a regulatory-structure override for UMA / Reinsurer.
    insurance_subtype = infer_insurance_subtype(sub_industry, domain,
                                                page_title=page_title,
                                                page_text_sample=html_content)
    b2c = infer_b2c(
        sub_industry,
        payment_form_detected=bool(html_content and PAYMENT_FORM_HINTS.search(html_content)),
        insurance_subtype=insurance_subtype.get("insurance_subtype"),
    )
    ai = infer_accountable_institution(sub_industry)
    health_detail = infer_healthcare_subdetail(sub_industry, domain,
                                                page_title=page_title,
                                                page_text_sample=html_content)
    gdpr = infer_gdpr_suggestion(domain, html_content)
    pci = infer_pci_suggestion(domain, html_content)

    # S-1 v1.1 — related-domain auto-discovery (cert SAN MVP).
    # Surfaces candidate sibling domains for broker confirmation in
    # the same pre-flight UX used for regulatory flags. Wrapped so a
    # crt.sh outage / timeout never breaks the rest of pre-flight.
    related_candidates = {"status": "skipped", "candidates": []}
    try:
        from related_domain_discovery import discover_related_domains
        related_candidates = discover_related_domains(domain)
    except Exception as _rd_err:
        related_candidates = {
            "status": "error",
            "primary_domain": domain,
            "candidates": [],
            "methods_used": [],
            "error": str(_rd_err)[:200],
        }

    return {
        "domain": domain,
        "status": "ok",
        "sub_industry": sub_industry,
        "industry": industry,
        "page_title": page_title,
        "flags": {
            "listed_company": listed,
            "b2c": b2c,
            "accountable_institution": ai,
            "sub_industry_detail": health_detail,
            "insurance_subtype": insurance_subtype,
            "gdpr_applicable": gdpr,
            "pci_applicable": pci,
        },
        "related_candidates": related_candidates,
    }
