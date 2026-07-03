"""
Section 4.6 — Exposure & Reputation
Phishield Cyber Risk Scanner User Manual

Covers all 18 sub-checkers in the Exposure & Reputation category:
  1. Credential Exposure (HIBP)
  2. IP/Domain Reputation (DNSBL)
  3. Exposed Admin Panels
  4. Subdomain Exposure (CT Logs)
  5. CVE / Known Vulnerabilities (Shodan)
  6. Dehashed Credential Leaks
  7. Infostealer Detection (Hudson Rock)
  8. Dark Web Monitoring (IntelX)
  9. Credential Risk Assessment
 10. VirusTotal Reputation
 11. Fraudulent Domains (Typosquat)
 12. Supply-Chain / Related Domains (S-1)
 13. Exposed Dependency Manifests (S-3)
 14. Third-Party JavaScript (S-2)
 15. Email-Vendor Surface (S-4)
 16. CMS Plugin Surface (S-10)
 17. Vendor Breach Correlation (S-5)
 18. Cross-Correlation (Hudson Rock × S-4 × S-5)
"""

from manual_helpers import (
    add_h1, add_h2, add_body, add_bold_body, add_bullet, add_tip,
    add_warning, add_note,
)


def build(doc):
    """Add Section 4.6 — Exposure & Reputation to the document."""

    # ── Section heading ──────────────────────────────────────────────────
    add_h1(doc, "4.6  Exposure & Reputation")

    add_body(
        doc,
        "The Exposure & Reputation category is the largest in the scanner, "
        "comprising eleven distinct sub-checkers that together paint a "
        "comprehensive picture of a domain's threat-intelligence footprint. "
        "While the preceding categories examine how a domain is configured, "
        "these checks ask a different question: what does the outside world "
        "already know about this domain, and how has it been affected by "
        "breaches, malware, blacklisting, and criminal activity?"
    )

    add_body(
        doc,
        "For insurance underwriting this category is arguably the most "
        "impactful. A company may have perfect TLS and DNS configurations, "
        "but if employee credentials are circulating on dark-web markets or "
        "the domain's IP is blacklisted for spam, the residual risk is "
        "material. Exposure findings often correlate directly with the "
        "likelihood of a future claim — particularly credential-stuffing "
        "attacks, business-email compromise, and ransomware intrusions."
    )

    add_body(
        doc,
        "Several checkers in this category rely on paid or credit-based "
        "APIs (Dehashed, IntelX). These are toggleable in the scanner UI "
        "and will degrade gracefully when disabled, showing a 'no_api_key' "
        "status rather than failing the scan."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.1  Credential Exposure (HIBP)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.1  Credential Exposure (HIBP)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner queries the Have I Been Pwned (HIBP) breaches-by-domain "
        "API to determine whether email addresses belonging to the target "
        "domain appear in any of the 700+ known data breaches catalogued by "
        "HIBP. The API returns the number of breaches, the date of the most "
        "recent breach, and the data classes exposed in each incident "
        "(passwords, email addresses, names, phone numbers, physical "
        "addresses, dates of birth, IP addresses, and more)."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "A single GET request is sent to the HIBP v3 API endpoint with the "
        "target domain as a query parameter. When an HIBP API key is "
        "configured the scanner uses authenticated access for higher rate "
        "limits; without a key the free tier is used. The response contains "
        "an array of breach objects, each including the breach name, date, "
        "record count (PwnCount), and the list of DataClasses that were "
        "exposed. The scanner aggregates these into a deduplicated set of "
        "data classes and identifies the most recent breach date."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Credential exposure is one of the strongest predictors of future "
        "compromise. If employee passwords leaked in a breach and were never "
        "rotated, attackers can use credential-stuffing tools to gain access "
        "to corporate systems. Breaches that include passwords, security "
        "questions, or phone numbers are especially dangerous because they "
        "enable multi-vector attacks — password reuse, SIM-swapping, and "
        "social-engineering of help desks."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "The score starts at 100 and is reduced based on the number of "
        "breaches found. A single breach results in a moderate penalty; "
        "multiple breaches with password exposure result in steeper "
        "deductions. The recency of breaches is also considered — a breach "
        "from 2024 is weighted more heavily than one from 2015 because "
        "credentials are more likely to still be valid."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "Domain found in 3 known data breach(es) — this is a typical "
        "result for established businesses. The breach names, dates, and "
        "exposed data types are listed in the report."
    )
    add_bullet(
        doc,
        "Data classes exposed: Email addresses, Passwords, Names, Phone "
        "numbers — the more sensitive data classes present, the higher the "
        "risk to the organisation."
    )
    add_bullet(
        doc,
        "Most recent breach: 2024-01-15 — recent breaches are flagged "
        "prominently because the exposed credentials may still be in active "
        "use."
    )

    add_note(
        doc,
        "HIBP only reports breaches where the domain's email addresses "
        "appeared. It does not indicate whether specific individuals' "
        "passwords were exposed — that detail comes from the Dehashed "
        "checker (Section 4.6.6). HIBP provides the breadth view; Dehashed "
        "provides the depth."
    )

    add_tip(
        doc,
        "If HIBP reports breaches with 'Passwords' in the data classes, "
        "treat this as a HIGH-priority finding. Recommend the client force "
        "password resets for all accounts and enable MFA organisation-wide."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.2  IP/Domain Reputation (DNSBL)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.2  IP/Domain Reputation (DNSBL)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner queries multiple DNS-based blackhole lists (DNSBLs) to "
        "determine whether the domain's IP address or the domain name itself "
        "is listed. A listing indicates that the IP or domain has been "
        "associated with spam, malware distribution, or other malicious "
        "activity at some point."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "For IP-based checks, the scanner reverses the IP address octets "
        "and performs DNS A-record lookups against four major blacklists: "
        "Spamhaus ZEN (zen.spamhaus.org), SpamCop (bl.spamcop.net), "
        "Barracuda (b.barracudacentral.org), and UCEProtect "
        "(dnsbl-1.uceprotect.net). For domain-based checks, it queries "
        "Spamhaus DBL (dbl.spamhaus.org) and URIBL (uribl.com). A bare DNS "
        "resolution is not by itself treated as a listing: the scanner "
        "validates each reply against the list's documented return codes "
        "and only counts a genuine listing code (typically 127.0.0.2 and "
        "above). Error, blocked, and refused replies — Spamhaus open-"
        "resolver / rate-limit codes in the 127.255.255.x range and the "
        "URIBL 127.0.0.1 query-refused code — are explicitly rejected, so "
        "an infrastructure response is never mistaken for a blacklisting."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "A blacklisted IP or domain signals a history of compromise or "
        "abuse. Even if the current owner is legitimate, a listing on "
        "Spamhaus or Barracuda means the infrastructure has been used to "
        "send spam or distribute malware — either by the current tenant or "
        "a previous one. Blacklisting also destroys email deliverability, "
        "which can be a business-continuity issue for companies that rely "
        "on email for client communication."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "A clean DNSBL check (no listings) leaves the score at 100. Each "
        "listing on a major blacklist (Spamhaus, Barracuda) results in a "
        "significant penalty. Multiple listings compound the deduction. The "
        "DNSBL weight in the overall score is 6%, reflecting its importance "
        "as an indicator of active or recent compromise."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "Domain/IP listed on 1 blacklist(s): zen.spamhaus.org — this is "
        "the most common single listing and indicates the IP has been "
        "flagged for spam or malware activity."
    )
    add_bullet(
        doc,
        "Listed on dnsbl-1.uceprotect.net — UCEProtect listings often "
        "indicate the IP sits on a range with a poor sending reputation or "
        "has been an open relay."
    )
    add_bullet(
        doc,
        "No listings found — this is the desired result and confirms the "
        "domain's infrastructure has a clean reputation."
    )

    add_warning(
        doc,
        "A Spamhaus listing is particularly serious because many enterprise "
        "email gateways reject mail from Spamhaus-listed IPs outright. If "
        "a client's domain is listed, their business emails may be silently "
        "dropped by recipients."
    )

    add_note(
        doc,
        "Shared-hosting environments can produce false positives: another "
        "tenant on the same IP may have caused the listing. The scanner "
        "reports the finding regardless because the risk to the client is "
        "real — they share the reputational damage."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.3  Exposed Admin Panels
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.3  Exposed Admin Panels")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner probes the domain for 46 common administrative, "
        "configuration, and development paths across three risk tiers. "
        "Critical paths include .env files, .git/HEAD, wp-config.php, "
        "database dumps (backup.sql, dump.sql), and .htpasswd files. High-"
        "risk paths include /admin, /administrator, /wp-admin, /wp-login.php, "
        "/phpmyadmin, /cpanel, /jenkins, /grafana, /kibana, /portainer, "
        "/gitlab, and API user endpoints. Medium-risk paths include "
        "/server-status, /actuator, /swagger-ui, /phpinfo.php, and similar "
        "information-disclosure endpoints."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "HTTPS GET requests are sent to each path with a four-second timeout "
        "and redirects disabled. Up to 15 paths are probed concurrently using "
        "a thread pool. Only an HTTP 200 response that also passes a body-"
        "sanity check counts as an exposure — confirming the path is directly "
        "accessible and is serving real content rather than a generic landing "
        "or error page. HTTP 401 and 403 responses are treated as PROTECTED "
        "(access-controlled) and are NOT counted as findings: a server that "
        "returns 403 on /.env or /wp-admin is enforcing access control, which "
        "is the desired posture. This 200-only, body-checked approach mirrors "
        "the dependency-manifest probe and prevents WAF/CDN-defended sites "
        "from being penalised for blocking the probe."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Exposed admin panels are a direct attack surface. An accessible "
        "/wp-admin or /phpmyadmin page is an invitation for brute-force "
        "attacks. Exposed .env files frequently contain database credentials, "
        "API keys, and secret tokens in plaintext. Exposed .git/HEAD "
        "allows attackers to reconstruct the entire source code repository. "
        "These findings represent some of the lowest-effort, highest-reward "
        "attack vectors available to adversaries."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Each exposed path carries a penalty based on its risk tier. "
        "Critical findings (exposed .env, .git, database dumps) incur the "
        "heaviest penalties. High-risk findings (admin login pages) carry "
        "moderate penalties. Medium-risk findings (server-status, swagger) "
        "carry lighter penalties. A single exposed .env file can reduce the "
        "score by 25 points or more."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "/.env — HTTP 200 (CRITICAL): The environment file is publicly "
        "readable. This typically exposes database host, username, password, "
        "API keys, and application secrets."
    )
    add_bullet(
        doc,
        "/wp-admin — HTTP 200: The WordPress administration panel is "
        "accessible from the public internet without IP restriction."
    )
    add_bullet(
        doc,
        "/server-status — HTTP 200 (MEDIUM): Apache mod_status is enabled, "
        "leaking active connections, client IPs, and request URLs."
    )
    add_bullet(
        doc,
        "/.git/HEAD — HTTP 200 (CRITICAL): The Git repository metadata is "
        "publicly readable, allowing an attacker to reconstruct the source "
        "tree. A path that instead returns 401/403 is reported as protected "
        "and does not appear as a finding."
    )

    add_warning(
        doc,
        "An exposed .env file is one of the most critical findings the "
        "scanner can produce. It should be treated as an active compromise "
        "— all secrets in that file must be rotated immediately."
    )

    add_tip(
        doc,
        "Recommend clients restrict all admin paths to internal IPs or "
        "require VPN access. Default admin URLs should be renamed where the "
        "platform supports it (e.g., renaming /wp-admin to a custom path)."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.4  Subdomain Exposure (CT Logs)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.4  Subdomain Exposure (CT Logs)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner discovers subdomains through two methods. Certificate "
        "Transparency (CT) log scanning is the PRIMARY source: it reveals "
        "every subdomain that has ever had a public certificate issued. The "
        "scanner queries TWO independent CT-log providers, crt.sh and "
        "certspotter, in parallel and merges (unions) their results, so a "
        "slow or failed response from one provider does not lose coverage. "
        "DNS brute-force resolution of 50+ common prefixes (www, mail, vpn, "
        "dev, staging, test, admin, api, beta, backup, jenkins, gitlab, "
        "jira, grafana, kibana, phpmyadmin, cpanel, owa, exchange, and many "
        "more) is the secondary source, used to catch subdomains that have "
        "no certificate. Discovered subdomains are classified as 'risky' "
        "when a risk keyword (dev, staging, admin, backup, and similar) "
        "appears as a distinct label; the apex itself and the ordinary www "
        "host are excluded from the risky count."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "First, the scanner queries both CT-log providers (crt.sh and "
        "certspotter) in parallel and unions the subdomains they return. "
        "Certificate Transparency reveals subdomains the organisation may "
        "have forgotten about, such as old staging servers, decommissioned "
        "APIs, and test environments. Querying two providers matters because "
        "crt.sh in particular is prone to timeouts and rate-limiting under "
        "load; when it fails, certspotter still supplies CT coverage, so "
        "enumeration does not silently collapse to the brute-force list "
        "alone. If BOTH CT providers are unreachable on a given scan, the "
        "card is flagged low-coverage: the report states plainly that the "
        "external attack surface is likely under-reported, and that a fall "
        "in subdomain count versus a prior scan should be read as missing "
        "data rather than as the organisation having removed subdomains. "
        "Second, the scanner resolves each of the 50+ brute-force prefixes "
        "via DNS. Before doing so it runs a wildcard-DNS guard: two random "
        "non-existent labels are resolved, and if they answer (meaning "
        "*.domain is a catch-all wildcard) brute-force discovery is "
        "suppressed, because every guessed prefix would otherwise appear to "
        "resolve and fabricate subdomains that do not exist."
    )

    add_bold_body(
        doc,
        "Phase 3 — Subdomain Takeover Detection: ",
        "For every discovered subdomain, the scanner checks the CNAME "
        "record to determine whether it points to a third-party cloud "
        "service. If the CNAME target matches one of 28 known takeover "
        "signatures (GitHub Pages, AWS S3, Heroku, Azure Web Sites, Azure "
        "Blob, Azure Traffic Manager, Netlify, Vercel, Shopify, Ghost, "
        "Surge, Bitbucket, WordPress.com, Pantheon, Unbounce, Zendesk, "
        "Fastly, Fly.io, Render, and others), the scanner checks whether "
        "the target is dangling — meaning the CNAME points to a service "
        "endpoint that no longer exists. A dangling CNAME is confirmed by "
        "either NXDOMAIN resolution or an HTTP response matching the "
        "service's known 'not configured' fingerprint (e.g., 'There isn't "
        "a GitHub Pages site here' or 'NoSuchBucket' for S3). A confirmed "
        "dangling CNAME means an attacker can claim the endpoint and serve "
        "arbitrary content on the organisation's subdomain."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Forgotten subdomains are one of the most common entry points in "
        "real-world breaches. A staging server with default credentials, a "
        "dev environment with debug mode enabled, or a decommissioned app "
        "with unpatched vulnerabilities — all are discovered by attackers "
        "using the same techniques this scanner employs. Subdomain takeover "
        "is particularly dangerous because it allows an attacker to host "
        "phishing pages on a legitimate subdomain (e.g., "
        "login.staging.example.com), bypassing email security filters "
        "and SSL certificate warnings that would normally alert users."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "The subdomain checker carries a 2% weight in the overall score. "
        "Risky subdomains (containing keywords like dev, staging, admin, "
        "backup) each incur a penalty. Confirmed subdomain takeover "
        "vulnerabilities carry the heaviest penalty — a single takeover-"
        "vulnerable subdomain can significantly reduce the score because "
        "it represents an immediately exploitable issue."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "12 subdomains discovered, 4 classified as risky (dev.example.com, "
        "staging.example.com, test.example.com, admin.example.com)."
    )
    add_bullet(
        doc,
        "SUBDOMAIN TAKEOVER: old-blog.example.com CNAME points to "
        "example.github.io — endpoint unclaimed. An attacker can register "
        "this GitHub Pages repository and serve content on the subdomain."
    )
    add_bullet(
        doc,
        "vpn.example.com, owa.example.com — internal service subdomains "
        "are publicly resolvable, revealing the organisation's internal "
        "infrastructure topology."
    )

    add_warning(
        doc,
        "Subdomain takeover vulnerabilities should be treated as CRITICAL. "
        "The remediation is simple — remove the dangling CNAME record from "
        "DNS — but the risk of phishing or malware hosting is immediate."
    )

    add_tip(
        doc,
        "Advise clients to maintain a subdomain inventory and review it "
        "quarterly. Any subdomain pointing to a third-party service should "
        "be removed when that service is decommissioned."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.5  CVE / Known Vulnerabilities (Shodan)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.5  CVE / Known Vulnerabilities (Shodan)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner queries Shodan to identify known CVE vulnerabilities "
        "associated with each of the domain's IP addresses. It uses two "
        "data sources: Shodan InternetDB (free, no API key required) for "
        "basic CVE lists and open ports, and the full Shodan API (when a "
        "key is configured) for detailed service banners, OS detection, "
        "ISP/ASN information, and per-port service identification. Each "
        "discovered CVE is then enriched from multiple sources."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "For each IP address resolved from the domain, the scanner first "
        "attempts the full Shodan API (if a key is available), then falls "
        "back to InternetDB. The returned CVE list is enriched with: "
        "(1) CVSS scores from the NVD (National Vulnerability Database), "
        "including the full CVSS vector string and exploitability indicators "
        "(network-accessible, low-complexity, no privileges required); "
        "(2) CISA KEV (Known Exploited Vulnerabilities) status, which "
        "flags CVEs that are confirmed to be actively exploited in the "
        "wild; (3) EPSS (Exploit Prediction Scoring System) probability "
        "from FIRST.org, which estimates the likelihood a CVE will be "
        "exploited in the next 30 days; (4) exploit maturity classification "
        "(weaponized, poc_public, or theoretical) based on cross-referencing "
        "Metasploit modules and ExploitDB entries; and (5) OSV.dev "
        "enrichment that adds version-to-vulnerability matching. The "
        "scanner also calculates patch management metrics: the oldest "
        "unpatched CVE, the average CVE age, and an age-band distribution."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Unpatched vulnerabilities with public exploits are the single "
        "most common initial access vector in ransomware attacks. A CVE "
        "that is listed in CISA KEV is not a theoretical risk — it is "
        "being actively exploited by threat actors right now. EPSS scores "
        "above 0.5 (50% exploitation probability in 30 days) demand "
        "immediate attention. For underwriters, this checker provides the "
        "clearest view of whether the organisation keeps its "
        "internet-facing infrastructure patched."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Scoring is per-IP and based on the severity and exploitability of "
        "discovered CVEs. Critical CVEs (CVSS 9.0+) carry the heaviest "
        "penalty, especially when combined with CISA KEV status or a "
        "weaponized exploit. High CVEs (CVSS 7.0-8.9) carry moderate "
        "penalties. The EPSS probability acts as a multiplier — a medium-"
        "severity CVE with 80% EPSS is scored more harshly than a high-"
        "severity CVE with 1% EPSS. The Shodan checker is one of the "
        "highest-weighted components in the overall score calculation."
    )

    add_note(
        doc,
        "Version-confirmation gating. Where a CVE is inferred from an open "
        "port or a service template rather than from a confirmed software "
        "version, the scanner marks it as version-unconfirmed and the report "
        "presents it as a potential, unconfirmed finding. When a detected "
        "service banner names a different product than a templated CVE "
        "assumes (for example a Pure-FTPd banner on a port whose template "
        "lists ProFTPD vulnerabilities), that CVE is dropped rather than "
        "shown. The CISA KEV 'actively exploited' badge is displayed only "
        "for CVEs that survive this gating, so a well-defended host is not "
        "tagged with exploited-CVE warnings it does not actually carry."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "Per-IP vulnerability cards listing each CVE with its CVSS score, "
        "severity badge, EPSS percentage, and exploit maturity status."
    )
    add_bullet(
        doc,
        "CVE-2024-XXXXX — CVSS 9.8 (CRITICAL) — CISA KEV: Yes — EPSS: "
        "94.2% — Exploit: weaponized. This is the worst-case scenario: a "
        "critical vulnerability with a public weaponized exploit that is "
        "known to be actively exploited."
    )
    add_bullet(
        doc,
        "Patch management posture: oldest unpatched CVE is 847 days old, "
        "average CVE age is 423 days. Age bands: 0-90 days (2 CVEs), "
        "91-365 days (5 CVEs), 365+ days (8 CVEs)."
    )
    add_bullet(
        doc,
        "Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), "
        "8080 (HTTP-alt). Service banners reveal software versions that "
        "may be vulnerable."
    )

    add_warning(
        doc,
        "Any CVE with CISA KEV status should be treated as requiring "
        "immediate patching. These are not theoretical vulnerabilities — "
        "they are confirmed to be in active exploitation by ransomware "
        "groups, nation-state actors, or criminal organisations."
    )

    add_note(
        doc,
        "Shodan data reflects what is visible from the internet. Internal "
        "vulnerabilities behind firewalls are not detected. The scanner "
        "complements (but does not replace) internal vulnerability scanning."
    )

    add_note(
        doc,
        "Source-honesty: the free Shodan InternetDB path does not return "
        "ASN or hosting-country data, so when only InternetDB is available "
        "the card shows ASN and Country as 'not available' rather than "
        "inventing a placeholder count. Similarly, when OSV.dev reports a "
        "vulnerability with no real CVSS score, the severity is shown as "
        "estimated (derived from the database's own severity label) and "
        "flagged as such, rather than presenting a fabricated numeric CVSS."
    )

    add_tip(
        doc,
        "When presenting findings, prioritise by EPSS and KEV status "
        "rather than raw CVSS score. A CVSS 7.0 CVE with 90% EPSS is more "
        "urgent than a CVSS 9.8 CVE with 0.1% EPSS."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.6  Dehashed Credential Leaks
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.6  Dehashed Credential Leaks")

    add_bold_body(
        doc,
        "What it checks: ",
        "Dehashed is a paid, credit-based API that searches aggregated "
        "credential leak databases for entries associated with the target "
        "domain. Unlike HIBP (which reports breaches at the domain level), "
        "Dehashed returns individual credential records — including email "
        "addresses, passwords (plaintext or hashed), usernames, names, and "
        "IP addresses. This checker is toggleable in the scanner UI because "
        "it consumes API credits."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The scanner sends a POST request to the Dehashed v2 API (falling "
        "back to the v1 GET endpoint if v2 is unavailable) with a domain "
        "search query. The response includes up to 100 credential records "
        "per page, along with a total count. The scanner processes each "
        "record to extract: unique email addresses, password presence, "
        "breach source names, and breach details."
    )

    add_bold_body(
        doc,
        "Phase 3 — Credential Type Parsing: ",
        "For every record that contains a password or hashed_password field, "
        "the scanner classifies the credential type. Plaintext passwords "
        "are identified when the password field contains a readable string "
        "that does not match any known hash pattern. Hashed passwords are "
        "identified using regex patterns for seven hash types: bcrypt "
        "($2a$/$2b$/$2y$ prefix), argon2 ($argon2i$/$argon2d$/$argon2id$ "
        "prefix), scrypt ($s0$ prefix), SHA-512 (128 hex characters), "
        "SHA-256 (64 hex characters), SHA-1 (40 hex characters), and "
        "MD5/NTLM (32 hex characters). Hash types are further classified "
        "as weak (MD5, SHA-1, NTLM — easily cracked) or strong (bcrypt, "
        "argon2, scrypt, SHA-256, SHA-512 — computationally expensive to "
        "crack). The scanner also splits findings into corporate email "
        "addresses (matching the target domain) versus personal email "
        "addresses (Gmail, Yahoo, etc.)."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Enhanced scoring assigns different penalties per credential type. "
        "Plaintext passwords incur -5 points per record (the credentials "
        "are immediately usable). Weak hashes (MD5, SHA-1, NTLM) incur -3 "
        "points per record (crackable in minutes to hours). Strong hashes "
        "(bcrypt, argon2) incur -1 point per record (resistant to brute-"
        "force but still exposed). The overall Dehashed weight is 3% of "
        "the total score."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "47 credential records found across 6 breach sources, 23 unique "
        "email addresses exposed."
    )
    add_bullet(
        doc,
        "Credential breakdown: 5 plaintext passwords, 12 weak hashes "
        "(8 MD5, 4 SHA-1), 30 strong hashes (28 bcrypt, 2 argon2)."
    )
    add_bullet(
        doc,
        "Corporate vs personal split: 18 corporate emails "
        "(@example.com), 5 personal emails (Gmail, Yahoo) — corporate "
        "addresses represent direct risk to the organisation."
    )
    add_bullet(
        doc,
        "Breach sources: Collection #1, LinkedIn 2012, Adobe, Exploit.in, "
        "Anti Public Combo List — multiple sources increase the likelihood "
        "that credentials overlap with active accounts."
    )

    add_warning(
        doc,
        "Plaintext passwords in Dehashed results mean the credentials are "
        "immediately usable by any attacker. This is a CRITICAL finding "
        "that warrants immediate password resets for all affected accounts."
    )

    add_note(
        doc,
        "Dehashed is credit-based and can be toggled off in the scanner "
        "settings. When disabled, the checker returns status 'no_api_key' "
        "and does not contribute to the score. The Credential Risk "
        "Assessment (Section 4.6.9) will still function using the other "
        "three credential sources."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.7  Infostealer Detection (Hudson Rock)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.7  Infostealer Detection (Hudson Rock)")

    add_bold_body(
        doc,
        "What it checks: ",
        "Hudson Rock's free OSINT API checks whether employee devices "
        "associated with the domain are CURRENTLY infected with infostealer "
        "malware — specifically Raccoon Stealer, RedLine Stealer, Vidar, "
        "and similar credential-harvesting trojans. This is not historical "
        "data: it reflects active, ongoing compromise."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "A single GET request to the Hudson Rock Cavalier API with the "
        "domain returns three counts: compromised_employees (devices where "
        "the corporate email was used to log in, and the device is "
        "currently infected), compromised_users (user accounts compromised "
        "via infostealer), and third_party_exposures (credentials exposed "
        "through partner or supply-chain compromise). The scanner reports "
        "all three categories and totals."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "An active infostealer infection is the single most critical "
        "credential finding the scanner can produce. Unlike a historical "
        "breach where passwords may have been rotated, an infostealer is "
        "exfiltrating credentials in real time — every new password the "
        "user sets is immediately captured. Infostealers harvest saved "
        "browser passwords, session cookies (enabling session hijacking "
        "that bypasses MFA), autofill data, crypto wallets, and VPN "
        "configurations. This data is sold on dark-web markets within "
        "hours of collection."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Compromised employees are the most severe finding: each infected "
        "employee device reduces the score by 30 points (to a minimum of "
        "0). Compromised users reduce the score by 10 points each. Third-"
        "party exposures reduce the score by 5 points each. A single "
        "compromised employee device will typically push the score into "
        "critical territory."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "CRITICAL: 2 employee device(s) infected with infostealer malware "
        "— credentials are actively being sold on dark web markets. "
        "Immediate incident response required."
    )
    add_bullet(
        doc,
        "3 user account(s) compromised via infostealer — force password "
        "resets and enable MFA for affected accounts."
    )
    add_bullet(
        doc,
        "5 third-party exposure(s) detected — review supply chain partners "
        "and shared credential access."
    )
    add_bullet(
        doc,
        "No infostealer infections detected — this is the desired result "
        "and indicates no currently active credential theft."
    )

    add_warning(
        doc,
        "Any Hudson Rock finding of compromised employees should trigger "
        "immediate incident response: isolate affected devices, force "
        "password resets for ALL accounts (not just the infected user's), "
        "revoke active sessions, and engage a forensics team. Session "
        "cookies harvested by infostealers can bypass MFA."
    )

    add_tip(
        doc,
        "Hudson Rock data is real-time. If a rescan shows the same finding "
        "weeks later, it means the infection has not been remediated — "
        "escalate the urgency."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.8  Dark Web Monitoring (IntelX)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.8  Dark Web Monitoring (IntelX)")

    add_bold_body(
        doc,
        "What it checks: ",
        "Intelligence X (IntelX) searches dark web forums, paste sites "
        "(Pastebin and similar), and aggregated leak databases for mentions "
        "of the target domain. The results are classified into three "
        "categories: dark web mentions (from .onion sites and criminal "
        "forums), paste site mentions (from public paste platforms), and "
        "leak database entries (from aggregated breach compilations). This "
        "checker uses a paid API with credit-based pricing and is "
        "toggleable in the scanner UI."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The scanner uses IntelX's two-step search process. First, a POST "
        "request initiates a search with the domain as the search term, "
        "requesting up to 40 results sorted by relevance. After a short "
        "polling interval, the scanner retrieves results via GET requests. "
        "Each result is classified by media type: media types 1 and 2 are "
        "paste sites, media type 13 is dark web, and others are classified "
        "as leak database entries. The 10 most recent results are preserved "
        "for display, including the name, type, media classification, and "
        "date."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Dark web mentions indicate that the domain's data, credentials, "
        "or infrastructure is being discussed or traded in criminal "
        "communities. This is a leading indicator of imminent attack — "
        "if credentials appear on a dark web marketplace, credential-"
        "stuffing attacks typically follow within days. Paste site mentions "
        "may indicate data dumps where exfiltrated information has been "
        "publicly shared. For underwriters, dark web exposure is one of "
        "the strongest predictors of a future claim."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Dark web mentions carry the heaviest penalty: each mention "
        "reduces the score by 15 points. Paste site mentions (when more "
        "than 5 are found) reduce the score by 3 points each. The "
        "presence of any dark web mention will typically push the "
        "Credential Risk Assessment (Section 4.6.9) to HIGH or CRITICAL."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "3 dark web mention(s) found — credentials or data may be "
        "actively traded on criminal forums."
    )
    add_bullet(
        doc,
        "8 paste site mention(s) — data has been shared on public paste "
        "sites (Pastebin, etc.)."
    )
    add_bullet(
        doc,
        "12 reference(s) found in dark web and leak databases — the "
        "domain appears in multiple breach compilations."
    )
    add_bullet(
        doc,
        "Recent results with dates and sources are shown, allowing the "
        "underwriter to assess whether the exposure is current or "
        "historical."
    )

    add_note(
        doc,
        "IntelX uses the free tier by default (40 results per search, "
        "approximately 500 credits per day). The results represent a "
        "sample of available intelligence — commercial IntelX subscriptions "
        "would return more comprehensive results."
    )

    add_warning(
        doc,
        "Dark web mentions combined with Hudson Rock infostealer findings "
        "create a compounding risk: stolen credentials are being both "
        "actively harvested AND traded. This combination should be treated "
        "as an ongoing security incident."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.9  Credential Risk Assessment
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.9  Credential Risk Assessment")

    add_bold_body(
        doc,
        "What it checks: ",
        "The Credential Risk Assessment is an aggregate classifier that "
        "combines data from all four credential intelligence sources — "
        "Dehashed, HIBP, Hudson Rock, and IntelX — to produce a single "
        "risk classification: CRITICAL, HIGH, MEDIUM, or LOW. It is not "
        "a separate API call but rather a synthesis layer that interprets "
        "the combined findings."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The classifier evaluates four factors in priority order. "
        "Factor 1 (highest priority): Active infostealer detection from "
        "Hudson Rock. Any compromised employees immediately set the risk "
        "level to CRITICAL and the active_compromise flag to true, with a "
        "50-point score reduction. Compromised users add a further "
        "20-point reduction. "
        "Factor 1b: Dark web exposure from IntelX. Dark web mentions set "
        "the level to HIGH (if not already CRITICAL), with each mention "
        "reducing the score by 10 points. Paste site mentions above 5 "
        "reduce the score by 3 points each. "
        "Factor 2: Credential exposure from Dehashed. Records with "
        "password exposure set the level to HIGH and reduce the score by "
        "30 points; records without passwords set the level to MEDIUM and "
        "reduce by 15 points. "
        "Factor 3: Breach recency from HIBP-enriched data. Breaches from "
        "2023 or later elevate the level to HIGH with a 15-point "
        "reduction. Breaches that included passwords in their data classes "
        "are specifically flagged."
    )

    add_bold_body(
        doc,
        "Counting password-bearing records: ",
        "Where the assessment reports an exposed-credential count, it counts "
        "the records (mailboxes) that actually carry a password — the "
        "plaintext- and hashed-password subset from the Dehashed credential "
        "breakdown — rather than treating a single 'passwords present' "
        "indicator as if it were a count. The figure is therefore phrased so "
        "the reader can see both the total exposure and how much of it is "
        "directly loginable (for example, one mailbox carrying a password "
        "across thirteen breach-exposure records). Email addresses are "
        "lower-cased and trimmed before the unique-mailbox tally so that the "
        "same address in different letter cases is not double-counted."
    )

    add_bold_body(
        doc,
        "Risk levels and their meanings: ",
        "CRITICAL — Active infostealer infection detected or credentials "
        "being actively traded on the dark web. Immediate incident "
        "response required: isolate devices, force all password resets, "
        "enable MFA, engage forensics. "
        "HIGH — Recent breach (2023+) with password exposure, or dark web "
        "mentions detected. Force password resets for identified accounts, "
        "enable MFA, implement continuous monitoring. "
        "MEDIUM — Historical credential exposure without active compromise "
        "indicators. Review affected accounts, enforce MFA, monitor for "
        "credential-stuffing attempts. "
        "LOW — No active compromise or significant credential exposure "
        "detected."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "The Credential Risk Assessment provides the summary verdict that "
        "underwriters need. Rather than interpreting four separate data "
        "sources, the classifier presents a single risk level with "
        "supporting factors. A CRITICAL rating should influence premium "
        "pricing or trigger a requirement for remediation before policy "
        "binding. A HIGH rating may warrant additional underwriting "
        "questions. MEDIUM and LOW ratings provide assurance that "
        "credential hygiene is acceptable."
    )

    add_body(doc, "The assessment produces:")
    add_bullet(
        doc,
        "A single risk_level (CRITICAL, HIGH, MEDIUM, or LOW)."
    )
    add_bullet(
        doc,
        "A numerical risk_score (0-100, where 100 is no risk)."
    )
    add_bullet(
        doc,
        "An active_compromise boolean flag."
    )
    add_bullet(
        doc,
        "A list of risk factors — human-readable explanations of why the "
        "risk level was assigned (e.g., 'ACTIVE INFOSTEALER: 2 employee "
        "device(s) currently infected — credentials are being exfiltrated "
        "in real-time')."
    )
    add_bullet(
        doc,
        "A summary paragraph suitable for inclusion in underwriting "
        "reports."
    )

    add_tip(
        doc,
        "The Credential Risk Assessment is the best single metric to "
        "present to underwriters. Lead with the risk level and summary, "
        "then drill into the individual sources only if the underwriter "
        "wants detail."
    )

    add_note(
        doc,
        "If Dehashed and IntelX are both disabled (no API keys), the "
        "assessment still functions using HIBP and Hudson Rock data. The "
        "classification may be less comprehensive but will still capture "
        "active compromises and known breaches."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.10  VirusTotal Reputation
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.10  VirusTotal Reputation")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner queries the VirusTotal API v3 to scan the domain "
        "against 70+ security engines from vendors including McAfee, "
        "Kaspersky, Bitdefender, Sophos, ESET, Fortinet, and many others. "
        "Each engine returns a verdict: malicious, suspicious, harmless, "
        "or undetected. The API also returns the community reputation "
        "score, security-vendor category classifications, popularity "
        "rankings, and details of which specific engines flagged the "
        "domain."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "A single GET request is sent to the VirusTotal v3 domains "
        "endpoint with the API key in the header. The response includes "
        "last_analysis_stats (counts of malicious, suspicious, harmless, "
        "and undetected verdicts), total_votes (community malicious vs "
        "harmless votes), categories (how vendors classify the domain — "
        "e.g., 'business', 'phishing', 'malware'), popularity_ranks "
        "(Alexa, Cisco Umbrella), and last_analysis_results (per-engine "
        "verdict details). The scanner extracts flagging engines — any "
        "engine that returned 'malicious' or 'suspicious' — and lists "
        "them by name with their specific verdict."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "VirusTotal is the industry standard for domain reputation "
        "checking. If multiple security engines flag a domain as malicious, "
        "it means the domain has been associated with malware distribution, "
        "phishing, command-and-control infrastructure, or other criminal "
        "activity. Even a single malicious flag from a reputable engine is "
        "cause for investigation. Category classifications like 'phishing' "
        "or 'malware' from vendors indicate the domain has been "
        "actively blacklisted by endpoint security products — meaning "
        "employees at other companies may be blocked from visiting the "
        "domain entirely."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Malicious flags carry heavy penalties. A single malicious flag "
        "is a significant finding; multiple malicious flags indicate "
        "confirmed malicious activity. Suspicious flags carry lighter "
        "penalties. The scanner also checks category classifications for "
        "keywords like 'malware', 'phishing', 'spam', and 'scam' — "
        "these carry additional penalties. The VirusTotal weight in the "
        "overall score is 5%. The free API tier allows 4 requests per "
        "minute and 500 per day."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "CRITICAL: 3 security engine(s) flagged this domain as MALICIOUS "
        "— the flagging engines are listed by name (e.g., Fortinet, "
        "Kaspersky, ESET) with their specific verdicts."
    )
    add_bullet(
        doc,
        "1 security engine(s) flagged this domain as suspicious — a "
        "single suspicious flag may be a false positive but warrants "
        "investigation."
    )
    add_bullet(
        doc,
        "Categories: Fortinet classifies the domain as 'phishing' — "
        "this means Fortinet endpoint products will block access to the "
        "domain for their customers."
    )
    add_bullet(
        doc,
        "Community reputation score: -5 (negative values indicate the "
        "community considers the domain suspicious or malicious)."
    )
    add_bullet(
        doc,
        "0 malicious, 0 suspicious, 68 harmless, 4 undetected — a clean "
        "result indicating no security engines have flagged the domain."
    )

    add_warning(
        doc,
        "Multiple malicious flags from reputable engines (Kaspersky, "
        "Bitdefender, Sophos, ESET) should be treated as confirmed "
        "malicious activity. This may indicate the domain has been "
        "compromised and is hosting malware or phishing content without "
        "the owner's knowledge."
    )

    add_tip(
        doc,
        "A single flag from a lesser-known engine may be a false positive. "
        "Focus on flags from tier-1 vendors and look for corroborating "
        "evidence from other checkers (DNSBL listings, dark web mentions)."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.11  Fraudulent Domains (Typosquat)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.11  Fraudulent Domains (Typosquat)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner generates lookalike domain permutations and checks "
        "which ones are registered and actively resolving via DNS. These "
        "lookalike domains can be used for phishing attacks targeting the "
        "organisation's employees, clients, and partners. The scanner "
        "employs several generation techniques: character omission, adjacent "
        "character swap, character duplication, ASCII homoglyph substitution "
        "(visually similar characters like 'o' and '0', 'l' and '1'), "
        "adjacent-keyboard typos (fat-finger errors), TLD variants (e.g., "
        ".com to .net, .co, .io, .co.za), dot insertion, and hyphen "
        "insertion. It also generates a bounded set of IDN / homoglyph "
        "candidates — internationalised-domain lookalikes that substitute "
        "Unicode characters resembling Latin letters (e.g. a Cyrillic 'а' "
        "for an ASCII 'a') and are registered in their punycode (xn--) "
        "form. These are the hardest lookalikes for a human to spot in an "
        "address bar."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "First, the domain is split into its name and TLD components "
        "(handling multi-part TLDs like .co.za). The permutation engine "
        "generates all variants using the techniques above. For "
        "ASCII homoglyph substitution, the scanner uses a mapping of "
        "visually similar characters (a/4/@, b/d/6, e/3, i/1/l/!, o/0, "
        "s/5/$, etc.). IDN / homoglyph candidates are built by swapping a "
        "Latin letter for a confusable Unicode character and encoding the "
        "result to its punycode (xn--) label, which is what actually "
        "appears in DNS; this set is deliberately bounded to keep the "
        "permutation space manageable. For keyboard typos, it uses an "
        "adjacency map of QWERTY keyboard neighbours. TLD variants are "
        "checked across 17 common "
        "TLDs including .com, .net, .org, .co, .dev, .online, .io, .info, "
        ".co.za, and .africa. Each generated permutation is checked via "
        "DNS resolution — if it resolves, the domain is registered and "
        "active. Resolved domains are further checked for SSL certificates, "
        "which indicate the lookalike is actively being used (possibly for "
        "phishing with a convincing HTTPS connection). Each permutation "
        "includes a visual similarity percentage."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Typosquatting is one of the most common techniques used in "
        "phishing and business-email compromise (BEC) attacks. An attacker "
        "registers a domain like examp1e.com (with a '1' instead of 'l') "
        "or example.co (dropping the 'm') and sends emails that appear to "
        "come from the legitimate organisation. These domains bypass "
        "SPF/DKIM/DMARC checks because they are separate domains with "
        "their own valid DNS records. Staff and clients who do not "
        "scrutinise the sender address carefully may fall victim to "
        "credential harvesting, invoice fraud, or malware delivery."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Each resolved lookalike domain incurs a penalty, with higher "
        "penalties for domains with high visual similarity (above 90%) or "
        "those that have active SSL certificates. TLD variants of the "
        "exact domain name (e.g., example.net when the real domain is "
        "example.com) carry the highest risk because they are the most "
        "convincing to victims."
    )

    add_body(doc, "Common findings include:")
    add_bullet(
        doc,
        "7 lookalike domains resolving: examp1e.com (homoglyph, 90% "
        "similarity), examlpe.com (char-swap, 86%), example.net "
        "(tld-variant, 85%), example.co (tld-variant, 85%), "
        "exaample.com (char-duplicate, 88%)."
    )
    add_bullet(
        doc,
        "3 of 7 lookalike domains have active SSL certificates — these "
        "are the highest-risk variants as they can serve convincing HTTPS "
        "phishing pages."
    )
    add_bullet(
        doc,
        "No lookalike domains resolving — this is uncommon for popular "
        "domains but indicates low typosquatting risk."
    )

    add_tip(
        doc,
        "Advise clients to proactively register high-similarity variants "
        "of their domain (especially TLD variants and single-character "
        "homoglyphs) as a defensive measure. This is significantly cheaper "
        "than responding to a phishing campaign."
    )

    add_note(
        doc,
        "Not every resolved lookalike domain is malicious — some may be "
        "legitimately owned by other businesses or parked by domain "
        "speculators. The scanner flags them as potential risks for "
        "investigation, not confirmed threats."
    )

    add_warning(
        doc,
        "Lookalike domains with SSL certificates that were recently issued "
        "(within the last 30 days) are the most suspicious — they suggest "
        "someone is actively setting up infrastructure for an attack."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.12  Supply-Chain / Related Domains (S-1)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.12  Supply-Chain / Related Domains (S-1)")

    add_bold_body(
        doc,
        "What it checks: ",
        "When the broker declares sibling, supplier, or group-related "
        "domains in the scan request, this checker scans each declared "
        "domain in LITE mode (SSL/TLS certificate posture, DNS-port "
        "exposure, and information disclosure paths). Findings are rolled "
        "up worst-of-N into a single supply-chain category that feeds "
        "both the headline risk score and the civil-liability uplift in "
        "the financial-impact model."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The broker provides the related_domains list as part of the "
        "scan request body. Each sibling is probed in parallel with a "
        "45-second wall-clock budget per domain (capped at 10 siblings to "
        "bound scan time). For each sibling the scanner computes a LITE "
        "score (0-100) combining SSL grade, DNS-port risk, and "
        "info-disclosure findings. The worst-performing sibling drives "
        "the category traffic-light. Critical findings (e.g. exposed "
        ".env, exposed database dumps) are flagged separately and feed "
        "into the catastrophe-tail inflation in the FAIR Monte Carlo."
    )

    add_body(doc,
        "Presentation: across all supply-chain signals (related domains, "
        "third-party scripts, dependency manifests, the email-vendor surface, "
        "vendor-breach correlation, CMS plugins and the cross-correlation), the "
        "executive deck presents a single rolled-up supply-chain verdict and "
        "only the signals carrying a material finding; the full per-signal "
        "detail appears in the technical report and the HTML view. A checker "
        "that runs and finds nothing is reported as clean - a positive due-"
        "diligence result - which is distinct from a checker that did not run "
        "or is not applicable (for example, the CMS-plugin checker on a non-"
        "WordPress site)."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Under aggregator-liability theory a breach at a declared "
        "supplier can be imputed back to the insured. The Lloyd's "
        "Talbot mrcourier case is the canonical precedent — Talbot's "
        "insured was held liable for downstream losses originating at "
        "an undeclared supplier. Surfacing declared siblings during "
        "underwriting lets the broker price the civil-liability "
        "channel explicitly and prevents the 'undeclared supplier' "
        "blind spot that has empirically driven multi-percentile "
        "claim jumps."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Score = worst-of-N LITE score across all scanned siblings. The "
        "category contributes up to +0.03 to the RSI ransomware base "
        "(operational pivot path) and up to +0.04 to the vulnerability "
        "uplift in the financial model (civil-liability inflator). "
        "Critical findings on any sibling also drive the catastrophe "
        "tail K_TAIL_SC widening at P75-P99.6."
    )

    add_note(
        doc,
        "v1.0 is broker-declared only. v1.1 (deferred) adds "
        "auto-discovery via cert SAN, WHOIS registrant match, and "
        "analytics-ID correlation — the broker confirms auto-detected "
        "siblings via the same pre-flight UI used for regulatory flags."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.13  Exposed Dependency Manifests (S-3)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.13  Exposed Dependency Manifests (S-3)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner probes the web root for exposed dependency "
        "manifest files across seven ecosystems: Node (package.json, "
        "package-lock.json, yarn.lock), PHP (composer.json, "
        "composer.lock), Python (requirements.txt, Pipfile, "
        "Pipfile.lock), Ruby (Gemfile, Gemfile.lock), Go (go.mod, "
        "go.sum), Rust (Cargo.toml, Cargo.lock), and Java (pom.xml). "
        "For each exposed file the scanner parses the dependency map "
        "and reports the count by ecosystem."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "Each manifest path is probed in parallel with HEAD-then-GET to "
        "minimise WAF noise. A 200 response with parseable manifest "
        "content is treated as 'exposed'. Lockfiles (which carry exact "
        "pinned versions) are classified as 'critical' severity because "
        "they directly enable OSV-chained CVE discovery; manifest files "
        "(which carry only SemVer ranges) are 'high' because they "
        "still leak the dependency list."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Exposed lockfiles eliminate the reconnaissance step from a "
        "ransomware-via-vulnerable-dependency attack. The attacker "
        "downloads package-lock.json, feeds it to OSV.dev, and "
        "receives a working list of CVEs with public exploits — no "
        "scanning, no fingerprinting required. Patchstack 2024 data "
        "shows 11.6% of WordPress plugin CVEs are actively exploited; "
        "the same pattern applies to npm/Composer/PyPI."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Penalty = 30 per critical lockfile + 15 per manifest, capped "
        "at -100. Contributes up to +0.04 to RSI raw base. Remediation "
        "is cheap (deny /package*.json, /*.lock at the web server) so "
        "the remediation panel weights this finding for rapid action."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.14  Third-Party JavaScript (S-2)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.14  Third-Party JavaScript (S-2)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner fetches the homepage HTML and enumerates every "
        "<script src=...> tag pointing at a third-party origin. For "
        "each external script it tracks whether a Subresource Integrity "
        "(SRI) hash is present and whether the host appears on the "
        "known-compromised CDN list (currently polyfill.io 2024 sale, "
        "bootcss/bootcdn 2018 Magecart). Hosts on the known-CDN "
        "allow-list (googleapis, gstatic, cloudflare, cloudfront, "
        "akamaihd, fastly, azureedge, jsdelivr, unpkg, cdnjs, etc.) "
        "are labelled but not penalised on the CDN signal alone."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "Script tag parsing uses a forgiving regex (case-insensitive, "
        "handles single/double quotes, supports protocol-relative URLs "
        "and relative paths). The host is resolved via urlparse; "
        "first-party hosts (same apex or sub-domain) are excluded. "
        "Each third-party script is matched against the "
        "KNOWN_COMPROMISED_HOSTS dict (suffix-match) and the "
        "KNOWN_CDN_SUFFIXES tuple."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Every external script runs with the same privileges as the "
        "insured's own code — it can read forms, intercept payment "
        "fields, and exfiltrate data. SRI hashes pin each script to a "
        "known good version, so an upstream CDN hijack (Magecart 2018, "
        "polyfill.io 2024) cannot silently replace the script. "
        "Polyfill.io alone compromised 100,000+ sites including Hulu, "
        "Mercedes-Benz, WarnerBros, and JSTOR. This is the single "
        "biggest predictor of card-skimming and form-skimming breaches."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Penalty = 60 per known-compromised host (capped) + 10-20 "
        "based on SRI coverage on third-party scripts + 5 if >15 "
        "distinct third-party origins (consolidation signal). "
        "Contributes up to +0.05 RSI raw and +0.06 to the "
        "financial-model vulnerability uplift (Magecart channel)."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.15  Email-Vendor Surface (S-4)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.15  Email-Vendor Surface (SPF, S-4)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner walks the SPF include: chain (depth-5 cap) and "
        "classifies each include against 24 known email-SaaS vendor "
        "patterns (SendGrid, Mailgun, Mailchimp, Amazon SES, Microsoft "
        "365, Google Workspace, Klaviyo, HubSpot, Salesforce, "
        "Marketo, Constant Contact, ActiveCampaign, Mailjet, Postmark, "
        "SparkPost, SendinBlue/Brevo, Zendesk, Freshdesk, Intercom, "
        "Pardot, Oracle Responsys, Netcore, and SA-local Everlytic). "
        "It also fetches the DMARC policy at _dmarc.<domain>."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Every vendor in the SPF chain is implicitly authorised to "
        "send mail as the insured. A compromise at any single vendor "
        "(Mailchimp 2022/2023, Constant Contact 2021, Microsoft "
        "Storm-0558 2023) becomes a phishing path directly into the "
        "insured's customer base. The risk is dramatically larger "
        "when DMARC policy is 'none' or absent — CISA BOD 18-01 "
        "cohort data shows DMARC p=reject reduces phishing inbox "
        "success from 69% to 14% (~80% relative reduction)."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Penalty graduates with vendor count: +5 at >=3 vendors, +15 "
        "at >=6 vendors. An additional +20 penalty fires when DMARC "
        "is weak AND there is at least one vendor in the chain. "
        "Contributes up to +0.02 RSI raw."
    )

    add_note(
        doc,
        "A vendor of 'unknown' (not on the classification list) is "
        "still counted but separately flagged — broker should review "
        "whether the unknown include is legitimate or a stale "
        "configuration artefact."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.16  CMS Plugin Surface (S-10)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.16  CMS Plugin Surface — WordPress (S-10)")

    add_bold_body(
        doc,
        "What it checks: ",
        "WordPress-only. The checker first establishes a genuine WordPress "
        "fingerprint by probing /wp-content/, /wp-login.php, and "
        "/wp-includes/, guarded by a random-path catch-all test so a site "
        "that returns 200 for every URL (a soft-404 / SPA front end behind "
        "a CDN) is NOT mistaken for WordPress. If no genuine fingerprint is "
        "found the checker reports 'skipped' (the site is not WordPress and "
        "the card does not render in the report). Only when WordPress is "
        "confirmed does the scanner enumerate 25 popular plugin slugs by "
        "requesting /wp-content/plugins/<slug>/readme.txt; a plugin is "
        "counted only when that readme returns HTTP 200 AND passes a body-"
        "sanity check confirming it is a real plugin readme (not a generic "
        "page). Version strings are harvested from the readme's 'Stable "
        "tag:' header."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "Patchstack 2024 reported 7,633 WordPress vulnerabilities, "
        "96% of which were in plugins; 11.6% are actively exploited "
        "in the wild. For SA SMEs this is the dominant external "
        "ransomware entry vector per the Sophos State of Ransomware "
        "SA 2024 report (69% of SA orgs hit, malicious email + "
        "exploitation as top root causes). Readable version strings "
        "are directly CVE-chainable — the attacker reads the version "
        "from readme.txt and goes straight to the CVE database."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Penalty = up to 30 based on plugin count + up to 20 based "
        "on versioned-readable count. Contributes up to +0.04 RSI raw "
        "(highest single supply-chain RSI factor, reflecting the "
        "empirical dominance of WP plugins as an SA SME attack "
        "vector)."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.17  Vendor Breach Correlation (S-5)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.17  Vendor Breach Correlation (S-5)")

    add_bold_body(
        doc,
        "What it checks: ",
        "The scanner re-extracts the email-vendor surface (same SPF "
        "include-chain walk as S-4) and cross-references each "
        "detected vendor against a curated editorial breach database "
        "(vendor_breaches.json). The current database carries 14 "
        "confirmed public-record breaches across 10 vendors: "
        "Mailchimp (2022 x2 + 2023), Salesforce/Heroku (2022 + 2023), "
        "Okta (2022 + 2023), Microsoft 365 (Storm-0558 2023, Midnight "
        "Blizzard 2024), HubSpot, Intercom, Zendesk, SendGrid, "
        "Constant Contact, and Marketo."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The database is loaded once per process and indexed by "
        "vendor key. Each match has a date, severity "
        "(critical/high/medium/low), and exposure_class (e.g. "
        "session_tokens, customer_email_lists, mailbox_content). "
        "Each match's penalty decays linearly with age over a "
        "5-year lookback window — full SEVERITY_PENALTY at age=0, "
        "zero at LOOKBACK_DAYS. Five years is empirically supported "
        "because customer-key rotation post-disclosure is typically "
        "incomplete years after the incident (Ponemon Third-Party "
        "Risk 2023)."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "This is the strongest broker-narrative signal in the "
        "supply-chain layer: 'your supplier was breached N months "
        "ago — have credentials been rotated?'. Case anchors include "
        "MOVEit Cl0p 2023 (2,700+ orgs / USD 12-15B aggregate "
        "economic impact via ONE vendor breach), Polyfill.io 2024 "
        "(100,000+ sites compromised), Storm-0558 (25 orgs incl. US "
        "State Department via ONE forged Microsoft key), and the "
        "Mailchimp 0ktapus cluster 2022-2023 (668 customer accounts "
        "across 3 incidents → downstream phishing at Trezor, "
        "DigitalOcean, WooCommerce)."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "Penalty per match = SEVERITY_PENALTY (critical=25, "
        "high=15, medium=8, low=3) × linear age decay. Contributes "
        "up to +0.04 to the vulnerability uplift in the financial "
        "model. The catastrophe-tail percentiles (P75-P99.6) move "
        "naturally through the Monte Carlo as the vulnerability uplift "
        "shifts the entire distribution rightward — no separate "
        "tail-widening is applied on top (an earlier iteration did "
        "exactly that and was removed during the 2026-05-27 design "
        "review to avoid double-counting the same signal)."
    )

    add_warning(
        doc,
        "Editorial discipline: vendor_breaches.json follows the same "
        "rules as darkweb_providers.py — only CONFIRMED public-record "
        "incidents are added, each with a citable source field. The "
        "broker can defend each row in a FAIS audit."
    )

    add_note(
        doc,
        "Empirical anchor for the calibration: IBM Cost of a Data "
        "Breach 2024 reports supply-chain compromise as the initial "
        "attack vector in 12% of breaches (vs Verizon DBIR 2025's 30% "
        "third-party 'involvement' figure, which bundles upstream "
        "compromise with partner-data exposure and credential reuse). "
        "Mandiant M-Trends 2025 puts the strict trojanised-vendor "
        "subset at ~3%. The defensible 'upstream root cause' rate "
        "lies in the 12-20% band. The catastrophe model captures this "
        "loss-given-breach severity through the records-driven C1 "
        "liability (a supplier-vectored breach still exposes the "
        "insured's full record base), and discloses correlated systemic "
        "supply-chain catastrophe at portfolio level. The earlier "
        "conditional-Pareto loss-given-breach widening was retired to "
        "keep one signal mapped to one channel and avoid double-counting."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.18  Credential Exposure Correlation (DeHashed × Recency × Infostealer × IntelX)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.18  Credential Exposure Correlation "
                "(DeHashed × Recency × Infostealer × IntelX)")

    add_bold_body(
        doc,
        "What it checks: ",
        "A reporting-only cross-correlation that joins four independent "
        "credential signals already gathered elsewhere in the scan into a "
        "single rotate-now verdict: (1) the breached-credential corpus from "
        "Dehashed (4.6.6); (2) the recency of that exposure, dated from "
        "IntelX, HIBP-enriched breach dates, and — most reliably — the "
        "infostealer infection date; (3) active theft from Hudson Rock "
        "infostealer infections (4.6.7); and (4) active circulation / "
        "trading from IntelX leak, paste, and dark-web mentions (4.6.8). "
        "It is the credential analogue of the Third-Party Cross-Correlation "
        "card (4.6.19) and follows the same design pattern."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "The verdict escalates from NONE up to CRITICAL based on how many "
        "signals confirm ACTIVE (not merely historical) compromise. The "
        "decisive factor is a date-proven fresh infostealer infection "
        "(≤90 days): a breached corpus PLUS a live infection is CRITICAL; "
        "a recent non-combo breach or aged infection is HIGH; a corpus that "
        "is merely circulating with no fresh-theft proof is MEDIUM (it may "
        "already be rotated); old datable exposure with no active signal is "
        "LOW. Every dated record is bucketed into a recency timeline "
        "(<30d / 30-90d / 90-180d / 180-360d / 1-2yr / >2yr) so the reader "
        "can see at a glance whether the exposure is fresh or stale."
    )

    add_bold_body(
        doc,
        "Active vs re-circulated — the date-anchor discipline: ",
        "Aggregator / combo-list sources (e.g. ALIEN TXTBASE) are flagged "
        "as re-packaged historical data: a recent OBSERVED date on a combo "
        "list is re-circulation, not fresh theft, and on its own does not "
        "qualify as 'genuinely recent'. Only the infostealer infection "
        "date — a point-in-time malware capture — is treated as a reliable "
        "freshness anchor. This prevents a recycled compilation from "
        "inflating the verdict to CRITICAL."
    )

    add_bold_body(
        doc,
        "Password-bearing records are counted, not assumed: ",
        "The card reports the breached-record total AND, separately, how "
        "many of those records actually carry a password — e.g. "
        "'13 leaked credential records (2 with passwords)'. Only the "
        "plaintext- and hashed-password subset (from Dehashed's credential "
        "breakdown) is counted as 'with passwords'; the remaining records "
        "are breach-exposure rows (email appeared in a breach) with no "
        "credential attached. This distinction is deliberate: tagging the "
        "full corpus as 'with passwords' would overstate the rotate-now "
        "severity that underwriters act on."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "This card answers the single question an underwriter cares about "
        "for credentials — 'is someone able to log in right now?' — by "
        "separating live, date-proven exposure from old or recycled data. "
        "A HIGH or CRITICAL verdict justifies a forced-reset + MFA "
        "remediation condition before binding; a MEDIUM/LOW verdict on "
        "aged-only exposure provides assurance that the credential risk is "
        "largely historical."
    )

    add_note(
        doc,
        "Like the Third-Party Cross-Correlation card, this is "
        "REPORTING-ONLY and carries NO scoring weight. The underlying "
        "signals (Dehashed, Hudson Rock, IntelX) already score through "
        "their own channels and the Credential Risk Assessment (4.6.9) "
        "provides the headline verdict; a separate weight here would "
        "double-count. The correlation exists to prioritise the rotate-"
        "list, not to move the score."
    )

    # ══════════════════════════════════════════════════════════════════════
    # 4.6.19  Third-Party Cross-Correlation (Hudson Rock × S-4 × S-5)
    # ══════════════════════════════════════════════════════════════════════
    add_h2(doc, "4.6.19  Third-Party Cross-Correlation (Hudson Rock × S-4 × S-5)")

    add_bold_body(
        doc,
        "What it checks: ",
        "Joins three independent risk signals into a single actionable "
        "finding: (A) Hudson Rock's infostealer-harvested credential "
        "count for third-party services used by the insured's employees; "
        "(B) the email-vendor surface detected by S-4 (vendors in the "
        "SPF send-authority chain); and (C) public-record breaches at "
        "those vendors per the curated S-5 vendor_breaches.json "
        "database. When all three sources align, the intersection is "
        "the highest-priority rotate-target in the entire scan."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "Post-scan Phase 4f reads cat_results['hudson_rock'], "
        "cat_results['email_vendor_surface'], and cat_results"
        "['vendor_breach']. The cavalier.hudsonrock.com free-tier "
        "endpoint returns aggregate counts only (no per-vendor "
        "breakdown), so the correlation is necessarily soft: when HR "
        "reports N third-party exposures AND M vendors are detected "
        "in the SPF chain AND K of those vendors have known public "
        "breaches, the K vendors in the intersection are the most "
        "likely candidates for the HR-reported harvest. The result is "
        "stored as cat_results['third_party_correlation'] with severity "
        "ladder critical (triple-source match) / high (HR + SPF) / "
        "medium (HR only)."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance: ",
        "This is the strongest single signal in the model because "
        "three independent measurement methods confirm the same risk "
        "vector. The infostealer harvest is OBSERVED (not predicted); "
        "the vendor surface is DOCUMENTED (SPF DNS records); the "
        "vendor breach is PUBLIC RECORD. When all three align, the "
        "broker can write the rotate-list with confidence: 'rotate "
        "credentials at these specific vendors before underwriting "
        "completes.' Empirical anchor: Hudson Rock's 2024 infostealer "
        "data shows ~50% of compromised credentials are reused across "
        "multiple SaaS, and post-breach key rotation at vendors is "
        "incomplete years after disclosure (Ponemon Third-Party Risk "
        "2023)."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "REPORTING-ONLY. The cross-correlation deliberately does NOT "
        "carry its own scoring weight, RSI factor, or financial-impact "
        "uplift. The underlying signals it joins — Hudson Rock "
        "infostealer harvest (via credential_risk), S-4 SPF vendor "
        "surface, S-5 known-breach matches — each already contribute "
        "to RSI and financial impact through their own channels. "
        "Adding a separate weight here would double-count the same "
        "data without empirical justification (no public evidence "
        "that the correlation itself increases breach cost beyond "
        "what each signal individually drives). The correlation's "
        "value is QUALITATIVE: tell the broker which specific "
        "vendors to rotate at, with confidence backed by three "
        "independent sources. Credential rotation is cheap (R0–R3,600 "
        "per vendor) — the value is in the specificity of the "
        "rotate-list, not in a phantom RSI reduction."
    )

    add_note(
        doc,
        "Surface coverage: this finding is explicitly rendered in "
        "ALL six broker-facing surfaces — HTML cat-card (Exposure & "
        "Reputation), top recommendations block (auto via "
        "RECOMMENDATIONS), PDF body cat_third_party_correlation, PDF "
        "Broker Summary spotlight row, PDF Executive Deck Slide 4 "
        "Supply-Chain Exposure (7th card), Executive Deck Slide 7 "
        "Next Steps (promoted to Step 1 when critical). The "
        "verification harness asserts the signal appears in all "
        "rendered outputs."
    )

    add_warning(
        doc,
        "Soft-correlation caveat: the free Hudson Rock endpoint "
        "returns aggregate counts only, not per-vendor names. The "
        "'suspected vendors' list is therefore the intersection of "
        "S-4 detected vendors and S-5 breach database — it identifies "
        "the highest-probability candidates, NOT a confirmed mapping. "
        "Brokers should treat the rotate-list as priority targets, not "
        "as definitive attribution. A v1.2 enhancement to fetch per-"
        "vendor data from a richer Hudson Rock endpoint would tighten "
        "the attribution."
    )

    # ── Section summary ──────────────────────────────────────────────────
    add_h2(doc, "4.6.20  Section Summary — Interpreting Exposure Results")

    add_body(
        doc,
        "The seventeen checkers in this section work together to provide "
        "a 360-degree view of a domain's exposure and reputation profile "
        "— including the six supply-chain signals (4.6.12-17) that close "
        "the historical gap between observed posture and supplier-chain "
        "risk. When interpreting results, consider the following priority "
        "framework:"
    )

    add_bold_body(
        doc,
        "Immediate action required (CRITICAL): ",
        "Active infostealer infections (Hudson Rock), exposed .env files "
        "or database dumps (Admin Panels), confirmed subdomain takeover "
        "vulnerabilities, CISA KEV-listed CVEs with weaponized exploits, "
        "and multiple VirusTotal malicious flags."
    )

    add_bold_body(
        doc,
        "Urgent remediation (HIGH): ",
        "Recent breaches with password exposure (HIBP + Dehashed), dark "
        "web mentions (IntelX), plaintext credentials in leak databases, "
        "Spamhaus blacklisting (DNSBL), and high-similarity typosquat "
        "domains with SSL certificates."
    )

    add_bold_body(
        doc,
        "Scheduled remediation (MEDIUM): ",
        "Historical credential exposure without active indicators, "
        "paste-site mentions, accessible admin panels behind "
        "authentication, risky subdomains (dev/staging), and medium-"
        "severity unpatched CVEs."
    )

    add_bold_body(
        doc,
        "Acceptable risk (LOW): ",
        "No credential exposure, clean DNSBL and VirusTotal results, no "
        "exposed admin panels, well-managed subdomains, and a patched "
        "vulnerability posture."
    )

    add_tip(
        doc,
        "When presenting exposure findings to underwriters, lead with the "
        "Credential Risk Assessment (Section 4.6.9) as the headline "
        "metric, then support it with the individual checker findings. "
        "This provides both the summary verdict and the evidentiary basis."
    )
