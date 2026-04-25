"""
Section 4.6 — Exposure & Reputation
Phishield Cyber Risk Scanner User Manual

Covers all 11 sub-checkers in the Exposure & Reputation category:
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
        "and performs DNS A-record lookups against five major blacklists: "
        "Spamhaus ZEN (zen.spamhaus.org), SpamCop (bl.spamcop.net), SORBS "
        "(dnsbl.sorbs.net), Barracuda (b.barracudacentral.org), and "
        "UCEProtect (dnsbl-1.uceprotect.net). For domain-based checks, it "
        "queries Spamhaus DBL (dbl.spamhaus.org) and URIBL (uribl.com). A "
        "successful DNS resolution means the IP or domain is listed."
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
        "Listed on dnsbl.sorbs.net — SORBS listings often indicate the IP "
        "is on a dynamic/residential range or has been an open relay."
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
        "a thread pool. An HTTP 200 response means the path is directly "
        "accessible — this is a confirmed exposure. For critical paths, HTTP "
        "401 and 403 responses are also flagged because they confirm the path "
        "exists (a server that returns 403 on /.env has admitted the file is "
        "there, even if it is access-controlled). Non-critical paths only flag "
        "on HTTP 200."
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
        "/.git/HEAD — HTTP 403: The Git repository metadata exists on the "
        "server. While blocked, its presence confirms a deployment practice "
        "that may expose source code if misconfigured."
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
        "The scanner discovers subdomains through two methods: Certificate "
        "Transparency (CT) log scanning via crt.sh and DNS brute-force "
        "resolution of 50+ common prefixes (www, mail, vpn, dev, staging, "
        "test, admin, api, beta, backup, jenkins, gitlab, jira, grafana, "
        "kibana, phpmyadmin, cpanel, owa, exchange, and many more). "
        "Discovered subdomains are classified as 'risky' if they contain "
        "keywords associated with development, administration, or internal "
        "infrastructure."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "First, a query to crt.sh retrieves all certificates ever issued "
        "for the domain and its subdomains from public Certificate "
        "Transparency logs. This reveals subdomains the organisation may "
        "have forgotten about — old staging servers, decommissioned APIs, "
        "and test environments. Second, the scanner resolves each of the "
        "50+ brute-force prefixes via DNS to catch subdomains that may "
        "not have certificates. Each discovered subdomain is tagged with "
        "risk keywords (dev, staging, test, admin, backup, database, "
        "internal, vpn, etc.)."
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
        "employs eight generation techniques: character omission, adjacent "
        "character swap, character duplication, homoglyph substitution "
        "(visually similar characters like 'o' and '0', 'l' and '1'), "
        "adjacent-keyboard typos (fat-finger errors), TLD variants (e.g., "
        ".com to .net, .co, .io, .co.za), dot insertion, and hyphen "
        "insertion."
    )

    add_bold_body(
        doc,
        "How it works: ",
        "First, the domain is split into its name and TLD components "
        "(handling multi-part TLDs like .co.za). The permutation engine "
        "generates all variants using the eight techniques above. For "
        "homoglyph substitution, the scanner uses a mapping of visually "
        "similar characters (a/4/@, b/d/6, e/3, i/1/l/!, o/0, s/5/$, "
        "etc.). For keyboard typos, it uses an adjacency map of QWERTY "
        "keyboard neighbours. TLD variants are checked across 17 common "
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

    # ── Section summary ──────────────────────────────────────────────────
    add_h2(doc, "4.6.12  Section Summary — Interpreting Exposure Results")

    add_body(
        doc,
        "The eleven checkers in this section work together to provide a "
        "360-degree view of a domain's exposure and reputation profile. "
        "When interpreting results, consider the following priority "
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
