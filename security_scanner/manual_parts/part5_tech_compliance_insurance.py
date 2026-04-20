"""
Phishield Cyber Risk Scanner — User Manual
Sections 4.7, 4.8, and 5: Technology & Governance, Compliance Framework Mapping,
and Insurance Analytics (Deep Dive).

Provides build(doc) that appends all content to an existing python-docx Document.
Uses shared helpers: add_h1, add_h2, add_body, add_bold_body, add_bullet,
add_tip, add_warning, add_note.
"""


def build(doc):
    """Append sections 4.7, 4.8, and 5 to *doc*."""
    from manual_helpers import (
        add_h1, add_h2, add_body, add_bold_body, add_bullet,
        add_tip, add_warning, add_note,
    )

    # ==================================================================
    # 4.7  Technology & Governance
    # ==================================================================
    add_h1(doc, "4.7  Technology & Governance")

    add_body(doc,
        "The Technology and Governance category groups six checkers that examine "
        "the software powering a domain, the maturity of the domain itself, DNS "
        "intelligence, privacy and security policy posture, and payment security. "
        "Together these paint a picture of how well-managed the organisation's "
        "public-facing technology estate is."
    )

    # ---- Technology Stack & EOL Software ----
    add_h2(doc, "Technology Stack & End-of-Life Software")

    add_body(doc,
        "This checker fingerprints the technology running behind a website. It "
        "identifies content management systems (WordPress, Joomla, Drupal), web "
        "server software (Apache, Nginx, IIS, LiteSpeed), JavaScript libraries "
        "(jQuery, AngularJS, React, Vue.js), and programming frameworks (PHP, "
        "ASP.NET, Ruby on Rails). Detection uses a combination of HTTP response "
        "headers, meta tags, JavaScript global variables, and known URL patterns."
    )

    add_body(doc,
        "The scanner maintains 29 end-of-life (EOL) software signatures that are "
        "checked against every detected component. A component is flagged as EOL "
        "when its version falls below the vendor's actively supported threshold. "
        "For example, jQuery versions below 3.x, PHP below 8.1, or WordPress "
        "major releases that no longer receive security updates."
    )

    add_warning(doc,
        "End-of-life software is permanently unpatched. Unlike a missing patch "
        "on supported software, there is no fix coming — the vendor has stopped "
        "releasing security updates. Attackers specifically target EOL software "
        "because exploitation is guaranteed to succeed indefinitely. A single "
        "EOL component can undermine every other security control."
    )

    add_bold_body(doc, "Scoring: ",
        "Each detected EOL component reduces the checker score. A clean stack "
        "with no EOL components and current versions scores 100. One EOL "
        "component drops the score significantly; multiple EOL components can "
        "bring it near zero."
    )

    add_bold_body(doc, "What this means for you: ",
        "If the report shows EOL software, upgrade or replace it as a priority. "
        "Even if no CVEs are currently known, the absence of future patches "
        "creates an ever-growing attack surface."
    )

    add_tip(doc,
        "WordPress sites should enable automatic minor updates at a minimum. "
        "For plugins and themes, use a staging environment to test major updates "
        "before applying them to production."
    )

    # ---- Domain Intelligence (WHOIS) ----
    add_h2(doc, "Domain Intelligence (WHOIS)")

    add_body(doc,
        "The WHOIS checker queries domain registration data to extract the "
        "registrar, creation date, expiry date, domain age, and whether WHOIS "
        "privacy protection is enabled. This information serves as a business "
        "maturity proxy — older domains generally belong to more established "
        "organisations, while very young domains are statistically more likely "
        "to be associated with fraud, phishing, or recently created shell "
        "companies."
    )

    add_bold_body(doc, "Key signals: ", "")
    add_bullet(doc,
        "Domain age under 1 year — flagged as a risk factor. New domains lack "
        "reputation history and are disproportionately used in scam operations."
    )
    add_bullet(doc,
        "Domain age over 5 years — positive trust signal. Long-standing domains "
        "indicate business continuity and established operations."
    )
    add_bullet(doc,
        "Domain expiry within 90 days — warning flag. A domain that is about to "
        "expire may indicate neglected infrastructure or a business in decline."
    )
    add_bullet(doc,
        "WHOIS privacy enabled — neutral for most organisations. However, for "
        "businesses that are legally required to publish contact details (e.g. "
        "financial services providers), hidden WHOIS data may raise regulatory "
        "questions."
    )

    add_note(doc,
        "Domain age is one input into the overall risk model. A young domain "
        "does not automatically mean the organisation is untrustworthy — it "
        "simply increases the weight given to other risk indicators."
    )

    # ---- DNS Intelligence (SecurityTrails) ----
    add_h2(doc, "DNS Intelligence (SecurityTrails)")

    add_body(doc,
        "This checker uses the SecurityTrails API (paid) to retrieve historical "
        "DNS records, associated domains, MX (mail exchange) records, and NS "
        "(name server) records for the target domain. SecurityTrails maintains "
        "one of the largest historical DNS databases, providing visibility into "
        "how a domain's infrastructure has changed over time."
    )

    add_bold_body(doc, "What the scanner looks for: ", "")
    add_bullet(doc,
        "Associated domains — other domains that share the same IP address, "
        "name server, or MX record. A high associated domain count (50+) "
        "indicates shared hosting, which means the domain shares an IP with "
        "many unrelated websites. Shared hosting increases risk because a "
        "compromise on any co-hosted site can affect neighbours."
    )
    add_bullet(doc,
        "Historical DNS changes — frequent changes to A records or NS records "
        "may indicate infrastructure instability or a recent migration."
    )
    add_bullet(doc,
        "MX record analysis — identifies the email provider (Google Workspace, "
        "Microsoft 365, self-hosted). Self-hosted mail servers require more "
        "operational security than managed providers."
    )
    add_bullet(doc,
        "NS record analysis — identifies DNS hosting provider. Single NS "
        "provider without redundancy is a resilience concern."
    )

    add_tip(doc,
        "If your report shows a high number of associated domains, consider "
        "moving to a dedicated IP or a VPS/cloud hosting provider where you "
        "control the IP address. This isolates your domain from neighbours' "
        "security issues."
    )

    add_note(doc,
        "SecurityTrails is a paid API. If no API key is configured, this "
        "checker returns a NO_DATA status and does not affect the overall "
        "risk score."
    )

    # ---- Privacy Policy Compliance ----
    add_h2(doc, "Privacy Policy Compliance")

    add_body(doc,
        "The privacy policy checker visits the target website and attempts to "
        "locate a privacy policy page. It searches common paths (/privacy, "
        "/privacy-policy, /legal/privacy) and footer links. Once found, the "
        "policy text is parsed to check for the presence of required sections "
        "mandated by data protection regulations, particularly POPIA (the "
        "Protection of Personal Information Act) in South Africa."
    )

    add_bold_body(doc, "Sections checked: ", "")
    add_bullet(doc,
        "Data collection — Does the policy describe what personal information "
        "is collected and the lawful basis for processing?"
    )
    add_bullet(doc,
        "Data retention — Does the policy state how long data is kept and the "
        "criteria used to determine retention periods?"
    )
    add_bullet(doc,
        "Data subject rights — Does the policy inform individuals of their "
        "rights to access, correct, and delete their personal information?"
    )
    add_bullet(doc,
        "Information officer — Does the policy name or reference an information "
        "officer or data protection officer, as required by POPIA Section 55?"
    )
    add_bullet(doc,
        "Cross-border transfers — Does the policy address whether personal "
        "information is transferred outside South Africa, and the safeguards "
        "applied?"
    )

    add_body(doc,
        "The checker calculates a compliance percentage based on how many of "
        "these required sections are present. A policy that covers all five "
        "areas scores 100%. A missing section reduces the score proportionally. "
        "No privacy policy at all results in a score of 0."
    )

    add_warning(doc,
        "Under POPIA, processing personal information without adequate "
        "transparency (including a compliant privacy policy) can result in "
        "fines of up to R10 million or imprisonment. This is not a theoretical "
        "risk — the South African Information Regulator has begun issuing "
        "enforcement notices. A missing or incomplete privacy policy is a "
        "compliance gap that should be addressed immediately."
    )

    add_tip(doc,
        "Use the compliance percentage in the report as a checklist. If the "
        "scanner flags a missing 'data retention' section, for example, work "
        "with your legal team to add an explicit retention statement to your "
        "privacy policy."
    )

    # ---- Security Policy & Vulnerability Disclosure ----
    add_h2(doc, "Security Policy & Vulnerability Disclosure")

    add_body(doc,
        "This checker looks for three indicators of a mature security posture:"
    )

    add_bullet(doc,
        "security.txt — The scanner checks for a machine-readable security "
        "contact file at /.well-known/security.txt, as defined by RFC 9116. "
        "This file tells security researchers how to report vulnerabilities "
        "responsibly. Its presence indicates the organisation has a Vulnerability "
        "Disclosure Policy (VDP), which is a hallmark of mature security "
        "practices."
    )
    add_bullet(doc,
        "PGP key — If security.txt references a PGP encryption key, it shows "
        "the organisation can receive encrypted vulnerability reports, adding "
        "another layer of operational maturity."
    )
    add_bullet(doc,
        "robots.txt — While primarily an SEO file, robots.txt can reveal "
        "hidden directories or admin paths through its Disallow rules. The "
        "scanner checks whether it exists and whether it inadvertently exposes "
        "sensitive paths."
    )

    add_note(doc,
        "A Vulnerability Disclosure Policy does not directly prevent attacks, "
        "but organisations with a VDP are statistically more likely to learn "
        "about and fix vulnerabilities before they are exploited. The scanner "
        "treats the presence of security.txt as a positive governance signal."
    )

    # ---- Payment Security (PCI) ----
    add_h2(doc, "Payment Security (PCI)")

    add_body(doc,
        "The payment security checker scans the target website for payment "
        "processing pages and identifies how card payments are handled. It "
        "detects both self-hosted payment forms and third-party payment "
        "providers."
    )

    add_bold_body(doc, "Self-hosted payment forms: ",
        "If the website hosts its own payment form (i.e. the card number field "
        "is on the organisation's own domain), the full scope of PCI DSS "
        "compliance applies. This means the organisation must meet all PCI DSS "
        "requirements including quarterly vulnerability scans by an Approved "
        "Scanning Vendor (ASV), penetration testing, and extensive documentation. "
        "Self-hosted payment forms are flagged as a significant compliance risk."
    )

    add_bold_body(doc, "Third-party payment providers: ",
        "If the website uses a recognised payment provider such as Stripe, "
        "PayFast, PayGate, Peach Payments, or Yoco, the card data never touches "
        "the organisation's servers. This dramatically reduces PCI scope, "
        "typically to SAQ A or SAQ A-EP level. The scanner treats third-party "
        "payment processing as a positive security signal."
    )

    add_warning(doc,
        "If your report flags a self-hosted payment form, this is a critical "
        "finding. Handling card data directly exposes you to PCI DSS audit "
        "requirements, potential fines from card brands, and significantly "
        "higher breach liability. Migrating to a third-party payment provider "
        "is almost always the correct remediation."
    )

    add_tip(doc,
        "Even if you use a third-party provider, ensure the payment page is "
        "served over TLS 1.2 or later and that your Content Security Policy "
        "headers restrict which domains can load scripts. A compromised script "
        "on your page can still intercept payment data before it reaches the "
        "provider (a Magecart-style attack)."
    )

    # ==================================================================
    # 4.8  Compliance Framework Mapping
    # ==================================================================
    add_h1(doc, "4.8  Compliance Framework Mapping")

    add_body(doc,
        "The scanner maps every checker result to four widely-used compliance "
        "frameworks. Rather than requiring a separate compliance audit, the "
        "scan data is automatically cross-referenced against each framework's "
        "controls to produce a per-framework compliance estimate. This section "
        "explains each framework, the controls mapped, and how to interpret "
        "the results."
    )

    # ---- POPIA ----
    add_h2(doc, "POPIA (Protection of Personal Information Act)")

    add_body(doc,
        "POPIA is South Africa's data protection law, broadly equivalent to "
        "the EU's GDPR. It governs how organisations collect, process, store, "
        "and share personal information. Every South African organisation that "
        "processes personal information must comply with POPIA."
    )

    add_bold_body(doc, "Controls mapped from the scan: ", "")
    add_bullet(doc,
        "S19a — Encryption in Transit: TLS configuration and certificate "
        "validity (from the SSL checker). POPIA Section 19 requires appropriate "
        "technical measures to secure personal information."
    )
    add_bullet(doc,
        "S19b — Security Headers: HTTP security headers that prevent XSS, "
        "clickjacking, and MIME-type attacks."
    )
    add_bullet(doc,
        "S19c — Web Application Security: Secure website configuration and "
        "WAF protection."
    )
    add_bullet(doc,
        "S19d — Network Access Control: Restriction of remote access services "
        "(RDP, VPN) and closure of high-risk network ports."
    )
    add_bullet(doc,
        "S19e — Email Security: SPF, DMARC, and DKIM configuration to prevent "
        "phishing and email impersonation."
    )
    add_bullet(doc,
        "S20a — Privacy Policy: Published privacy policy covering all POPIA-"
        "required sections."
    )
    add_bullet(doc,
        "S20b — Data Minimisation: No unnecessary exposure of sensitive files "
        "or admin interfaces."
    )
    add_bullet(doc,
        "S21a — Software Currency: All software components actively maintained "
        "with no end-of-life versions."
    )
    add_bullet(doc,
        "S22a — Breach History: Historical data breach exposure and notification "
        "readiness."
    )
    add_bullet(doc,
        "S22b — Credential Exposure: Leaked credentials in public breach "
        "databases (Dehashed)."
    )

    # ---- PCI DSS ----
    add_h2(doc, "PCI DSS v4.0 (Payment Card Industry Data Security Standard)")

    add_body(doc,
        "PCI DSS is a global standard that applies to any organisation that "
        "stores, processes, or transmits payment card data. Even organisations "
        "that use third-party payment processors must demonstrate certain "
        "baseline controls."
    )

    add_bold_body(doc, "Controls mapped from the scan: ", "")
    add_bullet(doc,
        "Req 2a — Default Credentials: Checks for exposed admin panels that "
        "may use default or guessable credentials."
    )
    add_bullet(doc,
        "Req 2b — System Hardening: Security headers and information disclosure "
        "controls."
    )
    add_bullet(doc,
        "Req 2c — Security Policies: Presence of documented security policies "
        "(security.txt)."
    )
    add_bullet(doc,
        "Req 4a — TLS Configuration: Strong TLS encryption for cardholder data "
        "transmission."
    )
    add_bullet(doc,
        "Req 4b — HTTPS Enforcement: All endpoints handling sensitive data "
        "served exclusively over HTTPS."
    )
    add_bullet(doc,
        "Req 6a — Patch Management: Software versions current with no known "
        "vulnerabilities."
    )
    add_bullet(doc,
        "Req 6b — Secure Coding: Secure application headers and web application "
        "protection."
    )
    add_bullet(doc,
        "Req 8a — Payment Security: PCI-compliant payment processing (third-"
        "party vs. self-hosted)."
    )
    add_bullet(doc,
        "Req 11a — Vulnerability Scanning: External vulnerability scan results "
        "from Shodan CVE analysis."
    )
    add_bullet(doc,
        "Req 11b — Threat Monitoring: VirusTotal reputation and DNSBL "
        "blacklist monitoring."
    )

    # ---- ISO 27001 ----
    add_h2(doc, "ISO 27001 (Information Security Management)")

    add_body(doc,
        "ISO 27001 is the international standard for information security "
        "management systems (ISMS). It provides a systematic approach to "
        "managing sensitive information through risk assessment and controls. "
        "Many enterprise clients and government tenders require ISO 27001 "
        "certification."
    )

    add_bold_body(doc, "Controls mapped from the scan: ", "")
    add_bullet(doc,
        "A.8a — Asset Inventory: Technology stack detection and external IP "
        "enumeration."
    )
    add_bullet(doc,
        "A.8b — Attack Surface: Subdomain discovery and attack surface mapping."
    )
    add_bullet(doc,
        "A.12a — Network Security: Open port analysis, DNS infrastructure, and "
        "service hardening."
    )
    add_bullet(doc,
        "A.12b — Remote Access: RDP, VPN, and remote access protocol security."
    )
    add_bullet(doc,
        "A.12c — Malware and Reputation: DNSBL blacklisting and VirusTotal "
        "malware detection."
    )
    add_bullet(doc,
        "A.12d — DDoS Resilience: WAF detection and CDN/cloud infrastructure."
    )
    add_bullet(doc,
        "A.14a — Encryption Standards: SSL/TLS configuration and certificate "
        "management."
    )
    add_bullet(doc,
        "A.14b — Application Security: HTTP security headers and web "
        "application hardening."
    )
    add_bullet(doc,
        "A.14c — Payment and Data Handling: Secure payment processing and "
        "information disclosure controls."
    )

    # ---- NIST CSF 2.0 ----
    add_h2(doc, "NIST Cybersecurity Framework (CSF) 2.0")

    add_body(doc,
        "NIST CSF 2.0 is the United States' voluntary cybersecurity framework, "
        "widely adopted globally. Version 2.0 (released February 2024) added a "
        "sixth function — Govern — to the original five. The framework organises "
        "cybersecurity activities into six core functions: Govern, Identify, "
        "Protect, Detect, Respond, and Recover."
    )

    add_bold_body(doc, "14 sub-controls mapped from the scan: ", "")
    add_bullet(doc, "GOVERN — GV.1 Security Policy: Documented cybersecurity governance (security.txt).")
    add_bullet(doc, "GOVERN — GV.2 Privacy Governance: Privacy policy and data protection compliance.")
    add_bullet(doc, "IDENTIFY — ID.1 Asset Discovery: Technology stack and external IP inventory.")
    add_bullet(doc, "IDENTIFY — ID.2 Attack Surface Mapping: Subdomain discovery and information disclosure.")
    add_bullet(doc, "PROTECT — PR.1 Encryption and TLS: Data-in-transit protection.")
    add_bullet(doc, "PROTECT — PR.2 Security Headers and Hardening: HTTP hardening and web application security.")
    add_bullet(doc, "PROTECT — PR.3 Perimeter Defence: WAF, firewall rules, and remote access controls.")
    add_bullet(doc, "PROTECT — PR.4 Email Authentication: SPF, DMARC, DKIM, and MTA-STS.")
    add_bullet(doc, "DETECT — DE.1 Vulnerability Detection: Shodan CVE analysis and version-based vulnerability scanning.")
    add_bullet(doc, "DETECT — DE.2 Threat Intelligence: VirusTotal, DNSBL, and exposed admin detection.")
    add_bullet(doc, "RESPOND — RS.1 Breach Response: Historical breach exposure and credential leak monitoring.")
    add_bullet(doc, "RESPOND — RS.2 Security Disclosure: Published vulnerability disclosure policy.")
    add_bullet(doc, "RECOVER — RC.1 Infrastructure Resilience: DNS redundancy and CDN availability.")
    add_bullet(doc, "RECOVER — RC.2 Communication Recovery: Email infrastructure resilience.")

    # ---- How Compliance Scoring Works ----
    add_h2(doc, "How Compliance Scoring Works")

    add_body(doc,
        "The scanner uses a hybrid scoring approach for compliance assessment. "
        "Each sub-control (e.g. 'S19a — Encryption in Transit') receives a "
        "score of 0 to 100 derived from the checker or checkers that feed into "
        "it. If a sub-control is fed by multiple checkers, the scores are "
        "averaged. Each sub-control also carries a weight (typically 0.6 to 1.2) "
        "reflecting its relative importance within the framework. The "
        "framework's overall percentage is then the weighted average of all its "
        "sub-control scores."
    )

    add_bold_body(doc, "Status badges: ", "")
    add_bullet(doc, "PASS (score 70 or above) — The control meets the expected standard based on external evidence.")
    add_bullet(doc, "PARTIAL (score 40 to 69) — The control is partially implemented but has gaps.")
    add_bullet(doc, "FAIL (score below 40) — The control is absent or critically deficient.")
    add_bullet(doc, "NO_DATA — The checker(s) feeding this control did not return data (e.g. paid API not configured, checker timed out). The control is excluded from the weighted average so it does not unfairly penalise the score.")

    add_body(doc,
        "Because this is an external-only assessment (no internal network "
        "access, no agent installed, no interviews), the scanner typically "
        "covers 60 to 80 percent of each framework's controls. Controls that "
        "require internal assessment — such as access management policies, "
        "backup procedures, or physical security — cannot be evaluated "
        "externally and are marked as NO_DATA."
    )

    add_warning(doc,
        "The compliance percentages in this report are estimates based on "
        "externally observable evidence. They are not a substitute for a "
        "formal compliance audit. A PASS status on an external scan does not "
        "guarantee full compliance with the framework — internal controls must "
        "also be assessed. Use these results as a starting point and gap "
        "analysis tool, not as a certification claim."
    )

    add_tip(doc,
        "Focus remediation on FAIL controls first, then PARTIAL controls. "
        "NO_DATA controls should be assessed through an internal review or "
        "formal audit. The scanner's compliance mapping is designed to "
        "prioritise the controls that can be validated externally."
    )

    # ==================================================================
    # 5.  Insurance Analytics (Deep Dive)
    # ==================================================================
    add_h1(doc, "5.  Insurance Analytics (Deep Dive)")

    add_body(doc,
        "The Insurance Analytics module translates raw scan findings into "
        "financially meaningful metrics for cyber insurance underwriting, "
        "premium benchmarking, and risk transfer decisions. It consists of "
        "four interconnected components: the Ransomware Susceptibility Index "
        "(RSI), the Data Breach Index (DBI), a Hybrid Financial Impact "
        "model, and a Remediation Roadmap with projected cost savings."
    )

    add_body(doc,
        "These analytics are designed to be used by insurance brokers, "
        "underwriters, and risk managers. They convert technical scan data "
        "into the language of insurance — probability, loss magnitude, "
        "confidence intervals, and risk reduction ROI."
    )

    # ==================================================================
    # 5.1  Ransomware Susceptibility Index (RSI)
    # ==================================================================
    add_h2(doc, "5.1  Ransomware Susceptibility Index (RSI)")

    add_body(doc,
        "The RSI is a 0.0 to 1.0 score that estimates how susceptible an "
        "organisation is to a successful ransomware attack, based entirely "
        "on externally observable indicators. Higher scores mean higher "
        "susceptibility. The RSI is the primary input to the financial impact "
        "model's ransomware scenario."
    )

    add_bold_body(doc, "Base score: ",
        "Every internet-connected organisation starts with a base score of "
        "0.05, representing the inherent risk of having any internet presence. "
        "From there, contributing factors are added based on scan findings."
    )

    add_h2(doc, "RSI Contributing Factors")

    add_bold_body(doc, "Priority 1 — Critical signals (strongest ransomware indicators): ", "")
    add_bullet(doc,
        "RDP exposed (port 3389): +0.25. This is the single largest contributor "
        "because RDP is the number one ransomware entry vector globally. "
        "Exposed RDP alone pushes the score to at least 0.30."
    )
    add_bullet(doc,
        "Exposed database ports (MongoDB, Redis, PostgreSQL, MySQL, etc.): "
        "+0.10 per exposed database, capped at +0.20. Exposed databases "
        "indicate severe network segmentation failures."
    )
    add_bullet(doc,
        "CISA KEV CVEs (Known Exploited Vulnerabilities): +0.08 per KEV CVE, "
        "capped at +0.20. These are vulnerabilities that CISA has confirmed "
        "are actively being exploited in the wild — they are not theoretical "
        "risks."
    )

    add_bold_body(doc, "Priority 2 — High-impact signals: ", "")
    add_bullet(doc,
        "High-EPSS CVEs (exploit probability above 50%): +0.04 each, capped "
        "at +0.12. EPSS (Exploit Prediction Scoring System) predicts the "
        "likelihood a CVE will be exploited within 30 days."
    )
    add_bullet(doc,
        "Other critical or high-severity CVEs: +0.02 each, capped at +0.08. "
        "Unpatched vulnerabilities that are not yet in CISA KEV but still "
        "carry significant risk."
    )
    add_bullet(doc,
        "IP or domain blacklisted: +0.04. Blacklisting on DNSBL lists "
        "indicates prior compromise, spam origination, or malware distribution."
    )
    add_bullet(doc,
        "Critical files exposed (e.g. .env, .git, backups): +0.02 per "
        "exposure, capped at +0.06. Exposed configuration files can leak "
        "credentials and infrastructure details."
    )

    add_bold_body(doc, "Priority 3 — Contributing factors (hygiene indicators): ", "")
    add_bullet(doc,
        "Credential leaks (from Dehashed): Scaled by volume. Over 100 leaks: "
        "+0.06. Between 10 and 100: +0.04. Under 10: +0.02. Leaked "
        "credentials enable credential stuffing and account takeover."
    )
    add_bullet(doc,
        "Breach history: +0.03 if more than 3 historical breaches. Prior "
        "breaches are a strong predictor of future incidents."
    )
    add_bullet(doc,
        "No DMARC record: +0.03. DMARC policy set to 'none': +0.02. Missing "
        "or unenforced DMARC leaves the domain vulnerable to phishing and "
        "business email compromise (BEC)."
    )
    add_bullet(doc,
        "No WAF detected: +0.03. Without a web application firewall, the "
        "site is exposed to OWASP Top 10 attacks."
    )
    add_bullet(doc,
        "Weak SSL (grade D, E, or F): +0.03. Weak encryption can allow "
        "man-in-the-middle attacks."
    )

    add_h2(doc, "RSI Diminishing Returns and Multipliers")

    add_body(doc,
        "To prevent score inflation from stacking many moderate findings, "
        "the RSI applies a diminishing returns function above 0.50. Below "
        "0.50, the score is linear (each factor adds its full value). Above "
        "0.50, each additional increment contributes progressively less — the "
        "score approaches 1.0 asymptotically but never reaches it from "
        "moderate findings alone. This means an RSI above 0.75 requires "
        "genuinely critical issues (exposed RDP, KEV CVEs, active compromise), "
        "not just an accumulation of minor hygiene gaps."
    )

    add_bold_body(doc, "Industry multipliers: ",
        "After the diminishing returns adjustment, an industry multiplier "
        "is applied. Healthcare (1.15), Legal (1.12), Finance (1.10), "
        "Government (1.12), Manufacturing (1.05), Retail (1.05), "
        "Education (1.05), Technology (1.0), Other (1.0). These reflect "
        "the empirical reality that certain industries are disproportionately "
        "targeted by ransomware operators."
    )

    add_bold_body(doc, "Size multiplier: ",
        "Large enterprises (annual revenue above R500M) receive a modest "
        "discount (0.95 multiplier) because they are assumed to have internal "
        "defences not visible to an external scan. SMEs are scored at 1.0 "
        "(neutral)."
    )

    add_bold_body(doc, "Risk labels: ", "")
    add_bullet(doc, "Critical: RSI of 0.75 or above. Immediate action required.")
    add_bullet(doc, "High: RSI of 0.50 to 0.74. Significant exposure, address within 30 days.")
    add_bullet(doc, "Medium: RSI of 0.25 to 0.49. Moderate exposure, address within 90 days.")
    add_bullet(doc, "Low: RSI below 0.25. Acceptable risk posture for most organisations.")

    add_note(doc,
        "The RSI measures susceptibility to ransomware attack, not the "
        "probability of one occurring. An RSI of 0.60 does not mean there "
        "is a 60% chance of ransomware — it means the external attack surface "
        "has 60% of the observable characteristics that ransomware operators "
        "look for when selecting targets."
    )

    # ==================================================================
    # 5.2  Data Breach Index (DBI)
    # ==================================================================
    add_h2(doc, "5.2  Data Breach Index (DBI)")

    add_body(doc,
        "The Data Breach Index is a 0 to 100 score that measures historical "
        "breach exposure and resilience. Unlike the RSI (where higher is "
        "worse), a higher DBI score is better — it indicates lower historical "
        "exposure and a more favourable breach profile. The DBI uses data from "
        "Have I Been Pwned (HIBP) breach records and Dehashed credential leak "
        "databases."
    )

    add_h2(doc, "DBI Components")

    add_bold_body(doc, "1. Breach Count (maximum 30 points): ",
        "Zero breaches scores the full 30 points. One to three breaches "
        "scores 15 points. More than three breaches scores 0 points. Breach "
        "count is the single largest component because repeated breaches "
        "indicate systemic security weaknesses."
    )

    add_bold_body(doc, "2. Recency (maximum 20 points): ",
        "Measures how recently the most recent breach occurred. A breach "
        "within the last year scores 0 points — this is a current, active "
        "risk. A breach between one and three years ago scores 10 points. "
        "No breach in the last three years (or no breaches at all) scores "
        "the full 20 points. Recent breaches weigh more heavily because the "
        "compromised data is more likely to still be in active circulation."
    )

    add_bold_body(doc, "3. Data Severity (maximum 15 points): ",
        "Evaluates what types of data were exposed. If breaches included "
        "passwords, credit card numbers, bank account numbers, social "
        "security numbers, or financial data, the score is 0 points — these "
        "are the most damaging data classes. If only email addresses were "
        "exposed, the score is 10 points. No data exposed at all scores "
        "the full 15 points."
    )

    add_bold_body(doc, "4. Credential Leaks (maximum 20 points): ",
        "Counts credential entries found in the Dehashed database. Zero "
        "leaks scores 20 points. Up to 100 leaks scores 10 points. More "
        "than 100 leaks scores 0 points. If the Dehashed API key is not "
        "configured, a middle score of 10 points is assigned (unknown "
        "status is treated as moderate risk)."
    )

    add_bold_body(doc, "5. Breach Trend (maximum 15 points): ",
        "Analyses the trajectory of breach exposure. If no breaches occurred "
        "in the last two years, the trend is 'Improving' (15 points). One "
        "or two recent breaches scores 'Stable' (7 points). Three or more "
        "recent breaches scores 'Worsening' (0 points). An improving trend "
        "signals that the organisation may have strengthened its defences "
        "since the last incident."
    )

    add_bold_body(doc, "DBI labels: ", "")
    add_bullet(doc, "Excellent: 80-100. Minimal historical breach exposure.")
    add_bullet(doc, "Good: 60-79. Low exposure with no critical data compromised recently.")
    add_bullet(doc, "Fair: 40-59. Moderate exposure requiring attention.")
    add_bullet(doc, "Poor: 20-39. Significant breach history with concerning patterns.")
    add_bullet(doc, "Critical: 0-19. Extensive breach exposure with active credential leaks.")

    add_tip(doc,
        "A low DBI score does not mean a breach is inevitable — it means the "
        "organisation's historical exposure is high, which increases the "
        "probability of credential reuse attacks, phishing using leaked data, "
        "and repeat incidents. The most effective remediation is a forced "
        "password reset combined with mandatory multi-factor authentication."
    )

    # ==================================================================
    # 5.3  Financial Impact (Hybrid Model)
    # ==================================================================
    add_h2(doc, "5.3  Financial Impact Estimation (Hybrid Model)")

    add_body(doc,
        "The Financial Impact module uses a hybrid approach derived from FAIR "
        "(Factor Analysis of Information Risk) methodology, anchored to IBM "
        "SA 2025 breach cost data (R49.22 million ransom-inclusive average), "
        "Sophos SA 2025 ransomware survey data, and actual South African "
        "insurance claims data. The model produces four cost categories, seven "
        "incident types, and Monte Carlo confidence intervals for probable "
        "annual loss."
    )

    add_h2(doc, "Hybrid engine architecture")

    add_body(doc,
        "The total breach magnitude is anchored to the IBM SA average cost "
        "(R49.22 million, ransom-inclusive) and scaled by two factors:"
    )
    add_bullet(doc,
        "Revenue scaling with graduated elasticity — smaller organisations "
        "experience proportionally higher costs relative to revenue, while "
        "larger organisations benefit from economies of scale in incident "
        "response. The elasticity curve ensures that a R10 million-revenue "
        "company is not assigned the same absolute loss as a R500 million "
        "enterprise."
    )
    add_bullet(doc,
        "Industry multiplier with graduated severity — high-risk industries "
        "(financial services, healthcare, legal) receive a graduated uplift "
        "reflecting their higher regulatory exposure, data sensitivity, and "
        "historical claims frequency."
    )

    add_body(doc,
        "The anchored magnitude is then decomposed into five cost components:"
    )
    add_bullet(doc,
        "C1: Post-breach liability (residual) — notification costs, credit "
        "monitoring, legal fees, reputational damage, and customer churn. "
        "This is the residual after C2-C5 are allocated."
    )
    add_bullet(doc,
        "C2: Regulatory fines per jurisdiction — POPIA fines (up to "
        "R10 million), GDPR exposure (4% of global turnover, uncapped) if "
        "applicable, and PCI DSS fines if applicable. Jurisdiction-specific "
        "calculations based on the scan input toggles."
    )
    add_bullet(doc,
        "C3: Business interruption — revenue loss during recovery. Uses a "
        "SA-calibrated PERT distribution for recovery time: PERT(3, 25, 120) "
        "days, reflecting the Sophos SA 2025 finding that SA organisations "
        "take a median of 25 days to recover from ransomware."
    )
    add_bullet(doc,
        "C4: Ransom/extortion — set at 10.40% of total breach magnitude, "
        "proportional to the IBM SA data decomposition. This component is "
        "only activated for ransomware-family incidents."
    )
    add_bullet(doc,
        "C5: Incident response — forensics, containment, eradication, and "
        "recovery costs. Tiered by organisation size: smaller companies face "
        "relatively higher IR costs (fewer internal resources), while larger "
        "companies benefit from retained IR relationships and internal SOC "
        "capabilities."
    )

    add_h2(doc, "Four reporting categories")

    add_body(doc,
        "The five cost components are grouped into four reporting categories "
        "that align with standard insurance policy sections:"
    )
    add_bullet(doc,
        "Data breach exposure: C1 (post-breach liability) + C2 (regulatory "
        "fines). Covers third-party liability and regulatory penalties."
    )
    add_bullet(doc,
        "Detection and escalation: C5 (incident response). Covers forensic "
        "investigation, notification, and containment costs."
    )
    add_bullet(doc,
        "Ransom demand: C4 (ransom/extortion). Covers extortion payments "
        "and negotiation costs."
    )
    add_bullet(doc,
        "Business interruption: C3 (business interruption). Covers revenue "
        "loss and extra expense during the recovery period."
    )

    add_h2(doc, "Probability model")

    add_body(doc,
        "The probability of a breach event is calculated as:"
    )
    add_body(doc,
        "p_breach = Vulnerability x TEF x 0.30"
    )
    add_body(doc,
        "Where Vulnerability is derived from the scan findings (SSL grade, "
        "exposed services, patch posture, credential leaks) and TEF (Threat "
        "Event Frequency) is the annual frequency of attempted attacks for "
        "the organisation's industry and size profile. The 0.30 calibration "
        "factor aligns modelled probabilities with observed SA claims "
        "frequencies."
    )

    add_body(doc,
        "The RSI score drives ransomware-family incidents specifically. "
        "Ransomware initial access vector weights are calibrated to Sophos "
        "SA 2025 survey data:"
    )
    add_bullet(doc, "Compromised credentials: 34%")
    add_bullet(doc, "Exploited vulnerabilities: 28%")
    add_bullet(doc, "Malicious email (phishing): 22%")
    add_bullet(doc, "Other vectors (brute force, supply chain, etc.): 16%")

    add_body(doc,
        "These weights rebalance the RSI contributing factors so that "
        "credential exposure and vulnerability posture carry appropriately "
        "higher weight in the ransomware probability calculation than "
        "secondary indicators like missing headers or weak DNS."
    )

    add_h2(doc, "Monte Carlo simulation")

    add_body(doc,
        "The model runs 10,000 Monte Carlo iterations using PERT "
        "distributions (lambda = 4) for all uncertain parameters. PERT "
        "distributions are preferred over triangular distributions because "
        "they concentrate more probability around the most likely value "
        "while still allowing for tail events."
    )

    add_body(doc,
        "Key PERT parameters include SA recovery time PERT(3, 25, 120) "
        "days, cost-per-record ranges by industry, and ransom demand "
        "distributions calibrated to the Sophos SA 2025 median payment "
        "data."
    )

    add_body(doc,
        "The simulation produces a full probability distribution from which "
        "percentiles are extracted: P5 (optimistic), P25, P50 (median/most "
        "likely), P75, and P95 (pessimistic). The 90% confidence interval "
        "(P5 to P95) represents the range within which actual annual loss "
        "is expected to fall with 90% confidence."
    )

    add_h2(doc, "Insurance recommendations")

    add_body(doc,
        "The model outputs three insurance-relevant figures derived from the "
        "Monte Carlo distribution:"
    )
    add_bullet(doc,
        "Suggested deductible — calculated as a percentage of the recommended "
        "coverage limit, scaled by the RSI score. The deductible percentage "
        "ranges from 0.5% (low risk) to 20% (critical risk) on a non-linear "
        "curve, with increments accelerating at higher risk levels. This "
        "represents the amount the organisation can reasonably self-insure."
    )
    add_bullet(doc,
        "Expected annual loss — the P50 (median) total loss across all "
        "incident types. This is the most likely annual cyber loss figure "
        "and should be the baseline for premium calculations."
    )
    add_bullet(doc,
        "Recommended coverage limit — set at 120% of the P95 (pessimistic) "
        "loss estimate. This provides a buffer above the worst-case-with-"
        "confidence scenario to account for tail risk."
    )

    add_note(doc,
        "The financial estimates are modelled projections, not guarantees. "
        "They are based on externally observable data combined with IBM SA "
        "benchmarks, Sophos SA 2025 ransomware data, and actual SA insurance "
        "claims experience. Actual losses may be higher or lower depending "
        "on internal controls, incident response capability, and the specific "
        "nature of any incident. Use these figures as a data-driven starting "
        "point for insurance discussions, not as actuarial certainties."
    )

    add_warning(doc,
        "The breach cost anchor (R49.22 million) and component proportions "
        "are derived from IBM 2025 SA-specific data. The ransomware recovery "
        "time and vector weights use Sophos SA 2025 survey data. These are "
        "calibrated averages — actual costs will vary based on data "
        "sensitivity, regulatory jurisdiction, organisation size, and "
        "incident response readiness."
    )

    # ==================================================================
    # 5.4  Remediation Roadmap
    # ==================================================================
    add_h2(doc, "5.4  Remediation Roadmap")

    add_body(doc,
        "The Remediation Roadmap is the most actionable section of the "
        "insurance analytics. It takes every finding from the scan and "
        "converts it into a prioritised list of remediation steps, ordered "
        "by the magnitude of RSI reduction each step would achieve. For "
        "each step, the roadmap provides: a plain-English action description, "
        "a priority level, an indicative cost range, the projected RSI "
        "reduction, and the estimated annual savings in financial impact."
    )

    add_h2(doc, "Priority Levels")

    add_bullet(doc,
        "P1 (Critical) — RSI reduction of 0.10 or more per step. These are "
        "the findings that contribute the most to ransomware susceptibility. "
        "Examples: blocking exposed RDP, firewalling exposed databases, "
        "patching CISA KEV CVEs. Address within 14 days."
    )
    add_bullet(doc,
        "P2 (High) — RSI reduction of 0.05 to 0.09 per step. Significant "
        "security improvements that should be addressed within 30 days. "
        "Examples: deploying a WAF, implementing DMARC, resetting leaked "
        "credentials."
    )
    add_bullet(doc,
        "P3 (Medium) — RSI reduction below 0.05 per step. Hygiene "
        "improvements to address within 90 days. Examples: updating EOL "
        "software, creating a security.txt file, resolving DNSBL blacklisting."
    )

    add_h2(doc, "Estimated Cost Ranges")

    add_body(doc,
        "Each remediation step includes an indicative cost range in South "
        "African Rand (ZAR). These are based on typical SA market rates for "
        "the type of work involved and are intended as a conversation starter "
        "for budgeting discussions — they are not project quotes. Actual costs "
        "will depend on the complexity of the environment, the service "
        "provider chosen, and whether in-house resources are available."
    )

    add_bold_body(doc, "Example cost ranges: ", "")
    add_bullet(doc, "Blocking RDP or firewalling database ports: R9,000 to R36,000.")
    add_bullet(doc, "Patching CISA KEV or critical CVEs: R18,000 to R90,000.")
    add_bullet(doc, "SSL/TLS reconfiguration: R0 to R3,600 (often free with hosting provider tools).")
    add_bullet(doc, "DMARC implementation: R3,600 to R9,000.")
    add_bullet(doc, "WAF deployment (e.g. Cloudflare): R0 to R9,000 per month.")
    add_bullet(doc, "Credential reset and MFA rollout: R9,000 to R36,000.")

    add_warning(doc,
        "The cost estimates are indicative SA market rates and are provided "
        "as a budgeting guide only. They are not quotations and should not "
        "be treated as binding. Always obtain formal quotes from qualified "
        "service providers before committing to remediation expenditure."
    )

    add_h2(doc, "Annual Savings Calculation")

    add_body(doc,
        "For each remediation step, the roadmap estimates the annual savings "
        "by calculating how much the financial impact model's expected loss "
        "would decrease if that step were completed. The formula is:"
    )

    add_body(doc,
        "Annual Savings = (RSI Reduction / Current RSI) x Total Expected "
        "Annual Loss x 0.70"
    )

    add_body(doc,
        "The 0.70 factor is a conservatism adjustment — it acknowledges that "
        "not all of the modelled financial benefit will materialise perfectly "
        "in practice. This prevents over-promising on savings."
    )

    add_h2(doc, "Current vs. Projected RSI")

    add_body(doc,
        "The roadmap concludes with a comparison of the current RSI and the "
        "projected RSI if all recommended steps were completed. The simulated "
        "RSI is calculated by subtracting the total RSI reduction from all "
        "steps (floored at 0.0). The simulated financial impact is then "
        "recalculated proportionally, showing the new expected annual loss "
        "under the improved security posture."
    )

    add_body(doc,
        "The total potential savings figure represents the aggregate annual "
        "financial benefit of completing all remediation steps. This figure "
        "is particularly valuable for justifying cybersecurity budgets to "
        "executive management and boards — it translates security improvements "
        "into a return-on-investment narrative."
    )

    add_tip(doc,
        "When presenting the Remediation Roadmap to clients, focus on the "
        "P1 items first. A single P1 remediation (such as blocking RDP) "
        "often produces a larger RSI reduction than all P3 items combined. "
        "This makes the business case for immediate, high-impact fixes "
        "compelling and easy to communicate."
    )

    add_note(doc,
        "The Remediation Roadmap is regenerated with every scan. As "
        "remediation steps are completed and the domain is rescanned, "
        "completed items will disappear from the roadmap, the RSI will "
        "decrease, and the financial impact estimates will update accordingly. "
        "This creates a measurable improvement cycle that can be tracked "
        "over time."
    )
