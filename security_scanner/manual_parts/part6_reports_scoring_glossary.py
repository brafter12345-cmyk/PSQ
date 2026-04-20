"""
Phishield Cyber Risk Scanner -- User Manual
Sections 6-11: PDF Reports, Scoring Methodology, API Integrations,
Known Limitations, Glossary, Version History.

Consumed by the manual builder via  build(doc).
"""


def build(doc):
    """Append sections 6-11 to *doc* using the shared helper API."""
    from manual_parts.helpers import (
        add_h1,
        add_h2,
        add_body,
        add_bold_body,
        add_bullet,
        add_tip,
        add_warning,
        add_note,
    )

    # ------------------------------------------------------------------ #
    #  SECTION 6 -- PDF REPORTS                                          #
    # ------------------------------------------------------------------ #
    add_h1(doc, "6. PDF Reports")

    add_body(
        doc,
        "The Phishield scanner produces two distinct PDF report formats, each "
        "tailored for a different audience. Both reports are generated "
        "automatically at the end of every scan and can be downloaded from "
        "the results screen or emailed directly to the intended recipient.",
    )

    # 6.1 Full Technical Report ---------------------------------------- #
    add_h2(doc, "6.1 Full Technical Report")

    add_body(
        doc,
        "The Full Technical Report is the primary deliverable of every "
        "Phishield scan. It typically spans 20-25 pages and provides an "
        "exhaustive, evidence-based assessment of the target domain's "
        "external cyber-risk posture. The report is structured for both "
        "technical and executive audiences, with progressive detail from "
        "summary to granular findings.",
    )

    add_bold_body(doc, "Cover Page", "")
    add_body(
        doc,
        "The cover page displays the target domain, scan date and time, "
        "and a large risk-score gauge that immediately communicates the "
        "overall risk level. The gauge uses a colour gradient from green "
        "(low risk) through amber to red (critical risk) with the numeric "
        "score (0-1000) prominently displayed.",
    )

    add_bold_body(doc, "Executive Summary", "")
    add_body(
        doc,
        "A one-page overview presenting the overall risk score alongside "
        "key metrics: total vulnerabilities found, critical and high-severity "
        "issue counts, breach exposure count, number of leaked credentials, "
        "estimated financial impact range, and scan completeness percentage. "
        "This section is designed to be read in under two minutes by a "
        "C-suite executive or board member.",
    )

    add_bold_body(doc, "Vulnerability Posture", "")
    add_body(
        doc,
        "This section delivers the technical depth. It includes a CVE "
        "severity breakdown (critical, high, medium, low) with bar charts, "
        "patch management indicators showing the age and exploitability of "
        "discovered vulnerabilities, and threat indicators such as EPSS "
        "scores and CISA KEV membership for each CVE. Where applicable, "
        "CVSS base scores and vector strings are provided alongside "
        "plain-language explanations of potential impact.",
    )

    add_bold_body(doc, "Attacker's View (Kill Chain Narrative)", "")
    add_body(
        doc,
        "A four-phase narrative that walks the reader through how an "
        "attacker would exploit the findings discovered during the scan. "
        "The phases are: (1) Reconnaissance -- what an attacker can learn "
        "from publicly available information about the target, "
        "(2) Weaponisation -- how discovered vulnerabilities and leaked "
        "credentials could be combined into an attack toolkit, "
        "(3) Delivery & Exploitation -- the most likely attack vectors "
        "such as phishing with leaked credentials, exploiting unpatched "
        "services, or abusing misconfigured email authentication, and "
        "(4) Impact -- the realistic business consequences including "
        "data exfiltration, ransomware deployment, business email "
        "compromise, and financial loss. Each phase references specific "
        "findings from the scan to ground the narrative in evidence.",
    )

    add_bold_body(doc, "Insurance Analytics", "")
    add_body(
        doc,
        "This section presents the quantitative risk metrics used by "
        "cyber-insurance underwriters and brokers. It includes the "
        "Ransomware Susceptibility Index (RSI) score, the Data Breach "
        "Impact (DBI) score, a hybrid-model financial impact estimate "
        "using Monte Carlo simulation with PERT distributions, and a "
        "prioritised remediation roadmap showing which actions would "
        "yield the greatest score improvement. Cost estimates are "
        "presented as indicative ranges to account for organisational "
        "differences in remediation complexity.",
    )

    add_bold_body(doc, "Checker Cards", "")
    add_body(
        doc,
        "The bulk of the report consists of individual checker cards, "
        "one for each of the 25+ security checks performed. Cards are "
        "grouped by category (Email Security, Network Security, Web "
        "Application Security, Reputation & Intelligence, Identity & "
        "Access, Compliance & Privacy, Insurance Analytics). Each card "
        "contains a data table with key-value findings, a 'What This "
        "Means' narrative explaining the significance of the results in "
        "plain language, and a 'Recommended Actions' list with numbered, "
        "prioritised steps. Where issues are found, the card header "
        "displays a traffic-light indicator (red, amber, or green).",
    )

    add_bold_body(doc, "Compliance Framework Mapping", "")
    add_body(
        doc,
        "A mapping table that links each finding to relevant compliance "
        "frameworks including NIST CSF 2.0, ISO 27001, PCI DSS, and "
        "POPIA. This helps organisations understand which regulatory "
        "obligations may be affected by discovered issues. Note that "
        "this mapping is based on external-only observations and does "
        "not constitute a compliance audit.",
    )

    add_bold_body(doc, "Prioritised Remediation Recommendations", "")
    add_body(
        doc,
        "A consolidated list of all recommended actions across all "
        "checker cards, sorted by priority. Priority is determined by "
        "a combination of severity, exploitability (EPSS score), "
        "potential business impact, and estimated remediation effort. "
        "Each recommendation includes a reference back to the relevant "
        "checker card for full context.",
    )

    add_bold_body(doc, "Disclaimer", "")
    add_body(
        doc,
        "The report concludes with a disclaimer clarifying that the "
        "assessment is based exclusively on externally observable data, "
        "does not constitute a penetration test or compliance audit, "
        "and that results reflect a point-in-time snapshot. Cost "
        "estimates are indicative and should be validated by the "
        "organisation's own procurement and IT teams.",
    )

    # 6.2 Broker Summary ----------------------------------------------- #
    add_h2(doc, "6.2 Broker Summary")

    add_body(
        doc,
        "The Broker Summary is a condensed 3-5 page report designed "
        "specifically for insurance brokers presenting cyber-risk "
        "findings to their clients. It strips away deep technical "
        "detail in favour of business-impact language that resonates "
        "with decision-makers.",
    )

    add_bold_body(doc, "Contents:", "")
    add_bullet(
        doc,
        "Cover Page -- branded cover with target domain, scan date, "
        "and overall risk score gauge.",
    )
    add_bullet(
        doc,
        "Executive Summary -- high-level risk posture with key metrics "
        "(overall score, critical issues, breach count, credential "
        "exposure, estimated financial impact range).",
    )
    add_bullet(
        doc,
        "Vulnerability Posture -- simplified severity breakdown focusing "
        "on critical and high-severity findings only, with plain-language "
        "explanations.",
    )
    add_bullet(
        doc,
        "Attacker's View -- abbreviated kill chain narrative highlighting "
        "the most impactful attack paths.",
    )
    add_bullet(
        doc,
        "Financial Impact Summary -- RSI score, DBI score, and hybrid-model "
        "estimated loss range presented in a broker-friendly format with "
        "clear rand-value ranges.",
    )
    add_bullet(
        doc,
        "'Why This Matters' Section -- a persuasive closing section with "
        "a call to action explaining why the client should engage further, "
        "including statistics on breach likelihood, average breach costs, "
        "and the value of proactive remediation.",
    )

    add_tip(
        doc,
        "The Broker Summary is intentionally designed to be shared with "
        "prospective clients. It contains no sensitive technical detail "
        "that could aid an attacker, making it safe for distribution "
        "outside the organisation's security team.",
    )

    # 6.3 Reading the Report ------------------------------------------- #
    add_h2(doc, "6.3 Reading the Report")

    add_bold_body(doc, "Traffic Light Indicators", "")
    add_body(
        doc,
        "Throughout both reports, findings are annotated with coloured "
        "circle indicators that provide an at-a-glance risk assessment:",
    )
    add_bullet(
        doc,
        "Green circle -- No issues found or the configuration meets "
        "best-practice standards. No action required.",
    )
    add_bullet(
        doc,
        "Amber circle -- Minor issues or partial implementation detected. "
        "Improvement is recommended but the risk is moderate.",
    )
    add_bullet(
        doc,
        "Red circle -- Significant issues found that pose a material risk. "
        "Immediate remediation is strongly recommended.",
    )

    add_bold_body(doc, "Checker Card Structure", "")
    add_body(
        doc,
        "Each checker card in the Full Technical Report follows a "
        "consistent structure:",
    )
    add_bullet(
        doc,
        "Title Bar -- contains the traffic-light indicator, the checker "
        "name, and a one-line summary of the finding (e.g., 'SPF record "
        "is valid but could be stricter').",
    )
    add_bullet(
        doc,
        "Data Table -- key-value rows showing the raw findings. For "
        "example, an SSL checker card might show rows for certificate "
        "issuer, expiry date, protocol versions supported, and cipher "
        "suite strength.",
    )
    add_bullet(
        doc,
        "Issues / Fallback Message -- if issues were found, they are "
        "listed here with severity indicators. If no issues were found, "
        "a positive confirmation message is displayed instead (e.g., "
        "'No issues detected. Configuration meets recommended standards.').",
    )
    add_bullet(
        doc,
        "'What This Means' Narrative -- a plain-language paragraph "
        "explaining the significance of the findings for a non-technical "
        "reader. This section answers the question: 'Why should I care?'",
    )
    add_bullet(
        doc,
        "'Recommended Actions' -- numbered steps the organisation should "
        "take to address any issues found. Actions are ordered by priority "
        "(highest impact first). Each action is written as a concrete, "
        "actionable instruction rather than a vague suggestion.",
    )

    add_bold_body(doc, "Recommendations & Cost Estimates", "")
    add_body(
        doc,
        "Where cost estimates are included alongside recommendations, "
        "these are indicative ranges based on typical market rates for "
        "similar remediation activities. Actual costs will vary depending "
        "on the organisation's size, existing infrastructure, vendor "
        "relationships, and internal capabilities. Cost estimates should "
        "be treated as order-of-magnitude guidance, not quotations.",
    )

    add_bold_body(doc, "Compliance Section Disclaimer", "")
    add_body(
        doc,
        "The compliance framework mapping in the report is based solely "
        "on externally observable indicators. It does not constitute a "
        "formal compliance assessment or audit. Many compliance "
        "requirements relate to internal controls, policies, and "
        "processes that cannot be evaluated through external scanning "
        "alone. Organisations should engage qualified auditors for "
        "formal compliance assessments.",
    )

    # ------------------------------------------------------------------ #
    #  SECTION 7 -- SCORING METHODOLOGY                                  #
    # ------------------------------------------------------------------ #
    add_h1(doc, "7. Scoring Methodology")

    add_body(
        doc,
        "The Phishield scanner produces a single Overall Risk Score that "
        "distils findings from all security checks into one number. This "
        "section explains how that score is calculated, how the system "
        "handles checker failures, and how to interpret scan completeness.",
    )

    # 7.1 Overall Risk Score ------------------------------------------- #
    add_h2(doc, "7.1 Overall Risk Score (0-1000)")

    add_body(
        doc,
        "The Overall Risk Score is a weighted sum of 25 individual "
        "category risk scores, where each category corresponds to a "
        "security checker or checker group. Every category produces a "
        "normalised score, and the final score is the weighted sum of "
        "all category scores, yielding a value between 0 (no identified "
        "risk) and 1000 (maximum identified risk).",
    )

    add_bold_body(doc, "Category Weights", "")
    add_body(
        doc,
        "Each category contributes a fixed percentage to the overall "
        "score. The weights reflect the relative importance of each "
        "category to the organisation's external cyber-risk posture, "
        "informed by industry threat data and insurance underwriting "
        "priorities. The weights are as follows:",
    )

    add_bullet(doc, "SSL/TLS Configuration: 9%")
    add_bullet(doc, "Exposed Admin Panels: 9%")
    add_bullet(doc, "High-Risk Protocols (open ports): 8%")
    add_bullet(doc, "Shodan CVEs (known vulnerabilities on exposed services): 7%")
    add_bullet(doc, "Breaches (HIBP breach exposure): 7%")
    add_bullet(doc, "Email Security (SPF, DKIM, DMARC): 6%")
    add_bullet(doc, "DNSBL (DNS blacklist presence): 6%")
    add_bullet(doc, "Ransomware Susceptibility Index (RSI): 6%")
    add_bullet(doc, "HTTP Security Headers: 5%")
    add_bullet(doc, "Tech Stack (outdated or EOL software): 5%")
    add_bullet(doc, "VirusTotal (domain reputation): 5%")
    add_bullet(doc, "Information Disclosure: 5%")
    add_bullet(doc, "Fraudulent Domains (typosquatting): 4%")
    add_bullet(doc, "Website Security (WAF, cookies, forms): 4%")
    add_bullet(doc, "VPN/Remote Access Exposure: 4%")
    add_bullet(doc, "External IPs (attack surface breadth): 3%")
    add_bullet(doc, "Dehashed (leaked credentials): 3%")
    add_bullet(doc, "Data Breach Impact (DBI): 3%")
    add_bullet(doc, "Email Hardening (MTA-STS, TLS-RPT, DANE, BIMI): 2%")
    add_bullet(doc, "Payment Security (PCI indicators): 2%")
    add_bullet(doc, "Privacy Policy & POPIA: 2%")
    add_bullet(doc, "Subdomains (subdomain takeover risk): 2%")
    add_bullet(doc, "Web Ranking (Tranco rank as legitimacy signal): 2%")
    add_bullet(doc, "Financial Impact (hybrid model output): 2%")
    add_bullet(doc, "SecurityTrails (historical DNS anomalies): 1%")

    add_bold_body(doc, "Score Ranges", "")
    add_body(doc, "The overall score maps to four risk bands:")
    add_bullet(doc, "Low Risk: 0 - 199")
    add_bullet(doc, "Medium Risk: 200 - 399")
    add_bullet(doc, "High Risk: 400 - 599")
    add_bullet(doc, "Critical Risk: 600 - 1000")

    add_bold_body(doc, "WAF Bonus", "")
    add_body(
        doc,
        "If the scanner detects that the target domain is protected by a "
        "Web Application Firewall (WAF), a bonus of -50 points is applied "
        "to the overall score. This reflects the significant risk reduction "
        "provided by a WAF in mitigating web application attacks. The bonus "
        "is only applied when the WAF checker completes successfully and "
        "positively identifies WAF presence.",
    )

    add_note(
        doc,
        "The WAF bonus is applied after the weighted sum is calculated. "
        "The final score is clamped to a minimum of 0 (it cannot go "
        "negative).",
    )

    # 7.2 Scoring Failsafe --------------------------------------------- #
    add_h2(doc, "7.2 Scoring Failsafe")

    add_body(
        doc,
        "In real-world scanning, individual checkers may fail due to API "
        "errors, network timeouts, or rate limiting by the target's "
        "infrastructure. The scoring failsafe mechanism ensures that a "
        "failed checker does not artificially inflate or deflate the "
        "overall score.",
    )

    add_bold_body(doc, "How It Works", "")
    add_body(
        doc,
        "When a checker fails (returns an error or times out), its weight "
        "is set to zero and the weight it would have contributed is "
        "redistributed proportionally across all checkers that completed "
        "successfully. This means the overall score is calculated using "
        "only the data that was actually collected, with the same relative "
        "proportions between successful checkers preserved.",
    )

    add_bold_body(doc, "Failure vs. Skipped Distinction", "")
    add_body(
        doc,
        "The failsafe distinguishes between two different reasons a "
        "checker might not produce results:",
    )
    add_bullet(
        doc,
        "Genuine failure (error or timeout) -- the checker attempted to "
        "run but could not complete. These are flagged with a warning "
        "indicator in the report, the checker's weight is redistributed, "
        "and a WARNING recommendation is injected advising a re-scan.",
    )
    add_bullet(
        doc,
        "Intentionally skipped (no_api_key or disabled) -- the checker "
        "was not configured to run (e.g., the Dehashed API key was not "
        "provided, or IntelX was toggled off). These are excluded from "
        "the assessable checker count entirely and do not generate a "
        "warning. The weight is still redistributed, but no warning is "
        "shown because the omission was deliberate.",
    )

    add_warning(
        doc,
        "When checkers fail, the overall score may be less reliable "
        "because it is based on incomplete data. The scan completeness "
        "percentage (see Section 7.3) quantifies this. Always review "
        "the completeness indicator before relying on the score for "
        "underwriting or remediation decisions.",
    )

    # 7.3 Scan Completeness -------------------------------------------- #
    add_h2(doc, "7.3 Scan Completeness")

    add_body(
        doc,
        "Scan completeness is expressed as a percentage and indicates "
        "how much of the intended assessment was successfully completed.",
    )

    add_bold_body(doc, "Formula:", "")
    add_body(
        doc,
        "Completeness % = (Assessable - Failed) / Assessable x 100",
    )

    add_body(
        doc,
        "Where 'Assessable' is the number of checkers that were "
        "configured to run (i.e., total checkers minus those skipped "
        "due to missing API keys or being disabled), and 'Failed' is "
        "the number of assessable checkers that returned an error or "
        "timed out.",
    )

    add_bullet(
        doc,
        "Checkers skipped because of no_api_key or disabled status are "
        "excluded from the assessable count entirely. They do not reduce "
        "the completeness percentage.",
    )
    add_bullet(
        doc,
        "Failed checkers are listed by name in the report so the user "
        "can identify which data sources were unavailable.",
    )
    add_bullet(
        doc,
        "When one or more checkers fail, a WARNING recommendation is "
        "automatically injected at the top of the prioritised "
        "recommendations list advising the user to re-scan to obtain "
        "complete results.",
    )

    add_tip(
        doc,
        "A completeness of 100% means every configured checker ran "
        "successfully. If completeness drops below 80%, consider "
        "re-scanning after a short delay -- transient API issues or "
        "rate limiting may have resolved.",
    )

    # 7.4 Score Reliability -------------------------------------------- #
    add_h2(doc, "7.4 Score Reliability")

    add_body(
        doc,
        "While the Overall Risk Score provides a useful snapshot, several "
        "conditions can reduce its reliability. A re-scan is recommended "
        "when any of the following apply:",
    )

    add_bullet(
        doc,
        "Scan completeness is below 100% -- one or more checkers failed, "
        "meaning the score is based on incomplete data. The missing "
        "checkers may have detected additional risks or confirmed that "
        "certain controls are in place.",
    )
    add_bullet(
        doc,
        "HTTPS was unreachable during the scan -- several checkers "
        "(HTTP headers, WAF detection, tech stack fingerprinting, "
        "privacy policy analysis, admin panel discovery) depend on "
        "being able to fetch the target's website over HTTPS. If the "
        "target site was temporarily down or blocking the scanner's IP, "
        "these checkers will fail. Verify that the target site is "
        "accessible before re-scanning.",
    )
    add_bullet(
        doc,
        "Significant time has passed since the last scan -- because "
        "results reflect a point-in-time snapshot, scores can become "
        "stale as the target's infrastructure changes, new "
        "vulnerabilities are disclosed, or new breaches are reported. "
        "Regular re-scanning (monthly at minimum) is recommended.",
    )
    add_bullet(
        doc,
        "Remediation has been applied -- after the target organisation "
        "addresses findings from a previous scan, a fresh scan should "
        "be performed to verify that remediation was effective and to "
        "update the score accordingly.",
    )

    add_note(
        doc,
        "The score is a risk indicator, not an absolute measure of "
        "security. A low score does not guarantee the absence of "
        "vulnerabilities -- it indicates that no significant external "
        "risks were detected by the checks performed.",
    )

    # ------------------------------------------------------------------ #
    #  SECTION 8 -- API INTEGRATIONS & DATA SOURCES                      #
    # ------------------------------------------------------------------ #
    add_h1(doc, "8. API Integrations & Data Sources")

    add_body(
        doc,
        "The Phishield scanner aggregates data from multiple external "
        "intelligence sources to build a comprehensive view of the "
        "target's external risk posture. The table below lists every "
        "data source, its cost model, what it provides, and whether it "
        "can be toggled on or off.",
    )

    # Shodan
    add_bold_body(doc, "Shodan (InternetDB + Full API)", "")
    add_bullet(doc, "Type: Port scanning, service detection, CVE lookup")
    add_bullet(doc, "Cost: Paid (API key required)")
    add_bullet(
        doc,
        "What It Provides: Discovers open ports and running services on "
        "the target's IP addresses using the free InternetDB endpoint. "
        "When a paid Shodan API key is configured, full banner data and "
        "CVE associations are retrieved, enabling precise vulnerability "
        "mapping against CISA KEV and EPSS databases.",
    )
    add_bullet(doc, "Toggle: Always on (InternetDB is free; full API requires key)")

    # VirusTotal
    add_bold_body(doc, "VirusTotal", "")
    add_bullet(doc, "Type: Domain reputation analysis")
    add_bullet(doc, "Cost: Free tier (API key required)")
    add_bullet(
        doc,
        "What It Provides: Submits the target domain to 70+ security "
        "engines and aggregates their verdicts. Detects malware hosting, "
        "phishing associations, suspicious redirects, and known malicious "
        "activity linked to the domain.",
    )
    add_bullet(doc, "Toggle: Always on")

    # SecurityTrails
    add_bold_body(doc, "SecurityTrails", "")
    add_bullet(doc, "Type: Historical DNS intelligence")
    add_bullet(doc, "Cost: Free tier (API key required)")
    add_bullet(
        doc,
        "What It Provides: Historical DNS records, associated domains, "
        "and subdomain enumeration. Reveals infrastructure changes over "
        "time, identifies related domains that may share risk, and "
        "discovers subdomains that could represent an expanded attack "
        "surface.",
    )
    add_bullet(doc, "Toggle: Always on")

    # Dehashed
    add_bold_body(doc, "Dehashed", "")
    add_bullet(doc, "Type: Credential leak database")
    add_bullet(doc, "Cost: Paid (credit-based)")
    add_bullet(
        doc,
        "What It Provides: Searches for leaked credentials (email "
        "addresses, passwords, password hashes) associated with the "
        "target domain across known breach datasets. Returns the number "
        "of exposed credentials, the types of data leaked (plaintext "
        "passwords, hashed passwords, usernames), and the sources where "
        "they appeared.",
    )
    add_bullet(doc, "Toggle: Yes (can be disabled to conserve credits)")

    # Hudson Rock
    add_bold_body(doc, "Hudson Rock", "")
    add_bullet(doc, "Type: Active infostealer detection")
    add_bullet(doc, "Cost: Free (no API key needed)")
    add_bullet(
        doc,
        "What It Provides: Detects whether employees of the target "
        "organisation have been compromised by active infostealer "
        "malware. Returns the number of infected machines, compromised "
        "credentials, and affected third-party services. This data "
        "represents an immediate, active threat rather than historical "
        "breach data.",
    )
    add_bullet(doc, "Toggle: Always on")

    # IntelX
    add_bold_body(doc, "IntelX (Intelligence X)", "")
    add_bullet(doc, "Type: Dark web monitoring, paste sites, leak databases")
    add_bullet(doc, "Cost: Paid (credit-based)")
    add_bullet(
        doc,
        "What It Provides: Searches the dark web, paste sites (such as "
        "Pastebin), and underground forums for mentions of the target "
        "domain, email addresses, and credentials. Provides visibility "
        "into data that has been shared or sold in criminal marketplaces.",
    )
    add_bullet(doc, "Toggle: Yes (can be disabled to conserve credits)")

    # HIBP
    add_bold_body(doc, "Have I Been Pwned (HIBP)", "")
    add_bullet(doc, "Type: Breach metadata")
    add_bullet(doc, "Cost: Free")
    add_bullet(
        doc,
        "What It Provides: Returns metadata about known data breaches "
        "affecting the target domain, including breach dates, the types "
        "of data exposed (emails, passwords, financial data, personal "
        "information), and the number of affected accounts. Does not "
        "return actual breach data -- only metadata about the breaches.",
    )
    add_bullet(doc, "Toggle: Always on")

    # CISA KEV
    add_bold_body(doc, "CISA KEV (Known Exploited Vulnerabilities)", "")
    add_bullet(doc, "Type: Vulnerability intelligence")
    add_bullet(doc, "Cost: Free")
    add_bullet(
        doc,
        "What It Provides: Cross-references CVEs discovered by Shodan "
        "against CISA's catalog of vulnerabilities known to be actively "
        "exploited in the wild. CVEs on this list represent an immediate, "
        "confirmed threat and are flagged with the highest priority in "
        "the report.",
    )
    add_bullet(doc, "Toggle: Always on")

    # FIRST.org EPSS
    add_bold_body(doc, "FIRST.org EPSS (Exploit Prediction Scoring System)", "")
    add_bullet(doc, "Type: Vulnerability exploitation probability")
    add_bullet(doc, "Cost: Free")
    add_bullet(
        doc,
        "What It Provides: For each CVE discovered, EPSS provides a "
        "probability score (0-1) indicating the likelihood that the "
        "vulnerability will be exploited in the wild within the next "
        "30 days. This helps prioritise remediation by focusing on "
        "vulnerabilities most likely to be exploited, not just those "
        "with the highest CVSS severity score.",
    )
    add_bullet(doc, "Toggle: Always on")

    # OSV.dev
    add_bold_body(doc, "OSV.dev", "")
    add_bullet(doc, "Type: Version-to-vulnerability matching")
    add_bullet(doc, "Cost: Free")
    add_bullet(
        doc,
        "What It Provides: Maps detected software versions (identified "
        "by the tech stack fingerprinter) to known vulnerabilities in "
        "Google's Open Source Vulnerability database. Useful for "
        "identifying risks in open-source components such as WordPress "
        "plugins, JavaScript libraries, and server software where the "
        "version number is externally visible.",
    )
    add_bullet(doc, "Toggle: Always on")

    add_note(
        doc,
        "API keys are configured in the scanner's environment file. "
        "Toggling a paid API off does not affect the scan -- the "
        "checker is simply skipped and its weight is redistributed "
        "across the remaining checkers (see Section 7.2).",
    )

    # ------------------------------------------------------------------ #
    #  SECTION 9 -- KNOWN LIMITATIONS & PLANNED IMPROVEMENTS             #
    # ------------------------------------------------------------------ #
    add_h1(doc, "9. Known Limitations & Planned Improvements")

    add_body(
        doc,
        "The Phishield scanner is a powerful external reconnaissance "
        "tool, but like all security assessment tools it operates within "
        "certain constraints. Understanding these limitations is "
        "essential for interpreting results correctly and setting "
        "appropriate expectations.",
    )

    add_bold_body(doc, "External-Only Scanning", "")
    add_body(
        doc,
        "The scanner assesses only the externally visible attack surface "
        "of the target domain. It cannot evaluate internal network "
        "security, employee security awareness training, incident "
        "response plans, endpoint protection coverage, or internal "
        "access controls. A comprehensive cyber-risk assessment should "
        "complement Phishield results with internal assessments.",
    )

    add_bold_body(doc, "Point-in-Time Results", "")
    add_body(
        doc,
        "Scan results reflect the target's posture at the exact moment "
        "the scan was performed. Infrastructure changes, new vulnerability "
        "disclosures, or fresh breach events occurring after the scan "
        "will not be reflected until the next scan. For organisations "
        "with dynamic infrastructure, regular re-scanning is strongly "
        "recommended.",
    )

    add_bold_body(doc, "Scan Duration", "")
    add_body(
        doc,
        "A typical scan takes between 5 and 18 minutes depending on "
        "the target's complexity (number of IPs, subdomains, and "
        "responsiveness of external APIs). An optimisation roadmap "
        "exists to achieve sub-2-minute monitoring re-scans by caching "
        "baseline data and only re-checking elements that are likely "
        "to have changed.",
    )

    add_bold_body(doc, "OSV.dev API Reliability", "")
    add_body(
        doc,
        "The OSV.dev vulnerability database API intermittently returns "
        "empty results for valid software version queries. This can "
        "cause the tech stack checker to underreport vulnerabilities "
        "in detected software. Retry logic and local caching of "
        "previously successful lookups are planned improvements.",
    )

    add_bold_body(doc, "Rate Limiting by Target Infrastructure", "")
    add_body(
        doc,
        "Repeated scans of the same target in a short period may trigger "
        "the target's firewall or intrusion prevention system to block "
        "the scanner's IP address. This has been observed particularly "
        "with hosting providers such as Hetzner. If a scan returns "
        "unexpectedly sparse results, wait at least 30 minutes before "
        "re-scanning.",
    )

    add_bold_body(doc, "HTTPS Dependency", "")
    add_body(
        doc,
        "Several checkers depend on fetching the target's website over "
        "HTTPS, including HTTP security headers, WAF detection, tech "
        "stack fingerprinting, privacy policy analysis, and admin panel "
        "discovery. If the target's HTTPS endpoint is unreachable "
        "(due to downtime, IP blocking, or misconfiguration), these "
        "checkers will fail and their results will be absent from the "
        "report. The scan completeness percentage will reflect this.",
    )

    add_bold_body(doc, "CDN Masking", "")
    add_body(
        doc,
        "Targets that sit behind CDN providers such as Cloudflare "
        "present the CDN's IP addresses rather than the origin server's "
        "IP addresses. This means Shodan data will reflect the CDN "
        "infrastructure rather than the actual target servers, "
        "potentially masking vulnerabilities on the origin server. "
        "The scanner notes when CDN presence is detected and adjusts "
        "interpretations accordingly.",
    )

    add_bold_body(doc, "Full Roadmap Reference", "")
    add_body(
        doc,
        "A detailed gap analysis document tracks all planned "
        "improvements across Phases 4 through 6, including enhanced "
        "port scanning depth, technology fingerprinting improvements, "
        "continuous monitoring capabilities, and broker API integration. "
        "Contact Phishield support for access to the current roadmap.",
    )

    # ------------------------------------------------------------------ #
    #  SECTION 10 -- GLOSSARY                                            #
    # ------------------------------------------------------------------ #
    add_h1(doc, "10. Glossary")

    add_body(
        doc,
        "This glossary defines technical terms used throughout the "
        "Phishield scanner reports and this manual. Definitions are "
        "written for a non-technical audience.",
    )

    _glossary = [
        (
            "AXFR (DNS Zone Transfer)",
            "A mechanism for replicating DNS records between servers. If "
            "misconfigured, it allows anyone to download a complete list of "
            "all DNS records for a domain, revealing internal hostnames and "
            "network structure.",
        ),
        (
            "BEC (Business Email Compromise)",
            "A type of fraud where an attacker impersonates a trusted person "
            "(such as a CEO or supplier) via email to trick employees into "
            "transferring money or sharing sensitive information.",
        ),
        (
            "BIMI (Brand Indicators for Message Identification)",
            "A standard that allows organisations to display their brand logo "
            "next to authenticated emails in recipients' inboxes. Requires "
            "DMARC enforcement and a verified logo certificate.",
        ),
        (
            "CAA (Certificate Authority Authorization)",
            "A DNS record that specifies which certificate authorities are "
            "permitted to issue SSL/TLS certificates for a domain. Prevents "
            "unauthorised certificate issuance.",
        ),
        (
            "CDN (Content Delivery Network)",
            "A globally distributed network of servers that caches and "
            "delivers website content from locations close to the user, "
            "improving performance and providing a layer of protection "
            "against direct attacks on the origin server.",
        ),
        (
            "CNAME (Canonical Name Record)",
            "A DNS record that maps one domain name to another. Used for "
            "aliasing subdomains to other services. A dangling CNAME "
            "(pointing to a decommissioned service) can enable subdomain "
            "takeover attacks.",
        ),
        (
            "Credential Stuffing",
            "An automated attack that uses leaked username-password pairs "
            "from one breach to attempt login on other websites, exploiting "
            "the common practice of password reuse.",
        ),
        (
            "CSP (Content Security Policy)",
            "An HTTP security header that tells browsers which sources of "
            "content (scripts, stylesheets, images) are permitted on a web "
            "page. A strong CSP significantly reduces the risk of cross-site "
            "scripting (XSS) attacks.",
        ),
        (
            "CVE (Common Vulnerabilities and Exposures)",
            "A standardised identifier (e.g., CVE-2024-12345) assigned to a "
            "publicly known security vulnerability. CVEs enable consistent "
            "tracking and communication about specific vulnerabilities "
            "across tools and organisations.",
        ),
        (
            "CVSS (Common Vulnerability Scoring System)",
            "A numerical scoring system (0-10) that rates the severity of "
            "security vulnerabilities. Scores are categorised as Low "
            "(0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), and Critical "
            "(9.0-10.0).",
        ),
        (
            "DANE (DNS-based Authentication of Named Entities)",
            "A protocol that uses DNS records (TLSA) to associate a domain's "
            "TLS certificate with its DNS name, providing an additional "
            "layer of certificate verification independent of certificate "
            "authorities.",
        ),
        (
            "DBI (Data Breach Impact Score)",
            "A Phishield metric that estimates the potential impact of a "
            "data breach on the target organisation, based on the volume "
            "and sensitivity of exposed data, the recency of breaches, "
            "and the presence of active threats such as infostealers.",
        ),
        (
            "DKIM (DomainKeys Identified Mail)",
            "An email authentication method that uses cryptographic "
            "signatures to verify that an email was sent by the domain "
            "it claims to be from and was not altered in transit.",
        ),
        (
            "DMARC (Domain-based Message Authentication, Reporting & Conformance)",
            "An email authentication policy that builds on SPF and DKIM. "
            "It tells receiving mail servers what to do with emails that "
            "fail authentication (none, quarantine, or reject) and provides "
            "reporting on authentication results.",
        ),
        (
            "DNS (Domain Name System)",
            "The internet's address book. DNS translates human-readable "
            "domain names (e.g., example.co.za) into numerical IP addresses "
            "that computers use to locate servers on the internet.",
        ),
        (
            "DNSBL (DNS-based Blackhole List)",
            "A list of IP addresses and domains that have been identified "
            "as sources of spam or malicious activity. If a domain appears "
            "on a DNSBL, its emails may be blocked or flagged by recipients' "
            "mail servers.",
        ),
        (
            "EOL (End of Life)",
            "The date after which a software product no longer receives "
            "security patches or support from its vendor. Running EOL "
            "software exposes the organisation to unpatched vulnerabilities.",
        ),
        (
            "EPSS (Exploit Prediction Scoring System)",
            "A model maintained by FIRST.org that estimates the probability "
            "(0-100%) that a given CVE will be exploited in the wild within "
            "the next 30 days. Helps prioritise patching by likelihood of "
            "exploitation rather than severity alone.",
        ),
        (
            "Hybrid Financial Impact Model (derived from FAIR)",
            "A quantitative risk analysis model that expresses cyber risk "
            "in financial terms. The Phishield scanner uses a hybrid "
            "approach derived from FAIR principles, anchored to IBM SA "
            "breach cost data and calibrated with Sophos SA 2025 and "
            "actual insurance claims data.",
        ),
        (
            "HSTS (HTTP Strict Transport Security)",
            "An HTTP header that instructs browsers to only connect to the "
            "website over HTTPS, preventing downgrade attacks that could "
            "intercept traffic over unencrypted HTTP.",
        ),
        (
            "Infostealer",
            "A type of malware that silently captures passwords, browser "
            "cookies, cryptocurrency wallets, and other sensitive data from "
            "infected computers and sends it to attackers. Infostealers "
            "represent an active, ongoing compromise.",
        ),
        (
            "ISO 27001",
            "An international standard for information security management "
            "systems (ISMS). It provides a systematic approach to managing "
            "sensitive information through policies, processes, and controls.",
        ),
        (
            "KEV (Known Exploited Vulnerabilities)",
            "A catalog maintained by CISA (the U.S. Cybersecurity and "
            "Infrastructure Security Agency) listing CVEs that are confirmed "
            "to have been exploited in real-world attacks. Presence on this "
            "list indicates an urgent patching priority.",
        ),
        (
            "Monte Carlo Simulation",
            "A statistical technique that runs thousands of random "
            "simulations to estimate a range of possible outcomes. The "
            "Phishield scanner uses it to estimate financial impact ranges "
            "for potential cyber incidents.",
        ),
        (
            "MTA-STS (Mail Transfer Agent Strict Transport Security)",
            "A standard that enables a domain to declare that it supports "
            "encrypted email delivery (TLS) and that sending servers should "
            "refuse to deliver email if encryption cannot be established.",
        ),
        (
            "NIST CSF 2.0 (National Institute of Standards and Technology "
            "Cybersecurity Framework version 2.0)",
            "A widely adopted cybersecurity framework organised around six "
            "functions: Govern, Identify, Protect, Detect, Respond, and "
            "Recover. Used as a reference for mapping security findings to "
            "best-practice controls.",
        ),
        (
            "OCSP (Online Certificate Status Protocol)",
            "A protocol used to check in real time whether an SSL/TLS "
            "certificate has been revoked by its certificate authority. "
            "Ensures that browsers and servers are not trusting compromised "
            "certificates.",
        ),
        (
            "PCI DSS (Payment Card Industry Data Security Standard)",
            "A set of security standards for organisations that handle "
            "credit card data. Compliance is required for any business "
            "that processes, stores, or transmits cardholder data.",
        ),
        (
            "PERT Distribution",
            "A probability distribution used in the hybrid financial impact model to represent "
            "uncertain values with a minimum, most likely, and maximum "
            "estimate. It produces more realistic estimates than simple "
            "averages by weighting the most likely value more heavily.",
        ),
        (
            "Phishing",
            "A social engineering attack where fraudulent emails, messages, "
            "or websites impersonate trusted entities to trick people into "
            "revealing sensitive information such as passwords or financial "
            "details.",
        ),
        (
            "POPIA (Protection of Personal Information Act)",
            "South Africa's data protection legislation that governs the "
            "collection, processing, and storage of personal information. "
            "Organisations must comply with POPIA requirements to protect "
            "individuals' personal data.",
        ),
        (
            "Privacy Policy",
            "A statement on a website that discloses how the organisation "
            "collects, uses, stores, and protects visitors' personal "
            "information. Required by POPIA and other data protection "
            "regulations.",
        ),
        (
            "Ransomware",
            "Malicious software that encrypts a victim's files or systems "
            "and demands payment (a ransom) for the decryption key. "
            "Ransomware attacks can halt business operations entirely and "
            "often involve data exfiltration for additional extortion.",
        ),
        (
            "RDP (Remote Desktop Protocol)",
            "A Microsoft protocol that allows remote access to a computer's "
            "desktop. Exposed RDP services are a top target for attackers "
            "because they provide direct interactive access to systems.",
        ),
        (
            "RSI (Ransomware Susceptibility Index)",
            "A Phishield metric that estimates how susceptible the target "
            "organisation is to a ransomware attack, based on exposed "
            "services, known vulnerabilities, email security posture, "
            "and credential exposure.",
        ),
        (
            "SPF (Sender Policy Framework)",
            "An email authentication standard that specifies which mail "
            "servers are authorised to send email on behalf of a domain. "
            "Helps prevent email spoofing by allowing recipients to verify "
            "the sender's legitimacy.",
        ),
        (
            "SSL/TLS (Secure Sockets Layer / Transport Layer Security)",
            "Cryptographic protocols that encrypt communication between "
            "a web browser and a server. TLS is the modern successor to "
            "SSL. A valid TLS certificate is essential for secure HTTPS "
            "connections.",
        ),
        (
            "TLS-RPT (TLS Reporting)",
            "A standard that allows domains to receive reports about "
            "failures in TLS-encrypted email delivery. Helps domain "
            "owners identify and troubleshoot email encryption issues.",
        ),
        (
            "Typosquatting",
            "The registration of domain names that are slight misspellings "
            "or variations of a legitimate domain (e.g., examp1e.com "
            "instead of example.com). Used for phishing, brand abuse, "
            "or traffic interception.",
        ),
        (
            "VPN (Virtual Private Network)",
            "A technology that creates an encrypted tunnel between a user's "
            "device and a remote network. Exposed VPN login portals can be "
            "targeted by credential stuffing or vulnerability exploitation.",
        ),
        (
            "WAF (Web Application Firewall)",
            "A security system that monitors and filters HTTP traffic "
            "between the internet and a web application. WAFs protect "
            "against common web attacks such as SQL injection, cross-site "
            "scripting, and DDoS attacks.",
        ),
        (
            "Zero-day",
            "A vulnerability that is unknown to the software vendor and "
            "for which no patch exists. Zero-day vulnerabilities are "
            "particularly dangerous because there is no available fix "
            "at the time of discovery or exploitation.",
        ),
    ]

    for term, definition in _glossary:
        add_bold_body(doc, term, "")
        add_body(doc, definition)

    # ------------------------------------------------------------------ #
    #  SECTION 11 -- VERSION HISTORY                                     #
    # ------------------------------------------------------------------ #
    add_h1(doc, "11. Version History")

    add_bold_body(doc, "v1.0 -- April 2026", "Initial Release")
    add_body(
        doc,
        "First public release of the Phishield Cyber Risk Scanner User "
        "Manual, covering all scanner capabilities delivered through "
        "Phase 3 implementation. This version includes:",
    )
    add_bullet(
        doc,
        "Detailed explanations of all 25+ security checkers across six "
        "categories (Email Security, Network Security, Web Application "
        "Security, Reputation & Intelligence, Identity & Access, "
        "Compliance & Privacy).",
    )
    add_bullet(
        doc,
        "Insurance analytics methodology documentation including RSI, "
        "DBI, hybrid financial impact model with Monte Carlo simulation, and the "
        "remediation roadmap generation logic.",
    )
    add_bullet(
        doc,
        "Complete scoring methodology with category weights, failsafe "
        "behaviour, scan completeness calculation, and score reliability "
        "guidance.",
    )
    add_bullet(
        doc,
        "API integration guide covering all ten external data sources "
        "with cost models, data provided, and toggle availability.",
    )
    add_bullet(
        doc,
        "PDF report format documentation for both the Full Technical "
        "Report and Broker Summary, including guidance on reading and "
        "interpreting report content.",
    )
    add_bullet(
        doc,
        "Known limitations and planned improvements referencing the "
        "Phase 4-6 roadmap.",
    )
    add_bullet(
        doc,
        "Comprehensive glossary of 40+ technical terms written for "
        "non-technical readers.",
    )
