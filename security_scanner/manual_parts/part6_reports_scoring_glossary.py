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
        "The phases are: (1) Reconnaissance, what an attacker can learn "
        "from publicly available information about the target, "
        "(2) Weaponisation, how discovered vulnerabilities and leaked "
        "credentials could be combined into an attack toolkit, "
        "(3) Delivery & Exploitation, the most likely attack vectors "
        "such as phishing with leaked credentials, exploiting unpatched "
        "services, or abusing misconfigured email authentication, and "
        "(4) Impact, the realistic business consequences including "
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
        "using a 50,000-iteration Monte Carlo simulation with PERT "
        "distributions and a Generalised Pareto tail fit for catastrophe "
        "return periods, a Loss Exposure Scenarios table presenting "
        "Most Likely / Median / 1-in-100 / 1-in-200 / 1-in-250 outcomes "
        "for FAIS-compliant cover-sizing discussion, a Civil Liability "
        "Disclosure flagging uncapped POPIA Section 99 / common-law "
        "delict exposure, a Regulatory Flag Audit trail showing broker "
        "input versus pre-flight auto-detection per flag, a Scan "
        "Duration Profile showing per-checker wall-time, and a "
        "prioritised remediation roadmap showing which actions would "
        "yield the greatest score improvement. The report intentionally "
        "does NOT present a Recommended Cover Limit figure - cover "
        "sizing is a broker / client decision informed by the Loss "
        "Exposure Scenarios.",
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
        "Cover Page, branded cover with target domain, scan date, "
        "and overall risk score gauge.",
    )
    add_bullet(
        doc,
        "Executive Summary, high-level risk posture with key metrics "
        "(overall score, critical issues, breach count, credential "
        "exposure, estimated financial impact range).",
    )
    add_bullet(
        doc,
        "Vulnerability Posture, simplified severity breakdown focusing "
        "on critical and high-severity findings only, with plain-language "
        "explanations.",
    )
    add_bullet(
        doc,
        "Attacker's View, abbreviated kill chain narrative highlighting "
        "the most impactful attack paths.",
    )
    add_bullet(
        doc,
        "Financial Impact Summary, RSI score, DBI score, and hybrid-model "
        "estimated loss range presented in a broker-friendly format with "
        "clear rand-value ranges.",
    )
    add_bullet(
        doc,
        "'Why This Matters' Section, a persuasive closing section with "
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
        "Green circle: No issues found or the configuration meets "
        "best-practice standards. No action required.",
    )
    add_bullet(
        doc,
        "Amber circle: Minor issues or partial implementation detected. "
        "Improvement is recommended but the risk is moderate.",
    )
    add_bullet(
        doc,
        "Red circle: Significant issues found that pose a material risk. "
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
        "Title Bar, contains the traffic-light indicator, the checker "
        "name, and a one-line summary of the finding (e.g., 'SPF record "
        "is valid but could be stricter').",
    )
    add_bullet(
        doc,
        "Data Table, key-value rows showing the raw findings. For "
        "example, an SSL checker card might show rows for certificate "
        "issuer, expiry date, protocol versions supported, and cipher "
        "suite strength.",
    )
    add_bullet(
        doc,
        "Issues / Fallback Message, if issues were found, they are "
        "listed here with severity indicators. If no issues were found, "
        "a positive confirmation message is displayed instead (e.g., "
        "'No issues detected. Configuration meets recommended standards.').",
    )
    add_bullet(
        doc,
        "'What This Means' Narrative, a plain-language paragraph "
        "explaining the significance of the findings for a non-technical "
        "reader. This section answers the question: 'Why should I care?'",
    )
    add_bullet(
        doc,
        "'Recommended Actions', numbered steps the organisation should "
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

    # 6.4 Sensitive Credential Disclosure & Encrypted Export ----------- #
    add_h2(doc, "6.4 Sensitive Credential Disclosure & Encrypted Export")

    add_body(
        doc,
        "The scanner surfaces leaked credentials (DeHashed), active "
        "infostealer infections (Hudson Rock, with infection dates), and "
        "dark-web / forum circulation (IntelX or replacement). Because this "
        "is sensitive personal information, it is disclosed in TIERS by "
        "audience, and the complete unmasked detail, including the actual "
        "passwords, is delivered only on request, with the client's signed "
        "consent, as an encrypted file. This exposure is already circulating "
        "in the public / criminal domain; the scanner re-surfaces it solely so "
        "the organisation can remediate (force resets, enforce MFA).",
    )

    add_bold_body(doc, "Tiered disclosure: ", "what each output shows.")
    add_bullet(doc, "Executive Deck: counts only (number of exposed accounts, infected devices, services). No identifiers.")
    add_bullet(doc, "Broker Summary: 2-3 partially-masked example accounts / services plus summarised counts. No passwords.")
    add_bullet(doc, "Full Technical Report: enumerated, partially-masked accounts, a per-service summary, infection dates, and stealer families. No passwords.")
    add_bullet(doc, "Encrypted Credential Export (on request): the complete list INCLUDING actual passwords, delivered as an encrypted file after signed client consent. Never stored on the scanner; generated on demand.")

    add_body(
        doc,
        "Masking uses a partial reveal (first two plus last character of the "
        "local part, e.g. 'jo***n@example.com') so the organisation can "
        "recognise its own accounts, demonstrating the findings are real, "
        "while an outsider cannot reconstruct them.",
    )

    add_bold_body(
        doc,
        "Export file format, date-clustered, with a confidence column: ",
        "The encrypted CSV is sorted newest-first and carries the same recency "
        "clustering the dashboard shows, so the client can act on the freshest "
        "circulation first. Columns: record_type, source, date, recency_band, "
        "match_type, confidence, email, username, password, hashed_password, "
        "note. Two record types appear in the one file: 'credential' (a DeHashed "
        "leak record, which may include a password) and 'leak_reference' (an "
        "IntelX stealer-log posting that references the domain). Each credential "
        "inherits its source's breach-date guesstimate and recency band; note "
        "that this is a per-SOURCE date, not a per-record date (DeHashed records "
        "carry no reliable individual date).",
    )

    add_bold_body(
        doc,
        "The confidence column, and why it governs breach-probability decisions: ",
        "Not every hit is a stolen credential, and the confidence column makes "
        "that explicit. HIGH = a secret was actually captured (a plaintext "
        "password, or an Autofill / Passwords / credit-card store in a stealer "
        "log). MEDIUM = session data (cookies) or a hashed password. LOW = the "
        "site was merely referenced (a browser-History entry) or the domain "
        "appears in an aggregated multi-domain dump that lists thousands of "
        "sites. The distinction is decisive for underwriting: a LOW-confidence "
        "match is a MONITORING signal, not evidence of compromise, and should "
        "NOT on its own be read as raising the breach probability. To act on a "
        "low-confidence hit, or to justify any uplift to the probability of "
        "breach / RSI, request a content-fetch of the specific named dump to "
        "confirm whether a phishield credential (not just a visited URL) was "
        "actually exposed.",
    )

    add_note(
        doc,
        "Worked example: a domain may show recent (30-90 day) leak references "
        "that are ALL low-confidence (aggregated indexes plus a single browser-"
        "History entry), while its only high-confidence rows are years-old "
        "password records from a re-circulated combo list. The honest reading "
        "is 'recently CIRCULATING, but no fresh high-confidence theft', the "
        "catastrophe model is unaffected, but the probability-of-breach input "
        "should not be inflated by the low-confidence freshness alone.",
    )

    add_bold_body(doc, "Operator workflow (broker / scanner user): ", "")
    add_bullet(doc, "1. Obtain the client's SIGNED CONSENT form and upload it, this is the authorisation gate and the FAIS / POPIA audit trail.")
    add_bullet(doc, "2. Obtain the client's age PUBLIC key (the client generates it, see below). A public key is safe to share openly.")
    add_bullet(doc, "3. Trigger the export. The scanner re-queries DeHashed at that moment, builds the CSV, and encrypts it to the client's public key with age. No passwords are written to the scanner database.")
    add_bullet(doc, "4. Share the one-time, expiring download link with the client. The encrypted file is deleted after download or expiry.")
    add_bullet(doc, "5. Fallback if the client cannot use age keys: the scanner produces an AES-256 password-protected file; send the passphrase via a SEPARATE secure channel (never the same channel as the link).")

    add_bold_body(doc, "Client guide, one-time setup (age, recommended): ", "")
    add_bullet(doc, "Install age (a small, free, cross-platform tool: github.com/FiloSottile/age).")
    add_bullet(doc, "Generate a keypair: run 'age-keygen -o key.txt'. This prints your PUBLIC key (starts with 'age1...') and writes your PRIVATE key to key.txt.")
    add_bullet(doc, "Send ONLY the public key (the 'age1...' line) to your broker. Keep key.txt (the private key) secret and backed up, without it the file cannot be opened.")

    add_bold_body(doc, "Client guide, retrieve & decrypt: ", "")
    add_bullet(doc, "Open the one-time link within its expiry window and download the '.age' file.")
    add_bullet(doc, "Decrypt: 'age -d -i key.txt -o credentials.csv credentials.csv.age'. The result is the plain CSV.")
    add_bullet(doc, "AES fallback: receive the passphrase from your broker via a separate channel, then open the file with 7-Zip (AES-256) or 'openssl enc -d -aes-256-cbc -in file.enc -out credentials.csv'.")

    add_warning(
        doc,
        "The encrypted export contains live passwords, treat it like any "
        "breach dump. Decrypt only on a secure workstation, action the password "
        "resets and MFA enrolment, then securely delete the file. The scanner "
        "itself never stores passwords, and none of the rendered reports (deck, "
        "broker summary, full report) ever contain passwords.",
    )

    add_note(
        doc,
        "Why public-key (age) over a shared password: with age, only the "
        "client's private key, which never leaves them, can decrypt the "
        "file, so there is no secret to intercept in transit. A shared AES "
        "passphrase is offered only as a fallback and must travel on a channel "
        "separate from the file.",
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
        "Web Application Firewall (WAF), a bonus of up to -50 points is "
        "applied to the overall score. This reflects the significant risk "
        "reduction provided by a WAF in mitigating web application attacks. "
        "The bonus is only applied when the WAF checker completes "
        "successfully and positively identifies WAF presence.",
    )
    add_body(
        doc,
        "The bonus is discounted to -25 points when the same WAF / "
        "bot-manager actively blinded the scan (sustained 403 / 406 / 451 "
        "blocking, a challenge page, or probe timeouts). In that case the "
        "target would otherwise be credited twice: once for the genuine "
        "web-layer control, and again because the blinded path-prober "
        "checkers return falsely clean results. The blindness is an "
        "artefact of the defensive posture, not measured security, so only "
        "half the credit is banked.",
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
        "Genuine failure (error or timeout), the checker attempted to "
        "run but could not complete. These are flagged with a warning "
        "indicator in the report, the checker's weight is redistributed, "
        "and a WARNING recommendation is injected advising a re-scan.",
    )
    add_bullet(
        doc,
        "Intentionally skipped (no_api_key or disabled), the checker "
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
        "re-scanning after a short delay, transient API issues or "
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
        "Scan completeness is below 100%, one or more checkers failed, "
        "meaning the score is based on incomplete data. The missing "
        "checkers may have detected additional risks or confirmed that "
        "certain controls are in place.",
    )
    add_bullet(
        doc,
        "HTTPS was unreachable during the scan, several checkers "
        "(HTTP headers, WAF detection, tech stack fingerprinting, "
        "privacy policy analysis, admin panel discovery) depend on "
        "being able to fetch the target's website over HTTPS. If the "
        "target site was temporarily down or blocking the scanner's IP, "
        "these checkers will fail. Verify that the target site is "
        "accessible before re-scanning.",
    )
    add_bullet(
        doc,
        "Significant time has passed since the last scan, because "
        "results reflect a point-in-time snapshot, scores can become "
        "stale as the target's infrastructure changes, new "
        "vulnerabilities are disclosed, or new breaches are reported. "
        "Regular re-scanning (monthly at minimum) is recommended.",
    )
    add_bullet(
        doc,
        "Remediation has been applied, after the target organisation "
        "addresses findings from a previous scan, a fresh scan should "
        "be performed to verify that remediation was effective and to "
        "update the score accordingly.",
    )

    add_note(
        doc,
        "The score is a risk indicator, not an absolute measure of "
        "security. A low score does not guarantee the absence of "
        "vulnerabilities, it indicates that no significant external "
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
        "return actual breach data, only metadata about the breaches.",
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
        "Toggling a paid API off does not affect the scan, the "
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
        (
            "Accountable Institution (FIC Act)",
            "An entity listed in Schedule 1 of the Financial Intelligence "
            "Centre Act 38 of 2001. Includes banks, brokers, attorneys, "
            "estate agents, dealers in precious metals, casinos, motor "
            "vehicle dealers, and crypto asset service providers. "
            "Accountable institutions face FIC Section 45C administrative "
            "penalties up to R50M for legal persons (R10M for natural "
            "persons) for AML/CFT non-compliance.",
        ),
        (
            "B2C (Business to Consumer)",
            "An entity whose primary customer is an individual consumer "
            "rather than another business. B2C trigger applies the "
            "Consumer Protection Act Section 112 administrative fine: "
            "10% of annual turnover or R1M, whichever is greater. Auto-"
            "inferred from consumer-facing sub-industry labels (Retail, "
            "Health Services, Personal Services, etc.) and supporting "
            "payment-form signals.",
        ),
        (
            "Capacity Factor (Enterprise)",
            "A revenue-band scaling factor applied to all statutory "
            "maxima in the catastrophe regulatory stack. Reflects the "
            "Information Regulator's Section 109(3) 'extent and ability' "
            "considerations and equivalent enforcement-discretion "
            "patterns across other SA regulators. Range: 0.10 for "
            "entities below R10M revenue to 1.00 for entities at or "
            "above R10B. Ensures a small FSP does not face the same "
            "cat ceiling as a major insurer.",
        ),
        (
            "Catastrophe Regulatory Stack",
            "The sum of every applicable regulatory framework's "
            "statutory maximum (capacity-scaled) used for the 1-in-100, "
            "1-in-200, and 1-in-250 catastrophe loss views. Includes "
            "POPIA Section 109, ECTA Section 89, GDPR (if EU data), "
            "PCI DSS (if card data), CPA Section 112 (if B2C), JSE "
            "Listings Requirements (if listed), FIC Act Section 45C "
            "(if accountable institution), and sector-specific "
            "frameworks resolved from the sub-industry (FSCA, FAIS, "
            "NHA, HPCSA, ICASA, MHSA, PFMA, etc.).",
        ),
        (
            "Civil Liability Disclosure",
            "A required disclosure in the financial impact section of "
            "the report. States that the model's figures exclude civil "
            "liability under POPIA Section 99 (uncapped), common-law "
            "delict, contractual indemnities, master service agreement "
            "penalties, and third-party claims. These exposures depend "
            "on contractual data invisible to an external scan and can "
            "materially exceed the regulatory fine figures shown.",
        ),
        (
            "GPD (Generalised Pareto Distribution)",
            "A statistical distribution used to model the tail of a "
            "heavy-tailed distribution above a high threshold (Peaks "
            "Over Threshold method). The scanner's Monte Carlo engine "
            "fits a GPD above the P95 percentile using a pure-numpy "
            "method-of-moments estimator, then extrapolates the P99, "
            "P99.5, and P99.6 percentiles from the fitted tail. Falls "
            "back to raw percentiles if the fit fails sanity checks.",
        ),
        (
            "Loss Exposure Scenarios",
            "A table presenting five modelled annual loss outcomes "
            "(Most Likely / Median / 1-in-100 / 1-in-200 / 1-in-250) "
            "in place of the previous Recommended Cover Limit figure. "
            "Provides analytical inputs for a broker / client cover-"
            "sizing decision without making that decision on behalf of "
            "the insured. FAIS reasonable-advice compliance.",
        ),
        (
            "POPIA Section 99 (Civil Action)",
            "Section 99 of the Protection of Personal Information Act "
            "4 of 2013. Permits a data subject (or the Information "
            "Regulator on the subject's behalf) to institute civil "
            "action against a responsible party for breach of the Act. "
            "Damages can include patrimonial loss, non-patrimonial "
            "loss, aggravated damages, interest, and costs. NO "
            "STATUTORY CAP applies.",
        ),
        (
            "POPIA Section 109 (Administrative Fine)",
            "Section 109 of the Protection of Personal Information Act "
            "4 of 2013. Empowers the Information Regulator to impose "
            "an administrative fine not exceeding R10 million for "
            "contravention of the Act. Section 109(3) lists eight "
            "factors the Regulator must consider when determining the "
            "fine amount: nature of the personal information; duration "
            "and extent of the contravention; number of data subjects "
            "affected; public-importance issues; likelihood of "
            "substantial damage; prevention possibility; failure to "
            "conduct risk assessments; previous offence history. "
            "Note: the previous reference to 'Section 107' in earlier "
            "versions of the report was incorrect - Section 107 "
            "governs criminal penalties (court-imposed, post-"
            "conviction).",
        ),
        (
            "Pre-flight Auto-detection",
            "A lightweight detection pass run by the /api/preflight "
            "endpoint before the full scan starts. Resolves the "
            "regulatory flags (listed_company, b2c, "
            "accountable_institution, GDPR, PCI, healthcare sub-detail) "
            "from a single HTTP fetch plus the sub-industry. Results "
            "pre-fill the broker form with badge-marked suggestions "
            "the broker can confirm or override before submitting the "
            "full scan. Both broker input and auto-detected values "
            "are recorded in the scan output for the FAIS audit trail.",
        ),
        (
            "Regulatory Flag Audit",
            "A panel in the report showing broker-input vs auto-"
            "detected values for every regulatory flag, side-by-side "
            "with the evidence supporting each auto-detection. Broker "
            "input is authoritative (drives the catastrophe stack "
            "calculation) but the auto-detected value remains visible "
            "as an independent check. Discrepancies are not errors - "
            "they reflect broker knowledge of context the scanner "
            "cannot observe (e.g. unlisted contractual EU customer "
            "relationships).",
        ),
        (
            "Return Period",
            "An actuarial / reinsurance term denoting the average "
            "interval between events of a given severity (a 1-in-100 "
            "year event classically carries a 1% annual exceedance "
            "probability). In this report the 1-in-100 / 1-in-200 / "
            "1-in-250 names are used for the P99 / P99.5 / P99.6 "
            "SEVERITY tiers - the severity of a single severe event, "
            "conditional on it occurring and therefore posture-"
            "independent - NOT literal annual frequencies. They are "
            "surfaced as the Loss Exposure Scenarios and Cover-Sizing "
            "Ladder for catastrophe cover-sizing discussion.",
        ),
        (
            "Scan Duration Profile",
            "A section in the full PDF report listing per-checker "
            "wall-clock time for the scan. Both an SLA quality signal "
            "for brokers and an operational diagnostic primitive for "
            "identifying slow checkers. Recorded under "
            "_scan_completeness.per_checker_seconds in the JSON output.",
        ),
        (
            "Sector Framework Mapping",
            "An auto-applied resolution from the entity's sub-industry "
            "(SIC code) to the regulatory frameworks that could impose "
            "fines on that sector. FS sub-industries map to FSCA + "
            "FIC; Health Services maps to NHA + HPCSA (plus Medical "
            "Schemes Act / Pharmacy Act / SAHPRA via sub-industry-"
            "detail); telecoms maps to ECA / ICASA; mining maps to "
            "MHSA; legal services maps to LPC + FIC; public sector "
            "maps to PFMA.",
        ),
        (
            "Rate Limiter (Token Bucket)",
            "Per-apex traffic-pacing component in the scanner's HTTP "
            "client. Maintains a token bucket per target apex domain. "
            "Each outbound request consumes 1 token; tokens refill at "
            "2 per second up to a burst capacity of 5. When the bucket "
            "is empty, the requesting thread sleeps until tokens are "
            "available. Different apexes have separate buckets so "
            "external API calls are not bottlenecked by target probing.",
        ),
        (
            "WAF / Bot-Manager Tracker",
            "Sliding-window response monitor in the scanner's HTTP "
            "client that flags a target apex as 'protected' when the "
            "rate of 4xx/5xx/timeout responses or the presence of "
            "challenge-page signatures (Cloudflare, Akamai, Imperva, "
            "DataDome, PerimeterX, hCaptcha) crosses threshold. Drives "
            "the Partial Coverage Notice in the PDF and HTML reports.",
        ),
        (
            "Partial Coverage Notice",
            "A disclosure block rendered in the PDF and HTML report "
            "when the WAF tracker flags the target apex as protected "
            "during the scan. States explicitly that absence of a "
            "finding in affected sections does NOT confirm absence "
            "of the underlying risk - the scanner could not verify "
            "it because the target's defensive infrastructure "
            "intervened. FAIS reasonable-advice compliance: without "
            "this notice the report would produce false-negative "
            "findings that mislead the broker and client.",
        ),
        (
            "Probe Cache",
            "Interface defined in http_client.py for caching probe "
            "results across scans. Default implementation is "
            "_NullProbeCache (every lookup misses). Real backing "
            "store (SQLite probe_cache table) is deferred to the "
            "continuous-monitoring track per gap analysis SCN-026. "
            "Refresh rules per response status: 2xx 24h with HEAD "
            "re-verify; 404 7d with 10% spot-check; 5xx 1h; WAF "
            "(403/406/451) 6h; rate-limited (429/503) 30m; "
            "timeout 1h.",
        ),
        (
            "HEAD-first Discovery",
            "Path-existence check pattern that issues a HEAD request "
            "to determine whether a URL responds 200, only issuing a "
            "GET when content analysis is required. Significantly "
            "reduces bandwidth and avoids the directory-enumeration "
            "WAF signature that bursts of GETs typically trip.",
        ),
        (
            "Scanner Self-identification Page",
            "Public page served at /scanner-info on the scanner host. "
            "Documents the scanner operator (Phishield UMA), what the "
            "scanner does and does not do, the typical request profile "
            "(2 req/sec, HEAD-first), the source network, a sample WAF "
            "whitelist rule for security teams, and a security contact "
            "email. The URL is embedded in every scanner request's "
            "User-Agent header so security teams investigating scanner "
            "traffic can verify legitimacy out-of-band.",
        ),
        (
            "Peer Rating (1.0-10.0)",
            "A comparative score derived from the percentile rank of "
            "the assessed organisation's (inverted) risk score against "
            "the peer benchmark pool. Higher rating = better security "
            "posture relative to peers. Purely comparative; the existing "
            "0-1000 risk score remains the absolute measure that drives "
            "the remediation roadmap. Formula: 1.0 + 9.0 * (percentile "
            "/ 100). The rating is intentionally allowed to take decimal "
            "values for granularity (e.g. 7.3 / 10).",
        ),
        (
            "Peer Benchmark Pool",
            "A database of benchmark scans (benchmark_scans table in "
            "scans.db) used to compute peer-rating percentiles. Three "
            "source classes: 'benchmark_pool' (public-domain reference "
            "scans curated by Phishield, refreshed bi-weekly), "
            "'lower_tier_upsell' (Phishield's existing lower-tier "
            "client cohort scanned for premier-tier upsell, no broker "
            "intermediating), 'client_optin' (broker-paid scans "
            "contributed with explicit consent). Pool composition is "
            "disclosed in every report so brokers can weight the "
            "comparison.",
        ),
        (
            "Peer Cell Fallback",
            "When the most-specific (industry, sub_industry, "
            "revenue_band) cell has fewer than 5 peer scans, the "
            "lookup widens progressively: drop revenue band, then "
            "drop sub_industry, then drop revenue band again, then "
            "fall back to the global pool. The cell actually used is "
            "disclosed in the report so brokers know how specific the "
            "peer comparison is.",
        ),
        (
            "Critical Findings (cross-checker count)",
            "Hero-strip metric counting CRITICAL-severity issues "
            "across all checkers: shodan_vulns (critical CVEs + KEV-"
            "listed), exposed_admin (critical-classified paths), "
            "high_risk_protocols (critical ports), info_disclosure "
            "(critical-classified files), ssl (F-grade or expired "
            "certificate), dehashed (plaintext passwords leaked), "
            "hudson_rock (active infostealer hits), external_ips "
            "(zero-scored per-IP risk). Replaces the previously-"
            "considered compliance % which could not be reliably "
            "determined from external scans alone.",
        ),
        (
            "Insurance Sub-type Classifier",
            "A keyword classifier in flag_inference.py that distinguishes "
            "Underwriting Management Agents (UMAs), reinsurers, "
            "insurance brokers, and direct insurers from website "
            "content (domain, page title, body keywords). The SIC "
            "sub-industry code lumps all of these into 'Insurance "
            "Agents, Brokers, And Service' / 'Insurance Carriers' but "
            "SA FAIS / Insurance Act regulation treats them very "
            "differently: UMAs cannot sell directly to consumers (B2B "
            "only by regulatory structure), reinsurers sell only to "
            "insurers (B2B by definition), brokers and direct insurers "
            "can be either B2C or B2B. When UMA or reinsurer is "
            "detected, B2C is explicitly negated in the audit panel "
            "with evidence; for brokers and carriers, B2C is left "
            "unset for broker confirmation.",
        ),
    ]

    for term, definition in _glossary:
        add_bold_body(doc, term, "")
        add_body(doc, definition)

    # ------------------------------------------------------------------ #
    #  SECTION 11 -- VERSION HISTORY                                     #
    # ------------------------------------------------------------------ #
    add_h1(doc, "11. Version History")

    add_bold_body(doc, "v2.0: July 2026", " Major revision.")
    add_body(
        doc,
        "This release brings the manual current with the scanner development "
        "delivered since the v1.0 initial release. The changes are listed below "
        "with the date each landed.",
    )
    add_bullet(doc, "2026-07-06: Retired the legacy Render free-tier deployment; the Google Cloud VM is now the sole production instance. The scanner's public self-identification (User-Agent and scanner-info page) was updated to the VM and its single static outbound IP.")
    add_bullet(doc, "2026-07-03: Reconciled the manual against current scanner behaviour: dual-source Certificate Transparency subdomain enumeration (crt.sh and certspotter, with a low-coverage flag), CVE version-gating disclosure (CVEs shown as 'potential, unconfirmed' where the exact software version is not fingerprinted), and the production endpoint moved to the Google Cloud VM at veilguard.phishield.com/scanner. Includes a document-wide readability and punctuation pass.")
    add_bullet(doc, "2026-06-08: Catastrophe-model mid-market calibration: a revenue-band taper and a POPIA/ECTA-scoped regulatory fine floor, with cyber-band, SPF/DMARC and availability frequency and severity refinements.")
    add_bullet(doc, "2026-06-05: Catastrophe-model redesign and FAIR reporting-card pass, with email-security accuracy improvements.")
    add_bullet(doc, "2026-06-02: Credential-exposure correlation now counts password-bearing records specifically; the encrypted export gained recency clustering and leak-reference confidence; the manual was brought current with the Waves 1 to 6 behavioural changes.")
    add_bullet(doc, "2026-06-01: Added the sensitive-credential disclosure tiers and the encrypted credential export (Section 6.4).")
    add_bullet(doc, "2026-05-29: Documented RDP and origin-discovery handling, the B2C and PCI regulatory flags, and the P50 headline correction.")
    add_bullet(doc, "2026-05-28: Added the Hudson Rock, S-4 and S-5 cross-correlation, scoped as reporting-only so it does not double-count in scoring.")
    add_bullet(doc, "2026-05-27: Added the supply-chain checker layer (related domains, third-party JavaScript, exposed dependency manifests, email-vendor surface, vendor-breach correlation, and CMS plugin surface); removed the earlier catastrophe-tail double-count; folded in the Q&A audit fixes.")
    add_bullet(doc, "2026-05-18: Documented the WAF partial-coverage adjustment.")
    add_bullet(doc, "2026-05-15: FAIR financial-impact overhaul: 1-in-50, 1-in-100 and 1-in-150 return-period worst-case views, the sector regulatory catastrophe stack, and FAIS-safe 'Loss Exposure Scenarios' disclosure. Added the records-based Cat Modelling Validity Notice, peer benchmarking with a 1.0 to 10.0 peer rating, the WAF-friendly HTTP architecture, and the auto-detect to broker to cat-stack input flow.")
    add_bullet(doc, "2026-04-20: Regenerated for the hybrid financial-impact model, sub-industry selection, and GDPR and PCI inputs.")
    add_bullet(doc, "2026-04-16: Hybrid financial-impact model engine rewrite.")

    add_bold_body(doc, "v1.0: April 2026", " Initial Release")
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
