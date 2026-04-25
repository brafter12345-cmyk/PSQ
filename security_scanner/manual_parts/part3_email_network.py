"""
Phishield Cyber Risk Scanner - User Manual
Sections 4.3 - 4.5: Information Security, Email Security, Network & Infrastructure

Provides build(doc) which appends content using the shared helper functions:
    add_h1, add_h2, add_body, add_bold_body, add_bullet, add_tip, add_warning, add_note
"""

from manual_parts.helpers import (
    add_h1, add_h2, add_body, add_bold_body, add_bullet, add_tip, add_warning, add_note,
)


def build(doc):
    """Append sections 4.3 - 4.5 to the document."""

    # ═════════════════════════════════════════════════════════════════════════
    # 4.3  INFORMATION SECURITY
    # ═════════════════════════════════════════════════════════════════════════
    add_h1(doc, "4.3  Information Security")

    # ── 4.3.1  Information Disclosure ────────────────────────────────────────
    add_h2(doc, "4.3.1  Information Disclosure")

    add_body(
        doc,
        "The Information Disclosure check probes your website for sensitive files "
        "and endpoints that should never be publicly accessible. Attackers routinely "
        "scan the internet for these files because a single exposed configuration "
        "file can hand over database credentials, API keys, or an entire copy of "
        "your source code. This check simulates exactly what an attacker would do "
        "and reports anything it finds."
    )

    add_bold_body(
        doc,
        "How It Works: ",
        "The scanner sends HTTP requests to a curated list of commonly exposed "
        "file paths on your web server. If the server responds with the file "
        "contents (rather than a 403 Forbidden or 404 Not Found), the finding is "
        "recorded and scored according to its severity."
    )

    add_bold_body(
        doc,
        "Scoring: ",
        "You start at 100% and lose points for every exposed file. A Critical "
        "finding deducts 20 points and a Medium finding deducts 10 points. If "
        "multiple files are exposed the penalties accumulate, so a site with "
        "several leaked files can quickly drop to 0%."
    )

    # -- File types probed --
    add_bold_body(doc, "Files and Endpoints Probed", "")

    add_bold_body(
        doc,
        ".env (Environment Variables) \u2014 Critical: ",
        "This file typically stores database passwords, API keys, mail server "
        "credentials, and third-party service tokens. If exposed, an attacker "
        "gains immediate access to every connected system. This is one of the "
        "most damaging single-file exposures possible."
    )

    add_bold_body(
        doc,
        ".git/HEAD and .git/config (Source Code Metadata) \u2014 Critical: ",
        "These files are part of the Git version-control system. When the .git "
        "directory is accessible, an attacker can reconstruct your entire source "
        "code repository, including historical commits that may contain passwords, "
        "internal comments, and proprietary business logic."
    )

    add_bold_body(
        doc,
        "wp-config.php.bak (WordPress Configuration Backup) \u2014 Critical: ",
        "WordPress stores its database host, username, password, and secret keys "
        "in wp-config.php. Backup copies (with .bak, .old, or ~ suffixes) are "
        "served as plain text by most web servers, revealing every credential "
        "needed to take over the site and its database."
    )

    add_bold_body(
        doc,
        ".htpasswd (Apache Password File) \u2014 Critical: ",
        "Contains hashed usernames and passwords used by the Apache web server "
        "for basic authentication. The hashes can be cracked offline in minutes "
        "with modern tools, giving an attacker valid login credentials."
    )

    add_bold_body(
        doc,
        "backup.sql / dump.sql / db.sql (Database Dumps) \u2014 Critical: ",
        "SQL dump files contain a complete copy of your database, including "
        "customer records, email addresses, hashed (or sometimes plaintext) "
        "passwords, financial data, and any other information stored in your "
        "application. A single exposed dump file can constitute a full data breach."
    )

    add_bold_body(
        doc,
        "phpinfo.php (PHP Information Page) \u2014 Medium: ",
        "Displays the full PHP configuration of the server, including file paths, "
        "loaded modules, environment variables, and sometimes database connection "
        "strings. Attackers use this information to tailor exploits to your exact "
        "server setup."
    )

    add_bold_body(
        doc,
        "server-status (Apache Status Page) \u2014 Medium: ",
        "Exposes real-time information about every active connection to the web "
        "server, including client IP addresses, requested URLs, and virtual host "
        "names. This is useful reconnaissance for planning further attacks."
    )

    add_bold_body(
        doc,
        ".DS_Store (macOS Directory Metadata) \u2014 Medium: ",
        "Created automatically by macOS Finder, this file lists every file and "
        "folder in the directory. Attackers parse it to discover hidden files, "
        "admin panels, or backup directories that are not linked from the website."
    )

    add_bold_body(
        doc,
        "web.config (IIS Configuration) \u2014 Medium: ",
        "The configuration file for Microsoft IIS web servers. May contain "
        "connection strings, authentication settings, URL rewrite rules, and "
        "custom error pages that reveal internal architecture."
    )

    add_bold_body(
        doc,
        "Debug Endpoints \u2014 Medium: ",
        "Development and debugging endpoints (such as /debug, /trace, or "
        "framework-specific diagnostic pages) expose internal application state, "
        "stack traces, and configuration details that are invaluable to an attacker."
    )

    add_bold_body(
        doc,
        "Spring Boot Actuator Endpoints \u2014 Critical: ",
        "Java Spring Boot applications expose management endpoints (such as "
        "/actuator/env, /actuator/configprops, and /actuator/heapdump) that can "
        "reveal environment variables, configuration properties, and even a full "
        "memory dump of the running application. Unsecured actuator endpoints are "
        "a well-known path to remote code execution."
    )

    add_tip(
        doc,
        "Ensure your web server is configured to deny access to hidden files "
        "(those starting with a dot), backup files, and any development or "
        "debugging endpoints. A simple rule in your web server or CDN "
        "configuration can block all of these at once."
    )

    add_warning(
        doc,
        "A single exposed .env or database dump file can result in a complete "
        "compromise of your application, your database, and every connected "
        "third-party service. Treat any finding in this section as urgent."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "Underwriters view exposed credentials and database files as evidence "
        "of poor security hygiene. Findings here directly increase the assessed "
        "likelihood of a data breach, which is the most expensive category of "
        "cyber insurance claim."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "The most frequently discovered files are .env (especially on Laravel "
        "and Node.js applications), .git directories on sites deployed via Git, "
        "and phpinfo.php left behind after initial server setup."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "The scanner checks a curated list of well-known paths. Custom file "
        "names or non-standard backup locations are not tested. The check also "
        "relies on HTTP response codes; a server that returns 200 OK for all "
        "paths (a soft 404) may produce false positives that are filtered where "
        "possible but cannot be entirely eliminated."
    )

    # ═════════════════════════════════════════════════════════════════════════
    # 4.4  EMAIL SECURITY
    # ═════════════════════════════════════════════════════════════════════════
    add_h1(doc, "4.4  Email Security")

    add_body(
        doc,
        "Email remains the primary attack vector for phishing, business email "
        "compromise (BEC), and malware delivery. The scanner evaluates two layers "
        "of email security: the foundational authentication records that every "
        "domain should have, and the advanced hardening mechanisms that represent "
        "current best practice."
    )

    # ── 4.4.1  Email Authentication (SPF / DKIM / DMARC) ────────────────────
    add_h2(doc, "4.4.1  Email Authentication (SPF / DKIM / DMARC)")

    add_bold_body(
        doc,
        "Score: ",
        "0 to 10. Points are awarded for each correctly configured record and "
        "deducted for missing or misconfigured entries."
    )

    add_body(
        doc,
        "These three DNS-based records work together to prove that an email "
        "genuinely came from your organisation and has not been tampered with in "
        "transit. Without them, anyone on the internet can send emails that appear "
        "to come from your domain, making phishing and BEC attacks trivial."
    )

    # SPF
    add_bold_body(
        doc,
        "SPF (Sender Policy Framework): ",
        "An SPF record is a DNS TXT entry that lists the mail servers authorised "
        "to send email on behalf of your domain. When a receiving mail server "
        "gets a message claiming to be from your domain, it checks the SPF record "
        "to verify that the sending server is on the approved list. If the server "
        "is not listed, the message can be rejected or flagged as suspicious."
    )

    add_bullet(doc, "Prevents attackers from sending email that appears to come from your domain.")
    add_bullet(doc, "Should end with -all (hard fail) rather than ~all (soft fail) for strongest protection.")
    add_bullet(doc, "Overly broad SPF records (such as including large cloud provider IP ranges) weaken protection.")

    # DKIM
    add_bold_body(
        doc,
        "DKIM (DomainKeys Identified Mail): ",
        "DKIM adds a cryptographic signature to every outgoing email. The sending "
        "server signs the message with a private key, and the receiving server "
        "verifies the signature using a public key published in your DNS. This "
        "proves that the email has not been altered in transit and genuinely "
        "originated from your mail infrastructure."
    )

    add_bullet(doc, "The scanner checks up to 40 common DKIM selector names to locate your published key.")
    add_bullet(doc, "A valid DKIM signature significantly improves email deliverability.")
    add_bullet(doc, "Without DKIM, recipients have no way to verify that your emails are authentic.")

    # DMARC
    add_bold_body(
        doc,
        "DMARC (Domain-based Message Authentication, Reporting and Conformance): ",
        "DMARC ties SPF and DKIM together with a policy that tells receiving "
        "servers what to do when authentication fails. The three policy levels are:"
    )

    add_bullet(
        doc,
        "none \u2014 Monitor only. Failing messages are still delivered. "
        "This is a starting point for collecting data but provides no protection."
    )
    add_bullet(
        doc,
        "quarantine \u2014 Failing messages are sent to the recipient\u2019s spam or "
        "junk folder. Provides moderate protection."
    )
    add_bullet(
        doc,
        "reject \u2014 Failing messages are blocked entirely. This is the "
        "strongest setting and the recommended target for all organisations."
    )

    add_body(
        doc,
        "DMARC also enables aggregate and forensic reporting, giving you "
        "visibility into who is sending email using your domain and whether "
        "legitimate messages are passing authentication."
    )

    # MX Records
    add_bold_body(
        doc,
        "MX Records: ",
        "The scanner verifies that your domain has valid MX (Mail Exchanger) "
        "records pointing to operational mail servers. Missing or misconfigured "
        "MX records mean your domain cannot receive email, which also affects "
        "DMARC report delivery."
    )

    add_tip(
        doc,
        "If you do not send email from your domain (for example, a domain used "
        "only for a website), you should still publish SPF, DKIM, and DMARC "
        "records with restrictive policies. This prevents attackers from abusing "
        "your domain for phishing."
    )

    add_warning(
        doc,
        "A domain with no DMARC record or a DMARC policy of 'none' offers no "
        "protection against email spoofing. Attackers actively scan for these "
        "domains and use them in targeted phishing campaigns. Business email "
        "compromise attacks that exploit missing DMARC are among the most "
        "financially damaging cyber incidents."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "Email authentication is one of the first things cyber insurers check. "
        "A missing or weak DMARC policy is a strong predictor of phishing "
        "susceptibility. Many insurers now require at least a DMARC quarantine "
        "policy as a condition of coverage, and some offer premium discounts for "
        "domains with a reject policy."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "The most frequent issue is a DMARC policy set to 'none' (monitoring "
        "only), often because the organisation started the deployment process but "
        "never progressed to enforcement. Missing DKIM records are also common, "
        "particularly when the email provider was configured without completing "
        "the DNS verification step."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "The scanner checks 40 well-known DKIM selector names. If your provider "
        "uses a unique or custom selector not in this list, the DKIM check may "
        "report the key as missing even though it exists. SPF evaluation does not "
        "perform recursive include lookups beyond the first level, so deeply "
        "nested SPF configurations may not be fully validated."
    )

    # ── 4.4.2  Advanced Email Hardening (MTA-STS / DANE / BIMI / TLS-RPT) ──
    add_h2(doc, "4.4.2  Advanced Email Hardening (MTA-STS / DANE / BIMI / TLS-RPT)")

    add_bold_body(
        doc,
        "Score: ",
        "0 to 10. Points are awarded for each advanced mechanism that is "
        "correctly deployed."
    )

    add_body(
        doc,
        "While SPF, DKIM, and DMARC address who sent an email and whether it "
        "was tampered with, they do not protect the email while it travels "
        "between mail servers. The advanced mechanisms in this section represent "
        "the next generation of email security, ensuring that messages are "
        "encrypted in transit, that the receiving server\u2019s identity is verified, "
        "and that your brand is visually authenticated in the recipient\u2019s inbox."
    )

    # MTA-STS
    add_bold_body(
        doc,
        "MTA-STS (Mail Transfer Agent Strict Transport Security): ",
        "MTA-STS forces all inbound email to your domain to be delivered over "
        "an encrypted TLS connection. Without MTA-STS, a man-in-the-middle "
        "attacker can intercept the connection between mail servers and downgrade "
        "it to unencrypted plaintext, reading or modifying every email in transit. "
        "MTA-STS is published as a combination of a DNS TXT record and a policy "
        "file hosted on your web server."
    )

    add_bullet(doc, "Prevents TLS downgrade attacks on email delivery.")
    add_bullet(doc, "Requires a valid HTTPS certificate on the policy endpoint.")
    add_bullet(doc, "Relatively simple to deploy and supported by all major email providers.")

    # BIMI
    add_bold_body(
        doc,
        "BIMI (Brand Indicators for Message Identification): ",
        "BIMI allows your organisation\u2019s verified logo to appear next to your "
        "emails in the recipient\u2019s inbox. It requires a DMARC policy of "
        "quarantine or reject, a published BIMI DNS record, and (for full "
        "support) a Verified Mark Certificate (VMC) from a certificate authority. "
        "BIMI increases brand trust and makes spoofed emails visually obvious "
        "because they will not display your logo."
    )

    add_bullet(doc, "Serves as a visual trust indicator for email recipients.")
    add_bullet(doc, "Requires DMARC enforcement as a prerequisite.")
    add_bullet(doc, "Supported by Gmail, Apple Mail, Yahoo, and an expanding list of providers.")

    # DANE / TLSA
    add_bold_body(
        doc,
        "DANE / TLSA (DNS-Based Authentication of Named Entities): ",
        "DANE uses DNSSEC-signed TLSA records to pin the TLS certificate of "
        "your mail server directly in DNS. This means that a sending server can "
        "verify your mail server\u2019s certificate without relying on the public "
        "certificate authority system. DANE provides the strongest possible "
        "assurance that the connection is going to the genuine mail server and "
        "not an impostor."
    )

    add_bullet(doc, "Requires DNSSEC to be enabled on your domain (a prerequisite that many domains lack).")
    add_bullet(doc, "Provides certificate pinning that is independent of certificate authorities.")
    add_bullet(doc, "Most effective when both the sending and receiving domains support DANE.")

    # TLS-RPT
    add_bold_body(
        doc,
        "TLS-RPT (SMTP TLS Reporting \u2014 RFC 8460): ",
        "TLS-RPT is a DNS TXT record that tells sending mail servers where to "
        "deliver reports about TLS connection failures when delivering email to "
        "your domain. If a sending server cannot establish an encrypted connection "
        "(for example, because of a certificate mismatch or an MTA-STS policy "
        "failure), TLS-RPT ensures you receive a structured report about the "
        "failure. This is essential for monitoring and troubleshooting your "
        "MTA-STS and DANE deployments."
    )

    add_bullet(doc, "Published as a DNS TXT record at _smtp._tls.yourdomain.com.")
    add_bullet(doc, "Reports are sent as JSON to the email address or HTTPS endpoint specified in the record.")
    add_bullet(doc, "Without TLS-RPT, MTA-STS and DANE failures are silent and invisible to the domain owner.")
    add_bullet(doc, "Added in Phase 3 of the scanner to provide complete email transport security visibility.")

    add_note(
        doc,
        "TLS-RPT is the email equivalent of DMARC reporting but for transport "
        "encryption. Just as DMARC reports tell you who is spoofing your domain, "
        "TLS-RPT reports tell you when encrypted email delivery is failing."
    )

    add_tip(
        doc,
        "Deploy MTA-STS and TLS-RPT together. MTA-STS enforces encryption, and "
        "TLS-RPT tells you when enforcement causes delivery failures. Start "
        "MTA-STS in 'testing' mode to receive reports before switching to "
        "'enforce' mode."
    )

    add_warning(
        doc,
        "Without MTA-STS or DANE, email between your domain and other mail "
        "servers may be transmitted in plaintext, even if both servers support "
        "TLS. This is because the standard SMTP protocol uses opportunistic "
        "encryption that is trivially downgraded by a network attacker."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "Advanced email hardening demonstrates mature security posture. While "
        "not yet universally required by insurers, the presence of MTA-STS, "
        "BIMI, and TLS-RPT signals that an organisation takes proactive steps "
        "beyond minimum compliance. As email-borne attacks continue to dominate "
        "claim volumes, these controls are increasingly recognised in risk "
        "assessments."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "Most organisations have not yet deployed any of these advanced "
        "mechanisms. MTA-STS is the most commonly adopted because major email "
        "providers (including Google and Microsoft) support it natively. DANE "
        "adoption remains low because it requires DNSSEC. TLS-RPT and BIMI are "
        "the least deployed, often because organisations are not yet aware they "
        "exist."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "The scanner verifies the presence and basic syntax of each DNS record "
        "but does not perform a full end-to-end delivery test. MTA-STS policy "
        "file validation checks that the file is reachable and correctly "
        "formatted but does not test TLS negotiation with every sending server. "
        "BIMI logo validation does not verify VMC certificate chains."
    )

    # ═════════════════════════════════════════════════════════════════════════
    # 4.5  NETWORK & INFRASTRUCTURE
    # ═════════════════════════════════════════════════════════════════════════
    add_h1(doc, "4.5  Network & Infrastructure")

    add_body(
        doc,
        "This section examines the network perimeter of your organisation: which "
        "ports and services are visible from the internet, what information your "
        "servers reveal about themselves, and whether critical infrastructure "
        "components are properly secured. Every open port is a potential entry "
        "point, and the scanner evaluates each one from the perspective of an "
        "attacker or an insurance underwriter."
    )

    # ── 4.5.1  DNS & Open Ports ──────────────────────────────────────────────
    add_h2(doc, "4.5.1  DNS & Open Ports")

    add_body(
        doc,
        "The open port scan is one of the most important checks in the entire "
        "scanner. It enumerates the network services visible on your public IP "
        "addresses and classifies each one by risk level. Attackers begin almost "
        "every intrusion by scanning for open ports, and so does the scanner."
    )

    add_bold_body(
        doc,
        "How It Works: ",
        "The scanner performs a TCP port scan against your domain\u2019s resolved IP "
        "addresses, checking for commonly targeted services. Each discovered open "
        "port is classified into one of three risk tiers."
    )

    # Risk tiers
    add_bold_body(doc, "Risk Classification", "")

    add_bold_body(
        doc,
        "High Risk: ",
        "FTP (port 21), Telnet (port 23), MySQL (port 3306), RDP (port 3389), "
        "and VNC (ports 5900-5901). These services are actively targeted by "
        "automated attack tools and botnets. FTP and Telnet transmit credentials "
        "in plaintext. RDP is the number-one initial access vector for "
        "ransomware. MySQL and VNC exposed to the internet are routinely brute-forced."
    )

    add_bold_body(
        doc,
        "Medium Risk: ",
        "SSH (port 22), SMTP (port 25), POP3 (port 110), and IMAP (port 143). "
        "These services have legitimate reasons to be internet-facing but require "
        "careful configuration. SSH should use key-based authentication and "
        "non-standard ports where possible. SMTP, POP3, and IMAP should enforce "
        "encryption (STARTTLS or implicit TLS)."
    )

    add_bold_body(
        doc,
        "Informational: ",
        "HTTP (port 80) and HTTPS (port 443). These are expected to be open on "
        "any web server and are reported for completeness. HTTP should redirect "
        "to HTTPS."
    )

    # Per-port intelligence
    add_bold_body(
        doc,
        "Per-Port Exploit Intelligence: ",
        "For each open port, the scanner provides contextual threat intelligence "
        "including the Common Vulnerability Scoring System (CVSS) base score for "
        "known vulnerabilities associated with the service, the Exploit "
        "Prediction Scoring System (EPSS) probability that the vulnerability will "
        "be exploited in the wild, notable CVE references for the service type, "
        "and specific insurance risk context explaining why the finding matters "
        "to underwriters."
    )

    # Server headers
    add_bold_body(
        doc,
        "Server Header Fingerprinting: ",
        "The scanner inspects HTTP response headers to identify the web server "
        "software and version (for example, Apache 2.4.51 or nginx 1.22). "
        "Detailed version information helps attackers identify servers running "
        "outdated or vulnerable software. Best practice is to suppress or "
        "generalise server version headers."
    )

    # Reverse DNS
    add_bold_body(
        doc,
        "Reverse DNS: ",
        "A reverse DNS (PTR) lookup is performed on each IP address to identify "
        "the hostname associated with the server. This helps map infrastructure "
        "and can reveal hosting providers, internal naming conventions, or "
        "unexpected third-party services."
    )

    # Zone Transfer (AXFR) - Phase 3
    add_bold_body(
        doc,
        "Zone Transfer (AXFR) \u2014 Phase 3: ",
        "The scanner tests each of your domain\u2019s authoritative name servers for "
        "DNS zone transfer vulnerability. A zone transfer (AXFR) is a mechanism "
        "designed to replicate DNS records between authorised name servers. If a "
        "name server allows zone transfers to any requester, an attacker can "
        "download the complete DNS zone file, revealing every subdomain, mail "
        "server, internal hostname, and service record for the domain."
    )

    add_bullet(doc, "If AXFR succeeds on any name server, the finding is rated CRITICAL.")
    add_bullet(
        doc,
        "A successful zone transfer discloses the entire DNS infrastructure, "
        "including internal subdomains that may host development, staging, or "
        "administrative systems not intended to be public."
    )
    add_bullet(
        doc,
        "Each authoritative name server is tested individually because zone "
        "transfer restrictions are configured per server."
    )

    add_warning(
        doc,
        "An open zone transfer is one of the most serious DNS misconfigurations "
        "possible. It gives an attacker a complete map of your infrastructure in "
        "a single query. Every authoritative name server should restrict zone "
        "transfers to explicitly authorised IP addresses."
    )

    add_tip(
        doc,
        "Ask your DNS provider or hosting company to confirm that zone transfers "
        "are restricted. Most managed DNS providers (Cloudflare, AWS Route 53, "
        "Azure DNS) disable zone transfers by default, but self-hosted DNS "
        "servers frequently have them enabled."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "Open ports are a primary factor in cyber risk scoring. Exposed RDP is "
        "specifically flagged by most insurers as an automatic risk elevation "
        "because of its dominant role in ransomware attacks. Services like Telnet "
        "and FTP indicate legacy infrastructure that is difficult to patch and "
        "maintain. The presence of exploit intelligence (CVSS and EPSS data) "
        "allows underwriters to quantify the specific risk each open port "
        "introduces."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "SSH open to the internet is the most frequent medium-risk finding. "
        "Exposed RDP is alarmingly common on Windows-based infrastructure, "
        "particularly for organisations that enabled remote access during the "
        "pandemic and never secured it afterwards. Verbose server headers that "
        "reveal exact software versions are found on the majority of scanned "
        "domains."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "The port scan covers commonly targeted ports rather than the full "
        "65,535 TCP port range. Services running on non-standard ports may not "
        "be detected. UDP services are not scanned. The scan reflects the state "
        "at the moment of testing; firewall rules or cloud security group changes "
        "made after the scan will not be reflected until the next scan."
    )

    # ── 4.5.2  Database & Service Exposure ───────────────────────────────────
    add_h2(doc, "4.5.2  Database & Service Exposure")

    add_body(
        doc,
        "Databases and data stores should never be directly accessible from the "
        "internet. This check specifically targets high-risk database and service "
        "ports that, if exposed, provide an attacker with a direct path to your "
        "organisation\u2019s data."
    )

    add_bold_body(
        doc,
        "How It Works: ",
        "The scanner probes for the following database and service ports on your "
        "public IP addresses:"
    )

    add_bullet(
        doc,
        "MongoDB (port 27017) \u2014 NoSQL databases are frequently deployed without "
        "authentication. Tens of thousands of exposed MongoDB instances have been "
        "ransomed after attackers deleted the data and demanded payment for its "
        "return."
    )
    add_bullet(
        doc,
        "Redis (port 6379) \u2014 An in-memory data store often used for caching and "
        "session management. Default Redis installations have no authentication, "
        "and an exposed instance can be exploited for remote code execution via "
        "crafted commands."
    )
    add_bullet(
        doc,
        "Elasticsearch (port 9200) \u2014 A search and analytics engine that often "
        "contains indexed copies of sensitive business data. Exposed Elasticsearch "
        "clusters are a leading cause of large-scale data leaks."
    )
    add_bullet(
        doc,
        "PostgreSQL (port 5432) \u2014 A relational database that, if internet-facing, "
        "is subject to brute-force password attacks and exploitation of known "
        "vulnerabilities."
    )
    add_bullet(
        doc,
        "Microsoft SQL Server (port 1433) \u2014 MSSQL exposed to the internet is a "
        "common target for credential stuffing and exploitation. The xp_cmdshell "
        "stored procedure can be abused for direct operating system command "
        "execution."
    )
    add_bullet(
        doc,
        "CouchDB (port 5984) \u2014 A document-oriented database that exposes an "
        "HTTP API. Default configurations may allow unauthenticated read and "
        "write access to all databases."
    )
    add_bullet(
        doc,
        "MySQL (port 3306) \u2014 One of the most widely used databases. Exposed "
        "MySQL servers are continuously targeted by automated brute-force tools "
        "attempting common usernames and passwords."
    )

    add_body(
        doc,
        "For each exposed database or service, the scanner provides exploit "
        "intelligence including relevant CVE references, CVSS severity scores, "
        "EPSS exploitation probability, and insurance risk context."
    )

    add_warning(
        doc,
        "Any database port accessible from the internet is a critical finding. "
        "Databases should be placed behind a firewall and accessed only through "
        "your application server or via a VPN. There is no legitimate reason for "
        "a production database to accept connections from arbitrary internet "
        "addresses."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "An exposed database is one of the strongest indicators of imminent "
        "breach risk. Underwriters treat this finding as a potential dealbreaker "
        "because it represents a direct, unauthenticated (or weakly "
        "authenticated) path to data that is almost certainly subject to privacy "
        "regulations such as POPIA, GDPR, or PCI-DSS."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "MongoDB and Redis are the most frequently exposed services, largely "
        "because their default configurations do not require authentication. "
        "Elasticsearch clusters are also commonly found, particularly in "
        "organisations running log aggregation or search platforms."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "The scanner detects that the port is open and responding but does not "
        "attempt to authenticate or extract data. An open port does not "
        "necessarily mean the service is unauthenticated, but the mere fact that "
        "it is internet-accessible is itself a significant risk."
    )

    # ── 4.5.3  Cloud & CDN Infrastructure ────────────────────────────────────
    add_h2(doc, "4.5.3  Cloud & CDN Infrastructure")

    add_body(
        doc,
        "A Content Delivery Network (CDN) sits between your web server and "
        "the internet, caching content closer to users and absorbing malicious "
        "traffic before it reaches your infrastructure. The scanner identifies "
        "whether your domain uses a CDN and which provider is in place."
    )

    add_bold_body(
        doc,
        "How It Works: ",
        "The scanner examines HTTP response headers, DNS CNAME chains, and IP "
        "address ranges to detect known CDN providers including Cloudflare, "
        "Amazon Web Services (CloudFront), Akamai, Fastly, Azure CDN, Google "
        "Cloud CDN, and others. It also identifies the general hosting type "
        "(cloud, shared hosting, dedicated server, or VPS) and the hosting "
        "provider."
    )

    add_bold_body(doc, "What a CDN Provides:", "")

    add_bullet(
        doc,
        "DDoS Mitigation \u2014 The CDN absorbs volumetric attacks that would "
        "overwhelm your origin server, maintaining availability during an attack."
    )
    add_bullet(
        doc,
        "Origin Masking \u2014 The CDN hides your actual server IP address, making "
        "it significantly harder for attackers to target your infrastructure "
        "directly."
    )
    add_bullet(
        doc,
        "Web Application Firewall (WAF) \u2014 Many CDN providers include a WAF that "
        "filters common web attacks (SQL injection, cross-site scripting) before "
        "they reach your application."
    )
    add_bullet(
        doc,
        "Performance \u2014 Content is served from edge locations geographically "
        "close to the user, reducing latency and improving page load times."
    )

    add_warning(
        doc,
        "If no CDN is detected, your origin server is directly exposed to the "
        "internet. This means all traffic, including malicious traffic, hits your "
        "server directly. You are fully responsible for absorbing DDoS attacks, "
        "filtering web application attacks, and maintaining availability without "
        "the buffer that a CDN provides."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "CDN usage is a positive signal for underwriters. It demonstrates "
        "investment in infrastructure resilience and reduces the likelihood of "
        "successful DDoS attacks, which can trigger business interruption claims. "
        "The specific CDN provider may also indicate the availability of "
        "enterprise-grade WAF and bot management capabilities."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "Cloudflare is the most frequently detected CDN, followed by AWS "
        "CloudFront. Organisations using shared hosting plans often have no CDN "
        "in place. Some domains use a CDN for their main website but expose "
        "subdomains (such as API endpoints or mail servers) directly."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "CDN detection is based on observable indicators. Some CDN configurations "
        "(particularly enterprise setups with custom CNAME records) may not be "
        "detected. The scanner identifies that a CDN is present but does not "
        "evaluate its configuration, WAF rules, or DDoS mitigation capacity."
    )

    # ── 4.5.4  VPN & Remote Access ───────────────────────────────────────────
    add_h2(doc, "4.5.4  VPN & Remote Access")

    add_body(
        doc,
        "Remote access is essential for modern organisations, but how it is "
        "implemented has a direct impact on security posture. The scanner checks "
        "for exposed remote access services and identifies the method your "
        "organisation uses to enable remote work."
    )

    add_bold_body(
        doc,
        "RDP Exposure (Port 3389): ",
        "The Remote Desktop Protocol is the single most exploited initial access "
        "vector for ransomware. The scanner checks whether port 3389 is open on "
        "your public IP addresses. An exposed RDP service is rated as a critical "
        "finding because automated attack tools continuously scan the entire "
        "internet for open RDP, and compromised RDP credentials are bought and "
        "sold on criminal marketplaces."
    )

    add_bullet(doc, "RDP exposed directly to the internet is a critical finding regardless of whether it is patched.")
    add_bullet(doc, "Even with strong passwords, RDP is vulnerable to brute-force attacks, credential stuffing, and zero-day exploits.")
    add_bullet(doc, "RDP should always be accessed through a VPN, a jump server, or a zero-trust access solution.")

    add_bold_body(
        doc,
        "VPN Gateway Detection: ",
        "The scanner identifies known VPN and remote access gateways by checking "
        "for characteristic ports, HTTP response headers, and TLS certificate "
        "attributes associated with common VPN solutions. Detected platforms "
        "include Citrix Gateway (NetScaler), Fortinet FortiGate, Pulse Secure "
        "(now Ivanti Connect Secure), Palo Alto GlobalProtect, Cisco AnyConnect, "
        "SonicWall, and WireGuard."
    )

    add_body(
        doc,
        "The presence of a recognised VPN gateway is generally a positive "
        "finding, as it indicates that remote access is channelled through a "
        "controlled and authenticated entry point. However, VPN gateways "
        "themselves are high-value targets and must be kept rigorously updated. "
        "Recent critical vulnerabilities in Citrix, Fortinet, Pulse Secure, and "
        "Palo Alto products have been widely exploited in ransomware campaigns."
    )

    add_note(
        doc,
        "If no VPN gateway is detected and RDP is not exposed, the scanner "
        "reports that the remote access method is unknown. This does not "
        "necessarily mean there is a problem. Your organisation may use a "
        "cloud-based zero-trust solution, a software-defined perimeter, or "
        "another method that does not leave a detectable network signature."
    )

    add_warning(
        doc,
        "Exposed RDP with no VPN is the highest-risk remote access "
        "configuration. This is the primary entry point for the majority of "
        "ransomware incidents. If the scanner detects this combination, it "
        "should be treated as an emergency requiring immediate remediation."
    )

    add_tip(
        doc,
        "If your organisation uses RDP, place it behind a VPN or a remote "
        "desktop gateway with multi-factor authentication. Network Level "
        "Authentication (NLA) should be enabled as a minimum, but NLA alone is "
        "not sufficient to make RDP safe for direct internet exposure."
    )

    add_bold_body(
        doc,
        "Insurance Relevance: ",
        "RDP exposure is one of the most heavily weighted factors in cyber "
        "insurance risk assessments. Many insurers will decline coverage or "
        "impose exclusions if RDP is exposed to the internet. The presence of a "
        "recognised, current-generation VPN gateway is a positive factor, but "
        "underwriters may also ask about patch cadence for the VPN appliance "
        "itself, given the frequency of critical vulnerabilities in these "
        "products."
    )

    add_bold_body(
        doc,
        "Common Findings: ",
        "Exposed RDP remains disturbingly common, particularly among small and "
        "medium businesses that set up remote access during the pandemic using "
        "simple port forwarding. Fortinet and Citrix gateways are the most "
        "frequently detected VPN solutions. A significant number of scanned "
        "domains show no detectable VPN or remote access footprint."
    )

    add_bold_body(
        doc,
        "Limitations: ",
        "VPN detection relies on network signatures that may not be present if "
        "the VPN terminates on a different IP address or subdomain than the one "
        "being scanned. Cloud-based VPN solutions (such as Zscaler or Cloudflare "
        "Access) operate at the DNS or application layer and may not be "
        "detectable via port scanning. The scanner does not test VPN "
        "authentication strength or check for known vulnerabilities in the "
        "detected VPN product."
    )
