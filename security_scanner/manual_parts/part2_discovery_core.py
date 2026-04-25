"""
Phishield Cyber Risk Scanner User Manual — Sections 4.1–4.2
Discovery and Core Security checkers.

Requires helpers: add_h1, add_h2, add_body, add_bold_body, add_bullet,
                  add_tip, add_warning, add_note
"""


def build(doc):
    """Append sections 4.1 (Discovery) and 4.2 (Core Security) to *doc*."""

    # ================================================================
    # 4.1  DISCOVERY
    # ================================================================
    add_h1(doc, "4.1  Discovery")

    add_body(
        doc,
        "The Discovery category provides contextual intelligence about the domain "
        "being scanned. These checks do not directly measure security posture but "
        "give underwriters and risk analysts important background information that "
        "influences how other findings should be interpreted."
    )

    # ── 4.1.1 Web Ranking (Tranco) ──────────────────────────────────
    add_h2(doc, "4.1.1  Web Ranking (Tranco)")

    add_bold_body(
        doc,
        "What it checks:  ",
        "The scanner looks up the target domain in the Tranco top-1-million list, "
        "a research-grade website popularity ranking maintained by academic "
        "researchers. Tranco aggregates data from multiple providers (including "
        "Cisco Umbrella and the Chrome User Experience Report) to produce a stable, "
        "manipulation-resistant ranking that is updated daily. The scanner downloads "
        "the current list once per day and caches it for performance."
    )

    add_bold_body(
        doc,
        "How to read the result:  ",
        "The report shows two pieces of information: whether the domain appears in "
        "the list at all (Ranked or Unranked) and, if ranked, its numerical "
        "position (1 being the most popular website globally)."
    )

    add_body(doc, "Scoring breakdown:")
    add_bullet(doc, "Rank 1 -- 1 000:  Score 100.  Among the most visited sites on the internet.")
    add_bullet(doc, "Rank 1 001 -- 10 000:  Score 90.  High-traffic, well-known domain.")
    add_bullet(doc, "Rank 10 001 -- 100 000:  Score 70.  Moderate traffic, established online presence.")
    add_bullet(doc, "Rank 100 001 -- 1 000 000:  Score 50.  Lower traffic but still in the top million.")
    add_bullet(doc, "Unranked (not in list):  Score 30.  Domain does not appear in the top one million.")

    add_bold_body(
        doc,
        "Why it matters for insurance:  ",
        "Popularity is a double-edged indicator. Higher-traffic websites are more "
        "attractive targets for attackers because a successful breach exposes more "
        "users and data. At the same time, organisations with high-traffic sites "
        "tend to invest more heavily in security infrastructure, dedicated teams, "
        "and incident-response capability. The ranking therefore provides context "
        "rather than a direct risk verdict."
    )

    add_body(
        doc,
        "For the vast majority of South African small and medium enterprises, the "
        "domain will be unranked. This is entirely normal and expected. An unranked "
        "result does not indicate a security problem; it simply means the site does "
        "not attract enough global traffic to appear in the top million. The scanner "
        "uses this check as a context indicator, not as a risk factor that penalises "
        "the overall score."
    )

    add_note(
        doc,
        "The Tranco list is a research-grade data source. Unlike commercial "
        "popularity rankings, it is specifically designed to resist manipulation "
        "through botnets or click fraud. The scanner refreshes its copy of the "
        "list once every 24 hours."
    )

    add_bold_body(
        doc,
        "Common findings:  ",
        "Almost all SME domains will show as Unranked with a contextual score of "
        "30. Larger enterprises, banks, and e-commerce platforms with significant "
        "South African or international traffic may appear in the list."
    )

    add_bold_body(
        doc,
        "Limitations:  ",
        "The Tranco list measures global popularity. A domain that receives "
        "significant traffic only within South Africa may still be unranked if its "
        "global volume is insufficient. The ranking cannot distinguish between "
        "legitimate user traffic and bot traffic that has not been filtered by "
        "Tranco's anti-manipulation algorithms. Additionally, subdomains are not "
        "ranked individually; the list operates at the registrable domain level."
    )

    # ================================================================
    # 4.2  CORE SECURITY
    # ================================================================
    add_h1(doc, "4.2  Core Security")

    add_body(
        doc,
        "The Core Security category contains the foundational checks that every "
        "internet-facing domain should pass. These checks evaluate the "
        "cryptographic transport layer, browser security headers, firewall "
        "protection, and general website hygiene. Together they form the first line "
        "of defence that an attacker must overcome before reaching the application "
        "itself."
    )

    # ── 4.2.1 SSL/TLS ──────────────────────────────────────────────
    add_h2(doc, "4.2.1  SSL/TLS Certificate and Transport Security")

    add_bold_body(
        doc,
        "What it checks:  ",
        "This is one of the most comprehensive individual checks in the scanner. "
        "It performs a deep analysis of the domain's SSL/TLS configuration by "
        "examining the certificate itself, the protocol versions supported, the "
        "cipher suites offered, and several complementary security mechanisms. "
        "When the sslyze library is available, the scanner performs an in-depth "
        "probe that tests every TLS version and enumerates all accepted cipher "
        "suites. When sslyze is not installed, the scanner falls back to Python's "
        "built-in SSL library, which provides a reliable but less detailed "
        "assessment."
    )

    add_body(doc, "The following elements are evaluated:")

    add_bold_body(
        doc,
        "Certificate details:  ",
        "The subject (which domain the certificate was issued for), the issuer "
        "(which Certificate Authority signed it), the expiry date, and the number "
        "of days remaining until expiry. A certificate that has expired or will "
        "expire within 30 days triggers a significant penalty."
    )

    add_bold_body(
        doc,
        "TLS version support:  ",
        "The scanner tests which protocol versions the server accepts. TLS 1.2 "
        "and TLS 1.3 are the current standards and are required for a passing "
        "grade. TLS 1.0 and TLS 1.1 were officially deprecated in 2021 because "
        "they contain known vulnerabilities (such as the POODLE and BEAST "
        "attacks). If the older SSL 2.0 or SSL 3.0 protocols are still enabled, "
        "the penalty is even more severe, as these are critically insecure."
    )

    add_bold_body(
        doc,
        "Cipher strength:  ",
        "The scanner identifies the cipher suites the server is willing to use. "
        "Weak ciphers include those based on RC4, DES, 3DES, MD5, NULL, EXPORT, "
        "and anonymous key exchange. Any weak cipher that the server accepts "
        "represents a potential downgrade-attack vector, even if the server also "
        "supports strong ciphers."
    )

    add_bold_body(
        doc,
        "Key size:  ",
        "The public key in the certificate is checked for adequate length. Keys "
        "shorter than 2 048 bits are considered weak and incur a penalty. A "
        "2 048-bit or 4 096-bit RSA key, or an equivalent elliptic-curve key, is "
        "the current industry standard."
    )

    add_bold_body(
        doc,
        "HSTS (HTTP Strict Transport Security):  ",
        "HSTS is a response header that instructs browsers to only connect via "
        "HTTPS, preventing protocol-downgrade attacks. When HSTS is missing, an "
        "attacker on the same network can intercept the initial HTTP request "
        "before the redirect to HTTPS occurs."
    )

    add_bold_body(
        doc,
        "OCSP Stapling:  ",
        "Online Certificate Status Protocol (OCSP) stapling allows the server to "
        "attach a time-stamped, signed response from the Certificate Authority "
        "confirming that the certificate has not been revoked. Without stapling, "
        "the visitor's browser must contact the CA directly, which is slower and "
        "may fail silently, leaving revoked certificates undetected."
    )

    add_bold_body(
        doc,
        "Certificate chain validity:  ",
        "The scanner verifies that the full chain of certificates from the leaf "
        "(server) certificate up to a trusted root CA is present and correctly "
        "ordered. An incomplete or invalid chain can cause connection failures in "
        "some browsers and indicates a misconfigured server."
    )

    add_bold_body(
        doc,
        "CAA records (Certificate Authority Authorization):  ",
        "This is a Phase 3 addition. CAA is a DNS record type that specifies "
        "which Certificate Authorities are permitted to issue certificates for the "
        "domain. When CAA records are present and restrictive (for example, "
        "allowing only Let's Encrypt or DigiCert), they prevent an attacker who "
        "has compromised a different CA from issuing a fraudulent certificate. "
        "When no CAA records exist, any CA in the world can issue a certificate "
        "for the domain, which is considered permissive. The scanner parses CAA "
        "records to identify the authorised issuers, wildcard policies, and "
        "incident-reporting (iodef) contacts."
    )

    add_body(doc, "Grade interpretation:")
    add_bullet(
        doc,
        "Grade A+ (score 95--100):  Excellent. Modern TLS only, strong ciphers, "
        "valid certificate with adequate key size, HSTS enabled, OCSP stapling "
        "active, valid chain, and restrictive CAA records. This is the gold "
        "standard."
    )
    add_bullet(
        doc,
        "Grade A (score 85--94):  Very good. One or two minor items may be "
        "missing (for example, OCSP stapling or CAA records) but overall "
        "configuration is strong."
    )
    add_bullet(
        doc,
        "Grade B (score 70--84):  Acceptable. The certificate is valid and "
        "modern TLS is supported, but there may be a deprecated TLS version "
        "still enabled or HSTS may be missing. Remediation is recommended."
    )
    add_bullet(
        doc,
        "Grade C (score 55--69):  Weak. Multiple issues are present. Commonly "
        "this means legacy TLS versions are enabled alongside weak ciphers or a "
        "certificate approaching expiry. Remediation should be prioritised."
    )
    add_bullet(
        doc,
        "Grade D (score 40--54):  Poor. Serious configuration weaknesses are "
        "present. This may include an expiring certificate combined with "
        "deprecated protocols and missing HSTS."
    )
    add_bullet(
        doc,
        "Grade F (score 0--39):  Critical. The certificate may be expired or "
        "invalid, extremely insecure protocols may be enabled, or the chain of "
        "trust is broken. Immediate remediation is required."
    )

    add_body(doc, "Scoring deductions (from a starting score of 100):")
    add_bullet(doc, "Invalid or unverifiable certificate: -40 points")
    add_bullet(doc, "Expired certificate: -40 points")
    add_bullet(doc, "Certificate expiring within 30 days: -20 points")
    add_bullet(doc, "Incomplete or invalid certificate chain: -15 points")
    add_bullet(doc, "Key size below 2 048 bits: -20 points")
    add_bullet(doc, "SSL 2.0 enabled: -30 points")
    add_bullet(doc, "SSL 3.0 enabled: -25 points")
    add_bullet(doc, "TLS 1.0 enabled: -20 points")
    add_bullet(doc, "TLS 1.1 enabled: -10 points")
    add_bullet(doc, "No modern TLS version (1.2 or 1.3): -30 points")
    add_bullet(doc, "Weak cipher suite in use: -20 points")
    add_bullet(doc, "Additional weak cipher suites accepted: -2 points each (maximum -10)")
    add_bullet(doc, "HSTS header missing: -10 points")
    add_bullet(doc, "OCSP stapling not enabled: -5 points")
    add_bullet(doc, "No CAA records: -5 points")

    add_tip(
        doc,
        "For most organisations, the quickest wins are ensuring the certificate "
        "is renewed well before expiry, disabling TLS 1.0 and 1.1 on the web "
        "server, enabling HSTS, and adding CAA records to DNS. These changes "
        "typically take less than an hour and can move a Grade C to a Grade A."
    )

    add_bold_body(
        doc,
        "Common findings:  ",
        "Expired or soon-to-expire certificates are the single most frequent "
        "issue, particularly on sites that do not use automated renewal (such as "
        "Let's Encrypt with certbot). Legacy TLS 1.0 or 1.1 support is common "
        "on older servers that have not been reconfigured since the deprecation "
        "in 2021. Missing HSTS is widespread. Weak cipher suites are less common "
        "on modern hosting but still appear on self-managed servers. Missing CAA "
        "records are very common, as many administrators are not yet aware of "
        "this DNS record type."
    )

    add_bold_body(
        doc,
        "Limitations:  ",
        "The scanner tests the default HTTPS endpoint on port 443. If the "
        "organisation runs additional TLS services on non-standard ports (such as "
        "a mail server on port 465 or a VPN gateway), those are not evaluated by "
        "this check. The stdlib fallback mode cannot enumerate all accepted cipher "
        "suites or detect SSL 2.0/3.0 support; installing sslyze provides "
        "significantly more detailed results. OCSP stapling detection requires "
        "the sslyze deep-scan path. CAA record lookups require the dnspython "
        "library."
    )

    add_warning(
        doc,
        "An expired SSL certificate is treated as a critical finding. Browsers "
        "display prominent security warnings to visitors, search engines may "
        "de-index the site, and encrypted connections cannot be trusted. If the "
        "scanner reports an expired certificate, the organisation should renew "
        "it immediately."
    )

    # ── 4.2.2 HTTP Security Headers ─────────────────────────────────
    add_h2(doc, "4.2.2  HTTP Security Headers")

    add_bold_body(
        doc,
        "What it checks:  ",
        "The scanner requests the domain's home page over HTTPS and inspects the "
        "HTTP response headers for six security-critical headers. Each header "
        "carries a weighted score that reflects its relative importance. The "
        "overall score is expressed as a percentage (0--100%) of the maximum "
        "achievable weight."
    )

    add_body(doc, "Headers evaluated and their weights:")

    add_bold_body(
        doc,
        "Strict-Transport-Security (HSTS) -- weight 20:  ",
        "Instructs the browser to only communicate over HTTPS for a specified "
        "duration. This prevents protocol-downgrade attacks and cookie hijacking. "
        "It is the highest-weighted header because without it, even a site with a "
        "valid SSL certificate can be intercepted during the initial HTTP request."
    )

    add_bold_body(
        doc,
        "X-Frame-Options -- weight 15:  ",
        "Controls whether the page can be embedded in an iframe on another site. "
        "Without this header (or an equivalent CSP frame-ancestors directive), the "
        "site is vulnerable to clickjacking attacks, where an attacker overlays "
        "invisible frames to trick users into clicking hidden buttons."
    )

    add_bold_body(
        doc,
        "X-Content-Type-Options -- weight 15:  ",
        "When set to 'nosniff', this header prevents browsers from guessing "
        "(MIME-sniffing) the content type of a response. Without it, an attacker "
        "can upload a file that the browser incorrectly interprets as executable "
        "script, enabling cross-site scripting."
    )

    add_bold_body(
        doc,
        "Content-Security-Policy (CSP) -- weight 10 (presence) + 10 (quality):  ",
        "CSP is the most powerful browser-side defence against cross-site "
        "scripting (XSS) and data injection attacks. It specifies exactly which "
        "sources are allowed to load scripts, styles, images, fonts, and other "
        "resources. Because a poorly configured CSP can be worse than no CSP at "
        "all (by giving a false sense of security), the scanner evaluates both "
        "presence and quality separately."
    )

    add_bold_body(
        doc,
        "Referrer-Policy -- weight 15:  ",
        "Controls how much referrer information the browser sends when navigating "
        "away from the page. Without a restrictive policy, sensitive URL "
        "parameters (such as session tokens or search queries) may leak to "
        "third-party sites."
    )

    add_bold_body(
        doc,
        "Permissions-Policy -- weight 15:  ",
        "Allows the site to disable browser features it does not use, such as "
        "the camera, microphone, geolocation, or payment API. This limits the "
        "damage an attacker can do even if they inject malicious script into the "
        "page."
    )

    add_body(
        doc,
        "The total possible weight is 100 (six header presence checks totalling "
        "90 points, plus 10 points for CSP quality). The score is calculated as "
        "(earned points / total weight) * 100, expressed as a percentage."
    )

    # CSP Quality sub-section
    add_h2(doc, "4.2.2.1  CSP Quality Analysis (Phase 3)")

    add_body(
        doc,
        "When a Content-Security-Policy header is present, the scanner performs "
        "an additional quality analysis that produces a separate 0--100 score. "
        "This analysis was introduced in Phase 3 to address a common problem: "
        "many sites deploy a CSP header that technically exists but is configured "
        "so permissively that it provides little real protection."
    )

    add_body(doc, "The quality analysis evaluates three dimensions:")

    add_bold_body(
        doc,
        "1. Dangerous patterns detected:  ",
        "The scanner searches the CSP for patterns that undermine its "
        "effectiveness. Each dangerous pattern deducts 15 points from the "
        "quality score."
    )
    add_bullet(
        doc,
        "'unsafe-inline' -- Allows inline scripts and event handlers. This "
        "effectively defeats XSS protection, because an attacker who can inject "
        "HTML can also inject inline script tags."
    )
    add_bullet(
        doc,
        "'unsafe-eval' -- Allows the use of eval(), new Function(), and similar "
        "dynamic code execution methods. Attackers frequently exploit these "
        "functions to execute injected payloads."
    )
    add_bullet(
        doc,
        "Wildcard (*) in script-src -- Permits scripts from any domain. An "
        "attacker can host a malicious script on any server and it will be "
        "allowed by the policy."
    )
    add_bullet(
        doc,
        "data: URIs in script-src -- Allows scripts to be loaded from data: "
        "URIs, which can be used to encode and execute malicious JavaScript "
        "without an external server."
    )

    add_bold_body(
        doc,
        "2. Missing critical directives:  ",
        "The scanner checks whether five essential directives are defined in the "
        "policy. Each missing directive deducts 8 points."
    )
    add_bullet(
        doc,
        "default-src -- The fallback directive. If this is missing and a "
        "specific directive is also missing, the browser applies no restriction "
        "for that resource type."
    )
    add_bullet(
        doc,
        "script-src -- Controls where JavaScript can be loaded from. This is the "
        "most important directive for preventing XSS."
    )
    add_bullet(
        doc,
        "frame-ancestors -- Controls which sites can embed this page in a frame. "
        "This is the modern replacement for X-Frame-Options."
    )
    add_bullet(
        doc,
        "object-src -- Controls where plugins (Flash, Java applets) can be "
        "loaded from. Setting this to 'none' blocks legacy plugin-based attacks."
    )
    add_bullet(
        doc,
        "base-uri -- Controls the URL that can be used in the <base> element. "
        "Without this, an attacker can change the base URL to hijack relative "
        "resource paths."
    )

    add_bold_body(
        doc,
        "3. Bonus points for restrictive policies:  ",
        "The score starts at 50 (for having CSP at all) and can earn additional "
        "points for best-practice configurations."
    )
    add_bullet(
        doc,
        "+20 points if script-src uses 'self' without 'unsafe-inline' or "
        "'unsafe-eval' (a genuinely restrictive policy)."
    )
    add_bullet(doc, "+10 points if the frame-ancestors directive is present (anti-clickjacking).")
    add_bullet(doc, "+10 points if object-src is set to 'none' (blocks legacy plugins).")
    add_bullet(doc, "+10 points if base-uri is set to 'none' (prevents base-tag hijacking).")

    add_body(
        doc,
        "The CSP quality score feeds into the overall HTTP Security Headers "
        "percentage. Specifically, the quality score (0--100) is divided by 10 "
        "to produce a 0--10 point bonus that is added to the earned header "
        "weights. This means a perfect CSP contributes up to 20 points in total "
        "(10 for presence, 10 for quality) out of the overall 100-point budget."
    )

    add_tip(
        doc,
        "Deploying CSP is an iterative process. Start with a report-only policy "
        "(Content-Security-Policy-Report-Only) to identify which resources your "
        "site loads, then tighten the policy gradually. Many sites begin with "
        "'unsafe-inline' enabled and remove it once inline scripts have been "
        "refactored to use nonces or hashes."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance:  ",
        "HTTP security headers are the browser's built-in defence layer. They "
        "cost nothing to implement (they are server configuration changes, not "
        "software purchases) yet dramatically reduce the attack surface for "
        "cross-site scripting, clickjacking, and data exfiltration. A site "
        "missing most security headers signals that basic hardening has not been "
        "performed, which is a strong predictor of other security gaps."
    )

    add_bold_body(
        doc,
        "Common findings:  ",
        "The most frequently missing headers are Content-Security-Policy and "
        "Permissions-Policy. Many sites implement HSTS and X-Content-Type-Options "
        "but overlook the more complex CSP header. When CSP is present, the most "
        "common quality issue is the use of 'unsafe-inline', which is often added "
        "to avoid breaking inline scripts during deployment."
    )

    add_bold_body(
        doc,
        "Limitations:  ",
        "The scanner evaluates the headers returned by the domain's home page. "
        "Some applications set different headers on different routes (for example, "
        "an API endpoint may have different CSP rules than the public marketing "
        "site). The scanner does not crawl the entire site to collect headers from "
        "every page. Additionally, some security headers may be set by a reverse "
        "proxy or CDN rather than the application itself; the scanner reports what "
        "it observes regardless of where the header originates."
    )

    # ── 4.2.3 WAF / DDoS Protection ────────────────────────────────
    add_h2(doc, "4.2.3  WAF / DDoS Protection")

    add_bold_body(
        doc,
        "What it checks:  ",
        "The scanner sends an HTTPS request to the domain and examines the "
        "response for signatures that indicate a Web Application Firewall (WAF) "
        "or DDoS protection service is in place. Detection is based on three "
        "categories of evidence: HTTP response headers unique to the WAF vendor, "
        "cookies set by the WAF, and characteristic content in the response body."
    )

    add_body(doc, "The scanner recognises the following WAF and protection services:")
    add_bullet(doc, "Cloudflare -- Detected via cf-ray header, cf-cache-status header, and related cookies.")
    add_bullet(doc, "AWS WAF / CloudFront -- Detected via x-amz-cf-id header, x-amzn-requestid header, and AWS load-balancer cookies.")
    add_bullet(doc, "Imperva / Incapsula -- Detected via x-iinfo header, x-cdn header, and incapsula session cookies.")
    add_bullet(doc, "Akamai -- Detected via x-akamai-transformed header and Akamai bot-management cookies.")
    add_bullet(doc, "Sucuri -- Detected via x-sucuri-id header, x-sucuri-cache header, and body content.")
    add_bullet(doc, "F5 BIG-IP ASM -- Detected via proprietary headers and F5 session cookies.")
    add_bullet(doc, "Barracuda -- Detected via barracuda session cookies.")

    add_bold_body(
        doc,
        "How to read the result:  ",
        "The report indicates whether a WAF was detected (Yes or No) and, if yes, "
        "names the specific product or products identified. In some cases, "
        "multiple layers of protection may be detected simultaneously (for "
        "example, Cloudflare CDN with an Imperva WAF behind it)."
    )

    add_bold_body(
        doc,
        "Why it matters for insurance:  ",
        "A Web Application Firewall sits between the internet and the web "
        "application, filtering out malicious requests such as SQL injection "
        "attempts, cross-site scripting payloads, and volumetric DDoS traffic. "
        "Without a WAF, the application is directly exposed to every automated "
        "attack tool on the internet. WAF presence is a strong signal that the "
        "organisation takes perimeter security seriously."
    )

    add_body(
        doc,
        "From an insurance perspective, the absence of a WAF is considered a "
        "material risk factor. Modern WAF services are available as cloud-based "
        "solutions (such as Cloudflare, AWS WAF, and Sucuri) at relatively low "
        "cost, making their absence difficult to justify for any internet-facing "
        "application."
    )

    add_bold_body(
        doc,
        "Common findings:  ",
        "Many South African SME websites are hosted on shared hosting platforms "
        "that do not include WAF protection. Sites using Cloudflare as a DNS "
        "proxy will typically show WAF detected even if the paid WAF rules are "
        "not enabled, because Cloudflare's free tier includes basic DDoS "
        "mitigation. Self-hosted sites on dedicated servers or VPS instances "
        "frequently have no WAF in place."
    )

    add_bold_body(
        doc,
        "Limitations:  ",
        "WAF detection is based on observable response characteristics. A WAF "
        "that is configured to suppress all identifying headers and cookies may "
        "not be detected (a false negative). Conversely, a CDN that shares "
        "infrastructure with a WAF vendor may trigger a false positive. The "
        "scanner reports the presence of WAF indicators, not the quality or "
        "configuration of the WAF rules themselves. An organisation could have "
        "Cloudflare enabled with all WAF rules disabled, and the scanner would "
        "still report WAF detected."
    )

    add_note(
        doc,
        "The scanner does not perform active WAF bypass testing or attempt to "
        "trigger WAF rules. Detection is purely passive, based on response "
        "analysis. This is intentional: active testing could disrupt the target "
        "website and would raise ethical and legal concerns."
    )

    # ── 4.2.4 Website Security ──────────────────────────────────────
    add_h2(doc, "4.2.4  Website Security")

    add_bold_body(
        doc,
        "What it checks:  ",
        "This checker evaluates four aspects of general website hygiene: HTTPS "
        "enforcement, mixed content, content management system (CMS) detection, "
        "and cookie security flags. The result is a composite score from 0 to "
        "100%."
    )

    add_body(doc, "The following elements are evaluated:")

    add_bold_body(
        doc,
        "HTTPS enforcement (-40 points if missing):  ",
        "The scanner connects to the domain via plain HTTP (port 80) and checks "
        "whether the server redirects to HTTPS. If it does not, any data "
        "transmitted by visitors (including login credentials and personal "
        "information) can be intercepted in transit. This is the most heavily "
        "weighted component because it is the most fundamental requirement for "
        "secure web communication."
    )

    add_bold_body(
        doc,
        "Mixed content (-25 points if detected):  ",
        "Even when the main page is served over HTTPS, it may load images, "
        "scripts, stylesheets, or iframes over plain HTTP. This is called mixed "
        "content. Browsers display warnings (or block the content entirely), and "
        "an attacker can tamper with the insecure resources. The scanner examines "
        "the page source for any script, image, link, or iframe tags that "
        "reference HTTP URLs."
    )

    add_bold_body(
        doc,
        "Cookie security flags:  ",
        "The scanner examines all cookies set by the domain and checks for two "
        "critical flags."
    )
    add_bullet(
        doc,
        "Secure flag (-20 points if missing on any cookie):  Ensures the cookie "
        "is only transmitted over HTTPS. Without it, a cookie (potentially "
        "containing a session token) can be intercepted on an insecure "
        "connection."
    )
    add_bullet(
        doc,
        "HttpOnly flag (-15 points if missing on any cookie):  Prevents "
        "JavaScript from accessing the cookie. Without it, a cross-site "
        "scripting attack can steal session cookies directly from the browser."
    )

    add_bold_body(
        doc,
        "CMS detection (informational):  ",
        "The scanner identifies the content management system in use by looking "
        "for known signatures in the page source and response headers. "
        "Currently detected platforms include WordPress, Joomla, Drupal, Wix, "
        "Shopify, Squarespace, and Magento. For WordPress sites, the scanner "
        "also attempts to identify the version number. CMS detection does not "
        "directly affect the score but is reported as context. Certain CMS "
        "platforms (particularly self-hosted WordPress with plugins) have a "
        "higher historical rate of vulnerabilities."
    )

    add_body(doc, "Score calculation:")
    add_bullet(doc, "Starting score: 100")
    add_bullet(doc, "HTTPS not enforced: -40 points")
    add_bullet(doc, "Mixed content detected: -25 points")
    add_bullet(doc, "Cookies missing Secure flag: -20 points")
    add_bullet(doc, "Cookies missing HttpOnly flag: -15 points")
    add_bullet(doc, "Final score: maximum of 0 and the result (score cannot go negative)")

    add_bold_body(
        doc,
        "Why it matters for insurance:  ",
        "Website security hygiene reflects the organisation's baseline security "
        "awareness. HTTPS enforcement, in particular, is considered table stakes "
        "in the modern web. Sites that fail to enforce HTTPS or serve mixed "
        "content are signalling a lack of attention to security fundamentals, "
        "which often correlates with deeper issues in application security, "
        "patching discipline, and incident-response readiness."
    )

    add_bold_body(
        doc,
        "Common findings:  ",
        "Most modern hosting providers and CMS platforms enforce HTTPS by default, "
        "so this check passes for the majority of sites scanned. Mixed content is "
        "the most common issue, often caused by legacy images or third-party "
        "widgets that still use HTTP URLs. Cookie security flags are frequently "
        "missing on smaller sites that use default CMS configurations without "
        "hardening. WordPress is by far the most commonly detected CMS among "
        "South African SME domains."
    )

    add_bold_body(
        doc,
        "Limitations:  ",
        "The scanner evaluates only the home page. Mixed content or insecure "
        "cookies on internal pages or authenticated sections will not be detected. "
        "Cookie analysis depends on which cookies are set during an unauthenticated "
        "visit; session cookies that are only issued after login are not evaluated. "
        "CMS version detection relies on publicly visible signatures, which can be "
        "hidden by security plugins or server configuration."
    )

    add_tip(
        doc,
        "If the report shows cookies missing the Secure or HttpOnly flags, "
        "check your web server or CMS configuration. In WordPress, security "
        "plugins such as Wordfence or iThemes Security can enforce these flags "
        "with a single setting. For Apache or Nginx, the fix is typically a "
        "one-line configuration change."
    )
