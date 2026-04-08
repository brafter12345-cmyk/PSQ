# Phishield.com Baseline Expected Values
# Source: cyber-risk-phishield.com-2026-04-06.pdf (07:23 UTC scan, score 403)
# Use this as the reference when all checkers pass successfully.

## Overall
- Risk Score: 403
- Risk Level: HIGH RISK

## Checker Scores
| Checker | Value |
|---------|-------|
| SSL Grade | F (score 17) |
| Email Security | 6/10 |
| Email Hardening | 0/10 |
| HTTP Headers | 0% |
| WAF | Not detected |
| Website Security | ~60% |
| Exposed Admin | 3 found (2 critical HTTP 403) |
| HRP | 1 critical (PostgreSQL 5432) |
| DNSBL | Blacklisted (YES) |
| Breaches (HIBP) | 0 |
| Dehashed | 9 records |
| IntelX | 58 results |
| Hudson Rock | 1 third-party |
| CVEs Total | 30 (10 critical, 6 high, 14 medium) |
| Max CVSS | 10.0 |
| Max EPSS | 72.4% |
| Tech Stack | ~100 (no EOL) |
| Info Disclosure | ~100 |
| Fraudulent Domains | 0 |
| Web Ranking | Unranked (score 30) |
| VirusTotal | Clean |
| SecurityTrails | Clean |

## Insurance Analytics
| Metric | Value |
|--------|-------|
| RSI | 0.803 / Critical |
| DBI | 90/100 / Excellent |
| Est. Annual Loss | R 1,247,747 |

## Open Ports (Primary IP 213.133.105.171)
21/FTP, 22/SSH, 25/SMTP, 80/HTTP, 110/POP3, 143/IMAP, 443/HTTPS,
465/SMTPS, 587/Submission, 993/IMAPS, 995/POP3S, 3306/MySQL, 5432/PostgreSQL, 222/SSH-alt

## Notes
- Score of 294 occurs when HTTPS to phishield.com is blocked (4 checkers fail)
- The 403 vs 294 gap is caused by: exposed_admin finding 0 instead of 3,
  CVEs 15 instead of 30 (only primary IP scanned via Shodan, others need HTTPS),
  and http_headers/waf/tech_stack/privacy_compliance all erroring out
- phishield_baseline.json contains the 294-score scan data (with HTTPS blocked)
