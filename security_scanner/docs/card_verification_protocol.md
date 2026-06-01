# Card Verification Protocol

**Status:** mandatory for every new output card; use to back-test existing cards.
**Origin:** derived from the RDP false-negative, supply-chain rollup, and
breached-credential hardening accuracy work (2026-05-31).

A card is not "accurate" until it passes this 5-step ground-truth check on a
**live `takealot.com` reference scan**.

## The 5 steps

1. **Ground truth, direct from source.**
   Query the underlying provider *directly* (Shodan `/host/{ip}` or `/host/count`,
   Hudson Rock API, IntelX `/authenticate/info`, DeHashed, a raw TLS handshake) —
   NOT via our scanner — to establish what is actually true/current.

2. **Attribution — "is it real, is it theirs, is it current?"**
   Before attributing any finding (especially IPs / infrastructure / credentials):
   - **Ownership:** TLS cert-match, reverse-DNS, declared/related-domain.
     (e.g. `35.190.12.220` → recycled GCP Redis box ≠ takealot;
     `152.111.191.48` → legacy `download.kalahari.com`.)
   - **Recency:** infection dates, breach dates vs re-circulated combo lists.
   Never attribute on an unverified / legacy / reassigned asset.

3. **Render & inspect the ACTUAL card — in every tier.**
   Render the real output (PDF text-extraction + HTML preview/screenshot), not the
   data dict. Confirm the card shows the verified data and is **consistent across
   exec deck / broker summary / full report / HTML**.

4. **Benchmark against an authoritative source of truth.**
   The reinsurer's report is ONE benchmark — but our scanner tests far more
   cards than a typical/reinsurer scan, so **many cards have no reinsurer
   equivalent**. For any card *without* an external benchmark, pick a **typical,
   well-known/respected reference for that finding type** (an authoritative
   example) and validate our output against *its* ground truth. Where you
   differ, *prove* which is correct.

5. **Run live on a reference target that ACTUALLY exhibits the finding.**
   `takealot.com` is the default fixed target — but where it doesn't show the
   card's finding, **choose a well-known target that does**, run the same test
   through our scanner, and trace any discrepancy through
   render → data-capture → attribution, fix, and re-verify.

## Pass criteria
- [ ] Value matches direct-source ground truth
- [ ] Correctly attributed (verified ownership + recency)
- [ ] Renders consistently across all four output tiers
- [ ] Any divergence from an external benchmark is explained

## Credit caution
Ground-truth API calls cost credits (**IntelX = 50/day**, DeHashed metered).
Prefer the cheapest endpoint (Shodan `/host/count`, IntelX `/authenticate/info`),
and never run `verify_scan_smoke.py` with real keys (it's built credit-free).

## Back-test checklist (existing cards)
Run each card through the 5 steps. Cards to cover include: SSL/TLS, Email
Security, HTTP Headers, WAF, Third-Party JS, DNS & Open Ports, Database/Service
Exposure, VPN & Remote Access (RDP), **Origin IP Discovery**, CVE/Known Vulns,
Brand Breach (HIBP), IP/Domain Reputation (DNSBL), Exposed Admin, Subdomains,
Dehashed, **Credential Risk + Credential Exposure Correlation + Credential
Remediation Detail**, Hudson Rock, IntelX, **Third-Party Cross-Correlation**,
Supply-Chain (S-1/2/3/4/5/10) rollup, Fraudulent Domains, Tech Stack, CMS Plugins,
Vendor Breach, RSI, DBI, Financial Impact, Loss Exposure, Peer Benchmarking.
