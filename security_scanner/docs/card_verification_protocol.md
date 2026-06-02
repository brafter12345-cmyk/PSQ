# Card Verification Protocol

**Status:** mandatory for every new output card AND every card adjustment; use to back-test existing cards.
**Origin:** derived from the RDP false-negative, supply-chain rollup, and
breached-credential hardening accuracy work (2026-05-31); Step 6 (heuristics)
added 2026-06-03 after the 34-card back-test, whose bugs were overwhelmingly
heuristic failures.

A card is not "accurate" until it passes this 6-step ground-truth check on a
**live `takealot.com` reference scan**. Steps 1-5 are black-box (does the output
match reality?); **Step 6 is white-box (are the card's internal assumptions
sound?)** — it runs every time because the back-test proved most defects are
heuristics that look fine on a sample target but are arbitrary or fragile.

## The 6 steps

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

6. **Heuristics-sequence test (white-box — run EVERY time).**
   Read the card's **checker + its scoring contribution + its renderer** and
   enumerate EVERY heuristic: hardcoded threshold, magic constant, multiplier,
   cap (`min/max`), fingerprint/substring, fallback default, status-code rule,
   and curated table/list. For each heuristic, screen against the **failure
   modes the back-test found** (any hit is a defect, not a card that "passes"):
   - **Fabrication on absent input** — a fallback that invents a value when the
     source is empty (e.g. `unique_asns or 1` rendering "1 ASN" on InternetDB).
   - **Generic/standard/error response read as a positive signal** — a 403 (WAF
     block), a 200 catch-all, a DNSBL error/refused code (`127.255.255.x` /
     `127.0.0.1`), a ubiquitous header (`x-frame-options` ⇒ "F5"), a wildcard
     DNS/`*._domainkey`, or a loose substring counted as a real finding.
   - **Boolean conflated with a count** — a yes/no flag rendered as "N records"
     (the "13 with passwords" bug).
   - **Inversion** — a protective signal scored as a risk (403 = protected,
     scored as "critical exposure"; penalises well-defended orgs).
   - **Stale curated table** — a hardcoded list that silently goes out of date
     (EOL dates, `vendor_breaches.json` rows past the lookback).
   Then **classify each heuristic**: `justified` (cite the empirical basis) /
   `fragile` (works on the sample, brittle elsewhere — harden it) / `arbitrary`
   (no rationale — document one or remove) / `calibration-gated` (a scoring
   magic-number — DO NOT intuit a new value; flag it for the calibration session
   / FIN-9). Every heuristic must end with a documented rationale or a
   calibration flag. **Prefer a robust gate over a magic number** — the S-3
   `_probe` (200-only + body-sanity) is the reference pattern for response
   handling.

## Pass criteria
- [ ] Value matches direct-source ground truth
- [ ] Correctly attributed (verified ownership + recency)
- [ ] Renders consistently across all four output tiers
- [ ] Any divergence from an external benchmark is explained
- [ ] **Every heuristic enumerated, screened against the failure modes, and classified (justified / fragile / arbitrary / calibration-gated) — no fabrication, no generic-response-as-signal, no boolean-as-count, no inversion, no stale table**

## Credit caution
Ground-truth API calls cost credits (**IntelX = 50/day**, DeHashed metered).
Prefer the cheapest endpoint (Shodan `/host/count`, IntelX `/authenticate/info`),
and never run `verify_scan_smoke.py` with real keys (it's built credit-free).

## Back-test checklist (existing cards)
Run each card through the 6 steps (incl. the Step-6 heuristics sweep). Cards to cover include: SSL/TLS, Email
Security, HTTP Headers, WAF, Third-Party JS, DNS & Open Ports, Database/Service
Exposure, VPN & Remote Access (RDP), **Origin IP Discovery**, CVE/Known Vulns,
Brand Breach (HIBP), IP/Domain Reputation (DNSBL), Exposed Admin, Subdomains,
Dehashed, **Credential Risk + Credential Exposure Correlation + Credential
Remediation Detail**, Hudson Rock, IntelX, **Third-Party Cross-Correlation**,
Supply-Chain (S-1/2/3/4/5/10) rollup, Fraudulent Domains, Tech Stack, CMS Plugins,
Vendor Breach, RSI, DBI, Financial Impact, Loss Exposure, Peer Benchmarking.
