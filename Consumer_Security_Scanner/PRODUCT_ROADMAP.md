# Phishield Consumer Security Scanner — Product Roadmap

## Reference: AURA (US) Benchmarking

Researched April 2026. AURA is the US market leader ($2.5B valuation, ~$300M revenue, 1,200 employees).

---

## AURA Product Suite (for reference)
- Identity theft protection (SSN, bank, health, passport monitoring)
- Three-bureau credit monitoring (Experian, Equifax, TransUnion)
- Credit lock (instant Experian lock/unlock)
- Dark web monitoring
- Data broker removal (200+ sites)
- VPN (AES-256, 80+ countries)
- Antivirus (Windows, macOS, Android)
- Password manager
- Encrypted vault
- Parental controls + Safe Gaming
- Spam call/text filtering (AI-powered)
- Home title monitoring
- Court filing monitoring
- AI Privacy Assistant
- Google Search cleanup
- $1M-$5M identity theft insurance

**Pricing:** $9-50/month USD per tier (Individual/Couple/Family)

---

## SA Consumer Product — Adapted Feature Set

### Tier 1: Basic (R29-49/mo) — Mass market
- SIM swap alert monitoring (Vodacom, MTN, Cell C, Telkom)
- Dark web credential monitoring (email + SA ID number)
- WhatsApp link scanning
- Spam call/text filtering
- Basic fraud alerts

### Tier 2: Standard (R99-149/mo) — Middle market
- Everything in Basic
- SA credit bureau monitoring (TransUnion SA, Experian SA, XDS, Compuscan)
- VPN
- Password manager
- SAFPS Protective Registration automation
- SARS identity fraud monitoring
- EFT/PayShap fraud alerts

### Tier 3: Premium (R199-299/mo) — Upper market
- Everything in Standard
- CIPC company registration fraud monitoring
- Deeds Office property fraud monitoring
- Home Affairs ID document monitoring
- UIF fraud monitoring
- Data broker removal (SA-specific)
- Identity theft insurance (SA underwriter, ZAR)
- Antivirus (Android focus)
- Encrypted document vault

### Tier 4: Family (R249-399/mo)
- Everything in Premium
- Up to 5 family members
- Parental controls
- Per-child monitoring dashboard
- Cyberbullying detection

---

## SA-Specific Features NOT in AURA

These are critical differentiators for the SA market:

1. **SIM Swap Protection** — SA's #1 digital fraud vector (R5.3B in losses 2024). Integrate with Scam Signal API (launched Oct 2025, GSMA/MTN/banking collaboration)
2. **RICA Verification Monitoring** — Alert on new SIM registrations against your ID number
3. **WhatsApp Fraud Protection** — Link scanning, business impersonation detection, "Hi Mom" scam alerts. WhatsApp is SA's primary messaging platform
4. **USSD Security** — Banking transactions via USSD codes; session hijacking protection
5. **SA Banking Integration** — FNB, Standard Bank, Nedbank, Absa, Capitec, TymeBank
6. **SAFPS Automation** — Automated Protective Registration (currently manual)
7. **SARS/Home Affairs/CIPC Monitoring** — Government services identity fraud
8. **SA Scam Database** — Known SA fraud patterns (advance fee, job scams, rental scams, crypto targeting SA)
9. **SABRIC Integration** — SA Banking Risk Information Centre alerts
10. **Load Shedding Resilient** — Offline capability, low-bandwidth, minimal data consumption
11. **Zero-Rated Alerts** — Partner with networks to zero-rate critical security notifications
12. **Prepaid-Friendly** — Works for prepaid mobile users (majority of SA market)

---

## Technical Architecture Requirements

### Mobile-First (SA market reality)
- React Native (iOS + Android from one codebase)
- Progressive Web App fallback for storage-conscious users
- USSD fallback for feature phones (still a segment)
- Offline caching of security status
- Data-light design (SA data is expensive)
- Target: works well on low-end Android devices

### Backend
- Central database (PostgreSQL) for all consumer accounts
- API layer shared with commercial scanner where applicable
- Real-time push notifications (Firebase Cloud Messaging)
- Webhook integrations with SA credit bureaus + mobile operators
- POPIA-compliant data handling (consent management, data minimisation, breach reporting via Information Regulator eServices Portal)

### Shared Infrastructure with Commercial Scanner
- Dark web monitoring (Dehashed, IntelX, Hudson Rock)
- Credential breach checking (HIBP)
- Domain/email reputation (VirusTotal)
- FAIR risk model (adapted for personal risk)

---

## Competitive Landscape in SA

| Competitor | What they offer | Gap |
|---|---|---|
| Secure Citizen | ID verification, fraud alerts | No credit monitoring, no dark web, no VPN |
| TransUnion SA app | Credit score only | No identity protection, no security tools |
| Experian SA app | Credit score only | Same limitations |
| Individual VPN apps | VPN only | No identity monitoring |
| Norton 360 | Antivirus + VPN | No SA-specific fraud (SIM swap, RICA, SARS) |

**First-mover opportunity:** No single SA platform bundles identity protection + credit monitoring + dark web + SIM swap + VPN + SA-specific fraud monitoring.

---

## Development Phases

### Phase 1 (MVP — 3-6 months)
- SIM swap alerts (API integration with 1-2 operators)
- Dark web credential monitoring (reuse commercial scanner Dehashed/HIBP/Hudson Rock)
- Basic fraud alerts
- Mobile app (React Native)
- POPIA-compliant signup and consent

### Phase 2 (6-12 months)
- SA credit bureau integration (TransUnion SA first)
- WhatsApp link scanning
- Spam call filtering
- Password manager
- VPN integration (white-label or partner)

### Phase 3 (12-18 months)
- Full credit monitoring (all 4 SA bureaus)
- SAFPS automation
- SARS/CIPC/Deeds Office monitoring
- Identity theft insurance (partner with Phishield UMA / Bryte)
- Parental controls

### Phase 4 (18-24 months)
- Data broker removal (SA-specific)
- AI fraud detection
- Banking app integration
- Family plans
- B2B white-label for employers/insurers
