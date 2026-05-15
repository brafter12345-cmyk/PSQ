"""Bi-weekly benchmark scan runner.

Runs the security scanner against a curated list of SA reference
companies and persists results into the `benchmark_scans` table for
peer-rating percentile calculations (SCN-028).

Usage:
    py -3 benchmark_runner.py              # scan the full BENCHMARK_SEED list
    py -3 benchmark_runner.py --cell finance/Insurance Agents,Brokers,And Service
                                            # scan only entries in this cell
    py -3 benchmark_runner.py --dry-run    # show what would run, no actual scans

Cadence: invoke this every 2 weeks via cron / Render scheduled job /
manual operations. Pool freshness window is 90 days (peer_benchmarking.
FRESHNESS_DAYS) so a missed cycle does not break peer ratings.

Seed list curation: starts with JSE Top-40 + mid-market SA companies
covering the most-scanned industries. Expand by hand as Phishield needs
more peer cells. Each entry is (domain, industry, sub_industry,
approx_revenue_zar) - the revenue estimate is rough; the model only uses
it to assign a revenue_band so order-of-magnitude is sufficient.

Source classification: this script writes with source='benchmark_pool'
- public-domain scans, no consent needed. The two other source classes
('lower_tier_upsell' and 'client_optin') are written by the regular
scan flow when triggered by the appropriate UI / API path.
"""

import argparse
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Load .env from main project so API keys are available
HERE = Path(__file__).parent
env_path = HERE / ".env"
if not env_path.exists():
    env_path = Path("C:/Users/sarel/Desktop/Sarel/SML Consulting/PSQ/security_scanner/.env")
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

sys.path.insert(0, str(HERE))
from scanner import SecurityScanner
from peer_benchmarking import record_to_benchmark_pool, revenue_band


# ---------------------------------------------------------------------------
# Initial seed list — 60-90 SA reference companies across major industries.
# Expand by hand. Revenue is approximate (order of magnitude is what matters
# for the band assignment).
# Format: (domain, industry, sub_industry, approx_annual_revenue_zar, note)
# ---------------------------------------------------------------------------
BENCHMARK_SEED = [
    # ------------- FINANCIAL SERVICES -------------
    # Depository Institutions (banks) - all major SA banks
    ("standardbank.co.za",  "Finance",  "Depository Institutions", 200_000_000_000, "Standard Bank Group (JSE: SBK)"),
    ("nedbank.co.za",       "Finance",  "Depository Institutions", 130_000_000_000, "Nedbank Group (JSE: NED)"),
    ("absa.africa",         "Finance",  "Depository Institutions", 150_000_000_000, "Absa Group (JSE: ABG)"),
    ("firstrand.co.za",     "Finance",  "Depository Institutions", 180_000_000_000, "FirstRand (JSE: FSR)"),
    ("capitecbank.co.za",   "Finance",  "Depository Institutions",  50_000_000_000, "Capitec Bank (JSE: CPI)"),
    ("investec.com",        "Finance",  "Depository Institutions",  60_000_000_000, "Investec (JSE: INL)"),
    ("tymebank.co.za",      "Finance",  "Depository Institutions",   2_000_000_000, "TymeBank (digital, mid-tier)"),
    # Insurance Carriers
    ("sanlam.co.za",        "Finance",  "Insurance Carriers",       80_000_000_000, "Sanlam (JSE: SLM)"),
    ("oldmutual.co.za",     "Finance",  "Insurance Carriers",       90_000_000_000, "Old Mutual (JSE: OMU)"),
    ("discovery.co.za",     "Finance",  "Insurance Carriers",       70_000_000_000, "Discovery (JSE: DSY)"),
    ("santam.co.za",        "Finance",  "Insurance Carriers",       30_000_000_000, "Santam (JSE: SNT)"),
    ("momentum.co.za",      "Finance",  "Insurance Carriers",       50_000_000_000, "Momentum (JSE: MTM)"),
    ("libertyholdings.co.za","Finance", "Insurance Carriers",       40_000_000_000, "Liberty Holdings (JSE: LBH)"),
    ("outsurance.co.za",    "Finance",  "Insurance Carriers",       20_000_000_000, "OUTsurance Group (JSE: OUT)"),
    # Insurance Agents, Brokers, And Service
    ("aon.co.za",           "Finance",  "Insurance Agents, Brokers, And Service",  500_000_000, "Aon SA (broker)"),
    ("marsh.co.za",         "Finance",  "Insurance Agents, Brokers, And Service",  400_000_000, "Marsh SA (broker)"),
    ("willis.com",          "Finance",  "Insurance Agents, Brokers, And Service",  300_000_000, "WTW SA (broker)"),
    # Security and Commodity Brokers
    ("psg.co.za",           "Finance",  "Security And Commodity Brokers, Dealers, Exchanges, And Services", 5_000_000_000, "PSG Group (JSE: PSG)"),
    ("jse.co.za",           "Finance",  "Security And Commodity Brokers, Dealers, Exchanges, And Services", 3_000_000_000, "Johannesburg Stock Exchange"),
    # Real estate
    ("growthpoint.co.za",   "Finance",  "Real Estate",              10_000_000_000, "Growthpoint Properties (JSE: GRT)"),

    # ------------- HEALTHCARE / Health Services -------------
    ("netcare.co.za",       "Healthcare", "Health Services",        25_000_000_000, "Netcare hospital group"),
    ("lifehealthcare.co.za","Healthcare", "Health Services",        25_000_000_000, "Life Healthcare (JSE: LHC)"),
    ("mediclinic.com",      "Healthcare", "Health Services",        55_000_000_000, "Mediclinic International (JSE: MEI)"),
    ("aspen.co.za",         "Healthcare", "Health Services",        40_000_000_000, "Aspen Pharmacare (JSE: APN)"),
    ("dischem.co.za",       "Healthcare", "Health Services",        35_000_000_000, "Dis-Chem Pharmacies (JSE: DCP)"),
    ("clicks.co.za",        "Healthcare", "Health Services",        40_000_000_000, "Clicks Group (JSE: CLS)"),
    ("medicalsa.co.za",     "Healthcare", "Health Services",         1_000_000_000, "Medical scheme (mid-market)"),

    # ------------- TELECOMS / Communications -------------
    ("mtn.com",             "Communications", "Communications",     85_000_000_000, "MTN Group (JSE: MTN)"),
    ("vodacom.co.za",       "Communications", "Communications",    120_000_000_000, "Vodacom Group (JSE: VOD)"),
    ("telkom.co.za",        "Communications", "Communications",     40_000_000_000, "Telkom (JSE: TKG)"),
    ("rain.co.za",          "Communications", "Communications",      5_000_000_000, "Rain (mobile data)"),
    ("multichoice.co.za",   "Communications", "Communications",     55_000_000_000, "MultiChoice (JSE: MCG)"),

    # ------------- RETAIL -------------
    ("shoprite.co.za",      "Retail",   "Food Stores",             190_000_000_000, "Shoprite Holdings (JSE: SHP)"),
    ("picknpay.co.za",      "Retail",   "Food Stores",             100_000_000_000, "Pick n Pay Stores (JSE: PIK)"),
    ("spar.co.za",          "Retail",   "Food Stores",             140_000_000_000, "The SPAR Group (JSE: SPP)"),
    ("woolworths.co.za",    "Retail",   "General Merchandise Stores",80_000_000_000, "Woolworths Holdings (JSE: WHL)"),
    ("mrprice.com",         "Retail",   "Apparel And Accessory Stores",30_000_000_000, "Mr Price Group (JSE: MRP)"),
    ("truworths.co.za",     "Retail",   "Apparel And Accessory Stores",25_000_000_000, "Truworths International (JSE: TRU)"),
    ("takealot.com",        "Retail",   "Miscellaneous Retail",     10_000_000_000, "Takealot.com (online)"),

    # ------------- MANUFACTURING -------------
    ("sasol.com",           "Manufacturing", "Chemicals And Allied Products",   240_000_000_000, "Sasol (JSE: SOL)"),
    ("tigerbrands.com",     "Manufacturing", "Food And Kindred Products",        35_000_000_000, "Tiger Brands (JSE: TBS)"),
    ("distell.co.za",       "Manufacturing", "Food And Kindred Products",        30_000_000_000, "Distell Group (JSE: DGH)"),
    ("amplats.co.za",       "Manufacturing", "Primary Metal Industries",         80_000_000_000, "Anglo American Platinum (JSE: AMS)"),

    # ------------- MINING -------------
    ("angloamerican.com",   "Mining",   "Metal Mining",            200_000_000_000, "Anglo American (JSE: AGL)"),
    ("anglogoldashanti.com","Mining",   "Metal Mining",             80_000_000_000, "AngloGold Ashanti (JSE: ANG)"),
    ("goldfields.com",      "Mining",   "Metal Mining",             50_000_000_000, "Gold Fields (JSE: GFI)"),
    ("sibanyestillwater.com","Mining",  "Metal Mining",            120_000_000_000, "Sibanye Stillwater (JSE: SSW)"),
    ("implats.co.za",       "Mining",   "Metal Mining",             80_000_000_000, "Impala Platinum (JSE: IMP)"),
    ("exxaroresources.com", "Mining",   "Coal Mining",              30_000_000_000, "Exxaro Resources (JSE: EXX)"),

    # ------------- TECHNOLOGY -------------
    ("naspers.com",         "Technology", "Software and Technology",100_000_000_000, "Naspers (JSE: NPN)"),
    ("prosus.com",          "Technology", "Software and Technology", 80_000_000_000, "Prosus N.V. (JSE: PRX)"),
    ("ee.co.za",            "Technology", "Software and Technology",  1_000_000_000, "Datacentrix (mid-market IT)"),

    # ------------- TRANSPORTATION -------------
    ("imperial.co.za",      "Transportation", "Motor Freight Transportation And Warehousing", 40_000_000_000, "Imperial Logistics (JSE: IPL)"),
    ("bidvest.com",         "Transportation", "Transportation Services", 100_000_000_000, "The Bidvest Group (JSE: BVT)"),

    # ------------- SERVICES -------------
    ("barloworld.com",      "Services", "Business Services",         50_000_000_000, "Barloworld (JSE: BAW)"),
    ("aveng.co.za",         "Services", "Engineering, Accounting, Research, Management, And Related Services", 30_000_000_000, "Aveng (JSE: AEG)"),

    # ------------- PUBLIC SECTOR -------------
    ("treasury.gov.za",     "Public Sector", "Public Finance, Taxation, And Monetary Policy", 50_000_000_000, "National Treasury"),
    ("sars.gov.za",         "Public Sector", "Public Finance, Taxation, And Monetary Policy", 20_000_000_000, "SARS"),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_one_benchmark(entry, scanner, db_path):
    """Scan one entry and persist to the benchmark pool."""
    domain, industry, sub_industry, revenue_zar, note = entry
    print(f"\n--- {domain} ({industry} / {sub_industry}, rev~R{revenue_zar:,}) ---")
    t0 = time.perf_counter()
    try:
        scanner._regulatory_flags = None
        scanner._sub_industry = sub_industry
        results = scanner.scan(
            domain,
            industry=industry, annual_revenue=0,
            annual_revenue_zar=revenue_zar,
            country="ZA",
            include_fraudulent_domains=False,
        )
        elapsed = time.perf_counter() - t0
        # Make sure scan_context carries sub_industry / revenue (consumed
        # by peer_benchmarking + report flows)
        results.setdefault("scan_context", {})
        results["scan_context"]["sub_industry"] = sub_industry
        results["scan_context"]["annual_revenue_zar"] = revenue_zar
        # Persist to benchmark pool
        conn = sqlite3.connect(db_path)
        try:
            row_id = record_to_benchmark_pool(results, conn, source="benchmark_pool")
        finally:
            conn.close()
        score = results.get("overall_risk_score", "?")
        print(f"  OK  risk_score={score}  band={revenue_band(revenue_zar)}  elapsed={elapsed:.1f}s  row_id={row_id}")
        return True
    except Exception as e:
        elapsed = time.perf_counter() - t0
        print(f"  FAIL  elapsed={elapsed:.1f}s  error={e!r}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Bi-weekly benchmark scan runner")
    parser.add_argument("--cell", default=None,
                        help="Restrict to entries matching industry or industry/sub_industry")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show entries that would run, don't scan")
    parser.add_argument("--db-path", default=str(HERE / "scans.db"),
                        help="Path to scans.db (default: ./scans.db)")
    args = parser.parse_args()

    entries = list(BENCHMARK_SEED)
    if args.cell:
        cell_q = args.cell.lower()
        filtered = []
        for e in entries:
            ind = (e[1] or "").lower()
            sub = (e[2] or "").lower()
            if cell_q in ind or cell_q in sub or cell_q in f"{ind}/{sub}":
                filtered.append(e)
        entries = filtered

    print(f"Benchmark runner: {len(entries)} entries to process")
    print(f"DB path: {args.db_path}")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    if args.dry_run:
        for e in entries:
            print(f"  WOULD SCAN  {e[0]:30s}  ({e[1]} / {e[2]})  rev~R{e[3]:,}")
        return

    # Build scanner with available API keys
    scanner = SecurityScanner(
        hibp_api_key=os.environ.get("HIBP_API_KEY"),
        virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY"),
        securitytrails_api_key=os.environ.get("SECURITYTRAILS_API_KEY"),
        shodan_api_key=os.environ.get("SHODAN_API_KEY"),
    )

    success = fail = 0
    for entry in entries:
        if run_one_benchmark(entry, scanner, args.db_path):
            success += 1
        else:
            fail += 1

    print(f"\nFinished: {success} succeeded, {fail} failed")


if __name__ == "__main__":
    main()
