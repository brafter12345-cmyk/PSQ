"""
Comprehensive QA Test — Hybrid Financial Impact Model
Runs cached phishield.com scan data through the model across multiple profiles.
Saves results to QA_Test_Results.txt for review.
"""
import sqlite3, json, sys, io
from datetime import datetime
from scoring_analytics import FinancialImpactCalculator, RansomwareIndex, SA_INDUSTRY_COSTS

# Redirect output to file
output = io.StringIO()

def p(text=""):
    output.write(text + "\n")

conn = sqlite3.connect('scans.db')
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT results FROM scans WHERE domain LIKE '%phishield%' ORDER BY created_at DESC LIMIT 1").fetchone()
results = json.loads(row['results'])
cats = results.get('categories', {})
cats['credential_risk'] = {'risk_level': 'HIGH', 'risk_score': 30}

rsi_calc = RansomwareIndex()
calc = FinancialImpactCalculator()

p("=" * 100)
p(f"PHISHIELD HYBRID FINANCIAL IMPACT MODEL — QA TEST REPORT")
p(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
p(f"Scan data: phishield.com (cached)")
p("=" * 100)

# ══════════════════════════════════════════════════════════════
# TEST 1: Industry comparison at R200M (baseline size)
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 1: Industry comparison at R200M (baseline size mult = 1.00)")
p("=" * 80)
p(f"{'Industry':>25s} | {'RSI':>6s} | {'TEF':>5s} | {'p_breach':>8s} | {'Total':>12s} | {'Breach%':>7s} | {'D&E%':>5s} | {'Ransom%':>7s} | {'BI%':>5s} | {'RecCov':>10s}")
p("-" * 115)

for ind in ['Financial Services', 'Healthcare', 'Manufacturing', 'Retail', 'Public Sector', 'Technology', 'Services', 'Agriculture', 'Other']:
    rsi = rsi_calc.calculate(cats, industry=ind, annual_revenue=200_000_000)
    fin = calc.calculate(cats, rsi, 0, ind, annual_revenue_zar=200_000_000)
    t = fin['total']['most_likely']
    sc4 = fin['scenarios_4cat']
    pd = fin['probability_drivers']
    ins = fin['insurance_recommendation']
    b = sc4['data_breach']['estimated_loss']/t*100 if t > 0 else 0
    d = sc4['detection_escalation']['estimated_loss']/t*100 if t > 0 else 0
    r = sc4['ransom_demand']['estimated_loss']/t*100 if t > 0 else 0
    bi = sc4['business_interruption']['estimated_loss']/t*100 if t > 0 else 0
    p(f"{ind:>25s} | {rsi['rsi_score']:>6.3f} | {pd['tef']:>5.2f} | {pd['p_breach']*100:>7.1f}% | R{t:>10,} | {b:>6.1f}% | {d:>4.1f}% | {r:>6.1f}% | {bi:>4.1f}% | R{ins['recommended_cover_zar']:>8,}")

# ══════════════════════════════════════════════════════════════
# TEST 2: Size comparison for Financial Services
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 2: Size comparison — Financial Services across revenue bands")
p("=" * 80)
p(f"{'Revenue':>8s} | {'SM':>6s} | {'RSI':>6s} | {'EffMult':>7s} | {'Total':>12s} | {'%Rev':>6s} | {'Score':>5s} | {'MinCov':>10s} | {'RecCov':>10s}")
p("-" * 95)

for rev in [5_000_000, 10_000_000, 25_000_000, 50_000_000, 75_000_000, 100_000_000, 200_000_000, 500_000_000, 1_000_000_000]:
    rsi = rsi_calc.calculate(cats, industry='Financial Services', annual_revenue=rev)
    fin = calc.calculate(cats, rsi, 0, 'Financial Services', annual_revenue_zar=rev)
    t = fin['total']['most_likely']
    ins = fin['insurance_recommendation']
    pct = t/rev*100
    p(f"R{rev/1e6:>6.0f}M | {rsi['size_multiplier']:>6.3f} | {rsi['rsi_score']:>6.3f} | {'n/a':>7s} | R{t:>10,} | {pct:>5.1f}% | {fin['score']:>5d} | R{ins['minimum_cover_zar']:>8,} | R{ins['recommended_cover_zar']:>8,}")

# ══════════════════════════════════════════════════════════════
# TEST 3: Regulatory exposure comparison
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 3: Regulatory exposure — R200M Financial Services")
p("=" * 80)

for label, flags in [('POPIA only', {}), ('+GDPR', {'gdpr': True}), ('+PCI', {'pci': True}), ('+GDPR+PCI', {'gdpr': True, 'pci': True})]:
    rsi = rsi_calc.calculate(cats, industry='Financial Services', annual_revenue=200_000_000)
    fin = calc.calculate(cats, rsi, 0, 'Financial Services', annual_revenue_zar=200_000_000, regulatory_flags=flags)
    reg = fin['regulatory_exposure']
    t = fin['total']['most_likely']
    sc4 = fin['scenarios_4cat']
    p(f"\n--- {label} ---")
    p(f"  C2: POPIA R{reg['c2_popia']:,} + GDPR R{reg['c2_gdpr']:,} + PCI R{reg['c2_pci']:,} = R{reg['c2_total']:,}")
    p(f"  Total: R{t:,}")
    for key, data in sc4.items():
        pct = data['estimated_loss']/t*100 if t > 0 else 0
        p(f"    {data['label']:30s} R{data['estimated_loss']:>10,} ({pct:5.1f}%)")

# ══════════════════════════════════════════════════════════════
# TEST 4: Detailed phishield.com R10M breakdown
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 4: Detailed breakdown — phishield.com R10M Financial Services")
p("=" * 80)

rsi = rsi_calc.calculate(cats, industry='Financial Services', annual_revenue=10_000_000)
fin = calc.calculate(cats, rsi, 0, 'Financial Services', annual_revenue_zar=10_000_000)
total = fin['total']['most_likely']
sc4 = fin['scenarios_4cat']
pd = fin['probability_drivers']
mc = fin['monte_carlo']['total']
ins = fin['insurance_recommendation']

p(f"\nRSI: {rsi['rsi_score']} ({rsi['risk_label']})")
p(f"  Base: {rsi['base_score']} | Ind mult: {rsi['industry_multiplier']} | Size mult: {rsi['size_multiplier']}")
for f in rsi['contributing_factors']:
    p(f"    +{f['impact']:5.2f}  P{f['priority']}  {f['factor'][:65]}")

p(f"\np_breach: {pd['p_breach']} (vuln={pd['vulnerability']}, TEF={pd['tef']})")
p(f"Financial Impact Score: {fin['score']}")

p(f"\n4-Category Breakdown:")
for key, data in sc4.items():
    pct = data['estimated_loss']/total*100 if total > 0 else 0
    p(f"  {data['label']:30s} R{data['estimated_loss']:>10,} ({pct:5.1f}%)")
p(f"  {'TOTAL':30s} R{total:>10,} ({total/10e6*100:.1f}% of revenue)")

p(f"\nMonte Carlo: P5=R{mc['p5']:,} | P50=R{mc['p50']:,} | P75=R{mc['p75']:,} | P95=R{mc['p95']:,}")
p(f"Insurance: Min R{ins['minimum_cover_zar']:,} | Rec R{ins['recommended_cover_zar']:,} | Premium: {ins['premium_risk_tier']}")

p(f"\nIncident Types:")
for k, inc in fin['incident_types'].items():
    if inc['expected_loss'] > 0:
        per_ev = inc['expected_loss'] / inc['probability'] if inc['probability'] > 0 else 0
        p(f"  {inc['label']:40s} p={inc['probability']:.4f} | annual=R{inc['expected_loss']:>10,} | per-event=R{per_ev:>10,.0f}")

mit = fin.get('risk_mitigations', {})
p(f"\nMitigations: {len(mit['findings'])} findings")
p(f"  Current: R{mit['current_annual_loss']:>10,}")
p(f"  Savings: R{mit['total_potential_savings']:>10,}")
p(f"  After:   R{mit['mitigated_annual_loss']:>10,}")
for f in mit['findings']:
    p(f"    [{f['severity']:8s}] R{f['estimated_annual_savings_zar']:>8,}  {f['recommendation'][:55]}")

# ══════════════════════════════════════════════════════════════
# TEST 5: Clean company vs worst case
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 5: Sanity checks — clean vs worst posture (R200M Financial Services)")
p("=" * 80)

# Clean company
clean = dict(cats)
clean['_overall_score'] = 800
clean['shodan_vulns'] = {'cves': []}
clean['dehashed'] = {'total_entries': 0}
clean['breaches'] = {'breach_count': 0}
clean['waf'] = {'detected': True}
clean['ssl'] = {'score': 90, 'grade': 'A'}
clean['email_security'] = {'dmarc': {'present': True, 'policy': 'reject'}, 'spf': {'present': True}}
clean['credential_risk'] = {'risk_level': 'LOW', 'risk_score': 100}
clean['cloud_cdn'] = {'cdn_detected': True}
clean['dnsbl'] = {'blacklisted': False}
clean['vpn_remote'] = {'rdp_exposed': False}
clean['info_disclosure'] = {'exposed_paths': []}
clean['high_risk_protocols'] = {'exposed_services': []}

rsi_clean = rsi_calc.calculate(clean, industry='Financial Services', annual_revenue=200_000_000)
fin_clean = calc.calculate(clean, rsi_clean, 0, 'Financial Services', annual_revenue_zar=200_000_000)
p(f"\nClean company:  RSI {rsi_clean['rsi_score']} ({rsi_clean['risk_label']}) | Total R{fin_clean['total']['most_likely']:,} | {fin_clean['total']['most_likely']/200e6*100:.1f}% of rev | Score {fin_clean['score']} | Rec R{fin_clean['insurance_recommendation']['recommended_cover_zar']:,}")

# Worst case
worst = dict(cats)
worst['_overall_score'] = 100
worst['vpn_remote'] = {'rdp_exposed': True}
worst['credential_risk'] = {'risk_level': 'CRITICAL', 'risk_score': 0, 'active_compromise': True}

rsi_worst = rsi_calc.calculate(worst, industry='Financial Services', annual_revenue=200_000_000)
fin_worst = calc.calculate(worst, rsi_worst, 0, 'Financial Services', annual_revenue_zar=200_000_000)
p(f"Worst company:  RSI {rsi_worst['rsi_score']} ({rsi_worst['risk_label']}) | Total R{fin_worst['total']['most_likely']:,} | {fin_worst['total']['most_likely']/200e6*100:.1f}% of rev | Score {fin_worst['score']} | Rec R{fin_worst['insurance_recommendation']['recommended_cover_zar']:,}")

p(f"\nClean/Worst ratio: {fin_worst['total']['most_likely'] / fin_clean['total']['most_likely']:.1f}x")

# ══════════════════════════════════════════════════════════════
# TEST 6: Standard FAIR comparison
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 6: Standard FAIR (USD) vs Hybrid (ZAR) — R10M Financial Services")
p("=" * 80)

usd_rev = 10_000_000 / 18.02
rsi_usd = rsi_calc.calculate(cats, industry='Financial Services', annual_revenue=usd_rev)
fin_usd = calc.calculate(cats, rsi_usd, usd_rev, 'Financial Services', annual_revenue_zar=0)
usd_total = fin_usd.get('total', {}).get('most_likely', 0)

p(f"\nStandard FAIR (USD):  ${usd_total:,.0f} (R{usd_total*18.02:,.0f} at R18.02)")
p(f"Hybrid model (ZAR):   R{total:,}")
p(f"Delta: {((total - usd_total*18.02) / (usd_total*18.02) * 100) if usd_total > 0 else 0:+.1f}%")

# ══════════════════════════════════════════════════════════════
# TEST 7: Max p_breach sanity
# ══════════════════════════════════════════════════════════════
p("\n" + "=" * 80)
p("TEST 7: Max p_breach at worst posture (score 0)")
p("=" * 80)
for ind in ['Financial Services', 'Healthcare', 'Manufacturing', 'Agriculture']:
    from scoring_analytics import FinancialImpactCalculator as FIC
    tef = FIC.THREAT_EVENT_FREQUENCY.get(ind.title(), 1.0)
    p_max = min(1.0, 1.0 * tef * 0.3)
    p(f"  {ind:>25s}: TEF={tef:.2f} -> p_max={p_max:.1%}")

p("\n" + "=" * 80)
p("END OF QA TEST REPORT")
p("=" * 80)

# Write to file
result_text = output.getvalue()
with open('QA_Test_Results.txt', 'w', encoding='utf-8') as f:
    f.write(result_text)
print(f"QA test saved to QA_Test_Results.txt ({len(result_text):,} chars)")
print(result_text[:200] + "...")
