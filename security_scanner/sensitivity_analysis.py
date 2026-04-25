"""
FAIR Model Sensitivity Analysis
One-at-a-time (OAT) perturbation of each editable parameter to measure
% impact on total estimated annual loss (ZAR).

Reference profile: R100M revenue, "Other" industry, moderate scan posture.
"""

import json, math

# ── SA Industry cost data (from scoring_analytics.py SA_INDUSTRY_COSTS) ──
SA_INDUSTRY_COSTS = {
    "Other": {"breach_cost_zar": 44_100_000, "cost_per_record": 1881, "multiplier": 1.00},
}

# ── Reference company profile ──
REF_REVENUE = 100_000_000  # R100M
REF_INDUSTRY = "Other"
REF_OVERALL_SCORE = 550     # moderate posture (out of 1000)
REF_RSI_SCORE = 0.30        # moderate RSI
REF_WAF = False
REF_CDN = False
REF_SINGLE_ASN = True


def calc_breach(revenue, overall_score, multiplier, cost_per_record, records_divisor, popia_pct):
    """Scenario 1: Data Breach loss."""
    p_breach = min(1.0, max(0.0, ((100 - overall_score / 10) / 100) * multiplier * 0.3))
    estimated_records = max(100, revenue // records_divisor)
    regulatory_fine = revenue * popia_pct
    return p_breach * (estimated_records * cost_per_record + regulatory_fine)


def calc_ransomware(revenue, rsi_score, downtime_days, revenue_loss_pct,
                    ransom_estimate, ir_cost):
    """Scenario 2: Ransomware loss."""
    daily_revenue = revenue / 365
    return rsi_score * (downtime_days * daily_revenue * revenue_loss_pct + ransom_estimate + ir_cost)


def calc_bi(revenue, p_base, waf_p, cdn_p, asn_p, p_cap,
            bi_days, impact_base, waf_i, cdn_i, asn_i, impact_cap,
            waf_detected, cdn_detected, single_asn):
    """Scenario 3: Business Interruption loss."""
    daily_revenue = revenue / 365
    p = p_base + (waf_p if not waf_detected else 0) + (cdn_p if not cdn_detected else 0) + (asn_p if single_asn else 0)
    p = min(p_cap, p)
    impact = impact_base + (waf_i if not waf_detected else 0) + (cdn_i if not cdn_detected else 0) + (asn_i if single_asn else 0)
    impact = min(impact_cap, impact)
    return p * (bi_days * daily_revenue * impact)


# ── Default parameter values ──
DEFAULTS = {
    # Scenario 1: Data Breach
    "industry_multiplier":   1.00,
    "cost_per_record":       1881,
    "records_divisor":       50_000,
    "popia_pct":             0.02,
    "overall_score":         REF_OVERALL_SCORE,

    # Scenario 2: Ransomware
    "rsi_score":             REF_RSI_SCORE,
    "downtime_days":         22,
    "revenue_loss_pct":      0.50,
    "ransom_estimate":       2_500_000,   # R50M-R200M tier
    "ir_cost":               1_500_000,

    # Scenario 3: Business Interruption
    "bi_p_base":             0.05,
    "bi_waf_p":              0.05,
    "bi_cdn_p":              0.05,
    "bi_asn_p":              0.05,
    "bi_p_cap":              0.50,
    "bi_days":               5,
    "bi_impact_base":        0.30,
    "bi_waf_i":              0.15,
    "bi_cdn_i":              0.15,
    "bi_asn_i":              0.10,
    "bi_impact_cap":         0.80,

    # Cross-cutting
    "annual_revenue":        REF_REVENUE,
}

# Map each parameter to its scenario, description, code reference and doc section
PARAM_META = {
    "annual_revenue":      {"scenario": "All",       "section": "Cross-cutting",     "desc": "Annual revenue (ZAR) - scales records, fines, daily revenue",             "code": "annual_revenue_zar (input)"},
    "industry_multiplier": {"scenario": "Breach",    "section": "1 (SA Industry)",   "desc": "Industry breach cost multiplier from IBM data",                            "code": "industry_data['multiplier'] line 1272"},
    "cost_per_record":     {"scenario": "Breach",    "section": "1 (SA Industry)",   "desc": "Cost per compromised record (ZAR)",                                        "code": "industry_data['cost_per_record'] line 1274"},
    "records_divisor":     {"scenario": "Breach",    "section": "4 (Data Breach)",   "desc": "Revenue / divisor = estimated records; lower divisor = more records",       "code": "revenue_zar // 50_000 line 1273"},
    "popia_pct":           {"scenario": "Breach",    "section": "2 (POPIA Fines)",   "desc": "POPIA regulatory fine as % of annual turnover",                             "code": "revenue * 0.02 line 1275"},
    "overall_score":       {"scenario": "Breach",    "section": "4 (Data Breach)",   "desc": "Scanner overall score (0-1000); drives p_breach via formula",               "code": "((100 - score/10)/100)*mult*0.3 line 1272"},
    "rsi_score":           {"scenario": "Ransomware","section": "3 (RSI)",           "desc": "Ransomware Susceptibility Index (0.0-1.0); probability multiplier",         "code": "rsi_score line 1292"},
    "downtime_days":       {"scenario": "Ransomware","section": "5 (Ransomware)",    "desc": "Average ransomware recovery downtime in days",                              "code": "avg_downtime_days=22 line 1279"},
    "revenue_loss_pct":    {"scenario": "Ransomware","section": "5 (Ransomware)",    "desc": "% of daily revenue lost during downtime (partial ops)",                     "code": "daily_revenue * 0.5 line 1292"},
    "ransom_estimate":     {"scenario": "Ransomware","section": "5 (Ransomware)",    "desc": "Expected ransom demand for company size tier (ZAR)",                        "code": "ransom_estimate tiered line 1280-1291"},
    "ir_cost":             {"scenario": "Ransomware","section": "5 (Ransomware)",    "desc": "Incident response cost for company size tier (ZAR)",                        "code": "ir_cost tiered line 1280-1291"},
    "bi_p_base":           {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Base probability of business interruption",                                "code": "0.05 line 1298"},
    "bi_waf_p":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added probability if no WAF detected",                                     "code": "+0.05 line 1298"},
    "bi_cdn_p":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added probability if no CDN detected",                                     "code": "+0.05 line 1298"},
    "bi_asn_p":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added probability if single ASN (no redundancy)",                           "code": "+0.05 line 1298"},
    "bi_p_cap":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Maximum probability cap for BI scenario",                                  "code": "min(0.5,...) line 1298"},
    "bi_days":             {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Average business interruption duration (days)",                             "code": "5 line 1300"},
    "bi_impact_base":      {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Base proportion of revenue lost during interruption",                       "code": "0.30 line 1299"},
    "bi_waf_i":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added impact factor if no WAF",                                             "code": "+0.15 line 1299"},
    "bi_cdn_i":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added impact factor if no CDN",                                             "code": "+0.15 line 1299"},
    "bi_asn_i":            {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Added impact factor if single ASN",                                         "code": "+0.10 line 1299"},
    "bi_impact_cap":       {"scenario": "BI",        "section": "6 (Bus. Interrupt.)","desc": "Maximum impact factor cap",                                                 "code": "min(0.80,...) line 1299"},
}


def total_loss(params):
    """Calculate total annual loss from all three scenarios."""
    rev = params["annual_revenue"]

    breach = calc_breach(
        rev, params["overall_score"], params["industry_multiplier"],
        params["cost_per_record"], params["records_divisor"], params["popia_pct"])

    ransomware = calc_ransomware(
        rev, params["rsi_score"], params["downtime_days"],
        params["revenue_loss_pct"], params["ransom_estimate"], params["ir_cost"])

    bi = calc_bi(
        rev, params["bi_p_base"], params["bi_waf_p"], params["bi_cdn_p"],
        params["bi_asn_p"], params["bi_p_cap"], params["bi_days"],
        params["bi_impact_base"], params["bi_waf_i"], params["bi_cdn_i"],
        params["bi_asn_i"], params["bi_impact_cap"],
        REF_WAF, REF_CDN, REF_SINGLE_ASN)

    return breach, ransomware, bi, breach + ransomware + bi


def scenario_loss(params, scenario):
    """Get loss for a specific scenario."""
    b, r, bi, t = total_loss(params)
    return {"Breach": b, "Ransomware": r, "BI": bi, "All": t}[scenario]


def run_sensitivity(perturbation=0.25):
    """Run OAT sensitivity: +/- perturbation on each parameter."""
    base_b, base_r, base_bi, base_total = total_loss(DEFAULTS)

    results = []
    for param_name, default_val in DEFAULTS.items():
        meta = PARAM_META[param_name]

        # For each parameter, compute loss at +25% and -25%
        for direction, factor in [("up", 1 + perturbation), ("down", 1 - perturbation)]:
            perturbed = dict(DEFAULTS)
            perturbed[param_name] = default_val * factor

            pb, pr, pbi, ptotal = total_loss(perturbed)
            delta_total = ptotal - base_total
            pct_change = (delta_total / base_total * 100) if base_total > 0 else 0

            # Per-scenario deltas
            delta_breach = pb - base_b
            delta_ransom = pr - base_r
            delta_bi = pbi - base_bi

            results.append({
                "parameter": param_name,
                "direction": direction,
                "default_value": default_val,
                "perturbed_value": round(default_val * factor, 4),
                "scenario": meta["scenario"],
                "section": meta["section"],
                "description": meta["desc"],
                "code_ref": meta["code"],
                "base_total": round(base_total),
                "perturbed_total": round(ptotal),
                "delta_total": round(delta_total),
                "pct_change_total": round(pct_change, 2),
                "delta_breach": round(delta_breach),
                "delta_ransom": round(delta_ransom),
                "delta_bi": round(delta_bi),
            })

    # Compute max absolute % change per parameter (for ranking)
    param_max = {}
    for r in results:
        key = r["parameter"]
        absval = abs(r["pct_change_total"])
        if key not in param_max or absval > param_max[key]["max_abs_pct"]:
            param_max[key] = {
                "parameter": key,
                "max_abs_pct": absval,
                "scenario": r["scenario"],
                "section": r["section"],
                "description": r["description"],
                "code_ref": r["code_ref"],
                "default_value": r["default_value"],
            }

    ranking = sorted(param_max.values(), key=lambda x: -x["max_abs_pct"])
    for i, r in enumerate(ranking):
        r["rank"] = i + 1
        if r["max_abs_pct"] >= 15:
            r["sensitivity"] = "High"
        elif r["max_abs_pct"] >= 5:
            r["sensitivity"] = "Medium"
        else:
            r["sensitivity"] = "Low"

    output = {
        "reference_profile": {
            "annual_revenue_zar": REF_REVENUE,
            "industry": REF_INDUSTRY,
            "overall_score": REF_OVERALL_SCORE,
            "rsi_score": REF_RSI_SCORE,
            "waf_detected": REF_WAF,
            "cdn_detected": REF_CDN,
            "single_asn": REF_SINGLE_ASN,
        },
        "base_losses": {
            "data_breach": round(base_b),
            "ransomware": round(base_r),
            "business_interruption": round(base_bi),
            "total": round(base_total),
        },
        "perturbation": f"+/- {int(perturbation*100)}%",
        "detailed_results": results,
        "ranking": ranking,
    }
    return output


if __name__ == "__main__":
    result = run_sensitivity()
    print(json.dumps(result, indent=2))
