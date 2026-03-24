/**
 * SME Rating Engine — Data Layer
 * Cyber Protect Business Policy (Risk Rated)
 * Phishield UMA (Pty) Ltd / Bryte Insurance Company Limited
 *
 * All premium data, formulas, modifiers, and reference tables.
 * Update this file when product specs, competitor benchmarks, or market conditions change.
 *
 * Last updated: 2026-03-23
 */

// ─── Market Condition (update annually) ────────────────────────────────────────
// Values: "softening" | "stable" | "hardening"
const MARKET_CONDITION = "softening";
const MARKET_CONDITION_YEAR = 2026;
const MARKET_CONDITION_LABEL = "Softening market for 2026";

// ─── Revenue Bands ─────────────────────────────────────────────────────────────
const REVENUE_BANDS = [
  { key: "0-10M",     label: "R0 \u2013 R10M",     min: 0,           max: 10_000_000  },
  { key: "10M-25M",   label: "R10M \u2013 R25M",   min: 10_000_001,  max: 25_000_000  },
  { key: "25M-50M",   label: "R25M \u2013 R50M",   min: 25_000_001,  max: 50_000_000  },
  { key: "50M-75M",   label: "R50M \u2013 R75M",   min: 50_000_001,  max: 75_000_000  },
  { key: "75M-100M",  label: "R75M \u2013 R100M",  min: 75_000_001,  max: 100_000_000 },
  { key: "100M-150M", label: "R100M \u2013 R150M", min: 100_000_001, max: 150_000_000 },
  { key: "150M-200M", label: "R150M \u2013 R200M", min: 150_000_001, max: 200_000_000 },
];

// ─── Cover Limits ──────────────────────────────────────────────────────────────
const COVER_LIMITS = [
  { key: "1M",   value: 1_000_000,   label: "R1M",   excess: 10_000 },
  { key: "2.5M", value: 2_500_000,   label: "R2.5M", excess: 10_000 },
  { key: "5M",   value: 5_000_000,   label: "R5M",   excess: 10_000 },
  { key: "7.5M", value: 7_500_000,   label: "R7.5M", excess: 15_000 },
  { key: "10M",  value: 10_000_000,  label: "R10M",  excess: 20_000 },
  { key: "15M",  value: 15_000_000,  label: "R15M",  excess: 25_000 },
];

// ─── SME Standard Premium Table (annual, VAT inclusive) ────────────────────────
// Indexed: SME_PREMIUMS[revenueBandIndex][coverLimitIndex]
// This is the consolidated view; formulas below are used for precise calculation.
const SME_PREMIUMS = [
  // R1M,   R2.5M,  R5M,    R7.5M,  R10M,   R15M
  [7872,   9060,   11160,  15816,  20184,  27816],   // R0-R10M
  [9612,   11268,  14148,  19428,  23988,  31788],   // R10M-R25M
  [11340,  13464,  17124,  23028,  27792,  35760],   // R25M-R50M
  [14040,  17172,  24072,  30228,  35436,  41928],   // R50M-R75M
  [16488,  22440,  28332,  33660,  39480,  47832],   // R75M-R100M
  [18804,  24144,  30300,  37476,  43248,  52824],   // R100M-R150M
  [22608,  28116,  33396,  41112,  46644,  58524],   // R150M-R200M
];

// ─── Premium Formulas (per cover limit tab) ────────────────────────────────────
// Formula: annualPremium = (rateCoeff * actualTurnover) + adjustment
// Indexed by revenue band (starting from band 1 = R10M-R25M; band 0 uses Micro or flat rate)
// Each array: [R10M-R25M, R25M-R50M, R50M-R75M, R75M-R100M, R100M-R150M, R150M-R200M]
const PREMIUM_FORMULAS = {
  "1M": {
    rateCoeffs:  [0.000116,    0.00006912,  0.000108,    0.00009792,  0.00004632,  0.00007608],
    adjustments: [4612,        5784,        3840,        4596,        9756,        5292],
  },
  "2.5M": {
    rateCoeffs:  [0.0001472,   0.00008784,  0.00014832,  0.00021072,  0.00003408,  0.00007944],
    adjustments: [4972,        6456,        3432,        -1248,       16416,       9612],
  },
  "5M": {
    rateCoeffs:  [0.0001992,   0.00011904,  0.00027792,  0.0001704,   0.00003936,  0.00006192],
    adjustments: [6024,        8028,        84,          8148,        21252,       17868],
  },
  "7.5M": {
    rateCoeffs:  [0.0002408,   0.000144,    0.000288,    0.00013728,  0.00007632,  0.00007272],
    adjustments: [8608,        11028,       3828,        15132,       21228,       21768],
  },
  "10M": {
    rateCoeffs:  [0.0002536,   0.00015216,  0.00030576,  0.00016176,  0.00007536,  0.00006792],
    adjustments: [8540,        11076,       3396,        14196,       22836,       23952],
  },
  "15M": {
    rateCoeffs:  [0.0002648,   0.00015888,  0.00024672,  0.00023616,  0.00009984,  0.000114],
    adjustments: [9412,        12060,       7668,        8460,        22092,       19968],
  },
};

// ─── Micro SME Premium Table ───────────────────────────────────────────────────
// Base premium and base FP are SEPARATE amounts. Total = base + FP.
const MICRO_PREMIUMS = {
  "1M":   { basePremium: 4164, baseFPCost: 2100 },
  "2.5M": { basePremium: 5904, baseFPCost: 2616 },
  "5M":   { basePremium: 7908, baseFPCost: 3144 },
};

// ─── Funds Protect (FP) Data ───────────────────────────────────────────────────
// Minimum (base) FP limit per cover limit — cannot go below this
const BASE_FP_BY_COVER = {
  "1M":   150_000,
  "2.5M": 200_000,
  "5M":   250_000,
  "7.5M": 500_000,
  "10M":  1_000_000,
  "15M":  1_500_000,
};

// FP tier costs (annual premium for each FP limit level)
const FP_COSTS = [
  { limit: 150_000,   label: "R150k",  cost: 2100  },
  { limit: 200_000,   label: "R200k",  cost: 2616  },
  { limit: 250_000,   label: "R250k",  cost: 3144  },
  { limit: 500_000,   label: "R500k",  cost: 4800  },
  { limit: 1_000_000, label: "R1M",    cost: 9108  },
  { limit: 1_500_000, label: "R1.5M",  cost: 15756 },
  { limit: 2_000_000, label: "R2M",    cost: 26640 },
  { limit: 3_000_000, label: "R3M",    cost: 42420 },
  { limit: 4_000_000, label: "R4M",    cost: 56760 },
  { limit: 5_000_000, label: "R5M",    cost: 71160 },
];

// Get available FP options for a given cover limit (can't go below base)
function getAvailableFPOptions(coverLimitKey) {
  const baseFP = BASE_FP_BY_COVER[coverLimitKey];
  return FP_COSTS.filter(fp => fp.limit >= baseFP);
}

// Get the base FP cost for a cover limit
function getBaseFPCost(coverLimitKey) {
  const baseFP = BASE_FP_BY_COVER[coverLimitKey];
  const entry = FP_COSTS.find(fp => fp.limit === baseFP);
  return entry ? entry.cost : 0;
}

// ─── Industry Modifiers ────────────────────────────────────────────────────────
// Applied to base premium ONLY (not FP). Indexed by band starting from R0-R10M.
// Modifier of 1.0 = no change (industry average).
// Other industries not listed here use 1.0 across all bands.
const INDUSTRY_MODIFIERS = {
  "Software and Technology": [1.10, 1.25, 1.35, 1.45, 1.55, 1.67],
  "Finance":                 [1.00, 1.06, 1.12, 1.20, 1.30, 1.40],
};

// Map finance sub-industries to the "Finance" modifier key
const FINANCE_SUB_INDUSTRIES = [
  "Depository Institutions",
  "Non-depository Credit Institutions",
  "Security And Commodity Brokers, Dealers, Exchanges, And Services",
  "Insurance Carriers",
  "Insurance Agents, Brokers, And Service",
  "Real Estate",
  "Holding And Other Investment Offices",
];

// ─── IToo Benchmark Table (2024) ──────────────────────────────────────────────
// Competitor pricing for comparison. FP not included by IToo.
// Update annually with new competitor data.
const ITOO_BENCHMARKS = [
  // { bracket, deductible, premiums: [R1M, R2.5M, R5M, R7.5M, R10M, R15M] }
  { bracket: "R10M-R25M",   min: 10_000_001, max: 25_000_000,  deductible: 5000,   premiums: [5375,  8485,  11805, 14985, 18165, 27225] },
  { bracket: "R25M-R50M",   min: 25_000_001, max: 50_000_000,  deductible: 10000,  premiums: [7225,  11365, 16405, 19975, 23625, 31565] },
  { bracket: "R50M-R100M",  min: 50_000_001, max: 100_000_000, deductible: 15000,  premiums: [8775,  13895, 19970, 24350, 28745, 38405] },
  { bracket: "R100M-R150M", min: 100_000_001,max: 150_000_000, deductible: 25000,  premiums: [9805,  15485, 22305, 27175, 32050, 42825] },
  { bracket: "R150M-R200M", min: 150_000_001,max: 200_000_000, deductible: 50000,  premiums: [10485, 16550, 23795, 29005, 34175, 45685] },
  { bracket: "R200M-R250M", min: 200_000_001,max: 250_000_000, deductible: 75000,  premiums: [11765, 18585, 26775, 32615, 39270, 51395] },
  { bracket: "R250M+",      min: 250_000_001,max: Infinity,    deductible: 100000, premiums: [13425, 21205, 30910, 37215, 43905, 58680] },
];

// ─── Industries ────────────────────────────────────────────────────────────────
const INDUSTRIES = [
  // Agriculture, Forestry, And Fishing
  { main: "Agriculture, Forestry, And Fishing", sub: "Agricultural Production Crops",                          referForUW: false },
  { main: "Agriculture, Forestry, And Fishing", sub: "Agriculture Production Livestock And Animal Specialties", referForUW: false },
  { main: "Agriculture, Forestry, And Fishing", sub: "Agricultural Services",                                  referForUW: false },
  { main: "Agriculture, Forestry, And Fishing", sub: "Forestry",                                               referForUW: false },
  { main: "Agriculture, Forestry, And Fishing", sub: "Fishing, Hunting And Trapping",                          referForUW: false },

  // Mining
  { main: "Mining", sub: "Metal Mining",                                              referForUW: false },
  { main: "Mining", sub: "Coal Mining",                                               referForUW: false },
  { main: "Mining", sub: "Oil And Gas Extraction",                                    referForUW: false },
  { main: "Mining", sub: "Mining And Quarrying Of Nonmetallic Minerals, Except Fuels", referForUW: false },

  // Construction
  { main: "Construction", sub: "Building Construction General Contractors And Operative Builders", referForUW: false },
  { main: "Construction", sub: "Heavy Construction Other Than Building Construction Contractors",  referForUW: false },
  { main: "Construction", sub: "Construction Special Trade Contractors",                           referForUW: false },

  // Manufacturing
  { main: "Manufacturing", sub: "Food And Kindred Products",                                                                             referForUW: false },
  { main: "Manufacturing", sub: "Tobacco Products",                                                                                      referForUW: false },
  { main: "Manufacturing", sub: "Textile Mill Products",                                                                                  referForUW: false },
  { main: "Manufacturing", sub: "Apparel And Other Finished Products Made From Fabrics And Similar Materials",                            referForUW: false },
  { main: "Manufacturing", sub: "Lumber And Wood Products, Except Furniture",                                                             referForUW: false },
  { main: "Manufacturing", sub: "Furniture And Fixtures",                                                                                 referForUW: false },
  { main: "Manufacturing", sub: "Paper And Allied Products",                                                                              referForUW: false },
  { main: "Manufacturing", sub: "Printing, Publishing, And Allied Industries",                                                            referForUW: false },
  { main: "Manufacturing", sub: "Chemicals And Allied Products",                                                                          referForUW: false },
  { main: "Manufacturing", sub: "Petroleum Refining And Related Industries",                                                              referForUW: false },
  { main: "Manufacturing", sub: "Rubber And Miscellaneous Plastics Products",                                                             referForUW: false },
  { main: "Manufacturing", sub: "Leather And Leather Products",                                                                           referForUW: false },
  { main: "Manufacturing", sub: "Stone, Clay, Glass, And Concrete Products",                                                              referForUW: false },
  { main: "Manufacturing", sub: "Primary Metal Industries",                                                                               referForUW: false },
  { main: "Manufacturing", sub: "Fabricated Metal Products, Except Machinery And Transportation Equipment",                               referForUW: false },
  { main: "Manufacturing", sub: "Industrial And Commercial Machinery And Computer Equipment",                                             referForUW: false },
  { main: "Manufacturing", sub: "Electronic And Other Electrical Equipment And Components, Except Computer Equipment",                    referForUW: false },
  { main: "Manufacturing", sub: "Transportation Equipment",                                                                               referForUW: false },
  { main: "Manufacturing", sub: "Measuring, Analyzing, And Controlling Instruments; Photographic, Medical And Optical Goods; Watches And Clocks", referForUW: false },
  { main: "Manufacturing", sub: "Miscellaneous Manufacturing Industries",                                                                 referForUW: false },

  // Transportation, Communications, Electric, Gas and Sanitary Services
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Railroad Transportation",                                               referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Local And Suburban Transit And Interurban Highway Passenger Transportation", referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Motor Freight Transportation And Warehousing",                           referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Postal Service",                                                        referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Water Transportation",                                                  referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Transportation By Air",                                                 referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Pipelines, Except Natural Gas",                                         referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Transportation Services",                                               referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Communications",                                                        referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Electric, Gas, And Sanitary Services",                                  referForUW: false },
  { main: "Transportation, Communications, Electric, Gas And Sanitary Services", sub: "Water And Waste Management",                                            referForUW: false },

  // Wholesale Trade
  { main: "Wholesale Trade", sub: "Wholesale Trade-Durable Goods",      referForUW: false },
  { main: "Wholesale Trade", sub: "Wholesale Trade-Non-durable Goods",  referForUW: false },

  // Retail Trade
  { main: "Retail Trade", sub: "eCommerce",                                                          referForUW: false },
  { main: "Retail Trade", sub: "Building Materials, Hardware, Garden Supply, And Mobile Home Dealers", referForUW: false },
  { main: "Retail Trade", sub: "General Merchandise Stores",                                          referForUW: false },
  { main: "Retail Trade", sub: "Food Stores",                                                         referForUW: false },
  { main: "Retail Trade", sub: "Automotive Dealers And Gasoline Service Stations",                    referForUW: false },
  { main: "Retail Trade", sub: "Apparel And Accessory Stores",                                        referForUW: false },
  { main: "Retail Trade", sub: "Home Furniture, Furnishings, And Equipment Stores",                   referForUW: false },
  { main: "Retail Trade", sub: "Eating And Drinking Places",                                          referForUW: false },
  { main: "Retail Trade", sub: "Miscellaneous Retail",                                                referForUW: false },

  // Finance, Insurance, And Real Estate
  { main: "Finance, Insurance, And Real Estate", sub: "Depository Institutions",                                              referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Non-depository Credit Institutions",                                   referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Security And Commodity Brokers, Dealers, Exchanges, And Services",     referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Insurance Carriers",                                                   referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Insurance Agents, Brokers, And Service",                               referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Real Estate",                                                          referForUW: false },
  { main: "Finance, Insurance, And Real Estate", sub: "Holding And Other Investment Offices",                                 referForUW: false },

  // Services
  { main: "Services", sub: "Hotels, Rooming Houses, Camps, And Other Lodging Places",              referForUW: false },
  { main: "Services", sub: "Personal Services",                                                     referForUW: false },
  { main: "Services", sub: "Business Services",                                                     referForUW: false },
  { main: "Services", sub: "Automotive Repair, Services, And Parking",                              referForUW: false },
  { main: "Services", sub: "Miscellaneous Repair Services",                                         referForUW: false },
  { main: "Services", sub: "Motion Pictures",                                                       referForUW: false },
  { main: "Services", sub: "Amusement And Recreation Services",                                     referForUW: false },
  { main: "Services", sub: "Legal Services",                                                        referForUW: false },
  { main: "Services", sub: "Educational Services",                                                  referForUW: false },
  { main: "Services", sub: "Social Services",                                                       referForUW: false },
  { main: "Services", sub: "Museums, Art Galleries, And Botanical And Zoological Gardens",          referForUW: false },
  { main: "Services", sub: "Membership Organisations",                                              referForUW: false },
  { main: "Services", sub: "Engineering, Accounting, Research, Management, And Related Services",   referForUW: false },
  { main: "Services", sub: "Private Households",                                                    referForUW: false },
  { main: "Services", sub: "Miscellaneous Services",                                                referForUW: false },
  { main: "Services", sub: "Software and Technology",                                               referForUW: false },

  // Healthcare (always refer for underwriting)
  { main: "Healthcare", sub: "Healthcare Services",  referForUW: true },
  { main: "Healthcare", sub: "Hospitals",            referForUW: true },
  { main: "Healthcare", sub: "Medical Practices",    referForUW: true },
  { main: "Healthcare", sub: "Pharmacies",           referForUW: true },

  // Public Administration (always refer for underwriting)
  { main: "Public Administration", sub: "Government Services",              referForUW: true },
  { main: "Public Administration", sub: "Non-classifiable Establishments",  referForUW: true },
];

// ─── Cover Limit Availability per Turnover Band (from Quote Options tab) ───────
// Values: "recommended" | "optional" | "request-only" | null (not available)
// Indexed: COVER_AVAILABILITY[revenueBandIndex][coverLimitIndex]
const COVER_AVAILABILITY = [
  // R1M,           R2.5M,          R5M,            R7.5M,          R10M,           R15M
  ["recommended",  "recommended",  "optional",     "optional",     "optional",     "optional"],     // R0-R10M
  ["optional",     "recommended",  "recommended",  "optional",     "optional",     "optional"],     // R10M-R25M
  ["optional",     "recommended",  "recommended",  "optional",     "optional",     "optional"],     // R25M-R50M
  ["request-only", "optional",     "recommended",  "recommended",  "optional",     "optional"],     // R50M-R75M
  [null,           "optional",     "optional",     "recommended",  "recommended",  "optional"],     // R75M-R100M
  [null,           null,           "optional",     "recommended",  "recommended",  "optional"],     // R100M-R150M
  [null,           null,           "optional",     "optional",     "recommended",  "recommended"],   // R150M-R200M
];

// ─── Underwriting Questions ────────────────────────────────────────────────────
const UNDERWRITING_QUESTIONS = [
  {
    id: "Q1",
    text: "Does Your Business have an active, comprehensive, paid for internet security software installed on all computer systems?",
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q2",
    text: "Data Back-Up",
    isCompound: true,
    subQuestions: [
      { id: "Q2.1", text: "Do you back up your data on a weekly basis?" },
      { id: "Q2.2", text: "Do you perform recovery testing at least once per year?" },
    ],
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q3",
    text: "Is your data stored separately from your main computer e.g. via the cloud or on an offline hard disk?",
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q4",
    text: "Do you regularly update and patch your computers so that they always have the latest security patches installed?",
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q5",
    text: "Are all the emails received and sent by your workplace computers and network checked for viruses/malware via an email filter?",
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q6",
    text: "Are your employees regularly advised about the secure use of their workplace computer, especially regarding the dangers of using the internet/email?",
    alwaysVisible: true,
    fpDependent: false,
  },
  {
    id: "Q7",
    text: "Do you have documented procedures in place for the following:",
    isCompound: true,
    subQuestions: [
      { id: "Q7.1", text: "vetting of new vendors/customers/payees?" },
      { id: "Q7.2", text: "to verify new beneficiaries loaded onto your business\u2019s banking profiles for funds transfers?" },
      { id: "Q7.3", text: "to verify requests to amend existing beneficiary payment details?" },
    ],
    alwaysVisible: false,
    fpDependent: true,  // Only active when FP > R250,000
  },
  {
    id: "Q8",
    text: "Do you utilise account verification services offered by your bank or third-party provider?",
    alwaysVisible: false,
    fpDependent: true,  // Only active when FP > R250,000
  },
  {
    id: "Q9",
    text: "Have you been covered for cyber liability risks in the last 12 months prior to the inception date of this policy?",
    alwaysVisible: true,
    fpDependent: false,
  },
];

// ─── Underwriting Loading Rules ────────────────────────────────────────────────
// Based on number of Q2-Q6 "No" answers (Q2.1+Q2.2 count as single Q2)
const UNDERWRITING_LOADINGS = {
  0: { loading: 0,    label: "Standard Rates" },
  1: { loading: 0,    label: "Proceed with Caution" },
  2: { loading: 0.05, label: "5% Loading Applied" },
  3: { loading: 0.10, label: "10% Loading Applied" },
  4: { loading: 0.10, label: "10% Loading Applied" },
  5: { loading: 0.15, label: "15% Loading Applied" },
};

// ─── Broker Commission & Fees ──────────────────────────────────────────────────
const BROKER_COMMISSION = 0.20; // 20% of premium
const ADMIN_FEE_RATE = 0.06;   // 6% risk management fee
