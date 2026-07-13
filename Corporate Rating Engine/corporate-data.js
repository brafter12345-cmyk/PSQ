/* corporate-data.js — Corporate Rating Engine data layer.
 * AUTO-GENERATED from the workbook 'Look Up Tables' by tools/gen_corporate_data.py.
 * Do not edit by hand; re-run the generator if the spreadsheet changes.
 */
const CORP_DATA = {
  "META": {
    "product": "Cyber Protect — Corporate (Risk Rated)",
    "administrator": "Phishield UMA (Pty) Ltd",
    "source_workbook": "Phishield Corporate Rarting Engine with Sec Questions_13_03_2026.xlsx"
  },
  "CONSTANTS": {
    "EXPONENT_A": -0.03035,
    "EXPONENT_B": 1.462732,
    "C15_DIVISOR": 1.155,
    "DEFAULT_VAT": 0.15,
    "RANSOM_DIV": 100,
    "YEARLY_MARKET_ADJ": -0.2,
    "EXCESS_POWER": 1.1,
    "EXCESS_HALF_COVER": 0.5,
    "CLAIMS_PORTION": 0.3,
    "RISK_MGMT_FEE": 0.06,
    "SA_BREACH_FACTOR": 0.569672131147541,
    "GLOBAL_BREACH_ZAR": 92913736,
    "SA_BREACH_ZAR": 52930366,
    "SME_CORP_RATIO": 0.6173479179,
    "TURNOVER_MIN": 250000000
  },
  "BASE_PREMIUM": [
    {
      "cover": 5000000,
      "constant": 1179.066054308966,
      "raw": null
    },
    {
      "cover": 7500000,
      "constant": 1930.5921176966901,
      "raw": null
    },
    {
      "cover": 10000000,
      "constant": 2447.7826373520984,
      "raw": null
    },
    {
      "cover": 15000000,
      "constant": 3696.0187487879557,
      "raw": null
    },
    {
      "cover": 25000000,
      "constant": 6896.458922823278,
      "raw": null
    },
    {
      "cover": 50000000,
      "constant": 17092.950753799614,
      "raw": null
    },
    {
      "cover": 75000000,
      "constant": 32385.46520914375,
      "raw": null
    },
    {
      "cover": 100000000,
      "constant": 51945.45043986207,
      "raw": null
    },
    {
      "cover": 150000000,
      "constant": null,
      "raw": "TBC"
    }
  ],
  "COVER_OPTIONS": [
    5000000,
    7500000,
    10000000,
    15000000,
    25000000,
    50000000,
    75000000,
    100000000
  ],
  "INDUSTRIES": [
    {
      "main": "Agriculture, Forestry, And Fishing",
      "sub": "Agriculture, Forestry, And Fishing - Agricultural Production Crops",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.40759910415955275,
      "biFac": 0.027680321162883617,
      "row": 3
    },
    {
      "main": "Agriculture, Forestry, And Fishing",
      "sub": "Agriculture, Forestry, And Fishing - Agriculture production livestock and animal specialties",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.40759910415955275,
      "biFac": 0.013840160581441809,
      "row": 4
    },
    {
      "main": "Agriculture, Forestry, And Fishing",
      "sub": "Agriculture, Forestry, And Fishing - Agricultural Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": -0.4092418844235307,
      "biFac": 0.013840160581441809,
      "row": 5
    },
    {
      "main": "Agriculture, Forestry, And Fishing",
      "sub": "Agriculture, Forestry, And Fishing - Forestry",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.40759910415955275,
      "biFac": 0.013840160581441809,
      "row": 6
    },
    {
      "main": "Agriculture, Forestry, And Fishing",
      "sub": "Agriculture, Forestry, And Fishing- Fishing hunting and trapping",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.40759910415955275,
      "biFac": 0.013840160581441809,
      "row": 7
    },
    {
      "main": "Mining",
      "sub": "Mining - Metal Mining",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.34620243683837887,
      "biFac": 0.04152048174432542,
      "row": 8
    },
    {
      "main": "Mining",
      "sub": "Mining - Coal Mining",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": -0.3324395341170777,
      "biFac": 0.04152048174432542,
      "row": 9
    },
    {
      "main": "Mining",
      "sub": "Mining - Oil And Gas Extraction",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": -0.24710860915322644,
      "biFac": 0.04152048174432542,
      "row": 10
    },
    {
      "main": "Mining",
      "sub": "Mining - Mining And Quarrying Of Nonmetallic Minerals, Except Fuels",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.34620243683837887,
      "biFac": 0.04152048174432542,
      "row": 11
    },
    {
      "main": "Construction",
      "sub": "Construction - Building Construction General Contractors And Operative Builders",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.07819492032856011,
      "biFac": 0.013840160581441809,
      "row": 12
    },
    {
      "main": "Construction",
      "sub": "Construction - Heavy Construction Other Than Building Construction Contractors",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.07819492032856011,
      "biFac": 0.013840160581441809,
      "row": 13
    },
    {
      "main": "Construction",
      "sub": "Construction - Construction Special Trade Contractors",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.07819492032856011,
      "biFac": 0.013840160581441809,
      "row": 14
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Food And Kindred Products",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.2402336605047008,
      "biFac": 0.13840160581441807,
      "row": 15
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Tobacco Products",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.3178072286536562,
      "biFac": 0.13840160581441807,
      "row": 16
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Textile Mill Products",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.3178072286536562,
      "biFac": 0.13840160581441807,
      "row": 17
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Apparel And Other Finished Products Made From Fabrics And Similar Materials",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.3953807968026116,
      "biFac": 0.13840160581441807,
      "row": 18
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Lumber And Wood Products, Except Furniture",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.3699333027304561,
      "biFac": 0.13840160581441807,
      "row": 19
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Furniture And Fixtures",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.3178072286536562,
      "biFac": 0.13840160581441807,
      "row": 20
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Paper And Allied Products",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.2923597345815007,
      "biFac": 0.13840160581441807,
      "row": 21
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Printing, Publishing, And Allied Industries",
      "breachUSD": 2330000,
      "breachZAR": 41986600,
      "industryFac": -0.02748603849460665,
      "biFac": 0.13840160581441807,
      "row": 22
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Chemicals And Allied Products",
      "breachUSD": 2540000,
      "breachZAR": 45770800,
      "industryFac": -0.222897559313218,
      "biFac": 0.13840160581441807,
      "row": 23
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Petroleum Refining And Related Industries",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": -0.18550855008145278,
      "biFac": 0.13840160581441807,
      "row": 24
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Rubber And Miscellaneous Plastics Products",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.2923597345815007,
      "biFac": 0.13840160581441807,
      "row": 25
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Leather And Leather Products",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.3178072286536562,
      "biFac": 0.13840160581441807,
      "row": 26
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Stone, Clay, Glass, And Concrete Products",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.3699333027304561,
      "biFac": 0.13840160581441807,
      "row": 27
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Primary Metal Industries",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.2923597345815007,
      "biFac": 0.13840160581441807,
      "row": 28
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Fabricated Metal Products, Except Machinery And Transportation Equipment",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.2923597345815007,
      "biFac": 0.13840160581441807,
      "row": 29
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Industrial And Commercial Machinery And Computer Equipment",
      "breachUSD": 2640000,
      "breachZAR": 47572800,
      "industryFac": -0.08002052310539523,
      "biFac": 0.13840160581441807,
      "row": 30
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Electronic And Other Electrical Equipment And Components, Except Computer Equipment",
      "breachUSD": 2640000,
      "breachZAR": 47572800,
      "industryFac": -0.08002052310539523,
      "biFac": 0.13840160581441807,
      "row": 31
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Transportation Equipment",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.2923597345815007,
      "biFac": 0.13840160581441807,
      "row": 32
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Measuring, Analyzing, And Controlling Instruments; Photographic, Medical And Optical Goods; Watches And Clocks",
      "breachUSD": 4090000,
      "breachZAR": 73701800,
      "industryFac": -0.33908426989810536,
      "biFac": 0.13840160581441807,
      "row": 33
    },
    {
      "main": "Manufacturing",
      "sub": "Manufacturing - Miscellaneous Manufacturing Industries",
      "breachUSD": 2760000,
      "breachZAR": 49735200,
      "industryFac": -0.44750687087941154,
      "biFac": 0.13840160581441807,
      "row": 34
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Railroad Transportation",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.1678585556670688,
      "biFac": 0.27680321162883614,
      "row": 35
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Local And Suburban Transit And Interurban Highway Passenger Transportation",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.012353490637928002,
      "biFac": 0.2076024087216271,
      "row": 36
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Motor Freight Transportation And Warehousing",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.1678585556670688,
      "biFac": 0.27680321162883614,
      "row": 37
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Postal Service",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.1678585556670688,
      "biFac": 0.27680321162883614,
      "row": 38
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Water Transportation",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.1678585556670688,
      "biFac": 0.27680321162883614,
      "row": 39
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Transportation By Air",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.1678585556670688,
      "biFac": 0.27680321162883614,
      "row": 40
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Pipelines, Except Natural Gas",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": -0.10292053902645115,
      "biFac": 0.27680321162883614,
      "row": 41
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Transportation Services",
      "breachUSD": 2200000,
      "breachZAR": 39644000,
      "industryFac": -0.04402036272449968,
      "biFac": 0.27680321162883614,
      "row": 42
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Communications",
      "breachUSD": 2069999.9999999998,
      "breachZAR": 37301399.99999999,
      "industryFac": 0.42418541886823224,
      "biFac": 0.27680321162883614,
      "row": 43
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Electric, Gas, And Sanitary Services ",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": 0.025559863429745158,
      "biFac": 0.27680321162883614,
      "row": 44
    },
    {
      "main": "Transportation, Communications, Electric, Gas, And Sanitary Services",
      "sub": "Transportation, Communications, Electric, Gas, And Sanitary Services - Water and Waste Management",
      "breachUSD": 2670000,
      "breachZAR": 48113400,
      "industryFac": 0.02589656188176183,
      "biFac": 0.27680321162883614,
      "row": 45
    },
    {
      "main": "Wholesale Trade",
      "sub": "Wholesale Trade - Wholesale Trade-durable Goods",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.5661398982894595,
      "biFac": 0.27680321162883614,
      "row": 46
    },
    {
      "main": "Wholesale Trade",
      "sub": "Wholesale Trade - Wholesale Trade-non-durable Goods",
      "breachUSD": 2049999.9999999998,
      "breachZAR": 36940999.99999999,
      "industryFac": -0.5661398982894595,
      "biFac": 0.27680321162883614,
      "row": 47
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - eCommerce",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": 0.164714706805212,
      "biFac": 0.4152048174432542,
      "row": 48
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Building Materials, Hardware, Garden Supply, And Mobile Home Dealers",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": -0.04278260219589963,
      "biFac": 0.3460040145360452,
      "row": 49
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - General Merchandise Stores",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": 0.03540784515922979,
      "biFac": 0.3460040145360452,
      "row": 50
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Food Stores",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": -0.04278260219589963,
      "biFac": 0.3460040145360452,
      "row": 51
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Automotive Dealers And Gasoline Service Stations",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": -0.3164491679388531,
      "biFac": 0.3460040145360452,
      "row": 52
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Apparel And Accessory Stores",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": 0.03540784515922979,
      "biFac": 0.3460040145360452,
      "row": 53
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Home Furniture, Furnishings, And Equipment Stores",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": -0.04278260219589963,
      "biFac": 0.3460040145360452,
      "row": 54
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Eating And Drinking Places",
      "breachUSD": 3190000,
      "breachZAR": 57483800,
      "industryFac": -0.010930167489607734,
      "biFac": 0.3460040145360452,
      "row": 55
    },
    {
      "main": "Retail Trade",
      "sub": "Retail Trade - Miscellaneous Retail ",
      "breachUSD": 1950000,
      "breachZAR": 35139000,
      "industryFac": 0.03540784515922979,
      "biFac": 0.3460040145360452,
      "row": 56
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Depository Institutions",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.6821041170836917,
      "biFac": 0.48440562035046325,
      "row": 57
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Non-depository Credit Institutions",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.6821041170836917,
      "biFac": 0.27680321162883614,
      "row": 58
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Security And Commodity Brokers, Dealers, Exchanges, And Services",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.6821041170836917,
      "biFac": 0.27680321162883614,
      "row": 59
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Insurance Carriers",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.3185298500929945,
      "biFac": 0.2076024087216271,
      "row": 60
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Insurance Agents, Brokers, And Service",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.3185298500929945,
      "biFac": 0.13840160581441807,
      "row": 61
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Real Estate",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.6652682281487559,
      "biFac": 0.06920080290720904,
      "row": 62
    },
    {
      "main": "Finance, Insurance, And Real Estate",
      "sub": "Finance, Insurance, And Real Estate - Holding And Other Investment Offices",
      "breachUSD": 3900000,
      "breachZAR": 70278000,
      "industryFac": 0.6821041170836917,
      "biFac": 0.2076024087216271,
      "row": 63
    },
    {
      "main": "Services",
      "sub": "Services - Hotels, Rooming Houses, Camps, And Other Lodging Places",
      "breachUSD": 3190000,
      "breachZAR": 57483800,
      "industryFac": 0.7310898916715896,
      "biFac": 0.27680321162883614,
      "row": 64
    },
    {
      "main": "Services",
      "sub": "Services - Personal Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.25725672278981826,
      "biFac": 0.27680321162883614,
      "row": 65
    },
    {
      "main": "Services",
      "sub": "Services - Business Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.44522495618376423,
      "biFac": 0.27680321162883614,
      "row": 66
    },
    {
      "main": "Services",
      "sub": "Services - Automotive Repair, Services, And Parking",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.1631930699621336,
      "biFac": 0.2076024087216271,
      "row": 67
    },
    {
      "main": "Services",
      "sub": "Services - Miscellaneous Repair Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.1631930699621336,
      "biFac": 0.27680321162883614,
      "row": 68
    },
    {
      "main": "Services",
      "sub": "Services - Motion Pictures",
      "breachUSD": 2440000,
      "breachZAR": 43968800,
      "industryFac": 0.4412336822385666,
      "biFac": 0.27680321162883614,
      "row": 69
    },
    {
      "main": "Services",
      "sub": "Services - Amusement And Recreation Services",
      "breachUSD": 2440000,
      "breachZAR": 43968800,
      "industryFac": 0.36350332975364935,
      "biFac": 0.2076024087216271,
      "row": 70
    },
    {
      "main": "Services",
      "sub": "Services - Health Services",
      "breachUSD": 4090000,
      "breachZAR": 73701800,
      "industryFac": 0.4385749513781367,
      "biFac": 0.27680321162883614,
      "row": 71
    },
    {
      "main": "Services",
      "sub": "Services - Legal Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.44522495618376423,
      "biFac": 0.27680321162883614,
      "row": 72
    },
    {
      "main": "Services",
      "sub": "Services - Educational Services",
      "breachUSD": 2100000,
      "breachZAR": 37842000,
      "industryFac": 0.7392924542506636,
      "biFac": 0.27680321162883614,
      "row": 73
    },
    {
      "main": "Services",
      "sub": "Services - Social Services",
      "breachUSD": 1580000,
      "breachZAR": 28471600,
      "industryFac": 0.7185644475311148,
      "biFac": 0.27680321162883614,
      "row": 74
    },
    {
      "main": "Services",
      "sub": "Services - Museums, Art Galleries, And Botanical And Zoological Gardens",
      "breachUSD": 2440000,
      "breachZAR": 43968800,
      "industryFac": 0.3518165222887554,
      "biFac": 0.27680321162883614,
      "row": 75
    },
    {
      "main": "Services",
      "sub": "Services - Membership Organizations",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.38390537958902304,
      "biFac": 0.13840160581441807,
      "row": 76
    },
    {
      "main": "Services",
      "sub": "Services - Engineering, Accounting, Research, Management, And Related Services",
      "breachUSD": 2089999.9999999998,
      "breachZAR": 37661799.99999999,
      "industryFac": 0.4302403964407815,
      "biFac": 0.27680321162883614,
      "row": 77
    },
    {
      "main": "Services",
      "sub": "Services - Private Households",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.23269486787274232,
      "biFac": 0.2076024087216271,
      "row": 78
    },
    {
      "main": "Services",
      "sub": "Services - Miscellaneous Services",
      "breachUSD": 3160000,
      "breachZAR": 56943200,
      "industryFac": 0.25725672278981826,
      "biFac": 0.27680321162883614,
      "row": 79
    },
    {
      "main": "Services",
      "sub": "Services - Software and Technology",
      "breachUSD": 2640000,
      "breachZAR": 47572800,
      "industryFac": 0.7365953416408593,
      "biFac": 0.27680321162883614,
      "row": 80
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Executive, Legislative, And General Government, Except Finance",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 81
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Justice, Public Order, And Safety",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 82
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Public Finance, Taxation, And Monetary Policy",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 83
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Administration Of Human Resource Programs",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 84
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Administration Of Environmental Quality And Housing Programs",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 85
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Administration Of Economic Programs",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 86
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - National Security And International Affairs",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 87
    },
    {
      "main": "Public Administration",
      "sub": "Public Administration - Nonclassifiable Establishments",
      "breachUSD": 4467253.137254902,
      "breachZAR": 80499901.53333333,
      "industryFac": 0.9265,
      "biFac": 0.27680321162883614,
      "row": 88
    }
  ],
  "DEPOSITORY_SUB": "Finance, Insurance, And Real Estate - Depository Institutions",
  "DEPOSITORY_BANDS": [
    {
      "modifier": 2.5,
      "gte": 0,
      "lt": 1000000000
    },
    {
      "modifier": 2.15,
      "gte": 1000000000,
      "lt": 2500000000
    },
    {
      "modifier": 1.9,
      "gte": 2500000000,
      "lt": 5000000000
    },
    {
      "modifier": 1.65,
      "gte": 5000000000,
      "lt": 7500000000
    },
    {
      "modifier": 1.45,
      "gte": 7500000000,
      "lt": 10000000000
    },
    {
      "modifier": 1.3,
      "gte": 10000000000,
      "lt": 15000000000
    },
    {
      "modifier": 1.15,
      "gte": 15000000000,
      "lt": 20000000000
    },
    {
      "modifier": 1,
      "gte": 20000000000,
      "lt": null
    }
  ],
  "BENEFITS": [
    {
      "name": "Business Interruption Loss",
      "contribution": 0.27680321162883614
    },
    {
      "name": "Multimedia Liability Claims",
      "contribution": 0.01876304090006786
    },
    {
      "name": "Regulatory Expenses and Penalties",
      "contribution": 0.05619240599453313
    },
    {
      "name": "Third Party Claims",
      "contribution": 0.1872435421779968
    },
    {
      "name": "Emergency Response Costs",
      "contribution": 0.2790276958592566
    },
    {
      "name": "Data Restoration Costs",
      "contribution": 0.12921351877572507
    },
    {
      "name": "Cyber Extortion Costs",
      "contribution": 0.03283294329547112
    },
    {
      "name": "PCI Fines and Penalties",
      "contribution": 0.005319418811874909
    },
    {
      "name": "Computer Crime",
      "contribution": 0.014604222556238385
    }
  ],
  "BENEFIT_SUBLIMIT_RATIOS": [
    0.1,
    0.2,
    0.3,
    0.4,
    0.5,
    0.6,
    0.7,
    0.8,
    0.9,
    1
  ],
  "MATURITY_BANDS": [
    {
      "label": "Very Strong",
      "multiplier": 0.75,
      "description": "Industry-leading security, 24/7 monitoring, zero-trust architecture, advanced threat detection.",
      "gte": 0.9,
      "lt": null
    },
    {
      "label": "Strong",
      "multiplier": 0.85,
      "description": "Well-implemented security controls, endpoint protection, regular testing, strong compliance.",
      "gte": 0.8,
      "lt": 0.9
    },
    {
      "label": "Moderate",
      "multiplier": 1,
      "description": "Standard security measures, some vulnerabilities, meets compliance but limited advanced protections.",
      "gte": 0.7,
      "lt": 0.8
    },
    {
      "label": "Weak",
      "multiplier": 1.15,
      "description": "Basic security, outdated controls, minimal monitoring, higher risk exposure.",
      "gte": 0.6,
      "lt": 0.7
    },
    {
      "label": "Very Weak",
      "multiplier": 1.25,
      "description": "No formal cybersecurity, outdated software, high vulnerability to attacks.",
      "gte": 0.5,
      "lt": 0
    },
    {
      "label": "N/A",
      "multiplier": 1,
      "description": "If no maturity overrider is required",
      "gte": null,
      "lt": null
    }
  ],
  "FP_STANDARD": {
    "amounts": [
      500000,
      750000,
      1000000,
      1500000,
      2000000,
      2500000,
      3000000,
      4000000,
      5000000,
      7500000,
      10000000
    ],
    "costs": [
      6054.545454545454,
      9300,
      12545.454545454544,
      21709.090909090908,
      24420,
      31680,
      38940,
      52140,
      65400,
      99120,
      132840
    ]
  },
  "FP_ADJUSTABLE": {
    "amounts": [
      0,
      500000,
      750000,
      1000000,
      2000000,
      3000000,
      4000000,
      5000000,
      7500000,
      10000000
    ],
    "costs": [
      0,
      6054.545454545454,
      9297.272727272728,
      12540,
      24420,
      38940,
      52140,
      65400,
      130799.24242424243,
      196198.48484848486
    ]
  },
  "EXCESS_OPTIONS": [
    0,
    500000,
    1000000,
    1500000,
    2000000,
    2500000,
    3000000,
    3500000,
    4000000,
    4500000,
    5000000,
    5500000,
    6000000,
    6500000,
    7000000,
    7500000,
    8000000,
    8500000,
    9000000,
    9500000,
    10000000,
    10500000,
    11000000,
    11500000,
    12000000,
    12500000,
    13000000,
    13500000,
    14000000,
    14500000,
    15000000,
    15500000,
    16000000,
    16500000,
    17000000,
    17500000,
    18000000,
    18500000,
    19000000,
    19500000,
    20000000,
    20500000,
    21000000,
    21500000,
    22000000,
    22500000,
    23000000,
    23500000,
    24000000,
    24500000,
    25000000
  ],
  "MDR_OPTIONS": [
    {
      "label": "No MDR",
      "discount": 0
    },
    {
      "label": "MDR Essential without Sophos Endpoint Deployment",
      "discount": 0.1
    },
    {
      "label": "MDR Essential with Sophos Endpoint Deployment",
      "discount": 0.15
    },
    {
      "label": "MDR Complete without Sophos Endpoint Deployment",
      "discount": 0.2
    },
    {
      "label": "MDR Complete with Sophos Endpoint Deployment",
      "discount": 0.3
    }
  ],
  "VAT_OPTIONS": [
    0.15,
    0.155,
    0.16,
    0.165,
    0.17,
    0.175,
    0.18,
    0.185,
    0.19,
    0.195,
    0.2
  ]
};

if (typeof window !== 'undefined') { window.CORP_DATA = CORP_DATA; }
if (typeof module !== 'undefined' && module.exports) { module.exports = CORP_DATA; }
