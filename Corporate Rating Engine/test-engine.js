/* Headless test: reproduce the workbook's embedded example end-to-end.
 * Run: node "test-engine.js"   (expect Final Premium R457,460.93)
 */
const CORP_DATA = require("./corporate-data.js");
global.CORP_DATA = CORP_DATA;
const Engine = require("./corporate-engine.js");

const benefitsAllButPCIandCrime = [
  { name: "Business Interruption Loss", included: true, sublimitRatio: 1 },
  { name: "Multimedia Liability Claims", included: true, sublimitRatio: 1 },
  { name: "Regulatory Expenses and Penalties", included: true, sublimitRatio: 1 },
  { name: "Third Party Claims", included: true, sublimitRatio: 1 },
  { name: "Emergency Response Costs", included: true, sublimitRatio: 1 },
  { name: "Data Restoration Costs", included: true, sublimitRatio: 1 },
  { name: "Cyber Extortion Costs", included: true, sublimitRatio: 1 },
  { name: "PCI Fines and Penalties", included: false, sublimitRatio: 1 },
  { name: "Computer Crime", included: false, sublimitRatio: 1 },
];

const example = {
  turnover: 7200000000,
  cover: 50000000,
  subIndustry: "Manufacturing - Fabricated Metal Products, Except Machinery And Transportation Equipment",
  maturityOverride: "Moderate",
  vat: 0.15,
  benefits: benefitsAllButPCIandCrime,
  excess: 2000000,
  fpAdjustableAmount: 2000000,
  mdr: "No MDR",
};

const r = Engine.computePremium(example);

function approx(got, want, tol = 1) { return Math.abs(got - want) <= tol; }
const checks = [
  ["Final premium", r.finalPremium, 457460.93],
  ["Base premium", r.basePremium, 457460.93],
  ["Funds Protect (R2M)", r.fundsProtect, 24420],
  ["Expected breach cost", r.expectedBreachCost, 28332757.38],
  ["Maturity multiplier", r.maturityMultiplier, 1.0],
];

console.log("=== Embedded example ===");
let allOk = true;
for (const [label, got, want] of checks) {
  const ok = approx(got, want, Math.max(1, Math.abs(want) * 1e-4));
  allOk = allOk && ok;
  console.log(`  [${ok ? "OK " : "XX "}] ${label.padEnd(24)} got=${got.toLocaleString("en-ZA", { maximumFractionDigits: 2 }).padStart(16)}  want=${want.toLocaleString("en-ZA")}`);
}

console.log("\n=== Step trace ===");
for (const s of r.steps) {
  console.log(`  ${s.label.padEnd(36)} ${Number(s.value).toLocaleString("en-ZA", { maximumFractionDigits: 2 }).padStart(16)}   ${s.note}`);
}

// Sanity sweep: a few extra cases just to ensure no crashes + monotonic behaviour
console.log("\n=== Sanity sweep (no oracle, just sane outputs) ===");
for (const cover of [5000000, 10000000, 100000000]) {
  for (const band of ["Very Strong", "Moderate", "Very Weak"]) {
    const rr = Engine.computePremium({ ...example, cover, maturityOverride: band });
    console.log(`  cover=${(cover/1e6)+"M"} band=${band.padEnd(11)} final=${Engine.zar(rr.finalPremium)}`);
  }
}

console.log("\n" + (allOk ? "ALL CHECKS PASSED ✓" : "*** CHECKS FAILED ***"));
process.exit(allOk ? 0 : 1);
