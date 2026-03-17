/* ===== Pricing Data ===== */
const REVENUE_BANDS = [
  "R0 – R10M", "R10M – R25M", "R25M – R50M",
  "R50M – R75M", "R75M – R100M", "R100M – R150M",
  "R150M – R200M", "Over R200,000,000"
];

const COVER_LIMITS = [
  "R1M", "R2.5M", "R5M", "R7.5M", "R10M", "R15M", "Over R15,000,000"
];

// Matrix: Row = Revenue Band, Column = Cover Limit
// Values represent ANNUAL premiums
const PRICING = [
  [6264, 8520, 11052, 15816, 20184, 27816], // R0 - R10M
  [6264, 8520, 11052, 19428, 23988, 31788], // R10M - R25M
  [6264, 8520, 11052, 23028, 27792, 35760], // R25M - R50M
  [14040, 17172, 24072, 30228, 35436, 41928], // R50M - R75M
  [16488, 22440, 28332, 33660, 39480, 47832], // R75M - R100M
  [18804, 24144, 30300, 37476, 43248, 52824], // R100M - R150M
  [22608, 28116, 33396, 41112, 46644, 58524]  // R150M - R200M
];

/* ===== DOM Refs ===== */
const $ = id => document.getElementById(id);

const revenueSlider = $('revenueSlider');
const coverSlider = $('coverSlider');
const revenueValue = $('revenueValue');
const coverValue = $('coverValue');
const annualEl = $('annualPremium');
const monthlyEl = $('monthlyPremium');
const mdrYes = $('mdrYes');
const mdrNo = $('mdrNo');
const mdrSubOptions = $('mdrSubOptions');
const mdrTypeRadios = document.querySelectorAll('input[name="mdrType"]');
const discountBadge = $('discountBadge');
const industryDisclaimer = $('industryDisclaimer');
const industryField = $('industryField');

const customTurnoverGroup = $('customTurnoverGroup');
const customCoverGroup = $('customCoverGroup');
const customTurnoverInput = $('customTurnover');
const customCoverInput = $('customCover');

const step1 = $('step1');
const step2 = $('step2');
const successPanel = $('successPanel');

const dot1 = $('dot1');
const dot2 = $('dot2');
const lineFill = $('lineFill');
const label1 = $('label1');
const label2 = $('label2');

const nextBtn = $('nextBtn');
const backBtn = $('backBtn');
const submitBtn = $('submitBtn');
const leadForm = $('leadForm');

/* Summary in step 2 */
const sumRevenue = $('sumRevenue');
const sumCover = $('sumCover');
const sumAnnual = $('sumAnnual');
const sumMonthly = $('sumMonthly');

/* ===== Formatting ===== */
function formatR(n) {
  // Drop decimals as requested
  return 'R' + Math.round(n).toLocaleString('en-ZA');
}

/* ===== Core Logic ===== */
function getMDRDiscount() {
  if (!mdrYes.checked) return 0;
  const mdrType = document.querySelector('input[name="mdrType"]:checked').value;
  if (mdrType.includes("Essentials + endpoints not deployed")) return 0.10;
  if (mdrType.includes("Essentials + endpoints deployed")) return 0.15;
  if (mdrType.includes("Complete + endpoints not deployed")) return 0.20;
  if (mdrType.includes("Complete + endpoints deployed")) return 0.30;
  return 0;
}

/* ===== Quote Updater ===== */
function updateQuote() {
  const ri = parseInt(revenueSlider.value, 10);
  const ci = parseInt(coverSlider.value, 10);

  revenueValue.textContent = REVENUE_BANDS[ri];
  coverValue.textContent = COVER_LIMITS[ci] + (ci < 6 ? ' Cover Limit' : '');

  // Toggle custom fields & MDR sub-options
  const isOverRevenue = ri === 7;
  const isOverCover = ci === 6;
  const hasMDR = mdrYes.checked;
  const indVal = industryField.value;
  const isExcludedInd = (indVal === "Public Administration" || indVal === "Healthcare");

  // Disclaimer logic
  if (['Finance, Insurance and Real Estate', 'Software and Technology'].includes(indVal)) {
    industryDisclaimer.innerHTML = `
      <strong>Please note that the following high-risk industries may have an industry risk modifier included in the final quote:</strong>
      <ul>
        <li>Finance, Insurance and Real Estate</li>
        <li>Software and Technology</li>
      </ul>
    `;
    industryDisclaimer.classList.add('visible');
  } else if (isExcludedInd) {
    industryDisclaimer.innerHTML = `
      <strong>Please note:</strong> Public Administration and Healthcare require manual underwriting.
    `;
    industryDisclaimer.classList.add('visible');
  } else {
    industryDisclaimer.classList.remove('visible');
  }

  customTurnoverGroup.style.display = isOverRevenue ? 'block' : 'none';
  customCoverGroup.style.display = isOverCover ? 'block' : 'none';
  mdrSubOptions.style.display = hasMDR ? 'block' : 'none';

  if (isOverRevenue || isOverCover || isExcludedInd) {
    annualEl.innerHTML = `<span style="font-size: 1.1rem; color: var(--accent);">Contact for Quote</span>`;
    monthlyEl.innerHTML = `<span style="font-size: 1.1rem; color: var(--accent);">Contact for Quote</span>`;
    discountBadge.classList.remove('visible');
  } else {
    let annual = PRICING[ri][ci];
    const discountPct = getMDRDiscount();

    if (discountPct > 0) {
      annual = annual * (1 - discountPct);
      discountBadge.textContent = `${Math.round(discountPct * 100)}% MDR Discount Applied`;
      discountBadge.classList.add('visible');
    } else {
      discountBadge.classList.remove('visible');
    }

    const monthly = annual / 12;

    annualEl.innerHTML = `<span class="currency">R</span>${Math.round(annual).toLocaleString('en-ZA')}`;
    monthlyEl.innerHTML = `<span class="currency">R</span>${Math.round(monthly).toLocaleString('en-ZA')}`;
  }

  fillSliderTrack(revenueSlider);
  fillSliderTrack(coverSlider);
}

function fillSliderTrack(slider) {
  const pct = ((slider.value - slider.min) / (slider.max - slider.min)) * 100;
  slider.style.background = `linear-gradient(to right, #00b4d8 0%, #0077b6 ${pct}%, rgba(255,255,255,0.08) ${pct}%)`;
}

/* ===== Step Navigation ===== */
function goToStep(n) {
  if (n === 2) {
    const ri = parseInt(revenueSlider.value, 10);
    const ci = parseInt(coverSlider.value, 10);
    const indVal = industryField.value;
    const isExcludedInd = (indVal === "Public Administration" || indVal === "Healthcare");
    const isOver = (ri === 7 || ci === 6 || isExcludedInd);

    if (isOver) {
      sumRevenue.textContent = ri === 7 ? `Over R200M (${customTurnoverInput.value || 'N/A'})` : REVENUE_BANDS[ri];
      sumCover.textContent = ci === 6 ? `Over R15M (${customCoverInput.value || 'N/A'})` : COVER_LIMITS[ci];
      sumAnnual.textContent = "Contact Required";
      sumMonthly.textContent = "Contact Required";
    } else {
      let annual = PRICING[ri][ci];
      const discountPct = getMDRDiscount();
      if (discountPct > 0) annual *= (1 - discountPct);
      const monthly = annual / 12;

      sumRevenue.textContent = REVENUE_BANDS[ri];
      sumCover.textContent = COVER_LIMITS[ci];
      sumAnnual.textContent = formatR(annual);
      sumMonthly.textContent = formatR(monthly);
    }

    step1.classList.remove('active');
    step2.classList.add('active');
    dot1.classList.remove('active');
    dot1.classList.add('completed');
    dot1.textContent = '✓';
    dot2.classList.add('active');
    lineFill.classList.add('filled');
    label1.classList.remove('active');
    label1.classList.add('completed');
    label2.classList.add('active');
  } else {
    step2.classList.remove('active');
    step1.classList.add('active');
    dot1.classList.add('active');
    dot1.classList.remove('completed');
    dot1.textContent = '1';
    dot2.classList.remove('active');
    lineFill.classList.remove('filled');
    label1.classList.add('active');
    label1.classList.remove('completed');
    label2.classList.remove('active');
  }

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ===== Form Validation ===== */
function validateStep2() {
  const required = step2.querySelectorAll('[required]');
  let valid = true;

  required.forEach(el => {
    el.classList.remove('invalid');
    if (!el.value.trim()) {
      el.classList.add('invalid');
      valid = false;
    }
  });

  const email = $('emailField');
  if (email.value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
    email.classList.add('invalid');
    valid = false;
  }

  if (!valid) {
    const first = step2.querySelector('.invalid');
    if (first) first.focus();
  }

  return valid;
}

/* ===== Submit Handler ===== */
function handleSubmit(e) {
  e.preventDefault();
  if (!validateStep2()) return;

  const ri = parseInt(revenueSlider.value, 10);
  const ci = parseInt(coverSlider.value, 10);
  const indVal = industryField.value;
  const isExcludedInd = (indVal === "Public Administration" || indVal === "Healthcare");
  const isOver = (ri === 7 || ci === 6 || isExcludedInd);

  let annualVal = "Contact for Quote";
  let monthlyVal = "Contact for Quote";

  if (!isOver) {
    let annual = PRICING[ri][ci];
    const discountPct = getMDRDiscount();
    if (discountPct > 0) annual *= (1 - discountPct);
    annualVal = formatR(annual);
    monthlyVal = formatR(annual / 12);
  }

  // Populate hidden fields
  $('h_revenueBand').value = REVENUE_BANDS[ri];
  $('h_coverLimit').value = COVER_LIMITS[ci];
  $('h_annualPremium').value = annualVal;
  $('h_monthlyPremium').value = monthlyVal;
  $('h_mdrQualified').value = mdrYes.checked ? document.querySelector('input[name="mdrType"]:checked').value : 'No';
  $('h_customTurnover').value = customTurnoverInput.value || 'N/A';
  $('h_customCover').value = customCoverInput.value || 'N/A';

  // Update subject dynamically
  $('fs_subject').value = `Lead Submission: ${$('companyName').value.trim()} - Phishield Cyber Cover`;

  // Submit the form natively (standard POST to FormSubmit)
  submitBtn.disabled = true;
  submitBtn.textContent = 'Sending...';
  leadForm.submit();
}

/* ===== Event Listeners ===== */
revenueSlider.addEventListener('input', updateQuote);
coverSlider.addEventListener('input', updateQuote);
mdrYes.addEventListener('change', updateQuote);
mdrNo.addEventListener('change', updateQuote);
industryField.addEventListener('change', updateQuote);
mdrTypeRadios.forEach(radio => radio.addEventListener('change', updateQuote));

nextBtn.addEventListener('click', () => {
  if (!industryField.value) {
    industryField.classList.add('invalid');
    industryField.focus();
    return;
  }
  industryField.classList.remove('invalid');
  goToStep(2);
});

backBtn.addEventListener('click', () => goToStep(1));
submitBtn.addEventListener('click', handleSubmit);

/* ===== Init ===== */
updateQuote();

/* ===== Check for FormSubmit redirect ===== */
if (new URLSearchParams(window.location.search).get('submitted') === 'true') {
  step1.classList.remove('active');
  step2.classList.remove('active');
  successPanel.style.display = 'block';
  dot1.classList.remove('active');
  dot1.classList.add('completed');
  dot1.textContent = '✓';
  dot2.classList.add('completed');
  dot2.textContent = '✓';
  lineFill.classList.add('filled');
  label1.classList.remove('active');
  label1.classList.add('completed');
  label2.classList.add('completed');
  // Clean the URL
  window.history.replaceState({}, '', window.location.pathname);
}
