/* corporate-rating.js — UI controller for the Corporate Rating Engine.
 * Wires the wizard to the (validated) CorpEngine. No framework; vanilla DOM.
 */
(function () {
  "use strict";
  const D = window.CORP_DATA;
  const E = window.CorpEngine;
  const $ = (id) => document.getElementById(id);
  // Market-condition indicator shown on the Renewal branch — update annually.
  const MARKET_CONDITION = { label: "Stable market — 2026" };

  // ---------- formatting ----------
  const zar0 = (n) => "R" + Math.round(n).toLocaleString("en-ZA");
  const zar2 = (n) => "R" + Number(n).toLocaleString("en-ZA", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const pct = (x) => (x * 100).toFixed(2) + "%";
  const parseNum = (s) => { const n = parseFloat(String(s).replace(/[^0-9.]/g, "")); return isNaN(n) ? 0 : n; };
  const groupNum = (s) => { const n = parseNum(s); return n ? n.toLocaleString("en-ZA") : ""; };

  // ---------- state ----------
  const state = {
    step: 1,
    companyName: "", website: "", subIndustry: "",
    turnover: 0, cover: 10000000, excess: 1000000, excessType: "Per Event",
    vat: D.CONSTANTS.DEFAULT_VAT,
    maturityOverride: "",
    benefits: D.BENEFITS.map((b) => ({
      name: b.name,
      included: b.name !== "PCI Fines and Penalties" && b.name !== "Computer Crime",
      sublimitRatio: 1,
    })),
    fpMode: "standard", fpAdjustableAmount: 0,
    mdr: "No MDR", discretionary: 0,
    quoteType: "new",
    renewalCover: 0, renewalPremium: 0, renewalFP: 0,
    competitorName: "", competitorPremium: 0, competitorLimit: 0, competitorHasFP: false,
    options: [], activeOption: 0,
    quoteRef: "",
  };

  // ---------- dropdowns / datalists ----------
  function fillSelect(el, items, valueKey, labelKey, selected) {
    el.innerHTML = "";
    items.forEach((it) => {
      const opt = document.createElement("option");
      opt.value = valueKey ? it[valueKey] : it;
      opt.textContent = labelKey ? it[labelKey] : it;
      if (selected != null && String(opt.value) === String(selected)) opt.selected = true;
      el.appendChild(opt);
    });
  }
  // datalist options: single formatted line (value carries the number; no separate label
  // text, which the browser would otherwise render as a doubled raw/formatted row)
  function fillDatalist(el, values) {
    el.innerHTML = values.map((v) => `<option value="${v.toLocaleString("en-ZA")}"></option>`).join("");
  }

  function initDropdowns() {
    fillSelect($("cover"), D.COVER_OPTIONS.map((c) => ({ v: c, l: zar0(c) })), "v", "l", state.cover);
    fillSelect($("excess"), D.EXCESS_OPTIONS.map((c) => ({ v: c, l: zar0(c) })), "v", "l", state.excess);
    fillSelect($("vat"), D.VAT_OPTIONS.map((v) => ({ v: v, l: pct(v) })), "v", "l", state.vat);
    fillSelect($("mdr"), D.MDR_OPTIONS, "label", "label", state.mdr);
    fillSelect($("renewal-cover"), D.COVER_OPTIONS.map((c) => ({ v: c, l: zar0(c) })), "v", "l", state.cover);
    const fpPresets = D.FP_ADJUSTABLE.amounts.filter((a) => a >= 500000);
    fillDatalist($("fp-presets"), fpPresets);
  }

  // ---------- searchable industry select ----------
  function initIndustrySelect() {
    const search = $("industry-search");
    const dd = $("industry-dropdown");
    const groups = {};
    D.INDUSTRIES.forEach((r) => { (groups[r.main] = groups[r.main] || []).push(r); });

    function render(filter) {
      dd.innerHTML = "";
      const f = (filter || "").toLowerCase();
      let count = 0;
      Object.keys(groups).forEach((main) => {
        const matches = groups[main].filter((r) => r.sub.toLowerCase().includes(f) || main.toLowerCase().includes(f));
        if (!matches.length) return;
        const g = document.createElement("div");
        g.className = "sd-group"; g.textContent = main; dd.appendChild(g);
        matches.forEach((r) => {
          const o = document.createElement("div");
          o.className = "sd-option" + (r.sub === state.subIndustry ? " selected" : "");
          const short = r.sub.includes(" - ") ? r.sub.split(" - ").slice(1).join(" - ") : r.sub;
          o.textContent = short; o.title = r.sub;
          o.addEventListener("mousedown", (ev) => {
            ev.preventDefault();
            state.subIndustry = r.sub;
            search.value = r.sub; // full "Main - Sub" label after selection
            $("industry-select").value = r.sub;
            $("industry-hint").textContent = `${r.main} · industry modifier ${pct(r.industryFac)} · BI modifier ${pct(r.biFac)}`;
            dd.classList.remove("open");
            recompute();
          });
          dd.appendChild(o); count++;
        });
      });
      if (!count) dd.innerHTML = '<div class="sd-empty">No matching industry</div>';
    }
    search.addEventListener("focus", () => { render(""); dd.classList.add("open"); });
    search.addEventListener("input", () => { render(search.value); dd.classList.add("open"); });
    document.addEventListener("click", (ev) => { if (!$("industry-wrapper").contains(ev.target)) dd.classList.remove("open"); });
  }

  // ---------- maturity cards ----------
  function initMaturityCards() {
    const grid = $("maturity-grid");
    grid.innerHTML = "";
    D.MATURITY_BANDS.filter((m) => m.label !== "N/A").forEach((m) => {
      const card = document.createElement("div");
      card.className = "maturity-card"; card.dataset.band = m.label;
      const good = m.multiplier <= 1;
      card.innerHTML =
        `<div class="mc-name">${m.label}</div>` +
        `<div class="mc-mult ${good ? "good" : "bad"}">${m.multiplier < 1 ? "−" : m.multiplier > 1 ? "+" : ""}${Math.abs((m.multiplier - 1) * 100).toFixed(0)}% premium · ×${m.multiplier}</div>` +
        `<div class="mc-desc">${m.description || ""}</div>`;
      card.addEventListener("click", () => {
        state.maturityOverride = m.label;
        grid.querySelectorAll(".maturity-card").forEach((c) => c.classList.toggle("selected", c.dataset.band === m.label));
        $("next-2").disabled = false;
        recompute();
      });
      grid.appendChild(card);
    });
  }

  // ---------- benefits table (preset dropdown + free % field) ----------
  function initBenefitsTable() {
    const body = $("benefits-body");
    body.innerHTML = "";
    state.benefits.forEach((b, i) => {
      const tr = document.createElement("tr");
      tr.className = b.included ? "" : "excluded";
      const ratioOpts = D.BENEFIT_SUBLIMIT_RATIOS.map((r) => `<option value="${r}" ${r === b.sublimitRatio ? "selected" : ""}>${Math.round(r * 100)}%</option>`).join("");
      tr.innerHTML =
        `<td class="bt-name">${b.name}</td>` +
        `<td><label class="toggle"><input type="checkbox" data-i="${i}" class="bt-inc" ${b.included ? "checked" : ""}><span class="slider"></span></label></td>` +
        `<td><select class="form-select bt-ratio" data-i="${i}">${ratioOpts}</select></td>` +
        `<td><input class="form-input bt-ratio-free" data-i="${i}" type="number" min="0" max="100" step="1" value="${+(b.sublimitRatio * 100).toFixed(2)}" style="padding:6px 8px;width:62px"></td>` +
        `<td class="bt-sub" data-sub="${i}">${zar0(b.sublimitRatio * state.cover)}</td>`;
      body.appendChild(tr);
    });
    body.querySelectorAll(".bt-inc").forEach((cb) => cb.addEventListener("change", (e) => {
      const i = +e.target.dataset.i;
      state.benefits[i].included = e.target.checked;
      e.target.closest("tr").className = e.target.checked ? "" : "excluded";
      recompute();
    }));
    body.querySelectorAll(".bt-ratio").forEach((sel) => sel.addEventListener("change", (e) => setBenefitRatio(+e.target.dataset.i, parseFloat(e.target.value), "dropdown")));
    body.querySelectorAll(".bt-ratio-free").forEach((inp) => inp.addEventListener("input", (e) => {
      let p = parseFloat(e.target.value);
      if (isNaN(p)) return;
      p = Math.max(0, Math.min(100, p));
      setBenefitRatio(+e.target.dataset.i, p / 100, "free");
    }));
  }
  function setBenefitRatio(i, ratio, source) {
    state.benefits[i].sublimitRatio = ratio;
    const body = $("benefits-body");
    body.querySelector(`[data-sub="${i}"]`).textContent = zar0(ratio * state.cover);
    // keep the two controls roughly in sync without fighting the user's typing
    if (source !== "free") { const f = body.querySelector(`.bt-ratio-free[data-i="${i}"]`); if (f) f.value = +(ratio * 100).toFixed(2); }
    if (source !== "dropdown") { const d = body.querySelector(`.bt-ratio[data-i="${i}"]`); if (d) d.value = D.BENEFIT_SUBLIMIT_RATIOS.includes(ratio) ? String(ratio) : d.value; }
    recompute();
  }
  function refreshBenefitSublimits() {
    state.benefits.forEach((b, i) => {
      const el = $("benefits-body").querySelector(`[data-sub="${i}"]`);
      if (el) el.textContent = zar0(b.sublimitRatio * state.cover);
    });
  }

  // ---------- compute ----------
  function buildInputs() {
    return {
      turnover: state.turnover, cover: state.cover, subIndustry: state.subIndustry,
      maturityOverride: state.maturityOverride || "N/A", posture: null, vat: state.vat,
      benefits: state.benefits, excess: state.excess,
      fpAdjustableAmount: state.fpMode === "adjustable" ? state.fpAdjustableAmount : 0,
      mdr: state.mdr, discretionary: state.discretionary,
    };
  }
  // --- quote options (up to 3) ---
  function optCfgFromBase() { return { cover: state.cover, fpMode: state.fpMode, fpAdjustableAmount: state.fpAdjustableAmount }; }
  function optionInputsFor(o) {
    return Object.assign(buildInputs(), { cover: o.cover, fpAdjustableAmount: o.fpMode === "adjustable" ? o.fpAdjustableAmount : 0 });
  }
  function activeInputs() {
    if (state.step === 4 && state.options.length) return optionInputsFor(state.options[state.activeOption] || state.options[0]);
    return buildInputs();
  }

  let lastResult = null;
  function recompute() {
    if (!state.subIndustry || !state.turnover || !state.maturityOverride) { lastResult = null; updateTicker(); updateLiveHints(); return; }
    lastResult = E.computePremium(activeInputs());
    updateTicker(); updateLiveHints();
    if (state.step === 4) renderQuote();
  }
  function updateTicker() {
    const t = $("quoteTicker");
    if (lastResult && lastResult.ok) {
      $("tickerAnnual").textContent = zar0(lastResult.finalPremium);
      $("tickerMonthly").textContent = zar0(lastResult.monthly);
      t.classList.add("visible");
    } else t.classList.remove("visible");
  }
  // live hints that don't need a full valid quote
  function updateLiveHints() {
    // MDR discount display
    const mdrOpt = D.MDR_OPTIONS.find((m) => m.label === state.mdr);
    const mdrPct = mdrOpt ? mdrOpt.discount : 0;
    if (mdrPct > 0 && lastResult && lastResult.ok) $("mdr-discount").textContent = `−${pct(mdrPct)} discount · −${zar0(lastResult.mdrAmount)}`;
    else if (mdrPct > 0) $("mdr-discount").textContent = `−${pct(mdrPct)} discount applied.`;
    else $("mdr-discount").textContent = "No discount applied.";
    // Discretionary effect
    const eff = $("discretionary-effect");
    if (eff) {
      if (state.discretionary && lastResult && lastResult.ok) {
        const verb = state.discretionary >= 0 ? "discount" : "loading";
        eff.textContent = `${pct(Math.abs(state.discretionary))} ${verb} · ${state.discretionary >= 0 ? "−" : "+"}${zar0(Math.abs(lastResult.discretionaryAmount))}`;
      } else eff.textContent = "—";
    }
    // FP hint + below-10% warning
    if (state.fpMode === "adjustable") {
      const fr = state.fpAdjustableAmount > 0 ? E.fpAdjustableCost(state.fpAdjustableAmount) : { cost: 0, interpolated: false };
      $("fp-hint").textContent = state.fpAdjustableAmount > 0
        ? `Contribution: ${zar0(fr.cost)}${fr.interpolated ? " (interpolated between table values)" : ""}`
        : "Enter an amount from R500,000.";
      $("fp-warning").style.display = (state.fpAdjustableAmount > 0 && state.fpAdjustableAmount < 0.10 * state.cover) ? "flex" : "none";
    } else {
      $("fp-warning").style.display = "none";
    }
  }

  // ---------- step 4 render ----------
  function renderQuote() {
    const r = lastResult;
    const warn = $("quote-warning");
    if (!r || !r.ok) { warn.innerHTML = `<div class="banner danger"><span class="b-icon">&#9888;</span><span>${(r && r.error) || "Complete all inputs to generate a quote."}</span></div>`; return; }
    let warnHtml = r.warning ? `<div class="banner warn"><span class="b-icon">&#9888;</span><span>${r.warning}</span></div>` : "";
    if (r.fpBelowMin) warnHtml += `<div class="banner warn"><span class="b-icon">&#9888;</span><span>Funds Protect sub-limit is below 10% of the cover amount.</span></div>`;
    warn.innerHTML = warnHtml;

    if (!state.quoteRef) state.quoteRef = genRef();
    $("quote-ref").textContent = state.quoteRef;
    $("hp-amount").textContent = zar0(r.finalPremium);
    $("hp-vat-note").textContent = `(incl. ${pct(state.vat)} VAT)`;
    $("hp-monthly").textContent = `${zar0(r.monthly)} / month`;
    $("hp-exrm").textContent = zar0(r.premiumExRM);
    $("hp-exrm-monthly").textContent = `${zar0(r.monthlyExRM)} / month · before the 6% RM fee`;
    renderBenchmarkCompare(r);

    const kv = [
      ["Base premium", zar2(r.basePremium), "before discounts"],
      ["Funds Protect", zar0(r.fundsProtect), state.fpMode === "adjustable" ? "adjustable" + (r.fpInterpolated ? " (interp.)" : "") : "standard (10% of cover)"],
      ["Sophos MDR discount", r.mdrDiscount ? "−" + zar0(r.mdrAmount) : "—", r.mdrDiscount ? pct(r.mdrDiscount) + " — " + state.mdr : "No MDR"],
      ["Discretionary", r.discretionary ? (r.discretionary >= 0 ? "−" : "+") + zar0(Math.abs(r.discretionaryAmount)) : "—", r.discretionary ? pct(Math.abs(r.discretionary)) + (r.discretionary >= 0 ? " discount" : " loading") : "none"],
      ["Premium ex-Funds Protect", zar0(r.exFP), ""],
      ["Expected industry breach cost", zar0(r.expectedBreachCost), "SA-adjusted"],
      ["SME-equivalent (ex-FP, ex-VAT)", zar0(r.smeEquivalent), ""],
      ["SME / Corporate ratio line", zar0(r.smeRatio), "×" + D.CONSTANTS.SME_CORP_RATIO.toFixed(4)],
    ];
    $("kv-grid").innerHTML = kv.map(([l, v, s]) => `<div class="kv"><div class="kv-label">${l}</div><div class="kv-value">${v}</div>${s ? `<div class="kv-sub">${s}</div>` : ""}</div>`).join("");

    const fmtStep = (s) => s.kind === "pct" ? pct(s.value) : s.kind === "mult" ? "×" + Number(s.value).toFixed(2) : zar2(s.value);
    $("breakdown-body").innerHTML = r.steps.map((s) => {
      const isFinal = s.label === "Final premium";
      return `<tr class="${isFinal ? "bd-total" : ""}"><td>${s.label}${s.note ? `<span class="bd-note">${s.note}</span>` : ""}</td><td>${fmtStep(s)}</td></tr>`;
    }).join("");

    renderComparison();

    $("summary-benefits").innerHTML = r.benefitRows.map((b) =>
      `<tr class="${b.included ? "" : "excluded"}"><td class="bt-name">${b.name}</td><td>${b.included ? "Included" : "Excluded"}</td><td class="bt-sub">${b.included ? zar0(b.subLimit) + " (" + +(b.ratio * 100).toFixed(2) + "%)" : "—"}</td></tr>`
    ).join("");

    const qtLabel = { new: "New Business", renewal: "Renewal", competing: "Competing Quote" }[state.quoteType] || "New Business";
    const recap = [
      ["Quote type", qtLabel],
      ["Company", state.companyName || "—"],
      ["Industry", state.subIndustry],
      ["Annual turnover", zar0(state.turnover)],
      ["Cover amount", zar0(state.cover)],
      ["Excess", zar0(state.excess) + " (" + state.excessType + ")"],
      ["Cyber maturity", state.maturityOverride + " (×" + r.maturityMultiplier + ")"],
      ["Funds Protect", state.fpMode === "adjustable" ? zar0(state.fpAdjustableAmount) + " (adjustable)" : "Standard (10% of cover)"],
      ["Sophos MDR", state.mdr + (r.mdrDiscount ? " (−" + pct(r.mdrDiscount) + ")" : "")],
      ["Discretionary", r.discretionary ? pct(Math.abs(r.discretionary)) + (r.discretionary >= 0 ? " discount" : " loading") : "None"],
    ];
    if (state.quoteType === "renewal" && state.renewalPremium) recap.push(["Existing premium", zar0(state.renewalPremium)]);
    if (state.quoteType === "competing" && state.competitorPremium) recap.push(["Competitor", (state.competitorName || "—") + " · " + zar0(state.competitorPremium)]);
    $("recap-list").innerHTML = recap.map(([l, v]) => `<li><span class="rl-label">${l}</span><span class="rl-value">${v}</span></li>`).join("");
  }

  function renderComparison() {
    const rows = E.computeAcrossCovers(buildInputs());
    $("cover-comparison").innerHTML = rows.map((r) => {
      if (r.error) return `<tr><td class="bt-name">${zar0(r.cover)}</td><td colspan="3">${r.error}</td></tr>`;
      const sel = r.cover === state.cover;
      return `<tr style="${sel ? "background:rgba(0,180,216,0.10)" : ""}">` +
        `<td class="bt-name">${zar0(r.cover)}${sel ? ' <span class="bt-sub">← selected</span>' : ""}</td>` +
        `<td>${zar0(r.finalPremium)}${r.warning || r.fpBelowMin ? " &#9888;" : ""}</td>` +
        `<td>${zar0(r.monthly)}</td>` +
        `<td>${sel ? "" : `<button class="btn btn-ghost" style="padding:4px 12px;font-size:0.76rem" data-cover="${r.cover}">Use</button>`}</td></tr>`;
    }).join("");
    $("cover-comparison").querySelectorAll("button[data-cover]").forEach((b) => b.addEventListener("click", () => {
      const c = +b.dataset.cover;
      if (state.options.length) { state.options[state.activeOption].cover = c; selectOption(state.activeOption); }
      else { state.cover = c; $("cover").value = c; refreshBenefitSublimits(); recompute(); }
    }));
  }

  function benchBar(label, value, max, cls) {
    const w = max > 0 ? Math.max(2, (value / max) * 100) : 0;
    return `<div class="bench-row"><div class="bench-label">${label}</div><div class="bench-bar-track"><div class="bench-bar-fill ${cls}" style="width:${w}%"></div></div><div class="bench-amount">${zar0(value)}</div></div>`;
  }
  // Renewal / Competing benchmark comparison block (hidden for New Business).
  function renderBenchmarkCompare(r) {
    const el = $("benchmark-compare");
    if (!el) return;
    if (state.quoteType === "renewal" && state.renewalPremium > 0) {
      const ours = r.finalPremium, ex = state.renewalPremium;
      const pctChg = (ours - ex) / ex, retention = ours / ex, max = Math.max(ours, ex);
      let verdict, vclass;
      if (ours < 0.8 * ex) { verdict = `New premium is ${pct(Math.abs(pctChg))} below the expiring premium — review cover/terms to retain value.`; vclass = "neutral"; }
      else if (ours <= ex) { verdict = `${pct(Math.abs(pctChg))} below the expiring premium.`; vclass = "win"; }
      else { verdict = `${pct(pctChg)} above the expiring premium.`; vclass = "lose"; }
      el.innerHTML =
        `<div class="section-title">Renewal — vs Existing Policy</div>` +
        `<div class="bench-wrap">${benchBar("Phishield (new)", ours, max, "ours")}${benchBar("Existing policy", ex, max, "them")}</div>` +
        `<div class="bench-verdict ${vclass}">${verdict}</div>` +
        `<div class="field-hint">Retention: ${pct(retention)} of expiring premium${state.renewalFP ? " · existing FP " + zar0(state.renewalFP) : ""}${state.renewalCover ? " · existing cover " + zar0(state.renewalCover) : ""}.</div>`;
    } else if (state.quoteType === "competing" && state.competitorPremium > 0) {
      const ours = state.competitorHasFP ? r.finalPremium : r.exFP, comp = state.competitorPremium;
      const pctChg = (ours - comp) / comp, max = Math.max(ours, comp);
      const basis = state.competitorHasFP ? "incl. FP" : "ex-FP", who = state.competitorName || "Competitor";
      let verdict, vclass;
      if (ours < comp) { verdict = `Phishield is ${pct(Math.abs(pctChg))} cheaper than ${who} (${basis}).`; vclass = "win"; }
      else if (Math.abs(pctChg) <= 0.05) { verdict = `Within ${pct(Math.abs(pctChg))} of ${who} (${basis}).`; vclass = "neutral"; }
      else { verdict = `Phishield is ${pct(pctChg)} above ${who} (${basis}).`; vclass = "lose"; }
      el.innerHTML =
        `<div class="section-title">Competing Quote — vs ${who}</div>` +
        `<div class="bench-wrap">${benchBar(`Phishield (${basis})`, ours, max, "ours")}${benchBar(who, comp, max, "them")}</div>` +
        `<div class="bench-verdict ${vclass}">${verdict}</div>` +
        (state.competitorLimit ? `<div class="field-hint">Competitor limit ${zar0(state.competitorLimit)} vs our cover ${zar0(state.cover)}.</div>` : "");
    } else {
      el.innerHTML = "";
    }
  }

  function renderOptionsBar() {
    const bar = $("options-bar");
    if (!bar) return;
    if (!state.options.length) { state.options = [optCfgFromBase()]; state.activeOption = 0; }
    const fpAmts = D.FP_ADJUSTABLE.amounts.filter((a) => a >= 500000);
    const cards = state.options.map((o, i) => {
      const res = E.computePremium(optionInputsFor(o));
      const prem = res.ok ? zar0(res.finalPremium) : "—";
      const monthly = res.ok ? zar0(res.monthly) + " / mo" : "";
      const coverOpts = D.COVER_OPTIONS.map((c) => `<option value="${c}" ${c === o.cover ? "selected" : ""}>${zar0(c)}</option>`).join("");
      const fpOpts = `<option value="standard" ${o.fpMode === "standard" ? "selected" : ""}>Standard (10%)</option>` +
        fpAmts.map((a) => `<option value="${a}" ${o.fpMode === "adjustable" && o.fpAdjustableAmount === a ? "selected" : ""}>FP ${zar0(a)}</option>`).join("");
      return `<div class="opt-card ${i === state.activeOption ? "active" : ""}" data-opt="${i}">
        <div class="opt-head"><span class="opt-title">Option ${i + 1}</span>${state.options.length > 1 ? `<button class="opt-remove" data-rm="${i}" title="Remove">✕</button>` : ""}</div>
        <label class="opt-field">Cover<select class="form-select opt-cover" data-opt="${i}">${coverOpts}</select></label>
        <label class="opt-field">Funds Protect<select class="form-select opt-fp" data-opt="${i}">${fpOpts}</select></label>
        <div class="opt-premium">${prem}<span class="opt-pm-sub">${monthly}</span></div>
      </div>`;
    }).join("");
    bar.innerHTML = `<div class="opt-cards">${cards}</div><button class="opt-add" id="opt-add" ${state.options.length >= 3 ? "disabled" : ""}>+ Add quote option</button>`;
    bar.querySelectorAll(".opt-card").forEach((card) => card.addEventListener("click", (e) => {
      if (e.target.closest("select") || e.target.closest(".opt-remove")) return;
      selectOption(+card.dataset.opt);
    }));
    bar.querySelectorAll(".opt-cover").forEach((sel) => sel.addEventListener("change", (e) => {
      const i = +e.target.dataset.opt; state.options[i].cover = parseNum(e.target.value);
      i === state.activeOption ? selectOption(i) : renderOptionsBar();
    }));
    bar.querySelectorAll(".opt-fp").forEach((sel) => sel.addEventListener("change", (e) => {
      const i = +e.target.dataset.opt, v = e.target.value;
      if (v === "standard") { state.options[i].fpMode = "standard"; state.options[i].fpAdjustableAmount = 0; }
      else { state.options[i].fpMode = "adjustable"; state.options[i].fpAdjustableAmount = parseNum(v); }
      i === state.activeOption ? selectOption(i) : renderOptionsBar();
    }));
    bar.querySelectorAll(".opt-remove").forEach((b) => b.addEventListener("click", (e) => { e.stopPropagation(); removeOption(+b.dataset.rm); }));
    const add = $("opt-add"); if (add) add.addEventListener("click", addOption);
  }
  function selectOption(i) {
    state.activeOption = i;
    const o = state.options[i];
    state.cover = o.cover; state.fpMode = o.fpMode; state.fpAdjustableAmount = o.fpAdjustableAmount;
    if ($("cover")) $("cover").value = o.cover;
    recompute(); renderOptionsBar();
  }
  function addOption() {
    if (state.options.length >= 3) return;
    const b = state.options[state.activeOption];
    state.options.push({ cover: b.cover, fpMode: b.fpMode, fpAdjustableAmount: b.fpAdjustableAmount });
    selectOption(state.options.length - 1);
  }
  function removeOption(i) {
    if (state.options.length <= 1) return;
    state.options.splice(i, 1);
    selectOption(Math.min(state.activeOption, state.options.length - 1));
  }

  function genRef() {
    const d = new Date();
    const ymd = d.getFullYear() + String(d.getMonth() + 1).padStart(2, "0") + String(d.getDate()).padStart(2, "0");
    return `CRE-${ymd}-${String(Math.floor(1000 + Math.random() * 9000))}`;
  }

  // ---------- navigation ----------
  function goToStep(n) {
    state.step = n;
    document.querySelectorAll(".step-panel").forEach((p) => p.classList.toggle("active", +p.dataset.step === n));
    document.querySelectorAll(".progress-step").forEach((b) => {
      const s = +b.dataset.step;
      b.classList.toggle("active", s === n);
      b.classList.toggle("completed", s < n);
    });
    $("progressFill").style.width = ((n - 1) / 3) * 100 + "%";
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (n === 4) {
      // single option tracks the base selection; multiple options are user-curated
      if (state.options.length <= 1) { state.options = [optCfgFromBase()]; state.activeOption = 0; }
      renderOptionsBar();
      recompute();
    }
  }

  function validateStep1() {
    let ok = true;
    if (!state.turnover || state.turnover <= 0) { $("turnover").classList.add("invalid"); ok = false; } else $("turnover").classList.remove("invalid");
    if (!state.subIndustry) { $("industry-search").classList.add("invalid"); ok = false; } else $("industry-search").classList.remove("invalid");
    return ok;
  }

  // ---------- PDF ----------
  function generatePDF(forSave, optIdx) {
    if (!window.jspdf || !window.jspdf.jsPDF) { if (!forSave) toast("PDF library not loaded", "error"); return null; }
    const o = (optIdx != null && state.options[optIdx]) ? state.options[optIdx] : null;
    const r = o ? E.computePremium(optionInputsFor(o)) : lastResult;
    if (!r || !r.ok) { if (!forSave) toast("Complete the quote first", "error"); return null; }
    const oCover = o ? o.cover : state.cover;
    const oFP = (o ? o.fpMode : state.fpMode) === "adjustable" ? zar0(o ? o.fpAdjustableAmount : state.fpAdjustableAmount) + " (adj.)" : "Standard 10%";
    const multi = state.options.length > 1;
    const baseRef = state.quoteRef || (state.quoteRef = genRef());
    const ref = (multi && optIdx != null) ? baseRef + "-Opt" + (optIdx + 1) : baseRef;
    const doc = new window.jspdf.jsPDF({ unit: "pt", format: "a4" });
    const W = doc.internal.pageSize.getWidth();
    const M = 40;
    let y = 0;
    const pageBreak = (limit) => { if (y > (limit || 760)) { doc.addPage(); y = 50; } };

    // Header band
    doc.setFillColor(0, 29, 61); doc.rect(0, 0, W, 70, "F");
    doc.setFillColor(0, 180, 216); doc.rect(0, 70, W, 3, "F");
    doc.setTextColor(255, 255, 255); doc.setFont("helvetica", "bold"); doc.setFontSize(18);
    doc.text("Phishield", M, 32);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11);
    doc.text("Corporate Rating Engine — Cyber Quote", M, 50);
    doc.setFontSize(9); doc.setTextColor(180, 200, 220);
    doc.text(new Date().toLocaleDateString("en-ZA"), W - M, 30, { align: "right" });
    doc.text("Internal use only", W - M, 46, { align: "right" });
    y = 96;

    // Company + ref
    doc.setTextColor(20, 20, 20); doc.setFont("helvetica", "bold"); doc.setFontSize(13);
    doc.text((state.companyName || "—") + (multi && optIdx != null ? "  ·  Option " + (optIdx + 1) : ""), M, y);
    doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(90, 90, 90);
    doc.text("Quote ref: " + ref, W - M, y, { align: "right" });
    y += 20;

    // Client details (2 columns)
    const qtLabel = { new: "New Business", renewal: "Renewal", competing: "Competing Quote" }[state.quoteType] || "New Business";
    const details = [
      ["Quote type", qtLabel], ["Industry", state.subIndustry],
      ["Annual turnover", zar0(state.turnover)], ["Cover amount", zar0(oCover)],
      ["Excess", zar0(state.excess) + " (" + state.excessType + ")"], ["Cyber maturity", state.maturityOverride + " (×" + r.maturityMultiplier + ")"],
      ["Funds Protect", oFP], ["Sophos MDR", state.mdr],
    ];
    doc.setFontSize(9);
    details.forEach((d, i) => {
      const x = M + (i % 2) * ((W - 2 * M) / 2), yy = y + Math.floor(i / 2) * 15;
      doc.setTextColor(120, 120, 120); doc.text(d[0] + ":", x, yy);
      doc.setTextColor(30, 30, 30); doc.text(String(d[1]).slice(0, 50), x + 88, yy);
    });
    y += Math.ceil(details.length / 2) * 15 + 14;

    // Premium build-up
    const heading = (t) => { doc.setFont("helvetica", "bold"); doc.setFontSize(10); doc.setTextColor(0, 119, 182); doc.text(t, M, y); y += 5; doc.setDrawColor(220, 220, 220); doc.line(M, y, W - M, y); y += 14; doc.setFont("helvetica", "normal"); doc.setFontSize(9); };
    heading("PREMIUM BUILD-UP");
    r.steps.forEach((s) => {
      const val = s.kind === "pct" ? pct(s.value) : s.kind === "mult" ? "×" + Number(s.value).toFixed(2) : zar2(s.value);
      const isFinal = s.label === "Final premium";
      if (isFinal) { doc.setFont("helvetica", "bold"); doc.setDrawColor(0, 180, 216); doc.line(M, y - 9, W - M, y - 9); }
      doc.setTextColor(isFinal ? 20 : 70, isFinal ? 20 : 70, isFinal ? 20 : 70);
      doc.text(s.label + (s.note ? "  (" + s.note + ")" : ""), M, y);
      doc.text(val, W - M, y, { align: "right" });
      if (isFinal) doc.setFont("helvetica", "normal");
      y += 14; pageBreak();
    });
    y += 6;

    // Final premium box
    doc.setFillColor(240, 248, 250); doc.roundedRect(M, y, W - 2 * M, 66, 4, 4, "F");
    doc.setFont("helvetica", "bold"); doc.setFontSize(10); doc.setTextColor(0, 119, 182);
    doc.text("FINAL ANNUAL PREMIUM (incl. " + pct(state.vat) + " VAT)", M + 14, y + 21);
    doc.setFontSize(15); doc.setTextColor(20, 20, 20);
    doc.text(zar0(r.finalPremium), W - M - 14, y + 23, { align: "right" });
    doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(80, 80, 80);
    doc.text("Premium without RM fee (admin input): " + zar0(r.premiumExRM) + "  ·  " + zar0(r.monthlyExRM) + "/month", M + 14, y + 45);
    doc.setFontSize(7.5); doc.setTextColor(130, 130, 130);
    doc.text("The administration platform adds a 6% RM fee to this input figure to reach the final premium.", M + 14, y + 58);
    y += 84; pageBreak();

    // Benchmark
    if (state.quoteType === "renewal" && state.renewalPremium > 0) {
      const chg = (r.finalPremium - state.renewalPremium) / state.renewalPremium;
      doc.setFont("helvetica", "bold"); doc.setFontSize(9); doc.setTextColor(30, 30, 30);
      doc.text("Renewal vs existing policy: " + zar0(r.finalPremium) + " vs " + zar0(state.renewalPremium) + "  (" + (chg <= 0 ? "−" : "+") + pct(Math.abs(chg)) + ")", M, y);
      y += 18;
    } else if (state.quoteType === "competing" && state.competitorPremium > 0) {
      const ours = state.competitorHasFP ? r.finalPremium : r.exFP;
      doc.setFont("helvetica", "bold"); doc.setFontSize(9); doc.setTextColor(30, 30, 30);
      doc.text("Vs " + (state.competitorName || "competitor") + " (" + (state.competitorHasFP ? "incl FP" : "ex-FP") + "): " + zar0(ours) + " vs " + zar0(state.competitorPremium), M, y);
      y += 18;
    }
    pageBreak();

    // Benefits
    heading("INSURING CLAUSES & SUB-LIMITS");
    doc.setFontSize(8.5);
    r.benefitRows.forEach((b) => {
      doc.setTextColor(b.included ? 40 : 165, b.included ? 40 : 165, b.included ? 40 : 165);
      doc.text(b.name, M, y);
      doc.text(b.included ? "Included" : "Excluded", M + 270, y);
      doc.text(b.included ? zar0(b.subLimit) + " (" + Math.round(b.ratio * 100) + "%)" : "—", W - M, y, { align: "right" });
      y += 13; pageBreak(780);
    });

    // Footer
    doc.setFontSize(7.5); doc.setTextColor(150, 150, 150);
    doc.text("Phishield UMA (Pty) Ltd — Corporate Rating Engine. Premiums are indicative and subject to final underwriting approval. Not for distribution.", M, 815);

    if (forSave) return doc.output("datauristring").split(",")[1];
    const slug = (state.companyName || "quote").replace(/[^a-zA-Z0-9]/g, "_").replace(/_+/g, "_");
    doc.save(slug + "_" + ref + ".pdf");
    toast("PDF downloaded", "success");
    return null;
  }

  // ---------- save / export ----------
  async function saveQuote() {
    if (!lastResult || !lastResult.ok) return toast("Complete the quote first", "error");
    const baseRef = state.quoteRef || (state.quoteRef = genRef());
    const opts = state.options.length ? state.options : [optCfgFromBase()];
    const multi = opts.length > 1;
    let saved = 0;
    for (let i = 0; i < opts.length; i++) {
      const o = opts[i];
      const res = E.computePremium(optionInputsFor(o));
      if (!res.ok) continue;
      const ref = multi ? baseRef + "-Opt" + (i + 1) : baseRef;
      const payload = {
        quote_ref: ref, company_name: state.companyName, website: state.website,
        sub_industry: state.subIndustry, turnover: state.turnover, cover: o.cover, excess: state.excess,
        vat: state.vat, maturity: state.maturityOverride, fp_mode: o.fpMode, fp_adjustable: o.fpAdjustableAmount,
        mdr: state.mdr, benefits: state.benefits, final_premium: res.finalPremium, base_premium: res.basePremium,
        pdf_base64: generatePDF(true, multi ? i : null),
        inputs: optionInputsFor(o),
        result: {
          quoteType: state.quoteType, option: i + 1, finalPremium: res.finalPremium, premiumExRM: res.premiumExRM, monthly: res.monthly,
          discretionary: state.discretionary,
          renewal: state.quoteType === "renewal" ? { cover: state.renewalCover, premium: state.renewalPremium, fp: state.renewalFP } : null,
          competitor: state.quoteType === "competing" ? { name: state.competitorName, premium: state.competitorPremium, limit: state.competitorLimit, hasFP: state.competitorHasFP } : null,
          steps: res.steps,
        },
      };
      try { const rr = await fetch("/api/quotes", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); if (rr.ok) saved++; } catch (e) { /* offline */ }
    }
    if (saved) toast(saved > 1 ? saved + " quote options saved · " + baseRef : "Quote saved · " + baseRef, "success");
    else toast("Save failed (backend offline?) — quote held locally", "error");
  }

  function copyQuote() {
    if (!lastResult || !lastResult.ok) return toast("Complete the quote first", "error");
    const r = lastResult;
    const lines = [
      `Phishield Corporate Cyber — Quote ${state.quoteRef}`,
      `Company: ${state.companyName || "—"}`,
      `Industry: ${state.subIndustry}`,
      `Turnover: ${zar0(state.turnover)}   Cover: ${zar0(state.cover)}   Excess: ${zar0(state.excess)}`,
      `Cyber maturity: ${state.maturityOverride}   Sophos MDR: ${state.mdr}` + (r.discretionary ? `   Discretionary: ${pct(Math.abs(r.discretionary))} ${r.discretionary >= 0 ? "discount" : "loading"}` : ""),
      `Base premium: ${zar2(r.basePremium)}`,
      `FINAL ANNUAL PREMIUM (incl. ${pct(state.vat)} VAT): ${zar0(r.finalPremium)}   (${zar0(r.monthly)}/month)`,
    ];
    navigator.clipboard.writeText(lines.join("\n")).then(() => toast("Quote copied to clipboard", "success"), () => toast("Copy failed", "error"));
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg; t.className = "toast show " + (kind || "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.className = "toast"), 3200);
  }

  // ---------- wire up ----------
  function init() {
    initDropdowns();
    initIndustrySelect();
    initMaturityCards();
    initBenefitsTable();

    $("company-name").addEventListener("input", (e) => (state.companyName = e.target.value));
    $("company-website").addEventListener("input", (e) => (state.website = e.target.value));
    $("turnover").addEventListener("input", (e) => { state.turnover = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });
    $("cover").addEventListener("change", (e) => { state.cover = parseNum(e.target.value); refreshBenefitSublimits(); checkExcess(); recompute(); });
    $("excess").addEventListener("change", (e) => { state.excess = parseNum(e.target.value); checkExcess(); recompute(); });
    $("excess-type").addEventListener("change", (e) => (state.excessType = e.target.value));
    $("vat").addEventListener("change", (e) => { state.vat = parseFloat(e.target.value); recompute(); });
    $("mdr").addEventListener("change", (e) => { state.mdr = e.target.value; recompute(); });
    $("discretionary").addEventListener("input", (e) => { const v = parseFloat(e.target.value); state.discretionary = isNaN(v) ? 0 : v / 100; recompute(); });

    $("fp-mode").querySelectorAll(".pill").forEach((p) => p.addEventListener("click", () => {
      state.fpMode = p.dataset.fp;
      $("fp-mode").querySelectorAll(".pill").forEach((x) => x.classList.toggle("selected", x === p));
      $("fp-adjustable-group").style.display = state.fpMode === "adjustable" ? "block" : "none";
      if (state.fpMode === "adjustable") {
        if (!state.fpAdjustableAmount || state.fpAdjustableAmount < 500000) state.fpAdjustableAmount = 500000;
        $("fp-adjustable").value = groupNum(state.fpAdjustableAmount);
      }
      recompute();
    }));
    $("fp-adjustable").addEventListener("input", (e) => { state.fpAdjustableAmount = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });

    // Quote-type branches
    $("quote-type").querySelectorAll(".pill").forEach((p) => p.addEventListener("click", () => {
      state.quoteType = p.dataset.qt;
      $("quote-type").querySelectorAll(".pill").forEach((x) => x.classList.toggle("selected", x === p));
      $("renewal-section").style.display = state.quoteType === "renewal" ? "block" : "none";
      $("competing-section").style.display = state.quoteType === "competing" ? "block" : "none";
      const mb = $("market-badge");
      if (state.quoteType === "renewal") { mb.style.display = "block"; mb.textContent = "Market condition: " + MARKET_CONDITION.label; }
      else mb.style.display = "none";
      recompute();
    }));
    $("renewal-cover").addEventListener("change", (e) => { state.renewalCover = parseNum(e.target.value); recompute(); });
    $("renewal-premium").addEventListener("input", (e) => { state.renewalPremium = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });
    $("renewal-fp").addEventListener("input", (e) => { state.renewalFP = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });
    $("competitor-name").addEventListener("input", (e) => { state.competitorName = e.target.value; recompute(); });
    $("competitor-premium").addEventListener("input", (e) => { state.competitorPremium = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });
    $("competitor-limit").addEventListener("input", (e) => { state.competitorLimit = parseNum(e.target.value); e.target.value = groupNum(e.target.value); recompute(); });
    $("competitor-fp").querySelectorAll(".pill").forEach((p) => p.addEventListener("click", () => {
      state.competitorHasFP = p.dataset.cfp === "yes";
      $("competitor-fp").querySelectorAll(".pill").forEach((x) => x.classList.toggle("selected", x === p));
      recompute();
    }));

    $("next-1").addEventListener("click", () => { if (validateStep1()) goToStep(2); });
    $("back-2").addEventListener("click", () => goToStep(1));
    $("next-2").addEventListener("click", () => goToStep(3));
    $("back-3").addEventListener("click", () => goToStep(2));
    $("next-3").addEventListener("click", () => goToStep(4));
    $("back-4").addEventListener("click", () => goToStep(3));
    document.querySelectorAll(".progress-step").forEach((b) => b.addEventListener("click", () => { const s = +b.dataset.step; if (s < state.step || (s === 2 && validateStep1())) goToStep(s); }));

    $("btn-save").addEventListener("click", saveQuote);
    $("btn-copy").addEventListener("click", copyQuote);
    $("btn-print").addEventListener("click", () => window.print());
    $("btn-pdf").addEventListener("click", () => {
      if (state.options.length > 1) state.options.forEach((_, i) => setTimeout(() => generatePDF(false, i), i * 400));
      else generatePDF(false, state.options.length ? state.activeOption : null);
    });
  }

  function checkExcess() {
    $("excess-warning").style.display = state.excess > 0.5 * state.cover ? "flex" : "none";
  }

  document.addEventListener("DOMContentLoaded", init);
})();
