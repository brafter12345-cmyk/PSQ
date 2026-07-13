/* assessment.js — risk-assessment upload + conversion (Phase 1) + mapping scorecard (Phase 2).
 * Uploads to /api/ingest (local extraction), then /api/map (redact → map → scorecard).
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const dz = $("dropzone");
  const input = $("file-input");
  let lastStored = null;

  // ---- drag & drop ----
  dz.addEventListener("click", () => input.click());
  ["dragenter", "dragover"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("dragover"); }));
  dz.addEventListener("drop", (e) => { const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) upload(f); });
  input.addEventListener("change", (e) => { const f = e.target.files && e.target.files[0]; if (f) upload(f); });

  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const kb = (n) => n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.round(n / 1024) + " KB";
  const pct = (x) => Math.round((x || 0) * 100) + "%";
  const rcls = (label) => "r-" + String(label || "na").toLowerCase().replace(/[^a-z]/g, "");
  const banner = (cls, icon, html) => `<div class="banner ${cls}" style="margin-top:16px"><span class="b-icon">${icon}</span><span>${html}</span></div>`;

  // ---- Phase 1: upload + convert ----
  async function upload(file) {
    $("ingest-result").innerHTML = ""; $("map-result").innerHTML = ""; $("map-status").innerHTML = "";
    $("ingest-status").innerHTML = banner("info", "⏳", `Converting <strong>${esc(file.name)}</strong> (${kb(file.size)})…`);
    const fd = new FormData(); fd.append("file", file);
    try {
      const res = await fetch("/api/ingest", { method: "POST", body: fd });
      const data = await res.json();
      $("ingest-status").innerHTML = "";
      if (!data.ok) { $("ingest-status").innerHTML = banner("danger", "&#9888;", esc(data.error || "Could not convert this file.")); return; }
      renderResult(data);
      toast("Converted · " + data.filename, "success");
    } catch (err) {
      $("ingest-status").innerHTML = banner("danger", "&#9888;", "Upload failed (is the backend running?). " + esc(String(err)));
    }
  }

  function renderResult(d) {
    lastStored = d.stored_as;
    const chips = [
      `<span class="meta-chip">${esc(d.filename)}</span>`,
      `<span class="meta-chip">${(d.format || "?").toUpperCase()}</span>`,
      (d.pages != null ? `<span class="meta-chip">${d.pages} page${d.pages === 1 ? "" : "s"}</span>` : ""),
      `<span class="meta-chip">${(d.chars || 0).toLocaleString()} chars</span>`,
      d.needs_ocr
        ? `<span class="meta-chip warn">OCR required — ${(d.ocr_pages || []).length}/${d.pages || "?"} page(s) scanned</span>`
        : `<span class="meta-chip ok">Text read directly — no OCR needed</span>`,
    ].join("");
    const notes = (d.notes && d.notes.length) ? banner("warn", "&#9888;", d.notes.map(esc).join("<br>")) : "";
    const body = d.text && d.text.trim()
      ? `<div class="section-title">Extracted Text</div><div class="extract-text">${esc(d.text)}</div>`
      : banner("info", "&#9432;", "No machine-readable text — the vision step (Phase 2) will read it.");
    const seeds = d.scan_seeds || { domains: [], ips: [] };
    const seedHtml = (seeds.domains.length || seeds.ips.length)
      ? `<div class="section-title">External-Scan Targets <span class="field-hint" style="display:inline;text-transform:none;letter-spacing:0">— detected on the form; confirm before scanning</span></div>` +
        `<div class="extract-meta">${seeds.domains.map((x) => `<span class="meta-chip ok">${esc(x)}</span>`).join("")}${seeds.ips.map((x) => `<span class="meta-chip">${esc(x)}</span>`).join("")}</div>` +
        `<div class="field-hint">These seed the external scan (run in the closed environment) and are redacted before the mapping step.</div>`
      : "";
    $("ingest-result").innerHTML =
      `<div class="extract-meta">${chips}</div>${notes}${body}${seedHtml}` +
      `<div class="btn-row"><span></span><button class="btn btn-primary" id="btn-map">Map to our questionnaire →</button></div>`;
    $("btn-map").addEventListener("click", runMap);
  }

  // ---- Phase 2: map against our questionnaire ----
  async function runMap() {
    if (!lastStored) return;
    $("map-result").innerHTML = "";
    $("map-status").innerHTML = banner("info", "⏳", "Redacting PII &amp; mapping against our questionnaire…");
    try {
      const res = await fetch("/api/map", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ stored_as: lastStored }) });
      const d = await res.json();
      $("map-status").innerHTML = "";
      if (!d.ok) { $("map-status").innerHTML = banner("danger", "&#9888;", esc(d.error || "Mapping failed.")); return; }
      renderScorecard(d);
      toast("Mapped (" + d.engine + ")", "success");
    } catch (err) {
      $("map-status").innerHTML = banner("danger", "&#9888;", "Mapping request failed. " + esc(String(err)));
    }
  }

  function renderScorecard(d) {
    const reqSet = new Set();
    d.families.forEach((f) => f.controls.forEach((c) => { if (c.required) reqSet.add(c.name); }));
    const mr = d.minimumRequirements || { met: [], unmet: [], ready: false };
    const gate = mr.ready
      ? `<div class="banner" style="background:rgba(46,196,182,0.08);border:1px solid rgba(46,196,182,0.3);color:var(--success)"><span class="b-icon">✓</span><span><strong>Minimum requirements met</strong> — all ${mr.met.length} required controls favourable; eligible to rate &amp; quote.</span></div>`
      : `<div class="banner warn"><span class="b-icon">&#9888;</span><span><strong>${mr.unmet.length} minimum requirement(s) outstanding</strong> before rating: ${mr.unmet.map(esc).join(", ")}</span></div>`;
    const engineChips = `<span class="meta-chip">${d.engine === "claude" ? "Claude mapping" : "Offline mock"}</span> <span class="meta-chip">redaction: ${esc(d.redaction)}</span>`;

    const hero =
      `<div class="score-hero">
        <div class="score-badge"><div class="sb-num">${d.overallScore}<span class="sb-of">/5</span></div><div class="sb-label ${rcls(d.overallLabel)}">${esc(d.overallLabel)}</div></div>
        <div class="kv"><div class="kv-label">Favourable responses</div><div class="kv-value">${pct(d.favorablePct)}</div></div>
        <div class="kv"><div class="kv-label">Completeness</div><div class="kv-value">${pct(d.completeness)}</div><div class="kv-sub">${d.counts.favorable + d.counts.deficient}/${d.counts.total} controls addressed</div></div>
        <div class="kv"><div class="kv-label">Controls</div><div class="kv-value">${d.counts.favorable}✓ / ${d.counts.deficient}⚠ / ${d.counts.missing}✕</div><div class="kv-sub">favourable / deficient / missing</div></div>
      </div>`;
    const famRows = d.families.map((f) =>
      `<tr><td class="bt-name">${esc(f.name)}</td><td><span class="rating-pill ${rcls(f.rating)}">${esc(f.rating)}</span></td><td><span class="fam-pct"><span style="width:${pct(f.favorablePct)}"></span></span>${pct(f.favorablePct)}</td><td>${pct(f.completeness)}</td></tr>`
    ).join("");
    const star = (n) => reqSet.has(n) ? '<span class="req-star" title="Minimum requirement">★</span> ' : "";
    const col = (title, arr, cls) =>
      `<div class="cdm-col"><h4 class="${cls}">${title} (${arr.length})</h4><ul>${arr.length ? arr.map((n) => `<li>${star(n)}${esc(n)}</li>`).join("") : "<li style='color:var(--text-muted)'>—</li>"}</ul></div>`;

    $("map-result").innerHTML =
      `<div class="section-title" style="margin-top:22px">Posture Map vs Our Questionnaire &nbsp; ${engineChips}</div>` +
      gate + hero +
      `<div class="section-title">Control Families</div>` +
      `<table class="benefits-table"><thead><tr><th>Family</th><th style="width:90px">Rating</th><th style="width:200px">Favourable</th><th style="width:110px">Completeness</th></tr></thead><tbody>${famRows}</tbody></table>` +
      `<div class="section-title">Controls — Favourable · Deficient · Missing &nbsp;<span class="field-hint" style="display:inline;text-transform:none;letter-spacing:0">★ = minimum requirement</span></div>` +
      `<div class="cdm-cols">${col("Favourable", d.favorable, "r-strong")}${col("Deficient", d.deficient, "r-moderate")}${col("Missing", d.missing, "r-critical")}</div>` +
      banner("info", "&#9432;", (d.engine === "claude"
        ? "Mapped by Claude on redacted text."
        : "Offline <strong>mock</strong> (keyword) mapper for plumbing tests — it can't read negation (e.g. &quot;no MDR&quot;). Set <code>ANTHROPIC_API_KEY</code> for accurate Claude mapping.")
        + " Next: attach this as a gap report to the quote &amp; auto-fill Step 2 posture.");
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg; t.className = "toast show " + (kind || "");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = "toast"), 3000);
  }
})();
