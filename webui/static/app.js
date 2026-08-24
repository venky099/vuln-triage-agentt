(() => {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  const scanEl     = $("#scan");
  const findingsEl = $("#findings");
  const bannerEl   = $("#diff-banner");
  const progressEl = $("#progress");
  const runEl      = $("#run");
  const runLabel   = $("#run-label");
  const parseChip  = $("#parse-chip");
  const emptyEl    = $("#empty");
  const reportEl   = $("#report");
  const headEl     = $("#results-head");
  const footEl     = $("#results-foot");

  let state = null;      // last successful /api/triage payload
  let grounded = true;   // which view is showing
  let openRows = new Set();

  // ------------------------------------------------------------- helpers

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function toast(msg, kind) {
    const el = document.createElement("div");
    el.className = "toast" + (kind ? " " + kind : "");
    el.innerHTML = `<span class="ico">${kind === "err" ? "⚠" : kind === "ok" ? "✓" : "•"}</span><span>${esc(msg)}</span>`;
    $("#toasts").appendChild(el);
    setTimeout(() => {
      el.style.transition = "opacity .25s, transform .25s";
      el.style.opacity = "0";
      el.style.transform = "translateY(6px)";
      setTimeout(() => el.remove(), 260);
    }, kind === "err" ? 6000 : 3200);
  }

  // Highlight the two states a claim can be in: a fabricated identifier the
  // model produced, or the marker left behind after it was removed.
  function markClaims(text) {
    let out = esc(text);
    out = out.replace(/\[UNVERIFIED REFERENCE REMOVED\]|\[UNSUPPORTED CLAIM REMOVED\]/g,
      (m) => `<span class="redacted">${m}</span>`);
    out = out.replace(/\bCVE-\d{4}-\d{4,7}\b/g,
      (m) => `<span class="fabricated" title="Not present in the scan data">${m}</span>`);
    return out;
  }

  // --------------------------------------------- live scan introspection

  // Says what the server would make of the paste before a request is spent on
  // it: valid JSON, which format, how many findings.
  function inspect() {
    const raw = scanEl.value.trim();
    if (!raw) {
      parseChip.className = "chip";
      parseChip.textContent = "Empty";
      return;
    }
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      parseChip.className = "chip err";
      parseChip.textContent = "Invalid JSON";
      return;
    }
    if (Array.isArray(data)) data = { findings: data };
    // Mirrors detect_format() in triage/parsers.py -- keep the two in step.
    const fmt = data.site ? "zap"
      : data.hosts ? "nmap"
      : (data.issues || data.issue_events) ? "burp"
      : "vibescanner";
    let n = 0;
    if (fmt === "vibescanner") {
      n = (data.findings || data.results || []).length;
    } else if (fmt === "burp") {
      n = (data.issues || data.issue_events || []).length;
    } else if (fmt === "zap") {
      (data.site || []).forEach((s) => (s.alerts || []).forEach((a) => { n += (a.instances || [{}]).length; }));
    } else {
      (data.hosts || []).forEach((h) => (h.ports || []).forEach((p) => { if (p.state === "open") n++; }));
    }
    parseChip.className = "chip ok";
    parseChip.textContent = `${fmt} · ${plural(n, "finding", "findings")}`;
  }
  scanEl.addEventListener("input", inspect);

  // ------------------------------------------------------ backend picker

  // The key and model inputs live in the app bar, so they appear beside the
  // choice that needs them rather than in a panel somewhere below.
  function syncBackendFields() {
    const which = $('input[name="backend"]:checked').value;
    $("#api-key").hidden = which !== "openai";
    const model = $("#ollama-model");
    if (model) model.hidden = which !== "ollama";
  }
  $$('input[name="backend"]').forEach((r) => r.addEventListener("change", syncBackendFields));

  $("#load-example").addEventListener("click", async () => {
    try {
      const res = await fetch("/api/example");
      scanEl.value = JSON.stringify(await res.json(), null, 2);
      inspect();
      toast("Example scan loaded", "ok");
    } catch {
      toast("Could not load the example.", "err");
    }
  });

  // ---------------------------------------------------------------- run

  function setBusy(busy, label) {
    runEl.disabled = busy;
    progressEl.hidden = !busy;
    runLabel.textContent = busy ? label : "Run triage";
    const old = runEl.querySelector(".spinner");
    if (old) old.remove();
    if (busy) {
      const sp = document.createElement("span");
      sp.className = "spinner";
      runEl.insertBefore(sp, runLabel);
    }
  }

  async function run() {
    const scan = scanEl.value.trim();
    if (!scan) { toast("Paste a scan first, or load the example.", "err"); scanEl.focus(); return; }

    const backend = $('input[name="backend"]:checked').value;
    const apiKey = $("#api-key").value.trim();
    const modelEl = $("#ollama-model");
    const model = backend === "ollama" && modelEl ? modelEl.value : null;

    setBusy(true, backend === "ollama" ? "Running…" : "Triaging…");
    if (backend === "ollama") toast("Local model: about a minute per finding.", null);

    try {
      const res = await fetch("/api/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan, backend, api_key: apiKey || null, model }),
      });
      const data = await res.json();
      if (!data.ok) { toast(data.error || `Request failed (${res.status})`, "err"); return; }

      // The key has served its purpose; do not leave it sitting in the DOM.
      $("#api-key").value = "";

      state = data;
      grounded = true;
      // Open the findings that need a human; leave the clean ones collapsed.
      openRows = new Set(
        data.grounded.map((f, i) => (f.flags && f.flags.length ? i : -1)).filter((i) => i >= 0));

      emptyEl.hidden = true;
      reportEl.hidden = false;
      headEl.hidden = false;
      footEl.hidden = false;
      render();
      $("#results-body").scrollTop = 0;

      if (data.flaggedCount) {
        toast(`${plural(data.flaggedCount, "finding", "findings")} flagged — expanded in the report.`, "err");
      } else {
        toast("Every claim traced. Nothing flagged.", "ok");
      }
    } catch (err) {
      toast("Network error: " + err.message, "err");
    } finally {
      setBusy(false);
    }
  }

  runEl.addEventListener("click", run);
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); run(); }
  });

  // ------------------------------------------------------- the A/B switch

  function setView(next) {
    if (!state || next === grounded) return;
    grounded = next;
    render();
  }
  $("#view-raw").addEventListener("click", () => setView(false));
  $("#view-safe").addEventListener("click", () => setView(true));

  // -------------------------------------------------------------- render

  function render() {
    if (!state) return;
    const list = grounded ? state.grounded : state.ungrounded;
    const flagged = state.flaggedCount;

    $("#view-raw").setAttribute("aria-pressed", String(!grounded));
    $("#view-safe").setAttribute("aria-pressed", String(grounded));

    $("#verdict-title").textContent =
      state.counts.Critical ? "Report · critical findings"
        : state.counts.High ? "Report · high severity"
          : "Report";

    $("#verdict-sub").textContent =
      `${plural(list.length, "finding", "findings")} · ` +
      `${plural(state.duplicatesRemoved, "duplicate", "duplicates")} merged · ` +
      `${state.format} · ${state.backend}` +
      (state.target ? ` · ${state.target}` : "");

    $("#counts").innerHTML = ["Critical", "High", "Medium", "Low", "None"]
      .filter((s) => state.counts[s])
      .map((s) => `<div class="stat ${s}"><b>${state.counts[s]}</b><span>${s}</span></div>`)
      .join("");

    bannerEl.hidden = false;
    if (flagged === 0) {
      bannerEl.className = "banner clean";
      bannerEl.innerHTML = `<span class="banner-ico">✓</span><span><b>Nothing ungrounded in this run.</b> Every claim traced back to the scanner output or the CWE catalogue.</span>`;
    } else {
      bannerEl.className = "banner";
      bannerEl.innerHTML = `<span class="banner-ico">⚠</span><span>` + (grounded
        ? `<b>${plural(flagged, "finding", "findings")} contained a claim that could not be traced.</b> Removed and flagged below. Switch to "Raw output" to see what the model wrote.`
        : `<b>This is the unchecked output.</b> ${plural(flagged, "finding contains", "findings contain")} a fabricated reference, struck through in red. This is what would have reached a client.`)
        + `</span>`;
    }

    findingsEl.innerHTML = list.map((f, i) => {
      const isFlagged = grounded && f.flags && f.flags.length;
      const open = openRows.has(i);

      const flags = isFlagged
        ? `<div class="flags"><b>Needs review before sending</b><ul>${
            f.flags.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`
        : "";

      const cweChip = f.cwe_id
        ? `<span class="meta-chip cwe">${esc(f.cwe_id)} ${esc(f.cwe_name)}</span>`
        : (grounded ? `<span class="meta-chip"><span class="redacted">CWE dropped</span></span>` : "");

      const dupes = f.duplicates && f.duplicates.length
        ? `<span class="meta-chip">also seen as ${f.duplicates.map(esc).join(", ")}</span>` : "";

      return `<article class="finding ${open ? "open" : ""}">
        <div class="f-head" data-row="${i}" role="button" tabindex="0" aria-expanded="${open}">
          <span class="sev ${esc(f.severity)}">${esc(String(f.cvss_score))}</span>
          <span class="sev-word ${esc(f.severity)}">${esc(f.severity)}</span>
          <span class="f-title">${esc(f.title)}</span>
          ${isFlagged ? '<span class="f-warn" title="Contains an ungrounded claim">⚠</span>' : ""}
          <svg class="f-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>
        </div>
        <div class="f-body">
          <div class="f-meta">
            <span class="meta-chip">${esc(f.cvss_vector)}</span>
            ${cweChip}
            <span class="meta-chip">source ${esc(f.source_id)}</span>
            ${dupes}
          </div>
          <div class="f-sec"><h5>Summary</h5><p>${markClaims(f.summary)}</p></div>
          <div class="f-sec"><h5>Reproduction</h5><p>${markClaims(f.reproduction)}</p></div>
          <div class="f-sec"><h5>Remediation</h5><p>${markClaims(f.remediation)}</p></div>
          ${flags}
        </div>
      </article>`;
    }).join("");

    findingsEl.querySelectorAll(".f-head").forEach((head) => {
      const toggle = () => {
        const i = Number(head.dataset.row);
        const card = head.parentElement;
        const nowOpen = !card.classList.contains("open");
        card.classList.toggle("open", nowOpen);
        head.setAttribute("aria-expanded", String(nowOpen));
        if (nowOpen) openRows.add(i); else openRows.delete(i);
      };
      head.addEventListener("click", toggle);
      head.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
      });
    });
  }

  // ----------------------------------------------------------- downloads

  $$("[data-dl]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!state) return;
      const fmt = btn.dataset.dl;
      btn.disabled = true;
      try {
        const res = await fetch("/api/render", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ payload: state, format: fmt }),
        });
        const data = await res.json();
        if (!data.ok) { toast(data.error || "Render failed", "err"); return; }
        const ext = { markdown: "md", html: "html", json: "json" }[fmt];
        const type = { markdown: "text/markdown", html: "text/html", json: "application/json" }[fmt];
        const url = URL.createObjectURL(new Blob([data.body], { type }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `vulnerability-report.${ext}`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        toast(`Downloaded vulnerability-report.${ext}`, "ok");
      } catch (err) {
        toast("Download failed: " + err.message, "err");
      } finally {
        btn.disabled = false;
      }
    });
  });

  // -------------------------------------------------------------- dialog

  const dialog = $("#how-dialog");
  $("#how-open").addEventListener("click", () => {
    if (dialog.showModal) dialog.showModal();
  });
  $("#how-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (e) => {
    // click outside the panel closes it
    if (e.target === dialog) dialog.close();
  });

  syncBackendFields();
  inspect();
})();
