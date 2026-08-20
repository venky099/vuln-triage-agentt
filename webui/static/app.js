(() => {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const scanEl = $("#scan");
  const statusEl = $("#status");
  const resultsEl = $("#results");
  const findingsEl = $("#findings");
  const toggleEl = $("#toggle");
  const bannerEl = $("#diff-banner");

  let state = null;        // last successful /api/triage payload
  let grounded = true;     // which view is showing

  // ---------- helpers ----------

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function setStatus(msg, isError) {
    statusEl.textContent = msg || "";
    statusEl.className = "status" + (isError ? " error" : "");
  }

  // Highlight the two states a claim can be in: a fabricated identifier that
  // the model produced, or the marker left behind after it was removed.
  function markClaims(text) {
    let out = esc(text);
    out = out.replace(/\[UNVERIFIED REFERENCE REMOVED\]|\[UNSUPPORTED CLAIM REMOVED\]/g,
      (m) => `<span class="redacted">${m}</span>`);
    out = out.replace(/\bCVE-\d{4}-\d{4,7}\b/g,
      (m) => `<span class="fabricated" title="Not present in the scan data">${m}</span>`);
    return out;
  }

  // ---------- backend selection ----------

  document.querySelectorAll('input[name="backend"]').forEach((r) => {
    r.addEventListener("change", () => {
      const which = $('input[name="backend"]:checked').value;
      $("#key-row").hidden = which !== "openai";
      const ollamaRow = $("#ollama-row");
      if (ollamaRow) ollamaRow.hidden = which !== "ollama";
    });
  });

  $("#load-example").addEventListener("click", async () => {
    try {
      const res = await fetch("/api/example");
      scanEl.value = JSON.stringify(await res.json(), null, 2);
      setStatus("Example loaded — hit Triage findings.");
    } catch {
      setStatus("Could not load the example.", true);
    }
  });

  // ---------- run ----------

  $("#run").addEventListener("click", async () => {
    const scan = scanEl.value.trim();
    if (!scan) { setStatus("Paste a scan first, or load the example.", true); return; }

    const backend = $('input[name="backend"]:checked').value;
    const apiKey = $("#api-key").value.trim();
    const modelEl = $("#ollama-model");
    const model = backend === "ollama" && modelEl ? modelEl.value : null;

    $("#run").disabled = true;
    resultsEl.hidden = true;
    setStatus(backend === "mock" ? "Triaging…"
      : backend === "ollama" ? "Running locally — about a minute per finding, please wait…"
      : "Calling the model (this can take a moment)…");

    try {
      const res = await fetch("/api/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan, backend, api_key: apiKey || null, model }),
      });
      const data = await res.json();
      if (!data.ok) { setStatus(data.error || `Request failed (${res.status})`, true); return; }

      // The key has served its purpose; do not leave it sitting in the DOM.
      $("#api-key").value = "";

      state = data;
      grounded = true;
      toggleEl.setAttribute("aria-checked", "true");
      setStatus("");
      render();
      resultsEl.hidden = false;
      resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      setStatus("Network error: " + err.message, true);
    } finally {
      $("#run").disabled = false;
    }
  });

  // ---------- the toggle ----------

  toggleEl.addEventListener("click", () => {
    if (!state) return;
    grounded = !grounded;
    toggleEl.setAttribute("aria-checked", String(grounded));
    render();
  });

  // ---------- render ----------

  function render() {
    if (!state) return;
    const list = grounded ? state.grounded : state.ungrounded;
    const flagged = state.flaggedCount;

    $("#verdict-title").textContent =
      state.counts.Critical ? "Critical findings present"
        : state.counts.High ? "High severity findings present"
          : "Report";
    $("#verdict-sub").textContent =
      `${list.length} finding${list.length === 1 ? "" : "s"} · ` +
      `${state.duplicatesRemoved} duplicate${state.duplicatesRemoved === 1 ? "" : "s"} merged · ` +
      `${state.format} format · ${state.backend} model` +
      (state.target ? ` · ${state.target}` : "");

    $("#counts").innerHTML = ["Critical", "High", "Medium", "Low"]
      .filter((s) => state.counts[s])
      .map((s) => `<span class="pill ${s}">${state.counts[s]} ${s}</span>`).join("");

    $("#toggle-explain").textContent = grounded
      ? "on — every claim traced to the scan data"
      : "off — raw model output, nothing checked";

    if (flagged === 0) {
      bannerEl.hidden = false;
      bannerEl.className = "diff-banner clean";
      bannerEl.innerHTML = "<b>Nothing ungrounded in this run.</b> Every claim traced back to the scanner output or the CWE catalogue.";
    } else {
      bannerEl.hidden = false;
      bannerEl.className = "diff-banner";
      bannerEl.innerHTML = grounded
        ? `<b>${flagged} finding${flagged === 1 ? "" : "s"} contained a claim that could not be traced.</b> Removed and flagged below. Flip the switch to see what the model originally wrote.`
        : `<b>This is the unchecked output.</b> ${flagged} finding${flagged === 1 ? " contains" : "s contain"} a fabricated reference, shown in red. This is what would have reached a client.`;
    }

    findingsEl.innerHTML = list.map((f, i) => {
      const flags = (grounded && f.flags && f.flags.length)
        ? `<div class="flags"><b>Needs review before sending</b><ul>${
            f.flags.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`
        : "";
      const cwe = f.cwe_id
        ? ` · <code>${esc(f.cwe_id)}</code> ${esc(f.cwe_name)}`
        : (grounded ? ` · <span class="redacted">CWE dropped</span>` : "");
      const dupes = f.duplicates && f.duplicates.length
        ? ` · also seen as ${f.duplicates.map(esc).join(", ")}` : "";

      return `<article class="finding ${grounded && f.flags && f.flags.length ? "flagged" : ""}">
        <div class="f-head">
          <span class="sev ${esc(f.severity)}">${esc(f.severity)} ${f.cvss_score}</span>
          <span class="f-title">${i + 1}. ${esc(f.title)}</span>
        </div>
        <p class="f-meta"><code>${esc(f.cvss_vector)}</code>${cwe} · source ${esc(f.source_id)}${dupes}</p>
        <div class="f-body">
          <p>${markClaims(f.summary)}</p>
          <h5>Reproduction</h5><p>${markClaims(f.reproduction)}</p>
          <h5>Remediation</h5><p>${markClaims(f.remediation)}</p>
        </div>
        ${flags}
      </article>`;
    }).join("");
  }

  // ---------- downloads ----------

  document.querySelectorAll("[data-dl]").forEach((btn) => {
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
        if (!data.ok) { setStatus(data.error || "Render failed", true); return; }
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
      } catch (err) {
        setStatus("Download failed: " + err.message, true);
      } finally {
        btn.disabled = false;
      }
    });
  });
})();
