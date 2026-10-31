// Scam Investigator UI: POST the message, read the SSE stream with fetch, render as it arrives.
(() => {
  const $ = (sel) => document.querySelector(sel);
  const form = $("#form");
  const textarea = $("#message");
  const button = $("#submit");
  const statusEl = $("#status");
  const timelineSection = $("#timeline-section");
  const timeline = $("#timeline");
  const verdictEl = $("#verdict");

  const LABELS = {
    likely_scam: "Likely a scam",
    likely_legitimate: "Likely legitimate",
    cannot_determine: "Can't say for sure",
  };
  const findings = new Map();

  function setStatus(text, kind) {
    statusEl.hidden = !text;
    statusEl.textContent = text || "";
    statusEl.className = "status" + (kind ? " " + kind : "");
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function addStep(message) {
    const node = $("#tpl-step").content.firstElementChild.cloneNode(true);
    node.querySelector(".tl-text").textContent = message;
    timeline.appendChild(node);
  }

  function addFinding(f) {
    findings.set(f.id, f);
    const node = $("#tpl-finding").content.firstElementChild.cloneNode(true);
    node.id = "finding-" + f.id;
    node.querySelector(".fid").textContent = f.id;
    node.querySelector(".source").textContent = f.source;
    const badge = node.querySelector(".badge");
    const label = f.status === "ok" ? f.signal : f.status;
    badge.textContent = label;
    badge.classList.add(f.status === "ok" ? f.signal : "neutral");
    node.querySelector(".tl-dot").classList.add(f.status === "ok" ? f.signal : "neutral");
    node.querySelector(".tl-text").textContent = f.summary;
    node.querySelector("pre").textContent = JSON.stringify(
      { tool: f.tool, status: f.status, timestamp_utc: f.timestamp_utc, raw: f.raw }, null, 2);
    timeline.appendChild(node);
  }

  function citeButton(id, holder) {
    const btn = el("button", "cite", id);
    btn.type = "button";
    btn.setAttribute("aria-expanded", "false");
    btn.addEventListener("click", () => {
      const open = holder.querySelector(`[data-fid="${id}"]`);
      if (open) {
        open.remove();
        btn.setAttribute("aria-expanded", "false");
        return;
      }
      const f = findings.get(id);
      if (!f) return;
      const box = el("div", "cite-raw");
      box.dataset.fid = id;
      box.appendChild(el("strong", "", `${f.id} · ${f.source} · ${f.timestamp_utc}`));
      box.appendChild(el("div", "", f.summary));
      box.appendChild(el("pre", "", JSON.stringify(f.raw, null, 2)));
      holder.appendChild(box);
      btn.setAttribute("aria-expanded", "true");
      const tl = document.getElementById("finding-" + id);
      if (tl) {
        tl.classList.add("flash");
        setTimeout(() => tl.classList.remove("flash"), 1500);
      }
    });
    return btn;
  }

  function renderVerdict(v) {
    verdictEl.innerHTML = "";
    verdictEl.className = "card verdict " + v.verdict;
    verdictEl.appendChild(el("p", "v-label", LABELS[v.verdict] || v.verdict));

    const pct = Math.round((v.confidence || 0) * 100);
    verdictEl.appendChild(el("p", "conf", `Confidence: ${pct}%`));
    const bar = el("div", "conf-bar");
    bar.setAttribute("role", "meter");
    bar.setAttribute("aria-valuemin", "0");
    bar.setAttribute("aria-valuemax", "100");
    bar.setAttribute("aria-valuenow", String(pct));
    bar.setAttribute("aria-label", "Confidence");
    const fill = el("div", "conf-fill");
    fill.style.width = pct + "%";
    bar.appendChild(fill);
    verdictEl.appendChild(bar);

    if (!v.live_evidence) {
      verdictEl.appendChild(el("p", "notes",
        "No live evidence was available for this check — treat the result as a pattern-based estimate."));
    }

    if (v.reasons && v.reasons.length) {
      verdictEl.appendChild(el("h3", "", "Why"));
      const ul = el("ul");
      for (const r of v.reasons) {
        const li = el("li");
        li.appendChild(el("span", "", r.text));
        for (const id of r.finding_ids) li.appendChild(citeButton(id, li));
        ul.appendChild(li);
      }
      verdictEl.appendChild(ul);
    }

    if (v.action_guidance && v.action_guidance.length) {
      verdictEl.appendChild(el("h3", "", "What to do"));
      const ul = el("ul");
      for (const g of v.action_guidance) ul.appendChild(el("li", "", g));
      verdictEl.appendChild(ul);
    }

    if (v.notes && v.notes.length) {
      const notes = el("div", "notes");
      for (const n of v.notes) notes.appendChild(el("p", "", n));
      verdictEl.appendChild(notes);
    }

    verdictEl.hidden = false;
  }

  function handle(event) {
    switch (event.type) {
      case "step": addStep(event.message); break;
      case "finding": addFinding(event.finding); break;
      case "error": setStatus(event.message, "error"); break;
      case "verdict": renderVerdict(event.verdict); break;
    }
  }

  async function run(message) {
    const res = await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({ message }),
    });
    if (!res.ok || !res.body) {
      throw new Error(res.status === 422 ? "Please paste a message (up to 5000 characters)." :
        `The server returned an error (${res.status}).`);
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let gotVerdict = false;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buffer.indexOf("\n\n")) !== -1) {
        const chunk = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const data = chunk.split("\n").filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trimStart()).join("\n");
        if (!data) continue;
        let event;
        try { event = JSON.parse(data); } catch { continue; }
        if (event.type === "verdict") gotVerdict = true;
        handle(event);
      }
    }
    return gotVerdict;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = textarea.value.trim();
    if (!message) {
      setStatus("Please paste the message or link first.", "error");
      return;
    }
    timeline.innerHTML = "";
    findings.clear();
    verdictEl.hidden = true;
    timelineSection.hidden = false;
    button.disabled = true;
    setStatus("Investigating — this can take up to a minute while we query live sources.", "loading");
    try {
      const gotVerdict = await run(message);
      if (gotVerdict) { if (statusEl.classList.contains("loading")) setStatus(""); }
      else setStatus("The connection closed before a verdict arrived. Please try again.", "error");
    } catch (err) {
      setStatus(err.message || "Network error — please check your connection and try again.", "error");
    } finally {
      button.disabled = false;
    }
  });
})();
