// Scam Investigator UI: POST the message, read the SSE stream with fetch, print each event into the
// passbook as it arrives. Nothing here invents results; every row comes from a server event.
(() => {
  const $ = (sel) => document.querySelector(sel);
  const form = $("#form");
  const textarea = $("#message");
  const button = $("#submit");
  const statusEl = $("#status");
  const ledger = $("#ledger");
  const ledgerScroll = $("#ledger-scroll");
  const ledgerEmpty = $("#ledger-empty");
  const verdictEl = $("#verdict");
  const stampsEl = $("#stamps");
  const resultEl = $("#result");
  const entryEl = $("#case-entry");
  const summaryEl = $("#case-summary");
  const spreadEl = $("#case");
  const headEl = $("#result-head");
  const leftPage = $(".page-left");
  const countEl = $("#trail-count");

  const LABELS = {
    likely_scam: "Likely a scam",
    likely_legitimate: "Likely genuine",
    cannot_determine: "Can't say for sure",
  };
  const SIGNAL_WORDS = {
    malicious: "Malicious", suspicious: "Suspicious", benign: "Clean", neutral: "No signal",
    unavailable: "Unavailable", error: "Error", timeout: "Timed out",
  };
  const STAGE_OF_TOOL = {
    message_analysis: "read",
    safe_browsing: "reputation", virustotal: "reputation", urlhaus: "reputation", openphish: "reputation",
    rdap: "reputation", crtsh: "reputation", lookalike: "reputation",
    browser_trace: "visit", page_analysis: "visit", urlscan: "visit",
  };
  const STAGES = ["read", "reputation", "visit", "judge"];

  // Example INPUTS only (what people receive). They fill the box; nothing is submitted for you.
  const EXAMPLES = {
    kyc: "Dear Customer, your SBI YONO account will be BLOCKED today due to incomplete KYC. Update your PAN immediately to avoid suspension. Call our KYC desk now.",
    power: "Priya upbhokta, aapka bijli connection aaj raat 9:30 baje kaat diya jayega kyunki pichhle mahine ka bill update nahi hua hai. Turant bijli officer se sampark karein.",
    bank: "Is this really my bank's website? https://www.hdfcbank.com",
  };

  const findings = new Map();
  const mobile = window.matchMedia("(max-width: 900px)");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function setStatus(text, kind) {
    statusEl.textContent = text || "";
    statusEl.className = "status" + (kind ? " " + kind : "");
  }

  function clock(iso) {
    const d = iso ? new Date(iso) : new Date();
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  }

  function setStage(stage) {
    const idx = STAGES.indexOf(stage);
    if (idx < 0) return;
    document.querySelectorAll("#stations li").forEach((li) => {
      const current = STAGES.indexOf(li.dataset.stage);
      if (current < idx) { li.classList.add("done"); li.classList.remove("active"); }
      else if (current === idx && !li.classList.contains("done")) li.classList.add("active");
    });
  }
  function finishStages() {
    document.querySelectorAll("#stations li").forEach((li) => {
      if (li.classList.contains("active") || li.dataset.stage === "judge") li.classList.add("done");
      li.classList.remove("active");
    });
  }

  function keepLatestVisible() {
    if (mobile.matches) return;
    ledgerScroll.scrollTo({ top: ledgerScroll.scrollHeight, behavior: reduceMotion.matches ? "auto" : "smooth" });
  }

  function addNote(message) {
    if (/^Weighing the evidence/.test(message)) setStage("judge");
    else if (/^Reading the message/.test(message)) setStage("read");
    else if (/^Checking .* against live sources/.test(message)) setStage("reputation");
    else if (/isolated|redirects to a different site|short link leads/.test(message)) setStage("visit");
    const row = $("#tpl-note").content.firstElementChild.cloneNode(true);
    row.querySelector(".note-time").textContent = clock();
    row.querySelector(".note-text").textContent = message;
    ledger.appendChild(row);
    ledgerEmpty.hidden = true;
    keepLatestVisible();
  }

  function addFinding(f) {
    findings.set(f.id, f);
    setStage(STAGE_OF_TOOL[f.tool] || "reputation");
    const row = $("#tpl-row").content.firstElementChild.cloneNode(true);
    row.id = "finding-" + f.id;
    row.querySelector(".src").textContent = f.source;
    row.querySelector(".ref").textContent = `Entry ${f.id} · ${clock(f.timestamp_utc)}`;
    row.querySelector(".part").textContent = f.summary;
    const key = f.status === "ok" ? f.signal : f.status;
    const sig = row.querySelector(".sig");
    sig.textContent = SIGNAL_WORDS[key] || key;
    sig.classList.add(key);
    row.classList.add("is-" + key);
    row.querySelector("pre").textContent = JSON.stringify(
      { tool: f.tool, status: f.status, timestamp_utc: f.timestamp_utc, raw: f.raw }, null, 2);
    ledger.appendChild(row);
    ledgerEmpty.hidden = true;
    const n = findings.size;
    setStatus(`Investigating · ${n} ${n === 1 ? "entry" : "entries"} printed so far`, "busy");
    updateCount();
    keepLatestVisible();
  }

  // A one-line tally of the real findings, so the trail reads at a glance.
  function updateCount() {
    const all = [...findings.values()];
    const has = (fn) => all.filter(fn).length;
    const parts = [`${all.length} ${all.length === 1 ? "entry" : "entries"}`];
    const flagged = has((f) => f.status === "ok" && (f.signal === "malicious" || f.signal === "suspicious"));
    const clean = has((f) => f.status === "ok" && f.signal === "benign");
    const failed = has((f) => f.status !== "ok");
    if (flagged) parts.push(`${flagged} flagged`);
    if (clean) parts.push(`${clean} clean`);
    if (failed) parts.push(`${failed} could not answer`);
    countEl.textContent = parts.join(" · ");
  }

  function showEntry(id, btn) {
    const row = document.getElementById("finding-" + id);
    if (!row) return;
    document.querySelectorAll(".cite[aria-pressed='true']").forEach((b) => b.setAttribute("aria-pressed", "false"));
    btn.setAttribute("aria-pressed", "true");
    row.querySelector("details")?.setAttribute("open", "");
    row.scrollIntoView({ block: "nearest", behavior: reduceMotion.matches ? "auto" : "smooth" });
    row.classList.remove("flash");
    void row.offsetWidth;
    row.classList.add("flash");
  }

  function citeButton(id) {
    const btn = el("button", "cite", id);
    btn.type = "button";
    btn.setAttribute("aria-pressed", "false");
    btn.setAttribute("aria-label", `Show ledger entry ${id}`);
    btn.addEventListener("click", () => showEntry(id, btn));
    return btn;
  }

  // ReactBits CountUp, reduced to what the confidence figure needs.
  function countUp(node, to) {
    if (reduceMotion.matches) { node.textContent = to + "%"; return; }
    const start = performance.now(), dur = 900;
    const tick = (now) => {
      const t = Math.min(1, (now - start) / dur);
      node.textContent = Math.round(to * (1 - Math.pow(1 - t, 4))) + "%";
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  // The trail ends on the outcome, not on the step that was still running.
  function closeTrail(v) {
    const text = `Evidence weighed. Verdict: ${LABELS[v.verdict] || v.verdict}, ${Math.round((v.confidence || 0) * 100)}% sure.`;
    let row = [...ledger.querySelectorAll(".entry-note")].reverse()
      .find((r) => r.querySelector(".note-text").textContent.startsWith("Weighing the evidence"));
    if (!row) {
      row = $("#tpl-note").content.firstElementChild.cloneNode(true);
      ledger.appendChild(row);
      ledgerEmpty.hidden = true;
    }
    row.classList.add("entry-close");
    row.querySelector(".note-time").textContent = clock();
    row.querySelector(".note-text").textContent = text;
  }

  function strike(verdict) {
    stampsEl.classList.add("decided");
    stampsEl.querySelectorAll(".stamp").forEach((s) => {
      const on = s.dataset.verdict === verdict;
      s.classList.toggle("struck", on);
      if (on) s.setAttribute("aria-current", "true"); else s.removeAttribute("aria-current");
    });
  }

  function renderVerdict(v) {
    finishStages();
    closeTrail(v);
    strike(v.verdict);
    verdictEl.innerHTML = "";
    verdictEl.className = "verdict " + v.verdict;

    const head = el("div", "v-head");
    const title = el("h3", "v-title", LABELS[v.verdict] || v.verdict);
    title.id = "verdict-title";
    head.appendChild(title);
    const pct = Math.round((v.confidence || 0) * 100);
    const sure = el("p", "v-sure");
    const num = el("strong", "", "0%");
    sure.append(num, document.createTextNode("sure"));
    head.appendChild(sure);
    verdictEl.appendChild(head);

    const meter = el("div", "meter");
    meter.setAttribute("role", "meter");
    meter.setAttribute("aria-valuemin", "0");
    meter.setAttribute("aria-valuemax", "100");
    meter.setAttribute("aria-valuenow", String(pct));
    meter.setAttribute("aria-label", "How sure the verdict is");
    const lit = Math.round(pct / 5);
    for (let i = 0; i < 20; i++) meter.appendChild(el("i", i < lit ? "on" : ""));
    verdictEl.appendChild(meter);

    const jump = el("a", "v-jump", `See the evidence trail (${findings.size} ${findings.size === 1 ? "entry" : "entries"})`);
    jump.href = "#trail";
    verdictEl.appendChild(jump);

    const cols = el("div", "v-cols");
    if (v.action_guidance && v.action_guidance.length) {
      const box = el("div");
      box.appendChild(el("h3", "", "What to do"));
      const ul = el("ul");
      for (const g of v.action_guidance) ul.appendChild(el("li", "", g));
      box.appendChild(ul);
      cols.appendChild(box);
    }
    if (v.reasons && v.reasons.length) {
      const box = el("div");
      box.appendChild(el("h3", "", "Why, with evidence"));
      const ul = el("ul");
      for (const r of v.reasons) {
        const li = el("li");
        li.appendChild(el("span", "", r.text));
        for (const id of r.finding_ids) li.appendChild(citeButton(id));
        ul.appendChild(li);
      }
      box.appendChild(ul);
      cols.appendChild(box);
    }
    verdictEl.appendChild(cols);

    if (!v.live_evidence) {
      verdictEl.appendChild(el("p", "v-note",
        "No live evidence was available for this check, so treat the result as an estimate from the wording alone."));
    }
    for (const n of v.notes || []) verdictEl.appendChild(el("p", "v-note", n));

    verdictEl.hidden = false;
    verdictEl.scrollTop = 0;
    if (!mobile.matches) ledgerScroll.scrollTop = 0; // read the trail from its first entry
    countUp(num, pct);
    const total = findings.size;
    setStatus(`Investigation closed · ${total} ${total === 1 ? "entry" : "entries"} in the ledger`);
    // The answer comes first: bring the stamp and verdict into view wherever the page is scrolled.
    revealResult();
  }

  function revealResult() {
    const top = headEl.getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.35) {
      headEl.scrollIntoView({ block: "start", behavior: reduceMotion.matches ? "auto" : "smooth" });
    }
  }

  function handle(event) {
    switch (event.type) {
      case "step": addNote(event.message); break;
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
      let detail = "";
      try { detail = (await res.json()).detail; } catch { /* not JSON */ }
      if (res.status === 422) throw new Error("Please paste a message (up to 5000 characters).");
      if (res.status === 429 && typeof detail === "string") throw new Error(detail);
      throw new Error(`The server returned an error (${res.status}). Please try again.`);
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

  function resetCase() {
    ledger.innerHTML = "";
    ledgerEmpty.hidden = false;
    $("#ledger-empty-text").textContent = "Waiting for the first source to answer…";
    findings.clear();
    countEl.textContent = "";
    verdictEl.hidden = true;
    verdictEl.innerHTML = "";
    stampsEl.classList.remove("decided");
    stampsEl.querySelectorAll(".stamp").forEach((s) => { s.classList.remove("struck"); s.removeAttribute("aria-current"); });
    document.querySelectorAll("#stations li").forEach((li) => li.classList.remove("done", "active"));
  }

  function setBusy(busy) {
    button.disabled = busy;
    button.setAttribute("aria-busy", busy ? "true" : "false");
    button.querySelector(".btn-text").textContent = busy ? "Investigating" : "Investigate";
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const message = textarea.value.trim();
    if (!message) {
      setStatus("Paste the message or link first, then press Investigate.", "error");
      textarea.focus();
      return;
    }
    resetCase();
    setBusy(true);
    setStatus("Opening the case…", "busy");
    $("#case-text").textContent = message;
    entryEl.hidden = true;
    summaryEl.hidden = false;
    spreadEl.classList.add("open");
    leftPage.appendChild(headEl); // verdict on the left page, the trail gets the whole right page
    // On phones the result page sits below; bring it up so progress and the verdict are what you see.
    if (mobile.matches) headEl.scrollIntoView({ block: "start", behavior: reduceMotion.matches ? "auto" : "smooth" });
    try {
      const gotVerdict = await run(message);
      if (!gotVerdict) setStatus("The connection closed before a verdict arrived. Please try again.", "error");
    } catch (err) {
      setStatus(err.message || "Network error. Check your connection and try again.", "error");
    } finally {
      setBusy(false);
      if (!findings.size && ledger.children.length === 0) $("#ledger-empty-text").textContent = "No entries were printed.";
    }
  });

  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) form.requestSubmit();
  });

  $("#new-case").addEventListener("click", () => {
    summaryEl.hidden = true;
    entryEl.hidden = false;
    spreadEl.classList.remove("open");
    resultEl.insertBefore(headEl, resultEl.querySelector(".trail-head"));
    textarea.focus();
    textarea.select();
  });

  document.querySelectorAll(".try").forEach((b) => b.addEventListener("click", () => {
    textarea.value = EXAMPLES[b.dataset.example] || "";
    textarea.focus();
  }));
})();
