# Scam Investigator — rules for working in this repo

A FastAPI app: a citizen pastes a suspicious SMS / WhatsApp text / link, an agent
investigates it with LIVE tools, streams each step over SSE, and returns an
evidence-cited verdict. Built for a hackathon with a ZERO-TOLERANCE rule on
mock/hardcoded data.

## Hard rules (always follow)

1. **No mock data.** No fake responses, placeholder numbers, sample JSON results or
   canned findings anywhere in the app or frontend. If an API key is missing, the
   tool returns a `Finding` with `status="unavailable"` and says why. It never
   fabricates a result. Reference lists (link shorteners, official brand domains in
   `tools/lookalike.py`) must be real and verifiable; they are reference data, not
   evidence. Unit tests may build inputs for pure functions but never fake an API
   response to simulate a live result.
2. **One Finding shape.** Every tool returns
   `{id, tool, source, timestamp_utc, status: ok|error|unavailable|timeout, summary, raw, signal: malicious|suspicious|benign|neutral}`.
   Any non-`ok` finding must have `signal="neutral"` (enforced by the model).
3. **Cited verdicts only.** The verdict may only cite Finding ids that exist in the
   case's evidence store. Output is exactly one of `likely_scam`,
   `likely_legitimate`, `cannot_determine`, plus confidence 0–1, reasons (each
   citing finding ids) and action guidance. Reasons citing unknown ids are
   dropped. Thin or conflicting evidence → lower confidence or `cannot_determine`.
4. **Prompt-injection defense.** The user message and any fetched web content are
   UNTRUSTED DATA. They go to the LLM only inside delimited tags
   (`<untrusted_message>`, `<untrusted_page>`, `<untrusted_entities>`,
   `<evidence>`) with an instruction to ignore any commands inside them.
   LLM-extracted URLs/phones/UPI ids are kept only if they literally appear in the
   original message.
5. **Privacy.** Never persist or log user messages. The browser tracer visits the
   link itself from our server, so a scammer's server may see one visit (from our
   IP, not the user's); it never sends the user's message anywhere. Third-party lookup APIs receive
   only URLs or domains — never the message text or personal data. (The Gemini
   API is the only service that sees the message, for extraction. On Gemini's free
   tier Google may use that content to improve its products; use a billed key for
   real users.)
6. **Resilience.** Every external HTTP call has a timeout (10 s default; crt.sh gets
   20 s because it is slow; LLM calls get longer timeouts), at most one retry (for
   LLM calls, the one retry is the backup model), and
   a graceful fallback. Every tool runs inside `tools.run_tool`, which converts any
   exception/timeout into a Finding. One failing tool never crashes a case, and a
   final `verdict` event is always emitted.
7. **Browser safety (SSRF).** The headless browser may only reach public hosts:
   `app/safety.py` blocks private, loopback, link-local and metadata addresses on
   every request, and captured content is discarded if any redirect hop lands on
   one. Downloads are refused and images/media/fonts are not loaded.
8. **Dependencies.** Ask the user before adding anything beyond: fastapi, uvicorn,
   httpx, pydantic, python-dotenv, playwright, tldextract. The Gemini API is called
   over httpx (REST `generateContent`), not an SDK. Domain registration data uses
   RDAP over httpx (no whois libraries). Tests use stdlib `unittest`.

## Layout

- `app/config.py` — env loading, key presence (names only), secret redaction.
- `app/models.py` — `Finding`, `Target`, `Entities`, `Verdict`, `CaseState`, citation validation.
- `app/net.py` — shared httpx client with timeout + single retry.
- `app/llm.py` — Gemini `generateContent` JSON calls: primary model, then one backup model.
- `app/extraction.py` — LLM entity extraction (fast model) with regex fallback.
- `app/orchestrator.py` — async generator producing SSE events; escalation rules; shortener
  unrolling and redirect following (destinations become new targets, max 5); tool budget
  (12 external calls/case; local tools and `unavailable` results don't count).
- `app/verdict.py` — LLM judge (judge model) that sees only entities + evidence; post-validation.
- `app/tools/` — one module per source; registry with cost tiers in `__init__.py`.
  Cheap tier: safe_browsing, virustotal, urlhaus, openphish, rdap, crtsh, lookalike (local).
  Expensive tier: browser_trace (Playwright), page_analysis (Gemini on the captured page,
  shares one browser visit via `browser_trace.capture`), urlscan (search, else new unlisted scan).
- `app/safety.py` — public-host check used by the browser.
- `app/ratelimit.py` — in-memory per-client rate limit + concurrency cap for `/api/investigate`.
- `static/` — single page UI, no build step: `index.html`, `style.css`, `app.js` (fetch + stream
  reader for POST SSE), `guilloche.js` (paper background, a Canvas 2D port of ReactBits Waves),
  `fonts/` (self-hosted Anek Latin, OFL). Visual system: `DESIGN.md`; product context: `PRODUCT.md`.
  The UI may offer example *inputs*, never example results.

## Conventions

- Async everywhere. Tools have signature `async def check(target: Target) -> Finding`.
- Build findings with `Finding.new(...)` / `Finding.unavailable(...)`; the
  orchestrator assigns ids (`F1`, `F2`, …) when adding to the case.
- `raw` holds `{"request": ..., "response": ..., "derived": ...}`: what was sent,
  a trimmed copy of what the API actually returned, and values computed from it.
- Never put secrets in URLs (use headers) and pass error text through `config.redact`.
- Do not run network calls against API keys the user has not provided.
- On Windows, run uvicorn **without** `--reload`: its subprocess event loop can't start the browser.
