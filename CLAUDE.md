# Scam Investigator — rules for working in this repo

A FastAPI app: a citizen pastes a suspicious SMS / WhatsApp text / link, an agent
investigates it with LIVE tools, streams each step over SSE, and returns an
evidence-cited verdict. Built for a hackathon with a ZERO-TOLERANCE rule on
mock/hardcoded data.

## Hard rules (always follow)

1. **No mock data.** No fake responses, placeholder numbers, sample JSON results or
   canned findings anywhere — not in tools, not in the frontend, not in tests.
   If an API key is missing, the tool returns a `Finding` with
   `status="unavailable"` and says why. It never fabricates a result.
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
5. **Privacy.** Never persist or log user messages. Third-party lookup APIs receive
   only URLs or domains — never the message text or personal data. (The Anthropic
   API is the only service that sees the message, for extraction.)
6. **Resilience.** Every external HTTP call has a timeout (10 s default; crt.sh gets
   20 s because it is slow; LLM calls get longer timeouts), at most one retry, and
   a graceful fallback. Every tool runs inside `tools.run_tool`, which converts any
   exception/timeout into a Finding. One failing tool never crashes a case, and a
   final `verdict` event is always emitted.
7. **Dependencies.** Ask the user before adding anything beyond: fastapi, uvicorn,
   httpx, pydantic, python-dotenv, playwright, anthropic, tldextract. Domain
   registration data uses RDAP over httpx (no whois libraries). Tests use stdlib
   `unittest`.

## Layout

- `app/config.py` — env loading, key presence (names only), secret redaction.
- `app/models.py` — `Finding`, `Target`, `Entities`, `Verdict`, `CaseState`, citation validation.
- `app/net.py` — shared httpx client with timeout + single retry.
- `app/extraction.py` — LLM entity extraction (fast model) with regex fallback.
- `app/orchestrator.py` — async generator producing SSE events; escalation rules; tool budget (12/case).
- `app/verdict.py` — LLM judge (judge model) that sees only entities + evidence; post-validation.
- `app/tools/` — one module per live source; registry with cost tiers in `__init__.py`.
  `lookalike`, `browser_trace`, `page_analysis` are stubs returning `unavailable`.
- `static/` — single page UI (vanilla JS, fetch + stream reader for POST SSE).

## Conventions

- Async everywhere. Tools have signature `async def check(target: Target) -> Finding`.
- Build findings with `Finding.new(...)` / `Finding.unavailable(...)`; the
  orchestrator assigns ids (`F1`, `F2`, …) when adding to the case.
- `raw` holds `{"request": ..., "response": ..., "derived": ...}`: what was sent,
  a trimmed copy of what the API actually returned, and values computed from it.
- Never put secrets in URLs (use headers) and pass error text through `config.redact`.
- Do not run network calls against API keys the user has not provided.
