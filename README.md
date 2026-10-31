# Scam Investigator

Paste a suspicious SMS, WhatsApp message or link. An agent investigates it with **live**
security sources, streams every step to the page, and returns a verdict in which every
reason cites the evidence it came from.

No mock data: if a source is not configured or fails, it shows up as `unavailable`,
`error` or `timeout` — never as a made-up result.

## Setup (local)

Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # then fill in the keys you have
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000. `GET /health` shows which keys are configured (names only).

The app starts with any subset of keys. Without `ANTHROPIC_API_KEY`, extraction falls back
to a regex extractor and the verdict to a rule-based summary of blocklist hits.

### Keys

| Variable | Used by | Get one at |
|---|---|---|
| `ANTHROPIC_API_KEY` | entity extraction + judge | console.anthropic.com |
| `ANTHROPIC_MODEL_FAST` | extraction model (default `claude-haiku-5-5`) | — |
| `ANTHROPIC_MODEL_JUDGE` | judge model (default `claude-sonnet-5-5`) | — |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing v4 | Google Cloud console |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 | virustotal.com |
| `URLSCAN_API_KEY` | urlscan.io search | urlscan.io |
| `URLHAUS_AUTH_KEY` | URLhaus | auth.abuse.ch |

RDAP, crt.sh and the OpenPhish community feed need no key.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Docker

```bash
docker build -t scam-investigator .
docker run --rm -p 8000:8000 --env-file .env scam-investigator
```

The image includes Playwright + Chromium for the upcoming browser tracer. `$PORT` is honoured.

## How it works

1. **Extract** — the fast Claude model pulls links, phone numbers, UPI ids, the claimed brand,
   urgency cues and the requested action out of the message (wrapped in
   `<untrusted_message>` tags). Links it returns are kept only if they appear in the text.
2. **Cheap tier** (parallel, per link) — Safe Browsing, VirusTotal, URLhaus, OpenPhish, RDAP, crt.sh.
3. **Escalate** if signals conflict, the domain is < 30 days old, or nothing gave a clear
   signal — urlscan.io search, plus stubs for lookalike, browser trace and page analysis.
4. **Budget** — at most 12 tool calls per case.
5. **Judge** — the stronger Claude model sees only the entities and the findings, and must
   cite finding ids. Reasons citing unknown ids are dropped; no-link cases are capped at 0.6
   confidence; if every live check failed the verdict is `cannot_determine`.

## Architecture

<!-- TODO: architecture diagram -->

## Privacy

User messages are never stored or logged. Third-party lookup services receive only URLs or
domains. The message text is sent only to the Anthropic API for extraction.
