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
python -m playwright install chromium   # browser for the redirect tracer
uvicorn app.main:app --port 8000
```

On Windows don't add `--reload`: it switches to an event loop that cannot start the browser
(the browser checks then report `unavailable`).

Open http://localhost:8000. `GET /health` shows which keys are configured (names only).

The app starts with any subset of keys. Without `GEMINI_API_KEY`, extraction falls back
to a regex extractor and the verdict to a rule-based summary of blocklist hits.

### Keys

| Variable | Used by | Get one at |
|---|---|---|
| `GEMINI_API_KEY` | entity extraction + judge | aistudio.google.com/apikey |
| `GEMINI_MODEL_FAST` / `_BACKUP` | extraction (default `gemini-3.6-flash`, backup `gemini-3.5-flash-lite`) | — |
| `GEMINI_MODEL_JUDGE` / `_BACKUP` | judge (default `gemini-3.6-flash`, backup `gemini-3.5-flash-lite`) | — |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing v4 | Google Cloud console |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 | virustotal.com |
| `URLSCAN_API_KEY` | urlscan.io search | urlscan.io |
| `URLHAUS_AUTH_KEY` | URLhaus | auth.abuse.ch |

RDAP, crt.sh, the OpenPhish community feed, the lookalike check and the browser tracer
need no key.

Each LLM step tries its primary model and, on failure (rate limit, timeout, block,
bad output), its backup model once. Defaults were picked by measured free-tier latency
(`gemini-3.8-flash` took 85-100+ s per call). All default models are on Gemini's free tier;
`gemini-4-argon` is a stronger judge but is paid-only. Note that on the free tier Google
may use submitted content to improve its products — enable billing before real users.

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

1. **Extract** — the fast Gemini model pulls links, phone numbers, UPI ids, the claimed brand,
   urgency cues and the requested action out of the message (wrapped in
   `<untrusted_message>` tags). Links it returns are kept only if they appear in the text.
2. **Cheap tier** (parallel, per link) — Safe Browsing, VirusTotal, URLhaus, OpenPhish, RDAP,
   crt.sh, plus a local lookalike check against a curated list of official brand domains.
3. **Shorteners** (bit.ly, tinyurl…) are opened in an isolated headless browser to find the
   real destination, which is then investigated as a new link.
4. **Escalate** if signals conflict, the domain is < 30 days old, a lookalike/suspicious signal
   appears, or nothing gave a clear signal — browser trace (redirects, password/OTP/card fields,
   APK downloads), Gemini page analysis of the landing page (in `<untrusted_page>` tags), and
   urlscan.io (existing scans, else a new unlisted scan). Redirects to another site are followed.
5. **Budget** — at most 12 external calls per case.
6. **Judge** — the Gemini judge model sees only the entities and the findings, and must
   cite finding ids. Reasons citing unknown ids are dropped; no-link cases are capped at 0.6
   confidence; if every live check failed the verdict is `cannot_determine`.

## Architecture

![Scam Investigator architecture](docs/architecture.png)

<details>
<summary>Mermaid source (edit this, then re-render docs/architecture.png)</summary>

```mermaid
flowchart TD
    U["Citizen pastes message"] -->|"POST /api/investigate"| RL["Rate limit"]
    RL --> X["Extraction: Gemini, regex fallback"]
    X -->|"links"| N["Normalize URLs"]
    X -->|"no links"| J
    N --> S{"Shortener?"}
    S -->|"yes"| B1["Browser unroll + URL reputation"]
    B1 -->|"destination"| N
    S -->|"no"| C["Cheap tier: Safe Browsing, VirusTotal, URLhaus,<br/>OpenPhish, RDAP, crt.sh, lookalike"]
    C --> E{"Escalate?"}
    E -->|"yes"| D["Expensive tier: browser trace,<br/>page analysis, urlscan"]
    D -->|"cross-site redirect"| N
    E -->|"no"| J
    D --> J["Judge: Gemini sees only entities + evidence"]
    J --> V["Guardrails: drop uncited reasons,<br/>confidence caps"]
    V -->|"SSE stream"| UI["Passbook UI: ledger entries + struck verdict stamp"]
```

</details>


## Interface

A single static page (no build step), designed as an Indian bank passbook: each live check prints
as a ledger entry and the verdict is struck as a rubber stamp. When a case opens, the result page
takes the width so the verdict, confidence, next steps and cited reasons are on screen without
scrolling (on phones the page scrolls the result into view). The paper's moving guilloche is a
Canvas 2D port of the ReactBits "Waves" background; the typeface is Anek Latin (Ek Type, OFL),
self-hosted in `static/fonts/`. Design tokens and rules: [DESIGN.md](DESIGN.md).

## Privacy

User messages are never stored or logged. Third-party lookup services receive only URLs or
domains. The message text is sent only to the Gemini API for extraction. The browser tracer
opens suspicious links from the server (not the user's device) with downloads blocked and
private network addresses unreachable.

`/api/investigate` is rate limited per client (default 20/min and 200/hour, 6 cases at once;
set `RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_PER_HOUR`, `MAX_CONCURRENT_CASES`). The Docker image runs
uvicorn with `--proxy-headers` so limits apply per real client behind a load balancer.

## Deploy (Vercel)

Vercel runs `Dockerfile.vercel` as a container function (Chromium included), region `bom1`
(Mumbai). The project's environment needs the five API keys plus `PORT=8080`. Pushing to `main`
deploys to production. Containers scale to zero after ~5 idle minutes, so the first request after a
quiet spell has a cold start; in-memory caches and rate-limit counters reset with them.

## Deploy (Railway)

`railway.toml` builds the Dockerfile and health-checks `/health`. With the Railway CLI:

```bash
railway login
railway init            # create a project
railway up              # upload and build (respects .gitignore, so .env is not sent)
railway variables --set GEMINI_API_KEY=...   # and the other four keys
railway domain          # generate the public URL
```

## Deploy (Render)

`render.yaml` is a Render Blueprint: in the Render dashboard choose **New → Blueprint**, pick this
repository, and paste the five API keys when prompted. It builds the Dockerfile on a 2 GB
`standard` instance in Singapore with `/health` as the health check. Use a billed Gemini key for
real users (see Privacy).
