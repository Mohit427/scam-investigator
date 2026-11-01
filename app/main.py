"""FastAPI entrypoint: static UI, SSE investigation endpoint, health check."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import net
from app.config import ROOT, key_presence, log_key_presence, settings
from app.orchestrator import investigate
from app.ratelimit import RateLimiter
from app.tools import browser_trace

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC_DIR = ROOT / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    log_key_presence()
    yield
    await browser_trace.shutdown()
    await net.aclose()


app = FastAPI(title="Scam Investigator", lifespan=lifespan)
limiter = RateLimiter(limits=((60.0, settings.rate_per_minute), (3600.0, settings.rate_per_hour)),
                      max_concurrent=settings.max_concurrent_cases)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class InvestigateRequest(BaseModel):
    message: str = Field(min_length=1, max_length=5000)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "keys_present": key_presence()}


async def _sse(events: AsyncIterator[dict]) -> AsyncIterator[str]:
    limiter.active += 1
    try:
        async for event in events:
            yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"
    finally:
        limiter.active -= 1


@app.post("/api/investigate", response_model=None)
async def api_investigate(body: InvestigateRequest, request: Request) -> StreamingResponse | JSONResponse:
    # Behind a reverse proxy request.client is the proxy; run uvicorn with --proxy-headers there.
    allowed, reason, retry_after = limiter.check(request.client.host if request.client else "unknown")
    if not allowed:
        return JSONResponse({"detail": reason}, status_code=429, headers={"Retry-After": str(retry_after)})
    # The message lives only in memory for the duration of this request; it is never logged or stored.
    return StreamingResponse(
        _sse(investigate(body.message)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
