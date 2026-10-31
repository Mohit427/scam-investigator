"""FastAPI entrypoint: static UI, SSE investigation endpoint, health check."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import net
from app.config import ROOT, key_presence, log_key_presence
from app.orchestrator import investigate

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC_DIR = ROOT / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    log_key_presence()
    yield
    await net.aclose()


app = FastAPI(title="Scam Investigator", lifespan=lifespan)
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
    async for event in events:
        yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"


@app.post("/api/investigate")
async def api_investigate(body: InvestigateRequest) -> StreamingResponse:
    # The message lives only in memory for the duration of this request; it is never logged or stored.
    return StreamingResponse(
        _sse(investigate(body.message)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
