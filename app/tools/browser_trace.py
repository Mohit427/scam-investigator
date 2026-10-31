"""STUB: Playwright redirect tracer / shortener unroller. Not implemented yet."""
from __future__ import annotations

from app.models import Finding, Target

TOOL = "browser_trace"
SOURCE = "Headless browser redirect trace"


async def check(target: Target) -> Finding:
    return Finding.unavailable(TOOL, SOURCE, "not implemented yet")
