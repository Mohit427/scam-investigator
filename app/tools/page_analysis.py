"""STUB: LLM analysis of fetched page content (will use <untrusted_page> tags). Not implemented yet."""
from __future__ import annotations

from app.models import Finding, Target

TOOL = "page_analysis"
SOURCE = "Page content analysis"


async def check(target: Target) -> Finding:
    return Finding.unavailable(TOOL, SOURCE, "not implemented yet")
