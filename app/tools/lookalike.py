"""STUB: brand lookalike-domain detection. Not implemented yet."""
from __future__ import annotations

from app.models import Finding, Target

TOOL = "lookalike"
SOURCE = "Lookalike domain analysis"


async def check(target: Target) -> Finding:
    return Finding.unavailable(TOOL, SOURCE, "not implemented yet")
