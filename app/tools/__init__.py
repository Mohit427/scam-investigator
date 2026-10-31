"""Tool registry: name -> async check function + cost tier.

run_tool() is the only way tools should be invoked: it enforces an overall
deadline and turns any exception into a Finding, so one tool never crashes a case.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Literal

import httpx

from app.config import redact
from app.models import Finding, Target
from app.tools import (
    browser_trace, crtsh, lookalike, openphish, page_analysis, rdap, safe_browsing, urlhaus, urlscan, virustotal,
)

log = logging.getLogger("scam_investigator.tools")

Tier = Literal["cheap", "expensive"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    source: str
    fn: Callable[[Target], Awaitable[Finding]]
    tier: Tier
    deadline: float  # overall seconds for the whole tool, including retries/polling


REGISTRY: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec("safe_browsing", safe_browsing.SOURCE, safe_browsing.check, "cheap", 25),
        ToolSpec("virustotal", virustotal.SOURCE, virustotal.check, "cheap", 40),
        ToolSpec("urlhaus", urlhaus.SOURCE, urlhaus.check, "cheap", 25),
        ToolSpec("openphish", openphish.SOURCE, openphish.check, "cheap", 25),
        ToolSpec("rdap", rdap.SOURCE, rdap.check, "cheap", 25),
        ToolSpec("crtsh", crtsh.SOURCE, crtsh.check, "cheap", 45),
        ToolSpec("urlscan", urlscan.SOURCE, urlscan.check, "expensive", 25),
        ToolSpec("lookalike", lookalike.SOURCE, lookalike.check, "expensive", 10),
        ToolSpec("browser_trace", browser_trace.SOURCE, browser_trace.check, "expensive", 10),
        ToolSpec("page_analysis", page_analysis.SOURCE, page_analysis.check, "expensive", 10),
    )
}

# Order = priority when the per-case tool budget can't cover the whole tier.
CHEAP_TOOLS = [n for n, s in REGISTRY.items() if s.tier == "cheap"]
EXPENSIVE_TOOLS = [n for n, s in REGISTRY.items() if s.tier == "expensive"]


async def run_tool(name: str, target: Target) -> Finding:
    spec = REGISTRY[name]
    try:
        finding = await asyncio.wait_for(spec.fn(target), timeout=spec.deadline)
    except (asyncio.TimeoutError, httpx.TimeoutException):
        return Finding.new(name, spec.source, "timeout",
                           f"{spec.source} did not respond in time; skipped.", {"request": {"url": target.url}})
    except Exception as exc:  # noqa: BLE001 - any failure becomes evidence of failure, never a crash
        log.warning("tool %s failed: %s", name, type(exc).__name__)
        message = redact(str(exc))[:300]
        return Finding.new(name, spec.source, "error",
                           f"{spec.source} lookup failed ({type(exc).__name__}).",
                           {"request": {"url": target.url}, "error": message})
    return finding
