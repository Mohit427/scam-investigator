"""The investigation loop: an async generator of SSE-ready event dicts.

Events: {"type": "step", "message"}, {"type": "finding", "finding"},
        {"type": "verdict", "verdict"}, {"type": "error", "message"}.
A verdict event is always the last event.
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator

from app import tools
from app.extraction import extract_entities
from app.models import CaseState, Entities, Finding, Verdict
from app.urls import normalize_url
from app.verdict import DEFAULT_GUIDANCE, MESSAGE_TOOL, finalize, judge

log = logging.getLogger("scam_investigator.orchestrator")

MAX_URLS = 5
YOUNG_DOMAIN_DAYS = 30
HIGH_RISK_ACTION_WORDS = ("otp", "pay", "install", "money")


def step(message: str) -> dict:
    return {"type": "step", "message": message}


def finding_event(f: Finding) -> dict:
    return {"type": "finding", "finding": f.model_dump()}


def _message_finding(entities: Entities, method: str) -> Finding:
    """Evidence about the message itself, derived from the extraction call's output."""
    if method == "llm":
        source = "Claude entity extraction"
        parts = []
        if entities.claimed_brand:
            parts.append(f"claims to be from {entities.claimed_brand}")
        if entities.requested_action:
            parts.append(f"asks the reader to {entities.requested_action}")
        if entities.urgency_cues:
            parts.append(f"uses pressure cues: {'; '.join(entities.urgency_cues[:4])}")
        summary = ("Message " + ", ".join(parts) + "." if parts else "No pressure cues or requested action detected.")
        summary += f" Type: {entities.message_type_guess}; language: {entities.language_detected}."
        action = (entities.requested_action or "").lower()
        risky = any(w in action for w in HIGH_RISK_ACTION_WORDS)
        signal = "suspicious" if risky or (entities.urgency_cues and action) else "neutral"
    else:
        source = "Local regex extractor"
        summary = (f"Found {len(entities.urls)} link(s), {len(entities.phone_numbers)} phone number(s), "
                   f"{len(entities.upi_ids)} UPI id(s). Message intent not analysed (LLM unavailable).")
        signal = "neutral"
    return Finding.new(MESSAGE_TOOL, source, "ok", summary,
                       {"derived": entities.model_dump(), "method": method}, signal)


def _escalation(findings: list[Finding]) -> tuple[bool, str]:
    ok = [f for f in findings if f.status == "ok"]
    malicious = [f for f in ok if f.signal == "malicious"]
    benign = [f for f in ok if f.signal == "benign"]
    suspicious = [f for f in ok if f.signal == "suspicious"]
    age = next((f.raw.get("derived", {}).get("age_days") for f in ok if f.tool == "rdap"), None)

    if malicious and benign:
        return True, (f"Signals conflict ({len(malicious)} malicious vs {len(benign)} benign) — "
                      "running deeper checks.")
    if malicious:
        return False, (f"{len(malicious)} source(s) flag this link as malicious — confident enough, "
                       "skipping deeper checks.")
    if age is not None and age < YOUNG_DOMAIN_DAYS:
        return True, f"Domain is only {age} days old — running deeper checks."
    if benign and not suspicious:
        return False, "No red flags and some positive signals — no deeper checks needed."
    if suspicious:
        return True, "Some suspicious signals but nothing conclusive — running deeper checks."
    return True, "No source gave a clear signal — running deeper checks."


async def _run_batch(case: CaseState, names: list[str], target) -> AsyncIterator[Finding]:
    """Run tools concurrently; yield each finding the moment it completes."""
    case.tool_calls += len(names)
    tasks = [asyncio.create_task(tools.run_tool(n, target)) for n in names]
    try:
        for next_done in asyncio.as_completed(tasks):
            yield case.add_finding(await next_done)
    finally:
        for t in tasks:
            t.cancel()


def _plan(case: CaseState, tier: list[str]) -> tuple[list[str], list[str]]:
    budget = case.budget_left
    return tier[:budget], tier[budget:]


async def investigate(message: str) -> AsyncIterator[dict]:
    case = CaseState()
    try:
        async for event in _investigate(case, message):
            yield event
    except Exception as exc:  # noqa: BLE001 - last line of defence; always end with a verdict
        log.exception("investigation crashed")
        yield {"type": "error", "message": f"Investigation hit an internal error ({type(exc).__name__})."}
        fallback = Verdict(verdict="cannot_determine", confidence=0.0, action_guidance=DEFAULT_GUIDANCE,
                           notes=["The investigation stopped early because of an internal error."])
        yield {"type": "verdict", "verdict": finalize(fallback, case).model_dump()}


async def _investigate(case: CaseState, message: str) -> AsyncIterator[dict]:
    yield step("Reading the message: looking for links, phone numbers, UPI ids and what it asks you to do…")
    entities, method, note = await extract_entities(message)
    case.entities = entities
    if note:
        yield step(note)
    yield finding_event(case.add_finding(_message_finding(entities, method)))

    seen: set[str] = set()
    for raw_url in entities.urls:
        target = normalize_url(raw_url)
        if target and target.url not in seen:
            seen.add(target.url)
            case.targets.append(target)
    if len(case.targets) > MAX_URLS:
        yield step(f"Found {len(case.targets)} links; investigating the first {MAX_URLS}.")
        case.targets = case.targets[:MAX_URLS]

    if not case.targets:
        yield step("No link found in the message, so there is nothing to look up live. "
                   "Assessing the message pattern only.")
    else:
        yield step(f"Found {len(case.targets)} link(s): " + ", ".join(t.host for t in case.targets))

    for target in case.targets:
        if case.budget_left == 0:
            yield step(f"Tool budget ({case.tool_budget} calls) used up; skipping {target.host}.")
            continue
        if target.is_shortener:
            yield step(f"{target.host} is a link shortener — the real destination is hidden. Marked for "
                       "unrolling (the redirect tracer is not available yet); checking the short link itself.")

        run, skipped = _plan(case, tools.CHEAP_TOOLS)
        yield step(f"Checking {target.url} against {len(run)} live sources in parallel…")
        if skipped:
            yield step(f"Tool budget reached; skipping: {', '.join(skipped)}.")
        target_findings: list[Finding] = []
        async for f in _run_batch(case, run, target):
            target_findings.append(f)
            yield finding_event(f)

        escalate, why = _escalation(target_findings)
        if target.is_shortener and not escalate:
            escalate, why = True, ("Results above describe the shortener service, not the hidden destination — "
                                   "running deeper checks.")
        yield step(why)
        if not escalate:
            continue
        run, skipped = _plan(case, tools.EXPENSIVE_TOOLS)
        if not run:
            yield step("Tool budget used up; no deeper checks possible.")
            continue
        if skipped:
            yield step(f"Tool budget reached; skipping deeper checks: {', '.join(skipped)}.")
        async for f in _run_batch(case, run, target):
            yield finding_event(f)

    yield step("Weighing the evidence…")
    verdict = await judge(case)
    yield {"type": "verdict", "verdict": verdict.model_dump()}
