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
from app.models import CaseState, Entities, Finding, Target, Verdict
from app.urls import normalize_url
from app.verdict import MESSAGE_TOOL, default_guidance, finalize, judge

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
    if method.startswith("llm"):
        source = f"Gemini entity extraction ({method.split(':', 1)[1]})"
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


async def _run_batch(case: CaseState, names: list[str], target: Target) -> AsyncIterator[Finding]:
    """Run tools concurrently; yield each finding the moment it completes.

    External tools are charged to the budget up front; a tool that returned
    "unavailable" (no key / no browser) made no call, so its charge is refunded.
    """
    charged = {n for n in names if tools.REGISTRY[n].external}
    case.tool_calls += len(charged)
    tasks = [asyncio.create_task(tools.run_tool(n, target)) for n in names]
    try:
        for next_done in asyncio.as_completed(tasks):
            finding = await next_done
            if finding.status == "unavailable" and finding.tool in charged:
                case.tool_calls -= 1
            yield case.add_finding(finding)
    finally:
        for t in tasks:
            t.cancel()


def _plan(case: CaseState, names: list[str]) -> tuple[list[str], list[str]]:
    """Split tools into (run, skipped) by the remaining budget; local tools always run."""
    run, skipped, budget = [], [], case.budget_left
    for name in names:
        if not tools.REGISTRY[name].external:
            run.append(name)
        elif budget > 0:
            run.append(name)
            budget -= 1
        else:
            skipped.append(name)
    return run, skipped


def _enqueue(case: CaseState, url: str, via: str) -> Target | None:
    target = normalize_url(url)
    if target is None or any(t.url == target.url for t in case.targets) or len(case.targets) >= MAX_URLS:
        return None
    target.via = via
    case.targets.append(target)
    return target


def _destination(findings: list[Finding]) -> str | None:
    trace = next((f for f in findings if f.tool == "browser_trace" and f.status == "ok"), None)
    return trace.raw.get("derived", {}).get("final_url") if trace else None


async def _run_tier(case: CaseState, names: list[str], target: Target, label: str,
                    out: list[Finding]) -> AsyncIterator[dict]:
    run, skipped = _plan(case, names)
    if skipped:
        yield step(f"Tool budget ({case.tool_budget} calls) reached; skipping {label}: {', '.join(skipped)}.")
    if not any(tools.REGISTRY[n].external for n in run):
        return
    async for f in _run_batch(case, run, target):
        out.append(f)
        yield finding_event(f)


async def _investigate_shortener(case: CaseState, target: Target) -> AsyncIterator[dict]:
    yield step(f"{target.host} is a link shortener that hides the real destination. Opening it in an isolated "
               "browser to unroll it, and checking the short link's reputation…")
    found: list[Finding] = []
    async for event in _run_tier(case, tools.SHORTENER_TOOLS, target, "checks", found):
        yield event
    dest = _destination(found)
    dest_target = normalize_url(dest) if dest else None
    if dest_target is None:
        yield step("Could not determine where the short link leads (the page did not load).")
    elif dest_target.host == target.host:
        yield step(f"The link does not redirect anywhere; it shows a page on {target.host}.")
    elif _enqueue(case, dest, via=target.url):
        yield step(f"The short link leads to {dest} — investigating that destination next.")
    else:
        yield step(f"The short link leads to {dest} (already checked, or link limit reached).")


async def _investigate_link(case: CaseState, target: Target) -> AsyncIterator[dict]:
    yield step(f"Checking {target.url} against live sources in parallel…")
    found: list[Finding] = []
    async for event in _run_tier(case, tools.CHEAP_TOOLS, target, "quick checks", found):
        yield event

    escalate, why = _escalation(found)
    yield step(why)
    if not escalate:
        return
    deep = [n for n in tools.EXPENSIVE_TOOLS if not (n == "browser_trace" and target.via)]
    if case.budget_left == 0:
        yield step("Tool budget used up; no deeper checks possible.")
        return
    deep_found: list[Finding] = []
    async for event in _run_tier(case, deep, target, "deeper checks", deep_found):
        yield event
    dest = _destination(deep_found)
    dest_target = normalize_url(dest) if dest else None
    if dest_target and dest_target.registered_domain != target.registered_domain:
        if _enqueue(case, dest, via=target.url):
            yield step(f"{target.host} redirects to a different site ({dest_target.host}) — investigating it too.")


async def investigate(message: str) -> AsyncIterator[dict]:
    case = CaseState()
    try:
        async for event in _investigate(case, message):
            yield event
    except Exception as exc:  # noqa: BLE001 - last line of defence; always end with a verdict
        log.exception("investigation crashed")
        yield {"type": "error", "message": f"Investigation hit an internal error ({type(exc).__name__})."}
        fallback = Verdict(verdict="cannot_determine", confidence=0.0,
                           action_guidance=default_guidance(bool(case.targets)),
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

    i = 0
    while i < len(case.targets):  # targets can grow as redirects are discovered
        target = case.targets[i]
        i += 1
        if case.budget_left == 0:
            yield step(f"Tool budget ({case.tool_budget} calls) used up; skipping {target.host}.")
            continue
        events = _investigate_shortener(case, target) if target.is_shortener else _investigate_link(case, target)
        async for event in events:
            yield event

    yield step("Weighing the evidence…")
    verdict = await judge(case)
    yield {"type": "verdict", "verdict": verdict.model_dump()}
