"""VirusTotal v3 URL report; submits the URL for analysis if no report exists."""
from __future__ import annotations

import asyncio
import base64

from app import net
from app.config import settings
from app.models import Finding, Target

TOOL = "virustotal"
SOURCE = "VirusTotal v3"
API = "https://www.virustotal.com/api/v3"
POLL_ATTEMPTS = 3
POLL_INTERVAL = 4.0


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _classify(stats: dict) -> tuple[str, str]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    text = (f"{malicious} engines flag it malicious, {suspicious} suspicious, "
            f"{harmless} harmless, {undetected} undetected.")
    if malicious >= 2:
        return "malicious", text
    if malicious == 1 or suspicious >= 1:
        return "suspicious", text
    if harmless >= 5:
        return "benign", text
    return "neutral", text


def _flagging_engines(results: dict) -> list[str]:
    return sorted(name for name, r in (results or {}).items()
                  if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"))


async def check(target: Target) -> Finding:
    if not settings.virustotal_key:
        return Finding.unavailable(TOOL, SOURCE, "VIRUSTOTAL_API_KEY is not set.")

    headers = {"x-apikey": settings.virustotal_key}
    request = {"url": target.url}

    resp = await net.request("GET", f"{API}/urls/{_url_id(target.url)}", headers=headers)
    if resp.status_code == 200:
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        signal, text = _classify(stats)
        response = {
            "last_analysis_stats": stats,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "flagging_engines": _flagging_engines(attrs.get("last_analysis_results")),
        }
        return Finding.new(TOOL, SOURCE, "ok", f"Existing VirusTotal report: {text}",
                           {"request": request, "response": response}, signal)

    if resp.status_code == 429:
        return Finding.new(TOOL, SOURCE, "error", "VirusTotal rate limit reached (free tier allows 4 lookups/minute).",
                           {"request": request, "response": {"http_status": 429}})
    if resp.status_code != 404:
        return Finding.new(TOOL, SOURCE, "error", f"VirusTotal returned HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    # No report yet: submit the URL (only the URL) and poll briefly.
    submit = await net.request("POST", f"{API}/urls", headers=headers, data={"url": target.url})
    if submit.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error",
                           f"No existing report and submission failed with HTTP {submit.status_code}.",
                           {"request": request, "response": {"http_status": submit.status_code}})
    analysis_id = (submit.json().get("data") or {}).get("id")
    request["submitted_analysis_id"] = analysis_id

    for _ in range(POLL_ATTEMPTS):
        await asyncio.sleep(POLL_INTERVAL)
        poll = await net.request("GET", f"{API}/analyses/{analysis_id}", headers=headers)
        if poll.status_code != 200:
            continue
        attrs = (poll.json().get("data") or {}).get("attributes") or {}
        if attrs.get("status") == "completed":
            stats = attrs.get("stats") or {}
            signal, text = _classify(stats)
            response = {"analysis_status": "completed", "stats": stats, "date": attrs.get("date"),
                        "flagging_engines": _flagging_engines(attrs.get("results"))}
            return Finding.new(TOOL, SOURCE, "ok", f"Fresh VirusTotal scan (no prior report): {text}",
                               {"request": request, "response": response}, signal)

    return Finding.new(TOOL, SOURCE, "ok",
                       "VirusTotal had no prior report; URL was submitted but the scan did not finish in time.",
                       {"request": request, "response": {"analysis_status": "pending"}}, "neutral")
