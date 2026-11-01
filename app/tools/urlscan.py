"""urlscan.io: search existing scans of the host; if none in the last week, submit a new scan.

Runs only in the expensive tier. New scans are submitted with "unlisted"
visibility (not on the public feed) and polled briefly.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from app import net
from app.config import settings
from app.models import Finding, Target

TOOL = "urlscan"
SOURCE = "urlscan.io"
API = "https://urlscan.io/api/v1"
FRESH_DAYS = 7
POLL_ATTEMPTS = 6
POLL_INTERVAL = 5.0


def _scan_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _summarize_search(target: Target, results: list[dict], total: int) -> tuple[str, str, list[dict]]:
    scans, flagged = [], 0
    for r in results:
        verdicts = r.get("verdicts") or {}
        malicious = bool((verdicts.get("overall") or {}).get("malicious"))
        flagged += malicious
        page = r.get("page") or {}
        scans.append({"time": (r.get("task") or {}).get("time"), "url": page.get("url"), "title": page.get("title"),
                      "ip": page.get("ip"), "country": page.get("country"), "result": r.get("result"),
                      "malicious_verdict": malicious if verdicts else None})
    summary = f"{total} prior urlscan.io scan(s) of {target.host}; most recent {scans[0]['time']}."
    if flagged:
        summary += f" {flagged} of the latest {len(scans)} were marked malicious by urlscan."
        return summary, "malicious", scans
    return summary, "neutral", scans


async def _submit_and_poll(target: Target, headers: dict) -> Finding:
    request = {"url": f"{API}/scan/", "scanned_url": target.url, "visibility": "unlisted"}
    submit = await net.request("POST", f"{API}/scan/", headers=headers,
                               json={"url": target.url, "visibility": "unlisted"})
    if submit.status_code == 429:
        return Finding.new(TOOL, SOURCE, "error", "urlscan.io scan quota reached.",
                           {"request": request, "response": {"http_status": 429}})
    if submit.status_code != 200:
        message = ""
        try:
            message = (submit.json().get("message") or "")[:150]
        except ValueError:
            pass
        return Finding.new(TOOL, SOURCE, "error",
                           f"No recent scans, and urlscan.io refused a new scan (HTTP {submit.status_code}). {message}".strip(),
                           {"request": request, "response": {"http_status": submit.status_code}})
    uuid = submit.json().get("uuid")
    request["uuid"] = uuid
    for _ in range(POLL_ATTEMPTS):
        await asyncio.sleep(POLL_INTERVAL)
        res = await net.request("GET", f"{API}/result/{uuid}/", headers=headers)
        if res.status_code == 404:
            continue  # still scanning
        if res.status_code != 200:
            break
        data = res.json()
        overall = (data.get("verdicts") or {}).get("overall") or {}
        page = data.get("page") or {}
        malicious = bool(overall.get("malicious"))
        response = {"verdict_overall": overall, "page": {k: page.get(k) for k in
                    ("url", "domain", "ip", "country", "server", "title", "status")},
                    "result": f"https://urlscan.io/result/{uuid}/"}
        summary = (f"Fresh urlscan.io scan: page served from {page.get('ip')} ({page.get('country')}); "
                   f"urlscan verdict: {'malicious' if malicious else 'not flagged'} (score {overall.get('score')}).")
        return Finding.new(TOOL, SOURCE, "ok", summary, {"request": request, "response": response},
                           "malicious" if malicious else "neutral")
    return Finding.new(TOOL, SOURCE, "ok", "Submitted a new urlscan.io scan; it did not finish in time.",
                       {"request": request, "response": {"result": f"https://urlscan.io/result/{uuid}/"}}, "neutral")


async def check(target: Target) -> Finding:
    if not settings.urlscan_key:
        return Finding.unavailable(TOOL, SOURCE, "URLSCAN_API_KEY is not set.")
    headers = {"API-Key": settings.urlscan_key}

    params = {"q": f"page.domain:{target.host}", "size": 10}
    resp = await net.request("GET", f"{API}/search/", params=params, headers=headers)
    request = {"url": f"{API}/search/", "params": params}
    if resp.status_code == 429:
        return Finding.new(TOOL, SOURCE, "error", "urlscan.io rate limit reached.",
                           {"request": request, "response": {"http_status": 429}})
    if resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"urlscan.io search returned HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    data = resp.json()
    results = data.get("results") or []
    total = data.get("total", len(results))
    latest = _scan_time(((results[0] if results else {}).get("task") or {}).get("time"))
    fresh = latest is not None and datetime.now(timezone.utc) - latest < timedelta(days=FRESH_DAYS)
    if fresh:
        summary, signal, scans = _summarize_search(target, results, total)
        return Finding.new(TOOL, SOURCE, "ok", summary,
                           {"request": request, "response": {"total": total, "scans": scans}}, signal)
    return await _submit_and_poll(target, headers)
