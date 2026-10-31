"""urlscan.io search for existing scans of the host. (No new submissions yet.)"""
from __future__ import annotations

from app import net
from app.config import settings
from app.models import Finding, Target

TOOL = "urlscan"
SOURCE = "urlscan.io search"
ENDPOINT = "https://urlscan.io/api/v1/search/"


async def check(target: Target) -> Finding:
    if not settings.urlscan_key:
        return Finding.unavailable(TOOL, SOURCE, "URLSCAN_API_KEY is not set.")

    params = {"q": f"page.domain:{target.host}", "size": 10}
    resp = await net.request("GET", ENDPOINT, params=params, headers={"API-Key": settings.urlscan_key})
    request = {"url": ENDPOINT, "params": params}

    if resp.status_code == 429:
        return Finding.new(TOOL, SOURCE, "error", "urlscan.io rate limit reached.",
                           {"request": request, "response": {"http_status": 429}})
    if resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"urlscan.io returned HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    data = resp.json()
    results = data.get("results") or []
    total = data.get("total", len(results))
    scans = []
    flagged = 0
    for r in results:
        verdicts = r.get("verdicts") or {}
        malicious = bool((verdicts.get("overall") or {}).get("malicious"))
        flagged += malicious
        scans.append({
            "time": (r.get("task") or {}).get("time"),
            "url": (r.get("page") or {}).get("url"),
            "title": (r.get("page") or {}).get("title"),
            "ip": (r.get("page") or {}).get("ip"),
            "country": (r.get("page") or {}).get("country"),
            "result": r.get("result"),
            "malicious_verdict": malicious if verdicts else None,
        })

    if not results:
        return Finding.new(TOOL, SOURCE, "ok", f"No prior urlscan.io scans found for {target.host}.",
                           {"request": request, "response": {"total": total}}, "neutral")

    summary = f"{total} prior urlscan.io scan(s) of {target.host}; most recent {scans[0]['time']}."
    signal = "neutral"
    if flagged:
        summary += f" {flagged} of the latest {len(scans)} were marked malicious by urlscan."
        signal = "malicious"
    return Finding.new(TOOL, SOURCE, "ok", summary,
                       {"request": request, "response": {"total": total, "scans": scans}}, signal)
