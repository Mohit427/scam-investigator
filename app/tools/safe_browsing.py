"""Google Safe Browsing v4 threatMatches:find."""
from __future__ import annotations

from app import net
from app.config import settings
from app.models import Finding, Target

TOOL = "safe_browsing"
SOURCE = "Google Safe Browsing v4"
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


async def check(target: Target) -> Finding:
    if not settings.safe_browsing_key:
        return Finding.unavailable(TOOL, SOURCE, "GOOGLE_SAFE_BROWSING_API_KEY is not set.")

    body = {
        "client": {"clientId": "scam-investigator", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target.url}],
        },
    }
    # Key goes in a header, never in the URL, so it can't leak into error messages.
    resp = await net.request("POST", ENDPOINT, json=body, headers={"X-Goog-Api-Key": settings.safe_browsing_key})
    request = {"url": target.url, "threatTypes": THREAT_TYPES}

    if resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"Safe Browsing returned HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    data = resp.json()
    matches = data.get("matches") or []
    if matches:
        types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return Finding.new(TOOL, SOURCE, "ok",
                           f"Google Safe Browsing flags this URL as: {', '.join(types)}.",
                           {"request": request, "response": data}, "malicious")
    return Finding.new(TOOL, SOURCE, "ok",
                       "Not on Google Safe Browsing threat lists (absence is not proof of safety).",
                       {"request": request, "response": data}, "neutral")
