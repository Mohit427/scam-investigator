"""OpenPhish community feed membership (feed cached in memory for 1 hour)."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app import net
from app.models import Finding, Target

TOOL = "openphish"
SOURCE = "OpenPhish community feed"
FEED_URL = "https://openphish.com/feed.txt"
CACHE_TTL = 3600.0

_lock = asyncio.Lock()
_cache: dict = {"fetched_at": 0.0, "fetched_iso": None, "urls": set(), "hosts": {}}


def _canon(url: str) -> str:
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{(parts.hostname or '').lower()}{path}{query}"


async def _feed() -> dict:
    async with _lock:
        if time.monotonic() - _cache["fetched_at"] < CACHE_TTL and _cache["urls"]:
            return _cache
        resp = await net.request("GET", FEED_URL)
        resp.raise_for_status()
        urls: set[str] = set()
        hosts: dict[str, list[str]] = {}
        for line in resp.text.splitlines():
            line = line.strip()
            if not line.startswith(("http://", "https://")):
                continue  # guard against an HTML error page being parsed as feed entries
            urls.add(_canon(line))
            host = (urlsplit(line).hostname or "").lower()
            if host:
                hosts.setdefault(host, []).append(line)
        if not urls:
            raise ValueError("OpenPhish feed contained no URLs")
        _cache.update(fetched_at=time.monotonic(),
                      fetched_iso=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      urls=urls, hosts=hosts)
        return _cache


async def check(target: Target) -> Finding:
    feed = await _feed()
    raw_base = {"request": {"feed": FEED_URL, "url": target.url, "host": target.host},
                "derived": {"feed_fetched_at": feed["fetched_iso"], "feed_size": len(feed["urls"])}}

    if _canon(target.url) in feed["urls"]:
        return Finding.new(TOOL, SOURCE, "ok", "This exact URL is in the current OpenPhish phishing feed.",
                           {**raw_base, "response": {"matched": "url"}}, "malicious")
    # For shared shortener hosts only the exact link matters.
    host_matches = [] if target.is_shortener else feed["hosts"].get(target.host, [])
    if host_matches:
        return Finding.new(TOOL, SOURCE, "ok",
                           f"{len(host_matches)} phishing URL(s) on host {target.host} are in the OpenPhish feed.",
                           {**raw_base, "response": {"matched": "host", "entries": host_matches[:10]}}, "suspicious")
    return Finding.new(TOOL, SOURCE, "ok",
                       f"Not in the OpenPhish feed ({len(feed['urls'])} active entries checked).",
                       {**raw_base, "response": {"matched": None}}, "neutral")
