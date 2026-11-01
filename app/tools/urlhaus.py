"""abuse.ch URLhaus URL + host lookup."""
from __future__ import annotations

from app import net
from app.config import settings
from app.models import Finding, Target

TOOL = "urlhaus"
SOURCE = "abuse.ch URLhaus"
API = "https://urlhaus-api.abuse.ch/v1"


def _listed_blacklists(blacklists: dict | None) -> list[str]:
    return sorted(name for name, value in (blacklists or {}).items()
                  if isinstance(value, str) and value not in ("not listed", ""))


async def check(target: Target) -> Finding:
    if not settings.urlhaus_key:
        return Finding.unavailable(TOOL, SOURCE, "URLHAUS_AUTH_KEY is not set.")

    headers = {"Auth-Key": settings.urlhaus_key}
    request = {"url": target.url, "host": target.host}

    url_resp = await net.request("POST", f"{API}/url/", headers=headers, data={"url": target.url})
    if url_resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"URLhaus URL lookup returned HTTP {url_resp.status_code}.",
                           {"request": request, "response": {"http_status": url_resp.status_code}})
    url_data = url_resp.json()
    if url_data.get("query_status") == "ok":
        response = {k: url_data.get(k) for k in
                    ("url_status", "threat", "tags", "date_added", "last_online", "blacklists", "urlhaus_reference")}
        return Finding.new(
            TOOL, SOURCE, "ok",
            f"This exact URL is listed on URLhaus as '{url_data.get('threat')}' "
            f"(status: {url_data.get('url_status')}, added {url_data.get('date_added')}).",
            {"request": request, "response": response}, "malicious",
        )

    if target.is_shortener:
        # Every big shortener host has some abusive links; host-level stats say nothing about this one.
        return Finding.new(TOOL, SOURCE, "ok", "This exact short link is not listed on URLhaus.",
                           {"request": request, "response": {"url_query_status": url_data.get("query_status")}},
                           "neutral")

    host_resp = await net.request("POST", f"{API}/host/", headers=headers, data={"host": target.host})
    if host_resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"URLhaus host lookup returned HTTP {host_resp.status_code}.",
                           {"request": request, "response": {"url_query_status": url_data.get("query_status"),
                                                             "host_http_status": host_resp.status_code}})
    host_data = host_resp.json()
    if host_data.get("query_status") == "ok":
        url_count = int(host_data.get("url_count") or 0)
        listed = _listed_blacklists(host_data.get("blacklists"))
        response = {
            "url_count": url_count,
            "blacklists": host_data.get("blacklists"),
            "firstseen": host_data.get("firstseen"),
            "urlhaus_reference": host_data.get("urlhaus_reference"),
            "sample_urls": [{k: u.get(k) for k in ("url", "url_status", "threat", "date_added")}
                            for u in (host_data.get("urls") or [])[:5]],
        }
        summary = f"Host {target.host} has {url_count} malware URL(s) recorded on URLhaus"
        summary += f" and is listed on {', '.join(listed)}." if listed else "."
        return Finding.new(TOOL, SOURCE, "ok", summary, {"request": request, "response": response},
                           "suspicious" if url_count or listed else "neutral")

    return Finding.new(TOOL, SOURCE, "ok",
                       f"Neither the URL nor host {target.host} is listed on URLhaus.",
                       {"request": request, "response": {"url_query_status": url_data.get("query_status"),
                                                         "host_query_status": host_data.get("query_status")}},
                       "neutral")
