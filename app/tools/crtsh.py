"""Certificate transparency lookup via crt.sh JSON output."""
from __future__ import annotations

from datetime import datetime, timezone

from app import net
from app.models import Finding, Target

TOOL = "crtsh"
SOURCE = "crt.sh certificate transparency"
ENDPOINT = "https://crt.sh/"
TIMEOUT = 20.0  # crt.sh is routinely slow; documented exception to the 10 s default


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def check(target: Target) -> Finding:
    domain = target.registered_domain
    params = {"q": domain, "output": "json"}
    resp = await net.request("GET", ENDPOINT, params=params, timeout=TIMEOUT)
    request = {"url": ENDPOINT, "params": params}

    if resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"crt.sh returned HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    entries = resp.json() or []
    dated = [(d, e) for e in entries if (d := _parse(e.get("not_before")))]
    if not dated:
        return Finding.new(TOOL, SOURCE, "ok",
                           f"No certificates logged for {domain} in certificate transparency.",
                           {"request": request, "response": {"count": 0}}, "neutral")

    dated.sort(key=lambda pair: pair[0])
    earliest, first_entry = dated[0]
    latest = dated[-1][0]
    age_days = (datetime.now(timezone.utc) - earliest).days
    response = {
        "count": len(entries),
        "earliest_entry": {k: first_entry.get(k) for k in ("id", "issuer_name", "common_name", "not_before", "not_after")},
        "latest_not_before": latest.isoformat(),
    }
    derived = {"earliest_cert_age_days": age_days}

    summary = (f"{len(entries)} certificate log entries for {domain}; earliest issued "
               f"{earliest.date().isoformat()} ({age_days} days ago).")
    if age_days < 30:
        signal = "suspicious"
        summary += " The domain's first certificate is very recent."
    else:
        signal = "neutral"
    return Finding.new(TOOL, SOURCE, "ok", summary,
                       {"request": request, "response": response, "derived": derived}, signal)
