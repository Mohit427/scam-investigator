"""Domain age and registrar via RDAP (rdap.org bootstrap redirector)."""
from __future__ import annotations

from datetime import datetime, timezone

from app import net
from app.models import Finding, Target

TOOL = "rdap"
SOURCE = "RDAP (rdap.org)"


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _registrar(data: dict) -> str | None:
    for entity in data.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    return str(item[3])
        handle = entity.get("handle")
        if handle:
            return str(handle)
    return None


async def check(target: Target) -> Finding:
    domain = target.registered_domain
    url = f"https://rdap.org/domain/{domain}"
    resp = await net.request("GET", url, headers={"Accept": "application/rdap+json"})
    request = {"url": url, "domain": domain}

    if resp.status_code == 404:
        return Finding.new(
            TOOL, SOURCE, "ok",
            f"No RDAP record found for {domain} (unregistered, or its registry does not publish RDAP).",
            {"request": request, "response": {"http_status": 404}},
        )
    if resp.status_code != 200:
        return Finding.new(TOOL, SOURCE, "error", f"RDAP lookup failed with HTTP {resp.status_code}.",
                           {"request": request, "response": {"http_status": resp.status_code}})

    data = resp.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events") or [] if isinstance(e, dict)}
    registered = _parse_date(events.get("registration"))
    registrar = _registrar(data)
    age_days = (datetime.now(timezone.utc) - registered).days if registered else None

    response = {
        "ldhName": data.get("ldhName"),
        "status": data.get("status"),
        "events": data.get("events"),
        "registrar": registrar,
        "port43": data.get("port43"),
    }
    derived = {"age_days": age_days, "registration_date": registered.isoformat() if registered else None}

    if age_days is None:
        summary = f"{domain}: registration date not published in RDAP" + (f"; registrar {registrar}." if registrar else ".")
        signal = "neutral"
    else:
        summary = f"{domain} was registered {age_days} days ago ({registered.date().isoformat()})"
        summary += f" via {registrar}." if registrar else "."
        if age_days < 30:
            signal = "suspicious"
            summary += " Very new domains are common in scams."
        elif age_days >= 365:
            signal = "benign"
        else:
            signal = "neutral"

    return Finding.new(TOOL, SOURCE, "ok", summary,
                       {"request": request, "response": response, "derived": derived}, signal)
