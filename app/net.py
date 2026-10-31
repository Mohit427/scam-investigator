"""Shared async HTTP client: every call has a timeout and at most one retry."""
from __future__ import annotations

import asyncio

import httpx

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "ScamInvestigator/0.1 (+citizen scam-check tool)"
_RETRY_STATUS = {500, 502, 503, 504}

_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(headers={"User-Agent": USER_AGENT}, follow_redirects=True)
    return _client


async def aclose() -> None:
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


async def request(
    method: str,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 1,
    **kwargs,
) -> httpx.Response:
    """Send a request, retrying once on transport errors and 5xx responses.

    Raises httpx.TimeoutException / httpx.TransportError if the last attempt fails;
    callers rely on tools.run_tool to turn that into a Finding.
    """
    for attempt in range(retries + 1):
        try:
            resp = await client().request(method, url, timeout=timeout, **kwargs)
        except httpx.TransportError:
            if attempt >= retries:
                raise
            await asyncio.sleep(0.5)
            continue
        if resp.status_code in _RETRY_STATUS and attempt < retries:
            await asyncio.sleep(0.5)
            continue
        return resp
    raise RuntimeError("unreachable")  # loop always returns or raises
