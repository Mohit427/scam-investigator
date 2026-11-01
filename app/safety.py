"""SSRF guard: the headless browser may only reach public internet hosts."""
from __future__ import annotations

import asyncio
import ipaddress
import socket


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def is_public_host(host: str | None) -> bool:
    """True only if every address the host resolves to is a public (global) IP."""
    if not host:
        return False
    host = host.strip("[]").rstrip(".").lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return False
    try:
        ipaddress.ip_address(host)
        return is_public_ip(host)
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=5.0)
    except (OSError, asyncio.TimeoutError):
        return False
    ips = {info[4][0] for info in infos}
    return bool(ips) and all(is_public_ip(ip) for ip in ips)
