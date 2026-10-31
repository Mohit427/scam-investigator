"""URL normalization and domain helpers."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

import tldextract

from app.models import Target

# Use the public-suffix snapshot bundled with tldextract; no network fetch at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=())

KNOWN_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly",
    "rb.gy", "ow.ly", "buff.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.ly",
    "lnkd.in", "shorte.st", "adf.ly", "bl.ink", "short.io", "tinu.be", "u.to", "qr.ae",
})

_TRAILING_JUNK = ".,;:!?)]}>'\"`*"
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def registered_domain(host: str) -> str:
    ext = _extract(host)
    return ext.top_domain_under_public_suffix if hasattr(ext, "top_domain_under_public_suffix") else ext.registered_domain


def has_public_suffix(host: str) -> bool:
    ext = _extract(host)
    return bool(ext.suffix and ext.domain)


def normalize_url(raw: str) -> Target | None:
    """Turn a raw extracted link into a Target, or None if it is not a usable web URL.

    Scheme-less links get "http://" (what a phone would open). The host is
    lowercased and IDNA-encoded; trailing punctuation from the message is stripped.
    """
    text = raw.strip().strip("<>").rstrip(_TRAILING_JUNK)
    if not text:
        return None
    if not _SCHEME_RE.match(text):
        text = "http://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not has_public_suffix(host):
        return None
    netloc = host if port is None else f"{host}:{port}"
    url = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    domain = registered_domain(host) or host
    return Target(
        url=url,
        host=host,
        registered_domain=domain,
        is_shortener=host in KNOWN_SHORTENERS or domain in KNOWN_SHORTENERS,
    )
