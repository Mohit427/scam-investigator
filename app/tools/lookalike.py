"""Brand lookalike / typosquat detection against a curated list of official domains.

Runs locally (no network). The reference list is real, publicly verifiable
official domains of brands commonly impersonated in Indian SMS scams; it is
reference data, not evidence. The finding is computed from the target URL.
"""
from __future__ import annotations

import re

from app.models import Finding, Target
from app.urls import split_domain

TOOL = "lookalike"
SOURCE = "Lookalike-domain check (curated official-domain list)"

# brand -> (keywords that suggest the brand in a hostname, official registered domains)
BRANDS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "State Bank of India": (("sbi", "yono", "onlinesbi"), ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in")),
    "HDFC Bank": (("hdfc", "hdfcbank"), ("hdfcbank.com", "hdfc.bank.in")),
    "ICICI Bank": (("icici", "icicibank"), ("icicibank.com", "icici.bank.in")),
    "Axis Bank": (("axisbank",), ("axisbank.com", "axis.bank.in")),
    "Kotak Mahindra Bank": (("kotak",), ("kotak.com", "kotak.bank.in")),
    "Punjab National Bank": (("pnb", "pnbindia"), ("pnbindia.in", "pnb.bank.in")),
    "Bank of Baroda": (("bankofbaroda", "baroda"), ("bankofbaroda.in", "bankofbaroda.bank.in")),
    "Canara Bank": (("canara", "canarabank"), ("canarabank.com", "canarabank.bank.in")),
    "Union Bank of India": (("unionbank", "unionbankofindia"), ("unionbankofindia.co.in",)),
    "Paytm": (("paytm",), ("paytm.com", "paytm.in")),
    "PhonePe": (("phonepe",), ("phonepe.com",)),
    "Google / Google Pay": (("gpay", "googlepay"), ("google.com", "google.co.in")),
    "NPCI / BHIM UPI": (("npci", "bhim", "bhimupi"), ("npci.org.in", "bhimupi.org.in")),
    "Amazon": (("amazon",), ("amazon.in", "amazon.com")),
    "Flipkart": (("flipkart",), ("flipkart.com",)),
    "Jio": (("jio", "myjio"), ("jio.com",)),
    "Airtel": (("airtel",), ("airtel.in", "airtel.com")),
    "BSNL": (("bsnl",), ("bsnl.co.in",)),
    "India Post": (("indiapost",), ("indiapost.gov.in",)),
    "Income Tax Department": (("incometax", "itr"), ("incometax.gov.in",)),
    "UIDAI / Aadhaar": (("aadhaar", "aadhar", "uidai"), ("uidai.gov.in",)),
    "EPFO": (("epfo", "epfindia"), ("epfindia.gov.in",)),
    "IRCTC": (("irctc",), ("irctc.co.in",)),
    "LIC": (("lic", "licindia"), ("licindia.in",)),
    "Parivahan / e-Challan": (("parivahan", "echallan"), ("parivahan.gov.in",)),
    "WhatsApp": (("whatsapp",), ("whatsapp.com", "wa.me")),
    "Facebook": (("facebook",), ("facebook.com", "fb.com")),
    "Instagram": (("instagram",), ("instagram.com",)),
    "Netflix": (("netflix",), ("netflix.com",)),
    "Microsoft": (("microsoft", "outlook"), ("microsoft.com", "live.com", "outlook.com")),
    "Apple": (("icloud", "appleid"), ("apple.com", "icloud.com")),
    "Blue Dart": (("bluedart",), ("bluedart.com",)),
    "DTDC": (("dtdc",), ("dtdc.in", "dtdc.com")),
    "Delhivery": (("delhivery",), ("delhivery.com",)),
    "FedEx": (("fedex",), ("fedex.com",)),
}

# Registries restricted to vetted owners.
RESTRICTED_SUFFIXES = {
    ".gov.in": "an Indian government domain (.gov.in registrations are restricted to government bodies)",
    ".nic.in": "an Indian government domain (.nic.in is run by the National Informatics Centre)",
    ".bank.in": "an Indian bank domain (.bank.in registrations are restricted to RBI-regulated banks)",
    ".sbi": "State Bank of India's own top-level domain (.sbi)",
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})
_SHORT_KEYWORD = 4  # keywords shorter than this must match a whole hostname token


def _normalize(label: str) -> str:
    return label.lower().translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w").replace("-", "")


def _has_keyword(keyword: str, tokens: list[str]) -> bool:
    if len(keyword) < _SHORT_KEYWORD:
        return keyword in tokens
    return any(keyword in t for t in tokens)


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official_brand(host: str, domain: str) -> str | None:
    for brand, (_, officials) in BRANDS.items():
        if any(domain == o or host == o or host.endswith("." + o) for o in officials):
            return brand
    return None


def analyze(host: str, domain: str) -> tuple[str, str, dict]:
    """Returns (signal, summary, derived) for a host and its registered domain."""
    host, domain = host.lower(), domain.lower()
    brand = _official_brand(host, domain)
    if brand:
        return "benign", f"{host} is on {domain}, an official domain of {brand}.", {"official_brand": brand}
    for suffix, meaning in RESTRICTED_SUFFIXES.items():
        if host.endswith(suffix):
            return "benign", f"{host} is {meaning}.", {"restricted_suffix": suffix}

    label, suffix = split_domain(host)
    tokens = [t for t in re.split(r"[.\-]", host) if t]
    norm_tokens = [_normalize(t) for t in tokens]
    hits: list[dict] = []
    for brand, (keywords, officials) in BRANDS.items():
        for kw in keywords:
            if _has_keyword(kw, tokens):
                hits.append({"brand": brand, "reason": f"contains '{kw}'", "official": list(officials)})
                break
            if _has_keyword(kw, norm_tokens):
                hits.append({"brand": brand, "reason": f"spells '{kw}' with look-alike characters",
                             "official": list(officials)})
                break
        else:
            norm = _normalize(label)
            for official in officials:
                off_label = split_domain(official)[0]
                if len(off_label) < 5:
                    continue
                if label == off_label:
                    hits.append({"brand": brand, "reason": f"same name as {official} on a different ending (.{suffix})",
                                 "official": list(officials)})
                    break
                if norm == off_label:
                    hits.append({"brand": brand, "reason": f"'{label}' imitates '{off_label}' with look-alike characters",
                                 "official": list(officials)})
                    break
                limit = 1 if len(off_label) <= 6 else 2
                if 0 < _levenshtein(norm, off_label) <= limit:
                    hits.append({"brand": brand, "reason": f"'{label}' is one or two letters away from '{off_label}'",
                                 "official": list(officials)})
                    break

    derived: dict = {"matches": hits[:3], "punycode": "xn--" in host, "brands_checked": len(BRANDS)}
    if hits:
        h = hits[0]
        summary = (f"{host} {h['reason']} but is not on the official-domain list for {h['brand']} "
                   f"({', '.join(h['official'])}).")
        if "xn--" in host:
            summary += " It also uses an internationalised (punycode) name that can imitate normal letters."
        return "suspicious", summary, derived
    if "xn--" in host:
        return "suspicious", (f"{host} uses an internationalised (punycode) name, which can imitate normal "
                              "letters; no specific brand match."), derived
    return "neutral", (f"{domain} is not an official domain of the {len(BRANDS)} commonly impersonated brands "
                       "checked, and shows no lookalike pattern."), derived


async def check(target: Target) -> Finding:
    signal, summary, derived = analyze(target.host, target.registered_domain)
    return Finding.new(TOOL, SOURCE, "ok", summary,
                       {"request": {"host": target.host, "registered_domain": target.registered_domain},
                        "derived": derived}, signal)
