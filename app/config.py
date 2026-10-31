"""Environment configuration. Reports which keys are present, never their values."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

log = logging.getLogger("scam_investigator")

SECRET_KEYS = (
    "ANTHROPIC_API_KEY",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "URLHAUS_AUTH_KEY",
)

DEFAULT_MODEL_FAST = "claude-haiku-5-5"
DEFAULT_MODEL_JUDGE = "claude-sonnet-5-5"


def _env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str | None
    model_fast: str
    model_judge: str
    safe_browsing_key: str | None
    virustotal_key: str | None
    urlscan_key: str | None
    urlhaus_key: str | None
    port: int


def _load() -> Settings:
    port = _env("PORT")
    return Settings(
        anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        model_fast=_env("ANTHROPIC_MODEL_FAST") or DEFAULT_MODEL_FAST,
        model_judge=_env("ANTHROPIC_MODEL_JUDGE") or DEFAULT_MODEL_JUDGE,
        safe_browsing_key=_env("GOOGLE_SAFE_BROWSING_API_KEY"),
        virustotal_key=_env("VIRUSTOTAL_API_KEY"),
        urlscan_key=_env("URLSCAN_API_KEY"),
        urlhaus_key=_env("URLHAUS_AUTH_KEY"),
        port=int(port) if port and port.isdigit() else 8000,
    )


settings = _load()


def key_presence() -> dict[str, bool]:
    """Names of secret keys mapped to whether they are set. Never exposes values."""
    return {name: _env(name) is not None for name in SECRET_KEYS}


def log_key_presence() -> None:
    presence = key_presence()
    present = [k for k, v in presence.items() if v]
    missing = [k for k, v in presence.items() if not v]
    log.info("API keys present: %s", ", ".join(present) or "none")
    if missing:
        log.warning("API keys missing (those tools will report 'unavailable'): %s", ", ".join(missing))
    log.info("Models: fast=%s judge=%s", settings.model_fast, settings.model_judge)


def redact(text: str) -> str:
    """Strip any configured secret values out of a string (e.g. an error message)."""
    for name in SECRET_KEYS:
        value = _env(name)
        if value:
            text = text.replace(value, "[redacted]")
    return text
