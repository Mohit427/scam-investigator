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
    "GEMINI_API_KEY",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "URLHAUS_AUTH_KEY",
)

# Extraction: fast + cheap. Judge: strongest Flash models. All four have a free tier.
# (gemini-4-argon is stronger for the judge but is paid-only.)
DEFAULT_MODEL_FAST = "gemini-3.5-flash-lite"
DEFAULT_MODEL_FAST_BACKUP = "gemini-3.1-flash-lite"
DEFAULT_MODEL_JUDGE = "gemini-3.8-flash"
DEFAULT_MODEL_JUDGE_BACKUP = "gemini-3.6-flash"


def _env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str | None
    model_fast: str
    model_fast_backup: str
    model_judge: str
    model_judge_backup: str
    safe_browsing_key: str | None
    virustotal_key: str | None
    urlscan_key: str | None
    urlhaus_key: str | None
    port: int


def _load() -> Settings:
    port = _env("PORT")
    return Settings(
        gemini_api_key=_env("GEMINI_API_KEY"),
        model_fast=_env("GEMINI_MODEL_FAST") or DEFAULT_MODEL_FAST,
        model_fast_backup=_env("GEMINI_MODEL_FAST_BACKUP") or DEFAULT_MODEL_FAST_BACKUP,
        model_judge=_env("GEMINI_MODEL_JUDGE") or DEFAULT_MODEL_JUDGE,
        model_judge_backup=_env("GEMINI_MODEL_JUDGE_BACKUP") or DEFAULT_MODEL_JUDGE_BACKUP,
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
    log.info("Models: extraction=%s (backup %s), judge=%s (backup %s)", settings.model_fast,
             settings.model_fast_backup, settings.model_judge, settings.model_judge_backup)


def redact(text: str) -> str:
    """Strip any configured secret values out of a string (e.g. an error message)."""
    for name in SECRET_KEYS:
        value = _env(name)
        if value:
            text = text.replace(value, "[redacted]")
    return text
