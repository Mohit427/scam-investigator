"""Structured-JSON calls to the Gemini API (generateContent over httpx).

Each call tries a primary model, then one backup model. That is the single
retry allowed per call: on a timeout, rate limit, server error, block or
unusable output, the backup model is tried once and then the caller falls back.
"""
from __future__ import annotations

import json
import logging
from typing import Callable, TypeVar

import httpx

from app import net
from app.config import redact, settings

log = logging.getLogger("scam_investigator.llm")

T = TypeVar("T")

API = "https://generativelanguage.googleapis.com/v1beta/models"


class LLMUnavailable(Exception):
    """No API key configured."""


class LLMError(Exception):
    """Every model failed, was blocked, or returned unusable output."""


async def _call_model(model: str, *, system: str, user: str, schema: dict,
                      max_tokens: int, timeout: float, thinking_level: str | None) -> dict:
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseJsonSchema": schema,
            "maxOutputTokens": max_tokens,
        },
    }
    if thinking_level:
        body["generationConfig"]["thinkingConfig"] = {"thinkingLevel": thinking_level}
    try:
        # Key goes in a header, never in the URL. retries=0: the backup model is the retry.
        resp = await net.request("POST", f"{API}/{model}:generateContent", json=body, timeout=timeout,
                                 retries=0, headers={"x-goog-api-key": settings.gemini_api_key})
    except httpx.TimeoutException as exc:
        raise LLMError(f"{model} timed out") from exc
    except httpx.TransportError as exc:
        raise LLMError("could not reach the Gemini API") from exc

    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("error", {}).get("message", "")[:200]
        except ValueError:
            pass
        raise LLMError(redact(f"{model} returned HTTP {resp.status_code} {detail}".strip()))

    data = resp.json()
    block = (data.get("promptFeedback") or {}).get("blockReason")
    if block:
        raise LLMError(f"{model} blocked the prompt ({block})")
    candidates = data.get("candidates") or []
    if not candidates:
        raise LLMError(f"{model} returned no candidates")
    candidate = candidates[0]
    finish = candidate.get("finishReason")
    if finish not in (None, "STOP"):
        raise LLMError(f"{model} stopped early ({finish})")
    # Skip thought parts; the JSON answer is in the regular text parts.
    text = "".join(p.get("text", "") for p in (candidate.get("content") or {}).get("parts") or []
                   if not p.get("thought"))
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"{model} returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise LLMError(f"{model} returned non-object JSON")
    return parsed


async def json_call(*, models: list[str], system: str, user: str, schema: dict,
                    max_tokens: int, timeout: float, validate: Callable[[dict], T],
                    thinking_level: str | None = None) -> tuple[T, str]:
    """Returns (validate(parsed JSON), model that produced it).

    `validate` should raise ValueError (pydantic's ValidationError is one) on bad
    output; that counts as a failure and moves on to the backup model.
    """
    if not settings.gemini_api_key:
        raise LLMUnavailable("GEMINI_API_KEY is not set")
    errors = []
    for model in dict.fromkeys(m for m in models if m):  # de-duplicated, order kept
        try:
            data = await _call_model(model, system=system, user=user, schema=schema,
                                     max_tokens=max_tokens, timeout=timeout, thinking_level=thinking_level)
            return validate(data), model
        except LLMError as exc:
            log.warning("LLM call failed: %s", exc)
            errors.append(str(exc))
        except (ValueError, TypeError):
            log.warning("LLM output from %s failed validation", model)
            errors.append(f"{model} output failed validation")
    raise LLMError("; ".join(errors) or "no model configured")
