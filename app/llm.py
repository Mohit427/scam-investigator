"""Thin wrapper over the Anthropic SDK for structured-JSON calls."""
from __future__ import annotations

import json

import anthropic

from app.config import settings


class LLMUnavailable(Exception):
    """No API key configured."""


class LLMError(Exception):
    """The call failed, was refused, or returned unusable output."""


_client: anthropic.AsyncAnthropic | None = None


def client() -> anthropic.AsyncAnthropic:
    global _client
    if not settings.anthropic_api_key:
        raise LLMUnavailable("ANTHROPIC_API_KEY is not set")
    if _client is None:
        # max_retries=1 matches the project-wide "at most one retry" rule.
        _client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key, max_retries=1, timeout=60.0)
    return _client


async def json_call(
    *,
    model: str,
    system: str,
    user: str,
    schema: dict,
    effort: str,
    max_tokens: int,
    timeout: float,
) -> dict:
    """One Messages API call constrained to `schema`; returns the parsed JSON object."""
    try:
        response = await client().with_options(timeout=timeout).messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        )
    except anthropic.APITimeoutError as exc:
        raise LLMError("model call timed out") from exc
    except anthropic.APIConnectionError as exc:
        raise LLMError("could not reach the Anthropic API") from exc
    except anthropic.RateLimitError as exc:
        raise LLMError("Anthropic API rate limit hit") from exc
    except anthropic.AuthenticationError as exc:
        raise LLMError("Anthropic API key was rejected") from exc
    except anthropic.APIStatusError as exc:
        raise LLMError(f"Anthropic API returned HTTP {exc.status_code}") from exc

    if response.stop_reason == "refusal":
        raise LLMError("model declined the request")
    if response.stop_reason == "max_tokens":
        raise LLMError("model output was truncated")
    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError("model returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise LLMError("model returned non-object JSON")
    return data
