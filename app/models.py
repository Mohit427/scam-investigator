"""Pydantic models shared across the app."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Status = Literal["ok", "error", "unavailable", "timeout"]
Signal = Literal["malicious", "suspicious", "benign", "neutral"]
VerdictLabel = Literal["likely_scam", "likely_legitimate", "cannot_determine"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Finding(BaseModel):
    """One piece of evidence produced by one live tool call."""

    id: str = ""  # assigned by CaseState.add_finding
    tool: str
    source: str
    timestamp_utc: str = Field(default_factory=utc_now)
    status: Status
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)
    signal: Signal = "neutral"

    @model_validator(mode="after")
    def _non_ok_is_neutral(self) -> "Finding":
        # A tool that did not get a real answer cannot lean either way.
        if self.status != "ok" and self.signal != "neutral":
            raise ValueError("findings without status 'ok' must have signal 'neutral'")
        return self

    @classmethod
    def new(
        cls,
        tool: str,
        source: str,
        status: Status,
        summary: str,
        raw: dict[str, Any] | None = None,
        signal: Signal = "neutral",
    ) -> "Finding":
        return cls(tool=tool, source=source, status=status, summary=summary, raw=raw or {}, signal=signal)

    @classmethod
    def unavailable(cls, tool: str, source: str, why: str) -> "Finding":
        return cls.new(tool, source, "unavailable", why)


class Target(BaseModel):
    """A normalized URL under investigation."""

    url: str
    host: str
    registered_domain: str
    is_shortener: bool = False
    via: str | None = None  # the link that redirected here, if this target was discovered by the browser


class Entities(BaseModel):
    urls: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    upi_ids: list[str] = Field(default_factory=list)
    claimed_brand: str | None = None
    language_detected: str = "unknown"
    urgency_cues: list[str] = Field(default_factory=list)
    requested_action: str | None = None
    message_type_guess: str = "unknown"


class Reason(BaseModel):
    text: str
    finding_ids: list[str] = Field(default_factory=list)


class Verdict(BaseModel):
    verdict: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[Reason] = Field(default_factory=list)
    action_guidance: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # system notes (caps, dropped reasons, ...)
    live_evidence: bool = True


def validate_citations(verdict: Verdict, known_ids: set[str]) -> tuple[Verdict, int]:
    """Drop any reason that cites no ids or cites an id not in the evidence store.

    Returns the cleaned verdict and the number of reasons dropped.
    """
    kept = [
        r for r in verdict.reasons
        if r.finding_ids and all(fid in known_ids for fid in r.finding_ids)
    ]
    dropped = len(verdict.reasons) - len(kept)
    return verdict.model_copy(update={"reasons": kept}), dropped


class CaseState(BaseModel):
    """In-memory evidence store for one investigation. Never persisted."""

    case_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    entities: Entities | None = None
    targets: list[Target] = Field(default_factory=list)
    findings: dict[str, Finding] = Field(default_factory=dict)
    tool_calls: int = 0
    tool_budget: int = 12

    def add_finding(self, finding: Finding) -> Finding:
        fid = f"F{len(self.findings) + 1}"
        stored = finding.model_copy(update={"id": fid})
        self.findings[fid] = stored
        return stored

    @property
    def budget_left(self) -> int:
        return max(0, self.tool_budget - self.tool_calls)
