"""Typed models for Digate."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReleaseState(str, Enum):
    CANDIDATE = "candidate"
    PROMOTED = "promoted"
    BLOCKED = "blocked"


class VerdictOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class Candidate(BaseModel):
    release_id: str
    digest: str
    image_ref: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("digest")
    @classmethod
    def digest_must_be_hex(cls, value: str) -> str:
        text = value.strip().lower()
        if text.startswith("sha256:"):
            text = text[7:]
        if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise ValueError("digest must be sha256 hex (64 chars)")
        return text


class ScanVerdict(BaseModel):
    """Unsigned scan result before sealing."""

    release_id: str
    digest: str
    outcome: VerdictOutcome
    scanner: str
    findings: list[str] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=utc_now)

    @field_validator("digest")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        text = value.strip().lower()
        if text.startswith("sha256:"):
            text = text[7:]
        return text


class SignedVerdict(BaseModel):
    """Digest-bound signed promotion evidence."""

    release_id: str
    digest: str
    outcome: VerdictOutcome
    scanner: str
    findings: list[str] = Field(default_factory=list)
    issued_at: datetime
    signer_id: str
    signature: str
    payload_hash: str

    @field_validator("digest")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        text = value.strip().lower()
        if text.startswith("sha256:"):
            text = text[7:]
        return text


class ReleaseRecord(BaseModel):
    release_id: str
    digest: str
    state: ReleaseState = ReleaseState.CANDIDATE
    image_ref: str = ""
    promoted_at: datetime | None = None
    last_verdict_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PromotionRequest(BaseModel):
    release_id: str
    candidate_digest: str
    verdict: SignedVerdict

    @field_validator("candidate_digest")
    @classmethod
    def normalize_digest(cls, value: str) -> str:
        text = value.strip().lower()
        if text.startswith("sha256:"):
            text = text[7:]
        return text


class PromotionResult(BaseModel):
    accepted: bool
    release_id: str
    state: ReleaseState
    reason: str
    digest: str
