"""Promotion policy checks."""

from __future__ import annotations

from datetime import datetime, timezone

from digate.errors import PromotionDenied
from digate.models import PromotionRequest, ReleaseRecord, ReleaseState, SignedVerdict


def ensure_digest_binding(request: PromotionRequest) -> None:
    if request.candidate_digest != request.verdict.digest:
        raise PromotionDenied(
            "verdict digest does not match candidate digest",
            code="digest_mismatch",
        )


def ensure_release_binding(record: ReleaseRecord, request: PromotionRequest) -> None:
    if record.release_id != request.release_id:
        raise PromotionDenied("release id mismatch", code="release_mismatch")
    if record.digest != request.candidate_digest:
        raise PromotionDenied(
            "candidate digest does not match registered release digest",
            code="candidate_mismatch",
        )
    if request.verdict.release_id != request.release_id:
        raise PromotionDenied(
            "verdict was issued for a different release id",
            code="verdict_release_mismatch",
        )


def ensure_not_already_promoted_other(record: ReleaseRecord, digest: str) -> None:
    if record.state == ReleaseState.PROMOTED and record.digest != digest:
        raise PromotionDenied(
            "release already promoted for a different digest",
            code="already_promoted",
        )


def ensure_fresh(verdict: SignedVerdict, max_age_seconds: int, *, now: datetime | None = None) -> None:
    current = now or datetime.now(timezone.utc)
    issued = verdict.issued_at
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    age = (current - issued).total_seconds()
    if age > max_age_seconds:
        raise PromotionDenied(
            f"verdict expired ({int(age)}s old)",
            code="stale_verdict",
        )
