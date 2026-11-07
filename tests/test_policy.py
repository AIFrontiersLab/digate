from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from digate.errors import PromotionDenied
from digate.hashing import sha256_text
from digate.models import PromotionRequest, ReleaseRecord, ScanVerdict, SignedVerdict, VerdictOutcome
from digate.policy import ensure_digest_binding, ensure_fresh


def _signed(digest: str, issued_at: datetime) -> SignedVerdict:
    return SignedVerdict(
        release_id="r",
        digest=digest,
        outcome=VerdictOutcome.PASS,
        scanner="s",
        findings=[],
        issued_at=issued_at,
        signer_id="scanner-primary",
        signature="qq==",
        payload_hash="0" * 64,
    )


def test_digest_binding_rejects_mismatch() -> None:
    d1 = sha256_text("a")
    d2 = sha256_text("b")
    req = PromotionRequest(
        release_id="r",
        candidate_digest=d1,
        verdict=_signed(d2, datetime.now(timezone.utc)),
    )
    with pytest.raises(PromotionDenied, match="does not match"):
        ensure_digest_binding(req)


def test_freshness_window() -> None:
    digest = sha256_text("fresh")
    old = _signed(digest, datetime.now(timezone.utc) - timedelta(hours=2))
    with pytest.raises(PromotionDenied, match="expired"):
        ensure_fresh(old, max_age_seconds=3600)
