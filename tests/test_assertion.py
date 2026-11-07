"""MVP acceptance: valid signature on the wrong digest leaves release unchanged."""

from __future__ import annotations

from digate.demo import run_demo
from digate.gateway import PromotionGateway
from digate.hashing import sha256_text
from digate.models import Candidate, PromotionRequest, ReleaseState, ScanVerdict, VerdictOutcome
from digate.verdict import rebind_signature_to_digest


def test_valid_signature_wrong_digest_leaves_state_unchanged(gateway: PromotionGateway) -> None:
    yesterday = sha256_text("yesterday-build")
    today = sha256_text("today-build")

    gateway.register_candidate(Candidate(release_id="rel-assert", digest=today))
    signed_yesterday = gateway.issue_verdict(
        ScanVerdict(
            release_id="rel-assert",
            digest=yesterday,
            outcome=VerdictOutcome.PASS,
            scanner="unit",
        )
    )
    forged = rebind_signature_to_digest(signed_yesterday, today)

    before = gateway.status("rel-assert")
    assert before is not None
    assert before.state == ReleaseState.CANDIDATE

    result = gateway.promote(
        PromotionRequest(
            release_id="rel-assert",
            candidate_digest=today,
            verdict=forged,
        )
    )

    after = gateway.status("rel-assert")
    assert result.accepted is False
    assert after is not None
    assert after.state == ReleaseState.CANDIDATE
    assert after.digest == today
    assert after.promoted_at is None


def test_demo_assertion_holds(tmp_path) -> None:
    result = run_demo(tmp_path)
    assert result["assertion_holds"] is True
