from __future__ import annotations

from digate.gateway import PromotionGateway
from digate.hashing import sha256_text
from digate.models import Candidate, PromotionRequest, ReleaseState, ScanVerdict, VerdictOutcome


def test_happy_path_promotion(gateway: PromotionGateway) -> None:
    digest = sha256_text("candidate-v1")
    gateway.register_candidate(Candidate(release_id="rel-1", digest=digest))
    verdict = gateway.issue_verdict(
        ScanVerdict(
            release_id="rel-1",
            digest=digest,
            outcome=VerdictOutcome.PASS,
            scanner="unit",
        )
    )
    result = gateway.promote(
        PromotionRequest(release_id="rel-1", candidate_digest=digest, verdict=verdict)
    )
    assert result.accepted
    assert gateway.status("rel-1").state == ReleaseState.PROMOTED


def test_failing_verdict_denied(gateway: PromotionGateway) -> None:
    digest = sha256_text("candidate-v2")
    gateway.register_candidate(Candidate(release_id="rel-2", digest=digest))
    verdict = gateway.issue_verdict(
        ScanVerdict(
            release_id="rel-2",
            digest=digest,
            outcome=VerdictOutcome.FAIL,
            scanner="unit",
            findings=["critical CVE"],
        )
    )
    result = gateway.promote(
        PromotionRequest(release_id="rel-2", candidate_digest=digest, verdict=verdict)
    )
    assert not result.accepted
    assert gateway.status("rel-2").state == ReleaseState.CANDIDATE
