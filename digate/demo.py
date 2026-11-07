"""Local demo proving the ReleaseProof assertion."""

from __future__ import annotations

import tempfile
from pathlib import Path

from digate.config import Settings
from digate.gateway import PromotionGateway
from digate.hashing import sha256_text
from digate.models import Candidate, PromotionRequest, ReleaseState, ScanVerdict, VerdictOutcome
from digate.verdict import rebind_signature_to_digest


def run_demo(data_dir: Path | None = None) -> dict:
    root = Path(data_dir) if data_dir else Path(tempfile.mkdtemp(prefix="digate-demo-"))
    settings = Settings(data_dir=root)
    gateway = PromotionGateway(settings)

    yesterday = sha256_text("build-yesterday")
    today = sha256_text("build-today")

    gateway.register_candidate(
        Candidate(release_id="rel-100", digest=today, image_ref="app:1.0.0-rc2")
    )

    # Scanner correctly signed yesterday's digest (or an attacker presents that seal).
    signed_yesterday = gateway.issue_verdict(
        ScanVerdict(
            release_id="rel-100",
            digest=yesterday,
            outcome=VerdictOutcome.PASS,
            scanner="image-scanner",
            findings=[],
        )
    )

    # Attacker reuses that signature while pointing promotion at today's candidate.
    forged = rebind_signature_to_digest(signed_yesterday, today)
    denied = gateway.promote(
        PromotionRequest(
            release_id="rel-100",
            candidate_digest=today,
            verdict=forged,
        )
    )

    # Honest path: seal for the exact candidate digest.
    signed_today = gateway.issue_verdict(
        ScanVerdict(
            release_id="rel-100",
            digest=today,
            outcome=VerdictOutcome.PASS,
            scanner="image-scanner",
            findings=[],
        )
    )
    accepted = gateway.promote(
        PromotionRequest(
            release_id="rel-100",
            candidate_digest=today,
            verdict=signed_today,
        )
    )

    status = gateway.status("rel-100")
    assert status is not None
    return {
        "data_dir": str(root),
        "yesterday_digest": yesterday,
        "today_digest": today,
        "wrong_digest_accepted": denied.accepted,
        "wrong_digest_state": denied.state.value,
        "correct_digest_accepted": accepted.accepted,
        "final_state": status.state.value,
        "assertion_holds": (
            denied.accepted is False
            and denied.state == ReleaseState.CANDIDATE
            and accepted.accepted is True
            and status.state == ReleaseState.PROMOTED
            and status.digest == today
        ),
    }


def print_demo() -> None:
    result = run_demo()
    print("Digate demo — ReleaseProof assertion")
    print(f"  yesterday digest: {result['yesterday_digest'][:12]}...")
    print(f"  today digest:     {result['today_digest'][:12]}...")
    print(f"  wrong-digest promote accepted? {result['wrong_digest_accepted']}")
    print(f"  state after wrong digest:      {result['wrong_digest_state']}")
    print(f"  correct-digest promote accepted? {result['correct_digest_accepted']}")
    print(f"  final state: {result['final_state']}")
    print(f"  assertion holds: {result['assertion_holds']}")
