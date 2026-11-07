from __future__ import annotations

from pathlib import Path

from digate.crypto import save_keypair
from digate.hashing import sha256_text
from digate.models import ScanVerdict, VerdictOutcome
from digate.verdict import rebind_signature_to_digest, seal_verdict, verify_verdict


def test_sealed_verdict_verifies(tmp_path: Path) -> None:
    save_keypair(tmp_path, "scanner-primary")
    digest = sha256_text("artifact")
    signed = seal_verdict(
        tmp_path,
        "scanner-primary",
        ScanVerdict(
            release_id="r1",
            digest=digest,
            outcome=VerdictOutcome.PASS,
            scanner="unit",
        ),
    )
    assert verify_verdict(tmp_path, signed)


def test_rebound_digest_fails_crypto(tmp_path: Path) -> None:
    save_keypair(tmp_path, "scanner-primary")
    good = sha256_text("good")
    bad = sha256_text("bad")
    signed = seal_verdict(
        tmp_path,
        "scanner-primary",
        ScanVerdict(
            release_id="r1",
            digest=good,
            outcome=VerdictOutcome.PASS,
            scanner="unit",
        ),
    )
    rebound = rebind_signature_to_digest(signed, bad)
    assert not verify_verdict(tmp_path, rebound)
