"""Create and verify digest-bound signed verdicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from digate.crypto import canonical_json, payload_hash, sign_bytes, verify_signature
from digate.errors import VerdictError
from digate.models import ScanVerdict, SignedVerdict, VerdictOutcome


def sealing_payload(verdict: ScanVerdict, signer_id: str) -> dict[str, Any]:
    return {
        "digest": verdict.digest,
        "findings": list(verdict.findings),
        "issued_at": verdict.issued_at.isoformat(),
        "outcome": verdict.outcome.value,
        "release_id": verdict.release_id,
        "scanner": verdict.scanner,
        "signer_id": signer_id,
    }


def seal_verdict(keys_dir: Path, signer_id: str, verdict: ScanVerdict) -> SignedVerdict:
    payload = sealing_payload(verdict, signer_id)
    message = canonical_json(payload)
    signature = sign_bytes(keys_dir, signer_id, message)
    return SignedVerdict(
        release_id=verdict.release_id,
        digest=verdict.digest,
        outcome=verdict.outcome,
        scanner=verdict.scanner,
        findings=list(verdict.findings),
        issued_at=verdict.issued_at,
        signer_id=signer_id,
        signature=signature,
        payload_hash=payload_hash(payload),
    )


def verify_verdict(keys_dir: Path, signed: SignedVerdict) -> bool:
    payload = {
        "digest": signed.digest,
        "findings": list(signed.findings),
        "issued_at": signed.issued_at.isoformat(),
        "outcome": signed.outcome.value,
        "release_id": signed.release_id,
        "scanner": signed.scanner,
        "signer_id": signed.signer_id,
    }
    if payload_hash(payload) != signed.payload_hash:
        return False
    message = canonical_json(payload)
    return verify_signature(keys_dir, signed.signer_id, message, signed.signature)


def require_passing_verdict(keys_dir: Path, signed: SignedVerdict) -> None:
    if not verify_verdict(keys_dir, signed):
        raise VerdictError("signature verification failed")
    if signed.outcome != VerdictOutcome.PASS:
        raise VerdictError("verdict outcome is not pass")


def rebind_signature_to_digest(signed: SignedVerdict, wrong_digest: str) -> SignedVerdict:
    """Simulate an attacker reusing a valid signature against a different digest.

    The cryptographic signature remains the bytes from the original seal, so
    verification against the rebound payload must fail — and even if a caller
    skips crypto, the gateway still compares digests explicitly.
    """
    text = wrong_digest.strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    return signed.model_copy(update={"digest": text})
