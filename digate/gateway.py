"""Promotion gateway: verify signed verdict for the exact candidate digest."""

from __future__ import annotations

from pathlib import Path

from digate.audit import AuditLog
from digate.config import Settings
from digate.crypto import save_keypair
from digate.errors import PromotionDenied, VerdictError
from digate.models import (
    Candidate,
    PromotionRequest,
    PromotionResult,
    ReleaseRecord,
    ReleaseState,
    ScanVerdict,
    SignedVerdict,
)
from digate.policy import (
    ensure_digest_binding,
    ensure_fresh,
    ensure_not_already_promoted_other,
    ensure_release_binding,
)
from digate.store import ReleaseStore
from digate.verdict import require_passing_verdict, seal_verdict


class PromotionGateway:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.store = ReleaseStore(settings.store_path)
        self.audit = AuditLog(settings.audit_path)
        self.keys_dir = settings.keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        priv = self.keys_dir / f"{settings.signer_id}.priv"
        if not priv.exists():
            save_keypair(self.keys_dir, settings.signer_id)

    def register_candidate(self, candidate: Candidate) -> ReleaseRecord:
        record = ReleaseRecord(
            release_id=candidate.release_id,
            digest=candidate.digest,
            state=ReleaseState.CANDIDATE,
            image_ref=candidate.image_ref,
        )
        saved = self.store.upsert_candidate(record)
        self.audit.append(
            "candidate_registered",
            release_id=saved.release_id,
            digest=saved.digest,
            state=saved.state.value,
        )
        return saved

    def issue_verdict(self, scan: ScanVerdict) -> SignedVerdict:
        signed = seal_verdict(self.keys_dir, self.settings.signer_id, scan)
        self.audit.append(
            "verdict_issued",
            release_id=signed.release_id,
            digest=signed.digest,
            outcome=signed.outcome.value,
            payload_hash=signed.payload_hash,
        )
        return signed

    def promote(self, request: PromotionRequest) -> PromotionResult:
        record = self.store.get(request.release_id)
        if record is None:
            raise PromotionDenied("unknown release", code="unknown_release")

        try:
            ensure_digest_binding(request)
            ensure_release_binding(record, request)
            ensure_not_already_promoted_other(record, request.candidate_digest)
            ensure_fresh(request.verdict, self.settings.require_fresh_seconds)
            require_passing_verdict(self.keys_dir, request.verdict)
        except (PromotionDenied, VerdictError) as exc:
            reason = str(exc)
            code = getattr(exc, "code", "denied")
            self.audit.append(
                "promotion_denied",
                release_id=request.release_id,
                candidate_digest=request.candidate_digest,
                verdict_digest=request.verdict.digest,
                reason=reason,
                code=code,
                state=record.state.value,
            )
            return PromotionResult(
                accepted=False,
                release_id=record.release_id,
                state=record.state,
                reason=reason,
                digest=record.digest,
            )

        if record.state == ReleaseState.PROMOTED and record.digest == request.candidate_digest:
            return PromotionResult(
                accepted=True,
                release_id=record.release_id,
                state=record.state,
                reason="already promoted for this digest",
                digest=record.digest,
            )

        verdict_id = request.verdict.payload_hash
        promoted = self.store.promote(request.release_id, request.candidate_digest, verdict_id)
        self.audit.append(
            "promotion_accepted",
            release_id=promoted.release_id,
            digest=promoted.digest,
            verdict_id=verdict_id,
            state=promoted.state.value,
        )
        return PromotionResult(
            accepted=True,
            release_id=promoted.release_id,
            state=promoted.state,
            reason="promotion accepted",
            digest=promoted.digest,
        )

    def status(self, release_id: str) -> ReleaseRecord | None:
        return self.store.get(release_id)
