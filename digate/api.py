"""FastAPI surface for Digate."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from digate.config import Settings
from digate.gateway import PromotionGateway
from digate.models import (
    Candidate,
    PromotionRequest,
    ReleaseRecord,
    ScanVerdict,
    SignedVerdict,
    VerdictOutcome,
)


class RegisterBody(BaseModel):
    release_id: str
    digest: str
    image_ref: str = ""


class ScanBody(BaseModel):
    release_id: str
    digest: str
    outcome: VerdictOutcome = VerdictOutcome.PASS
    scanner: str = "demo-scanner"
    findings: list[str] = Field(default_factory=list)


class PromoteBody(BaseModel):
    release_id: str
    candidate_digest: str
    verdict: SignedVerdict


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings()
    gateway = PromotionGateway(cfg)
    app = FastAPI(title="Digate", version="0.1.0")
    app.state.gateway = gateway

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "digate"}

    @app.post("/candidates", response_model=ReleaseRecord)
    def register_candidate(body: RegisterBody) -> ReleaseRecord:
        return gateway.register_candidate(
            Candidate(release_id=body.release_id, digest=body.digest, image_ref=body.image_ref)
        )

    @app.post("/verdicts", response_model=SignedVerdict)
    def issue_verdict(body: ScanBody) -> SignedVerdict:
        return gateway.issue_verdict(
            ScanVerdict(
                release_id=body.release_id,
                digest=body.digest,
                outcome=body.outcome,
                scanner=body.scanner,
                findings=body.findings,
            )
        )

    @app.post("/promote")
    def promote(body: PromoteBody) -> dict:
        result = gateway.promote(
            PromotionRequest(
                release_id=body.release_id,
                candidate_digest=body.candidate_digest,
                verdict=body.verdict,
            )
        )
        if not result.accepted:
            raise HTTPException(status_code=409, detail=result.model_dump(mode="json"))
        return result.model_dump(mode="json")

    @app.get("/releases/{release_id}", response_model=ReleaseRecord)
    def get_release(release_id: str) -> ReleaseRecord:
        record = gateway.status(release_id)
        if record is None:
            raise HTTPException(status_code=404, detail="release not found")
        return record

    @app.get("/audit")
    def audit() -> list[dict]:
        return gateway.audit.read_all()

    return app
