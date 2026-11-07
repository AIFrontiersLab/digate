from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from digate.api import create_app
from digate.config import Settings
from digate.hashing import sha256_text


def test_api_promote_roundtrip(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))
    client = TestClient(app)
    digest = sha256_text("api-candidate")

    assert client.get("/health").json()["status"] == "ok"

    reg = client.post(
        "/candidates",
        json={"release_id": "rel-api", "digest": digest, "image_ref": "app:rc"},
    )
    assert reg.status_code == 200

    verdict = client.post(
        "/verdicts",
        json={"release_id": "rel-api", "digest": digest, "outcome": "pass"},
    ).json()

    ok = client.post(
        "/promote",
        json={
            "release_id": "rel-api",
            "candidate_digest": digest,
            "verdict": verdict,
        },
    )
    assert ok.status_code == 200
    assert ok.json()["accepted"] is True

    status = client.get("/releases/rel-api")
    assert status.json()["state"] == "promoted"
