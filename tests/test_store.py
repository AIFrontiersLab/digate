from __future__ import annotations

from pathlib import Path

import pytest

from digate.errors import StoreConflict
from digate.hashing import sha256_text
from digate.models import ReleaseRecord, ReleaseState
from digate.store import ReleaseStore


def test_promote_persists(tmp_path: Path) -> None:
    store = ReleaseStore(tmp_path / "releases.json")
    digest = sha256_text("store")
    store.upsert_candidate(
        ReleaseRecord(release_id="r1", digest=digest, state=ReleaseState.CANDIDATE)
    )
    promoted = store.promote("r1", digest, verdict_id="abc")
    assert promoted.state == ReleaseState.PROMOTED
    assert store.get("r1").promoted_at is not None


def test_cannot_replace_promoted_digest(tmp_path: Path) -> None:
    store = ReleaseStore(tmp_path / "releases.json")
    d1 = sha256_text("one")
    d2 = sha256_text("two")
    store.upsert_candidate(ReleaseRecord(release_id="r1", digest=d1))
    store.promote("r1", d1, "v1")
    with pytest.raises(StoreConflict):
        store.upsert_candidate(ReleaseRecord(release_id="r1", digest=d2))
