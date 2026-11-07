"""Persistent release-state store."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from digate.errors import StoreConflict
from digate.models import ReleaseRecord, ReleaseState


class ReleaseStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({})

    def _read(self) -> dict[str, ReleaseRecord]:
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        return {k: ReleaseRecord.model_validate(v) for k, v in raw.items()}

    def _write(self, records: dict[str, ReleaseRecord]) -> None:
        payload = {k: v.model_dump(mode="json") for k, v in records.items()}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def upsert_candidate(self, record: ReleaseRecord) -> ReleaseRecord:
        with self._lock:
            records = self._read()
            existing = records.get(record.release_id)
            if existing and existing.state == ReleaseState.PROMOTED:
                if existing.digest != record.digest:
                    raise StoreConflict(
                        f"release {record.release_id} already promoted for digest {existing.digest}"
                    )
                return existing
            records[record.release_id] = record
            self._write(records)
            return record

    def get(self, release_id: str) -> ReleaseRecord | None:
        with self._lock:
            return self._read().get(release_id)

    def save(self, record: ReleaseRecord) -> ReleaseRecord:
        with self._lock:
            records = self._read()
            records[record.release_id] = record
            self._write(records)
            return record

    def list_releases(self) -> list[ReleaseRecord]:
        with self._lock:
            return list(self._read().values())

    def promote(self, release_id: str, digest: str, verdict_id: str) -> ReleaseRecord:
        with self._lock:
            records = self._read()
            record = records.get(release_id)
            if record is None:
                raise StoreConflict(f"unknown release {release_id}")
            if record.digest != digest:
                raise StoreConflict("candidate digest mismatch against stored release")
            if record.state == ReleaseState.PROMOTED and record.digest == digest:
                return record
            from digate.models import utc_now

            record.state = ReleaseState.PROMOTED
            record.promoted_at = utc_now()
            record.last_verdict_id = verdict_id
            records[release_id] = record
            self._write(records)
            return record
