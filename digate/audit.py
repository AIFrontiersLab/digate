"""Append-only audit trail."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from digate.models import utc_now


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def append(self, event_type: str, **fields: Any) -> dict[str, Any]:
        event = {
            "ts": utc_now().isoformat(),
            "event": event_type,
            **fields,
        }
        line = json.dumps(event, sort_keys=True, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return event

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events
