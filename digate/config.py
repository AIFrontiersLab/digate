"""Runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path("data"))
    release_env: str = "staging"
    require_fresh_seconds: int = 3600
    signer_id: str = "scanner-primary"

    @property
    def store_path(self) -> Path:
        return self.data_dir / "releases.json"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit.jsonl"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "keys"


DEFAULT_SETTINGS = Settings()
