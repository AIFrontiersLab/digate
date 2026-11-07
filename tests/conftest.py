from __future__ import annotations

from pathlib import Path

import pytest

from digate.config import Settings
from digate.gateway import PromotionGateway


@pytest.fixture
def gateway(tmp_path: Path) -> PromotionGateway:
    return PromotionGateway(Settings(data_dir=tmp_path))
