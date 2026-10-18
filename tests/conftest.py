from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from .support import FixtureSite, write_data


@pytest.fixture
def site() -> Iterator[FixtureSite]:
    s = FixtureSite()
    s.start()
    yield s
    s.stop()


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    return write_data(tmp_path / "data")
