"""Shared pytest fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).parent.parent / "examples"
