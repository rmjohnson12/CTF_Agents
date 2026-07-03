"""Fixtures for HTB integration unit tests. Fakes live in ``htb_fakes.py``."""
import pytest

from integrations.hackthebox.config import HTBConfig


@pytest.fixture
def config() -> HTBConfig:
    return HTBConfig()
