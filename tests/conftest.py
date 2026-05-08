import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def disable_live_llm_keys(monkeypatch):
    """Keep tests deterministic even when developer shells have API keys set."""
    for key in (
        "LLM_PROVIDER",
        "NVAPI_KEYS",
        "NVAPI_KEY",
        "NGC_API_KEY",
        "NVIDIA_MODEL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
    ):
        monkeypatch.delenv(key, raising=False)
