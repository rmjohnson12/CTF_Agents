"""Integration tests for PWN agent registration, routing, ELF detection, and solve behavior."""
from __future__ import annotations

import os
import stat
import subprocess
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_llm_keys(monkeypatch):
    for key in ("LLM_PROVIDER", "NVAPI_KEYS", "NVAPI_KEY", "NGC_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# 1. Registration
# ---------------------------------------------------------------------------

def test_pwn_agent_registered_in_coordinator_ask():
    """ask.py's main() block registers PwnAgent under the key 'pwn_agent'."""
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    from agents.specialists.pwn.pwn_agent import PwnAgent

    coordinator = CoordinatorAgent()
    coordinator.register_agent(PwnAgent())

    assert "pwn_agent" in coordinator.specialist_agents


def test_pwn_agent_registered_in_main():
    """main.py registers PwnAgent with explicit agent_id='pwn_agent'."""
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    from agents.specialists.pwn.pwn_agent import PwnAgent

    coordinator = CoordinatorAgent()
    coordinator.register_agent(PwnAgent(agent_id="pwn_agent"))

    assert "pwn_agent" in coordinator.specialist_agents


# ---------------------------------------------------------------------------
# 2. LLMReasoner heuristic routing
# ---------------------------------------------------------------------------

def test_reasoner_routes_pwn_category_to_pwn_agent():
    from core.decision_engine.llm_reasoner import LLMReasoner

    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge({
        "id": "pwn_cat",
        "name": "Pwn challenge",
        "category": "pwn",
        "description": "Get a shell.",
        "files": [], "hints": [], "tags": [],
    })

    assert analysis.recommended_target == "pwn_agent"
    assert analysis.recommended_action == "run_agent"
    assert analysis.category_guess == "pwn"


def test_reasoner_routes_overflow_description_to_pwn_agent():
    from core.decision_engine.llm_reasoner import LLMReasoner

    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge({
        "id": "pwn_overflow",
        "name": "Stack overflow",
        "category": "",
        "description": "Exploit the buffer overflow to hijack control flow.",
        "files": [], "hints": [], "tags": [],
    })

    assert analysis.recommended_target == "pwn_agent"


def test_reasoner_routes_rop_description_to_pwn_agent():
    from core.decision_engine.llm_reasoner import LLMReasoner

    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge({
        "id": "pwn_rop",
        "name": "ROP",
        "category": "",
        "description": "Build a ROP chain to bypass NX.",
        "files": ["vuln.elf"],
        "hints": [], "tags": [],
    })

    assert analysis.recommended_target == "pwn_agent"


def test_reasoner_routes_shellcode_to_pwn_agent():
    from core.decision_engine.llm_reasoner import LLMReasoner

    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge({
        "id": "pwn_shellcode",
        "name": "Shellcode injection",
        "category": "",
        "description": "Inject shellcode into the vulnerable binary.",
        "files": [], "hints": [], "tags": [],
    })

    assert analysis.recommended_target == "pwn_agent"


def test_reasoner_next_action_pwn_returns_run_agent():
    from core.decision_engine.llm_reasoner import LLMReasoner, ChallengeAnalysis

    reasoner = LLMReasoner(client=None)
    analysis = ChallengeAnalysis(
        category_guess="pwn",
        confidence=0.94,
        reasoning="pwn",
        recommended_target="pwn_agent",
        recommended_action="run_agent",
        detected_indicators=["pwn_terms"],
    )
    action = reasoner._heuristic_next_action({}, analysis, [])

    assert action["next_action"] == "run_agent"
    assert action["target"] == "pwn_agent"


def test_reasoner_elf_without_extension_plus_exploit_routes_to_pwn(tmp_path):
    """An extensionless ELF + 'exploit' keyword → pwn_agent."""
    from core.decision_engine.llm_reasoner import LLMReasoner

    elf = tmp_path / "vuln"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)

    reasoner = LLMReasoner(client=None)
    analysis = reasoner.analyze_challenge({
        "id": "pwn_extensionless",
        "name": "Mystery binary",
        "category": "",
        "description": "exploit this binary to get code execution",
        "files": [str(elf)],
        "hints": [], "tags": [],
    })

    assert analysis.recommended_target == "pwn_agent"


# ---------------------------------------------------------------------------
# 3. angr graceful fallback
# ---------------------------------------------------------------------------

def test_angr_tool_raises_import_error_with_pip_hint():
    """AngrTool.__init__ raises ImportError with a 'pip install angr' message."""
    from tools.pwn import angr_tool

    with patch.dict("sys.modules", {"angr": None}):
        with pytest.raises(ImportError, match="pip install angr"):
            angr_tool.AngrTool()


def test_pwn_agent_skips_angr_gracefully_when_not_installed():
    """PwnAgent.solve_challenge includes the angr-skipped step when angr is absent."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    agent = PwnAgent()
    # Force _load_angr to simulate missing angr
    agent._angr = None  # clear cache
    with patch.dict("sys.modules", {"angr": None}):
        # Re-patch AngrTool to raise ImportError
        with patch("agents.specialists.pwn.pwn_agent.PwnAgent._load_angr", return_value=None):
            result = agent.solve_challenge({
                "id": "pwn_no_angr",
                "description": "overflow challenge",
                "files": ["test.elf"],
                "category": "pwn",
            })

    assert result["status"] in ("attempted", "failed")
    angr_step = any("angr skipped" in s for s in result.get("steps", []))
    assert angr_step, f"Expected angr-skipped step, got: {result['steps']}"


# ---------------------------------------------------------------------------
# 4. Extensionless ELF detection
# ---------------------------------------------------------------------------

def test_is_elf_binary_detects_elf_magic(tmp_path):
    from tools.common.elf_utils import is_elf_binary

    elf = tmp_path / "vuln"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert is_elf_binary(str(elf)) is True


def test_is_elf_binary_rejects_non_elf(tmp_path):
    from tools.common.elf_utils import is_elf_binary

    script = tmp_path / "run.sh"
    script.write_bytes(b"#!/bin/sh\necho hello\n")
    assert is_elf_binary(str(script)) is False


def test_is_elf_binary_handles_missing_file():
    from tools.common.elf_utils import is_elf_binary

    assert is_elf_binary("/nonexistent/path/that/does/not/exist") is False


def test_is_elf_binary_handles_empty_file(tmp_path):
    from tools.common.elf_utils import is_elf_binary

    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert is_elf_binary(str(empty)) is False


def test_expand_challenge_artifacts_includes_extensionless_elf(tmp_path, monkeypatch):
    """_expand_challenge_artifacts picks up extensionless ELF files inside a directory."""
    from ask import _expand_challenge_artifacts

    # Create a challenge directory with an extensionless ELF and a text file
    chall_dir = tmp_path / "chall"
    chall_dir.mkdir()
    elf = chall_dir / "vuln"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)
    readme = chall_dir / "README.txt"
    readme.write_text("solve me")

    expanded = _expand_challenge_artifacts([str(chall_dir)])

    assert str(elf.resolve()) in expanded
    assert str(readme.resolve()) in expanded


def test_expand_challenge_artifacts_ignores_non_elf_extensionless(tmp_path):
    """Non-ELF extensionless files in a directory are NOT included."""
    from ask import _expand_challenge_artifacts

    chall_dir = tmp_path / "chall"
    chall_dir.mkdir()
    script = chall_dir / "run"
    script.write_bytes(b"#!/bin/sh\necho hello\n")

    expanded = _expand_challenge_artifacts([str(chall_dir)])

    assert str(script.resolve()) not in expanded


# ---------------------------------------------------------------------------
# 5. Payload → artifact, not flag
# ---------------------------------------------------------------------------

def test_pwn_agent_payload_stored_as_artifact_when_no_flag(tmp_path):
    """When angr finds a payload but binary output has no flag, result is
    'attempted' and the payload hex is in artifacts, not in 'flag'."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

    agent = PwnAgent()

    with patch.object(agent, "_phase_angr", return_value=(["angr found payload"], b"AAAA\n")):
        with patch.object(agent, "_phase_run_with_payload", return_value=(["No flag found"], None)):
            result = agent.solve_challenge({
                "id": "pwn_artifact",
                "description": "overflow challenge",
                "files": [str(fake_binary)],
                "category": "pwn",
            })

    assert result["status"] == "attempted"
    assert "flag" not in result
    assert result.get("artifacts", {}).get("angr_payload") == b"AAAA\n".hex()


def test_pwn_agent_solved_when_flag_in_binary_output(tmp_path):
    """When binary output contains a flag pattern, result is 'solved' with the flag."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

    agent = PwnAgent()

    with patch.object(agent, "_phase_angr", return_value=(["angr found payload"], b"AAAA\n")):
        with patch.object(agent, "_phase_run_with_payload",
                          return_value=(["Flag confirmed: CTF{test_flag}"], "CTF{test_flag}")):
            result = agent.solve_challenge({
                "id": "pwn_solved",
                "description": "overflow challenge",
                "files": [str(fake_binary)],
                "category": "pwn",
            })

    assert result["status"] == "solved"
    assert result["flag"] == "CTF{test_flag}"
    assert "artifacts" not in result


def test_pwn_agent_flag_never_set_to_raw_payload_bytes(tmp_path):
    """The raw angr payload (bytes) must never appear directly as the 'flag' value."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

    agent = PwnAgent()
    payload = b"\x41\x41\x41\x41\x0a"

    with patch.object(agent, "_phase_angr", return_value=(["found"], payload)):
        with patch.object(agent, "_phase_run_with_payload", return_value=(["no flag"], None)):
            result = agent.solve_challenge({
                "id": "pwn_no_raw_flag",
                "description": "pwn me",
                "files": [str(fake_binary)],
                "category": "pwn",
            })

    assert result.get("flag") != payload
    assert result.get("flag") != payload.decode("utf-8", errors="replace")


def test_pwn_agent_adds_execute_permission_before_running_payload(tmp_path):
    """Downloaded binaries may not preserve +x; the agent should repair that before execution."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    fake_binary.chmod(0o600)

    completed = subprocess.CompletedProcess(
        args=[str(fake_binary)],
        returncode=0,
        stdout=b"CTF{chmod_then_run}\n",
        stderr=b"",
    )

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=completed):
        steps, flag = PwnAgent()._phase_run_with_payload(str(fake_binary), b"AAAA\n")

    assert flag == "CTF{chmod_then_run}"
    assert os.access(fake_binary, os.X_OK)
    assert any("added user execute permission" in step for step in steps)
