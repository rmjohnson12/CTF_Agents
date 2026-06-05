"""Integration tests for PWN agent registration, routing, ELF detection, and solve behavior."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import types
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_llm_keys(monkeypatch):
    for key in ("LLM_PROVIDER", "NVAPI_KEYS", "NVAPI_KEY", "NGC_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
                "GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI",
                "GOOGLE_GENAI_USE_ENTERPRISE", "GOOGLE_CLOUD_PROJECT",
                "GOOGLE_PROJECT_ID"):
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

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=completed) as mock_run:
        steps, flag = PwnAgent()._phase_run_with_payload(str(fake_binary), b"AAAA\n")

    assert flag == "CTF{chmod_then_run}"
    assert os.access(fake_binary, os.X_OK)
    assert any("added user execute permission" in step for step in steps)
    assert "env" in mock_run.call_args.kwargs
    assert "OPENAI_API_KEY" not in mock_run.call_args.kwargs["env"]


# ---------------------------------------------------------------------------
# 6. _find_win_addr
# ---------------------------------------------------------------------------

def test_find_win_addr_finds_function_via_nm():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    nm_out = "0000000000401234 T win\n0000000000401200 T main\n"
    ok = subprocess.CompletedProcess([], returncode=0, stdout=nm_out, stderr="")

    steps = []
    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=ok):
        addr = PwnAgent()._find_win_addr("vuln", steps)

    assert addr == 0x401234
    assert any("0x401234" in s for s in steps)


def test_find_win_addr_falls_back_to_objdump():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    nm_fail = subprocess.CompletedProcess([], returncode=1, stdout="", stderr="")
    objdump_out = "0000000000401234 g     F .text\t0000000000000023 win\n"
    objdump_ok = subprocess.CompletedProcess([], returncode=0, stdout=objdump_out, stderr="")

    steps = []
    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=[nm_fail, objdump_ok]):
        addr = PwnAgent()._find_win_addr("vuln", steps)

    assert addr == 0x401234


def test_find_win_addr_returns_none_when_no_win_function():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    no_win = subprocess.CompletedProcess(
        [], returncode=0, stdout="0000000000401200 T main\n", stderr=""
    )

    steps = []
    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=no_win):
        addr = PwnAgent()._find_win_addr("vuln", steps)

    assert addr is None


def test_find_win_addr_matches_flag_and_shell_functions():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    nm_out = "0000000000401100 T main\n0000000000401300 T get_shell\n"
    ok = subprocess.CompletedProcess([], returncode=0, stdout=nm_out, stderr="")

    steps = []
    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=ok):
        addr = PwnAgent()._find_win_addr("vuln", steps)

    assert addr == 0x401300


# ---------------------------------------------------------------------------
# 7. _is_pie
# ---------------------------------------------------------------------------

def test_is_pie_detects_dyn_type():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    out = "  Type:                              DYN (Position-Independent Executable file)\n"
    ok = subprocess.CompletedProcess([], returncode=0, stdout=out, stderr="")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=ok):
        assert PwnAgent()._is_pie("vuln") is True


def test_is_pie_returns_false_for_exec_type():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    out = "  Type:                              EXEC (Executable file)\n"
    ok = subprocess.CompletedProcess([], returncode=0, stdout=out, stderr="")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=ok):
        assert PwnAgent()._is_pie("vuln") is False


def test_is_pie_returns_false_on_readelf_error():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=FileNotFoundError("readelf not found")):
        assert PwnAgent()._is_pie("vuln") is False


# ---------------------------------------------------------------------------
# 8. _find_ret_gadget
# ---------------------------------------------------------------------------

def test_find_ret_gadget_parses_ropgadget_output():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    out = (
        "Gadgets information\n"
        "============================================================\n"
        "0x0000000000401016 : ret\n"
        "\nUnique gadgets found: 1\n"
    )
    ok = subprocess.CompletedProcess([], returncode=0, stdout=out, stderr="")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=ok):
        addr = PwnAgent()._find_ret_gadget("vuln")

    assert addr == 0x401016


def test_find_ret_gadget_falls_back_to_objdump():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    # ROPgadget returns nothing useful
    ropgadget_empty = subprocess.CompletedProcess([], returncode=0, stdout="", stderr="")
    objdump_out = "  401016:\tc3                   \tret\n"
    objdump_ok = subprocess.CompletedProcess([], returncode=0, stdout=objdump_out, stderr="")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=[ropgadget_empty, objdump_ok]):
        addr = PwnAgent()._find_ret_gadget("vuln")

    assert addr == 0x401016


def test_find_ret_gadget_returns_none_when_both_fail():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    no_gadget = subprocess.CompletedProcess([], returncode=0, stdout="", stderr="")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=no_gadget):
        addr = PwnAgent()._find_ret_gadget("vuln")

    assert addr is None


# ---------------------------------------------------------------------------
# 9. _send_payload_remote
# ---------------------------------------------------------------------------

class _FakePwnRemote:
    def __init__(self, *args, **kwargs):
        self.sent = None

    def recvrepeat(self, timeout=2):
        return b"Enter input: "

    def sendline(self, data):
        self.sent = data

    def recvall(self, timeout=5):
        return b"Congratulations! HTB{ret2win_remote_works}\n"

    def close(self):
        pass


def _fake_pwn_module(remote_cls=_FakePwnRemote):
    ctx = types.SimpleNamespace(log_level="error", arch="amd64")
    return types.SimpleNamespace(context=ctx, remote=remote_cls)


def test_send_payload_remote_extracts_flag(monkeypatch):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    monkeypatch.setitem(sys.modules, "pwn", _fake_pwn_module())

    steps, flag = PwnAgent()._send_payload_remote("1.2.3.4:4444", b"A" * 40 + b"\x34\x12\x40\x00\x00\x00\x00\x00")

    assert flag == "HTB{ret2win_remote_works}"
    assert any("1.2.3.4" in s for s in steps)


def test_send_payload_remote_records_banner(monkeypatch):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    monkeypatch.setitem(sys.modules, "pwn", _fake_pwn_module())

    steps, _ = PwnAgent()._send_payload_remote("1.2.3.4:4444", b"payload")

    assert any("Enter input" in s for s in steps)


def test_send_payload_remote_bad_connection_info():
    from agents.specialists.pwn.pwn_agent import PwnAgent

    steps, flag = PwnAgent()._send_payload_remote("not_a_valid_addr", b"payload")

    assert flag is None
    assert any("Could not parse" in s for s in steps)


def test_send_payload_remote_handles_missing_pwntools(monkeypatch):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    monkeypatch.setitem(sys.modules, "pwn", None)

    steps, flag = PwnAgent()._send_payload_remote("1.2.3.4:4444", b"payload")

    assert flag is None
    assert any("pwntools not installed" in s for s in steps)


def test_send_payload_remote_handles_connection_error(monkeypatch):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    class _ErrorRemote:
        def __init__(self, *a, **kw):
            raise ConnectionRefusedError("refused")

    monkeypatch.setitem(sys.modules, "pwn", _fake_pwn_module(remote_cls=_ErrorRemote))

    steps, flag = PwnAgent()._send_payload_remote("1.2.3.4:4444", b"payload")

    assert flag is None
    assert any("failed" in s.lower() for s in steps)


# ---------------------------------------------------------------------------
# 10. _find_overflow_offset
# ---------------------------------------------------------------------------

def test_find_overflow_offset_returns_none_when_pwntools_missing(monkeypatch):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    monkeypatch.setitem(sys.modules, "pwn", None)

    steps = []
    result = PwnAgent()._find_overflow_offset("vuln", steps)

    assert result is None
    assert any("pwntools not installed" in s for s in steps)


# ---------------------------------------------------------------------------
# 11. _phase_ret2win
# ---------------------------------------------------------------------------

def test_phase_ret2win_skips_pie_binary(tmp_path):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_is_pie", return_value=True):
        steps, flag = agent._phase_ret2win(str(fake_binary), {"id": "t"})

    assert flag is None
    assert any("PIE" in s for s in steps)


def test_phase_ret2win_skips_when_no_win_function(tmp_path):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_is_pie", return_value=False):
        with patch.object(agent, "_find_win_addr", return_value=None):
            steps, flag = agent._phase_ret2win(str(fake_binary), {"id": "t"})

    assert flag is None
    assert any("no win" in s.lower() for s in steps)


def test_phase_ret2win_solves_locally(tmp_path):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_is_pie", return_value=False):
        with patch.object(agent, "_find_win_addr", return_value=0x401234):
            with patch.object(agent, "_find_overflow_offset", return_value=40):
                with patch.object(agent, "_find_ret_gadget", return_value=None):
                    with patch.object(agent, "_phase_run_with_payload",
                                      return_value=(["flag!"], "HTB{local_ret2win}")):
                        steps, flag = agent._phase_ret2win(
                            str(fake_binary), {"id": "t"}
                        )

    assert flag == "HTB{local_ret2win}"


def test_phase_ret2win_tries_remote_when_local_fails(tmp_path):
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_is_pie", return_value=False):
        with patch.object(agent, "_find_win_addr", return_value=0x401234):
            with patch.object(agent, "_find_overflow_offset", return_value=40):
                with patch.object(agent, "_find_ret_gadget", return_value=None):
                    with patch.object(agent, "_phase_run_with_payload",
                                      return_value=(["no flag"], None)):
                        with patch.object(agent, "_send_payload_remote",
                                          return_value=(["remote flag"], "HTB{remote_ret2win}")):
                            steps, flag = agent._phase_ret2win(
                                str(fake_binary),
                                {"id": "t", "connection_info": "1.2.3.4:1337"},
                            )

    assert flag == "HTB{remote_ret2win}"


def test_phase_ret2win_uses_ret_gadget_for_alignment(tmp_path):
    """When a ret gadget is found, it should appear in the payload sent to run_with_payload."""
    import struct
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    received_payloads = []

    def capture_payload(binary, payload):
        received_payloads.append(payload)
        if struct.pack("<Q", 0x401016) in payload:
            return (["flag!"], "HTB{aligned}")
        return (["no flag"], None)

    with patch.object(agent, "_is_pie", return_value=False):
        with patch.object(agent, "_find_win_addr", return_value=0x401234):
            with patch.object(agent, "_find_overflow_offset", return_value=40):
                with patch.object(agent, "_find_ret_gadget", return_value=0x401016):
                    with patch.object(agent, "_phase_run_with_payload",
                                      side_effect=capture_payload):
                        steps, flag = agent._phase_ret2win(
                            str(fake_binary), {"id": "t"}
                        )

    assert flag == "HTB{aligned}"
    # First payload tried must contain the ret gadget address
    assert struct.pack("<Q", 0x401016) in received_payloads[0]


def test_phase_ret2win_brute_forces_common_offsets(tmp_path):
    """When overflow offset is unknown, ret2win walks common offsets until one works."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    tried_offsets = []

    def track_offset(binary, offset, win_addr, conn_info):
        tried_offsets.append(offset)
        if offset == 88:
            return (["found"], "HTB{brute_offset_88}")
        return ([], None)

    with patch.object(agent, "_is_pie", return_value=False):
        with patch.object(agent, "_find_win_addr", return_value=0x401234):
            with patch.object(agent, "_find_overflow_offset", return_value=None):
                with patch.object(agent, "_try_ret2win_at_offset", side_effect=track_offset):
                    steps, flag = agent._phase_ret2win(
                        str(fake_binary), {"id": "t"}
                    )

    assert flag == "HTB{brute_offset_88}"
    assert tried_offsets[0] == 40    # starts at smallest common offset
    assert 88 in tried_offsets
    assert 104 not in tried_offsets  # stops as soon as one works


# ---------------------------------------------------------------------------
# 12. Phase 3c: angr payload → remote delivery
# ---------------------------------------------------------------------------

def test_solve_challenge_sends_angr_payload_to_remote_when_local_fails(tmp_path):
    """Phase 3c: angr finds payload, local run yields nothing, remote delivers the flag."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_phase_checksec", return_value=[]):
        with patch.object(agent, "_phase_ghidra", return_value=([], [])):
            with patch.object(agent, "_phase_angr",
                              return_value=(["payload found"], b"AAAA\n")):
                with patch.object(agent, "_phase_run_with_payload",
                                  return_value=(["no flag locally"], None)):
                    with patch.object(agent, "_send_payload_remote",
                                      return_value=(["remote flag"], "HTB{angr_remote}")):
                        result = agent.solve_challenge({
                            "id": "angr_remote_test",
                            "description": "overflow",
                            "files": [str(fake_binary)],
                            "category": "pwn",
                            "connection_info": "1.2.3.4:1337",
                        })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{angr_remote}"


def test_solve_challenge_skips_remote_send_when_no_connection_info(tmp_path):
    """Phase 3c is skipped when challenge has no connection_info."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    send_calls = []

    with patch.object(agent, "_phase_checksec", return_value=[]):
        with patch.object(agent, "_phase_ghidra", return_value=([], [])):
            with patch.object(agent, "_phase_angr",
                              return_value=(["payload"], b"AAAA\n")):
                with patch.object(agent, "_phase_run_with_payload",
                                  return_value=(["no flag"], None)):
                    with patch.object(agent, "_send_payload_remote",
                                      side_effect=lambda *a: send_calls.append(a) or ([], None)):
                        result = agent.solve_challenge({
                            "id": "no_conn_test",
                            "description": "overflow",
                            "files": [str(fake_binary)],
                            "category": "pwn",
                        })

    assert len(send_calls) == 0
    assert result["status"] == "attempted"
    assert result.get("artifacts", {}).get("angr_payload") == b"AAAA\n".hex()


def test_solve_challenge_ret2win_runs_after_angr_fails(tmp_path):
    """Phase 4 (ret2win) is attempted when angr finds no payload."""
    from agents.specialists.pwn.pwn_agent import PwnAgent

    fake_binary = tmp_path / "vuln.elf"
    fake_binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent()

    with patch.object(agent, "_phase_checksec", return_value=[]):
        with patch.object(agent, "_phase_ghidra", return_value=([], [])):
            with patch.object(agent, "_phase_angr", return_value=(["no symbols"], None)):
                with patch.object(agent, "_phase_ret2win",
                                  return_value=(["ret2win solved"], "HTB{ret2win}")):
                    result = agent.solve_challenge({
                        "id": "ret2win_test",
                        "description": "overflow",
                        "files": [str(fake_binary)],
                        "category": "pwn",
                    })

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{ret2win}"
