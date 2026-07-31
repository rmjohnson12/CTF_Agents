"""The pwn agent must not retry payloads it has no way to execute.

Before this, a Linux ELF on a macOS host produced one
``[Errno 8] Exec format error`` per payload — twenty-odd identical failures that
read like a broken exploit rather than a host that cannot run the binary.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from agents.specialists.pwn.pwn_agent import PwnAgent
from tools.common import elf_utils
from tools.common.cross_arch_runner import CrossArchRunResult


@pytest.fixture(autouse=True)
def no_llm_keys(monkeypatch):
    for key in ("LLM_PROVIDER", "NVAPI_KEYS", "NVAPI_KEY", "NGC_API_KEY",
                "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY",
                "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def _elf_bytes(machine: int = 0x3E) -> bytes:
    header = bytearray(b"\x00" * 20)
    header[0:4] = b"\x7fELF"
    header[4] = 2   # 64-bit
    header[5] = 1   # little-endian
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header) + b"\x00" * 44


@pytest.fixture
def linux_binary(tmp_path):
    path = tmp_path / "ring_the_bell"
    path.write_bytes(_elf_bytes())
    return str(path)


@pytest.fixture
def on_macos(monkeypatch):
    """Pin the host identity so the suite behaves the same on any machine."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "arm64")


class _StubRunner:
    """Stands in for CrossArchElfRunner without touching a container runtime."""

    def __init__(self, available=True, results=None):
        self._available = available
        self._results = list(results or [])
        self.run_calls = 0
        self.probe_calls = 0

    def daemon_available(self):
        self.probe_calls += 1
        if self._available:
            return True, "docker daemon 27.1.1"
        return False, "Cannot connect to the Docker daemon. Is the docker daemon running?"

    def run(self, binary, payload=b"", timeout_s=20):
        self.run_calls += 1
        if self._results:
            return self._results.pop(0)
        return CrossArchRunResult(True, output="no flag here")


# ---------------------------------------------------------------------------
# Execution is refused, not retried
# ---------------------------------------------------------------------------

def test_unrunnable_binary_reports_the_host_reason(on_macos, linux_binary):
    agent = PwnAgent(elf_runner=_StubRunner(available=False))

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run") as run:
        steps, flag = agent._phase_run_with_payload(linux_binary, b"A" * 40)

    assert flag is None
    assert run.call_count == 0, "must not exec a binary the host cannot run"
    joined = " ".join(steps)
    assert "Local execution unavailable" in joined
    assert "Darwin" in joined and "x86-64" in joined
    assert "docker daemon" in joined


def test_host_and_runtime_are_probed_once_across_many_payloads(on_macos, linux_binary):
    runner = _StubRunner(available=False)
    agent = PwnAgent(elf_runner=runner)

    for _ in range(5):
        agent._phase_run_with_payload(linux_binary, b"A" * 40)

    assert runner.probe_calls == 1


def test_ret2win_ladder_stops_instead_of_burning_every_offset(on_macos, linux_binary):
    agent = PwnAgent(elf_runner=_StubRunner(available=False))
    challenge = {"id": "ring_the_bell", "files": [linux_binary]}

    with patch.object(PwnAgent, "_is_pie", return_value=False), \
         patch.object(PwnAgent, "_find_win_addr", return_value=0x401577), \
         patch("agents.specialists.pwn.pwn_agent.subprocess.run") as run:
        steps, flag = agent._phase_ret2win(linux_binary, challenge)

    assert flag is None
    assert run.call_count == 0
    assert not [s for s in steps if s.startswith("Trying ret2win")], (
        "no payload should be attempted when none of them can be delivered"
    )
    reason = " ".join(steps)
    assert "cannot deliver a payload" in reason
    assert "no remote target" in reason


def test_ladder_still_runs_when_a_remote_target_exists(on_macos, linux_binary):
    """Local execution being impossible must not disable remote delivery."""
    agent = PwnAgent(elf_runner=_StubRunner(available=False))
    challenge = {
        "id": "ring_the_bell",
        "files": [linux_binary],
        "connection_info": "94.237.1.1:31337",
    }

    with patch.object(PwnAgent, "_is_pie", return_value=False), \
         patch.object(PwnAgent, "_find_win_addr", return_value=0x401577), \
         patch.object(PwnAgent, "_find_ret_gadget", return_value=None), \
         patch.object(PwnAgent, "_send_payload_remote", return_value=([], None)) as remote:
        steps, _ = agent._phase_ret2win(linux_binary, challenge)

    assert remote.call_count > 0
    assert [s for s in steps if s.startswith("Trying ret2win")]


def test_core_dump_offset_discovery_is_skipped_without_native_execution(on_macos, linux_binary):
    agent = PwnAgent(elf_runner=_StubRunner(available=True))
    steps = []

    offset = agent._find_overflow_offset(linux_binary, steps)

    assert offset is None
    assert any("native execution" in s for s in steps)


# ---------------------------------------------------------------------------
# Emulated execution
# ---------------------------------------------------------------------------

def test_emulated_run_recovers_a_flag(on_macos, linux_binary):
    runner = _StubRunner(results=[CrossArchRunResult(True, output="Bell rung! HTB{emulated_win}")])
    agent = PwnAgent(elf_runner=runner)

    steps, flag = agent._phase_run_with_payload(linux_binary, b"A" * 40)

    assert flag == "HTB{emulated_win}"
    assert runner.run_calls == 1
    assert any("under emulation" in s for s in steps)


def test_a_timeout_does_not_disable_the_route_for_later_payloads(on_macos, linux_binary):
    """A hung payload says nothing about whether the host can run the binary."""
    runner = _StubRunner(results=[
        CrossArchRunResult(False, reason="emulated execution timed out after 20s", timed_out=True),
        CrossArchRunResult(True, output="HTB{second_payload_won}"),
    ])
    agent = PwnAgent(elf_runner=runner)

    first_steps, first_flag = agent._phase_run_with_payload(linux_binary, b"A" * 40)
    _, second_flag = agent._phase_run_with_payload(linux_binary, b"A" * 56)

    assert first_flag is None
    assert any("timed out" in s for s in first_steps)
    assert second_flag == "HTB{second_payload_won}", "a timeout must not close the route"
    assert runner.run_calls == 2


def test_emulation_failure_downgrades_so_the_ladder_stops(on_macos, linux_binary):
    runner = _StubRunner(results=[CrossArchRunResult(False, reason="no matching manifest")])
    agent = PwnAgent(elf_runner=runner)

    first_steps, _ = agent._phase_run_with_payload(linux_binary, b"A" * 40)
    second_steps, _ = agent._phase_run_with_payload(linux_binary, b"A" * 56)

    assert runner.run_calls == 1, "a failed container start must not be retried per payload"
    assert any("Emulated execution unavailable" in s for s in first_steps)
    assert any("Local execution unavailable" in s for s in second_steps)


# ---------------------------------------------------------------------------
# A wrong "native" guess costs one attempt, not a whole ladder
# ---------------------------------------------------------------------------

def test_enoexec_on_a_host_we_thought_was_native_downgrades_once(monkeypatch, linux_binary):
    """The header check defers to a real exec when it has no evidence; ENOEXEC is that evidence."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "sparc64")  # unlisted host
    runner = _StubRunner(available=False)
    agent = PwnAgent(elf_runner=runner)

    boom = OSError(8, "Exec format error")
    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", side_effect=boom) as run:
        first, _ = agent._phase_run_with_payload(linux_binary, b"A" * 40)
        second, _ = agent._phase_run_with_payload(linux_binary, b"A" * 56)

    assert run.call_count == 1, "the second payload must not repeat a proven-impossible exec"
    assert any("Host cannot load this binary" in s for s in first)
    assert any("Local execution unavailable" in s for s in second)


def test_enoexec_switches_to_emulation_when_a_runtime_exists(monkeypatch, linux_binary):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "sparc64")
    runner = _StubRunner(
        available=True,
        results=[CrossArchRunResult(True, output="HTB{fell_back_to_emulation}")],
    )
    agent = PwnAgent(elf_runner=runner)

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=OSError(8, "Exec format error")):
        agent._phase_run_with_payload(linux_binary, b"A" * 40)
        steps, flag = agent._phase_run_with_payload(linux_binary, b"A" * 56)

    assert flag == "HTB{fell_back_to_emulation}"
    assert runner.run_calls == 1


def test_a_genuinely_missing_binary_is_not_blamed_on_the_host(monkeypatch, tmp_path):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")
    agent = PwnAgent(elf_runner=_StubRunner())
    missing = str(tmp_path / "not_here")

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=FileNotFoundError(2, "No such file or directory")):
        steps, _ = agent._phase_run_with_payload(missing, b"A")

    assert any("Binary not found" in s for s in steps)
    assert not any("Host cannot load" in s for s in steps)


def test_missing_32bit_loader_is_treated_as_an_execution_failure(monkeypatch, tmp_path):
    """A present binary whose interpreter is absent raises ENOENT, not ENOEXEC."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")
    binary = tmp_path / "thirtytwo"
    binary.write_bytes(_elf_bytes(machine=0x03))
    agent = PwnAgent(elf_runner=_StubRunner(available=False))

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run",
               side_effect=FileNotFoundError(2, "No such file or directory")) as run:
        agent._phase_run_with_payload(str(binary), b"A")
        agent._phase_run_with_payload(str(binary), b"B")

    assert run.call_count == 1


# ---------------------------------------------------------------------------
# Native hosts are unaffected
# ---------------------------------------------------------------------------

def test_native_linux_host_still_executes_directly(monkeypatch, linux_binary):
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Linux")
    monkeypatch.setattr(elf_utils.platform, "machine", lambda: "x86_64")
    runner = _StubRunner()
    agent = PwnAgent(elf_runner=runner)

    class _Proc:
        stdout = b"HTB{native_win}"
        stderr = b""

    with patch("agents.specialists.pwn.pwn_agent.subprocess.run", return_value=_Proc()) as run:
        steps, flag = agent._phase_run_with_payload(linux_binary, b"A" * 40)

    assert flag == "HTB{native_win}"
    assert run.call_count == 1
    assert runner.run_calls == 0
    assert any("angr payload" in s for s in steps)


def test_non_elf_artifact_keeps_the_original_native_path(monkeypatch, tmp_path):
    """The zero-filled ELF stub used by older tests must not change behavior."""
    monkeypatch.setattr(elf_utils.platform, "system", lambda: "Darwin")
    stub = tmp_path / "stub"
    stub.write_bytes(b"\x7fELF" + b"\x00" * 60)
    agent = PwnAgent(elf_runner=_StubRunner(available=False))

    mode, _ = agent._execution_mode(str(stub))

    assert mode == "native"
