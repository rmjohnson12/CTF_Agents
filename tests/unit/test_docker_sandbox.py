import os
import shutil
import subprocess

import pytest

from tools.common.docker_sandbox import DockerPythonSandbox, SandboxConfigError
from tools.common.python_tool import PythonTool
from tools.common.result import ToolResult


class _CapturingRunner:
    """Fake ToolRunner that records argv and returns a canned success result."""

    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout_s=None, cwd=None, env=None):
        self.calls.append(list(argv))
        return ToolResult(
            argv=list(argv),
            stdout="ok",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_s=0.01,
        )


@pytest.fixture
def force_docker(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_SANDBOX", "docker")
    monkeypatch.delenv("CTF_AGENTS_SANDBOX_EGRESS_PROXY", raising=False)


def _sandbox_with(runner, monkeypatch):
    sandbox = DockerPythonSandbox(runner=runner)
    # Pretend the docker CLI exists regardless of the host.
    monkeypatch.setattr(DockerPythonSandbox, "is_available", classmethod(lambda cls: True))
    return sandbox


def test_default_run_has_no_network_and_hard_limits(force_docker, monkeypatch, tmp_path):
    runner = _CapturingRunner()
    sandbox = _sandbox_with(runner, monkeypatch)
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))

    sandbox.run("print(1)", timeout_s=7)

    argv = runner.calls[0]
    assert argv[0] == "docker" and argv[1] == "run"
    assert "--rm" in argv
    # Default deny network.
    assert argv[argv.index("--network") + 1] == "none"
    # Hardening flags present.
    assert "--read-only" in argv
    assert ["--cap-drop", "ALL"] == argv[argv.index("--cap-drop"):argv.index("--cap-drop") + 2]
    assert "--security-opt" in argv and "no-new-privileges" in argv
    assert "--memory" in argv and "--pids-limit" in argv
    assert argv[-3:] == ["python", "/sandbox/solver.py"] or "/sandbox/solver.py" in argv


def test_artifacts_are_mounted_read_only_at_original_path(force_docker, monkeypatch, tmp_path):
    runner = _CapturingRunner()
    sandbox = _sandbox_with(runner, monkeypatch)
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))
    artifact = tmp_path / "cipher.bin"
    artifact.write_text("data")

    sandbox.run("print(1)", artifact_paths=[str(artifact)])

    argv = runner.calls[0]
    joined = " ".join(argv)
    assert f"{artifact.resolve()}:{artifact.resolve()}:ro" in joined


def test_network_requires_allowlist(force_docker, monkeypatch, tmp_path):
    runner = _CapturingRunner()
    sandbox = _sandbox_with(runner, monkeypatch)
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))

    with pytest.raises(SandboxConfigError, match="not yet supported"):
        sandbox.run("print(1)", allow_network=True, allowed_targets=[])


def test_network_fails_closed_without_egress_proxy(force_docker, monkeypatch, tmp_path):
    runner = _CapturingRunner()
    sandbox = _sandbox_with(runner, monkeypatch)
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))

    with pytest.raises(SandboxConfigError, match="not yet supported"):
        sandbox.run("print(1)", allow_network=True, allowed_targets=["example.com:443"])


def test_network_stays_disabled_even_when_legacy_proxy_variable_is_configured(force_docker, monkeypatch, tmp_path):
    runner = _CapturingRunner()
    sandbox = _sandbox_with(runner, monkeypatch)
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_EGRESS_PROXY", "http://127.0.0.1:8080")

    with pytest.raises(SandboxConfigError, match="network-policy sidecar"):
        sandbox.run("print(1)", allow_network=True, allowed_targets=["example.com:443"])
    assert runner.calls == []


def test_python_tool_reports_missing_docker_cli(force_docker, monkeypatch, tmp_path):
    monkeypatch.setattr(DockerPythonSandbox, "is_available", classmethod(lambda cls: False))
    tool = PythonTool()
    result = tool.run("print(1)")
    assert tool.execution_backend() == "docker"
    assert result.exit_code == 126
    assert "docker" in result.stderr.lower()


def test_config_error_surfaces_as_tool_result(force_docker, monkeypatch, tmp_path):
    monkeypatch.setattr(DockerPythonSandbox, "is_available", classmethod(lambda cls: True))
    tool = PythonTool(sandbox=DockerPythonSandbox(runner=_CapturingRunner()))
    monkeypatch.setenv("CTF_AGENTS_SANDBOX_TMPDIR", str(tmp_path))
    result = tool.run("print(1)", allow_network=True, allowed_targets=[])
    assert result.exit_code == 126
    assert "not yet supported" in result.stderr.lower()


def _docker_live() -> bool:
    docker = shutil.which(os.getenv("CTF_AGENTS_DOCKER_BIN") or "docker")
    if not docker:
        return False
    try:
        return subprocess.run(
            [docker, "info"], capture_output=True, timeout=5, check=False
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


DOCKER_LIVE = _docker_live()


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker CLI not available")
def test_live_sandbox_blocks_network_and_reads_artifact(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_AGENTS_SANDBOX", "docker")
    artifact = tmp_path / "flag.txt"
    artifact.write_text("HTB{sandbox_ok}")
    unrelated = tmp_path / "operator-secret.txt"
    unrelated.write_text("DO_NOT_READ")
    tool = PythonTool()
    script = (
        f"print(open({str(artifact.resolve())!r}).read().strip())\n"
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=2); print('NET_OPEN')\n"
        "except Exception:\n"
        "    print('NET_BLOCKED')\n"
        f"try:\n    print(open({str(unrelated.resolve())!r}).read())\n"
        "except Exception:\n    print('SECRET_BLOCKED')\n"
        f"try:\n    open({str(artifact.resolve())!r}, 'w').write('changed')\n"
        "except Exception:\n    print('WRITE_BLOCKED')\n"
        "try:\n    open('/owned.txt', 'w').write('changed')\n"
        "except Exception:\n    print('ROOTFS_BLOCKED')\n"
    )
    result = tool.run(script, artifact_paths=[str(artifact)], timeout_s=90)
    if result.exit_code != 0 and "platform" in result.stderr.lower():
        pytest.skip("docker image/platform unavailable in this environment")
    assert "HTB{sandbox_ok}" in result.stdout
    assert "NET_BLOCKED" in result.stdout
    assert "NET_OPEN" not in result.stdout
    assert "SECRET_BLOCKED" in result.stdout
    assert "DO_NOT_READ" not in result.stdout
    assert "WRITE_BLOCKED" in result.stdout
    assert "ROOTFS_BLOCKED" in result.stdout
    assert artifact.read_text() == "HTB{sandbox_ok}"


@pytest.mark.skipif(not DOCKER_LIVE, reason="docker daemon not available")
def test_live_timeout_force_removes_container(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_AGENTS_SANDBOX", "docker")
    tool = PythonTool()

    result = tool.run("while True: pass", timeout_s=2)

    assert result.timed_out is True
    name = result.argv[result.argv.index("--name") + 1]
    docker = os.getenv("CTF_AGENTS_DOCKER_BIN") or "docker"
    remaining = subprocess.run(
        [docker, "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{{{.Names}}}}"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert remaining.stdout.strip() == ""
