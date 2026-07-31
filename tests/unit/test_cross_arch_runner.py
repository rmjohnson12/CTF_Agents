"""Emulated execution of foreign-architecture challenge binaries.

No test here starts a container: every subprocess call is intercepted, so the
suite stays offline and does not require a docker daemon.
"""
from __future__ import annotations

import subprocess

import pytest

from tools.common import cross_arch_runner
from tools.common.cross_arch_runner import CrossArchElfRunner


def _elf_bytes(machine: int = 0x3E, ei_class: int = 2, ei_data: int = 1) -> bytes:
    header = bytearray(b"\x00" * 20)
    header[0:4] = b"\x7fELF"
    header[4] = ei_class
    header[5] = ei_data
    header[6] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little" if ei_data == 1 else "big")
    return bytes(header) + b"\x00" * 44


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / "target"
    path.write_bytes(_elf_bytes())
    return str(path)


class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _patch_subprocess(monkeypatch, handler):
    """Route cross_arch_runner's subprocess.run through *handler*."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return handler(list(argv), kwargs)

    monkeypatch.setattr(cross_arch_runner.subprocess, "run", fake_run)
    return calls


def _daemon_up(argv, _kwargs):
    if argv[1] == "version":
        return _FakeProc(stdout="27.1.1\n")
    return _FakeProc(stdout=b"")


# ---------------------------------------------------------------------------
# Daemon probing
# ---------------------------------------------------------------------------

def test_missing_cli_reports_reason_without_running(monkeypatch):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: None)
    calls = _patch_subprocess(monkeypatch, lambda a, k: _FakeProc())

    ok, detail = CrossArchElfRunner().daemon_available()

    assert ok is False
    assert "not found on PATH" in detail
    assert calls == []


def test_stopped_daemon_reports_its_own_error(monkeypatch):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stderr="Cannot connect to the Docker daemon", returncode=1),
    )

    ok, detail = CrossArchElfRunner().daemon_available()

    assert ok is False
    assert "Cannot connect to the Docker daemon" in detail


def test_daemon_probe_is_cached(monkeypatch):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    calls = _patch_subprocess(monkeypatch, _daemon_up)
    runner = CrossArchElfRunner()

    runner.daemon_available()
    runner.daemon_available()
    runner.daemon_available()

    assert len([c for c in calls if c[0][1] == "version"]) == 1


def test_probe_timeout_does_not_propagate(monkeypatch):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")

    def timeout(argv, kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=8)

    _patch_subprocess(monkeypatch, timeout)

    ok, detail = CrossArchElfRunner().daemon_available()

    assert ok is False
    assert "timed out" in detail


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def test_run_builds_a_hardened_container_command(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    calls = _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stdout="27.1.1\n") if a[1] == "version"
        else _FakeProc(stdout=b"HTB{emulated}"),
    )

    result = CrossArchElfRunner().run(binary, payload=b"AAAA", timeout_s=15)

    assert result.ran is True
    assert "HTB{emulated}" in result.output

    argv = next(c[0] for c in calls if c[0][1] == "run")
    assert argv[argv.index("--platform") + 1] == "linux/amd64"
    assert argv[argv.index("--network") + 1] == "none"
    assert "--read-only" in argv
    assert "--rm" in argv
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--user") + 1] == "65534:65534"
    assert "--memory" in argv and "--pids-limit" in argv
    # The binary is mounted read-only, never copied in writable.
    assert any(arg.endswith(":ro") and "/target/" in arg for arg in argv)


def test_payload_is_piped_as_raw_bytes(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    payload = b"A" * 40 + b"\x77\x15\x40\x00\x00\x00\x00\x00"
    calls = _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stdout="27.1.1\n") if a[1] == "version" else _FakeProc(),
    )

    CrossArchElfRunner().run(binary, payload=payload)

    run_kwargs = next(c[1] for c in calls if c[0][1] == "run")
    assert run_kwargs["input"] == payload


def test_binary_output_that_is_not_utf8_does_not_raise(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stdout="27.1.1\n") if a[1] == "version"
        else _FakeProc(stdout=b"\xff\xfe\x00 HTB{binary_safe}"),
    )

    result = CrossArchElfRunner().run(binary)

    assert result.ran is True
    assert "HTB{binary_safe}" in result.output


def test_stopped_daemon_short_circuits_before_any_run(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    calls = _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stderr="Is the docker daemon running?", returncode=1),
    )

    result = CrossArchElfRunner().run(binary, payload=b"A")

    assert result.ran is False
    assert "docker daemon" in result.reason
    assert "Start Docker" in result.reason
    assert not [c for c in calls if c[0][1] == "run"]


def test_unmappable_architecture_is_refused_before_probing(monkeypatch, tmp_path):
    """MIPS has no docker platform in either byte order; say so, don't try."""
    path = tmp_path / "mips"
    path.write_bytes(_elf_bytes(machine=0x08, ei_data=2))
    calls = _patch_subprocess(monkeypatch, lambda a, k: _FakeProc())

    result = CrossArchElfRunner().run(str(path))

    assert result.ran is False
    assert "cannot emulate" in result.reason
    assert calls == []


def test_big_endian_s390_is_emulated_not_refused(monkeypatch, tmp_path):
    """linux/s390x is a real big-endian platform docker supports."""
    path = tmp_path / "s390"
    path.write_bytes(_elf_bytes(machine=0x16, ei_data=2))
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    calls = _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stdout="27.1.1\n") if a[1] == "version" else _FakeProc(),
    )

    result = CrossArchElfRunner().run(path.as_posix())

    assert result.ran is True
    argv = next(c[0] for c in calls if c[0][1] == "run")
    assert argv[argv.index("--platform") + 1] == "linux/s390x"


@pytest.mark.parametrize("code, stderr", [
    (125, b"no matching manifest for linux/amd64"),
    (126, b"exec /target/foo: permission denied"),
])
def test_docker_refusal_is_not_reported_as_a_target_crash(monkeypatch, binary, code, stderr):
    """125 = daemon rejected the request, 126 = it could not exec the target."""
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    _patch_subprocess(
        monkeypatch,
        lambda a, k: _FakeProc(stdout="27.1.1\n") if a[1] == "version"
        else _FakeProc(stderr=stderr, returncode=code),
    )

    result = CrossArchElfRunner().run(binary)

    assert result.ran is False
    assert "could not run the target" in result.reason


@pytest.mark.parametrize("mode", [0o644, 0o600, 0o700, 0o744])
def test_binary_is_made_loadable_by_the_container_uid(monkeypatch, tmp_path, mode):
    """Owner-only bits are useless to uid 65534, and the mount is read-only.

    0o700 is what the native path's own chmod produces, so the emulated
    fallback inherits a file it cannot load unless this repairs it.
    """
    path = tmp_path / "artifact"
    path.write_bytes(_elf_bytes())
    path.chmod(mode)
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    _patch_subprocess(monkeypatch, _daemon_up)

    result = CrossArchElfRunner().run(str(path))

    assert result.ran is True
    # Read as well as execute: the loader must read a dynamically linked ELF.
    assert path.stat().st_mode & 0o555 == 0o555


def test_cpu_quota_is_capped_like_the_generated_solver_sandbox(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    calls = _patch_subprocess(monkeypatch, _daemon_up)

    CrossArchElfRunner().run(binary)

    argv = next(c[0] for c in calls if c[0][1] == "run")
    assert argv[argv.index("--cpus") + 1] == "1.0"


def test_timeout_forces_container_removal(monkeypatch, binary):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")

    def handler(argv, kwargs):
        if argv[1] == "version":
            return _FakeProc(stdout="27.1.1\n")
        if argv[1] == "run":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=20)
        return _FakeProc()

    calls = _patch_subprocess(monkeypatch, handler)

    result = CrossArchElfRunner().run(binary, timeout_s=20)

    assert result.ran is False and result.timed_out is True
    assert any(c[0][1] == "rm" and "-f" in c[0] for c in calls)


def test_missing_binary_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(cross_arch_runner.shutil, "which", lambda _n: "/usr/bin/docker")
    _patch_subprocess(monkeypatch, _daemon_up)
    ghost = tmp_path / "ghost"
    ghost.write_bytes(_elf_bytes())
    path = str(ghost)
    ghost.unlink()

    result = CrossArchElfRunner().run(path)

    assert result.ran is False
    assert "not an ELF" in result.reason or "not found" in result.reason
