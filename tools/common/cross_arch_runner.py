"""Run a foreign-architecture Linux ELF inside a locked-down container.

A Linux challenge binary cannot be exec'd on a macOS host, and an x86-64 binary
cannot be exec'd on an arm64 host. Both failures surface as
``[Errno 8] Exec format error``, so an exploit ladder that retries on failure
will burn its whole budget on attempts that were never going to run.

This runner is the emulation escape hatch. It mirrors the safety posture of
:mod:`tools.common.docker_sandbox` — no network, read-only root, dropped
capabilities, non-root uid, hard resource limits, strict timeout — but executes
the *challenge* binary under ``--platform`` rather than a generated Python
script. Docker Desktop and podman supply the qemu-user binfmt handlers that make
the cross-architecture case work; when they cannot, the caller gets an explicit
reason instead of a retry loop. Execution is default-deny behind
``CTF_AGENTS_ALLOW_DOCKER=1``, and only a temporary copy of the artifact is
permission-adjusted and mounted.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple

from core.utils.security import minimal_subprocess_env
from tools.common.elf_utils import elf_info

logger = logging.getLogger(__name__)

_DEFAULT_IMAGE = "debian:bookworm-slim"
_DEFAULT_MEMORY = "256m"
_DEFAULT_CPUS = "1.0"
_DEFAULT_PIDS = "128"
_DEFAULT_TMPFS_SIZE = "64m"
_RUNNER_UID_GID = "65534:65534"  # nobody:nogroup
_DAEMON_PROBE_TIMEOUT_S = 8
_MAX_CAPTURE_BYTES = 200_000


class CrossArchRunResult:
    """Outcome of one emulated execution.

    ``output`` is the merged stdout/stderr as text; ``reason`` explains why the
    run could not happen when ``ran`` is False.
    """

    def __init__(
        self,
        ran: bool,
        output: str = "",
        reason: str = "",
        timed_out: bool = False,
        exit_code: Optional[int] = None,
    ) -> None:
        self.ran = ran
        self.output = output
        self.reason = reason
        self.timed_out = timed_out
        self.exit_code = exit_code


def docker_bin() -> str:
    return os.getenv("CTF_AGENTS_DOCKER_BIN") or "docker"


def image() -> str:
    return os.getenv("CTF_AGENTS_ELF_RUNNER_IMAGE") or _DEFAULT_IMAGE


def docker_execution_enabled() -> bool:
    """Return whether the operator explicitly allowed local Docker runs."""
    return os.getenv("CTF_AGENTS_ALLOW_DOCKER") == "1"


class CrossArchElfRunner:
    """Execute a foreign ELF through Docker's binfmt/qemu emulation."""

    def __init__(self) -> None:
        self._daemon_state: Optional[Tuple[bool, str]] = None

    # ------------------------------------------------------------------
    @staticmethod
    def cli_available() -> bool:
        """True if a docker CLI is on PATH. Says nothing about the daemon."""
        return shutil.which(docker_bin()) is not None

    def daemon_available(self) -> Tuple[bool, str]:
        """Probe the daemon once per instance and cache the verdict.

        The CLI being installed is not enough: on a developer laptop Docker
        Desktop is frequently stopped, and every `docker run` then blocks for
        its own connect timeout before failing. One bounded probe up front keeps
        a dead daemon from multiplying across an exploit ladder.
        """
        if not docker_execution_enabled():
            return (
                False,
                "Docker execution is disabled; set CTF_AGENTS_ALLOW_DOCKER=1 "
                "for an authorized local challenge run",
            )

        if self._daemon_state is not None:
            return self._daemon_state

        if not self.cli_available():
            self._daemon_state = (False, f"'{docker_bin()}' CLI not found on PATH")
            return self._daemon_state

        try:
            proc = subprocess.run(
                [docker_bin(), "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                env=minimal_subprocess_env(),
                timeout=_DAEMON_PROBE_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            self._daemon_state = (False, "docker daemon probe timed out")
            return self._daemon_state
        except OSError as exc:
            self._daemon_state = (False, f"docker probe failed: {exc}")
            return self._daemon_state

        if proc.returncode == 0 and proc.stdout.strip():
            self._daemon_state = (True, f"docker daemon {proc.stdout.strip()}")
        else:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            self._daemon_state = (
                False,
                detail[0][:200] if detail else "docker daemon is not responding",
            )
        return self._daemon_state

    # ------------------------------------------------------------------
    def run(
        self,
        binary: str,
        payload: bytes = b"",
        timeout_s: int = 20,
    ) -> CrossArchRunResult:
        """Run *binary* with *payload* on stdin inside an ephemeral container."""
        info = elf_info(binary)
        if info is None:
            return CrossArchRunResult(False, reason=f"{binary} is not an ELF binary")
        if info.docker_platform is None:
            return CrossArchRunResult(
                False,
                reason=(
                    f"no Docker platform maps to {info.machine_name} "
                    f"({info.endian}-endian); cannot emulate"
                ),
            )

        ok, detail = self.daemon_available()
        if not ok:
            return CrossArchRunResult(
                False,
                reason=(
                    f"cannot emulate {info.machine_name} Linux binary: {detail}. "
                    "Start Docker (or set CTF_AGENTS_DOCKER_BIN to a compatible "
                    "runtime) to enable local execution of foreign binaries."
                ),
            )

        host = Path(binary).resolve()
        if not host.is_file():
            return CrossArchRunResult(False, reason=f"binary not found: {binary}")

        staging_dir, staged, stage_error = self._stage_binary(host)
        if stage_error:
            return CrossArchRunResult(False, reason=stage_error)
        assert staging_dir is not None and staged is not None

        container_name = f"ctf-elf-{uuid.uuid4().hex[:12]}"
        guest_path = "/target/challenge"
        argv = [
            docker_bin(), "run", "--rm", "-i",
            "--name", container_name,
            "--platform", info.docker_platform,
            "--network", "none",
            "--read-only",
            f"--tmpfs=/tmp:rw,noexec,nosuid,size={_DEFAULT_TMPFS_SIZE}",
            "--memory", os.getenv("CTF_AGENTS_SANDBOX_MEMORY") or _DEFAULT_MEMORY,
            "--memory-swap", os.getenv("CTF_AGENTS_SANDBOX_MEMORY") or _DEFAULT_MEMORY,
            "--cpus", os.getenv("CTF_AGENTS_SANDBOX_CPUS") or _DEFAULT_CPUS,
            "--pids-limit", os.getenv("CTF_AGENTS_SANDBOX_PIDS") or _DEFAULT_PIDS,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", _RUNNER_UID_GID,
            "-v", f"{staged}:{guest_path}:ro",
            "-w", "/tmp",
            image(),
            guest_path,
        ]

        try:
            start = time.time()
            try:
                proc = subprocess.run(
                    argv,
                    input=payload,
                    capture_output=True,
                    env=minimal_subprocess_env(),
                    timeout=timeout_s,
                )
            except subprocess.TimeoutExpired:
                self._force_remove(container_name)
                return CrossArchRunResult(
                    False,
                    reason=f"emulated execution timed out after {timeout_s}s",
                    timed_out=True,
                )
            except OSError as exc:
                return CrossArchRunResult(False, reason=f"emulated execution failed: {exc}")

            raw = (proc.stdout or b"") + (proc.stderr or b"")
            output = raw[:_MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")

            # 125 is the daemon refusing the request (missing image, unsupported
            # --platform) and 126 is the runtime failing to exec the target (not
            # executable by the container uid). Neither is the binary running and
            # crashing, so report them as a failure to run — otherwise the caller
            # treats the error text as program output and repeats the same doomed
            # container start for every payload.
            if proc.returncode in (125, 126):
                return CrossArchRunResult(
                    False,
                    reason=f"docker could not run the target: {output.strip()[:200]}",
                    exit_code=proc.returncode,
                )

            logger.debug(
                "Emulated %s in %.1fs (exit=%s)", host.name, time.time() - start, proc.returncode
            )
            return CrossArchRunResult(True, output=output, exit_code=proc.returncode)
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    @staticmethod
    def _stage_binary(host: Path) -> Tuple[Optional[Path], Optional[Path], Optional[str]]:
        """Copy *host* to a private throwaway path loadable by the container.

        The original artifact may be owner-only and must remain untouched. The
        staged copy receives only read/execute bits and is removed after the run.
        """
        staging_dir: Optional[Path] = None
        try:
            temp_base = os.getenv("CTF_AGENTS_SANDBOX_TMPDIR") or None
            staging_dir = Path(tempfile.mkdtemp(prefix="ctf-elf-runner-", dir=temp_base))
            staged = staging_dir / "challenge"
            shutil.copyfile(host, staged)
            staged.chmod(0o555)
        except OSError as exc:
            if staging_dir is not None:
                shutil.rmtree(staging_dir, ignore_errors=True)
            return None, None, f"cannot stage {host.name} for container execution: {exc}"
        return staging_dir, staged, None

    def _force_remove(self, container_name: str) -> None:
        try:
            subprocess.run(
                [docker_bin(), "rm", "-f", container_name],
                capture_output=True,
                env=minimal_subprocess_env(),
                timeout=10,
            )
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            logger.debug("Container cleanup failed for %s: %s", container_name, exc)
