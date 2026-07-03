"""Docker-isolated execution for model-generated solver scripts.

Running arbitrary LLM-written Python directly on the host (the
``CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION`` path) means a bad or hostile script
can read the operator's files, reach the network, or burn the machine down. This
sandbox runs the same scripts inside a throwaway container with, by default:

  * no network at all (``--network none``),
  * a read-only root filesystem with a small ``noexec`` tmpfs for scratch,
  * challenge artifacts mounted read-only at their original absolute paths,
  * hard memory / CPU / PID limits,
  * all Linux capabilities dropped, ``no-new-privileges``, non-root uid,
  * a strict wall-clock timeout after which the container is force-removed.

Network egress is *fail-closed*: the current implementation never enables it.
A future sidecar must enforce destination policy at the network layer before
networked generated solvers can be supported safely.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import List, Optional, Sequence

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

logger = logging.getLogger(__name__)

_DEFAULT_IMAGE = "python:3.11-slim-bookworm"
_DEFAULT_MEMORY = "256m"
_DEFAULT_CPUS = "1.0"
_DEFAULT_PIDS = "128"
_DEFAULT_TMPFS_SIZE = "64m"
_SANDBOX_UID_GID = "65534:65534"  # nobody:nogroup


class SandboxConfigError(RuntimeError):
    """Raised when a requested sandbox configuration cannot be honored safely."""


class DockerPythonSandbox(BaseTool):
    """Execute a Python script inside a locked-down ephemeral container."""

    @property
    def tool_name(self) -> str:
        return os.getenv("CTF_AGENTS_DOCKER_BIN") or "docker"

    # ------------------------------------------------------------------
    @classmethod
    def is_available(cls) -> bool:
        """True if a docker CLI is on PATH (does not verify the daemon runs)."""
        return shutil.which(os.getenv("CTF_AGENTS_DOCKER_BIN") or "docker") is not None

    @staticmethod
    def image() -> str:
        return os.getenv("CTF_AGENTS_SANDBOX_IMAGE") or _DEFAULT_IMAGE

    def run(
        self,
        script_content: str,
        args: Optional[List[str]] = None,
        timeout_s: int = 30,
        artifact_paths: Optional[Sequence[str]] = None,
        allow_network: bool = False,
        allowed_targets: Optional[Sequence[str]] = None,
    ) -> ToolResult:
        """Run ``script_content`` in a container and return its ToolResult.

        ``artifact_paths`` are mounted read-only at their original absolute path
        so generated scripts that reference the challenge files by the paths in
        their prompt still resolve.
        """
        args = list(args or [])
        if not self.is_available():
            return self._error_result(
                args,
                "Docker sandbox selected but the 'docker' CLI was not found on PATH.",
            )

        network_args = self._network_args(allow_network, allowed_targets)

        work_dir = Path(tempfile.mkdtemp(prefix="ctf-sandbox-", dir=self._tmp_base()))
        script_path = work_dir / "solver.py"
        script_path.write_text(script_content, encoding="utf-8")
        container_name = f"ctf-sandbox-{uuid.uuid4().hex[:12]}"

        try:
            mount_args = self._mount_args(script_path, artifact_paths)
            # BaseTool.execute prepends self.tool_name ("docker"), so argv starts at "run".
            argv = [
                "run", "--rm",
                "--name", container_name,
                *network_args,
                "--read-only",
                f"--tmpfs=/tmp:rw,noexec,nosuid,size={_DEFAULT_TMPFS_SIZE}",
                "--memory", os.getenv("CTF_AGENTS_SANDBOX_MEMORY") or _DEFAULT_MEMORY,
                "--memory-swap", os.getenv("CTF_AGENTS_SANDBOX_MEMORY") or _DEFAULT_MEMORY,
                "--cpus", os.getenv("CTF_AGENTS_SANDBOX_CPUS") or _DEFAULT_CPUS,
                "--pids-limit", os.getenv("CTF_AGENTS_SANDBOX_PIDS") or _DEFAULT_PIDS,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--user", _SANDBOX_UID_GID,
                *mount_args,
                "-w", "/sandbox",
                self.image(),
                "python", "/sandbox/solver.py", *args,
            ]
            result = self.execute(argv, timeout_s=timeout_s)
            if result.timed_out:
                self._force_remove(container_name)
            return result
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    def _mount_args(
        self,
        script_path: Path,
        artifact_paths: Optional[Sequence[str]],
    ) -> List[str]:
        mounts = ["-v", f"{script_path}:/sandbox/solver.py:ro"]
        seen = set()
        for raw in artifact_paths or []:
            if not raw:
                continue
            host = Path(str(raw)).resolve()
            if not host.exists():
                continue
            key = str(host)
            if key in seen:
                continue
            seen.add(key)
            # Mount at the original absolute path so scripts that reference the
            # challenge files by prompt path resolve unchanged.
            mounts += ["-v", f"{host}:{host}:ro"]
        return mounts

    @staticmethod
    def _network_args(
        allow_network: bool,
        allowed_targets: Optional[Sequence[str]],
    ) -> List[str]:
        if not allow_network:
            return ["--network", "none"]

        targets = [t.strip() for t in (allowed_targets or []) if t and t.strip()]
        raise SandboxConfigError(
            "Networked generated solvers are not yet supported safely. "
            f"Requested targets: {targets or ['<none>']}. The sandbox remains "
            "on --network none until an enforcing network-policy sidecar exists."
        )

    @staticmethod
    def _tmp_base() -> Optional[str]:
        # Allow overriding where the throwaway script dir is created, in case the
        # default temp dir is not shared with Docker Desktop's VM.
        return os.getenv("CTF_AGENTS_SANDBOX_TMPDIR") or None

    def _force_remove(self, container_name: str) -> None:
        try:
            self.execute(["rm", "-f", container_name], timeout_s=10)
        except Exception as exc:  # pragma: no cover - best-effort cleanup
            logger.debug("Sandbox container cleanup failed for %s: %s", container_name, exc)

    @staticmethod
    def _error_result(args: List[str], message: str) -> ToolResult:
        return ToolResult(
            argv=["docker", "run", "<sandbox>"] + args,
            stdout="",
            stderr=message,
            exit_code=126,
            timed_out=False,
            duration_s=0.0,
        )
