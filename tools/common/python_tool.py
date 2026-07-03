from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Optional, List, Sequence

from tools.base_tool import BaseTool
from tools.common.result import ToolResult
from tools.common.docker_sandbox import DockerPythonSandbox, SandboxConfigError

class PythonTool(BaseTool):
    """
    Standard tool for executing Python scripts.

    Execution backend is selected by ``CTF_AGENTS_SANDBOX``:
      * ``docker`` -> run inside a locked-down throwaway container (recommended).
      * unset/other -> run on the host, but only when
        ``CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION`` is explicitly enabled.
    """

    _HOST_EXECUTION_ENV = "CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION"
    _SANDBOX_ENV = "CTF_AGENTS_SANDBOX"

    def __init__(self, *args, sandbox: Optional[DockerPythonSandbox] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._sandbox = sandbox or DockerPythonSandbox()

    @property
    def tool_name(self) -> str:
        # Use the current python executable to ensure we stay in the same environment/venv
        return sys.executable

    def _sandbox_mode(self) -> str:
        return (os.getenv(self._SANDBOX_ENV) or "").strip().lower()

    def execution_backend(self) -> str:
        if self._sandbox_mode() == "docker":
            return "docker"
        if os.getenv(self._HOST_EXECUTION_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
            return "host"
        return "disabled"

    def run(
        self,
        script_content: str,
        args: Optional[List[str]] = None,
        timeout_s: int = 30,
        artifact_paths: Optional[Sequence[str]] = None,
        allow_network: bool = False,
        allowed_targets: Optional[Sequence[str]] = None,
    ) -> ToolResult:
        """
        Execute a string of Python code as a script.

        When the Docker sandbox is selected, ``artifact_paths`` are mounted
        read-only so generated scripts can still read the challenge files.
        """
        if self._sandbox_mode() == "docker":
            try:
                return self._sandbox.run(
                    script_content,
                    args=args,
                    timeout_s=timeout_s,
                    artifact_paths=artifact_paths,
                    allow_network=allow_network,
                    allowed_targets=allowed_targets,
                )
            except SandboxConfigError as exc:
                return ToolResult(
                    argv=[self.tool_name, "<sandboxed-script>"] + (args or []),
                    stdout="",
                    stderr=str(exc),
                    exit_code=126,
                    timed_out=False,
                    duration_s=0.0,
                )

        if os.getenv(self._HOST_EXECUTION_ENV, "").strip().lower() not in {"1", "true", "yes", "on"}:
            return ToolResult(
                argv=[self.tool_name, "<generated-script>"] + (args or []),
                stdout="",
                stderr=(
                    "Host Python script execution is disabled by default. Either set "
                    f"{self._SANDBOX_ENV}=docker to run in an isolated container "
                    f"(recommended), or set {self._HOST_EXECUTION_ENV}=1 only for "
                    "trusted, authorized challenge runs."
                ),
                exit_code=126,
                timed_out=False,
                duration_s=0.0,
            )

        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            script_path = f.name

        try:
            full_args = [script_path] + (args or [])
            # BaseTool.execute calls ToolRunner.run([self.tool_name] + args)
            return self.execute(full_args, timeout_s=timeout_s)
        finally:
            # Clean up the temporary script file
            try:
                Path(script_path).unlink()
            except OSError:
                pass
