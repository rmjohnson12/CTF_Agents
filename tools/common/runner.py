from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from tools.common.result import ToolResult


@dataclass
class RunnerConfig:
    """
    Configuration for ToolRunner.

    allowlist:
      - If set, only executables in this allowlist are allowed to run.
    """
    allowlist: Optional[set[str]] = None
    default_timeout_s: int = 60
    max_output_chars: int = 200_000
    inherit_env: bool = True


class ToolRunner:
    """
    Simple, safe-ish wrapper around subprocess.run that:
    - supports timeouts
    - captures stdout/stderr
    - optionally restricts executables via allowlist
    - truncates output to keep logs sane
    """

    def __init__(self, config: Optional[RunnerConfig] = None):
        self.config = config or RunnerConfig()

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> ToolResult:
        if not argv:
            raise ValueError("argv must be non-empty")

        exe = os.path.basename(argv[0]).lower()
        if exe.endswith(".exe"):
            exe = exe[:-4]
            
        if self.config.allowlist is not None and exe not in self.config.allowlist:
            raise PermissionError(f"Executable '{exe}' not in allowlist")

        timeout = timeout_s if timeout_s is not None else self.config.default_timeout_s

        # Build environment
        run_env = None
        if self.config.inherit_env:
            run_env = dict(os.environ)
            if env:
                run_env.update(env)
        else:
            run_env = env

        start = time.time()
        timed_out = False

        try:
            proc = subprocess.run(
                list(argv),
                cwd=cwd,
                env=run_env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            exit_code = None

        duration = time.time() - start

        stdout = self._truncate(stdout)
        stderr = self._truncate(stderr)

        return ToolResult(
            argv=argv,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            timed_out=timed_out,
            duration_s=duration,
        )

    def _truncate(self, s: str) -> str:
        if len(s) <= self.config.max_output_chars:
            return s
        return s[: self.config.max_output_chars] + "\n...[truncated]..."
