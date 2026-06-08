from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Optional, List

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

class PythonTool(BaseTool):
    """
    Standard tool for executing Python scripts.
    """

    _HOST_EXECUTION_ENV = "CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION"

    @property
    def tool_name(self) -> str:
        # Use the current python executable to ensure we stay in the same environment/venv
        return sys.executable

    def run(self, script_content: str, args: Optional[List[str]] = None, timeout_s: int = 30) -> ToolResult:
        """
        Execute a string of Python code as a script.
        """
        if os.getenv(self._HOST_EXECUTION_ENV, "").strip().lower() not in {"1", "true", "yes", "on"}:
            return ToolResult(
                argv=[self.tool_name, "<generated-script>"] + (args or []),
                stdout="",
                stderr=(
                    "Host Python script execution is disabled by default. "
                    f"Set {self._HOST_EXECUTION_ENV}=1 only for trusted, authorized challenge runs."
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
