from __future__ import annotations

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

    @property
    def tool_name(self) -> str:
        # Use the current python executable to ensure we stay in the same environment/venv
        return sys.executable

    def run(self, script_content: str, args: Optional[List[str]] = None, timeout_s: int = 30) -> ToolResult:
        """
        Execute a string of Python code as a script.
        """
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
