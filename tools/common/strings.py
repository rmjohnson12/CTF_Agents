from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class StringsResult:
    file_path: str
    strings: List[str]
    raw: ToolResult

class StringsTool(BaseTool):
    """
    Standard tool for extracting printable strings from a binary file.
    """

    @property
    def tool_name(self) -> str:
        return "strings"

    def run(self, file_path: str, min_len: int = 4, timeout_s: int = 30) -> StringsResult:
        """
        Run strings on a file and return a list of extracted strings.
        """
        args = ["-n", str(min_len), file_path]
        res = self.execute(args, timeout_s=timeout_s)
        
        extracted = []
        if res.exit_code == 0 and res.stdout:
            extracted = res.stdout.splitlines()
            
        return StringsResult(file_path=file_path, strings=extracted, raw=res)
