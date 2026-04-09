from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Any, List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class ExiftoolResult:
    file_path: str
    metadata: Dict[str, Any]
    raw: ToolResult

class ExiftoolTool(BaseTool):
    """
    Standard tool for extracting metadata using exiftool.
    """

    @property
    def tool_name(self) -> str:
        return "exiftool"

    def run(self, file_path: str, timeout_s: int = 30) -> ExiftoolResult:
        """
        Extract metadata from a file in JSON format.
        """
        # -j flag returns JSON output
        res = self.execute(["-j", file_path], timeout_s=timeout_s)
        
        metadata = {}
        if res.exit_code == 0 and res.stdout:
            try:
                # Exiftool returns a list of dictionaries
                data = json.loads(res.stdout)
                if isinstance(data, list) and len(data) > 0:
                    metadata = data[0]
            except json.JSONDecodeError:
                pass
                
        return ExiftoolResult(file_path=file_path, metadata=metadata, raw=res)
