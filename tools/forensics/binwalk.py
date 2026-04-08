from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class BinwalkSignature:
    decimal: int
    hexadecimal: str
    description: str

@dataclass(frozen=True)
class BinwalkResult:
    file_path: str
    signatures: List[BinwalkSignature]
    raw: ToolResult

class BinwalkTool(BaseTool):
    """
    Thin wrapper around binwalk.
    """

    @property
    def tool_name(self) -> str:
        return "binwalk"

    def run(self, file_path: str, *, timeout_s: int = 60) -> BinwalkResult:
        """
        Scan a file for signatures.
        """
        res = self.execute([file_path], timeout_s=timeout_s)
        signatures = self._parse_output(res.stdout)
        return BinwalkResult(file_path=file_path, signatures=signatures, raw=res)

    @staticmethod
    def _parse_output(text: str) -> List[BinwalkSignature]:
        """
        Example output format:
        DECIMAL       HEXADECIMAL     DESCRIPTION
        --------------------------------------------------------------------------------
        0             0x0             PNG image, 512 x 512, 8-bit/color RGBA, non-interlaced
        41            0x29            Zlib compressed data, default compression
        """
        out: List[BinwalkSignature] = []
        lines = text.splitlines()
        
        # Skip header lines
        start_index = 0
        for i, line in enumerate(lines):
            if "-----------" in line:
                start_index = i + 1
                break
        
        for line in lines[start_index:]:
            line = line.strip()
            if not line:
                continue
            
            # Match decimal, hex, and description
            m = re.match(r"^(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)$", line)
            if m:
                out.append(
                    BinwalkSignature(
                        decimal=int(m.group(1)),
                        hexadecimal=m.group(2),
                        description=m.group(3)
                    )
                )
        return out
