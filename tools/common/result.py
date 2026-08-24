from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass(frozen=True)
class ToolResult:
    """
    Structured result from executing an external tool.
    """
    argv: Sequence[str]
    stdout: str
    stderr: str
    exit_code: Optional[int]   # None if timed out / not started
    timed_out: bool
    duration_s: float
