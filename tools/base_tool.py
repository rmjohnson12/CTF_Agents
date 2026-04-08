from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence
from tools.common.runner import ToolRunner
from tools.common.result import ToolResult

class BaseTool(ABC):
    """
    Abstract base class for all tools.
    Provides a standard interface for execution and result handling.
    """
    def __init__(self, runner: Optional[ToolRunner] = None):
        self.runner = runner or ToolRunner()

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """The command-line name of the tool (e.g., 'nmap')."""
        pass

    def execute(self, args: Sequence[str], timeout_s: Optional[int] = None) -> ToolResult:
        """
        Execute the tool with the given arguments.
        This is the low-level execution that returns a ToolResult.
        """
        argv = [self.tool_name] + list(args)
        return self.runner.run(argv, timeout_s=timeout_s)

    @abstractmethod
    def run(self, *args: Any, **kwargs: Any) -> Any:
        """
        The main entry point for the tool. 
        Subclasses should implement this to provide a tool-specific interface
        that calls self.execute() and parses the result.
        """
        pass
