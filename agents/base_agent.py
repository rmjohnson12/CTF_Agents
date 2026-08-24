"""
Base Agent Interface

This module defines the abstract base class that all agents must implement.
"""

from abc import ABC, abstractmethod
from enum import Enum
import logging
import shlex
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from core.knowledge_base.knowledge_store import KnowledgeStore
from tools.common.runner import ToolRunner


class AgentType(Enum):
    """Types of agents in the system"""
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"
    SUPPORT = "support"


class AgentStatus(Enum):
    """Agent status states"""
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"


class BaseAgent(ABC):
    """
    Abstract base class for all agents in the CTF multi-agent system.
    
    All agents must implement this interface to ensure consistent
    communication and behavior across the system.
    """
    
    def __init__(self, agent_id: str, agent_type: AgentType, knowledge_store: Optional[KnowledgeStore] = None):
        """
        Initialize the base agent.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_type: Type of agent (coordinator, specialist, support)
            knowledge_store: Shared intelligence store
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = AgentStatus.IDLE
        self.current_task = None
        self.capabilities = []
        self.knowledge_store = knowledge_store or KnowledgeStore()
        self.solve_trace_store = None
        self.progress_reporter = None
        self._task_started_monotonic: Optional[float] = None
        
    @abstractmethod
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a challenge and determine if this agent can handle it.
        
        Args:
            challenge: Challenge information dictionary
            
        Returns:
            Analysis results including confidence score and strategy
        """
        pass
    
    @abstractmethod
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a challenge.
        
        Args:
            challenge: Challenge information dictionary
            
        Returns:
            Solution results including flag (if found) and methodology
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """
        Return list of capabilities this agent possesses.
        
        Returns:
            List of capability identifiers
        """
        pass
    
    def update_status(self, status: AgentStatus):
        """Update the agent's current status"""
        self.status = status
        
    def get_status(self) -> AgentStatus:
        """Get the agent's current status"""
        return self.status
    
    def assign_task(self, task: Dict[str, Any]):
        """Assign a task to this agent"""
        self.current_task = task
        self.status = AgentStatus.BUSY
        self._task_started_monotonic = time.monotonic()
        
    def complete_task(self):
        """Mark current task as complete"""
        self.current_task = None
        self.status = AgentStatus.IDLE
        self._task_started_monotonic = None

    def emit_progress(
        self,
        *,
        status: str,
        step_title: str,
        step_description: str = "",
        challenge: Optional[Dict[str, Any]] = None,
        confidence: Optional[float] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        final_flag: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """Emit an optional structured update without affecting solve behavior.

        Specialists can call this during long-running work. The coordinator also
        emits lifecycle events around every specialist, so existing agents gain
        useful reporting without needing immediate rewrites.
        """
        if self.progress_reporter is None:
            return False
        task = challenge or self.current_task or {}
        run_id = task.get("run_id")
        challenge_id = task.get("id") or task.get("challenge_id")
        if not run_id or not challenge_id:
            return False
        started = task.get("_reporting_started_monotonic") or self._task_started_monotonic
        elapsed = max(0.0, time.monotonic() - float(started)) if started else None
        try:
            from core.reporting.models import ProgressUpdate

            return bool(self.progress_reporter.emit(ProgressUpdate(
                challenge_id=str(challenge_id),
                run_id=str(run_id),
                agent_name=self.agent_id,
                agent_type=self.agent_type.value,
                status=status,
                step_title=step_title,
                step_description=step_description,
                confidence=confidence,
                elapsed_seconds=elapsed,
                artifacts=artifacts or {},
                final_flag=final_flag,
                error_message=error_message,
            )))
        except Exception as exc:
            logging.getLogger(self.agent_id).warning("Progress reporting failed: %s", exc)
            return False

    def _plan_approach(self, indicators: List[str]) -> str:
        """
        Default approach planner. Can be overridden by specialists.
        
        Args:
            indicators: List of detected indicators or types
            
        Returns:
            A string describing the planned approach
        """
        if not indicators:
            return "General analysis and tool execution"
        return f"Focus on {', '.join(indicators)} indicators"

    def run_shell_command(
        self,
        command: Union[str, Sequence[str]],
        timeout: int = 60,
    ):
        """
        Helper to run shell commands from agents safely (no shell=True).
        Accepts either a string (split via shlex) or a list of arguments.
        """
        from tools.common.result import ToolResult

        if isinstance(command, str):
            argv = shlex.split(command)
        else:
            argv = list(command)

        start_time = time.time()
        try:
            return ToolRunner().run(argv, timeout_s=timeout)
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return ToolResult(
                argv=argv,
                stdout="",
                stderr="Timeout",
                exit_code=-1,
                timed_out=True,
                duration_s=duration,
            )
        except Exception as e:
            duration = time.time() - start_time
            logging.getLogger(self.agent_id).warning(
                "run_shell_command failed: %s (argv=%s)", e, argv
            )
            return ToolResult(
                argv=argv,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                timed_out=False,
                duration_s=duration,
            )
