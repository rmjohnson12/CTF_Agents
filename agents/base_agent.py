"""
Base Agent Interface

This module defines the abstract base class that all agents must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from enum import Enum


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
    
    def __init__(self, agent_id: str, agent_type: AgentType):
        """
        Initialize the base agent.
        
        Args:
            agent_id: Unique identifier for the agent
            agent_type: Type of agent (coordinator, specialist, support)
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.status = AgentStatus.IDLE
        self.current_task = None
        self.capabilities = []
        
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
        
    def complete_task(self):
        """Mark current task as complete"""
        self.current_task = None
        self.status = AgentStatus.IDLE
