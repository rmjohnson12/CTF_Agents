"""
Challenge schema and data structures.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ChallengeCategory(Enum):
    """CTF challenge categories"""
    WEB = "web"
    CRYPTO = "crypto"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    PWN = "pwn"
    BINARY = "binary"
    OSINT = "osint"
    MISC = "misc"
    NETWORKING = "networking"


class ChallengeDifficulty(Enum):
    """Challenge difficulty levels"""
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    INSANE = "insane"


class ChallengeStatus(Enum):
    """Challenge status states"""
    PENDING = "pending"
    ACTIVE = "active"
    SOLVED = "solved"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class Challenge:
    """
    Represents a CTF challenge.
    """
    id: str
    name: str
    category: ChallengeCategory
    difficulty: ChallengeDifficulty
    description: str
    points: int
    files: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    url: Optional[str] = None
    connection_info: Optional[Dict[str, str]] = None
    status: ChallengeStatus = ChallengeStatus.PENDING
    assigned_agents: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    completion_time: Optional[datetime] = None
    flag: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert challenge to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category.value,
            'difficulty': self.difficulty.value,
            'description': self.description,
            'points': self.points,
            'files': self.files,
            'hints': self.hints,
            'tags': self.tags,
            'url': self.url,
            'connection_info': self.connection_info,
            'status': self.status.value,
            'assigned_agents': self.assigned_agents,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'completion_time': self.completion_time.isoformat() if self.completion_time else None,
            'flag': self.flag,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Challenge':
        """Create challenge from dictionary"""
        return cls(
            id=data['id'],
            name=data['name'],
            category=ChallengeCategory(data['category']),
            difficulty=ChallengeDifficulty(data['difficulty']),
            description=data['description'],
            points=data['points'],
            files=data.get('files', []),
            hints=data.get('hints', []),
            tags=data.get('tags', []),
            url=data.get('url'),
            connection_info=data.get('connection_info'),
            status=ChallengeStatus(data.get('status', 'pending')),
            assigned_agents=data.get('assigned_agents', []),
            start_time=datetime.fromisoformat(data['start_time']) if data.get('start_time') else None,
            completion_time=datetime.fromisoformat(data['completion_time']) if data.get('completion_time') else None,
            flag=data.get('flag'),
            metadata=data.get('metadata', {})
        )


@dataclass
class SolutionResult:
    """
    Represents the result of a challenge solution attempt.
    """
    challenge_id: str
    agent_id: str
    success: bool
    flag: Optional[str] = None
    steps: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    vulnerabilities_found: List[str] = field(default_factory=list)
    confidence: float = 0.0
    execution_time: float = 0.0
    error_message: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            'challenge_id': self.challenge_id,
            'agent_id': self.agent_id,
            'success': self.success,
            'flag': self.flag,
            'steps': self.steps,
            'tools_used': self.tools_used,
            'vulnerabilities_found': self.vulnerabilities_found,
            'confidence': self.confidence,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'artifacts': self.artifacts
        }
