"""
Message definitions for agent communication.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum


class MessageType(Enum):
    """Types of messages in the system"""
    TASK_ASSIGNMENT = "task_assignment"
    TASK_COMPLETE = "task_complete"
    STATUS_UPDATE = "status_update"
    KNOWLEDGE_SHARE = "knowledge_share"
    REQUEST_HELP = "request_help"
    RESULT_REPORT = "result_report"
    SYSTEM_EVENT = "system_event"


class MessagePriority(Enum):
    """Message priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Message:
    """
    Represents a message between agents or system components.
    """
    message_id: str
    message_type: MessageType
    sender: str
    recipient: str
    timestamp: datetime
    priority: MessagePriority = MessagePriority.NORMAL
    payload: Dict[str, Any] = field(default_factory=dict)
    requires_response: bool = False
    response_to: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            'message_id': self.message_id,
            'message_type': self.message_type.value,
            'sender': self.sender,
            'recipient': self.recipient,
            'timestamp': self.timestamp.isoformat(),
            'priority': self.priority.value,
            'payload': self.payload,
            'requires_response': self.requires_response,
            'response_to': self.response_to
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create message from dictionary"""
        return cls(
            message_id=data['message_id'],
            message_type=MessageType(data['message_type']),
            sender=data['sender'],
            recipient=data['recipient'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            priority=MessagePriority(data.get('priority', 2)),
            payload=data.get('payload', {}),
            requires_response=data.get('requires_response', False),
            response_to=data.get('response_to')
        )


@dataclass
class TaskAssignment(Message):
    """Message for assigning a task to an agent"""
    
    def __init__(self, message_id: str, sender: str, recipient: str, 
                 challenge: Dict[str, Any], deadline: Optional[datetime] = None):
        super().__init__(
            message_id=message_id,
            message_type=MessageType.TASK_ASSIGNMENT,
            sender=sender,
            recipient=recipient,
            timestamp=datetime.now(),
            priority=MessagePriority.HIGH,
            payload={
                'challenge': challenge,
                'deadline': deadline.isoformat() if deadline else None
            },
            requires_response=True
        )


@dataclass
class StatusUpdate(Message):
    """Message for status updates"""
    
    def __init__(self, message_id: str, sender: str, status: str, 
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message_id=message_id,
            message_type=MessageType.STATUS_UPDATE,
            sender=sender,
            recipient="coordinator",
            timestamp=datetime.now(),
            priority=MessagePriority.NORMAL,
            payload={
                'status': status,
                'details': details or {}
            }
        )


@dataclass
class ResultReport(Message):
    """Message for reporting results"""
    
    def __init__(self, message_id: str, sender: str, challenge_id: str, 
                 result: Dict[str, Any]):
        super().__init__(
            message_id=message_id,
            message_type=MessageType.RESULT_REPORT,
            sender=sender,
            recipient="coordinator",
            timestamp=datetime.now(),
            priority=MessagePriority.HIGH,
            payload={
                'challenge_id': challenge_id,
                'result': result
            }
        )
