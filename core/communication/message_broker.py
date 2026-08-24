"""
In-memory message broker for inter-agent communication.
"""

import threading
from collections import deque
from typing import Callable, Deque, Dict, List, Optional

from core.communication.message import Message


# Type alias for handler callbacks
MessageHandler = Callable[[Message], None]


class MessageBroker:
    """
    Simple in-memory publish/subscribe message broker.

    Agents subscribe by ID; published messages are routed to the
    matching recipient handler.  A special ``"*"`` channel receives
    all messages (broadcast).

    Thread-safe via a ``threading.Lock``.
    """

    def __init__(self, *, max_history: int = 1000):
        """
        Args:
            max_history: Maximum number of messages to retain in
                         the history buffer.
        """
        self._lock = threading.Lock()
        self._handlers: Dict[str, List[MessageHandler]] = {}
        self._history: Deque[Message] = deque(maxlen=max_history)

    def subscribe(self, agent_id: str, handler: MessageHandler) -> None:
        """
        Register a handler for messages addressed to *agent_id*.

        Use ``"*"`` to receive every published message (broadcast).

        Args:
            agent_id: Recipient identifier (or ``"*"`` for broadcast).
            handler:  Callable that accepts a ``Message``.
        """
        with self._lock:
            self._handlers.setdefault(agent_id, []).append(handler)

    def publish(self, message: Message) -> None:
        """
        Route *message* to the recipient's handlers and any broadcast
        (``"*"``) handlers.

        Args:
            message: The message to publish.

        Raises:
            TypeError: If *message* is not a ``Message`` instance.
        """
        if not isinstance(message, Message):
            raise TypeError(
                f"Expected a Message instance, got {type(message).__name__}"
            )

        with self._lock:
            self._history.append(message)
            handlers = list(self._handlers.get(message.recipient, []))
            broadcast = list(self._handlers.get("*", []))

        # Invoke outside the lock to avoid deadlocks in handlers
        for h in handlers:
            h(message)
        for h in broadcast:
            h(message)

    def get_history(
        self, *, agent_id: Optional[str] = None
    ) -> List[Message]:
        """
        Return the message history log.

        Args:
            agent_id: If provided, only return messages where the
                      sender **or** recipient matches this ID.

        Returns:
            List of ``Message`` objects (oldest first).
        """
        with self._lock:
            msgs = list(self._history)

        if agent_id is not None:
            msgs = [
                m for m in msgs
                if m.sender == agent_id or m.recipient == agent_id
            ]
        return msgs
