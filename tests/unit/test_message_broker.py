"""Unit tests for MessageBroker."""

from datetime import datetime

import pytest

from core.communication.message import Message, MessageType, MessagePriority
from core.communication.message_broker import MessageBroker


def _make_message(
    msg_id: str = "m1",
    sender: str = "agent_a",
    recipient: str = "agent_b",
) -> Message:
    return Message(
        message_id=msg_id,
        message_type=MessageType.STATUS_UPDATE,
        sender=sender,
        recipient=recipient,
        timestamp=datetime.now(),
        priority=MessagePriority.NORMAL,
        payload={"info": msg_id},
    )


# ── subscribe + publish ──────────────────────────────────────────────

def test_publish_routes_to_recipient():
    broker = MessageBroker()
    received = []
    broker.subscribe("agent_b", lambda m: received.append(m))

    msg = _make_message()
    broker.publish(msg)

    assert len(received) == 1
    assert received[0] is msg


def test_publish_does_not_route_to_other_agents():
    broker = MessageBroker()
    received = []
    broker.subscribe("agent_c", lambda m: received.append(m))

    broker.publish(_make_message(recipient="agent_b"))

    assert received == []


def test_multiple_handlers_for_same_recipient():
    broker = MessageBroker()
    box_1, box_2 = [], []
    broker.subscribe("agent_b", lambda m: box_1.append(m))
    broker.subscribe("agent_b", lambda m: box_2.append(m))

    broker.publish(_make_message())

    assert len(box_1) == 1
    assert len(box_2) == 1


# ── broadcast ("*") ─────────────────────────────────────────────────

def test_broadcast_receives_all_messages():
    broker = MessageBroker()
    broadcast = []
    broker.subscribe("*", lambda m: broadcast.append(m))

    broker.publish(_make_message(recipient="agent_b"))
    broker.publish(_make_message(recipient="agent_c"))

    assert len(broadcast) == 2


def test_broadcast_and_direct_both_fire():
    broker = MessageBroker()
    direct, broadcast = [], []
    broker.subscribe("agent_b", lambda m: direct.append(m))
    broker.subscribe("*", lambda m: broadcast.append(m))

    broker.publish(_make_message(recipient="agent_b"))

    assert len(direct) == 1
    assert len(broadcast) == 1


# ── get_history ──────────────────────────────────────────────────────

def test_history_records_all_published():
    broker = MessageBroker()

    broker.publish(_make_message(msg_id="m1"))
    broker.publish(_make_message(msg_id="m2"))

    history = broker.get_history()
    assert len(history) == 2
    assert history[0].message_id == "m1"
    assert history[1].message_id == "m2"


def test_history_filtered_by_agent_id():
    broker = MessageBroker()

    broker.publish(_make_message(sender="x", recipient="y"))
    broker.publish(_make_message(sender="a", recipient="b"))
    broker.publish(_make_message(sender="y", recipient="z"))

    filtered = broker.get_history(agent_id="y")

    assert len(filtered) == 2
    assert all(m.sender == "y" or m.recipient == "y" for m in filtered)


def test_history_bounded():
    broker = MessageBroker(max_history=3)

    for i in range(5):
        broker.publish(_make_message(msg_id=f"m{i}"))

    history = broker.get_history()
    assert len(history) == 3
    assert history[0].message_id == "m2"


# ── type validation ──────────────────────────────────────────────────

def test_publish_rejects_non_message():
    broker = MessageBroker()

    with pytest.raises(TypeError, match="Expected a Message instance"):
        broker.publish({"not": "a message"})
