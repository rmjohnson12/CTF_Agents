from unittest.mock import MagicMock

import pytest

from agents.registry import AgentRegistry


def test_registry_discovers_all_shipped_agents_in_stable_order():
    agents = AgentRegistry.create_all()

    assert [agent.agent_id for agent in agents] == [
        "crypto_agent",
        "web_agent",
        "coding_agent",
        "forensics_agent",
        "reverse_agent",
        "osint_agent",
        "log_agent",
        "networking_agent",
        "hardware_agent",
        "docker_agent",
        "recon_agent",
        "pwn_agent",
        "blockchain_agent",
        "secure_coding_agent",
    ]


def test_registry_injects_only_matching_constructor_dependencies(monkeypatch):
    monkeypatch.setattr(AgentRegistry, "_registrations", {})
    monkeypatch.setattr(AgentRegistry, "_discovered", True)
    reasoner = object()

    @AgentRegistry.register(order=20)
    class LaterAgent:
        def __init__(self):
            self.agent_id = "later"

    @AgentRegistry.register(order=10)
    class InjectedAgent:
        def __init__(self, reasoner=None):
            self.agent_id = "injected"
            self.reasoner = reasoner

    agents = AgentRegistry.create_all({"reasoner": reasoner, "unused": object()})

    assert [agent.agent_id for agent in agents] == ["injected", "later"]
    assert agents[0].reasoner is reasoner


def test_registry_rejects_duplicate_registration_names(monkeypatch):
    monkeypatch.setattr(AgentRegistry, "_registrations", {})

    @AgentRegistry.register(name="duplicate")
    class FirstAgent:
        pass

    with pytest.raises(ValueError, match="already exists"):

        @AgentRegistry.register(name="duplicate")
        class SecondAgent:
            pass


def test_registry_attaches_constructed_agents_to_coordinator(monkeypatch):
    monkeypatch.setattr(AgentRegistry, "_registrations", {})
    monkeypatch.setattr(AgentRegistry, "_discovered", True)

    @AgentRegistry.register()
    class ExampleAgent:
        pass

    coordinator = MagicMock()
    agents = AgentRegistry.register_all(coordinator)

    assert len(agents) == 1
    coordinator.register_agent.assert_called_once_with(agents[0])

