import json

import pytest

from agents.specialists.industrial_control.ics_agent import IndustrialControlAgent
from core.decision_engine.llm_reasoner import LLMReasoner


class FactorySocket:
    def __init__(self, *, permit_manual=True):
        self.buffer = bytearray(b"Water Storage Facility Interface\nSelect:")
        self.sent_packets = []
        self.awaiting_packet = False
        self.closed = False
        self.permit_manual = permit_manual
        self.state = {
            "auto_mode": 1,
            "manual_mode": 0,
            "stop_out": 0,
            "stop_in": 0,
            "low_sensor": 0,
            "high_sesnor": 0,
            "in_valve": 1,
            "out_valve": 0,
            "flag": "HTB{}",
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def settimeout(self, _timeout):
        return None

    def recv(self, size):
        if not self.buffer:
            raise TimeoutError()
        chunk = bytes(self.buffer[:size])
        del self.buffer[:size]
        return chunk

    def sendall(self, data):
        value = data.strip().decode("ascii")
        if value == "1":
            self.buffer.extend(json.dumps(self.state).encode() + b"\nSelect:")
            return
        if value == "2":
            self.awaiting_packet = True
            self.buffer.extend(b"Modbus command:")
            return
        assert self.awaiting_packet
        self.awaiting_packet = False
        self.sent_packets.append(value)
        if value == "52050021ff00" and self.permit_manual and "520526dbff00" in self.sent_packets:
            self.state.update(auto_mode=0, manual_mode=1)
        if value == "5205001aff00" and self.state["manual_mode"]:
            self.state.update(stop_in=1, in_valve=0)
        if value == "52050034ff00" and self.state["manual_mode"]:
            self.state.update(out_valve=1, flag="HTB{factory_fixture}")
        self.buffer.extend(b"Modbus command sent to the network!\nSelect:")


def factory_challenge():
    return {
        "id": "htb-222",
        "name": "Factory",
        "category": "ICS",
        "description": (
            "The HMI is offline. Regain control of the water storage PLC through "
            "the remote serial network."
        ),
        "files": ["interface_setup.png", "PLC_Ladder_Logic.pdf"],
        "url": "http://127.0.0.1:31337",
    }


def test_build_write_single_coil_uses_big_endian_fc05_without_crc():
    assert IndustrialControlAgent.build_write_single_coil(82, 9947, True) == "520526dbff00"
    assert IndustrialControlAgent.build_write_single_coil(82, 33, False) == "520500210000"


@pytest.mark.parametrize("slave,address", [(-1, 1), (256, 1), (1, -1), (1, 65536)])
def test_build_write_single_coil_rejects_out_of_range_fields(slave, address):
    with pytest.raises(ValueError):
        IndustrialControlAgent.build_write_single_coil(slave, address, True)


def test_factory_playbook_solves_and_sends_only_documented_coils(monkeypatch):
    fake = FactorySocket()
    monkeypatch.setattr(
        "agents.specialists.industrial_control.ics_agent.assert_host_allowed",
        lambda *_args, **_kwargs: None,
    )
    agent = IndustrialControlAgent(connector=lambda *_args, **_kwargs: fake, sleeper=lambda _n: None)

    result = agent.solve_challenge(factory_challenge())

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{factory_fixture}"
    assert fake.sent_packets == [
        "520526dbff00",
        "52050021ff00",
        "5205001aff00",
        "52050034ff00",
    ]


def test_factory_playbook_stops_before_actuator_writes_when_mode_transition_fails(monkeypatch):
    fake = FactorySocket(permit_manual=False)
    monkeypatch.setattr(
        "agents.specialists.industrial_control.ics_agent.assert_host_allowed",
        lambda *_args, **_kwargs: None,
    )
    agent = IndustrialControlAgent(connector=lambda *_args, **_kwargs: fake, sleeper=lambda _n: None)

    result = agent.solve_challenge(factory_challenge())

    assert result["status"] == "attempted"
    assert fake.sent_packets == ["520526dbff00", "52050021ff00"]
    assert any("did not enter manual mode" in step for step in result["steps"])


def test_generic_ics_challenge_is_analyzed_without_sending_writes():
    connected = False

    def connector(*_args, **_kwargs):
        nonlocal connected
        connected = True
        raise AssertionError("must not connect")

    agent = IndustrialControlAgent(connector=connector)
    challenge = {
        "id": "generic",
        "category": "ics",
        "description": "Inspect an OPC UA industrial control service.",
        "url": "127.0.0.1:1234",
    }
    assert agent.analyze_challenge(challenge)["can_handle"] is True
    result = agent.solve_challenge(challenge)
    assert result["status"] == "attempted"
    assert connected is False
    assert any("no PLC writes" in step for step in result["steps"])


def test_reasoner_routes_ics_category_and_terms_to_ics_agent(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "none")
    reasoner = LLMReasoner()
    explicit = reasoner.analyze_challenge({"category": "ics", "description": "PLC control"})
    inferred = reasoner.analyze_challenge(
        {"category": "misc", "description": "Recover a SCADA HMI over a Modbus serial network"}
    )
    assert explicit.category_guess == "ics"
    assert explicit.recommended_target == "ics_agent"
    assert inferred.category_guess == "ics"
    assert inferred.recommended_target == "ics_agent"
