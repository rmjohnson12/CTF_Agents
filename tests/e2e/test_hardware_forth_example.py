import json
from pathlib import Path

from agents.specialists.hardware_logic.hardware_agent import HardwareLogicAgent
from challenges.challenge_parser import ChallengeParser


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "hardware" / "forth"


class TranscriptSocket:
    def __init__(self, responses):
        self.responses = responses
        self.sent = []
        self.pending = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def settimeout(self, _timeout):
        pass

    def sendall(self, payload):
        command = payload.decode("ascii")
        self.sent.append(command)
        self.pending = self.responses.get(command, "").encode("utf-8")

    def recv(self, size):
        chunk, self.pending = self.pending[:size], self.pending[size:]
        return chunk


def test_golden_hardware_forth_workflow(monkeypatch):
    raw = json.loads((EXAMPLE / "challenge.json").read_text(encoding="utf-8"))
    expected = raw["expected"]
    challenge = ChallengeParser().parse_dict(raw)
    challenge["files"] = [str(EXAMPLE / "session.json")]
    responses = json.loads((EXAMPLE / "session.json").read_text(encoding="utf-8"))
    transcript_socket = TranscriptSocket(responses)

    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.assert_host_allowed",
        lambda host, port: None,
    )
    monkeypatch.setattr(
        "agents.specialists.hardware_logic.hardware_agent.socket.create_connection",
        lambda endpoint, timeout: transcript_socket,
    )

    result = HardwareLogicAgent().solve_challenge(challenge)

    assert expected["category"] == challenge["category"]
    assert expected["agent"] == result["agent_id"]
    assert expected["status"] == result["status"]
    assert expected["flag"] == result["flag"]
    assert expected["commands"] == transcript_socket.sent
