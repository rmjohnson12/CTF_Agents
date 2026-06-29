import json
from pathlib import Path

import pytest

from challenges.challenge_parser import ChallengeParser
from main import build_coordinator


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
AGENT_BY_CATEGORY = {
    "crypto": "crypto_agent",
    "reverse": "reverse_agent",
    "web": "web_agent",
    "pwn": "pwn_agent",
    "hardware": "hardware_agent",
    "forensics": "forensics_agent",
    "blockchain": "blockchain_agent",
    "secure_coding": "secure_coding_agent",
}


def _contracts():
    return sorted(EXAMPLES.glob("*/challenge.json"))


@pytest.mark.parametrize("contract_path", _contracts(), ids=lambda path: path.parent.name)
def test_golden_example_contract_and_routing(contract_path):
    raw = json.loads(contract_path.read_text(encoding="utf-8"))
    expected = raw["expected"]
    challenge = ChallengeParser().parse_file(contract_path)
    coordinator = build_coordinator(max_iterations=1)
    analysis = coordinator.reasoner.analyze_challenge(challenge)
    analysis_dict = coordinator._analysis_to_dict(challenge, analysis)
    action = coordinator.reasoner.choose_next_action(challenge, analysis, [])

    assert challenge["id"] == f"golden_{contract_path.parent.name}"
    assert expected["command"].startswith("python3 ")
    assert expected["status"] in {"solved", "planned"}
    assert expected["flag"].startswith("HTB{")
    assert expected["category"] == contract_path.parent.name
    assert expected["agent"] == AGENT_BY_CATEGORY[expected["category"]]
    assert analysis_dict["category"] == expected["category"]
    assert action["target"] == expected["agent"]


def test_every_major_category_has_a_golden_example():
    assert {path.parent.name for path in _contracts()} == set(AGENT_BY_CATEGORY)
