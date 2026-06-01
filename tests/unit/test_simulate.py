from simulate import SimulatedReasoner, SimulatedWebAgent
from simulate_v2 import SimulatedReasonerV2, SimulatedWebAgent as SimulatedWebAgentV2


def test_simulated_reasoner_supports_coding_agent_contract():
    reasoner = SimulatedReasoner()

    assert reasoner.is_available is True
    assert hasattr(reasoner, "generate_script")
    assert hasattr(reasoner, "fix_script")


def test_simulated_reasoner_uses_challenge_description_for_prime_script():
    reasoner = SimulatedReasoner()
    challenge = {
        "description": "Calculate the sum of all prime numbers between 1 and 100.",
    }

    script = reasoner.generate_script(challenge, "Need to write a script.")

    assert "def is_prime" in script
    assert "sum(primes)" in script


def test_simulated_web_agent_solves_sky_fixture_offline():
    result = SimulatedWebAgent().solve_challenge({"id": "sim_sky_001", "category": "web"})

    assert result["status"] == "solved"
    assert result["flag"] == "SKY-QIZK-8026"


def test_simulated_v2_reasoner_and_web_agent_support_sky_fixture():
    reasoner = SimulatedReasonerV2()
    challenge = {"id": "sim_sky_001", "category": "web"}

    assert reasoner.is_available is True
    assert reasoner.choose_next_action(challenge, None, [])["target"] == "web_agent"

    result = SimulatedWebAgentV2().solve_challenge(challenge)
    assert result["status"] == "solved"
    assert result["flag"] == "SKY-QIZK-8026"
