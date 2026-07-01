import pytest

from core.decision_engine.llm_reasoner import LLMReasoner


@pytest.fixture(autouse=True)
def clear_llm_env(monkeypatch):
    monkeypatch.delenv("NVAPI_KEY", raising=False)
    monkeypatch.delenv("NGC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def test_reasoner_routes_crypto():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "crypto_001",
        "name": "Crypto challenge",
        "category": "crypto",
        "description": "Decrypt this Caesar cipher: 'Khoor Zruog'",
        "hints": ["Try shifting the letters"],
        "tags": ["crypto", "caesar"],
        "metadata": {"cipher_type": "caesar"},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "crypto"
    assert analysis.recommended_target == "crypto_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_arms_race_wordplay_to_reverse_before_generic_host():
    reasoner = LLMReasoner(client=None)
    challenge = {
        "id": "mystery_remote",
        "name": "Script K. Iddie",
        "description": (
            "A server sends mysterious data for a multi-level challenge. "
            "Everyone is in an ARMs race. 192.0.2.10:31337"
        ),
        "url": "http://192.0.2.10:31337",
        "files": [],
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "reverse"
    assert analysis.recommended_target == "reverse_agent"


def test_reasoner_routes_sqli():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "web_001",
        "name": "SQLi challenge",
        "category": "web",
        "description": "Possible login bypass via SQL injection",
        "hints": [],
        "tags": ["web", "sqli"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "web"
    assert analysis.recommended_target == "tony_htb_sql"
    assert analysis.recommended_action == "run_tool"


def test_reasoner_routes_web():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "web_002",
        "name": "Login page",
        "category": "web",
        "description": "Inspect the login form on the page",
        "hints": [],
        "tags": ["web"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "web"
    assert analysis.recommended_target == "browser_snapshot"
    assert analysis.recommended_action == "run_tool"


def test_reasoner_routes_secure_coding():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "secure_001",
        "name": "Powergrid",
        "category": "secure_coding",
        "description": "Secure coding challenge: patch the vulnerability and verify the fix.",
        "hints": [],
        "tags": ["secure coding"],
        "metadata": {},
        "url": "http://127.0.0.1:31337",
    }

    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "secure_coding"
    assert analysis.recommended_target == "secure_coding_agent"
    assert analysis.recommended_action == "run_agent"
    assert next_action["target"] == "secure_coding_agent"


def test_reasoner_routes_auth_log_before_web_login():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "log_001",
        "name": "Auth incident",
        "category": "log",
        "description": "Review this auth log and identify the suspicious login activity.",
        "hints": [],
        "tags": [],
        "files": ["auth.log"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "log"
    assert analysis.recommended_target == "log_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_hidden_binary_artifact_to_forensics_before_reverse():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "forensics_bin_001",
        "name": "Hidden Artifact",
        "category": "forensics",
        "description": "Analyze this file for hidden flags.",
        "hints": [],
        "tags": [],
        "files": ["artifact.bin"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "forensics"
    assert analysis.recommended_target == "forensics_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_auth_text_file_to_log_agent():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "auth_text_001",
        "name": "Auth events",
        "category": "log",
        "description": "Identify which IP executed a brute force SSH attack.",
        "hints": [],
        "tags": [],
        "files": ["auth_events.txt"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "log"
    assert analysis.recommended_target == "log_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_live_ssh_rootkit_to_forensics_before_log():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "live_rootkit_001",
        "name": "Suspicious Threat",
        "category": "forensics",
        "description": (
            "Our SSH server is showing strange library linking errors and "
            "critical folders seem to be missing. Investigate hidden "
            "filesystem manipulations that could indicate a userland rootkit. "
            "Creds: root:hackthebox IP and port are 127.0.0.1:31361"
        ),
        "hints": [],
        "tags": [],
        "files": [],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "forensics"
    assert analysis.recommended_target == "forensics_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_prime_sum_task_to_coding_agent():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "prime_sum_001",
        "name": "Prime Sum",
        "category": "misc",
        "description": "Calculate the sum of all prime numbers between 1 and 100 and print it in the format CTF{result}.",
        "hints": [],
        "tags": [],
        "files": [],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "misc"
    assert analysis.recommended_target == "coding_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_routes_web_prime_product_runner_to_web_agent():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "primed_for_action",
        "name": "Primed for Action",
        "category": "web",
        "description": (
            "A list of numbers contains garbage, but two are prime. "
            "The key is obtained by multiplying the two prime numbers."
        ),
        "url": "http://154.57.164.77:30498",
        "hints": [],
        "tags": [],
        "files": [],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "web"
    assert analysis.recommended_target == "web_agent"
    assert analysis.recommended_action == "run_agent"
    assert "coding_runner_prime_product" in analysis.detected_indicators

    next_action = reasoner.choose_next_action(challenge, analysis, [])
    assert next_action["next_action"] == "run_agent"
    assert next_action["target"] == "web_agent"


def test_reasoner_routes_solidity_to_blockchain_agent():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "blockchain_001",
        "name": "Contract",
        "category": "blockchain",
        "description": "Exploit this Solidity smart contract.",
        "files": ["Setup.sol"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "blockchain"
    assert analysis.recommended_target == "blockchain_agent"
    assert next_action["target"] == "blockchain_agent"


def test_reasoner_keeps_rsa_private_key_prompt_on_crypto():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "rsa_private_key",
        "name": "RSA",
        "category": "crypto",
        "description": "Recover the RSA private key from these values and decrypt the flag.",
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "crypto"
    assert analysis.recommended_target == "crypto_agent"


def test_reasoner_keeps_json_rpc_web_prompt_on_web():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "json_rpc_web",
        "name": "JSON RPC",
        "category": "web",
        "description": "The web app exposes a JSON-RPC endpoint. Find the admin flag.",
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)

    assert analysis.category_guess == "web"
    assert analysis.recommended_target == "web_agent"


def test_reasoner_routes_hardware_logic_to_hardware_agent():
    reasoner = LLMReasoner(client=None)

    challenge = {
        "id": "low_logic",
        "name": "Low Logic",
        "category": "hardware",
        "description": "Understand how this simple chip works and give me the output.",
        "hints": [],
        "tags": [],
        "files": ["chip.jpg", "input.csv"],
        "metadata": {},
    }

    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "hardware"
    assert analysis.recommended_target == "hardware_agent"
    assert next_action["target"] == "hardware_agent"


def test_reasoner_decision_guard_keeps_hardware_from_reverse_agent():
    reasoner = LLMReasoner(client=None)
    challenge = {
        "id": "low_logic",
        "category": "reverse",
        "description": "Understand this simple chip and give me the output.",
        "files": ["chip.jpg", "input.csv"],
    }
    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert next_action["target"] == "hardware_agent"


def test_reasoner_does_not_match_gate_inside_investigate():
    reasoner = LLMReasoner(client=None)
    challenge = {
        "id": "game_loader",
        "category": "reverse",
        "description": "Investigate this compromised game and uncover the flag.",
        "files": ["Platformer 2D.exe", "Platformer 2D.pck"],
    }

    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.category_guess == "reverse"
    assert next_action["target"] == "reverse_agent"
