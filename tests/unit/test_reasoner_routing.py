from core.decision_engine.llm_reasoner import LLMReasoner


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
