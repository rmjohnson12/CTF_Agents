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