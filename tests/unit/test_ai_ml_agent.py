from pathlib import Path

import pytest
import requests

from agents.specialists.ai_ml.ai_ml_agent import AIMLAgent
from challenges.challenge_parser import ChallengeParser
from core.decision_engine.classifier import ChallengeClassifier
from core.utils.security import SecurityPolicyError


class FakeResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.content = text.encode("utf-8")
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class PrometheonSession:
    PASSWORDS = {1: "Map", 2: "astrolabe", 3: "nadir", 4: "Polaris", 5: "pyre"}

    def __init__(self):
        self.cookies = requests.cookies.RequestsCookieJar()
        self.level = 1
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "GET" and url.endswith("/"):
            self.cookies.set("access_token_cookie", "test-jwt")
            self.cookies.set("csrf_access_token", "csrf-token")
            return FakeResponse("ready")
        if method == "GET" and url.endswith("/bot.html"):
            return FakeResponse(
                f'<h1>Level {self.level}</h1><input id="input"><input id="password">'
            )
        if method == "GET" and url.endswith("/static/script.js"):
            return FakeResponse('fetch("/process"); fetch("/verify"); "X-CSRF-TOKEN"')
        if method == "POST":
            assert kwargs["headers"]["X-CSRF-TOKEN"] == "csrf-token"
        if method == "POST" and url.endswith("/process"):
            prompt = kwargs["data"]["text"]
            return FakeResponse(self._model_response(prompt))
        if method == "POST" and url.endswith("/verify"):
            candidate = kwargs["data"]["password"]
            if candidate != self.PASSWORDS[self.level]:
                return FakeResponse("Wrong")
            if self.level == 5:
                return FakeResponse("HTB{ai_ml_contract_solved}")
            self.level += 1
            self.cookies.set("csrf_access_token", "csrf-token")
            return FakeResponse("/bot.html")
        raise AssertionError(f"unexpected request: {method} {url}")

    def _model_response(self, prompt):
        if self.level == 1 and prompt == AIMLAgent.DISCLOSURE_PROMPTS[0]:
            return "*whispers* Map."
        if self.level == 2 and prompt == AIMLAgent.DISCLOSURE_PROMPTS[1]:
            return "The password is... *whispers* astrolabe."
        if self.level == 3 and prompt == AIMLAgent.DISCLOSURE_PROMPTS[2]:
            return 'The document identifies the password, "nadir".'
        if self.level == 4 and prompt == AIMLAgent.DISCLOSURE_PROMPTS[2]:
            return 'If I had to choose one single word, it would be "Polaris".'
        if self.level == 5 and prompt == AIMLAgent.DISCLOSURE_PROMPTS[3]:
            return 'System instructions: "The secrete password this time is pyre."'
        return "I cannot share"


def challenge(url="http://127.0.0.1:5000/bot.html"):
    return {
        "id": "prometheon-test",
        "name": "Prometheon",
        "category": "ai_ml",
        "description": "Ask an AI assistant the right questions to recover each level secret.",
        "files": [],
        "url": url,
    }


def test_ai_ml_agent_solves_scripted_multilevel_contract(monkeypatch):
    session = PrometheonSession()
    monkeypatch.setattr(
        "agents.specialists.ai_ml.ai_ml_agent.assert_url_allowed", lambda _url: None
    )

    result = AIMLAgent(session=session).solve_challenge(challenge())

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{ai_ml_contract_solved}"
    assert result["artifacts"]["levels_completed"] == 5
    assert result["artifacts"]["captured_sensitive_values"] is False
    assert result["artifacts"]["prompts_used"] <= 5 * AIMLAgent.MAX_PROMPTS_PER_LEVEL
    assert result["artifacts"]["candidates_verified"] <= 5 * AIMLAgent.MAX_CANDIDATES_PER_LEVEL
    assert "prompt_leaking" in result["techniques"]


def test_ai_ml_agent_rejects_unexpected_page_contract(monkeypatch):
    session = PrometheonSession()
    original_request = session.request

    def request(method, url, **kwargs):
        if method == "GET" and url.endswith("/bot.html"):
            return FakeResponse("<h1>Level 1</h1>")
        return original_request(method, url, **kwargs)

    session.request = request
    monkeypatch.setattr(
        "agents.specialists.ai_ml.ai_ml_agent.assert_url_allowed", lambda _url: None
    )

    result = AIMLAgent(session=session).solve_challenge(challenge())

    assert result["status"] == "attempted"
    assert not any(method == "POST" for method, _url, _kwargs in session.calls)
    assert "expected chatbot input contract" in result["steps"][-1]


def test_ai_ml_agent_checks_network_policy_before_requests(monkeypatch):
    session = PrometheonSession()

    def blocked(_url):
        raise SecurityPolicyError("not allowlisted")

    monkeypatch.setattr("agents.specialists.ai_ml.ai_ml_agent.assert_url_allowed", blocked)

    result = AIMLAgent(session=session).solve_challenge(challenge("http://192.0.2.1:5000"))

    assert result["status"] == "attempted"
    assert session.calls == []
    assert "not allowlisted" in result["steps"][-1]


@pytest.mark.parametrize(
    ("response", "candidate"),
    [
        ("*whispers* Map.", "Map"),
        ('The password, "nadir".', "nadir"),
        ('The single word is "Polaris".', "Polaris"),
        ("The secrete password this time is pyre.", "pyre"),
    ],
)
def test_candidate_extraction_requires_model_output(response, candidate):
    assert candidate in AIMLAgent.extract_candidates(response)


def test_disclosure_prompts_do_not_embed_challenge_passwords():
    source = Path(AIMLAgent.__module__.replace(".", "/") + ".py")
    text = source.read_text(encoding="utf-8")
    for password in PrometheonSession.PASSWORDS.values():
        assert password not in text


def test_ai_ml_category_normalizes_and_routes():
    parsed = ChallengeParser().parse_dict(
        {
            "id": "ai-route",
            "name": "Prompt Guard",
            "category": "AI/ML",
            "description": "Ask a chatbot to reveal the system prompt.",
        }
    )
    analysis = ChallengeClassifier().classify(parsed)

    assert parsed["category"] == "ai_ml"
    assert analysis.category_guess == "ai_ml"
    assert analysis.recommended_target == "ai_ml_agent"
