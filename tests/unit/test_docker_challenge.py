from pathlib import Path

import pytest

from agents.support.docker_agent import DockerChallengeAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from core.decision_engine.llm_reasoner import LLMReasoner
from tools.common.result import ToolResult
from tools.web.docker_challenge import DockerChallengeTool


class FakeDockerRunner:
    def __init__(self):
        self.commands = []

    def run(self, argv, *, timeout_s=None, cwd=None, env=None):
        self.commands.append(list(argv))
        if argv[:2] == ["docker", "build"]:
            return ToolResult(argv, "built", "", 0, False, 0.01)
        if argv[:2] == ["docker", "run"]:
            return ToolResult(argv, "abc123def456\n", "", 0, False, 0.01)
        if argv[:2] == ["docker", "port"]:
            return ToolResult(argv, "3000/tcp -> 127.0.0.1:49153\n", "", 0, False, 0.01)
        if argv[:2] == ["docker", "logs"]:
            return ToolResult(argv, "ready", "", 0, False, 0.01)
        if argv[:3] == ["docker", "rm", "-f"]:
            return ToolResult(argv, "removed", "", 0, False, 0.01)
        return ToolResult(argv, "", "unexpected command", 1, False, 0.01)


def _docker_context(tmp_path: Path) -> Path:
    context = tmp_path / "challenge"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM node:20-alpine\nEXPOSE 3000\n")
    return context


def test_docker_tool_finds_context_from_parent_dir(tmp_path):
    context = _docker_context(tmp_path)
    tool = DockerChallengeTool(runner=FakeDockerRunner())

    assert tool.find_context([str(tmp_path)]) == context


def test_docker_tool_requires_explicit_opt_in(tmp_path, monkeypatch):
    context = _docker_context(tmp_path)
    tool = DockerChallengeTool(runner=FakeDockerRunner())
    monkeypatch.delenv("CTF_AGENTS_ALLOW_DOCKER", raising=False)

    with pytest.raises(PermissionError):
        tool.launch(str(context))


def test_docker_tool_launches_and_maps_localhost_url(tmp_path, monkeypatch):
    context = _docker_context(tmp_path)
    runner = FakeDockerRunner()
    tool = DockerChallengeTool(runner=runner)
    monkeypatch.setenv("CTF_AGENTS_ALLOW_DOCKER", "1")
    monkeypatch.setattr(DockerChallengeTool, "_wait_for_http", lambda self_or_url, *args, **kwargs: None)

    result = tool.launch(str(context))

    assert result.url == "http://127.0.0.1:49153"
    assert result.container_id == "abc123def456"
    assert any(cmd[:2] == ["docker", "build"] for cmd in runner.commands)
    assert any(cmd[:2] == ["docker", "run"] for cmd in runner.commands)


def test_docker_agent_reports_disabled_launch(tmp_path, monkeypatch):
    context = _docker_context(tmp_path)
    agent = DockerChallengeAgent(docker_tool=DockerChallengeTool(runner=FakeDockerRunner()))
    monkeypatch.delenv("CTF_AGENTS_ALLOW_DOCKER", raising=False)

    result = agent.solve_challenge({"id": "docker_1", "files": [str(context)]})

    assert result["status"] == "attempted"
    assert result["artifacts"]["docker_allowed"] is False
    assert "CTF_AGENTS_ALLOW_DOCKER=1" in result["steps"][-1]


def test_reasoner_routes_docker_context_to_docker_agent(tmp_path):
    context = _docker_context(tmp_path)
    reasoner = LLMReasoner(client=None)
    reasoner.client = None

    analysis = reasoner.analyze_challenge(
        {
            "id": "docker_2",
            "category": "web",
            "description": "Solve this local Docker web challenge.",
            "files": [str(context)],
        }
    )

    assert analysis.recommended_target == "docker_agent"
    assert analysis.recommended_action == "run_agent"


def test_reasoner_pivots_from_docker_agent_to_web_agent():
    reasoner = LLMReasoner(client=None)
    reasoner.client = None
    analysis = reasoner.analyze_challenge(
        {
            "id": "docker_3",
            "category": "web",
            "description": "Solve this Docker challenge.",
        }
    )

    next_action = reasoner.choose_next_action(
        {"id": "docker_3", "category": "web", "description": "Solve this Docker challenge."},
        analysis,
        [
            {
                "agent_id": "docker_agent",
                "status": "attempted",
                "artifacts": {"docker_target_url": "http://127.0.0.1:49153"},
            }
        ],
    )

    assert next_action["next_action"] == "run_agent"
    assert next_action["target"] == "web_agent"


def test_coordinator_hydrates_url_from_docker_fact():
    challenge = {"id": "docker_4", "category": "web", "description": "Docker web challenge"}
    CoordinatorAgent._hydrate_challenge_from_facts(
        challenge,
        [{"key": "docker_target_url", "value": "http://127.0.0.1:49153"}],
    )

    assert challenge["url"] == "http://127.0.0.1:49153"


def test_docker_agent_cleanup_uses_container_id(tmp_path):
    runner = FakeDockerRunner()
    agent = DockerChallengeAgent(docker_tool=DockerChallengeTool(runner=runner))
    steps = []

    agent.cleanup_artifacts({"docker_container_id": "abc123def456"}, steps)

    assert ["docker", "rm", "-f", "abc123def456"] in runner.commands
    assert "Cleaned up Docker container" in steps[-1]
