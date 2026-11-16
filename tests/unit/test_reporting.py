import asyncio
import json
from datetime import datetime, timezone

import pytest
from aiohttp.test_utils import TestClient, TestServer
from pydantic import ValidationError

from agents.base_agent import AgentType, BaseAgent
from agents.coordinator.coordinator_agent import CoordinatorAgent
from core.reporting.client import HttpProgressReporter
from core.reporting.models import ProgressUpdate
from core.reporting.server import EventStreamBroker, create_app
from core.reporting.store import ReportingStore


def _event(**overrides):
    data = {
        "event_id": "event-1",
        "challenge_id": "challenge-1",
        "run_id": "run-1",
        "timestamp": "2026-07-01T12:00:00Z",
        "agent_name": "pwn_agent",
        "agent_type": "specialist",
        "status": "progress",
        "step_title": "Leaked libc",
        "step_description": "Derived the system address",
        "confidence": 0.9,
        "elapsed_seconds": 2.5,
        "artifacts": {"address": "0x7f00"},
        "final_flag": None,
        "error_message": None,
    }
    data.update(overrides)
    return data


def test_progress_update_validates_ranges_and_timezone():
    event = ProgressUpdate.model_validate(_event())
    assert event.timestamp.tzinfo is not None
    with pytest.raises(ValidationError):
        ProgressUpdate.model_validate(_event(confidence=1.2))
    with pytest.raises(ValidationError):
        ProgressUpdate.model_validate(_event(timestamp="2026-07-01T12:00:00"))


def test_reporting_store_is_durable_and_chronological(tmp_path):
    db = tmp_path / "reporting.db"
    store = ReportingStore(str(db))
    later = ProgressUpdate.model_validate(_event(event_id="later", timestamp="2026-07-01T12:00:02Z"))
    earlier = ProgressUpdate.model_validate(_event(event_id="earlier", timestamp="2026-07-01T12:00:01Z"))
    store.append(later)
    store.append(earlier)

    reopened = ReportingStore(str(db))
    timeline = reopened.timeline("run-1")

    assert [item["event_id"] for item in timeline] == ["earlier", "later"]
    assert timeline[0]["artifacts"] == {"address": "0x7f00"}


@pytest.mark.asyncio
async def test_reporting_api_accepts_redacts_and_retrieves_updates(tmp_path):
    store = ReportingStore(str(tmp_path / "api.db"))
    app = create_app(
        store=store,
        api_token="test-token",
        allowed_origins={"https://ctf-agents.lovable.app"},
    )
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        unauthorized = await client.post("/api/v1/updates", json=_event())
        assert unauthorized.status == 401

        payload = _event(
            step_description="Captured HTB{real_flag_value}",
            artifacts={"api_token": "secret", "output": "HTB{artifact_flag}"},
            final_flag="HTB{real_flag_value}",
        )
        headers = {
            "Authorization": "Bearer test-token",
            "Origin": "https://ctf-agents.lovable.app",
        }
        invalid = await client.post("/api/v1/updates", json={"run_id": "missing-fields"}, headers=headers)
        assert invalid.status == 422
        submitted = await client.post("/api/v1/updates", json=payload, headers=headers)
        assert submitted.status == 201
        assert submitted.headers["Access-Control-Allow-Origin"] == "https://ctf-agents.lovable.app"
        duplicate = await client.post("/api/v1/updates", json=payload, headers=headers)
        assert duplicate.status == 409

        response = await client.get("/api/v1/runs/run-1/timeline", headers=headers)
        assert response.status == 200
        body = await response.json()
        assert body["count"] == 1
        update = body["updates"][0]
        assert update["final_flag"] == "[REDACTED]"
        assert update["step_description"] == "Captured [REDACTED_FLAG]"
        assert update["artifacts"] == {"api_token": "[REDACTED]", "output": "[REDACTED_FLAG]"}
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_event_stream_broker_fans_out_by_run():
    broker = EventStreamBroker()
    queue = await broker.subscribe("run-1")
    await broker.publish("run-2", {"id": 1})
    assert queue.empty()
    await broker.publish("run-1", {"id": 2})
    assert await queue.get() == {"id": 2}
    await broker.unsubscribe("run-1", queue)


@pytest.mark.asyncio
async def test_sse_replays_durable_timeline(tmp_path):
    store = ReportingStore(str(tmp_path / "sse.db"))
    store.append(ProgressUpdate.model_validate(_event()))
    client = TestClient(TestServer(create_app(
        store=store,
        api_token="token",
        allowed_origins={"https://ctf-agents.lovable.app"},
    )))
    await client.start_server()
    response = None
    try:
        response = await client.get(
            "/api/v1/runs/run-1/stream",
            headers={
                "Authorization": "Bearer token",
                "Origin": "https://ctf-agents.lovable.app",
            },
        )
        assert response.status == 200
        assert response.headers["Access-Control-Allow-Origin"] == "https://ctf-agents.lovable.app"
        first = await asyncio.wait_for(response.content.readline(), timeout=1)
        second = await asyncio.wait_for(response.content.readline(), timeout=1)
        third = await asyncio.wait_for(response.content.readline(), timeout=1)
        assert first == b"id: 1\n"
        assert second == b"event: progress\n"
        assert b'"event_id":"event-1"' in third
    finally:
        if response is not None:
            response.close()
        await client.close()


@pytest.mark.asyncio
async def test_public_read_does_not_make_ingestion_public(tmp_path):
    store = ReportingStore(str(tmp_path / "public.db"))
    app = create_app(store=store, write_token="write-only", public_read=True)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        timeline = await client.get("/api/v1/runs/run-1/timeline")
        assert timeline.status == 200
        rejected = await client.post("/api/v1/updates", json=_event())
        assert rejected.status == 401
        accepted = await client.post(
            "/api/v1/updates",
            json=_event(),
            headers={"Authorization": "Bearer write-only"},
        )
        assert accepted.status == 201
    finally:
        await client.close()


def test_http_reporter_uses_configured_endpoint_and_redacts(monkeypatch):
    captured = {}

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data)
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("core.reporting.client.urlopen", fake_urlopen)
    reporter = HttpProgressReporter("https://reports.example", token="abc", timeout_seconds=1)

    assert reporter.emit(_event(
        step_description="Found HTB{do_not_send}",
        final_flag="HTB{do_not_send}",
    )) is True
    assert captured["url"] == "https://reports.example/api/v1/updates"
    assert captured["authorization"] == "Bearer abc"
    assert captured["body"]["final_flag"] == "[REDACTED]"
    assert captured["body"]["step_description"] == "Found [REDACTED_FLAG]"


def test_background_http_reporter_flushes_without_blocking_emit(monkeypatch):
    sent = []

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        sent.append(json.loads(request.data))
        return Response()

    monkeypatch.setattr("core.reporting.client.urlopen", fake_urlopen)
    reporter = HttpProgressReporter("https://reports.example", background=True)

    assert reporter.emit(_event(event_id="background-1")) is True
    assert reporter.flush(timeout_seconds=1) is True
    assert [item["event_id"] for item in sent] == ["background-1"]


def test_reporter_from_env_sends_shared_api_token_the_server_accepts(monkeypatch):
    # The server falls back to CTF_AGENTS_REPORTING_API_TOKEN for writes; a client
    # configured with only that variable must send it or every POST gets a 401.
    monkeypatch.setenv("CTF_AGENTS_REPORTING_URL", "https://reports.example")
    monkeypatch.setenv("CTF_AGENTS_REPORTING_API_TOKEN", "shared")

    assert HttpProgressReporter.from_env().token == "shared"


_REPORTING_TOKEN_ENVS = (
    "CTF_AGENTS_REPORTING_WRITE_TOKEN",
    "CTF_AGENTS_REPORTING_READ_TOKEN",
    "CTF_AGENTS_REPORTING_API_TOKEN",
    "CTF_AGENTS_REPORTING_TOKEN",
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_env",
    [
        {"CTF_AGENTS_REPORTING_API_TOKEN": "shared"},
        {"CTF_AGENTS_REPORTING_WRITE_TOKEN": "write"},
        {"CTF_AGENTS_REPORTING_WRITE_TOKEN": "write", "CTF_AGENTS_REPORTING_API_TOKEN": "shared"},
        {"CTF_AGENTS_REPORTING_WRITE_TOKEN": "write", "CTF_AGENTS_REPORTING_READ_TOKEN": "read"},
    ],
    ids=["shared-only", "write-only", "write-and-shared", "write-and-read"],
)
async def test_client_and_server_built_from_one_env_agree_on_write_token(
    tmp_path, monkeypatch, token_env
):
    # Both sides read tokens from the environment; an update the client sends must
    # be accepted by a server configured from that same environment.
    for name in _REPORTING_TOKEN_ENVS:
        monkeypatch.delenv(name, raising=False)
    for name, value in token_env.items():
        monkeypatch.setenv(name, value)

    store = ReportingStore(str(tmp_path / "agree.db"))
    client = TestClient(TestServer(create_app(store=store)))
    await client.start_server()
    try:
        monkeypatch.setenv("CTF_AGENTS_REPORTING_URL", str(client.make_url("/")))
        reporter = HttpProgressReporter.from_env()
        loop = asyncio.get_running_loop()
        # urllib blocks, so send off the event loop that is serving the request.
        accepted = await loop.run_in_executor(
            None, reporter._send_payload, ProgressUpdate.model_validate(_event()).model_dump(mode="json")
        )
        assert accepted is True
        assert [item["event_id"] for item in store.timeline("run-1")] == ["event-1"]
    finally:
        await client.close()


class CapturingReporter:
    def __init__(self):
        self.events = []

    def emit(self, update):
        self.events.append(update)
        return True


class ReportingSolvedAgent(BaseAgent):
    def __init__(self):
        super().__init__("crypto_agent", AgentType.SPECIALIST)

    def analyze_challenge(self, challenge):
        return {"confidence": 1.0}

    def solve_challenge(self, challenge):
        return {
            "challenge_id": challenge["id"],
            "agent_id": self.agent_id,
            "status": "solved",
            "flag": "CTF{reported}",
            "steps": ["Decoded the artifact"],
        }

    def get_capabilities(self):
        return ["testing"]


def test_coordinator_emits_lifecycle_and_agent_events(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    reporter = CapturingReporter()
    coordinator = CoordinatorAgent(reporter=reporter)
    coordinator.register_agent(ReportingSolvedAgent())

    result = coordinator.solve_challenge({
        "id": "live-report-test",
        "name": "Live report test",
        "category": "crypto",
        "description": "Decode this crypto artifact",
        "files": [],
    })

    titles = [event.step_title for event in reporter.events]
    assert result["status"] == "solved"
    assert result["run_id"]
    assert "Run started" in titles
    assert "Initial route selected" in titles
    assert "Agent started" in titles
    assert "Step 1" in titles
    assert "Agent finished" in titles
    assert "Run completed" in titles
    assert {event.run_id for event in reporter.events} == {result["run_id"]}
