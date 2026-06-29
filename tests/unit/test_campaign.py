import sqlite3
import json

from core.campaign import AttemptStore, CampaignRunner
from core.campaign.providers import LocalChallengeProvider


class FakeProvider:
    name = "fake"

    def __init__(self, challenges):
        self.challenges = challenges

    def list_challenges(self):
        return self.challenges


def test_campaign_records_success_and_failed_technique(tmp_path):
    store = AttemptStore(str(tmp_path / "attempts.db"))
    challenges = [
        {"id": "one", "name": "One", "description": "x", "category": "web"},
        {"id": "two", "name": "Two", "description": "x", "category": "crypto"},
    ]

    def solve(challenge):
        if challenge["id"] == "one":
            return {"status": "solved", "flag": "CTF{one}", "history": []}
        return {
            "status": "attempted",
            "steps": ["No valid decode found"],
            "history": [{
                "agent_id": "crypto_agent",
                "status": "failed",
                "steps": ["Base64 decoding did not yield a flag"],
                "routing": {"execution_type": "agent", "selected_target": "crypto_agent"},
                "artifacts": {"decoded_text": "hello"},
            }],
        }

    summary = CampaignRunner(FakeProvider(challenges), solve, store).run(max_attempts=2)

    assert summary.solved == 1
    assert summary.failed == 1
    failures = store.recent_failures("fake", "two")
    assert failures[0]["failure_reason"] == "No valid decode found"
    with sqlite3.connect(store.db_path) as conn:
        technique = conn.execute(
            "SELECT actor, status, failure_reason, artifact_keys FROM technique_attempts"
        ).fetchone()
    assert technique == (
        "crypto_agent",
        "failed",
        "Base64 decoding did not yield a flag",
        '["decoded_text"]',
    )


def test_campaign_skips_solved_and_respects_attempt_cap(tmp_path):
    store = AttemptStore(str(tmp_path / "attempts.db"))
    challenge = {"id": "one", "name": "One", "description": "x", "category": "misc"}
    calls = []

    def solve(_challenge):
        calls.append(1)
        return {"status": "solved", "flag": "CTF{one}", "history": []}

    runner = CampaignRunner(FakeProvider([challenge]), solve, store)
    first = runner.run(max_attempts=1)
    second = runner.run(max_attempts=1)

    assert first.solved == 1
    assert second.skipped == 1
    assert len(calls) == 1


def test_campaign_captures_solver_exception(tmp_path):
    store = AttemptStore(str(tmp_path / "attempts.db"))
    challenge = {"id": "boom", "name": "Boom", "description": "x", "category": "misc"}

    def solve(_challenge):
        raise RuntimeError("tool exploded")

    summary = CampaignRunner(FakeProvider([challenge]), solve, store).run()

    assert summary.failed == 1
    assert "RuntimeError: tool exploded" in store.recent_failures("fake", "boom")[0]["failure_reason"]


def test_local_provider_reads_supported_solve_entries_from_manifest(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"benchmarks": [
        {"mode": "solve", "challenge": {"id": "ready", "name": "Ready", "description": "x"}},
        {"mode": "route", "challenge": {"id": "route", "name": "Route", "description": "x"}},
        {
            "mode": "solve",
            "generated_files": [{"name": "artifact"}],
            "challenge": {"id": "generated", "name": "Generated", "description": "x"},
        },
    ]}))

    challenges = LocalChallengeProvider(str(manifest)).list_challenges()

    assert [challenge["id"] for challenge in challenges] == ["ready"]


def test_campaign_summary_exports_machine_readable_metrics_and_markdown(tmp_path):
    store = AttemptStore(str(tmp_path / "attempts.db"))
    challenge = {"id": "metric", "name": "Metric", "description": "x", "category": "web"}

    def solve(_challenge):
        return {
            "status": "attempted",
            "iterations": 2,
            "steps": ["No flag found"],
            "routing_summary": {"selected_target": "web_agent"},
            "history": [
                {
                    "agent_id": "web_agent",
                    "status": "attempted",
                    "routing": {"execution_type": "agent", "selected_target": "web_agent"},
                },
                {
                    "status": "failed",
                    "routing": {"execution_type": "tool", "selected_target": "browser_snapshot"},
                },
            ],
        }

    summary = CampaignRunner(FakeProvider([challenge]), solve, store).run()
    payload = summary.to_dict()

    assert payload["attempted"] == 1
    assert payload["solve_rate"] == 0.0
    assert payload["iterations"] == 2
    assert payload["tools_invoked"] == 1
    assert payload["fallback_count"] == 1
    assert payload["challenges"][0]["agent_selected"] == "web_agent"
    assert payload["challenges"][0]["failure_reason"] == "No flag found"
    markdown = summary.to_markdown()
    assert "# CTF_Agents Benchmark Summary" in markdown
    assert "| metric | attempted | web_agent |" in markdown
