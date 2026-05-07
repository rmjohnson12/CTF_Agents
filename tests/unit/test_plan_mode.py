"""
Tests for --plan dry-run mode in ask.py and main.py.

Verifies:
  - _print_plan prints expected fields without invoking any agents
  - ask.py main() exits before solve_challenge when --plan is passed
  - main.py main() exits before solve_challenge when --plan is passed
  - Both handle missing user_input / missing challenge path gracefully
"""

import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJ_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = PROJ_ROOT / "challenges" / "evaluation"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analysis(category="crypto", confidence=0.85, indicators=None, reasoning="test reason"):
    if indicators is None:
        indicators = ["base64", "encoded"]
    return {
        "challenge_id": "test_001",
        "category": category,
        "difficulty": "medium",
        "assigned_agents": ["crypto_agent"],
        "strategy": {
            "action": "run_agent",
            "target": "crypto_agent",
            "reasoning": reasoning,
            "detected_indicators": indicators,
        },
        "confidence": confidence,
    }


def _make_next_action(action="run_agent", target="crypto_agent", reasoning="looks like crypto"):
    return {
        "next_action": action,
        "target": target,
        "reasoning": reasoning,
    }


def _make_challenge(name="Test", cid="test_001", category="crypto"):
    return {"id": cid, "name": name, "category": category, "description": "test"}


# ---------------------------------------------------------------------------
# _print_plan unit tests
# ---------------------------------------------------------------------------

class TestPrintPlan:
    def _call(self, challenge=None, analysis=None, next_action=None, tracker=None):
        from ask import _print_plan
        challenge = challenge or _make_challenge()
        analysis = analysis or _make_analysis()
        next_action = next_action or _make_next_action()
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_plan(challenge, analysis, next_action, tracker)
        return buf.getvalue()

    def test_prints_challenge_name_and_id(self):
        out = self._call()
        assert "Test" in out
        assert "test_001" in out

    def test_prints_category_and_confidence(self):
        out = self._call()
        assert "crypto" in out
        assert "85%" in out

    def test_prints_indicators(self):
        out = self._call()
        assert "base64" in out
        assert "encoded" in out

    def test_prints_routing_with_target(self):
        out = self._call()
        assert "run_agent" in out
        assert "crypto_agent" in out

    def test_prints_stop_when_no_target(self):
        next_action = {"next_action": "stop", "target": "none"}
        out = self._call(next_action=next_action)
        assert "no confident path" in out

    def test_prints_reasoning_from_next_action(self):
        out = self._call()
        assert "looks like crypto" in out

    def test_falls_back_to_analysis_reasoning_when_next_action_has_none(self):
        next_action = _make_next_action(reasoning=None)
        out = self._call(next_action=next_action)
        assert "test reason" in out

    def test_no_agents_invoked_message(self):
        out = self._call()
        assert "No agents or tools were invoked" in out

    def test_perf_hint_shown_when_tracker_has_history(self):
        tracker = MagicMock()
        tracker.get_routing_hint.return_value = ("crypto_agent", 0.75)
        out = self._call(tracker=tracker)
        assert "75%" in out
        assert "crypto_agent" in out

    def test_perf_hint_no_history_message(self):
        tracker = MagicMock()
        tracker.get_routing_hint.return_value = None
        out = self._call(tracker=tracker)
        assert "No history yet" in out

    def test_no_perf_hint_section_when_tracker_is_none(self):
        out = self._call(tracker=None)
        assert "Perf hint" not in out

    def test_empty_indicators_shows_none(self):
        analysis = _make_analysis(indicators=[])
        out = self._call(analysis=analysis)
        assert "none" in out


# ---------------------------------------------------------------------------
# ask.py --plan integration: solve_challenge must NOT be called
# ---------------------------------------------------------------------------

class TestAskPlanMode:
    """ask.py main() must exit before solve_challenge when --plan is given."""

    def test_plan_flag_prevents_solve_challenge(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys, "argv",
            ["ask.py", "--plan", "decode the hex string 4354467b74657374 from the challenge"],
        )

        with patch(
            "agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge"
        ) as mock_solve:
            import ask
            ask.main()

        mock_solve.assert_not_called()

    def test_plan_flag_prints_plan_header(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys, "argv",
            ["ask.py", "--plan", "decode the hex string from this crypto challenge"],
        )

        with patch("agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge"):
            import ask
            ask.main()

        captured = capsys.readouterr()
        assert "=== Plan (dry run) ===" in captured.out

    def test_plan_flag_no_instruction_prints_usage(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["ask.py", "--plan"])

        with patch("agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge"):
            import ask
            ask.main()

        captured = capsys.readouterr()
        assert "Usage" in captured.out

    def test_no_plan_flag_calls_solve_challenge(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            sys, "argv",
            ["ask.py", "decode the hex string from this crypto challenge"],
        )

        with patch(
            "agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge",
            return_value={"status": "solved", "flag": "CTF{x}", "steps": []},
        ) as mock_solve:
            import ask
            ask.main()

        mock_solve.assert_called_once()


# ---------------------------------------------------------------------------
# main.py --plan integration
# ---------------------------------------------------------------------------

class TestMainPlanMode:
    """main.py --plan must print plan and return 0 without calling solve_challenge."""

    def _run(self, argv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import main as main_module
        return main_module.main(argv)

    def test_plan_flag_prevents_solve_challenge(self, tmp_path, monkeypatch):
        json_path = str(EVAL_DIR / "eval_crypto_decimal_ctfd.json")
        with patch(
            "agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge"
        ) as mock_solve:
            rc = self._run(["main.py", json_path, "--plan"], tmp_path, monkeypatch)

        assert rc == 0
        mock_solve.assert_not_called()

    def test_plan_flag_prints_plan_header(self, tmp_path, monkeypatch, capsys):
        json_path = str(EVAL_DIR / "eval_crypto_decimal_ctfd.json")
        self._run(["main.py", json_path, "--plan"], tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "=== Plan (dry run) ===" in captured.out

    def test_plan_flag_shows_challenge_name(self, tmp_path, monkeypatch, capsys):
        json_path = str(EVAL_DIR / "eval_crypto_decimal_ctfd.json")
        self._run(["main.py", json_path, "--plan"], tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "Numbers Game" in captured.out

    def test_no_plan_flag_calls_solve_challenge(self, tmp_path, monkeypatch):
        json_path = str(EVAL_DIR / "eval_crypto_decimal_ctfd.json")
        with patch(
            "agents.coordinator.coordinator_agent.CoordinatorAgent.solve_challenge",
            return_value={"status": "attempted", "flag": None, "steps": []},
        ) as mock_solve:
            rc = self._run(["main.py", json_path], tmp_path, monkeypatch)

        mock_solve.assert_called_once()

    def test_plan_with_log_challenge(self, tmp_path, monkeypatch, capsys):
        json_path = str(EVAL_DIR / "eval_log_webaccess.json")
        self._run(["main.py", json_path, "--plan"], tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "=== Plan (dry run) ===" in captured.out
        assert "Who's Hammering the Server?" in captured.out
