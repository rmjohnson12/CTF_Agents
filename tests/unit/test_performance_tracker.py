"""
Unit tests for PerformanceTracker.
"""

import os
import tempfile
import pytest

from core.decision_engine.performance_tracker import PerformanceTracker


@pytest.fixture
def tracker(tmp_path):
    db = str(tmp_path / "perf.db")
    return PerformanceTracker(db_path=db)


def test_record_and_success_rate(tracker):
    tracker.record_outcome("crypto_agent", "crypto", "chal1", "solved")
    tracker.record_outcome("crypto_agent", "crypto", "chal2", "solved")
    tracker.record_outcome("crypto_agent", "crypto", "chal3", "failed")

    rate = tracker.get_success_rate("crypto_agent", "crypto")
    assert abs(rate - 2 / 3) < 1e-6


def test_success_rate_no_history(tracker):
    assert tracker.get_success_rate("nonexistent_agent") == 0.0


def test_success_rate_without_category_filter(tracker):
    tracker.record_outcome("web_agent", "web", "w1", "solved")
    tracker.record_outcome("web_agent", "crypto", "w2", "failed")

    # Without category filter: 1 solved out of 2
    assert tracker.get_success_rate("web_agent") == 0.5


def test_get_best_agent_for(tracker):
    for i in range(3):
        tracker.record_outcome("crypto_agent", "crypto", f"c{i}", "solved")
    tracker.record_outcome("coding_agent", "crypto", "c3", "failed")
    tracker.record_outcome("coding_agent", "crypto", "c4", "failed")

    best = tracker.get_best_agent_for("crypto", min_runs=2)
    assert best == "crypto_agent"


def test_get_best_agent_min_runs_threshold(tracker):
    # Only 1 run — below min_runs=2 threshold
    tracker.record_outcome("crypto_agent", "crypto", "c1", "solved")
    assert tracker.get_best_agent_for("crypto", min_runs=2) is None


def test_get_best_agent_no_data(tracker):
    assert tracker.get_best_agent_for("forensics") is None


def test_get_stats_aggregation(tracker):
    tracker.record_outcome("web_agent", "web", "w1", "solved", duration_sec=5.0)
    tracker.record_outcome("web_agent", "web", "w2", "failed", duration_sec=3.0)
    tracker.record_outcome("web_agent", "web", "w3", "attempted", duration_sec=1.0)

    stats = tracker.get_stats(agent_id="web_agent", category="web")
    assert len(stats) == 1
    row = stats[0]
    assert row["total"] == 3
    assert row["solved"] == 1
    assert row["failed"] == 1
    assert row["attempted"] == 1
    assert abs(row["success_rate"] - 1 / 3) < 1e-3
    assert abs(row["avg_duration_sec"] - 3.0) < 1e-3


def test_get_routing_hint_returns_none_without_history(tracker):
    assert tracker.get_routing_hint("web") is None


def test_get_routing_hint_returns_best(tracker):
    for i in range(4):
        tracker.record_outcome("forensics_agent", "forensics", f"f{i}", "solved")

    hint = tracker.get_routing_hint("forensics")
    assert hint is not None
    agent_id, rate = hint
    assert agent_id == "forensics_agent"
    assert rate == 1.0


def test_duration_recorded(tracker):
    tracker.record_outcome("net_agent", "networking", "n1", "solved", duration_sec=12.5)
    stats = tracker.get_stats(agent_id="net_agent")
    assert stats[0]["avg_duration_sec"] == 12.5


def test_multiple_agents_best_selected(tracker):
    # Agent A: 2/3 solve rate
    tracker.record_outcome("agent_a", "misc", "m1", "solved")
    tracker.record_outcome("agent_a", "misc", "m2", "solved")
    tracker.record_outcome("agent_a", "misc", "m3", "failed")
    # Agent B: 1/3 solve rate
    tracker.record_outcome("agent_b", "misc", "m4", "solved")
    tracker.record_outcome("agent_b", "misc", "m5", "failed")
    tracker.record_outcome("agent_b", "misc", "m6", "failed")

    best = tracker.get_best_agent_for("misc", min_runs=2)
    assert best == "agent_a"
