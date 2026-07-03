from core.decision_engine.classifier import ChallengeAnalysis
from core.decision_engine.strategy_selector import StrategySelector


def _analysis(category: str, target: str = "none") -> ChallengeAnalysis:
    return ChallengeAnalysis(
        category_guess=category,
        confidence=0.8,
        reasoning="No explicit target returned.",
        recommended_target=target,
        recommended_action="stop",
        detected_indicators=[],
    )


def test_known_category_falls_back_to_untried_specialist():
    decision = StrategySelector().select_next(
        {"category": "crypto", "files": []},
        _analysis("crypto"),
        [],
    )

    assert decision["next_action"] == "run_agent"
    assert decision["target"] == "crypto_agent"


def test_declared_category_is_used_when_analysis_category_is_unknown():
    decision = StrategySelector().select_next(
        {"category": "forensics", "files": []},
        _analysis("unknown"),
        [],
    )

    assert decision["target"] == "forensics_agent"


def test_category_fallback_does_not_repeat_routing_only_history():
    decision = StrategySelector().select_next(
        {"category": "web", "files": []},
        _analysis("web"),
        [{
            "status": "attempted",
            "routing": {"selected_target": "web_agent", "execution_type": "agent"},
        }],
    )

    assert decision["next_action"] == "stop"
    assert decision["target"] == "none"
