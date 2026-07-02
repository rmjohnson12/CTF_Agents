# main.py
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from challenges.challenge_parser import ChallengeParser, ParseError
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.registry import AgentRegistry


def _print_plan_main(
    challenge: Dict[str, Any],
    analysis: Dict[str, Any],
    next_action: Dict[str, Any],
    tracker=None,
) -> None:
    conf_pct = f"{analysis['confidence'] * 100:.0f}%"
    indicators = ", ".join(analysis["strategy"]["detected_indicators"]) or "none"
    action = next_action.get("next_action", "stop")
    target = next_action.get("target", "none")
    routing = f"{action} -> {target}" if target != "none" else "stop  (no confident path)"

    print("\n=== Plan (dry run) ===\n")
    print(f"Challenge : {challenge.get('name', 'Unknown')}  [{challenge.get('id', '?')}]")
    print(f"Category  : {analysis['category']}  ({conf_pct} confidence)")
    print(f"Indicators: {indicators}")
    print()
    print(f"Routing   : {routing}")
    print(f"Reasoning : {next_action.get('reasoning') or analysis['strategy']['reasoning']}")

    if tracker is not None:
        hint = tracker.get_routing_hint(analysis["category"])
        if hint:
            agent_id, rate = hint
            print()
            print(
                f"Perf hint : {agent_id} -> {rate:.0%} historical solve rate "
                f"for '{analysis['category']}' challenges"
            )
        else:
            print()
            print(f"Perf hint : No history yet for '{analysis['category']}' challenges")

    print()
    print("No agents or tools were invoked. Remove --plan to execute.")


def build_coordinator(max_iterations: int = 5) -> CoordinatorAgent:
    """Build the standard coordinator and register every shipped agent."""
    from tools.web.browser_snapshot_tool import BrowserSnapshotTool
    from tools.crypto.john import JohnTool
    from tools.crypto.hashcat import HashcatTool

    browser_tool = BrowserSnapshotTool()
    john_tool = JohnTool()
    hashcat_tool = HashcatTool()
    coordinator = CoordinatorAgent(
        browser_snapshot_tool=browser_tool,
        max_iterations=max_iterations,
    )
    AgentRegistry.register_all(coordinator, {
        "browser_tool": browser_tool,
        "john_tool": john_tool,
        "hashcat_tool": hashcat_tool,
    })
    return coordinator


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the CTF multi-agent coordinator.")
    parser.add_argument("challenge_json_path", help="Path to a challenge JSON file.")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from logs/checkpoints/{challenge_id}.json if present.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        help="Maximum coordinator iterations for this run.",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Dry-run: show routing plan without invoking any agents or tools.",
    )
    args = parser.parse_args(argv[1:])

    try:
        challenge = ChallengeParser().parse_file(args.challenge_json_path)
    except ParseError as exc:
        print(f"Error loading challenge: {exc}", file=sys.stderr)
        return 1

    coordinator = build_coordinator(max_iterations=args.max_iterations)

    if args.plan:
        raw_analysis = coordinator.reasoner.analyze_challenge(challenge)
        analysis_dict = coordinator._analysis_to_dict(challenge, raw_analysis)
        next_action = coordinator.reasoner.choose_next_action(challenge, raw_analysis, [])
        _print_plan_main(challenge, analysis_dict, next_action, coordinator.performance_tracker)
        return 0

    result = coordinator.solve_challenge(challenge, resume=args.resume)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
