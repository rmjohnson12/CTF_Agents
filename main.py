# main.py
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from challenges.challenge_parser import ChallengeParser, ParseError
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from agents.specialists.forensics.forensics_agent import ForensicsAgent
from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent
from agents.specialists.osint.osint_agent import OSINTAgent
from agents.specialists.log_analysis.log_agent import LogAnalysisAgent
from agents.specialists.networking.networking_agent import NetworkingAgent
from agents.support.docker_agent import DockerChallengeAgent
from agents.support.recon_agent import ReconAgent
from agents.specialists.pwn.pwn_agent import PwnAgent


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

    from tools.web.browser_snapshot_tool import BrowserSnapshotTool
    browser_tool = BrowserSnapshotTool()

    coordinator = CoordinatorAgent(
        browser_snapshot_tool=browser_tool,
        max_iterations=args.max_iterations,
    )

    # Register agents with IDs that match the reasoner/coordinator routing targets
    from tools.crypto.john import JohnTool
    from tools.crypto.hashcat import HashcatTool
    john_tool = JohnTool()
    hashcat_tool = HashcatTool()

    coordinator.register_agent(CryptographyAgent(john_tool=john_tool, hashcat_tool=hashcat_tool))  # agent_id defaults to "crypto_agent"
    coordinator.register_agent(WebExploitationAgent(agent_id="web_agent", browser_tool=browser_tool))
    coordinator.register_agent(CodingAgent(agent_id="coding_agent"))
    coordinator.register_agent(ForensicsAgent(agent_id="forensics_agent", john_tool=john_tool, hashcat_tool=hashcat_tool))
    coordinator.register_agent(ReverseEngineeringAgent(agent_id="reverse_agent"))
    coordinator.register_agent(OSINTAgent(agent_id="osint_agent", browser_tool=browser_tool))
    coordinator.register_agent(LogAnalysisAgent(agent_id="log_agent"))
    coordinator.register_agent(NetworkingAgent(agent_id="networking_agent"))
    coordinator.register_agent(DockerChallengeAgent(agent_id="docker_agent"))
    coordinator.register_agent(ReconAgent(agent_id="recon_agent"))
    coordinator.register_agent(PwnAgent(agent_id="pwn_agent"))

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
