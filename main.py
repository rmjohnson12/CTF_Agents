# main.py
import argparse
import json
import sys
from pathlib import Path
from typing import List

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

    result = coordinator.solve_challenge(challenge, resume=args.resume)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
