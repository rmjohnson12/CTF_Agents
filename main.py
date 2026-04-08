# main.py
import json
import sys
from pathlib import Path
from typing import List

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from agents.specialists.forensics.forensics_agent import ForensicsAgent


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("Usage: python main.py <challenge_json_path>")
        return 2

    challenge_path = Path(argv[1])
    if not challenge_path.exists():
        raise FileNotFoundError(f"Challenge file not found: {challenge_path}")

    challenge = json.loads(challenge_path.read_text())

    coordinator = CoordinatorAgent()

    # Register agents with IDs that match the reasoner/coordinator routing targets
    coordinator.register_agent(CryptographyAgent())  # agent_id defaults to "crypto_agent"
    coordinator.register_agent(WebExploitationAgent(agent_id="web_agent"))
    coordinator.register_agent(CodingAgent(agent_id="coding_agent"))
    coordinator.register_agent(ForensicsAgent(agent_id="forensics_agent"))

    result = coordinator.solve_challenge(challenge)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))