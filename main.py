# main.py
import json
import sys
from pathlib import Path
from typing import List


from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print("Usage: python main.py <challenge_json_path>")
        return 2

    challenge_path = Path(argv[1])
    if not challenge_path.exists():
        raise FileNotFoundError(f"Challenge file not found: {challenge_path}")

    challenge = json.loads(challenge_path.read_text())

    coordinator = CoordinatorAgent()
    coordinator.register_agent(CryptographyAgent(agent_id="crypto"))
    coordinator.register_agent(WebExploitationAgent(agent_id="web"))

    result = coordinator.solve_challenge(challenge)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))