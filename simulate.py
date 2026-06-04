import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

# Ensure we can import from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.base_agent import BaseAgent, AgentType
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from core.decision_engine.llm_reasoner import ChallengeAnalysis

class SimulatedWebAgent(BaseAgent):
    """Deterministic web agent for offline simulation fixtures."""

    def __init__(self):
        super().__init__("web_agent", AgentType.SPECIALIST)
        self.capabilities = ["web", "directory_discovery", "simulation"]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "can_handle": challenge.get("category") == "web",
            "confidence": 0.9,
            "approach": "Use deterministic simulated web responses.",
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        cid = challenge.get("id", "")
        if cid == "sim_sky_001":
            return {
                "challenge_id": cid,
                "agent_id": self.agent_id,
                "status": "solved",
                "flag": "SKY-QIZK-8026",
                "steps": [
                    "Simulated directory discovery against ncl.target.local.",
                    "  Found /hidden_flag.txt",
                    "  Flag found in simulated directory response: SKY-QIZK-8026",
                ],
                "artifacts": {"directory_discovery": ["/hidden_flag.txt"]},
            }

        return {
            "challenge_id": cid,
            "agent_id": self.agent_id,
            "status": "attempted",
            "flag": None,
            "steps": [
                "Simulated web reconnaissance completed.",
                "  Found binary artifact for follow-up analysis.",
            ],
            "artifacts": {},
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

class SimulatedReasoner:
    """
    Simulates LLM reasoning for the live demo.
    """
    def __init__(self):
        self.step_counts = {}

    @property
    def is_available(self) -> bool:
        return True

    def analyze_challenge(self, challenge: Dict[str, Any]) -> ChallengeAnalysis:
        cid = challenge["id"]
        if cid == "sim_sky_001":
            return ChallengeAnalysis("web", 0.9, "NCL Web discovery task.", "web_agent", "run_agent", ["url"])
        if "web" in cid:
            return ChallengeAnalysis("web", 0.9, "Looks like a web task.", "web_agent", "run_agent", ["url_found"])
        return ChallengeAnalysis("misc", 0.9, "Coding task detected.", "coding_agent", "run_agent", ["math_task"])

    def choose_next_action(self, challenge: Dict[str, Any], analysis: Any, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        cid = challenge["id"]
        steps = self.step_counts.get(cid, 0)
        self.step_counts[cid] = steps + 1

        if "web" in cid:
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "web_agent",
                    "reasoning": "First, let's scan the files and reconnaissance the URL."
                }
            elif steps == 1:
                # After web agent runs, it might have found something in artifacts
                return {
                    "next_action": "run_agent",
                    "target": "coding_agent",
                    "reasoning": "Web agent found a binary artifact. Let's use the coding agent to extract strings."
                }
            else:
                return {"next_action": "stop", "reasoning": "Task complete or giving up."}

        if cid == "sim_sky_001":
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "web_agent",
                    "reasoning": "Let's perform directory discovery to find the flag.",
                }
            return {"next_action": "stop", "reasoning": "Scan complete."}
        
        if "coding" in cid:
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "coding_agent",
                    "reasoning": "Need to write a script to calculate the sum of primes."
                }
            else:
                return {"next_action": "stop", "reasoning": "Script executed, checking results."}

        return {"next_action": "stop", "reasoning": "Unknown challenge type."}

    def generate_script(self, challenge: Dict[str, Any], task_description: str) -> str:
        prompt_text = f"{task_description}\n{challenge.get('description', '')}".lower()
        if "prime" in prompt_text:
            return """
def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0: return False
    return True

primes = [n for n in range(1, 101) if is_prime(n)]
print(f"CTF{{{sum(primes)}}}")
"""
        return "print('CTF{extracted_from_artifact}')"

    def fix_script(
        self,
        challenge: Dict[str, Any],
        script_content: str,
        error: str,
        stdout: str = "",
    ) -> str:
        return self.generate_script(challenge, challenge.get("description", ""))

def run_simulation(challenge_path: str):
    print(f"\n{'='*20} SIMULATING: {challenge_path} {'='*20}")
    with open(challenge_path) as f:
        challenge = json.load(f)

    previous_allowed_networks = os.environ.get("CTF_AGENTS_ALLOWED_NETWORKS")
    if challenge.get("url"):
        host = challenge["url"].split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        allowed = [item for item in (previous_allowed_networks or "").split(",") if item]
        if host and host not in allowed:
            os.environ["CTF_AGENTS_ALLOWED_NETWORKS"] = ",".join(allowed + [host])

    try:
        coordinator = CoordinatorAgent(max_iterations=3)
        # Inject our simulator
        coordinator.reasoner = SimulatedReasoner()

        web_agent = SimulatedWebAgent() if challenge.get("id") == "sim_sky_001" else WebExploitationAgent()
        coordinator.register_agent(web_agent)
        coordinator.register_agent(CodingAgent(reasoner=coordinator.reasoner))
        coordinator.register_agent(CryptographyAgent())

        result = coordinator.solve_challenge(challenge)

        print(f"\nFinal Status: {result['status']}")
        print(f"Flag: {result['flag']}")
        print(f"Iterations: {result['iterations']}")
        print("\nStep Log:")
        for step in result['steps']:
            print(f"  - {step}")
    finally:
        if previous_allowed_networks is None:
            os.environ.pop("CTF_AGENTS_ALLOWED_NETWORKS", None)
        else:
            os.environ["CTF_AGENTS_ALLOWED_NETWORKS"] = previous_allowed_networks

if __name__ == "__main__":
    run_simulation("challenges/active/sim_web_001.json")
    run_simulation("challenges/active/sim_coding_001.json")
    run_simulation("challenges/active/sim_sky_001.json")
