import json
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
from agents.specialists.forensics.forensics_agent import ForensicsAgent
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
            "steps": ["Simulated web reconnaissance completed."],
            "artifacts": {},
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

class SimulatedReasonerV2:
    """
    Simulates LLM reasoning for the V2 demo (Forensics + Ambiguous).
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
        if cid == "ambiguous_001":
            return ChallengeAnalysis("misc", 0.7, "Ambiguous: contains both web and crypto elements.", "web_agent", "run_agent", ["base64", "url"])
        if cid == "sim_htb_001":
            return ChallengeAnalysis("forensics", 0.9, "HTB Forensics task.", "forensics_agent", "run_agent", ["files"])
        if "forensics" in cid or challenge.get("category") == "forensics":
            return ChallengeAnalysis("forensics", 0.9, "Forensics task detected.", "forensics_agent", "run_agent", ["files"])
        return ChallengeAnalysis("misc", 0.5, "Unknown", "none", "stop", [])

    def choose_next_action(self, challenge: Dict[str, Any], analysis: Any, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        cid = challenge["id"]
        steps = self.step_counts.get(cid, 0)
        self.step_counts[cid] = steps + 1

        if cid == "sim_sky_001":
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "web_agent",
                    "reasoning": "Let's perform directory discovery to find the flag."
                }
            else:
                return {"next_action": "stop", "reasoning": "Scan complete."}

        if cid == "sim_htb_001":
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "forensics_agent",
                    "reasoning": "First, let's analyze the binary file for strings or metadata."
                }
            else:
                return {"next_action": "stop", "reasoning": "Forensics analysis completed."}

        if cid == "ambiguous_001":
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "web_agent",
                    "reasoning": "Let's start by inspecting the web page."
                }
            elif steps == 1:
                return {
                    "next_action": "run_agent",
                    "target": "crypto_agent",
                    "reasoning": "Web agent found a base64 string. Let's decode it."
                }
            else:
                return {"next_action": "stop", "reasoning": "Task complete."}
        
        if "forensics" in cid or challenge.get("category") == "forensics":
            if steps == 0:
                return {
                    "next_action": "run_agent",
                    "target": "forensics_agent",
                    "reasoning": "Analyze the provided files for artifacts."
                }
            else:
                return {"next_action": "stop", "reasoning": "Analysis complete."}

        return {"next_action": "stop", "reasoning": "Unknown challenge type."}

    def generate_script(self, challenge: Dict[str, Any], task_description: str) -> str:
        return "print('CTF{simulated_coding_flag}')"

    def fix_script(
        self,
        challenge: Dict[str, Any],
        script: str,
        error: str,
        stdout: str = "",
    ) -> str:
        return script # Just return same for mock

def run_simulation(challenge_path: str):
    print(f"\n{'='*20} SIMULATING: {challenge_path} {'='*20}")
    with open(challenge_path) as f:
        challenge = json.load(f)

    coordinator = CoordinatorAgent(max_iterations=5)
    coordinator.reasoner = SimulatedReasonerV2() 
    
    web_agent = SimulatedWebAgent() if challenge.get("id") == "sim_sky_001" else WebExploitationAgent()
    coordinator.register_agent(web_agent)
    coordinator.register_agent(CodingAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(CryptographyAgent())
    coordinator.register_agent(ForensicsAgent())

    result = coordinator.solve_challenge(challenge)
    
    print(f"\nFinal Status: {result['status']}")
    print(f"Flag: {result['flag']}")
    print(f"Iterations: {result['iterations']}")
    print("\nStep Log:")
    for step in result['steps']:
        print(f"  - {step}")

if __name__ == "__main__":
    # Create a forensics challenge file first
    forensics_challenge = {
        "id": "sim_forensics_001",
        "name": "Hidden in Plain Sight",
        "category": "forensics",
        "description": "Analyze this file for hidden flags.",
        "files": ["challenges/active/sim_web_001/artifact.bin"] # Reuse existing file
    }
    with open("challenges/active/sim_forensics_001.json", "w") as f:
        json.dump(forensics_challenge, f)

    run_simulation("challenges/active/sim_htb_001.json")
    run_simulation("challenges/active/sim_sky_001.json")
    run_simulation("challenges/active/sim_forensics_001.json")
    run_simulation("challenges/templates/example_ambiguous_001.json")
