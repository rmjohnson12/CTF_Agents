"""
Forensics Specialist Agent

Specialized agent for forensics-based CTF challenges.
"""

from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from tools.forensics.binwalk import BinwalkTool


class ForensicsAgent(BaseAgent):
    """
    Specialist agent for forensics challenges.
    """

    def __init__(self, agent_id: str = "forensics_agent", binwalk_tool: Optional[BinwalkTool] = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.binwalk_tool = binwalk_tool or BinwalkTool()
        self.capabilities = [
            "forensics",
            "file_analysis",
            "binwalk",
            "artifact_extraction",
            "steganography",
            "metadata",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        tags = " ".join(challenge.get("tags", [])).lower()
        
        indicators = ["artifact", "file", "disk", "memory", "pcap", "extract", "binwalk", "forensics"]
        is_forensics = any(k in description or k in tags for k in indicators) or bool(files)
        
        confidence = 0.9 if is_forensics or challenge.get("category") == "forensics" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_forensics or challenge.get("category") == "forensics",
            "confidence": confidence,
            "approach": "Perform file analysis and artifact extraction",
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self.analyze_challenge(challenge)
        steps: List[str] = []
        flag = None

        files = challenge.get("files", [])
        if not files:
            steps.append("No files provided for forensics analysis.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        steps.append(f"Analyzing {len(files)} files...")
        all_signatures = []

        for file_path in files:
            steps.append(f"Running binwalk on {file_path}")
            try:
                res = self.binwalk_tool.run(file_path)
                if res.signatures:
                    steps.append(f"  Found {len(res.signatures)} signatures in {file_path}")
                    for s in res.signatures:
                        all_signatures.append({
                            "file": file_path,
                            "decimal": s.decimal,
                            "hex": s.hexadecimal,
                            "description": s.description
                        })
                        # Heuristic flag detection in descriptions
                        if "CTF{" in s.description:
                            import re
                            m = re.search(r"CTF\{[^}]+\}", s.description)
                            if m:
                                flag = m.group(0)
                                steps.append(f"  Flag found in binwalk description: {flag}")
                else:
                    steps.append(f"  No signatures found in {file_path}")
            except Exception as e:
                steps.append(f"  Error running binwalk on {file_path}: {e}")

        # If no flag found yet, maybe the "coding_agent" can help with extraction
        # but the ForensicsAgent itself has done its primary job of identification.

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": {
                "binwalk_signatures": all_signatures
            }
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities
