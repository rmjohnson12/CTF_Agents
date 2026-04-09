"""
Forensics Specialist Agent

Specialized agent for forensics-based CTF challenges.
"""

import json
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from tools.forensics.binwalk import BinwalkTool
from tools.forensics.exiftool import ExiftoolTool
from tools.common.strings import StringsTool
from core.utils.flag_utils import find_first_flag


class ForensicsAgent(BaseAgent):
    """
    Specialist agent for forensics challenges.
    """

    def __init__(
        self, 
        agent_id: str = "forensics_agent", 
        binwalk_tool: Optional[BinwalkTool] = None,
        exiftool_tool: Optional[ExiftoolTool] = None,
        strings_tool: Optional[StringsTool] = None
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.binwalk_tool = binwalk_tool or BinwalkTool()
        self.exiftool_tool = exiftool_tool or ExiftoolTool()
        self.strings_tool = strings_tool or StringsTool()
        self.capabilities = [
            "forensics",
            "file_analysis",
            "binwalk",
            "exiftool",
            "strings",
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
        all_artifacts = {
            "binwalk": [],
            "exiftool": [],
            "strings": []
        }

        for file_path in files:
            # 1. Binwalk
            steps.append(f"Running binwalk on {file_path}")
            try:
                res = self.binwalk_tool.run(file_path)
                if res.signatures:
                    steps.append(f"  Found {len(res.signatures)} binwalk signatures")
                    for s in res.signatures:
                        all_artifacts["binwalk"].append({"file": file_path, "description": s.description})
                        found_flag = find_first_flag(s.description)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in binwalk: {flag}")
            except Exception as e:
                steps.append(f"  Binwalk error: {e}")

            # 2. Exiftool
            steps.append(f"Running exiftool on {file_path}")
            try:
                res = self.exiftool_tool.run(file_path)
                if res.metadata:
                    all_artifacts["exiftool"].append({"file": file_path, "metadata": res.metadata})
                    # Scan metadata values for flags
                    metadata_str = json.dumps(res.metadata)
                    found_flag = find_first_flag(metadata_str)
                    if found_flag and not flag:
                        flag = found_flag
                        steps.append(f"  Flag found in metadata: {flag}")
            except Exception as e:
                steps.append(f"  Exiftool error: {e}")

            # 3. Strings
            steps.append(f"Running strings on {file_path}")
            try:
                res = self.strings_tool.run(file_path)
                if res.strings:
                    # Scan for flags in extracted strings
                    for s in res.strings:
                        found_flag = find_first_flag(s)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in strings: {flag}")
                            break
            except Exception as e:
                steps.append(f"  Strings error: {e}")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": all_artifacts
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities
