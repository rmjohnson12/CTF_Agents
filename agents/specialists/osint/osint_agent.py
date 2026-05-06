"""
OSINT Specialist Agent

Specialized agent for Open Source Intelligence challenges.
"""

import logging
from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent, AgentType
from tools.forensics.exiftool import ExiftoolTool
from tools.web.browser_snapshot_tool import BrowserSnapshotTool
from core.utils.flag_utils import find_first_flag
import re

logger = logging.getLogger(__name__)


class OSINTAgent(BaseAgent):
    """
    Specialist agent for OSINT challenges.
    """

    def __init__(
        self, 
        agent_id: str = "osint_agent", 
        exiftool_tool: Optional[ExiftoolTool] = None,
        browser_tool: Optional[BrowserSnapshotTool] = None
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.exiftool_tool = exiftool_tool or ExiftoolTool()
        self.browser_tool = browser_tool or BrowserSnapshotTool()
        self.capabilities = [
            "osint",
            "open_source_intelligence",
            "metadata_extraction",
            "domain_enumeration",
            "whois",
            "email_harvesting",
            "social_media_analysis",
            "geolocation",
            "public_records",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        tags = " ".join(challenge.get("tags", [])).lower()
        
        osint_indicators = [
            "osint", "whois", "domain", "email", "social media", "person", 
            "find", "located", "where", "username", "profile", "metadata"
        ]
        is_osint = any(k in description or k in tags for k in osint_indicators)
        
        detected = [k for k in osint_indicators if k in description or k in tags]
        confidence = 0.9 if is_osint or challenge.get("category") == "osint" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_osint or challenge.get("category") == "osint",
            "confidence": confidence,
            "approach": self._plan_approach(detected),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self.analyze_challenge(challenge)
        steps: List[str] = []
        flag = None
        artifacts = {}

        description = challenge.get("description", "").lower()
        
        # 1. Metadata analysis (common first step if files provided)
        files = challenge.get("files", [])
        if files:
            steps.append(f"Analyzing metadata for {len(files)} files")
            for f in files:
                try:
                    res = self.exiftool_tool.run(f)
                    if res.metadata:
                        steps.append(f"  Extracted metadata from {f}")
                        # Check for flags in metadata
                        metadata_str = str(res.metadata)
                        found_flag = find_first_flag(metadata_str)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in metadata: {flag}")
                        
                        # Store artifacts
                        if 'metadata' not in artifacts: artifacts['metadata'] = []
                        artifacts['metadata'].append({"file": f, "metadata": res.metadata})
                except Exception as e:
                    steps.append(f"  Exiftool error on {f}: {e}")

        # 2. Extract and analyze domains/emails/usernames
        domains = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', description)
        emails = re.findall(r'[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', description)
        
        if domains:
            steps.append(f"Found potential domains: {', '.join(domains[:3])}")
            for domain in domains[:2]: # Limit to first 2 to avoid noise
                if domain in ['google.com', 'gmail.com', 'outlook.com', 'hotmail.com']: continue
                
                # Snapshot the domain if it looks interesting
                steps.append(f"  Attempting to snapshot domain: {domain}")
                try:
                    res = self.browser_tool.snapshot(f"http://{domain}")
                    steps.append(f"    Captured snapshot: {res.title}")
                    
                    found_flag = find_first_flag(res.raw.stdout)
                    if found_flag and not flag:
                        flag = found_flag
                        steps.append(f"    Flag found in domain snapshot: {flag}")
                except Exception as exc:
                    logger.debug("Could not snapshot %s: %s", domain, exc)
                    steps.append(f"    Could not snapshot {domain}")

        # 3. Handle specific OSINT questions (Common in NCL)
        # E.g., "What is the phone number of X?" or "When was Y created?"
        # For a real agent, this would involve searching, but here we provide the framework.
        if not flag:
            steps.append("Search phase: Attempting to find answers in provided artifacts or description.")
            # Simple heuristic: look for things that look like flags in the whole challenge object
            all_text = str(challenge)
            found_flag = find_first_flag(all_text)
            if found_flag:
                flag = found_flag
                steps.append(f"  Found flag in challenge data: {flag}")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": artifacts
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities
