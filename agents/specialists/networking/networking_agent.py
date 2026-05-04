"""
Networking Specialist Agent

Specialized agent for network traffic analysis and protocol reverse engineering.
"""

from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
import os

class NetworkingAgent(BaseAgent):
    """
    Specialist agent for networking challenges.
    Handles PCAP analysis, protocol identification, and traffic reconstruction.
    """

    def __init__(self, agent_id: str = "networking_agent", reasoner: Optional[LLMReasoner] = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.capabilities = [
            "pcap_analysis",
            "protocol_analysis",
            "traffic_reconstruction",
            "network_enumeration",
            "packet_inspection"
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        
        is_networking = any(f.endswith('.pcap') or f.endswith('.pcapng') for f in files) or \
                        any(word in description for word in ["packet", "traffic", "wireshark", "tshark", "pcap"])
        
        confidence = 0.9 if is_networking or challenge.get("category") == "networking" else 0.1

        return {
            "agent_id": self.agent_id,
            "can_handle": is_networking or challenge.get("category") == "networking",
            "confidence": confidence,
            "approach": "Perform packet inspection and traffic reconstruction" if is_networking else "None",
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps = []
        files = challenge.get("files", [])
        pcap_files = [f for f in files if f.endswith('.pcap') or f.endswith('.pcapng')]
        
        if not pcap_files:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "steps": ["No PCAP files found for analysis"]
            }

        for pcap in pcap_files:
            steps.append(f"Analyzing network traffic in: {pcap}")
            
            # Use strings as a quick first pass for flags
            steps.append(f"Performing strings analysis on {pcap}...")
            try:
                # Basic heuristic: look for flag patterns in the raw file
                import subprocess
                result = subprocess.run(["strings", pcap], capture_output=True, text=True)
                from core.utils.flag_utils import find_first_flag
                flag = find_first_flag(result.stdout)
                
                if flag:
                    steps.append(f"✅ Found flag in raw strings: {flag}")
                    return {
                        "challenge_id": challenge.get("id"),
                        "agent_id": self.agent_id,
                        "status": "solved",
                        "flag": flag,
                        "steps": steps
                    }
            except Exception as e:
                steps.append(f"Strings analysis failed: {e}")

            # Placeholder for deeper analysis with Scapy/TShark
            steps.append("Deeping packet inspection required. (Tool integration pending...)")
            
            if self.reasoner.is_available:
                steps.append("Requesting protocol analysis strategy from LLM...")
                # In a real implementation, we might send packet summaries to the LLM
                prompt = f"How should I analyze this PCAP file for a flag? File: {pcap}. Context: {challenge.get('description')}"
                llm_advice = self.reasoner._call_llm(prompt)
                steps.append(f"LLM Advice: {llm_advice}")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "attempted",
            "steps": steps
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities
