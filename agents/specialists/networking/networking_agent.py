"""
Networking Specialist Agent

Specialized agent for network traffic analysis and protocol reverse engineering.
"""

from dataclasses import asdict
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from tools.network.nmap import NmapTool
from tools.network.tshark import TsharkTool
from tools.network.scapy_tool import ScapyTool
from core.utils.flag_utils import find_first_flag
import logging
import os

logger = logging.getLogger(__name__)

class NetworkingAgent(BaseAgent):
    """
    Specialist agent for networking challenges.
    Handles PCAP analysis, protocol identification, and traffic reconstruction.
    """

    def __init__(
        self, 
        agent_id: str = "networking_agent", 
        reasoner: Optional[LLMReasoner] = None,
        nmap_tool: Optional[NmapTool] = None,
        tshark_tool: Optional[TsharkTool] = None,
        scapy_tool: Optional[ScapyTool] = None
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.nmap_tool = nmap_tool or NmapTool()
        self.tshark_tool = tshark_tool or TsharkTool()
        self.scapy_tool = scapy_tool or ScapyTool()
        
        self.capabilities = [
            "pcap_analysis",
            "protocol_analysis",
            "traffic_reconstruction",
            "network_enumeration",
            "packet_inspection",
            "nmap_scan",
            "stream_following"
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        url = challenge.get("url") or challenge.get("target", {}).get("url")
        
        is_networking = any(f.endswith('.pcap') or f.endswith('.pcapng') for f in files) or \
                        any(word in description for word in ["packet", "traffic", "wireshark", "tshark", "pcap", "nmap", "port scan"]) or \
                        (url and not url.startswith("http"))
        
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
        url = challenge.get("url") or challenge.get("target", {}).get("url")
        description = challenge.get("description", "").lower()
        
        flag = None
        artifacts = {}

        # 1. PCAP Analysis (TShark / Scapy)
        pcap_files = [f for f in files if f.endswith('.pcap') or f.endswith('.pcapng')]
        for pcap in pcap_files:
            steps.append(f"Analyzing PCAP file: {pcap}")
            
            # Step A: Strings check (fastest)
            try:
                res = self.run_shell_command(["strings", pcap])
                flag = find_first_flag(res.stdout)
                if flag:
                    steps.append(f"  Found flag in raw strings: {flag}")
                    break
            except Exception as e:
                logger.debug("strings analysis failed for %s: %s", pcap, e)
                steps.append(f"  Raw strings analysis failed: {e}")

            # Step B: TShark Summary
            try:
                steps.append(f"  Running TShark summary for {pcap}...")
                ts_res = self.tshark_tool.run(pcap)
                steps.append(f"    Detected IPs: {', '.join(ts_res.ips[:5])}")
                if ts_res.hostnames:
                    steps.append(f"    Detected Hostnames: {', '.join(ts_res.hostnames[:5])}")
                artifacts["tshark_summary"] = {
                    "ips": ts_res.ips,
                    "hostnames": ts_res.hostnames
                }
            except Exception as e:
                steps.append(f"  TShark analysis failed: {e}")

            # Step C: Stream Reconstruction (Scapy)
            try:
                steps.append(f"  Reconstructing streams with Scapy...")
                streams = self.scapy_tool.reconstruct_all_streams(pcap)
                steps.append(f"    Extracted {len(streams)} streams.")
                
                for i, stream in enumerate(streams[:10]): # Limit to top 10
                    # Check for flags in raw stream data
                    data = (stream.data_c2s + stream.data_s2c).decode('utf-8', errors='ignore')
                    found = find_first_flag(data)
                    if found:
                        flag = found
                        steps.append(f"  Found flag in {stream.protocol} stream {i} ({stream.client} -> {stream.server}): {flag}")
                        break
            except Exception as e:
                steps.append(f"  Scapy reconstruction failed: {e}")
            
            if flag: break

        # 2. Network Enumeration (Nmap)
        if not flag and url:
            target = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            steps.append(f"No PCAP flag found. Running Nmap scan against {target}...")
            try:
                nm_res = self.nmap_tool.scan_top(target)
                open_ports = [f"{p.port}/{p.proto} ({p.service})" for p in nm_res.ports if p.state == "open"]
                steps.append(f"  Open ports: {', '.join(open_ports) if open_ports else 'None found'}")
                artifacts["nmap_scan"] = {
                    "target": target,
                    "ports": [asdict(p) for p in nm_res.ports]
                }
                
                # Check nmap output for flags (unlikely but possible in banner grabs)
                found = find_first_flag(nm_res.raw.stdout)
                if found:
                    flag = found
                    steps.append(f"  Found flag in Nmap banner/output: {flag}")
            except Exception as e:
                steps.append(f"  Nmap scan failed: {e}")

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
