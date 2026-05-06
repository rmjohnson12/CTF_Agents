"""
Log Analysis Specialist Agent

Specialized agent for analyzing server, auth, and application logs.
"""

import logging
import re
import collections
from typing import Dict, Any, List, Optional

from agents.base_agent import BaseAgent, AgentType
from core.utils.flag_utils import find_first_flag

logger = logging.getLogger(__name__)


class LogAnalysisAgent(BaseAgent):
    """
    Specialist agent for log analysis challenges.
    """

    def __init__(self, agent_id: str = "log_agent"):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.capabilities = [
            "log_analysis",
            "apache_logs",
            "nginx_logs",
            "auth_logs",
            "brute_force_detection",
            "traffic_analysis",
            "regex_search",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        
        log_indicators = ["log", "access", "auth", "server", "hits", "most common", "requests"]
        is_log = any(k in description for k in log_indicators) or \
                 any(f.endswith('.log') or f.endswith('.txt') for f in files)
        
        detected = [k for k in log_indicators if k in description]
        confidence = 0.9 if is_log or challenge.get("category") == "log" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_log or challenge.get("category") == "log",
            "confidence": confidence,
            "approach": self._plan_approach(detected),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps = []
        files = challenge.get("files", [])
        description = challenge.get("description", "").lower()
        
        if not files:
            return {"status": "failed", "steps": ["No log files provided for analysis"]}

        flag = None
        all_results = {}

        for file_path in files:
            steps.append(f"Analyzing log file: {file_path}")
            try:
                with open(file_path, "r") as f:
                    lines = f.readlines()
                
                steps.append(f"  Read {len(lines)} lines.")
                
                # Common OSINT/Log tasks in NCL:
                # 1. Most common IP
                ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                ips = []
                for line in lines:
                    match = re.search(ip_pattern, line)
                    if match:
                        ips.append(match.group(1))
                
                if ips:
                    ip_counts = collections.Counter(ips)
                    most_common_ip = ip_counts.most_common(1)[0]
                    steps.append(f"  Most common IP: {most_common_ip[0]} ({most_common_ip[1]} hits)")
                    all_results["most_common_ip"] = most_common_ip[0]
                    
                    if "ip" in description and ("most" in description or "highest" in description):
                        flag = most_common_ip[0]
                        steps.append(f"  Heuristic: Found likely answer to IP question: {flag}")

                # 2. HTTP Status Codes
                status_pattern = r'\" [1-5]\d{2} '
                statuses = []
                for line in lines:
                    match = re.search(status_pattern, line)
                    if match:
                        statuses.append(match.group(0).strip())
                
                if statuses:
                    status_counts = collections.Counter(statuses)
                    steps.append(f"  Status code summary: {dict(status_counts.most_common(3))}")

                # 3. Look for flags in lines
                for line in lines:
                    found_flag = find_first_flag(line)
                    if found_flag and not flag:
                        flag = found_flag
                        steps.append(f"  Found flag in log line: {flag}")
                        break

                # 4. Auth failures (brute force)
                if "failed password" in str(lines).lower() or "authentication failure" in str(lines).lower():
                    failed_ips = []
                    for line in lines:
                        if "failed password" in line.lower():
                            match = re.search(ip_pattern, line)
                            if match:
                                failed_ips.append(match.group(1))
                    
                    if failed_ips:
                        brute_force_ip = collections.Counter(failed_ips).most_common(1)[0]
                        steps.append(f"  Potential brute force from IP: {brute_force_ip[0]} ({brute_force_ip[1]} failures)")
                        if "brute" in description or "failed" in description:
                            flag = brute_force_ip[0]
                            steps.append(f"  Heuristic: Found likely answer to auth question: {flag}")

            except Exception as exc:
                logger.warning("Error analyzing %s: %s", file_path, exc)
                steps.append(f"  Error analyzing {file_path}: {exc}")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "results": all_results
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities
