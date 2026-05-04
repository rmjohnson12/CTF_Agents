"""
Reverse Engineering Specialist Agent

Specialized agent for binary and source code analysis.
"""

from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from core.decision_engine.llm_reasoner import LLMReasoner
from tools.common.python_tool import PythonTool
import re
import sys

class ReverseEngineeringAgent(BaseAgent):
    """
    Specialist agent for reverse engineering challenges.
    Handles source code analysis and binary reversing.
    """

    def __init__(self, agent_id: str = "reverse_agent", reasoner: Optional[LLMReasoner] = None, python_tool: Optional[PythonTool] = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.capabilities = [
            "reverse_engineering",
            "source_code_analysis",
            "python_analysis",
            "decompilation",
            "static_analysis",
            "verification"
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        
        indicators = ["reverse", "analyze", "source code", "authenticate the program"]
        is_reverse = any(f.endswith('.py') or f.endswith('.exe') or f.endswith('.bin') for f in files) or \
                     any(word in description for word in indicators)
        
        detected = [k for k in indicators if k in description]
        confidence = 0.9 if is_reverse or challenge.get("category") == "reverse" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_reverse or challenge.get("category") == "reverse",
            "confidence": confidence,
            "approach": self._plan_approach(detected),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps = []
        files = challenge.get("files", [])
        
        if not files:
            return {"status": "failed", "steps": ["No files provided for analysis"]}

        for file_path in files:
            steps.append(f"Analyzing file: {file_path}")
            try:
                with open(file_path, "r") as f:
                    content = f.read()
                
                steps.append("File content read successfully.")
                
                # Logic Analysis
                target_sum_match = re.search(r"builder\s*==\s*(\d+)", content)
                length_match = re.search(r"len\(password\)\s*[=!]=\s*(\d+)", content)
                # Improved regex for index access patterns: password[idx], password[idx], etc.
                fixed_char_match = re.search(r"password\[(\d+)\]\s*==\s*(\d+)", content) or \
                                   re.search(r"ord\(password\[(\d+)\]\)\s*==\s*(\d+)", content)

                if target_sum_match and length_match:
                    target_sum = int(target_sum_match.group(1))
                    target_len = int(length_match.group(1))
                    
                    steps.append(f"1. Extracted Constraints: Sum={target_sum}, Length={target_len}")
                    
                    fixed_idx = None
                    fixed_val = None
                    if fixed_char_match:
                        fixed_idx = int(fixed_char_match.group(1))
                        fixed_val = int(fixed_char_match.group(2))
                        steps.append(f"2. Fixed Character: Index {fixed_idx} must be '{chr(fixed_val)}' (ASCII {fixed_val})")

                    # Solve
                    steps.append("3. Calculating balanced ASCII distribution...")
                    candidate = self._solve_sum_constraint(target_sum, target_len, fixed_idx, fixed_val)
                    if candidate:
                        steps.append(f"4. Candidate Derived: {candidate}")
                        steps.append(f"5. Verifying candidate by executing {file_path}...")
                        
                        res = self.python_tool.execute([file_path, candidate], timeout_s=5)
                        if "correct" in res.stdout.lower():
                            steps.append("✅ Verification SUCCESS: Program returned 'correct'.")
                            return {
                                "challenge_id": challenge.get("id"),
                                "agent_id": self.agent_id,
                                "status": "solved",
                                "flag": candidate,
                                "steps": steps
                            }
                        else:
                            steps.append(f"❌ Verification FAILED: Program returned '{res.stdout.strip()}'.")
                
                if not self.reasoner.is_available:
                    steps.append("LLM not available for complex code analysis.")
                    continue

                # Fallback to LLM analysis for non-trivial logic
                steps.append("Requesting logic analysis from LLM...")
                analysis_prompt = f"Analyze this code and find a valid input: \n{content}"
                result = self.reasoner._call_llm(analysis_prompt).strip()
                if result:
                    steps.append(f"LLM suggested input: {result}. Verifying...")
                    res = self.python_tool.execute([file_path, result], timeout_s=5)
                    if "correct" in res.stdout.lower():
                        return {"challenge_id": challenge.get("id"), "agent_id": self.agent_id, "status": "solved", "flag": result, "steps": steps}

            except Exception as e:
                steps.append(f"Error during analysis: {e}")

        return {"challenge_id": challenge.get("id"), "agent_id": self.agent_id, "status": "attempted", "steps": steps}

    def _solve_sum_constraint(self, target_sum, length, fixed_idx=None, fixed_val=None) -> Optional[str]:
        """Balanced solver: calculates average ASCII and distributes remainder."""
        slots = length - (1 if fixed_idx is not None else 0)
        remaining_sum = target_sum - (fixed_val if fixed_val is not None else 0)
        
        if slots <= 0: return None
        
        avg_val = remaining_sum // slots
        remainder = remaining_sum % slots
        
        # Build the password list
        password = [chr(avg_val)] * length
        if fixed_idx is not None:
            password[fixed_idx] = chr(fixed_val)
            
        # Distribute the remainder to the first available slot
        for i in range(length):
            if i == fixed_idx: continue
            password[i] = chr(ord(password[i]) + remainder)
            break
            
        return "".join(password)

    def get_capabilities(self) -> List[str]:
        return self.capabilities
