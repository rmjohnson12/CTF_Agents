"""
Coding Specialist Agent

Specialized agent for programming, scripting, and automation challenges.
"""

from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from tools.common.python_tool import PythonTool
from core.decision_engine.llm_reasoner import LLMReasoner
import re

class CodingAgent(BaseAgent):
    """
    Specialist agent for programming and scripting challenges.
    
    Handles:
    - Python/Bash/Ruby scripting
    - Algorithm implementation
    - Data parsing and transformation
    - Automation of repetitive tasks
    - Code debugging and fixing
    """
    
    def __init__(self, agent_id: str = "coding_agent", reasoner: Optional[LLMReasoner] = None, python_tool: Optional[PythonTool] = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.capabilities = [
            'programming',
            'scripting',
            'python',
            'bash',
            'automation',
            'algorithm',
            'debugging',
            'misc'
        ]
    
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a coding challenge.
        """
        description = challenge.get('description', '').lower()
        
        # Detect potential coding tasks
        coding_indicators = ['script', 'write a program', 'python', 'code', 'automate', 'parse', 'algorithm']
        is_coding = any(indicator in description for indicator in coding_indicators)
        
        confidence = 0.9 if is_coding or challenge.get('category') == 'misc' else 0.2
        
        return {
            'agent_id': self.agent_id,
            'can_handle': is_coding or challenge.get('category') == 'misc',
            'confidence': confidence,
            'approach': "LLM-assisted code generation and execution"
        }
    
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a coding challenge by generating and running a script.
        Includes a self-correction loop.
        """
        analysis = self.analyze_challenge(challenge)
        steps = []
        flag = None
        max_retries = 3
        
        steps.append("Analyzed task requirements")
        
        # Generate script using reasoner
        task_desc = challenge.get('description', 'Solve the challenge')
        steps.append("Generating solution script via LLM...")
        script_content = self.reasoner.generate_script(challenge, task_desc)
        
        if script_content.startswith("# LLM not available"):
            steps.append("Error: LLM not available for script generation.")
            return {
                'challenge_id': challenge.get('id'),
                'agent_id': self.agent_id,
                'status': 'failed',
                'flag': None,
                'steps': steps
            }

        for attempt in range(max_retries + 1):
            if attempt > 0:
                steps.append(f"Attempt {attempt + 1}: Fixing script based on previous error...")
                script_content = self.reasoner.fix_script(challenge, script_content, last_error)

            steps.append(f"Executing script (Attempt {attempt + 1})...")
            try:
                res = self.python_tool.run(script_content)
                
                if res.timed_out:
                    last_error = "Execution timed out."
                    steps.append(f"  {last_error}")
                
                if res.stdout:
                    # steps.append(f"Stdout: {res.stdout[:500]}") # Too noisy for all attempts?
                    # Simple flag detection in stdout
                    flag_match = re.search(r"CTF\{[^}]+\}", res.stdout)
                    if flag_match:
                        flag = flag_match.group(0)
                        steps.append(f"  Found flag in stdout: {flag}")
                        break
                
                if res.stderr:
                    last_error = res.stderr
                    steps.append(f"  Stderr: {res.stderr[:200]}")
                else:
                    last_error = "Script executed but no flag found and no error message."

                if res.exit_code == 0:
                    if flag: break
                    steps.append("  Script executed successfully but no flag detected.")
                else:
                    steps.append(f"  Script failed with exit code {res.exit_code}")

            except Exception as e:
                last_error = str(e)
                steps.append(f"  Error during script execution: {e}")

            if attempt == max_retries:
                steps.append("Max retries reached. Self-correction failed.")

        return {
            'challenge_id': challenge.get('id'),
            'agent_id': self.agent_id,
            'status': 'solved' if flag else 'failed' if attempt == max_retries else 'attempted',
            'flag': flag,
            'steps': steps,
            'artifacts': {
                'generated_script': script_content,
                'final_attempt': attempt + 1
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return self.capabilities
