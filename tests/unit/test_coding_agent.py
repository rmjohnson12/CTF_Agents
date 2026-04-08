import pytest
from agents.specialists.misc.coding_agent import CodingAgent
from core.decision_engine.llm_reasoner import LLMReasoner
from tools.common.result import ToolResult
from typing import Dict, Any

class MockReasoner:
    def generate_script(self, challenge, task_description):
        return "print('CTF{coding_is_fun}')"

class MockPythonTool:
    def run(self, script_content, args=None, timeout_s=30):
        # Simulate script execution finding a flag
        return ToolResult(
            argv=["python", "tmp.py"],
            stdout="Starting execution...\nCTF{coding_is_fun}\nDone.",
            stderr="",
            exit_code=0,
            timed_out=False,
            duration_s=0.1
        )

def test_coding_agent_solve_success():
    reasoner = MockReasoner()
    python_tool = MockPythonTool()
    agent = CodingAgent(reasoner=reasoner, python_tool=python_tool)
    
    challenge = {
        "id": "code_1",
        "description": "Write a script to print the flag"
    }
    
    result = agent.solve_challenge(challenge)
    
    assert result["status"] == "solved"
    assert result["flag"] == "CTF{coding_is_fun}"
    assert "Executing script (Attempt 1)..." in result["steps"]
    assert result["artifacts"]["generated_script"] == "print('CTF{coding_is_fun}')"

def test_coding_agent_analyze():
    agent = CodingAgent()
    
    challenge = {
        "description": "Please write a python script to automate this"
    }
    analysis = agent.analyze_challenge(challenge)
    assert analysis["can_handle"] is True
    assert analysis["confidence"] > 0.8

    challenge = {
        "description": "Decrypt this message"
    }
    analysis = agent.analyze_challenge(challenge)
def test_coding_agent_self_correction_success():
    class MockFixReasoner:
        def __init__(self):
            self.calls = 0
        def generate_script(self, challenge, task_description):
            return "print('error')" # Initial bad script
        def fix_script(self, challenge, script, error):
            self.calls += 1
            return "print('CTF{fixed_flag}')" # Fixed script

    class MockFailingPythonTool:
        def __init__(self):
            self.calls = 0
        def run(self, script_content, args=None, timeout_s=30):
            self.calls += 1
            if "fixed_flag" in script_content:
                return ToolResult(["python"], "CTF{fixed_flag}", "", 0, False, 0.1)
            return ToolResult(["python"], "no flag here", "some error", 1, False, 0.1)

    reasoner = MockFixReasoner()
    python_tool = MockFailingPythonTool()
    agent = CodingAgent(reasoner=reasoner, python_tool=python_tool)
    
    challenge = {"id": "code_fix", "description": "Fix this script"}
    result = agent.solve_challenge(challenge)
    
    assert result["status"] == "solved"
    assert result["flag"] == "CTF{fixed_flag}"
    assert reasoner.calls == 1
    assert python_tool.calls == 2 # 1 fail, 1 success after fix
