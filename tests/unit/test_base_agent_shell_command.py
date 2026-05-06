import sys

from agents.base_agent import AgentType, BaseAgent


class ShellCommandAgent(BaseAgent):
    def __init__(self):
        super().__init__("shell_command_test_agent", AgentType.SPECIALIST)

    def analyze_challenge(self, challenge):
        return {}

    def solve_challenge(self, challenge):
        return {}

    def get_capabilities(self):
        return []


def test_run_shell_command_accepts_argument_list():
    agent = ShellCommandAgent()

    result = agent.run_shell_command([sys.executable, "-c", "print('safe list command')"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "safe list command"
    assert result.argv == [sys.executable, "-c", "print('safe list command')"]


def test_run_shell_command_splits_string_without_shell_injection(tmp_path):
    agent = ShellCommandAgent()
    marker = tmp_path / "injected"

    result = agent.run_shell_command(
        f"{sys.executable} -c \"print('safe string command')\" ; touch {marker}"
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "safe string command"
    assert not marker.exists()
