import sys
from tools.common.runner import ToolRunner, RunnerConfig


def test_runner_allowlist_blocks():
    #runner = ToolRunner(RunnerConfig(allowlist={"python"}))
    runner = ToolRunner(RunnerConfig(allowlist=("python", "python3", "python3.13")))
    try:
        runner.run(["nope-not-allowed", "hi"])
        assert False, "Expected PermissionError"
    except PermissionError:
        assert True


def test_runner_runs_python_print():
   #runner = ToolRunner(RunnerConfig(allowlist={"python"}))
    runner = ToolRunner(RunnerConfig(allowlist=("python", "python3", "python3.13")))
    res = runner.run([sys.executable, "-c", "print('hello')"], timeout_s=5)
    assert "hello" in res.stdout
    assert res.timed_out is False
