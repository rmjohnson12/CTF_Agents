import sys
from tools.common.runner import ToolRunner, RunnerConfig
from tools.common.python_tool import PythonTool


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


def test_runner_does_not_inherit_secret_environment_by_default(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-secret")
    runner = ToolRunner(RunnerConfig(allowlist=("python", "python3", "python3.13")))

    res = runner.run(
        [sys.executable, "-c", "import os; print(os.getenv('OPENAI_API_KEY'))"],
        timeout_s=5,
    )

    assert "None" in res.stdout


def test_runner_full_environment_inheritance_is_opt_in(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-secret")
    runner = ToolRunner(RunnerConfig(
        allowlist=("python", "python3", "python3.13"),
        inherit_env=True,
    ))

    res = runner.run(
        [sys.executable, "-c", "import os; print(os.getenv('OPENAI_API_KEY'))"],
        timeout_s=5,
    )

    assert "sk-real-secret" in res.stdout


def test_python_tool_blocks_generated_script_execution_by_default(monkeypatch):
    monkeypatch.delenv("CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION", raising=False)

    res = PythonTool().run("print('should not run')")

    assert res.exit_code == 126
    assert res.stdout == ""
    assert "Host Python script execution is disabled by default" in res.stderr
    assert "CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION=1" in res.stderr


def test_python_tool_host_execution_is_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION", "1")

    res = PythonTool().run("print('trusted run')", timeout_s=5)

    assert res.exit_code == 0
    assert "trusted run" in res.stdout
