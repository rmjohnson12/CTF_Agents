"""Tests for the runtime-synthesis `compute` op (model-authored computation).

The compute op is what lets the agentic loop actually *work* a problem instead
of only fetching/decoding — it runs model-written Python through the
policy-enforced PythonTool (disabled by default, Docker/host opt-in), exposing
prior operation outputs as ``inputs[name]``.
"""
import os

import pytest

from core.runtime_synthesis import RuntimeToolSynthesisLoop, RuntimeToolValidationError
from tools.common.result import ToolResult


class _StubPython:
    """Deterministic stand-in for PythonTool, capturing the script it's given."""

    def __init__(self, stdout="", stderr="", exit_code=0, timed_out=False):
        self._r = (stdout, stderr, exit_code, timed_out)
        self.last_script = None
        self.last_artifacts = None

    def run(self, script, timeout_s=30, artifact_paths=None, allow_network=False, **_):
        self.last_script = script
        self.last_artifacts = artifact_paths
        stdout, stderr, code, timed = self._r
        return ToolResult(argv=["python", "-"], stdout=stdout, stderr=stderr,
                          exit_code=code, timed_out=timed, duration_s=0.01)


def _loop(python_tool):
    return RuntimeToolSynthesisLoop(reasoner=None, python_tool=python_tool)


def _spec(code, **op):
    return {"name": "t", "hypothesis": "h", "evidence": ["e"],
            "operations": [{"op": "compute", "save_as": "answer", "code": code, **op}]}


def test_compute_is_allowed_and_validates():
    loop = _loop(_StubPython())
    loop.validate_spec(_spec("print(1)"), {"description": "d"})
    with pytest.raises(RuntimeToolValidationError):
        loop.validate_spec(_spec(""), {"description": "d"})  # empty code
    with pytest.raises(RuntimeToolValidationError):
        loop.validate_spec(_spec("x" * 10_001), {"description": "d"})  # oversized


def test_compute_runs_and_captures_flag_from_stdout():
    stub = _StubPython(stdout="HTB{computed_by_the_model}\n")
    loop = _loop(stub)
    result = loop.execute_spec(
        _spec("print('HTB{computed_by_the_model}')"),
        {"id": "c", "description": "d", "files": []},
        initial_values={"target": "1 2 3"},
    )
    assert result["status"] == "solved"
    assert result["flag"] == "HTB{computed_by_the_model}"
    # Prior outputs must be injected as inputs[...] for the model's code to use.
    assert "inputs = " in stub.last_script


def test_compute_disabled_backend_is_a_safe_rejection():
    stub = _StubPython(stderr="Host Python script execution is disabled by default.", exit_code=126)
    with pytest.raises(RuntimeToolValidationError, match="disabled"):
        _loop(stub)._execute_operation(
            "compute", {"op": "compute", "save_as": "a", "code": "print(1)"},
            {"id": "c", "description": "d", "files": []}, {"challenge_description": "d"},
        )


def test_compute_timeout_is_rejected():
    stub = _StubPython(timed_out=True)
    with pytest.raises(RuntimeToolValidationError, match="time budget"):
        _loop(stub)._execute_operation(
            "compute", {"op": "compute", "save_as": "a", "code": "print(1)", "timeout_s": 5},
            {"id": "c", "description": "d", "files": []}, {"challenge_description": "d"},
        )


def test_compute_end_to_end_solves_swap_problem_under_host_exec(monkeypatch):
    # Real execution proof (not a stub): the model's algorithm solves the
    # "Three Tankards" swap-tracking problem from an injected input variable.
    monkeypatch.setenv("CTF_AGENTS_ALLOW_HOST_PYTHON_EXECUTION", "1")
    monkeypatch.delenv("CTF_AGENTS_SANDBOX", raising=False)
    loop = RuntimeToolSynthesisLoop(reasoner=None)  # real PythonTool
    code = (
        "d=inputs['problem'].split()\n"
        "n=int(d[0]);m=int(d[1]);q=int(d[2]);i=3\n"
        "at=list(range(n+1));pos=list(range(n+1))\n"
        "for _ in range(m):\n"
        "    a=int(d[i]);b=int(d[i+1]);i+=2\n"
        "    ia,ib=at[a],at[b];at[a],at[b]=ib,ia;pos[ia],pos[ib]=b,a\n"
        "print('HTB{'+'_'.join(str(pos[int(d[i+k])]) for k in range(q))+'_tankards}')\n"
    )
    result = loop.execute_spec(
        _spec(code),
        {"id": "tankards", "description": "swap tracking", "files": []},
        initial_values={"problem": "5 4 2 1 3 2 4 3 5 4 1 3 5"},
    )
    assert result["status"] == "solved"
    assert result["flag"] == "HTB{4_3_tankards}"
