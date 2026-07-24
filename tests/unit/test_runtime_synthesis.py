import subprocess
from types import SimpleNamespace

import pytest

from core.runtime_synthesis import (
    RuntimeToolSynthesisLoop,
    RuntimeToolValidationError,
)


class ProposalReasoner:
    def __init__(self, proposal):
        self.proposal = proposal

    def synthesize_runtime_tool(self, challenge, history, steps, allowed_operations):
        return self.proposal


class FakeHttpTool:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def fetch(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return SimpleNamespace(body_preview=self.body)


class SequencedReasoner:
    def __init__(self):
        self.turn = 0
        self.histories = []

    def synthesize_runtime_tool(self, challenge, history, steps, allowed_operations):
        self.histories.append(history)
        self.turn += 1
        if self.turn == 1:
            return {
                "name": "inspect_root",
                "hypothesis": "The root page may disclose a next endpoint.",
                "evidence": ["The root page was observed."],
                "operations": [
                    {"op": "http_request", "url": "/", "save_as": "response"}
                ],
            }
        assert "next=/secret" in str(history[-1])
        return {
            "name": "follow_observed_endpoint",
            "hypothesis": "The observed endpoint may contain the result.",
            "evidence": ["next=/secret"],
            "operations": [
                {"op": "http_request", "url": "/secret", "save_as": "response"}
            ],
        }


class CrossTurnVariableReasoner:
    def __init__(self):
        self.turn = 0

    def synthesize_runtime_tool(self, challenge, history, steps, allowed_operations):
        self.turn += 1
        if self.turn == 1:
            return {
                "name": "read_encoded",
                "evidence": ["The challenge supplied encoded.txt."],
                "operations": [{
                    "op": "read_artifact",
                    "path": challenge["files"][0],
                    "save_as": "artifact_text",
                }],
            }
        return {
            "name": "decode_prior_output",
            "evidence": ["SFRCe2Nyb3NzX3R1cm5fdmFyaWFibGV9"],
            "operations": [{
                "op": "decode",
                "source": "artifact_text",
                "encoding": "base64",
                "save_as": "decoded",
            }],
        }


class RoutedHttpTool:
    def __init__(self):
        self.calls = []

    def fetch(self, url, **kwargs):
        self.calls.append(url)
        body = "next=/secret" if url.endswith("/") else "HTB{agentic_runtime_loop}"
        return SimpleNamespace(body_preview=body)


def test_runtime_synthesis_executes_bounded_http_decode_chain():
    proposal = {
        "name": "decode_api_result",
        "hypothesis": "The API returns a base64 flag field.",
        "evidence": ["Recon found /api/result and an encoded value."],
        "operations": [
            {"op": "http_request", "url": "/api/result", "save_as": "response"},
            {
                "op": "regex_extract",
                "source": "response",
                "pattern": r'encoded=([A-Za-z0-9+/=]+)',
                "group": 1,
                "save_as": "encoded",
            },
            {"op": "decode", "source": "encoded", "encoding": "base64", "save_as": "decoded"},
        ],
    }
    http = FakeHttpTool("encoded=SFRCe3J1bnRpbWVfdG9vbH0=")
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(proposal), http_tool=http)

    result = loop.attempt(
        {"id": "runtime", "url": "http://target.local:31337", "files": []},
        [],
        ["Recon found /api/result"],
    )

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{runtime_tool}"
    assert http.calls[0][0] == "http://target.local:31337/api/result"
    assert result["artifacts"]["runtime_tool_synthesis"]["validated"] is True


def test_runtime_synthesis_feeds_observations_back_to_model_for_next_turn():
    reasoner = SequencedReasoner()
    http = RoutedHttpTool()
    loop = RuntimeToolSynthesisLoop(reasoner, http_tool=http, max_turns=3)

    result = loop.attempt(
        {"id": "runtime", "url": "http://target.local:31337", "files": []},
        [],
        ["The root page was observed."],
    )

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{agentic_runtime_loop}"
    assert http.calls == [
        "http://target.local:31337/",
        "http://target.local:31337/secret",
    ]
    metadata = result["artifacts"]["runtime_tool_synthesis"]
    assert metadata["agentic_loop"] is True
    assert metadata["turns_used"] == 2
    assert metadata["tool_names"] == ["inspect_root", "follow_observed_endpoint"]
    assert "runtime_tool_observation" not in str(result["artifacts"])


def test_runtime_synthesis_preserves_bounded_variables_across_turns(tmp_path):
    artifact = tmp_path / "encoded.txt"
    artifact.write_text("SFRCe2Nyb3NzX3R1cm5fdmFyaWFibGV9")
    loop = RuntimeToolSynthesisLoop(CrossTurnVariableReasoner(), max_turns=2)

    result = loop.attempt(
        {"id": "runtime", "files": [str(artifact)]},
        [],
        ["The challenge supplied encoded.txt."],
    )

    assert result["status"] == "solved"
    assert result["flag"] == "HTB{cross_turn_variable}"
    assert "_runtime_values" not in result


def test_runtime_synthesis_rejects_cross_origin_http():
    spec = {
        "name": "leave_scope",
        "evidence": ["A URL was observed."],
        "operations": [
            {"op": "http_request", "url": "https://other.example/", "save_as": "response"}
        ],
    }
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(spec), http_tool=FakeHttpTool(""))

    with pytest.raises(RuntimeToolValidationError, match="challenge origin"):
        loop.validate_spec(spec, {"url": "http://target.local:31337"})


def test_runtime_synthesis_reads_only_supplied_artifacts(tmp_path):
    allowed = tmp_path / "challenge"
    allowed.mkdir()
    artifact = allowed / "output.txt"
    artifact.write_text("HTB{artifact_runtime_tool}")
    outside = tmp_path / "outside.txt"
    outside.write_text("HTB{outside}")
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(None))
    challenge = {"id": "files", "files": [str(allowed)]}
    spec = {
        "name": "read_output",
        "evidence": ["The challenge supplied output.txt."],
        "operations": [
            {"op": "read_artifact", "path": str(artifact), "save_as": "content"}
        ],
    }

    result = loop.execute_spec(spec, challenge)

    assert result["flag"] == "HTB{artifact_runtime_tool}"
    bad = dict(spec)
    bad["operations"] = [
        {"op": "read_artifact", "path": str(outside), "save_as": "content"}
    ]
    with pytest.raises(RuntimeToolValidationError, match="outside provided"):
        loop.validate_spec(bad, challenge)


def test_runtime_synthesis_disassembles_only_supplied_artifact(monkeypatch, tmp_path):
    artifact = tmp_path / "challenge.elf"
    artifact.write_bytes(b"\x7fELF")
    calls = []

    monkeypatch.setattr("core.runtime_synthesis.shutil.which", lambda name: "/usr/bin/r2")
    monkeypatch.setattr(
        "core.runtime_synthesis.subprocess.run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs))
            or SimpleNamespace(
                stdout="0x1000 13000000 nop\nHTB{disassembly_tool}",
                stderr="",
                returncode=0,
            )
        ),
    )
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(None))
    challenge = {"id": "reverse", "files": [str(artifact)]}
    spec = {
        "name": "inspect_binary",
        "evidence": ["The challenge supplied challenge.elf."],
        "operations": [{
            "op": "disassemble_artifact",
            "path": str(artifact),
            "max_bytes": 2048,
            "save_as": "disassembly",
        }],
    }

    loop.validate_spec(spec, challenge)
    result = loop.execute_spec(spec, challenge)

    assert result["flag"] == "HTB{disassembly_tool}"
    assert calls[0][0][0] == "/usr/bin/r2"
    assert calls[0][0][-1] == str(artifact)
    assert calls[0][1]["timeout"] == 30


def test_runtime_synthesis_inspects_only_explicit_git_repository(monkeypatch, tmp_path):
    repository = tmp_path / "challenge"
    repository.mkdir()
    (repository / ".git").mkdir()
    nested = repository / "nested"
    nested.mkdir()
    calls = []

    monkeypatch.setattr("core.runtime_synthesis.shutil.which", lambda name: "/usr/bin/git")
    monkeypatch.setattr(
        "core.runtime_synthesis.subprocess.run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs))
            or SimpleNamespace(
                stdout="-flag = HTB{deleted_history}\n",
                stderr="",
                returncode=0,
            )
        ),
    )
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(None))
    challenge = {"id": "git", "files": [str(repository)]}
    spec = {
        "name": "inspect_deleted_files",
        "evidence": ["The challenge supplied a Git repository."],
        "operations": [{
            "op": "inspect_git_history",
            "path": str(repository),
            "max_commits": 12,
            "save_as": "history",
        }],
    }

    loop.validate_spec(spec, challenge)
    result = loop.execute_spec(spec, challenge)

    assert result["flag"] == "HTB{deleted_history}"
    assert calls[0][0][:4] == [
        "/usr/bin/git", "-C", str(repository), "--no-pager"
    ]
    assert "--max-count=12" in calls[0][0]
    assert calls[0][1]["timeout"] == 30

    nested_spec = {
        **spec,
        "operations": [{
            **spec["operations"][0],
            "path": str(nested),
        }],
    }
    with pytest.raises(RuntimeToolValidationError, match="explicitly supplied"):
        loop.validate_spec(nested_spec, challenge)


def test_runtime_synthesis_git_history_includes_deleted_content(tmp_path):
    repository = tmp_path / "challenge"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Test"],
        check=True,
    )
    erased = repository / "erased.txt"
    erased.write_text("training rite: campaign-key=remember-me\n")
    subprocess.run(["git", "-C", str(repository), "add", "erased.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "add rite"],
        check=True,
    )
    erased.unlink()
    subprocess.run(["git", "-C", str(repository), "add", "-u"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "erase rite"],
        check=True,
    )

    loop = RuntimeToolSynthesisLoop(ProposalReasoner(None))
    challenge = {"id": "git", "files": [str(repository)]}
    output = loop._execute_operation(
        "inspect_git_history",
        {
            "op": "inspect_git_history",
            "path": str(repository),
            "max_commits": 10,
            "save_as": "history",
        },
        challenge,
        {},
    )

    assert "training rite: campaign-key=remember-me" in output
    assert "Subject: erase rite" in output


def test_runtime_synthesis_rejects_missing_evidence():
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(None))
    with pytest.raises(RuntimeToolValidationError, match="observed evidence"):
        loop.validate_spec(
            {
                "name": "guess",
                "evidence": [],
                "operations": [
                    {
                        "op": "regex_extract",
                        "source": "challenge_description",
                        "pattern": "x",
                        "save_as": "value",
                    }
                ],
            },
            {},
        )


def test_runtime_synthesis_rejects_unobserved_evidence():
    spec = {
        "name": "invented_route",
        "evidence": ["The trace exposed /admin/flag."],
        "operations": [
            {"op": "http_request", "url": "/admin/flag", "save_as": "response"}
        ],
    }
    loop = RuntimeToolSynthesisLoop(ProposalReasoner(spec), http_tool=FakeHttpTool(""))

    result = loop.attempt(
        {"id": "runtime", "url": "http://target.local:31337"},
        [],
        ["Only the root page was observed."],
    )

    assert result["status"] == "attempted"
    assert "evidence is not present" in result["steps"][0]
