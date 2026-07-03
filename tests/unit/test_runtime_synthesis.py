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
