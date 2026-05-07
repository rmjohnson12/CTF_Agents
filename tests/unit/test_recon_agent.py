from tools.common.result import ToolResult
from tools.network.nmap import NmapPort, NmapScan
from tools.web.dirsearch import DirsearchEntry, DirsearchResult
from tools.web.http_fetch import HttpFetchResult

from agents.base_agent import AgentType
from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.support.recon_agent import ReconAgent
from core.decision_engine.llm_reasoner import LLMReasoner


class FakeHttpTool:
    def fetch(self, url, **kwargs):
        return HttpFetchResult(
            url=url,
            final_url=url + "/",
            method="GET",
            status_code=200,
            headers={"X-Powered-By": "Next.js"},
            body_preview="<html><script src='/_next/static/app.js'></script></html>",
            elapsed_s=0.01,
        )


class FakeDirsearchTool:
    def run(self, url, **kwargs):
        return DirsearchResult(
            target_url=url,
            entries=[DirsearchEntry(status=200, size="123B", url="/admin")],
            raw=ToolResult(["dirsearch"], "", "", 0, False, 0.01),
        )


class FakeNmapTool:
    def scan_top(self, target, **kwargs):
        return NmapScan(
            target=target,
            ports=[NmapPort(port=80, proto="tcp", state="open", service="http")],
            raw=ToolResult(["nmap"], "80/tcp open http", "", 0, False, 0.01),
        )


def _agent():
    return ReconAgent(
        http_tool=FakeHttpTool(),
        dirsearch_tool=FakeDirsearchTool(),
        nmap_tool=FakeNmapTool(),
    )


def test_recon_agent_is_support_agent():
    assert _agent().agent_type == AgentType.SUPPORT


def test_recon_agent_extracts_target_and_collects_artifacts():
    challenge = {
        "id": "recon_001",
        "name": "Recon",
        "category": "web",
        "description": "Enumerate http://127.0.0.1:8080 and fingerprint it.",
    }

    result = _agent().solve_challenge(challenge)

    assert result["status"] == "attempted"
    assert "http://127.0.0.1:8080" in result["artifacts"]["recon_targets"]
    assert result["artifacts"]["http_probes"][0]["status_code"] == 200
    assert result["artifacts"]["discovered_paths"][0]["url"] == "/admin"
    assert result["artifacts"]["service_scans"][0]["open_ports"][0]["service"] == "http"
    assert "next.js" in result["artifacts"]["technologies"]


def test_heuristic_reasoner_routes_explicit_recon_to_recon_agent():
    challenge = {
        "id": "recon_002",
        "name": "Recon",
        "category": "web",
        "description": "Please enumerate and scan 127.0.0.1:8080 before exploiting.",
    }

    reasoner = LLMReasoner(client=None)
    reasoner.client = None
    analysis = reasoner.analyze_challenge(challenge)
    next_action = reasoner.choose_next_action(challenge, analysis, [])

    assert analysis.recommended_target == "recon_agent"
    assert next_action["target"] == "recon_agent"
    assert next_action["next_action"] == "run_agent"


def test_coordinator_can_run_registered_support_agent():
    coordinator = CoordinatorAgent(llm_client=None)
    coordinator.register_agent(_agent())

    result = coordinator._run_selected_agent(
        {
            "id": "recon_003",
            "category": "web",
            "description": "recon http://127.0.0.1:8080",
        },
        "recon_agent",
        [],
    )

    assert result["agent_id"] == "recon_agent"
    assert result["routing"]["selected_target"] == "recon_agent"
    assert result["artifacts"]["http_probes"][0]["status_code"] == 200
