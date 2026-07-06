"""Unit tests for the interactive web-coding autograder playbook (no network).

Covers the HTB "Pivot Chain" pattern: a Monaco-editor instance that grades
submitted code via a /run endpoint, where the real problem (a weighted-graph
safest-path / Dijkstra task) is on the page, not in the challenge description.
"""
import subprocess
import sys
from unittest.mock import MagicMock, patch

from agents.specialists.misc.coding_agent import CodingAgent, _SHORTEST_PATH_PROGRAM
from core.utils.security import temporary_allowed_networks

_PAGE = """
<html><head>
<script src="https://cdn.jsdelivr.net/npm/monaco-editor/loader.js"></script>
</head><body>
<h1>Pivot Chain</h1>
<p>Use the network map to identify the safest path - the sequence of pivots with
the lowest cumulative detection risk - to reach the Core Administration Server.</p>
<p>Input Format: two integers N and M, the start host and target host, then M
directed paths "host_a host_b risk". Output the lowest cumulative detection risk.</p>
<script>
function run(code){ fetch("/run", {method:"POST", headers:{"Content-Type":"application/json"},
  body: JSON.stringify({code: code, language: "python"})}); }
</script>
</body></html>
"""


def _run_program(stdin_text):
    out = subprocess.run(
        [sys.executable, "-c", _SHORTEST_PATH_PROGRAM],
        input=stdin_text, capture_output=True, text=True, timeout=15,
    )
    return out.stdout.strip()


def test_dijkstra_program_matches_example():
    example = ("5 6 host_1 host_5\n"
               "host_1 host_2 7\nhost_2 host_3 6\nhost_3 host_4 6\n"
               "host_4 host_5 7\nhost_5 host_3 11\nhost_1 host_4 20\n")
    assert _run_program(example) == "26"


def test_dijkstra_prefers_cheaper_multi_hop_over_direct():
    # direct a->c is 100, but a->b->c is 3; must pick 3.
    assert _run_program("3 3 a c\na b 1\nb c 2\na c 100\n") == "3"


def test_dijkstra_unreachable_target_returns_minus_one():
    assert _run_program("2 0 a b\n") == "-1"


def test_detect_run_endpoint():
    agent = CodingAgent()
    assert agent._detect_run_endpoint(_PAGE) == "/run"
    assert agent._detect_run_endpoint('x = "/run";') == "/run"
    assert agent._detect_run_endpoint("<html>nothing here</html>") is None


def test_extract_problem_statement_strips_markup():
    agent = CodingAgent()
    text = agent._extract_problem_statement(_PAGE)
    assert "safest path" in text
    assert "<script>" not in text and "fetch(" not in text


def test_looks_like_shortest_path_detection():
    agent = CodingAgent()
    assert agent._looks_like_shortest_path(agent._extract_problem_statement(_PAGE))
    assert not agent._looks_like_shortest_path("Reverse the input string and print it.")


def test_web_coding_challenge_solves_graph_task_end_to_end():
    agent = CodingAgent()
    steps = []

    def fake_get(url, timeout=0):
        return MagicMock(status_code=200, text=_PAGE)

    def fake_post(url, json=None, timeout=0):
        # The grader only accepts the correct Dijkstra answer for the sample.
        assert url.endswith("/run")
        assert json["language"] == "python"
        answer = _run_program("5 6 host_1 host_5\nhost_1 host_2 7\nhost_2 host_3 6\n"
                              "host_3 host_4 6\nhost_4 host_5 7\nhost_5 host_3 11\nhost_1 host_4 20\n")
        completed = answer == "26"
        body = {"challengeCompleted": completed,
                "flag": "HTB{unit_web_coding_fixture}" if completed else "",
                "result": {}}
        return MagicMock(status_code=200, text=str(body).replace("'", '"'),
                         json=MagicMock(return_value=body))

    with temporary_allowed_networks(["target"]), \
            patch("requests.get", fake_get), patch("requests.post", fake_post):
        result = agent._try_web_coding_challenge(
            {"id": "htb-950", "url": "http://target:1337", "category": "Coding"}, steps
        )

    assert result is not None
    flag, techniques = result
    assert flag == "HTB{unit_web_coding_fixture}"
    assert "graph_shortest_path" in techniques


def test_web_coding_challenge_declines_non_coding_page():
    agent = CodingAgent()
    with temporary_allowed_networks(["target"]), \
            patch("requests.get", lambda url, timeout=0: MagicMock(status_code=200, text="<html>hi</html>")):
        assert agent._try_web_coding_challenge(
            {"id": "x", "url": "http://target:1337"}, []
        ) is None
