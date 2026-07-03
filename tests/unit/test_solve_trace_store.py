import hashlib

from core.knowledge_base.solve_trace_store import SolveTraceStore


def test_solve_trace_store_records_compact_success(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    flag = "SVIBGR{learn_from_the_route}"

    row_id = store.record_solve(
        {
            "id": "meshage",
            "category": "web",
            "description": "3d assets in a binary STL artifact",
            "url": "https://example.web.ctf.local",
            "files": ["/tmp/model.stl"],
        },
        {
            "challenge_id": "meshage",
            "agent_id": "coordinator",
            "status": "solved",
            "flag": flag,
            "iterations": 2,
            "steps": ["Initial", "Solved"],
            "history": [
                {
                    "agent_id": "web_agent",
                    "status": "solved",
                    "flag": flag,
                    "routing": {
                        "selected_target": "web_agent",
                        "execution_type": "agent",
                    },
                    "artifacts": {
                        "rendered_stl": "/tmp/projection.png",
                        "analysis": {"techniques": ["stl_projection"]},
                    },
                }
            ],
        },
    )

    rows = store.get_recent_solves()

    assert row_id is not None
    assert len(rows) == 1
    assert rows[0]["challenge_id"] == "meshage"
    assert rows[0]["category"] == "web"
    assert rows[0]["flag_prefix"] == "SVIBGR"
    assert rows[0]["flag_sha256"] == hashlib.sha256(flag.encode("utf-8")).hexdigest()
    assert flag not in rows[0].values()
    assert rows[0]["successful_agent"] == "web_agent"
    assert rows[0]["successful_target"] == "web_agent"
    assert rows[0]["route_signature"] == "agent:web_agent:solved"
    assert "artifact_keys" in rows[0]
    assert "rendered_stl" in rows[0]["artifact_keys"]
    assert rows[0]["techniques"] == ["stl_projection"]
    assert "keyword:stl" in rows[0]["indicators"]
    assert "file_ext:.stl" in rows[0]["indicators"]


def test_solve_trace_store_ignores_unsolved_attempts(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))

    row_id = store.record_solve(
        {"id": "miss", "category": "pwn"},
        {
            "challenge_id": "miss",
            "agent_id": "pwn_agent",
            "status": "attempted",
            "flag": None,
            "history": [],
        },
    )

    assert row_id is None
    assert store.get_recent_solves() == []


def test_solve_trace_store_returns_successful_patterns(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    store.record_solve(
        {"id": "jwt_web", "category": "web", "description": "jwt cookie challenge"},
        {
            "challenge_id": "jwt_web",
            "agent_id": "coordinator",
            "status": "solved",
            "flag": "HTB{jwt_pattern}",
            "history": [
                {
                    "agent_id": "web_agent",
                    "status": "solved",
                    "flag": "HTB{jwt_pattern}",
                    "routing": {
                        "selected_target": "web_agent",
                        "execution_type": "agent",
                    },
                    "artifacts": {"jwt_claims": {"admin": True}},
                }
            ],
        },
    )

    patterns = store.get_successful_patterns(category="web")

    assert patterns == [
        {
            "category": "web",
            "successful_agent": "web_agent",
            "successful_target": "web_agent",
            "route_signature": "agent:web_agent:solved",
            "indicators": ["category:web", "keyword:cookie", "keyword:jwt"],
            "artifact_keys": ["jwt_claims"],
            "techniques": [],
        }
    ]


def test_solve_trace_store_retrieves_runtime_technique_matches(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    store.record_solve(
        {"id": "pdf_chain", "category": "web"},
        {
            "status": "solved",
            "flag": "HTB{technique_memory}",
            "agent_id": "web_agent",
            "artifacts": {
                "chain": {
                    "techniques": [
                        "url_to_pdf_renderer",
                        "duplicate_parameter_parser_mismatch",
                    ]
                }
            },
        },
    )

    matches = store.find_by_techniques(
        ["url_to_pdf_renderer"],
        category="web",
    )

    assert len(matches) == 1
    assert matches[0]["successful_target"] == "web_agent"
    assert matches[0]["shared_techniques"] == ["url_to_pdf_renderer"]
    assert "HTB{technique_memory}" not in str(matches)


def test_solve_trace_store_finds_similar_patterns_without_flag_replay(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    store.record_solve(
        {
            "id": "matrix_route_training",
            "category": "misc",
            "description": "matrix route state conjugation",
            "files": ["/tmp/output.json"],
        },
        {
            "challenge_id": "matrix_route_training",
            "agent_id": "coordinator",
            "status": "solved",
            "flag": "SVIBGR{old_matrix_flag}",
            "history": [
                {
                    "agent_id": "coding_agent",
                    "status": "solved",
                    "flag": "SVIBGR{old_matrix_flag}",
                    "routing": {
                        "selected_target": "coding_agent",
                        "execution_type": "agent",
                    },
                    "artifacts": {
                        "solver_script": "solve.py",
                        "techniques": ["matrix_conjugation"],
                    },
                }
            ],
        },
    )

    matches = store.find_similar_patterns(
        {
            "id": "new_matrix_route",
            "category": "misc",
            "description": "recover live route from encrypted matrices",
            "files": ["/tmp/new/output.json"],
        }
    )

    assert len(matches) == 1
    assert matches[0]["successful_target"] == "coding_agent"
    assert matches[0]["similarity_score"] >= 6
    assert "keyword:matrix" in matches[0]["shared_indicators"]
    assert matches[0]["techniques"] == ["matrix_conjugation"]
    assert "SVIBGR{old_matrix_flag}" not in str(matches[0])


def test_solve_trace_store_does_not_match_on_category_only(tmp_path):
    store = SolveTraceStore(db_path=str(tmp_path / "solve_traces.db"))
    store.record_solve(
        {"id": "generic_misc", "category": "misc", "description": "count numbers"},
        {
            "challenge_id": "generic_misc",
            "agent_id": "coordinator",
            "status": "solved",
            "flag": "CTF{generic}",
            "history": [
                {
                    "agent_id": "coding_agent",
                    "status": "solved",
                    "flag": "CTF{generic}",
                    "routing": {
                        "selected_target": "coding_agent",
                        "execution_type": "agent",
                    },
                }
            ],
        },
    )

    assert store.find_similar_patterns({
        "id": "different_misc",
        "category": "misc",
        "description": "unrelated puzzle",
    }) == []
