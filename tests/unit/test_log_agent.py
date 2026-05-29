from agents.specialists.log_analysis.log_agent import LogAnalysisAgent


def test_log_agent_answers_status_specific_ip_question(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        "\n".join([
            '10.0.0.1 - - [07/May/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 403 512 "-" "curl/8.0"',
            '10.0.0.1 - - [07/May/2026:10:01:00 +0000] "GET /admin HTTP/1.1" 403 512 "-" "curl/8.0"',
            '10.0.0.2 - - [07/May/2026:10:02:00 +0000] "GET / HTTP/1.1" 403 512 "-" "curl/8.0"',
            '10.0.0.2 - - [07/May/2026:10:03:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
            '10.0.0.2 - - [07/May/2026:10:04:00 +0000] "GET /dashboard HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        ])
    )
    challenge = {
        "id": "log_status_ip",
        "category": "log",
        "description": "Which IP had the most 403 responses?",
        "files": [str(log_file)],
    }

    result = LogAnalysisAgent().solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "10.0.0.1"
    assert result["results"]["answer_type"] == "ip"


def test_log_agent_answers_most_requested_endpoint_question(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(
        "\n".join([
            '10.0.0.1 - - [07/May/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 200 512 "-" "curl/8.0"',
            '10.0.0.2 - - [07/May/2026:10:01:00 +0000] "GET /login HTTP/1.1" 200 512 "-" "curl/8.0"',
            '10.0.0.3 - - [07/May/2026:10:02:00 +0000] "GET /admin HTTP/1.1" 200 512 "-" "curl/8.0"',
        ])
    )
    challenge = {
        "id": "log_endpoint",
        "category": "log",
        "description": "Which endpoint was requested most often?",
        "files": [str(log_file)],
    }

    result = LogAnalysisAgent().solve_challenge(challenge)

    assert result["status"] == "solved"
    assert result["flag"] == "/admin"
    assert result["results"]["answer_type"] == "path"
