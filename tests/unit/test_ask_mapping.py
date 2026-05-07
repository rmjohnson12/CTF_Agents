import json

from ask import _heuristic_challenge_from_instruction, _normalize_path, _normalize_url, _unwrap_ask_command


def test_heuristic_mapping_loads_referenced_challenge_json(tmp_path, monkeypatch):
    challenge_path = tmp_path / "example.json"
    challenge_path.write_text(json.dumps({
        "id": "json_crypto",
        "name": "JSON Crypto",
        "category": "crypto",
        "description": "Decode this base64 string: 'Q1RGe2pzb25fbG9hZGVkfQ=='",
        "files": [],
        "metadata": {"author": "test"},
    }))

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Decode this base64 challenge from example.json",
        available_tools=["python3"],
    )

    assert challenge["id"] == "json_crypto"
    assert challenge["category"] == "crypto"
    assert challenge["files"] == []
    assert challenge["metadata"]["author"] == "test"
    assert challenge["metadata"]["system_tools"] == ["python3"]


def test_heuristic_mapping_keeps_non_json_artifacts_as_files(tmp_path, monkeypatch):
    artifact = tmp_path / "cipher.txt"
    artifact.write_text("Q1RGe2FydGlmYWN0X2ZpbGV9")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Decode this base64 file cipher.txt",
        available_tools=[],
    )

    assert challenge["id"] == "heuristic_task"
    assert challenge["category"] == "crypto"
    assert challenge["files"] == [str(artifact)]


def test_heuristic_mapping_routes_hidden_binary_artifact_to_forensics(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"binary-ish data")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Analyze this file for hidden flags. File is located in artifact.bin",
        available_tools=[],
    )

    assert challenge["category"] == "forensics"
    assert challenge["files"] == [str(artifact)]


def test_heuristic_mapping_routes_auth_text_file_to_log(tmp_path, monkeypatch):
    log_file = tmp_path / "auth_events.txt"
    log_file.write_text("Failed password for root from 192.0.2.10 port 22 ssh2")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Analyze auth_events.txt and identify which IP executed a brute force SSH attack",
        available_tools=[],
    )

    assert challenge["category"] == "log"
    assert challenge["files"] == [str(log_file)]


def test_unwrap_ask_command_from_interactive_prompt():
    instruction = _unwrap_ask_command(
        'python3 ask.py "Analyze this file for hidden flags. File is located in artifact.bin"'
    )

    assert instruction == "Analyze this file for hidden flags. File is located in artifact.bin"


def test_normalize_path_recovers_downloads_path_from_llm_output(tmp_path, monkeypatch):
    home = tmp_path / "home"
    download_file = home / "Downloads" / "challenge.py"
    download_file.parent.mkdir(parents=True)
    download_file.write_text("print('challenge')")
    monkeypatch.setenv("HOME", str(home))

    assert _normalize_path("Downloads/challenge.py") == str(download_file)


def test_normalize_url_adds_scheme_to_bare_ip_port():
    assert _normalize_url("154.57.164.65:30433") == "http://154.57.164.65:30433"


def test_heuristic_mapping_normalizes_bare_ip_port_to_http_url():
    challenge = _heuristic_challenge_from_instruction(
        "Help desk JWT challenge at 154.57.164.65:30433",
        available_tools=[],
    )

    assert challenge["category"] == "web"
    assert challenge["url"] == "http://154.57.164.65:30433"


def test_heuristic_mapping_routes_local_docker_folder_to_web(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "docker_challenge"
    challenge_dir.mkdir()
    (challenge_dir / "Dockerfile").write_text("FROM python:3.12-alpine\nEXPOSE 8000\n")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Solve this Docker challenge in docker_challenge",
        available_tools=[],
    )

    assert challenge["category"] == "web"
    assert challenge["files"] == [str(challenge_dir)]
