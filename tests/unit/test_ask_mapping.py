import json

from ask import _heuristic_challenge_from_instruction


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
