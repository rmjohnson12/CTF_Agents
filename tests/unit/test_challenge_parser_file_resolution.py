import json
import pytest

from challenges.challenge_parser import ChallengeParser, ParseError


def _write_challenge(tmp_path, files):
    payload = {
        "id": "res_test",
        "name": "Resolution Test",
        "category": "web",
        "description": "Audit the local source fixture.",
        "files": files,
    }
    challenge_path = tmp_path / "challenge.json"
    challenge_path.write_text(json.dumps(payload), encoding="utf-8")
    return challenge_path


def test_relative_file_resolved_against_json_directory(tmp_path):
    (tmp_path / "app.js").write_text("const flag = 'HTB{x}';", encoding="utf-8")
    challenge_path = _write_challenge(tmp_path, ["app.js"])

    parsed = ChallengeParser().parse_file(challenge_path)

    from pathlib import Path
    assert parsed["files"][0].endswith("app.js")
    # The resolved path must actually exist so agents can open it.
    assert Path(parsed["files"][0]).exists()
    assert Path(parsed["files"][0]).parent == tmp_path


def test_absolute_paths_are_left_untouched(tmp_path):
    real = tmp_path / "artifact.bin"
    real.write_text("data", encoding="utf-8")
    challenge_path = _write_challenge(tmp_path, [str(real)])

    parsed = ChallengeParser().parse_file(challenge_path)

    assert parsed["files"] == [str(real)]


def test_missing_file_is_left_as_is(tmp_path):
    challenge_path = _write_challenge(tmp_path, ["does_not_exist.txt"])

    parsed = ChallengeParser().parse_file(challenge_path)

    # Unresolvable entries are preserved verbatim rather than dropped.
    assert parsed["files"] == ["does_not_exist.txt"]


def test_parent_traversal_is_rejected(tmp_path):
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    challenge_path = _write_challenge(challenge_dir, ["../outside.txt"])

    with pytest.raises(ParseError, match="escapes"):
        ChallengeParser().parse_file(challenge_path)


def test_symlink_escape_is_rejected(tmp_path):
    challenge_dir = tmp_path / "challenge"
    challenge_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    (challenge_dir / "linked.txt").symlink_to(outside)
    challenge_path = _write_challenge(challenge_dir, ["linked.txt"])

    with pytest.raises(ParseError, match="escapes"):
        ChallengeParser().parse_file(challenge_path)
