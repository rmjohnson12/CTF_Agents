"""
Unit tests for challenges/challenge_parser.py.
"""

import json
from pathlib import Path

import pytest

from challenges.challenge_parser import ChallengeParser, ParseError, KNOWN_CATEGORIES


@pytest.fixture
def parser() -> ChallengeParser:
    return ChallengeParser()


# ---------------------------------------------------------------------------
# parse_file
# ---------------------------------------------------------------------------

def test_parse_file_reads_standard_json(tmp_path, parser):
    data = {
        "id": "test_001",
        "name": "Test Challenge",
        "category": "crypto",
        "description": "Decode this.",
        "files": [],
    }
    f = tmp_path / "challenge.json"
    f.write_text(json.dumps(data))

    result = parser.parse_file(f)

    assert result["id"] == "test_001"
    assert result["category"] == "crypto"
    assert result["files"] == []


def test_parse_file_missing_file_raises(parser):
    with pytest.raises(ParseError, match="not found"):
        parser.parse_file("/nonexistent/path/challenge.json")


def test_parse_file_invalid_json_raises(tmp_path, parser):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json }")
    with pytest.raises(ParseError, match="Invalid JSON"):
        parser.parse_file(bad)


def test_parse_file_non_object_json_raises(tmp_path, parser):
    f = tmp_path / "list.json"
    f.write_text("[1, 2, 3]")
    with pytest.raises(ParseError, match="Expected a JSON object"):
        parser.parse_file(f)


def test_parse_file_missing_required_field_raises(tmp_path, parser):
    # missing 'description'
    data = {"id": "x", "name": "X"}
    f = tmp_path / "partial.json"
    f.write_text(json.dumps(data))
    with pytest.raises(ParseError, match="'description' is required"):
        parser.parse_file(f)


# ---------------------------------------------------------------------------
# parse_dict — standard format
# ---------------------------------------------------------------------------

def test_parse_dict_fills_defaults_for_optional_fields(parser):
    minimal = {"id": "min_001", "name": "Minimal", "description": "Solve this."}
    result = parser.parse_dict(minimal)

    assert result["difficulty"] == "unknown"
    assert result["points"] == 0
    assert result["files"] == []
    assert result["hints"] == []
    assert result["tags"] == []
    assert result["url"] is None
    assert result["status"] == "active"
    assert result["flag"] is None
    assert result["metadata"] == {}


def test_parse_dict_preserves_existing_optional_fields(parser):
    data = {
        "id": "full_001",
        "name": "Full",
        "description": "Solve this.",
        "difficulty": "hard",
        "points": 500,
        "url": "http://ctf.example.com",
        "hints": ["Try harder"],
        "tags": ["crypto", "hard"],
        "files": ["/tmp/file.bin"],
        "flag": "CTF{real_flag}",
    }
    result = parser.parse_dict(data)

    assert result["difficulty"] == "hard"
    assert result["points"] == 500
    assert result["url"] == "http://ctf.example.com"
    assert result["hints"] == ["Try harder"]
    assert result["flag"] == "CTF{real_flag}"


def test_parse_dict_normalizes_category_to_lowercase(parser):
    result = parser.parse_dict({
        "id": "x",
        "name": "X",
        "description": "d",
        "category": "Cryptography",
    })
    assert result["category"] == "crypto"


def test_parse_dict_normalizes_id_to_string(parser):
    result = parser.parse_dict({
        "id": 42,
        "name": "Numeric ID",
        "description": "Has integer id.",
    })
    assert result["id"] == "42"
    assert isinstance(result["id"], str)


def test_parse_dict_coerces_string_files_to_list(parser):
    result = parser.parse_dict({
        "id": "x",
        "name": "X",
        "description": "d",
        "files": "/single/file.bin",
    })
    assert result["files"] == ["/single/file.bin"]


def test_parse_dict_coerces_string_hints_to_list(parser):
    result = parser.parse_dict({
        "id": "x",
        "name": "X",
        "description": "d",
        "hints": "One hint string",
    })
    assert result["hints"] == ["One hint string"]


def test_parse_dict_coerces_scalar_tags_to_single_item_list(parser):
    result = parser.parse_dict({
        "id": "x",
        "name": "X",
        "description": "d",
        "tags": 123,
    })
    assert result["tags"] == [123]


# ---------------------------------------------------------------------------
# parse_dict — CTFd format
# ---------------------------------------------------------------------------

def test_parse_dict_normalizes_ctfd_value_to_points(parser):
    ctfd = {
        "id": "1",
        "name": "CTFd Challenge",
        "description": "A CTFd challenge.",
        "category": "misc",
        "value": 250,
        "type": "standard",
        "flags": ["CTF{flag_value}"],
        "files": [],
        "tags": [],
        "hints": [],
    }
    result = parser.parse_dict(ctfd)

    assert result["points"] == 250
    assert "value" not in result
    assert result["flag"] == "CTF{flag_value}"
    assert "flags" not in result
    assert "type" not in result


def test_parse_dict_ctfd_flags_list_becomes_flag(parser):
    data = {
        "id": "2",
        "name": "Multi-flag",
        "description": "desc",
        "category": "web",
        "flags": ["CTF{first}", "CTF{second}"],
    }
    result = parser.parse_dict(data)
    assert result["flag"] == "CTF{first}"


def test_parse_dict_ctfd_empty_flags_leaves_flag_null(parser):
    data = {
        "id": "3",
        "name": "No flags",
        "description": "desc",
        "category": "misc",
        "flags": [],
    }
    result = parser.parse_dict(data)
    assert result["flag"] is None


# ---------------------------------------------------------------------------
# parse_dict — picoCTF format
# ---------------------------------------------------------------------------

def test_parse_dict_picoctf_pid_becomes_id(parser):
    pico = {
        "pid": 9876,
        "name": "picoCTF challenge",
        "description": "A pico challenge.",
        "category": "Cryptography",
        "value": 100,
        "files": [],
        "hints": [],
    }
    result = parser.parse_dict(pico)

    assert result["id"] == "9876"
    assert "pid" not in result
    assert result["points"] == 100
    assert result["category"] == "crypto"


# ---------------------------------------------------------------------------
# Category inference
# ---------------------------------------------------------------------------

def test_parse_dict_infers_crypto_from_description(parser):
    data = {
        "id": "inf_001",
        "name": "Inference Test",
        "description": "Decode this base64 cipher and find the flag.",
    }
    result = parser.parse_dict(data)
    assert result["category"] == "crypto"


def test_parse_dict_infers_web_from_tags(parser):
    data = {
        "id": "inf_002",
        "name": "Web Test",
        "description": "Find the vulnerability.",
        "tags": ["sql injection", "web"],
    }
    result = parser.parse_dict(data)
    assert result["category"] == "web"


def test_parse_dict_infers_forensics_from_pcap_mention(parser):
    data = {
        "id": "inf_003",
        "name": "Forensics",
        "description": "Analyze the pcap and recover credentials.",
    }
    result = parser.parse_dict(data)
    assert result["category"] == "forensics"


def test_parse_dict_unknown_category_when_no_signals(parser):
    data = {
        "id": "inf_004",
        "name": "Mystery",
        "description": "Something completely unrelated.",
    }
    result = parser.parse_dict(data)
    assert result["category"] == "unknown"


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

def test_validate_returns_empty_list_for_valid_challenge(parser):
    valid = {
        "id": "v_001",
        "name": "Valid",
        "description": "Valid challenge.",
        "category": "crypto",
        "files": [],
    }
    assert parser.validate(valid) == []


def test_validate_reports_missing_required_fields(parser):
    errors = parser.validate({})
    assert any("'id' is required" in e for e in errors)
    assert any("'name' is required" in e for e in errors)
    assert any("'description' is required" in e for e in errors)


def test_validate_reports_unknown_category(parser):
    data = {
        "id": "x",
        "name": "X",
        "description": "d",
        "category": "made_up_category",
    }
    errors = parser.validate(data)
    assert any("unknown category" in e for e in errors)


def test_validate_accepts_all_known_categories(parser):
    for cat in KNOWN_CATEGORIES:
        data = {"id": "x", "name": "X", "description": "d", "category": cat}
        errors = parser.validate(data)
        assert not any("unknown category" in e for e in errors), (
            f"category '{cat}' was rejected unexpectedly"
        )


def test_parse_dict_missing_id_raises(parser):
    with pytest.raises(ParseError, match="'id' is required"):
        parser.parse_dict({"name": "No ID", "description": "desc"})


def test_parse_dict_missing_name_raises(parser):
    with pytest.raises(ParseError, match="'name' is required"):
        parser.parse_dict({"id": "x", "description": "desc"})


def test_parse_dict_missing_description_raises(parser):
    with pytest.raises(ParseError, match="'description' is required"):
        parser.parse_dict({"id": "x", "name": "X"})


def test_parse_dict_non_dict_input_raises(parser):
    with pytest.raises(ParseError):
        parser.parse_dict("not a dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Real template files (smoke test against our own fixtures)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "example_crypto_base64.json",
    "example_crypto_xor.json",
    "example_crypto_hex.json",
    "example_web_challenge.json",
    "example_crypto_challenge.json",
])
def test_parse_existing_templates(parser, filename):
    template_path = (
        Path(__file__).resolve().parents[2] / "challenges" / "templates" / filename
    )
    if not template_path.exists():
        pytest.skip(f"Template not found: {filename}")
    result = parser.parse_file(template_path)
    assert result["id"]
    assert result["name"]
    assert result["description"]
    assert isinstance(result["files"], list)
    assert isinstance(result["hints"], list)
