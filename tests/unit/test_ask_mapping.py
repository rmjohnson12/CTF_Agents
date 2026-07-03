import json

from ask import (
    _expand_challenge_artifacts,
    _heuristic_challenge_from_instruction,
    _heuristic_mapping_is_actionable,
    _looks_like_new_challenge_instruction,
    _merge_heuristic_context,
    _normalize_challenge,
    _normalize_path,
    _normalize_url,
    _should_disable_llm_for_direct_cli,
    _unwrap_ask_command,
)


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
    assert challenge["metadata"]["loaded_from_challenge_json"] is True


def test_heuristic_mapping_keeps_non_json_artifacts_as_files(tmp_path, monkeypatch):
    artifact = tmp_path / "cipher.txt"
    artifact.write_text("Q1RGe2FydGlmYWN0X2ZpbGV9")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Decode this base64 file cipher.txt",
        available_tools=[],
    )

    assert challenge["id"].startswith("heuristic_")
    assert challenge["category"] == "crypto"
    assert challenge["files"] == [str(artifact)]


def test_actionable_heuristic_mapping_skips_llm_gate_for_pwn_files(tmp_path, monkeypatch):
    binary = tmp_path / "execute"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    source = tmp_path / "execute.c"
    source.write_text("int main(){return 0;}")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        f"Pwn challenge. Can you feed the hungry code? files in {tmp_path} ip and port are 154.57.164.80:30338",
        available_tools=[],
    )

    assert challenge["category"] == "pwn"
    assert challenge["id"].startswith("pwn_154_57_164_80_")
    assert _heuristic_mapping_is_actionable(challenge) is True


def test_direct_pwn_cli_disables_llm_before_coordinator_init(tmp_path, monkeypatch):
    binary = tmp_path / "restaurant"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("CTF_AGENTS_ENABLE_LLM_FOR_DIRECT_PWN", raising=False)

    assert _should_disable_llm_for_direct_cli(
        f"Pwn challenge files in {tmp_path} ip and port are 154.57.164.66:31594",
        available_tools=[],
        plan_mode=False,
    ) is True


def test_direct_pwn_cli_can_opt_into_llm(tmp_path, monkeypatch):
    binary = tmp_path / "restaurant"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CTF_AGENTS_ENABLE_LLM_FOR_DIRECT_PWN", "1")

    assert _should_disable_llm_for_direct_cli(
        f"Pwn challenge files in {tmp_path} ip and port are 154.57.164.66:31594",
        available_tools=[],
        plan_mode=False,
    ) is False


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


def test_explicit_crypto_challenge_with_authorisations_routes_to_crypto(tmp_path, monkeypatch):
    challenge_file = tmp_path / "challenge.txt"
    challenge_file.write_text("n = 123\ne = 65537\np_high = 456\nc = 789\n")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Crypto challenge. The treasury server encrypts confidential authorisations "
        "with RSA-2048. File is in challenge.txt",
        available_tools=[],
    )

    assert challenge["category"] == "crypto"
    assert challenge["files"] == [str(challenge_file)]


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


def test_normalize_path_recovers_common_downloads_typo(tmp_path, monkeypatch):
    home = tmp_path / "home"
    download_file = home / "Downloads" / "buddy"
    download_file.parent.mkdir(parents=True)
    download_file.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setenv("HOME", str(home))

    assert _normalize_path("~/Downlaods/buddy") == str(download_file)


def test_normalize_url_adds_scheme_to_bare_ip_port():
    assert _normalize_url("154.57.164.65:30433") == "http://154.57.164.65:30433"


def test_heuristic_mapping_normalizes_bare_ip_port_to_http_url():
    challenge = _heuristic_challenge_from_instruction(
        "Help desk JWT challenge at 154.57.164.65:30433",
        available_tools=[],
    )

    assert challenge["category"] == "web"
    assert challenge["url"] == "http://154.57.164.65:30433"


def test_web_prompt_with_downloads_typo_does_not_expand_downloads(tmp_path, monkeypatch):
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    stale = downloads / "input.csv"
    stale.write_text("in0,in1,in2,in3\n1,1,0,0\n")
    monkeypatch.setenv("HOME", str(home))

    challenge = _heuristic_challenge_from_instruction(
        "Web challenge https://ecyewxoj.web.ctf.uscybergames.com file is in ~/Downlaods/",
        available_tools=[],
    )

    assert challenge["category"] == "web"
    assert challenge["id"].startswith("web_ecyewxoj_web_ctf_uscybergames_com_")
    assert challenge["url"] == "https://ecyewxoj.web.ctf.uscybergames.com"
    assert challenge["files"] == []


def test_downloads_root_is_not_expanded_as_challenge_directory(tmp_path, monkeypatch):
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    stale = downloads / "01_inverter_exterior_positions_ABCD.png"
    stale.write_bytes(b"old hardware image")
    monkeypatch.setenv("HOME", str(home))

    assert _expand_challenge_artifacts([str(downloads)]) == []


def test_small_pwn_directory_includes_versioned_libc_and_loader(tmp_path):
    challenge_dir = tmp_path / "bird"
    glibc_dir = challenge_dir / "glibc"
    glibc_dir.mkdir(parents=True)
    binary = challenge_dir / "r0bob1rd"
    binary.write_bytes(b"\x7fELF" + b"\0" * 60)
    libc = glibc_dir / "libc.so.6"
    libc.write_bytes(b"\x7fELF" + b"\0" * 60)
    loader = glibc_dir / "ld.so.2"
    loader.write_bytes(b"\x7fELF" + b"\0" * 60)

    expanded = _expand_challenge_artifacts([str(challenge_dir)])

    assert str(binary.resolve()) in expanded
    assert str(libc.resolve()) in expanded
    assert str(loader.resolve()) in expanded


def test_merge_heuristic_context_drops_llm_invented_local_files(tmp_path):
    stale = tmp_path / "input.csv"
    stale.write_text("in0,in1,in2,in3\n1,1,0,0\n")
    llm_challenge = {
        "id": "llm_task",
        "category": "hardware",
        "description": "Web status page.",
        "files": [str(stale)],
    }
    heuristic = {
        "id": "web_example_test_12345678",
        "category": "web",
        "description": "Web challenge https://example.test",
        "url": "https://example.test",
        "files": [],
    }

    merged = _merge_heuristic_context(llm_challenge, heuristic)

    assert merged["category"] == "web"
    assert merged["id"] == "web_example_test_12345678"
    assert merged["files"] == []
    assert merged["url"] == "https://example.test"


def test_interactive_new_challenge_detector_for_url_and_file_prompts():
    assert _looks_like_new_challenge_instruction("Web challenge https://example.test")
    assert _looks_like_new_challenge_instruction("files are in ~/Downloads/new_challenge")
    assert not _looks_like_new_challenge_instruction("try the admin feed next")


def test_heuristic_mapping_routes_secure_coding_ip_port_to_secure_coding():
    challenge = _heuristic_challenge_from_instruction(
        "Secure coding challenge, ip and port are 154.57.164.65:31327",
        available_tools=[],
    )

    assert challenge["category"] == "secure_coding"
    assert challenge["url"] == "http://154.57.164.65:31327"


def test_heuristic_mapping_routes_partial_pin_runner_before_brute_force_log():
    challenge = _heuristic_challenge_from_instruction(
        "A critical system is locked behind a numeric PIN. Only partial digits are visible. "
        "Use an educated brute force attack. Port and IP: 154.57.164.81:31473",
        available_tools=[],
    )

    assert challenge["category"] == "secure_coding"
    assert challenge["url"] == "http://154.57.164.81:31473"


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


def test_heuristic_mapping_expands_challenge_dir_but_skips_wordlists(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "challenge"
    wordlists_dir = tmp_path / "WordLists"
    challenge_dir.mkdir()
    wordlists_dir.mkdir()
    chall_py = challenge_dir / "chall.py"
    msg_enc = challenge_dir / "msg.enc"
    chall_py.write_text("print('cipher')")
    msg_enc.write_text("00")
    (wordlists_dir / "rockyou.txt").write_text("password\n" * 10)

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Decrypt it. Files are in challenge wordlists are in WordLists",
        available_tools=[],
    )

    assert challenge["category"] == "crypto"
    assert challenge["files"] == sorted([str(chall_py), str(msg_enc)])


def test_normalize_challenge_expands_directory_returned_by_llm(tmp_path):
    challenge_dir = tmp_path / "baby_time_capsule"
    challenge_dir.mkdir()
    server = challenge_dir / "server.py"
    server.write_text("e = 5\n")

    challenge = _normalize_challenge({
        "id": "llm_task",
        "category": "crypto",
        "description": "Very easy crypto challenge.",
        "files": [str(challenge_dir)],
    })

    assert challenge["files"] == [str(server)]


def test_heuristic_mapping_routes_explicit_crypto_source_folder_to_crypto(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "baby_time_capsule"
    challenge_dir.mkdir()
    server = challenge_dir / "server.py"
    server.write_text("e = 5\n")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Very easy crypto challenge. Files are located in baby_time_capsule",
        available_tools=[],
    )

    assert challenge["category"] == "crypto"
    assert challenge["files"] == [str(server)]


def test_heuristic_mapping_keeps_crypto_source_with_ip_port_as_crypto(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "baby_time_capsule"
    challenge_dir.mkdir()
    server = challenge_dir / "server.py"
    server.write_text("e = 5\n")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Very easy crypto challenge at 127.0.0.1:1337. Files are in baby_time_capsule",
        available_tools=[],
    )

    assert challenge["category"] == "crypto"
    assert challenge["url"] == "http://127.0.0.1:1337"
    assert challenge["files"] == [str(server)]


def test_merge_heuristic_context_preserves_llm_omitted_ip_and_files():
    from ask import _merge_heuristic_context

    challenge = {
        "id": "llm_task",
        "category": "crypto",
        "description": "Very easy crypto challenge.",
        "files": [],
    }
    heuristic = {
        "description": "Very easy crypto challenge. Files are in baby_time_capsule. Ip and Port are 127.0.0.1:1337",
        "files": ["/tmp/baby_time_capsule/server.py"],
        "url": "http://127.0.0.1:1337",
    }

    merged = _merge_heuristic_context(challenge, heuristic)

    assert merged["url"] == "http://127.0.0.1:1337"
    assert merged["files"] == ["/tmp/baby_time_capsule/server.py"]
    assert "Original instruction" in merged["description"]


def test_merge_heuristic_context_preserves_web_category_for_ip_port():
    from ask import _merge_heuristic_context

    challenge = {
        "id": "llm_task",
        "category": "unknown",
        "description": "Solve this coding challenge.",
    }
    heuristic = {
        "category": "web",
        "description": "Solve this coding challenge at 154.57.164.77:30498.",
        "url": "http://154.57.164.77:30498",
    }

    merged = _merge_heuristic_context(challenge, heuristic)

    assert merged["category"] == "web"
    assert merged["url"] == "http://154.57.164.77:30498"


def test_heuristic_mapping_routes_chip_csv_folder_to_hardware(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "hw_lowlogic"
    challenge_dir.mkdir()
    chip = challenge_dir / "chip.jpg"
    table = challenge_dir / "input.csv"
    chip.write_bytes(b"image")
    table.write_text("in0,in1,in2,in3\n1,1,0,0\n")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "I have this simple chip. Files are in hw_lowlogic",
        available_tools=[],
    )

    assert challenge["category"] == "hardware"
    assert challenge["files"] == sorted([str(chip), str(table)])


def test_heuristic_mapping_routes_godot_bundle_to_reverse(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "rev_gameloader"
    challenge_dir.mkdir()
    exe = challenge_dir / "Platformer 2D.exe"
    pck = challenge_dir / "Platformer 2D.pck"
    exe.write_bytes(b"MZ placeholder")
    pck.write_bytes(b"GDPC placeholder")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Investigate this compromised game. Files are in rev_gameloader",
        available_tools=[],
    )

    assert challenge["category"] == "reverse"
    assert challenge["files"] == sorted([str(exe), str(pck)])


def test_merge_heuristic_context_preserves_hardware_category():
    from ask import _merge_heuristic_context

    challenge = {
        "id": "llm_task",
        "category": "reverse",
        "description": "Analyze this file.",
    }
    heuristic = {
        "category": "hardware",
        "description": "Analyze this simple chip.",
        "files": ["/tmp/chip.jpg", "/tmp/input.csv"],
    }

    merged = _merge_heuristic_context(challenge, heuristic)

    assert merged["category"] == "hardware"


def test_heuristic_mapping_expands_solidity_folder_to_blockchain(tmp_path, monkeypatch):
    challenge_dir = tmp_path / "Survival"
    challenge_dir.mkdir()
    creature = challenge_dir / "Creature.sol"
    setup = challenge_dir / "Setup.sol"
    creature.write_text("contract Creature { function strongAttack(uint256 damage) public {} }")
    setup.write_text("contract Setup { function isSolved() public view returns (bool) {} }")

    monkeypatch.chdir(tmp_path)
    challenge = _heuristic_challenge_from_instruction(
        "Blockchain challenge. Files are in Survival and the target is 127.0.0.1:31337.",
        available_tools=[],
    )

    assert challenge["category"] == "blockchain"
    assert challenge["url"] == "http://127.0.0.1:31337"
    assert challenge["files"] == sorted([str(creature), str(setup)])


def test_merge_heuristic_context_preserves_blockchain_category():
    from ask import _merge_heuristic_context

    challenge = {
        "id": "llm_task",
        "category": "web",
        "description": "Exploit the endpoint.",
    }
    heuristic = {
        "category": "blockchain",
        "description": "Exploit this Solidity smart contract.",
        "files": ["/tmp/Creature.sol", "/tmp/Setup.sol"],
        "url": "http://127.0.0.1:31337",
    }

    merged = _merge_heuristic_context(challenge, heuristic)

    assert merged["category"] == "blockchain"
    assert merged["url"] == "http://127.0.0.1:31337"


def test_heuristic_mapping_routes_explicit_reversing_with_missing_file_to_reverse():
    # Regression: an explicit "Reversing challenge" must route to reverse even
    # when the referenced binary path is mistyped / does not exist on disk.
    # Previously the reverse keyword was gated on a valid ELF file being
    # present, so a typo'd path silently fell through to "misc".
    challenge = _heuristic_challenge_from_instruction(
        "Reversing challenge, file is in ~/Downloads/becaon_override",
        available_tools=["python3"],
    )
    assert challenge["category"] == "reverse"
    assert _heuristic_mapping_is_actionable(challenge) is True


def test_heuristic_mapping_does_not_find_sha_inside_shaping(tmp_path):
    source = tmp_path / "web_reactoops"
    source.mkdir()
    (source / "Dockerfile").write_text("FROM node:20-alpine")

    challenge = _heuristic_challenge_from_instruction(
        f"User input may be shaping the reactive interface. Files are in {source}. "
        "Target 192.0.2.10:31337",
        available_tools=[],
    )

    assert challenge["category"] == "web"
    assert challenge["files"] == [str(source)]


def test_heuristic_mapping_routes_arms_race_wordplay_to_reverse_before_web():
    challenge = _heuristic_challenge_from_instruction(
        "A server sends mysterious data in a multi-level challenge. "
        "Everyone is in an ARMs race. Target 192.0.2.10:31337",
        available_tools=[],
    )

    assert challenge["category"] == "reverse"
    assert challenge["url"] == "http://192.0.2.10:31337"


def test_reversing_prompt_with_downloads_typo_recovers_file_and_category(tmp_path, monkeypatch):
    home = tmp_path / "home"
    buddy = home / "Downloads" / "buddy"
    buddy.parent.mkdir(parents=True)
    buddy.write_bytes(b"\x7fELF" + b"\x00" * 60)
    monkeypatch.setenv("HOME", str(home))

    challenge = _heuristic_challenge_from_instruction(
        "Reversing challenge. File is in ~/Downlaods/buddy",
        available_tools=[],
    )

    assert challenge["category"] == "reverse"
    assert challenge["files"] == [str(buddy)]


def test_merge_heuristic_context_preserves_explicit_reversing_over_llm_misc():
    llm_challenge = {
        "id": "llm_task",
        "category": "misc",
        "description": "A miscellaneous file analysis task.",
        "files": [],
    }
    heuristic = {
        "id": "reverse_missing_file_12345678",
        "category": "reverse",
        "description": "Reversing challenge. File is in ~/Downlaods/buddy",
        "files": [],
    }

    merged = _merge_heuristic_context(llm_challenge, heuristic)

    assert merged["category"] == "reverse"
    assert merged["id"] == "reverse_missing_file_12345678"


def test_heuristic_mapping_routes_decompile_crackme_to_reverse():
    for text in (
        "Please decompile ~/Downloads/nope",
        "crackme at /tmp/missing_thing",
        "reverse engineer this binary ~/Downloads/foo",
    ):
        challenge = _heuristic_challenge_from_instruction(text, available_tools=[])
        assert challenge["category"] == "reverse", text


def test_heuristic_mapping_reverse_shell_does_not_route_to_reverse():
    # Guardrail: "reverse shell" / "reverse proxy" must NOT be treated as a
    # reverse-engineering challenge just because the word "reverse" appears.
    challenge = _heuristic_challenge_from_instruction(
        "Get a reverse shell on the box at http://target.example",
        available_tools=[],
    )
    assert challenge["category"] == "web"
