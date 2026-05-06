import pytest
import os
from ask import _heuristic_challenge_from_instruction

@pytest.mark.parametrize("instruction, expected_category", [
    ("Find the password for tests/e2e/fixtures/reverse_me.py", "reverse"),
    ("Decode this base64 challenge from challenges/templates/example_crypto_base64.json", "crypto"),
    ("Decrypt the following message: 'pm ol ohk hufaopun jvumpkluaphs av zhf...'", "crypto"),
    ("Analyze this file for hidden flags. File is located in challenges/active/sim_web_001/artifact.bin", "forensics"),
    ("Analyze tests/e2e/fixtures/auth_events.txt and identify which IP executed a brute force SSH attack", "log"),
    ("Calculate the sum of all prime numbers between 1 and 100 and print it in the format CTF{result}", "misc"),
    ("Check http://challenge.local:8080 for common CTF web leaks", "web")
])
def test_smoke_heuristic_mapping(instruction, expected_category):
    """
    Verify that the heuristic mapping in ask.py correctly categorizes
    the example prompts from the README.
    """
    # Simulate available tools
    available_tools = ["sqlmap", "john", "hashcat", "binwalk"]
    
    challenge = _heuristic_challenge_from_instruction(instruction, available_tools)
    
    assert challenge["category"] == expected_category, f"Failed for instruction: {instruction}"

def test_smoke_target_file_extraction():
    """
    Verify that heuristic mapping correctly extracts target files from instructions.
    """
    instruction = "Find the password for tests/e2e/fixtures/reverse_me.py"
    # Ensure the file exists for the test to pass the os.path.exists check in ask.py
    # (In real life it does, so we mock or ensure presence)
    
    challenge = _heuristic_challenge_from_instruction(instruction, [])
    
    # We expect the file to be detected if it exists on disk
    # Since we are running in the repo, it should be there.
    assert any("reverse_me.py" in f for f in challenge["files"])
