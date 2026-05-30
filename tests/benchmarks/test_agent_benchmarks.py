"""Data-driven regression benchmarks for challenge routing and solving."""
from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any, Dict

import pytest

from challenges.challenge_parser import ChallengeParser

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "challenges" / "benchmarks" / "manifest.json"


def _load_cases() -> list[Dict[str, Any]]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["benchmarks"]


def _build_coordinator():
    from agents.coordinator.coordinator_agent import CoordinatorAgent
    from agents.specialists.cryptography.crypto_agent import CryptographyAgent
    from agents.specialists.forensics.forensics_agent import ForensicsAgent
    from agents.specialists.log_analysis.log_agent import LogAnalysisAgent
    from agents.specialists.misc.coding_agent import CodingAgent
    from agents.specialists.pwn.pwn_agent import PwnAgent
    from agents.specialists.reverse_engineering.reverse_agent import ReverseEngineeringAgent
    from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
    from tools.crypto.hashcat import HashcatTool
    from tools.crypto.john import JohnTool
    from tools.web.dirsearch import DirsearchTool

    class NoopDirsearchTool(DirsearchTool):
        def run(self, url):  # pragma: no cover - benchmark cases avoid live web
            raise RuntimeError("dirsearch disabled in benchmarks")

    coordinator = CoordinatorAgent(max_iterations=3)
    coordinator.register_agent(CryptographyAgent(john_tool=JohnTool(), hashcat_tool=HashcatTool()))
    coordinator.register_agent(ForensicsAgent(john_tool=JohnTool(), hashcat_tool=HashcatTool()))
    coordinator.register_agent(LogAnalysisAgent())
    coordinator.register_agent(ReverseEngineeringAgent())
    coordinator.register_agent(PwnAgent())
    coordinator.register_agent(WebExploitationAgent(dirsearch_tool=NoopDirsearchTool()))
    coordinator.register_agent(CodingAgent())
    return coordinator


def _materialize_generated_file(spec: Dict[str, Any], tmp_path: Path) -> Path:
    out = tmp_path / spec["name"]
    kind = spec["kind"]

    if kind == "elf_stub":
        out.write_bytes(b"\x7fELF" + b"\x00" * 96)
        return out

    if kind == "elf_numeric_flag":
        flag = spec["flag"]
        multiplier = int(spec.get("multiplier", 16))
        encoded = " ".join(str(ord(ch) * multiplier) for ch in flag)
        out.write_bytes(b"\x7fELF" + b"\x00" * 32 + encoded.encode("ascii") + b"\n")
        return out

    raise ValueError(f"Unknown generated fixture kind: {kind}")


def _prepare_challenge(case: Dict[str, Any], tmp_path: Path) -> Dict[str, Any]:
    generated: Dict[str, Path] = {}
    for spec in case.get("generated_files", []):
        generated[spec["name"]] = _materialize_generated_file(spec, tmp_path)

    challenge = copy.deepcopy(case["challenge"])
    resolved_files = []
    for raw_file in challenge.get("files", []):
        if raw_file.startswith("{generated:") and raw_file.endswith("}"):
            name = raw_file[len("{generated:"):-1]
            resolved_files.append(str(generated[name]))
        else:
            path = Path(raw_file)
            resolved_files.append(str((ROOT / path).resolve() if not path.is_absolute() else path))
    challenge["files"] = resolved_files
    return ChallengeParser().parse_dict(challenge)


def _skip_missing_requirements(case: Dict[str, Any]) -> None:
    missing = [cmd for cmd in case.get("requires", []) if shutil.which(cmd) is None]
    if missing:
        pytest.skip(f"Missing benchmark requirement(s): {', '.join(missing)}")


@pytest.mark.parametrize("case", _load_cases(), ids=lambda c: c["id"])
def test_agent_benchmark(case: Dict[str, Any], tmp_path: Path):
    _skip_missing_requirements(case)
    challenge = _prepare_challenge(case, tmp_path)
    coordinator = _build_coordinator()
    expected = case["expect"]

    analysis = coordinator.analyze_challenge(challenge)
    assert analysis["category"] == expected["category"]
    assert analysis["strategy"]["target"] == expected["target"]

    if case["mode"] == "route":
        assert analysis["strategy"]["action"] == expected["action"]
        return

    result = coordinator.solve_challenge(challenge)

    assert result["status"] == expected["status"], "\n".join(result.get("steps", []))
    assert result.get("flag") == expected["flag"], "\n".join(result.get("steps", []))
