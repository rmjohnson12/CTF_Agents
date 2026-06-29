"""Challenge-provider adapters used by the campaign runner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Protocol

from challenges.challenge_parser import ChallengeParser


class ChallengeProvider(Protocol):
    name: str

    def list_challenges(self) -> Iterable[Dict[str, Any]]: ...


class LocalChallengeProvider:
    """Load challenges from a directory, a single JSON file, or a benchmark manifest."""

    name = "local"

    def __init__(self, source: str):
        self.source = Path(source)
        self.parser = ChallengeParser()

    def list_challenges(self) -> List[Dict[str, Any]]:
        if self.source.is_dir():
            return [self.parser.parse_file(path) for path in sorted(self.source.glob("*.json"))]

        raw = json.loads(self.source.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("benchmarks"), list):
            return [
                self.parser.parse_dict(item["challenge"])
                for item in raw["benchmarks"]
                if item.get("mode", "solve") == "solve"
                and not item.get("generated_files")
                and isinstance(item.get("challenge"), dict)
            ]
        return [self.parser.parse_dict(raw)]
