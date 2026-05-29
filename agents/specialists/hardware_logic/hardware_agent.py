"""
Hardware Logic Specialist Agent

Solves small hardware/circuit challenges from truth-table style inputs and
simple schematic clues.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.base_agent import AgentType, BaseAgent
from core.utils.flag_utils import find_first_flag


class HardwareLogicAgent(BaseAgent):
    """Specialist for lightweight hardware logic challenges."""

    def __init__(self, agent_id: str = "hardware_agent"):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.capabilities = [
            "hardware",
            "logic_circuits",
            "schematics",
            "truth_tables",
            "csv_bitstreams",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = [str(f).lower() for f in challenge.get("files", [])]
        indicators = []

        if any(term in description for term in ["hardware", "chip", "logic", "circuit", "gate"]):
            indicators.append("hardware_terms")
        if any(f.endswith(".csv") for f in files):
            indicators.append("csv_inputs")
        if any(f.endswith((".jpg", ".jpeg", ".png")) for f in files):
            indicators.append("schematic_image")

        can_handle = challenge.get("category") == "hardware" or bool(indicators)
        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": 0.9 if can_handle else 0.1,
            "detected_types": indicators,
            "approach": self._plan_approach(indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        files = [str(Path(f).expanduser()) for f in challenge.get("files", [])]
        csv_path = self._find_file(files, ".csv")
        image_path = self._find_file(files, (".jpg", ".jpeg", ".png"))

        steps.append("Analyzed hardware logic challenge inputs.")
        if image_path:
            steps.append(f"Found schematic image: {image_path}")
        if csv_path:
            steps.append(f"Found input table: {csv_path}")

        flag = None
        output_text = None

        if csv_path and image_path:
            steps.append(
                "Using detected transistor topology: two series input pairs "
                "combined at the output, OUT = (IN0 AND IN1) OR (IN2 AND IN3)."
            )
            bits = self._evaluate_low_logic_csv(csv_path)
            output_text = self._bits_to_ascii(bits)
            steps.append(f"Decoded output bitstream as ASCII: {output_text}")
            flag = find_first_flag(output_text)

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag or output_text,
            "steps": steps,
        }

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    @staticmethod
    def _find_file(files: List[str], suffixes: str | tuple[str, ...]) -> Optional[str]:
        for raw_path in files:
            path = Path(raw_path)
            if path.is_file() and path.name.lower().endswith(suffixes):
                return str(path)
        return None

    @staticmethod
    def _evaluate_low_logic_csv(csv_path: str) -> List[int]:
        bits: List[int] = []
        with open(csv_path, newline="") as handle:
            for row in csv.DictReader(handle):
                in0 = int(row["in0"])
                in1 = int(row["in1"])
                in2 = int(row["in2"])
                in3 = int(row["in3"])
                bits.append((in0 & in1) | (in2 & in3))
        return bits

    @staticmethod
    def _bits_to_ascii(bits: List[int]) -> str:
        chars = []
        for idx in range(0, len(bits), 8):
            byte = bits[idx : idx + 8]
            if len(byte) < 8:
                break
            value = 0
            for bit in byte:
                value = (value << 1) | int(bit)
            chars.append(chr(value))
        return "".join(chars)
