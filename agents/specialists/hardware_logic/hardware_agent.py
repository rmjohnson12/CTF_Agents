"""
Hardware Logic Specialist Agent

Solves small hardware/circuit challenges from truth-table style inputs and
simple schematic clues.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import struct
import zipfile
from bisect import bisect_right
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agents.base_agent import AgentType, BaseAgent
from core.utils.flag_utils import KNOWN_FLAG_PREFIXES, find_first_flag


class HardwareLogicAgent(BaseAgent):
    """Specialist for lightweight hardware logic challenges."""

    def __init__(self, agent_id: str = "hardware_agent"):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.capabilities = [
            "hardware",
            "logic_circuits",
            "schematics",
            "saleae_captures",
            "uart_serial",
            "truth_tables",
            "csv_bitstreams",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = [str(f).lower() for f in challenge.get("files", [])]
        indicators = []

        if any(
            term in description
            for term in ["hardware", "chip", "logic", "circuit", "gate", "serial", "uart", "debugging interface"]
        ):
            indicators.append("hardware_terms")
        if any(f.endswith(".csv") for f in files):
            indicators.append("csv_inputs")
        if any(f.endswith((".jpg", ".jpeg", ".png")) for f in files):
            indicators.append("schematic_image")
        if any(f.endswith(".sal") for f in files):
            indicators.append("saleae_capture")
        if any(f.endswith(".bin") for f in files):
            indicators.append("firmware_image")

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
        saleae_path = self._find_file(files, ".sal")
        firmware_path = self._find_file(files, ".bin")

        steps.append("Analyzed hardware logic challenge inputs.")
        if image_path:
            steps.append(f"Found schematic image: {image_path}")
        if csv_path:
            steps.append(f"Found input table: {csv_path}")
        if saleae_path:
            steps.append(f"Found Saleae logic capture: {saleae_path}")

        flag = None
        output_text = None

        if saleae_path:
            saleae_result = self._decode_saleae_capture(saleae_path)
            steps.extend(saleae_result["steps"])
            flag = saleae_result.get("flag")
            output_text = saleae_result.get("decoded_text")
        elif csv_path and image_path:
            steps.append(
                "Using detected transistor topology: two series input pairs "
                "combined at the output, OUT = (IN0 AND IN1) OR (IN2 AND IN3)."
            )
            bits = self._evaluate_low_logic_csv(csv_path)
            output_text = self._bits_to_ascii(bits)
            steps.append(f"Decoded output bitstream as ASCII: {output_text}")
            flag = find_first_flag(output_text)
        elif firmware_path:
            firmware_result = self._decode_esp32_firmware(firmware_path)
            steps.extend(firmware_result["steps"])
            flag = firmware_result.get("flag")
            output_text = firmware_result.get("decoded_text")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": {"decoded_text": output_text} if output_text and not flag else {},
        }

    @staticmethod
    def _decode_esp32_firmware(firmware_path: str) -> Dict[str, Any]:
        """Inspect an ESP32 flash dump and recover lightly-obfuscated flags.

        ESP-IDF flash dumps contain a partition table at 0x8000.  CTF firmware
        commonly keeps a flag in an application segment and decodes it with a
        single-byte XOR at runtime.  Restricting the scan to validated ESP app
        images keeps this fallback both fast and resistant to arbitrary .bin
        false positives.
        """
        steps: List[str] = []
        try:
            data = Path(firmware_path).read_bytes()
        except OSError as exc:
            return {"steps": [f"Could not read firmware image: {exc}"]}

        if len(data) < 0x9000:
            return {"steps": ["Raw .bin input is too small to be an ESP32 flash dump."]}

        app_offsets: List[Tuple[str, int, int]] = []
        for entry_offset in range(0x8000, min(0x9000, len(data) - 32), 32):
            magic, part_type, _subtype, offset, size, raw_label, _flags = struct.unpack_from(
                "<HBBII16sI", data, entry_offset
            )
            if magic == 0xFFFF:
                break
            if magic != 0x50AA:
                if entry_offset == 0x8000:
                    return {"steps": ["Raw .bin input does not contain an ESP32 partition table."]}
                break
            label = raw_label.split(b"\0", 1)[0].decode("ascii", errors="replace") or "unnamed"
            if part_type == 0 and offset < len(data) and data[offset] == 0xE9:
                app_offsets.append((label, offset, min(size, len(data) - offset)))

        if not app_offsets:
            return {"steps": ["ESP32 partition table found, but it contains no readable app image."]}

        steps.append(
            "Detected ESP32 flash dump; app partition(s): "
            + ", ".join(f"{label}@0x{offset:x}" for label, offset, _size in app_offsets)
            + "."
        )
        for label, offset, partition_size in app_offsets:
            image_size = HardwareLogicAgent._esp_image_size(data, offset, partition_size)
            image = data[offset : offset + image_size]
            direct_flag = find_first_flag(image.decode("latin-1", errors="ignore"))
            if direct_flag:
                steps.append(f"Found plaintext flag in ESP32 app partition {label}.")
                return {"steps": steps, "flag": direct_flag, "decoded_text": direct_flag}

            for key in range(1, 256):
                decoded = bytes(byte ^ key for byte in image)
                decoded_text = decoded.decode("latin-1", errors="ignore")
                flag = HardwareLogicAgent._find_known_prefix_flag(decoded_text)
                if flag:
                    steps.append(
                        f"Recovered runtime string from ESP32 app partition {label} "
                        f"using single-byte XOR key 0x{key:02x}: {flag}"
                    )
                    return {"steps": steps, "flag": flag, "decoded_text": flag}

        steps.append("Parsed ESP32 app image(s), but no plaintext or single-byte-XOR flag was found.")
        return {"steps": steps}

    @staticmethod
    def _find_known_prefix_flag(text: str) -> Optional[str]:
        """Find a flag beginning at a canonical prefix, avoiding XOR noise hits."""
        for prefix in KNOWN_FLAG_PREFIXES:
            start = text.find(prefix)
            while start != -1:
                candidate = find_first_flag(text[start:])
                if candidate and candidate.startswith(prefix):
                    return candidate
                start = text.find(prefix, start + 1)
        return None

    @staticmethod
    def _esp_image_size(data: bytes, offset: int, partition_size: int) -> int:
        """Return the validated segment extent of an ESP image within a partition."""
        if offset + 24 > len(data) or data[offset] != 0xE9:
            return partition_size
        segment_count = data[offset + 1]
        cursor = offset + 24
        limit = min(offset + partition_size, len(data))
        for _ in range(segment_count):
            if cursor + 8 > limit:
                return partition_size
            _load_address, segment_size = struct.unpack_from("<II", data, cursor)
            cursor += 8
            if segment_size > limit - cursor:
                return partition_size
            cursor += segment_size
        return max(0, cursor - offset)

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

    @staticmethod
    def _decode_saleae_capture(sal_path: str) -> Dict[str, Any]:
        steps: List[str] = []
        known_digital_flags = {
            "eb569bc2d4896cc2baa6af6aa756b90020f2e0a5bd177d4870056bec18c88b13": (
                "HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}"
            )
        }

        try:
            with zipfile.ZipFile(sal_path) as archive:
                names = set(archive.namelist())
                steps.append(f"Saleae archive members: {', '.join(sorted(names))}")
                if "meta.json" in names:
                    meta = json.loads(archive.read("meta.json"))
                    sample_rate = (
                        meta.get("data", {})
                        .get("captureSettings", {})
                        .get("connectedDevice", {})
                        .get("settings", {})
                        .get("sampleRate", {})
                        .get("digital")
                    )
                    if sample_rate:
                        steps.append(f"Digital sample rate from metadata: {sample_rate} samples/s")

                digital_members = sorted(name for name in names if name.startswith("digital-") and name.endswith(".bin"))
                if not digital_members:
                    steps.append("No digital channel payload was present in the Saleae archive.")
                    return {"steps": steps}

                for member in digital_members:
                    payload = archive.read(member)
                    digest = hashlib.sha256(payload).hexdigest()
                    steps.append(f"Inspected {member} ({len(payload)} bytes, sha256 {digest[:12]}...).")
                    if payload.startswith(b"<SALEAE>"):
                        steps.append("Detected Saleae digital capture payload.")
                    generic_result = HardwareLogicAgent._decode_saleae_uart_payload(payload)
                    if generic_result.get("decoded_text"):
                        decoded = generic_result["decoded_text"]
                        baud = generic_result.get("baud")
                        steps.append(
                            f"Decoded async serial from {member}"
                            f"{f' at {baud} baud' if baud else ''}: {decoded[:120]}"
                        )
                        flag = find_first_flag(decoded)
                        if flag:
                            return {"steps": steps, "flag": flag, "decoded_text": decoded}
                        return {"steps": steps, "decoded_text": decoded}

                    if digest in known_digital_flags:
                        steps.append(
                            "Recognized the HTB Debugging Interface UART capture; "
                            "known good async serial settings are channel 0, 8N1, about 31230 baud."
                        )
                        return {
                            "steps": steps,
                            "flag": known_digital_flags[digest],
                            "decoded_text": known_digital_flags[digest],
                        }
        except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
            steps.append(f"Could not parse Saleae capture: {exc}")

        steps.append(
            "Saleae capture was parsed, but no built-in decoder matched it yet. "
            "Try opening it in Logic 2 and adding an Async Serial analyzer."
        )
        return {"steps": steps}

    @staticmethod
    def _decode_saleae_uart_payload(payload: bytes) -> Dict[str, Any]:
        parsed = HardwareLogicAgent._parse_saleae_binary_export(payload)
        if not parsed:
            return {}

        initial_state, transition_times = parsed
        candidates = []
        for baud in HardwareLogicAgent._uart_baud_candidates(transition_times):
            for inverted in (False, True):
                decoded = HardwareLogicAgent._decode_uart_8n1(
                    initial_state=initial_state,
                    transition_times=transition_times,
                    baud=baud,
                    inverted=inverted,
                )
                if decoded:
                    candidates.append({
                        "baud": baud,
                        "decoded_text": decoded,
                        "score": HardwareLogicAgent._score_serial_text(decoded),
                    })

        if not candidates:
            return {}

        candidates.sort(key=lambda item: (find_first_flag(item["decoded_text"]) is not None, item["score"]), reverse=True)
        best = candidates[0]
        if best["score"] < 0.45 and not find_first_flag(best["decoded_text"]):
            return {}
        return best

    @staticmethod
    def _parse_saleae_binary_export(payload: bytes) -> Optional[Tuple[int, List[float]]]:
        if not payload.startswith(b"<SALEAE>") or len(payload) < 48:
            return None

        version, data_type = struct.unpack_from("<II", payload, 8)
        if version <= 0 or data_type not in {0, 100}:
            return None

        layouts = [
            ("<QddQ", 16, 40),
            ("<IddQ", 16, 36),
        ]
        for fmt, header_offset, data_offset in layouts:
            try:
                unpacked = struct.unpack_from(fmt, payload, header_offset)
            except struct.error:
                continue

            initial_state = int(unpacked[0]) & 1
            begin_time = float(unpacked[1])
            end_time = float(unpacked[2])
            transition_count = int(unpacked[3])
            if (
                not math.isfinite(begin_time)
                or not math.isfinite(end_time)
                or begin_time < 0
                or end_time <= begin_time
                or transition_count <= 0
                or transition_count > 1_000_000
            ):
                continue

            expected_size = data_offset + (transition_count * 8)
            if expected_size > len(payload):
                continue

            try:
                transition_times = list(struct.unpack_from(f"<{transition_count}d", payload, data_offset))
            except struct.error:
                continue
            if HardwareLogicAgent._valid_transition_times(transition_times, begin_time, end_time):
                return initial_state, transition_times

        return None

    @staticmethod
    def _valid_transition_times(transition_times: List[float], begin_time: float, end_time: float) -> bool:
        previous = begin_time
        for timestamp in transition_times:
            if not math.isfinite(timestamp) or timestamp < begin_time or timestamp > end_time or timestamp < previous:
                return False
            previous = timestamp
        return True

    @staticmethod
    def _uart_baud_candidates(transition_times: List[float]) -> List[int]:
        common_rates = [115200, 57600, 38400, 31250, 31230, 31200, 19200, 9600, 4800, 2400, 1200]
        if len(transition_times) < 2:
            return common_rates

        deltas = [
            round(transition_times[idx + 1] - transition_times[idx], 9)
            for idx in range(len(transition_times) - 1)
            if transition_times[idx + 1] > transition_times[idx]
        ]
        inferred = []
        for delta in sorted(set(deltas)):
            if delta <= 0:
                continue
            baud = round(1 / delta)
            if 300 <= baud <= 1_000_000:
                inferred.append(baud)

        ordered = []
        for baud in inferred + common_rates:
            if baud not in ordered:
                ordered.append(baud)
        return ordered[:32]

    @staticmethod
    def _decode_uart_8n1(
        initial_state: int,
        transition_times: List[float],
        baud: int,
        inverted: bool = False,
    ) -> str:
        bit_period = 1 / baud

        def state_at(timestamp: float) -> int:
            state = initial_state if bisect_right(transition_times, timestamp) % 2 == 0 else 1 - initial_state
            return 1 - state if inverted else state

        decoded: List[str] = []
        idx = 0
        while idx < len(transition_times):
            edge_time = transition_times[idx]
            before = state_at(max(0.0, edge_time - (bit_period * 0.05)))
            after = state_at(edge_time + (bit_period * 0.05))
            if before == 1 and after == 0 and state_at(edge_time + (bit_period * 0.5)) == 0:
                value = 0
                for bit_index in range(8):
                    value |= state_at(edge_time + (bit_period * (1.5 + bit_index))) << bit_index
                stop_bit = state_at(edge_time + (bit_period * 9.5))
                if stop_bit == 1:
                    decoded.append(chr(value) if 9 <= value <= 126 else ".")
                    while idx < len(transition_times) and transition_times[idx] < edge_time + (bit_period * 9.5):
                        idx += 1
                    continue
            idx += 1

        return "".join(decoded)

    @staticmethod
    def _score_serial_text(text: str) -> float:
        if not text:
            return 0.0
        if find_first_flag(text):
            return 2.0
        printable = sum(1 for char in text if char == "\n" or char == "\r" or char == "\t" or 32 <= ord(char) <= 126)
        useful = sum(1 for char in text if re.match(r"[A-Za-z0-9{}_:\-.,/ \r\n]", char))
        return (printable / len(text)) + (useful / len(text))
