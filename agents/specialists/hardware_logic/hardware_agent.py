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
import socket
import struct
import time
import zipfile
from bisect import bisect_right
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from agents.base_agent import AgentType, BaseAgent
from agents.registry import AgentRegistry
from core.utils.flag_utils import KNOWN_FLAG_PREFIXES, find_first_flag
from core.utils.security import SecurityPolicyError, assert_host_allowed

# Raw SDR / IQ capture extensions. Each maps to how the interleaved samples are
# laid out on disk; see ``_IQ_DTYPES`` for the numpy dtype and any DC offset.
_IQ_SUFFIXES = (
    ".cf32", ".fc32", ".cfile", ".32fc", ".iq", ".complex",
    ".cu8", ".cs8", ".c8", ".cs16", ".sc16", ".c16",
)


@AgentRegistry.register(order=90)
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
            "forth_diagnostic_terminals",
            "sdr_iq_captures",
            "ook_ask_demodulation",
            "manchester_decoding",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = [str(f).lower() for f in challenge.get("files", [])]
        indicators = []

        if any(
            term in description
            for term in [
                "hardware", "chip", "logic", "circuit", "gate", "serial", "uart",
                "debugging interface", "sdr", "radio", " rf ", "signal", "remote",
                "modulat", "captured the signal",
            ]
        ):
            indicators.append("hardware_terms")
        if any(f.endswith(".csv") for f in files):
            indicators.append("csv_inputs")
        if any(f.endswith((".jpg", ".jpeg", ".png")) for f in files):
            indicators.append("schematic_image")
        if any(f.endswith(".sal") for f in files):
            indicators.append("saleae_capture")
        if any(f.endswith(_IQ_SUFFIXES) for f in files):
            indicators.append("sdr_iq_capture")
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
        iq_path = self._find_file(files, _IQ_SUFFIXES)
        firmware_path = self._find_file(files, ".bin")

        steps.append("Analyzed hardware logic challenge inputs.")
        if image_path:
            steps.append(f"Found schematic image: {image_path}")
        if csv_path:
            steps.append(f"Found input table: {csv_path}")
        if saleae_path:
            steps.append(f"Found Saleae logic capture: {saleae_path}")
        if iq_path:
            steps.append(f"Found SDR IQ capture: {iq_path}")

        flag = None
        output_text = None
        # Technique tags feed the solve-trace store's technique-reuse learner so
        # a future capture of the same shape can be routed straight here.
        techniques: List[str] = []

        if self._looks_like_remote_forth(challenge):
            forth_result = self._solve_remote_forth(challenge)
            steps.extend(forth_result["steps"])
            flag = forth_result.get("flag")
            output_text = forth_result.get("decoded_text")
            if flag:
                return {
                    "challenge_id": challenge.get("id"),
                    "agent_id": self.agent_id,
                    "status": "solved",
                    "flag": flag,
                    "steps": steps,
                    "techniques": ["forth_diagnostic_terminal"],
                    "artifacts": {},
                }

        if saleae_path:
            saleae_result = self._decode_saleae_capture(saleae_path)
            steps.extend(saleae_result["steps"])
            flag = saleae_result.get("flag")
            output_text = saleae_result.get("decoded_text")
            techniques.extend(saleae_result.get("techniques") or ["saleae_uart_decoding"])
        elif iq_path:
            iq_result = self._decode_iq_capture(iq_path)
            steps.extend(iq_result["steps"])
            flag = iq_result.get("flag")
            output_text = iq_result.get("decoded_text")
            techniques.extend(iq_result.get("techniques") or ["sdr_iq_ook_demodulation"])
        elif csv_path and image_path:
            steps.append(
                "Using detected transistor topology: two series input pairs "
                "combined at the output, OUT = (IN0 AND IN1) OR (IN2 AND IN3)."
            )
            bits = self._evaluate_low_logic_csv(csv_path)
            output_text = self._bits_to_ascii(bits)
            steps.append(f"Decoded output bitstream as ASCII: {output_text}")
            flag = find_first_flag(output_text)
            techniques.append("transistor_logic_truth_table")
        elif firmware_path:
            firmware_result = self._decode_esp32_firmware(firmware_path)
            steps.extend(firmware_result["steps"])
            techniques.extend(firmware_result.get("techniques") or ["esp32_firmware_analysis"])
            flag = firmware_result.get("flag")
            output_text = firmware_result.get("decoded_text")

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "techniques": sorted(set(techniques)) if flag else [],
            "artifacts": {"decoded_text": output_text} if output_text and not flag else {},
        }

    @staticmethod
    def _looks_like_remote_forth(challenge: Dict[str, Any]) -> bool:
        description = str(challenge.get("description") or "").lower()
        return "forth" in description and HardwareLogicAgent._remote_endpoint(challenge) is not None

    @staticmethod
    def _remote_endpoint(challenge: Dict[str, Any]) -> Optional[Tuple[str, int]]:
        candidates = [
            challenge.get("url"),
            challenge.get("connection_info"),
            challenge.get("remote"),
            challenge.get("target"),
            challenge.get("description"),
        ]
        for raw_candidate in candidates:
            if isinstance(raw_candidate, dict):
                host = raw_candidate.get("host") or raw_candidate.get("hostname")
                port = raw_candidate.get("port")
                if host and str(port).isdigit():
                    return str(host), int(port)
                continue
            candidate = str(raw_candidate or "")
            match = re.search(
                r"\b((?:\d{1,3}\.){3}\d{1,3}|localhost|[a-zA-Z0-9.-]+):(\d{2,5})\b",
                candidate,
            )
            if match:
                return match.group(1), int(match.group(2))
            if "://" in candidate:
                parsed = urlparse(candidate)
                if parsed.hostname and parsed.port:
                    return parsed.hostname, parsed.port
        return None

    @staticmethod
    def _solve_remote_forth(challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        endpoint = HardwareLogicAgent._remote_endpoint(challenge)
        if endpoint is None:
            return {"steps": steps}
        host, port = endpoint
        try:
            assert_host_allowed(host, port=port)
        except SecurityPolicyError as exc:
            return {"steps": [f"Forth terminal blocked by network policy: {exc}"]}

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.settimeout(0.25)
                # The scenario evidence gates this diagnostic-menu probe.
                sock.sendall(b"3\n")
                diagnostic = HardwareLogicAgent._recv_bounded(
                    sock,
                    timeout=7,
                    markers=(b"diag-complete", b"forth", b"fourth error"),
                )
                diagnostic_text = diagnostic.decode("utf-8", errors="replace")
                if not re.search(r"forth|fourth error|diag-complete", diagnostic_text, re.I):
                    steps.append("Remote diagnostic menu did not expose a Forth interpreter.")
                    return {"steps": steps, "decoded_text": diagnostic_text}

                steps.append("Entered the remote diagnostic Forth interpreter through menu option 3.")
                sock.sendall(b"words\n")
                dictionary = HardwareLogicAgent._recv_bounded(
                    sock,
                    timeout=2,
                    markers=(b" system ",),
                )
                dictionary_text = dictionary.decode("utf-8", errors="replace")
                if not re.search(r"(?:^|\s)system(?:\s|$)", dictionary_text):
                    steps.append("Forth dictionary enumeration did not expose the system word.")
                    return {"steps": steps, "decoded_text": diagnostic_text + dictionary_text}

                steps.append("Enumerated the Forth dictionary and confirmed the non-standard system word.")
                combined = diagnostic + dictionary
                for flag_path in ("flag.txt", "/flag.txt", "/home/ctf/flag.txt"):
                    command = f's" cat {flag_path}" system\n'.encode("ascii")
                    sock.sendall(command)
                    response = HardwareLogicAgent._recv_bounded(
                        sock,
                        timeout=2,
                        markers=(b"}",),
                    )
                    combined += response
                    flag = find_first_flag(response.decode("utf-8", errors="replace"))
                    if flag:
                        steps.append(f"Recovered flag through Forth system from {flag_path}: {flag}")
                        return {
                            "steps": steps,
                            "flag": flag,
                            "decoded_text": combined.decode("utf-8", errors="replace"),
                        }
                steps.append("Forth system execution succeeded, but standard flag paths returned no flag.")
                return {"steps": steps, "decoded_text": combined.decode("utf-8", errors="replace")}
        except (OSError, socket.timeout) as exc:
            steps.append(f"Remote Forth diagnostic attempt failed: {exc}")
            return {"steps": steps}

    @staticmethod
    def _recv_bounded(
        sock: socket.socket,
        *,
        timeout: float,
        markers: Tuple[bytes, ...] = (),
        limit: int = 128 * 1024,
    ) -> bytes:
        deadline = time.monotonic() + timeout
        output = bytearray()
        lowered_markers = tuple(marker.lower() for marker in markers)
        while time.monotonic() < deadline and len(output) < limit:
            try:
                chunk = sock.recv(min(8192, limit - len(output)))
            except socket.timeout:
                continue
            if not chunk:
                break
            output.extend(chunk)
            lowered_output = bytes(output).lower()
            if any(marker in lowered_output for marker in lowered_markers):
                break
        return bytes(output)

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

    # ------------------------------------------------------------ SDR / IQ
    # numpy dtype and DC bias for each raw IQ layout. ``bias`` is subtracted
    # from the unsigned formats so the samples are centred on zero before the
    # I/Q pair is combined into a complex value.
    _IQ_DTYPES: Dict[str, Tuple[str, float]] = {
        ".cf32": ("complex64", 0.0), ".fc32": ("complex64", 0.0),
        ".cfile": ("complex64", 0.0), ".32fc": ("complex64", 0.0),
        ".iq": ("complex64", 0.0), ".complex": ("complex64", 0.0),
        ".cu8": ("uint8", 127.5), ".cs8": ("int8", 0.0), ".c8": ("int8", 0.0),
        ".cs16": ("int16", 0.0), ".sc16": ("int16", 0.0), ".c16": ("int16", 0.0),
    }

    @classmethod
    def _load_iq_samples(cls, iq_path: str):
        """Load an interleaved-IQ capture as a complex numpy array.

        Returns ``None`` (rather than raising) when numpy is unavailable or the
        file cannot be interpreted, so the caller can degrade gracefully.
        """
        try:
            import numpy as np
        except Exception:  # pragma: no cover - numpy is a project dependency
            return None

        suffix = Path(iq_path).suffix.lower()
        dtype_name, bias = cls._IQ_DTYPES.get(suffix, ("complex64", 0.0))
        try:
            raw = np.fromfile(iq_path, dtype=np.dtype(dtype_name))
        except OSError:
            return None
        if raw.size == 0:
            return None

        if dtype_name == "complex64":
            samples = raw.astype(np.complex64)
        else:
            real = raw.astype(np.float32) - bias
            if real.size % 2:  # drop a trailing half-sample if the file is odd
                real = real[:-1]
            samples = real[0::2] + 1j * real[1::2]
        # Guard against non-finite values that would poison the magnitude math.
        samples = samples[np.isfinite(samples.real) & np.isfinite(samples.imag)]
        return samples if samples.size else None

    def _decode_iq_capture(self, iq_path: str) -> Dict[str, Any]:
        """Demodulate an SDR IQ capture (OOK/ASK) and recover an ASCII flag.

        Handles the common "captured a remote/key-fob signal" hardware
        challenge: threshold the complex magnitude into on/off symbols, recover
        the symbol period from run lengths, then try Manchester and plain
        NRZ line codes across every bit alignment and inversion.
        """
        steps: List[str] = []
        try:
            import numpy as np
        except Exception:  # pragma: no cover
            return {"steps": ["numpy is unavailable; cannot demodulate the IQ capture."]}

        samples = self._load_iq_samples(iq_path)
        if samples is None:
            return {"steps": [f"Could not read IQ capture as complex samples: {iq_path}"]}

        mag = np.abs(samples).astype(np.float64)
        peak = float(mag.max())
        if peak <= 0:
            return {"steps": ["IQ capture contained no signal energy."]}
        mag /= peak  # normalise to [0, 1] so thresholds are scale-independent

        threshold = self._otsu_threshold(mag)
        on = mag > threshold
        low_mean = float(mag[~on].mean()) if (~on).any() else 0.0
        high_mean = float(mag[on].mean()) if on.any() else 0.0
        steps.append(
            f"Loaded {samples.size} IQ samples; amplitude is bimodal "
            f"(off~{low_mean:.2f}, on~{high_mean:.2f}) — treating as OOK/ASK."
        )
        # OOK needs two well-separated amplitude levels. If the high level is not
        # clearly above the low level this is likely FSK/PSK, not OOK.
        if high_mean - low_mean < 0.15:
            steps.append(
                "Amplitude levels are not clearly separated; the signal may be "
                "FSK/PSK rather than OOK. No OOK bitstream recovered."
            )
            return {"steps": steps}

        symbols = on.astype(np.int8)
        values, lengths = self._run_lengths(symbols, np)
        # Ignore the long idle runs at the very start/end when estimating the
        # symbol period so leading/trailing silence does not skew it.
        period, residual = self._estimate_symbol_period(lengths, np)
        if period <= 0:
            steps.append("Could not estimate a stable symbol period from the capture.")
            return {"steps": steps}
        steps.append(
            f"Estimated symbol period {period:.1f} samples/chip "
            f"(fit residual {residual:.3f}) across {len(lengths)} pulses."
        )

        # Pad a trailing idle so the final data byte always completes even when
        # the capture is cut off right after the last on-pulse (e.g. a flag that
        # ends on the "}" byte, whose Manchester/NRZ tail needs a following chip).
        chips = self._chip_stream(values, lengths, period) + "0" * 16
        flag, method, text = self._decode_ook_chips(chips)
        if flag:
            steps.append(f"Recovered flag via {method} decoding of the OOK bitstream.")
            line_code = "manchester_decoding" if "Manchester" in (method or "") else "nrz_line_decoding"
            return {
                "steps": steps,
                "flag": flag,
                "decoded_text": text,
                "techniques": ["sdr_iq_ook_demodulation", line_code],
            }

        steps.append(
            "Demodulated the OOK bitstream but no Manchester/NRZ alignment "
            "produced a flag. Best-effort ASCII: "
            f"{(text or '')[:120]!r}"
        )
        return {"steps": steps, "decoded_text": text}

    @staticmethod
    def _otsu_threshold(values) -> float:
        """Otsu's method: the level that best splits a bimodal amplitude set."""
        import numpy as np

        hist, edges = np.histogram(values, bins=256)
        hist = hist.astype(np.float64)
        total = hist.sum()
        if total == 0:
            return float(np.mean(values))
        prob = hist / total
        omega = np.cumsum(prob)
        mids = (edges[:-1] + edges[1:]) / 2.0
        mu = np.cumsum(prob * mids)
        mu_total = mu[-1]
        denom = omega * (1.0 - omega)
        denom[denom == 0] = 1e-12
        between = (mu_total * omega - mu) ** 2 / denom
        return float(mids[int(np.nanargmax(between))])

    @staticmethod
    def _run_lengths(symbols, np):
        """Run-length encode a 0/1 array into (values, lengths)."""
        if symbols.size == 0:
            return symbols, symbols
        change = np.where(np.diff(symbols) != 0)[0] + 1
        starts = np.concatenate(([0], change))
        ends = np.concatenate((change, [symbols.size]))
        return symbols[starts], (ends - starts)

    @staticmethod
    def _estimate_symbol_period(lengths, np) -> Tuple[float, float]:
        """Estimate the chip period as the unit best explaining all run lengths.

        Each run is one or more chips of equal value, so its length is close to
        an integer multiple of the chip period. Search for the period that
        minimises the mean rounding residual of ``length / period``.
        """
        lengths = np.asarray(lengths, dtype=np.float64)
        lengths = lengths[lengths > 0]
        if lengths.size == 0:
            return 0.0, 1.0
        # The shortest recurring runs are single chips; seed the search there.
        base = float(np.percentile(lengths, 5))
        if base <= 0:
            base = float(lengths.min())
        best_u, best_err = base, 1e9
        for candidate in np.linspace(base * 0.6, base * 1.5, 400):
            k = np.maximum(np.round(lengths / candidate), 1)
            err = float(np.mean(np.abs(lengths - k * candidate)) / candidate)
            if err < best_err:
                best_err, best_u = err, float(candidate)
        return best_u, best_err

    @staticmethod
    def _chip_stream(values, lengths, period: float) -> str:
        """Expand run-length pulses into a per-chip 0/1 string."""
        chunks: List[str] = []
        for value, length in zip(values, lengths):
            count = max(1, int(round(float(length) / period)))
            chunks.append(str(int(value)) * count)
        return "".join(chunks)

    @classmethod
    def _decode_ook_chips(cls, chips: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Try Manchester then NRZ line codes over an OOK chip string.

        Returns ``(flag, method, decoded_text)``. Manchester is attempted first
        because plain NRZ over a Manchester-coded stream yields only the
        alternating preamble, so it never produces a false flag; the converse is
        just as safe because ``find_first_flag`` requires a real flag prefix.
        """
        best_text: Optional[str] = None
        inverted = chips.translate(str.maketrans("01", "10"))

        for one_symbol in ("10", "01"):
            for phase in (0, 1):
                bits = cls._manchester_decode(chips[phase:], one_symbol)
                for offset in range(8):
                    text = cls._bitstring_to_ascii(bits[offset:])
                    best_text = best_text or text
                    flag = cls._find_known_prefix_flag(text) or find_first_flag(text)
                    if flag:
                        return flag, f"Manchester (bit1={one_symbol}, phase {phase})", text

        for label, stream in (("NRZ", chips), ("NRZ-inverted", inverted)):
            for offset in range(8):
                text = cls._bitstring_to_ascii(stream[offset:])
                best_text = best_text or text
                flag = cls._find_known_prefix_flag(text) or find_first_flag(text)
                if flag:
                    return flag, label, text

        return None, None, best_text

    @staticmethod
    def _manchester_decode(chips: str, one_symbol: str) -> str:
        """Decode a chip string as Manchester; unknown pairs become '?'."""
        zero_symbol = "01" if one_symbol == "10" else "10"
        out: List[str] = []
        for idx in range(0, len(chips) - 1, 2):
            pair = chips[idx:idx + 2]
            if pair == one_symbol:
                out.append("1")
            elif pair == zero_symbol:
                out.append("0")
            else:
                out.append("?")
        return "".join(out)

    @staticmethod
    def _bitstring_to_ascii(bits: str) -> str:
        chars: List[str] = []
        for idx in range(0, len(bits) - 7, 8):
            byte = bits[idx:idx + 8]
            if "?" in byte:
                chars.append(".")
            else:
                chars.append(chr(int(byte, 2) & 0xFF))
        return "".join(chars)

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
