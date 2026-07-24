"""Quantum challenge specialist.

The first deterministic technique targets BB84-style bit-commitment services
that mistakenly let the committer prepare an entangled two-qubit state.  An
EPR pair has correlated outcomes in both the Z and X bases, so the committer
can defer the effective choice until after the verifier announces its basis.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from agents.base_agent import AgentType, BaseAgent
from agents.registry import AgentRegistry
from core.utils.flag_utils import find_first_flag
from core.utils.security import SecurityPolicyError, assert_url_allowed


@AgentRegistry.register(order=95)
class QuantumAgent(BaseAgent):
    """Specialist for quantum circuits and vulnerable quantum protocols."""

    MAX_ROUNDS = 128
    MAX_STRANDS = 128

    def __init__(
        self,
        agent_id: str = "quantum_agent",
        session: Optional[requests.Session] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.session = session or requests.Session()
        self.capabilities = [
            "quantum",
            "quantum_circuits",
            "quantum_protocols",
            "bb84",
            "epr_pairs",
            "bell_states",
            "entanglement_attacks",
            "quantum_bit_commitment",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        text = self._challenge_text(challenge)
        indicators: List[str] = []
        if re.search(r"\b(?:quantum|qubit|qiskit|cirq|bloch)\b", text):
            indicators.append("quantum_terms")
        if re.search(r"\b(?:epr|bell state|entangl|bb84)\b", text):
            indicators.append("entanglement_protocol")
        if (
            ("commit" in text or "sealed" in text)
            and re.search(r"\b(?:basis|measure|warden|oath)\b", text)
        ):
            indicators.append("quantum_commitment_protocol")

        can_handle = str(challenge.get("category") or "").lower() == "quantum" or bool(indicators)
        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": 0.97 if "quantum_commitment_protocol" in indicators else (0.9 if can_handle else 0.1),
            "detected_types": indicators,
            "approach": self._plan_approach(indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps = ["Analyzed the challenge for quantum-protocol weaknesses."]
        base_url = self._base_url(challenge)
        if not base_url:
            steps.append("No HTTP target was provided for deterministic protocol interaction.")
            return self._result(challenge, steps=steps)

        try:
            assert_url_allowed(base_url)
            oath = self._json("GET", f"{base_url}/api/oath")
            if not self._is_oathbinding_protocol(oath):
                steps.append("The target does not expose the supported Oathbinding API contract.")
                return self._result(challenge, steps=steps)

            hearing = self._json("POST", f"{base_url}/api/new")
            token = str(hearing["token"])
            rounds = self._bounded_count(hearing.get("rounds", oath.get("rounds")), "rounds", self.MAX_ROUNDS)
            strands = self._bounded_count(
                hearing.get("strands", oath.get("strands")), "strands", self.MAX_STRANDS
            )
            steps.append(
                f"Opened a hearing with {strands} strands across {rounds} rounds."
            )
            steps.append(
                "Prepared |Phi+> EPR pairs using H(a), CX(a,b); their outcomes "
                "match when both halves are measured in either Z or X."
            )

            slot = [["H", "a"], ["CX", "a", "b"]]
            final_payload: Dict[str, Any] = {}
            for round_index in range(rounds):
                commitment = self._json(
                    "POST",
                    f"{base_url}/api/commit",
                    {"token": token, "slots": [slot for _ in range(strands)]},
                )
                challenge_bit = commitment.get("challenge", commitment.get("c"))
                if challenge_bit not in (0, 1):
                    raise ValueError("commit response did not contain a binary challenge")
                basis = "Z" if challenge_bit == 0 else "X"
                peek = self._json(
                    "POST",
                    f"{base_url}/api/peek",
                    {"token": token, "basis": basis},
                )
                values = peek.get("a_outcomes", peek.get("outcomes", peek.get("values")))
                self._validate_bits(values, strands, "peek outcomes")
                final_payload = self._json(
                    "POST",
                    f"{base_url}/api/open",
                    {"token": token, "values": values},
                )
                if final_payload.get("round_held") is not True:
                    raise ValueError(f"round {round_index + 1} was rejected")

            flag = final_payload.get("flag") or find_first_flag(str(final_payload))
            if not flag:
                steps.append("All configured rounds held, but the final response contained no flag.")
                return self._result(
                    challenge,
                    steps=steps,
                    artifacts={"final_response": final_payload},
                    techniques=["epr_deferred_measurement"],
                )

            steps.append(f"Opened all {rounds} rounds successfully with deferred-basis measurements.")
            return self._result(
                challenge,
                steps=steps,
                flag=str(flag),
                techniques=["bell_state_correlations", "epr_deferred_measurement"],
            )
        except (requests.RequestException, SecurityPolicyError, KeyError, TypeError, ValueError) as exc:
            steps.append(f"Quantum protocol solve stopped safely: {exc}")
            return self._result(challenge, steps=steps)

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    def _json(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        response = self.session.request(method, url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError(f"{url} returned a non-object JSON response")
        return data

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
    def _base_url(challenge: Dict[str, Any]) -> Optional[str]:
        candidates = [
            challenge.get("url"),
            challenge.get("connection_info"),
            challenge.get("remote"),
            challenge.get("target"),
        ]
        for candidate in candidates:
            if isinstance(candidate, dict):
                candidate = candidate.get("url") or candidate.get("base_url")
            value = str(candidate or "").strip()
            if not value:
                continue
            if not re.match(r"^https?://", value, re.IGNORECASE):
                value = f"http://{value}"
            parsed = urlparse(value)
            if parsed.hostname and parsed.port:
                return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        return None

    @staticmethod
    def _is_oathbinding_protocol(oath: Dict[str, Any]) -> bool:
        commit = str(oath.get("commit") or "").lower()
        peek = str(oath.get("peek") or "").lower()
        opened = str(oath.get("open") or "").lower()
        gates = str(oath.get("gates") or "").upper()
        return (
            "/api/commit" in commit
            and "/api/peek" in peek
            and "/api/open" in opened
            and "CX" in gates
            and "H" in gates
        )

    @staticmethod
    def _bounded_count(raw: Any, label: str, maximum: int) -> int:
        value = int(raw)
        if value < 1 or value > maximum:
            raise ValueError(f"{label} must be between 1 and {maximum}, got {value}")
        return value

    @staticmethod
    def _validate_bits(values: Any, expected: int, label: str) -> None:
        if not isinstance(values, list) or len(values) != expected:
            raise ValueError(f"{label} must contain exactly {expected} values")
        if any(value not in (0, 1) for value in values):
            raise ValueError(f"{label} must contain only binary values")

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
