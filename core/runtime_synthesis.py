"""Evidence-gated runtime tool synthesis.

The model may compose a short-lived tool from a deliberately small operation
DSL.  It never writes/imports Python modules or installs packages; execution is
delegated to existing policy-enforced wrappers.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urljoin, urlparse

from core.utils.flag_utils import find_first_flag
from tools.web.http_fetch import HttpFetchTool


class RuntimeToolValidationError(ValueError):
    """Raised when a synthesized tool exceeds its execution contract."""


class RuntimeToolSynthesisLoop:
    """Validate and execute one ephemeral, declarative recovery tool."""

    ALLOWED_OPERATIONS = {
        "http_request",
        "read_artifact",
        "regex_extract",
        "decode",
        "json_extract",
    }

    def __init__(self, reasoner: Any, http_tool: Optional[HttpFetchTool] = None):
        self.reasoner = reasoner
        self.http_tool = http_tool or HttpFetchTool(max_preview_chars=200_000)

    def attempt(
        self,
        challenge: Dict[str, Any],
        history: List[Dict[str, Any]],
        trace_steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        propose = getattr(self.reasoner, "synthesize_runtime_tool", None)
        if not callable(propose):
            return None
        spec = propose(challenge, history, trace_steps, sorted(self.ALLOWED_OPERATIONS))
        if not spec:
            return None

        try:
            evidence_text = json.dumps(
                {
                    "challenge": challenge,
                    "history": history[-6:],
                    "steps": trace_steps[-60:],
                },
                default=str,
            )
            self.validate_spec(spec, challenge, evidence_text=evidence_text)
            return self.execute_spec(spec, challenge)
        except Exception as exc:
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": "runtime_tool_synthesizer",
                "status": "attempted",
                "flag": None,
                "steps": [f"Synthesized tool rejected or failed safely: {exc}"],
                "artifacts": {
                    "runtime_tool_synthesis": {
                        "name": str(spec.get("name", "unnamed"))[:80],
                        "validated": False,
                        "captured_sensitive_values": False,
                        "techniques": ["runtime_tool_synthesis"],
                    }
                },
            }

    def validate_spec(
        self,
        spec: Dict[str, Any],
        challenge: Dict[str, Any],
        *,
        evidence_text: Optional[str] = None,
    ) -> None:
        if not isinstance(spec, dict):
            raise RuntimeToolValidationError("proposal must be an object")
        if len(json.dumps(spec, default=str)) > 50_000:
            raise RuntimeToolValidationError("proposal exceeds the 50 KB limit")
        if not str(spec.get("name", "")).strip():
            raise RuntimeToolValidationError("proposal needs a stable name")
        evidence = spec.get("evidence")
        if not isinstance(evidence, list) or not any(str(item).strip() for item in evidence):
            raise RuntimeToolValidationError("proposal must cite observed evidence")
        if evidence_text is not None and not any(
            self._evidence_supported(str(item), evidence_text)
            for item in evidence
            if str(item).strip()
        ):
            raise RuntimeToolValidationError("proposal evidence is not present in the observed trace")
        operations = spec.get("operations")
        if not isinstance(operations, list) or not 1 <= len(operations) <= 12:
            raise RuntimeToolValidationError("proposal must contain 1-12 operations")

        seen_outputs = {"challenge_description"}
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                raise RuntimeToolValidationError(f"operation {index} is not an object")
            kind = str(operation.get("op", ""))
            if kind not in self.ALLOWED_OPERATIONS:
                raise RuntimeToolValidationError(f"operation {kind!r} is not allowed")
            output = str(operation.get("save_as", ""))
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", output):
                raise RuntimeToolValidationError(f"operation {index} has an invalid save_as")
            if output in seen_outputs:
                raise RuntimeToolValidationError(f"duplicate output variable {output!r}")
            self._validate_operation(kind, operation, challenge, seen_outputs)
            seen_outputs.add(output)

    def _validate_operation(
        self,
        kind: str,
        operation: Dict[str, Any],
        challenge: Dict[str, Any],
        seen_outputs: set[str],
    ) -> None:
        if kind == "http_request":
            method = str(operation.get("method", "GET")).upper()
            if method not in {"GET", "POST"}:
                raise RuntimeToolValidationError("HTTP method must be GET or POST")
            self._resolve_target_url(challenge, str(operation.get("url", "")))
        elif kind == "read_artifact":
            self._resolve_artifact(challenge, str(operation.get("path", "")))
        elif kind in {"regex_extract", "decode", "json_extract"}:
            source = str(operation.get("source", ""))
            if source not in seen_outputs:
                raise RuntimeToolValidationError(f"unknown source variable {source!r}")
            if kind == "regex_extract":
                pattern = str(operation.get("pattern", ""))
                if not pattern or len(pattern) > 500:
                    raise RuntimeToolValidationError("regex must contain at most 500 characters")
                if re.search(r"\(\?|\\[1-9]|\)[*+{]", pattern):
                    raise RuntimeToolValidationError("regex uses a potentially unsafe construct")
                re.compile(pattern)
            elif kind == "decode" and operation.get("encoding") not in {
                "base64", "hex", "url"
            }:
                raise RuntimeToolValidationError("unsupported decode encoding")

    def execute_spec(self, spec: Dict[str, Any], challenge: Dict[str, Any]) -> Dict[str, Any]:
        values: Dict[str, Any] = {
            "challenge_description": str(challenge.get("description", "")),
        }
        steps = [
            f"Validated ephemeral runtime tool: {str(spec['name'])[:80]}",
            f"Hypothesis: {str(spec.get('hypothesis', 'unspecified'))[:300]}",
        ]
        flag = None

        for operation in spec["operations"]:
            kind = operation["op"]
            output = operation["save_as"]
            values[output] = self._execute_operation(kind, operation, challenge, values)
            rendered = self._bounded_text(values[output])
            flag = find_first_flag(rendered)
            steps.append(f"Executed synthesized operation {kind} -> {output}.")
            if flag:
                steps.append("Runtime tool produced a validated flag candidate from executed output.")
                break

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": "runtime_tool_synthesizer",
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": {
                "runtime_tool_synthesis": {
                    "name": str(spec["name"])[:80],
                    "validated": True,
                    "operation_types": [item["op"] for item in spec["operations"]],
                    "captured_sensitive_values": False,
                    "techniques": ["runtime_tool_synthesis"],
                }
            },
        }

    def _execute_operation(
        self,
        kind: str,
        operation: Dict[str, Any],
        challenge: Dict[str, Any],
        values: Dict[str, Any],
    ) -> Any:
        if kind == "http_request":
            url = self._resolve_target_url(challenge, operation["url"])
            result = self.http_tool.fetch(
                url,
                method=str(operation.get("method", "GET")),
                timeout_s=min(max(int(operation.get("timeout_s", 10)), 1), 20),
                allow_redirects=False,
                data=operation.get("data"),
                headers=self._safe_headers(operation.get("headers")),
            )
            return result.body_preview
        if kind == "read_artifact":
            path = self._resolve_artifact(challenge, operation["path"])
            return path.read_bytes()[:1_000_000].decode("utf-8", errors="replace")
        if kind == "regex_extract":
            text = self._bounded_text(values[operation["source"]])
            match = re.search(operation["pattern"], text, re.MULTILINE | re.DOTALL)
            if not match:
                return ""
            group = int(operation.get("group", 0))
            return match.group(group)
        if kind == "decode":
            raw = self._bounded_text(values[operation["source"]]).strip()
            encoding = operation["encoding"]
            if encoding == "base64":
                return base64.b64decode(raw, validate=True).decode("utf-8", errors="replace")
            if encoding == "hex":
                return bytes.fromhex(raw).decode("utf-8", errors="replace")
            return unquote(raw)
        if kind == "json_extract":
            value: Any = json.loads(self._bounded_text(values[operation["source"]]))
            for part in str(operation.get("path", "")).split("."):
                if not part:
                    continue
                value = value[int(part)] if isinstance(value, list) else value[part]
            return value
        raise RuntimeToolValidationError(f"unsupported operation {kind!r}")

    @staticmethod
    def _safe_headers(value: Any) -> Optional[Dict[str, str]]:
        if not isinstance(value, dict):
            return None
        blocked = {"authorization", "cookie", "proxy-authorization"}
        return {
            str(key): str(item)[:2000]
            for key, item in value.items()
            if str(key).lower() not in blocked
        }

    @staticmethod
    def _evidence_supported(claim: str, observed: str) -> bool:
        claim_lower, observed_lower = claim.strip().lower(), observed.lower()
        if claim_lower and claim_lower in observed_lower:
            return True
        stopwords = {"that", "this", "with", "from", "into", "trace", "value", "found"}
        claim_tokens = {
            token.strip(".,:;")
            for token in re.findall(r"[a-z0-9_./:-]{4,}", claim_lower)
            if token.strip(".,:;") not in stopwords
        }
        observed_tokens = {
            token.strip(".,:;")
            for token in re.findall(r"[a-z0-9_./:-]{4,}", observed_lower)
        }
        return bool(claim_tokens) and len(claim_tokens & observed_tokens) / len(claim_tokens) >= 0.6

    @staticmethod
    def _bounded_text(value: Any) -> str:
        if isinstance(value, str):
            return value[:200_000]
        return json.dumps(value, default=str)[:200_000]

    @staticmethod
    def _resolve_target_url(challenge: Dict[str, Any], proposed: str) -> str:
        base = challenge.get("url") or (challenge.get("target") or {}).get("url")
        if not base:
            raise RuntimeToolValidationError("HTTP operation requires a challenge URL")
        resolved = urljoin(str(base).rstrip("/") + "/", proposed)
        base_parsed, target_parsed = urlparse(str(base)), urlparse(resolved)
        if (
            target_parsed.scheme not in {"http", "https"}
            or target_parsed.hostname != base_parsed.hostname
            or target_parsed.port != base_parsed.port
        ):
            raise RuntimeToolValidationError("HTTP operation must stay on the challenge origin")
        return resolved

    @staticmethod
    def _resolve_artifact(challenge: Dict[str, Any], proposed: str) -> Path:
        candidate = Path(proposed).expanduser().resolve()
        for raw in challenge.get("files") or []:
            allowed = Path(str(raw)).expanduser().resolve()
            if candidate == allowed or (allowed.is_dir() and allowed in candidate.parents):
                if candidate.is_file():
                    return candidate
        raise RuntimeToolValidationError("artifact path is outside provided challenge files")
