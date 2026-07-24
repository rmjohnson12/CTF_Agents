"""Evidence-gated runtime tool synthesis.

The model may compose a short-lived tool from a deliberately small operation
DSL.  Observation ops (fetch/decode/regex) never write or import Python.  The
``compute`` op lets the model run a bounded algorithm it authored, but that code
is executed *only* through the policy-enforced ``PythonTool`` — disabled by
default, Docker-isolated when enabled — never in this process.  This is the
"actually work the problem" capability: given data already gathered by other
ops, the model can invert a transform, simulate a process, or search a space.
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urljoin, urlparse

from core.utils.flag_utils import find_first_flag
from core.utils.security import redact_sensitive_data
from tools.common.python_tool import PythonTool
from tools.web.http_fetch import HttpFetchTool


class RuntimeToolValidationError(ValueError):
    """Raised when a synthesized tool exceeds its execution contract."""


class RuntimeToolSynthesisLoop:
    """Run a bounded model-driven observe/propose/execute recovery loop."""

    ALLOWED_OPERATIONS = {
        "http_request",
        "read_artifact",
        "regex_extract",
        "decode",
        "disassemble_artifact",
        "json_extract",
        "compute",
    }

    # Upper bound on model-authored compute source, so a proposal can't smuggle
    # in a huge script or blow the 50 KB spec budget on one operation.
    MAX_COMPUTE_CODE = 10_000

    def __init__(
        self,
        reasoner: Any,
        http_tool: Optional[HttpFetchTool] = None,
        *,
        python_tool: Optional[PythonTool] = None,
        max_turns: int = 4,
    ):
        self.reasoner = reasoner
        self.http_tool = http_tool or HttpFetchTool(max_preview_chars=200_000)
        # PythonTool enforces the execution policy (disabled by default; Docker or
        # explicit host opt-in). We never exec model code ourselves.
        self.python_tool = python_tool or PythonTool()
        self.max_turns = min(max(int(max_turns), 1), 8)

    def attempt(
        self,
        challenge: Dict[str, Any],
        history: List[Dict[str, Any]],
        trace_steps: List[str],
    ) -> Optional[Dict[str, Any]]:
        propose = getattr(self.reasoner, "synthesize_runtime_tool", None)
        if not callable(propose):
            return None
        working_history = list(history[-6:])
        working_steps = list(trace_steps[-60:])
        aggregate_steps: List[str] = []
        attempted_names: List[str] = []
        seen_specs = set()
        persisted_values: Dict[str, Any] = {}

        for turn in range(1, self.max_turns + 1):
            spec = propose(
                challenge,
                working_history,
                working_steps,
                sorted(self.ALLOWED_OPERATIONS),
            )
            if not spec:
                if turn == 1:
                    return None
                aggregate_steps.append(f"AI solver stopped after {turn - 1} tool turn(s).")
                break

            signature = json.dumps(spec, sort_keys=True, default=str)
            if signature in seen_specs:
                aggregate_steps.append(
                    f"AI solver stopped at turn {turn}: the model repeated an earlier tool."
                )
                break
            seen_specs.add(signature)
            name = str(spec.get("name", "unnamed"))[:80]
            attempted_names.append(name)

            evidence_text = json.dumps(
                {
                    "challenge": challenge,
                    "history": working_history[-8:],
                    "steps": working_steps[-80:],
                },
                default=str,
            )
            try:
                self.validate_spec(
                    spec,
                    challenge,
                    evidence_text=evidence_text,
                    available_sources=set(persisted_values),
                )
                result = self.execute_spec(
                    spec,
                    challenge,
                    initial_values=persisted_values,
                )
                observations = result.pop("_runtime_observations", [])
                persisted_values.update(result.pop("_runtime_values", {}))
                aggregate_steps.append(f"AI tool turn {turn}/{self.max_turns}: {name}")
                aggregate_steps.extend(result.get("steps") or [])
                if result.get("status") == "solved" and result.get("flag"):
                    result["steps"] = aggregate_steps
                    result["artifacts"]["runtime_tool_synthesis"].update({
                        "turns_used": turn,
                        "tool_names": attempted_names,
                        "agentic_loop": True,
                    })
                    return result

                feedback = {
                    "agent_id": "runtime_tool_synthesizer",
                    "status": "attempted",
                    "steps": result.get("steps") or [],
                    "artifacts": {
                        "runtime_tool_observation": {
                            "turn": turn,
                            "name": name,
                            "outputs": redact_sensitive_data(observations),
                        }
                    },
                }
            except Exception as exc:
                message = f"Synthesized tool rejected or failed safely: {exc}"
                aggregate_steps.extend([
                    message,
                    f"AI tool turn {turn}/{self.max_turns}: {name}",
                ])
                feedback = {
                    "agent_id": "runtime_tool_synthesizer",
                    "status": "attempted",
                    "steps": [message],
                    "artifacts": {
                        "runtime_tool_observation": {
                            "turn": turn,
                            "name": name,
                            "validation_error": str(exc)[:1000],
                        }
                    },
                }

            working_history.append(feedback)
            working_history = working_history[-8:]
            working_steps.extend(feedback["steps"])
            working_steps = working_steps[-80:]

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": "runtime_tool_synthesizer",
            "status": "attempted",
            "flag": None,
            "steps": aggregate_steps,
            "artifacts": {
                "runtime_tool_synthesis": {
                    "name": attempted_names[-1] if attempted_names else "none",
                    "validated": bool(attempted_names),
                    "captured_sensitive_values": False,
                    "techniques": ["runtime_tool_synthesis", "agentic_tool_loop"],
                    "turns_used": len(attempted_names),
                    "tool_names": attempted_names,
                    "agentic_loop": True,
                }
            },
        }

    def validate_spec(
        self,
        spec: Dict[str, Any],
        challenge: Dict[str, Any],
        *,
        evidence_text: Optional[str] = None,
        available_sources: Optional[set[str]] = None,
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

        prior_sources = available_sources or set()
        seen_outputs = {"challenge_description", *prior_sources}
        new_outputs = set()
        for index, operation in enumerate(operations):
            if not isinstance(operation, dict):
                raise RuntimeToolValidationError(f"operation {index} is not an object")
            kind = str(operation.get("op", ""))
            if kind not in self.ALLOWED_OPERATIONS:
                raise RuntimeToolValidationError(f"operation {kind!r} is not allowed")
            output = str(operation.get("save_as", ""))
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", output):
                raise RuntimeToolValidationError(f"operation {index} has an invalid save_as")
            if output == "challenge_description" or output in new_outputs:
                raise RuntimeToolValidationError(f"duplicate output variable {output!r}")
            self._validate_operation(kind, operation, challenge, seen_outputs)
            seen_outputs.add(output)
            new_outputs.add(output)

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
        elif kind == "disassemble_artifact":
            self._resolve_artifact(challenge, str(operation.get("path", "")))
            max_bytes = int(operation.get("max_bytes", 4096))
            if not 64 <= max_bytes <= 65_536:
                raise RuntimeToolValidationError(
                    "disassembly max_bytes must be between 64 and 65536"
                )
        elif kind == "compute":
            code = operation.get("code")
            if not isinstance(code, str) or not code.strip():
                raise RuntimeToolValidationError("compute requires a non-empty 'code' string")
            if len(code) > self.MAX_COMPUTE_CODE:
                raise RuntimeToolValidationError(
                    f"compute code must be at most {self.MAX_COMPUTE_CODE} characters"
                )
            for source in operation.get("inputs", []) or []:
                if str(source) not in seen_outputs:
                    raise RuntimeToolValidationError(f"compute input {source!r} is not an available variable")
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

    def execute_spec(
        self,
        spec: Dict[str, Any],
        challenge: Dict[str, Any],
        *,
        initial_values: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        values: Dict[str, Any] = {
            "challenge_description": str(challenge.get("description", "")),
            **(initial_values or {}),
        }
        new_values: Dict[str, Any] = {}
        steps = [
            f"Validated ephemeral runtime tool: {str(spec['name'])[:80]}",
            f"Hypothesis: {str(spec.get('hypothesis', 'unspecified'))[:300]}",
        ]
        flag = None
        observations: List[Dict[str, Any]] = []

        for operation in spec["operations"]:
            kind = operation["op"]
            output = operation["save_as"]
            values[output] = self._execute_operation(kind, operation, challenge, values)
            new_values[output] = values[output]
            rendered = self._bounded_text(values[output])
            observations.append({
                "operation": kind,
                "save_as": output,
                "output": rendered[:8_000],
            })
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
            "_runtime_observations": observations,
            "_runtime_values": new_values,
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
        if kind == "disassemble_artifact":
            path = self._resolve_artifact(challenge, operation["path"])
            r2 = shutil.which("r2") or shutil.which("radare2")
            if not r2:
                raise RuntimeToolValidationError(
                    "disassemble_artifact requires radare2 on PATH"
                )
            max_bytes = min(max(int(operation.get("max_bytes", 4096)), 64), 65_536)
            command = (
                "aaa;"
                "afl;"
                f"pD {max_bytes} @ entry0;"
                "izz"
            )
            result = subprocess.run(
                [r2, "-q", "-e", "bin.relocs.apply=true", "-c", command, str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = (result.stdout or "") + (result.stderr or "")
            if result.returncode != 0 and not output.strip():
                raise RuntimeToolValidationError(
                    f"radare2 failed with exit code {result.returncode}"
                )
            return output[:200_000]
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
        if kind == "compute":
            return self._run_compute(operation, challenge, values)
        raise RuntimeToolValidationError(f"unsupported operation {kind!r}")

    def _run_compute(
        self,
        operation: Dict[str, Any],
        challenge: Dict[str, Any],
        values: Dict[str, Any],
    ) -> str:
        """Run a model-authored algorithm via the sandboxed PythonTool.

        Every prior operation output is exposed to the script as ``inputs[name]``
        (JSON-safe, bounded), and any supplied challenge files are mounted
        read-only in the Docker sandbox so the code can parse raw artifacts. The
        script is expected to ``print`` its result; the loop scans that output
        for a flag or carries it forward for the next turn. Execution honours the
        PythonTool policy: it stays disabled unless the operator enables a
        sandbox, so this op cannot run arbitrary code without an explicit opt-in.
        """
        code = str(operation["code"])
        payload = {name: self._bounded_text(value)[:50_000] for name, value in values.items()}
        preamble = (
            "import base64 as _b64, json as _json\n"
            "inputs = _json.loads(_b64.b64decode(%r).decode())\n"
            % base64.b64encode(json.dumps(payload, default=str).encode()).decode()
        )
        timeout_s = min(max(int(operation.get("timeout_s", 10)), 1), 30)
        result = self.python_tool.run(
            preamble + "\n" + code,
            timeout_s=timeout_s,
            artifact_paths=[str(f) for f in (challenge.get("files") or [])],
            allow_network=False,
        )
        if result.timed_out:
            raise RuntimeToolValidationError(f"compute exceeded its {timeout_s}s time budget")
        if result.exit_code == 126:
            # Execution backend is disabled/misconfigured — surface how to enable it.
            raise RuntimeToolValidationError(
                (result.stderr or "compute execution backend is disabled").strip()[:300]
            )
        stdout = result.stdout or ""
        if not stdout.strip() and result.stderr:
            # Return the error text so the model can revise its code next turn.
            return f"[compute error]\n{result.stderr[:4000]}"
        return stdout[:200_000]

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
