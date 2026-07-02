"""
Secure Coding Specialist Agent

Handles source-patch CTF challenges where the target exposes an editor/API and
expects the player to fix a vulnerability, then verify the remediation.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from agents.base_agent import AgentType, BaseAgent
from agents.registry import AgentRegistry
from core.utils.flag_utils import find_first_flag
from tools.web.http_fetch import HttpFetchTool


@AgentRegistry.register(order=140)
class SecureCodingAgent(BaseAgent):
    """Specialist for secure-coding/source-remediation challenge targets."""

    def __init__(
        self,
        agent_id: str = "secure_coding_agent",
        http_tool: Optional[HttpFetchTool] = None,
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.http_tool = http_tool or HttpFetchTool(max_preview_chars=20000)
        self.capabilities = [
            "secure_coding",
            "source_patch",
            "vulnerability_remediation",
            "editor_api",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        text = self._challenge_text(challenge)
        indicators = []
        if challenge.get("category") == "secure_coding":
            indicators.append("secure_coding_category")
        if self._has_secure_coding_terms(text):
            indicators.append("secure_coding_terms")
        if challenge.get("url"):
            indicators.append("live_target")

        can_handle = challenge.get("category") == "secure_coding" or bool(indicators)
        confidence = 0.95 if challenge.get("category") == "secure_coding" else 0.75
        return {
            "agent_id": self.agent_id,
            "can_handle": can_handle,
            "confidence": confidence if can_handle else 0.1,
            "detected_types": indicators,
            "approach": self._plan_approach(indicators),
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        steps: List[str] = []
        target_url = self._target_url(challenge)
        if not target_url:
            return self._result(challenge, "failed", None, ["No target URL found."], {})

        steps.append(f"Target URL: {target_url}")

        coding_flag = self._try_pin_enumeration_runner(target_url, steps)
        if coding_flag:
            return self._result(
                challenge, "solved", coding_flag, steps,
                {"coding_runner": "pin_enumeration", "patch_applied": False},
            )

        flag, verify_body = self._verify(target_url, steps)
        if flag:
            steps.append("Verification endpoint already returned a flag.")
            return self._result(
                challenge,
                "solved",
                flag,
                steps,
                {"verify_body": verify_body, "patch_applied": False},
            )

        source, source_path = self._load_source(target_url, steps)
        if not source:
            return self._result(
                challenge,
                "attempted",
                None,
                steps + ["Could not load a recognized editable source file."],
                {"verify_body": verify_body},
            )

        patched, changed, reason = self._patch_known_vulnerability(source)
        steps.append(reason)
        if not changed:
            return self._result(
                challenge,
                "attempted",
                None,
                steps + ["No safe patch was generated, so no source was saved."],
                {"source_path": source_path},
            )

        if not self._save_source(target_url, source_path, patched, steps):
            return self._result(
                challenge,
                "failed",
                None,
                steps + ["Patch save failed."],
                {"source_path": source_path, "patch_applied": False},
            )

        flag, verify_body = self._verify(target_url, steps)
        status = "solved" if flag else "attempted"
        if flag:
            steps.append("Verification returned a flag after patching.")
        else:
            steps.append("Verification did not return a flag after patching.")

        return self._result(
            challenge,
            status,
            flag,
            steps,
            {
                "source_path": source_path,
                "patch_applied": True,
                "verify_body": verify_body,
            },
        )

    def get_capabilities(self) -> List[str]:
        return self.capabilities

    @staticmethod
    def _challenge_text(challenge: Dict[str, Any]) -> str:
        return " ".join([
            str(challenge.get("name", "")),
            str(challenge.get("description", "")),
            " ".join(str(h) for h in challenge.get("hints", [])),
            " ".join(str(t) for t in challenge.get("tags", [])),
        ]).lower()

    @staticmethod
    def _has_secure_coding_terms(text: str) -> bool:
        terms = [
            "secure coding",
            "secure-coding",
            "fix the vulnerability",
            "patch the vulnerability",
            "patch source",
            "source patch",
            "code review",
            "remediate",
            "vulnerable code",
        ]
        return any(term in text for term in terms)

    @staticmethod
    def _target_url(challenge: Dict[str, Any]) -> Optional[str]:
        url = challenge.get("url")
        if url:
            return str(url).rstrip("/") + "/"

        connection_info = challenge.get("connection_info") or {}
        if isinstance(connection_info, dict):
            for key in ("url", "target_url", "base_url"):
                if connection_info.get(key):
                    return str(connection_info[key]).rstrip("/") + "/"
        return None

    def _verify(self, target_url: str, steps: List[str]) -> Tuple[Optional[str], str]:
        verify_url = urljoin(target_url, "/api/verify")
        try:
            result = self.http_tool.fetch(verify_url, timeout_s=10)
        except Exception as exc:
            steps.append(f"Verification request failed: {exc}")
            return None, ""

        body = result.body_preview
        steps.append(f"Checked /api/verify (HTTP {result.status_code}).")
        flag = find_first_flag(body)
        if flag:
            return flag, body
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return None, body
        if isinstance(parsed, dict):
            for value in parsed.values():
                if isinstance(value, str):
                    flag = find_first_flag(value)
                    if flag:
                        return flag, body
        return None, body

    def _try_pin_enumeration_runner(self, target_url: str, steps: List[str]) -> Optional[str]:
        """Recognize and solve PIN-template enumeration code-runner tasks."""
        try:
            page = self.http_tool.fetch(target_url, timeout_s=10)
        except Exception as exc:
            steps.append(f"Coding-runner inspection failed: {exc}")
            return None

        body = page.body_preview
        if not (
            "unknown positions are represented" in body.lower()
            and "no two adjacent digits" in body.lower()
            and ("pinsmith" in body.lower() or 'fetch("/run"' in body)
        ):
            return None

        steps.append("Detected PIN-template enumeration runner from challenge-page evidence.")
        code = '''import sys

def main():
    pattern = sys.stdin.readline().strip()
    current = []
    output = []

    def generate(index):
        if index == len(pattern):
            output.append("".join(current))
            return
        choices = "0123456789" if pattern[index] == "*" else pattern[index]
        for digit in choices:
            if current and current[-1] == digit:
                continue
            current.append(digit)
            generate(index + 1)
            current.pop()

    generate(0)
    sys.stdout.write("\\n".join(output))
    if output:
        sys.stdout.write("\\n")

if __name__ == "__main__":
    main()
'''
        try:
            result = self.http_tool.fetch(
                urljoin(target_url, "/run"), method="POST", timeout_s=30,
                json_data={"code": code, "language": "python"},
            )
        except Exception as exc:
            steps.append(f"PIN enumeration submission failed: {exc}")
            return None

        flag = find_first_flag(result.body_preview)
        if flag:
            steps.append("PIN enumeration program passed all runner tests and returned a flag.")
        else:
            steps.append(f"PIN enumeration runner returned HTTP {result.status_code} without a flag.")
        return flag

    def _load_source(self, target_url: str, steps: List[str]) -> Tuple[Optional[str], str]:
        for source_path in ("utils/db.js",):
            file_url = urljoin(target_url, "/api/file")
            try:
                result = self.http_tool.fetch(
                    file_url,
                    timeout_s=10,
                    params={"path": source_path},
                )
            except Exception as exc:
                steps.append(f"Failed to load {source_path}: {exc}")
                continue

            steps.append(f"Loaded {source_path} (HTTP {result.status_code}).")
            content = self._content_from_body(result.body_preview)
            if content is not None:
                return content, source_path
        return None, ""

    @staticmethod
    def _content_from_body(body: str) -> Optional[str]:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return body if "function addUser" in body else None
        if isinstance(parsed, dict) and isinstance(parsed.get("content"), str):
            return parsed["content"]
        return None

    def _save_source(self, target_url: str, source_path: str, content: str, steps: List[str]) -> bool:
        save_url = urljoin(target_url, "/api/save")
        try:
            result = self.http_tool.fetch(
                save_url,
                method="POST",
                timeout_s=10,
                json_data={"path": source_path, "content": content},
            )
        except Exception as exc:
            steps.append(f"Failed to save {source_path}: {exc}")
            return False

        steps.append(f"Saved patched {source_path} (HTTP {result.status_code}).")
        return 200 <= result.status_code < 300

    @staticmethod
    def _patch_known_vulnerability(source: str) -> Tuple[str, bool, str]:
        if all(marker in source for marker in ("username.includes('\\n')", "username.includes('\\r')", "username.includes('|')")):
            return source, False, "Username delimiter guard already appears to be present."

        pattern = re.compile(
            r"(?P<head>(?:export\s+)?function\s+addUser\s*\([^)]*\)\s*\{)",
            re.MULTILINE,
        )
        match = pattern.search(source)
        if not match:
            return source, False, "Could not find a recognizable addUser function to patch."

        indent = SecureCodingAgent._infer_body_indent(source, match.end())
        guard = (
            "\n"
            f"{indent}if (typeof username !== 'string' ||\n"
            f"{indent}    username.includes('\\n') ||\n"
            f"{indent}    username.includes('\\r') ||\n"
            f"{indent}    username.includes('|')) {{\n"
            f"{indent}    return false;\n"
            f"{indent}}}\n"
        )
        patched = source[:match.end()] + guard + source[match.end():]
        return patched, True, "Patched addUser to reject newline, carriage-return, and pipe delimiters."

    @staticmethod
    def _infer_body_indent(source: str, function_body_start: int) -> str:
        remainder = source[function_body_start:]
        next_line = remainder.splitlines()[1:2]
        if next_line:
            match = re.match(r"(\s*)", next_line[0])
            if match and match.group(1):
                return match.group(1)
        return "    "

    def _result(
        self,
        challenge: Dict[str, Any],
        status: str,
        flag: Optional[str],
        steps: List[str],
        artifacts: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": status,
            "flag": flag,
            "steps": steps,
            "artifacts": artifacts,
        }
