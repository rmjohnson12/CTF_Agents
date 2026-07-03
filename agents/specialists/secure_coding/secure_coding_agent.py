"""
Secure Coding Specialist Agent

Handles source-patch CTF challenges where the target exposes an editor/API and
expects the player to fix a vulnerability, then verify the remediation.
"""

from __future__ import annotations

import json
import re
import time
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
                {
                    "coding_runner": "pin_enumeration",
                    "patch_applied": False,
                    "techniques": [
                        "partial_pin_constraint_enumeration",
                        "remote_code_runner_submission",
                    ],
                },
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

        sources = self._load_sources(target_url, steps)
        if not sources:
            return self._result(
                challenge,
                "attempted",
                None,
                steps + ["Could not load a recognized editable source file."],
                {"verify_body": verify_body},
            )

        patch = self._select_patch(sources)
        if patch is None:
            return self._result(
                challenge,
                "attempted",
                None,
                steps + ["No evidence-backed safe patch was generated, so no source was saved."],
                {"discovered_source_files": sorted(sources)},
            )

        source_path, patched, reason, vulnerability_class = patch
        steps.append(reason)

        if not self._save_source(target_url, source_path, patched, steps):
            return self._result(
                challenge,
                "failed",
                None,
                steps + ["Patch save failed."],
                {"source_path": source_path, "patch_applied": False},
            )

        if not self._source_matches(target_url, source_path, patched, steps):
            return self._result(
                challenge,
                "failed",
                None,
                steps + ["Saved source did not match on read-back."],
                {"source_path": source_path, "patch_applied": False},
            )

        self._restart(target_url, steps)

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
                "vulnerability_class": vulnerability_class,
                "discovered_source_files": sorted(sources),
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

    def _load_sources(self, target_url: str, steps: List[str]) -> Dict[str, str]:
        source_paths = self._discover_source_paths(target_url, steps)
        # Compatibility with older editor challenges that do not expose a tree.
        if not source_paths:
            source_paths = ["utils/db.js"]

        sources: Dict[str, str] = {}
        for source_path in source_paths[:40]:
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
                sources[source_path] = content
        return sources

    def _discover_source_paths(self, target_url: str, steps: List[str]) -> List[str]:
        try:
            result = self.http_tool.fetch(urljoin(target_url, "/api/directory"), timeout_s=10)
        except Exception as exc:
            steps.append(f"Source-tree discovery failed: {exc}")
            return []
        steps.append(f"Discovered editable source tree (HTTP {result.status_code}).")
        if not 200 <= result.status_code < 300:
            return []
        try:
            tree = json.loads(result.body_preview)
        except json.JSONDecodeError:
            return []
        if not isinstance(tree, dict):
            return []

        paths: List[str] = []

        def walk(node: Dict[str, Any], prefix: str = "") -> None:
            for name, item in node.items():
                if not isinstance(item, dict):
                    continue
                path = f"{prefix}/{name}".strip("/")
                if item.get("type") == "folder":
                    walk(item.get("children") or {}, path)
                elif item.get("type") == "file" and self._is_reviewable_source(path):
                    paths.append(path)

        walk(tree)
        # Proof-of-concept and server-side files provide the strongest evidence.
        paths.sort(key=self._source_priority)
        return paths

    @staticmethod
    def _is_reviewable_source(path: str) -> bool:
        lowered = path.lower()
        if lowered.endswith(("package-lock.json", ".min.js")):
            return False
        return lowered.endswith((".js", ".ts", ".jsx", ".tsx", ".py", ".json"))

    @staticmethod
    def _source_priority(path: str) -> Tuple[int, str]:
        lowered = path.lower()
        if "exploit" in lowered or "poc" in lowered or "solver" in lowered:
            return (0, lowered)
        if lowered.startswith(("routes/", "utils/", "src/", "app")):
            return (1, lowered)
        if lowered.startswith("static/"):
            return (3, lowered)
        return (2, lowered)

    @staticmethod
    def _content_from_body(body: str) -> Optional[str]:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return body if body.strip() else None
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

    def _source_matches(
        self,
        target_url: str,
        source_path: str,
        expected: str,
        steps: List[str],
    ) -> bool:
        try:
            result = self.http_tool.fetch(
                urljoin(target_url, "/api/file"), timeout_s=10, params={"path": source_path}
            )
        except Exception as exc:
            steps.append(f"Patch read-back failed for {source_path}: {exc}")
            return False
        actual = self._content_from_body(result.body_preview)
        matched = actual == expected
        steps.append(f"Patch read-back for {source_path}: {'matched' if matched else 'mismatch'}.")
        return matched

    def _restart(self, target_url: str, steps: List[str]) -> bool:
        try:
            result = self.http_tool.fetch(
                urljoin(target_url, "/api/restart"), method="POST", timeout_s=15, json_data={}
            )
        except Exception as exc:
            steps.append(f"Service restart failed: {exc}")
            return False
        steps.append(f"Restarted patched service (HTTP {result.status_code}).")
        if 200 <= result.status_code < 300:
            time.sleep(0.5)
            return True
        return False

    @classmethod
    def _select_patch(
        cls,
        sources: Dict[str, str],
    ) -> Optional[Tuple[str, str, str, str]]:
        evidence = "\n".join(sources.values()).lower()
        prototype_evidence = (
            "__proto__" in evidence
            or "prototype pollution" in evidence
            or ("constructor" in evidence and "prototype" in evidence)
        )
        for source_path, source in sources.items():
            patched, changed, reason = cls._patch_known_vulnerability(
                source,
                allow_prototype_pollution_patch=prototype_evidence,
            )
            if changed:
                vulnerability_class = (
                    "prototype_pollution" if "prototype-pollution" in reason else "delimiter_injection"
                )
                return source_path, patched, reason, vulnerability_class
        return None

    @staticmethod
    def _patch_known_vulnerability(
        source: str,
        *,
        allow_prototype_pollution_patch: bool = True,
    ) -> Tuple[str, bool, str]:
        if allow_prototype_pollution_patch:
            merge_loop = re.compile(
                r"(?P<head>for\s*\(\s*(?:let|const|var)\s+(?P<key>[A-Za-z_$][\w$]*)\s+in\s+(?P<src>[A-Za-z_$][\w$]*)\s*\)\s*\{)"
            )
            merge_match = merge_loop.search(source)
            recursive_merge = bool(
                merge_match
                and re.search(r"\b(?:deepMerge|merge|mergeDeep)\s*\(", source[merge_match.end():])
            )
            already_guarded = all(marker in source for marker in ("'__proto__'", "'prototype'", "'constructor'"))
            if merge_match and recursive_merge and not already_guarded:
                key = merge_match.group("key")
                src = merge_match.group("src")
                indent = SecureCodingAgent._infer_body_indent(source, merge_match.end())
                guard = (
                    "\n"
                    f"{indent}if (!Object.prototype.hasOwnProperty.call({src}, {key}) ||\n"
                    f"{indent}    {key} === '__proto__' || {key} === 'prototype' || {key} === 'constructor') {{\n"
                    f"{indent}  continue;\n"
                    f"{indent}}}\n"
                )
                patched = source[:merge_match.end()] + guard + source[merge_match.end():]
                return (
                    patched,
                    True,
                    "Patched unsafe recursive merge with own-property and prototype-pollution key guards.",
                )

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
