"""
Challenge parser and validator.

Accepts challenge dicts or JSON files and normalizes them to the schema
expected by the coordinator.  Handles our native format as well as common
CTF platform exports (CTFd, picoCTF).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class ParseError(ValueError):
    """Raised when a challenge cannot be parsed or is missing required fields."""


KNOWN_CATEGORIES = frozenset({
    "crypto", "web", "reverse", "pwn", "forensics",
    "osint", "log", "misc", "networking", "unknown",
})

_REQUIRED_FIELDS = ("id", "name", "description")

_CATEGORY_MAP: Dict[str, str] = {
    "cryptography": "crypto",
    "crypto": "crypto",
    "web exploitation": "web",
    "web security": "web",
    "web": "web",
    "reverse engineering": "reverse",
    "reversing": "reverse",
    "reverse": "reverse",
    "binary exploitation": "pwn",
    "binary": "pwn",
    "pwn": "pwn",
    "forensics": "forensics",
    "digital forensics": "forensics",
    "network forensics": "forensics",
    "osint": "osint",
    "open source intelligence": "osint",
    "miscellaneous": "misc",
    "general skills": "misc",
    "general": "misc",
    "misc": "misc",
    "log analysis": "log",
    "log": "log",
    "networking": "networking",
    "network": "networking",
    "unknown": "unknown",
}

_DEFAULTS: Dict[str, Any] = {
    "difficulty": "unknown",
    "points": 0,
    "files": [],
    "hints": [],
    "tags": [],
    "url": None,
    "connection_info": None,
    "status": "active",
    "metadata": {},
    "flag": None,
}


class ChallengeParser:
    """
    Parse, normalize, and validate challenge dicts.

    Usage::

        parser = ChallengeParser()
        challenge = parser.parse_file("challenges/active/example.json")
        errors = parser.validate(challenge)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, path: Union[str, Path]) -> Dict[str, Any]:
        """
        Read a JSON file and return a normalized challenge dict.

        Raises:
            ParseError: if the file does not exist, cannot be decoded as JSON,
                        or is missing required fields.
        """
        path = Path(path)
        if not path.exists():
            raise ParseError(f"Challenge file not found: {path}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ParseError(f"Expected a JSON object in {path}, got {type(raw).__name__}")
        return self.parse_dict(raw)

    def parse_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a raw challenge dict to the coordinator's expected schema.

        Raises:
            ParseError: if a required field is absent.
        """
        if not isinstance(data, dict):
            raise ParseError(f"Expected a dict, got {type(data).__name__}")

        normalized = self._detect_and_normalize(data)
        errors = self._check_required(normalized)
        if errors:
            raise ParseError("; ".join(errors))
        return normalized

    def validate(self, data: Dict[str, Any]) -> List[str]:
        """
        Return a list of validation error/warning strings without raising.

        An empty list means the dict is valid.
        """
        errors = self._check_required(data)
        errors.extend(self._check_category(data))
        return errors

    # ------------------------------------------------------------------
    # Internal: format detection and normalization
    # ------------------------------------------------------------------

    def _detect_and_normalize(self, data: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(data)

        # picoCTF: has 'pid' as the numeric id
        if "pid" in out and "id" not in out:
            out["id"] = str(out.pop("pid"))
        elif "pid" in out:
            out.pop("pid")

        # CTFd / picoCTF: 'value' is points
        if "value" in out and "points" not in out:
            out["points"] = out.pop("value")
        elif "value" in out:
            out.pop("value")

        # CTFd: 'flags' is a list of accepted flag strings
        if "flags" in out:
            flags = out.pop("flags")
            if isinstance(flags, list) and flags and "flag" not in out:
                out["flag"] = flags[0]

        # CTFd: 'type' is the challenge type ("standard", "dynamic", …) — not our category
        if "type" in out and "category" in out:
            out.pop("type")
        elif "type" in out:
            out.pop("type")

        # Normalize id to str
        if "id" in out:
            out["id"] = str(out["id"])

        # Normalize category
        out["category"] = self._normalize_category(out.get("category", ""))

        # If category still unknown, try to infer from tags or description
        if out["category"] == "unknown":
            out["category"] = self._infer_category(out)

        # Coerce list fields
        for field in ("files", "hints", "tags"):
            val = out.get(field)
            if val is None:
                out[field] = []
            elif isinstance(val, str):
                out[field] = [val] if val else []
            elif not isinstance(val, list):
                try:
                    out[field] = list(val)
                except TypeError:
                    out[field] = [val]

        # Apply defaults for missing optional fields
        for key, default in _DEFAULTS.items():
            if key not in out:
                out[key] = default

        return out

    @staticmethod
    def _normalize_category(raw: Any) -> str:
        if not raw or not isinstance(raw, str):
            return "unknown"
        normalized = raw.strip().lower()
        return _CATEGORY_MAP.get(normalized, "unknown")

    @staticmethod
    def _infer_category(data: Dict[str, Any]) -> str:
        """Guess category from tags and description when none is provided."""
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tag_text = tags
        else:
            try:
                tag_text = " ".join(str(tag) for tag in tags)
            except TypeError:
                tag_text = str(tags)

        text = " ".join([
            tag_text,
            data.get("description", ""),
            data.get("name", ""),
        ]).lower()

        patterns = [
            (r"\bcrypto\b|cipher|decrypt|base64|xor|hash",            "crypto"),
            (r"\bweb\b|http|sql.?inject|xss|cookie|jwt|session",      "web"),
            (r"\breverse\b|reversing|disassemble|decompile|binary",    "reverse"),
            (r"\bpwn\b|buffer.?overflow|exploit|shellcode|rop",       "pwn"),
            (r"\bforensics?\b|pcap|binwalk|metadata|steganograph",    "forensics"),
            (r"\bosint\b|whois|social.?media|geolocation",            "osint"),
            (r"\blog\b|auth.?log|access.?log|brute.?force",           "log"),
            (r"\bnetwork\b|nmap|port.?scan|packet",                    "networking"),
        ]
        for pattern, category in patterns:
            if re.search(pattern, text):
                return category
        return "unknown"

    # ------------------------------------------------------------------
    # Internal: validation
    # ------------------------------------------------------------------

    @staticmethod
    def _check_required(data: Dict[str, Any]) -> List[str]:
        return [
            f"'{f}' is required"
            for f in _REQUIRED_FIELDS
            if not data.get(f)
        ]

    @staticmethod
    def _check_category(data: Dict[str, Any]) -> List[str]:
        cat = data.get("category", "unknown")
        if cat not in KNOWN_CATEGORIES:
            return [f"unknown category '{cat}'; expected one of {sorted(KNOWN_CATEGORIES)}"]
        return []
