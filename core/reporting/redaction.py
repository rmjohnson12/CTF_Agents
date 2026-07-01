"""Reporting-specific redaction for secrets and captured flags."""

from __future__ import annotations

from typing import Any

from core.utils.flag_utils import extract_flags
from core.utils.security import redact_sensitive_data


def redact_reporting_data(value: Any, *, include_flags: bool = False) -> Any:
    """Redact ordinary secrets plus flags embedded in descriptions/artifacts."""
    sanitized = redact_sensitive_data(value)
    if include_flags:
        return sanitized
    return _redact_flags(sanitized)


def _redact_flags(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_flags(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_flags(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_flags(item) for item in value)
    if isinstance(value, str):
        result = value
        for flag in extract_flags(value):
            result = result.replace(flag, "[REDACTED_FLAG]")
        return result
    return value
