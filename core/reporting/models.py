"""Validated wire model for live solve progress updates."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


ProgressStatus = Literal[
    "queued",
    "running",
    "progress",
    "stalled",
    "attempted",
    "solved",
    "completed",
    "failed",
    "blocked",
]


class ProgressUpdate(BaseModel):
    """One immutable event in a solve timeline."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=128)
    challenge_id: str = Field(min_length=1, max_length=200)
    run_id: str = Field(min_length=1, max_length=200)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_name: str = Field(min_length=1, max_length=120)
    agent_type: str = Field(min_length=1, max_length=80)
    status: ProgressStatus
    step_title: str = Field(min_length=1, max_length=240)
    step_description: str = Field(default="", max_length=8000)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    elapsed_seconds: Optional[float] = Field(default=None, ge=0.0)
    artifacts: Dict[str, Any] = Field(default_factory=dict)
    final_flag: Optional[str] = Field(default=None, max_length=1000)
    error_message: Optional[str] = Field(default=None, max_length=8000)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("artifacts")
    @classmethod
    def artifacts_must_be_json_serializable(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        try:
            json.dumps(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("artifacts must be JSON serializable") from exc
        return value
