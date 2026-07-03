"""Typed models for HTB challenges, credentials, spawn info, and run results."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").lower()).strip("-")
    return slug or "challenge"


@dataclass
class HTBCredentials:
    """Credentials sourced exclusively from the environment.

    ``__repr__`` is overridden so secrets never land in logs or tracebacks.
    """

    email: Optional[str] = None
    password: Optional[str] = None
    otp: Optional[str] = None
    token: Optional[str] = None

    @classmethod
    def from_env(cls) -> "HTBCredentials":
        return cls(
            email=os.getenv("HTB_EMAIL") or None,
            password=os.getenv("HTB_PASSWORD") or None,
            otp=os.getenv("HTB_OTP") or None,
            token=os.getenv("HTB_TOKEN") or None,
        )

    @property
    def has_token(self) -> bool:
        return bool(self.token)

    @property
    def has_login(self) -> bool:
        return bool(self.email and self.password)

    def __repr__(self) -> str:  # never leak secrets
        return (
            "HTBCredentials("
            f"email={'set' if self.email else 'unset'}, "
            f"password={'set' if self.password else 'unset'}, "
            f"otp={'set' if self.otp else 'unset'}, "
            f"token={'set' if self.token else 'unset'})"
        )


@dataclass
class Challenge:
    """A challenge as understood by this integration.

    ``raw`` retains the original API object so we never silently drop fields the
    community docs did not describe.
    """

    id: int
    name: str
    category: str = "unknown"
    difficulty: str = "unknown"
    description: str = ""
    points: Optional[int] = None
    retired: bool = False
    solved: bool = False
    locked: bool = False
    has_download: bool = False
    needs_instance: bool = False
    download_url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def slug(self) -> str:
        return f"{self.id}-{slugify(self.name)}"

    @property
    def available(self) -> bool:
        """Accessible to this account right now (not locked)."""
        return not self.locked

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)  # raw can be large / noisy in reports
        return d


@dataclass
class SpawnInfo:
    """Details of a spawned challenge instance/target."""

    challenge_id: int
    status: str = "unknown"
    ip: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    url: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def target(self) -> Optional[str]:
        if self.url:
            return self.url
        if self.host or self.ip:
            base = self.host or self.ip
            return f"{base}:{self.port}" if self.port else base
        return None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        d["target"] = self.target
        return d


@dataclass
class ChallengeAttempt:
    """The full record of what happened for one challenge in a run."""

    challenge: Challenge
    started: bool = False
    spawn: Optional[SpawnInfo] = None
    downloaded_files: List[str] = field(default_factory=list)
    work_dir: Optional[str] = None
    solver_status: Optional[str] = None
    solver_steps: List[str] = field(default_factory=list)
    candidate_flags: List[str] = field(default_factory=list)
    submitted: bool = False
    submission_result: Optional[str] = None
    dry_run: bool = False
    error: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge": self.challenge.to_dict(),
            "started": self.started,
            "spawn": self.spawn.to_dict() if self.spawn else None,
            "downloaded_files": self.downloaded_files,
            "work_dir": self.work_dir,
            "solver_status": self.solver_status,
            "solver_steps": self.solver_steps,
            "candidate_flags": self.candidate_flags,
            "submitted": self.submitted,
            "submission_result": self.submission_result,
            "dry_run": self.dry_run,
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class RunReport:
    """Top-level report for a whole run."""

    timestamp: str
    user: Dict[str, Any] = field(default_factory=dict)
    filters: Dict[str, Any] = field(default_factory=dict)
    dry_run: bool = True
    submit_enabled: bool = False
    attempts: List[ChallengeAttempt] = field(default_factory=list)
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "user": self.user,
            "filters": self.filters,
            "dry_run": self.dry_run,
            "submit_enabled": self.submit_enabled,
            "attempts": [a.to_dict() for a in self.attempts],
            "duration_seconds": round(self.duration_seconds, 2),
            "errors": self.errors,
        }
