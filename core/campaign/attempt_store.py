"""SQLite persistence for campaign runs, including unsuccessful techniques."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

from core.utils.security import redact_sensitive_data


class AttemptStore:
    """Record challenge runs and their individual agent/tool attempts."""

    def __init__(self, db_path: str = "logs/attempts.db"):
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    configuration TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS challenge_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    category TEXT,
                    status TEXT NOT NULL,
                    failure_reason TEXT,
                    duration_sec REAL,
                    iterations INTEGER,
                    flag_sha256 TEXT,
                    started_at REAL NOT NULL,
                    finished_at REAL NOT NULL,
                    result_summary TEXT NOT NULL,
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(id)
                );
                CREATE TABLE IF NOT EXISTS technique_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_attempt_id INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    actor TEXT,
                    technique TEXT,
                    target TEXT,
                    status TEXT NOT NULL,
                    observation TEXT,
                    failure_reason TEXT,
                    artifact_keys TEXT NOT NULL,
                    FOREIGN KEY(challenge_attempt_id) REFERENCES challenge_attempts(id)
                );
                CREATE INDEX IF NOT EXISTS idx_attempt_challenge
                    ON challenge_attempts(provider, challenge_id);
                CREATE INDEX IF NOT EXISTS idx_technique_challenge_attempt
                    ON technique_attempts(challenge_attempt_id);
                """
            )

    def start_campaign(self, provider: str, configuration: Dict[str, Any]) -> str:
        campaign_id = uuid.uuid4().hex
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO campaigns (id, provider, started_at, configuration) VALUES (?, ?, ?, ?)",
                (campaign_id, provider, time.time(), json.dumps(configuration, sort_keys=True)),
            )
        return campaign_id

    def finish_campaign(self, campaign_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE campaigns SET finished_at = ? WHERE id = ?", (time.time(), campaign_id))

    def record_attempt(
        self,
        campaign_id: str,
        provider: str,
        challenge: Dict[str, Any],
        result: Dict[str, Any],
        started_at: float,
        finished_at: Optional[float] = None,
    ) -> int:
        import hashlib

        finished_at = finished_at or time.time()
        flag = result.get("flag")
        safe_result = redact_sensitive_data(result)
        status = str(safe_result.get("status") or "failed")
        failure_reason = self._failure_reason(safe_result) if status != "solved" else None
        summary = {
            "agent_id": safe_result.get("agent_id"),
            "status": status,
            "steps": list(safe_result.get("steps") or [])[-20:],
            "history_count": len(safe_result.get("history") or []),
        }
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO challenge_attempts (
                    campaign_id, provider, challenge_id, category, status,
                    failure_reason, duration_sec, iterations, flag_sha256,
                    started_at, finished_at, result_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    campaign_id,
                    provider,
                    str(challenge.get("id", "unknown")),
                    challenge.get("category"),
                    status,
                    failure_reason,
                    max(0.0, finished_at - started_at),
                    int(safe_result.get("iterations") or 0),
                    hashlib.sha256(str(flag).encode()).hexdigest() if flag else None,
                    started_at,
                    finished_at,
                    json.dumps(summary, sort_keys=True, default=str),
                ),
            )
            attempt_id = int(cursor.lastrowid)
            for sequence, entry in enumerate(safe_result.get("history") or []):
                routing = entry.get("routing") or {}
                actor = entry.get("agent_id") or routing.get("selected_target")
                entry_status = str(entry.get("status") or "attempted")
                conn.execute(
                    """
                    INSERT INTO technique_attempts (
                        challenge_attempt_id, sequence, actor, technique, target,
                        status, observation, failure_reason, artifact_keys
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        sequence,
                        actor,
                        routing.get("execution_type") or entry.get("technique") or "agent_run",
                        routing.get("selected_target") or actor,
                        entry_status,
                        self._observation(entry),
                        self._failure_reason(entry) if entry_status != "solved" else None,
                        json.dumps(sorted((entry.get("artifacts") or {}).keys())),
                    ),
                )
        return attempt_id

    def attempt_count(self, provider: str, challenge_id: str) -> int:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM challenge_attempts WHERE provider = ? AND challenge_id = ?",
                (provider, challenge_id),
            ).fetchone()
        return int(row[0])

    def is_solved(self, provider: str, challenge_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """SELECT 1 FROM challenge_attempts
                   WHERE provider = ? AND challenge_id = ? AND status = 'solved' LIMIT 1""",
                (provider, challenge_id),
            ).fetchone()
        return row is not None

    def recent_failures(self, provider: str, challenge_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT status, failure_reason, duration_sec, iterations, finished_at
                   FROM challenge_attempts
                   WHERE provider = ? AND challenge_id = ? AND status != 'solved'
                   ORDER BY finished_at DESC LIMIT ?""",
                (provider, challenge_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _failure_reason(result: Dict[str, Any]) -> Optional[str]:
        for key in ("error", "failure_reason", "reason"):
            if result.get(key):
                return str(result[key])[:2000]
        steps = result.get("steps") or []
        return str(steps[-1])[:2000] if steps else None

    @staticmethod
    def _observation(entry: Dict[str, Any]) -> Optional[str]:
        for key in ("observation", "message", "result", "reasoning"):
            value = entry.get(key)
            if value:
                return str(value)[:4000]
        steps = entry.get("steps") or []
        return str(steps[-1])[:4000] if steps else None
