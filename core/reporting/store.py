"""SQLite persistence for chronological live-reporting events."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import List, Optional

from core.reporting.models import ProgressUpdate


DEFAULT_REPORTING_DB = "logs/reporting.db"


class ReportingStore:
    """Append-only timeline store, isolated from learning and benchmark data."""

    def __init__(self, db_path: str = DEFAULT_REPORTING_DB) -> None:
        self.db_path = db_path
        parent = Path(db_path).expanduser().parent
        if str(parent) not in {"", "."}:
            os.makedirs(parent, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS progress_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    challenge_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    step_title TEXT NOT NULL,
                    step_description TEXT NOT NULL,
                    confidence REAL,
                    elapsed_seconds REAL,
                    artifacts_json TEXT NOT NULL,
                    final_flag TEXT,
                    error_message TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_progress_run_time "
                "ON progress_updates(run_id, timestamp, id)"
            )

    def append(self, update: ProgressUpdate) -> int:
        """Persist one event and return its monotonically increasing row id."""
        data = update.model_dump(mode="json")
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO progress_updates (
                    event_id, challenge_id, run_id, timestamp, agent_name,
                    agent_type, status, step_title, step_description,
                    confidence, elapsed_seconds, artifacts_json, final_flag,
                    error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["event_id"], data["challenge_id"], data["run_id"],
                    data["timestamp"], data["agent_name"], data["agent_type"],
                    data["status"], data["step_title"], data["step_description"],
                    data["confidence"], data["elapsed_seconds"],
                    json.dumps(data["artifacts"], sort_keys=True),
                    data["final_flag"], data["error_message"],
                ),
            )
            return int(cursor.lastrowid)

    def timeline(
        self,
        run_id: str,
        *,
        after_id: int = 0,
        limit: int = 2000,
    ) -> List[dict]:
        """Return one run in timestamp order, with insertion id as a tiebreaker."""
        safe_limit = max(1, min(int(limit), 5000))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM progress_updates
                WHERE run_id = ? AND id > ?
                ORDER BY timestamp ASC, id ASC
                LIMIT ?
                """,
                (run_id, max(0, int(after_id)), safe_limit),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def latest_id(self, run_id: str) -> Optional[int]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(id) AS latest FROM progress_updates WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return int(row["latest"]) if row and row["latest"] is not None else None

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": int(row["id"]),
            "event_id": row["event_id"],
            "challenge_id": row["challenge_id"],
            "run_id": row["run_id"],
            "timestamp": row["timestamp"],
            "agent_name": row["agent_name"],
            "agent_type": row["agent_type"],
            "status": row["status"],
            "step_title": row["step_title"],
            "step_description": row["step_description"],
            "confidence": row["confidence"],
            "elapsed_seconds": row["elapsed_seconds"],
            "artifacts": json.loads(row["artifacts_json"] or "{}"),
            "final_flag": row["final_flag"],
            "error_message": row["error_message"],
        }
