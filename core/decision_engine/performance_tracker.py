"""
SQLite-backed agent performance tracker.

Records per-agent outcomes (solved / failed / attempted) broken down by
challenge category, and exposes queries so the coordinator can bias its
initial routing toward agents that have historically succeeded.
"""

import sqlite3
import os
import time
from typing import Dict, List, Optional, Tuple


_DB_PATH = "logs/performance.db"


class PerformanceTracker:
    """
    Tracks agent success rates across challenge categories.

    Data is persisted to a local SQLite database so history survives
    between runs.  All public methods are thread-safe via per-call
    connections.
    """

    def __init__(self, db_path: str = _DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS outcomes (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id       TEXT    NOT NULL,
                    category       TEXT    NOT NULL,
                    challenge_id   TEXT    NOT NULL,
                    status         TEXT    NOT NULL,
                    duration_sec   REAL,
                    recorded_at    REAL    NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent    ON outcomes(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON outcomes(category)")

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record_outcome(
        self,
        agent_id: str,
        category: str,
        challenge_id: str,
        status: str,
        duration_sec: Optional[float] = None,
    ) -> None:
        """
        Persist one agent outcome.

        Args:
            agent_id:     e.g. "crypto_agent"
            category:     e.g. "crypto", "web", "forensics"
            challenge_id: unique challenge identifier
            status:       "solved", "failed", or "attempted"
            duration_sec: wall-clock seconds the agent ran, if known
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO outcomes (agent_id, category, challenge_id, status, duration_sec, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, category, challenge_id, status, duration_sec, time.time()),
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_success_rate(
        self, agent_id: str, category: Optional[str] = None
    ) -> float:
        """
        Return the fraction of runs where the agent produced "solved".

        Returns 0.0 when there is no history for the given filters.
        """
        query = "SELECT status FROM outcomes WHERE agent_id = ?"
        params: List = [agent_id]
        if category:
            query += " AND category = ?"
            params.append(category)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        if not rows:
            return 0.0
        solved = sum(1 for (s,) in rows if s == "solved")
        return solved / len(rows)

    def get_best_agent_for(self, category: str, min_runs: int = 2) -> Optional[str]:
        """
        Return the agent_id with the highest solve rate for *category*.

        Agents with fewer than *min_runs* total attempts are excluded to
        avoid recommending an agent based on a single lucky solve.

        Returns None when no agent meets the threshold.
        """
        query = """
            SELECT
                agent_id,
                SUM(CASE WHEN status = 'solved' THEN 1 ELSE 0 END) AS wins,
                COUNT(*) AS total
            FROM outcomes
            WHERE category = ?
            GROUP BY agent_id
            HAVING total >= ?
            ORDER BY CAST(wins AS REAL) / total DESC
            LIMIT 1
        """
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(query, (category, min_runs)).fetchone()

        return row[0] if row else None

    def get_stats(
        self,
        agent_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict]:
        """
        Return per-agent-per-category aggregate stats.

        Each dict has keys: agent_id, category, total, solved, failed,
        attempted, success_rate, avg_duration_sec.
        """
        clauses = []
        params: List = []
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if category:
            clauses.append("category = ?")
            params.append(category)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"""
            SELECT
                agent_id,
                category,
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'solved'    THEN 1 ELSE 0 END) AS solved,
                SUM(CASE WHEN status = 'failed'    THEN 1 ELSE 0 END) AS failed,
                SUM(CASE WHEN status = 'attempted' THEN 1 ELSE 0 END) AS attempted,
                AVG(duration_sec) AS avg_duration_sec
            FROM outcomes
            {where}
            GROUP BY agent_id, category
            ORDER BY agent_id, category
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            {
                "agent_id": r[0],
                "category": r[1],
                "total": r[2],
                "solved": r[3],
                "failed": r[4],
                "attempted": r[5],
                "success_rate": round(r[3] / r[2], 3) if r[2] else 0.0,
                "avg_duration_sec": round(r[6], 2) if r[6] is not None else None,
            }
            for r in rows
        ]

    def get_routing_hint(self, category: str) -> Optional[Tuple[str, float]]:
        """
        Return (agent_id, success_rate) for the best known agent for *category*,
        or None if there is insufficient history.

        Intended for use by the coordinator to augment LLM routing decisions.
        """
        best = self.get_best_agent_for(category)
        if best is None:
            return None
        rate = self.get_success_rate(best, category)
        return (best, rate)
