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

from core.utils.category_utils import normalize_category


_DB_PATH = "logs/performance.db"


def _wilson_lower_bound(wins: int, total: int, z: float = 1.96) -> float:
    """Lower bound of the Wilson score interval for a binomial success rate.

    Rewards both a high solve rate and a large sample, so a 500/538 agent
    outranks a 2/2 one instead of losing on raw rate alone.
    """
    if total <= 0:
        return 0.0
    import math

    phat = wins / total
    denom = 1 + z * z / total
    center = phat + z * z / (2 * total)
    margin = z * math.sqrt((phat * (1 - phat) + z * z / (4 * total)) / total)
    return (center - margin) / denom


class PerformanceTracker:
    """
    Tracks agent success rates across challenge categories.

    Data is persisted to a local SQLite database so history survives
    between runs.  All public methods are thread-safe via per-call
    connections.
    """

    def __init__(self, db_path: Optional[str] = None):
        # Env override lets tests (and multi-run operators) isolate persistent
        # state instead of sharing one repo-relative DB across every run.
        db_path = db_path or os.getenv("CTF_AGENTS_PERFORMANCE_DB") or _DB_PATH
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
                (agent_id, normalize_category(category), challenge_id, status, duration_sec, time.time()),
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
            params.append(normalize_category(category))

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        if not rows:
            return 0.0
        solved = sum(1 for (s,) in rows if s == "solved")
        return solved / len(rows)

    def get_best_agent_for(self, category: str, min_runs: int = 2) -> Optional[str]:
        """
        Return the specialist agent with the best solve record for *category*.

        Only true specialist agents (ids ending in ``_agent``) are eligible to be
        recommended as a *primary* route. This deliberately excludes narrow tool
        routes such as ``tony_htb_sql`` or ``browser_snapshot`` — which post very
        high category solve rates only because they are run exclusively on the
        challenges they suit (selection bias) — and also filters mock/test agents
        (``agent_1``…) that can leak into a shared DB. Ranking uses the Wilson
        lower bound so a proven high-volume agent is not beaten by an agent with
        one or two lucky solves.

        Agents with fewer than *min_runs* attempts are excluded. Returns None
        when no eligible agent meets the threshold.
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
        """
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, (normalize_category(category), min_runs)).fetchall()

        best_agent: Optional[str] = None
        best_score = -1.0
        for agent_id, wins, total in rows:
            if not str(agent_id).endswith("_agent"):
                continue
            score = _wilson_lower_bound(int(wins), int(total))
            if score > best_score:
                best_agent, best_score = agent_id, score
        return best_agent

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
            params.append(normalize_category(category))

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
