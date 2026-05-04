"""
SQLite-backed persistent knowledge store for the CTF Agent system.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union


class KnowledgeStore:
    """
    Persistent store for facts and intelligence gathered by agents.
    """

    def __init__(self, db_path: str = "logs/knowledge.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id TEXT,
                    agent_id TEXT,
                    key TEXT,
                    value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge ON knowledge(challenge_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key ON knowledge(key)")

    def add_fact(self, challenge_id: str, agent_id: str, key: str, value: Any, metadata: Optional[Dict[str, Any]] = None):
        """Store a new fact."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO knowledge (challenge_id, agent_id, key, value, metadata) VALUES (?, ?, ?, ?, ?)",
                (challenge_id, agent_id, key, json.dumps(value), json.dumps(metadata or {}))
            )

    def get_facts(self, challenge_id: Optional[str] = None, key: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve facts, optionally filtered by challenge or key."""
        query = "SELECT challenge_id, agent_id, key, value, timestamp, metadata FROM knowledge WHERE 1=1"
        params = []
        
        if challenge_id:
            query += " AND challenge_id = ?"
            params.append(challenge_id)
        if key:
            query += " AND key = ?"
            params.append(key)
            
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, params)
            return [
                {
                    "challenge_id": r[0],
                    "agent_id": r[1],
                    "key": r[2],
                    "value": json.loads(r[3]),
                    "timestamp": r[4],
                    "metadata": json.loads(r[5])
                }
                for r in cursor.fetchall()
            ]

    def find_latest_fact(self, challenge_id: str, key: str) -> Optional[Dict[str, Any]]:
        """Get the most recent fact for a given key in a challenge."""
        query = "SELECT challenge_id, agent_id, key, value, timestamp, metadata FROM knowledge WHERE challenge_id = ? AND key = ? ORDER BY timestamp DESC, id DESC LIMIT 1"
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(query, (challenge_id, key))
            row = cursor.fetchone()
            if row:
                return {
                    "challenge_id": row[0],
                    "agent_id": row[1],
                    "key": row[2],
                    "value": json.loads(row[3]),
                    "timestamp": row[4],
                    "metadata": json.loads(row[5])
                }
        return None
