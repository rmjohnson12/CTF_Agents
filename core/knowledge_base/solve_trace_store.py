"""
SQLite-backed store for compact solved-challenge traces.

This is intentionally not a flag cache.  It records structured signals about
what worked, plus a hash and prefix of the flag, so future retrieval/training
can learn patterns without replaying answers verbatim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.utils.category_utils import normalize_category


_DB_PATH = "logs/solve_traces.db"
_FLAG_PREFIX_RE = re.compile(r"^([A-Za-z0-9_-]+)\{")


class SolveTraceStore:
    """Persist compact solved-challenge traces for later retrieval/training."""

    def __init__(self, db_path: Optional[str] = None):
        # Env override lets tests (and multi-run operators) isolate persistent
        # state instead of sharing one repo-relative DB across every run.
        db_path = db_path or os.getenv("CTF_AGENTS_SOLVE_TRACE_DB") or _DB_PATH
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS solve_traces (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id       TEXT    NOT NULL,
                    category           TEXT,
                    status             TEXT    NOT NULL,
                    solved             INTEGER NOT NULL,
                    flag_prefix        TEXT,
                    flag_sha256        TEXT    NOT NULL,
                    flag_length        INTEGER,
                    successful_agent   TEXT,
                    successful_target  TEXT,
                    route_signature    TEXT,
                    indicators         TEXT,
                    artifact_keys      TEXT,
                    techniques         TEXT    NOT NULL DEFAULT '[]',
                    step_count         INTEGER,
                    iterations         INTEGER,
                    recorded_at        REAL    NOT NULL,
                    UNIQUE(challenge_id, flag_sha256)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_solve_category ON solve_traces(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_solve_agent ON solve_traces(successful_agent)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_solve_recorded ON solve_traces(recorded_at)")
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(solve_traces)")
            }
            if "techniques" not in columns:
                conn.execute(
                    "ALTER TABLE solve_traces ADD COLUMN techniques TEXT NOT NULL DEFAULT '[]'"
                )

    def record_solve(self, challenge: Dict[str, Any], result: Dict[str, Any]) -> Optional[int]:
        """Record a solved run and return the row id, or None for unsolved runs."""
        flag = result.get("flag")
        if not flag or result.get("status") != "solved":
            return None

        flag_text = str(flag)
        history = result.get("history") or []
        solved_entry = self._solved_history_entry(history, result)
        route_signature = self._route_signature(history)
        artifact_keys = self._artifact_keys(history, result)
        techniques = self._techniques(history, result)
        indicators = self._challenge_indicators(challenge)
        routing = solved_entry.get("routing") or {}
        successful_agent = solved_entry.get("agent_id") or result.get("agent_id")
        successful_target = routing.get("selected_target") or successful_agent

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO solve_traces (
                    challenge_id,
                    category,
                    status,
                    solved,
                    flag_prefix,
                    flag_sha256,
                    flag_length,
                    successful_agent,
                    successful_target,
                    route_signature,
                    indicators,
                    artifact_keys,
                    techniques,
                    step_count,
                    iterations,
                    recorded_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(challenge.get("id", result.get("challenge_id", "unknown"))),
                    normalize_category(challenge.get("category", "misc")),
                    str(result.get("status", "solved")),
                    1,
                    self._flag_prefix(flag_text),
                    hashlib.sha256(flag_text.encode("utf-8")).hexdigest(),
                    len(flag_text),
                    successful_agent,
                    successful_target,
                    route_signature,
                    json.dumps(indicators, sort_keys=True),
                    json.dumps(artifact_keys, sort_keys=True),
                    json.dumps(techniques, sort_keys=True),
                    len(result.get("steps") or []),
                    int(result.get("iterations") or 0),
                    time.time(),
                ),
            )
            return int(cursor.lastrowid)

    def get_recent_solves(
        self,
        category: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return recent solved traces, newest first."""
        query = """
            SELECT
                challenge_id,
                category,
                status,
                solved,
                flag_prefix,
                flag_sha256,
                flag_length,
                successful_agent,
                successful_target,
                route_signature,
                indicators,
                artifact_keys,
                techniques,
                step_count,
                iterations,
                recorded_at
            FROM solve_traces
            WHERE solved = 1
        """
        params: List[Any] = []
        if category:
            query += " AND category = ?"
            params.append(normalize_category(category))
        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def get_successful_patterns(
        self,
        category: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Return compact routing patterns that have solved past challenges."""
        return [
            {
                "category": row["category"],
                "successful_agent": row["successful_agent"],
                "successful_target": row["successful_target"],
                "route_signature": row["route_signature"],
                "indicators": row["indicators"],
                "artifact_keys": row["artifact_keys"],
                "techniques": row["techniques"],
            }
            for row in self.get_recent_solves(category=category, limit=limit)
        ]

    def find_by_techniques(
        self,
        techniques: List[str],
        *,
        category: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Retrieve prior solved routes sharing runtime-observed techniques."""
        wanted = {str(item) for item in techniques if item}
        if not wanted:
            return []
        matches = []
        for row in self.get_recent_solves(category=category, limit=200):
            shared = sorted(wanted & set(row.get("techniques") or []))
            if not shared:
                continue
            matches.append({
                "challenge_id": row["challenge_id"],
                "successful_target": row["successful_target"],
                "route_signature": row["route_signature"],
                "shared_techniques": shared,
                "techniques": row["techniques"],
                "recorded_at": row["recorded_at"],
            })
        return matches[:limit]

    def find_similar_patterns(
        self,
        challenge: Dict[str, Any],
        limit: int = 5,
        min_score: int = 4,
    ) -> List[Dict[str, Any]]:
        """Return solved traces whose structured indicators resemble a challenge."""
        current_indicators = set(self._challenge_indicators(challenge))
        if not current_indicators:
            return []

        category = normalize_category(challenge.get("category")) if challenge.get("category") else ""
        candidates = self.get_recent_solves(category=category or None, limit=100)
        if len(candidates) < limit:
            seen_ids = {row["challenge_id"] for row in candidates}
            candidates.extend(
                row for row in self.get_recent_solves(limit=100)
                if row["challenge_id"] not in seen_ids
            )

        scored: List[Dict[str, Any]] = []
        for row in candidates:
            row_indicators = set(row.get("indicators") or [])
            shared = sorted(current_indicators & row_indicators)
            if not shared:
                continue
            if not any(not indicator.startswith("category:") for indicator in shared):
                continue

            score = self._similarity_score(category, row, shared)
            if score < min_score:
                continue

            scored.append({
                "challenge_id": row["challenge_id"],
                "category": row["category"],
                "successful_agent": row["successful_agent"],
                "successful_target": row["successful_target"],
                "route_signature": row["route_signature"],
                "artifact_keys": row["artifact_keys"],
                "techniques": row["techniques"],
                "shared_indicators": shared,
                "similarity_score": score,
                "recorded_at": row["recorded_at"],
            })

        scored.sort(key=lambda row: (row["similarity_score"], row["recorded_at"]), reverse=True)
        return scored[:limit]

    @staticmethod
    def _similarity_score(
        category: str,
        row: Dict[str, Any],
        shared_indicators: List[str],
    ) -> int:
        score = 0
        if category and row.get("category") == category:
            score += 3

        weights = {
            "category:": 3,
            "keyword:": 3,
            "file_ext:": 2,
            "url_scheme:": 1,
            "url_host:": 1,
        }
        for indicator in shared_indicators:
            score += next(
                (weight for prefix, weight in weights.items() if indicator.startswith(prefix)),
                1,
            )
        return score

    @staticmethod
    def _solved_history_entry(
        history: List[Dict[str, Any]],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        for entry in reversed(history):
            if entry.get("flag") or entry.get("status") == "solved":
                return entry
        return result

    @staticmethod
    def _route_signature(history: List[Dict[str, Any]]) -> str:
        parts = []
        for entry in history:
            routing = entry.get("routing") or {}
            execution_type = routing.get("execution_type") or "unknown"
            target = routing.get("selected_target") or entry.get("agent_id") or "unknown"
            status = entry.get("status") or "unknown"
            parts.append(f"{execution_type}:{target}:{status}")
        return " > ".join(parts)

    @staticmethod
    def _artifact_keys(history: List[Dict[str, Any]], result: Dict[str, Any]) -> List[str]:
        keys = set()
        for entry in [*history, result]:
            artifacts = entry.get("artifacts") or {}
            if isinstance(artifacts, dict):
                keys.update(str(key) for key in artifacts.keys())
        return sorted(keys)

    @staticmethod
    def _techniques(history: List[Dict[str, Any]], result: Dict[str, Any]) -> List[str]:
        techniques = set()
        # Category-agnostic noise that carries no learning value as a technique.
        noise = {"general_web", "unknown", "none", "", "misc"}

        def visit(value: Any, parent_key: str = "") -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    visit(item, str(key).lower())
            elif isinstance(value, (list, tuple, set)):
                for item in value:
                    visit(item, parent_key)
            elif parent_key in {"technique", "techniques"} and value:
                if str(value).lower() not in noise:
                    techniques.add(str(value))

        for entry in [*history, result]:
            # 1) technique/techniques keys nested anywhere in the artifacts tree.
            visit(entry.get("artifacts") or {})
            # 2) explicit technique / vulnerability-class lists at the entry level,
            #    so every specialist that reports what it used feeds the learner.
            for key in ("techniques", "vulnerabilities_found", "detected_vulnerabilities", "vulnerabilities"):
                value = entry.get(key)
                if isinstance(value, (list, tuple, set)):
                    for item in value:
                        if item and str(item).lower() not in noise:
                            techniques.add(str(item))
        return sorted(techniques)

    @staticmethod
    def _challenge_indicators(challenge: Dict[str, Any]) -> List[str]:
        indicators = set()
        category = challenge.get("category")
        if category:
            indicators.add(f"category:{normalize_category(category)}")

        url = challenge.get("url") or challenge.get("target", {}).get("url")
        if url:
            parsed = urlparse(str(url))
            if parsed.scheme:
                indicators.add(f"url_scheme:{parsed.scheme}")
            if parsed.hostname:
                indicators.add(f"url_host:{parsed.hostname}")

        for raw_path in challenge.get("files") or []:
            suffix = Path(str(raw_path)).suffix.lower()
            if suffix:
                indicators.add(f"file_ext:{suffix}")

        description = str(challenge.get("description") or "").lower()
        keyword_aliases = {
            "jwt": ("jwt",),
            "sql": ("sql",),
            "cookie": ("cookie",),
            "godot": ("godot",),
            "pck": ("pck",),
            "binary": ("binary",),
            "overflow": ("overflow",),
            "pwn": ("pwn",),
            "ret2libc": ("ret2libc",),
            "libc": ("libc",),
            "stl": ("stl",),
            "matrix": ("matrix", "matrices"),
            "blockchain": ("blockchain",),
            "secure_coding": ("secure coding", "secure-coding"),
        }
        for canonical, aliases in keyword_aliases.items():
            if any(alias in description for alias in aliases):
                indicators.add(f"keyword:{canonical}")

        return sorted(indicators)

    @staticmethod
    def _flag_prefix(flag: str) -> Optional[str]:
        match = _FLAG_PREFIX_RE.match(flag)
        if match:
            return match.group(1)
        # Unwrapped answers are frequently passwords. Storing even a short
        # plaintext prefix can disclose the complete answer.
        return None

    @staticmethod
    def _row_to_dict(row: Any) -> Dict[str, Any]:
        return {
            "challenge_id": row[0],
            "category": row[1],
            "status": row[2],
            "solved": bool(row[3]),
            "flag_prefix": row[4],
            "flag_sha256": row[5],
            "flag_length": row[6],
            "successful_agent": row[7],
            "successful_target": row[8],
            "route_signature": row[9],
            "indicators": json.loads(row[10] or "[]"),
            "artifact_keys": json.loads(row[11] or "[]"),
            "techniques": json.loads(row[12] or "[]"),
            "step_count": row[13],
            "iterations": row[14],
            "recorded_at": row[15],
        }
