"""Durable SQLite implementation of :class:`services.sequence.state.StateStore`."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .errors import StateCorruptionError
from .state import ScopeState


class SQLiteStateStore:
    """Thread-safe SQLite-backed per-scope state store."""

    def __init__(self, db_path: Path | str) -> None:
        self._raw_path = str(db_path)
        if self._raw_path != ":memory:":
            Path(self._raw_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._raw_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sequence_scope_state (
                scope_key TEXT PRIMARY KEY,
                model_version TEXT NOT NULL,
                state_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, scope_key: str) -> ScopeState | None:
        """Load and deserialize the retained ``ScopeState`` for ``scope_key``."""
        with self._lock:
            row = self._conn.execute(
                "SELECT state_json FROM sequence_scope_state WHERE scope_key = ?",
                (scope_key,),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(row[0])
        except json.JSONDecodeError as exc:
            raise StateCorruptionError(
                f"corrupted JSON state for scope {scope_key!r}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise StateCorruptionError(
                f"corrupted state payload for scope {scope_key!r}: expected JSON object"
            )
        return ScopeState.from_dict(payload)

    def put(self, state: ScopeState) -> None:
        """Persist ``state`` atomically by ``state.scope_key``."""
        serialized = json.dumps(state.to_dict(), separators=(",", ":"))
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sequence_scope_state (scope_key, model_version, state_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(scope_key) DO UPDATE SET
                    model_version = excluded.model_version,
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (state.scope_key, state.model_version, serialized, updated_at),
            )
            self._conn.commit()

    def delete(self, scope_key: str) -> None:
        """Remove persisted state for ``scope_key``."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM sequence_scope_state WHERE scope_key = ?",
                (scope_key,),
            )
            self._conn.commit()

    def scope_keys(self) -> Iterable[str]:
        """List all persisted scope keys in deterministic order."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT scope_key FROM sequence_scope_state ORDER BY scope_key ASC"
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()

