"""
SQLite-backed event log for durable, replayable Cyber-CoPilot sessions.

The log is intentionally append-first: conversations, tool calls, decisions,
findings, and long-running jobs can be reconstructed without trusting lossy
conversation trimming.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger


MAX_PAYLOAD_CHARS = 120_000
MAX_FIELD_CHARS = 40_000


def _now() -> str:
    return datetime.now().isoformat()


def _text_safe(value: Any) -> str:
    return str(value or "").encode("utf-8", "backslashreplace").decode("utf-8")


def _json_safe(value: Any) -> Any:
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, dict):
        return {_text_safe(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, str):
        if len(value) > MAX_FIELD_CHARS:
            value = value[:MAX_FIELD_CHARS] + "\n...[event-field-truncated]"
        return _text_safe(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _text_safe(value)


def _dumps(payload: dict[str, Any]) -> str:
    text = json.dumps(_json_safe(payload or {}), ensure_ascii=False, sort_keys=True)
    if len(text) > MAX_PAYLOAD_CHARS:
        text = text[:MAX_PAYLOAD_CHARS] + "\n...[event-payload-truncated]"
    return text


def _session_context(target: str = "", session_dir: str | Path | None = None) -> tuple[str, str, Path]:
    resolved_target = target or ""
    resolved_session = ""

    if session_dir:
        path = Path(session_dir)
        resolved_session = path.name
        return resolved_target, resolved_session, path / "events.sqlite"

    try:
        from src.repl.target_manager import get_target_manager

        manager = get_target_manager()
        if getattr(manager, "current_target", None):
            resolved_target = resolved_target or str(manager.current_target)
        if getattr(manager, "session_dir", None):
            session_path = Path(manager.session_dir)
            resolved_session = session_path.name
            return resolved_target, resolved_session, session_path / "events.sqlite"
    except Exception:
        pass

    safe_target = (resolved_target or "global").replace("://", "_").replace("/", "_").replace(":", "_")
    path = Path("./targets") / safe_target / "events.sqlite" if resolved_target else Path("./.memory") / "events.sqlite"
    return resolved_target, resolved_session, path


class EventLog:
    """Durable SQLite event store for one active session or target."""

    def __init__(self, db_path: str | Path, target: str = "", session_id: str = "") -> None:
        self.db_path = Path(db_path)
        self.target = target or ""
        self.session_id = session_id or ""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    agent TEXT NOT NULL DEFAULT '',
                    tool TEXT NOT NULL DEFAULT '',
                    correlation_id TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_events_target_session
                ON events(target, session_id, id)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS long_tasks (
                    task_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT '',
                    command TEXT NOT NULL,
                    tmux_session TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL DEFAULT '',
                    last_event_id INTEGER,
                    last_output TEXT NOT NULL DEFAULT ''
                )
                """
            )

    def record(
        self,
        event_type: str,
        *,
        target: str = "",
        session_id: str = "",
        agent: str = "",
        tool: str = "",
        correlation_id: str = "",
        payload: Optional[dict[str, Any]] = None,
    ) -> int:
        """Append an immutable event and return its id."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO events(ts, event_type, target, session_id, agent, tool, correlation_id, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now(),
                    _text_safe(event_type),
                    _text_safe(target or self.target),
                    _text_safe(session_id or self.session_id),
                    _text_safe(agent),
                    _text_safe(tool),
                    _text_safe(correlation_id),
                    _dumps(payload or {}),
                ),
            )
            return int(cur.lastrowid)

    def upsert_long_task(
        self,
        *,
        task_id: str,
        command: str,
        tmux_session: str,
        status: str,
        target: str = "",
        session_id: str = "",
        last_event_id: int | None = None,
        last_output: str = "",
    ) -> None:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO long_tasks(
                    task_id, target, session_id, command, tmux_session, status,
                    started_at, updated_at, completed_at, last_event_id, last_output
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    completed_at=CASE WHEN excluded.status IN ('completed', 'failed', 'stopped')
                        THEN excluded.updated_at ELSE long_tasks.completed_at END,
                    last_event_id=excluded.last_event_id,
                    last_output=excluded.last_output
                """,
                (
                    _text_safe(task_id),
                    _text_safe(target or self.target),
                    _text_safe(session_id or self.session_id),
                    _text_safe(command),
                    _text_safe(tmux_session),
                    _text_safe(status),
                    now,
                    now,
                    last_event_id,
                    _json_safe(last_output),
                ),
            )

    def update_long_task(self, task_id: str, status: str, last_output: str = "", last_event_id: int | None = None) -> None:
        now = _now()
        completed_at = now if status in {"completed", "failed", "stopped"} else ""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE long_tasks
                SET status=?, updated_at=?, completed_at=COALESCE(NULLIF(?, ''), completed_at),
                    last_output=CASE WHEN ? != '' THEN ? ELSE last_output END,
                    last_event_id=COALESCE(?, last_event_id)
                WHERE task_id=?
                """,
                (
                    _text_safe(status),
                    now,
                    completed_at,
                    _text_safe(last_output),
                    _json_safe(last_output),
                    last_event_id,
                    _text_safe(task_id),
                ),
            )

    def list_long_tasks(self, status: str = "", limit: int = 20) -> list[dict[str, Any]]:
        query = "SELECT * FROM long_tasks"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(_text_safe(status))
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(max(1, min(int(limit or 20), 200)))
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit or 50), 500)),),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            try:
                item["payload"] = json.loads(item.pop("payload_json") or "{}")
            except Exception:
                item["payload"] = {}
            out.append(item)
        return out


def get_event_log(target: str = "", session_dir: str | Path | None = None) -> EventLog:
    """Resolve the active session/target database and return an EventLog."""
    resolved_target, session_id, db_path = _session_context(target=target, session_dir=session_dir)
    try:
        return EventLog(db_path=db_path, target=resolved_target, session_id=session_id)
    except Exception as exc:
        logger.debug(f"Failed to open event log at {db_path}: {exc}")
        fallback = Path("./.memory") / "events.sqlite"
        return EventLog(db_path=fallback, target=resolved_target, session_id=session_id)
