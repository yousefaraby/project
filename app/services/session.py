"""In-memory session store (stands in for Redis).

Sessions are keyed by session_id (falls back to user_id when no session_id is given).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Session(BaseModel):
    user_id: str
    session_id: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)
    open_incident_id: str | None = None
    last_findings: dict[str, Any] = Field(default_factory=dict)
    last_outcome: str | None = None

    @property
    def key(self) -> str:
        return self.session_id or self.user_id


class SessionStore:
    def __init__(self) -> None:
        self._data: dict[str, Session] = {}

    def peek(self, key: str) -> Session | None:
        s = self._data.get(key)
        return s.model_copy(deep=True) if s else None

    def get(self, key: str, user_id: str | None = None) -> Session:
        """Returns a copy (new session if absent); call save() to persist changes."""
        s = self._data.get(key)
        if s:
            return s.model_copy(deep=True)
        return Session(user_id=user_id or key, session_id=key if user_id else None)

    def save(self, session: Session) -> None:
        self._data[session.key] = session.model_copy(deep=True)

    def append_history(self, key: str, role: str, text: str) -> Session:
        s = self.get(key)
        s.history.append({"ts": datetime.now(timezone.utc).isoformat(), "role": role, "text": text})
        self.save(s)
        return s

    def set_open_incident(self, key: str, incident_id: str | None) -> Session:
        s = self.get(key)
        s.open_incident_id = incident_id
        self.save(s)
        return s

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


sessions = SessionStore()
