"""Read-only access to JSON fixtures."""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from typing import Any

from app.config import FIXTURES_DIR
from app.controls import controls


@lru_cache(maxsize=1)
def _users() -> dict[str, dict[str, Any]]:
    raw = json.loads((FIXTURES_DIR / "users.json").read_text(encoding="utf-8"))
    return {u["user_id"]: u for u in raw["employees"]}


@lru_cache(maxsize=1)
def _kb() -> list[dict[str, Any]]:
    raw = json.loads((FIXTURES_DIR / "kb.json").read_text(encoding="utf-8"))
    return raw["articles"]


def get_user(user_id: str) -> dict[str, Any] | None:
    u = _users().get(user_id)
    return copy.deepcopy(u) if u else None


def list_user_ids() -> list[str]:
    return sorted(_users())


def get_kb_articles() -> list[dict[str, Any]]:
    return copy.deepcopy(_kb())


def fixture_tool_override(user_id: str | None, tool: str) -> str | None:
    if not user_id:
        return None
    u = _users().get(user_id) or {}
    return (u.get("mock") or {}).get("tool_overrides", {}).get(tool)


def troubleshooter_behavior(user_id: str) -> str:
    """Runtime override wins; otherwise fixture value; default 'ok'."""
    if controls.troubleshooter_behavior:
        return controls.troubleshooter_behavior
    u = _users().get(user_id) or {}
    return (u.get("mock") or {}).get("troubleshooter_behavior", "ok")
