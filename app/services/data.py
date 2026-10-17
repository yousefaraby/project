"""Global reset of all mock state."""
from __future__ import annotations

from typing import Callable

from app.config import alerts_path, outbox_path
from app.controls import controls
from app.services.audit import clear_audit
from app.services.itsm import itsm
from app.services.messaging import clear_sent_keys
from app.services.session import sessions

_reset_hooks: list[Callable[[], None]] = []


def register_reset(fn: Callable[[], None]) -> Callable[[], None]:
    """Modules with their own in-memory state (rate limiter, caches, stub) register here."""
    if fn not in _reset_hooks:
        _reset_hooks.append(fn)
    return fn


def reset_data() -> None:
    itsm.reset()
    sessions.clear()
    for p in (outbox_path(), alerts_path()):
        p.unlink(missing_ok=True)
    clear_sent_keys()
    clear_audit()
    controls.reset()
    for hook in _reset_hooks:
        hook()
