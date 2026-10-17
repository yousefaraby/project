"""Mock bearer auth and sliding-window rate limiting."""
from __future__ import annotations

import hmac
import time
from collections import deque
from typing import Callable

from app.services import fixtures

ADMIN_TOKEN = "test-admin-token"


def verify_bearer(authorization: str | None, user_id: str) -> bool:
    """Valid iff header == 'Bearer test-token-<user_id>' and the user exists."""
    if not authorization or not user_id:
        return False
    if fixtures.get_user(user_id) is None:
        return False
    return hmac.compare_digest(authorization.strip(), f"Bearer test-token-{user_id}")


def verify_admin(authorization: str | None) -> bool:
    return bool(authorization) and hmac.compare_digest(authorization.strip(), f"Bearer {ADMIN_TOKEN}")


class RateLimiter:
    """Sliding window: at most `limit` accepted requests per `window_s` per key."""

    def __init__(self, limit: int = 10, window_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        dq = self._hits.setdefault(key, deque())
        while dq and now - dq[0] >= self.window_s:
            dq.popleft()
        if len(dq) >= self.limit:
            return False
        dq.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()
        self.clock = time.monotonic
