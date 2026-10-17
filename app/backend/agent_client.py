"""Client for the Agent Service: timeout, one retry, idempotency key, response validation."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from app.agents.base import Trace
from app.backend.schemas import AgentResult, InvalidAgentResponse, validate_agent_result

AgentFn = Callable[[dict[str, Any], dict[str, Any]], Awaitable[Any]]


class AgentCallFailed(Exception):
    pass


class AgentClient:
    def __init__(self, fn: AgentFn, timeout_s: float = 15.0, max_retries: int = 1) -> None:
        self.fn = fn
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self._completed: dict[str, AgentResult] = {}  # idempotency_key -> validated result

    def clear_cache(self) -> None:
        self._completed.clear()

    async def call(self, incident: dict[str, Any], session_ctx: dict[str, Any], trace: Trace) -> AgentResult:
        key = incident["idempotency_key"]
        if key in self._completed:
            trace.add("agent_call", "code", key, "cached result (idempotent)", branch="cached")
            return self._completed[key]

        errors: list[str] = []
        for attempt in range(1, self.max_retries + 2):
            t0 = time.perf_counter()
            try:
                raw = await asyncio.wait_for(self.fn(incident, session_ctx), timeout=self.timeout_s)
                result = validate_agent_result(raw)
            except asyncio.TimeoutError:
                err = f"timeout after {self.timeout_s}s"
            except InvalidAgentResponse as e:
                err = f"invalid response: {e}"
            except Exception as e:  # noqa: BLE001 - any agent crash is retried, then WF-ERR
                err = f"exception: {type(e).__name__}: {e}"
            else:
                trace.add("agent_call", "code", f"attempt {attempt} key={key}",
                          f"ok outcome={result.outcome}", branch="ok",
                          duration_ms=_ms(t0))
                trace.add("validate_response", "decision", "schema + outcome + safety rules",
                          "valid", branch="valid")
                self._completed[key] = result
                return result
            errors.append(err)
            last = attempt == self.max_retries + 1
            trace.add("agent_call", "code", f"attempt {attempt} key={key}", err,
                      branch="give_up" if last else "retry", duration_ms=_ms(t0))
        raise AgentCallFailed("; ".join(errors))


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)
