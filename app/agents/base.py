"""Agent interfaces (Protocols) and the Trace helper.

Mock and real LLM-backed agents implement these; the workflow only depends on them.
"""
from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable

StepType = Literal["code", "llm", "decision", "human", "blocked"]


class Trace:
    """Collects one entry per pipeline step."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def add(
        self,
        step: str,
        step_type: StepType,
        input: str = "",
        output: str = "",
        branch: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        self.entries.append(
            {
                "step": step,
                "type": step_type,
                "input": input,
                "output": output,
                "branch": branch,
                "duration_ms": duration_ms,
            }
        )

    def extend(self, entries: list[dict[str, Any]]) -> None:
        self.entries.extend(entries)

    def to_list(self) -> list[dict[str, Any]]:
        return list(self.entries)


@runtime_checkable
class TriageAgent(Protocol):
    async def triage(self, message: str, context: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class Planner(Protocol):
    async def plan(self, triage: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class Worker(Protocol):
    name: str

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class Troubleshooter(Protocol):
    async def propose(
        self, findings: dict[str, Any], feedback: str | None, context: dict[str, Any]
    ) -> dict[str, Any]: ...


@runtime_checkable
class Evaluator(Protocol):
    async def evaluate(self, proposal: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]: ...
