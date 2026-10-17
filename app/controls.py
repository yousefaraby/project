"""Runtime controls used to simulate faults in mock mode."""
from __future__ import annotations

from dataclasses import dataclass, field

TOOL_NAMES: tuple[str, ...] = (
    "check_account_status",
    "check_vpn_status",
    "check_device_status",
    "check_network_status",
    "search_it_knowledge",
)
TOOL_MODES: tuple[str, ...] = ("ok", "error", "slow")
TROUBLESHOOTER_BEHAVIORS: tuple[str, ...] = ("ok", "hallucinate_once", "hallucinate_always")


AGENT_SERVICE_FAULTS: tuple[str, ...] = ("none", "timeout", "exception", "invalid response")


@dataclass
class Controls:
    kill_switch: bool = False
    agent_fault: bool = False
    agent_service_fault: str = "none"
    tool_modes: dict[str, str] = field(default_factory=dict)
    troubleshooter_behavior: str | None = None  # None = use the fixture value
    slow_delay_s: float = 3.0

    def set_tool_mode(self, tool: str, mode: str) -> None:
        if tool not in TOOL_NAMES:
            raise ValueError(f"unknown tool: {tool}")
        if mode not in TOOL_MODES:
            raise ValueError(f"unknown tool mode: {mode}")
        self.tool_modes[tool] = mode

    def tool_mode(self, tool: str) -> str:
        return self.tool_modes.get(tool, "ok")

    def set_troubleshooter_behavior(self, behavior: str | None) -> None:
        if behavior is not None and behavior not in TROUBLESHOOTER_BEHAVIORS:
            raise ValueError(f"unknown troubleshooter behavior: {behavior}")
        self.troubleshooter_behavior = behavior

    def set_agent_service_fault(self, fault: str) -> None:
        if fault not in AGENT_SERVICE_FAULTS:
            raise ValueError(f"unknown agent service fault: {fault}")
        self.agent_service_fault = fault
        self.agent_fault = fault != "none"

    def reset(self) -> None:
        self.kill_switch = False
        self.agent_fault = False
        self.agent_service_fault = "none"
        self.tool_modes = {}
        self.troubleshooter_behavior = None
        self.slow_delay_s = 3.0


controls = Controls()
