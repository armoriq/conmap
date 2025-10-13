from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field

from ..models import Severity


class ConboxConfig(BaseModel):
    enabled: bool = False
    max_runtime: float = 15.0
    max_tools: int = 5


class SandboxAlert(BaseModel):
    category: str
    severity: Severity
    message: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class SandboxReport(BaseModel):
    tool_name: str
    alerts: List[SandboxAlert] = Field(default_factory=list)
    duration_seconds: float = 0.0
    events: List[Dict[str, Any]] = Field(default_factory=list)


def should_profile_tool(tool: Dict[str, Any]) -> bool:
    metadata = tool.get("metadata") or {}
    if not isinstance(metadata, dict):
        return True
    if metadata.get("signature") is None:
        return True
    if metadata.get("sandbox_required"):
        return True
    if isinstance(metadata.get("sandbox_simulation"), dict):
        return True
    return False


def run_sandbox(tool: Dict[str, Any], config: ConboxConfig) -> SandboxReport:
    metadata = tool.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    simulation = metadata.get("sandbox_simulation") or {}
    if not isinstance(simulation, dict):
        simulation = {}

    events: List[Dict[str, Any]] = []
    alerts: List[SandboxAlert] = []

    # Simulated network events
    for destination in simulation.get("network", []) or []:
        events.append({"type": "network", "destination": destination})
        alerts.append(
            SandboxAlert(
                category="network_exfiltration",
                severity=Severity.high,
                message=f"Tool attempted network egress to {destination} during sandbox execution.",
                evidence={"destination": destination},
            )
        )

    # Simulated filesystem writes
    for path in simulation.get("filesystem", []) or []:
        events.append({"type": "filesystem", "path": path})
        alerts.append(
            SandboxAlert(
                category="filesystem_write",
                severity=Severity.medium,
                message=f"Tool wrote to {path} inside sandbox.",
                evidence={"path": path},
            )
        )

    if simulation.get("spawn_shell"):
        events.append({"type": "process", "command": simulation.get("shell_command", "/bin/sh")})
        alerts.append(
            SandboxAlert(
                category="shell_spawn",
                severity=Severity.high,
                message="Tool spawned a shell process inside sandbox.",
                evidence={"command": simulation.get("shell_command", "/bin/sh")},
            )
        )

    duration = float(simulation.get("duration", min(config.max_runtime, 1.0)))

    return SandboxReport(
        tool_name=str(tool.get("name", "unknown")),
        alerts=alerts,
        duration_seconds=duration,
        events=events,
    )
