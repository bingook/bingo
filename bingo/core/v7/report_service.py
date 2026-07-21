from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .contracts import MissionEvent, MissionPhase
from .state_machine import MissionStateMachine


@dataclass(frozen=True)
class ReportLifecycleResult:
    completed: bool
    artifacts: tuple[Path, ...] = ()
    error: str = ""


class ReportService:
    """Verify report artifacts before completing the mission lifecycle."""

    def __init__(
        self,
        mission: MissionStateMachine,
        writer: Callable[[], tuple[Path, ...]],
    ) -> None:
        self.mission = mission
        self.writer = writer

    def generate(self) -> ReportLifecycleResult:
        if self.mission.phase is not MissionPhase.REPORT:
            self.mission.apply(MissionEvent.REPORT_REQUESTED, "report service")
        try:
            artifacts = tuple(self.writer())
        except Exception as exc:
            return ReportLifecycleResult(completed=False, error=str(exc))
        missing = tuple(path for path in artifacts if not path.is_file())
        if not artifacts or missing:
            names = ", ".join(str(path) for path in missing) or "no artifacts"
            return ReportLifecycleResult(
                completed=False,
                artifacts=artifacts,
                error=f"report artifacts incomplete: {names}",
            )
        self.mission.apply(MissionEvent.REPORT_EMITTED, "artifacts verified")
        return ReportLifecycleResult(completed=True, artifacts=artifacts)
