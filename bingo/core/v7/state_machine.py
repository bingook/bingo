from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import MissionEvent, MissionPhase, MissionScope


_TRANSITIONS: dict[MissionPhase, dict[MissionEvent, MissionPhase]] = {
    MissionPhase.INTAKE: {
        MissionEvent.START: MissionPhase.RECON,
        MissionEvent.HALT: MissionPhase.HALTED,
    },
    MissionPhase.RECON: {
        MissionEvent.RECON_COMPLETE: MissionPhase.ENUMERATE,
        MissionEvent.SURFACE_MAPPED: MissionPhase.ENUMERATE,
        MissionEvent.EVIDENCE_CONFIRMED: MissionPhase.VALIDATE,
        MissionEvent.REPORT_REQUESTED: MissionPhase.REPORT,
        MissionEvent.HALT: MissionPhase.HALTED,
    },
    MissionPhase.ENUMERATE: {
        MissionEvent.HYPOTHESIS_READY: MissionPhase.VALIDATE,
        MissionEvent.EVIDENCE_CONFIRMED: MissionPhase.VALIDATE,
        MissionEvent.REPORT_REQUESTED: MissionPhase.REPORT,
        MissionEvent.HALT: MissionPhase.HALTED,
    },
    MissionPhase.VALIDATE: {
        MissionEvent.EVIDENCE_OBSERVED: MissionPhase.VALIDATE,
        MissionEvent.EVIDENCE_CONFIRMED: MissionPhase.VALIDATE,
        MissionEvent.PLATEAU: MissionPhase.REPORT,
        MissionEvent.REPORT_REQUESTED: MissionPhase.REPORT,
        MissionEvent.HALT: MissionPhase.HALTED,
    },
    MissionPhase.REPORT: {
        MissionEvent.REPORT_EMITTED: MissionPhase.DONE,
        MissionEvent.HALT: MissionPhase.HALTED,
    },
    MissionPhase.DONE: {},
    MissionPhase.HALTED: {},
}


@dataclass
class MissionStateMachine:
    scope: MissionScope
    phase: MissionPhase = MissionPhase.INTAKE
    loop_count: int = 0
    observed_count: int = 0
    confirmed_count: int = 0
    plateau_turns: int = 0
    history: list[str] = field(default_factory=list)

    def apply(self, event: MissionEvent, detail: str = "") -> MissionPhase:
        self.history.append(f"{self.phase.value}:{event.value}:{detail}".strip(":"))
        target_phase = _TRANSITIONS.get(self.phase, {}).get(event, self.phase)
        if event == MissionEvent.EVIDENCE_OBSERVED:
            self.observed_count += 1
            self.plateau_turns = 0
        elif event == MissionEvent.EVIDENCE_CONFIRMED:
            self.confirmed_count += 1
            self.plateau_turns = 0
        elif event == MissionEvent.PLATEAU:
            self.plateau_turns += 1
        self.phase = target_phase
        return self.phase

    def begin_loop(self) -> None:
        self.loop_count += 1

    def note_no_progress(self) -> int:
        self.plateau_turns += 1
        return self.plateau_turns

    def should_report(self) -> bool:
        if self.phase == MissionPhase.REPORT:
            return True
        if self.confirmed_count > 0 and self.plateau_turns >= 2:
            return True
        return False
