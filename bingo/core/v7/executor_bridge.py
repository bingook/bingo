from __future__ import annotations

from dataclasses import dataclass

from ..target_state import TargetState
from .contracts import ActionEnvelope, MissionScope, PlannerIntent


@dataclass
class ExecutorActionBuilder:
    scope: MissionScope

    def __post_init__(self) -> None:
        state = TargetState.from_target(self.scope.target)
        if state is None:
            raise ValueError(f"invalid mission target: {self.scope.target}")
        self._target_state = state

    def build(self, intent: PlannerIntent) -> ActionEnvelope:
        method = (intent.method or "GET").upper()
        url = self._target_state.build_url(intent.path)
        return ActionEnvelope(
            tool=intent.tool,
            url=url,
            method=method,
            params=dict(intent.params),
            headers=dict(intent.headers),
            evidence_goal=intent.evidence_goal,
            summary=intent.summary,
        )
