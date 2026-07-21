from __future__ import annotations

from dataclasses import dataclass

from urllib.parse import urlparse

from ..engagement import (
    ActionAuthority,
    ActionClass,
    ActionDecision,
    ActionRequest,
    Engagement,
)
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
        path = intent.path or "/"
        parsed = urlparse(path)
        if parsed.scheme or parsed.netloc:
            raise ValueError("planner intent path must be relative to the mission target")
        url = self._target_state.build_url(path)
        return ActionEnvelope(
            tool=intent.tool,
            url=url,
            method=method,
            params=dict(intent.params),
            headers=dict(intent.headers),
            evidence_goal=intent.evidence_goal,
            summary=intent.summary,
        )

    def prepare(
        self,
        intent: PlannerIntent,
        engagement: Engagement,
        *,
        now: float,
        authority: ActionAuthority | None = None,
        approved_identity: str = "",
        action_class: ActionClass = ActionClass.BOUNDED_NETWORK_READ,
    ) -> ActionDecision:
        """Bind planner intent, then evaluate it before any dispatch."""

        envelope = self.build(intent)
        request = ActionRequest(
            capability=envelope.tool,
            url=envelope.url,
            method=envelope.method,
            arguments={
                "params": dict(envelope.params),
                "headers": dict(envelope.headers),
            },
            action_class=action_class,
            evidence_goal=envelope.evidence_goal,
            summary=envelope.summary,
        )
        return (authority or ActionAuthority()).evaluate(
            request,
            engagement,
            now=now,
            approved_identity=approved_identity,
        )
