from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping

from ..core.engagement import (
    ActionClass,
    ActionDecisionKind,
    Engagement,
    ExecutionEnvelope,
)
from ..core.v7 import MissionRuntimeCoordinator, PlannerIntent
from ..runtime.contracts import RuntimeEvent, RuntimeEventKind, ToolRequest
from ..ui.view_models import ActivityEvent, ActivityKind


ToolExecutor = Callable[[ExecutionEnvelope], str]
ActivitySink = Callable[[ActivityEvent], None]


@dataclass
class ChatApplication:
    """Provider-neutral chat/tool loop with one pre-dispatch authority path."""

    runtime: MissionRuntimeCoordinator
    engagement: Engagement
    execute: ToolExecutor
    emit: ActivitySink
    capability_labels: Mapping[str, str] = field(default_factory=dict)

    def handle_runtime_events(self, events: Iterable[RuntimeEvent], *, now: float) -> str:
        text: list[str] = []
        pending: list[ToolRequest] = []
        for event in events:
            if event.kind is RuntimeEventKind.TEXT_DELTA and event.text:
                text.append(event.text)
            elif event.kind is RuntimeEventKind.TOOL_REQUESTED and event.tool_request:
                pending.append(event.tool_request)
            elif event.kind is RuntimeEventKind.REFUSED:
                self.emit(ActivityEvent(ActivityKind.RUNTIME_FAILED, "chat_runtime_refused"))
            elif event.kind is RuntimeEventKind.ERROR:
                self.emit(ActivityEvent(ActivityKind.RUNTIME_FAILED, "chat_runtime_failed"))

        for request in pending:
            self._handle_tool_request(request, now=now)
        return "".join(text)

    def _handle_tool_request(self, request: ToolRequest, *, now: float) -> None:
        intent = self._intent(request)
        decision = self.runtime.prepare_action(
            intent,
            self.engagement,
            now=now,
            action_class=self._action_class(request),
        )
        if decision.kind is ActionDecisionKind.DENY:
            self.emit(ActivityEvent(ActivityKind.SCOPE_REJECTED, "chat_scope_rejected"))
            return
        if decision.kind is ActionDecisionKind.REQUIRE_CONFIRMATION:
            self.emit(ActivityEvent(ActivityKind.APPROVAL_REQUIRED, "chat_approval_required"))
            return

        envelope = decision.envelope
        if envelope is None:
            self.emit(ActivityEvent(ActivityKind.RUNTIME_FAILED, "chat_runtime_failed"))
            return
        activity = self.capability_labels.get(request.capability, "application surface")
        self.emit(
            ActivityEvent(
                ActivityKind.ACTION_STARTED,
                "chat_action_started",
                values={"activity": activity},
                diagnostics={"capability": request.capability},
            )
        )
        self.execute(envelope)
        self.runtime.record_execution(envelope)
        self.engagement.actions_used += 1
        self.emit(
            ActivityEvent(
                ActivityKind.ACTION_COMPLETED,
                "chat_action_completed",
                values={"activity": activity},
                diagnostics={"capability": request.capability},
            )
        )

    @staticmethod
    def _intent(request: ToolRequest) -> PlannerIntent:
        arguments = dict(request.arguments)
        url = str(arguments.get("url", "") or "")
        from urllib.parse import parse_qsl, urlparse

        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        raw_params = arguments.get("params")
        if isinstance(raw_params, dict):
            params.update({str(key): str(value) for key, value in raw_params.items()})
        method = str(arguments.get("method", "GET") or "GET").upper()
        return PlannerIntent(
            summary=str(arguments.get("summary", request.capability)),
            path=parsed.path or "/",
            method=method,
            params=params,
            tool=request.capability,
            evidence_goal=str(arguments.get("evidence_goal", "") or ""),
        )

    @staticmethod
    def _action_class(request: ToolRequest) -> ActionClass:
        value = str(request.provider_metadata.get("action_class", "") or "")
        try:
            return ActionClass(value)
        except ValueError:
            method = str(request.arguments.get("method", "GET") or "GET").upper()
            if method in {"GET", "HEAD", "OPTIONS"}:
                return ActionClass.BOUNDED_NETWORK_READ
            return ActionClass.REVERSIBLE_STATE_CHANGE
