from bingo.application.chat import ChatApplication
from bingo.core.engagement import Engagement, EngagementAuthorization, ScopeDefinition
from bingo.core.v7 import MissionRuntimeCoordinator
from bingo.runtime.contracts import RuntimeEvent, RuntimeEventKind, ToolRequest
from bingo.ui.view_models import ActivityKind


def _engagement(asserted=True, *, allowed_methods=("GET", "HEAD", "OPTIONS")):
    return Engagement(
        scope=ScopeDefinition(
            target="https://example.test",
            allowed_methods=allowed_methods,
        ),
        authorization=EngagementAuthorization(
            asserted=asserted,
            asserted_by="operator" if asserted else "",
            asserted_at=1.0 if asserted else 0.0,
        ),
        goal="map metadata",
    )


def test_chat_application_executes_only_authorized_envelope():
    executed = []
    activity = []
    app = ChatApplication(
        runtime=MissionRuntimeCoordinator(),
        engagement=_engagement(),
        execute=lambda envelope: executed.append(envelope) or "ok",
        emit=activity.append,
        capability_labels={"fetch": "application entry point"},
    )
    events = [
        RuntimeEvent(kind=RuntimeEventKind.TEXT_DELTA, text="Working."),
        RuntimeEvent(
            kind=RuntimeEventKind.TOOL_REQUESTED,
            tool_request=ToolRequest(
                request_id="tool-1",
                capability="fetch",
                arguments={"url": "https://example.test/metadata"},
            ),
        ),
    ]

    text = app.handle_runtime_events(events, now=2.0)

    assert text == "Working."
    assert len(executed) == 1
    assert executed[0].engagement_id == app.engagement.engagement_id
    assert app.engagement.actions_used == 1
    assert [event.kind for event in activity] == [
        ActivityKind.ACTION_STARTED,
        ActivityKind.ACTION_COMPLETED,
    ]
    assert all(event.diagnostics.get("capability") == "fetch" for event in activity)


def test_chat_application_does_not_execute_without_authorization():
    executed = []
    activity = []
    app = ChatApplication(
        runtime=MissionRuntimeCoordinator(),
        engagement=_engagement(asserted=False),
        execute=lambda envelope: executed.append(envelope) or "ok",
        emit=activity.append,
    )

    app.handle_runtime_events(
        [
            RuntimeEvent(
                kind=RuntimeEventKind.TOOL_REQUESTED,
                tool_request=ToolRequest(
                    request_id="tool-1",
                    capability="fetch",
                    arguments={"url": "https://example.test/"},
                ),
            )
        ],
        now=2.0,
    )

    assert executed == []
    assert activity[0].kind is ActivityKind.SCOPE_REJECTED


def test_chat_application_requests_approval_for_state_change():
    executed = []
    activity = []
    app = ChatApplication(
        runtime=MissionRuntimeCoordinator(),
        engagement=_engagement(allowed_methods=("GET", "HEAD", "OPTIONS", "POST")),
        execute=lambda envelope: executed.append(envelope) or "ok",
        emit=activity.append,
    )

    app.handle_runtime_events(
        [
            RuntimeEvent(
                kind=RuntimeEventKind.TOOL_REQUESTED,
                tool_request=ToolRequest(
                    request_id="tool-2",
                    capability="authenticated_check",
                    arguments={"url": "https://example.test/profile", "method": "POST"},
                ),
            )
        ],
        now=2.0,
    )

    assert executed == []
    assert activity[0].kind is ActivityKind.APPROVAL_REQUIRED
