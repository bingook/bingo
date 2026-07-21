from bingo.runtime.contracts import (
    Completion,
    ConversationTurn,
    RuntimeEvent,
    RuntimeEventKind,
    StopReason,
    TextContent,
)
from bingo.runtime.legacy_tool_decoder import decode_legacy_tool_calls
from bingo.runtime.session import RuntimeSession


def test_runtime_session_preserves_typed_completion():
    session = RuntimeSession()
    session.append(ConversationTurn.text("user", "hello"))
    completion = Completion(
        response_id="response-1",
        stop_reason=StopReason.COMPLETE,
        content=(TextContent("done"),),
    )

    session.observe(
        RuntimeEvent(kind=RuntimeEventKind.RESPONSE_COMPLETED, completion=completion)
    )

    assert session.turns[0].content == (TextContent("hello"),)
    assert session.last_completion is completion


def test_legacy_tool_decoder_never_leaks_or_executes_directive():
    decoded = decode_legacy_tool_calls(
        'Checking now.\nTOOL_CALL:{"name":"http_get","args":{"url":"https://example.test"}}'
    )

    assert decoded.visible_text == "Checking now."
    assert len(decoded.requests) == 1
    assert decoded.requests[0].capability == "http_get"
    assert decoded.requests[0].arguments == {"url": "https://example.test"}
