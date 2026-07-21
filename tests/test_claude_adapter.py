from __future__ import annotations

from types import SimpleNamespace

from bingo.models.base import ModelConfig
from bingo.runtime.claude_adapter import ClaudeAdapter
from bingo.runtime.contracts import (
    ConversationTurn,
    ModelRequest,
    RuntimeEventKind,
    StopReason,
)


class _Stream:
    def __init__(self, message, texts=()):
        self.message = message
        self.text_stream = iter(texts)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get_final_message(self):
        return self.message


class _Messages:
    def __init__(self, stream):
        self._stream = stream
        self.params = None

    def stream(self, **params):
        self.params = params
        return self._stream


class _Client:
    def __init__(self, stream):
        self.messages = _Messages(stream)


def _config(model="claude-opus-4-8"):
    return ModelConfig(
        provider="claude",
        model=model,
        api_key="test",
        base_url="https://api.anthropic.com/v1",
    )


def _request(model="claude-opus-4-8"):
    return ModelRequest(
        provider="claude",
        model=model,
        system="system",
        conversation=(ConversationTurn.text("user", "hello"),),
    )


def test_claude_adapter_streams_text_and_preserves_completion():
    message = SimpleNamespace(
        id="msg-1",
        model="claude-opus-4-8",
        stop_reason="end_turn",
        stop_details=None,
        content=[SimpleNamespace(type="text", text="done")],
        usage=SimpleNamespace(
            input_tokens=3,
            output_tokens=2,
            cache_read_input_tokens=1,
            cache_creation_input_tokens=0,
        ),
    )
    client = _Client(_Stream(message, texts=("do", "ne")))
    adapter = ClaudeAdapter(_config(), client=client)

    events = list(adapter.stream(_request()))

    assert [event.text for event in events if event.kind is RuntimeEventKind.TEXT_DELTA] == ["do", "ne"]
    completed = [event for event in events if event.kind is RuntimeEventKind.RESPONSE_COMPLETED][0]
    assert completed.completion.stop_reason is StopReason.COMPLETE
    assert completed.completion.usage.cache_read_input_tokens == 1
    assert client.messages.params["thinking"] == {"type": "adaptive"}
    assert client.messages.params["output_config"] == {"effort": "high"}


def test_claude_adapter_surfaces_native_tool_request_without_executing():
    tool = SimpleNamespace(type="tool_use", id="tool-1", name="fetch", input={"url": "https://example.test"})
    message = SimpleNamespace(
        id="msg-2",
        model="claude-opus-4-8",
        stop_reason="tool_use",
        stop_details=None,
        content=[tool],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
    )
    adapter = ClaudeAdapter(_config(), client=_Client(_Stream(message)))

    events = list(adapter.stream(_request()))

    requested = [event for event in events if event.kind is RuntimeEventKind.TOOL_REQUESTED]
    assert len(requested) == 1
    assert requested[0].tool_request.capability == "fetch"
    assert requested[0].tool_request.arguments == {"url": "https://example.test"}


def test_claude_adapter_checks_refusal_before_content():
    message = SimpleNamespace(
        id="msg-3",
        model="claude-fable-5",
        stop_reason="refusal",
        stop_details=SimpleNamespace(category="cyber", explanation="declined"),
        content=[],
        usage=SimpleNamespace(input_tokens=0, output_tokens=0),
    )
    adapter = ClaudeAdapter(_config("claude-fable-5"), client=_Client(_Stream(message)))

    events = list(adapter.stream(_request("claude-fable-5")))

    refused = [event for event in events if event.kind is RuntimeEventKind.REFUSED]
    assert len(refused) == 1
    assert refused[0].completion.stop_reason is StopReason.REFUSED
    assert refused[0].diagnostics["stop_category"] == "cyber"
