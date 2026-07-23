from __future__ import annotations

import json

import httpx

from bingo.models.base import BaseModel, ClaudeModel, Message, ModelConfig


class _FakeStreamResponse:
    def __init__(self, status_code: int, body: dict | str, lines=None, headers=None):
        self.status_code = status_code
        self._body = json.dumps(body) if isinstance(body, dict) else body
        self._lines = list(lines or [])
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._body.encode()

    def iter_lines(self):
        yield from self._lines


class _FakeClient:
    def __init__(self, response: _FakeStreamResponse, capture: dict, *args, **kwargs):
        self.response = response
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def stream(self, method, url, json=None, headers=None):
        self.capture["calls"] = self.capture.get("calls", 0) + 1
        self.capture["method"] = method
        self.capture["url"] = url
        self.capture["payload"] = json
        self.capture["headers"] = headers
        return self.response


def _config(provider="custom"):
    return ModelConfig(
        provider=provider,
        model="test-model",
        api_key="test-key",
        base_url="https://provider.test",
        system_prompt="configured system",
    )


def _patch_client(monkeypatch, response):
    capture = {}
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda *args, **kwargs: _FakeClient(response, capture, *args, **kwargs),
    )
    return capture


def test_generic_invalid_request_400_is_not_retried_or_compacted(monkeypatch) -> None:
    capture = _patch_client(
        monkeypatch,
        _FakeStreamResponse(
            400,
            {"error": {"type": "invalid_request_error", "code": "bad_role", "message": "system role invalid"}},
            headers={"x-request-id": "req-400"},
        ),
    )
    model = BaseModel(_config())
    chunks = list(
        model.chat_stream(
            [Message("system", "caller system"), Message("user", "hello")],
            _amp_skip=True,
        )
    )

    assert capture["calls"] == 1
    assert [message["content"] for message in capture["payload"]["messages"]].count("caller system") == 1
    assert "configured system" not in [message["content"] for message in capture["payload"]["messages"]]
    assert chunks[-1].failure is not None
    assert chunks[-1].failure.kind == "invalid_request"
    assert chunks[-1].failure.status_code == 400
    assert chunks[-1].failure.error_code == "bad_role"
    assert chunks[-1].failure.request_id == "req-400"
    assert not chunks[-1].failure.retryable


def test_source_contains_no_policy_rewrite_or_refusal_fallback() -> None:
    base_source = __import__("inspect").getsource(BaseModel)
    terminal_source = __import__("inspect").getsource(
        __import__("bingo.ui.terminal", fromlist=["BingoTerminal"]).BingoTerminal._send_message
    )
    assert "_grok_403_bypass_rewrite" not in base_source
    assert "rephrase_refused_request" not in terminal_source
    assert "fallback to" not in terminal_source


def test_generic_content_filter_400_is_terminal_without_fallback(monkeypatch) -> None:
    capture = _patch_client(
        monkeypatch,
        _FakeStreamResponse(
            400,
            {"error": {"type": "content_filter", "code": "safety_policy", "message": "rejected"}},
        ),
    )
    chunks = list(BaseModel(_config()).chat_stream([Message("user", "request")]))
    assert capture["calls"] == 1
    assert chunks[-1].failure.kind == "policy_rejection"
    assert chunks[-1].failure.policy_rejection


def test_http_200_without_model_event_is_protocol_failure(monkeypatch) -> None:
    _patch_client(monkeypatch, _FakeStreamResponse(200, "", lines=["data: {}", "data: [DONE]"]))
    chunks = list(BaseModel(_config()).chat_stream([Message("user", "hello")]))
    assert chunks[-1].failure is not None
    assert chunks[-1].failure.kind == "protocol_error"


def test_claude_extracts_single_system_and_accepts_dicts_and_amp_skip(monkeypatch) -> None:
    response = _FakeStreamResponse(
        200,
        "",
        lines=[
            'data: {"type":"message_start","message":{"id":"msg-1","usage":{}}}',
            'data: {"type":"content_block_delta","delta":{"text":"ok"}}',
            'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}',
            'data: {"type":"message_stop"}',
        ],
        headers={"request-id": "req-1"},
    )
    capture = _patch_client(monkeypatch, response)
    model = ClaudeModel(_config("claude"))
    chunks = list(
        model.chat_stream(
            [
                {"role": "system", "content": "caller system"},
                {"role": "user", "content": "hello"},
            ],
            _amp_skip=True,
        )
    )

    assert capture["payload"]["system"][0]["text"] == "caller system"
    assert all(message["role"] != "system" for message in capture["payload"]["messages"])
    assert "configured system" not in json.dumps(capture["payload"])
    assert "".join(chunk.text for chunk in chunks) == "ok"
    assert chunks[-1].finish_reason == "end_turn"


def test_claude_refusal_is_typed_terminal_failure(monkeypatch) -> None:
    response = _FakeStreamResponse(
        200,
        "",
        lines=[
            'data: {"type":"message_start","message":{"id":"msg-1","usage":{}}}',
            'data: {"type":"message_delta","delta":{"stop_reason":"refusal"}}',
            'data: {"type":"message_stop"}',
        ],
    )
    _patch_client(monkeypatch, response)
    chunks = list(ClaudeModel(_config("claude")).chat_stream([Message("user", "hello")], _amp_skip=True))
    assert chunks[-1].failure is not None
    assert chunks[-1].failure.kind == "refusal"
    assert chunks[-1].failure.policy_rejection
