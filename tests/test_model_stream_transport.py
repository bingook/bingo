from __future__ import annotations

from bingo.models.base import BaseModel, Message, ModelConfig


class _FakeResponse:
    def __init__(self, lines: list[str], status_code: int = 200, body: str = "") -> None:
        self._lines = lines
        self.status_code = status_code
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def iter_lines(self):
        yield from self._lines

    def read(self) -> bytes:
        return self._body.encode("utf-8")


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def stream(self, *_args, **_kwargs):
        return self.response


def _model_with_lines(monkeypatch, lines: list[str]) -> BaseModel:
    response = _FakeResponse(lines)
    monkeypatch.setattr("bingo.models.base.httpx.Client", lambda timeout: _FakeClient(response))
    cfg = ModelConfig(
        provider="custom",
        model="test-model",
        api_key="test",
        base_url="https://llm.test/v1",
        system_prompt="system",
    )
    return BaseModel(cfg)


def _collect_text_and_errors(model: BaseModel) -> tuple[str, list[str], list[str]]:
    text = ""
    errors: list[str] = []
    diagnostics: list[str] = []
    for chunk in model.chat_stream([Message(role="user", content="continue")]):
        text += chunk.text
        if chunk.error:
            errors.append(chunk.error)
        if chunk.diagnostics:
            diagnostics.append(chunk.diagnostics)
    return text, errors, diagnostics


def test_openai_stream_transport_extracts_structured_content(monkeypatch) -> None:
    model = _model_with_lines(
        monkeypatch,
        [
            'data: {"choices":[{"delta":{"content":[{"type":"text","text":"next "},{"type":"text","text":"action"}]},"finish_reason":null}]}',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
            "data: [DONE]",
        ],
    )

    text, errors, _diagnostics = _collect_text_and_errors(model)

    assert text == "next action"
    assert errors == []


def test_openai_stream_transport_extracts_reasoning_content_variant(monkeypatch) -> None:
    model = _model_with_lines(
        monkeypatch,
        [
            'data: {"choices":[{"delta":{"reasoning_content":"continue from latest tool result"},"finish_reason":null}]}',
            "data: [DONE]",
        ],
    )

    text, errors, _diagnostics = _collect_text_and_errors(model)

    assert text == "continue from latest tool result"
    assert errors == []


def test_openai_stream_transport_extracts_non_sse_message_json(monkeypatch) -> None:
    model = _model_with_lines(
        monkeypatch,
        [
            '{"choices":[{"message":{"content":"full JSON answer"},"finish_reason":"stop"}]}',
        ],
    )

    text, errors, _diagnostics = _collect_text_and_errors(model)

    assert text == "full JSON answer"
    assert errors == []


def test_openai_stream_transport_treats_empty_http_200_as_protocol_error(monkeypatch) -> None:
    model = _model_with_lines(monkeypatch, [])

    text, errors, diagnostics = _collect_text_and_errors(model)

    assert text == ""
    assert errors
    assert "MODEL_STREAM_PROTOCOL" in errors[0]
    assert "reason=no-json-events" in errors[0]
    assert diagnostics == errors


def test_openai_stream_transport_treats_unknown_events_as_protocol_error(monkeypatch) -> None:
    model = _model_with_lines(
        monkeypatch,
        [
            'data: {"id":"chatcmpl-test","usage":{"prompt_tokens":1,"completion_tokens":0}}',
            "data: [DONE]",
        ],
    )

    text, errors, diagnostics = _collect_text_and_errors(model)

    assert text == ""
    assert errors
    assert "reason=no-usable-text" in errors[0]
    assert "parsed=1" in errors[0]
    assert diagnostics == errors


def test_openai_stream_transport_surfaces_provider_error_payload(monkeypatch) -> None:
    model = _model_with_lines(
        monkeypatch,
        [
            'data: {"error":{"message":"provider rejected stream schema"}}',
        ],
    )

    text, errors, diagnostics = _collect_text_and_errors(model)

    assert text == ""
    assert errors == ["provider rejected stream schema"]
    assert diagnostics
    assert "reason=provider-error" in diagnostics[0]
