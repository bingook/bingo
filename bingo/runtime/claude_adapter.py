from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterator

from .contracts import (
    Completion,
    ConversationTurn,
    ModelRequest,
    OpaqueContent,
    ProviderCapabilities,
    RuntimeEvent,
    RuntimeEventKind,
    StopReason,
    TextContent,
    ToolRequest,
    UsageRecord,
)


_STOP_REASONS = {
    "end_turn": StopReason.COMPLETE,
    "stop_sequence": StopReason.COMPLETE,
    "tool_use": StopReason.TOOL_REQUEST,
    "pause_turn": StopReason.PAUSED,
    "refusal": StopReason.REFUSED,
    "max_tokens": StopReason.OUTPUT_LIMIT,
    "model_context_window_exceeded": StopReason.CONTEXT_LIMIT,
}


class ClaudeAdapter:
    """Official Anthropic SDK transport; Bingo retains execution authority."""

    def __init__(self, config, *, client: Any | None = None):
        self.config = config
        if client is None:
            import anthropic

            kwargs: dict[str, Any] = {"api_key": config.api_key}
            if config.base_url:
                kwargs["base_url"] = config.base_url
            client = anthropic.Anthropic(**kwargs)
        self.client = client

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            native_tool_use=True,
            structured_output=True,
            reasoning_blocks=True,
            pause_resume=True,
            lossless_replay=True,
            compaction=True,
        )

    def stream(self, request: ModelRequest) -> Iterator[RuntimeEvent]:
        yield RuntimeEvent(kind=RuntimeEventKind.RESPONSE_STARTED)
        try:
            with self.client.messages.stream(**self._request_params(request)) as stream:
                for text in stream.text_stream:
                    if text:
                        yield RuntimeEvent(kind=RuntimeEventKind.TEXT_DELTA, text=text)
                message = stream.get_final_message()
        except Exception as exc:
            yield RuntimeEvent(kind=RuntimeEventKind.ERROR, error=self._error_text(exc))
            return

        completion = self._completion(message)
        if completion.usage != UsageRecord():
            yield RuntimeEvent(kind=RuntimeEventKind.USAGE, usage=completion.usage)
        if completion.stop_reason is StopReason.REFUSED:
            yield RuntimeEvent(
                kind=RuntimeEventKind.REFUSED,
                completion=completion,
                diagnostics=completion.provider_metadata,
            )
        elif completion.stop_reason is StopReason.PAUSED:
            yield RuntimeEvent(kind=RuntimeEventKind.PAUSED, completion=completion)
        else:
            for content in completion.content:
                if isinstance(content, OpaqueContent):
                    block = content.value
                    if getattr(block, "type", "") == "tool_use":
                        yield RuntimeEvent(
                            kind=RuntimeEventKind.TOOL_REQUESTED,
                            tool_request=ToolRequest(
                                request_id=str(block.id),
                                capability=str(block.name),
                                arguments=dict(block.input),
                                provider_metadata={"provider": "claude"},
                            ),
                        )
        yield RuntimeEvent(kind=RuntimeEventKind.RESPONSE_COMPLETED, completion=completion)

    def _request_params(self, request: ModelRequest) -> dict[str, Any]:
        options = dict(request.options)
        params: dict[str, Any] = {
            "model": request.model,
            "max_tokens": int(options.pop("max_tokens", self.config.max_tokens)),
            "system": request.system,
            "messages": [self._turn(turn) for turn in request.conversation],
        }
        if request.tools:
            params["tools"] = [dict(tool) for tool in request.tools]
        if not request.model.startswith("claude-fable-5"):
            params["thinking"] = options.pop("thinking", {"type": "adaptive"})
        effort = options.pop("effort", "high")
        params["output_config"] = {"effort": effort}
        params.update(options)
        return params

    @staticmethod
    def _turn(turn: ConversationTurn) -> dict[str, Any]:
        content: list[Any] = []
        for block in turn.content:
            if isinstance(block, TextContent):
                content.append({"type": "text", "text": block.text})
            elif isinstance(block, OpaqueContent) and block.provider == "claude":
                content.append(block.value)
            else:
                content.append(asdict(block))
        return {"role": turn.role, "content": content}

    @staticmethod
    def _completion(message: Any) -> Completion:
        usage_obj = getattr(message, "usage", None)
        usage = UsageRecord(
            input_tokens=int(getattr(usage_obj, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage_obj, "output_tokens", 0) or 0),
            cache_read_input_tokens=int(
                getattr(usage_obj, "cache_read_input_tokens", 0) or 0
            ),
            cache_creation_input_tokens=int(
                getattr(usage_obj, "cache_creation_input_tokens", 0) or 0
            ),
        )
        metadata: dict[str, Any] = {"model": str(getattr(message, "model", ""))}
        stop_details = getattr(message, "stop_details", None)
        if stop_details is not None:
            metadata["stop_category"] = getattr(stop_details, "category", None)
            metadata["stop_explanation"] = getattr(stop_details, "explanation", None)
        content = tuple(
            TextContent(block.text)
            if getattr(block, "type", "") == "text"
            else OpaqueContent(provider="claude", value=block)
            for block in (getattr(message, "content", None) or [])
        )
        return Completion(
            response_id=str(getattr(message, "id", "")),
            stop_reason=_STOP_REASONS.get(
                str(getattr(message, "stop_reason", "")), StopReason.ERROR
            ),
            content=content,
            usage=usage,
            provider_metadata=metadata,
        )

    @staticmethod
    def _error_text(exc: Exception) -> str:
        request_id = getattr(exc, "request_id", None)
        message = getattr(exc, "message", None) or str(exc)
        return f"{message} (request_id={request_id})" if request_id else str(message)
