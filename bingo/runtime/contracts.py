from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class StopReason(str, Enum):
    COMPLETE = "complete"
    TOOL_REQUEST = "tool_request"
    PAUSED = "paused"
    REFUSED = "refused"
    OUTPUT_LIMIT = "output_limit"
    CONTEXT_LIMIT = "context_limit"
    CANCELLED = "cancelled"
    ERROR = "error"


class RuntimeEventKind(str, Enum):
    RESPONSE_STARTED = "response_started"
    TEXT_DELTA = "text_delta"
    REASONING_STATUS = "reasoning_status"
    TOOL_REQUESTED = "tool_requested"
    RESPONSE_COMPLETED = "response_completed"
    PAUSED = "paused"
    REFUSED = "refused"
    USAGE = "usage"
    ERROR = "error"


@dataclass(frozen=True)
class TextContent:
    text: str


@dataclass(frozen=True)
class ToolResultContent:
    request_id: str
    content: str
    is_error: bool = False


@dataclass(frozen=True)
class OpaqueContent:
    """Provider-owned replay data that must not be rendered directly."""

    provider: str
    value: Any


Content = TextContent | ToolResultContent | OpaqueContent


@dataclass(frozen=True)
class ConversationTurn:
    role: str
    content: tuple[Content, ...]

    @classmethod
    def text(cls, role: str, text: str) -> "ConversationTurn":
        return cls(role=role, content=(TextContent(text=text),))


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    capability: str
    arguments: Mapping[str, Any]
    parallel_group: str = ""
    provider_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class UsageRecord:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass(frozen=True)
class Completion:
    response_id: str
    stop_reason: StopReason
    content: tuple[Content, ...] = ()
    usage: UsageRecord = field(default_factory=UsageRecord)
    provider_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderCapabilities:
    native_tool_use: bool = False
    structured_output: bool = False
    reasoning_blocks: bool = False
    pause_resume: bool = False
    lossless_replay: bool = False
    compaction: bool = False


@dataclass(frozen=True)
class ModelRequest:
    provider: str
    model: str
    system: str
    conversation: tuple[ConversationTurn, ...]
    tools: tuple[Mapping[str, Any], ...] = ()
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeEvent:
    kind: RuntimeEventKind
    text: str = ""
    tool_request: ToolRequest | None = None
    completion: Completion | None = None
    usage: UsageRecord | None = None
    error: str | None = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)
