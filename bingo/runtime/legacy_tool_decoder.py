from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .contracts import ToolRequest


_TOOL_CALL = re.compile(r"TOOL_CALL\s*:\s*")
_LEGACY_SUMMARY = re.compile(
    r"^TOOL_CALL_SUMMARY:.*?(?=^\s*$|^TOOL_CALL_SUMMARY:|\Z)",
    re.M | re.S,
)
_EXPOSED_ACTION = re.compile(
    r"^\[bingo action\].*?(?=^\)\s*$|^\[bingo action\]|\Z)",
    re.M | re.S,
)


@dataclass(frozen=True)
class LegacyDecodeResult:
    visible_text: str
    requests: tuple[ToolRequest, ...]


def decode_legacy_tool_calls(text: str) -> LegacyDecodeResult:
    """Decode old textual calls without executing or exposing their payloads."""

    requests: list[ToolRequest] = []
    spans: list[tuple[int, int]] = []
    for index, match in enumerate(_TOOL_CALL.finditer(text)):
        start = match.end()
        decoded = _decode_json_object(text, start)
        if decoded is None:
            continue
        value, end = decoded
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            continue
        args = value.get("args")
        if not isinstance(args, dict):
            args = {}
        requests.append(
            ToolRequest(
                request_id=f"legacy-{index}",
                capability=value["name"],
                arguments=args,
                provider_metadata={"transport": "legacy_text"},
            )
        )
        spans.append((match.start(), end))

    visible = _remove_spans(text, spans)
    visible = _LEGACY_SUMMARY.sub("", visible)
    visible = _EXPOSED_ACTION.sub("", visible)
    visible = re.sub(r"^\)\s*$", "", visible, flags=re.M).strip()
    return LegacyDecodeResult(visible_text=visible, requests=tuple(requests))


def _decode_json_object(text: str, start: int) -> tuple[Any, int] | None:
    while start < len(text) and text[start].isspace():
        start += 1
    if start >= len(text) or text[start] != "{":
        return None
    try:
        value, length = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError:
        return None
    return value, start + length


def _remove_spans(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chunks: list[str] = []
    start = 0
    for left, right in spans:
        chunks.append(text[start:left])
        start = right
    chunks.append(text[start:])
    return "".join(chunks)
