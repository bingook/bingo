"""Crash-safe local project checkpoints for this workspace.

Local lifecycle hooks call this module before and after meaningful events.
The resulting state is intentionally small, sanitized, and atomically replaced so
that a new session can recover the current objective and unfinished actions even
when the previous terminal disappeared without running a stop hook.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .change_memory import (
    BINGO_AUTO_START,
    SECRET_LINE_RE,
    bingo_project_memory_path,
    memory_write_lock,
)

CHECKPOINT_FILE = Path(".bingo") / "live-checkpoint.json"
EVENT_LOG_FILE = Path(".bingo") / "live-events.jsonl"
LIVE_START = "<!-- bingo-live-checkpoint:start -->"
LIVE_END = "<!-- bingo-live-checkpoint:end -->"
MAX_TEXT = 2_000
MAX_OBJECTIVE_TEXT = 700
MAX_RENDERED_DETAIL = 240
MAX_CONTEXT_BYTES = 4 * 1024
MAX_EVENTS = 20
MAX_PROMPTS = 5
MAX_EVENT_LOG_BYTES = 512 * 1024

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|authorization|cookie)\b"
    r"\s*[:=]\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def sanitize_text(value: object, limit: int = MAX_TEXT) -> str:
    """Return bounded text with common credentials and private keys removed."""
    text = str(value or "").replace("\x00", "")
    text = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _BEARER_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = SECRET_LINE_RE.sub("[REDACTED]", text)
    encoded = text.encode("utf-8")
    if len(encoded) > limit:
        text = encoded[:limit].decode("utf-8", errors="ignore") + "…"
    return text.strip()


def checkpoint_path(cwd: str | Path) -> Path:
    return Path(cwd).resolve() / CHECKPOINT_FILE


def event_log_path(cwd: str | Path) -> Path:
    return Path(cwd).resolve() / EVENT_LOG_FILE


def load_checkpoint(cwd: str | Path) -> dict[str, Any]:
    path = checkpoint_path(cwd)
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_path(value: object, repo: Path) -> str:
    text = sanitize_text(value, 500)
    if not text:
        return ""
    try:
        path = Path(text).expanduser()
        if path.is_absolute():
            return str(path.resolve().relative_to(repo))
    except (OSError, ValueError):
        pass
    return text


def _tool_input_summary(tool_name: str, tool_input: object, repo: Path) -> dict[str, Any]:
    if not isinstance(tool_input, dict):
        return {}
    summary: dict[str, Any] = {}
    for key in ("file_path", "notebook_path", "path", "localPath"):
        if key in tool_input:
            summary[key] = _safe_path(tool_input[key], repo)
    for key in ("description", "subject", "taskId", "query", "url"):
        if key in tool_input:
            summary[key] = sanitize_text(tool_input[key], 500)
    if tool_name == "Bash" and "command" in tool_input:
        command = sanitize_text(tool_input["command"], 500)
        summary["command"] = command.splitlines()[0] if command else ""
    return {key: value for key, value in summary.items() if value not in (None, "", [])}


def _event_from_payload(payload: dict[str, Any], repo: Path) -> dict[str, Any]:
    event_name = sanitize_text(payload.get("hook_event_name") or "Unknown", 80)
    event: dict[str, Any] = {
        "at": _now(),
        "event": event_name,
        "session_id": sanitize_text(payload.get("session_id"), 160),
    }
    transcript = payload.get("transcript_path")
    if transcript:
        event["transcript_path"] = _safe_path(transcript, repo)

    if event_name == "UserPromptSubmit":
        event["prompt"] = sanitize_text(payload.get("prompt"), MAX_OBJECTIVE_TEXT)
    if event_name in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
        tool_name = sanitize_text(payload.get("tool_name"), 100)
        event["tool"] = tool_name
        event["tool_use_id"] = sanitize_text(payload.get("tool_use_id"), 160)
        event["input"] = _tool_input_summary(tool_name, payload.get("tool_input"), repo)
        if event_name == "PostToolUseFailure":
            event["error"] = sanitize_text(
                payload.get("error") or payload.get("tool_response"), 800
            )
        elif event_name == "PostToolUse":
            event["outcome"] = "completed"
    if event_name in {"PreCompact", "PostCompact"}:
        event["trigger"] = sanitize_text(payload.get("trigger"), 80)
        summary = payload.get("summary") or payload.get("compact_summary")
        if summary:
            event["summary"] = sanitize_text(summary, MAX_TEXT)
    if event_name in {"Stop", "StopFailure", "SessionEnd"}:
        event["reason"] = sanitize_text(
            payload.get("reason") or payload.get("stop_reason") or payload.get("last_assistant_message"),
            1_000,
        )
    return {key: value for key, value in event.items() if value not in (None, "", {})}


def _append_event_log(path: Path, event: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_EVENT_LOG_BYTES:
        data = path.read_bytes()[-(MAX_EVENT_LOG_BYTES // 2) :]
        newline = data.find(b"\n")
        if newline >= 0:
            data = data[newline + 1 :]
        _atomic_write_text(path, data.decode("utf-8", errors="ignore"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _update_state(state: dict[str, Any], event: dict[str, Any], repo: Path) -> dict[str, Any]:
    previous_event = state.get("last_event") if isinstance(state.get("last_event"), dict) else {}
    previous_session = str(state.get("active_session") or "")
    session_id = str(event.get("session_id") or previous_session)
    event_name = str(event.get("event") or "Unknown")

    if event_name == "SessionStart" and previous_session and previous_session != session_id:
        if previous_event.get("event") not in {"Stop", "SessionEnd"}:
            state["interrupted"] = {
                "session_id": previous_session,
                "detected_at": event["at"],
                "last_event": previous_event,
                "pending_actions": list(state.get("pending_actions") or []),
            }
        else:
            state.pop("interrupted", None)
    if session_id:
        state["active_session"] = session_id

    if event_name == "UserPromptSubmit" and event.get("prompt"):
        state["current_objective"] = event["prompt"]
        prompts = list(state.get("recent_prompts") or [])
        prompts.append({"at": event["at"], "prompt": event["prompt"]})
        state["recent_prompts"] = prompts[-MAX_PROMPTS:]

    pending = [item for item in list(state.get("pending_actions") or []) if isinstance(item, dict)]
    tool_use_id = str(event.get("tool_use_id") or "")
    if event_name == "PreToolUse":
        pending = [item for item in pending if item.get("tool_use_id") != tool_use_id]
        pending.append(
            {
                "started_at": event["at"],
                "tool_use_id": tool_use_id,
                "tool": event.get("tool", ""),
                "input": event.get("input", {}),
            }
        )
    elif event_name in {"PostToolUse", "PostToolUseFailure"}:
        pending = [item for item in pending if item.get("tool_use_id") != tool_use_id]
    state["pending_actions"] = pending[-20:]

    events = [item for item in list(state.get("recent_events") or []) if isinstance(item, dict)]
    events.append(event)
    state.update(
        {
            "schema": 1,
            "workspace": str(repo),
            "updated_at": event["at"],
            "last_event": event,
            "recent_events": events[-MAX_EVENTS:],
        }
    )
    return state


def _event_label(event: dict[str, Any]) -> str:
    name = str(event.get("event") or "Unknown")
    if event.get("tool"):
        name += f" {event['tool']}"
    detail = event.get("input") or event.get("reason") or event.get("summary")
    if detail:
        rendered = json.dumps(detail, ensure_ascii=False) if isinstance(detail, dict) else str(detail)
        name += f": {sanitize_text(rendered, MAX_RENDERED_DETAIL)}"
    return name


def render_checkpoint_markdown(state: dict[str, Any]) -> str:
    lines = [
        LIVE_START,
        "## Live recovery checkpoint",
        "",
        f"- Updated: `{state.get('updated_at', 'unknown')}`",
        f"- Active session: `{state.get('active_session', 'unknown')}`",
    ]
    objective = sanitize_text(state.get("current_objective"), MAX_OBJECTIVE_TEXT)
    if objective:
        lines.extend(["", "### Current objective", objective])
    interrupted = state.get("interrupted")
    if isinstance(interrupted, dict):
        lines.extend(
            [
                "",
                "### Interrupted session to recover",
                f"- Session: `{sanitize_text(interrupted.get('session_id'), 160)}`",
                f"- Last event: {_event_label(interrupted.get('last_event') or {})}",
            ]
        )
    pending = state.get("pending_actions")
    if isinstance(pending, list) and pending:
        lines.extend(["", "### Unfinished actions"])
        for item in pending[-5:]:
            lines.append(f"- {_event_label({'event': 'pending', **item})}")
        if len(pending) > 5:
            lines.append(f"- … {len(pending) - 5} older pending action(s) omitted")
    events = state.get("recent_events")
    if isinstance(events, list) and events:
        lines.extend(["", "### Recent checkpoint events"])
        for item in events[-6:]:
            lines.append(f"- `{item.get('at', '')}` {_event_label(item)}")
        if len(events) > 6:
            lines.append(f"- … {len(events) - 6} older event(s) omitted")
    lines.extend([LIVE_END, ""])
    return "\n".join(lines)


def _replace_live_block(project_memory: Path, block: str) -> None:
    existing = project_memory.read_text(encoding="utf-8", errors="replace") if project_memory.exists() else ""
    if LIVE_START in existing and LIVE_END in existing:
        before, _, rest = existing.partition(LIVE_START)
        _, _, after = rest.partition(LIVE_END)
        content = before.rstrip() + "\n\n" + block
        if after.strip():
            content += "\n" + after.lstrip()
    elif BINGO_AUTO_START in existing:
        before, separator, after = existing.partition(BINGO_AUTO_START)
        content = before.rstrip() + "\n\n" + block + "\n"
        if separator:
            content += BINGO_AUTO_START + after
    else:
        content = existing.rstrip() + "\n\n" + block
    _atomic_write_text(project_memory, content.rstrip() + "\n")


def record_hook_checkpoint(cwd: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """Durably record one local lifecycle event and refresh recovery context."""
    repo = Path(cwd).resolve()
    event = _event_from_payload(payload, repo)
    with memory_write_lock(repo):
        state = _update_state(load_checkpoint(repo), event, repo)
        _atomic_write_text(
            checkpoint_path(repo),
            json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        _append_event_log(event_log_path(repo), event)
        project_memory = bingo_project_memory_path(repo)
        project_memory.parent.mkdir(parents=True, exist_ok=True)
        _replace_live_block(project_memory, render_checkpoint_markdown(state))
    return state


def render_recovery_context(cwd: str | Path, max_bytes: int = MAX_CONTEXT_BYTES) -> str:
    state = load_checkpoint(cwd)
    if not state:
        return "No live recovery checkpoint exists yet."
    content = render_checkpoint_markdown(state)
    encoded = content.encode("utf-8")
    if len(encoded) > max_bytes:
        content = encoded[:max_bytes].decode("utf-8", errors="ignore")
        content += "\n[Checkpoint truncated; read .bingo/live-checkpoint.json.]"
    return content
