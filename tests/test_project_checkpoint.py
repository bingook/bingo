from __future__ import annotations

import json
import subprocess
from pathlib import Path

from bingo.core.project_checkpoint import (
    LIVE_START,
    checkpoint_path,
    load_checkpoint,
    record_hook_checkpoint,
    render_recovery_context,
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / ".bingo").mkdir()
    (repo / ".bingo" / "project-memory.md").write_text(
        "# Bingo Project Memory\n\n## Persistent Notes\n\n- keep me\n",
        encoding="utf-8",
    )
    return repo


def test_checkpoint_survives_interrupted_session_and_restores_objective(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "SessionStart",
            "session_id": "old-session",
        },
    )
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "old-session",
            "prompt": "restore 6.2.195 then build crash-safe memory",
        },
    )
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "old-session",
            "tool_use_id": "tool-1",
            "tool_name": "Bash",
            "tool_input": {"command": "pytest -q"},
        },
    )

    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "SessionStart",
            "session_id": "new-session",
        },
    )

    state = load_checkpoint(repo)
    assert checkpoint_path(repo).is_file()
    assert state["current_objective"] == "restore 6.2.195 then build crash-safe memory"
    assert state["interrupted"]["session_id"] == "old-session"
    assert state["interrupted"]["pending_actions"][0]["tool_use_id"] == "tool-1"
    assert state["pending_actions"][0]["input"]["command"] == "pytest -q"
    context = render_recovery_context(repo)
    assert "Interrupted session to recover" in context
    assert "restore 6.2.195" in context
    project_memory = (repo / ".bingo" / "project-memory.md").read_text(encoding="utf-8")
    assert "- keep me" in project_memory
    assert project_memory.count(LIVE_START) == 1


def test_completed_tool_is_removed_from_pending_actions(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    before = {
        "hook_event_name": "PreToolUse",
        "session_id": "session",
        "tool_use_id": "tool-1",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(repo / "file.py")},
    }
    record_hook_checkpoint(repo, before)
    assert load_checkpoint(repo)["pending_actions"]

    record_hook_checkpoint(
        repo,
        {
            **before,
            "hook_event_name": "PostToolUse",
            "tool_response": {"success": True},
        },
    )
    assert load_checkpoint(repo)["pending_actions"] == []


def test_checkpoint_redacts_secrets_from_prompt_and_tool_input(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "session",
            "prompt": "API_KEY=sk-test-secret password=hunter2 Authorization: Bearer abc.def",
        },
    )
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "PreToolUse",
            "session_id": "session",
            "tool_use_id": "tool-1",
            "tool_name": "Bash",
            "tool_input": {"command": "curl -H 'Authorization: Bearer abc.def' example.test"},
        },
    )

    combined = (
        checkpoint_path(repo).read_text(encoding="utf-8")
        + (repo / ".bingo" / "live-events.jsonl").read_text(encoding="utf-8")
        + (repo / ".bingo" / "project-memory.md").read_text(encoding="utf-8")
    )
    assert "sk-test-secret" not in combined
    assert "hunter2" not in combined
    assert "abc.def" not in combined
    assert "[REDACTED]" in combined


def test_clean_session_end_does_not_report_false_interruption(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    record_hook_checkpoint(
        repo,
        {"hook_event_name": "SessionStart", "session_id": "old-session"},
    )
    record_hook_checkpoint(
        repo,
        {"hook_event_name": "SessionEnd", "session_id": "old-session", "reason": "complete"},
    )
    record_hook_checkpoint(
        repo,
        {"hook_event_name": "SessionStart", "session_id": "new-session"},
    )
    assert "interrupted" not in load_checkpoint(repo)


def test_checkpoint_json_is_valid_after_repeated_atomic_updates(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    for index in range(30):
        record_hook_checkpoint(
            repo,
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "session",
                "prompt": f"step {index}",
            },
        )
        json.loads(checkpoint_path(repo).read_text(encoding="utf-8"))
    assert load_checkpoint(repo)["current_objective"] == "step 29"
    assert len(load_checkpoint(repo)["recent_events"]) <= 20


def test_recovery_context_stays_small_after_large_prompt_and_many_events(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    huge_prompt = "recover objective " + ("large notification payload " * 200)
    record_hook_checkpoint(
        repo,
        {
            "hook_event_name": "UserPromptSubmit",
            "session_id": "session",
            "prompt": huge_prompt,
        },
    )
    for index in range(30):
        record_hook_checkpoint(
            repo,
            {
                "hook_event_name": "PreToolUse",
                "session_id": "session",
                "tool_use_id": f"tool-{index}",
                "tool_name": "Bash",
                "tool_input": {"command": "python - <<'PY'\n" + ("print('x')\n" * 200) + "PY"},
            },
        )

    context = render_recovery_context(repo)

    assert "recover objective" in context
    assert len(context.encode("utf-8")) <= 4 * 1024 + 200
    assert "older event(s) omitted" in context
    assert "large notification payload" in context
    assert context.count("print('x')") < 10
