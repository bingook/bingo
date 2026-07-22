#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def _run(command: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        env=env,
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}
    event = str(payload.get("hook_event_name") or "")
    repo = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
    sync_script = repo / "scripts" / "bingo-memory-sync.sh"
    autostart_script = repo / "scripts" / "bingo-memory-autostart.sh"

    if event == "SessionStart":
        env = dict(os.environ)
        env["BINGO_MEMORY_BACKGROUND"] = "1"
        _run([str(autostart_script)], env=env)
    else:
        _run([str(sync_script)])

    output: dict[str, object] = {"suppressOutput": True}
    if event in {"SessionStart", "SubagentStart", "PostCompact", "UserPromptSubmit"}:
        try:
            sys.path.insert(0, str(repo))
            from bingo.core.change_memory import render_hook_context

            context = render_hook_context(repo)
        except Exception:
            context = "Bingo memory sync completed; read .bingo/project-memory.md before project work."
        output["hookSpecificOutput"] = {
            "hookEventName": event,
            "additionalContext": context,
        }
    json.dump(output, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
