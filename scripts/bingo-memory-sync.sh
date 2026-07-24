#!/bin/sh
# bingo-memory-sync: worktree 변경 후 live-checkpoint 갱신
set -eu

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
python_bin=${PYTHON:-python3}
hook="$repo_root/.claude/hooks/bingo-memory-hook.py"

if [ -f "$hook" ]; then
    echo '{"hook_event_name":"PostToolUse"}' | "$python_bin" "$hook" >/dev/null 2>&1 || true
fi
