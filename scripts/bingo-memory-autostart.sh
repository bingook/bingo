#!/bin/sh
# bingo-memory-autostart: 세션 시작 시 checkpoint 동기화
set -eu

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
python_bin=${PYTHON:-python3}
hook="$repo_root/.claude/hooks/bingo-memory-hook.py"

if [ -f "$hook" ]; then
    echo '{"hook_event_name":"SessionStart"}' | "$python_bin" "$hook" >/dev/null 2>&1 || true
fi

echo "synced"
