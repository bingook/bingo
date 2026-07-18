#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
python_bin=${PYTHON:-python3}
memory_script="$repo_root/bingo/core/change_memory.py"
memory_root="$repo_root/.codex/bingo-memory"

exec "$python_bin" "$memory_script" \
  --cwd "$repo_root" \
  --memory-root "$memory_root" \
  --snapshot \
  --sync-codex-memory
