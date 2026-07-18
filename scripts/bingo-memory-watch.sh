#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
python_bin=${PYTHON:-python3}
memory_script="$repo_root/bingo/core/change_memory.py"
memory_root="$repo_root/.bingo/memory"
poll_interval=${BINGO_MEMORY_POLL:-2}

exec "$python_bin" "$memory_script" \
  --cwd "$repo_root" \
  --memory-root "$memory_root" \
  --watch \
  --poll-interval "$poll_interval" \
  --sync-project-memory
