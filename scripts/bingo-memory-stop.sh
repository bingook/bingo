#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
pid_file="$repo_root/.bingo/bingo-memory-watch.pid"

if [ ! -f "$pid_file" ]; then
  exit 0
fi

pid=$(cat "$pid_file" 2>/dev/null || true)
if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
  kill "$pid" >/dev/null 2>&1 || true
fi
rm -f "$pid_file"
