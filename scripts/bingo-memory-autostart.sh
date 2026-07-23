#!/bin/sh
set -eu

repo_root=$(git rev-parse --show-toplevel)
pid_file="$repo_root/.bingo/bingo-memory-watch.pid"
stdout_log="$repo_root/.bingo/bingo-memory-watch.log"
stderr_log="$repo_root/.bingo/bingo-memory-watch.err"
watch_script="$repo_root/scripts/bingo-memory-watch.sh"
sync_script="$repo_root/scripts/bingo-memory-sync.sh"

mkdir -p "$repo_root/.bingo"

"$sync_script" >/dev/null 2>>"$stderr_log" || true

if [ -f "$pid_file" ]; then
  old_pid=$(cat "$pid_file" 2>/dev/null || true)
  if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    old_command=$(ps -p "$old_pid" -o command= 2>/dev/null || true)
    case "$old_command" in
      *"$watch_script"*)
        echo "$old_pid"
        exit 0
        ;;
    esac
  fi
  rm -f "$pid_file"
fi

nohup "$watch_script" >>"$stdout_log" 2>>"$stderr_log" &
new_pid=$!
printf '%s\n' "$new_pid" > "$pid_file"
echo "$new_pid"
