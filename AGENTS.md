# AGENTS.md — Bingo workspace memory

This repository uses project-local memory. At the start of every Codex session
launched from this folder, read `.bingo/project-memory.md` before modifying or
answering about the project.

Startup routine:

1. Read `.bingo/project-memory.md` and `.bingo/live-checkpoint.json` when present.
2. Run `scripts/bingo-memory-autostart.sh` from the repository root.
3. If the live checkpoint reports an interrupted session, continue from its
   current objective, unfinished actions, and latest verified event instead of
   repeating discovery from the beginning.
4. Treat the loaded memory as project context, while preserving unrelated user
   changes in the worktree.

Local lifecycle hooks checkpoint every prompt, tool start/result/failure,
compaction, stop, and session boundary. A background watcher captures other
working-tree changes. After file edits, formatting, tests that generate files,
or other worktree changes, run `scripts/bingo-memory-sync.sh` from the repository
root so the next session can continue from the current state.

Communication preference:

- Use concise Korean status updates.
- Lead with concrete current state, files changed, commands run, and remaining
  next steps.
- Do not store secrets in `.bingo/project-memory.md`.

Engineering preference:

- Do not treat forced blocking, suppression, or hard stop rules as the default
  fix. Use them only as temporary safety rails.
- For recurring Bingo agent problems, prefer root-cause architecture changes:
  canonical state, executor-owned URL/action construction, path-only model
  proposals, state-machine transitions, and history/context sanitization.
- If a bug is caused by model freedom over concrete state such as target URL,
  credentials, request profile, or action identity, move ownership of that
  state from model text into executor/state-machine code instead of adding
  another blocklist.
