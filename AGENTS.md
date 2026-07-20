# AGENTS.md — Bingo workspace memory

This repository uses project-local memory. At the start of every Codex session
launched from this folder, read `.bingo/project-memory.md` before modifying or
answering about the project.

Startup routine:

1. Read `.bingo/project-memory.md`.
2. Run `scripts/bingo-memory-autostart.sh` from the repository root.
3. Treat the loaded memory as project context, while preserving unrelated user
   changes in the worktree.

After file edits, formatting, tests that generate files, or other worktree
changes, run `scripts/bingo-memory-sync.sh` from the repository root so the next
session can continue from the current state.

Communication preference:

- Use concise Korean status updates.
- Lead with concrete current state, files changed, commands run, and remaining
  next steps.
- Do not store secrets in `.bingo/project-memory.md`.
