@AGENTS.md
@.bingo/project-memory.md

## Claude Code project memory

- Treat the imported Bingo project memory as the shared continuity record for every main agent, resumed session, compacted session, and subagent.
- Project hooks synchronize the current Git/worktree state automatically. Before substantial work, use the latest hook-provided context and preserve unrelated user changes.
- Record durable continuity only: confirmed decisions, current implementation status, verification results, blockers, and concrete next steps.
- Never store raw conversations, API keys, access tokens, cookies, authorization headers, private keys, `.env` contents, target PII, credentials, loot, or other secret values in project memory.
- Claude Code retains full session transcripts separately. `.bingo/project-memory.md` is a sanitized cross-agent summary, not a transcript mirror.
- Memory automation is project infrastructure and must be preserved when restoring or replacing Bingo source versions.
