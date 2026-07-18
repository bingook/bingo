# Bingo Project Memory

> Project-local persistent memory for AI-assisted bingo development.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current base: restored from `6.2.199` (`ddbff39f5`) before the bad `6.2.200`~`6.2.204` timeout/TOOL_CALL-only experiments.
- Current working release: `6.2.205` = `6.2.199` capability baseline + supervised codeblock runtime.
- Bingo project memory is automatic:
  - At every AI assistant session start in this repo, read this file and silently run `scripts/bingo-memory-autostart.sh`.
  - After every file edit/patch/format/test-generated worktree change, silently run `scripts/bingo-memory-sync.sh`.
  - Post-commit hook records committed changes into local Bingo memory automatically.
- Recent validated command set:
  - `python3 -m py_compile ...`
  - `ruff check --select F821,F811 ...`
  - `git diff --check`
  - `pytest -q`
- Recent full-suite status for `6.2.205`: `201 passed`.

## Runtime Decision

- Markdown `bash/python` codeblock execution remains enabled for capability compatibility.
- The project does not use TOOL_CALL-only policy and does not bridge codeblocks into TOOL_CALL as the primary solution.
- Long-running generated code is handled by supervised runtime state:
  - normal completion returns `JOB_STATE status=completed`;
  - timeout/interruption returns `JOB_STATE status=timeout_interrupted` or equivalent;
  - partial stdout/stderr is preserved under `partial_output`;
  - the model must decide continue/split/pivot/report from evidence.
- Runtime knobs:
  - `BINGO_EXEC_TIMEOUT` default `300`
  - `BINGO_EXEC_IDLE_REPORT` default `30`
  - `BINGO_EXEC_WALL_CLOCK_TIMEOUT` default `timeout + 10~60`

## Public Branding Rule

- Public scripts, tracked memory files, documentation, and hooks use `bingo` naming.
- Do not add worker/tool-specific file names to public repository paths.

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-19T03:48:06+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-19T03:48:06+08:00

### Status
```text
 M bingo/core/change_memory.py
 M scripts/git-hooks/post-commit
```

### Diff Stat
```text
 bingo/core/change_memory.py   | 14 +++++++++++++-
 scripts/git-hooks/post-commit |  3 +--
 2 files changed, 14 insertions(+), 3 deletions(-)
```

### Added Highlights
- `def _without_legacy_worker_lines(content: str) -> str:`
- `"""Remove local worker/cache branded paths from public project memory."""`
- `return "\n".join(`
- `line for line in content.splitlines()`
- `)`
- `name_status = _without_legacy_worker_lines(name_status)`
- `diff_stat = _without_legacy_worker_lines(`
- `_git(repo, ["show", "--format=", "--stat", "--oneline", commit_id])`
- `)`
- `source_content = _without_legacy_worker_lines(source_content)`
- `--memory-root "$memory_root" >/dev/null 2>&1 || true`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:6e7ab01d2c3dc5b8d9e18f8893b6786ce9224158 -->
## Code change: chore: rebrand project memory as bingo memory
- Commit: `6e7ab01d2c3d`
- Recorded: 2026-07-19T03:46:36+08:00
- Committed: 2026-07-19T03:46:36+08:00

### Files
```text
A	.bingo/project-memory.md
M	.gitignore
M	AGENTS.md
M	bingo/core/change_memory.py
A	scripts/bingo-memory-autostart.sh
A	scripts/bingo-memory-stop.sh
A	scripts/bingo-memory-sync.sh
A	scripts/bingo-memory-watch.sh
M	scripts/git-hooks/post-commit
```

### Diff Stat
```text
6e7ab01d2 chore: rebrand project memory as bingo memory
 .bingo/project-memory.md                           |  89 +++++
 .gitignore                                         |   6 +-
 AGENTS.md                                          |   9 +
 bingo/core/change_memory.py                        |  95 +++--
 ...mory-autostart.sh => bingo-memory-autostart.sh} |  14 +-
 scripts/git-hooks/post-commit                      |   4 +-
 10 files changed, 170 insertions(+), 494 deletions(-)
```

### Added Highlights
- `.bingo/*`
- `!.bingo/project-memory.md`
- `PROJECT_MEMORY_FILE = Path(".bingo") / "project-memory.md"`
- `PROJECT_AUTO_START = "<!-- bingo-project-memory:auto:start -->"`
- `PROJECT_AUTO_END = "<!-- bingo-project-memory:auto:end -->"`
- `".bingo/project-memory.md",`
- `WORKTREE_SKIP_PREFIXES = (".bingo/", LEGACY_ASSISTANT_CACHE_PREFIX)`
- `def project_memory_path(cwd: str | Path) -> Path:`
- `"""Return bingo's project-local memory file."""`
- `return Path(cwd).resolve() / PROJECT_MEMORY_FILE`
- `return True`
- `":(exclude).bingo",`
- `":(exclude).bingo/**",`
- `f":(exclude){LEGACY_ASSISTANT_CACHE_PREFIX.rstrip('/')}",`
- `f":(exclude){LEGACY_ASSISTANT_CACHE_PREFIX}**",`
- `if (`
- `current_file in HIGHLIGHT_SKIP_PATHS`
- `or current_file.startswith(".bingo/")`
- `or current_file.startswith(LEGACY_ASSISTANT_CACHE_PREFIX)`
- `):`
- `if text.startswith("<!-- bingo-project-memory:"):`
- `def _project_auto_block(source_path: Path, source_content: str, repo: Path) -> str:`
- `f"{PROJECT_AUTO_START}\n"`
- `f"{PROJECT_AUTO_END}\n"`
- `def _drop_generated_project_tail(tail: str) -> str:`
- `or PROJECT_AUTO_END in stripped`
- `or "### Added Highlights" in stripped`
- `def sync_project_memory(`
- `"""Mirror workspace memory into '.bingo/project-memory.md' for future runs.`
- `block are preserved. AGENTS.md is responsible for making future AI`

<!-- commit:3ebef35dc88726455334c9596259ea157420285d -->
## Code change: chore: rebrand project memory as bingo memory
- Commit: `3ebef35dc887`
- Recorded: 2026-07-19T03:45:29+08:00
- Committed: 2026-07-19T03:45:28+08:00

### Files
```text
M	scripts/git-hooks/post-commit
```

### Diff Stat
```text
3ebef35dc chore: rebrand project memory as bingo memory
 scripts/git-hooks/post-commit     |   4 +-
 6 files changed, 2 insertions(+), 511 deletions(-)
```

### Added Highlights
- `memory_root="$repo_root/.bingo/memory"`
- `--sync-project-memory >/dev/null 2>&1 || true`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.
<!-- bingo-project-memory:auto:end -->
