# Bingo Project Memory

> Project-local persistent memory for Bingo sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.bingo/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current stable version after latest execution watchdog work: `6.2.201`.
- Bingo project memory is automatic:
  - At every Bingo session start in this repo, `AGENTS.md` instructs the agent to read this file and silently run `scripts/bingo-memory-autostart.sh`.
  - After every file edit/patch/format/test-generated worktree change, Bingo must silently run `scripts/bingo-memory-sync.sh`.
  - Post-commit hook mirrors committed changes automatically.
- Recent validated command set:
  - `python3 -m py_compile ...`
  - `ruff check --select F821,F811 ...`
  - `git diff --check`
  - `pytest -q`
- Recent full-suite status after latest watchdog/memory work: `211 passed`.
- Recent target-log decisions for `mjh.or.kr`:
  - LFI broad-token false positive fixed: `nginx`/`mysql` words and response-size deltas are candidates only, not confirmed LFI.
  - XSS blocked-payload false positive fixed: `NOT REFLECTED`, `被过滤/不存在`, `403/404`, and `Location=N/A` contexts must not produce `XSS_TRIGGER_DETECTED` or potential findings.
  - SQLi WAF/oracle failures remain `blocked`/low unless stable TRUE/FALSE oracle or cross-tool proof exists.
- Latest target-log issue:
  - Markdown BASH codeblock execution, not TOOL_CALL `run_bash`, caused heartbeat-only hangs up to 3600s because terminal execution used a 24h default timeout.
  - Fixed by bounded codeblock execution limits: `BINGO_EXEC_TIMEOUT` default 180s, `BINGO_EXEC_IDLE_TIMEOUT` default 120s, and wall-clock fallback default timeout+30s.

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-19T16:31:38+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.
<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-19T16:31:38+08:00

### Status
```text
M .bingo/project-memory.md
 D .github/workflows/fp-regression.yml
 M .gitignore
 D README_ko.md
 D README_zh.md
 D assets/logo.png
 D bingo-github-profile.png
 M bingo/__init__.py
 M bingo/cli.py
 M bingo/core/change_memory.py
 M bingo/lang/strings.py
 M bingo/models/system_prompt.py
 M bingo/ui/terminal.py
 D jwt_response.txt
 D lahyl_coordinates.json
 D push.sh
 M scripts/bingo-memory-sync.sh
 M scripts/bingo-memory-watch.sh
 M scripts/git-hooks/post-commit
 M tests/test_change_memory.py
 M tests/test_terminal_completion_regressions.py
?? PKG-INFO
```

### Diff Stat
```text
.github/workflows/fp-regression.yml           |     58 -
 .gitignore                                    |      2 +-
 README_ko.md                                  |   2092 -
 README_zh.md                                  |   2066 -
 assets/logo.png                               |    Bin 231102 -> 0 bytes
 bingo-github-profile.png                      |    Bin 231102 -> 0 bytes
 bingo/__init__.py                             |      2 +-
 bingo/cli.py                                  |      2 +-
 bingo/core/change_memory.py                   |    128 +-
 bingo/lang/strings.py                         |      4 +
 bingo/models/system_prompt.py                 |    134 +-
 bingo/ui/terminal.py                          |    373 +-
 jwt_response.txt                              |      1 -
 lahyl_coordinates.json                        | 464522 -----------------------
 push.sh                                       |     23 -
 scripts/bingo-memory-sync.sh                  |      4 +-
 scripts/bingo-memory-watch.sh                 |      4 +-
 scripts/git-hooks/post-commit                 |     12 +-
 tests/test_change_memory.py                   |    139 +
 tests/test_terminal_completion_regressions.py |    335 +-
 20 files changed, 574 insertions(+), 469327 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.201"`
- `from pathlib import Path`
- `BINGO_MEMORY_FILE = Path(".bingo") / "project-memory.md"`
- `BINGO_AUTO_START = "<!-- bingo-project-memory:auto:start -->"`
- `BINGO_AUTO_END = "<!-- bingo-project-memory:auto:end -->"`
- `".bingo/instruction.md",`
- `WORKTREE_SKIP_PREFIXES = (".bingo/",)`
- `def bingo_project_memory_path(cwd: str | Path) -> Path:`
- `"""Return the project-local memory file that AGENTS.md tells Bingo to read."""`
- `return Path(cwd).resolve() / BINGO_MEMORY_FILE`
- `return result.stdout.strip()`
- `if current_file in HIGHLIGHT_SKIP_PATHS or current_file.startswith(".bingo/"):`
- `diff_stat = _git(repo, ["show", "--format=", "--stat", "--oneline", commit_id])`
- `def _bingo_auto_block(source_path: Path, source_content: str, repo: Path) -> str:`
- `f"{BINGO_AUTO_START}\n"`
- `f"{BINGO_AUTO_END}\n"`
- `def _drop_generated_bingo_tail(tail: str) -> str:`
- `def sync_bingo_project_memory(`
- `"""Mirror workspace memory into '.bingo/project-memory.md' for future Bingo runs.`
- `The auto block is replaced on every sync while any manual notes outside the`
- `block are preserved. AGENTS.md is responsible for making future Bingo`
- `sessions load this file.`
- `path = bingo_project_memory_path(repo)`
- `"> Project-local persistent memory for Bingo sessions launched from this repository.\n"`
- `"- Next Bingo session must read this file before modifying the project.\n"`
- `auto_block = _bingo_auto_block(source, source_content, repo)`
- `elif BINGO_AUTO_START in existing and BINGO_AUTO_END in existing:`
- `before, _, rest = existing.partition(BINGO_AUTO_START)`
- `_, _, after = rest.partition(BINGO_AUTO_END)`
- `after = _drop_generated_bingo_tail(after)`
<!-- working-tree:end -->
<!-- bingo-project-memory:auto:end -->
