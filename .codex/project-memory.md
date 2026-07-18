# Codex Project Memory

> Project-local persistent memory for Codex sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.codex/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current stable version after latest execution watchdog work: `6.2.201`.
- Codex project memory is automatic:
  - At every Codex session start in this repo, `AGENTS.md` instructs the agent to read this file and silently run `scripts/codex-memory-autostart.sh`.
  - After every file edit/patch/format/test-generated worktree change, Codex must silently run `scripts/codex-memory-sync.sh`.
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

<!-- codex-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-18T23:43:35+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.codex/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-18T23:43:35+08:00

### Status
```text
M .gitignore
 M AGENTS.md
 M bingo/__init__.py
 M bingo/cli.py
 M bingo/core/change_memory.py
 M bingo/lang/strings.py
 M bingo/tools/gnuboard.py
 M bingo/tools/recon_engine.py
 M bingo/ui/terminal.py
 M scripts/git-hooks/post-commit
 M tests/test_change_memory.py
 M tests/test_terminal_completion_regressions.py
?? scripts/codex-memory-autostart.sh
?? scripts/codex-memory-stop.sh
?? scripts/codex-memory-sync.sh
?? scripts/codex-memory-watch.sh
```

### Diff Stat
```text
.gitignore                                    |   4 +
 AGENTS.md                                     | 383 ++++++++++++++++++++++++--
 bingo/__init__.py                             |   2 +-
 bingo/cli.py                                  |   2 +-
 bingo/core/change_memory.py                   | 201 +++++++++++++-
 bingo/lang/strings.py                         |   4 +
 bingo/tools/gnuboard.py                       |   6 -
 bingo/tools/recon_engine.py                   |   3 +-
 bingo/ui/terminal.py                          | 141 +++++++---
 scripts/git-hooks/post-commit                 |  13 +-
 tests/test_change_memory.py                   | 139 ++++++++++
 tests/test_terminal_completion_regressions.py |  36 +++
 12 files changed, 844 insertions(+), 90 deletions(-)
```

### Added Highlights
- `.codex/*`
- `!.codex/project-memory.md`
- `__version__ = "6.2.201"`
- `from pathlib import Path`
- `CODEX_MEMORY_FILE = Path(".codex") / "project-memory.md"`
- `CODEX_AUTO_START = "<!-- codex-project-memory:auto:start -->"`
- `CODEX_AUTO_END = "<!-- codex-project-memory:auto:end -->"`
- `HIGHLIGHT_SKIP_PATHS = {`
- `"AGENTS.md",`
- `".codex/instruction.md",`
- `".codex/project-memory.md",`
- `}`
- `WORKTREE_SKIP_PREFIXES = (".codex/",)`
- `)`
- `def codex_project_memory_path(cwd: str | Path) -> Path:`
- `"""Return the project-local memory file that AGENTS.md tells Codex to read."""`
- `return Path(cwd).resolve() / CODEX_MEMORY_FILE`
- `def _skip_worktree_path(path: str) -> bool:`
- `normalized = path.strip().strip('"')`
- `if " -> " in normalized:`
- `return any(_skip_worktree_path(part) for part in normalized.split(" -> ", 1))`
- `return any(`
- `normalized == prefix.rstrip("/") or normalized.startswith(prefix)`
- `for prefix in WORKTREE_SKIP_PREFIXES`
- `)`
- `def _worktree_status(cwd: Path) -> str:`
- `status = _git(cwd, ["status", "--short"])`
- `lines = []`
- `for line in status.splitlines():`
- `path = line[3:] if len(line) > 3 else ""`
<!-- working-tree:end -->










# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:a1a2dca52d914b967e60d87a263d8ccffbbd3b7e -->
## Code change: fix: suppress blocked XSS payload false positives
- Commit: `a1a2dca52d91`
- Recorded: 2026-07-18T22:10:58+08:00
- Committed: 2026-07-18T22:02:29+08:00

### Files
```text
M	bingo/__init__.py
M	bingo/tools/findings_exporter.py
M	bingo/tools_ext/pentest_tools.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
a1a2dca52 fix: suppress blocked XSS payload false positives
 bingo/__init__.py                             |   2 +-
 bingo/tools/findings_exporter.py              |   8 +-
 bingo/tools_ext/pentest_tools.py              |   4 +-
 tests/test_terminal_completion_regressions.py | 111 ++++++++++++++++++++++++++
 4 files changed, 120 insertions(+), 5 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.200"`
- `r'XSS.{0,40}(?:confirmed|executed|browser\s+verified))',`
- `r'no\s+xss|not\s+vulnerable|被过滤|过滤|被拦截|拦截|不存在|'`
- `r'(?:status|状态)\s*[:=]?\s*(?:403|404)\b|'`
- `r'\b(?:403|404)\s*/\s*\d+B\b|Location\s*=\s*N/A',`
- `r'XSS.{0,40}(?:confirmed|executed|browser\s+verified|success)',`
- `r'no\s+xss|not\s+vulnerable|被过滤|过滤|被拦截|拦截|不存在|'`
- `r'(?:status|状态)\s*[:=]?\s*(?:403|404)\b|'`
- `r'\b(?:403|404)\s*/\s*\d+B\b|Location\s*=\s*N/A',`
- `_inject_vuln_trigger_notice,`
- `def test_xss_trigger_ignores_not_reflected_payload_text(tmp_path: Path) -> None:`
- `payload = '"><script>alert(1)</script>'`
- `output = (`
- `"HTTP 200\n"`
- `f"[NOT REFLECTED] payload: {payload}\n"`
- `"browser_confirmed=false\n"`
- `)`
- `assert "XSS_TRIGGER_DETECTED" not in _inject_vuln_trigger_notice(output)`
- `exporter = FindingsExporter(target="https://example.test", output_dir=str(tmp_path))`
- `assert exporter.process(output, code_snippet="run_python xss smoke") is None`
- `assert exporter.findings == []`
- `def test_xss_trigger_ignores_filtered_or_403_payload_text(tmp_path: Path) -> None:`
- `output = (`
- `"=== XSS 反射测试 ===\n"`
- `"url=javascript:alert(1): 403 Location=N/A\n"`
- `"url=data:text/html,<script>alert(1)</script>: 403 Location=N/A\n"`
- `"被过滤/不存在: <script>alert(1)</script> | 199B\n"`
- `"被过滤/不存在: <img src=x onerror=alert(1)> | 199B\n"`
- `)`
- `assert "XSS_TRIGGER_DETECTED" not in _inject_vuln_trigger_notice(output)`
<!-- codex-project-memory:auto:end -->
