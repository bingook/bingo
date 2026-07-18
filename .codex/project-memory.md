# Codex Project Memory

> Project-local persistent memory for Codex sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.codex/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current stable version after public execution-policy hardening: `6.2.204`.
- Codex project memory is automatic:
  - At every Codex session start in this repo, `AGENTS.md` instructs the agent to read this file and silently run `scripts/codex-memory-autostart.sh`.
  - After every file edit/patch/format/test-generated worktree change, Codex must silently run `scripts/codex-memory-sync.sh`.
  - Post-commit hook mirrors committed changes automatically.
- Recent validated command set:
  - `python3 -m py_compile ...`
  - `ruff check --select F821,F811 ...`
  - `git diff --check`
  - `pytest -q`
- Recent full-suite status after public execution-policy hardening: `217 passed`.
- Recent target-log decisions for `mjh.or.kr`:
  - LFI broad-token false positive fixed: `nginx`/`mysql` words and response-size deltas are candidates only, not confirmed LFI.
  - XSS blocked-payload false positive fixed: `NOT REFLECTED`, `被过滤/不存在`, `403/404`, and `Location=N/A` contexts must not produce `XSS_TRIGGER_DETECTED` or potential findings.
  - SQLi WAF/oracle failures remain `blocked`/low unless stable TRUE/FALSE oracle or cross-tool proof exists.
- Latest target-log issue:
  - Markdown BASH codeblock execution, not TOOL_CALL `run_bash`, caused heartbeat-only hangs up to 3600s because terminal execution used a 24h default timeout.
  - Fixed by bounded codeblock execution limits: `BINGO_EXEC_TIMEOUT` default 180s, `BINGO_EXEC_IDLE_TIMEOUT` default 120s, and wall-clock fallback default timeout+30s.
- Latest credential false-positive issue:
  - Report showed `{'password': '> 200 登出:'}` under extracted credentials.
  - Fixed by requiring credential key-value separators `:`/`=`, rejecting UI/status/logout/error values, and sanitizing stored/session credentials before agent-knowledge/report use.
- Latest bash codeblock execution issue:
  - Bash blocks starting with `for` loops or variable assignments could be silently skipped even when they contained allowed `curl`/`python3` commands.
  - Fixed by scanning the whole block for allowed executable commands while still ignoring comments and non-exec wrappers like `echo`.
- Latest root execution-policy issue:
  - Public/default GitHub builds must not auto-execute arbitrary raw markdown ```bash/```python codeblocks from model prose.
  - Default execution policy is now TOOL_CALL-only. Raw markdown codeblock execution is disabled unless explicitly opted in with `BINGO_ALLOW_CODEBLOCK_EXEC=1`.
  - Model prompts/retry nudges must ask for `TOOL_CALL` (`http_get`, `run_bash`, `run_python`, structured scanners), not raw code fences.

<!-- codex-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-19T02:03:55+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.codex/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-19T02:03:55+08:00

### Status
```text
M .codex/project-memory.md
 M AGENTS.md
 M bingo/__init__.py
 M bingo/models/system_prompt.py
 M bingo/ui/terminal.py
 M tests/test_change_memory.py
 M tests/test_terminal_completion_regressions.py
?? scripts/codex-memory-autostart.sh
?? scripts/codex-memory-stop.sh
?? scripts/codex-memory-sync.sh
?? scripts/codex-memory-watch.sh
```

### Diff Stat
```text
AGENTS.md                                     |   2 +-
 bingo/__init__.py                             |   2 +-
 bingo/models/system_prompt.py                 | 134 +++++------------
 bingo/ui/terminal.py                          | 205 ++++++++++++++++----------
 tests/test_change_memory.py                   | 139 +++++++++++++++++
 tests/test_terminal_completion_regressions.py | 161 +++++++++++++++++++-
 6 files changed, 466 insertions(+), 177 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.204"`
- `║  일반 Markdown bash/python 코드블록은 기본값에서 실행되지 않는다.          ║`
- `║  1. 실행은 TOOL_CALL 로만 요청할 것                                        ║`
- `║  4. custom Python/bash/외부 도구는 run_python/run_bash TOOL_CALL로 실행    ║`
- `║  🚨 EXECUTION STANDARD v6.2.204 — TOOL_CALL ONLY BY DEFAULT                 ║`
- `║  Public/default runtime: raw '''bash / '''python blocks are documentation    ║`
- `║  only and are NOT executed. Use TOOL_CALL for every executable action.        ║`
- `║  Local legacy opt-in exists only with BINGO_ALLOW_CODEBLOCK_EXEC=1.          ║`
- `║  ✅ CANONICAL PATTERNS — copy one TOOL_CALL at a time:              ║`
- `║  TOOL_CALL:{"name":"http_get","args":{"url":"https://TARGET/path?param=VALUE","timeout":15}} ║`
- `║  TOOL_CALL:{"name":"run_bash","args":{"script":"curl -sk -m 15 -H 'User-Agent: Mozilla/5.0' 'https://TARGET/path?param=VALUE'"}} ║`
- `║  TOOL_CALL:{"name":"run_python","args":{"code":"import requests\nr=requests.get('https://TARGET/',timeout=15,verify=False)\nprint(r.status_code, len(r.text)); print(r.text[:500])`
- `║  🚨 MULTI-LINE PYTHON → run_python TOOL_CALL 필수:                  ║`
- `║  ✅ TIME-BASED BLIND SQLi — use structured tools first:             ║`
- `║  TOOL_CALL:{"name":"sqli_timebased","args":{"url":"https://REAL_TARGET/","param":"id","payload":"1 AND SLEEP(5)--","sleep_time":5}} ║`
- `║  If custom timing is required, wrap curl timing in run_bash TOOL_CALL.║`
- `║  ✅ BLIND BIT EXTRACTION — use bool_oracle_extract first:           ║`
- `║  TOOL_CALL:{"name":"bool_oracle_extract","args":{"url":"https://REAL_TARGET/?id=1","param":"id","true_condition":"1=1","extract_expr":"@@version"}} ║`
- `║  If custom bit loops are required, wrap the loop in run_python TOOL_CALL. ║`
- `║  WHY: bingo executes TOOL_CALL operations and returns TOOL_RESULT.   ║`
- `║  run_bash has curl access; run_python can parse raw response bytes.  ║`
- `║  IF YOU NEED SHELL/PYTHON → USE run_bash/run_python TOOL_CALL.      ║`
- `║  ✅ CORRECT PATTERN — ALWAYS use TOOL_CALL:                         ║`
- `║  TOOL_CALL:{"name":"http_get","args":{"url":"https://REAL_TARGET/path","timeout":15}} ║`
- `║  For custom curl, wrap it in run_bash TOOL_CALL.                    ║`
- `║  WHY YOU THINK YOU CAN'T: You are WRONG. bingo runs TOOL_CALLs on   ║`
- `║  a machine with network/tool access. Test it through TOOL_CALL.      ║`
- `║  run_bash subprocesses have network connectivity when used.          ║`
- `Output: plain text plus exactly one TOOL_CALL for execution. Raw bash/python code blocks are documentation only by default.`
- `1. MANDATORY: Immediately emit a TOOL_CALL to verify the candidates.`
<!-- working-tree:end -->
# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:5c446e876b280d3fa212b64bd211a6883723243c -->
## Code change: fix: execute looped bash codeblocks
- Commit: `5c446e876b28`
- Recorded: 2026-07-19T01:43:27+08:00
- Committed: 2026-07-19T01:43:26+08:00

### Files
```text
M	.codex/project-memory.md
M	AGENTS.md
M	bingo/__init__.py
M	bingo/ui/terminal.py
M	scripts/git-hooks/post-commit
```

### Diff Stat
```text
5c446e876 fix: execute looped bash codeblocks
 .codex/project-memory.md      | 95 +++++++++++++++++++++++++++++++++++--------
 AGENTS.md                     |  2 +-
 bingo/__init__.py             |  2 +-
 bingo/ui/terminal.py          | 74 +++++++++++++++++++++++++++------
 scripts/git-hooks/post-commit | 13 +++++-
 5 files changed, 155 insertions(+), 31 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.203"`
- `_BASH_CONTROL_WORDS = {`
- `"for", "while", "until", "if", "then", "elif", "else", "fi",`
- `"do", "done", "case", "esac", "select", "function",`
- `}`
- `_BASH_NON_EXEC_WRAPPERS = {"echo", "printf"}`
- `def _bash_allowed_command_label(script_text: str) -> str:`
- `"""Return a display label if a Bash block contains an allowed command.`
- `v6.2.203: LLM often emits valid scanner loops such as`
- `'for idx ...; do curl ...; done' or starts scripts with variable`
- `assignments before the first curl/python command.  The old gate`
- `checked only line 1, so those blocks were silently skipped.`
- `"""`
- `heredoc_end: str | None = None`
- `cmd_pattern = re.compile(`
- `r"(?<![A-Za-z0-9_./-])("`
- `+ "|".join(re.escape(cmd) for cmd in sorted(_BASH_ALLOWED, key=len, reverse=True))`
- `+ r")(?=$|[\s'\"\\|;&)<])"`
- `)`
- `heredoc_open = re.compile(r"<<\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")`
- `for raw_line in script_text.splitlines():`
- `stripped = raw_line.strip()`
- `if not stripped or stripped.startswith("#"):`
- `continue`
- `if heredoc_end:`
- `if stripped == heredoc_end:`
- `heredoc_end = None`
- `continue`
- `try:`
- `parts = _shlex_bash.split(stripped.split("|", 1)[0].split("&&", 1)[0])`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:cf5ff6575e597944f07bb27dbf3cb9f1962730d6 -->
## Code change: fix: suppress credential evidence false positives
- Commit: `cf5ff6575e59`
- Recorded: 2026-07-19T00:52:18+08:00
- Committed: 2026-07-19T00:52:18+08:00

### Files
```text
M	.codex/project-memory.md
M	AGENTS.md
M	bingo/__init__.py
M	bingo/lang/strings.py
M	bingo/tools/gnuboard.py
M	bingo/tools/recon_engine.py
M	bingo/ui/terminal.py
```

### Diff Stat
```text
cf5ff6575 fix: suppress credential evidence false positives
 .codex/project-memory.md    | 101 ++++++++++++++-----
 AGENTS.md                   |   2 +-
 bingo/__init__.py           |   2 +-
 bingo/lang/strings.py       |   4 +
 bingo/tools/gnuboard.py     |   6 --
 bingo/tools/recon_engine.py |   3 +-
 bingo/ui/terminal.py        | 235 ++++++++++++++++++++++++++++++++++----------
 7 files changed, 266 insertions(+), 87 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.202"`
- `"script_killed_idle_timeout": {`
- `"ko": "[스크립트_종료: 유휴_타임아웃]\n스크립트가 {sec}초 동안 출력을 내지 않아 강제 종료되었습니다.\n요청별 타임아웃을 추가하거나, 루프를 줄이거나, 스크립트를 더 작은 블록으로 나누세요.",`
- `"zh": "[脚本已终止: 空闲超时]\n脚本连续{sec}秒没有输出，已被强制终止。\n请为单个请求添加超时、减少循环或将脚本拆分为更小的块。",`
- `"en": "[SCRIPT_KILLED: IDLE_TIMEOUT]\nScript produced no output for {sec}s and was forcibly terminated.\nAdd per-request timeouts, reduce loops, or split the script into smaller bl`
- `if re.match(r"^\d+\.\d+\.\d+\.\d+$", ln)]`
- `def _positive_int_env(`
- `name: str,`
- `default: int,`
- `minimum: int = 1,`
- `maximum: int = 86_400,`
- `) -> int:`
- `"""Return a bounded positive integer from the environment."""`
- `raw = os.environ.get(name)`
- `if raw is None:`
- `return default`
- `try:`
- `value = int(str(raw).strip())`
- `except (TypeError, ValueError):`
- `return default`
- `return max(minimum, min(value, maximum))`
- `def _codeblock_exec_limits() -> tuple[int, int, int]:`
- `"""Execution limits for markdown Python/Bash code blocks."""`
- `script_timeout = _positive_int_env("BINGO_EXEC_TIMEOUT", 180)`
- `idle_timeout = _positive_int_env(`
- `"BINGO_EXEC_IDLE_TIMEOUT",`
- `120,`
- `maximum=script_timeout,`
- `)`
- `wall_clock_timeout = _positive_int_env(`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:4e7a7e601e061febaa7b5c3b565c4567c9fc3bee -->
## Code change: fix: bound codeblock execution watchdog
- Commit: `4e7a7e601e06`
- Recorded: 2026-07-19T00:07:54+08:00
- Committed: 2026-07-19T00:07:54+08:00

### Files
```text
A	.codex/project-memory.md
M	.gitignore
M	AGENTS.md
M	bingo/__init__.py
M	bingo/cli.py
M	bingo/core/change_memory.py
```

### Diff Stat
```text
4e7a7e601 fix: bound codeblock execution watchdog
 .codex/project-memory.md    | 179 +++++++++++++++++++++
 .gitignore                  |   4 +
 AGENTS.md                   | 383 +++++++++++++++++++++++++++++++++++++++++---
 bingo/__init__.py           |   2 +-
 bingo/cli.py                |   2 +-
 bingo/core/change_memory.py | 201 +++++++++++++++++++++--
 6 files changed, 735 insertions(+), 36 deletions(-)
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
