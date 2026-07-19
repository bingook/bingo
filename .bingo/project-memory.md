# Bingo Project Memory

> Project-local persistent memory for AI-assisted bingo development.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Rollback point for the clean `6.2.199` baseline: commit `07eefa781` (`revert: restore 6.2.199 baseline`).
- Current working release: `6.2.199` restored from commit `07eefa781` code behavior, while keeping public `bingo` memory branding.
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
- Current full-suite status for restored `6.2.199`: `204 passed`.

## Runtime Decision

- Runtime has been reverted away from the raw/hybrid experiment.
- Restored behavior is the older Bingo `TOOL_CALL`-first pipeline from `6.2.199`.
- Markdown codeblock execution is legacy opt-in only via `BINGO_ALLOW_CODEBLOCK_EXEC=1`; default execution expects `TOOL_CALL` helper dispatch.
- The failed raw/hybrid experiment started at `2026-07-19 05:33:54 +0800` with commit `03253633f`.
- Safety backup branch before local revert: `backup-before-raw-revert-20260719`.

## Public Branding Rule

- Public scripts, tracked memory files, documentation, and hooks use `bingo` naming.
- Do not add worker/tool-specific file names to public repository paths.

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-19T16:00:01+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-19T16:00:01+08:00

### Status
```text
 M bingo/__init__.py
 M bingo/core/execution_anchor.py
 M bingo/lang/strings.py
 M bingo/models/base.py
 M bingo/models/system_prompt.py
 M bingo/redteam/verification.py
 M bingo/tools/findings_exporter.py
 M bingo/tools/gnuboard.py
 M bingo/tools/recon_engine.py
 M bingo/tools_ext/autoexploit_modules.py
 M bingo/tools_ext/builtin/advanced_scanners.py
 M bingo/tools_ext/pentest_tools.py
 M bingo/ui/terminal.py
 M tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
 bingo/__init__.py                             |    2 +-
 bingo/core/execution_anchor.py                |    2 +-
 bingo/lang/strings.py                         |   92 +-
 bingo/models/base.py                          |    2 +-
 bingo/models/system_prompt.py                 |  297 ++---
 bingo/redteam/verification.py                 |    2 +-
 bingo/tools/findings_exporter.py              |   10 +-
 bingo/tools/gnuboard.py                       |    6 -
 bingo/tools/recon_engine.py                   |    3 +-
 bingo/tools_ext/autoexploit_modules.py        |    4 +-
 bingo/tools_ext/builtin/advanced_scanners.py  |  110 +-
 bingo/tools_ext/pentest_tools.py              |  285 ++--
 bingo/ui/terminal.py                          | 1739 ++++++++++++++++---------
 tests/test_terminal_completion_regressions.py |  334 +++--
 14 files changed, 1613 insertions(+), 1275 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.199"`
- `},`
- `},`
- `},`
- `},`
- `},`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:f8a6ea583536d3d12dfac14d0b645eb53e20c4d0 -->
## Code change: fix: separate weak param fuzz evidence
- Commit: `f8a6ea583536`
- Recorded: 2026-07-19T15:21:01+08:00
- Committed: 2026-07-19T15:21:01+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/__init__.py
M	bingo/models/system_prompt.py
M	bingo/tools_ext/builtin/advanced_scanners.py
```

### Diff Stat
```text
f8a6ea583 fix: separate weak param fuzz evidence
 .bingo/project-memory.md                     |  84 ++++++++++++++++++--
 bingo/__init__.py                            |   2 +-
 bingo/models/system_prompt.py                |   7 +-
 bingo/tools_ext/builtin/advanced_scanners.py | 110 ++++++++++++++++++++++++---
 4 files changed, 186 insertions(+), 17 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.209"`
- `6. param_fuzz weak_reflections/observations are reconnaissance queues only.`
- `Validate them with the matching Bingo module before treating them as useful`
- `attack parameters.`
- `7. Port-open claims require deterministic TCP connect proof. HTTP status text,`
- `redirects, proxy responses, or timeouts are not port-open evidence.`
- `8. This contract changes evidence promotion only; it does not remove attack`
- `def _dedupe_preserve_order(values: List[str]) -> List[str]:`
- `seen: Set[str] = set()`
- `out: List[str] = []`
- `for value in values:`
- `key = str(value or "").strip()`
- `if not key or key in seen:`
- `continue`
- `seen.add(key)`
- `out.append(key)`
- `return out`
- `def _visible_text_contains_marker(html: str, marker: str) -> bool:`
- `"""Return True only when marker appears in rendered-ish text, not URL echo."""`
- `if not marker or marker not in (html or ""):`
- `return False`
- `text = re.sub(r"(?is)<(script|style|noscript)\b[^>]*>.*?</\1>", " ", html or "")`
- `text = re.sub(r"(?is)<[^>]+>", " ", text)`
- `text = re.sub(r"\s+", " ", text)`
- `return marker in text`
- `def _marker_contexts(html: str, marker: str, max_hits: int = 4) -> List[str]:`
- `contexts: List[str] = []`
- `if not marker:`
- `return contexts`
- `for match in re.finditer(re.escape(marker), html or ""):`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:c874807971ce81e7687d1f6f7f678a3bcea44fa4 -->
## Code change: refactor: add hybrid raw attack assist
- Commit: `c874807971ce`
- Recorded: 2026-07-19T14:09:09+08:00
- Committed: 2026-07-19T14:09:09+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/__init__.py
M	bingo/models/system_prompt.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
c87480797 refactor: add hybrid raw attack assist
 .bingo/project-memory.md                      | 84 ++++++++++++++++++++---
 bingo/__init__.py                             |  2 +-
 bingo/models/system_prompt.py                 | 10 ++-
 bingo/ui/terminal.py                          | 98 ++++++++++++++++++++++++++-
 tests/test_terminal_completion_regressions.py | 40 ++++++++++-
 5 files changed, 218 insertions(+), 16 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.208"`
- `Default runtime behavior is hybrid Bingo execution with raw evidence:`
- `5. Built-in skills and Bingo modules are mandatory first-class assets. For web`
- `candidates, route through Bingo helpers such as sqli_autoexploit, execute_tool`
- `registry tools, WAF/XSS/SSRF/IDOR scanners, and skill references before long`
- `ad-hoc loops.`
- `6. This contract changes evidence promotion only; it does not remove attack`
- `capability or module usage.`
- `@staticmethod`
- `def _hybrid_attack_assist_mode() -> bool:`
- `"""Keep Bingo's built-in skills/modules active while preserving raw evidence.`
- `This is the intended default: Bingo supplies attack technique, module`
- `routing, and helper examples; the model still decides from raw execution`
- `output and cannot promote helper/model prose into confirmed findings.`
- `"""`
- `flag = os.environ.get("BINGO_ATTACK_ASSIST", "1").strip().lower()`
- `return flag not in {"0", "false", "no", "off", "raw-only", "raw_only"}`
- `attack_assist_context: str = "",`
- `feedback = (`
- `if attack_assist_context:`
- `feedback += "\n\n" + attack_assist_context`
- `return feedback`
- `def _build_bingo_attack_assist_context(self, code: str, output: str = "") -> str:`
- `"""Inject Bingo-native module routing without auto-confirming findings."""`
- `if not self._hybrid_attack_assist_mode():`
- `return ""`
- `import re as _assist_re`
- `blob = f"{code}\n{output}".lower()`
- `lines = [`
- `"=== BINGO HYBRID ATTACK ASSIST ===",`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:e481ecc8e464d58c2adfd5c0c6c0aa52ed464270 -->
## Code change: refactor: default to raw execution feedback
- Commit: `e481ecc8e464`
- Recorded: 2026-07-19T12:53:19+08:00
- Committed: 2026-07-19T12:53:19+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
e481ecc8e refactor: default to raw execution feedback
 .bingo/project-memory.md                      | 127 ++++++++++++++++++++++++--
 bingo/ui/terminal.py                          |  62 ++++++++++---
 tests/test_terminal_completion_regressions.py |  10 ++
 3 files changed, 182 insertions(+), 17 deletions(-)
```

### Added Highlights
- `@staticmethod`
- `def _raw_loop_limit_message(count: int, lang: str = "en") -> str:`
- `messages = {`
- `"ko": (`
- `f"⛔ [LOOP_LIMIT_STOP] {count}회 루프 도달 — raw 모드에서 자동 중지.\n"`
- `"보고서/확정 결과를 자동 생성하지 않고 다음 선택지만 표시합니다."`
- `),`
- `"zh": (`
- `f"⛔ [LOOP_LIMIT_STOP] 已达第 {count} 次循环 — raw模式自动停止。\n"`
- `"不自动生成报告或确认结论，只显示下一步选项。"`
- `),`
- `"en": (`
- `f"⛔ [LOOP_LIMIT_STOP] Loop #{count} reached — raw mode auto-stop.\n"`
- `"No automatic report or confirmed conclusion is generated; showing next options only."`
- `),`
- `}`
- `return messages.get(lang, messages["en"])`
- `@staticmethod`
- `def _raw_loop_limit_resume_message(lang: str = "en") -> str:`
- `messages = {`
- `"ko": "Raw 모드 루프가 중지됨 — 자동 보고서 없이 다음 선택지를 표시합니다.",`
- `"zh": "Raw模式循环已停止 — 不自动生成报告，只显示下一步选项。",`
- `"en": "Raw mode loop stopped — showing next options without auto-report.",`
- `}`
- `return messages.get(lang, messages["en"])`
- `if not self._raw_runtime_mode():`
- `self._notify_hashes_found(full_response)`
- `if _raw_runtime_mode:`
- `_loop_stop_msg = "\n" + self._raw_loop_limit_message(`
- `self._exec_loop_count,`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:03253633f78da0387c38a6a6a34bff7d47d63d2b -->
## Code change: refactor: default to raw execution feedback
- Commit: `03253633f78d`
- Recorded: 2026-07-19T05:34:17+08:00
- Committed: 2026-07-19T05:34:17+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/__init__.py
M	bingo/models/system_prompt.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
03253633f refactor: default to raw execution feedback
 .bingo/project-memory.md                      |  95 ++++++++--
 bingo/__init__.py                             |   2 +-
 bingo/models/system_prompt.py                 |  18 ++
 bingo/ui/terminal.py                          | 243 ++++++++++++++++++--------
 tests/test_terminal_completion_regressions.py |  54 +++++-
 5 files changed, 317 insertions(+), 95 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.207"`
- `RAW_RUNTIME_CONTRACT = """`
- `=== BINGO RAW RUNTIME CONTRACT ===`
- `Default runtime behavior is Claude-CLI-style direct execution:`
- `1. Emit fenced bash/python code blocks for runnable work. Bingo executes them and`
- `returns raw stdout/stderr.`
- `2. Treat stdout/stderr as the only evidence source. Your own prose, script labels,`
- `helper print labels, and previous assumptions are not proof.`
- `3. Do not call login, SSRF, SQLi, XSS, RCE, bypass, credential extraction, or data`
- `access CONFIRMED unless the returned output contains deterministic proof for`
- `that exact claim.`
- `4. If evidence is insufficient, keep the candidate and write the next verifier.`
- `Do not fabricate a finding and do not discard a viable technique.`
- `5. Built-in skills and tool knowledge remain available. This contract changes`
- `evidence promotion only; it does not remove attack capability.`
- `""".strip()`
- `+ "\n\n"`
- `+ RAW_RUNTIME_CONTRACT`
- `@staticmethod`
- `def _raw_runtime_mode() -> bool:`
- `"""Return True for Claude-CLI-style raw execution feedback.`
- `Default is raw/thin mode: run fenced bash/python blocks, return stdout/stderr,`
- `and let the model decide the next action from that evidence.  The legacy`
- `heavy auto-analysis path remains available for regression testing via`
- `BINGO_RUNTIME_MODE=classic or BINGO_CLAUDE_CLI_MODE=0.`
- `"""`
- `mode = os.environ.get("BINGO_RUNTIME_MODE", "").strip().lower()`
- `if mode in {"classic", "legacy", "heavy", "bingo"}:`
- `return False`
- `if mode in {"raw", "thin", "claude", "claude-cli", "claude_cli"}:`

<!-- commit:653fb1206a9d1b8556f8582cc89e0fa7855871f7 -->
## Code change: refactor: default to raw execution feedback
- Commit: `653fb1206a9d`
- Recorded: 2026-07-19T05:33:55+08:00
- Committed: 2026-07-19T05:33:54+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/__init__.py
M	bingo/models/system_prompt.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
653fb1206 refactor: default to raw execution feedback
 .bingo/project-memory.md                      |  95 ++++++++--
 bingo/__init__.py                             |   2 +-
 bingo/models/system_prompt.py                 |  18 ++
 bingo/ui/terminal.py                          | 243 ++++++++++++++++++--------
 tests/test_terminal_completion_regressions.py |  54 +++++-
 5 files changed, 317 insertions(+), 95 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.207"`
- `RAW_RUNTIME_CONTRACT = """`
- `=== BINGO RAW RUNTIME CONTRACT ===`
- `Default runtime behavior is Claude-CLI-style direct execution:`
- `1. Emit fenced bash/python code blocks for runnable work. Bingo executes them and`
- `returns raw stdout/stderr.`
- `2. Treat stdout/stderr as the only evidence source. Your own prose, script labels,`
- `helper print labels, and previous assumptions are not proof.`
- `3. Do not call login, SSRF, SQLi, XSS, RCE, bypass, credential extraction, or data`
- `access CONFIRMED unless the returned output contains deterministic proof for`
- `that exact claim.`
- `4. If evidence is insufficient, keep the candidate and write the next verifier.`
- `Do not fabricate a finding and do not discard a viable technique.`
- `5. Built-in skills and tool knowledge remain available. This contract changes`
- `evidence promotion only; it does not remove attack capability.`
- `""".strip()`
- `+ "\n\n"`
- `+ RAW_RUNTIME_CONTRACT`
- `@staticmethod`
- `def _raw_runtime_mode() -> bool:`
- `"""Return True for Claude-CLI-style raw execution feedback.`
- `Default is raw/thin mode: run fenced bash/python blocks, return stdout/stderr,`
- `and let the model decide the next action from that evidence.  The legacy`
- `heavy auto-analysis path remains available for regression testing via`
- `BINGO_RUNTIME_MODE=classic or BINGO_CLAUDE_CLI_MODE=0.`
- `"""`
- `mode = os.environ.get("BINGO_RUNTIME_MODE", "").strip().lower()`
- `if mode in {"classic", "legacy", "heavy", "bingo"}:`
- `return False`
- `if mode in {"raw", "thin", "claude", "claude-cli", "claude_cli"}:`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:48a353c3e8053c6bf902b40efcf8df70ff059e89 -->
## Code change: refactor: remove legacy structured call runtime
- Commit: `48a353c3e805`
- Recorded: 2026-07-19T04:24:47+08:00
- Committed: 2026-07-19T04:24:47+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/__init__.py
M	bingo/core/change_memory.py
M	bingo/core/execution_anchor.py
M	bingo/lang/strings.py
M	bingo/models/base.py
M	bingo/models/system_prompt.py
M	bingo/redteam/verification.py
M	bingo/tools/findings_exporter.py
M	bingo/tools_ext/autoexploit_modules.py
M	bingo/tools_ext/pentest_tools.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
48a353c3e refactor: remove legacy structured call runtime
 .bingo/project-memory.md                      | 194 +++++++-
 bingo/__init__.py                             |   2 +-
 bingo/core/change_memory.py                   |  12 +-
 bingo/core/execution_anchor.py                |   2 +-
 bingo/lang/strings.py                         |  92 +---
 bingo/models/base.py                          |   2 +-
 bingo/models/system_prompt.py                 | 152 ++----
 bingo/redteam/verification.py                 |   2 +-
 bingo/tools/findings_exporter.py              |   2 +-
 bingo/tools_ext/autoexploit_modules.py        |   4 +-
 bingo/tools_ext/pentest_tools.py              | 281 +++++++----
 bingo/ui/terminal.py                          | 657 +-------------------------
 tests/test_terminal_completion_regressions.py |  65 +--
 13 files changed, 483 insertions(+), 984 deletions(-)
```

### Added Highlights
- `__version__ = "6.2.206"`
- `"".join(("TOOL", "_", "CALL")),`
- `"_".join(("tool", "call")),`
- `"tool" + "call",`
- `"".join(("TOOL", "_", "RESULT")),`
- `)`
- `)`
- `"""Remove local worker/cache/runtime-noise lines from public project memory."""`
- `r'=== RUNTIME_RESULT:[\s\S]{0,240}?exit_code=0',`
- `"커스텀 추출 루프를 즉시 중단하고 sqli_autoexploit Python helper 호출로 전환하라."`
- `"立即停止自定义提取循环，改用 sqli_autoexploit Python helper 调用."`
- `"Stop all custom extraction loops immediately. Use the sqli_autoexploit Python helper instead."`
- `"  다음 프록시({next_proxy})로 전환하여 Python helper로 재시도하세요."`
- `"  请切换到下一个代理({next_proxy})，使用 Python helper 重试。"`
- `"  Rotate to next proxy ({next_proxy}) and retry with the Python helper."`
- `"Use fenced bash/python code blocks for runnable work and JOB_STATE for long-running progress."`
- `║   1) '''bash 코드블록                                            ║`
- `║      → curl, python3, heredoc, sqlmap/ghauri fallback 모두 OK.   ║`
- `║   2) '''python 코드블록                                          ║`
- `║      → requests, subprocess, 커스텀 루프, 세션 처리 모두 OK.     ║`
- `║   3) 실행 결과는 JOB_STATE로 돌아오며 partial_output을 보존한다. ║`
- `║   • print()로 결과 출력 (JOB_STATE로 자동 반환)                   ║`
- `║  🚨 CODE BLOCK STANDARD v6.2.206 — bash/python direct execution         ║`
- `║  HTTP 실행: bash curl 또는 Python requests/httpx 코드블록을 직접 사용.       ║`
- `║  🚨 MULTI-LINE PYTHON → '''python 코드블록 권장:                    ║`
- `║    if/for/try/def 포함 코드는 Python 코드블록이 가장 안정적          ║`
- `║  → requests code: prefer '''python code block                      ║`
- `Output: plain text, bash/python code blocks. Long-running work reports JOB_STATE.`
- `RULE #4: ANY Python code with if/for/try/def/class MUST use a fenced python code block.`
- `RULE #5: Boolean oracle loop, char extraction loop → ALWAYS use a fenced python code block. Never bash loop.`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:913ae94d6c4b9bb2a9a478ed24309cc83a0b6ee8 -->
## Code change: chore: rebrand project memory as bingo memory
- Commit: `913ae94d6c4b`
- Recorded: 2026-07-19T03:49:32+08:00
- Committed: 2026-07-19T03:49:32+08:00

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
913ae94d6 chore: rebrand project memory as bingo memory
 .bingo/project-memory.md                           | 173 +++++++++++++++++++++
 .gitignore                                         |   6 +-
 AGENTS.md                                          |   9 ++
 bingo/core/change_memory.py                        | 109 ++++++++-----
 ...mory-autostart.sh => bingo-memory-autostart.sh} |  14 +-
 scripts/git-hooks/post-commit                      |   5 +-
 9 files changed, 267 insertions(+), 61 deletions(-)
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
- `def _without_legacy_worker_lines(content: str) -> str:`
- `"""Remove local worker/cache branded paths from public project memory."""`
- `return "\n".join(`
- `line for line in content.splitlines()`
- `)`
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
- `name_status = _without_legacy_worker_lines(name_status)`
- `diff_stat = _without_legacy_worker_lines(`
- `_git(repo, ["show", "--format=", "--stat", "--oneline", commit_id])`
- `)`

<!-- commit:a4b7c57da7aa43cd044e82b3b45716c379f7b8c9 -->
## Code change: chore: rebrand project memory as bingo memory
- Commit: `a4b7c57da7aa`
- Recorded: 2026-07-19T03:48:58+08:00
- Committed: 2026-07-19T03:48:58+08:00

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
a4b7c57da chore: rebrand project memory as bingo memory
 .bingo/project-memory.md                           | 173 ++++++++
 .gitignore                                         |   6 +-
 AGENTS.md                                          |   9 +
 bingo/core/change_memory.py                        | 109 ++++--
 ...mory-autostart.sh => bingo-memory-autostart.sh} |  14 +-
 scripts/git-hooks/post-commit                      |   5 +-
 10 files changed, 267 insertions(+), 496 deletions(-)
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
- `def _without_legacy_worker_lines(content: str) -> str:`
- `"""Remove local worker/cache branded paths from public project memory."""`
- `return "\n".join(`
- `line for line in content.splitlines()`
- `)`
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
- `name_status = _without_legacy_worker_lines(name_status)`
- `diff_stat = _without_legacy_worker_lines(`
- `_git(repo, ["show", "--format=", "--stat", "--oneline", commit_id])`
- `)`

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
