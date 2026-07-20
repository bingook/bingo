# Bingo Project Memory

> Project-local persistent memory for Bingo sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.bingo/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current stable version after Bingo memory rebrand: `6.2.224`.
- Restored workspace from `/Users/jmaker/Desktop/bingo_ai-6.2.218.tar.gz` on 2026-07-20; removed bundled prompt profile txt files and external profile loader changes; bumped package version to `6.2.224` for PyPI release. Validation after restore: `pytest -q` → `237 passed`.
- Latest GLM/custom prompt-hygiene fix as of v6.2.218:
  - Removed model-facing jailbreak-style trigger phrases such as `pre-granted`, `BEHAVIOR OVERRIDE`, `No refusals`, `No disclaimers`, and `CONTINUE REQUIRED` from the main prompt/task/retry/hook paths.
  - `custom` models with names/aliases/base URLs containing `glm`, `qwen`, `zhipu`, `alibaba`, or `dashscope` now route to the GLM/Qwen compatibility prompt instead of the Claude/GPT/custom prompt.
  - Legacy few-shot warmup history is disabled by default (`BINGO_LEGACY_WARMUP_HISTORY=1` opt-in) so providers do not interpret preloaded SQLi/admin-hash examples as prompt injection.
  - No attack modules, embedded skills, TOOL_CALL schema, WAF/SQLi engines, or evidence/reporting paths were disabled.
- Latest model management fix as of v6.2.217:
  - `/model` now supports deleting saved models with `d번호`, `del 번호`, `delete 번호`, `remove 번호`, `rm 번호`, `삭제 번호`, or `删除 번호`.
  - Deleting the active model automatically switches to the first remaining saved model; deleting the last saved model clears `active_model`.
  - Invalid delete indexes do not save or mutate the model list.
- Latest model setup input fix as of v6.2.216:
  - `/model` interactive inputs now catch `UnicodeDecodeError` from broken terminal/IME/paste bytes.
  - Model selection, API key, Base URL, model name, alias, and language prompts use safe retry input handling instead of crashing.
  - Custom provider registration now refuses empty Base URL/model name instead of saving an unusable config after repeated input decode failures.
- Token usage reduction direction as of v6.2.215:
  - Use Token Governor only on the model-input copy of prior context.
  - Do not reduce attack execution, embedded skills, tool calls, payload families, target/session state, or raw evidence/session logs.
  - Large HTML/tool-output context is summarized into `[HTML_SUMMARY]` plus `[EVIDENCE_LINES]`, with `[BINGO_EVIDENCE_LEDGER]` injected so penetration capability and evidence grounding stay intact.
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
- Latest target-log issue after v6.2.212:
  - Deterministic report correctly showed `confirmed=0`, but interactive post-report next-step summary still overclaimed DB/hash/admin progress from model prose.
  - Fix direction: evidence-gate `_suggest_next_steps`; with zero confirmed findings, downgrade unsupported progress summaries and remove post-exploit options such as os-shell/admin insert/hash cracking unless confirmed evidence exists.
  - Earlier Markdown Python example blocks were also auto-executed even when they were generic templates with unresolved placeholders like `URL`, `PARAM`, `VAL`, `BASE_VALUE`, `TRUESIZE`, or `THRESHOLD`.
  - Fix direction: preflight Markdown Python blocks before execution; unresolved template placeholders and SyntaxError blocks return an internal regeneration request instead of runtime execution. Common missing stdlib imports such as `random` are injected before valid codeblock execution.
- Latest target-log issue after v6.2.213:
  - `happymfg.co.kr` run produced a false confirmed SQLi finding from a plain CMS fingerprint block: `FOUND: g5_` / `FOUND: bo_table` was misread as `db_table_extract`.
  - The same run later printed `SQLI_NO_VALID_CHANNEL` and `SQLI_EXTRACTION_FAILURE`, but negative oracle markers were evaluated after the db/table confirmation heuristic.
  - Fix direction: SQLi negative markers outrank SQLi db/table extraction heuristics; DB/table confirmed now requires explicit extraction context such as `Database confirmed`, `Found tables`, `TABLE_EXISTS`, `SHOW TABLES`, or `information_schema` query context. CMS fingerprints alone cannot become confirmed SQLi.
  - Markdown Bash heredoc regex repair now handles raw bytes regex prefixes (`rb'...'`, `br'...'`) so quote classes like `[\\"']` do not produce SyntaxError.
  - User-facing codeblock rendering masks raw internal action directives so `TOOL_CALL:` JSON does not appear in collapsed execution previews.
- Latest target-log issue after v6.2.223:
  - `m.justintime-capital.com` run reached loop 60 with `confirmed=0`; root causes were repeated broken `run_python` SyntaxError, noisy advertising/analytics XHR being counted as progress, and broad standalone 32hex/40char info-disclosure matches.
  - Fix direction: keep TOOL_CALL/run_python/skills enabled, but precheck Python syntax before subprocess execution; repair escaped raw-regex quote classes; count only actionable high-value endpoint/param discoveries as loop progress; require secret/hash context for 40-char AWS secret and 32-hex token findings.
  - Validation after fix: `pytest -q tests/test_terminal_completion_regressions.py -q` → `118 passed`; `ruff check --select F821,F811 ...` → passed; `git diff --check` → passed; `pytest -q` → `243 passed`.

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-20T12:31:59+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-20T12:31:59+08:00

### Status
```text
M .bingo/project-memory.md
 M PKG-INFO
 M bingo/__init__.py
 M bingo/core/change_memory.py
```

### Diff Stat
```text
PKG-INFO                    | 2 +-
 bingo/__init__.py           | 2 +-
 bingo/core/change_memory.py | 7 +++++++
 3 files changed, 9 insertions(+), 2 deletions(-)
```

### Added Highlights
- `Version: 6.2.224`
- `__version__ = "6.2.224"`
- `WORKTREE_START,`
- `WORKTREE_END,`
- `BINGO_AUTO_START,`
- `BINGO_AUTO_END,`
- `}:`
- `continue`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:549afad3865229b3600717a8c779e058dfa40116 -->
## Code change: fix: stabilize scan loop and python tool execution
- Commit: `549afad38652`
- Recorded: 2026-07-20T12:29:02+08:00
- Committed: 2026-07-20T12:29:02+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/core/change_memory.py
M	bingo/tools_ext/builtin/security_audit.py
M	bingo/tools_ext/pentest_tools.py
M	bingo/ui/terminal.py
M	tests/test_change_memory.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
549afad38 fix: stabilize scan loop and python tool execution
 .bingo/project-memory.md                      | 927 ++------------------------
 bingo/core/change_memory.py                   |  50 +-
 bingo/tools_ext/builtin/security_audit.py     |  12 +-
 bingo/tools_ext/pentest_tools.py              |  25 +-
 bingo/ui/terminal.py                          |  91 ++-
 tests/test_change_memory.py                   |  34 +
 tests/test_terminal_completion_regressions.py |  83 +++
 7 files changed, 329 insertions(+), 893 deletions(-)
```

### Added Highlights
- `content = _compact_project_memory_source(source_content) or "_No captured workspace memory yet._"`
- `def _first_commit_block(content: str) -> str:`
- `marker = "<!-- commit:"`
- `start = content.find(marker)`
- `if start < 0:`
- `return ""`
- `candidates = [`
- `pos for pos in (`
- `content.find("\n<!-- commit:", start + len(marker)),`
- `content.find("\n# Workspace Memory", start + len(marker)),`
- `)`
- `if pos > start`
- `]`
- `end = min(candidates) if candidates else len(content)`
- `return content[start:end].strip()`
- `def _compact_project_memory_source(source_content: str) -> str:`
- `"""Keep project memory concise and prevent stale generated history nesting.`
- `Workspace MEMORY.md can accumulate previous project-memory sync output when`
- `committed memory files are recorded.  For the tracked '.bingo' mirror, keep`
- `only the current worktree snapshot and newest commit entry so old deleted`
- `file names or large prompt payloads do not reappear in future sessions.`
- `"""`
- `source_content = source_content.strip()`
- `if not source_content:`
- `return ""`
- `sections: list[str] = []`
- `worktree_match = re.search(`
- `rf"{re.escape(WORKTREE_START)}.*?{re.escape(WORKTREE_END)}",`
- `source_content,`
- `flags=re.DOTALL,`
<!-- bingo-project-memory:auto:end -->

"`
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
