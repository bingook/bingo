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
- Latest target-log issue after v6.2.224:
  - `www.balance-cf.co.kr` run produced 24,651 log lines. Main causes: 60 loops, 1,976 raw `TOOL_CALL` payloads in terminal/session/model history, repeated proof rechecks treated as new progress, 54 target-drift blocks from `.co.kr` → `.co.jp`, and large tool floods such as 46 calls in one loop.
  - Fix direction: keep original TOOL_CALL execution untouched, but compact TOOL_CALL payloads for display/session/model history; de-duplicate repeated progress signatures; stop after repeated no-new-progress escape attempts instead of waiting for loop 60.
  - Validation after fix: `pytest -q tests/test_terminal_completion_regressions.py -q` → `121 passed`; `ruff check --select F821,F811 ...` → passed; `git diff --check` → passed; `pytest -q` → `247 passed`.

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-21T03:23:45+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-21T03:23:45+08:00

### Status
```text
M .bingo/project-memory.md
 M PKG-INFO
 M bingo/__init__.py
 M bingo/ui/terminal.py
 M tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
PKG-INFO                                      |   2 +-
 bingo/__init__.py                             |   2 +-
 bingo/ui/terminal.py                          | 340 +++++++++++++++++++++++++-
 tests/test_terminal_completion_regressions.py | 244 ++++++++++++++++++
 4 files changed, 577 insertions(+), 11 deletions(-)
```

### Added Highlights
- `Version: 6.2.241`
- `__version__ = "6.2.241"`
- `self._action_ledger: dict[str, dict] = {}`
- `_action_sig, _action_summary = BingoTerminal._action_ledger_signature(`
- `_tool_name, _tool_args`
- `)`
- `_skip_action_reason = self._action_ledger_skip_reason(`
- `_action_sig, _action_summary`
- `)`
- `if _skip_action_reason:`
- `_skip_result = (`
- `f"=== TOOL_RESULT: {_tool_name or '?'} ===\n"`
- `"exit_code=-96 success=false\n"`
- `"--- output ---\n"`
- `f"[ACTION_LEDGER_SKIP] {_skip_action_reason}\n"`
- `"This action is already done/blocked in the executor ledger. "`
- `"Choose a different pending vector, endpoint, parameter, or payload class.\n"`
- `f"signature={_action_sig}\n"`
- `f"summary={_action_summary}\n"`
- `"=== END TOOL_RESULT ==="`
- `)`
- `tool_results.append(_skip_result)`
- `continue`
- `self._action_ledger_start(_action_sig, _action_summary)`
- `self._action_ledger_finish(`
- `_action_sig,`
- `_action_summary,`
- `output=_result_str,`
- `success=bool(_ok),`
- `exit_code=int(_ec) if isinstance(_ec, int) else -1,`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:4fdc9f65591f660d32c9a7461681ecc1703ae679 -->
## Code change: fix: improve proxy parsing and runtime sync
- Commit: `4fdc9f65591f`
- Recorded: 2026-07-21T02:46:47+08:00
- Committed: 2026-07-21T02:46:47+08:00

### Files
```text
M	PKG-INFO
M	bingo/__init__.py
M	bingo/proxy/manager.py
M	bingo/tools_ext/pentest_tools.py
M	bingo/ui/terminal.py
```

### Diff Stat
```text
4fdc9f655 fix: improve proxy parsing and runtime sync
 PKG-INFO                         |   2 +-
 bingo/__init__.py                |   2 +-
 bingo/proxy/manager.py           | 245 ++++++++++++++++++++++++++++++++++++---
 bingo/tools_ext/pentest_tools.py |  71 ++++++++++--
 bingo/ui/terminal.py             |  23 ++++
 5 files changed, 315 insertions(+), 28 deletions(-)
```

### Added Highlights
- `Version: 6.2.239`
- `__version__ = "6.2.239"`
- `import urllib.parse`
- `_SCHEME_ALIASES = {`
- `"http": "http",`
- `"https": "https",`
- `"socks": "socks5",`
- `"socks4": "socks4",`
- `"socks4a": "socks4a",`
- `"socks5": "socks5",`
- `"socks5h": "socks5h",`
- `}`
- `_HOST_RE = re.compile(r"^(?:\[[0-9a-f:]+\]|[a-z0-9._-]+)$", re.I)`
- `"""URL 문자열 → ProxyEntry 파싱. 실패 시 None.`
- `Accepts common proxy-list formats:`
- `- scheme://host:port`
- `- scheme://user:pass@host:port`
- `- host:port`
- `- user:pass@host:port`
- `- host:port:user:pass`
- `- user:pass:host:port`
- `- host port user pass / host,port,user,pass / host|port|user|pass`
- `"""`
- `raw = (url or "").strip().strip("'\"")`
- `if not raw or raw.startswith("#"):`
- `return None`
- `raw = re.split(r"\s+#", raw, 1)[0].strip()`
- `if not raw:`
- `return None`
- `parsed = _normalise_proxy_parts(raw)`
<!-- bingo-project-memory:auto:end -->
