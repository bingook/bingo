# Bingo Project Memory

> Project-local persistent memory for Bingo sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.bingo/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current local working version after v7 foundation start: `6.2.251`.
- v6.2.251 architecture direction: keep the chat UI shell, but rebuild the core around `bingo/core/v7/` typed contracts. Planner proposes intent only; mission state machine owns phase; executor owns action envelopes and target identity; coverage ledger owns remaining test surfaces; evidence graph owns finding promotion and report truth.
- v6.2.250 root-fix direction: do not solve quality failures by adding more hard blocks. Promote executor-observed evidence into state: public dependency artifacts, stack traces, and admin username-enumeration differentials become confirmed findings; UI/action ledger keys canonicalized args, not model-drifted hosts; confirmed-evidence plateau stops with report-first instead of more low-value loops.
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

- Last synced: 2026-07-22T04:21:20+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-22T04:21:20+08:00

### Status
```text
M .bingo/project-memory.md
 M PKG-INFO
 M README.md
 M bingo/__init__.py
 M bingo/core/executor_state.py
 M bingo/ui/terminal.py
 M docs/ENGINEERING.md
 M tests/test_terminal_completion_regressions.py
?? bingo/core/session_bridge.py
?? bingo/core/v7/
?? docs/BINGO_V7_ARCHITECTURE.md
?? tests/test_v7_architecture.py
```

### Diff Stat
```text
PKG-INFO                                      |   11 +-
 README.md                                     |    9 +-
 bingo/__init__.py                             |    2 +-
 bingo/core/executor_state.py                  |  476 +++----
 bingo/ui/terminal.py                          | 1824 ++++++-------------------
 docs/ENGINEERING.md                           |   24 +
 tests/test_terminal_completion_regressions.py |  302 +++-
 7 files changed, 875 insertions(+), 1773 deletions(-)
```

### Added Highlights
- `Version: 6.2.251`
- `[![Version](https://img.shields.io/badge/version-6.2.251-brightgreen)](https://github.com/bingook/bingo/releases)`
- `| v6.2.251 | **Bingo v7 foundation** — added 'bingo/core/v7/' as the new typed core: mission state machine, coverage ledger, evidence graph, executor action envelope, and determini`
- `| v3.2.94 | **Dead-loop detection overhaul** — legacy retry-counter design for INFINITE_LOOP_RISK; superseded by v6.2.251 executor runtime-budget instrumentation, so loop risk is b`
- `| v3.2.91 | **Fix: INFINITE_LOOP_RISK over-detection + Ctrl+C hang** — legacy loop retry-counter design; superseded by v6.2.251 executor runtime-budget instrumentation. Cursor-patt`
- `[![Version](https://img.shields.io/badge/version-6.2.251-brightgreen)](https://github.com/bingook/bingo/releases)`
- `[![Version](https://img.shields.io/badge/version-6.2.251-brightgreen)](https://github.com/bingook/bingo/releases)`
- `| v6.2.251 | **Bingo v7 foundation** — added 'bingo/core/v7/' as the new typed core: mission state machine, coverage ledger, evidence graph, executor action envelope, and determini`
- `| v3.2.94 | **Dead-loop detection overhaul** — legacy retry-counter design for INFINITE_LOOP_RISK; superseded by v6.2.251 executor runtime-budget instrumentation, so loop risk is b`
- `| v3.2.91 | **Fix: INFINITE_LOOP_RISK over-detection + Ctrl+C hang** — legacy loop retry-counter design; superseded by v6.2.251 executor runtime-budget instrumentation. Cursor-patt`
- `[![Version](https://img.shields.io/badge/version-6.2.251-brightgreen)](https://github.com/bingook/bingo/releases)`
- `__version__ = "6.2.251"`
- `from .v7.loop_policy import (`
- `doom_loop_cutoff_reason,`
- `has_meaningful_loop_progress,`
- `ledger_skip_count,`
- `low_value_reentry_count,`
- `meaningful_loop_progress_signature,`
- `no_progress_penalty,`
- `repeated_response_pattern,`
- `response_pattern_signature,`
- `strip_action_ledger_skip_noise,`
- `target_drift_block_count,`
- `)`
- `def canonical_action_args(tool_name: str, args: dict) -> dict:`
- `"""Return executor-normalized args for stable action identity.`
- `This mirrors execution-time target canonicalization so the action ledger`
- `never stores model-drifted hosts as distinct identities.`
- `"""`
- `if not isinstance(args, dict):`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:0985c1b55b59b996fbe183788cf47899b073e92b -->
## Code change: fix: promote runtime evidence into executor state
- Commit: `0985c1b55b59`
- Recorded: 2026-07-21T23:45:57+08:00
- Committed: 2026-07-21T23:45:57+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	README.md
M	bingo/__init__.py
M	bingo/core/executor_state.py
M	bingo/tools/findings_exporter.py
M	bingo/ui/terminal.py
M	docs/ENGINEERING.md
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
0985c1b55 fix: promote runtime evidence into executor state
 .bingo/project-memory.md                      | 186 ++++++++++----------
 PKG-INFO                                      |  11 +-
 README.md                                     |   9 +-
 bingo/__init__.py                             |   2 +-
 bingo/core/executor_state.py                  |  35 ++++
 bingo/tools/findings_exporter.py              | 239 +++++++++++++++++++++++++-
 bingo/ui/terminal.py                          |  42 ++++-
 docs/ENGINEERING.md                           |  39 ++++-
 tests/test_terminal_completion_regressions.py |  83 +++++++++
 9 files changed, 541 insertions(+), 105 deletions(-)
```

### Added Highlights
- `Version: 6.2.250`
- `[![Version](https://img.shields.io/badge/version-6.2.250-brightgreen)](https://github.com/bingook/bingo/releases)`
- `| v6.2.250 | **Executor evidence-state upgrade** — promotes concrete runtime observations such as public 'composer.json'/'composer.lock'/'vendor/composer/installed.json', server st`
- `| v3.2.94 | **Dead-loop detection overhaul** — legacy retry-counter design for INFINITE_LOOP_RISK; superseded by v6.2.250 executor runtime-budget instrumentation, so loop risk is b`
- `| v3.2.91 | **Fix: INFINITE_LOOP_RISK over-detection + Ctrl+C hang** — legacy loop retry-counter design; superseded by v6.2.250 executor runtime-budget instrumentation. Cursor-patt`
- `[![Version](https://img.shields.io/badge/version-6.2.250-brightgreen)](https://github.com/bingook/bingo/releases)`
- `[![Version](https://img.shields.io/badge/version-6.2.250-brightgreen)](https://github.com/bingook/bingo/releases)`
- `| v6.2.250 | **Executor evidence-state upgrade** — promotes concrete runtime observations such as public 'composer.json'/'composer.lock'/'vendor/composer/installed.json', server st`
- `| v3.2.94 | **Dead-loop detection overhaul** — legacy retry-counter design for INFINITE_LOOP_RISK; superseded by v6.2.250 executor runtime-budget instrumentation, so loop risk is b`
- `| v3.2.91 | **Fix: INFINITE_LOOP_RISK over-detection + Ctrl+C hang** — legacy loop retry-counter design; superseded by v6.2.250 executor runtime-budget instrumentation. Cursor-patt`
- `[![Version](https://img.shields.io/badge/version-6.2.250-brightgreen)](https://github.com/bingook/bingo/releases)`
- `__version__ = "6.2.250"`
- `r"/(?:composer\.(?:json|lock)|vendor/composer/installed\.json)\s*->\s*200\b",`
- `r"\bPKG\s+[a-z0-9_.-]+/[a-z0-9_.-]+@?v?\d",`
- `r"(?:ADMIN\s+ENUM|USER(?:NAME)?[_ -]?ENUM).{0,400}"`
- `r"(?:Fatal\s+error:\s*Uncaught|Uncaught\s+(?:TypeError|Error|Exception)).{0,500}"`
- `r"(?:called\s+in\s+/|Stack\s+trace)",`
- `if int(confirmed_count or 0) > 0:`
- `if int(no_progress_count or 0) >= 4 and int(loop_count or 0) >= 10:`
- `return "confirmed evidence plateau; report current findings"`
- `if int(low_value_reentry_count or 0) >= 2 and int(loop_count or 0) >= 12:`
- `return "confirmed evidence reached; low-value re-entry exhausted"`
- `("artifact_exposure", r"(?:composer\.(?:json|lock)|vendor/composer/installed\.json|package-lock\.json|yarn\.lock)"),`
- `def _looks_transport_proxy_endpoint(host: str, port: str) -> bool:`
- `host_l = str(host or "").lower().strip("[]")`
- `port_s = str(port or "")`
- `if host_l not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:`
- `return False`
- `if port_s not in {"9050", "9051", "1080", "1086", "1087", "7890", "7891", "8080", "8081", "8118"}:`
- `return False`
<!-- bingo-project-memory:auto:end -->
