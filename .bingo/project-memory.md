# Bingo Project Memory

> Project-local persistent memory for Bingo sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User's real requirement is not "improve existing Bingo" but "rebuild default Bingo into a chat-first agent while keeping only the broad UI shell." Internal runtime fixes alone do not satisfy the request.
- Failure criteria explicitly called out by the user: if legacy Bingo surfaces are still visible, the redesign is not done. Unacceptable user-facing surfaces include `/waf`, `/tools`, `/skill`, `/recon`, `/agent`, `OPS MATRIX`, `tools+skills`, `operator stream`, `[bingo action]`, and raw internal tool names such as `http_get`, `waf_detect`, and `web_tech_detect`.
- Do not tell the user to update, test, or rerun the same target until both the runtime structure and the visible UI/UX surface are redesigned enough that old Bingo behavior is no longer apparent.
- Current local state after partial fixes: stream transport/target canonicalization work exists and the local test suite passed, but the user correctly rejected it as incomplete because visible legacy Bingo workflow still remains. Treat the redesign as unfinished.
- When confirming understanding with the user, lock the acceptance criteria in code-facing terms immediately. If those visible legacy surfaces remain, report the work as incomplete instead of calling it "v7 redesign" or "ready to test".
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

- Last synced: 2026-07-22T07:15:38+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-22T07:15:38+08:00

### Status
```text
M .bingo/project-memory.md
 M README.md
 M bingo/cli.py
 M bingo/core/authorization.py
 M bingo/core/v7/__init__.py
 M bingo/core/v7/executor_bridge.py
 M bingo/core/v7/runtime.py
 M bingo/lang/strings.py
 M bingo/models/base.py
 M bingo/ui/terminal.py
 M docs/BINGO_V7_ARCHITECTURE.md
 M pyproject.toml
 M tests/test_terminal_completion_regressions.py
 M tests/test_v7_architecture.py
?? bingo/application/
?? bingo/core/engagement.py
?? bingo/core/v7/report_service.py
?? bingo/runtime/
?? bingo/ui/commands.py
?? bingo/ui/presenter.py
?? bingo/ui/view_models.py
?? tests/test_chat_application.py
?? tests/test_chat_presentation.py
?? tests/test_claude_adapter.py
?? tests/test_engagement_authority.py
?? tests/test_report_service.py
?? tests/test_runtime_contracts.py
```

### Diff Stat
```text
README.md                                     | 2253 +------------------------
 bingo/cli.py                                  |  102 +-
 bingo/core/authorization.py                   |    8 +-
 bingo/core/v7/__init__.py                     |    3 +
 bingo/core/v7/executor_bridge.py              |   47 +-
 bingo/core/v7/runtime.py                      |   76 +-
 bingo/lang/strings.py                         |   71 +-
 bingo/models/base.py                          |  138 +-
 bingo/ui/terminal.py                          |  430 +----
 docs/BINGO_V7_ARCHITECTURE.md                 |  261 ++-
 pyproject.toml                                |    1 +
 tests/test_terminal_completion_regressions.py |   33 +-
 tests/test_v7_architecture.py                 |   62 +
 13 files changed, 549 insertions(+), 2936 deletions(-)
```

### Added Highlights
- `Bingo is a multilingual, chat-first agent for authorized security validation.`
- `- **Chat first** — the default product is a conversation, not a technique-command console.`
- `- **Multi-provider** — Claude, OpenAI-compatible providers, GLM, Qwen, Ollama, and custom endpoints remain supported behind one typed runtime contract.`
- `- **Executor-owned authority** — models propose intent; Bingo owns the canonical target, scope, action identity, approval, execution, and mission phase.`
- `- **Evidence led** — model prose is never a finding. Confirmed findings require executor-observed evidence and stable finding IDs.`
- `- **Long-horizon but bounded** — resumable missions use action, concurrency, timeout, output, and plateau budgets.`
- `- **Non-destructive** — destructive actions, denial of service, mass targeting, persistence, stealth/evasion, and autonomous scope expansion are outside the execution boundary.`
- `Python 3.12 or later is required. Native Windows is not supported; use Linux, macOS, or WSL2.`
- `From source:`
- `cd bingo`
- `bash install.sh`
- `bingo`
- `1. Select English, 한국어, or 中文.`
- `2. Configure a model provider.`
- `3. Describe the authorized validation goal in natural language.`
- `4. Confirm the exact target scope before active validation begins.`
- `Example:`
- `'''text`
- `Assess https://example.test for exposed application metadata.`
- `I confirm I am authorized to test this exact host using bounded read-only requests.`
- `The command surface contains session controls only:`
- `| Command | Purpose |`
- `|---|---|`
- `| '/help' | Show help |`
- `| '/hint <message>' | Add a hint during an active turn |`
- `| '/retry' | Retry the previous request or failed step |`
- `| '/load <session-file>' | Load and sanitize an existing session |`
- `| '/report' | Generate a report from current evidence |`
- `| '/model' | Add or switch model provider |`
- `| '/export' | Export the conversation |`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:cf67ae5c5a6a9100e01fa5106c6e88bb3059acb9 -->
## Code change: docs: sync project memory
- Commit: `cf67ae5c5a6a`
- Recorded: 2026-07-22T05:13:39+08:00
- Committed: 2026-07-22T05:13:39+08:00

### Files
```text
M	.bingo/project-memory.md
```

### Diff Stat
```text
cf67ae5c5 docs: sync project memory
 .bingo/project-memory.md | 58 +++++++++++++-----------------------------------
 1 file changed, 16 insertions(+), 42 deletions(-)
```
<!-- bingo-project-memory:auto:end -->
