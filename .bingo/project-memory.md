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

- Last synced: 2026-07-20T16:19:20+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-20T16:19:20+08:00

### Status
```text
M .bingo/project-memory.md
 M PKG-INFO
 M bingo/__init__.py
 M bingo/models/system_prompt.py
 M bingo/ui/terminal.py
 M tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
PKG-INFO                                      |   2 +-
 bingo/__init__.py                             |   2 +-
 bingo/models/system_prompt.py                 |  52 +-
 bingo/ui/terminal.py                          | 714 ++++++++++++++++++++++++--
 tests/test_terminal_completion_regressions.py | 127 +++++
 5 files changed, 838 insertions(+), 59 deletions(-)
```

### Added Highlights
- `Version: 6.2.225`
- `__version__ = "6.2.225"`
- `BINGO ENGINE v6.2 — HYBRID AI-LED MODE`
- `║  ★★★ HYBRID AI-LED MODE — 모델 주도 + Bingo 증거 검증 ★★★        ║`
- `║  AI 모델이 전략, 판단, 다음 행동을 주도한다.                      ║`
- `║  Bingo는 스킬 자동주입, 툴 실행, 증거 ledger, 보고서 생성을 맡는다.║`
- `║  Raw 모드처럼 모델의 자유 실행을 보장하되, 확정/완료/보고서는      ║`
- `║  Bingo의 실행 증거와 Finding ID 기준으로만 승격된다.              ║`
- `║  run_python — 복잡한 검증에 사용:                                 ║`
- `║   • 필요한 만큼 완전한 스크립트 작성, 단 결과는 짧고 검증 가능하게 ║`
- `║  ⚡ 중간형 원칙: 모델이 직접 판단하되 Bingo의 검증 기준을 통과해야 한다.║`
- `║     막히면 같은 시도를 반복하지 말고 payload/transport/endpoint/vector를 바꾼다.║`
- `║  ● Use real execution output; simulation text is not evidence     ║`
- `║  ● The words CONFIRMED, TASK_COMPLETE, dumped, shell, admin, DB, ║`
- `║    credential, or extracted are not proof by themselves.          ║`
- `║  ● Confirmed findings require Bingo Finding ID or deterministic  ║`
- `║    type-specific verifier output. Otherwise label as hypothesis.  ║`
- `║  2. 기본은 한 번에 TOOL_CALL 하나. 독립 baseline probe만 작은 batch(최대 3) 허용║`
- `║  3. TOOL flood 금지: 같은 목적의 10개+ 호출을 한 턴에 쏟아내지 말 것        ║`
- `║  4. TOOL_RESULT 결과를 분석 후 다음 TOOL_CALL 또는 BINGO_SIGNAL 출력       ║`
- `║  5. TOOL_CALL 우선; custom Python/bash/외부 도구는 fallback으로 즉시 사용   ║`
- `Principle: Skills are Bingo's technique memory. When the task clearly matches a`
- `known skill family, load the matching skill early, then execute real verification`
- `with TOOL_CALL/run_python/run_bash. Skills guide technique; execution output and`
- `Finding IDs decide what is true.`
- `TASK_COMPLETE → only after passing all evidence gates above. It is a stop/report`
- `signal, not proof. If Bingo has zero confirmed Finding IDs, the final report must`
- `say no confirmed vulnerability and keep candidates in the verification backlog.`
- `13. Hybrid mode rule: the model chooses strategy and next actions; Bingo owns`
- `execution, skill injection, evidence ledger, and report truth. A model-written`
<!-- working-tree:end -->

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:126aed157903ff2227ca94549039314a8a192229 -->
## Code change: chore: bump version to 6.2.224
- Commit: `126aed157903`
- Recorded: 2026-07-20T12:32:43+08:00
- Committed: 2026-07-20T12:32:43+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	bingo/__init__.py
M	bingo/core/change_memory.py
```

### Diff Stat
```text
126aed157 chore: bump version to 6.2.224
 .bingo/project-memory.md    | 65 ++++++++++++++++++++++++++++++++++-----------
 PKG-INFO                    |  2 +-
 bingo/__init__.py           |  2 +-
 bingo/core/change_memory.py |  7 +++++
 4 files changed, 59 insertions(+), 17 deletions(-)
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
