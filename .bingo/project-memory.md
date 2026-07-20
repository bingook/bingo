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

- Last synced: 2026-07-20T17:08:14+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:094240208a8956a5e6c2418e31a2d09640c9f3ca -->
## Code change: refactor: make waf and sqli ai-led with bingo verification
- Commit: `094240208a89`
- Recorded: 2026-07-20T17:08:14+08:00
- Committed: 2026-07-20T17:08:14+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	bingo/__init__.py
M	bingo/cli.py
M	bingo/lang/strings.py
M	bingo/models/system_prompt.py
M	bingo/tools_ext/builtin/mission_orchestrator.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
094240208 refactor: make waf and sqli ai-led with bingo verification
 .bingo/project-memory.md                        | 88 +++++++++++++------------
 PKG-INFO                                        |  2 +-
 bingo/__init__.py                               |  2 +-
 bingo/cli.py                                    | 16 ++---
 bingo/lang/strings.py                           |  6 +-
 bingo/models/system_prompt.py                   | 63 ++++++++++++------
 bingo/tools_ext/builtin/mission_orchestrator.py |  5 +-
 bingo/ui/terminal.py                            | 73 +++++++++++---------
 tests/test_terminal_completion_regressions.py   | 15 ++++-
 9 files changed, 156 insertions(+), 114 deletions(-)
```

### Added Highlights
- `Version: 6.2.228`
- `__version__ = "6.2.228"`
- `engine = WafBypassEngine(probe)`
- `console.print(f"\n[#00d4aa]AI-led WAF plan:[/]")`
- `console.print("[#4a4a4a]  Auto bypass spray is disabled. Use model + waf_bypass skill to choose one bounded verifier.[/]")`
- `console.print(f"[#4a4a4a]{engine.get_bypass_summary(result.waf_type)}[/]")`
- `"ko": "[AI 주도 피벗 권고] SQLi 대조가 반복 차단됨. 현재 실행은 막지 않지만, 다음 판단은 sqli/waf_bypass skill 기반으로 새 검증기 또는 JS/API/IDOR/XSS/LFI/인증 벡터를 선택하세요.",`
- `"zh": "[AI主导切换建议] SQLi 对照请求重复受阻。当前执行不被拦截；下一步请基于 sqli/waf_bypass skill 选择新的验证器或 JS/API/IDOR/XSS/LFI/认证向量。",`
- `"en": "[AI-led pivot advisory] Repeated SQLi controls were blocked. Current execution is not suppressed; next choose a new verifier or JS/API/IDOR/XSS/LFI/auth vector using sqli/wa`
- `RULE #27: SQLi 후보 발견 시 모델+sqli skill이 먼저 가설과 검증 순서를 정한다.`
- `sqli_autoexploit는 baseline/profile이 충분할 때 선택하는 bounded verifier다.`
- `RULE #30: [SQLI_TRIGGER_DETECTED] → AI/skill이 다음 SQLi verifier를 선택한다.`
- `custom/sqlmap/ghauri/sqli_autoexploit는 교차검증 도구이며 이름 자체가 증거는 아니다.`
- `=== WAF BYPASS — AI/SKILL LED STRATEGY SELECTION ===`
- `When WAF is suspected, first capture the blocked-vs-control evidence, then let`
- `the model choose one technique using waf_bypass skill memory. Bingo executes and`
- `measures the result; do not run a fixed automatic bypass pipeline just because a`
- `vendor name appears.`
- `These are selectable skill references, not an autopilot queue. Apply one small`
- `branch at a time, read the evidence, then choose the next branch.`
- `[REFERENCE: BLIND SQLi 데이터 추출 — bounded custom script]`
- `WAF 환경 blind SQLi 데이터 추출은 안정적인 TRUE/FALSE 오라클이 생긴 뒤에만`
- `아래 형태의 Python 검증 스크립트를 작성/실행:`
- `⚠️  SQLi VERIFIER/HANDOFF [v6.2.228]: AI/skill first, Bingo verifies ⚠️`
- `★★★ 핵심 계약 (v6.2.228) ★★★`
- `SQLi 전략은 모델과 sqli/waf_bypass skill이 먼저 선택한다.`
- `sqli_autoexploit()은 제거하지 않는다. 단, 첫 반응에서 무조건 호출하는`
- `자동완료 엔진이 아니라, 요청 프로필과 baseline이 충분할 때 쓰는`
- `bounded verifier / handoff 도구다.`
- `선택 호출 예시:`
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
