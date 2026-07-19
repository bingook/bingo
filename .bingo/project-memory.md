# Bingo Project Memory

> Project-local persistent memory for Bingo sessions launched from this repository.
> Keep durable facts, decisions, and verification status here. Do not store secrets.

## Persistent Notes

- User prefers direct Korean updates, concise factual engineering status, and concrete commit/push commands.
- Preserve unrelated user changes unless explicitly scoped. Recent unrelated/local state often includes `AGENTS.md` and `.bingo/`.
- Platform guard policy is strict: do not weaken Windows/WSL blocking logic or related dependency markers.
- Current stable version after Bingo memory rebrand: `6.2.213`.
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

<!-- bingo-project-memory:auto:start -->
## Auto-captured workspace memory

- Last synced: 2026-07-19T20:33:08+08:00
- Workspace: `/Users/jmaker/Desktop/hacker/bingo`
- Source: `/Users/jmaker/Desktop/hacker/bingo/.bingo/bingo-memory/c6a511e7ba35526f/MEMORY.md`

<!-- working-tree:start -->
## Working tree snapshot (uncommitted)
- Captured: 2026-07-19T20:33:08+08:00

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
 bingo/ui/terminal.py                          | 265 +++++++++++++++++++++++++-
 tests/test_terminal_completion_regressions.py | 238 +++++++++++++++++++++++
 4 files changed, 500 insertions(+), 7 deletions(-)
```

### Added Highlights
- `Version: 6.2.213`
- `__version__ = "6.2.213"`
- `r"(密码哈希|管理员哈希|哈希|hash|md5|sha1|해시)\s*[:：]\s*[a-fA-F0-9\*]{20,}",`
- `r"(sql\s*注入|sql注入|注入).{0,60}(已验证|验证|确认|完整数据库|数据库泄露|数据库转储|命令执行|shell)",`
- `r"(完整)?数据库.{0,30}(转储|泄露|导出|提取|dump)",`
- `r"(sqlmap|os-?shell|shell).{0,40}(命令执行|实现|成功|已验证)",`
- `r"(获取|提取|拿到|导出|转储).{0,30}(密码|账号|凭证|数据库|hash|哈希|管理员|令牌)",`
- `_placeholder_names = (`
- `"URL", "PARAM", "BASE_VALUE", "TRUESIZE", "TRUE_SIZE",`
- `"FALSESIZE", "FALSE_SIZE", "THRESHOLD", "VAL",`
- `)`
- `_unbound_placeholders = [`
- `name for name in _placeholder_names`
- `if _hall_re.search(rf'\b{name}\b', s)`
- `and not _hall_re.search(rf'(?m)^\s*{name}\s*=', s)`
- `and not _hall_re.search(rf'\bfor\s+{name}\s+in\b', s)`
- `]`
- `_placeholder_assignment = _hall_re.search(`
- `r'(?m)^\s*(?:URL|PARAM|BASE_VALUE|TRUESIZE|TRUE_SIZE|FALSESIZE|'`
- `r'FALSE_SIZE|THRESHOLD|VAL)\s*=\s*["\'](?:<[^>]+>|'`
- `r'URL|PARAM|BASE_VALUE|TRUESIZE|THRESHOLD|REPLACE_ME|CHANGE_ME|'`
- `r'YOUR_[A-Z_]+|TARGET_[A-Z_]+)["\']',`
- `s,`
- `_hall_re.IGNORECASE,`
- `)`
- `if _unbound_placeholders or _placeholder_assignment:`
- `return (`
- `"PLACEHOLDER_TEMPLATE_CODE: Python block contains unresolved "`
- `f"template placeholder(s): {', '.join(_unbound_placeholders) or 'assignment'}. "`
- `"Do not execute generic examples; regenerate a concrete TOOL_CALL run_python "`
<!-- working-tree:end -->
# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:edc114463b324cad9ae82fcfa499a8672c343569 -->
## Code change: fix: harden report evidence and syntax recovery
- Commit: `edc114463b32`
- Recorded: 2026-07-19T18:35:46+08:00
- Committed: 2026-07-19T18:35:46+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	bingo/__init__.py
M	bingo/tools_ext/pentest_tools.py
M	bingo/ui/terminal.py
```

### Diff Stat
```text
edc114463 fix: harden report evidence and syntax recovery
 .bingo/project-memory.md         | 35 ++++++++++++++--
 PKG-INFO                         |  2 +-
 bingo/__init__.py                |  2 +-
 bingo/tools_ext/pentest_tools.py | 90 ++++++++++++++++++++++++++++++++++++++--
 bingo/ui/terminal.py             | 80 ++++++++++++++++++++++++++++++-----
 5 files changed, 191 insertions(+), 18 deletions(-)
```

### Added Highlights
- `Version: 6.2.212`
- `__version__ = "6.2.212"`
- `def _repair_python_regex_quote_literals(code: str) -> str:`
- `"""`
- `Repair model-generated Python regex literals where a raw single-quoted`
- `pattern contains quote character classes such as ["'].`
- `Example:`
- `re.findall(r'<input type=["']hidden["']>', html)`
- `becomes:`
- `re.findall(r'''<input type=["']hidden["']>''', html)`
- `This preserves the regex semantics and prevents SyntaxError:`
- `"closing parenthesis ']' does not match opening parenthesis".`
- `"""`
- `import re as _rxq`
- `def _needs_repair(pattern: str) -> bool:`
- `'["\']', '[\'"]', '[^"\']', '[^\'"]',`
- `'[\\"\\\']', '[\\\'\\"]',`
- `))`
- `def _repair_line(line: str) -> str:`
- `if "re." not in line or "r'" not in line:`
- `return line`
- `if not _rxq.search(r'\bre\.(?:findall|finditer|search|match|compile|sub|split)\s*\(', line):`
- `return line`
- `out: list[str] = []`
- `i = 0`
- `changed = False`
- `while i < len(line):`
- `start = line.find("r'", i)`
- `if start < 0:`
- `out.append(line[i:])`

<!-- commit:863be3f4b710e5836b7c3bed59bd6f2dd3fb8f7c -->
## Code change: bump: v6.2.211
- Commit: `863be3f4b710`
- Recorded: 2026-07-19T17:50:13+08:00
- Committed: 2026-07-19T17:50:13+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	bingo/__init__.py
M	bingo/tools_ext/pentest_tools.py
```

### Diff Stat
```text
863be3f4b bump: v6.2.211
 .bingo/project-memory.md         | 62 ++++++++++++++++++++++++++++++++++++++--
 PKG-INFO                         |  2 +-
 bingo/__init__.py                |  2 +-
 bingo/tools_ext/pentest_tools.py |  2 +-
 4 files changed, 62 insertions(+), 6 deletions(-)
```

### Added Highlights
- `Version: 6.2.211`
- `__version__ = "6.2.211"`
- `v6.2.211: 도메인 바인딩/vhost 오판 방지 — URL 정체성은 도메인으로 유지하고,`

<!-- commit:00c37783e2074143a91c0618d59b4460948c3bc2 -->
## Code change: fix: preserve domain-bound target identity
- Commit: `00c37783e207`
- Recorded: 2026-07-19T17:46:10+08:00
- Committed: 2026-07-19T17:46:10+08:00

### Files
```text
M	.bingo/project-memory.md
M	bingo/tools_ext/pentest_tools.py
M	bingo/ui/terminal.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
00c37783e fix: preserve domain-bound target identity
 .bingo/project-memory.md                      |  36 +++--
 bingo/tools_ext/pentest_tools.py              | 212 +++++++++++++++++++++++---
 bingo/ui/terminal.py                          |  59 +++++--
 tests/test_terminal_completion_regressions.py |  52 +++++++
 4 files changed, 318 insertions(+), 41 deletions(-)
```

### Added Highlights
- `def _normalise_web_host(host: str) -> str:`
- `"""웹 타겟 비교용 호스트 정규화. 포트와 leading www.만 제거한다."""`
- `h = (host or "").strip().lower().rstrip(".,/")`
- `if h.startswith("[") and "]" in h:`
- `h = h[1:h.index("]")]`
- `elif ":" in h:`
- `h = h.split(":", 1)[0]`
- `return h.removeprefix("www.")`
- `def _is_ip_literal(host: str) -> bool:`
- `try:`
- `import ipaddress as _ipaddr`
- `_ipaddr.ip_address(_normalise_web_host(host))`
- `return True`
- `except Exception:`
- `return False`
- `def _host_matches_current_target(host: str) -> bool:`
- `cur = _normalise_web_host(_CURRENT_TARGET_DOMAIN)`
- `return bool(cur and _normalise_web_host(host) == cur)`
- `def _headers_bind_current_target(headers: object) -> bool:`
- `if not isinstance(headers, dict):`
- `return False`
- `for key, value in headers.items():`
- `if str(key).lower() == "host" and _host_matches_current_target(str(value)):`
- `return True`
- `return False`
- `def _script_has_current_host_header(script: str) -> bool:`
- `"""curl -H 'Host: target' 또는 Python headers={'Host':'target'} 감지."""`
- `import re as _re_host`
- `host_pat = _re_host.compile(`
- `r"""(?ix)`

<!-- commit:4d671034a40a6dca608787a8ce698db609107cc0 -->
## Code change: bump: v6.2.210
- Commit: `4d671034a40a`
- Recorded: 2026-07-19T16:42:01+08:00
- Committed: 2026-07-19T16:42:01+08:00

### Files
```text
M	.bingo/project-memory.md
M	PKG-INFO
M	bingo/__init__.py
M	bingo/ui/terminal.py
```

### Diff Stat
```text
4d671034a bump: v6.2.210
 .bingo/project-memory.md | 122 ++++++++++++++++++++++++++++++++++-------------
 PKG-INFO                 |   2 +-
 bingo/__init__.py        |   2 +-
 bingo/ui/terminal.py     |   2 +-
 4 files changed, 93 insertions(+), 35 deletions(-)
```

### Added Highlights
- `Version: 6.2.210`
- `__version__ = "6.2.210"`

# Workspace Memory

> Automatically records committed code changes. Newest entries appear first.

<!-- commit:01c83c04270549a18f3e18e33c1e88f3417f71bd -->
## Code change: chore: rebrand memory system as bingo
- Commit: `01c83c042705`
- Recorded: 2026-07-19T16:38:10+08:00
- Committed: 2026-07-19T16:38:09+08:00

### Files
```text
M	.bingo/project-memory.md
D	.github/workflows/fp-regression.yml
M	.gitignore
A	PKG-INFO
D	README_ko.md
D	README_zh.md
D	assets/logo.png
D	bingo-github-profile.png
M	bingo/__init__.py
M	bingo/cli.py
M	bingo/core/change_memory.py
M	bingo/lang/strings.py
M	bingo/models/system_prompt.py
M	bingo/ui/terminal.py
D	jwt_response.txt
D	lahyl_coordinates.json
D	push.sh
M	scripts/bingo-memory-sync.sh
M	scripts/bingo-memory-watch.sh
M	scripts/git-hooks/post-commit
M	tests/test_change_memory.py
M	tests/test_terminal_completion_regressions.py
```

### Diff Stat
```text
01c83c042 chore: rebrand memory system as bingo
 .bingo/project-memory.md                      |    744 +-
 .github/workflows/fp-regression.yml           |     58 -
 .gitignore                                    |      2 +-
 PKG-INFO                                      |   2262 +
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
 22 files changed, 2924 insertions(+), 469983 deletions(-)
```

### Added Highlights
- `Metadata-Version: 2.4`
- `Name: bingo-ai`
- `Version: 6.2.201`
- `Summary: AI-powered red team terminal — Zero-Hallucination · WAF bypass · XSS·Upload·SSRF·OAuth·GraphQL·Smuggling exploit chains · CVE/Exploit KB (trickest+exploitarium) · role-bas`
- `Author-email: bingook <bingook@users.noreply.github.com>`
- `License: MIT`
- `Keywords: ai,cli,cve,exploit,hacker,knowledge-base,llm,pentest,red-team,security,terminal,waf`
- `Classifier: Development Status :: 5 - Production/Stable`
- `Classifier: Environment :: Console`
- `Classifier: Intended Audience :: Information Technology`
- `Classifier: License :: OSI Approved :: MIT License`
- `Classifier: Operating System :: MacOS`
- `Classifier: Operating System :: POSIX :: Linux`
- `Classifier: Programming Language :: Python :: 3`
- `Classifier: Programming Language :: Python :: 3.12`
- `Classifier: Programming Language :: Python :: 3.13`
- `Classifier: Programming Language :: Python :: 3.14`
- `Classifier: Topic :: Security`
- `Classifier: Topic :: Terminals`
- `Requires-Python: >=3.12`
- `Requires-Dist: aiohttp>=3.8`
- `Requires-Dist: beautifulsoup4>=4.11`
- `Requires-Dist: certifi>=2023.0`
- `Requires-Dist: chardet>=5.0`
- `Requires-Dist: charset-normalizer>=3.0`
- `Requires-Dist: colorama>=0.4`
- `Requires-Dist: cryptography>=41.0`
- `Requires-Dist: cssselect>=1.2`
- `Requires-Dist: dnspython>=2.3`
- `Requires-Dist: fake-useragent>=1.1`
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
