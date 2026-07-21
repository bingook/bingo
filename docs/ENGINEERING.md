# Bingo Engineering Notes

This document records the current product-quality direction for Bingo.

## Executor/state-machine model

Bingo uses a Claude Code-style split:

1. The model proposes actions.
2. The executor owns action state and canonical target identity.
3. The Action Ledger decides whether an action family is pending, done, negative, or blocked.
4. The Evidence Ledger promotes concrete runtime observations into findings.
5. The loop guard decides whether to pivot, continue, or stop and generate a report.
6. Target canonicalization rewrites model-proposed URL hosts before execution/history.
7. The target-scope guard remains a fallback for cases canonicalization must not rewrite, such as direct IP transport without a current-target Host binding.

The policy implementation lives in:

- `bingo/core/executor_state.py`
- `bingo/core/target_state.py`
- `bingo/tools/findings_exporter.py`
- `bingo/ui/terminal.py` wrapper methods for backward-compatible tests and UI integration

## Canonical target ownership

The model does not own the concrete request host. It may propose paths, payloads,
headers, or even an absolute URL, but the executor resolves URL-bearing action
fields through `TargetState` before dispatch.

Rules:

- current target origin (`scheme://host[:port]`) is authoritative;
- lookalike/off-scope application hosts are rewritten to the authoritative target while preserving path/query;
- same root-domain subdomains and evidence-learned related domains are preserved;
- whitelisted OSINT/CDN/callback infrastructure is preserved;
- `Referer`, `Origin`, and `Host` header values are canonicalized consistently with the request URL;
- canonicalization notices must not echo the wrong host, because that pollutes the next model context.

The guard policy is not the primary fix for target drift. It is a safety fallback
when the executor cannot safely canonicalize a request, especially direct IP URLs
for domain-bound web apps.

## Guard-debt retirement rules

When an older version note says "block", "force", "suppress", or "hard stop",
do not add another pattern gate first. Convert it into executor-owned state when
possible.

Retired/converted categories:

- malformed URL guard (`https://file.asp`) → `TargetState` rebuilds it as
  `current-target/file.asp`;
- lookalike target drift (`TARGET.kr` → `TARGET.jp`) → `TargetState`
  canonicalizes host before execution/history;
- irrelevant package/auth setup block → script setup normalizer removes only the
  unrelated setup line and preserves the target action;
- repeated `http_get` → executor cache hit for the same action signature;
- repeated semantic SQLi vector → semantic ledger terminal state;
- repeated boolean oracle confirmation → `boolean_oracle_already_modeled` state;
- admin path brute-force exhaustion → `admin_path_family_exhausted` state;
- `INFINITE_LOOP_RISK` precheck block → runtime budget instrumentation.

## Evidence Ledger promotion

The report must be built from executor-observed evidence, not from model
phrasing. When runtime output contains concrete HTTP observations, the
FindingsExporter promotes them before generic SQLi/XSS pattern matching.

Confirmed non-payload observations include:

- public dependency artifacts with HTTP `200` and manifest content, such as
  `composer.json`, `composer.lock`, and `vendor/composer/installed.json`;
- server stack/error disclosure with filesystem/class context;
- admin login username-enumeration differentials where an unknown account and a
  known account with the wrong password produce stable, distinct responses.

These findings are evidence, not brute-force success. They should be reported
with appropriate severity and should not be inflated to Critical unless there is
credential extraction, RCE, SQLi data extraction, or equivalent impact evidence.

The Action Ledger must key UI state from executor-canonicalized arguments. A
model-drifted host that is rewritten before execution must not remain as the
ledger target, because that pollutes the next model context and makes healthy
canonicalization look like a failed run.

Fallback categories that may still emit a guard result:

- direct IP URL for a domain-bound target without a matching `Host` binding;
- target-scope request that cannot be canonicalized without losing authority;
- externally observed WAF/rate-limit/auth "blocked" responses from the target
  itself. These are evidence classifications, not Bingo control-plane blocks.

## Action Ledger states

Current statuses:

- `pending`: action has been registered but not completed.
- `running`: action is executing.
- `done`: action produced meaningful target evidence.
- `no_progress`: action completed but did not advance evidence.
- `negative`: repeated no-progress action family.
- `timeout`: first timeout.
- `blocked_timeout`: repeated timeout family.
- `error`: script/tool failure, syntax error, or invalid tool output.

The executor must skip `done`, `blocked_timeout`, and repeated `negative` families before execution and emit `[ACTION_LEDGER_SKIP]`.

## Loop cutoff policy

The loop should stop and report when confirmed evidence has plateaued, or when
there is no confirmed finding and one of these conditions is met:

- confirmed evidence exists, loop `>= 10`, and new evidence has plateaued;
- confirmed evidence exists, loop `>= 12`, and low-value executor families re-enter;

- repeated `TARGET_DRIFT_BLOCKED` appears after canonicalization failed or was intentionally bypassed;
- loop `>= 20` and the current turn has at least 2 ledger skips;
- loop `>= 20` and ledger skip turns repeat;
- loop `>= 24` and low-value executor families re-enter without confirmed findings;
- loop `>= 24` and cumulative ledger skips reach 6;
- loop `>= 30` and there are still zero confirmed findings;
- repeated no-progress escape attempts continue.

Low-value late-loop families include infrastructure/header/Tomcat-style probes that are useful early but should not keep the agent alive indefinitely.

## Progress rules

These are not enough to reset no-progress:

- target drift guard output;
- `[ACTION_LEDGER_SKIP]` control-plane output;
- `confirmed=False`;
- repeated `probable boolean_true_false_diff`;
- repeated stack-leak payload variants with only size/value changes.

These can count as progress:

- confirmed finding IDs;
- real credential/database/table/column extraction;
- first-time stack/exception leakage evidence;
- public dependency artifact exposure;
- admin username-enumeration differentials;
- high-value endpoint/parameter discovery.

## Regression log acceptance criteria

Use synthetic or authorized targets only. Keep raw logs out of commits unless they are sanitized.

A healthy no-confirmation run should show:

```text
NO_NEW_PROGRESS_STOP
reason: action ledger exhausted pending vectors
or reason: late low-value executor re-entry without confirmed findings
or reason: cumulative action ledger skips without confirmed findings
```

Expected envelope:

- any lookalike/off-scope domain such as `TARGET.jp` while target is `TARGET.kr`: rewrite to the authoritative target before execution/history and emit `TARGET_CANONICALIZED`;
- any assistant response that proposes a lookalike/off-scope URL: canonicalize before history; discard/retry only if unsafe target drift remains after canonicalization;
- same-target no-confirmed regression: stop near loop `20~24`;
- mixed/late low-value no-confirmed regression: stop no later than loop `24~29`;
- any run past loop `30` with `confirmed=0` is a regression unless it is explicitly marked as a long-run mode.

## Verification checklist

Before commit:

```bash
python3 -m py_compile bingo/core/target_state.py bingo/core/executor_state.py bingo/ui/terminal.py bingo/tools_ext/pentest_tools.py tests/test_terminal_completion_regressions.py
pytest -q tests/test_terminal_completion_regressions.py -q
ruff check --select F821,F811 bingo/core/target_state.py bingo/core/executor_state.py bingo/ui/terminal.py bingo/tools_ext/pentest_tools.py tests/test_terminal_completion_regressions.py
pytest -q
git diff --check
scripts/bingo-memory-sync.sh
```
