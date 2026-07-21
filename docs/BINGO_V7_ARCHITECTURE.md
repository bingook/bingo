# Bingo v7 Architecture

## Product goal

Bingo is a multilingual, chat-first agent for authorized security validation. It accepts a natural-language goal, confirms a bounded engagement, plans and executes through typed contracts, correlates runtime evidence, and completes with verified artifacts.

Campaign-grade means long-horizon planning, resumable state, broad validation coverage, evidence correlation, and disciplined reporting. It does not mean destructive actions, denial of service, mass targeting, persistence, stealth/evasion, or autonomous scope expansion.

## Ownership rules

1. The model proposes intent, never authority.
2. Engagement state owns authorization and scope.
3. The executor owns target identity and action construction.
4. `ActionAuthority` decides allow, confirm, or deny before dispatch.
5. The state machine owns mission phases.
6. Authorized execution updates coverage; model proposals and policy denials do not.
7. `FindingsExporter` owns finding truth; `EvidenceGraph` is its typed projection.
8. Reports are derived from immutable state and active finding IDs.
9. Required artifacts must exist before `REPORT_EMITTED` moves the mission to `DONE`.

## Trust boundaries

Untrusted inputs:

- user-provided target content;
- model/provider output;
- provider tool arguments;
- remote responses;
- legacy session files and textual execution directives.

Trusted authority:

- explicit user authorization assertion;
- normalized engagement scope;
- typed action policy and exact-action approval;
- executor-owned canonical target and arguments;
- evidence verdict and report validation code.

A prompt sentence such as “fully authorized” never grants execution authority.

## Runtime flow

```text
BingoTerminal (I/O only)
  -> ChatApplication
  -> ProviderAdapter
  -> RuntimeEvent stream
  -> PlannerIntent
  -> ExecutorActionBuilder
  -> ActionRequest
  -> ActionAuthority
  -> ExecutionEnvelope
  -> capability adapter
  -> execution result
  -> FindingsExporter
  -> EvidenceGraph + CoverageLedger
  -> AssessmentDirector
  -> ReportService
```

Only an `ExecutionEnvelope` may cross into an executor adapter.

## Provider-neutral runtime

`bingo/runtime/` defines provider-neutral conversation content, tool requests, completions, stop reasons, usage, runtime events, and capability flags.

- Claude uses the official Anthropic SDK inside `ClaudeAdapter` and normalizes native tool blocks, refusals, pause state, usage, and lossless replay content.
- OpenAI-compatible providers, DeepSeek, GLM, Qwen, Ollama, and custom endpoints normalize into the same contracts.
- Provider adapters decode only. They do not execute tools.
- Legacy textual directives are accepted through `legacy_tool_decoder.py` only for compatibility. They are stripped from display, history, and export.

## Engagement and action policy

Authorization starts false. An engagement contains:

- assertion identity, time, reference, and optional expiry;
- canonical target and explicit allowed hosts;
- schemes, ports, methods, paths, credentials, and exclusions;
- action and concurrency budgets.

Action classes distinguish local/passive reads, bounded network reads, authenticated reads, reversible state changes, high-impact changes, and prohibited operations. Approvals are bound to the canonical action identity. Modified arguments require a new decision.

## Mission core

`bingo/core/v7/` contains:

- `MissionStateMachine`: intake, recon, enumerate, validate, report, done, halted;
- `ExecutorActionBuilder`: relative planner intent to canonical target-bound action;
- `CoverageLedger`: routes, surfaces, and canonical action identities;
- `EvidenceGraph`: observation, candidate, and confirmed evidence projection;
- `AssessmentDirector`: deterministic coverage, pivot, plateau, and report advice;
- `ReportService`: artifact verification and terminal mission transition.

Long-horizon operation is bounded by action, host, concurrency, timeout, output, plateau, and provider-continuation budgets. Budget exhaustion produces a report or typed halt, not an infinite loop.

## Presentation boundary

Runtime services emit semantic activity events. `ActivityPresenter` maps these events to localized view models. Raw provider block names, capability identifiers, action-ledger details, and tool arguments remain diagnostics and never become ordinary chat text.

Autocomplete, help, and dispatch must use one `CommandRegistry`. The public command surface is limited to session and conversation controls. Security techniques remain internal capabilities selected through natural language.

## Evidence and report truth

Execution results carry engagement, action, scope, and evidence provenance. `FindingsExporter` applies the established false-positive and promotion rules. Evidence graph state cannot promote beyond the exporter verdict.

Report generation follows:

1. immutable findings/evidence/coverage/session snapshot;
2. deterministic report basis;
3. optional provider prose improvement;
4. finding-ID and credential validation;
5. Markdown, HTML, findings data, and index artifact writes;
6. artifact existence verification;
7. `REPORT_EMITTED` and transition to `DONE`.

Failure leaves the mission in `REPORT` and supports report retry without repeating assessment actions.

## Compatibility strategy

Keep existing provider configuration, target canonicalization, action identity lessons, evidence false-positive logic, executor implementations, session import, findings data, and report readers. Migrate capability families behind typed adapters incrementally.

Do not preserve technique-oriented UI commands or raw protocol rendering as compatibility. Capability compatibility and UI compatibility are separate.

## Verification

All tests use synthetic targets, fake provider clients, fake transports, or loopback-only servers. Required checks cover:

- provider event normalization and Claude refusal/tool handling;
- authorization, exact-host scope, budgets, and approvals;
- pre-dispatch v7 authority and canonical action identity;
- multilingual presentation without internal names;
- false-positive and report-truth invariants;
- PTY cancellation and stream failures;
- report artifact lifecycle;
- static absence of forbidden legacy product surfaces.
