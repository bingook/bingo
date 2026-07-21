# Bingo v7 Architecture

## Goal

Rebuild Bingo into a strong chat-first security assessment agent without
carrying forward the legacy "LLM writes everything and the runtime tries to
patch it afterward" design.

The shell stays:

- terminal UI
- model configuration
- chat workflow
- report output

The core changes completely:

- executor owns target identity
- executor owns action construction
- session bridge owns terminal-facing runtime/action state
- state machine owns phase transitions
- evidence graph owns finding promotion
- coverage ledger owns "what is left to test"

This is campaign-grade operator discipline, not a pile of ad hoc modules.

## Design Principles

1. The model proposes intent, never raw authority.
2. Target identity is canonical and executor-owned.
3. Findings are promoted from observed runtime evidence, not model prose.
4. Coverage is explicit; repeated work is a state bug, not a prompt problem.
5. Reports are derived from state, not generated from free-form summaries.
6. Long sessions must degrade into report-first behavior, not endless loops.

## Keep, Freeze, Replace

Keep:

- `bingo/ui/terminal.py`
- model/provider configuration
- current `TargetState`
- current executor/evidence lessons (`executor_state`, `findings_exporter`)

Freeze:

- legacy mega-prompts that try to encode the whole attack methodology
- legacy auto-pivot logic that lets the model invent new hosts/workflows
- broad regex-only finding paths
- tool wrappers that mix discovery, execution, classification, and reporting

Replace:

- free-form orchestrator loop with typed mission state
- free-form tool call identity with action envelopes
- implicit progress heuristics with coverage/evidence state
- post hoc correction layers with pre-dispatch authority control
- terminal-owned mission prompt/guidance rendering with runtime-owned rendering

## New Core

`bingo/core/v7/` is the new foundation.

### 1. Mission State Machine

Phases:

- `intake`
- `recon`
- `enumerate`
- `validate`
- `report`
- `done`
- `halted`

The model does not choose phases. It can suggest an action, but only the state
machine moves the mission.

### 2. Planner Intent

The planner is constrained to a small contract:

- summary
- relative path
- method
- params
- headers
- evidence goal

No planner-owned absolute host. No planner-owned proxy identity. No planner-owned
report conclusion.

### 3. Executor Action Envelope

The executor converts planner intent into a fully bound action envelope:

- canonical URL
- canonical method
- canonical headers
- stable identity key for dedup/repeat checks

This is where target drift dies.

### 4. Coverage Ledger

Coverage is tracked by explicit points:

- routes
- auth surfaces
- API surfaces
- artifact surfaces
- action identities

The question is no longer "what does the model feel like testing next?"

The question becomes:

- what surfaces exist
- what surfaces are still unvisited
- what action classes are already exhausted

### 5. Evidence Graph

Evidence tiers:

- observation
- candidate
- confirmed

Merging rules:

- repeated observations merge
- stronger evidence replaces weaker evidence
- confirmed evidence can trigger report-first plateau logic

This graph becomes the single source of truth for reports, summaries, and next
steps.

### 6. Assessment Director

The director is a small deterministic kernel:

- if coverage is missing, do recon/enumeration
- if confirmed evidence exists, validate impact only
- if confirmed evidence plateaus, report now
- if no evidence exists, choose distinct high-value validations

This is the replacement for prompt-only orchestration.

### 7. Reporting Snapshot

`bingo/core/v7/reporting.py` owns evidence-count snapshots and deterministic
next-step fallback guidance.

It now also owns report-session provenance notes and the final report-generation
prompt contract, report artifact path planning, and converged artifact index
content, plus the standalone HTML report builder, so the terminal shell no longer
hand-builds those strings.

That keeps "confirmed vs candidate vs blocked" semantics in core state instead
of scattering them across terminal-only helper methods.

## Migration Plan

Phase 1:

- land `v7` contracts, state machine, coverage ledger, evidence graph
- no UI binding yet

Phase 2:

- add adapter inside terminal loop
- build mission snapshots from current runtime
- let `v7` director advise phase/focus
- keep action-ledger state executor-owned instead of terminal-owned dict mutation
- keep runtime session state (`goal`, `last_status`, prompt block) in core instead of terminal locals
- route both through `bingo/core/session_bridge.py` so terminal keeps one bridge, not parallel state objects

Phase 3:

- align action-ledger identity with `ActionEnvelope`
- move report generation to `EvidenceGraph` snapshots

Phase 4:

- deprecate or quarantine legacy modules that duplicate the same responsibility
- shrink old prompt layers

## Deletion Candidates

Not deleting yet, but these are likely quarantine targets if `v7` takes over:

- legacy APT auto-mode prompt inflation
- overlapping tool wrappers that duplicate recon/finding/report logic
- legacy free-form orchestrator decision JSON path
- regex-only finding codepaths that bypass structured evidence promotion

## Success Criteria

The redesign is successful only if these are true:

1. The model cannot silently change the target host.
2. The same target run does not oscillate between unrelated vectors without state justification.
3. Confirmed evidence never disappears into a zero-finding report.
4. Repeated work is visible in coverage state before execution, not after 20 loops.
5. Terminal UX can stay chat-first while core behavior becomes deterministic.
