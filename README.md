# Bingo

Bingo is a multilingual, chat-first agent for authorized security validation.
Describe the target, authorization scope, and validation goal in natural language. Bingo plans bounded actions, executes only within the confirmed engagement, correlates runtime evidence, and produces verified Markdown and HTML reports.

## Principles

- **Chat first** — the default product is a conversation, not a technique-command console.
- **Multi-provider** — Claude, OpenAI-compatible providers, GLM, Qwen, Ollama, and custom endpoints remain supported behind one typed runtime contract.
- **Executor-owned authority** — models propose intent; Bingo owns the canonical target, scope, action identity, approval, execution, and mission phase.
- **Evidence led** — model prose is never a finding. Confirmed findings require executor-observed evidence and stable finding IDs.
- **Long-horizon but bounded** — resumable missions use action, concurrency, timeout, output, and plateau budgets.
- **Non-destructive** — destructive actions, denial of service, mass targeting, persistence, stealth/evasion, and autonomous scope expansion are outside the execution boundary.

## Installation

Python 3.12 or later is required. Native Windows is not supported; use Linux, macOS, or WSL2.

```bash
pip install bingo-ai
bingo
```

From source:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
bingo
```

## First run

1. Select English, 한국어, or 中文.
2. Configure a model provider.
3. Describe the authorized validation goal in natural language.
4. Confirm the exact target scope before active validation begins.

Example:

```text
Assess https://example.test for exposed application metadata.
I confirm I am authorized to test this exact host using bounded read-only requests.
```

Bingo then maps the request into typed planner intent, binds it to the canonical engagement target, checks authorization and scope, executes through an approved capability adapter, records evidence, and reports only verified claims.

## Chat commands

The command surface contains session controls only:

| Command | Purpose |
|---|---|
| `/help` | Show help |
| `/hint <message>` | Add a hint during an active turn |
| `/retry` | Retry the previous request or failed step |
| `/load <session-file>` | Load and sanitize an existing session |
| `/report` | Generate a report from current evidence |
| `/model` | Add or switch model provider |
| `/history` | View conversation history |
| `/export` | Export the conversation |
| `/config` | View configuration |
| `/lang` | Switch English, Korean, or Chinese |
| `/clear` | Clear the display |
| `/quit` | Exit Bingo |

Security techniques and executor capabilities are selected internally by the agent and are not exposed as slash commands or raw tool names.

## Authorization and action policy

Bingo starts closed by default. Entering a URL does not grant authority. An engagement records:

- authorization assertion and optional reference/expiry;
- canonical target and explicitly allowed hosts;
- schemes, ports, methods, paths, credentials, and exclusions;
- action, concurrency, request, timeout, and output budgets.

Read-only actions within an active scope may run autonomously. Reversible or high-impact state changes require an approval bound to the exact normalized action arguments. Changing the arguments invalidates the approval. Prohibited action classes cannot be approved.

## Runtime architecture

```text
Terminal chat
  -> ChatApplication
  -> provider-neutral RuntimeEvent stream
  -> typed planner intent
  -> v7 action builder
  -> engagement ActionAuthority
  -> authorized ExecutionEnvelope
  -> capability adapter
  -> FindingsExporter evidence truth
  -> EvidenceGraph + CoverageLedger
  -> deterministic mission director
  -> verified report artifacts
```

Provider output and remote target content are untrusted. Only the scope engine, action policy, explicit approval result, executor normalization, and evidence-verdict code grant authority or promote findings.

### Provider support

- Anthropic Claude uses the official Anthropic Python SDK and preserves native tool requests, stop reasons, refusals, usage, and replay content.
- OpenAI-compatible providers, DeepSeek, GLM, Qwen, Ollama, and custom endpoints normalize their streams into the same provider-neutral runtime events.
- Legacy textual execution directives are decoded only as compatibility input. They are never rendered or executed directly.

## Evidence and reporting

Evidence tiers are observation, candidate, and confirmed. False-positive controls remain mandatory:

- blocked or WAF responses are not successful vulnerability proof;
- reflection alone is not browser execution;
- model-authored credentials are not extracted credentials;
- queued actions are not completed actions;
- report claims must resolve to active finding IDs.

Reports are generated from immutable evidence and session snapshots. Provider prose may improve readability, but every claim is validated afterward. The mission reaches `done` only after all required report artifacts exist.

## Development

Use synthetic targets, fake transports, or loopback-only test servers. Never run repository tests against third-party systems.

```bash
python3 -m pytest -q
ruff check --select F821,F811 bingo tests
python3 -m py_compile bingo/runtime/*.py bingo/application/*.py bingo/core/v7/*.py
git diff --check
```

Focused suites include runtime contracts, engagement authority, chat presentation, provider adapters, v7 architecture, false-positive controls, terminal/PTTY behavior, stream transport, report lifecycle, and Vshell truth contracts.

## License and responsible use

Use Bingo only on systems you own or are explicitly authorized to assess. Authorization, target scope, and action approval are runtime data, not assumptions embedded in a prompt.
