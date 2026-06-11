<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

**Hacker-style AI Red Team Terminal — Multi-Model · Multi-Language · Full Automation**

[![Python](https://img.shields.io/badge/python-3.10%2B-green?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-green)](https://github.com/bingook/bingo)
[![PyPI](https://img.shields.io/badge/PyPI-bingo--ai-green?logo=pypi&logoColor=white)](https://pypi.org/project/bingo-ai)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## Installation

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

Or clone and install:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

Or clone and install:

```powershell
git clone https://github.com/bingook/bingo.git
cd bingo
.\install.ps1
```

### pip

```bash
pip install bingo-ai
```

> **Requirements:** Python 3.10+  
> `sqlmap` and `wafw00f` are automatically installed as dependencies.

---

## Usage

```bash
bingo                  # Start interactive chat
bingo scan <url>       # Full automated red team scan
bingo --reset          # Reset settings
bingo --version        # Show version
```

On first run: **select language → enter AI model API key → start chatting**.  
Settings are saved automatically.

---

## Core Features

### Automated WAF Bypass
When a URL is mentioned in chat, bingo automatically:
1. Detects WAF type (Cloudflare, AWS, ModSecurity, etc.)
2. Selects optimal bypass strategy
3. Runs `WafBypassEngine` with real HTTP probes
4. Converts bypass results into `sqlmap` arguments (tamper scripts, headers, prefix/suffix) — WAF bypass is **automatically applied to sqlmap**

| WAF | Auto Bypass Strategy |
|-----|---------------------|
| Cloudflare | newline encoding → MySQL comment → UA rotation |
| AWS WAF | tab encoding → keyword bypass → header injection |
| ModSecurity | space bypass → double encoding → keyword obfuscation |

### Hash Cracking — Fully Automated
When password hashes appear in AI responses, bingo automatically:

**Step 1 — Online Lookup** (fast, no GPU needed):
| Site | Notes |
|------|-------|
| CrackStation | Largest free DB |
| hashes.com | Multi-algorithm |
| md5decrypt.net | MD5 specialist |
| nivaura.com | SHA-1 / MD5 |
| cmd5.org | Asia-friendly |

**Step 2 — Offline Crack** (if online fails):
- `john` (John the Ripper)
- `hashcat` (GPU-accelerated, bcrypt)
- Python wordlist engine (rockyou.txt auto-detected)

Supported hash types: `bcrypt`, `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `NTLM`, `MySQL41`

Stop anytime: type `/stop` in chat.

### External Tool Auto-Install & Python Fallback
bingo manages all external tools automatically — no manual setup required.

**4-step execution priority for every tool:**

| Step | Action |
|------|--------|
| 1 | Use built-in vendor (sqlmap, wafw00f) |
| 2 | Use `~/.bingo/tools/` or system PATH |
| 3 | **Auto-install** (GitHub Releases / brew / apt / pip) |
| 4 | **Python fallback** — pure Python alternative, workflow never stops |

**Go binary tools** (auto-downloaded from GitHub Releases → `~/.bingo/tools/`):

| Tool | Purpose |
|------|---------|
| `nuclei` | Vulnerability scanning |
| `httpx` | HTTP probing & tech detection |
| `ffuf` | Directory & parameter fuzzing |
| `gobuster` | Directory brute-force |
| `subfinder` | Subdomain enumeration |
| `amass` | Attack surface mapping |

**Package manager tools** (brew / apt / yum auto-install):

| Tool | Purpose | Fallback |
|------|---------|---------|
| `nmap` | Port scan | Python `socket` port scan |
| `nikto` | Web vuln scan | Python `requests` vuln check |
| `whatweb` | Tech fingerprint | bingo http_probe |

**Python tools** (pip auto-install):

| Tool | Purpose |
|------|---------|
| `sqlmap` | SQL injection (also bundled in vendor/) |
| `wafw00f` | WAF detection (also bundled in vendor/) |

All Python fallbacks produce output in the same format as the original tool — **AI context is never interrupted**.

### Session Auto-Save
Every chat session is automatically saved to:
```
~/.config/bingo/sessions/session_YYYYMMDD_HHMMSS.md
```
Full AI responses, commands, and crack results are logged in real time.

### Skill Engine
220+ red team skills auto-injected into AI context based on your input.

### AI Refusal Bypass
All models (DeepSeek, Claude, GPT, GLM) are guided by a proprietary universal system prompt that enforces:
- Structured task execution with semantic delimiters
- OODA-loop based decision making (Observe → Orient → Decide → Act)
- Anti-laziness enforcement — explicit evidence required for every step
- 5-phase red team pipeline with intel accumulation and coverage tracking

---

## Commands

Type `/` in chat to see an interactive command menu (arrow keys to navigate).

| Command | Description |
|---------|-------------|
| `/scan <url>` | Quick recon: WAF + fingerprint + sensitive files |
| `/waf <url>` | WAF detection + auto bypass attempt |
| `/crack [hash]` | Hash crack — online lookup → offline crack pipeline |
| `/stop` | Stop running crack / scan |
| `/tools` | Show all tools + auto-install missing ones |
| `/tools install <name>` | Install a specific tool automatically |
| `/tools install all` | Install all missing tools at once |
| `/model` | Add or switch AI model |
| `/skill <keyword>` | Search skill knowledge base |
| `/history` | View conversation history |
| `/export` | Save conversation as `.md` file |
| `/config` | View current settings |
| `/lang` | Change language (ko / zh / en) |
| `/clear` | Clear screen |
| `/quit` | Exit |

### `/tools` Usage

```bash
/tools                       # Show all tools — installed / missing / type
/tools install nmap          # Auto-install nmap via brew/apt
/tools install nuclei ffuf   # Auto-install multiple tools from GitHub Releases
/tools install all           # Auto-install every missing tool
```

When running `/tools`, bingo also asks interactively:
```
지금 없는 도구를 모두 설치할까요? (y/N)
```

### `/crack` Usage

```bash
/crack                             # Auto-extract hashes from last AI response
/crack $2y$10$Eix...               # Crack a specific hash
/crack -w ~/Downloads/rockyou.txt  # Use custom wordlist
```

### `bingo scan` Full Pipeline

```bash
bingo scan https://target.com
```

Runs the full 5-phase red team pipeline:
1. **Recon** — tech fingerprint, WAF detection, endpoint mapping
2. **Collect** — sensitive files, admin panels, parameter discovery
3. **Test** — SQLi, LFI, XSS, SSRF probing
4. **Exploit** — WAF bypass + SQLi extraction + credential dump
5. **Report** — auto-generated markdown report in `targets/`

---

## Supported Models

| Provider | Default Model | API |
|----------|--------------|-----|
| **DeepSeek** | `deepseek-chat` | [platform.deepseek.com](https://platform.deepseek.com) |
| **Anthropic Claude** | `claude-opus-4-5` | [console.anthropic.com](https://console.anthropic.com) |
| **OpenAI GPT** | `gpt-4o` | [platform.openai.com](https://platform.openai.com) |
| **Zhipu GLM** | `glm-4` | [open.bigmodel.cn](https://open.bigmodel.cn) |
| **Alibaba Qwen** | `qwen-turbo` | [dashscope.aliyuncs.com](https://dashscope.aliyuncs.com) |
| **Ollama** (local) | `llama3` | [ollama.com](https://ollama.com) |
| **Custom** | — | Enter Base URL manually |

Switch models anytime with `/model`.

---

## Languages

| Language | Code |
|----------|------|
| 한국어 | `ko` |
| 中文 | `zh` |
| English | `en` |

---

## Data Storage

| Data | Location | When |
|------|----------|------|
| Chat sessions | `~/.config/bingo/sessions/session_*.md` | Auto (real-time) |
| Scan reports | `targets/report_<domain>.md` | Auto on `bingo scan` |
| Command history | `~/.config/bingo/history` | Auto |
| Manual export | `./bingo_chat_<timestamp>.md` | `/export` command |
| Config | `~/.config/bingo/config.json` | Auto |
| Go tools | `~/.bingo/tools/` | Auto on first use |

---

## Config File

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

---

## Project Structure

```
bingo/
├── bingo/
│   ├── cli.py              # Entry point + onboarding
│   ├── config.py           # Settings (cross-platform)
│   ├── models/
│   │   ├── base.py         # Streaming HTTP (OpenAI-compatible + Claude)
│   │   ├── registry.py     # Provider registry
│   │   └── system_prompt.py # Universal pentest prompt (all models)
│   ├── tools/
│   │   ├── registry.py     # Tool detection (~/.bingo/tools/ + PATH + vendor)
│   │   ├── executor.py     # 4-step: vendor → PATH → auto-install → Python fallback
│   │   ├── downloader.py   # Go binary auto-download from GitHub Releases
│   │   ├── installer.py    # brew / apt / pip auto-install
│   │   ├── http_probe.py   # HTTP fingerprinting
│   │   ├── sqli.py         # SQLi detection & exploitation
│   │   ├── waf_bypass.py   # WAF detection + bypass → sqlmap args
│   │   ├── hash_crack.py   # Offline hash cracker (bcrypt/MD5/SHA/NTLM)
│   │   └── hash_lookup.py  # Online hash lookup (CrackStation, hashes.com, etc.)
│   ├── redteam/
│   │   └── phases/         # 5-phase pipeline (recon → report)
│   ├── skills/
│   │   └── engine.py       # 220+ skill knowledge base
│   ├── ui/
│   │   └── terminal.py     # Interactive terminal (slash autocomplete, auto-crack, /tools)
│   └── lang/
│       └── strings.py      # Multi-language strings
├── vendor/
│   ├── sqlmap/             # Embedded sqlmap (git submodule)
│   └── wafw00f/            # Embedded wafw00f (git submodule)
├── install.sh              # macOS/Linux installer
├── install.ps1             # Windows installer
└── pyproject.toml
```

---

## Contributing

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
pip install -e ".[dev]"
```

Pull requests are welcome.

---

## License

MIT © 2026 bingook
