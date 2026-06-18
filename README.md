<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI-Powered Red Team Terminal**

[![Version](https://img.shields.io/badge/version-3.0.4-brightgreen)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**🌐 Language:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

</div>

---

## Install

```bash
pip install bingo-ai
bingo
```

**Update:**
```bash
bingo --update
```

**Git clone:**
```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

**Windows (PowerShell as Admin):**
```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

---

## Quick Start

```bash
bingo                        # Launch
bingo scan https://target    # Auto full scan
bingo --version
bingo --reset
```

First launch: select language → enter API key → start.

---

## How to Use

Just type your target and task in the chat window. No commands needed.

**Example prompt (paste into bingo):**
```
Target: https://example.com

Tasks:
1. Full recon — detect WAF, DB type, tech stack
2. SQLi — error → union → blind → time-based
3. Admin credentials — dump admin/user/member tables
4. Admin login — screenshot proof
5. DB full dump — run DbDumper on success
```

> Just describe what you want. AI decides everything automatically.

---

## Core Capabilities

| Area | What bingo does |
|------|----------------|
| **Recon** | WAF detection, tech fingerprinting, crawl all pages/JS/API endpoints |
| **SQLi** | Error-based → Union → Boolean blind → Time-based (all DB types) |
| **WAF Bypass** | Cloudflare / AWS WAF / ModSecurity — auto-selected bypass |
| **XSS** | Stored / Reflected / DOM — session hijack on success |
| **SSRF** | Cloud metadata (AWS/GCP/Azure) endpoint testing |
| **File Upload** | Extension bypass, webshell upload |
| **Auth Attack** | Login brute force, SQLi auth bypass, CAPTCHA auto-solve |
| **IDOR/BOLA** | Object ID enumeration, horizontal privilege escalation |
| **JWT/OAuth** | alg:none, weak secret, redirect_uri abuse |
| **GraphQL** | Introspection, batch attack, field injection |
| **HTTP Smuggling** | CL.TE / TE.CL desync |
| **Credential Dump** | Extract hashes → suggest hashcat command |
| **DB Dump** | Full table dump on confirmed SQLi (DbDumper v2.7) |
| **Screenshot** | Admin panel auto-screenshot via Playwright |
| **Report** | Auto-saved markdown report with CVSS scores |

---

## Supported AI Models

| Provider | Example models |
|----------|---------------|
| OpenAI | `gpt-4o`, `gpt-4-turbo`, `o1` |
| Anthropic | `claude-3-5-sonnet`, `claude-opus-4` |
| DeepSeek | `deepseek-chat`, `deepseek-reasoner` |
| GLM | `glm-4`, `glm-5` |
| Qwen | `qwen-max`, `qwen-plus` |
| Ollama | any local model |
| Custom | any OpenAI-compatible endpoint |

---

## WAF Bypass — Auto Selected

| WAF | Bypass used |
|-----|------------|
| Cloudflare | Double URL encode → Unicode → UA spoof |
| AWS WAF | Encoding → SLEEP→subquery → XFF header |
| ModSecurity | Space/**/ → IF→CASE WHEN → mixed case |
| Nginx/OpenResty | `%0a` newline → comment → obfuscation |
| Chinese WAF | Null byte → overlong UTF-8 → function replace |

---

## Anti-Hallucination — 4-Layer Guard

Every AI response is blocked unless it passes all 4 checks:

1. **Code block guard** — rejects empty stubs, JSON plans
2. **Text intercept** — rejects AI self-confessions
3. **Fake credential block** — no credentials without HTTP proof
4. **Unproven conclusion block** — no "SQLi confirmed" without code execution

Evidence labels in reports:

| Label | Meaning |
|-------|---------|
| `✅ VERIFIED` | Real HTTP response confirmed |
| `🟡 LIKELY` | Partial evidence |
| `🔍 INFERRED` | Reasoning only — verify manually |

---

## `bingo scan` — Full Auto Pipeline

```bash
bingo scan https://target.com
```

Runs 5 phases automatically, no interaction needed:

| Phase | What happens |
|-------|-------------|
| 1. Recon | Tech fingerprint, WAF detect, endpoint map |
| 2. Collect | Admin panels, sensitive files, parameter discovery |
| 3. Test | SQLi / LFI / XSS / SSRF / IDOR probing |
| 4. Exploit | WAF bypass, data extraction, credential dump |
| 5. Report | Markdown report with CVSS scores + evidence |

Report saved to: `~/.config/bingo/reports/report_<domain>.md`

---

## Commands

Type `/` in the chat to open command menu (arrow keys to navigate).

| Command | What it does |
|---------|-------------|
| `/scan <url>` | Full red team pipeline |
| `/waf <url>` | WAF detection + bypass only |
| `/crack [hash]` | Hash crack — online lookup → offline |
| `/stop` | Stop running task |
| `/tools` | Show all tools + install status |
| `/tools install <name>` | Install a specific tool |
| `/tools install all` | Install all missing tools at once |
| `/model` | Add or switch AI model |
| `/skill <keyword>` | Search skill knowledge base |
| `/history` | View conversation history |
| `/export` | Save conversation as `.md` |
| `/config` | View current settings |
| `/lang` | Change language (ko / zh / en) |
| `/clear` | Clear screen |
| `/quit` | Exit |

**Tool install examples:**
```bash
/tools                        # See all tools
/tools install nmap           # Auto-install nmap
/tools install nuclei ffuf    # Install multiple
/tools install all            # Install everything
```

**Hash crack examples:**
```bash
/crack                              # Auto-extract from last response
/crack $2y$10$Eix...               # Crack specific hash
/crack -w ~/rockyou.txt             # Custom wordlist
```

---

## Config & Data Storage

| Path | Content |
|------|---------|
| `~/.config/bingo/config.json` | API keys, model, language |
| `~/.config/bingo/reports/` | Auto-saved scan reports |
| `~/.config/bingo/sessions/` | Chat session history |
| `~/.bingo/tools/` | Auto-downloaded Go tools |
| `BINGO_REPORTS_DIR` | Override report path (env var) |

**Config file locations by OS:**

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/bingo/config.json` |
| Linux | `~/.config/bingo/config.json` |
| Windows | `%APPDATA%\bingo\config.json` |

---

## Mobile — APK / IPA Analysis (v2.2.8)

bingo can analyze Android APK and iOS IPA files directly from the chat window.

### Android APK

```bash
# In bingo chat
bingo> analyze target.apk
bingo> target.apk secret scan
bingo> pentest com.example.app
```

| Method | Speed | Command |
|--------|-------|---------|
| TruffleHog native | ⚡ 9× faster | `bingo> target.apk trufflehog` |
| jadx full decompile | Thorough | `bingo> target.apk jadx full scan` |

**CLI / Python:**
```bash
trufflehog filesystem target.apk --json --no-verification
# Docker (no install needed):
docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json
```

**Install TruffleHog:**
```bash
brew install trufflesecurity/trufflehog/trufflehog   # macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin  # Linux
```

### iOS IPA

```bash
# In bingo chat
bingo> analyze target.ipa
bingo> ios swift decompile target.ipa
bingo> malimite target.ipa
```

**Requires:** Java 17+ and Malimite.jar
```bash
brew install openjdk@17
# Download Malimite.jar from https://github.com/LaurieWired/Malimite/releases
mkdir -p ~/tools && mv ~/Downloads/Malimite.jar ~/tools/
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled/
trufflehog filesystem ./decompiled/ --json --no-verification
```

### Auto-detect (APK or IPA)

```bash
bingo> auto scan target.apk    # AI picks the right method automatically
bingo> auto scan target.ipa
```

### What bingo extracts

| Item | Detail |
|------|--------|
| Hardcoded secrets | AWS keys, Google API, Firebase, Stripe, JWT, GitHub token |
| Permissions | All declared + dangerous permissions |
| Exported components | Activities, Services, Receivers, Providers |
| Deep links / URL schemes | Intent filters, custom scheme handlers |
| Network endpoints | API URLs extracted from code + assets |
| SSL pinning | Detected → bypass guide auto-generated |
| 3rd party SDKs | Firebase, Sentry, Analytics, etc. |

---

## Windows EXE — Standalone Build

Build a portable `.exe` that runs without Python installed:

```bash
pip install pyinstaller
pyinstaller --onefile --name bingo bingo/__main__.py
# Output: dist/bingo.exe
```

Copy `dist/bingo.exe` to any Windows PC — no Python required.  
Run: `bingo.exe` or `bingo.exe scan https://target.com`

---

## EXE Phase 0 — Windows PE Analysis (v2.3.5)

Analyze Windows executables (EXE / DLL / SYS) **without running them**.

```bash
# In bingo chat
bingo> analyze malware.exe
bingo> pe static analysis sample.dll
bingo> check this exe: payload.exe
```

| What bingo checks | Detail |
|-------------------|--------|
| Architecture | x86 / x64 / ARM, compile timestamp |
| Section entropy | >7.0 = packed/encrypted/obfuscated |
| Import table | 30+ suspicious Windows APIs by attack category |
| Strings | C2 URLs, hardcoded IPs, API keys, mutex names, Base64 blobs |
| Packer detection | UPX, Themida, VMProtect, MPRESS, ASPack |
| Digital signature | Authenticode validity check |
| YARA scan | Built-in rules + custom rule file support |
| Risk score | AUTO: LOW / MEDIUM / HIGH |
| Hashes | MD5, SHA1, SHA256, ImpHash, SSDeep |
| VirusTotal | Optional hash lookup via VT API |

---

## Post-Exploitation — Webshell Deploy (v2.2.5)

After confirmed SQLi, bingo runs the full post-exploit chain automatically:

**Chain:** `SQLi login bypass → file upload → webshell → AntSword connect`

```bash
# In bingo chat — just describe the goal
bingo> I have SQLi on https://target.com/login — get admin access and deploy webshell
```

bingo handles each step:

| Step | What happens |
|------|-------------|
| 1. SQLi auth bypass | `admin'--` / `' OR 1=1--` injected into login form |
| 2. Session capture | Auth cookies saved automatically |
| 3. File upload | Webshell uploaded via authenticated upload endpoint |
| 4. Webshell test | `id`, `whoami`, `uname -a` executed to confirm RCE |
| 5. AntSword config | Connection string printed for AntSword C2 |
| 6. DB full dump | DbDumper runs automatically after shell confirmed |

**Webshell types auto-selected:**

| Backend | Webshell |
|---------|----------|
| PHP | `<?php system($_GET['cmd']); ?>` |
| JSP | Runtime.exec() shell |
| ASPX | ProcessStartInfo shell |

---

## DB Dump (v2.9.6)

Triggered automatically after confirmed SQLi / webshell / RCE:

- Dumps: `member` / `user` / `admin` / `g5_member` / `xe_member`
- **No row limit** — `max_rows_per_table=0` (unlimited), entire table dumped
- Saves credentials → `CREDENTIALS_{table}.json`
- Detects hash type → prints `hashcat -m {mode}` command
- Re-attempts admin login with extracted credentials

**Save location (auto-detected by OS):**

| OS | Path |
|----|------|
| macOS | `~/Desktop/dump/{target}_{timestamp}/` |
| Windows | `~/Desktop/dump/{target}_{timestamp}/` (OneDrive Desktop auto-detected) |
| Linux | `~/Desktop/dump/{target}_{timestamp}/` (falls back to `~/dump/` if no Desktop) |

> **v2.9.6 fix:** AI-generated extraction code was saving to `/tmp/` and ignoring DbDumper.
> Now enforced: `/tmp/` forbidden, Desktop path mandatory, FLOOR injection `query_fn` template added.

---

## XSS Scan (v2.9.6)

bingo detects reflected and stored XSS automatically:

- Scans all parameters for reflection contexts (HTML / Attribute / JS / URL)
- **Deduplicates reflection positions** — same context printed only once even if it appears multiple times in the HTML response
- Loop detector distinguishes legitimate scan output from actual infinite loops
- Outputs: `Reflection at: {param}={context}` + unique count

**Why this matters:** some pages reflect the same XSS probe tens of times in a single response. Previous versions triggered the infinite-loop kill after 5 identical lines. v2.9.5 raises the threshold to 25 for scan result lines and enforces deduplication in the AI-generated scan code.

---

## Cloudflare Bypass (Real IP Discovery)

```python
import requests, urllib3
urllib3.disable_warnings()
REAL_IP = "x.x.x.x"  # from SPF/DNS records
s = requests.Session()
s.verify = False
r = s.get(f"https://{REAL_IP}/", headers={"Host": "target.com"})
```

Find real IP: `dig TXT target.com` → look for SPF record IP.

---

## Changelog

| Version | Summary |
|---------|---------|
| v3.0.4 | Post-credential: admin page discovery + IP restriction bypass (header spoofing/SSRF/real-IP) + report |
| v3.0.3 | DB dump: DbDumper first → auto fallback to manual pagination if DbDumper fails or misses STEP 0 tables |
| v3.0.2 | DB dump: AI verifies member tables via actual sample data (SELECT LIMIT 5), not just column names |
| v3.0.1 | DB table identification: column-name based detection + obfuscated table support |
| v3.0.0 | DbDumper flexible usage — AI selects method by context (no WAF / WAF / WebShell) |
| v2.9.8 | Simplified save rules: /tmp/ allowed for intermediate files, Desktop for final output only |
| v2.9.7 | All final output files enforced to Desktop/dump/target/ |
| v2.9.6 | DB dump: forbid /tmp/ save, enforce Desktop path, add FLOOR injection query_fn template |
| v2.9.5 | XSS reflection dedup fix — prevent false infinite-loop kill on repeated reflections |
| v2.9.3 | DB dump: no row limit + Desktop save path (macOS/Windows auto-detect) |
| v2.9.2 | CMS bias fix — fresh detection per target, zero assumptions |
| v2.9.1 | Bug fixes: variable substitution, warning spam, false positives |
| v2.9.0 | 11 new modules: HTTP smuggling, GraphQL, OAuth/JWT, Playwright, alerts |
| v2.8.0 | SQLi engine overhaul — sqlmap-level precision |
| v2.7.0 | Auto DB dump on successful breach |
| v2.3.0 | Burp Engine — full Repeater/Intruder/Scanner in pure Python |
| v2.2.0 | Pentest Precision Engine — WAF bypass, CAPTCHA OCR |
| v2.1.0 | API fuzzing, post-report interactive actions |

---

## Languages

```bash
/lang        # Switch language in chat
```

| Language | Code |
|----------|------|
| English | `en` |
| 한국어 | `ko` |
| 中文 | `zh` |

---

## Requirements

- Python 3.10+
- API key for at least one supported model
- (Optional) VPN for anonymity — auto-detected and displayed

---

## Contributing

```bash
git clone https://github.com/bingook/bingo.git
cd bingo && bash install.sh
```

Pull requests welcome. Open an issue first for major changes.

---

## License

MIT © 2026 bingook

---

<div align="center">

**Type your target. bingo does the rest.**

</div>
