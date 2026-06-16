"""
skills_data12.py — .NET RE + CSWSH 스킬 DB
bingo v2.3.2

Reference: https://blog.voorivex.team/first-rce-via-reverse-engineering-with-ai

7 new skills:
  1. exe-dotnet-detect       — .NET assembly identification
  2. exe-dotnet-strings      — US-heap string dump & categorization
  3. exe-dotnet-crypto       — AES key / IV detection (adjacent-pair heuristic)
  4. exe-localhost-ws        — Localhost WebSocket server discovery
  5. cswsh-detect            — Cross-Site WebSocket Hijacking test
  6. cswsh-poc-gen           — CSWSH PoC HTML generator (RCE template)
  7. exe-dotnet-pipeline     — Full .NET → CSWSH analysis pipeline
"""
from __future__ import annotations

SKILLS_DB_12: dict[str, dict] = {

    # ── 1. .NET assembly detection ────────────────────────────────────────────
    "exe-dotnet-detect": {
        "id":          "exe-dotnet-detect",
        "name":        ".NET Assembly Detection",
        "name_ko":     ".NET 어셈블리 탐지",
        "name_zh":     ".NET程序集识别",
        "description": (
            "Detect whether a PE/EXE file is a .NET assembly. "
            "Checks for CLR header (BSJB magic), metadata stream names (#~, #Strings, #US, #GUID, #Blob), "
            "CLR version string, and Costura/ILMerge embedded DLLs."
        ),
        "description_ko": (
            "PE/EXE 파일이 .NET 어셈블리인지 탐지한다. "
            "CLR 헤더(BSJB 시그니처), 메타데이터 스트림명(#~, #Strings, #US, #GUID, #Blob), "
            "CLR 버전 문자열, Costura/ILMerge 내장 DLL 여부를 확인한다."
        ),
        "description_zh": (
            "检测PE/EXE文件是否为.NET程序集。"
            "检查CLR头(BSJB魔数)、元数据流名称、CLR版本字符串和Costura嵌入DLL。"
        ),
        "tags": [
            "dotnet", ".net", "clr", "csharp", "c#", "assembly",
            "pe analysis", "exe analysis", "reverse engineering",
            "bsjb", "metadata stream", "costura", "ilmerge",
            "dotnet detect", ".net detect", "is dotnet", "exe type",
            "exe 분석", ".NET 탐지", "어셈블리 탐지",
            "识别.NET", "程序集检测",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": ["detect_dotnet(file_path)"],
        "example_commands": [
            "python -m bingo.tools.dotnet_analyzer target.exe",
            'from bingo.tools.dotnet_analyzer import detect_dotnet; print(detect_dotnet("app.exe"))',
        ],
        "notes": (
            "KO: pefile 없이도 순수 Python으로 동작. BSJB 시그니처 + 스트림명으로 탐지.\n"
            "EN: Works without pefile — pure Python BSJB + stream name search.\n"
            "ZH: 无需pefile，纯Python检测CLR头和元数据流。"
        ),
    },

    # ── 2. .NET string dump ───────────────────────────────────────────────────
    "exe-dotnet-strings": {
        "id":          "exe-dotnet-strings",
        "name":        ".NET String Dump & Categorization",
        "name_ko":     ".NET 문자열 덤프 및 분류",
        "name_zh":     ".NET字符串提取与分类",
        "description": (
            "Extract all hardcoded strings from a .NET EXE's US (#UserStrings) heap. "
            "Categorizes results into: URLs, file paths, registry keys, crypto material, "
            "error messages, command keywords, update strings, credentials. "
            "Also generates a PowerShell reflection script for Windows-native extraction."
        ),
        "description_ko": (
            ".NET EXE의 US 힙에서 하드코딩된 문자열을 전부 추출한다. "
            "URLs, 파일 경로, 레지스트리 키, 암호화 재료, 오류 메시지, 명령어 키워드, "
            "업데이트 문자열, 자격증명 등으로 자동 분류한다. "
            "Windows 네이티브 추출용 PowerShell Reflection 스크립트도 생성한다."
        ),
        "description_zh": (
            "从.NET EXE的US堆提取所有硬编码字符串，"
            "自动分类为URL、路径、注册表键、加密材料、错误消息等。"
            "同时生成PowerShell反射脚本用于Windows原生提取。"
        ),
        "tags": [
            "dotnet strings", ".net string dump", "us heap", "hardcoded strings",
            "string extraction", "categorize strings", "powershell reflection",
            "url extraction", "registry path", "credential hunting",
            "reverse engineering", "binary analysis", "string analysis",
            "문자열 추출", "하드코딩 탐지", "PowerShell 덤프",
            "提取字符串", "硬编码字符串",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": [
            "extract_dotnet_strings(file_path)",
            "generate_powershell_dump(exe_path)",
        ],
        "example_commands": [
            'from bingo.tools.dotnet_analyzer import extract_dotnet_strings; strings = extract_dotnet_strings("app.exe")',
            "python -m bingo.tools.dotnet_analyzer app.exe",
        ],
        "notes": (
            "KO: 블로그 포스트 핵심 기술 — PowerShell Reflection으로 US 힙 덤프.\n"
            "EN: Core technique from the blog post — dump US heap via PowerShell reflection.\n"
            "ZH: 博文核心技术：通过PowerShell反射提取US堆字符串。"
        ),
    },

    # ── 3. Crypto material detection ─────────────────────────────────────────
    "exe-dotnet-crypto": {
        "id":          "exe-dotnet-crypto",
        "name":        ".NET Crypto Key / IV Detection",
        "name_ko":     ".NET 암호화 키·IV 탐지",
        "name_zh":     ".NET加密密钥/IV检测",
        "description": (
            "Identify potential AES keys, IVs, and crypto material in extracted strings. "
            "Uses the blog-post heuristic: 16-byte strings at adjacent heap offsets "
            "are likely a key+IV pair. Also detects 32/64-char hex strings and mixed "
            "alphanumeric 16/32-byte strings that don't look like natural language."
        ),
        "description_ko": (
            "추출된 문자열에서 AES 키, IV 등 암호화 재료를 식별한다. "
            "블로그 포스트 휴리스틱: 인접 힙 오프셋에 위치한 16바이트 문자열 쌍 = 키+IV. "
            "32/64자리 hex 문자열, 16/32바이트 영숫자 혼합 문자열도 탐지한다."
        ),
        "description_zh": (
            "识别提取字符串中的AES密钥、IV等加密材料。"
            "使用博文启发式方法：相邻堆偏移处的16字节字符串对可能是key+IV组合。"
        ),
        "tags": [
            "crypto", "aes key", "iv detection", "encryption key", "hardcoded key",
            "key iv pair", "16 byte", "32 byte", "hex key", "crypto material",
            "cryptanalysis", "reverse engineering crypto", "dotnet crypto",
            "암호화 키 탐지", "IV 탐지", "AES 키",
            "加密密钥检测", "AES密钥", "IV检测",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": ["detect_crypto_material(strings)"],
        "example_commands": [
            'from bingo.tools.dotnet_analyzer import extract_dotnet_strings, detect_crypto_material\n'
            'strings = extract_dotnet_strings("app.exe")\n'
            'crypto = detect_crypto_material(strings)',
        ],
        "notes": (
            "KO: 두 개의 16바이트 인접 문자열 발견 시 key+IV 쌍으로 플래그 처리.\n"
            "EN: Adjacent 16-byte pair → flag as potential key+IV (blog post pattern).\n"
            "ZH: 相邻16字节字符串对→标记为潜在key+IV（博文模式）。"
        ),
    },

    # ── 4. Localhost WebSocket discovery ─────────────────────────────────────
    "exe-localhost-ws": {
        "id":          "exe-localhost-ws",
        "name":        "Localhost WebSocket Server Discovery",
        "name_ko":     "로컬호스트 WebSocket 서버 탐지",
        "name_zh":     "本地WebSocket服务器发现",
        "description": (
            "Find ws://127.0.0.1:PORT or ws://localhost:PORT endpoints in EXE strings "
            "and JavaScript files. A localhost WebSocket server with no origin validation "
            "is a classic CSWSH attack surface — any website can connect to it."
        ),
        "description_ko": (
            "EXE 문자열 및 JS 파일에서 ws://127.0.0.1:PORT 또는 ws://localhost:PORT 엔드포인트를 찾는다. "
            "오리진 검증이 없는 로컬호스트 WebSocket 서버는 CSWSH 공격면 — 어떤 웹사이트도 접속 가능."
        ),
        "description_zh": (
            "在EXE字符串和JS文件中查找ws://127.0.0.1:PORT或ws://localhost:PORT端点。"
            "无origin验证的本地WebSocket服务器是典型CSWSH攻击面。"
        ),
        "tags": [
            "websocket", "localhost websocket", "ws://127.0.0.1", "ws://localhost",
            "local service", "port discovery", "cswsh surface", "attack surface",
            "javascript websocket", "ws endpoint", "websocket server",
            "exe websocket", "dotnet websocket", "reverse engineering ws",
            "로컬 WebSocket 탐지", "ws 포트 발견",
            "WebSocket本地服务", "ws://127", "端口发现",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": [
            "find_websocket_endpoints(strings)",
            "scan_js_for_websockets(js_content)",
            "test_ws_port_open(host, port)",
        ],
        "example_commands": [
            'from bingo.tools.dotnet_analyzer import extract_dotnet_strings, find_websocket_endpoints\n'
            'strings = extract_dotnet_strings("app.exe")\n'
            'eps = find_websocket_endpoints(strings)\n'
            'for ep in eps: print(ep.url)',
        ],
        "notes": (
            "KO: JS 파일에서도 탐지 가능 — scan_js_for_websockets(js_content).\n"
            "EN: Also scans JS files for 'new WebSocket(\"ws://127...\")' patterns.\n"
            "ZH: 同样扫描JS文件中的'new WebSocket(\"ws://127...\")'模式。"
        ),
    },

    # ── 5. CSWSH vulnerability test ───────────────────────────────────────────
    "cswsh-detect": {
        "id":          "cswsh-detect",
        "name":        "Cross-Site WebSocket Hijacking (CSWSH) Detection",
        "name_ko":     "크로스사이트 WebSocket 하이재킹(CSWSH) 탐지",
        "name_zh":     "跨站WebSocket劫持(CSWSH)检测",
        "description": (
            "Test a WebSocket endpoint for Cross-Site WebSocket Hijacking vulnerability. "
            "Sends HTTP Upgrade requests with no Origin header and with wrong Origin header. "
            "If both return 101 Switching Protocols → server performs no origin validation → CSWSH confirmed. "
            "Severity: Critical when combined with a powerful WebSocket API (RCE risk)."
        ),
        "description_ko": (
            "WebSocket 엔드포인트가 CSWSH에 취약한지 테스트한다. "
            "Origin 헤더 없음, 잘못된 Origin 헤더 두 경우 모두 101 응답 → 오리진 검증 없음 → CSWSH 확인. "
            "강력한 WebSocket API와 결합 시 심각도: Critical (RCE 위험)."
        ),
        "description_zh": (
            "测试WebSocket端点是否存在跨站WebSocket劫持漏洞。"
            "发送无Origin头和错误Origin头的HTTP Upgrade请求，"
            "两者均返回101→无origin验证→CSWSH确认。严重性：Critical(RCE风险)。"
        ),
        "tags": [
            "cswsh", "cross-site websocket hijacking", "websocket hijacking",
            "origin validation", "websocket security", "websocket vuln",
            "101 switching protocols", "no origin check", "websocket pentest",
            "localhost rce", "ws attack", "desktop app vuln",
            "크로스사이트 WebSocket", "CSWSH 탐지", "오리진 검증",
            "跨站WebSocket劫持", "CSWSH", "origin验证",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": [
            "test_cswsh(ws_url)",
            "cswsh_full_test(ws_url, save_poc=None)",
        ],
        "example_commands": [
            "python -m bingo.tools.dotnet_analyzer ws://127.0.0.1:3100",
            'from bingo.tools.dotnet_analyzer import cswsh_full_test\n'
            'print(cswsh_full_test("ws://127.0.0.1:3100", save_poc="poc.html"))',
        ],
        "notes": (
            "KO: 로컬 서비스라 직접 테스트하려면 대상 호스트에서 실행해야 함.\n"
            "EN: Tests via raw TCP WebSocket upgrade; run on the target host for local services.\n"
            "ZH: 通过原始TCP WebSocket升级测试；本地服务需在目标主机上运行。"
        ),
    },

    # ── 6. CSWSH PoC generator ────────────────────────────────────────────────
    "cswsh-poc-gen": {
        "id":          "cswsh-poc-gen",
        "name":        "CSWSH PoC HTML Generator",
        "name_ko":     "CSWSH PoC HTML 생성기",
        "name_zh":     "CSWSH PoC HTML生成器",
        "description": (
            "Generate a ready-to-use CSWSH attack PoC HTML page. "
            "The page auto-connects to the target WebSocket on load (zero interaction), "
            "enumerates WebSocket methods, and demonstrates RCE via gadgets like: "
            "{RUN: 'DRIVE', URL: 'calc.exe'} → falls through to explorer.exe '{URL}'. "
            "Includes multiple method probes (VERSION, EXECUTE, APP, DRIVE variants)."
        ),
        "description_ko": (
            "CSWSH 공격 PoC HTML 페이지를 즉시 사용 가능한 형태로 생성한다. "
            "페이지 로드 시 자동 WebSocket 연결(클릭 불필요), 메서드 열거, "
            "{RUN: 'DRIVE', URL: 'calc.exe'} → explorer.exe 폴백 RCE 가젯 실증. "
            "VERSION / EXECUTE / APP / DRIVE 변형 등 다중 메서드 프로브 포함."
        ),
        "description_zh": (
            "生成即用型CSWSH攻击PoC HTML页面。"
            "页面加载时自动连接WebSocket(零交互)，枚举方法，"
            "演示通过{RUN:'DRIVE',URL:'calc.exe'}→explorer.exe回退实现RCE。"
        ),
        "tags": [
            "cswsh poc", "websocket poc", "poc generator", "rce poc",
            "websocket hijacking exploit", "html poc", "one click rce",
            "zero interaction", "explorer.exe rce", "drive rce",
            "desktop app rce", "cswsh exploit", "websocket exploit",
            "PoC 생성", "RCE PoC", "CSWSH 익스플로잇",
            "PoC生成", "RCE演示", "WebSocket劫持利用",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": ["generate_cswsh_poc(ws_url, methods=None, rce_payload='calc.exe')"],
        "example_commands": [
            'from bingo.tools.dotnet_analyzer import generate_cswsh_poc\n'
            'html = generate_cswsh_poc("ws://127.0.0.1:3100", rce_payload="calc.exe")\n'
            'open("poc.html","w").write(html)',
            'from bingo.tools.dotnet_analyzer import generate_cswsh_poc\n'
            'html = generate_cswsh_poc("ws://127.0.0.1:3100",\n'
            '    methods=[{"action":"RCE","payload":{"RUN":"DRIVE","URL":"calc.exe"}}])',
        ],
        "notes": (
            "KO: 생성된 PoC를 attacker.com에서 호스팅하고 피해자가 방문하면 자동 실행.\n"
            "EN: Host the generated PoC on attacker.com — auto-fires when victim visits.\n"
            "ZH: 将生成的PoC托管在attacker.com——受害者访问时自动执行。"
        ),
    },

    # ── 7. Full .NET → CSWSH pipeline ────────────────────────────────────────
    "exe-dotnet-pipeline": {
        "id":          "exe-dotnet-pipeline",
        "name":        ".NET EXE → CSWSH Full Analysis Pipeline",
        "name_ko":     ".NET EXE → CSWSH 전체 분석 파이프라인",
        "name_zh":     ".NET EXE→CSWSH完整分析流水线",
        "description": (
            "Full AI-guided .NET reverse engineering pipeline inspired by the Voorivex blog post. "
            "Steps: (1) Detect .NET / CLR / embedded DLLs, (2) Dump & categorize all strings, "
            "(3) Find crypto keys/IVs, (4) Discover localhost WebSocket servers, "
            "(5) Test CSWSH (origin validation absence), (6) Generate attack PoC HTML. "
            "Mimics the AI-assisted methodology: break task into steps, feed results forward."
        ),
        "description_ko": (
            "Voorivex 블로그 포스트에서 영감을 받은 AI 가이드 .NET 리버스 엔지니어링 파이프라인. "
            "단계: (1) .NET/CLR/DLL 탐지, (2) 문자열 덤프 및 분류, "
            "(3) 암호화 키·IV 탐지, (4) 로컬호스트 WebSocket 서버 발견, "
            "(5) CSWSH 테스트(오리진 검증 부재), (6) PoC HTML 생성. "
            "AI 지원 방법론 모방: 작업을 단계별로 분해하고 결과를 다음 단계로 전달."
        ),
        "description_zh": (
            "受Voorivex博文启发的AI引导.NET逆向工程全流水线。"
            "步骤：(1)检测.NET/CLR/内嵌DLL，(2)提取分类字符串，"
            "(3)发现加密密钥/IV，(4)发现本地WebSocket服务器，"
            "(5)测试CSWSH(无origin验证)，(6)生成PoC HTML。"
        ),
        "tags": [
            "dotnet pipeline", ".net full analysis", "exe analysis pipeline",
            "reverse engineering pipeline", "ai assisted re", "cswsh pipeline",
            "dotnet to rce", "exe to cswsh", "full analysis",
            "websocket rce chain", "voorivex", "blog post technique",
            "exe pentest", "desktop app pentest", "thick client pentest",
            "전체 파이프라인", ".NET 분석 파이프라인", "CSWSH 파이프라인",
            "全流水线", ".NET逆向流水线", "CSWSH利用链",
        ],
        "module": "bingo.tools.dotnet_analyzer",
        "tools": [
            "analyze_dotnet(file_path)",
            "format_report(result)",
            "test_cswsh(ws_url)",
            "cswsh_full_test(ws_url, save_poc=None)",
            "generate_cswsh_poc(ws_url)",
        ],
        "example_commands": [
            "python -m bingo.tools.dotnet_analyzer target.exe",
            "python -m bingo.tools.dotnet_analyzer ws://127.0.0.1:3100",
            '# Full pipeline:\n'
            'from bingo.tools.dotnet_analyzer import analyze_dotnet, format_report, cswsh_full_test\n'
            'result = analyze_dotnet("target.exe")\n'
            'print(format_report(result))\n'
            'for ep in result.websocket_endpoints:\n'
            '    print(cswsh_full_test(ep.url, save_poc="poc.html"))',
        ],
        "notes": (
            "KO: 참조 포스트 핵심 교훈 — '하나의 큰 프롬프트 X, 작은 단계로 분해 O'.\n"
            "EN: Blog post lesson: don't use one huge prompt — break into small steps.\n"
            "ZH: 博文经验：不要用一个大提示词，要分解成小步骤逐步引导AI。"
        ),
    },
}

# ── Index builders ────────────────────────────────────────────────────────────

MODULE_INDEX_12: dict[str, list[str]] = {}
TAG_INDEX_12:    dict[str, list[str]] = {}

for _sid, _skill in SKILLS_DB_12.items():
    _mod = _skill.get("module", "")
    if _mod:
        MODULE_INDEX_12.setdefault(_mod, []).append(_sid)
    for _tag in _skill.get("tags", []):
        TAG_INDEX_12.setdefault(_tag.lower(), []).append(_sid)
