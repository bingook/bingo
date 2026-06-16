"""
skills_data11.py — Windows EXE / PE Phase 0 Static Analysis Skills
bingo v2.3.4

6 AI-selectable skills for Windows executable analysis:
  - exe-pe-analysis       : Full PE header + section + import analysis
  - exe-string-extract    : Extract URLs, IPs, secrets from EXE
  - exe-import-analysis   : Suspicious API import detection
  - exe-packer-detect     : Packer / protector / obfuscation detection
  - exe-yara-scan         : YARA rule matching
  - exe-full-pipeline     : Complete EXE analysis pipeline

All skills support: Korean / English / Chinese descriptions
"""

from __future__ import annotations

SKILLS_DB_11: list[dict] = [
    # ─────────────────────────────────────────────────────────────
    # 1. exe-pe-analysis — Full PE Static Analysis
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-pe-analysis",
        "module": "exe",
        "tags": [
            # EN
            "exe analysis", "pe analysis", "pe file", "pe header", "analyze exe",
            "static analysis exe", "windows executable", "pe static", "dll analysis",
            "sys analysis", "driver analysis", "exe phase 0", "pe phase 0",
            "windows binary analysis", "executable analysis", "pe recon",
            "pe structure", "pe metadata", "pe info", "pe header analysis",
            "pe section analysis", "compile time", "image base", "entry point",
            "subsystem", "architecture x86 x64", "dotnet detection", "pe checksum",
            # KO
            "exe 분석", "pe 분석", "pe 헤더", "실행파일 분석", "윈도우 실행파일",
            "악성코드 정적 분석", "dll 분석", "exe 정적", "pe 구조",
            # ZH
            "PE分析", "exe分析", "PE文件分析", "Windows可执行文件", "静态分析EXE",
            "PE头分析", "可执行文件分析",
        ],
        "desc": {
            "ko": (
                "Windows PE(EXE/DLL/SYS) 파일의 전체 정적 분석을 수행합니다. "
                "PE 헤더(아키텍처, 컴파일 시간, 서브시스템, 진입점), 섹션 분석(엔트로피), "
                "임포트/익스포트 테이블, .NET 탐지, 디지털 서명, "
                "버전 정보 등을 추출합니다. 실행 없이 100% 정적 분석."
            ),
            "en": (
                "Full static analysis of Windows PE files (EXE/DLL/SYS/SCR). "
                "Extracts PE headers (architecture, compile timestamp, subsystem, entry point), "
                "section metadata, import/export tables, .NET detection, digital signature status, "
                "version info (product name, company, original filename). "
                "100% static — no execution required."
            ),
            "zh": (
                "对Windows PE文件（EXE/DLL/SYS）进行全面静态分析。"
                "提取PE头（架构、编译时间、子系统、入口点）、节信息（熵值）、"
                "导入/导出表、.NET检测、数字签名状态、版本信息。"
                "纯静态分析，无需执行文件。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer.analyze_pe",
            "bingo.tools.exe_analyzer.quick_scan",
        ],
        "commands": [
            "python3 -c \"from bingo.tools.exe_analyzer import quick_scan; print(quick_scan('target.exe'))\"",
            "# pefile installation",
            "pip install pefile lief",
            "# Basic analysis",
            "python3 -c \"from bingo.tools.exe_analyzer import analyze_pe; r=analyze_pe('sample.exe'); print(r.summary())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "pefile 라이브러리가 필요합니다 (pip install pefile). "
                "lief를 추가 설치하면 더 정확한 분석이 가능합니다. "
                "실행파일을 절대 실행하지 마세요 — 격리된 환경(VM/Sandbox)에서만 분석하세요. "
                "컴파일 시간은 조작될 수 있으므로 참고 자료로만 활용하세요."
            ),
            "en": (
                "Requires pefile (pip install pefile). "
                "Install lief for richer analysis (pip install lief). "
                "NEVER execute the target file — analyze in isolated environment (VM/Sandbox). "
                "Compile timestamp can be faked by malware authors — use as reference only."
            ),
            "zh": (
                "需要pefile库（pip install pefile）。安装lief可获得更丰富分析（pip install lief）。"
                "切勿执行目标文件——只在隔离环境（VM/沙箱）中分析。"
                "编译时间戳可能被篡改，仅作参考。"
            ),
        },
    },

    # ─────────────────────────────────────────────────────────────
    # 2. exe-string-extract — String Extraction
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-string-extract",
        "module": "exe",
        "tags": [
            # EN
            "exe strings", "extract strings exe", "strings from binary",
            "url in exe", "ip in exe", "domain in exe", "registry in exe",
            "hardcoded secret exe", "api key exe", "password exe", "credential exe",
            "mutex exe", "c2 address", "c2 url", "malware c2", "hardcoded ip",
            "embedded url", "strings binary", "strings analysis",
            "extract credentials exe", "exe secrets", "binary strings",
            # KO
            "exe 문자열", "실행파일 문자열", "악성코드 c2", "하드코딩 ip",
            "실행파일 시크릿", "바이너리 문자열 추출",
            # ZH
            "EXE字符串", "二进制字符串提取", "恶意软件C2", "硬编码IP", "EXE密钥",
        ],
        "desc": {
            "ko": (
                "EXE/DLL/SYS 바이너리에서 의미 있는 문자열을 자동 추출합니다. "
                "C2 URL, 하드코딩 IP/도메인, API 키, 패스워드, 레지스트리 경로, "
                "파일 경로, 뮤텍스 이름, User-Agent, Base64 인코딩 데이터 등을 탐지합니다."
            ),
            "en": (
                "Automatically extracts meaningful strings from EXE/DLL/SYS binaries. "
                "Detects: C2 URLs, hardcoded IPs/domains, API keys, passwords, "
                "registry paths, file paths, mutex names, User-Agent strings, "
                "Base64-encoded blobs, and email addresses."
            ),
            "zh": (
                "自动从EXE/DLL/SYS二进制文件中提取有意义的字符串。"
                "检测：C2 URL、硬编码IP/域名、API密钥、密码、"
                "注册表路径、文件路径、互斥体名称、User-Agent字符串、Base64编码数据。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer._extract_strings",
            "bingo.tools.exe_analyzer.analyze_pe",
        ],
        "commands": [
            "# Extract all strings from binary",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe')",
            "print('URLs:', r.strings.urls)",
            "print('IPs:', r.strings.ips)",
            "print('Secrets:', r.strings.api_keys)",
            "print('Mutexes:', r.strings.mutexes)",
            "\"",
            "# CLI: classic strings command",
            "strings target.exe | grep -E 'https?://'",
            "strings target.exe | grep -E '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "Base64 인코딩된 문자열은 실제 페이로드나 설정 데이터일 수 있습니다. "
                "C2 주소는 DGA(도메인 생성 알고리즘)로 동적 생성될 수 있어 "
                "정적 분석만으로는 모든 C2를 찾을 수 없습니다."
            ),
            "en": (
                "Base64 strings may be encoded payloads or config data — decode and inspect. "
                "C2 addresses can be dynamically generated via DGA, "
                "so static analysis may not reveal all C2 infrastructure."
            ),
            "zh": (
                "Base64字符串可能是编码的载荷或配置数据。"
                "C2地址可能通过DGA动态生成，静态分析可能无法发现所有C2基础设施。"
            ),
        },
    },

    # ─────────────────────────────────────────────────────────────
    # 3. exe-import-analysis — Suspicious API Detection
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-import-analysis",
        "module": "exe",
        "tags": [
            # EN
            "import analysis", "exe imports", "dll imports", "suspicious api",
            "process injection detection", "api call analysis", "malware imports",
            "virtualalloc", "createremotethread", "writeprocessmemory",
            "minidumpwritedump", "credential dumping", "anti debug detection",
            "lsass access", "hook detection", "keylogger detection",
            "screen capture detection", "registry persistence detection",
            "import table", "iat analysis", "function imports",
            "suspicious windows api", "malware indicator",
            # KO
            "임포트 분석", "악성 api", "프로세스 인젝션 탐지", "임포트 테이블",
            "악성코드 지표", "윈도우 api 분석",
            # ZH
            "导入分析", "恶意API检测", "进程注入检测", "IAT分析", "恶意软件指标",
        ],
        "desc": {
            "ko": (
                "PE 파일의 임포트 테이블을 분석하여 악성 행위 관련 Windows API를 탐지합니다. "
                "프로세스 인젝션(VirtualAllocEx/WriteProcessMemory/CreateRemoteThread), "
                "프로세스 할로잉(NtUnmapViewOfSection), 자격증명 덤프(MiniDumpWriteDump), "
                "안티 디버깅(IsDebuggerPresent), 키로거(GetAsyncKeyState), "
                "레지스트리 퍼시스턴스 등 30+ 의심 API를 자동 분류합니다."
            ),
            "en": (
                "Analyzes PE import tables to detect malicious Windows API usage. "
                "Automatically classifies: process injection (VirtualAllocEx/WriteProcessMemory/CreateRemoteThread), "
                "process hollowing (NtUnmapViewOfSection), credential dumping (MiniDumpWriteDump), "
                "anti-debugging (IsDebuggerPresent), keylogging (GetAsyncKeyState), "
                "registry persistence (RegSetValueEx), and 30+ other suspicious APIs."
            ),
            "zh": (
                "分析PE文件的导入表，检测恶意Windows API使用情况。"
                "自动分类：进程注入（VirtualAllocEx/WriteProcessMemory/CreateRemoteThread）、"
                "进程空洞（NtUnmapViewOfSection）、凭据转储（MiniDumpWriteDump）、"
                "反调试（IsDebuggerPresent）、键盘记录（GetAsyncKeyState）、"
                "注册表持久化等30+可疑API。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer.analyze_pe",
            "bingo.tools.exe_analyzer._SUSPICIOUS_IMPORTS",
        ],
        "commands": [
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe')",
            "for fn, reason in r.suspicious_imports:",
            "    print(f'  [{reason}] {fn}')",
            "\"",
            "# Check capabilities score",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe')",
            "print(r.capabilities.severity())",
            "for cap, ev in r.capabilities.capabilities:",
            "    print(f'  {cap}: {ev}')",
            "\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "임포트가 거의 없거나 GetProcAddress 하나만 있는 경우 패커/난독화 의심. "
                "LoadLibraryA + GetProcAddress 조합은 동적 API 해결(런타임 임포트) 의미. "
                "pefile 없이는 기본 헤더만 파싱됩니다."
            ),
            "en": (
                "Very few imports or only GetProcAddress = likely packed/obfuscated. "
                "LoadLibraryA + GetProcAddress combination = dynamic API resolution at runtime. "
                "Without pefile installed, only basic header info is parsed."
            ),
            "zh": (
                "导入极少或只有GetProcAddress = 可能已加壳/混淆。"
                "LoadLibraryA + GetProcAddress组合 = 运行时动态API解析。"
                "未安装pefile时只解析基本头信息。"
            ),
        },
    },

    # ─────────────────────────────────────────────────────────────
    # 4. exe-packer-detect — Packer / Protector Detection
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-packer-detect",
        "module": "exe",
        "tags": [
            # EN
            "packer detection", "detect packer", "upx detection", "packed exe",
            "protector detection", "themida", "vmprotect", "aspack", "mpress",
            "obfuscated exe", "entropy analysis", "high entropy section",
            "packed binary", "encrypted binary", "exe obfuscation",
            "anti analysis", "unpacking", "die", "detect it easy",
            "exeinfope", "pe packer", "packer identifier",
            "is exe packed", "check if packed",
            # KO
            "패커 탐지", "upx 탐지", "패킹 탐지", "난독화 탐지", "엔트로피 분석",
            "패킹된 실행파일", "vmprotect 탐지", "themida 탐지",
            # ZH
            "加壳检测", "UPX检测", "混淆检测", "熵值分析", "加密二进制",
            "VMProtect检测", "Themida检测",
        ],
        "desc": {
            "ko": (
                "실행파일의 패커/프로텍터/난독화를 탐지합니다. "
                "섹션 엔트로피 분석(>7.0 = 암호화/압축 의심), 알려진 패커 섹션 이름 "
                "(UPX0/1/2, .aspack, .vmp0-2, .themida, .MPRESS 등), "
                "임포트 수 이상 탐지로 UPX/Themida/VMProtect/MPRESS/Enigma 등을 식별합니다."
            ),
            "en": (
                "Detects packers, protectors, and obfuscators in PE files. "
                "Uses section entropy analysis (>7.0 = encrypted/compressed), "
                "known packer section names (UPX0/1/2, .aspack, .vmp0-2, .themida, .MPRESS, etc.), "
                "and import count anomalies to identify UPX/Themida/VMProtect/MPRESS/Enigma."
            ),
            "zh": (
                "检测PE文件中的加壳、保护和混淆工具。"
                "使用节区熵值分析（>7.0=加密/压缩）、已知加壳节区名称"
                "（UPX0/1/2、.aspack、.vmp0-2、.themida、.MPRESS等）"
                "和导入数量异常来识别各种加壳工具。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer.analyze_pe",
            "bingo.tools.exe_analyzer._PACKER_SECTIONS",
        ],
        "commands": [
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe')",
            "if r.packer.detected:",
            "    print(f'Packer: {r.packer.packer_name} [{r.packer.confidence}]')",
            "    for ev in r.packer.evidence:",
            "        print(f'  Evidence: {ev}')",
            "else:",
            "    print('No packer detected')",
            "\"",
            "# Section entropy check",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe')",
            "for sec in r.sections:",
            "    flag = '⚠ HIGH ENTROPY' if sec.entropy > 7.0 else ''",
            "    print(f'{sec.name:<15} entropy={sec.entropy:.2f} {flag}')",
            "\"",
            "# External: Detect-It-Easy",
            "die target.exe",
            "diec target.exe    # console mode",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "엔트로피 7.0 이상 = 암호화 또는 압축 섹션 (패커 강력 의심). "
                "임포트가 2개 이하이면서 첫 섹션 엔트로피 높은 경우 UPX 또는 커스텀 패커. "
                "Detect-It-Easy (die) 외부 도구를 함께 사용하면 더 정확합니다. "
                "패킹된 파일은 언패킹 후 재분석이 필요합니다."
            ),
            "en": (
                "Entropy > 7.0 = encrypted/compressed section (strong packer indicator). "
                "≤2 imports + high first-section entropy = UPX or custom packer. "
                "Combine with Detect-It-Easy (die) for better accuracy. "
                "Packed files require unpacking before full analysis."
            ),
            "zh": (
                "熵值>7.0=加密/压缩节区（强加壳指标）。"
                "≤2个导入+第一节区高熵值=UPX或自定义加壳。"
                "结合Detect-It-Easy(die)可提高准确性。"
                "加壳文件需要脱壳后才能完整分析。"
            ),
        },
    },

    # ─────────────────────────────────────────────────────────────
    # 5. exe-yara-scan — YARA Rule Scanning
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-yara-scan",
        "module": "exe",
        "tags": [
            # EN
            "yara scan", "yara rules exe", "yara exe", "yara binary",
            "malware signature", "yara match", "threat hunting exe",
            "yara pattern", "signature detection", "malware detection yara",
            "custom yara rules", "yara rule file", "yara scan exe",
            "detect malware yara", "yara hunt",
            # KO
            "야라 스캔", "야라 룰", "악성코드 시그니처", "야라 패턴 매칭",
            "위협 헌팅 exe",
            # ZH
            "YARA扫描", "YARA规则", "恶意软件签名", "威胁猎捕EXE",
        ],
        "desc": {
            "ko": (
                "YARA 룰을 사용하여 PE 파일에서 악성코드 패턴을 탐지합니다. "
                "내장 룰(프로세스 인젝션, MiniDump, 안티 디버깅, 하드코딩 자격증명)이 기본 포함되며 "
                "사용자 정의 .yar 파일 경로를 지정하면 해당 룰셋으로 스캔합니다. "
                "yara-python 라이브러리 필요."
            ),
            "en": (
                "Scans PE files for malware patterns using YARA rules. "
                "Built-in rules cover process injection, MiniDump, anti-debug, and hardcoded credentials. "
                "Specify a custom .yar file path to scan with your own ruleset. "
                "Requires yara-python library."
            ),
            "zh": (
                "使用YARA规则扫描PE文件中的恶意软件模式。"
                "内置规则涵盖进程注入、MiniDump、反调试和硬编码凭据。"
                "指定自定义.yar文件路径以使用自己的规则集扫描。"
                "需要yara-python库。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer._run_yara",
            "bingo.tools.exe_analyzer._BUILT_IN_YARA",
            "bingo.tools.exe_analyzer.analyze_pe",
        ],
        "commands": [
            "pip install yara-python",
            "# Scan with built-in rules",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe', run_yara=True)",
            "print('YARA matches:', r.yara_matches)",
            "\"",
            "# Scan with custom rule file",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('target.exe', run_yara=True, yara_rules='/path/to/rules.yar')",
            "print('Matches:', r.yara_matches)",
            "\"",
            "# CLI yara",
            "yara rules.yar target.exe",
            "yara -r rules/ target_directory/",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "yara-python 없이도 bingo는 동작하지만 YARA 스캔은 건너뜁니다. "
                "커뮤니티 룰셋: https://github.com/Yara-Rules/rules "
                "악성코드 패밀리별 룰: https://github.com/reversinglabs/reversinglabs-yara-rules"
            ),
            "en": (
                "bingo works without yara-python but YARA scanning is skipped. "
                "Community rulesets: https://github.com/Yara-Rules/rules "
                "Malware family rules: https://github.com/reversinglabs/reversinglabs-yara-rules"
            ),
            "zh": (
                "没有yara-python时bingo仍可运行，但跳过YARA扫描。"
                "社区规则集：https://github.com/Yara-Rules/rules "
                "恶意软件家族规则：https://github.com/reversinglabs/reversinglabs-yara-rules"
            ),
        },
    },

    # ─────────────────────────────────────────────────────────────
    # 6. exe-full-pipeline — Complete EXE Analysis Pipeline
    # ─────────────────────────────────────────────────────────────
    {
        "name": "exe-full-pipeline",
        "module": "exe",
        "tags": [
            # EN
            "full exe analysis", "exe pipeline", "exe all in one",
            "malware analysis full", "pe full analysis", "exe complete analysis",
            "malware triage", "exe triage", "pe triage", "exe end to end",
            "binary analysis pipeline", "exe investigation", "malware investigation",
            "exe batch analysis", "batch pe analysis", "compare pe files",
            "virustotal lookup", "vt lookup hash", "hash lookup",
            "exe all", "full malware analysis",
            # KO
            "exe 전체 분석", "악성코드 전체 분석", "pe 파이프라인", "악성코드 조사",
            "바이러스토탈 조회", "해시 조회",
            # ZH
            "EXE全面分析", "恶意软件完整分析", "PE流水线", "VirusTotal查询", "哈希查询",
        ],
        "desc": {
            "ko": (
                "PE 파일의 완전한 분석 파이프라인을 실행합니다. "
                "해싱(MD5/SHA256/ImpHash/SSDeep) → PE 헤더 파싱 → 섹션 엔트로피 분석 → "
                "임포트 악성 API 탐지 → 패커 탐지 → 문자열 추출(C2/시크릿/레지스트리) → "
                "YARA 스캔 → 능력 점수 산정 → VirusTotal 해시 조회(선택). "
                "배치 분석 및 PE 파일 비교 기능도 포함."
            ),
            "en": (
                "Runs the complete PE analysis pipeline in one step: "
                "hashing (MD5/SHA256/ImpHash/SSDeep) → PE header parsing → section entropy → "
                "suspicious API import detection → packer detection → string extraction "
                "(C2/secrets/registry) → YARA scanning → capability scoring → "
                "VirusTotal hash lookup (optional). "
                "Also supports batch directory analysis and PE file comparison."
            ),
            "zh": (
                "一步运行完整PE分析流水线："
                "哈希（MD5/SHA256/ImpHash/SSDeep）→PE头解析→节区熵值→"
                "可疑API导入检测→加壳检测→字符串提取（C2/密钥/注册表）→"
                "YARA扫描→能力评分→VirusTotal哈希查询（可选）。"
                "还支持批量目录分析和PE文件比较。"
            ),
        },
        "tools": [
            "bingo.tools.exe_analyzer.analyze_pe",
            "bingo.tools.exe_analyzer.quick_scan",
            "bingo.tools.exe_analyzer.batch_analyze",
            "bingo.tools.exe_analyzer.compare_pe",
            "bingo.tools.exe_analyzer.vt_lookup",
            "bingo.tools.exe_analyzer.install_guide",
        ],
        "commands": [
            "# Full analysis — single file",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import analyze_pe",
            "r = analyze_pe('malware.exe', extract_strings=True, run_yara=True)",
            "print(r.summary())",
            "\"",
            "# Batch analysis — directory",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import batch_analyze",
            "results = batch_analyze('./samples/', recursive=True)",
            "for r in results:",
            "    print(r.summary())",
            "\"",
            "# Compare two PE files",
            "python3 -c \"",
            "from bingo.tools.exe_analyzer import compare_pe",
            "import json",
            "diff = compare_pe('original.exe', 'modified.exe')",
            "print(json.dumps(diff, indent=2))",
            "\"",
            "# VirusTotal hash lookup",
            "python3 -c \"",
            "import os",
            "from bingo.tools.exe_analyzer import analyze_pe, vt_lookup",
            "r = analyze_pe('target.exe')",
            "result = vt_lookup(r.hashes.sha256, api_key=os.environ.get('VT_API_KEY',''))",
            "print(result)",
            "\"",
            "# Print install guide",
            "python3 -c \"from bingo.tools.exe_analyzer import install_guide; print(install_guide())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "VirusTotal 조회는 VT_API_KEY 환경변수 설정 필요 (무료 API 키: virustotal.com). "
                "악성코드 샘플은 반드시 격리된 환경(VM/FlareVM/REMnux)에서 분석하세요. "
                "권장 분석 환경: FlareVM(Windows), REMnux(Linux), Cuckoo Sandbox(자동화). "
                "설치: pip install pefile lief yara-python ssdeep requests"
            ),
            "en": (
                "VirusTotal lookup requires VT_API_KEY env var (free API key at virustotal.com). "
                "ALWAYS analyze malware samples in isolated environments (VM/FlareVM/REMnux). "
                "Recommended environments: FlareVM (Windows), REMnux (Linux), Cuckoo Sandbox (automated). "
                "Install: pip install pefile lief yara-python ssdeep requests"
            ),
            "zh": (
                "VirusTotal查询需要设置VT_API_KEY环境变量（在virustotal.com获取免费API密钥）。"
                "务必在隔离环境（VM/FlareVM/REMnux）中分析恶意软件样本。"
                "推荐环境：FlareVM（Windows）、REMnux（Linux）、Cuckoo沙箱（自动化）。"
                "安装：pip install pefile lief yara-python ssdeep requests"
            ),
        },
    },
]

# ── index helpers ─────────────────────────────────────────────────────────────

MODULE_INDEX_11: dict[str, list[str]] = {}
TAG_INDEX_11: dict[str, list[str]] = {}

for _s in SKILLS_DB_11:
    _mod = _s.get("module", "exe")
    MODULE_INDEX_11.setdefault(_mod, []).append(_s["name"])
    for _tag in _s.get("tags", []):
        TAG_INDEX_11.setdefault(_tag.lower(), []).append(_s["name"])
