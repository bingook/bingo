"""
skills_data9.py — TruffleHog APK Scanner + Malimite iOS Decompiler Skills
bingo v2.2.9

References:
  TruffleHog APK : https://trufflesecurity.com/blog/cracking-open-apk-files-at-scale
  Malimite        : https://github.com/LaurieWired/Malimite
"""
from __future__ import annotations

SKILLS_DB_9: list[dict] = [
    # ──────────────────────────────────────────────────────────────────────────
    # 1. TruffleHog Native APK Scanner
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "apk-trufflehog-scan",
        "module": "mobile",
        "tags": [
            # Tool names
            "trufflehog", "trufflesecurity",
            # Target types
            "apk", "android", "mobile",
            # Task keywords
            "secret", "secret-scan", "leaked-key", "hardcoded", "hardcoded-secret",
            "api-key", "api_key", "apikey",
            # File targets inside APK
            "dex", "classes-dex", "strings.xml", "resources-arsc", "resources.arsc",
            "androidmanifest", "manifest",
            # Credential types
            "aws-key", "firebase", "google-api", "stripe", "github-token",
            "jwt", "private-key",
            # Performance
            "fast-scan", "no-jadx", "no-decompile",
        ],
        "desc": {
            "ko": (
                "TruffleHog 네이티브 APK 스캐너 — jadx 없이 9배 빠른 시크릿 탐지.\n"
                "  ① AndroidManifest.xml → Android Binary XML을 resources.arsc로 디코드\n"
                "  ② strings.xml → resources.arsc ID 범위 0x7f000000-0x7fffffff 에서 재구성\n"
                "  ③ DEX 바이트코드 → const-string 명령어 + 클래스/메서드 컨텍스트\n"
                "  ④ 기타 모든 파일 → *.json, *.properties, sqlite, .git, asset JS"
            ),
            "en": (
                "TruffleHog native APK secret scanner — 9× faster than jadx method.\n"
                "  ① AndroidManifest.xml → Android Binary XML decoded via resources.arsc ResourceTable\n"
                "  ② strings.xml → reconstructed from resources.arsc ID range 0x7f000000–0x7fffffff\n"
                "  ③ DEX bytecode → const-string instructions with class/method context keywords\n"
                "  ④ All other files → *.json, *.properties, sqlite DBs, .git dirs, asset JS"
            ),
            "zh": (
                "TruffleHog 原生 APK 密钥扫描 — 比 jadx 方法快9倍。\n"
                "  ① AndroidManifest.xml → 通过 resources.arsc ResourceTable 解码 Android 二进制 XML\n"
                "  ② strings.xml → 从 resources.arsc ID 范围 0x7f000000–0x7fffffff 重建\n"
                "  ③ DEX 字节码 → const-string 指令+类/方法上下文关键词\n"
                "  ④ 所有其他文件 → *.json, *.properties, sqlite, .git 目录, asset JS"
            ),
        },
        "tools": [
            "bingo.tools.apk_secret_scanner.scan_apk_trufflehog",
            "bingo.tools.apk_secret_scanner.auto_scan",
        ],
        "commands": [
            "# Native APK scan (no decompiler needed — recommended)",
            "trufflehog filesystem target.apk --json --no-verification",
            "trufflehog filesystem target.apk --json  # with cloud verification",
            "# Docker variant",
            "docker run -v $(pwd):/work trufflesecurity/trufflehog:latest filesystem /work/target.apk --json",
            "# bingo Python API",
            "python3 -c \"from bingo.tools.apk_secret_scanner import scan_apk_trufflehog; r=scan_apk_trufflehog('target.apk'); print(r.summary())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "TruffleHog v3.63+ 필요.\n"
                "설치: brew install trufflesecurity/trufflehog/trufflehog\n"
                "jadx 없어도 됨 — TruffleHog이 APK를 직접 파싱."
            ),
            "en": (
                "Requires TruffleHog v3.63+.\n"
                "Install: brew install trufflesecurity/trufflehog/trufflehog\n"
                "No jadx needed — TruffleHog parses APK natively."
            ),
            "zh": (
                "需要 TruffleHog v3.63+。\n"
                "安装: brew install trufflesecurity/trufflehog/trufflehog\n"
                "无需 jadx — TruffleHog 直接解析 APK。"
            ),
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    # 2. jadx + TruffleHog (thorough, slower)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "apk-trufflehog-jadx",
        "module": "mobile",
        "tags": [
            "trufflehog", "jadx", "apk", "android", "mobile",
            "decompile", "thorough", "full-decompile",
            "secret", "secret-scan", "obfuscated",
        ],
        "desc": {
            "ko": (
                "jadx 완전 디컴파일 후 TruffleHog 스캔 — 더 철저하지만 ~9배 느림.\n"
                "난독화된 코드, 동적 클래스 로딩, 비표준 위치 시크릿까지 커버.\n"
                "네이티브 스캔이 놓친 경우 보완으로 사용."
            ),
            "en": (
                "Full jadx decompile then TruffleHog scan — more thorough but ~9× slower.\n"
                "Covers obfuscated code, dynamic class loading, secrets in non-standard locations.\n"
                "Use as follow-up when native scan finds nothing suspicious."
            ),
            "zh": (
                "完整 jadx 反编译后 TruffleHog 扫描 — 更彻底但约慢9倍。\n"
                "覆盖混淆代码、动态类加载、非标准位置的密钥。\n"
                "当原生扫描未发现可疑内容时作为补充使用。"
            ),
        },
        "tools": [
            "bingo.tools.apk_secret_scanner.scan_apk_jadx_trufflehog",
        ],
        "commands": [
            "# Step 1: Decompile",
            "jadx target.apk -d ./decompiled_src/",
            "# Step 2: Scan decompiled output",
            "trufflehog filesystem ./decompiled_src/ --json --no-verification",
            "# bingo one-liner",
            "python3 -c \"from bingo.tools.apk_secret_scanner import scan_apk_jadx_trufflehog; r=scan_apk_jadx_trufflehog('target.apk'); print(r.summary())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "jadx + trufflehog 모두 필요. brew install jadx",
            "en": "Requires both jadx and trufflehog. brew install jadx",
            "zh": "需要 jadx 和 trufflehog 两者。brew install jadx",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Malimite iOS Decompiler
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "ios-malimite-decompile",
        "module": "mobile",
        "tags": [
            # Tool
            "malimite", "ghidra",
            # Platform
            "ios", "macos", "ipa", "app-bundle",
            # Language
            "swift", "objective-c", "objc",
            # Task
            "decompile", "reverse-engineering", "re", "static-analysis",
            "mobile", "frida",
            # Features
            "llm-translation", "swift-class", "method-naming",
            # Security focus
            "keychain", "ssl-pinning", "jailbreak-detection",
        ],
        "desc": {
            "ko": (
                "Malimite — Ghidra 기반 iOS/macOS IPA 디컴파일러.\n"
                "  • Swift 클래스 재구성 (struct, enum, protocol)\n"
                "  • Objective-C 메서드 지원\n"
                "  • 내장 LLM 메서드 번역 (난독화 이름 해독)\n"
                "  • 라이브러리 코드 제외 → 앱 코드만 집중 분석\n"
                "  • bingo 자동 후처리: 시크릿 스캔 + 보안 민감 메서드 목록"
            ),
            "en": (
                "Malimite — Ghidra-based iOS/macOS IPA decompiler.\n"
                "  • Swift class reconstruction (struct, enum, protocol)\n"
                "  • Objective-C method support\n"
                "  • Built-in LLM method translation (resolve obfuscated names)\n"
                "  • Skips library code → focused analysis of app-only code\n"
                "  • bingo auto post-processing: secret scan + security-sensitive method listing"
            ),
            "zh": (
                "Malimite — 基于 Ghidra 的 iOS/macOS IPA 反编译器。\n"
                "  • Swift 类重建 (struct, enum, protocol)\n"
                "  • Objective-C 方法支持\n"
                "  • 内置 LLM 方法翻译（解析混淆名称）\n"
                "  • 跳过库代码 → 专注应用自身代码分析\n"
                "  • bingo 自动后处理：密钥扫描 + 安全敏感方法列表"
            ),
        },
        "tools": [
            "bingo.tools.apk_secret_scanner.decompile_ipa_malimite",
            "bingo.tools.apk_secret_scanner.scan_and_decompile_ios",
        ],
        "commands": [
            "# Download Malimite JAR: https://github.com/LaurieWired/Malimite/releases",
            "java -jar ~/tools/Malimite.jar target.ipa --output ./decompiled_output/",
            "# Scan decompiled output for secrets",
            "trufflehog filesystem ./decompiled_output/ --json --no-verification",
            "# bingo all-in-one (decompile + secret scan)",
            "python3 -c \"from bingo.tools.apk_secret_scanner import decompile_ipa_malimite; r=decompile_ipa_malimite('target.ipa'); print(r.summary())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "Java 17+ 필요: brew install openjdk@17\n"
                "Malimite.jar 다운로드: https://github.com/LaurieWired/Malimite/releases\n"
                "JAR 위치: ~/tools/Malimite.jar 또는 MALIMITE_JAR 환경 변수 설정"
            ),
            "en": (
                "Requires Java 17+: brew install openjdk@17\n"
                "Download Malimite.jar: https://github.com/LaurieWired/Malimite/releases\n"
                "Place JAR at ~/tools/Malimite.jar or set MALIMITE_JAR env var"
            ),
            "zh": (
                "需要 Java 17+：brew install openjdk@17\n"
                "下载 Malimite.jar：https://github.com/LaurieWired/Malimite/releases\n"
                "将 JAR 放在 ~/tools/Malimite.jar 或设置 MALIMITE_JAR 环境变量"
            ),
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Unified Mobile Secret Pipeline
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "mobile-secret-pipeline",
        "module": "mobile",
        "tags": [
            "mobile", "android", "ios", "apk", "ipa",
            "secret", "pipeline", "comprehensive", "full-scan",
            "trufflehog", "malimite",
            "hardcoded", "api-key", "leaked-credential",
            "auto", "auto-detect",
        ],
        "desc": {
            "ko": (
                "모바일 시크릿 종합 스캔 파이프라인 — 파일 타입 자동 감지.\n"
                "  .apk → TruffleHog 네이티브 스캔 (9배 빠름)\n"
                "  .ipa → Malimite 디컴파일 + 시크릿 스캔\n"
                "  패키지명/URL → APK/IPA 다운로드 명령 자동 생성"
            ),
            "en": (
                "Comprehensive mobile secret scanning pipeline — auto-detects file type.\n"
                "  .apk → TruffleHog native scan (9× faster, no decompiler)\n"
                "  .ipa → Malimite decompile + secret scan\n"
                "  package name / URL → auto-generates APK/IPA download commands"
            ),
            "zh": (
                "移动端综合密钥扫描流水线 — 自动检测文件类型。\n"
                "  .apk → TruffleHog 原生扫描（快9倍，无需反编译器）\n"
                "  .ipa → Malimite 反编译+密钥扫描\n"
                "  包名/URL → 自动生成 APK/IPA 下载命令"
            ),
        },
        "tools": [
            "bingo.tools.apk_secret_scanner.auto_scan",
            "bingo.tools.apk_secret_scanner.check_tools",
            "bingo.tools.apk_secret_scanner.install_guide",
        ],
        "commands": [
            "# Android APK",
            "python3 -c \"from bingo.tools.apk_secret_scanner import auto_scan; r=auto_scan('target.apk'); print(r.summary())\"",
            "# iOS IPA",
            "python3 -c \"from bingo.tools.apk_secret_scanner import auto_scan; r=auto_scan('target.ipa'); print(r.summary())\"",
            "# Package name (no file)",
            "python3 -c \"from bingo.tools.apk_secret_scanner import auto_scan; import json; print(json.dumps(auto_scan('com.target.app'), indent=2))\"",
            "# Check tool availability",
            "python3 -c \"from bingo.tools.apk_secret_scanner import check_tools; import json; print(json.dumps(check_tools(), indent=2))\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "APK: TruffleHog 필요. IPA: Java 17+ + Malimite.jar 필요.",
            "en": "APK: needs TruffleHog. IPA: needs Java 17+ + Malimite.jar.",
            "zh": "APK：需要 TruffleHog。IPA：需要 Java 17+ + Malimite.jar。",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    # 5. DEX Bytecode Secret Analysis (educational/manual)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "name": "apk-dex-secret-analysis",
        "module": "mobile",
        "tags": [
            "dex", "bytecode", "android", "const-string",
            "resources-arsc", "strings-xml", "binary-xml",
            "secret", "trufflehog", "apk",
            "manual", "low-level",
        ],
        "desc": {
            "ko": (
                "DEX 바이트코드 시크릿 분석 원리 설명 + 수동 추출.\n"
                "  • const-string 명령어에서 API 키/토큰 추출\n"
                "  • resources.arsc로 strings.xml 재구성 (ID 0x7f000000-0x7fffffff)\n"
                "  • Android Binary XML 디코딩 원리\n"
                "  • TruffleHog의 keyword pre-flighting 메커니즘 이해"
            ),
            "en": (
                "DEX bytecode secret analysis — principles and manual extraction.\n"
                "  • Extract API keys/tokens from const-string DEX instructions\n"
                "  • Reconstruct strings.xml via resources.arsc (ID range 0x7f000000–0x7fffffff)\n"
                "  • Android Binary XML decoding mechanics\n"
                "  • How TruffleHog keyword pre-flighting works for APK scanning"
            ),
            "zh": (
                "DEX 字节码密钥分析原理与手动提取。\n"
                "  • 从 const-string DEX 指令提取 API 密钥/令牌\n"
                "  • 通过 resources.arsc 重建 strings.xml（ID 范围 0x7f000000–0x7fffffff）\n"
                "  • Android 二进制 XML 解码机制\n"
                "  • TruffleHog keyword pre-flighting 工作原理"
            ),
        },
        "tools": [
            "bingo.tools.apk_secret_scanner.scan_apk_trufflehog",
            "bingo.tools.apk_secret_scanner._scan_apk_manual",
        ],
        "commands": [
            "# Manual DEX string extraction",
            "unzip -p target.apk classes.dex | strings | grep -E 'AKIA|AIza|sk_live|eyJ'",
            "# List all files in APK",
            "unzip -l target.apk",
            "# Extract strings.xml from APK",
            "unzip target.apk res/values/strings.xml -d ./extracted/",
            "# Full TruffleHog APK scan with jq filter",
            "trufflehog filesystem target.apk --json --no-verification | jq -r '\"[\" + .DetectorName + \"] \" + .Redacted'",
            "# Check resources.arsc range",
            "python3 -c \"import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); print([n for n in z.namelist() if 'arsc' in n.lower()])\" target.apk",
        ],
        "payloads": [],
        "notes": {
            "ko": "resources.arsc ID 범위 0x7f000000-0x7fffffff에 strings.xml 데이터가 들어있음",
            "en": "strings.xml data lives in resources.arsc ID range 0x7f000000–0x7fffffff",
            "zh": "strings.xml 数据存储在 resources.arsc ID 范围 0x7f000000–0x7fffffff",
        },
    },
]

# ── Index generation ──────────────────────────────────────────────────────────

MODULE_INDEX_9: dict[str, list[str]] = {}
TAG_INDEX_9: dict[str, list[str]] = {}

for _s in SKILLS_DB_9:
    _mod = _s.get("module", "misc")
    MODULE_INDEX_9.setdefault(_mod, []).append(_s["name"])
    for _t in _s.get("tags", []):
        TAG_INDEX_9.setdefault(_t, []).append(_s["name"])
