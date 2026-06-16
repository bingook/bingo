"""
skills_data8.py — Mobile App Phase 0 스킬 DB
bingo v2.2.7

Android / iOS 앱 침투테스트 Phase 0 (초기 정찰 ~ 환경 구성) 내장 스킬 12종.
OWASP MASTG / Mobile Top 10 / Cursor 동급 커버리지.

AI 자동선택:
  - .apk / .ipa 파일 경로가 주어진 경우
  - Android / iOS / 모바일 앱 타겟임을 명시한 경우
  - 패키지명 (com.xxx.xxx) 이 타겟인 경우
  - 앱스토어 URL 이 주어진 경우
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────
# Module / Tag 인덱스
# ─────────────────────────────────────────────────────────────

MODULE_INDEX_8: dict[str, list[str]] = {
    "mobile-phase0":         ["mobile_recon.mobile_phase0"],
    "mobile-android-static": ["mobile_recon.AndroidAnalyzer"],
    "mobile-android-dynamic":["mobile_recon.quick_setup_guide"],
    "mobile-ios-static":     ["mobile_recon.IOSAnalyzer"],
    "mobile-ios-dynamic":    ["mobile_recon.quick_setup_guide"],
    "mobile-secret-scan":    ["mobile_recon.SECRET_PATTERNS"],
    "mobile-ssl-bypass":     ["mobile_recon.SSL_PINNING_PATTERNS"],
    "mobile-deep-link":      ["mobile_recon.mobile_phase0"],
    "mobile-api-recon":      ["mobile_recon.ENDPOINT_PATTERNS"],
    "mobile-frida-setup":    ["mobile_recon.quick_setup_guide"],
    "mobile-store-osint":    ["mobile_recon.recon_by_store_url"],
    "mobile-env-setup":      ["mobile_recon.quick_setup_guide"],
}

TAG_INDEX_8: dict[str, list[str]] = {
    # 플랫폼
    "android":          ["mobile-phase0", "mobile-android-static", "mobile-android-dynamic"],
    "ios":              ["mobile-phase0", "mobile-ios-static", "mobile-ios-dynamic"],
    "apk":              ["mobile-android-static", "mobile-phase0"],
    "ipa":              ["mobile-ios-static", "mobile-phase0"],
    "mobile":           ["mobile-phase0", "mobile-android-static", "mobile-ios-static"],
    "app":              ["mobile-phase0"],
    # 기법
    "phase0":           ["mobile-phase0"],
    "phase-0":          ["mobile-phase0"],
    "static-analysis":  ["mobile-android-static", "mobile-ios-static"],
    "frida":            ["mobile-android-dynamic", "mobile-ios-dynamic", "mobile-frida-setup"],
    "objection":        ["mobile-android-dynamic", "mobile-ios-dynamic"],
    "ssl-pinning":      ["mobile-ssl-bypass"],
    "ssl-bypass":       ["mobile-ssl-bypass"],
    "certificate-pin":  ["mobile-ssl-bypass"],
    "deep-link":        ["mobile-deep-link"],
    "intent":           ["mobile-deep-link", "mobile-android-dynamic"],
    "hardcoded":        ["mobile-secret-scan"],
    "secret-scan":      ["mobile-secret-scan"],
    "api-key":          ["mobile-secret-scan"],
    "root-detection":   ["mobile-android-dynamic"],
    "jailbreak":        ["mobile-ios-dynamic"],
    "adb":              ["mobile-android-dynamic"],
    "mobsf":            ["mobile-android-static", "mobile-ios-static"],
    "apktool":          ["mobile-android-static"],
    "jadx":             ["mobile-android-static"],
    "class-dump":       ["mobile-ios-static"],
    "keychain":         ["mobile-ios-dynamic"],
    "shared-prefs":     ["mobile-android-dynamic"],
    "network-recon":    ["mobile-api-recon"],
    "endpoint":         ["mobile-api-recon"],
    "store-osint":      ["mobile-store-osint"],
    "play-store":       ["mobile-store-osint"],
    "app-store":        ["mobile-store-osint"],
    "recon":            ["mobile-phase0", "mobile-store-osint"],
    "pentest":          ["mobile-phase0", "mobile-android-static", "mobile-ios-static"],
    "owasp-mastg":      ["mobile-phase0", "mobile-android-static", "mobile-ios-static"],
    "mobile-top10":     ["mobile-phase0"],
}

# ─────────────────────────────────────────────────────────────
# 스킬 DB
# ─────────────────────────────────────────────────────────────

SKILLS_DB_8: list[dict] = [

    # ════════════════════════════════
    # 1. Phase 0 — 자동 진입점
    # ════════════════════════════════
    {
        "name": "mobile-phase0",
        "module": "mobile",
        "tags": ["mobile", "android", "ios", "phase0", "phase-0", "apk", "ipa",
                 "recon", "pentest", "owasp-mastg", "mobile-top10"],
        "desc": {
            "ko": (
                "모바일 앱 Phase 0 자동 정찰 (Android + iOS 통합 진입점).\n"
                "입력: .apk/.ipa 파일, 패키지명(com.x.x), 앱스토어 URL\n"
                "자동 수행:\n"
                "  Android: 매니페스트 파싱, exported 컴포넌트, 권한, 딥링크\n"
                "  iOS:     Info.plist, ATS, URL Scheme, 바이너리 보안 플래그\n"
                "  공통:    시크릿 스캔, 네트워크 엔드포인트, SDK 지문, 공격면 맵핑\n"
                "출력: Frida/ADB/objection 즉시 실행 명령 + 취약점 목록"
            ),
            "en": (
                "Mobile App Phase 0 auto-recon — unified Android + iOS entry point.\n"
                "Input: .apk/.ipa file, package name (com.x.x), app store URL\n"
                "Auto performs:\n"
                "  Android: manifest parse, exported components, permissions, deep links\n"
                "  iOS:     Info.plist, ATS settings, URL schemes, binary security flags\n"
                "  Both:    secret scan, network endpoint extraction, SDK fingerprint, attack surface map\n"
                "Output: ready-to-run Frida/ADB/objection commands + vulnerability list"
            ),
            "zh": (
                "移动App Phase 0自动侦察（Android+iOS统一入口）。\n"
                "输入：.apk/.ipa文件、包名(com.x.x)、应用商店URL\n"
                "自动执行：\n"
                "  Android：清单解析、导出组件、权限、深度链接\n"
                "  iOS：Info.plist、ATS设置、URL Scheme、二进制安全标志\n"
                "  共同：密钥扫描、网络端点提取、SDK指纹、攻击面映射\n"
                "输出：即用型Frida/ADB/objection命令+漏洞列表"
            ),
        },
        "tools": [
            "bingo.tools.mobile_recon.mobile_phase0",
            "bingo.tools.mobile_recon.quick_setup_guide",
        ],
        "commands": [
            "python3 -c \"from bingo.tools.mobile_recon import mobile_phase0; r=mobile_phase0('target.apk'); print(r.summary())\"",
            "python3 -c \"from bingo.tools.mobile_recon import mobile_phase0; r=mobile_phase0('com.target.app'); import json; print(json.dumps(r, indent=2))\"",
            "python3 -c \"from bingo.tools.mobile_recon import quick_setup_guide; print(quick_setup_guide())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "AI 자동선택 조건:\n"
                "  - '.apk' 또는 '.ipa' 파일이 타겟일 때\n"
                "  - 'com.xxx.xxx' 형태의 패키지명이 주어진 경우\n"
                "  - '앱 침투', 'apk 분석', 'ios 테스트', 'mobile pentest' 키워드\n"
                "  - Play Store / App Store URL이 주어진 경우"
            ),
            "en": (
                "Auto-select: .apk/.ipa file, package name, mobile pentest keyword, "
                "or Play Store/App Store URL as target."
            ),
            "zh": "自动选择：目标为.apk/.ipa文件、包名、移动渗透关键词或应用商店URL时触发。",
        },
    },

    # ════════════════════════════════
    # 2. Android — 정적 분석
    # ════════════════════════════════
    {
        "name": "mobile-android-static",
        "module": "mobile",
        "tags": ["android", "apk", "static-analysis", "apktool", "jadx", "mobsf",
                 "manifest", "permissions", "owasp-mastg"],
        "desc": {
            "ko": (
                "Android APK 정적 분석 (OWASP MASTG MSTG-ARCH / CODE 기준).\n"
                "도구 체인: aapt → apktool → jadx → MobSF\n"
                "분석 항목:\n"
                "  - AndroidManifest.xml: debuggable, backup, cleartext, exported 컴포넌트\n"
                "  - 소스코드: 하드코딩 시크릿, SQL 쿼리, 암호화 키\n"
                "  - 네트워크 보안 정책(NSC): cleartext, custom CA\n"
                "  - Native 라이브러리(.so): 취약 버전, 커스텀 프로토콜\n"
                "  - Smali: 역공학을 통한 민감 로직 파악"
            ),
            "en": (
                "Android APK static analysis (OWASP MASTG MSTG-ARCH/CODE).\n"
                "Tool chain: aapt → apktool → jadx → MobSF\n"
                "Analysis scope:\n"
                "  - AndroidManifest.xml: debuggable, backup, cleartext, exported components\n"
                "  - Source code: hardcoded secrets, SQL queries, crypto keys\n"
                "  - Network Security Config: cleartext, custom CA trust\n"
                "  - Native libs (.so): vulnerable versions, custom protocols\n"
                "  - Smali: reverse-engineer sensitive logic"
            ),
            "zh": (
                "Android APK静态分析（OWASP MASTG MSTG-ARCH/CODE）。\n"
                "工具链：aapt→apktool→jadx→MobSF\n"
                "分析范围：\n"
                "  - AndroidManifest.xml：debuggable/backup/cleartext/导出组件\n"
                "  - 源代码：硬编码密钥/SQL查询/加密Key\n"
                "  - 网络安全策略：明文/自定义CA\n"
                "  - Native库(.so)：漏洞版本/自定义协议\n"
                "  - Smali：逆向分析敏感逻辑"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.AndroidAnalyzer"],
        "commands": [
            "# APK 분해\napktool d target.apk -o ./decompiled",
            "# Java 소스 복원\njadx -d ./jadx_output target.apk",
            "# MobSF 자동 분석\ndocker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf\ncurl -F 'file=@target.apk' http://localhost:8000/api/v1/upload",
            "# 하드코딩 시크릿\ngrep -rE '(password|token|secret|api_key)\\s*=\\s*[\"\\'].+[\"\\']' ./decompiled/",
            "# 매니페스트 분석\ngrep -E 'android:(debuggable|allowBackup|exported|usesCleartextTraffic)' decompiled/AndroidManifest.xml",
            "# bingo 자동 분석\npython3 -c \"from bingo.tools.mobile_recon import AndroidAnalyzer; r=AndroidAnalyzer('target.apk').analyze(); print(r.summary())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: .apk 파일 경로 + 정적분석/매니페스트/소스 분석 의도.",
            "en": "Auto-select: .apk file path + static analysis / manifest / source review intent.",
            "zh": "自动选择：.apk文件路径+静态分析/清单/源码审计意图。",
        },
    },

    # ════════════════════════════════
    # 3. Android — 동적 분석 + Frida
    # ════════════════════════════════
    {
        "name": "mobile-android-dynamic",
        "module": "mobile",
        "tags": ["android", "frida", "objection", "adb", "dynamic-analysis",
                 "root-detection", "ssl-pinning", "shared-prefs", "intent"],
        "desc": {
            "ko": (
                "Android 동적 분석 — Frida + objection + ADB 워크플로우.\n"
                "환경: 루팅 기기 또는 에뮬레이터(Genymotion/AVD)\n"
                "주요 작업:\n"
                "  - ADB: 앱 데이터 디렉터리, SharedPreferences, SQLite DB, 로그\n"
                "  - Frida: SSL 피닝 우회, 루트 탐지 우회, 메서드 훅\n"
                "  - objection: 실시간 파일 탐색, 클래스 열거, 힙 인스턴스 검색\n"
                "  - Intent 공격: exported Activity/Service 강제 실행\n"
                "  - Broadcast: 취약한 Receiver 직접 트리거"
            ),
            "en": (
                "Android dynamic analysis — Frida + objection + ADB workflow.\n"
                "Environment: rooted device or emulator (Genymotion/AVD)\n"
                "Key operations:\n"
                "  - ADB: app data dir, SharedPreferences, SQLite DB, logcat\n"
                "  - Frida: SSL pinning bypass, root detection bypass, method hooking\n"
                "  - objection: live file exploration, class enumeration, heap instance search\n"
                "  - Intent attacks: force-launch exported Activity/Service\n"
                "  - Broadcast: directly trigger vulnerable Receivers"
            ),
            "zh": (
                "Android动态分析——Frida+objection+ADB工作流。\n"
                "环境：已root设备或模拟器（Genymotion/AVD）\n"
                "主要操作：\n"
                "  - ADB：应用数据目录/SharedPreferences/SQLite数据库/日志\n"
                "  - Frida：SSL Pinning绕过/root检测绕过/方法Hook\n"
                "  - objection：实时文件浏览/类枚举/堆实例搜索\n"
                "  - Intent攻击：强制启动导出的Activity/Service\n"
                "  - Broadcast：直接触发脆弱的Receiver"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.AndroidAnalyzer"],
        "commands": [
            "# Frida SSL 피닝 우회\nfrida -U -l https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/ -f <package>",
            "# objection 종합\nobjection -g <package> explore\n# → android sslpinning disable\n# → android root disable\n# → android hooking list classes",
            "# ADB — SharedPrefs\nadb shell run-as <package> cat /data/data/<package>/shared_prefs/*.xml",
            "# ADB — SQLite\nadb shell run-as <package> sqlite3 /data/data/<package>/databases/*.db '.tables'",
            "# ADB — logcat 시크릿\nadb logcat | grep -iE 'token|password|secret|api_key|Bearer'",
            "# exported Activity 실행\nadb shell am start -n <package>/<activity>",
            "# exported Service\nadb shell am startservice -n <package>/<service>",
            "# Broadcast trigger\nadb shell am broadcast -a <action> -n <package>/<receiver>",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'frida', 'objection', 'adb', '루트 탐지 우회', 'ssl 우회' 키워드 + Android 타겟.",
            "en": "Auto-select: frida/objection/adb/root-bypass/ssl-bypass keywords + Android target.",
            "zh": "自动选择：frida/objection/adb/root绕过/ssl绕过关键词+Android目标。",
        },
    },

    # ════════════════════════════════
    # 4. iOS — 정적 분석
    # ════════════════════════════════
    {
        "name": "mobile-ios-static",
        "module": "mobile",
        "tags": ["ios", "ipa", "static-analysis", "class-dump", "otool", "plist",
                 "ats", "mobsf", "owasp-mastg"],
        "desc": {
            "ko": (
                "iOS IPA 정적 분석 (OWASP MASTG MSTG-ARCH / CODE 기준).\n"
                "도구 체인: unzip → plutil → otool → strings → class-dump → MobSF\n"
                "분석 항목:\n"
                "  - Info.plist: ATS, URL Scheme, 버전, 권한 설명\n"
                "  - 바이너리: PIE, Stack Canary, ARC, Objective-C 클래스\n"
                "  - Framework: 서드파티 SDK 탐지 (Firebase/Sentry/Amplitude)\n"
                "  - Bundle: hardcoded secrets, 네트워크 엔드포인트\n"
                "  - 코드 서명: 인증서 발급자, entitlement"
            ),
            "en": (
                "iOS IPA static analysis (OWASP MASTG MSTG-ARCH/CODE).\n"
                "Tool chain: unzip → plutil → otool → strings → class-dump → MobSF\n"
                "Analysis scope:\n"
                "  - Info.plist: ATS, URL Schemes, version, privacy permissions\n"
                "  - Binary: PIE, Stack Canary, ARC, Objective-C class structure\n"
                "  - Frameworks: 3rd-party SDK detection (Firebase/Sentry/Amplitude)\n"
                "  - Bundle: hardcoded secrets, network endpoints\n"
                "  - Code signing: certificate issuer, entitlements"
            ),
            "zh": (
                "iOS IPA静态分析（OWASP MASTG MSTG-ARCH/CODE）。\n"
                "工具链：unzip→plutil→otool→strings→class-dump→MobSF\n"
                "分析范围：\n"
                "  - Info.plist：ATS/URL Scheme/版本/权限描述\n"
                "  - 二进制：PIE/Stack Canary/ARC/ObjC类结构\n"
                "  - Framework：第三方SDK检测（Firebase/Sentry/Amplitude）\n"
                "  - Bundle：硬编码密钥/网络端点\n"
                "  - 代码签名：证书颁发者/entitlement"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.IOSAnalyzer"],
        "commands": [
            "# IPA 추출\nunzip target.ipa -d ./ipa_extracted",
            "# Info.plist 파싱\nplutil -convert json -o - ./ipa_extracted/Payload/*.app/Info.plist | python3 -m json.tool",
            "# Objective-C 클래스 덤프\nclass-dump -H ./ipa_extracted/Payload/*.app/<AppName> -o ./headers/",
            "# 링크된 라이브러리\notool -L ./ipa_extracted/Payload/*.app/<AppName>",
            "# 바이너리 보안 플래그\notool -hv ./ipa_extracted/Payload/*.app/<AppName> | grep PIE",
            "# 하드코딩 시크릿\nstrings ./ipa_extracted/Payload/*.app/<AppName> | grep -iE 'key|token|secret|password'",
            "# bingo 자동 분석\npython3 -c \"from bingo.tools.mobile_recon import IOSAnalyzer; r=IOSAnalyzer('target.ipa').analyze(); print(r.summary())\"",
            "# MobSF\ncurl -F 'file=@target.ipa' http://localhost:8000/api/v1/upload",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: .ipa 파일 경로 + 정적분석/plist/바이너리 분석 의도.",
            "en": "Auto-select: .ipa file path + static analysis / plist / binary review intent.",
            "zh": "自动选择：.ipa文件路径+静态分析/plist/二进制审计意图。",
        },
    },

    # ════════════════════════════════
    # 5. iOS — 동적 분석 + Frida
    # ════════════════════════════════
    {
        "name": "mobile-ios-dynamic",
        "module": "mobile",
        "tags": ["ios", "frida", "objection", "jailbreak", "keychain", "ssl-pinning",
                 "dynamic-analysis", "runtime-analysis"],
        "desc": {
            "ko": (
                "iOS 동적 분석 — Frida + objection 워크플로우 (탈옥 기기 기준).\n"
                "환경: Jailbreak(Checkra1n/Unc0ver/Dopamine) + frida-server 설치\n"
                "주요 작업:\n"
                "  - objection: SSL 피닝 비활성화, 탈옥 탐지 비활성화\n"
                "  - Keychain 덤프: 저장된 인증서/토큰/비밀번호\n"
                "  - NSUserDefaults / 파일 시스템 탐색\n"
                "  - 클래스 열거 및 메서드 훅 (ObjC + Swift)\n"
                "  - 네트워크 트래픽 인터셉트 (Burp + mitmproxy)\n"
                "  - 메모리 덤프: 실행 중 민감 데이터 추출"
            ),
            "en": (
                "iOS dynamic analysis — Frida + objection workflow (jailbroken device).\n"
                "Environment: Jailbreak (Checkra1n/Unc0ver/Dopamine) + frida-server installed\n"
                "Key operations:\n"
                "  - objection: disable SSL pinning, disable jailbreak detection\n"
                "  - Keychain dump: stored certificates/tokens/passwords\n"
                "  - NSUserDefaults / filesystem exploration\n"
                "  - Class enumeration and method hooking (ObjC + Swift)\n"
                "  - Network traffic interception (Burp + mitmproxy)\n"
                "  - Memory dump: extract sensitive data from live process"
            ),
            "zh": (
                "iOS动态分析——Frida+objection工作流（越狱设备）。\n"
                "环境：越狱(Checkra1n/Unc0ver/Dopamine)+安装frida-server\n"
                "主要操作：\n"
                "  - objection：禁用SSL Pinning/越狱检测\n"
                "  - Keychain转储：存储的证书/令牌/密码\n"
                "  - NSUserDefaults/文件系统浏览\n"
                "  - 类枚举与方法Hook（ObjC+Swift）\n"
                "  - 网络流量拦截（Burp+mitmproxy）\n"
                "  - 内存转储：从运行进程提取敏感数据"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.IOSAnalyzer"],
        "commands": [
            "# frida-server 실행 (탈옥 기기)\nssh root@<device_ip> '/usr/sbin/frida-server &'",
            "# SSL 피닝 우회\nobjection -g <bundle.id> explore --startup-command 'ios sslpinning disable'",
            "# 탈옥 탐지 우회\nobjection -g <bundle.id> explore --startup-command 'ios jailbreak disable'",
            "# Keychain 덤프\nobjection -g <bundle.id> explore\n# → ios keychain dump",
            "# 클래스 열거\nobjection -g <bundle.id> explore\n# → ios hooking list classes | grep -i auth",
            "# Swift 메서드 훅\nfrida -U -e \"var resolver = new ApiResolver('objc'); resolver.enumerateMatches('*[* *password*]', {onMatch: function(m){console.log(m.name);}});\" <bundle.id>",
            "# 메모리 덤프\nobjection -g <bundle.id> explore\n# → memory dump all mem.bin",
            "# NSUserDefaults\nobjection -g <bundle.id> explore\n# → ios nsuserdefaults get",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'frida', 'objection', '탈옥', 'keychain', 'ios ssl' 키워드 + iOS 타겟.",
            "en": "Auto-select: frida/objection/jailbreak/keychain/ios-ssl keywords + iOS target.",
            "zh": "自동选择：frida/objection/越狱/keychain/ios-ssl关键词+iOS目标。",
        },
    },

    # ════════════════════════════════
    # 6. 시크릿 & 하드코딩 스캔
    # ════════════════════════════════
    {
        "name": "mobile-secret-scan",
        "module": "mobile",
        "tags": ["hardcoded", "secret-scan", "api-key", "firebase", "aws",
                 "google-api", "jwt-token", "android", "ios"],
        "desc": {
            "ko": (
                "모바일 앱 하드코딩 시크릿 스캔 (Android + iOS 공통).\n"
                "탐지 패턴 (16종):\n"
                "  - AWS Access/Secret Key, Google API Key, Firebase URL/Key\n"
                "  - Stripe Live/PK Key, GitHub Token, Slack Token\n"
                "  - Private Key (PEM), JWT Token\n"
                "  - 카카오/네이버 API 키 (한국 서비스 특화)\n"
                "  - 하드코딩된 password/token/secret 변수\n"
                "도구: semgrep, trufflehog, gitleaks, bingo 내장 스캐너"
            ),
            "en": (
                "Mobile app hardcoded secret scanner (Android + iOS).\n"
                "Detection patterns (16 types):\n"
                "  - AWS Access/Secret Key, Google API Key, Firebase URL/Key\n"
                "  - Stripe Live/PK Key, GitHub Token, Slack Token\n"
                "  - Private Key (PEM), JWT Token\n"
                "  - Kakao/Naver API keys (Korean service specific)\n"
                "  - Hardcoded password/token/secret variables\n"
                "Tools: semgrep, trufflehog, gitleaks, bingo built-in scanner"
            ),
            "zh": (
                "移动App硬编码密钥扫描（Android+iOS通用）。\n"
                "检测模式（16种）：\n"
                "  - AWS Access/Secret Key、Google API Key、Firebase URL/Key\n"
                "  - Stripe Live/PK Key、GitHub Token、Slack Token\n"
                "  - PEM私钥、JWT Token\n"
                "  - Kakao/Naver API Key（韩国服务专项）\n"
                "  - 硬编码password/token/secret变量\n"
                "工具：semgrep/trufflehog/gitleaks/bingo内置扫描器"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.SECRET_PATTERNS"],
        "commands": [
            "# APK 내 시크릿 (apktool 후)\ngrep -rE 'AKIA[0-9A-Z]{16}' ./decompiled/",
            "grep -rE 'AIza[0-9A-Za-z\\-_]{35}' ./decompiled/",
            "grep -rE '(password|token|secret|api_key)\\s*[:=]\\s*[\\'\"]{1}[^\\'\"]{6,}[\\'\"]{1}' ./decompiled/",
            "# trufflehog\ntrufflehog filesystem ./decompiled/ --json",
            "# gitleaks (소스 git 있을 경우)\ngitleaks detect --source ./decompiled/ --report-format json",
            "# semgrep\nsemgrep --config 'p/secrets' ./decompiled/",
            "# bingo 내장\npython3 -c \"from bingo.tools.mobile_recon import AndroidAnalyzer; r=AndroidAnalyzer('target.apk').analyze(); [print(s) for s in r.hardcoded_secrets]\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'hardcoded', 'api key 유출', '시크릿 스캔', 'firebase key', 'aws key' 키워드.",
            "en": "Auto-select: hardcoded/api-key-leak/secret-scan/firebase-key/aws-key keywords.",
            "zh": "自动选择：hardcoded/api密钥泄露/密钥扫描/firebase密钥/aws密钥关键词。",
        },
    },

    # ════════════════════════════════
    # 7. SSL 피닝 탐지 + 우회
    # ════════════════════════════════
    {
        "name": "mobile-ssl-bypass",
        "module": "mobile",
        "tags": ["ssl-pinning", "ssl-bypass", "certificate-pin", "mitm",
                 "burp-mobile", "frida", "objection", "android", "ios"],
        "desc": {
            "ko": (
                "SSL 피닝 탐지 및 우회 (Android + iOS).\n"
                "탐지: CertificatePinner, TrustKit, AFSSLPinningMode, SecTrustEvaluate\n"
                "우회 방법:\n"
                "  Android:\n"
                "    - objection: android sslpinning disable\n"
                "    - Frida universal bypass script (pcipolloni)\n"
                "    - apktool + network_security_config.xml 수정 후 재서명\n"
                "    - OkHttp/TrustManager 클래스 훅\n"
                "  iOS:\n"
                "    - objection: ios sslpinning disable\n"
                "    - SSL Kill Switch 2 (Cydia tweak)\n"
                "    - Frida SecTrustEvaluate 훅\n"
                "Burp 설정: Proxy → Options → Import CA 인증서"
            ),
            "en": (
                "SSL pinning detection and bypass (Android + iOS).\n"
                "Detection: CertificatePinner, TrustKit, AFSSLPinningMode, SecTrustEvaluate\n"
                "Bypass methods:\n"
                "  Android:\n"
                "    - objection: android sslpinning disable\n"
                "    - Frida universal bypass script (pcipolloni)\n"
                "    - apktool + patch network_security_config.xml + re-sign\n"
                "    - OkHttp/TrustManager class hooking\n"
                "  iOS:\n"
                "    - objection: ios sslpinning disable\n"
                "    - SSL Kill Switch 2 (Cydia tweak)\n"
                "    - Frida SecTrustEvaluate hook\n"
                "Burp setup: Proxy → Options → Import CA certificate"
            ),
            "zh": (
                "SSL Pinning检测与绕过（Android+iOS）。\n"
                "检测：CertificatePinner/TrustKit/AFSSLPinningMode/SecTrustEvaluate\n"
                "绕过方式：\n"
                "  Android：\n"
                "    - objection：android sslpinning disable\n"
                "    - Frida通用绕过脚本（pcipolloni）\n"
                "    - apktool+修改network_security_config.xml+重签名\n"
                "    - Hook OkHttp/TrustManager类\n"
                "  iOS：\n"
                "    - objection：ios sslpinning disable\n"
                "    - SSL Kill Switch 2（Cydia插件）\n"
                "    - Frida Hook SecTrustEvaluate\n"
                "Burp设置：Proxy→Options→导入CA证书"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.SSL_PINNING_PATTERNS"],
        "commands": [
            "# Android SSL 피닝 우회 (objection)\nobjection -g <package> explore --startup-command 'android sslpinning disable'",
            "# Android SSL 피닝 우회 (Frida)\nfrida -U -l pinning-bypass.js -f <package> --no-pause",
            "# Android NSC 패치\napktool d target.apk -o decompiled\n# res/xml/network_security_config.xml 수정\napktool b decompiled -o patched.apk\nzipalign -v 4 patched.apk aligned.apk\napksigner sign --ks debug.keystore aligned.apk",
            "# iOS SSL 피닝 우회 (objection)\nobjection -g <bundle.id> explore --startup-command 'ios sslpinning disable'",
            "# iOS SSL Kill Switch (SSH)\nssh root@<device> 'apt install com.nablac0d3.sslkillswitch2'",
            "# Burp CA 인증서 설치 (Android)\nadb push cacert.der /sdcard/\nadb shell settings put global http_proxy <burp_ip>:8080",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'ssl bypass', 'ssl 우회', 'certificate pinning', 'burp 모바일', 'mitm 앱' 키워드.",
            "en": "Auto-select: ssl-bypass/certificate-pinning/burp-mobile/mitm-app keywords.",
            "zh": "自动选择：ssl绕过/证书Pinning/burp移动/mitm App关键词。",
        },
    },

    # ════════════════════════════════
    # 8. 딥링크 & Intent 취약점
    # ════════════════════════════════
    {
        "name": "mobile-deep-link",
        "module": "mobile",
        "tags": ["deep-link", "intent", "url-scheme", "exported", "activity",
                 "android", "ios", "universal-link", "app-link"],
        "desc": {
            "ko": (
                "딥링크 / Intent 취약점 분석 (Android App Links + iOS Universal Links).\n"
                "공격 벡터:\n"
                "  Android Intent:\n"
                "    - exported Activity/Service/Receiver 직접 호출\n"
                "    - Intent Redirection: 공격자가 임의 Intent 전달\n"
                "    - Pending Intent 하이재킹\n"
                "    - Content Provider: 미인증 데이터 접근\n"
                "  iOS URL Scheme:\n"
                "    - 커스텀 URL 스킴 하이재킹 (복수 앱 등록)\n"
                "    - Universal Link MITM\n"
                "    - 파라미터 인젝션 (XSS via WebView)"
            ),
            "en": (
                "Deep link / Intent vulnerability analysis (Android App Links + iOS Universal Links).\n"
                "Attack vectors:\n"
                "  Android Intent:\n"
                "    - Direct call to exported Activity/Service/Receiver\n"
                "    - Intent Redirection: attacker delivers arbitrary Intent\n"
                "    - Pending Intent hijacking\n"
                "    - Content Provider: unauthenticated data access\n"
                "  iOS URL Scheme:\n"
                "    - Custom URL scheme hijacking (multi-app registration)\n"
                "    - Universal Link MITM\n"
                "    - Parameter injection (XSS via WebView)"
            ),
            "zh": (
                "深度链接/Intent漏洞分析（Android App Links+iOS Universal Links）。\n"
                "攻击向量：\n"
                "  Android Intent：\n"
                "    - 直接调用导出的Activity/Service/Receiver\n"
                "    - Intent重定向：攻击者传递任意Intent\n"
                "    - Pending Intent劫持\n"
                "    - Content Provider：未授权数据访问\n"
                "  iOS URL Scheme：\n"
                "    - 自定义URL Scheme劫持（多App注册）\n"
                "    - Universal Link MITM\n"
                "    - 参数注入（通过WebView的XSS）"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.mobile_phase0"],
        "commands": [
            "# exported Activity 실행\nadb shell am start -n <package>/<activity> --es param1 val1",
            "# exported Service\nadb shell am startservice -n <package>/<service>",
            "# Broadcast Receiver\nadb shell am broadcast -a <action>",
            "# Content Provider\nadb shell content query --uri content://<authority>/users",
            "# iOS 딥링크 트리거 (탈옥 기기 SSH)\nopen '<scheme>://target/action?param=value'",
            "# iOS Safari 딥링크 테스트\n# → Navigate to: <scheme>://admin",
            "# Intent Redirection PoC\nadb shell am start -n <package>/VulnActivity --es redirect_url 'http://evil.com'",
        ],
        "payloads": [
            "# WebView XSS via deep link\nyourapp://page?url=javascript:alert(document.cookie)",
            "# Content Provider 미인증 접근\nadb shell content query --uri content://com.target.provider/accounts",
            "# Pending Intent 하이재킹\nadb shell am start -n <package>/PendingIntentActivity --ea extras '...'",
        ],
        "notes": {
            "ko": "AI 자동선택: 'deep link', 'intent', 'exported', 'url scheme', 'content provider' 키워드 + 모바일.",
            "en": "Auto-select: deep-link/intent/exported/url-scheme/content-provider keywords + mobile target.",
            "zh": "自动选择：深度链接/intent/exported/url-scheme/content-provider关键词+移动目标。",
        },
    },

    # ════════════════════════════════
    # 9. API 엔드포인트 추출 & 재콘
    # ════════════════════════════════
    {
        "name": "mobile-api-recon",
        "module": "mobile",
        "tags": ["network-recon", "endpoint", "api-discovery", "burp", "mitmproxy",
                 "charles", "android", "ios"],
        "desc": {
            "ko": (
                "모바일 앱 API 엔드포인트 추출 및 정찰.\n"
                "정적 추출:\n"
                "  - strings/grep: URL, Base URL, endpoint 상수\n"
                "  - jadx/class-dump: 네트워크 클래스, Retrofit interface\n"
                "  - apktool smali: 하드코딩된 host/path\n"
                "동적 캡처:\n"
                "  - Burp Suite: 프록시를 통한 실시간 캡처\n"
                "  - mitmproxy: CLI 자동화 분석\n"
                "  - Frida: HTTP 라이브러리 훅으로 모든 요청 캡처\n"
                "분석: 미인증 API, IDOR, 민감 파라미터, GraphQL 스키마"
            ),
            "en": (
                "Mobile app API endpoint extraction and reconnaissance.\n"
                "Static extraction:\n"
                "  - strings/grep: URLs, Base URLs, endpoint constants\n"
                "  - jadx/class-dump: network classes, Retrofit interfaces\n"
                "  - apktool smali: hardcoded host/path strings\n"
                "Dynamic capture:\n"
                "  - Burp Suite: real-time intercept via proxy\n"
                "  - mitmproxy: CLI-based automated analysis\n"
                "  - Frida: hook HTTP libraries to capture all requests\n"
                "Analysis: unauthenticated APIs, IDOR, sensitive params, GraphQL schema"
            ),
            "zh": (
                "移动App API端点提取与侦察。\n"
                "静态提取：\n"
                "  - strings/grep：URL/Base URL/端点常量\n"
                "  - jadx/class-dump：网络类/Retrofit接口\n"
                "  - apktool smali：硬编码host/path字符串\n"
                "动态捕获：\n"
                "  - Burp Suite：通过代理实时拦截\n"
                "  - mitmproxy：CLI自动化分析\n"
                "  - Frida：Hook HTTP库捕获所有请求\n"
                "分析：未授权API/IDOR/敏感参数/GraphQL模式"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.ENDPOINT_PATTERNS"],
        "commands": [
            "# 정적 URL 추출 (apktool 후)\ngrep -rEoh 'https?://[a-zA-Z0-9./_-]+' ./decompiled/ | sort -u",
            "# Frida — OkHttp 요청 캡처\nfrida -U -e \"\nJava.perform(function(){\n  var OkHttpClient = Java.use('okhttp3.OkHttpClient');\n  OkHttpClient.newCall.implementation = function(req){\n    console.log('[REQ]', req.url().toString());\n    return this.newCall(req);\n  };\n});\n\" <package>",
            "# mitmproxy 자동 분석\nmitmproxy --mode transparent --showhost -w capture.mitm",
            "# Burp — 모바일 프록시 설정\n# 기기 WiFi → 수동 프록시: <PC IP>:8080\n# Burp CA 인증서 설치 후 HTTPS 인터셉트",
            "# bingo — 정적 엔드포인트 추출\npython3 -c \"from bingo.tools.mobile_recon import AndroidAnalyzer; r=AndroidAnalyzer('target.apk').analyze(); [print(u) for u in r.network_endpoints[:30]]\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'api 추출', 'endpoint', '네트워크 트래픽', 'burp 모바일', 'mitmproxy' 키워드.",
            "en": "Auto-select: api-extract/endpoint/network-traffic/burp-mobile/mitmproxy keywords.",
            "zh": "自动选择：api提取/endpoint/网络流量/burp移动/mitmproxy关键词。",
        },
    },

    # ════════════════════════════════
    # 10. Frida 환경 설정 + 스크립트
    # ════════════════════════════════
    {
        "name": "mobile-frida-setup",
        "module": "mobile",
        "tags": ["frida", "frida-setup", "objection", "android", "ios",
                 "hook", "instrument", "runtime"],
        "desc": {
            "ko": (
                "Frida / objection 환경 설정 및 핵심 스크립트 모음.\n"
                "설치:\n"
                "  pip install frida-tools objection\n"
                "  Android: rooted device + frida-server push\n"
                "  iOS: jailbroken device + Cydia frida package\n"
                "핵심 스크립트:\n"
                "  - SSL 피닝 우회 (Android + iOS 통합)\n"
                "  - 루트/탈옥 탐지 우회\n"
                "  - 메서드 인자/리턴값 로깅\n"
                "  - 암호화 함수 훅 (AES/RSA 키 추출)\n"
                "  - SharedPreferences / Keychain 실시간 모니터\n"
                "  - 네트워크 요청 전체 로깅"
            ),
            "en": (
                "Frida / objection environment setup and essential scripts.\n"
                "Install:\n"
                "  pip install frida-tools objection\n"
                "  Android: rooted device + frida-server push via ADB\n"
                "  iOS: jailbroken device + Cydia frida package\n"
                "Essential scripts:\n"
                "  - SSL pinning bypass (Android + iOS unified)\n"
                "  - Root/jailbreak detection bypass\n"
                "  - Method argument/return value logging\n"
                "  - Crypto function hooking (AES/RSA key extraction)\n"
                "  - SharedPreferences / Keychain live monitor\n"
                "  - Full network request logging"
            ),
            "zh": (
                "Frida/objection环境配置与核心脚本集合。\n"
                "安装：\n"
                "  pip install frida-tools objection\n"
                "  Android：已root设备+通过ADB推送frida-server\n"
                "  iOS：已越狱设备+Cydia安装frida包\n"
                "核心脚本：\n"
                "  - SSL Pinning绕过（Android+iOS统一）\n"
                "  - Root/越狱检测绕过\n"
                "  - 方法参数/返回值日志记录\n"
                "  - 加密函数Hook（AES/RSA密钥提取）\n"
                "  - SharedPreferences/Keychain实时监控\n"
                "  - 全量网络请求日志"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.quick_setup_guide"],
        "commands": [
            "# Frida 설치\npip install frida-tools objection",
            "# Android frida-server 설치\nadb push frida-server /data/local/tmp/\nadb shell chmod +x /data/local/tmp/frida-server\nadb shell /data/local/tmp/frida-server &",
            "# 연결 확인\nfrida-ps -Ua",
            "# 전체 설정 가이드\npython3 -c \"from bingo.tools.mobile_recon import quick_setup_guide; print(quick_setup_guide())\"",
        ],
        "payloads": [
            # SSL + Root 통합 우회 스크립트 (Frida JS)
            """// ssl_root_bypass.js — 통합 우회 스크립트
Java.perform(function() {
  // 1. SSL TrustManager 우회
  var TrustManager = [{
    checkClientTrusted: function(chain, authType) {},
    checkServerTrusted: function(chain, authType) {},
    getAcceptedIssuers: function() { return []; }
  }];
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TrustManagerClass = Java.use('javax.net.ssl.X509TrustManager');
  var sc = SSLContext.getInstance('TLS');
  sc.init(null, Java.array('javax.net.ssl.TrustManager', [
    Java.registerClass({name:'BingoTM', implements:[TrustManagerClass], methods:TrustManager[0]}).implementation
  ]), null);
  SSLContext.getDefault.implementation = function() { return sc; };

  // 2. OkHttp3 CertificatePinner 우회
  try {
    var CertPinner = Java.use('okhttp3.CertificatePinner');
    CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function(h, c) {
      console.log('[Frida] CertificatePinner.check bypassed for: ' + h);
    };
  } catch(e) {}

  // 3. Root Detection 우회
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { return false; };
  } catch(e) {}

  console.log('[Frida] SSL + Root bypass applied!');
});""",
        ],
        "notes": {
            "ko": "AI 자동선택: 'frida 설정', 'objection 설치', '훅 스크립트', 'frida server' 키워드.",
            "en": "Auto-select: frida-setup/objection-install/hook-script/frida-server keywords.",
            "zh": "自动选择：frida配置/objection安装/Hook脚本/frida-server关键词。",
        },
    },

    # ════════════════════════════════
    # 11. 앱스토어 OSINT
    # ════════════════════════════════
    {
        "name": "mobile-store-osint",
        "module": "mobile",
        "tags": ["store-osint", "play-store", "app-store", "package-name",
                 "apk-download", "ipa-download", "recon"],
        "desc": {
            "ko": (
                "앱스토어 기반 OSINT 및 APK/IPA 확보 방법.\n"
                "정보 수집:\n"
                "  - 앱 메타데이터: 버전 이력, 업데이트 날짜, 권한 목록\n"
                "  - 개발자 정보: 회사명, 이메일, 연관 앱\n"
                "  - 리뷰 분석: 보안 관련 불만 사항\n"
                "APK 확보 방법 (Play Store):\n"
                "  - gplaycli, apkeep (CLI)\n"
                "  - APKPure, APKMirror, APKCombo (웹)\n"
                "IPA 확보 방법 (App Store):\n"
                "  - ipatool (Xcodes)\n"
                "  - 탈옥 기기에서 clutch/frida-ios-dump\n"
                "도메인 정찰: 패키지명 기반 subfinder/amass"
            ),
            "en": (
                "App store OSINT and APK/IPA acquisition methods.\n"
                "Information gathering:\n"
                "  - App metadata: version history, update dates, permissions\n"
                "  - Developer info: company name, email, related apps\n"
                "  - Review analysis: security-related complaints\n"
                "APK acquisition (Play Store):\n"
                "  - gplaycli, apkeep (CLI tools)\n"
                "  - APKPure, APKMirror, APKCombo (web)\n"
                "IPA acquisition (App Store):\n"
                "  - ipatool (Xcodes)\n"
                "  - clutch/frida-ios-dump on jailbroken device\n"
                "Domain recon: package-name-based subfinder/amass"
            ),
            "zh": (
                "应用商店OSINT及APK/IPA获取方法。\n"
                "信息收集：\n"
                "  - App元数据：版本历史/更新日期/权限列表\n"
                "  - 开发者信息：公司名/邮件/关联App\n"
                "  - 评论分析：安全相关投诉\n"
                "APK获取（Play Store）：\n"
                "  - gplaycli/apkeep（命令行工具）\n"
                "  - APKPure/APKMirror/APKCombo（网页）\n"
                "IPA获取（App Store）：\n"
                "  - ipatool（Xcodes）\n"
                "  - 越狱设备上的clutch/frida-ios-dump\n"
                "域名侦察：基于包名的subfinder/amass"
            ),
        },
        "tools": [
            "bingo.tools.mobile_recon.recon_by_store_url",
            "bingo.tools.mobile_recon.recon_by_package",
        ],
        "commands": [
            "# Play Store 메타데이터\ncurl -s 'https://play.google.com/store/apps/details?id=<package>' | grep -oP '(?<=content=\")[^\"]+(?=\".*?itemprop)'",
            "# App Store 메타데이터\ncurl -s 'https://itunes.apple.com/lookup?id=<app_id>' | python3 -m json.tool",
            "# APK 다운로드 (gplaycli)\npip install gplaycli\ngplaycli -d <package> -f . -v",
            "# APK 다운로드 (apkeep)\ncargo install apkeep\napkeep -a <package> -d google-play .",
            "# IPA 다운로드 (ipatool)\nbrew install majd/repo/ipatool\nipatool auth login --email <email> --password <pw>\nipatool download -b <bundle.id>",
            "# 도메인 정찰\nsubfinder -d <reverse-package-domain> -o domains.txt",
            "# bingo OSINT\npython3 -c \"from bingo.tools.mobile_recon import recon_by_store_url; import json; print(json.dumps(recon_by_store_url('https://play.google.com/store/apps/details?id=com.target'), indent=2))\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: 'apk 다운로드', 'ipa 확보', '앱스토어 OSINT', '패키지명 조사' 키워드.",
            "en": "Auto-select: apk-download/ipa-acquire/app-store-osint/package-name-recon keywords.",
            "zh": "自动选择：APK下载/IPA获取/应用商店OSINT/包名调查关键词。",
        },
    },

    # ════════════════════════════════
    # 12. 도구 설치 & 환경 설정
    # ════════════════════════════════
    {
        "name": "mobile-env-setup",
        "module": "mobile",
        "tags": ["mobile", "setup", "install", "tools", "android", "ios",
                 "apktool", "jadx", "frida", "objection", "mobsf"],
        "desc": {
            "ko": (
                "모바일 침투테스트 환경 구성 완전 가이드 (Cursor 동급).\n"
                "Android 도구 스택:\n"
                "  정적: apktool, jadx, aapt, androguard, MobSF\n"
                "  동적: ADB, Frida, objection, Drozer, RootBeer\n"
                "  네트워크: Burp Suite, mitmproxy, Wireshark\n"
                "  기타: gplaycli, apkeep, dex2jar, apksigner\n"
                "iOS 도구 스택:\n"
                "  정적: otool, class-dump, strings, Hopper, MobSF\n"
                "  동적: Frida, objection, SSL Kill Switch 2, Clutch\n"
                "  네트워크: Burp Suite, Charles Proxy, mitmproxy\n"
                "  기타: ipatool, libimobiledevice, ifuse\n"
                "에뮬레이터: Genymotion (Android), Corellium (iOS)"
            ),
            "en": (
                "Complete mobile pentest environment setup guide (Cursor-grade).\n"
                "Android tool stack:\n"
                "  Static: apktool, jadx, aapt, androguard, MobSF\n"
                "  Dynamic: ADB, Frida, objection, Drozer, RootBeer\n"
                "  Network: Burp Suite, mitmproxy, Wireshark\n"
                "  Other: gplaycli, apkeep, dex2jar, apksigner\n"
                "iOS tool stack:\n"
                "  Static: otool, class-dump, strings, Hopper, MobSF\n"
                "  Dynamic: Frida, objection, SSL Kill Switch 2, Clutch\n"
                "  Network: Burp Suite, Charles Proxy, mitmproxy\n"
                "  Other: ipatool, libimobiledevice, ifuse\n"
                "Emulators: Genymotion (Android), Corellium (iOS)"
            ),
            "zh": (
                "移动渗透测试环境完整配置指南（Cursor同级）。\n"
                "Android工具栈：\n"
                "  静态：apktool/jadx/aapt/androguard/MobSF\n"
                "  动态：ADB/Frida/objection/Drozer/RootBeer\n"
                "  网络：Burp Suite/mitmproxy/Wireshark\n"
                "  其他：gplaycli/apkeep/dex2jar/apksigner\n"
                "iOS工具栈：\n"
                "  静态：otool/class-dump/strings/Hopper/MobSF\n"
                "  动态：Frida/objection/SSL Kill Switch 2/Clutch\n"
                "  网络：Burp Suite/Charles Proxy/mitmproxy\n"
                "  其他：ipatool/libimobiledevice/ifuse\n"
                "模拟器：Genymotion（Android）/Corellium（iOS）"
            ),
        },
        "tools": ["bingo.tools.mobile_recon.quick_setup_guide"],
        "commands": [
            "# macOS 전체 설치\nbrew install apktool aapt android-platform-tools jadx\nbrew install libimobiledevice ideviceinstaller ifuse\npip install frida-tools objection gplaycli",
            "# Ubuntu 전체 설치\napt install apktool aapt adb default-jdk\npip install frida-tools objection\nsnap install jadx",
            "# MobSF (Docker)\ndocker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf",
            "# Genymotion (Android 에뮬레이터)\n# https://www.genymotion.com/product-desktop/",
            "# 설치 가이드 출력\npython3 -c \"from bingo.tools.mobile_recon import quick_setup_guide; print(quick_setup_guide())\"",
        ],
        "payloads": [],
        "notes": {
            "ko": "AI 자동선택: '도구 설치', '환경 설정', '모바일 세팅', 'frida 설치', 'apktool 설치' 키워드.",
            "en": "Auto-select: tool-install/env-setup/mobile-setup/frida-install/apktool-install keywords.",
            "zh": "自动选择：工具安装/环境配置/移动设置/frida安装/apktool安装关键词。",
        },
    },
]
