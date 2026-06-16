"""
skills_data10.py — APK Toolkit Skills (apkd + apkscan + apk.sh)
bingo v2.2.9

Integrates:
  apkd    : https://github.com/kiber-io/apkd          — APK downloader (ApkPure/ApkCombo/F-Droid/RuStore)
  apkscan : https://github.com/LucasFaudman/apkscan    — Multi-decompiler secret+endpoint scanner
  apk.sh  : https://github.com/ax/apk.sh               — APK manipulation & Frida gadget injection
"""
from __future__ import annotations

SKILLS_DB_10: list[dict] = [
    # ── 1. apkd: APK Download ────────────────────────────────────────────────
    {
        "name": "apk-download",
        "module": "mobile",
        "tags": [
            # EN
            "apk download", "download apk", "apkd", "apkpure", "apkcombo",
            "fdroid", "f-droid", "appgallery", "rustore", "nashstore",
            "apk store", "app download", "android download", "no google play",
            "apk without google play", "apk by package name", "list apk versions",
            "batch download apk", "developer apk", "apk version list",
            "apk downloader", "android app downloader",
            # KO
            "apk 다운로드", "앱 다운로드", "구글플레이 없이 apk",
            "패키지 다운로드", "안드로이드 apk 받기",
            # ZH
            "apk下载", "安卓APK下载", "无谷歌商店下载", "应用下载",
        ],
        "desc": {
            "ko": (
                "apkd를 사용하여 ApkPure/ApkCombo/F-Droid/AppGallery/RuStore 등 "
                "여러 소스에서 APK 파일을 다운로드합니다. 구글 플레이 계정 없이 "
                "패키지명만으로 특정 버전 지정 다운로드, 배치 다운로드, "
                "개발자 전체 앱 다운로드가 가능합니다."
            ),
            "en": (
                "Download APK files from multiple sources (ApkPure, ApkCombo, F-Droid, "
                "AppGallery, RuStore, NashStore) using apkd — no Google Play account needed. "
                "Supports listing versions, batch download, and developer ID download."
            ),
            "zh": (
                "使用apkd从ApkPure/ApkCombo/F-Droid/AppGallery/RuStore等多个来源下载APK，"
                "无需Google Play账户。支持版本列表、批量下载、开发者所有应用下载。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.download_apk",
            "bingo.tools.apk_toolkit.list_apk_versions",
            "bingo.tools.apk_toolkit.batch_download_apks",
            "bingo.tools.apk_toolkit.get_developer_apks",
        ],
        "commands": [
            "apkd -p com.target.app -d -s apkpure          # download from ApkPure",
            "apkd -p com.target.app -lv                     # list available versions",
            "apkd -p com.target.app -d -s fdroid            # download from F-Droid",
            "apkd -l packages.txt -d                        # batch download from packages.txt",
            "apkd -ld -p com.target.app -s apkpure          # find developer ID",
            "apkd -d -did 'Instagram' -s apkpure            # download all apps from developer",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "apkd는 현재 아카이브(개발 중단) 상태이며 Python 버전 기준입니다. "
                "새 버전은 Go 기반으로 별도 존재합니다. "
                "ApkCombo는 가끔 불안정할 수 있으므로 ApkPure 우선 사용 권장. "
                "설치: pip install git+https://github.com/kiber-io/apkd"
            ),
            "en": (
                "apkd Python version is archived; a new Go-based version exists. "
                "ApkCombo may be unstable — prefer ApkPure or F-Droid. "
                "Install: pip install git+https://github.com/kiber-io/apkd"
            ),
            "zh": (
                "apkd Python版本已归档，新版本基于Go。ApkCombo可能不稳定，建议优先使用ApkPure。"
                "安装: pip install git+https://github.com/kiber-io/apkd"
            ),
        },
    },

    # ── 2. apkscan: Secret + Endpoint Scanner ────────────────────────────────
    {
        "name": "apkscan-secret-endpoint",
        "module": "mobile",
        "tags": [
            # EN
            "apkscan", "apk secret scan", "apk endpoint scan", "apk vulnerability scan",
            "android secret scan", "android secret leak", "android api key",
            "android hardcoded secret", "android leaked credentials", "android token leak",
            "decompile apk secrets", "jadx secret", "apktool secret",
            "multiple decompilers", "smali secret", "dex secret analysis",
            "android backend endpoint", "android backend url", "android api endpoint",
            "find endpoints android", "attack surface mobile", "android xapk scan",
            "ssl pinning location", "root detection location", "android obfuscation",
            "gitleaks apk", "secret patterns android", "cfr decompiler", "procyon decompiler",
            # KO
            "apk 시크릿 스캔", "안드로이드 하드코딩 키", "앱 api키 유출",
            "앱 엔드포인트 찾기", "ssl 피닝 위치",
            # ZH
            "apk密钥扫描", "安卓硬编码密钥", "安卓接口发现", "APK端点扫描",
        ],
        "desc": {
            "ko": (
                "apkscan을 사용하여 APK를 복수 디컴파일러(JADX/APKTool/CFR/Procyon)로 "
                "디컴파일하고 API 키, 토큰, 패스워드 등 시크릿과 백엔드 엔드포인트를 "
                "스캔합니다. .apk, .xapk, .dex, .jar, .smali, .aar, .aab 지원. "
                "Gitleaks TOML, YAML, JSON 커스텀 룰셋 지원."
            ),
            "en": (
                "Scan APK for secrets (API keys, tokens, passwords) and backend endpoints "
                "using apkscan with multiple decompilers (JADX, APKTool, CFR, Procyon, "
                "Krakatau, Fernflower). Also locates SSL pinning and root detection code. "
                "Supports .apk, .xapk, .dex, .jar, .smali, .aar, .arsc, .aab files. "
                "Custom rules: Gitleaks TOML, secret-patterns-db YAML, or JSON format."
            ),
            "zh": (
                "使用apkscan通过多种反编译器(JADX/APKTool/CFR/Procyon)对APK进行反编译，"
                "扫描API密钥、Token、密码等敏感信息和后端接口。"
                "支持.apk/.xapk/.dex/.jar/.smali/.aar/.aab，可使用Gitleaks/YAML/JSON自定义规则。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.scan_apk_secrets_endpoints",
            "bingo.tools.apk_toolkit.scan_apk_endpoints",
            "bingo.tools.apk_toolkit.scan_apk_cloud_credentials",
        ],
        "commands": [
            "apkscan target.apk                                       # default scan (jadx+default rules)",
            "apkscan target.apk -r all_secret_locators endpoints      # scan all secrets + endpoints",
            "apkscan target.apk -r aws gcp azure -o cloud_creds.json  # cloud credentials only",
            "apkscan target.apk -J -A -o combined.json                # jadx + apktool dual decompile",
            "apkscan -J -A -C -P -K -F target.apk -o all.yaml -f yaml  # all 6 decompilers",
            "apkscan target.apk -r /path/to/custom_rules.json         # custom rules",
            "apkscan target.apk -r gitleaks high-confidence -f json -g locator  # gitleaks rules",
            "apkscan f1.apk f2.apk f3.apk -r default -c              # batch scan + cleanup",
        ],
        "payloads": [
            # Custom rule example (JSON format)
            '{"id":"custom-api-key","name":"Custom API Key","pattern":"API_KEY[\\s=:]+[\\"\\\'](\\w+)[\\"\\'"]","confidence":"high"}',
        ],
        "notes": {
            "ko": (
                "내장 룰셋: all_secret_locators, aws, azure, cloud, endpoints, gcp, "
                "gitleaks, high-confidence, nuclei-regexes 등. "
                "다중 디컴파일러 사용 시 난독화 우회 가능성 높아짐. "
                "설치: pip3 install apkscan (jadx 별도 필요: brew install jadx)"
            ),
            "en": (
                "Built-in rule sets: all_secret_locators, aws, azure, cloud, endpoints, gcp, "
                "gitleaks, high-confidence, nuclei-regexes, secret, curated, etc. "
                "Using multiple decompilers increases chance of bypassing obfuscation. "
                "Install: pip3 install apkscan  +  brew install jadx (required)"
            ),
            "zh": (
                "内置规则集：all_secret_locators/aws/azure/cloud/endpoints/gcp/gitleaks/"
                "high-confidence/nuclei-regexes等。多个反编译器可提高绕过混淆的成功率。"
                "安装: pip3 install apkscan + brew install jadx"
            ),
        },
    },

    # ── 3. apk.sh: Frida Gadget Injection ───────────────────────────────────
    {
        "name": "apk-frida-patch",
        "module": "mobile",
        "tags": [
            # EN
            "apk.sh", "apksh", "frida gadget", "frida patch", "frida injection",
            "apk patch frida", "inject frida", "frida no root", "no root frida",
            "dynamic analysis no root", "frida gadget injection", "frida-gadget.so",
            "android dynamic analysis", "ssl pinning bypass frida", "objection explore",
            "hook android method", "runtime instrumentation apk",
            "frida script android", "patch apk frida", "instrument apk",
            "android frida gadget", "apktool frida", "smali frida",
            # KO
            "프리다 가젯 주입", "apk 패치", "루트 없이 프리다",
            "안드로이드 동적 분석", "ssl 피닝 우회 프리다",
            # ZH
            "frida注入", "apk注入gadget", "无需root动态分析",
            "SSL证书绑定绕过", "安卓动态分析", "frida无需root",
        ],
        "desc": {
            "ko": (
                "apk.sh를 사용하여 APK에 Frida gadget(frida-gadget.so)을 자동 주입합니다. "
                "루트 없이 Frida 기반 동적 분석, SSL 피닝 우회, 메서드 후킹이 가능합니다. "
                "Split APK/App Bundle 지원. arm, arm64, x86, x86_64 아키텍처 선택 가능."
            ),
            "en": (
                "Patch APK to inject Frida gadget (frida-gadget.so) using apk.sh — "
                "enables dynamic instrumentation WITHOUT a rooted device. "
                "After patching: hook methods, bypass SSL pinning, intercept traffic with Burp. "
                "Supports split APKs/app bundles and multiple architectures (arm, arm64, x86, x86_64)."
            ),
            "zh": (
                "使用apk.sh向APK注入Frida gadget(frida-gadget.so)，"
                "无需root即可进行动态插桩、SSL证书绑定绕过、方法Hook。"
                "支持Split APK/App Bundle，支持arm/arm64/x86/x86_64架构。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.patch_apk_frida_gadget",
        ],
        "commands": [
            "./apk.sh patch target.apk --arch arm64              # inject Frida gadget (arm64)",
            "./apk.sh patch target.apk --arch arm64 --net        # + permissive network config",
            'adb install target.gadget.apk                       # install patched APK',
            "frida -U com.target.app                             # connect Frida",
            "frida -U com.target.app -l ssl_bypass.js            # run SSL bypass script",
            "objection -g com.target.app explore                 # Objection shell",
            # Frida gadget config for script mode
            '# gadget-conf.json: {"interaction":{"type":"script","path":"/data/local/tmp/hook.js"}}',
            "./apk.sh patch target.apk --arch arm64 --gadget-conf gadget-conf.json",
            "adb push hook.js /data/local/tmp/hook.js            # push script to device",
        ],
        "payloads": [
            # SSL pinning bypass (Frida)
            "Java.perform(function(){var TrustManager={checkClientTrusted:function(){},checkServerTrusted:function(){},getAcceptedIssuers:function(){return[];},};var TrustManagerImpl=Java.use('com.android.org.conscrypt.TrustManagerImpl');TrustManagerImpl.checkTrustedRecursive.overload('java.util.List','java.util.List','java.util.List','boolean').implementation=function(){return[];};});",
        ],
        "notes": {
            "ko": (
                "필요 도구: apktool, apksigner, aapt, zipalign, adb, unxz. "
                "macOS: brew install apktool android-platform-tools. "
                "Ubuntu: apt install apktool adb apksigner zipalign. "
                "apk.sh 설치: git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo && "
                "cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh && chmod +x ~/tools/apk.sh. "
                "환경변수: export APKSH_PATH=~/tools/apk.sh"
            ),
            "en": (
                "Requirements: apktool, apksigner, aapt, zipalign, adb, unxz. "
                "macOS: brew install apktool android-platform-tools. "
                "Ubuntu: apt install apktool adb apksigner zipalign. "
                "apk.sh install: git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo && "
                "cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh && chmod +x ~/tools/apk.sh. "
                "Set env: export APKSH_PATH=~/tools/apk.sh"
            ),
            "zh": (
                "依赖工具: apktool, apksigner, aapt, zipalign, adb, unxz。"
                "macOS: brew install apktool android-platform-tools。"
                "安装apk.sh: git clone https://github.com/ax/apk.sh ~/tools/apk.sh-repo && "
                "cp ~/tools/apk.sh-repo/apk.sh ~/tools/apk.sh && chmod +x ~/tools/apk.sh。"
                "设置环境变量: export APKSH_PATH=~/tools/apk.sh"
            ),
        },
    },

    # ── 4. apk.sh: Decode / Rebuild / Rename ────────────────────────────────
    {
        "name": "apk-decode-rebuild",
        "module": "mobile",
        "tags": [
            # EN
            "apk decode", "apk decompile smali", "apktool decode", "apk disassemble",
            "apk rebuild", "apk recompile", "apk build", "apk repack",
            "apk rename package", "apk package rename",
            "smali analysis", "apk resources decode", "apk manifest decode",
            "apk reverse engineering", "apktool d", "apktool b",
            "android reverse engineering", "apk modification",
            # KO
            "apk 디코드", "apk 리빌드", "apk 분해", "smali 분석",
            "apk 패키지명 변경",
            # ZH
            "apk反编译smali", "apk重打包", "APK资源解码", "APK改包",
        ],
        "desc": {
            "ko": (
                "apk.sh를 사용하여 APK를 smali + 리소스로 디코드하고, "
                "수정 후 재빌드합니다. 패키지명 변경도 지원합니다. "
                "내부적으로 apktool을 사용하며 Split APK 자동 병합 기능을 제공합니다."
            ),
            "en": (
                "Decode APK to smali + resources using apk.sh (wraps apktool), "
                "then rebuild after modification. Also supports package renaming. "
                "Useful for: patching logic, removing obfuscation markers, "
                "modifying AndroidManifest.xml, and re-signing APKs."
            ),
            "zh": (
                "使用apk.sh(封装apktool)将APK解码为smali+资源，修改后重新打包。"
                "支持APK包名重命名，适用于逻辑修改、AndroidManifest.xml修改和重签名。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.decode_apk",
            "bingo.tools.apk_toolkit.rebuild_apk",
            "bingo.tools.apk_toolkit.rename_apk_package",
        ],
        "commands": [
            "./apk.sh decode target.apk                       # decode APK → target/",
            "./apk.sh decode target.apk -r                    # decode without resources (-r)",
            "./apk.sh decode target.apk -s                    # decode without src smali (-s)",
            "./apk.sh build target/                           # rebuild APK from decoded dir",
            "./apk.sh rename target.apk com.new.package       # rename package",
            "apktool d target.apk -o decoded/                 # direct apktool fallback",
            "apktool b decoded/ -o rebuilt.apk                # rebuild with apktool",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "디코드 후 decoded/ 폴더에서 AndroidManifest.xml, smali/*.smali, "
                "res/values/strings.xml 등 분석 가능. "
                "리빌드 시 apksigner로 서명 필요: "
                "apksigner sign --ks debug.keystore rebuilt.apk"
            ),
            "en": (
                "After decode: inspect AndroidManifest.xml, smali/*.smali, res/values/strings.xml. "
                "After rebuild, sign with apksigner: "
                "apksigner sign --ks debug.keystore rebuilt.apk"
            ),
            "zh": (
                "解码后可分析AndroidManifest.xml、smali/*.smali、res/values/strings.xml。"
                "重打包后需重新签名: apksigner sign --ks debug.keystore rebuilt.apk"
            ),
        },
    },

    # ── 5. apk.sh: Pull from Device ─────────────────────────────────────────
    {
        "name": "apk-pull-device",
        "module": "mobile",
        "tags": [
            # EN
            "pull apk device", "adb pull apk", "extract apk device",
            "apk from phone", "apk from emulator", "apk.sh pull",
            "device apk extraction", "android device apk", "adb extract apk",
            "split apk merge", "app bundle pull", "xapk pull",
            # KO
            "기기에서 apk 추출", "adb apk 추출", "폰에서 apk 가져오기",
            # ZH
            "从设备提取APK", "adb pull APK", "从手机获取APK", "APK提取",
        ],
        "desc": {
            "ko": (
                "apk.sh pull 또는 adb를 사용하여 연결된 Android 기기/에뮬레이터에서 "
                "APK를 추출합니다. Split APK/App Bundle을 자동으로 단일 APK로 병합합니다."
            ),
            "en": (
                "Pull APK from a connected Android device or emulator using apk.sh. "
                "Automatically merges split APKs/app bundles into a single APK "
                "(fixing public resource identifiers) — ideal for analysis of installed apps."
            ),
            "zh": (
                "使用apk.sh pull或adb从已连接的Android设备/模拟器中提取APK。"
                "自动将Split APK/App Bundle合并为单个APK，修正公共资源标识符。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.pull_apk_from_device",
        ],
        "commands": [
            "adb devices                                       # check connected devices",
            "./apk.sh pull com.target.app                      # pull + merge split APKs",
            "adb shell pm list packages | grep target          # find package name",
            "adb shell pm path com.target.app                  # get APK path on device",
            "adb pull /data/app/com.target.app.apk ./          # manual pull fallback",
            "adb shell pm list packages -f | grep target       # find package + path at once",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "기기 연결 확인: adb devices. "
                "앱이 Split APK(App Bundle)인 경우 apk.sh pull이 자동으로 합쳐줌. "
                "일반 adb pull은 Split APK를 합치지 않음."
            ),
            "en": (
                "Verify device: adb devices. "
                "apk.sh pull automatically merges split APKs — regular adb pull does not. "
                "For emulator: adb -e shell pm path com.target.app"
            ),
            "zh": (
                "确认设备: adb devices。apk.sh pull自动合并Split APK，普通adb pull不会合并。"
                "模拟器: adb -e shell pm path com.target.app"
            ),
        },
    },

    # ── 6. Full APK Pipeline ─────────────────────────────────────────────────
    {
        "name": "apk-full-pipeline",
        "module": "mobile",
        "tags": [
            # EN
            "full apk analysis", "apk pipeline", "apk download scan patch",
            "android pentest pipeline", "apk complete analysis", "mobile full test",
            "download scan frida", "apk all in one", "android security test",
            "apk workflow", "apk recon pipeline", "mobile attack chain",
            "apk end to end", "android full pentest", "apkd apkscan apksh",
            # KO
            "apk 전체 분석", "안드로이드 침투 파이프라인", "apk 자동화",
            "모바일 전체 테스트",
            # ZH
            "APK全流程分析", "安卓渗透流水线", "APK自动化测试",
            "移动端完整分析",
        ],
        "desc": {
            "ko": (
                "APK 전체 분석 파이프라인: "
                "1) apkd로 APK 다운로드(패키지명 입력 시) → "
                "2) apkscan으로 시크릿+엔드포인트 스캔 → "
                "3) apk.sh로 Frida gadget 주입. "
                "한 번의 명령으로 정적 분석부터 동적 분석 준비까지 완료."
            ),
            "en": (
                "Full APK analysis pipeline combining all three tools: "
                "Step 1: Download APK via apkd (if package name provided) → "
                "Step 2: Scan for secrets + endpoints using apkscan → "
                "Step 3: Patch APK with Frida gadget via apk.sh for dynamic analysis. "
                "One command from reconnaissance to dynamic instrumentation setup."
            ),
            "zh": (
                "APK全流程分析流水线：\n"
                "步骤1: 通过apkd下载APK(输入包名时) → "
                "步骤2: 用apkscan扫描密钥+接口 → "
                "步骤3: 用apk.sh注入Frida gadget。"
                "一条命令完成从静态分析到动态分析准备。"
            ),
        },
        "tools": [
            "bingo.tools.apk_toolkit.full_apk_analysis_pipeline",
            "bingo.tools.apk_toolkit.download_apk",
            "bingo.tools.apk_toolkit.scan_apk_secrets_endpoints",
            "bingo.tools.apk_toolkit.patch_apk_frida_gadget",
            "bingo.tools.apk_toolkit.check_tools",
        ],
        "commands": [
            # Full pipeline from package name
            "python3 -c \"from bingo.tools.apk_toolkit import full_apk_analysis_pipeline; import json; print(json.dumps(full_apk_analysis_pipeline('com.target.app'), indent=2))\"",
            # Check tools
            "python3 -c \"from bingo.tools.apk_toolkit import check_tools, install_guide; print(install_guide()); import json; print(json.dumps(check_tools(), indent=2))\"",
            # Step-by-step manual
            "apkd -p com.target.app -d -s apkpure            # 1. Download",
            "apkscan target.apk -r all_secret_locators endpoints -o secrets.json  # 2. Scan",
            "./apk.sh patch target.apk --arch arm64           # 3. Frida patch",
            "adb install target.gadget.apk                    # 4. Install",
            "objection -g com.target.app explore              # 5. Dynamic analysis",
        ],
        "payloads": [],
        "notes": {
            "ko": (
                "전체 파이프라인 실행 전 check_tools()로 도구 설치 상태 확인 권장. "
                "각 단계 독립 실행 가능: apk-download / apkscan-secret-endpoint / apk-frida-patch. "
                "동적 분석 완료 후 iOS 앱 병행 분석 시 ios-malimite-decompile 스킬 사용."
            ),
            "en": (
                "Run check_tools() before full pipeline to verify tool availability. "
                "Each step is also available independently as separate skills. "
                "For iOS companion app analysis, combine with ios-malimite-decompile skill."
            ),
            "zh": (
                "运行完整流水线前建议先执行check_tools()确认工具安装状态。"
                "每个步骤也可单独执行。iOS配套应用分析可结合ios-malimite-decompile技能。"
            ),
        },
    },
]

# ── Skill indexes ─────────────────────────────────────────────────────────────

MODULE_INDEX_10: dict[str, list[str]] = {}
TAG_INDEX_10: dict[str, list[str]] = {}

for _s in SKILLS_DB_10:
    _mod = _s["module"]
    if _mod not in MODULE_INDEX_10:
        MODULE_INDEX_10[_mod] = []
    MODULE_INDEX_10[_mod].append(_s["name"])

    for _tag in _s["tags"]:
        _t = _tag.lower()
        if _t not in TAG_INDEX_10:
            TAG_INDEX_10[_t] = []
        TAG_INDEX_10[_t].append(_s["name"])
