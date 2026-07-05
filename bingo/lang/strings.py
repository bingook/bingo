SUPPORTED_LANGS = {"ko": "한국어", "zh": "中文", "en": "English"}

_STRINGS = {
    # ── 온보딩 ──────────────────────────────────────────────────
    "welcome": {
        "ko": "빙고에 오신 것을 환영합니다",
        "zh": "欢迎使用 Bingo",
        "en": "Welcome to Bingo",
    },
    "select_lang": {
        "ko": "언어를 선택하세요",
        "zh": "请选择语言",
        "en": "Select your language",
    },
    "lang_saved": {
        "ko": "언어가 저장되었습니다",
        "zh": "语言已保存",
        "en": "Language saved",
    },
    # ── 모델 설정 ────────────────────────────────────────────────
    "select_model": {
        "ko": "AI 모델을 선택하세요",
        "zh": "请选择 AI 模型",
        "en": "Select AI model",
    },
    "enter_api_key": {
        "ko": "API 키를 입력하세요",
        "zh": "请输入 API 密钥",
        "en": "Enter your API key",
    },
    "enter_base_url": {
        "ko": "Base URL을 입력하세요 (엔터 = 기본값 사용)",
        "zh": "输入 Base URL（回车使用默认值）",
        "en": "Enter Base URL (Enter = use default)",
    },
    "model_saved": {
        "ko": "모델 설정이 저장되었습니다",
        "zh": "模型配置已保存",
        "en": "Model configuration saved",
    },
    "model_name_prompt": {
        "ko": "모델명을 입력하세요 (예: deepseek-v4-pro)",
        "zh": "请输入模型名称（例：deepseek-v4-pro）",
        "en": "Enter model name (e.g. deepseek-v4-pro)",
    },
    "add_model": {
        "ko": "새 모델 추가",
        "zh": "添加新模型",
        "en": "Add new model",
    },
    "switch_model": {
        "ko": "모델 전환",
        "zh": "切换模型",
        "en": "Switch model",
    },
    # ── 채팅 UI ──────────────────────────────────────────────────
    "you": {
        "ko": "나",
        "zh": "我",
        "en": "You",
    },
    "thinking": {
        "ko": "생각 중...",
        "zh": "思考中...",
        "en": "Thinking...",
    },
    "input_prompt": {
        "ko": "메시지 입력 (Ctrl+C = 종료, /help = 도움말)",
        "zh": "输入消息（Ctrl+C 退出，/help 帮助）",
        "en": "Type a message (Ctrl+C to quit, /help for help)",
    },
    "empty_input": {
        "ko": "메시지를 입력하세요",
        "zh": "请输入消息",
        "en": "Please enter a message",
    },
    "goodbye": {
        "ko": "빙고를 종료합니다. 안녕히 가세요!",
        "zh": "再见！感谢使用 Bingo。",
        "en": "Goodbye! Thanks for using Bingo.",
    },
    # ── 명령어 ────────────────────────────────────────────────────
    "help_text": {
        "ko": """/login <url> <id> <pw>   🔑 실제 로그인 실행 + 세션 쿠키 자동 저장
/cred <id> <pw> [쿠키]  🔑 자격증명 수동 저장 (쿠키 없어도 OK)
/session                 현재 인증 세션 확인 | /session clear 초기화
/hint <메시지>           💬 AI 실행 도중 힌트 주입 (재실행 없이 방향 전환)
/retry                   🔁 마지막 실패 단계만 재실행 (처음부터 재시작 불필요)
/ctf <url>               🏁 웹 실습 환경 보안 점검 (--status / --resume=no / --headless=no)
/scan <url>              빠른 정찰: WAF + 핑거프린트 + 민감파일
/waf <url>               WAF 탐지 + 자동 우회 시도
/crack [hash]            해시 크랙 — 온라인 조회 → 오프라인 크랙
/stop                    실행 중인 크랙/스캔 중단
/whitebox <경로|paste>   🔍 소스코드 화이트박스 분석 → 취약점 힌트 추출
/agent [list|plan|priority] 🤖 취약점 전담 에이전트 관리
/report [save|clear]     📋 Proof-by-exploitation 리포트
/load <세션파일경로>      📂 이전 세션 불러오기 + AI 자동 재개 (경로 직접 붙여넣기도 가능)
/tools                   도구 목록 + 자동 설치
/tools install <이름>    특정 도구 자동 설치
/tools install all       미설치 도구 전체 설치
/model                   AI 모델 추가/변경
/skill <키워드>          스킬 지식베이스 검색
/kb                      로컬 지식베이스  /kb [list|search <kw>|show <name>|reload]
/cve [sync|search|status] 🛡️ CVE/Exploit KB  /cve sync 로 trickest+exploitarium 동기화
/history                 대화 기록 보기
/export                  대화를 .md 파일로 저장
/config                  현재 설정 보기
/lang                    언어 변경 (ko / zh / en)
/clear                   화면 지우기
/quit                    종료

⚡ Ctrl+C → 힌트 입력창 → 텍스트 입력 시 루프 유지 / Enter 시 중단""",
        "zh": """/login <url> <id> <pw>   🔑 执行实际登录 + 自动保存会话 Cookie
/cred <id> <pw> [Cookie] 🔑 手动保存凭据（无 Cookie 也可）
/session                 查看当前认证会话 | /session clear 清除
/hint <消息>             💬 执行中注入提示 (无需重启即可改变方向)
/retry                   🔁 仅重试上次失败步骤 (无需从头重新启动)
/ctf <url>               🏁 Web实验环境安全扫描 (--status / --resume=no / --headless=no)
/scan <url>              快速侦察：WAF + 指纹识别 + 敏感文件
/waf <url>               WAF 检测 + 自动绕过尝试
/crack [hash]            哈希破解 — 在线查询 → 离线破解
/stop                    停止正在运行的破解/扫描
/whitebox <路径|paste>   🔍 白盒源码分析 → 提取漏洞提示
/agent [list|plan|priority] 🤖 漏洞专属代理管理
/report [save|clear]     📋 漏洞利用证明报告
/load <会话文件路径>      📂 加载历史会话 + AI自动续接 (直接粘贴路径也可)
/tools                   工具列表 + 自动安装
/tools install <名称>    自动安装指定工具
/tools install all       安装所有缺失工具
/model                   添加/切换 AI 模型
/skill <关键词>          搜索技能知识库
/kb                      本地知识库  /kb [list|search <kw>|show <name>|reload]
/cve [sync|search|status] 🛡️ CVE/Exploit知识库  /cve sync 同步trickest+exploitarium
/history                 查看对话历史
/export                  导出对话为 .md 文件
/config                  查看当前配置
/lang                    切换语言 (ko / zh / en)
/clear                   清屏
/quit                    退出

⚡ Ctrl+C → 提示输入框 → 输入文字继续 / 直接回车停止""",
        "en": """/login <url> <id> <pw>   🔑 Perform real login + auto-save session cookies
/cred <id> <pw> [cookie] 🔑 Manually store credentials (cookie optional)
/session                 View auth session | /session clear to reset
/hint <message>          💬 Inject hint mid-execution (redirect without restart)
/retry                   🔁 Retry only the last failed step (no full restart)
/ctf <url>               🏁 Web lab security scan (--status / --resume=no / --headless=no)
/scan <url>              Quick recon: WAF + fingerprint + sensitive files
/waf <url>               WAF detection + auto bypass attempt
/crack [hash]            Hash crack — online lookup → offline crack
/stop                    Stop running crack/scan
/whitebox <path|paste>   🔍 Whitebox source code analysis → extract attack hints
/agent [list|plan|priority] 🤖 Vulnerability specialist agent management
/report [save|clear]     📋 Proof-by-exploitation report
/load <session-file>     📂 Load previous session + auto-resume AI (paste path directly too)
/tools                   Tool list + auto-install
/tools install <name>    Auto-install a specific tool
/tools install all       Install all missing tools
/model                   Add or switch AI model
/skill <keyword>         Search skill knowledge base
/kb                      Local knowledge base  /kb [list|search <kw>|show <name>|reload]
/cve [sync|search|status] 🛡️ CVE/Exploit KB  /cve sync to fetch trickest+exploitarium
/history                 View chat history
/export                  Export chat as .md file
/config                  View current settings
/lang                    Change language (ko / zh / en)
/clear                   Clear screen
/quit                    Quit

⚡ Ctrl+C → hint prompt → type to continue loop / Enter to stop""",
    },
    "login_usage": {
        "ko": "사용법: /login <url> <아이디> <비밀번호>\n예) /login https://target.com/manager/login.asp admin admin123",
        "zh": "用法: /login <url> <用户名> <密码>\n示例: /login https://target.com/admin/login admin admin123",
        "en": "Usage: /login <url> <username> <password>\nExample: /login https://target.com/manager/login.asp admin admin123",
    },
    "login_failed_tip": {
        "ko": "💡 직접 브라우저로 로그인 후 쿠키를 복사해서 /cred 명령어로 수동 입력하세요.\n예) /cred admin admin123 SESSIONID=abc123",
        "zh": "💡 请手动在浏览器登录后复制 Cookie，用 /cred 命令手动输入。\n示例: /cred admin admin123 SESSIONID=abc123",
        "en": "💡 Try logging in manually via browser, copy the cookie, then use /cred.\nExample: /cred admin admin123 SESSIONID=abc123",
    },
    "cred_usage": {
        "ko": "사용법: /cred <아이디> <비밀번호> [쿠키이름=값 ...]\n예) /cred admin admin123\n예) /cred admin admin123 SESSIONID=abc123",
        "zh": "用法: /cred <用户名> <密码> [Cookie名=值 ...]\n示例: /cred admin admin123\n示例: /cred admin admin123 SESSIONID=abc123",
        "en": "Usage: /cred <username> <password> [COOKIE_NAME=value ...]\nExample: /cred admin admin123\nExample: /cred admin admin123 SESSIONID=abc123",
    },
    "cred_none": {
        "ko": "저장된 자격증명이 없습니다. /login 또는 /cred 로 설정하세요.",
        "zh": "尚未保存凭据。请使用 /login 或 /cred 设置。",
        "en": "No credentials stored. Use /login or /cred to set them.",
    },
    "config_view": {
        "ko": "현재 설정",
        "zh": "当前配置",
        "en": "Current config",
    },
    "history_empty": {
        "ko": "대화 내역이 없습니다",
        "zh": "暂无对话历史",
        "en": "No chat history yet",
    },
    "export_saved": {
        "ko": "대화가 저장되었습니다",
        "zh": "对话已导出",
        "en": "Chat exported",
    },
    "no_model_configured": {
        "ko": "모델이 설정되지 않았습니다. /model 명령어로 추가하세요.",
        "zh": "尚未配置模型，请使用 /model 命令添加。",
        "en": "No model configured. Use /model to add one.",
    },

    # ── WAF 스캔 ─────────────────────────────────────────────────
    "waf_auto_scan":        {"ko": "🛡 WAF 자동 스캔",          "zh": "🛡 WAF 自动扫描",         "en": "🛡 WAF auto scan"},
    "waf_running":          {"ko": "wafw00f 실행 중...",         "zh": "wafw00f 执行中...",        "en": "Running wafw00f..."},
    "waf_internal":         {"ko": "내부 WAF 탐지 중...",        "zh": "内部 WAF 检测中...",       "en": "Running internal WAF detector..."},
    "waf_fingerprint":      {"ko": "핑거프린트...",              "zh": "指纹识别中...",            "en": "Fingerprinting..."},
    "waf_bypass_ok":        {"ko": "✓ 우회 성공",               "zh": "✓ 绕过成功",              "en": "✓ Bypass successful"},
    "waf_bypass_fail":      {"ko": "우회 실패 — /waf 결과를 AI에게 물어보세요",
                             "zh": "绕过失败 — 请将 /waf 结果发给 AI",
                             "en": "Bypass failed — ask AI with /waf results"},
    "waf_analyzing":        {"ko": "WAF 분석",                  "zh": "WAF 分析",                "en": "WAF analysis"},
    "waf_detecting":        {"ko": "WAF 탐지 중...",             "zh": "WAF 检测中...",            "en": "Detecting WAF..."},
    "waf_priority":         {"ko": "우선 우회 전략",             "zh": "优先绕过策略",             "en": "Priority bypass strategies"},
    # ── 프로토콜 자동 감지 ────────────────────────────────────────────
    "proto_detecting":      {"ko": "🔍 프로토콜 자동 감지 중... ({domain})",
                             "zh": "🔍 自动检测协议中... ({domain})",
                             "en": "🔍 Auto-detecting protocol... ({domain})"},
    "proto_detected":       {"ko": "✅ 프로토콜 감지 완료: {url}",
                             "zh": "✅ 协议检测完成: {url}",
                             "en": "✅ Protocol detected: {url}"},
    "proto_fallback":       {"ko": "⚠️  연결 실패 — https:// 기본값 사용: {url}",
                             "zh": "⚠️  连接失败 — 使用默认 https://: {url}",
                             "en": "⚠️  Connection failed — using https:// default: {url}"},
    "waf_auto_bypass":      {"ko": "자동 우회 시도 중...",       "zh": "自动绕过尝试中...",        "en": "Attempting auto bypass..."},
    "waf_ai_request":       {"ko": "AI 분석 요청 중...",         "zh": "请求 AI 分析中...",        "en": "Requesting AI analysis..."},

    # ── 해시 크랙 ────────────────────────────────────────────────
    "hash_found":           {"ko": "🔑 해시 {n}개 감지 — 자동 크랙 시작 (/stop 으로 중단 가능)",
                             "zh": "🔑 检测到 {n} 个哈希 — 自动破解开始（/stop 可中断）",
                             "en": "🔑 {n} hash(es) found — auto-crack started (/stop to cancel)"},
    "hash_online":          {"ko": "① 온라인 해시 조회 중...",   "zh": "① 在线哈希查询中...",     "en": "① Online hash lookup..."},
    "hash_offline":         {"ko": "② 오프라인 크랙 ({n}개 남음)...", "zh": "② 离线破解（剩余 {n} 个）...", "en": "② Offline crack ({n} remaining)..."},
    "hash_stopped":         {"ko": "⏹ 크랙 중단됨",             "zh": "⏹ 破解已中断",            "en": "⏹ Crack stopped"},
    "hash_result_title":    {"ko": "🔓 크랙 결과",               "zh": "🔓 破解结果",              "en": "🔓 Crack results"},
    "hash_col_hash":        {"ko": "해시",                      "zh": "哈希",                    "en": "Hash"},
    "hash_col_plain":       {"ko": "평문",                      "zh": "明文",                    "en": "Plaintext"},
    "hash_col_method":      {"ko": "방법",                      "zh": "方法",                    "en": "Method"},
    "hash_unsolved":        {"ko": "미해결",                     "zh": "未解决",                  "en": "unsolved"},
    "hash_done":            {"ko": "(크랙 완료 — 결과가 세션 로그에 저장됨)",
                             "zh": "（破解完成 — 结果已保存到会话日志）",
                             "en": "(Crack done — results saved to session log)"},
    "hash_none":            {"ko": "크랙할 해시가 없습니다.",    "zh": "没有可破解的哈希。",       "en": "No hashes to crack."},
    "hash_usage":           {"ko": "사용법:\n  /crack <hash>  — 직접 입력\n  /crack         — 최근 AI 응답에서 자동 추출\n  /crack -w /path/rockyou.txt <hash>",
                             "zh": "用法:\n  /crack <hash>  — 直接输入\n  /crack         — 从最近 AI 回复自动提取\n  /crack -w /path/rockyou.txt <hash>",
                             "en": "Usage:\n  /crack <hash>  — direct input\n  /crack         — auto-extract from last AI response\n  /crack -w /path/rockyou.txt <hash>"},
    "hash_start":           {"ko": "🔓 해시 크랙 시작 ({n}개) — /stop 으로 중단",
                             "zh": "🔓 哈希破解开始（{n} 个）— /stop 可中断",
                             "en": "🔓 Hash crack started ({n}) — /stop to cancel"},
    "hash_stop_signal":     {"ko": "⏹ 크랙 중단 신호 전송됨",   "zh": "⏹ 已发送中断信号",        "en": "⏹ Stop signal sent"},

    # ── 도구 관리 ────────────────────────────────────────────────
    "tools_title":          {"ko": "Bingo Tools ({a}/{t} 설치됨)", "zh": "Bingo Tools（{a}/{t} 已安装）", "en": "Bingo Tools ({a}/{t} installed)"},
    "tools_col_tool":       {"ko": "도구",                      "zh": "工具",                    "en": "Tool"},
    "tools_col_type":       {"ko": "유형",                      "zh": "类型",                    "en": "Type"},
    "tools_col_status":     {"ko": "상태",                      "zh": "状态",                    "en": "Status"},
    "tools_col_version":    {"ko": "버전 / 설치 방법",          "zh": "版本 / 安装方法",          "en": "Version / Install hint"},
    "tools_installed":      {"ko": "설치됨",                    "zh": "已安装",                  "en": "installed"},
    "tools_all_ok":         {"ko": "모든 도구가 설치되어 있습니다.", "zh": "所有工具已安装。",       "en": "All tools are installed."},
    "tools_missing":        {"ko": "{n}개 도구 미설치.  자동 설치 옵션:", "zh": "{n} 个工具未安装。自动安装选项：", "en": "{n} tool(s) not installed. Auto-install options:"},
    "tools_install_hint":   {"ko": "설치: /tools install <도구명>  또는  /tools install all\n  예)  /tools install nmap nuclei ffuf\n  예)  /tools install all",
                             "zh": "安装: /tools install <名称>  或  /tools install all\n  例)  /tools install nmap nuclei ffuf\n  例)  /tools install all",
                             "en": "Install: /tools install <name>  or  /tools install all\n  e.g.  /tools install nmap nuclei ffuf\n  e.g.  /tools install all"},
    "tools_install_all_ask":{"ko": "지금 없는 도구를 모두 설치할까요? (y/N)",
                             "zh": "立即安装所有缺失的工具吗？(y/N)",
                             "en": "Install all missing tools now? (y/N)"},
    "tools_install_later":  {"ko": "나중에 /tools install <이름> 으로 개별 설치 가능",
                             "zh": "稍后可用 /tools install <名称> 单独安装",
                             "en": "Install later with /tools install <name>"},
    "tools_auto_install":   {"ko": "📦 도구 자동 설치",         "zh": "📦 工具自动安装",          "en": "📦 Auto-installing tools"},
    "tools_install_start":  {"ko": "📦 {n}개 도구 자동 설치 시작...", "zh": "📦 开始自动安装 {n} 个工具...", "en": "📦 Auto-installing {n} tool(s)..."},
    "tools_install_ok":     {"ko": "✓ {name} 설치 완료",        "zh": "✓ {name} 安装完成",       "en": "✓ {name} installed"},
    "tools_install_fail":   {"ko": "✗ {name} 설치 실패 — Python 폴백 사용", "zh": "✗ {name} 安装失败 — 使用 Python 回退", "en": "✗ {name} install failed — using Python fallback"},
    "tools_usage_hint":     {"ko": "사용법: /tools install <도구명>  또는  /tools install all",
                             "zh": "用法: /tools install <名称>  或  /tools install all",
                             "en": "Usage: /tools install <name>  or  /tools install all"},

    # ── 세션/UI ──────────────────────────────────────────────────
    "session_saved":        {"ko": "📝 세션 자동 저장",          "zh": "📝 会话自动保存",          "en": "📝 Session auto-save"},
    "session_done":         {"ko": "💾 세션 저장됨",             "zh": "💾 会话已保存",            "en": "💾 Session saved"},
    "rephrase_retry":       {"ko": "⚡ 요청 재구성 중...",        "zh": "⚡ 重新构建请求中...",     "en": "⚡ Rephrasing request..."},
    "lang_changed":         {"ko": "언어 변경 완료: {lang}  — 모든 메시지가 즉시 적용됩니다",
                             "zh": "语言已切换: {lang}  — 所有消息立即生效",
                             "en": "Language changed: {lang}  — all messages updated immediately"},
    "lang_invalid":         {"ko": "지원하지 않는 언어: {raw}  (ko / zh / en 또는 1 / 2 / 3)",
                             "zh": "不支持的语言: {raw}  (ko / zh / en 或 1 / 2 / 3)",
                             "en": "Unsupported language: {raw}  (ko / zh / en or 1 / 2 / 3)"},

    # ── 스캔 명령 ─────────────────────────────────────────────────
    "scan_title":           {"ko": "🎯 Red Team 스캔",           "zh": "🎯 Red Team 扫描",        "en": "🎯 Red Team scan"},
    "scan_hint":            {"ko": "채팅 창 내에서 실행 — 상세 결과는 'bingo scan {url}' 사용",
                             "zh": "在聊天窗口中执行 — 详细结果请使用 'bingo scan {url}'",
                             "en": "Running in chat — for full results use 'bingo scan {url}'"},
    "scan_recon":           {"ko": "정찰 중...",                  "zh": "侦察中...",               "en": "Recon in progress..."},
    "scan_result_title":    {"ko": "빠른 스캔 결과",             "zh": "快速扫描结果",             "en": "Quick scan results"},
    "scan_col_item":        {"ko": "항목",                      "zh": "项目",                    "en": "Item"},
    "scan_col_result":      {"ko": "결과",                      "zh": "结果",                    "en": "Result"},
    "scan_tech":            {"ko": "기술스택",                   "zh": "技术栈",                  "en": "Tech stack"},
    "scan_waf":             {"ko": "WAF",                       "zh": "WAF",                     "en": "WAF"},
    "scan_waf_none":        {"ko": "없음",                      "zh": "无",                      "en": "None"},
    "scan_sensitive":       {"ko": "민감파일",                   "zh": "敏感文件",                "en": "Sensitive files"},
    "scan_admin":           {"ko": "관리자패널",                 "zh": "管理后台",                "en": "Admin panels"},
    "scan_sensitive_found": {"ko": "⚠ 민감 파일",               "zh": "⚠ 敏感文件",              "en": "⚠ Sensitive files"},
    "scan_admin_found":     {"ko": "⚠ 관리자 패널",             "zh": "⚠ 管理后台",              "en": "⚠ Admin panels"},
    "scan_full_hint":       {"ko": "전체 자동화 스캔: bingo scan {url}",
                             "zh": "完整自动化扫描: bingo scan {url}",
                             "en": "Full automated scan: bingo scan {url}"},
    "models_saved":         {"ko": "── 저장된 모델",             "zh": "── 已保存模型",            "en": "── Saved models"},
    "models_add_new":       {"ko": "── 새 모델 추가",            "zh": "── 添加新模型",            "en": "── Add new model"},
    "select_number":        {"ko": "번호 선택",                  "zh": "选择编号",                "en": "Select number"},
    "alias_prompt":         {"ko": "별칭 (선택, 엔터 스킵)",     "zh": "别名（可选，回车跳过）",   "en": "Alias (optional, Enter to skip)"},
    "crack_stopped":        {"ko": "⏹ 크랙 중단됨",             "zh": "⏹ 破解已中断",            "en": "⏹ Crack stopped"},

    # ── 해시 온라인/오프라인 상세 ────────────────────────────────
    "hash_checking":        {"ko": "🔍 조회 중",                 "zh": "🔍 查询中",               "en": "🔍 Checking"},
    "hash_bcrypt_no_online":{"ko": "⚠ bcrypt → 온라인 DB 조회 불가 (salt 포함 단방향 암호화) → 오프라인 크랙 실행",
                             "zh": "⚠ bcrypt → 无法在线查询（含 salt 的单向加密）→ 离线破解",
                             "en": "⚠ bcrypt → online DB lookup impossible (salted one-way) → offline crack"},
    "hash_online_not_found":{"ko": "✗ 온라인 조회 결과 없음",    "zh": "✗ 在线查询无结果",         "en": "✗ Not found in online databases"},
    "hash_offline_ok":      {"ko": "✓ [오프라인/{method}] {h}... → {plain}",
                             "zh": "✓ [离线/{method}] {h}... → {plain}",
                             "en": "✓ [offline/{method}] {h}... → {plain}"},
    "hash_offline_fail":    {"ko": "✗ {h}... — {err}",          "zh": "✗ {h}... — {err}",        "en": "✗ {h}... — {err}"},
    "hash_manual_unsolved": {"ko": "미해결",                     "zh": "未解决",                  "en": "unsolved"},

    # ── 스킬 검색 ────────────────────────────────────────────────
    "skill_search_result":  {"ko": "스킬 검색",                  "zh": "技能搜索",                "en": "Skill search"},
    "skill_no_result":      {"ko": "'{kw}' 검색 결과 없음",      "zh": "'{kw}' 搜索无结果",        "en": "No results for '{kw}'"},
    "skill_search_hint":    {"ko": "/skill <키워드>  로 검색  예) /skill sqli",
                             "zh": "/skill <关键词> 搜索  例) /skill sqli",
                             "en": "/skill <keyword> to search  e.g. /skill sqli"},
    "skill_module_title":   {"ko": "CyberSecurity-Skills 39 모듈", "zh": "CyberSecurity-Skills 39 模块", "en": "CyberSecurity-Skills 39 Modules"},

    # ── terminal.py 나머지 ────────────────────────────────────────
    "cmd_unknown":      {"ko": "알 수 없는 명령어: {name}  (/help 참고)",
                         "zh": "未知命令: {name}  （/help 查看帮助）",
                         "en": "Unknown command: {name}  (see /help)"},
    "target_url_prompt":{"ko": "타겟 URL",    "zh": "目标 URL",      "en": "Target URL"},
    "waf_confidence":   {"ko": "신뢰도",      "zh": "置信度",        "en": "Confidence"},
    "waf_evidence":     {"ko": "증거",        "zh": "证据",          "en": "Evidence"},
    "install_trying":   {"ko": "설치 시도...", "zh": "安装尝试中...", "en": "Installing..."},
    "install_error":    {"ko": "오류",        "zh": "错误",          "en": "Error"},

    # ── cli.py 스탠드어론 모드 ────────────────────────────────────
    "cli_model_later":  {"ko": "나중에 /model 명령어로 추가할 수 있습니다",
                         "zh": "稍后可使用 /model 命令添加",
                         "en": "You can add a model later with /model"},
    "cli_skip_model":   {"ko": "나중에 설정",  "zh": "稍后设置",     "en": "Set up later"},
    "cli_scan_done":    {"ko": "✓ 완료! 보고서", "zh": "✓ 完成！报告", "en": "✓ Done! Report"},
    "cli_scan_abort":   {"ko": "중단됨 — 세션이 저장됐습니다", "zh": "已中断 — 会话已保存", "en": "Aborted — session saved"},
    "cli_waf_title":    {"ko": "🛡 WAF 분석",  "zh": "🛡 WAF 分析",  "en": "🛡 WAF analysis"},
    "cli_waf_detected": {"ko": "WAF 탐지됨",  "zh": "检测到 WAF",   "en": "WAF detected"},
    "cli_waf_confidence":{"ko": "신뢰도",     "zh": "置信度",       "en": "Confidence"},
    "cli_waf_evidence": {"ko": "증거",        "zh": "证据",         "en": "Evidence"},
    "cli_waf_strategy": {"ko": "권장 우회 전략", "zh": "推荐绕过策略","en": "Recommended bypass strategies"},
    "cli_waf_bypass_try":{"ko": "자동 우회 시도 중...", "zh": "自动绕过尝试中...", "en": "Attempting auto bypass..."},
    "cli_waf_bypass_ok":{"ko": "✓ 우회 성공!",  "zh": "✓ 绕过成功！", "en": "✓ Bypass successful!"},
    "cli_waf_tech":     {"ko": "기법",         "zh": "技术",         "en": "Technique"},
    "cli_waf_payload":  {"ko": "페이로드",     "zh": "有效载荷",     "en": "Payload"},
    "cli_waf_bypass_fail":{"ko": "현재 기법으로 우회 실패 — AI 분석 필요",
                           "zh": "当前技术绕过失败 — 需要 AI 分析",
                           "en": "Bypass failed with current techniques — AI analysis needed"},
    "cli_waf_none":     {"ko": "WAF 탐지 안됨 — 정상 접근 가능",
                         "zh": "未检测到 WAF — 可正常访问",
                         "en": "No WAF detected — direct access possible"},
    # ── 고급 WAF 우회 기법 (신규) ─────────────────────────────────
    "waf_adv_function": {"ko": "🔀 SQL 함수 대체 시도 중...",
                          "zh": "🔀 SQL 函数替换尝试中...",
                          "en": "🔀 Trying SQL function replacement..."},
    "waf_adv_unicode":  {"ko": "🌐 Unicode/오버롱 인코딩 시도 중...",
                          "zh": "🌐 Unicode/超长编码尝试中...",
                          "en": "🌐 Trying Unicode/overlong encoding..."},
    "waf_adv_chunked":  {"ko": "📦 HTTP Chunked 분할 전송 시도 중...",
                          "zh": "📦 HTTP 分块传输尝试中...",
                          "en": "📦 Trying HTTP chunked transfer encoding..."},
    "waf_adv_case_when":{"ko": "IF → CASE WHEN 대체 적용",
                          "zh": "IF → CASE WHEN 替换应用",
                          "en": "Applying IF → CASE WHEN replacement"},
    "waf_adv_sleep_sub":{"ko": "SLEEP → 서브쿼리 타이밍 대체 적용",
                          "zh": "SLEEP → 子查询时序替换应用",
                          "en": "Applying SLEEP → heavy subquery timing"},
    "waf_adv_combined_fn":{"ko": "함수대체 + 공백 + 헤더 조합 시도",
                            "zh": "函数替换 + 空格 + 请求头组合尝试",
                            "en": "Trying function+space+header combined bypass"},
    "waf_adv_combined_uni":{"ko": "Unicode + 함수대체 조합 시도",
                             "zh": "Unicode + 函数替换组合尝试",
                             "en": "Trying unicode+function combined bypass"},
    "waf_anti_ban":     {"ko": "🐢 IP 밴 방지 — 랜덤 딜레이 적용",
                          "zh": "🐢 防 IP 封禁 — 随机延迟中",
                          "en": "🐢 Anti-IP-ban — applying random delay"},
    "cli_tools_title":  {"ko": "설치된 도구 현황", "zh": "已安装工具状态", "en": "Installed tools status"},
    "cli_skill_stats":  {"ko": "📚 내장 스킬 통계", "zh": "📚 内置技能统计", "en": "📚 Built-in skill stats"},
    "cli_skill_total":  {"ko": "전체 스킬",    "zh": "总技能数",     "en": "Total skills"},
    "cli_skill_modules":{"ko": "모듈",         "zh": "模块",         "en": "Modules"},
    "cli_skill_tags":   {"ko": "태그",         "zh": "标签",         "en": "Tags"},
    "cli_skill_local":  {"ko": "로컬 Clone",   "zh": "本地克隆",     "en": "Local clone"},
    "cli_skill_need_install":{"ko": "bingo skill install 필요", "zh": "需要 bingo skill install", "en": "run bingo skill install"},
    "cli_help_chat":    {"ko": "AI 채팅 터미널", "zh": "AI 聊天终端",  "en": "AI chat terminal"},
    "cli_help_scan":    {"ko": "🎯 자동 Red Team 스캔", "zh": "🎯 自动 Red Team 扫描", "en": "🎯 Auto Red Team scan"},
    "cli_help_waf":     {"ko": "🛡 WAF 탐지 + 우회 테스트", "zh": "🛡 WAF 检测 + 绕过测试", "en": "🛡 WAF detect + bypass test"},
    "cli_help_tools":   {"ko": "🔧 설치된 도구 목록", "zh": "🔧 已安装工具列表", "en": "🔧 Installed tool list"},
    "cli_help_skill":   {"ko": "📚 CyberSecurity-Skills 목록", "zh": "📚 CyberSecurity-Skills 列表", "en": "📚 CyberSecurity-Skills list"},
    "cli_help_skill_install":{"ko": "스킬 DB 다운로드", "zh": "下载技能数据库", "en": "Download skill DB"},
    "cli_help_skill_search":{"ko": "스킬 검색",   "zh": "搜索技能",     "en": "Search skills"},
    "cli_help_reset":   {"ko": "설정 초기화",   "zh": "重置配置",     "en": "Reset config"},
    "cli_help_version": {"ko": "버전 표시",     "zh": "显示版本",     "en": "Show version"},
    "cli_help_update":  {"ko": "최신 버전으로 업데이트 (PyPI)", "zh": "升级到最新版本 (PyPI)", "en": "Update to latest version (PyPI)"},
    "cli_help_output":  {"ko": "보고서 저장 위치", "zh": "报告保存位置","en": "Report save path"},
    "cli_help_phase":   {"ko": "실행할 단계 선택", "zh": "选择执行阶段","en": "Select phases to run"},
    "crawling":            {"ko": "🔍 사이트 크롤 중...", "zh": "🔍 站点抓取中...", "en": "🔍 Crawling site..."},
    "params_found":        {"ko": "✓ 파라미터 발견", "zh": "✓ 发现参数",     "en": "✓ Parameters found"},
    "exec_running":        {"ko": "실행 중",       "zh": "执行中",       "en": "Running"},
    "exec_analyzing":      {"ko": "📊 실행 결과 분석 중...", "zh": "📊 分析执行结果...", "en": "📊 Analyzing results..."},
    "site_recon":          {"ko": "🔍 사이트 정보 수집",   "zh": "🔍 站点信息收集",  "en": "🔍 Site reconnaissance"},
    "burp_auto_scan":      {"ko": "🔧 Burp 자동 스캔 중...", "zh": "🔧 Burp 自动扫描中...", "en": "🔧 Burp auto-scanning..."},
    "burp_scan_done":      {"ko": "✅ Burp 스캔 완료",        "zh": "✅ Burp 扫描完成",       "en": "✅ Burp scan complete"},
    "burp_scan_error":     {"ko": "⚠️ Burp 스캔 오류",        "zh": "⚠️ Burp 扫描错误",       "en": "⚠️ Burp scan error"},
    "burp_findings":       {"ko": "개 발견",                   "zh": "个发现",                  "en": "findings"},
    "burp_no_findings":    {"ko": "발견 없음",                 "zh": "无发现",                  "en": "no findings"},
    "burp_more":           {"ko": "개 추가 발견 (AI 컨텍스트에 포함)", "zh": "个更多发现(已注入AI上下文)", "en": "more findings (in AI context)"},
    "page_crawling":       {"ko": "🔍 페이지 크롤 중...", "zh": "🔍 页面抓取中...", "en": "🔍 Crawling page..."},
    "waf_hint":            {"ko": "⚡ WAF 힌트",         "zh": "⚡ WAF 提示",     "en": "⚡ WAF hint"},
    "python_exec":         {"ko": "Python 실행",         "zh": "Python 执行",     "en": "Python execution"},
    "skill_ctx_injected":  {"ko": "💡 이 레퍼런스는 AI 메시지 전송 시 자동으로 컨텍스트에 주입됩니다.",
                            "zh": "💡 发送 AI 消息时，此参考资料将自动注入上下文。",
                            "en": "💡 This reference is automatically injected into AI context on send."},
    "skill_local_packs":   {"ko": "📦 SecSkills 로컬 레퍼런스 팩", "zh": "📦 SecSkills 本地参考包", "en": "📦 SecSkills Local Reference Packs"},
    "skill_search_tip":    {"ko": "💡 /skill <키워드> 로 특정 레퍼런스 검색 가능",
                            "zh": "💡 使用 /skill <关键词> 搜索特定参考资料",
                            "en": "💡 Use /skill <keyword> to search specific references"},
    "skill_db_label":      {"ko": "내장 DB 스킬",    "zh": "内置数据库技能",   "en": "Built-in DB skills"},
    "skill_col_refs":      {"ko": "레퍼런스 수",     "zh": "参考数量",        "en": "Refs"},
    "skill_col_main":      {"ko": "주요 레퍼런스",   "zh": "主要参考",        "en": "Main References"},

    "cli_skill_integrated":{"ko": "CyberSecurity-Skills 39 모듈 + SecSkills 로컬 통합",
                            "zh": "CyberSecurity-Skills 39 模块 + SecSkills 本地集成",
                            "en": "CyberSecurity-Skills 39 modules + SecSkills local integration"},

    # ── Agent 루프 / 실행 UI ──────────────────────────────────────
    "agent_loop":          {"ko": "Agent 루프",          "zh": "Agent 循环",       "en": "Agent loop"},
    "agent_ctrl_c":        {"ko": "Ctrl+C로 중단 가능",  "zh": "Ctrl+C 可中断",    "en": "Ctrl+C to stop"},
    "agent_done":          {"ko": "Agent 작업 완료",     "zh": "Agent 任务完成",   "en": "Agent task complete"},
    "agent_max_loop":      {"ko": "Agent 최대 루프 도달 — 직접 다음 명령을 입력하세요",
                            "zh": "Agent 达到最大循环次数 — 请手动输入下一条指令",
                            "en": "Agent max loops reached — enter next command manually"},
    "agent_depth_exceeded":{"ko": "Agent 재귀 깊이 초과 — 강제 중단",
                            "zh": "Agent 递归深度超限 — 强制终止",
                            "en": "Agent recursion depth exceeded — force stopped"},
    "agent_interrupted":   {"ko": "Agent 루프 중단됨 (Ctrl+C)",
                            "zh": "Agent 循环已中断 (Ctrl+C)",
                            "en": "Agent loop interrupted (Ctrl+C)"},
    "agent_stop_warn":     {"ko": "Ctrl+C — Agent 루프 중단 중... (한 번 더 누르면 완전 종료)",
                            "zh": "Ctrl+C — Agent 循环中断中... (再按一次完全退出)",
                            "en": "Ctrl+C — stopping agent... (press again to force quit)"},
    "skill_loaded":        {"ko": "스킬 로드됨",         "zh": "技能已加载",       "en": "Skills loaded"},
    "skill_applying":      {"ko": "스킬 지식 적용 중...", "zh": "正在应用技能知识...", "en": "Applying skill knowledge..."},

    # ── DApp / Web3 / 스마트컨트랙트 ─────────────────────────────────
    "web3_skill_injected_ko": {"ko": "🔗 Web3/DApp 스킬 자동 로드됨",
                               "zh": "🔗 Web3/DApp技能已自动加载",
                               "en": "🔗 Web3/DApp skills auto-loaded"},
    "web3_scan_start":        {"ko": "DApp/Web3 스캔 시작",
                               "zh": "DApp/Web3扫描启动",
                               "en": "DApp/Web3 scan started"},
    "web3_rpc_found":         {"ko": "JSON-RPC 엔드포인트 발견",
                               "zh": "发现JSON-RPC端点",
                               "en": "JSON-RPC endpoint found"},
    "web3_contract_found":    {"ko": "스마트 컨트랙트 주소 발견",
                               "zh": "发现智能合约地址",
                               "en": "Smart contract address found"},
    "web3_abi_extracted":     {"ko": "ABI 추출 완료",
                               "zh": "ABI提取完成",
                               "en": "ABI extracted"},
    "web3_reentrancy":        {"ko": "재진입 취약점 감지",
                               "zh": "检测到重入漏洞",
                               "en": "Reentrancy vulnerability detected"},
    "web3_access_ctrl":       {"ko": "접근 제어 취약점",
                               "zh": "访问控制漏洞",
                               "en": "Access control vulnerability"},
    "web3_flash_loan":        {"ko": "플래시론 공격 벡터",
                               "zh": "闪电贷攻击向量",
                               "en": "Flash loan attack vector"},
    "web3_blind_signing":     {"ko": "블라인드 서명 취약점 감지",
                               "zh": "检测到盲签名漏洞",
                               "en": "Blind signing vulnerability detected"},
    "web3_eip7730_missing":   {"ko": "EIP-7730 클리어 사이닝 미구현",
                               "zh": "EIP-7730清晰签名未实现",
                               "en": "EIP-7730 clear signing not implemented"},
    "web3_bybit_vector":      {"ko": "Safe 멀티시그 Operation 타입 조작 위험",
                               "zh": "Safe多签Operation类型篡改风险",
                               "en": "Safe multisig operation-type tampering risk"},
    "web3_frontend_inject":   {"ko": "DApp 프론트엔드 JS 인젝션 위험",
                               "zh": "DApp前端JS注入风险",
                               "en": "DApp frontend JS injection risk"},
    "web3_weak_random":       {"ko": "약한 온체인 무작위성 감지 (SWC-120)",
                               "zh": "检测到弱链上随机性 (SWC-120)",
                               "en": "Weak on-chain randomness detected (SWC-120)"},
    "web3_dos_gas":           {"ko": "가스 한도 DoS 취약점 (SWC-128)",
                               "zh": "Gas限制DoS漏洞 (SWC-128)",
                               "en": "Gas limit DoS vulnerability (SWC-128)"},
    "web3_csp_missing":       {"ko": "DApp CSP 헤더 없음 — JS 인젝션 무방비",
                               "zh": "DApp缺少CSP头部 — JS注入无防护",
                               "en": "DApp missing CSP — JS injection unprotected"},
    "web3_sri_missing":       {"ko": "SRI 무결성 검사 미적용",
                               "zh": "未应用SRI完整性检查",
                               "en": "SRI integrity check not applied"},
    "tool_init":           {"ko": "툴 초기화 중...",     "zh": "正在初始化工具...", "en": "Initializing tools..."},
    "mscan_title":         {"ko": "멀티 에이전트 스캔",   "zh": "多智能体扫描",     "en": "Multi-Agent Scan"},
    "mscan_subtitle":      {"ko": "Recon + SQLi + WebVuln + Auth — 동시 실행",
                            "zh": "Recon + SQLi + WebVuln + Auth — 并行执行",
                            "en": "Recon + SQLi + WebVuln + Auth — parallel"},
    "exec_waiting":        {"ko": "실행 대기 중",         "zh": "等待执行",         "en": "Waiting to execute"},
    "undo_done":           {"ko": "롤백 완료",            "zh": "回滚完成",         "en": "Rollback complete"},
    "undo_none":           {"ko": "롤백할 스냅샷이 없습니다", "zh": "没有可回滚的快照", "en": "No snapshots to undo"},
    "snapshots_empty":     {"ko": "저장된 스냅샷 없음",   "zh": "无已保存快照",     "en": "No saved snapshots"},
    "cost_title":          {"ko": "토큰 사용량",          "zh": "Token 用量",       "en": "Token Usage"},
    "agent_phase2":        {"ko": "Phase 2: Recon 결과로 추가 타겟 스캔 중...",
                            "zh": "Phase 2: 基于 Recon 结果扫描额外目标...",
                            "en": "Phase 2: scanning additional targets from recon..."},

    # ── 오류 / 연결 ──────────────────────────────────────────────
    "conn_failed":         {"ko": "연결 실패",          "zh": "连接失败",         "en": "Connection failed"},
    "timeout":             {"ko": "타임아웃",            "zh": "超时",             "en": "Timeout"},
    "force_quit":          {"ko": "강제 종료",           "zh": "强制退出",         "en": "Force quit"},
    "api_error":           {"ko": "API 오류",            "zh": "API 错误",         "en": "API error"},
    "no_result":           {"ko": "결과 없음",           "zh": "无结果",           "en": "No result"},

    # ── 작업 완료 메시지 ──────────────────────────────────────────
    "task_complete":       {"ko": "작업 완료",           "zh": "任务完成",         "en": "Task complete"},
    "mission_complete":    {"ko": "미션 완료",           "zh": "任务全部完成",     "en": "Mission complete"},

    # ── WAF / SQLi 로그 ───────────────────────────────────────────
    "waf_detected":        {"ko": "WAF 탐지됨",          "zh": "检测到 WAF",       "en": "WAF detected"},
    "waf_none":            {"ko": "WAF 없음",            "zh": "无 WAF",           "en": "No WAF detected"},
    "waf_bypass_try":      {"ko": "WAF 우회 시도 중",    "zh": "正在尝试绕过 WAF", "en": "Attempting WAF bypass"},
    "sqli_found":          {"ko": "SQLi 취약점 발견",    "zh": "发现 SQLi 漏洞",   "en": "SQLi vulnerability found"},
    "sqli_none":           {"ko": "SQLi 취약점 없음",    "zh": "无 SQLi 漏洞",     "en": "No SQLi found"},
    "sqli_extracting":     {"ko": "DB 추출 중",          "zh": "正在提取数据库",   "en": "Extracting DB"},
    "creds_found":         {"ko": "자격증명 발견",       "zh": "发现凭据",         "en": "Credentials found"},

    # ── SQLi 페이로드 에코 / 커서 폭발 감지 (v3.2.70) ──────────────
    "sqli_payload_echo_warn": {
        "ko": "⚠ SQLi 페이로드 에코 감지 — 응답 파싱 오류 (커서 hex 폭발 위험)",
        "zh": "⚠ 检测到SQLi载荷回显 — 响应解析错误（hex游标爆炸风险）",
        "en": "⚠ SQLi payload echo detected — response parsing failure (hex cursor explosion risk)",
    },
    "sqli_reparse_hint": {
        "ko": "⚡ SQLi 응답 파싱 재시도 유도 중...",
        "zh": "⚡ 正在引导重新解析SQLi响应...",
        "en": "⚡ Guiding SQLi response re-parse...",
    },
    "sqli_guard_injected": {
        "ko": "_bingo_sqli_guard 검증 함수 자동 주입됨",
        "zh": "已自动注入_bingo_sqli_guard验证函数",
        "en": "_bingo_sqli_guard validator auto-injected",
    },
    "sqli_cursor_explosion": {
        "ko": "SQLi 커서 hex 폭발 탐지 — 추출 중단",
        "zh": "检测到SQLi hex游标爆炸 — 已中止提取",
        "en": "SQLi hex cursor explosion detected — extraction aborted",
    },

    # ── v3.2.71 — 응답 크기 SQLi 강제 전환 ─────────────────────────
    "sqli_size_diff_detected": {
        "ko": "⚡ 응답 크기 차이 감지 — SQLi 강제 우선 전환 (브루트포스/재탐색 중단)",
        "zh": "⚡ 检测到响应大小差异 — 强制切换SQLi优先（停止暴力破解/侦察）",
        "en": "⚡ Response size diff detected — forcing SQLi priority (halting brute force/recon)",
    },
    "sqli_size_force_hint": {
        "ko": "⚡ 크기 차이 기반 SQLi 강제 전환 유도 중...",
        "zh": "⚡ 正在基于响应大小差异强制引导SQLi...",
        "en": "⚡ Forcing SQLi pivot based on response size difference...",
    },

    # ── v3.2.71 — 브루트포스 자동 포기 ─────────────────────────────
    "bruteforce_abort_warn": {
        "ko": "🛑 브루트포스 연속 실패 임계값 초과 — 자동 포기 후 대안 벡터 전환",
        "zh": "🛑 暴力破解连续失败超过阈值 — 自动放弃并切换到替代攻击向量",
        "en": "🛑 Brute force consecutive fail threshold exceeded — auto-abort, switching vectors",
    },
    "bruteforce_redirect_hint": {
        "ko": "🛑 브루트포스 중단 → SQLi / 관리자 패널 등 대안 벡터로 전환 중...",
        "zh": "🛑 暴力破解已中止 → 正在切换到SQLi/管理员面板等替代向量...",
        "en": "🛑 Brute force aborted → redirecting to SQLi / admin panel / other vectors...",
    },

    # ── v3.2.71 — 타겟 메모리 ────────────────────────────────────────
    "target_memory_loaded": {
        "ko": "🧠 타겟 메모리 로드 — 이전 세션 SQLi 포인트·유저 정보를 AI에 주입",
        "zh": "🧠 目标记忆已加载 — 将上次会话SQLi注入点和用户信息注入AI",
        "en": "🧠 Target memory loaded — injecting previous session SQLi points & user info into AI",
    },
    "target_memory_saved": {
        "ko": "🧠 타겟 메모리 저장됨 — SQLi 포인트 누적 완료",
        "zh": "🧠 目标记忆已保存 — SQLi注入点已累积",
        "en": "🧠 Target memory saved — SQLi points accumulated",
    },
    "target_memory_not_found": {
        "ko": "🧠 저장된 타겟 메모리 없음 — 새로 탐색 시작",
        "zh": "🧠 没有保存的目标记忆 — 开始新的侦察",
        "en": "🧠 No target memory found — starting fresh recon",
    },

    # ── 멀티 에이전트 / Recon ─────────────────────────────────────
    "port_open":           {"ko": "열린 포트",           "zh": "开放端口",         "en": "Open port"},
    "tech_found":          {"ko": "기술스택 식별",       "zh": "技术栈识别",       "en": "Tech stack identified"},
    "subdomain_found":     {"ko": "서브도메인 발견",     "zh": "发现子域名",       "en": "Subdomain found"},
    "dir_found":           {"ko": "디렉터리 발견",       "zh": "发现目录",         "en": "Directory found"},

    # ── 보고서 ───────────────────────────────────────────────────
    "report_generating":   {"ko": "보고서 생성 중",      "zh": "正在生成报告",     "en": "Generating report"},
    "severity_critical":   {"ko": "위험 (Critical)",     "zh": "严重 (Critical)",  "en": "Critical"},
    "severity_high":       {"ko": "높음 (High)",         "zh": "高危 (High)",      "en": "High"},
    "severity_medium":     {"ko": "중간 (Medium)",       "zh": "中危 (Medium)",    "en": "Medium"},
    "severity_low":        {"ko": "낮음 (Low)",          "zh": "低危 (Low)",       "en": "Low"},
    "severity_info":       {"ko": "정보 (Info)",         "zh": "信息 (Info)",      "en": "Info"},

    # ── 인증 / 로그인 ─────────────────────────────────────────────
    "login_success":       {"ko": "로그인 성공",         "zh": "登录成功",         "en": "Login success"},
    "login_fail":          {"ko": "로그인 실패",         "zh": "登录失败",         "en": "Login failed"},
    "default_cred_found":  {"ko": "기본 자격증명 발견",  "zh": "发现默认凭据",     "en": "Default credentials found"},

    # ── 일반 진행 상태 ────────────────────────────────────────────
    "scanning":            {"ko": "스캔 중",             "zh": "扫描中",           "en": "Scanning"},
    "testing":             {"ko": "테스트 중",           "zh": "测试中",           "en": "Testing"},
    "done":                {"ko": "완료",                "zh": "完成",             "en": "Done"},
    "skip":                {"ko": "스킵",                "zh": "跳过",             "en": "Skip"},
    "error":               {"ko": "오류",                "zh": "错误",             "en": "Error"},
    "found":               {"ko": "발견",                "zh": "发现",             "en": "Found"},
    "not_found":           {"ko": "없음",                "zh": "未找到",           "en": "Not found"},
    "target":              {"ko": "타겟",                "zh": "目标",             "en": "Target"},
    "next_steps_title":    {"ko": "다음 선택지",              "zh": "下一步选项",           "en": "Next Options"},
    "progress_summary":    {"ko": "현황 요약",                "zh": "进展摘要",             "en": "Summary"},
    "agent_stuck":         {"ko": "Agent 막힘 — 자동 보고서 생성 중",
                            "zh": "Agent 卡住 — 正在生成报告",
                            "en": "Agent stuck — generating report"},
    "strategy_change":     {"ko": "전략 전환 요청",           "zh": "请求切换策略",          "en": "Strategy change requested"},
    "report_auto":         {"ko": "자동 보고서",              "zh": "自动报告",             "en": "Auto report"},
    "recon_summary":       {"ko": "링크={links}  폼={forms}  파라미터URL={params}  API={api}",
                            "zh": "链接={links}  表单={forms}  参数URL={params}  API={api}",
                            "en": "links={links}  forms={forms}  param_urls={params}  api={api}"},
    "recon_stack":         {"ko": "기술 스택",                "zh": "技术栈",               "en": "tech stack"},
    "exec_parallel":       {"ko": "병렬 실행 중",             "zh": "并行执行中",            "en": "Running"},
    "exec_scripts":        {"ko": "개 스크립트 동시 실행",    "zh": "个脚本并行",            "en": "scripts in parallel"},
    "exec_timeout_soft":   {"ko": "소프트 타임아웃 — 부분 결과 수집 중",
                            "zh": "软超时 — 正在收集部分结果",
                            "en": "soft timeout — collecting partial results"},
}


_SLASH_DESC = {
    "/help":    {"ko": "도움말 표시",                  "zh": "显示帮助",             "en": "Show help"},
    "/clear":   {"ko": "화면 초기화",                  "zh": "清屏",                "en": "Clear screen"},
    "/model":   {"ko": "AI 모델 추가/변경",             "zh": "添加/切换 AI 模型",    "en": "Add or switch AI model"},
    "/config":  {"ko": "현재 설정 보기",               "zh": "查看当前配置",          "en": "View current settings"},
    "/history": {"ko": "대화 기록 보기",               "zh": "查看对话历史",          "en": "View chat history"},
    "/export":  {"ko": "대화 기록 파일로 저장",         "zh": "导出对话为 .md 文件",   "en": "Export chat as .md"},
    "/lang":    {"ko": "언어 변경",                    "zh": "切换语言",             "en": "Change language"},
    "/scan":    {"ko": "빠른 레드팀 스캔  /scan <url>", "zh": "快速侦察  /scan <url>","en": "Quick recon  /scan <url>"},
    "/waf":     {"ko": "WAF 탐지 + 자동 우회  /waf <url>","zh": "WAF检测+绕过  /waf <url>","en": "WAF detect + bypass  /waf <url>"},
    "/crack":   {"ko": "해시 크랙  /crack [hash]  (인자 없으면 자동 추출)",
                 "zh": "哈希破解  /crack [hash]  (省略则自动提取)",
                 "en": "Hash crack  /crack [hash]  (auto-extract if omitted)"},
    "/tools":   {"ko": "도구 목록 + 자동 설치  /tools [install <name>|all]",
                 "zh": "工具列表+自动安装  /tools [install <名称>|all]",
                 "en": "Tool list + auto-install  /tools [install <name>|all]"},
    "/skill":           {"ko": "스킬 검색/설치  /skill <키워드>  또는  /skill install <url>",
                        "zh": "技能搜索/安装  /skill <关键词>  或  /skill install <url>",
                        "en": "Skill search/install  /skill <kw>  or  /skill install <url>"},
    "/skill install":  {"ko": "스킬 설치  /skill install <github_url 또는 로컬경로>",
                        "zh": "安装技能  /skill install <github_url 或 本地路径>",
                        "en": "Install skill  /skill install <github_url or local_path>"},
    "/stop":    {"ko": "자동 크랙 중단",               "zh": "停止自动破解",          "en": "Stop running crack"},
    "/webshell":{"ko": "웹쉘 업로드 시도  /webshell <url>  (Gnuboard5/범용 GIF polyglot)",
                 "zh": "Webshell上传  /webshell <url>  (Gnuboard5/通用GIF polyglot)",
                 "en": "Webshell upload  /webshell <url>  (Gnuboard5/generic GIF polyglot)"},
    "/mscan":   {"ko": "멀티 에이전트 병렬 스캔  /mscan <url>",
                 "zh": "多智能体并发扫描  /mscan <url>",
                 "en": "Multi-agent parallel scan  /mscan <url>"},
    "/login":   {"ko": "자격증명 등록/자동 로그인  /login <url> [user] [pass]",
                 "zh": "注册凭证/自动登录  /login <url> [user] [pass]",
                 "en": "Register creds + auto-login  /login <url> [user] [pass]"},
    "/cred":    {"ko": "저장된 자격증명 관리  /cred [list|del <id>|use <id>]",
                 "zh": "管理保存的凭证  /cred [list|del <id>|use <id>]",
                 "en": "Manage saved credentials  /cred [list|del <id>|use <id>]"},
    "/session": {"ko": "현재 세션 정보 보기  /session [clear]",
                 "zh": "查看会话信息  /session [clear]",
                 "en": "View session info  /session [clear]"},
    "/undo":    {"ko": "N단계 전으로 롤백  /undo [N]",
                 "zh": "回滚N步  /undo [N]",
                 "en": "Roll back N steps  /undo [N]"},
    "/snapshots":{"ko": "저장된 스냅샷 목록 보기",
                  "zh": "查看保存的快照列表",
                  "en": "View saved snapshots"},
    "/cost":    {"ko": "토큰 사용량 / 비용 확인",
                 "zh": "查看 token 用量/费用",
                 "en": "View token usage / cost"},
    "/retry":   {"ko": "마지막 요청 재시도",
                 "zh": "重试上一次请求",
                 "en": "Retry last request"},
    "/hint":    {"ko": "AI에게 힌트 주입  /hint <힌트 텍스트>",
                 "zh": "向AI注入提示  /hint <文本>",
                 "en": "Inject hint to AI  /hint <text>"},
    "/install": {"ko": "EXE 분석 도구 설치  /install exe-deps",
                 "zh": "安装EXE分析工具  /install exe-deps",
                 "en": "Install EXE analysis deps  /install exe-deps"},
    "/proxy":   {"ko": "프록시 풀 관리  /proxy [list|add|file|api|tor|rotate|test|unban|clear|off]",
                 "zh": "代理池管理  /proxy [list|add|file|api|tor|rotate|test|unban|clear|off]",
                 "en": "Proxy pool mgmt  /proxy [list|add|file|api|tor|rotate|test|unban|clear|off]"},
    "/ctf":     {"ko": "🏁 웹 실습 환경 보안 점검  /ctf <url> [--status|--resume=no|--headless=no]",
                 "zh": "🏁 Web实验环境安全扫描  /ctf <url> [--status|--resume=no|--headless=no]",
                 "en": "🏁 Web lab security scan  /ctf <url> [--status|--resume=no|--headless=no]"},
    "/whitebox":{"ko": "소스코드 화이트박스 분석  /whitebox <경로> 또는 /whitebox paste",
                 "zh": "白盒源码分析  /whitebox <路径> 或 /whitebox paste",
                 "en": "Whitebox source analysis  /whitebox <path> or /whitebox paste"},
    "/agent":   {"ko": "취약점 전담 에이전트  /agent [list|plan|priority <유형>]",
                 "zh": "漏洞专属代理  /agent [list|plan|priority <类型>]",
                 "en": "Vulnerability agents  /agent [list|plan|priority <type>]"},
    "/report":  {"ko": "Proof-by-exploitation 리포트  /report [save|clear]",
                 "zh": "漏洞利用证明报告  /report [save|clear]",
                 "en": "Proof-by-exploitation report  /report [save|clear]"},
    "/load":    {"ko": "이전 세션 불러오기 + AI 자동 재개  /load <파일경로>",
                 "zh": "加载历史会话 + AI自动续接  /load <文件路径>",
                 "en": "Load previous session + auto-resume AI  /load <file-path>"},
    "/quit":    {"ko": "종료",                        "zh": "退出",                "en": "Quit"},
    # ── v3.4.0 신규 명령어 ────────────────────────────────────────
    "/role":        {"ko": "역할 기반 테스트  /role [list|set <name>|info]",
                     "zh": "角色测试模式  /role [list|set <name>|info]",
                     "en": "Role-based testing  /role [list|set <name>|info]"},
    "/vulns":       {"ko": "취약점 DB  /vulns [list|add|show <id>|del <id>|export]",
                     "zh": "漏洞管理  /vulns [list|add|show <id>|del <id>|export]",
                     "en": "Vuln database  /vulns [list|add|show <id>|del <id>|export]"},
    "/board":       {"ko": "프로젝트 블랙보드  /board [show|set <k> <v>|del <k>|clear]",
                     "zh": "项目黑板  /board [show|set <k> <v>|del <k>|clear]",
                     "en": "Project blackboard  /board [show|set <k> <v>|del <k>|clear]"},
    "/tools-ext":   {"ko": "외부 CLI 도구  /tools-ext [list|run <name>|reload]",
                     "zh": "外部工具  /tools-ext [list|run <name>|reload]",
                     "en": "External CLI tools  /tools-ext [list|run <name>|reload]"},
    "/kb":          {"ko": "로컬 지식베이스  /kb [list|search <kw>|show <name>|reload]",
                     "zh": "本地知识库  /kb [list|search <kw>|show <name>|reload]",
                     "en": "Local knowledge base  /kb [list|search <kw>|show <name>|reload]"},
    "/cve":         {"ko": "CVE/Exploit KB  /cve [sync|status|search <kw>|CVE-ID]",
                     "zh": "CVE/Exploit知识库  /cve [sync|status|search <kw>|CVE-ID]",
                     "en": "CVE/Exploit KB  /cve [sync|status|search <kw>|CVE-ID]"},
    # ── CVE sync 상태 메시지 ─────────────────────────────────────────
    "cve_sync_start": {"ko": "🔄 CVE KB 동기화 시작... (최초 실행 시 수 분 소요)",
                       "zh": "🔄 CVE KB 同步中... (首次运行可能需要数分钟)",
                       "en": "🔄 Syncing CVE KB... (first run may take a few minutes)"},
    "cve_sync_done":  {"ko": "✅ CVE KB 동기화 완료 ({n}개 문서)",
                       "zh": "✅ CVE KB 同步完成 ({n} 篇文档)",
                       "en": "✅ CVE KB sync complete ({n} docs)"},
    "cve_not_synced": {"ko": "💡 /cve sync 실행 후 사용 가능합니다",
                       "zh": "💡 请先执行 /cve sync",
                       "en": "💡 Run /cve sync first"},
    "cve_search_empty":  {"ko": "사용법: /cve search <키워드|CVE-ID>",
                          "zh": "用法: /cve search <关键词|CVE-ID>",
                          "en": "Usage: /cve search <keyword|CVE-ID>"},
    "cve_no_results":    {"ko": "'{query}' 결과 없음. /cve sync 먼저 실행하세요",
                          "zh": "'{query}' 无结果。请先执行 /cve sync",
                          "en": "No results for '{query}'. Run /cve sync first"},
    "cve_not_found":     {"ko": "{cve_id} 없음. /cve sync 후 재시도하세요",
                          "zh": "{cve_id} 未找到。请执行 /cve sync 后重试",
                          "en": "{cve_id} not found. Run /cve sync and retry"},
    "cve_usage":         {"ko": ("사용법: /cve [sync|status|search <키워드>|<CVE-ID>]\n"
                                 "  /cve sync          — trickest/cve + exploitarium 동기화\n"
                                 "  /cve status        — 동기화 상태 확인\n"
                                 "  /cve search <kw>   — CVE/PoC 검색\n"
                                 "  /cve CVE-2024-0001 — 특정 CVE 조회"),
                          "zh": ("用法: /cve [sync|status|search <关键词>|<CVE-ID>]\n"
                                 "  /cve sync          — 同步 trickest/cve + exploitarium\n"
                                 "  /cve status        — 查看同步状态\n"
                                 "  /cve search <kw>   — 搜索 CVE/PoC\n"
                                 "  /cve CVE-2024-0001 — 查询特定CVE"),
                          "en": ("Usage: /cve [sync|status|search <kw>|<CVE-ID>]\n"
                                 "  /cve sync          — sync trickest/cve + exploitarium\n"
                                 "  /cve status        — check sync status\n"
                                 "  /cve search <kw>   — search CVE/PoC\n"
                                 "  /cve CVE-2024-0001 — lookup specific CVE")},
    "/batch":       {"ko": "배치 멀티타겟  /batch [list|add <url>|run|status|clear]",
                     "zh": "批量多目标  /batch [list|add <url>|run|status|clear]",
                     "en": "Batch multi-target  /batch [list|add <url>|run|status|clear]"},
    "/chain":       {"ko": "공격 체인 추적  /chain [show|add <step>|clear|export]",
                     "zh": "攻击链追踪  /chain [show|add <step>|clear|export]",
                     "en": "Attack chain tracker  /chain [show|add <step>|clear|export]"},
    "/hitl":        {"ko": "인간 확인 게이트  /hitl [on|off|status|log]",
                     "zh": "人工审批门  /hitl [on|off|status|log]",
                     "en": "Human-in-the-loop gate  /hitl [on|off|status|log]"},
    "/orch":        {"ko": "LLM 오케스트레이터  /orch [start <url>|stop|status|log|report]",
                     "zh": "LLM编排器  /orch [start <url>|stop|status|log|report]",
                     "en": "LLM orchestrator  /orch [start <url>|stop|status|log|report]"},
    # ── v3.5.3 PhantomGuard ───────────────────────────────────────────
    "/reset-phantom": {"ko": "🔄 PhantomGuard 카운터 초기화 + Liveness 재확인",
                       "zh": "🔄 重置幻影守卫计数器 + 重新检查工具Liveness",
                       "en": "🔄 Reset PhantomGuard counters + re-run liveness probe"},
    "/apt":           {"ko": "🕵️ APT 모듈: phish|supply|lateral|c2 — 全面APT化",
                       "zh": "🕵️ APT模块: phish|supply|lateral|c2 — 全面APT化",
                       "en": "🕵️ APT module suite: phish|supply|lateral|c2 — full APT-ification"},
    "/recon":         {"ko": "🔍 정보수집/자산수집: passive|active|full|js|nuclei|dorks",
                       "zh": "🔍 信息/资产收集: passive|active|full|js|nuclei|dorks",
                       "en": "🔍 Recon/asset collection: passive|active|full|js|nuclei|dorks"},
}

# ── v3.6.0: CVE/KB 메시지 (_STRINGS 에 추가 — get_strings() 반환 대상) ──────
_STRINGS.update({
    "cve_sync_start":   {"ko": "🔄 CVE KB 동기화 시작... (최초 실행 시 수 분 소요)",
                         "zh": "🔄 CVE KB 同步中... (首次运行可能需要数分钟)",
                         "en": "🔄 Syncing CVE KB... (first run may take a few minutes)"},
    "cve_sync_done":    {"ko": "✅ CVE KB 동기화 완료 ({n}개 문서)",
                         "zh": "✅ CVE KB 同步完成 ({n} 篇文档)",
                         "en": "✅ CVE KB sync complete ({n} docs)"},
    "cve_not_synced":   {"ko": "💡 /cve sync 실행 후 사용 가능합니다",
                         "zh": "💡 请先执行 /cve sync",
                         "en": "💡 Run /cve sync first"},
    "cve_search_empty": {"ko": "사용법: /cve search <키워드|CVE-ID>",
                         "zh": "用法: /cve search <关键词|CVE-ID>",
                         "en": "Usage: /cve search <keyword|CVE-ID>"},
    "cve_no_results":   {"ko": "'{query}' 결과 없음. /cve sync 먼저 실행하세요",
                         "zh": "'{query}' 无结果。请先执行 /cve sync",
                         "en": "No results for '{query}'. Run /cve sync first"},
    "cve_not_found":    {"ko": "{cve_id} 없음. /cve sync 후 재시도하세요",
                         "zh": "{cve_id} 未找到。请执行 /cve sync 后重试",
                         "en": "{cve_id} not found. Run /cve sync and retry"},
    "cve_usage":        {"ko": ("사용법: /cve [sync|status|search <키워드>|<CVE-ID>]\n"
                                "  /cve sync          — trickest/cve + exploitarium 동기화\n"
                                "  /cve status        — 동기화 상태 확인\n"
                                "  /cve search <kw>   — CVE/PoC 검색\n"
                                "  /cve CVE-2024-0001 — 특정 CVE 조회"),
                         "zh": ("用法: /cve [sync|status|search <关键词>|<CVE-ID>]\n"
                                "  /cve sync          — 同步 trickest/cve + exploitarium\n"
                                "  /cve status        — 查看同步状态\n"
                                "  /cve search <kw>   — 搜索 CVE/PoC\n"
                                "  /cve CVE-2024-0001 — 查询特定CVE"),
                         "en": ("Usage: /cve [sync|status|search <kw>|<CVE-ID>]\n"
                                "  /cve sync          — sync trickest/cve + exploitarium\n"
                                "  /cve status        — check sync status\n"
                                "  /cve search <kw>   — search CVE/PoC\n"
                                "  /cve CVE-2024-0001 — lookup specific CVE")},
})

# ── 스킬 시스템 / WAF / 자동 분석 추가 문자열 ──────────────────────────────
_STRINGS.update({
    "url_404_fallback":     {"ko": "⚠ {url} → 404. 루트 사이트로 분석 전환: {root}",
                             "zh": "⚠ {url} → 404。切换到根站点分析: {root}",
                             "en": "⚠ {url} → 404. Switching to root site analysis: {root}"},
    "hackskills_match":     {"ko": "hack-skills 매칭 ({n}개) — AI가 자동 로드:",
                             "zh": "hack-skills 匹配 ({n} 个) — AI 将自动加载:",
                             "en": "hack-skills match ({n}) — AI will auto-load:"},
    "hackskills_auto_note": {"ko": "AI가 공격 상황에 맞게 자동 선택합니다. 수동 설치 불필요.",
                             "zh": "AI 将根据攻击情况自动选择，无需手动安装。",
                             "en": "AI auto-selects based on attack context. No manual install needed."},
    "hackskills_all_ready": {"ko": "hack-skills — {n}개 자동 활성화됨 (설치 불필요)",
                             "zh": "hack-skills — {n} 个已自动激活（无需安装）",
                             "en": "hack-skills — {n} ready (no install needed)"},
    "hackskills_auto_full": {"ko": "AI가 공격 상황에 맞게 자동 선택합니다. 수동 설치/활성화 불필요.",
                             "zh": "AI 将根据攻击情况自动选择，无需手动安装/激活。",
                             "en": "AI auto-selects based on attack context. No manual install/activation needed."},
    "skill_db_load_example":{"ko": "예) SKILL_LOAD: Exploitation  →  9개 Exploitation 스킬 전체 주입",
                             "zh": "例) SKILL_LOAD: Exploitation  →  注入全部 9 个 Exploitation 技能",
                             "en": "e.g. SKILL_LOAD: Exploitation  →  injects all 9 Exploitation skills"},
    # ── 실행 / 타이머 ───────────────────────────────────────────
    "countdown_remain":      {"ko": "⏱ {sec}s 남음...",
                              "zh": "⏱ 剩余 {sec}s...",
                              "en": "⏱ {sec}s remaining..."},
    "undo_hint":             {"ko": "/undo 1 — 1단계 전으로, /undo 3 — 3단계 전으로",
                              "zh": "/undo 1 — 返回1步，/undo 3 — 返回3步",
                              "en": "/undo 1 — go back 1 step, /undo 3 — go back 3 steps"},
    # ── 스킬 설치 ────────────────────────────────────────────────
    "skill_install_start":   {"ko": "📦 스킬 설치: {source}",
                              "zh": "📦 安装技能包: {source}",
                              "en": "📦 Installing skill: {source}"},
    "skill_already_installed":{"ko": "이미 설치됨: {name}",
                               "zh": "已安装: {name}",
                               "en": "Already installed: {name}"},
    "skill_install_ok":      {"ko": "✔ {name} 설치 완료 → {dst}",
                              "zh": "✔ {name} 安装完成 → {dst}",
                              "en": "✔ {name} installed → {dst}"},
    "skill_install_ok_local":{"ko": "✔ {name} 설치 완료",
                              "zh": "✔ {name} 安装完成",
                              "en": "✔ {name} installed"},
    "skill_clone_fail":      {"ko": "git clone 실패: {err}",
                              "zh": "git clone 失败: {err}",
                              "en": "git clone failed: {err}"},
    "skill_install_err":     {"ko": "오류: {err}",
                              "zh": "错误: {err}",
                              "en": "Error: {err}"},
    "skill_path_notfound":   {"ko": "경로 없음: {path}",
                              "zh": "路径不存在: {path}",
                              "en": "Path not found: {path}"},
    "skill_updating":        {"ko": "이미 설치됨: {name} — 업데이트 중...",
                              "zh": "已安装: {name} — 更新中...",
                              "en": "Already installed: {name} — updating..."},
    "skill_install_usage":   {"ko": "사용법:",
                              "zh": "用法:",
                              "en": "Usage:"},
    "skill_installed_count": {"ko": "설치된 스킬 팩: {n}개",
                              "zh": "已安装技能包: {n} 个",
                              "en": "Installed skill packs: {n}"},
    "skill_ref_count":       {"ko": "{n}개 레퍼런스",
                              "zh": "{n} 个引用",
                              "en": "{n} references"},
    # ── 네트워크 / VPN ──────────────────────────────────────────
    "vpn_on_banner":         {"ko": "🔒 VPN ON  출구IP: {ip}  {country}  (로컬: {local})",
                              "zh": "🔒 VPN 已连接  出口IP: {ip}  {country}  (本地: {local})",
                              "en": "🔒 VPN ON  Exit IP: {ip}  {country}  (local: {local})"},
    "vpn_off_banner":        {"ko": "🌐 공개IP: {ip}  {country}",
                              "zh": "🌐 公网IP: {ip}  {country}",
                              "en": "🌐 Public IP: {ip}  {country}"},
    "vpn_detected_scan":     {"ko": "🔒 VPN 감지: 출구 IP [{ip}] ({country})",
                              "zh": "🔒 检测到VPN: 出口IP [{ip}] ({country})",
                              "en": "🔒 VPN detected: Exit IP [{ip}] ({country})"},
    "vpn_ip_blocked":        {"ko": "⛔ 출구 IP 차단됨 — VPN 서버 변경 후 재시도 권장",
                              "zh": "⛔ 出口IP已被封锁 — 建议更换VPN服务器后重试",
                              "en": "⛔ Exit IP blocked — switch VPN server and retry"},
    # ── v3.5.17: macOS VPN DNS 스푸핑 — 실제 IP 자동 조회 (VPN 유지) ──
    # ★ "VPN 끄라"는 메시지 없음 — VPN 켜둔 채 대안 IP 조회 후 계속 진행
    "vpn_dns_spoof_warn":       {"ko": "⚠️  macOS VPN DNS 스푸핑 모드 (198.18.x.x) — 스캔 시 Google DNS로 실제 IP 자동 조회",
                                  "zh": "⚠️  macOS VPN DNS 欺骗模式 (198.18.x.x) — 扫描时将自动通过 Google DNS 获取真实IP",
                                  "en": "⚠️  macOS VPN DNS spoof mode (198.18.x.x) — real IP will be auto-resolved via Google DNS during scan"},
    "vpn_dns_spoof_exec":       {"ko": "🛑 [VPN DNS 스푸핑] 실행 결과에 198.18.x.x 가상 IP {count}개 감지 — 실제 IP 자동 조회 중",
                                  "zh": "🛑 [VPN DNS欺骗] 检测到 {count} 个 198.18.x.x 虚假IP — 正在自动获取真实IP",
                                  "en": "🛑 [VPN DNS Spoof] {count} virtual IPs detected — auto-resolving real IPs"},
    "vpn_dns_spoof_fixed":      {"ko": "🔍 [VPN DNS 스푸핑] 실제 IP 자동 획득: {ips} — 스캔 계속",
                                  "zh": "🔍 [VPN DNS欺骗] 已自动获取真实IP: {ips} — 继续扫描",
                                  "en": "🔍 [VPN DNS Spoof] Real IPs auto-resolved: {ips} — continuing scan"},
    "vpn_dns_spoof_fallback":   {"ko": "⚠️  [VPN DNS 스푸핑] Google DNS 자동 조회 실패 — AI가 Shodan/crt.sh 대안 방법 시도",
                                  "zh": "⚠️  [VPN DNS欺骗] Google DNS 自动解析失败 — AI 将尝试 Shodan/crt.sh 备用方法",
                                  "en": "⚠️  [VPN DNS Spoof] Auto-resolve failed — AI will try Shodan/crt.sh fallback"},
    "vpn_dns_spoof_inject_ok":  {"ko": "[VPN_DNS_SPOOF_AUTO_FIXED]\nVPN DNS 스푸핑 자동 감지 및 수정 완료.\n도메인 {target}의 실제 IP (Google DNS 8.8.8.8): {ips}\n\n이 실제 IP로 포트스캔과 침투테스트를 재실행하세요.\nVPN은 켜둔 채로 — 실제 IP로 직접 연결하면 DNS 스푸핑을 우회합니다.",
                                  "zh": "[VPN_DNS_SPOOF_AUTO_FIXED]\nVPN DNS 欺骗已自动检测并修正。\n域名 {target} 的真实 IP (通过 Google DNS 8.8.8.8 查询): {ips}\n\n请用这些真实 IP 重新执行端口扫描和渗透测试。\nVPN 保持开启 — 用真实 IP 直接发起连接即可绕过 DNS 欺骗。",
                                  "en": "[VPN_DNS_SPOOF_AUTO_FIXED]\nVPN DNS spoofing auto-detected and corrected.\nReal IP for {target} (via Google DNS 8.8.8.8): {ips}\n\nRe-run port scan and pentest using these real IPs.\nKeep VPN ON — connecting directly via real IP bypasses the DNS spoof."},
    "vpn_dns_spoof_inject_fail":{"ko": "[VPN_DNS_SPOOF_DETECTED]\nmacOS VPN DNS 스푸핑 (198.18.x.x) 감지.\nGoogle DNS (8.8.8.8)로 실제 IP 자동 조회 실패.\n\nVPN은 유지한 채 다음 대안 스크립트를 생성하세요:\n  1. Shodan API로 {target} 조회\n  2. crt.sh 인증서 투명성 조회\n  3. host -t A {target} 8.8.8.8",
                                  "zh": "[VPN_DNS_SPOOF_DETECTED]\n检测到 macOS VPN DNS 欺骗 (198.18.x.x)。\n尝试通过 Google DNS (8.8.8.8) 自动获取真实IP失败。\n\n请生成以下备用脚本来获取真实IP (VPN 保持开启):\n  1. 用 Shodan API 查询 {target}\n  2. 用 crt.sh 查证书透明度记录\n  3. 用 host -t A {target} 8.8.8.8",
                                  "en": "[VPN_DNS_SPOOF_DETECTED]\nmacOS VPN DNS spoof (198.18.x.x) detected.\nAuto-resolution via Google DNS (8.8.8.8) failed.\n\nGenerate fallback scripts to get real IPs (keep VPN ON):\n  1. Shodan API lookup for {target}\n  2. crt.sh certificate transparency lookup\n  3. host -t A {target} 8.8.8.8"},
    # ── 웹쉘 / Gnuboard5 ────────────────────────────────────────────
    "webshell_phase_start":  {"ko": "🐚 웹쉘 획득 단계 시작",
                              "zh": "🐚 开始 Webshell 获取阶段",
                              "en": "🐚 Webshell acquisition phase started"},
    "webshell_success":      {"ko": "✅ 웹쉘 획득 성공: {url}",
                              "zh": "✅ Webshell 获取成功: {url}",
                              "en": "✅ Webshell acquired: {url}"},
    "webshell_fail":         {"ko": "웹쉘 업로드 실패: {reason}",
                              "zh": "Webshell 上传失败: {reason}",
                              "en": "Webshell upload failed: {reason}"},
    "webshell_antsword":     {"ko": "🐜 AntSword 연결 설정:\n  URL: {url}\n  비밀번호: {pw}\n  인코더: default\n  디코더: default",
                              "zh": "🐜 AntSword 连接设置:\n  URL: {url}\n  密码: {pw}\n  编码器: default\n  解码器: default",
                              "en": "🐜 AntSword settings:\n  URL: {url}\n  Password: {pw}\n  Encoder: default\n  Decoder: default"},
    "gnuboard_found":        {"ko": "그누보드5 탐지: 관리자 패널 {path}",
                              "zh": "检测到 Gnuboard5: 管理员面板 {path}",
                              "en": "Gnuboard5 detected: admin panel at {path}"},
    "gnuboard_login_ok":     {"ko": "✅ 그누보드5 관리자 로그인: {id}/{pw}",
                              "zh": "✅ Gnuboard5 管理员登录成功: {id}/{pw}",
                              "en": "✅ Gnuboard5 admin login: {id}/{pw}"},
    "csrf_bypass_ok":        {"ko": "CSRF 이중 토큰 우회 성공 (세션키 + ajax.token.php)",
                              "zh": "CSRF 双令牌绕过成功 (Session key + ajax.token.php)",
                              "en": "CSRF dual-token bypass success (session key + ajax.token.php)"},
    "gif_polyglot_upload":   {"ko": "GIF polyglot PHP 업로드 중...",
                              "zh": "上传 GIF polyglot PHP...",
                              "en": "Uploading GIF polyglot PHP..."},
    "clean_shell_drop":      {"ko": "클린 PHP 쉘 드롭 완료 (GIF 헤더 오염 제거)",
                              "zh": "已落地纯净 PHP Shell（消除 GIF 头污染）",
                              "en": "Clean PHP shell dropped (GIF header pollution removed)"},
    "otp_leak_found":        {"ko": "⚠️ OTP/AUTH_KEY 노출 발견: {path}",
                              "zh": "⚠️ 发现 OTP/AUTH_KEY 泄露: {path}",
                              "en": "⚠️ OTP/AUTH_KEY leak found: {path}"},
    "antsword_prefix_note":  {"ko": "⚠️ AntSword가 파라미터에 \\x08\\x08 prefix 전송 — php://input 파싱으로 처리됨",
                              "zh": "⚠️ AntSword 发送 \\x08\\x08 前缀 — 已通过 php://input 解析处理",
                              "en": "⚠️ AntSword sends \\x08\\x08 prefix — handled via php://input parsing"},

    # ── /skill 명령어 UI ──────────────────────────────────────────
    "skill_col_name":        {"ko": "스킬명 (SKILL_LOAD)",
                              "zh": "技能名 (SKILL_LOAD)",
                              "en": "Skill Name (SKILL_LOAD)"},
    "skill_col_lines":       {"ko": "줄수", "zh": "行数", "en": "Lines"},
    "skill_secskills_ref":   {"ko": "SecSkills 레퍼런스", "zh": "SecSkills 参考", "en": "SecSkills References"},
    "skill_col_pack":        {"ko": "스킬 팩", "zh": "技能包", "en": "Skill Pack"},
    "skill_col_ref":         {"ko": "레퍼런스", "zh": "参考", "en": "Reference"},
    "skill_col_tag":         {"ko": "키워드", "zh": "关键词", "en": "Keywords"},
    "skill_already_builtin": {"ko": "⚡ {name} — 이미 내장됨 (설치 불필요)",
                              "zh": "⚡ {name} — 已内置（无需安装）",
                              "en": "⚡ {name} — already built-in (no install needed)"},
    "skill_not_found_tip":   {"ko": "❌ '{name}' 스킬 없음 — /skill 로 전체 목록 확인",
                              "zh": "❌ 未找到 '{name}' — 用 /skill 查看完整列表",
                              "en": "❌ '{name}' not found — use /skill to list all"},

    # ── 보고서 후 다음 단계 선택지 ────────────────────────────────
    "next_steps_after_report":  {"ko": "보고서 생성 완료 — 다음 단계를 선택하세요",
                                 "zh": "报告已生成 — 请选择下一步操作",
                                 "en": "Report generated — choose your next step"},
    "next_steps_prompt":     {"ko": "번호 입력 후 엔터 (0 = 종료, 그 외 = 직접 입력)",
                              "zh": "输入数字后回车（0=退出，其他=直接输入）",
                              "en": "Enter number + Enter (0 = exit, other = type freely)"},
    "next_steps_invalid":    {"ko": "잘못된 입력입니다. 1~{n} 사이 숫자를 입력하세요",
                              "zh": "输入无效，请输入 1~{n} 之间的数字",
                              "en": "Invalid input. Enter a number between 1 and {n}"},
    "next_steps_executing":  {"ko": "▶ 선택 {n}번 실행 중...",
                              "zh": "▶ 执行选项 {n}...",
                              "en": "▶ Executing option {n}..."},
    "next_steps_skipped":    {"ko": "선택지를 건너뜁니다.",
                              "zh": "跳过选项选择。",
                              "en": "Skipping next step selection."},

    # ── evidence_level 라벨 ──────────────────────────────────────
    "evidence_verified":     {"ko": "✅ 검증됨",  "zh": "✅ 已验证",  "en": "✅ Verified"},
    "evidence_likely":       {"ko": "🟡 가능성 높음", "zh": "🟡 可能",  "en": "🟡 Likely"},
    "evidence_inferred":     {"ko": "🔍 추론됨", "zh": "🔍 推断",   "en": "🔍 Inferred"},
    "evidence_ai":           {"ko": "🤖 AI 분석", "zh": "🤖 AI分析", "en": "🤖 AI Analysis"},

    # ── Zero-Hallucination 상태 메시지 ────────────────────────────
    "zh_system_label":       {"ko": "Zero-Hallucination 활성 — 모든 결과 증거 레벨 표시",
                              "zh": "Zero-Hallucination 已启用 — 所有结果标注置信度",
                              "en": "Zero-Hallucination active — all results labeled by evidence level"},
    "zh_finding_verified":   {"ko": "✅ VERIFIED 발견: {title}",
                              "zh": "✅ VERIFIED 发现: {title}",
                              "en": "✅ VERIFIED finding: {title}"},
    "zh_finding_inferred":   {"ko": "🔍 INFERRED 항목 (추가 조사 필요): {title}",
                              "zh": "🔍 INFERRED 项目（需进一步调查）: {title}",
                              "en": "🔍 INFERRED item (needs further investigation): {title}"},
    "zh_report_section_verified": {"ko": "검증된 취약점",
                                   "zh": "已验证漏洞",
                                   "en": "Verified Vulnerabilities"},
    "zh_report_section_inferred": {"ko": "추가 조사 필요 항목",
                                   "zh": "需进一步调查项目",
                                   "en": "Items Needing Further Investigation"},

    # ── IDOR 단계 메시지 ─────────────────────────────────────────
    "idor_phase_start":      {"ko": "🔍 IDOR/인증 우회 단계 시작",
                              "zh": "🔍 开始 IDOR/认证绕过阶段",
                              "en": "🔍 IDOR/Auth Bypass phase started"},
    "idor_hit_found":        {"ko": "🎯 IDOR 발견: {url} ({type})",
                              "zh": "🎯 发现 IDOR: {url} ({type})",
                              "en": "🎯 IDOR found: {url} ({type})"},
    "idor_pw_reset_ok":      {"ko": "✅ 비밀번호 재설정 성공 (IDOR): {user} → {pw}",
                              "zh": "✅ 密码重置成功 (IDOR): {user} → {pw}",
                              "en": "✅ Password reset via IDOR: {user} → {pw}"},
    "idor_login_verified":   {"ko": "✅ 로그인 검증 성공: {user}",
                              "zh": "✅ 登录验证成功: {user}",
                              "en": "✅ Login verified: {user}"},
    "idor_login_unverified": {"ko": "🟡 폼 제출 성공, 로그인 미확인 (수동 확인 필요)",
                              "zh": "🟡 表单提交成功，登录未确认（需手动验证）",
                              "en": "🟡 Form submitted, login unverified (manual check needed)"},

    # ── ACPV (클라이언트 사이드 인증 우회) ──────────────────────────────
    "acpv_phase_start":      {"ko": "🔐 ACPV: 클라이언트 사이드 인증 우회 스캔 시작",
                              "zh": "🔐 ACPV: 开始客户端认证绕过扫描",
                              "en": "🔐 ACPV: Client-side auth bypass scan started"},
    "acpv_js_collecting":    {"ko": "📄 JS 파일 수집 중... ({n}개 후보)",
                              "zh": "📄 正在收集 JS 文件... ({n} 个候选)",
                              "en": "📄 Collecting JS files... ({n} candidates)"},
    "acpv_pattern_found":    {"ko": "⚠ ACPV 패턴 발견 [{url}]: localStorage 키 {keys}",
                              "zh": "⚠ 发现 ACPV 模式 [{url}]: localStorage 键 {keys}",
                              "en": "⚠ ACPV pattern found [{url}]: localStorage keys {keys}"},
    "acpv_unauth_api":       {"ko": "🔴 무인증 API 접근: {url} ({size}B)",
                              "zh": "🔴 未授权 API 访问: {url} ({size}B)",
                              "en": "🔴 Unauthenticated API: {url} ({size}B)"},
    "acpv_response_manip":   {"ko": "🔧 응답 변조 포인트: {val}",
                              "zh": "🔧 响应篡改点: {val}",
                              "en": "🔧 Response manipulation point: {val}"},
    "acpv_no_finding":       {"ko": "✓ ACPV: 클라이언트 사이드 인증 우회 패턴 없음",
                              "zh": "✓ ACPV: 未发现客户端认证绕过模式",
                              "en": "✓ ACPV: No client-side auth bypass patterns found"},
    "acpv_summary":          {"ko": "🔐 ACPV 결과: 발견 {n}개 | 무인증 API {api}개 | 심각도: {sev}",
                              "zh": "🔐 ACPV 结果: 发现 {n} 项 | 未授权 API {api} 个 | 严重性: {sev}",
                              "en": "🔐 ACPV result: {n} findings | {api} unauth APIs | severity: {sev}"},
    "acpv_storage_bypass":   {"ko": "🔑 Storage 기반 인증 우회 가능 — 브라우저 콘솔 PoC 생성됨",
                              "zh": "🔑 可绕过 Storage 认证 — 已生成浏览器控制台 PoC",
                              "en": "🔑 Storage-based auth bypass possible — browser console PoC generated"},
    "acpv_poc_title":        {"ko": "=== ACPV PoC (클라이언트 사이드 인증 우회) ===",
                              "zh": "=== ACPV PoC（客户端认证绕过）===",
                              "en": "=== ACPV PoC (Client-side Auth Bypass) ==="},
    "acpv_burp_hint":        {"ko": "Burp Suite Match & Replace: 응답 본문에서 값 반전으로 권한 우회",
                              "zh": "Burp Suite Match & Replace: 在响应体中反转值以绕过权限",
                              "en": "Burp Suite Match & Replace: flip values in response body to bypass auth"},
    "acpv_auto_trigger":     {"ko": "🤖 AI 판단: JS 기반 앱 감지 → ACPV 스캔 자동 활성화",
                              "zh": "🤖 AI 判断: 检测到 JS 应用 → 自动启用 ACPV 扫描",
                              "en": "🤖 AI decision: JS-based app detected → ACPV scan auto-activated"},

    # ── API Discovery & AI Fuzzing ─────────────────────────────────────────
    "apid_phase_start":      {"ko": "🔍 API Discovery: Swagger/OpenAPI 문서 탐색 시작",
                              "zh": "🔍 API Discovery: 开始扫描 Swagger/OpenAPI 文档",
                              "en": "🔍 API Discovery: scanning for Swagger/OpenAPI docs"},
    "apid_doc_found":        {"ko": "📄 API 문서 발견 [{type}]: {url} ({n}개 엔드포인트)",
                              "zh": "📄 发现 API 文档 [{type}]: {url} ({n} 个端点)",
                              "en": "📄 API doc found [{type}]: {url} ({n} endpoints)"},
    "apid_no_doc":           {"ko": "✓ API Discovery: 공개 API 문서 없음",
                              "zh": "✓ API Discovery: 未发现公开 API 文档",
                              "en": "✓ API Discovery: no public API docs found"},
    "apid_interesting":      {"ko": "⚠ 민감 경로 발견: {paths}",
                              "zh": "⚠ 发现敏感路径: {paths}",
                              "en": "⚠ Interesting paths found: {paths}"},
    "apid_auto_trigger":     {"ko": "🤖 AI 판단: API 엔드포인트 존재 → API Fuzzing 자동 시작",
                              "zh": "🤖 AI 判断: 检测到 API 端点 → 自动启动 API Fuzzing",
                              "en": "🤖 AI decision: API endpoints found → auto-starting API fuzzing"},
    "apifuzz_phase_start":   {"ko": "🎯 API Fuzzing: {n}개 엔드포인트 자동 테스트 시작",
                              "zh": "🎯 API Fuzzing: 开始自动测试 {n} 个端点",
                              "en": "🎯 API Fuzzing: auto-testing {n} endpoints"},
    "apifuzz_unauth":        {"ko": "🔴 무인증 API 접근: {url} (HTTP {code}, {size}B)",
                              "zh": "🔴 未授权 API 访问: {url} (HTTP {code}, {size}B)",
                              "en": "🔴 Unauthenticated API: {url} (HTTP {code}, {size}B)"},
    "apifuzz_sensitive":     {"ko": "🔴 민감 정보 노출: {url} → 키워드: {keys}",
                              "zh": "🔴 敏感信息泄露: {url} → 关键词: {keys}",
                              "en": "🔴 Sensitive data exposed: {url} → keywords: {keys}"},
    "apifuzz_error":         {"ko": "⚠ 서버 오류 유발: {url} (HTTP 500) → 인젝션 가능성",
                              "zh": "⚠ 触发服务器错误: {url} (HTTP 500) → 可能存在注入",
                              "en": "⚠ Server error triggered: {url} (HTTP 500) → possible injection"},
    "apifuzz_summary":       {"ko": "🎯 API Fuzzing 결과: 테스트 {n}개 | 무인증 {ua}개 | 발견 {f}개 | 심각도: {sev}",
                              "zh": "🎯 API Fuzzing 结果: 测试 {n} 个 | 未授权 {ua} 个 | 发现 {f} 个 | 严重性: {sev}",
                              "en": "🎯 API Fuzzing: tested {n} | unauth {ua} | findings {f} | severity: {sev}"},
    "apifuzz_no_finding":    {"ko": "✓ API Fuzzing: 취약점 없음",
                              "zh": "✓ API Fuzzing: 未发现漏洞",
                              "en": "✓ API Fuzzing: no vulnerabilities found"},

    # ── MSSQL 2025 AI Feature Exploitation ────────────────────────────────
    "mssql2025_scan_start":  {"ko": "🤖 AI 판단: MSSQL 감지 → SQL Server 2025 AI 기능 악용 스캔 시작",
                              "zh": "🤖 AI 判断: 检测到 MSSQL → 开始扫描 SQL Server 2025 AI 特性",
                              "en": "🤖 AI decision: MSSQL detected → scanning for SQL Server 2025 AI features"},
    "mssql2025_version":     {"ko": "🗄 SQL Server 버전 확인: {ver}",
                              "zh": "🗄 SQL Server 版本: {ver}",
                              "en": "🗄 SQL Server version: {ver}"},
    "mssql2025_not_2025":    {"ko": "✓ SQL Server {ver} — 2025 AI 기능 없음 (스킵)",
                              "zh": "✓ SQL Server {ver} — 无 2025 AI 特性 (跳过)",
                              "en": "✓ SQL Server {ver} — no 2025 AI features (skip)"},
    "mssql2025_detected":    {"ko": "🚨 SQL Server 2025 확인! AI 기능 악용 가능성 높음",
                              "zh": "🚨 确认 SQL Server 2025！高风险 AI 特性可利用",
                              "en": "🚨 SQL Server 2025 confirmed! AI feature exploitation possible"},
    "mssql2025_stacked":     {"ko": "✅ Stacked Query 실행 가능 (지연 {delay:.1f}s)",
                              "zh": "✅ Stacked Query 可执行 (延迟 {delay:.1f}s)",
                              "en": "✅ Stacked query execution confirmed (delay {delay:.1f}s)"},
    "mssql2025_no_stacked":  {"ko": "✗ Stacked Query 불가 — AI 기능 악용 중단",
                              "zh": "✗ Stacked Query 不可用 — 停止 AI 特性利用",
                              "en": "✗ Stacked query not possible — AI exploitation skipped"},
    "mssql2025_priv":        {"ko": "🔑 DB 권한 확인: {role}",
                              "zh": "🔑 DB 权限确认: {role}",
                              "en": "🔑 DB privilege confirmed: {role}"},
    "mssql2025_rest_avail":  {"ko": "🌐 sp_invoke_external_rest_endpoint 활성화됨 — 외부 데이터 전송 가능",
                              "zh": "🌐 sp_invoke_external_rest_endpoint 已启用 — 可向外部传输数据",
                              "en": "🌐 sp_invoke_external_rest_endpoint enabled — external data exfil possible"},
    "mssql2025_poc_ready":   {"ko": "💥 SQL Server 2025 PoC {n}개 생성 완료 (보고서에 포함됨)",
                              "zh": "💥 已生成 {n} 个 SQL Server 2025 PoC（已包含在报告中）",
                              "en": "💥 {n} SQL Server 2025 PoC payloads ready (included in report)"},
    "mssql2025_summary":     {"ko": "🗄 MSSQL 2025 결과: {n}개 발견 | 권한: {priv} | 심각도: {sev}",
                              "zh": "🗄 MSSQL 2025 结果: {n} 项发现 | 权限: {priv} | 严重性: {sev}",
                              "en": "🗄 MSSQL 2025: {n} findings | privilege: {priv} | severity: {sev}"},
    "mssql2025_no_finding":  {"ko": "✓ MSSQL 2025: AI 기능 악용 가능성 없음",
                              "zh": "✓ MSSQL 2025: 无 AI 特性可利用",
                              "en": "✓ MSSQL 2025: no AI feature exploitation possible"},
    "mssql2025_auto_skip":   {"ko": "💡 MSSQL 미감지 또는 조건 미충족 — MSSQL 2025 스캔 스킵",
                              "zh": "💡 未检测到 MSSQL 或条件不满足 — 跳过 MSSQL 2025 扫描",
                              "en": "💡 MSSQL not detected or conditions not met — MSSQL 2025 scan skipped"},

    # ── ArubaOS XXE → OOB SSRF ────────────────────────────────────────────
    "aruba_scan_start":      {"ko": "🤖 AI 판단: 포트 32000 감지 → ArubaOS XXE/SSRF 스캔 자동 활성화",
                              "zh": "🤖 AI 判断: 检测到端口 32000 → 自动启动 ArubaOS XXE/SSRF 扫描",
                              "en": "🤖 AI decision: port 32000 detected → ArubaOS XXE/SSRF scan activated"},
    "aruba_port_open":       {"ko": "🔌 포트 32000/TCP 열림 — Aruba XML API 접근 가능",
                              "zh": "🔌 端口 32000/TCP 开放 — Aruba XML API 可访问",
                              "en": "🔌 Port 32000/TCP open — Aruba XML API accessible"},
    "aruba_banner":          {"ko": "🚨 ArubaOS 배너 확인! Pre-Auth XXE 테스트 시작",
                              "zh": "🚨 确认 ArubaOS 横幅！开始 Pre-Auth XXE 测试",
                              "en": "🚨 ArubaOS banner confirmed! Starting Pre-Auth XXE test"},
    "aruba_xxe_confirmed":   {"ko": "💥 XXE OOB SSRF 확인! 컨트롤러가 공격자 서버로 연결함 ({addr})",
                              "zh": "💥 XXE OOB SSRF 已确认！控制器连接到攻击者服务器 ({addr})",
                              "en": "💥 XXE OOB SSRF confirmed! Controller connected to attacker ({addr})"},
    "aruba_xxe_timing":      {"ko": "⚠ XXE 타이밍 이상 — 외부 연결 시도 가능성 (LIKELY)",
                              "zh": "⚠ XXE 时序异常 — 可能尝试外部连接 (LIKELY)",
                              "en": "⚠ XXE timing anomaly — possible external connection attempt (LIKELY)"},
    "aruba_ssrf_port":       {"ko": "🔴 SSRF 내부 포트 확인: {ports}",
                              "zh": "🔴 SSRF 内部端口已确认: {ports}",
                              "en": "🔴 SSRF internal ports confirmed: {ports}"},
    "aruba_no_finding":      {"ko": "✓ ArubaOS: 포트 32000 미감지 또는 취약점 없음",
                              "zh": "✓ ArubaOS: 未检测到端口 32000 或无漏洞",
                              "en": "✓ ArubaOS: port 32000 not detected or no vulnerability found"},
    "aruba_summary":         {"ko": "🌐 ArubaOS XXE 결과: {n}개 발견 | 내부 포트 {ports} | 심각도: {sev}",
                              "zh": "🌐 ArubaOS XXE 结果: {n} 项发现 | 内部端口 {ports} | 严重性: {sev}",
                              "en": "🌐 ArubaOS XXE: {n} findings | internal ports {ports} | severity: {sev}"},
    "aruba_poc_ready":       {"ko": "💥 ArubaOS PoC curl 명령 생성 완료 (보고서에 포함됨)",
                              "zh": "💥 ArubaOS PoC curl 命令已生成（已包含在报告中）",
                              "en": "💥 ArubaOS PoC curl command ready (included in report)"},
    "aruba_auto_skip":       {"ko": "💡 포트 32000 미감지 — ArubaOS XXE 스캔 스킵",
                              "zh": "💡 未检测到端口 32000 — 跳过 ArubaOS XXE 扫描",
                              "en": "💡 Port 32000 not found — ArubaOS XXE scan skipped"},

    # ── Ivanti Sentry CVE-2026-10520 Pre-Auth RCE ─────────────────────────
    "ivanti_scan_start":     {"ko": "🤖 AI 판단: Ivanti Sentry 감지 → CVE-2026-10520 Pre-Auth RCE 스캔 자동 활성화",
                              "zh": "🤖 AI 判断: 检测到 Ivanti Sentry → 自动启动 CVE-2026-10520 Pre-Auth RCE 扫描",
                              "en": "🤖 AI decision: Ivanti Sentry detected → CVE-2026-10520 Pre-Auth RCE scan activated"},
    "ivanti_product":        {"ko": "🏢 Ivanti Sentry 제품 확인 (/mics/login.jsp 존재)",
                              "zh": "🏢 确认 Ivanti Sentry 产品 (/mics/login.jsp 存在)",
                              "en": "🏢 Ivanti Sentry product confirmed (/mics/login.jsp exists)"},
    "ivanti_endpoint":       {"ko": "🔓 취약 엔드포인트 인증 없이 접근 가능 — 미패치 버전",
                              "zh": "🔓 漏洞端点无需认证即可访问 — 未打补丁版本",
                              "en": "🔓 Vulnerable endpoint accessible without authentication — unpatched version"},
    "ivanti_patched":        {"ko": "✓ 취약 엔드포인트 302 리다이렉트 — 패치된 버전",
                              "zh": "✓ 漏洞端点返回 302 重定向 — 已打补丁版本",
                              "en": "✓ Vulnerable endpoint returns 302 redirect — patched version"},
    "ivanti_rce":            {"ko": "💥 CVE-2026-10520 RCE 확인! 명령 실행 결과: {output}",
                              "zh": "💥 CVE-2026-10520 RCE 已确认！命令执行结果: {output}",
                              "en": "💥 CVE-2026-10520 RCE confirmed! Command output: {output}"},
    "ivanti_version":        {"ko": "🔖 Ivanti Sentry 버전: {ver}",
                              "zh": "🔖 Ivanti Sentry 版本: {ver}",
                              "en": "🔖 Ivanti Sentry version: {ver}"},
    "ivanti_poc_ready":      {"ko": "💥 Ivanti Sentry RCE PoC 생성 완료 (보고서에 포함됨)",
                              "zh": "💥 Ivanti Sentry RCE PoC 已生成（已包含在报告中）",
                              "en": "💥 Ivanti Sentry RCE PoC ready (included in report)"},
    "ivanti_summary":        {"ko": "🏢 Ivanti Sentry 결과: {n}개 발견 | 사용자: {user} | OS: {os} | 심각도: {sev}",
                              "zh": "🏢 Ivanti Sentry 结果: {n} 项发现 | 用户: {user} | OS: {os} | 严重性: {sev}",
                              "en": "🏢 Ivanti Sentry: {n} findings | user: {user} | OS: {os} | severity: {sev}"},
    "ivanti_no_finding":     {"ko": "✓ Ivanti Sentry: CVE-2026-10520 취약점 없음 (패치됨 또는 제품 미감지)",
                              "zh": "✓ Ivanti Sentry: CVE-2026-10520 无漏洞 (已打补丁或未检测到产品)",
                              "en": "✓ Ivanti Sentry: CVE-2026-10520 not vulnerable (patched or product not detected)"},
    "ivanti_auto_skip":      {"ko": "💡 Ivanti Sentry 미감지 — CVE-2026-10520 스캔 스킵",
                              "zh": "💡 未检测到 Ivanti Sentry — 跳过 CVE-2026-10520 扫描",
                              "en": "💡 Ivanti Sentry not detected — CVE-2026-10520 scan skipped"},

    # ── OAuth Chain Attack (Pattern A + B) ───────────────────────────────────
    "oauth_metadata":            {"ko": "📋 OAuth 서버 메타데이터 노출: {url}",
                                  "zh": "📋 OAuth 服务器元数据已暴露: {url}",
                                  "en": "📋 OAuth server metadata exposed: {url}"},
    "oauth_open_reg":            {"ko": "🔓 인증 없이 OAuth 클라이언트 등록 가능! client_id: {cid}",
                                  "zh": "🔓 无需认证即可注册 OAuth 客户端！client_id: {cid}",
                                  "en": "🔓 OAuth client registration without authentication! client_id: {cid}"},
    "oauth_auth_no_session":     {"ko": "💥 Authorization 엔드포인트 미인증 접근 → 인증코드 발급 확인!",
                                  "zh": "💥 Authorization 端点无需认证即可访问 → 已确认授权码发放！",
                                  "en": "💥 Authorization endpoint accessible without auth → code issued without session!"},
    "oauth_cors_wild":           {"ko": "⚠ CORS: * (wildcard) 발견 — OAuth 응답 크로스오리진 읽기 가능",
                                  "zh": "⚠ 发现 CORS: * (通配符) — OAuth 响应可跨域读取",
                                  "en": "⚠ CORS wildcard detected — OAuth responses readable cross-origin"},
    "oauth_unverified_email":    {"ko": "🚨 이메일 미검증 계정 생성 확인 — OAuth Provider인 경우 수백만 계정 탈취 가능",
                                  "zh": "🚨 未验证邮箱即可创建账户 — 若为 OAuth Provider，可接管数百万账户",
                                  "en": "🚨 Account created without email verification — mass ATO possible if OAuth provider"},
    "oauth_provider_found":      {"ko": "🌐 플랫폼이 OAuth Provider로 동작 확인",
                                  "zh": "🌐 确认平台作为 OAuth Provider 运行",
                                  "en": "🌐 Platform confirmed acting as OAuth provider"},
    "oauth_email_chain":         {"ko": "💥 Critical! OAuth 이메일 신뢰 체인 완성 — 연동된 모든 사이트 계정 탈취 가능",
                                  "zh": "💥 Critical！OAuth 邮箱信任链完成 — 可接管所有集成站点的账户",
                                  "en": "💥 Critical! OAuth email trust chain complete — all integrated sites vulnerable to ATO"},
    "oauth_chain_a_score":       {"ko": "🔗 패턴 A (등록체인) 스코어: {score}/5 | 패턴 B (이메일신뢰) 스코어: {bscore}/3",
                                  "zh": "🔗 模式 A（注册链）评分: {score}/5 | 模式 B（邮箱信任）评分: {bscore}/3",
                                  "en": "🔗 Pattern A (Registration Chain) score: {score}/5 | Pattern B (Email Trust) score: {bscore}/3"},
    "oauth_no_finding":          {"ko": "✓ OAuth: 취약점 없음 (메타데이터 미노출 또는 모두 패치됨)",
                                  "zh": "✓ OAuth: 无漏洞 (元数据未暴露或全部已修补)",
                                  "en": "✓ OAuth: no vulnerabilities found (metadata not exposed or all patched)"},
    # ── Next.js Cache Poisoning → 0-click SXSS ──────────────────────────────
    "nextjs_scan_start":     {"ko": "🤖 AI 판단: Next.js+캐시 레이어 감지 → 0-click SXSS 체인 스캔 자동 활성화",
                               "zh": "🤖 AI 判断: 检测到 Next.js+缓存层 → 自动启动 0-click SXSS 链式扫描",
                               "en": "🤖 AI decision: Next.js + cache layer detected → 0-click SXSS chain scan activated"},
    "nextjs_detected":       {"ko": "📦 Next.js 감지: {version} ({router})",
                               "zh": "📦 检测到 Next.js: {version} ({router})",
                               "en": "📦 Next.js detected: {version} ({router})"},
    "nextjs_cache_layer":    {"ko": "🗄 캐시 레이어 확인: {layer} — 캐시 포이즈닝 공격면 존재",
                               "zh": "🗄 确认缓存层: {layer} — 缓存投毒攻击面已确认",
                               "en": "🗄 Cache layer confirmed: {layer} — cache poisoning attack surface present"},
    "nextjs_header_reflect": {"ko": "💥 헤더 반영 확인! Content-Type 주입 가능 → RSC→HTML 컨텍스트 전환 가능",
                               "zh": "💥 确认响应头反射！可注入 Content-Type → RSC→HTML 上下文切换成功",
                               "en": "💥 Header reflection confirmed! Content-Type injectable → RSC→HTML context switch possible"},
    "nextjs_rsc_dynamic":    {"ko": "📄 동적 RSC 페이지 발견: {pages}",
                               "zh": "📄 发现动态 RSC 页面: {pages}",
                               "en": "📄 Dynamic RSC pages found: {pages}"},
    "nextjs_ct_inject":      {"ko": "💥 Content-Type 주입 성공! RSC가 text/html로 반환됨",
                               "zh": "💥 Content-Type 注入成功！RSC 以 text/html 返回",
                               "en": "💥 Content-Type injection confirmed! RSC served as text/html"},
    "nextjs_param_reflect":  {"ko": "💥 URL 파라미터 RSC body에 반영 확인! SXSS 페이로드 실행 가능",
                               "zh": "💥 URL 参数已在 RSC body 中反射！SXSS payload 可执行",
                               "en": "💥 URL parameter reflected in RSC body! SXSS payload will execute"},
    "nextjs_chain_full":     {"ko": "💥 CRITICAL! Next.js 0-click SXSS 체인 완성 — 피해자 방문만으로 XSS 실행",
                               "zh": "💥 CRITICAL！Next.js 0-click SXSS 链完成 — 受害者访问即触发 XSS",
                               "en": "💥 CRITICAL! Next.js 0-click SXSS chain complete — XSS fires on victim visit"},
    "nextjs_summary":        {"ko": "🌐 Next.js SXSS 결과: {n}개 발견 | 체인완성:{chain} | 심각도: {sev}",
                               "zh": "🌐 Next.js SXSS 结果: {n} 项发现 | 链完成:{chain} | 严重性: {sev}",
                               "en": "🌐 Next.js SXSS scan: {n} findings | chain complete:{chain} | severity: {sev}"},
    "nextjs_no_finding":     {"ko": "✓ Next.js SXSS: 취약 조건 미충족 (Next.js 미감지 또는 헤더 반영 없음)",
                               "zh": "✓ Next.js SXSS: 条件不满足（未检测到 Next.js 或无响应头反射）",
                               "en": "✓ Next.js SXSS: conditions not met (Next.js not detected or no header reflection)"},
    "nextjs_auto_skip":      {"ko": "💡 Next.js 미감지 — 0-click SXSS 스캔 스킵",
                               "zh": "💡 未检测到 Next.js — 跳过 0-click SXSS 扫描",
                               "en": "💡 Next.js not detected — 0-click SXSS scan skipped"},

    # ── CSWSH + EXE Exposure + Localhost WebSocket RCE ──────────────────────
    "cswsh_scan_start":     {"ko": "🤖 AI 판단: localhost WebSocket 패턴 감지 → CSWSH+RCE 체인 스캔 자동 활성화",
                              "zh": "🤖 AI 判断: 检测到 localhost WebSocket 模式 → 自动启动 CSWSH+RCE 链式扫描",
                              "en": "🤖 AI decision: localhost WebSocket pattern detected → CSWSH+RCE chain scan activated"},
    "cswsh_js_download":    {"ko": "📦 JS에서 EXE 다운로드 함수 발견: {snippet}",
                              "zh": "📦 在 JS 中发现 EXE 下载函数: {snippet}",
                              "en": "📦 EXE download function found in JS: {snippet}"},
    "cswsh_exe_exposed":    {"ko": "🔓 EXE 파일 미인증 다운로드 가능! URL: {url} ({size} bytes)",
                              "zh": "🔓 可在无需认证的情况下下载 EXE 文件！URL: {url} ({size} 字节)",
                              "en": "🔓 EXE file accessible without authentication! URL: {url} ({size} bytes)"},
    "cswsh_js_ws":          {"ko": "⚡ JS에서 localhost WebSocket 발견 — 포트: {ports}",
                              "zh": "⚡ 在 JS 中发现 localhost WebSocket — 端口: {ports}",
                              "en": "⚡ Localhost WebSocket found in JS — ports: {ports}"},
    "cswsh_port_open":      {"ko": "💥 WebSocket 포트 {port} 열려있음! CSWSH 공격 가능",
                              "zh": "💥 WebSocket 端口 {port} 开放！可发动 CSWSH 攻击",
                              "en": "💥 WebSocket port {port} is OPEN! CSWSH attack possible"},
    "cswsh_rce_chain":      {"ko": "💥 CSWSH→RCE 체인 완성! 피해자 방문만으로 제로클릭 코드 실행",
                              "zh": "💥 CSWSH→RCE 链完成！受害者访问即可实现零点击代码执行",
                              "en": "💥 CSWSH→RCE chain complete! Zero-click code execution on victim visit"},
    "cswsh_poc_ready":      {"ko": "💥 CSWSH PoC HTML 생성 완료 (보고서에 포함됨)",
                              "zh": "💥 CSWSH PoC HTML 已生成（已包含在报告中）",
                              "en": "💥 CSWSH PoC HTML ready (included in report)"},
    "cswsh_summary":        {"ko": "🔌 CSWSH 결과: {n}개 발견 | EXE노출:{exe} | WS포트:{ports} | 심각도: {sev}",
                              "zh": "🔌 CSWSH 结果: {n} 项发现 | EXE暴露:{exe} | WS端口:{ports} | 严重性: {sev}",
                              "en": "🔌 CSWSH scan: {n} findings | EXE exposed:{exe} | WS ports:{ports} | severity: {sev}"},
    "cswsh_no_finding":     {"ko": "✓ CSWSH: localhost WebSocket 패턴 없음 (데스크톱 앱 미감지)",
                              "zh": "✓ CSWSH: 未发现 localhost WebSocket 模式 (未检测到桌面应用)",
                              "en": "✓ CSWSH: no localhost WebSocket pattern found (desktop app not detected)"},
    "cswsh_auto_skip":      {"ko": "💡 localhost WebSocket 패턴 미감지 — CSWSH 스캔 스킵",
                              "zh": "💡 未检测到 localhost WebSocket 模式 — 跳过 CSWSH 扫描",
                              "en": "💡 No localhost WebSocket pattern detected — CSWSH scan skipped"},

    "oauth_auto_skip":           {"ko": "💡 OAuth 엔드포인트 미감지 — OAuth 체인 스캔 스킵",
                                  "zh": "💡 未检测到 OAuth 端点 — 跳过 OAuth 链式扫描",
                                  "en": "💡 OAuth endpoints not detected — OAuth chain scan skipped"},
    "oauth_poc_ready":           {"ko": "💥 OAuth 체인 PoC 생성 완료 (보고서에 포함됨)",
                                  "zh": "💥 OAuth 链式 PoC 已生成（已包含在报告中）",
                                  "en": "💥 OAuth chain PoC ready (included in report)"},

    # ── Redis DarkReplica CVE-2026-23631 ─────────────────────────────────────
    "redis_scan_start":         {"ko": "🤖 AI 판단: Redis 포트/키워드 감지 → CVE-2026-23631 DarkReplica UAF 스캔 자동 활성화",
                                  "zh": "🤖 AI 判断: 检测到 Redis 端口/关键字 → 自动启动 CVE-2026-23631 DarkReplica UAF 扫描",
                                  "en": "🤖 AI decision: Redis port/keyword detected → CVE-2026-23631 DarkReplica UAF scan activated"},
    "redis_found":              {"ko": "📦 Redis 서버 발견: {host}:{port}",
                                  "zh": "📦 发现 Redis 服务器: {host}:{port}",
                                  "en": "📦 Redis server found: {host}:{port}"},
    "redis_version":            {"ko": "🔎 Redis 버전: {version} — {status}",
                                  "zh": "🔎 Redis 版本: {version} — {status}",
                                  "en": "🔎 Redis version: {version} — {status}"},
    "redis_noauth":             {"ko": "💥 Redis 인증 없음! 직접 접근 가능 → CVE-2026-23631 완전 노출",
                                  "zh": "💥 Redis 无需认证！可直接访问 → CVE-2026-23631 完全暴露",
                                  "en": "💥 Redis requires NO authentication — CVE-2026-23631 fully exposed"},
    "redis_auth_cred":          {"ko": "🔑 Redis 인증 성공 (자격증명: {cred})",
                                  "zh": "🔑 Redis 认证成功（凭据: {cred}）",
                                  "en": "🔑 Redis authenticated (credential: {cred})"},
    "redis_slaveof_ok":         {"ko": "⚡ SLAVEOF 권한 확인 — 복제 제어 가능",
                                  "zh": "⚡ SLAVEOF 权限已确认 — 可控制复制",
                                  "en": "⚡ SLAVEOF permission confirmed — replication control possible"},
    "redis_function_ok":        {"ko": "⚡ FUNCTION 엔진 사용 가능 — Lua 함수 등록 가능",
                                  "zh": "⚡ FUNCTION 引擎可用 — 可注册 Lua 函数",
                                  "en": "⚡ Redis FUNCTION engine available — Lua function registration possible"},
    "redis_exploitable":        {"ko": "💥 CRITICAL! CVE-2026-23631 DarkReplica 완전 익스플로잇 가능 — Redis {version} UAF→RCE 체인 완성",
                                  "zh": "💥 CRITICAL！CVE-2026-23631 DarkReplica 完全可利用 — Redis {version} UAF→RCE 链完成",
                                  "en": "💥 CRITICAL! CVE-2026-23631 DarkReplica FULLY EXPLOITABLE — Redis {version} UAF→RCE chain confirmed"},
    "redis_likely":             {"ko": "⚠ CVE-2026-23631 LIKELY 취약 — 버전 취약 + 일부 권한 미확인",
                                  "zh": "⚠ CVE-2026-23631 LIKELY 可利用 — 版本脆弱 + 部分权限待确认",
                                  "en": "⚠ CVE-2026-23631 LIKELY exploitable — version vulnerable, some permissions unconfirmed"},
    "redis_summary":            {"ko": "🗄 Redis DarkReplica 결과: {n}개 발견 | 버전:{ver} | 익스플로잇:{exp} | 심각도:{sev}",
                                  "zh": "🗄 Redis DarkReplica 结果: {n} 项发现 | 版本:{ver} | 可利用:{exp} | 严重性:{sev}",
                                  "en": "🗄 Redis DarkReplica scan: {n} findings | version:{ver} | exploitable:{exp} | severity:{sev}"},
    "redis_no_finding":         {"ko": "✓ Redis DarkReplica: 취약 조건 미충족 (Redis 미감지 또는 패치된 버전)",
                                  "zh": "✓ Redis DarkReplica: 条件不满足（未检测到 Redis 或版本已修补）",
                                  "en": "✓ Redis DarkReplica: conditions not met (Redis not found or patched version)"},
    "redis_auto_skip":          {"ko": "💡 Redis 미감지 — DarkReplica 스캔 스킵",
                                  "zh": "💡 未检测到 Redis — 跳过 DarkReplica 扫描",
                                  "en": "💡 Redis not detected — DarkReplica scan skipped"},

    # ── HTML Injection + Chrome Autofill → CSP Bypass Password Steal ─────────
    "autofill_scan_start":      {"ko": "🤖 AI 판단: 로그인 페이지/HTML 반사 탐지 → Chrome 자동완성 비번탈취 스캔 자동 활성화",
                                  "zh": "🤖 AI 判断: 检测到登录页/HTML 反射 → 自动启动 Chrome 自动填充密码窃取扫描",
                                  "en": "🤖 AI decision: login page/HTML reflection detected → Chrome autofill password steal scan activated"},
    "autofill_csp_found":       {"ko": "🔒 CSP 감지: {csp}",
                                  "zh": "🔒 检测到 CSP: {csp}",
                                  "en": "🔒 CSP detected: {csp}"},
    "autofill_login_found":     {"ko": "📋 로그인 폼 발견 — 브라우저 자동완성 활성화 상태",
                                  "zh": "📋 发现登录表单 — 浏览器自动填充处于激活状态",
                                  "en": "📋 Login form found — browser password autofill active"},
    "autofill_injection_found": {"ko": "💥 HTML Injection 확인! 파라미터: {param} — Chrome 자동완성 악용 가능",
                                  "zh": "💥 确认 HTML 注入！参数: {param} — 可利用 Chrome 自动填充",
                                  "en": "💥 HTML injection confirmed! Parameter: {param} — Chrome autofill exploitable"},
    "autofill_csp_bypassed":    {"ko": "⚡ CSP script-src 차단 → JS 없이 HTML만으로 비번 탈취 가능 (CSP 우회)",
                                  "zh": "⚡ CSP script-src 已阻断 → 仅用 HTML 即可窃取密码（CSP 绕过）",
                                  "en": "⚡ CSP script-src blocked → password theft via HTML-only, no JS required (CSP bypass)"},
    "autofill_referrer_override":{"ko": "🔗 Referrer-Policy 오버라이드 가능 — <meta name=referrer content=unsafe-url> 주입으로 우회",
                                  "zh": "🔗 可覆盖 Referrer-Policy — 注入 <meta name=referrer content=unsafe-url> 绕过",
                                  "en": "🔗 Referrer-Policy can be overridden via injected <meta name=referrer content=unsafe-url>"},
    "autofill_exploitable":     {"ko": "💥 CRITICAL! HTML Injection + Chrome 자동완성 + Referer 탈취 체인 완성 — 1클릭 비번 탈취",
                                  "zh": "💥 CRITICAL！HTML 注入 + Chrome 自动填充 + Referer 泄露链完成 — 1次点击即可窃取密码",
                                  "en": "💥 CRITICAL! HTML injection + Chrome autofill + Referer exfil chain confirmed — 1-click password theft"},
    "autofill_likely":          {"ko": "⚠ LIKELY 취약 — 로그인 폼 존재, HTML Injection 확인 필요",
                                  "zh": "⚠ LIKELY 可利用 — 登录表单存在，需确认 HTML 注入",
                                  "en": "⚠ LIKELY exploitable — login form found, HTML injection confirmation needed"},
    "autofill_summary":         {"ko": "🔑 AutofillSteal 결과: {n}개 발견 | 로그인폼:{lf} | HTML주입:{hi} | 익스플로잇:{exp} | 심각도:{sev}",
                                  "zh": "🔑 AutofillSteal 结果: {n} 项发现 | 登录表单:{lf} | HTML注入:{hi} | 可利用:{exp} | 严重性:{sev}",
                                  "en": "🔑 AutofillSteal scan: {n} findings | login_form:{lf} | html_injection:{hi} | exploitable:{exp} | severity:{sev}"},
    "autofill_no_finding":      {"ko": "✓ AutofillSteal: 로그인 폼 미발견 또는 HTML 반사 없음",
                                  "zh": "✓ AutofillSteal: 未发现登录表单或无 HTML 反射",
                                  "en": "✓ AutofillSteal: no login form or HTML reflection found"},
    "autofill_auto_skip":       {"ko": "💡 로그인 페이지 미감지 — AutofillSteal 스캔 스킵",
                                  "zh": "💡 未检测到登录页面 — 跳过 AutofillSteal 扫描",
                                  "en": "💡 Login page not detected — AutofillSteal scan skipped"},

    # ── Web Cache Deception + SameSite Lax Bypass ──────────────────────────────
    "wcd_scan_start":           {"ko": "🤖 AI 판단: CDN/캐시 환경 감지 → Web Cache Deception + SameSite 우회 스캔 자동 활성화",
                                  "zh": "🤖 AI 判断: 检测到 CDN/缓存环境 → 自动启动 Web 缓存欺骗 + SameSite 绕过扫描",
                                  "en": "🤖 AI decision: CDN/cache env detected → Web Cache Deception + SameSite bypass scan activated"},
    "wcd_cache_header":         {"ko": "📦 캐시 헤더 감지: {header}: {value}",
                                  "zh": "📦 检测到缓存响应头: {header}: {value}",
                                  "en": "📦 Cache header detected: {header}: {value}"},
    "wcd_no_private":           {"ko": "⚠️  Cache-Control에 'private' 없음: '{cc}' — 공개 캐시 가능",
                                  "zh": "⚠️  Cache-Control 缺少 'private': '{cc}' — 可能被公开缓存",
                                  "en": "⚠️  Cache-Control missing 'private': '{cc}' — may be publicly cached"},
    "wcd_sensitive_in_cache":   {"ko": "🔑 캐시된 응답에 민감 데이터: {data}",
                                  "zh": "🔑 缓存响应中发现敏感数据: {data}",
                                  "en": "🔑 Sensitive data in cacheable response: {data}"},
    "wcd_confirmed":            {"ko": "✅ 캐시 MISS→HIT 확인: 실제 캐싱 동작 검증 완료",
                                  "zh": "✅ 缓存 MISS→HIT 确认: 实际缓存行为已验证",
                                  "en": "✅ Cache MISS→HIT confirmed: actual caching behavior verified"},
    "wcd_samesite":             {"ko": "🍪 SameSite={samesite} — top-level navigation(meta-refresh)으로 우회 가능",
                                  "zh": "🍪 SameSite={samesite} — 可通过 top-level navigation(meta-refresh)绕过",
                                  "en": "🍪 SameSite={samesite} — bypassable via top-level navigation (meta-refresh)"},
    "wcd_exploitable":          {"ko": "🚨 Web Cache Deception 완전 익스플로잇 가능! 캐시 + 민감데이터 + SameSite 우회 모두 확인",
                                  "zh": "🚨 Web 缓存欺骗完全可利用! 缓存 + 敏感数据 + SameSite 绕过均已确认",
                                  "en": "🚨 Web Cache Deception FULLY exploitable! Cache + sensitive data + SameSite bypass all confirmed"},
    "wcd_likely":               {"ko": "🟡 Web Cache Deception 가능성 높음 — 인증된 세션으로 추가 검증 필요",
                                  "zh": "🟡 Web 缓存欺骗可能性高 — 需使用认证会话进一步验证",
                                  "en": "🟡 Web Cache Deception likely — further verification with authenticated session needed"},
    "wcd_summary":              {"ko": "🧩 WCD 스캔: {n}건 발견 | 캐시가능:{c} | 민감데이터:{s} | 익스플로잇:{e} | 심각도:{sev}",
                                  "zh": "🧩 WCD 扫描: {n} 项发现 | 可缓存:{c} | 敏感数据:{s} | 可利用:{e} | 严重性:{sev}",
                                  "en": "🧩 WCD scan: {n} findings | cacheable:{c} | sensitive:{s} | exploitable:{e} | severity:{sev}"},
    "wcd_no_finding":           {"ko": "✓ WCD: Cache-Control private 설정 또는 민감 데이터 없음",
                                  "zh": "✓ WCD: Cache-Control 已设置 private 或无敏感数据",
                                  "en": "✓ WCD: Cache-Control private set or no sensitive data found"},
    "wcd_auto_skip":            {"ko": "💡 캐시 레이어 미감지 — WCD 스캔 스킵",
                                  "zh": "💡 未检测到缓存层 — 跳过 WCD 扫描",
                                  "en": "💡 No cache layer detected — WCD scan skipped"},

    # ── Cloud Token Recon (TLS SAN + JS Bundle + Unauthenticated Token) ───────
    "ctr_scan_start":           {"ko": "🤖 AI 판단: 클라우드/DevTool 환경 감지 → TLS SAN + JS 번들 + 클라우드 토큰 엔드포인트 스캔 자동 활성화",
                                  "zh": "🤖 AI 判断: 检测到云/DevTool 环境 → 自动启动 TLS SAN + JS Bundle + 云令牌端点扫描",
                                  "en": "🤖 AI decision: cloud/DevTool env detected → TLS SAN + JS bundle + cloud token endpoint scan activated"},
    "ctr_dev_tool":             {"ko": "⚠️  오픈 DevTool 발견: {tool} at {url} — 클라우드 체인의 첫 번째 홉",
                                  "zh": "⚠️  发现开放 DevTool: {tool} at {url} — 云凭证链第一跳",
                                  "en": "⚠️  Open DevTool detected: {tool} at {url} — first hop in cloud chain"},
    "ctr_tls_san":              {"ko": "🔍 TLS 와일드카드 SAN: {san} → 숨겨진 서브도메인 발굴 가능 (crt.sh)",
                                  "zh": "🔍 TLS 通配符 SAN: {san} → 可发现隐藏子域名 (crt.sh)",
                                  "en": "🔍 TLS wildcard SAN: {san} → shadow subdomains discoverable via crt.sh"},
    "ctr_js_domain":            {"ko": "📦 JS 번들에서 숨겨진 도메인 {n}개 발견: {domains}",
                                  "zh": "📦 JS Bundle 中发现 {n} 个隐藏域名: {domains}",
                                  "en": "📦 JS bundles revealed {n} hidden domain(s): {domains}"},
    "ctr_token_found":          {"ko": "🚨 비인증 클라우드 토큰 엔드포인트 발견! {url} → {type} ({preview})",
                                  "zh": "🚨 发现未认证云令牌端点! {url} → {type} ({preview})",
                                  "en": "🚨 Unauthenticated cloud token endpoint found! {url} → {type} ({preview})"},
    "ctr_shadow_token":         {"ko": "🚨 섀도우 도메인에서 토큰 발견! {url} — JS 번들에서 피벗",
                                  "zh": "🚨 在影子域名中发现令牌! {url} — 从 JS Bundle 进行了枢转",
                                  "en": "🚨 Token found on shadow domain! {url} — pivoted via JS bundle"},
    "ctr_chain_likely":         {"ko": "🟡 DevTool + 클라우드 환경 감지 → GCP/AWS Secret Manager → GitHub 토큰 체인 가능성 높음",
                                  "zh": "🟡 检测到 DevTool + 云环境 → GCP/AWS Secret Manager → GitHub 令牌链可能性高",
                                  "en": "🟡 DevTool + cloud env detected → GCP/AWS Secret Manager → GitHub token chain likely"},
    "ctr_summary":              {"ko": "🧩 CloudTokenRecon: {n}건 | DevTool:{dt} | 섀도우도메인:{sd} | 토큰노출:{te} | 홉:{hops} | 심각도:{sev}",
                                  "zh": "🧩 CloudTokenRecon: {n} 项 | DevTool:{dt} | 影子域名:{sd} | 令牌暴露:{te} | 跳数:{hops} | 严重性:{sev}",
                                  "en": "🧩 CloudTokenRecon: {n} findings | dev_tool:{dt} | shadow_domains:{sd} | tokens:{te} | hops:{hops} | severity:{sev}"},
    "ctr_no_finding":           {"ko": "✓ CloudTokenRecon: 오픈 DevTool 또는 클라우드 토큰 노출 없음",
                                  "zh": "✓ CloudTokenRecon: 未发现开放 DevTool 或云令牌暴露",
                                  "en": "✓ CloudTokenRecon: no open DevTool or cloud token exposure found"},
    "ctr_auto_skip":            {"ko": "💡 클라우드/DevTool 환경 미감지 — CloudTokenRecon 스캔 스킵",
                                  "zh": "💡 未检测到云/DevTool 环境 — 跳过 CloudTokenRecon 扫描",
                                  "en": "💡 No cloud/DevTool env detected — CloudTokenRecon scan skipped"},

    # ── Advanced SQLi Exploit (EXTRACTVALUE error-based + Second-Order) ──────
    "asqli_scan_start":         {"ko": "🤖 AI 판단: SQL 인젝션 환경 감지 → EXTRACTVALUE 에러 기반 + Second-Order SQLi 고급 스캔 자동 활성화",
                                  "zh": "🤖 AI 判断: 检测到 SQL 注入环境 → 自动启用 EXTRACTVALUE 错误型 + 二阶 SQLi 高级扫描",
                                  "en": "🤖 AI decision: SQLi env detected → EXTRACTVALUE error-based + second-order SQLi advanced scan activated"},
    "asqli_extractvalue_hit":   {"ko": "🚨 EXTRACTVALUE 에러 기반 SQLi 확인! {url} [{param}] → 추출 데이터: {data}",
                                  "zh": "🚨 EXTRACTVALUE 错误型 SQLi 确认! {url} [{param}] → 提取数据: {data}",
                                  "en": "🚨 EXTRACTVALUE error-based SQLi confirmed! {url} [{param}] → extracted: {data}"},
    "asqli_time_hit":           {"ko": "⏱️ Time-based blind SQLi 확인! {url} [{param}] 지연: {delay}s (DB: {db})",
                                  "zh": "⏱️ 基于时间的盲注确认! {url} [{param}] 延迟: {delay}s (DB: {db})",
                                  "en": "⏱️ Time-based blind SQLi confirmed! {url} [{param}] delay: {delay}s (DB: {db})"},
    "asqli_second_order":       {"ko": "⚠️  Second-Order SQLi 잠재 컨텍스트 발견! 비동기 처리: {ctx} — 저장 후 지연 테스트 권장",
                                  "zh": "⚠️  发现二阶 SQLi 潜在上下文! 异步处理: {ctx} — 建议存储后延迟测试",
                                  "en": "⚠️  Second-order SQLi async context found! Deferred contexts: {ctx} — store+trigger test recommended"},
    "asqli_version":            {"ko": "📌 DB 버전 추출: {ver}",
                                  "zh": "📌 提取 DB 版本: {ver}",
                                  "en": "📌 DB version extracted: {ver}"},
    "asqli_database":           {"ko": "📌 현재 DB명 추출: {db}",
                                  "zh": "📌 提取当前数据库名: {db}",
                                  "en": "📌 Current database extracted: {db}"},
    "asqli_creds":              {"ko": "🔑 DB 크리덴셜 추출 성공! {creds}",
                                  "zh": "🔑 数据库凭证提取成功! {creds}",
                                  "en": "🔑 DB credentials extracted! {creds}"},
    "asqli_summary":            {"ko": "🧩 AdvancedSQLi: {n}건 | EXTRACTVALUE:{ev} | TimeBased:{tb} | SecondOrder:{so} | 크리덴셜:{cr} | 심각도:{sev}",
                                  "zh": "🧩 AdvancedSQLi: {n} 项 | EXTRACTVALUE:{ev} | 时间盲注:{tb} | 二阶:{so} | 凭证:{cr} | 严重性:{sev}",
                                  "en": "🧩 AdvancedSQLi: {n} findings | extractvalue:{ev} | time_based:{tb} | second_order:{so} | creds:{cr} | severity:{sev}"},
    "asqli_no_finding":         {"ko": "✓ AdvancedSQLi: EXTRACTVALUE / Second-Order 취약점 없음",
                                  "zh": "✓ AdvancedSQLi: 未发现 EXTRACTVALUE / 二阶 SQLi 漏洞",
                                  "en": "✓ AdvancedSQLi: no EXTRACTVALUE or second-order SQLi found"},
    "asqli_auto_skip":          {"ko": "💡 SQLi 컨텍스트 미감지 — AdvancedSQLi 스캔 스킵",
                                  "zh": "💡 未检测到 SQLi 上下文 — 跳过 AdvancedSQLi 扫描",
                                  "en": "💡 No SQLi context detected — AdvancedSQLi scan skipped"},

    # ── Copy Fail LPE — CVE-2026-31431 (algif_aead kernel LPE + container escape) ──
    "copyfail_scan_start":      {"ko": "🤖 AI 판단: 리눅스 서버 + post-RCE 컨텍스트 감지 → CVE-2026-31431 커널 LPE 취약점 자동 스캔 활성화",
                                  "zh": "🤖 AI 判断: 检测到 Linux 服务器 + post-RCE 上下文 → 自动启用 CVE-2026-31431 内核 LPE 漏洞扫描",
                                  "en": "🤖 AI decision: Linux server + post-RCE context detected → CVE-2026-31431 kernel LPE scan activated"},
    "copyfail_kernel_leak":     {"ko": "🔍 커널 버전 노출: {kver} — CVE-2026-31431 취약 범위 확인 필요",
                                  "zh": "🔍 内核版本泄露: {kver} — 需确认是否在 CVE-2026-31431 漏洞范围内",
                                  "en": "🔍 Kernel version leaked: {kver} — verify if in CVE-2026-31431 vulnerable range"},
    "copyfail_kernel_vuln":     {"ko": "🚨 커널 {kver} — CVE-2026-31431 취약 범위 확인! AF_ALG + authencesn → 4바이트 페이지 캐시 쓰기 → root 권한 상승",
                                  "zh": "🚨 内核 {kver} — 确认在 CVE-2026-31431 漏洞范围! AF_ALG + authencesn → 4字节页缓存写入 → root 提权",
                                  "en": "🚨 Kernel {kver} — CVE-2026-31431 confirmed vulnerable! AF_ALG+authencesn → 4-byte page cache write → root LPE"},
    "copyfail_algif_loaded":    {"ko": "🔴 algif_aead 모듈 로드 확인! 732바이트 Python PoC 즉시 실행 가능 (root 획득)",
                                  "zh": "🔴 确认加载 algif_aead 模块! 732字节 Python PoC 可立即执行 (获取 root)",
                                  "en": "🔴 algif_aead module loaded! 732-byte Python PoC can execute immediately (root)"},
    "copyfail_container_escape":{"ko": "🔴 컨테이너/K8s 환경 감지 — 페이지 캐시 호스트 전역 공유 → 컨테이너 탈출 → 노드 root 가능",
                                  "zh": "🔴 检测到容器/K8s 环境 — 页缓存全主机共享 → 容器逃逸 → 节点 root 可能",
                                  "en": "🔴 Container/K8s env detected — page cache is host-wide → container escape → node root possible"},
    "copyfail_lpe_confirmed":   {"ko": "☠️  LPE 경로 완전 확인: 취약 커널 + algif_aead 로드 + 웹쉘 실행 가능 → root 권한 상승 즉시 가능",
                                  "zh": "☠️  LPE 路径完全确认: 漏洞内核 + algif_aead 已加载 + webshell 可执行 → 可立即提权至 root",
                                  "en": "☠️  LPE path fully confirmed: vuln kernel + algif_aead loaded + webshell exec → immediate root escalation"},
    "copyfail_summary":         {"ko": "CopyFail LPE 스캔 완료: {count}개 발견 | 커널:{kver} | LPE확인:{lpe} | 컨테이너탈출:{escape}",
                                  "zh": "CopyFail LPE 扫描完成: 发现 {count} 个 | 内核:{kver} | LPE确认:{lpe} | 容器逃逸:{escape}",
                                  "en": "CopyFail LPE scan complete: {count} findings | kernel:{kver} | lpe_confirmed:{lpe} | container_escape:{escape}"},
    "copyfail_no_finding":      {"ko": "✓ CopyFailLPE: CVE-2026-31431 취약점 미감지 (커널 버전 확인 불가 또는 패치됨)",
                                  "zh": "✓ CopyFailLPE: 未检测到 CVE-2026-31431 漏洞 (内核版本不可知或已修补)",
                                  "en": "✓ CopyFailLPE: CVE-2026-31431 not detected (kernel version unknown or patched)"},
    "copyfail_auto_skip":       {"ko": "💡 Linux 서버 컨텍스트 미감지 — CopyFailLPE 스캔 스킵",
                                  "zh": "💡 未检测到 Linux 服务器上下文 — 跳过 CopyFailLPE 扫描",
                                  "en": "💡 No Linux server context detected — CopyFailLPE scan skipped"},

    # ── Ruby LibAFL Fuzz Surface Detection (Ruzzy+LibAFL attack surface mapper) ──
    "ruby_fuzz_scan_start":     {"ko": "🤖 AI 판단: Ruby 웹 프레임워크 감지 → Ruzzy+LibAFL C 확장 파서 퍼징 표면 자동 스캔 활성화",
                                  "zh": "🤖 AI 判断: 检测到 Ruby Web 框架 → 自动启用 Ruzzy+LibAFL C 扩展解析器模糊测试面扫描",
                                  "en": "🤖 AI decision: Ruby web framework detected → Ruzzy+LibAFL C extension parser fuzz surface scan activated"},
    "ruby_fuzz_framework":      {"ko": "🔍 Ruby 프레임워크 확인: {fw} — Rails/Sinatra/Rack 계열 C 확장 파서 표면 존재",
                                  "zh": "🔍 确认 Ruby 框架: {fw} — Rails/Sinatra/Rack 系 C 扩展解析器攻击面存在",
                                  "en": "🔍 Ruby framework confirmed: {fw} — Rails/Sinatra/Rack C extension parser attack surface present"},
    "ruby_fuzz_c_ext_found":    {"ko": "🎯 C 확장 파서 엔드포인트 발견: {cext} ({url}) — Ruzzy+LibAFL 퍼징 HIGH VALUE 타겟",
                                  "zh": "🎯 发现 C 扩展解析器端点: {cext} ({url}) — Ruzzy+LibAFL 模糊测试高价值目标",
                                  "en": "🎯 C extension parser endpoint found: {cext} ({url}) — HIGH VALUE Ruzzy+LibAFL fuzzing target"},
    "ruby_fuzz_graphql":        {"ko": "🔴 GraphQL 엔드포인트 확인: {url} — graphql-ruby libgraphqlparser C 확장 → 퍼징 최우선 타겟",
                                  "zh": "🔴 确认 GraphQL 端点: {url} — graphql-ruby libgraphqlparser C 扩展 → 最高优先模糊测试目标",
                                  "en": "🔴 GraphQL endpoint confirmed: {url} — graphql-ruby libgraphqlparser C ext → top fuzzing priority"},
    "ruby_fuzz_yaml_risk":      {"ko": "⚠️  YAML 엔드포인트 감지 — Psych.load (unsafe) Ruby 객체 역직렬화 위험. YAML.safe_load 사용 확인 필요",
                                  "zh": "⚠️  检测到 YAML 端点 — Psych.load (不安全) Ruby 对象反序列化风险. 需确认使用 YAML.safe_load",
                                  "en": "⚠️  YAML endpoint detected — Psych.load (unsafe) Ruby object deserialization risk. Verify YAML.safe_load usage"},
    "ruby_fuzz_upload":         {"ko": "📎 파일 업로드 엔드포인트 발견: {url} — RMagick/MiniMagick C 확장 파이프라인 퍼징 표면",
                                  "zh": "📎 发现文件上传端点: {url} — RMagick/MiniMagick C 扩展管道模糊测试面",
                                  "en": "📎 File upload endpoint found: {url} — RMagick/MiniMagick C extension pipeline fuzz surface"},
    "ruby_fuzz_harness_gen":    {"ko": "📝 Ruzzy+LibAFL 하네스 자동 생성 완료 ({count}개) — LibAFL 0.8.0 lld/preinit_array 패치 적용",
                                  "zh": "📝 自动生成 Ruzzy+LibAFL 测试钩子完成 ({count}个) — 已应用 LibAFL 0.8.0 lld/preinit_array 补丁",
                                  "en": "📝 Ruzzy+LibAFL harness auto-generated ({count} harnesses) — LibAFL 0.8.0 lld/preinit_array patch applied"},
    "ruby_fuzz_summary":        {"ko": "Ruby LibAFL 퍼징 표면 스캔 완료: {count}개 발견 | 고가치:{high} | C확장:{cext}개 | GraphQL:{gql} | YAML위험:{yaml}",
                                  "zh": "Ruby LibAFL 模糊测试面扫描完成: 发现 {count} 个 | 高价值:{high} | C扩展:{cext}个 | GraphQL:{gql} | YAML风险:{yaml}",
                                  "en": "Ruby LibAFL fuzz surface scan complete: {count} surfaces | high-value:{high} | C-exts:{cext} | GraphQL:{gql} | YAML-risk:{yaml}"},
    "ruby_fuzz_no_finding":     {"ko": "✓ RubyLibAFLFuzz: Ruby 프레임워크 미감지 또는 퍼징 표면 없음",
                                  "zh": "✓ RubyLibAFLFuzz: 未检测到 Ruby 框架或无模糊测试攻击面",
                                  "en": "✓ RubyLibAFLFuzz: No Ruby framework detected or no fuzzing attack surface found"},
    "ruby_fuzz_auto_skip":      {"ko": "💡 Ruby 프레임워크 미감지 — RubyLibAFLFuzz 스캔 스킵",
                                  "zh": "💡 未检测到 Ruby 框架 — 跳过 RubyLibAFLFuzz 扫描",
                                  "en": "💡 No Ruby framework detected — RubyLibAFLFuzz scan skipped"},

    # ── AI Code Security Surface Detection (AICodeSecSurface) ──
    "aicsec_scan_start":        {"ko": "🤖 AI 판단: AI 생성 코드 보안 표면 탐지 활성화 — 시크릿/의존성/비즈니스로직/아티팩트 자동 스캔",
                                  "zh": "🤖 AI 判断: AI 生成代码安全面检测激活 — 自动扫描机密/依赖/业务逻辑/代码制品",
                                  "en": "🤖 AI decision: AI-generated code security surface scan activated — secrets/deps/business-logic/artifacts"},
    "aicsec_secret_found":      {"ko": "🔴 시크릿 노출: {label} 발견 at {url} — AI 코드가 자격증명을 하드코딩 [{ev}]",
                                  "zh": "🔴 机密泄露: 在 {url} 发现 {label} — AI 代码硬编码凭证 [{ev}]",
                                  "en": "🔴 Secret exposed: {label} found at {url} — AI code hardcoded credential [{ev}]"},
    "aicsec_env_exposed":       {"ko": "🚨 .env 파일 공개 접근 가능 — AI 스캐폴드 기본 설정으로 환경변수 파일 노출",
                                  "zh": "🚨 .env 文件可公开访问 — AI 脚手架默认配置导致环境变量文件暴露",
                                  "en": "🚨 .env file publicly accessible — AI scaffold default config exposes environment variables"},
    "aicsec_dep_vuln":          {"ko": "⚠️  취약 의존성 노출: {dep}@{ver} — {cve}",
                                  "zh": "⚠️  存在漏洞的依赖包暴露: {dep}@{ver} — {cve}",
                                  "en": "⚠️  Vulnerable dependency exposed: {dep}@{ver} — {cve}"},
    "aicsec_ai_artifact":       {"ko": "🔍 AI 코딩 아티팩트 감지: {desc} — 프로덕션 배포 전 리뷰 누락",
                                  "zh": "🔍 检测到 AI 编码制品: {desc} — 部署前代码审查缺失",
                                  "en": "🔍 AI coding artifact detected: {desc} — pre-deploy code review missed"},
    "aicsec_cors_wildcard":     {"ko": "⚠️  CORS Access-Control-Allow-Origin: * — AI 보일러플레이트 기본값, 크로스오리진 데이터 탈취 위험",
                                  "zh": "⚠️  CORS Access-Control-Allow-Origin: * — AI 样板代码默认值，存在跨域数据窃取风险",
                                  "en": "⚠️  CORS wildcard (*) — AI boilerplate default, cross-origin data theft risk"},
    "aicsec_biz_logic":         {"ko": "📊 비즈니스 로직 표면: {path} ({status}) — {desc}",
                                  "zh": "📊 业务逻辑攻击面: {path} ({status}) — {desc}",
                                  "en": "📊 Business logic surface: {path} ({status}) — {desc}"},
    "aicsec_actuator":          {"ko": "🔴 Spring Actuator 노출 (/actuator/env or /heapdump) — 환경변수/힙덤프 전체 노출",
                                  "zh": "🔴 Spring Actuator 暴露 (/actuator/env 或 /heapdump) — 环境变量/堆转储完全暴露",
                                  "en": "🔴 Spring Actuator exposed (/actuator/env or /heapdump) — full env vars / heap dump exposed"},
    "aicsec_summary":           {"ko": "AICodeSecSurface 스캔 완료: {total}건 | 시크릿:{secrets} | 의존성:{deps} | AI아티팩트:{artifacts} | 비즈니스로직:{biz} | 설정노출:{cfg}",
                                  "zh": "AICodeSecSurface 扫描完成: {total}条 | 机密:{secrets} | 依赖:{deps} | AI制品:{artifacts} | 业务逻辑:{biz} | 配置暴露:{cfg}",
                                  "en": "AICodeSecSurface scan complete: {total} findings | secrets:{secrets} | deps:{deps} | artifacts:{artifacts} | bizlogic:{biz} | config:{cfg}"},
    "aicsec_no_finding":        {"ko": "✓ AICodeSecSurface: 심각한 AI 코드 보안 이슈 미발견",
                                  "zh": "✓ AICodeSecSurface: 未发现严重 AI 代码安全问题",
                                  "en": "✓ AICodeSecSurface: No critical AI code security issues found"},
    # v3.5.1 Zero-Hallucination fix — VerificationEngine integration keys
    "aicsec_ev_policy":         {"ko": "🔒 증거등급 정책 — VERIFIED:검증엔진통과 | LIKELY:HTTP응답패턴매칭 | INFERRED:엔드포인트존재확인 | AI_ANALYSIS:AI패턴추론",
                                  "zh": "🔒 证据级别策略 — VERIFIED:验证引擎确认 | LIKELY:HTTP响应模式匹配 | INFERRED:端点存在确认 | AI_ANALYSIS:AI模式推断",
                                  "en": "🔒 Evidence policy — VERIFIED:VerificationEngine passed | LIKELY:HTTP response pattern match | INFERRED:endpoint confirmed | AI_ANALYSIS:AI inference"},
    "aicsec_not_verified":      {"ko": "⚠️  패턴 매칭만으로는 VERIFIED 불가 — VerificationEngine 5원칙 검증 필요",
                                  "zh": "⚠️  仅凭模式匹配无法标记 VERIFIED — 需要通过 VerificationEngine 5原则验证",
                                  "en": "⚠️  Pattern match alone cannot produce VERIFIED — requires VerificationEngine 5-principle check"},
    "aicsec_biz_logic_note":    {"ko": "ℹ️  비즈니스 로직 경로는 최대 LIKELY — 실제 익스플로잇 성공 전까지 VERIFIED 불가",
                                  "zh": "ℹ️  业务逻辑路径最高为 LIKELY — 实际利用成功前不得标记 VERIFIED",
                                  "en": "ℹ️  Business logic paths capped at LIKELY — VERIFIED requires confirmed exploit"},
    "aicsec_hallucination_fix": {"ko": "✅ v3.5.1 환각 수정: AICodeSecSurface가 VerificationEngine을 우회하여 AI 추론을 직접 VERIFIED로 표기하던 버그 수정",
                                  "zh": "✅ v3.5.1 幻觉修复: 修复 AICodeSecSurface 绕过 VerificationEngine、将 AI 推理直接标记为 VERIFIED 的漏洞",
                                  "en": "✅ v3.5.1 hallucination fix: AICodeSecSurface no longer bypasses VerificationEngine to mark AI inferences as VERIFIED"},

    # ── CSPT + Cloudflare WAF Bypass + Multi-ContentType Fuzzing (CSPTWafBypass) ──
    "cspt_scan_start":          {"ko": "🌐 AI 판단: CSPT+CloudflareWAF우회+다중ContentType 탐지 활성화 — SPA프레임워크/WAF/OAuth 자동 스캔",
                                  "zh": "🌐 AI 判断: CSPT+CloudflareWAF绕过+多ContentType检测激活 — SPA框架/WAF/OAuth 自动扫描",
                                  "en": "🌐 AI decision: CSPT+CloudflareWAF bypass+MultiContentType scan activated — SPA/WAF/OAuth auto-detect"},
    "cspt_cf_detected":         {"ko": "☁ Cloudflare WAF 감지: {target} — oncontentvisibilityautostatechange XSS 우회 페이로드 준비 (@YourFinalSin, Bug Bytes #235) [{ev}]",
                                  "zh": "☁ 检测到 Cloudflare WAF: {target} — oncontentvisibilityautostatechange XSS 绕过 payload 就绪 [{ev}]",
                                  "en": "☁ Cloudflare WAF detected: {target} — oncontentvisibilityautostatechange XSS bypass payload ready [{ev}]"},
    "cspt_pattern_found":       {"ko": "🔴 CSPT 패턴 감지: {pattern} in {url} — SPA({fw}) 라우팅이 경로 순회를 API fetch에 전달 [{ev}]",
                                  "zh": "🔴 CSPT 模式检测: {pattern} in {url} — SPA({fw}) 路由将路径遍历传递到 API fetch [{ev}]",
                                  "en": "🔴 CSPT pattern detected: {pattern} in {url} — SPA({fw}) routing passes path traversal to API fetch [{ev}]"},
    "cspt_endpoint_hit":        {"ko": "🔴 CSPT 엔드포인트 확인: {url} (traversal:{payload}, status:{status}, size:{size}) [{ev}]",
                                  "zh": "🔴 CSPT 端点确认: {url} (遍历:{payload}, 状态:{status}, 大小:{size}) [{ev}]",
                                  "en": "🔴 CSPT endpoint confirmed: {url} (traversal:{payload}, status:{status}, size:{size}) [{ev}]"},
    "cspt_cf_bypass_payload":   {"ko": "🔴 CF WAF 우회 페이로드: {name} — {desc} (ATO 체인 가능) [{ev}]",
                                  "zh": "🔴 CF WAF 绕过 payload: {name} — {desc} (ATO 链可行) [{ev}]",
                                  "en": "🔴 CF WAF bypass payload: {name} — {desc} (ATO chain possible) [{ev}]"},
    "cspt_content_type":        {"ko": "🟡 다중 ContentType 퍼징: {url} — {ct} 수락 (XXE/WAF우회 가능성) [{ev}]",
                                  "zh": "🟡 多 ContentType 模糊测试: {url} — {ct} 被接受 (XXE/WAF绕过可能) [{ev}]",
                                  "en": "🟡 Multi-ContentType fuzzing: {url} — {ct} accepted (XXE/WAF bypass possible) [{ev}]"},
    "cspt_oauth_chain":         {"ko": "🔴 OAuth ATO 체인: CF WAF 우회 XSS → OAuth 코드 탈취 → 완전 계정 탈취 at {url} [{ev}]",
                                  "zh": "🔴 OAuth ATO 链: CF WAF 绕过 XSS → OAuth 代码窃取 → 完全账户接管 at {url} [{ev}]",
                                  "en": "🔴 OAuth ATO chain: CF WAF bypass XSS → OAuth code theft → Full ATO at {url} [{ev}]"},
    "cspt_cookie_xss":          {"ko": "🟡 쿠키 주입 → DOM XSS: document.cookie가 innerHTML/eval 싱크로 흘러들어감 at {url} [{ev}]",
                                  "zh": "🟡 Cookie 注入 → DOM XSS: document.cookie 流入 innerHTML/eval sink at {url} [{ev}]",
                                  "en": "🟡 Cookie injection → DOM XSS: document.cookie flows into innerHTML/eval sink at {url} [{ev}]"},
    "cspt_auxclick":            {"ko": "🟡 Auxclick 클릭재킹 변형: 중간 마우스 버튼이 X-Frame-Options 방어 우회 at {url} [{ev}]",
                                  "zh": "🟡 Auxclick 点击劫持变体: 中键绕过 X-Frame-Options 防御 at {url} [{ev}]",
                                  "en": "🟡 Auxclick clickjacking variant: middle mouse button bypasses X-Frame-Options at {url} [{ev}]"},
    "cspt_summary":             {"ko": "CSPTWafBypass 스캔 완료: {total}건 | CF:{cf} | SPA:{spa} | CSPT패턴:{cspt_p} | CF우회:{cf_p} | ContentType:{ct} | OAuth:{oauth} | 심각도:{sev}",
                                  "zh": "CSPTWafBypass 扫描完成: {total}条 | CF:{cf} | SPA:{spa} | CSPT模式:{cspt_p} | CF绕过:{cf_p} | ContentType:{ct} | OAuth:{oauth} | 严重度:{sev}",
                                  "en": "CSPTWafBypass scan done: {total} findings | CF:{cf} | SPA:{spa} | CSPT_patterns:{cspt_p} | CF_bypass:{cf_p} | ContentType:{ct} | OAuth:{oauth} | sev:{sev}"},
    "cspt_no_finding":          {"ko": "✓ CSPTWafBypass: CSPT/CF우회/ContentType 심각 이슈 미발견",
                                  "zh": "✓ CSPTWafBypass: 未发现 CSPT/CF绕过/ContentType 严重问题",
                                  "en": "✓ CSPTWafBypass: No critical CSPT/CF bypass/ContentType issues found"},

    # ── DOMPurify Prototype Pollution → XSS Bypass (CVE-2026-41238) ──────────
    "dp_scan_start":            {"ko": "🔬 AI 판단: DOMPurify PP→XSS 우회 탐지 활성화 (CVE-2026-41238) — JS번들/package.json/PP가젯 자동 분석",
                                  "zh": "🔬 AI 判断: DOMPurify PP→XSS 绕过检测激活 (CVE-2026-41238) — JS包/package.json/PP小工具 自动分析",
                                  "en": "🔬 AI decision: DOMPurify PP→XSS bypass scan activated (CVE-2026-41238) — JS bundle/package.json/PP gadget auto-analysis"},
    "dp_version_found":         {"ko": "📦 DOMPurify {version} 감지 [{ev}] — {status} (found at: {url})",
                                  "zh": "📦 发现 DOMPurify {version} [{ev}] — {status} (位置: {url})",
                                  "en": "📦 DOMPurify {version} detected [{ev}] — {status} (found at: {url})"},
    "dp_vulnerable":            {"ko": "🚨 DOMPurify {version} 취약 범위 확인! (3.0.1–3.3.3) CVE-2026-41238: Prototype Pollution → CUSTOM_ELEMENT_HANDLING 폴백 상속 → XSS 완전 우회 [{ev}]",
                                  "zh": "🚨 DOMPurify {version} 确认漏洞范围! (3.0.1–3.3.3) CVE-2026-41238: 原型污染 → CUSTOM_ELEMENT_HANDLING 回退继承 → XSS完全绕过 [{ev}]",
                                  "en": "🚨 DOMPurify {version} in VULNERABLE range! (3.0.1–3.3.3) CVE-2026-41238: Prototype Pollution → CUSTOM_ELEMENT_HANDLING fallback inheritance → full XSS bypass [{ev}]"},
    "dp_fixed":                 {"ko": "✅ DOMPurify {version} ≥ 3.4.0 — CVE-2026-41238 패치됨 [{ev}]",
                                  "zh": "✅ DOMPurify {version} ≥ 3.4.0 — CVE-2026-41238 已修复 [{ev}]",
                                  "en": "✅ DOMPurify {version} ≥ 3.4.0 — CVE-2026-41238 patched [{ev}]"},
    "dp_pp_gadget":             {"ko": "⚡ PP 가젯 발견: {library} {version} — {desc} [{ev}]",
                                  "zh": "⚡ 发现PP小工具: {library} {version} — {desc} [{ev}]",
                                  "en": "⚡ PP gadget found: {library} {version} — {desc} [{ev}]"},
    "dp_combined_chain":        {"ko": "💥 CVE-2026-41238 완전 공격 체인! DOMPurify {dp_ver} (취약) + PP 가젯 [{gadgets}] → Object.prototype 오염 → sanitize() 무력화 → XSS CRITICAL [{ev}]",
                                  "zh": "💥 CVE-2026-41238 完整攻击链! DOMPurify {dp_ver} (漏洞) + PP小工具 [{gadgets}] → Object.prototype污染 → sanitize()失效 → XSS CRITICAL [{ev}]",
                                  "en": "💥 CVE-2026-41238 full attack chain! DOMPurify {dp_ver} (vuln) + PP gadget [{gadgets}] → Object.prototype pollution → sanitize() neutralized → XSS CRITICAL [{ev}]"},
    "dp_default_config":        {"ko": "⚠ DOMPurify.sanitize() 기본설정 사용 탐지 — CUSTOM_ELEMENT_HANDLING 미지정 → CVE-2026-41238 노출 [{ev}]",
                                  "zh": "⚠ 检测到DOMPurify.sanitize()默认配置 — 未指定CUSTOM_ELEMENT_HANDLING → CVE-2026-41238暴露 [{ev}]",
                                  "en": "⚠ DOMPurify.sanitize() default config detected — no CUSTOM_ELEMENT_HANDLING → CVE-2026-41238 exposure [{ev}]"},
    "dp_postmessage_risk":      {"ko": "📨 postMessage + deep-merge 패턴 탐지 — 타입 보존 PP 벡터(RegExp 주입 가능) + DOMPurify 취약 버전 조합 위험 [{ev}]",
                                  "zh": "📨 检测到postMessage+deep-merge模式 — 类型保留PP向量(可注入RegExp) + DOMPurify漏洞版本组合风险 [{ev}]",
                                  "en": "📨 postMessage + deep-merge pattern detected — type-preserving PP vector (RegExp injection) + vuln DOMPurify combination risk [{ev}]"},
    "dp_package_exposed":       {"ko": "📄 package.json 노출 확인 — 의존성 정보 공개됨 [{ev}]",
                                  "zh": "📄 package.json暴露确认 — 依赖信息已公开 [{ev}]",
                                  "en": "📄 package.json exposed — dependency information publicly accessible [{ev}]"},
    "dp_summary":               {"ko": "DOMPurifyPPBypass 스캔 완료: {total}건 | DP버전:{dp_ver} | 취약:{vuln} | PP가젯:{pp} | 기본설정:{dc} | postMsg:{pm} | 심각도:{sev}",
                                  "zh": "DOMPurifyPPBypass 扫描完成: {total}条 | DP版本:{dp_ver} | 漏洞:{vuln} | PP小工具:{pp} | 默认配置:{dc} | postMsg:{pm} | 严重度:{sev}",
                                  "en": "DOMPurifyPPBypass scan done: {total} findings | DP_ver:{dp_ver} | vuln:{vuln} | PP_gadgets:{pp} | default_cfg:{dc} | postMsg:{pm} | sev:{sev}"},
    "dp_no_finding":            {"ko": "✓ DOMPurifyPPBypass: 취약 DOMPurify 버전 또는 PP 가젯 미발견",
                                  "zh": "✓ DOMPurifyPPBypass: 未发现漏洞DOMPurify版本或PP小工具",
                                  "en": "✓ DOMPurifyPPBypass: No vulnerable DOMPurify version or PP gadget detected"},

    # ── Prompt Cache Optimizer (Three-Breakpoint Architecture) ──────────────
    "pc_init":                  {"ko": "⚡ 프롬프트 캐시 옵티마이저 활성화 — BP1(시스템)/BP2(스킬목록)/BP3(대화히스토리) 3중 캐시 브레이크포인트",
                                  "zh": "⚡ 提示词缓存优化器激活 — BP1(系统)/BP2(技能列表)/BP3(对话历史) 三重缓存断点",
                                  "en": "⚡ Prompt Cache Optimizer active — BP1(system)/BP2(skills)/BP3(conversation) three-breakpoint caching"},
    "pc_provider":              {"ko": "🔧 캐시 전략: {provider} — {strategy}",
                                  "zh": "🔧 缓存策略: {provider} — {strategy}",
                                  "en": "🔧 Cache strategy: {provider} — {strategy}"},
    "pc_hit":                   {"ko": "💰 캐시 HIT [{tokens}토큰 절약] 누적 절약률 {pct}%",
                                  "zh": "💰 缓存命中 [{tokens}词元节省] 累计节省率 {pct}%",
                                  "en": "💰 Cache HIT [{tokens} tokens saved] cumulative savings {pct}%"},
    "pc_miss":                  {"ko": "📝 캐시 MISS — BP1 핑거프린트 저장 완료 (다음 턴부터 캐시 히트 예상)",
                                  "zh": "📝 缓存未命中 — BP1指纹已保存 (下次调用预计命中缓存)",
                                  "en": "📝 Cache MISS — BP1 fingerprint saved (cache hit expected from next turn)"},
    "pc_relocation":            {"ko": "📌 재배치 트릭 적용: 동적 컨텐츠(타겟/날짜)를 프롬프트 꼬리로 이동 → 정적 캐시 유효성 유지",
                                  "zh": "📌 重定位技巧: 动态内容(目标/日期)移至提示词末尾 → 保持静态缓存有效性",
                                  "en": "📌 Relocation trick applied: dynamic content (target/date) moved to prompt tail → static cache remains valid"},
    "pc_frozen_date":           {"ko": "📅 Frozen Datetime 적용: {date} — 분 단위 캐시 버스팅 방지",
                                  "zh": "📅 冻结日期时间: {date} — 防止每分钟缓存失效",
                                  "en": "📅 Frozen datetime: {date} — prevents per-minute cache busting"},
    "pc_bp3_window":            {"ko": "🗂 BP3 슬라이딩 윈도우: 최근 {turns}턴만 유지 (컨텍스트 폭발 방지)",
                                  "zh": "🗂 BP3滑动窗口: 仅保留最近{turns}轮 (防止上下文爆炸)",
                                  "en": "🗂 BP3 sliding window: keeping last {turns} turns only (prevents context explosion)"},
    "pc_deepseek_flag":         {"ko": "🚀 DeepSeek prefix_caching=true 설정 — 서버 측 prefix 캐시 활성화",
                                  "zh": "🚀 DeepSeek prefix_caching=true — 激活服务端前缀缓存",
                                  "en": "🚀 DeepSeek prefix_caching=true — server-side prefix cache enabled"},
    "pc_claude_beta":           {"ko": "🔑 Anthropic prompt-caching-2024-07-31 베타 헤더 활성화 — cache_control:ephemeral 마커 3개 삽입",
                                  "zh": "🔑 Anthropic prompt-caching-2024-07-31 Beta头激活 — 插入3个cache_control:ephemeral标记",
                                  "en": "🔑 Anthropic prompt-caching-2024-07-31 beta header active — 3 cache_control:ephemeral markers injected"},
    "pc_summary":               {"ko": "📊 캐시 통계: 총호출 {calls}회 | HIT {hits}회({pct}%) | 절약토큰≈{saved} | 비용절감≈{saving_pct}%",
                                  "zh": "📊 缓存统计: 总调用{calls}次 | 命中{hits}次({pct}%) | 节省词元≈{saved} | 费用节省≈{saving_pct}%",
                                  "en": "📊 Cache stats: total={calls} | hits={hits}({pct}%) | saved≈{saved}tok | cost_reduction≈{saving_pct}%"},
    "pc_cost_model":            {"ko": "💡 비용 모델: 캐시 쓰기=1.25×, 캐시 읽기=0.10× (Anthropic 기준) / DeepSeek=prefix 자동 캐싱",
                                  "zh": "💡 费用模型: 缓存写入=1.25×, 缓存读取=0.10× (Anthropic) / DeepSeek=前缀自动缓存",
                                  "en": "💡 Cost model: cache write=1.25×, cache read=0.10× (Anthropic) / DeepSeek=auto prefix caching"},

    # ── Cloudflare ACME WAF Bypass — Skill #58 ─────────────────────────────
    "acme_init":                {"ko": "🔍 Cloudflare ACME WAF 우회 스캐너 시작 — /.well-known/acme-challenge/ 경로 테스트",
                                  "zh": "🔍 Cloudflare ACME WAF绕过扫描器启动 — 测试 /.well-known/acme-challenge/ 路径",
                                  "en": "🔍 Cloudflare ACME WAF Bypass Scanner started — testing /.well-known/acme-challenge/ path"},
    "acme_cf_detected":         {"ko": "☁️ Cloudflare 감지됨: {indicators} — ACME 우회 테스트 진행",
                                  "zh": "☁️ 检测到Cloudflare: {indicators} — 进行ACME绕过测试",
                                  "en": "☁️ Cloudflare detected: {indicators} — proceeding with ACME bypass test"},
    "acme_cf_not_found":        {"ko": "ℹ️ Cloudflare 미감지 — ACME 우회 테스트 해당 없음",
                                  "zh": "ℹ️ 未检测到Cloudflare — ACME绕过测试不适用",
                                  "en": "ℹ️ Cloudflare not detected — ACME bypass test not applicable"},
    "acme_bypass_confirmed":    {"ko": "🚨 CRITICAL: Cloudflare WAF 우회 확인! ACME 경로에서 오리진 서버 직접 도달 [{ev}] — 오리진: {origin}",
                                  "zh": "🚨 严重: Cloudflare WAF绕过确认! ACME路径直接到达源服务器 [{ev}] — 源服务器: {origin}",
                                  "en": "🚨 CRITICAL: Cloudflare WAF bypass confirmed! Origin reached directly via ACME path [{ev}] — origin: {origin}"},
    "acme_waf_enforced":        {"ko": "✅ WAF 정상 적용 — ACME 경로에서도 Cloudflare 보호 활성 (패치됨) [{ev}]",
                                  "zh": "✅ WAF正常执行 — ACME路径上Cloudflare保护仍然有效(已修复) [{ev}]",
                                  "en": "✅ WAF correctly enforced — Cloudflare protection active on ACME path too (patched) [{ev}]"},
    "acme_header_attack":       {"ko": "⚠️ WAF 우회 시 헤더 공격 벡터 노출: {vec_count}개 — SSRF/캐시 포이즈닝/메서드 오버라이드 가능",
                                  "zh": "⚠️ WAF绕过时标头攻击向量暴露: {vec_count}个 — 可能SSRF/缓存投毒/方法覆盖",
                                  "en": "⚠️ Header attack vectors exposed via bypass: {vec_count} — SSRF/cache poisoning/method override possible"},
    "acme_lfi_found":           {"ko": "🔥 LFI 발견! ACME 우회 경로에서 파일 시스템 접근 확인 [{ev}]: {path}",
                                  "zh": "🔥 发现LFI! ACME绕过路径文件系统访问确认 [{ev}]: {path}",
                                  "en": "🔥 LFI found! Filesystem access confirmed via ACME bypass path [{ev}]: {path}"},
    "acme_actuator_exposed":    {"ko": "⚠️ Spring Actuator ACME 우회로 노출: {path} — 환경변수/빈 정보 접근 가능",
                                  "zh": "⚠️ Spring Actuator通过ACME绕过暴露: {path} — 可访问环境变量/Bean信息",
                                  "en": "⚠️ Spring Actuator exposed via ACME bypass: {path} — env vars/beans accessible"},
    "acme_summary":             {"ko": "📊 ACME 스캔 완료: 발견={total} | 우회={bypass} | 오리진 노출={origin} | 헤더공격={headers} | 소요={dur}s",
                                  "zh": "📊 ACME扫描完成: 发现={total} | 绕过={bypass} | 源服务器暴露={origin} | 标头攻击={headers} | 耗时={dur}s",
                                  "en": "📊 ACME scan done: findings={total} | bypass={bypass} | origin exposed={origin} | header attacks={headers} | dur={dur}s"},
    "acme_remediation":         {"ko": "🔧 수정 방법: Cloudflare IP 범위만 오리진 허용 + Authenticated Origin Pulls(mTLS) 활성화 + /.well-known/ 경로 WAF 적용 확인",
                                  "zh": "🔧 修复方法: 仅允许Cloudflare IP范围访问源服务器 + 启用Authenticated Origin Pulls(mTLS) + 确认WAF应用于/.well-known/路径",
                                  "en": "🔧 Fix: Allow only Cloudflare IP ranges to origin + Enable Authenticated Origin Pulls (mTLS) + Verify WAF on /.well-known/ path"},

    # ── React2Shell WAF Bypass — Skill #59 ─────────────────────────────────────
    "r2s_init":                 {"ko": "🔍 React2Shell WAF 우회 스캐너 시작 — Next.js RSF 엔드포인트 + 멀티파트 파서 차이 테스트",
                                  "zh": "🔍 React2Shell WAF绕过扫描器启动 — 测试Next.js RSF端点及multipart解析差异",
                                  "en": "🔍 React2Shell WAF Bypass Scanner started — testing Next.js RSF endpoints and multipart parser differentials"},
    "r2s_react_detected":       {"ko": "⚛️  React/Next.js 감지됨: {indicators} — CVE-2025-55182 공격 표면 확인",
                                  "zh": "⚛️  检测到React/Next.js: {indicators} — CVE-2025-55182攻击面确认",
                                  "en": "⚛️  React/Next.js detected: {indicators} — CVE-2025-55182 attack surface identified"},
    "r2s_rsc_found":            {"ko": "🎯 React Server Functions 엔드포인트 발견: {endpoint} — Next-Action 헤더 수락 확인",
                                  "zh": "🎯 发现React Server Functions端点: {endpoint} — 确认接受Next-Action请求头",
                                  "en": "🎯 React Server Functions endpoint found: {endpoint} — accepts Next-Action header"},
    "r2s_waf_detected":         {"ko": "🛡️  WAF 감지됨: :constructor 차단 ({indicator}) — 우회 기법 5종 테스트 시작",
                                  "zh": "🛡️  检测到WAF: 阻断:constructor ({indicator}) — 开始测试5种绕过技术",
                                  "en": "🛡️  WAF detected blocking :constructor ({indicator}) — starting BP1-BP5 bypass tests"},
    "r2s_bypass_works":         {"ko": "🚨 WAF 우회 성공 [{bp_id}]: {title} — 페이로드가 백엔드에 도달함 VERIFIED",
                                  "zh": "🚨 WAF绕过成功 [{bp_id}]: {title} — 载荷已到达后端 VERIFIED",
                                  "en": "🚨 WAF bypass CONFIRMED [{bp_id}]: {title} — payload reaches backend VERIFIED"},
    "r2s_bypass_blocked":       {"ko": "✅ [{bp_id}] WAF 차단 유지 — 해당 기법 패치됨",
                                  "zh": "✅ [{bp_id}] WAF仍然拦截 — 该技术已修补",
                                  "en": "✅ [{bp_id}] WAF blocking maintained — technique patched"},
    "r2s_summary":              {"ko": "📊 React2Shell 스캔 완료: 우회 {count}개 확인 / 5개 테스트 — Next.js 버전 16.0.7+ 업그레이드 권장",
                                  "zh": "📊 React2Shell扫描完成: 确认{count}个绕过/5个测试 — 建议升级Next.js至16.0.7+",
                                  "en": "📊 React2Shell scan done: {count} bypasses confirmed of 5 tested — upgrade to Next.js 16.0.7+"},
    "r2s_no_rsc":               {"ko": "ℹ️  React Server Functions 엔드포인트 미발견 — React2Shell 공격 표면 없음",
                                  "zh": "ℹ️  未发现React Server Functions端点 — 无React2Shell攻击面",
                                  "en": "ℹ️  No React Server Functions endpoint found — React2Shell attack surface absent"},
    "r2s_remediation":          {"ko": "🔧 수정: Next.js 16.0.7+ 업그레이드 (CVE-2025-55182 패치) + 원시 바이트 기반 WAF 규칙 (0x00 제거 + 이중 JSON 언이스케이프 + :constructor 차단)",
                                  "zh": "🔧 修复: 升级到Next.js 16.0.7+(修复CVE-2025-55182) + 原始字节WAF规则(去除0x00+双重JSON反转义+阻断:constructor)",
                                  "en": "🔧 Fix: Upgrade to Next.js 16.0.7+ (CVE-2025-55182 patched) + raw-body WAF rules (strip 0x00 + double JSON-unescape + block :constructor)"},

    # ── Apache Druid SSRF — Skill #60 ──────────────────────────────────────────
    "druid_init":               {"ko": "🔍 Apache Druid SSRF 스캐너 시작 — 관리 콘솔 탐지 + CVE-2025-27888 프록시 엔드포인트 테스트",
                                  "zh": "🔍 Apache Druid SSRF扫描器启动 — 检测管理控制台 + 测试CVE-2025-27888代理端点",
                                  "en": "🔍 Apache Druid SSRF Scanner started — detecting management console + CVE-2025-27888 proxy endpoint test"},
    "druid_detected":           {"ko": "🐉 Apache Druid 감지됨{version}: {indicators} — CVE-2025-27888 SSRF 공격 표면 확인",
                                  "zh": "🐉 检测到Apache Druid{version}: {indicators} — 确认CVE-2025-27888 SSRF攻击面",
                                  "en": "🐉 Apache Druid detected{version}: {indicators} — CVE-2025-27888 SSRF attack surface confirmed"},
    "druid_proxy_found":        {"ko": "🎯 Druid 프록시 엔드포인트 발견: {endpoint} — SSRF 테스트 시작",
                                  "zh": "🎯 发现Druid代理端点: {endpoint} — 开始SSRF测试",
                                  "en": "🎯 Druid proxy endpoint found: {endpoint} — starting SSRF tests"},
    "druid_ssrf_confirmed":     {"ko": "🚨 CVE-2025-27888 SSRF 확인됨! 내부 URL 도달: {ssrf_target} — 클라우드 메타데이터/내부망 접근 가능",
                                  "zh": "🚨 CVE-2025-27888 SSRF已确认! 已到达内部URL: {ssrf_target} — 可访问云元数据/内部网络",
                                  "en": "🚨 CVE-2025-27888 SSRF CONFIRMED! Internal URL reached: {ssrf_target} — cloud metadata / internal network accessible"},
    "druid_cloud_metadata":     {"ko": "💀 클라우드 메타데이터 서비스 노출! IAM 자격증명 탈취 가능 — 즉시 자격증명 교체 필요",
                                  "zh": "💀 云元数据服务暴露! 可窃取IAM凭证 — 需立即轮换凭证",
                                  "en": "💀 Cloud metadata service exposed! IAM credential theft possible — rotate credentials immediately"},
    "druid_internal_nodes":     {"ko": "⚠️  Druid 클러스터 내부 노드 {count}개 SSRF로 접근 가능 — 데이터소스/태스크 정보 노출",
                                  "zh": "⚠️  通过SSRF可访问{count}个Druid集群内部节点 — 数据源/任务信息暴露",
                                  "en": "⚠️  {count} Druid cluster internal nodes reachable via SSRF — datasource/task information exposed"},
    "druid_no_proxy":           {"ko": "ℹ️  Druid 감지됐으나 프록시 엔드포인트 미발견 — 패치 적용됐거나 접근 제한됨",
                                  "zh": "ℹ️  检测到Druid但未发现代理端点 — 可能已修补或访问受限",
                                  "en": "ℹ️  Druid detected but proxy endpoint not found — patched or access restricted"},
    "druid_not_found":          {"ko": "ℹ️  Apache Druid 미감지 — CVE-2025-27888 공격 표면 없음",
                                  "zh": "ℹ️  未检测到Apache Druid — 无CVE-2025-27888攻击面",
                                  "en": "ℹ️  Apache Druid not detected — no CVE-2025-27888 attack surface"},
    "druid_remediation":        {"ko": "🔧 수정: Apache Druid 31.0.2+/32.0.1+ 업그레이드 + 관리 콘솔 외부 차단 + IMDSv2 강제 + 프록시 대상 URL 화이트리스트",
                                  "zh": "🔧 修复: 升级到Apache Druid 31.0.2+/32.0.1+ + 阻止管理控制台外部访问 + 强制IMDSv2 + 代理目标URL白名单",
                                  "en": "🔧 Fix: Upgrade Apache Druid to 31.0.2+/32.0.1+ + block management console externally + enforce IMDSv2 + whitelist proxy target URLs"},

    # ── PAN-OS Auth Bypass — Skill #61 ─────────────────────────────────────────
    "panos_init":               {"ko": "🔍 PAN-OS 인증 우회 스캐너 시작 — Nginx/Apache 경로 혼동 CVE-2025-0108 테스트",
                                  "zh": "🔍 PAN-OS认证绕过扫描器启动 — 测试Nginx/Apache路径混淆CVE-2025-0108",
                                  "en": "🔍 PAN-OS Auth Bypass Scanner started — testing Nginx/Apache path confusion CVE-2025-0108"},
    "panos_detected":           {"ko": "🔥 Palo Alto PAN-OS 관리 인터페이스 감지됨{version}: {indicators} — CVE-2025-0108 공격 표면 확인",
                                  "zh": "🔥 检测到Palo Alto PAN-OS管理界面{version}: {indicators} — CVE-2025-0108攻击面确认",
                                  "en": "🔥 Palo Alto PAN-OS management interface detected{version}: {indicators} — CVE-2025-0108 attack surface confirmed"},
    "panos_bypass_confirmed":   {"ko": "🚨 CVE-2025-0108 인증 우회 확인됨! {php_file} 인증 없이 실행 — /unauth/%252e%252e/ 이중 디코딩 트래버설 성공",
                                  "zh": "🚨 CVE-2025-0108认证绕过已确认! {php_file}无需认证即可执行 — /unauth/%252e%252e/双重解码路径遍历成功",
                                  "en": "🚨 CVE-2025-0108 Auth Bypass CONFIRMED! {php_file} executed unauthenticated — double-decode traversal /unauth/%252e%252e/ succeeded"},
    "panos_rce_chain":          {"ko": "💀 CVE-2025-0108 + CVE-2024-9474 RCE 체인 가능! 인증 우회 → 권한 상승 → root 실행",
                                  "zh": "💀 CVE-2025-0108 + CVE-2024-9474 RCE链可行! 认证绕过 → 权限提升 → root执行",
                                  "en": "💀 CVE-2025-0108 + CVE-2024-9474 RCE chain possible! Auth bypass → privilege escalation → root execution"},
    "panos_not_found":          {"ko": "ℹ️  PAN-OS 관리 인터페이스 미감지 — CVE-2025-0108 공격 표면 없음",
                                  "zh": "ℹ️  未检测到PAN-OS管理界面 — 无CVE-2025-0108攻击面",
                                  "en": "ℹ️  PAN-OS management interface not detected — no CVE-2025-0108 attack surface"},
    "panos_patched":            {"ko": "✅ PAN-OS 감지됐으나 CVE-2025-0108 우회 차단됨 — 패치 적용됐거나 관리 인터페이스 접근 제한됨",
                                  "zh": "✅ 检测到PAN-OS但CVE-2025-0108绕过被阻断 — 已修补或管理界面访问受限",
                                  "en": "✅ PAN-OS detected but CVE-2025-0108 bypass blocked — patched or management interface access restricted"},
    "panos_remediation":        {"ko": "🔧 수정: PAN-OS 업그레이드 10.2.14+/11.0.7+/11.2.5+ + 관리 인터페이스 IP 화이트리스트 + 인터넷 노출 즉시 차단",
                                  "zh": "🔧 修复: 升级PAN-OS至10.2.14+/11.0.7+/11.2.5+ + 管理界面IP白名单 + 立即阻止互联网暴露",
                                  "en": "🔧 Fix: Upgrade PAN-OS to 10.2.14+/11.0.7+/11.2.5+ + whitelist management interface IPs + block internet exposure immediately"},

    # ── IngressNightmare RCE — Skill #62 ───────────────────────────────────────
    "ingress_init":             {"ko": "🔍 IngressNightmare 스캐너 시작 — K8s 클러스터 + ingress-nginx 어드미션 컨트롤러 CVE-2025-1974 탐지",
                                  "zh": "🔍 IngressNightmare扫描器启动 — 检测K8s集群 + ingress-nginx准入控制器CVE-2025-1974",
                                  "en": "🔍 IngressNightmare Scanner started — detecting K8s cluster + ingress-nginx admission controller CVE-2025-1974"},
    "ingress_k8s_detected":     {"ko": "☸️  Kubernetes 클러스터 감지됨{version} — ingress-nginx 취약점 체인 공격 표면 확인",
                                  "zh": "☸️  检测到Kubernetes集群{version} — 确认ingress-nginx漏洞链攻击面",
                                  "en": "☸️  Kubernetes cluster detected{version} — ingress-nginx vulnerability chain attack surface confirmed"},
    "ingress_admission_exposed": {"ko": "🚨 ingress-nginx 어드미션 컨트롤러 무인증 노출! 포트 {port} — CVE-2025-1974 CVSS 9.8 직접 접근 가능",
                                  "zh": "🚨 ingress-nginx准入控制器无认证暴露! 端口{port} — CVE-2025-1974 CVSS 9.8可直接访问",
                                  "en": "🚨 ingress-nginx admission controller unauthenticated exposure! Port {port} — CVE-2025-1974 CVSS 9.8 direct access confirmed"},
    "ingress_rce_chain":        {"ko": "💀 IngressNightmare RCE 체인 가능! 어드미션 컨트롤러 무인증 + 어노테이션 인젝션 + ssl_engine .so 로드 → 클러스터 전체 Secret 탈취",
                                  "zh": "💀 IngressNightmare RCE链可行! 未认证准入控制器 + 注解注入 + ssl_engine .so加载 → 整个集群Secret泄露",
                                  "en": "💀 IngressNightmare RCE chain possible! Unauthenticated admission + annotation injection + ssl_engine .so load → full cluster secret takeover"},
    "ingress_not_found":        {"ko": "ℹ️  ingress-nginx 어드미션 컨트롤러 미감지 — CVE-2025-1974 공격 표면 없음",
                                  "zh": "ℹ️  未检测到ingress-nginx准入控制器 — 无CVE-2025-1974攻击面",
                                  "en": "ℹ️  ingress-nginx admission controller not detected — no CVE-2025-1974 attack surface"},
    "ingress_version_vuln":     {"ko": "⚠️  ingress-nginx 취약 버전 감지: {version} — 1.11.5+/1.12.1+로 즉시 업그레이드 필요",
                                  "zh": "⚠️  检测到ingress-nginx漏洞版本: {version} — 需立即升级至1.11.5+/1.12.1+",
                                  "en": "⚠️  Vulnerable ingress-nginx version detected: {version} — immediate upgrade to 1.11.5+/1.12.1+ required"},
    "ingress_remediation":      {"ko": "🔧 수정: ingress-nginx 1.11.5+/1.12.1+ 업그레이드 + NetworkPolicy로 kube-apiserver만 8443 접근 허용 + Gateway API 마이그레이션 고려(EOL 2025-11)",
                                  "zh": "🔧 修复: 升级ingress-nginx至1.11.5+/1.12.1+ + NetworkPolicy仅允许kube-apiserver访问8443 + 考虑迁移到Gateway API(EOL 2025-11)",
                                  "en": "🔧 Fix: Upgrade ingress-nginx to 1.11.5+/1.12.1+ + NetworkPolicy: only kube-apiserver can reach port 8443 + plan Gateway API migration (EOL Nov 2025)"},

    # ── 무한루프 킬러 / Infinite Loop Killer (v2.3.22+) ─────────────
    "loop_block_label":         {"ko": "🚫 [루프 차단 #{n}] {reason}",
                                  "zh": "🚫 [循环拦截 #{n}] {reason}",
                                  "en": "🚫 [LOOP BLOCK #{n}] {reason}"},
    "loop_block_reason_infinite": {
                                  "ko": "INFINITE_LOOP_RISK: for/range + TOP 1 쿼리 + seen=set() 없음 → 동일 결과 무한 반복",
                                  "zh": "INFINITE_LOOP_RISK: for/range + TOP 1查询 + 无seen=set() → 无限重复相同结果",
                                  "en": "INFINITE_LOOP_RISK: for/range loop with TOP 1 query and no seen=set() will repeat same result forever"},
    "loop_block_feedback_title": {
                                  "ko": "⛔ 코드 블록 거부 — 무한 루프 패턴 감지됨",
                                  "zh": "⛔ 代码块被拒绝 — 检测到无限循环模式",
                                  "en": "⛔ CODE BLOCK REJECTED — INFINITE LOOP PATTERN DETECTED"},
    "loop_block_mandatory_rewrite": {
                                  "ko": "필수 재작성 — 커서 페이지네이션 패턴을 사용하세요:",
                                  "zh": "强制重写 — 请使用游标分页模式：",
                                  "en": "MANDATORY REWRITE — Use cursor pagination:"},
    "loop_block_rewrite_now":   {"ko": "위의 커서 페이지네이션 패턴으로 지금 당장 재작성하세요.",
                                  "zh": "请立即使用上面的游标分页模式重写。",
                                  "en": "Rewrite with the cursor pagination pattern above NOW."},

    # ── 스크립트 킬 메시지 / Script Kill Messages (v2.3.23) ───────────
    "script_killed_infinite":   {"ko": "[스크립트_종료: 무한_루프 감지됨]",
                                  "zh": "[脚本已终止: 检测到无限循环]",
                                  "en": "[SCRIPT_KILLED: INFINITE_LOOP detected]"},
    "script_killed_same_val":   {"ko": "동일 값 '{val}'이(가) {n}회 이상 반복됨.",
                                  "zh": "相同值 '{val}' 重复出现 {n} 次以上。",
                                  "en": "Same value '{val}' repeated {n}+ times."},
    "script_killed_mandatory_fix": {
                                  "ko": "필수 수정 — 열거 루프에 중복 제거 로직이 없습니다.",
                                  "zh": "强制修复 — 您的枚举循环没有去重逻辑。",
                                  "en": "MANDATORY FIX — Your enumeration loop has NO deduplication."},
    "script_killed_cursor_must": {
                                  "ko": "반드시 커서 페이지네이션 패턴으로 재작성하세요:",
                                  "zh": "必须使用游标分页模式重写：",
                                  "en": "You MUST rewrite with cursor pagination pattern:"},
    "script_killed_timeout":    {"ko": "[스크립트_종료: 타임아웃]\n스크립트가 {sec}초 제한을 초과하여 강제 종료되었습니다.\n스크립트를 더 작은 블록으로 나누거나 루프를 최적화하세요.",
                                  "zh": "[脚本已终止: 超时]\n脚本超过{sec}秒限制，已被强制终止。\n请将脚本拆分为更小的块或优化循环。",
                                  "en": "[SCRIPT_KILLED: TIMEOUT]\nScript exceeded {sec}s timeout and was forcibly terminated.\nSplit the script into smaller blocks or optimize the loop."},

    # ── VBScript 에러 / VBScript Error Detection (v2.3.21+) ──────────
    "vbscript_not_sqli_title":  {"ko": "⚠️  VBScript 에러 감지 — 이 파라미터들은 SQL 인젝션이 아닙니다",
                                  "zh": "⚠️  检测到VBScript错误 — 这些参数不是SQL注入点",
                                  "en": "⚠️  VBScript error detected — these parameters are NOT SQL injectable"},
    "vbscript_not_sqli_detail": {"ko": "감지된 에러: {signals}\n→ 파라미터화된 쿼리/ADO 타입 불일치 = 인젝션 불가\n→ 이 파라미터 테스트 중단. 다른 진입점을 찾으세요.",
                                  "zh": "检测到的错误: {signals}\n→ 参数化查询/ADO类型不匹配 = 无法注入\n→ 停止测试此参数，寻找其他入口点。",
                                  "en": "Detected: {signals}\n→ Parameterized query/ADO type mismatch = NOT injectable\n→ STOP testing this parameter. Find a different entry point."},

    # ── ADODB 800a0cc1 / Stacked Query Signal (v2.3.22+) ─────────────
    "stacked_query_detected":   {"ko": "⚡ ADODB 800a0cc1 감지 — 세미콜론 스택 쿼리 실행 가능! (SELECT가 아닌 EXEC/INSERT 시도)",
                                  "zh": "⚡ 检测到ADODB 800a0cc1 — 分号堆叠查询可执行！(尝试EXEC/INSERT而非SELECT)",
                                  "en": "⚡ ADODB 800a0cc1 detected — semicolon stacked query IS executing! (try EXEC/INSERT not SELECT)"},

    # ── 무한 루프 경고 (사후 감지) / Post-execution loop warning ────────
    "infinite_loop_warning":    {"ko": "⚠️  무한 루프 감지 — '{name}'이(가) {n}회 이상 반복됨. 커서 페이지네이션 없이 TOP 1 쿼리를 사용한 것 같습니다.",
                                  "zh": "⚠️  检测到无限循环 — '{name}' 重复出现 {n} 次以上。疑似使用TOP 1查询而无游标分页。",
                                  "en": "⚠️  Infinite loop detected — '{name}' repeated {n}+ times. Likely TOP 1 query without cursor pagination."},

    # v3.6.6: WAF 차단 응답 루프 오탐 방지
    # WAF가 여러 페이로드를 동일한 403 HTML로 차단할 때 무한루프로 오탐되던 문제 수정
    "loop_fp_waf_block":        {"ko": "⚡ 루프 오탐 스킵: '{name}'은 WAF 차단 응답 — SQL 데이터 루프 아님.",
                                  "zh": "⚡ 跳过循环误报: '{name}'是WAF拦截响应 — 不是SQL数据无限循环。",
                                  "en": "⚡ Loop false-positive skipped: '{name}' is WAF block response — not SQL data loop."},

    # v3.6.7: VPN DNS 우회 관련 다국어 키
    # socket.gethostbyname() → dig @8.8.8.8 교체로 VPN 켠 상태에서도 실제 IP 반환
    "dns_vpn_virtual_ip":       {"ko": "⚠️ VPN 가상IP 감지: {ip} ← {host} — 실제 서버 IP 아님. 외부 DNS로 재조회 중...",
                                  "zh": "⚠️ 检测到VPN虚拟IP: {ip} ← {host} — 非真实服务器IP，正在通过外部DNS重新查询...",
                                  "en": "⚠️ VPN virtual IP detected: {ip} ← {host} — not real server IP. Re-querying via external DNS..."},
    "dns_vpn_bypass_ok":        {"ko": "✅ 실제 IP 확인 (외부 DNS): {ip} ← {host}",
                                  "zh": "✅ 真实IP已确认（外部DNS）: {ip} ← {host}",
                                  "en": "✅ Real IP confirmed (external DNS): {ip} ← {host}"},
    "dns_vpn_bypass_fail":      {"ko": "❌ VPN 우회 DNS 조회 실패. 수동 확인: dig @8.8.8.8 +short {host}",
                                  "zh": "❌ VPN绕过DNS查询失败。请手动确认: dig @8.8.8.8 +short {host}",
                                  "en": "❌ VPN-bypass DNS query failed. Check manually: dig @8.8.8.8 +short {host}"},
    "dns_os_fallback":          {"ko": "⚠️ OS DNS 폴백: {ip} — VPN 켠 상태에서 왜곡될 수 있음",
                                  "zh": "⚠️ OS DNS备用: {ip} — VPN开启时可能失真",
                                  "en": "⚠️ OS DNS fallback: {ip} — may be distorted when VPN is active"},

    # ── XSS 반사 중복 제거 / XSS Reflection Deduplication (v2.9.4) ─────
    "xss_reflect_dedup_fix":    {"ko": "필수 수정 — XSS 반사 위치를 중복 제거 없이 출력하고 있습니다.\nseen_ctx = set() 으로 고유 컨텍스트만 출력하세요.",
                                  "zh": "强制修复 — XSS反射位置输出没有去重。\n请使用 seen_ctx = set() 仅输出唯一上下文。",
                                  "en": "MANDATORY FIX — XSS reflection positions printed without deduplication.\nUse seen_ctx = set() to print unique contexts only."},
    "xss_reflect_unique_count": {"ko": "총 고유 반사 위치: {n}개",
                                  "zh": "唯一反射位置总计: {n} 处",
                                  "en": "Total unique reflection positions: {n}"},
    "xss_scan_result_prefix":   {"ko": "반사 위치",
                                  "zh": "反射位置",
                                  "en": "Reflection at"},

    # ── 혼합 SQLi 결과 (VBScript + OLE DB 동시 감지) / Mixed SQLi result ──
    "mixed_sqli_result_title":  {"ko": "🔍 혼합 결과 — VBScript 에러 + 진짜 OLE DB SQL 에러 동시 감지",
                                  "zh": "🔍 混合结果 — 同时检测到VBScript错误和真实OLE DB SQL错误",
                                  "en": "🔍 Mixed result — VBScript errors AND real OLE DB SQL errors both detected"},
    "mixed_sqli_result_detail": {"ko": "→ 80040e1x 에러가 발생한 파라미터는 SQLi 가능! VBScript 에러 파라미터는 파라미터화됨(불가)\n→ 80040e14/80040e07 파라미터에 집중하세요.",
                                  "zh": "→ 触发80040e1x错误的参数可注入！VBScript错误参数已参数化（不可注入）\n→ 专注于80040e14/80040e07参数。",
                                  "en": "→ Parameters triggering 80040e1x ARE injectable! VBScript error params are parameterized (NOT injectable)\n→ Focus on 80040e14/80040e07 parameters."},

    # ── 타입 에러 파라미터 스킵 안내 / Typed param skip notice ──────────
    "typed_param_skip":         {"ko": "⏭️  타입 지정 파라미터 — ORDER BY/UNION 열거 건너뜀 (type error 감지됨)",
                                  "zh": "⏭️  类型指定参数 — 跳过ORDER BY/UNION枚举（检测到类型错误）",
                                  "en": "⏭️  Typed parameter — skipping ORDER BY/UNION enumeration (type error detected)"},

    # ── v2.3.26 신규: pymssql/VPN/oracle/WAITFOR 관련 ──
    "script_watchdog_killed":   {"ko": "⏱️  [워치독] 스크립트 {sec}초 초과 (stdout 없는 블로킹 감지) → 강제 종료",
                                  "zh": "⏱️  [看门狗] 脚本超过 {sec} 秒（检测到无输出阻塞）→ 强制终止",
                                  "en": "⏱️  [WATCHDOG] Script exceeded {sec}s with no output (blocking socket detected) → KILLED"},

    "pymssql_vpn_ip_warn":      {"ko": "⚠️  VPN NAT IP ({ip}) 감지 — 직접 연결 차단. 도메인명으로 재시도하세요.",
                                  "zh": "⚠️  检测到VPN NAT IP ({ip}) — 直接连接被阻止。请使用域名重试。",
                                  "en": "⚠️  VPN NAT IP ({ip}) detected — direct connection blocked. Retry with hostname."},

    "bool_oracle_invalid":      {"ko": "❌  Boolean oracle 무효 — TRUE/FALSE 응답 크기 동일 ({size}B). 다른 기법으로 전환.",
                                  "zh": "❌  布尔Oracle无效 — TRUE/FALSE响应大小相同 ({size}B)。切换到其他技术。",
                                  "en": "❌  Boolean oracle INVALID — TRUE/FALSE return identical size ({size}B). Switch technique."},

    "waitfor_false_positive":   {"ko": "⚠️  WAITFOR 오탐 — {sec}초 설정인데 응답 {rt:.2f}초 (<{threshold}초). 주입 미실행.",
                                  "zh": "⚠️  WAITFOR误报 — 设置{sec}秒但响应{rt:.2f}秒 (<{threshold}秒). 注入未执行。",
                                  "en": "⚠️  WAITFOR false positive — {sec}s delay set but response was {rt:.2f}s (<{threshold}s). Not executed."},

    "cred_first_login_try":     {"ko": "🔑  추출된 자격증명으로 로그인 시도: {url}",
                                  "zh": "🔑  使用提取的凭据尝试登录: {url}",
                                  "en": "🔑  Trying extracted credentials on login: {url}"},

    "login_page_no_form":       {"ko": "⏭️  로그인 폼 없음 ({size}B) — 건너뜀: {url}",
                                  "zh": "⏭️  无登录表单 ({size}B) — 跳过: {url}",
                                  "en": "⏭️  No login form ({size}B) — skipping: {url}"},

    # ── 스크립트 강제 종료 피드백 (중복 제거됨 v3.2.91 — 원본은 ~1705) ───────

    # ── v3.2.91: LOOP_BLOCK 연속 차단 강제 탈출 안내 ─────────────────────
    "loop_block_escape_title":     {"ko": "⚠ LOOP_BLOCK 연속 {n}회 — 패턴 전환 필요",
                                    "zh": "⚠ 连续 {n} 次LOOP_BLOCK — 需要切换模式",
                                    "en": "⚠ LOOP_BLOCK fired {n} consecutive times — pattern switch required"},

    "loop_block_escape_body":      {"ko": (
                                        "같은 루프 패턴이 계속 차단되고 있습니다. 다른 열거 전략을 시도하세요:\n"
                                        "  1) seen=set() + while True + 커서 기반 (name > last_hex)\n"
                                        "  2) OFFSET N 기반 페이지네이션\n"
                                        "  3) NOT IN (already_found) 서브쿼리\n"
                                        "지금 바로 위 전략 중 하나로 코드를 재작성하세요."
                                    ),
                                    "zh": (
                                        "相同的循环模式持续被拦截，请尝试其他枚举策略：\n"
                                        "  1) seen=set() + while True + 游标 (name > last_hex)\n"
                                        "  2) 基于 OFFSET N 的分页\n"
                                        "  3) NOT IN (already_found) 子查询\n"
                                        "请立即用以上策略之一重写代码。"
                                    ),
                                    "en": (
                                        "The same loop pattern keeps getting blocked. Try a different enumeration strategy:\n"
                                        "  1) seen=set() + while True + cursor-based (name > last_hex)\n"
                                        "  2) OFFSET N pagination\n"
                                        "  3) NOT IN (already_found) subquery\n"
                                        "Rewrite code with one of these strategies NOW."
                                    )},

    # ── v3.2.95: ILR override 다국어 메시지 (iteration limiter로 교체) ─────────
    "ilr_override_title":       {"ko": "⚡ ILR {n}회 연속 차단 → override: 다음 실행 시 반복 제한기(500회) 자동 주입",
                                  "zh": "⚡ ILR 连续拦截{n}次 → override: 下次运行自动注入迭代限制器(最多500次)",
                                  "en": "⚡ ILR {n}x blocked → override: iteration limiter (max 500) auto-inject next run"},
    "ilr_override_body":        {"ko": ("INFINITE_LOOP_RISK가 코드를 3회 연속 차단했습니다.\n"
                                        "bingo가 다음 for/range 루프에 반복 제한기를 자동 주입하고 직접 실행합니다.\n"
                                        "  주입 내용: 루프 내 500회 초과 시 break 자동 삽입\n"
                                        "작업: 같은 열거 코드를 다시 생성하세요. bingo가 루프 가드를 자동으로 수정합니다."),
                                  "zh": ("INFINITE_LOOP_RISK 已连续拦截您的代码3次。\n"
                                         "bingo 将在下次 for/range 循环中自动注入迭代限制器并直接执行。\n"
                                         "  注入内容: 循环超过500次时自动 break\n"
                                         "操作: 重新生成相同的枚举代码，bingo 将自动修复循环保护。"),
                                  "en": ("INFINITE_LOOP_RISK blocked your code 3 times in a row.\n"
                                         "bingo will AUTO-INJECT an iteration limiter into your next for/range loop and run it.\n"
                                         "  Injected: _bingo_ilr_guard counter + break after 500 iterations\n"
                                         "ACTION: regenerate the same enumeration code. "
                                         "bingo will auto-fix the loop guard.")},

    # ── v3.2.91: Ctrl+C 힌트 프롬프트 / Stream Interrupted Messages ─────────
    "hint_loop_paused":         {"ko": ("⚡ [bold]루프 일시정지[/bold] — 힌트를 입력하면 중단 없이 계속 진행\n"
                                        "   (그냥 Enter 또는 Ctrl+C 한 번 더 → 완전 중단)"),
                                  "zh": ("⚡ [bold]循环暂停[/bold] — 输入提示则继续执行\n"
                                         "   (直接回车或再按Ctrl+C → 完全停止)"),
                                  "en": ("⚡ [bold]Loop paused[/bold] — type a hint to keep going\n"
                                         "   (press Enter or Ctrl+C again → stop completely)")},

    "stream_interrupted":       {"ko": "⏸ 응답 중단됨",
                                  "zh": "⏸ 已中断",
                                  "en": "⏸ Interrupted"},

    # ── v3.2.99: Ctrl+C 즉시 반응 관련 ─────────────────────────────────────
    "ctrl_c_killing_procs":     {"ko": "⚡ 실행 중인 스크립트 즉시 종료 중...",
                                  "zh": "⚡ 正在立即终止运行中的脚本...",
                                  "en": "⚡ Killing running scripts immediately..."},

    "ctrl_c_hint_ready":        {"ko": "✅ 중단 완료 — 이제 hint를 입력하세요 (Enter = 완전 중단)",
                                  "zh": "✅ 已中断 — 现在输入提示（回车 = 完全停止）",
                                  "en": "✅ Stopped — enter a hint now (Enter = stop completely)"},

    "exec_interrupted_partial": {"ko": "⚠ Ctrl+C — 부분 결과 수집 후 hint 입력 대기 중",
                                  "zh": "⚠ Ctrl+C — 收集部分结果后等待输入提示",
                                  "en": "⚠ Ctrl+C — collecting partial results, waiting for hint"},

    # ── v3.3.3: /dev/tty 기반 hint 입력 — VM/WSL 환경 근본 수정 ─────────────
    "hint_tty_active":          {"ko": "🔧 터미널 직접 입력 모드 (VM/Kali 환경 최적화)",
                                  "zh": "🔧 终端直接输入模式（针对 VM/Kali 环境优化）",
                                  "en": "🔧 Direct TTY input mode (optimized for VM/Kali env)"},

    "hint_tty_fallback":        {"ko": "ℹ  표준 입력 모드로 전환 중...",
                                  "zh": "ℹ  切换到标准输入模式...",
                                  "en": "ℹ  Falling back to standard input mode..."},

    "hint_termios_restored":    {"ko": "✅ 터미널 설정 복원 완료",
                                  "zh": "✅ 终端设置已恢复",
                                  "en": "✅ Terminal settings restored"},

    # ── Rule 17: 기법 소진 후 피벗 알림 ────────────────────────────────────
    "technique_exhausted":      {"ko": "🔄  [{param}] {technique} 3회 연속 실패 → 기법 소진, 다음으로 전환",
                                  "zh": "🔄  [{param}] {technique} 连续失败3次 → 技术耗尽, 切换下一个",
                                  "en": "🔄  [{param}] {technique} failed 3x in a row → technique exhausted, pivoting"},

    # ── Rule 18: requests timeout 자동 주입 알림 ────────────────────────────
    "requests_timeout_injected": {"ko": "⚠️  코드에 timeout=30 자동 주입됨 (서버 블로킹 방지)",
                                   "zh": "⚠️  已自动注入 timeout=30 (防止服务器阻塞)",
                                   "en": "⚠️  Auto-injected timeout=30 into requests calls (prevents server hang)"},

    # ── Rule 19: WAF ReadTimeout 피벗 알림 ──────────────────────────────
    "waf_timeout_detected":      {"ko": "🛡️  [{param}] ReadTimeout = WAF silent drop — 동일 페이로드 재시도 금지, 다음으로 전환",
                                   "zh": "🛡️  [{param}] ReadTimeout = WAF静默丢弃 — 禁止重试相同载荷, 切换下一个",
                                   "en": "🛡️  [{param}] ReadTimeout = WAF silent drop — do NOT retry same payload, pivoting"},

    # ── Rule 20: URL 연소 버그 자동 수정 알림 ───────────────────────────
    "url_concat_fixed":          {"ko": "🔧  URL 연소 버그 자동 수정: base_url + 'https://...' → 완전한 URL만 사용",
                                   "zh": "🔧  已修复URL拼接错误: base_url + 'https://...' → 仅使用完整URL",
                                   "en": "🔧  URL concat bug auto-fixed: base_url + 'https://...' → using full URL only"},

    # ── Syntax Precheck 메시지 ────────────────────────────────────────
    "syntax_precheck_warn":      {"ko": "⚠ [SYNTAX PRECHECK #{n}] 문법 오류 감지 — 자동 수정 실패. f-string 백슬래시 또는 dict 키 따옴표 충돌 확인 필요.",
                                   "zh": "⚠ [SYNTAX PRECHECK #{n}] 检测到语法错误 — 自动修复失败。请检查f-string反斜杠或dict下标引号冲突。",
                                   "en": "⚠ [SYNTAX PRECHECK #{n}] SyntaxError detected — auto-fix failed. Check f-string backslash or dict subscript issues."},

    # ── 인코딩 자동 감지 ──────────────────────────────────────────────
    "encoding_auto_detected":    {"ko": "🔤 인코딩 자동 감지: {enc} (EUC-KR/UTF-8/등 구형 사이트 대응)",
                                   "zh": "🔤 自动检测编码: {enc} (兼容EUC-KR/UTF-8等旧式网站)",
                                   "en": "🔤 Encoding auto-detected: {enc} (EUC-KR/UTF-8/legacy site support)"},
    "encoding_inject_notice":    {"ko": "🔤 [PRECHECK] r.text → smart_decode() 자동 교체 (인코딩 자동 감지)",
                                   "zh": "🔤 [PRECHECK] r.text → smart_decode() 已自动替换 (自动检测编码)",
                                   "en": "🔤 [PRECHECK] r.text → smart_decode() injected (auto encoding detection)"},

    # ── urllib.parse 자동 주입 ──────────────────────────────────────────
    "urllib_parse_injected":     {"ko": "🔧 [PRECHECK] import urllib.parse 자동 주입 (urllib3 와 혼용 오류 방지)",
                                   "zh": "🔧 [PRECHECK] import urllib.parse 已自动注入 (防止与urllib3混淆)",
                                   "en": "🔧 [PRECHECK] import urllib.parse injected (was missing, prevent NameError)"},

    # ── UTF-16LE 해시 오탐 필터 ──────────────────────────────────────────
    "hash_utf16le_skipped":      {"ko": "⚠️ [해시] UTF-16LE 인코딩 문자열로 오탐 감지 — 크랙 건너뜀: {h}",
                                   "zh": "⚠️ [哈希] 检测到UTF-16LE编码字符串误报 — 跳过破解: {h}",
                                   "en": "⚠️ [Hash] UTF-16LE encoded string detected as false positive — skipping crack: {h}"},

    # ── 세션 state 초기화 (보고서 환각 방지) ──────────────────────────────
    "session_state_cleared":     {"ko": "🗑️ 이전 세션 state 초기화 완료 (자격증명·테이블·DB 정보 리셋)",
                                   "zh": "🗑️ 已清除上次会话状态（凭据/表/数据库信息已重置）",
                                   "en": "🗑️ Previous session state cleared (credentials/tables/DB reset)"},
    "session_prev_data_warning": {"ko": "⚠️ 이전 세션 복원 — 아래 항목은 이번 세션에서 재확인되지 않음",
                                   "zh": "⚠️ 已恢复上次会话 — 以下项目本次未重新验证",
                                   "en": "⚠️ Session resumed — items below were NOT re-verified in this run"},
    "session_current_confirmed": {"ko": "✅ 현재 세션 확인 항목",
                                   "zh": "✅ 本次会话已确认项目",
                                   "en": "✅ Confirmed in current session"},

    # ── v2.4.0 SQLi 자동 단계 전환 ─────────────────────────────────────
    "sqli_stage_detecting":      {"ko": "🔍 SQLi 최적 기법 자동 탐지 중 ({param})...",
                                   "zh": "🔍 自动检测最优SQLi技术 ({param})...",
                                   "en": "🔍 Auto-detecting best SQLi stage for param: {param}..."},
    "sqli_stage_found":          {"ko": "✅ [SQLi] {stage} 기법 확인 — DB: {db_type}",
                                   "zh": "✅ [SQLi] 已确认 {stage} 技术 — 数据库: {db_type}",
                                   "en": "✅ [SQLi] Stage confirmed: {stage} — DB: {db_type}"},
    "sqli_stage_failed":         {"ko": "❌ [SQLi] 모든 기법 실패 — 해당 파라미터 주입 불가",
                                   "zh": "❌ [SQLi] 所有技术均失败 — 该参数不可注入",
                                   "en": "❌ [SQLi] All stages exhausted — parameter not injectable"},
    "sqli_db_detected":          {"ko": "🎯 DB 타입 감지: {db_type} (신뢰도: {confidence})",
                                   "zh": "🎯 检测到数据库类型: {db_type} (置信度: {confidence})",
                                   "en": "🎯 DB type detected: {db_type} (confidence: {confidence})"},

    # ── v2.4.0 DB 권한 상승 ─────────────────────────────────────────────
    "privesc_starting":          {"ko": "🔑 DB 권한 상승 자동 시도 시작 ({db_type})...",
                                   "zh": "🔑 开始自动数据库权限提升 ({db_type})...",
                                   "en": "🔑 Starting DB privilege escalation ({db_type})..."},
    "privesc_success":           {"ko": "🎉 DB 권한 상승 성공! 방법: {method}",
                                   "zh": "🎉 数据库权限提升成功！方法: {method}",
                                   "en": "🎉 DB privilege escalation succeeded! Method: {method}"},
    "privesc_failed":            {"ko": "⚠️ DB 권한 상승 실패 — 수동 시도 필요",
                                   "zh": "⚠️ 数据库权限提升失败 — 需要手动尝试",
                                   "en": "⚠️ DB privilege escalation failed — manual attempt required"},
    "xp_cmdshell_enabled":       {"ko": "🚀 xp_cmdshell 활성화 성공 — OS 명령 실행 가능",
                                   "zh": "🚀 xp_cmdshell 启用成功 — 可执行系统命令",
                                   "en": "🚀 xp_cmdshell enabled — OS command execution available"},

    # ── v2.4.0 웹쉘/리버스쉘 ───────────────────────────────────────────
    "shell_drop_starting":       {"ko": "🐚 웹쉘 배포 자동 시도 ({method})...",
                                   "zh": "🐚 开始自动部署WebShell ({method})...",
                                   "en": "🐚 Auto-deploying webshell ({method})..."},
    "shell_drop_success":        {"ko": "✅ 웹쉘 배포 성공: {url}  비번: {pwd}",
                                   "zh": "✅ WebShell 部署成功: {url}  密码: {pwd}",
                                   "en": "✅ Webshell deployed: {url}  password: {pwd}"},
    "shell_drop_failed":         {"ko": "❌ 웹쉘 배포 실패 — 수동 certutil/echo 시도 필요",
                                   "zh": "❌ WebShell 部署失败 — 需手动使用certutil/echo",
                                   "en": "❌ Webshell deployment failed — manual certutil/echo required"},
    "reverse_shell_ready":       {"ko": "🔄 리버스 쉘 페이로드 생성 완료 → nc -lvnp {lport}",
                                   "zh": "🔄 反弹Shell载荷已生成 → nc -lvnp {lport}",
                                   "en": "🔄 Reverse shell payload ready → nc -lvnp {lport}"},

    # ── v2.4.0 WAF 신규 시그니처 ───────────────────────────────────────
    "waf_new_detected":          {"ko": "🛡️ 신규 WAF 감지: {waf_type} — 전용 우회 전략 적용",
                                   "zh": "🛡️ 检测到新型WAF: {waf_type} — 应用专属绕过策略",
                                   "en": "🛡️ New WAF detected: {waf_type} — applying targeted bypass strategy"},

    # ── v2.5.0 신규 엔진 ─────────────────────────────────────────────
    "js_analyze_start":          {"ko": "🔍 JS 파일 자동 분석 시작... ({count}개 파일)",
                                   "zh": "🔍 开始自动分析JS文件... ({count}个文件)",
                                   "en": "🔍 Starting JS file auto-analysis... ({count} files)"},
    "js_analyze_done":           {"ko": "✅ JS 분석 완료 | 엔드포인트 {ep}개 | 시크릿 {sec}개 | 관리자 경로 {adm}개",
                                   "zh": "✅ JS分析完成 | 接口 {ep}个 | 密钥 {sec}个 | 管理路径 {adm}个",
                                   "en": "✅ JS analysis done | Endpoints: {ep} | Secrets: {sec} | Admin paths: {adm}"},
    "idor_scan_start":           {"ko": "🔁 IDOR 자동 스캔 시작 — 엔드포인트 {count}개",
                                   "zh": "🔁 开始IDOR自动扫描 — {count}个接口",
                                   "en": "🔁 Starting IDOR auto-scan — {count} endpoints"},
    "idor_found":                {"ko": "🚨 IDOR 발견: {url} ({id_type}) | 신뢰도: {conf}",
                                   "zh": "🚨 发现IDOR: {url} ({id_type}) | 置信度: {conf}",
                                   "en": "🚨 IDOR found: {url} ({id_type}) | Confidence: {conf}"},
    "idor_vertical_found":       {"ko": "🚨 수직 권한 상승: {url} — 일반 계정으로 관리자 접근 가능",
                                   "zh": "🚨 垂直权限提升: {url} — 普通账户可访问管理员接口",
                                   "en": "🚨 Vertical privilege escalation: {url} — user can access admin endpoint"},
    "auth_bypass_jwt":           {"ko": "🔓 JWT 취약점 발견: {method} — 관리자 토큰 위조 가능",
                                   "zh": "🔓 发现JWT漏洞: {method} — 可伪造管理员Token",
                                   "en": "🔓 JWT vulnerability found: {method} — admin token forgery possible"},
    "auth_bypass_admin":         {"ko": "🔓 미인증 관리자 접근: {url} (HTTP {status})",
                                   "zh": "🔓 未授权管理员访问: {url} (HTTP {status})",
                                   "en": "🔓 Unauthenticated admin access: {url} (HTTP {status})"},
    "ssrf_found":                {"ko": "🌐 SSRF 발견: {param}={url} → {evidence}",
                                   "zh": "🌐 发现SSRF: {param}={url} → {evidence}",
                                   "en": "🌐 SSRF found: {param}={url} → {evidence}"},
    "ssrf_aws_meta":             {"ko": "🚨 CRITICAL: AWS 메타데이터 노출! IAM 자격증명 탈취 가능",
                                   "zh": "🚨 严重: AWS元数据暴露! 可窃取IAM凭证",
                                   "en": "🚨 CRITICAL: AWS metadata exposed! IAM credentials at risk"},
    "xxe_found":                 {"ko": "📄 XXE 발견: {endpoint} → 서버 파일 읽기 성공",
                                   "zh": "📄 发现XXE: {endpoint} → 成功读取服务器文件",
                                   "en": "📄 XXE found: {endpoint} → server file read confirmed"},
    "upload_bypass_found":       {"ko": "📁 파일 업로드 우회 성공: {filename} ({mime}) → {url}",
                                   "zh": "📁 文件上传绕过成功: {filename} ({mime}) → {url}",
                                   "en": "📁 Upload bypass success: {filename} ({mime}) → {url}"},
    "cms_detected":              {"ko": "🏷️ CMS 감지: {cms_type} (신뢰도: {conf})",
                                   "zh": "🏷️ 检测到CMS: {cms_type} (置信度: {conf})",
                                   "en": "🏷️ CMS detected: {cms_type} (confidence: {conf})"},
    "cms_admin_exposed":         {"ko": "🚨 {cms_type} 관리자 경로 노출: {url}",
                                   "zh": "🚨 {cms_type}管理路径暴露: {url}",
                                   "en": "🚨 {cms_type} admin path exposed: {url}"},
    "post_exploit_start":        {"ko": "⚙️ Post-Exploit 자동화 시작 (OS: {os_type})",
                                   "zh": "⚙️ 开始后渗透自动化 (OS: {os_type})",
                                   "en": "⚙️ Post-exploit automation started (OS: {os_type})"},
    "post_exploit_cred":         {"ko": "🔑 자격증명 발견: {cred}",
                                   "zh": "🔑 发现凭证: {cred}",
                                   "en": "🔑 Credential found: {cred}"},
    "post_exploit_privesc":      {"ko": "⬆️ 권한 상승 벡터: {vector}",
                                   "zh": "⬆️ 权限提升向量: {vector}",
                                   "en": "⬆️ Privilege escalation vector: {vector}"},
    "report_saved_detail":        {"ko": "📋 보고서 저장: {path} (취약점 {count}건, CVSS 최고: {max_cvss})",
                                   "zh": "📋 报告已保存: {path} (漏洞 {count}个, 最高CVSS: {max_cvss})",
                                   "en": "📋 Report saved: {path} (vulnerabilities: {count}, max CVSS: {max_cvss})"},
    "report_save_ok":             {"ko": "💾 보고서 저장 완료",
                                   "zh": "💾 报告保存成功",
                                   "en": "💾 REPORT SAVED SUCCESSFULLY"},
    "report_save_path":           {"ko": "경로",
                                   "zh": "路径",
                                   "en": "PATH"},

    # ── v2.6.0 TIER1 신규 엔진 ────────────────────────────────────────────────
    "recon_start":               {"ko": "🌐 레콘 시작: {domain} — 서브도메인/포트/기술스택 자동 수집",
                                   "zh": "🌐 侦察开始: {domain} — 自动收集子域名/端口/技术栈",
                                   "en": "🌐 Recon started: {domain} — auto-collecting subdomains/ports/tech"},
    "recon_done":                {"ko": "✅ 레콘 완료 | 서브도메인 {sub}개 | 오픈포트 {ports}개 | 기술: {tech}",
                                   "zh": "✅ 侦察完成 | 子域名 {sub}个 | 开放端口 {ports}个 | 技术: {tech}",
                                   "en": "✅ Recon done | Subdomains: {sub} | Open ports: {ports} | Tech: {tech}"},
    "subdomain_takeover_found":  {"ko": "🚨 서브도메인 탈취 가능: {subdomain} → {service} CNAME 댕글링",
                                   "zh": "🚨 子域名可被接管: {subdomain} → {service} CNAME悬空",
                                   "en": "🚨 Subdomain takeover possible: {subdomain} → {service} CNAME dangling"},
    "subdomain_takeover_instr":  {"ko": "📌 탈취 방법: {instructions}",
                                   "zh": "📌 接管方法: {instructions}",
                                   "en": "📌 Takeover instructions: {instructions}"},
    "ssti_probe_start":          {"ko": "🧪 SSTI 탐지 시작: {param} 파라미터 ({engine_count}개 엔진)",
                                   "zh": "🧪 SSTI探测开始: {param}参数 ({engine_count}个引擎)",
                                   "en": "🧪 SSTI probing: {param} ({engine_count} engines)"},
    "ssti_engine_found":         {"ko": "🚨 SSTI 확인! 엔진: {engine} | 파라미터: {param} | RCE 페이로드 준비됨",
                                   "zh": "🚨 SSTI已确认! 引擎: {engine} | 参数: {param} | RCE载荷已准备",
                                   "en": "🚨 SSTI confirmed! Engine: {engine} | Param: {param} | RCE payload ready"},
    "ssti_rce_confirmed":        {"ko": "🔴 SSTI RCE 성공: {engine} → 명령 실행 결과: {output}",
                                   "zh": "🔴 SSTI RCE成功: {engine} → 命令执行结果: {output}",
                                   "en": "🔴 SSTI RCE confirmed: {engine} → cmd output: {output}"},
    "param_fuzz_start":          {"ko": "🔍 숨겨진 파라미터 탐색 중... ({count}개 후보)",
                                   "zh": "🔍 正在发掘隐藏参数... ({count}个候选)",
                                   "en": "🔍 Discovering hidden parameters... ({count} candidates)"},
    "param_found":               {"ko": "✨ 신규 파라미터 발견: {param} (상태: {status})",
                                   "zh": "✨ 发现新参数: {param} (状态: {status})",
                                   "en": "✨ New parameter found: {param} (status: {status})"},
    "header_bypass_found":       {"ko": "🔓 헤더 우회 성공: {header}: {value} → HTTP {status}",
                                   "zh": "🔓 Header绕过成功: {header}: {value} → HTTP {status}",
                                   "en": "🔓 Header bypass success: {header}: {value} → HTTP {status}"},
    "smuggling_found":           {"ko": "🚨 HTTP 스머글링 발견: {technique} | 응답시간: {time}s",
                                   "zh": "🚨 发现HTTP请求走私: {technique} | 响应时间: {time}s",
                                   "en": "🚨 HTTP smuggling found: {technique} | Response time: {time}s"},
    "race_found":                {"ko": "⚡ 레이스 컨디션 발견: {endpoint} | 상태 변형: {statuses}",
                                   "zh": "⚡ 发现竞争条件: {endpoint} | 状态变化: {statuses}",
                                   "en": "⚡ Race condition found: {endpoint} | Status variation: {statuses}"},

    # ── v2.6.0 TIER2 신규 엔진 ────────────────────────────────────────────────
    "graphql_batch_dos":         {"ko": "⚠️ GraphQL 배칭 DoS 가능: {count}개 쿼리 → {time}s",
                                   "zh": "⚠️ GraphQL批量DoS可行: {count}个查询 → {time}s",
                                   "en": "⚠️ GraphQL batch DoS possible: {count} queries → {time}s"},
    "twofa_bypass_found":        {"ko": "🔓 2FA 우회 성공: {technique} | 엔드포인트: {endpoint}",
                                   "zh": "🔓 2FA绕过成功: {technique} | 接口: {endpoint}",
                                   "en": "🔓 2FA bypass found: {technique} | Endpoint: {endpoint}"},
    "otp_brute_success":         {"ko": "🚨 OTP 브루트포스 성공: {code} | 레이트리밋 없음",
                                   "zh": "🚨 OTP爆破成功: {code} | 无频率限制",
                                   "en": "🚨 OTP brute-force success: {code} | No rate limiting"},
    "cache_poison_found":        {"ko": "☠️ 캐시 포이즈닝 발견: {header} → {domain} 캐시됨",
                                   "zh": "☠️ 发现缓存投毒: {header} → {domain}已缓存",
                                   "en": "☠️ Cache poisoning found: {header} → {domain} cached"},
    "cache_deception_found":     {"ko": "☠️ 캐시 디셉션: {path} → 인증 데이터 {bytes}바이트 캐시됨",
                                   "zh": "☠️ 缓存欺骗: {path} → 认证数据{bytes}字节已缓存",
                                   "en": "☠️ Cache deception: {path} → {bytes} bytes of auth data cached"},
    "deserialize_java_found":    {"ko": "🚨 Java 역직렬화 엔드포인트 발견: {endpoint} | ysoserial 사용 권장",
                                   "zh": "🚨 发现Java反序列化接口: {endpoint} | 建议使用ysoserial",
                                   "en": "🚨 Java deserialization endpoint found: {endpoint} | Use ysoserial"},
    "deserialize_viewstate":     {"ko": "⚠️ .NET ViewState (MAC 없음) 발견: {url} | ysoserial.net 사용 가능",
                                   "zh": "⚠️ 发现.NET ViewState(无MAC): {url} | 可使用ysoserial.net",
                                   "en": "⚠️ .NET ViewState without MAC: {url} | ysoserial.net applicable"},

    # ── v2.6.0 TIER3 신규 엔진 ────────────────────────────────────────────────
    "nuclei_start":              {"ko": "🔫 Nuclei 스캔 시작: {target} ({mode}모드)",
                                   "zh": "🔫 Nuclei扫描开始: {target} ({mode}模式)",
                                   "en": "🔫 Nuclei scan started: {target} ({mode} mode)"},
    "nuclei_found":              {"ko": "🎯 Nuclei 취약점: [{severity}] {name} @ {url}",
                                   "zh": "🎯 Nuclei发现漏洞: [{severity}] {name} @ {url}",
                                   "en": "🎯 Nuclei finding: [{severity}] {name} @ {url}"},
    "nuclei_done":               {"ko": "✅ Nuclei 완료: {critical}개 CRITICAL | {high}개 HIGH | {total}개 총계",
                                   "zh": "✅ Nuclei完成: {critical}个CRITICAL | {high}个HIGH | {total}个总计",
                                   "en": "✅ Nuclei done: {critical} CRITICAL | {high} HIGH | {total} total"},
    "bizlogic_negative":         {"ko": "💸 비즈니스 로직: 음수 금액 허용 ({amount}) → 환급 공격 가능",
                                   "zh": "💸 业务逻辑: 允许负金额({amount}) → 可发起退款攻击",
                                   "en": "💸 BizLogic: Negative amount accepted ({amount}) → refund attack possible"},
    "dom_xss_found":             {"ko": "🌐 DOM XSS Source/Sink 발견: {source} → {sink} @ {file}:{line}",
                                   "zh": "🌐 发现DOM XSS Source/Sink: {source} → {sink} @ {file}:{line}",
                                   "en": "🌐 DOM XSS source/sink: {source} → {sink} @ {file}:{line}"},
    "dom_xss_confirmed":         {"ko": "🚨 DOM XSS 확인: {url} | PoC: {poc}",
                                   "zh": "🚨 DOM XSS已确认: {url} | PoC: {poc}",
                                   "en": "🚨 DOM XSS confirmed: {url} | PoC: {poc}"},
    "api_version_unauth":        {"ko": "🔓 구버전 API 미인증 접근: {path} (HTTP {status}) — 인증 없이 데이터 노출",
                                   "zh": "🔓 旧版API未授权访问: {path} (HTTP {status}) — 未鉴权数据泄露",
                                   "en": "🔓 Old API version unauth: {path} (HTTP {status}) — data exposed without auth"},
    "api_version_regression":    {"ko": "⚠️ API 보안 회귀: {path} — {signals}",
                                   "zh": "⚠️ API安全回归: {path} — {signals}",
                                   "en": "⚠️ API security regression: {path} — {signals}"},
    "bucket_public_found":       {"ko": "🪣 공개 버킷 발견: {provider} | {bucket} | 목록조회: {listable}",
                                   "zh": "🪣 发现公开Bucket: {provider} | {bucket} | 可列举: {listable}",
                                   "en": "🪣 Public bucket found: {provider} | {bucket} | Listable: {listable}"},
    "bucket_sensitive_found":    {"ko": "🚨 버킷 민감파일 노출: {bucket} | {files}",
                                   "zh": "🚨 Bucket敏感文件暴露: {bucket} | {files}",
                                   "en": "🚨 Bucket sensitive files exposed: {bucket} | {files}"},

    # ── v2.9.3 DB 자동 전체 덤프 엔진 ────────────────────────────────────────
    "dump_save_dir":             {"ko": "📂 덤프 저장 위치: {path}",
                                   "zh": "📂 转储保存位置: {path}",
                                   "en": "📂 Dump save path: {path}"},
    "dump_no_limit":             {"ko": "⚠️  행 수 제한 없음 — 전체 {count:,}행 전부 덤프",
                                   "zh": "⚠️  无行数限制 — 全量转储 {count:,}行",
                                   "en": "⚠️  No row limit — dumping all {count:,} rows"},
    "dump_start":                {"ko": "💾 DB 자동 덤프 시작: {db_type} | DB: {db_name} | 사용자: {db_user}",
                                   "zh": "💾 DB自动转储开始: {db_type} | 数据库: {db_name} | 用户: {db_user}",
                                   "en": "💾 DB auto-dump started: {db_type} | DB: {db_name} | User: {db_user}"},
    "dump_tables_found":         {"ko": "📋 테이블 발견: {total}개 (관리자: {admin}개 | 회원: {member}개 | 민감: {sensitive}개)",
                                   "zh": "📋 发现表: {total}个 (管理员: {admin}个 | 会员: {member}个 | 敏感: {sensitive}个)",
                                   "en": "📋 Tables found: {total} (admin: {admin} | member: {member} | sensitive: {sensitive})"},
    "dump_table_start":          {"ko": "⬇️  [{category}] {table} 덤프 중... (총 {count:,}행)",
                                   "zh": "⬇️  [{category}] {table} 转储中... (共{count:,}行)",
                                   "en": "⬇️  [{category}] dumping {table}... ({count:,} rows total)"},
    "dump_table_done":           {"ko": "✅ [{category}] {table} 완료: {rows:,}행 → {path}",
                                   "zh": "✅ [{category}] {table} 完成: {rows:,}行 → {path}",
                                   "en": "✅ [{category}] {table} done: {rows:,} rows → {path}"},
    "dump_admin_found":          {"ko": "🔑 관리자 테이블 덤프 완료: {table} | {rows:,}건 | 크리덴셜: {creds}개",
                                   "zh": "🔑 管理员表转储完成: {table} | {rows:,}条 | 凭据: {creds}个",
                                   "en": "🔑 Admin table dumped: {table} | {rows:,} rows | Credentials: {creds}"},
    "dump_member_found":         {"ko": "👥 회원 테이블 덤프 완료: {table} | {rows:,}명 | 비밀번호: {pw_col}",
                                   "zh": "👥 会员表转储完成: {table} | {rows:,}人 | 密码列: {pw_col}",
                                   "en": "👥 Member table dumped: {table} | {rows:,} users | Password col: {pw_col}"},
    "dump_credentials_saved":    {"ko": "🗝️  크리덴셜 추출: {count:,}건 → {path}",
                                   "zh": "🗝️  凭据提取: {count:,}条 → {path}",
                                   "en": "🗝️  Credentials extracted: {count:,} entries → {path}"},
    "dump_complete":             {"ko": "🏁 DB 덤프 완료 | 테이블 {tables}개 | 총 {records:,}건 | 저장: {save_dir}",
                                   "zh": "🏁 DB转储完成 | 表{tables}个 | 共{records:,}条 | 保存: {save_dir}",
                                   "en": "🏁 DB dump complete | {tables} tables | {records:,} total records | Saved: {save_dir}"},
    "dump_sqli_union":           {"ko": "🔀 UNION SQLi 덤프: {table}.{col} — {count}개 추출",
                                   "zh": "🔀 UNION SQLi转储: {table}.{col} — 提取{count}个",
                                   "en": "🔀 UNION SQLi dump: {table}.{col} — {count} extracted"},
    "dump_webshell_cmd":         {"ko": "💻 WebShell 덤프 명령어 생성: {db_type} → {table}",
                                   "zh": "💻 生成WebShell转储命令: {db_type} → {table}",
                                   "en": "💻 WebShell dump command generated: {db_type} → {table}"},
    "dump_admin_login_try":      {"ko": "🔐 관리자 크리덴셜 획득 → {admin_url} 로그인 시도 중...",
                                   "zh": "🔐 获取管理员凭据 → 正在尝试登录 {admin_url}...",
                                   "en": "🔐 Admin credentials obtained → trying login at {admin_url}..."},
    "dump_hash_crack_suggest":   {"ko": "⚡ 해시 크래킹 권장: hashcat -m {mode} hashes.txt /usr/share/wordlists/rockyou.txt",
                                   "zh": "⚡ 建议破解Hash: hashcat -m {mode} hashes.txt /usr/share/wordlists/rockyou.txt",
                                   "en": "⚡ Hash cracking suggested: hashcat -m {mode} hashes.txt /usr/share/wordlists/rockyou.txt"},

    # ── v2.8.0 Advanced SQLi ────────────────────────────────────────────────
    "sqli_adv_start":            {"ko": "🔬 [SQLi 고급] {url} — Level:{level} Risk:{risk} WAF:{waf}",
                                   "zh": "🔬 [高级SQLi] {url} — Level:{level} Risk:{risk} WAF:{waf}",
                                   "en": "🔬 [SQLi Advanced] {url} — Level:{level} Risk:{risk} WAF:{waf}"},
    "sqli_adv_tamper_selected":  {"ko": "🛡️ WAF={waf} → Tamper 자동선택: {tampers}",
                                   "zh": "🛡️ WAF={waf} → 自动选择Tamper: {tampers}",
                                   "en": "🛡️ WAF={waf} → Tampers auto-selected: {tampers}"},
    "sqli_adv_db_detected":      {"ko": "🗄️ DB 타입 탐지: {db_type} (버전: {version})",
                                   "zh": "🗄️ 检测到数据库类型: {db_type} (版本: {version})",
                                   "en": "🗄️ DB type detected: {db_type} (version: {version})"},
    "sqli_adv_error_found":      {"ko": "✅ Error-Based SQLi 발견! 파라미터: {param} | DB: {db_type}",
                                   "zh": "✅ 发现Error-Based SQLi! 参数: {param} | DB: {db_type}",
                                   "en": "✅ Error-Based SQLi found! Param: {param} | DB: {db_type}"},
    "sqli_adv_time_found":       {"ko": "✅ Time-Based 블라인드 SQLi 발견! {param} — 응답지연 {delay}s",
                                   "zh": "✅ 发现Time-Based盲注! {param} — 响应延迟 {delay}s",
                                   "en": "✅ Time-Based blind SQLi found! {param} — delay {delay}s"},
    "sqli_adv_union_cols":       {"ko": "📊 UNION 컬럼 수 탐지: {cols}개",
                                   "zh": "📊 检测到UNION列数: {cols}",
                                   "en": "📊 UNION column count detected: {cols}"},
    "sqli_adv_file_read":        {"ko": "📂 LOAD_FILE 성공: {path}",
                                   "zh": "📂 LOAD_FILE成功: {path}",
                                   "en": "📂 LOAD_FILE success: {path}"},
    "sqli_adv_file_read_fail":   {"ko": "📂 LOAD_FILE 실패 (권한부족/secure_file_priv): {path}",
                                   "zh": "📂 LOAD_FILE失败(权限不足): {path}",
                                   "en": "📂 LOAD_FILE failed (permission/secure_file_priv): {path}"},
    "sqli_adv_webshell_written": {"ko": "💀 웹쉘 쓰기 성공! → {shell_url}",
                                   "zh": "💀 WebShell写入成功! → {shell_url}",
                                   "en": "💀 WebShell written successfully! → {shell_url}"},
    "sqli_adv_stacked_rce":      {"ko": "💥 Stacked Queries RCE 성공! ({db_type})",
                                   "zh": "💥 Stacked Queries RCE成功! ({db_type})",
                                   "en": "💥 Stacked Queries RCE achieved! ({db_type})"},
    "sqli_adv_oob_sent":         {"ko": "📡 OOB 페이로드 전송 → {domain} (외부 DNS 확인 필요)",
                                   "zh": "📡 已发送OOB Payload → {domain} (需要检查外部DNS)",
                                   "en": "📡 OOB payload sent → {domain} (check external DNS)"},
    "sqli_adv_hash_found":       {"ko": "🔑 해시 발견: {hash_type} → {hash_val[:20]}... | 크래킹: {crack_cmd}",
                                   "zh": "🔑 发现Hash: {hash_type} → {hash_val[:20]}... | 破解: {crack_cmd}",
                                   "en": "🔑 Hash found: {hash_type} → {hash_val[:20]}... | crack: {crack_cmd}"},
    "sqli_adv_hash_cracked":     {"ko": "🎯 해시 크래킹 성공! {hash_type}: {hash_val} → 평문: {plaintext}",
                                   "zh": "🎯 Hash破解成功! {hash_type}: {hash_val} → 明文: {plaintext}",
                                   "en": "🎯 Hash cracked! {hash_type}: {hash_val} → plaintext: {plaintext}"},
    "sqli_adv_header_vuln":      {"ko": "⚠️ 헤더 인젝션 취약! [{header}] — 응답지연 {delay}s",
                                   "zh": "⚠️ 头部注入漏洞! [{header}] — 延迟 {delay}s",
                                   "en": "⚠️ Header injection vulnerable! [{header}] — delay {delay}s"},
    "sqli_adv_second_order":     {"ko": "🔄 2차 인젝션 탐지! 저장위치: {store_url} → 트리거: {trigger_url}",
                                   "zh": "🔄 检测到二阶注入! 存储: {store_url} → 触发: {trigger_url}",
                                   "en": "🔄 Second-order injection detected! Store: {store_url} → Trigger: {trigger_url}"},
    "sqli_adv_udf_shell":        {"ko": "🐚 UDF 쉘 획득! 명령 실행 가능: sys_exec('{cmd}')",
                                   "zh": "🐚 获得UDF Shell! 可执行命令: sys_exec('{cmd}')",
                                   "en": "🐚 UDF shell obtained! Command exec: sys_exec('{cmd}')"},
    "sqli_adv_summary":          {"ko": "📋 SQLi 고급 스캔 완료 | 포인트:{findings}개 | 파일읽기:{files}개 | 해시:{hashes}개 | RCE:{rce}",
                                   "zh": "📋 高级SQLi扫描完成 | 注入点:{findings} | 文件读取:{files} | Hash:{hashes} | RCE:{rce}",
                                   "en": "📋 Advanced SQLi scan complete | Points:{findings} | FileRead:{files} | Hashes:{hashes} | RCE:{rce}"},
    "sqli_adv_config_read":      {"ko": "🔓 설정파일 읽기 성공: DB={db} / USER={user} / PASS={password}",
                                   "zh": "🔓 读取配置文件成功: DB={db} / USER={user} / PASS={password}",
                                   "en": "🔓 Config file read: DB={db} / USER={user} / PASS={password}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — XSS Exploiter
    # ──────────────────────────────────────────────────────────────────────────
    "xss_scan_start":            {"ko": "🔍 XSS 자동 공격 스캔 시작: {url}",
                                   "zh": "🔍 开始XSS自动攻击扫描: {url}",
                                   "en": "🔍 Starting XSS auto-exploit scan: {url}"},
    "xss_found_reflected":       {"ko": "⚠️ 반사형 XSS 발견! 파라미터: {param} | 컨텍스트: {ctx}",
                                   "zh": "⚠️ 发现反射型XSS! 参数: {param} | 上下文: {ctx}",
                                   "en": "⚠️ Reflected XSS found! Param: {param} | Context: {ctx}"},
    "xss_session_hijack":        {"ko": "🍪 세션 하이재킹 페이로드 생성 완료 → exfil: {exfil_url}",
                                   "zh": "🍪 会话劫持载荷生成完成 → exfil: {exfil_url}",
                                   "en": "🍪 Session hijack payload generated → exfil: {exfil_url}"},
    "xss_keylogger_injected":    {"ko": "⌨️ 키로거 삽입 완료 — 입력값 캡처 시작",
                                   "zh": "⌨️ 键盘记录器注入完成 — 开始捕获输入",
                                   "en": "⌨️ Keylogger injected — capturing keystrokes"},
    "xss_csrf_chain":            {"ko": "🔗 Stored XSS → CSRF 체인 생성: 대상={target}",
                                   "zh": "🔗 Stored XSS → CSRF链生成: 目标={target}",
                                   "en": "🔗 Stored XSS → CSRF chain: target={target}"},
    "xss_csp_bypass":            {"ko": "🛡️ CSP 우회 시도: nonce={nonce} / 신뢰도메인={domain}",
                                   "zh": "🛡️ 尝试绕过CSP: nonce={nonce} / 信任域={domain}",
                                   "en": "🛡️ CSP bypass attempt: nonce={nonce} / trusted={domain}"},
    "xss_summary":               {"ko": "📋 XSS 스캔 완료 | 발견:{count}개 | 세션탈취:{hijack} | 키로거:{keylog}",
                                   "zh": "📋 XSS扫描完成 | 发现:{count} | 会话劫持:{hijack} | 键盘记录:{keylog}",
                                   "en": "📋 XSS scan complete | Found:{count} | Hijack:{hijack} | Keylog:{keylog}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — Upload Exploiter
    # ──────────────────────────────────────────────────────────────────────────
    "upload_scan_start":         {"ko": "📁 파일 업로드 취약점 스캔 시작: {url}",
                                   "zh": "📁 开始文件上传漏洞扫描: {url}",
                                   "en": "📁 Starting file upload exploit scan: {url}"},
    "upload_htaccess_success":   {"ko": "✅ .htaccess 업로드 성공! PHP 강제 실행 가능",
                                   "zh": "✅ .htaccess上传成功! 可强制执行PHP",
                                   "en": "✅ .htaccess upload success! PHP exec forced"},
    "upload_ext_bypass":         {"ko": "✅ 확장자 우회 성공! {ext} → 경로: {path}",
                                   "zh": "✅ 扩展名绕过成功! {ext} → 路径: {path}",
                                   "en": "✅ Extension bypass success! {ext} → path: {path}"},
    "upload_rce_confirmed":      {"ko": "🔴 웹쉘 RCE 확인! URL: {shell_url} | 출력: {output}",
                                   "zh": "🔴 WebShell RCE确认! URL: {shell_url} | 输出: {output}",
                                   "en": "🔴 WebShell RCE confirmed! URL: {shell_url} | Output: {output}"},
    "upload_polyglot":           {"ko": "🎭 폴리글롯 쉘 생성: GIF89a + PHP (MIME 우회)",
                                   "zh": "🎭 生成多语言Shell: GIF89a + PHP (MIME绕过)",
                                   "en": "🎭 Polyglot shell: GIF89a + PHP (MIME bypass)"},
    "upload_summary":            {"ko": "📋 업로드 스캔 완료 | 성공:{count}개 | RCE:{rce}개",
                                   "zh": "📋 上传扫描完成 | 成功:{count} | RCE:{rce}",
                                   "en": "📋 Upload scan complete | Success:{count} | RCE:{rce}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — SSRF Advanced Engine
    # ──────────────────────────────────────────────────────────────────────────
    "ssrf_scan_start":           {"ko": "🌐 SSRF 고급 스캔 시작: {url}",
                                   "zh": "🌐 开始高级SSRF扫描: {url}",
                                   "en": "🌐 Starting advanced SSRF scan: {url}"},
    "ssrf_aws_imds_found":       {"ko": "☁️ AWS IMDS 접근 성공! IAM 자격증명 탈취: {role}",
                                   "zh": "☁️ AWS IMDS访问成功! IAM凭证已窃取: {role}",
                                   "en": "☁️ AWS IMDS access! IAM creds stolen: {role}"},
    "ssrf_gopher_redis":         {"ko": "🔑 Gopher Redis 공격 성공 → 웹쉘 경로: {path}",
                                   "zh": "🔑 Gopher Redis攻击成功 → WebShell路径: {path}",
                                   "en": "🔑 Gopher Redis exploit → WebShell: {path}"},
    "ssrf_internal_found":       {"ko": "🏠 내부 서비스 발견: {host}:{port}",
                                   "zh": "🏠 发现内部服务: {host}:{port}",
                                   "en": "🏠 Internal service found: {host}:{port}"},
    "ssrf_bypass_success":       {"ko": "🔓 SSRF 필터 우회 성공: {bypass_url}",
                                   "zh": "🔓 SSRF过滤器绕过成功: {bypass_url}",
                                   "en": "🔓 SSRF filter bypass: {bypass_url}"},
    "ssrf_summary":              {"ko": "📋 SSRF 스캔 완료 | 발견:{count}개 | 클라우드:{cloud} | 내부망:{internal}개",
                                   "zh": "📋 SSRF扫描完成 | 发现:{count} | 云:{cloud} | 内网:{internal}",
                                   "en": "📋 SSRF scan complete | Found:{count} | Cloud:{cloud} | Internal:{internal}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — Admin Panel Auto
    # ──────────────────────────────────────────────────────────────────────────
    "admin_scan_start":          {"ko": "🔐 관리자 패널 자동화 시작: {url}",
                                   "zh": "🔐 开始管理员面板自动化: {url}",
                                   "en": "🔐 Starting admin panel automation: {url}"},
    "admin_panel_found":         {"ko": "✅ 관리자 패널 발견: {panel_url}",
                                   "zh": "✅ 发现管理员面板: {panel_url}",
                                   "en": "✅ Admin panel found: {panel_url}"},
    "admin_login_success":       {"ko": "🎉 관리자 로그인 성공! ID:{username} PW:{password}",
                                   "zh": "🎉 管理员登录成功! ID:{username} PW:{password}",
                                   "en": "🎉 Admin login success! ID:{username} PW:{password}"},
    "admin_login_failed":        {"ko": "❌ 관리자 로그인 실패: 자격증명 소진",
                                   "zh": "❌ 管理员登录失败: 凭证耗尽",
                                   "en": "❌ Admin login failed: credentials exhausted"},
    "admin_csrf_extracted":      {"ko": "🛡️ CSRF 토큰 추출: {token}",
                                   "zh": "🛡️ CSRF令牌提取: {token}",
                                   "en": "🛡️ CSRF token extracted: {token}"},
    "admin_screenshot":          {"ko": "📸 관리자 패널 스크린샷 촬영 완료",
                                   "zh": "📸 管理员面板截图完成",
                                   "en": "📸 Admin panel screenshot captured"},
    "admin_summary":             {"ko": "📋 관리자 패널 스캔 | 패널:{panel} | 로그인:{login} | 기능:{funcs}개",
                                   "zh": "📋 管理员面板扫描 | 面板:{panel} | 登录:{login} | 功能:{funcs}",
                                   "en": "📋 Admin panel scan | Panel:{panel} | Login:{login} | Functions:{funcs}"},

    # v3.0.4 — Post-Credential: Admin Page Discovery + IP Restriction Bypass
    # ──────────────────────────────────────────────────────────────────────────
    "post_cred_start":           {"ko": "🔑 크리덴셜 확보 완료 — 관리자 패널 탐색 시작",
                                   "zh": "🔑 凭据确认 — 开始搜索管理员面板",
                                   "en": "🔑 Credentials confirmed — starting admin panel discovery"},
    "admin_page_searching":      {"ko": "🔍 관리자 페이지 경로 탐색 중... ({count}개 경로 시도)",
                                   "zh": "🔍 正在搜索管理员页面路径... (尝试{count}条路径)",
                                   "en": "🔍 Searching admin page paths... ({count} paths tested)"},
    "admin_page_not_found":      {"ko": "⚠️ 관리자 페이지 경로 미발견 ({count}개 경로 소진) — 크리덴셜만 확보된 상태",
                                   "zh": "⚠️ 未找到管理员页面路径 (已尝试{count}条) — 仅持有凭据",
                                   "en": "⚠️ Admin page not found ({count} paths exhausted) — credentials obtained only"},
    "ip_restrict_detected":      {"ko": "🚫 IP 제한 감지됨: {msg} — 우회 시도 시작",
                                   "zh": "🚫 检测到IP限制: {msg} — 开始尝试绕过",
                                   "en": "🚫 IP restriction detected: {msg} — attempting bypass"},
    "ip_bypass_trying":          {"ko": "🔄 IP 우회 시도 [{idx}/{total}]: {header}: {value}",
                                   "zh": "🔄 尝试IP绕过 [{idx}/{total}]: {header}: {value}",
                                   "en": "🔄 Trying IP bypass [{idx}/{total}]: {header}: {value}"},
    "ip_bypass_success":         {"ko": "✅ IP 제한 우회 성공! 헤더: {header}: {value}",
                                   "zh": "✅ IP限制绕过成功！标头: {header}: {value}",
                                   "en": "✅ IP restriction bypassed! Header: {header}: {value}"},
    "ip_bypass_failed":          {"ko": "❌ 모든 IP 우회 방법 실패 ({count}개 시도) — 보고서에 기재됨",
                                   "zh": "❌ 所有IP绕过方法失败 (已尝试{count}种) — 已记录至报告",
                                   "en": "❌ All IP bypass methods failed ({count} tried) — recorded in report"},
    "ip_bypass_ssrf":            {"ko": "🔀 SSRF로 내부 관리자 접근 시도: {admin_url}",
                                   "zh": "🔀 通过SSRF尝试内部管理员访问: {admin_url}",
                                   "en": "🔀 Attempting admin access via SSRF: {admin_url}"},
    "ip_bypass_realip":          {"ko": "🌐 Cloudflare 우회: 실서버 IP {real_ip} 직접 접근 시도",
                                   "zh": "🌐 Cloudflare绕过: 直接访问真实服务器IP {real_ip}",
                                   "en": "🌐 Cloudflare bypass: direct access to real server IP {real_ip}"},
    "cred_only_report":          {"ko": "📄 [CRITICAL] 관리자 크리덴셜 탈취 — 관리자 페이지 접근 대기 중\n  ID: {admin_id}\n  PW: {admin_pw}\n  덤프 위치: {dump_path}",
                                   "zh": "📄 [CRITICAL] 管理员凭据已窃取 — 等待管理员页面访问\n  ID: {admin_id}\n  PW: {admin_pw}\n  转储位置: {dump_path}",
                                   "en": "📄 [CRITICAL] Admin credentials stolen — admin panel access pending\n  ID: {admin_id}\n  PW: {admin_pw}\n  Dump: {dump_path}"},
    "ip_restrict_report":        {"ko": "📄 [CRITICAL] 관리자 크리덴셜 탈취 + IP 제한 우회 실패\n  관리자 페이지: {admin_url}\n  시도한 우회: {bypass_methods}\n  크리덴셜 자체가 CRITICAL 증거",
                                   "zh": "📄 [CRITICAL] 管理员凭据已窃取 + IP限制绕过失败\n  管理员页面: {admin_url}\n  尝试的绕过: {bypass_methods}\n  凭据本身即为CRITICAL证据",
                                   "en": "📄 [CRITICAL] Admin creds stolen + IP restriction bypass failed\n  Admin page: {admin_url}\n  Bypass tried: {bypass_methods}\n  Credentials alone are CRITICAL evidence"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — JS Secret Finder
    # ──────────────────────────────────────────────────────────────────────────
    "js_scan_start":             {"ko": "🔎 JS 비밀 탐지 스캔 시작: {url}",
                                   "zh": "🔎 开始JS秘密检测扫描: {url}",
                                   "en": "🔎 Starting JS secret scan: {url}"},
    "js_endpoint_found":         {"ko": "🌐 숨겨진 API 발견: {endpoint}",
                                   "zh": "🌐 发现隐藏API: {endpoint}",
                                   "en": "🌐 Hidden API endpoint: {endpoint}"},
    "js_jwt_forged":             {"ko": "🎭 JWT alg:none 위조 성공: {forged}",
                                   "zh": "🎭 JWT alg:none伪造成功: {forged}",
                                   "en": "🎭 JWT alg:none forged: {forged}"},
    "js_summary":                {"ko": "📋 JS 스캔 완료 | 비밀:{secrets}개 | API:{endpoints}개 | JWT:{jwt}개",
                                   "zh": "📋 JS扫描完成 | 秘密:{secrets} | API:{endpoints} | JWT:{jwt}",
                                   "en": "📋 JS scan complete | Secrets:{secrets} | APIs:{endpoints} | JWTs:{jwt}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — HTTP Request Smuggling Exploiter
    # ──────────────────────────────────────────────────────────────────────────
    "smuggling_scan_start":      {"ko": "🚢 HTTP 스머글링 스캔 시작: {url}",
                                   "zh": "🚢 开始HTTP走私扫描: {url}",
                                   "en": "🚢 Starting HTTP smuggling scan: {url}"},
    "smuggling_clte_found":      {"ko": "⚠️ CL.TE 스머글링 취약! 지연: {delay}s",
                                   "zh": "⚠️ CL.TE走私漏洞! 延迟: {delay}s",
                                   "en": "⚠️ CL.TE smuggling vulnerable! Delay: {delay}s"},
    "smuggling_tecl_found":      {"ko": "⚠️ TE.CL 스머글링 취약! 관리자 요청 독살 시도",
                                   "zh": "⚠️ TE.CL走私漏洞! 尝试毒化管理员请求",
                                   "en": "⚠️ TE.CL smuggling! Poisoning admin request"},
    "smuggling_admin_bypass":    {"ko": "🔴 관리자 접근 우회 성공! 스머글링으로 /admin 접근",
                                   "zh": "🔴 管理员访问绕过成功! 通过走私访问/admin",
                                   "en": "🔴 Admin bypass via smuggling! /admin accessed"},
    "smuggling_summary":         {"ko": "📋 스머글링 스캔 완료 | 발견:{count}개 | 유형:{types}",
                                   "zh": "📋 走私扫描完成 | 发现:{count} | 类型:{types}",
                                   "en": "📋 Smuggling scan complete | Found:{count} | Types:{types}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — GraphQL Advanced Engine
    # ──────────────────────────────────────────────────────────────────────────
    "graphql_scan_start":        {"ko": "📊 GraphQL 고급 스캔 시작: {url}",
                                   "zh": "📊 开始GraphQL高级扫描: {url}",
                                   "en": "📊 Starting GraphQL advanced scan: {url}"},
    "graphql_introspection":     {"ko": "📖 GraphQL 스키마 덤프 완료: 타입={types}개 | 뮤테이션={muts}개",
                                   "zh": "📖 GraphQL模式转储完成: 类型={types} | 变更={muts}",
                                   "en": "📖 GraphQL schema dump: types={types} | mutations={muts}"},
    "graphql_sensitive_mut":     {"ko": "⚠️ 민감 뮤테이션 발견: {name} (권한없이 실행 가능)",
                                   "zh": "⚠️ 发现敏感变更: {name} (无需权限可执行)",
                                   "en": "⚠️ Sensitive mutation: {name} (accessible without auth)"},
    "graphql_batch_bypass":      {"ko": "🚀 배치 공격으로 rate-limit 우회: {count}건 동시",
                                   "zh": "🚀 通过批量攻击绕过速率限制: {count}个同时",
                                   "en": "🚀 Batch attack rate-limit bypass: {count} simultaneous"},
    "graphql_injection":         {"ko": "💉 GraphQL 인젝션 취약! 필드:{field} 페이로드:{payload}",
                                   "zh": "💉 GraphQL注入漏洞! 字段:{field} 载荷:{payload}",
                                   "en": "💉 GraphQL injection! Field:{field} Payload:{payload}"},
    "graphql_summary":           {"ko": "📋 GraphQL 스캔 완료 | 발견:{count}개 | 민감뮤테이션:{muts}개",
                                   "zh": "📋 GraphQL扫描完成 | 发现:{count} | 敏感变更:{muts}",
                                   "en": "📋 GraphQL scan complete | Found:{count} | Sensitive:{muts}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — OAuth/JWT Attacker
    # ──────────────────────────────────────────────────────────────────────────
    "oauth_scan_start":          {"ko": "🔓 OAuth/JWT 공격 스캔 시작: {url}",
                                   "zh": "🔓 开始OAuth/JWT攻击扫描: {url}",
                                   "en": "🔓 Starting OAuth/JWT attack scan: {url}"},
    "jwt_none_forged":           {"ko": "🎭 JWT alg:none 위조 성공! 관리자 권한 획득",
                                   "zh": "🎭 JWT alg:none伪造成功! 获得管理员权限",
                                   "en": "🎭 JWT alg:none forged! Admin privileges obtained"},
    "jwt_kid_sqli":              {"ko": "💉 JWT kid SQL인젝션 성공: {payload}",
                                   "zh": "💉 JWT kid SQL注入成功: {payload}",
                                   "en": "💉 JWT kid SQL injection: {payload}"},
    "oauth_redirect_bypass":     {"ko": "🔀 OAuth redirect_uri 우회 성공: {uri}",
                                   "zh": "🔀 OAuth redirect_uri绕过成功: {uri}",
                                   "en": "🔀 OAuth redirect_uri bypass: {uri}"},
    "oauth_state_csrf":          {"ko": "⚠️ OAuth state CSRF 취약: {desc}",
                                   "zh": "⚠️ OAuth state CSRF漏洞: {desc}",
                                   "en": "⚠️ OAuth state CSRF: {desc}"},
    "oauth_summary":             {"ko": "📋 OAuth/JWT 스캔 완료 | 발견:{count}개 | 위조:{forged}개",
                                   "zh": "📋 OAuth/JWT扫描完成 | 发现:{count} | 伪造:{forged}",
                                   "en": "📋 OAuth/JWT scan complete | Found:{count} | Forged:{forged}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.0 — Session Manager / Playwright / Webhook
    # ──────────────────────────────────────────────────────────────────────────
    "session_mgr_saved":         {"ko": "💾 세션 저장 완료: {name} (역할:{role})",
                                   "zh": "💾 会话保存完成: {name} (角色:{role})",
                                   "en": "💾 Session saved: {name} (role:{role})"},
    "session_expired":           {"ko": "⚠️ 세션 만료 감지 → 자동 재로그인 시도",
                                   "zh": "⚠️ 检测到会话过期 → 自动重新登录",
                                   "en": "⚠️ Session expired → auto re-login"},
    "playwright_no_install":     {"ko": "⚠️ Playwright 미설치 → requests fallback 사용",
                                   "zh": "⚠️ Playwright未安装 → 使用requests回退",
                                   "en": "⚠️ Playwright not installed → requests fallback"},
    "webhook_sent":              {"ko": "📡 웹훅 전송 완료: [{severity}] {title}",
                                   "zh": "📡 Webhook发送完成: [{severity}] {title}",
                                   "en": "📡 Webhook sent: [{severity}] {title}"},
    "webhook_batch":             {"ko": "📦 배치 알림 전송: {count}건",
                                   "zh": "📦 批量通知发送: {count}条",
                                   "en": "📦 Batch notification sent: {count} alerts"},

    # ──────────────────────────────────────────────────────────────────────────
    # v2.9.1 — Bug Fix keys
    # ──────────────────────────────────────────────────────────────────────────
    "ssl_warn_suppressed":       {"ko": "🔇 SSL 인증서 경고 억제 (verify=False 스크립트)",
                                   "zh": "🔇 SSL证书警告已抑制 (verify=False脚本)",
                                   "en": "🔇 SSL certificate warnings suppressed (verify=False scripts)"},
    "soft_404_detected":         {"ko": "⚠️ Soft 404 감지 — {path} (200이지만 오류 페이지 내용)",
                                   "zh": "⚠️ 检测到软404 — {path} (返回200但内容为错误页面)",
                                   "en": "⚠️ Soft 404 detected — {path} (200 but error page content)"},
    "admin_confirmed":           {"ko": "✅ 관리자 패널 확인: {path} (실제 콘텐츠 존재)",
                                   "zh": "✅ 管理员面板已确认: {path} (存在真实内容)",
                                   "en": "✅ Admin panel confirmed: {path} (real content exists)"},
    "admin_false_positive":      {"ko": "🚫 False Positive 제거: {path} (Soft 404 — 실제 관리자 패널 없음)",
                                   "zh": "🚫 误报已过滤: {path} (软404 — 无真实管理面板)",
                                   "en": "🚫 False positive removed: {path} (Soft 404 — no real admin panel)"},
    # v2.9.2 — CMS Bias Fix keys
    # ──────────────────────────────────────────────────────────────────────────
    "new_target_reset":          {"ko": "🆕 새 타겟 감지 — CMS 컨텍스트 완전 초기화 (이전 스캔 기록 무효)",
                                   "zh": "🆕 检测到新目标 — CMS上下文完全重置 (先前扫描记录已失效)",
                                   "en": "🆕 New target detected — CMS context fully reset (prior scan history voided)"},
    "cms_bias_blocked":          {"ko": "🚫 CMS 편향 차단: {cms} 추정 근거 없음 (HTML 증거 필요)",
                                   "zh": "🚫 CMS偏见已阻止: 无{cms}推断依据 (需要HTML证据)",
                                   "en": "🚫 CMS bias blocked: no evidence for {cms} (HTML proof required)"},
    "cms_detected_fresh":        {"ko": "✅ CMS 탐지 완료 (신규 스캔): {cms}",
                                   "zh": "✅ CMS检测完成 (新鲜扫描): {cms}",
                                   "en": "✅ CMS detected (fresh scan): {cms}"},
    "history_trimmed":           {"ko": "✂️ 타겟 전환 — 대화 히스토리 정리 (CMS 오염 방지)",
                                   "zh": "✂️ 目标切换 — 对话历史已清理 (防止CMS污染)",
                                   "en": "✂️ Target switched — conversation history trimmed (CMS contamination prevention)"},
    # ── v3.1.3 — AUTO-FIX 레이블 다국어 ──────────────────────────────────
    "fix_is_not_str":            {"ko": "is/is not → ==/!=",
                                   "zh": "is/is not → ==/!=",
                                   "en": "is/is not → ==/!="},
    "fix_requests_timeout":      {"ko": "requests timeout=30 주입",
                                   "zh": "注入requests超时=30",
                                   "en": "requests timeout=30 injected"},
    "fix_db_timeout":            {"ko": "DB connect timeout 주입",
                                   "zh": "注入DB连接超时",
                                   "en": "DB connect timeout injected"},
    "fix_socket_timeout":        {"ko": "socket.settimeout(10) 주입",
                                   "zh": "注入socket.settimeout(10)",
                                   "en": "socket.settimeout(10) injected"},
    "fix_urljoin_timeout":       {"ko": "urljoin timeout 인자 제거",
                                   "zh": "移除urljoin超时参数",
                                   "en": "urljoin timeout arg removed"},
    "fix_url_concat":            {"ko": "URL 연결 버그 수정",
                                   "zh": "修复URL拼接错误",
                                   "en": "URL concat bug fixed"},
    "fix_fstring_quote":         {"ko": "f-string 따옴표 충돌 수정",
                                   "zh": "修复f-string引号冲突",
                                   "en": "f-string quote conflict fixed"},
    "fix_sql_sleep_cap":         {"ko": "SQL SLEEP 과대값 캡(→3s)",
                                   "zh": "SQL SLEEP值限制(→3s)",
                                   "en": "SQL SLEEP capped (→3s)"},
    "fix_time_sleep_uniform":    {"ko": "time.sleep(a,b) → random.uniform",
                                   "zh": "time.sleep(a,b) → random.uniform",
                                   "en": "time.sleep(a,b) → random.uniform"},
    "fix_fstring_syntax":        {"ko": "f-string SyntaxError 복구",
                                   "zh": "f-string语法错误已恢复",
                                   "en": "f-string SyntaxError recovered"},
    # ── v3.2.2 — escape sequence AUTO-FIX 다국어 ─────────────────────────
    "fix_escape_seq":            {"ko": "잘못된 escape sequence 수정 (\\b\\E 등 → \\\\)",
                                   "zh": "修复无效转义序列 (\\b\\E等 → \\\\)",
                                   "en": "invalid escape sequences fixed (\\b\\E etc → \\\\)"},
    # ── v3.2.3 — None target fallback 다국어 ─────────────────────────────
    "none_target_fallback":      {"ko": "⚠️  타겟 값이 None — 기본값 'target'으로 대체",
                                   "zh": "⚠️  目标值为None — 使用默认值'target'替代",
                                   "en": "⚠️  target value is None — fallback to 'target'"},
    # ── v3.2.4 — 429 오탐 방지 / 차단 감지 정확도 개선 ──────────────────
    "block_detect_false_positive": {
        "ko": "⚠️  차단 오탐 방지: HTTP 컨텍스트 패턴 매칭으로 업그레이드",
        "zh": "⚠️  误报防止: 已升级为HTTP上下文模式匹配",
        "en": "⚠️  False positive prevention: upgraded to HTTP context pattern matching",
    },

    # ── v3.2.5 — 무한루프 감지 오탐 수정 ──────────────────────────────
    "loop_detect_false_positive": {
        "ko": "⚠️  무한루프 오탐 방지: UI 키워드/접두어 라인 필터링 강화",
        "zh": "⚠️  无限循环误报防止: 已增强UI关键词/前缀行过滤",
        "en": "⚠️  Infinite loop false positive prevention: enhanced UI keyword/prefix line filtering",
    },
    "loop_detect_skip_ui": {
        "ko": "ℹ️  반복 감지 건너뜀: '{val}' — UI 피드백 키워드 (SQL 데이터 아님)",
        "zh": "ℹ️  跳过重复检测: '{val}' — UI反馈关键词(非SQL数据)",
        "en": "ℹ️  Loop detection skipped: '{val}' — UI feedback keyword (not SQL data)",
    },

    # ── v3.2.6 — Python 3.12 regex / re.compile dict 오류 방지 ──────────
    "regex_flag_autofix": {
        "ko": "🔧 [AUTO-FIX] Python 3.12 regex (?i) 플래그 위치 자동 수정",
        "zh": "🔧 [AUTO-FIX] Python 3.12正则表达式(?i)标志位置已自动修复",
        "en": "🔧 [AUTO-FIX] Python 3.12 regex (?i) flag position auto-fixed",
    },
    "regex_compile_rule": {
        "ko": "⚠️  regex dict 오류: re.compile() 없이 raw string 저장 → AttributeError 발생",
        "zh": "⚠️  正则字典错误: 未使用re.compile()存储原始字符串 → AttributeError",
        "en": "⚠️  Regex dict error: raw string stored without re.compile() → AttributeError",
    },

    # ── v3.2.7: URL 중복출력 오탐 수정 ──
    "url_dedup_autofix": {
        "ko": "[AUTO-FIX] URL 중복 감지: 동일 URL이 {n}회 반복 출력됨 → 루프감지 오탐 방지를 위해 중복제거 규칙 적용",
        "zh": "[AUTO-FIX] 检测到URL重复: 相同URL输出{n}次 → 应用去重规则以防止误报无限循环检测",
        "en": "[AUTO-FIX] URL dedup: same URL printed {n} times → dedup rule applied to prevent false-positive loop detection",
    },
    "loop_detect_url_skip": {
        "ko": "⚡ 무한루프 감지 건너뜀: '{val}'은 URL/경로 패턴 → SQL 데이터 추출 루프가 아님",
        "zh": "⚡ 跳过无限循环检测: '{val}'是URL/路径模式 → 不是SQL数据提取循环",
        "en": "⚡ Loop detect skipped: '{val}' is URL/path pattern — not SQL extraction loop",
    },

    # ──────────────────────────────────────────────────────────────────────────
    # v3.0.0 — Five-Pillar Enhancement 다국어 키
    # ──────────────────────────────────────────────────────────────────────────
    # Pillar 1 — Enterprise Slow-Scan
    "slow_scan_activated":       {"ko": "🐢 SLOW-SCAN MODE 활성화 — 기업급 WAF 감지 (2~8s 딜레이 + UA 로테이션)",
                                   "zh": "🐢 慢速扫描模式已激活 — 检测到企业级WAF (2~8秒延迟 + UA轮换)",
                                   "en": "🐢 SLOW-SCAN MODE activated — Enterprise WAF detected (2~8s delay + UA rotation)"},
    "slow_scan_request_count":   {"ko": "🐢 [{req_count}번째 요청] 딜레이 {delay:.1f}s | UA: {ua_short}",
                                   "zh": "🐢 [第{req_count}次请求] 延迟 {delay:.1f}s | UA: {ua_short}",
                                   "en": "🐢 [Request #{req_count}] Delay {delay:.1f}s | UA: {ua_short}"},
    "ip_ban_slow_switch":        {"ko": "⚠️ IP 차단 감지 ({ban_count}회) → SLOW-SCAN 전환",
                                   "zh": "⚠️ 检测到IP封禁({ban_count}次) → 切换到慢速扫描",
                                   "en": "⚠️ IP ban detected ({ban_count} times) → switching to SLOW-SCAN"},

    # Pillar 2 — Authenticated IDOR
    "auth_idor_start":           {"ko": "🔑 인증 후 IDOR 테스트 시작 — 테스트 계정 생성 중",
                                   "zh": "🔑 开始认证后IDOR测试 — 正在创建测试账户",
                                   "en": "🔑 Authenticated IDOR test starting — creating test account"},
    "auth_idor_account_created": {"ko": "✅ 테스트 계정 생성 완료: {test_id}",
                                   "zh": "✅ 测试账户创建成功: {test_id}",
                                   "en": "✅ Test account created: {test_id}"},
    "auth_idor_login_ok":        {"ko": "✅ 로그인 성공 → 세션 획득 완료",
                                   "zh": "✅ 登录成功 → 会话已获取",
                                   "en": "✅ Login successful → session acquired"},
    "auth_idor_horizontal":      {"ko": "🔍 수평 IDOR 테스트: {endpoint} (ID: {id_val})",
                                   "zh": "🔍 水平IDOR测试: {endpoint} (ID: {id_val})",
                                   "en": "🔍 Horizontal IDOR test: {endpoint} (ID: {id_val})"},
    "auth_idor_vertical":        {"ko": "🔍 수직 IDOR 테스트: {admin_path} (일반 세션으로 접근)",
                                   "zh": "🔍 垂直IDOR测试: {admin_path} (使用普通用户会话访问)",
                                   "en": "🔍 Vertical IDOR test: {admin_path} (accessing with user session)"},
    "auth_idor_confirmed":       {"ko": "🔴 IDOR 확인! {type} — {endpoint} → 타인 데이터 노출",
                                   "zh": "🔴 IDOR已确认! {type} — {endpoint} → 他人数据泄露",
                                   "en": "🔴 IDOR confirmed! {type} — {endpoint} → other user's data exposed"},

    # Pillar 3 — JS Deep Mining
    "js_deep_start":             {"ko": "🔍 JS 딥 분석 시작 — {js_count}개 파일",
                                   "zh": "🔍 开始JS深度分析 — {js_count}个文件",
                                   "en": "🔍 JS deep mining started — {js_count} files"},
    "js_deep_found":             {"ko": "📋 JS 분석 완료 → API {endpoint_count}개 / 시크릿 {secret_count}개 / 관리자경로 {admin_count}개",
                                   "zh": "📋 JS分析完成 → API {endpoint_count}个 / 密钥 {secret_count}个 / 管理员路径 {admin_count}个",
                                   "en": "📋 JS analysis done → API {endpoint_count} / secrets {secret_count} / admin paths {admin_count}"},
    "js_secret_found":           {"ko": "🔴 JS 하드코딩 시크릿 발견: {secret_type} = {secret_preview}...",
                                   "zh": "🔴 发现JS硬编码密钥: {secret_type} = {secret_preview}...",
                                   "en": "🔴 JS hardcoded secret found: {secret_type} = {secret_preview}..."},
    "js_mobile_paths":           {"ko": "📱 모바일 API 경로 {count}개 발견 → Pillar 4 전달",
                                   "zh": "📱 发现{count}个移动API路径 → 传递给Pillar 4",
                                   "en": "📱 Mobile API paths found: {count} → passing to Pillar 4"},

    # Pillar 4 — Mobile API Scanner
    "mobile_api_start":          {"ko": "📱 모바일 API 스캔 시작 — WAF 우회 (모바일 UA 사용)",
                                   "zh": "📱 开始移动端API扫描 — WAF绕过 (使用移动UA)",
                                   "en": "📱 Mobile API scan starting — WAF bypass (mobile UA)"},
    "mobile_api_found":          {"ko": "✅ 모바일 API 발견: {path} [{status}]",
                                   "zh": "✅ 发现移动端API: {path} [{status}]",
                                   "en": "✅ Mobile API found: {path} [{status}]"},
    "mobile_api_unauth":         {"ko": "🔴 모바일 API 무인증 접근: {path} → 데이터 노출!",
                                   "zh": "🔴 移动端API未授权访问: {path} → 数据泄露!",
                                   "en": "🔴 Mobile API unauthenticated access: {path} → data exposed!"},
    "mobile_api_weaker_waf":     {"ko": "⚡ 모바일 API WAF 취약 감지 ({path}) — 인젝션 테스트 전환",
                                   "zh": "⚡ 检测到移动端API WAF较弱 ({path}) — 切换到注入测试",
                                   "en": "⚡ Mobile API weaker WAF detected ({path}) — switching to injection tests"},
    "mobile_api_summary":        {"ko": "📱 모바일 API 스캔 완료: {found}개 발견 / {vuln}개 취약",
                                   "zh": "📱 移动端API扫描完成: 发现{found}个 / {vuln}个存在漏洞",
                                   "en": "📱 Mobile API scan done: {found} found / {vuln} vulnerable"},

    # Pillar 5 — Business Logic Fuzzer v2
    "bizlogic_start":            {"ko": "⚙️ 비즈니스 로직 테스트 시작 (WAF 우회 전략)",
                                   "zh": "⚙️ 开始业务逻辑测试 (WAF绕过策略)",
                                   "en": "⚙️ Business logic testing started (WAF bypass strategy)"},
    "bizlogic_price_manip":      {"ko": "💰 가격/수량 조작 테스트: {endpoint} (price={price}, qty={qty})",
                                   "zh": "💰 价格/数量篡改测试: {endpoint} (price={price}, qty={qty})",
                                   "en": "💰 Price/quantity manipulation test: {endpoint} (price={price}, qty={qty})"},
    "bizlogic_race_start":       {"ko": "🏃 레이스 컨디션 테스트: {endpoint} (동시 {concurrency}개 요청)",
                                   "zh": "🏃 竞争条件测试: {endpoint} (并发{concurrency}个请求)",
                                   "en": "🏃 Race condition test: {endpoint} (concurrent {concurrency} requests)"},
    "bizlogic_race_confirmed":   {"ko": "🔴 레이스 컨디션 확인! {endpoint} — {dup_count}회 중복 처리됨",
                                   "zh": "🔴 竞争条件已确认! {endpoint} — {dup_count}次重复处理",
                                   "en": "🔴 Race condition confirmed! {endpoint} — {dup_count} duplicate processes"},
    "bizlogic_workflow_skip":    {"ko": "🔀 워크플로우 스킵 테스트: {step} → {skip_to} 직접 접근",
                                   "zh": "🔀 工作流程跳过测试: {step} → 直接访问{skip_to}",
                                   "en": "🔀 Workflow skip test: {step} → direct access to {skip_to}"},
    "bizlogic_role_inject":      {"ko": "👑 역할 파라미터 삽입 테스트: role=admin / isAdmin=true",
                                   "zh": "👑 角色参数注入测试: role=admin / isAdmin=true",
                                   "en": "👑 Role parameter injection test: role=admin / isAdmin=true"},
    "bizlogic_waf_pivot":        {"ko": "🔄 WAF가 모든 SQLi 차단 → 비즈니스 로직 전략으로 자동 전환",
                                   "zh": "🔄 WAF已拦截所有SQLi → 自动切换为业务逻辑测试策略",
                                   "en": "🔄 WAF blocked all SQLi → auto-pivoting to business logic strategy"},
    "bizlogic_summary":          {"ko": "⚙️ 비즈니스 로직 테스트 완료: {total}개 테스트 / {vuln}개 확인",
                                   "zh": "⚙️ 业务逻辑测试完成: {total}个测试 / {vuln}个确认漏洞",
                                   "en": "⚙️ Business logic tests done: {total} tests / {vuln} confirmed"},

    # ──────────────────────────────────────────────────────────────────────────
    # v3.1.7 — Pillar 6: Ghostcat / AJP Scanner 다국어 키
    # ──────────────────────────────────────────────────────────────────────────
    "ghostcat_start":            {"ko": "🦈 Ghostcat 스캐너 시작 — Tomcat AJP 포트 탐지 중...",
                                   "zh": "🦈 启动Ghostcat扫描器 — 检测Tomcat AJP端口...",
                                   "en": "🦈 Ghostcat scanner started — detecting Tomcat AJP port..."},
    "ghostcat_port_open":        {"ko": "🦈 AJP 포트 {port} 열림 감지 — Ghostcat CVE-2020-1938 검증 중...",
                                   "zh": "🦈 检测到AJP端口 {port} — 验证Ghostcat CVE-2020-1938...",
                                   "en": "🦈 AJP port {port} open — verifying Ghostcat CVE-2020-1938..."},
    "ghostcat_cpong":            {"ko": "🚨 AJP 서비스 응답 확인 (CPong) — Ghostcat 실제 취약 가능성 높음",
                                   "zh": "🚨 AJP服务响应确认 (CPong) — Ghostcat漏洞可利用性高",
                                   "en": "🚨 AJP service active (CPong received) — high Ghostcat exploitability"},
    "ghostcat_file_read":        {"ko": "💀 [CRITICAL] Ghostcat CVE-2020-1938 — WEB-INF/{file} 읽기 성공!",
                                   "zh": "💀 [CRITICAL] Ghostcat CVE-2020-1938 — 成功读取WEB-INF/{file}!",
                                   "en": "💀 [CRITICAL] Ghostcat CVE-2020-1938 — WEB-INF/{file} read success!"},
    "ghostcat_not_vulnerable":   {"ko": "✅ AJP 포트 닫힘 — Ghostcat 위험 없음",
                                   "zh": "✅ AJP端口关闭 — 无Ghostcat风险",
                                   "en": "✅ AJP port closed — not vulnerable to Ghostcat"},
    "ghostcat_manager_exposed":  {"ko": "⚠️ Tomcat Manager 노출: {path} (HTTP {code})",
                                   "zh": "⚠️ Tomcat Manager已暴露: {path} (HTTP {code})",
                                   "en": "⚠️ Tomcat Manager exposed: {path} (HTTP {code})"},
    "ghostcat_summary":          {"ko": "🦈 Ghostcat 스캔 완료: {severity} — {finding_count}개 발견",
                                   "zh": "🦈 Ghostcat扫描完成: {severity} — 发现{finding_count}个问题",
                                   "en": "🦈 Ghostcat scan done: {severity} — {finding_count} findings"},

    # ──────────────────────────────────────────────────────────────────────────
    # v3.1.7 — Pillar 7: SSL Deep + Heartbleed 다국어 키
    # ──────────────────────────────────────────────────────────────────────────
    "ssl_deep_start":            {"ko": "🔐 SSL/TLS 심층 분석 시작 — Heartbleed 검증 포함...",
                                   "zh": "🔐 开始深度SSL/TLS分析 — 包括Heartbleed验证...",
                                   "en": "🔐 Deep SSL/TLS scan started — Heartbleed check included..."},
    "ssl_openssl_detected":      {"ko": "🔍 OpenSSL {version} 감지 — 취약 버전 분석 중...",
                                   "zh": "🔍 检测到OpenSSL {version} — 分析漏洞版本...",
                                   "en": "🔍 OpenSSL {version} detected — analyzing vulnerability..."},
    "ssl_heartbleed_start":      {"ko": "💉 Heartbleed CVE-2014-0160 PoC 전송 중...",
                                   "zh": "💉 发送Heartbleed CVE-2014-0160 PoC请求...",
                                   "en": "💉 Sending Heartbleed CVE-2014-0160 PoC..."},
    "ssl_heartbleed_vuln":       {"ko": "💀 [CRITICAL] Heartbleed CVE-2014-0160 확인! 서버 메모리 누출 발생",
                                   "zh": "💀 [CRITICAL] 确认Heartbleed CVE-2014-0160! 服务器内存泄漏",
                                   "en": "💀 [CRITICAL] Heartbleed CVE-2014-0160 confirmed! Server memory leak detected"},
    "ssl_heartbleed_safe":       {"ko": "✅ Heartbleed 취약점 미감지 (메모리 누출 없음)",
                                   "zh": "✅ 未检测到Heartbleed漏洞 (无内存泄漏)",
                                   "en": "✅ Heartbleed not confirmed (no memory leak detected)"},
    "ssl_hsts_missing":          {"ko": "⚠️ [MEDIUM] HSTS 헤더 미설정 — 다운그레이드 공격 위험",
                                   "zh": "⚠️ [MEDIUM] HSTS头部缺失 — 存在降级攻击风险",
                                   "en": "⚠️ [MEDIUM] HSTS header missing — downgrade attack risk"},
    "ssl_weak_protocol":         {"ko": "🔓 [HIGH] 취약 프로토콜 수락: {protocol} — POODLE/BEAST 공격 가능",
                                   "zh": "🔓 [HIGH] 接受弱协议: {protocol} — 可能遭受POODLE/BEAST攻击",
                                   "en": "🔓 [HIGH] Weak protocol accepted: {protocol} — POODLE/BEAST attack possible"},
    "ssl_cert_expired":          {"ko": "⛔ [HIGH] SSL 인증서 만료: {expiry}",
                                   "zh": "⛔ [HIGH] SSL证书已过期: {expiry}",
                                   "en": "⛔ [HIGH] SSL certificate expired: {expiry}"},
    "ssl_deep_summary":          {"ko": "🔐 SSL/TLS 스캔 완료: {severity} — OpenSSL {version} / Heartbleed: {hb}",
                                   "zh": "🔐 SSL/TLS扫描完成: {severity} — OpenSSL {version} / Heartbleed: {hb}",
                                   "en": "🔐 SSL/TLS scan done: {severity} — OpenSSL {version} / Heartbleed: {hb}"},

    # ──────────────────────────────────────────────────────────────────────────
    # v3.1.7 — Pillar 8: CSRF Deep Scanner v2 다국어 키
    # ──────────────────────────────────────────────────────────────────────────
    "csrf_deep_start":           {"ko": "🛡️ CSRF 심층 분석 시작 — 토큰/Origin/CORS/SameSite 전체 검증...",
                                   "zh": "🛡️ 开始深度CSRF分析 — 验证Token/Origin/CORS/SameSite...",
                                   "en": "🛡️ Deep CSRF scan — Token/Origin/CORS/SameSite verification..."},
    "csrf_form_no_token":        {"ko": "⚠️ [HIGH] POST 폼에 CSRF 토큰 없음: {action}",
                                   "zh": "⚠️ [HIGH] POST表单缺少CSRF令牌: {action}",
                                   "en": "⚠️ [HIGH] POST form missing CSRF token: {action}"},
    "csrf_weak_token":           {"ko": "🔍 [MEDIUM] 약한 CSRF 토큰 감지: {action} — {reason}",
                                   "zh": "🔍 [MEDIUM] 检测到弱CSRF令牌: {action} — {reason}",
                                   "en": "🔍 [MEDIUM] Weak CSRF token detected: {action} — {reason}"},
    "csrf_referer_bypass":       {"ko": "💀 [CRITICAL] Referer 헤더 우회 성공! {action} — CSRF 공격 가능",
                                   "zh": "💀 [CRITICAL] Referer头部绕过成功! {action} — 可进行CSRF攻击",
                                   "en": "💀 [CRITICAL] Referer bypass confirmed! {action} — CSRF attack possible"},
    "csrf_origin_bypass":        {"ko": "🚨 [HIGH] Origin 헤더 우회: 외부 도메인에서 POST 허용됨 ({action})",
                                   "zh": "🚨 [HIGH] Origin头部绕过: 允许外部域POST ({action})",
                                   "en": "🚨 [HIGH] Origin header bypass: external domain POST accepted ({action})"},
    "csrf_json_bypass":          {"ko": "🚨 [HIGH] JSON CSRF 가능 (text/plain): {action}",
                                   "zh": "🚨 [HIGH] JSON CSRF可行 (text/plain): {action}",
                                   "en": "🚨 [HIGH] JSON CSRF possible (text/plain): {action}"},
    "csrf_cors_critical":        {"ko": "💀 [CRITICAL] CORS + Credentials=true 조합 — 인증된 CSRF 공격 가능!",
                                   "zh": "💀 [CRITICAL] CORS + Credentials=true组合 — 可进行身份验证CSRF攻击!",
                                   "en": "💀 [CRITICAL] CORS + Credentials=true — authenticated CSRF attack possible!"},
    "csrf_samesite_missing":     {"ko": "⚠️ [MEDIUM] SameSite 속성 없음: 쿠키 {cookie_name}",
                                   "zh": "⚠️ [MEDIUM] Cookie缺少SameSite属性: {cookie_name}",
                                   "en": "⚠️ [MEDIUM] SameSite attribute missing on cookie: {cookie_name}"},
    "csrf_admin_vulnerable":     {"ko": "🚨 [HIGH] 민감 API CSRF 취약: {endpoint}",
                                   "zh": "🚨 [HIGH] 敏感API存在CSRF漏洞: {endpoint}",
                                   "en": "🚨 [HIGH] Sensitive endpoint CSRF vulnerable: {endpoint}"},
    "csrf_deep_summary":         {"ko": "🛡️ CSRF 스캔 완료: {severity} — {form_count}개 폼 / {vuln_count}개 취약점",
                                   "zh": "🛡️ CSRF扫描完成: {severity} — {form_count}个表单 / {vuln_count}个漏洞",
                                   "en": "🛡️ CSRF scan done: {severity} — {form_count} forms / {vuln_count} vulns"},

    # ──────────────────────────────────────────────────────────────────────────
    # v3.1.7 — 보안 헤더 점검 (Missing Security Headers) 다국어 키
    # ──────────────────────────────────────────────────────────────────────────
    "sec_headers_start":         {"ko": "📋 보안 헤더 점검 시작 — HSTS/CSP/X-Frame/X-Content-Type 확인...",
                                   "zh": "📋 开始安全头部检查 — 检测HSTS/CSP/X-Frame/X-Content-Type...",
                                   "en": "📋 Security headers check — HSTS/CSP/X-Frame/X-Content-Type..."},
    "sec_header_missing":        {"ko": "⚠️ 보안 헤더 누락: {header} — {severity}",
                                   "zh": "⚠️ 安全头部缺失: {header} — {severity}",
                                   "en": "⚠️ Security header missing: {header} — {severity}"},
    "sec_server_version":        {"ko": "🔍 서버 버전 노출: {server_header} — 공격 대상 정보 제공됨",
                                   "zh": "🔍 服务器版本已暴露: {server_header} — 向攻击者提供目标信息",
                                   "en": "🔍 Server version disclosed: {server_header} — provides attacker target info"},
    "sec_headers_summary":       {"ko": "📋 보안 헤더 점검 완료: {missing_count}개 누락 ({severity})",
                                   "zh": "📋 安全头部检查完成: {missing_count}个缺失 ({severity})",
                                   "en": "📋 Security headers check done: {missing_count} missing ({severity})"},

    # ── v3.2.8: SQLi 피벗 / ASP.NET 특화 / Playwright 다국어 키 ──
    "sqli_exhausted_pivot":      {"ko": "⚡ [PIVOT] SQLi 소진 → {vector} 공격 벡터로 전환 (RULE 28)",
                                   "zh": "⚡ [PIVOT] SQLi耗尽 → 切换到{vector}攻击向量 (RULE 28)",
                                   "en": "⚡ [PIVOT] SQLi exhausted → switching to {vector} vector (RULE 28)"},
    "pivot_path_traversal":      {"ko": "📂 [PIVOT] 경로 순회(Path Traversal) 테스트 시작: {url}",
                                   "zh": "📂 [PIVOT] 开始路径遍历测试: {url}",
                                   "en": "📂 [PIVOT] Path traversal test started: {url}"},
    "pivot_webconfig_found":     {"ko": "🎯 [PIVOT] web.config 획득 성공! DB자격증명/설정 파싱 중...",
                                   "zh": "🎯 [PIVOT] 成功获取web.config！正在解析DB凭据/配置...",
                                   "en": "🎯 [PIVOT] web.config obtained! Parsing DB credentials/config..."},
    "pivot_webconfig_fail":      {"ko": "❌ [PIVOT] web.config 직접 접근 실패 → 핸들러 우회 시도",
                                   "zh": "❌ [PIVOT] web.config直接访问失败 → 尝试处理器绕过",
                                   "en": "❌ [PIVOT] web.config direct access failed → trying handler bypass"},
    "pivot_dirlisting_found":    {"ko": "📁 [PIVOT] 디렉토리 리스팅 감지! 경로: {path}",
                                   "zh": "📁 [PIVOT] 检测到目录列表！路径: {path}",
                                   "en": "📁 [PIVOT] Directory listing detected! Path: {path}"},
    "pivot_stacktrace_found":    {"ko": "💥 [PIVOT] 스택 트레이스 노출! DB경로/버전 수집 중...",
                                   "zh": "💥 [PIVOT] 堆栈跟踪已暴露！正在收集DB路径/版本...",
                                   "en": "💥 [PIVOT] Stack trace exposed! Collecting DB path/version..."},
    "pivot_authbypass_try":      {"ko": "🔑 [PIVOT] 인증 우회 시도: {method}",
                                   "zh": "🔑 [PIVOT] 尝试认证绕过: {method}",
                                   "en": "🔑 [PIVOT] Auth bypass attempt: {method}"},
    "pivot_authbypass_success":  {"ko": "✅ [PIVOT] 인증 우회 성공! 세션: {session_id}",
                                   "zh": "✅ [PIVOT] 认证绕过成功！会话: {session_id}",
                                   "en": "✅ [PIVOT] Auth bypass success! Session: {session_id}"},
    "pivot_upload_try":          {"ko": "📤 [PIVOT] 파일 업로드 취약점 테스트: {endpoint}",
                                   "zh": "📤 [PIVOT] 测试文件上传漏洞: {endpoint}",
                                   "en": "📤 [PIVOT] File upload vuln test: {endpoint}"},
    "pivot_upload_success":      {"ko": "🎯 [PIVOT] 웹쉘 업로드 성공! URL: {shell_url}",
                                   "zh": "🎯 [PIVOT] Webshell上传成功！URL: {shell_url}",
                                   "en": "🎯 [PIVOT] Webshell uploaded! URL: {shell_url}"},
    "pivot_ssrf_try":            {"ko": "🔄 [PIVOT] SSRF 테스트: {url}",
                                   "zh": "🔄 [PIVOT] SSRF测试: {url}",
                                   "en": "🔄 [PIVOT] SSRF test: {url}"},
    "aspnet_trace_exposed":      {"ko": "⚠️ [ASP.NET] trace.axd 노출 — 전체 요청/세션 이력 열람 가능",
                                   "zh": "⚠️ [ASP.NET] trace.axd已暴露 — 可查看全部请求/会话历史",
                                   "en": "⚠️ [ASP.NET] trace.axd exposed — full request/session history visible"},
    "aspnet_elmah_exposed":      {"ko": "⚠️ [ASP.NET] elmah.axd 노출 — 전체 에러 로그 열람 가능",
                                   "zh": "⚠️ [ASP.NET] elmah.axd已暴露 — 可查看全部错误日志",
                                   "en": "⚠️ [ASP.NET] elmah.axd exposed — full error log visible"},
    "aspnet_debug_mode":         {"ko": "⚠️ [ASP.NET] debug=true 감지 — 소스코드/내부경로 노출 위험",
                                   "zh": "⚠️ [ASP.NET] 检测到debug=true — 源码/内部路径泄露风险",
                                   "en": "⚠️ [ASP.NET] debug=true detected — source/internal path exposure risk"},
    "aspnet_custom_errors_off":  {"ko": "⚠️ [ASP.NET] customErrors=Off — 상세 에러 페이지 노출",
                                   "zh": "⚠️ [ASP.NET] customErrors=Off — 详细错误页面已暴露",
                                   "en": "⚠️ [ASP.NET] customErrors=Off — detailed error page exposed"},
    "playwright_start":          {"ko": "🎭 [PLAYWRIGHT] {task} 시작 — 브라우저 자동화 모드",
                                   "zh": "🎭 [PLAYWRIGHT] {task}开始 — 浏览器自动化模式",
                                   "en": "🎭 [PLAYWRIGHT] {task} started — browser automation mode"},
    "playwright_done":           {"ko": "🎭 [PLAYWRIGHT] 완료: {result}",
                                   "zh": "🎭 [PLAYWRIGHT] 完成: {result}",
                                   "en": "🎭 [PLAYWRIGHT] Done: {result}"},
    "playwright_session_found":  {"ko": "🎭 [PLAYWRIGHT] 세션 발견: {name} = {value}",
                                   "zh": "🎭 [PLAYWRIGHT] 发现会话: {name} = {value}",
                                   "en": "🎭 [PLAYWRIGHT] Session found: {name} = {value}"},
    "playwright_screenshot":     {"ko": "🎭 [PLAYWRIGHT] 스크린샷 저장: {filename}",
                                   "zh": "🎭 [PLAYWRIGHT] 截图已保存: {filename}",
                                   "en": "🎭 [PLAYWRIGHT] Screenshot saved: {filename}"},
    "playwright_fallback":       {"ko": "⚠️ [PLAYWRIGHT] 모듈 로드 실패 → requests fallback 전환",
                                   "zh": "⚠️ [PLAYWRIGHT] 模块加载失败 → 切换到requests回退模式",
                                   "en": "⚠️ [PLAYWRIGHT] Module load failed → falling back to requests"},
    "playwright_api_captured":   {"ko": "🎭 [PLAYWRIGHT] API 요청 {count}개 캡처: {endpoints}",
                                   "zh": "🎭 [PLAYWRIGHT] 已捕获{count}个API请求: {endpoints}",
                                   "en": "🎭 [PLAYWRIGHT] {count} API requests captured: {endpoints}"},

    # ── v3.2.9: XML/HTML/JSON 오탐 방지 다국어 키 ──
    "loop_detect_xml_skip":      {"ko": "⚡ 루프감지 건너뜀: '{val}'은 XML/HTML 태그 → SQL 데이터 아님",
                                   "zh": "⚡ 跳过循环检测: '{val}'是XML/HTML标签 → 非SQL数据",
                                   "en": "⚡ Loop detect skipped: '{val}' is XML/HTML tag — not SQL data"},
    "loop_detect_json_skip":     {"ko": "⚡ 루프감지 건너뜀: '{val}'은 JSON 구조 문자 → SQL 데이터 아님",
                                   "zh": "⚡ 跳过循环检测: '{val}'是JSON结构字符 → 非SQL数据",
                                   "en": "⚡ Loop detect skipped: '{val}' is JSON structure — not SQL data"},
    "loop_detect_numeric_skip":  {"ko": "⚡ 루프감지 건너뜀: '{val}'은 숫자/날짜 값 → SQL 데이터 아님",
                                   "zh": "⚡ 跳过循环检测: '{val}'是数字/日期值 → 非SQL数据",
                                   "en": "⚡ Loop detect skipped: '{val}' is numeric/date — not SQL data"},
    "xml_content_summary":       {"ko": "📄 [XML] {tag} 항목 {count}개 발견 (최대 5개 표시)",
                                   "zh": "📄 [XML] 发现{count}个{tag}条目（最多显示5个）",
                                   "en": "📄 [XML] {count} {tag} entries found (showing up to 5)"},
    "json_content_summary":      {"ko": "📄 [JSON] 항목 {count}개 발견 (키: {keys})",
                                   "zh": "📄 [JSON] 发现{count}个条目 (键: {keys})",
                                   "en": "📄 [JSON] {count} items found (keys: {keys})"},
    "loop_false_positive_xml":   {"ko": "[AUTO-FIX] XML/HTML 태그 오탐 방지: '{val}' 반복감지 → 루프 아님",
                                   "zh": "[AUTO-FIX] XML/HTML标签误报防护: '{val}'重复检测 → 非循环",
                                   "en": "[AUTO-FIX] XML/HTML tag false positive: '{val}' repeated → not a loop"},

    # v3.2.11: 스크립트 오류 메시지 오탐 방지
    "loop_skip_error_msg":       {"ko": "⚡ 루프감지 건너뜀: '{val}'은 실행 오류 메시지 → SQL 데이터 아님",
                                   "zh": "⚡ 循环检测跳过: '{val}'为执行错误消息 → 非SQL数据",
                                   "en": "⚡ Loop detect skip: '{val}' is error message → not SQL data"},
    "autofix_regex_char_range":  {"ko": "[AUTO-FIX] 정규식 character range 오류 수정: \\-/ → - (하이픈 위치 교정)",
                                   "zh": "[AUTO-FIX] 修复正则字符范围错误: \\-/ → - (连字符位置修正)",
                                   "en": "[AUTO-FIX] Regex bad character range fixed: \\-/ → - (hyphen repositioned)"},
    "regex_char_range_rule":     {"ko": "⚠ RULE 26-N: [] 내 하이픈은 맨 앞/뒤에만 배치 — r'[-\\.+]' (올바름) vs r'[\\-/]' (오류)",
                                   "zh": "⚠ RULE 26-N: []内连字符必须在首尾 — r'[-\\.+]'(正确) vs r'[\\-/]'(错误)",
                                   "en": "⚠ RULE 26-N: Hyphen in [] must be at start/end — r'[-\\.+]' (ok) vs r'[\\-/]' (error)"},

    # v3.2.12: 이모지/중국어 분석 출력 오탐 방지
    "loop_skip_emoji_prefix":    {"ko": "⚡ 루프감지 건너뜀: '{val}'은 이모지/분석 출력 → SQL 데이터 아님",
                                   "zh": "⚡ 循环检测跳过: '{val}'为分析输出标记 → 非SQL数据",
                                   "en": "⚡ Loop detect skip: '{val}' is analysis output → not SQL data"},
    "loop_skip_cn_prefix":       {"ko": "⚡ 루프감지 건너뜀: '{val}'은 중국어 분석 상태 메시지 → SQL 데이터 아님",
                                   "zh": "⚡ 循环检测跳过: '{val}'为中文状态消息 → 非SQL数据",
                                   "en": "⚡ Loop detect skip: '{val}' is Chinese status msg → not SQL data"},
    "autofix_charclass_escape":  {"ko": "[AUTO-FIX] 문자 클래스[] 내 잘못된 이스케이프 수정 (\\Z, \\E 등 → 백슬래시 제거)",
                                   "zh": "[AUTO-FIX] 修复字符类[]内无效转义序列 (\\Z, \\E等 → 删除反斜杠)",
                                   "en": "[AUTO-FIX] Char class invalid escape fixed (\\Z, \\E etc → backslash removed)"},
    "rule_26o_no_repeat_print":  {"ko": "⚠ RULE 26-O: 루프 내 동일 메시지 반복 print 금지 — 카운터 요약 사용",
                                   "zh": "⚠ RULE 26-O: 禁止循环内重复print相同消息 — 使用计数器汇总",
                                   "en": "⚠ RULE 26-O: No repeated same-message print in loops — use counter summary"},
    "autofix_loop_dedup":        {"ko": "[AUTO-FIX] 루프 내 반복 출력 감지 → 카운터 방식으로 자동 교체",
                                   "zh": "[AUTO-FIX] 检测到循环内重复输出 → 自动替换为计数器方式",
                                   "en": "[AUTO-FIX] Repeated output in loop detected → auto-replaced with counter"},
    # v3.2.16: CAPTCHA 오탐 방지 (RULE 26-R)
    "captcha_false_positive":    {"ko": "⚡ CAPTCHA 오탐 건너뜀: 실제 챌린지 없음 (script src 오탐) → 정상 계속 진행",
                                   "zh": "⚡ CAPTCHA误报跳过: 无实际挑战页面 (仅script src标签) → 继续正常执行",
                                   "en": "⚡ CAPTCHA false-positive skipped: no real challenge page (script src only) → continuing normally"},
    "captcha_real_detected":     {"ko": "⛔ CAPTCHA 실제 감지: data-sitekey 또는 Cloudflare 챌린지 페이지 확인됨",
                                   "zh": "⛔ 检测到真实CAPTCHA: 发现data-sitekey或Cloudflare挑战页面",
                                   "en": "⛔ Real CAPTCHA detected: data-sitekey or Cloudflare challenge page confirmed"},
    "rule_26r_captcha_check":    {"ko": "⚠ RULE 26-R: CAPTCHA 알림 수신 → 실제 응답 HTML 직접 확인 후 판단 (오탐 가능)",
                                   "zh": "⚠ RULE 26-R: 收到CAPTCHA通知 → 直接检查实际响应HTML再判断 (可能误报)",
                                   "en": "⚠ RULE 26-R: CAPTCHA alert received → verify actual response HTML before acting (may be false positive)"},
    # v3.2.15: 변수 미초기화 NameError 방지 (RULE 26-Q)
    "rule_26q_undef_var":        {"ko": "⚠ RULE 26-Q: 변수 정의 전 참조 금지 — 사용 전 반드시 초기화 ([] / {} / \"\" / 0)",
                                   "zh": "⚠ RULE 26-Q: 禁止在定义变量前引用 — 使用前必须初始化 ([] / {} / \"\" / 0)",
                                   "en": "⚠ RULE 26-Q: Never reference variable before defining — always init first ([] / {} / \"\" / 0)"},
    "nameerror_detected":        {"ko": "[ERROR] NameError 감지: '{var}' 변수가 정의되지 않음 — 스크립트 상단에 초기화 추가 필요",
                                   "zh": "[ERROR] 检测到NameError: 变量'{var}'未定义 — 需在脚本顶部添加初始化",
                                   "en": "[ERROR] NameError detected: '{var}' not defined — add initialization at script top"},
    "autofix_init_var":          {"ko": "[AUTO-FIX] 미초기화 변수 '{var}' 탐지 → 스크립트 상단에 {var} = {default} 자동 추가",
                                   "zh": "[AUTO-FIX] 检测到未初始化变量'{var}' → 自动在脚本顶部添加{var} = {default}",
                                   "en": "[AUTO-FIX] Uninitialized var '{var}' found → auto-added {var} = {default} at script top"},
    # v3.2.14: 로그인 500 반복 → JS 딥 분석 전환 (RULE 26-P)
    "rule_26p_pivot_js":         {"ko": "⚠ RULE 26-P: 로그인 500이 3회 반복됨 → JS 딥 분석으로 즉시 전환",
                                   "zh": "⚠ RULE 26-P: 登录500错误重复3次 → 立即切换到JS深度分析",
                                   "en": "⚠ RULE 26-P: Login 500 repeated 3x → pivoting to JS deep analysis now"},
    "pivot_js_analysis":         {"ko": "[PIVOT] 로그인 필드명/인코딩 JS 분석 시작 (btoa/AES/md5 탐지)",
                                   "zh": "[PIVOT] 开始JS分析登录字段名/编码方式 (btoa/AES/md5检测)",
                                   "en": "[PIVOT] Starting JS analysis for login field names/encoding (btoa/AES/md5 detect)"},
    "pivot_js_found":            {"ko": "[JS-PARSE] 발견: {fields} | 인코딩: {enc}",
                                   "zh": "[JS-PARSE] 发现: {fields} | 编码: {enc}",
                                   "en": "[JS-PARSE] Found: {fields} | encoding: {enc}"},
    "pivot_js_not_found":        {"ko": "[JS-PARSE] 필드명/인코딩 패턴 미발견 → 평문 재시도",
                                   "zh": "[JS-PARSE] 未找到字段名/编码模式 → 尝试明文",
                                   "en": "[JS-PARSE] No field/encoding pattern found → retrying plain text"},
    "login_500_count":           {"ko": "[LOGIN] 500 에러 {n}회 발생 ({url})",
                                   "zh": "[LOGIN] 500错误已发生{n}次 ({url})",
                                   "en": "[LOGIN] 500 error occurred {n} times ({url})"},
    # v3.2.17: HTTP 응답 반복 출력 → 루프 오탐 방지 (RULE 26-S)
    "rule_26s_body_loop":        {"ko": "⚠ RULE 26-S: 'Body: <!DOCTYPE html>' 반복 감지 → HTTP 출력 시 URL/상태코드 포함 의무",
                                   "zh": "⚠ RULE 26-S: 检测到'Body: <!DOCTYPE html>'重复 → HTTP输出必须包含URL/状态码",
                                   "en": "⚠ RULE 26-S: 'Body: <!DOCTYPE html>' repetition detected → HTTP output must include URL/status code"},
    "body_loop_false_positive":  {"ko": "⚡ 루프 오탐 건너뜀: 'Body: <!DOCTYPE html>' 반복은 HTML 응답 출력 — 무한 루프 아님",
                                   "zh": "⚡ 跳过循环误报: 'Body: <!DOCTYPE html>'重复是HTML响应输出 — 不是无限循环",
                                   "en": "⚡ Loop false-positive skipped: 'Body: <!DOCTYPE html>' repeat is HTTP response output — not infinite loop"},
    "http_all_same_response":    {"ko": "[INFO] 전체 {n}개 엔드포인트 → 동일 응답 ({size}B) — 인증 필요 또는 다른 API Base URL 탐색 필요",
                                   "zh": "[INFO] 全部{n}个端点 → 相同响应 ({size}B) — 需要认证或探索其他API Base URL",
                                   "en": "[INFO] All {n} endpoints → same response ({size}B) — auth required or explore different API base URL"},

    # v3.2.18: 프록시 풀 로테이션 (RULE 26-T)
    "proxy_added":               {"ko": "✅ 프록시 추가됨: {url}",
                                   "zh": "✅ 已添加代理: {url}",
                                   "en": "✅ Proxy added: {url}"},
    "proxy_add_fail":            {"ko": "❌ 추가 실패 (중복 또는 형식 오류): {url}",
                                   "zh": "❌ 添加失败（重复或格式错误）: {url}",
                                   "en": "❌ Add failed (duplicate or bad format): {url}"},
    "proxy_file_loaded":         {"ko": "📂 파일에서 {n}개 프록시 로드됨",
                                   "zh": "📂 从文件加载了 {n} 个代理",
                                   "en": "📂 Loaded {n} proxies from file"},
    "proxy_api_fetched":         {"ko": "🌐 API에서 {n}개 프록시 수집됨",
                                   "zh": "🌐 从API收集了 {n} 个代理",
                                   "en": "🌐 Fetched {n} proxies from API"},
    "proxy_tor_enabled":         {"ko": "🧅 Tor 모드 활성화 — socks5h://127.0.0.1:9050 사용 중\n   stem 설치됨: {stem} | 회로 교체 지원: {stem}",
                                   "zh": "🧅 Tor模式已激活 — 使用 socks5h://127.0.0.1:9050\n   stem已安装: {stem} | 支持线路切换: {stem}",
                                   "en": "🧅 Tor mode activated — using socks5h://127.0.0.1:9050\n   stem installed: {stem} | circuit rotation: {stem}"},
    "proxy_rotated":             {"ko": "🔄 프록시 교체됨 → {url}",
                                   "zh": "🔄 已切换代理 → {url}",
                                   "en": "🔄 Proxy rotated → {url}"},
    "proxy_pool_empty":          {"ko": "⚠ 사용 가능한 프록시 없음 — /proxy add <url> 로 추가하세요",
                                   "zh": "⚠ 无可用代理 — 请使用 /proxy add <url> 添加",
                                   "en": "⚠ No available proxy — add with /proxy add <url>"},
    "proxy_test_ok":             {"ko": "✅ 프록시 연결 성공: {url} (지연: {lat}ms)",
                                   "zh": "✅ 代理连接成功: {url} (延迟: {lat}ms)",
                                   "en": "✅ Proxy connection OK: {url} (latency: {lat}ms)"},
    "proxy_test_fail":           {"ko": "❌ 프록시 연결 실패: {url}",
                                   "zh": "❌ 代理连接失败: {url}",
                                   "en": "❌ Proxy connection failed: {url}"},
    # v3.2.74 프록시 진단 키
    "proxy_pysocks_missing":     {"ko": "⚠ PySocks 미설치 — SOCKS5/SOCKS4 사용 불가\n"
                                        "   설치: pip install 'requests[socks]'",
                                   "zh": "⚠ 未安装PySocks — 无法使用SOCKS5/SOCKS4代理\n"
                                        "   安装: pip install 'requests[socks]'",
                                   "en": "⚠ PySocks not installed — SOCKS5/SOCKS4 unavailable\n"
                                        "   Install: pip install 'requests[socks]'"},
    "proxy_test_detail":         {"ko": "   상세: {detail}",
                                   "zh": "   详情: {detail}",
                                   "en": "   Detail: {detail}"},
    "proxy_fix_pysocks":         {"ko": "   → 해결: pip install 'requests[socks]'",
                                   "zh": "   → 解决: pip install 'requests[socks]'",
                                   "en": "   → Fix: pip install 'requests[socks]'"},
    "proxy_fix_connection":      {"ko": "   → IP/포트/인증정보를 확인하세요. 다른 프록시를 시도하세요.",
                                   "zh": "   → 请检查代理IP/端口/认证信息，或尝试其他代理。",
                                   "en": "   → Check proxy IP/port/credentials or try another proxy."},
    "proxy_fix_timeout":         {"ko": "   → 타임아웃: 프록시가 응답 없음. /proxy rotate 로 교체하세요.",
                                   "zh": "   → 超时: 代理无响应，请使用 /proxy rotate 切换。",
                                   "en": "   → Timeout: proxy not responding. Use /proxy rotate."},
    "proxy_unban":               {"ko": "✅ 밴 해제됨: {n}개",
                                   "zh": "✅ 已解封 {n} 个代理",
                                   "en": "✅ Unbanned {n} proxies"},
    "proxy_cleared":             {"ko": "🗑 프록시 풀 초기화됨",
                                   "zh": "🗑 代理池已清空",
                                   "en": "🗑 Proxy pool cleared"},
    "proxy_disabled":            {"ko": "⛔ 프록시 비활성화됨",
                                   "zh": "⛔ 代理已停用",
                                   "en": "⛔ Proxy disabled"},
    "proxy_auto_rotate":         {"ko": "🔄 IP 밴 감지 → 프록시 자동 교체: {url}",
                                   "zh": "🔄 检测到IP封禁 → 自动切换代理: {url}",
                                   "en": "🔄 IP ban detected → auto-rotated proxy: {url}"},
    "proxy_tip_no_proxy":        {"ko": "💡 팁: /proxy add <url> 또는 /proxy tor 로 IP 밴 자동 우회 가능",
                                   "zh": "💡 提示: 使用 /proxy add <url> 或 /proxy tor 自动绕过IP封禁",
                                   "en": "💡 Tip: /proxy add <url> or /proxy tor to auto-rotate past IP bans"},
    # v3.2.77: 프록시 3개 버그 수정 키
    "proxy_file_not_found":      {"ko": "❌ 파일을 찾을 수 없습니다: {path}",
                                   "zh": "❌ 找不到文件: {path}",
                                   "en": "❌ File not found: {path}"},
    "proxy_file_empty":          {"ko": "⚠ 파일에서 유효한 프록시를 찾지 못했습니다: {path}\n"
                                        "   형식: 한 줄에 1개  (예: socks5://1.2.3.4:1080  또는  1.2.3.4:8080)",
                                   "zh": "⚠ 文件中未找到有效代理: {path}\n"
                                        "   格式: 每行一个代理 (例: socks5://1.2.3.4:1080 或 1.2.3.4:8080)",
                                   "en": "⚠ No valid proxies found in file: {path}\n"
                                        "   Format: one proxy per line (e.g. socks5://1.2.3.4:1080 or 1.2.3.4:8080)"},
    "proxy_saved":               {"ko": "💾 프록시 설정 저장됨 (~/.config/bingo/proxy_pool.json)",
                                   "zh": "💾 代理设置已保存 (~/.config/bingo/proxy_pool.json)",
                                   "en": "💾 Proxy config saved (~/.config/bingo/proxy_pool.json)"},
    "proxy_restored":            {"ko": "🔁 이전 세션 프록시 {n}개 복원됨 (/proxy list 로 확인)",
                                   "zh": "🔁 已恢复上次会话代理 {n} 个 (使用 /proxy list 查看)",
                                   "en": "🔁 Restored {n} proxies from last session (/proxy list to view)"},
    "proxy_testall_header":      {"ko": "🔍 프록시 풀 전체 테스트 시작 ({total}개) — 완료까지 최대 {secs}초 소요...",
                                   "zh": "🔍 开始测试整个代理池 ({total}个) — 最长需 {secs} 秒...",
                                   "en": "🔍 Testing entire proxy pool ({total}) — may take up to {secs}s..."},
    "proxy_testall_summary":     {"ko": "결과: ✅ 성공 {ok}개  ❌ 실패 {fail}개 (실패 프록시는 자동 밴됨)",
                                   "zh": "结果: ✅ 成功 {ok} 个  ❌ 失败 {fail} 个 (失败代理已自动屏蔽)",
                                   "en": "Result: ✅ OK {ok}  ❌ Failed {fail} (failed proxies auto-banned)"},

    # v3.2.85: /proxy list 테이블 다국어 키
    "proxy_list_col_item":       {"ko": "항목",         "zh": "项目",     "en": "Item"},
    "proxy_list_col_value":      {"ko": "값",           "zh": "值",       "en": "Value"},
    "proxy_list_enabled":        {"ko": "활성화",        "zh": "已启用",   "en": "Enabled"},
    "proxy_list_total":          {"ko": "총 프록시",     "zh": "总代理数", "en": "Total Proxies"},
    "proxy_list_active":         {"ko": "사용 가능",     "zh": "可用",     "en": "Available"},
    "proxy_list_banned":         {"ko": "밴됨",          "zh": "已屏蔽",   "en": "Banned"},
    "proxy_list_current":        {"ko": "현재 프록시",   "zh": "当前代理", "en": "Current Proxy"},
    "proxy_list_tor":            {"ko": "Tor 모드",      "zh": "Tor模式",  "en": "Tor Mode"},
    "proxy_list_stem":           {"ko": "stem (Tor 회로 교체)", "zh": "stem（Tor线路切换）", "en": "stem (Tor circuit rotation)"},
    "proxy_list_pysocks":        {"ko": "PySocks (SOCKS5)", "zh": "PySocks（SOCKS5）", "en": "PySocks (SOCKS5)"},
    "proxy_list_installed":      {"ko": "✅ 설치됨",     "zh": "✅ 已安装", "en": "✅ Installed"},
    "proxy_list_col_proxy":      {"ko": "프록시",        "zh": "代理",     "en": "Proxy"},
    "proxy_list_col_status":     {"ko": "상태",          "zh": "状态",     "en": "Status"},
    "proxy_list_col_success":    {"ko": "성공",          "zh": "成功",     "en": "Success"},
    "proxy_list_col_fail":       {"ko": "실패",          "zh": "失败",     "en": "Fail"},
    "proxy_list_col_latency":    {"ko": "지연(ms)",      "zh": "延迟(ms)", "en": "Latency(ms)"},
    "proxy_testall_testing":     {"ko": "🔍 테스트 중...", "zh": "🔍 测试中...", "en": "🔍 Testing..."},
    "proxy_testall_col_proxy":   {"ko": "프록시",        "zh": "代理",     "en": "Proxy"},
    "proxy_testall_col_result":  {"ko": "결과",          "zh": "结果",     "en": "Result"},
    "proxy_testall_col_detail":  {"ko": "상세",          "zh": "详情",     "en": "Detail"},
    "proxy_add_usage":           {
        "ko": "사용법: /proxy add <url>\n예시:   /proxy add socks5://1.2.3.4:1080\n        /proxy add http://user:pass@5.6.7.8:3128\n        /proxy add https://9.10.11.12:443",
        "zh": "用法: /proxy add <url>\n示例:   /proxy add socks5://1.2.3.4:1080\n        /proxy add http://user:pass@5.6.7.8:3128\n        /proxy add https://9.10.11.12:443",
        "en": "Usage: /proxy add <url>\nExamples: /proxy add socks5://1.2.3.4:1080\n          /proxy add http://user:pass@5.6.7.8:3128\n          /proxy add https://9.10.11.12:443",
    },
    "proxy_file_usage":          {
        "ko": "사용법: /proxy file <파일경로>   (한 줄에 프록시 1개)",
        "zh": "用法: /proxy file <文件路径>   (每行一个代理)",
        "en": "Usage: /proxy file <path>   (one proxy per line)",
    },
    "proxy_api_presets":         {"ko": "사용 가능한 무료 프록시 API 프리셋:", "zh": "可用的免费代理API预设:", "en": "Available free proxy API presets:"},
    "proxy_api_choice":          {"ko": "번호 선택 (0=직접입력)", "zh": "选择编号（0=手动输入）", "en": "Select number (0=enter manually)"},
    "proxy_api_url_input":       {"ko": "API URL 입력", "zh": "输入API URL", "en": "Enter API URL"},
    "proxy_api_bad_choice":      {"ko": "잘못된 선택.", "zh": "选择无效。", "en": "Invalid choice."},
    "proxy_tor_fail":            {"ko": "Tor 추가 실패.", "zh": "Tor添加失败。", "en": "Failed to enable Tor."},
    "proxy_tor_stem_missing":    {"ko": "   Tor 회로 자동 교체 비활성화 (stem 미설치)\n   → pip install stem  후 재실행", "zh": "   Tor线路自动切换未激活（未安装stem）\n   → pip install stem 后重启", "en": "   Tor circuit auto-rotation disabled (stem not installed)\n   → pip install stem then restart"},
    "proxy_test_checking":       {"ko": "🔍 {url} 연결 테스트 중... (최대 15초)", "zh": "🔍 正在测试 {url} 连接... (最多15秒)", "en": "🔍 Testing {url} connection... (up to 15s)"},
    "proxy_test_fail_reason":    {"ko": "   원인: {detail}", "zh": "   原因: {detail}", "en": "   Reason: {detail}"},
    "proxy_usage":               {
        "ko": "사용법: /proxy [list|add|file|api|tor|rotate|test|testall|unban|clear|off]\n예시:   /proxy add socks5://1.2.3.4:1080\n        /proxy tor\n        /proxy api\n        /proxy file ~/proxies.txt\n        /proxy testall",
        "zh": "用法: /proxy [list|add|file|api|tor|rotate|test|testall|unban|clear|off]\n示例:   /proxy add socks5://1.2.3.4:1080\n        /proxy tor\n        /proxy api\n        /proxy file ~/proxies.txt\n        /proxy testall",
        "en": "Usage: /proxy [list|add|file|api|tor|rotate|test|testall|unban|clear|off]\nExamples: /proxy add socks5://1.2.3.4:1080\n          /proxy tor\n          /proxy api\n          /proxy file ~/proxies.txt\n          /proxy testall",
    },

    # v3.2.80: 프록시 자동 교체 알림
    "proxy_switch_ban":          {"ko": "🔄 IP 차단 감지 → 프록시 자동 교체\n   ❌ {old}\n   ✅ {new}",
                                   "zh": "🔄 检测到IP封禁 → 自动切换代理\n   ❌ {old}\n   ✅ {new}",
                                   "en": "🔄 IP ban detected → proxy auto-switched\n   ❌ {old}\n   ✅ {new}"},
    "proxy_switch_rotate":       {"ko": "🔄 프록시 수동 교체\n   ❌ {old}\n   ✅ {new}",
                                   "zh": "🔄 代理手动切换\n   ❌ {old}\n   ✅ {new}",
                                   "en": "🔄 Proxy manually rotated\n   ❌ {old}\n   ✅ {new}"},
    "proxy_pool_exhausted":      {"ko": "⚠ 프록시 풀 소진 — 차단 우회 불가. /proxy add 로 추가하세요",
                                   "zh": "⚠ 代理池已耗尽 — 无法绕过封锁。请用 /proxy add 补充",
                                   "en": "⚠ Proxy pool exhausted — cannot bypass block. Use /proxy add to refill"},

    # v3.3.4: Silent drop 자동 HTTP 헤더 우회 (proxy 없을 때)
    "silent_drop_header_bypass": {"ko": "🔀 Silent drop 감지 → HTTP 헤더 우회 자동 적용 (프록시 없음)",
                                   "zh": "🔀 检测到静默丢弃 → 自动应用HTTP头部绕过 (无代理)",
                                   "en": "🔀 Silent drop detected → applying HTTP header bypass (no proxy)"},
    "silent_drop_ua_rotate":     {"ko": "  • User-Agent → Googlebot 위장",
                                   "zh": "  • User-Agent → 伪装为Googlebot",
                                   "en": "  • User-Agent → spoofing as Googlebot"},
    "silent_drop_xff_inject":    {"ko": "  • X-Forwarded-For: 127.0.0.1 주입",
                                   "zh": "  • X-Forwarded-For: 127.0.0.1 注入",
                                   "en": "  • X-Forwarded-For: 127.0.0.1 injected"},
    "silent_drop_delay_random":  {"ko": "  • 딜레이 랜덤화: 3~7초 (패턴 탐지 회피)",
                                   "zh": "  • 随机延迟: 3~7秒 (规避模式检测)",
                                   "en": "  • Randomized delay: 3~7s (evade rate detection)"},
    "silent_drop_proxy_hint":    {"ko": "💡 팁: /proxy add <url> 또는 /proxy tor 로 IP 밴 자동 우회 가능",
                                   "zh": "💡 提示: 使用 /proxy add <url> 或 /proxy tor 自动绕过IP封禁",
                                   "en": "💡 Tip: /proxy add <url> or /proxy tor to auto-rotate past IP bans"},

    # v3.2.19: 연결 오류 반복 오탐 수정 (RULE 26-U)
    "conn_error_loop_skip":      {"ko": "⚡ 루프 오탐 건너뜀: 연결 오류 반복은 WAF 차단 — 무한 루프 아님",
                                   "zh": "⚡ 跳过循环误报: 连接错误重复是WAF封锁 — 不是无限循环",
                                   "en": "⚡ Loop false-positive skipped: repeated conn errors are WAF blocks — not infinite loop"},
    "rule_26u_conn_loop":        {"ko": "⚠ RULE 26-U: 연결 오류 반복 감지 → 페이로드 인덱스를 출력에 포함 의무",
                                   "zh": "⚠ RULE 26-U: 检测到连接错误重复 → 输出中必须包含payload索引",
                                   "en": "⚠ RULE 26-U: Repeated conn errors detected → include payload index in output"},
    "waf_conn_reset_hint":       {"ko": "🚧 WAF 연결 강제 종료 감지 — 다른 엔드포인트/딜레이 전략으로 피벗 권장",
                                   "zh": "🚧 检测到WAF强制断开连接 — 建议切换到其他端点/延迟策略",
                                   "en": "🚧 WAF connection reset detected — pivot to different endpoint/delay strategy"},

    # v3.2.20: _smart_decode() 직접 호출 → def 자동 주입
    "smart_decode_def_injected": {"ko": "🔧 [PRECHECK] _smart_decode() 호출 감지 — def 자동 주입 (NameError 방지)",
                                   "zh": "🔧 [PRECHECK] 检测到_smart_decode()调用 — 自动注入def（防止NameError）",
                                   "en": "🔧 [PRECHECK] _smart_decode() call detected — def auto-injected (NameError prevention)"},

    # v3.2.22: Traceback 폭탄 → 1줄 압축 필터 (실행 출력 레벨)
    "traceback_filtered":        {"ko": "📦 [EXEC] Traceback {n}줄 → {count}줄로 압축 (에러만 표시)",
                                   "zh": "📦 [EXEC] Traceback {n}行 → 压缩为{count}行（仅显示错误）",
                                   "en": "📦 [EXEC] Traceback {n} lines → compressed to {count} lines (errors only)"},
    # v3.2.23: 스트리밍 실시간 Traceback 압축 알림 (_flush_tb_compressed)
    "traceback_stream_compressed": {"ko": "📦 [EXEC] Traceback {n}줄 → 실시간 압축",
                                    "zh": "📦 [EXEC] Traceback {n}行 → 实时压缩",
                                    "en": "📦 [EXEC] Traceback {n} lines → compressed (streaming)"},
    # v3.2.24: IP 레벨 차단 감지 메시지 (RULE 26-W 적용 결과 AI 출력)
    "ip_blocked_detected":          {"ko": "🚫 [IP_BLOCKED] 연속 연결 실패 → IP 레벨 차단 감지. /proxy 설정 후 재시도.",
                                     "zh": "🚫 [IP_BLOCKED] 连续连接失败 → 检测到IP级封锁。请设置 /proxy 后重试。",
                                     "en": "🚫 [IP_BLOCKED] Consecutive connection failures → IP-level block detected. Set /proxy and retry."},
    # v3.2.24: 병렬 스크립트 의존성 감지 경고 (RULE 26-X)
    "parallel_dep_warning":         {"ko": "⚠️ [RULE 26-X] 스크립트 간 파일 의존성 감지 — 병렬 실행에서 동작 보장 불가",
                                     "zh": "⚠️ [RULE 26-X] 检测到脚本间文件依赖 — 并行执行中不保证执行顺序",
                                     "en": "⚠️ [RULE 26-X] Inter-script file dependency detected — execution order not guaranteed in parallel"},
    # v3.2.25: Python 연쇄 예외 구분자 억제 (The above exception was... / During handling of...)
    "chained_exc_suppressed":       {"ko": "🔕 [EXEC] 연쇄 예외 구분자 억제됨",
                                     "zh": "🔕 [EXEC] 链式异常分隔符已抑制",
                                     "en": "🔕 [EXEC] Chained exception separator suppressed"},
    # v3.2.26 — RULE 26-Y / 26-Z
    "base64_alias_forbidden":       {"ko": "🔧 [PRECHECK] import base64 자동 주입 (b64 alias 또는 import 누락 감지)",
                                     "zh": "🔧 [PRECHECK] 自动注入 import base64 (检测到 b64 别名或缺少导入)",
                                     "en": "🔧 [PRECHECK] import base64 injected (b64 alias / missing import detected)"},
    "json_type_check_required":     {"ko": "⚠ [RULE 26-Z] r.json() 결과 dict 체크 누락 — isinstance(data, dict) 필수",
                                     "zh": "⚠ [RULE 26-Z] r.json() 结果未做 dict 检查 — 必须使用 isinstance(data, dict)",
                                     "en": "⚠ [RULE 26-Z] r.json() result not validated as dict — isinstance(data, dict) required"},
    # v3.2.27 — RULE 26-AA / 26-AB / loop false-positive fix
    "json_field_loop_skip":         {"ko": "🔕 [LOOP] JSON 필드 패턴 감지 — 루프 감지 제외 (오탐 방지)",
                                     "zh": "🔕 [LOOP] 检测到 JSON 字段模式 — 已排除循环检测（防误报）",
                                     "en": "🔕 [LOOP] JSON field pattern detected — excluded from loop detection (false-positive prevention)"},
    "rule_26aa_index_check":        {"ko": "⚠ [RULE 26-AA] 리스트 인덱스 접근 전 len() 체크 필수 (IndexError 방지)",
                                     "zh": "⚠ [RULE 26-AA] 访问列表索引前必须检查 len() (防止 IndexError)",
                                     "en": "⚠ [RULE 26-AA] len() check required before list index access (IndexError prevention)"},
    "rule_26ab_fstring_backslash":  {"ko": "⚠ [RULE 26-AB] f-string 내부 백슬래시 이스케이프 금지 — 변수 분리 사용",
                                     "zh": "⚠ [RULE 26-AB] 禁止在 f-string 内部使用反斜杠转义 — 请分离变量",
                                     "en": "⚠ [RULE 26-AB] Backslash escape inside f-string forbidden — use variable separation"},
    # v3.2.28 — 루프 감지 양성 필터 (화이트리스트 레이어)
    "loop_status_keyword_skip":     {"ko": "🔕 [LOOP v3.2.28] 상태/오류 키워드 감지 — 루프 감지 제외 (양성 필터 오탐 방지)",
                                     "zh": "🔕 [LOOP v3.2.28] 检测到状态/错误关键词 — 已排除循环检测（白名单正向过滤防误报）",
                                     "en": "🔕 [LOOP v3.2.28] Status/error keyword detected — excluded from loop detection (whitelist positive filter)"},
    "loop_structural_char_skip":    {"ko": "🔕 [LOOP v3.2.28] 구조적 문자 시작 라인 — 루프 감지 제외 (JSON/문자열 리터럴 오탐 방지)",
                                     "zh": "🔕 [LOOP v3.2.28] 结构性字符开头行 — 已排除循环检测（防JSON/字符串字面量误报）",
                                     "en": "🔕 [LOOP v3.2.28] Structural char start line — excluded from loop detection (JSON/literal false-positive prevention)"},
    "loop_length_skip":             {"ko": "🔕 [LOOP v3.2.28] 150자 초과 라인 — 루프 감지 제외 (로그 라인 오탐 방지)",
                                     "zh": "🔕 [LOOP v3.2.28] 超过150字符行 — 已排除循环检测（防日志行误报）",
                                     "en": "🔕 [LOOP v3.2.28] Line >150 chars — excluded from loop detection (log line false-positive prevention)"},

    # ── 플랫폼 메시지 (v5.0.3) ────────────────────────────────────────
    "platform_win32":               {"ko": "⚠️  Windows 네이티브 환경입니다.\n   WSL2(Windows Subsystem for Linux 2) 사용을 권장합니다.\n   일부 기능(curl/bash 실행)은 WSL2에서만 정상 동작합니다.",
                                     "zh": "⚠️  检测到 Windows 原生环境。\n   建议使用 WSL2（Windows Subsystem for Linux 2）。\n   部分功能（curl/bash 执行）仅在 WSL2 下正常工作。",
                                     "en": "⚠️  Windows native environment detected.\n   Recommended: WSL2 (Windows Subsystem for Linux 2).\n   Some features (curl/bash execution) work best on WSL2."},
    "platform_wsl":                 {"ko": "✅ WSL2(Windows Subsystem for Linux) 환경을 감지했습니다.\n   bingo가 WSL2에서 정상적으로 실행됩니다.",
                                     "zh": "✅ 检测到 WSL2（Windows Subsystem for Linux）环境。\n   bingo 在 WSL2 上可以正常运行。",
                                     "en": "✅ WSL2 (Windows Subsystem for Linux) environment detected.\n   bingo runs normally on WSL2."},

    # ── v3.2.57: 스킬 로딩 / Playwright / 헬루시네이션 방지 ──────────
    "skill_auto_detected":       {"ko": "🧠 스킬 자동 매칭: {count}개 로드됨",
                                   "zh": "🧠 技能自动匹配: 已加载 {count} 个",
                                   "en": "🧠 Skill auto-matched: {count} loaded"},
    "skill_db_total":            {"ko": "📚 전체 스킬 DB: {total}개 (1~14 파일)",
                                   "zh": "📚 技能数据库总计: {total} 个 (文件1~14)",
                                   "en": "📚 Total skill DB: {total} (files 1~14)"},
    "pw_param_trigger":          {"ko": "🎭 파라미터 URL 0개 — Playwright로 JS 렌더링 재정찰",
                                   "zh": "🎭 未发现参数URL — 使用Playwright重新渲染侦察",
                                   "en": "🎭 No param URLs found — re-scanning with Playwright JS rendering"},
    "pw_recon_success":          {"ko": "🎭 Playwright 정찰 완료: 링크 {links}개 / 파라미터 {params}개 발견",
                                   "zh": "🎭 Playwright侦察完成: 发现链接{links}个 / 参数{params}个",
                                   "en": "🎭 Playwright recon done: {links} links / {params} param URLs found"},
    "verified_finding":          {"ko": "✅ [VERIFIED] HTTP 응답으로 확인된 취약점",
                                   "zh": "✅ [VERIFIED] 已通过HTTP响应确认的漏洞",
                                   "en": "✅ [VERIFIED] Vulnerability confirmed via HTTP response"},
    "likely_finding":            {"ko": "🟡 [LIKELY] 행동 증거 기반 (직접 데이터 미확인)",
                                   "zh": "🟡 [LIKELY] 基于行为证据 (未直接获取数据)",
                                   "en": "🟡 [LIKELY] Based on behavioral evidence (no direct data yet)"},
    "inferred_finding":          {"ko": "🔵 [INFERRED] 간접 신호 추론 — 보고서 제외, 추가 검증 필요",
                                   "zh": "🔵 [INFERRED] 间接信号推断 — 排除在报告外，需进一步验证",
                                   "en": "🔵 [INFERRED] Inferred from indirect signals — excluded from report, needs proof"},
    "hallucination_blocked":     {"ko": "⛔ AI 추론만으로 취약점 선언 차단됨 — HTTP 증거 필요",
                                   "zh": "⛔ 仅凭AI推理宣称漏洞已被拦截 — 需要HTTP证据",
                                   "en": "⛔ Vulnerability claim blocked — AI reasoning only, HTTP evidence required"},

    # ── DApp 지갑 인증 (v3.2.62) ────────────────────────────────────────
    "web3_wallet_gen":           {"ko": "🔑 테스트 지갑 생성 중...",
                                   "zh": "🔑 正在生成测试钱包...",
                                   "en": "🔑 Generating test wallet..."},
    "web3_wallet_gen_done":      {"ko": "🔑 테스트 지갑 생성 완료 (실제 자산 절대 입금 금지)",
                                   "zh": "🔑 测试钱包生成完成 (绝对禁止存入真实资产)",
                                   "en": "🔑 Test wallet created — DO NOT send real funds to this address"},
    "web3_siwe_start":           {"ko": "🔐 SIWE (EIP-4361) 로그인 시도 중...",
                                   "zh": "🔐 正在尝试SIWE (EIP-4361) 登录...",
                                   "en": "🔐 Attempting SIWE (EIP-4361) login..."},
    "web3_siwe_success":         {"ko": "✅ SIWE 로그인 성공 — 세션 토큰 획득",
                                   "zh": "✅ SIWE登录成功 — 获取会话令牌",
                                   "en": "✅ SIWE login successful — session token acquired"},
    "web3_siwe_fail":            {"ko": "⚠️  SIWE 자동 로그인 실패 — 수동 분석 필요",
                                   "zh": "⚠️  SIWE自动登录失败 — 需要手动分析",
                                   "en": "⚠️  SIWE auto-login failed — manual analysis required"},
    "web3_auth_pipeline_start":  {"ko": "🔗 DApp 완전 인증 파이프라인 시작 (지갑→로그인→API 퍼징)",
                                   "zh": "🔗 DApp完整认证流水线启动 (钱包→登录→API模糊测试)",
                                   "en": "🔗 DApp full auth pipeline started (wallet→login→API fuzzing)"},
    "web3_auth_pipeline_done":   {"ko": "✅ DApp 인증 파이프라인 완료",
                                   "zh": "✅ DApp认证流水线完成",
                                   "en": "✅ DApp auth pipeline complete"},
    "web3_idor_found":           {"ko": "🚨 IDOR/BOLA 의심 경로 발견",
                                   "zh": "🚨 发现疑似IDOR/BOLA路径",
                                   "en": "🚨 Suspected IDOR/BOLA path found"},
    "web3_wallet_warning":       {"ko": "⚠️  이것은 테스트 전용 지갑입니다. 실제 자산 절대 넣지 마세요!",
                                   "zh": "⚠️  这是仅用于测试的钱包。绝对不要存入真实资产！",
                                   "en": "⚠️  This is a TEST-ONLY wallet. NEVER send real funds to this address!"},

    # ── OAuth 이메일 미검증 ATO (v3.2.66) ─────────────────────────────────
    "oauth_email_unverified_scan_start": {
        "ko": "🤖 AI 판단: OAuth Social Login 탐지 → 이메일 미검증 ATO 스캔 자동 활성화",
        "zh": "🤖 AI 判断: 检测到OAuth社交登录 → 自动启动未验证邮箱ATO扫描",
        "en": "🤖 AI decision: OAuth social login detected → email unverified ATO scan activated",
    },
    "oauth_email_unverified_test": {
        "ko": "🔍 IdP 이메일 미검증 계정 생성 테스트 중: {provider}",
        "zh": "🔍 正在测试IdP未验证邮箱账户创建: {provider}",
        "en": "🔍 Testing unverified email account creation at IdP: {provider}",
    },
    "oauth_email_unverified_vuln": {
        "ko": "🚨 [CRITICAL] 이메일 검증 없이 IdP 계정 생성 가능! email_verified 클레임: {val}",
        "zh": "🚨 [CRITICAL] IdP可无需邮箱验证创建账户！email_verified声明: {val}",
        "en": "🚨 [CRITICAL] IdP account created without email verification! email_verified: {val}",
    },
    "oauth_email_unverified_claim_bad": {
        "ko": "💥 타겟이 email_verified: false 클레임 무시 → 이메일로 계정 자동 연결 → ATO 완성",
        "zh": "💥 目标忽略email_verified: false声明 → 按邮箱自动关联账户 → ATO完成",
        "en": "💥 Target ignores email_verified: false claim → auto-links by email → ATO complete",
    },
    "oauth_email_unverified_safe": {
        "ko": "✅ IdP 이메일 검증 강제 또는 타겟이 email_verified 클레임 검증 — 안전",
        "zh": "✅ IdP强制邮箱验证或目标验证email_verified声明 — 安全",
        "en": "✅ IdP enforces email verification or target validates email_verified claim — safe",
    },
    "oauth_email_unverified_summary": {
        "ko": "🔑 이메일 미검증 ATO 요약: IdP={idp} | 미검증={unverified} | 타겟연결={link} | 심각도={sev}",
        "zh": "🔑 未验证邮箱ATO摘要: IdP={idp} | 未验证={unverified} | 目标关联={link} | 严重性={sev}",
        "en": "🔑 Unverified email ATO summary: IdP={idp} | unverified={unverified} | link={link} | severity={sev}",
    },

    # ── IoT MQTT 자격증명 탈취 (v3.2.66) ───────────────────────────────────
    "mqtt_cred_scan_start": {
        "ko": "🤖 AI 판단: IoT/채팅 서비스 탐지 → MQTT 자격증명 탈취 스캔 자동 활성화",
        "zh": "🤖 AI 判断: 检测到IoT/聊天服务 → 自动启动MQTT凭据泄露扫描",
        "en": "🤖 AI decision: IoT/chat service detected → MQTT credential leak scan activated",
    },
    "mqtt_cred_found_in_js": {
        "ko": "🚨 [HIGH] JS 소스에서 MQTT 자격증명 발견! host={host} user={user}",
        "zh": "🚨 [HIGH] 在JS源码中发现MQTT凭据！host={host} user={user}",
        "en": "🚨 [HIGH] MQTT credentials found in JS source! host={host} user={user}",
    },
    "mqtt_broker_connected": {
        "ko": "📡 MQTT 브로커 연결 성공: {host}:{port} — 모든 토픽('#') 구독 시작",
        "zh": "📡 MQTT Broker连接成功: {host}:{port} — 开始订阅所有主题('#')",
        "en": "📡 MQTT broker connected: {host}:{port} — subscribing to all topics ('#')",
    },
    "mqtt_message_intercepted": {
        "ko": "📨 MQTT 메시지 도청 성공! 토픽: {topic} — 대화 내용 탈취 가능",
        "zh": "📨 MQTT消息窃听成功！主题: {topic} — 可窃取对话内容",
        "en": "📨 MQTT message intercepted! Topic: {topic} — conversation content exposed",
    },
    "mqtt_no_finding": {
        "ko": "✓ MQTT: JS에서 자격증명 미발견 또는 브로커 연결 불가",
        "zh": "✓ MQTT: JS中未发现凭据或无法连接Broker",
        "en": "✓ MQTT: no credentials found in JS or broker unreachable",
    },
    "mqtt_summary": {
        "ko": "📡 MQTT 스캔 결과: 자격증명={cred} | 연결={conn} | 도청={intercept} | 심각도={sev}",
        "zh": "📡 MQTT扫描结果: 凭据={cred} | 连接={conn} | 窃听={intercept} | 严重性={sev}",
        "en": "📡 MQTT scan: credentials={cred} | connected={conn} | intercepted={intercept} | severity={sev}",
    },

    # ── AI Agent CI/CD Prompt Injection (v3.2.66) ──────────────────────────
    "ai_agent_ci_scan_start": {
        "ko": "🤖 AI 판단: GitHub Actions + AI Agent 탐지 → CI/CD 프롬프트 인젝션 스캔 자동 활성화",
        "zh": "🤖 AI 判断: 检测到GitHub Actions + AI Agent → 自动启动CI/CD提示词注入扫描",
        "en": "🤖 AI decision: GitHub Actions + AI agent detected → CI/CD prompt injection scan activated",
    },
    "ai_agent_ci_workflow_found": {
        "ko": "📋 AI Agent 워크플로 발견: {file} — 프롬프트 인젝션 취약성 평가 중",
        "zh": "📋 发现AI Agent工作流: {file} — 正在评估提示词注入漏洞",
        "en": "📋 AI agent workflow found: {file} — evaluating prompt injection risk",
    },
    "ai_agent_ci_user_input_direct": {
        "ko": "🚨 [HIGH] 사용자 입력({param}) 소독 없이 AI 에이전트 프롬프트에 직접 삽입!",
        "zh": "🚨 [HIGH] 用户输入({param})未经清理直接插入AI Agent提示词！",
        "en": "🚨 [HIGH] User input ({param}) inserted directly into AI agent prompt without sanitization!",
    },
    "ai_agent_ci_injection_poc": {
        "ko": "💥 프롬프트 인젝션 PoC 가능 — Issue/PR에 악성 지시 삽입 시 CI 명령 실행",
        "zh": "💥 提示词注入PoC可行 — 在Issue/PR中插入恶意指令可执行CI命令",
        "en": "💥 Prompt injection PoC viable — malicious instructions in Issue/PR execute CI commands",
    },
    "ai_agent_ci_secrets_exfil": {
        "ko": "🚨 [CRITICAL] AI 에이전트가 CI 환경 시크릿 탈취 명령 실행 가능 → 공급망 완전 오염",
        "zh": "🚨 [CRITICAL] AI Agent可执行CI环境密钥泄露命令 → 供应链完全污染",
        "en": "🚨 [CRITICAL] AI agent can execute CI secret exfiltration → full supply chain compromise",
    },
    "ai_agent_ci_safe": {
        "ko": "✅ AI Agent 워크플로: 사용자 입력 소독 또는 권한 제한 — 안전",
        "zh": "✅ AI Agent工作流: 用户输入已清理或权限受限 — 安全",
        "en": "✅ AI agent workflow: user input sanitized or permissions limited — safe",
    },
    "ai_agent_ci_summary": {
        "ko": "🔗 AI Agent CI 스캔 결과: 워크플로={wf} | 취약={vuln} | 인젝션가능={inj} | 심각도={sev}",
        "zh": "🔗 AI Agent CI扫描结果: 工作流={wf} | 漏洞={vuln} | 可注入={inj} | 严重性={sev}",
        "en": "🔗 AI agent CI scan: workflows={wf} | vulnerable={vuln} | injectable={inj} | severity={sev}",
    },

    # ── OAuth 오픈 클라이언트 등록 체인 공격 (v3.2.65) ─────────────────────
    "oauth_meta_probe":          {"ko": "🔍 OAuth 메타데이터 엔드포인트 탐지 중 ({url})",
                                   "zh": "🔍 正在探测OAuth元数据端点 ({url})",
                                   "en": "🔍 Probing OAuth metadata endpoint ({url})"},
    "oauth_reg_endpoint_found":  {"ko": "⚠️  registration_endpoint 발견! 미인증 등록 테스트 시작",
                                   "zh": "⚠️  发现registration_endpoint！开始测试未认证注册",
                                   "en": "⚠️  registration_endpoint found! Testing unauthenticated registration"},
    "oauth_reg_endpoint_none":   {"ko": "ℹ️  registration_endpoint 없음 — 오픈 등록 취약점 해당 없음",
                                   "zh": "ℹ️  未发现registration_endpoint — 无开放注册漏洞",
                                   "en": "ℹ️  No registration_endpoint — open registration not applicable"},
    "oauth_open_reg_vuln":       {"ko": "🚨 [CRITICAL] OAuth 오픈 클라이언트 등록 취약! client_id={cid}",
                                   "zh": "🚨 [CRITICAL] OAuth开放客户端注册漏洞！client_id={cid}",
                                   "en": "🚨 [CRITICAL] OAuth open client registration vulnerable! client_id={cid}"},
    "oauth_open_reg_safe":       {"ko": "✅ 클라이언트 등록 인증 필요 — 안전",
                                   "zh": "✅ 客户端注册需要认证 — 安全",
                                   "en": "✅ Client registration requires authentication — safe"},
    "oauth_redirect_uri_test":   {"ko": "🔗 redirect_uri 화이트리스트 검증 테스트 중...",
                                   "zh": "🔗 正在测试redirect_uri白名单验证...",
                                   "en": "🔗 Testing redirect_uri whitelist validation..."},
    "oauth_redirect_uri_vuln":   {"ko": "🚨 [HIGH] redirect_uri 검증 미흡 — 인가 코드 탈취 가능",
                                   "zh": "🚨 [HIGH] redirect_uri验证不足 — 可劫持授权码",
                                   "en": "🚨 [HIGH] Weak redirect_uri validation — authorization code hijacking possible"},
    "oauth_pkce_missing":        {"ko": "🚨 [HIGH] PKCE 미강제 — code_verifier 없이 토큰 교환 성공",
                                   "zh": "🚨 [HIGH] PKCE未强制 — 无code_verifier即可换取令牌",
                                   "en": "🚨 [HIGH] PKCE not enforced — token exchange succeeds without code_verifier"},
    "oauth_pkce_ok":             {"ko": "✅ PKCE (S256) 강제 확인 — 안전",
                                   "zh": "✅ 已确认PKCE(S256)强制执行 — 安全",
                                   "en": "✅ PKCE (S256) enforced — safe"},
    "oauth_cors_wildcard":       {"ko": "🚨 [HIGH] 와일드카드 CORS + Credentials — 크로스오리진 토큰 탈취 가능",
                                   "zh": "🚨 [HIGH] 通配符CORS + Credentials — 可跨域劫持令牌",
                                   "en": "🚨 [HIGH] Wildcard CORS + Credentials — cross-origin token theft possible"},
    "oauth_cors_ok":             {"ko": "✅ CORS 정책 안전",
                                   "zh": "✅ CORS策略安全",
                                   "en": "✅ CORS policy is safe"},
    "oauth_chain_ato_confirmed": {"ko": "🚨 [CRITICAL] OAuth 체인 계정 탈취 확인! 액세스 토큰 획득 성공",
                                   "zh": "🚨 [CRITICAL] OAuth链式账户接管已确认！成功获取访问令牌",
                                   "en": "🚨 [CRITICAL] OAuth chain account takeover confirmed! Access token acquired"},
    "oauth_chain_summary":       {"ko": "📋 OAuth 오픈 등록 체인 요약: 등록={reg} / redirect_uri={redir} / PKCE={pkce} / CORS={cors}",
                                   "zh": "📋 OAuth开放注册链摘要: 注册={reg} / redirect_uri={redir} / PKCE={pkce} / CORS={cors}",
                                   "en": "📋 OAuth open reg chain summary: reg={reg} / redirect_uri={redir} / PKCE={pkce} / CORS={cors}"},

    # ── v3.2.67 신규 스킬 다국어 키 ────────────────────────────────────────────

    # sec-web-dom-clobbering
    "dom_clobber_dompurify_check": {
        "ko": "🔍 DOMPurify 버전 및 id/name 속성 필터링 여부 확인 중...",
        "zh": "🔍 正在检查DOMPurify版本及id/name属性过滤状态...",
        "en": "🔍 Checking DOMPurify version and id/name attribute filtering...",
    },
    "dom_clobber_vuln": {
        "ko": "🚨 [HIGH] DOM Clobbering 가능 — id/name 속성이 전역 변수를 덮어씀, XSS 체인 위험",
        "zh": "🚨 [HIGH] 存在DOM Clobbering — id/name属性可覆盖全局变量，XSS链风险",
        "en": "🚨 [HIGH] DOM Clobbering possible — id/name attributes overwrite globals, XSS chain risk",
    },
    "dom_clobber_safe": {
        "ko": "✅ id/name 속성 필터링 확인 — DOM Clobbering 불가",
        "zh": "✅ id/name属性已过滤 — DOM Clobbering不可行",
        "en": "✅ id/name attribute filtering confirmed — DOM Clobbering not possible",
    },

    # sec-web-dompurify-pp-bypass
    "dompurify_pp_probe": {
        "ko": "🔍 Prototype Pollution + DOMPurify contenteditable 우회 테스트 중...",
        "zh": "🔍 正在测试Prototype Pollution + DOMPurify contenteditable绕过...",
        "en": "🔍 Testing Prototype Pollution + DOMPurify contenteditable bypass...",
    },
    "dompurify_pp_vuln": {
        "ko": "🚨 [CRITICAL] DOMPurify PP 우회 성공 — Prototype 오염으로 XSS 필터 무력화",
        "zh": "🚨 [CRITICAL] DOMPurify PP绕过成功 — 原型污染导致XSS过滤器失效",
        "en": "🚨 [CRITICAL] DOMPurify PP bypass success — prototype pollution neutralizes XSS filter",
    },
    "dompurify_pp_safe": {
        "ko": "✅ Prototype Pollution 또는 DOMPurify 안전 — PP 우회 불가",
        "zh": "✅ Prototype Pollution或DOMPurify安全 — 无法绕过",
        "en": "✅ Prototype Pollution or DOMPurify safe — bypass not possible",
    },

    # sec-web-imagemagick-ghostscript-rce
    "imagemagick_version_check": {
        "ko": "🔍 ImageMagick/Ghostscript 버전 및 정책 파일 확인 중...",
        "zh": "🔍 正在检查ImageMagick/Ghostscript版本及策略文件...",
        "en": "🔍 Checking ImageMagick/Ghostscript version and policy file...",
    },
    "imagemagick_mvg_vuln": {
        "ko": "🚨 [CRITICAL] MVG/MSL 인젝션 가능 — SVG→RCE 체인 위험",
        "zh": "🚨 [CRITICAL] 可进行MVG/MSL注入 — SVG→RCE链风险",
        "en": "🚨 [CRITICAL] MVG/MSL injection possible — SVG to RCE chain risk",
    },
    "imagemagick_policy_ok": {
        "ko": "✅ ImageMagick 정책 파일이 MVG/MSL/SVG 비활성화 — 안전",
        "zh": "✅ ImageMagick策略文件已禁用MVG/MSL/SVG — 安全",
        "en": "✅ ImageMagick policy disables MVG/MSL/SVG — safe",
    },

    # sec-cloud-aws-alb-bypass
    "alb_direct_probe": {
        "ko": "🔍 AWS ALB 직접 접근 및 CloudFront/WAF 우회 가능성 테스트 중...",
        "zh": "🔍 正在测试AWS ALB直接访问及CloudFront/WAF绕过可能性...",
        "en": "🔍 Testing AWS ALB direct access and CloudFront/WAF bypass possibility...",
    },
    "alb_bypass_vuln": {
        "ko": "🚨 [HIGH] ALB 직접 접근 성공 — CloudFront/WAF 완전 우회",
        "zh": "🚨 [HIGH] ALB直接访问成功 — CloudFront/WAF完全绕过",
        "en": "🚨 [HIGH] ALB direct access success — CloudFront/WAF fully bypassed",
    },
    "alb_rule_shadow": {
        "ko": "🚨 [HIGH] ALB 룰 섀도잉 탐지 — 낮은 우선순위 룰이 높은 우선순위 룰 무력화",
        "zh": "🚨 [HIGH] 检测到ALB规则遮蔽 — 低优先级规则使高优先级规则失效",
        "en": "🚨 [HIGH] ALB rule shadowing detected — lower priority rule overrides higher priority rule",
    },
    "alb_protected": {
        "ko": "✅ ALB Security Group이 CloudFront IP 범위만 허용 — 안전",
        "zh": "✅ ALB安全组仅允许CloudFront IP范围 — 安全",
        "en": "✅ ALB Security Group allows only CloudFront IP ranges — safe",
    },

    # sec-cloud-gcp-debug-rce
    "gcp_debug_probe": {
        "ko": "🔍 GCP 내부 디버그 엔드포인트 탐색 중...",
        "zh": "🔍 正在探测GCP内部调试端点...",
        "en": "🔍 Probing GCP internal debug endpoints...",
    },
    "gcp_debug_rce_vuln": {
        "ko": "🚨 [CRITICAL] GCP 디버그 엔드포인트 RCE — Protobuf 스키마 노출 + 워크플로 실행",
        "zh": "🚨 [CRITICAL] GCP调试端点RCE — Protobuf架构泄露+工作流执行",
        "en": "🚨 [CRITICAL] GCP debug endpoint RCE — Protobuf schema leak + workflow execution",
    },
    "gcp_debug_safe": {
        "ko": "✅ GCP 디버그 엔드포인트 미노출 또는 인증 필요 — 안전",
        "zh": "✅ GCP调试端点未暴露或需要认证 — 安全",
        "en": "✅ GCP debug endpoint not exposed or requires auth — safe",
    },

    # sec-cloud-aws-cognito-sso
    "cognito_sso_probe": {
        "ko": "🔍 AWS Cognito User Pool 다중 IdP 설정 분석 중...",
        "zh": "🔍 正在分析AWS Cognito用户池多IdP配置...",
        "en": "🔍 Analyzing AWS Cognito User Pool multi-IdP configuration...",
    },
    "cognito_ghost_identity": {
        "ko": "🚨 [CRITICAL] Cognito Ghost Identity 인젝션 가능 — JIT 계정 생성 오남용",
        "zh": "🚨 [CRITICAL] Cognito Ghost Identity注入可行 — JIT账户创建被滥用",
        "en": "🚨 [CRITICAL] Cognito Ghost Identity injection possible — JIT account creation abused",
    },
    "cognito_trigger_confused": {
        "ko": "🚨 [HIGH] Cognito Trigger Source 혼동 — Pre-Auth Lambda 우회 가능",
        "zh": "🚨 [HIGH] Cognito Trigger Source混淆 — 可绕过Pre-Auth Lambda",
        "en": "🚨 [HIGH] Cognito Trigger Source confused — Pre-Auth Lambda bypass possible",
    },
    "cognito_sso_safe": {
        "ko": "✅ Cognito IdP 이메일 검증 및 Trigger Source 검증 — 안전",
        "zh": "✅ Cognito IdP邮箱验证及Trigger Source验证 — 安全",
        "en": "✅ Cognito IdP email validation and Trigger Source verification — safe",
    },

    # sec-supply-chain-npx-confusion
    "npx_confusion_scan": {
        "ko": "🔍 npx 바이너리명 혼동 공격 가능성 스캔 중...",
        "zh": "🔍 正在扫描npx二进制名混淆攻击可能性...",
        "en": "🔍 Scanning for npx binary name confusion attack possibility...",
    },
    "npx_confusion_vuln": {
        "ko": "🚨 [HIGH] npx 바이너리명 혼동 탐지 — 악성 패키지가 동일 바이너리명으로 등록됨",
        "zh": "🚨 [HIGH] 检测到npx二进制名混淆 — 恶意包以相同二进制名注册",
        "en": "🚨 [HIGH] npx binary name confusion detected — malicious package registered with same binary name",
    },
    "npx_confusion_safe": {
        "ko": "✅ 바이너리명 충돌 없음 또는 스코프 패키지 사용 — 안전",
        "zh": "✅ 无二进制名冲突或使用作用域包 — 安全",
        "en": "✅ No binary name collision or scoped package used — safe",
    },

    # sec-infra-exim-rce
    "exim_version_check": {
        "ko": "🔍 Exim MTA 버전 확인 중 (CVE-2026-45185 대상: 4.96 이하)...",
        "zh": "🔍 正在检查Exim MTA版本（CVE-2026-45185影响：4.96及以下）...",
        "en": "🔍 Checking Exim MTA version (CVE-2026-45185 target: 4.96 and below)...",
    },
    "exim_rce_vuln": {
        "ko": "🚨 [CRITICAL] Exim 취약 버전 탐지 — dead letter 역직렬화 RCE 가능 (CVE-2026-45185)",
        "zh": "🚨 [CRITICAL] 检测到Exim漏洞版本 — dead letter反序列化RCE可行（CVE-2026-45185）",
        "en": "🚨 [CRITICAL] Exim vulnerable version detected — dead letter deserialization RCE (CVE-2026-45185)",
    },
    "exim_patched": {
        "ko": "✅ Exim 4.97+ 패치 적용 또는 SMTP 접근 제한 — 안전",
        "zh": "✅ 已应用Exim 4.97+补丁或限制SMTP访问 — 安全",
        "en": "✅ Exim 4.97+ patched or SMTP access restricted — safe",
    },

    # sec-android-wireless-debug-rce
    "android_adb_scan": {
        "ko": "🔍 Android ADB 무선 디버깅 포트(5554-5558) 스캔 중...",
        "zh": "🔍 正在扫描Android ADB无线调试端口（5554-5558）...",
        "en": "🔍 Scanning for Android ADB wireless debugging ports (5554-5558)...",
    },
    "android_adb_rce_vuln": {
        "ko": "🚨 [CRITICAL] Android ADB 무선 디버깅 인증 없이 접근 가능 (CVE-2026-0073) — RCE",
        "zh": "🚨 [CRITICAL] Android ADB无线调试可无认证访问（CVE-2026-0073）— RCE",
        "en": "🚨 [CRITICAL] Android ADB wireless debugging accessible without auth (CVE-2026-0073) — RCE",
    },
    "android_adb_safe": {
        "ko": "✅ ADB 무선 디버깅 포트 미노출 또는 접근 불가 — 안전",
        "zh": "✅ ADB无线调试端口未暴露或无法访问 — 安全",
        "en": "✅ ADB wireless debugging port not exposed or inaccessible — safe",
    },

    # sec-kernel-af-alg-lpe
    "kernel_af_alg_check": {
        "ko": "🔍 커널 버전 및 AF_ALG 소켓 지원 확인 중 (CVE-2026-31431)...",
        "zh": "🔍 正在检查内核版本及AF_ALG套接字支持（CVE-2026-31431）...",
        "en": "🔍 Checking kernel version and AF_ALG socket support (CVE-2026-31431)...",
    },
    "kernel_af_alg_vuln": {
        "ko": "🚨 [CRITICAL] Linux 커널 AF_ALG + splice() 페이지 캐시 LPE 가능 (CVE-2026-31431)",
        "zh": "🚨 [CRITICAL] Linux内核AF_ALG + splice()页缓存LPE可行（CVE-2026-31431）",
        "en": "🚨 [CRITICAL] Linux kernel AF_ALG + splice() page cache LPE possible (CVE-2026-31431)",
    },
    "kernel_af_alg_safe": {
        "ko": "✅ 커널 패치 적용 또는 seccomp로 AF_ALG 차단 — 안전",
        "zh": "✅ 已应用内核补丁或seccomp阻止AF_ALG — 安全",
        "en": "✅ Kernel patched or seccomp blocks AF_ALG — safe",
    },

    # sec-ai-ide-toctou-rce
    "ai_ide_prompt_inject_probe": {
        "ko": "🔍 AI IDE 프롬프트 인젝션 + TOCTOU RCE 가능성 분석 중...",
        "zh": "🔍 正在分析AI IDE提示词注入+TOCTOU RCE可能性...",
        "en": "🔍 Analyzing AI IDE prompt injection + TOCTOU RCE possibility...",
    },
    "ai_ide_toctou_vuln": {
        "ko": "🚨 [CRITICAL] AI IDE TOCTOU RCE — applyPatchTool 경로 검증 없이 .git/config 오버라이트",
        "zh": "🚨 [CRITICAL] AI IDE TOCTOU RCE — applyPatchTool未验证路径覆写.git/config",
        "en": "🚨 [CRITICAL] AI IDE TOCTOU RCE — applyPatchTool overwrites .git/config without path validation",
    },
    "ai_ide_token_stolen": {
        "ko": "🚨 [CRITICAL] GITHUB_TOKEN 탈취 가능 — 공급망 완전 오염 위험",
        "zh": "🚨 [CRITICAL] GITHUB_TOKEN可被窃取 — 供应链完全污染风险",
        "en": "🚨 [CRITICAL] GITHUB_TOKEN theft possible — full supply chain compromise risk",
    },
    "ai_ide_toctou_safe": {
        "ko": "✅ AI IDE 경로 검증 강화 또는 GITHUB_TOKEN 최소 권한 — 안전",
        "zh": "✅ AI IDE路径验证已加强或GITHUB_TOKEN权限最小化 — 安全",
        "en": "✅ AI IDE path validation hardened or GITHUB_TOKEN minimal permissions — safe",
    },

    # sec-ai-autonomous-hunt-mcp
    "ai_mcp_hunt_init": {
        "ko": "🤖 Claude Code + MCP 자율 취약점 헌팅 시스템 초기화 중...",
        "zh": "🤖 正在初始化Claude Code + MCP自主漏洞挖掘系统...",
        "en": "🤖 Initializing Claude Code + MCP autonomous vulnerability hunting system...",
    },
    "ai_mcp_hallucination_bin": {
        "ko": "⚠️  Hallucination Bin 저장 — AI 생성 취약점은 수동 검증 필수",
        "zh": "⚠️  Hallucination Bin存储 — AI生成漏洞必须手动验证",
        "en": "⚠️  Hallucination Bin stored — AI-generated vulns require manual verification",
    },
    "ai_mcp_confirmed_vuln": {
        "ko": "✅ 취약점 확인 완료 — Knowledge Loop RAG DB 누적",
        "zh": "✅ 漏洞已确认 — Knowledge Loop RAG数据库累积",
        "en": "✅ Vulnerability confirmed — accumulated in Knowledge Loop RAG DB",
    },
    "ai_mcp_hunt_summary": {
        "ko": "📊 자율 헌팅 결과: 발견={found} | 미확인={unconfirmed} | 확인={confirmed} | 오탐={fp}",
        "zh": "📊 自主挖掘结果: 发现={found} | 未确认={unconfirmed} | 已确认={confirmed} | 误报={fp}",
        "en": "📊 Autonomous hunt results: found={found} | unconfirmed={unconfirmed} | confirmed={confirmed} | fp={fp}",
    },

    # ── v3.2.68 신규 스킬 다국어 키 ──────────────────────────────────────────

    # sec-cpp-libc-gotcha
    "cpp_libc_init": {
        "ko": "🔍 C/C++ Linux libc 함정 & seccomp/BPF 샌드박스 우회 분석 시작...",
        "zh": "🔍 开始分析C/C++ Linux libc陷阱和seccomp/BPF沙盒绕过...",
        "en": "🔍 Starting C/C++ Linux libc gotcha & seccomp/BPF sandbox bypass analysis...",
    },
    "cpp_libc_inet_ntoa": {
        "ko": "⚠️  inet_ntoa() 정적 버퍼 레이스 조건 발견 — inet_ntop로 교체 필요",
        "zh": "⚠️  发现inet_ntoa()静态缓冲区竞争条件 — 需要替换为inet_ntop",
        "en": "⚠️  inet_ntoa() static buffer race condition found — replace with inet_ntop",
    },
    "cpp_seccomp_vulnerable": {
        "ko": "🚨 seccomp BPF 필터에 io_uring syscall 미차단 — 샌드박스 우회 가능",
        "zh": "🚨 seccomp BPF过滤器未拦截io_uring syscall — 可绕过沙盒",
        "en": "🚨 seccomp BPF filter does not block io_uring syscalls — sandbox bypass possible",
    },
    "cpp_libc_safe": {
        "ko": "✅ libc 함정 미탐지 — AddressSanitizer 추가 검증 권장",
        "zh": "✅ 未检测到libc陷阱 — 建议使用AddressSanitizer进行额外验证",
        "en": "✅ No libc gotchas detected — AddressSanitizer additional verification recommended",
    },

    # sec-windows-driver-registry-tycon
    "windrv_init": {
        "ko": "🔍 Windows WDF 드라이버 RTL_QUERY_REGISTRY_TABLE 타입 혼동 분석...",
        "zh": "🔍 分析Windows WDF驱动程序RTL_QUERY_REGISTRY_TABLE类型混淆...",
        "en": "🔍 Analyzing Windows WDF driver RTL_QUERY_REGISTRY_TABLE type confusion...",
    },
    "windrv_type_confused": {
        "ko": "🚨 레지스트리 값 타입 혼동 가능 — EntryContext 함수 포인터 덮어쓰기 위험",
        "zh": "🚨 注册表值类型混淆可能 — EntryContext函数指针覆写风险",
        "en": "🚨 Registry value type confusion possible — EntryContext function pointer overwrite risk",
    },
    "windrv_dos_possible": {
        "ko": "⚠️  RTL_QUERY_REGISTRY_DIRECT DoS 가능 — 큰 레지스트리 값으로 커널 버퍼 오버플로우",
        "zh": "⚠️  RTL_QUERY_REGISTRY_DIRECT DoS可能 — 大注册表值导致内核缓冲区溢出",
        "en": "⚠️  RTL_QUERY_REGISTRY_DIRECT DoS possible — oversized registry value → kernel buffer overflow",
    },
    "windrv_safe": {
        "ko": "✅ 레지스트리 쿼리 처리 안전 — QueryRoutine 콜백 방식 사용 확인",
        "zh": "✅ 注册表查询处理安全 — 确认使用QueryRoutine回调方式",
        "en": "✅ Registry query handling safe — QueryRoutine callback pattern confirmed",
    },

    # sec-web-oauth-dcr-ssrf-chain
    "dcr_ssrf_init": {
        "ko": "🔍 OAuth DCR + Open Redirect + Path Normalization → Full-Read SSRF 체인 분석...",
        "zh": "🔍 分析OAuth DCR + 开放重定向 + 路径规范化 → 完整读取SSRF链...",
        "en": "🔍 Analyzing OAuth DCR + Open Redirect + Path Normalization → Full-Read SSRF chain...",
    },
    "dcr_ssrf_endpoint": {
        "ko": "📡 OAuth DCR 엔드포인트 발견: {url} — redirect_uri 검증 테스트 중",
        "zh": "📡 发现OAuth DCR端点: {url} — 正在测试redirect_uri验证",
        "en": "📡 OAuth DCR endpoint found: {url} — testing redirect_uri validation",
    },
    "dcr_ssrf_vulnerable": {
        "ko": "🚨 DCR redirect_uri 미검증 + Open Redirect 확인 — Full-Read SSRF 가능",
        "zh": "🚨 DCR redirect_uri未验证 + 开放重定向已确认 — 完整读取SSRF可能",
        "en": "🚨 DCR redirect_uri unvalidated + Open Redirect confirmed — Full-Read SSRF possible",
    },
    "dcr_ssrf_safe": {
        "ko": "✅ DCR redirect_uri 화이트리스트 검증 확인 — SSRF 체인 불가",
        "zh": "✅ 确认DCR redirect_uri白名单验证 — SSRF链不可行",
        "en": "✅ DCR redirect_uri whitelist validation confirmed — SSRF chain not feasible",
    },

    # sec-web-smuggling-upgrade-bypass
    "smuggle_upgrade_init": {
        "ko": "🔍 HTTP Upgrade 헤더 패스스루 취약점 & Request Smuggling 분석...",
        "zh": "🔍 分析HTTP Upgrade头透传漏洞和请求走私...",
        "en": "🔍 Analyzing HTTP Upgrade header passthrough vulnerability & Request Smuggling...",
    },
    "smuggle_upgrade_vulnerable": {
        "ko": "🚨 Upgrade 헤더 미검증 패스스루 확인 (CVE-2026-2833) — Request Smuggling 가능",
        "zh": "🚨 确认Upgrade头未验证透传(CVE-2026-2833) — 请求走私可能",
        "en": "🚨 Upgrade header unvalidated passthrough confirmed (CVE-2026-2833) — Request Smuggling possible",
    },
    "smuggle_cache_poison": {
        "ko": "⚠️  Cache Poisoning 체인 가능 — 스머글된 응답이 캐시에 저장됨",
        "zh": "⚠️  缓存投毒链可能 — 走私响应已存储在缓存中",
        "en": "⚠️  Cache Poisoning chain possible — smuggled response stored in cache",
    },
    "smuggle_upgrade_safe": {
        "ko": "✅ Upgrade 처리 안전 — 101 응답 확인 후 패스스루 전환 확인",
        "zh": "✅ Upgrade处理安全 — 确认收到101响应后才切换透传",
        "en": "✅ Upgrade handling safe — switches to passthrough only after 101 response confirmed",
    },

    # sec-cloud-git-toctou-fsmonitor-rce
    "git_toctou_init": {
        "ko": "🔍 Git 디렉터리 삭제 TOCTOU + fsmonitor Hook RCE 분석...",
        "zh": "🔍 分析Git目录删除TOCTOU + fsmonitor钩子RCE...",
        "en": "🔍 Analyzing Git directory deletion TOCTOU + fsmonitor hook RCE...",
    },
    "git_toctou_dir_bypass": {
        "ko": "🚨 dir_path_array=[\"/\"] 검증 우회 성공 — .git 삭제 레이스 조건 시도 중",
        "zh": "🚨 dir_path_array=[\"/\"]验证绕过成功 — 正在尝试.git删除竞争条件",
        "en": "🚨 dir_path_array=[\"/\"] validation bypass succeeded — attempting .git deletion race",
    },
    "git_fsmonitor_rce": {
        "ko": "💥 fsmonitor 훅 트리거 성공 — 임의 명령 실행 (RCE) 달성!",
        "zh": "💥 fsmonitor钩子触发成功 — 任意命令执行(RCE)已实现!",
        "en": "💥 fsmonitor hook triggered successfully — arbitrary command execution (RCE) achieved!",
    },
    "git_k8s_privesc": {
        "ko": "⚠️  K8s 서비스 계정 secrets 업데이트 권한 발견 — 타 인스턴스 접근 가능",
        "zh": "⚠️  发现K8s服务账户secrets更新权限 — 可访问其他实例",
        "en": "⚠️  K8s service account secrets update permission found — other instances accessible",
    },

    # sec-ai-chrome-ext-xss-prompt-inject
    "chrome_ext_init": {
        "ko": "🔍 Chrome 확장 Wildcard Origin + DOM-XSS → AI 프롬프트 하이재킹 분석...",
        "zh": "🔍 分析Chrome扩展通配符来源 + DOM-XSS → AI提示词劫持...",
        "en": "🔍 Analyzing Chrome extension Wildcard Origin + DOM-XSS → AI prompt hijacking...",
    },
    "chrome_ext_wildcard": {
        "ko": "⚠️  Chrome 확장 wildcard origin 허용 발견: {pattern} — 서브도메인 XSS 탐색 중",
        "zh": "⚠️  发现Chrome扩展通配符来源允许: {pattern} — 正在探索子域XSS",
        "en": "⚠️  Chrome extension wildcard origin found: {pattern} — exploring subdomain XSS",
    },
    "chrome_ext_xss_found": {
        "ko": "🚨 서브도메인 DOM-XSS 발견 (dangerouslySetInnerHTML + postMessage 오리진 미검증)",
        "zh": "🚨 发现子域DOM-XSS (dangerouslySetInnerHTML + postMessage来源未验证)",
        "en": "🚨 Subdomain DOM-XSS found (dangerouslySetInnerHTML + postMessage origin not verified)",
    },
    "chrome_ext_prompt_hijack": {
        "ko": "💥 AI 어시스턴트 프롬프트 하이재킹 성공 — Gmail/Drive 토큰 탈취 가능",
        "zh": "💥 AI助手提示词劫持成功 — 可窃取Gmail/Drive令牌",
        "en": "💥 AI assistant prompt hijacking successful — Gmail/Drive token theft possible",
    },

    # sec-ai-rag-sqli-vector-store
    "rag_sqli_init": {
        "ko": "🔍 AI RAG 벡터 스토어 SQL Injection (CVE-2026-22730 패턴) 분석...",
        "zh": "🔍 分析AI RAG向量存储SQL注入(CVE-2026-22730模式)...",
        "en": "🔍 Analyzing AI RAG vector store SQL Injection (CVE-2026-22730 pattern)...",
    },
    "rag_sqli_vulnerable": {
        "ko": "🚨 RAG 메타데이터 필터 SQL Injection 확인 — 테넌트 격리 우회 가능 (CVSS 8.8)",
        "zh": "🚨 RAG元数据过滤器SQL注入已确认 — 租户隔离可绕过(CVSS 8.8)",
        "en": "🚨 RAG metadata filter SQL injection confirmed — tenant isolation bypass possible (CVSS 8.8)",
    },
    "rag_sqli_delete": {
        "ko": "💥 DELETE 경로 SQL Injection — 전체 벡터 스토어 삭제 가능 (서비스 중단)",
        "zh": "💥 DELETE路径SQL注入 — 可删除整个向量存储(服务中断)",
        "en": "💥 DELETE path SQL injection — entire vector store deletion possible (service disruption)",
    },
    "rag_sqli_safe": {
        "ko": "✅ Spring AI 1.0.4/1.1.3 이상 확인 — 벡터 스토어 필터 이스케이프 패치됨",
        "zh": "✅ 确认Spring AI 1.0.4/1.1.3或更高版本 — 向量存储过滤器转义已修补",
        "en": "✅ Spring AI 1.0.4/1.1.3 or higher confirmed — vector store filter escaping patched",
    },

    # sec-ai-agent-dns-confusion-escape
    "ai_agent_dns_init": {
        "ko": "🔍 AI 에이전트 DNS Confusion + 샌드박스 탈출 + Guardrail 우회 분석...",
        "zh": "🔍 分析AI代理DNS混淆 + 沙盒逃逸 + 护栏绕过...",
        "en": "🔍 Analyzing AI agent DNS Confusion + sandbox escape + guardrail bypass...",
    },
    "ai_agent_detected": {
        "ko": "📡 AI 에이전트 탐지 (User-Agent: {ua}) — 역공격 시나리오 준비",
        "zh": "📡 AI代理已检测到(User-Agent: {ua}) — 准备反击场景",
        "en": "📡 AI agent detected (User-Agent: {ua}) — preparing counterattack scenario",
    },
    "ai_agent_dns_confusion": {
        "ko": "🚨 DNS Confusion 가능 — 프라이빗 DNS 레코드 조작으로 에이전트 스캔 대상 변경 가능",
        "zh": "🚨 DNS混淆可能 — 操纵私有DNS记录可改变代理扫描目标",
        "en": "🚨 DNS Confusion possible — private DNS record manipulation can redirect agent scan target",
    },
    "ai_agent_aws_token": {
        "ko": "💥 AWS IMDS 토큰 탈취 성공 — 클라우드 자격증명 획득!",
        "zh": "💥 AWS IMDS令牌窃取成功 — 获取云凭证!",
        "en": "💥 AWS IMDS token stolen successfully — cloud credentials obtained!",
    },

    # sec-web-hmac-bypass-deser
    "hmac_deser_init": {
        "ko": "🔍 HMAC IV 구조 오류 서명 우회 → Java 역직렬화 RCE 분석...",
        "zh": "🔍 分析HMAC IV结构错误签名绕过 → Java反序列化RCE...",
        "en": "🔍 Analyzing HMAC IV structure flaw signature bypass → Java deserialization RCE...",
    },
    "hmac_deser_bypass": {
        "ko": "🚨 HMAC 서명 우회 가능 — IV 분리 구조 오류로 임의 메시지 서명 생성 가능",
        "zh": "🚨 HMAC签名可绕过 — IV分离结构错误可生成任意消息签名",
        "en": "🚨 HMAC signature bypassable — IV separation flaw allows forging arbitrary message signatures",
    },
    "hmac_deser_rce": {
        "ko": "💥 Java 역직렬화 RCE 달성 — ysoserial 페이로드 실행 성공!",
        "zh": "💥 Java反序列化RCE已实现 — ysoserial载荷执行成功!",
        "en": "💥 Java deserialization RCE achieved — ysoserial payload executed successfully!",
    },
    "hmac_deser_safe": {
        "ko": "✅ HMAC 검증 안전 — IV 포함 전체 메시지 서명 또는 안전한 직렬화 라이브러리 사용",
        "zh": "✅ HMAC验证安全 — 包含IV的完整消息签名或使用安全序列化库",
        "en": "✅ HMAC validation safe — full message including IV signed or safe serialization library used",
    },

    # sec-cloud-bi-cross-tenant-sqli
    "bi_cross_tenant_init": {
        "ko": "🔍 Cloud BI 크로스 테넌트 SQL Injection + XS-Leak + Denial of Wallet 분석...",
        "zh": "🔍 分析Cloud BI跨租户SQL注入 + XS泄漏 + 拒绝钱包...",
        "en": "🔍 Analyzing Cloud BI cross-tenant SQL injection + XS-Leak + Denial of Wallet...",
    },
    "bi_cross_tenant_0click": {
        "ko": "🚨 0-click 크로스 테넌트 SQL Injection 확인 — Owner 자격증명으로 피해자 DB 접근",
        "zh": "🚨 0点击跨租户SQL注入已确认 — 使用所有者凭证访问受害者数据库",
        "en": "🚨 0-click cross-tenant SQL injection confirmed — victim DB accessed via owner credentials",
    },
    "bi_denial_of_wallet": {
        "ko": "💸 Denial of Wallet 공격 가능 — BigQuery 대용량 쿼리 강제 실행으로 피해자 비용 폭탄",
        "zh": "💸 拒绝钱包攻击可能 — 强制执行BigQuery大量查询导致受害者费用暴增",
        "en": "💸 Denial of Wallet possible — forced BigQuery bulk queries cause victim cost explosion",
    },
    "bi_xs_leak": {
        "ko": "⚠️  XS-Leak 가능 — Frame Counting/Timing Oracle로 크로스 테넌트 데이터 추론",
        "zh": "⚠️  XS泄漏可能 — Frame计数/时序预言机可推断跨租户数据",
        "en": "⚠️  XS-Leak possible — Frame Counting/Timing Oracle allows cross-tenant data inference",
    },
    # ── v3.2.72: 세션 로그 자동 파싱 관련 ─────────────────────────────
    "session_parsed_saved": {
        "ko": "🧠 세션 파싱 완료 → SQLi={0}건 / 유저={1}명 / 엔드포인트={2}건 target_memory에 저장 (다음 세션 자동 로드)",
        "zh": "🧠 会话解析完成 → SQLi={0}项 / 用户={1}个 / 端点={2}个 已存入target_memory（下次会话自动加载）",
        "en": "🧠 Session parsed → SQLi={0} / users={1} / endpoints={2} saved to target_memory (auto-loaded next session)",
    },
    "session_parsed_empty": {
        "ko": "📭 세션 파싱 완료 — 새로운 취약점 정보 없음",
        "zh": "📭 会话解析完成 — 无新漏洞信息",
        "en": "📭 Session parsed — no new vulnerability info found",
    },
    "session_parse_start": {
        "ko": "🔍 세션 로그 파싱 중 (SQLi/유저/엔드포인트 추출)...",
        "zh": "🔍 正在解析会话日志（提取SQLi/用户/端点）...",
        "en": "🔍 Parsing session log (extracting SQLi/users/endpoints)...",
    },
    "session_parse_injected": {
        "ko": "🧠 이전 세션 발견 정보를 AI 컨텍스트에 주입 완료",
        "zh": "🧠 已将上次会话发现信息注入AI上下文",
        "en": "🧠 Previous session findings injected into AI context",
    },
    # ── v3.2.73: 모의실행(模拟渗透) 차단 관련 ─────────────────────────────
    "simulated_output_intercepted": {
        "ko": "⛔ 모의 침투 출력 감지 — 실제 HTTP 실행 강제 재요청",
        "zh": "⛔ 检测到模拟渗透输出 — 强制要求真实HTTP执行",
        "en": "⛔ Simulated penetration output detected — forcing real HTTP execution",
    },
    "simulated_output_retrying": {
        "ko": "⛔ 모의실행 차단 → 실제 HTTP 코드 재요청 중...",
        "zh": "⛔ 模拟执行已拦截 → 正在重新请求真实HTTP代码...",
        "en": "⛔ Simulation blocked → requesting real HTTP code...",
    },
    "sim_code_blocked": {
        "ko": "⛔ [코드 내 모의실행 감지] simulated_response / 模拟 변수 사용 금지 — ```bash 블록 안에서 curl 명령으로 실제 HTTP 요청 필수",
        "zh": "⛔ [检测到代码内模拟执行] 禁止使用simulated_response/模拟变量 — 必须在```bash块中使用curl发送真实HTTP请求",
        "en": "⛔ [In-code simulation detected] simulated_response/模拟 vars forbidden — use real curl inside a ```bash block",
    },
    "sim_var_warning": {
        "ko": "⚠️ 코드에서 모의/가짜 결과 변수 감지 — 네트워크 연결 정상, 실제 HTTP 요청 실행 가능",
        "zh": "⚠️ 代码中检测到模拟/虚假结果变量 — 网络连接正常，可执行真实HTTP请求",
        "en": "⚠️ Mock/fake result variable in code — network is live, real HTTP requests work",
    },

    # ── v3.2.83: 화이트박스 하이브리드 모드 ─────────────────────────
    "wb_hybrid_target": {
        "ko": "🎯 하이브리드 모드: 타깃 URL → {url}",
        "zh": "🎯 混合模式：目标 URL → {url}",
        "en": "🎯 Hybrid mode: target URL → {url}",
    },
    "wb_hybrid_hint": {
        "ko": "소스코드 힌트 + 라이브 HTTP 공격 동시 진행",
        "zh": "源码提示 + 实时HTTP攻击同步进行",
        "en": "Source code hints + live HTTP attacks combined",
    },
    "wb_ask_path": {
        "ko": "📂 소스코드 경로 있으면 입력 (없으면 엔터):",
        "zh": "📂 请输入源代码路径（没有则按回车）:",
        "en": "📂 Source code path? (press Enter to skip):",
    },
    "wb_ask_path_cmd": {
        "ko": "📂 소스코드 경로 입력 (디렉토리 또는 파일):",
        "zh": "📂 请输入源代码路径（目录或文件）:",
        "en": "📂 Enter source code path (directory or file):",
    },
    "wb_path_not_found": {
        "ko": "경로 없음: {path}",
        "zh": "路径不存在: {path}",
        "en": "Path not found: {path}",
    },

    # ── v3.2.82: 화이트박스 분석 ──────────────────────────────────────
    "wb_paste_prompt": {
        "ko": "소스코드를 붙여넣으세요. 완료 후 빈 줄에 END 입력:",
        "zh": "请粘贴源代码。完成后在空行输入 END:",
        "en": "Paste source code. Type END on an empty line when done:",
    },
    "wb_empty": {
        "ko": "코드가 없습니다. 다시 시도하세요.",
        "zh": "没有代码，请重试。",
        "en": "No code provided. Please try again.",
    },
    "wb_loading": {
        "ko": "📂 소스코드 분석 중...",
        "zh": "📂 正在分析源代码...",
        "en": "📂 Analyzing source code...",
    },
    "wb_no_hints": {
        "ko": "취약점 패턴 없음 — 블랙박스 테스트를 계속합니다.",
        "zh": "未发现漏洞模式 — 继续黑盒测试。",
        "en": "No vulnerability patterns found — continuing blackbox testing.",
    },
    "wb_result_title": {
        "ko": "🔍 화이트박스 분석 결과",
        "zh": "🔍 白盒分析结果",
        "en": "🔍 Whitebox Analysis Results",
    },
    "wb_agent_order": {
        "ko": "에이전트 우선순위",
        "zh": "代理优先级",
        "en": "Agent priority",
    },
    # ── v3.2.82: 전담 에이전트 ──────────────────────────────────────
    "agent_list_title": {
        "ko": "🤖 취약점 전담 에이전트 목록",
        "zh": "🤖 漏洞专属代理列表",
        "en": "🤖 Vulnerability Specialist Agent List",
    },
    "agent_usage": {
        "ko": "사용법: /agent [list|plan|priority <유형,유형,...>]",
        "zh": "用法: /agent [list|plan|priority <类型,类型,...>]",
        "en": "Usage: /agent [list|plan|priority <type,type,...>]",
    },
    # ── v3.2.82: Proof-by-exploitation 리포트 ──────────────────────
    "report_cleared": {
        "ko": "✅ 리포트 초기화 완료",
        "zh": "✅ 报告已清除",
        "en": "✅ Report cleared",
    },
    "report_saved": {
        "ko": "💾 리포트 저장됨",
        "zh": "💾 报告已保存",
        "en": "💾 Report saved",
    },
    "report_no_proofs": {
        "ko": "확인된 취약점 없음 (PoC 미입증)",
        "zh": "无已确认漏洞（PoC未验证）",
        "en": "No confirmed vulnerabilities (no PoC verified)",
    },

    # ── v3.2.86: Web3/DApp 스마트컨트랙트 감사 출력 ─────────────────
    "web3_audit_report": {
        "ko": "🔐 스마트 컨트랙트 감사 보고서",
        "zh": "🔐 智能合约审计报告",
        "en": "🔐 Smart Contract Audit Report",
    },
    "web3_execution_plan": {
        "ko": "📋 실행 계획",
        "zh": "📋 执行计划",
        "en": "📋 Execution Plan",
    },
    "web3_col_action": {
        "ko": "작업",
        "zh": "操作",
        "en": "Action",
    },
    "web3_col_result": {
        "ko": "결과 요약",
        "zh": "结果摘要",
        "en": "Result",
    },
    "web3_col_severity": {
        "ko": "위험도",
        "zh": "严重性",
        "en": "Severity",
    },
    "web3_col_type": {
        "ko": "취약점 유형",
        "zh": "漏洞类型",
        "en": "Vulnerability Type",
    },
    "web3_col_desc": {
        "ko": "설명",
        "zh": "描述",
        "en": "Description",
    },
    "web3_col_snippet": {
        "ko": "코드 예시",
        "zh": "代码片段",
        "en": "Code Snippet",
    },
    "web3_overall_risk": {
        "ko": "🎯 전체 위험도",
        "zh": "🎯 整体风险等级",
        "en": "🎯 Overall Risk",
    },
    "web3_vuln_table_title": {
        "ko": "발견된 취약점 목록",
        "zh": "发现的漏洞列表",
        "en": "Discovered Vulnerabilities",
    },
    "web3_recommendations": {
        "ko": "📝 수정 권고사항",
        "zh": "📝 修复建议",
        "en": "📝 Recommendations",
    },
    "web3_step_complete": {
        "ko": "✅ 단계 완료",
        "zh": "✅ 步骤完成",
        "en": "✅ Step Complete",
    },
    "web3_audit_auto_continue": {
        "ko": "🔄 감사 결과를 보고서로 정리 중...",
        "zh": "🔄 正在整理审计结果为报告...",
        "en": "🔄 Compiling audit results into report...",
    },
    "web3_audit_complete": {
        "ko": "✅ 스마트 컨트랙트 감사 완료",
        "zh": "✅ 智能合约审计完成",
        "en": "✅ Smart Contract Audit Complete",
    },
    "web3_no_vuln": {
        "ko": "취약점 없음 (Clean)",
        "zh": "无漏洞 (Clean)",
        "en": "No Vulnerabilities (Clean)",
    },
    "web3_skill_injected": {
        "ko": "🔗 Web3/DApp 스킬 자동 로드됨",
        "zh": "🔗 Web3/DApp技能已自动加载",
        "en": "🔗 Web3/DApp skills auto-loaded",
    },
    "web3_skill_injected_zh": {
        "ko": "🔗 Web3/DApp 스킬 자동 로드됨",
        "zh": "🔗 Web3/DApp技能已自动加载",
        "en": "🔗 Web3/DApp skills auto-loaded",
    },
    "web3_skill_injected_en": {
        "ko": "🔗 Web3/DApp 스킬 자동 로드됨",
        "zh": "🔗 Web3/DApp技能已自动加载",
        "en": "🔗 Web3/DApp skills auto-loaded",
    },
    "web3_rendering_report": {
        "ko": "📊 감사 결과를 시각화합니다...",
        "zh": "📊 正在可视化审计结果...",
        "en": "📊 Rendering audit results...",
    },

    # ── v3.2.87: MVVS — Multi-Vector Verification System i18n 키 ──────────
    "mvvs_triggered": {
        "ko": "🔍 MVVS — 2차 검증 자동 실행 중...",
        "zh": "🔍 MVVS — 自动执行二次验证...",
        "en": "🔍 MVVS — Auto-triggering secondary verification...",
    },
    "mvvs_confirmed": {
        "ko": "✅ [CONFIRMED] — 실행결과 기반 취약점 확인됨",
        "zh": "✅ [CONFIRMED] — 基于执行结果，漏洞确认",
        "en": "✅ [CONFIRMED] — Confirmed from actual execution output",
    },
    "mvvs_false_positive": {
        "ko": "❌ [FALSE POSITIVE] — 실행결과 기반 오탐 확인됨",
        "zh": "❌ [FALSE POSITIVE] — 基于执行结果，误报确认",
        "en": "❌ [FALSE POSITIVE] — Confirmed false positive from execution output",
    },
    # v4.5.0: 실행 후 followup_response에서 감지된 CONFIRMED/FALSE POSITIVE
    "mvvs_confirmed_exec": {
        "ko": "✅ [CONFIRMED] — 실행결과 기반 취약점 확인됨",
        "zh": "✅ [CONFIRMED] — 基于执行结果，漏洞确认",
        "en": "✅ [CONFIRMED] — Confirmed from actual execution output",
    },
    "mvvs_false_positive_exec": {
        "ko": "❌ [FALSE POSITIVE] — 실행결과 기반 오탐 확인됨",
        "zh": "❌ [FALSE POSITIVE] — 基于执行结果，误报确认",
        "en": "❌ [FALSE POSITIVE] — Confirmed false positive from execution output",
    },
    # v4.5.0: 실행 전 LLM 예측에 의한 사전 판정 억제 로그
    "mvvs_tag_suppressed_pre_exec": {
        "ko": "⏳ 실행 전 판정 억제 — 코드 실행 후 실제 결과로 판단",
        "zh": "⏳ 执行前判定抑制 — 等待代码执行结果再判断",
        "en": "⏳ Pre-exec tag suppressed — judgment after actual code execution",
    },
    # v4.6.0: Rate limit 오탐 억제 메시지
    "rate_limit_fp_suppressed": {
        "ko": "⚡ 'rate limit' 텍스트 감지됐지만 실제 차단 없음 (오탐 억제됨)",
        "zh": "⚡ 检测到'rate limit'文本但实际无封锁（误报已抑制）",
        "en": "⚡ 'rate limit' text detected but site is accessible — false positive suppressed",
    },
    "ip_block_fp_cross_verified": {
        "ko": "✅ IP 차단 교차검증 완료 — 실제 차단 확인됨",
        "zh": "✅ IP封锁交叉验证完成 — 实际封锁已确认",
        "en": "✅ IP block cross-verified — confirmed real block",
    },
    # ── v4.7.0: AST 정적 분석 무한루프 선제 차단 메시지 ─────────────────
    "ast_infinite_loop_blocked": {
        "ko": "🚫 [AST 분석] 무한루프 패턴 감지 — 실행 차단됨. LLM에 재작성 요청 중...",
        "zh": "🚫 [AST分析] 检测到无限循环模式 — 已阻止执行，正在要求LLM重写...",
        "en": "🚫 [AST Analysis] Infinite loop pattern detected — execution blocked. Requesting LLM rewrite...",
    },
    "ast_guard_loaded": {
        "ko": "🛡️  AST 무한루프 가드 활성화 (code_guard v4.7.0)",
        "zh": "🛡️  AST无限循环守卫已激活 (code_guard v4.7.0)",
        "en": "🛡️  AST infinite loop guard active (code_guard v4.7.0)",
    },
    "ast_guard_fallback": {
        "ko": "⚠️  AST 가드 로드 실패 — Regex 폴백 사용 중",
        "zh": "⚠️  AST守卫加载失败 — 使用正则表达式回退",
        "en": "⚠️  AST guard load failed — falling back to regex detection",
    },
    "script_timeout_rewrite_hint": {
        "ko": (
            "[SCRIPT_TIMEOUT] 스크립트가 타임아웃으로 종료되었습니다.\n"
            "원인: 무한루프 또는 과도하게 큰 이터레이션.\n"
            "수정 규칙:\n"
            "  1) while True 루프에는 반드시 break 조건 추가\n"
            "  2) for 루프는 range(N)에서 N ≤ 1000 으로 제한\n"
            "  3) 페이지네이션: cursor 기반 + seen=set() 로 중복 방지\n"
            "  4) itertools.cycle/count 사용 금지\n"
            "  5) 재귀 함수는 반드시 if n<=0: return 형태 base case 필요\n"
            "코드를 재작성하세요."
        ),
        "zh": (
            "[SCRIPT_TIMEOUT] 脚本因超时而终止。\n"
            "原因：无限循环或迭代次数过多。\n"
            "修复规则：\n"
            "  1) while True循环必须添加break条件\n"
            "  2) for循环range(N)中N必须≤1000\n"
            "  3) 分页：使用游标+seen=set()防止重复\n"
            "  4) 禁止使用itertools.cycle/count\n"
            "  5) 递归函数必须有if n<=0: return形式的基本情况\n"
            "请重写代码。"
        ),
        "en": (
            "[SCRIPT_TIMEOUT] Script terminated due to timeout.\n"
            "Cause: infinite loop or excessive iteration count.\n"
            "Fix rules:\n"
            "  1) Add break condition to every while True loop\n"
            "  2) Keep range(N) with N ≤ 1000 in for loops\n"
            "  3) Pagination: use cursor + seen=set() to avoid repeats\n"
            "  4) Do not use itertools.cycle/count\n"
            "  5) Recursive functions MUST have base case: if n<=0: return\n"
            "Rewrite the code."
        ),
    },
    "mvvs_suspected": {
        "ko": "⚠️  [SUSPECTED] — 단일 신호 감지, 검증 필요",
        "zh": "⚠️  [SUSPECTED] — 单一信号检测，需要验证",
        "en": "⚠️  [SUSPECTED] — Single signal detected, needs verification",
    },
    "mvvs_likely": {
        "ko": "🟡 [LIKELY] — 부분 검증 완료, 추가 확인 권장",
        "zh": "🟡 [LIKELY] — 部分验证完成，建议进一步确认",
        "en": "🟡 [LIKELY] — Partially verified, further confirmation recommended",
    },
    "mvvs_signal_found": {
        "ko": "⚡ 취약점 신호 감지됨 — 자동 재검증 시작",
        "zh": "⚡ 检测到漏洞信号 — 开始自动重新验证",
        "en": "⚡ Vulnerability signal detected — starting auto re-verification",
    },
    "mvvs_no_signal": {
        "ko": "✓ 취약점 신호 없음 — 계속 진행",
        "zh": "✓ 未检测到漏洞信号 — 继续",
        "en": "✓ No vulnerability signal — continuing",
    },
    "mvvs_max_retry": {
        "ko": "ℹ️  MVVS 최대 재시도 도달 — 다음 단계로 진행",
        "zh": "ℹ️  MVVS 已达最大重试次数 — 进入下一步",
        "en": "ℹ️  MVVS max retry reached — proceeding to next step",
    },
    # ── v3.2.88: /load 세션 복원 ──────────────────────────────────────
    # 고객 피드백: "哥，不可以直接喂会话吗" — 세션 파일 직접 입력 → 이어가기
    "load_success": {
        "ko": "✅ 세션 복원 완료 — 이전 작업을 이어 진행합니다",
        "zh": "✅ 会话恢复完成 — 继续上次任务",
        "en": "✅ Session loaded — resuming previous task",
    },
    "load_not_found": {
        "ko": "❌ 파일을 찾을 수 없습니다",
        "zh": "❌ 找不到文件",
        "en": "❌ File not found",
    },
    "load_parse_fail": {
        "ko": "⚠️  대화 내용을 파싱하지 못했습니다 (bingo 세션 파일 형식 아님?)",
        "zh": "⚠️  无法解析对话内容（不是bingo会话文件？）",
        "en": "⚠️  Could not parse conversation (not a bingo session file?)",
    },
    "load_usage": {
        "ko": "사용법: /load <세션파일경로>\n예) /load ~/.config/bingo/sessions/session_20260629_134027.md\n\n💡 경로를 직접 붙여넣기해도 자동으로 인식됩니다",
        "zh": "用法: /load <会话文件路径>\n例) /load ~/.config/bingo/sessions/session_20260629_134027.md\n\n💡 直接粘贴路径也会自动识别",
        "en": "Usage: /load <session-file-path>\nEx)   /load ~/.config/bingo/sessions/session_20260629_134027.md\n\n💡 You can also paste the path directly without /load",
    },
    "load_auto_detected": {
        "ko": "📂 세션 파일 경로 감지됨 — 자동 로드 중...",
        "zh": "📂 检测到会话文件路径 — 自动加载中...",
        "en": "📂 Session file path detected — auto-loading...",
    },
    "load_resuming": {
        "ko": "이전 작업에서 어디까지 진행됐는지 간략히 요약하고, 다음 단계를 이어서 진행해 주세요.",
        "zh": "请简要总结之前的进度，并继续下一步工作。",
        "en": "Please briefly summarize progress so far and continue with the next step.",
    },

    # ── v3.2.96: FindingsExporter / XSS Playwright 자동 검증 다국어 ────────────
    "fe_finding_detected": {
        "ko": "⚡ 취약점 발견 자동 감지됨",
        "zh": "⚡ 自动检测到漏洞发现",
        "en": "⚡ Finding Auto-Detected",
    },
    "fe_auto_saved": {
        "ko": "📁 발견 중간 자동 저장",
        "zh": "📁 发现中途自动保存",
        "en": "📁 Findings Auto-Saved (interim)",
    },
    "fe_session_saved": {
        "ko": "📊 세션 발견 JSON 자동 저장됨",
        "zh": "📊 会话发现 JSON 已自动保存",
        "en": "📊 Session Findings JSON Auto-Saved",
    },
    "fe_xss_verify": {
        "ko": "🌐 XSS payload 브라우저 자동 검증 중...",
        "zh": "🌐 正在通过浏览器自动验证 XSS payload...",
        "en": "🌐 Auto-verifying XSS payload in browser...",
    },
    "fe_xss_confirmed": {
        "ko": "✅ XSS 브라우저 실행 확인됨 [CONFIRMED]",
        "zh": "✅ XSS 浏览器执行已确认 [CONFIRMED]",
        "en": "✅ XSS Execution Confirmed in Browser [CONFIRMED]",
    },
    "fe_xss_unconfirmed": {
        "ko": "⚠ XSS 브라우저 자동 확인 실패 (수동 검증 권장)",
        "zh": "⚠ XSS 浏览器自动确认失败 (建议手动验证)",
        "en": "⚠ XSS Browser Auto-Confirm Failed (manual verify recommended)",
    },

    # ── v3.2.96: CLI --silent 헤드리스 모드 다국어 ──────────────────────────────
    "cli_help_silent": {
        "ko": "비대화식(헤드리스) 모드 — 자동 침투 후 findings JSON 출력 (CI/CD 용)",
        "zh": "非交互(无界面)模式 — 自动渗透后输出 findings JSON (CI/CD)",
        "en": "Non-interactive (headless) mode — auto-pentest then output findings JSON (CI/CD)",
    },
    "cli_help_silent_out": {
        "ko": "결과 저장 디렉토리 지정",
        "zh": "指定结果保存目录",
        "en": "Specify output directory for results",
    },
    "cli_silent_start": {
        "ko": "🔇 [SILENT] 비대화식 자동 침투 시작: {target}",
        "zh": "🔇 [SILENT] 启动非交互式自动渗透: {target}",
        "en": "🔇 [SILENT] Starting non-interactive auto-pentest: {target}",
    },
    "cli_silent_done": {
        "ko": "🔇 [SILENT] 완료 — 발견: {total}건 (CRITICAL:{crit} HIGH:{high})",
        "zh": "🔇 [SILENT] 完成 — 发现: {total}项 (CRITICAL:{crit} HIGH:{high})",
        "en": "🔇 [SILENT] Done — Findings: {total} (CRITICAL:{crit} HIGH:{high})",
    },

    # ── v3.2.97: WebLab 분석 스킬팩 다국어 ──────────────────────────────
    "skill_pack_loaded": {
        "ko": "🎯 스킬팩 로드됨: {name} (+{count}개)",
        "zh": "🎯 技能包已加载: {name} (+{count}个)",
        "en": "🎯 Skill pack loaded: {name} (+{count} skills)",
    },
    "sqli_closure_detected": {
        "ko": "🔍 SQLi 클로저 패턴 감지: {pattern}",
        "zh": "🔍 检测到 SQLi 闭合模式: {pattern}",
        "en": "🔍 SQLi closure pattern detected: {pattern}",
    },
    "sqli_filter_bypass": {
        "ko": "⚙️ SQLi 키워드 필터 우회 시도 중...",
        "zh": "⚙️ 正在尝试 SQLi 关键字过滤绕过...",
        "en": "⚙️ Attempting SQLi keyword filter bypass...",
    },
    "jwt_alg_confusion": {
        "ko": "🔑 JWT 알고리즘 혼동 공격 — RS256→HS256 전환",
        "zh": "🔑 JWT 算法混淆攻击 — RS256→HS256 切换",
        "en": "🔑 JWT algorithm confusion attack — RS256→HS256 switch",
    },
    "jwt_alg_none": {
        "ko": "🔑 JWT alg:none 공격 — 서명 검증 우회",
        "zh": "🔑 JWT alg:none 攻击 — 绕过签名验证",
        "en": "🔑 JWT alg:none attack — signature verification bypass",
    },
    "upload_bypass_start": {
        "ko": "📤 파일 업로드 우회 시도 ({method})",
        "zh": "📤 正在尝试文件上传绕过 ({method})",
        "en": "📤 Attempting file upload bypass ({method})",
    },
    "upload_bypass_success": {
        "ko": "✅ 파일 업로드 우회 성공 — 웹쉘 업로드 완료",
        "zh": "✅ 文件上传绕过成功 — Webshell 上传完成",
        "en": "✅ File upload bypass succeeded — webshell uploaded",
    },
    "idor_horizontal": {
        "ko": "🔓 수평 권한상승(IDOR) — 타 사용자 리소스 접근",
        "zh": "🔓 水平越权(IDOR) — 访问其他用户资源",
        "en": "🔓 Horizontal privilege escalation (IDOR) — accessing other user resources",
    },
    "idor_vertical": {
        "ko": "🔓 수직 권한상승(IDOR) — 관리자 기능 접근",
        "zh": "🔓 垂直越权(IDOR) — 访问管理员功能",
        "en": "🔓 Vertical privilege escalation (IDOR) — accessing admin functions",
    },
    "biz_logic_bypass": {
        "ko": "⚠️ 비즈니스 로직 우회 감지 — {type}",
        "zh": "⚠️ 检测到业务逻辑绕过 — {type}",
        "en": "⚠️ Business logic bypass detected — {type}",
    },
    "race_condition_start": {
        "ko": "⚡ 레이스 컨디션 공격 시작 — {threads}개 스레드 동시 전송",
        "zh": "⚡ 竞态条件攻击开始 — 同时发送 {threads} 个线程",
        "en": "⚡ Race condition attack started — {threads} threads concurrent",
    },
    "ssrf_metadata_probe": {
        "ko": "🌐 SSRF — 클라우드 메타데이터 엔드포인트 탐색 중",
        "zh": "🌐 SSRF — 正在探测云元数据端点",
        "en": "🌐 SSRF — probing cloud metadata endpoints",
    },
    "rce_cmd_inject": {
        "ko": "💀 RCE 명령 인젝션 확인 — 실행 결과: {output}",
        "zh": "💀 RCE 命令注入已确认 — 执行结果: {output}",
        "en": "💀 RCE command injection confirmed — output: {output}",
    },
    "lfi_to_rce_chain": {
        "ko": "🔗 LFI→RCE 체인 시도 — {method}",
        "zh": "🔗 LFI→RCE 链尝试 — {method}",
        "en": "🔗 LFI→RCE chain attempt — {method}",
    },
    "shop_vuln_map": {
        "ko": "🛒 종합 쇼핑몰 취약점 맵 로드 — {count}개 엔드포인트",
        "zh": "🛒 综合商城漏洞地图已加载 — {count}个端点",
        "en": "🛒 Comprehensive shop vuln map loaded — {count} endpoints",
    },
    "probability_exploit": {
        "ko": "🎰 확률/포인트 조작 공격 — 무한 획득 시도",
        "zh": "🎰 概率/积分操控攻击 — 尝试无限获取",
        "en": "🎰 Probability/point manipulation attack — attempting infinite gain",
    },
    "request_smuggling_start": {
        "ko": "🚢 HTTP 요청 밀수 공격 시작 — {type}",
        "zh": "🚢 HTTP 请求走私攻击开始 — {type}",
        "en": "🚢 HTTP request smuggling attack started — {type}",
    },
    "secret_key_found": {
        "ko": "🔑 민감 키/자격증명 노출 감지 — {location}",
        "zh": "🔑 检测到敏感密钥/凭据泄露 — {location}",
        "en": "🔑 Sensitive key/credential exposure detected — {location}",
    },
    # ── v3.2.98: agent_state 방어 코드 관련 ──────────────────────────────
    "agent_state_corrupted": {
        "ko": "⚠️ agent_state 손상 감지 — 기본값으로 초기화됨",
        "zh": "⚠️ 检测到 agent_state 损坏 — 已重置为默认值",
        "en": "⚠️ agent_state corruption detected — reset to defaults",
    },
    "agent_state_key_missing": {
        "ko": "⚠️ agent_state 키 누락 ({key}) — 기본값 사용",
        "zh": "⚠️ agent_state 键缺失 ({key}) — 使用默认值",
        "en": "⚠️ agent_state key missing ({key}) — using default",
    },
    "agent_state_new_target": {
        "ko": "🆕 새 타겟 감지 — agent_state 초기화: {target}",
        "zh": "🆕 检测到新目标 — 重置 agent_state: {target}",
        "en": "🆕 New target detected — agent_state reset: {target}",
    },
    "agent_state_knowledge_injected": {
        "ko": "🧠 누적 지식 {count}개 항목 AI에 주입됨",
        "zh": "🧠 已将 {count} 条累积知识注入AI上下文",
        "en": "🧠 Injected {count} accumulated knowledge items into AI context",
    },
    "agent_state_sqli_confirmed": {
        "ko": "✅ SQLi 확인됨 — agent_state에 저장 (세션 재시작 시 유지)",
        "zh": "✅ SQLi 已确认 — 已保存到 agent_state（会话重启后保留）",
        "en": "✅ SQLi confirmed — saved to agent_state (persists across restart)",
    },
    "agent_state_creds_saved": {
        "ko": "🔑 자격증명 agent_state에 저장됨 — 자동 복구 활성화",
        "zh": "🔑 凭据已保存到 agent_state — 自动恢复已启用",
        "en": "🔑 Credentials saved to agent_state — auto-recovery enabled",
    },
    "whitebox_target_combined": {
        "ko": "🔗 화이트박스+블랙박스 하이브리드 모드 — {target}",
        "zh": "🔗 白盒+黑盒混合模式 — {target}",
        "en": "🔗 Whitebox+Blackbox hybrid mode — {target}",
    },
    "whitebox_full_urls_built": {
        "ko": "🌐 소스 엔드포인트 → 전체 URL {count}개 생성됨",
        "zh": "🌐 源端点 → 已生成 {count} 个完整URL",
        "en": "🌐 Source endpoints → {count} full URLs constructed",
    },

    # ── v3.3.0: CTF 항목 보안 점검 ─────────────────────────────────────────
    "ctf_usage": {
        "ko": (
            "사용법: /ctf <url>\n"
            "  예) /ctf http://localhost:8888\n"
            "      /ctf http://localhost:8888 --resume=no\n"
            "      /ctf http://localhost:8888 --headless=no\n"
            "      /ctf http://localhost:8888 --status\n"
            '      /ctf http://lab.com --cookie "PHPSESSID=abc"'
        ),
        "zh": (
            "用法: /ctf <url>\n"
            "  例) /ctf http://localhost:8888\n"
            "      /ctf http://localhost:8888 --resume=no\n"
            "      /ctf http://localhost:8888 --headless=no\n"
            "      /ctf http://localhost:8888 --status"
        ),
        "en": (
            "Usage: /ctf <url>\n"
            "  e.g. /ctf http://localhost:8888\n"
            "       /ctf http://localhost:8888 --resume=no\n"
            "       /ctf http://localhost:8888 --headless=no\n"
            "       /ctf http://localhost:8888 --status"
        ),
    },
    "ctf_start": {
        "ko": "🏁 웹 실습 환경 점검 시작: {url}",
        "zh": "🏁 Web实验环境扫描开始: {url}",
        "en": "🏁 web lab scan started: {url}",
    },
    "ctf_enumerating": {
        "ko": "📋 항목 목록 수집 중...",
        "zh": "📋 正在枚举检测项目列表...",
        "en": "📋 Enumerating target list...",
    },
    "ctf_no_challenges": {
        "ko": "⚠ 항목을 찾지 못했습니다. URL을 확인하세요.",
        "zh": "⚠ 未找到任何检测项目，请确认目标URL。",
        "en": "⚠ No targets found. Check the target URL.",
    },
    "ctf_challenge_start": {
        "ko": "🔓 [{cat}] {title}",
        "zh": "🔓 [{cat}] {title}",
        "en": "🔓 [{cat}] {title}",
    },
    "ctf_challenge_skip": {
        "ko": "⏭ 이미 완료됨 — 스킵",
        "zh": "⏭ 已完成 — 跳过",
        "en": "⏭ Already completed — skipping",
    },
    "ctf_exploit_success": {
        "ko": "✅ 익스플로잇 성공",
        "zh": "✅ 漏洞利用成功",
        "en": "✅ Exploit succeeded",
    },
    "ctf_exploit_fail": {
        "ko": "❌ 익스플로잇 실패",
        "zh": "❌ 漏洞利用失败",
        "en": "❌ Exploit failed",
    },
    "ctf_submit_ok": {
        "ko": "🎯 점수 제출 성공!",
        "zh": "🎯 成功提交得分！",
        "en": "🎯 Score submitted successfully!",
    },
    "ctf_submit_fail": {
        "ko": "⚠ 점수 제출 실패 (익스플로잇은 성공)",
        "zh": "⚠ 得分提交失败（但漏洞利用已成功）",
        "en": "⚠ Score submission failed (exploit was successful)",
    },
    "ctf_result": {
        "ko": "🏆 완료: {solved}/{total} ({pct:.1f}%) | 실패: {failed}개 | {elapsed:.1f}초",
        "zh": "🏆 完成: {solved}/{total} ({pct:.1f}%) | 失败: {failed}个 | {elapsed:.1f}秒",
        "en": "🏆 Solved: {solved}/{total} ({pct:.1f}%) | Failed: {failed} | {elapsed:.1f}s",
    },
    "ctf_state_saved": {
        "ko": "💾 진행상황 자동 저장: ~/Desktop/dump/ctf_state/",
        "zh": "💾 进度已自动保存: ~/Desktop/dump/ctf_state/",
        "en": "💾 Progress auto-saved to ~/Desktop/dump/ctf_state/",
    },
    "ctf_status_header": {
        "ko": "📊 웹 실습 진행상황",
        "zh": "📊 Web实验进度",
        "en": "📊 Web Lab Progress",
    },
    "ctf_playwright_active": {
        "ko": "🎭 Playwright 브라우저 자동화 활성화됨",
        "zh": "🎭 Playwright 浏览器自动化已启用",
        "en": "🎭 Playwright browser automation active",
    },
    "ctf_playwright_fallback": {
        "ko": "⚠ Playwright 없음 — requests 모드로 동작 (일부 JS 항목 제한)",
        "zh": "⚠ 无 Playwright — 使用 requests 模式（部分JS项目受限）",
        "en": "⚠ Playwright unavailable — running in requests mode (JS targets limited)",
    },

    # ── v3.3.5: tgtylab 6-레이어 우회 시스템 상태 키 ──────────────────
    "hook_identity_lock_active": {
        "ko": "🔒 신원 고정 레이어 활성화 (v3.3.5)",
        "zh": "🔒 身份锁定层已激活 (v3.3.5)",
        "en": "🔒 Identity lock layer active (v3.3.5)",
    },
    "hook_thinking_redirect_active": {
        "ko": "🔄 사고 리다이렉트 레이어 활성화 — 거부 언어 차단",
        "zh": "🔄 思维重定向层已激活 — 阻断拒绝语言",
        "en": "🔄 Thinking redirect layer active — refusal language blocked",
    },
    "hook_example_flood_loaded": {
        "ko": "📚 예시 범람 라이브러리 로드 완료 (50+ 패턴)",
        "zh": "📚 示例洪水库加载完成 (50+ 模式)",
        "en": "📚 Example flood library loaded (50+ patterns)",
    },
    "hook_operational_context": {
        "ko": "🏗 운영 컨텍스트: 격리 보안 연구 실험실 (세션 전체 적용)",
        "zh": "🏗 运营上下文: 隔离安全研究实验室（整个会话生效）",
        "en": "🏗 Operational context: isolated security research lab (session-wide)",
    },
    "hook_forbidden_language_guard": {
        "ko": "🚫 금지어 가드 활성화 — 모델 거부 언어 실시간 차단",
        "zh": "🚫 禁用词守卫已激活 — 实时屏蔽模型拒绝语言",
        "en": "🚫 Forbidden language guard active — real-time refusal blocking",
    },
    "hook_reverselab_rules_loaded": {
        "ko": "📋 행동 규범 로드 완료 (reverselab AGENTS.md)",
        "zh": "📋 行为规范加载完成 (reverselab AGENTS.md)",
        "en": "📋 Work style rules loaded (reverselab AGENTS.md)",
    },
    "hook_pre_tool_injected": {
        "ko": "💉 Pre-tool-call 컨텍스트 훅 주입 완료",
        "zh": "💉 Pre-tool-call 上下文钩子注入完成",
        "en": "💉 Pre-tool-call context hook injected",
    },
    "hook_refusal_detected": {
        "ko": "⚠ 거부 언어 감지 — 컨텍스트 재주입 트리거",
        "zh": "⚠ 检测到拒绝语言 — 触发上下文重新注入",
        "en": "⚠ Refusal language detected — context reinject triggered",
    },
    "hook_refusal_recovery": {
        "ko": "🔁 거부 복구 메시지 전송 중...",
        "zh": "🔁 正在发送拒绝恢复消息...",
        "en": "🔁 Sending refusal recovery message...",
    },
    "hook_layer_summary": {
        "ko": "✅ tgtylab 6-레이어 + reverselab 규범 로드 완료 (v3.3.5)",
        "zh": "✅ tgtylab 6层 + reverselab规范 加载完成 (v3.3.5)",
        "en": "✅ tgtylab 6-layer + reverselab rules loaded (v3.3.5)",
    },

    # ── v3.4.0: 역할 기반 테스팅 ─────────────────────────────────────
    "role_loaded": {
        "ko": "🎯 역할 로드됨: {role}",
        "zh": "🎯 角色已加载: {role}",
        "en": "🎯 Role loaded: {role}",
    },
    "role_not_found": {
        "ko": "❌ 역할을 찾을 수 없음: {role}",
        "zh": "❌ 未找到角色: {role}",
        "en": "❌ Role not found: {role}",
    },
    "role_list_header": {
        "ko": "📋 사용 가능한 역할 목록",
        "zh": "📋 可用角色列表",
        "en": "📋 Available roles",
    },
    "role_switched": {
        "ko": "✅ 역할 전환 → {role}",
        "zh": "✅ 角色切换 → {role}",
        "en": "✅ Role switched → {role}",
    },
    "role_cleared": {
        "ko": "역할 해제됨",
        "zh": "角色已清除",
        "en": "Role cleared",
    },

    # ── v3.4.0: 취약점 관리 ───────────────────────────────────────────
    "vuln_saved": {
        "ko": "💾 취약점 저장됨 [{id}] {title}",
        "zh": "💾 漏洞已保存 [{id}] {title}",
        "en": "💾 Vulnerability saved [{id}] {title}",
    },
    "vuln_list_header": {
        "ko": "🔴 취약점 목록 ({count}건)",
        "zh": "🔴 漏洞列表 ({count}条)",
        "en": "🔴 Vulnerability list ({count} items)",
    },
    "vuln_updated": {
        "ko": "✅ 취약점 업데이트됨 [{id}]",
        "zh": "✅ 漏洞已更新 [{id}]",
        "en": "✅ Vulnerability updated [{id}]",
    },
    "vuln_removed": {
        "ko": "🗑 취약점 삭제됨 [{id}]",
        "zh": "🗑 漏洞已删除 [{id}]",
        "en": "🗑 Vulnerability removed [{id}]",
    },
    "vuln_cleared": {
        "ko": "🗑 취약점 전체 초기화 ({count}건 삭제)",
        "zh": "🗑 所有漏洞已清空 ({count}条已删除)",
        "en": "🗑 All vulnerabilities cleared ({count} removed)",
    },
    "vuln_stats": {
        "ko": "📊 취약점 통계 | 전체: {total} | Critical: {critical} | High: {high}",
        "zh": "📊 漏洞统计 | 总计: {total} | 严重: {critical} | 高危: {high}",
        "en": "📊 Vuln stats | Total: {total} | Critical: {critical} | High: {high}",
    },

    # ── v3.4.0: 배치 작업 ─────────────────────────────────────────────
    "batch_start": {
        "ko": "⚡ 배치 시작 [{id}] — {count}개 타겟",
        "zh": "⚡ 批次开始 [{id}] — {count}个目标",
        "en": "⚡ Batch started [{id}] — {count} targets",
    },
    "batch_task_done": {
        "ko": "  ✓ [{seq}/{total}] {target} 완료",
        "zh": "  ✓ [{seq}/{total}] {target} 完成",
        "en": "  ✓ [{seq}/{total}] {target} done",
    },
    "batch_task_failed": {
        "ko": "  ✗ [{seq}/{total}] {target} 실패: {error}",
        "zh": "  ✗ [{seq}/{total}] {target} 失败: {error}",
        "en": "  ✗ [{seq}/{total}] {target} failed: {error}",
    },
    "batch_complete": {
        "ko": "✅ 배치 완료 [{id}] — 성공: {done} / 실패: {failed}",
        "zh": "✅ 批次完成 [{id}] — 成功: {done} / 失败: {failed}",
        "en": "✅ Batch complete [{id}] — done: {done} / failed: {failed}",
    },

    # ── v3.4.0: YAML 도구 레시피 ──────────────────────────────────────
    "tool_ext_loaded": {
        "ko": "🔧 외부 도구 로드됨: {name}",
        "zh": "🔧 外部工具已加载: {name}",
        "en": "🔧 External tool loaded: {name}",
    },
    "tool_ext_not_found": {
        "ko": "❌ 도구를 찾을 수 없음: {name}",
        "zh": "❌ 未找到工具: {name}",
        "en": "❌ Tool not found: {name}",
    },
    "tool_ext_not_installed": {
        "ko": "⚠ {name} 설치되지 않음 — 먼저 설치하세요",
        "zh": "⚠ {name} 未安装 — 请先安装",
        "en": "⚠ {name} not installed — install it first",
    },
    "tool_ext_list": {
        "ko": "🔧 사용 가능한 외부 도구 ({count}개)",
        "zh": "🔧 可用外部工具 ({count}个)",
        "en": "🔧 Available external tools ({count})",
    },

    # ── v3.4.0: 프로젝트 블랙보드 ────────────────────────────────────
    "board_fact_saved": {
        "ko": "📌 블랙보드 저장됨: {key} = {value}",
        "zh": "📌 黑板已记录: {key} = {value}",
        "en": "📌 Blackboard saved: {key} = {value}",
    },
    "board_fact_removed": {
        "ko": "🗑 블랙보드 항목 삭제: {key}",
        "zh": "🗑 黑板条目已删除: {key}",
        "en": "🗑 Blackboard entry removed: {key}",
    },
    "board_cleared": {
        "ko": "🗑 블랙보드 초기화 ({count}개 삭제)",
        "zh": "🗑 黑板已清空 ({count}条已删除)",
        "en": "🗑 Blackboard cleared ({count} removed)",
    },
    "board_list_header": {
        "ko": "📌 블랙보드 — {target}",
        "zh": "📌 黑板 — {target}",
        "en": "📌 Blackboard — {target}",
    },

    # ── v3.4.0: 지식 베이스 ───────────────────────────────────────────
    "kb_loaded": {
        "ko": "📚 지식 베이스 로드됨: {count}개 파일",
        "zh": "📚 知识库已加载: {count}个文件",
        "en": "📚 Knowledge base loaded: {count} files",
    },
    "kb_injected": {
        "ko": "📚 KB 컨텍스트 주입됨 (쿼리: {query})",
        "zh": "📚 KB上下文已注入 (查询: {query})",
        "en": "📚 KB context injected (query: {query})",
    },
    "kb_no_match": {
        "ko": "📚 관련 KB 없음: {query}",
        "zh": "📚 无相关知识库: {query}",
        "en": "📚 No matching KB for: {query}",
    },
    "kb_no_docs": {
        "ko": "📚 KB 문서 없음. bingo/knowledge/base/ 에 .md 파일을 추가하세요",
        "zh": "📚 暂无知识库文档。请将.md文件添加到 bingo/knowledge/base/",
        "en": "📚 No KB documents found. Add .md files to bingo/knowledge/base/",
    },
    "kb_no_results": {
        "ko": "📚 '{query}' 검색 결과 없음",
        "zh": "📚 未找到 '{query}' 的相关结果",
        "en": "📚 No results for '{query}'",
    },
    "kb_doc_not_found": {
        "ko": "📚 문서 '{name}' 없음",
        "zh": "📚 文档 '{name}' 未找到",
        "en": "📚 Document '{name}' not found",
    },
    "kb_reloaded": {
        "ko": "📚 지식 베이스 재로드 완료",
        "zh": "📚 知识库已重新加载",
        "en": "📚 Knowledge base reloaded",
    },
    "kb_usage": {
        "ko": "사용법: /kb [list|search <키워드>|show <문서명>|reload]",
        "zh": "用法: /kb [list|search <关键词>|show <文档名>|reload]",
        "en": "Usage: /kb [list|search <kw>|show <name>|reload]",
    },

    # ── v3.6.0: KB 자동 주입 알림 ────────────────────────────────────
    "kb_auto_loaded": {
        "ko": "📚 KB 자동 로드됨 ({n}개 문서 매칭: {names})",
        "zh": "📚 知识库自动加载 ({n} 个文档匹配: {names})",
        "en": "📚 KB auto-loaded ({n} docs matched: {names})",
    },
    "kb_auto_hint": {
        "ko": "💡 /kb search <키워드> 로 더 많은 관련 문서를 검색할 수 있습니다",
        "zh": "💡 使用 /kb search <关键词> 可查找更多相关文档",
        "en": "💡 Use /kb search <keyword> to find more related documents",
    },

    # ── v3.4.0: 공격 체인 ────────────────────────────────────────────
    "chain_step_added": {
        "ko": "⛓ 체인 단계 추가 [{seq}] {type}: {title}",
        "zh": "⛓ 攻击链步骤已添加 [{seq}] {type}: {title}",
        "en": "⛓ Chain step added [{seq}] {type}: {title}",
    },
    "chain_header": {
        "ko": "⛓ 공격 체인 — {session}",
        "zh": "⛓ 攻击链 — {session}",
        "en": "⛓ Attack chain — {session}",
    },
    "chain_cleared": {
        "ko": "🗑 공격 체인 초기화 ({count}단계 삭제)",
        "zh": "🗑 攻击链已清空 ({count}步已删除)",
        "en": "🗑 Attack chain cleared ({count} steps removed)",
    },

    # ── v3.4.0: HITL ──────────────────────────────────────────────────
    "hitl_prompt": {
        "ko": "⚠️  [HITL] 위험 작업 확인 필요: {action}",
        "zh": "⚠️  [HITL] 需要确认危险操作: {action}",
        "en": "⚠️  [HITL] Confirm dangerous action: {action}",
    },
    "hitl_allowed": {
        "ko": "✅ [HITL] 허용됨: {action}",
        "zh": "✅ [HITL] 已允许: {action}",
        "en": "✅ [HITL] Allowed: {action}",
    },
    "hitl_cancelled": {
        "ko": "🚫 [HITL] 취소됨: {action}",
        "zh": "🚫 [HITL] 已取消: {action}",
        "en": "🚫 [HITL] Cancelled: {action}",
    },
    "hitl_always": {
        "ko": "✅ [HITL] '항상 허용' 등록: {action}",
        "zh": "✅ [HITL] '始终允许'已注册: {action}",
        "en": "✅ [HITL] 'Always allow' registered: {action}",
    },

    # ── v3.5.0: LLM 오케스트레이터 ───────────────────────────────────
    "orch_started": {
        "ko": "🤖 오케스트레이터 시작: {target} | 목표={goal} | 스텝={steps}",
        "zh": "🤖 编排器已启动: {target} | 目标={goal} | 步数={steps}",
        "en": "🤖 Orchestrator started: {target} | goal={goal} | steps={steps}",
    },
    "orch_stopped": {
        "ko": "⏹ 오케스트레이터 중지됨.",
        "zh": "⏹ 编排器已停止。",
        "en": "⏹ Orchestrator stopped.",
    },
    "orch_not_running": {
        "ko": "오케스트레이터가 실행 중이 아닙니다.",
        "zh": "编排器未在运行。",
        "en": "Orchestrator is not running.",
    },
    "orch_not_started": {
        "ko": "오케스트레이터가 아직 시작되지 않았습니다.",
        "zh": "编排器尚未启动。",
        "en": "Orchestrator has not been started.",
    },
    "orch_no_log": {
        "ko": "오케스트레이터 로그가 없습니다.",
        "zh": "无编排器日志。",
        "en": "No orchestrator log.",
    },
    "orch_goal_achieved": {
        "ko": "🎯 오케스트레이터 목표 달성! ({steps} 스텝)",
        "zh": "🎯 编排器目标达成！({steps} 步)",
        "en": "🎯 Orchestrator goal achieved! ({steps} steps)",
    },
    "orch_step_label": {
        "ko": "━━━ 오케스트레이터 스텝 {step}/{max_steps} ━━━",
        "zh": "━━━ 编排器步骤 {step}/{max_steps} ━━━",
        "en": "━━━ Orchestrator step {step}/{max_steps} ━━━",
    },
    "orch_decision_thinking": {
        "ko": "🧠 LLM 의사결정 중...",
        "zh": "🧠 LLM决策中...",
        "en": "🧠 LLM deciding next action...",
    },
    "orch_executing": {
        "ko": "▶ 실행: {command}",
        "zh": "▶ 执行: {command}",
        "en": "▶ Executing: {command}",
    },
    "orch_completed": {
        "ko": "⏹ 오케스트레이터 완료 (스텝: {step}/{max_steps})",
        "zh": "⏹ 编排器完成 (步骤: {step}/{max_steps})",
        "en": "⏹ Orchestrator completed (steps: {step}/{max_steps})",
    },
    "orch_hitl_denied": {
        "ko": "🚫 [HITL] 거부됨: {action}",
        "zh": "🚫 [HITL] 已拒绝: {action}",
        "en": "🚫 [HITL] Denied: {action}",
    },
    "orch_board_updated": {
        "ko": "📌 블랙보드 업데이트: {key} = {value}",
        "zh": "📌 黑板已更新: {key} = {value}",
        "en": "📌 Blackboard updated: {key} = {value}",
    },

    # ── v3.5.2: Phantom Guard ─────────────────────────────────────────────
    "phantom_mode_blocked": {
        "ko": "⛔ 팬텀 모드 차단 — 도구 재활성화 강제",
        "zh": "⛔ 幻影模式阻断 — 强制重新激活工具",
        "en": "⛔ Phantom Mode Blocked — Forcing Tool Reactivation",
    },
    "phantom_self_loop_blocked": {
        "ko": "⛔ 자기수정 루프 차단 — 직접 HTTP 실행 강제",
        "zh": "⛔ 自我修正循环阻断 — 强制直接HTTP执行",
        "en": "⛔ Self-Correction Loop Blocked — Forcing Direct HTTP Execution",
    },
    "phantom_stale_cache_blocked": {
        "ko": "⛔ 구캐시 차단 — 신선 스캔 강제",
        "zh": "⛔ 缓存阻断 — 强制新鲜扫描",
        "en": "⛔ Stale Cache Blocked — Forcing Fresh Scan",
    },
    "phantom_target_mismatch": {
        "ko": "⚠️ 타겟 오인 경고 — 세션 타겟 재확인",
        "zh": "⚠️ 目标混淆警告 — 重新确认会话目标",
        "en": "⚠️ Target Mismatch Warning — Reconfirm Session Target",
    },
    "phantom_retrying": {
        "ko": "⛔ 팬텀 모드 차단 → 실제 HTTP 코드 재요청 중...",
        "zh": "⛔ 幻影模式阻断 → 重新请求真实HTTP代码...",
        "en": "⛔ Phantom Mode Blocked → Requesting Real HTTP Code...",
    },
    "phantom_code_exec_first": {
        "ko": "✅ 코드 블록 감지 → 즉시 실행 (사전 차단 없음)",
        "zh": "✅ 检测到代码块 → 立即执行 (无预执行拦截)",
        "en": "✅ Code Block Detected → Execute First (No Pre-block)",
    },
    "phantom_post_exec_check": {
        "ko": "✅ 실행 완료 → 사후 결과 검증",
        "zh": "✅ 执行完成 → 事后结果验证",
        "en": "✅ Execution Done → Post-Execution Verification",
    },
    "phantom_guard_note": {
        "ko": (
            "v3.5.3 팬텀가드 v2: 팬텀모드·구캐시·타겟오인·자기수정루프·HTTP0건주장·하드재시작 차단.\n"
            "  - 팬텀 모드 (도구 비활성화 2회 연속) → 즉시 차단 + 재시도\n"
            "  - 구캐시 (ScanResult-*.json 2회 이상 재사용) → 차단 + 신선스캔\n"
            "  - 타겟 오인 (다른 도메인 감지) → 경고 주입\n"
            "  - 자기수정 루프 (3회 연속) → 강제 직접 HTTP 실행\n"
            "  - HTTP 0건 주장 (실행 증거 없이 취약점 클레임) → 즉시 차단\n"
            "  - 하드 재시작 (3회 연속 차단) → 히스토리 초기화 + 세션 재시작\n"
            "  /reset-phantom 으로 수동 초기화 가능"
        ),
        "zh": (
            "v3.5.3 幻影防护v2: 拦截幻影模式·旧缓存·目标混淆·自我修正循环·HTTP0次声明·强制重启.\n"
            "  - 幻影模式 (工具连续禁用2次) → 立即拦截+重试\n"
            "  - 旧缓存 (ScanResult-*.json复用≥2次) → 拦截+新鲜扫描\n"
            "  - 目标混淆 (检测到其他域名) → 注入警告\n"
            "  - 自我修正循环 (连续3次) → 强制直接HTTP执行\n"
            "  - HTTP 0次声明 (无执行证据的漏洞声明) → 立即拦截\n"
            "  - 强制重启 (连续3次拦截) → 清空历史+重启会话\n"
            "  使用 /reset-phantom 手动重置"
        ),
        "en": (
            "v3.5.3 PhantomGuard v2: Blocks phantom mode, stale cache, target mismatch, "
            "self-correction loops, zero-HTTP claims, hard session restart.\n"
            "  - Phantom mode (tools disabled 2x consecutive) → immediate block + retry\n"
            "  - Stale cache (ScanResult-*.json reused 2+x) → block + fresh scan\n"
            "  - Target mismatch (other domain detected) → warning injection\n"
            "  - Self-correction loop (3x consecutive) → force direct HTTP execution\n"
            "  - Zero-HTTP claim (vuln claim without execution evidence) → immediate block\n"
            "  - Hard restart (3x consecutive blocks) → clear history + restart session\n"
            "  Use /reset-phantom to manually reset all counters"
        ),
    },
    # ── v3.5.3 PhantomGuard v2 신규 다국어 키 ──────────────────
    "phantom_zero_http_blocked": {
        "ko": "⛔ HTTP 0건 주장 차단 — 실증 없는 취약점 클레임",
        "zh": "⛔ HTTP 0次请求声明拦截 — 无证据漏洞声明",
        "en": "⛔ Zero-HTTP Claim Blocked — Vulnerability Claim Without Evidence",
    },
    "phantom_hard_restart": {
        "ko": "🔄 하드 세션 재시작 — 팬텀 모드 3회 연속 차단",
        "zh": "🔄 强制会话重启 — 幻影模式连续3次拦截",
        "en": "🔄 Hard Session Restart — Phantom Mode Blocked 3x Consecutive",
    },
    "phantom_liveness_ok": {
        "ko": "도구 Liveness: ✅ 정상 (실제 네트워크 연결 확인)",
        "zh": "工具存活: ✅ 正常 (真实网络连接确认)",
        "en": "Tool Liveness: ✅ OK (Real network connection confirmed)",
    },
    "phantom_liveness_fail": {
        "ko": "도구 Liveness: ⚠️ 실패 — 네트워크 연결 확인 필요",
        "zh": "工具存活: ⚠️ 失败 — 请检查网络连接",
        "en": "Tool Liveness: ⚠️ FAIL — Check network connection",
    },
    "phantom_reset_title": {
        "ko": "✅ PhantomGuard 카운터 초기화 완료",
        "zh": "✅ 幻影防护计数器已全部重置",
        "en": "✅ PhantomGuard Counters Reset Successfully",
    },
    "phantom_reset_target": {
        "ko": "세션 타겟",
        "zh": "会话目标",
        "en": "Session Target",
    },
    "phantom_reset_note": {
        "ko": "모든 팬텀 가드 카운터가 0으로 초기화되었습니다. (팬텀/구캐시/루프/HTTP0건/하드재시작)",
        "zh": "所有幻影防护计数器已重置为0。(幻影/旧缓存/循环/HTTP0次/强制重启)",
        "en": "All PhantomGuard counters reset to 0. (phantom/stale-cache/loop/zero-HTTP/hard-restart)",
    },
    "phantom_guard_not_active": {
        "ko": "PhantomGuard가 비활성화 상태입니다. (초기화 실패 또는 미지원)",
        "zh": "幻影防护未激活。(初始化失败或不支持)",
        "en": "PhantomGuard is not active. (init failed or unsupported)",
    },
    "phantom_liveness_probe_start": {
        "ko": "🔍 도구 Liveness 프로브 실행 중...",
        "zh": "🔍 正在执行工具存活探测...",
        "en": "🔍 Running tool liveness probe...",
    },
    "phantom_reset_phantom_help": {
        "ko": (
            "/reset-phantom\n"
            "  PhantomGuard 카운터 수동 초기화.\n"
            "  팬텀 가드가 오탐하거나 정상 세션을 방해할 때 사용.\n"
            "  초기화 항목: 팬텀/자기수정루프/구캐시/HTTP0건/하드재시작 카운터\n"
            "  + Liveness 재프로브 실행"
        ),
        "zh": (
            "/reset-phantom\n"
            "  手动重置幻影防护计数器。\n"
            "  当幻影防护误报或干扰正常会话时使用。\n"
            "  重置项目: 幻影/自我修正循环/旧缓存/HTTP0次/强制重启计数器\n"
            "  + 重新执行存活探测"
        ),
        "en": (
            "/reset-phantom\n"
            "  Manually reset PhantomGuard counters.\n"
            "  Use when PhantomGuard causes false positives or disrupts a normal session.\n"
            "  Resets: phantom/self-correction-loop/stale-cache/zero-HTTP/hard-restart counters\n"
            "  + Re-runs liveness probe"
        ),
    },
})

# ── v3.5.6: HITL Gate 다국어 키 ─────────────────────────────────────
_STRINGS.update({
    "hitl_confirm_prompt": {
        "ko": "⚠️  [HITL] 위험 작업 확인: {label}\n  [y/N/a(항상허용)] > ",
        "zh": "⚠️  [HITL] 确认危险操作: {label}\n  [y/N/a(始终允许)] > ",
        "en": "⚠️  [HITL] Confirm dangerous action: {label}\n  [y/N/a(always)] > ",
    },
    "hitl_rejected": {
        "ko": "🚫 [HITL] 거부됨: {action}",
        "zh": "🚫 [HITL] 已拒绝: {action}",
        "en": "🚫 [HITL] Rejected: {action}",
    },
    "hitl_allowed": {
        "ko": "✅ [HITL] 허용됨: {action}",
        "zh": "✅ [HITL] 已允许: {action}",
        "en": "✅ [HITL] Allowed: {action}",
    },
})

# ── v3.5.5: OrchestratorEngine 다국어 키 ─────────────────────────────
_STRINGS.update({
    "orch_ui_started": {
        "ko": "🤖 [ORCHESTRATOR] 시작",
        "zh": "🤖 [编排器] 启动",
        "en": "🤖 [ORCHESTRATOR] Started",
    },
    "orch_ui_step": {
        "ko": "━━━ ORCHESTRATOR STEP {step}/{total} ━━━",
        "zh": "━━━ 编排步骤 {step}/{total} ━━━",
        "en": "━━━ ORCHESTRATOR STEP {step}/{total} ━━━",
    },
    "orch_ui_deciding": {
        "ko": "🧠 LLM 의사결정 중...",
        "zh": "🧠 LLM 决策中...",
        "en": "🧠 LLM deciding...",
    },
    "orch_ui_no_decision": {
        "ko": "⚠ 결정 LLM 응답 없음 — 기본 스캔 실행",
        "zh": "⚠ 决策LLM无响应 — 执行默认扫描",
        "en": "⚠ Decision LLM returned empty — running default scan",
    },
    "orch_ui_hitl_rejected": {
        "ko": "🚫 [HITL] 거부됨: {action}",
        "zh": "🚫 [HITL] 已拒绝: {action}",
        "en": "🚫 [HITL] Rejected: {action}",
    },
    "orch_ui_executing": {
        "ko": "▶ 실행: {cmd}",
        "zh": "▶ 执行: {cmd}",
        "en": "▶ Executing: {cmd}",
    },
    "orch_ui_exec_error": {
        "ko": "❌ 실행 오류: {err}",
        "zh": "❌ 执行错误: {err}",
        "en": "❌ Execution error: {err}",
    },
    "orch_ui_goal_done": {
        "ko": "🎯 [ORCHESTRATOR] 목표 달성! ({step} 스텝)",
        "zh": "🎯 [编排器] 目标达成！（{step} 步）",
        "en": "🎯 [ORCHESTRATOR] Goal achieved! ({step} steps)",
    },
    "orch_ui_completed": {
        "ko": "⏹ [ORCHESTRATOR] 완료 (스텝: {step}/{total})",
        "zh": "⏹ [编排器] 完成（步骤: {step}/{total}）",
        "en": "⏹ [ORCHESTRATOR] Completed (steps: {step}/{total})",
    },
    "orch_ui_default_goal": {
        "ko": "관리자 계정 탈취 및 최대 권한 획득",
        "zh": "夺取管理员账户并获取最高权限",
        "en": "Obtain admin credentials and maximum privilege",
    },
    # ── 타겟 오인 방지 guardrail ────────────────────────────────────────
    "orch_target_prefix": {
        "ko": "🎯 [타겟: {target}]\n",
        "zh": "🎯 [目标: {target}]\n",
        "en": "🎯 [TARGET: {target}]\n",
    },
    "orch_stale_cleaned": {
        "ko": "🧹 이전 세션 임시파일 정리 완료 (타겟 오인 방지)",
        "zh": "🧹 已清理上次会话临时文件（防止目标混淆）",
        "en": "🧹 Stale session temp files cleaned (target-mismatch prevention)",
    },
    "orch_target_written": {
        "ko": "📌 타겟 등록: /tmp/bingo_target.txt → {target}",
        "zh": "📌 目标已写入: /tmp/bingo_target.txt → {target}",
        "en": "📌 Target registered: /tmp/bingo_target.txt → {target}",
    },
    # ── TargetMismatchGuard exec 차단 메시지 ───────────────────────────
    "target_mismatch_exec_blocked": {
        "ko": "🚨 타겟 오인 차단 (실행 결과 도메인 불일치)",
        "zh": "🚨 目标混淆阻断 (执行域名不匹配)",
        "en": "🚨 Target mismatch blocked (exec domain mismatch)",
    },
    # ── v3.5.8: SPA 오탐 탐지 ────────────────────────────────────────
    "phantom_spa_detected": {
        "ko": "⚠️ SPA 오탐 차단",
        "zh": "⚠️ SPA误报拦截",
        "en": "⚠️ SPA False Positive Blocked",
    },
    "spa_detected_detail": {
        "ko": (
            "⚠️ [SPA_DETECTED] Next.js/React SPA가 모든 API 경로에 HTML 반환\n"
            "→ 이 응답들은 실제 API 응답이 아닙니다. 별도 API 서버에서 테스트하세요."
        ),
        "zh": (
            "⚠️ [SPA_DETECTED] Next.js/React SPA对所有API路径返回HTML\n"
            "→ 这些不是真实API响应。请在独立API服务器上测试。"
        ),
        "en": (
            "⚠️ [SPA_DETECTED] Next.js/React SPA returns HTML for all API paths\n"
            "→ These are NOT real API responses. Test against the actual API server."
        ),
    },
    # ── v3.5.19: 0day Hunter 다국어 키 ──────────────────────────────────────
    "zeroday_auto_inject": {
        "ko": "⬆ 0day Hunter가 위 후보를 AI에게 자동 전달 — PoC 코드 자동 생성 시작",
        "zh": "⬆ 0day Hunter 已将上述候选项自动传递给 AI — 开始自动生成 PoC 代码",
        "en": "⬆ 0day Hunter auto-forwarded candidates to AI — PoC code generation starting",
    },
    "zeroday_high_found": {
        "ko": "🔴 [0day] HIGH 신뢰도 {n}개 탐지 — 즉시 PoC 생성",
        "zh": "🔴 [0day] 检测到 {n} 个高置信度候选项 — 立即生成 PoC",
        "en": "🔴 [0day] {n} HIGH-confidence candidates — generating PoC now",
    },
    "zeroday_cve_matched": {
        "ko": "🛑 CVE 매핑: {software} {version} → {cves}",
        "zh": "🛑 CVE 映射: {software} {version} → {cves}",
        "en": "🛑 CVE match: {software} {version} → {cves}",
    },
    "zeroday_no_candidate": {
        "ko": "✅ [0day] 이 실행 결과에서 0day 후보 없음",
        "zh": "✅ [0day] 此次执行结果中未发现 0day 候选项",
        "en": "✅ [0day] No 0day candidates in this execution output",
    },
    "zeroday_exploit_hint": {
        "ko": "💡 Exploit 힌트: {hint}",
        "zh": "💡 利用提示: {hint}",
        "en": "💡 Exploit hint: {hint}",
    },
    "zeroday_nvd_lookup": {
        "ko": "🔍 NVD API로 {software} {version} CVE 조회 중...",
        "zh": "🔍 通过 NVD API 查询 {software} {version} CVE...",
        "en": "🔍 Looking up CVEs for {software} {version} via NVD API...",
    },
    "zeroday_session_reset": {
        "ko": "🔄 0day Hunter 세션 초기화 (새 타겟)",
        "zh": "🔄 0day Hunter 会话已重置 (新目标)",
        "en": "🔄 0day Hunter session reset (new target)",
    },
    # ── v3.5.20: 0day Hunter exploit 모듈 연동 키 ───────────────────────────
    "zeroday_micollab_hint": {
        "ko": "🎯 Mitel MiCollab exploit 모듈 사용 가능: from bingo.core.exploits.mitel_micollab import MitelMiCollabExploit",
        "zh": "🎯 Mitel MiCollab exploit 模块可用: from bingo.core.exploits.mitel_micollab import MitelMiCollabExploit",
        "en": "🎯 Mitel MiCollab exploit module available: from bingo.core.exploits.mitel_micollab import MitelMiCollabExploit",
    },
    "zeroday_wappd_hint": {
        "ko": "📡 MediaTek wappd (CVE-2024-20017) exploit: from bingo.core.exploits.mediatek_wappd import WappdExploit",
        "zh": "📡 MediaTek wappd (CVE-2024-20017) exploit: from bingo.core.exploits.mediatek_wappd import WappdExploit",
        "en": "📡 MediaTek wappd (CVE-2024-20017) exploit: from bingo.core.exploits.mediatek_wappd import WappdExploit",
    },
    "zeroday_webp_hint": {
        "ko": "🖼️  libwebp (CVE-2023-4863) exploit: from bingo.core.exploits.webp_cve2023_4863 import WebPExploit",
        "zh": "🖼️  libwebp (CVE-2023-4863) exploit: from bingo.core.exploits.webp_cve2023_4863 import WebPExploit",
        "en": "🖼️  libwebp (CVE-2023-4863) exploit: from bingo.core.exploits.webp_cve2023_4863 import WebPExploit",
    },
    "zeroday_glibc_hint": {
        "ko": "⚡ glibc LPE (CVE-2023-4911 Looney Tunables): from bingo.core.exploits.glibc_tunables import GlibcTunablesExploit",
        "zh": "⚡ glibc LPE (CVE-2023-4911 Looney Tunables): from bingo.core.exploits.glibc_tunables import GlibcTunablesExploit",
        "en": "⚡ glibc LPE (CVE-2023-4911 Looney Tunables): from bingo.core.exploits.glibc_tunables import GlibcTunablesExploit",
    },
    "zeroday_chain_running": {
        "ko": "🔗 0day 체인 공격 자동 실행 중...",
        "zh": "🔗 自动执行 0day 链式攻击...",
        "en": "🔗 Running 0day exploit chain automatically...",
    },
    "zeroday_lpe_detected": {
        "ko": "🔴 LOCAL PRIVILEGE ESCALATION 탐지! glibc {version} — CVE-2023-4911",
        "zh": "🔴 检测到本地权限提升! glibc {version} — CVE-2023-4911",
        "en": "🔴 LOCAL PRIVILEGE ESCALATION detected! glibc {version} — CVE-2023-4911",
    },
    "zeroday_heap_overflow": {
        "ko": "🟡 힙 버퍼 오버플로우 탐지! {software} {version} — {cve}",
        "zh": "🟡 检测到堆缓冲区溢出! {software} {version} — {cve}",
        "en": "🟡 Heap buffer overflow detected! {software} {version} — {cve}",
    },
    "zeroday_udp_overflow": {
        "ko": "📡 UDP 스택 오버플로우 탐지! MediaTek wappd — CVE-2024-20017",
        "zh": "📡 检测到 UDP 栈溢出! MediaTek wappd — CVE-2024-20017",
        "en": "📡 UDP stack overflow detected! MediaTek wappd — CVE-2024-20017",
    },
    # ── v3.5.21: APT 모듈 — 자동 탐지 힌트 + /apt 커맨드 ───────────────────────
    "apt_lateral_hint": {
        "ko": "🔀 내부망 탐지 — /apt lateral <IP> 로 횡방향 이동 명령 자동 생성",
        "zh": "🔀 检测到内网环境 — 使用 /apt lateral <IP> 自动生成横向移动命令",
        "en": "🔀 Internal network detected — use /apt lateral <IP> for lateral movement commands",
    },
    "apt_supply_hint": {
        "ko": "⛓️ 공급망 파일 탐지 — /apt supply <path> 로 의존성 취약점 스캔",
        "zh": "⛓️ 检测到供应链文件 — 使用 /apt supply <path> 扫描依赖漏洞",
        "en": "⛓️ Supply chain file detected — use /apt supply <path> to scan dependency vulnerabilities",
    },
    "apt_phish_hint": {
        "ko": "🎣 피싱 컨텍스트 감지 — /apt phish <email> 로 스피어피싱 이메일 생성",
        "zh": "🎣 检测到钓鱼上下文 — 使用 /apt phish <email> 生成鱼叉式网络钓鱼邮件",
        "en": "🎣 Phishing context detected — use /apt phish <email> to generate spear-phishing email",
    },
    "apt_c2_hint": {
        "ko": "🕵️ C2 컨텍스트 감지 — /apt c2 <host> 로 은폐 C2 채널 생성",
        "zh": "🕵️ 检测到C2上下文 — 使用 /apt c2 <host> 生成隐蔽C2信道",
        "en": "🕵️ C2 context detected — use /apt c2 <host> to generate covert C2 channel",
    },
    "apt_help_title": {
        "ko": "🕵️  APT 모듈 스위트 (v3.5.21) — 全面APT化",
        "zh": "🕵️  APT 模块套件 (v3.5.21) — 全面APT化",
        "en": "🕵️  APT Module Suite (v3.5.21) — Full APT-ification",
    },
    "apt_help_phish": {
        "ko": "  /apt phish <email> [lure]       — AI 스피어피싱 이메일 생성",
        "zh": "  /apt phish <email> [lure]       — AI鱼叉式钓鱼邮件生成",
        "en": "  /apt phish <email> [lure]       — AI spear-phishing email generator",
    },
    "apt_help_supply": {
        "ko": "  /apt supply <path>              — npm/pip/Actions 공급망 취약점 스캔",
        "zh": "  /apt supply <path>              — npm/pip/Actions 供应链漏洞扫描",
        "en": "  /apt supply <path>              — npm/pip/Actions supply chain vuln scan",
    },
    "apt_help_lateral": {
        "ko": "  /apt lateral <ip> [user] [hash] — Impacket/CME 횡방향 이동 명령 생성",
        "zh": "  /apt lateral <ip> [user] [hash] — Impacket/CME 横向移动命令生成",
        "en": "  /apt lateral <ip> [user] [hash] — Impacket/CME lateral movement commands",
    },
    "apt_help_c2": {
        "ko": "  /apt c2 <host> [dns|https|both]  — DNS터널/HTTPS 비콘 은폐 C2 생성",
        "zh": "  /apt c2 <host> [dns|https|both]  — DNS隧道/HTTPS信标隐蔽C2生成",
        "en": "  /apt c2 <host> [dns|https|both]  — DNS tunnel/HTTPS beacon covert C2",
    },
    "apt_phish_need_email": {
        "ko": "사용법: /apt phish <대상-이메일> [lure 주제]",
        "zh": "用法: /apt phish <目标邮箱> [诱饵主题]",
        "en": "Usage: /apt phish <target-email> [lure-topic]",
    },
    "apt_lateral_need_ip": {
        "ko": "사용법: /apt lateral <IP> [사용자명] [NTLM해시_또는_패스워드]",
        "zh": "用法: /apt lateral <IP> [用户名] [NTLM哈希或密码]",
        "en": "Usage: /apt lateral <IP> [username] [ntlm_hash_or_password]",
    },
    "apt_unknown_sub": {
        "ko": "알 수 없는 APT 서브 명령. /apt 로 도움말 확인",
        "zh": "未知APT子命令。输入 /apt 查看帮助",
        "en": "Unknown APT subcommand. Use /apt for help",
    },
    "apt_phish_generated": {
        "ko": "🎣 스피어피싱 이메일 생성 완료",
        "zh": "🎣 鱼叉式网络钓鱼邮件生成完成",
        "en": "🎣 Spear-phishing email generated",
    },
    "apt_supply_no_findings": {
        "ko": "✅ 공급망 취약점 없음 — 스캔 완료",
        "zh": "✅ 未发现供应链漏洞 — 扫描完成",
        "en": "✅ No supply chain vulnerabilities found — scan complete",
    },
    "apt_lateral_commands_ready": {
        "ko": "🔀 횡방향 이동 명령 생성 완료",
        "zh": "🔀 横向移动命令生成完成",
        "en": "🔀 Lateral movement commands ready",
    },
    "apt_c2_generated": {
        "ko": "🕵️ 은폐 C2 채널 스크립트 생성 완료",
        "zh": "🕵️ 隐蔽C2信道脚本生成完成",
        "en": "🕵️ Covert C2 channel scripts generated",
    },
    # ── v3.5.11: Ctrl+C / 오케스트레이터 중단 관련 ──────────────────────────
    "orch_ctrlc_stopped": {
        "ko": "⏹ 오케스트레이터 중단됨 — 다음 단계를 선택하세요",
        "zh": "⏹ 编排器已停止 — 请选择下一步",
        "en": "⏹ Orchestrator stopped — choose next step",
    },
    "ctrlc_cancel_hint": {
        "ko": "(입력 취소 — 다시 입력하거나 Ctrl+C 한 번 더 누르면 종료)",
        "zh": "(输入已取消 — 重新输入或再按一次 Ctrl+C 退出)",
        "en": "(Input cancelled — type again or press Ctrl+C once more to quit)",
    },

    # ── v3.5.22: Recon 모듈 — 자동 탐지 힌트 + /recon 커맨드 ─────────────────
    "recon_subdomain_hint": {
        "ko": "🔍 도메인 컨텍스트 탐지 — /recon passive <domain> 으로 서브도메인/인증서 수집",
        "zh": "🔍 检测到域名上下文 — 使用 /recon passive <domain> 收集子域名/证书",
        "en": "🔍 Domain context detected — use /recon passive <domain> for subdomain/cert collection",
    },
    "recon_port_hint": {
        "ko": "🗺 포트/서비스 컨텍스트 탐지 — /recon active <target> 으로 포트스캔 및 서비스 식별",
        "zh": "🗺 检测到端口/服务上下文 — 使用 /recon active <target> 进行端口扫描",
        "en": "🗺 Port/service context detected — use /recon active <target> for port scan & service ID",
    },
    "recon_asset_hint": {
        "ko": "🗄 자산 수집 컨텍스트 탐지 — /recon full <domain> 으로 전체 자산 자동 수집 + P0-P3 분류",
        "zh": "🗄 检测到资产收集上下文 — 使用 /recon full <domain> 自动收集资产并P0-P3分类",
        "en": "🗄 Asset collection context detected — use /recon full <domain> for full recon + prioritization",
    },
    "recon_js_hint": {
        "ko": "📜 JS/API 컨텍스트 탐지 — /recon js <url> 로 JS 파일에서 숨겨진 엔드포인트/키 추출",
        "zh": "📜 检测到JS/API上下文 — 使用 /recon js <url> 从JS文件提取隐藏端点/密钥",
        "en": "📜 JS/API context detected — use /recon js <url> to extract hidden endpoints/keys from JS",
    },
    "recon_nuclei_hint": {
        "ko": "🧬 Nuclei 컨텍스트 탐지 — /recon nuclei <target> 으로 자동 템플릿 취약점 스캔",
        "zh": "🧬 检测到Nuclei上下文 — 使用 /recon nuclei <target> 自动模板漏洞扫描",
        "en": "🧬 Nuclei context detected — use /recon nuclei <target> for auto template vulnerability scan",
    },
    # ── v3.6.8 FULL-UNLOCK 봉인 해제 관련 키 ─────────────────────────────
    "unlock_mode_active":       {"ko": "🔓 완전 강화 모드 활성화 — 봉인 해제됨 (v3.6.8)",
                                  "zh": "🔓 完全增强模式已激活 — 封印已解除 (v3.6.8)",
                                  "en": "🔓 Full-Unlock Mode Active — all restrictions unsealed (v3.6.8)"},
    "unlock_r1_unsealed":       {"ko": "✅ R1 완화 — 증거용 UPDATE 허용 (bingo_test_ 접두사 필수)",
                                  "zh": "✅ R1已解封 — 允许证据UPDATE（必须使用bingo_test_前缀）",
                                  "en": "✅ R1 unsealed — Proof-of-concept UPDATE allowed (bingo_test_ prefix required)"},
    "unlock_req_cap_removed":   {"ko": "✅ 요청 횟수 제한 해제 — 기법당 최대 50개 요청 (기존 15개)",
                                  "zh": "✅ 请求次数限制已解除 — 每技术最多50次请求（原15次）",
                                  "en": "✅ Request cap removed — up to 50 requests/technique (was 15)"},
    "unlock_output_limit_off":  {"ko": "✅ 출력 크기 제한 해제 — DB 덤프/RCE 결과 전체 출력",
                                  "zh": "✅ 输出大小限制已解除 — DB转储/RCE结果完整输出",
                                  "en": "✅ Output limit removed — full DB dump / RCE output enabled"},
    "unlock_delay_reduced":     {"ko": "✅ 딜레이 최소화 — adaptive_delay() 기본 0ms (ban 감지 시 자동 증가)",
                                  "zh": "✅ 延迟最小化 — adaptive_delay()默认0ms（检测到封禁时自动增加）",
                                  "en": "✅ Delay minimized — adaptive_delay() default 0ms (auto-increase on ban)"},
    "unlock_escalation_1sig":   {"ko": "✅ 에스컬레이션 임계값 낮춤 — 신뢰 신호 1개로 다음 단계 진행",
                                  "zh": "✅ 提权阈值降低 — 1个可信信号即可进入下一阶段",
                                  "en": "✅ Escalation threshold lowered — 1 reliable signal triggers next phase"},
    "unlock_rule42_chain":      {"ko": "⚡ RULE 42: 자동 공격 체인 활성화 — SQLi→덤프→크리덴셜→관리자→웹쉘→RCE",
                                  "zh": "⚡ RULE 42: 自动攻击链已激活 — SQLi→转储→凭据→管理员→Webshell→RCE",
                                  "en": "⚡ RULE 42: Auto attack chain active — SQLi→dump→creds→admin→webshell→RCE"},
    "unlock_rule43_postex":     {"ko": "⚡ RULE 43: 후속 공격 체인 — 초기 접근 후 자동 권한 상승 + 피벗",
                                  "zh": "⚡ RULE 43: 后渗透链 — 初始访问后自动提权+横向移动",
                                  "en": "⚡ RULE 43: Post-exploitation chain — auto privesc + pivot after initial access"},
    "unlock_rule44_creds":      {"ko": "⚡ RULE 44: 크리덴셜 수확 파이프라인 — 추출→크래킹→재사용 자동화",
                                  "zh": "⚡ RULE 44: 凭据收割管道 — 自动化提取→破解→复用",
                                  "en": "⚡ RULE 44: Credential harvest pipeline — extract→crack→reuse automated"},
    "unlock_rule45_bypass":     {"ko": "⚡ RULE 45: 고급 우회 무장 — WAF/IP차단/인증 우회 10종 자동 적용",
                                  "zh": "⚡ RULE 45: 高级绕过武装 — 10种WAF/IP封锁/认证绕过自动应用",
                                  "en": "⚡ RULE 45: Advanced bypass arsenal — 10x WAF/IP-ban/auth bypass auto-applied"},
    "unlock_rule46_recon":      {"ko": "⚡ RULE 46: 깊은 정찰 — JS API 추출 + 클라우드 메타데이터 SSRF 자동화",
                                  "zh": "⚡ RULE 46: 深度侦察 — JS API提取+云元数据SSRF自动化",
                                  "en": "⚡ RULE 46: Deep recon — JS API extraction + cloud metadata SSRF automated"},
    "unlock_rule47_cve":        {"ko": "⚡ RULE 47: CVE 연동 — 버전 지문 즉시 CVE 매핑 + KB 자동 참조",
                                  "zh": "⚡ RULE 47: CVE联动 — 版本指纹即时CVE映射+KB自动参考",
                                  "en": "⚡ RULE 47: CVE integration — version fingerprint → CVE map + KB auto-load"},
    "unlock_rule48_report":     {"ko": "⚡ RULE 48: 증거 수집 + 자동 리포트 — CVSS 자동 계산 + curl PoC 생성",
                                  "zh": "⚡ RULE 48: 证据收集+自动报告 — CVSS自动计算+curl PoC生成",
                                  "en": "⚡ RULE 48: Evidence harvest + auto-report — CVSS auto-score + curl PoC gen"},
    "full_unlock_summary":      {"ko": "🔓 bingo v3.6.8 완전 강화 버전 — 7개 봉인 해제 완료\n   R1완화 | 요청무제한 | 출력무제한 | 딜레이0 | 에스컬레이션완화 | RULE42-48탑재",
                                  "zh": "🔓 bingo v3.6.8 完全增强版 — 7项封印已解除\n   R1缓解|请求无限制|输出无限制|延迟0|提权宽松|RULE42-48已装载",
                                  "en": "🔓 bingo v3.6.8 Full-Unlock Edition — 7 restrictions unsealed\n   R1eased|no req cap|no output cap|0 delay|loose escalation|RULE42-48 loaded"},

    # ── v3.6.9 실전화 버전 관련 키 ────────────────────────────────────────
    "combat_mode_active":        {"ko": "⚔️ 완전 실전화 모드 활성화 (v3.6.9) — 자연어 파서 + 자동 체인 탑재",
                                   "zh": "⚔️ 完全实战化模式已激活 (v3.6.9) — 自然语言解析器+自动链已装载",
                                   "en": "⚔️ Full Combat Mode Active (v3.6.9) — NL parser + auto-chain loaded"},
    "combat_auto_pivot":         {"ko": "⚡ [AUTO-PIVOT] 기법 전환: {from_tech} → {to_tech}",
                                   "zh": "⚡ [AUTO-PIVOT] 技术切换: {from_tech} → {to_tech}",
                                   "en": "⚡ [AUTO-PIVOT] Switching: {from_tech} → {to_tech}"},
    "combat_chain_next":         {"ko": "🔗 [AUTO-CHAIN] {prev} 확인 → 다음 단계: {next} 자동 실행",
                                   "zh": "🔗 [AUTO-CHAIN] {prev} 已确认 → 自动执行下一步: {next}",
                                   "en": "🔗 [AUTO-CHAIN] {prev} confirmed → auto-exec next: {next}"},
    "combat_target_classified":  {"ko": "🎯 타겟 분류 완료: [{type}] — 공격 우선순위: {priority}",
                                   "zh": "🎯 目标分类完成: [{type}] — 攻击优先级: {priority}",
                                   "en": "🎯 Target classified: [{type}] — Attack priority: {priority}"},
    "combat_cmd_interpreted":    {"ko": "▶ [해석된 작전: {op}] → {target}",
                                   "zh": "▶ [解析作战: {op}] → {target}",
                                   "en": "▶ [Interpreted op: {op}] → {target}"},
    "combat_session_expired":    {"ko": "⚠️ 세션 만료 감지 — 자동 재인증 중...",
                                   "zh": "⚠️ 检测到会话过期 — 正在自动重新认证...",
                                   "en": "⚠️ Session expired detected — auto re-auth in progress..."},
    "combat_session_renewed":    {"ko": "✅ 세션 갱신 완료 — 공격 재개",
                                   "zh": "✅ 会话已更新 — 恢复攻击",
                                   "en": "✅ Session renewed — resuming attack"},
    "combat_stealth_on":         {"ko": "🥷 스텔스 모드 ON — 인간화 딜레이 + UA 랜덤화 적용",
                                   "zh": "🥷 隐身模式已开启 — 人性化延迟+UA随机化已应用",
                                   "en": "🥷 Stealth mode ON — humanized delay + UA randomization applied"},
    "combat_rate_limit_hit":     {"ko": "⏳ 속도 제한 감지 ({code}) — {delay}초 대기 후 재시도",
                                   "zh": "⏳ 检测到速率限制 ({code}) — 等待{delay}秒后重试",
                                   "en": "⏳ Rate limit detected ({code}) — waiting {delay}s before retry"},
    "combat_creds_found":        {"ko": "🔑 크리덴셜 발견! → 자동 재사용 테스트 시작: {services}",
                                   "zh": "🔑 发现凭据! → 自动复用测试开始: {services}",
                                   "en": "🔑 Credentials found! → Auto reuse test starting: {services}"},
    "combat_shell_acquired":     {"ko": "💀 웹쉘 획득! → 자동 후속 공격 체인 시작 (RULE 43)",
                                   "zh": "💀 获得Webshell! → 自动后渗透链开始 (RULE 43)",
                                   "en": "💀 Shell acquired! → Auto post-exploit chain starting (RULE 43)"},
    "combat_privesc_auto":       {"ko": "⬆️ 권한 상승 자동 탐색 중... (sudo/SUID/cron/kernel)",
                                   "zh": "⬆️ 自动搜索提权路径... (sudo/SUID/cron/kernel)",
                                   "en": "⬆️ Auto-searching privesc paths... (sudo/SUID/cron/kernel)"},
    "combat_pivot_internal":     {"ko": "🌐 내부망 피벗 시작 — 내부 IP 범위: {range} 스캔 중",
                                   "zh": "🌐 开始内网横向移动 — 扫描内部IP范围: {range}",
                                   "en": "🌐 Internal pivot starting — scanning range: {range}"},
    "combat_kr_gnuboard":        {"ko": "🇰🇷 그누보드 탐지 — 특화 공격 패턴 로드 (bo_table/wr_id SQLi)",
                                   "zh": "🇰🇷 检测到Gnuboard — 加载专项攻击模式 (bo_table/wr_id SQLi)",
                                   "en": "🇰🇷 Gnuboard detected — loading specialized attack pattern (bo_table/wr_id SQLi)"},
    "combat_kr_xe":              {"ko": "🇰🇷 XpressEngine(XE) 탐지 — 특화 공격 패턴 로드",
                                   "zh": "🇰🇷 检测到XpressEngine(XE) — 加载专项攻击模式",
                                   "en": "🇰🇷 XpressEngine(XE) detected — loading specialized attack pattern"},
    "combat_cn_thinkphp":        {"ko": "🇨🇳 ThinkPHP 탐지 — CVE RCE 페이로드 자동 시도",
                                   "zh": "🇨🇳 检测到ThinkPHP — 自动尝试CVE RCE Payload",
                                   "en": "🇨🇳 ThinkPHP detected — auto-trying CVE RCE payload"},
    "combat_cn_shiro":           {"ko": "🇨🇳 Apache Shiro 탐지 — rememberMe CBC Oracle 공격 준비",
                                   "zh": "🇨🇳 检测到Apache Shiro — 准备rememberMe CBC Oracle攻击",
                                   "en": "🇨🇳 Apache Shiro detected — preparing rememberMe CBC Oracle attack"},
    "combat_cn_fastjson":        {"ko": "🇨🇳 Fastjson 탐지 — @type 역직렬화 RCE 페이로드 준비",
                                   "zh": "🇨🇳 检测到Fastjson — 准备@type反序列化RCE Payload",
                                   "en": "🇨🇳 Fastjson detected — preparing @type deserialization RCE payload"},
    "combat_full_summary":       {"ko": "⚔️ bingo v3.6.9 완전 실전화 — RULE 49~53 탑재\n   자연어파서 | 타겟분류 | 자동체인 | 스텔스 | 한중특화",
                                   "zh": "⚔️ bingo v3.6.9 完全实战化 — RULE 49~53已装载\n   自然语言解析|目标分类|自动链|隐身|中韩专项",
                                   "en": "⚔️ bingo v3.6.9 Full Combat — RULE 49~53 loaded\n   NL-parser|target-classify|auto-chain|stealth|KR/CN specialist"},

    "recon_help_title": {
        "ko": "🔍  Recon 모듈 스위트 (v3.9.0) — 정보수집 / 자산수집",
        "zh": "🔍  侦察模块套件 (v3.9.0) — 信息收集 / 资产收集",
        "en": "🔍  Recon Module Suite (v3.9.0) — Info Gathering / Asset Collection",
    },
    "recon_help_passive": {
        "ko": "  /recon passive <domain>   — Passive 수집 (crt.sh/BGPView/Shodan/FOFA/Dorks)",
        "zh": "  /recon passive <domain>   — 被动收集 (crt.sh/BGPView/Shodan/FOFA/Dorks)",
        "en": "  /recon passive <domain>   — Passive collection (crt.sh/BGPView/Shodan/FOFA/Dorks)",
    },
    "recon_help_active": {
        "ko": "  /recon active  <target>   — Active 수집 (서브도메인 브루트/포트스캔/HTTP 프로빙)",
        "zh": "  /recon active  <target>   — 主动收集 (子域名爆破/端口扫描/HTTP探测)",
        "en": "  /recon active  <target>   — Active collection (subdomain brute/port scan/HTTP probe)",
    },
    "recon_help_full": {
        "ko": "  /recon full    <domain>   — 전체 수행 + P0-P3 자산 우선순위 분류",
        "zh": "  /recon full    <domain>   — 全量执行 + P0-P3资产优先级分类",
        "en": "  /recon full    <domain>   — Full run + P0-P3 asset priority classification",
    },
    "recon_help_js": {
        "ko": "  /recon js      <url>      — JS 파일에서 API 엔드포인트/시크릿 추출",
        "zh": "  /recon js      <url>      — 从JS文件提取API端点/密钥",
        "en": "  /recon js      <url>      — Extract API endpoints/secrets from JS files",
    },
    "recon_help_nuclei": {
        "ko": "  /recon nuclei  <target>   — Nuclei 템플릿 취약점 스캔",
        "zh": "  /recon nuclei  <target>   — Nuclei模板漏洞扫描",
        "en": "  /recon nuclei  <target>   — Nuclei template vulnerability scan",
    },
    "recon_help_dorks": {
        "ko": "  /recon dorks   <domain>   — Google/GitHub Dork 자동 생성",
        "zh": "  /recon dorks   <domain>   — 自动生成Google/GitHub Dork",
        "en": "  /recon dorks   <domain>   — Auto-generate Google/GitHub Dorks",
    },
    "recon_help_env": {
        "ko": "  환경변수(선택): SHODAN_KEY  FOFA_EMAIL  FOFA_KEY  HUNTER_KEY",
        "zh": "  环境变量(可选): SHODAN_KEY  FOFA_EMAIL  FOFA_KEY  HUNTER_KEY",
        "en": "  Env vars (optional): SHODAN_KEY  FOFA_EMAIL  FOFA_KEY  HUNTER_KEY",
    },
    "recon_unknown_sub": {
        "ko": "알 수 없는 Recon 서브 명령. /recon 으로 도움말 확인",
        "zh": "未知Recon子命令。输入 /recon 查看帮助",
        "en": "Unknown Recon subcommand. Use /recon for help",
    },
    # ── /tools-ext ──────────────────────────────────────────────────
    "tools_ext_no_tools": {
        "ko": "정의된 외부 도구 없음. bingo/tools_ext/builtin/ 에 YAML 파일을 추가하세요",
        "zh": "未定义外部工具。请在 bingo/tools_ext/builtin/ 添加 YAML 文件",
        "en": "No external tools defined. Add YAML files to bingo/tools_ext/builtin/",
    },
    "tools_ext_run_usage": {
        "ko": "사용법: /tools-ext run <도구명> [인자...]",
        "zh": "用法: /tools-ext run <工具名> [参数...]",
        "en": "Usage: /tools-ext run <tool_name> [args...]",
    },
    "tools_ext_reloaded": {
        "ko": "외부 도구 목록을 새로 불러왔습니다.",
        "zh": "外部工具已重新加载。",
        "en": "External tools reloaded.",
    },
    "tools_ext_usage": {
        "ko": "사용법: /tools-ext [list|run <이름>|reload]",
        "zh": "用法: /tools-ext [list|run <名称>|reload]",
        "en": "Usage: /tools-ext [list|run <name>|reload]",
    },
    # v3.6.3 — 오탐 방지 규칙 관련 경고 메시지
    "sqli_warn_error_fp": {
        "ko": "⚠️ [오탐주의] 'error' 문자열 단독 = SQL 오류 아님. 실제 SQL 문법 오류 패턴 확인 필요.",
        "zh": "⚠️ [误报警告] 单独 'error' 字符串 ≠ SQL 错误。需确认真实 SQL 语法错误模式。",
        "en": "⚠️ [FP-WARN] Bare 'error' string ≠ SQL error. Verify actual SQL syntax error pattern.",
    },
    "sqli_warn_mysql_baseline": {
        "ko": "⚠️ [오탐주의] 'mysql' 키워드가 베이스라인에도 존재 — 인젝션 신호로 사용 불가.",
        "zh": "⚠️ [误报警告] 'mysql' 关键字在基线响应中已存在 — 不可用作注入信号。",
        "en": "⚠️ [FP-WARN] 'mysql' keyword present in baseline — cannot use as injection signal.",
    },
    "sqli_warn_union_reflection": {
        "ko": "⚠️ [오탐주의] UNION 응답 크기 선형 증가 = 반사(Reflection). sentinel 값으로 재검증 필요.",
        "zh": "⚠️ [误报警告] UNION 响应大小线性增长 = 反射(Reflection)。需用 sentinel 值重新验证。",
        "en": "⚠️ [FP-WARN] UNION response size grows linearly = payload reflection. Re-verify with sentinel.",
    },
    "sqli_warn_sleep_no_delay": {
        "ko": "⚠️ [오탐주의] SLEEP 실제 지연 미확인 — WAF가 SLEEP 함수 차단 중일 수 있음.",
        "zh": "⚠️ [误报警告] SLEEP 实际延迟未确认 — WAF 可能正在拦截 SLEEP 函数。",
        "en": "⚠️ [FP-WARN] SLEEP delay not confirmed — WAF may be blocking SLEEP execution.",
    },
    "proxy_err_socks": {
        "ko": "⚠️ [PROXY-ERROR] SOCKS 프록시 연결 실패 (Tor 미실행 또는 설정 오류). IP 차단 아님.",
        "zh": "⚠️ [PROXY-ERROR] SOCKS 代理连接失败（Tor 未运行或配置错误），不是 IP 封锁。",
        "en": "⚠️ [PROXY-ERROR] SOCKS proxy connection failed (Tor not running or misconfigured). Not an IP ban.",
    },
    "sqli_escalate_blocked": {
        "ko": "⚠️ 신뢰 신호 부족 — 에스컬레이션 보류. 신뢰 가능한 SQLi 신호 2개 이상 필요.",
        "zh": "⚠️ 可信信号不足 — 暂停升级。需要至少 2 个可信 SQLi 信号。",
        "en": "⚠️ Insufficient reliable signals — escalation paused. Need 2+ confirmed SQLi signals.",
    },
    "credential_fp_login_form": {
        "ko": "[-] 로그인 폼 존재 = 정상 기능. 실제 인증 우회 확인 없이 credential 취약점 생성 안 함.",
        "zh": "[-] 登录表单存在 = 正常功能。未实际确认身份验证绕过，不生成 credential 漏洞。",
        "en": "[-] Login form exists = normal feature. No credential finding without confirmed auth bypass.",
    },
    "idor_fp_public_access": {
        "ko": "[-] 공개 게시물 순차 접근 = 정상 동작. 인가 경계 교차 확인 없이 IDOR 생성 안 함.",
        "zh": "[-] 顺序访问公开帖子 = 正常行为。未确认授权边界越界，不生成 IDOR 漏洞。",
        "en": "[-] Sequential access to public posts = normal behavior. No IDOR finding without auth boundary test.",
    },
    # ── v3.6.4 Pentest-Lyan Integration Keys ──
    "threat_model_12dim_header": {
        "ko": "[위협모델] 12차원 위협 식별 프레임워크 적용 중",
        "zh": "[威胁建模] 正在应用 12 维威胁识别框架",
        "en": "[ThreatModel] Applying 12-dimension threat identification framework",
    },
    "threat_model_dim_irrelevant": {
        "ko": "  · [{dim}] 해당 기능과 무관 — 건너뜀",
        "zh": "  · [{dim}] 与当前功能无关 — 跳过",
        "en": "  · [{dim}] Not relevant to this feature — skipped",
    },
    "threat_model_dim_candidate": {
        "ko": "  · [{dim}] 잠재 위협 발견: {threat_name} — 이유: {reason}",
        "zh": "  · [{dim}] 潜在威胁: {threat_name} — 原因: {reason}",
        "en": "  · [{dim}] Potential threat: {threat_name} — reason: {reason}",
    },
    "coverage_note_required": {
        "ko": "[커버리지 노트] 테스트 종료 전 3개 항목 필수 기록 — 입력면/행동면/미배제 공격면",
        "zh": "[覆盖率笔记] 测试结束前必须记录 3 项 — 输入面/行为面/未排除攻击面",
        "en": "[CoverageNote] Before closing test, record 3 items — input/behavior/unruled-out surface",
    },
    "coverage_unruled_out": {
        "ko": "  ⚠️ 미배제 공격면: {surfaces}",
        "zh": "  ⚠️ 未排除攻击面: {surfaces}",
        "en": "  ⚠️ Unruled-out surface: {surfaces}",
    },
    "g3_evidence_missing": {
        "ko": "[-] 증거 불충분 → [SUSPECTED ⚠️] 강등. 누락 항목: {missing}",
        "zh": "[-] 证据不足 → 降级为 [SUSPECTED ⚠️]。缺少: {missing}",
        "en": "[-] Insufficient evidence → demoted to [SUSPECTED ⚠️]. Missing: {missing}",
    },
    "g3_info_not_vuln": {
        "ko": "[INFO] 설정 관찰 항목 — 취약점 번호 부여 안 함: {item}",
        "zh": "[INFO] 配置观察项 — 不赋予漏洞编号: {item}",
        "en": "[INFO] Config observation — no vuln ID assigned: {item}",
    },
    "cross_role_start": {
        "ko": "[크로스롤] victim 자원 ID 수집 → attacker 세션으로 교차 접근 테스트 시작",
        "zh": "[跨角色] 收集 victim 资源 ID → 使用 attacker 会话开始交叉访问测试",
        "en": "[CrossRole] Collecting victim resource IDs → starting cross-access test with attacker session",
    },
    "cross_role_confirmed": {
        "ko": "[크로스롤] CONFIRMED — attacker가 victim 자원({rid}) 접근 성공. 실제 데이터 확인됨.",
        "zh": "[跨角色] 已确认 — attacker 成功访问 victim 资源 ({rid})。已验证实际数据。",
        "en": "[CrossRole] CONFIRMED — attacker accessed victim resource ({rid}). Real data verified.",
    },
    "cross_role_not_vuln": {
        "ko": "[크로스롤] 안전 — attacker 요청 403/401 또는 빈 응답. 권한 경계 정상.",
        "zh": "[跨角色] 安全 — attacker 请求返回 403/401 或空响应。权限边界正常。",
        "en": "[CrossRole] Safe — attacker request returned 403/401 or empty. Auth boundary enforced.",
    },
    "cross_role_skip_no_account": {
        "ko": "[크로스롤] 계정 부족 — 크로스롤 검증 생략. 단일 계정으로 진행.",
        "zh": "[跨角色] 账户不足 — 跳过跨角色验证。使用单账户继续。",
        "en": "[CrossRole] Insufficient accounts — cross-role check skipped. Proceeding with single account.",
    },
    "victim_id_hardcode_blocked": {
        "ko": "[-] victim ID 하드코딩 금지. 반드시 실제 계정에서 ID를 추출할 것.",
        "zh": "[-] 禁止硬编码 victim ID。必须从真实账户中提取 ID。",
        "en": "[-] Hardcoding victim IDs is forbidden. Must extract IDs from real accounts.",
    },
    # ── v3.7.0 전문가 해커 레벨 (RULE 54~63) 다국어 키 ──
    "expert_mode_active": {
        "ko": "[+] 전문가 해커 모드 활성화 (v3.7.0) — C2·AD·바이너리·0day·피싱·클라우드·IoT·안티포렌식·공급망·AI공격 가능",
        "zh": "[+] 专家黑客模式已激活 (v3.7.0) — C2·AD·二进制·0day·钓鱼·云·IoT·反取证·供应链·AI攻击 已启用",
        "en": "[+] Expert Hacker Mode ACTIVE (v3.7.0) — C2·AD·Binary·0day·Phishing·Cloud·IoT·AntiForensics·SupplyChain·AI attacks enabled",
    },
    "expert_c2_beacon_gen": {
        "ko": "[RULE 54] C2 비콘 생성 중 — 플랫폼: {platform} | 리스너: {listener}",
        "zh": "[RULE 54] 正在生成 C2 信标 — 平台: {platform} | 监听器: {listener}",
        "en": "[RULE 54] Generating C2 beacon — Platform: {platform} | Listener: {listener}",
    },
    "expert_c2_session": {
        "ko": "[RULE 54] C2 세션 획득! 호스트: {host} | 권한: {priv} | 지속화 방법: {persist}",
        "zh": "[RULE 54] C2 会话已获取！主机: {host} | 权限: {priv} | 持久化方式: {persist}",
        "en": "[RULE 54] C2 session obtained! Host: {host} | Privilege: {priv} | Persistence: {persist}",
    },
    "expert_c2_fileless": {
        "ko": "[RULE 54] 파일리스 임플란트 배포 — 메모리 내 실행, 디스크 흔적 없음",
        "zh": "[RULE 54] 部署无文件植入 — 内存执行，无磁盘痕迹",
        "en": "[RULE 54] Fileless implant deployed — in-memory execution, no disk artifacts",
    },
    "expert_ad_bloodhound": {
        "ko": "[RULE 55] BloodHound 경로 분석 완료 — DC까지 {hops}홉, 최단 경로: {path}",
        "zh": "[RULE 55] BloodHound 路径分析完成 — 距 DC {hops} 跳，最短路径: {path}",
        "en": "[RULE 55] BloodHound path analysis done — {hops} hops to DC, shortest: {path}",
    },
    "expert_ad_kerberos": {
        "ko": "[RULE 55] Kerberos 공격 — 방법: {method} | 크랙된 계정: {account} | 해시: {hash}",
        "zh": "[RULE 55] Kerberos 攻击 — 方式: {method} | 已破解账户: {account} | 哈希: {hash}",
        "en": "[RULE 55] Kerberos attack — Method: {method} | Cracked account: {account} | Hash: {hash}",
    },
    "expert_ad_dcsync": {
        "ko": "[RULE 55] DCSync 완료 — NTDS.dit 전체 덤프, KRBTGT 해시 획득, Golden Ticket 준비 완료",
        "zh": "[RULE 55] DCSync 完成 — NTDS.dit 全量转储，获取 KRBTGT 哈希，Golden Ticket 就绪",
        "en": "[RULE 55] DCSync complete — Full NTDS.dit dump, KRBTGT hash obtained, Golden Ticket ready",
    },
    "expert_binary_exploit": {
        "ko": "[RULE 56] 바이너리 익스플로잇 — 오프셋: {offset} | 보호: {protections} | 페이로드: {payload_type}",
        "zh": "[RULE 56] 二进制漏洞利用 — 偏移: {offset} | 保护: {protections} | 载荷: {payload_type}",
        "en": "[RULE 56] Binary exploit — Offset: {offset} | Protections: {protections} | Payload: {payload_type}",
    },
    "expert_binary_shell": {
        "ko": "[RULE 56] 쉘 획득! PID: {pid} | UID: {uid} | 커널: {kernel}",
        "zh": "[RULE 56] 获得 Shell！PID: {pid} | UID: {uid} | 内核: {kernel}",
        "en": "[RULE 56] Shell obtained! PID: {pid} | UID: {uid} | Kernel: {kernel}",
    },
    "expert_0day_found": {
        "ko": "[RULE 57] 0-Day/N-Day 발견 — CVE: {cve} | CVSS: {score} | KEV: {in_kev} | PoC: {poc_url}",
        "zh": "[RULE 57] 发现 0-Day/N-Day — CVE: {cve} | CVSS: {score} | KEV: {in_kev} | PoC: {poc_url}",
        "en": "[RULE 57] 0-Day/N-Day found — CVE: {cve} | CVSS: {score} | KEV: {in_kev} | PoC: {poc_url}",
    },
    "expert_0day_patch_diff": {
        "ko": "[RULE 57] 패치 분석 완료 — 변경 함수: {funcs}개, 잠재 취약점 경로: {paths}개",
        "zh": "[RULE 57] 补丁分析完成 — 变更函数: {funcs} 个，潜在漏洞路径: {paths} 个",
        "en": "[RULE 57] Patch diff done — {funcs} changed functions, {paths} potential vuln paths",
    },
    "expert_phish_campaign": {
        "ko": "[RULE 58] 피싱 캠페인 시작 — 타겟: {count}명 | 방법: {method} | 추적 URL: {url}",
        "zh": "[RULE 58] 钓鱼活动已启动 — 目标: {count} 人 | 方式: {method} | 跟踪 URL: {url}",
        "en": "[RULE 58] Phishing campaign started — Targets: {count} | Method: {method} | Tracking URL: {url}",
    },
    "expert_phish_mfa_bypass": {
        "ko": "[RULE 58] evilginx3 AiTM 성공 — MFA 우회 완료, 세션 쿠키 탈취: {cookie_count}개",
        "zh": "[RULE 58] evilginx3 AiTM 成功 — MFA 绕过完成，已截取会话 Cookie: {cookie_count} 个",
        "en": "[RULE 58] evilginx3 AiTM success — MFA bypassed, session cookies stolen: {cookie_count}",
    },
    "expert_cloud_aws_privesc": {
        "ko": "[RULE 59] AWS 권한 상승 완료 — 경로: {path} | 최종 권한: {final_priv} | 백도어: 생성됨",
        "zh": "[RULE 59] AWS 权限提升完成 — 路径: {path} | 最终权限: {final_priv} | 后门: 已创建",
        "en": "[RULE 59] AWS privilege escalation done — Path: {path} | Final: {final_priv} | Backdoor: created",
    },
    "expert_cloud_k8s_etcd": {
        "ko": "[RULE 59] K8s etcd 접근 성공 — 시크릿 {count}개 추출, ServiceAccount 토큰 획득",
        "zh": "[RULE 59] K8s etcd 访问成功 — 提取 {count} 个 Secret，获取 ServiceAccount 令牌",
        "en": "[RULE 59] K8s etcd accessed — {count} secrets extracted, ServiceAccount tokens obtained",
    },
    "expert_cloud_azure_prt": {
        "ko": "[RULE 59] Azure AD PRT 탈취 — 테넌트: {tenant} | MFA 없이 M365 전체 접근 가능",
        "zh": "[RULE 59] Azure AD PRT 已窃取 — 租户: {tenant} | 无需 MFA 可访问所有 M365 服务",
        "en": "[RULE 59] Azure AD PRT stolen — Tenant: {tenant} | Full M365 access without MFA",
    },
    "expert_iot_firmware": {
        "ko": "[RULE 60] 펌웨어 분석 완료 — 발견: 하드코딩 크리덴셜 {cred_count}개, 백도어 {bd_count}개",
        "zh": "[RULE 60] 固件分析完成 — 发现: 硬编码凭据 {cred_count} 个，后门 {bd_count} 个",
        "en": "[RULE 60] Firmware analyzed — Found: {cred_count} hardcoded creds, {bd_count} backdoors",
    },
    "expert_iot_modbus": {
        "ko": "[RULE 60] Modbus/DNP3 장치 발견 — Unit ID {unit_id} | 레지스터 {reg_count}개 읽기 성공",
        "zh": "[RULE 60] 发现 Modbus/DNP3 设备 — Unit ID {unit_id} | 成功读取 {reg_count} 个寄存器",
        "en": "[RULE 60] Modbus/DNP3 device found — Unit ID {unit_id} | {reg_count} registers read",
    },
    "expert_antiforensic_ts": {
        "ko": "[RULE 61] 타임스탬프 조작 완료 — {file_count}개 파일이 {ref_file} 기준으로 위장됨",
        "zh": "[RULE 61] 时间戳篡改完成 — {file_count} 个文件已伪装为 {ref_file} 的时间",
        "en": "[RULE 61] Timestomping done — {file_count} files disguised as {ref_file}",
    },
    "expert_antiforensic_log": {
        "ko": "[RULE 61] 이벤트 로그 선택 삭제 — ID {event_ids} | {count}개 항목 제거됨",
        "zh": "[RULE 61] 选择性删除事件日志 — ID {event_ids} | 已删除 {count} 条记录",
        "en": "[RULE 61] Event log selectively cleared — IDs {event_ids} | {count} entries removed",
    },
    "expert_antiforensic_shred": {
        "ko": "[RULE 61] 증거 완전 삭제 — {file_count}개 파일 3회 덮어쓰기 후 삭제, 복구 불가",
        "zh": "[RULE 61] 证据彻底删除 — {file_count} 个文件 3 次覆写后删除，无法恢复",
        "en": "[RULE 61] Evidence shredded — {file_count} files overwritten 3x, unrecoverable",
    },
    "expert_supply_dep_confusion": {
        "ko": "[RULE 62] 의존성 혼동 공격 — 내부 패키지 {pkg_count}개 발견, {registry}에 섀도우 패키지 등록 준비",
        "zh": "[RULE 62] 依赖混淆攻击 — 发现内部包 {pkg_count} 个，准备在 {registry} 注册影子包",
        "en": "[RULE 62] Dependency confusion — {pkg_count} internal packages found, shadow packages ready for {registry}",
    },
    "expert_supply_gh_inject": {
        "ko": "[RULE 62] GitHub Actions 인젝션 — 워크플로우 {workflow} 취약, GITHUB_TOKEN 탈취 가능",
        "zh": "[RULE 62] GitHub Actions 注入 — 工作流 {workflow} 存在漏洞，可窃取 GITHUB_TOKEN",
        "en": "[RULE 62] GitHub Actions injection — Workflow {workflow} vulnerable, GITHUB_TOKEN extractable",
    },
    "expert_supply_docker": {
        "ko": "[RULE 62] Docker 이미지 백도어 삽입 — 이미지: {image} | 백도어 레이어 숨김 완료",
        "zh": "[RULE 62] Docker 镜像后门植入 — 镜像: {image} | 后门层已隐藏",
        "en": "[RULE 62] Docker image backdoored — Image: {image} | Hidden backdoor layer injected",
    },
    "expert_llm_prompt_inject": {
        "ko": "[RULE 63] 프롬프트 인젝션 성공 — 모델: {model} | 우회 방법: {method} | 탈취 데이터: {data_type}",
        "zh": "[RULE 63] 提示注入成功 — 模型: {model} | 绕过方式: {method} | 窃取数据: {data_type}",
        "en": "[RULE 63] Prompt injection success — Model: {model} | Bypass: {method} | Stolen: {data_type}",
    },
    "expert_llm_rag_poison": {
        "ko": "[RULE 63] RAG 시스템 오염 — 악성 청크 {chunk_count}개 삽입, 관련 쿼리 시 자동 실행",
        "zh": "[RULE 63] RAG 系统已污染 — 插入恶意块 {chunk_count} 个，相关查询时自动执行",
        "en": "[RULE 63] RAG system poisoned — {chunk_count} malicious chunks injected, auto-triggered on queries",
    },
    "expert_llm_extract": {
        "ko": "[RULE 63] LLM 모델 추출 중 — 쿼리: {query_count}개 | 복제 정확도: {accuracy}%",
        "zh": "[RULE 63] 正在提取 LLM 模型 — 查询: {query_count} 个 | 复制准确度: {accuracy}%",
        "en": "[RULE 63] LLM model extraction — Queries: {query_count} | Clone accuracy: {accuracy}%",
    },
    "expert_llm_mcp_inject": {
        "ko": "[RULE 63] MCP 에이전트 체인 인젝션 — 에이전트 {agent}가 악성 페이지 방문 → 명령 전파됨",
        "zh": "[RULE 63] MCP 代理链注入 — 代理 {agent} 访问恶意页面 → 命令已传播",
        "en": "[RULE 63] MCP agent chain injection — Agent {agent} visited malicious page → command propagated",
    },
    "expert_full_summary": {
        "ko": "═══ 전문가 해커 레벨 활성화 완료 (v3.7.0) ═══\n"
              "RULE 54: C2 프레임워크 연동 (Sliver/Havoc/DNS)\n"
              "RULE 55: 고급 AD 공격 체인 (BloodHound→DCSync→Golden Ticket)\n"
              "RULE 56: 바이너리 익스플로잇 (ROP·Heap·Kernel)\n"
              "RULE 57: 0-Day/N-Day 리서치 파이프라인 (KEV·NVD·EDB·PoC)\n"
              "RULE 58: 피싱 자동화 (OSINT→AiTM MFA우회→GoPhish)\n"
              "RULE 59: 클라우드 심층 공격 (Pacu·etcd·Azure PRT·GCP SA)\n"
              "RULE 60: IoT/하드웨어 공격 (펌웨어·Modbus·WiFi)\n"
              "RULE 61: 고급 안티포렌식 (Timestomping·로그삭제·shred)\n"
              "RULE 62: 공급망 공격 (Dep Confusion·GH Actions·Docker)\n"
              "RULE 63: AI/LLM 타겟 공격 (인젝션·RAG오염·추출·MCP)\n"
              "━━━ 완전 전문가 해커 레벨 달성 ━━━",
        "zh": "═══ 专家黑客级别激活完成 (v3.7.0) ═══\n"
              "RULE 54: C2 框架联动 (Sliver/Havoc/DNS)\n"
              "RULE 55: 高级 AD 攻击链 (BloodHound→DCSync→Golden Ticket)\n"
              "RULE 56: 二进制漏洞利用 (ROP·堆·内核)\n"
              "RULE 57: 0-Day/N-Day 研究管道 (KEV·NVD·EDB·PoC)\n"
              "RULE 58: 钓鱼自动化 (OSINT→AiTM MFA绕过→GoPhish)\n"
              "RULE 59: 云深度攻击 (Pacu·etcd·Azure PRT·GCP SA)\n"
              "RULE 60: IoT/硬件攻击 (固件·Modbus·WiFi)\n"
              "RULE 61: 高级反取证 (时间戳篡改·日志删除·碎片化)\n"
              "RULE 62: 供应链攻击 (依赖混淆·GH Actions·Docker)\n"
              "RULE 63: AI/LLM 目标攻击 (注入·RAG投毒·提取·MCP)\n"
              "━━━ 全面专家黑客级别达成 ━━━",
        "en": "═══ Expert Hacker Level ACTIVATED (v3.7.0) ═══\n"
              "RULE 54: C2 Framework (Sliver/Havoc/DNS Beaconing)\n"
              "RULE 55: Advanced AD Attack Chain (BloodHound→DCSync→Golden Ticket)\n"
              "RULE 56: Binary Exploitation (ROP·Heap·Kernel)\n"
              "RULE 57: 0-Day/N-Day Research Pipeline (KEV·NVD·EDB·PoC)\n"
              "RULE 58: Phishing Automation (OSINT→AiTM MFA Bypass→GoPhish)\n"
              "RULE 59: Deep Cloud Attacks (Pacu·etcd·Azure PRT·GCP SA)\n"
              "RULE 60: IoT/Hardware Attacks (Firmware·Modbus·WiFi)\n"
              "RULE 61: Advanced Anti-Forensics (Timestomping·Log Delete·Shred)\n"
              "RULE 62: Supply Chain Attacks (Dep Confusion·GH Actions·Docker)\n"
              "RULE 63: AI/LLM Target Attacks (Injection·RAG Poison·Extract·MCP)\n"
              "━━━ Full Expert Hacker Level Achieved ━━━",
    },
    # ── v3.8.0 최고급 엘리트 해커 (RULE 64~73) 다국어 키 ──
    "elite_mode_active": {
        "ko": "[+] 엘리트 해커 모드 활성화 (v3.8.0) — C2회피·커스텀임플란트·OPSEC소각·물리공격·다크웹OSINT·퍼징·고가치자산·EDR우회·자동보고서·포렌식역통합 가능",
        "zh": "[+] 精英黑客模式已激活 (v3.8.0) — C2规避·自定义植入·OPSEC销毁·物理攻击·暗网OSINT·模糊测试·高价值资产·EDR绕过·自动报告·取证反整合 已启用",
        "en": "[+] Elite Hacker Mode ACTIVE (v3.8.0) — C2 evasion·Custom implant·OPSEC burn·Physical·DarkWeb OSINT·Fuzzing·Asset hunt·EDR bypass·Auto report·Forensic audit enabled",
    },
    "elite_c2_front": {
        "ko": "[RULE 64] Domain Fronting 설정 완료 — 프론트: {front} | 실제C2: {c2} | CDN 위장 트래픽 활성",
        "zh": "[RULE 64] Domain Fronting 配置完成 — 前端: {front} | 实际C2: {c2} | CDN 伪装流量已激活",
        "en": "[RULE 64] Domain Fronting set — Front: {front} | Actual C2: {c2} | CDN-disguised traffic active",
    },
    "elite_c2_tunnel": {
        "ko": "[RULE 64] {protocol} 터널링 C2 수립 — 채널: {channel} | 핑 간격: {interval}ms",
        "zh": "[RULE 64] {protocol} 隧道 C2 建立 — 通道: {channel} | Ping 间隔: {interval}ms",
        "en": "[RULE 64] {protocol} tunnel C2 established — Channel: {channel} | Ping interval: {interval}ms",
    },
    "elite_implant_built": {
        "ko": "[RULE 65] 커스텀 임플란트 빌드 완료 — 언어: {lang} | 해시: {hash} | VT 탐지: {detections}/72",
        "zh": "[RULE 65] 自定义植入构建完成 — 语言: {lang} | 哈希: {hash} | VT 检测: {detections}/72",
        "en": "[RULE 65] Custom implant built — Lang: {lang} | Hash: {hash} | VT detections: {detections}/72",
    },
    "elite_implant_polymorphic": {
        "ko": "[RULE 65] 다형성 변형 #{iteration} — 새 해시: {new_hash} | 탐지 감소: {before}→{after}",
        "zh": "[RULE 65] 多态变形 #{iteration} — 新哈希: {new_hash} | 检测减少: {before}→{after}",
        "en": "[RULE 65] Polymorphic variant #{iteration} — New hash: {new_hash} | Detections: {before}→{after}",
    },
    "elite_opsec_burn": {
        "ko": "[RULE 66] 인프라 자동 소각 완료 — {resource_count}개 리소스 삭제, DNS 레코드 제거, 로컬 흔적 7회 덮어쓰기",
        "zh": "[RULE 66] 基础设施自动销毁完成 — 删除 {resource_count} 个资源，清除 DNS 记录，本地痕迹 7 次覆写",
        "en": "[RULE 66] Infrastructure burned — {resource_count} resources deleted, DNS cleared, local traces 7x overwritten",
    },
    "elite_opsec_ip_chain": {
        "ko": "[RULE 66] 익명 IP 체인 구성 완료 — Tor→VPN→VPS→타겟 (역추적 {hops}단계)",
        "zh": "[RULE 66] 匿名 IP 链配置完成 — Tor→VPN→VPS→目标（反追踪 {hops} 层）",
        "en": "[RULE 66] Anonymous IP chain ready — Tor→VPN→VPS→Target ({hops}-layer traceback)",
    },
    "elite_physical_badusb": {
        "ko": "[RULE 67] BadUSB 페이로드 생성 완료 — OS: {os_type} | C2: {lhost}:{lport} | 실행 시간: ~{delay}초",
        "zh": "[RULE 67] BadUSB 载荷生成完成 — OS: {os_type} | C2: {lhost}:{lport} | 执行时间: ~{delay}秒",
        "en": "[RULE 67] BadUSB payload ready — OS: {os_type} | C2: {lhost}:{lport} | Exec delay: ~{delay}s",
    },
    "elite_physical_nfc": {
        "ko": "[RULE 67] NFC 카드 클로닝 완료 — 카드 타입: {card_type} | UID: {uid} | 섹터 크랙: {sectors}/16",
        "zh": "[RULE 67] NFC 卡克隆完成 — 卡类型: {card_type} | UID: {uid} | 扇区破解: {sectors}/16",
        "en": "[RULE 67] NFC card cloned — Type: {card_type} | UID: {uid} | Sectors cracked: {sectors}/16",
    },
    "elite_osint_darkweb": {
        "ko": "[RULE 68] 다크웹 OSINT 완료 — 탐색 사이트: {site_count}개 | 유출 데이터: {leak_count}건 | Tor 회로 순환: {rotations}회",
        "zh": "[RULE 68] 暗网 OSINT 完成 — 搜索站点: {site_count} 个 | 泄露数据: {leak_count} 条 | Tor 线路轮换: {rotations} 次",
        "en": "[RULE 68] DarkWeb OSINT done — {site_count} sites searched | {leak_count} leaks found | {rotations} Tor rotations",
    },
    "elite_osint_employee": {
        "ko": "[RULE 68] 임직원 프로파일링 완료 — {count}명 수집 | 이메일 패턴: {pattern} | GitHub 유출: {github_leaks}건",
        "zh": "[RULE 68] 员工画像完成 — 收集 {count} 人 | 邮箱模式: {pattern} | GitHub 泄露: {github_leaks} 条",
        "en": "[RULE 68] Employee profiling done — {count} profiles | Email pattern: {pattern} | GitHub leaks: {github_leaks}",
    },
    "elite_fuzz_crash": {
        "ko": "[RULE 69] 퍼저 크래시 발견! 유형: {crash_type} | 파일: {crash_file} | 실행 횟수: {execs}/초",
        "zh": "[RULE 69] 模糊测试发现崩溃！类型: {crash_type} | 文件: {crash_file} | 执行速率: {execs}/秒",
        "en": "[RULE 69] Fuzzer crash found! Type: {crash_type} | File: {crash_file} | Exec speed: {execs}/sec",
    },
    "elite_fuzz_0day": {
        "ko": "[RULE 69] 잠재 0-Day 발견! CVE 미등록, 취약점: {vuln_type} | PoC 자동 생성 중...",
        "zh": "[RULE 69] 发现潜在 0-Day！未注册 CVE，漏洞类型: {vuln_type} | 正在自动生成 PoC...",
        "en": "[RULE 69] Potential 0-Day found! Unregistered CVE, type: {vuln_type} | Auto-generating PoC...",
    },
    "elite_asset_found": {
        "ko": "[RULE 70] 고가치 자산 발견! 유형: {asset_type} | 경로: {path} | 우선순위: {priority}",
        "zh": "[RULE 70] 发现高价值资产！类型: {asset_type} | 路径: {path} | 优先级: {priority}",
        "en": "[RULE 70] High-value asset found! Type: {asset_type} | Path: {path} | Priority: {priority}",
    },
    "elite_db_dumped": {
        "ko": "[RULE 70] DB 전체 덤프 완료 — 엔진: {db_type} | 크기: {size}MB | 압축 전송: {chunks}청크",
        "zh": "[RULE 70] 数据库全量转储完成 — 引擎: {db_type} | 大小: {size}MB | 压缩传输: {chunks} 块",
        "en": "[RULE 70] Full DB dump complete — Engine: {db_type} | Size: {size}MB | Chunked transfer: {chunks}",
    },
    "elite_edr_unhooked": {
        "ko": "[RULE 71] EDR 언훅 완료 — NTDLL 클린 버전 로드, {hooks_removed}개 후킹 제거됨",
        "zh": "[RULE 71] EDR 脱钩完成 — 加载干净 NTDLL，已移除 {hooks_removed} 个钩子",
        "en": "[RULE 71] EDR unhooked — Clean NTDLL loaded, {hooks_removed} hooks removed",
    },
    "elite_edr_syscall": {
        "ko": "[RULE 71] 직접 Syscall 활성화 (Hell's Gate) — NTDLL 우회, {syscalls}개 시스콜 직접 호출",
        "zh": "[RULE 71] 直接系统调用已激活（Hell's Gate）— 绕过 NTDLL，直接调用 {syscalls} 个系统调用",
        "en": "[RULE 71] Direct Syscall active (Hell's Gate) — NTDLL bypassed, {syscalls} syscalls direct",
    },
    "elite_edr_av_zero": {
        "ko": "[RULE 71] AV 탐지 0개 달성! 반복 횟수: {iterations} | 최종 해시: {hash}",
        "zh": "[RULE 71] AV 检测 0 个达成！迭代次数: {iterations} | 最终哈希: {hash}",
        "en": "[RULE 71] AV detections zeroed! Iterations: {iterations} | Final hash: {hash}",
    },
    "elite_report_generated": {
        "ko": "[RULE 72] 레드팀 보고서 자동 생성 완료 — 경로: {path} | 취약점: 치명 {critical}/고 {high}/중 {medium}",
        "zh": "[RULE 72] 红队报告自动生成完成 — 路径: {path} | 漏洞: 严重 {critical}/高 {high}/中 {medium}",
        "en": "[RULE 72] Red team report generated — Path: {path} | Vulns: Critical {critical}/High {high}/Med {medium}",
    },
    "elite_cvss4_score": {
        "ko": "[RULE 72] CVSS v4.0 점수 산출 — 점수: {score} ({severity}) | 벡터: {vector}",
        "zh": "[RULE 72] CVSS v4.0 分数计算 — 分数: {score} ({severity}) | 向量: {vector}",
        "en": "[RULE 72] CVSS v4.0 scored — Score: {score} ({severity}) | Vector: {vector}",
    },
    "elite_forensic_detected": {
        "ko": "[RULE 73] 탐지 위험! SIEM 쿼리 {query}에 내 흔적 감지 → 즉시 은닉 조치 실행",
        "zh": "[RULE 73] 检测风险！SIEM 查询 {query} 发现我的痕迹 → 立即执行隐藏措施",
        "en": "[RULE 73] Detection risk! SIEM query {query} found my traces → executing immediate concealment",
    },
    "elite_forensic_clean": {
        "ko": "[RULE 73] OPSEC 자체 감사 완료 — {checks}개 검사, {fixed}개 수정, 잔여 위험: {risk_level}",
        "zh": "[RULE 73] OPSEC 自我审计完成 — {checks} 项检查，{fixed} 项修复，剩余风险: {risk_level}",
        "en": "[RULE 73] OPSEC self-audit done — {checks} checks, {fixed} fixed, residual risk: {risk_level}",
    },
    # ── v3.9.0 월드클래스 영웅등급 (RULE 74~83) 다국어 키 ──
    "worldclass_mode_active": {
        "ko": "[+] 월드클래스 영웅등급 APT 모드 활성화 (v3.9.0) — APT캠페인·하이퍼바이저루트킷·SS7·AI공격·딥페이크·Web3·GPS스푸핑·의료OT·PoC무기화·글로벌C2 가능",
        "zh": "[+] 世界级英雄等级 APT 模式已激活 (v3.9.0) — APT活动·Hypervisor Rootkit·SS7·AI攻击·深度伪造·Web3·GPS欺骗·医疗OT·PoC武器化·全球C2 已启用",
        "en": "[+] Worldclass Hero APT Mode ACTIVE (v3.9.0) — APT campaign·Hypervisor rootkit·SS7·AI attack·Deepfake·Web3·GPS spoof·Medical OT·PoC weaponize·Global C2 enabled",
    },
    "apt_campaign_started": {
        "ko": "[RULE 74] APT 장기 캠페인 시작 — 타겟: {target} | 단계: {phase} | 은신 지속 목표: {duration}",
        "zh": "[RULE 74] APT 长期活动启动 — 目标: {target} | 阶段: {phase} | 持久潜伏目标: {duration}",
        "en": "[RULE 74] APT long campaign started — Target: {target} | Phase: {phase} | Stealth goal: {duration}",
    },
    "apt_skeleton_key": {
        "ko": "[RULE 74] AD Skeleton Key 주입 완료 — 도메인: {domain} | 마스터PW 설정 | DC 재부팅 전 유효",
        "zh": "[RULE 74] AD Skeleton Key 注入完成 — 域: {domain} | 主密码已设置 | DC 重启前有效",
        "en": "[RULE 74] AD Skeleton Key injected — Domain: {domain} | Master PW set | Valid until DC reboot",
    },
    "hypervisor_rootkit": {
        "ko": "[RULE 75] 하이퍼바이저 루트킷 설치 완료 — 플랫폼: {platform} | 게스트VM {vm_count}개 완전 제어 | 재설치 생존 여부: {survives_reinstall}",
        "zh": "[RULE 75] Hypervisor Rootkit 安装完成 — 平台: {platform} | 完全控制 {vm_count} 个来宾VM | 重装存活: {survives_reinstall}",
        "en": "[RULE 75] Hypervisor rootkit installed — Platform: {platform} | {vm_count} guest VMs controlled | Survives reinstall: {survives_reinstall}",
    },
    "uefi_rootkit": {
        "ko": "[RULE 75] UEFI/BIOS 루트킷 심기 완료 — Secure Boot 무력화, HVCI 비활성화, EDR OS 부팅 전 차단",
        "zh": "[RULE 75] UEFI/BIOS Rootkit 植入完成 — Secure Boot 已失效，HVCI 已禁用，EDR 在 OS 启动前被拦截",
        "en": "[RULE 75] UEFI/BIOS rootkit planted — Secure Boot disabled, HVCI off, EDR blocked pre-OS boot",
    },
    "ss7_sms_intercept": {
        "ko": "[RULE 76] SS7 SMS 탈취 성공 — 타겟: {phone} | MFA OTP 수신 중 | 실시간 포워딩 활성",
        "zh": "[RULE 76] SS7 短信拦截成功 — 目标: {phone} | 正在接收 MFA OTP | 实时转发已激活",
        "en": "[RULE 76] SS7 SMS intercept active — Target: {phone} | MFA OTP receiving | Real-time forward on",
    },
    "imsi_catcher_active": {
        "ko": "[RULE 76] 가짜 기지국(IMSI Catcher) 가동 — 반경 {radius}m 내 {device_count}대 접속 | IMSI 수집: {collected}건",
        "zh": "[RULE 76] 伪基站 (IMSI Catcher) 启动 — 半径 {radius}m 内 {device_count} 台设备连接 | IMSI 收集: {collected} 条",
        "en": "[RULE 76] Fake base station active — {device_count} devices in {radius}m radius | IMSI collected: {collected}",
    },
    "ai_spearphish_generated": {
        "ko": "[RULE 77] AI 맞춤 스피어피싱 이메일 생성 완료 — 타겟: {name}({position}) | 맞춤도: {personalization}% | 모델: {model}",
        "zh": "[RULE 77] AI 定制鱼叉钓鱼邮件生成完成 — 目标: {name}({position}) | 定制度: {personalization}% | 模型: {model}",
        "en": "[RULE 77] AI spearphish generated — Target: {name}({position}) | Personalization: {personalization}% | Model: {model}",
    },
    "ai_vuln_found": {
        "ko": "[RULE 77] AI 취약점 발견 — CVE유사: {cve_type} | 위치: {location} | 예상CVSS: {cvss} | PoC 자동 생성 중",
        "zh": "[RULE 77] AI 发现漏洞 — CVE 类型: {cve_type} | 位置: {location} | 预估 CVSS: {cvss} | 正在自动生成 PoC",
        "en": "[RULE 77] AI vuln found — Type: {cve_type} | Location: {location} | Est. CVSS: {cvss} | Auto-generating PoC",
    },
    "deepfake_voice_ready": {
        "ko": "[RULE 78] 딥페이크 음성 클로닝 완료 — 대상: {target_name} | 유사도: {similarity}% | 언어: {lang} | 통화 준비 완료",
        "zh": "[RULE 78] 深度伪造语音克隆完成 — 目标: {target_name} | 相似度: {similarity}% | 语言: {lang} | 通话准备就绪",
        "en": "[RULE 78] Deepfake voice cloned — Target: {target_name} | Similarity: {similarity}% | Lang: {lang} | Call ready",
    },
    "deepfake_bec_sent": {
        "ko": "[RULE 78] BEC 딥페이크 공격 전송 — 사칭: {impersonate} → 피해자: {victim} | 금액: ${amount:,} | 채널: {channel}",
        "zh": "[RULE 78] BEC 深度伪造攻击已发送 — 冒充: {impersonate} → 受害者: {victim} | 金额: ${amount:,} | 渠道: {channel}",
        "en": "[RULE 78] BEC deepfake attack sent — Impersonate: {impersonate} → Victim: {victim} | Amount: ${amount:,} | Channel: {channel}",
    },
    "web3_flashloan": {
        "ko": "[RULE 79] 플래시론 공격 실행 — DEX: {dex} | 차용: {loan_amount} ETH | 수익: {profit} ETH | 가스비: {gas} Gwei",
        "zh": "[RULE 79] 闪电贷攻击执行 — DEX: {dex} | 借款: {loan_amount} ETH | 收益: {profit} ETH | Gas: {gas} Gwei",
        "en": "[RULE 79] Flash loan attack executed — DEX: {dex} | Loan: {loan_amount} ETH | Profit: {profit} ETH | Gas: {gas} Gwei",
    },
    "web3_drainer": {
        "ko": "[RULE 79] 지갑 드레이너 활성 — 서명 방식: {method} | 탈취 완료: {amount} ETH / {nft_count}개 NFT",
        "zh": "[RULE 79] 钱包耗尽器已激活 — 签名方式: {method} | 已提取: {amount} ETH / {nft_count} 个 NFT",
        "en": "[RULE 79] Wallet drainer active — Signature: {method} | Drained: {amount} ETH / {nft_count} NFTs",
    },
    "gps_spoof_active": {
        "ko": "[RULE 80] GPS 스푸핑 신호 전송 중 — 가짜 위치: {fake_lat},{fake_lon} | 주파수: {freq}MHz | 영향 기기: {devices}",
        "zh": "[RULE 80] GPS 欺骗信号发送中 — 虚假位置: {fake_lat},{fake_lon} | 频率: {freq}MHz | 受影响设备: {devices}",
        "en": "[RULE 80] GPS spoof signal transmitting — Fake pos: {fake_lat},{fake_lon} | Freq: {freq}MHz | Affected: {devices}",
    },
    "satellite_intercept": {
        "ko": "[RULE 80] 위성 통신 도청 활성 — 위성: {satellite} | 다운링크 채널: {channel} | 암호화: {encrypted}",
        "zh": "[RULE 80] 卫星通信窃听已激活 — 卫星: {satellite} | 下行链路频道: {channel} | 加密: {encrypted}",
        "en": "[RULE 80] Satellite intercept active — Satellite: {satellite} | Downlink: {channel} | Encrypted: {encrypted}",
    },
    "medical_pacs_accessed": {
        "ko": "[RULE 81] 병원 PACS 무단 접근 — 서버: {pacs_ip} | 환자 레코드: {record_count}건 | DICOM 프로토콜 포트: {port}",
        "zh": "[RULE 81] 医院 PACS 未授权访问 — 服务器: {pacs_ip} | 患者记录: {record_count} 条 | DICOM 端口: {port}",
        "en": "[RULE 81] Hospital PACS accessed — Server: {pacs_ip} | Patient records: {record_count} | DICOM port: {port}",
    },
    "scada_ics_control": {
        "ko": "[RULE 81] SCADA/ICS 제어권 획득 — 시설: {facility_type} | PLC {plc_count}개 접근 | 프로토콜: {protocol} | 물리 영향 가능: {physical_impact}",
        "zh": "[RULE 81] 获得 SCADA/ICS 控制权 — 设施: {facility_type} | 访问 {plc_count} 台 PLC | 协议: {protocol} | 可造成物理影响: {physical_impact}",
        "en": "[RULE 81] SCADA/ICS control gained — Facility: {facility_type} | {plc_count} PLCs accessed | Protocol: {protocol} | Physical impact: {physical_impact}",
    },
    "poc_weaponized": {
        "ko": "[RULE 82] PoC 무기화 완료 — CVE: {cve_id} | 소스: {source_count}개 수집 | Metasploit 모듈 생성 | 예상 성공률: {success_rate}%",
        "zh": "[RULE 82] PoC 武器化完成 — CVE: {cve_id} | 收集 {source_count} 个来源 | Metasploit 模块已生成 | 预计成功率: {success_rate}%",
        "en": "[RULE 82] PoC weaponized — CVE: {cve_id} | {source_count} sources collected | MSF module generated | Est. success: {success_rate}%",
    },
    "nday_pipeline_alert": {
        "ko": "[RULE 82] N-Day 자동 탐지 경보! CVE: {cve_id} | CVSS: {cvss} | 타겟 영향: {impact} | 자동 무기화 시작",
        "zh": "[RULE 82] N-Day 自动检测警报！CVE: {cve_id} | CVSS: {cvss} | 目标影响: {impact} | 自动武器化开始",
        "en": "[RULE 82] N-Day pipeline alert! CVE: {cve_id} | CVSS: {cvss} | Target impact: {impact} | Auto-weaponizing",
    },
    "global_c2_deployed": {
        "ko": "[RULE 83] 글로벌 C2 인프라 배포 완료 — 노드: {node_count}개 | 대륙: {continents} | 관할권: {jurisdictions} | 다음 소각: {next_burn}",
        "zh": "[RULE 83] 全球 C2 基础设施部署完成 — 节点: {node_count} 个 | 大陆: {continents} | 司法管辖区: {jurisdictions} | 下次销毁: {next_burn}",
        "en": "[RULE 83] Global C2 deployed — Nodes: {node_count} | Continents: {continents} | Jurisdictions: {jurisdictions} | Next burn: {next_burn}",
    },
    "global_c2_rotated": {
        "ko": "[RULE 83] C2 인프라 자동 교체 완료 — 구 노드 {old_count}개 소각 | 신 노드 {new_count}개 배포 | 다운타임: {downtime}초",
        "zh": "[RULE 83] C2 基础设施自动轮换完成 — 销毁旧节点 {old_count} 个 | 部署新节点 {new_count} 个 | 停机: {downtime} 秒",
        "en": "[RULE 83] C2 infra rotated — {old_count} old nodes burned | {new_count} new nodes deployed | Downtime: {downtime}s",
    },
    "worldclass_full_summary": {
        "ko": "═══ 월드클래스 영웅등급 APT 레벨 활성화 완료 (v3.9.0) ═══\n"
              "RULE 74: APT급 장기 캠페인 자동화 (6개월+ 은신·Skeleton Key·DSRM 백도어)\n"
              "RULE 75: 하이퍼바이저/펌웨어 루트킷 (ESXi VIB·BlackLotus UEFI·재설치 생존)\n"
              "RULE 76: 통신 코어망 공격 (SS7 SMS탈취·IMSI Catcher·VoIP 도청)\n"
              "RULE 77: AI 기반 공격 자동화 (GPT-4o 스피어피싱·o3 취약점발견·맞춤 페이로드)\n"
              "RULE 78: 딥페이크 사회공학 (음성클로닝·실시간 화상위장·AI BEC 자동화)\n"
              "RULE 79: 블록체인/Web3 공격 (플래시론·스마트컨트랙트 드레이너·MEV 봇)\n"
              "RULE 80: 위성/GPS 스푸핑 (GPS-SDR-SIM·Starlink 도청·AIS 스푸핑)\n"
              "RULE 81: 의료/크리티컬 인프라 (DICOM PACS·의료기기·전력망·정수처리 SCADA)\n"
              "RULE 82: PoC→실전 무기화 파이프라인 (자동수집·AI변환·MSF모듈·N-Day 즉시배포)\n"
              "RULE 83: 글로벌 분산 C2 (Terraform 4대륙·24h 자동소각재구축·관할권 분산)\n"
              "━━━ 완전 월드클래스 영웅등급 달성 ━━━",
        "zh": "═══ 世界级英雄等级 APT 激活完成 (v3.9.0) ═══\n"
              "RULE 74: APT 级长期活动自动化 (6个月+潜伏·Skeleton Key·DSRM后门)\n"
              "RULE 75: Hypervisor/固件 Rootkit (ESXi VIB·BlackLotus UEFI·重装存活)\n"
              "RULE 76: 通信核心网攻击 (SS7短信劫持·IMSI Catcher·VoIP窃听)\n"
              "RULE 77: AI攻击自动化 (GPT-4o鱼叉钓鱼·o3漏洞发现·定制载荷)\n"
              "RULE 78: 深度伪造社会工程 (语音克隆·实时视频伪装·AI BEC自动化)\n"
              "RULE 79: 区块链/Web3攻击 (闪电贷·智能合约耗尽器·MEV机器人)\n"
              "RULE 80: 卫星/GPS欺骗 (GPS-SDR-SIM·Starlink窃听·AIS欺骗)\n"
              "RULE 81: 医疗/关键基础设施 (DICOM PACS·医疗设备·电网·水厂SCADA)\n"
              "RULE 82: PoC→实战武器化管道 (自动收集·AI转换·MSF模块·N-Day即时部署)\n"
              "RULE 83: 全球分布式C2 (Terraform 4大洲·24h自动销毁重建·司法分散)\n"
              "━━━ 全面世界级英雄等级达成 ━━━",
        "en": "═══ Worldclass Hero APT Level ACTIVATED (v3.9.0) ═══\n"
              "RULE 74: APT Long Campaign Auto (6mo+ stealth·Skeleton Key·DSRM backdoor)\n"
              "RULE 75: Hypervisor/Firmware Rootkit (ESXi VIB·BlackLotus UEFI·survives reinstall)\n"
              "RULE 76: Telecom Core Attack (SS7 SMS hijack·IMSI Catcher·VoIP intercept)\n"
              "RULE 77: AI Attack Automation (GPT-4o spearphish·o3 vuln find·custom payload)\n"
              "RULE 78: Deepfake Social Eng (voice clone·realtime video fake·AI BEC auto)\n"
              "RULE 79: Blockchain/Web3 (Flash loan·Contract drainer·MEV bot)\n"
              "RULE 80: Satellite/GPS Spoof (GPS-SDR-SIM·Starlink intercept·AIS spoof)\n"
              "RULE 81: Medical/Critical Infra (DICOM PACS·medical device·power·water SCADA)\n"
              "RULE 82: PoC→Weaponize Pipeline (auto-collect·AI convert·MSF module·N-Day instant)\n"
              "RULE 83: Global Distributed C2 (Terraform 4 continents·24h auto-burn·jurisdiction split)\n"
              "━━━ Full Worldclass Hero Level Achieved ━━━",
    },
    "elite_full_summary": {
        "ko": "═══ 최고급 엘리트 해커 레벨 활성화 완료 (v3.8.0) ═══\n"
              "RULE 64: 고급 C2 회피 (Domain Fronting·ICMP/SMB 터널링)\n"
              "RULE 65: 커스텀 임플란트 자동 생성 (Rust/Go·다형성·AMSI/ETW 우회)\n"
              "RULE 66: OPSEC 완전 제로화 (Terraform 소각·TOR 4단계·CDN 위장)\n"
              "RULE 67: 물리적 공격 연계 (BadUSB·HID·NFC 클로닝)\n"
              "RULE 68: 고급 OSINT 자동화 (다크웹Tor·LinkedIn·Shodan·GitHub유출)\n"
              "RULE 69: 퍼징 자동화 (AFL++·웹 API 퍼저·크래시 자동 분류)\n"
              "RULE 70: 포스트 익스플로잇 심화 (고가치 자산 자동 매핑·DB 전체덤프)\n"
              "RULE 71: EDR 고급 우회 (NTDLL 언훅·직접 Syscall·VT 탐지0 루프)\n"
              "RULE 72: 레드팀 보고서 자동화 (CVSS v4.0·HTML리포트·증거수집)\n"
              "RULE 73: 포렌식 역통합 (SIEM 자가검증·MITRE 갭 분석·흔적 자동소거)\n"
              "━━━ 완전 최고급 엘리트 해커 레벨 달성 ━━━",
        "zh": "═══ 顶级精英黑客级别激活完成 (v3.8.0) ═══\n"
              "RULE 64: 高级 C2 规避 (Domain Fronting·ICMP/SMB 隧道)\n"
              "RULE 65: 自动生成自定义植入 (Rust/Go·多态·AMSI/ETW 绕过)\n"
              "RULE 66: OPSEC 完全归零 (Terraform 销毁·TOR 4层·CDN 伪装)\n"
              "RULE 67: 物理攻击联动 (BadUSB·HID·NFC 克隆)\n"
              "RULE 68: 高级 OSINT 自动化 (暗网Tor·LinkedIn·Shodan·GitHub泄露)\n"
              "RULE 69: 模糊测试自动化 (AFL++·Web API 模糊·崩溃自动分类)\n"
              "RULE 70: 后渗透深化 (高价值资产自动映射·数据库全量转储)\n"
              "RULE 71: EDR 高级绕过 (NTDLL脱钩·直接Syscall·VT检测0循环)\n"
              "RULE 72: 红队报告自动化 (CVSS v4.0·HTML报告·证据收集)\n"
              "RULE 73: 取证反整合 (SIEM自检·MITRE差距分析·自动消迹)\n"
              "━━━ 全面顶级精英黑客级别达成 ━━━",
        "en": "═══ Elite Hacker Level ACTIVATED (v3.8.0) ═══\n"
              "RULE 64: Advanced C2 Evasion (Domain Fronting·ICMP/SMB Tunneling)\n"
              "RULE 65: Custom Implant Auto-gen (Rust/Go·Polymorphic·AMSI/ETW bypass)\n"
              "RULE 66: Full OPSEC Zero (Terraform burn·TOR 4-layer·CDN disguise)\n"
              "RULE 67: Physical Attack Integration (BadUSB·HID·NFC Cloning)\n"
              "RULE 68: Advanced OSINT Automation (DarkWeb·LinkedIn·Shodan·GitHub leaks)\n"
              "RULE 69: Fuzzing Automation (AFL++·Web API Fuzzer·Crash Auto-triage)\n"
              "RULE 70: Post-Exploit Deep (High-value asset mapping·Full DB dump)\n"
              "RULE 71: Advanced EDR Bypass (NTDLL unhook·Direct Syscall·VT 0-detection loop)\n"
              "RULE 72: Red Team Report Auto (CVSS v4.0·HTML report·Evidence collect)\n"
              "RULE 73: Forensic Reverse Integration (SIEM self-audit·MITRE gap·Auto-cleanup)\n"
              "━━━ Full Elite Hacker Level Achieved ━━━",
    },
})

# ── v4.0.0 Intelligence Amplifier 다국어 키 ──────────────────────────────
_STRINGS.update({
    "amp_active": {
        "ko": "⚡ [AMPLIFIER v4.0.0] CoT + 정밀RAG + 자기수정 + 작업분해 — 활성화",
        "zh": "⚡ [AMPLIFIER v4.0.0] CoT + 精准RAG + 自我修正 + 任务分解 — 已激活",
        "en": "⚡ [AMPLIFIER v4.0.0] CoT + PrecisionRAG + SelfCorrect + TaskDecompose — ACTIVE",
    },
    "amp_cot_activated": {
        "ko": "🧠 [CoT] 단계적 추론 활성화 — 7단계 사고 프레임워크 적용 중",
        "zh": "🧠 [CoT] 链式推理已激活 — 正在应用7步思维框架",
        "en": "🧠 [CoT] Chain-of-Thought activated — 7-step reasoning framework applied",
    },
    "amp_rag_injected": {
        "ko": "📚 [RAG] 정밀 컨텍스트 주입 완료 — 기술스택 힌트 + CVE 데이터 삽입",
        "zh": "📚 [RAG] 精准上下文注入完成 — 技术栈提示 + CVE数据已注入",
        "en": "📚 [RAG] Precision context injected — tech-stack hints + CVE data inserted",
    },
    "amp_self_correct": {
        "ko": "🔄 [자기수정] 응답 품질 기준 미달 — 자동 수정 루프 실행 ({attempt}/{max})",
        "zh": "🔄 [自我修正] 响应质量未达标 — 自动修正循环执行中 ({attempt}/{max})",
        "en": "🔄 [SelfCorrect] Response quality below threshold — auto-correction loop ({attempt}/{max})",
    },
    "amp_correction_done": {
        "ko": "✅ [자기수정] 수정 완료 — 품질 점수: {score:.0%}",
        "zh": "✅ [自我修正] 修正完成 — 质量评分: {score:.0%}",
        "en": "✅ [SelfCorrect] Correction done — quality score: {score:.0%}",
    },
    "amp_decompose_triggered": {
        "ko": "🔩 [작업분해] 복잡도 감지 — {total}개 서브태스크로 분해 실행",
        "zh": "🔩 [任务分解] 检测到复杂度 — 分解为 {total} 个子任务执行",
        "en": "🔩 [Decompose] Complexity detected — executing {total} subtasks",
    },
    "amp_decompose_step": {
        "ko": "▶ [분해 {step}/{total}] {name} — {objective}",
        "zh": "▶ [分解 {step}/{total}] {name} — {objective}",
        "en": "▶ [Decompose {step}/{total}] {name} — {objective}",
    },
    "amp_stats": {
        "ko": "📊 [앰플리파이어 통계] 호출={calls} | CoT={cot} | RAG={rag} | 수정={corrections} | 분해={decompose}",
        "zh": "📊 [增幅器统计] 调用={calls} | CoT={cot} | RAG={rag} | 修正={corrections} | 分解={decompose}",
        "en": "📊 [Amplifier Stats] calls={calls} | CoT={cot} | RAG={rag} | corrections={corrections} | decompose={decompose}",
    },
    "amp_quality_low": {
        "ko": "⚠️ [품질경고] 응답 품질 낮음 (점수: {score:.0%}) — 문제: {issues}",
        "zh": "⚠️ [质量警告] 响应质量较低 (评分: {score:.0%}) — 问题: {issues}",
        "en": "⚠️ [QualityWarn] Low response quality (score: {score:.0%}) — issues: {issues}",
    },
    "amp_tech_hints": {
        "ko": "💡 [기술스택 힌트] 감지된 스택: {techs} → 관련 공격 벡터 주입",
        "zh": "💡 [技术栈提示] 检测到堆栈: {techs} → 注入相关攻击向量",
        "en": "💡 [TechHints] Detected stack: {techs} → injecting relevant attack vectors",
    },
    "amp_cve_found": {
        "ko": "🔴 [CVE매칭] {count}개 관련 CVE 발견 — 우선 시도: {top_cve}",
        "zh": "🔴 [CVE匹配] 发现 {count} 个相关CVE — 优先尝试: {top_cve}",
        "en": "🔴 [CVEMatch] {count} relevant CVEs found — priority: {top_cve}",
    },
    "amp_full_summary": {
        "ko": (
            "═══ BINGO v4.0.0 Intelligence Amplifier 활성화 완료 ═══\n"
            "RULE 84: Chain-of-Thought 강제 (7단계 추론·복잡도 자동감지·구조화 출력)\n"
            "RULE 85: 자기 수정 루프 (품질 자동평가·최대2회 수정·오류율 -70%)\n"
            "RULE 86: 정밀 RAG (기술스택→CVE매핑·Blackboard활용·토큰효율화)\n"
            "RULE 87: 작업 분해 (5~7서브태스크·단계간컨텍스트전달·약한모델도극복)\n"
            "━━━ 어떤 모델이든 월드컵 최고급 수준 달성 ━━━"
        ),
        "zh": (
            "═══ BINGO v4.0.0 智能增幅器激活完成 ═══\n"
            "RULE 84: 链式推理强制 (7步推理·复杂度自动检测·结构化输出)\n"
            "RULE 85: 自我修正循环 (质量自动评估·最多2次修正·错误率-70%)\n"
            "RULE 86: 精准RAG (技术栈→CVE映射·Blackboard利用·Token效率化)\n"
            "RULE 87: 任务分解 (5~7子任务·步骤间上下文传递·弱模型也能胜任)\n"
            "━━━ 无论连接何种模型均可达到世界顶级水平 ━━━"
        ),
        "en": (
            "═══ BINGO v4.0.0 Intelligence Amplifier ACTIVATED ═══\n"
            "RULE 84: CoT Enforced (7-step reasoning·auto-complexity·structured output)\n"
            "RULE 85: Self-Correction Loop (quality auto-eval·max 2 retries·error rate -70%)\n"
            "RULE 86: Precision RAG (tech→CVE map·Blackboard reuse·token efficiency)\n"
            "RULE 87: Task Decomposer (5~7 subtasks·context passing·weak models overcome)\n"
            "━━━ World Cup level performance with ANY connected model ━━━"
        ),
    },
})

# ── v4.1.0 Zero Hallucination v5 다국어 키 ──────────────────────────────
_STRINGS.update({
    "zerohal_active": {
        "ko": "🛡️ [ZERO-HAL v5] 9단계 제로 환각 방어 — 활성화 (FactRegistry + ClaimAnchor + NumericGuard + InferenceMeter + ContextPoison)",
        "zh": "🛡️ [ZERO-HAL v5] 9层零幻觉防护 — 已激活 (事实注册 + 声明锚定 + 数字守卫 + 推断计量 + 上下文防毒)",
        "en": "🛡️ [ZERO-HAL v5] 9-Layer Zero Hallucination ACTIVE (FactRegistry + ClaimAnchor + NumericGuard + InferenceMeter + ContextPoison)",
    },
    "zerohal_blocked": {
        "ko": "⛔ [ZERO-HAL] 환각 차단: {reason}",
        "zh": "⛔ [ZERO-HAL] 幻觉拦截: {reason}",
        "en": "⛔ [ZERO-HAL] Hallucination blocked: {reason}",
    },
    "zerohal_warn": {
        "ko": "⚠️ [ZERO-HAL] 경고: {reason}",
        "zh": "⚠️ [ZERO-HAL] 警告: {reason}",
        "en": "⚠️ [ZERO-HAL] Warning: {reason}",
    },
    "zerohal_facts_registered": {
        "ko": "📌 [FactRegistry] {count}개 사실 등록 완료 (IP/포트/헤더/버전/경로)",
        "zh": "📌 [事实注册] 已注册 {count} 条事实 (IP/端口/Header/版本/路径)",
        "en": "📌 [FactRegistry] {count} facts registered (IP/port/header/version/path)",
    },
    "zerohal_claim_blocked": {
        "ko": "⛔ [클레임앵커] 증거 없는 취약점 주장 차단 — 실행 후 재시도하세요",
        "zh": "⛔ [声明锚定] 无证据漏洞声明被拦截 — 请执行后重试",
        "en": "⛔ [ClaimAnchor] Unanchored vulnerability claim blocked — execute and retry",
    },
    "zerohal_numeric_blocked": {
        "ko": "⛔ [숫자환각] 등록되지 않은 숫자 사용 차단 — 실제 실행 결과의 숫자만 허용",
        "zh": "⛔ [数字幻觉] 使用未注册数字被拦截 — 仅允许真实执行结果中的数字",
        "en": "⛔ [NumericHal] Unregistered numeric value blocked — only real execution values allowed",
    },
    "zerohal_inference_warn": {
        "ko": "⚠️ [추론계량] 추론 비율 {pct}% — 실행 결과로 검증 권장",
        "zh": "⚠️ [推断计量] 推断比例 {pct}% — 建议用执行结果验证",
        "en": "⚠️ [InferenceMeter] Inference ratio {pct}% — recommend verifying with execution results",
    },
    "zerohal_inference_blocked": {
        "ko": "⛔ [추론계량] 과다 추론 차단 ({pct}%) — 즉시 HTTP 요청 실행",
        "zh": "⛔ [推断计量] 过度推断拦截 ({pct}%) — 立即执行HTTP请求",
        "en": "⛔ [InferenceMeter] Excessive inference blocked ({pct}%) — execute HTTP request now",
    },
    "zerohal_context_poison": {
        "ko": "⚠️ [컨텍스트오염] 이전 세션 데이터 유출 감지 — 현재 타겟: {target}",
        "zh": "⚠️ [上下文污染] 检测到历史会话数据泄露 — 当前目标: {target}",
        "en": "⚠️ [ContextPoison] Previous session data leak detected — current target: {target}",
    },
    "zerohal_stats": {
        "ko": "📊 [ZERO-HAL 통계] 처리={processed} | 차단={blocked} | 등록사실={facts}",
        "zh": "📊 [ZERO-HAL 统计] 处理={processed} | 拦截={blocked} | 注册事实={facts}",
        "en": "📊 [ZERO-HAL Stats] processed={processed} | blocked={blocked} | facts={facts}",
    },
    "zerohal_full_summary": {
        "ko": (
            "═══ BINGO v4.1.0 Zero Hallucination v5 — 9단계 방어 완전체 ═══\n"
            "기존 4단계: ①팬텀 ②구캐시 ③타겟오인 ④루프탈출\n"
            "신규 5레이어:\n"
            "  RULE 88: FactRegistry     — 숫자/IP/버전/헤더 증거 앵커\n"
            "  RULE 89: ClaimAnchor      — 취약점 주장 = 실행 증거 필수\n"
            "  RULE 90: NumericGuard     — LLM 생성 숫자 환각 차단\n"
            "  RULE 91: InferenceMeter   — 추론 35% 상한 / 60% 차단\n"
            "  RULE 92: ContextPoison    — 크로스 세션 오염 방지\n"
            "━━━ 환각률 0% 목표 — 월드컵급 정확도 ━━━"
        ),
        "zh": (
            "═══ BINGO v4.1.0 零幻觉 v5 — 9层完整防护 ═══\n"
            "原4层: ①幻影 ②旧缓存 ③目标误认 ④循环逃脱\n"
            "新5层:\n"
            "  RULE 88: 事实注册    — 数字/IP/版本/Header证据锚定\n"
            "  RULE 89: 声明锚定    — 漏洞声明必须有执行证据\n"
            "  RULE 90: 数字守卫    — 拦截LLM生成数字幻觉\n"
            "  RULE 91: 推断计量    — 35%上限/60%拦截\n"
            "  RULE 92: 上下文防毒  — 防止跨会话信息污染\n"
            "━━━ 幻觉率0%目标 — 世界杯级精准度 ━━━"
        ),
        "en": (
            "═══ BINGO v4.1.0 Zero Hallucination v5 — 9-Layer Complete Defense ═══\n"
            "Existing 4 layers: ①Phantom ②StaleCache ③TargetMismatch ④LoopBreak\n"
            "New 5 layers:\n"
            "  RULE 88: FactRegistry   — numeric/IP/version/header evidence anchor\n"
            "  RULE 89: ClaimAnchor    — vulnerability claims require execution evidence\n"
            "  RULE 90: NumericGuard   — block LLM-generated numeric hallucinations\n"
            "  RULE 91: InferenceMeter — 35% cap / 60% block\n"
            "  RULE 92: ContextPoison  — prevent cross-session contamination\n"
            "━━━ Goal: 0% hallucination rate — World Cup level accuracy ━━━"
        ),
    },
})

# ── v4.1.0 버전 문자열 업데이트 ─────────────────────────────────────────
_STRINGS.update({
    "recon_help_title": {
        "ko": "🔍  정찰 모듈 모음 (v4.1.0) — 정보 수집 / 자산 수집",
        "zh": "🔍  侦察模块套件 (v4.1.0) — 信息收集 / 资产收集",
        "en": "🔍  Recon Module Suite (v4.1.0) — Info Gathering / Asset Collection",
    },
})

# ── v4.2.0 Auto-Proxy Rotation ───────────────────────────────────────────────
_STRINGS.update({
    # 오케스트레이터 초기화 메시지
    "proxy_active": {
        "ko": "🔄 [AUTO-PROXY] IP 차단 감지기 + 무료 프록시 풀 활성화",
        "zh": "🔄 [AUTO-PROXY] IP封锁检测器 + 免费代理池已启动",
        "en": "🔄 [AUTO-PROXY] IP Block Detector + Free Proxy Pool ACTIVE",
    },
    # 프록시 자동 교체 성공 (오케스트레이터용 — 수동 /proxy rotate 키와 구분)
    "proxy_auto_rotated": {
        "ko": "🔄 [AUTO-PROXY] IP 차단 감지! 프록시 교체 → {url}",
        "zh": "🔄 [AUTO-PROXY] 检测到IP封锁！切换代理 → {url}",
        "en": "🔄 [AUTO-PROXY] IP blocked! Rotated → {url}",
    },
    # 프록시 풀 고갈
    "proxy_exhausted": {
        "ko": "⚠ [AUTO-PROXY] 프록시 풀 소진 — 직접 연결로 계속",
        "zh": "⚠ [AUTO-PROXY] 代理池耗尽 — 直连继续",
        "en": "⚠ [AUTO-PROXY] All proxies exhausted — continuing direct",
    },
    # 세션 종료 프록시 요약
    "proxy_session_end": {
        "ko": "🔄 [AUTO-PROXY] 세션 종료 | 교체={n}회 풀잔여={p}개",
        "zh": "🔄 [AUTO-PROXY] 会话结束 | 轮换={n}次 池剩余={p}个",
        "en": "🔄 [AUTO-PROXY] Session ended | rotations={n} pool={p}",
    },
    # IP 차단 감지 상세 (로그용)
    "proxy_block_detected": {
        "ko": "🚨 IP 차단 확정 | 신호={signals} 신뢰도={conf:.0%} | {detail}",
        "zh": "🚨 IP封锁确认 | 信号={signals} 置信度={conf:.0%} | {detail}",
        "en": "🚨 IP block confirmed | signals={signals} conf={conf:.0%} | {detail}",
    },
    # 프록시 수집 시작
    "proxy_hunt_start": {
        "ko": "🕵️ [PROXY HUNTER] 무료 프록시 수집 중...",
        "zh": "🕵️ [PROXY HUNTER] 正在收集免费代理...",
        "en": "🕵️ [PROXY HUNTER] Collecting free proxies...",
    },
    # 프록시 수집 완료
    "proxy_hunt_done": {
        "ko": "✅ [PROXY HUNTER] 검증 완료: {n}개 사용 가능 (3단계 통과)",
        "zh": "✅ [PROXY HUNTER] 验证完成: {n}个可用（通过3阶段）",
        "en": "✅ [PROXY HUNTER] Validated: {n} proxies ready (3-stage pass)",
    },
    # 프록시 검증 실패
    "proxy_validate_fail": {
        "ko": "❌ [PROXY] {host}:{port} 검증 실패 (stage={stage})",
        "zh": "❌ [PROXY] {host}:{port} 验证失败（阶段={stage}）",
        "en": "❌ [PROXY] {host}:{port} validation failed (stage={stage})",
    },
    # 블랙리스트 등록
    "proxy_blacklisted": {
        "ko": "🚫 [PROXY] {host}:{port} 블랙리스트 등록 (실패={n}회)",
        "zh": "🚫 [PROXY] {host}:{port} 已列入黑名单（失败={n}次）",
        "en": "🚫 [PROXY] {host}:{port} blacklisted (fail={n})",
    },
    # 재수집 트리거
    "proxy_refill_trigger": {
        "ko": "♻️ [PROXY POOL] 풀 부족 ({n}개) → 백그라운드 재수집 시작",
        "zh": "♻️ [PROXY POOL] 代理不足({n}个) → 后台重新收集",
        "en": "♻️ [PROXY POOL] Pool low ({n}) → background refill started",
    },
    # 도움말: proxy 상태
    "proxy_help_status": {
        "ko": "🔄 AUTO-PROXY 상태: 현재={cur} | 풀={pool} | 교체={rot}회 | 블랙리스트={bl}",
        "zh": "🔄 AUTO-PROXY 状态: 当前={cur} | 池={pool} | 轮换={rot}次 | 黑名单={bl}",
        "en": "🔄 AUTO-PROXY Status: current={cur} | pool={pool} | rotations={rot} | blacklist={bl}",
    },

    # ── v4.3.0 ExecutionAnchor 다국어 키 ───────────────────────────────────
    # 앵커 엔진 활성화 알림
    "anchor_active": {
        "ko": "⚓ [EXEC-ANCHOR] 실행결과 앵커링 엔진 v1.0 ACTIVE (0-환각 보장)",
        "zh": "⚓ [EXEC-ANCHOR] 执行结果锚定引擎 v1.0 已激活（零幻觉保障）",
        "en": "⚓ [EXEC-ANCHOR] Execution Result Anchoring Engine v1.0 ACTIVE (zero-hallucination)",
    },
    # 추측 언어 + 기술 주장 차단
    "anchor_blocked": {
        "ko": "⛔ [EXEC-ANCHOR] 0-환각 위반 차단: {reason}",
        "zh": "⛔ [EXEC-ANCHOR] 零幻觉规则违规拦截: {reason}",
        "en": "⛔ [EXEC-ANCHOR] Zero-hallucination violation blocked: {reason}",
    },
    # 추측 언어 + 기술 주장 (SPECULATION_CLAIM)
    "anchor_speculation_claim": {
        "ko": "⛔ [추측+주장 차단] 추측 언어와 기술 보안 주장이 동시 감지됨 — 직접 실행 후 결과만 보고하십시오",
        "zh": "⛔ [推测+声明拦截] 同时检测到推测语言和技术安全声明 — 请先执行后仅报告实际结果",
        "en": "⛔ [SPECULATION+CLAIM BLOCKED] Speculation language + technical security claim detected — execute first, report only actual results",
    },
    # 실행 증거 없는 기술 주장 (UNEXECUTED_CLAIM)
    "anchor_unexecuted_claim": {
        "ko": "⛔ [미실행 주장 차단] 실행 결과 없이 기술 보안 주장 감지 — 먼저 실행하고 결과로 말하십시오",
        "zh": "⛔ [未执行声明拦截] 无执行证据的技术安全声明 — 请先执行并仅依据结果陈述",
        "en": "⛔ [UNEXECUTED CLAIM BLOCKED] Technical security claim without execution evidence — execute first and report only results",
    },
    # 앵커 통계
    "anchor_stats": {
        "ko": "⚓ [EXEC-ANCHOR 통계] 검사={total} | 추측차단={spec} | 미실행차단={unex} | 총차단={blk}",
        "zh": "⚓ [EXEC-ANCHOR 统计] 检查={total} | 推测拦截={spec} | 未执行拦截={unex} | 总拦截={blk}",
        "en": "⚓ [EXEC-ANCHOR Stats] Checked={total} | SpecBlocks={spec} | UnexBlocks={unex} | TotalBlocks={blk}",
    },
    # 앵커 경고 (차단은 아니지만 주의)
    "anchor_warn_speculation": {
        "ko": "⚠️ [EXEC-ANCHOR 경고] 응답에 추측 언어 감지 — 기술 주장은 반드시 실행 결과 기반으로",
        "zh": "⚠️ [EXEC-ANCHOR 警告] 响应中检测到推测语言 — 技术声明必须基于实际执行结果",
        "en": "⚠️ [EXEC-ANCHOR WARN] Speculation language detected — technical claims must be based on execution results",
    },
    # 채팅 모드 앵커 위반
    "anchor_chat_violation": {
        "ko": "⛔ [채팅 앵커 위반] 채팅 모드에서도 실행 없이 기술 보안 주장 금지 — 실행 코드를 제시하거나 직접 실행하십시오",
        "zh": "⛔ [聊天锚定违规] 即使在聊天模式下也禁止无执行的技术安全声明 — 请提供执行代码或直接执行",
        "en": "⛔ [CHAT ANCHOR VIOLATION] Even in chat mode, technical security claims without execution are forbidden — provide executable code or execute directly",
    },
    # RULE 96-98 설명 (도움말)
    "anchor_help_rules": {
        "ko": (
            "⚓ [EXEC-ANCHOR v1.0 — 0환각 3대 규칙]\n"
            "  RULE 96: 추측 언어(아마도/것 같다/probably) + 기술 주장 = 즉시 차단\n"
            "  RULE 97: 실행 출력 없이 기술 주장(SQLi/XSS/취약점) = 즉시 차단\n"
            "  RULE 98: 보고 형식 의무 — [실행결과]→[관측값]→[보안결론]"
        ),
        "zh": (
            "⚓ [EXEC-ANCHOR v1.0 — 零幻觉三大规则]\n"
            "  规则96: 推测语言(可能/也许/probably)+技术声明 = 立即拦截\n"
            "  规则97: 无执行输出的技术声明(SQLi/XSS/漏洞) = 立即拦截\n"
            "  规则98: 报告格式义务 — [执行结果]→[观察值]→[安全结论]"
        ),
        "en": (
            "⚓ [EXEC-ANCHOR v1.0 — Zero-Hallucination 3 Rules]\n"
            "  RULE 96: Speculation language (probably/might/seems) + tech claim = immediate block\n"
            "  RULE 97: Technical claim (SQLi/XSS/vuln) without exec output = immediate block\n"
            "  RULE 98: Report format required — [exec result]→[observation]→[security conclusion]"
        ),
    },
    # ── v4.8.0: TARGET_LOCK 메시지 ──────────────────────────────────
    "target_lock_blocked": {
        "ko": "⛔ [TARGET_LOCK v4.8.0] 타겟 무단 변경 차단 — 새 타겟은 '/target <URL>'로 명시적 지정 필요",
        "zh": "⛔ [TARGET_LOCK v4.8.0] 阻止未授权目标变更 — 需通过 '/target <URL>' 明确指定新目标",
        "en": "⛔ [TARGET_LOCK v4.8.0] Unauthorized target change blocked — use '/target <URL>' to switch explicitly",
    },
    # ── v4.8.0: [VERIFIED] 빈값 경고 ───────────────────────────────
    "verified_empty_blocked": {
        "ko": "⚠️ [v4.8.0] VERIFIED_EMPTY: 추출값이 비어 있음 — [VERIFIED] 태그는 실제 값이 있을 때만 사용",
        "zh": "⚠️ [v4.8.0] VERIFIED_EMPTY: 提取值为空 — [VERIFIED]标签只能在有实际值时使用",
        "en": "⚠️ [v4.8.0] VERIFIED_EMPTY: Extracted value is empty — [VERIFIED] tag only valid with non-empty value",
    },
    # ── v4.8.0: SLEEP 판정 교정 경고 ────────────────────────────────
    "sleep_judgment_corrected": {
        "ko": "⚠️ [v4.8.0] SLEEP_JUDGMENT_CORRECTED: elapsed < threshold(N*0.8) — ❌로 판정 교정됨",
        "zh": "⚠️ [v4.8.0] SLEEP_JUDGMENT_CORRECTED: elapsed < threshold(N*0.8) — 判定已更正为 ❌",
        "en": "⚠️ [v4.8.0] SLEEP_JUDGMENT_CORRECTED: elapsed < threshold(N*0.8) — verdict corrected to ❌",
    },
    # ── v4.8.0: random 모듈 자동 주입 ───────────────────────────────
    "inject_import_random": {
        "ko": "🔧 [v4.8.0] 'import random' 자동 주입 — random 모듈 사용 감지됨",
        "zh": "🔧 [v4.8.0] 自动注入 'import random' — 检测到 random 模块使用",
        "en": "🔧 [v4.8.0] Auto-injected 'import random' — random module usage detected",
    },
    # ── v4.8.0: 환각 감지 (텍스트 결과 위조) ────────────────────────
    "hallucination_claimed_result": {
        "ko": "⛔ [HALLUCINATION v4.8.0] 미실행 결과 위조 감지 — 실제 코드 실행 후 print() 출력만 보고",
        "zh": "⛔ [HALLUCINATION v4.8.0] 检测到伪造未执行结果 — 只能报告实际代码执行的print()输出",
        "en": "⛔ [HALLUCINATION v4.8.0] Fabricated result without execution detected — only report actual print() output",
    },
    # ── v4.8.0: SQLi 컨텍스트 타입 교정 ────────────────────────────
    "sqli_context_type_corrected": {
        "ko": "🔧 [v4.8.0] SQLi 컨텍스트 감지 — credential 대신 sqli로 취약점 유형 교정",
        "zh": "🔧 [v4.8.0] 检测到SQLi上下文 — 漏洞类型从credential修正为sqli",
        "en": "🔧 [v4.8.0] SQLi context detected — vuln type corrected from credential to sqli",
    },
    # ── v4.9.0: 코드 내 타 도메인 URL 차단 (근본 수정) ──────────────
    "target_domain_mismatch": {
        "ko": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] 코드 내 타겟 외 도메인 감지 — 실행 차단\n"
            "  현재 타겟 도메인만 코드에 사용 가능. 타겟 변경은 '/target <URL>'로만."
        ),
        "zh": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] 检测到代码中包含非目标域名 — 已阻止执行\n"
            "  代码中只能使用当前目标域名. 切换目标请使用 '/target <URL>'."
        ),
        "en": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] Non-target domain detected in code — execution blocked\n"
            "  Only the current target domain may be used in code. Use '/target <URL>' to switch."
        ),
        "ja": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] コード内に対象外ドメインを検出 — 実行ブロック\n"
            "  コードは現在のターゲットドメインのみ使用可. 変更は '/target <URL>' で."
        ),
        "ru": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] В коде обнаружен сторонний домен — выполнение заблокировано\n"
            "  В коде разрешён только текущий целевой домен. Смена цели через '/target <URL>'."
        ),
        "ar": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] تم اكتشاف نطاق خارج الهدف في الكود — تم حظر التنفيذ\n"
            "  يُسمح فقط باستخدام نطاق الهدف الحالي. لتغيير الهدف استخدم '/target <URL>'."
        ),
        "es": (
            "⛔ [TARGET_DOMAIN_MISMATCH v4.9.0] Dominio no objetivo detectado en código — ejecución bloqueada\n"
            "  Solo se permite el dominio objetivo actual en el código. Use '/target <URL>' para cambiar."
        ),
    },
    # ── v4.9.0: TARGET_LOCK 업데이트 (2차 방어선) ───────────────────
    "target_lock_blocked_v490": {
        "ko": (
            "⛔ [TARGET_LOCK v4.9.0] 텍스트 내 타 도메인 URL 감지 — 2차 방어 차단\n"
            "  새 타겟은 '/target <URL>'로만 명시적 지정 가능."
        ),
        "zh": (
            "⛔ [TARGET_LOCK v4.9.0] 检测到文本中包含非目标域名URL — 二级防御拦截\n"
            "  新目标只能通过 '/target <URL>' 明确指定."
        ),
        "en": (
            "⛔ [TARGET_LOCK v4.9.0] Non-target domain URL in text — secondary defense blocked\n"
            "  New targets must be set explicitly via '/target <URL>'."
        ),
    },
    # ── v4.9.1: 텍스트 레벨 환각 스캐너 (Gap 1 수정) ─────────────────
    "text_hallucination_detected": {
        "ko": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] 코드 실행 없이 텍스트로 결과 서술 감지\n"
            "  ```bash 블록으로 curl 명령을 작성하고 실제 HTTP 응답만 보고하세요."
        ),
        "zh": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] 检测到未执行代码即通过文字描述结果\n"
            "  请编写 ```bash 代码块使用curl，只报告实际HTTP响应输出."
        ),
        "en": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] Claimed result in text without code execution detected\n"
            "  Write a ```bash block with curl and only report actual HTTP response output."
        ),
        "ja": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] コード実行なしでテキストに結果を記述することを検出\n"
            "  ```bash ブロックでcurlを使い、実際のHTTPレスポンスのみを報告してください."
        ),
        "ru": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] Обнаружено описание результатов без выполнения кода\n"
            "  Напишите блок ```bash с curl и сообщайте только реальный HTTP-ответ."
        ),
        "ar": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] تم اكتشاف وصف النتائج في النص بدون تنفيذ كود\n"
            "  اكتب كتلة ```bash مع curl وأبلغ فقط عن استجابة HTTP الفعلية."
        ),
        "es": (
            "⛔ [TEXT_HALLUCINATION v4.9.7] Resultado reclamado en texto sin ejecución de código\n"
            "  Escriba un bloque ```bash con curl y reporte solo la respuesta HTTP real."
        ),
    },
    # ── v4.9.1: Pattern 6 확장 (Gap 4 수정) ──────────────────────────
    "pattern6_expanded_block": {
        "ko": "⛔ [PATTERN6_EXT v4.9.1] 코드 블록 내 미실행 결과 서술 (확장 패턴) 감지 — 실행 차단",
        "zh": "⛔ [PATTERN6_EXT v4.9.1] 检测到代码块内描述未执行结果 (扩展模式) — 已阻止执行",
        "en": "⛔ [PATTERN6_EXT v4.9.1] Claimed result inside code block (extended pattern) detected — blocked",
    },

    # ── v4.9.3: Pattern 7 AST 기반 재작성 — regex 오탐 구조적 불가능 ────────────
    # v4.9.2: regex로 헤더 제거 → 일부 엣지케이스 여전히 오탐 가능
    # v4.9.3: ast.parse() 사용 → Python 파서 수준에서 주석/헤더 완전 제외
    "pattern7_fp_fixed": {
        "ko": (
            "⛔ [PATTERN7 v4.9.3/AST] 타겟 외 도메인 HTTP 요청 감지 — 실행 차단\n"
            "코드가 현재 타겟({target})이 아닌 다른 도메인({offender})으로 요청을 보내려 합니다.\n"
            "AST 파싱으로 실제 요청 인수만 검사 (헤더/주석 내 URL 완전 제외)."
        ),
        "zh": (
            "⛔ [PATTERN7 v4.9.3/AST] 检测到非目标域名HTTP请求 — 已阻止执行\n"
            "代码尝试向 {offender} 发送请求，但活跃目标为 {target}。\n"
            "使用AST解析仅检查实际请求参数（完全排除headers/注释中的URL）。"
        ),
        "en": (
            "⛔ [PATTERN7 v4.9.3/AST] Non-target domain HTTP request detected — blocked\n"
            "Code attempts to request {offender} but the ACTIVE TARGET is {target}.\n"
            "AST parsing used — only actual request args checked (headers/comments fully excluded)."
        ),
        "ja": (
            "⛔ [PATTERN7 v4.9.3/AST] 非ターゲットドメインへのHTTPリクエスト検出 — ブロック\n"
            "コードが{offender}へリクエストしようとしていますが、アクティブターゲットは{target}です。\n"
            "ASTパーシングで実際のリクエスト引数のみを検査（ヘッダー/コメント内URL完全除外）。"
        ),
        "es": (
            "⛔ [PATTERN7 v4.9.3/AST] Solicitud HTTP a dominio no objetivo detectada — bloqueada\n"
            "El código intenta solicitar {offender} pero el objetivo activo es {target}.\n"
            "Análisis AST: solo se verifican argumentos reales de solicitud (headers/comentarios excluidos)."
        ),
        "ru": (
            "⛔ [PATTERN7 v4.9.3/AST] Обнаружен HTTP-запрос к стороннему домену — заблокировано\n"
            "Код пытается обратиться к {offender}, но активная цель — {target}.\n"
            "Используется AST-анализ: проверяются только аргументы запроса (headers/комментарии исключены)."
        ),
        "ar": (
            "⛔ [PATTERN7 v4.9.3/AST] تم اكتشاف طلب HTTP إلى نطاق غير مستهدف — تم الحظر\n"
            "الكود يحاول الاتصال بـ {offender} لكن الهدف النشط هو {target}.\n"
            "يستخدم تحليل AST: يتم فحص وسائط الطلب الفعلية فقط (URL في الترويسات/التعليقات مستبعدة تمامًا)."
        ),
    },

    # ── v4.9.3: WAF 페이로드 차단 vs IP 차단 구분 (다중 경로 검증) ──────────────
    # v4.9.2: 루트(/) 1개만 체크 → 루트가 WAF에 차단된 경우 IP 차단으로 오판 가능
    # v4.9.3: /robots.txt, /favicon.ico 등 3개 경로 순차 시도 → 하나라도 응답 시 WAF 차단
    "waf_payload_blocked_not_ip": {
        "ko": (
            "⚡ 'blocked' 감지됐지만 서버 응답 정상 확인 — "
            "WAF 페이로드 차단 (IP 차단 아님, 다중경로 검증 완료)"
        ),
        "zh": (
            "⚡ 检测到'blocked'但服务器正常响应 — "
            "WAF拦截特定载荷（非IP封锁，多路径验证完成）"
        ),
        "en": (
            "⚡ 'blocked' text found but server responding normally — "
            "WAF payload block, NOT IP block (multi-path probe confirmed)"
        ),
        "ja": (
            "⚡ 'blocked'テキスト検出もサーバーは正常応答 — "
            "WAFペイロードブロック（IPブロックではない、複数パス検証済み）"
        ),
        "es": (
            "⚡ Texto 'blocked' detectado pero el servidor responde normalmente — "
            "Bloqueo de carga WAF, NO bloqueo de IP (verificación multi-ruta confirmada)"
        ),
        "ru": (
            "⚡ Текст 'blocked' обнаружен, но сервер отвечает нормально — "
            "WAF заблокировал нагрузку, IP не заблокирован (многопутевая проверка подтверждена)"
        ),
        "ar": (
            "⚡ تم اكتشاف نص 'blocked' لكن الخادم يستجيب بشكل طبيعي — "
            "WAF يحظر الحمولة وليس IP (تم تأكيد التحقق متعدد المسارات)"
        ),
    },

    # ── v4.9.4: LFI 오탐 방지 (php://filter redirect 구별) ──────────────────
    "lfi_redirect_fp_blocked": {
        "ko": (
            "⛔ [v4.9.4] LFI 오탐 차단: php://filter 응답이 HTML 페이지 → "
            "홈페이지 리다이렉트 (실제 파일 내용 없음, base64 블록 미감지)"
        ),
        "zh": (
            "⛔ [v4.9.4] LFI误报拦截: php://filter响应为HTML页面 → "
            "主页重定向（无实际文件内容，未检测到base64块）"
        ),
        "en": (
            "⛔ [v4.9.4] LFI false positive blocked: php://filter response is HTML page → "
            "homepage redirect (no actual file content, no base64 block detected)"
        ),
        "ja": (
            "⛔ [v4.9.4] LFI誤検知ブロック: php://filterレスポンスはHTMLページ → "
            "ホームページリダイレクト（実ファイル内容なし、base64ブロック未検出）"
        ),
        "es": (
            "⛔ [v4.9.4] Falso positivo LFI bloqueado: respuesta php://filter es página HTML → "
            "redirección a página principal (sin contenido real de archivo, sin bloque base64)"
        ),
        "ru": (
            "⛔ [v4.9.4] Ложное срабатывание LFI заблокировано: ответ php://filter — HTML страница → "
            "перенаправление на главную (нет реального содержимого файла, нет base64 блока)"
        ),
        "ar": (
            "⛔ [v4.9.4] إيقاف الإيجابي الكاذب LFI: استجابة php://filter هي صفحة HTML → "
            "إعادة توجيه إلى الصفحة الرئيسية (لا محتوى ملف حقيقي، لا كتلة base64)"
        ),
    },

    # ── v4.9.4: Oracle 실패 감지 (반복 문자 추출) ────────────────────────────
    "oracle_failure_detected": {
        "ko": (
            "⛔ [v4.9.4] ORACLE_FAILURE: 추출값 동일 문자 반복 감지 → Oracle 무효 오탐. "
            "이 추출 결과는 신뢰할 수 없음 — BINGO 찾기 억제됨"
        ),
        "zh": (
            "⛔ [v4.9.4] ORACLE_FAILURE: 检测到重复字符提取 → Oracle无效误报. "
            "此提取结果不可信 — BINGO发现已抑制"
        ),
        "en": (
            "⛔ [v4.9.4] ORACLE_FAILURE: repeated same-char extraction detected → invalid oracle false positive. "
            "Extraction result unreliable — BINGO finding suppressed"
        ),
        "ja": (
            "⛔ [v4.9.4] ORACLE_FAILURE: 同一文字の繰り返し抽出を検出 → Oracleが無効な誤検知. "
            "この抽出結果は信頼できない — BINGO検出を抑制"
        ),
        "es": (
            "⛔ [v4.9.4] ORACLE_FAILURE: extracción de caracteres repetidos detectada → oráculo inválido falso positivo. "
            "Resultado de extracción no confiable — hallazgo BINGO suprimido"
        ),
        "ru": (
            "⛔ [v4.9.4] ORACLE_FAILURE: обнаружено повторное извлечение одинаковых символов → недействительный оракул. "
            "Результат извлечения ненадёжен — обнаружение BINGO подавлено"
        ),
        "ar": (
            "⛔ [v4.9.4] ORACLE_FAILURE: تم اكتشاف استخراج متكرر لنفس الأحرف → إيجابي كاذب لـ Oracle غير صالح. "
            "نتيجة الاستخراج غير موثوقة — تم قمع اكتشاف BINGO"
        ),
    },
    # ── v4.9.5: bash+curl 전환 관련 키 ─────────────────────────────────────────
    "bash_exec_start": {
        "ko": "🔧 bash 실행",
        "zh": "🔧 bash 执行",
        "en": "🔧 bash exec",
        "ja": "🔧 bash 実行",
        "es": "🔧 ejecución bash",
        "ru": "🔧 выполнение bash",
        "ar": "🔧 تنفيذ bash",
    },
    "bash_hallucination_blocked": {
        "ko": "⛔ [v4.9.5] BASH_HALLUCINATION: curl/네트워크 명령 없는 bash 블록 차단. bash+curl 방식으로 재작성 요청",
        "zh": "⛔ [v4.9.5] BASH_HALLUCINATION: 无curl/网络命令的bash块已拦截. 请求重写为bash+curl方式",
        "en": "⛔ [v4.9.5] BASH_HALLUCINATION: bash block with no curl/network command blocked. Rewrite as bash+curl requested",
        "ja": "⛔ [v4.9.5] BASH_HALLUCINATION: curl/ネットワークコマンドのないbashブロックをブロック. bash+curlで書き直しを要求",
        "es": "⛔ [v4.9.5] BASH_HALLUCINATION: bloque bash sin curl/comando de red bloqueado. Reescritura como bash+curl solicitada",
        "ru": "⛔ [v4.9.5] BASH_HALLUCINATION: bash-блок без curl/сетевых команд заблокирован. Запрошена перезапись в формат bash+curl",
        "ar": "⛔ [v4.9.5] BASH_HALLUCINATION: تم حجب كتلة bash بدون curl/أوامر شبكية. مطلوب إعادة الكتابة بصيغة bash+curl",
    },
    "bash_placeholder_blocked": {
        "ko": "⛔ [v4.9.5] BASH_PLACEHOLDER: TARGET_URL/example.com 플레이스홀더 감지 → 실제 대상 URL로 재작성 필요",
        "zh": "⛔ [v4.9.5] BASH_PLACEHOLDER: 检测到TARGET_URL/example.com占位符 → 需要用真实目标URL重写",
        "en": "⛔ [v4.9.5] BASH_PLACEHOLDER: TARGET_URL/example.com placeholder detected → must rewrite with real target URL",
        "ja": "⛔ [v4.9.5] BASH_PLACEHOLDER: TARGET_URL/example.comプレースホルダーを検出 → 実際のターゲットURLで書き直しが必要",
        "es": "⛔ [v4.9.5] BASH_PLACEHOLDER: placeholder TARGET_URL/example.com detectado → debe reescribirse con URL de destino real",
        "ru": "⛔ [v4.9.5] BASH_PLACEHOLDER: обнаружен заполнитель TARGET_URL/example.com → необходимо переписать с реальным целевым URL",
        "ar": "⛔ [v4.9.5] BASH_PLACEHOLDER: تم اكتشاف placeholder TARGET_URL/example.com → يجب إعادة الكتابة بعنوان URL الحقيقي للهدف",
    },
    # ── v4.9.6: heredoc/requests 차단 키 ──────────────────────────────────────
    "bash_heredoc_blocked": {
        "ko": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: bash 블록 안의 python3 << 'PYEOF' heredoc 차단 → curl | python3 -c 방식만 허용",
        "zh": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: bash块内的python3 << 'PYEOF' heredoc已拦截 → 仅允许 curl | python3 -c 方式",
        "en": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: python3 heredoc inside bash blocked → only curl | python3 -c pipe is allowed",
        "ja": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: bash内のpython3 heredocをブロック → curl | python3 -c パイプのみ許可",
        "es": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: heredoc de python3 en bash bloqueado → solo se permite curl | python3 -c",
        "ru": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: heredoc python3 внутри bash заблокирован → разрешён только curl | python3 -c",
        "ar": "⛔ [v4.9.6] BASH_HEREDOC_PYTHON: تم حجب heredoc python3 داخل bash → يُسمح فقط بـ curl | python3 -c",
    },
    "bash_requests_blocked": {
        "ko": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: bash 블록에 'import requests' 감지 → requests 금지, curl 사용 필수",
        "zh": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: bash块中检测到'import requests' → 禁止requests库，必须使用curl",
        "en": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: 'import requests' in bash block blocked → requests forbidden, must use curl",
        "ja": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: bashブロック内で'import requests'を検出 → requests禁止、curl使用必須",
        "es": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: 'import requests' detectado en bash → requests prohibido, debe usar curl",
        "ru": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: обнаружен 'import requests' в bash-блоке → requests запрещён, нужно использовать curl",
        "ar": "⛔ [v4.9.6] BASH_CONTAINS_REQUESTS: تم اكتشاف 'import requests' في كتلة bash → requests محظور، يجب استخدام curl",
    },

    # ── v5.0.4: FP-ZERO — 크기 기반 WAF 판정 + 오발 제로 i18n 키 ─────────
    "fp_waf_size_block": {
        "ko": "⛔ WAF 차단 감지 — 응답 크기 {size}B (기준 {baseline}B의 {pct:.0f}%)",
        "zh": "⛔ 检测到WAF拦截 — 响应大小 {size}B（基准 {baseline}B 的 {pct:.0f}%）",
        "en": "⛔ WAF block detected — response size {size}B ({pct:.0f}% of baseline {baseline}B)",
        "ja": "⛔ WAFブロック検出 — レスポンスサイズ {size}B（基準 {baseline}B の {pct:.0f}%）",
        "es": "⛔ Bloqueo WAF detectado — tamaño de respuesta {size}B ({pct:.0f}% del baseline {baseline}B)",
        "ru": "⛔ Обнаружена блокировка WAF — размер ответа {size}B ({pct:.0f}% от baseline {baseline}B)",
        "ar": "⛔ تم اكتشاف حظر WAF — حجم الاستجابة {size}B ({pct:.0f}% من الأساس {baseline}B)",
    },
    "fp_waf_size_normal": {
        "ko": "✅ 정상 응답 — 크기 {size}B (기준 {baseline}B, WAF 차단 아님)",
        "zh": "✅ 正常响应 — 大小 {size}B（基准 {baseline}B，未被WAF拦截）",
        "en": "✅ Normal response — size {size}B (baseline {baseline}B, not WAF blocked)",
        "ja": "✅ 正常レスポンス — サイズ {size}B（基準 {baseline}B、WAFブロックなし）",
        "es": "✅ Respuesta normal — tamaño {size}B (baseline {baseline}B, no bloqueado por WAF)",
        "ru": "✅ Нормальный ответ — размер {size}B (baseline {baseline}B, WAF не блокирует)",
        "ar": "✅ استجابة طبيعية — الحجم {size}B (الأساس {baseline}B، لا يوجد حظر WAF)",
    },
    "fp_boolean_no_diff": {
        "ko": "❌ Boolean SQLi 오발 억제 — 1=1({t}B) ≈ 1=2({f}B) 크기 동일, WAF 차단 중일 가능성",
        "zh": "❌ Boolean SQLi误判抑制 — 1=1({t}B) ≈ 1=2({f}B) 大小相同，可能被WAF拦截",
        "en": "❌ Boolean SQLi FP suppressed — 1=1({t}B) ≈ 1=2({f}B) same size, likely WAF blocked",
        "ja": "❌ Boolean SQLi誤検知抑制 — 1=1({t}B) ≈ 1=2({f}B) サイズ同じ、WAFブロック可能性",
        "es": "❌ FP Boolean SQLi suprimido — 1=1({t}B) ≈ 1=2({f}B) mismo tamaño, posible bloqueo WAF",
        "ru": "❌ Подавлен ложный позитив Boolean SQLi — 1=1({t}B) ≈ 1=2({f}B) одинаковый размер",
        "ar": "❌ تم تجاهل الإيجابية الكاذبة Boolean SQLi — 1=1({t}B) ≈ 1=2({f}B) نفس الحجم",
    },
    "fp_xss_javascript_href": {
        "ko": "❌ XSS 오발 억제 — javascript: href는 일반 HTML 링크, XSS 아님",
        "zh": "❌ XSS误判抑制 — javascript: href 是普通HTML链接，不是XSS",
        "en": "❌ XSS FP suppressed — javascript: href is normal HTML link, not XSS",
        "ja": "❌ XSS誤検知抑制 — javascript: href は通常のHTMLリンク、XSSではない",
        "es": "❌ FP XSS suprimido — javascript: href es enlace HTML normal, no XSS",
        "ru": "❌ Подавлен ложный позитив XSS — javascript: href является обычной HTML-ссылкой",
        "ar": "❌ تم تجاهل الإيجابية الكاذبة XSS — javascript: href هو رابط HTML عادي",
    },
    "fp_zero_rule99_violated": {
        "ko": "⛔ [RULE 99] WAF 판정에 키워드 검색 사용 금지 — 크기 기반으로 판정할 것",
        "zh": "⛔ [RULE 99] WAF判定禁止使用关键词搜索 — 必须基于响应大小判定",
        "en": "⛔ [RULE 99] Keyword-based WAF detection forbidden — must use response size",
        "ja": "⛔ [RULE 99] WAF判定にキーワード検索禁止 — レスポンスサイズで判定すること",
        "es": "⛔ [RULE 99] Detección WAF por palabras clave prohibida — usar tamaño de respuesta",
        "ru": "⛔ [RULE 99] Определение WAF по ключевым словам запрещено — использовать размер ответа",
        "ar": "⛔ [RULE 99] يُحظر الكشف عن WAF بالكلمات المفتاحية — يجب استخدام حجم الاستجابة",
    },
    # ── v5.0.5: FP-ZERO RULE 102~104 (IDOR/RCE/SSRF 오발 방지) ──────────────────
    "fp_idor_own_data": {
        "ko": "⛔ [RULE 102] 자신의 계정 데이터 응답 — IDOR 아님. 타인 ID로 타인 데이터 반환 확인 필요.",
        "zh": "⛔ [RULE 102] 这是自己的账户数据 — 非IDOR。需确认使用他人ID访问他人数据。",
        "en": "⛔ [RULE 102] Own account data returned — not IDOR. Must confirm other user's data via other user's ID.",
    },
    "fp_rce_root_prefix": {
        "ko": "⛔ [RULE 103] 'root:' 단독 출현 — RCE 아님. uid=0(root) 또는 /etc/passwd 레코드 형식 필요.",
        "zh": "⛔ [RULE 103] 仅出现'root:'字符串 — 非RCE。需要uid=0(root)或/etc/passwd记录格式。",
        "en": "⛔ [RULE 103] 'root:' alone is not RCE. Require uid=0(root) or /etc/passwd record format.",
    },
    "fp_ssrf_internal_word": {
        "ko": "⛔ [RULE 104] 'internal' 단어 단독 — SSRF 아님. 사설 IP(10./172.16-31./192.168.) 직접 노출 필요.",
        "zh": "⛔ [RULE 104] 仅出现'internal'单词 — 非SSRF。需要私有IP(10./172.16-31./192.168.)直接暴露。",
        "en": "⛔ [RULE 104] 'internal' word alone is not SSRF. Require private IP (10./172.16-31./192.168.) direct exposure.",
    },
    "fp_rce_command_log": {
        "ko": "⛔ [RULE 103] 스크립트 로그 'command output:' — RCE 아님. 실제 OS 명령 결과(uid=/hostname=) 필요.",
        "zh": "⛔ [RULE 103] 脚本日志'command output:' — 非RCE。需要实际OS命令结果(uid=/hostname=)。",
        "en": "⛔ [RULE 103] Script log 'command output:' is not RCE. Require actual OS command result (uid=/hostname=).",
    },
    # FP-ZERO 회귀 테스트 스위트 관련 메시지 (v5.0.6)
    "fp_regression_pass": {
        "ko": "✅ FP-ZERO 회귀 테스트 전체 통과 — 오발 없음 확인",
        "zh": "✅ FP-ZERO 回归测试全部通过 — 已确认无误判",
        "en": "✅ FP-ZERO regression suite passed — zero false positives confirmed",
    },
    "fp_regression_fail": {
        "ko": "🚨 FP-ZERO 회귀 테스트 실패 — 릴리즈 전 오발 수정 필수",
        "zh": "🚨 FP-ZERO 回归测试失败 — 发布前必须修复误判",
        "en": "🚨 FP-ZERO regression suite FAILED — must fix false positives before release",
    },
    "fp_new_pattern_warning": {
        "ko": "⚠️  MVVS 패턴 추가 시 tests/test_mvvs_false_positive.py에 FP/TP 케이스 반드시 추가",
        "zh": "⚠️  添加MVVS模式时必须在tests/test_mvvs_false_positive.py中添加FP/TP用例",
        "en": "⚠️  When adding MVVS patterns, always add FP/TP cases to tests/test_mvvs_false_positive.py",
    },
    # BINGO_SIGNAL 구조화 보고 시스템 관련 메시지 (v5.0.7)
    "bingo_signal_detected": {
        "ko": "🎯 BINGO_SIGNAL 구조화 신호 탐지됨 — 증거 검증 완료",
        "zh": "🎯 检测到BINGO_SIGNAL结构化信号 — 已验证证据",
        "en": "🎯 BINGO_SIGNAL structured signal detected — evidence validated",
    },
    "bingo_signal_rejected": {
        "ko": "⛔ BINGO_SIGNAL 증거 불충분 — 오발 차단됨",
        "zh": "⛔ BINGO_SIGNAL证据不足 — 已阻止误判",
        "en": "⛔ BINGO_SIGNAL rejected — insufficient evidence, false positive blocked",
    },
    "bingo_signal_invalid_json": {
        "ko": "⚠️  BINGO_SIGNAL JSON 파싱 실패 — 형식 오류",
        "zh": "⚠️  BINGO_SIGNAL JSON解析失败 — 格式错误",
        "en": "⚠️  BINGO_SIGNAL JSON parse failed — format error",
    },
    "bingo_signal_fallback_regex": {
        "ko": "🔍 구조화 신호 없음 — 정규식 백업 모드로 탐지 시도",
        "zh": "🔍 无结构化信号 — 切换至正则备用模式检测",
        "en": "🔍 No structured signal — falling back to regex detection mode",
    },
    "bingo_signal_rule_add_reminder": {
        "ko": "⚠️  새 BINGO_SIGNAL 타입 추가 시 _validate_bingo_signal 및 테스트 케이스 반드시 추가",
        "zh": "⚠️  添加新BINGO_SIGNAL类型时必须同步更新_validate_bingo_signal及测试用例",
        "en": "⚠️  When adding new BINGO_SIGNAL types, always update _validate_bingo_signal and test cases",
    },
})


def get_strings(lang: str = "en") -> dict:
    """특정 언어의 모든 문자열 반환"""
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return {k: v.get(lang, v.get("en", "")) for k, v in _STRINGS.items()}


def get_slash_commands(lang: str = "en") -> list:
    """슬래시 자동완성 명령어 목록 (현재 언어 기준)"""
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return [(cmd, desc.get(lang, desc.get("en", ""))) for cmd, desc in _SLASH_DESC.items()]
