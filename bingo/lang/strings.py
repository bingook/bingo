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
        "ko": "모델명을 입력하세요 (예: deepseek-chat)",
        "zh": "请输入模型名称（例：deepseek-chat）",
        "en": "Enter model name (e.g. deepseek-chat)",
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
    "error": {
        "ko": "오류",
        "zh": "错误",
        "en": "Error",
    },
    "api_error": {
        "ko": "API 오류가 발생했습니다",
        "zh": "API 调用失败",
        "en": "API call failed",
    },
    # ── 명령어 ────────────────────────────────────────────────────
    "help_text": {
        "ko": """/scan <url>              빠른 정찰: WAF + 핑거프린트 + 민감파일
/waf <url>               WAF 탐지 + 자동 우회 시도
/crack [hash]            해시 크랙 — 온라인 조회 → 오프라인 크랙
/stop                    실행 중인 크랙/스캔 중단
/tools                   도구 목록 + 자동 설치
/tools install <이름>    특정 도구 자동 설치
/tools install all       미설치 도구 전체 설치
/model                   AI 모델 추가/변경
/skill <키워드>          스킬 지식베이스 검색
/history                 대화 기록 보기
/export                  대화를 .md 파일로 저장
/config                  현재 설정 보기
/lang                    언어 변경 (ko / zh / en)
/clear                   화면 지우기
/quit                    종료""",
        "zh": """/scan <url>              快速侦察：WAF + 指纹识别 + 敏感文件
/waf <url>               WAF 检测 + 自动绕过尝试
/crack [hash]            哈希破解 — 在线查询 → 离线破解
/stop                    停止正在运行的破解/扫描
/tools                   工具列表 + 自动安装
/tools install <名称>    自动安装指定工具
/tools install all       安装所有缺失工具
/model                   添加/切换 AI 模型
/skill <关键词>          搜索技能知识库
/history                 查看对话历史
/export                  导出对话为 .md 文件
/config                  查看当前配置
/lang                    切换语言 (ko / zh / en)
/clear                   清屏
/quit                    退出""",
        "en": """/scan <url>              Quick recon: WAF + fingerprint + sensitive files
/waf <url>               WAF detection + auto bypass attempt
/crack [hash]            Hash crack — online lookup → offline crack
/stop                    Stop running crack/scan
/tools                   Tool list + auto-install
/tools install <name>    Auto-install a specific tool
/tools install all       Install all missing tools
/model                   Add or switch AI model
/skill <keyword>         Search skill knowledge base
/history                 View chat history
/export                  Export chat as .md file
/config                  View current settings
/lang                    Change language (ko / zh / en)
/clear                   Clear screen
/quit                    Quit""",
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
    "waf_detected":         {"ko": "🔥 WAF 탐지",               "zh": "🔥 检测到 WAF",            "en": "🔥 WAF detected"},
    "waf_none":             {"ko": "✓ WAF 없음 — 직접 공격 가능","zh": "✓ 无 WAF — 可直接攻击",    "en": "✓ No WAF — direct attack possible"},
    "waf_fingerprint":      {"ko": "핑거프린트...",              "zh": "指纹识别中...",            "en": "Fingerprinting..."},
    "waf_bypass_ok":        {"ko": "✓ 우회 성공",               "zh": "✓ 绕过成功",              "en": "✓ Bypass successful"},
    "waf_bypass_fail":      {"ko": "우회 실패 — /waf 결과를 AI에게 물어보세요",
                             "zh": "绕过失败 — 请将 /waf 结果发给 AI",
                             "en": "Bypass failed — ask AI with /waf results"},
    "waf_analyzing":        {"ko": "WAF 분석",                  "zh": "WAF 分析",                "en": "WAF analysis"},
    "waf_detecting":        {"ko": "WAF 탐지 중...",             "zh": "WAF 检测中...",            "en": "Detecting WAF..."},
    "waf_priority":         {"ko": "우선 우회 전략",             "zh": "优先绕过策略",             "en": "Priority bypass strategies"},
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
    "cli_help_output":  {"ko": "보고서 저장 위치", "zh": "报告保存位置","en": "Report save path"},
    "cli_help_phase":   {"ko": "실행할 단계 선택", "zh": "选择执行阶段","en": "Select phases to run"},
    "crawling":            {"ko": "🔍 사이트 크롤 중...", "zh": "🔍 站点抓取中...", "en": "🔍 Crawling site..."},
    "params_found":        {"ko": "✓ 파라미터 발견", "zh": "✓ 发现参数",     "en": "✓ Parameters found"},
    "exec_running":        {"ko": "실행 중",       "zh": "执行中",       "en": "Running"},
    "exec_analyzing":      {"ko": "📊 실행 결과 분석 중...", "zh": "📊 分析执行结果...", "en": "📊 Analyzing results..."},
    "site_recon":          {"ko": "🔍 사이트 정보 수집",   "zh": "🔍 站点信息收集",  "en": "🔍 Site reconnaissance"},
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
    "skill_col_pack":      {"ko": "스킬 팩",         "zh": "技能包",          "en": "Skill Pack"},
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

    # ── 멀티 에이전트 / Recon ─────────────────────────────────────
    "recon_start":         {"ko": "정찰 시작",           "zh": "开始侦察",         "en": "Recon started"},
    "port_open":           {"ko": "열린 포트",           "zh": "开放端口",         "en": "Open port"},
    "tech_found":          {"ko": "기술스택 식별",       "zh": "技术栈识别",       "en": "Tech stack identified"},
    "subdomain_found":     {"ko": "서브도메인 발견",     "zh": "发现子域名",       "en": "Subdomain found"},
    "dir_found":           {"ko": "디렉터리 발견",       "zh": "发现目录",         "en": "Directory found"},

    # ── 보고서 ───────────────────────────────────────────────────
    "report_generating":   {"ko": "보고서 생성 중",      "zh": "正在生成报告",     "en": "Generating report"},
    "report_saved":        {"ko": "보고서 저장됨",       "zh": "报告已保存",       "en": "Report saved"},
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
    "/webshell":{"ko": "웹쉘 획득  /webshell <url>  (Gnuboard5/범용 GIF polyglot)",
                 "zh": "获取Webshell  /webshell <url>  (Gnuboard5/通用GIF polyglot)",
                 "en": "Get webshell  /webshell <url>  (Gnuboard5/generic GIF polyglot)"},
    "/quit":    {"ko": "종료",                        "zh": "退出",                "en": "Quit"},
}

# ── 스킬 시스템 / WAF / 자동 분석 추가 문자열 ──────────────────────────────
_STRINGS.update({
    "url_404_fallback":     {"ko": "⚠ {url} → 404. 루트 사이트로 분석 전환: {root}",
                             "zh": "⚠ {url} → 404。切换到根站点分析: {root}",
                             "en": "⚠ {url} → 404. Switching to root site analysis: {root}"},
    "skill_already_builtin":{"ko": "'{name}' 스킬이 이미 내장되어 있습니다. AI가 자동 사용합니다.",
                             "zh": "技能 '{name}' 已内置，AI 将自动使用。",
                             "en": "Skill '{name}' is already built-in. AI will use it automatically."},
    "skill_not_found_tip":  {"ko": "스킬 '{name}'을 찾을 수 없습니다. /skill <키워드> 로 검색해보세요.",
                             "zh": "未找到技能 '{name}'。请用 /skill <关键词> 搜索。",
                             "en": "Skill '{name}' not found. Try /skill <keyword> to search."},
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
})


def get_slash_commands(lang: str = "en") -> list[tuple[str, str]]:
    """슬래시 자동완성 명령어 목록 (현재 언어 기준)"""
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return [(cmd, desc[lang]) for cmd, desc in _SLASH_DESC.items()]


def get_strings(lang: str = "en") -> dict:
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return {k: v[lang] for k, v in _STRINGS.items()}
