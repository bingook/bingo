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
        "ko": """/clear    — 화면 지우기
/model    — 모델 전환
/config   — 설정 보기/수정
/history  — 대화 내역
/export   — 대화 내보내기 (.md)
/lang     — 언어 변경
/quit     — 종료""",
        "zh": """/clear    — 清屏
/model    — 切换模型
/config   — 查看/修改配置
/history  — 对话历史
/export   — 导出对话 (.md)
/lang     — 切换语言
/quit     — 退出""",
        "en": """/clear    — Clear screen
/model    — Switch model
/config   — View/edit config
/history  — Chat history
/export   — Export chat (.md)
/lang     — Change language
/quit     — Quit""",
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
}


def get_strings(lang: str = "en") -> dict:
    if lang not in SUPPORTED_LANGS:
        lang = "en"
    return {k: v[lang] for k, v in _STRINGS.items()}
