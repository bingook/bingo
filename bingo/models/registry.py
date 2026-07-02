from .base import BaseModel, ClaudeModel, ModelConfig

# ── 내장 프로바이더 정보 ──────────────────────────────────────────
# 최신순 → 구버전 순으로 정렬 (2026-06 기준)
# ── label 다국어 헬퍼 ────────────────────────────────────────────────
# v3.2.89: label 값을 {ko/zh/en} dict로 변경 → _cmd_model에서 lang 적용
# 고객 피드백: 모델 선택 화면에 한국어가 섞여 나옴
def _label(ko: str, zh: str, en: str) -> dict:
    return {"ko": ko, "zh": zh, "en": en}


def get_provider_label(info: dict, lang: str = "en") -> str:
    """label이 dict면 lang 키로, str이면 그대로 반환"""
    lbl = info.get("label", "")
    if isinstance(lbl, dict):
        return lbl.get(lang) or lbl.get("en") or next(iter(lbl.values()), "")
    return lbl


BUILTIN_PROVIDERS: dict[str, dict] = {
    "deepseek": {
        "label": _label(
            ko="DeepSeek  ★ 추천",
            zh="DeepSeek  ★ 推荐",
            en="DeepSeek  ★ Recommended",
        ),
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-v4-pro",
        "max_tokens": 8192,        # DeepSeek V4 최대 출력 8K
        "models": [
            # ── V4 세대 (현재) ──
            "deepseek-v4-pro",     # V4 Pro — 1.6T params, 49B active, 1M ctx (최신·권장)
            "deepseek-v4-flash",   # V4 Flash — 284B params, 13B active, 1M ctx (빠름·저렴)
            # ── 레거시 (2026-07-24 폐기 예정) ──
            "deepseek-reasoner",   # → v4-flash thinking 으로 라우팅됨
            "deepseek-chat",       # → v4-flash 로 라우팅됨 (폐기 예정)
        ],
        "cls": "openai_compat",
        "recommended": True,
        "note": "deepseek-v4-pro 권장 / deepseek-chat 은 2026-07-24 폐기 예정",
    },
    "claude": {
        "label": _label(
            ko="Anthropic Claude",
            zh="Anthropic Claude",
            en="Anthropic Claude",
        ),
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-fable-5",
        "max_tokens": 16000,       # Claude 최대 출력 16K (안전 기본값)
        "models": [
            # ── Fable 세대 (2026-06, 최상위) ──
            "claude-fable-5",          # Fable 5 — 최상위 Mythos 클래스 (2026-06)
            # ── Opus 세대 ──
            "claude-opus-4-8",         # Opus 4.8 — 가장 최신 Opus (2026-05)
            "claude-opus-4-7",         # Opus 4.7 (2026-04)
            "claude-opus-4-6",         # Opus 4.6 (2026-02)
            "claude-opus-4-5",         # Opus 4.5 (2025-11)
            # ── Sonnet 세대 ──
            "claude-sonnet-4-6",       # Sonnet 4.6 — 균형잡힌 권장 (2026-02)
            "claude-sonnet-4-5",       # Sonnet 4.5 (2025-09)
            # ── Haiku 세대 ──
            "claude-haiku-4-5",        # Haiku 4.5 — 빠름·저렴 (2025-10)
        ],
        "cls": "claude",
        "note": "claude-fable-5 최상위 / claude-sonnet-4-6 범용 권장",
    },
    "openai": {
        "label": _label(
            ko="OpenAI GPT",
            zh="OpenAI GPT",
            en="OpenAI GPT",
        ),
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-5.5",
        "max_tokens": 16384,       # GPT-4o/5 계열 최대 출력 16K
        "models": [
            # ── GPT-5 세대 (최신) ──
            "gpt-5.5",             # GPT-5.5 — 최신 플래그십 (2026)
            "gpt-5.4",             # GPT-5.4
            "gpt-5.4-mini",        # GPT-5.4 mini
            "gpt-5.4-nano",        # GPT-5.4 nano
            "gpt-5.2",             # GPT-5.2
            "gpt-5.2-pro",         # GPT-5.2 Pro
            "gpt-5.1",             # GPT-5.1
            "gpt-5.1-mini",        # GPT-5.1 mini
            "gpt-5",               # GPT-5
            "gpt-5-mini",          # GPT-5 mini
            # ── GPT-4 세대 ──
            "gpt-4.1",             # GPT-4.1
            "gpt-4.1-mini",        # GPT-4.1 mini
            "gpt-4.1-nano",        # GPT-4.1 nano
            "gpt-4o",              # GPT-4o
            "gpt-4o-mini",         # GPT-4o mini
            # ── o-시리즈 (추론) ──
            "o4-mini",             # o4-mini
            "o3",                  # o3
            "o3-mini",             # o3-mini
            "o1",                  # o1
            "o1-mini",             # o1-mini
            # ── 구버전 ──
            "gpt-4-turbo",         # GPT-4 Turbo
            "gpt-4",               # GPT-4
            "gpt-3.5-turbo",       # GPT-3.5 Turbo
        ],
        "cls": "openai_compat",
        "note": "gpt-5.5 최신 플래그십 / gpt-4o 안정적 구버전",
    },
    "glm": {
        "label": _label(
            ko="Zhipu GLM (Z.ai) ★ 해킹특화",
            zh="智谱 GLM (Z.ai) ★ 安全专项",
            en="Zhipu GLM (Z.ai) ★ Security-focused",
        ),
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-5.1",
        "max_tokens": 8192,        # GLM 최대 출력 8K
        "models": [
            # ── GLM-5 세대 (최신) ──
            "glm-5.2",             # GLM-5.2 — 1M ctx (2026, 최신)
            "glm-5.1",             # GLM-5.1 — 200K ctx 플래그십 (2026-03)
            "glm-5",               # GLM-5 (2026-02)
            "glm-5-turbo",         # GLM-5 Turbo (2026)
            "glm-5v-turbo",        # GLM-5V Turbo — 비전 (2026-04)
            # ── GLM-4 세대 ──
            "glm-4.7",             # GLM-4.7 — 200K ctx (2025-12)
            "glm-4.7-flash",       # GLM-4.7 Flash — 무료 (2026-01)
            "glm-4.7-flashx",      # GLM-4.7 FlashX — 저렴 (2026-01)
            "glm-4.6",             # GLM-4.6 (2025-09)
            "glm-4.6v",            # GLM-4.6V — 비전 (2025-12)
            "glm-4.5",             # GLM-4.5 (2025-07)
            "glm-4.5-air",         # GLM-4.5 Air (2025-07)
            "glm-4.5-flash",       # GLM-4.5 Flash — 무료 (2025-07)
            "glm-4-plus",          # GLM-4 Plus
            "glm-4",               # GLM-4 — 구버전
            # ── Z1 추론 시리즈 ──
            "glm-z1-air",          # GLM-Z1 Air — 추론 (저렴)
            "glm-z1-airx",         # GLM-Z1 AirX — 추론 고속
            "glm-z1-flash",        # GLM-Z1 Flash — 추론 무료
            "glm-4-flash",         # GLM-4 Flash (구버전)
        ],
        "cls": "openai_compat",
        "note": "glm-5.1 플래그십 / glm-4.7-flash·glm-4.5-flash 무료",
    },
    "qwen": {
        "label": _label(
            ko="Alibaba Qwen (DashScope) — 국내 접속 안정",
            zh="阿里 通义千问 (DashScope) — 国内访问稳定",
            en="Alibaba Qwen (DashScope) — stable in CN",
        ),
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen3.7-max",
        "max_tokens": 8192,        # Qwen 최대 출력 8K
        "models": [
            # ── Qwen3.7 세대 (최신) ──
            "qwen3.7-max",         # Qwen3.7-Max — 최신 플래그십 (2026-05)
            "qwen3.7-plus",        # Qwen3.7-Plus — 멀티모달 에이전트 (2026-05)
            # ── Qwen3.6 세대 ──
            "qwen3.6-max-preview", # Qwen3.6-Max Preview
            "qwen3.6-plus",        # Qwen3.6-Plus
            "qwen3.6-flash",       # Qwen3.6-Flash
            # ── Qwen3.5 세대 ──
            "qwen3.5-plus",        # Qwen3.5-Plus (2026-04)
            # ── Qwen3 세대 ──
            "qwen3-max",           # Qwen3-Max
            "qwen3-max-2026-01-23", # Qwen3-Max Thinking
            "qwen3-235b-a22b",     # Qwen3 235B A22B (오픈웨이트)
            "qwen3-30b-a3b",       # Qwen3 30B A3B
            # ── Qwen2.5 세대 ──
            "qwen-max",            # Qwen-Max (Qwen2.5-Max 별칭)
            "qwen-plus",           # Qwen-Plus
            "qwen-turbo",          # Qwen-Turbo (저렴)
            "qwen2.5-72b-instruct", # Qwen2.5 72B
            "qwen2.5-32b-instruct", # Qwen2.5 32B
            "qwen2.5-14b-instruct", # Qwen2.5 14B
            "qwen2.5-7b-instruct",  # Qwen2.5 7B
        ],
        "cls": "openai_compat",
        "note": "qwen3.7-max 최신 플래그십 / qwen-turbo 저렴 옵션",
    },
    "ollama": {
        "label": _label(
            ko="Ollama (로컬)",
            zh="Ollama (本地)",
            en="Ollama (Local)",
        ),
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3",
        "max_tokens": 8192,        # 로컬 모델 안전 기본값
        "models": [],  # 동적 조회
        "cls": "openai_compat",
        "note": "로컬 실행 — 모델 목록은 ollama list 로 확인",
    },
    "custom": {
        "label": _label(
            ko="커스텀 / 직접 입력",
            zh="自定义 / 直接输入",
            en="Custom / Enter directly",
        ),
        "base_url": "",
        "default_model": "",
        "max_tokens": 8192,        # 커스텀 안전 기본값
        "models": [],
        "cls": "openai_compat",
        "note": "base_url 과 model 을 직접 입력",
    },
}


class ModelRegistry:
    """설정에서 ModelConfig를 읽어 모델 인스턴스를 반환"""

    @staticmethod
    def build(config: ModelConfig) -> BaseModel:
        provider = config.provider
        info = BUILTIN_PROVIDERS.get(provider, BUILTIN_PROVIDERS["custom"])

        # ── max_tokens 자동 설정 ──────────────────────────────────────────
        # 사용자가 별도 지정(4096 초과)하지 않은 경우, 모델별 최적값 자동 적용
        if config.max_tokens <= 4096:
            config.max_tokens = info.get("max_tokens", 8192)

        if info["cls"] == "claude":
            return ClaudeModel(config)
        return BaseModel(config)

    @staticmethod
    def provider_list(lang: str = "en") -> list[tuple[str, str]]:
        """(id, label) 목록 — lang에 맞는 레이블 반환"""
        return [(k, get_provider_label(v, lang)) for k, v in BUILTIN_PROVIDERS.items()]
