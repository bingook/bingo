from .base import BaseModel, ClaudeModel, ModelConfig

# ── 내장 프로바이더 정보 ──────────────────────────────────────────
BUILTIN_PROVIDERS: dict[str, dict] = {
    "deepseek": {
        "label": "DeepSeek V4 Pro  ★ 추천",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-v4-pro",        # 실제 Pro 모델 ID (deepseek-chat → flash로 변경됨)
        "models": [
            "deepseek-v4-pro",     # DeepSeek V4 Pro (최신, 권장) ← 반드시 이것만 사용
            "deepseek-reasoner",   # DeepSeek R2 (추론 특화)
        ],
        "cls": "openai_compat",
        "recommended": True,
        "note": "모의침투 기본 추천 모델 — deepseek-v4-pro 전용 (deepseek-chat은 flash로 전락)",
    },
    "claude": {
        "label": "Anthropic Claude",
        "base_url": "https://api.anthropic.com/v1",
        "default_model": "claude-opus-4-5",
        "models": [
            "claude-opus-4-5", "claude-sonnet-4-5", "claude-haiku-3-5",
            "claude-3-7-sonnet-20250219",
        ],
        "cls": "claude",
    },
    "openai": {
        "label": "OpenAI GPT",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3"],
        "cls": "openai_compat",
    },
    "glm": {
        "label": "Zhipu GLM",
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "default_model": "glm-4",
        "models": ["glm-4", "glm-4-flash", "glm-4v", "glm-z1-flash"],
        "cls": "openai_compat",
    },
    "qwen": {
        "label": "Alibaba Qwen",
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "default_model": "qwen-turbo",
        "models": ["qwen-turbo", "qwen-plus", "qwen-max", "qwen3-235b-a22b"],
        "cls": "openai_compat",
    },
    "ollama": {
        "label": "Ollama (로컬)",
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3",
        "models": [],  # 동적 조회
        "cls": "openai_compat",
    },
    "custom": {
        "label": "커스텀 / 직접 입력",
        "base_url": "",
        "default_model": "",
        "models": [],
        "cls": "openai_compat",
    },
}


class ModelRegistry:
    """설정에서 ModelConfig를 읽어 모델 인스턴스를 반환"""

    @staticmethod
    def build(config: ModelConfig) -> BaseModel:
        provider = config.provider
        info = BUILTIN_PROVIDERS.get(provider, BUILTIN_PROVIDERS["custom"])
        if info["cls"] == "claude":
            return ClaudeModel(config)
        return BaseModel(config)

    @staticmethod
    def provider_list() -> list[tuple[str, str]]:
        """(id, label) 목록"""
        return [(k, v["label"]) for k, v in BUILTIN_PROVIDERS.items()]
