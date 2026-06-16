from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field, asdict
from .models.base import ModelConfig


def _config_dir() -> Path:
    """OS별 설정 디렉토리 반환"""
    if sys.platform == "win32":
        # Windows: %APPDATA%\bingo
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "bingo"
    elif sys.platform == "darwin":
        # macOS: ~/Library/Application Support/bingo
        return Path.home() / "Library" / "Application Support" / "bingo"
    else:
        # Linux/BSD: ~/.config/bingo
        xdg = os.environ.get("XDG_CONFIG_HOME", "")
        base = Path(xdg) if xdg else Path.home() / ".config"
        return base / "bingo"


CONFIG_DIR = _config_dir()
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class BingoConfig:
    lang: str = "en"
    active_model: str = ""          # ModelConfig.alias 또는 "provider/model"
    models: list[ModelConfig] = field(default_factory=list)
    system_prompt: str = "You are a helpful assistant."

    # ── 직렬화 ────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        d = asdict(self)
        d["models"] = [asdict(m) for m in self.models]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "BingoConfig":
        models = [ModelConfig(**m) for m in d.get("models", [])]
        return cls(
            lang=d.get("lang", "en"),
            active_model=d.get("active_model", ""),
            models=models,
            system_prompt=d.get("system_prompt", "You are a helpful assistant."),
        )

    # ── 파일 I/O ──────────────────────────────────────────────────
    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls) -> "BingoConfig":
        if CONFIG_FILE.exists():
            try:
                d = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                cfg = cls.from_dict(d)
                # ── deepseek-chat → deepseek-v4-pro 자동 마이그레이션 ──
                # deepseek-chat은 현재 flash 모델로 전락함 (2026년 DeepSeek 정책 변경)
                _migrated = False
                for m in cfg.models:
                    if m.provider == "deepseek" and m.model == "deepseek-chat":
                        m.model = "deepseek-v4-pro"
                        _migrated = True
                if _migrated:
                    cfg.save()  # 마이그레이션 결과 즉시 저장
                return cfg
            except Exception:
                pass
        return cls()

    # ── 헬퍼 ──────────────────────────────────────────────────────
    def get_active_model_config(self) -> ModelConfig | None:
        if not self.models:
            return None
        if self.active_model:
            for m in self.models:
                if m.display_name() == self.active_model or m.alias == self.active_model:
                    return m
        return self.models[0]

    def add_model(self, cfg: ModelConfig) -> None:
        for i, m in enumerate(self.models):
            if m.display_name() == cfg.display_name():
                self.models[i] = cfg
                return
        self.models.append(cfg)
        if not self.active_model:
            self.active_model = cfg.display_name()

    def is_first_run(self) -> bool:
        return not CONFIG_FILE.exists()
