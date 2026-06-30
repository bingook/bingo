"""
bingo/roles/manager.py — 역할 기반 테스팅 시스템

역할별 시스템 프롬프트·도구 제한·아이콘을 YAML 파일로 관리.
builtin/ 디렉토리와 사용자 정의 roles_dir 양쪽을 스캔.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class RoleConfig:
    name: str
    description: str = ""
    icon: str = "🎯"
    user_prompt: str = ""
    tools: List[str] = field(default_factory=list)
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "RoleConfig":
        return cls(
            name=d.get("name", "unknown"),
            description=d.get("description", ""),
            icon=d.get("icon", "🎯"),
            user_prompt=d.get("user_prompt", ""),
            tools=d.get("tools", []),
            enabled=d.get("enabled", True),
        )


_BUILTIN_DIR = Path(__file__).parent / "builtin"


class RoleManager:
    """
    역할 관리자 — YAML 파일 기반으로 역할을 로드·전환·조회.
    싱글톤 패턴: `RoleManager.instance()` 로 접근.
    """

    _instance: Optional["RoleManager"] = None
    _roles: Dict[str, RoleConfig] = {}
    _active: Optional[str] = None

    def __init__(self, extra_dir: Optional[str] = None) -> None:
        self._roles = {}
        self._active = None
        self._load_from_dir(_BUILTIN_DIR)
        if extra_dir:
            self._load_from_dir(Path(extra_dir))

    @classmethod
    def instance(cls, extra_dir: Optional[str] = None) -> "RoleManager":
        if cls._instance is None:
            cls._instance = cls(extra_dir)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    # ── 로드 ─────────────────────────────────────────────────────────
    def _load_from_dir(self, path: Path) -> None:
        if not path.is_dir():
            return
        for f in path.glob("*.yaml"):
            self._load_file(f)
        for f in path.glob("*.yml"):
            self._load_file(f)

    def _load_file(self, path: Path) -> None:
        if not _HAS_YAML:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                return
            cfg = RoleConfig.from_dict(data)
            if cfg.enabled:
                self._roles[cfg.name.lower().replace(" ", "_")] = cfg
        except Exception:
            pass

    # ── 조회 ─────────────────────────────────────────────────────────
    def list_roles(self) -> List[RoleConfig]:
        return list(self._roles.values())

    def get(self, key: str) -> Optional[RoleConfig]:
        return self._roles.get(key.lower().replace(" ", "_"))

    def active(self) -> Optional[RoleConfig]:
        if self._active:
            return self._roles.get(self._active)
        return None

    # ── 전환 ─────────────────────────────────────────────────────────
    def switch(self, key: str) -> Optional[RoleConfig]:
        k = key.lower().replace(" ", "_")
        if k in self._roles:
            self._active = k
            return self._roles[k]
        return None

    def clear(self) -> None:
        self._active = None

    # ── 시스템 프롬프트 확장 ──────────────────────────────────────────
    def get_role_prompt(self) -> str:
        """현재 활성 역할의 user_prompt 반환. 없으면 빈 문자열."""
        r = self.active()
        if r and r.user_prompt:
            return f"\n\n[ACTIVE ROLE: {r.name} {r.icon}]\n{r.user_prompt}\n"
        return ""
