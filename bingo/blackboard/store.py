"""
bingo/blackboard/store.py — 프로젝트 블랙보드

타겟별 Facts(발견 사실·경로·자격증명 등)를 세션 간 지속 저장.
~/.bingo/boards/<target_hash>.json 에 저장.
AI 대화 시 시스템 프롬프트 앞에 자동 주입 가능.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _board_dir() -> Path:
    d = Path.home() / ".bingo" / "boards"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _target_key(target: str) -> str:
    return hashlib.sha1(target.encode()).hexdigest()[:12]


class Blackboard:
    """
    타겟 전용 블랙보드.
    facts: {key: {"value": ..., "ts": ...}} 구조로 저장.

    사용법:
        bb = Blackboard("https://target.com")
        bb.upsert("admin_creds", "admin:admin123")
        bb.upsert("rce_path", "/api/upload?cmd=")
        bb.as_context()  → AI 주입용 텍스트
        bb.list()        → [(key, value, ts), ...]
    """

    def __init__(self, target: str) -> None:
        self._target = target
        self._key = _target_key(target)
        self._path = _board_dir() / f"{self._key}.json"
        self._data: Dict[str, Any] = self._load()

    # ── 저장 ─────────────────────────────────────────────────────────
    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"target": self._target, "facts": {}}

    def _save(self) -> None:
        self._path.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ── CRUD ──────────────────────────────────────────────────────────
    def upsert(self, key: str, value: Any) -> None:
        self._data.setdefault("facts", {})[key] = {
            "value": value,
            "ts": time.time(),
        }
        self._save()

    def get(self, key: str) -> Optional[Any]:
        fact = self._data.get("facts", {}).get(key)
        return fact["value"] if fact else None

    def remove(self, key: str) -> bool:
        facts = self._data.get("facts", {})
        if key in facts:
            del facts[key]
            self._save()
            return True
        return False

    def clear(self) -> int:
        n = len(self._data.get("facts", {}))
        self._data["facts"] = {}
        self._save()
        return n

    def list(self) -> List[tuple]:
        """→ [(key, value, iso_time), ...]"""
        import datetime
        facts = self._data.get("facts", {})
        result = []
        for k, v in facts.items():
            ts = v.get("ts", 0)
            dt = datetime.datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
            result.append((k, v.get("value"), dt))
        return sorted(result, key=lambda x: x[2])

    # ── AI 컨텍스트 주입 ──────────────────────────────────────────────
    def as_context(self) -> str:
        """세션 시작 시 시스템 프롬프트에 삽입할 텍스트."""
        facts = self._data.get("facts", {})
        if not facts:
            return ""
        lines = [f"[PROJECT BLACKBOARD — {self._target}]"]
        for k, v in facts.items():
            lines.append(f"  {k}: {v['value']}")
        return "\n".join(lines) + "\n"

    def target(self) -> str:
        return self._target


class BoardRegistry:
    """여러 타겟의 블랙보드를 관리하는 레지스트리."""

    _boards: Dict[str, Blackboard] = {}

    @classmethod
    def get(cls, target: str) -> Blackboard:
        if target not in cls._boards:
            cls._boards[target] = Blackboard(target)
        return cls._boards[target]

    @classmethod
    def list_targets(cls) -> List[str]:
        """저장된 모든 타겟 목록."""
        result = []
        for p in _board_dir().glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                t = data.get("target", "")
                if t:
                    result.append(t)
            except Exception:
                pass
        return result
