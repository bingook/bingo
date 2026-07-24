"""
bingo/chain/tracker.py — 공격 체인 트래커

대화 세션에서 발견된 취약점·도구 실행·경로를 파싱해
순서 있는 공격 체인으로 재구성. `/chain` 명령으로 출력.
Bingo workspace chain store에 저장.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..core.local_state import workspace_state_dir


def _chain_dir() -> Path:
    d = workspace_state_dir() / "chains"
    d.mkdir(parents=True, exist_ok=True)
    return d


# 공격 체인 단계 유형
STEP_TYPES = {
    "recon":     "🔍",
    "vuln":      "🔴",
    "exploit":   "💥",
    "persist":   "🔒",
    "lateral":   "↔️",
    "exfil":     "📤",
    "tool":      "🔧",
    "cred":      "🔑",
    "access":    "🚪",
}

# 자동 분류 패턴
_CLASSIFY_PATTERNS: List[tuple] = [
    ("cred",    re.compile(r"(password|passwd|credential|hash|token|api.?key|secret)", re.I)),
    ("exfil",   re.compile(r"(dump|exfil|download|extract|export|data.?theft)", re.I)),
    ("persist", re.compile(r"(webshell|backdoor|cron|autorun|persist|rootkit)", re.I)),
    ("lateral", re.compile(r"(lateral|pivot|smb|rdp|ssh|pass.the|kerberos)", re.I)),
    ("exploit", re.compile(r"(rce|exec|shell|payload|exploit|inject|overflow)", re.I)),
    ("vuln",    re.compile(r"(sqli|xss|ssrf|lfi|idor|csrf|xxe|ssti|cve-)", re.I)),
    ("recon",   re.compile(r"(scan|enum|recon|subdomain|port|nmap|ffuf|dirb)", re.I)),
]


@dataclass
class ChainStep:
    seq: int
    step_type: str
    title: str
    detail: str = ""
    target: str = ""
    ts: float = field(default_factory=time.time)

    def icon(self) -> str:
        return STEP_TYPES.get(self.step_type, "▪️")

    def short(self) -> str:
        return f"{self.icon()} [{self.seq:02d}] {self.title}"


class AttackChain:
    """
    공격 체인 — 세션 내 발견/실행 단계를 순서대로 기록.

    사용법:
        chain = AttackChain("sess_abc")
        chain.add("recon", "subfinder on target.com", target="target.com")
        chain.add_from_text("Found SQLi at /login — time-based blind")
        chain.summary()  → 텍스트 요약
    """

    def __init__(self, session_id: str) -> None:
        self._session = session_id
        self._steps: List[ChainStep] = []
        self._path = _chain_dir() / f"{session_id}.json"
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                for s in data.get("steps", []):
                    self._steps.append(ChainStep(**s))
            except Exception:
                pass

    def _save(self) -> None:
        data = {
            "session": self._session,
            "steps": [s.__dict__ for s in self._steps],
        }
        self._path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # ── 추가 ──────────────────────────────────────────────────────────
    def add(
        self,
        step_type: str,
        title: str,
        detail: str = "",
        target: str = "",
    ) -> ChainStep:
        step = ChainStep(
            seq=len(self._steps) + 1,
            step_type=step_type,
            title=title,
            detail=detail,
            target=target,
        )
        self._steps.append(step)
        self._save()
        return step

    def add_from_text(self, text: str, target: str = "") -> Optional[ChainStep]:
        """텍스트에서 단계 유형을 자동 분류 후 추가."""
        for stype, pattern in _CLASSIFY_PATTERNS:
            if pattern.search(text):
                # 첫 60자를 제목으로
                title = text[:60].replace("\n", " ").strip()
                return self.add(stype, title, detail=text, target=target)
        return None

    def clear(self) -> int:
        n = len(self._steps)
        self._steps = []
        self._save()
        return n

    # ── 출력 ──────────────────────────────────────────────────────────
    def steps(self) -> List[ChainStep]:
        return list(self._steps)

    def summary(self) -> str:
        if not self._steps:
            return "(no steps recorded)"
        lines = [f"[ATTACK CHAIN — {self._session}]"]
        for s in self._steps:
            lines.append(s.short())
            if s.target:
                lines.append(f"      target: {s.target}")
        lines.append(f"\n  Total: {len(self._steps)} steps")
        return "\n".join(lines)

    def stats(self) -> Dict[str, int]:
        s: Dict[str, int] = {}
        for step in self._steps:
            s[step.step_type] = s.get(step.step_type, 0) + 1
        return s


class ChainRegistry:
    _chains: Dict[str, AttackChain] = {}

    @classmethod
    def get(cls, session_id: str) -> AttackChain:
        if session_id not in cls._chains:
            cls._chains[session_id] = AttackChain(session_id)
        return cls._chains[session_id]
