"""
bingo/hitl/gate.py — Human-In-The-Loop 승인 게이트  (v3.5.6)

위험 작업(RCE 실행, 페이로드 업로드, 민감 DB 덤프 등) 전
사용자에게 확인을 요청. 화이트리스트 등록 시 자동 승인.

v3.5.6 변경:
  - /dev/tty 직접 I/O: prompt_toolkit이 stdin을 점유 중인 백그라운드 스레드에서도
    사용자 입력을 정상 수신 (Application is already running 오류 방지)
  - lang 파라미터 추가: 다국어 확인 메시지 지원
  - check() 에 lang 파라미터 추가
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional, Set


# 위험 키워드 — 이 단어가 포함된 작업은 기본적으로 확인 요청
_DEFAULT_DANGEROUS: List[str] = [
    "exec", "shell", "rce", "drop", "delete", "format",
    "exploit", "payload", "reverse_shell", "c2", "implant",
    "mimikatz", "dump_hash", "privesc",
]


def _tty_prompt(prompt_text: str) -> str:
    """
    /dev/tty 로 직접 출력·입력.

    prompt_toolkit이 stdin을 점유한 상태에서도 동작한다.
    macOS / Linux 공통. Windows에서는 fallback으로 input() 사용.
    """
    tty_path = "/dev/tty"
    if os.path.exists(tty_path):
        try:
            with open(tty_path, "r") as _r, open(tty_path, "w") as _w:
                _w.write(prompt_text)
                _w.flush()
                return _r.readline().strip().lower()
        except OSError:
            pass
    # fallback — Windows 또는 /dev/tty 없는 환경
    try:
        return input(prompt_text).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return ""


class HitlGate:
    """
    HITL 게이트.

    사용법:
        gate = HitlGate()
        if gate.check("run_reverse_shell", target="192.168.1.1", lang="zh"):
            do_action()

    whitelist 에 등록된 작업은 확인 없이 통과.
    enabled=False 이면 모든 작업 자동 통과.
    """

    def __init__(
        self,
        enabled: bool = True,
        whitelist: Optional[List[str]] = None,
        dangerous_keywords: Optional[List[str]] = None,
    ) -> None:
        self.enabled = enabled
        self._whitelist: Set[str] = set(whitelist or [])
        self._dangerous = set(dangerous_keywords or _DEFAULT_DANGEROUS)
        self._always_allow: Set[str] = set()   # 세션 내 "항상 허용" 목록

    # ── 위험 판별 ─────────────────────────────────────────────────────
    def is_dangerous(self, action: str) -> bool:
        a_lower = action.lower()
        return any(kw in a_lower for kw in self._dangerous)

    # ── 메인 게이트 ───────────────────────────────────────────────────
    def check(
        self,
        action: str,
        target: str = "",
        silent: bool = False,
        lang: str = "ko",
    ) -> bool:
        """
        위험 작업 실행 전 호출.
        Returns True → 실행 허용, False → 거부

        lang: 다국어 확인 메시지 언어 ("ko" | "zh" | "en")
        """
        if not self.enabled:
            return True
        if action in self._whitelist or action in self._always_allow:
            return True
        if not self.is_dangerous(action):
            return True

        if silent:
            return False

        # 다국어 프롬프트 문자열 로드
        try:
            from ..lang.strings import get_strings as _gs
            _s = _gs(lang)
        except Exception:
            _s = {}

        label = f"{action}" + (f" → {target}" if target else "")
        _default_prompt = "⚠️  [HITL] Confirm dangerous action: {label}\n  [y/N/a(always)] > "
        prompt_text = _s.get("hitl_confirm_prompt", _default_prompt).format(label=label)

        # /dev/tty 직접 I/O — prompt_toolkit stdin 점유와 충돌 없음
        try:
            ans = _tty_prompt(prompt_text)
        except (EOFError, KeyboardInterrupt):
            ans = ""

        if ans == "a":
            self._always_allow.add(action)
            return True
        return ans in ("y", "yes")

    # ── 화이트리스트 관리 ─────────────────────────────────────────────
    def allow(self, action: str) -> None:
        self._whitelist.add(action)

    def deny(self, action: str) -> None:
        self._whitelist.discard(action)
        self._always_allow.discard(action)

    def whitelist(self) -> List[str]:
        return sorted(self._whitelist | self._always_allow)


# 글로벌 싱글톤
_gate: Optional[HitlGate] = None


def global_gate() -> HitlGate:
    global _gate
    if _gate is None:
        _gate = HitlGate(enabled=True)
    return _gate


def check(action: str, target: str = "", silent: bool = False, lang: str = "ko") -> bool:
    return global_gate().check(action, target, silent, lang)
