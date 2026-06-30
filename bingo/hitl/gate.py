"""
bingo/hitl/gate.py — Human-In-The-Loop 승인 게이트  (v3.5.14)

위험 작업(RCE 실행, 페이로드 업로드, 민감 DB 덤프 등) 전
사용자에게 확인을 요청. 화이트리스트 등록 시 자동 승인.

v3.5.14 변경 (근본 수정):
  - 백그라운드 스레드에서 HITL 호출 시 메인 스레드에 위임
    (queue + session.app.exit 인터럽트 방식)
  - prompt_toolkit 이 raw mode 로 터미널을 점유한 상태에서도
    Ctrl+C 포함 모든 키 정상 동작
  - termios 기반 cooked mode 복원으로 메인 스레드 직접 I/O 개선
"""
from __future__ import annotations

import os
import queue
import sys
import threading
from typing import Callable, List, Optional, Set

# ── HITL 메인-스레드 위임 브리지 ────────────────────────────────────────────
# 백그라운드 스레드 → 메인 스레드로 HITL 입력 요청/응답을 전달하는 큐
_HITL_REQ: queue.Queue = queue.Queue()   # 백그라운드 → 메인: prompt_text
_HITL_RESP: queue.Queue = queue.Queue()  # 메인 → 백그라운드: answer str

# 메인 스레드의 session.prompt()를 인터럽트하는 콜백 (terminal.py 가 등록)
_interrupt_fn: Optional[Callable[[], None]] = None

# _chat_loop 이 HITL 요청을 인식하는 sentinel 값
HITL_SENTINEL = "__bingo_hitl__"


def register_interrupt_fn(fn: Callable[[], None]) -> None:
    """terminal.py 초기화 시 호출: session.prompt()를 인터럽트하는 콜백 등록."""
    global _interrupt_fn
    _interrupt_fn = fn


def _tty_prompt(prompt_text: str) -> str:
    """
    HITL 입력 획득.

    ┌── 메인 스레드 ──────────────────────────────────────────────────┐
    │  termios cooked mode 복원 후 /dev/tty 직접 읽기                 │
    └─────────────────────────────────────────────────────────────────┘
    ┌── 백그라운드 스레드 (오케스트레이터 등) ─────────────────────────┐
    │  1. prompt_text 를 _HITL_REQ 에 push                           │
    │  2. _interrupt_fn() 호출 → session.prompt() 가 sentinel 반환   │
    │  3. _HITL_RESP 에서 답변 대기 (메인 스레드가 처리 후 put)        │
    └─────────────────────────────────────────────────────────────────┘
    """
    if (threading.current_thread() is not threading.main_thread()
            and _interrupt_fn is not None):
        # ── 백그라운드 스레드 경로 ──
        _HITL_REQ.put(prompt_text)
        try:
            _interrupt_fn()
        except Exception:
            pass
        try:
            return _HITL_RESP.get(timeout=300)
        except queue.Empty:
            return ""

    # ── 메인 스레드 경로: termios cooked mode 복원 후 직접 읽기 ──
    return _tty_prompt_direct(prompt_text)


def _tty_prompt_direct(prompt_text: str) -> str:
    """메인 스레드 전용: /dev/tty + termios cooked mode 복원으로 안전하게 읽기."""
    tty_path = "/dev/tty"
    if not os.path.exists(tty_path):
        try:
            return input(prompt_text).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ""

    try:
        import termios
        _has_termios = True
    except ImportError:
        _has_termios = False

    if not _has_termios:
        try:
            with open(tty_path, "r") as _r, open(tty_path, "w") as _w:
                _w.write(prompt_text)
                _w.flush()
                return _r.readline().strip().lower()
        except OSError:
            return ""

    fd = None
    saved = None
    try:
        fd = os.open(tty_path, os.O_RDWR | os.O_NOCTTY)
        saved = termios.tcgetattr(fd)

        # cooked mode: ICANON + ECHO 활성화 (prompt_toolkit 이 끈 것을 복원)
        cooked = list(saved)
        cooked[0] |= termios.ICRNL              # c_iflag: CR → NL
        cooked[3] |= termios.ICANON | termios.ECHO  # c_lflag
        termios.tcsetattr(fd, termios.TCSADRAIN, cooked)

        os.write(fd, prompt_text.encode("utf-8", errors="replace"))

        line = b""
        while True:
            ch = os.read(fd, 1)
            if not ch or ch in (b"\n", b"\r"):
                break
            if ch == b"\x03":   # Ctrl+C
                raise KeyboardInterrupt
            if ch == b"\x04":   # Ctrl+D / EOF
                break
            if ch in (b"\x7f", b"\x08"):  # Backspace
                if line:
                    line = line[:-1]
                continue
            line += ch

        return line.decode("utf-8", errors="replace").strip().lower()

    except KeyboardInterrupt:
        return ""
    except OSError:
        try:
            return input(prompt_text).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ""
    finally:
        if saved is not None and fd is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            except Exception:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass


# 위험 키워드 — 이 단어가 포함된 작업은 기본적으로 확인 요청
_DEFAULT_DANGEROUS: List[str] = [
    "exec", "shell", "rce", "drop", "delete", "format",
    "exploit", "payload", "reverse_shell", "c2", "implant",
    "mimikatz", "dump_hash", "privesc",
]


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
