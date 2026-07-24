"""v6.2.184: hint 먹통 재현과 Ctrl+C/도구 출력 경합 회귀 검증.

실제 사용자 터미널 없이 PTY 로:
  1) raw 모드(ICANON·ECHO off) 를 만들어 먹통 상태 재현
  2) BingoTerminal._force_tty_sane() 호출
  3) ICANON+ECHO 복구 확인
  4) 라인 입력이 실제로 읽히는지 확인
"""
from __future__ import annotations

import os
import select
import signal
import termios
import threading
import tty
import unittest
from io import StringIO
from types import SimpleNamespace


class TestHintTtySane(unittest.TestCase):
    def test_force_tty_sane_heals_raw_mode(self):
        from bingo.ui.terminal import BingoTerminal

        master, slave = os.openpty()
        try:
            # ── 1) 먹통 상태 재현: raw (ICANON·ECHO off) ──
            tty.setraw(slave)
            before = termios.tcgetattr(slave)
            self.assertFalse(
                before[3] & termios.ICANON,
                "setup failed: expected raw (no ICANON)",
            )
            self.assertFalse(
                before[3] & termios.ECHO,
                "setup failed: expected raw (no ECHO)",
            )

            # ── 2) 근본 치료 ──
            ok = BingoTerminal._force_tty_sane(slave)
            self.assertTrue(ok, "_force_tty_sane must report success")

            after = termios.tcgetattr(slave)
            self.assertTrue(
                after[3] & termios.ICANON,
                "ICANON must be restored (line editing)",
            )
            self.assertTrue(
                after[3] & termios.ECHO,
                "ECHO must be restored (typed chars visible)",
            )
        finally:
            os.close(master)
            os.close(slave)

    def test_line_readable_after_heal(self):
        """raw → heal → 상대편이 'hello\\n' 보내면 readline 성공."""
        from bingo.ui.terminal import BingoTerminal

        master, slave = os.openpty()
        try:
            tty.setraw(slave)
            self.assertTrue(BingoTerminal._force_tty_sane(slave))

            # master 쪽에 입력 주입 (사용자가 타이핑한 것처럼)
            os.write(master, b"hello\n")

            # slave 에서 한 줄 읽기 (hint 경로와 동일)
            rdy, _, _ = select.select([slave], [], [], 2.0)
            self.assertTrue(rdy, "select must wake after line input")
            # 캐노니컬 모드면 readline 가능 — os.read 로 확인
            data = os.read(slave, 64)
            self.assertIn(b"hello", data)
        finally:
            os.close(master)
            os.close(slave)

    def test_normalize_continue_expands(self):
        """continue/继续 단독 → 재개 지시로 확장."""
        from bingo.ui.terminal import BingoTerminal
        # BingoTerminal 전체 초기화 없이 normalize만 테스트
        obj = SimpleNamespace(
            _agent_state={"target": "https://example.com", "findings": ["sqli"]},
            config=SimpleNamespace(lang="zh"),
        )
        out = BingoTerminal._normalize_mid_task_hint(obj, "继续")
        self.assertIn("中断后继续", out)
        self.assertIn("example.com", out)
        self.assertNotEqual(out, "继续")

    def test_second_ctrl_c_cancels_hint_without_exiting_process(self):
        """힌트 입력 중 SIGINT는 SystemExit가 아니라 정상 취소로 변환된다."""
        from bingo.ui.terminal import BingoTerminal

        class _Console:
            file = SimpleNamespace(flush=lambda: None)

            @staticmethod
            def print(*_args, **_kwargs):
                return None

        obj = SimpleNamespace(
            _hint_input_active=threading.Event(),
            _agent_stop_flag=threading.Event(),
            _active_tool_thread=None,
            _session=None,
            config=SimpleNamespace(lang="ko"),
            console=_Console(),
            _force_tty_sane=lambda *_args, **_kwargs: True,
        )
        seen_timeout: list[float] = []

        def _read(**kwargs):
            seen_timeout.append(kwargs["timeout"])
            try:
                os.kill(os.getpid(), signal.SIGINT)
            except KeyboardInterrupt:
                return None
            self.fail("SIGINT must be converted to KeyboardInterrupt")

        obj._read_hint_line_from_tty = _read
        original = signal.getsignal(signal.SIGINT)
        result = BingoTerminal._prompt_mid_task_hint(obj)

        self.assertIsNone(result)
        self.assertEqual(seen_timeout, [300.0])
        self.assertIs(signal.getsignal(signal.SIGINT), original)
        self.assertFalse(obj._hint_input_active.is_set())

    def test_tool_output_proxy_mutes_only_owner_thread(self):
        """hint 중 도구 출력만 숨기고 메인 UI 출력은 계속 전달한다."""
        from bingo.ui.terminal import _ToolThreadOutput

        sink = StringIO()
        hint_active = threading.Event()
        muted = threading.Event()
        proxy = _ToolThreadOutput(
            sink, threading.current_thread(), hint_active, muted
        )

        proxy.write("visible-before\n")
        hint_active.set()
        proxy.write("hidden-during-hint\n")
        hint_active.clear()
        muted.set()
        proxy.write("hidden-after-detach\n")

        forwarded: list[int] = []

        def _ui_writer():
            forwarded.append(proxy.write("visible-from-ui\n"))

        thread = threading.Thread(target=_ui_writer)
        thread.start()
        thread.join(timeout=2.0)

        self.assertEqual(forwarded, [len("visible-from-ui\n")])
        self.assertEqual(sink.getvalue(), "visible-before\nvisible-from-ui\n")


if __name__ == "__main__":
    unittest.main()
