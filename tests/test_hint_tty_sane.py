"""v6.2.183: hint 먹통 근본 원인(raw tty) 재현 + 치료 검증.

실제 사용자 터미널 없이 PTY 로:
  1) raw 모드(ICANON·ECHO off) 를 만들어 먹통 상태 재현
  2) BingoTerminal._force_tty_sane() 호출
  3) ICANON+ECHO 복구 확인
  4) 라인 입력이 실제로 읽히는지 확인
"""
from __future__ import annotations

import os
import select
import sys
import termios
import tty
import unittest


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
        from types import SimpleNamespace

        # BingoTerminal 전체 초기화 없이 normalize만 테스트
        obj = SimpleNamespace(
            _agent_state={"target": "https://example.com", "findings": ["sqli"]},
            config=SimpleNamespace(lang="zh"),
        )
        out = BingoTerminal._normalize_mid_task_hint(obj, "继续")
        self.assertIn("中断后继续", out)
        self.assertIn("example.com", out)
        self.assertNotEqual(out, "继续")


if __name__ == "__main__":
    unittest.main()
