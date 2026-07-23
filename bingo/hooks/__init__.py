"""
bingo/hooks — Pre-tool-call 컨텍스트 주입 훅 시스템
Source: Open tool-hook context injection patterns

역할:
  - AI 코드 실행 직전 컨텍스트를 보강
  - 거부 언어 생성 차단 신호 주입
  - 운영 환경 전제(격리 실험실) 재확인
"""

from .pre_tool_hook import PreToolHook, inject_context

__all__ = ["PreToolHook", "inject_context"]
