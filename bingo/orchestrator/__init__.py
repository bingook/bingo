"""
bingo/orchestrator — LLM 오케스트레이터 패키지

상황 인식 기반 동적 공격 흐름 제어.
고정 파이프라인 대신 LLM이 매 단계마다 최적 다음 액션을 결정.
"""
from .engine import OrchestratorEngine, global_orchestrator

__all__ = ["OrchestratorEngine", "global_orchestrator"]
