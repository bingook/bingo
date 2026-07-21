from __future__ import annotations

from dataclasses import dataclass, field

from . import executor_state as _executor_state

try:
    from .v7 import MissionRuntimeCoordinator, RuntimeSessionState
except ImportError:
    MissionRuntimeCoordinator = None  # type: ignore[assignment]
    RuntimeSessionState = None  # type: ignore[assignment]


@dataclass
class AssessmentSessionBridge:
    """Own terminal-adjacent execution state in one place.

    The terminal should not separately manage action-ledger state and v7 runtime
    session state. This bridge keeps those executor-owned objects together while
    preserving compatibility with older terminal fields/tests.
    """

    runtime_session: object | None = None
    action_ledger: _executor_state.ActionLedger = field(
        default_factory=_executor_state.ActionLedger
    )

    @staticmethod
    def _default_runtime_session():
        if RuntimeSessionState is None:
            return None
        runtime = MissionRuntimeCoordinator() if MissionRuntimeCoordinator is not None else None
        return RuntimeSessionState(runtime=runtime)

    @classmethod
    def create(cls) -> "AssessmentSessionBridge":
        return cls(
            runtime_session=cls._default_runtime_session(),
            action_ledger=_executor_state.ActionLedger(),
        )

    @classmethod
    def coerce(
        cls,
        value: object,
        *,
        action_ledger: object = None,
        runtime_session: object = None,
    ) -> "AssessmentSessionBridge":
        bridge = value if isinstance(value, cls) else cls.create()
        bridge.action_ledger = _executor_state.ActionLedger.coerce(
            action_ledger if action_ledger is not None else bridge.action_ledger
        )
        if runtime_session is not None:
            bridge.runtime_session = runtime_session
        elif bridge.runtime_session is None:
            bridge.runtime_session = cls._default_runtime_session()
        return bridge

    def action_identity(self, tool_name: str, args: dict) -> tuple[dict, str, str]:
        return _executor_state.action_ledger_identity(tool_name, args)

    def action_skip_reason(self, signature: str, summary: str = "") -> str:
        return self.action_ledger.skip_reason(signature, summary)

    def start_action(self, signature: str, summary: str = "", *, loop_count: int = 0) -> dict:
        return self.action_ledger.start(signature, summary, loop_count=loop_count)

    def finish_action(
        self,
        signature: str,
        summary: str = "",
        *,
        output: str = "",
        success: bool = False,
        exit_code: int = -1,
        loop_count: int = 0,
    ) -> dict:
        return self.action_ledger.finish(
            signature,
            summary,
            output=output,
            success=success,
            exit_code=exit_code,
            loop_count=loop_count,
        )

    def action_context(self, *, limit: int = 8) -> str:
        return self.action_ledger.context(limit=limit)

    def reset_runtime(self, target: str, goal: str = "") -> None:
        session = self.runtime_session
        if session is None:
            return
        session.reset_runtime(target, goal=goal)

    def record_action(
        self,
        tool_name: str,
        args: dict,
        *,
        agent_state: object = None,
        current_target: str = "",
    ) -> None:
        session = self.runtime_session
        if session is None:
            return
        session.record_action(
            tool_name,
            args,
            agent_state=agent_state,
            current_target=current_target,
        )

    def observe_loop(self, response: str, result_text: str):
        session = self.runtime_session
        if session is None:
            return None
        return session.observe_loop(response, result_text)

    def advance_runtime(
        self,
        *,
        agent_state: object = None,
        current_target: str = "",
        exporter=None,
        progress: bool = False,
        loop_signals=None,
    ):
        session = self.runtime_session
        if session is None:
            return None
        return session.advance_runtime(
            agent_state=agent_state,
            current_target=current_target,
            exporter=exporter,
            progress=progress,
            loop_signals=loop_signals,
        )

    def prompt_block(self) -> str:
        session = self.runtime_session
        if session is None:
            return ""
        return session.prompt_block()

    def reset_loop_window(self, *, full: bool = False) -> None:
        session = self.runtime_session
        if session is None:
            return
        session.reset_loop_window(full=full)
