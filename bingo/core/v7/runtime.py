from __future__ import annotations

from dataclasses import dataclass
import re
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlparse

from .contracts import (
    ActionEnvelope,
    DecisionAdvice,
    EvidenceItem,
    EvidenceTier,
    LoopSignals,
    MissionEvent,
    MissionPhase,
    MissionScope,
    PlannerIntent,
)
from .coverage import CoverageLedger
from .decision import AssessmentDirector
from .evidence_graph import EvidenceGraph
from .executor_bridge import ExecutorActionBuilder
from . import loop_policy as _loop_policy
from .state_machine import MissionStateMachine


_URL_KEYS = (
    "url",
    "base_url",
    "target_url",
    "login_url",
    "admin_url",
    "webshell_url",
    "verify_url",
    "upload_url",
    "endpoint_url",
)


@dataclass(frozen=True)
class RuntimeStatus:
    target: str
    phase: MissionPhase
    reason: str
    report_now: bool
    next_focus: tuple[str, ...]
    loop_count: int
    plateau_turns: int
    observation_count: int
    candidate_count: int
    confirmed_count: int
    pivot_now: bool = False

    def prompt_block(self) -> str:
        focus = ", ".join(self.next_focus) if self.next_focus else "-"
        return (
            "\n[V7_MISSION]\n"
            f"target={self.target}\n"
            f"phase={self.phase.value}\n"
            f"reason={self.reason}\n"
            f"report_now={str(self.report_now).lower()}\n"
            f"pivot_now={str(self.pivot_now).lower()}\n"
            f"loop_count={self.loop_count}\n"
            f"plateau_turns={self.plateau_turns}\n"
            f"observations={self.observation_count} candidates={self.candidate_count} confirmed={self.confirmed_count}\n"
            f"next_focus={focus}\n"
            "[/V7_MISSION]\n"
        )

    def guidance_message(self, lang: str = "en") -> str:
        focus_items = tuple(str(item).strip() for item in self.next_focus if str(item).strip())
        if not focus_items:
            return ""
        focus_lines = "\n".join(f"{idx}) {item}" for idx, item in enumerate(focus_items, start=1))
        phase = getattr(self.phase, "value", str(self.phase or "")).strip() or "-"
        if lang == "ko":
            return (
                "⚠️ [V7_NEXT_FOCUS] executor state가 반복 대신 구조화된 다음 포커스를 지정했습니다.\n"
                f"authoritative_target={self.target or '-'}\n"
                f"phase={phase}\n"
                f"reason={self.reason or 'executor-owned pivot required'}\n"
                "focus:\n"
                f"{focus_lines}\n"
                "rules:\n"
                "- 모든 새 URL과 액션은 authoritative_target 기준으로만 구성\n"
                "- 위 focus 중 하나만 골라 한정된 검증 1개 실행\n"
                "- 이미 exhausted/no-progress인 동일 action family 재생성 금지"
            )
        if lang == "zh":
            return (
                "⚠️ [V7_NEXT_FOCUS] executor state 已给出结构化下一焦点，而不是继续重复。\n"
                f"authoritative_target={self.target or '-'}\n"
                f"phase={phase}\n"
                f"reason={self.reason or 'executor-owned pivot required'}\n"
                "focus:\n"
                f"{focus_lines}\n"
                "rules:\n"
                "- 所有新 URL 和动作都只从 authoritative_target 构造\n"
                "- 只选择一个 focus，执行一个有边界的验证动作\n"
                "- 不要重放已 exhausted/no-progress 的同类 action family"
            )
        return (
            "⚠️ [V7_NEXT_FOCUS] The executor state assigned a structured next focus instead of repeating the same loop.\n"
            f"authoritative_target={self.target or '-'}\n"
            f"phase={phase}\n"
            f"reason={self.reason or 'executor-owned pivot required'}\n"
            "focus:\n"
            f"{focus_lines}\n"
            "rules:\n"
            "- Build every new URL and action from authoritative_target only\n"
            "- Pick exactly one focus item and run one bounded verifier\n"
            "- Do not replay an action family already marked exhausted/no-progress"
        )

    def action_contract(self, adaptive_pivot_context: str = "") -> str:
        focus_items = tuple(str(item).strip() for item in self.next_focus if str(item).strip())
        if focus_items:
            focus_preview = " / ".join(focus_items[:3])
            return (
                "NEXT ACTION: Follow V7_MISSION next_focus from executor state. "
                f"Pick exactly one bounded verifier from {focus_preview}. "
                "Build new URLs/actions from authoritative_target only. "
                "Do not re-extract known facts or replay exhausted action families.\n"
            )
        if adaptive_pivot_context and "next=cross_vector" in adaptive_pivot_context:
            return (
                "NEXT ACTION: Treat ADAPTIVE_OFFENSE_PIVOT as an AI-led advisory. "
                "Prefer a non-SQLi vector after repeated blocked controls, unless you can state "
                "the new SQLi/WAF hypothesis and execute one distinct bounded verifier. "
                "Do not repeat the same blocked request.\n"
            )
        return (
            "NEXT ACTION: Continue from where you left off. "
            "DO NOT re-extract already known facts above. "
            "Proceed to the next unknown step.\n"
        )


@dataclass
class RuntimeSessionState:
    runtime: MissionRuntimeCoordinator | None = None
    goal: str = ""
    last_status: RuntimeStatus | None = None

    @staticmethod
    def default_goal() -> str:
        return "chat security assessment"

    def effective_goal(self, goal: str = "") -> str:
        clean_goal = str(goal or self.goal or "").strip()
        if clean_goal:
            self.goal = clean_goal
        elif not self.goal:
            self.goal = self.default_goal()
        return str(self.goal or self.default_goal())

    @staticmethod
    def effective_target(agent_state: object, current_target: str = "") -> str:
        target = (
            str(agent_state.get("target") or "") if isinstance(agent_state, dict) else ""
        ) or str(current_target or "")
        return target.strip()

    @staticmethod
    def _runtime_call(runtime, method_name: str, *args, default=None, **kwargs):
        if runtime is None:
            return default
        method = getattr(runtime, method_name, None)
        if not callable(method):
            return default
        try:
            return method(*args, **kwargs)
        except Exception:
            return default

    def bind(self, runtime: MissionRuntimeCoordinator | None) -> "RuntimeSessionState":
        self.runtime = runtime
        return self

    def reset_runtime(self, target: str, goal: str = "") -> None:
        clean_target = str(target or "").strip()
        clean_goal = self.effective_goal(goal)
        if self.runtime is None:
            return
        self._runtime_call(self.runtime, "reset", clean_target, goal=clean_goal, default=None)
        self.last_status = None

    def record_action(
        self,
        tool_name: str,
        args: dict,
        *,
        agent_state: object = None,
        current_target: str = "",
    ) -> None:
        if self.runtime is None:
            return
        target = self.effective_target(agent_state, current_target)
        if not target:
            return
        goal = self.effective_goal()
        self._runtime_call(
            self.runtime,
            "record_action",
            tool_name,
            args,
            target=target,
            goal=goal,
            default=None,
        )

    def observe_loop(self, response: str, result_text: str):
        return self._runtime_call(
            self.runtime,
            "observe_loop_outcome",
            response,
            result_text,
            default=None,
        )

    def reset_loop_window(self, *, full: bool = False) -> None:
        self._runtime_call(self.runtime, "reset_loop_window", full=bool(full), default=None)

    def advance_runtime(
        self,
        *,
        agent_state: object = None,
        current_target: str = "",
        exporter=None,
        progress: bool = False,
        loop_signals: LoopSignals | None = None,
    ):
        if self.runtime is None:
            return None
        target = self.effective_target(agent_state, current_target)
        if not target:
            return None
        goal = self.effective_goal()
        self._runtime_call(self.runtime, "ensure_target", target, goal=goal, default=None)
        status = self._runtime_call(
            self.runtime,
            "advance_loop",
            progress=bool(progress),
            exporter=exporter,
            loop_signals=loop_signals,
            default=None,
        )
        if status is not None:
            self.last_status = status
        return status

    def prompt_block(self) -> str:
        return self._runtime_call(
            self.runtime,
            "prompt_block",
            status=self.last_status,
            default="",
        ) or ""


class MissionRuntimeCoordinator:
    """Bridge between legacy terminal runtime and the new typed v7 core."""

    def __init__(self) -> None:
        self.scope: MissionScope | None = None
        self.mission: MissionStateMachine | None = None
        self.coverage = CoverageLedger()
        self.evidence = EvidenceGraph()
        self.director = AssessmentDirector()
        self._builder: ExecutorActionBuilder | None = None
        self._reset_loop_tracker()

    def _reset_loop_tracker(self) -> None:
        self._loop_response_signatures: list[str] = []
        self._loop_progress_signatures: set[str] = set()
        self._loop_no_progress: int = 0
        self._loop_ledger_skip_total: int = 0
        self._loop_ledger_skip_streak: int = 0
        self._loop_target_drift_total: int = 0
        self._loop_target_drift_streak: int = 0

    def reset_loop_window(self, *, full: bool = False) -> None:
        self._loop_response_signatures = []
        self._loop_no_progress = 0
        if full:
            self._loop_ledger_skip_total = 0
            self._loop_ledger_skip_streak = 0
            self._loop_target_drift_total = 0
            self._loop_target_drift_streak = 0

    def reset(
        self,
        target: str,
        goal: str = "",
        *,
        allowed_hosts: tuple[str, ...] = (),
        constraints: tuple[str, ...] = (),
    ) -> None:
        clean = (target or "").strip()
        if not clean:
            self.scope = None
            self.mission = None
            self.coverage = CoverageLedger()
            self.evidence = EvidenceGraph()
            self._builder = None
            self._reset_loop_tracker()
            return
        self.scope = MissionScope(
            target=clean,
            goal=goal or "chat security assessment",
            allowed_hosts=allowed_hosts,
            constraints=constraints,
        )
        self.mission = MissionStateMachine(self.scope)
        self.mission.apply(MissionEvent.START, goal)
        self.coverage = CoverageLedger()
        self.evidence = EvidenceGraph()
        self._builder = ExecutorActionBuilder(self.scope)
        self._reset_loop_tracker()

    def ensure_target(self, target: str, goal: str = "") -> None:
        clean = (target or "").strip()
        if not clean:
            return
        if self.scope is None or self.scope.target != clean:
            self.reset(clean, goal=goal)

    def prompt_block(self, status: RuntimeStatus | None = None) -> str:
        if status is not None:
            try:
                return status.prompt_block()
            except Exception:
                pass
        if self.mission is None or self.scope is None:
            return ""
        try:
            counts = self.evidence.counts()
        except Exception:
            counts = {"observation": 0, "candidate": 0, "confirmed": 0}
        focus = "-"
        try:
            missing = self.coverage.uncovered(list(self.director.expected_surfaces))
            if missing:
                focus = ", ".join(f"{surface}:{key}" for surface, key in missing[:4])
        except Exception:
            pass
        return (
            "\n[V7_MISSION]\n"
            f"target={self.scope.target}\n"
            f"phase={self.mission.phase.value}\n"
            "reason=executor-owned mission state active; fill missing coverage before deeper validation\n"
            "report_now=false\n"
            "pivot_now=false\n"
            f"loop_count={self.mission.loop_count}\n"
            f"plateau_turns={self.mission.plateau_turns}\n"
            f"observations={counts['observation']} candidates={counts['candidate']} confirmed={counts['confirmed']}\n"
            f"next_focus={focus}\n"
            "[/V7_MISSION]\n"
        )

    def prepare_action(
        self,
        intent: PlannerIntent,
        engagement,
        *,
        now: float,
        approved_identity: str = "",
        action_class=None,
    ):
        """Return an authority decision before dispatching a planner intent."""

        from ..engagement import ActionClass

        self.ensure_target(engagement.scope.target, goal=engagement.goal)
        if self.scope is not None and self.mission is not None:
            self.scope = MissionScope(
                target=self.scope.target,
                goal=self.scope.goal,
                mode=self.scope.mode,
                allowed_hosts=engagement.scope.normalized_hosts(),
                constraints=(
                    f"schemes={','.join(engagement.scope.allowed_schemes)}",
                    f"methods={','.join(engagement.scope.allowed_methods)}",
                    f"max_actions={engagement.scope.max_actions}",
                ),
            )
            self.mission.scope = self.scope
            self._builder = ExecutorActionBuilder(self.scope)
        if self._builder is None:
            raise ValueError("mission runtime has no active target")
        selected_class = action_class or ActionClass.BOUNDED_NETWORK_READ
        return self._builder.prepare(
            intent,
            engagement,
            now=now,
            approved_identity=approved_identity,
            action_class=selected_class,
        )

    def record_execution(self, envelope) -> None:
        """Record coverage only after authority produced an execution envelope."""

        if self.mission is None:
            return
        action = ActionEnvelope(
            tool=envelope.action.capability,
            url=envelope.normalized_url,
            method=envelope.action.method,
            params={
                str(key): str(value)
                for key, value in dict(envelope.action.arguments.get("params", {})).items()
            },
            evidence_goal=envelope.action.evidence_goal,
            summary=envelope.action.summary,
        )
        self.coverage.record_action(action)
        path = urlparse(action.url).path or "/"
        self.coverage.mark("route", path)

    def record_action(self, tool_name: str, args: dict, *, target: str = "", goal: str = "") -> None:
        self.ensure_target(target or (self.scope.target if self.scope else ""), goal=goal)
        if self.mission is None or self._builder is None:
            return
        intent = self._intent_from_tool_call(tool_name, args)
        envelope = self._builder.build(intent)
        self.coverage.record_action(envelope)
        path = urlparse(envelope.url).path or "/"
        self.coverage.mark("route", path)

        lower_path = path.lower()
        param_keys = {str(key).lower() for key in envelope.params}
        if any(token in lower_path for token in ("login", "auth", "admin")) or any(
            token in param_keys for token in ("user", "username", "email", "passwd", "password", "token")
        ):
            self.coverage.mark("surface", "auth")
        if "/api/" in lower_path or lower_path.startswith("/api") or "ajax" in lower_path:
            self.coverage.mark("surface", "api")
        if any(token in lower_path for token in ("composer.json", "composer.lock", "installed.json")):
            self.coverage.mark("surface", "artifact")

        if (
            self.mission.phase == MissionPhase.RECON
            and not self.coverage.uncovered(list(self.director.expected_surfaces))
        ):
            self.mission.apply(MissionEvent.SURFACE_MAPPED, intent.summary)

    def sync_findings(self, exporter) -> None:
        if self.mission is None or exporter is None:
            return
        before = self.evidence.counts()
        items = list(getattr(exporter, "findings", []) or []) + list(getattr(exporter, "quarantined", []) or [])
        for finding in items:
            confidence = str(getattr(finding, "confidence", "") or "").lower()
            confirmed = bool(getattr(finding, "confirmed", False)) or confidence == "confirmed"
            if confirmed:
                tier = EvidenceTier.CONFIRMED
            elif confidence in {"probable", "potential", "inconclusive", "quarantined"}:
                tier = EvidenceTier.CANDIDATE
            else:
                tier = EvidenceTier.OBSERVATION
            key = str(getattr(finding, "scope_key", "") or getattr(finding, "id", "") or "")
            if not key:
                key = f"{getattr(finding, 'vuln_type', 'finding')}:{getattr(finding, 'reason_code', '-')}"
            evidence = str(getattr(finding, "evidence", "") or "").replace("\n", " ").strip()
            self.evidence.add(
                EvidenceItem(
                    key=key,
                    kind=str(getattr(finding, "vuln_type", "") or "finding"),
                    tier=tier,
                    summary=evidence[:180] or str(getattr(finding, "notes", "") or ""),
                    source_url=str(getattr(finding, "target", "") or ""),
                    source_action=str(getattr(finding, "payload", "") or "")[:160],
                    attributes={
                        "severity": str(getattr(finding, "severity", "") or ""),
                        "reason_code": str(getattr(finding, "reason_code", "") or ""),
                    },
                )
            )
        after = self.evidence.counts()
        if after["confirmed"] > before["confirmed"]:
            for _ in range(after["confirmed"] - before["confirmed"]):
                self.mission.apply(MissionEvent.EVIDENCE_CONFIRMED, "v7 evidence sync")
        elif (after["candidate"] + after["observation"]) > (before["candidate"] + before["observation"]):
            self.mission.apply(MissionEvent.EVIDENCE_OBSERVED, "v7 evidence sync")

    def observe_loop_outcome(self, response: str, result_text: str) -> LoopSignals:
        previous_no_progress = self._loop_no_progress

        response_signature = _loop_policy.response_pattern_signature(response or "")
        self._loop_response_signatures.append(response_signature)
        if len(self._loop_response_signatures) > 12:
            self._loop_response_signatures = self._loop_response_signatures[-12:]
        doom_detected = _loop_policy.repeated_response_pattern(self._loop_response_signatures)

        ledger_skip_count = _loop_policy.ledger_skip_count(result_text)
        low_value_reentry_count = _loop_policy.low_value_reentry_count(result_text)
        target_drift_count = _loop_policy.target_drift_block_count(result_text)

        if ledger_skip_count > 0:
            self._loop_ledger_skip_total += ledger_skip_count
            self._loop_ledger_skip_streak += 1
        else:
            self._loop_ledger_skip_streak = 0
        if target_drift_count > 0:
            self._loop_target_drift_total += target_drift_count
            self._loop_target_drift_streak += 1
        else:
            self._loop_target_drift_streak = 0

        progress = _loop_policy.has_meaningful_loop_progress(result_text)
        if progress:
            progress_signature = _loop_policy.meaningful_loop_progress_signature(result_text)
            if progress_signature and progress_signature in self._loop_progress_signatures:
                progress = False
            elif progress_signature:
                self._loop_progress_signatures.add(progress_signature)

        if not progress:
            penalty = max(
                _loop_policy.no_progress_penalty(ledger_skip_count),
                _loop_policy.no_progress_penalty(target_drift_count),
            )
            self._loop_no_progress += penalty
            recovered_progress = False
        else:
            recovered_progress = previous_no_progress > 0
            self._loop_no_progress = 0

        return LoopSignals(
            progress=progress,
            recovered_progress=recovered_progress,
            no_progress_count=self._loop_no_progress,
            doom_detected=doom_detected,
            ledger_skip_count=ledger_skip_count,
            ledger_skip_total=self._loop_ledger_skip_total,
            ledger_skip_streak=self._loop_ledger_skip_streak,
            low_value_reentry_count=low_value_reentry_count,
            target_drift_count=target_drift_count,
            target_drift_total=self._loop_target_drift_total,
            target_drift_streak=self._loop_target_drift_streak,
        )

    def advance_loop(
        self,
        *,
        progress: bool,
        exporter=None,
        loop_signals: LoopSignals | None = None,
    ) -> RuntimeStatus | None:
        if self.mission is None or self.scope is None:
            return None
        self.mission.begin_loop()
        self.sync_findings(exporter)
        if progress:
            self.mission.plateau_turns = 0
        else:
            self.mission.note_no_progress()

        advice = self.director.advise(
            self.mission,
            self.evidence,
            self.coverage,
            loop_signals=loop_signals,
        )
        self._apply_advice(advice)
        counts = self.evidence.counts()
        return RuntimeStatus(
            target=self.scope.target,
            phase=self.mission.phase,
            reason=advice.reason,
            report_now=advice.report_now,
            pivot_now=advice.pivot_now,
            next_focus=advice.next_focus,
            loop_count=self.mission.loop_count,
            plateau_turns=self.mission.plateau_turns,
            observation_count=counts["observation"],
            candidate_count=counts["candidate"],
            confirmed_count=counts["confirmed"],
        )

    def _apply_advice(self, advice: DecisionAdvice) -> None:
        if self.mission is None:
            return
        if advice.report_now and self.mission.phase != MissionPhase.REPORT:
            self.mission.apply(MissionEvent.REPORT_REQUESTED, advice.reason)
            return
        if advice.phase == MissionPhase.ENUMERATE and self.mission.phase == MissionPhase.RECON:
            self.mission.apply(MissionEvent.SURFACE_MAPPED, advice.reason)
        elif advice.phase == MissionPhase.VALIDATE and self.mission.phase in {MissionPhase.RECON, MissionPhase.ENUMERATE}:
            self.mission.apply(MissionEvent.HYPOTHESIS_READY, advice.reason)

    def _intent_from_tool_call(self, tool_name: str, args: dict) -> PlannerIntent:
        args = dict(args or {})
        summary = str(tool_name or "tool")
        method = "GET"
        if str(args.get("method", "")).upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = str(args["method"]).upper()
        elif "post" in summary.lower():
            method = "POST"

        text_blob = "\n".join(
            str(args.get(key, "") or "")
            for key in ("url", "base_url", "target_url", "login_url", "admin_url", "code", "script")
        )
        url = ""
        for key in _URL_KEYS:
            value = str(args.get(key, "") or "").strip()
            if value:
                url = value
                break
        if not url:
            match = re.search(r"https?://[^\s\"'<>]+", text_blob)
            if match:
                url = match.group(0)
        parsed = urlparse(url) if url else SimpleNamespace(path="/", query="")
        path = parsed.path or "/"
        params = {key: value for key, value in parse_qsl(parsed.query, keep_blank_values=True)}

        for key in ("params", "data"):
            payload = args.get(key)
            if isinstance(payload, dict):
                for item_key, item_value in payload.items():
                    params[str(item_key)] = str(item_value)

        if method == "GET":
            code = text_blob.lower()
            if any(marker in code for marker in ("requests.post", "session.post", "curl -x post", "curl -xpost", "curl --request post", "fetch(", "axios.post")):
                method = "POST"

        return PlannerIntent(
            summary=f"{tool_name} {path}",
            path=path,
            method=method,
            params=params,
            evidence_goal=str(args.get("evidence_goal", "") or ""),
            tool=str(tool_name or "tool"),
        )
