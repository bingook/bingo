"""Executor-owned mission state and semantic convergence.

The model may propose actions and describe outcomes, but only observations from
an executor can advance evidence, exhaust work, or complete a mission.  Runtime
transitions are based on that state, never an iteration counter or prose token.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class MissionPhase(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED_NO_ACTION = "failed_no_action"
    FAILED_PROVIDER = "failed_provider"
    INTERRUPTED = "interrupted"
    REPORTING = "reporting"
    FINALIZED = "finalized"


class RuntimeDecision(str, Enum):
    CONTINUE = "continue"
    PIVOT = "pivot"
    REPORT = "report"


@dataclass(frozen=True)
class TargetIdentity:
    raw: str
    canonical: str
    scheme: str = ""
    host: str = ""

    @classmethod
    def from_target(cls, target: str) -> "TargetIdentity":
        from urllib.parse import urlparse

        raw = str(target or "").strip()
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        scheme = (parsed.scheme or "https").lower()
        host = (parsed.netloc or parsed.path).split("/")[0].lower()
        path = parsed.path if parsed.netloc else ""
        canonical = f"{scheme}://{host}{path.rstrip('/')}"
        return cls(raw=raw, canonical=canonical, scheme=scheme, host=host)

    def scope_key(self, method: str = "GET", path: str = "/", param: str = "") -> str:
        clean_path = path or "/"
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        suffix = f":{param}" if param else ""
        return f"{method.upper()}:{self.host}{clean_path}{suffix}"


@dataclass(frozen=True)
class ActionEnvelope:
    target: TargetIdentity
    technique: str
    method: str = "GET"
    path: str = "/"
    param: str = ""
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    verifier: str = ""
    node_id: str = "executor"
    evidence_revision: str = "initial"

    @property
    def arguments(self) -> dict[str, Any]:
        return {
            "method": self.method.upper(),
            "path": self.path,
            "param": self.param,
            "body": dict(self.body),
            "headers": dict(self.headers),
        }

    @property
    def arguments_digest(self) -> str:
        material = json.dumps(self.arguments, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    def candidate(self) -> "ActionCandidate":
        return ActionCandidate(
            node_id=self.node_id,
            target=self.target.canonical,
            scope_key=self.target.scope_key(self.method, self.path, self.param),
            technique=self.technique,
            verifier=self.verifier,
            arguments_digest=self.arguments_digest,
            evidence_revision=self.evidence_revision,
        )


@dataclass(frozen=True)
class ExecutionObservation:
    observation_id: str
    action_id: str
    target: str
    scope_key: str
    source: str
    tool_name: str
    arguments: dict[str, Any]
    started_at: str
    finished_at: str
    completed: bool
    success: bool
    exit_code: int | None
    output: str
    output_digest: str
    execution_context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        action_id: str,
        target: str,
        scope_key: str,
        source: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        started_at: str,
        finished_at: str,
        completed: bool,
        success: bool,
        exit_code: int | None,
        output: str,
        execution_context: dict[str, Any] | None = None,
    ) -> "ExecutionObservation":
        canonical = json.dumps(
            {
                "action_id": action_id,
                "target": target,
                "scope_key": scope_key,
                "source": source,
                "tool_name": tool_name,
                "arguments": arguments or {},
                "started_at": started_at,
                "finished_at": finished_at,
                "exit_code": exit_code,
                "output": output,
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        observation_id = "OBS-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]
        output_digest = hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest()
        return cls(
            observation_id=observation_id,
            action_id=action_id,
            target=target,
            scope_key=scope_key,
            source=source,
            tool_name=tool_name,
            arguments=dict(arguments or {}),
            started_at=started_at,
            finished_at=finished_at,
            completed=completed,
            success=success,
            exit_code=exit_code,
            output=output,
            output_digest=output_digest,
            execution_context=dict(execution_context or {}),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ExecutionObservation" | None:
        if not isinstance(data, dict):
            return None
        required = {
            "observation_id", "action_id", "target", "scope_key", "source",
            "tool_name", "started_at", "finished_at", "completed", "success",
            "output", "output_digest",
        }
        if not required.issubset(data):
            return None
        return cls(
            observation_id=str(data.get("observation_id") or ""),
            action_id=str(data.get("action_id") or ""),
            target=str(data.get("target") or ""),
            scope_key=str(data.get("scope_key") or ""),
            source=str(data.get("source") or ""),
            tool_name=str(data.get("tool_name") or ""),
            arguments=dict(data.get("arguments") or {}),
            started_at=str(data.get("started_at") or ""),
            finished_at=str(data.get("finished_at") or ""),
            completed=bool(data.get("completed")),
            success=bool(data.get("success")),
            exit_code=data.get("exit_code") if isinstance(data.get("exit_code"), int) else None,
            output=str(data.get("output") or ""),
            output_digest=str(data.get("output_digest") or ""),
            execution_context=dict(data.get("execution_context") or {}),
        )


@dataclass(frozen=True)
class ActionCandidate:
    node_id: str
    target: str
    scope_key: str
    technique: str
    verifier: str = ""
    arguments_digest: str = ""
    evidence_revision: str = ""

    @property
    def action_id(self) -> str:
        canonical = json.dumps(
            {
                "node_id": self.node_id,
                "target": self.target,
                "scope_key": self.scope_key,
                "technique": self.technique,
                "verifier": self.verifier,
                "arguments_digest": self.arguments_digest,
                "evidence_revision": self.evidence_revision,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return "ACT-" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class EvidenceDelta:
    fact_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    promoted_ids: tuple[str, ...] = ()
    invalidated_ids: tuple[str, ...] = ()
    coverage_changed: bool = False
    new_action_ids: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        return bool(
            self.fact_ids
            or self.finding_ids
            or self.promoted_ids
            or self.invalidated_ids
            or self.coverage_changed
            or self.new_action_ids
        )


@dataclass
class MissionRuntime:
    objective: str = ""
    target: str = ""
    phase: MissionPhase = MissionPhase.ACTIVE
    evidence_revision: str = "initial"
    pending_action_id: str = ""
    pending_work: int = 0
    objective_satisfied: bool = False
    terminal_reason: str = ""
    attempted_actions: dict[str, str] = field(default_factory=dict)
    observation_ids: list[str] = field(default_factory=list)
    provider_failure: dict[str, Any] | None = None
    report_artifacts: dict[str, str] = field(default_factory=dict)

    def action_available(self, candidate: ActionCandidate) -> bool:
        return self.attempted_actions.get(candidate.action_id) != self.evidence_revision

    def record_observation(
        self,
        observation: ExecutionObservation,
        delta: EvidenceDelta,
    ) -> None:
        self.observation_ids.append(observation.observation_id)
        self.attempted_actions[observation.action_id] = self.evidence_revision
        self.pending_action_id = ""
        if delta.changed:
            material = json.dumps(
                {
                    "previous": self.evidence_revision,
                    "observation": observation.observation_id,
                    "facts": delta.fact_ids,
                    "findings": delta.finding_ids,
                    "promoted": delta.promoted_ids,
                    "invalidated": delta.invalidated_ids,
                    "coverage": delta.coverage_changed,
                    "actions": delta.new_action_ids,
                },
                sort_keys=True,
            )
            self.evidence_revision = hashlib.sha256(material.encode()).hexdigest()[:16]

    def exhaust_action(self, candidate: ActionCandidate) -> None:
        self.attempted_actions[candidate.action_id] = self.evidence_revision
        self.pending_action_id = ""

    def record_provider_failure(self, failure: dict[str, Any]) -> None:
        self.provider_failure = dict(failure)
        self.phase = MissionPhase.FAILED_PROVIDER
        self.terminal_reason = "provider_failure"
        self.pending_action_id = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["phase"] = self.phase.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "MissionRuntime":
        if not isinstance(data, dict):
            return cls()
        fields = {
            key: value
            for key, value in data.items()
            if key in cls.__dataclass_fields__
        }
        try:
            fields["phase"] = MissionPhase(fields.get("phase", MissionPhase.ACTIVE))
        except ValueError:
            fields["phase"] = MissionPhase.ACTIVE
        return cls(**fields)


def reduce_mission(
    runtime: MissionRuntime,
    *,
    delta: EvidenceDelta | None = None,
    candidates: Iterable[ActionCandidate] = (),
) -> RuntimeDecision:
    """Return the next transition from canonical state only."""
    if runtime.phase in {
        MissionPhase.COMPLETED,
        MissionPhase.FAILED_NO_ACTION,
        MissionPhase.FAILED_PROVIDER,
        MissionPhase.INTERRUPTED,
        MissionPhase.REPORTING,
        MissionPhase.FINALIZED,
    }:
        return RuntimeDecision.REPORT

    if runtime.objective_satisfied:
        runtime.phase = MissionPhase.COMPLETED
        runtime.terminal_reason = "objective_satisfied"
        return RuntimeDecision.REPORT

    if runtime.pending_work > 0 or runtime.pending_action_id:
        return RuntimeDecision.CONTINUE

    available = [candidate for candidate in candidates if runtime.action_available(candidate)]
    if available:
        return RuntimeDecision.CONTINUE if delta and delta.changed else RuntimeDecision.PIVOT

    runtime.phase = MissionPhase.FAILED_NO_ACTION
    runtime.terminal_reason = "useful_action_frontier_exhausted"
    return RuntimeDecision.REPORT
