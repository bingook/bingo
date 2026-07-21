from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class MissionMode(str, Enum):
    AUTHORIZED_ASSESSMENT = "authorized_assessment"


class MissionPhase(str, Enum):
    INTAKE = "intake"
    RECON = "recon"
    ENUMERATE = "enumerate"
    VALIDATE = "validate"
    REPORT = "report"
    DONE = "done"
    HALTED = "halted"


class MissionEvent(str, Enum):
    START = "start"
    RECON_COMPLETE = "recon_complete"
    SURFACE_MAPPED = "surface_mapped"
    HYPOTHESIS_READY = "hypothesis_ready"
    EVIDENCE_OBSERVED = "evidence_observed"
    EVIDENCE_CONFIRMED = "evidence_confirmed"
    PLATEAU = "plateau"
    REPORT_REQUESTED = "report_requested"
    REPORT_EMITTED = "report_emitted"
    HALT = "halt"


class EvidenceTier(str, Enum):
    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class MissionScope:
    target: str
    goal: str
    mode: MissionMode = MissionMode.AUTHORIZED_ASSESSMENT
    allowed_hosts: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlannerIntent:
    summary: str
    path: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tool: str = "http_request"
    evidence_goal: str = ""


@dataclass(frozen=True)
class ActionEnvelope:
    tool: str
    url: str
    method: str
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    evidence_goal: str = ""
    summary: str = ""

    def identity_key(self) -> str:
        items = ",".join(f"{k}={self.params[k]}" for k in sorted(self.params))
        return f"{self.tool}|{self.method}|{self.url}|{items}"


@dataclass(frozen=True)
class EvidenceItem:
    key: str
    kind: str
    tier: EvidenceTier
    summary: str
    source_url: str = ""
    source_action: str = ""
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CoveragePoint:
    surface: str
    key: str
    status: str = "seen"


@dataclass(frozen=True)
class LoopSignals:
    progress: bool = False
    recovered_progress: bool = False
    no_progress_count: int = 0
    doom_detected: bool = False
    ledger_skip_count: int = 0
    ledger_skip_total: int = 0
    ledger_skip_streak: int = 0
    low_value_reentry_count: int = 0
    target_drift_count: int = 0
    target_drift_total: int = 0
    target_drift_streak: int = 0


@dataclass(frozen=True)
class DecisionAdvice:
    phase: MissionPhase
    reason: str
    report_now: bool = False
    pivot_now: bool = False
    next_focus: tuple[str, ...] = ()
