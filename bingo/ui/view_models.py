from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class ActivityKind(str, Enum):
    MISSION_STARTED = "mission_started"
    AUTHORIZATION_REQUIRED = "authorization_required"
    AUTHORIZATION_ACCEPTED = "authorization_accepted"
    SCOPE_REJECTED = "scope_rejected"
    PLANNING_STARTED = "planning_started"
    ACTION_STARTED = "action_started"
    ACTION_COMPLETED = "action_completed"
    APPROVAL_REQUIRED = "approval_required"
    EVIDENCE_OBSERVED = "evidence_observed"
    REPORT_STARTED = "report_started"
    REPORT_COMPLETED = "report_completed"
    RUNTIME_FAILED = "runtime_failed"


@dataclass(frozen=True)
class ActivityEvent:
    kind: ActivityKind
    message_key: str
    values: Mapping[str, object] = field(default_factory=dict)
    diagnostics: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ActivityLine:
    text: str


@dataclass(frozen=True)
class ApprovalCard:
    title: str
    description: str
    approval_id: str


@dataclass(frozen=True)
class FindingCard:
    title: str
    summary: str
    status: str


@dataclass(frozen=True)
class ArtifactNotice:
    text: str
    path: str
