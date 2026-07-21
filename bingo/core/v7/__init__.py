"""Bingo v7 core.

This package is the replacement foundation for the legacy "model drives
everything" flow. The UI/chat shell can stay, but execution state, target
identity, evidence, and coverage move into explicit contracts here.
"""

from .contracts import (
    ActionEnvelope,
    CoveragePoint,
    DecisionAdvice,
    EvidenceItem,
    EvidenceTier,
    LoopSignals,
    MissionEvent,
    MissionMode,
    MissionPhase,
    MissionScope,
    PlannerIntent,
)
from .coverage import CoverageLedger
from .decision import AssessmentDirector
from .evidence_graph import EvidenceGraph
from .executor_bridge import ExecutorActionBuilder
from .reporting import (
    ArtifactConvergencePlan,
    EvidenceSnapshot,
    FindingsArtifactSnapshot,
    NextStepSuggestion,
    NextStepPlan,
    ReportArtifactPlan,
    ReportGroundTruthSnapshot,
    ReportSessionSnapshot,
    build_artifact_convergence_plan,
    build_html_report,
    build_next_step_prompt,
    build_report_generation_prompt,
    build_evidence_based_next_steps,
    build_fallback_report,
    filter_verified_report_credentials,
    filter_next_steps_by_evidence,
    next_step_panel_title,
    parse_next_step_response,
    resolve_report_artifact_plan,
    sanitize_next_step_summary,
    validate_report_finding_ids,
)
from .runtime import MissionRuntimeCoordinator, RuntimeSessionState, RuntimeStatus
from .state_machine import MissionStateMachine

__all__ = [
    "ActionEnvelope",
    "AssessmentDirector",
    "ArtifactConvergencePlan",
    "CoverageLedger",
    "CoveragePoint",
    "DecisionAdvice",
    "EvidenceGraph",
    "EvidenceItem",
    "EvidenceSnapshot",
    "EvidenceTier",
    "ExecutorActionBuilder",
    "FindingsArtifactSnapshot",
    "LoopSignals",
    "MissionEvent",
    "MissionMode",
    "MissionPhase",
    "MissionRuntimeCoordinator",
    "MissionScope",
    "MissionStateMachine",
    "NextStepSuggestion",
    "NextStepPlan",
    "PlannerIntent",
    "ReportArtifactPlan",
    "ReportGroundTruthSnapshot",
    "ReportSessionSnapshot",
    "build_artifact_convergence_plan",
    "build_html_report",
    "build_next_step_prompt",
    "RuntimeSessionState",
    "RuntimeStatus",
    "build_report_generation_prompt",
    "build_evidence_based_next_steps",
    "build_fallback_report",
    "filter_verified_report_credentials",
    "filter_next_steps_by_evidence",
    "next_step_panel_title",
    "parse_next_step_response",
    "resolve_report_artifact_plan",
    "sanitize_next_step_summary",
    "validate_report_finding_ids",
]
