from __future__ import annotations

from dataclasses import dataclass

from .contracts import DecisionAdvice, EvidenceTier, LoopSignals, MissionPhase
from .coverage import CoverageLedger
from .evidence_graph import EvidenceGraph
from .state_machine import MissionStateMachine


@dataclass
class AssessmentDirector:
    """Executor-owned decision kernel for the new chat agent.

    The planner model may propose ideas, but phase changes and report timing
    come from concrete state here.
    """

    expected_surfaces: tuple[tuple[str, str], ...] = (
        ("route", "/"),
        ("surface", "auth"),
        ("surface", "api"),
    )

    @staticmethod
    def _dedupe_focus(items: list[str], limit: int = 4) -> tuple[str, ...]:
        ordered: list[str] = []
        for item in items:
            clean = str(item or "").strip()
            if clean and clean not in ordered:
                ordered.append(clean)
            if len(ordered) >= limit:
                break
        return tuple(ordered)

    def _missing_surface_focus(
        self,
        missing: list[tuple[str, str]],
        coverage: CoverageLedger,
    ) -> tuple[str, ...]:
        focus: list[str] = []
        for surface, key in missing:
            if surface == "route" and key == "/":
                focus.extend(("route:/", "route:robots.txt"))
            elif surface == "surface" and key == "auth":
                focus.extend(("auth:login_entry", "auth:session_boundary"))
            elif surface == "surface" and key == "api":
                focus.extend(("api:index_probe", "api:error_paths"))
            elif surface == "surface" and key == "artifact":
                focus.extend(("artifact:manifest_fetch", "artifact:secret_reuse"))
            else:
                focus.append(f"{surface}:{key}")
        for route in coverage.route_keys(exclude_root=True, limit=2):
            focus.append(f"route-neighbor:{route}")
        return self._dedupe_focus(focus)

    def _evidence_kind_focus(
        self,
        evidence: EvidenceGraph,
        *,
        tier: EvidenceTier,
    ) -> tuple[str, ...]:
        focus: list[str] = []
        for kind in evidence.strongest_kinds(tier=tier, limit=2):
            if kind == "user_enumeration":
                focus.extend(("auth:session_boundary", "auth:privilege_separation"))
            elif kind == "info_disclosure":
                focus.extend(("artifact:impact_validation", "artifact:secret_reuse"))
            elif kind == "sqli":
                focus.extend(("db:impact_validation", "db:minimum_proof"))
            elif kind == "idor":
                focus.extend(("api:object_access", "auth:horizontal_access"))
            else:
                focus.append(f"evidence:{kind}")
        return self._dedupe_focus(focus)

    def _validation_focus(
        self,
        evidence: EvidenceGraph,
        coverage: CoverageLedger,
    ) -> tuple[str, ...]:
        focus: list[str] = list(self._evidence_kind_focus(evidence, tier=EvidenceTier.CANDIDATE))
        if coverage.has("surface", "auth"):
            focus.append("auth:session_boundary")
        if coverage.has("surface", "api"):
            focus.append("api:error_paths")
        if coverage.has("surface", "artifact"):
            focus.append("artifact:manifest_fetch")
        for route in coverage.route_keys(exclude_root=True, limit=2):
            focus.append(f"route-neighbor:{route}")
        if coverage.has("surface", "auth"):
            focus.append("auth:password_reset")
        if coverage.has("surface", "api"):
            focus.append("api:object_access")
        if coverage.has("surface", "artifact"):
            focus.append("artifact:secret_reuse")
        if not focus:
            focus.extend(("auth_flow", "artifact_exposure", "api_error_paths"))
        return self._dedupe_focus(focus)

    def _confirmed_focus(
        self,
        evidence: EvidenceGraph,
        coverage: CoverageLedger,
    ) -> tuple[str, ...]:
        focus: list[str] = list(self._evidence_kind_focus(evidence, tier=EvidenceTier.CONFIRMED))
        focus.append("report_artifacts")
        focus.append("impact_validation")
        if coverage.has("surface", "api"):
            focus.append("api:authorization_matrix")
        return self._dedupe_focus(focus)

    @staticmethod
    def _loop_signals_default(loop_signals: LoopSignals | None) -> LoopSignals:
        return loop_signals if loop_signals is not None else LoopSignals()

    def _scope_reanchor_focus(self, coverage: CoverageLedger) -> tuple[str, ...]:
        focus: list[str] = ["target:authoritative_scope", "route:/"]
        if coverage.has("surface", "auth"):
            focus.append("auth:login_entry")
        elif coverage.has("surface", "api"):
            focus.append("api:index_probe")
        for route in coverage.route_keys(exclude_root=True, limit=2):
            focus.append(f"route-neighbor:{route}")
        return self._dedupe_focus(focus)

    def _should_report_confirmed(
        self,
        mission: MissionStateMachine,
        loop_signals: LoopSignals,
    ) -> bool:
        if mission.should_report():
            return True
        if mission.confirmed_count <= 0:
            return False
        if loop_signals.no_progress_count >= 4 and mission.loop_count >= 10:
            return True
        if loop_signals.low_value_reentry_count >= 2 and mission.loop_count >= 12:
            return True
        if loop_signals.target_drift_total >= 4:
            return True
        return False

    def _should_report_exhausted_negative(
        self,
        mission: MissionStateMachine,
        missing: list[tuple[str, str]],
        loop_signals: LoopSignals,
    ) -> bool:
        if mission.confirmed_count > 0:
            return False
        if missing:
            return False
        if mission.loop_count >= 30 and loop_signals.no_progress_count >= 6:
            return True
        if mission.plateau_turns >= 2 and loop_signals.ledger_skip_total >= 6 and mission.loop_count >= 24:
            return True
        return False

    def _pressure_validation_focus(
        self,
        evidence: EvidenceGraph,
        coverage: CoverageLedger,
        missing: list[tuple[str, str]],
        loop_signals: LoopSignals,
    ) -> tuple[str, ...]:
        if loop_signals.target_drift_count > 0:
            return self._scope_reanchor_focus(coverage)
        if missing:
            return self._missing_surface_focus(missing, coverage)
        if loop_signals.low_value_reentry_count > 0:
            focus: list[str] = []
            if coverage.has("surface", "api"):
                focus.append("api:object_access")
            if coverage.has("surface", "auth"):
                focus.append("auth:session_boundary")
            if coverage.has("surface", "artifact"):
                focus.append("artifact:impact_validation")
            return self._dedupe_focus(focus or list(self._validation_focus(evidence, coverage)))
        return self._validation_focus(evidence, coverage)

    def advise(
        self,
        mission: MissionStateMachine,
        evidence: EvidenceGraph,
        coverage: CoverageLedger,
        loop_signals: LoopSignals | None = None,
    ) -> DecisionAdvice:
        counts = evidence.counts()
        missing = coverage.uncovered(list(self.expected_surfaces))
        signals = self._loop_signals_default(loop_signals)

        if self._should_report_confirmed(mission, signals):
            return DecisionAdvice(
                phase=MissionPhase.REPORT,
                reason="confirmed evidence plateau reached; stop expanding loops and report current findings",
                report_now=True,
            )
        if self._should_report_exhausted_negative(mission, missing, signals):
            return DecisionAdvice(
                phase=MissionPhase.REPORT,
                reason="coverage and executor action families are exhausted without confirmed findings; report retained candidates and negative proof instead of extending the loop",
                report_now=True,
            )

        if mission.phase == MissionPhase.INTAKE:
            return DecisionAdvice(
                phase=MissionPhase.RECON,
                reason="mission just started; establish baseline surfaces before testing hypotheses",
                next_focus=("baseline_http", "route_map", "auth_surface"),
            )

        if signals.target_drift_count > 0:
            return DecisionAdvice(
                phase=mission.phase,
                reason="target drift was blocked by the executor; rebuild the next action from authoritative target scope only",
                pivot_now=True,
                next_focus=self._scope_reanchor_focus(coverage),
            )

        if missing:
            focus = self._missing_surface_focus(missing, coverage)
            if (
                mission.plateau_turns >= 2
                or signals.ledger_skip_count >= 2
                or signals.ledger_skip_streak >= 2
                or signals.ledger_skip_total >= 6
            ):
                return DecisionAdvice(
                    phase=MissionPhase.RECON if mission.phase == MissionPhase.RECON else MissionPhase.ENUMERATE,
                    reason="critical surface coverage is still incomplete and the current executor family is exhausted; pivot to the missing surfaces instead of retrying the same probes",
                    pivot_now=True,
                    next_focus=focus,
                )
            return DecisionAdvice(
                phase=MissionPhase.RECON if mission.phase == MissionPhase.RECON else MissionPhase.ENUMERATE,
                reason="coverage is incomplete; fill missing high-value surfaces before deeper validation",
                next_focus=focus,
            )

        if counts["confirmed"] > 0:
            if signals.low_value_reentry_count >= 2 or signals.no_progress_count >= 4:
                return DecisionAdvice(
                    phase=MissionPhase.VALIDATE,
                    reason="confirmed evidence exists, but the current loop is re-entering low-value families; pivot to impact-only validation and report artifacts",
                    pivot_now=True,
                    next_focus=self._confirmed_focus(evidence, coverage),
                )
            return DecisionAdvice(
                phase=MissionPhase.VALIDATE,
                reason="confirmed evidence exists; validate impact and collect only directly related proof",
                next_focus=self._confirmed_focus(evidence, coverage),
            )

        if (
            mission.plateau_turns >= 2
            or signals.doom_detected
            or signals.no_progress_count >= 6
            or signals.ledger_skip_count >= 2
            or signals.ledger_skip_streak >= 2
            or signals.ledger_skip_total >= 6
            or signals.low_value_reentry_count >= 2
        ):
            return DecisionAdvice(
                phase=MissionPhase.VALIDATE,
                reason="no confirmed evidence after repeated executor pressure; pivot to one distinct bounded hypothesis instead of replaying the same action family",
                pivot_now=True,
                next_focus=self._pressure_validation_focus(evidence, coverage, missing, signals),
            )

        return DecisionAdvice(
            phase=MissionPhase.VALIDATE,
            reason="surface coverage exists but no confirmed evidence yet; run distinct validation on highest-value hypotheses",
            next_focus=self._validation_focus(evidence, coverage),
        )
