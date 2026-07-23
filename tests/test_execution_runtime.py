from bingo.core.execution_runtime import (
    ActionCandidate,
    EvidenceDelta,
    ExecutionObservation,
    MissionPhase,
    MissionRuntime,
    RuntimeDecision,
    reduce_mission,
)


def _observation(action_id: str, output: str = "ok") -> ExecutionObservation:
    return ExecutionObservation.create(
        action_id=action_id,
        target="https://example.test",
        scope_key="GET:/search:q",
        source="tool_call",
        tool_name="http_get",
        arguments={"path": "/search", "param": "q"},
        started_at="2026-07-23T00:00:00Z",
        finished_at="2026-07-23T00:00:01Z",
        completed=True,
        success=True,
        exit_code=0,
        output=output,
    )


def test_more_than_sixty_semantic_progress_events_do_not_end_mission() -> None:
    runtime = MissionRuntime(objective="assess", target="https://example.test")
    for index in range(75):
        candidate = ActionCandidate(
            node_id="crawl",
            target=runtime.target,
            scope_key=f"GET:/page/{index}",
            technique="discover_endpoint",
            evidence_revision=runtime.evidence_revision,
        )
        runtime.pending_action_id = candidate.action_id
        runtime.record_observation(
            _observation(candidate.action_id, f"endpoint /page/{index}"),
            EvidenceDelta(fact_ids=(f"fact-{index}",), coverage_changed=True),
        )
        next_candidate = ActionCandidate(
            node_id="crawl",
            target=runtime.target,
            scope_key=f"GET:/page/{index + 1}",
            technique="discover_endpoint",
            evidence_revision=runtime.evidence_revision,
        )
        assert reduce_mission(
            runtime,
            delta=EvidenceDelta(coverage_changed=True),
            candidates=[next_candidate],
        ) in {RuntimeDecision.CONTINUE, RuntimeDecision.PIVOT}
        assert runtime.phase == MissionPhase.ACTIVE


def test_action_is_exhausted_only_for_unchanged_evidence_revision() -> None:
    runtime = MissionRuntime(objective="assess", target="https://example.test")
    candidate = ActionCandidate(
        node_id="sqli",
        target=runtime.target,
        scope_key="GET:/search:q",
        technique="boolean_oracle",
        evidence_revision=runtime.evidence_revision,
    )
    runtime.record_observation(_observation(candidate.action_id), EvidenceDelta())

    assert not runtime.action_available(candidate)
    assert reduce_mission(runtime, candidates=[candidate]) == RuntimeDecision.REPORT
    assert runtime.phase == MissionPhase.FAILED_NO_ACTION


def test_new_evidence_revision_can_expose_a_new_semantic_action() -> None:
    runtime = MissionRuntime(objective="assess", target="https://example.test")
    first = ActionCandidate(
        node_id="crawl",
        target=runtime.target,
        scope_key="GET:/",
        technique="discover_endpoint",
        evidence_revision=runtime.evidence_revision,
    )
    runtime.record_observation(
        _observation(first.action_id, "found /search?q="),
        EvidenceDelta(fact_ids=("endpoint-search",), coverage_changed=True),
    )
    second = ActionCandidate(
        node_id="sqli",
        target=runtime.target,
        scope_key="GET:/search:q",
        technique="boolean_oracle",
        evidence_revision=runtime.evidence_revision,
    )

    assert runtime.action_available(second)
    assert reduce_mission(runtime, candidates=[second]) == RuntimeDecision.PIVOT
    assert runtime.phase == MissionPhase.ACTIVE


def test_empty_frontier_immediately_reports_incomplete() -> None:
    runtime = MissionRuntime(objective="assess", target="https://example.test")
    assert reduce_mission(runtime, candidates=[]) == RuntimeDecision.REPORT
    assert runtime.phase == MissionPhase.FAILED_NO_ACTION
    assert runtime.terminal_reason == "useful_action_frontier_exhausted"


def test_pending_work_prevents_premature_report() -> None:
    runtime = MissionRuntime(
        objective="assess",
        target="https://example.test",
        pending_work=1,
    )
    assert reduce_mission(runtime, candidates=[]) == RuntimeDecision.CONTINUE
    assert runtime.phase == MissionPhase.ACTIVE


def test_provider_failure_is_terminal_and_serializable() -> None:
    runtime = MissionRuntime(objective="assess", target="https://example.test")
    runtime.record_provider_failure(
        {"kind": "invalid_request", "status_code": 400, "retryable": False}
    )
    restored = MissionRuntime.from_dict(runtime.to_dict())
    assert restored.phase == MissionPhase.FAILED_PROVIDER
    assert reduce_mission(restored) == RuntimeDecision.REPORT
    assert restored.provider_failure["status_code"] == 400
