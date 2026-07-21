from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from bingo.core.session_bridge import AssessmentSessionBridge
from bingo.core.v7 import (
    AssessmentDirector,
    ArtifactConvergencePlan,
    CoverageLedger,
    EvidenceGraph,
    EvidenceItem,
    EvidenceSnapshot,
    EvidenceTier,
    ExecutorActionBuilder,
    FindingsArtifactSnapshot,
    LoopSignals,
    MissionEvent,
    MissionPhase,
    MissionRuntimeCoordinator,
    MissionScope,
    MissionStateMachine,
    NextStepSuggestion,
    PlannerIntent,
    ReportArtifactPlan,
    ReportGroundTruthSnapshot,
    ReportSessionSnapshot,
    RuntimeStatus,
    RuntimeSessionState,
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


def test_executor_action_builder_binds_relative_path_to_canonical_target() -> None:
    scope = MissionScope(target="https://moneyknock.kr", goal="map target")
    builder = ExecutorActionBuilder(scope)
    intent = PlannerIntent(summary="fetch admin login", path="/admin/login.php")

    envelope = builder.build(intent)

    assert envelope.url == "https://moneyknock.kr/admin/login.php"
    assert envelope.method == "GET"


def test_mission_state_machine_reports_after_confirmed_plateau() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))

    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.RECON_COMPLETE)
    mission.apply(MissionEvent.EVIDENCE_CONFIRMED)
    mission.note_no_progress()
    mission.note_no_progress()

    assert mission.should_report() is True


def test_evidence_graph_promotes_weaker_item_to_confirmed() -> None:
    graph = EvidenceGraph()
    graph.add(
        EvidenceItem(
            key="artifact:composer.lock",
            kind="info_disclosure",
            tier=EvidenceTier.OBSERVATION,
            summary="200 on composer.lock",
        )
    )
    graph.add(
        EvidenceItem(
            key="artifact:composer.lock",
            kind="info_disclosure",
            tier=EvidenceTier.CONFIRMED,
            summary="200 plus manifest content",
        )
    )

    confirmed = graph.confirmed()

    assert len(confirmed) == 1
    assert confirmed[0].summary == "200 plus manifest content"


def test_coverage_ledger_detects_repeated_action_identities() -> None:
    scope = MissionScope(target="https://example.kr", goal="assess")
    builder = ExecutorActionBuilder(scope)
    envelope = builder.build(
        PlannerIntent(summary="fetch root", path="/", params={"view": "home"})
    )
    ledger = CoverageLedger()

    ledger.record_action(envelope)
    ledger.record_action(envelope)

    assert ledger.repeated_action(envelope) is True


def test_assessment_director_prioritizes_report_on_confirmed_plateau() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.RECON_COMPLETE)
    mission.apply(MissionEvent.EVIDENCE_CONFIRMED)
    mission.note_no_progress()
    mission.note_no_progress()

    graph = EvidenceGraph()
    graph.add(
        EvidenceItem(
            key="enum:jcorp",
            kind="user_enumeration",
            tier=EvidenceTier.CONFIRMED,
            summary="admin login differential",
        )
    )
    coverage = CoverageLedger()
    director = AssessmentDirector()

    advice = director.advise(mission, graph, coverage)

    assert advice.phase == MissionPhase.REPORT
    assert advice.report_now is True


def test_assessment_director_reports_zero_confirmed_after_exhaustive_executor_pressure() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.SURFACE_MAPPED)
    mission.apply(MissionEvent.HYPOTHESIS_READY)
    mission.loop_count = 30
    mission.plateau_turns = 2

    coverage = CoverageLedger()
    coverage.mark("route", "/")
    coverage.mark("surface", "auth")
    coverage.mark("surface", "api")
    graph = EvidenceGraph()
    director = AssessmentDirector()

    advice = director.advise(
        mission,
        graph,
        coverage,
        loop_signals=LoopSignals(no_progress_count=6, ledger_skip_total=6),
    )

    assert advice.phase == MissionPhase.REPORT
    assert advice.report_now is True


def test_assessment_director_pivots_on_target_drift_signal() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.SURFACE_MAPPED)
    coverage = CoverageLedger()
    coverage.mark("route", "/")
    coverage.mark("surface", "auth")
    graph = EvidenceGraph()
    director = AssessmentDirector()

    advice = director.advise(
        mission,
        graph,
        coverage,
        loop_signals=LoopSignals(target_drift_count=1, target_drift_streak=1),
    )

    assert advice.report_now is False
    assert advice.pivot_now is True
    assert advice.next_focus[0] == "target:authoritative_scope"


def test_assessment_director_uses_missing_surface_focus_after_plateau() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.note_no_progress()
    mission.note_no_progress()

    coverage = CoverageLedger()
    graph = EvidenceGraph()
    director = AssessmentDirector()

    advice = director.advise(mission, graph, coverage)

    assert advice.phase == MissionPhase.RECON
    assert advice.report_now is False
    assert advice.next_focus
    assert "critical surface coverage is still incomplete" in advice.reason
    assert "route:/" in advice.next_focus
    assert "auth:login_entry" in advice.next_focus


def test_assessment_director_builds_surface_specific_validation_focus() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.SURFACE_MAPPED)

    coverage = CoverageLedger()
    coverage.mark("route", "/")
    coverage.mark("route", "/admin/login")
    coverage.mark("surface", "auth")
    coverage.mark("surface", "api")
    coverage.mark("surface", "artifact")
    graph = EvidenceGraph()
    director = AssessmentDirector()

    advice = director.advise(mission, graph, coverage)

    assert advice.phase == MissionPhase.VALIDATE
    assert "auth:session_boundary" in advice.next_focus
    assert "api:error_paths" in advice.next_focus
    assert "artifact:manifest_fetch" in advice.next_focus


def test_assessment_director_builds_confirmed_kind_specific_focus() -> None:
    mission = MissionStateMachine(MissionScope(target="https://example.kr", goal="assess"))
    mission.apply(MissionEvent.START)
    mission.apply(MissionEvent.SURFACE_MAPPED)
    mission.apply(MissionEvent.EVIDENCE_CONFIRMED)

    coverage = CoverageLedger()
    coverage.mark("route", "/")
    coverage.mark("surface", "auth")
    coverage.mark("surface", "api")
    coverage.mark("surface", "artifact")
    graph = EvidenceGraph()
    graph.add(
        EvidenceItem(
            key="artifact:composer-lock",
            kind="info_disclosure",
            tier=EvidenceTier.CONFIRMED,
            summary="composer.lock exposed",
        )
    )
    director = AssessmentDirector()

    advice = director.advise(mission, graph, coverage)

    assert advice.phase == MissionPhase.VALIDATE
    assert "artifact:impact_validation" in advice.next_focus
    assert "report_artifacts" in advice.next_focus


def test_runtime_coordinator_records_route_and_surface_coverage() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/admin/login?email=test@example.kr"},
        target="https://example.kr",
        goal="chat assessment",
    )
    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/api/users"},
        target="https://example.kr",
        goal="chat assessment",
    )
    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/vendor/composer/installed.json"},
        target="https://example.kr",
        goal="chat assessment",
    )

    assert "route:/admin/login" in runtime.coverage.points
    assert "route:/api/users" in runtime.coverage.points
    assert "surface:auth" in runtime.coverage.points
    assert "surface:api" in runtime.coverage.points
    assert "surface:artifact" in runtime.coverage.points
    assert runtime.mission is not None
    assert runtime.mission.phase == MissionPhase.RECON


def test_runtime_status_renders_guidance_and_action_contract() -> None:
    status = RuntimeStatus(
        target="https://example.kr",
        phase=MissionPhase.VALIDATE,
        reason="surface coverage exists but no confirmed evidence yet",
        report_now=False,
        pivot_now=True,
        next_focus=("auth:session_boundary", "api:error_paths", "artifact:manifest_fetch"),
        loop_count=7,
        plateau_turns=1,
        observation_count=1,
        candidate_count=1,
        confirmed_count=0,
    )

    guidance = status.guidance_message(lang="en")
    contract = status.action_contract(
        adaptive_pivot_context="[ADAPTIVE_OFFENSE_PIVOT]\nnext=cross_vector"
    )

    assert "[V7_NEXT_FOCUS]" in guidance
    assert "authoritative_target=https://example.kr" in guidance
    assert "Follow V7_MISSION next_focus" in contract
    assert "auth:session_boundary / api:error_paths / artifact:manifest_fetch" in contract
    assert "ADAPTIVE_OFFENSE_PIVOT" not in contract


def test_runtime_coordinator_prompt_block_renders_live_snapshot_without_cached_status() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")
    runtime.coverage.mark("route", "/")

    block = runtime.prompt_block()

    assert "[V7_MISSION]" in block
    assert "target=https://example.kr" in block
    assert "reason=executor-owned mission state active" in block
    assert "surface:auth" in block


def test_runtime_coordinator_syncs_confirmed_finding_into_evidence_graph() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    exporter = SimpleNamespace(
        findings=[
            SimpleNamespace(
                scope_key="auth:enum-admin",
                id="finding-1",
                vuln_type="user_enumeration",
                confidence="confirmed",
                confirmed=True,
                evidence="admin account responds differently",
                target="https://example.kr/admin/login",
                payload="email=admin@example.kr",
                severity="medium",
                reason_code="enum_diff",
                notes="confirmed differential",
            )
        ],
        quarantined=[],
    )

    runtime.sync_findings(exporter)
    counts = runtime.evidence.counts()

    assert counts["confirmed"] == 1
    assert runtime.mission is not None
    assert runtime.mission.phase == MissionPhase.VALIDATE


def test_runtime_coordinator_requests_report_after_confirmed_plateau() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    exporter = SimpleNamespace(
        findings=[
            SimpleNamespace(
                scope_key="artifact:composer-lock",
                id="finding-2",
                vuln_type="info_disclosure",
                confidence="confirmed",
                confirmed=True,
                evidence="composer.lock served with dependency list",
                target="https://example.kr/composer.lock",
                payload="GET /composer.lock",
                severity="medium",
                reason_code="artifact_exposed",
                notes="confirmed artifact exposure",
            )
        ],
        quarantined=[],
    )

    first = runtime.advance_loop(progress=False, exporter=exporter)
    second = runtime.advance_loop(progress=False, exporter=exporter)

    assert first is not None
    assert first.report_now is False
    assert second is not None
    assert second.report_now is True
    assert second.phase == MissionPhase.REPORT


def test_runtime_coordinator_emits_pivot_now_for_target_drift_pressure() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    status = runtime.advance_loop(
        progress=False,
        exporter=SimpleNamespace(findings=[], quarantined=[]),
        loop_signals=LoopSignals(target_drift_count=1, target_drift_streak=1),
    )

    assert status is not None
    assert status.pivot_now is True
    assert status.report_now is False


def test_runtime_coordinator_observe_loop_outcome_tracks_and_resets_pressure() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    first = runtime.observe_loop_outcome(
        "probe auth entry",
        "=== TOOL_RESULT: http_get ===\n[ACTION_LEDGER_SKIP] family timeout-exhausted\n[TARGET_DRIFT_BLOCKED]\n=== END TOOL_RESULT ===",
    )

    assert first.progress is False
    assert first.no_progress_count >= 1
    assert first.ledger_skip_count == 1
    assert first.target_drift_count == 1

    runtime.reset_loop_window(full=False)
    second = runtime.observe_loop_outcome(
        "fresh probe",
        "=== TOOL_RESULT: run_python ===\nHTTP 200 OK\n/checkout -> order_id\n=== END TOOL_RESULT ===",
    )

    assert second.no_progress_count == 0


def test_runtime_coordinator_moves_to_enumerate_when_expected_surfaces_are_covered() -> None:
    runtime = MissionRuntimeCoordinator()
    runtime.reset("https://example.kr", goal="chat assessment")

    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/"},
        target="https://example.kr",
        goal="chat assessment",
    )
    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/admin/login?email=test@example.kr"},
        target="https://example.kr",
        goal="chat assessment",
    )
    runtime.record_action(
        "http_get",
        {"url": "https://example.kr/api/users"},
        target="https://example.kr",
        goal="chat assessment",
    )

    assert runtime.mission is not None
    assert runtime.mission.phase == MissionPhase.ENUMERATE


def test_assessment_session_bridge_adopts_legacy_runtime_and_action_state() -> None:
    runtime = MissionRuntimeCoordinator()
    session = RuntimeSessionState(runtime=runtime)
    bridge = AssessmentSessionBridge.coerce(
        None,
        action_ledger={},
        runtime_session=session,
    )

    assert bridge.runtime_session is session
    assert bridge.runtime_session.runtime is runtime
    assert bridge.action_ledger.__class__.__name__ == "ActionLedger"


def test_assessment_session_bridge_routes_runtime_progress_through_single_owner() -> None:
    bridge = AssessmentSessionBridge.create()

    bridge.reset_runtime("https://example.kr", goal="chat assessment")
    bridge.record_action(
        "http_get",
        {"url": "https://example.kr/admin/login?email=test@example.kr"},
        current_target="https://example.kr",
    )
    status = bridge.advance_runtime(
        current_target="https://example.kr",
        exporter=SimpleNamespace(findings=[], quarantined=[]),
        progress=False,
    )

    assert status is not None
    assert "route:/admin/login" in bridge.runtime_session.runtime.coverage.points
    assert "[V7_MISSION]" in bridge.prompt_block()


def test_v7_evidence_snapshot_uses_exporter_stats_contract() -> None:
    snapshot = EvidenceSnapshot.from_exporter(
        SimpleNamespace(
            stats=lambda: {
                "confirmed": 0,
                "probable": 1,
                "potential": 0,
                "potential_critical": 2,
                "potential_high": 1,
                "blocked": 3,
                "quarantined": 4,
            }
        )
    )

    assert snapshot.as_dict() == {
        "confirmed": 0,
        "probable": 1,
        "potential": 3,
        "blocked": 3,
        "quarantined": 4,
    }


def test_v7_next_step_plan_stays_unconfirmed_without_verified_evidence() -> None:
    plan = build_evidence_based_next_steps(
        "ko",
        {"has_potential_sqli": False, "blocked_count": 2, "has_admin_panel": False},
        confirmed_count=0,
        potential_count=0,
    )

    joined = "\n".join((plan.summary, *plan.options))
    assert "confirmed 취약점은 없다" in plan.summary
    assert "쓰면 안 된다" in plan.summary
    assert "login_form_only" in joined


def test_v7_sanitize_next_step_summary_rejects_unverified_takeover_claims() -> None:
    safe = sanitize_next_step_summary(
        "进展摘要：已通过 SQL 注入获取数据库 SinkDB 和管理员哈希，但缺少 shell。",
        {
            "has_confirmed_sqli": False,
            "has_potential_sqli": False,
            "has_real_cred": False,
            "has_upload": False,
            "blocked_count": 2,
        },
        "zh",
        confirmed_count=0,
        potential_count=0,
        claim_sanitizer=lambda text, _confirmed, _potential: text,
    )

    assert "未确认" in safe
    assert "SinkDB" not in safe


def test_v7_report_ground_truth_snapshot_uses_exporter_contract() -> None:
    snapshot = ReportGroundTruthSnapshot.from_exporter(
        SimpleNamespace(
            stats=lambda: {
                "confirmed": 0,
                "probable": 3,
                "potential_high": 2,
                "potential_critical": 0,
            },
            ground_truth_block=lambda: "- id=BINGO-1 tier=potential type=sqli",
            findings=[SimpleNamespace(id="BINGO-1", confidence="probable", vuln_type="sqli")],
            revalidate_quarantined=lambda: 0,
        )
    )

    assert snapshot.confirmed_count == 0
    assert snapshot.potential_count == 5
    assert snapshot.should_force_deterministic_report is True
    assert "EVIDENCE LADDER RULES" in snapshot.prompt_block
    assert "BINGO-1" in snapshot.prompt_block


def test_v7_filter_verified_report_credentials_rejects_password_candidate() -> None:
    filtered = filter_verified_report_credentials(
        [
            "Password: cheomdan",
            {"password": "cheomdan", "source": "login failed candidate"},
            {"username": "admin", "password": "p@ss", "status": "confirmed"},
        ]
    )

    assert filtered == [{"username": "admin", "password": "p@ss", "status": "confirmed"}]


def test_v7_validate_report_finding_ids_rejects_unconfirmed_claims() -> None:
    findings = [
        SimpleNamespace(id="BINGO-0001", confidence="probable", vuln_type="sqli"),
    ]
    report = (
        "# Target: https://example.test\n"
        "## Vulnerabilities Found\n"
        "1. **SQL Injection (BINGO-0001)**\n- exploitable response difference\n"
    )

    valid, errors = validate_report_finding_ids(report, findings)

    assert not valid
    assert errors == ["unconfirmed_claim:BINGO-0001"]


def test_v7_build_fallback_report_keeps_unconfirmed_items_out_of_vuln_section() -> None:
    report = build_fallback_report(
        "https://example.test",
        "en",
        confirmed_count=0,
        potential_count=1,
        ground_truth="- id=BINGO-1 tier=potential type=sqli",
        session_credentials=["Password: cheomdan"],
    )

    vuln_section = report.split("## Vulnerabilities Found", 1)[1].split("##", 1)[0]
    assert "BINGO-1" not in vuln_section
    assert "Verification Backlog (Unconfirmed)" in report
    assert "No credentials confirmed in this session" in report


def test_v7_report_session_snapshot_marks_fresh_session_accuracy_notice() -> None:
    snapshot = ReportSessionSnapshot.from_state(
        {"tables": [], "credentials": []},
        session_tables=[],
        session_credentials=[],
        session_fresh=True,
    )

    assert "SESSION ACCURACY NOTICE" in snapshot.origin_note
    assert snapshot.session_credentials == ()


def test_v7_report_session_snapshot_marks_resumed_session_origin() -> None:
    snapshot = ReportSessionSnapshot.from_state(
        {
            "tables": ["g5_member"],
            "credentials": [{"username": "legacy", "password": "oldpass", "status": "confirmed"}],
        },
        session_tables=[],
        session_credentials=[],
        session_fresh=False,
    )

    assert "SESSION ORIGIN NOTICE" in snapshot.origin_note
    assert "g5_member" in snapshot.origin_note
    assert "legacy" in snapshot.origin_note


def test_v7_build_report_generation_prompt_keeps_exact_report_contract() -> None:
    prompt = build_report_generation_prompt(
        target="https://example.test",
        lang="en",
        known_state={"target": "https://example.test"},
        recent_findings_context="assistant finding context",
        ground_truth_prompt_block="\n⚠️ FINDINGS GROUND TRUTH:\n- id=BINGO-1 tier=potential type=sqli",
        session_snapshot=ReportSessionSnapshot.from_state(
            {"tables": [], "credentials": []},
            session_tables=[],
            session_credentials=[],
            session_fresh=True,
        ),
    )

    assert "[GENERATE FINAL PENTEST REPORT]" in prompt
    assert "# Target: https://example.test" in prompt
    assert "## Vulnerabilities Found (severity: Critical/High/Medium/Low)" in prompt
    assert "BINGO finding ID" in prompt
    assert "assistant finding context" in prompt


def test_v7_resolve_report_artifact_plan_uses_env_override_directory(tmp_path: Path) -> None:
    plan = resolve_report_artifact_plan(
        "https://example.test",
        "20260721_120000",
        env_dir=str(tmp_path),
    )

    assert isinstance(plan, ReportArtifactPlan)
    assert plan.report_dir == tmp_path
    assert plan.report_path == tmp_path / "report_example.test_20260721_120000.md"
    assert plan.html_report_path == tmp_path / "report_example.test_20260721_120000.html"
    assert plan.env_override_used is True


def test_v7_resolve_report_artifact_plan_builds_desktop_dump_target_path(tmp_path: Path) -> None:
    plan = resolve_report_artifact_plan(
        "https://demo.example.test/admin",
        "20260721_120000",
        platform_system="Darwin",
        desktop_dir=tmp_path,
    )

    assert plan.report_dir == tmp_path / "dump" / "demo.example.test_admin"
    assert plan.report_path.name == "report_demo.example.test_admin_20260721_120000.md"


def test_v7_build_artifact_convergence_plan_renders_index_and_appendix(tmp_path: Path) -> None:
    report_path = tmp_path / "report.md"
    html_path = tmp_path / "report.html"
    findings_path = tmp_path / "findings.json"
    session_path = tmp_path / "session.md"
    plan = build_artifact_convergence_plan(
        "https://example.test",
        updated_at="2026-07-21 12:00:00",
        findings_snapshot=FindingsArtifactSnapshot(
            summary="confirmed=1 probable=0",
            findings_brief=(
                {
                    "id": "BINGO-0001",
                    "severity": "high",
                    "vuln_type": "sqli",
                    "title": "Boolean oracle",
                    "confirmed": True,
                },
            ),
        ),
        report_path=report_path,
        findings_path=findings_path,
        html_path=html_path,
        session_path=session_path,
    )

    assert isinstance(plan, ArtifactConvergencePlan)
    assert plan.index_path == tmp_path / "INDEX_example.test.md"
    assert "Bingo Session Index" in plan.markdown
    assert "confirmed=1 probable=0" in plan.markdown
    assert "## Converged Artifacts" in plan.report_appendix
    assert "HTML_REPORT:" in plan.session_pointer
    assert plan.payload["findings_snapshot"][0]["id"] == "BINGO-0001"


def test_v7_next_step_panel_title_uses_language_label() -> None:
    assert next_step_panel_title("ko") == "다음 권장 단계"
    assert next_step_panel_title("zh") == "建议下一步"


def test_v7_build_next_step_prompt_embeds_ground_truth_and_hint_contract() -> None:
    prompt = build_next_step_prompt(
        target="https://example.test",
        current_state={"target": "https://example.test"},
        lang="en",
        recent_context="recent assistant context",
        ground_truth="- id=BINGO-1 tier=potential type=sqli",
        evidence_flags={"blocked_count": 2, "has_real_cred": False},
        summary_label="Summary",
        options_label="Next Options",
        option_hint="exact bingo command or instruction",
    )

    assert "[NEXT STEP SUGGESTIONS — PENTEST CONTINUATION]" in prompt
    assert "recent assistant context" in prompt
    assert "FINDINGS GROUND TRUTH" in prompt
    assert "exact bingo command or instruction" in prompt


def test_v7_parse_next_step_response_extracts_summary_and_options() -> None:
    parsed = parse_next_step_response(
        "进展摘要: 当前未确认漏洞。\n\n下一步选项:\n1. 继续解析 main.do 菜单链接\n2. 复测 SQLi/WAF oracle\n",
        option_markers=("下一步选项", "Next Options"),
    )

    assert isinstance(parsed, NextStepSuggestion)
    assert parsed.summary_lines == ("进展摘要: 当前未确认漏洞。",)
    assert parsed.options == ("继续解析 main.do 菜单链接", "复测 SQLi/WAF oracle")


def test_v7_filter_next_steps_by_evidence_removes_post_exploit_without_proof() -> None:
    filtered = filter_next_steps_by_evidence(
        [
            "使用 SQLMap 的 os-shell 功能尝试执行系统命令（whoami / id）",
            "通过堆叠查询向 g5_member 表插入新管理员账户",
            "检查 admin/admin.login.php 是否存在默认凭证或简单密码",
            "枚举同一域名下的 JS/API 端点寻找新输入点",
        ],
        {
            "has_confirmed_sqli": False,
            "has_potential_sqli": False,
            "has_real_cred": False,
            "has_upload": False,
            "has_admin_panel": False,
            "blocked_count": 2,
        },
    )

    joined = "\n".join(filtered)
    assert "os-shell" not in joined
    assert "插入新管理员" not in joined
    assert "默认凭证" not in joined
    assert "JS/API" in joined


def test_v7_build_html_report_escapes_content_and_keeps_finding_badges() -> None:
    html = build_html_report(
        "# Target: <script>alert(1)</script>\n"
        "## Summary\n"
        "- **Critical** candidate BINGO-0001\n"
        "```bash\ncurl -sk https://example.test/\n```\n",
        target="<script>alert(1)</script>",
        confirmed_count=0,
        potential_count=1,
        generated_at="2026-07-21 12:00:00",
    )

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert 'class="report-card"' in html
    assert 'class="finding-id">BINGO-0001' in html
    assert "curl -sk https://example.test/" in html
    assert "2026-07-21 12:00:00" in html
