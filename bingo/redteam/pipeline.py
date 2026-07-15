"""
Red Team Pipeline — Recon → Scan → Exploit → Report
RedteamAgent 5단계 + TianTi 검증 + Authorization 시스템 통합
"""
from __future__ import annotations
import importlib
import time
from typing import Callable, Any

from .session import RedTeamSession, PhaseResult
from .agent import RedTeamAgent
from .agents import AgentOrchestrator
from .verification import VerificationEngine


PHASE_MODULES = {
    "recon":    "01_recon",
    "scan":     "02_scan",
    "exploit":  "03_exploit",
    "webshell": "04_webshell",   # GIF polyglot/비인증 업로드/AntSword 자동화
    "idor":     "05_idor",       # IDOR + 권한상승 (loan2 실전 패턴)
    "report":   "09_report",
}

DEFAULT_PHASES = ["recon", "scan", "exploit", "webshell", "idor", "report"]


class RedTeamPipeline:
    def __init__(
        self,
        target: str,
        model_config=None,
        output_dir: str = ".",
        on_progress: Callable[[str], None] | None = None,
        auth_ctx=None,   # AuthorizationContext
    ):
        self.target = target.rstrip("/")
        self.session = RedTeamSession(target=self.target)
        self.agent = RedTeamAgent(model_config=model_config)
        self.output_dir = output_dir
        self.log = on_progress or print
        self.auth_ctx = auth_ctx
        self.orchestrator = AgentOrchestrator()
        self.verifier = VerificationEngine()

        # 인가 컨텍스트 없으면 자동 생성
        if not self.auth_ctx:
            from ..core.authorization import create_auth_context
            self.auth_ctx = create_auth_context(target)

        # AI 에이전트에 인가 시스템 프롬프트 주입
        if model_config:
            from ..models.system_prompt import get_pentest_system_prompt
            provider = getattr(model_config, "provider", "deepseek")
            pentest_sys = get_pentest_system_prompt(provider)
            auth_prefix = self.auth_ctx.to_system_prefix()
            # 기존 시스템 프롬프트를 인가된 버전으로 교체
            self.agent.system_override = auth_prefix + "\n\n" + pentest_sys

    def run(self, phases: list[str] | None = None) -> str:
        """파이프라인 전체 실행 — 보고서 경로 반환"""
        if phases is None:
            phases = DEFAULT_PHASES

        self.log(f"\n{'='*60}")
        self.log(f"  ⚔  Bingo Authorized Engagement — {self.target}")
        self.log(f"{'='*60}\n")
        self.log(self.auth_ctx.to_human_notice("ko"))

        for phase in phases:
            if phase == "report":
                continue

            # webshell phase는 exploit에서 관리자 로그인 성공 시에만 자동 실행
            # (또는 phases에 명시적으로 포함된 경우)
            if phase == "webshell":
                exploit_result = self.session.get_phase_findings("exploit")
                admin_logged_in = any(
                    f.get("data", {}).get("admin_login")
                    for f in exploit_result
                    if isinstance(f, dict) and isinstance(f.get("data"), dict)
                )
                # 비인증 업로드도 있으면 webshell 진행
                unauth_upload = any(
                    "unauth_upload:" in str(
                        f.get("data", "") if isinstance(f, dict) else f
                    )
                    for f in exploit_result
                )
                if not admin_logged_in and not unauth_upload and "webshell" not in (phases or []):
                    self.log("[dim]  웹쉘 phase: 관리자 로그인/비인증 업로드 없음 — 스킵[/dim]")
                    continue

            # idor phase는 항상 실행 (비인증 체크 포함)
            # exploit 결과에 관계없이 phpinfo, IDOR 탐지 수행

            self._run_phase(phase)

        # AI 종합 분석
        ai_decision = self.agent.analyze_phase(
            "exploit",
            self.session.all_findings(),
            self.target,
        )
        self.log(f"\n[AI 분석]\n{ai_decision['summary']}\n")

        # 보고서 생성
        report_path = self._run_report()
        self.session.save()

        self.log(f"\n{'='*60}")
        self.log(self.session.summary_table())
        self.log(f"\n📄 보고서: {report_path}")
        self.log(f"{'='*60}\n")

        return report_path

    def _run_phase(self, phase: str):
        module_name = PHASE_MODULES.get(phase)
        if not module_name:
            self.log(f"[SKIP] 알 수 없는 단계: {phase}")
            return

        try:
            mod = importlib.import_module(f"bingo.redteam.phases.{module_name}")
        except ImportError as e:
            self.log(f"[ERROR] {phase} 모듈 로드 실패: {e}")
            return

        self.log(f"\n▶ Phase [{phase.upper()}] 시작")
        pr = PhaseResult(phase=phase, status="running")
        self.session.phases[phase] = pr

        # 컨텍스트에 인가 정보 포함
        context = {
            "auth_ctx": self.auth_ctx,
            "session": self.session,
            "on_progress": self.log,
        }

        try:
            # 새 exploit 모듈은 context 파라미터 받음
            try:
                findings = mod.run_phase(self.target, context, self.session)
            except AttributeError:
                findings = mod.run(self.target, self.session, on_progress=self.log)

            # TianTi 피로 감지기 확인
            should_pivot, pivot_reason = self.verifier.should_pivot()
            if should_pivot:
                self.log(f"[PIVOT] {pivot_reason} — 전략 전환")

            decision = self.agent.analyze_phase(phase, findings, self.target)
            pr.finish(findings, summary=decision["summary"])
            self.session.save()

            # 다음 단계 결과 로그
            if findings:
                severity = findings.get("severity", "info") if isinstance(findings, dict) else "info"
                if severity in ("critical", "high"):
                    self.log(f"[!] {phase.upper()} — 심각한 취약점 발견!")

        except Exception as e:
            pr.status = "error"
            pr.raw_output = str(e)
            self.log(f"[ERROR] {phase}: {e}")

    def _run_report(self) -> str:
        try:
            mod = importlib.import_module("bingo.redteam.phases.09_report")
            return mod.run(self.session, output_dir=self.output_dir, on_progress=self.log)
        except Exception as e:
            self.log(f"[ERROR] 보고서 생성 실패: {e}")
            return ""
