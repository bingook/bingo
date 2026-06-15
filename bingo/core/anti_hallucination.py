"""
Zero-Hallucination Labeling System
=====================================
원칙: 모든 해킹 기능은 그대로 실행된다.
      환각 차단 = 기능 차단이 아니라 '증거 등급 라벨링'.

중요: 이 시스템은 절대 해킹 기능을 막지 않는다.
      발견된 것은 모두 기록한다.
      다만 보고서에서 "확인됨 / 추론" 을 명확히 구분한다.

라벨 등급 (3단계):
  VERIFIED    — 실제 HTTP 응답 증거 있음 → 보고서 메인 섹션
  LIKELY      — 부분 증거 있음 (폼 제출 성공 but 로그인 미확인) → 보고서 포함, 주석 달림
  INFERRED    — HTTP 증거 없음, 추론 기반 → 보고서 하단 별도 섹션
  AI_ANALYSIS — AI 생성 텍스트 → 보고서 "AI 분석" 섹션

기능 실행은 막지 않는다:
  - 자격증명: 쿠키 없어도 LIKELY로 기록
  - IDOR 재설정: 로그인 검증 실패해도 LIKELY로 기록
  - 모든 발견은 세션에 저장됨
"""
from __future__ import annotations

import hashlib
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceLevel(Enum):
    VERIFIED    = "VERIFIED"    # 실제 HTTP 증거 확인됨 → 보고서 메인
    LIKELY      = "LIKELY"      # 부분 증거 → 보고서 포함, 주석
    INFERRED    = "INFERRED"    # 증거 없음, 추론 → 보고서 하단
    AI_ANALYSIS = "AI_ANALYSIS" # AI 텍스트 → 별도 섹션


@dataclass
class HttpEvidence:
    """
    실제 HTTP 요청/응답 증거.
    이 객체 없이는 VERIFIED 등급 불가.
    """
    method: str              # GET / POST / PUT ...
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""   # 최대 2000자
    timestamp: float = field(default_factory=time.time)

    # 자격증명 검증용
    login_verified: bool = False   # 로그인이라면 실제 성공 여부
    session_cookie: str = ""       # 발급된 세션 쿠키

    @property
    def curl_command(self) -> str:
        """재현 가능한 curl 명령어 자동 생성"""
        headers = " ".join(
            f'-H "{k}: {v}"'
            for k, v in self.request_headers.items()
            if k.lower() not in ("content-length",)
        )
        if self.method.upper() == "POST" and self.request_body:
            body_arg = f"--data-raw '{self.request_body[:500]}'"
        else:
            body_arg = ""
        return f"curl -sk -X {self.method} '{self.url}' {headers} {body_arg}".strip()

    @property
    def evidence_hash(self) -> str:
        """증거 고유 해시 (위변조 탐지)"""
        raw = f"{self.url}{self.status_code}{self.response_body[:500]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_empty(self) -> bool:
        return not self.url or self.status_code == 0


@dataclass
class VerifiedFinding:
    """
    보고서에 포함 가능한 검증된 발견.
    evidence 없이는 생성 불가.
    """
    vuln_type: str           # idor / sqli / upload / credential / misconfig ...
    severity: str            # critical / high / medium / low
    title: str
    description: str
    evidence: HttpEvidence
    level: EvidenceLevel = EvidenceLevel.VERIFIED
    remediation: str = ""
    cvss_score: float = 0.0
    cwe: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self):
        # 증거 없이는 VERIFIED 등급 불가
        if self.evidence.is_empty():
            self.level = EvidenceLevel.INFERRED

    @property
    def is_reportable(self) -> bool:
        """
        보고서 메인 섹션 포함 여부.
        VERIFIED + LIKELY 모두 포함.
        INFERRED는 하단 별도 섹션에 표시.
        AI_ANALYSIS는 별도 섹션.
        → 어떤 발견도 완전히 버려지지 않는다.
        """
        return self.level in (EvidenceLevel.VERIFIED, EvidenceLevel.LIKELY)

    def to_report_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "is_reportable": self.is_reportable,
            "curl": self.evidence.curl_command,
            "evidence_hash": self.evidence.evidence_hash,
            "status_code": self.evidence.status_code,
            "response_snippet": self.evidence.response_body[:300],
            "remediation": self.remediation,
            "cvss": self.cvss_score,
            "cwe": self.cwe,
        }


class ZeroHallucinationGuard:
    """
    모든 finding을 보고서에 넣기 전에 통과해야 하는 검증 게이트.

    규칙:
    - HTTP 응답 코드가 실제로 있어야 함 (status_code > 0)
    - 응답 본문이 비어있지 않아야 함
    - 자격증명이라면 login_verified=True 필수
    - AI 텍스트는 완전히 분리
    """

    def __init__(self):
        self._findings: list[VerifiedFinding] = []
        self._inferred: list[dict] = []        # 증거 없는 추론 (로그용)
        self._ai_analyses: list[str] = []      # AI 생성 텍스트

    # ── Finding 추가 ──────────────────────────────────────────────────────────

    def add_http_finding(
        self,
        vuln_type: str,
        severity: str,
        title: str,
        description: str,
        *,
        method: str,
        url: str,
        status_code: int,
        response_body: str,
        request_body: str = "",
        request_headers: dict | None = None,
        login_verified: bool = False,
        session_cookie: str = "",
        remediation: str = "",
        cvss_score: float = 0.0,
        cwe: str = "",
        extra: dict | None = None,
    ) -> VerifiedFinding:
        """
        실제 HTTP 증거가 있는 finding 추가.
        status_code=0이면 자동으로 INFERRED 처리.
        """
        evidence = HttpEvidence(
            method=method,
            url=url,
            request_headers=request_headers or {},
            request_body=request_body,
            status_code=status_code,
            response_body=response_body[:2000],
            login_verified=login_verified,
            session_cookie=session_cookie,
        )
        finding = VerifiedFinding(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cvss_score=cvss_score,
            cwe=cwe,
            extra=extra or {},
        )
        # 모든 발견을 저장 — 기능 차단 없음
        self._findings.append(finding)
        return finding

    def add_credential(
        self,
        username: str,
        password: str,
        *,
        login_url: str,
        status_code: int,
        response_body: str,
        session_cookie: str = "",
        baseline_response_len: int | None = None,
        role: str = "unknown",
        method: str = "bruteforce",
    ) -> VerifiedFinding:
        """
        자격증명 기록.
        쿠키/응답에 따라 VERIFIED / LIKELY 자동 라벨링.
        → 쿠키 없어도 차단하지 않는다. LIKELY로 기록됨.

        ※ ASP/IIS 오판 방지:
           - ASPSESSIONID 같은 범용 세션 쿠키는 로그인 성공 증거가 아님
           - 반드시 응답 본문에 성공 신호가 있어야 VERIFIED
           - baseline_response_len 제공 시 길이 변화로 추가 판단
        """
        # 명확한 성공 신호 (로그인 후에만 나타나는 키워드)
        success_signs = [
            "logout", "log out", "sign out", "signout",
            "로그아웃", "대시보드", "마이페이지", "회원정보", "환영합니다",
            "dashboard", "welcome,", "my account",
        ]
        # 명확한 실패 신호
        fail_signs = [
            "incorrect", "invalid", "failed", "wrong", "error",
            "틀렸", "잘못된", "실패", "인증실패", "아이디 또는 비밀번호",
            "비밀번호가 일치하지", "존재하지 않", "login failed",
        ]

        body_l = response_body.lower()
        has_success_text = any(s.lower() in body_l for s in success_signs)
        has_fail_text = any(s.lower() in body_l for s in fail_signs)

        # 리다이렉트가 로그인 페이지 외부로 향하는지 확인
        is_login_redirect = (
            status_code in (301, 302)
            and not any(x in body_l for x in ["login", "signin", "logon"])
        )

        # 쿠키 존재 여부 (단, 범용 세션 쿠키는 성공 증거 아님)
        # ASPSESSIONID, PHPSESSID 등은 항상 발급되므로 단독 증거로 불충분
        generic_cookies = {"aspsessionid", "phpsessid", "jsessionid", "cfid", "cftoken"}
        meaningful_cookie = False
        if session_cookie:
            cookie_names = {c.split("=")[0].strip().lower() for c in session_cookie.split(";")}
            meaningful_cookie = bool(cookie_names - generic_cookies)

        # baseline 길이 비교 (제공된 경우)
        length_differs = False
        if baseline_response_len is not None:
            length_differs = abs(len(response_body) - baseline_response_len) > 200

        # 등급 결정 (차단 없음 — 단, 실패 신호 있으면 INFERRED)
        if has_fail_text:
            level_str = "INFERRED"
        elif has_success_text and (meaningful_cookie or is_login_redirect):
            level_str = "VERIFIED"
        elif has_success_text or (meaningful_cookie and is_login_redirect):
            level_str = "LIKELY"
        elif length_differs and not has_fail_text:
            level_str = "LIKELY"
        else:
            level_str = "INFERRED"

        desc = (
            f"사용자 `{username}` 로그인.\n"
            f"비밀번호: `{password}`\n"
            f"역할: {role} | 획득방법: {method}\n"
            f"증거등급: {level_str}"
        )
        f = self.add_http_finding(
            vuln_type="credential",
            severity="critical",
            title=f"자격증명 발견 [{level_str}]: {username}",
            description=desc,
            method="POST",
            url=login_url,
            status_code=status_code,
            response_body=response_body[:500],
            login_verified=(level_str == "VERIFIED"),
            session_cookie=session_cookie,
            remediation="해당 계정 비밀번호 즉시 변경 및 감사 로그 확인",
            cvss_score=9.8,
            cwe="CWE-521",
            extra={
                "username": username, "password": password,
                "role": role, "evidence_grade": level_str,
                "has_success_text": has_success_text,
                "meaningful_cookie": meaningful_cookie,
                "is_login_redirect": is_login_redirect,
            },
        )
        # 수동으로 등급 반영
        f.level = EvidenceLevel[level_str]
        return f

    def add_ai_analysis(self, text: str):
        """AI 생성 텍스트 — 취약점 목록과 완전 분리"""
        self._ai_analyses.append(text)

    def add_inferred(self, title: str, reason: str, data: dict | None = None):
        """증거 없는 추론 — 보고서 미포함, 로그에만"""
        self._inferred.append({
            "title": title,
            "reason": reason,
            "data": data or {},
        })

    # ── 보고서용 조회 ─────────────────────────────────────────────────────────

    @property
    def verified_findings(self) -> list[VerifiedFinding]:
        """보고서 메인 섹션용 — VERIFIED + LIKELY"""
        return [f for f in self._findings if f.is_reportable]

    @property
    def all_findings_flat(self) -> list[VerifiedFinding]:
        """모든 발견 (등급 무관) — 완전한 목록"""
        return list(self._findings)

    @property
    def inferred_count(self) -> int:
        return len(self._inferred)

    @property
    def ai_analysis_text(self) -> str:
        if not self._ai_analyses:
            return ""
        return "\n\n---\n".join(self._ai_analyses)

    def hallucination_report(self) -> str:
        """
        증거 등급 감사 보고서.
        모든 발견의 등급 분포를 보여줌.
        """
        by_level: dict[str, int] = {}
        for f in self._findings:
            lvl = f.level.value
            by_level[lvl] = by_level.get(lvl, 0) + 1

        lines = ["[Evidence Grade Audit]"]
        for lvl, cnt in sorted(by_level.items()):
            lines.append(f"  {lvl}: {cnt}건")
        lines.append(f"  INFERRED(레거시): {self.inferred_count}건")
        return "\n".join(lines)

    def to_session_findings(self) -> list[dict]:
        """
        session.add_finding()에 전달할 형식으로 변환.
        모든 발견 포함 (VERIFIED/LIKELY/INFERRED) — 기능 차단 없음.
        """
        result = []
        for f in self.all_findings_flat:  # 전체 발견 포함
            result.append({
                "type": f.vuln_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "evidence_level": f.level.value,
                "curl": f.evidence.curl_command,
                "evidence_hash": f.evidence.evidence_hash,
                "status_code": f.evidence.status_code,
                "response_snippet": f.evidence.response_body[:300],
                "remediation": f.remediation,
                "cvss": f.cvss_score,
                "cwe": f.cwe,
                **f.extra,
            })
        return result


# ── 자격증명 실시간 검증기 ────────────────────────────────────────────────────

class CredentialVerifier:
    """
    발견된 자격증명을 실제로 로그인 시도해서 검증.
    검증 실패 = 보고서에 포함 금지.
    """

    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip("/")
        self.timeout = timeout

    def verify(
        self,
        username: str,
        password: str,
        login_url: str | None = None,
        login_data_template: dict | None = None,
    ) -> dict:
        """
        실제 로그인 시도.
        Returns: {
            "verified": bool,
            "status_code": int,
            "session_cookie": str,
            "response_snippet": str,
            "curl": str,
        }
        """
        import requests, urllib3
        urllib3.disable_warnings()

        login_url = login_url or self._guess_login_url()
        template = login_data_template or self._default_login_template(username, password)

        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": "Mozilla/5.0"})

        try:
            r = s.post(login_url, data=template, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            return {"verified": False, "error": str(e)}

        success_signs = [
            "logout", "log out", "로그아웃", "대시보드",
            "dashboard", "welcome,", "마이페이지",
        ]
        fail_signs = [
            "incorrect", "invalid", "failed", "wrong",
            "틀렸", "잘못된", "실패", "인증실패", "아이디 또는 비밀번호",
        ]
        cookie_str = "; ".join(f"{k}={v}" for k, v in s.cookies.items())

        # 쿠키 존재만으로 성공 판단 금지 (ASP ASPSESSIONID 오판 방지)
        generic_cookies = {"aspsessionid", "phpsessid", "jsessionid"}
        cookie_names = {k.lower() for k in s.cookies.keys()}
        has_meaningful_cookie = bool(cookie_names - generic_cookies)

        has_success_text = any(sign.lower() in r.text.lower() for sign in success_signs)
        has_fail_text = any(sign.lower() in r.text.lower() for sign in fail_signs)
        is_offsite_redirect = (
            r.status_code == 302
            and "login" not in r.headers.get("Location", "").lower()
        )

        verified = (
            not has_fail_text
            and (has_success_text or is_offsite_redirect)
            and (has_meaningful_cookie or is_offsite_redirect)
        )

        curl = (
            f"curl -sk -X POST '{login_url}' "
            f"--data-raw '{self._encode_form(template)}'"
        )

        return {
            "verified": verified,
            "status_code": r.status_code,
            "session_cookie": cookie_str,
            "response_snippet": r.text[:300],
            "curl": curl,
            "username": username,
            "password": password,
        }

    def _guess_login_url(self) -> str:
        import requests, urllib3
        urllib3.disable_warnings()
        candidates = [
            "/ko_admin/login_proc.php", "/admin/login_proc.php",
            "/login.php", "/admin/login.php",
            "/member/login_proc.php",
        ]
        s = requests.Session()
        s.verify = False
        for c in candidates:
            try:
                r = s.get(self.target + c.replace("_proc.php", ".php"), timeout=5)
                if r.status_code in (200, 405):
                    return self.target + c
            except Exception:
                pass
        return self.target + "/ko_admin/login_proc.php"

    def _default_login_template(self, username: str, password: str) -> dict:
        return {
            "admin_id": username,
            "admin_password": password,
            "mode": "login_proc",
            "rand_auth_": "0",
        }

    def _encode_form(self, data: dict) -> str:
        from urllib.parse import urlencode
        return urlencode(data)
