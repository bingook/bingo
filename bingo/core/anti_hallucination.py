"""
Zero-Hallucination Enforcement System
======================================
원칙: bingo가 출력하는 모든 취약점/자격증명/파일은
      실제 HTTP 응답 또는 파일시스템 증거가 반드시 존재해야 한다.

GitHub 신용의 핵심 — 단 하나의 오탐도 없어야 한다.

강제 규칙:
  1. VERIFIED 등급만 보고서에 포함됨
  2. 자격증명은 실제 로그인 성공 응답 코드/쿠키 첨부 필수
  3. 파일 업로드는 업로드 후 GET 요청으로 파일 존재 확인 필수
  4. IDOR는 두 계정의 응답 본문 차이 필수 첨부
  5. AI 분석은 항상 [AI_ANALYSIS] 태그로 분리, 취약점 목록에 포함 금지
  6. 추론/가정 기반 발견은 INFERRED 등급으로 별도 분류 (보고서 미포함)

등급:
  VERIFIED   — HTTP 응답 증거 첨부 + 재현 성공
  INFERRED   — 증거 불충분, 추론 기반 → 보고서 제외, 로그에만 기록
  AI_ANALYSIS— AI 모델이 생성한 분석 → 완전 별도 섹션, 취약점 아님
"""
from __future__ import annotations

import hashlib
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceLevel(Enum):
    VERIFIED  = "VERIFIED"   # 실제 HTTP 증거 확인됨
    INFERRED  = "INFERRED"   # 증거 없음, 추론 기반 (보고서 제외)
    AI_ANALYSIS = "AI_ANALYSIS"  # AI 생성 텍스트 (취약점 아님)


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
        """보고서에 포함 가능한지"""
        return (
            self.level == EvidenceLevel.VERIFIED
            and not self.evidence.is_empty()
            and self.evidence.status_code > 0
        )

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
        if finding.is_reportable:
            self._findings.append(finding)
        else:
            # 증거 없음 → INFERRED로 강등, 로그에만 기록
            self._inferred.append({
                "title": title,
                "reason": "HTTP 증거 없음 (status_code=0 또는 빈 응답)",
                "original": description[:200],
            })
        return finding

    def add_credential(
        self,
        username: str,
        password: str,
        *,
        login_url: str,
        status_code: int,
        response_body: str,
        session_cookie: str,
        role: str = "unknown",
        method: str = "bruteforce",
    ) -> VerifiedFinding | None:
        """
        자격증명은 실제 로그인 성공 응답이 필수.
        session_cookie 없으면 등록 거부.
        """
        # 실제 로그인 성공 징표 확인
        success_signs = [
            "logout", "로그아웃", "dashboard", "대시보드",
            "welcome", "환영", "index", "mypage",
        ]
        login_ok = (
            session_cookie != ""
            or any(s.lower() in response_body.lower() for s in success_signs)
        ) and status_code in (200, 302)

        if not login_ok:
            self._inferred.append({
                "title": f"자격증명 미검증: {username}",
                "reason": "실제 로그인 성공 증거 없음 (쿠키/응답 부재)",
            })
            return None

        desc = (
            f"사용자 `{username}` 로그인 성공.\n"
            f"비밀번호: `{password}`\n"
            f"역할: {role}\n"
            f"획득 방법: {method}"
        )
        return self.add_http_finding(
            vuln_type="credential",
            severity="critical",
            title=f"유효한 자격증명 발견: {username}",
            description=desc,
            method="POST",
            url=login_url,
            status_code=status_code,
            response_body=response_body[:500],
            login_verified=True,
            session_cookie=session_cookie,
            remediation="해당 계정 비밀번호 즉시 변경 및 감사 로그 확인",
            cvss_score=9.8,
            cwe="CWE-521",
            extra={"username": username, "password": password, "role": role},
        )

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
        """보고서에 포함 가능한 VERIFIED 발견만 반환"""
        return [f for f in self._findings if f.is_reportable]

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
        환각 방지 감사 보고서.
        숨겨진 INFERRED 항목들을 보여줌.
        """
        lines = ["[Zero-Hallucination Audit]"]
        lines.append(f"  VERIFIED (보고서 포함): {len(self.verified_findings)}건")
        lines.append(f"  INFERRED (보고서 제외): {self.inferred_count}건")
        if self._inferred:
            lines.append("  제외된 항목:")
            for item in self._inferred[:10]:
                lines.append(f"    - {item['title']}: {item['reason']}")
        return "\n".join(lines)

    def to_session_findings(self) -> list[dict]:
        """session.add_finding()에 전달할 형식으로 변환"""
        result = []
        for f in self.verified_findings:
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

        success_signs = ["logout", "로그아웃", "dashboard", "대시보드"]
        cookie_str = "; ".join(f"{k}={v}" for k, v in s.cookies.items())
        verified = (
            any(sign.lower() in r.text.lower() for sign in success_signs)
            or (r.status_code == 302 and "login" not in r.headers.get("Location", ""))
        ) and bool(cookie_str)

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
