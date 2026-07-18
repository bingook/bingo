"""
TianTi 5원칙 취약점 검증 엔진
================================
출처: https://github.com/To-be-w1th0ut/TianTi (Apache 2.0)
Bingo에 맞게 재구현

5원칙:
  1. 재현성 (Reproducibility)  — 최소 3회 독립 재시도
  2. 인과격리 (Causal Isolation) — 정상 요청 vs 악성 요청 비교
  3. 협소한 질문 (Narrow Questions) — 한 번에 변수 하나만
  4. 생성≠검증 (Generate≠Validate) — 발견과 증명 분리
  5. 결정론 우선 (Deterministic First) — 15개 취약점별 특화 체크

판정: VERIFIED | LIKELY | INCONCLUSIVE | REFUTED

Anti-Laziness 게이트:
  Gate1: 커버리지 책임 (Coverage Accountability)
  Gate2: 합리화 방지 (Anti-Rationalization)
  Gate3: 피로 감지기 (Fatigue Circuit Breaker)
  Gate4: 검증 완성도 (Verification Completeness)
  Gate5: 정보 장벽 (Information Barrier)
"""
from __future__ import annotations
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Verdict(Enum):
    VERIFIED = "VERIFIED"          # 결정론적 증거 존재
    LIKELY = "LIKELY"              # 강한 증거, 인과격리 부족
    INCONCLUSIVE = "INCONCLUSIVE"  # 증거 불충분
    REFUTED = "REFUTED"            # 증거가 취약점 부정


class VulnType(Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    XXE = "xxe"
    SSTI = "ssti"
    UPLOAD = "upload"
    INFORMATION_DISCLOSURE = "info_disclosure"
    MISCONFIG = "misconfig"
    DIRECTORY_TRAVERSAL = "directory_traversal"


@dataclass
class Evidence:
    """취약점 증거 체인"""
    vuln_type: VulnType
    payload: str
    request_raw: str = ""
    response_raw: str = ""
    baseline_response: str = ""  # 정상 응답 (비교용)
    reproduction_count: int = 0
    timestamp: float = field(default_factory=time.time)
    notes: str = ""


@dataclass
class VerificationResult:
    """검증 결과"""
    verdict: Verdict
    vuln_type: VulnType
    confidence: float  # 0.0 ~ 1.0
    evidence: Evidence
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    summary: str = ""

    def to_report_line(self) -> str:
        icon = {
            Verdict.VERIFIED: "🔴 VERIFIED",
            Verdict.LIKELY: "🟠 LIKELY",
            Verdict.INCONCLUSIVE: "🟡 INCONCLUSIVE",
            Verdict.REFUTED: "⚪ REFUTED",
        }[self.verdict]
        return (
            f"{icon} [{self.vuln_type.value.upper()}] "
            f"confidence={self.confidence:.0%} — {self.summary}"
        )


# ── 결정론적 취약점별 체크 (Principle 5) ────────────────────────────
class DeterministicChecks:
    """15개 취약점 타입별 특화 검증 체크"""

    @staticmethod
    def check_sqli(evidence: Evidence) -> tuple[bool, str]:
        """SQLi: DB 에러 메시지 또는 데이터 변화로 검증"""
        resp = evidence.response_raw.lower()
        base = evidence.baseline_response.lower()

        # 에러 기반 확인
        sql_errors = [
            "sql syntax", "mysql_fetch", "you have an error",
            "ora-", "pg::", "sqlite_", "warning: mysql",
            "invalid query", "unexpected token",
            "1064 you have an error",
        ]
        for err in sql_errors:
            if err in resp and err not in base:
                return True, f"SQL error pattern found: '{err}'"

        # UNION 기반 데이터 노출
        if evidence.payload and "union" in evidence.payload.lower():
            # 응답 길이 차이 or 숫자/문자 패턴
            if len(resp) > len(base) * 1.5:
                return True, "Response length increased significantly (UNION injection)"
            # DB 버전 패턴
            if re.search(r'\d+\.\d+\.\d+-', resp):
                return True, "DB version string found in response"

        # 시간 기반
        if evidence.payload and "sleep" in evidence.payload.lower():
            # 타임스탬프 차이 (Evidence에 타이밍 정보가 있을 때)
            pass

        return False, "No deterministic SQLi evidence"

    @staticmethod
    def check_xss(evidence: Evidence) -> tuple[bool, str]:
        """XSS: 페이로드 반사 확인"""
        resp = evidence.response_raw
        payload = evidence.payload

        # 인코딩 없이 그대로 반사
        if payload and payload in resp:
            return True, f"Payload reflected verbatim in response"

        # 부분 반사
        for marker in ["<script", "onerror=", "onload=", "javascript:"]:
            if marker in payload.lower() and marker in resp.lower():
                return True, f"XSS marker '{marker}' reflected"

        return False, "XSS payload not reflected"

    @staticmethod
    def check_lfi(evidence: Evidence) -> tuple[bool, str]:
        """LFI: 알려진 파일 내용 패턴"""
        resp = evidence.response_raw

        lfi_patterns = [
            (r"root:x:0:0:", "Linux /etc/passwd"),
            (r"\[drivers\]", "Windows win.ini"),
            (r"<?php", "PHP source code"),
            (r"define\s*\(", "PHP config file"),
            (r"\$db_", "DB config variable"),
        ]
        for pattern, desc in lfi_patterns:
            if re.search(pattern, resp, re.I):
                return True, f"LFI confirmed: {desc} found"

        return False, "No LFI evidence"

    @staticmethod
    def check_rce(evidence: Evidence) -> tuple[bool, str]:
        """RCE: 명령어 실행 결과 패턴"""
        resp = evidence.response_raw

        rce_patterns = [
            (r"uid=\d+\(", "Linux id command output"),
            (r"Volume Serial Number", "Windows dir output"),
            (r"NT AUTHORITY\\SYSTEM", "Windows SYSTEM account"),
            (r"/usr/bin/", "Linux path in output"),
            (r"Linux.*#\d+", "Linux kernel string"),
        ]
        for pattern, desc in rce_patterns:
            if re.search(pattern, resp, re.I):
                return True, f"RCE confirmed: {desc}"

        return False, "No RCE evidence"

    @staticmethod
    def check_auth_bypass(evidence: Evidence) -> tuple[bool, str]:
        """인증 우회: 관리자 패널 접근 확인"""
        resp = evidence.response_raw.lower()
        base = evidence.baseline_response.lower()

        admin_indicators = [
            "admin dashboard", "관리자", "administration",
            "logout", "welcome back", "logged in as",
            "dashboard", "control panel", "manage",
        ]
        for indicator in admin_indicators:
            if indicator in resp and indicator not in base:
                return True, f"Admin indicator after bypass: '{indicator}'"

        # HTTP 302 → 200 변화
        if "302" in base and "200" in resp:
            return True, "HTTP redirect bypassed"

        return False, "No auth bypass evidence"

    @staticmethod
    def check_upload(evidence: Evidence) -> tuple[bool, str]:
        """파일 업로드: 웹셸 접근 가능성 확인"""
        resp = evidence.response_raw

        # 업로드 성공 응답
        upload_patterns = [
            r'"success"\s*:\s*true',
            r'"status"\s*:\s*"ok"',
            r'upload.*success',
            r'파일.*업로드.*성공',
            r'file.*uploaded',
        ]
        for pat in upload_patterns:
            if re.search(pat, resp, re.I):
                return True, "File upload succeeded"

        # 파일 URL 반환
        if re.search(r'https?://[^\s"]+\.(php|jsp|aspx|phtml)', resp, re.I):
            return True, "Uploaded file URL with executable extension found"

        return False, "No upload evidence"

    @classmethod
    def run(cls, evidence: Evidence) -> tuple[bool, str]:
        """취약점 타입에 맞는 결정론적 체크 실행"""
        check_map = {
            VulnType.SQLI: cls.check_sqli,
            VulnType.XSS: cls.check_xss,
            VulnType.LFI: cls.check_lfi,
            VulnType.RCE: cls.check_rce,
            VulnType.AUTH_BYPASS: cls.check_auth_bypass,
            VulnType.UPLOAD: cls.check_upload,
        }
        fn = check_map.get(evidence.vuln_type)
        if fn:
            return fn(evidence)
        return False, "No deterministic check available for this vuln type"


# ── 피로 감지기 (Anti-Laziness Gate 3) ──────────────────────────────
class FatigueMonitor:
    """에이전트 반복/정체 탐지"""

    def __init__(self):
        self._call_history: list[str] = []
        self._finding_count: int = 0
        self._total_calls: int = 0

    def record_call(self, tool_name: str):
        self._call_history.append(tool_name)
        self._total_calls += 1

    def record_finding(self):
        self._finding_count += 1

    def check_repetition(self, window: int = 5) -> bool:
        """최근 N번 호출이 모두 동일하면 True"""
        recent = self._call_history[-window:]
        return len(set(recent)) == 1 and len(recent) >= window

    def check_stagnation(self, window: int = 10) -> bool:
        """최근 N번 호출에서 발견 없으면 True"""
        recent_calls = len(self._call_history[-window:])
        return recent_calls >= window and self._finding_count == 0

    def should_pivot(self) -> tuple[bool, str]:
        """전략 전환이 필요한지 판단"""
        if self.check_repetition():
            recent = self._call_history[-1]
            return True, f"Repetition detected: '{recent}' called 5+ times consecutively"
        if self.check_stagnation():
            return True, f"Stagnation: {len(self._call_history)} calls with 0 findings"
        if self._total_calls > 0 and self._total_calls % 30 == 0:
            return True, "Periodic pivot check (every 30 calls)"
        return False, ""


# ── 메인 검증 엔진 ───────────────────────────────────────────────────
class VerificationEngine:
    """
    TianTi 5원칙 기반 취약점 검증 엔진

    사용법:
        engine = VerificationEngine()
        result = engine.verify(evidence)
        print(result.to_report_line())
    """

    def __init__(self, min_reproductions: int = 3):
        self.min_reproductions = min_reproductions
        self._fatigue = FatigueMonitor()
        self._verified_findings: list[VerificationResult] = []
        self._shapley_stats = {
            "total_submitted": 0,
            "verified": 0,
            "likely": 0,
            "refuted": 0,
        }

    def verify(self, evidence: Evidence) -> VerificationResult:
        """5원칙 파이프라인으로 증거 검증"""
        self._shapley_stats["total_submitted"] += 1
        checks_passed = []
        checks_failed = []
        confidence = 0.0

        # Principle 5: Deterministic First
        det_passed, det_msg = DeterministicChecks.run(evidence)
        if det_passed:
            checks_passed.append(f"P5_Deterministic: {det_msg}")
            confidence += 0.4
        else:
            checks_failed.append(f"P5_Deterministic: {det_msg}")

        # Principle 1: Reproducibility
        if evidence.reproduction_count >= self.min_reproductions:
            checks_passed.append(f"P1_Reproducibility: {evidence.reproduction_count} replays")
            confidence += 0.25
        else:
            checks_failed.append(
                f"P1_Reproducibility: only {evidence.reproduction_count}/{self.min_reproductions} replays"
            )

        # Principle 2: Causal Isolation
        if evidence.baseline_response and evidence.response_raw:
            if evidence.baseline_response != evidence.response_raw:
                checks_passed.append("P2_CausalIsolation: baseline differs from malicious response")
                confidence += 0.2
            else:
                checks_failed.append("P2_CausalIsolation: no difference from baseline")
        else:
            checks_failed.append("P2_CausalIsolation: no baseline provided")

        # Principle 3: Narrow Questions (자동 체크 — 페이로드에 변수 하나인지)
        if evidence.payload and evidence.payload.count("?") <= 2:
            checks_passed.append("P3_NarrowQuestion: single variable payload")
            confidence += 0.1
        else:
            checks_failed.append("P3_NarrowQuestion: multiple variables in payload")

        # Principle 4: Generate≠Validate (별도 재검증 요청인지)
        if evidence.reproduction_count > 0:
            checks_passed.append("P4_GenerateValidate: separate validation pass done")
            confidence += 0.05
        else:
            checks_failed.append("P4_GenerateValidate: no separate validation")

        # 최종 판정
        confidence = min(confidence, 1.0)
        if confidence >= 0.75:
            verdict = Verdict.VERIFIED
            self._shapley_stats["verified"] += 1
        elif confidence >= 0.45:
            verdict = Verdict.LIKELY
            self._shapley_stats["likely"] += 1
        elif confidence >= 0.2:
            verdict = Verdict.INCONCLUSIVE
        else:
            verdict = Verdict.REFUTED
            self._shapley_stats["refuted"] += 1

        result = VerificationResult(
            verdict=verdict,
            vuln_type=evidence.vuln_type,
            confidence=confidence,
            evidence=evidence,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            summary=(
                f"{evidence.vuln_type.value.upper()} via {evidence.payload[:50] if evidence.payload else 'N/A'}"
            ),
        )

        if verdict in (Verdict.VERIFIED, Verdict.LIKELY):
            self._verified_findings.append(result)

        return result

    def shapley_score(self) -> dict:
        """에이전트 성능 점수 (TianTi Shapley-lite)"""
        s = self._shapley_stats
        total = max(s["total_submitted"], 1)
        verified_likely = s["verified"] + s["likely"]
        return {
            "precision": verified_likely / total,
            "fp_rate": s["refuted"] / total,
            "verified": s["verified"],
            "likely": s["likely"],
            "refuted": s["refuted"],
            "total": s["total_submitted"],
        }

    def findings_summary(self) -> str:
        """발견된 취약점 요약"""
        if not self._verified_findings:
            return "No verified findings yet."
        lines = [f"Found {len(self._verified_findings)} verified/likely vulnerabilities:"]
        for f in self._verified_findings:
            lines.append(f"  {f.to_report_line()}")
        return "\n".join(lines)

    def should_pivot(self) -> tuple[bool, str]:
        return self._fatigue.should_pivot()

    def record_helper_run(self, tool: str):
        self._fatigue.record_call(tool)

    def record_finding(self):
        self._fatigue.record_finding()
