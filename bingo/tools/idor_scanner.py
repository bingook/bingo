"""
IDOR Auto-Scanner — 권한 자동 탐지 / 수평·수직 권한 상승 탐지
=============================================================
1. 수평 IDOR: 동일 권한 사용자 간 리소스 교차 접근
2. 수직 IDOR: 일반 사용자 → 관리자 API 직접 접근
3. UUID/GUID/해시 ID 예측 및 열거
4. 응답 비교 기반 자동 확인
"""
from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable


# ══════════════════════════════════════════════════════════════
# ID 패턴 탐지
# ══════════════════════════════════════════════════════════════

ID_PATTERNS = [
    (r"/(\d{1,10})(?:/|$|\?)", "numeric"),
    (r"[?&](?:id|uid|user_id|userId|member_id|memberId|no|seq|idx|num)=(\d+)", "numeric_param"),
    (r"[?&](?:id|uid|user_id)=([a-f0-9]{32})", "md5"),
    (r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)", "uuid"),
    (r"[?&](?:token|key)=([A-Za-z0-9_\-]{20,})", "token"),
    # 한국 사이트 특화
    (r"[?&](?:mb_id|wr_id|bo_table|gr_id)=(\w+)", "gnuboard"),
    (r"[?&](?:uid|vid|pid|cid|oid)=(\d+)", "korean_id"),
]

# IDOR 고위험 엔드포인트 패턴
HIGH_RISK_ENDPOINTS = [
    r"/api/(?:v\d/)?user(?:s)?/",
    r"/api/(?:v\d/)?member(?:s)?/",
    r"/api/(?:v\d/)?account",
    r"/api/(?:v\d/)?profile",
    r"/api/(?:v\d/)?order(?:s)?/",
    r"/api/(?:v\d/)?invoice",
    r"/api/(?:v\d/)?payment",
    r"/api/(?:v\d/)?admin",
    r"/member/(?:view|info|detail|edit)",
    r"/user/(?:view|info|detail|edit)",
    r"/mypage/",
    r"/board/(?:write|edit|delete|view)",
    # 한국 특화
    r"/shop/mypage",
    r"/member/info\.php",
    r"/bbs/view\.php",
]


@dataclass
class IdorFinding:
    endpoint: str
    id_type: str
    original_id: str
    tested_id: str
    result: str
    confidence: str  # HIGH / MEDIUM / LOW
    evidence: str = ""
    http_method: str = "GET"
    response_diff: str = ""


@dataclass
class IdorReport:
    target: str
    endpoints_tested: int = 0
    findings: list[IdorFinding] = field(default_factory=list)
    confirmed: list[IdorFinding] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════
# 응답 비교 유틸
# ══════════════════════════════════════════════════════════════

def _response_differs(body1: str, body2: str) -> tuple[bool, str]:
    """두 응답이 의미있게 다른지 비교"""
    if not body1 or not body2:
        return False, "empty"
    if len(body2) < 50:
        return False, "too_short"
    if abs(len(body1) - len(body2)) < 20:
        return False, "same_length"

    # JSON 파싱 비교
    try:
        j1, j2 = json.loads(body1), json.loads(body2)
        # 다른 유저 ID가 응답에 포함되는지 체크
        if isinstance(j2, dict):
            for k, v in j2.items():
                if k in ("id", "user_id", "email", "username", "name"):
                    if str(v) != str(j1.get(k, "")):
                        return True, f"different_{k}: {v}"
        return True, "json_differs"
    except Exception:
        pass

    # 길이 차이가 크면 다른 내용
    ratio = len(body2) / max(len(body1), 1)
    if 0.5 < ratio < 2.0 and len(body2) > 100:
        return True, f"content_differs (len:{len(body2)})"

    return False, "no_diff"


def _generate_test_ids(original_id: str, id_type: str) -> list[str]:
    """테스트용 ID 목록 생성"""
    ids: list[str] = []

    if id_type in ("numeric", "numeric_param", "korean_id"):
        try:
            n = int(original_id)
            # 인접 ID 테스트
            candidates = [n - 1, n + 1, n - 2, n + 2, 1, 2, 100, 9999]
            ids = [str(c) for c in candidates if c > 0 and c != n]
        except ValueError:
            pass
    elif id_type == "md5":
        # 숫자 1,2,3의 MD5 해시
        for i in range(1, 6):
            ids.append(hashlib.md5(str(i).encode()).hexdigest())
    elif id_type == "uuid":
        # nil UUID + 예측 가능 UUID
        ids = [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
        ]
    elif id_type == "gnuboard":
        pass  # 타입별 처리

    return ids[:5]  # 최대 5개


# ══════════════════════════════════════════════════════════════
# IDOR 스캐너 메인
# ══════════════════════════════════════════════════════════════

class IdorScanner:
    """
    IDOR/권한 자동 스캐너.
    두 개의 인증 토큰(사용자A, 사용자B)으로 교차 검증.
    """

    def __init__(
        self,
        request_fn: Callable[[str, str, dict], tuple[int, str]],
        # url, method, headers → (status, body)
        target_base: str,
        headers_a: dict | None = None,   # 사용자 A 인증 헤더
        headers_b: dict | None = None,   # 사용자 B 인증 헤더 (없으면 비인증)
        log_fn: Callable[[str], None] | None = None,
    ):
        self._req = request_fn
        self.base = target_base.rstrip("/")
        self.headers_a = headers_a or {}
        self.headers_b = headers_b or {}
        self.log = log_fn or (lambda s: None)

    def scan_endpoint(self, url: str, method: str = "GET") -> list[IdorFinding]:
        """단일 엔드포인트 IDOR 스캔"""
        findings: list[IdorFinding] = []

        for pat, id_type in ID_PATTERNS:
            m = re.search(pat, url, re.I)
            if not m:
                continue
            original_id = m.group(1)
            test_ids = _generate_test_ids(original_id, id_type)

            # 사용자A로 원본 응답 가져오기
            _, body_a = self._req(url, method, self.headers_a)

            for test_id in test_ids:
                test_url = url.replace(original_id, test_id, 1)

                # 사용자B(또는 비인증)로 다른 ID 접근
                status_b, body_b = self._req(test_url, method, self.headers_b)

                if status_b in (200, 201, 206):
                    differs, diff_reason = _response_differs(body_a, body_b)
                    if differs:
                        confidence = "HIGH" if id_type in ("numeric", "numeric_param") else "MEDIUM"
                        f = IdorFinding(
                            endpoint=test_url,
                            id_type=id_type,
                            original_id=original_id,
                            tested_id=test_id,
                            result=f"ACCESSIBLE (HTTP {status_b})",
                            confidence=confidence,
                            evidence=diff_reason,
                            http_method=method,
                            response_diff=body_b[:200],
                        )
                        findings.append(f)
                        self.log(
                            f"[IDOR!] {test_url} → {status_b} | {diff_reason} | {confidence}"
                        )
        return findings

    def scan_vertical_priv(self, admin_endpoints: list[str]) -> list[IdorFinding]:
        """
        수직 권한 상승: 일반 사용자 토큰으로 관리자 API 직접 접근
        admin_endpoints: JS 분석기 등으로 발견한 관리자 엔드포인트 목록
        """
        findings: list[IdorFinding] = []
        for ep in admin_endpoints:
            url = ep if ep.startswith("http") else self.base + ep
            status, body = self._req(url, "GET", self.headers_b)
            if status in (200, 201) and len(body) > 50:
                f = IdorFinding(
                    endpoint=url,
                    id_type="admin_endpoint",
                    original_id="",
                    tested_id="",
                    result=f"ADMIN_ACCESSIBLE (HTTP {status})",
                    confidence="HIGH",
                    evidence=body[:300],
                    http_method="GET",
                )
                findings.append(f)
                self.log(f"[PRIV!] 수직 권한 상승: {url} → {status}")
        return findings

    def auto_scan(self, endpoints: list[str], admin_paths: list[str] | None = None) -> IdorReport:
        """
        전체 IDOR 자동 스캔.
        endpoints: 테스트할 엔드포인트 목록 (JS 분석기로 추출)
        admin_paths: 관리자 경로 목록 (수직 권한 상승 테스트)
        """
        report = IdorReport(target=self.base)

        # 고위험 엔드포인트 우선 필터
        high_risk = [ep for ep in endpoints if any(
            re.search(p, ep, re.I) for p in HIGH_RISK_ENDPOINTS
        )]
        other = [ep for ep in endpoints if ep not in high_risk]
        ordered = high_risk + other

        self.log(f"[IDOR] 고위험: {len(high_risk)}개 / 전체: {len(ordered)}개")

        for ep in ordered[:50]:  # 최대 50개
            url = ep if ep.startswith("http") else self.base + ep
            findings = self.scan_endpoint(url)
            report.findings.extend(findings)
            report.endpoints_tested += 1

        # 수직 권한 상승 테스트
        if admin_paths:
            vp_findings = self.scan_vertical_priv(admin_paths)
            report.findings.extend(vp_findings)

        # 확인된 취약점 분류
        report.confirmed = [f for f in report.findings if f.confidence == "HIGH"]

        self.log(
            f"[IDOR✓] 완료: 테스트 {report.endpoints_tested}개 | "
            f"발견 {len(report.findings)}개 | 확인 {len(report.confirmed)}개"
        )
        return report


IDOR_SCANNER_SUMMARY = """
=== IDOR AUTO-SCANNER (AI AUTO-SELECT) ===

Trigger: run AFTER js_analyzer (use discovered endpoints)
Steps:
  [1] Feed endpoints from js_analyzer.run() → report.all_endpoints
  [2] IdorScanner.auto_scan(endpoints, admin_paths=report.all_admin_paths)
  [3] HIGH confidence findings → immediate report
  [4] Vertical privesc test: non-admin token → admin endpoints

Two-user mode: headers_a (user A), headers_b (user B or anonymous)
"""
