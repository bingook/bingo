"""bingo/tools/param_discovery.py — 숨겨진 파라미터 자동 발굴 (v2.6.0)"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

# ── 공통 파라미터 워드리스트 ───────────────────────────────────────────────────
COMMON_PARAMS = [
    # 인증/권한
    "admin", "debug", "test", "internal", "hidden", "secret", "key", "token",
    "access_token", "auth", "auth_token", "api_key", "apikey", "api",
    # ID/사용자
    "id", "user_id", "uid", "account", "user", "username", "email", "member_id",
    "customer_id", "userid", "uuid", "guid", "pid", "cid",
    # 제어 흐름
    "redirect", "url", "next", "return", "returnUrl", "redirect_url", "goto",
    "target", "dest", "destination", "redir", "ref", "referer", "forward",
    # 파일/경로
    "file", "filename", "path", "page", "template", "view", "load", "include",
    "src", "source", "dir", "folder", "document", "doc",
    # 기능
    "action", "method", "func", "function", "cmd", "command", "exec", "run",
    "mode", "type", "format", "output", "callback", "data", "json", "xml",
    # 기타
    "lang", "language", "locale", "currency", "country", "region",
    "version", "v", "ver", "rev", "build",
    "limit", "offset", "page", "per_page", "start", "end", "from", "to",
    "sort", "order", "orderby", "filter", "search", "q", "query",
    "hash", "nonce", "timestamp", "ts", "expire", "ttl",
]

# ── 헤더 인젝션 우회용 헤더 ────────────────────────────────────────────────────
BYPASS_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Forwarded-Proto", "https"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1"),
    ("X-Host", "localhost"),
    ("X-Forwarded-Server", "localhost"),
    ("CF-Connecting-IP", "127.0.0.1"),
]


@dataclass
class ParamFinding:
    param: str
    url: str
    method: str
    baseline_status: int
    found_status: int
    response_diff: str
    finding_type: str   # "new_param" | "header_bypass" | "hpp"
    evidence: str = ""
    severity: str = "MEDIUM"


@dataclass
class ParamReport:
    target: str
    discovered_params: list[str] = field(default_factory=list)
    findings: list[ParamFinding] = field(default_factory=list)

    @property
    def high_findings(self) -> list[ParamFinding]:
        return [f for f in self.findings if f.severity in ("HIGH", "CRITICAL")]


class ParamDiscovery:
    """숨겨진 파라미터 발굴 + 헤더 인젝션 우회 + HPP"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── JS/HTML에서 파라미터 추출 ─────────────────────────────────────────────
    def extract_params_from_html(self, html: str) -> list[str]:
        found: set[str] = set()
        # input name, id
        found.update(re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.I))
        # query string in href/action/src
        for qs in re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', html):
            found.add(qs)
        # JS 변수명 (fetch, axios 파라미터)
        found.update(re.findall(r'["\']([a-z_][a-z0-9_]{1,20})["\']:\s*(?:req|request|param)', html, re.I))
        return list(found)

    # ── 파라미터 퍼징 ─────────────────────────────────────────────────────────
    def fuzz_params(self, url: str, method: str = "GET", html: str = "") -> ParamReport:
        report = ParamReport(target=url)
        parsed = urllib.parse.urlparse(url)
        existing = set(urllib.parse.parse_qs(parsed.query).keys())

        # 베이스라인
        try:
            base_status, base_body = self.req(url, method, self.headers, "")
        except Exception:
            return report

        # 워드리스트 + HTML에서 추출한 파라미터 합산
        test_params = list(set(COMMON_PARAMS) | set(self.extract_params_from_html(html)) - existing)

        for param in test_params:
            qs = dict(urllib.parse.parse_qsl(parsed.query))
            qs[param] = "1"
            test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
            try:
                status, body = self.req(test_url, method, self.headers, "")
                if status != base_status or (
                    abs(len(body) - len(base_body)) > 50
                    and not _noise_response(body)
                ):
                    severity = "HIGH" if status in (200, 302) and base_status in (403, 404) else "LOW"
                    report.findings.append(ParamFinding(
                        param=param, url=test_url, method=method,
                        baseline_status=base_status, found_status=status,
                        response_diff=f"len: {len(base_body)}→{len(body)}",
                        finding_type="new_param",
                        evidence=body[:150],
                        severity=severity,
                    ))
                    report.discovered_params.append(param)
            except Exception:
                pass

        return report

    # ── 헤더 인젝션 우회 ─────────────────────────────────────────────────────
    def test_header_bypass(self, url: str) -> list[ParamFinding]:
        findings: list[ParamFinding] = []
        try:
            base_status, base_body = self.req(url, "GET", self.headers, "")
        except Exception:
            return findings

        for header, value in BYPASS_HEADERS:
            inject_hdrs = {**self.headers, header: value}
            try:
                status, body = self.req(url, "GET", inject_hdrs, "")
                if status != base_status and status in (200, 302, 301):
                    findings.append(ParamFinding(
                        param=header, url=url, method="GET",
                        baseline_status=base_status, found_status=status,
                        response_diff=f"status {base_status}→{status}",
                        finding_type="header_bypass",
                        evidence=f"{header}: {value}",
                        severity="HIGH",
                    ))
            except Exception:
                pass
        return findings

    # ── HPP (파라미터 오염) ───────────────────────────────────────────────────
    def test_hpp(self, url: str, param: str) -> list[ParamFinding]:
        findings: list[ParamFinding] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qsl(parsed.query)

        # 파라미터 중복 추가
        for inject_val in ["1", "admin", "true", "../../etc/passwd"]:
            new_qs = qs + [(param, inject_val)]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs))
            )
            try:
                base_status, _ = self.req(url, "GET", self.headers, "")
                status, body = self.req(test_url, "GET", self.headers, "")
                if status != base_status:
                    findings.append(ParamFinding(
                        param=param, url=test_url, method="GET",
                        baseline_status=base_status, found_status=status,
                        response_diff=f"HPP {param}={inject_val}",
                        finding_type="hpp",
                        evidence=body[:100],
                        severity="MEDIUM",
                    ))
            except Exception:
                pass
        return findings


def _noise_response(body: str) -> bool:
    """노이즈 응답 필터"""
    noise = ["not found", "page not found", "404", "error", "invalid", "bad request"]
    b = body.lower()
    return any(n in b for n in noise)
