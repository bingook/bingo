"""bingo/tools/api_version_enum.py — API 버전 열거 + 보안 회귀 탐지 (v2.6.0)"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# ── API 버전 경로 패턴 ────────────────────────────────────────────────────────
VERSION_PATHS = [
    "/v1", "/v2", "/v3", "/v4", "/v5", "/v6",
    "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/v1.0", "/api/v2.0", "/api/v3.0",
    "/api/1.0", "/api/2.0",
    "/api/1", "/api/2", "/api/3",
    "/api-v1", "/api-v2", "/api-v3",
    "/rest/v1", "/rest/v2",
    "/service/v1", "/service/v2",
    "/app/v1", "/app/v2",
    "/mobile/v1", "/mobile/v2",
    "/internal/v1", "/internal/v2",
    "/private/v1",
    "/public/v1",
    "/beta", "/alpha", "/stable",
    "/dev", "/staging", "/prod",
]

# ── 구버전 취약점 신호 ─────────────────────────────────────────────────────────
REGRESSION_SIGNALS = [
    "password", "secret", "token", "api_key", "internal",
    "debug", "admin", "root", "superuser",
    "swagger", "api-docs", "openapi",
    "stack trace", "traceback", "exception", "error details",
    "SQL", "ORA-", "mysql_",
]


@dataclass
class ApiVersionFinding:
    version_path: str
    full_url: str
    status: int
    response_size: int
    has_auth: bool
    security_regression: bool
    regression_evidence: list[str]
    endpoints_found: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    notes: str = ""


@dataclass
class ApiVersionReport:
    target: str
    current_version: str = ""
    findings: list[ApiVersionFinding] = field(default_factory=list)
    all_versions: list[str] = field(default_factory=list)

    @property
    def vulnerable_versions(self) -> list[ApiVersionFinding]:
        return [f for f in self.findings if f.security_regression or not f.has_auth]


class ApiVersionEnumerator:
    """API 버전 경로 열거 + 인증 우회 + 보안 회귀 탐지"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    def _detect_current_version(self, html: str) -> str:
        for pat in [r'/v(\d+)/', r'version["\s]*[:=]["\s]*(\d+)', r'api/v(\d+)']:
            m = re.search(pat, html, re.I)
            if m:
                return f"v{m.group(1)}"
        return ""

    def _check_auth_bypass(self, url: str) -> bool:
        """인증 없이 접근 가능한지 확인"""
        no_auth_headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("authorization", "x-api-key", "cookie")}
        try:
            status, resp = self.req(url, "GET", no_auth_headers, "")
            return status == 200 and len(resp) > 100
        except Exception:
            return False

    def _detect_regression(self, resp: str) -> list[str]:
        found = []
        for sig in REGRESSION_SIGNALS:
            if sig.lower() in resp.lower():
                found.append(sig)
        return found

    def _discover_endpoints(self, version_url: str) -> list[str]:
        """버전 경로 아래의 엔드포인트 발굴"""
        discovery_paths = [
            "", "/users", "/user", "/accounts", "/account",
            "/admin", "/orders", "/products", "/items",
            "/search", "/upload", "/download",
            "/api-docs", "/swagger.json", "/openapi.json", "/docs",
        ]
        found = []
        for path in discovery_paths:
            url = version_url.rstrip("/") + path
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                if status in (200, 201, 400, 401, 403) and len(resp) > 50:
                    found.append(f"{url} [{status}]")
            except Exception:
                pass
        return found[:20]

    def scan(self, check_endpoints: bool = False) -> ApiVersionReport:
        report = ApiVersionReport(target=self.base)

        # 현재 버전 탐지
        try:
            _, html = self.req(self.base, "GET", self.headers, "")
            report.current_version = self._detect_current_version(html)
        except Exception:
            pass

        for ver_path in VERSION_PATHS:
            url = self.base + ver_path
            try:
                status, resp = self.req(url, "GET", self.headers, "")
                if status in (200, 201, 400, 401, 403, 405):
                    has_auth = not self._check_auth_bypass(url)
                    regression = self._detect_regression(resp)
                    endpoints = self._discover_endpoints(url) if check_endpoints else []

                    severity = "LOW"
                    if not has_auth:
                        severity = "HIGH"
                    if regression:
                        severity = "CRITICAL" if not has_auth else "HIGH"

                    report.all_versions.append(ver_path)
                    report.findings.append(ApiVersionFinding(
                        version_path=ver_path,
                        full_url=url,
                        status=status,
                        response_size=len(resp),
                        has_auth=has_auth,
                        security_regression=bool(regression),
                        regression_evidence=regression,
                        endpoints_found=endpoints,
                        severity=severity,
                        notes=f"Version accessible | Auth: {'YES' if has_auth else 'NO'} | Regression signals: {regression}",
                    ))
            except Exception:
                pass

        return report
