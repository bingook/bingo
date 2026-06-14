"""
ACPV — Client-side Authentication Bypass Scanner
================================================
클라이언트 사이드 인증 우회 자동 탐지 모듈.

탐지 패턴:
  • localStorage / sessionStorage 토큰 검사 우회
  • authRequired / isLoggedIn / isAuthenticated 플래그 조작
  • API 엔드포인트 무인증 접근
  • Burp Suite 응답 변조 포인트 탐지

참고: https://kuldeep.io/posts/client-side-authentication-bypass/

환각 정책: 모든 결과는 실제 HTTP 응답에서 확인된 데이터만 출력.
           추론/미확인 항목은 evidence_level로 명시.
"""
from __future__ import annotations

import re
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3
urllib3.disable_warnings()


# ── 탐지 패턴 ──────────────────────────────────────────────────────────────

# localStorage / sessionStorage 관련 인증 변수명
_STORAGE_AUTH_KEYS = [
    "token", "tokenExpiry", "accessToken", "access_token",
    "authToken", "auth_token", "jwtToken", "jwt",
    "userInfo", "user_info", "loggedIn", "isLoggedIn",
    "isAuthenticated", "sessionToken", "userToken",
    "userData", "user_data", "loginStatus",
]

# JS에서 인증 체크 패턴
_AUTH_CHECK_PATTERNS = [
    # authRequired
    r'authRequired\s*:\s*!0',
    r'authRequired\s*:\s*true',
    r'requireAuth\s*:\s*true',
    r'meta\.authRequired',
    # localStorage 기반 체크
    r'localStorage\.getItem\(["\'](?:token|accessToken|authToken|jwt)["\']',
    r'localStorage\.getItem\(["\'](?:tokenExpiry|expires|expiry)["\']',
    # sessionStorage 기반 체크
    r'sessionStorage\.getItem\(["\'](?:userInfo|loggedIn|isLoggedIn)["\']',
    # isUserLoggedIn 함수 패턴
    r'isUserLoggedIn\s*[:=]?\s*function',
    r'function\s+isUserLoggedIn',
    r'isLoggedIn\s*[:=]\s*function',
    # 토큰 만료 체크
    r'new\s+Date\(.*tokenExpiry',
    r'Date\.now\(\)\s*[<>]\s*new\s+Date',
]

# API 엔드포인트 탐지 패턴
_API_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^\s"\']+)["\']',
    r'["\'](/v\d+/[^\s"\']+)["\']',
    r'axios\.(get|post|put|delete)\(["\']([^\s"\']+)["\']',
    r'fetch\(["\']([^\s"\']+)["\']',
    r'\$\.ajax\(\{[^}]*url\s*:\s*["\']([^\s"\']+)["\']',
    r'["\']url["\']\s*:\s*["\']([^\s"\']+)["\']',
]

# 응답 변조 탐지 패턴 (Burp Suite 응답 변조 포인트)
_RESPONSE_MANIPULATION_PATTERNS = [
    r'"is_active"\s*:\s*(?:false|true)',
    r'"isActive"\s*:\s*(?:false|true)',
    r'"authenticated"\s*:\s*(?:false|true)',
    r'"loggedIn"\s*:\s*(?:false|true)',
    r'"TimeoutStatus"\s*:\s*"Timeout"',
    r'"status"\s*:\s*"(?:inactive|active|disabled|enabled)"',
    r'"role"\s*:\s*"(?:user|admin|guest)"',
    r'"Groups"\s*:\s*null',
    r'"permissions"\s*:\s*\[\s*\]',
]

# JS 파일 경로 패턴
_JS_FILE_PATTERNS = [
    r'<script[^>]+src=["\']([^\s"\']*\.js(?:\?[^"\']*)?)["\']',
    r'["\']((?:/|\.)[^\s"\']*(?:main|app|index|bundle|chunk)[^\s"\']*\.js)["\']',
]


@dataclass
class AcpvFinding:
    """단일 ACPV 발견 항목"""
    finding_type: str          # "storage_auth", "unauth_api", "response_manip", "js_pattern"
    url: str                   # 발견된 URL
    detail: str                # 상세 설명
    evidence_level: str        # "VERIFIED", "LIKELY", "INFERRED"
    exploit_hint: str = ""     # 익스플로잇 힌트 (JS 코드 등)
    poc: str = ""              # PoC 코드


@dataclass
class AcpvResult:
    """ACPV 스캔 전체 결과"""
    target: str
    phase: str = "acpv"
    findings: list[AcpvFinding] = field(default_factory=list)
    js_files_scanned: list[str] = field(default_factory=list)
    api_endpoints_found: list[str] = field(default_factory=list)
    unauth_api_count: int = 0
    storage_auth_bypass_possible: bool = False
    response_manip_points: list[str] = field(default_factory=list)
    recommended_poc: str = ""
    error: str = ""

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def severity(self) -> str:
        if self.storage_auth_bypass_possible:
            return "critical"
        if self.unauth_api_count >= 5:
            return "high"
        if self.unauth_api_count > 0 or self.response_manip_points:
            return "medium"
        return "low"


class AcpvScanner:
    """
    클라이언트 사이드 인증 우회 자동 스캐너

    AI가 타겟을 분석하면서 자동으로 판단:
      1. JS 파일 수집 → 인증 패턴 탐지
      2. API 엔드포인트 수집 → 무인증 접근 테스트
      3. 응답 변조 포인트 탐지
      4. PoC 자동 생성
    """

    def __init__(self, target: str, verbose: bool = True, timeout: int = 10):
        self.target = target.rstrip("/")
        self.verbose = verbose
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = False
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0.0.0 Safari/537.36",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        })

    def log(self, msg: str):
        if self.verbose:
            try:
                from rich.console import Console
                Console().print(msg)
            except Exception:
                print(msg)

    # ── 메인 스캔 ────────────────────────────────────────────────────────

    def scan(self) -> AcpvResult:
        result = AcpvResult(target=self.target)

        self.log("\n[bold cyan]🔐 ACPV: 클라이언트 사이드 인증 우회 스캔 시작[/bold cyan]")

        # 1단계: 메인 페이지에서 JS 파일 수집
        js_urls = self._collect_js_files(result)

        # 2단계: JS 파일 분석
        js_contents: list[tuple[str, str]] = []
        for js_url in js_urls[:8]:  # 최대 8개 JS 파일만 분석
            content = self._fetch_js(js_url)
            if content:
                js_contents.append((js_url, content))
                result.js_files_scanned.append(js_url)

        # 3단계: 인증 패턴 탐지 (JS 분석)
        for js_url, content in js_contents:
            self._analyze_js_auth_patterns(result, js_url, content)

        # 4단계: API 엔드포인트 수집 및 무인증 테스트
        api_endpoints = set()
        for _, content in js_contents:
            endpoints = self._extract_api_endpoints(content)
            api_endpoints.update(endpoints)

        self._test_unauth_api_access(result, list(api_endpoints)[:20])

        # 5단계: 응답 변조 포인트 탐지
        for js_url, content in js_contents:
            self._find_response_manipulation_points(result, js_url, content)

        # 6단계: PoC 자동 생성
        if result.storage_auth_bypass_possible or result.findings:
            result.recommended_poc = self._generate_poc(result)

        # 요약
        self._log_summary(result)
        return result

    # ── JS 파일 수집 ────────────────────────────────────────────────────

    def _collect_js_files(self, result: AcpvResult) -> list[str]:
        js_urls: list[str] = []
        try:
            resp = self._session.get(self.target, timeout=self.timeout)
            html = resp.text

            for pattern in _JS_FILE_PATTERNS:
                for match in re.finditer(pattern, html, re.IGNORECASE):
                    path = match.group(1)
                    if path.startswith("http"):
                        url = path
                    elif path.startswith("//"):
                        url = "https:" + path
                    elif path.startswith("/"):
                        url = self.target + path
                    else:
                        url = self.target + "/" + path

                    if url not in js_urls:
                        js_urls.append(url)

            # 공통 JS 경로 추가 시도
            common_js = [
                "/js/app.js", "/js/main.js", "/static/js/main.chunk.js",
                "/assets/index.js", "/dist/bundle.js", "/app.js",
                "/js/index.js", "/src/main.js",
            ]
            for path in common_js:
                url = self.target + path
                if url not in js_urls:
                    js_urls.append(url)

        except Exception as e:
            result.error = str(e)

        self.log(f"[dim]📄 JS 파일 후보: {len(js_urls)}개[/dim]")
        return js_urls

    def _fetch_js(self, url: str) -> str | None:
        try:
            resp = self._session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and len(resp.text) > 100:
                ct = resp.headers.get("Content-Type", "")
                if "javascript" in ct or "text" in ct or url.endswith(".js"):
                    return resp.text
        except Exception:
            pass
        return None

    # ── JS 인증 패턴 분석 ───────────────────────────────────────────────

    def _analyze_js_auth_patterns(
        self, result: AcpvResult, js_url: str, content: str
    ):
        matched_patterns: list[str] = []

        for pattern in _AUTH_CHECK_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                matched_patterns.append(pattern)

        if not matched_patterns:
            return

        # localStorage 기반 인증 확인
        storage_keys_found: list[str] = []
        for key in _STORAGE_AUTH_KEYS:
            if f'getItem("{key}"' in content or f"getItem('{key}')" in content:
                storage_keys_found.append(key)

        if storage_keys_found:
            result.storage_auth_bypass_possible = True
            poc = self._generate_storage_poc(content, storage_keys_found)

            finding = AcpvFinding(
                finding_type="storage_auth",
                url=js_url,
                detail=(
                    f"클라이언트 사이드 인증 체크 탐지: "
                    f"localStorage/sessionStorage 키 [{', '.join(storage_keys_found)}] "
                    f"서버 검증 없이 인증 판단"
                ),
                evidence_level="LIKELY",
                exploit_hint=(
                    f"브라우저 콘솔에서 실행:\n"
                    f"localStorage.setItem('token', '<JWT>'); "
                    f"localStorage.setItem('tokenExpiry', '2027-12-31T23:59:59Z');"
                ),
                poc=poc,
            )
            result.findings.append(finding)
            self.log(
                f"[yellow]⚠ ACPV 패턴 발견 [{js_url}]: "
                f"localStorage 키 {storage_keys_found}[/yellow]"
            )

    def _generate_storage_poc(self, content: str, keys: list[str]) -> str:
        """JS 코드를 분석하여 최적의 PoC 생성"""
        poc_lines: list[str] = []

        # JWT 기반인지 확인
        is_jwt = any(
            k in content for k in
            ["split('.')[1]", "window.atob", "atob(", "JsonWebToken", "jwt"]
        )

        # sessionStorage vs localStorage 확인
        use_session = "sessionStorage" in content and "localStorage" not in content

        storage = "sessionStorage" if use_session else "localStorage"

        for key in keys:
            if key in ("token", "accessToken", "authToken", "jwtToken", "jwt"):
                if is_jwt:
                    poc_lines.append(
                        f'{storage}.setItem("{key}", '
                        f'"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                        f'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwicm9sZXMiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.'
                        f'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");'
                    )
                else:
                    poc_lines.append(f'{storage}.setItem("{key}", "bingo_bypass_token");')
            elif key in ("tokenExpiry", "expires", "expiry"):
                poc_lines.append(f'{storage}.setItem("{key}", "2027-12-31T23:59:59Z");')
            elif key in ("userInfo", "user_info"):
                poc_lines.append(f'{storage}.setItem("{key}", JSON.stringify({{}}));')
            elif key in ("loggedIn", "isLoggedIn", "isAuthenticated"):
                poc_lines.append(f'{storage}.setItem("{key}", JSON.stringify(true));')
            else:
                poc_lines.append(f'{storage}.setItem("{key}", "bingo_test");')

        poc_lines.append("location.reload(); // 새로고침 후 인증 우회 확인")
        return "\n".join(poc_lines)

    # ── API 엔드포인트 추출 ─────────────────────────────────────────────

    def _extract_api_endpoints(self, content: str) -> list[str]:
        endpoints: list[str] = []
        for pattern in _API_ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                for group in match.groups():
                    if group and group.startswith("/") and len(group) > 2:
                        endpoint = group.split("?")[0]  # 쿼리 제거
                        if endpoint not in endpoints:
                            endpoints.append(endpoint)
        return endpoints

    # ── 무인증 API 테스트 ───────────────────────────────────────────────

    def _test_unauth_api_access(
        self, result: AcpvResult, endpoints: list[str]
    ):
        if not endpoints:
            return

        self.log(f"[dim]🔍 API 엔드포인트 {len(endpoints)}개 무인증 테스트 중...[/dim]")

        no_cookie_session = requests.Session()
        no_cookie_session.verify = False
        no_cookie_session.headers.update({
            "User-Agent": "Mozilla/5.0",
        })

        for path in endpoints:
            url = self.target + path
            try:
                resp = no_cookie_session.get(url, timeout=6)
                if resp.status_code in (200, 201) and len(resp.text) > 50:
                    # JSON 응답이면서 데이터가 있는 경우
                    is_json = False
                    data_size = len(resp.text)
                    try:
                        parsed = json.loads(resp.text)
                        is_json = True
                        # 빈 응답이나 에러 응답 필터링
                        if isinstance(parsed, dict):
                            if parsed.get("error") or parsed.get("message") == "Unauthorized":
                                continue
                    except Exception:
                        pass

                    if is_json and data_size > 100:
                        result.unauth_api_count += 1
                        result.api_endpoints_found.append(url)

                        finding = AcpvFinding(
                            finding_type="unauth_api",
                            url=url,
                            detail=(
                                f"무인증 API 접근 가능: HTTP {resp.status_code}, "
                                f"응답 크기 {data_size}bytes"
                            ),
                            evidence_level="VERIFIED",
                            exploit_hint=f"curl '{url}' — 인증 없이 데이터 반환",
                        )
                        result.findings.append(finding)
                        self.log(f"[red]🔴 무인증 API: {url} ({data_size}B)[/red]")

            except Exception:
                pass

    # ── 응답 변조 포인트 탐지 ───────────────────────────────────────────

    def _find_response_manipulation_points(
        self, result: AcpvResult, js_url: str, content: str
    ):
        for pattern in _RESPONSE_MANIPULATION_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                matched_val = match.group(0)
                if js_url not in result.response_manip_points:
                    result.response_manip_points.append(js_url)

                finding = AcpvFinding(
                    finding_type="response_manip",
                    url=js_url,
                    detail=(
                        f"Burp Suite 응답 변조 포인트: "
                        f"[{matched_val}] → 값 반전 시 권한 우회 가능"
                    ),
                    evidence_level="INFERRED",
                    exploit_hint=(
                        f"Burp Suite → Proxy → Match and Replace:\n"
                        f'  Match: {matched_val}\n'
                        f"  Replace: 값 반전 (false→true, null→관련값)"
                    ),
                )
                result.findings.append(finding)
                self.log(f"[yellow]🔧 응답 변조 포인트: {matched_val[:60]}[/yellow]")

    # ── PoC 생성 ────────────────────────────────────────────────────────

    def _generate_poc(self, result: AcpvResult) -> str:
        poc_parts: list[str] = []

        if result.storage_auth_bypass_possible:
            poc_parts.append(
                "=== [Browser Console PoC] ===\n"
                "// 1. 아래 코드를 브라우저 개발자 도구 Console에 붙여넣기\n"
            )
            for f in result.findings:
                if f.finding_type == "storage_auth" and f.poc:
                    poc_parts.append(f.poc)
                    break

        if result.api_endpoints_found:
            poc_parts.append(
                "\n=== [Unauthenticated API PoC] ===\n"
                "# 아래 curl 명령어로 무인증 API 접근 확인:"
            )
            for url in result.api_endpoints_found[:3]:
                poc_parts.append(f"curl -sk '{url}' | python3 -m json.tool")

        if result.response_manip_points:
            poc_parts.append(
                "\n=== [Response Manipulation PoC] ===\n"
                "# Burp Suite → Proxy → Options → Match and Replace:\n"
                '# Response Body: "false" → "true" (is_active, loggedIn 등)\n'
                '# Response Body: "Timeout" → 삭제 (TimeoutStatus)'
            )

        return "\n".join(poc_parts)

    # ── 요약 출력 ────────────────────────────────────────────────────────

    def _log_summary(self, result: AcpvResult):
        if not result.findings:
            self.log("[dim]✓ ACPV: 클라이언트 사이드 인증 우회 패턴 없음[/dim]")
            return

        self.log(
            f"\n[bold yellow]🔐 ACPV 스캔 결과 요약:[/bold yellow]\n"
            f"  발견 항목: [red]{len(result.findings)}개[/red]\n"
            f"  JS 파일 분석: {len(result.js_files_scanned)}개\n"
            f"  무인증 API: [red]{result.unauth_api_count}개[/red]\n"
            f"  Storage 우회 가능: {'[red]YES[/red]' if result.storage_auth_bypass_possible else '[green]NO[/green]'}\n"
            f"  심각도: [bold]{result.severity.upper()}[/bold]"
        )
