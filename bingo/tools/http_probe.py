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

    def check_admin_panels(self) -> list[dict]:
        """관리자 패널 탐색"""
        ADMIN_PATHS = [
            "/admin/", "/admin/login/", "/admin/login/index.php",
            "/admin/index.php", "/admin.php", "/administrator/",
            "/manager/", "/manage/", "/panel/",
            "/wp-admin/", "/wp-login.php",
            "/login.php", "/member/login.php",
        ]
        found = []
        for path in ADMIN_PATHS:
            r = self.get(path, timeout=8)
            if r.status in (200, 301, 302):
                has_form = bool(re.search(r'<form|<input.*password', r.body, re.I))
                found.append({
                    "path": path, "status": r.status,
                    "has_login_form": has_form,
                    "title": (re.search(r'<title>([^<]+)</title>', r.body) or ["", ""])[1],
                })
            time.sleep(0.15)
        return found
