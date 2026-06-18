"""bingo/tools/session_manager.py — 세션/쿠키 자동 관리 (v2.9.0)

기능:
  - 로그인 후 세션 쿠키 영속 관리
  - 세션 만료 감지 → 자동 재로그인
  - 다중 계정 풀 (일반/관리자)
  - CSRF 토큰 자동 갱신
  - Cookie Jar 직렬화/역직렬화
  - 쿠키 도메인별 분리 관리
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class SessionInfo:
    name: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    csrf_token: str = ""
    logged_in: bool = False
    last_used: float = field(default_factory=time.time)
    username: str = ""
    password: str = ""
    role: str = "user"  # user / admin


class CsrfExtractor:
    """HTML에서 CSRF 토큰 추출"""

    PATTERNS = [
        r'<input[^>]+name=["\'](?:csrf[_\-]?token|_token|authenticity_token|__RequestVerificationToken)["\'][^>]+value=["\']([\w\-=+/]+)["\']',
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([\w\-=+/]+)["\']',
        r'"csrf[_\-]?token"\s*:\s*"([\w\-=+/]+)"',
    ]

    @classmethod
    def extract(cls, html: str) -> str | None:
        for pat in cls.PATTERNS:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return None


class CookieJar:
    """쿠키 저장소"""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, str]] = {}  # domain → {name: value}

    def set(self, domain: str, name: str, value: str) -> None:
        self._store.setdefault(domain, {})[name] = value

    def get(self, domain: str) -> dict[str, str]:
        return dict(self._store.get(domain, {}))

    def parse_set_cookie(self, domain: str, set_cookie_header: str) -> None:
        """Set-Cookie 헤더 파싱"""
        parts = [p.strip() for p in set_cookie_header.split(";")]
        if parts:
            kv = parts[0].split("=", 1)
            if len(kv) == 2:
                self.set(domain, kv[0], kv[1])

    def to_header(self, domain: str) -> str:
        cookies = self.get(domain)
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._store, f, ensure_ascii=False, indent=2)

    def load(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                self._store = json.load(f)
        except Exception:
            pass


class SessionPool:
    """다중 세션 풀"""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionInfo] = {}
        self._lock = threading.Lock()

    def add(self, session: SessionInfo) -> None:
        with self._lock:
            self._sessions[session.name] = session

    def get(self, name: str) -> SessionInfo | None:
        with self._lock:
            return self._sessions.get(name)

    def get_admin(self) -> SessionInfo | None:
        with self._lock:
            for s in self._sessions.values():
                if s.role == "admin" and s.logged_in:
                    return s
        return None

    def all_sessions(self) -> list[SessionInfo]:
        with self._lock:
            return list(self._sessions.values())


class SessionManager:
    """세션 자동 관리자"""

    EXPIRY_PATTERNS = [
        r"session\s*expired",
        r"please\s*log\s*in",
        r"로그인이\s*필요",
        r"인증이\s*만료",
        r"/login",
        r"401",
    ]

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str = "",
        login_url: str = "",
    ) -> None:
        self.req = request_fn
        self.base_url = base_url
        self.login_url = login_url
        self.pool = SessionPool()
        self.jar = CookieJar()
        self._domain = urllib.parse.urlparse(base_url).netloc if base_url else ""

    def _is_expired(self, body: str) -> bool:
        for pat in self.EXPIRY_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return True
        return False

    def login(
        self,
        username: str,
        password: str,
        role: str = "user",
        extra_headers: dict | None = None,
    ) -> SessionInfo | None:
        """로그인 시도 → 세션 생성"""
        url = self.login_url or (self.base_url + "/login")
        # 먼저 로그인 페이지 GET → CSRF 토큰 추출
        status, html = self.req(url, "GET", {}, "")
        csrf = CsrfExtractor.extract(html) or ""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if extra_headers:
            headers.update(extra_headers)
        body_parts = {"username": username, "password": password}
        if csrf:
            body_parts["_token"] = csrf
            body_parts["csrf_token"] = csrf
        body = urllib.parse.urlencode(body_parts)
        status2, resp = self.req(url, "POST", headers, body)
        if status2 in (200, 302, 303) and not self._is_expired(resp):
            info = SessionInfo(
                name=username,
                logged_in=True,
                username=username,
                password=password,
                role=role,
                csrf_token=csrf,
            )
            self.pool.add(info)
            return info
        return None

    def refresh_csrf(self, session: SessionInfo) -> str:
        """CSRF 토큰 갱신"""
        url = self.base_url
        _, html = self.req(url, "GET", session.headers, "")
        token = CsrfExtractor.extract(html) or ""
        session.csrf_token = token
        return token

    def ensure_logged_in(self, session: SessionInfo) -> bool:
        """세션 유효성 확인 → 만료 시 자동 재로그인"""
        _, body = self.req(self.base_url, "GET", session.headers, "")
        if self._is_expired(body):
            new_sess = self.login(session.username, session.password, session.role)
            if new_sess:
                session.logged_in = True
                session.cookies = new_sess.cookies
                return True
            session.logged_in = False
            return False
        return True

    def get_active_cookie_header(self, name: str) -> str:
        s = self.pool.get(name)
        if not s:
            return ""
        return "; ".join(f"{k}={v}" for k, v in s.cookies.items())

    def get_admin_session(self) -> SessionInfo | None:
        return self.pool.get_admin()

    def save_sessions(self, path: str) -> None:
        data = [
            {
                "name": s.name, "username": s.username,
                "password": s.password, "role": s.role,
                "cookies": s.cookies, "headers": s.headers,
            }
            for s in self.pool.all_sessions()
        ]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load_sessions(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for d in data:
                info = SessionInfo(
                    name=d["name"],
                    username=d.get("username", ""),
                    password=d.get("password", ""),
                    role=d.get("role", "user"),
                    cookies=d.get("cookies", {}),
                    headers=d.get("headers", {}),
                    logged_in=bool(d.get("cookies")),
                )
                self.pool.add(info)
        except Exception:
            pass
