"""
ProxyManager — 프록시 풀 로테이션 관리자 (v3.2.18)

지원 타입:
  HTTP    → http://ip:port  또는  http://user:pass@ip:port
  HTTPS   → https://ip:port
  SOCKS5  → socks5://ip:port  또는  socks5h://ip:port
  Tor     → socks5://127.0.0.1:9050  + stem으로 회로 교체 (NEWNYM)
  API     → URL에서 프록시 목록 자동 수집 (ProxyScrape / Webshare / 커스텀)

사용법:
  pm = ProxyManager()
  pm.add("socks5://1.2.3.4:1080")
  pm.enable_tor()
  proxies = pm.current_requests_dict()   # requests 용
  pm.report_ban()                        # 밴 → 자동 다음 프록시
"""

from __future__ import annotations

import json
import os
import re
import time
import random
import threading
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# 세션 간 프록시 풀 저장 경로
_PROXY_SAVE_PATH = Path.home() / ".config" / "bingo" / "proxy_pool.json"


# ── Tor stem import (선택적 — 없어도 동작) ────────────────────────
try:
    from stem import Signal  # type: ignore
    from stem.control import Controller  # type: ignore
    _STEM_OK = True
except ImportError:
    _STEM_OK = False


# ── SOCKS5 지원 확인 ──────────────────────────────────────────────
try:
    import socks  # PySocks  # noqa: F401
    _PYSOCKS_OK = True
except ImportError:
    _PYSOCKS_OK = False


_URL_RE = re.compile(
    r'^(https?|socks5h?|socks4a?)://'
    r'(?:([^:@/\s]+)(?::([^@/\s]*))?@)?'   # user:pass (optional)
    r'([^:/\s]+)'                            # host
    r'(?::(\d{1,5}))?'                      # port (optional)
    r'(/.*)?$',
    re.IGNORECASE,
)

TOR_PROXY_URL  = "socks5h://127.0.0.1:9050"
TOR_CTRL_HOST  = "127.0.0.1"
TOR_CTRL_PORT  = 9051


@dataclass
class ProxyEntry:
    url: str                       # 원본 URL (socks5://...)
    scheme: str                    # http / https / socks5 / socks5h
    host: str
    port: int
    user: str = ""
    password: str = ""
    is_tor: bool = False
    banned: bool = False
    fail_count: int = 0
    success_count: int = 0
    last_used: float = field(default_factory=time.time)
    latency_ms: float = -1.0       # -1 = 미측정

    # ── requests 라이브러리용 dict ────────────────────────────────
    def to_requests_dict(self) -> dict[str, str]:
        return {"http": self.url, "https": self.url}

    # ── httpx 라이브러리용 dict ───────────────────────────────────
    def to_httpx_dict(self) -> dict[str, str]:
        return {"http://": self.url, "https://": self.url}

    # ── Python 환경변수용 ─────────────────────────────────────────
    def to_env_dict(self) -> dict[str, str]:
        return {
            "HTTP_PROXY":  self.url,
            "HTTPS_PROXY": self.url,
            "http_proxy":  self.url,
            "https_proxy": self.url,
        }

    def __str__(self) -> str:
        tag = " [TOR]" if self.is_tor else ""
        auth = f"{self.user}:***@" if self.user else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}{tag}"


def _parse_proxy_url(url: str) -> Optional[ProxyEntry]:
    """URL 문자열 → ProxyEntry 파싱. 실패 시 None."""
    url = url.strip()
    if not url or url.startswith("#"):
        return None
    # scheme 없으면 http:// 붙여서 재시도
    if "://" not in url:
        url = "http://" + url
    m = _URL_RE.match(url)
    if not m:
        return None
    scheme, user, pw, host, port_s, _ = m.groups()
    scheme = scheme.lower()
    port = int(port_s) if port_s else (443 if scheme == "https" else 1080)
    is_tor = (host in ("127.0.0.1", "localhost") and port == 9050)
    return ProxyEntry(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        user=user or "",
        password=pw or "",
        is_tor=is_tor,
    )


class ProxyManager:
    """
    프록시 풀 로테이션 관리자.

    thread-safe (내부 Lock 사용).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()  # RLock: 같은 스레드 재진입 허용 (데드락 방지)
        self._pool: list[ProxyEntry] = []
        self._index: int = 0          # 현재 사용 중인 인덱스
        self._tor_enabled: bool = False
        self._tor_ctrl_password: str = ""
        self._enabled: bool = False   # 프록시 기능 활성화 여부
        # 프록시 교체 시 호출되는 콜백: on_switch(old_entry, new_entry, reason)
        # reason: "rotate" | "ban"
        self.on_switch: Optional[callable] = None  # type: ignore[type-arg]

    # ── 활성화 상태 ───────────────────────────────────────────────
    @property
    def enabled(self) -> bool:
        return self._enabled and bool(self._pool)

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    # ── 프록시 추가 ───────────────────────────────────────────────
    def add(self, url: str) -> bool:
        """프록시 1개 추가. 성공 시 True."""
        entry = _parse_proxy_url(url)
        if entry is None:
            return False
        with self._lock:
            # 중복 제거
            if any(e.url == entry.url for e in self._pool):
                return False
            self._pool.append(entry)
            self._enabled = True
        return True

    def add_many(self, urls: list[str]) -> int:
        """여러 URL 일괄 추가. 추가된 개수 반환."""
        return sum(1 for u in urls if self.add(u))

    def load_file(self, path: str) -> int:
        """파일에서 한 줄씩 읽어 추가. 추가된 개수 반환.
        
        ~ 및 환경변수($HOME 등) 자동 확장 지원.
        """
        try:
            real_path = os.path.expandvars(os.path.expanduser(path.strip()))
            with open(real_path, encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
            return self.add_many(lines)
        except OSError:
            return 0

    def fetch_from_api(self, api_url: str, timeout: int = 10) -> int:
        """
        API URL에서 프록시 목록 자동 수집.

        지원 형식:
          - 줄 구분 텍스트 (ip:port 또는 scheme://ip:port)
          - JSON 배열 ["ip:port", ...]
          - ProxyScrape / Webshare / 커스텀 API 모두 가능
        """
        try:
            req = urllib.request.Request(
                api_url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return 0

        # JSON 배열 처리
        if body.strip().startswith("["):
            try:
                import json
                items = json.loads(body)
                if isinstance(items, list):
                    return self.add_many([str(x) for x in items])
            except Exception:
                pass

        # 줄 구분 텍스트 처리
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        return self.add_many(lines)

    # ── Tor 설정 ─────────────────────────────────────────────────
    def enable_tor(self, ctrl_password: str = "") -> bool:
        """
        Tor 모드 활성화.
        - socks5h://127.0.0.1:9050 을 풀에 추가
        - stem이 있으면 회로 교체(NEWNYM) 지원
        """
        self._tor_enabled = True
        self._tor_ctrl_password = ctrl_password
        return self.add(TOR_PROXY_URL)

    def tor_new_circuit(self) -> bool:
        """
        Tor 제어 포트(9051)로 새 회로 요청 (NEWNYM).
        stem 라이브러리 필요. 없으면 False.
        """
        if not _STEM_OK:
            return False
        try:
            with Controller.from_port(
                address=TOR_CTRL_HOST, port=TOR_CTRL_PORT
            ) as ctrl:
                if self._tor_ctrl_password:
                    ctrl.authenticate(password=self._tor_ctrl_password)
                else:
                    ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
            time.sleep(1)  # 새 회로 안정화 대기
            return True
        except Exception:
            return False

    # ── 현재 프록시 ───────────────────────────────────────────────
    def current(self) -> Optional[ProxyEntry]:
        """현재 사용 중인 ProxyEntry. 없으면 None."""
        with self._lock:
            active = [e for e in self._pool if not e.banned]
            if not active:
                return None
            idx = self._index % len(active)
            return active[idx]

    def current_requests_dict(self) -> Optional[dict[str, str]]:
        """현재 프록시를 requests 라이브러리용 dict로 반환."""
        e = self.current()
        return e.to_requests_dict() if e else None

    def current_httpx_dict(self) -> Optional[dict[str, str]]:
        e = self.current()
        return e.to_httpx_dict() if e else None

    def current_env_dict(self) -> Optional[dict[str, str]]:
        e = self.current()
        return e.to_env_dict() if e else None

    # ── 로테이션 ──────────────────────────────────────────────────
    def rotate(self) -> Optional[ProxyEntry]:
        """다음 프록시로 강제 전환. 새 ProxyEntry 반환."""
        with self._lock:
            active = [e for e in self._pool if not e.banned]
            if not active:
                return None
            old = active[self._index % len(active)] if active else None
            self._index = (self._index + 1) % len(active)
            entry = active[self._index % len(active)]
            entry.last_used = time.time()
        # Tor 회로 갱신
        if entry.is_tor:
            self.tor_new_circuit()
        # 교체 콜백
        if self.on_switch and entry is not old:
            try:
                self.on_switch(old, entry, "rotate")
            except Exception:
                pass
        return entry

    def report_ban(self) -> Optional[ProxyEntry]:
        """
        현재 프록시가 밴됨을 보고.
        해당 프록시를 banned=True 처리 후 다음으로 전환.
        """
        with self._lock:
            active = [e for e in self._pool if not e.banned]
            if not active:
                return None
            cur = active[self._index % len(active)]
            cur.banned = True
            cur.fail_count += 1
            active2 = [e for e in self._pool if not e.banned]
            if not active2:
                return None
            self._index = 0
            entry = active2[0]
            entry.last_used = time.time()
        if entry.is_tor:
            self.tor_new_circuit()
        # 교체 콜백
        if self.on_switch:
            try:
                self.on_switch(cur, entry, "ban")
            except Exception:
                pass
        return entry

    def report_success(self) -> None:
        """현재 프록시 성공 기록."""
        e = self.current()
        if e:
            e.success_count += 1

    # ── 상태 조회 ─────────────────────────────────────────────────
    def pool_status(self) -> dict:
        """풀 상태 요약 dict 반환."""
        with self._lock:
            total  = len(self._pool)
            banned = sum(1 for e in self._pool if e.banned)
            active = total - banned
            cur    = self.current()
        return {
            "enabled": self.enabled,
            "total":   total,
            "active":  active,
            "banned":  banned,
            "current": str(cur) if cur else "none",
            "tor":     self._tor_enabled,
            "stem":    _STEM_OK,
            "pysocks": _PYSOCKS_OK,
        }

    def list_all(self) -> list[dict]:
        """모든 프록시 정보 목록 반환."""
        with self._lock:
            return [
                {
                    "url":      str(e),
                    "banned":   e.banned,
                    "success":  e.success_count,
                    "fails":    e.fail_count,
                    "latency":  e.latency_ms,
                    "is_tor":   e.is_tor,
                }
                for e in self._pool
            ]

    def clear(self) -> None:
        """풀 초기화."""
        with self._lock:
            self._pool.clear()
            self._index = 0
            self._enabled = False

    def unban_all(self) -> int:
        """밴된 프록시 전부 해제. 해제된 개수 반환."""
        with self._lock:
            count = 0
            for e in self._pool:
                if e.banned:
                    e.banned = False
                    e.fail_count = 0
                    count += 1
        return count

    # ── 헬스체크 ─────────────────────────────────────────────────
    # 테스트 URL 우선순위 (빠르고 신뢰할 수 있는 IP 확인 서비스)
    _TEST_URLS: list[str] = [
        "http://ip.sb",              # 가장 빠름, 단순 IP 텍스트
        "http://api.ipify.org",      # 안정적 IP API
        "http://ifconfig.me/ip",     # 단순 IP
        "http://ip-api.com/line/?fields=query",  # 빠른 IP API
        "http://checkip.amazonaws.com",          # AWS endpoint
    ]

    def test_proxy(
        self,
        entry: "ProxyEntry",
        test_url: str | None = None,
        timeout: int = 15,
    ) -> tuple[bool, str]:
        """
        단일 프록시 동작 확인.

        Returns
        -------
        (ok: bool, detail: str)
            ok=True  → 'IP=x.x.x.x latency=Xms' 문자열
            ok=False → 실패 원인 설명 문자열
        """
        # SOCKS5/SOCKS4 사용 시 PySocks 설치 여부 확인
        is_socks = entry.scheme.startswith("socks")
        if is_socks and not _PYSOCKS_OK:
            return (
                False,
                "PySocks not installed — run: pip install requests[socks]\n"
                "PySocks 미설치 — 실행 필요: pip install 'requests[socks]'",
            )

        import requests as _req  # type: ignore
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        proxies = entry.to_requests_dict()
        urls_to_try = [test_url] if test_url else list(self._TEST_URLS)

        last_err = "No test URL available"
        for url in urls_to_try:
            try:
                sess = _req.Session()
                sess.trust_env = False          # 환경변수 HTTP_PROXY 등 무시
                t0 = time.time()
                r = sess.get(
                    url,
                    proxies=proxies,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
                elapsed = round((time.time() - t0) * 1000, 1)

                if r.status_code < 400:
                    ip_text = r.text.strip().split()[0] if r.text.strip() else "?"
                    # 응답이 IP 형식인지 확인 (단순 검증)
                    import re as _re
                    if not _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_text):
                        ip_text = "connected"
                    entry.latency_ms = elapsed
                    entry.success_count += 1
                    return (True, f"IP={ip_text}  latency={elapsed:.0f}ms  via {url}")
                else:
                    last_err = f"HTTP {r.status_code} from {url}"
            except _req.exceptions.ProxyError as e:
                last_err = f"ProxyError: {str(e)[:120]}"
                # ProxyError는 즉시 실패 (다른 URL 시도해도 무의미)
                entry.fail_count += 1
                return (False, last_err)
            except _req.exceptions.ConnectTimeout:
                last_err = f"ConnectTimeout ({timeout}s) → {url}"
            except _req.exceptions.ConnectionError as e:
                _msg = str(e)
                if "SOCKS5" in _msg or "SOCKS4" in _msg:
                    last_err = f"SOCKS connection refused: {_msg[:100]}"
                    entry.fail_count += 1
                    return (False, last_err)
                last_err = f"ConnectionError: {_msg[:100]}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {str(e)[:100]}"

        entry.fail_count += 1
        return (False, last_err)

    def test_all(self, test_url: str | None = None) -> dict[str, tuple[bool, str]]:
        """풀 전체 헬스체크. {proxy_str: (ok, detail)} dict 반환."""
        results: dict[str, tuple[bool, str]] = {}
        for e in list(self._pool):
            ok, detail = self.test_proxy(e, test_url)
            results[str(e)] = (ok, detail)
            if not ok:
                e.banned = True
        return results

    # ── AI 스크립트 주입용 코드 스니펫 생성 ──────────────────────
    def inject_snippet(self) -> str:
        """
        현재 프록시를 AI 생성 Python 스크립트에 주입할 코드 스니펫.
        AI가 이 코드를 그대로 사용하면 프록시가 적용됨.
        """
        e = self.current()
        if not e:
            return ""
        return (
            f"# [PROXY INJECTED by bingo v3.2.74]\n"
            f"import urllib3; urllib3.disable_warnings()\n"
            f"PROXIES = {{'http': '{e.url}', 'https': '{e.url}'}}\n"
            f"# requests.get(url, proxies=PROXIES, verify=False, timeout=15)\n"
        )

    # ── 세션 간 저장/복원 (v3.2.77) ─────────────────────────────────
    def save_config(self, path: "Path | str | None" = None) -> bool:
        """
        현재 프록시 풀을 JSON 파일로 저장.

        저장 항목: 원본 URL 목록 + enabled 상태
        Returns True on success, False on error.
        """
        save_path = Path(path) if path else _PROXY_SAVE_PATH
        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = {
                    "enabled": self._enabled,
                    "proxies": [e.url for e in self._pool if not e.banned],
                }
            save_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    def load_config(self, path: "Path | str | None" = None) -> int:
        """
        JSON 파일에서 프록시 풀 복원.

        Returns: 추가된 프록시 수 (0이면 파일 없음 또는 빈 파일)
        """
        load_path = Path(path) if path else _PROXY_SAVE_PATH
        if not load_path.exists():
            return 0
        try:
            data = json.loads(load_path.read_text(encoding="utf-8"))
            urls: list[str] = data.get("proxies", [])
            n = self.add_many(urls)
            if data.get("enabled", True) and n > 0:
                self._enabled = True
            return n
        except Exception:
            return 0

    # ── 빠른 API 프리셋 ──────────────────────────────────────────
    @staticmethod
    def free_api_urls() -> list[tuple[str, str]]:
        """
        무료 프록시 API URL 목록 (이름, URL).
        /proxy api 명령에서 선택지로 표시.
        """
        return [
            (
                "ProxyScrape (SOCKS5)",
                "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=socks5&timeout=10000"
                "&proxy_format=protocolipport&format=text",
            ),
            (
                "ProxyScrape (HTTP)",
                "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=http&timeout=10000"
                "&proxy_format=protocolipport&format=text",
            ),
            (
                "ProxyScrape (SOCKS4)",
                "https://api.proxyscrape.com/v3/free-proxy-list/get"
                "?request=displayproxies&protocol=socks4&timeout=10000"
                "&proxy_format=protocolipport&format=text",
            ),
            (
                "GeoNode Free",
                "https://proxylist.geonode.com/api/proxy-list"
                "?limit=100&page=1&sort_by=lastChecked&sort_type=desc"
                "&filterUpTime=90&protocols=socks5",
            ),
        ]
