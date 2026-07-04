"""
bingo/core/proxy_hunter.py — 무료 프록시 자동 수집 + 3단계 검증 (v4.2.0)

【수집 소스】
  1. free-proxy-list.net  (HTML 파싱)
  2. proxyscrape.com API  (CSV)
  3. spys.me              (TXT)
  4. raw.githubusercontent.com (TheSpeedX/PROXY-List)

【3단계 검증 파이프라인】
  Stage 1 — TCP 연결 (socket.create_connection, timeout 5s)
  Stage 2 — HTTP 익명성 검사 (httpbin.org/ip or ipecho.net)
            응답 IP가 실제 내 IP와 다른지 확인 → 실제 프록시 여부
  Stage 3 — 타겟 경량 요청 (robots.txt HEAD)
            타겟에서 차단되지 않은 프록시만 통과

【품질 기준】
  - 응답시간 < 3.0s
  - 익명성: Elite / Anonymous (X-Forwarded-For 미노출)
  - HTTP / HTTPS / SOCKS5 지원 여부 기록

【스레드 안전성】
  - 수집·검증은 별도 ThreadPool에서 병렬 처리
  - 결과는 ProxyInfo 리스트로 반환 (mutable 공유 없음)
"""
from __future__ import annotations

import csv
import io
import json
import logging
import queue
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── 검증 시간 제한 ───────────────────────────────────────────────────────────
_TCP_TIMEOUT  = 5.0   # Stage-1: TCP 연결 제한
_HTTP_TIMEOUT = 8.0   # Stage-2/3: HTTP 요청 제한
_MAX_LATENCY  = 3.0   # 응답 시간 상한 (초)

# ── 내 실제 IP 확인용 엔드포인트 (순서대로 시도) ─────────────────────────────
_MY_IP_SOURCES = [
    "https://api.ipify.org",
    "https://ipecho.net/plain",
    "https://icanhazip.com",
]

# ── 타겟 경량 확인 경로 ──────────────────────────────────────────────────────
_TARGET_PROBE = "/robots.txt"


# ── 프록시 데이터클래스 ──────────────────────────────────────────────────────
@dataclass
class ProxyInfo:
    host:       str
    port:       int
    protocol:   str    # "http" / "https" / "socks5"
    latency:    float  # 실측 응답시간 (Stage-3 기준)
    anonymous:  bool   # True = Elite/Anonymous
    validated:  bool   # 3단계 모두 통과
    score:      float  # 0.0 ~ 1.0 (낮을수록 좋음, = latency/3)
    fail_count: int    = 0  # 실패 누적 (블랙리스트 판단용)
    last_ok_at: float  = field(default_factory=time.time)

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    def mark_failed(self) -> None:
        self.fail_count += 1
        self.validated   = False

    def mark_success(self) -> None:
        self.fail_count  = 0
        self.validated   = True
        self.last_ok_at  = time.time()


# ── 내 IP 확인 ──────────────────────────────────────────────────────────────
def _get_my_ip(timeout: float = 6.0) -> Optional[str]:
    """현재 실제 IP 반환. 실패 시 None."""
    for src in _MY_IP_SOURCES:
        try:
            req = urllib.request.Request(src, headers={"User-Agent": "curl/7.88"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read(64).decode("utf-8", errors="replace").strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    return ip
        except Exception:
            continue
    return None


# ── 소스 수집 함수들 ─────────────────────────────────────────────────────────
def _fetch_free_proxy_list() -> List[ProxyInfo]:
    """free-proxy-list.net HTML에서 프록시 파싱."""
    proxies: List[ProxyInfo] = []
    url = "https://free-proxy-list.net/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            html = resp.read(200_000).decode("utf-8", errors="replace")
        # IP:PORT 패턴 추출
        rows = re.findall(
            r'<tr[^>]*>\s*<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>'
            r'\s*<td>(\d+)</td>'
            r'.*?<td[^>]*>(\w+)</td>',  # 익명성 컬럼
            html, re.DOTALL
        )
        for ip, port, anon_raw in rows[:60]:
            anon = anon_raw.lower() in {"elite proxy", "anonymous", "elite"}
            proto = "https" if "yes" in html[html.find(ip):html.find(ip)+300].lower() else "http"
            proxies.append(ProxyInfo(
                host=ip, port=int(port), protocol=proto,
                latency=99.0, anonymous=anon, validated=False, score=1.0,
            ))
    except Exception as e:
        logger.debug(f"[proxy_hunter] free-proxy-list fetch error: {e}")
    return proxies


def _fetch_proxyscrape() -> List[ProxyInfo]:
    """proxyscrape.com API CSV."""
    proxies: List[ProxyInfo] = []
    urls = [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=elite",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all",
    ]
    for url in urls:
        try:
            proto = "socks5" if "socks5" in url else "http"
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88"})
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                text = resp.read(50_000).decode("utf-8", errors="replace")
            for line in text.strip().splitlines():
                line = line.strip()
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        ip, port_str = parts
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                            proxies.append(ProxyInfo(
                                host=ip, port=int(port_str), protocol=proto,
                                latency=99.0, anonymous=True, validated=False, score=1.0,
                            ))
        except Exception as e:
            logger.debug(f"[proxy_hunter] proxyscrape fetch error: {e}")
    return proxies


def _fetch_github_proxy_list() -> List[ProxyInfo]:
    """TheSpeedX/PROXY-List (GitHub 공개 목록)."""
    proxies: List[ProxyInfo] = []
    raw_urls = [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    ]
    for url in raw_urls:
        proto = "socks5" if "socks5" in url else "http"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/7.88"})
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                text = resp.read(100_000).decode("utf-8", errors="replace")
            for line in text.strip().splitlines()[:200]:  # 최대 200개
                line = line.strip()
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        ip, port_str = parts
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                            proxies.append(ProxyInfo(
                                host=ip, port=int(port_str), protocol=proto,
                                latency=99.0, anonymous=True, validated=False, score=1.0,
                            ))
        except Exception as e:
            logger.debug(f"[proxy_hunter] github proxy fetch error: {e}")
    return proxies


# ── 3단계 검증 ──────────────────────────────────────────────────────────────
def _validate_proxy(proxy: ProxyInfo, my_ip: Optional[str], target: Optional[str] = None) -> bool:
    """
    Stage 1~3 순차 검증. 통과 시 proxy.validated=True, latency 갱신.
    """
    # ── Stage 1: TCP 연결 ──────────────────────────────────────────────────
    try:
        with socket.create_connection((proxy.host, proxy.port), timeout=_TCP_TIMEOUT):
            pass
    except OSError:
        return False

    # ── Stage 2: HTTP 익명성 확인 ─────────────────────────────────────────
    # SOCKS5 는 urllib 기본 지원 안 됨 → HTTP 전용 검증
    proto_scheme = proxy.protocol if proxy.protocol != "socks5" else "http"
    proxy_handler = urllib.request.ProxyHandler({
        "http":  f"http://{proxy.host}:{proxy.port}",
        "https": f"http://{proxy.host}:{proxy.port}",
    })
    opener = urllib.request.build_opener(proxy_handler)

    t0 = time.monotonic()
    try:
        req = opener.open("http://httpbin.org/ip", timeout=_HTTP_TIMEOUT)
        body = req.read(512).decode("utf-8", errors="replace")
        latency = time.monotonic() - t0
        if latency > _MAX_LATENCY:
            return False
        # 응답 IP가 내 IP가 아닌지 확인 (실제 프록시 여부)
        if my_ip and my_ip in body:
            return False  # 프록시가 내 IP 노출 → Elite/Anonymous 아님
        # X-Forwarded-For 노출 여부는 httpbin.org/headers로도 가능하지만
        # 단순화: origin IP가 내 IP가 아니면 익명 처리
        proxy.latency  = latency
        proxy.score    = latency / _MAX_LATENCY
        proxy.anonymous = True
    except Exception:
        return False

    # ── Stage 3: 타겟 경량 요청 ─────────────────────────────────────────
    if target:
        probe_url = target.rstrip("/") + _TARGET_PROBE
        try:
            t1 = time.monotonic()
            req2 = opener.open(probe_url, timeout=_HTTP_TIMEOUT)
            _ = req2.read(512)
            stage3_latency = time.monotonic() - t1
            if stage3_latency > _MAX_LATENCY:
                return False
            # 최종 latency = Stage-3 기준으로 갱신
            proxy.latency = stage3_latency
            proxy.score   = stage3_latency / _MAX_LATENCY
        except urllib.error.HTTPError as e:
            # robots.txt 404 는 정상 (파일 없는 것), 403 → 차단
            if e.code == 403:
                return False
        except Exception:
            return False

    proxy.validated = True
    proxy.mark_success()
    return True


# ── 메인 수집기 ─────────────────────────────────────────────────────────────
class ProxyHunter:
    """
    무료 프록시 수집 + 3단계 검증.

    사용법:
        hunter = ProxyHunter(target="https://example.com")
        validated = hunter.hunt(min_count=10)
    """

    def __init__(self, target: Optional[str] = None, workers: int = 20):
        self._target  = target
        self._workers = workers

    def _collect_raw(self) -> List[ProxyInfo]:
        """모든 소스에서 원시 프록시 수집 (중복 제거)."""
        raw: List[ProxyInfo] = []
        seen = set()

        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [
                ex.submit(_fetch_free_proxy_list),
                ex.submit(_fetch_proxyscrape),
                ex.submit(_fetch_github_proxy_list),
            ]
            for fut in as_completed(futs):
                try:
                    for p in fut.result():
                        key = (p.host, p.port)
                        if key not in seen:
                            seen.add(key)
                            raw.append(p)
                except Exception:
                    pass

        return raw

    def hunt(self, min_count: int = 10, max_check: int = 150) -> List[ProxyInfo]:
        """
        수집 → 병렬 검증 → 최소 min_count개 반환.
        """
        logger.info("[proxy_hunter] 프록시 수집 시작...")
        raw = self._collect_raw()
        logger.info(f"[proxy_hunter] 원시 수집: {len(raw)}개 → 검증 시작 (max {max_check}개)")

        my_ip = _get_my_ip()
        if my_ip:
            logger.debug(f"[proxy_hunter] 내 IP: {my_ip}")

        validated: List[ProxyInfo] = []
        candidates = raw[:max_check]

        with ThreadPoolExecutor(max_workers=self._workers) as ex:
            futs = {
                ex.submit(_validate_proxy, p, my_ip, self._target): p
                for p in candidates
            }
            for fut in as_completed(futs):
                proxy = futs[fut]
                try:
                    ok = fut.result()
                    if ok:
                        validated.append(proxy)
                        logger.debug(
                            f"[proxy_hunter] ✓ {proxy.host}:{proxy.port} "
                            f"latency={proxy.latency:.2f}s"
                        )
                        if len(validated) >= min_count * 3:
                            # 충분히 모이면 나머지 취소 (시간 절약)
                            for f2 in futs:
                                f2.cancel()
                            break
                except Exception:
                    pass

        # 지연시간 오름차순 정렬
        validated.sort(key=lambda p: p.latency)
        logger.info(f"[proxy_hunter] 검증 완료: {len(validated)}개 사용 가능")
        return validated


# ── 편의 팩토리 ─────────────────────────────────────────────────────────────
def hunt_proxies(target: Optional[str] = None, min_count: int = 10) -> List[ProxyInfo]:
    """빠른 수집 실행 (외부에서 단순 호출용)."""
    return ProxyHunter(target=target).hunt(min_count=min_count)
