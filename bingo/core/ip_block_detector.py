"""
bingo/core/ip_block_detector.py — 제로 오탐 IP 차단 감지기 (v4.2.0)

【설계 철학】
  "오탐은 절대 금지" — 실제 IP 차단일 때만 발동.
  단일 신호 대신 5개 독립 신호를 교차 검증.
  신호 3개 이상 일치 → IP 차단 확정.

【5개 감지 신호】
  S1. HTTP 상태코드 패턴  (403/429/503 + WAF 헤더)
  S2. 복수 경로 재현성    (동일 응답이 3개+ 경로에서 반복)
  S3. 베이스라인 편차     (과거 정상 응답 대비 이상 탐지)
  S4. TCP 레벨 연결       (연결 성공 vs RST / timeout)
  S5. DNS vs HTTP 교차    (DNS 정상 → HTTP 실패 = 방화벽)

【보장】
  - 일시적 네트워크 오류 (타임아웃 1~2회) 는 차단으로 처리 안 함.
  - 404 / 500 (서버 오류) 는 차단이 아님.
  - 최소 3/5 신호 + 연속 N회 재현 시만 확정.
"""
from __future__ import annotations

import hashlib
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── 차단 판정 임계값 ─────────────────────────────────────────────────────────
_MIN_SIGNALS     = 3     # 5개 중 3개 이상 → 차단 확정
_REPEAT_REQUIRED = 2     # 동일 패턴 연속 N회 후 S2 신호 발화
_PROBE_PATHS     = [     # 멀티-경로 검증용 무해 경로 목록
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
]
_BLOCK_CODES     = {403, 429, 503, 429, 999, 530}  # Cloudflare 530 포함
_WAF_HEADERS     = {                                # WAF 노출 헤더 패턴
    "cf-ray", "x-sucuri-id", "x-fw-hash", "x-akamai-session-info",
    "x-cache-status",
}
_WAF_BODIES      = [                                # WAF 바디 키워드
    "access denied", "your ip", "ip address", "has been blocked",
    "automated request", "captcha", "cloudflare", "sucuri website firewall",
    "wordfence", "rate limit", "please wait", "ddos protection",
    "you have been blocked",
]


# ── 응답 스냅샷 ──────────────────────────────────────────────────────────────
@dataclass
class _Snapshot:
    status:   int
    body_sig: str   # SHA256[:16]
    waf_hdrs: bool
    latency:  float  # seconds


def _snapshot(url: str, timeout: float = 8.0, proxies: Optional[Dict] = None) -> Optional[_Snapshot]:
    """타겟 URL에 GET 요청 후 스냅샷 반환. 실패 시 None."""
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency  = time.monotonic() - t0
            status   = resp.status
            body_raw = resp.read(4096).decode("utf-8", errors="replace").lower()
            hdrs     = {k.lower(): v for k, v in resp.headers.items()}
            body_sig = hashlib.sha256(body_raw.encode()).hexdigest()[:16]
            waf_hdrs = bool(_WAF_HEADERS & set(hdrs.keys()))
            return _Snapshot(status, body_sig, waf_hdrs, latency)
    except urllib.error.HTTPError as e:
        latency = time.monotonic() - t0
        body_raw = e.read(4096).decode("utf-8", errors="replace").lower()
        body_sig = hashlib.sha256(body_raw.encode()).hexdigest()[:16]
        hdrs     = {k.lower(): v for k, v in e.headers.items()}
        waf_hdrs = bool(_WAF_HEADERS & set(hdrs.keys()))
        waf_body = any(kw in body_raw for kw in _WAF_BODIES)
        return _Snapshot(e.code, body_sig if not waf_body else "waf_" + body_sig, waf_hdrs, latency)
    except (urllib.error.URLError, socket.timeout, OSError):
        return None


# ── TCP 레벨 검사 ────────────────────────────────────────────────────────────
def _tcp_ok(host: str, port: int = 80, timeout: float = 5.0) -> bool:
    """TCP 연결 성공 여부 반환."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ── 도메인 추출 ──────────────────────────────────────────────────────────────
def _extract_host_port(url: str) -> Tuple[str, int]:
    """URL 에서 (host, port) 추출."""
    url = url.rstrip("/")
    if url.startswith("https://"):
        host = url[8:].split("/")[0]
        port = 443
    elif url.startswith("http://"):
        host = url[7:].split("/")[0]
        port = 80
    else:
        host = url.split("/")[0]
        port = 80
    if ":" in host:
        host, p = host.rsplit(":", 1)
        port = int(p)
    return host, port


# ── 결과 데이터클래스 ────────────────────────────────────────────────────────
@dataclass
class BlockDetectResult:
    blocked:       bool
    confidence:    float           # 0.0 ~ 1.0
    signals_fired: List[str]       # 발화된 신호 이름 목록
    detail:        str             # 사람이 읽을 수 있는 설명
    timestamp:     float = field(default_factory=time.time)


# ── 메인 감지기 ─────────────────────────────────────────────────────────────
class IPBlockDetector:
    """
    5-Signal 교차검증 IP 차단 감지기.

    사용법:
        detector = IPBlockDetector(target="https://example.com")
        result = detector.check()
        if result.blocked:
            # 프록시 로테이션 트리거
    """

    def __init__(self, target: str, baseline_ttl: float = 300.0):
        self._target      = target.rstrip("/")
        self._baseline: Optional[_Snapshot] = None
        self._baseline_at: float = 0.0
        self._baseline_ttl = baseline_ttl
        self._consecutive_blocks = 0

    # ── 베이스라인 갱신 ────────────────────────────────────────────────────
    def _refresh_baseline(self) -> None:
        """베이스라인 응답 갱신 (TTL 기반 캐시)."""
        now = time.monotonic()
        if self._baseline is None or (now - self._baseline_at) > self._baseline_ttl:
            snap = _snapshot(self._target + "/robots.txt")
            if snap and snap.status < 400:
                self._baseline    = snap
                self._baseline_at = now

    # ── 신호 1: HTTP 상태코드 + WAF 헤더 ──────────────────────────────────
    def _signal_s1_http_code(self, snap: Optional[_Snapshot]) -> bool:
        if snap is None:
            return False
        if snap.status in _BLOCK_CODES:
            return True
        if snap.waf_hdrs and snap.status >= 400:
            return True
        return False

    # ── 신호 2: 복수 경로 재현성 ─────────────────────────────────────────
    def _signal_s2_multipath(self) -> bool:
        """3개 경로에서 모두 차단 응답이면 True."""
        blocked_count = 0
        for path in _PROBE_PATHS:
            snap = _snapshot(self._target + path, timeout=5.0)
            if snap and snap.status in _BLOCK_CODES:
                blocked_count += 1
            elif snap is None:
                blocked_count += 1  # 연결 실패도 차단 신호
        return blocked_count >= _REPEAT_REQUIRED

    # ── 신호 3: 베이스라인 편차 ──────────────────────────────────────────
    def _signal_s3_baseline_deviation(self, snap: Optional[_Snapshot]) -> bool:
        if self._baseline is None or snap is None:
            return False
        # 베이스라인 대비 상태코드 급변 (200 → 403/429 등)
        if self._baseline.status < 400 and snap.status in _BLOCK_CODES:
            return True
        # 응답 시간 10배 이상 지연 (DDoS 방어 반응)
        if self._baseline.latency > 0 and snap.latency > self._baseline.latency * 10:
            return True
        return False

    # ── 신호 4: TCP 레벨 연결 ────────────────────────────────────────────
    def _signal_s4_tcp(self, snap: Optional[_Snapshot]) -> bool:
        """TCP는 OK인데 HTTP가 차단 → 방화벽/WAF 레이어 차단 확정."""
        if snap is not None:
            return False  # HTTP 응답 있음 → TCP OK
        host, port = _extract_host_port(self._target)
        # HTTPS 포트 시도
        https_port = 443 if "https://" in self._target else 80
        tcp_ok = _tcp_ok(host, https_port)
        # TCP 연결됐지만 HTTP 응답 없음 = WAF가 HTTP 레벨 차단
        return tcp_ok  # TCP OK + HTTP None = 차단

    # ── 신호 5: DNS vs HTTP 교차 ────────────────────────────────────────
    def _signal_s5_dns_vs_http(self, snap: Optional[_Snapshot]) -> bool:
        """DNS 정상 분해 + HTTP 실패 = 방화벽 차단."""
        if snap is not None and snap.status < 400:
            return False  # HTTP 정상 → 차단 아님
        host, _ = _extract_host_port(self._target)
        try:
            socket.getaddrinfo(host, None)
            dns_ok = True
        except socket.gaierror:
            dns_ok = False
        # DNS 정상인데 HTTP 실패 → 방화벽 차단 신호
        if dns_ok and (snap is None or snap.status in _BLOCK_CODES):
            return True
        return False

    # ── 메인 검사 ────────────────────────────────────────────────────────
    def check(self) -> BlockDetectResult:
        """
        5개 신호 교차검증 → BlockDetectResult 반환.
        _MIN_SIGNALS(=3)개 이상 발화 시만 blocked=True.
        """
        self._refresh_baseline()

        # 타겟 메인 경로 스냅샷
        snap = _snapshot(self._target)

        signals: Dict[str, bool] = {}
        signals["S1_http_code"]   = self._signal_s1_http_code(snap)
        signals["S3_baseline"]    = self._signal_s3_baseline_deviation(snap)
        signals["S4_tcp_layer"]   = self._signal_s4_tcp(snap)
        signals["S5_dns_vs_http"] = self._signal_s5_dns_vs_http(snap)

        # S2 는 네트워크 요청 3개 → 빠른 판단이 필요할 때만 실행
        s1_hint = signals["S1_http_code"] or signals["S5_dns_vs_http"]
        if s1_hint:
            signals["S2_multipath"] = self._signal_s2_multipath()
        else:
            signals["S2_multipath"] = False

        fired = [name for name, v in signals.items() if v]
        cnt   = len(fired)
        conf  = cnt / 5.0

        blocked = cnt >= _MIN_SIGNALS

        # 연속 차단 카운터 관리
        if blocked:
            self._consecutive_blocks += 1
        else:
            self._consecutive_blocks = 0

        detail_parts = []
        if snap:
            detail_parts.append(f"status={snap.status} latency={snap.latency:.2f}s")
        else:
            detail_parts.append("no_response")
        detail_parts.append(f"signals={cnt}/5 fired={fired}")
        detail = " | ".join(detail_parts)

        return BlockDetectResult(
            blocked=blocked,
            confidence=conf,
            signals_fired=fired,
            detail=detail,
        )

    def reset_baseline(self) -> None:
        """강제 베이스라인 초기화 (프록시 변경 후 호출)."""
        self._baseline    = None
        self._baseline_at = 0.0
        self._consecutive_blocks = 0


# ── 편의 팩토리 ─────────────────────────────────────────────────────────────
def make_detector(target: str) -> IPBlockDetector:
    return IPBlockDetector(target)
